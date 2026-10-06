//
// terminate_contain_ut.cpp —— 「终止进程收敛」判据单测（v36）。
//
// 直接链**真实的** r3shieldcore_rules.cpp（同 build_ut.sh 的配方），
// 并用**真实进程树**驱动它 —— 不是复刻一份逻辑：
//
//   T1 直接子进程   —— 子进程应被认作后代 → 放行
//   T2 孙进程       —— 孙进程也应被认作后代（整棵子树）→ 放行
//   T3 无关进程     —— explorer 之类 → 高危（"不许杀别人"）
//   T4 同镜像非后代 —— 孤儿进程（中间父进程已退出）→ 靠"同镜像"放行
//   T5 自己 / pid=0 —— 无条件放行（存活前提）
//
// 角色（自己分饰）：
//   --sleeper                 只睡，等被当靶子
//   --spawner <outfile>       拉一个 sleeper，把它的 pid 写进 outfile
//       --orphan              写完立刻退出（制造"父进程已死"的孤儿）
//
// 只碰自己拉起的进程 + 读一个 shell 窗口的 pid，绝不动它们。

#include "r3shieldcore_rules.h"

#include <windows.h>
#include <stdio.h>
#include <string>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

static std::wstring SelfPath()
{
	WCHAR p[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, p, _countof(p));
	return std::wstring(p);
}

static bool SpawnSelf(const std::wstring& extraArgs, PROCESS_INFORMATION* pi)
{
	std::wstring cmd = L"\"" + SelfPath() + L"\" " + extraArgs;
	STARTUPINFOW si = { sizeof(si) };
	*pi = {};
	return CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
		0, nullptr, nullptr, &si, pi) != FALSE;
}

static bool IsAlive(HANDLE h)
{
	DWORD code = 0;
	return GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
}

// 读 spawner 写出的 pid 文件。
static ULONG ReadPidFile(const WCHAR* path)
{
	FILE* f = nullptr;
	_wfopen_s(&f, path, L"r");
	if (!f) return 0;
	unsigned long pid = 0;
	if (fscanf_s(f, "%lu", &pid) != 1) pid = 0;
	fclose(f);
	return static_cast<ULONG>(pid);
}

// ---------------------------------------------------------------- 角色
static int RunSleeper()
{
	for (int i = 0; i < 600; i++) Sleep(100);
	return 0;
}

static int RunSpawner(const wchar_t* outFile, bool orphan)
{
	PROCESS_INFORMATION pi = {};
	if (!SpawnSelf(L"--sleeper", &pi)) return 2;

	FILE* f = nullptr;
	_wfopen_s(&f, outFile, L"w");
	if (f) { fprintf(f, "%lu\n", pi.dwProcessId); fclose(f); }

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (orphan) return 0;          // 立刻退出 → 孙进程变"孤儿"
	for (int i = 0; i < 600; i++) Sleep(100);
	return 0;
}

// ---------------------------------------------------------------- 主测
int main(int argc, char** argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--sleeper") == 0) return RunSleeper();
		if (strcmp(argv[i], "--spawner") == 0) {
			WCHAR out[MAX_PATH] = {};
			if (i + 1 < argc) MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, out, _countof(out));
			bool orphan = false;
			for (int j = 1; j < argc; j++)
				if (strcmp(argv[j], "--orphan") == 0) orphan = true;
			return RunSpawner(out, orphan);
		}
	}

	const ULONG selfPid = GetCurrentProcessId();
	printf("UT pid=%u  镜像=%ls\n", selfPid, SelfPath().c_str());

	WCHAR tmpDir[MAX_PATH] = {};
	GetTempPathW(_countof(tmpDir), tmpDir);
	WCHAR gOut[MAX_PATH] = {};
	WCHAR oOut[MAX_PATH] = {};
	swprintf_s(gOut, L"%stc_grandchild.txt", tmpDir);
	swprintf_s(oOut, L"%stc_orphan.txt", tmpDir);
	DeleteFileW(gOut);
	DeleteFileW(oOut);

	// ============================================================
	// 第 1 组：纯规则（假 pid）
	// ============================================================
	printf("\n=== 第 1 组：纯规则（假 pid）===\n");
	Check("pid=0 → 放行", R3ShieldCoreRules::TerminateRiskReason(0, selfPid) == nullptr);
	Check("目标==自己 → 放行", R3ShieldCoreRules::TerminateRiskReason(selfPid, selfPid) == nullptr);
	Check("selfPid=0 → 放行（判不出来不拦）",
		R3ShieldCoreRules::TerminateRiskReason(4242, 0) == nullptr);
	Check("不存在的 pid → 高危（不是后代、镜像也拿不到）",
		R3ShieldCoreRules::TerminateRiskReason(0x7FFFFFF0UL, selfPid) != nullptr);
	Check("IsHighRiskTerminate 与 TerminateRiskReason 一致",
		R3ShieldCoreRules::IsHighRiskTerminate(selfPid, selfPid) == false &&
		R3ShieldCoreRules::IsHighRiskTerminate(0x7FFFFFF0UL, selfPid) == true);

	// ============================================================
	// 第 2 组：真实进程树
	// ============================================================
	printf("\n=== 第 2 组：真实进程树 ===\n");

	// ---- T1 直接子进程 ----
	PROCESS_INFORMATION child = {};
	if (!SpawnSelf(L"--sleeper", &child)) { printf("拉子进程失败\n"); return 1; }
	Sleep(400);
	printf("  T1 子进程 pid=%u\n", child.dwProcessId);
	Check("ParentPidOf(子) == 自己", R3ShieldCoreRules::ParentPidOf(child.dwProcessId) == selfPid);
	Check("IsOwnDescendant(子, 自己) == true",
		R3ShieldCoreRules::IsOwnDescendant(child.dwProcessId, selfPid));
	Check("★ 终止子进程 → 放行（不高危）",
		R3ShieldCoreRules::TerminateRiskReason(child.dwProcessId, selfPid) == nullptr);

	// ---- T2 孙进程（中间父进程**存活**，父链完整）----
	PROCESS_INFORMATION spawner = {};
	if (!SpawnSelf(L"--spawner \"" + std::wstring(gOut) + L"\"", &spawner)) {
		printf("拉 spawner 失败\n");
		return 1;
	}
	Sleep(900);
	const ULONG grandchildPid = ReadPidFile(gOut);
	printf("  T2 spawner pid=%u 孙进程 pid=%u\n", spawner.dwProcessId, grandchildPid);
	Check("孙进程 pid 拿到", grandchildPid != 0);
	Check("ParentPidOf(孙) == spawner",
		R3ShieldCoreRules::ParentPidOf(grandchildPid) == spawner.dwProcessId);
	Check("★ IsOwnDescendant(孙, 自己) == true（整棵子树）",
		R3ShieldCoreRules::IsOwnDescendant(grandchildPid, selfPid));
	Check("★ 终止孙进程 → 放行", R3ShieldCoreRules::TerminateRiskReason(grandchildPid, selfPid) == nullptr);

	// ---- T3 无关进程（explorer / shell 窗口）----
	printf("  T3 无关进程\n");
	HWND shell = FindWindowW(L"Shell_TrayWnd", nullptr);
	if (!shell) shell = GetShellWindow();
	ULONG otherPid = 0;
	if (shell) {
		DWORD pid = 0;
		GetWindowThreadProcessId(shell, &pid);
		otherPid = pid;
	}
	if (otherPid != 0 && otherPid != selfPid) {
		printf("    取到 shell 窗口进程 pid=%u\n", otherPid);
		Check("IsOwnDescendant(无关, 自己) == false",
			!R3ShieldCoreRules::IsOwnDescendant(otherPid, selfPid));
		Check("★ 终止无关进程 → 高危（不许杀别人）",
			R3ShieldCoreRules::TerminateRiskReason(otherPid, selfPid) != nullptr);
	} else {
		printf("    (没有 shell 窗口，跳过 T3)\n");
	}

	// ---- T4 同镜像但非后代（孤儿：中间父进程已退出）----
	PROCESS_INFORMATION orphanSpawner = {};
	if (!SpawnSelf(L"--spawner \"" + std::wstring(oOut) + L"\" --orphan", &orphanSpawner)) {
		printf("拉 orphan spawner 失败\n");
		return 1;
	}

	// ★ 必须**关掉句柄**再判定！
	//   实测（本探针第一次跑就踩到）：只要还有任何句柄指向那个已退出的
	//   进程对象，**进程对象就不会销毁，它的 pid 仍然可以 OpenProcess** ——
	//   于是父链"看起来"还是通的（ParentPidOf 照样查得到它、再往上是自己），
	//   孤儿会被误判成后代。关句柄后进程对象才真正释放，pid 才不可查。
	WaitForSingleObject(orphanSpawner.hProcess, 5000);
	CloseHandle(orphanSpawner.hProcess);
	CloseHandle(orphanSpawner.hThread);
	Sleep(300);

	const ULONG orphanPid = ReadPidFile(oOut);
	const ULONG orphanParent = R3ShieldCoreRules::ParentPidOf(orphanPid);
	printf("  T4 孤儿 pid=%u  其父 pid=%u（spawner 原 pid=%u，已退且句柄已关）\n",
		orphanPid, orphanParent, orphanSpawner.dwProcessId);
	if (orphanPid != 0) {
		Check("孤儿不是后代（父链断了）",
			!R3ShieldCoreRules::IsOwnDescendant(orphanPid, selfPid));
		Check("孤儿同镜像", R3ShieldCoreRules::SameImageAsSelf(orphanPid));
		Check("★ 终止同镜像孤儿 → 放行（同程序多实例）",
			R3ShieldCoreRules::TerminateRiskReason(orphanPid, selfPid) == nullptr);
	}

	// ---- 清理（孙进程 / 孤儿要按 pid 收，它们不是我们的直接子进程）----
	for (ULONG pid : {grandchildPid, orphanPid}) {
		if (pid == 0) continue;
		HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		if (h) { TerminateProcess(h, 0); CloseHandle(h); }
	}
	if (child.hProcess) {
		TerminateProcess(child.hProcess, 0);
		WaitForSingleObject(child.hProcess, 3000);
		CloseHandle(child.hProcess); CloseHandle(child.hThread);
	}
	if (spawner.hProcess) {
		TerminateProcess(spawner.hProcess, 0);
		WaitForSingleObject(spawner.hProcess, 3000);
		CloseHandle(spawner.hProcess); CloseHandle(spawner.hThread);
	}
	DeleteFileW(gOut);
	DeleteFileW(oOut);

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
