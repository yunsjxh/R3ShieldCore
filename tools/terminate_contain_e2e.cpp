//
// terminate_contain_e2e.cpp —— 「终止进程收敛」端到端实测（v36）。
//
// ★ 与 terminate_contain_ut.cpp 的分工：
//   · terminate_contain_ut —— 测**规则层**（TerminateRiskReason 的判定）。
//   · 本文件 —— 把**真实的 process_guard.cpp** 链进来，在本进程里
//     **真的装 hook**（ProcessGuard::Install + MH_ApplyQueued），
//     然后**真的去杀进程**，看：调用方拿到什么、目标活没活、
//     GuardStub 收到的 Event 是什么。
//
//   ⇒ 这是"产品代码本身"的端到端，不是复刻一份逻辑。
//     而且**不需要提权、不需要全系统注入** —— hook 只装在本探针进程里。
//
// 用法：无参数（自己分饰三角）。
//   --sleeper                 只睡，当靶子
//   --spawner <outfile>       拉一个自己的 sleeper，写 pid，然后常驻（父链完整）
//   --orphan-cmd <outfile>    拉一个 cmd.exe 当靶子，写 pid，**立刻退出**（造无关进程）
//
// 只碰自己拉起的进程；对 shell 窗口进程只"尝试杀"（预期被拦，不会真死）。

#include <windows.h>
#include <stdio.h>
#include <string>
#include <string.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "process_guard.h"
#include <MinHook.h>

// tools/guard_stub.cpp 提供的可控桩（声明方式同 v28/v29 单测）。
namespace GuardStub
{
	void SetMode(ULONG mode) noexcept;
	void SetHighRisk(bool on) noexcept;
	void SetPromptOpen(bool open) noexcept;
	void ResetPolicy() noexcept;
	bool HasEvent() noexcept;
	R3ShieldCore::Event LastEvent() noexcept;
	void ClearEvent() noexcept;
	R3ShieldCore::Policy* PolicyPtr() noexcept;
}

enum
{
	ModeLog = 0,
	ModeBlock = 1,
};

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

static bool Spawn(const std::wstring& args, PROCESS_INFORMATION* pi)
{
	std::wstring cmd = L"\"" + SelfPath() + L"\" " + args;
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

//
// 杀一个"只有 pid"的进程。
//
// ⚠️ 必须把「OpenProcess 失败」与「TerminateProcess 被拦」分开 ——
//    两者都可能给 err=5(ERROR_ACCESS_DENIED)，混在一起会把
//    "句柄都拿不到（ACL 拒绝）"误报成"我们的 hook 拦住了"。
//
struct KillResult
{
	bool opened;    // OpenProcess 是否成功
	BOOL ok;        // TerminateProcess 的返回值
	DWORD err;      // 失败时的 GetLastError
	HANDLE handle;  // 成功打开时的句柄（调用方负责关）
};

static KillResult KillByPid(ULONG pid)
{
	KillResult r = { false, FALSE, 0, nullptr };

	r.handle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
	if (!r.handle) {
		r.err = GetLastError();
		return r;
	}

	r.opened = true;
	r.ok = TerminateProcess(r.handle, 0);
	if (!r.ok) {
		r.err = GetLastError();
	}
	return r;
}

// ---------------------------------------------------------------- 角色
static int RunSleeper()
{
	for (int i = 0; i < 1200; i++) Sleep(100);
	return 0;
}

static int RunSpawner(const wchar_t* outFile, bool orphanCmd)
{
	PROCESS_INFORMATION pi = {};
	if (orphanCmd) {
		WCHAR comspec[MAX_PATH] = {};
		if (!GetEnvironmentVariableW(L"ComSpec", comspec, _countof(comspec)))
			wcscpy_s(comspec, L"C:\\Windows\\System32\\cmd.exe");
		std::wstring cmd = L"\"" + std::wstring(comspec) + L"\" /c ping -n 120 127.0.0.1 > nul";
		STARTUPINFOW si = { sizeof(si) };
		if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
			0, nullptr, nullptr, &si, &pi)) {
			return 2;
		}
	}
	else {
		if (!Spawn(L"--sleeper", &pi)) return 2;
	}

	FILE* f = nullptr;
	_wfopen_s(&f, outFile, L"w");
	if (f) { fprintf(f, "%lu\n", pi.dwProcessId); fclose(f); }

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (orphanCmd) return 0;              // 立刻退出 → 靶子变"孤儿"
	for (int i = 0; i < 1200; i++) Sleep(100);
	return 0;
}

// ---------------------------------------------------------------- 主测
int main(int argc, char** argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--sleeper") == 0) return RunSleeper();
		if (strcmp(argv[i], "--spawner") == 0 || strcmp(argv[i], "--orphan-cmd") == 0) {
			const bool orphanCmd = (strcmp(argv[i], "--orphan-cmd") == 0);
			WCHAR out[MAX_PATH] = {};
			if (i + 1 < argc) MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, out, _countof(out));
			return RunSpawner(out, orphanCmd);
		}
	}

	const ULONG selfPid = GetCurrentProcessId();
	printf("E2E pid=%u  镜像=%ls\n", selfPid, SelfPath().c_str());

	WCHAR tmpDir[MAX_PATH] = {};
	GetTempPathW(_countof(tmpDir), tmpDir);
	WCHAR gOut[MAX_PATH] = {}, u1Out[MAX_PATH] = {}, u2Out[MAX_PATH] = {};
	swprintf_s(gOut, L"%se2e_grandchild.txt", tmpDir);
	swprintf_s(u1Out, L"%se2e_u1.txt", tmpDir);
	swprintf_s(u2Out, L"%se2e_u2.txt", tmpDir);
	DeleteFileW(gOut); DeleteFileW(u1Out); DeleteFileW(u2Out);

	// ============================================================
	// 第 0 步：**先**把靶子都拉起来（此时还没装 hook，
	//         免得进程创建本身被别的规则干扰）。
	// ============================================================
	printf("\n=== 第 0 步：准备靶子（装 hook 之前）===\n");

	PROCESS_INFORMATION child = {};
	if (!Spawn(L"--sleeper", &child)) { printf("拉子进程失败\n"); return 1; }

	PROCESS_INFORMATION spawner = {};
	if (!Spawn(L"--spawner \"" + std::wstring(gOut) + L"\"", &spawner)) {
		printf("拉 spawner 失败\n"); return 1;
	}

	PROCESS_INFORMATION u1s = {}, u2s = {};
	Spawn(L"--orphan-cmd \"" + std::wstring(u1Out) + L"\"", &u1s);
	Spawn(L"--orphan-cmd \"" + std::wstring(u2Out) + L"\"", &u2s);

	Sleep(1500);
	const ULONG grandchildPid = ReadPidFile(gOut);
	const ULONG u1Pid = ReadPidFile(u1Out);
	const ULONG u2Pid = ReadPidFile(u2Out);

	// 无关进程必须"真的无关"：关掉中间父进程的句柄，否则进程对象不销毁、
	// 父链仍可查（见 skill：句柄保活进程对象）。
	if (u1s.hProcess) { WaitForSingleObject(u1s.hProcess, 3000); CloseHandle(u1s.hProcess); CloseHandle(u1s.hThread); }
	if (u2s.hProcess) { WaitForSingleObject(u2s.hProcess, 3000); CloseHandle(u2s.hProcess); CloseHandle(u2s.hThread); }

	HWND shell = FindWindowW(L"Shell_TrayWnd", nullptr);
	if (!shell) shell = GetShellWindow();
	ULONG shellPid = 0;
	if (shell) { DWORD p = 0; GetWindowThreadProcessId(shell, &p); shellPid = p; }

	printf("  自己=%u 子=%u 孙=%u 无关靶子1=%u 无关靶子2=%u shell=%u\n",
		selfPid, child.dwProcessId, grandchildPid, u1Pid, u2Pid, shellPid);

	// ============================================================
	// 第 1 步：装**真实**的 ProcessGuard hook（本进程）
	// ============================================================
	printf("\n=== 第 1 步：ProcessGuard::Install（真实 guard 代码）===\n");

	if (MH_Initialize() != MH_OK) { printf("MH_Initialize 失败\n"); return 1; }

	GuardStub::ResetPolicy();
	GuardStub::SetHighRisk(true);
	GuardStub::SetPromptOpen(false);
	GuardStub::SetMode(ModeBlock);

	{
		R3ShieldCore::Policy* p = GuardStub::PolicyPtr();
		p->Flags |= R3ShieldCore::FlagHookProcess;             // 挂进程创建/终止
		p->Flags2 |= R3ShieldCore::FlagHookTerminateContain;   // ★ v36 终止收敛
		p->EngineProcessId = selfPid;
		// 刻意**不开** FlagSelfProtect —— 本测试只关心终止判据。
	}

	if (!ProcessGuard::Install(nullptr)) { printf("ProcessGuard::Install 失败\n"); return 1; }
	if (MH_ApplyQueued() != MH_OK) { printf("MH_ApplyQueued 失败\n"); return 1; }

	printf("  已挂 hook 数 = %d\n", ProcessGuard::HookCount());
	Check("真实 guard 的 hook 装上了", ProcessGuard::HookCount() > 0);

	// ============================================================
	// 第 2 步：逐条实测（mode=block）
	// ============================================================
	printf("\n=== 第 2 步：mode=block ===\n");

	// ---- T1 杀自己的**直接子进程** → 应放行 ----
	GuardStub::ClearEvent();
	const BOOL t1 = TerminateProcess(child.hProcess, 0);
	Sleep(500);
	printf("  T1 杀子进程: 返回=%d 存活=%d\n", t1, IsAlive(child.hProcess));
	Check("T1 杀自己子进程 → 放行（返回 TRUE）", t1 == TRUE);
	Check("T1 子进程确实死了", !IsAlive(child.hProcess));
	if (GuardStub::HasEvent()) {
		const R3ShieldCore::Event e = GuardStub::LastEvent();
		printf("      event: decision=%u flags=0x%08X targetPid=%u\n",
			e.Decision, e.Flags, e.TargetProcessId);
		Check("T1 事件 Decision=Allowed",
			e.Decision == static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
	}

	// ---- T2 杀自己的**孙进程**（整棵子树）→ 应放行 ----
	GuardStub::ClearEvent();
	const KillResult t2 = KillByPid(grandchildPid);
	Sleep(500);
	const bool t2alive = t2.handle && IsAlive(t2.handle);
	printf("  T2 杀孙进程: opened=%d 返回=%d err=%lu 存活=%d\n",
		t2.opened, t2.ok, t2.err, t2alive);
	Check("T2 拿得到孙进程句柄", t2.opened);
	Check("T2 杀孙进程 → 放行（返回 TRUE）", t2.ok == TRUE);
	Check("T2 孙进程确实死了", !t2alive);
	if (t2.handle) CloseHandle(t2.handle);

	// ---- T3 杀**无关进程**（孤儿 cmd）→ 应被拦 ----
	GuardStub::ClearEvent();
	const KillResult t3 = KillByPid(u1Pid);
	Sleep(500);
	const bool t3alive = t3.handle && IsAlive(t3.handle);
	printf("  T3 杀无关进程: opened=%d 返回=%d err=%lu 存活=%d\n",
		t3.opened, t3.ok, t3.err, t3alive);
	Check("T3 拿得到无关进程句柄（不是 ACL 拒绝）", t3.opened);
	Check("★ T3 杀无关进程 → 被拦（TerminateProcess 返回 FALSE）", t3.ok == FALSE);
	Check("★ T3 调用方拿到 err=5 (ERROR_ACCESS_DENIED)", t3.err == 5);
	Check("★ T3 无关进程仍存活（拦真的生效）", t3alive);
	if (GuardStub::HasEvent()) {
		const R3ShieldCore::Event e = GuardStub::LastEvent();
		printf("      event: decision=%u risk=%u flags=0x%08X targetPid=%u (期望 target=%u)\n",
			e.Decision, e.RiskLevel, e.Flags, e.TargetProcessId, u1Pid);
		Check("T3 事件 Decision=Blocked",
			e.Decision == static_cast<ULONG>(R3ShieldCore::Decision::Blocked));
		Check("T3 事件带 [by R3ShieldCore] 标记（FlagEventBlocked）",
			(e.Flags & R3ShieldCore::FlagEventBlocked) != 0);
		Check("T3 事件 RiskLevel=High",
			e.RiskLevel == static_cast<ULONG>(R3ShieldCore::RiskLevel::High));
		Check("T3 事件 targetPid 就是那个无关进程", e.TargetProcessId == u1Pid);
	}
	if (t3.handle) CloseHandle(t3.handle);

	// ---- T4 杀 shell 窗口进程（真·系统无关进程）→ 应被拦，且**绝不能真死** ----
	if (shellPid != 0 && shellPid != selfPid) {
		const KillResult t4 = KillByPid(shellPid);
		Sleep(500);
		HANDLE sh = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, shellPid);
		const bool shAlive = sh && IsAlive(sh);
		if (sh) CloseHandle(sh);
		printf("  T4 杀 shell(%u): opened=%d 返回=%d err=%lu 存活=%d\n",
			shellPid, t4.opened, t4.ok, t4.err, shAlive);
		if (!t4.opened) {
			printf("      (拿不到 shell 句柄 err=%lu，本项不适用，跳过)\n", t4.err);
		}
		else {
			Check("★ T4 杀 shell 进程 → 被拦", t4.ok == FALSE);
			Check("★ T4 shell 进程安然无恙", shAlive);
		}
		if (t4.handle) CloseHandle(t4.handle);
	}

	// ============================================================
	// 第 3 步：mode=log → 只记录不拦
	// ============================================================
	printf("\n=== 第 3 步：mode=log（应只记录，不拦）===\n");
	GuardStub::SetMode(ModeLog);
	GuardStub::ClearEvent();

	const KillResult t5 = KillByPid(u2Pid);
	Sleep(500);
	const bool t5alive = t5.handle && IsAlive(t5.handle);
	printf("  T5 杀无关进程(log): opened=%d 返回=%d err=%lu 存活=%d\n",
		t5.opened, t5.ok, t5.err, t5alive);
	Check("T5 拿得到句柄", t5.opened);
	Check("T5 log 模式下放行（返回 TRUE）", t5.ok == TRUE);
	Check("T5 log 模式下目标真的死了", !t5alive);
	if (GuardStub::HasEvent()) {
		const R3ShieldCore::Event e = GuardStub::LastEvent();
		printf("      event: decision=%u (2=WouldBlock) flags=0x%08X\n", e.Decision, e.Flags);
		Check("T5 事件 Decision=WouldBlock（记录但不拦）",
			e.Decision == static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock));
	}
	if (t5.handle) CloseHandle(t5.handle);

	// ============================================================
	// 清理（此刻 mode=log，跨进程杀已放行）
	// ============================================================
	const KillResult cu1 = KillByPid(u1Pid);
	if (cu1.handle) CloseHandle(cu1.handle);
	const KillResult cg = KillByPid(grandchildPid);
	if (cg.handle) CloseHandle(cg.handle);
	if (spawner.hProcess) { TerminateProcess(spawner.hProcess, 0); WaitForSingleObject(spawner.hProcess, 2000); CloseHandle(spawner.hProcess); CloseHandle(spawner.hThread); }
	DeleteFileW(gOut); DeleteFileW(u1Out); DeleteFileW(u2Out);

	ProcessGuard::WaitForHooksToDrain(2000);

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
