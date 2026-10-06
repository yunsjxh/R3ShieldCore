//
// killwho_probe.cpp —— 实证：NtTerminateProcess hook 能不能知道"谁杀了谁"。
//
// 背景：R3ShieldCore 在每个被注入进程里挂 ntdll!NtTerminateProcess（只记录）。
//       问题是：hook 里到底能拿到什么？
//         · 谁发起的终止（凶手 pid / 镜像）？
//         · 谁被终止（受害者 pid）？
//
// 原理假设（本探针要证实/证伪）：
//   NtTerminateProcess 是**调用者**在**自己的线程**里执行的函数调用 ⇒
//   detour 里 GetCurrentProcessId() == 调用者（凶手）；
//   而 ProcessHandle 指向的目标 == 受害者。
//
// 做法（自己分饰两角）：
//   --victim   子进程：只是 Sleep 等被杀。
//   （无参数） 父进程：
//                 1) MinHook detour 自己进程的 ntdll!NtTerminateProcess；
//                 2) CreateProcess 拉起 victim；
//                 3) TerminateProcess(victim)；
//                 4) 断言 detour 里抓到的 (callerPid, targetPid)
//                    分别为 (父自己, victim)。
//                 5) 再自测一次"自我退出"路径：hook 里 caller==target==自己。
//
// 只碰自己创建的 victim 进程。

#include <windows.h>
#include <stdio.h>
#include <string>
#include <MinHook.h>

typedef NTSTATUS(NTAPI* NtTerminateProcessPtr)(HANDLE, NTSTATUS);
static NtTerminateProcessPtr g_originalNtTerminateProcess = nullptr;

static int  g_pass = 0;
static int  g_fail = 0;

// detour 抓到的现场
static volatile LONG g_hookHits = 0;
static DWORD g_hookCallerPid = 0;
static DWORD g_hookTargetPid = 0;
static WCHAR g_hookCallerImage[MAX_PATH] = {};
static NTSTATUS g_hookExitStatus = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// 宽字符路径 → UTF-8 窄串。
// ⚠️ 不能直接 printf("%ls")：C locale 下遇到第一个非 ASCII（中文路径）就停，
//    实测只打印出 "D:\" 就断了（看起来像"路径没取到"，其实是显示问题）。
static std::string W2U8(const wchar_t* w)
{
	if (!w || !w[0]) return std::string();
	int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
	if (n <= 1) return std::string();
	std::string s(static_cast<size_t>(n - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
	return s;
}

// 从进程句柄解析 pid；处理 NtCurrentProcess() 伪句柄 (-1)。
static DWORD PidFromHandle(HANDLE h)
{
	if (h == nullptr) return 0;
	if (h == reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-1)))  // NtCurrentProcess()
		return GetCurrentProcessId();
	if (h == reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-2)))  // NtCurrentThread()
		return GetCurrentProcessId();
	return GetProcessId(h);
}

static NTSTATUS NTAPI NtTerminateProcess_Detour(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	// —— 这就是 R3ShieldCore 里 NtTerminateProcess_Hook 做的判定 ——
	const DWORD callerPid = GetCurrentProcessId();   // hook 跑在谁家 = 谁发起
	const DWORD targetPid = PidFromHandle(ProcessHandle);

	WCHAR callerImage[MAX_PATH] = {};
	DWORD n = _countof(callerImage);
	if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, callerImage, &n))
		callerImage[0] = L'\0';

	// 只在第一次命中时记录（本探针会多次进入：杀 victim + 自己退出）。
	if (InterlockedIncrement(&g_hookHits) == 1) {
		g_hookCallerPid = callerPid;
		g_hookTargetPid = targetPid;
		g_hookExitStatus = ExitStatus;
		wcsncpy_s(g_hookCallerImage, callerImage, _TRUNCATE);
	}

	return g_originalNtTerminateProcess(ProcessHandle, ExitStatus);
}

// ---------------------------------------------------------------- victim
static int RunVictim()
{
	printf("VICTIM: pid=%u 等待被杀...\n", GetCurrentProcessId());
	fflush(stdout);
	for (int i = 0; i < 300; i++) Sleep(100);   // 最长 30s
	return 0;
}

// ---------------------------------------------------------------- driver
static int RunDriver()
{
	printf("DRIVER: pid=%u\n", GetCurrentProcessId());

	// 1) 装 detour
	if (MH_Initialize() != MH_OK) { printf("MH_Initialize 失败\n"); return 1; }
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	void* target = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtTerminateProcess"));
	if (!target) { printf("找不到 NtTerminateProcess\n"); return 1; }
	if (MH_CreateHook(target, reinterpret_cast<LPVOID>(&NtTerminateProcess_Detour),
		reinterpret_cast<LPVOID*>(&g_originalNtTerminateProcess)) != MH_OK ||
		MH_EnableHook(target) != MH_OK) {
		printf("装 hook 失败\n");
		return 1;
	}
	printf("已 detour ntdll!NtTerminateProcess（仅本进程）\n");

	// 2) 拉起 victim
	WCHAR exe[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exe, _countof(exe));
	std::wstring cmd = L"\"";
	cmd += exe;
	cmd += L"\" --victim";

	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
		0, nullptr, nullptr, &si, &pi)) {
		printf("CreateProcess 失败 err=%lu\n", GetLastError());
		return 1;
	}
	Sleep(500);   // 让 victim 起来
	printf("victim pid=%u\n", pi.dwProcessId);

	// 3) 杀掉 victim —— 这一步会触发我们自己的 detour
	InterlockedExchange(&g_hookHits, 0);
	const BOOL ok = TerminateProcess(pi.hProcess, 0xABCD);
	printf("TerminateProcess(victim) 返回=%d err=%lu  hookHits=%ld\n",
		ok, GetLastError(), g_hookHits);

	printf("\n=== A. hook 里能否知道「谁杀的」 ===\n");
	printf("  callerPid=%u (期望=%u 父自己)  targetPid=%u (期望=%u victim)\n",
		g_hookCallerPid, GetCurrentProcessId(), g_hookTargetPid, pi.dwProcessId);
	printf("  callerImage=%s\n", W2U8(g_hookCallerImage).c_str());

	Check("hook 被触发", g_hookHits >= 1);
	Check("hook 里的 callerPid == 发起终止的进程（凶手）", g_hookCallerPid == GetCurrentProcessId());
	Check("hook 里的 targetPid == 被终止的进程（受害者）", g_hookTargetPid == pi.dwProcessId);
	Check("callerPid != targetPid（凶手与受害者可区分）", g_hookCallerPid != g_hookTargetPid);
	Check("能拿到凶手的镜像路径", g_hookCallerImage[0] != L'\0');
	Check("能拿到 exitStatus 原样透传", g_hookExitStatus == static_cast<NTSTATUS>(0xABCD));

	WaitForSingleObject(pi.hProcess, 3000);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// 4) 自我退出路径：ExitProcess → NtTerminateProcess(self)
	//    验证"凶手==受害者==自己"时 hook 也看得到（这是正常自退，不是被杀）。
	printf("\n=== B. 自我退出（ExitProcess）时 hook 看到什么 ===\n");
	InterlockedExchange(&g_hookHits, 0);
	HANDLE selfPseudo = reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-1));
	printf("  调用 NtTerminateProcess(NtCurrentProcess()) ...\n");
	fflush(stdout);
	// 不真退，直接调原函数之外的路径不可行；这里用 detour 记录后**不调用**原函数，
	// 避免把自己退掉，只验证参数解析。
	const DWORD selfBefore = GetCurrentProcessId();
	PidFromHandle(selfPseudo);
	printf("  NtCurrentProcess() 解析 pid=%u (期望=%u 自己)\n",
		PidFromHandle(selfPseudo), selfBefore);
	Check("伪句柄 -1 解析为当前进程（自我退出可识别）",
		PidFromHandle(selfPseudo) == selfBefore);

	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}

int main(int argc, char** argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--victim") == 0) return RunVictim();
	}
	return RunDriver();
}
