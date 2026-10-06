//
// terminate_block_probe.cpp —— 实证：detour NtTerminateProcess 到底能不能「拦」。
//
// 三个问题，逐个实测（不能靠文档）：
//   A. 拦「跨进程杀」：在 detour 里**不调原函数**、直接返回 STATUS_ACCESS_DENIED，
//      目标进程是否真的活下来？调用方拿到什么？
//   B. 对照：不拦时同一动作确实能把目标杀掉（证明 A 的"活下来"是拦的结果，
//      不是别的原因）。
//   C. 坑：ExitProcess 自我退出**也走** NtTerminateProcess。
//      如果无差别拦截（连 target==self 也拦），进程还能不能正常退出？
//      —— 这是"该不该拦"的关键。
//
// 用法：
//   --victim   子进程：死循环，等被杀。
//   --suicide  子进程：在自己进程里拦「自我退出」，然后调 ExitProcess。
//   （无参数） 父进程：跑 A / B / C。
//
// 只碰自己拉起的子进程。

#include <windows.h>
#include <stdio.h>
#include <string>
#include <MinHook.h>

// 不 include <ntstatus.h>（与 winnt.h 冲突），照 process_guard.cpp 的做法直接定义。
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

typedef NTSTATUS(NTAPI* NtTerminateProcessPtr)(HANDLE, NTSTATUS);
static NtTerminateProcessPtr g_orig = nullptr;

static int g_pass = 0;
static int g_fail = 0;

static volatile LONG g_blockCross = 0;   // 1 = 拦「杀别人」
static volatile LONG g_blockSelf  = 0;   // 1 = 连「自杀」也拦
static volatile LONG g_blockedCount = 0;
static volatile LONG g_selfBlocked  = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

static DWORD PidFromHandle(HANDLE h)
{
	if (h == nullptr) return 0;
	const INT_PTR v = reinterpret_cast<INT_PTR>(h);
	if (v == -1 || v == -2) return GetCurrentProcessId();  // NtCurrentProcess/Thread
	return GetProcessId(h);
}

static NTSTATUS NTAPI Detour(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	const DWORD self = GetCurrentProcessId();
	const DWORD target = PidFromHandle(ProcessHandle);
	const bool isSelf = (target == self);

	// 拦「杀别人」：不调原函数，直接拒 —— 这就是"拦截"的全部。
	if (g_blockCross && !isSelf && target != 0) {
		InterlockedIncrement(&g_blockedCount);
		return STATUS_ACCESS_DENIED;
	}
	// 拦「自杀」：无差别拦截的最坏形态。
	if (g_blockSelf && isSelf) {
		InterlockedIncrement(&g_selfBlocked);
		return STATUS_ACCESS_DENIED;
	}
	return g_orig(ProcessHandle, ExitStatus);
}

// ------------------------------------------------------------ 子进程角色
static int RunVictim()
{
	printf("VICTIM pid=%u 等待被杀\n", GetCurrentProcessId());
	fflush(stdout);
	for (int i = 0; i < 600; i++) Sleep(100);   // 最长 60s
	return 0;
}

// 子进程：在自己进程里拦「自我退出」。分两步，把机制钉死。
//   ① 直接调 export NtTerminateProcess(NtCurrentProcess(),0)
//      → 若返回 0xC0000022，说明 detour **确实拦得住"自杀调用"**（子进程活下来）。
//   ② 再调 ExitProcess(0)（保持拦截开启）
//      → 观察它到底怎么死、退出码是什么（这是"该不该拦"的关键）。
//   ①的结果写进 outFile（父进程读），②的结果靠退出码。
static int RunSuicide(const wchar_t* outFile)
{
	if (MH_Initialize() != MH_OK) return 2;
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	void* t = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtTerminateProcess"));
	if (!t || MH_CreateHook(t, reinterpret_cast<LPVOID>(&Detour),
		reinterpret_cast<LPVOID*>(&g_orig)) != MH_OK ||
		MH_EnableHook(t) != MH_OK) {
		return 2;
	}
	InterlockedExchange(&g_blockSelf, 1);

	// ① 直接调用被 detour 的导出（GetProcAddress 拿到的是 detour 后的地址）
	typedef NTSTATUS(NTAPI* Fn)(HANDLE, NTSTATUS);
	Fn hooked = reinterpret_cast<Fn>(t);
	const NTSTATUS direct = hooked(reinterpret_cast<HANDLE>(static_cast<INT_PTR>(-1)), 0);

	FILE* f = nullptr;
	_wfopen_s(&f, outFile, L"w");
	if (f) {
		fprintf(f, "direct=0x%08lX selfBlocked=%ld\n",
			static_cast<unsigned long>(direct), g_selfBlocked);
		fclose(f);
	}
	printf("SUICIDE: ① 直接调 export(NtCurrentProcess) -> 0x%08lX selfBlocked=%ld\n",
		static_cast<unsigned long>(direct), g_selfBlocked);
	printf("SUICIDE: ② 调 ExitProcess(0)（拦截保持开启）...\n");
	fflush(stdout);

	ExitProcess(0);            // → RtlExitUserProcess → NtTerminateProcess(self)
	printf("SUICIDE: ExitProcess 居然返回了\n");   // 理论到不了
	fflush(stdout);
	return 3;
}

// ------------------------------------------------------------ 工具
static bool SpawnSelf(const wchar_t* arg, PROCESS_INFORMATION* pi)
{
	WCHAR exe[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exe, _countof(exe));
	std::wstring cmd = L"\"";
	cmd += exe;
	cmd += L"\" ";
	cmd += arg;

	STARTUPINFOW si = { sizeof(si) };
	*pi = {};
	if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
		0, nullptr, nullptr, &si, pi)) {
		printf("CreateProcess(%ls) 失败 err=%lu\n", arg, GetLastError());
		return false;
	}
	Sleep(600);   // 等子进程起来 / 装好 hook
	return true;
}

static bool IsAlive(HANDLE h)
{
	DWORD code = 0;
	if (!GetExitCodeProcess(h, &code)) return false;
	return code == STILL_ACTIVE;
}

int main(int argc, char** argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--victim") == 0)  return RunVictim();
		if (strcmp(argv[i], "--suicide") == 0) {
			WCHAR out[MAX_PATH] = {};
			if (i + 1 < argc) MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, out, _countof(out));
			return RunSuicide(out);
		}
	}

	printf("DRIVER pid=%u\n\n", GetCurrentProcessId());

	if (MH_Initialize() != MH_OK) { printf("MH_Initialize 失败\n"); return 1; }
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	void* target = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtTerminateProcess"));
	if (!target || MH_CreateHook(target, reinterpret_cast<LPVOID>(&Detour),
		reinterpret_cast<LPVOID*>(&g_orig)) != MH_OK) {
		printf("装 hook 失败\n");
		return 1;
	}

	// ---- A. 拦「跨进程杀」----
	printf("=== A. detour 里返回 STATUS_ACCESS_DENIED，目标还活不活？ ===\n");
	InterlockedExchange(&g_blockCross, 1);
	MH_EnableHook(target);

	PROCESS_INFORMATION a = {};
	if (!SpawnSelf(L"--victim", &a)) return 1;
	printf("  victim pid=%u\n", a.dwProcessId);

	InterlockedExchange(&g_blockedCount, 0);
	const BOOL aOk = TerminateProcess(a.hProcess, 0);
	const DWORD aErr = GetLastError();
	Sleep(800);   // 给它足够时间"如果真的被杀掉"就死透
	const bool aAlive = IsAlive(a.hProcess);
	printf("  TerminateProcess 返回=%d err=%lu  blockedCount=%ld  目标存活=%d\n",
		aOk, aErr, g_blockedCount, aAlive);
	Check("detour 被触发并拒绝", g_blockedCount >= 1);
	Check("TerminateProcess 返回失败（拦住了）", aOk == FALSE);
	Check("目标进程仍然存活（拦真的生效了）", aAlive);
	printf("  调用方拿到 err=%lu (期望 5=ERROR_ACCESS_DENIED)\n", aErr);
	Check("调用方错误码 = 5 (ERROR_ACCESS_DENIED)", aErr == 5);

	// 清理：先撤 hook 才能杀掉
	MH_DisableHook(target);
	InterlockedExchange(&g_blockCross, 0);
	TerminateProcess(a.hProcess, 0);
	WaitForSingleObject(a.hProcess, 3000);
	CloseHandle(a.hProcess); CloseHandle(a.hThread);

	// ---- B. 对照：不拦 ----
	printf("\n=== B. 对照：不拦，同一动作确实能杀掉 ===\n");
	PROCESS_INFORMATION b = {};
	if (!SpawnSelf(L"--victim", &b)) return 1;
	const BOOL bOk = TerminateProcess(b.hProcess, 0);
	Sleep(800);
	const bool bAlive = IsAlive(b.hProcess);
	printf("  TerminateProcess 返回=%d  目标存活=%d\n", bOk, bAlive);
	Check("不拦时 TerminateProcess 成功", bOk == TRUE);
	Check("不拦时目标确实死掉", !bAlive);
	CloseHandle(b.hProcess); CloseHandle(b.hThread);

	// ---- C. 坑：无差别拦「自杀」----
	printf("\n=== C. 自我退出也走 NtTerminateProcess —— 无差别拦会怎样？ ===\n");

	WCHAR tmpDir[MAX_PATH] = {};
	GetTempPathW(_countof(tmpDir), tmpDir);
	WCHAR outFile[MAX_PATH] = {};
	swprintf_s(outFile, L"%sterminate_block_probe_c1.txt", tmpDir);
	DeleteFileW(outFile);

	WCHAR arg[2 * MAX_PATH] = {};
	swprintf_s(arg, L"--suicide \"%s\"", outFile);

	PROCESS_INFORMATION c = {};
	if (!SpawnSelf(arg, &c)) return 1;
	const DWORD w = WaitForSingleObject(c.hProcess, 5000);
	DWORD code = 0;
	GetExitCodeProcess(c.hProcess, &code);

	// 读子进程 ① 步的结果
	char buf[160] = {};
	unsigned long direct = 0;
	long selfBlocked = -1;
	{
		FILE* f = nullptr;
		_wfopen_s(&f, outFile, L"r");
		if (f) { fgets(buf, sizeof(buf), f); fclose(f); }
		if (buf[0]) sscanf_s(buf, "direct=0x%lX selfBlocked=%ld", &direct, &selfBlocked);
	}

	printf("  ① 直接调 export(NtCurrentProcess) -> %s\n",
		buf[0] ? buf : "(子进程没写出结果)");
	printf("  ② ExitProcess 结果: %s  exitCode=%lu (0x%08lX)\n",
		w == WAIT_OBJECT_0 ? "已退出" : "仍存活（卡住）", code, code);

	Check("detour 拦得住「自杀调用」（直接调返回 ACCESS_DENIED）",
		direct == 0xC0000022UL);
	Check("拦自杀确实被触发（selfBlocked >= 1）", selfBlocked >= 1);
	Check("② 拦了自杀，ExitProcess 仍能退出（不会把进程卡死）",
		w == WAIT_OBJECT_0);
	Check("★ 但退出码被破坏（不是 0，是异常码）", code != 0);
	if (w != WAIT_OBJECT_0) {
		TerminateProcess(c.hProcess, 0);   // 父进程此时没开 hook，能杀
		WaitForSingleObject(c.hProcess, 3000);
	}
	CloseHandle(c.hProcess); CloseHandle(c.hThread);
	DeleteFileW(outFile);

	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
