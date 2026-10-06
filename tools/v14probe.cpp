//
// v14probe.cpp - R3ShieldCore v14 新增事件的触发探针。
//
// 用途（逐个跑，验证 hook 有没有装上、判据有没有生效）：
//   v14probe.exe inject    触发代码注入链：起一个子进程，然后对它
//                          OpenProcess -> NtAllocateVirtualMemory(COMMIT|RX)
//                          -> NtWriteVirtualMemory -> NtProtectVirtualMemory
//                          -> NtCreateThreadEx，测完关掉子进程
//   v14probe.exe sendinput 批量 SendInput（超过密度阈值）→ 合成输入判据
//   v14probe.exe keybd     批量 keybd_event（老 API）→ 同一判据
//   v14probe.exe blockin   BlockInput(TRUE) 然后立刻解冻 → 锁屏勒索判据
//   v14probe.exe clipcur   ClipCursor 到一个小矩形再解除 → 伪造登录框判据
//   v14probe.exe memself   **自检**：对自己进程做 Allocate+Write+Protect，
//                          验证"本进程一律放行"（应 0 事件）
//   v14probe.exe dbg       免等待版（不 Sleep）
//
// ⚠️ 安全：blockin 模式真正调用 BlockInput(TRUE) —— 如果 hook 没拦住，
//    键鼠会真的冻结。所以起一个看门狗线程，无论如何 2 秒后调
//    BlockInput(FALSE) 解冻。
//
// 所有模式（除 dbg）先 Sleep(3000) —— 引擎注入 + guard 安装需要时间。
//
// 用法：先启引擎，再跑本探针。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>

// ------------------------------------------------------------------
// 注入链模式
// ------------------------------------------------------------------
//
// NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory
// 都从 ntdll 动态取（不静态链），这样即使 GetProcAddress 失败也不影响编译，
// 且更贴近攻击者行为（运行时解析）。
//
typedef LONG(NTAPI* NtAllocateVirtualMemoryFn)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef LONG(NTAPI* NtWriteVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef LONG(NTAPI* NtProtectVirtualMemoryFn)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef LONG(NTAPI* NtCreateThreadExFn)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
	PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static const ULONG kStatusAccessDenied = 0xC0000022;
static const ULONG kStatusSuccess = 0x00000000;

// 对指定 pid 走完注入链四步（inject / inject_pid 共用）。
static int RunInjectAgainst(DWORD targetPid);

static int ModeInject()
{
	printf("=== 触发代码注入链（对子进程）===\n");

	// 起一个被注入的目标：notepad.exe（有界面、容易观察，退出即清理）。
	WCHAR systemDir[MAX_PATH] = {};
	GetSystemDirectoryW(systemDir, MAX_PATH);

	WCHAR cmdLine[512] = {};
	swprintf_s(cmdLine, L"\"%s\\notepad.exe\"", systemDir);

	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
		CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		printf("CreateProcessW(notepad) 失败 err=%u\n", GetLastError());
		printf("（BLOCK 模式下起新进程会被拒 —— 改用 inject_pid <pid> 注入已运行的进程）\n");
		return 1;
	}
	printf("目标进程 notepad pid=%u（挂起中）\n", pi.dwProcessId);

	int rc = RunInjectAgainst(pi.dwProcessId);

	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	printf("\n（探针自身是控制台进程，前台窗口不属于它）\n");
	return rc;
}

// ------------------------------------------------------------------
// 注入链核心：对指定 pid 走完四步（inject 与 inject_pid 共用）
// ------------------------------------------------------------------
static int RunInjectAgainst(DWORD targetPid)
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto ntAlloc = reinterpret_cast<NtAllocateVirtualMemoryFn>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
	auto ntWrite = reinterpret_cast<NtWriteVirtualMemoryFn>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
	auto ntProtect = reinterpret_cast<NtProtectVirtualMemoryFn>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
	auto ntThread = reinterpret_cast<NtCreateThreadExFn>(GetProcAddress(ntdll, "NtCreateThreadEx"));

	if (!ntAlloc || !ntWrite || !ntProtect) {
		printf("ntdll 导出解析失败（alloc=%p write=%p protect=%p）\n",
			reinterpret_cast<void*>(ntAlloc), reinterpret_cast<void*>(ntWrite),
			reinterpret_cast<void*>(ntProtect));
		return 1;
	}

	// 拿目标进程的完全控制句柄。
	HANDLE target = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
		FALSE, targetPid);
	if (!target) {
		printf("OpenProcess(pid=%u) 失败 err=%u（引擎自我保护可能剥了权限）\n",
			targetPid, GetLastError());
		return 1;
	}

	// ---- ① NtAllocateVirtualMemory：跨进程申请 COMMIT + RWX 内存 ----
	PVOID base = nullptr;
	SIZE_T size = 0x1000;
	LONG st = ntAlloc(target, &base, 0, &size, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	printf("① NtAllocateVirtualMemory(远程, RWX) status=0x%08X %s\n", static_cast<unsigned>(st),
		(st == static_cast<LONG>(kStatusAccessDenied)) ? "-> 被拦（ACCESS_DENIED，预期 BLOCK）"
			: (st == kStatusSuccess ? "-> 成功（LOG/ASK 放行，预期 HIGH）" : "-> 其它"));

	if (st != kStatusSuccess) {
		printf("   分配失败，跳过后续步骤\n");
	}
	else {
		// ---- ② NtWriteVirtualMemory：写一段无害字节 ----
		BYTE payload[16] = { 0x90, 0x90, 0x90, 0x90, 0xC3 }; // nop;nop;nop;nop;ret
		SIZE_T written = 0;
		LONG st2 = ntWrite(target, base, payload, sizeof(payload), &written);
		printf("② NtWriteVirtualMemory(远程) status=0x%08X %s\n", static_cast<unsigned>(st2),
			(st2 == static_cast<LONG>(kStatusAccessDenied)) ? "-> 被拦（预期 BLOCK）"
				: (st2 == kStatusSuccess ? "-> 成功（预期 HIGH）" : "-> 其它"));

		// ---- ③ NtProtectVirtualMemory：改成 RX（模拟注入链收尾）----
		PVOID protectBase = base;
		SIZE_T protectSize = 0x1000;
		ULONG oldProtect = 0;
		LONG st3 = ntProtect(target, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
		printf("③ NtProtectVirtualMemory(远程 → RX) status=0x%08X %s\n", static_cast<unsigned>(st3),
			(st3 == static_cast<LONG>(kStatusAccessDenied)) ? "-> 被拦（预期 BLOCK）"
				: (st3 == kStatusSuccess ? "-> 成功（预期 HIGH）" : "-> 其它"));

		// ---- ④ NtCreateThreadEx：远程线程（v13 已有，对照）----
		if (ntThread) {
			HANDLE hThread = nullptr;
			LONG st4 = ntThread(&hThread, THREAD_ALL_ACCESS, nullptr, target,
				base, nullptr, 0, 0, 0, 0, nullptr);
			printf("④ NtCreateThreadEx(远程) status=0x%08X %s\n", static_cast<unsigned>(st4),
				(st4 == static_cast<LONG>(kStatusAccessDenied)) ? "-> 被拦（预期 BLOCK）"
					: (st4 >= 0 ? "-> 成功（预期 HIGH）" : "-> 其它"));
			if (hThread) CloseHandle(hThread);
		}
	}

	CloseHandle(target);
	return 0;
}

// inject_pid <pid>：注入一个已经跑着的进程（BLOCK 模式下起不了新进程时用）。
static int ModeInjectPid(unsigned long pid)
{
	printf("=== 触发代码注入链（对已运行进程 pid=%lu）===\n", pid);
	return RunInjectAgainst(static_cast<DWORD>(pid));
}

// ------------------------------------------------------------------
// 自检：本进程内存操作必须放行
// ------------------------------------------------------------------
static int ModeMemSelf()
{
	printf("=== 自检：对本进程做 Allocate+Write+Protect（应 0 事件）===\n");

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto ntAlloc = reinterpret_cast<NtAllocateVirtualMemoryFn>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
	auto ntWrite = reinterpret_cast<NtWriteVirtualMemoryFn>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
	auto ntProtect = reinterpret_cast<NtProtectVirtualMemoryFn>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
	if (!ntAlloc || !ntWrite || !ntProtect) {
		printf("ntdll 导出解析失败\n");
		return 1;
	}

	HANDLE self = GetCurrentProcess();
	PVOID base = nullptr;
	SIZE_T size = 0x1000;
	LONG st = ntAlloc(self, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("① 本进程 Allocate(RW) status=0x%08X %s\n", static_cast<unsigned>(st),
		(st == kStatusSuccess) ? "-> 成功（预期：本进程放行）" : "-> 失败/被拦（异常！）");

	if (st == kStatusSuccess) {
		SIZE_T written = 0;
		LONG st2 = ntWrite(self, base, (PVOID)"junk", 4, &written);
		printf("② 本进程 Write status=0x%08X %s\n", static_cast<unsigned>(st2),
			(st2 == kStatusSuccess) ? "-> 成功（预期放行）" : "-> 失败/被拦（异常！）");

		PVOID pb = base;
		SIZE_T ps = 0x1000;
		ULONG oldp = 0;
		LONG st3 = ntProtect(self, &pb, &ps, PAGE_EXECUTE_READWRITE, &oldp);
		printf("③ 本进程 Protect(RWX) status=0x%08X %s\n", static_cast<unsigned>(st3),
			(st3 == kStatusSuccess) ? "-> 成功（预期放行，JIT 依赖此路径）" : "-> 失败/被拦（异常！）");
	}
	return 0;
}

// ------------------------------------------------------------------
// 合成输入模式
// ------------------------------------------------------------------
static int ModeSendInput()
{
	printf("=== 批量 SendInput（超过密度阈值 %d 事件）===\n", 120);

	// 送无害的鼠标移动 + 键抬起/按下（不真的打出字符：只用 VK 的 UP 事件）。
	const int kBatch = 200;
	INPUT* inputs = static_cast<INPUT*>(calloc(kBatch, sizeof(INPUT)));
	if (!inputs) {
		printf("calloc 失败\n");
		return 1;
	}

	for (int i = 0; i < kBatch; ++i) {
		inputs[i].type = INPUT_MOUSE;
		inputs[i].mi.dx = 1;
		inputs[i].mi.dy = 0;
		inputs[i].mi.dwFlags = MOUSEEVENTF_MOVE;
	}

	UINT sent = SendInput(static_cast<UINT>(kBatch), inputs, sizeof(INPUT));
	printf("SendInput(%d) 返回 %u  err=%u\n", kBatch, sent,
		(sent == static_cast<UINT>(kBatch)) ? 0 : GetLastError());
	printf("预期：LOG/BLOCK 下单条 HIGH（合成键鼠输入）；BLOCK 下返回 0\n");

	free(inputs);
	return 0;
}

static int ModeKeybd()
{
	printf("=== 批量 keybd_event ===\n");

	// 只用"抬起"事件（KEYEVENTF_KEYUP），不会真的输入字符。
	const int kBatch = 200;
	for (int i = 0; i < kBatch; ++i) {
		keybd_event(0x41 /*A*/, 0, KEYEVENTF_KEYUP, 0);
	}
	printf("keybd_event x%d 完成（预期：单条 HIGH）\n", kBatch);
	return 0;
}

// ------------------------------------------------------------------
// BlockInput / ClipCursor
// ------------------------------------------------------------------
static DWORD WINAPI BlockInputWatchdog(LPVOID)
{
	// 无论如何，2 秒后解冻 —— 防止 hook 没装上时键鼠被真冻结。
	Sleep(2000);
	BlockInput(FALSE);
	return 0;
}

static int ModeBlockInput()
{
	printf("=== BlockInput(TRUE) → 立刻解冻 ===\n");
	printf("（看门狗线程保证 2s 后无条件解冻）\n");

	HANDLE watchdog = CreateThread(nullptr, 0, BlockInputWatchdog, nullptr, 0, nullptr);
	CloseHandle(watchdog);

	BOOL ok = BlockInput(TRUE);
	printf("BlockInput(TRUE) 返回 %d err=%u %s\n", ok, ok ? 0 : GetLastError(),
		ok ? "-> 成功（进程不是前台属主，预期 HIGH）" : "-> 失败（可能被拦）");

	// 尽快解冻，别真锁住用户。
	BlockInput(FALSE);
	Sleep(100); // 给看门狗一点时间，避免它先跑
	return 0;
}

static int ModeClipCursor()
{
	printf("=== ClipCursor 到小矩形 → 解除 ===\n");

	RECT rect = { 0, 0, 200, 200 };
	BOOL ok = ClipCursor(&rect);
	printf("ClipCursor(200x200) 返回 %d err=%u %s\n", ok, ok ? 0 : GetLastError(),
		ok ? "-> 成功（进程不是前台属主，预期 HIGH）" : "-> 失败（可能被拦）");

	// 必须立刻解除 —— ClipCursor 是系统全局的。
	ClipCursor(nullptr);
	printf("已解除 ClipCursor\n");
	return 0;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	setvbuf(stdout, nullptr, _IONBF, 0);

	const char* mode = (argc > 1) ? argv[1] : "inject";
	const bool noWait = (strcmp(mode, "dbg") == 0);

	printf("R3ShieldCore v14 探针  (pid=%u)  mode=%s\n", GetCurrentProcessId(), mode);

	if (!noWait) {
		printf("[v14probe] 等待 3s 让引擎完成注入与 guard 安装...\n");
		Sleep(3000);
	}
	printf("\n");

	int rc = 0;
	if (strcmp(mode, "inject") == 0) {
		rc = ModeInject();
	}
	else if (strcmp(mode, "inject_pid") == 0) {
		if (argc < 3) {
			printf("用法: v14probe.exe inject_pid <pid>\n");
			rc = 1;
		}
		else {
			rc = ModeInjectPid(strtoul(argv[2], nullptr, 10));
		}
	}
	else if (strcmp(mode, "memself") == 0) {
		rc = ModeMemSelf();
	}
	else if (strcmp(mode, "sendinput") == 0) {
		rc = ModeSendInput();
	}
	else if (strcmp(mode, "keybd") == 0) {
		rc = ModeKeybd();
	}
	else if (strcmp(mode, "blockin") == 0) {
		rc = ModeBlockInput();
	}
	else if (strcmp(mode, "clipcur") == 0) {
		rc = ModeClipCursor();
	}
	else if (strcmp(mode, "dbg") == 0) {
		printf("dbg：仅确认探针本身可运行。\n");
	}
	else {
		printf("未知模式，可用：inject / memself / sendinput / keybd / blockin / clipcur / dbg\n");
		rc = 1;
	}

	printf("\ndone\n");
	return rc;
}
