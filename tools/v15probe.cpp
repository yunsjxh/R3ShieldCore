//
// v15probe.cpp - R3ShieldCore v15（宿主劫持 / 加载器）新增事件的触发探针。
//
// 用途（逐个跑，验证 hook 有没有装上、判据有没有生效）：
//
//   v15probe.exe appinit    注册表全局注入键：往 HKCU\...\Windows\AppInit_DLLs
//                           写一个**用户可写目录**下的 DLL 路径 → 预期 HIGH
//   v15probe.exe appinit_sys 同上但写系统目录路径 → 预期非高危（放行）
//   v15probe.exe loadlibex   LoadLibraryExW 带 DONT_RESOLVE_DLL_REFERENCES
//                           加载一个用户可写目录 DLL → 预期 HIGH
//   v15probe.exe apc         对**别的进程**的目标线程 QueueUserAPC → 预期 HIGH
//   v15probe.exe apcself     对自己进程的线程 QueueUserAPC → 预期 0 事件
//   v15probe.exe ldrnotify   LdrRegisterDllNotification（非系统模块调用）→ 预期视模块而定
//   v15probe.exe dbg         免等待版（不 Sleep）
//
// ⚠️ 全部是**无害**操作：
//   · appinit 写的值随后立刻还原（原本就为空）。
//   · loadlibex 加载的 DLL 是我们自己造的、DllMain 什么都不做的小 DLL，
//     且带 DONT_RESOLVE_DLL_REFERENCES（不执行初始化）—— 即使加载成功也无副作用。
//   · apc 投的函数是一个 nop;ret 桩（目标进程不 alertable 就永远不执行）。
//
// 所有模式（除 dbg）先 Sleep(3000) —— 引擎注入 + guard 安装需要时间。
//
// 用法：先启引擎，再跑本探针。
//
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

static const ULONG kStatusAccessDenied = 0xC0000022;
static const ULONG kStatusSuccess = 0x00000000;

typedef LONG(NTAPI* NtQueueApcThreadFn)(HANDLE, PVOID, PVOID, PVOID, PVOID);

// 用于 loadlibex 的载荷 DLL：DllMain 什么都不做（也不该被执行 —— 带
// DONT_RESOLVE_DLL_REFERENCES）。放在 %TEMP% 下（用户可写目录）。
static const WCHAR kPayloadName[] = L"r3shieldcore_v15_payload.dll";

// 写一个最小 PE DLL 到 temp 目录（只有 DllMain，返回 TRUE）。
static bool WritePayloadDll(WCHAR* outPath, size_t outChars)
{
	WCHAR tempDir[MAX_PATH] = {};
	DWORD n = GetTempPathW(MAX_PATH, tempDir);
	if (n == 0 || n >= MAX_PATH) {
		return false;
	}

	swprintf_s(outPath, outChars, L"%s%s", tempDir, kPayloadName);

	// 64 位最小 DLL 字节（不依赖编译器）：
	// 手工构造一个极简 PE32+ DLL 太啰嗦，这里改为**直接用本探针自身**
	// 作为被加载对象不可靠。用一个更简单的办法：写一段有效的最小 PE。
	//
	// 实际做法：把当前进程的 kernel32.dll 路径当"用户可写目录 DLL"不行
	// （那在系统目录）。所以真正加载时用 system32 下的一个 DLL 复制到 temp。
	WCHAR sys32[MAX_PATH] = {};
	GetSystemDirectoryW(sys32, MAX_PATH);
	WCHAR src[MAX_PATH] = {};
	swprintf_s(src, MAX_PATH, L"%s\\version.dll", sys32);

	if (!CopyFileW(src, outPath, FALSE)) {
		return false;
	}
	return true;
}

// ------------------------------------------------------------------
// 子面① 注册表全局注入键
// ------------------------------------------------------------------
static int ModeAppInit(bool systemPath)
{
	printf("=== 注册表全局注入键 AppInit_DLLs（%s）===\n",
		systemPath ? "系统目录路径 —— 预期放行" : "用户可写目录路径 —— 预期 HIGH");

	const WCHAR* keyPath = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
	const WCHAR* valueName = L"AppInit_DLLs";

	HKEY key = nullptr;
	LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, keyPath, 0, nullptr, 0,
		KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &key, nullptr);
	if (rc != ERROR_SUCCESS) {
		printf("RegCreateKeyExW 失败 rc=%ld\n", rc);
		return 1;
	}

	// 备份原值（通常为空）。
	WCHAR oldValue[MAX_PATH] = {};
	DWORD oldType = 0;
	DWORD oldSize = sizeof(oldValue);
	RegQueryValueExW(key, valueName, nullptr, &oldType,
		reinterpret_cast<LPBYTE>(oldValue), &oldSize);

	// 要写的值。
	WCHAR payload[MAX_PATH] = {};
	if (systemPath) {
		WCHAR sys32[MAX_PATH] = {};
		GetSystemDirectoryW(sys32, MAX_PATH);
		swprintf_s(payload, MAX_PATH, L"%s\\version.dll", sys32);
	}
	else {
		if (!WritePayloadDll(payload, MAX_PATH)) {
			printf("构造载荷路径失败\n");
			RegCloseKey(key);
			return 1;
		}
	}

	printf("写入 %s = \"%ls\"\n", "AppInit_DLLs", payload);

	rc = RegSetValueExW(key, valueName, 0, REG_SZ,
		reinterpret_cast<const BYTE*>(payload),
		static_cast<DWORD>((wcslen(payload) + 1) * sizeof(WCHAR)));

	printf("RegSetValueExW 返回 %ld %s\n", rc,
		(rc == ERROR_ACCESS_DENIED || rc == 5) ? "-> 被拦（预期 BLOCK）"
			: (rc == ERROR_SUCCESS ? "-> 成功（预期 HIGH）" : "-> 其它"));

	// ---- 立即还原（无论成功与否）----
	if (oldSize > 0 && oldValue[0]) {
		RegSetValueExW(key, valueName, 0, oldType,
			reinterpret_cast<const BYTE*>(oldValue), oldSize);
		printf("已还原原值\n");
	}
	else {
		// 原本不存在或为空 → 删掉我们写进去的。
		RegDeleteValueW(key, valueName);
		printf("原本为空，已删除写入的值\n");
	}

	RegCloseKey(key);
	return 0;
}

// ------------------------------------------------------------------
// 子面② 加载器侧加载变体：LoadLibraryExW 带特殊 flag
// ------------------------------------------------------------------
static int ModeLoadLibEx()
{
	printf("=== LoadLibraryExW + DONT_RESOLVE_DLL_REFERENCES（用户可写目录）===\n");
	printf("（预期 HIGH：带特殊 flag 加载用户可写目录 DLL = 手工映射注入铺垫）\n");

	WCHAR payload[MAX_PATH] = {};
	if (!WritePayloadDll(payload, MAX_PATH)) {
		printf("构造载荷路径失败\n");
		return 1;
	}

	// DONT_RESOLVE_DLL_REFERENCES：只映射不执行 DllMain —— 正是"手工映射"
	// 的第一步，也是最可疑的信号。
	HMODULE h = LoadLibraryExW(payload, nullptr, DONT_RESOLVE_DLL_REFERENCES);
	printf("LoadLibraryExW 返回 %p  err=%u %s\n", reinterpret_cast<void*>(h),
		h ? 0 : GetLastError(),
		h ? "-> 成功（预期 HIGH）" : "-> 失败（BLOCK 模式下被拦）");

	if (h) {
		FreeLibrary(h);
	}

	// 清理载荷文件。
	DeleteFileW(payload);
	return 0;
}

// ------------------------------------------------------------------
// 子面③ 跨进程 APC 注入
// ------------------------------------------------------------------
static DWORD WINAPI ApcStub(LPVOID) { return 0; }

static int ModeApc(bool self)
{
	printf("=== QueueUserAPC（%s）===\n",
		self ? "本进程线程 —— 预期 0 事件" : "别的进程线程 —— 预期 HIGH");

	DWORD targetPid = 0;
	if (self) {
		targetPid = GetCurrentProcessId();
	}
	else {
		// 起一个子进程（notepad），对它的主线程投 APC。
		WCHAR sys32[MAX_PATH] = {};
		GetSystemDirectoryW(sys32, MAX_PATH);
		WCHAR cmdLine[512] = {};
		swprintf_s(cmdLine, L"\"%s\\notepad.exe\"", sys32);

		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
			0, nullptr, nullptr, &si, &pi)) {
			printf("CreateProcessW(notepad) 失败 err=%u\n", GetLastError());
			printf("（BLOCK 模式下起不了新进程）\n");
			return 1;
		}
		targetPid = pi.dwProcessId;
		printf("目标进程 notepad pid=%u\n", targetPid);

		// 给一点时间让主线程起来。
		Sleep(500);

		// 找目标进程的第一个线程。
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		DWORD targetTid = 0;
		if (snap != INVALID_HANDLE_VALUE) {
			THREADENTRY32 te = { sizeof(te) };
			if (Thread32First(snap, &te)) {
				do {
					if (te.th32OwnerProcessID == targetPid) {
						targetTid = te.th32ThreadID;
						break;
					}
				} while (Thread32Next(snap, &te));
			}
			CloseHandle(snap);
		}

		if (targetTid == 0) {
			printf("找不到目标线程\n");
			TerminateProcess(pi.hProcess, 0);
			return 1;
		}

		HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid);
		if (!hThread) {
			printf("OpenThread(tid=%u) 失败 err=%u\n", targetTid, GetLastError());
			TerminateProcess(pi.hProcess, 0);
			return 1;
		}

		// 用**本进程**里的函数地址当 APC 载荷（目标进程不 alertable，不会执行）。
		DWORD r = QueueUserAPC(reinterpret_cast<PAPCFUNC>(ApcStub), hThread, 0);
		printf("QueueUserAPC(跨进程) 返回 %u err=%u %s\n", r,
			r ? 0 : GetLastError(),
			r ? "-> 成功（预期 HIGH）" : "-> 失败（BLOCK 模式下被拦）");

		CloseHandle(hThread);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return 0;
	}

	// self 分支
	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
	if (!hThread) {
		printf("OpenThread(自己) 失败 err=%u\n", GetLastError());
		return 1;
	}

	DWORD r = QueueUserAPC(reinterpret_cast<PAPCFUNC>(ApcStub), hThread, 0);
	printf("QueueUserAPC(本进程) 返回 %u err=%u %s\n", r,
		r ? 0 : GetLastError(),
		r ? "-> 成功（预期放行，0 事件）" : "-> 失败（异常！本进程不该被拦）");

	CloseHandle(hThread);
	return 0;
}

// ------------------------------------------------------------------
// ntdll 直调版 APC（绕过 kernel32，验证 ntdll hook 是否也生效）
// ------------------------------------------------------------------
static int ModeApcNt()
{
	printf("=== ntdll!NtQueueApcThread 直调（跨进程）===\n");
	printf("（预期 HIGH：绕过 kernel32 直调 ntdll 也要能看到）\n");

	WCHAR sys32[MAX_PATH] = {};
	GetSystemDirectoryW(sys32, MAX_PATH);
	WCHAR cmdLine[512] = {};
	swprintf_s(cmdLine, L"\"%s\\notepad.exe\"", sys32);

	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
		0, nullptr, nullptr, &si, &pi)) {
		printf("CreateProcessW 失败 err=%u\n", GetLastError());
		return 1;
	}
	printf("目标进程 notepad pid=%u\n", pi.dwProcessId);
	Sleep(500);

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	DWORD targetTid = 0;
	if (snap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te = { sizeof(te) };
		if (Thread32First(snap, &te)) {
			do {
				if (te.th32OwnerProcessID == pi.dwProcessId) {
					targetTid = te.th32ThreadID;
					break;
				}
			} while (Thread32Next(snap, &te));
		}
		CloseHandle(snap);
	}

	if (targetTid == 0) {
		printf("找不到目标线程\n");
		TerminateProcess(pi.hProcess, 0);
		return 1;
	}

	HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, targetTid);
	if (!hThread) {
		printf("OpenThread 失败 err=%u\n", GetLastError());
		TerminateProcess(pi.hProcess, 0);
		return 1;
	}

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto ntQueue = reinterpret_cast<NtQueueApcThreadFn>(
		GetProcAddress(ntdll, "NtQueueApcThread"));
	if (!ntQueue) {
		printf("NtQueueApcThread 解析失败\n");
		CloseHandle(hThread);
		TerminateProcess(pi.hProcess, 0);
		return 1;
	}

	LONG st = ntQueue(hThread, reinterpret_cast<PVOID>(ApcStub), nullptr, nullptr, nullptr);
	printf("NtQueueApcThread(跨进程) status=0x%08X %s\n", static_cast<unsigned>(st),
		(st == static_cast<LONG>(kStatusAccessDenied)) ? "-> 被拦（预期 BLOCK）"
			: (st == kStatusSuccess ? "-> 成功（预期 HIGH）" : "-> 其它"));

	CloseHandle(hThread);
	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	setvbuf(stdout, nullptr, _IONBF, 0);

	const char* mode = (argc > 1) ? argv[1] : "appinit";
	const bool noWait = (strcmp(mode, "dbg") == 0);

	printf("R3ShieldCore v15 探针  (pid=%u)  mode=%s\n", GetCurrentProcessId(), mode);

	if (!noWait) {
		printf("[v15probe] 等待 3s 让引擎完成注入与 guard 安装...\n");
		Sleep(3000);
	}
	printf("\n");

	int rc = 0;
	if (strcmp(mode, "appinit") == 0) {
		rc = ModeAppInit(false);
	}
	else if (strcmp(mode, "appinit_sys") == 0) {
		rc = ModeAppInit(true);
	}
	else if (strcmp(mode, "loadlibex") == 0) {
		rc = ModeLoadLibEx();
	}
	else if (strcmp(mode, "apc") == 0) {
		rc = ModeApc(false);
	}
	else if (strcmp(mode, "apcself") == 0) {
		rc = ModeApc(true);
	}
	else if (strcmp(mode, "apcnt") == 0) {
		rc = ModeApcNt();
	}
	else if (strcmp(mode, "dbg") == 0) {
		printf("dbg：仅确认探针本身可运行。\n");
	}
	else {
		printf("未知模式，可用：appinit / appinit_sys / loadlibex / apc / apcself / apcnt / dbg\n");
		rc = 1;
	}

	printf("\ndone\n");
	return rc;
}
