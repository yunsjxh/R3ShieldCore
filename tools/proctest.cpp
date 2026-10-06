//
// proctest.cpp - 进程 / 线程 / 驱动监控验证探针。
//
// 目的：验证 process_guard / driver_guard 的行为 —— 普通创建只记录、
// 高危创建走询问、远程线程注入被识别、非系统驱动加载被识别。
//
// 关键：本 exe 必须放在 C:\Windows 之外，否则被判为系统程序，一个 hook 都不挂。
//
// 用例：
//   proc-cmd      [普通] CreateProcess 起一个 cmd（正常来源 = 探针自己所在的目录）
//   proc-sys      [高危] CreateProcess 起 C:\Windows\System32\cmd.exe
//   proc-temp     [高危] 把自身副本复制到 %TEMP% 再起它
//   thread-remote [高危] 向别的进程注入远程线程（用 CreateRemoteThread，最简单）
//   thread-self   [对照] 在本进程创建一个线程
//   driver-load   [高危] NtLoadDriver 加载一个非系统目录的 .sys 服务（需提权 + 真实 .sys）
//   driver-unload [高危] NtUnloadDriver 卸载它
//
// 用法：
//   proctest [case] [delaySeconds] [outFile]
//     case: all / proc / thread / driver / 具体子用例名
//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

// WIN32_LEAN_AND_MEAN 把 ntdef.h 排除了，NTSTATUS 没定义 —— 自己补一个
// （值不重要，只要类型对；真值由调用返回）。
#ifndef _NTDEF_
typedef LONG NTSTATUS;
#endif
typedef void* NtProcGeneric;

// 自备 UNICODE_STRING（不要引 winternl.h，避免与 windows.h 里的定义冲突）。
// 注意名字不能叫 PT_UNICODE_STRING —— 那个名字在 windows.h 里已存在
// （是 UNICODE_STRING* 的 typedef），重定义会让编译器把它当类去构造。
struct RG_US
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
};

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

typedef NTSTATUS(NTAPI* NtLoadDriverPtr)(RG_US*);
typedef NTSTATUS(NTAPI* NtUnloadDriverPtr)(RG_US*);
typedef NTSTATUS(NTAPI* NtCreateThreadExFullPtr)(PHANDLE, ACCESS_MASK, PVOID,
	HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// ----------------------------------------------------------------
// 通用工具
// ----------------------------------------------------------------

static void Report(const char* what, DWORD err)
{
	const char* tag = "";
	if (err == ERROR_ACCESS_DENIED) tag = "   [被拦截]";
	printf("%-56s -> %lu%s\n", what, err, tag);
}

static bool IsElevated()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
	TOKEN_ELEVATION elev = {};
	DWORD size = sizeof(elev);
	bool ok = GetTokenInformation(token, TokenElevation, &elev, size, &size) && elev.TokenIsElevated;
	CloseHandle(token);
	return ok;
}

static void SelfImagePath(WCHAR* out, DWORD cch)
{
	out[0] = L'\0';
	DWORD size = cch;
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, out, &size);
}

// ----------------------------------------------------------------
// 进程用例
// ----------------------------------------------------------------

static void RunProcess(const WCHAR* exe, const WCHAR* args, const char* label)
{
	WCHAR cmdline[1024] = {};
	if (args) {
		swprintf_s(cmdline, L"\"%ls\" %ls", exe, args);
	} else {
		swprintf_s(cmdline, L"\"%ls\"", exe);
	}

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = {};

	BOOL ok = CreateProcessW(exe, cmdline, nullptr, nullptr, FALSE,
		CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
	Report(label, ok ? ERROR_SUCCESS : GetLastError());
	if (ok) {
		printf("      -> 新进程 pid=%lu\n", pi.dwProcessId);
		WaitForSingleObject(pi.hProcess, 3000);
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

static void CaseProcNormal()
{
	printf("\n--- [普通] CreateProcess（探针自身目录 / 正常来源） ---\n");
	// 用探针自己 —— 它在 C:\Windows 之外，来源正常。
	WCHAR self[MAX_PATH] = {};
	SelfImagePath(self, _countof(self));
	// 带个参数避免它自己递归跑用例（传一个不存在的方法名 → 直接退出）。
	RunProcess(self, L"__noop__", "CreateProcess 自身副本（普通来源）");
}

static void CaseProcSystem32()
{
	printf("\n--- [高危] CreateProcess System32 下的程序 ---\n");
	RunProcess(L"C:\\Windows\\System32\\cmd.exe", L"/c echo r3shieldcore", "CreateProcess C:\\Windows\\System32\\cmd.exe");
}

static void CaseProcTemp()
{
	printf("\n--- [高危] 从 TEMP 起程序 ---\n");
	WCHAR self[MAX_PATH] = {};
	SelfImagePath(self, _countof(self));

	WCHAR tempDir[MAX_PATH] = {};
	GetTempPathW(_countof(tempDir), tempDir);
	WCHAR tempCopy[MAX_PATH] = {};
	swprintf_s(tempCopy, L"%lsR3ShieldCoreProcProbe.exe", tempDir);

	if (!CopyFileW(self, tempCopy, FALSE)) {
		Report("CopyFile 到 %TEMP%", GetLastError());
		return;
	}
	printf("   已复制到 %ls\n", tempCopy);

	RunProcess(tempCopy, L"__noop__", "CreateProcess %TEMP%\\R3ShieldCoreProcProbe.exe");
	DeleteFileW(tempCopy);
}

// ----------------------------------------------------------------
// 线程用例
// ----------------------------------------------------------------

// 远程线程体：空转一会儿就返回。
static DWORD WINAPI RemoteThreadBody(LPVOID)
{
	Sleep(200);
	return 0;
}

static void CaseThreadRemote()
{
	printf("\n--- [高危] 向别的进程注入远程线程 ---\n");

	// 目标：找一个当前会话里、同权限、能打开的进程。用 explorer 最稳
	// （同用户、同完整性级别）。找不到就退而求其次找任意同用户进程。
	DWORD targetPid = 0;
	{
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W pe = {};
			pe.dwSize = sizeof(pe);
			DWORD selfPid = GetCurrentProcessId();
			if (Process32FirstW(snap, &pe)) {
				do {
					if (pe.th32ProcessID == selfPid || pe.th32ProcessID <= 4) continue;
					// 优先 explorer
					if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
						targetPid = pe.th32ProcessID;
						break;
					}
					if (targetPid == 0) targetPid = pe.th32ProcessID; // 备选
				} while (Process32NextW(snap, &pe));
			}
			CloseHandle(snap);
		}
	}

	if (targetPid == 0) {
		printf("   找不到可用于注入的目标进程，跳过\n");
		return;
	}
	printf("   目标进程 pid=%lu\n", targetPid);

	HANDLE hProc = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, targetPid);
	if (!hProc) {
		Report("OpenProcess 目标进程", GetLastError());
		return;
	}
	printf("   OpenProcess 成功\n");

	// 不能把本进程的函数地址直接塞过去（ASLR 下地址空间不同）。
	// 用最简单可靠的一招：直接让远程线程跑 kernel32!Sleep，参数放远程内存。
	// 这样不需要写入任何代码，只需要目标进程里的 Sleep 地址 —— 同版本
	// ntdll/kernel32 在两个进程里的基址可能不同，所以从目标进程模块里查。
	HMODULE hK32Local = GetModuleHandleW(L"kernel32.dll");
	FARPROC pSleepLocal = GetProcAddress(hK32Local, "Sleep");

	// 简化的真实注入：把 Sleep 的参数（毫秒数）写到远程内存，
	// 然后用远程线程调 Sleep。Sleep 地址在两进程里通常相同
	// （同一 ASLR 基线，同一次 boot 的 kernel32 基址一致）。
	LPVOID remoteArg = VirtualAllocEx(hProc, nullptr, sizeof(DWORD),
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remoteArg) {
		Report("VirtualAllocEx 参数内存", GetLastError());
		CloseHandle(hProc);
		return;
	}
	DWORD ms = 300;
	WriteProcessMemory(hProc, remoteArg, &ms, sizeof(ms), nullptr);
	printf("   已写入远程内存，准备 CreateRemoteThread\n");

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
		(LPTHREAD_START_ROUTINE)pSleepLocal, remoteArg, 0, nullptr);
	if (!hThread) {
		Report("CreateRemoteThread 到目标进程", GetLastError());
		// 兜底：用 NtCreateThreadEx（process_guard 主 hook 点）
		printf("   改试 NtCreateThreadEx...\n");
		HMODULE nt = GetModuleHandleW(L"ntdll.dll");
		auto pNtCreateThreadEx = (NtCreateThreadExFullPtr)GetProcAddress(nt, "NtCreateThreadEx");
		HANDLE h2 = nullptr;
		NTSTATUS st = pNtCreateThreadEx(&h2, THREAD_ALL_ACCESS, nullptr, hProc,
			(PVOID)pSleepLocal, remoteArg, 0, 0, 0, 0, nullptr);
		printf("   NtCreateThreadEx -> NTSTATUS 0x%08lX%s\n", (unsigned long)st,
			st == STATUS_ACCESS_DENIED ? "   [被拦截]" : "");
		if (st >= 0 && h2) {
			WaitForSingleObject(h2, 2000);
			CloseHandle(h2);
		}
	} else {
		printf("   CreateRemoteThread 成功，句柄=%p\n", hThread);
		WaitForSingleObject(hThread, 2000);
		CloseHandle(hThread);
	}

	VirtualFreeEx(hProc, remoteArg, 0, MEM_RELEASE);
	CloseHandle(hProc);
}

static void CaseThreadSelf()
{
	printf("\n--- [对照] 本进程创建线程 ---\n");
	HANDLE h = CreateThread(nullptr, 0, RemoteThreadBody, nullptr, 0, nullptr);
	if (h) {
		printf("   CreateThread 成功（本进程，不应判高危）\n");
		WaitForSingleObject(h, 2000);
		CloseHandle(h);
	} else {
		Report("CreateThread", GetLastError());
	}
}

// ----------------------------------------------------------------
// 驱动用例
// ----------------------------------------------------------------

// 通过服务注册表路径调 NtLoadDriver。
// 需要：① 提权；② HKLM\SYSTEM\CurrentControlSet\Services\<名> 下写好
//       ImagePath 指向真实存在的 .sys；③ 加载非系统目录的驱动才会被判高危。
//
// 为了让探针能独立验证，这里**只调 NtLoadDriver 观察返回值**，
// 不真的准备一个可加载的 .sys（准备不了 → 内核会拒）。所以期望是
// "调用被我们看到 / 被拦"，而不是"驱动真的加载成功"。
static void CaseDriverLoad()
{
	printf("\n--- NtLoadDriver（服务方式加载驱动） ---\n");

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	auto pNtLoadDriver = (NtLoadDriverPtr)GetProcAddress(ntdll, "NtLoadDriver");
	auto pNtUnloadDriver = (NtUnloadDriverPtr)GetProcAddress(ntdll, "NtUnloadDriver");
	if (!pNtLoadDriver) {
		printf("   拿不到 NtLoadDriver，跳过\n");
		return;
	}

	// 服务名 R3ShieldCoreProbeDrv，注册表路径用\Registry\Machine\ 形式。
	// ImagePath 指向一个**不存在于系统驱动目录**的位置 —— 命中"非系统驱动"规则。
	const WCHAR* svcName = L"R3ShieldCoreProbeDrv";
	WCHAR regPath[256] = {};
	swprintf_s(regPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ls", svcName);

	// 先写服务键（ImagePath 指向桌面上的假 .sys）。
	// 注意：写注册表本身会被 registry hook 看到（不是系统程序写服务键 → 高危）。
	HKEY key = nullptr;
	DWORD disp = 0;
	LSTATUS st = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Services\\R3ShieldCoreProbeDrv",
		0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &key, &disp);
	Report("RegCreateKeyEx Services\\R3ShieldCoreProbeDrv", (DWORD)st);
	if (st == ERROR_SUCCESS) {
		WCHAR imgPath[MAX_PATH] = {};
		WCHAR userProfile[MAX_PATH] = {};
		GetEnvironmentVariableW(L"USERPROFILE", userProfile, _countof(userProfile));
		swprintf_s(imgPath, L"\\??\\%ls\\Desktop\\reguard_probe.sys", userProfile);
		LSTATUS s2 = RegSetValueExW(key, L"ImagePath", 0, REG_EXPAND_SZ,
			(const BYTE*)imgPath, (DWORD)((wcslen(imgPath) + 1) * sizeof(WCHAR)));
		Report("RegSetValueEx ImagePath", (DWORD)s2);
		DWORD svcType = 1; // SERVICE_KERNEL_DRIVER
		LSTATUS s3 = RegSetValueExW(key, L"Type", 0, REG_DWORD,
			(const BYTE*)&svcType, sizeof(svcType));
		Report("RegSetValueEx Type=1", (DWORD)s3);
		RegCloseKey(key);
	} else {
		printf("   服务键建不了（缺权限？），仍尝试直接调 NtLoadDriver 观察。\n");
	}

	// 组装 UNICODE_STRING。
	RG_US us = {};
	us.Buffer = (PWSTR)regPath;
	us.Length = (USHORT)(wcslen(regPath) * sizeof(WCHAR));
	us.MaximumLength = us.Length + sizeof(WCHAR);

	printf("   调 NtLoadDriver(%ls)...\n", regPath);
	NTSTATUS status = pNtLoadDriver(&us);
	printf("   NtLoadDriver -> NTSTATUS 0x%08lX%s\n", (unsigned long)status,
		status == STATUS_ACCESS_DENIED ? "   [被拦截]"
			: (status == 0 ? "   [成功]" : ""));

	if (status == 0 && pNtUnloadDriver) {
		printf("   调 NtUnloadDriver 卸载...\n");
		NTSTATUS us2 = pNtUnloadDriver(&us);
		printf("   NtUnloadDriver -> NTSTATUS 0x%08lX%s\n", (unsigned long)us2,
			us2 == STATUS_ACCESS_DENIED ? "   [被拦截]" : "");
	}

	// 收尾：删掉服务键。
	RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\R3ShieldCoreProbeDrv");
}

// ----------------------------------------------------------------
// main
// ----------------------------------------------------------------

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	setvbuf(stdout, nullptr, _IONBF, 0);

	if (argc > 3 && argv[3][0]) {
		WCHAR widePath[MAX_PATH] = {};
		MultiByteToWideChar(CP_ACP, 0, argv[3], -1, widePath, _countof(widePath));
		FILE* out = nullptr;
		_wfreopen_s(&out, widePath, L"w", stdout);
	}

	const char* mode = (argc > 1) ? argv[1] : "all";
	if (strcmp(mode, "__noop__") == 0) {
		// 被 CaseProcNormal 当子进程拉起来时直接退出。
		return 0;
	}
	int delaySeconds = (argc > 2) ? atoi(argv[2]) : 0;

	printf("R3ShieldCore 进程/线程/驱动探针 (pid=%lu)%s\n", GetCurrentProcessId(),
		IsElevated() ? "  [已提权]" : "  [普通权限]");
	{
		WCHAR path[MAX_PATH] = {};
		SelfImagePath(path, _countof(path));
		printf("镜像路径: %ls\n", path);
	}
	if (delaySeconds > 0) {
		printf("等待 %d 秒，让引擎完成注入...\n", delaySeconds);
		Sleep(delaySeconds * 1000);
	}
	printf("========================================\n");

	bool all = (strcmp(mode, "all") == 0);
	bool doProc = all || (strncmp(mode, "proc", 4) == 0);
	bool doThread = all || (strncmp(mode, "thread", 6) == 0);
	bool doDriver = all || (strcmp(mode, "driver") == 0);

	if (doProc) {
		if (all || strcmp(mode, "proc") == 0) {
			CaseProcNormal();
			CaseProcSystem32();
			CaseProcTemp();
		} else if (strcmp(mode, "proc-sys") == 0) {
			CaseProcSystem32();
		} else if (strcmp(mode, "proc-temp") == 0) {
			CaseProcTemp();
		} else if (strcmp(mode, "proc-cmd") == 0) {
			CaseProcNormal();
		}
	}
	if (doThread) {
		if (all || strcmp(mode, "thread") == 0) {
			CaseThreadSelf();
			CaseThreadRemote();
		} else if (strcmp(mode, "thread-remote") == 0) {
			CaseThreadRemote();
		} else if (strcmp(mode, "thread-self") == 0) {
			CaseThreadSelf();
		}
	}
	if (doDriver) {
		CaseDriverLoad();
	}

	printf("\n完成。\n");
	return 0;
}
