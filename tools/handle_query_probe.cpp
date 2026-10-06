//
// handle_query_probe.cpp —— 实证：什么样的进程句柄能反查 pid？
//
// 背景（v36 端到端探针抓到的真 bug）：
//   NtTerminateProcess 的 hook 用 `NtQueryInformationProcess(ProcessBasicInformation)`
//   从调用方的**句柄**反查目标 pid。但调用方通常只用 `PROCESS_TERMINATE`
//   打开句柄 —— 那种句柄**可能没有查询权限**，于是反查失败 → 目标判不出来
//   → 规则被绕过（放行）。
//
// 本探针把"哪种 access mask 能反查成功"一次测清楚。
//
// 用法：无参数。

#include <windows.h>
#include <stdio.h>
#include <string>

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct PBI
{
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
};

static int g_pass = 0, g_fail = 0;
static void Check(const char* n, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", n);
	if (ok) g_pass++; else g_fail++;
}

static int RunSleeper()
{
	for (int i = 0; i < 600; i++) Sleep(100);
	return 0;
}

// 反查结果：返回 pid（0 = 失败），statusOut 收原始 NTSTATUS。
static ULONG QueryPid(HANDLE h, NtQueryInformationProcessPtr fn, NTSTATUS* statusOut)
{
	PBI info = {};
	ULONG len = 0;
	const NTSTATUS st = fn(h, 0 /*ProcessBasicInformation*/, &info, sizeof(info), &len);
	if (statusOut) *statusOut = st;
	return (st >= 0) ? static_cast<ULONG>(info.UniqueProcessId) : 0;
}

static void TryMask(NtQueryInformationProcessPtr fn, ULONG targetPid, DWORD mask, const char* label)
{
	HANDLE h = OpenProcess(mask, FALSE, targetPid);
	if (!h) {
		printf("  %-46s OpenProcess 失败 err=%lu\n", label, GetLastError());
		return;
	}
	NTSTATUS st = 0;
	const ULONG pid = QueryPid(h, fn, &st);
	const DWORD gpid = GetProcessId(h);
	printf("  %-46s BasicInfo->pid=%-6u status=0x%08lX  GetProcessId=%u\n",
		label, pid, static_cast<unsigned long>(st), gpid);
	CloseHandle(h);
}

int main(int argc, char** argv)
{
	for (int i = 1; i < argc; i++)
		if (strcmp(argv[i], "--sleeper") == 0) return RunSleeper();

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	NtQueryInformationProcessPtr fn = reinterpret_cast<NtQueryInformationProcessPtr>(
		GetProcAddress(ntdll, "NtQueryInformationProcess"));
	if (!fn) { printf("拿不到 NtQueryInformationProcess\n"); return 1; }

	WCHAR exe[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exe, _countof(exe));
	std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --sleeper";
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
		printf("拉子进程失败 err=%lu\n", GetLastError());
		return 1;
	}
	Sleep(500);
	const ULONG target = pi.dwProcessId;
	printf("目标 pid=%u\n\n", target);

	printf("=== 各种 access mask 能否反查 pid ===\n");
	TryMask(fn, target, PROCESS_TERMINATE, "PROCESS_TERMINATE");
	TryMask(fn, target, PROCESS_QUERY_LIMITED_INFORMATION, "PROCESS_QUERY_LIMITED_INFORMATION");
	TryMask(fn, target, PROCESS_QUERY_INFORMATION, "PROCESS_QUERY_INFORMATION");
	TryMask(fn, target, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
		"PROCESS_TERMINATE|QUERY_LIMITED");
	TryMask(fn, target, PROCESS_ALL_ACCESS, "PROCESS_ALL_ACCESS");
	TryMask(fn, target, SYNCHRONIZE, "SYNCHRONIZE");

	printf("\n=== CreateProcess 返回的 hProcess（全权限）===\n");
	NTSTATUS st = 0;
	printf("  CreateProcess hProcess -> pid=%u status=0x%08lX\n",
		QueryPid(pi.hProcess, fn, &st), static_cast<unsigned long>(st));

	printf("\n=== 伪句柄 NtCurrentProcess() = (HANDLE)-1 ===\n");
	const ULONG selfViaPseudo = QueryPid(reinterpret_cast<HANDLE>(-1), fn, &st);
	printf("  (HANDLE)-1 -> pid=%u status=0x%08lX (自己=%u)\n",
		selfViaPseudo, static_cast<unsigned long>(st), GetCurrentProcessId());

	printf("\n=== 结论断言 ===\n");
	{
		HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, target);
		NTSTATUS s1 = 0;
		const ULONG p1 = QueryPid(h, fn, &s1);
		Check("★ PROCESS_TERMINATE-only 句柄**反查不到** pid（这就是 bug 根因）",
			p1 == 0 && s1 < 0);
		CloseHandle(h);

		HANDLE h2 = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target);
		NTSTATUS s2 = 0;
		const ULONG p2 = QueryPid(h2, fn, &s2);
		Check("TERMINATE|QUERY_LIMITED 能反查到 pid", p2 == target);
		CloseHandle(h2);

		Check("伪句柄 (HANDLE)-1 解析为自己", selfViaPseudo == GetCurrentProcessId());
		Check("CreateProcess 的 hProcess 能反查到 pid", QueryPid(pi.hProcess, fn, nullptr) == target);
	}

	TerminateProcess(pi.hProcess, 0);
	WaitForSingleObject(pi.hProcess, 3000);
	CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
