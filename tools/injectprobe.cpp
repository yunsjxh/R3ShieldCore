//
// 复现注入失败：对指定 pid 做和注入器完全一样的操作，逐步报告失败点。
//
// 用法: injectprobe.exe <pid> [pid...]
//
// 关键实验：把 VirtualAllocEx 拆成两次试
//   A) MEM_COMMIT | MEM_RESERVE  —— 注入器用的就是这个
//   B) MEM_RESERVE 单独          —— 只保留地址空间，不产生提交量
// 如果 A 失败而 B 成功，说明卡在"提交量"上，而不是地址空间 ——
// 目标进程极可能在一个设了内存上限的 Job Object 里。
//
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>

namespace
{
	// 与 DllInject::ProcessAccess 一致
	constexpr DWORD InjectAccess =
		PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | SYNCHRONIZE;

	void ProbeProcess(DWORD pid)
	{
		wprintf(L"--- pid %u ---\n", pid);

		HANDLE process = OpenProcess(InjectAccess, FALSE, pid);
		if (!process) {
			wprintf(L"  OpenProcess(注入权限)  失败, err=%u\n", GetLastError());
			return;
		}

		// 架构
		BOOL isWow64 = FALSE;
		IsWow64Process(process, &isWow64);
		SYSTEM_INFO native = {};
		GetNativeSystemInfo(&native);
		wprintf(L"  目标架构               %s\n",
			native.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? L"x86" :
			(isWow64 ? L"x86 (WOW64)" : L"x64"));

		// 目标进程的提交量
		PROCESS_MEMORY_COUNTERS_EX counters = {};
		counters.cb = sizeof(counters);
		if (GetProcessMemoryInfo(process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) {
			wprintf(L"  目标已提交内存         %llu MB\n",
				static_cast<unsigned long long>(counters.PagefileUsage) / (1024 * 1024));
		}

		// 是否在 job 里
		BOOL inJob = FALSE;
		if (IsProcessInJob(process, nullptr, &inJob)) {
			wprintf(L"  在 Job Object 里       %s\n", inJob ? L"是" : L"否");
		}

		// A) 和注入器一样：COMMIT | RESERVE
		void* a = VirtualAllocEx(process, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		wprintf(L"  A) COMMIT|RESERVE      %s", a ? L"成功" : L"失败");
		if (!a) {
			wprintf(L", err=%u", GetLastError());
		}
		wprintf(L"\n");
		if (a) {
			VirtualFreeEx(process, a, 0, MEM_RELEASE);
		}

		// B) 只 RESERVE
		void* b = VirtualAllocEx(process, nullptr, 4096, MEM_RESERVE, PAGE_READWRITE);
		wprintf(L"  B) RESERVE 单独        %s", b ? L"成功" : L"失败");
		if (!b) {
			wprintf(L", err=%u", GetLastError());
		}
		wprintf(L"\n");
		if (b) {
			VirtualFreeEx(process, b, 0, MEM_RELEASE);
		}

		CloseHandle(process);
		wprintf(L"\n");
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	setvbuf(stdout, nullptr, _IONBF, 0);

	if (argc < 2) {
		printf("usage: injectprobe.exe <pid> [pid...]\n");
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		ProbeProcess(static_cast<DWORD>(strtoul(argv[i], nullptr, 10)));
	}

	return 0;
}
