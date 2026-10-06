//
// injecttest.cpp — 注入探针。
//
// 目的：实测「R3ShieldCore 能否阻止别的进程往『引擎进程』注入」。
//
// 用法: injecttest.exe <targetPid> [delayMs] [outFile]
//
// 完整复刻注入链，逐步报告卡在哪一步：
//   1) OpenProcess(注入权限)
//   2) VirtualAllocEx(PAGE_EXECUTE_READWRITE)
//   3) WriteProcessMemory(shellcode: xor eax,eax; ret)
//   4) CreateRemoteThread  ← 这一步走 ntdll!NtCreateThreadEx，是 R3ShieldCore 唯一挂的注入相关点
//
// 判读：若第 4 步 err=5 且目标进程活着 → 该步被 R3ShieldCore 拦；
//       若四步全过 → 注入成功，引擎无防注入能力（针对该注入方）。
//
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static FILE* g_out = nullptr;

static void Emit(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	if (g_out) {
		va_start(ap, fmt);
		vfprintf(g_out, fmt, ap);
		va_end(ap);
		fflush(g_out);
	}
}

int main(int argc, char** argv)
{
	WCHAR self[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, self, _countof(self));

	const DWORD pid = (argc > 1) ? static_cast<DWORD>(strtoul(argv[1], nullptr, 10)) : 0;
	const int delayMs = (argc > 2) ? atoi(argv[2]) : 0;
	if (argc > 3 && argv[3][0]) {
		g_out = fopen(argv[3], "w");
	}

	Emit("injecttest pid=%u\n", GetCurrentProcessId());
	Emit("镜像路径: %ls\n", self);
	Emit("目标 pid=%u  delay=%dms\n", pid, delayMs);

	if (pid == 0) {
		Emit("缺少目标 pid。\n");
		if (g_out) fclose(g_out);
		return 1;
	}

	if (delayMs > 0) {
		Sleep(static_cast<DWORD>(delayMs));
	}

	const DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

	// 1) 打开目标进程。
	HANDLE h = OpenProcess(access, FALSE, pid);
	if (!h) {
		Emit("1) OpenProcess(注入权限)      失败 err=%u\n", GetLastError());
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("1) OpenProcess(注入权限)      成功\n");

	// 2) 在目标里分配可执行内存。
	void* remote = VirtualAllocEx(h, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remote) {
		Emit("2) VirtualAllocEx(RWX)        失败 err=%u\n", GetLastError());
		CloseHandle(h);
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("2) VirtualAllocEx(RWX)        成功  addr=%p\n", remote);

	// 3) 写 shellcode（xor eax,eax; ret —— 线程起来立刻返回，无害）。
	const unsigned char sc[] = { 0x33, 0xC0, 0xC3 };
	SIZE_T written = 0;
	if (!WriteProcessMemory(h, remote, sc, sizeof(sc), &written)) {
		Emit("3) WriteProcessMemory         失败 err=%u\n", GetLastError());
		VirtualFreeEx(h, remote, 0, MEM_RELEASE);
		CloseHandle(h);
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("3) WriteProcessMemory         成功  写入 %llu 字节\n",
		static_cast<unsigned long long>(written));

	// 4) 远程建线程 —— 关键一步。
	SetLastError(0);
	DWORD tid = 0;
	HANDLE th = CreateRemoteThread(h, nullptr, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(remote), nullptr, 0, &tid);
	const DWORD err = GetLastError();
	if (!th) {
		Emit("4) CreateRemoteThread         失败 err=%u  <-- 注入在最后一步被挡\n", err);
	} else {
		Emit("4) CreateRemoteThread         成功  tid=%u\n", tid);
		WaitForSingleObject(th, 3000);
		CloseHandle(th);
	}

	// 5) 目标是否还活着。
	HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (q) {
		DWORD code = 0;
		GetExitCodeProcess(q, &code);
		Emit("5) 目标状态                   %s\n", (code == STILL_ACTIVE) ? "仍在运行" : "已退出");
		CloseHandle(q);
	} else {
		Emit("5) 目标状态                   已不存在 (err=%u)\n", GetLastError());
	}

	VirtualFreeEx(h, remote, 0, MEM_RELEASE);
	CloseHandle(h);
	Emit("完成。\n");
	if (g_out) fclose(g_out);
	return 0;
}
