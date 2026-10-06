//
// killprobe.cpp — 终止探针。
//
// 目的：实测「R3ShieldCore 能否防止自己的引擎进程被终止」。
//
// 用法: killprobe.exe <pid> [delayMs] [outFile]
//
// 从两个位置各跑一次做对照：
//   tools\killprobe.exe                          —— 不在 exclude 里，会被引擎注入
//   C:\Users\<user>\.workbuddy-ai\killprobe.exe  —— 在 exclude 里，不会被注入
//
// 判读：若两处都能把引擎杀掉 → 引擎无自我保护；
//       若只有「被注入」的那次被拦，说明保护只在注入方进程里生效。
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

	Emit("killprobe pid=%u\n", GetCurrentProcessId());
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

	// 1) 拿 PROCESS_TERMINATE 权限句柄。
	HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (!h) {
		Emit("OpenProcess(PROCESS_TERMINATE) 失败 err=%u\n", GetLastError());
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("OpenProcess(PROCESS_TERMINATE) 成功 handle=%p\n", reinterpret_cast<void*>(h));

	// 2) 终止。
	SetLastError(0);
	BOOL ok = TerminateProcess(h, 1);
	DWORD err = GetLastError();
	Emit("TerminateProcess -> %s err=%u\n", ok ? "成功" : "失败", ok ? 0u : err);
	CloseHandle(h);

	// 3) 复查目标是否还在。
	Sleep(400);
	HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (q) {
		DWORD code = 0;
		if (GetExitCodeProcess(q, &code) && code == STILL_ACTIVE) {
			Emit("复查: 目标仍在运行 (STILL_ACTIVE)\n");
		} else {
			Emit("复查: 目标已退出 code=0x%08X\n", code);
		}
		CloseHandle(q);
	} else {
		Emit("复查: 目标已不存在 (OpenProcess err=%u)\n", GetLastError());
	}

	Emit("完成。\n");
	if (g_out) fclose(g_out);
	return 0;
}
