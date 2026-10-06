// dbgcap —— 捕获本机所有进程的 OutputDebugString 输出。
//
// 为什么需要它：guard 里的 LOG() 走 OutputDebugString，而 guard 跑在**被注入
// 的进程**里（探针进程），那些进程的控制台我们看不到。要定位"懒 patch 为什么
// 没生效"，必须能读到这些行。
//
// Windows 的 OutputDebugString 是广播式的：每个会话最多一个"调试输出监听器"，
// 通过两个内核对象通信：
//   DBWIN_BUFFER       —— 共享内存段（dbwin_buffer 结构：pid + 字符串）
//   DBWIN_BUFFER_READY —— 监听器置位，表示缓冲区可写
//   DBWIN_DATA_READY   —— 写方置位，表示有新行
//
// 用法： dbgcap.exe [秒数]     默认抓 8 秒
//        dbgcap.exe 0          无限抓，Ctrl+C 停
// 过滤： 只打印含 "R3ShieldCore" / "Wmi" / "R3SHIELDCORE-LOG" 的行（用 -a 关掉过滤）

#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

namespace
{
	const DWORD kBufferSize = 4096;

	const char* kSharedBufferName = "DBWIN_BUFFER";
	const char* kBufferReadyName  = "DBWIN_BUFFER_READY";
	const char* kDataReadyName    = "DBWIN_DATA_READY";

	bool g_all = false;

	bool Wanted(const char* line)
	{
		if (g_all) {
			return true;
		}
		// 只留我们关心的：guard 的日志前缀，以及 WMI/令牌/音频相关。
		static const char* kNeedles[] = {
			"R3SHIELDCORE-LOG",
			"WmiSubscription",
			"TokenTheft",
			"ScheduledTask",
			"ComHijack",
			"CameraGuard",
		};
		for (const char* n : kNeedles) {
			if (strstr(line, n) != nullptr) {
				return true;
			}
		}
		return false;
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	DWORD seconds = 8;
	if (argc > 1) {
		seconds = static_cast<DWORD>(atoi(argv[1]));
	}
	if (argc > 2 && strcmp(argv[2], "-a") == 0) {
		g_all = true;
	}

	HANDLE hReady = CreateEventA(nullptr, FALSE, FALSE, kBufferReadyName);
	HANDLE hData = CreateEventA(nullptr, FALSE, FALSE, kDataReadyName);
	HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
		0, kBufferSize, kSharedBufferName);

	if (!hReady || !hData || !hMap) {
		printf("初始化失败（可能已有别的调试监听器在跑）：err=%u\n", GetLastError());
		printf("  提示：同一会话只允许一个 OutputDebugString 监听器。\n");
		return 1;
	}

	void* view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, kBufferSize);
	if (!view) {
		printf("MapViewOfFile 失败 err=%u\n", GetLastError());
		return 1;
	}

	const ULONGLONG deadline = (seconds == 0) ? 0 : GetTickCount64() + seconds * 1000ULL;

	printf("dbgcap 监听中（%s）...\n", seconds == 0 ? "不限时，Ctrl+C 停止" : "限时");
	fflush(stdout);

	for (;;) {
		if (deadline != 0 && GetTickCount64() >= deadline) {
			break;
		}

		SetEvent(hReady);

		const DWORD wait = WaitForSingleObject(hData, 500);
		if (wait != WAIT_OBJECT_0) {
			continue;
		}

		// dbwin_buffer 布局： DWORD pid; char data[];
		const DWORD pid = *reinterpret_cast<const DWORD*>(view);
		const char* text = static_cast<const char*>(view) + sizeof(DWORD);

		if (Wanted(text)) {
			printf("[%5lu] %s", pid, text);
			fflush(stdout);
		}
	}

	UnmapViewOfFile(view);
	CloseHandle(hMap);
	CloseHandle(hData);
	CloseHandle(hReady);
	printf("\ndbgcap 结束\n");
	return 0;
}
