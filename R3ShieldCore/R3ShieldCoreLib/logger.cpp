#include "stdafx.h"
#include "logger.h"

#include <clocale>

namespace
{
	//
	// 本 DLL 用的是静态 CRT，有自己的 locale 状态，默认是 "C"。
	// 不设成系统默认的话，往 stderr 写中文会因为转换失败变成 "????"，
	// 甚至整行被截断。只影响本模块，不会动宿主进程。
	//
	void EnsureLocale() noexcept
	{
		static bool initialized = false;
		if (!initialized) {
			setlocale(LC_ALL, "");
			initialized = true;
		}
	}

	volatile LONG g_stderrOutputEnabled = 0;
}

namespace Logger
{
	void EnableStderrOutput(bool enable) noexcept
	{
		InterlockedExchange(&g_stderrOutputEnabled, enable ? 1 : 0);
	}

	void VLogLine(PCWSTR format, va_list args)
	{
		EnsureLocale();

		WCHAR buffer[1025];
		int len = _vsnwprintf_s(buffer, _TRUNCATE, format, args);
		if (len == -1) {
			// Truncation occurred.
			len = _countof(buffer) - 1;
		}

		while (--len >= 0 && buffer[len] == L'\n') {
			// Skip all newlines at the end.
		}

		// Leave only a single trailing newline.
		if (buffer[len + 1] == L'\n' && buffer[len + 2] == L'\n') {
			buffer[len + 2] = L'\0';
		}

		OutputDebugString(buffer);

		// 只有引擎进程会打开这个开关。注入到别的进程里 stderr 通常无效，
		// 但万一是继承来的有效句柄，就会把宿主的控制台刷爆。
		if (InterlockedCompareExchange(&g_stderrOutputEnabled, 0, 0) != 0) {
			fwprintf(stderr, L"%s\n", buffer);
			fflush(stderr);
		}
	}

	void LogLine(PCWSTR format, ...)
	{
		va_list args;
		va_start(args, format);
		VLogLine(format, args);
		va_end(args);
	}
}
