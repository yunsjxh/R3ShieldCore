#pragma once

namespace Logger
{
	void VLogLine(PCWSTR format, va_list args);
	void LogLine(PCWSTR format, ...);

	// 日志同时写到 stderr。只有引擎进程该开这个 —— 注入到别的进程里
	// 一开就会把宿主进程的控制台刷爆。
	void EnableStderrOutput(bool enable) noexcept;
}

#define LOG(message, ...)     Logger::LogLine(L"[R3SHIELDCORE-LOG]     [%S]: " message L"\n", __FUNCTION__, __VA_ARGS__)
#define VERBOSE(message, ...) Logger::LogLine(L"[R3SHIELDCORE-VERBOSE] [%S]: " message L"\n", __FUNCTION__, __VA_ARGS__)
