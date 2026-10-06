#pragma once

//
// 引擎侧的事件落盘。Drain 由引擎主循环定期调用，把所有进程投递到
// 环形缓冲里的记录写成一行行文本。
//
namespace R3ShieldCoreLog
{
	bool Open(const WCHAR* path) noexcept;
	int DrainAndWrite() noexcept;
	void Close() noexcept;
	bool IsOpen() noexcept;
}
