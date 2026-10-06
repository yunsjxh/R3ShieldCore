#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

//
// 引擎侧的询问 UI。独立线程，与主循环（注入 + drain）互不阻塞。
//
// 询问用「右下角通知卡片」呈现（r3shieldcore_toast），不用模态对话框：
//   - 一次可能同时有多个待询问请求，模态会串行阻塞
//   - 通知不抢焦点，用户正在打字时不会被打断
//
namespace R3ShieldCorePromptUi
{
	bool Start() noexcept;
	void Stop() noexcept;

	// 每次询问有结论后记一笔（写入共享内存的统计槽）。
	void NotePromptResult(R3ShieldCore::Verdict verdict, bool timedOut) noexcept;

	// 读累计询问统计。引擎 GUI 面板用。
	void ReadPromptStats(ULONG& shown, ULONG& allowed, ULONG& denied, ULONG& timedOut) noexcept;
}
