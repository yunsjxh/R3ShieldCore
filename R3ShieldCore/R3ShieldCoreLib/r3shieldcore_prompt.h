#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

//
// 询问通道：hook 里同步阻塞，等引擎弹窗给出结论。
//
// 引擎进程调用 Create() 建共享内存和事件，UI 线程通过下面几个访问器
// 扫描待处理槽并写回答复；被注入的进程调用 Open() 后即可用 Ask()。
//
namespace R3ShieldCorePrompt
{
	// ---- 引擎侧 ----
	bool Create() noexcept;

	// ---- 注入侧 ----
	bool Open(DWORD enginePid) noexcept;

	// ---- 两侧共用 ----
	void Close() noexcept;
	bool IsOpen() noexcept;

	// 询问用户。超时、通道不可用、同进程已有待处理请求，都直接返回 fallback。
	// 绝不无限阻塞。
	R3ShieldCore::Verdict Ask(const R3ShieldCore::Event& event, R3ShieldCore::Verdict fallback) noexcept;

	// ------------------------------------------------------------------
	// ★★ 带「通道可用性」降级判定的询问包装（v29）—— 所有 guard 都该用它。
	// ------------------------------------------------------------------
	//
	// 背景（★ 用户实报，2026-09-30）：
	//   `Ask()` 的 fallback 是 `deny`，**分不清"用户拒绝"与"问不出去"**。
	//   引擎以**管理员**启动 → 被注入进程（同会话、跨完整性）打不开询问
	//   通道 → `IsOpen()==false` → `Ask()` 立刻返 deny → **静默拒**。
	//
	//   表现取决于命中的 guard：
	//     · 注册表 / 文件写 → 第三方软件配置写被拒（v26/v28 已修）
	//     · **令牌 / 进程等其它 guard → UAC 提权链断裂 → 连 UAC 框都不出现**
	//       （提权必经 AdjustTokenPrivileges 调整敏感特权 → token guard 恒高危
	//        → Ask 通道不可用 → 静默拒 → 提权失败）
	//
	// v26/v28 只把降级补进了 registry_guard / file_guard（4 处），
	// **其余 15 个 guard 共 20+ 个 Ask() 调用点全无保护**。本函数把降级
	// 收拢到一处，供所有 guard 复用，杜绝"又一个漏网的 Ask 分支"。
	//
	// 语义：
	//   · 通道可用 → 等价于 `Ask()`（可能阻塞等用户，verdict 有效，返回 true）
	//   · 通道不可用 **且 mode == Log** → **降级放行**：返回 false，调用方应
	//     置 `WouldBlock` + `FlagEvent2AskUnavailable`（日志出 `[ASK-UNAVAIL→ALLOW]`）
	//   · 通道不可用 **且 mode != Log**（Block / Ask / block_all）→ 返回 true
	//     且 `verdictOut = fallback`（安全边界**不降**：用户明确要拦，通道坏了也拦）
	//
	// 返回 true  → 按 verdictOut 处置（Allow/AllowAlways 放行；否则拒）
	// 返回 false → 调用方降级放行为 Record
	//
	// ★★ v29 重要使用约束（踩过一次坑，务必看清）：
	//   本函数**只对 LOG 返回 false**。`block_all` 模式下它返回 true +
	//   `verdictOut=fallback(deny)`，调用方**无法**从返回值区分
	//   "通道坏了" 与 "用户点了拒绝"。
	//
	//   所以 **block_all 分支不许依赖本函数的返回值做降级**。要保 UAC
	//   （consent.exe 进程创建 / AdjustTokenPrivileges 提权）必须像
	//   v26/v28 那样**在调用 `Ask()` 之前显式探一次 `R3ShieldCorePrompt::IsOpen()`**，
	//   不可用则直接降级放行 + `FlagEvent2AskUnavailable`（见
	//   `token_theft_guard.cpp` / `process_guard.cpp` 的 block_all 分支）。
	bool AskWithChannelGuard(const R3ShieldCore::Event& event, R3ShieldCore::Verdict fallback,
		ULONG mode, R3ShieldCore::Verdict& verdictOut) noexcept;

	// 引擎没了 / 本进程要收尾时调用。让还在等待的 Ask() 立刻返回兜底结论，
	// 不再让宿主进程的线程白等几十秒。
	void NotifyShutdown() noexcept;

	// ---- 引擎 UI 线程用 ----
	R3ShieldCore::PromptHeader* Header() noexcept;
	HANDLE RequestEvent() noexcept;
	HANDLE SlotEvent(ULONG index) noexcept;
	ULONG SlotCount() noexcept;

	// 写答复并唤醒等待方。只有当槽仍处于"待处理"时才会生效。
	// 返回 true 表示答复已投递。
	bool Answer(ULONG index, LONG generation, R3ShieldCore::Verdict verdict) noexcept;
}
