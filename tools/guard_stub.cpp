//
// guard_stub.cpp —— guard 层单测用的桩（v28）。
//
// ★ 为什么需要这个（与 channel_stub.cpp 的区别）：
//   `channel_stub.cpp` 只提供 `Policy()` 一个函数，够 `r3shieldcore_rules.cpp`
//   用，但**不够 `registry_guard.cpp` / `file_guard.cpp`** —— 它们的 `Evaluate`
//   还依赖 `R3ShieldCoreChannel::Channel/Publish` 和 `R3ShieldCorePrompt::Ask/IsOpen`。
//
//   v28 的修复点（"LOG 模式 + 高危不可问 → 降级放行"）**正好在 guard 层**，
//   而 `build_ut.sh` 只链规则层 ⇒ 修复点**测不到**。这个桩把 guard 层
//   跑起来所需的全部外部符号都提供出来，且**可控**：
//     · `SetMode()`        —— 切 Policy->Mode（LOG / BLOCK / ASK / block_all）
//     · `SetHighRisk()`    —— 切 Policy->Flags 的 FlagHighRiskGuard
//     · `SetPromptOpen()`  —— 控制 `R3ShieldCorePrompt::IsOpen()` 的返回值
//                             （模拟"引擎以管理员启动 → 询问通道打不开"）
//     · `LastPublish()`    —— 取回 guard 上报的 event（看 Decision / Flags2）
//     · `AskCallCount()`   —— **询问通道真的被碰过几次**（v66 新增）
//
//   `Ask()` 的行为严格照 `r3shieldcore_prompt.cpp:414-426` 实现：
//   **通道不在 → 立刻返回 fallback**（不阻塞、不弹窗）。
//
// ★ v66 为什么要 `AskCallCount()`：
//   v66 的验收要求是"全拦模式下**不弹窗**"。这是一个**否定式**断言 ——
//   如果只断言 `Decision == Blocked`，那么"直接拒"和"先弹窗、用户拒绝后拒"
//   这两条**完全相反**的实现会给出**同一个** `Decision` ⇒ 断言恒真、测不出回归。
//   （这正是铁律 97「布尔判定=不可诊断」/ 铁律 110「计数相等先问全零是否也成立」
//     说的那类空真判据。）
//   所以必须把"有没有碰过询问通道"变成**可数的事实**，再配一条
//   **负对照**（Ask 模式下这个计数必须 > 0，证明计数器本身是活的）。
//
#include <r3shieldcore/r3shieldcore_shared.h>
#include <atomic>

namespace
{
	R3ShieldCore::Policy g_policy = {};
	bool g_promptOpen = false;

	// 询问通道被**尝试**的次数（v66）。
	// ★ 用途见文件头：「全拦模式不弹窗」是**否定式**要求，
	//   只断言 Decision 无法区分"直接拒"与"先问后拒"。
	//
	// ⚠️ 口径（**必须比触发口径更宽**，见铁律 99）：
	//   在两个地方各加一次 —— `AskWithChannelGuard()` 入口 和 `Ask()` 入口。
	//   理由：`AskWithChannelGuard` 在通道打不开时**不会**转调 `Ask`
	//   （见下方实现），只数 `Ask()` 会漏掉"问了但通道不在"这条回归。
	//   代价是通道正常时一次询问会被数成 2 —— 所以本计数
	//   **只用于 `== 0` / `> 0` 判定，不保证精确去重**。
	std::atomic<ULONG> g_askAttempts{ 0 };

	// 最后一次 Publish 的事件快照（供断言读 Decision / Flags / Flags2）。
	std::atomic<bool> g_hasEvent{ false };
	R3ShieldCore::Event g_lastEvent = {};
}

namespace GuardStub
{
	void SetMode(ULONG mode) noexcept { g_policy.Mode = mode; }
	void SetHighRisk(bool on) noexcept
	{
		if (on) { g_policy.Flags |= R3ShieldCore::FlagHighRiskGuard; }
		else { g_policy.Flags &= ~R3ShieldCore::FlagHighRiskGuard; }
	}
	void SetPromptOpen(bool open) noexcept { g_promptOpen = open; }
	void ResetPolicy() noexcept
	{
		g_policy = {};
		// 默认给一个"高危开关打开"的 Policy，贴近真实 ini（high_risk=1）。
		g_policy.Flags = R3ShieldCore::FlagHighRiskGuard;
		g_askAttempts.store(0);
	}

	// ★ v66：询问通道被**尝试**的次数（== 0 即"一次都没碰过询问通道"）。
	ULONG AskAttemptCount() noexcept { return g_askAttempts.load(); }
	void ResetAskAttemptCount() noexcept { g_askAttempts.store(0); }

	bool HasEvent() noexcept { return g_hasEvent.load(); }
	R3ShieldCore::Event LastEvent() noexcept { return g_lastEvent; }
	void ClearEvent() noexcept { g_hasEvent.store(false); g_lastEvent = {}; }
	R3ShieldCore::Policy* PolicyPtr() noexcept { return &g_policy; }
}

namespace R3ShieldCoreChannel
{
	R3ShieldCore::Policy* Policy() noexcept { return &g_policy; }

	// ── v28 单测里 guard 会调、但不影响断言结果的那些 ──
	//
	// 事件通道：单测不真的跑生产者-消费者，只把最后一次事件存下来。
	bool IsOpen() noexcept { return true; }
	bool IsOwner() noexcept { return true; }
	R3ShieldCore::ChannelHeader* Channel() noexcept
	{
		// 返回一个非空指针即可 —— `Evaluate` 只在里面递增计数器。
		static R3ShieldCore::ChannelHeader header = {};
		return &header;
	}
	void Publish(const R3ShieldCore::Event& event) noexcept
	{
		g_lastEvent = event;
		g_hasEvent.store(true);
	}
	void Publish(const R3ShieldCore::Event& event, ULONG /*objectType*/) noexcept
	{
		g_lastEvent = event;
		g_hasEvent.store(true);
	}
	R3ShieldCore::ChannelHeader* Create(const R3ShieldCore::Policy&) noexcept { return Channel(); }
	void Close() noexcept {}
	bool Open(DWORD) noexcept { return true; }
}

namespace R3ShieldCorePrompt
{
	bool IsOpen() noexcept { return g_promptOpen; }

	// ★ 严格照 r3shieldcore_prompt.cpp:414-426：
	//   通道不在（IsOpen()==false）→ **立刻**返回 fallback。
	//   这正是"静默拒"的来源 —— 单测要复现的就是它。
	R3ShieldCore::Verdict Ask(const R3ShieldCore::Event& /*event*/,
		R3ShieldCore::Verdict fallback) noexcept
	{
		g_askAttempts.fetch_add(1);   // ★ v66 计数口径之一
		if (!g_promptOpen)
		{
			return fallback;
		}
		// 通道在时：模拟"用户点了拒绝"（最保守），让断言能区分
		// "降级放行"与"用户拒绝"两条不同的路径。
		return R3ShieldCore::Verdict::Deny;
	}

	bool Open(DWORD) noexcept { return g_promptOpen; }

	// ★ v29：桩版本的 `AskWithChannelGuard`，语义与
	//   `r3shieldcore_prompt.cpp` 的真实实现**完全一致**：
	//     · 通道不可用 + LOG  → 返回 false（调用方降级放行）
	//     · 通道不可用 + 非LOG → 返回 true，verdictOut=fallback（保持安全边界）
	//     · 通道可用          → 等价 Ask()（桩里 Ask 恒返 Deny = 用户拒绝）
	bool AskWithChannelGuard(const R3ShieldCore::Event& event, R3ShieldCore::Verdict fallback,
		ULONG mode, R3ShieldCore::Verdict& verdictOut) noexcept
	{
		g_askAttempts.fetch_add(1);   // ★ v66 计数口径之二（通道不在时不会再转调 Ask）
		if (!g_promptOpen)
		{
			verdictOut = fallback;
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log))
			{
				return false; // 降级放行
			}
			return true; // 非 LOG：按 fallback 处置
		}

		verdictOut = Ask(event, fallback);
		return true;
	}
}

// ---------------------------------------------------------------------------
// registry_guard.cpp 的其余外部依赖（单测用不到它们的行为，只需能链接）
// ---------------------------------------------------------------------------

// `registry_guard.cpp` 的 Install 路径调它 —— 单测不跑 Install，
// 但同一 TU 里的引用必须在链接期解析掉。
namespace HostHijackGuard
{
	bool EvaluateInjectionKeyWrite(PCWSTR /*keyPath*/, PCWSTR /*valueName*/,
		PCWSTR /*pathValue*/) noexcept
	{
		return false;
	}
}

// `LOG(...)` 宏最终落到它。
namespace Logger
{
	void LogLine(PCWSTR /*format*/, ...) noexcept {}
}
