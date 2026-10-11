#include "stdafx.h"
#include "clipboard_guard.h"
#include "clipboard_spoof_codec.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

// ★ v78：规则脚本（用户在主程序「高级」页写的**中文规则**）。
//   命名空间 `R3ShieldCoreRuleScript` —— 与上面那个编译期高危规则表
//   （`R3ShieldCoreRules`）**同名不同物**，理由见 rules_codec.h 头部。
#include <r3shieldcore/spoof_apply_codec.h>
#include "rules_script_runtime.h"

//
// 剪贴板读取监控层。
//
// 挂载点（都在 user32）：
//   OpenClipboard    ← 打开剪贴板（读写的敲门砖）→ 只记录
//   GetClipboardData ← 真正取走内容              → 高危
//   CloseClipboard   ← ★ v70：只为**回收替换块**而挂（见下面"句柄所有权"）
//
// ⚠️ 噪音控制的要点：
//   OpenClipboard 频率不低（每次粘贴、每次截图工具、输入法都会调），
//   但**不能挂成"只记录"就不管** —— 记录本身也要走环形缓冲。
//   好在它比 BitBlt 那种热路径温和得多（人操作剪贴板的频率是人手频率），
//   所以这里不额外过滤，如实记录即可。
//
//   GetClipboardData 相对低频，且一旦出现就值得让用户看到，直接高危。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef BOOL(WINAPI* OpenClipboardPtr)(HWND);
	typedef HANDLE(WINAPI* GetClipboardDataPtr)(UINT);
	typedef BOOL(WINAPI* CloseClipboardPtr)();

	OpenClipboardPtr pOriginalOpenClipboard = nullptr;
	GetClipboardDataPtr pOriginalGetClipboardData = nullptr;
	CloseClipboardPtr pOriginalCloseClipboard = nullptr;

	// ★ v78：规则脚本的别名（与 registry_guard.cpp 里那两个**同名同物**，
	//   只是各自 TU 里的简写）。
	namespace RScript = R3ShieldCoreRuleScript;
	namespace RApply = R3ShieldCoreSpoofApply;

	// 首次用到规则时把规则文件读进来（每个被注入进程各一次；见
	// `rules_script_runtime.h` 的状态机 —— 同一模块里 registry_guard.cpp
	// 与这里**共用一份**状态，所以只有最先到的那个会真读、会打日志）。
	bool EnsureClipRulesLoaded() noexcept
	{
		if (!R3ShieldCoreRuleScriptRuntime::EnsureLoadedSafe()) {
			return false;
		}
		// ⚠️ ASCII 子串 `rules_script` 是 v78 代次标记的一部分，别删。
		LOG(L"ClipboardGuard: 规则脚本加载完毕（rules_script，路径 %s，%d 条有效 / %d 条无效）",
			R3ShieldCoreRuleScriptRuntime::Path(),
			static_cast<int>(R3ShieldCoreRuleScriptRuntime::OkCount()),
			static_cast<int>(R3ShieldCoreRuleScriptRuntime::BadCount()));
		return true;
	}

	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;

	// ★ v70：CloseClipboard 挂上了才允许替换 —— 否则替换出来的块无人回收。
	bool g_closeHookReady = false;

	// v74：决策档位收敛到共享 ABI（`R3ShieldCore::Action`，见
	//   shared/r3shieldcore/r3shieldcore_shared.h）。本文件**不再**自己定义。
	//   ★ 本面的 `Spoof` 落地形态：`GetClipboardData` **成功**返回，但返回的
	//     句柄指向我们造的中性化内容（v70），并在 `CloseClipboard` 回收。
	using Action = R3ShieldCore::Action;

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// ------------------------------------------------------------------
	// 上报与判定
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Clipboard);
		if (event.TimeStamp == 0) {
			event.TimeStamp = NowFileTime();
		}
		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();

		R3ShieldCoreChannel::Publish(event);
	}

	R3ShieldCore::Verdict PromptFallbackVerdict() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
			return static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
		}

		return R3ShieldCore::Verdict::Deny;
	}

	// ==================================================================
	// v70：替换（Spoof）—— 判据 + 伪造句柄的生命周期
	// ==================================================================
	//
	// ★★ 这个面**特有**的坑：**句柄所有权**。
	//
	//   契约（MSDN）：`GetClipboardData` 返回的 `HANDLE` **归剪贴板所有**，
	//   调用方**不得** `GlobalFree` / `DeleteObject`（它只该 `GlobalLock` +
	//   `GlobalUnlock`），有效期到 `CloseClipboard` 为止。
	//
	//   ⇒ 所以替换不是"改个指针"就完了，而是三件事：
	//     ① 自己造一块（`clipboard_spoof_codec.h`）；
	//     ② 把**原句柄**换成自己的，让调用方拿去用；
	//     ③ 等调用方用完之后再释放 —— **早了**对方读到已释放内存（崩溃），
	//        **晚了**就是泄漏。唯一正确的时刻是 `CloseClipboard`。
	//
	//   ⇒ 因此 v70 多挂了一个 `CloseClipboard`（只为回收，不改它的行为）。
	//     若它没挂上，**本次一律不启用替换**（`g_closeHookReady`）——
	//     宁可退回"拒绝"，也不能造出一批无人回收的块。
	//
	// 为什么槽是**进程级固定数组**而不是 thread_local：剪贴板由"打开它的
	//   线程"持有，但 `GetClipboardData` 的调用方**未必是那个线程**（同进程
	//   另一线程读剪贴板是合法的）。thread_local 会漏掉别人的槽 ⇒ 泄漏。
	//   槽的占用用 `InterlockedCompareExchange` 抢，不需要临界区。
	constexpr int kMaxFakeSlots = 16;

	struct FakeSlot
	{
		volatile LONG inUse;
		UINT format;
		HANDLE handle;
	};

	FakeSlot g_fakeSlots[kMaxFakeSlots] = {};
	volatile LONG g_fakeTracked = 0;   // 累计登记数（诊断）
	volatile LONG g_fakeOverflow = 0;  // 槽不够用的次数（**必须可见**，铁律 178）
	volatile LONG g_fakeReleased = 0;  // 累计回收数（诊断）

	bool SpoofClipboardEnabled() noexcept
	{
		// ⚠️ 前置条件：CloseClipboard 挂上了，否则块无法回收。
		if (!g_closeHookReady) {
			return false;
		}
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy && (policy->Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0;
	}

	void TrackFake(UINT format, HANDLE fake) noexcept
	{
		if (!fake) {
			return;
		}

		for (int i = 0; i < kMaxFakeSlots; ++i) {
			if (InterlockedCompareExchange(&g_fakeSlots[i].inUse, 1, 0) == 0) {
				g_fakeSlots[i].format = format;
				g_fakeSlots[i].handle = fake;
				InterlockedIncrement(&g_fakeTracked);
				return;
			}
		}

		// 槽满 —— 正常"open/close 配对 + 最多 6 种可伪造格式"下不可达。
		// ★ 这里的取舍：**宁可泄漏，也不提前释放**。提前释放 ⇒ 调用方拿到
		//   已释放的内存 ⇒ 宿主进程崩溃；泄漏几 KB 只是浪费。
		//   （铁律 97：不能只有"没生效"，所以这里必须留下痕迹。）
		InterlockedIncrement(&g_fakeOverflow);
		LOG(L"ClipboardGuard: 伪造句柄槽已满(%d)，本次块不再登记（选择泄漏，不提前释放）", kMaxFakeSlots);
	}

	void ReleaseAllFakes() noexcept
	{
		for (int i = 0; i < kMaxFakeSlots; ++i) {
			if (InterlockedCompareExchange(&g_fakeSlots[i].inUse, 0, 1) == 1) {
				const UINT format = g_fakeSlots[i].format;
				HANDLE handle = g_fakeSlots[i].handle;
				g_fakeSlots[i].handle = nullptr;
				g_fakeSlots[i].format = 0;
				R3ShieldCoreClipboardSpoof::FreeFake(format, handle);
				InterlockedIncrement(&g_fakeReleased);
			}
		}
	}

	// ★ v78：剪贴板面的规则求值。
	//
	// 规则按**格式名**匹配（`当 剪贴板 的 格式 等于 文本 时 …`）⇒ 这里用
	// `FormatLabel` 把格式号转成名字。**必须用 codec 里那一份**：自己再
	// switch 一遍必然与"哪些格式算文本"漂移（铁律 127/195）。
	//
	// ⚠️ 抽成函数是为了**决策层与 detour 层问的是同一件事**（铁律 22）。
	RScript::Verdict EvalClipRule(UINT format) noexcept
	{
		WCHAR buf[32] = {};
		// ⚠️ 必须用**返回值**，不能把 `buf` 直接传下去：文本 / 位图这两类
		//    `FormatLabel` 返回的是**静态字符串**，压根不往 `buf` 里写
		//    ⇒ 传 buf 的话匹配到的是空串，`当 剪贴板 的 格式 等于 文本 时 …`
		//      **永远不命中**（只有"未知格式"那一路才填 buf 并返回它）。
		//    这个坑在界面上完全看不出来 —— 规则显示得好好的，就是不生效。
		const WCHAR* label = R3ShieldCoreClipboardSpoof::FormatLabel(format, buf, _countof(buf));
		try {
			return RScript::Eval(RScript::Face::Clip, nullptr, nullptr, label);
		}
		catch (...) {
			return RScript::Verdict{};
		}
	}

	// 「本应拒绝」时的统一出口。
	//
	// ★ v70：开关打开 **且该格式造得出合法替代物** ⇒ 替换；否则 ⇒ 拒绝
	//   （原行为，一字不改）。
	//
	// ★ v78：**规则脚本优先**。命中即按规则处置：
	//     · 替换为 "文本" / 空 ⇒ 替换（**仅文本类格式**，见下）；
	//     · 拒绝             ⇒ 落到下面走拒绝；
	//     · 放行             ⇒ 原样返回真实内容（`Action::Pass`）。
	//   没命中 ⇒ 原样走 v70 的内置判据。
	//
	// ⚠️ 规则要求「替换为 文本」但格式是**位图 / 未知** ⇒ 回落**拒绝**
	//    （铁律 194：造不出合法替代物就不硬造）。把一段文本塞进 CF_BITMAP
	//    的槽里，调用方会把它当位图去解析 —— 那是"替换"新引入的崩溃面。
	// ⚠️ 与注册表面同一条口径：规则的**总闸**仍是 ini 的 `spoof_clipboard=1`
	//    （五个替换开关默认关是刻意的，铁律 199 同族）。
	// ⚠️ 为什么"格式不支持"要**回落拒绝**而不是"照原样返回"：造不出未知格式
	//    的合法布局，硬造一个长度不对的块会让调用方读越界/解析错 —— 那是
	//    "替换"**新引入**的崩溃面。回落拒绝 = v70 之前的行为，安全。
	// ⚠️ 返回 Spoof 时，detour 层**不得**返回 nullptr —— 要真调原函数、
	//    再把返回的句柄换成我们的。
	// ⚠️ 本函数**不**负责置 FlagEvent2Spoofed：那是 detour 层按"替代物是否
	//    真的造出来了"置的。
	Action RejectOrSpoof(R3ShieldCore::Event& event, UINT format) noexcept
	{
		EnsureClipRulesLoaded();

		const R3ShieldCoreClipboardSpoof::FakeKind kind =
			R3ShieldCoreClipboardSpoof::ClassifyFormat(format);
		const bool formatOk = kind != R3ShieldCoreClipboardSpoof::FakeKind::Unsupported;

		// ★ 规则命中 ⇒ **由规则说了算**，不再落到下面的内置替换判据。
		//   ⚠️ 这一条是必须的：规则要求「拒绝」或"要求替换但格式不支持"时，
		//      若继续往下走，内置判据会看到 `formatOk && 开关开着` ⇒ 又把它
		//      变成 Spoof ⇒ **用户写的「拒绝」被静默推翻**。
		//      （v78 单测第一版就是这样：两条"回落拒绝"的断言都红了。）
		bool ruleDecided = false;

		if (SpoofClipboardEnabled()) {
			const RScript::Verdict v = EvalClipRule(format);
			if (v.hit) {
				ruleDecided = true;
				if (v.act == RScript::Act::Pass) {
					event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
					return Action::Pass;
				}
				if (v.act != RScript::Act::Block) {
					// 替换类动作（`ReplaceByte` 已被解析器挡掉）。
					if (kind == R3ShieldCoreClipboardSpoof::FakeKind::Text) {
						event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Spoofed);
						return Action::Spoof;
					}
					// ⚠️ ASCII 子串 `rules_script` 是 v78 代次标记的一部分，别删。
					LOG(L"ClipboardGuard: 规则要求替换为文本，但格式 %u 不是文本类（rules_script 规则 #%d）=> 回落拒绝",
						format, v.index);
				}
			}
		}

		if (!ruleDecided && formatOk && SpoofClipboardEnabled()) {
			// 替换不是"被拦"：不置 FlagEventBlocked，不计 HighRiskBlocked。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Spoofed);
			return Action::Spoof;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return Action::Block;
	}

	Action Evaluate(R3ShieldCore::ClipboardOp op, R3ShieldCore::Event& event,
		bool allowAsk, UINT format) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Clipboard);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式 ----
		// Open is part of the read path; allowing it would leave a detectable
		// operation outside the advertised BlockAll boundary.
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
		return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskClipboard(static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				event.Flags |= R3ShieldCore::FlagEventClipboardRead;
			}
		}

		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// 高危：读取剪贴板内容。
		//
		// ⚠️ 必须再判一次 mode == Ask。Ask 依赖引擎侧 UI 线程，
		//    而那个线程只在 ASK 模式启动 —— LOG/BLOCK 下调 Ask 会等
		//    一个永远不来的答复（实测表现：LOG 模式被当成 Deny 直接拦）。
		const bool canAsk = allowAsk && (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask));
		if (!canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				// ★ v70：本应拒绝 ⇒ 看是否改走"替换"（不支持的格式仍回落拒绝）。
				return RejectOrSpoof(event, format);
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：走“通道可用性”包装 —— 管理员启动引擎时通道打不开，
		//   LOG 模式下降级放行（否则高危操作被静默拒，不可识别）。
		//   见 r3shieldcore_prompt.h 的 AskWithChannelGuard 说明。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return Action::Record;
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// 用户点了"拒绝"（或超时按兜底结论）：★ v70 —— 同样走 RejectOrSpoof。
		return RejectOrSpoof(event, format);
	}

	// 常用剪贴板格式名。只是给用户看个大概 —— 格式号可以是任意注册格式，
	// 没命中就退回数字。不 include winuser.h 里的常量表含义注释。
	const char* ClipboardFormatName(UINT format) noexcept
	{
		switch (format) {
		case 1:  return "CF_TEXT（文本）";
		case 2:  return "CF_BITMAP（位图）";
		case 3:  return "CF_METAFILEPICT";
		case 8:  return "CF_DIB（设备无关位图）";
		case 13: return "CF_UNICODETEXT（Unicode 文本）";
		case 16: return "CF_LOCALE";
		case 17: return "CF_DIBV5";
		default: return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// hook：OpenClipboard（只记录）
	// ------------------------------------------------------------------
	BOOL WINAPI OpenClipboard_Hook(HWND newOwner)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"打开剪贴板", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		event.Status = 0;

		// 只记录：allowAsk = false，且即使判定返回 Block 也不会拦开。
		// 走到 Open 的调用绝大多数是正常粘贴/复制，不该打断。
		// ⚠️ format 传 0：Open 没有格式概念，它永远走不到 RejectOrSpoof
		//    （规则层把 Open 判为非高危）。
		Evaluate(R3ShieldCore::ClipboardOp::Open, event, false, 0);

		const BOOL result = pOriginalOpenClipboard(newOwner);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：GetClipboardData（高危）
	// ------------------------------------------------------------------
	HANDLE WINAPI GetClipboardData_Hook(UINT format)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"读取剪贴板内容", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (const char* name = ClipboardFormatName(format)) {
			// %S 把窄串按当前 ANSI 代码页转宽 —— 这里全是 ASCII，安全。
			swprintf_s(event.ValueName, L"格式 %u：%S", format, name);
		}
		else {
			swprintf_s(event.ValueName, L"格式 %u", format);
		}
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ClipboardOp::Read, event, true, format);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		const HANDLE result = pOriginalGetClipboardData(format);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());

		// ★ v70：替换 —— 真调已经发生（剪贴板状态真实），现在把**返回的句柄**
		//    换成我们自己的中性化块，并**返回它**（调用者看不出区别）。
		//
		// ⚠️ 真调**失败**（该格式此刻不在剪贴板上）⇒ 没有内容可泄露，
		//    如实返回失败，不伪造一个"成功"。
		// ⚠️ 造不出来（分配失败 / 格式其实是 HBITMAP 但句柄不是位图）
		//    ⇒ **如实返回真实句柄**并留日志：这是"替换没做成"，不能假装成功
		//    （铁律 97：不能只有"没生效"）。Decision 仍是 Spoofed，但
		//    FlagEvent2Spoofed 不置 —— 事后能区分这两种情况。
		HANDLE returned = result;
		if (action == Action::Spoof && result) {
			// ★ v78：规则命中「替换为 <文本>」⇒ 用**规则给的文本**；
			//   没命中（或规则给的是"空"）⇒ 回落**生产** `BuildFake`
			//   （文本 ⇒ 空串、位图 ⇒ 同尺寸全 0、DIB ⇒ 像素清零）。
			//
			// ⚠️ `BuildClipText` 返回 nullptr（分配失败）时**落到 `BuildFake`**：
			//   那是"替换成空串"而不是"泄露真实内容" ⇒ 失败方向是安全的
			//   （宁可少给，不可多给）。这种情况下面那条日志会留痕。
			HANDLE fake = nullptr;
			const RScript::Verdict v = EvalClipRule(format);
			if (v.hit
				&& (v.act == RScript::Act::ReplaceText || v.act == RScript::Act::ReplaceEmpty)) {
				const WCHAR* text = (v.act == RScript::Act::ReplaceText) ? v.text.c_str() : L"";
				fake = RApply::BuildClipText(format, text);
			}
			if (!fake) {
				fake = R3ShieldCoreClipboardSpoof::BuildFake(format, result);
			}
			if (fake) {
				TrackFake(format, fake);
				returned = fake;
				event.Flags2 |= R3ShieldCore::FlagEvent2Spoofed;
			}
			else {
				// ⚠️ 这条日志里带 **ASCII** 子串 `spoof_clipboard`，不是给用户看的
				//    装饰 —— 它是 `check_dist_sync.sh` 的 v70 代次标记：
				//    `strings -el`（16 位）只输出 ASCII 可打印字符，纯中文标记
				//    永远查不到（会变成恒 FAIL）。改动这条日志时别把标记删了。
				LOG(L"ClipboardGuard: 剪贴板替换失败（spoof_clipboard，格式 %u 造不出替代物），本次返回真实内容", format);
			}
		}

		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return returned;
	}

	// ------------------------------------------------------------------
	// hook：CloseClipboard（★ v70 新增，只为**回收替换块**）
	// ------------------------------------------------------------------
	//
	// 它**不改** CloseClipboard 的行为（不拦、不改返回值），只是"顺手"在
	// 契约终点把我们的替代物还回去。
	//
	// ⚠️ 只在**原函数成功**时回收：CloseClipboard 成功 ⇒ 说明本线程/本进程
	//    确实是持有者，且这一轮会话已结束 ⇒ 登记在册的块都成了"没人该再用"
	//    的过期块。若原函数**失败**（本来就没开着），贸然回收会误伤另一个
	//    线程**正在进行**的会话里的块 —— 那会让对方读到已释放内存。
	BOOL WINAPI CloseClipboard_Hook()
	{
		InterlockedIncrement(&g_activeHooks);

		const BOOL result = pOriginalCloseClipboard();

		if (result) {
			ReleaseAllFakes();
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// 挂载
	// ------------------------------------------------------------------
	bool QueueHook(LPCSTR moduleName, LPCSTR functionName, LPVOID detour,
		LPVOID* original, bool required) noexcept
	{
		HMODULE module = GetModuleHandleA(moduleName);
		if (!module) {
			if (required) {
				LOG(L"ClipboardGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"ClipboardGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"ClipboardGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"ClipboardGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace ClipboardGuard
{
	int HookCount() noexcept
	{
		return g_hookCount;
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"ClipboardGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	bool Install(HANDLE /*engineProcess*/) noexcept
	{
		if (g_installed) {
			return true;
		}

		if (RegistryGuard::IsBypassed()) {
			g_bypass = true;
			g_installed = true;
			return true;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookClipboard) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ClipboardGuard: hook_clipboard 未开启，本进程不挂剪贴板 hook");
			return true;
		}

		g_bypass = false;

		// user32 在绝大多数有 GUI 的进程里已加载；纯控制台进程不挂也无所谓。
		// 与 ScreenGuard 同理，这里**不主动 LoadLibrary** —— 剪贴板是
		// 交互功能，没加载 user32 的进程本来也不会碰剪贴板。
		HMODULE user32 = GetModuleHandleW(L"user32.dll");
		if (!user32) {
			LOG(L"ClipboardGuard: user32.dll 未加载，本进程不挂剪贴板 hook");
			g_installed = true;
			return true;
		}

		QueueHook("user32.dll", "OpenClipboard", reinterpret_cast<LPVOID>(OpenClipboard_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalOpenClipboard), true);
		QueueHook("user32.dll", "GetClipboardData", reinterpret_cast<LPVOID>(GetClipboardData_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalGetClipboardData), true);

		// ★ v70：CloseClipboard 是**替换块的唯一回收点**。
		//   没挂上 ⇒ 本次**不启用替换**（`SpoofClipboardEnabled` 会返回 false）
		//   —— 宁可退回"拒绝"，也不能造出一批无人回收的块。
		//   见 `RejectOrSpoof` / `g_closeHookReady` 的注释。
		g_closeHookReady = QueueHook("user32.dll", "CloseClipboard",
			reinterpret_cast<LPVOID>(CloseClipboard_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalCloseClipboard), true);
		if (!g_closeHookReady) {
			LOG(L"ClipboardGuard: CloseClipboard 未挂上 ⇒ 本次不启用剪贴板替换"
				L"（替换出来的块将无人回收）");
		}

		g_installed = true;

		LOG(L"ClipboardGuard: 已挂载 %d 个剪贴板 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}

// ==================================================================
// ★ v78：单测专用入口
// ==================================================================
//
// 与 `registry_guard.cpp` 尾部那一段同构：`RejectOrSpoof` / `EvalClipRule`
// 都在本文件的匿名 namespace 里，外部 TU 拿不到，而 v78 要断言的
// **"规则把这次剪贴板读变成了什么处置"** 恰恰就在这里。
//
// 用编译宏隔离（`build_guard_ut.sh` 带、`build.sh` 不带）⇒ 导出表不变。
#ifdef CLIPGUARD_GUARD_UT
namespace ClipboardGuardTest
{
	// ★ 单测**必须**先调这个。
	//   `SpoofClipboardEnabled()` 的判据里有一条"CloseClipboard 挂上了没"
	//   （回收替换块的前提），单测不跑 `Install()` ⇒ 它恒为 false ⇒
	//   **剪贴板面的任何替换路径都测不到**，而且失败原因看不出来
	//   （"规则没生效"和"开关没打开"长得一模一样）。
	void SetCloseHookReady(bool ready) noexcept
	{
		g_closeHookReady = ready;
	}

	// 驱动「本应拒绝」的统一出口。返回 `Action` 的值；
	// `decisionOut` / `flagsOut` 收下判定与标志位（**可空**）。
	int RejectOrSpoofForTest(UINT format, int* decisionOut, ULONG* flagsOut) noexcept
	{
		R3ShieldCore::Event event = {};
		const Action action = RejectOrSpoof(event, format);
		if (decisionOut) *decisionOut = static_cast<int>(event.Decision);
		if (flagsOut)    *flagsOut = event.Flags;
		return static_cast<int>(action);
	}

	// 规则求值本身（**-1 = 没命中**；否则是 `Act` 的值）。`indexOut` 收命中序号。
	//
	// ⚠️ 不能用 0 当"没命中"的哨兵：`Act::ReplaceText` **就是 0**。
	//    这是本项目铁律 110 那一类坑（"哨兵值与合法值撞车 ⇒ 断言恒真"）——
	//    v78 单测第一版就是这么写的，"文本格式命中规则"在**完全没命中**时
	//    也显示 PASS。
	int EvalClipRuleForTest(UINT format, int* indexOut) noexcept
	{
		const RScript::Verdict v = EvalClipRule(format);
		if (indexOut) *indexOut = v.hit ? v.index : -1;
		return v.hit ? static_cast<int>(v.act) : -1;
	}

	// 规则给出的文本（`Act::ReplaceText` 用）。没命中/不是文本动作 ⇒ 空串。
	void RuleTextForTest(UINT format, WCHAR* out, size_t outChars) noexcept
	{
		if (!out || outChars == 0) return;
		out[0] = L'\0';
		const RScript::Verdict v = EvalClipRule(format);
		if (v.hit && v.act == RScript::Act::ReplaceText) {
			wcsncpy_s(out, outChars, v.text.c_str(), _TRUNCATE);
		}
	}
}
#endif // CLIPGUARD_GUARD_UT
