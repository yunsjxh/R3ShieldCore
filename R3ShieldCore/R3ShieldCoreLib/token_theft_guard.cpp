#include "stdafx.h"
#include "token_theft_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 令牌窃取 / 冒充监控层（v13）。
//
// 见 token_theft_guard.h 的详细说明（挂载点、三档判据、生存关键）。
//
// 本文件里最值得注意的是 **AdjustTokenPrivileges 的精细判据**：
//   规则层只说"这一档语义是铺路"，但真正决定要不要上报的是这里的
//   AnalyzePrivileges —— 它把 NewState 里的 LUID 一个个翻成名字，
//   只有命中 SeDebugPrivilege / SeImpersonatePrivilege / SeTcbPrivilege
//   **且是启用（SE_PRIVILEGE_ENABLED）** 才上报。
//
//   为什么必须这么细：AdjustTokenPrivileges 是**极高频**调用 ——
//   每个服务启动都会调它调整自己令牌、每次 UAC 提权会话都会调、
//   PsExec/ProcessHacker 这类工具启动时都要开一批特权。
//   如果"调了就报"，日志会被刷爆（v10/v12 已栽两次）。
//   而真正危险的是那三个"能拿到别人身份"的特权，不是所有特权。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef BOOL(WINAPI* OpenProcessTokenPtr)(HANDLE, DWORD, PHANDLE);
	typedef BOOL(WINAPI* OpenThreadTokenPtr)(HANDLE, DWORD, BOOL, PHANDLE);
	typedef BOOL(WINAPI* DuplicateTokenExPtr)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES,
		SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
	typedef BOOL(WINAPI* ImpersonateLoggedOnUserPtr)(HANDLE);
	typedef BOOL(WINAPI* SetThreadTokenPtr)(PHANDLE, HANDLE);
	typedef BOOL(WINAPI* AdjustTokenPrivilegesPtr)(HANDLE, BOOL, PTOKEN_PRIVILEGES,
		DWORD, PTOKEN_PRIVILEGES, PDWORD);

	OpenProcessTokenPtr pOriginalOpenProcessToken = nullptr;
	OpenThreadTokenPtr pOriginalOpenThreadToken = nullptr;
	DuplicateTokenExPtr pOriginalDuplicateTokenEx = nullptr;
	ImpersonateLoggedOnUserPtr pOriginalImpersonateLoggedOnUser = nullptr;
	SetThreadTokenPtr pOriginalSetThreadToken = nullptr;
	AdjustTokenPrivilegesPtr pOriginalAdjustTokenPrivileges = nullptr;

	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;

	enum class Action
	{
		Pass,
		Record,
		Block,
	};

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// ------------------------------------------------------------------
	// 令牌链关联状态（thread_local）
	// ------------------------------------------------------------------
	//
	// 一档调用后置位；二档读它。窗口 5 秒 —— 正常窃取链是毫秒级连续动作，
	// 而"我五分钟前开过别人的令牌"跟"我现在要复制它"没关系。
	//
	// ⚠️ 用 thread_local 而不是全局：见头文件说明。
	constexpr DWORDLONG kTokenChainWindowMs = 5000;
	thread_local DWORDLONG g_tokenPreparedAt = 0;

	// ------------------------------------------------------------------
	// 特权分析（AdjustTokenPrivileges 的精细判据）
	// ------------------------------------------------------------------
	//
	// 返回命中的"危险特权"个数，并把这些名字拼进 out 供事件展示。
	//
	// 危险特权（能直接拿到别人身份的）：
	//   SeDebugPrivilege       —— 打开任意进程的句柄（含 SYSTEM）→ 拿令牌的前提
	//   SeImpersonatePrivilege —— 拿到令牌后可冒充（服务账户默认就有，是
	//                              "土豆"系列提权的核心）
	//   SeTcbPrivilege         —— 内核级"我是操作系统的一部分"，可改任意令牌
	//   SeAssignPrimaryTokenPrivilege —— 可给进程指定任意令牌（CreateProcessAsUser）
	//   SeBackupPrivilege      —— 读任意文件（含 SAM）→ 拿哈希
	//
	// ⚠️ 只算 **SE_PRIVILEGE_ENABLED**（真正启用）。SE_PRIVILEGE_ENABLED_BY_DEFAULT
	//    单独出现不算 —— 那只是"默认启用标记"，很多进程天然带着。
	//
	// ⚠️ 不能有需要析构的对象（__try 编不过的要求在调用方保证）。
	int AnalyzePrivileges(const TOKEN_PRIVILEGES* state, WCHAR* out, size_t cch) noexcept
	{
		if (out && cch) {
			out[0] = L'\0';
		}
		if (!state) {
			return 0;
		}

		int hits = 0;
		const DWORD count = state->PrivilegeCount;
		// 防吹：恶意/损坏的 PrivilegeCount 可能是天文数字，读它会崩。
		// 正常进程很少有超过 20 个特权。
		const DWORD limit = (count > 32) ? 32 : count;

		for (DWORD i = 0; i < limit; i++) {
			const LUID_AND_ATTRIBUTES& entry = state->Privileges[i];

			// ★ 只认"启用"。这是压制噪音的第一道闸。
			if ((entry.Attributes & SE_PRIVILEGE_ENABLED) == 0) {
				continue;
			}

			WCHAR name[64] = {};
			DWORD nameLen = _countof(name);
			if (!LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&entry.Luid),
				name, &nameLen)) {
				continue;
			}

			// 只关心那几个"能拿别人身份"的。
			const bool dangerous =
				_wcsicmp(name, L"SeDebugPrivilege") == 0 ||
				_wcsicmp(name, L"SeImpersonatePrivilege") == 0 ||
				_wcsicmp(name, L"SeTcbPrivilege") == 0 ||
				_wcsicmp(name, L"SeAssignPrimaryTokenPrivilege") == 0 ||
				_wcsicmp(name, L"SeBackupPrivilege") == 0;

			if (!dangerous) {
				continue;
			}

			hits++;
			if (out && cch) {
				if (out[0]) {
					wcsncat_s(out, cch, L"|", _TRUNCATE);
				}
				wcsncat_s(out, cch, name, _TRUNCATE);
			}
		}

		return hits;
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::TokenTheft);
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

	//
	// 共用判定骨架。
	//
	// ⚠️ 关键取舍：**一档（tier==1）不进通道**。
	//    与 ComHijackGuard 的"非高危不进通道"同思路 —— 让 OpenProcessToken
	//    这种满天飞的调用根本不产生事件，只留 thread_local 状态供关联。
	//    （如果一档也上报，日志会被进程管理器/调试器刷爆。）
	//
	// forceHighRisk 用于 AdjustTokenPrivileges：规则层说它是高危，
	// 但**实际是否高危由调用方用 AnalyzePrivileges 决定** —— 只有
	// 真开了危险特权才把 forceHighRisk 置 true 传进来。
	//
	Action Evaluate(R3ShieldCore::TokenTheftOp op, R3ShieldCore::Event& event,
		bool allowAsk, bool forceHighRisk, bool chainFollowUp) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::TokenTheft);
		event.Op = static_cast<ULONG>(op);

		ULONG tier = 0;
		R3ShieldCoreRules::TokenTheftRiskReason(static_cast<ULONG>(op), &tier);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 一档：只记录状态，不进通道，不产生事件 ----
		//
		// 返回 Pass 表示"调用方照原样调原函数，什么都不用管"。
		if (tier == 1 && !forceHighRisk) {
			return Action::Pass;
		}
		// tier==2 恒高危；tier==3 需 forceHighRisk。
		const bool highRisk = forceHighRisk || (tier >= 2);

		if (!highRisk && !chainFollowUp) {
			// 非高危且非关联补报 —— 不进通道。
			return Action::Pass;
		}

		// 打标：二档（使用）与三档（铺路）。
		if (tier == 2) {
			event.Flags2 |= R3ShieldCore::FlagEvent2TokenUsed;
		}
		else if (tier == 3) {
			event.Flags2 |= R3ShieldCore::FlagEvent2TokenPrivEscalation;
		}
		if (chainFollowUp) {
			// 这条链前面有"准备"动作 —— 是一整条窃取链的一段。
			event.Flags2 |= R3ShieldCore::FlagEvent2TokenPrepared;
		}

		// ---- 完全拦截模式（★ v66：恢复为"直接拒"，撤销 v29 的"先问再拦"）----
		//
		// ★ 为什么现在可以（且应该）直接拒 —— v29 的理由**已经过时**：
		//
		//   v29（2026-09-30）的论证是"`consent.exe` 会被注入本引擎，
		//   一刀切 Block 会断掉 UAC 提权链"。但**当前代码里 `consent.exe`
		//   根本不会被注入**：
		//     · `inject_policy.cpp` 的 `kNeverInject[]` **第 27 行就是
		//       `L"consent.exe"`**；
		//     · `ClassifyImagePath()` 的顺序是
		//       `IsUnderWindowsDirectory` → `BaseNameInList(kNeverInject)`
		//       → 返回 `Mode::Skip`（见 inject_policy.cpp:279-287）；
		//     · 而且 `LogonUI.exe` / `winlogon.exe` / `CredentialUIBroker.exe`
		//       同在该名单里。
		//   ⇒ UAC 同意框、登录界面这些进程里**一个 guard 都没装**，
		//     本函数在它们里面**不会被执行** ⇒ "直接拒会打断 UAC"不成立。
		//
		//   另外，提权链的父进程是 `svchost.exe`（AppInfo 服务），它走
		//   **瘦会话**（只装 CreateProcessInternalW，不装任何 guard）
		//   ⇒ 提权链上也没有本函数。
		//
		// ★ 为什么"令牌"这一类该硬拒而不是放行（与注册表/文件写不同）：
		//   注册表/文件写的"普通档"是**正常软件写自己的配置**，拒了会挡住
		//   程序启动（v25 事故）。而 `AdjustTokenPrivileges` /
		//   `DuplicateTokenEx` / `CreateProcessWithTokenW` 是**特权操作**，
		//   不是程序启动的必经之路 —— 拒掉的只是"提权/借用令牌"这个动作本身。
		//   ⇒ 符合"不影响程序启动"这条要求。
		//
		// ⚠️ 计数口径：本分支不再 `HighRiskAsked++`（不问任何人），
		//    被拒事件仍写 `Decision=Blocked` + `FlagEventBlocked`。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
			event.Flags |= R3ShieldCore::FlagEventHighRisk;

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		if (highRisk) {
			event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
			event.Flags |= R3ShieldCore::FlagEventHighRisk;
		}

		// ---- 非高危（只是关联补报）：按 mode 处理，不拦 ----
		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// ---- 高危 ----
		const bool canAsk = allowAsk && (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask));
		if (!canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return Action::Block;
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

		// ★ v29：走"通道可用性"包装 —— 管理员启动引擎时通道打不开，
		//   LOG 模式下降级放行（否则 UAC 提权链的 AdjustTokenPrivileges
		//   被静默拒 → 连 UAC 框都不出现）。见 r3shieldcore_prompt.h 说明。
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

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return Action::Block;
	}

	// 填目标描述：KeyPath 放"操作对象"，ValueName 放补充。
	void SetTarget(R3ShieldCore::Event& event, PCWSTR text) noexcept
	{
		if (text && text[0]) {
			wcsncpy_s(event.KeyPath, text, _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
	}

	void SetDetail(R3ShieldCore::Event& event, PCWSTR text) noexcept
	{
		if (text && text[0]) {
			wcsncpy_s(event.ValueName, text, _TRUNCATE);
		}
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
	}

	// ------------------------------------------------------------------
	// 一档 hook：OpenProcessToken / OpenThreadToken
	// ------------------------------------------------------------------
	//
	// ⚠️ 这两个 hook **不产生事件**（Evaluate 对 tier==1 返回 Pass）。
	//    它们的作用只有一个：置 thread_local 关联状态。
	//    这既是"可见性"的损失（看不到谁在读令牌），也是**必要的代价** ——
	//    换成上报就等于日志雪崩（见头文件说明）。
	//
	BOOL WINAPI OpenProcessToken_Hook(HANDLE processHandle, DWORD desiredAccess, PHANDLE tokenHandle)
	{
		InterlockedIncrement(&g_activeHooks);

		const BOOL ok = pOriginalOpenProcessToken
			? pOriginalOpenProcessToken(processHandle, desiredAccess, tokenHandle)
			: FALSE;

		// 只有真的拿到了令牌句柄才算"准备完成"。
		if (ok && tokenHandle && *tokenHandle) {
			// 只关心"能复制/能冒充"的访问权限 —— 只查 TOKEN_QUERY
			// （读点信息）的不算。
			const bool usable = (desiredAccess & (TOKEN_DUPLICATE | TOKEN_IMPERSONATE
				| TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS)) != 0;
			if (usable) {
				TokenTheftGuard::MarkTokenPrepared();
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return ok;
	}

	BOOL WINAPI OpenThreadToken_Hook(HANDLE threadHandle, DWORD desiredAccess,
		BOOL openAsSelf, PHANDLE tokenHandle)
	{
		InterlockedIncrement(&g_activeHooks);

		const BOOL ok = pOriginalOpenThreadToken
			? pOriginalOpenThreadToken(threadHandle, desiredAccess, openAsSelf, tokenHandle)
			: FALSE;

		if (ok && tokenHandle && *tokenHandle) {
			const bool usable = (desiredAccess & (TOKEN_DUPLICATE | TOKEN_IMPERSONATE
				| TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS)) != 0;
			if (usable) {
				TokenTheftGuard::MarkTokenPrepared();
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return ok;
	}

	// ------------------------------------------------------------------
	// 二档 hook：DuplicateTokenEx / ImpersonateLoggedOnUser / SetThreadToken
	// ------------------------------------------------------------------

	BOOL WINAPI DuplicateTokenEx_Hook(HANDLE existingToken, DWORD desiredAccess,
		LPSECURITY_ATTRIBUTES tokenAttributes, SECURITY_IMPERSONATION_LEVEL level,
		TOKEN_TYPE type, PHANDLE newToken)
	{
		InterlockedIncrement(&g_activeHooks);

		const bool chain = TokenTheftGuard::WasTokenPreparedRecently();

		R3ShieldCore::Event event = {};
		SetTarget(event, L"复制令牌（DuplicateTokenEx）");

		WCHAR detail[192] = {};
		const WCHAR* levelText = L"未知";
		switch (level) {
		case SecurityAnonymous: levelText = L"Anonymous"; break;
		case SecurityIdentification: levelText = L"Identification"; break;
		case SecurityImpersonation: levelText = L"Impersonation"; break;
		case SecurityDelegation: levelText = L"Delegation"; break;
		default: break;
		}
		swprintf_s(detail, L"模拟级别=%s  类型=%s%s",
			levelText,
			type == TokenPrimary ? L"Primary(可直接起进程)" : L"Impersonation(可冒充)",
			chain ? L"  ← 本线程刚拿过令牌（一整条窃取链）" : L"");
		SetDetail(event, detail);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::DuplicateTokenEx,
			event, true, false, chain);

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL ok = pOriginalDuplicateTokenEx
			? pOriginalDuplicateTokenEx(existingToken, desiredAccess, tokenAttributes,
				level, type, newToken)
			: FALSE;
		event.Status = ok ? 0u : GetLastError();
		Publish(event);

		// 链已走完这一步，清掉状态（避免后续无关调用被误关联）。
		if (chain) {
			TokenTheftGuard::ClearTokenPrepared();
		}

		InterlockedDecrement(&g_activeHooks);
		return ok;
	}

	BOOL WINAPI ImpersonateLoggedOnUser_Hook(HANDLE token)
	{
		InterlockedIncrement(&g_activeHooks);

		const bool chain = TokenTheftGuard::WasTokenPreparedRecently();

		R3ShieldCore::Event event = {};
		SetTarget(event, L"冒充登录用户（ImpersonateLoggedOnUser）");
		SetDetail(event, chain
			? L"本线程身份被换成令牌持有者  ← 本线程刚拿过令牌（一整条窃取链）"
			: L"本线程身份被换成令牌持有者");
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::ImpersonateLoggedOnUser,
			event, true, false, chain);

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL ok = pOriginalImpersonateLoggedOnUser
			? pOriginalImpersonateLoggedOnUser(token)
			: FALSE;
		event.Status = ok ? 0u : GetLastError();
		Publish(event);

		if (chain) {
			TokenTheftGuard::ClearTokenPrepared();
		}

		InterlockedDecrement(&g_activeHooks);
		return ok;
	}

	BOOL WINAPI SetThreadToken_Hook(PHANDLE thread, HANDLE token)
	{
		InterlockedIncrement(&g_activeHooks);

		const bool chain = TokenTheftGuard::WasTokenPreparedRecently();

		R3ShieldCore::Event event = {};
		SetTarget(event, L"替换线程令牌（SetThreadToken）");
		// token == NULL 是"撤销令牌"（RevertToSelf 语义），不是窃取 —— 但仍然值得记录。
		SetDetail(event, token == nullptr
			? L"撤销线程令牌（token=NULL）"
			: (chain ? L"给线程换令牌  ← 本线程刚拿过令牌（一整条窃取链）"
				: L"给线程换令牌"));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::SetThreadToken,
			event, true, false, chain);

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL ok = pOriginalSetThreadToken
			? pOriginalSetThreadToken(thread, token)
			: FALSE;
		event.Status = ok ? 0u : GetLastError();
		Publish(event);

		if (chain) {
			TokenTheftGuard::ClearTokenPrepared();
		}

		InterlockedDecrement(&g_activeHooks);
		return ok;
	}

	// ------------------------------------------------------------------
	// 三档 hook：AdjustTokenPrivileges（精细判据）
	// ------------------------------------------------------------------
	BOOL WINAPI AdjustTokenPrivileges_Hook(HANDLE token, BOOL disableAll,
		PTOKEN_PRIVILEGES newState, DWORD bufferLength,
		PTOKEN_PRIVILEGES previousState, PDWORD returnLength)
	{
		InterlockedIncrement(&g_activeHooks);

		// ★ 精细判据：只有真的启用了危险特权才算高危。
		WCHAR privNames[256] = {};
		int dangerousCount = 0;
		if (!disableAll && newState) {
			dangerousCount = AnalyzePrivileges(newState, privNames, _countof(privNames));
		}

		// 没开危险特权 → 不产生事件（这是压制噪音的关键）。
		// ⚠️ 这里**必须**直接透传：AdjustTokenPrivileges 高频到不能有额外开销。
		if (dangerousCount == 0) {
			const BOOL ok = pOriginalAdjustTokenPrivileges
				? pOriginalAdjustTokenPrivileges(token, disableAll, newState,
					bufferLength, previousState, returnLength)
				: FALSE;
			InterlockedDecrement(&g_activeHooks);
			return ok;
		}

		const bool chain = TokenTheftGuard::WasTokenPreparedRecently();

		R3ShieldCore::Event event = {};
		SetTarget(event, L"启用令牌特权（AdjustTokenPrivileges）");
		WCHAR detail[384] = {};
		swprintf_s(detail, L"启用 %d 个敏感特权：%s%s",
			dangerousCount, privNames,
			chain ? L"  ← 本线程刚拿过令牌（一整条窃取链）" : L"");
		SetDetail(event, detail);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::AdjustTokenPrivileges,
			event, true, /*forceHighRisk=*/true, chain);

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL ok = pOriginalAdjustTokenPrivileges
			? pOriginalAdjustTokenPrivileges(token, disableAll, newState,
				bufferLength, previousState, returnLength)
			: FALSE;
		event.Status = ok ? 0u : GetLastError();
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return ok;
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
				LOG(L"TokenTheftGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"TokenTheftGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"TokenTheftGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"TokenTheftGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace TokenTheftGuard
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
				LOG(L"TokenTheftGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	// 令牌链关联状态（thread_local 实现）
	void MarkTokenPrepared() noexcept
	{
		g_tokenPreparedAt = GetTickCount64();
	}

	bool WasTokenPreparedRecently() noexcept
	{
		if (g_tokenPreparedAt == 0) {
			return false;
		}
		return (GetTickCount64() - g_tokenPreparedAt) <= kTokenChainWindowMs;
	}

	void ClearTokenPrepared() noexcept
	{
		g_tokenPreparedAt = 0;
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookTokenTheft) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"TokenTheftGuard: hook_token_theft 未开启，本进程不挂令牌窃取 hook");
			return true;
		}

		g_bypass = false;

		// advapi32 在所有进程里都加载（kernel32 依赖它），
		// 不需要主动 LoadLibrary。全部 7 个 API 实测都是 advapi32 直接导出。
		QueueHook("advapi32.dll", "OpenProcessToken",
			reinterpret_cast<LPVOID>(OpenProcessToken_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalOpenProcessToken), true);
		QueueHook("advapi32.dll", "OpenThreadToken",
			reinterpret_cast<LPVOID>(OpenThreadToken_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalOpenThreadToken), false);
		QueueHook("advapi32.dll", "DuplicateTokenEx",
			reinterpret_cast<LPVOID>(DuplicateTokenEx_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalDuplicateTokenEx), true);
		QueueHook("advapi32.dll", "ImpersonateLoggedOnUser",
			reinterpret_cast<LPVOID>(ImpersonateLoggedOnUser_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalImpersonateLoggedOnUser), true);
		QueueHook("advapi32.dll", "SetThreadToken",
			reinterpret_cast<LPVOID>(SetThreadToken_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalSetThreadToken), false);
		QueueHook("advapi32.dll", "AdjustTokenPrivileges",
			reinterpret_cast<LPVOID>(AdjustTokenPrivileges_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalAdjustTokenPrivileges), true);

		g_installed = true;

		LOG(L"TokenTheftGuard: 已挂载 %d 个令牌 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}

// ==================================================================
// ★ 单测专用入口（v29）
// ==================================================================
//
// 为什么需要它：`Evaluate` 在本文件的**匿名 namespace**（line 26~637）里，
// 外部 TU 拿不到；而 v29 的修复点（"block_all 下 AdjustTokenPrivileges
// 改为先问再拦 + 通道不可用降级放行，以保住 UAC 提权链"）**就在 Evaluate 里**。
// 规则层单测（`build_ut.sh` 只链 `r3shieldcore_rules.cpp`）**测不到**它。
//
// 用编译宏 `REGUARD_GUARD_UT` 隔离：**只在单测构建里编译**，
// 生产构建（build.sh）不带这个宏 ⇒ 导出表不变（仍是 10 个）。
//
// 语义：用给定的 op / forceHighRisk 跑一遍真实的 `Evaluate`，返回 Decision
// 与 Action，供单测断言。`SetTarget/SetDetail` 不需要 —— event 由 Evaluate 自己填。
#ifdef REGUARD_GUARD_UT
namespace TokenTheftGuardTest
{
	struct EvalOutcome
	{
		R3ShieldCore::Decision Decision; // Evaluate 写进 event 的最终决策
		ULONG Flags;                 // event.Flags（含 FlagEventBlocked / FlagEventHighRisk）
		ULONG Flags2;                // event.Flags2（含 FlagEvent2AskUnavailable 等）
		int   Action;                // Evaluate 的返回值（Action::Pass/Record/Block）
		bool  Blocked;               // Action == Block 的便捷布尔
	};

	// ★ 关键：调整令牌特权的"完全拦截"路径（UAC 断裂点）。
	//   真实 hook 里 Evaluate(AdjustTokenPrivileges, ..., allowAsk=false,
	//   forceHighRisk=<真开了危险特权>, ...)，单测直连同一条路。
	EvalOutcome EvaluateAdjustTokenPrivileges(ULONG mode, bool forceHighRisk) noexcept
	{
		R3ShieldCore::Event event = {};
		SetTarget(event, L"调整令牌特权（AdjustTokenPrivileges）");

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::AdjustTokenPrivileges,
			event, /*allowAsk=*/false, forceHighRisk, /*chainFollowUp=*/false);

		EvalOutcome out = {};
		out.Decision = static_cast<R3ShieldCore::Decision>(event.Decision);
		out.Flags = event.Flags;
		out.Flags2 = event.Flags2;
		out.Action = static_cast<int>(action);
		out.Blocked = (action == Action::Block);
		return out;
	}

	// 供"高危 ASK 分支"的通道可用性断言复用（DuplicateTokenEx 走 allowAsk=true）。
	EvalOutcome EvaluateDuplicateTokenEx(ULONG mode, bool /*forceHighRisk*/) noexcept
	{
		R3ShieldCore::Event event = {};
		SetTarget(event, L"复制令牌（DuplicateTokenEx）");

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::DuplicateTokenEx,
			event, /*allowAsk=*/true, /*forceHighRisk=*/false, /*chainFollowUp=*/false);

		EvalOutcome out = {};
		out.Decision = static_cast<R3ShieldCore::Decision>(event.Decision);
		out.Flags = event.Flags;
		out.Flags2 = event.Flags2;
		out.Action = static_cast<int>(action);
		out.Blocked = (action == Action::Block);
		return out;
	}

	// 供"一档非高危 → Pass"的断言用（OpenProcessToken 是 tier=1）。
	EvalOutcome EvaluateOpenProcessToken(ULONG mode) noexcept
	{
		R3ShieldCore::Event event = {};
		SetTarget(event, L"获取进程令牌（OpenProcessToken）");

		const Action action = Evaluate(R3ShieldCore::TokenTheftOp::OpenProcessToken,
			event, /*allowAsk=*/true, /*forceHighRisk=*/false, /*chainFollowUp=*/false);

		EvalOutcome out = {};
		out.Decision = static_cast<R3ShieldCore::Decision>(event.Decision);
		out.Flags = event.Flags;
		out.Flags2 = event.Flags2;
		out.Action = static_cast<int>(action);
		out.Blocked = (action == Action::Block);
		return out;
	}

	// ★ v66：**任意 op** 的通用入口。
	//
	// 为什么需要（而不是每个 op 写一个包装）：
	//   v66 的验收要求是"全拦模式下**所有**令牌高危 op 都直接拒"。
	//   如果单测只覆盖手写的那 2~3 个 op，就会漏掉
	//   `ImpersonateLoggedOnUser` / `CreateProcessWithToken` / `SetThreadToken`
	//   —— 而它们和已覆盖的那些**走同一个 block_all 分支**，
	//   漏测等于没测（改了分支却不知道）。
	//   有了通用入口，单测可以直接遍历 `TokenTheftOp` 全枚举，
	//   断言口径自然 ≥ 触发口径（铁律 99）。
	//
	// ⚠️ `allowAsk` 由调用方给：真实 hook 里二档传 true、三档传 false，
	//    单测遍历时**两种都要试**，否则"漏改 allowAsk=true 那条"测不出来。
	EvalOutcome EvaluateAnyOp(ULONG op, ULONG mode, bool allowAsk,
		bool forceHighRisk, bool chainFollowUp) noexcept
	{
		R3ShieldCore::Event event = {};
		SetTarget(event, L"令牌操作（单测遍历）");

		const Action action = Evaluate(static_cast<R3ShieldCore::TokenTheftOp>(op),
			event, allowAsk, forceHighRisk, chainFollowUp);

		EvalOutcome out = {};
		out.Decision = static_cast<R3ShieldCore::Decision>(event.Decision);
		out.Flags = event.Flags;
		out.Flags2 = event.Flags2;
		out.Action = static_cast<int>(action);
		out.Blocked = (action == Action::Block);
		return out;
	}
}
#endif // REGUARD_GUARD_UT
