//
// v29_guard_ut.cpp —— R3ShieldCore「令牌 Guard 在全拦模式下的行为」单测。
//
// ★ 名字的来历（**别被文件名骗了**）：
//   本文件是 v29（2026-09-30）为"block_all 先问再拦 + 通道不可用降级放行"
//   建立的单测。**v66 已把那条语义整体撤销**（全拦就是全拦：直接拒、不弹窗），
//   所以本文件的断言也已**按 v66 改写**。
//   文件名保留 `v29_` 是因为构建脚本 `build_guard_ut.sh` 按 `vNN_guard_ut`
//   命名约定枚举（改名要同步脚本 + 文档两处名字清单，收益不抵风险）。
//
// ==================================================================
// v66 的语义（本文件现在断言的就是它）
// ==================================================================
//
//   全拦模式（`block_all` / `block_all_safe`）下，令牌类高危操作
//   （`AdjustTokenPrivileges` / `DuplicateTokenEx` / `ImpersonateLoggedOnUser` /
//     `CreateProcessWithToken` / `SetThreadToken`）：
//
//     · **直接拒** —— 不弹窗、不问用户、不看 `prompt_default`；
//     · 事件写 `Decision=Blocked` + `FlagEventBlocked` + `FlagEventHighRisk`；
//     · **一次都不碰询问通道**（这是 v66 新增的可数判据）。
//
//   ⚠️ 一档（`OpenProcessToken` / `OpenThreadToken`）**不变**：
//      它只是令牌窃取链的起点、满天飞，仍走 `Action::Pass`（不产生事件）。
//
// ==================================================================
// 为什么 v29 的"先问再拦"可以撤销（**这是本文件最关键的一段注释**）
// ==================================================================
//
//   v29 的论证是：UAC 提权链**必经** `AdjustTokenPrivileges`，
//   而 `consent.exe` 会被注入本引擎 ⇒ 一刀切 Block 会断掉提权链
//   ⇒ **连 UAC 框都弹不出来**。
//
//   ★ 这个前提**已经过时**，当前代码里 `consent.exe` 根本不会被注入：
//     · `inject_policy.cpp` 的 `kNeverInject[]` 里就有 `L"consent.exe"`；
//     · `ClassifyImagePath()` 的顺序是
//       `IsUnderWindowsDirectory` → `BaseNameInList(kNeverInject)`
//       → 返回 `Mode::Skip`；
//     · `LogonUI.exe` / `winlogon.exe` / `CredentialUIBroker.exe` 同在该名单里；
//     · 提权链的父进程 `svchost.exe`（AppInfo 服务）走**瘦会话**
//       —— 只装 `CreateProcessInternalW`，**一个 guard 都不装**。
//     ⇒ 提权链上**没有任何 guard**，本函数在那条链上不会被执行。
//
//   ⇒ 于是 v66 把「全拦」恢复成硬拒，并另外用一条**最小白名单**
//     （`R3ShieldCoreRules::IsUacConsentImage`，见 `uacwhitelist_ut.cpp`）
//     在**进程创建**那条路上给 UAC 同意框留一条缝。
//     两件事分工不同，别混：白名单管"进程起不起得来"，
//     本文件管"令牌操作拒不拒"。
//
// ==================================================================
// 为什么这个单测和 `build_ut.sh` 不同（测的是 **guard 层**）
// ==================================================================
//   `build_ut.sh` 只链 `r3shieldcore_rules.cpp`，那条路**测不到** `Evaluate`。
//   本文件直接编译 `token_theft_guard.cpp` + `guard_stub.cpp`
//   （桩见 `tools/guard_stub.cpp`），编译时定义 `REGUARD_GUARD_UT`
//   打开 `token_theft_guard.cpp` 尾部那个单测入口。构建脚本 `build_guard_ut.sh`。
//
// ==================================================================
// ★ 判据设计说明：为什么"不弹窗"必须用**计数**断言（铁律 97 / 110）
// ==================================================================
//   "全拦模式不弹窗"是一个**否定式**要求。
//   如果只断言 `Decision == Blocked`，那么
//     (a) 直接拒                     → Decision = Blocked
//     (b) 先弹窗、用户拒绝后再拒       → Decision = Blocked
//   这两条**实现完全相反**的代码会给出**同一个** Decision
//   ⇒ 断言恒真、测不出回归（这就是铁律 110 说的"全零时也成立"的空真判据）。
//   所以本文件对每条 block_all 用例**额外断言**：
//     `GuardStub::AskAttemptCount() == 0`  （一次都没碰过询问通道）
//   并在第 8 节放一条**负对照**：ASK 模式下同一个计数必须 `> 0`
//   —— 证明计数器本身是活的，而不是恒为 0 的死值。
//
// ==================================================================
// ★ 判据设计说明之二：期望值**从规则层推导**，不手抄 tier 表
// ==================================================================
//   "哪个 op 该被拒"取决于 `r3shieldcore_rules.cpp` 的 tier 表
//   （1=准备 / 2=使用 / 3=铺路）。单测**不抄**这张表，
//   而是直接调 `R3ShieldCoreRules::TokenTheftRiskReason()` 拿 tier
//   —— 与 `token_theft_guard.cpp` 用的是**同一个函数**。
//   理由：抄一份就会漂（铁律 127「同一份清单拷贝多份⇒必漂」）。
//   代价是"单测和被测代码共用一个判据"，所以第 1/2 节**另配了手写期望**的
//   定点用例（AdjustTokenPrivileges 必须拒、OpenProcessToken 必须 Pass），
//   两者一起看才能区分"实现错了"和"表错了"。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <r3shieldcore/r3shieldcore_shared.h>
#include <r3shieldcore_rules.h>

// token_theft_guard.cpp 尾部的单测入口（宏 REGUARD_GUARD_UT 打开）。
namespace TokenTheftGuardTest
{
	struct EvalOutcome
	{
		R3ShieldCore::Decision Decision;
		ULONG Flags;
		ULONG Flags2;
		int   Action;
		bool  Blocked;
	};

	EvalOutcome EvaluateAdjustTokenPrivileges(ULONG mode, bool forceHighRisk) noexcept;
	EvalOutcome EvaluateDuplicateTokenEx(ULONG mode, bool /*forceHighRisk*/) noexcept;
	EvalOutcome EvaluateOpenProcessToken(ULONG mode) noexcept;

	// ★ v66：任意 op 的通用入口（遍历全枚举用，见文件头说明之二）。
	EvalOutcome EvaluateAnyOp(ULONG op, ULONG mode, bool allowAsk,
		bool forceHighRisk, bool chainFollowUp) noexcept;
}

// guard_stub.cpp 提供的控制器。
namespace GuardStub
{
	void SetMode(ULONG mode) noexcept;
	void SetHighRisk(bool on) noexcept;
	void SetPromptOpen(bool open) noexcept;
	void ResetPolicy() noexcept;
	bool HasEvent() noexcept;
	R3ShieldCore::Event LastEvent() noexcept;
	void ClearEvent() noexcept;

	// ★ v66：询问通道被尝试的次数（见文件头"判据设计说明"）。
	ULONG AskAttemptCount() noexcept;
	void  ResetAskAttemptCount() noexcept;
}

// 与 R3ShieldCore::Mode 对齐。
enum ProbeMode
{
	ModeLog = 0,
	ModeBlock = 1,
	ModeAsk = 2,
	ModeBlockAll = 3,
	ModeBlockAllSafe = 4,
};

// 与 token_theft_guard.cpp 匿名 namespace 里的 Action 对齐。
enum ProbeAction
{
	ActionPass = 0,
	ActionRecord = 1,
	ActionBlock = 2,
};

static int g_pass = 0;
static int g_fail = 0;

static const char* ModeName(ULONG mode)
{
	switch (mode) {
	case ModeLog: return "LOG";
	case ModeBlock: return "BLOCK";
	case ModeAsk: return "ASK";
	case ModeBlockAll: return "BLOCK_ALL";
	case ModeBlockAllSafe: return "BLOCK_ALL_SAFE";
	default: return "?";
	}
}

static const char* ActionName(int action)
{
	switch (action) {
	case ActionPass: return "Pass";
	case ActionRecord: return "Record";
	case ActionBlock: return "Block";
	default: return "?";
	}
}

// 把 event.Flags2 里的 tier 标记翻成可读串，便于失败时一眼看出"哪一档"。
static const char* TierFlagName(ULONG flags2)
{
	if (flags2 & R3ShieldCore::FlagEvent2TokenPrivEscalation) return "三档(0x400)";
	if (flags2 & R3ShieldCore::FlagEvent2TokenUsed) return "二档(0x200)";
	if (flags2 & R3ShieldCore::FlagEvent2TokenPrepared) return "一档(0x100)";
	return "无";
}

int main()
{
	setlocale(LC_ALL, ".UTF8");

	// ===============================================================
	// 1. ★★★ v66 核心：block_all + AdjustTokenPrivileges → **直接拒**
	//
	//    这是 v29 那个"UAC 弹不出来"的复现点。v66 后的期望是**拒**，
	//    并且**一次都不碰询问通道**（v29 的"降级放行"已撤销）。
	//
	//    同时断言 Flags2 **不含** FlagEvent2AskUnavailable
	//    —— 那个标记的含义是"可问项因通道不可用而降级放行"，
	//      硬拒路径下它必须**不存在**，否则日志会撒谎。
	// ===============================================================
	printf("=== 1. ★★★ v66 核心：block_all + AdjustTokenPrivileges → 直接拒（不弹窗）===\n");
	{
		const struct Case { const char* note; ULONG mode; bool promptOpen; } kCases[] = {
			{ "AdjustTokenPrivileges（block_all，通道打不开）",      ModeBlockAll,     false },
			{ "AdjustTokenPrivileges（block_all_safe，通道打不开）", ModeBlockAllSafe, false },
			{ "AdjustTokenPrivileges（block_all，通道正常）",        ModeBlockAll,     true  },
			{ "AdjustTokenPrivileges（block_all_safe，通道正常）",   ModeBlockAllSafe, true  },
		};
		for (const Case& c : kCases) {
			GuardStub::ResetPolicy();
			GuardStub::SetHighRisk(true);
			GuardStub::SetMode(c.mode);
			GuardStub::SetPromptOpen(c.promptOpen);
			GuardStub::ClearEvent();

			const TokenTheftGuardTest::EvalOutcome out =
				TokenTheftGuardTest::EvaluateAdjustTokenPrivileges(c.mode, /*forceHighRisk=*/true);

			const bool decisionOk = (out.Decision == R3ShieldCore::Decision::Blocked);
			const bool actionOk = (out.Action == ActionBlock);
			const bool tierOk = ((out.Flags2 & R3ShieldCore::FlagEvent2TokenPrivEscalation) != 0);
			const bool noAskFlagOk = ((out.Flags2 & R3ShieldCore::FlagEvent2AskUnavailable) == 0);
			const bool highRiskFlagOk = ((out.Flags & R3ShieldCore::FlagEventHighRisk) != 0);
			const bool blockedFlagOk = ((out.Flags & R3ShieldCore::FlagEventBlocked) != 0);
			const bool noAskOk = (GuardStub::AskAttemptCount() == 0);

			const bool ok = decisionOk && actionOk && tierOk && noAskFlagOk
				&& highRiskFlagOk && blockedFlagOk && noAskOk;
			if (ok) { g_pass++; } else { g_fail++; }

			printf("%s [v66] %-46s mode=%-15s prompt=%-4s decision=%-8s action=%-6s "
				"flags=0x%X flags2=0x%X(%s) askAttempts=%u\n",
				ok ? "  ok  " : "  FAIL", c.note, ModeName(c.mode),
				c.promptOpen ? "open" : "SHUT",
				R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
				ActionName(out.Action), out.Flags, out.Flags2, TierFlagName(out.Flags2),
				GuardStub::AskAttemptCount());
			if (!ok) {
				printf("         子判据: decision=%d action=%d tier3=%d 无AskUnavailable=%d "
					"HighRisk标=%d Blocked标=%d 未碰询问通道=%d\n",
					decisionOk, actionOk, tierOk, noAskFlagOk,
					highRiskFlagOk, blockedFlagOk, noAskOk);
			}
		}
	}

	// ===============================================================
	// 2. ★★ v66：block_all + DuplicateTokenEx（二档，allowAsk=true）→ **直接拒**
	//
	//    这条专门防"只改了 AdjustTokenPrivileges 一条路"的漏改：
	//    二档的 `allowAsk` 传的是 **true**，是**最容易漏**的一条
	//    （v29 之前它走的就是"高危 ASK 分支"）。
	// ===============================================================
	printf("\n=== 2. ★★ v66：block_all + DuplicateTokenEx（二档，allowAsk=true）→ 直接拒 ===\n");
	{
		const struct Case { const char* note; ULONG mode; bool promptOpen; } kCases[] = {
			{ "DuplicateTokenEx（block_all，通道打不开）",      ModeBlockAll,     false },
			{ "DuplicateTokenEx（block_all，通道正常）",        ModeBlockAll,     true  },
			{ "DuplicateTokenEx（block_all_safe，通道正常）",   ModeBlockAllSafe, true  },
		};
		for (const Case& c : kCases) {
			GuardStub::ResetPolicy();
			GuardStub::SetHighRisk(true);
			GuardStub::SetMode(c.mode);
			GuardStub::SetPromptOpen(c.promptOpen);
			GuardStub::ClearEvent();

			const TokenTheftGuardTest::EvalOutcome out =
				TokenTheftGuardTest::EvaluateDuplicateTokenEx(c.mode, /*forceHighRisk=*/false);

			const bool decisionOk = (out.Decision == R3ShieldCore::Decision::Blocked);
			const bool actionOk = (out.Action == ActionBlock);
			const bool tierOk = ((out.Flags2 & R3ShieldCore::FlagEvent2TokenUsed) != 0);
			const bool noAskFlagOk = ((out.Flags2 & R3ShieldCore::FlagEvent2AskUnavailable) == 0);
			const bool noAskOk = (GuardStub::AskAttemptCount() == 0);

			const bool ok = decisionOk && actionOk && tierOk && noAskFlagOk && noAskOk;
			if (ok) { g_pass++; } else { g_fail++; }

			printf("%s [v66] %-46s mode=%-15s prompt=%-4s decision=%-8s action=%-6s "
				"flags2=0x%X(%s) askAttempts=%u\n",
				ok ? "  ok  " : "  FAIL", c.note, ModeName(c.mode),
				c.promptOpen ? "open" : "SHUT",
				R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
				ActionName(out.Action), out.Flags2, TierFlagName(out.Flags2),
				GuardStub::AskAttemptCount());
			if (!ok) {
				printf("         子判据: decision=%d action=%d tier2=%d 无AskUnavailable=%d "
					"未碰询问通道=%d\n",
					decisionOk, actionOk, tierOk, noAskFlagOk, noAskOk);
			}
		}
	}

	// ===============================================================
	// 3. ★★ 安全边界不降：BLOCK 模式 + 通道不可用 → **照样拒**（v66 不得越界）
	//
	//    BLOCK 是用户明确表达的"要拦"，通道坏了也不该放行。
	//    v26/v28/v29 的"降级放行"**只作用于 LOG**，这条不能被 v66 带坏。
	// ===============================================================
	printf("\n=== 3. ★★ 安全边界不降：BLOCK + 通道不可用 → 仍拒 ===\n");
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(ModeBlock);
		GuardStub::SetPromptOpen(false);
		GuardStub::ClearEvent();

		const TokenTheftGuardTest::EvalOutcome out =
			TokenTheftGuardTest::EvaluateAdjustTokenPrivileges(ModeBlock, /*forceHighRisk=*/true);

		const bool decisionOk = (out.Decision == R3ShieldCore::Decision::Blocked);
		const bool actionOk = (out.Action == ActionBlock);
		const bool ok = decisionOk && actionOk;
		if (ok) { g_pass++; } else { g_fail++; }

		printf("%s [bound] %-43s mode=%-15s decision=%-8s action=%-6s flags=0x%X\n",
			ok ? "  ok  " : "  FAIL", "AdjustTokenPrivileges（BLOCK，通道打不开）",
			ModeName(ModeBlock),
			R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
			ActionName(out.Action), out.Flags);
	}

	// ===============================================================
	// 4. ★ LOG 模式 + 通道不可用 → 只记录（不拦，保 UAC）
	//
	//    LOG 下 `canAsk = allowAsk && mode==Ask` 为 **false**
	//    （mode 是 LOG 不是 ASK）⇒ 走 `!canAsk` 分支 → 直接 `WouldBlock`，
	//    **根本不调 Ask()**。所以这里天然没有"静默拒"风险。
	//    flags2 只带 tier 标记（AdjustTokenPrivileges = 三档 0x400），
	//    **不含** AskUnavailable（0x40000）—— 因为压根没尝试问。
	//    ★ 这条断言的意义：证明 LOG 下 AdjustTokenPrivileges 不会被拦。
	// ===============================================================
	printf("\n=== 4. ★ LOG + 通道不可用 → 只记录（不拦，保 UAC）===\n");
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(ModeLog);
		GuardStub::SetPromptOpen(false);
		GuardStub::ClearEvent();

		const TokenTheftGuardTest::EvalOutcome out =
			TokenTheftGuardTest::EvaluateAdjustTokenPrivileges(ModeLog, /*forceHighRisk=*/true);

		const bool decisionOk = (out.Decision == R3ShieldCore::Decision::WouldBlock);
		const bool actionOk = (out.Action == ActionRecord);
		const bool tierOk = ((out.Flags2 & R3ShieldCore::FlagEvent2TokenPrivEscalation) != 0);
		const bool noAskOk = (GuardStub::AskAttemptCount() == 0);
		const bool ok = decisionOk && actionOk && tierOk && noAskOk;
		if (ok) { g_pass++; } else { g_fail++; }

		printf("%s [log] %-45s mode=%-15s decision=%-11s action=%-6s flags2=0x%X askAttempts=%u\n",
			ok ? "  ok  " : "  FAIL", "AdjustTokenPrivileges（LOG，通道打不开）",
			ModeName(ModeLog),
			R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
			ActionName(out.Action), out.Flags2, GuardStub::AskAttemptCount());
	}

	// ===============================================================
	// 5. LOG + 通道正常 → 同样只记录（LOG 语义不受通道影响）
	// ===============================================================
	printf("\n=== 5. LOG + 通道正常 → 仍只记录（LOG 语义不受影响）===\n");
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(ModeLog);
		GuardStub::SetPromptOpen(true);
		GuardStub::ClearEvent();

		const TokenTheftGuardTest::EvalOutcome out =
			TokenTheftGuardTest::EvaluateAdjustTokenPrivileges(ModeLog, /*forceHighRisk=*/true);

		const bool decisionOk = (out.Decision == R3ShieldCore::Decision::WouldBlock);
		const bool actionOk = (out.Action == ActionRecord);
		const bool ok = decisionOk && actionOk;
		if (ok) { g_pass++; } else { g_fail++; }

		printf("%s [log] %-45s mode=%-15s decision=%-11s action=%-6s flags2=0x%X\n",
			ok ? "  ok  " : "  FAIL", "AdjustTokenPrivileges（LOG，通道正常）",
			ModeName(ModeLog),
			R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
			ActionName(out.Action), out.Flags2);
	}

	// ===============================================================
	// 6. ★ 一档非高危（OpenProcessToken）→ Pass（不进通道、不产生事件）
	//
	//    ⚠️ 注意：`AdjustTokenPrivileges` 是 **tier=3**，而
	//    `const bool highRisk = forceHighRisk || (tier >= 2);` —— tier 3 ≥ 2
	//    ⇒ **恒高危**，`forceHighRisk=false` 也挡不住它。
	//    所以"非高危"这条路只能用 **tier=1** 的 `OpenProcessToken` 来测。
	//    ★ v66 不得把这一档也改成拒 —— 它满天飞（进程管理器/调试器都调），
	//      改成拒等于把整个系统拖慢/拖坏。
	// ===============================================================
	printf("\n=== 6. ★ 一档非高危：OpenProcessToken → Pass（v66 不得波及）===\n");
	{
		const ULONG kModes[] = { ModeLog, ModeBlock, ModeAsk, ModeBlockAll, ModeBlockAllSafe };
		for (ULONG m : kModes) {
			GuardStub::ResetPolicy();
			GuardStub::SetHighRisk(true);
			GuardStub::SetMode(m);
			GuardStub::SetPromptOpen(true);
			GuardStub::ClearEvent();

			const TokenTheftGuardTest::EvalOutcome out =
				TokenTheftGuardTest::EvaluateOpenProcessToken(m);

			const bool actionOk = (out.Action == ActionPass);
			const bool notBlockedOk = !out.Blocked;
			const bool noAskOk = (GuardStub::AskAttemptCount() == 0);
			const bool ok = actionOk && notBlockedOk && noAskOk;
			if (ok) { g_pass++; } else { g_fail++; }

			printf("%s [norisk] %-34s mode=%-15s action=%-6s blocked=%-4s askAttempts=%u\n",
				ok ? "  ok  " : "  FAIL", "OpenProcessToken（一档，非高危）",
				ModeName(m), ActionName(out.Action), out.Blocked ? "yes" : "no",
				GuardStub::AskAttemptCount());
		}
	}

	// ===============================================================
	// 7. ★★ v66 全覆盖：**全部 7 个 op** × 两种 allowAsk × 两种 forceHighRisk
	//        × 两种全拦模式 → 逐个断言"该拒的必须拒、且一次都没碰询问通道"
	//
	//    为什么必须遍历（而不是手写几个）：
	//      `token_theft_guard.cpp` 的 hook 有 5 个出口，规则表里 tier≥2 的 op
	//      有 5 个。只测手写的那两个 ⇒ `ImpersonateLoggedOnUser` /
	//      `CreateProcessWithToken` / `SetThreadToken` **漏测**，
	//      而它们和已测的那些走同一个 block_all 分支
	//      ⇒ 分支改了却不知道（铁律 99「诊断口径必须 ≥ 触发口径」）。
	//
	//    ★ 期望值**从规则层推导**（不手抄 tier 表）：
	//      与 `token_theft_guard.cpp` 调的是**同一个** `TokenTheftRiskReason`。
	//      推导规则逐字对应 `Evaluate` 的前半段：
	//        · tier==1 且 !forceHighRisk            → Pass（line ~206）
	//        · !highRisk 且 !chainFollowUp          → Pass（line ~212）
	//        · 其余（即 highRisk，或 chainFollowUp）→ 进 block_all 分支 ⇒ 必须拒
	// ===============================================================
	printf("\n=== 7. ★★ v66 全覆盖：全部 op × allowAsk × forceHighRisk × 全拦模式 ===\n");
	{
		const struct OpName { ULONG op; const char* name; } kOps[] = {
			{ 1, "OpenProcessToken" },        { 2, "OpenThreadToken" },
			{ 3, "DuplicateTokenEx" },        { 4, "ImpersonateLoggedOnUser" },
			{ 5, "CreateProcessWithToken" },  { 6, "SetThreadToken" },
			{ 7, "AdjustTokenPrivileges" },
		};
		const ULONG kModes[] = { ModeBlockAll, ModeBlockAllSafe };
		const bool kAllowAsk[] = { true, false };
		const bool kForceHighRisk[] = { false, true };
		const bool kChainFollowUp[] = { false, true };

		int covered = 0;      // 真正走到"必须拒"的用例数（用于交叉恒等式自检）
		int expectPass = 0;   // 按规则层推导应当 Pass 的用例数

		for (const OpName& o : kOps) {
			ULONG tier = 0;
			R3ShieldCoreRules::TokenTheftRiskReason(o.op, &tier);

			for (ULONG m : kModes) {
				for (bool allowAsk : kAllowAsk) {
					for (bool fhr : kForceHighRisk) {
						for (bool followUp : kChainFollowUp) {
							GuardStub::ResetPolicy();
							GuardStub::SetHighRisk(true);
							GuardStub::SetMode(m);
							GuardStub::SetPromptOpen(true);   // 通道**开**着：最不利于"不弹窗"的档
							GuardStub::ClearEvent();

							const TokenTheftGuardTest::EvalOutcome out =
								TokenTheftGuardTest::EvaluateAnyOp(
									o.op, m, allowAsk, fhr, followUp);

							// 按规则层推导期望（与 Evaluate 前半段逐条对应）。
							const bool highRisk = fhr || (tier >= 2);
							const bool derivedPass = (tier == 1 && !fhr)
								|| (!highRisk && !followUp);

							bool ok;
							if (derivedPass) {
								expectPass++;
								ok = (out.Action == ActionPass) && !out.Blocked
									&& (GuardStub::AskAttemptCount() == 0);
							}
							else {
								covered++;
								ok = (out.Decision == R3ShieldCore::Decision::Blocked)
									&& (out.Action == ActionBlock)
									&& ((out.Flags & R3ShieldCore::FlagEventBlocked) != 0)
									&& ((out.Flags2 & R3ShieldCore::FlagEvent2AskUnavailable) == 0)
									&& (GuardStub::AskAttemptCount() == 0);
							}

							if (ok) { g_pass++; } else { g_fail++; }

							printf("%s %-24s tier=%u mode=%-15s allowAsk=%-5s forceHighRisk=%-5s "
								"chain=%-5s => %-11s %-6s flags2=0x%X(%s) ask=%u %s\n",
								ok ? "  ok  " : "  FAIL", o.name, tier, ModeName(m),
								allowAsk ? "true" : "false", fhr ? "true" : "false",
								followUp ? "true" : "false",
								R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
								ActionName(out.Action), out.Flags2, TierFlagName(out.Flags2),
								GuardStub::AskAttemptCount(),
								derivedPass ? "[期望 Pass]" : "[期望 拒]");
						}
					}
				}
			}
		}

		// ---- 交叉恒等式自检（铁律 148）----
		// 全量用例数必须等于 7 op × 2 mode × 2 allowAsk × 2 fhr × 2 chain。
		const int total = 7 * 2 * 2 * 2 * 2;
		const int actual = covered + expectPass;
		const bool identOk = (actual == total);
		if (!identOk) { g_fail++; } else { g_pass++; }
		printf("%s [自检] 用例数恒等式: covered(%d) + expectPass(%d) == %d ? %s\n",
			identOk ? "  ok  " : "  FAIL", covered, expectPass, total,
			identOk ? "是" : "否");

		// ★ 负对照：expectPass 必须 > 0，否则说明"推导"这一路根本没被走到，
		//   恒等式就是空真（铁律 110）。
		const bool passBranchOk = (expectPass > 0);
		const bool blockBranchOk = (covered > 0);
		if (!passBranchOk || !blockBranchOk) { g_fail++; } else { g_pass++; }
		printf("%s [自检] 两条分支都非空: Pass 分支=%d(>0? %s) 拒分支=%d(>0? %s)\n",
			(passBranchOk && blockBranchOk) ? "  ok  " : "  FAIL",
			expectPass, passBranchOk ? "是" : "否",
			covered, blockBranchOk ? "是" : "否");
	}

	// ===============================================================
	// 8. ★★ 负对照：ASK 模式下询问通道**必须真的被碰过**
	//
	//    这一节是给第 1/2/7 节的 `AskAttemptCount() == 0` 做**负对照**的。
	//    没有它的话，`AskAttemptCount()` 恒为 0（比如计数写错位置、
	//    或 `AskWithChannelGuard` 根本没被链接进来）也会让上面全绿
	//    —— 那就是铁律 128「闸门负对照走真判据」说的假绿。
	//
	//    ASK 模式 + DuplicateTokenEx（allowAsk=true）+ 通道正常：
	//      canAsk = true ⇒ 走 AskWithChannelGuard ⇒ 计数必须 > 0
	//      桩的 Ask 在通道开时返回 Deny（模拟"用户拒绝"）⇒ 必须 Block
	// ===============================================================
	printf("\n=== 8. ★★ 负对照：ASK + 通道正常 → 询问通道必须真被碰过 ===\n");
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(ModeAsk);
		GuardStub::SetPromptOpen(true);
		GuardStub::ClearEvent();

		const TokenTheftGuardTest::EvalOutcome out =
			TokenTheftGuardTest::EvaluateDuplicateTokenEx(ModeAsk, /*forceHighRisk=*/false);

		const bool askedOk = (GuardStub::AskAttemptCount() > 0);
		const bool blockedOk = (out.Decision == R3ShieldCore::Decision::Blocked)
			&& (out.Action == ActionBlock);
		const bool ok = askedOk && blockedOk;
		if (ok) { g_pass++; } else { g_fail++; }

		printf("%s [neg] %-46s mode=%-15s askAttempts=%u(>0? %s) decision=%-8s action=%-6s\n",
			ok ? "  ok  " : "  FAIL", "DuplicateTokenEx（ASK，通道正常，用户拒绝）",
			ModeName(ModeAsk), GuardStub::AskAttemptCount(),
			askedOk ? "是" : "否",
			R3ShieldCore::DecisionName(static_cast<ULONG>(out.Decision)),
			ActionName(out.Action));
		if (!askedOk) {
			printf("         [!] 询问通道一次都没被碰 -> 上面所有 "
				"`askAttempts == 0` 的断言都是**空真**，不能作为 v66 的证据\n");
		}
	}

	printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
