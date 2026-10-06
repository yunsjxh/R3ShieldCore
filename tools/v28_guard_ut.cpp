//
// v28_guard_ut.cpp —— R3ShieldCore v28「LOG 模式 + 高危不可问 → 降级放行」单测。
//
// ★ 本版本修的是什么（用户实报，2026-09-30）：
//
//   `mode=log` + `high_risk=1` 时，高危注册表写**照样进 `Ask()` 分支**
//   （`registry_guard.cpp` 的 `if (mode == Mode::Ask || highRisk)`），
//   而 `Ask()` 在询问通道拿不到时**立刻返回 fallback**（`prompt_default=deny`）
//   → 调用方把 deny 当"用户拒绝" → `Action::Block`
//   → 用户看到「Windows 无法访问指定设备、路径或文件」(0xC0000022)
//   **且界面上没有任何弹窗**。
//
//   触发条件：引擎**以管理员启动** → 跨完整性 / UIPI / 会话边界
//   → 被注入进程打不开询问通道 → `IsOpen() == false`。
//   用户原话：「用管理员就会炸」。
//
//   v26 只修了 `block_all` 分支，**漏了这条常规分支**；v28 补齐。
//
// ★ 为什么这个单测和别的不同（测的是 **guard 层**，不是规则层）：
//   `build_ut.sh` 只链 `r3shieldcore_rules.cpp`，那条路**测不到** v28 的修复点。
//   本文件改为直接编译 `registry_guard.cpp` + `guard_stub.cpp`
//   （桩见 `tools/guard_stub.cpp`），编译时定义 `REGUARD_GUARD_UT`
//   打开文件尾部那个单测入口。构建脚本见 `build_guard_ut.sh`。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <r3shieldcore/r3shieldcore_shared.h>

// registry_guard.cpp 尾部的单测入口（宏 REGUARD_GUARD_UT 打开）。
namespace RegistryGuardTest
{
	R3ShieldCore::Event EvaluateKey(PCWSTR keyPath, PCWSTR valueName, ULONG op,
		ULONG mode, bool blockable) noexcept;
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
}

// 与 r3shieldcore_shared.h 的 R3ShieldCore::Op 真实取值对齐。
enum ProbeOp
{
	OpCreateKey = 1,
	OpOpenKey = 2,
	OpSetValueKey = 3,
};

// 与 R3ShieldCore::Mode 对齐。
enum ProbeMode
{
	ModeLog = 0,
	ModeBlock = 1,
	ModeAsk = 2,
	ModeBlockAll = 3,
	ModeBlockAllSafe = 4,
};

static int g_pass = 0;
static int g_fail = 0;

// 断言：跑一次 EvaluateKey，检查 Decision。
static void CheckDecision(const char* group, const char* note,
	PCWSTR keyPath, ULONG op, ULONG mode, bool promptOpen,
	R3ShieldCore::Decision expectDecision, ULONG expectFlags2)
{
	GuardStub::ResetPolicy();
	GuardStub::SetHighRisk(true);
	GuardStub::SetMode(mode);
	GuardStub::SetPromptOpen(promptOpen);
	GuardStub::ClearEvent();

	const R3ShieldCore::Event ev = RegistryGuardTest::EvaluateKey(keyPath, L"SomeValue", op,
		mode, true);

	const bool decisionOk = (ev.Decision == static_cast<ULONG>(expectDecision));
	const bool flagsOk = (expectFlags2 == 0)
		|| ((ev.Flags2 & expectFlags2) == expectFlags2);

	const bool ok = decisionOk && flagsOk;
	if (ok) { g_pass++; } else { g_fail++; }

	const char* got = R3ShieldCore::DecisionName(ev.Decision);

	printf("%s  [%s] %-46s mode=%-10s prompt=%-5s expect=%-11s got=%-11s flags2=0x%X\n",
		ok ? "  ok  " : "  FAIL", group, note,
		(mode == ModeLog) ? "LOG" : (mode == ModeBlock ? "BLOCK"
			: (mode == ModeAsk ? "ASK" : "BLOCK_ALL")),
		promptOpen ? "open" : "SHUT",
		R3ShieldCore::DecisionName(static_cast<ULONG>(expectDecision)), got,
		ev.Flags2);
}

int main()
{
	setlocale(LC_ALL, ".UTF8");

	// 高危键：HKLM Run（命中 kRegistryRules）。
	const PCWSTR kHighRiskKey = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	// 非高危键：第三方自用配置。
	const PCWSTR kNormalKey = L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\MyApp\\Settings";
	// 基础设施键。
	const PCWSTR kInfraKey = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography";

	// ---------------------------------------------------------------
	// 1. ★★★ v28 核心回归：LOG + 高危 + **通道不在** → 必须放行（不静默拒）
	//    这是用户报的那个 bug 的直接复现点。
	// ---------------------------------------------------------------
	printf("=== 1. ★★★ v28 核心：LOG + 高危 + 通道不可用 → 降级放行 ===\n");
	CheckDecision("v28", "HKLM Run（LOG，通道打不开）",
		kHighRiskKey, OpSetValueKey, ModeLog, /*promptOpen=*/false,
		R3ShieldCore::Decision::WouldBlock, 0);
	CheckDecision("v28", "IFEO 劫持点（LOG，通道打不开）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\x.exe",
		OpCreateKey, ModeLog, false,
		R3ShieldCore::Decision::WouldBlock, 0);
	CheckDecision("v28", "服务 ImagePath（LOG，通道打不开）",
		L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Evil\\ImagePath",
		OpSetValueKey, ModeLog, false,
		R3ShieldCore::Decision::WouldBlock, 0);

	// ---------------------------------------------------------------
	// 2. LOG + 高危 → 只记录，不依赖询问通道。
	//    BLOCK 的主动防御语义必须是确定性的：LOG 不会因为通道存在
	//    就意外弹窗或拦截，管理员启动造成的完整性隔离也不会改变结果。
	// ---------------------------------------------------------------
	printf("\n=== 2. LOG + 高危 → 只记录，不弹窗 ===\n");
	CheckDecision("log", "HKLM Run（LOG，通道正常）",
		kHighRiskKey, OpSetValueKey, ModeLog, /*promptOpen=*/true,
		R3ShieldCore::Decision::WouldBlock, 0);

	// ---------------------------------------------------------------
	// 3. ★★ 安全边界不降：BLOCK / ASK 模式 + 通道不可用 → **照样拒**
	//
	//    BLOCK/ASK 是用户明确表达的"要拦 / 要问"，通道坏了也不该放行。
	//    v28 的降级**只作用于 LOG**，这两条断言就是防它越界的护栏。
	// ---------------------------------------------------------------
	printf("\n=== 3. ★★ 安全边界不降：BLOCK/ASK + 通道不可用 → 仍拒（v28 不得越界）===\n");
	CheckDecision("bound", "HKLM Run（BLOCK，通道打不开）",
		kHighRiskKey, OpSetValueKey, ModeBlock, false,
		R3ShieldCore::Decision::Blocked, 0);
	CheckDecision("bound", "HKLM Run（ASK，通道打不开）",
		kHighRiskKey, OpSetValueKey, ModeAsk, false,
		R3ShieldCore::Decision::Blocked, 0);

	// ---------------------------------------------------------------
	// 4. BLOCK 的日常可用性：普通应用配置写入放行，高危持久化仍拒绝。
	// ---------------------------------------------------------------
	printf("\n=== 4. BLOCK：普通配置放行，高危持久化拒绝 ===\n");
	CheckDecision("block", "第三方自用配置（BLOCK）",
		kNormalKey, OpSetValueKey, ModeBlock, false,
		R3ShieldCore::Decision::Allowed, 0);
	CheckDecision("block", "HKLM Run（BLOCK）",
		kHighRiskKey, OpSetValueKey, ModeBlock, false,
		R3ShieldCore::Decision::Blocked, 0);

	// ---------------------------------------------------------------
	// 5. LOG + **非高危** → WouldBlock 记录（这条 v28 前后一致，防回归）
	// ---------------------------------------------------------------
	printf("\n=== 5. LOG + 非高危 → 只记录（v28 不得改变这条）===\n");
	CheckDecision("log", "第三方自用配置（LOG，非高危）",
		kNormalKey, OpSetValueKey, ModeLog, false,
		R3ShieldCore::Decision::WouldBlock, 0);
	CheckDecision("log", "第三方自用配置（LOG，通道正常）",
		kNormalKey, OpSetValueKey, ModeLog, true,
		R3ShieldCore::Decision::WouldBlock, 0);

	// ---------------------------------------------------------------
	// 6. 非高危的普通键：LOG 下走到函数末尾的 `WouldBlock` + Record。
	//
	//    ⚠️ 注意：`IsSystemInfrastructureKey` 的豁免**只在 Ask 分支内**生效
	//    （`if (!highRisk && IsSystemInfrastructureKey(...))`）——
	//    它防的是"给基础设施键弹窗机枪"，不是"日志模式放行"。
	//    所以 `Cryptography` 这种"基础设施但非高危"的键，在 LOG 下
	//    结论仍是 `WouldBlock`（记录、不拦），与普通键**同一条路**。
	//    ★ 这正是"looks 拦但实际只记录"的正确形态 —— 关键是没有 `Blocked`。
	// ---------------------------------------------------------------
	printf("\n=== 6. 非高危键（含基础设施）：LOG 下只记录，不得 Blocked ===\n");
	CheckDecision("infra", "Cryptography（LOG，通道打不开）",
		kInfraKey, OpSetValueKey, ModeLog, false,
		R3ShieldCore::Decision::WouldBlock, 0);
	CheckDecision("infra", "Cryptography（LOG，通道正常）",
		kInfraKey, OpSetValueKey, ModeLog, true,
		R3ShieldCore::Decision::WouldBlock, 0);

	// ---------------------------------------------------------------
	// 7. ★ block_all 的既有行为（v26）**不得被 v28 破坏**
	// ---------------------------------------------------------------
	printf("\n=== 6. 回归：block_all 分支（v26 行为）不受影响 ===\n");
	CheckDecision("blkall", "高危键（block_all，高危直拒不问）",
		kHighRiskKey, OpSetValueKey, ModeBlockAll, false,
		R3ShieldCore::Decision::Blocked, 0);

	printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
