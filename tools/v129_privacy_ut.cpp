//
// v129_privacy_ut.cpp —— 「block 模式下隐私面不拦」的行为单测。
//
// ★ 为什么必须有这个（而不是只查代码里有没有 IsPrivacyFace 分支）：
//   v129 的改动点是"block 模式下**要不要走到** RejectOrSpoof"。
//   只 grep 分支存在 ⇒ 分不清"条件写反"和"条件正确"（铁律：验行为不验字面）。
//   这里直接调 guard 的 Evaluate，断言返回的 Action 与写进事件的 Decision。
//
// ★ 四条用例里有**三条是负对照**，这是刻意的：
//   ① block + 读剪贴板      → Record + WouldBlock（**新行为**）
//   ② block_all + 读剪贴板  → Block  + Blocked   （全拦模式不受影响）
//   ③ log + 读剪贴板        → Record + WouldBlock（旧行为不变）
//   ④ block + 写 Run 键     → Block  + Blocked   （**破坏类照拦**）
//
//   ④ 是关键：如果有人把 v129 实现成"block 干脆什么都不拦"，
//   ①②③ 会**全部继续通过**，只有 ④ 变红。它证明这次改动是**分流**，不是**放水**。
//   同理 ② 挡住"顺手把 block_all 也改了"。
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "r3shieldcore_rules.h"

// guard_stub.cpp 提供的控制器（Policy 由桩持有，与生产路径同源）。
namespace GuardStub
{
	void ResetPolicy() noexcept;
	void SetMode(ULONG mode) noexcept;
	void SetHighRisk(bool on) noexcept;
	R3ShieldCore::Policy* PolicyPtr() noexcept;
}

// clipboard_guard.cpp 尾部的单测入口（宏 CLIPGUARD_GUARD_UT 打开）。
namespace ClipboardGuardTest
{
	void SetCloseHookReady(bool ready) noexcept;
	int EvaluateForTest(ULONG op, UINT format, bool allowAsk,
		int* decisionOut, int* flagsOut) noexcept;
}

// registry_guard.cpp 尾部的单测入口（宏 REGUARD_GUARD_UT 打开）。
namespace RegistryGuardTest
{
	R3ShieldCore::Event EvaluateKey(PCWSTR keyPath, PCWSTR valueName, ULONG op,
		ULONG mode, bool blockable) noexcept;
}

// screen_guard.cpp / input_hook_guard.cpp 尾部的单测入口（v129 新增）。
namespace ScreenGuardTest
{
	int EvaluateForTest(ULONG op, bool allowAsk, int* decisionOut, ULONG* flagsOut) noexcept;
}

namespace InputHookGuardTest
{
	int EvaluateForTest(ULONG op, int idHook, ULONG threadId, bool rawSink,
		bool allowAsk, int* decisionOut, ULONG* flagsOut) noexcept;
}

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

static const char* ActionName(int action)
{
	switch (action)
	{
	case 0: return "Pass";
	case 1: return "Record";
	case 2: return "Block";
	case 3: return "Spoof";
	default: return "?";
	}
}

int main()
{
	setlocale(LC_ALL, "");

	printf("=== v129：block 模式下隐私面不拦 / 破坏类照拦 ===\n");

	const ULONG kLog      = static_cast<ULONG>(R3ShieldCore::Mode::Log);
	const ULONG kBlock    = static_cast<ULONG>(R3ShieldCore::Mode::Block);
	const ULONG kBlockAll = static_cast<ULONG>(R3ShieldCore::Mode::BlockAll);

	const int   kActionRecord = static_cast<int>(R3ShieldCore::Action::Record);
	const int   kActionBlock  = static_cast<int>(R3ShieldCore::Action::Block);
	const int   kActionSpoof  = static_cast<int>(R3ShieldCore::Action::Spoof);
	const ULONG kWouldBlock   = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
	const ULONG kBlocked      = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
	const ULONG kClipRead     = static_cast<ULONG>(R3ShieldCore::ClipboardOp::Read);

	GuardStub::ResetPolicy();
	// 高危规则必须打开：否则 highRisk=false，走的是"非高危"分支，
	// 根本到不了这次要验的 block 分支（会得到假绿）。
	GuardStub::SetHighRisk(true);
	// 剪贴板"替换"默认关。单测**不能**打开它 ——
	// 否则 RejectOrSpoof 返回 Spoof，"隐私面不拦"会被"替换"掩盖。
	ClipboardGuardTest::SetCloseHookReady(false);

	// ---- ① block + 读剪贴板：不拦，但要标 WouldBlock ----
	{
		GuardStub::SetMode(kBlock);
		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT, /*allowAsk=*/false,
			&decision, &flags);
		printf("  ① block + 读剪贴板 → %s (decision=%d)\n", ActionName(action), decision);
		Check("① block 下读剪贴板不拦（Action=Record）", action == kActionRecord);
		Check("① block 下读剪贴板仍标 WouldBlock（日志能看见）",
			decision == static_cast<int>(kWouldBlock));
	}

	// ---- ② 负对照：block_all 必须照拦（v129 只改 block）----
	{
		GuardStub::SetMode(kBlockAll);
		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT, /*allowAsk=*/false,
			&decision, &flags);
		printf("  ② block_all + 读剪贴板 → %s (decision=%d)\n", ActionName(action), decision);
		Check("② block_all 下读剪贴板仍然拦（全拦模式不受影响）",
			action == kActionBlock && decision == static_cast<int>(kBlocked));
	}

	// ---- ③ 负对照：log 行为不变 ----
	{
		GuardStub::SetMode(kLog);
		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT, /*allowAsk=*/false,
			&decision, &flags);
		printf("  ③ log + 读剪贴板 → %s (decision=%d)\n", ActionName(action), decision);
		Check("③ log 下读剪贴板仍只记录（旧行为没变）",
			action == kActionRecord && decision == static_cast<int>(kWouldBlock));
	}

	// ---- ④ 负对照：破坏类在 block 下照拦（证明是分流不是放水）----
	//
	// ⚠️ 必须 `GuardStub::SetMode()` —— `EvaluateKey()` 的 `mode` 形参是**死参数**
	//    （`Evaluate` 实际读 `Policy->Mode`，见 registry_guard.cpp:1196）。
	//    第一版只把 kBlock 传给形参，结果 ④ 实际跑在 ③ 留下的 log 模式下，
	//    得到 WouldBlock 而不是 Blocked —— 是这条负对照自己抓出来的。
	{
		GuardStub::SetMode(kBlock);
		const R3ShieldCore::Event ev = RegistryGuardTest::EvaluateKey(
			L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			L"R3ShieldCoreUtProbe",
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
			kBlock, /*blockable=*/true);
		printf("  ④ block + 写 Run 键 → decision=%u\n", ev.Decision);
		Check("④ block 下写 Run 仍然拦（破坏类照拦）", ev.Decision == kBlocked);
	}

	// ---- ⑤ block + 截屏：不拦（截图/录屏/会议共享都会走这里）----
	{
		GuardStub::SetMode(kBlock);
		int decision = -1;
		ULONG flags = 0;
		const int action = ScreenGuardTest::EvaluateForTest(
			static_cast<ULONG>(R3ShieldCore::ScreenOp::BitBlt), /*allowAsk=*/false, &decision, &flags);
		printf("  ⑤ block + BitBlt 截屏 → %s (decision=%d)\n", ActionName(action), decision);
		Check("⑤ block 下截屏不拦（Action=Record）", action == kActionRecord);
	}

	// ---- ⑥ block + 全局键盘钩子：不拦（输入法/游戏/远控都要装）----
	{
		GuardStub::SetMode(kBlock);
		int decision = -1;
		ULONG flags = 0;
		const int action = InputHookGuardTest::EvaluateForTest(
			static_cast<ULONG>(R3ShieldCore::HookOp::SetKeyboardHook),
			WH_KEYBOARD_LL, /*threadId=*/0, /*rawSink=*/false, /*allowAsk=*/false, &decision, &flags);
		printf("  ⑥ block + 全局键盘钩子 → %s (decision=%d)\n", ActionName(action), decision);
		Check("⑥ block 下全局键盘钩子不拦（Action=Record）", action == kActionRecord);
	}

	// ---- ⑦ block + 开了 spoof_clipboard → 走替换，不是"只记录" ----
	//
	// ★ 这条是 v131 补的：v129 第一版在隐私分支里**直接 return Record**，
	//   把 `RejectOrSpoof` 整段挡住了 ⇒ 用户开了 `spoof_clipboard=1` 也不生效
	//   （替换路径成了死代码）。这条用例专门钉"替换没被挡"。
	//
	//   语义差别：Record = 真实内容照常返回（只是记了一笔）；
	//            Spoof  = 调用成功、但内容是假的 —— 这才叫"不影响使用又保护数据"。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(kBlock);
		// 替换的前置条件：CloseClipboard 挂上了（否则替换块无人回收，开关会自锁）。
		ClipboardGuardTest::SetCloseHookReady(true);
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofClipboard;

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT, /*allowAsk=*/false,
			&decision, &flags);
		printf("  ⑦ block + spoof_clipboard=1 + 读剪贴板 → %s\n", ActionName(action));
		Check("⑦ block 下开了替换就走 Spoof（v129 曾把这条路径挡住）", action == kActionSpoof);
	}

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
