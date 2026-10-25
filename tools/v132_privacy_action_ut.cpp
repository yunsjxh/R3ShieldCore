//
// v132_privacy_action_ut.cpp —— 「隐私面处置可配置」的位布局 + 行为单测。
//
// 背景：v129 把"隐私面只记录"**硬编码**进四个 guard，没有中间档。
// v132 改成逐面可配（ini: privacy_camera / privacy_input_hook /
// privacy_screen / privacy_clipboard = record | ask | block）。
//
// ★ 这个单测分两段，两段缺一不可：
//
//   第一段：**位布局**（纯函数，不碰 guard）
//     位移写错一位、两个面共用一段位、或者"设 A 把 B 也改了" ——
//     这类错**不会让任何行为用例变红**（因为行为用例通常只查一个面），
//     但用户会在界面上看到"我改了截屏，结果剪贴板也变了"。
//     所以必须把位移**写死断言**（bit12/14/16/18），防的是未来有人
//     "顺手重排一下位"。
//
//   第二段：**行为**（走完整 Evaluate）
//     断言的是"这一档到底做了什么"，不是"代码里有这个分支"。
//
// ★ 负对照清单（只有第一条是"该发生"，其余全是"不该发生"）：
//     ① 默认（Flags2=0）            → 四面全 Record（v129 行为不变）
//     ② clipboard=Block             → 真的 Block
//     ③ clipboard=Ask + 能问        → 走到询问（AskAttempt > 0）
//     ④ clipboard=Ask + 问不了      → 回落 Record（不打断）
//     ⑤ screen=Block                → 真的 Block
//     ⑥ input_hook=Block            → 真的 Block
//     ⑦ block_all + clipboard=Record→ 仍然 Block（全拦不看这一层）
//     ⑧ camera=Block 不影响 clipboard（位不串）
//     ⑨ 未定义值 3                  → Block（fail-closed，不是静默放行）
//     ⑩ 非隐私面（Registry）        → 恒 Record，且 Set 不改 Flags2
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#include <r3shieldcore/r3shieldcore_shared.h>

// guard_stub.cpp 提供的控制器（Policy 由桩持有，与生产路径同源）。
namespace GuardStub
{
	void ResetPolicy() noexcept;
	void SetMode(ULONG mode) noexcept;
	void SetHighRisk(bool on) noexcept;
	void SetPromptOpen(bool open) noexcept;
	void SetPrivacyAction(R3ShieldCore::ObjectType face, R3ShieldCore::PrivacyAction action) noexcept;
	R3ShieldCore::PrivacyAction GetPrivacyAction(R3ShieldCore::ObjectType face) noexcept;
	void SetFlags2(ULONG flags2) noexcept;
	ULONG AskAttemptCount() noexcept;
	void ResetAskAttemptCount() noexcept;
	R3ShieldCore::Policy* PolicyPtr() noexcept;
}

// 三个 guard 尾部的单测入口（宏 *_GUARD_UT 打开）。
namespace ClipboardGuardTest
{
	void SetCloseHookReady(bool ready) noexcept;
	int EvaluateForTest(ULONG op, UINT format, bool allowAsk,
		int* decisionOut, int* flagsOut) noexcept;
}

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

static const char* PrivacyName(R3ShieldCore::PrivacyAction a)
{
	switch (a)
	{
	case R3ShieldCore::PrivacyAction::Record: return "record";
	case R3ShieldCore::PrivacyAction::Ask:    return "ask";
	case R3ShieldCore::PrivacyAction::Block:  return "block";
	default: return "?";
	}
}

// 位布局断言用的常量（**写死**，不从实现里取）。
static const ULONG kShiftCamera    = 12;
static const ULONG kShiftInputHook = 14;
static const ULONG kShiftScreen    = 16;
static const ULONG kShiftClipboard = 18;

int main()
{
	setlocale(LC_ALL, "");

	printf("=== v132：隐私面处置（record / ask / block）可配置 ===\n");

	const ULONG kLog      = static_cast<ULONG>(R3ShieldCore::Mode::Log);
	const ULONG kBlock    = static_cast<ULONG>(R3ShieldCore::Mode::Block);
	const ULONG kBlockAll = static_cast<ULONG>(R3ShieldCore::Mode::BlockAll);

	const int   kActionRecord = static_cast<int>(R3ShieldCore::Action::Record);
	const int   kActionBlock  = static_cast<int>(R3ShieldCore::Action::Block);
	const ULONG kWouldBlock   = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
	const ULONG kBlocked      = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);

	const auto kCamera    = R3ShieldCore::ObjectType::Camera;
	const auto kInputHook = R3ShieldCore::ObjectType::InputHook;
	const auto kScreen    = R3ShieldCore::ObjectType::Screen;
	const auto kClipboard = R3ShieldCore::ObjectType::Clipboard;

	// ================================================================
	// 第一段：位布局（纯函数）
	// ================================================================
	printf("\n-- 位布局 --\n");

	// 0) 位移必须钉死在 12/14/16/18。
	//
	//    ⚠️ 这条看着"废话"，但它是唯一能挡住"重排位"的判据：
	//       重排之后引擎写 ini 的位置和 DLL 读的位置会**一起**变，
	//       行为用例全绿，而已经烧进旧 DLL 的位约定悄悄错位。
	{
		const bool ok = R3ShieldCore::PrivacyActionShift(kCamera) == kShiftCamera
			&& R3ShieldCore::PrivacyActionShift(kInputHook) == kShiftInputHook
			&& R3ShieldCore::PrivacyActionShift(kScreen) == kShiftScreen
			&& R3ShieldCore::PrivacyActionShift(kClipboard) == kShiftClipboard;
		printf("  位移：camera=%u input=%u screen=%u clipboard=%u\n",
			R3ShieldCore::PrivacyActionShift(kCamera),
			R3ShieldCore::PrivacyActionShift(kInputHook),
			R3ShieldCore::PrivacyActionShift(kScreen),
			R3ShieldCore::PrivacyActionShift(kClipboard));
		Check("0) 四个面的位移是 12/14/16/18（钉死，防重排）", ok);
	}

	// ① 默认 Flags2=0 ⇒ 四面全 record。
	{
		const bool ok = R3ShieldCore::PrivacyActionOf(0, kCamera) == R3ShieldCore::PrivacyAction::Record
			&& R3ShieldCore::PrivacyActionOf(0, kInputHook) == R3ShieldCore::PrivacyAction::Record
			&& R3ShieldCore::PrivacyActionOf(0, kScreen) == R3ShieldCore::PrivacyAction::Record
			&& R3ShieldCore::PrivacyActionOf(0, kClipboard) == R3ShieldCore::PrivacyAction::Record;
		Check("① Flags2=0（没配）时四面全是 record", ok);
	}

	// ⑧ 设一个面不改别的面。
	{
		ULONG f2 = 0;
		f2 = R3ShieldCore::SetPrivacyAction(f2, kCamera, R3ShieldCore::PrivacyAction::Block);
		const bool ok = R3ShieldCore::PrivacyActionOf(f2, kCamera) == R3ShieldCore::PrivacyAction::Block
			&& R3ShieldCore::PrivacyActionOf(f2, kInputHook) == R3ShieldCore::PrivacyAction::Record
			&& R3ShieldCore::PrivacyActionOf(f2, kScreen) == R3ShieldCore::PrivacyAction::Record
			&& R3ShieldCore::PrivacyActionOf(f2, kClipboard) == R3ShieldCore::PrivacyAction::Record;
		printf("  只设 camera=block 后 Flags2=0x%08X\n", f2);
		Check("⑧ 设 camera 不影响其它三面（位不串）", ok);
	}

	// 四个面同时设成不同档 —— 交叉验证不是"共用一个字段"。
	{
		ULONG f2 = 0;
		f2 = R3ShieldCore::SetPrivacyAction(f2, kCamera, R3ShieldCore::PrivacyAction::Ask);
		f2 = R3ShieldCore::SetPrivacyAction(f2, kInputHook, R3ShieldCore::PrivacyAction::Block);
		f2 = R3ShieldCore::SetPrivacyAction(f2, kScreen, R3ShieldCore::PrivacyAction::Record);
		f2 = R3ShieldCore::SetPrivacyAction(f2, kClipboard, R3ShieldCore::PrivacyAction::Ask);
		const bool ok = R3ShieldCore::PrivacyActionOf(f2, kCamera) == R3ShieldCore::PrivacyAction::Ask
			&& R3ShieldCore::PrivacyActionOf(f2, kInputHook) == R3ShieldCore::PrivacyAction::Block
			&& R3ShieldCore::PrivacyActionOf(f2, kScreen) == R3ShieldCore::PrivacyAction::Record
			&& R3ShieldCore::PrivacyActionOf(f2, kClipboard) == R3ShieldCore::PrivacyAction::Ask;
		printf("  四面各不同：camera=%s input=%s screen=%s clipboard=%s\n",
			PrivacyName(R3ShieldCore::PrivacyActionOf(f2, kCamera)),
			PrivacyName(R3ShieldCore::PrivacyActionOf(f2, kInputHook)),
			PrivacyName(R3ShieldCore::PrivacyActionOf(f2, kScreen)),
			PrivacyName(R3ShieldCore::PrivacyActionOf(f2, kClipboard)));
		Check("⑧b 四面各设一档，互不影响", ok);
	}

	// 覆盖写（先 block 再 record）不能残留旧值。
	{
		ULONG f2 = 0;
		f2 = R3ShieldCore::SetPrivacyAction(f2, kScreen, R3ShieldCore::PrivacyAction::Block);
		f2 = R3ShieldCore::SetPrivacyAction(f2, kScreen, R3ShieldCore::PrivacyAction::Record);
		Check("⑧c 同一面改两次（block→record）不残留",
			R3ShieldCore::PrivacyActionOf(f2, kScreen) == R3ShieldCore::PrivacyAction::Record);
	}

	// ⑨ 未定义值 3 ⇒ block（fail-closed）。
	//
	//    ⚠️ 为什么是 block 而不是 record：3 只可能来自"写错位"或"未来版本
	//       用了这一档而老 DLL 不认识"。这两种情况下**收紧**是安全的，
	//       放松（当 record）等于"配置写坏了 ⇒ 防护静默失效"。
	{
		const ULONG f2 = R3ShieldCore::SetPrivacyAction(0, kClipboard, static_cast<R3ShieldCore::PrivacyAction>(3));
		Check("⑨ 未定义值 3 按 block 处理（fail-closed）",
			R3ShieldCore::PrivacyActionOf(f2, kClipboard) == R3ShieldCore::PrivacyAction::Block);
	}

	// ⑩ 非隐私面：读恒 record，写不改 Flags2。
	{
		ULONG f2 = 0xFFFFFFFF;
		const ULONG before = f2;
		f2 = R3ShieldCore::SetPrivacyAction(f2, R3ShieldCore::ObjectType::Registry,
			R3ShieldCore::PrivacyAction::Block);
		Check("⑩a 对非隐私面（Registry）SetPrivacyAction 不改 Flags2", f2 == before);
		Check("⑩b 对非隐私面（Registry）读恒 record",
			R3ShieldCore::PrivacyActionOf(0, R3ShieldCore::ObjectType::Registry)
				== R3ShieldCore::PrivacyAction::Record);
	}

	// AnyPrivacyFaceAsks：只在真有面是 ask 时为真。
	{
		ULONG f2 = 0;
		f2 = R3ShieldCore::SetPrivacyAction(f2, kScreen, R3ShieldCore::PrivacyAction::Block);
		const bool noneAsk = !R3ShieldCore::AnyPrivacyFaceAsks(f2);
		f2 = R3ShieldCore::SetPrivacyAction(f2, kCamera, R3ShieldCore::PrivacyAction::Ask);
		const bool hasAsk = R3ShieldCore::AnyPrivacyFaceAsks(f2);
		Check("11) AnyPrivacyFaceAsks：只有 block 时假，有 ask 时真", noneAsk && hasAsk);
	}

	// ================================================================
	// 第二段：行为（走完整 Evaluate）
	// ================================================================
	printf("\n-- 行为（block 模式）--\n");

	const ULONG kClipRead = static_cast<ULONG>(R3ShieldCore::ClipboardOp::Read);

	// ① 默认档：读剪贴板只记录（= v129 行为，回归保护）。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kBlock);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/true, &decision, &flags);
		printf("  clipboard=record + 读剪贴板 → %s (decision=%d)\n", ActionName(action), decision);
		Check("① 默认 record：不拦（Action=Record）", action == kActionRecord);
		Check("① 默认 record：仍标 WouldBlock（日志可见）",
			decision == static_cast<int>(kWouldBlock));
	}

	// ② clipboard=block ⇒ 真的拦。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kBlock);
		GuardStub::SetPrivacyAction(kClipboard, R3ShieldCore::PrivacyAction::Block);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/true, &decision, &flags);
		printf("  clipboard=block + 读剪贴板 → %s (decision=%d)\n", ActionName(action), decision);
		Check("② clipboard=block 真的拦（Action=Block + Blocked）",
			action == kActionBlock && decision == static_cast<int>(kBlocked));
	}

	// ③ clipboard=ask + 能问 ⇒ 真的走到询问通道。
	//
	//    ★ 只断言"Action=Block"是不够的：Record 档 + 通道打不开也会 Block，
	//      而"直接拒"与"先问后拒"会给出**同一个** Decision。
	//      必须用 AskAttemptCount() 把"有没有问过"变成可数事实（v66 同款）。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kBlock);
		GuardStub::SetPromptOpen(true);   // 询问通道可用（桩里 Ask 恒返 Deny）
		GuardStub::SetPrivacyAction(kClipboard, R3ShieldCore::PrivacyAction::Ask);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/true, &decision, &flags);
		const ULONG asks = GuardStub::AskAttemptCount();
		printf("  clipboard=ask + 读剪贴板 → %s，询问次数=%u\n", ActionName(action), asks);
		Check("③ clipboard=ask 真的弹窗问（询问次数 > 0）", asks > 0);
		Check("③ 用户拒绝后照拒（Action=Block）", action == kActionBlock);
	}

	// ④ clipboard=ask 但**问不了**（allowAsk=false）⇒ 回落 Record，不打断。
	//
	//    ★ 这是"不影响使用"的底线：配置写 ask、但调用路径不允许询问
	//      （例如 hook 层判定不该弹窗）时，宁可少拦一次，也不要静默把
	//      粘贴弄坏 —— 用户没被告知就失效，是最难诊断的一类故障。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kBlock);
		GuardStub::SetPromptOpen(true);
		GuardStub::ResetAskAttemptCount();
		GuardStub::SetPrivacyAction(kClipboard, R3ShieldCore::PrivacyAction::Ask);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/false, &decision, &flags);
		printf("  clipboard=ask 但 allowAsk=false → %s，询问次数=%u\n",
			ActionName(action), GuardStub::AskAttemptCount());
		Check("④ 问不了时回落 Record（不打断）",
			action == kActionRecord && decision == static_cast<int>(kWouldBlock));
		Check("④ 问不了时确实没碰询问通道", GuardStub::AskAttemptCount() == 0);
	}

	// ⑤ screen=block ⇒ 真的拦。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(kBlock);
		GuardStub::SetPrivacyAction(kScreen, R3ShieldCore::PrivacyAction::Block);

		int decision = -1;
		ULONG flags = 0;
		const int action = ScreenGuardTest::EvaluateForTest(
			static_cast<ULONG>(R3ShieldCore::ScreenOp::BitBlt), /*allowAsk=*/true,
			&decision, &flags);
		printf("  screen=block + BitBlt → %s (decision=%d)\n", ActionName(action), decision);
		Check("⑤ screen=block 真的拦", action == kActionBlock);
	}

	// ⑥ input_hook=block ⇒ 真的拦。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		GuardStub::SetMode(kBlock);
		GuardStub::SetPrivacyAction(kInputHook, R3ShieldCore::PrivacyAction::Block);

		int decision = -1;
		ULONG flags = 0;
		const int action = InputHookGuardTest::EvaluateForTest(
			static_cast<ULONG>(R3ShieldCore::HookOp::SetKeyboardHook),
			WH_KEYBOARD_LL, /*threadId=*/0, /*rawSink=*/false, /*allowAsk=*/true,
			&decision, &flags);
		printf("  input_hook=block + 全局键盘钩子 → %s (decision=%d)\n", ActionName(action), decision);
		Check("⑥ input_hook=block 真的拦", action == kActionBlock);
	}

	// ⑦ 负对照：block_all 不看这一层（配 record 也照拦）。
	//
	//    ★ 铁律 165：全拦模式下不开后门。如果有人把隐私面配置的判定
	//      提到 block_all 之前，这条会变红。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kBlockAll);
		GuardStub::SetPrivacyAction(kClipboard, R3ShieldCore::PrivacyAction::Record);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/true, &decision, &flags);
		printf("  block_all + clipboard=record → %s (decision=%d)\n", ActionName(action), decision);
		Check("⑦ block_all 下 record 档也照拦（全拦不看这一层）",
			action == kActionBlock && decision == static_cast<int>(kBlocked));
	}

	// ⑧ 负对照：log 模式不看这一层（配 block 也只记录）。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kLog);
		GuardStub::SetPrivacyAction(kClipboard, R3ShieldCore::PrivacyAction::Block);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/true, &decision, &flags);
		printf("  log + clipboard=block → %s (decision=%d)\n", ActionName(action), decision);
		Check("⑧ log 下配 block 也只记录（log 恒不拦）",
			action == kActionRecord && decision == static_cast<int>(kWouldBlock));
	}

	// ⑨ 负对照：把 camera 设成 block 不影响剪贴板（位不串的行为侧验证）。
	{
		GuardStub::ResetPolicy();
		GuardStub::SetHighRisk(true);
		ClipboardGuardTest::SetCloseHookReady(false);
		GuardStub::SetMode(kBlock);
		GuardStub::SetPrivacyAction(kCamera, R3ShieldCore::PrivacyAction::Block);

		int decision = -1;
		int flags = 0;
		const int action = ClipboardGuardTest::EvaluateForTest(kClipRead, CF_UNICODETEXT,
			/*allowAsk=*/true, &decision, &flags);
		printf("  camera=block（剪贴板没配）+ 读剪贴板 → %s\n", ActionName(action));
		Check("⑨ 设 camera=block 不波及剪贴板（仍 Record）", action == kActionRecord);
	}

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
