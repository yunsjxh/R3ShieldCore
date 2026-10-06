//
// v11_rules_ut.cpp - R3ShieldCoreRules v11 新增判据的单元测试。
//
// 覆盖三块（都是 v11 的 API 变体扩展）：
//   1. ScreenOp::GetDIBits        → 截屏第三条路（直读屏幕 DC）
//   2. ServiceConfigOp::*         → 服务/安全对象权限变更
//   3. HookOp::PollAsyncKeyState / PollKeyState → 轮询式键盘记录
//
// ⚠️ 轮询那两条的语义特殊：规则层只表达"一旦被认定就是高危"，
//    是否认定由 InputHookGuard 的密度检测器决定。这里只验规则层。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskScreen(unsigned long screenOp) noexcept;
	const char* ScreenRiskReason(unsigned long screenOp) noexcept;
	bool IsHighRiskServiceConfig(unsigned long serviceOp) noexcept;
	const char* ServiceConfigRiskReason(unsigned long serviceOp) noexcept;
	bool IsHighRiskInputPolling(unsigned long hookOp) noexcept;
	const char* InputHookRiskReason(unsigned long idHook, unsigned long threadId,
		unsigned long hookOp, bool rawInputSink) noexcept;
}

// ScreenOp（对齐 r3shieldcore_shared.h）
enum { SC_BitBlt = 1, SC_StretchBlt = 2, SC_PrintWindow = 3, SC_GetDIBits = 4 };
// ServiceConfigOp
enum { SV_SetServiceSecurity = 1, SV_SetKernelObjectSecurity = 2 };
// HookOp
enum
{
	HK_SetMouseHook = 1,
	HK_SetKeyboardHook = 2,
	HK_SetInputJournal = 3,
	HK_SetOtherHook = 4,
	HK_RegisterRawInput = 5,
	HK_Unhook = 6,
	HK_PollAsyncKeyState = 7,
	HK_PollKeyState = 8,
	HK_SetEventHook = 9,
};

static int g_failed = 0;

static void CheckBool(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-34s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm");
}

int wmain()
{
	setlocale(LC_ALL, "");

	printf("=== 1. 截屏（ScreenOp，v11 新增 GetDIBits）===\n");
	{
		const unsigned long cases[] = { SC_BitBlt, SC_StretchBlt, SC_PrintWindow, SC_GetDIBits };
		const char* notes[] = { "BitBlt（源屏幕 DC）", "StretchBlt（源屏幕 DC）",
			"PrintWindow（抓窗口）", "GetDIBits（直读屏幕 DC，绕过 BitBlt）" };
		for (int i = 0; i < 4; i++) {
			const char* reason = R3ShieldCoreRules::ScreenRiskReason(cases[i]);
			CheckBool("screen", notes[i], reason != nullptr, true);
			if (reason) printf("        reason=%s\n", reason);
		}
		CheckBool("screen", "op=0（未设置）",
			R3ShieldCoreRules::IsHighRiskScreen(0), false);
		CheckBool("screen", "op=99（未知，兜底）",
			R3ShieldCoreRules::IsHighRiskScreen(99), false);
	}

	printf("\n=== 2. 服务 / 安全对象权限变更（ServiceConfigOp，v11 新增）===\n");
	{
		const unsigned long cases[] = { SV_SetServiceSecurity, SV_SetKernelObjectSecurity };
		const char* notes[] = { "SetServiceObjectSecurity（sc sdset）",
			"NtSetSecurityObject（改任意对象 DACL）" };
		for (int i = 0; i < 2; i++) {
			const char* reason = R3ShieldCoreRules::ServiceConfigRiskReason(cases[i]);
			CheckBool("svccfg", notes[i], reason != nullptr, true);
			if (reason) printf("        reason=%s\n", reason);
		}
		CheckBool("svccfg", "op=0（未设置）",
			R3ShieldCoreRules::IsHighRiskServiceConfig(0), false);
		CheckBool("svccfg", "op=99（未知，兜底）",
			R3ShieldCoreRules::IsHighRiskServiceConfig(99), false);
	}

	printf("\n=== 3. 轮询式键盘记录（HookOp，v11 新增）===\n");
	{
		CheckBool("poll", "PollAsyncKeyState（轮询高危）",
			R3ShieldCoreRules::IsHighRiskInputPolling(HK_PollAsyncKeyState), true);
		CheckBool("poll", "PollKeyState（轮询高危）",
			R3ShieldCoreRules::IsHighRiskInputPolling(HK_PollKeyState), true);
		// SetWinEventHook 刻意不算高危（无障碍工具/窗口管理器都在用）。
		CheckBool("poll", "SetEventHook（只记录，不算高危）",
			R3ShieldCoreRules::IsHighRiskInputPolling(HK_SetEventHook), false);
		// ⚠️ 注意 IsHighRiskInputPolling 内部委托给 InputHookRiskReason(0,0,op,false)，
		//    而 threadId=0 在钩子那几条里表示"全局钩子" —— 那是**本来就高危**的。
		//    所以这里只验 Unhook（拆钩子，任何情况下都不高危），
		//    不能拿 SetMouseHook 当"非高危"的反例。
		CheckBool("poll", "Unhook（非轮询，不算）",
			R3ShieldCoreRules::IsHighRiskInputPolling(HK_Unhook), false);
		CheckBool("poll", "op=0（未设置）",
			R3ShieldCoreRules::IsHighRiskInputPolling(0), false);
		CheckBool("poll", "op=99（未知，兜底）",
			R3ShieldCoreRules::IsHighRiskInputPolling(99), false);
	}

	printf("\n%s  失败 %d\n", g_failed == 0 ? "全部通过" : "存在失败", g_failed);
	return g_failed;
}
