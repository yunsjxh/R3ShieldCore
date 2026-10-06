//
// v13_rules_ut.cpp - R3ShieldCoreRules v13 新增判据的单元测试。
//
// 覆盖三块（v13 新增 隐私/凭据/订阅 面）：
//   1. Audio        → 麦克风与环回采集
//   2. TokenTheft   → 令牌窃取三档（一档可疑非高危 / 二档使用高危 / 三档铺路高危）
//   3. WmiSubscription → root\subscription 三件套
//
// ⚠️ 三块判据各自的「存活关键」：
//
//   音频 —— CameraOp 值域与摄像头**共用**，音频判据必须只认音频那三个 op，
//     绝不能被 OpenDevice/CreateDeviceSource/CreateSourceReader 误触发
//     （那是摄像头判据的地盘，重复上报 = 同一动作两条事件）。
//
//   令牌 —— **一档（OpenProcessToken / OpenThreadToken）在规则层不判高危**。
//     这是关键设计：进程管理器、调试器、备份软件、以及我们自己的自我保护
//     hook 都在调 OpenProcessToken。判高危 = 满屏假 HIGH（v10/v12 已栽两次）。
//     本单测把这条显式钉死。
//
//   WMI —— **命名空间是第一道闸**。不在 root\subscription 的操作一律不算高危，
//     否则 root\cimv2 上的正常查询（每个管理类软件都在做）会刷爆日志。
//     本单测同样把这条钉死。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskAudio(ULONG cameraOp) noexcept;
	const char* AudioRiskReason(ULONG cameraOp) noexcept;
	bool IsHighRiskTokenTheft(ULONG tokenOp) noexcept;
	const char* TokenTheftRiskReason(ULONG tokenOp, ULONG* tierOut) noexcept;
	bool IsHighRiskWmiSubscription(ULONG wmiOp, bool inSubscriptionNs, PCWSTR wmiClass) noexcept;
	const char* WmiSubscriptionRiskReason(ULONG wmiOp, bool inSubscriptionNs, PCWSTR wmiClass) noexcept;
}

// CameraOp（对齐 r3shieldcore_shared.h）
enum
{
	CAM_OpenDevice = 1,
	CAM_CreateDeviceSource = 2,
	CAM_CreateSourceReader = 3,
	CAM_EnumDevice = 4,
	CAM_WasapiCapture = 5,
	CAM_WasapiLoopback = 6,
	CAM_MicOpen = 7,
};
// TokenTheftOp
enum
{
	TOK_OpenProcessToken = 1,
	TOK_OpenThreadToken = 2,
	TOK_DuplicateTokenEx = 3,
	TOK_ImpersonateLoggedOnUser = 4,
	TOK_CreateProcessWithToken = 5,
	TOK_SetThreadToken = 6,
	TOK_AdjustTokenPrivileges = 7,
};
// WmiSubscriptionOp
enum
{
	WMI_ConnectServer = 1,
	WMI_PutInstance = 2,
	WMI_ExecQuery = 3,
	WMI_ExecMethod = 4,
	WMI_Subscribe = 5,
};

static int g_failed = 0;

static void CheckBool(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-46s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm");
}

static void CheckAudio(const char* note, unsigned long op, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskAudio(op);
	CheckBool("audio", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::AudioRiskReason(op);
		if (reason) printf("        reason=%s\n", reason);
	}
}

static void CheckToken(const char* note, unsigned long op, bool expect, unsigned long expectTier)
{
	const bool got = R3ShieldCoreRules::IsHighRiskTokenTheft(op);
	ULONG tier = 0;
	const char* reason = R3ShieldCoreRules::TokenTheftRiskReason(op, &tier);
	CheckBool("token", note, got, expect);
	if (tier != expectTier) {
		g_failed++;
		printf("FAIL  [token] %-46s expectTier=%lu gotTier=%lu\n", note, expectTier, tier);
	} else {
		printf("OK    [token] %-46s tier=%lu\n", note, tier);
	}
	if (reason) printf("        reason=%s\n", reason);
}

static void CheckWmi(const char* note, unsigned long op, bool inNs, const wchar_t* cls, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskWmiSubscription(op, inNs, cls);
	CheckBool("wmi", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::WmiSubscriptionRiskReason(op, inNs, cls);
		if (reason) printf("        reason=%s\n", reason);
	}
}

int wmain()
{
	setlocale(LC_ALL, "");

	printf("=== 1. 音频采集 / 环回（Audio，v13 新增）===\n");
	{
		// —— 音频独有的三个入口：全部高危 ——
		CheckAudio("WASAPI 环回（录系统输出）", CAM_WasapiLoopback, true);
		CheckAudio("WASAPI 采集（麦克风）", CAM_WasapiCapture, true);
		CheckAudio("waveIn / MCI 录音", CAM_MicOpen, true);

		// —— ⚠️ 摄像头侧的 op 必须**不**被音频判据认领 ——
		//    它们由 IsHighRiskCamera 负责；这里返 false 才不会重复上报。
		CheckAudio("OpenDevice（摄像头判据的地盘）", CAM_OpenDevice, false);
		CheckAudio("CreateDeviceSource（摄像头判据的地盘）", CAM_CreateDeviceSource, false);
		CheckAudio("CreateSourceReader（摄像头判据的地盘）", CAM_CreateSourceReader, false);

		// —— 枚举设备：只记录 ——
		CheckAudio("EnumDevice（枚举，只记录）", CAM_EnumDevice, false);

		// —— 兜底 ——
		CheckAudio("op=0（未设置）", 0, false);
		CheckAudio("op=99（未知）", 99, false);

		// —— 原因文案必须真的来自音频判据（防串档）——
		printf("        环回 reason=%s\n", R3ShieldCoreRules::AudioRiskReason(CAM_WasapiLoopback));
	}

	printf("\n=== 2. 令牌窃取 / 冒充（TokenTheft，v13 新增）===\n");
	{
		// —— 一档 · 准备：**不判高危**（关键！否则满屏假 HIGH）——
		CheckToken("一档 OpenProcessToken（拿句柄，不判高危）", TOK_OpenProcessToken, false, 1);
		CheckToken("一档 OpenThreadToken（拿句柄，不判高危）", TOK_OpenThreadToken, false, 1);

		// —— 二档 · 使用：高危 ——
		CheckToken("二档 DuplicateTokenEx（复制令牌）", TOK_DuplicateTokenEx, true, 2);
		CheckToken("二档 ImpersonateLoggedOnUser（冒充）", TOK_ImpersonateLoggedOnUser, true, 2);
		CheckToken("二档 CreateProcessWithToken（用他人令牌起进程）", TOK_CreateProcessWithToken, true, 2);
		CheckToken("二档 SetThreadToken（替换线程令牌）", TOK_SetThreadToken, true, 2);

		// —— 三档 · 铺路：高危（精细判据在 guard 侧看特权名）——
		CheckToken("三档 AdjustTokenPrivileges（开特权铺路）", TOK_AdjustTokenPrivileges, true, 3);

		// —— 兜底 ——
		CheckToken("op=0（未设置）", 0, false, 0);
		CheckToken("op=99（未知）", 99, false, 0);

		// —— tierOut 可以为 nullptr（不能崩）——
		{
			const bool got = R3ShieldCoreRules::IsHighRiskTokenTheft(TOK_DuplicateTokenEx);
			R3ShieldCoreRules::TokenTheftRiskReason(TOK_DuplicateTokenEx, nullptr);
			CheckBool("token", "tierOut=nullptr 不崩且判定正确", got, true);
		}
	}

	printf("\n=== 3. WMI 事件订阅（WmiSubscription，v13 新增）===\n");
	{
		// —— ⚠️ 第一道闸：不在 root\subscription 一律不算高危 ——
		CheckWmi("root\\cimv2 写实例（正常，不算高危）", WMI_PutInstance, false, L"Win32_Process", false);
		CheckWmi("root\\cimv2 查询（正常，不算高危）", WMI_ExecQuery, false, L"__EventFilter", false);
		CheckWmi("root\\wmi 订阅（正常，不算高危）", WMI_Subscribe, false, nullptr, false);

		// —— 三件套（在 root\subscription）——
		CheckWmi("PutInstance __EventConsumer（执行体）", WMI_PutInstance, true, L"__EventConsumer", true);
		CheckWmi("PutInstance CommandLineEventConsumer（无文件执行）",
			WMI_PutInstance, true, L"CommandLineEventConsumer", true);
		CheckWmi("PutInstance __FilterToConsumerBinding（绑定）",
			WMI_PutInstance, true, L"__FilterToConsumerBinding", true);
		CheckWmi("PutInstance __EventFilter（触发条件）", WMI_PutInstance, true, L"__EventFilter", true);

		// —— 订阅 / 调用方法（在 root\subscription）——
		CheckWmi("Subscribe（ExecNotificationQuery）", WMI_Subscribe, true, nullptr, true);
		CheckWmi("ExecMethod（可能触发消费者）", WMI_ExecMethod, true, nullptr, true);

		// —— 只看不算高危的两个 op ——
		CheckWmi("ConnectServer（只记录）", WMI_ConnectServer, true, nullptr, false);
		CheckWmi("ExecQuery（审计行为，只记录）", WMI_ExecQuery, true, L"__EventFilter", false);

		// —— 在 root\subscription 写无关类：不报（避免误伤）——
		CheckWmi("PutInstance 无关类（不报）", WMI_PutInstance, true, L"SomeOtherClass", false);

		// —— 类名 nullptr（Subscribe 时不带类名）不崩 ——
		CheckWmi("PutInstance 类名 nullptr（不报）", WMI_PutInstance, true, nullptr, false);

		// —— 大小写不敏感 ——
		CheckWmi("大小写混写 __eventconsumer 仍命中",
			WMI_PutInstance, true, L"__EVENTCONSUMER", true);

		// —— 兜底 ——
		CheckWmi("op=0（未设置）", 0, true, L"__EventFilter", false);
		CheckWmi("op=99（未知）", 99, true, L"__EventFilter", false);
	}

	printf("\n=== 4. Op 枚举隔离（v13 语义，防串档）===\n");
	{
		// TokenTheftOp=1 与 WmiSubscriptionOp=1 与 CameraOp=1 含义完全不同。
		// 三个判据各吃各的域，不能互相误判。
		//
		// TokenTheftOp=1 → OpenProcessToken（一档，非高危）
		CheckBool("token", "TokenTheftOp=1（一档，非高危）",
			R3ShieldCoreRules::IsHighRiskTokenTheft(1), false);
		// WmiSubscriptionOp=1 → ConnectServer（只记录）
		CheckWmi("WmiSubscriptionOp=1（ConnectServer，非高危）", 1, true, nullptr, false);
		// CameraOp=1 → OpenDevice（摄像头的地盘，音频判据不认）
		CheckAudio("CameraOp=1（摄像头的地盘）", CAM_OpenDevice, false);
	}

	printf("\n");
	if (g_failed == 0) printf("全部通过  失败 0\n");
	else printf("存在失败  %d\n", g_failed);
	return g_failed;
}
