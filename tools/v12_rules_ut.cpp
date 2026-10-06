//
// v12_rules_ut.cpp - R3ShieldCoreRules v12 新增判据的单元测试。
//
// 覆盖两块（v12 新增持久化面）：
//   1. ComHijack   → CLSID 激活时解析出的服务器路径是否落在用户可写目录
//   2. ScheduledTask → RegisterTaskDefinition / TaskCacheWrite / Run 高危，
//                      CreateFolder 不算高危
//
// ⚠️ COM 判据的存活关键是「非高危不进通道」：
//    IsHighRiskComHijack 对 System32 下的正常服务器必须返回 false，
//    否则浏览器每秒几十次激活会把日志刷爆（v10 那个"噪音淹没真信号"的坑）。
//    本单测把这条**显式钉死**：System32 路径 → norm。
//
// ⚠️ 计划任务判据只看 Op，不看路径（路径提取在 guard 层，读不到也不误报）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskComHijack(PCWSTR comServerPath, bool inproc) noexcept;
	const char* ComHijackRiskReason(PCWSTR comServerPath, bool inproc) noexcept;
	bool IsHighRiskScheduledTask(ULONG taskOp) noexcept;
	const char* ScheduledTaskRiskReason(ULONG taskOp) noexcept;
}

// ComOp（对齐 r3shieldcore_shared.h）
enum
{
	COM_CreateInstance = 1,
	COM_CreateInstanceEx = 2,
	COM_GetClassObject = 3,
};
// ScheduledTaskOp
enum
{
	TASK_RegisterTaskDefinition = 1,
	TASK_CreateFolder = 2,
	TASK_Run = 3,
	TASK_TaskCacheWrite = 4,
};

static int g_failed = 0;

static void CheckBool(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-34s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm");
}

static void CheckCom(const char* note, const wchar_t* path, bool inproc, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskComHijack(path, inproc);
	CheckBool("com", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::ComHijackRiskReason(path, inproc);
		if (reason) printf("        reason=%s\n", reason);
	}
}

int wmain()
{
	setlocale(LC_ALL, "");

	printf("=== 1. COM / OLE 劫持（ComHijack，v12 新增）===\n");
	{
		// —— 必须放行的正常服务器（否则日志被刷爆）——
		CheckCom("System32 进程内服务器（正常）",
			L"C:\\Windows\\System32\\shell32.dll", true, false);
		CheckCom("System32 本地服务器（正常）",
			L"C:\\Windows\\System32\\svchost.exe", false, false);
		CheckCom("Program Files 进程内服务器（正常）",
			L"C:\\Program Files\\Common Files\\microsoft shared\\office16\\mso.dll", true, false);
		CheckCom("Windows\\Microsoft.NET（正常）",
			L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscoree.dll", true, false);

		// —— 必须命中的劫持路径 ——
		CheckCom("临时目录 InprocServer32（劫持）",
			L"C:\\Users\\v\\AppData\\Local\\Temp\\evil.dll", true, true);
		CheckCom("临时目录 LocalServer32（劫持）",
			L"C:\\Users\\v\\AppData\\Local\\Temp\\evil.exe", false, true);
		CheckCom("下载目录 InprocServer32（劫持）",
			L"C:\\Users\\v\\Downloads\\hijack.dll", true, true);
		CheckCom("AppData\\Roaming 下（劫持）",
			L"C:\\Users\\v\\AppData\\Roaming\\evil\\payload.dll", true, true);
		CheckCom("Public 共享目录（劫持）",
			L"C:\\Users\\Public\\drop.dll", true, true);

		// —— 拿不到路径 → 不判高危（宁可不报也不刷假 HIGH）——
		CheckCom("空路径（解析不到）", L"", true, false);
		CheckCom("nullptr（解析不到）", nullptr, true, false);

		// —— 大小写不敏感（大小写混写也要命中）——
		CheckCom("大小写混写 临时目录（劫持）",
			L"c:\\USERS\\v\\appdata\\local\\TEMP\\evil.dll", true, true);

		// —— inproc / local 只影响原因文案，不影响判据 ——
	}

	printf("\n=== 2. 计划任务持久化（ScheduledTask，v12 新增）===\n");
	{
		const unsigned long high[] = { TASK_RegisterTaskDefinition, TASK_TaskCacheWrite, TASK_Run };
		const char* notes[] = { "RegisterTaskDefinition（注册任务）",
			"TaskCacheWrite（直写注册表缓存）", "Run（立即运行任务）" };
		for (int i = 0; i < 3; i++) {
			const char* reason = R3ShieldCoreRules::ScheduledTaskRiskReason(high[i]);
			CheckBool("task", notes[i], reason != nullptr, true);
			if (reason) printf("        reason=%s\n", reason);
		}

		CheckBool("task", "CreateFolder（只建目录，不算高危）",
			R3ShieldCoreRules::IsHighRiskScheduledTask(TASK_CreateFolder), false);
		CheckBool("task", "op=0（未设置）",
			R3ShieldCoreRules::IsHighRiskScheduledTask(0), false);
		CheckBool("task", "op=99（未知，兜底）",
			R3ShieldCoreRules::IsHighRiskScheduledTask(99), false);
	}

	printf("\n=== 3. Op 枚举隔离（v12 语义，防串档）===\n");
	{
		// ComOp 的 1 与 ScheduledTaskOp 的 1 含义完全不同：
		//   ComOp=1             → CreateInstance
		//   ScheduledTaskOp=1   → RegisterTaskDefinition
		// 两个函数各吃各的域，不能互相误判。
		// COM 判据吃的是路径，用 op 值当路径必然解析不到 → 不判高危。
		CheckCom("ComOp=1 当路径传入（不判高危）", L"1", true, false);
		// 计划任务判据吃 op = 1 → 高危（这是 RegisterTaskDefinition）。
		CheckBool("task", "ScheduledTaskOp=1（注册任务）",
			R3ShieldCoreRules::IsHighRiskScheduledTask(1), true);
	}

	printf("\n");
	if (g_failed == 0) printf("全部通过  失败 0\n");
	else printf("存在失败  %d\n", g_failed);
	return g_failed;
}
