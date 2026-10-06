//
// reg_rules_ut.cpp - R3ShieldCoreRules::IsHighRiskRegistry 单元测试。
//
// 直接链 r3shieldcore_rules.cpp 的目标文件，验证规则表判定是否正确。
// 不需要引擎、不需要注入 —— 纯逻辑验证。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskRegistry(const wchar_t* keyPath, const wchar_t* valueName, unsigned long op) noexcept;
	const char* RegistryRiskReason(const wchar_t* keyPath, const wchar_t* valueName, unsigned long op) noexcept;
}

// Op 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	Op_CreateKey = 1,
	Op_OpenKey = 2,
	Op_SetValueKey = 3,
	Op_DeleteKey = 4,
	Op_DeleteValueKey = 5,
	Op_RenameKey = 6,
	Op_FlushKey = 7,
	Op_QueryValueKey = 8,
	Op_EnumerateKey = 9,
	Op_EnumerateValueKey = 10,
	Op_SetInformationKey = 11,
};

struct Case
{
	const wchar_t* path;
	unsigned long op;
	bool expectHigh;
	const char* note;
};

int wmain()
{
	setlocale(LC_ALL, "");

	const Case cases[] = {
		// 用户 hive 自启动键（探针实际写的路径）
		{ L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			Op_SetValueKey, true,  "HKCU Run 写值" },
		{ L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			Op_CreateKey, true,  "HKCU Run 建键" },
		// 机器 hive 自启动键（全大写）
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Op_SetValueKey, true,  "HKLM Run 写值" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			Op_SetValueKey, true,  "HKLM RunOnce 写值" },
		// 服务
		{ L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Evil",
			Op_CreateKey, true,  "HKLM 服务建键" },
		// Winlogon
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			Op_SetValueKey, true,  "HKLM Winlogon" },
		// IFEO
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
			Op_SetValueKey, true,  "HKLM IFEO" },
		// hosts 侧无
		// 普通键（对照）
		{ L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Software\\R3ShieldCoreNormalTest",
			Op_SetValueKey, false, "HKCU 普通键（应不高危）" },
		{ L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Software\\R3ShieldCoreNormalTest",
			Op_CreateKey, false, "HKCU 普通键建键（应不高危）" },
		// 读操作永不高危
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			Op_OpenKey, false, "HKLM Run 打开（读，应不高危）" },
	};

	int failed = 0;
	for (const Case& c : cases) {
		const char* reason = R3ShieldCoreRules::RegistryRiskReason(c.path, nullptr, c.op);
		bool got = (reason != nullptr);
		const char* mark = (got == c.expectHigh) ? "OK  " : "FAIL";
		if (got != c.expectHigh) failed++;
		printf("%s  op=%-2lu expect=%-5s got=%-5s  %-28s  reason=%s\n",
			mark, c.op, c.expectHigh ? "HIGH" : "norm",
			got ? "HIGH" : "norm", c.note, reason ? reason : "(null)");
	}

	printf("\n%s  失败 %d / %d\n", failed == 0 ? "全部通过" : "存在失败", failed, (int)(sizeof(cases) / sizeof(cases[0])));
	return failed;
}
