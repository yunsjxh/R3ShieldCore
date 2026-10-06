//
// protect_reg_ut.cpp —— 钉住 ini `protect_reg=` 的匹配语义。
//
// 为什么必须有这个测试（2026-10-05 真机日志复盘）：
//
//   用户报「病毒改了左右键互换 / 桌面图标没了，这些没拦住」。
//   查规则表：`Control Panel\Mouse` / `Explorer\Advanced` / `Policies\System`
//   **一条规则都没有**（`grep Control Panel r3shieldcore_rules.cpp` = 0 命中）。
//   但这些键**不能**进高危表 —— 它们本来就是用户自己点"鼠标设置 / 显示桌面图标 /
//   换壁纸"时被正常写入的，一刀切拦 = 把系统设置界面弄坏（铁律 4：高危判据必须带实际危害）。
//
//   引擎已经为这种需求准备了**用户自定义保护**：ini 的 `protect_reg=<前缀>`。
//   可是它能不能用，取决于前缀是拿**哪个形态**去比的 ——
//   注册表 hook 交给规则层的 `KeyPath` 是**完整形式**
//   `\REGISTRY\MACHINE\SOFTWARE\...` / `\REGISTRY\USER\S-1-5-21-...\Software\...`
//   （证据：同目录 `reg_rules_ut.cpp` 里所有用例都用完整形式，且真机日志里
//     `key=` 字段也是这个形态）。
//
//   而文档 `配置详解.md` 给的例子是**相对形式**：
//       # protect_reg=SOFTWARE\MyCompany\Critical
//
//   ⇒ 如果匹配用的是**原始字符串前缀**，用户照文档写的配置**永远命中不了**，
//     而且失败是**静默的**（没有报错、没有日志）—— 典型的"文档里写了，
//     但代码不会读"（铁律 93）。
//
// 本测试就是把这个语义钉死：**相对前缀必须能命中完整形式的键路径**。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskRegistry(const wchar_t* keyPath, const wchar_t* valueName, unsigned long op) noexcept;
	const char* RegistryRiskReason(const wchar_t* keyPath, const wchar_t* valueName, unsigned long op) noexcept;
}

namespace R3ShieldCoreChannel
{
	void StubSetProtectReg(const wchar_t* prefix) noexcept;
	void StubClearProtectReg() noexcept;
}

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

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// 断言：在给定 protect_reg 前缀下，path+op 的判定是否为高危。
static void Expect(const wchar_t* prefix, const wchar_t* path, unsigned long op,
	bool wantHigh, const char* name)
{
	R3ShieldCoreChannel::StubClearProtectReg();
	if (prefix && prefix[0]) {
		R3ShieldCoreChannel::StubSetProtectReg(prefix);
	}
	const char* reason = R3ShieldCoreRules::RegistryRiskReason(path, nullptr, op);
	const bool got = (reason != nullptr);
	printf("      prefix=%-34ls path=%-58ls\n", prefix ? prefix : L"(无)", path);
	printf("      reason=%s\n", reason ? reason : "(null)");
	Check(name, got == wantHigh);
}

int wmain()
{
	setlocale(LC_ALL, "");
	R3ShieldCoreChannel::StubClearProtectReg();

	// ---------------------------------------------------------------
	// A. 文档里的用法：相对前缀 —— 必须能命中完整形式的键路径
	// ---------------------------------------------------------------
	printf("\n=== A. 文档示例（相对前缀）必须生效 ===\n");
	Expect(L"SOFTWARE\\MyCompany\\Critical",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical",
		Op_SetValueKey, true, "相对前缀命中 HKLM 完整形式");

	Expect(L"SOFTWARE\\MyCompany\\Critical",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical\\Sub",
		Op_CreateKey, true, "相对前缀命中 HKLM 子键");

	Expect(L"Software\\MyCompany\\Critical",
		L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Software\\MyCompany\\Critical",
		Op_SetValueKey, true, "相对前缀命中 HKCU 完整形式（SID 段要跳过）");

	// 用户 hive 下要保护的"恶作剧键"——正是本次真机复盘的对象
	Expect(L"Control Panel\\Mouse",
		L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Control Panel\\Mouse",
		Op_SetValueKey, true, "相对前缀命中 HKCU Control Panel\\Mouse");

	Expect(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
		L"\\REGISTRY\\USER\\S-1-5-21-2945951036-705669437-1278233025-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
		Op_SetValueKey, true, "相对前缀命中 HKCU Explorer\\Advanced");

	// ---------------------------------------------------------------
	// B. 完整形式前缀也要能用（老用户可能就是这么配的）
	// ---------------------------------------------------------------
	printf("\n=== B. 完整形式前缀必须仍然生效（向后兼容）===\n");
	Expect(L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical",
		Op_SetValueKey, true, "完整形式前缀命中（不能被新逻辑弄坏）");

	// ---------------------------------------------------------------
	// C. 不该命中的（防止放宽过头 → 误报）
	// ---------------------------------------------------------------
	printf("\n=== C. 反向对照：不该命中的 ===\n");
	Expect(L"SOFTWARE\\MyCompany\\Critical",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\OtherCompany\\Critical",
		Op_SetValueKey, false, "不同公司路径不该命中");

	Expect(L"SOFTWARE\\MyCompany\\Critical",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany",
		Op_SetValueKey, false, "父键不该命中（前缀要逐段）");

	Expect(L"SOFTWARE\\MyCompany\\Critical",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical",
		Op_OpenKey, false, "读操作永不高危");

	Expect(nullptr,
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical",
		Op_SetValueKey, false, "没配 protect_reg 时不该命中");

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
