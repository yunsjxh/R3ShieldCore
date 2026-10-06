//
// v25_rules_ut.cpp - R3ShieldCoreRules v25「全拦模式注册表写『先问再拦』」单元测试。
//
// v25 把 block_all / block_all_safe 下**注册表写**的处置从
// 「一律直接拒、不弹窗」改成「先问再拦」—— 修的是
// 「正常软件写自己的配置 → 静默失败 → 系统弹 0xC0000022 且无任何提示」。
//
// 本单测覆盖规则层的纯函数：
//   · ShouldAskInsteadOfBlockAll —— 这次注册表写值不值得给用户一次放行机会
//
// ★ 为什么必须测（这是本版本唯一的安全边界）：
//    注册表写**比进程创建危险得多** —— 一次成功写入 Run / IFEO / 服务 /
//    WMI 订阅就是**永久持久化**，没有"下一步会再拦一次"的兜底。
//    所以「直接拦、不问」的面必须够大：**多放开一条 = 多一个持久化后门**。
//    这里把四类"不问"的边界逐条钉死，防止以后有人为了减噪往里塞白名单。
//
// ⚠️ 关键回归点：
//   1. 高危规则表命中的路径（Run / IFEO / 服务 / Winlogon / LSA /
//      COM 劫持 / WMI 订阅 / 打印机驱动 / COM+ 目录 / 各类自启点）
//      一律**不问** —— 样本的持久化落点全在册。
//   2. Windows 自身基础设施键（`SOFTWARE\Microsoft\Windows` / `Cryptography` /
//      `COM3` / `SystemCertificates` / `OLE` / `AppModel` / `SYSTEM\ControlSet`）
//      **不问** —— 它们本来就在豁免里，
//      而 block-all 分支抢在豁免之前跑，这个函数必须自己再判一遍。
//      ⚠️ v27 起 `SOFTWARE\Classes` / `MMDevices` 已从此档**剔除**（改为"可问"），
//         见 §3b 注释；本文件下方对应断言已同步为 expect=ASK。
//   3. hive 级操作（LoadKey / UnloadKey / SaveKey / RestoreKey …）**不问**。
//   4. 段边界：`SOFTWARE\Microsoft\WindowsApps` 不得被
//      `SOFTWARE\Microsoft\Windows` 前缀误吞（必须落在 '\' 或结尾）。
//   5. 空路径 / nullptr → **不问**（fail-closed）。
//   6. 第三方软件写自己的配置 → **问**（这才是 v25 要救的场景）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool ShouldAskInsteadOfBlockAll(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
}

// 与 r3shieldcore_shared.h 的 R3ShieldCore::Op **真实取值**对齐（照枚举声明顺序抄，
// 不要凭印象 —— 本项目在 v25 就踩过这个坑：把 SetValueKey 写成 5 实际是 3，
// 结果 4 个用例"失败"，实际是测试自己的常量错了，规则层无辜）。
//
//   CreateKey=1  OpenKey=2  SetValueKey=3  DeleteKey=4  DeleteValueKey=5
//   RenameKey=6  FlushKey=7  ...
//   LoadKey=13   UnloadKey=14  SaveKey=15  RestoreKey=16  ReplaceKey=17
//   LoadKeyEx=18 UnloadKeyEx=19 SaveKeyEx=20
//
// 本单测不链共享头（channel_stub.cpp 只提供 Policy 桩），所以手工镜像。
enum TestOp
{
	OpCreateKey = 1,
	OpOpenKey = 2,
	OpSetValueKey = 3,
	OpDeleteKey = 4,
	OpDeleteValueKey = 5,
	OpRenameKey = 6,
	OpSetInformationKey = 12,
	OpLoadKey = 13,
	OpUnloadKey = 14,
	OpSaveKey = 15,
	OpRestoreKey = 16,
	OpReplaceKey = 17,
	OpLoadKeyEx = 18,
	OpUnloadKeyEx = 19,
	OpSaveKeyEx = 20,
};

static int g_failed = 0;

static void Check(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-64s expect=%-6s got=%-6s\n", mark, group, note,
		expect ? "ASK" : "BLOCK", got ? "ASK" : "BLOCK");
}

// 便利包装：绝大多数用例都在"写一个值"这个 op 上。
static bool Ask(PCWSTR keyPath, ULONG op = OpSetValueKey)
{
	return R3ShieldCoreRules::ShouldAskInsteadOfBlockAll(keyPath, L"SomeValue", op);
}

int main()
{
	setlocale(LC_ALL, ".UTF8");

	printf("=== 1. ★ 高危持久化落点：一律不问（直接拦）===\n");
	Check("risk", "HKLM Run 键",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), false);
	Check("risk", "HKCU Run 键（用户 hive 形态）",
		Ask(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), false);
	Check("risk", "RunOnce",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), false);
	Check("risk", "IFEO 映像劫持",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\task.exe"), false);
	Check("risk", "Winlogon Shell",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), false);
	Check("risk", "服务子树（可指向任意驱动/服务二进制）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\ImagePath"), false);
	Check("risk", "WMI 事件订阅",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Wbem\\Subscription"), false);
	Check("risk", "打印机 Monitors（Spooler 以 SYSTEM 加载其下 DLL）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"), false);
	Check("risk", "AppInit_DLLs",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"), false);
	Check("risk", "ShellServiceObjectDelayLoad",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad"), false);
	Check("risk", "Browser Helper Objects",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"), false);
	Check("risk", "Active Setup Installed Components",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), false);
	Check("risk", "AppCertDlls",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"), false);
	Check("risk", "LSA 配置",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa"), false);
	Check("risk", "BootExecute",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"), false);
	Check("risk", "hosts 之外的 Tcpip 参数",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"), false);

	printf("\n=== 2. ★ 高危也覆盖删除类 op（不是只判写值）===\n");
	Check("del", "DeleteValueKey 于 Run 键",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", OpDeleteValueKey), false);
	Check("del", "DeleteKey 于 IFEO",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", OpDeleteKey), false);
	Check("del", "CreateKey 于服务子树",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NewSvc", OpCreateKey), false);

	printf("\n=== 3. ★ 基础设施键（豁免同款）：一律不问 ===\n");
	Check("infra", "SOFTWARE\\Microsoft\\Windows",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows"), false);
	Check("infra", "SOFTWARE\\Microsoft\\Windows 子键",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"), false);
	Check("infra", "用户 hive 的 Microsoft\\Windows",
		Ask(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion"), false);
	Check("infra", "Cryptography",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography"), false);
	Check("infra", "COM3",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3"), false);
	Check("infra", "SystemCertificates",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates"), false);
	Check("infra", "OLE",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\OLE"), false);
	Check("infra", "AppModel",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\AppModel"), false);
	Check("infra", "SYSTEM\\ControlSet001（★ 内核真实形态）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control"), false);
	Check("infra", "SYSTEM\\CurrentControlSet（★ 符号链接形态）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control"), false);
	Check("infra", "SYSTEM\\ControlSet001\\Control 深层子键",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management"), false);
	// ★ v27 变更：`SOFTWARE\Classes` 与 `MMDevices` 已从「不问直接拒」表**剔除**
	//    → 回到「可问」档。理由见 v26_rules_ut.cpp §3b：
	//    它们是 HKCR 机器侧主存储 / 音频设备枚举，正常软件常态读写；
	//    而 block-all 的"不问表"判错 = 整机报废（与"豁免表"判错语义相反）。
	//    本条由 expect=BLOCK 改为 expect=ASK（v25 时代期望已过时）。
	Check("infra", "SOFTWARE\\Classes（v27 起改为可问）",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID"), true);
	Check("infra", "MMDevices（v27 起改为可问）",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MMDevices"), true);
	Check("infra", "Policies\\Microsoft\\Cryptography",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography"), false);

	printf("\n=== 3b. ★ 会话管理器引导键 / WMI 仓库（段名不同形，必须逐段比对）===\n");
	Check("boot", "BootExecute",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\BootExecute"), false);
	Check("boot", "SetupExecute",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\SetupExecute"), false);
	Check("boot", "AppCertDlls",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCertDlls"), false);
	Check("boot", "LSA（句柄形态）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa"), false);
	Check("boot", "RDP rdpwd",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Terminal Server\\Wds\\rdpwd"), false);
	Check("boot", "SecurityProviders",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\SecurityProviders"), false);
	Check("boot", "WMI 仓库根",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Wbem"), false);
	Check("boot", "WMI 仓库 Subscription 子树（绕开 COM 直写）",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Wbem\\Subscription"), false);
	Check("boot", "WbemX（段边界，不得误命中）",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WbemX"), true);

	printf("\n=== 4. ★ COM+ 目录：不问（可指定激活身份）===\n");
	Check("complus", "COM3\\Catalog",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3\\Catalog"), false);
	Check("complus", "COM3\\Catalog 子键",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3\\Catalog\\{00000112-0000-0000-C000-000000000046}"), false);

	printf("\n=== 5. ★ hive 级操作：不问 ===\n");
	Check("hive", "LoadKey（挂载攻击者 hive）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\hivelist", OpLoadKey), false);
	Check("hive", "UnloadKey",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\Evil", OpUnloadKey), false);
	Check("hive", "SaveKey（导出 SAM 之类）",
		Ask(L"\\REGISTRY\\MACHINE\\SAM", OpSaveKey), false);

	printf("\n=== 6. ★ 段边界：不得被更长的近邻段误吞 ===\n");
	Check("bound", "SOFTWARE\\Microsoft\\WindowsApps（不是 \\Windows\\）",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WindowsApps"), true);
	Check("bound", "SOFTWARE\\Microsoft\\WindowsX",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WindowsX"), true);
	Check("bound", "SOFTWARE\\ClassesX",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\ClassesX"), true);
	Check("bound", "SOFTWARE\\Microsoft\\COM30",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM30"), true);
	Check("bound", "SYSTEM\\ControlSetX（非纯数字）",
		Ask(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSetX"), true);

	printf("\n=== 7. ★ v25 的本意：第三方软件写自己的配置 → 问 ===\n");
	Check("ask", "HKLM 第三方厂商键",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\MyProduct"), true);
	Check("ask", "HKCU 第三方厂商键",
		Ask(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\MyCompany\\MyProduct"), true);
	Check("ask", "HKCU 应用设置（TextInputHost 那类 LocalState）",
		Ask(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Input\\Settings"), true);
	Check("ask", "SOFTWARE\\Microsoft 下非 Windows 子键（如 Office）",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Office\\16.0"), true);
	Check("ask", "第三方 SOFTWARE 根",
		Ask(L"\\REGISTRY\\MACHINE\\SOFTWARE\\7-Zip"), true);
	Check("ask", "HKCU\\Software\\Classes 之外的普通键",
		Ask(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Notepad++"), true);

	printf("\n=== 8. ★ 边界 / 空输入（fail-closed）===\n");
	Check("edge", "空串", Ask(L""), false);
	Check("edge", "nullptr", Ask(nullptr), false);
	Check("edge", "只有 \\REGISTRY\\MACHINE\\", Ask(L"\\REGISTRY\\MACHINE\\"), true);
	Check("edge", "无 hive 前缀的裸路径（按原样判）",
		Ask(L"SOFTWARE\\MyCompany"), true);

	printf("\n=== 全部通过 ===  失败 %d\n", g_failed);
	return g_failed == 0 ? 0 : 1;
}
