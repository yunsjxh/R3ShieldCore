//
// v26_rules_ut.cpp - R3ShieldCore v26「全拦模式：可问项 + 询问通道不可用 → 降级放行」单测。
//
// ★ 本版本修的是什么（VM 实测 2026-09-30 20:38）：
//
//   block_all 下 `ShouldAskInsteadOfBlockAll` 判定为"可问"的注册表写，
//   在 `R3ShieldCorePrompt::Ask` 拿不到询问通道时会**立刻返回 fallback**
//   （`prompt_default=deny`）→ **静默直接拒** →
//   用户看到「Windows 无法访问指定设备」而**没有任何弹窗**，
//   与 v25 想修的老毛病**一模一样**（只是藏在判定层之后，看日志看不出来）。
//
//   v26 的处置在 **guard 层**（registry_guard.cpp / file_guard.cpp）：
//     `askable == true` 且通道不可用 → 放行 + `FlagEvent2AskUnavailable`。
//
// ⚠️ 单测只能覆盖**规则层**（`build_ut.sh` 只链 `r3shieldcore_rules.cpp`），
//    所以这里测的是 v26 依赖的**前置判据**仍然正确：
//    「哪些键是 askable，哪些必须直接拒」—— 这一档就是安全边界，
//    降级放行**绝不能**把边界也放开。
//
//     guard 层的三条分支（高危直拒 / 通道在→问 / 通道不在→放行）
//     靠 `build.sh` 编译 + VM 实测验证，**本文件测不到**。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool ShouldAskInsteadOfBlockAll(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
}

// 与 r3shieldcore_shared.h 的 R3ShieldCore::Op **真实取值**对齐（照枚举声明顺序抄）。
enum ProbeOp
{
	OpCreateKey = 1,
	OpOpenKey = 2,
	OpSetValueKey = 3,
	OpDeleteKey = 4,
	OpDeleteValueKey = 5,
	OpRenameKey = 6,
	OpFlushKey = 7,
	OpQueryValueKey = 8,
	OpEnumerateKey = 9,
	OpEnumerateValueKey = 10,
	OpQueryKey = 11,
	OpSetInformationKey = 12,
	OpLoadKey = 13,
	OpUnloadKey = 14,
	OpSaveKey = 15,
};

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* group, const char* note,
	PCWSTR keyPath, ULONG op, bool expectAsk)
{
	const bool got = R3ShieldCoreRules::ShouldAskInsteadOfBlockAll(keyPath, L"SomeValue", op);
	const bool ok = (got == expectAsk);

	if (ok) {
		g_pass++;
	}
	else {
		g_fail++;
	}

	printf("%s  [%s] %-58s expect=%-5s got=%-5s\n",
		ok ? "  ok  " : "  FAIL", group, note,
		expectAsk ? "ASK" : "BLOCK", got ? "ASK" : "BLOCK");
}

static bool Ask(PCWSTR keyPath, ULONG op = OpSetValueKey)
{
	return R3ShieldCoreRules::ShouldAskInsteadOfBlockAll(keyPath, L"SomeValue", op);
}

int main()
{
	setlocale(LC_ALL, ".UTF8");

	// ---------------------------------------------------------------
	// 1. ★ v26 回归点：VM 日志里的真实键 —— 必须是 ASK
	//    （v26 之前它们被"通道不可用→fallback"静默拒掉了。）
	// ---------------------------------------------------------------
	printf("=== 1. VM 实测键：必须 ASK（v26 降级放行的那一档）===\n");
	Check("vm", "HKCU\\Software（OneDrive 实测）",
		L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software", OpCreateKey, true);
	Check("vm", "HKCU\\Software 相对形态（日志里的 key=Software）",
		L"Software", OpCreateKey, true);
	Check("vm", "OneDrive 配置",
		L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\OneDrive", OpCreateKey, true);

	// ---------------------------------------------------------------
	// 2. ★★ 安全边界：这一档**绝不能**被降级放行放开。
	//    高危持久化落点 —— 样本的注册表持久化全在这里。
	// ---------------------------------------------------------------
	printf("\n=== 2. 安全边界：高危落点必须 BLOCK（降级放行不得波及）===\n");
	Check("risk", "HKLM Run", 
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", OpSetValueKey, false);
	Check("risk", "HKCU Run",
		L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", OpSetValueKey, false);
	Check("risk", "IFEO 映像劫持",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\task.exe", OpCreateKey, false);
	Check("risk", "Winlogon Shell",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", OpSetValueKey, false);
	Check("risk", "服务 ImagePath",
		L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EvilSvc\\ImagePath", OpSetValueKey, false);
	Check("risk", "WMI 订阅",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Wbem\\Subscription", OpCreateKey, false);
	Check("risk", "AppInit_DLLs",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", OpSetValueKey, false);

	// ---------------------------------------------------------------
	// 3. 安全边界：Windows 基础设施键 —— 同样 BLOCK
	//    （block-all 分支抢在豁免之前跑，这个函数必须自己判一遍。）
	// ---------------------------------------------------------------
	printf("\n=== 3. 安全边界：Windows 基础设施键必须 BLOCK ===\n");
	Check("infra", "SystemCertificates（OneDrive 实测被拒）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed", OpCreateKey, false);
	Check("infra", "Cryptography（OneDrive 实测被拒）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography", OpSetInformationKey, false);
	Check("infra", "WBEM\\CIMOM（WmiApSrv 实测被拒）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\CIMOM", OpCreateKey, false);
	Check("infra", "Tcpip\\Parameters（vmtoolsd 实测被拒）",
		L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", OpCreateKey, false);
	Check("infra", "SOFTWARE\\Microsoft\\Windows",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows", OpCreateKey, false);

	// ---------------------------------------------------------------
	// 3b. ★ v27：从"不问直接拒"表里**剔除**的两条 → 必须 ASK（弹窗）
	//
	//     它们曾从 `IsSystemInfrastructureKey`（LOG/BLOCK 的**豁免**表）
	//     照搬进 block-all 的**"不问表"** —— 但两表语义**相反**：
	//     豁免错了顶多"少拦一次"，不问错了是"整机报废"。
	//
	//     `HKLM\SOFTWARE\Classes` = HKCR 机器侧主存储，全系统最热键之一；
	//     `MMDevices` = 音频/蓝牙设备枚举，正常软件常态读写。
	//     ⇒ 回到"可问"档。
	//
	//     ★ 安全边界没漏：`Classes` 下真正的劫持点
	//     （`exefile\shell\open\command` / `ActivatableClasses` / `AppID` /
	//     `Extensions` / COM+ 两个 CLSID）都在 `kRegistryRules` **高危表**里，
	//     由判据 ① 直接拒，压根走不到这张表。见下方 3c 段。
	// ---------------------------------------------------------------
	printf("\n=== 3b. ★ v27 剔除条：必须 ASK（不再是「不问直接拒」）===\n");
	Check("v27", "SOFTWARE\\Classes（HKCR 机器侧主存储）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", OpCreateKey, true);
	Check("v27", "SOFTWARE\\Classes（常态 COM 激活）",
		L"\\REGISTRY\\MACHINE\\Software\\Classes", OpCreateKey, true);
	Check("v27", "SOFTWARE\\Microsoft\\MMDevices",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MMDevices", OpCreateKey, true);
	Check("v27", "SOFTWARE\\Microsoft\\MMDevices（音频子键）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\MMDevices\\Audio\\Capture", OpCreateKey, true);

	// ---------------------------------------------------------------
	// 3c. ★ v27 安全边界复核：`Classes` 下的**真劫持点**仍必须 BLOCK
	//     （它们在 `kRegistryRules` 高危表里，由判据 ① 直接拒 ——
	//      剔出"不问表"没让它们掉档。）
	// ---------------------------------------------------------------
	printf("\n=== 3c. ★ v27 复核：Classes 下的真劫持点仍必须 BLOCK ===\n");
	Check("v27", "Classes\\exefile\\shell\\open\\command（劫持 exe 关联）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\exefile\\shell\\open\\command", OpSetValueKey, false);
	Check("v27", "Classes\\ActivatableClasses（WinRT 激活劫持）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\ActivatableClasses", OpCreateKey, false);
	Check("v27", "Classes\\AppID（COM 身份劫持）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\AppID", OpCreateKey, false);
	Check("v27", "Classes\\Extensions（点劫持）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Extensions", OpCreateKey, false);

	// ---------------------------------------------------------------
	// 4. 安全边界：hive 级操作 —— 影响面最大，必须 BLOCK
	// ---------------------------------------------------------------
	printf("\n=== 4. 安全边界：hive 级操作必须 BLOCK ===\n");
	Check("hive", "SaveKey（拖走 SAM）",
		L"\\REGISTRY\\MACHINE\\SAM", OpSaveKey, false);
	Check("hive", "LoadKey（挂载任意 hive）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE", OpLoadKey, false);

	// ---------------------------------------------------------------
	// 5. fail-closed：拿不到路径 → BLOCK（不能因为"判不出"就放行）
	// ---------------------------------------------------------------
	printf("\n=== 5. fail-closed：空路径 / nullptr 必须 BLOCK ===\n");
	Check("empty", "空字符串", L"", OpSetValueKey, false);
	{
		const bool got = R3ShieldCoreRules::ShouldAskInsteadOfBlockAll(nullptr, L"v", OpSetValueKey);
		const bool ok = (got == false);
		if (ok) { g_pass++; } else { g_fail++; }
		printf("%s  [empty] %-58s expect=%-5s got=%-5s\n",
			ok ? "  ok  " : "  FAIL", "nullptr", "BLOCK", got ? "ASK" : "BLOCK");
	}

	// ---------------------------------------------------------------
	// 6. 段的边界：近邻段不得被误吞
	// ---------------------------------------------------------------
	printf("\n=== 6. 段边界：近邻段不得被前缀误吞 ===\n");
	Check("bound", "SOFTWARE\\Microsoft\\WindowsApps（近邻，必须 ASK）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WindowsApps", OpCreateKey, true);
	Check("bound", "SOFTWARE\\Microsoft\\WbemX（近邻，必须 ASK）",
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WbemX", OpCreateKey, true);

	// ---------------------------------------------------------------
	// 7. 正身：第三方软件写自己的配置 → ASK（v25 要救的场景，v26 保持）
	// ---------------------------------------------------------------
	printf("\n=== 7. 第三方自用配置：必须 ASK ===\n");
	Check("app", "HKCU\\Software\\MyApp\\Settings",
		L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\MyApp\\Settings", OpCreateKey, true);
	Check("app", "HKCU\\Software\\VendorX",
		L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\VendorX", OpSetValueKey, true);

	printf("\n=== 汇总：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
