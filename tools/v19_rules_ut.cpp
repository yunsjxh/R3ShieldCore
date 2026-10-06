//
// v19_rules_ut.cpp - R3ShieldCoreRules v19「持久化面扩容」单元测试。
//
// 本轮纯**规则表扩充**（不动 ABI、不加 hook、不加导出）。补的是
// HANDOVER §11 优先级 3 列的三类长期空白 —— 它们都有共同点：
// **既是持久化落点，又是代码执行落点**，且既有规则表看不到。
//
//   ① 打印机驱动 / 打印处理器（Spooler 以 SYSTEM 身份 LoadLibrary）
//        `...\Control\Print\Monitors` / `Providers` / `Environments`
//        → 写它 = 让打印服务按攻击者路径起 DLL（PrintNightmare 落点）。
//
//   ② WinRT / Appx 应用注册与激活
//        `...\CurrentVersion\AppModel` / `Classes\ActivatableClasses` /
//        `Classes\Extensions` / `Classes\AppID`
//        → 伪造包身份 / 注册后台任务 / 劫持 COM 激活入口。
//
//   ③ COM+ 目录
//        `SOFTWARE\Microsoft\COM3\Catalog` / COM+ 相关 CLSID
//        → COM+ 组件可指定运行身份，写它 = 让系统以高权限激活攻击者 DLL，
//          **不经过 HKCR\CLSID**（既有 COM 劫持规则看不到）。
//
//   ④ 其余自启 / 宿主劫持补盲（BHO / Active Setup / ShellExecuteHooks /
//      TimeProviders / SecurityProviders / AppInit / AppCertDlls 等），
//      用于补上 v15 宿主注入表"需要值指向用户可写目录"的盲区。
//
// ⚠️ 本表是 RegistryGuard 的**粗筛**（只看键路径，不看值），
//    判据是"写没写" —— 因此必须严格检查**噪音面**：
//    正常软件不该写这些键，包含它们的**子键**也一样（逐段前缀）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "r3shieldcore_rules.h"

static int g_failed = 0;

static void Check(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-66s expect=%-6s got=%-6s\n", mark, group, note,
		expect ? "YES" : "no", got ? "YES" : "no");
}

// 便捷封装：按"机器范围 + SetValueKey"调规则。
static const char* Reg(PCWSTR path)
{
	return R3ShieldCoreRules::RegistryRiskReason(path, L"TestValue", (ULONG)R3ShieldCore::Op::SetValueKey);
}
static bool RegHigh(PCWSTR path)
{
	return Reg(path) != nullptr;
}

// 命中规则返回的 reason 里是否包含指定子串（宽字符 → 窄字符比对）。
static bool ReasonHas(const char* reason, const char* needle)
{
	if (!reason) {
		return false;
	}
	return strstr(reason, needle) != nullptr;
}

int main()
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	// ==================================================================
	// 1. 打印机驱动 / 端口监视器 / 打印处理器
	// ==================================================================
	//
	// ⚠️ 必须是**内核真实路径形态**（NtQueryKey 返回的样子，见 §3.3c）：
	//    `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Print\...`
	//    `CurrentControlSet` 会被解析成 `ControlSet001` → 逐段比对要能等价。
	printf("=== 1. 打印机驱动 / Spooler 加载面 ===\n");

	Check("print", "Monitors（内核 ControlSetNNN 形态）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Monitors"), true);
	Check("print", "Monitors 子键（具体监视器名）→ 命中前缀",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Monitors\\EvilMon"), true);
	Check("print", "Monitors（CurrentControlSet 字面形态）→ 也命中",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"), true);
	Check("print", "Providers → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Providers"), true);
	Check("print", "Environments（x64 处理器）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Environments\\Windows x64\\Print Processors"), true);

	// 噪音面：Print 下的**其它**子键（正常打印机/驱动安装会写）不得命中。
	Check("print", "Print\\Printers（正常打印队列）→ 不判（防噪音）",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Printers"), false);
	Check("print", "Print\\Printers\\Foo\\PrinterDriverData → 不判",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Printers\\Foo\\PrinterDriverData"), false);
	// ⚠️ 段边界：`Monitors` 不得被 `MonitorsX` 撞上（逐段比对铁律）。
	Check("print", "Print\\MonitorsX（非 Monitors 段）→ 不判（段边界）",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\MonitorsX"), false);

	// ==================================================================
	// 2. WinRT / Appx 应用注册与激活
	// ==================================================================
	printf("\n=== 2. WinRT / Appx 注册与激活 ===\n");

	Check("winrt", "AppModel（包注册/身份）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel"), true);
	Check("winrt", "AppModel\\PackageRepository → 命中前缀",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\PackageRepository"), true);
	Check("winrt", "Classes\\ActivatableClasses（COM 激活入口）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\ActivatableClasses\\Package.abc"), true);
	Check("winrt", "Classes\\Extensions（扩展点/后台任务）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\Extensions\\Contract.abc"), true);
	Check("winrt", "Classes\\AppID（激活/权限绑定）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\AppID\\{12345678-1234-1234-1234-123456789012}"), true);
	// HKCU 侧 AppModel：同样列出（用户级包注册不需要提权）。
	Check("winrt", "HKCU 的 AppModel → 高危（user=true 有意放开）",
		R3ShieldCoreRules::RegistryRiskReason(
			L"\\REGISTRY\\USER\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel",
			L"V", (ULONG)R3ShieldCore::Op::SetValueKey) != nullptr, true);

	// 噪音面：AppModel 之外的同名段不得误命中。
	Check("winrt", "CurrentVersion\\Appx（非 AppModel）→ 不判",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx"), false);

	// ==================================================================
	// 3. COM+ 目录
	// ==================================================================
	printf("\n=== 3. COM+ 目录 ===\n");

	Check("complus", "COM3\\Catalog → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3\\Catalog"), true);
	Check("complus", "COM3\\Catalog\\CLSID 子键 → 命中前缀",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3\\Catalog\\CLSID\\{00000112-0000-0000-C000-000000000046}"), true);
	Check("complus", "COM+ 目录 CLSID {00000112...} → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{00000112-0000-0000-C000-000000000046}"), true);
	Check("complus", "COM+ 目录 CLSID {00000113...} → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{00000113-0000-0000-C000-000000000046}"), true);

	// 噪音面：普通 CLSID 不在表里（normal COM 注册太热，且已有 ComHijackGuard）。
	Check("complus", "普通 CLSID（非 COM+ 那两个）→ 不判（防噪音）",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000001}\\InprocServer32"), false);

	// ==================================================================
	// 4. 其余自启 / 宿主劫持补盲
	// ==================================================================
	printf("\n=== 4. 自启 / 宿主劫持补盲 ===\n");

	Check("misc", "ShellServiceObjectDelayLoad → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad"), true);
	Check("misc", "Explorer\\ShellExecuteHooks → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"), true);
	Check("misc", "Browser Helper Objects（BHO 注入）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{abc}"), true);
	Check("misc", "Active Setup\\Installed Components → 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{guid}"), true);
	Check("misc", "W32Time\\TimeProviders（LSASS 注入）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\W32Time\\TimeProviders"), true);
	Check("misc", "SecurityProviders（SSP 劫持）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\SecurityProviders"), true);
	Check("misc", "AppCertDlls（内核形态）→ 高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCertDlls"), true);

	// ★ AppInit_DLLs 的 **HKCU 覆盖**（这才是 v19 那条条目的真正价值）：
	//   既有规则只写了 `...\CurrentVersion\Windows`（machine=true, user=false），
	//   **不覆盖 HKCU** —— 而 HKCU 版 AppInit 恰恰是**不需要提权**的注入点。
	//   v19 补的 `...\Windows\AppInit_DLLs`（machine+user）把它补上。
	Check("misc", "★ HKCU AppInit_DLLs → 高危（v19 补的关键盲区）",
		ReasonHas(R3ShieldCoreRules::RegistryRiskReason(
			L"\\REGISTRY\\USER\\S-1-5-21-1\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
			L"AppInit_DLLs", (ULONG)R3ShieldCore::Op::SetValueKey), "AppInit"), true);
	Check("misc", "HKLM AppInit_DLLs → 仍高危（与既有宽泛条目一致）",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"), true);

	// ==================================================================
	// 5. ★ 段边界防回归（v17 的坑：逐段比对不得退化成字符前缀）
	// ==================================================================
	//
	// 这是本轮最容易引入的静默 bug：新增条目若用了会互相包含的段名，
	// 逐段比对必须仍然精确。逐个验证"近义段"不误命中。
	printf("\n=== 5. ★ 段边界防回归 ===\n");

	Check("bound", "Print\\Monitors 不撞 Print\\MonitorsX（段恰好结束/继续）",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\MonitorsX"), false);
	Check("bound", "AppModel 不撞 AppModelX",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelX"), false);
	Check("bound", "COM3 不撞 COM30",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM30\\Catalog"), false);
	Check("bound", "Active Setup 不撞 Active Setups",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Active Setups\\Installed Components"), false);
	// ControlSet0001（多余 0）不得等价于 ControlSetNNN 之外的东西 —— 只 NNN 纯数字。
	Check("bound", "ControlSetX 非纯数字不参与等价（回归）",
		RegHigh(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSetABC\\Control\\Print\\Monitors"), false);

	// ==================================================================
	// 5b. ★★ 规则表"具体条目必须排在宽泛条目之前"（v19 审计发现）
	// ==================================================================
	//
	// ⚠️ 本组是**审计时发现的真实缺陷**，不是新功能：
	//    `SYSTEM\CurrentControlSet\Services` 覆盖整棵子树，它后面的任何
	//    `Services\Xxx\...` 条目都**永不命中** —— 判据其实能命中，但返回的是
	//    通用 reason（"系统服务/驱动"）而不是具体 reason（"防火墙配置" /
	//    "时间服务提供程序"）。用户看到的是泛化措辞，丢失了"这是哪个要害"。
	//
	//    修法：把这两个具体点**上移到宽泛 Services 条目之前**（命中第一条即返回）。
	//    本组用例把"具体 reason 胜出"钉死，防止以后又被挪到后面。
	printf("\n=== 5b. ★★ 具体 reason 必须胜过宽泛 Services 规则 ===\n");

	Check("specific", "Services\\SharedAccess → reason 是「防火墙配置」而非「系统服务/驱动」",
		ReasonHas(Reg(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\SharedAccess"), "防火墙"), true);
	Check("specific", "Services\\SharedAccess（CurrentControlSet 字面形态）→ 同样具体",
		ReasonHas(Reg(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess"), "防火墙"), true);
	Check("specific", "Services\\W32Time\\TimeProviders → reason 是「时间服务提供程序」",
		ReasonHas(Reg(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\W32Time\\TimeProviders"), "时间服务"), true);
	// 对照组：Services 下的**普通**子键仍走通用 reason（证明宽泛条目还在生效）。
	Check("specific", "Services\\SomeVendorSvc → 仍走通用「系统服务/驱动」（对照）",
		ReasonHas(Reg(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\SomeVendorSvc"), "系统服务"), true);
	Check("specific", "Services\\SomeVendorSvc 不误报成「防火墙」",
		ReasonHas(Reg(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\SomeVendorSvc"), "防火墙"), false);

	// ==================================================================
	// 6. 防回归：v19 新增不得把只读操作 / 已知放行面拉成高危
	// ==================================================================
	printf("\n=== 6. 防回归：读操作与既有豁免不变 ===\n");

	// 读类操作不算高危（IsHighRiskOp 拦在规则匹配之前）。
	Check("regress", "QueryValueKey 读 Print\\Monitors → 不判（读不拦）",
		R3ShieldCoreRules::RegistryRiskReason(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Print\\Monitors",
			L"V", (ULONG)R3ShieldCore::Op::QueryValueKey) == nullptr, true);
	Check("regress", "OpenKey 读 COM3\\Catalog → 不判（读不拦）",
		R3ShieldCoreRules::RegistryRiskReason(
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\COM3\\Catalog",
			L"V", (ULONG)R3ShieldCore::Op::OpenKey) == nullptr, true);

	// 既有规则仍生效（抽两条最有代表性的）。
	Check("regress", "既有 Run 自启项仍高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), true);
	Check("regress", "既有 IFEO 仍高危",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe"), true);
	// 全无干系的路径仍不判（防"广谱命中"回归）。
	Check("regress", "无关路径 SOFTWARE\\Vendor\\App → 不判",
		RegHigh(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor\\App\\Settings"), false);
	Check("regress", "空路径 → 不判",
		RegHigh(L""), false);
	Check("regress", "nullptr 路径 → 不判",
		RegHigh(nullptr), false);

	printf("\n%s  失败 %d\n", g_failed ? "=== 存在失败用例 ===" : "=== 全部通过 ===", g_failed);
	return g_failed;
}
