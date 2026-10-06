//
// v15_rules_ut.cpp - R3ShieldCoreRules v15 新增判据的单元测试。
//
// 覆盖「宿主劫持 / 加载器」四个子面：
//   ① 注册表全局注入键  → HostInjectionKeyRiskReason
//   ② 加载器侧加载变体  → HostHijackRiskReason(LoadLibraryEx / RegisterDllNotification)
//   ③ 远程映射注入      → HostHijackRiskReason(MapSectionRemote / QueueApcRemote)
//   ④ 凭据宿主劫持      → HostHijackRiskReason(CredentialHost)
//
// ⚠️ 每块的「存活关键」（防误报 = 防空转）：
//
//   ① 注入键 —— **键命中不算高危，值指向用户可写目录才算**。
//      AppInit_DLLs 键系统自己天天读写且默认存在；IFEO Debugger 指向
//      System32 下的调试器是正常开发行为。只有"系统以后会加载的那个东西"
//      落在用户能改的地方 —— 才是攻击者可持续利用的劫持点。
//
//   ②③④ 机制类 —— **crossProcess 是硬门槛**（远程映射/APC）。
//      本进程映射段 = 加载自己的 DLL，走的就是 NtMapViewOfSection，
//      不判必放行。凭据宿主/本地加载变体回到"路径是否用户可写"，
//      系统 DLL / 系统目录一律放行。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	const char* HostInjectionKeyRiskReason(PCWSTR keyPath, PCWSTR pathValue) noexcept;
	bool IsHighRiskHostInjectionKey(PCWSTR keyPath, PCWSTR pathValue) noexcept;
	const char* HostHijackRiskReason(ULONG hostOp, PCWSTR dllPath, bool crossProcess, bool manualMap) noexcept;
	bool IsHighRiskHostHijack(ULONG hostOp, PCWSTR dllPath, bool crossProcess, bool manualMap) noexcept;
	const char* HostInjectionKeyReason(PCWSTR keyPath) noexcept;
}

// HostHijackOp（对齐 r3shieldcore_shared.h v15）
enum
{
	HH_InjectionRegistryKey = 1,
	HH_LoadLibraryEx = 2,
	HH_RegisterDllNotification = 3,
	HH_MapSectionRemote = 4,
	HH_QueueApcRemote = 5,
	HH_CredentialHost = 6,
};

static int g_failed = 0;

static void CheckBool(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-56s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm");
}

static void CheckKey(const char* note, PCWSTR keyPath, PCWSTR value, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskHostInjectionKey(keyPath, value);
	CheckBool("key", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::HostInjectionKeyRiskReason(keyPath, value);
		if (reason) printf("        reason=%s\n", reason);
	}
}

static void CheckHost(const char* note, ULONG op, PCWSTR path, bool crossProc, bool manualMap, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskHostHijack(op, path, crossProc, manualMap);
	CheckBool("host", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::HostHijackRiskReason(op, path, crossProc, manualMap);
		if (reason) printf("        reason=%s\n", reason);
	}
}

int wmain()
{
	setlocale(LC_ALL, "");

	printf("=== 1. 注册表全局注入键（子面①，v15）===\n");
	{
		// ---- ★ 存活前提：值指向系统目录 → 放行（正常系统配置）----
		CheckKey("AppInit_DLLs 指向 System32（系统 DLL，放行）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
			L"C:\\Windows\\System32\\normal.dll", false);
		CheckKey("IFEO Debugger 指向 System32 调试器（正常开发，放行）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe",
			L"C:\\Windows\\System32\\windbg.exe", false);
		CheckKey("AppInit 值为空（只改开关，放行）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
			L"", false);
		CheckKey("Winlogon Shell 指向系统 explorer（正常，放行）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			L"explorer.exe", false);

		// ---- 值指向用户可写目录 → 高危（真劫持）----
		CheckKey("AppInit_DLLs 指向 Temp（★ 全球注入，高危）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
			L"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.dll", true);
		CheckKey("AppCertDlls 指向 AppData（每次创建进程注入，高危）",
			L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
			L"C:\\Users\\victim\\AppData\\Roaming\\bad.dll", true);
		CheckKey("IFEO Debugger 指向用户目录（映像劫持，高危）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
			L"C:\\Users\\Public\\hijack.exe", true);
		CheckKey("LSA Security Packages 指向 ProgramData（LSASS 注入，高危）",
			L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
			L"C:\\ProgramData\\evil.dll", true);
		CheckKey("Winlogon Notify 指向 Temp（登录宿主，高危）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
			L"C:\\Windows\\Temp\\notify.dll", true);
		CheckKey("ShellServiceObjectDelayLoad 指向用户目录（高）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
			L"C:\\Users\\victim\\Downloads\\shell.dll", true);

		// ---- ★ 用户级（HKCU）注入键 —— 不需要提权，是更常见的注入点 ----
		//
		// ⚠️ 这是实机验证时发现的漏洞：AppInit 表最初只列了 machine 版，
		//    HKCU 写被 NormalizeKey 标成 user=true 后整条被跳过。
		//    回归用例就是它 —— 别再漏。
		CheckKey("★ HKCU AppInit_DLLs 指向 Temp（无需提权即可注入，高危）",
			L"\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
			L"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.dll", true);
		CheckKey("★ HKCU AppInit_DLLs 指向 System32（放行）",
			L"\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
			L"C:\\Windows\\System32\\normal.dll", false);
		CheckKey("★ HKCU IFEO Debugger 指向用户目录（高危）",
			L"\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
			L"C:\\Users\\victim\\AppData\\hijack.exe", true);
		CheckKey("★ HKCU Winlogon Shell 指向用户目录（高危）",
			L"\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			L"C:\\Users\\victim\\AppData\\Local\\shell.exe", true);
		CheckKey("★ HKCU 下的纯机器级键（LSA，不该被 user 命中）",
			L"\\REGISTRY\\USER\\S-1-5-21-111-222-333-1001\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
			L"C:\\Users\\victim\\AppData\\evil.dll", false);

		// ---- 键不在注入表里 → 无论值如何都放行 ----
		CheckKey("普通 Run 键（不归本判据）",
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
			L"C:\\Users\\victim\\AppData\\evil.exe", false);

		// ---- HostInjectionKeyReason 只判键（预筛）----
		printf("--- 键预筛（HostInjectionKeyReason，不看值）---\n");
		{
			const char* r1 = R3ShieldCoreRules::HostInjectionKeyReason(
				L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows");
			CheckBool("keypre", "AppInit 键命中预筛", r1 != nullptr, true);
			const char* r2 = R3ShieldCoreRules::HostInjectionKeyReason(
				L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
			CheckBool("keypre", "Run 键不命中预筛", r2 != nullptr, false);
		}
	}

	printf("\n=== 2. 加载器侧加载变体（子面②，v15）===\n");
	{
		// ---- 系统目录 → 放行 ----
		CheckHost("LoadLibraryEx 系统 DLL（放行）", HH_LoadLibraryEx,
			L"C:\\Windows\\System32\\shell32.dll", false, false, false);
		CheckHost("加载通知注册 系统 DLL（放行）", HH_RegisterDllNotification,
			L"C:\\Program Files\\App\\plugin.dll", false, false, false);

		// ---- 用户可写目录 → 高危（白加黑）----
		CheckHost("LoadLibraryEx 从 Temp（白加黑，高危）", HH_LoadLibraryEx,
			L"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.dll", false, false, true);
		CheckHost("加载通知注册 + 用户目录 DLL（劫持加载决策，高危）", HH_RegisterDllNotification,
			L"C:\\Users\\victim\\Downloads\\bad.dll", false, false, true);

		// ---- 手工映射 → 无论路径都高危 ----
		CheckHost("手工映射系统 DLL（映射异常，高危）", HH_LoadLibraryEx,
			L"C:\\Windows\\System32\\ntdll.dll", false, true, true);
	}

	printf("\n=== 3. 远程映射注入（子面③，v15）===\n");
	{
		// ---- ★ 存活前提：本进程映射 → 放行（加载自己的 DLL 走这条）----
		CheckHost("本进程 映射段（加载自己 DLL，必须放行）", HH_MapSectionRemote,
			L"C:\\Windows\\System32\\apphelp.dll", false, false, false);
		CheckHost("本进程 投 APC（正常，必须放行）", HH_QueueApcRemote,
			nullptr, false, false, false);

		// ---- 跨进程映射 → 高危（不看路径：机制即注入）----
		CheckHost("跨进程 映射段（反射式注入，高危）", HH_MapSectionRemote,
			nullptr, true, false, true);
		CheckHost("跨进程 映射段（带系统路径也高危 —— 机制即注入）", HH_MapSectionRemote,
			L"C:\\Windows\\System32\\x.dll", true, false, true);
		CheckHost("跨进程 投 APC（APC 注入，高危）", HH_QueueApcRemote,
			nullptr, true, false, true);
	}

	printf("\n=== 4. 凭据宿主劫持（子面④，v15）===\n");
	{
		// ---- 系统凭据 DLL → 放行（kerberos / msv1_0 是正常配置）----
		CheckHost("Security Package 指向 System32（正常，放行）", HH_CredentialHost,
			L"C:\\Windows\\System32\\kerberos.dll", false, false, false);
		CheckHost("Credential Provider 指向 System32（正常，放行）", HH_CredentialHost,
			L"C:\\Windows\\System32\\VaultCredProvider.dll", false, false, false);

		// ---- 用户可写 → 高危 ----
		CheckHost("Security Package 指向 AppData（LSASS 劫持，高危）", HH_CredentialHost,
			L"C:\\Users\\victim\\AppData\\Local\\cred.dll", false, false, true);
		CheckHost("Credential Provider 指向 Temp（登录宿主，高危）", HH_CredentialHost,
			L"C:\\Windows\\Temp\\fakeLogin.dll", false, false, true);
	}

	printf("\n=== 5. Op 隔离（防串档）===\n");
	{
		// 注入键 op 不在 HostHijackRiskReason 里判（需 keyPath，签名不同）→ 一律 nullptr
		CheckHost("InjectionRegistryKey op（走另一个函数，本判据不接）", HH_InjectionRegistryKey,
			L"C:\\Users\\victim\\evil.dll", false, false, false);
		// 未知 op
		CheckHost("op=0（未设置）", 0, L"C:\\Users\\victim\\evil.dll", false, false, false);
		CheckHost("op=99（未知）", 99, L"C:\\Users\\victim\\evil.dll", false, false, false);
	}

	printf("\n");
	if (g_failed == 0) {
		printf("=== 全部通过  失败 0 ===\n");
		return 0;
	}
	printf("=== 失败 %d 例 ===\n", g_failed);
	return 1;
}
