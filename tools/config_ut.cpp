#include <r3shieldcore_config.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace
{
	bool Check(const char* name, bool condition)
	{
		std::cout << (condition ? "PASS " : "FAIL ") << name << '\n';
		return condition;
	}

	// ★ 铁律 173：大聚合体的**花括号赋值**（`policy = {};`）会让 MSVC 抛
	//   C1001「内部编译器错误」—— 报错位置是"第 N 个"，看着像语法错，
	//   实际是编译器自己崩了，**闸门整条编不出来**（表现出来只是"没输出"）。
	//   本文件里这种赋值原本 25 处；v70 加到第 26 处时 UT 直接编不过。
	//   修法 = 换成 ZeroMemory（`Policy` 是 POD，语义完全一样），
	//   编译器不再为每次赋值造一个临时聚合体。
	void ResetPolicy(R3ShieldCore::Policy& p)
	{
		ZeroMemory(&p, sizeof(p));
	}

	//
	// ★ v91：单测必须**钉住文件**，不能走 `R3ShieldCoreConfig::Load`。
	//
	// `Load` 会按 `ResolveConfigPath` **优先**读
	//   `%ProgramData%\R3 Shield Core\r3shieldcore.ini` —— 那是运行期正确的语义，
	// 但对单测是灾难：开发机上一旦有那份配置（本机注入白名单是开发机标配），
	// 每个用例读到的都是**它**而不是用例自己写的临时 ini ⇒ 53 个断言集体假红
	// （实测：config_ut 从 0 失败变成大片 FAIL），而且**看着像解析器坏了**。
	// 这正是铁律 255 那类"判据被本机状态搬家"。所以这里统一走钉文件的入口。
	//
	void LoadPinned(R3ShieldCore::Policy& p, const std::filesystem::path& dir)
	{
		R3ShieldCoreConfig::LoadFromFile(p, dir / L"r3shieldcore.ini", dir);
	}

	R3ShieldCoreConfig::EngineSettings LoadEngineSettingsPinned(const std::filesystem::path& dir)
	{
		return R3ShieldCoreConfig::LoadEngineSettingsFromFile(dir / L"r3shieldcore.ini");
	}
}

int main()
{
	const std::filesystem::path dir = std::filesystem::temp_directory_path()
		/ (L"r3shieldcore-config-ut-" + std::to_wstring(GetCurrentProcessId()));
	std::error_code ec;
	std::filesystem::remove_all(dir, ec);
	std::filesystem::create_directories(dir, ec);
	if (ec) {
		std::cerr << "FAIL create temp directory: " << ec.message() << '\n';
		return 1;
	}

	int failed = 0;
	R3ShieldCore::Policy policy = {};
	LoadPinned(policy, dir);
	failed += !Check("missing config keeps file hook disabled",
		(policy.Flags & R3ShieldCore::FlagHookFile) == 0);
	failed += !Check("missing config keeps safe LOG defaults",
		policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Log));
	// v39：裸盘监控默认**开**，且独立于 hook_file（发布默认 hook_file=0 时也要生效）。
	failed += !Check("missing config keeps raw-disk hook ENABLED (v39 default on)",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) != 0);
	failed += !Check("missing config keeps terminate-contain enabled",
		(policy.Flags2 & R3ShieldCore::FlagHookTerminateContain) != 0);
	// v42：瘦注入默认**开** —— 不注入 explorer/svchost 就拿不到同步注入路。
	failed += !Check("missing config keeps thin-inject ENABLED (v42 default on)",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	// ---- v42：inject_shell_thin 开关 ----
	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=0\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("inject_shell_thin=0 disables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) == 0);
	failed += !Check("inject_shell_thin=0 does not disturb hook_raw_disk",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=1\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("inject_shell_thin=1 enables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	{
		// 行内注释必须被切掉（铁律 33：解析器只认行首注释会静默吞值）
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=1   # 瘦注入\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("inject_shell_thin inline comment stripped -> 1",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	{
		// 认不出的值按 IsTrue 的既有语义处理：非真值即关。
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=off\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("inject_shell_thin=off disables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) == 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=on\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("inject_shell_thin=on enables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_raw_disk=1\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	// ★ 交叉检查：改 hook_raw_disk 不能顺手把瘦注入关掉（两条独立的位）
	failed += !Check("hook_raw_disk=1 keeps thin-inject untouched (independent bits)",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	// ---- v39：hook_raw_disk 开关 ----
	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_raw_disk=0\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("hook_raw_disk=0 disables raw-disk hook",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) == 0);
	failed += !Check("hook_raw_disk=0 does not disturb hook_file flag",
		(policy.Flags & R3ShieldCore::FlagHookFile) == 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_raw_disk=1\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("hook_raw_disk=1 enables raw-disk hook",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_file=1\n";
	}
	LoadPinned(policy, dir);
	failed += !Check("hook_file=1 enables file hook",
		(policy.Flags & R3ShieldCore::FlagHookFile) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_file=0\n";
	}
	LoadPinned(policy, dir);
	failed += !Check("hook_file=0 disables file hook",
		(policy.Flags & R3ShieldCore::FlagHookFile) == 0);

	// ---- 行内注释（随包 ini 每个键后面都跟一小段说明）----
	// 解析器只在 `#`/`;` **前面是空白**时才当注释切，所以：
	//   `mode=block   # 说明`  -> block（注释被切掉）
	//   `exclude=C:\a#b`       -> 值原样保留（# 前面没空白，不是注释）
	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "mode=block                  # 主动防御：只拦高危\n";
		ini << "hook_file=1                 # 打开文件监控\n";
		ini << "exclude=C:\\a#b\n";
		ini << "exclude=D:\\x  ; 行内分号注释\n";
	}
	ResetPolicy(policy);
	LoadPinned(policy, dir);
	failed += !Check("inline comment: mode=block # ... parses as block",
		policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Block));
	failed += !Check("inline comment: hook_file=1 # ... enables file hook",
		(policy.Flags & R3ShieldCore::FlagHookFile) != 0);
	failed += !Check("inline comment: '#' without leading space stays in value",
		policy.ExcludePathCount == 2 &&
		std::wstring(policy.ExcludePaths[0]) == L"C:\\a#b");
	failed += !Check("inline comment: ';' with leading space is stripped",
		policy.ExcludePathCount == 2 &&
		std::wstring(policy.ExcludePaths[1]) == L"D:\\x");

	// ---- v39：窗口反制级别 neutralize_overlay = 0 / 1 / 2 ----
	//  0 = 关；1 = 开且**不问**；2 = 开且**弹窗询问**（默认）。
	//  ⚠️ 旧版是 bool（0/1），`1` 的语义必须保持"开且不问"。
	{
		// 缺文件 → 取内置默认 2（询问）。
		// ④⑤ 会结束目标进程，默认必须"先问"，不能静默杀正常全屏程序。
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
		failed += !Check("neutralize_overlay: missing config defaults to 2 (ask)",
			e.NeutralizeOverlayLevel == 2 && e.NeutralizeOverlayEnabled());

		struct Case { const char* text; ULONG expect; const char* what; };
		const Case cases[] = {
			{ "neutralize_overlay=0\n",     0, "0 -> off" },
			{ "neutralize_overlay=1\n",     1, "1 -> on, no ask (旧 bool 语义)" },
			{ "neutralize_overlay=2\n",     2, "2 -> on, ask" },
			{ "neutralize_overlay=false\n", 0, "false -> off" },
			{ "neutralize_overlay=off\n",   0, "off -> off" },
			{ "neutralize_overlay=true\n",  1, "true -> on, no ask" },
			{ "neutralize_overlay=on\n",    1, "on -> on, no ask" },
			// 认不出的值必须**保持默认 2**（宁可多问，也别因拼错变成静默杀进程）
			{ "neutralize_overlay=bogus\n", 2, "unrecognized -> keeps default 2" },
			{ "neutralize_overlay=3\n",     2, "out-of-range 3 -> keeps default 2" },
			// 行内注释（随包 ini 每个键后面都跟说明）—— 铁律 33
			{ "neutralize_overlay=1   # 不问直接执行\n", 1, "inline comment stripped -> 1" },
		};
		for (const Case& c : cases) {
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << c.text;
			ini.close();
			R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
			failed += !Check((std::string("neutralize_overlay: ") + c.what).c_str(),
				e.NeutralizeOverlayLevel == c.expect);
		}
	}

	// ---- v41：注入扫描间隔 inject_interval_ms（盲区大小）----
	{
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
		failed += !Check("inject_interval_ms: missing config defaults to 10 (短盲区)",
			e.InjectionIntervalMs == 10);

		struct Case { const char* text; ULONG expect; const char* what; };
		const Case cases[] = {
			{ "inject_interval_ms=10\n",   10, "10 -> 10" },
			{ "inject_interval_ms=1\n",     1, "1 -> 1（最小）" },
			{ "inject_interval_ms=1000\n", 1000, "1000 -> 1000（最大）" },
			// 越界 / 认不出必须**保持默认**，不能让一个坏值把盲区放到最大
			{ "inject_interval_ms=0\n",    10, "0 越界 -> 保持默认 10" },
			{ "inject_interval_ms=5000\n", 10, "5000 越界 -> 保持默认 10" },
			{ "inject_interval_ms=-5\n",   10, "负数 -> 保持默认 10" },
			{ "inject_interval_ms=abc\n",  10, "非数字 -> 保持默认 10" },
			{ "inject_interval_ms=\n",     10, "空值 -> 保持默认 10" },
			// 行内注释（随包 ini 每个键后面都跟说明）—— 铁律 33
			{ "inject_interval_ms=25   # 说明\n", 25, "行内注释被切 -> 25" },
		};
		for (const Case& c : cases) {
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << c.text;
			ini.close();
			R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
			failed += !Check((std::string("inject_interval_ms: ") + c.what).c_str(),
				e.InjectionIntervalMs == c.expect);
		}
	}

	// ---- v60：protect_reg= 必须真的进到 policy.ProtectRegPaths ----
	//
	// 为什么补这一条：2026-10-05 真机复盘发现 `protect_reg` 在**规则层**
	// 匹配不上（相对写法 vs 完整键路径，已由 tools/protect_reg_ut.cpp 钉住）。
	// 但"规则层能命中"只是半条链 —— 还得证明 ini 里的 `protect_reg=`
	// **真的被解析进 Policy**。否则修了匹配、配置照样读不进来，
	// 症状一模一样（静默失效）。这条断言把 ini → Policy 这一段钉死。
	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "protect_reg=SOFTWARE\\MyCompany\\Critical\n"
			<< "protect_reg=Control Panel\\Mouse\n"
			<< "# protect_reg=Software\\Commented\\Out\n"
			<< "protect_reg=  \n"                       // 空值必须被忽略
			<< "protect_reg=Software\\Trailing   # 行内注释\n";
		ini.close();

		ResetPolicy(policy);
		LoadPinned(policy, dir);

		failed += !Check("protect_reg: 3 条有效前缀被读进来（注释/空值被跳过）",
			policy.ProtectRegCount == 3);
		failed += !Check("protect_reg: 第 1 条内容正确",
			policy.ProtectRegCount >= 1
			&& std::wstring(policy.ProtectRegPaths[0]) == L"SOFTWARE\\MyCompany\\Critical");
		failed += !Check("protect_reg: 第 2 条内容正确（带空格的值）",
			policy.ProtectRegCount >= 2
			&& std::wstring(policy.ProtectRegPaths[1]) == L"Control Panel\\Mouse");
		failed += !Check("protect_reg: 行内注释被切掉（铁律 33）",
			policy.ProtectRegCount >= 3
			&& std::wstring(policy.ProtectRegPaths[2]) == L"Software\\Trailing");
	}

	// ---- v61：高危进程提示 high_risk_process_alert / high_risk_process_scan_ms ----
	//
	// 为什么补这一条：v60b 的教训（H.10 #4「半条链不算修好」）——
	// `high_risk_process_alert` 的**级别语义**（0/1/2，且 `1` ≠ 布尔真）
	// 与 `neutralize_overlay` 完全同源，这类"不是 bool 的开关"最容易
	// 被后来的人顺手改成 IsTrue，然后 `1` 的语义就悄悄退化了。
	// 同时钉住"认不出的值**保持默认 2**"——宁可多说一句，也不要因为
	// 一个拼错的值把功能**静默关掉**（那正是 v60 那类 bug 的形态）。
	{
		// 缺文件 → 内置默认：级别 2（记录 + 界面），间隔 1000ms。
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
		failed += !Check("high_risk_process_alert: missing config defaults to 2",
			e.HighRiskProcessAlert == 2);
		failed += !Check("high_risk_process_alert: default 2 means enabled",
			e.HighRiskProcessAlertEnabled());
		failed += !Check("high_risk_process_scan_ms: missing config defaults to 1000",
			e.HighRiskProcessScanMs == 1000);

		struct Case { const char* text; ULONG expect; const char* what; };
		const Case alertCases[] = {
			{ "high_risk_process_alert=0\n",     0, "0 -> off" },
			{ "high_risk_process_alert=1\n",     1, "1 -> on, log only (不是布尔真！)" },
			{ "high_risk_process_alert=2\n",     2, "2 -> on, log + UI" },
			{ "high_risk_process_alert=false\n", 0, "false -> off" },
			{ "high_risk_process_alert=off\n",   0, "off -> off" },
			{ "high_risk_process_alert=on\n",    2, "on -> 2（不是 1：布尔真=最高级别）" },
			{ "high_risk_process_alert=true\n",  2, "true -> 2" },
			// 认不出的值必须**保持默认 2**（宁可多报，也别因拼错静默关掉）
			{ "high_risk_process_alert=bogus\n", 2, "unrecognized -> keeps default 2" },
			{ "high_risk_process_alert=3\n",     2, "out-of-range 3 -> keeps default 2" },
			{ "high_risk_process_alert=-1\n",    2, "负数 -> keeps default 2" },
			{ "high_risk_process_alert=\n",      2, "空值 -> keeps default 2" },
			// 行内注释（随包 ini 每个键后面都跟说明）—— 铁律 33
			{ "high_risk_process_alert=1   # 仅记录\n", 1, "inline comment stripped -> 1" },
		};
		for (const Case& c : alertCases) {
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << c.text;
			ini.close();
			R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
			failed += !Check((std::string("high_risk_process_alert: ") + c.what).c_str(),
				e.HighRiskProcessAlert == c.expect);
		}

		const Case scanCases[] = {
			{ "high_risk_process_scan_ms=200\n",   200, "200 -> 200（最小）" },
			{ "high_risk_process_scan_ms=1000\n", 1000, "1000 -> 1000" },
			{ "high_risk_process_scan_ms=60000\n", 60000, "60000 -> 60000（最大）" },
			// 越界 / 认不出必须**保持默认**，不能让一个坏值把扫描停掉或打满 CPU
			{ "high_risk_process_scan_ms=199\n",   1000, "199 越界 -> 保持默认 1000" },
			{ "high_risk_process_scan_ms=0\n",     1000, "0 越界 -> 保持默认 1000" },
			{ "high_risk_process_scan_ms=60001\n", 1000, "60001 越界 -> 保持默认 1000" },
			{ "high_risk_process_scan_ms=-5\n",    1000, "负数 -> 保持默认 1000" },
			{ "high_risk_process_scan_ms=abc\n",   1000, "非数字 -> 保持默认 1000" },
			{ "high_risk_process_scan_ms=\n",      1000, "空值 -> 保持默认 1000" },
			{ "high_risk_process_scan_ms=2500   # 说明\n", 2500, "行内注释被切 -> 2500" },
		};
		for (const Case& c : scanCases) {
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << c.text;
			ini.close();
			R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
			failed += !Check((std::string("high_risk_process_scan_ms: ") + c.what).c_str(),
				e.HighRiskProcessScanMs == c.expect);
		}

		// ★ 交叉检查：两个键必须**各自独立** —— 关掉提示不应顺手把间隔
		//   改回默认，反之亦然（同 v42 的 inject_shell_thin × hook_raw_disk）。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "high_risk_process_alert=0\n";
			ini << "high_risk_process_scan_ms=5000\n";
			ini.close();
			R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
			failed += !Check("alert=0 不影响 scan_ms（两个键独立）",
				e.HighRiskProcessAlert == 0 && e.HighRiskProcessScanMs == 5000);
			failed += !Check("alert=0 时 HighRiskProcessAlertEnabled() 为 false",
				!e.HighRiskProcessAlertEnabled());
		}
	}

	// ---- v62/v63：ARK 页 ark_enabled / ark_scan_ms / ark_refresh_ms ----
	//
	// 为什么补这一节：v62 上线时**漏了** —— `verify_dist_ini` 只验"随包 ini 的
	// 具体取值"，验不到"解析器遇到坏值会怎样"。而这三个键全是
	// **写错一个字母就静默失效**的形态：
	//   · `ark_enabled` 是 bool，但**认不出的值必须保持默认 true**。
	//     若图省事写 `IsTrue()`（认不出→false），一个拼错的值就把 ARK
	//     静默关掉 —— 症状只是"列表空的"，没人会想到是 ini。
	//   · 两个间隔越界 / 非数字必须**保持默认**：0 会让引擎每轮都扫（打满 CPU），
	//     界面侧则是空转。
	//   · `ark_scan_ms` 与 `ark_refresh_ms` 必须是**两个独立的键**（含义不同：
	//     数据新鲜度 vs 显示新鲜度），写反 / 接错的症状是"改了没反应"。
	{
		// 缺文件 → 内置默认。
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		R3ShieldCoreConfig::EngineSettings e = LoadEngineSettingsPinned(dir);
		failed += !Check("ark_enabled: missing config defaults to true（随包默认开）",
			e.ArkEnabled);
		failed += !Check("ark_scan_ms: missing config defaults to 2000",
			e.ArkScanMs == 2000);
		failed += !Check("ark_refresh_ms: missing config defaults to 1000",
			e.ArkRefreshMs == 1000);

		// ark_enabled：认得出是假 ⇒ false；认不出 ⇒ **保持默认 true**
		{
			struct BoolCase { const char* text; bool expect; const char* what; };
			const BoolCase cases[] = {
				{ "ark_enabled=0\n",     false, "0 -> off" },
				{ "ark_enabled=false\n", false, "false -> off" },
				{ "ark_enabled=no\n",    false, "no -> off" },
				{ "ark_enabled=off\n",   false, "off -> off" },
				{ "ark_enabled=1\n",     true,  "1 -> on" },
				{ "ark_enabled=true\n",  true,  "true -> on" },
				{ "ark_enabled=yes\n",   true,  "yes -> on" },
				{ "ark_enabled=on\n",    true,  "on -> on" },
				// ★ 关键：拼错的值**不能**把功能静默关掉
				{ "ark_enabled=enable\n", true, "拼错(enable) -> 保持默认 true（不能静默关掉）" },
				{ "ark_enabled=2\n",     true,  "认不出(2) -> 保持默认 true" },
				{ "ark_enabled=\n",      true,  "空值 -> 保持默认 true" },
				{ "ark_enabled=1   # 说明\n", true, "行内注释被切 -> true" },
			};
			for (const BoolCase& c : cases) {
				std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
				ini << c.text;
				ini.close();
				R3ShieldCoreConfig::EngineSettings e2 = LoadEngineSettingsPinned(dir);
				failed += !Check((std::string("ark_enabled: ") + c.what).c_str(),
					e2.ArkEnabled == c.expect);
			}
		}

		struct ArkCase { const char* text; ULONG expect; const char* what; };

		const ArkCase scanCases[] = {
			{ "ark_scan_ms=500\n",   500,   "500 -> 500（最小）" },
			{ "ark_scan_ms=2000\n",  2000,  "2000 -> 2000" },
			{ "ark_scan_ms=60000\n", 60000, "60000 -> 60000（最大）" },
			{ "ark_scan_ms=499\n",   2000,  "499 越界 -> 保持默认 2000" },
			{ "ark_scan_ms=0\n",     2000,  "0 越界 -> 保持默认 2000（否则每轮都扫）" },
			{ "ark_scan_ms=60001\n", 2000,  "60001 越界 -> 保持默认 2000" },
			{ "ark_scan_ms=abc\n",   2000,  "非数字 -> 保持默认 2000" },
			{ "ark_scan_ms=\n",      2000,  "空值 -> 保持默认 2000" },
		};
		for (const ArkCase& c : scanCases) {
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << c.text;
			ini.close();
			R3ShieldCoreConfig::EngineSettings e2 = LoadEngineSettingsPinned(dir);
			failed += !Check((std::string("ark_scan_ms: ") + c.what).c_str(),
				e2.ArkScanMs == c.expect);
		}

		const ArkCase refreshCases[] = {
			{ "ark_refresh_ms=200\n",   200,   "200 -> 200（最小）" },
			{ "ark_refresh_ms=1000\n",  1000,  "1000 -> 1000" },
			{ "ark_refresh_ms=60000\n", 60000, "60000 -> 60000（最大）" },
			{ "ark_refresh_ms=199\n",   1000,  "199 越界 -> 保持默认 1000" },
			{ "ark_refresh_ms=0\n",     1000,  "0 越界 -> 保持默认 1000（否则界面空转）" },
			{ "ark_refresh_ms=60001\n", 1000,  "60001 越界 -> 保持默认 1000" },
			{ "ark_refresh_ms=abc\n",   1000,  "非数字 -> 保持默认 1000" },
			{ "ark_refresh_ms=\n",      1000,  "空值 -> 保持默认 1000" },
			{ "ark_refresh_ms=2500   # 说明\n", 2500, "行内注释被切 -> 2500" },
		};
		for (const ArkCase& c : refreshCases) {
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << c.text;
			ini.close();
			R3ShieldCoreConfig::EngineSettings e2 = LoadEngineSettingsPinned(dir);
			failed += !Check((std::string("ark_refresh_ms: ") + c.what).c_str(),
				e2.ArkRefreshMs == c.expect);
		}

		// ★ 交叉检查：三个键必须**各自独立**。
		//   特意把 scan 与 refresh 设成**不同**的值 —— 如果哪天有人把
		//   `ark_refresh_ms` 的解析错接到 `ark_scan_ms` 上（或反之），
		//   或者两个字段写反，这一条会立刻变红。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "ark_enabled=0\n";
			ini << "ark_scan_ms=3000\n";
			ini << "ark_refresh_ms=750\n";
			ini.close();
			R3ShieldCoreConfig::EngineSettings e2 = LoadEngineSettingsPinned(dir);
			failed += !Check("ark 三键各自独立（0 / 3000 / 750 互不影响）",
				!e2.ArkEnabled && e2.ArkScanMs == 3000 && e2.ArkRefreshMs == 750);
		}
	}

	// ---- v69：限定注入范围 test_inject_only= + mode=test ----
	//
	// 为什么补这一节：v69 把测试模式从**命令行**（`--test-inject-only=`）改成
	// **配置驱动**（`mode=test` + `test_inject_only=`）。改动集中在两处：
	//   ① `r3shieldcore_config.cpp` 的解析（本文件钉住）；
	//   ② `functions.cpp` 的注入决策（`MatchesTestInjectList`，需要引擎才能跑，
	//      由 tools/spoof_e2e.sh 的端到端矩阵负责）。
	// ②跑不起来（要提权、要注入）⇒ ①必须在这里钉死，否则"配置改了但没生效"
	// 和"决策写错了"两种故障长得一模一样（铁律 100：没看见 / 没规则 / 判据错
	// 要分得开）。
	//
	// ★ 本节还钉住一条**容易在重构中被弄丢**的设计：**注入范围与拦截行为解耦**
	//   —— `test_inject_only=` 与 `mode=` **无关**，只要名单非空就生效。
	//   为什么必须解耦：spoof（截屏替换）只在"本应拒绝"时才生效，而
	//   `mode=test` 的决策行为 = `log`（全部放行）⇒ 若白名单只认 `mode=test`，
	//   那就永远验证不到替换路径（为验证而加的模式，恰好让被验证的功能不触发）。
	{
		// ---- 缺文件：默认**不**限定注入范围，也**不**带 FlagTestMode ----
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		ResetPolicy(policy);
		LoadPinned(policy, dir);
		failed += !Check("test_inject_only: missing config -> count 0（默认全局注入）",
			policy.TestInjectCount == 0);
		failed += !Check("test_inject_only: missing config -> FlagTestMode 关",
			(policy.Flags2 & R3ShieldCore::FlagTestMode) == 0);

		// ---- mode=test ⇒ Mode::Log + FlagTestMode ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "mode=test\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("mode=test -> Mode 落到 Log（不新增 Mode 枚举值）",
				policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Log));
			failed += !Check("mode=test -> FlagTestMode 置位（引擎据此要求名单非空）",
				(policy.Flags2 & R3ShieldCore::FlagTestMode) != 0);
			// ★ fail-closed 的**触发条件**本身也要钉住：写了 test 却没给名单。
			failed += !Check("mode=test 且名单为空 -> 计数 0（引擎据此拒绝启动）",
				policy.TestInjectCount == 0);
		}

		// ---- mode= 是**权威**的：后面再写一行 mode=block 必须清掉 FlagTestMode ----
		//   否则会留下"最后一行是 block，但引擎仍要求白名单非空"的半开状态，
		//   而且**不可见**（铁律 97）。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "mode=test\n";
			ini << "mode=block\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("mode=block 覆盖 mode=test -> Mode 为 Block",
				policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Block));
			failed += !Check("mode=block 覆盖 mode=test -> FlagTestMode 被清掉（mode= 权威）",
				(policy.Flags2 & R3ShieldCore::FlagTestMode) == 0);
		}

		// ---- ★ 解耦：名单**与 mode= 无关**（block 下也照样读进来）----
		//   这是端到端三格矩阵能成立的前提（A/B 格是 mode=block）。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "mode=block\n";
			ini << "test_inject_only=probe.exe\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("解耦：mode=block + 名单 -> 名单照样被读进来（count 1）",
				policy.TestInjectCount == 1);
			failed += !Check("解耦：mode=block 不置 FlagTestMode",
				(policy.Flags2 & R3ShieldCore::FlagTestMode) == 0);
			failed += !Check("解耦：第 1 条内容正确",
				policy.TestInjectCount >= 1
				&& std::wstring(policy.TestInjectPaths[0]) == L"probe.exe");
		}

		// ---- 可重复 / 逗号分隔 / 空值 / 行内注释 / 路径形式 ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "mode=test\n";
			ini << "test_inject_only=a.exe\n";                       // 可重复
			ini << "test_inject_only=b.exe, c.exe\n";                // 一行逗号分隔 + 空格
			ini << "test_inject_only=\n";                            // 空值必须被忽略
			ini << "test_inject_only=   \n";                         // 纯空白必须被忽略
			ini << "test_inject_only=D:\\dev\\my target.exe   # 说明\n"; // 路径 + 行内注释
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("test_inject_only: 4 条有效（空值/纯空白被跳过）",
				policy.TestInjectCount == 4);
			failed += !Check("test_inject_only: 第 1 条 = a.exe",
				policy.TestInjectCount >= 1
				&& std::wstring(policy.TestInjectPaths[0]) == L"a.exe");
			failed += !Check("test_inject_only: 逗号分隔被切开 -> 第 2 条 = b.exe",
				policy.TestInjectCount >= 2
				&& std::wstring(policy.TestInjectPaths[1]) == L"b.exe");
			failed += !Check("test_inject_only: 逗号后的空格被去掉 -> 第 3 条 = c.exe",
				policy.TestInjectCount >= 3
				&& std::wstring(policy.TestInjectPaths[2]) == L"c.exe");
			failed += !Check("test_inject_only: 行内注释被切、路径原样保留",
				policy.TestInjectCount >= 4
				&& std::wstring(policy.TestInjectPaths[3]) == L"D:\\dev\\my target.exe");
		}

		// ---- 上限：超出的必须被**丢弃**，绝不能越界写 ----
		//   ⚠️ "静默丢弃"本身可接受（横幅会打实际生效条数），但**越界**不行。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "mode=test\n";
			for (int i = 0; i < 24; ++i) {
				ini << "test_inject_only=p" << i << ".exe\n";
			}
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("test_inject_only: 超过上限被截断到 MaxTestInjectPaths（不越界）",
				policy.TestInjectCount == R3ShieldCore::MaxTestInjectPaths);
			failed += !Check("test_inject_only: 截断后最后一条是第 15 个（顺序不乱）",
				policy.TestInjectCount >= R3ShieldCore::MaxTestInjectPaths
				&& std::wstring(policy.TestInjectPaths[R3ShieldCore::MaxTestInjectPaths - 1]) == L"p15.exe");
		}

		// ---- ★ 交叉检查：白名单与黑名单是**两个独立字段** ----
		//   写错一个（把 never_inject 接到 TestInjectPaths 上）会表现为
		//   "配了白名单结果全局都不注入了" —— 极端后果，必须钉住。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "mode=test\n";
			ini << "test_inject_only=only.exe\n";
			ini << "never_inject=D:\\never\\blocked.exe\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("白名单/黑名单各自独立：count 各为 1",
				policy.TestInjectCount == 1 && policy.NeverInjectCount == 1);
			failed += !Check("白名单/黑名单内容没串（白名单 = only.exe）",
				policy.TestInjectCount >= 1
				&& std::wstring(policy.TestInjectPaths[0]) == L"only.exe");
			failed += !Check("白名单/黑名单内容没串（黑名单 = D:\\never\\blocked.exe）",
				policy.NeverInjectCount >= 1
				&& std::wstring(policy.NeverInjectPaths[0]) == L"D:\\never\\blocked.exe");
		}
	}

	// ---- v70：剪贴板替换 spoof_clipboard= ----
	//
	// 为什么补这一节：v70 把「回传数据替换」从**屏幕**扩到**剪贴板**。改动分两层：
	//   ① `r3shieldcore_config.cpp` 的解析（本文件钉住）；
	//   ② `clipboard_guard.cpp` 的决策 + 伪造（需要注入才能跑 ⇒ 由
	//      `tools/spoof_clipboard_probe.cpp` 的机制探针 + 端到端夹具负责）。
	//
	// ★ 本节重点钉住**两条容易在重构里被弄丢的性质**：
	//   · 默认**关**（这是"主动欺骗"能力，默认配置行为必须与旧版一致）；
	//   · 与 `spoof_screen` **是两个独立的位**（配错一个会表现为
	//     "开了剪贴板替换结果截屏也被替换了" —— 极端后果，必须钉住）。
	{
		// ---- 缺文件：默认关 ----
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		ResetPolicy(policy);
		LoadPinned(policy, dir);
		failed += !Check("spoof_clipboard: missing config -> 默认关",
			(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);

		// ---- 开 / 关 ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_clipboard=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_clipboard=1 -> 置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_clipboard=0\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_clipboard=0 -> 不置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);
		}
		{
			// on/off 别名 + 最后一行权威
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_clipboard=on\n";
			ini << "spoof_clipboard=off\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_clipboard: on/off 别名可用且最后一行权威",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_clipboard=1 # 打开剪贴板替换\n";   // 行内注释
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_clipboard: 行内注释被切掉后仍为 1",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0);
		}

		// ---- ★ 交叉检查：两个 spoof 位**互不干扰**（双向）----
		//   单向断言只能证明"没被清掉"，证明不了"没被点亮"。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 spoof_screen -> 剪贴板替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);
			failed += !Check("交叉：只开 spoof_screen -> 截屏替换确实开了",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_clipboard=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 spoof_clipboard -> 截屏替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) == 0);
			failed += !Check("交叉：只开 spoof_clipboard -> 剪贴板替换确实开了",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：两个都开 -> 两个位都亮",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0);
		}

		// ---- ★ 位值不能撞：两个常量必须不同（防手滑写成同一个 0x 值）----
		failed += !Check("FlagSpoofScreen 与 FlagSpoofClipboard 不是同一位",
			R3ShieldCore::FlagSpoofScreen != R3ShieldCore::FlagSpoofClipboard);
	}

	// ---- v71：注册表值替换 spoof_reg= ----
	//
	// 为什么补这一节：v71 把「回传数据替换」从**屏幕 / 剪贴板**扩到**注册表值**。
	// 改动分两层：
	//   ① `r3shieldcore_config.cpp` 的解析（本文件钉住）；
	//   ② `registry_guard.cpp` 的决策 + 数据区清零（需要注入才能跑 ⇒ 由
	//      `tools/spoof_reg_probe.cpp` 的机制探针负责）。
	//
	// ★ 本节重点钉住三条性质：
	//   · 默认**关**；
	//   · 与 `spoof_screen` / `spoof_clipboard` 是**三个独立的位**
	//     （配错一个会表现为"开了注册表替换结果剪贴板也被换了" —— 必须钉住）；
	//   · 三个常量两两不同（防手滑写成同一个 0x 值）。
	{
		// ---- 缺文件：默认关 ----
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		ResetPolicy(policy);
		LoadPinned(policy, dir);
		failed += !Check("spoof_reg: missing config -> 默认关",
			(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) == 0);

		// ---- 开 / 关 ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg=1 -> 置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg=0\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg=0 -> 不置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) == 0);
		}
		{
			// on/off 别名 + 最后一行权威
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg=on\n";
			ini << "spoof_reg=off\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg: on/off 别名可用且最后一行权威",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg=1 # 打开注册表值替换\n";   // 行内注释
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg: 行内注释被切掉后仍为 1",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0);
		}

		// ---- ★ 交叉检查：三个 spoof 位**互不干扰**（双向）----
		//   单向断言只能证明"没被清掉"，证明不了"没被点亮"。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 screen+clipboard -> 注册表替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 spoof_reg -> 截屏替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) == 0);
			failed += !Check("交叉：只开 spoof_reg -> 剪贴板替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);
			failed += !Check("交叉：只开 spoof_reg -> 注册表替换确实开了",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini << "spoof_reg=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：三个都开 -> 三个位都亮",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0);
		}

		// ---- ★ 位值两两不同（防手滑写成同一个 0x 值）----
		failed += !Check("FlagSpoofRegistry 与 FlagSpoofScreen 不是同一位",
			R3ShieldCore::FlagSpoofRegistry != R3ShieldCore::FlagSpoofScreen);
		failed += !Check("FlagSpoofRegistry 与 FlagSpoofClipboard 不是同一位",
			R3ShieldCore::FlagSpoofRegistry != R3ShieldCore::FlagSpoofClipboard);
	}

	// ---- v72：注册表枚举隐藏 spoof_reg_enum= ----
	//
	// 为什么补这一节：v72 把「回传数据替换」从**单点取值**扩到**枚举遍历**
	// （`NtEnumerateKey` / `NtEnumerateValueKey`）。改动同样分两层：
	//   ① `r3shieldcore_config.cpp` 的解析（本文件钉住）；
	//   ② `registry_guard.cpp` 的决策 + 索引重映射（需要注入才能跑 ⇒ 由
	//      `tools/spoof_reg_enum_probe.cpp` 的机制探针 + `tools/v72_guard_ut.cpp`
	//      的纯逻辑单测负责）。
	//
	// ★ 本节重点钉住四条性质：
	//   · 默认**关**；
	//   · 与 `spoof_screen` / `spoof_clipboard` / `spoof_reg` 是**四个独立的位**
	//     （配错一个会表现为"开了枚举隐藏结果单点取值也被换了" —— 必须钉住）；
	//   · 四个常量**两两不同**（防手滑写成同一个 0x 值）；
	//   · ★ 枚举位**不能**被 `spoof_reg` 顺带点亮（铁律 199：放宽一个开关不能
	//     顺带打开别的行为 —— 枚举隐藏会让调用方**看不到**某些项，破坏性比单点
	//     取值大得多，必须由用户显式打开）。
	{
		// ---- 缺文件：默认关 ----
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		ResetPolicy(policy);
		LoadPinned(policy, dir);
		failed += !Check("spoof_reg_enum: missing config -> 默认关",
			(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) == 0);

		// ---- 开 / 关 ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg_enum=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg_enum=1 -> 置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg_enum=0\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg_enum=0 -> 不置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) == 0);
		}
		{
			// on/off 别名 + 最后一行权威
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg_enum=on\n";
			ini << "spoof_reg_enum=off\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg_enum: on/off 别名可用且最后一行权威",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg_enum=1 # 打开注册表枚举隐藏\n";   // 行内注释
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_reg_enum: 行内注释被切掉后仍为 1",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) != 0);
		}

		// ---- ★ 交叉检查：四个 spoof 位**互不干扰**（双向）----
		//   单向断言只能证明"没被清掉"，证明不了"没被点亮"。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini << "spoof_reg=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 screen+clipboard+reg -> 枚举隐藏仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_reg_enum=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 spoof_reg_enum -> 截屏替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) == 0);
			failed += !Check("交叉：只开 spoof_reg_enum -> 剪贴板替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);
			failed += !Check("交叉：只开 spoof_reg_enum -> 注册表值替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) == 0);
			failed += !Check("交叉：只开 spoof_reg_enum -> 枚举隐藏确实开了",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini << "spoof_reg=1\n";
			ini << "spoof_reg_enum=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：四个都开 -> 四个位都亮",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) != 0);
		}

		// ---- ★ 位值两两不同（防手滑写成同一个 0x 值）----
		//   到 v72 一共四个位 ⇒ 完整两两组合共 6 对。前面两节已钉住
		//   (Screen,Clipboard) / (Registry,Screen) / (Registry,Clipboard)，
		//   这里补齐含新位的 3 对，凑齐 6 对。
		failed += !Check("FlagSpoofRegistryEnum 与 FlagSpoofScreen 不是同一位",
			R3ShieldCore::FlagSpoofRegistryEnum != R3ShieldCore::FlagSpoofScreen);
		failed += !Check("FlagSpoofRegistryEnum 与 FlagSpoofClipboard 不是同一位",
			R3ShieldCore::FlagSpoofRegistryEnum != R3ShieldCore::FlagSpoofClipboard);
		failed += !Check("FlagSpoofRegistryEnum 与 FlagSpoofRegistry 不是同一位",
			R3ShieldCore::FlagSpoofRegistryEnum != R3ShieldCore::FlagSpoofRegistry);
	}

	// ---- v73：摄像头帧替换 spoof_camera= ----
	//
	// 为什么补这一节：v73 把「回传数据替换」扩到**流式**的摄像头帧。
	// 改动同样分两层：
	//   ① `r3shieldcore_config.cpp` 的解析（本文件钉住）；
	//   ② `camera_guard.cpp` 的 vtable patch + 逐帧中性化（需要注入才能跑
	//      ⇒ 由 `tools/spoof_camera_probe.cpp` 的机制探针 + `tools/v73_guard_ut.cpp`
	//      的纯逻辑单测负责）。
	//
	// ★ 本节重点钉住五条性质：
	//   · 默认**关**；
	//   · 与 `spoof_screen` / `spoof_clipboard` / `spoof_reg` / `spoof_reg_enum`
	//     是**五个独立的位**；
	//   · 五个常量**两两不同**（防手滑写成同一个 0x 值）；
	//   · ★ `hook_camera=1`（挂载开关）**不能**顺带点亮它（铁律 199：
	//     放宽一个开关不能顺带打开别的行为 —— 摄像头替换会把"打开失败"
	//     变成"打开成功但内容是假的"，语义变化比拒绝大得多）；
	//   · ★ 反过来它**不能**被前四个 spoof 开关顺带点亮。
	{
		// ---- 缺文件：默认关 ----
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		ResetPolicy(policy);
		LoadPinned(policy, dir);
		failed += !Check("spoof_camera: missing config -> 默认关",
			(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) == 0);

		// ---- 开 / 关 ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_camera=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_camera=1 -> 置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_camera=0\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_camera=0 -> 不置位",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) == 0);
		}
		{
			// on/off 别名 + 最后一行权威
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_camera=on\n";
			ini << "spoof_camera=off\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_camera: on/off 别名可用且最后一行权威",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_camera=1 # 打开摄像头帧替换\n";   // 行内注释
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("spoof_camera: 行内注释被切掉后仍为 1",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) != 0);
		}

		// ---- ★ 负对照：挂载开关 `hook_camera=1` 不能顺带点亮替换 ----
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "hook_camera=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 hook_camera -> 帧替换仍为关（负对照，铁律 199）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) == 0);
		}

		// ---- ★ 交叉检查：五个 spoof 位**互不干扰**（双向）----
		//   单向断言只能证明"没被清掉"，证明不了"没被点亮"。
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini << "spoof_reg=1\n";
			ini << "spoof_reg_enum=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开前四个 -> 摄像头帧替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) == 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_camera=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：只开 spoof_camera -> 截屏替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) == 0);
			failed += !Check("交叉：只开 spoof_camera -> 剪贴板替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) == 0);
			failed += !Check("交叉：只开 spoof_camera -> 注册表值替换仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) == 0);
			failed += !Check("交叉：只开 spoof_camera -> 枚举隐藏仍为关（负对照）",
				(policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) == 0);
			failed += !Check("交叉：只开 spoof_camera -> 摄像头帧替换确实开了",
				(policy.Flags2 & R3ShieldCore::FlagSpoofCamera) != 0);
		}
		{
			std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
			ini << "spoof_screen=1\n";
			ini << "spoof_clipboard=1\n";
			ini << "spoof_reg=1\n";
			ini << "spoof_reg_enum=1\n";
			ini << "spoof_camera=1\n";
			ini.close();
			ResetPolicy(policy);
			LoadPinned(policy, dir);
			failed += !Check("交叉：五个都开 -> 五个位都亮",
				(policy.Flags2 & R3ShieldCore::FlagSpoofScreen) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) != 0
				&& (policy.Flags2 & R3ShieldCore::FlagSpoofCamera) != 0);
		}

		// ---- ★ 位值两两不同（防手滑写成同一个 0x 值）----
		//   到 v73 一共五个位 ⇒ 完整两两组合共 10 对。前面三节已钉住 6 对：
		//   (Screen,Clipboard) / (Registry,Screen) / (Registry,Clipboard) /
		//   (Enum,Screen) / (Enum,Clipboard) / (Enum,Registry)。
		//   这里补齐含新位的 4 对，凑齐 10 对。
		failed += !Check("FlagSpoofCamera 与 FlagSpoofScreen 不是同一位",
			R3ShieldCore::FlagSpoofCamera != R3ShieldCore::FlagSpoofScreen);
		failed += !Check("FlagSpoofCamera 与 FlagSpoofClipboard 不是同一位",
			R3ShieldCore::FlagSpoofCamera != R3ShieldCore::FlagSpoofClipboard);
		failed += !Check("FlagSpoofCamera 与 FlagSpoofRegistry 不是同一位",
			R3ShieldCore::FlagSpoofCamera != R3ShieldCore::FlagSpoofRegistry);
		failed += !Check("FlagSpoofCamera 与 FlagSpoofRegistryEnum 不是同一位",
			R3ShieldCore::FlagSpoofCamera != R3ShieldCore::FlagSpoofRegistryEnum);
	}

	// ============================================================
	//  v103：SaveEntries —— 配置页「应用」按钮的写盘通道
	// ============================================================
	//
	//  ★ 为什么单独测它：这是**唯一**能从界面改 ini 的入口，而它做的事
	//    很危险 —— 整文件读入、改几行、整文件写回。写错一个字节就会
	//    把用户那份带大段中文注释的 ini 毁掉（注释和 CRLF 都要原样保住）。
	//
	//  测点（对应用户会在界面上碰到的情况）：
	//    ① 改一个已存在的键 ⇒ 只有那一行变，其余字节（注释 / 空行 / CRLF）不动；
	//    ② 同一个键在文件里出现两次 ⇒ **两处都改**（旧文件真有重复的 never_inject）；
	//    ③ 键不存在 ⇒ 追加到末尾，不覆盖别的行；
	//    ④ 多条一起改 ⇒ 全部生效，且互不干扰；
	//    ⑤ 空 entries ⇒ 返回 true 且**不改文件**（"没东西可改"不是失败）；
	//    ⑥ 形状不对的条目（没有 `=`）⇒ 被跳过，不写垃圾；
	//    ⑦ ini 打不开 ⇒ 返回 false，且**不创建/不截断**任何文件；
	//    ⑧ 键名大小写不敏感（`HOOK_FILE=1` 也要能命中 `hook_file`）。
	{
		const std::filesystem::path saveDir = dir / L"save_entries";
		std::filesystem::create_directories(saveDir, ec);
		const std::filesystem::path iniPath = saveDir / L"r3shieldcore.ini";

		// 一份"像用户手写的那种" ini：带中文注释、空行、CRLF、重复键。
		// 直接用 \r\n —— 这是本项目 ini 的真实行尾（Windows 记事本 / VS 都这么存）。
		const std::string original =
			"# R3 ShieldCore 配置\r\n"
			"# 这一行是注释，改配置时不能被吃掉\r\n"
			"\r\n"
			"mode=log\r\n"
			"hook_file=0\r\n"
			"; 下面这条重复了，旧版工具留下的\r\n"
			"never_inject=D:\\old\\a.exe\r\n"
			"never_inject=D:\\old\\b.exe\r\n"
			"\r\n"
			"test_inject_only=\r\n";

		auto WriteOriginal = [&]()
		{
			std::ofstream out(iniPath, std::ios::binary | std::ios::trunc);
			out.write(original.data(), static_cast<std::streamsize>(original.size()));
		};

		auto ReadAll = [&]() -> std::string
		{
			std::ifstream in(iniPath, std::ios::binary);
			return std::string((std::istreambuf_iterator<char>(in)),
				std::istreambuf_iterator<char>());
		};

		// ---- ① 改一个已存在的键 ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile({ "hook_file=1" }, iniPath);
			failed += !Check("SaveEntries：改已有键返回 true", ok);
			const std::string after = ReadAll();
			failed += !Check("SaveEntries：目标行确实改成了 hook_file=1",
				after.find("hook_file=1") != std::string::npos);
			failed += !Check("SaveEntries：旧值 hook_file=0 不再出现",
				after.find("hook_file=0") == std::string::npos);
			failed += !Check("SaveEntries：中文注释原样保留",
				after.find("# 这一行是注释，改配置时不能被吃掉") != std::string::npos);
			failed += !Check("SaveEntries：mode=log 没被顺手改掉",
				after.find("mode=log") != std::string::npos);
			failed += !Check("SaveEntries：CRLF 行尾保留（不变成纯 LF）",
				after.find("\r\n") != std::string::npos);
			// 字节数只该因为 0→1 而不变（同长度替换）
			failed += !Check("SaveEntries：同长度替换后文件大小不变（说明没重排）",
				after.size() == original.size());
		}

		// ---- ② 重复键全部改 ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile(
				{ "never_inject=D:\\new\\only.exe" }, iniPath);
			failed += !Check("SaveEntries：改重复键返回 true", ok);
			const std::string after = ReadAll();
			failed += !Check("SaveEntries：重复键的第一处也改了（新值出现 2 次）",
				[&after]()
				{
					size_t count = 0;
					const std::string needle = "never_inject=D:\\new\\only.exe";
					size_t p = after.find(needle);
					while (p != std::string::npos) { ++count; p = after.find(needle, p + 1); }
					return count;
				}() == 2);
			failed += !Check("SaveEntries：两处旧值都不在了",
				after.find("D:\\old\\a.exe") == std::string::npos
				&& after.find("D:\\old\\b.exe") == std::string::npos);
		}

		// ---- ③ 缺键追加 ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile({ "brand_new_key=42" }, iniPath);
			failed += !Check("SaveEntries：追加缺键返回 true", ok);
			const std::string after = ReadAll();
			failed += !Check("SaveEntries：缺键被追加进去了",
				after.find("brand_new_key=42") != std::string::npos);
			failed += !Check("SaveEntries：追加后原有的值都还在",
				after.find("mode=log") != std::string::npos
				&& after.find("hook_file=0") != std::string::npos);
			failed += !Check("SaveEntries：追加时没把注释挤掉",
				after.find("# 这一行是注释，改配置时不能被吃掉") != std::string::npos);
		}

		// ---- ④ 多条一起改 ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile(
				{ "hook_file=1", "hook_reads=1", "mode=block_all" }, iniPath);
			failed += !Check("SaveEntries：多条一起改返回 true", ok);
			const std::string after = ReadAll();
			failed += !Check("SaveEntries：多条全部生效",
				after.find("hook_file=1") != std::string::npos
				&& after.find("hook_reads=1") != std::string::npos
				&& after.find("mode=block_all") != std::string::npos);
			failed += !Check("SaveEntries：多条的旧值都清干净",
				after.find("hook_file=0") == std::string::npos
				&& after.find("mode=log") == std::string::npos);
		}

		// ---- ⑤ 空 entries ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile({}, iniPath);
			failed += !Check("SaveEntries：空 entries 返回 true（不是失败）", ok);
			failed += !Check("SaveEntries：空 entries 时文件一个字节都没动",
				ReadAll() == original);
		}

		// ---- ⑥ 形状不对的条目被跳过 ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile(
				{ "no_equals_sign_here", "=no_key" }, iniPath);
			failed += !Check("SaveEntries：全是坏条目 ⇒ 返回 false（没有可写的）", !ok);
			failed += !Check("SaveEntries：坏条目没被写成垃圾行",
				ReadAll() == original);
		}

		// ---- ⑦ ini 不存在 ⇒ false 且不创建文件 ----
		{
			const std::filesystem::path missingDir = dir / L"save_entries_missing";
			std::filesystem::create_directories(missingDir, ec);
			const std::filesystem::path missingIni = missingDir / L"r3shieldcore.ini";
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile({ "hook_file=1" }, missingIni);
			failed += !Check("SaveEntries：ini 不存在时返回 false（不偷偷新建）", !ok);
			failed += !Check("SaveEntries：ini 不存在时也没创建空文件",
				!std::filesystem::exists(missingIni));
		}

		// ---- ⑧ 键名大小写不敏感 ----
		WriteOriginal();
		{
			const bool ok = R3ShieldCoreConfig::SaveEntriesToFile({ "HOOK_FILE=1" }, iniPath);
			failed += !Check("SaveEntries：大写键名也能命中（返回 true）", ok);
			const std::string after = ReadAll();
			failed += !Check("SaveEntries：大写键名命中后，原行被替换成传入的写法",
				after.find("HOOK_FILE=1") != std::string::npos);
			failed += !Check("SaveEntries：小写旧行 hook_file=0 已消失",
				after.find("hook_file=0") == std::string::npos);
		}

		// ---- 还原，免得影响后面的用例 ----
		WriteOriginal();

		// ★★★ 环境自检：确认这一节**从头到尾没碰本机真实配置**。
		//
		//   加这条的理由很直接 —— 2026-10-24 第一版测试就是走的
		//   `SaveEntries(entries, dir)`，它内部解析到
		//   `%ProgramData%\R3 Shield Core\r3shieldcore.ini`（开发机上真实存在），
		//   于是"测试临时目录"里的断言全 FAIL，而**开发机的真配置被改坏**
		//   （`HOOK_FILE=1` 覆盖了 `hook_file=1`，末尾多出 `brand_new_key=42`）。
		//   两个后果都很难发现：FAIL 看着像实现有 bug，污染则完全静默。
		//
		//   ⇒ 钉文件入口（SaveEntriesToFile）是根本修法；这条自检是**哨兵**：
		//     以后谁把调用改回 `SaveEntries`，这里立刻红。
		{
			const bool prodIniTouched =
				std::filesystem::exists("C:\\ProgramData\\R3 Shield Core\\r3shieldcore.ini")
				&& [&]()
				{
					std::ifstream in("C:\\ProgramData\\R3 Shield Core\\r3shieldcore.ini",
						std::ios::binary);
					if (!in) { return false; }
					const std::string body((std::istreambuf_iterator<char>(in)),
						std::istreambuf_iterator<char>());
					// 只要本机那份里出现这两个测试专用标记，就说明被写进去了。
					return body.find("brand_new_key=42") != std::string::npos
						|| body.find("D:\\new\\only.exe") != std::string::npos;
				}();
			failed += !Check("环境自检：本机 %ProgramData% 的 ini 没有被测试写脏",
				!prodIniTouched);
		}
	}

	std::filesystem::remove_all(dir, ec);
	return failed == 0 ? 0 : 1;
}