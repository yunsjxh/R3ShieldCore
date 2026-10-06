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
	R3ShieldCoreConfig::Load(policy, dir);
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
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("inject_shell_thin=0 disables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) == 0);
	failed += !Check("inject_shell_thin=0 does not disturb hook_raw_disk",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=1\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("inject_shell_thin=1 enables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	{
		// 行内注释必须被切掉（铁律 33：解析器只认行首注释会静默吞值）
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=1   # 瘦注入\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("inject_shell_thin inline comment stripped -> 1",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	{
		// 认不出的值按 IsTrue 的既有语义处理：非真值即关。
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=off\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("inject_shell_thin=off disables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) == 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "inject_shell_thin=on\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("inject_shell_thin=on enables thin inject",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_raw_disk=1\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	// ★ 交叉检查：改 hook_raw_disk 不能顺手把瘦注入关掉（两条独立的位）
	failed += !Check("hook_raw_disk=1 keeps thin-inject untouched (independent bits)",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);

	// ---- v39：hook_raw_disk 开关 ----
	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_raw_disk=0\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("hook_raw_disk=0 disables raw-disk hook",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) == 0);
	failed += !Check("hook_raw_disk=0 does not disturb hook_file flag",
		(policy.Flags & R3ShieldCore::FlagHookFile) == 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_raw_disk=1\n";
	}
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("hook_raw_disk=1 enables raw-disk hook",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_file=1\n";
	}
	R3ShieldCoreConfig::Load(policy, dir);
	failed += !Check("hook_file=1 enables file hook",
		(policy.Flags & R3ShieldCore::FlagHookFile) != 0);

	{
		std::ofstream ini(dir / L"r3shieldcore.ini", std::ios::binary | std::ios::trunc);
		ini << "hook_file=0\n";
	}
	R3ShieldCoreConfig::Load(policy, dir);
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
	policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
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
		R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
			failed += !Check((std::string("neutralize_overlay: ") + c.what).c_str(),
				e.NeutralizeOverlayLevel == c.expect);
		}
	}

	// ---- v41：注入扫描间隔 inject_interval_ms（盲区大小）----
	{
		std::filesystem::remove(dir / L"r3shieldcore.ini", ec);
		R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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

		policy = {};
		R3ShieldCoreConfig::Load(policy, dir);

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
		R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
		R3ShieldCoreConfig::EngineSettings e = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
				R3ShieldCoreConfig::EngineSettings e2 = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e2 = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e2 = R3ShieldCoreConfig::LoadEngineSettings(dir);
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
			R3ShieldCoreConfig::EngineSettings e2 = R3ShieldCoreConfig::LoadEngineSettings(dir);
			failed += !Check("ark 三键各自独立（0 / 3000 / 750 互不影响）",
				!e2.ArkEnabled && e2.ArkScanMs == 3000 && e2.ArkRefreshMs == 750);
		}
	}

	std::filesystem::remove_all(dir, ec);
	return failed == 0 ? 0 : 1;
}