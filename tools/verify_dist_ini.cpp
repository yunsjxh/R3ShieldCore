//
// verify_dist_ini.cpp —— 发布闸门：验证**随包 ini** 真的解析成预期配置。
//
// 为什么需要它：
//   发布版把默认模式改成了 `block`，但那是**写进 ini 的**（代码默认仍是 log 兜底）。
//   ini 是纯文本，手改一行就可能写错（拼错 / 被注释掉 / 后面又冒出一行 mode=）；
//   预设文件是"最小覆盖"（只写与默认不同的项），更容易悄悄漂移。
//   光"看一遍文件"证明不了**引擎侧解析器**认不认 —— 必须真跑一次
//   `R3ShieldCoreConfig::Load`，看它吐出来的 Policy 是什么。
//
// 这正是铁律 17 的意思：判"生效没生效"要看真实现，不要看 grep。
//
// 用法：
//   verify_dist_ini.exe                     # 默认校验 dist/R3ShieldCore-x64
//   verify_dist_ini.exe <含 r3shieldcore.ini 的目录>
//
// 退出码：0 = 全部符合预期；1 = 有不符。

#include <r3shieldcore_config.h>

#include <cstdio>
#include <filesystem>
#include <string>

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok, const std::string& detail = {})
{
	printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
		detail.empty() ? "" : "  -> ", detail.c_str());
	if (ok) g_pass++; else g_fail++;
}

static const char* OnOff(ULONG flags, ULONG bit)
{
	return (flags & bit) ? "on" : "off";
}

static const char* ModeText(const R3ShieldCore::Policy& p)
{
	const char* t = R3ShieldCoreConfig::ModeIniText(p.Mode);
	return t ? t : "(无法识别)";
}

// ---- 主配置：逐项打印 + 断言 ----
static void CheckMainConfig(const std::filesystem::path& dir)
{
	R3ShieldCore::Policy policy = {};
	R3ShieldCoreConfig::Load(policy, dir);
	R3ShieldCoreConfig::EngineSettings eng = R3ShieldCoreConfig::LoadEngineSettings(dir);

	printf("\n-- 主配置 r3shieldcore.ini 解析结果 --\n");
	printf("  mode                   = %s\n", ModeText(policy));
	printf("  high_risk              = %s\n", OnOff(policy.Flags, R3ShieldCore::FlagHighRiskGuard));
	printf("  self_protect           = %s\n", OnOff(policy.Flags, R3ShieldCore::FlagSelfProtect));
	printf("  hook_process           = %s\n", OnOff(policy.Flags, R3ShieldCore::FlagHookProcess));
	printf("  hook_file              = %s\n", OnOff(policy.Flags, R3ShieldCore::FlagHookFile));
	printf("  hook_terminate_contain = %s\n", OnOff(policy.Flags2, R3ShieldCore::FlagHookTerminateContain));
	printf("  hook_raw_disk          = %s\n", OnOff(policy.Flags2, R3ShieldCore::FlagHookRawDisk));
	printf("  inject_shell_thin      = %s\n", OnOff(policy.Flags2, R3ShieldCore::FlagInjectShellThin));
	printf("  neutralize_overlay     = %lu (0=off 1=on-noask 2=on-ask)\n",
		static_cast<unsigned long>(eng.NeutralizeOverlayLevel));
	printf("  inject_interval_ms     = %lu (注入盲区大小)\n",
		static_cast<unsigned long>(eng.InjectionIntervalMs));
	printf("  prompt_timeout         = %lu\n", policy.PromptTimeoutMs);
	printf("  prompt_default         = %lu (0=deny 1=allow)\n", policy.PromptDefaultVerdict);
	printf("  exclude 条数           = %lu\n", policy.ExcludePathCount);
	printf("  never_inject 条数      = %lu\n", policy.NeverInjectCount);
	for (ULONG i = 0; i < policy.NeverInjectCount && i < R3ShieldCore::MaxNeverInjectPaths; ++i) {
		char buf[R3ShieldCore::MaxNeverInjectPathChars * 2] = {};
		WideCharToMultiByte(CP_ACP, 0, policy.NeverInjectPaths[i], -1, buf, sizeof(buf), nullptr, nullptr);
		printf("    [%lu] %s\n", static_cast<unsigned long>(i), buf);
	}

	printf("\n-- 断言（发布要求）--\n");
	Check("mode 解析为 block（发布默认 = 拦截）",
		policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Block), ModeText(policy));
	Check("high_risk=1（内置高危规则表开着）",
		(policy.Flags & R3ShieldCore::FlagHighRiskGuard) != 0);
	Check("self_protect=1（引擎自我保护开着）",
		(policy.Flags & R3ShieldCore::FlagSelfProtect) != 0);
	Check("hook_process=1（进程监控开着）",
		(policy.Flags & R3ShieldCore::FlagHookProcess) != 0);
	Check("hook_terminate_contain=1（终止收敛开着）",
		(policy.Flags2 & R3ShieldCore::FlagHookTerminateContain) != 0);
	// ★ v39：裸盘写入（引导区）保护必须随包默认开 —— 且**独立于 hook_file**。
	//   真实绕过就发生在发布默认配置（hook_file=0）下，这条断言就是防它复发。
	Check("hook_raw_disk=1（裸盘/引导区写入保护开着，且不依赖 hook_file）",
		(policy.Flags2 & R3ShieldCore::FlagHookRawDisk) != 0);
	// ★ v39：窗口反制默认 = 2（询问）。④⑤ 会结束目标进程，随包默认必须**先问**，
	//   不能静默杀正常全屏程序。改 ini 一行就能让这条失效 —— 所以必须真解析后断言。
	Check("neutralize_overlay=2（窗口反制开着，且默认询问而非静默执行）",
		eng.NeutralizeOverlayLevel == 2,
		std::to_string(static_cast<unsigned long>(eng.NeutralizeOverlayLevel)));
	Check("prompt_default=deny（兜底拒绝）",
		policy.PromptDefaultVerdict == static_cast<ULONG>(R3ShieldCore::Verdict::Deny));
	// ★ v41：注入扫描间隔必须**远小于**样本"启动→写 MBR"的几十~几百 ms。
	//   这个值就是"新进程未受保护的时间窗"—— 被改大就等于把 MBR 让出去。
	Check("inject_interval_ms <= 50（注入盲区足够短，否则样本能抢在 hook 之前写 MBR）",
		eng.InjectionIntervalMs >= 1 && eng.InjectionIntervalMs <= 50,
		std::to_string(static_cast<unsigned long>(eng.InjectionIntervalMs)));
	// ★ v42：瘦注入必须随包默认开 —— 不注入 explorer.exe / svchost.exe，
	//   "双击启动"与"UAC 提权启动"就**拿不到同步注入路**，只能靠轮询，
	//   盲区从 ≈0 退回 10~60 ms。样本 Windows XP Horror 恰好在
	//   `FormCreate`（启动后几十~几百 ms）里写 MBR —— 差的就是这一点。
	Check("inject_shell_thin=1（shell/服务宿主瘦注入开着，双击与提权启动才有同步注入路）",
		(policy.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);
	// ★ v49：用户自定义"绝不注入"名单必须真的被解析器读进来 —— 发布随包默认带
	//   WorkBuddyAI 一条（避免给宿主工具自身注入 hook 造成自锁/性能损耗）。
	//   这条同样是"改 ini 一行就能悄悄失效"的项，必须真解析后断言。
	//   ★ 顺带钉住"完整路径前缀"语义：只认前缀，不是文件名匹配。
	Check("never_inject 有 1 条，且为 D:\\Program Files\\WorkBuddyAI\\（v49 用户免注入名单生效）",
		policy.NeverInjectCount == 1 &&
		wcscmp(policy.NeverInjectPaths[0], L"D:\\Program Files\\WorkBuddyAI\\") == 0,
		std::to_string(static_cast<unsigned long>(policy.NeverInjectCount)) + " 条");

	// ★ v62/v63：ARK 页（全机进程视图 + 分组排序）。三个键随包必须都是预期值。
	//
	//   为什么值得断言：`ark_enabled=0` 的症状是"ARK 页签还在，但列表永远是空的"，
	//   用户会直接判断成"功能坏了"；而两个间隔写错一个，症状是"改了没反应"。
	//   这三条都属于"改 ini 一行就悄悄失效"的项 ⇒ 必须真解析后断言（铁律 17）。
	printf("  ark_enabled            = %s\n", eng.ArkEnabled ? "on" : "off");
	printf("  ark_scan_ms            = %lu (引擎枚举节奏)\n",
		static_cast<unsigned long>(eng.ArkScanMs));
	printf("  ark_refresh_ms         = %lu (界面刷新节奏)\n",
		static_cast<unsigned long>(eng.ArkRefreshMs));

	Check("ark_enabled=1（ARK 全机进程视图随包默认开）", eng.ArkEnabled);
	// ★ 两条一起断言，顺带证明 `ark_scan_ms` 与 `ark_refresh_ms` 是**两个独立的键**：
	//   随包写的是 2000 和 1000，若哪天有人把 refresh 的解析错接成 scan，
	//   或者把两个字段写反，下面必有一条变红。
	Check("ark_scan_ms=2000（引擎枚举节奏）", eng.ArkScanMs == 2000,
		std::to_string(static_cast<unsigned long>(eng.ArkScanMs)));
	Check("ark_refresh_ms=1000（界面刷新节奏，与 ark_scan_ms 相互独立）",
		eng.ArkRefreshMs == 1000,
		std::to_string(static_cast<unsigned long>(eng.ArkRefreshMs)));
}

// ---- 预设：把预设当作 r3shieldcore.ini 载入，验证"最小覆盖"等于预期完整配置 ----
struct PresetExpect
{
	const wchar_t* file;
	ULONG mode;
	bool hookFile;
	const char* what;
};

static void CheckPreset(const std::filesystem::path& distDir, const std::filesystem::path& tmpDir,
	const PresetExpect& e)
{
	std::error_code ec;
	const std::filesystem::path src = distDir / e.file;
	if (!std::filesystem::exists(src)) {
		Check("预设存在", false, std::string(e.what) + " 缺文件");
		return;
	}

	// 预设是"最小覆盖"：当成 r3shieldcore.ini 放进一个干净目录再解析。
	const std::filesystem::path work = tmpDir / e.file;
	std::filesystem::create_directories(work, ec);
	std::filesystem::copy_file(src, work / L"r3shieldcore.ini",
		std::filesystem::copy_options::overwrite_existing, ec);

	R3ShieldCore::Policy p = {};
	R3ShieldCoreConfig::Load(p, work);
	// 引擎侧设置也要真解析一遍：预设是"最小覆盖"，未列出的键必须落到内置默认。
	R3ShieldCoreConfig::EngineSettings pe = R3ShieldCoreConfig::LoadEngineSettings(work);

	printf("\n-- 预设 %ls --\n", e.file);
	printf("  mode=%s hook_file=%s terminate_contain=%s self_protect=%s neutralize_overlay=%lu\n",
		ModeText(p), OnOff(p.Flags, R3ShieldCore::FlagHookFile),
		OnOff(p.Flags2, R3ShieldCore::FlagHookTerminateContain),
		OnOff(p.Flags, R3ShieldCore::FlagSelfProtect),
		static_cast<unsigned long>(pe.NeutralizeOverlayLevel));

	Check((std::string(e.what) + "：mode 正确").c_str(),
		p.Mode == e.mode, ModeText(p));
	Check((std::string(e.what) + "：hook_file 正确").c_str(),
		((p.Flags & R3ShieldCore::FlagHookFile) != 0) == e.hookFile);
	// ★ 关键：预设是"最小覆盖"，必须确认**没被列出的项仍取到内置默认**
	//   （老版本的预设是整份拷贝，漏掉了后来新增的键 —— 这条就是防它复发）
	Check((std::string(e.what) + "：未列出的项仍为默认（terminate_contain 开）").c_str(),
		(p.Flags2 & R3ShieldCore::FlagHookTerminateContain) != 0);
	Check((std::string(e.what) + "：未列出的项仍为默认（self_protect 开）").c_str(),
		(p.Flags & R3ShieldCore::FlagSelfProtect) != 0);
	Check((std::string(e.what) + "：未列出的项仍为默认（neutralize_overlay=2 询问）").c_str(),
		pe.NeutralizeOverlayLevel == 2);
	Check((std::string(e.what) + "：未列出的项仍为默认（inject_interval_ms=10 短盲区）").c_str(),
		pe.InjectionIntervalMs == 10);
	// ★ v42：预设也不能把瘦注入漏掉 —— 否则用预设覆盖后同步注入路就没了
	Check((std::string(e.what) + "：未列出的项仍为默认（inject_shell_thin 开）").c_str(),
		(p.Flags2 & R3ShieldCore::FlagInjectShellThin) != 0);
	// ★ v49：预设也各带一条 never_inject —— 用预设覆盖主配置后，宿主工具仍必须免注入。
	//   这条同时验证"预设是完整可用配置"：光有 r3shieldcore.ini 带 never_inject 不够，
	//   用户一旦切到预设，免注入就没了。
	Check((std::string(e.what) + "：never_inject 有 1 条（v49 免注入名单随预设生效）").c_str(),
		p.NeverInjectCount == 1 &&
		wcscmp(p.NeverInjectPaths[0], L"D:\\Program Files\\WorkBuddyAI\\") == 0,
		std::to_string(static_cast<unsigned long>(p.NeverInjectCount)) + " 条");
	// ★ v63：ARK 也是"预设里没列出的项" —— 用预设覆盖后必须仍落到内置默认
	//   （开 + 2000/1000）。否则用户一切预设，ARK 就静默关了，
	//   而症状只是"列表空"，很难联想到预设。
	Check((std::string(e.what) + "：未列出的项仍为默认（ark_enabled 开）").c_str(),
		pe.ArkEnabled);
	Check((std::string(e.what) + "：未列出的项仍为默认（ark_scan_ms=2000）").c_str(),
		pe.ArkScanMs == 2000,
		std::to_string(static_cast<unsigned long>(pe.ArkScanMs)));
	Check((std::string(e.what) + "：未列出的项仍为默认（ark_refresh_ms=1000）").c_str(),
		pe.ArkRefreshMs == 1000,
		std::to_string(static_cast<unsigned long>(pe.ArkRefreshMs)));

	std::filesystem::remove_all(work, ec);
}

int main(int argc, char** argv)
{
	std::filesystem::path distDir = "dist/R3ShieldCore-x64";
	if (argc > 1) {
		distDir = std::filesystem::path(argv[1]);
	}

	printf("=== 发布闸门：随包 ini 校验 ===\n");
	printf("目录: %s\n", distDir.string().c_str());

	if (!std::filesystem::exists(distDir / L"r3shieldcore.ini")) {
		printf("  [FAIL] 找不到 %s\\r3shieldcore.ini\n", distDir.string().c_str());
		return 1;
	}

	CheckMainConfig(distDir);

	std::error_code ec;
	const std::filesystem::path tmpDir = std::filesystem::temp_directory_path()
		/ (L"r3shieldcore-dist-verify-" + std::to_wstring(GetCurrentProcessId()));
	std::filesystem::remove_all(tmpDir, ec);
	std::filesystem::create_directories(tmpDir, ec);

	const PresetExpect presets[] = {
		{ L"r3shieldcore-block.ini",        static_cast<ULONG>(R3ShieldCore::Mode::Block),        true,  "block" },
		{ L"r3shieldcore-safe-first.ini",   static_cast<ULONG>(R3ShieldCore::Mode::Log),          false, "safe-first" },
		{ L"r3shieldcore-blockallsafe.ini", static_cast<ULONG>(R3ShieldCore::Mode::BlockAllSafe), true,  "blockallsafe" },
		{ L"r3shieldcore-blockall.ini",     static_cast<ULONG>(R3ShieldCore::Mode::BlockAll),     true,  "blockall" },
	};
	printf("\n=== 预设校验（最小覆盖 = 预期完整配置）===\n");
	for (const auto& e : presets) {
		CheckPreset(distDir, tmpDir, e);
	}

	std::filesystem::remove_all(tmpDir, ec);

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
