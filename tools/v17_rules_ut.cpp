//
// v17_rules_ut.cpp - R3ShieldCoreRules v17「hive 级 Op 归位 + 内核路径形态」单元测试。
//
// 本轮修的三个「该升格没升格、且不报错」的静默漏洞：
//
//   ① IsHiveOp() 漏掉 Op::SaveKeyEx(=20)
//      → TargetKind 被判成 Key，下游日志/弹窗/统计把"导出 hive"当普通键操作，
//        措辞错乱（该显示"Hive 文件"却显示"值"）。不报错。
//
//   ② IsHighRiskOp() 漏掉 Op::UnloadKey(=14) / Op::UnloadKeyEx(=19)
//      → 卸载 hive 子树（可用来摘掉防护组件依赖的键）不判高危。不报错。
//
//   ③ NormalizeKey 只剥前缀不做段等价 —— 实测发现内核返回的路径里
//      `CurrentControlSet` 是**符号链接**，NtQueryKey 会解析成真实的
//      `ControlSet001`：
//          \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services
//            → NtQueryKey → ...\SYSTEM\ControlSet001\Services
//      而 NtSetValueKey / NtSaveKey 这类"拿句柄"的判定路径用的正是
//      NtQueryKey（ResolveKeyPath）→ 规则表里所有 `SYSTEM\CurrentControlSet\...`
//      条目对这两条路径**全部静默失效**。
//      （实测程序：tools/regnorm.cpp，本单测固化其结论。）
//
//   ④ hive 级操作拿到的是**子树根**（可能是规则的中间层级）：
//          NtSaveKey(句柄 = HKLM\SAM) → relative = "SAM"
//      规则表写的是叶子层 "SAM\SAM" → 前缀不成立 → 拖 SAM 不判高危。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "r3shieldcore_rules.h"

static int g_failed = 0;

static void Check(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-62s expect=%-6s got=%-6s\n", mark, group, note,
		expect ? "YES" : "no", got ? "YES" : "no");
}

int main()
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	typedef R3ShieldCore::Op Op;

	// ==================================================================
	// 1. IsHiveOp —— hive 级 Op 必须全部归位（TargetKind 靠它判）
	// ==================================================================
	printf("=== 1. IsHiveOp：hive 级 Op 全集 ===\n");

	Check("hive", "LoadKey(13)", R3ShieldCore::IsHiveOp((ULONG)Op::LoadKey), true);
	Check("hive", "UnloadKey(14)", R3ShieldCore::IsHiveOp((ULONG)Op::UnloadKey), true);
	Check("hive", "SaveKey(15)", R3ShieldCore::IsHiveOp((ULONG)Op::SaveKey), true);
	Check("hive", "RestoreKey(16)", R3ShieldCore::IsHiveOp((ULONG)Op::RestoreKey), true);
	Check("hive", "ReplaceKey(17)", R3ShieldCore::IsHiveOp((ULONG)Op::ReplaceKey), true);
	Check("hive", "LoadKeyEx(18)", R3ShieldCore::IsHiveOp((ULONG)Op::LoadKeyEx), true);
	Check("hive", "UnloadKeyEx(19)", R3ShieldCore::IsHiveOp((ULONG)Op::UnloadKeyEx), true);
	// ★ 本轮修的①
	Check("hive", "★ SaveKeyEx(20)（本轮修复）", R3ShieldCore::IsHiveOp((ULONG)Op::SaveKeyEx), true);

	// 对照：普通键操作不得被误判成 hive。
	Check("hive", "CreateKey(0) 不是 hive", R3ShieldCore::IsHiveOp((ULONG)Op::CreateKey), false);
	Check("hive", "SetValueKey(3) 不是 hive", R3ShieldCore::IsHiveOp((ULONG)Op::SetValueKey), false);
	Check("hive", "DeleteKey(4) 不是 hive", R3ShieldCore::IsHiveOp((ULONG)Op::DeleteKey), false);
	Check("hive", "FlushKey(7) 不是 hive", R3ShieldCore::IsHiveOp((ULONG)Op::FlushKey), false);

	// ==================================================================
	// 2. hive 级 Op 的高危判定 —— 提权/持久化关键动作
	// ==================================================================
	printf("\n=== 2. hive 级 Op 的高危判定（应全部 HIGH）===\n");

	// hive 级判定不依赖具体键路径（这里给一个中性路径，
	// 只要 IsHighRiskOp 认这个 Op 就会 HIGH）。
	const WCHAR* neutral = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services";
	const WCHAR* tmpKey  = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3ShieldCoreV17Neutral";

	Check("risk", "LoadKey 高危", R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::LoadKey), true);
	Check("risk", "LoadKeyEx 高危", R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::LoadKeyEx), true);
	Check("risk", "SaveKey 高危", R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::SaveKey), true);
	Check("risk", "SaveKeyEx 高危", R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::SaveKeyEx), true);
	Check("risk", "RestoreKey 高危", R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::RestoreKey), true);
	Check("risk", "ReplaceKey 高危", R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::ReplaceKey), true);
	// ★ 本轮修的②
	Check("risk", "★ UnloadKey 高危（本轮修复）",
		R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::UnloadKey), true);
	Check("risk", "★ UnloadKeyEx 高危（本轮修复）",
		R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::UnloadKeyEx), true);

	// 对照：读操作 / FlushKey 不是高危。
	Check("risk", "QueryValueKey 不是高危",
		R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::QueryValueKey), false);
	Check("risk", "EnumerateKey 不是高危",
		R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::EnumerateKey), false);
	Check("risk", "FlushKey 不是高危",
		R3ShieldCoreRules::IsHighRiskRegistry(neutral, nullptr, (ULONG)Op::FlushKey), false);

	// ==================================================================
	// 3. ★ CurrentControlSet ≡ ControlSetNNN（内核路径形态）
	// ==================================================================
	//
	// tools/regnorm.cpp 实测：NtQueryKey 返回 `ControlSet001`。
	// NtSetValueKey / NtSaveKey 走句柄判定 → 拿到的就是这种形态。
	// 这一组用 SetValueKey（走句柄的最典型路径）验证规则仍能命中。
	printf("\n=== 3. ControlSetNNN 形态仍须命中规则（★ 本轮修复）===\n");

	Check("ccs", "服务建键（CurrentControlSet 形态）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Evil",
			nullptr, (ULONG)Op::CreateKey), true);
	// ★ 关键：内核真实形态
	Check("ccs", "★ 服务建键（ControlSet001 形态，内核真实返回）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Evil",
			nullptr, (ULONG)Op::CreateKey), true);
	Check("ccs", "★ 防火墙配置（ControlSet001 形态）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters",
			nullptr, (ULONG)Op::SetValueKey), true);
	Check("ccs", "★ LSA 配置（ControlSet001 形态）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Lsa",
			nullptr, (ULONG)Op::SetValueKey), true);
	Check("ccs", "★ 远程桌面配置（ControlSet001 形态）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Terminal Server",
			nullptr, (ULONG)Op::SetValueKey), true);
	Check("ccs", "ControlSet002 也认（多套 control set）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet002\\Control\\Lsa",
			nullptr, (ULONG)Op::SetValueKey), true);

	// 对照：不得因段等价而误报。
	Check("ccs", "ControlSetX（非数字）不得误判成高危",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSetX\\Services\\Evil",
			nullptr, (ULONG)Op::CreateKey), false);
	Check("ccs", "普通键（对照）不是高危",
		R3ShieldCoreRules::IsHighRiskRegistry(tmpKey, nullptr, (ULONG)Op::SetValueKey), false);

	// ==================================================================
	// 4. ★ hive 级操作的「祖先层级」命中（拖 SAM）
	// ==================================================================
	//
	// NtSaveKey(句柄 = HKLM\SAM) → ResolveKeyPath 返回
	//   \REGISTRY\MACHINE\SAM → relative = "SAM"
	// 规则表写的是 "SAM\SAM"（SAM 数据库本体）。
	// hive 操作作用面是整棵子树 → 祖先前缀也应命中。
	printf("\n=== 4. hive 级「祖先层级」命中（★ 本轮修复）===\n");

	// ★ 关键：hive op + 中间层级 SAM
	Check("hive-anc", "★ NtSaveKey(句柄=HKLM\\SAM) 导出 SAM（hive，应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SAM", nullptr, (ULONG)Op::SaveKey), true);
	Check("hive-anc", "★ NtSaveKeyEx(句柄=HKLM\\SAM)（hive，应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SAM", nullptr, (ULONG)Op::SaveKeyEx), true);
	Check("hive-anc", "NtSaveKey(句柄=HKLM\\SAM\\SAM) 叶子层（也应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SAM\\SAM", nullptr, (ULONG)Op::SaveKey), true);

	// ★ 反向保护：**非 hive** 的普通键操作写父键 SAM 不得被判成"动 SAM 数据库"。
	Check("hive-anc", "普通 CreateKey 写 HKLM\\SAM 父键（非 hive，不应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SAM", nullptr, (ULONG)Op::CreateKey), false);
	Check("hive-anc", "普通 SetValueKey 写 HKLM\\SAM 父键（非 hive，不应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SAM", nullptr, (ULONG)Op::SetValueKey), false);
	// 普通操作写叶子层仍须命中。
	Check("hive-anc", "普通 SetValueKey 写 HKLM\\SAM\\SAM（叶子层，仍应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SAM\\SAM", nullptr, (ULONG)Op::SetValueKey), true);

	// SECURITY 子树：hive 操作拿 SECURITY 根 → 应命中（子树覆盖 Secrets）。
	Check("hive-anc", "★ NtSaveKey(句柄=HKLM\\SECURITY)（hive，祖先应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SECURITY", nullptr, (ULONG)Op::SaveKey), true);
	// 普通操作拿 SECURITY 根 → 不应命中（规则只对 Policy\Secrets / Accounts）。
	Check("hive-anc", "普通 CreateKey 写 HKLM\\SECURITY 根（非 hive，不应命中）",
		R3ShieldCoreRules::IsHighRiskRegistry(
			L"\\REGISTRY\\MACHINE\\SECURITY", nullptr, (ULONG)Op::CreateKey), false);

	// ==================================================================
	// 5. 宿主注入键（v15）也走句柄路径 —— ControlSetNNN 形态必须命中
	// ==================================================================
	printf("\n=== 5. 宿主注入键的 ControlSetNNN 形态（★ 本轮修复）===\n");

	{
		// IsHighRiskHostInjectionKey(keyPath, pathValue)：
		// 键命中注入表 **且** 值指向用户可写目录 → 高危。
		bool appCertCurrent = R3ShieldCoreRules::IsHighRiskHostInjectionKey(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
			L"C:\\Windows\\Temp\\evil.dll");
		bool appCertKernel = R3ShieldCoreRules::IsHighRiskHostInjectionKey(
			L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCertDlls",
			L"C:\\Windows\\Temp\\evil.dll");

		Check("host", "AppCertDlls（CurrentControlSet 形态）", appCertCurrent, true);
		// ★ 关键：内核真实形态
		Check("host", "★ AppCertDlls（ControlSet001 形态，内核真实返回）", appCertKernel, true);

		Check("host", "★ BootExecute（ControlSet001 形态）",
			R3ShieldCoreRules::IsHighRiskHostInjectionKey(
				L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\BootExecute",
				L"C:\\Users\\Public\\evil.exe"), true);

		// 对照：值指向系统目录 → 不算高危（可能是系统自己在配）。
		Check("host", "AppCertDlls 值指向 System32（不算高危）",
			R3ShieldCoreRules::IsHighRiskHostInjectionKey(
				L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCertDlls",
				L"C:\\Windows\\System32\\legit.dll"), false);

		// 非注入键（对照）。
		Check("host", "普通键 + 用户目录值（不是注入键，不应命中）",
			R3ShieldCoreRules::IsHighRiskHostInjectionKey(
				L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3ShieldCoreV17Neutral",
				L"C:\\Windows\\Temp\\evil.dll"), false);
	}

	printf("\n%s  失败 %d\n", g_failed ? "=== 存在失败用例 ===" : "=== 全部通过 ===", g_failed);
	return g_failed;
}
