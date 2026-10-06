//
// ark_order_ut.cpp —— `r3shieldcore_ark.h` 里「列表分组 + 排序」判据的单测（v63）
//
// ==================================================================
// 为什么这个功能值得单测
// ==================================================================
//
// 分组排序看着是"界面小事"，但它是**纯判据**，而且错法全都是静默的：
//
//   · 判据写成"名字像 svchost 就算系统进程" -> 用户把任意程序改名成
//     svchost.exe 就能把自己排进系统组，**而且界面上看不出来**
//     （这正是铁律 4/102 说的"只看名字 = 假判"）。
//   · 排序谓词写反（`>` 而不是 `<`）-> 顺序颠倒，不报错、不崩，
//     只是列表变成"系统进程在最上面"。
//   · 排序不稳定 / 组内键不唯一 -> 列表每次扫描自己抖，用户点不准。
//
// 上面三条**都不会**让程序崩溃或报错，只会让结果错。所以必须有断言钉住。
//
// ==================================================================
// 为什么能"只链头文件"（见 build_ut.sh 的 run_ark_order_ut）
// ==================================================================
// `GroupRankOf` / `ArkRowLess` 是**纯函数**，刻意以 `inline` 形式放在
// `r3shieldcore_ark.h` 里 —— 这样引擎和本测试用的是**同一份代码**，
// 而不是"测试里照抄一遍判据"（照抄 = 判据改了测试不会红，等于没测）。
//
// 本文件**不**调用 `R3ShieldCoreArk::Start/Tick/...`（那些要引擎环境），
// 所以只需要头文件，不需要链 r3shieldcore_ark.cpp / wil / psapi。
//
// ★ 负向对照（铁律 54/103：没有对照的 PASS 不算通过）：
//   第 5 组专门构造"名字极像系统进程、但事实不是系统进程"的行。
//   如果哪天有人把判据改成看名字，那一组会立刻变红。
//
#include "r3shieldcore_ark.h"

#include <algorithm>
#include <locale.h>
#include <stdio.h>
#include <vector>

namespace
{
	int g_pass = 0;
	int g_fail = 0;

	void Check(bool ok, const char* what)
	{
		if (ok) {
			g_pass++;
			printf("  [PASS] %s\n", what);
		}
		else {
			g_fail++;
			printf("  [FAIL] %s\n", what);
		}
	}

	void CheckEq(unsigned long actual, unsigned long expected, const char* what)
	{
		if (actual == expected) {
			g_pass++;
			printf("  [PASS] %s (=%lu)\n", what, actual);
		}
		else {
			g_fail++;
			printf("  [FAIL] %s —— 期望 %lu，实际 %lu\n", what, expected, actual);
		}
	}

	// 造一行。只填判据用得到的字段，其余保持默认 ——
	// 这样"判据到底读了哪几个字段"本身就是被钉住的：
	// 如果将来有人往判据里加了 `ThreadCount > 4` 之类，本测试会立刻红。
	R3ShieldCoreArk::Row MakeRow(unsigned long pid, bool isSystem, bool hasOurDll)
	{
		R3ShieldCoreArk::Row row = {};
		row.Pid = pid;
		row.IsSystem = isSystem;
		row.HasOurDll = hasOurDll;
		row.Group = R3ShieldCoreArk::GroupRankOf(row);
		return row;
	}

	std::vector<unsigned long> GroupsOf(const std::vector<R3ShieldCoreArk::Row>& rows)
	{
		std::vector<unsigned long> out;
		for (const R3ShieldCoreArk::Row& row : rows) {
			out.push_back(R3ShieldCoreArk::GroupRankOf(row));
		}
		return out;
	}

	// ------------------------------------------------------------------
	// A. 分组判据（纯函数）
	// ------------------------------------------------------------------
	void SectionA_Rank()
	{
		printf("\n--- A. 分组判据 GroupRankOf ---\n");

		// 组 0：普通 + 已注入（用户最关心的那批）
		CheckEq(R3ShieldCoreArk::GroupRankOf(MakeRow(100, false, true)), 0,
			"普通进程 + 已注入 -> 0");

		// 组 1：普通 + 未注入
		CheckEq(R3ShieldCoreArk::GroupRankOf(MakeRow(200, false, false)), 1,
			"普通进程 + 未注入 -> 1");

		// 组 2：系统进程（未注入）
		CheckEq(R3ShieldCoreArk::GroupRankOf(MakeRow(300, true, false)), 2,
			"系统进程 + 未注入 -> 2");

		// ★ 系统优先于"已注入"：系统进程永远排最后，即使它被注入了。
		CheckEq(R3ShieldCoreArk::GroupRankOf(MakeRow(400, true, true)), 2,
			"系统进程 + 已注入 -> 2（系统优先，仍排最后）");

		// ★ 路径读不出来 -> IsSystem 是 false（引擎的既有定义）-> 归普通。
		//   这里显式把 PathKnown=false 也写出来，把"路径未知不猜"钉住。
		{
			R3ShieldCoreArk::Row row = MakeRow(500, false, false);
			row.PathKnown = false;
			row.Path = L"";
			CheckEq(R3ShieldCoreArk::GroupRankOf(row), 1,
				"路径未知（PathKnown=false）-> 1（不按名字猜成系统进程）");
		}

		// ★ 模块表读不出来（PPL 之类）-> HasOurDll 是 false，但语义是"未知"。
		//   归组 1（排序用），界面照旧把注入状态显示成"?"。
		{
			R3ShieldCoreArk::Row row = MakeRow(600, false, false);
			row.ModuleQueryOk = false;
			CheckEq(R3ShieldCoreArk::GroupRankOf(row), 1,
				"模块表未知（ModuleQueryOk=false）-> 1（不猜成已注入）");
		}

		// ★ 关键进程标记**不参与**分组：关键进程也可能是系统进程，
		//   但它排在哪个组只由 IsSystem 决定（关键与否只影响按钮可用性）。
		{
			R3ShieldCoreArk::Row row = MakeRow(700, false, false);
			row.IsCritical = true;
			CheckEq(R3ShieldCoreArk::GroupRankOf(row), 1,
				"关键标记不影响分组（普通路径 + 关键 -> 1）");
		}
	}

	// ------------------------------------------------------------------
	// B. 排序契约
	// ------------------------------------------------------------------
	void SectionB_Sort()
	{
		printf("\n--- B. 排序契约 ArkRowLess ---\n");

		// 故意乱序：混入三组，且组内 pid 也不是升序。
		std::vector<R3ShieldCoreArk::Row> rows;
		rows.push_back(MakeRow(900, true, false));   // 组 2
		rows.push_back(MakeRow(120, false, true));   // 组 0
		rows.push_back(MakeRow(700, false, false));  // 组 1
		rows.push_back(MakeRow(110, false, true));   // 组 0
		rows.push_back(MakeRow(880, true, true));    // 组 2
		rows.push_back(MakeRow(650, false, false));  // 组 1

		std::stable_sort(rows.begin(), rows.end(), R3ShieldCoreArk::ArkRowLess);

		// B1：分组非递减（= 三组顺序正确）
		const std::vector<unsigned long> groups = GroupsOf(rows);
		bool nonDecreasing = true;
		for (size_t i = 1; i < groups.size(); i++) {
			if (groups[i] < groups[i - 1]) {
				nonDecreasing = false;
			}
		}
		Check(nonDecreasing, "排序后分组非递减（已注入 → 未注入 → 系统）");

		// B2：组内 pid 升序
		bool pidAscending = true;
		for (size_t i = 1; i < rows.size(); i++) {
			const unsigned long gPrev = R3ShieldCoreArk::GroupRankOf(rows[i - 1]);
			const unsigned long gCur = R3ShieldCoreArk::GroupRankOf(rows[i]);
			if (gPrev == gCur && rows[i].Pid < rows[i - 1].Pid) {
				pidAscending = false;
			}
		}
		Check(pidAscending, "同组内 pid 升序");

		// B3：**精确**的期望序列。
		//   只断言"非递减"是不够的 —— 一个把全部行都判成组 0 的 bug
		//   也满足"非递减"。必须逐项钉死。
		const unsigned long expectedPids[6] = { 110, 120, 650, 700, 880, 900 };
		bool exact = (rows.size() == 6);
		for (size_t i = 0; exact && i < 6; i++) {
			if (rows[i].Pid != expectedPids[i]) {
				exact = false;
			}
		}
		Check(exact, "排序结果逐项匹配 110,120,650,700,880,900");

		// B4：`Row::Group` 字段与 `GroupRankOf()` 一致
		//   （引擎写进快照的字段必须和判据同源，否则界面上的"分组"
		//     和实际的排序会各说各话）。
		bool fieldMatches = true;
		for (const R3ShieldCoreArk::Row& row : rows) {
			if (row.Group != R3ShieldCoreArk::GroupRankOf(row)) {
				fieldMatches = false;
			}
		}
		Check(fieldMatches, "Row::Group 字段与 GroupRankOf() 一致");

		// B5：空表不崩（首轮扫描 / 枚举失败时会走到）
		{
			std::vector<R3ShieldCoreArk::Row> empty;
			std::stable_sort(empty.begin(), empty.end(), R3ShieldCoreArk::ArkRowLess);
			Check(empty.empty(), "空表排序不崩");
		}

		// B6：单行不崩
		{
			std::vector<R3ShieldCoreArk::Row> one;
			one.push_back(MakeRow(42, false, false));
			std::stable_sort(one.begin(), one.end(), R3ShieldCoreArk::ArkRowLess);
			Check(one.size() == 1 && one[0].Pid == 42, "单行排序不崩");
		}
	}

	// ------------------------------------------------------------------
	// C. 负向对照：判据一旦改成"看名字"就必须变红
	// ------------------------------------------------------------------
	void SectionC_NegativeControl()
	{
		printf("\n--- C. 负向对照（防「按名字猜」）---\n");

		// 名字极像系统进程，但事实是"路径未知 / 不在 SystemRoot 下"。
		// 引擎的既有定义：IsSystem 只在**路径可读且确实在 SystemRoot 下**
		// 才为 true -> 这里 IsSystem=false。
		const wchar_t* const names[4] = {
			L"svchost.exe", L"lsass.exe", L"services.exe", L"explorer.exe",
		};

		for (const wchar_t* name : names) {
			R3ShieldCoreArk::Row row = MakeRow(1000, false, false);
			row.Name = name;
			row.PathKnown = false;
			CheckEq(R3ShieldCoreArk::GroupRankOf(row), 1,
				"名字像系统进程但事实不是 -> 仍归 1（不按名字猜）");
		}

		// 反向：真的系统进程（IsSystem=true）即使名字很"普通"也归 2。
		{
			R3ShieldCoreArk::Row row = MakeRow(1001, true, false);
			row.Name = L"totally-not-a-system-name.exe";
			CheckEq(R3ShieldCoreArk::GroupRankOf(row), 2,
				"名字很普通但 IsSystem=true -> 归 2（事实优先于名字）");
		}
	}
}

int main()
{
	// ★ 铁律 55：控制台是 GBK，不设 locale 的话窄 printf 打中文会截断。
	setlocale(LC_ALL, "");

	printf("=== ark_order_ut（v63 列表分组 + 排序）===\n");

	SectionA_Rank();
	SectionB_Sort();
	SectionC_NegativeControl();

	printf("\n=== 结果: %d passed, %d failed ===\n", g_pass, g_fail);
	return (g_fail == 0) ? 0 : 1;
}
