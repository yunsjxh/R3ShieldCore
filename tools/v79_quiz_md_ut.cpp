//
// v79_quiz_md_ut.cpp —— v79「题干 / 解析渲染 Markdown」+「规则输入实时提示」单测。
//
// ★ 为什么这两样要单测（而不是只看截图）
//   v79 在「高级」页加了两件"看得见才算数"的东西：
//     ① 题干 / 解析里的 Markdown（`**加粗**`、`` `行内代码` ``、8 空格代码行）
//        现在**被渲染**了，而不是把四个星号原样画出来；
//     ② 输入框下面多了一对**实时提示**（"✓ 可以解析…" / "✗ 不认识的算子…"
//        / "下一步：写动作…"）。
//   两件事的**判据本身**都是纯文本逻辑，只有"画在哪个像素"才需要 DC：
//     · ① 的解析在 `md_inline.h`（零依赖）；
//     · ② 的"下一步"在 `rules_codec.h` 的 `NextStepHint`。
//   本项目吃过"靠人眼 = 假绿"的亏（铁律 24/28）—— 所以把这两处**抽出来**
//   单测，而不是靠一张截图去猜"那几个字到底加粗了没有"。
//
// ★ 与 `tools/test_gui_preview.sh` 的分工
//   本文件：**纯逻辑**，毫秒级，覆盖解析/提示的**全部分支**（含反向对照）。
//   那个脚本：真起窗口截图 + 断言日志，证明"这两样真的接到了界面上"。
//   缺一不可：只有截图 ⇒ 分支（未闭合的引号、4 空格 vs 8 空格）覆盖不全；
//             只有单测 ⇒ "解析对了但没画出来"没人证。
//
// ★ 反向对照（否则断言可能恒真）
//   · 4 空格缩进**不该**被当成代码行（共享文本里那是控制台的续行记号）；
//   · 未配对的 `*` / 反引号**不该**被吃掉（`Pass.*` 这种通配写法里就有 `*`）；
//   · `NextStepHint` 说"写完了"时，**仍然**可能 `Parse` 失败 —— 这一条
//     被显式钉住，因为界面要靠它决定"是继续引导、还是让用户看错误信息"。
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#include <string>
#include <vector>

#include <r3shieldcore/md_inline.h>
#include <r3shieldcore/rules_codec.h>
#include <r3shieldcore/advanced_quiz.h>

namespace Md = R3ShieldCoreMd;
namespace RScript = R3ShieldCoreRuleScript;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// ---------------------------------------------------------------- 工具

static bool PieceIs(const Md::Piece& p, const WCHAR* text, Md::Style style)
{
	return p.text == text && p.style == style;
}

// 一行 -> pieces（带 codeLine 出参）。
static void Parse1(const WCHAR* line, std::vector<Md::Piece>& out, bool& codeLine)
{
	Md::ParseLine(std::wstring(line), out, codeLine);
}

static int CountStyle(const std::vector<Md::Piece>& ps, Md::Style style)
{
	int n = 0;
	for (const Md::Piece& p : ps) {
		if (p.style == style) ++n;
	}
	return n;
}

// ---------------------------------------------------------------- ① Markdown 解析

static void TestMdBasic()
{
	printf("\n-- Markdown 行内解析 --\n");

	std::vector<Md::Piece> ps;
	bool code = false;

	// 纯文本
	Parse1(L"plain text", ps, code);
	Check("plain: 1 piece / Normal / no code line",
		ps.size() == 1 && PieceIs(ps[0], L"plain text", Md::Style::Normal) && !code);

	// `**加粗**`
	Parse1(L"a **b** c", ps, code);
	Check("bold: a / BOLD b / c",
		ps.size() == 3
		&& PieceIs(ps[0], L"a ", Md::Style::Normal)
		&& PieceIs(ps[1], L"b", Md::Style::Bold)
		&& PieceIs(ps[2], L" c", Md::Style::Normal));

	// `` `行内代码` ``
	Parse1(L"x `y` z", ps, code);
	Check("code: x / CODE y / z",
		ps.size() == 3
		&& PieceIs(ps[0], L"x ", Md::Style::Normal)
		&& PieceIs(ps[1], L"y", Md::Style::Code)
		&& PieceIs(ps[2], L" z", Md::Style::Normal));

	// 8 空格缩进 = 整行代码
	Parse1(L"        RegOpenKeyExW(&h)", ps, code);
	Check("8-space indent -> codeLine, single Code piece",
		code && ps.size() == 1
		&& PieceIs(ps[0], L"RegOpenKeyExW(&h)", Md::Style::Code));

	// ★ 反向对照：4 空格是**控制台的续行记号**，不是代码
	Parse1(L"    HKEY_LOCAL_MACHINE 这类固定常量", ps, code);
	Check("NEG: 4-space indent -> NOT code, indent stripped",
		!code && ps.size() == 1
		&& PieceIs(ps[0], L"HKEY_LOCAL_MACHINE 这类固定常量", Md::Style::Normal));

	// 列表项（圆点用 U+25CF ● —— CP936 里有的那个，见 md_inline.h 的说明）
	Parse1(L"- item", ps, code);
	Check("bullet: dot + item",
		ps.size() == 2
		&& PieceIs(ps[0], L"\u25CF ", Md::Style::Normal)
		&& PieceIs(ps[1], L"item", Md::Style::Normal));

	// ★ 反向对照：未配对的 `**` / 反引号必须**原样输出**（不能吞字符）
	Parse1(L"a ** b", ps, code);
	Check("NEG: unpaired ** stays literal",
		ps.size() == 1 && PieceIs(ps[0], L"a ** b", Md::Style::Normal));

	Parse1(L"Pass.*", ps, code);
	Check("NEG: 'Pass.*' (single *) stays literal",
		ps.size() == 1 && PieceIs(ps[0], L"Pass.*", Md::Style::Normal));

	Parse1(L"a ` b", ps, code);
	Check("NEG: unpaired backtick stays literal",
		ps.size() == 1 && PieceIs(ps[0], L"a ` b", Md::Style::Normal));

	// 行尾空白去掉
	Parse1(L"text   ", ps, code);
	Check("trailing blanks trimmed",
		ps.size() == 1 && PieceIs(ps[0], L"text", Md::Style::Normal));

	// 空行
	Parse1(L"", ps, code);
	Check("empty line -> no piece, not code", ps.empty() && !code);

	// 整段（`\n` 切行）
	{
		std::vector<std::vector<Md::Piece>> lines;
		std::vector<bool> codes;
		Md::ParseText(std::wstring(L"l1\nl2"), lines, codes);
		Check("ParseText: 2 lines",
			lines.size() == 2 && codes.size() == 2
			&& lines[0].size() == 1 && PieceIs(lines[0][0], L"l1", Md::Style::Normal)
			&& lines[1].size() == 1 && PieceIs(lines[1][0], L"l2", Md::Style::Normal));
	}
}

// ★ 真实题目文本：证明"这套记号在**实际内容**里确实用到了"。
//
//   为什么值得单独一条：`md_inline.h` 全绿也只能说明"给它记号它会解"。
//   万一题目里的记号被改没了（或改成别的写法），渲染器就成了摆设 ——
//   而界面上看起来**完全正常**（只是没加粗）。这条断言把"内容里真有记号"
//   钉住：它红了就说明要么解析器坏了、要么题目不再用 md 了，两者都该看一眼。
static void TestQuizContentUsesMd()
{
	printf("\n-- 真实题目文本里的 Markdown 记号 --\n");

	const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();

	std::vector<std::vector<Md::Piece>> lines;
	std::vector<bool> codes;

	// 第 1 题题干里有 `**预定义伪句柄**`
	Md::ParseText(std::wstring(q[0].text), lines, codes);
	{
		int bold = 0;
		for (const auto& ln : lines) bold += CountStyle(ln, Md::Style::Bold);
		Check("Q1 stem contains a BOLD piece (from **...**)", bold >= 1);
	}

	// 第 1 题解析里有 `` `Nt*` ``
	Md::ParseText(std::wstring(q[0].why), lines, codes);
	{
		int code = 0;
		for (const auto& ln : lines) code += CountStyle(ln, Md::Style::Code);
		Check("Q1 why contains a CODE piece (from `...`)", code >= 1);
	}

	// 第 3 题题干里那行 `RegOpenKeyExW(...)` 是 8 空格缩进
	Md::ParseText(std::wstring(q[2].text), lines, codes);
	{
		int codeLines = 0;
		for (bool b : codes) if (b) ++codeLines;
		Check("Q3 stem contains a code LINE (8-space RegOpenKeyExW)", codeLines >= 1);
	}
}

// ---------------------------------------------------------------- ② 输入提示

static std::wstring Hint(const WCHAR* line)
{
	return RScript::NextStepHint(line);
}

static bool ParseFails(const WCHAR* line)
{
	RScript::Rule r;
	std::wstring err;
	return !RScript::Parse(line, r, err);
}

static void TestNextStepHint()
{
	printf("\n-- 输入提示 NextStepHint --\n");

	Check("empty -> start with Dang",
		Hint(L"") == L"每条规则都以「当」开头");
	Check("only Dang -> write face",
		Hint(L"当") == L"写面：注册表值 / 注册表枚举 / 剪贴板 / 文件 / 截屏");
	Check("face only -> write operator",
		Hint(L"当 注册表值") == L"写算子：等于 / 含 / 匹配 / 开头 / 结尾");
	Check("face+de -> write operator",
		Hint(L"当 注册表值 的") == L"写算子：等于 / 含 / 匹配 / 开头 / 结尾");
	Check("face+de+field+op -> write pattern",
		Hint(L"当 注册表值 的 值名 含") == L"写模式：\"文本\" 或 /正则/");
	Check("+pattern -> write 'Shi'",
		Hint(L"当 注册表值 的 值名 含 \"a\"") == L"写「时」");
	Check("+Shi -> write action",
		Hint(L"当 注册表值 的 值名 含 \"a\" 时")
			== L"写动作：替换为 … / 替换为图 …（截屏面）/ 隐藏（枚举面）/ 拒绝 / 放行");
	Check("complete -> empty hint",
		Hint(L"当 注册表值 的 值名 含 \"a\" 时 替换为 \"b\"") == L"");

	// 省略字段也认（字段是可选段）
	Check("field omitted -> still walks to action",
		Hint(L"当 剪贴板 含 \"a\" 时") == L"写动作：替换为 … / 替换为图 …（截屏面）/ 隐藏（枚举面）/ 拒绝 / 放行");
	Check("clipboard full rule -> empty hint",
		Hint(L"当 剪贴板 的 格式 等于 文本 时 替换为 \"x\"") == L"");

	// 未闭合的字面量：提示要说"先补全"
	{
		const std::wstring h = Hint(L"当 注册表值 的 值名 含 \"a");
		Check("unterminated string -> '先补全：…'", h.rfind(L"先补全：", 0) == 0);
	}
	{
		const std::wstring h = Hint(L"当 注册表值 的 值名 匹配 /a");
		Check("unterminated regex -> '先补全：…'", h.rfind(L"先补全：", 0) == 0);
	}

	// ★★ 分工必须钉住：`NextStepHint` 说"写完了"（返回空串）时，
	//    这一行**仍然可能**解析不了 —— 界面据此才敢分两种话术
	//    （继续引导 vs 让用户看 ✗ 的错误信息）。
	//    这里用一个"位置都对、但算子不认识"的写法制造这种状态。
	{
		const WCHAR* bad = L"当 注册表值 的 值名 模糊 /a/ 时 替换为 \"x\"";
		Check("scanner says complete (empty hint)", Hint(bad) == L"");
		Check("but Parse still rejects it (wrong operator)",
			ParseFails(bad));
	}

	// 反向对照：合法规则**不该**被判失败（否则上面那条就没意义了）
	Check("NEG: valid rule parses OK",
		!ParseFails(L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\""));
}

int main()
{
	printf("=== v79 单测：题干 Markdown 渲染 + 规则输入提示 ===\n");

	TestMdBasic();
	TestQuizContentUsesMd();
	TestNextStepHint();

	printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
