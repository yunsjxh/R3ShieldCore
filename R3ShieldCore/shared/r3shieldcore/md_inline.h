#pragma once
//
// md_inline.h —— 极简 **Markdown 行内**解析（只服务"把题目渲染给人看"）。
//
// ★ 为什么需要它
//   `advanced_quiz.h` 的题干与解析里**本来就写着 Markdown**：
//       `**预定义伪句柄**`、`` `Nt*` ``、缩进 8 空格的 `RegOpenKeyExW(...)`
//   那是给**控制台**看的记号 —— 终端里只能这么表达"这个词被强调了"。
//   但主程序「高级」页是**渲染**给眼睛看的：把原文直接画出来，
//   用户看到的是四个星号，而不是强调。
//   ⇒ 界面必须**解释**这些记号，而不是去改共享文本 ——
//     改了文本，控制台那边就不一致了（铁律 195：同一份逻辑不抄第二遍）。
//
// ★ 为什么不引第三方 Markdown 库
//   需要渲染的只有题干和解析，用到的东西只有四样：加粗、行内代码、
//   代码行、列表项。为这四样引一个库（还要处理它的编码/异常/体积），
//   不划算。
//
// ★ 为什么**解析**要单独抽出来（而不是和绘制写在一起）
//   "哪几个字是加粗的"是**纯文本逻辑**，可以单测；
//   "这几个字画在哪个像素"才需要 DC。
//   混在一起的话，Markdown 支不支持就只能靠**截图**去验 ——
//   而本项目吃过"靠人眼 = 假绿"的亏（铁律 24/28）。
//   所以：本文件只做解析（零依赖、可单测），绘制留在界面那一侧。
//
// ★ 支持范围（够用就好）
//     `**加粗**`         -> Style::Bold
//     `` `行内代码` ``   -> Style::Code
//     行首缩进 >= 8 空格 -> 整行当代码（codeLine = true）
//     行首 `- `          -> 圆点
//   不认识的记号（`#` 标题、链接、表格…）**原样当普通文字输出** ——
//   宁可显示得朴素，也不能把字符吞掉（吞了就是静默丢内容）。
//
// ★ 关于"缩进阈值为什么是 8 而不是 4"
//   共享文本里那两种缩进含义不同：
//     · 4 空格 = 控制台里"续行对齐"的记号，全是中文正文
//       （例：`    HKEY_LOCAL_MACHINE 这类固定常量）当作 RootDirectory 传进去…`）
//     · 8 空格 = 真代码行
//       （例：`        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Foo", …)`）
//   阈值取 4 的话，正文续行会被误判成代码，整段变成等宽 —— 很难看。
//
#include <string>
#include <vector>

namespace R3ShieldCoreMd
{
	enum class Style { Normal, Bold, Code };

	// 一段连续同风格的文本。
	struct Piece
	{
		std::wstring text;
		Style        style = Style::Normal;
	};

	inline bool IsBlank(wchar_t c)
	{
		return c == L' ' || c == L'\t' || c == L'\r';
	}

	// 一行原文 -> 若干 Piece。
	//
	// `codeLine` 为真表示"这一行整体是代码"（调用方通常会换等宽字体、
	// 加一点左缩进）。此时 `out` 里只有一个 Code piece，`text` 已去掉缩进。
	//
	// 行尾空白一律去掉（共享文本为了拼行，行尾可能留了空格）。
	inline void ParseLine(const std::wstring& raw, std::vector<Piece>& out, bool& codeLine)
	{
		out.clear();
		codeLine = false;

		// ---- 1. 去掉行尾空白 ----
		size_t end = raw.size();
		while (end > 0 && IsBlank(raw[end - 1])) {
			--end;
		}

		// ---- 2. 数行首缩进 ----
		size_t i = 0;
		while (i < end && (raw[i] == L' ' || raw[i] == L'\t')) {
			++i;
		}
		const size_t indent = i;

		if (indent >= 8) {
			// 整行代码
			codeLine = true;
			out.push_back({ raw.substr(i, end - i), Style::Code });
			return;
		}
		// indent 在 [4,8) 之间：那是控制台的续行记号，不是代码 ⇒
		// 把缩进去掉，当普通正文（否则每段续行都无端缩进一格）。

		// ---- 3. 行首 `- ` -> 圆点 ----
		//
		// ★ 为什么用 `\u25CF`（●）而不是 `\u2022`（•）：后者在 CP936 下
		//   **编不出**，会被 `check_source_gbk.py --wide` 拦下（铁律 226）。
		//   本文件这一行虽然只经 GDI 绘制、不会被转成 ANSI，但**没必要时**
		//   就别留这种"取决于谁调用"的隐患 —— 换一个 CP936 里有的圆点，
		//   这个隐患就不存在了，也不用写豁免。
		if (i + 1 < end && raw[i] == L'-' && raw[i + 1] == L' ') {
			out.push_back({ L"\u25CF ", Style::Normal });
			i += 2;
		}

		// ---- 4. 行内 `**加粗**` / `` `代码` `` ----
		//
		// 只在**成对**时才当成记号：找不到配对的星号/反引号就原样输出。
		// （题目里 `*` 也出现在通配写法里，比如 `Pass.*` —— 绝不能因为
		//   看到一个 `*` 就开始吃后面的字符。）
		std::wstring buf;
		auto flush = [&]() {
			if (!buf.empty()) {
				out.push_back({ buf, Style::Normal });
				buf.clear();
			}
		};

		while (i < end) {
			if (i + 1 < end && raw[i] == L'*' && raw[i + 1] == L'*') {
				const size_t close = raw.find(L"**", i + 2);
				if (close != std::wstring::npos && close < end) {
					flush();
					out.push_back({ raw.substr(i + 2, close - (i + 2)), Style::Bold });
					i = close + 2;
					continue;
				}
			}
			if (raw[i] == L'`') {
				const size_t close = raw.find(L'`', i + 1);
				if (close != std::wstring::npos && close < end) {
					flush();
					out.push_back({ raw.substr(i + 1, close - (i + 1)), Style::Code });
					i = close + 1;
					continue;
				}
			}
			buf.push_back(raw[i]);
			++i;
		}
		flush();
	}

	// 整段文本 -> 逐行解析（只是把 `\n` 切开再逐行调 ParseLine）。
	inline void ParseText(const std::wstring& text, std::vector<std::vector<Piece>>& out,
		std::vector<bool>& codeLines)
	{
		out.clear();
		codeLines.clear();

		std::wstring cur;
		for (size_t k = 0; k <= text.size(); ++k) {
			if (k == text.size() || text[k] == L'\n') {
				std::vector<Piece> pieces;
				bool codeLine = false;
				ParseLine(cur, pieces, codeLine);
				out.push_back(std::move(pieces));
				codeLines.push_back(codeLine);
				cur.clear();
				continue;
			}
			cur.push_back(text[k]);
		}
	}
}
