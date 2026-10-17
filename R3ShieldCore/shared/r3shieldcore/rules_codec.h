// rules_codec.h —— 「替换 API 结果」的**规则引擎**（中文规则 + 正则）
//
// ★ 为什么抽成共享头（铁律 195：同一份逻辑不抄第二遍）
//   规则引擎有几处要用，行为必须**逐字一致**：
//     · `tools/spoof_console.cpp`             —— 交互式控制台（高级模式）
//     · `R3ShieldCore/r3shieldcore_gui.cpp`   —— 主程序「高级」页签
//     · `R3ShieldCoreLib/registry_guard.cpp`  —— 引擎侧注册表值 / 枚举两个替换点
//     · `R3ShieldCoreLib/clipboard_guard.cpp` —— 引擎侧剪贴板替换点
//   所以它必须是一个 header-only 的共享 codec，而不是各写一份。
//
// ★★ 命名空间为什么**不叫** `R3ShieldCoreRules`（v78 改名，别改回去）
//   引擎侧另有一个 `R3ShieldCoreLib/r3shieldcore_rules.h`，它声明的也是
//   `namespace R3ShieldCoreRules` —— 那是**编译期定长的高危规则表**
//   （`IsHighRiskRegistry` / `IsHighRiskFile` …），与本文件的**中文 DSL
//   规则脚本**是两回事。两边一旦出现在**同一个翻译单元**（引擎侧接入
//   必然如此：`registry_guard.cpp` 两个头都要 include），命名空间就会**合并**：
//   当前符号恰好不重名，所以能编过 —— 但那是巧合，不是设计。
//   往后任一侧新增一个同名函数（`Count()` / `Add()` / `Parse()` …）就会
//   静默变成重载/冲突，而**错误信息指向的是另一个文件**。
//   ⇒ 本文件的命名空间定为 `R3ShieldCoreRuleScript`（"规则脚本"），
//     与"高危规则表"在名字上就分得开。引用点只有 4 处（本文件 +
//     `spoof_apply_codec.h` 的两个 using + GUI/控制台各一行别名）。
//
// ★ 语法（刻意做得像易语言）
//       当 <面> [的 <字段>] <算子> <模式> 时 <动作>
//
//     面   : 注册表值 | 注册表枚举 | 剪贴板
//     字段 : 值名 | 键路径 | 子键名 | 格式      （可省，用该面的默认字段）
//     算子 : 等于 | 含 | 匹配 | 开头 | 结尾     （匹配 = 正则，模式写 /.../）
//     模式 : "文本"  或  /正则/
//     动作 : 替换为 "文本" | 替换为 全零 | 替换为 全FF | 替换为 空
//            | 隐藏（只对枚举面） | 拒绝 | 放行
//
//   例：
//     当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 "***"
//     当 剪贴板 的 格式 等于 文本 时 替换为 "假的"
//     当 注册表枚举 的 子键名 含 "Secret" 时 隐藏
//
// ★ 求值：**按加入顺序，第一条命中的生效**（first-match wins）。
//   一条都没命中 ⇒ 由**调用方**回落自己的默认行为（控制台是 fill/hide/fakeclip）。
//
// ★ 解析期就挡住"面 × 动作"不相容的写法（`隐藏` 只对枚举面、`全XX` 对剪贴板面
//   不支持）—— 否则运行时静默不生效，这类"看着加上了其实没用"最费时间。
//
// ★ 线程：改规则与求值可能来自不同线程 ⇒ 一把 mutex 护住。
//   求值路径只读，规则表通常很小（几十条），开销可忽略。
//
// ★ 全部 inline / header-only：不引入 .cpp，不进构建脚本的文件列表。
//
#pragma once

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>

#include <string>
#include <vector>
#include <regex>
#include <mutex>
#include <initializer_list>

namespace R3ShieldCoreRuleScript {

	// 大小写不敏感的子串查找（ASCII 折叠）。
	// 从控制台那版 `ContainsW(hay, hayChars, needle)` 收敛成两参数版 ——
	// 头文件里的调用方都只关心"hay 里有没有 needle"。
	inline bool ContainsNoCase(const WCHAR* hay, const WCHAR* needle)
	{
		if (!hay || !needle) return false;
		const size_t hlen = wcslen(hay);
		const size_t nlen = wcslen(needle);
		if (nlen == 0 || hlen < nlen) return false;
		for (size_t i = 0; i + nlen <= hlen; ++i) {
			size_t j = 0;
			for (; j < nlen; ++j) {
				WCHAR a = hay[i + j], b = needle[j];
				if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a - L'A' + L'a');
				if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b - L'A' + L'a');
				if (a != b) break;
			}
			if (j == nlen) return true;
		}
		return false;
	}


enum class Face  { RegValue, RegEnum, Clip };
enum class Field { Name, Path, Format };   // Name：值名(值面) / 子键名(枚举面)
enum class Op    { Equal, Contains, Regex, StartsWith, EndsWith };
enum class Act   { ReplaceText, ReplaceByte, ReplaceEmpty, Hide, Block, Pass };

struct Rule {
	Face  face  = Face::RegValue;
	Field field = Field::Name;
	Op    op    = Op::Contains;
	std::wstring pattern;
	std::wregex  re;
	bool         hasRe = false;

	Act          act  = Act::ReplaceEmpty;
	std::wstring text;          // Act::ReplaceText 用
	BYTE         fill = 0;      // Act::ReplaceByte 用
	std::wstring src;           // 原始文本（列表显示用）
};

// 求值结果
struct Verdict {
	bool hit = false;
	int  index = -1;            // 命中的规则序号（0 起）
	Act  act = Act::Pass;
	std::wstring text;
	BYTE fill = 0;
};

// ★★ 为什么状态是 `inline` 而不是 `static`（v78，别改回去）
//   本头文件在**同一个模块里会被多个 TU 包含**（引擎侧：`registry_guard.cpp`
//   与 `clipboard_guard.cpp` 各包含一次）。`static` 是**内部链接** ⇒ 每个 TU
//   一份 ⇒ **两张互不相干的规则表**：注册表那边 `Add()` 的规则，剪贴板那边
//   一条都看不到，而且**谁都不报错**。
//   `inline`（C++17）给的是"整个模块**一份**"⇒ 两侧共用同一张表。
//   ⚠️ 跨模块（exe / dll）仍然是各一份 —— 那是对的：规则文件在每个
//      被注入进程里各加载一次（见 `rules_script_runtime.h`）。
inline std::vector<Rule> g_rules;
inline std::mutex        g_mtx;

// 最近一次命中（供 attack 打印 —— detour 里不能直接 Say）
inline volatile LONG g_lastHit = -1;
inline WCHAR         g_lastHitText[512] = L"";

static void NoteHit(int idx, const WCHAR* desc)
{
	InterlockedExchange(&g_lastHit, idx);
	if (desc) wcsncpy_s(g_lastHitText, _countof(g_lastHitText), desc, _TRUNCATE);
	else      g_lastHitText[0] = L'\0';
}

static std::wstring AnsiToW(const char* s)
{
	if (!s) return L"";
	const int n = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
	if (n <= 0) return L"";
	std::wstring w((size_t)n, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s, -1, &w[0], n);
	w.resize((size_t)n - 1);
	return w;
}

// ---------------------------------------------------------------- 词法
enum class TokKind { Word, Str, Regex };

struct Tok {
	TokKind kind;
	std::wstring text;
};

// 切 token：
//   · `"..."` / `“...”`  -> Str（内部文本，可以带空格）
//   · `/.../`            -> Regex（正则字面量，可以带空格）
//   · 其余按空白切        -> Word
static bool Tokenize(const WCHAR* line, std::vector<Tok>& out, std::wstring& err)
{
	const WCHAR* p = line;
	while (*p) {
		while (*p == L' ' || *p == L'\t') ++p;
		if (!*p) break;

		if (*p == L'/') {
			const WCHAR* q = p + 1;
			std::wstring body;
			while (*q && *q != L'/') body.push_back(*q++);
			if (*q != L'/') { err = L"正则字面量没闭合：缺一个结尾的 /"; return false; }
			if (body.empty()) { err = L"正则字面量是空的"; return false; }
			out.push_back({ TokKind::Regex, body });
			p = q + 1;
			continue;
		}

		if (*p == L'"' || *p == L'\x201C') {
			const WCHAR close = (*p == L'"') ? L'"' : L'\x201D';
			const WCHAR* q = p + 1;
			std::wstring body;
			while (*q && *q != close) body.push_back(*q++);
			if (*q != close) { err = L"字符串没闭合：缺一个结尾的引号"; return false; }
			out.push_back({ TokKind::Str, body });
			p = q + 1;
			continue;
		}

		const WCHAR* q = p;
		while (*q && *q != L' ' && *q != L'\t') ++q;
		out.push_back({ TokKind::Word, std::wstring(p, q) });
		p = q;
	}
	return true;
}

static bool IsWord(const Tok& t, const WCHAR* w) { return t.kind == TokKind::Word && t.text == w; }

static bool WordIn(const Tok& t, std::initializer_list<const WCHAR*> names)
{
	if (t.kind != TokKind::Word) return false;
	for (const WCHAR* w : names) if (t.text == w) return true;
	return false;
}

// 「这个词是不是字段名」—— **唯一一处**判据。
//
// ★ 为什么单独抽出来（v79）：这个集合有两个读者 ——
//     · `Parse`：决定"这里到底是字段、还是已经进到算子了"；
//     · `NextStepHint`：给界面算"下一步该写什么"。
//   写两遍必然漂（铁律 127）：漂了之后，用户在提示的引导下敲了一个
//   合法别名，`Parse` 却认不出来 —— 表现是"提示说这么写，写完又报错"，
//   最难查的一类不一致。
//   ⚠️ 新增字段别名：**先加进这里**，再去 `Parse` 的映射里补一行
//      （两处在同一文件、紧挨着）。
static bool IsFieldWord(const std::wstring& s)
{
	return s == L"值名" || s == L"名字" || s == L"名称" || s == L"name"
	    || s == L"键路径" || s == L"路径" || s == L"path"
	    || s == L"子键名" || s == L"子键" || s == L"child"
	    || s == L"格式" || s == L"format";
}

// ---------------------------------------------------------------- 匹配
static bool EndsWithW(const WCHAR* s, const WCHAR* suf)
{
	const size_t a = wcslen(s), b = wcslen(suf);
	if (b > a) return false;
	return _wcsicmp(s + (a - b), suf) == 0;
}

static bool StartsWithW(const WCHAR* s, const WCHAR* pre)
{
	return _wcsnicmp(s, pre, wcslen(pre)) == 0;
}

static bool MatchOne(const Rule& r, const WCHAR* value)
{
	if (!value) return false;
	switch (r.op) {
	case Op::Equal:      return _wcsicmp(value, r.pattern.c_str()) == 0;
	case Op::Contains:   return ContainsNoCase(value, r.pattern.c_str());
	case Op::StartsWith: return StartsWithW(value, r.pattern.c_str());
	case Op::EndsWith:   return EndsWithW(value, r.pattern.c_str());
	case Op::Regex:
		if (!r.hasRe) return false;
		try { return std::regex_search(value, r.re); }
		catch (...) { return false; }
	}
	return false;
}

// ---------------------------------------------------------------- 解析
// 语法： 当 <面> [的] [<字段>] <算子> <模式> 时 <动作...>
static bool Parse(const WCHAR* line, Rule& r, std::wstring& err)
{
	std::vector<Tok> t;
	if (!Tokenize(line, t, err)) return false;
	if (t.size() < 5) {
		err = L"规则太短。形如：当 注册表值 的 值名 含 \"Password\" 时 替换为 \"***\"";
		return false;
	}
	if (!IsWord(t[0], L"当")) { err = L"规则必须以「当」开头"; return false; }

	size_t i = 1;

	// --- 面 ---
	if (WordIn(t[i], { L"注册表值", L"值", L"reg", L"regvalue", L"value" }))        r.face = Face::RegValue;
	else if (WordIn(t[i], { L"注册表枚举", L"枚举", L"regenum", L"enum", L"key" })) r.face = Face::RegEnum;
	else if (WordIn(t[i], { L"剪贴板", L"clip", L"clipboard" }))                    r.face = Face::Clip;
	else { err = L"不认识的面：「" + t[i].text + L"」。可用：注册表值 / 注册表枚举 / 剪贴板"; return false; }
	++i;

	// --- 可选「的」---
	if (i < t.size() && IsWord(t[i], L"的")) ++i;

	// --- 字段（可省；省了就用该面的默认字段）---
	r.field = (r.face == Face::Clip) ? Field::Format : Field::Name;
	if (i < t.size() && t[i].kind == TokKind::Word && IsFieldWord(t[i].text)) {
		if (WordIn(t[i], { L"值名", L"名字", L"名称", L"name" })) r.field = Field::Name;
		else if (WordIn(t[i], { L"键路径", L"路径", L"path" }))   r.field = Field::Path;
		else if (WordIn(t[i], { L"子键名", L"子键", L"child" }))  r.field = Field::Name;
		else                                                     r.field = Field::Format;
		++i;
	}

	// --- 算子 ---
	if (i >= t.size()) { err = L"缺算子（等于 / 含 / 匹配 / 开头 / 结尾）"; return false; }
	if (WordIn(t[i], { L"等于", L"是", L"=", L"==", L"equal" }))      r.op = Op::Equal;
	else if (WordIn(t[i], { L"含", L"包含", L"contains" }))           r.op = Op::Contains;
	else if (WordIn(t[i], { L"匹配", L"正则", L"match", L"regex" }))  r.op = Op::Regex;
	else if (WordIn(t[i], { L"开头", L"starts" }))                    r.op = Op::StartsWith;
	else if (WordIn(t[i], { L"结尾", L"ends" }))                      r.op = Op::EndsWith;
	else { err = L"不认识的算子：「" + t[i].text + L"」。可用：等于 / 含 / 匹配 / 开头 / 结尾"; return false; }
	const Op op = r.op;
	++i;

	// --- 模式 ---
	if (i >= t.size()) { err = L"缺匹配模式（\"文本\" 或 /正则/）"; return false; }
	r.pattern = t[i].text;
	if (op == Op::Regex) {
		if (t[i].kind != TokKind::Regex) { err = L"「匹配」后面要跟 /正则/（用斜杠包起来）"; return false; }
		try { r.re = std::wregex(r.pattern, std::regex::icase); r.hasRe = true; }
		catch (const std::regex_error& e) { err = L"正则写错了：" + AnsiToW(e.what()); return false; }
	}
	++i;

	// --- 时 ---
	if (i >= t.size() || !IsWord(t[i], L"时")) { err = L"模式后面要跟「时」"; return false; }
	++i;

	// --- 动作 ---
	if (i >= t.size()) { err = L"缺动作（替换为 … / 隐藏 / 拒绝 / 放行）"; return false; }
	if (WordIn(t[i], { L"替换为", L"改成", L"replace" })) {
		++i;
		if (i >= t.size()) { err = L"「替换为」后面要跟内容（\"文本\" / 全零 / 全FF / 空）"; return false; }
		if (t[i].kind == TokKind::Str) { r.act = Act::ReplaceText; r.text = t[i].text; }
		else if (IsWord(t[i], L"空"))  { r.act = Act::ReplaceEmpty; }
		else if (t[i].text.size() >= 2 && t[i].text[0] == L'全') {
			std::wstring hex = t[i].text.substr(1);
			if (hex == L"零") hex = L"00";
			if (hex.size() > 2) { err = L"字节填充最多两位十六进制，如 全FF"; return false; }
			wchar_t* end = nullptr;
			const long v = wcstol(hex.c_str(), &end, 16);
			if (end == hex.c_str() || *end != L'\0' || v < 0 || v > 0xFF) {
				err = L"不认识的填充值：「" + t[i].text + L"」（试 全零 / 全FF / 全41）"; return false;
			}
			r.act = Act::ReplaceByte;
			r.fill = (BYTE)v;
		}
		else { err = L"「替换为」的内容要是 \"文本\" / 全零 / 全FF / 空"; return false; }
	}
	else if (WordIn(t[i], { L"隐藏", L"藏起来", L"hide" }))          r.act = Act::Hide;
	else if (WordIn(t[i], { L"拒绝", L"拦", L"block", L"deny" }))    r.act = Act::Block;
	else if (WordIn(t[i], { L"放行", L"通过", L"pass", L"allow" }))  r.act = Act::Pass;
	else { err = L"不认识的动作：「" + t[i].text + L"」。可用：替换为 … / 隐藏 / 拒绝 / 放行"; return false; }
	++i;

	if (i < t.size()) { err = L"「" + t[i].text + L"」是多余的（动作之后不该再有内容）"; return false; }

	// 面 × 动作 的相容性（提前挡住写错，而不是运行时静默不生效）
	if (r.act == Act::Hide && r.face != Face::RegEnum) {
		err = L"「隐藏」只对「注册表枚举」有意义"; return false;
	}
	if (r.face == Face::RegEnum && r.act != Act::Hide && r.act != Act::Pass && r.act != Act::Block) {
		err = L"注册表枚举面的动作只能是：隐藏 / 放行 / 拒绝"; return false;
	}
	if (r.act == Act::ReplaceByte && r.face == Face::Clip) {
		err = L"剪贴板面不支持「全XX」字节填充（试 替换为 \"文本\" 或 替换为 空）"; return false;
	}
	r.src = line;
	return true;
}

// ---------------------------------------------------------------- 表操作
static bool Add(const WCHAR* line, std::wstring& err, int* outIndex)
{
	Rule r;
	if (!Parse(line, r, err)) return false;
	std::lock_guard<std::mutex> lk(g_mtx);
	g_rules.push_back(r);
	if (outIndex) *outIndex = (int)g_rules.size() - 1;
	return true;
}

static int  Count() { std::lock_guard<std::mutex> lk(g_mtx); return (int)g_rules.size(); }
static void Clear() { std::lock_guard<std::mutex> lk(g_mtx); g_rules.clear(); }

// 表里有没有针对某个面的规则。
//
// ★ 语义是**保守上界**（给引擎侧做预筛用，与 `CouldHaveProtectedChildRegistry`
//   同一套路）：返回 false ⇒ 这个面**一条规则都没有** ⇒ 调用方可以**完全跳过**
//   规则求值。枚举面尤其需要 —— 它一次调用要逐个子项问规则，
//   不预筛的话每次枚举都要多扫一遍表。
//   ★ 方向：宁可多问一次，不可漏问（假阳性只是慢，假阴性 = 规则静默不生效）。
static bool HasFace(Face face)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	for (const Rule& r : g_rules) {
		if (r.face == face) return true;
	}
	return false;
}

static bool RemoveAt(int idx)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	if (idx < 0 || idx >= (int)g_rules.size()) return false;
	g_rules.erase(g_rules.begin() + idx);
	return true;
}

// ---------------------------------------------------------------- 求值
static Verdict Eval(Face face, const WCHAR* path, const WCHAR* name, const WCHAR* fmt)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	for (size_t k = 0; k < g_rules.size(); ++k) {
		const Rule& r = g_rules[k];
		if (r.face != face) continue;
		const WCHAR* v = nullptr;
		switch (r.field) {
		case Field::Name:   v = name; break;
		case Field::Path:   v = path; break;
		case Field::Format: v = fmt;  break;
		}
		if (!v) continue;
		if (!MatchOne(r, v)) continue;

		Verdict vd;
		vd.hit   = true;
		vd.index = (int)k;
		vd.act   = r.act;
		vd.text  = r.text;
		vd.fill  = r.fill;
		return vd;
	}
	return Verdict{};
}

// ---------------------------------------------------------------- 描述（打印用）
static const WCHAR* FaceName(Face f)
{
	switch (f) { case Face::RegValue: return L"注册表值"; case Face::RegEnum: return L"注册表枚举"; default: return L"剪贴板"; }
}
static const WCHAR* OpName(Op o)
{
	switch (o) {
	case Op::Equal: return L"等于"; case Op::Contains: return L"含";
	case Op::Regex: return L"匹配"; case Op::StartsWith: return L"开头"; default: return L"结尾";
	}
}
static std::wstring ActDesc(const Rule& r)
{
	switch (r.act) {
	case Act::ReplaceText:  return L"替换为 \"" + r.text + L"\"";
	case Act::ReplaceByte: {
		WCHAR b[16]; _snwprintf_s(b, _countof(b), _TRUNCATE, L"全%02X", r.fill); return b;
	}
	case Act::ReplaceEmpty: return L"替换为 空";
	case Act::Hide:         return L"隐藏";
	case Act::Block:        return L"拒绝";
	default:                return L"放行";
	}
}

static std::wstring Describe(const Rule& r)
{
	std::wstring s = L"当 ";
	s += FaceName(r.face);
	s += L" 的 ";
	switch (r.field) {
	case Field::Path:   s += L"键路径"; break;
	case Field::Format: s += L"格式";   break;
	default:            s += (r.face == Face::RegEnum) ? L"子键名" : L"值名"; break;
	}
	s += L" ";
	s += OpName(r.op);
	s += L" ";
	s += (r.op == Op::Regex) ? (L"/" + r.pattern + L"/") : (L"\"" + r.pattern + L"\"");
	s += L" 时 ";
	s += ActDesc(r);
	return s;
}

static bool DescribeAt(int idx, std::wstring& out)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	if (idx < 0 || idx >= (int)g_rules.size()) return false;
	out = Describe(g_rules[idx]);
	return true;
}

static void ListAll(std::vector<std::wstring>& out)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	out.clear();
	for (const Rule& r : g_rules) out.push_back(Describe(r));
}

// ---------------------------------------------------------------- 输入提示
// 「这一行写到哪一段了、下一段该写什么」—— 给界面的**实时提示**用。
//
// ★ 它**只用于提示，不参与判定**。
//   一行规则到底能不能用，永远由 `Parse` 说了算（`Add` 也是先 `Parse`）。
//   所以这里即便说错了，最多是"提示不准" —— 不会让一条合法规则被拒，
//   也不会让一条非法规则混进表里。这是它敢做"轻量扫描"而不是
//   "把 Parse 抄一遍"的前提。
//
// ★ 为什么要它：DSL 是中文的，用户**改到一半**（把 `含` 改成 `匹配`、
//   再补一个 `/正则/`）时界面上没有任何反馈，只能点一次「加入」才知道
//   错在哪 —— 而"点了才知道错"正是最劝退的交互。
//
// ★ 返回空串 = "按语法看已经写完了"（至于它到底能不能用，看 `Parse`）。
//   界面据此分两种话术：写完了还报错 ⇒ 让用户看错误信息；
//   没写完 ⇒ 直接告诉下一段该写什么。
static std::wstring NextStepHint(const WCHAR* line)
{
	std::vector<Tok> t;
	std::wstring terr;
	if (!Tokenize(line, t, terr)) {
		return L"先补全：" + terr;      // 引号 / 斜杠没闭合
	}

	size_t i = 0;
	if (i >= t.size()) {
		return L"每条规则都以「当」开头";
	}
	if (!(t[i].kind == TokKind::Word && t[i].text == L"当")) {
		return L"开头要写「当」";
	}
	++i;                                                        // 当

	if (i >= t.size()) {
		return L"写面：注册表值 / 注册表枚举 / 剪贴板";
	}
	++i;                                                        // 面

	if (i < t.size() && t[i].kind == TokKind::Word && t[i].text == L"的") {
		++i;                                                    // 可选「的」
	}
	if (i < t.size() && t[i].kind == TokKind::Word && IsFieldWord(t[i].text)) {
		++i;                                                    // 可选字段
	}
	if (i >= t.size()) {
		return L"写算子：等于 / 含 / 匹配 / 开头 / 结尾";
	}
	++i;                                                        // 算子

	if (i >= t.size()) {
		return L"写模式：\"文本\" 或 /正则/";
	}
	++i;                                                        // 模式

	if (i >= t.size()) {
		return L"写「时」";
	}
	if (!(t[i].kind == TokKind::Word && t[i].text == L"时")) {
		return L"模式后面要写「时」";
	}
	++i;                                                        // 时

	if (i >= t.size()) {
		return L"写动作：替换为 … / 隐藏 / 拒绝 / 放行";
	}
	return L"";                                                 // 写完了
}

// 存盘：UTF-8（带 BOM，记事本友好），一行一条 —— 存出来的东西能直接 `rule load` 回来
static bool SaveFile(const WCHAR* path, int* count)
{
	std::lock_guard<std::mutex> lk(g_mtx);
	// ★ `_wfopen` 的 C4996（"不安全"）只在**没定义** `_CRT_SECURE_NO_WARNINGS`
	//   的翻译单元里冒出来 —— 控制台的构建脚本定义了它，主程序没有。
	//   本头文件被两处共用，所以**就地**关掉这一条（只关 4996、只作用于下一行），
	//   而不是要求每个调用方都去改自己的编译参数。
#pragma warning(suppress: 4996)
	FILE* f = _wfopen(path, L"wb");
	if (!f) return false;
	fputs("\xEF\xBB\xBF", f);
	for (const Rule& r : g_rules) {
		const std::wstring s = r.src.empty() ? Describe(r) : r.src;
		const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
		if (n > 0) {
			std::vector<char> b((size_t)n);
			WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), b.data(), n, nullptr, nullptr);
			fwrite(b.data(), 1, (size_t)n, f);
		}
		fputs("\r\n", f);
	}
	fclose(f);
	if (count) *count = (int)g_rules.size();
	return true;
}

// ---------------------------------------------------------------- 从文件加载
// 一行一条；空行与 `#` 开头的行跳过。先按 UTF-8 解，解不出再按 ANSI 解。
static bool LoadFile(const WCHAR* path, int* okCount, int* badCount, std::wstring& firstErr)
{
#pragma warning(suppress: 4996)
	FILE* f = _wfopen(path, L"rb");
	if (!f) { firstErr = L"打不开文件"; return false; }
	std::string all;
	char buf[4096];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0) all.append(buf, n);
	fclose(f);

	int ok = 0, bad = 0;
	size_t start = 0;
	for (size_t k = 0; k <= all.size(); ++k) {
		if (k != all.size() && all[k] != '\n') continue;
		std::string ln = all.substr(start, k - start);
		start = k + 1;
		while (!ln.empty() && (ln.back() == '\r' || ln.back() == ' ' || ln.back() == '\t')) ln.pop_back();
		if (ln.empty()) continue;

		std::wstring w;
		const int wn = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, ln.c_str(), (int)ln.size(), nullptr, 0);
		if (wn > 0) {
			std::vector<WCHAR> b((size_t)wn + 1);
			MultiByteToWideChar(CP_UTF8, 0, ln.c_str(), (int)ln.size(), b.data(), wn);
			b[(size_t)wn] = L'\0';
			w = b.data();
		} else {
			w = AnsiToW(ln.c_str());
		}
		if (!w.empty() && w[0] == L'\xFEFF') w.erase(0, 1);   // 吃 BOM

		const size_t a = w.find_first_not_of(L" \t");
		if (a == std::wstring::npos || w[a] == L'#') continue;

		std::wstring err;
		if (Add(w.c_str(), err, nullptr)) ++ok;
		else { ++bad; if (firstErr.empty()) firstErr = w + L"   —— " + err; }
	}
	if (okCount) *okCount = ok;
	if (badCount) *badCount = bad;
	return true;
}

} // namespace R3ShieldCoreRuleScript
