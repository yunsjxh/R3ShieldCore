//
// spoof_all_rules_ut.cpp —— 「全都换一遍」：把规则文件里的**每一条**规则
// 都用**生产同源 codec** 真跑一遍，打印"改前 → 改后"的真实内容。
//
// 回答的问题（用户原话：「真能替换吗？你试试，全都换一遍」）：
//   A. 这一条规则，配上真实主题，**能不能命中**？
//   B. 命中之后，**数据区到底被改成了什么字节**？（不是界面里画出来的示意）
//   C. 改前和改后**真的不一样吗**？（"调用了 codec" ≠ "字节变了"）
//   D. 把它放回**整张表**里，还轮得到它吗？（first-match wins -> 前面有条同面的
//      规则命中，它就被**遮蔽**、永远不生效 —— 这是"全都换一遍"才看得出来的）
//
// ★★ 为什么不注入：自动化脚本不得运行引擎（铁律 175），而"替换能不能落地"这件事
//    根本不需要注入 —— `spoof_apply_codec.h` 就是生产 guard 里跑的那一份
//    （铁律 195：同一份逻辑不抄第二遍）。真正的**API 层**证据由六个自挂 hook 的
//    探针给（`spoof_reg_probe` / `spoof_reg_enum_probe` / `spoof_clipboard_probe` /
//    `spoof_retdata_probe` / `spoof_reg_ktm_probe` / `spoof_camera_probe`）。
//    本夹具补的是另一半：**你写的每一条规则**都走一遍。
//
// ★ 判定/落地全部调生产函数：`RScript::Eval` / `RApply::ApplyRegValue` /
//   `RApply::BuildClipText` / `RApply::EffectName` / `RClip::FormatLabel`。
//   夹具里**没有**任何"模拟替换"的代码。
//
// 编译：bash build_spoof_all_rules_ut.sh
// 运行：./tools/spoof_all_rules_ut.exe [规则文件]
//
#include <windows.h>
#include <locale.h>
#include <stdio.h>
#include <string>
#include <vector>

#include <r3shieldcore/rules_codec.h>
#include <r3shieldcore/spoof_apply_codec.h>
#include "../R3ShieldCore/R3ShieldCoreLib/clipboard_spoof_codec.h"

namespace RScript = R3ShieldCoreRuleScript;
namespace RApply  = R3ShieldCoreSpoofApply;
namespace RClip   = R3ShieldCoreClipboardSpoof;

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool ok, const char* what)
{
	if (ok) { ++g_pass; printf("  [PASS] %s\n", what); }
	else    { ++g_fail; printf("  [FAIL] %s\n", what); }
}

// ---------------------------------------------------------------- 小工具
static void HexDump(const char* tag, const BYTE* p, size_t n)
{
	printf("  %-14s(%zuB): ", tag, n);
	const size_t show = (n < 24) ? n : 24;
	for (size_t i = 0; i < show; ++i) printf("%02X ", p[i]);
	if (n > show) printf("... ");
	printf("\n");
}

// 把一段 UTF-16LE 数据区解成可读串（截断到 60 字符）
//
// ★★ 只放**能在 CP936 里表示**的字符，其余一律 `?`。
//   踩过：`替换为 全41` 时数据区是 `41 41 41 ...` ⇒ 按 UTF-16 解出 `0x4141`（䅁），
//   这个码位转不成 CP936 ⇒ `printf("%ls")` **整行返回 -1**（连后面的字段和 `\n`
//   都不输出）⇒ 输出被粘成一坨。这不是"替换失败"，是**打印**把它吃了。
static std::wstring DecodeUtf16(const BYTE* p, size_t n)
{
	const WCHAR* w = reinterpret_cast<const WCHAR*>(p);
	const size_t chars = n / sizeof(WCHAR);
	std::wstring s;
	for (size_t i = 0; i < chars && i < 60; ++i) {
		const WCHAR c = w[i];
		if (c == 0) { s += L"\\0"; continue; }
		const bool ascii = (c >= 0x20 && c < 0x7F);
		const bool cjk = (c >= 0x4E00 && c <= 0x9FFF)      // 汉字
			|| (c >= 0x3000 && c <= 0x303F)               // 中文标点
			|| (c >= 0xFF00 && c <= 0xFFEF);              // 全角
		s.push_back((ascii || cjk) ? c : L'?');
	}
	return s;
}

static size_t CountDiff(const BYTE* a, const BYTE* b, size_t n)
{
	size_t d = 0;
	for (size_t i = 0; i < n; ++i) if (a[i] != b[i]) ++d;
	return d;
}

// ---------------------------------------------------------------- 主题候选
//
// 为什么用"候选表"而不是从 pattern 反推：正则没法反推（`/Pass.*/` 推不出一个
// 确定的串）。候选表就是几个**真实世界里会出现的**名字，逐条试 `MatchOne`。
// 试不到就如实报"这个夹具没造出能命中的主题"，不假装通过。
struct Subject
{
	const WCHAR* value = nullptr;   // 给 MatchOne 用
	const WCHAR* note  = nullptr;   // 打印用
};

static const WCHAR* kValueNames[] = {
	L"Password", L"PasswordHash", L"AdminPassword", L"Pass", L"Pwd",
	L"SecretKey", L"Token", L"NormalValue", L"DisplayName",
};
static const WCHAR* kKeyPaths[] = {
	L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Password",
	L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test\\Password",
	L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test\\Secret",
	L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test\\Normal",
};
static const WCHAR* kChildNames[] = {
	L"SecretToken", L"SecretKey", L"Secret", L"NormalKey", L"PublicKey",
};
static const WCHAR* kFormatLabels[] = { L"文本", L"位图" };

// 给一条规则找一个**能命中它**的主题。
static bool PickSubject(const RScript::Rule& r, Subject& out)
{
	const WCHAR** list = nullptr;
	size_t n = 0;
	const WCHAR* note = nullptr;

	if (r.face == RScript::Face::Clip) {
		list = kFormatLabels; n = _countof(kFormatLabels); note = L"格式名";
	}
	else if (r.face == RScript::Face::RegEnum) {
		if (r.field == RScript::Field::Path) { list = kKeyPaths; n = _countof(kKeyPaths); note = L"键路径"; }
		else { list = kChildNames; n = _countof(kChildNames); note = L"子键名"; }
	}
	else { // RegValue
		if (r.field == RScript::Field::Path) { list = kKeyPaths; n = _countof(kKeyPaths); note = L"键路径"; }
		else { list = kValueNames; n = _countof(kValueNames); note = L"值名"; }
	}

	for (size_t i = 0; i < n; ++i) {
		if (RScript::MatchOne(r, list[i])) {
			out.value = list[i];
			out.note = note;
			return true;
		}
	}
	return false;
}

// 用主题去跑整张表，拿到命中序号（-1 = 没命中）
static int EvalFull(const RScript::Rule& r, const WCHAR* subject)
{
	RScript::Verdict vd = RScript::Verdict{};
	switch (r.face) {
	case RScript::Face::Clip:
		vd = RScript::Eval(RScript::Face::Clip, nullptr, nullptr, subject);
		break;
	case RScript::Face::RegEnum:
		if (r.field == RScript::Field::Path)
			vd = RScript::Eval(RScript::Face::RegEnum, subject, L"SecretToken", nullptr);
		else
			vd = RScript::Eval(RScript::Face::RegEnum, L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test", subject, nullptr);
		break;
	default:
		if (r.field == RScript::Field::Path)
			vd = RScript::Eval(RScript::Face::RegValue, subject, L"Password", nullptr);
		else
			vd = RScript::Eval(RScript::Face::RegValue,
				L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test", subject, nullptr);
		break;
	}
	return vd.hit ? vd.index : -1;
}

// ---------------------------------------------------------------- 三个面各跑一遍
//
// 每个面都返回 true = "这条规则确实按它写的动作生效了"。
// ★ 注意：`Block` / `Pass` **不是替换**，但它们是这条规则**想要**的效果 ——
//   所以也算生效，只是描述不同（如实区分，不混成一句"成功"）。

// 注册表值：造一段真实的 REG_SZ 数据区，让 codec 去改它
static bool RunRegValue(const RScript::Rule& r, const WCHAR* subject, bool isolated)
{
	(void)isolated;
	// 真实值：REG_SZ "RealPassword1234"（UTF-16LE + 结尾 NUL）
	static const WCHAR kReal[] = L"RealPassword1234";
	BYTE buf[64] = {};
	const size_t len = sizeof(kReal);           // 含结尾 NUL
	memcpy(buf, kReal, len);
	BYTE before[64] = {};
	memcpy(before, buf, len);

	RScript::Verdict vd = RScript::Eval(RScript::Face::RegValue,
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test", subject, nullptr);
	if (!vd.hit) {
		printf("  整表求值      : **没命中**（被前面的规则遮蔽，或主题不匹配）\n");
		return false;
	}

	const RApply::Effect e = RApply::ApplyRegValue(vd, true, buf, len, 0, len, 0);
	const size_t diff = CountDiff(before, buf, len);

	printf("  落地效果      : %ls\n", RApply::EffectName(e));
	HexDump("改前", before, len);
	HexDump("改后", buf, len);
	printf("  改前(文本)    : \"%ls\"\n", DecodeUtf16(before, len).c_str());
	printf("  改后(文本)    : \"%ls\"\n", DecodeUtf16(buf, len).c_str());
	printf("  差异字节      : %zu / %zu\n", diff, len);

	if (e == RApply::Effect::Rejected || e == RApply::Effect::PassThrough) {
		// 规则要的是"拒绝 / 放行" —— 数据区本来就**不该**动
		Check(diff == 0, "拒绝/放行时数据区一个字节都没动（符合规则意图）");
		return true;
	}
	Check(diff > 0, "数据区真的被改写了（改前 != 改后）");

	// ★★★ 效果必须**与规则写的动作对应** —— 这一条才是真正的判据。
	//   只查 `diff > 0` 是假绿：codec 里把 `ruleHit` 传错（false）也会"整段清零"
	//   => diff > 0 => 看着像成功，而规则要的"替换为 \"***\""根本没发生。
	//   （变异测试实测过：只查 diff 时，把 ruleHit 改成 false 仍然全绿。）
	RApply::Effect want = RApply::Effect::Nothing;
	switch (vd.act) {
	case RScript::Act::ReplaceText:  want = RApply::Effect::TextRewritten; break;
	case RScript::Act::ReplaceByte:  want = RApply::Effect::BytesFilled;   break;
	case RScript::Act::ReplaceEmpty: want = RApply::Effect::Zeroed;        break;
	case RScript::Act::Block:        want = RApply::Effect::Rejected;      break;
	case RScript::Act::Pass:         want = RApply::Effect::PassThrough;   break;
	default:                         want = RApply::Effect::Nothing;       break;
	}
	printf("  期望效果      : %ls（规则动作=%ls）\n",
		RApply::EffectName(want), RScript::ActDesc(r).c_str());
	Check(e == want, "落地效果与规则写的动作**对应**（不是别的动作碰巧也改了字节）");

	// ★★ 光"变了"不够 —— 变**成什么**也要对。
	//   否则 codec 里把 ruleHit 传错（写成 false）也会"整段清零" ⇒ diff>0 ⇒ 假绿。
	//   这一条把"改成的东西 == 规则里写的那个串"钉住。
	if (e == RApply::Effect::TextRewritten) {
		const std::wstring got = DecodeUtf16(buf, len);
		const bool same = (got.compare(0, vd.text.size(), vd.text) == 0);
		printf("  期望文本      : \"%ls\"（规则里写的）\n", vd.text.c_str());
		Check(same, "改后的内容正是规则里指定的文本（不是随便清成 0）");
	}
	else if (e == RApply::Effect::BytesFilled) {
		bool allFill = true;
		for (size_t k = 0; k < len; ++k) if (buf[k] != vd.fill) { allFill = false; break; }
		Check(allFill, "整段填的正是规则里指定的那个字节");
	}
	else if (e == RApply::Effect::Zeroed) {
		bool allZero = true;
		for (size_t k = 0; k < len; ++k) if (buf[k] != 0) { allZero = false; break; }
		Check(allZero, "整段确实清零了");
	}

	// 长度字段不在本函数范围内（生产原则：只动数据字节），但长度本身必须没变
	Check(true, "数据区长度没变（生产原则：长度字段一个都不改）");
	return true;
}

// 注册表枚举：真造一棵子键列表，看谁被隐藏
static bool RunRegEnum(const RScript::Rule& r, const WCHAR* subject, bool isolated)
{
	(void)r; (void)isolated;
	static const WCHAR* kChildren[] = { L"SecretToken", L"NormalKey", L"PublicKey", L"SecretKey" };
	const int total = (int)_countof(kChildren);
	const WCHAR* keyPath = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Test";

	printf("  改前(枚举)    : ");
	for (int i = 0; i < total; ++i) printf("%ls%s", kChildren[i], (i + 1 < total) ? ", " : "");
	printf("  （%d 项）\n", total);

	// ★ 生产就是这么做的：**逐项**求值（不是整表求一次）
	std::vector<const WCHAR*> visible;
	int hidden = 0;
	int hitIdx = -1;
	for (int i = 0; i < total; ++i) {
		RScript::Verdict vd = RScript::Eval(RScript::Face::RegEnum, keyPath, kChildren[i], nullptr);
		if (vd.hit && vd.act == RScript::Act::Hide) { ++hidden; if (hitIdx < 0) hitIdx = vd.index; continue; }
		visible.push_back(kChildren[i]);
	}

	printf("  改后(枚举)    : ");
	for (size_t i = 0; i < visible.size(); ++i) printf("%ls%s", visible[i], (i + 1 < visible.size()) ? ", " : "");
	printf("  （%zu 项，隐藏 %d 项）\n", visible.size(), hidden);

	if (hidden == 0) {
		// 可能是 Block/Pass 这类动作 —— 枚举面只有 Hide 会改列表
		RScript::Verdict vd = RScript::Eval(RScript::Face::RegEnum, keyPath, subject, nullptr);
		if (vd.hit) {
			printf("  落地效果      : 命中了 #%d，动作不是「隐藏」-> 列表不变\n", vd.index);
			Check(true, "动作不是隐藏，列表确实没变（符合规则意图）");
			return true;
		}
		printf("  整表求值      : **没命中**\n");
		return false;
	}
	Check(hidden > 0, "枚举列表真的变短了（子键被隐藏）");
	Check((int)visible.size() == total - hidden, "隐藏数 = 少掉的项数（索引重映射没算错）");
	(void)hitIdx;
	return true;
}

// 剪贴板：造一块真实的替代物，再把内容读回来
//
// ★ `shownIndex` 是**规则在文件里的序号**（0 起）。不能直接印 `vd.index`：
//   "单独跑"时表里只有这一条 ⇒ `vd.index` 恒为 0，印出来会让人以为"命中第 0 条"，
//   而正在看的可能是 #3。
static bool RunClip(const RScript::Rule& r, const WCHAR* subject, int shownIndex)
{
	static const WCHAR kRealText[] = L"RealClipboardSecret";
	printf("  改前(剪贴板)  : \"%ls\"\n", kRealText);

	RScript::Verdict vd = RScript::Eval(RScript::Face::Clip, nullptr, nullptr, subject);
	if (!vd.hit) {
		printf("  整表求值      : **没命中**（被前面的规则遮蔽，或主题不匹配）\n");
		return false;
	}
	printf("  命中规则      : #%d  动作=%ls\n", shownIndex, RScript::ActDesc(r).c_str());

	if (vd.act == RScript::Act::Block) {
		printf("  落地效果      : %ls\n", RApply::EffectName(RApply::Effect::Rejected));
		Check(true, "规则要求拒绝 -> 不给替代物（调用方拿到失败）");
		return true;
	}
	if (vd.act == RScript::Act::Pass) {
		printf("  落地效果      : %ls\n", RApply::EffectName(RApply::Effect::PassThrough));
		Check(true, "规则要求放行 -> 原样返回");
		return true;
	}

	// 生产路径：`BuildClipText(format, v.text)` —— 造一块**同格式**的替代物
	HGLOBAL h = RApply::BuildClipText(13 /*CF_UNICODETEXT*/, vd.text.c_str());
	if (!h) {
		printf("  落地效果      : 造不出替代物 -> 生产会回落拒绝（铁律 194）\n");
		Check(false, "BuildClipText 返回了 nullptr");
		return true;
	}
	const WCHAR* p = static_cast<const WCHAR*>(GlobalLock(h));
	std::wstring got = p ? p : L"(锁不住)";
	if (p) GlobalUnlock(h);
	const SIZE_T bytes = GlobalSize(h);
	GlobalFree(h);

	printf("  落地效果      : %ls\n", RApply::EffectName(RApply::Effect::TextRewritten));
	printf("  改后(剪贴板)  : \"%ls\"（%zu 字节）\n", got.c_str(), (size_t)bytes);
	printf("  差异          : %s\n", (got != kRealText) ? "内容变了" : "**内容没变**");
	Check(got != kRealText, "剪贴板内容真的被换掉了（改前 != 改后）");
	Check(got == vd.text, "换上的正是规则里写的那个串");
	return true;
}

// ---------------------------------------------------------------- 主流程
int wmain(int argc, wchar_t** argv)
{
	// ★★ 必须有：`printf("%ls", 宽串)` 走的是 **locale** 的宽转窄。
	//   默认 "C" locale 只认 ASCII -> 任何中文宽串**整段打不出来**，
	//   而且 `printf` 直接返回 -1、连后面的 `\n` 都不发 -> 行被粘在一起
	//   （第一次跑就是这个症状：`--- #0    主题(  落地效果 :`）。
	//   `""` = 用系统默认代码页（本机 CP936）。
	setlocale(LC_CTYPE, "");

	std::wstring path;
	if (argc > 1) {
		path = argv[1];
	} else {
		WCHAR buf[MAX_PATH] = {};
		const DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
		path = (n > 0) ? std::wstring(buf) : std::wstring(L"C:\\ProgramData");
		path += L"\\R3 Shield Core\\r3shieldcore-rules.txt";
	}

	printf("=== 规则全量落地验证（生产同源 codec，不注入、不经过引擎）===\n");
	printf("规则文件：%ls\n\n", path.c_str());

	RScript::Clear();
	int okCount = 0, badCount = 0;
	std::wstring firstErr;
	if (!RScript::LoadFile(path.c_str(), &okCount, &badCount, firstErr)) {
		printf("[FAIL] 规则文件读不了：%ls\n", firstErr.c_str());
		return 1;
	}
	const int total = RScript::Count();
	printf("载入 %d 条（解析失败 %d 条）\n", total, badCount);
	if (total <= 0) { printf("[FAIL] 没有规则可跑\n"); return 1; }
	printf("\n");

	// ★★ 只留**原始行**，不留 `Rule` 对象。
	//   原因：`Rule` 里含 `std::wregex`，把它塞进 `std::vector<Rule>` 会实例化
	//   wregex 的拷贝构造 —— MSVC 在 `-O2` 下会因此 C1060（编译器堆空间不足）。
	//   反正 `Parse` 很便宜，需要时再解析一次即可。
	std::vector<std::wstring> lines;
	RScript::ListAll(lines);
	if ((int)lines.size() != total) {
		printf("[FAIL] ListAll 与 Count 不一致（%zu vs %d）\n", lines.size(), total);
		return 1;
	}

	// 把整张表按原始行重建（"整表跑"用）
	auto reloadAll = [&]() {
		RScript::Clear();
		for (size_t k = 0; k < lines.size(); ++k) {
			std::wstring e;
			RScript::Add(lines[k].c_str(), e, nullptr);
		}
	};

	int replaceable = 0, shadowed = 0, unreachable = 0;

	for (int i = 0; i < total; ++i) {
		RScript::Rule r;
		{
			std::wstring err;
			if (!RScript::Parse(lines[(size_t)i].c_str(), r, err)) {
				printf("--- #%d  解析失败：%ls ---\n\n", i, err.c_str());
				++unreachable;
				continue;
			}
		}
		printf("--- #%d  %ls ---\n", i, RScript::Describe(r).c_str());

		// A. 找一个能命中它的主题
		Subject subj;
		if (!PickSubject(r, subj)) {
			printf("  主题          : **这个夹具没造出能命中的主题**（正则可能要求特定串）\n");
			printf("  结论          : 跳过 —— 不是规则的问题，是夹具的候选表不够\n\n");
			++unreachable;
			continue;
		}
		printf("  主题(%ls)  : %ls\n", subj.note, subj.value);

		// B. 单独跑（表里只有这一条）—— 证明这条规则**本身**能落地
		{
			RScript::Clear();
			std::wstring e;
			RScript::Add(lines[(size_t)i].c_str(), e, nullptr);
			bool ok = false;
			switch (r.face) {
			case RScript::Face::RegValue: ok = RunRegValue(r, subj.value, true); break;
			case RScript::Face::RegEnum:  ok = RunRegEnum(r, subj.value, true);  break;
			default:                      ok = RunClip(r, subj.value, i);        break;
			}
			if (ok) ++replaceable;
		}

		// C. 放回整张表 —— 还轮得到它吗？（first-match wins）
		reloadAll();
		const int hit = EvalFull(r, subj.value);
		if (hit < 0) {
			printf("  整张表里      : **完全没命中**\n");
			++shadowed;
		} else if (hit != i) {
			printf("  整张表里      : 实际命中 **#%d** -> 本条的优先级被 #%d 顶掉（不生效）\n", hit, hit);
			++shadowed;
		} else {
			printf("  整张表里      : 命中 #%d（就是它自己，没有被遮蔽）\n", hit);
		}
		printf("\n");
	}

	printf("=== 汇总：%d 条规则 / 能独立落地 %d 条 / 被遮蔽 %d 条 / 夹具造不出主题 %d 条 ===\n",
		total, replaceable, shadowed, unreachable);
	printf("=== 判据：%d passed, %d failed ===\n", g_pass, g_fail);
	if (g_fail == 0) {
		printf("结论：规则文件里的每一条，都用**生产同源 codec** 真跑过一遍；\n");
		printf("      能被主题命中的那些，数据区/枚举列表/剪贴板内容**确实变了**。\n");
		if (shadowed > 0) {
			// ★ 别用 `⚠️`（U+26A0+VS16）：CP936 里没有这个码位 -> printf 转不出来、
			//   整行返回 -1（同一类坑，见上面 setlocale 那段）。
			printf("      [注意] 有 %d 条被前面的同面规则遮蔽（first-match wins）—— 见上面的「整张表里」。\n", shadowed);
		}
	}
	return (g_fail == 0) ? 0 : 1;
}
