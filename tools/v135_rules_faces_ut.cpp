//
// v135_rules_faces_ut.cpp —— 规则表新增「文件」「截屏」两个面的单测。
//
// ======================================================================
// 为什么要有这个单测
// ======================================================================
// 用户原话：「规则表还没有文件和截图替换的规则啊」。
// 之前 DSL 只有三个面（注册表值 / 注册表枚举 / 剪贴板），v133 加文件、
// v134 加截屏图片时都只加了 ini 全局开关，没回头扩 DSL ⇒ 这两个面
// 变成"全有或全无"，没法按路径/来源细分。
//
// ★★ 这个单测重点不在"能解析出来"，而在**三件容易漏的事**：
//   ① **面 × 字段** 不相容必须**解析期就拒**。`Eval` 里某字段拿不到值会
//      `continue`（跳过这条），所以"当 文件 的 格式 含 ..."这种写法会
//      **解析通过、永远不命中、也不报错** —— 最费时间的一类静默失效。
//   ② **面 × 动作** 不相容同理（文件面不能"拒绝"、截屏面不能"替换为文本"）。
//   ③ **面之间必须隔离**：文件规则不能影响截屏求值，反之亦然。
//      （`Eval` 里 `if (r.face != face) continue;` 这一行就是它，删了也能
//        "编译通过、大部分用例通过"—— 所以要有一条专门打它的用例。）
//
// ★ 不挂 hook、不注入、不经过引擎：只调共享 codec，纯逻辑。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string>
#include <vector>

#include <r3shieldcore/rules_codec.h>

namespace RScript = R3ShieldCoreRuleScript;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const wchar_t* what, bool ok)
{
	if (ok)
	{
		wprintf(L"  [PASS] %ls\n", what);
		++g_pass;
	}
	else
	{
		wprintf(L"  [FAIL] %ls\n", what);
		++g_fail;
	}
}

// 解析一条；成功时把 Rule 带回来。
static bool TryParse(const wchar_t* line, RScript::Rule& out, std::wstring& err)
{
	err.clear();
	return RScript::Parse(line, out, err);
}

// 解析一条并断言**失败**，且错误信息里含某个关键字。
//
// ★ 只断言"失败"不够：失败的原因可能完全不相干（少个「时」也会失败），
//   那样这条用例就成了"随便什么错都算通过"的空真判据（铁律 110）。
static void CheckReject(const wchar_t* line, const wchar_t* mustMention)
{
	RScript::Rule r;
	std::wstring err;
	const bool ok = TryParse(line, r, err);
	const bool mentioned = (err.find(mustMention) != std::wstring::npos);
	if (ok)
	{
		wprintf(L"  [FAIL] 本该拒绝却解析通过：%ls\n", line);
		++g_fail;
		return;
	}
	if (!mentioned)
	{
		wprintf(L"  [FAIL] 拒绝了但理由不对（期望提到「%ls」）：%ls\n     实际：%ls\n",
			mustMention, line, err.c_str());
		++g_fail;
		return;
	}
	wprintf(L"  [PASS] 拒绝且理由正确：%ls\n", mustMention);
	++g_pass;
}

int main()
{
	setlocale(LC_ALL, ".936");
	wprintf(L"=== v135 规则表「文件 / 截屏」两个面 · codec 层单测（纯逻辑）===\n\n");

	RScript::Clear();

	// ================================================================
	// 1. 解析：文件面
	// ================================================================
	wprintf(L"--- 1. 文件面解析 ---\n");
	{
		RScript::Rule r;
		std::wstring err;
		Check(L"当 文件 的 路径 含 \"secret\" 时 替换为 全零",
			TryParse(L"当 文件 的 路径 含 \"secret\" 时 替换为 全零", r, err));
		Check(L"  面 = 文件", r.face == RScript::Face::File);
		Check(L"  字段 = 路径", r.field == RScript::Field::Path);
		Check(L"  动作 = 全零", r.act == RScript::Act::ReplaceByte && r.fill == 0);

		// 省略字段 ⇒ 用该面默认字段（文件面 = 路径）
		Check(L"当 文件 含 \"x\" 时 替换为 全FF（省略字段）",
			TryParse(L"当 文件 含 \"x\" 时 替换为 全FF", r, err));
		Check(L"  默认字段就是路径", r.field == RScript::Field::Path);
		Check(L"  填充值 = 0xFF", r.act == RScript::Act::ReplaceByte && r.fill == 0xFF);

		// 文本替换（用户明确要求支持）
		Check(L"当 文件 的 路径 匹配 /\\.key$/ 时 替换为 \"假配置\"",
			TryParse(L"当 文件 的 路径 匹配 /\\.key$/ 时 替换为 \"假配置\"", r, err));
		Check(L"  动作 = 替换为文本", r.act == RScript::Act::ReplaceText);
		Check(L"  文本原样保留", r.text == L"假配置");
	}

	// ================================================================
	// 2. 解析：截屏面
	// ================================================================
	wprintf(L"\n--- 2. 截屏面解析 ---\n");
	{
		RScript::Rule r;
		std::wstring err;
		Check(L"当 截屏 的 进程 含 \"OBS\" 时 替换为图 \"C:\\fake\\desktop.bmp\"",
			TryParse(L"当 截屏 的 进程 含 \"OBS\" 时 替换为图 \"C:\\fake\\desktop.bmp\"", r, err));
		Check(L"  面 = 截屏", r.face == RScript::Face::Screen);
		Check(L"  字段 = 进程", r.field == RScript::Field::Process);
		Check(L"  动作 = 替换为图", r.act == RScript::Act::ReplaceImage);
		// ★ 路径里的反斜杠必须**原样**保留：Tokenize 不做转义，
		//   若这里被吃掉一层，用户填的路径就到不了引擎。
		Check(L"  图片路径原样保留（反斜杠没被吃）",
			r.text == L"C:\\fake\\desktop.bmp");

		Check(L"当 截屏 含 \"obs\" 时 替换为 全零（省略字段）",
			TryParse(L"当 截屏 含 \"obs\" 时 替换为 全零", r, err));
		Check(L"  默认字段就是进程", r.field == RScript::Field::Process);

		// 别名
		Check(L"面名别名「屏幕」也认",
			TryParse(L"当 屏幕 的 进程 等于 \"a.exe\" 时 放行", r, err)
			&& r.face == RScript::Face::Screen);
		Check(L"面名别名「file」也认",
			TryParse(L"当 file 的 路径 含 \"x\" 时 放行", r, err)
			&& r.face == RScript::Face::File);
	}

	// ================================================================
	// 3. ★★ 面 × 字段 / 面 × 动作 不相容必须**解析期**拒
	// ================================================================
	wprintf(L"\n--- 3. 不相容组合必须在解析期拒 ---\n");
	CheckReject(L"当 文件 的 格式 含 \"x\" 时 替换为 全零", L"不支持这个字段");
	CheckReject(L"当 文件 的 值名 含 \"x\" 时 替换为 全零", L"不支持这个字段");
	CheckReject(L"当 截屏 的 路径 含 \"x\" 时 替换为 全零", L"不支持这个字段");
	CheckReject(L"当 剪贴板 的 进程 含 \"x\" 时 替换为 \"y\"", L"不支持这个字段");
	CheckReject(L"当 文件 的 路径 含 \"x\" 时 拒绝", L"文件面的动作只能是");
	CheckReject(L"当 文件 的 路径 含 \"x\" 时 隐藏", L"隐藏");
	CheckReject(L"当 截屏 的 进程 含 \"x\" 时 替换为 \"文本\"", L"截屏面的动作只能是");
	CheckReject(L"当 截屏 的 进程 含 \"x\" 时 拒绝", L"截屏面的动作只能是");
	CheckReject(L"当 剪贴板 的 格式 等于 文本 时 替换为图 \"a.bmp\"", L"替换为图");
	CheckReject(L"当 文件 的 路径 含 \"x\" 时 替换为图 \"a.bmp\"", L"替换为图");
	CheckReject(L"当 截屏 的 进程 含 \"x\" 时 替换为图", L"替换为图");
	CheckReject(L"当 不存在的面 含 \"x\" 时 放行", L"不认识的面");

	// ================================================================
	// 4. 求值：按面命中 + **面之间隔离**
	// ================================================================
	wprintf(L"\n--- 4. 求值（含面隔离）---\n");
	{
		RScript::Clear();
		std::wstring err;
		int idx = -1;
		Check(L"装入：当 文件 的 路径 含 \"secret\" 时 替换为 全零",
			RScript::Add(L"当 文件 的 路径 含 \"secret\" 时 替换为 全零", err, &idx));
		Check(L"装入：当 截屏 的 进程 含 \"OBS\" 时 替换为图 \"C:\\f.bmp\"",
			RScript::Add(L"当 截屏 的 进程 含 \"OBS\" 时 替换为图 \"C:\\f.bmp\"", err, &idx));

		Check(L"文件面：路径命中", RScript::Eval(RScript::Face::File,
			L"C:\\data\\secret.txt", nullptr, nullptr).hit);
		Check(L"文件面：路径不命中", !RScript::Eval(RScript::Face::File,
			L"C:\\data\\public.txt", nullptr, nullptr).hit);
		Check(L"文件面：路径为空不命中（不能因为规则在就乱命中）",
			!RScript::Eval(RScript::Face::File, nullptr, nullptr, nullptr).hit);

		{
			const RScript::Verdict v = RScript::Eval(RScript::Face::Screen,
				nullptr, L"obs64.exe", nullptr);
			Check(L"截屏面：进程命中", v.hit);
			Check(L"截屏面：拿到的是图路径",
				v.hit && v.act == RScript::Act::ReplaceImage && v.text == L"C:\\f.bmp");
		}
		Check(L"截屏面：进程不命中",
			!RScript::Eval(RScript::Face::Screen, nullptr, L"notepad.exe", nullptr).hit);

		// ★★★ 面隔离：拿"文件面的路径"去问截屏面，必须不命中。
		//   这条专门打 `Eval` 里的 `if (r.face != face) continue;` ——
		//   删掉那一行，上面多数用例仍然通过（因为别的面的规则模式不匹配），
		//   但这条会红。
		Check(L"★面隔离：文件规则不会被截屏面命中",
			!RScript::Eval(RScript::Face::Screen, nullptr, L"C:\\data\\secret.txt", nullptr).hit);
		Check(L"★面隔离：截屏规则不会被文件面命中",
			!RScript::Eval(RScript::Face::File, L"C:\\f.bmp", nullptr, nullptr).hit);

		// HasFace 预筛（引擎侧靠它决定"要不要进规则求值"）
		Check(L"HasFace(文件) 为真", RScript::HasFace(RScript::Face::File));
		Check(L"HasFace(截屏) 为真", RScript::HasFace(RScript::Face::Screen));
		Check(L"HasFace(剪贴板) 为假（负对照：没装就没有）",
			!RScript::HasFace(RScript::Face::Clip));
	}

	// ================================================================
	// 5. first-match wins（两个新面都要遵守）
	// ================================================================
	wprintf(L"\n--- 5. first-match wins ---\n");
	{
		RScript::Clear();
		std::wstring err;
		int idx = -1;
		RScript::Add(L"当 文件 的 路径 含 \"secret\" 时 替换为 全零", err, &idx);
		RScript::Add(L"当 文件 的 路径 含 \"secret\" 时 替换为 全FF", err, &idx);
		{
			const RScript::Verdict v = RScript::Eval(RScript::Face::File,
				L"C:\\secret.txt", nullptr, nullptr);
			Check(L"两条都命中时取**先加的那条**",
				v.hit && v.index == 0 && v.fill == 0x00);
		}

		RScript::Clear();
		RScript::Add(L"当 截屏 的 进程 含 \"a\" 时 替换为图 \"C:\\1.bmp\"", err, &idx);
		RScript::Add(L"当 截屏 的 进程 含 \"a\" 时 替换为 全零", err, &idx);
		{
			const RScript::Verdict v = RScript::Eval(RScript::Face::Screen,
				nullptr, L"abc.exe", nullptr);
			Check(L"截屏面同样取先加的那条",
				v.hit && v.index == 0 && v.text == L"C:\\1.bmp");
		}
	}

	// ================================================================
	// 6. 描述往返（`Describe` 的输出必须还能被 `Parse` 回来）
	// ================================================================
	//
	// ★ 为什么测：界面"点一行 -> 载入编辑框 -> 改一下 -> 更新"依赖它。
	//   规则是程序化构造（`src` 为空）时显示走 `Describe`，一旦生成物
	//   无法再解析，用户点一下就把那条改坏了。
	wprintf(L"\n--- 6. 描述往返 ---\n");
	{
		const wchar_t* lines[] = {
			L"当 文件 的 路径 含 \"secret\" 时 替换为 全零",
			L"当 文件 的 路径 匹配 /\\.key$/ 时 替换为 \"假配置\"",
			L"当 截屏 的 进程 含 \"OBS\" 时 替换为图 \"C:\\fake\\desktop.bmp\"",
			L"当 截屏 的 进程 等于 \"a.exe\" 时 替换为 全FF",
			L"当 文件 的 路径 结尾 \".txt\" 时 放行",
		};
		for (const wchar_t* line : lines)
		{
			RScript::Rule r1;
			std::wstring err;
			if (!TryParse(line, r1, err)) { Check(line, false); continue; }

			const std::wstring d = RScript::Describe(r1);
			RScript::Rule r2;
			const bool again = TryParse(d.c_str(), r2, err);
			const bool same = again
				&& r2.face == r1.face && r2.field == r1.field
				&& r2.op == r1.op && r2.act == r1.act
				&& r2.pattern == r1.pattern && r2.text == r1.text
				&& r2.fill == r1.fill;
			if (!same)
			{
				wprintf(L"      原文：%ls\n      生成：%ls\n", line, d.c_str());
			}
			Check(L"Describe -> Parse 得到同一条规则", same);
		}
	}

	// ================================================================
	// 7. 负对照：老三个面的行为**一字未改**
	// ================================================================
	//
	// ★ 新面是"加"不是"改"。如果三个老面被顺手改坏了，那才是真回归。
	wprintf(L"\n--- 7. 负对照：老三个面没变 ---\n");
	{
		RScript::Rule r;
		std::wstring err;
		Check(L"注册表值面仍可解析",
			TryParse(L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"", r, err)
			&& r.face == RScript::Face::RegValue && r.act == RScript::Act::ReplaceText);
		Check(L"注册表枚举面仍只允许 隐藏/放行/拒绝",
			TryParse(L"当 注册表枚举 的 子键名 含 \"Secret\" 时 隐藏", r, err)
			&& r.act == RScript::Act::Hide);
		CheckReject(L"当 注册表枚举 的 子键名 含 \"x\" 时 替换为 全零", L"注册表枚举面的动作");
		Check(L"剪贴板面仍可解析",
			TryParse(L"当 剪贴板 的 格式 等于 文本 时 替换为 \"假的\"", r, err)
			&& r.face == RScript::Face::Clip && r.field == RScript::Field::Format);
		CheckReject(L"当 剪贴板 的 格式 等于 文本 时 替换为 全零", L"剪贴板面不支持");
	}

	RScript::Clear();

	wprintf(L"\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
