//
// v78_guard_ut.cpp —— R3ShieldCore v78「规则脚本接进引擎」单测。
//
// ★ v78 加了什么：
//   主程序「高级」页里写的**中文规则**（`当 注册表值 的 值名 匹配 /Pass.*/ 时
//   替换为 "***"`），从"只影响那一页的预览"变成**真的作用于引擎**：
//     · 注册表**值**读取 → `registry_guard.cpp::Evaluate` + `NtQueryValueKey_Hook`
//     · 注册表**枚举**   → `registry_guard.cpp::ProtectedChildPredicate`
//     · **剪贴板**读取   → `clipboard_guard.cpp::RejectOrSpoof` + `GetClipboardData_Hook`
//
// ★★ 本文件要证的是**因果**，不是"代码里有这几行"：
//   同一条规则**加上去之前**不生效、**加上去之后**生效 —— 两个方向都要断言。
//   只断言"加了规则 => 变成 Spoof"是不够的：内置判据（`protect_reg`）本来
//   也会产生 Spoof，两条路给出**同一个**返回值 => 断言恒真，测不出
//   "规则根本没接上"（铁律 97/110 说的那类空真判据）。
//   所以每个面都配了**负对照**：撤掉规则 / 关掉总闸 / 换一个不匹配的名字。
//
// ★ 本机可跑（铁律 175 不适用）：直接编 `registry_guard.cpp` /
//   `clipboard_guard.cpp` **本体**，调的是**生产那个决策函数**，
//   不注入、不跑引擎、不碰真实注册表 / 剪贴板。
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <wchar.h>
#include <string>
#include <vector>

#include <r3shieldcore/r3shieldcore_shared.h>
// 规则脚本引擎（`R3ShieldCoreRuleScript`）+ 落地 codec —— 与生产**同一份**头
// （铁律 195：单测不能自带一份"照着写的"实现）。
#include <r3shieldcore/spoof_apply_codec.h>

// ---- 被单测驱动的两个 guard 的单测入口（见各 .cpp 文件尾）----
namespace RegistryGuardTest
{
	struct KeyEvalResult
	{
		R3ShieldCore::Event event;
		int action;
	};

	KeyEvalResult EvaluateKeyEx(PCWSTR keyPath, PCWSTR valueName, ULONG op, ULONG mode,
		bool blockable, ULONG spoofInfoClass) noexcept;

	bool EnumChildHidden(PCWSTR keyPath, PCWSTR childPath) noexcept;

	int ApplyValueRuleForTest(PCWSTR keyPath, PCWSTR valueName,
		BYTE* data, size_t dataLength, BYTE* outBytes, size_t outLength) noexcept;

	bool LoadRulesFromFile(PCWSTR path) noexcept;
	void ClearRulesForTest() noexcept;
	int  RuleCountForTest() noexcept;
}

namespace ClipboardGuardTest
{
	void SetCloseHookReady(bool ready) noexcept;
	int  RejectOrSpoofForTest(UINT format, int* decisionOut, ULONG* flagsOut) noexcept;
	int  EvalClipRuleForTest(UINT format, int* indexOut) noexcept;
	void RuleTextForTest(UINT format, WCHAR* out, size_t outChars) noexcept;
}

namespace GuardStub
{
	void SetMode(ULONG mode) noexcept;
	void ResetPolicy() noexcept;
	R3ShieldCore::Policy* PolicyPtr() noexcept;
}

namespace RScript = R3ShieldCoreRuleScript;
namespace RApply = R3ShieldCoreSpoofApply;

using Action = R3ShieldCore::Action;
using Decision = R3ShieldCore::Decision;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

static const int kActionPass = static_cast<int>(Action::Pass);
static const int kActionRecord = static_cast<int>(Action::Record);
static const int kActionBlock = static_cast<int>(Action::Block);
static const int kActionSpoof = static_cast<int>(Action::Spoof);

// ------------------------------------------------------------------ 规则文件
//
// ★ 全部写进**临时目录**，绝不碰 `%ProgramData%\R3 Shield Core\` ——
//   那是真装产品读的地方，单测往里写就等于"测试改了用户数据"。
static std::vector<std::wstring> g_tempFiles;

static std::wstring TempRulesPath(const wchar_t* tag)
{
	WCHAR dir[MAX_PATH] = {};
	GetTempPathW(_countof(dir), dir);
	WCHAR file[MAX_PATH] = {};
	// 带 pid：并行跑 x64/x86 时两边不打架。
	swprintf_s(file, L"%sr3sc-v78-%s-%lu.txt", dir, tag,
		static_cast<unsigned long>(GetCurrentProcessId()));
	g_tempFiles.push_back(file);
	return file;
}

// 按**生产 SaveFile 的口径**写：UTF-8 带 BOM、CRLF。
static bool WriteRulesFile(const std::wstring& path, const std::wstring& content)
{
	FILE* f = nullptr;
	if (_wfopen_s(&f, path.c_str(), L"wb") != 0 || !f) return false;
	fputs("\xEF\xBB\xBF", f);
	const int n = WideCharToMultiByte(CP_UTF8, 0, content.c_str(),
		static_cast<int>(content.size()), nullptr, 0, nullptr, nullptr);
	if (n > 0) {
		std::string bytes(static_cast<size_t>(n), '\0');
		WideCharToMultiByte(CP_UTF8, 0, content.c_str(), static_cast<int>(content.size()),
			&bytes[0], n, nullptr, nullptr);
		fwrite(bytes.data(), 1, static_cast<size_t>(n), f);
	}
	fclose(f);
	return true;
}

// 写一份规则文件并**加载**它。
static bool UseRules(const wchar_t* tag, const std::wstring& content)
{
	const std::wstring path = TempRulesPath(tag);
	if (!WriteRulesFile(path, content)) return false;
	return RegistryGuardTest::LoadRulesFromFile(path.c_str());
}

static void CleanupTempFiles()
{
	for (const std::wstring& p : g_tempFiles) {
		DeleteFileW(p.c_str());
	}
	g_tempFiles.clear();
}

// ---- 三个面的规则集（中文 DSL 原文，与界面里手敲的**同一条解析路径**）----

// 值面：正则匹配 -> 替换为文本
static const std::wstring kRulesValueReplace =
	L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"\r\n";

// 枚举面：含 -> 隐藏
static const std::wstring kRulesEnumHide =
	L"当 注册表枚举 的 子键名 含 \"Secret\" 时 隐藏\r\n";

// 剪贴板面：等于 -> 替换为文本
static const std::wstring kRulesClipReplace =
	L"当 剪贴板 的 格式 等于 文本 时 替换为 \"[已替换]\"\r\n";

// 三面齐全（值与序号都要对得上：值=#0、枚举=#1、剪贴板=#2）
static const std::wstring kRulesAll =
	kRulesValueReplace + kRulesEnumHide + kRulesClipReplace;

// 关掉三个总闸 + 复位到 Block 模式。
//
// ⚠️ 模式**必须一起复位**：`GuardStub::ResetPolicy()` 是 `ZeroMemory`，
//    而 `Mode::Log` 就是 0 —— 不复位的话后面每个子测试都悄悄跑在 Log 模式下，
//    "规则「拒绝」⇒ Block" 会变成 Record（Log 模式只记录），
//    而失败原因**完全看不出来**（看起来像"规则没接上"）。
//    v78 单测第一版就踩了这个，靠"Log 模式那条 PASS 而 Block 模式那条 FAIL"
//    才定位到。
static void ResetPolicyAllOff()
{
	GuardStub::ResetPolicy();
	GuardStub::PolicyPtr()->Flags2 &= ~(R3ShieldCore::FlagSpoofRegistry
		| R3ShieldCore::FlagSpoofRegistryEnum | R3ShieldCore::FlagSpoofClipboard);
	GuardStub::SetMode(static_cast<ULONG>(R3ShieldCore::Mode::Block));
	ClipboardGuardTest::SetCloseHookReady(false);
}

// ================================================================== 1. 加载
static void TestLoad()
{
	printf("\n--- 1. 规则文件加载（注释 / 空行 / 坏行计数）---\n");

	const std::wstring good =
		L"# 注释行会被跳过\r\n"
		L"\r\n"
		L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"\r\n"
		L"当 注册表枚举 的 子键名 含 \"Secret\" 时 隐藏\r\n"
		L"当 剪贴板 的 格式 等于 文本 时 替换为 \"[已替换]\"\r\n";

	const std::wstring goodPath = TempRulesPath(L"good");
	Check("写出临时规则文件", WriteRulesFile(goodPath, good));
	Check("LoadRulesFromFile 返回 true",
		RegistryGuardTest::LoadRulesFromFile(goodPath.c_str()));
	Check("解析出 3 条规则（注释与空行不计）", RegistryGuardTest::RuleCountForTest() == 3);

	// ★ 坏行必须**计数**、必须**不把好行带崩**，不能静默吞掉（铁律 97）。
	const std::wstring mixed =
		L"当 注册表值 的 值名 含 \"OK\" 时 替换为 \"x\"\r\n"
		L"这条根本不是规则\r\n"
		L"当 剪贴板 的 格式 等于 文本 时 隐藏\r\n";   // 「隐藏」只对枚举面 => 解析期就该挡
	const std::wstring mixedPath = TempRulesPath(L"mixed");
	Check("写出含坏行的文件", WriteRulesFile(mixedPath, mixed));
	Check("文件读到了（返回 true）",
		RegistryGuardTest::LoadRulesFromFile(mixedPath.c_str()));
	Check("3 行里只有 1 条合法规则被收下", RegistryGuardTest::RuleCountForTest() == 1);
}

// ================================================================== 2. 值面
static void TestRegValueFace()
{
	printf("\n--- 2. 注册表值面：规则真的改变了 Evaluate 的处置 ---\n");

	const WCHAR* key = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault";
	GuardStub::SetMode(static_cast<ULONG>(R3ShieldCore::Mode::Block));

	// ---- 2.1 没有规则：不是 Spoof（基线）----
	ResetPolicyAllOff();
	GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;
	RegistryGuardTest::ClearRulesForTest();
	{
		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Password",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("【负对照】没有规则 => 不产生替换决策", r.action != kActionSpoof);
	}

	// ---- 2.2 加载规则后：同一次调用变成 Spoof ----
	Check("加载值面规则", UseRules(L"val", kRulesValueReplace));
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Password",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("【因果】规则命中 => Action::Spoof", r.action == kActionSpoof);
		Check("【因果】规则命中 => Decision::Spoofed",
			r.event.Decision == static_cast<ULONG>(Decision::Spoofed));
	}

	// ---- 2.3 名字不匹配 => 不生效（证明"命中"是规则判出来的，不是恒真）----
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Token",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("【负对照】值名不匹配 /Pass.*/ => 不替换", r.action != kActionSpoof);
	}

	// ---- 2.4 落地：真的写进数据区 ----
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;

		BYTE data[32] = {};
		memcpy(data, L"hunter2", 8 * sizeof(WCHAR));
		BYTE out[32] = {};
		const int effect = RegistryGuardTest::ApplyValueRuleForTest(
			key, L"Password", data, sizeof(data), out, sizeof(out));

		Check("落地效果 == 写入了规则指定的文本",
			effect == static_cast<int>(RApply::Effect::TextRewritten));
		Check("数据区前 4 个 WCHAR == \"***\\0\"（UTF-16）",
			memcmp(out, L"***", 4 * sizeof(WCHAR)) == 0);
		Check("【负对照】原文 hunter2 已被覆盖（不是原样返回）",
			memcmp(out, L"hunter2", 7 * sizeof(WCHAR)) != 0);
	}

	// ---- 2.5 「拒绝」真的变成 Block ----
	Check("加载「拒绝」规则",
		UseRules(L"valblock", L"当 注册表值 的 值名 等于 \"Secret\" 时 拒绝\r\n"));
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Secret",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("规则「拒绝」=> Action::Block", r.action == kActionBlock);
		Check("规则「拒绝」=> Decision::Blocked",
			r.event.Decision == static_cast<ULONG>(Decision::Blocked));
		Check("规则「拒绝」=> 置了 FlagEventBlocked",
			(r.event.Flags & R3ShieldCore::FlagEventBlocked) != 0);
	}

	// ---- 2.6 Log 模式：拒绝只记录（与其它"本应拒绝"同构）----
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;
		GuardStub::SetMode(static_cast<ULONG>(R3ShieldCore::Mode::Log));
		UseRules(L"valblock2", L"当 注册表值 的 值名 等于 \"Secret\" 时 拒绝\r\n");

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Secret",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("Log 模式 + 规则「拒绝」=> 不真拒（Action::Record）", r.action == kActionRecord);
		Check("Log 模式 + 规则「拒绝」=> Decision::WouldBlock",
			r.event.Decision == static_cast<ULONG>(Decision::WouldBlock));

		GuardStub::SetMode(static_cast<ULONG>(R3ShieldCore::Mode::Block));
	}

	// ---- 2.7 「放行」能推翻内置判据（否则规则等于白写）----
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistry;
		// 把这条键放进 protect_reg => 内置判据本来**会**替换。
		R3ShieldCore::Policy* p = GuardStub::PolicyPtr();
		wcsncpy_s(p->ProtectRegPaths[0], key, _TRUNCATE);
		p->ProtectRegCount = 1;

		// 先证明内置判据确实会替换（否则下面那条断言可能恒真）。
		RegistryGuardTest::ClearRulesForTest();
		const auto builtin = RegistryGuardTest::EvaluateKeyEx(key, L"Anything",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("【前提】protect_reg 命中 => 内置判据会替换", builtin.action == kActionSpoof);

		Check("加载「放行」规则",
			UseRules(L"valpass", L"当 注册表值 的 值名 含 \"Anything\" 时 放行\r\n"));
		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Anything",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("【因果】规则「放行」=> 内置替换被压住", r.action != kActionSpoof);

		p->ProtectRegCount = 0;
	}

	// ---- 2.8 总闸：ini 开关关着 => 规则一律不动手 ----
	{
		ResetPolicyAllOff();   // 三个 spoof 位全清
		UseRules(L"valgate", kRulesValueReplace);

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, L"Password",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
		Check("【负对照】spoof_reg 关着 => 规则不生效（总闸优先）", r.action != kActionSpoof);
	}
}

// ================================================================== 3. 枚举面
static void TestRegEnumFace()
{
	printf("\n--- 3. 注册表枚举面：规则决定藏谁 ---\n");

	const WCHAR* key = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault";
	const WCHAR* secretKey = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault\\SecretKey";
	const WCHAR* secretToken = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault\\SecretToken";
	const WCHAR* publicKey = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault\\PublicKey";

	// ---- 3.1 没有规则：一项都不藏 ----
	ResetPolicyAllOff();
	GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofRegistryEnum;
	RegistryGuardTest::ClearRulesForTest();
	{
		Check("【负对照】没有规则 => SecretKey 不藏",
			!RegistryGuardTest::EnumChildHidden(key, secretKey));

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), 0, false, 0);
		Check("【负对照】没有规则 => 不产生枚举隐藏决策", r.action != kActionSpoof);
	}

	// ---- 3.2 加载规则后：按子键名藏 ----
	Check("加载枚举面规则", UseRules(L"enum", kRulesEnumHide));
	{
		Check("【因果】SecretKey 被藏",
			RegistryGuardTest::EnumChildHidden(key, secretKey));
		Check("【因果】SecretToken 被藏",
			RegistryGuardTest::EnumChildHidden(key, secretToken));
		Check("【负对照】PublicKey 不被藏（名字不匹配）",
			!RegistryGuardTest::EnumChildHidden(key, publicKey));

		const auto r = RegistryGuardTest::EvaluateKeyEx(key, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), 0, false, 0);
		Check("【因果】有枚举规则 => 产生 Spoof 决策（值得扫一遍）", r.action == kActionSpoof);
	}

	// ---- 3.3 「放行」压住规则 ----
	{
		Check("加载枚举面「放行」规则",
			UseRules(L"enumpass",
				L"当 注册表枚举 的 子键名 含 \"Secret\" 时 放行\r\n"));
		Check("【因果】规则「放行」=> SecretKey 不藏",
			!RegistryGuardTest::EnumChildHidden(key, secretKey));
	}

	// ---- 3.4 总闸 ----
	{
		ResetPolicyAllOff();
		UseRules(L"enumgate", kRulesEnumHide);
		const auto r = RegistryGuardTest::EvaluateKeyEx(key, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), 0, false, 0);
		Check("【负对照】spoof_reg_enum 关着 => 枚举规则不生效", r.action != kActionSpoof);
	}
}

// ================================================================== 4. 剪贴板面
static void TestClipboardFace()
{
	printf("\n--- 4. 剪贴板面：规则决定换成什么 ---\n");

	const UINT kText = 13;    // CF_UNICODETEXT
	const UINT kBitmap = 2;   // CF_BITMAP

	// ---- 4.1 没有规则：内置行为（文本 => 空串替换）----
	ResetPolicyAllOff();
	GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofClipboard;
	ClipboardGuardTest::SetCloseHookReady(true);
	RegistryGuardTest::ClearRulesForTest();
	{
		int decision = -1;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kText, &decision, nullptr);
		Check("【负对照】没有规则 => 仍是内置替换（Action::Spoof）", a == kActionSpoof);
		Check("【负对照】没有规则 => Decision::Spoofed",
			decision == static_cast<int>(Decision::Spoofed));
	}

	// ---- 4.2 规则决定替换文本 ----
	Check("加载剪贴板面规则", UseRules(L"clip", kRulesClipReplace));
	{
		int idx = -1;
		const int act = ClipboardGuardTest::EvalClipRuleForTest(kText, &idx);
		Check("【因果】文本格式命中规则", act == static_cast<int>(RScript::Act::ReplaceText));
		Check("【因果】命中的是第 0 条", idx == 0);

		WCHAR text[64] = {};
		ClipboardGuardTest::RuleTextForTest(kText, text, _countof(text));
		Check("【因果】规则给的文本 == [已替换]", wcscmp(text, L"[已替换]") == 0);

		int decision = -1;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kText, &decision, nullptr);
		Check("【因果】有规则 => Action::Spoof", a == kActionSpoof);
	}

	// ---- 4.3 「拒绝」 ----
	Check("加载剪贴板「拒绝」规则",
		UseRules(L"clipblock", L"当 剪贴板 的 格式 等于 文本 时 拒绝\r\n"));
	{
		int decision = -1;
		ULONG flags = 0;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kText, &decision, &flags);
		Check("规则「拒绝」=> Action::Block", a == kActionBlock);
		Check("规则「拒绝」=> Decision::Blocked",
			decision == static_cast<int>(Decision::Blocked));
		Check("规则「拒绝」=> 置了 FlagEventBlocked",
			(flags & R3ShieldCore::FlagEventBlocked) != 0);
	}

	// ---- 4.4 「放行」 ----
	Check("加载剪贴板「放行」规则",
		UseRules(L"clippass", L"当 剪贴板 的 格式 等于 文本 时 放行\r\n"));
	{
		int decision = -1;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kText, &decision, nullptr);
		Check("规则「放行」=> Action::Pass", a == kActionPass);
		Check("规则「放行」=> Decision::Allowed",
			decision == static_cast<int>(Decision::Allowed));
	}

	// ---- 4.5 位图格式 + 「替换为 文本」=> 回落拒绝（铁律 194）----
	Check("加载「位图替换为文本」规则",
		UseRules(L"clipbmp", L"当 剪贴板 的 格式 等于 位图 时 替换为 \"x\"\r\n"));
	{
		int decision = -1;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kBitmap, &decision, nullptr);
		Check("【负对照】位图 + 「替换为 文本」=> 回落 Action::Block（造不出合法替代物）",
			a == kActionBlock);
		Check("【负对照】回落拒绝 => Decision::Blocked",
			decision == static_cast<int>(Decision::Blocked));
	}

	// ---- 4.6 总闸 ----
	{
		ResetPolicyAllOff();
		ClipboardGuardTest::SetCloseHookReady(true);
		UseRules(L"clipgate", kRulesClipReplace);
		int decision = -1;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kText, &decision, nullptr);
		Check("【负对照】spoof_clipboard 关着 => 规则不生效（回落拒绝）", a == kActionBlock);
	}

	// ---- 4.7 CloseClipboard 没挂上 => 一律不替换（v70 的前提检查仍在）----
	{
		ResetPolicyAllOff();
		GuardStub::PolicyPtr()->Flags2 |= R3ShieldCore::FlagSpoofClipboard;
		ClipboardGuardTest::SetCloseHookReady(false);
		UseRules(L"clipnohook", kRulesClipReplace);
		int decision = -1;
		const int a = ClipboardGuardTest::RejectOrSpoofForTest(kText, &decision, nullptr);
		Check("【负对照】CloseClipboard 未挂 => 不替换也不放行（Action::Block）",
			a == kActionBlock);
	}
}

// ================================================================== 5. 三面同表
static void TestAllFacesOneTable()
{
	printf("\n--- 5. 一张表管三个面（同一次加载，三个面各自命中）---\n");

	ResetPolicyAllOff();
	R3ShieldCore::Policy* p = GuardStub::PolicyPtr();
	p->Flags2 |= (R3ShieldCore::FlagSpoofRegistry
		| R3ShieldCore::FlagSpoofRegistryEnum | R3ShieldCore::FlagSpoofClipboard);
	ClipboardGuardTest::SetCloseHookReady(true);
	GuardStub::SetMode(static_cast<ULONG>(R3ShieldCore::Mode::Block));

	Check("一次加载三面规则", UseRules(L"all", kRulesAll));
	Check("表里 3 条", RegistryGuardTest::RuleCountForTest() == 3);

	const WCHAR* key = L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault";

	const auto value = RegistryGuardTest::EvaluateKeyEx(key, L"Password",
		static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
	Check("值面命中（#0）", value.action == kActionSpoof);

	Check("枚举面命中（#1）",
		RegistryGuardTest::EnumChildHidden(key,
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault\\SecretKey"));

	int idx = -1;
	Check("剪贴板面命中（#2）",
		ClipboardGuardTest::EvalClipRuleForTest(13, &idx)
			== static_cast<int>(RScript::Act::ReplaceText) && idx == 2);

	// ★ 负对照：一个都不该命中的面（值名 /Pass.*/ 不匹配 + 枚举名字不含 Secret）。
	const auto miss = RegistryGuardTest::EvaluateKeyEx(key, L"Other",
		static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), 0, false, 2);
	Check("【负对照】值名不匹配 => 值面不命中", miss.action != kActionSpoof);
	Check("【负对照】子键名不含 Secret => 枚举面不命中",
		!RegistryGuardTest::EnumChildHidden(key,
			L"\\REGISTRY\\MACHINE\\SOFTWARE\\R3SCDemo\\Vault\\PlainKey"));
}

// ------------------------------------------------------------------ 主流程
int main()
{
	setlocale(LC_ALL, ".936");
	printf("=== v78 规则脚本接进引擎 · guard 层单测 ===\n");

	TestLoad();
	TestRegValueFace();
	TestRegEnumFace();
	TestClipboardFace();
	TestAllFacesOneTable();

	CleanupTempFiles();

	printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
