//
// v72_guard_ut.cpp —— R3ShieldCore v72「注册表枚举隐藏」单测（**纯逻辑，不碰注册表**）。
//
// ★ v72 加了什么：
//   在 v71「值替换」（`NtQueryValueKey` 的数据区清零）之后，补上 Phase 3 的
//   第二半 —— **枚举隐藏**：枚举受保护位置的子键 / 值时，把命中
//   `protect_reg=` 前缀的项**从列表里去掉**（`Decision::Spoofed`）。
//   实现 = **索引重映射**（调用方要第 N 个可见项，我们扫出它对应的原始索引，
//   再真调一次原函数取那一项）。
//
// ★ 为什么这个单测和机制探针**都要有**（分工）：
//   · 本文件（guard 层单测）：**纯逻辑**，零注册表访问、零提权、毫秒级。
//     覆盖"触发门"（`CouldHaveProtectedChildRegistry`）、"决策"
//     （`Evaluate` 对枚举类操作返回 Spoof）、codec 三态解析、以及
//     **重映射算法本身**（含"命中就往后挪一格会重复"这个错的**负对照**）。
//   · `tools/spoof_reg_enum_probe.cpp`：**真 API**。自己挂自己的 hook，
//     在 HKCU 下建真键、跑真 `NtEnumerateKey` / `NtEnumerateValueKey`，
//     实测 `KEY_*_BASIC_INFORMATION` 布局并把它钉成判据。
//   两者缺一：只跑探针 ⇒ 算法分支（越界 / 探测失败 / 空名）覆盖不全；
//   只跑单测 ⇒ "真 API 到底认不认这套布局"没人证。
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <wchar.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "registry_enum_codec.h"
#include "r3shieldcore_rules.h"
#include <r3shieldcore/rules_codec.h>
// ★ v133：规则脚本的**加载状态机**。
//   单测必须能把它“钉住”，否则第一次 `Evaluate` 会**懒加载本机真实规则文件**，
//   把刚清空的表又填回去（见 `PinEmptyRuleScript`）。
#include "rules_script_runtime.h"

// registry_guard.cpp 尾部的单测入口（宏 REGUARD_GUARD_UT 打开）。
namespace RegistryGuardTest
{
	R3ShieldCore::Event EvaluateKey(PCWSTR keyPath, PCWSTR valueName, ULONG op,
		ULONG mode, bool blockable) noexcept;
}

// guard_stub.cpp 提供的控制器。
namespace GuardStub
{
	void ResetPolicy() noexcept;
	void SetMode(ULONG mode) noexcept;
	R3ShieldCore::Policy* PolicyPtr() noexcept;
}

using namespace R3ShieldCoreRegistryEnum;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ 夹具
//
// ★★★ v133：把**规则脚本的加载状态**钉死，让本单测与“这台机器上装了什么规则”完全解耦。
//
//   为什么 `Clear()` 一个人不够（v133 实测踩到，不是推理出来的）：
//     `registry_guard.cpp` 的 `Evaluate` **第一次**被调用时会走
//     `R3ShieldCoreRuleScriptRuntime::EnsureLoadedSafe()` —— 那是**懒加载**，
//     它从 `%ProgramData%\R3 Shield Core\r3shieldcore-rules.txt` 把**本机真实的**
//     规则读进表里。于是：
//         单测开头 `Clear()`   => 表空
//         第一次 `Evaluate`    => 懒加载把表**填回去**
//         “无关键 -> 不 Spoofed”  => 因为本机有一条枚举规则，
//                                    `HasFace(RegEnum)` 恒真 => 断言**恒 FAIL**
//     更阴的是“自己变绿”：换一台**没有**枚举规则的机器，同一条
//     断言就过了。依赖环境的断言比没有断言更糟 —— 它把“真回归”与
//     “这台机器的规则文件不一样”混在一起（铁律 184 同族）。
//
//   解法：`ForceLoadFrom(<一定不存在的路径>)` —— 它内部
//     ① `Clear()` 清表 ② 读失败（表仍空）③ 把状态机置成“已加载完毕”。
//   状态被钉住之后，后面**任何** `Evaluate` 都不会再去读真实文件。
//   ⇒ 这是 `rules_script_runtime.h` 里明写“单测 / 端到端夹具用”的那个入口。
static void PinEmptyRuleScript()
{
	WCHAR noSuchFile[MAX_PATH] = {};
	const DWORD n = GetTempPathW(MAX_PATH, noSuchFile);
	if (n == 0 || n >= MAX_PATH) { wcscpy_s(noSuchFile, L".\\"); }
	// 刻意**不创建**它 —— 我们要的就是“读不到”。
	wcscat_s(noSuchFile, L"r3shieldcore-ut-no-such-rules.txt");

	const bool loaded = R3ShieldCoreRuleScriptRuntime::ForceLoadFrom(noSuchFile);
	R3ShieldCoreRuleScript::Clear();  // 双保险：即便上面的读“成功”了也清掉

	// 夹具自检：这两条红了，后面所有“不 Spoofed”的负对照都不可信。
	Check("夹具：规则表已清空（Count == 0）", R3ShieldCoreRuleScript::Count() == 0);
	Check("夹具：懒加载已被钉住（不存在的路径读不到）", !loaded);

	// 诊断：把“本机真实规则文件在哪”打出来 —— 失败时一眼看出是被谁污染的。
	WCHAR realPath[MAX_PATH] = {};
	if (R3ShieldCoreRulesFile::ResolveRulesPath(nullptr, realPath, _countof(realPath))) {
		printf("  （本机真实规则文件已刻意忽略：%ls）\n", realPath);
	}
}

// ------------------------------------------------------------------ 工具
static void SetProtectReg(const wchar_t* path)
{
	R3ShieldCore::Policy* policy = GuardStub::PolicyPtr();
	ZeroMemory(policy->ProtectRegPaths, sizeof(policy->ProtectRegPaths));
	if (path && path[0] != L'\0') {
		// 手写拷贝而不是 `wcsncpy`：那个函数在 C4996 名单里，
		// 本项目的构建要求**零警告**。
		const size_t chars = wcslen(path);
		const size_t limit = R3ShieldCore::MaxProtectPathChars - 1;
		const size_t copy = chars < limit ? chars : limit;
		memcpy(policy->ProtectRegPaths[0], path, copy * sizeof(wchar_t));
		policy->ProtectRegPaths[0][copy] = L'\0';
		policy->ProtectRegCount = 1;
	}
	else {
		policy->ProtectRegCount = 0;
	}
}

static void SetEnumSpoof(bool on)
{
	R3ShieldCore::Policy* policy = GuardStub::PolicyPtr();
	if (on) policy->Flags2 |= R3ShieldCore::FlagSpoofRegistryEnum;
	else    policy->Flags2 &= ~R3ShieldCore::FlagSpoofRegistryEnum;
}

static void SetValueSpoof(bool on)
{
	R3ShieldCore::Policy* policy = GuardStub::PolicyPtr();
	if (on) policy->Flags2 |= R3ShieldCore::FlagSpoofRegistry;
	else    policy->Flags2 &= ~R3ShieldCore::FlagSpoofRegistry;
}

// ==================================================================
// 1. 触发门：CouldHaveProtectedChildRegistry（保守上界）
// ==================================================================
//
// 它的语义是"**值不值得扫一遍**"，方向必须是"宁可多扫，不可漏藏"。
// 所以断言要**两侧都设界**：既要 true 的地方真 true，也要
// **边界**（`MyC` vs `MyCompany`）与**无关路径**真 false ——
// 只查一侧必被骗（铁律 186）。
static void TestTriggerGate()
{
	printf("--- 1. 触发门 CouldHaveProtectedChildRegistry（保守上界）---\n");

	const wchar_t* kProtect = L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical";

	struct Case { const wchar_t* path; bool expect; const char* note; };
	const Case cases[] = {
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany", true,  "父键（受保护键就挂在它下面）" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical", true, "受保护键本身" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical\\Sub", true, "受保护键的子键（整棵子树都在前缀下）" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE", true, "更高的祖先" },
		{ L"\\REGISTRY\\MACHINE", true, "更高" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Other", false, "无关兄弟" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyC", false, "★边界：MyC 不是 MyCompany 的祖先" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany2", false, "★边界：MyCompany2 不是 MyCompany" },
		{ L"\\REGISTRY\\USER\\S-1-5-21-1\\Software", false, "★跨根：HKCU 与 HKLM 无关" },
	};

	SetProtectReg(kProtect);
	for (const Case& c : cases) {
		char line[256];
		snprintf(line, sizeof(line), "命中判据：%s", c.note);
		Check(line, R3ShieldCoreRules::CouldHaveProtectedChildRegistry(c.path) == c.expect);
	}

	// ★ 负对照：名单为空 ⇒ **一律 false**。
	//   没有这一条，"恒返回 true"的实现也能过上面所有 true 的用例。
	SetProtectReg(nullptr);
	Check("负对照：名单为空 -> 一律 false（含受保护键本身）",
		!R3ShieldCoreRules::CouldHaveProtectedChildRegistry(kProtect)
		&& !R3ShieldCoreRules::CouldHaveProtectedChildRegistry(L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany"));

	// ★ 用户文档给的是**相对形式**（`SOFTWARE\MyCompany\Critical`），
	//   而引擎还原出来的 KeyPath 是**原始完整形式**。两种写法都要认
	//   （与 `IsProtectedRegistryPathForSpoof` 同一套口径）。
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	Check("相对形式写法：原始完整形式的父键也判 true（两种写法都认）",
		R3ShieldCoreRules::CouldHaveProtectedChildRegistry(L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany"));
	Check("相对形式写法：无关路径仍 false",
		!R3ShieldCoreRules::CouldHaveProtectedChildRegistry(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Other"));
}

// ==================================================================
// 2.5 ★ v133 新增：**规则面**那一半触发条件（v78 引入）
// ==================================================================
//
// `Evaluate` 的枚举替换条件是
//     spoof_reg_enum=1 && ( CouldHaveProtectedChildRegistry(path)
//                           || RScript::HasFace(RegEnum) )
// 上面第 2 节把**规则脚本清空**之后，测的是前半段（路径触发）。
// 这一节专门测后半段 —— 它是一条**独立**的触发路径，不测就等于
// "用户写了枚举规则、却什么都没发生"这个场景没人管。
//
// ★ 语义要钉清楚：`HasFace(RegEnum)` 是**保守上界** ——
//   只要表里有**任意一条**枚举面规则，就把枚举类操作标成 Spoofed，
//   **不**看这条规则会不会命中这个键（那是 detour 逐项问规则的事）。
//   ⇒ 所以这里断言的是"**无关键也会标 Spoofed**"，方向与第 2 节相反；
//     两条合起来才说明"规则面是独立触发、且方向是保守的"。
static void TestRuleFaceTriggers()
{
	printf("\n--- 2.5 规则面触发（v78：有枚举规则就保守标 Spoofed）---\n");

	const wchar_t* kPlainKey = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Other\\Thing";
	const ULONG kLog = 0;
	const ULONG kSpoofed = static_cast<ULONG>(R3ShieldCore::Decision::Spoofed);

	// 前置负对照：脚本为空 ⇒ 无关键**不**标 Spoofed
	R3ShieldCoreRuleScript::Clear();
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("2.5a 前置：脚本为空 + 无关键 -> 不 Spoofed",
		RegistryGuardTest::EvaluateKey(kPlainKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision != kSpoofed);

	// 正例：加一条**枚举面**规则 ⇒ 同一个无关键变成 Spoofed（保守上界）
	int idx = -1;
	std::wstring err;
	const bool added = R3ShieldCoreRuleScript::Add(
		L"当 注册表枚举 的 子键名 含 \"Whatever\" 时 隐藏", err, &idx);
	Check("2.5b 夹具：成功加了一条枚举面规则", added);
	Check("2.5c 夹具：HasFace(RegEnum) 为真",
		R3ShieldCoreRuleScript::HasFace(R3ShieldCoreRuleScript::Face::RegEnum));

	Check("2.5d ★ 有枚举规则 + 无关键 -> 仍标 Spoofed（保守上界，不是漏判）",
		RegistryGuardTest::EvaluateKey(kPlainKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision == kSpoofed);

	// 负对照：只有**值面**规则时，枚举面**不受影响**
	R3ShieldCoreRuleScript::Clear();
	R3ShieldCoreRuleScript::Add(
		L"当 注册表值 的 值名 含 \"Whatever\" 时 替换为 \"***\"", err, &idx);
	Check("2.5e 负对照：只有值面规则 -> 枚举面仍不标 Spoofed",
		RegistryGuardTest::EvaluateKey(kPlainKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision != kSpoofed);

	// 收尾：清干净，别把状态漏给后面的用例
	R3ShieldCoreRuleScript::Clear();
}


// ==================================================================
// 2. 决策：Evaluate 对枚举类操作返回 Spoof
// ==================================================================
static void TestEvaluateDecision()
{
	printf("\n--- 2. 决策 Evaluate（枚举类 -> Spoof；其它操作不受影响）---\n");

	const wchar_t* kProtectedKey = L"\\REGISTRY\\MACHINE\\SOFTWARE\\MyCompany\\Critical";
	const wchar_t* kPlainKey     = L"\\REGISTRY\\MACHINE\\SOFTWARE\\Other\\Thing";
	const ULONG kLog = 0, kBlockAll = 3;

	const ULONG kSpoofed = static_cast<ULONG>(R3ShieldCore::Decision::Spoofed);

	// ★★★ v133 修：先把**规则脚本**清空，否则本单测的结果取决于
	//   **本机真实的** `%ProgramData%\R3 Shield Core\r3shieldcore-rules.txt`。
	//
	//   为什么（v78 引入）：`Evaluate` 的枚举替换条件是
	//       spoof_reg_enum=1 && ( CouldHaveProtectedChildRegistry(path)
	//                             || RScript::HasFace(RegEnum) )
	//   后半个或项的意思是“用户写了枚举面规则 => 无法静态判断这条规则会不会
	//   命中这个键 => 保守标 Spoofed，交给 detour 逐项问规则”。
	//   而本机那份规则文件里恰好有一条「当 注册表枚举 的子键名 含 Secret 时
	//   隐藏」=> `HasFace(RegEnum)` 恒真 => **两条负对照恒 FAIL**。
	//
	//   ★★ 关键细节（v133 第一版只加了这个 `Clear()`，然后**照样红**）：
	//   `Clear()` 只是“瞬间真”。`Evaluate` 第一次被调用时会走
	//   `EnsureLoadedSafe()` **懒加载**，把表又填回去。
	//   => 真正起作用的是 `main()` 里那个 `PinEmptyRuleScript()`
	//      （用 `ForceLoadFrom` 把加载状态机钉成“已完成”）；这里的 `Clear()`
	//      只是保险丝 —— 它能清表，但**阻止不了重新加载**。
	//
	//   实测证据（v133）：换成没有枚举规则的机器，这两条会“自己变绿”。
	//   这种**依赖环境**的断言比没有断言更糟 —— 它让“真回归”和“这台机器的
	//   规则文件不一样”混在一起（铁律 184 同族）。
	//   => 单测自己钉死状态；“规则面”那一半单独测（见 `TestRuleFaceTriggers`）。
	R3ShieldCoreRuleScript::Clear();

	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");

	// ---- 正例：枚举类 + 开关开 + 相关路径 -> Spoofed ----
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("EnumerateKey + spoof_reg_enum=1 + 相关键 -> Spoofed",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision == kSpoofed);

	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("EnumerateValueKey + spoof_reg_enum=1 + 相关键 -> Spoofed",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateValueKey), kLog, false).Decision == kSpoofed);

	// ---- 负例 1：开关关 ----
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	GuardStub::SetMode(kLog);
	Check("负对照：spoof_reg_enum=0 -> 不 Spoofed",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision != kSpoofed);

	// ---- 负例 2：无关路径 ----
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("负对照：无关键 -> 不 Spoofed",
		RegistryGuardTest::EvaluateKey(kPlainKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision != kSpoofed);

	// ---- 负例 3：名单为空 ----
	GuardStub::ResetPolicy();
	SetProtectReg(nullptr);
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("负对照：protect_reg 名单为空 -> 不 Spoofed（开关空转）",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision != kSpoofed);

	// ---- 负例 4：★ 写操作 / 打开操作**不受枚举隐藏影响** ----
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("负对照：SetValueKey（写）-> 不 Spoofed",
		RegistryGuardTest::EvaluateKey(kProtectedKey, L"X",
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey), kLog, true).Decision != kSpoofed);

	// ---- 负例 5：★ 两个位**互不串台**（双向）----
	//   只开枚举位时，**值读取**不该被判成 Spoof（那是 v71 的位管的）。
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("交叉：只开 spoof_reg_enum -> QueryValueKey 不 Spoofed（值替换是另一个位）",
		RegistryGuardTest::EvaluateKey(kProtectedKey, L"X",
			static_cast<ULONG>(R3ShieldCore::Op::QueryValueKey), kLog, false).Decision != kSpoofed);

	//   只开值替换位时，**枚举**不该被判成 Spoof。
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetValueSpoof(true);
	GuardStub::SetMode(kLog);
	Check("交叉：只开 spoof_reg -> EnumerateKey 不 Spoofed（枚举隐藏是另一个位）",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, false).Decision != kSpoofed);

	// ---- 负例 6：★ 全拦模式下一律不做替换（铁律 165）----
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kBlockAll);
	Check("全拦模式（block_all）-> 不 Spoofed（铁律 165：全拦下不做替换）",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kBlockAll, false).Decision != kSpoofed);

	// ---- 负例 7：blockable=true（非读路径）不该进替换分支 ----
	GuardStub::ResetPolicy();
	SetProtectReg(L"SOFTWARE\\MyCompany\\Critical");
	SetEnumSpoof(true);
	GuardStub::SetMode(kLog);
	Check("blockable=true -> 不 Spoofed（替换只在读路径上）",
		RegistryGuardTest::EvaluateKey(kProtectedKey, nullptr,
			static_cast<ULONG>(R3ShieldCore::Op::EnumerateKey), kLog, true).Decision != kSpoofed);
}

// ==================================================================
// 3. codec：ProbeBasicName 三态
// ==================================================================
static ULONG PutName(void* info, ULONG nameLengthOffset, ULONG nameOffset,
	const wchar_t* name) noexcept
{
	const ULONG nameBytes = static_cast<ULONG>(wcslen(name) * sizeof(wchar_t));
	memcpy(static_cast<BYTE*>(info) + nameLengthOffset, &nameBytes, sizeof(nameBytes));
	if (nameBytes > 0) {
		memcpy(static_cast<BYTE*>(info) + nameOffset, name, nameBytes);
	}
	return nameOffset + nameBytes;
}

static void TestCodecNameProbe()
{
	printf("\n--- 3. codec：ProbeBasicName 三态（Parsed / Unnamed / Indeterminate）---\n");

	// ---- 值枚举（KEY_VALUE_BASIC_INFORMATION：NameLength@8、Name@12）----
	{
		BYTE buf[256] = {};
		const ULONG used = PutName(buf, kValueBasicNameLengthOffset, kValueBasicNameOffset, L"Secret1");
		NameRegion r = {};
		Check("值枚举：正常名字 -> Parsed 且偏移/长度正确",
			ProbeBasicName(true, buf, sizeof(buf), used, r) == NameProbe::Parsed
			&& r.offset == kValueBasicNameOffset
			&& r.length == 7 * sizeof(wchar_t));
	}
	{
		// ★★ 空名（值的"(默认)"项）必须是 **Unnamed**，不能是 Indeterminate。
		//   否则任何有默认值的键都会让枚举隐藏整体失效，而且完全不报错。
		BYTE buf[256] = {};
		const ULONG used = PutName(buf, kValueBasicNameLengthOffset, kValueBasicNameOffset, L"");
		NameRegion r = {};
		Check("★ 值枚举：空名 -> Unnamed（不是 Indeterminate）",
			ProbeBasicName(true, buf, sizeof(buf), used, r) == NameProbe::Unnamed);
	}
	{
		BYTE buf[8] = {};
		NameRegion r = {};
		Check("值枚举：缓冲区短于名字头 -> Indeterminate",
			ProbeBasicName(true, buf, sizeof(buf), sizeof(buf), r) == NameProbe::Indeterminate);
	}
	{
		// 长度字段说 1000 字节，实际只给 32 ⇒ 越界 ⇒ Indeterminate
		BYTE buf[32] = {};
		const ULONG bogus = 1000;
		memcpy(buf + kValueBasicNameLengthOffset, &bogus, sizeof(bogus));
		NameRegion r = {};
		Check("值枚举：名字长度超出可用长度 -> Indeterminate",
			ProbeBasicName(true, buf, sizeof(buf), sizeof(buf), r) == NameProbe::Indeterminate);
	}
	{
		// 长度不是偶数（WCHAR 必须对齐）
		BYTE buf[64] = {};
		const ULONG odd = 7;
		memcpy(buf + kValueBasicNameLengthOffset, &odd, sizeof(odd));
		NameRegion r = {};
		Check("值枚举：名字长度为奇数 -> Indeterminate",
			ProbeBasicName(true, buf, sizeof(buf), sizeof(buf), r) == NameProbe::Indeterminate);
	}
	{
		NameRegion r = {};
		Check("info == nullptr -> Indeterminate",
			ProbeBasicName(true, nullptr, 64, 64, r) == NameProbe::Indeterminate);
	}
	{
		// 长度字段**回绕**：offset(12) + 0xFFFFFFF8 在 32 位里回绕成 4 < available。
		// 必须用 64 位算加法才挡得住（经典整数溢出漏判）。
		BYTE buf[64] = {};
		const ULONG huge = 0xFFFFFFF8u;
		memcpy(buf + kValueBasicNameLengthOffset, &huge, sizeof(huge));
		NameRegion r = {};
		Check("长度字段回绕 -> Indeterminate（64 位算加法）",
			ProbeBasicName(true, buf, sizeof(buf), sizeof(buf), r) == NameProbe::Indeterminate);
	}

	// ---- 键枚举（KEY_BASIC_INFORMATION：NameLength@12、Name@16）----
	{
		BYTE buf[256] = {};
		const ULONG used = PutName(buf, kKeyBasicNameLengthOffset, kKeyBasicNameOffset, L"Alpha");
		NameRegion r = {};
		Check("键枚举：正常名字 -> Parsed 且偏移/长度正确（头 16 字节）",
			ProbeBasicName(false, buf, sizeof(buf), used, r) == NameProbe::Parsed
			&& r.offset == kKeyBasicNameOffset
			&& r.length == 5 * sizeof(wchar_t));
	}
	{
		// ★ 两个 class 的头**不一样长**（16 vs 12）—— 用错偏移必须判不出。
		//
		// ⚠️ 光"填一份键枚举结构、再按值枚举的偏移读"是**空真**：
		//    ZeroMemory 之后偏移 8（TitleIndex 的位置）恰好是 0 ⇒ 会得到
		//    `Unnamed` 而不是 `Indeterminate`，断言就没在测偏移。
		//    所以先把 TitleIndex 位置填成**奇数**（值枚举会把它当 NameLength），
		//    再确认同一份缓冲区在**正确**偏移下仍是 `Parsed` ——
		//    这样"载体有效"和"偏移不同导致判不出"两件事同时被钉住
		//    （铁律 110：先问"全零时是否也成立"）。
		BYTE buf[256] = {};
		const ULONG oddTitleIndex = 7;
		memcpy(buf + kKeyBasicNameLengthOffset - 4, &oddTitleIndex, sizeof(oddTitleIndex));
		const ULONG used = PutName(buf, kKeyBasicNameLengthOffset, kKeyBasicNameOffset, L"Alpha");

		NameRegion rKey = {};
		Check("载体有效：同一份缓冲区按**键枚举**偏移读 -> Parsed",
			ProbeBasicName(false, buf, sizeof(buf), used, rKey) == NameProbe::Parsed);

		NameRegion rVal = {};
		Check("★ 用值枚举的偏移去读键枚举结构 -> 判不出（两个头长度不同）",
			ProbeBasicName(true, buf, sizeof(buf), used, rVal) == NameProbe::Indeterminate);
	}

	// ---- 兼容包装 LocateBasicName：Unnamed 不算成功 ----
	{
		BYTE buf[64] = {};
		const ULONG used = PutName(buf, kValueBasicNameLengthOffset, kValueBasicNameOffset, L"");
		NameRegion r = {};
		Check("LocateBasicName（旧口径）对空名返回 false",
			!LocateBasicName(true, buf, sizeof(buf), used, r));
	}
}

// ==================================================================
// 4. codec：BuildChildPath 边界
// ==================================================================
static void TestBuildChildPath()
{
	printf("\n--- 4. codec：BuildChildPath 边界 ---\n");

	wchar_t out[64] = {};

	Check("父路径不带结尾反斜杠 -> 补一个",
		BuildChildPath(L"A\\B", 3, L"C", 1, out, 64) && wcscmp(out, L"A\\B\\C") == 0);

	Check("★ 父路径已带结尾反斜杠 -> 不补（否则 \\\\ 会让前缀比较失真）",
		BuildChildPath(L"A\\B\\", 4, L"C", 1, out, 64) && wcscmp(out, L"A\\B\\C") == 0);

	Check("容量恰好够 -> 成功",
		BuildChildPath(L"A", 1, L"B", 1, out, 4) && wcscmp(out, L"A\\B") == 0);

	Check("★ 容量差一格 -> 失败（**不截断**：截断可能碰巧命中前缀）",
		!BuildChildPath(L"A", 1, L"B", 1, out, 3));

	Check("空名字 -> 结果就是 `父\\`（调用方不该用它去比前缀）",
		BuildChildPath(L"A", 1, L"", 0, out, 64) && wcscmp(out, L"A\\") == 0);

	Check("nullptr 参数 -> 失败",
		!BuildChildPath(nullptr, 0, L"B", 1, out, 64)
		&& !BuildChildPath(L"A", 1, nullptr, 0, out, 64)
		&& !BuildChildPath(L"A", 1, L"B", 1, nullptr, 64));
}

// ==================================================================
// 5. ★★ 重映射算法（合成列表 —— 不碰注册表）
// ==================================================================
//
// 这是本版本**最容易写错**的地方，所以用合成数据把三条性质钉死：
//   ① 索引正确（调用方要第 N 个可见项，拿到的就是第 N 个可见项）；
//   ② **无重复**（"命中就往后挪一格"那种写法会产生重复项）；
//   ③ 越界语义正确（可见项数不够 -> Exhausted）。
//
// ★ 并且配一个**负对照**：把"命中就往后挪一格"的错法也实现一遍，
//   断言它**确实**产生重复 —— 否则"无重复"这条断言无法证明有判别力
//   （铁律 110：先问全零时是否也成立）。
static const wchar_t* g_fakeNames[8] = {};
static bool g_fakeHidden[8] = {};
static int g_fakeCount = 0;
static int g_fakeFailAt = -1;   // 这个索引上让"真调"返回失败（模拟探测判不出）

static LONG FakeEnumCall(ULONG index, ULONG /*infoClass*/, PVOID info, ULONG length, PULONG resultLength) noexcept
{
	if (static_cast<int>(index) >= g_fakeCount) {
		if (resultLength) *resultLength = 0;
		return kStatusNoMoreEntries;
	}
	if (g_fakeFailAt >= 0 && static_cast<int>(index) == g_fakeFailAt) {
		if (resultLength) *resultLength = 0;
		return kStatusBufferTooSmall;
	}

	const wchar_t* name = g_fakeNames[index];
	const ULONG nameBytes = static_cast<ULONG>(wcslen(name) * sizeof(wchar_t));
	const ULONG need = kValueBasicNameOffset + nameBytes;

	if (need > length || length < kValueBasicNameOffset) {
		if (resultLength) *resultLength = need;
		return kStatusBufferOverflow;
	}

	BYTE* bytes = static_cast<BYTE*>(info);
	ZeroMemory(bytes, length < need ? length : need);
	memcpy(bytes + kValueBasicNameLengthOffset, &nameBytes, sizeof(nameBytes));
	if (nameBytes > 0) {
		memcpy(bytes + kValueBasicNameOffset, name, nameBytes);
	}
	if (resultLength) *resultLength = need;
	return 0;
}

static bool FakeIsHidden(const wchar_t* childPath) noexcept
{
	const wchar_t* slash = wcsrchr(childPath, L'\\');
	const wchar_t* name = slash ? slash + 1 : childPath;
	for (int i = 0; i < g_fakeCount; ++i) {
		if (_wcsicmp(g_fakeNames[i], name) == 0) {
			return g_fakeHidden[i];
		}
	}
	return false;
}

static const wchar_t* kFakeKeyPath = L"\\REGISTRY\\USER\\S-1-5-21-1\\Software\\Fake";

// 用生产同款算法做一次重映射。
static RemapResult RemapFake(ULONG callerIndex, ULONG& originalIndex, ULONG& hiddenCount)
{
	LONG probeStatus = 0;
	const bool ok = RemapEnumerationIndexImpl(true, FakeEnumCall, FakeIsHidden, callerIndex,
		kFakeKeyPath, static_cast<ULONG>(wcslen(kFakeKeyPath)), originalIndex, hiddenCount, probeStatus);
	const bool exhausted = ok && IsNoMoreEntries(probeStatus);
	return ClassifyRemap(ok, hiddenCount, originalIndex, callerIndex, exhausted);
}

// ★ 把判定结果折算成"**最终会真调哪个原始索引**"。
//
//   为什么需要这层：`ClassifyRemap` 把"前面一个隐藏项都没有"的情况归到
//   `Passthrough`（⇒ 生产走"原样调用 `Index`"那条路）。这是**刻意的等价折叠**：
//     · `Mapped(orig == callerIndex)` 与 `Passthrough` 的**行为完全相同**
//       （都是对 `callerIndex` 真调一次），但后者少一次多余调用，
//       而且"与开关关闭时逐字节相同"这句话可以**逐字成立**。
//   ⇒ 断言"索引 0 拿到 Alpha"时必须按**行为**断言，不能按枚举值断言，
//     否则会把一个正确的实现判成 FAIL。
static constexpr ULONG kNoIndex = 0xFFFFFFFFu;

static ULONG EffectiveIndex(ULONG callerIndex, ULONG& hiddenCount)
{
	ULONG originalIndex = 0;
	hiddenCount = 0;
	const RemapResult r = RemapFake(callerIndex, originalIndex, hiddenCount);

	if (r == RemapResult::Mapped) {
		return originalIndex;
	}
	if (r == RemapResult::Passthrough) {
		return callerIndex;   // 恒等：生产就是原样调用
	}
	return kNoIndex;          // Exhausted
}

// ★ 负对照用的**错法**：命中隐藏就往后挪一格。
//   列表 [A, B(藏), C, D(藏), E] 下：索引 1 -> B 藏 -> 挪到 C；
//   索引 2 -> C **可见** -> 又返回 C ⇒ 调用方看到 [A, C, C]（重复）。
static ULONG NaiveMap(ULONG callerIndex, ULONG& hiddenCount) noexcept
{
	ULONG index = callerIndex;
	hiddenCount = 0;
	for (int guard = 0; guard < 16; ++guard) {
		if (static_cast<int>(index) >= g_fakeCount) {
			return 0xFFFFFFFFu;
		}
		if (g_fakeHidden[index]) {
			hiddenCount++;
			index++;
			continue;
		}
		return index;
	}
	return 0xFFFFFFFFu;
}

static void SetFakeList(const wchar_t** names, const bool* hidden, int count)
{
	ZeroMemory(g_fakeNames, sizeof(g_fakeNames));
	ZeroMemory(g_fakeHidden, sizeof(g_fakeHidden));
	for (int i = 0; i < count; ++i) {
		g_fakeNames[i] = names[i];
		g_fakeHidden[i] = hidden[i];
	}
	g_fakeCount = count;
	g_fakeFailAt = -1;
}

static void TestRemapAlgorithm()
{
	printf("\n--- 5. 重映射算法（合成列表 [Alpha, SecretA*, Beta, SecretB*, Zulu]，* = 隐藏）---\n");

	const wchar_t* names[] = { L"Alpha", L"SecretA", L"Beta", L"SecretB", L"Zulu" };
	const bool hidden[] = { false, true, false, true, false };
	SetFakeList(names, hidden, 5);

	// ---- ① 索引正确（按**行为**断言，见 EffectiveIndex 的说明）----
	{
		ULONG hid = 0;
		const ULONG idx = EffectiveIndex(0, hid);
		Check("调用方索引 0 -> 原始索引 0（Alpha；前面没有隐藏项，映射到它自己）",
			idx == 0 && hid == 0);
	}
	{
		ULONG orig = 0, hid = 0;
		const RemapResult r = RemapFake(0, orig, hid);
		Check("★ 索引 0 且前面无隐藏项 -> Passthrough（生产走原样调用，与开关关闭等价）",
			r == RemapResult::Passthrough);
	}
	{
		ULONG hid = 0;
		const ULONG idx = EffectiveIndex(1, hid);
		Check("★ 调用方索引 1 -> 原始索引 2（Beta，跳过 SecretA）", idx == 2 && hid == 1);
	}
	{
		ULONG hid = 0;
		const ULONG idx = EffectiveIndex(2, hid);
		Check("★ 调用方索引 2 -> 原始索引 4（Zulu，跳过 SecretA + SecretB）", idx == 4 && hid == 2);
	}

	// ---- ② 越界 ----
	{
		ULONG orig = 0, hid = 0;
		const RemapResult r = RemapFake(3, orig, hid);
		Check("★ 调用方索引 3（可见项只有 3 个）-> Exhausted（不是 Mapped）",
			r == RemapResult::Exhausted && hid == 2);
	}

	// ---- ③ 无重复（把 0..2 实际拿到的项名收集起来）----
	{
		const wchar_t* got[3] = { nullptr, nullptr, nullptr };
		bool ok = true;
		for (ULONG i = 0; i < 3; ++i) {
			ULONG hid = 0;
			const ULONG idx = EffectiveIndex(i, hid);
			if (idx == kNoIndex) { ok = false; break; }
			got[i] = g_fakeNames[idx];
		}
		Check("★ 无重复：三个可见索引分别拿到 Alpha / Beta / Zulu",
			ok && wcscmp(got[0], L"Alpha") == 0
			&& wcscmp(got[1], L"Beta") == 0
			&& wcscmp(got[2], L"Zulu") == 0);
	}

	// ---- ★ 负对照：证明"无重复"这条断言**有判别力** ----
	{
		ULONG h0 = 0, h1 = 0, h2 = 0;
		const ULONG naive0 = NaiveMap(0, h0);
		const ULONG naive1 = NaiveMap(1, h1);
		const ULONG naive2 = NaiveMap(2, h2);
		Check("★ 负对照：「命中就往后挪一格」的错法**确实**产生重复（索引 1 与 2 都指向 Beta）",
			naive0 == 0 && naive1 == 2 && naive2 == 2);
	}

	// ---- ④ 空名项按"可见"处理，**不能**中止扫描 ----
	{
		const wchar_t* names2[] = { L"", L"Alpha", L"SecretA" };
		const bool hidden2[] = { false, false, true };
		SetFakeList(names2, hidden2, 3);

		ULONG hid = 0;
		const ULONG idx0 = EffectiveIndex(0, hid);
		Check("★ 空名项（默认值）在索引 0 -> 按可见处理（不中止扫描，映射到它自己）",
			idx0 == 0);

		ULONG hid1 = 0;
		const ULONG idx1 = EffectiveIndex(1, hid1);
		Check("★ 空名项之后的可见项仍能正确映射（Alpha）", idx1 == 1 && hid1 == 0);

		ULONG orig2 = 0, hid2 = 0;
		const RemapResult r2 = RemapFake(2, orig2, hid2);
		Check("★ 空名项存在时，隐藏项仍被跳过且越界语义正确",
			r2 == RemapResult::Exhausted && hid2 == 1);
	}

	// ---- ⑤ 探测判不出 -> Passthrough（原样调用，绝不猜）----
	{
		SetFakeList(names, hidden, 5);
		g_fakeFailAt = 1;   // 扫到索引 1 时"真调"失败

		ULONG orig = 0, hid = 0;
		const RemapResult r = RemapFake(2, orig, hid);
		Check("★ 探测失败 -> Passthrough（宁可漏藏，不拿猜的名字去判）",
			r == RemapResult::Passthrough);

		g_fakeFailAt = -1;
	}

	// ---- ⑥ 一项都没藏 -> Passthrough（与开关关闭时**行为等价**）----
	{
		const bool noneHidden[] = { false, false, false, false, false };
		SetFakeList(names, noneHidden, 5);

		ULONG orig = 0, hid = 0;
		const RemapResult r = RemapFake(2, orig, hid);
		Check("★ 一项都没藏 -> Passthrough（走原样调用，与开关关闭逐字节相同）",
			r == RemapResult::Passthrough && hid == 0);
	}

	// ---- ⑦ 全部隐藏 -> Exhausted（列表变空）----
	{
		const bool allHidden[] = { true, true, true, true, true };
		SetFakeList(names, allHidden, 5);

		ULONG orig = 0, hid = 0;
		const RemapResult r = RemapFake(0, orig, hid);
		Check("全部隐藏 -> 调用方索引 0 也 Exhausted（列表变空）",
			r == RemapResult::Exhausted && hid == 5);
	}

	// ---- ⑧ 空键路径 -> Passthrough ----
	{
		SetFakeList(names, hidden, 5);
		LONG st = 0;
		ULONG orig = 0, hid = 0;
		const bool ok = RemapEnumerationIndexImpl(true, FakeEnumCall, FakeIsHidden, 0,
			L"", 0, orig, hid, st);
		Check("空键路径 -> 判不出（Passthrough）", !ok);
	}

	// ---- ⑨ 夹具自身的键路径没超上限（否则 Remap 会走"判不出"分支，
	//         上面那些断言会**恒绿**却什么也没测）----
	Check("夹具：合成键路径长度在上限内",
		wcslen(kFakeKeyPath) + 1 < kMaxKeyPathChars);
}

// ------------------------------------------------------------------ 主流程
int main()
{
	setlocale(LC_ALL, ".936");
	printf("=== v72 注册表枚举隐藏 · guard 层单测（纯逻辑，不碰注册表）===\n");

	// ★★★ 必须是**第一件事**：拿下面任何一条负对照之前，先把懒加载钉死。
	//   （夹具自检会多打两条 PASS，那是有意的 —— 铁律 148：夹具不可信时要能一眼看出来。）
	PinEmptyRuleScript();
	printf("\n");

	TestTriggerGate();
	TestEvaluateDecision();
	TestRuleFaceTriggers();
	TestCodecNameProbe();
	TestBuildChildPath();
	TestRemapAlgorithm();

	printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
