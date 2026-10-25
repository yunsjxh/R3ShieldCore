//
// v130_decision_cache_ut.cpp —— 「始终允许 / 始终拒绝」的**参数粒度**单测。
//
// ★ 用户要求（原话）：「**AllowAlways 改成同参数不过问，不同参数还是要问**」。
//
// 旧实现只比 `KeyPath`（还是前缀匹配）⇒ 这些情况**都会误放**：
//   · 允许写 Run 的 ValueA ⇒ 写 ValueB 不再问（值名没参与）
//   · 允许加载 DLL-A ⇒ 加载 DLL-B 不再问（KeyPath 为空，规则压根不命中/或按空前缀放行）
//   · 允许连某地址 443 ⇒ 同地址 8080 也不再问（端口没参与，询问槽甚至没拷端口）
//
// 本单测钉的就是"哪些维度变了必须重新问"。**每条都是一个负对照**：
// 只有 ① 是"该命中"，②~⑨ 全是"不该命中" —— 如果有人把匹配写回
// "只比进程 + 操作"，① 仍然通过，②③⑥⑦⑨ 会全部变红。
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "r3shieldcore_decision_cache.h"

using R3ShieldCoreDecisionCache::AddRule;
using R3ShieldCoreDecisionCache::LookupCached;
using R3ShieldCoreDecisionCache::ResetForTest;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// PromptSlot 里有 volatile 成员，不能直接赋值构造 —— 逐字段填。
static R3ShieldCore::PromptSlot MakeSlot(R3ShieldCore::ObjectType type, ULONG op,
	PCWSTR processPath, PCWSTR keyPath = L"", PCWSTR valueName = L"")
{
	R3ShieldCore::PromptSlot slot = {};
	slot.ObjectType = static_cast<ULONG>(type);
	slot.Op = op;
	if (processPath) wcsncpy_s(slot.ProcessPath, processPath, _TRUNCATE);
	if (keyPath)     wcsncpy_s(slot.KeyPath, keyPath, _TRUNCATE);
	if (valueName)   wcsncpy_s(slot.ValueName, valueName, _TRUNCATE);
	return slot;
}

int main()
{
	setlocale(LC_ALL, "");

	const ULONG kSetValue = static_cast<ULONG>(R3ShieldCore::Op::SetValueKey);
	const ULONG kDeleteValue = static_cast<ULONG>(R3ShieldCore::Op::DeleteValueKey);
	const auto kRegistry = R3ShieldCore::ObjectType::Registry;
	const auto kDllLoad = R3ShieldCore::ObjectType::DllLoad;
	const auto kNetwork = R3ShieldCore::ObjectType::Network;

	PCWSTR kProc = L"C:\\Program Files\\Demo\\demo.exe";
	PCWSTR kRunKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

	printf("=== v130：同参数不过问，不同参数照问 ===\n");

	// ------------------------------------------------------------------
	// 注册表：值名必须参与
	// ------------------------------------------------------------------
	ResetForTest();
	{
		const auto base = MakeSlot(kRegistry, kSetValue, kProc, kRunKey, L"ValueA");
		AddRule(base, true);

		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		Check("① 同参数（同进程+同操作+同键+同值名）→ 命中，不再问",
			LookupCached(base, verdict) && verdict == R3ShieldCore::Verdict::Allow);

		auto otherValue = base;
		wcsncpy_s(otherValue.ValueName, L"ValueB", _TRUNCATE);
		Check("② 同键**不同值名** → 不命中（要重新问）", !LookupCached(otherValue, verdict));

		auto otherKey = base;
		wcsncpy_s(otherKey.KeyPath, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", _TRUNCATE);
		Check("③ 不同键路径 → 不命中", !LookupCached(otherKey, verdict));

		auto otherOp = base;
		otherOp.Op = kDeleteValue;
		Check("④ 不同操作（写 → 删）→ 不命中", !LookupCached(otherOp, verdict));

		auto otherProc = base;
		wcsncpy_s(otherProc.ProcessPath, L"C:\\Program Files\\Other\\other.exe", _TRUNCATE);
		Check("⑤ 不同进程 → 不命中", !LookupCached(otherProc, verdict));
	}

	// ------------------------------------------------------------------
	// DLL 加载面：KeyPath 是空的，靠 DllPath 区分
	// ------------------------------------------------------------------
	ResetForTest();
	{
		auto dllA = MakeSlot(kDllLoad, 1, kProc);
		wcsncpy_s(dllA.DllPath, L"C:\\Data\\trusted.dll", _TRUNCATE);
		AddRule(dllA, true);

		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		Check("⑥ 同 DLL → 命中", LookupCached(dllA, verdict));

		auto dllB = dllA;
		wcsncpy_s(dllB.DllPath, L"C:\\Data\\evil.dll", _TRUNCATE);
		Check("⑥ 同进程**不同 DLL** → 不命中（旧版这里 KeyPath 为空，规则形同失效）",
			!LookupCached(dllB, verdict));
	}

	// ------------------------------------------------------------------
	// 网络面：端口必须参与（询问槽原来根本没拷端口）
	// ------------------------------------------------------------------
	ResetForTest();
	{
		auto net443 = MakeSlot(kNetwork, 1, kProc, L"203.0.113.7");
		net443.TargetPort = 443;
		net443.NetProtocol = 6;	// IPPROTO_TCP
		AddRule(net443, true);

		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		Check("⑦ 同地址同端口 → 命中", LookupCached(net443, verdict));

		auto net8080 = net443;
		net8080.TargetPort = 8080;
		Check("⑦ 同地址**不同端口** → 不命中", !LookupCached(net8080, verdict));

		auto netUdp = net443;
		netUdp.NetProtocol = 17;	// IPPROTO_UDP
		Check("⑦ 同地址同端口**不同协议** → 不命中", !LookupCached(netUdp, verdict));
	}

	// ------------------------------------------------------------------
	// 始终拒绝也必须生效（不能只实现 AllowAlways）
	// ------------------------------------------------------------------
	ResetForTest();
	{
		const auto deny = MakeSlot(kRegistry, kSetValue, L"C:\\Bad\\bad.exe", kRunKey, L"X");
		AddRule(deny, false);

		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Allow;
		Check("⑧ 始终拒绝 → 同参数直接拒，不再问",
			LookupCached(deny, verdict) && verdict == R3ShieldCore::Verdict::Deny);
	}

	// ------------------------------------------------------------------
	// 拼接歧义：("ab","c") 与 ("a","bc") 不能撞成同一条
	//
	// 这条验的是签名实现里的**长度前缀**。如果哪天有人把 HashString 改成
	// "直接喂字符、不加长度"，这条会红 —— 而上面所有用例仍然全绿。
	// ------------------------------------------------------------------
	ResetForTest();
	{
		const auto s1 = MakeSlot(kRegistry, kSetValue, kProc, L"ab", L"c");
		AddRule(s1, true);

		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		const auto s2 = MakeSlot(kRegistry, kSetValue, kProc, L"a", L"bc");
		Check("⑨ 键名/值名边界不同（ab+c vs a+bc）→ 不命中", !LookupCached(s2, verdict));
	}

	printf("\n%d passed, %d failed\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
