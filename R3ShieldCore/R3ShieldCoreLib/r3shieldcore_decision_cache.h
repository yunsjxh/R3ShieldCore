#pragma once
//
// r3shieldcore_decision_cache.h —— 询问决策缓存（「始终允许 / 始终拒绝」）。
//
// ★ 语义（v130 定稿）：**同参数不再问，不同参数照问。**
//
//   一条规则的"参数"= 谁 + 做什么 + 对什么：
//     谁      → ProcessPath（用路径而不是 pid：同一程序开两个实例都算）
//     做什么  → ObjectType + Op（「允许打开」≠「允许删除」）
//     对什么  → **该面的全部目标字段**（见 HashTargetSignature）
//
// ★ 为什么这个文件要独立出来（而不是留在 r3shieldcore_prompt_ui.cpp 里）：
//   prompt_ui.cpp 拉进了 toast / comctl32 / UI 线程，单测为了验三个纯逻辑函数
//   得链一整套窗口代码。抽成 header-only 后，`tools/v130_decision_cache_ut.cpp`
//   只 include 本文件 + shared.h，毫秒级跑完。
//   与 v72 的 `registry_enum_codec.h` 同一思路。
//
// ⚠️ 新增目标参数时**必须**加进 HashTargetSignature() ——
//    漏一个就等于那个维度"不同参数也不问"，而这**看不出来**（日志里两条规则一样）。
//
#include <r3shieldcore/r3shieldcore_shared.h>

namespace R3ShieldCoreDecisionCache
{
	constexpr ULONG MaxRules = 256;

	// 规则存的是**目标参数的全量签名**（哈希），不再只存 keyPath。
	//
	// 为什么：一次询问的参数不止 KeyPath 一个 ——
	//   Registry     → KeyPath + **ValueName**（值名）
	//   DllLoad      → **DllPath**（KeyPath 是空的）
	//   ProcessSpawn → **CommandLine**
	//   Network      → KeyPath(远端地址) + **TargetPort** + **NetProtocol**
	// 只比 KeyPath 的后果是"不同参数也被当成同一条规则"：
	//   · 允许写 Run 的 ValueA ⇒ 写 ValueB 不再问
	//   · 允许加载 DLL-A ⇒ 加载 DLL-B 不再问（KeyPath 空时压根不命中，规则形同失效）
	//   · 允许连某地址的 443 ⇒ 同地址 8080 也不再问
	struct Rule
	{
		bool used;
		bool allow;
		ULONG objectType;	// 与签名里重复，但留着能在循环里早剪枝（少算哈希）
		ULONG op;			// 同上
		WCHAR processPath[R3ShieldCore::MaxProcessPathChars];
		ULONGLONG targetHash;	// 见 HashTargetSignature()
	};

	// 只有 UI 线程碰它们（prompt_ui.cpp 的 UiThreadProc），所以不加锁。
	// ⚠️ 如果将来有多线程调用点，**必须**补锁 —— 见铁律 291。
	inline Rule g_rules[MaxRules];
	inline ULONG g_nextRuleSlot = 0;

	// FNV-1a 64。用哈希而不是存字符串：参数最长 KeyPath(520) + ValueName(260)
	// + DllPath(260) + CommandLine(512) ≈ 1.5K 字符 × 256 条 ≈ 800KB；
	// 哈希后每条 8 字节。
	inline ULONGLONG HashBytes(ULONGLONG h, const void* data, size_t bytes) noexcept
	{
		const unsigned char* p = static_cast<const unsigned char*>(data);
		for (size_t i = 0; i < bytes; i++) {
			h ^= static_cast<ULONGLONG>(p[i]);
			h *= 1099511628211ULL;	// FNV-1a 64 的素数
		}
		return h;
	}

	// ⚠️ 字符串必须**带长度前缀**再喂：否则 ("ab","c") 与 ("a","bc")
	//    会拼出同一个字节流 ⇒ 不同参数被当成同一条规则。
	inline ULONGLONG HashString(ULONGLONG h, PCWSTR text) noexcept
	{
		const size_t chars = (text && text[0]) ? wcslen(text) : 0;
		h = HashBytes(h, &chars, sizeof(chars));
		if (chars > 0) {
			h = HashBytes(h, text, chars * sizeof(WCHAR));
		}
		return h;
	}

	// ★ 新增目标参数时**必须**加到这里。
	inline ULONGLONG HashTargetSignature(const R3ShieldCore::PromptSlot& request) noexcept
	{
		ULONGLONG h = 1469598103934665603ULL;	// FNV-1a 64 offset basis

		h = HashBytes(h, &request.ObjectType, sizeof(ULONG));
		h = HashBytes(h, &request.Op, sizeof(ULONG));
		h = HashBytes(h, &request.TargetKind, sizeof(ULONG));
		h = HashString(h, request.KeyPath);
		h = HashString(h, request.ValueName);
		h = HashString(h, request.DllPath);
		h = HashString(h, request.CommandLine);
		h = HashBytes(h, &request.TargetPort, sizeof(ULONG));
		h = HashBytes(h, &request.NetProtocol, sizeof(ULONG));
		return h;
	}

	inline bool LookupCached(const R3ShieldCore::PromptSlot& request,
		R3ShieldCore::Verdict& verdict) noexcept
	{
		const ULONGLONG signature = HashTargetSignature(request);

		for (ULONG i = 0; i < MaxRules; i++) {
			if (!g_rules[i].used) {
				continue;
			}

			// 谁在做。用路径而不是 pid：同一程序两个实例，用户点过一次就该都算。
			if (_wcsicmp(g_rules[i].processPath, request.ProcessPath) != 0) {
				continue;
			}

			// 早剪枝：面 + 操作不一致直接跳过（这两个也在签名里，重复但更快）。
			if (g_rules[i].objectType != request.ObjectType) {
				continue;
			}
			if (g_rules[i].op != request.Op) {
				continue;
			}

			// 目标参数**全量**比较 —— 值名 / DLL 路径 / 命令行 / 端口都在签名里。
			if (g_rules[i].targetHash != signature) {
				continue;
			}

			verdict = g_rules[i].allow ? R3ShieldCore::Verdict::Allow : R3ShieldCore::Verdict::Deny;
			return true;
		}

		return false;
	}

	inline void AddRule(const R3ShieldCore::PromptSlot& request, bool allow) noexcept
	{
		Rule& rule = g_rules[g_nextRuleSlot % MaxRules];
		g_nextRuleSlot++;

		rule.used = true;
		rule.allow = allow;
		rule.objectType = request.ObjectType;
		rule.op = request.Op;
		wcsncpy_s(rule.processPath, request.ProcessPath, _TRUNCATE);
		rule.targetHash = HashTargetSignature(request);
	}

	// 单测用：清空（生产路径不需要 —— 缓存跟着引擎进程走）。
	inline void ResetForTest() noexcept
	{
		for (ULONG i = 0; i < MaxRules; i++) {
			g_rules[i] = Rule{};
		}
		g_nextRuleSlot = 0;
	}
}
