#pragma once
//
// spoof_apply_codec.h —— 把「规则引擎的判定」落到真实返回值上的**落地逻辑**。
//
// ★ 为什么抽成共享头（铁律 195：同一份逻辑不抄第二遍）
//   同一段"判定 -> 字节到底怎么写"要**逐字一致**地被两处使用：
//     · `tools/spoof_console.cpp`             —— 交互式控制台（高级模式）
//     · `R3ShieldCore/r3shieldcore_gui.cpp`   —— 主程序「高级」页签
//   抄两份必然漂（铁律 127）：漂了之后控制台照样全绿，而界面显示的是另一回事。
//
// ★ 与两个「面 codec」的分工（**不要混**）
//     · `registry_spoof_codec.h` / `clipboard_spoof_codec.h` —— **面特定**的
//       "数据区在哪 / 替代物怎么造"，生产 guard 也在用（住在 R3ShieldCoreLib/）；
//     · 本文件 —— **与面无关**的"判定 -> 写什么字节"这一层。
//   所以本文件**不 include** 那两个面 codec：定位与构造由调用方先做好，
//   把 region / 格式号传进来即可。这样它不依赖 R3ShieldCoreLib/，
//   `shared/` 的分层不被破坏（shared 是 lib 与 exe **共同**的底层）。
//
// ★ 铁律：**长度字段一个都不改**（与 registry_spoof_codec.h 同一条原则）——
//   改了长度就要同步改一堆字段，改错一个宿主就读越界。
//   所以这里只动"数据字节"，绝不碰结构头里的任何 ULONG。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <string.h>
#include <wchar.h>

#include <r3shieldcore/rules_codec.h>

namespace R3ShieldCoreSpoofApply
{
	using R3ShieldCoreRuleScript::Act;
	using R3ShieldCoreRuleScript::Verdict;

	// 这次落地**实际做了什么**。
	//
	// ★ 是语义枚举而不是"成功/失败"布尔（铁律 97）："拒绝"、"放行"、"替换成什么"
	//   三者在界面上必须分得开 —— 都显示"没换成真值"就等于什么都没说。
	enum class Effect
	{
		Nothing,         // 数据区长度为 0 / 指针为空 / 越界 —— 一个字节都没动
		Rejected,        // 规则要求拒绝（调用方应返回失败）
		PassThrough,     // 规则要求放行 —— 原样返回
		TextRewritten,   // 把规则给的文本按 UTF-16 写进数据区（放不下则截断并补 0）
		BytesFilled,     // 整段填同一个字节
		Zeroed,          // 整段清零（生产的默认行为）
	};

	// 注册表值：把判定落到数据区 `[base + offset, +length)` 上。
	//
	//   ruleHit == false ⇒ 没命中任何规则，**回落**调用方给的 `fallbackFill`
	//                      （生产行为是 0，见 registry_spoof_codec.h 的 ZeroDataRegion）。
	//   ruleHit == true  ⇒ 按 verdict 的动作落值。
	//
	// ★ 越界一律不写。`offset` / `length` 由调用方用**生产 codec** 的
	//   `LocateDataRegion` 算出来，这里只再核一次（铁律 186：判据两侧都要设界）——
	//   防的是"调用方传进来的 region 不是本函数算的"。
	inline Effect ApplyRegValue(const Verdict& v, bool ruleHit,
		BYTE* base, size_t bufferLength, size_t offset, size_t length,
		BYTE fallbackFill) noexcept
	{
		// ★ 拒绝 / 放行**先判**：它们与"有没有数据区"无关 ——
		//   即使这个 InformationClass 没有数据区（class 0），"拒绝"依然成立。
		if (ruleHit) {
			if (v.act == Act::Block) return Effect::Rejected;
			if (v.act == Act::Pass)  return Effect::PassThrough;
		}

		if (!base || length == 0) return Effect::Nothing;
		if (offset > bufferLength || length > bufferLength - offset) return Effect::Nothing;

		BYTE* dst = base + offset;

		if (ruleHit && v.act == Act::ReplaceText) {
			// 按 UTF-16 写进数据区，**长度字段一个字节不改**（生产原则）；
			// 放不下就截断 —— 调用方拿到的是"成功、但内容被换了"。
			const size_t want = v.text.size() * sizeof(WCHAR);
			const size_t n = (want < length) ? want : length;
			if (n) memcpy(dst, v.text.c_str(), n);
			if (length > n) memset(dst + n, 0, length - n);
			return Effect::TextRewritten;
		}

		// 规则命中但动作是"替换为 空" / "全XX"，或**根本没命中规则**（回落）。
		const BYTE fill = (ruleHit && v.act == Act::ReplaceByte) ? v.fill
			: (ruleHit ? 0 : fallbackFill);
		memset(dst, fill, length);
		return (fill == 0) ? Effect::Zeroed : Effect::BytesFilled;
	}

	// 剪贴板文本：造一块**同格式**的文本（UTF-16 / ANSI）。
	//
	// ★ 长度按**格式的字符宽度**算：CF_UNICODETEXT(13) 的空串也要一个 WCHAR（2 字节），
	//   只给 1 字节的话调用方读第一个 WCHAR 就越界 —— 与 clipboard_spoof_codec.h 的
	//   `BuildEmptyText` 是同一条规矩。
	// ★ 返回 nullptr ⇒ 调用方**必须**回落拒绝（铁律 194：造不出合法替代物就不硬造）。
	inline HGLOBAL BuildClipText(UINT format, const WCHAR* text) noexcept
	{
		const bool unicode = (format == 13 /*CF_UNICODETEXT*/);
		const size_t chars = text ? wcslen(text) : 0;

		if (chars == 0) {
			const size_t bytes = unicode ? sizeof(WCHAR) : sizeof(char);
			return GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
		}

		if (unicode) {
			const size_t bytes = (chars + 1) * sizeof(WCHAR);
			HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
			if (!h) return nullptr;
			void* p = GlobalLock(h);
			if (!p) { GlobalFree(h); return nullptr; }
			memcpy(p, text, chars * sizeof(WCHAR));
			GlobalUnlock(h);
			return h;
		}

		const int need = WideCharToMultiByte(CP_ACP, 0, text, static_cast<int>(chars),
			nullptr, 0, nullptr, nullptr);
		if (need <= 0) return nullptr;
		HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, static_cast<size_t>(need) + 1);
		if (!h) return nullptr;
		void* p = GlobalLock(h);
		if (!p) { GlobalFree(h); return nullptr; }
		WideCharToMultiByte(CP_ACP, 0, text, static_cast<int>(chars),
			static_cast<char*>(p), need, nullptr, nullptr);
		GlobalUnlock(h);
		return h;
	}

	// 动作的**一句话描述** —— "这次落地到底做了什么"。
	//
	// ★ 与 rules_codec.h 的 `ActDesc` **不是**一回事，别合并：
	//   那个描述**规则本身**（`替换为 "x"`），本函数描述**落地结果**（`整段清零`）。
	//   界面上两句话都要有，才能把"我写了什么规则"和"它实际干了什么"对上。
	inline const WCHAR* EffectName(Effect e) noexcept
	{
		switch (e) {
		case Effect::Nothing:       return L"没动（没有可替换的数据区）";
		case Effect::Rejected:      return L"拒绝（调用方拿到失败）";
		case Effect::PassThrough:   return L"放行（规则要求，原样返回）";
		case Effect::TextRewritten: return L"写入了规则指定的文本";
		case Effect::BytesFilled:   return L"整段填了同一个字节";
		case Effect::Zeroed:        return L"整段清零";
		default:                    return L"?";
		}
	}
}
