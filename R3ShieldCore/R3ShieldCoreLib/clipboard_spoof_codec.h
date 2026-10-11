#pragma once
//
// clipboard_spoof_codec.h —— 剪贴板替换的「伪造内容构造」。
//
// 职责单一：给定**格式号**与**真实句柄**，造出一块**同格式、同尺寸、
// 内容中性化**的替代物；以及按格式分型地把它释放掉。
//
// ★★ 为什么单独成一个**头文件**（而不是塞进 clipboard_guard.cpp）：
//   这份逻辑要**同时**被两处使用 ——
//     ① 生产：`clipboard_guard.cpp` 的 `GetClipboardData_Hook`；
//     ② 验证：`tools/spoof_clipboard_probe.cpp`（自挂自测探针）。
//   抄两份 ⇒ 必漂（铁律 127：同一份清单拷贝多份必然漂移，且漂了之后
//   探针照样全绿、生产照样出错）。全部 `inline` ⇒ 探针直接 `#include`
//   即可，不需要链接 lib、不需要改构建。
//
// ⚠️ 这里**不做**任何判定（不读 Policy、不看 mode、不打日志）——
//   那是 guard 的事。本文件是纯函数：进什么、出什么，没有全局状态。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <string.h>
#include <stdio.h>
#include <wchar.h>

namespace R3ShieldCoreClipboardSpoof
{
	// 伪造内容的大小上限。超过 ⇒ 退化到"最小合法内容"。
	//
	// ★ 为什么要有上限：造"同尺寸"的替代物意味着**再分配一份**（剪贴板里
	//   那张 100MB 的图，我们要再要 100MB）。攻击者可以用一张巨大的剪贴板
	//   图把被注入进程的地址空间挤爆 —— 那是"替换"引入的新 DoS 面。
	//   上限之内的行为不受影响。
	constexpr SIZE_T MaxFakeBytes = 64u * 1024u * 1024u;

	// 能伪造的格式。**不在表里的一律回落 Block**（见下面 BuildFake 的注释）。
	enum class FakeKind
	{
		Unsupported,   // 造不出合法布局 ⇒ 调用方必须回落"拒绝"
		Text,          // CF_TEXT / CF_OEMTEXT / CF_UNICODETEXT（HGLOBAL 里的字符串）
		Bitmap,        // CF_BITMAP —— ⚠️ 这是 HBITMAP（GDI 对象），不是 HGLOBAL！
		Dib,           // CF_DIB / CF_DIBV5（HGLOBAL 里的 BITMAPINFO + 像素）
	};

	inline FakeKind ClassifyFormat(UINT format) noexcept
	{
		switch (format) {
		case 1:  return FakeKind::Text;    // CF_TEXT
		case 2:  return FakeKind::Bitmap;  // CF_BITMAP
		case 7:  return FakeKind::Text;    // CF_OEMTEXT
		case 8:  return FakeKind::Dib;     // CF_DIB
		case 13: return FakeKind::Text;    // CF_UNICODETEXT
		case 17: return FakeKind::Dib;     // CF_DIBV5
		default: return FakeKind::Unsupported;
		}
	}

	// 格式的**显示名** —— 规则引擎按它匹配（`当 剪贴板 的 格式 等于 文本 时 …`）。
	//
	// ★ 为什么放在这里、而不是各调用方自己 switch 一遍：
	//   "哪些格式算文本"这件事 **ClassifyFormat 已经定义了**，再抄一份必然漂
	//   （铁律 127/195）。所以显示名直接从分类结果推，只有一个真源。
	// ★ 位图与文本分开命名：这两类的**动作相容性**不同（文本能"替换为 <串>"，
	//   位图只能清零），名字混着用会让人以为可以互换。
	// ★ 不在表里的格式（含 CF_DIB 8 / CF_DIBV5 17）落回**数字串** ——
	//   与旧版控制台逐字一致，不要顺手改成"位图"。
	inline const WCHAR* FormatLabel(UINT format, WCHAR* buf, size_t bufChars) noexcept
	{
		switch (ClassifyFormat(format)) {
		case FakeKind::Text:   return L"文本";
		case FakeKind::Bitmap: return L"位图";
		default:
			if (buf && bufChars) {
				_snwprintf_s(buf, bufChars, _TRUNCATE, L"%u", format);
				return buf;
			}
			return L"";
		}
	}

	// ------------------------------------------------------------------
	// 分配
	// ------------------------------------------------------------------
	//
	// ⚠️ `GlobalAlloc(..., 0)` 返回 NULL（不是"空块"）⇒ 至少 1 字节。
	// ⚠️ `GMEM_ZEROINIT` 让内容天然是 0 —— 文本 ⇒ 空串，像素 ⇒ 全 0。
	//    这样我们**不需要** GlobalLock 去清零，少一次锁/解锁配对出错的机会。
	inline HGLOBAL AllocZeroed(size_t bytes) noexcept
	{
		if (bytes == 0) {
			bytes = 1;
		}
		return GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
	}

	// ------------------------------------------------------------------
	// 文本：最小合法空串
	// ------------------------------------------------------------------
	//
	// ⚠️ 长度按**格式的字符宽度**算：CF_UNICODETEXT 是 UTF-16，空串也要
	//    一个 WCHAR（2 字节，含结尾 NUL）；ANSI 系只要 1 字节。
	//    给 Unicode 只分 1 字节 ⇒ 调用方读第一个 WCHAR 就越界。
	inline HGLOBAL BuildEmptyText(UINT format) noexcept
	{
		const size_t bytes = (format == 13 /*CF_UNICODETEXT*/) ? sizeof(WCHAR) : sizeof(char);
		return AllocZeroed(bytes);
	}

	// ------------------------------------------------------------------
	// DIB：同尺寸，头 + 调色板原样保留，像素字节清零
	// ------------------------------------------------------------------
	//
	// 算「头 + 调色板」占多少字节。**必须算对**：多算 ⇒ 把像素当调色板抄走
	// （内容没被中性化）；少算 ⇒ 把调色板当像素清掉（调色板索引全变 0，
	// 对 8bpp 图是"颜色变了但形状还在"，对 1bpp 是黑图 —— 前者是**未中性化**）。
	inline bool DibHeaderBytes(const BYTE* base, size_t total, size_t& out) noexcept
	{
		if (!base || total < sizeof(BITMAPINFOHEADER)) {
			return false;
		}

		const BITMAPINFOHEADER* h = reinterpret_cast<const BITMAPINFOHEADER*>(base);

		// 只认标准的那几个 biSize —— 其它值我们不知道头后面跟的是什么布局。
		switch (h->biSize) {
		case 40:  break;   // BITMAPINFOHEADER
		case 52:  break;   // BITMAPV2INFOHEADER（掩码在头里）
		case 56:  break;   // BITMAPV3INFOHEADER（+alpha 掩码）
		case 108: break;   // BITMAPV4HEADER
		case 124: break;   // BITMAPV5HEADER
		default:  return false;
		}
		if (static_cast<size_t>(h->biSize) > total) {
			return false;
		}
		if (h->biWidth <= 0 || h->biHeight == 0) {
			return false;
		}
		switch (h->biCompression) {
		case BI_RGB:
		case BI_BITFIELDS:
			break;
		default:
			// RLE / JPEG / PNG：字节布局不是"每像素固定位数"，不猜。
			return false;
		}

		size_t palette = 0;
		if (h->biBitCount <= 8) {
			palette = (static_cast<size_t>(1) << h->biBitCount) * sizeof(RGBQUAD);
		}
		else if (h->biBitCount == 16 || h->biBitCount == 32) {
			// ⚠️ biSize==40 时，BI_BITFIELDS 的 3 个掩码 DWORD **跟在头后面**
			//    （它们不是像素！不抄走 ⇒ 调用方按掩码解像素会解出垃圾）。
			//    biSize>=52 的掩码已经在头里，palette 保持 0。
			if (h->biSize == sizeof(BITMAPINFOHEADER) && h->biCompression == BI_BITFIELDS) {
				palette = 3 * sizeof(DWORD);
			}
		}
		else if (h->biBitCount != 24) {
			return false;   // 1/4/8 已处理；其余（0 等）非法
		}

		const size_t need = static_cast<size_t>(h->biSize) + palette;
		if (need > total) {
			return false;
		}
		out = need;
		return true;
	}

	// 最小合法 DIB：1x1、32bpp、BI_RGB、像素为 0。
	//
	// 用在两处：① 真实 DIB 太大（超上限）；② 真实 DIB 的头认不出来。
	// ★ 为什么"退化"比"原样返回"好：原样返回 = 泄露真实内容，替换白做；
	//   而一个 1x1 的合法 DIB 是**任何**消费者都能解析的（尺寸在头里，
	//   调用方不该假设它等于自己请求的尺寸）。
	inline HGLOBAL BuildMinimalZeroedDib() noexcept
	{
		const size_t bytes = sizeof(BITMAPINFOHEADER) + 4;   // 1 个 32bpp 像素
		HGLOBAL fake = AllocZeroed(bytes);
		if (!fake) {
			return nullptr;
		}

		BITMAPINFOHEADER* h = static_cast<BITMAPINFOHEADER*>(GlobalLock(fake));
		if (!h) {
			GlobalFree(fake);
			return nullptr;
		}
		h->biSize = sizeof(BITMAPINFOHEADER);
		h->biWidth = 1;
		h->biHeight = 1;      // 正高度 = bottom-up；只有 1 行，无所谓
		h->biPlanes = 1;
		h->biBitCount = 32;
		h->biCompression = BI_RGB;
		h->biSizeImage = 4;
		GlobalUnlock(fake);
		return fake;
	}

	inline HGLOBAL BuildZeroedDib(HGLOBAL real) noexcept
	{
		if (!real) {
			return nullptr;
		}

		const SIZE_T total = GlobalSize(real);
		if (total == 0 || total > MaxFakeBytes) {
			return BuildMinimalZeroedDib();
		}

		const void* src = GlobalLock(real);
		if (!src) {
			return BuildMinimalZeroedDib();
		}

		size_t headerBytes = 0;
		const bool headerOk = DibHeaderBytes(static_cast<const BYTE*>(src),
			static_cast<size_t>(total), headerBytes);

		HGLOBAL fake = AllocZeroed(static_cast<size_t>(total));
		void* dst = fake ? GlobalLock(fake) : nullptr;

		if (headerOk && dst) {
			// 头 + 调色板原样保留（"同格式"），其余字节已经是 0
			// （GMEM_ZEROINIT）⇒ 像素被中性化。
			memcpy(dst, src, headerBytes);
		}

		if (dst) {
			GlobalUnlock(fake);
		}
		GlobalUnlock(real);

		if (!headerOk || !dst) {
			if (fake) {
				GlobalFree(fake);
			}
			return BuildMinimalZeroedDib();
		}
		return fake;
	}

	// ------------------------------------------------------------------
	// CF_BITMAP：同尺寸的 1bpp 全零 DDB
	// ------------------------------------------------------------------
	//
	// ⚠️ 格式 2 返回的是 **HBITMAP**（GDI 对象），不是 HGLOBAL ——
	//    对它 GlobalLock/GlobalSize 是错的用法。它得用 CreateBitmap 造、
	//    用 DeleteObject 释放（见 FreeFake）。
	//
	// ★ 1bpp + 全零位 = 索引 0 = 黑。造 1bpp 而不是 32bpp 是因为
	//   位图内容由**位数组**决定，1bpp 每行只要 (w+15)/16*2 字节，
	//   分配量最小、清零最便宜，而结果同样是"一张全黑的同尺寸图"。
	inline HBITMAP BuildZeroedBitmap(HBITMAP real) noexcept
	{
		if (!real) {
			return nullptr;
		}

		BITMAP bm = {};
		if (GetObjectW(real, sizeof(bm), &bm) == 0) {
			return nullptr;   // 不是位图 / 句柄无效 ⇒ 造不出来，让调用方回落
		}
		if (bm.bmWidth <= 0 || bm.bmHeight <= 0) {
			return nullptr;
		}

		const size_t stride = (static_cast<size_t>(bm.bmWidth) + 15) / 16 * 2;
		const size_t bytes = stride * static_cast<size_t>(bm.bmHeight);
		if (bytes == 0 || bytes > MaxFakeBytes) {
			return nullptr;
		}

		void* bits = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
		if (!bits) {
			return nullptr;
		}
		// CreateBitmap 会**拷贝** lpBits ⇒ 可以立刻把临时缓冲还回去。
		HBITMAP fake = CreateBitmap(bm.bmWidth, bm.bmHeight, 1, 1, bits);
		HeapFree(GetProcessHeap(), 0, bits);
		return fake;
	}

	// ------------------------------------------------------------------
	// 统一入口 / 释放
	// ------------------------------------------------------------------
	//
	// ⚠️ 返回 nullptr 有两种含义，调用方**必须区分**（铁律 97）：
	//    · ClassifyFormat == Unsupported ⇒ **格式不支持**，调用方应回落 Block；
	//    · 支持但分配失败 ⇒ 替换**没做成**，同样回落 Block（不能把真实句柄
	//      当"伪造成功"返回 —— 那就是静默泄露）。
	//    本函数用 `ClassifyFormat` 让调用方先判第一种（guard 里就是这么做的）。
	inline HANDLE BuildFake(UINT format, HANDLE real) noexcept
	{
		if (!real) {
			return nullptr;
		}

		switch (ClassifyFormat(format)) {
		case FakeKind::Text:
			return BuildEmptyText(format);
		case FakeKind::Bitmap:
			return BuildZeroedBitmap(reinterpret_cast<HBITMAP>(real));
		case FakeKind::Dib:
			return BuildZeroedDib(reinterpret_cast<HGLOBAL>(real));
		default:
			return nullptr;
		}
	}

	// ⚠️ 释放必须**按格式分型**：HGLOBAL 用 GlobalFree，HBITMAP 用 DeleteObject。
	//    混用 ⇒ 要么泄漏，要么把 GDI 句柄表搞坏（那是全进程的）。
	inline void FreeFake(UINT format, HANDLE fake) noexcept
	{
		if (!fake) {
			return;
		}
		if (ClassifyFormat(format) == FakeKind::Bitmap) {
			DeleteObject(reinterpret_cast<HGDIOBJ>(fake));
		}
		else {
			GlobalFree(reinterpret_cast<HGLOBAL>(fake));
		}
	}
}
