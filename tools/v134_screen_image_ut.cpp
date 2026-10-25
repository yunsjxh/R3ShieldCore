//
// v134_screen_image_ut.cpp —— 截屏替换「外部图片来源」的单测（v134）。
//
// ======================================================================
// 它证明什么 / 不证明什么
// ======================================================================
// 证明：`screen_spoof_image.h` 那几个函数**真的把图片画上去了** ——
//   不是"代码里调了 StretchBlt"，而是"目标位图的像素确实等于图片的颜色，
//   且不是全 0（黑帧）"。用的是真 GDI、真 BMP 文件、真 GetDIBits 读回。
//
// **不**证明：引擎真的把 ini 解析成了 `Policy::SpoofScreenImagePath`、
//   真的在 BitBlt hook 里走了这条分支。那两件事分别由
//   `build_verify_dist.sh`（配置解析）与 `tools/spoof_screen_probe.exe`
//   （自挂 hook，黑帧基线）覆盖；把三者拼起来的**端到端**仍需真引擎
//   （`tools/spoof_e2e.sh --run-engine`，本机禁止）。
//
// ======================================================================
// ★ 判据为什么拿"图片自己的像素"当基准，而不是硬编某个色值
// ======================================================================
//   硬编色值要自己算 DIB 的 BGRA 内存序、行方向、行距对齐 —— 算错的话
//   测试和实现**一起错**，反而看不出问题（铁律 110 同族：判据与被测同源）。
//   ⇒ 先 `LoadImageW` 出 HBITMAP，用 GetDIBits 读它自己的像素当 `ref`，
//     再让 `PaintRect` 画到另一个位图、读回 `got`，比较两者。
//     这样"铺满 + 颜色对"是同一个比较就验掉了。
//
// 构建/运行：bash build_screen_image_ut.sh --run
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

// ★ 生产与单测**共用同一份**实现（铁律 127）。
#include "screen_spoof_image.h"

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) { g_pass++; } else { g_fail++; }
}

// ---------------------------------------------------------------------
// 写一个 w x h 的**纯色** 24bpp BMP（bottom-up，标准不压缩格式）
// ---------------------------------------------------------------------
// ★ 为什么手写而不是用 GDI 保存：`LoadImageW` 读的就是文件字节，
//   手写能让"文件里到底是什么"完全确定（不受 GDI 保存时的格式选择影响）。
static bool WriteSolidBmp(const WCHAR* path, int w, int h, BYTE r, BYTE g, BYTE b)
{
	const int stride = ((w * 3) + 3) & ~3;
	const DWORD pixels = static_cast<DWORD>(stride) * static_cast<DWORD>(h);
	const DWORD fileSize = 54 + pixels;

	BYTE* buf = static_cast<BYTE*>(calloc(1, fileSize));
	if (!buf) { return false; }

	// BITMAPFILEHEADER（14 字节，用小端手写，避免结构体对齐差异）
	buf[0] = 'B'; buf[1] = 'M';
	memcpy(buf + 2, &fileSize, 4);
	const DWORD offBits = 54;
	memcpy(buf + 10, &offBits, 4);

	// BITMAPINFOHEADER（40 字节）
	BYTE* ih = buf + 14;
	DWORD v = 40;
	memcpy(ih + 0, &v, 4);                       // biSize
	LONG lv = w;  memcpy(ih + 4, &lv, 4);        // biWidth
	lv = h;       memcpy(ih + 8, &lv, 4);        // biHeight（正 = bottom-up）
	WORD wv = 1;  memcpy(ih + 12, &wv, 2);       // biPlanes
	wv = 24;      memcpy(ih + 14, &wv, 2);       // biBitCount
	v = 0;        memcpy(ih + 16, &v, 4);        // biCompression = BI_RGB
	v = pixels;   memcpy(ih + 20, &v, 4);        // biSizeImage

	// 像素：每个像素 3 字节 BGR
	for (int y = 0; y < h; ++y)
	{
		BYTE* row = buf + 54 + static_cast<size_t>(y) * stride;
		for (int x = 0; x < w; ++x)
		{
			row[x * 3 + 0] = b;
			row[x * 3 + 1] = g;
			row[x * 3 + 2] = r;
		}
	}

	HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (f == INVALID_HANDLE_VALUE) { free(buf); return false; }
	DWORD wrote = 0;
	const bool ok = WriteFile(f, buf, fileSize, &wrote, nullptr) && wrote == fileSize;
	CloseHandle(f);
	free(buf);
	return ok;
}

// 把一个 HBITMAP 的像素读成 32bpp BGRA（用于比较）
static bool ReadBitmap32(HDC ref, HBITMAP bmp, int w, int h, DWORD* out)
{
	if (!bmp || !out) { return false; }
	HDC mem = CreateCompatibleDC(ref);
	if (!mem) { return false; }
	HGDIOBJ old = SelectObject(mem, bmp);
	if (!old || old == HGDI_ERROR) { DeleteDC(mem); return false; }

	BITMAPINFO bi = {};
	bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bi.bmiHeader.biWidth = w;
	bi.bmiHeader.biHeight = -h;     // top-down
	bi.bmiHeader.biPlanes = 1;
	bi.bmiHeader.biBitCount = 32;
	bi.bmiHeader.biCompression = BI_RGB;

	const int lines = GetDIBits(mem, bmp, 0, static_cast<UINT>(h), out, &bi, DIB_RGB_COLORS);
	SelectObject(mem, old);
	DeleteDC(mem);
	return lines == h;
}

// 把 target 的 LastWriteTime **强制**改成与 like 一致。
//
// ★ 为什么要这个夹具：Windows 对 `ftLastWriteTime` 是**懒更新**，本机实测
//   连续写两个文件、20 轮里 10 轮拿到**完全相同**的时间戳。
//   靠"碰巧相同"来测缓存键 ⇒ 时红时绿（实测就出现过 29/0 变 28/1）。
//   强制设成相同，才能把"偶发"变成"必然"。
// ★ 返回 true 的前提是**改完之后真的相等**（再读一次核对）——
//   否则夹具没生效，下面的断言就是空真（铁律 110）。
static bool ForceStamp(const WCHAR* target, const WCHAR* like)
{
	WIN32_FILE_ATTRIBUTE_DATA src = {};
	if (!GetFileAttributesExW(like, GetFileExInfoStandard, &src)) { return false; }

	HANDLE f = CreateFileW(target, FILE_WRITE_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (f == INVALID_HANDLE_VALUE) { return false; }
	const BOOL wrote = SetFileTime(f, nullptr, nullptr, &src.ftLastWriteTime);
	CloseHandle(f);
	if (!wrote) { return false; }

	WIN32_FILE_ATTRIBUTE_DATA now = {};
	if (!GetFileAttributesExW(target, GetFileExInfoStandard, &now)) { return false; }
	return now.ftLastWriteTime.dwLowDateTime == src.ftLastWriteTime.dwLowDateTime
		&& now.ftLastWriteTime.dwHighDateTime == src.ftLastWriteTime.dwHighDateTime;
}

int main()
{
	setlocale(LC_ALL, ".936");
	printf("=== v134 截屏替换「外部图片来源」单测（真 GDI，不注入）===\n\n");

	WCHAR tempDir[MAX_PATH] = {};
	if (GetTempPathW(MAX_PATH, tempDir) == 0) { printf("GetTempPath 失败\n"); return 2; }

	WCHAR bmpPath[MAX_PATH] = {};
	swprintf_s(bmpPath, L"%sr3sc_screen_image_ut.bmp", tempDir);

	WCHAR badPath[MAX_PATH] = {};
	swprintf_s(badPath, L"%sr3sc_screen_image_ut_notimage.bmp", tempDir);

	WCHAR missingPath[MAX_PATH] = {};
	swprintf_s(missingPath, L"%sr3sc_screen_image_ut_missing_%lu.bmp", tempDir,
		static_cast<unsigned long>(GetTickCount()));

	// 图片用**非黑、非灰、非纯色三原色**的取值：这样"读回全 0"（黑帧）
	// 与"读回原值"能一刀切开，不会被"恰好也是黑"骗过。
	const BYTE kR = 0x12, kG = 0x34, kB = 0x56;
	const int kImgW = 4, kImgH = 4;

	// ================================================================
	// 1. 夹具：写图 / 写一个"假 BMP"（其实不是图片）/ 一个不存在的路径
	// ================================================================
	printf("--- 1. 夹具 ---\n");
	Check("写一个 4x4 纯色 BMP", WriteSolidBmp(bmpPath, kImgW, kImgH, kR, kG, kB));

	{
		// 扩展名是 .bmp，内容却是文本 —— 模拟"用户填错了文件"。
		HANDLE f = CreateFileW(badPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		bool ok = false;
		if (f != INVALID_HANDLE_VALUE)
		{
			const char* junk = "this is definitely not a bitmap";
			DWORD wrote = 0;
			ok = WriteFile(f, junk, static_cast<DWORD>(strlen(junk)), &wrote, nullptr) != FALSE;
			CloseHandle(f);
		}
		Check("写一个「假 BMP」（内容是文本）", ok);
	}
	Check("不存在的路径没有被创建", GetFileAttributesW(missingPath) == INVALID_FILE_ATTRIBUTES);

	// ================================================================
	// 2. Load：正常 / 假图 / 不存在 / 空串
	// ================================================================
	printf("\n--- 2. Load（缓存 + 失败要缓存）---\n");
	R3ShieldCoreScreenImage::Forget();
	HBITMAP img = R3ShieldCoreScreenImage::Load(bmpPath);
	Check("Load 真 BMP 成功", img != nullptr);
	Check("读出的尺寸是 4x4",
		R3ShieldCoreScreenImage::Width() == 4 && R3ShieldCoreScreenImage::Height() == 4);
	Check("第二次 Load 走缓存（同一 HBITMAP）",
		R3ShieldCoreScreenImage::Load(bmpPath) == img);

	{
		HBITMAP same = R3ShieldCoreScreenImage::Load(L"");
		Check("空路径 -> nullptr（=> 调用方走黑帧）", same == nullptr);
	}

	// ★★★ 回归：**缓存键必须含路径**（v134 修掉的真缺陷）
	//
	// 原实现只比 mtime，注释却写着"同一路径 + 同一修改时间"——两处口径不一致
	// （铁律 97）。后果：换成另一张图、mtime 恰好相同，就**继续画上一张图**，
	// 且没有任何报错，排查的人会去怀疑 ini 路径/权限/重启，不会怀疑缓存键。
	{
		Check("夹具：把「假 BMP」的 mtime 改成与真图**完全一致**",
			ForceStamp(badPath, bmpPath));

		R3ShieldCoreScreenImage::Forget();
		HBITMAP good = R3ShieldCoreScreenImage::Load(bmpPath);
		Check("先加载真图（占住缓存槽）", good != nullptr);

		HBITMAP cross = R3ShieldCoreScreenImage::Load(badPath);
		Check("mtime 相同但路径不同 -> nullptr（缓存键含路径）", cross == nullptr);

		// 再反过来：假图把缓存占了之后，真图仍然读得到（失败缓存也要按路径分）
		Check("假图之后仍能读回真图", R3ShieldCoreScreenImage::Load(bmpPath) != nullptr);
	}

	// ================================================================
	// 3. PaintRect：画进一块 DC，读回比对
	// ================================================================
	printf("\n--- 3. PaintRect（DC 路径：BitBlt / StretchBlt / PrintWindow 共用）---\n");

	HDC screen = GetDC(nullptr);
	Check("拿到屏幕 DC", screen != nullptr);
	if (!screen) { return 2; }

	// 目标位图故意做成 8x8（与 4x4 的图片**尺寸不等**）=> 必须拉伸铺满。
	const int kDstW = 8, kDstH = 8;
	HDC dstDc = CreateCompatibleDC(screen);
	HBITMAP dstBmp = CreateCompatibleBitmap(screen, kDstW, kDstH);
	Check("创建目标位图 8x8", dstDc && dstBmp);
	if (!dstDc || !dstBmp) { return 2; }
	HGDIOBJ oldDst = SelectObject(dstDc, dstBmp);

	// 先把目标涂成**另一个已知色**：这样"没画上"和"画上了"也能分开
	// （空白位图本身是黑的，与"回落黑帧"混在一起就分不清了）。
	{
		RECT r = { 0, 0, kDstW, kDstH };
		HBRUSH br = CreateSolidBrush(RGB(0xFF, 0xFF, 0xFF));
		FillRect(dstDc, &r, br);
		DeleteObject(br);
	}

	Check("PaintRect 返回 true（真的画上了）",
		R3ShieldCoreScreenImage::PaintRect(dstDc, 0, 0, kDstW, kDstH, bmpPath));

	// ⚠⚠ MSDN 明写：`GetDIBits` 要求位图**不能正选在一个 DC 里**。
	//   第一版就是忘了这句：位图还选在 dstDc 上，
	//   读回时 `SelectObject` 失败 => 返回 false，于是三条断言全红。
	//   （而 PaintDib 那边是对的，因为它用的是**临时**位图）。
	//   => 每次读之前先把 `oldDst` 选回去，读完再选回来。
	SelectObject(dstDc, oldDst);
	DWORD got[8 * 8] = {};
	const bool readGot = ReadBitmap32(screen, dstBmp, kDstW, kDstH, got);
	SelectObject(dstDc, dstBmp);
	Check("读回目标位图", readGot);

	// 与图片自己的像素比（不硬编色值，理由见文件头）
	HBITMAP imgReload = R3ShieldCoreScreenImage::Load(bmpPath);
	DWORD ref[4 * 4] = {};
	const bool readRef = ReadBitmap32(screen, imgReload, kImgW, kImgH, ref);
	Check("读回图片自己的像素（基准）", readRef);

	if (readGot && readRef)
	{
		int diff = 0, nonBlack = 0;
		for (int i = 0; i < kDstW * kDstH; ++i)
		{
			if (got[i] != ref[0]) { ++diff; }
			if ((got[i] & 0x00FFFFFFu) != 0) { ++nonBlack; }
		}
		printf("     目标 64 像素：与图片色不同的 %d 个，非黑 %d 个（ref=0x%08lX）\n",
			diff, nonBlack, static_cast<unsigned long>(ref[0]));
		Check("★ 全部 64 个像素都等于图片颜色（拉伸铺满，不留边缘）", diff == 0);
		Check("★ 不是黑帧（非黑像素 64 个）", nonBlack == 64);
		Check("图片色本身不是黑（否则上面两条会空真）", (ref[0] & 0x00FFFFFFu) != 0);
	}

	// 画到**局部矩形**：只有那块被改，其余保持原色（白色）
	{
		RECT r = { 0, 0, kDstW, kDstH };
		HBRUSH br = CreateSolidBrush(RGB(0xFF, 0xFF, 0xFF));
		FillRect(dstDc, &r, br);
		DeleteObject(br);

		const bool ok = R3ShieldCoreScreenImage::PaintRect(dstDc, 2, 2, 4, 4, bmpPath);
		DWORD got2[8 * 8] = {};
		SelectObject(dstDc, oldDst);          // 同上：先选出去才能 GetDIBits
		ReadBitmap32(screen, dstBmp, kDstW, kDstH, got2);
		SelectObject(dstDc, dstBmp);
		// (0,0) 落在矩形外 => 还是白；(3,3) 在矩形内 => 图片色
		const bool outUntouched = (got2[0] & 0x00FFFFFFu) == 0x00FFFFFFu;
		const bool inPainted = readRef && got2[3 * kDstW + 3] == ref[0];
		printf("     局部绘制：角上 (0,0)=0x%08lX，(3,3)=0x%08lX\n",
			static_cast<unsigned long>(got2[0]), static_cast<unsigned long>(got2[3 * kDstW + 3]));
		Check("PaintRect 只画指定矩形（矩形外未被涂改）", ok && outUntouched);
		Check("PaintRect 矩形内是图片色", inPainted);
	}

	// 失败路径：三个都必须返回 false，好让调用方回落黑帧
	Check("PaintRect 用「假 BMP」-> false（回落黑帧）",
		!R3ShieldCoreScreenImage::PaintRect(dstDc, 0, 0, kDstW, kDstH, badPath));
	Check("PaintRect 用不存在路径 -> false（回落黑帧）",
		!R3ShieldCoreScreenImage::PaintRect(dstDc, 0, 0, kDstW, kDstH, missingPath));
	Check("PaintRect 用空路径 -> false（回落黑帧）",
		!R3ShieldCoreScreenImage::PaintRect(dstDc, 0, 0, kDstW, kDstH, L""));
	Check("PaintRect 宽高为 0 -> false",
		!R3ShieldCoreScreenImage::PaintRect(dstDc, 0, 0, 0, 0, bmpPath));

	// ================================================================
	// 4. PaintDib：GetDIBits 那条路（只有裸缓冲区，没有 DC）
	// ================================================================
	printf("\n--- 4. PaintDib（GetDIBits 路径）---\n");
	{
		const int w = 6, h = 6;
		DWORD* bits = static_cast<DWORD*>(calloc(static_cast<size_t>(w) * h, sizeof(DWORD)));
		BITMAPINFO bi = {};
		bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bi.bmiHeader.biWidth = w;
		bi.bmiHeader.biHeight = -h;
		bi.bmiHeader.biPlanes = 1;
		bi.bmiHeader.biBitCount = 32;
		bi.bmiHeader.biCompression = BI_RGB;

		Check("PaintDib 返回 true",
			R3ShieldCoreScreenImage::PaintDib(bits, &bi, h, bmpPath));

		int nonBlack = 0, diff = 0;
		for (int i = 0; i < w * h; ++i)
		{
			if ((bits[i] & 0x00FFFFFFu) != 0) { ++nonBlack; }
			if (readRef && bits[i] != ref[0]) { ++diff; }
		}
		printf("     缓冲区 %d 像素：非黑 %d 个，与图片色不同 %d 个\n", w * h, nonBlack, diff);
		Check("★ 缓冲区被填成图片色（不是全 0）", nonBlack == w * h && diff == 0);

		// 压缩格式：不该猜字节布局，必须拒绝（=> 调用方回落 memset(0)）
		BITMAPINFO jpg = bi;
		jpg.bmiHeader.biCompression = BI_JPEG;
		Check("PaintDib 遇到 BI_JPEG -> false（不猜压缩布局）",
			!R3ShieldCoreScreenImage::PaintDib(bits, &jpg, h, bmpPath));

		Check("PaintDib 用不存在路径 -> false",
			!R3ShieldCoreScreenImage::PaintDib(bits, &bi, h, missingPath));

		free(bits);
	}

	// ================================================================
	// 5. 缓存失效：改文件（且改 mtime）=> 必须重载
	// ================================================================
	printf("\n--- 5. 缓存失效（用户改图要能生效）---\n");
	{
		const DWORD_PTR before = reinterpret_cast<DWORD_PTR>(
			R3ShieldCoreScreenImage::Load(bmpPath));

		// 换成另一种颜色，并把 mtime 往后拨 2 秒（同一秒内写两次 mtime 可能不变）。
		Check("重写图片（换成另一色）",
			WriteSolidBmp(bmpPath, kImgW, kImgH, 0xC8, 0x00, 0x00));
		HANDLE f = CreateFileW(bmpPath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (f != INVALID_HANDLE_VALUE)
		{
			FILETIME now = {};
			GetSystemTimeAsFileTime(&now);
			ULARGE_INTEGER u;
			u.LowPart = now.dwLowDateTime;
			u.HighPart = now.dwHighDateTime;
			u.QuadPart += 20000000ull;   // +2s（100ns 单位）
			FILETIME later;
			later.dwLowDateTime = u.LowPart;
			later.dwHighDateTime = u.HighPart;
			SetFileTime(f, nullptr, nullptr, &later);
			CloseHandle(f);
		}

		HBITMAP after = R3ShieldCoreScreenImage::Load(bmpPath);
		Check("mtime 变了 => 重新加载（不是旧 HBITMAP）",
			after != nullptr && reinterpret_cast<DWORD_PTR>(after) != before);

		// 新图必须是红色（0x0000C8 的 R 通道在 DIB 里是第 3 字节）
		DWORD got2[4 * 4] = {};
		if (ReadBitmap32(screen, after, kImgW, kImgH, got2))
		{
			const DWORD rgb = got2[0] & 0x00FFFFFFu;
			printf("     新图首像素 = 0x%08lX\n", static_cast<unsigned long>(rgb));
			// ★ 别用 `GetRValue`：它吃的是 **COLORREF**(0x00BBGGRR)，
			//   而 DIB 像素 DWORD 是 **0x00RRGGBB** —— 直接套会把 R/B 对调。
			//   （测试第一版就是这么红的：实际 0x00C80000 已经是红了。）
			Check("重载后拿到的是新颜色（R=0xC8）", rgb == 0x00C80000u);
		}
		else
		{
			Check("读回重载后的图片", false);
		}
	}

	// 文件被删 => 必须丢掉缓存并返回 nullptr（用户删图 = 想关掉）
	{
		DeleteFileW(bmpPath);
		Check("删掉图片后 Load -> nullptr（不继续用旧图）",
			R3ShieldCoreScreenImage::Load(bmpPath) == nullptr);
	}

	// ================================================================
	// 收尾
	// ================================================================
	SelectObject(dstDc, oldDst);
	DeleteObject(dstBmp);
	DeleteDC(dstDc);
	ReleaseDC(nullptr, screen);

	R3ShieldCoreScreenImage::Forget();
	DeleteFileW(bmpPath);
	DeleteFileW(badPath);

	printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
