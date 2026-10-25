#pragma once
//
// screen_spoof_image.h —— 截屏替换的**外部图片来源**（v134）。
//
// ======================================================================
// 它解决什么
// ======================================================================
// v67 的截屏替换是**黑帧**（`PatBlt(BLACKNESS)`）。黑帧能证明"调用成功但内容
// 是假的"，但一眼就露：任何程序看到全黑都会怀疑被 hook；而且用户没法把
// 画面伪装成任何东西。
//
// v134 让替换内容来自**外部图片文件**（ini `spoof_screen_image=`）：
// 被截取的区域会被**拉伸铺满**这张图。cfg 里可以直接填路径。
//
// ======================================================================
// ★ 为什么放在**被注入进程**里解码（而不是引擎解码后共享像素）
// ======================================================================
//   ① 共享像素要让引擎建一个几 MB 的共享节，还要处理 DACL（被注入的可能
//      是普通用户进程）；漏了 DACL 就是"引擎能写、目标读不到"或反过来
//      —— 这类问题只在别的机器上暴露。
//   ② 缩放必须按**目标进程自己**的 DPI/尺寸做（`BitBlt` 的目标矩形就是
//      调用者要的尺寸），共享一份固定分辨率的像素反而要再缩一次。
//   ③ 解码只付**一次**（按"路径 + 文件修改时间"缓存），之后就是一次
//      `StretchBlt` / `StretchDIBits`，与画黑帧同量级。
//
// ======================================================================
// ★ 为什么只认 `LoadImageW` 能解的格式（BMP / ICO / CUR）
// ======================================================================
//   PNG/JPG 要走 WIC（`windowscodecs.dll` + `CoInitialize`）或 GDI+
//   （`GdiplusStartup`）。两者都是**在被注入进程里**初始化 COM/GDI+ ——
//   而这段代码活在 `BitBlt` 的热路径里：
//     · `CoInitialize` 会挑线程模型，宿主线程若已用别的模型 ⇒ 失败/改行为；
//     · `GdiplusStartup` 有全局状态与锁，在别人进程里启动它属于越界；
//     · 两者都会在 hook 里做**重活**，失败时还要分清"是我的问题还是宿主的问题"。
//   ⇒ v134 **只支持 `LoadImageW` 能解的格式**，并在 cfg 的提示里写清
//     「BMP」。要 PNG 的话正确做法是**在引擎侧**解码成 BMP 落盘一个缓存，
//     再把缓存路径下发 —— 那是下一步，不是这一版硬塞进来的东西。
//
// ======================================================================
// ★ 失败语义：一律**回落黑帧**，绝不回落"真画面"
// ======================================================================
//   调用方（screen_guard）的写法是"先试图片，失败再涂黑"。所以本文件里
//   每个函数**只**回答"我有没有真的画上"，不做任何"算了吧就这样"的兜底。
//   这条很重要：替换功能的失败方向必须是**更像假**，不是"更像真"。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif

namespace R3ShieldCoreScreenImage
{
	// 缓存：**同一路径 + 同一修改时间**才复用。
	//
	// ★ 为什么要看 mtime 而不是"加载过一次就永远用"：
	//   用户改图之后必须能生效（改完重启引擎也行，但 mtime 判断让它
	//   连重启都不用 —— 而这一步`GetFileAttributesEx` 只花一次系统调用）。
	// ★ 为什么不做多槽 LRU：配置里只有**一个**图片路径，单槽就是完整语义。
	//   多槽只会让"当前到底用哪张"变得需要推理。
	//
	// ★★★ 为什么键里**必须**有路径（v134 修）：原实现只比 mtime，注释写着
	//   "同一路径 + 同一修改时间"，代码却漏了路径 —— 两处口径不一致（铁律 97）。
	//   这不是理论问题：本机实测**连续写两个文件，20 轮里 10 轮**拿到**完全
	//   相同**的 `ftLastWriteTime`（Windows 对 LastWriteTime 是懒更新，
	//   粒度远粗于 NTFS 的 100ns）⇒ 换成另一张图、恰好 mtime 相同，就会
	//   **继续画上一张图**，且没有任何报错。
	//   症状是"改了配置没生效"，而排查的人会去怀疑 ini 路径、权限、重启 ——
	//   不会怀疑缓存键。⇒ 键 = 路径 + mtime，缺一不可。
	struct CacheSlot
	{
		HBITMAP  bitmap   = nullptr;
		DWORD    width    = 0;
		DWORD    height   = 0;
		FILETIME stamp    = {};
		WCHAR    path[MAX_PATH] = {};   // ★ 缓存键的一半，别删
		bool     tried    = false;   // 试过了（成功或失败都算，避免每次 hook 都撞一次盘）
		bool         ok   = false;   // 上次尝试的结果
	};

	inline CacheSlot g_cache;

	// 清掉缓存（配置变了 / 单测重置）。
	inline void Forget() noexcept
	{
		if (g_cache.bitmap)
		{
			DeleteObject(g_cache.bitmap);
		}
		g_cache = CacheSlot{};
	}

	// 取文件的修改时间。拿不到就返回 false（=> 调用方按"不能用"处理）。
	inline bool FileStamp(const WCHAR* path, FILETIME* out) noexcept
	{
		if (!path || !path[0] || !out)
		{
			return false;
		}
		WIN32_FILE_ATTRIBUTE_DATA data = {};
		if (!GetFileAttributesExW(path, GetFileExInfoStandard, &data))
		{
			return false;
		}
		if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
		{
			return false;   // 目录不是图片
		}
		*out = data.ftLastWriteTime;
		return true;
	}

	// 取（或加载）图片。返回 nullptr 表示**不能用**。
	//
	// ⚠️ `LR_CREATEDIBSECTION`：不要 GDI 自己挑格式。带 DIB section 的
	//    HBITMAP 才能稳定地 `GetObject` 出尺寸，也才不会被显示驱动转换。
	// ⚠️ 失败要**缓存失败**：否则一张坏图会让每次 `BitBlt` 都去撞一次盘，
	//    而那时宿主已经在被 hook 的热路径上（症状是"开着替换系统变卡"）。
	//    代价是"改好图片后要等 mtime 变化"—— mtime 变了就会重试，正好。
	inline HBITMAP Load(const WCHAR* path) noexcept
	{
		if (!path || !path[0])
		{
			return nullptr;
		}
		// ★ 超长路径**直接当"不能用"**，而不是截断后进缓存：
		//   截断会让"两条只在 260 字符之后不同的路径"共用同一条缓存 ⇒
		//   又变回"画错图"。失败方向必须是**更像假**（这里 = 走黑帧）。
		//   正常情况下到不了这里：引擎侧 `spoof_screen_image` 对
		//   `>= MaxProtectPathChars` 是**整条拒绝**的。
		if (wcslen(path) >= MAX_PATH)
		{
			return nullptr;
		}

		FILETIME stamp = {};
		if (!FileStamp(path, &stamp))
		{
			// 文件不在了：把缓存也丢掉，别继续用旧图（用户删图 = 想关掉）。
			Forget();
			return nullptr;
		}

		if (g_cache.tried
			&& g_cache.path[0] != 0
			&& wcscmp(g_cache.path, path) == 0
			&& g_cache.stamp.dwLowDateTime == stamp.dwLowDateTime
			&& g_cache.stamp.dwHighDateTime == stamp.dwHighDateTime)
		{
			return g_cache.ok ? g_cache.bitmap : nullptr;
		}

		Forget();

		HBITMAP loaded = static_cast<HBITMAP>(LoadImageW(nullptr, path, IMAGE_BITMAP,
			0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION));
		g_cache.tried = true;
		g_cache.stamp = stamp;
		// ★ 路径是缓存键的一半，**成功失败都要记** —— 失败缓存同样要按路径区分，
		//   否则"一张坏图"的失败结果会把"另一张好图"也带成 nullptr。
		wcsncpy_s(g_cache.path, path, _TRUNCATE);
		if (!loaded)
		{
			g_cache.ok = false;
			return nullptr;
		}

		BITMAP info = {};
		if (GetObjectW(loaded, sizeof(info), &info) == 0
			|| info.bmWidth <= 0 || info.bmHeight <= 0)
		{
			DeleteObject(loaded);
			g_cache.ok = false;
			return nullptr;
		}

		g_cache.bitmap = loaded;
		g_cache.width  = static_cast<DWORD>(info.bmWidth);
		g_cache.height = static_cast<DWORD>(info.bmHeight);
		g_cache.ok     = true;
		return loaded;
	}

	inline HBITMAP Current() noexcept { return g_cache.ok ? g_cache.bitmap : nullptr; }
	inline DWORD   Width()   noexcept { return g_cache.width; }
	inline DWORD   Height()  noexcept { return g_cache.height; }

	// ------------------------------------------------------------------
	// ① 画到目标 DC 的一块矩形（BitBlt / StretchBlt / PrintWindow 三条路共用）
	// ------------------------------------------------------------------
	//
	// 返回 true = **真的画上了**。false ⇒ 调用方该回落黑帧。
	//
	// ★ 用 `StretchBlt` 而不是 `BitBlt`：图片尺寸几乎不可能正好等于
	//   被截取区域的尺寸（用户截一块 128x96，图片是 1920x1080）。
	//   "拉伸铺满"比"平铺/裁切"更符合"整屏都被换成这张图"的直觉。
	// ★ `HALFTONE` + `SetBrushOrgEx`：缩小时不做这个会出摩尔纹/噪点
	//   （实测 1920→128 时不加 HALFTONE 会出现明显条带）。
	// ★ 用完**必须恢复** stretch mode 与 brush org —— 目标 DC 是**调用者的**
	//   （可能是屏幕 DC 或它自己的内存 DC），改了就污染别人的绘制状态。
	//   这类"改了别人的 DC 状态"极难查：表现为"某程序截图后界面变色"。
	inline bool PaintRect(HDC dc, int x, int y, int width, int height,
		const WCHAR* path) noexcept
	{
		if (!dc || width <= 0 || height <= 0)
		{
			return false;
		}
		HBITMAP image = Load(path);
		if (!image || g_cache.width == 0 || g_cache.height == 0)
		{
			return false;
		}

		bool painted = false;
		HDC mem = CreateCompatibleDC(dc);
		if (mem)
		{
			HGDIOBJ old = SelectObject(mem, image);
			if (old && old != HGDI_ERROR)
			{
				const int oldMode = SetStretchBltMode(dc, HALFTONE);
				POINT oldOrg = {};
				SetBrushOrgEx(dc, 0, 0, &oldOrg);

				__try {
					painted = StretchBlt(dc, x, y, width, height,
						mem, 0, 0, static_cast<int>(g_cache.width),
						static_cast<int>(g_cache.height), SRCCOPY) != FALSE;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					painted = false;
				}

				if (oldMode != 0)
				{
					SetStretchBltMode(dc, oldMode);
				}
				SetBrushOrgEx(dc, oldOrg.x, oldOrg.y, nullptr);
				SelectObject(mem, old);
			}
			DeleteDC(mem);
		}
		return painted;
	}

	// ------------------------------------------------------------------
	// ② 画进 `GetDIBits` 的**像素缓冲区**（没有 DC 可用，只有裸内存）
	// ------------------------------------------------------------------
	//
	// 返回 true = 缓冲区已被填上图片内容。false ⇒ 调用方该回落 `memset(0)`。
	//
	// ★ 为什么不能直接用 `StretchDIBits` 往 bits 里写：
	//   `StretchDIBits` 需要一个**源** DIB，而我们有的是 HBITMAP。
	//   标准做法是反过来：把图 `StretchBlt` 到一个**同样尺寸的内存位图**，
	//   再 `GetDIBits` 把它读进调用者的缓冲区。两步都是常规 API。
	// ★ 目标格式必须与 `BITMAPINFOHEADER` 完全一致（位深/行距/上下方向）。
	//   `GetDIBits` 会按 header 自己转换（32→24、top-down/bottom-up 都行），
	//   所以这里**不用**自己算 stride —— 一旦自己算，就会和
	//   `BlackenDibBits` 那套位深分支各写一份、慢慢分叉（铁律 127）。
	inline bool PaintDib(LPVOID bits, const BITMAPINFO* info, int rowsWritten,
		const WCHAR* path) noexcept
	{
		if (!bits || !info || rowsWritten <= 0)
		{
			return false;
		}
		const BITMAPINFOHEADER& header = info->bmiHeader;
		if (header.biWidth <= 0 || header.biBitCount == 0)
		{
			return false;
		}
		// 压缩格式（RLE/JPEG/PNG）的字节布局不是"每像素固定位数"，不猜。
		if (header.biCompression != BI_RGB && header.biCompression != BI_BITFIELDS)
		{
			return false;
		}

		HBITMAP image = Load(path);
		if (!image)
		{
			return false;
		}

		const LONG totalRows = header.biHeight < 0 ? -header.biHeight : header.biHeight;
		int rows = rowsWritten;
		if (rows > totalRows)
		{
			rows = static_cast<int>(totalRows);
		}
		const int width = static_cast<int>(header.biWidth);

		HDC screenDc = GetDC(nullptr);
		if (!screenDc)
		{
			return false;
		}

		bool painted = false;
		HDC src = CreateCompatibleDC(screenDc);
		HDC dst = CreateCompatibleDC(screenDc);
		if (src && dst)
		{
			HGDIOBJ oldSrc = SelectObject(src, image);
			// 目标位图：位深跟着调用者的 header（GDI 会做转换）。
			HBITMAP target = CreateCompatibleBitmap(screenDc, width, rows);
			if (target && oldSrc && oldSrc != HGDI_ERROR)
			{
				HGDIOBJ oldDst = SelectObject(dst, target);
				if (oldDst && oldDst != HGDI_ERROR)
				{
					const int oldMode = SetStretchBltMode(dst, HALFTONE);
					POINT oldOrg = {};
					SetBrushOrgEx(dst, 0, 0, &oldOrg);

					__try {
						if (StretchBlt(dst, 0, 0, width, rows, src, 0, 0,
								static_cast<int>(g_cache.width),
								static_cast<int>(g_cache.height), SRCCOPY))
						{
							// ⚠️ 传**调用者**的 info/bits —— 位深与方向由它决定。
							painted = GetDIBits(dst, target, 0, static_cast<UINT>(rows),
								bits, const_cast<BITMAPINFO*>(info), DIB_RGB_COLORS) > 0;
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						painted = false;
					}

					if (oldMode != 0) { SetStretchBltMode(dst, oldMode); }
					SetBrushOrgEx(dst, oldOrg.x, oldOrg.y, nullptr);
					SelectObject(dst, oldDst);
				}
				if (target) { DeleteObject(target); }
			}
			else if (target)
			{
				DeleteObject(target);
			}
			if (oldSrc && oldSrc != HGDI_ERROR) { SelectObject(src, oldSrc); }
		}
		if (src) { DeleteDC(src); }
		if (dst) { DeleteDC(dst); }
		ReleaseDC(nullptr, screenDc);
		return painted;
	}
}
