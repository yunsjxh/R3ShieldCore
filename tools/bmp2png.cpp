//
// bmp2png.cpp - 把 32 位 BMP 转成 PNG（GDI+）。
//
// 为什么要这个：Read 工具能直接看图，但不认 BMP；转成 PNG 才能目视检查
// R3ShieldCore 界面和通知卡片的渲染结果。
//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// GDI+ 的 C++ 头依赖这些先被包含。
#include <objidl.h>
#include <gdiplus.h>

#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "gdiplus.lib")

int wmain(int argc, wchar_t** argv)
{
	if (argc < 3) {
		wprintf(L"用法: bmp2png.exe <输入.bmp> <输出.png>\n");
		return 1;
	}

	Gdiplus::GdiplusStartupInput startupInput;
	ULONG_PTR token = 0;
	if (Gdiplus::GdiplusStartup(&token, &startupInput, nullptr) != Gdiplus::Ok) {
		printf("GdiplusStartup failed\n");
		return 1;
	}

	{
		Gdiplus::Bitmap bitmap(argv[1], FALSE);
		if (bitmap.GetLastStatus() != Gdiplus::Ok) {
			printf("load failed\n");
			Gdiplus::GdiplusShutdown(token);
			return 1;
		}

		// 找 PNG 编码器
		CLSID pngClsid = {};
		UINT numEncoders = 0;
		UINT size = 0;
		Gdiplus::GetImageEncodersSize(&numEncoders, &size);

		if (size == 0) {
			printf("no encoders\n");
			Gdiplus::GdiplusShutdown(token);
			return 1;
		}

		auto* encoders = static_cast<Gdiplus::ImageCodecInfo*>(malloc(size));
		Gdiplus::GetImageEncoders(numEncoders, size, encoders);

		bool found = false;
		for (UINT i = 0; i < numEncoders; i++) {
			if (wcscmp(encoders[i].MimeType, L"image/png") == 0) {
				pngClsid = encoders[i].Clsid;
				found = true;
				break;
			}
		}

		free(encoders);

		if (!found) {
			printf("PNG encoder not found\n");
			Gdiplus::GdiplusShutdown(token);
			return 1;
		}

		if (bitmap.Save(argv[2], &pngClsid, nullptr) != Gdiplus::Ok) {
			printf("save failed\n");
			Gdiplus::GdiplusShutdown(token);
			return 1;
		}

		printf("saved %ls (%ux%u)\n", argv[2], bitmap.GetWidth(), bitmap.GetHeight());
	}

	Gdiplus::GdiplusShutdown(token);
	return 0;
}
