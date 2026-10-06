//
// winshot.cpp - 截取指定窗口或整个屏幕，保存为 BMP。
//
// 用途：把 R3ShieldCore 的界面窗口和右下角通知截图下来，
// 检查 GDI 自绘的统计图表是否真的画出来了。
//
// 用法：
//   winshot.exe <输出.bmp>              截全屏
//   winshot.exe <输出.bmp> <窗口类名>   按窗口类名截那个窗口
//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

struct FindContext
{
	const wchar_t* targetClass;
	HWND found;
};

BOOL CALLBACK FindByClass(HWND hwnd, LPARAM lParam)
{
	auto* context = reinterpret_cast<FindContext*>(lParam);

	wchar_t className[256] = {};
	GetClassNameW(hwnd, className, _countof(className));

	if (_wcsicmp(className, context->targetClass) == 0) {
		context->found = hwnd;
		return FALSE;
	}

	return TRUE;
}

bool SaveBitmap(const char* path, int width, int height, const void* bits, int stride)
{
	BITMAPFILEHEADER fileHeader = {};
	BITMAPINFOHEADER infoHeader = {};

	const int imageSize = stride * height;

	fileHeader.bfType = 0x4D42; // 'BM'
	fileHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
	fileHeader.bfSize = fileHeader.bfOffBits + imageSize;

	infoHeader.biSize = sizeof(BITMAPINFOHEADER);
	infoHeader.biWidth = width;
	infoHeader.biHeight = -height; // 负值 = 自上而下
	infoHeader.biPlanes = 1;
	infoHeader.biBitCount = 32;
	infoHeader.biCompression = BI_RGB;
	infoHeader.biSizeImage = imageSize;

	FILE* file = nullptr;
	fopen_s(&file, path, "wb");
	if (!file) {
		return false;
	}

	fwrite(&fileHeader, sizeof(fileHeader), 1, file);
	fwrite(&infoHeader, sizeof(infoHeader), 1, file);
	fwrite(bits, imageSize, 1, file);
	fclose(file);
	return true;
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 2) {
		wprintf(L"用法: winshot.exe <输出.bmp> [窗口类名]\n");
		return 1;
	}

	char outputPath[512] = {};
	WideCharToMultiByte(CP_ACP, 0, argv[1], -1, outputPath, sizeof(outputPath), nullptr, nullptr);

	RECT capture = {};
	HWND hwnd = nullptr;

	if (argc >= 3) {
		if (_wcsicmp(argv[2], L"screen") == 0) {
			// "screen" 是伪类名：截全屏，语义同不带参数。
			capture.left = 0;
			capture.top = 0;
			capture.right = GetSystemMetrics(SM_CXSCREEN);
			capture.bottom = GetSystemMetrics(SM_CYSCREEN);
		}
		else if (wcsncmp(argv[2], L"rect:", 5) == 0) {
			// "rect:l,t,r,b"：截屏幕上的指定区域（走 BitBlt，拿真实合成结果）。
			int l = 0, t = 0, r = 0, b = 0;
			if (swscanf_s(argv[2] + 5, L"%d,%d,%d,%d", &l, &t, &r, &b) == 4) {
				capture.left = l;
				capture.top = t;
				capture.right = r;
				capture.bottom = b;
			}
		}
		else {
			FindContext context = { argv[2], nullptr };
			EnumWindows(FindByClass, reinterpret_cast<LPARAM>(&context));
			hwnd = context.found;

			if (!hwnd) {
				printf("window class not found: %ls\n", argv[2]);
				return 1;
			}

			GetWindowRect(hwnd, &capture);
		}
	}
	else {
		const int screenWidth = GetSystemMetrics(SM_CXSCREEN);
		const int screenHeight = GetSystemMetrics(SM_CYSCREEN);
		capture.left = 0;
		capture.top = 0;
		capture.right = screenWidth;
		capture.bottom = screenHeight;
	}

	const int width = capture.right - capture.left;
	const int height = capture.bottom - capture.top;
	if (width <= 0 || height <= 0) {
		printf("invalid window size\n");
		return 1;
	}

	HDC screenDc = GetDC(nullptr);
	HDC memoryDc = CreateCompatibleDC(screenDc);

	BITMAPINFO info = {};
	info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	info.bmiHeader.biWidth = width;
	info.bmiHeader.biHeight = -height;
	info.bmiHeader.biPlanes = 1;
	info.bmiHeader.biBitCount = 32;
	info.bmiHeader.biCompression = BI_RGB;

	void* bits = nullptr;
	HBITMAP bitmap = CreateDIBSection(screenDc, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
	if (!bitmap) {
		printf("CreateDIBSection failed: %lu\n", GetLastError());
		return 1;
	}

	HGDIOBJ oldBitmap = SelectObject(memoryDc, bitmap);

	// 用 PrintWindow 拿窗口内容（含被遮挡部分），失败再退回 BitBlt。
	// 传 "screen" 当类名时强制走 BitBlt —— PrintWindow 抓的是 DWM 静态缓存帧，
	// 自绘窗口用 InvalidateRect(..., FALSE) 刷新时缓存可能不更新，
	// 想验证"进度条这类动态内容到底有没有画"必须从屏幕抓。
	bool captured = false;
	if (hwnd) {
		captured = PrintWindow(hwnd, memoryDc, PW_RENDERFULLCONTENT) != FALSE;
	}

	if (!captured) {
		BitBlt(memoryDc, 0, 0, width, height, screenDc,
			capture.left, capture.top, SRCCOPY | CAPTUREBLT);
	}

	const bool saved = SaveBitmap(outputPath, width, height, bits, width * 4);

	SelectObject(memoryDc, oldBitmap);
	DeleteObject(bitmap);
	DeleteDC(memoryDc);
	ReleaseDC(nullptr, screenDc);

	if (!saved) {
		printf("save failed: %s\n", outputPath);
		return 1;
	}

	printf("saved %s  (%dx%d)\n", outputPath, width, height);
	return 0;
}
