//
// textwidth.cpp - 量一段文字在指定字体下的像素宽度。
//
// 用途：定日志表格的列宽。靠猜很容易截断（"SetInformationKey" 到底
// 需要多少像素，光看字符数估不准），实测一次最省事。
//
// 用法: textwidth.exe
//
#include <windows.h>
#include <locale.h>
#include <stdio.h>

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	HDC dc = GetDC(nullptr);
	HFONT font = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
		CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
	HGDIOBJ old = SelectObject(dc, font);

	const wchar_t* samples[] = {
		L"SetInformationKey",
		L"EnumerateValueKey",
		L"DeleteValueKey",
		L"pwsh.exe (18724)",
		L"10:00:48",
		L"00000000",
		L"Some\\Long\\Registry\\Path\\Here",
	};

	for (const wchar_t* text : samples) {
		SIZE size = {};
		GetTextExtentPoint32W(dc, text, (int)wcslen(text), &size);
		wprintf(L"%4ld px   %ls\n", size.cx, text);
	}

	SelectObject(dc, old);
	DeleteObject(font);
	ReleaseDC(nullptr, dc);
	return 0;
}
