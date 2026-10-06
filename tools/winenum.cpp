//
// winenum.cpp - 枚举当前桌面上的顶层窗口，按标题/类名过滤。
//
// 用途：验证 R3ShieldCore 的界面窗口和右下角通知卡片是否真的建出来了。
// 因为 TaskDialog / 自绘窗口的文字取不到（DirectUI 自绘），
// 这个工具就按「窗口类名 + 可见性 + 位置」来判断。
//
// 用法：
//   winenum.exe             列出所有可见顶层窗口
//   winenum.exe R3ShieldCore    只列标题或类名里含 R3ShieldCore 的
//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static const wchar_t* g_filter = nullptr;

BOOL CALLBACK EnumProc(HWND hwnd, LPARAM lParam)
{
	(void)lParam;

	wchar_t title[512] = {};
	wchar_t className[256] = {};
	GetWindowTextW(hwnd, title, _countof(title));
	GetClassNameW(hwnd, className, _countof(className));

	if (g_filter && wcsstr(title, g_filter) == nullptr && wcsstr(className, g_filter) == nullptr) {
		return TRUE;
	}

	RECT rect = {};
	GetWindowRect(hwnd, &rect);
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);

	wprintf(L"hwnd=0x%08p  pid=%-6lu  visible=%d  rect=(%d,%d)-(%d,%d)\n  class=%ls\n  title=%ls\n\n",
		hwnd, pid, IsWindowVisible(hwnd) ? 1 : 0,
		rect.left, rect.top, rect.right, rect.bottom,
		className, title[0] ? title : L"(no title)");

	return TRUE;
}

int wmain(int argc, wchar_t** argv)
{
	if (argc > 1) {
		g_filter = argv[1];
	}

	RECT workArea = {};
	SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
	printf("work area: (%d,%d)-(%d,%d)  size=%dx%d\n",
		workArea.left, workArea.top, workArea.right, workArea.bottom,
		workArea.right - workArea.left, workArea.bottom - workArea.top);
	printf("expected toast bottom-right: (%d,%d)  [work area inset 16px]\n\n",
		workArea.right - 16, workArea.bottom - 16);

	printf("=== top-level windows %s%s ===\n\n",
		g_filter ? "(filter: " : "(all",
		g_filter ? "(narrow)" : ")");

	EnumWindows(EnumProc, 0);
	return 0;
}
