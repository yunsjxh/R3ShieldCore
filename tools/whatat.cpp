//
// whatat.cpp - 查屏幕上某个坐标点最上层的窗口是谁。
//
// 用途：SendInput 打过去但窗口没收到消息时，确认是不是被别的窗口盖住了。
//
// 用法: whatat <x> <y>
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int wmain(int argc, wchar_t** argv)
{
	if (argc < 3) {
		wprintf(L"用法: whatat.exe <x> <y>\n");
		return 1;
	}

	POINT point = { _wtoi(argv[1]), _wtoi(argv[2]) };

	wprintf(L"=== 屏幕点 (%ld,%ld) 处的窗口（自顶向下）===\n\n", point.x, point.y);

	HWND hwnd = nullptr;
	for (int i = 0; i < 12; i++) {
		hwnd = (i == 0)
			? WindowFromPoint(point)
			: GetWindow(hwnd, GW_HWNDNEXT);
		if (!hwnd) { break; }

		// 用 ChildWindowFromPointEx 拿到最里层的子窗口。
		POINT client = point;
		ScreenToClient(hwnd, &client);

		wchar_t className[256] = {};
		wchar_t title[512] = {};
		GetClassNameW(hwnd, className, _countof(className));
		GetWindowTextW(hwnd, title, _countof(title));

		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);

		RECT rect = {};
		GetWindowRect(hwnd, &rect);

		wprintf(L"  [%d] hwnd=%p pid=%lu class=%ls\n", i, hwnd, pid, className);
		wprintf(L"      title=%ls\n", title[0] ? title : L"(空)");
		wprintf(L"      rect=(%d,%d)-(%d,%d) visible=%d enabled=%d\n",
			rect.left, rect.top, rect.right, rect.bottom,
			IsWindowVisible(hwnd) ? 1 : 0, IsWindowEnabled(hwnd) ? 1 : 0);

		if (!IsWindowVisible(hwnd)) { break; }
	}

	// 再单独做一次"命中测试"，看系统认为点在哪
	HWND direct = WindowFromPoint(point);
	wchar_t directClass[256] = {};
	GetClassNameW(direct, directClass, _countof(directClass));
	wprintf(L"\nWindowFromPoint 直接结果: %ls (hwnd=%p)\n", directClass, direct);
	return 0;
}
