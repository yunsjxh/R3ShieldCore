// clickat.cpp - 按窗口类名 + 客户区坐标投一次鼠标点击。
//
// 用途：验证 R3ShieldCore 界面的页签切换、滚动区点击等交互。
// 直接给客户区坐标，工具自己换算到屏幕坐标（算上窗口位置和边框偏移），
// 不用手算 —— 手算很容易差几个像素。
//
// 用法: clickat <窗口类名> <x> <y> [sendinput]
//
#include <windows.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

namespace
{
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
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	if (argc < 4) {
		wprintf(L"用法: clickat <窗口类名> <客户区x> <客户区y> [sendinput]\n");
		return 1;
	}

	FindContext context = { argv[1], nullptr };
	EnumWindows(FindByClass, reinterpret_cast<LPARAM>(&context));
	if (!context.found) {
		wprintf(L"找不到窗口类: %ls\n", argv[1]);
		return 1;
	}

	int clientX = _wtoi(argv[2]);
	int clientY = _wtoi(argv[3]);
	bool sendInput = (argc >= 5 && _wcsicmp(argv[4], L"sendinput") == 0);

	// 客户区坐标 -> 屏幕坐标
	POINT point = { clientX, clientY };
	ClientToScreen(context.found, &point);

	if (sendInput) {
		// 走系统输入队列（真人点击等效，不受 UIPI 限制）。
		SetCursorPos(point.x, point.y);

		INPUT inputs[2] = {};
		inputs[0].type = INPUT_MOUSE;
		inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
		inputs[1].type = INPUT_MOUSE;
		inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
		UINT sent = SendInput(2, inputs, sizeof(INPUT));
		wprintf(L"SendInput %u/2  events at screen (%ld,%ld)\n", sent, point.x, point.y);
	}
	else {
		// 直接投消息。同完整性级别才有效。
		LPARAM lparam = MAKELPARAM(clientX, clientY);
		SendMessage(context.found, WM_LBUTTONDOWN, MK_LBUTTON, lparam);
		SendMessage(context.found, WM_LBUTTONUP, 0, lparam);
		wprintf(L"SendMessage at client (%d,%d) -> screen (%ld,%ld)\n",
			clientX, clientY, point.x, point.y);
	}

	Sleep(400);
	return 0;
}
