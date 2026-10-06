//
// scrollat.cpp - 给指定窗口发一次滚轮或键盘消息，验证滚动。
//
// 用途：R3ShieldCore 日志页的滚动只能靠鼠标滚轮 / PgUp/PgDn / Home/End，
// 自动化验证需要一个能发这些消息的工具。
//
// 用法:
//   scrollat <窗口类名> wheel <delta>     发 WM_MOUSEWHEEL（正数向上）
//   scrollat <窗口类名> key <VK码>        发 WM_KEYDOWN（如 0x23 = End）
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
		wprintf(L"用法: scrollat <窗口类名> wheel <delta>  |  scrollat <窗口类名> key <VK码>\n");
		return 1;
	}

	FindContext context = { argv[1], nullptr };
	EnumWindows(FindByClass, reinterpret_cast<LPARAM>(&context));
	if (!context.found) {
		wprintf(L"找不到窗口类: %ls\n", argv[1]);
		return 1;
	}

	if (_wcsicmp(argv[2], L"wheel") == 0) {
		int delta = _wtoi(argv[3]);
		// wParam 高 16 位是 delta，低 16 位是按键状态
		WPARAM wparam = MAKEWPARAM(0, static_cast<short>(delta));
		SendMessage(context.found, WM_MOUSEWHEEL, wparam, 0);
		wprintf(L"WM_MOUSEWHEEL delta=%d\n", delta);
	}
	else if (_wcsicmp(argv[2], L"key") == 0) {
		int vk = wcstol(argv[3], nullptr, 0);
		SendMessage(context.found, WM_KEYDOWN, static_cast<WPARAM>(vk), 0);
		wprintf(L"WM_KEYDOWN vk=0x%02X\n", vk);
	}
	else {
		wprintf(L"未知模式: %ls\n", argv[2]);
		return 1;
	}

	Sleep(300);
	return 0;
}
