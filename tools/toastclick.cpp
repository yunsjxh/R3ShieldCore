//
// toastclick.cpp - 点 R3ShieldCore 右下角通知卡片上的按钮。
//
// 为什么不能用 promptclick：那个是给模态 TaskDialog 用的，靠枚举子窗口
// 找按钮控件。通知卡片是**单个自绘窗口**（WS_POPUP + GDI 双缓冲），
// 按钮不是子窗口，只能按坐标投鼠标消息。
//
// 卡片布局（见 r3shieldcore_toast.cpp）：
//   两行两列，每列宽 200，左边距 16，水平间距 10
//   第一行 top = 128，第二行 top = 162，高 28
//
// 用法: toastclick <引擎PID> <choice> [seconds]
//   choice: allow | deny | allowalways | denyalways
//
#include <windows.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

namespace
{
	constexpr int ToastWidth = 440;
	constexpr int ToastHeight = 210;
	constexpr int ButtonWidth = 200;
	constexpr int ButtonHeight = 28;
	constexpr int ButtonGapX = 10;
	constexpr int ButtonGapY = 6;
	constexpr int LeftMargin = 16;
	constexpr int Row1Top = 128;

	struct FindContext
	{
		DWORD enginePid;
		HWND toast;
	};

	BOOL CALLBACK FindToastProc(HWND hwnd, LPARAM lParam)
	{
		auto* context = reinterpret_cast<FindContext*>(lParam);

		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid != context->enginePid) {
			return TRUE;
		}

		WCHAR className[128] = {};
		GetClassNameW(hwnd, className, _countof(className));
		if (wcscmp(className, L"R3ShieldCoreToastWindow") != 0) {
			return TRUE;
		}

		if (!IsWindowVisible(hwnd)) {
			return TRUE;
		}

		context->toast = hwnd;
		return FALSE;
	}

	// 计算第 index 个按钮在客户区里的中心点。
	POINT ButtonCenter(int index)
	{
		int row = index / 2;
		int column = index % 2;

		POINT point = {};
		point.x = LeftMargin + column * (ButtonWidth + ButtonGapX) + ButtonWidth / 2;
		point.y = Row1Top + row * (ButtonHeight + ButtonGapY) + ButtonHeight / 2;
		return point;
	}

	// 直接给窗口发鼠标消息。卡片用的是 WM_LBUTTONUP + 客户区坐标，
	// 所以不用 SetCursorPos（那样会真的移动用户的鼠标）。
	//
	// 注意：跨进程 SendMessage 需要目标线程在泵消息。若目标进程完整性级别更高，
	// 这条消息会被 UIPI 静默丢弃（返回 0 但不报错），所以调用方要提权运行。
	void ClickAtMessage(HWND hwnd, POINT client)
	{
		LPARAM lParam = MAKELPARAM(client.x, client.y);

		SetLastError(0);
		LRESULT down = SendMessage(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
		DWORD downError = GetLastError();

		SetLastError(0);
		LRESULT up = SendMessage(hwnd, WM_LBUTTONUP, 0, lParam);
		DWORD upError = GetLastError();

		printf("  SendMessage down=%ld err=%lu  up=%ld err=%lu\n",
			(long)down, downError, (long)up, upError);
	}

	// 用 SendInput 造真实鼠标事件。
	//
	// 这是唯一能可靠穿过完整性级别边界的方式：SendInput 走的是系统输入队列，
	// 不是"跨进程发消息"，所以 UIPI 不管它。缺点是真的会动用户的鼠标指针。
	void ClickAtScreen(POINT screen)
	{
		SetCursorPos(screen.x, screen.y);
		Sleep(60);

		INPUT inputs[2] = {};

		inputs[0].type = INPUT_MOUSE;
		inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;

		inputs[1].type = INPUT_MOUSE;
		inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;

		UINT sent = SendInput(2, inputs, sizeof(INPUT));
		printf("  SendInput %u/2 events (screen %ld,%ld)\n", sent, screen.x, screen.y);
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	setvbuf(stdout, nullptr, _IONBF, 0);

	if (argc < 3) {
		printf("usage: toastclick <enginePid> <allow|deny|allowalways|denyalways> [seconds] [sendinput]\n");
		printf("  default uses WM_LBUTTONUP; pass 'sendinput' to use real mouse events\n");
		return 1;
	}

	DWORD enginePid = static_cast<DWORD>(strtoul(argv[1], nullptr, 10));

	int buttonIndex = -1;
	if (_stricmp(argv[2], "allow") == 0) { buttonIndex = 0; }
	else if (_stricmp(argv[2], "deny") == 0) { buttonIndex = 1; }
	else if (_stricmp(argv[2], "allowalways") == 0) { buttonIndex = 2; }
	else if (_stricmp(argv[2], "denyalways") == 0) { buttonIndex = 3; }
	else {
		printf("unknown choice: %s\n", argv[2]);
		return 1;
	}

	int seconds = (argc > 3) ? atoi(argv[3]) : 20;
	bool useSendInput = (argc > 4) && (_stricmp(argv[4], "sendinput") == 0);

	POINT client = ButtonCenter(buttonIndex);

	printf("target button index=%d at client (%ld,%ld), mode=%s, watching %d s\n",
		buttonIndex, client.x, client.y, useSendInput ? "SendInput" : "SendMessage", seconds);

	ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000;
	int clicked = 0;

	while (GetTickCount64() < deadline) {
		FindContext context = { enginePid, nullptr };
		EnumWindows(FindToastProc, reinterpret_cast<LPARAM>(&context));

		if (context.toast) {
			RECT windowRect = {};
			GetWindowRect(context.toast, &windowRect);

			if (useSendInput) {
				// 卡片是 WS_POPUP 无边框，客户区原点 == 窗口左上角。
				POINT screen = { windowRect.left + client.x, windowRect.top + client.y };
				printf("found toast [%p] at (%ld,%ld)\n",
					context.toast, windowRect.left, windowRect.top);
				ClickAtScreen(screen);
			}
			else {
				printf("found toast [%p]\n", context.toast);
				ClickAtMessage(context.toast, client);
			}

			clicked++;
			Sleep(300);
		}
		else {
			Sleep(120);
		}
	}

	printf("total clicks = %d\n", clicked);
	return 0;
}
