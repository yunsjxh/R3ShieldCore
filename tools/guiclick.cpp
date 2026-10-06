//
// R3ShieldCore 界面按钮点击探针。
//
// 用来在没有真人操作的环境里验证「点一下按钮能切换模式」这条链路：
//
//   点按钮 → WM_LBUTTONDOWN → HitTestModeButton → g_pendingMode
//          → 引擎主循环 TakePendingMode → EngineControl::SetMode
//          → DLL 里改共享内存 Policy->Mode → 写回 r3shieldcore.ini → 徽章刷新
//
// 为什么不用真实鼠标事件（mouse_event / SendInput）：那些要求窗口在前台、
// 且受 UIPI 限制；直接给窗口发 WM_LBUTTONDOWN 才是"只测我们自己那条链路"。
//
// ⚠️ 按钮位置必须和 r3shieldcore_gui.cpp 的 ModeButtonRect() 一致：
//      right  = 客户区宽 - Padding(20)
//      left   = right - ModeButtonWidth(112)
//      top    = TabBarTop(62) + 4        = 66
//      bottom = top + TabBarHeight(38) - 8 = 96
//    这里按**真实客户区宽度**算（窗口能拉宽），不能用窗口常量。
//    改了 gui 里的常量，这里要同步改 —— 和 toastclick.exe 是同一类坑。
//
// 用法：
//   guiclick               点一次「切换模式」按钮
//   guiclick 3             点 N 次（看模式循环：log → block → ask → log）
//   guiclick rect          只打印算出来的坐标，不点
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>

namespace
{
	constexpr PCWSTR GuiClassName = L"R3ShieldCoreMainWindow";

	constexpr int Padding = 20;
	constexpr int ModeButtonWidth = 112;
	constexpr int TabBarTop = 62;
	constexpr int TabBarHeight = 38;

	RECT ModeButtonRect(int clientWidth)
	{
		const int right = clientWidth - Padding;
		const int top = TabBarTop + 4;
		RECT rect = { right - ModeButtonWidth, top, right, top + TabBarHeight - 8 };
		return rect;
	}
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	int clickCount = 1;
	bool dryRun = false;

	if (argc > 1) {
		if (_wcsicmp(argv[1], L"rect") == 0) {
			dryRun = true;
		}
		else {
			clickCount = _wtoi(argv[1]);
			if (clickCount <= 0) {
				clickCount = 1;
			}
		}
	}

	HWND window = FindWindowW(GuiClassName, nullptr);
	if (!window) {
		wprintf(L"找不到窗口（类名 %s）—— 引擎没在跑，或者界面没打开。\n", GuiClassName);
		return 1;
	}

	RECT client = {};
	if (!GetClientRect(window, &client)) {
		wprintf(L"GetClientRect 失败 err=%lu\n", GetLastError());
		return 1;
	}

	RECT button = ModeButtonRect(client.right);
	const int centerX = (button.left + button.right) / 2;
	const int centerY = (button.top + button.bottom) / 2;

	wprintf(L"窗口        : 0x%p（客户区 %ldx%ld）\n", window, client.right, client.bottom);
	wprintf(L"按钮矩形    : (%ld,%ld)-(%ld,%ld)  中心=(%d,%d)\n",
		button.left, button.top, button.right, button.bottom, centerX, centerY);

	if (dryRun) {
		wprintf(L"（rect 模式，不点击）\n");
		return 0;
	}

	for (int i = 1; i <= clickCount; ++i) {
		SetLastError(0);
		LRESULT result = SendMessageW(window, WM_LBUTTONDOWN, MK_LBUTTON,
			MAKELPARAM(centerX, centerY));
		DWORD error = GetLastError();

		wprintf(L"第 %d 次点击   -> SendMessage 返回 %lld  err=%lu%s\n",
			i, static_cast<long long>(result), error,
			error == ERROR_ACCESS_DENIED ? L"   [被 UIPI 挡了：点击方和引擎权限不一致]" : L"");

		// 引擎主循环是 100ms 切片，等它把请求取走再点下一次，
		// 否则连点会被 g_pendingMode 的"后写覆盖前写"吃掉（这是设计如此）。
		Sleep(400);
	}

	return 0;
}
