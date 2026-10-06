#include "stdafx.h"
#include "r3shieldcore_toast.h"

#include <commctrl.h>
#include <windowsx.h>

#include <new>
#include <vector>

//
// 实现说明
// ========
//
// 为什么不用 TaskDialog：
//   1. TaskDialog 是「模态」的 —— 弹出来必须点掉才能继续，一次只能有一个。
//      这个项目里一次刷出 3-4 个待询问槽是常态，模态会串行阻塞。
//   2. TaskDialog 默认居中 + 抢焦点，用户正在打字时被抢焦点非常烦。
//   3. TaskDialog 的文字是 DirectUI 自绘的，自动化测试取不到，没法断言。
//
// 所以这里自己画一个 WS_POPUP 无边框窗口：
//   - 用 GDI 自绘（不引入 MFC/Qt），颜色/圆角由自己控制
//   - WS_EX_NOACTIVATE，点了也不抢焦点
//   - 定位在屏幕工作区右下角，多张卡片往上堆
//   - 每张卡片带一个倒计时进度条
//
// 卡片生存期与消息泵
// ------------------
// Show() 是同步的：建窗口 → 跑消息泵 → 直到有结论 → 销毁窗口 → 返回。
// 因为 UI 线程同时还要扫描询问槽，所以 Show() 里的消息泵是"分段"跑的：
// 每 30ms 泵一轮，检查一次结论标记，再让出。
//

namespace
{
	constexpr PCWSTR ToastClassName = L"R3ShieldCoreToastWindow";
	constexpr int ButtonIdAllow = 2001;
	constexpr int ButtonIdDeny = 2002;
	constexpr int ButtonIdAllowAlways = 2003;
	constexpr int ButtonIdDenyAlways = 2004;

	constexpr int ToastWidth = 440;
	constexpr int ToastHeight = 210;
	constexpr int ToastGap = 10;
	constexpr int MarginRight = 16;
	// ⚠️ 距离工作区底部的留白。**不能太小**：卡片行 2 按钮（y=162..190）
	//    若贴到工作区底边，正好压住任务栏通知区/时钟那一带，鼠标在托盘区
	//    松开时 WM_LBUTTONUP 会误投到卡片上（见 ToastState 里的说明）。
	//    这里留 56px，让整张卡片整体抬离托盘区。
	constexpr int MarginBottom = 56;
	constexpr int MaxToasts = 4;

	// 纵向布局（自上而下）：
	//   0..5     accent 条
	//   14..40   标题
	//   46..64   操作
	//   66..84   目标
	//   86..104  值 / hive 文件
	//   112..116 倒计时进度条
	//   128..156 第一行按钮
	//   162..190 第二行按钮
	constexpr int ButtonHeight = 28;
	constexpr int ButtonGapX = 10;
	constexpr int ButtonGapY = 6;
	constexpr int ButtonRow1Top = 128;
	constexpr int ButtonWidth = 200;

	HINSTANCE g_instance = nullptr;
	bool g_classRegistered = false;
	HFONT g_titleFont = nullptr;
	HFONT g_bodyFont = nullptr;
	HFONT g_buttonFont = nullptr;

	// 上一次 Show() 的结论是否来自倒计时兜底。
	volatile LONG g_lastTimedOut = 0;

	// 已存在的卡片窗口列表，用来算堆叠位置。只被 UI 线程访问。
	std::vector<HWND> g_liveToasts;

	struct ToastState
	{
		R3ShieldCoreToast::Action action;
		bool done;
		ULONG timeoutMs;
		ULONG startTick;
		R3ShieldCore::Verdict timeoutVerdict;
		bool timedOut;

		// 鼠标按下/抬起的配对跟踪。
		//
		// ⚠️ 为什么必须有：卡片贴在屏幕右下角且 WS_EX_TOPMOST，行 2 按钮
		//    （y=162..190）正好压在任务栏通知区/时钟那一带。鼠标在托盘区
		//    按下、松开时，系统会把 WM_LBUTTONUP 送到这里的卡片上（哪怕
		//    卡片从未收到对应的 WM_LBUTTONDOWN）。旧实现只要在
		//    WM_LBUTTONUP 里命中按钮就 Finish()，于是**没有任何人有意点它**
		//    也会触发「始终拒绝」→ 静默写入永久 deny 规则。
		//
		// 修法：记录按下的按钮下标与坐标，抬起时只有
		//    「按下的按钮 == 抬起的按钮，且抬起点仍在同一按钮内」
		//    才真正生效。没有配对 down 的 up 一律忽略。
		int pressedButton;           // -1 = 当前没有按下的按钮
		POINT pressedPoint;          // 按下时的坐标（用于判断是否拖出按钮）
		bool pressedValid;           // 是否处于"按下未抬起"状态

		// 绘制要用的文案
		WCHAR title[512];
		WCHAR line1[600];
		WCHAR line2[600];
		WCHAR line3[600];
		bool hive;
		bool highRisk;
	};

	ToastState* StateOf(HWND hwnd)
	{
		return reinterpret_cast<ToastState*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
	}

	void LayoutToasts()
	{
		RECT workArea = {};
		if (!SystemParametersInfo(SPI_GETWORKAREA, 0, &workArea, 0)) {
			workArea.right = GetSystemMetrics(SM_CXSCREEN);
			workArea.bottom = GetSystemMetrics(SM_CYSCREEN);
		}

		// 从下往上堆：最新的在最下面（离任务栏最近）。
		int bottom = workArea.bottom - MarginBottom;
		for (int i = static_cast<int>(g_liveToasts.size()) - 1; i >= 0; i--) {
			HWND toast = g_liveToasts[i];
			SetWindowPos(toast, HWND_TOPMOST,
				workArea.right - MarginRight - ToastWidth,
				bottom - ToastHeight,
				ToastWidth, ToastHeight,
				SWP_NOACTIVATE | SWP_SHOWWINDOW);
			bottom -= (ToastHeight + ToastGap);
		}
	}

	void RemoveToast(HWND hwnd)
	{
		for (auto it = g_liveToasts.begin(); it != g_liveToasts.end(); ++it) {
			if (*it == hwnd) {
				g_liveToasts.erase(it);
				break;
			}
		}

		LayoutToasts();
	}

	void Finish(HWND hwnd, R3ShieldCoreToast::Action action)
	{
		ToastState* state = StateOf(hwnd);
		if (!state || state->done) {
			return;
		}

		state->action = action;
		state->done = true;
	}

	// 圆角矩形 + 柔和边框。GDI 没有现成的圆角填充，用 RoundRect。
	void FillRoundedRect(HDC dc, const RECT& rect, int radius, COLORREF fill, COLORREF border)
	{
		HBRUSH brush = CreateSolidBrush(fill);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);

		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);

		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);
	}

	void DrawButton(HDC dc, const RECT& rect, PCWSTR text, bool primary)
	{
		// primary = 允许（红底白字，符合"允许"需要用户确认的心理）
		const COLORREF fill = primary ? RGB(0, 120, 215) : RGB(240, 240, 240);
		const COLORREF border = primary ? RGB(0, 90, 170) : RGB(200, 200, 200);
		const COLORREF textColor = primary ? RGB(255, 255, 255) : RGB(32, 32, 32);

		FillRoundedRect(dc, rect, 6, fill, border);

		SetBkMode(dc, TRANSPARENT);
		SetTextColor(dc, textColor);
		HGDIOBJ oldFont = SelectObject(dc, g_buttonFont);
		DrawText(dc, text, -1, const_cast<RECT*>(&rect), DT_CENTER | DT_VCENTER | DT_SINGLELINE);
		SelectObject(dc, oldFont);
	}

	RECT ButtonRect(int index)
	{
		// 两行两列排布：
		//   [允许这一次      ] [拒绝这一次      ]
		//   [始终允许此程序  ] [始终拒绝此程序  ]
		constexpr int leftMargin = 16;
		constexpr int buttonWidth = ButtonWidth;
		constexpr int buttonHeight = ButtonHeight;

		RECT rect = {};
		int row = index / 2;
		int column = index % 2;

		rect.left = leftMargin + column * (buttonWidth + ButtonGapX);
		rect.top = ButtonRow1Top + row * (buttonHeight + ButtonGapY);
		rect.right = rect.left + buttonWidth;
		rect.bottom = rect.top + buttonHeight;
		return rect;
	}

	int HitTestButton(POINT point)
	{
		for (int i = 0; i < 4; i++) {
			RECT rect = ButtonRect(i);
			if (PtInRect(&rect, point)) {
				return i;
			}
		}

		return -1;
	}

	R3ShieldCoreToast::Action ActionForButton(int index)
	{
		switch (index) {
		case 0: return R3ShieldCoreToast::Action::Allow;
		case 1: return R3ShieldCoreToast::Action::Deny;
		case 2: return R3ShieldCoreToast::Action::AllowAlways;
		case 3: return R3ShieldCoreToast::Action::DenyAlways;
		default: return R3ShieldCoreToast::Action::None;
		}
	}

	LRESULT CALLBACK ToastWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message) {
		case WM_ERASEBKGND:
			return 1; // 全在 WM_PAINT 里画，避免闪烁

		case WM_PAINT: {
			PAINTSTRUCT ps = {};
			HDC dc = BeginPaint(hwnd, &ps);
			ToastState* state = StateOf(hwnd);
			if (!state) {
				EndPaint(hwnd, &ps);
				return 0;
			}

			// 双缓冲，避免进度条刷新时闪。
			HDC buffer = CreateCompatibleDC(dc);
			HBITMAP bitmap = CreateCompatibleBitmap(dc, ToastWidth, ToastHeight);
			HGDIOBJ oldBitmap = SelectObject(buffer, bitmap);

			RECT client = { 0, 0, ToastWidth, ToastHeight };
			HBRUSH background = CreateSolidBrush(RGB(250, 250, 250));
			FillRect(buffer, &client, background);
			DeleteObject(background);

			// 顶部 accent 条：高危最醒目（品红），hive 次之（橙），普通蓝。
			RECT accent = { 0, 0, ToastWidth, 5 };
			const COLORREF accentColor = state->highRisk
				? RGB(190, 30, 120)
				: (state->hive ? RGB(230, 126, 34) : RGB(0, 120, 215));
			HBRUSH accentBrush = CreateSolidBrush(accentColor);
			FillRect(buffer, &accent, accentBrush);
			DeleteObject(accentBrush);

			SetBkMode(buffer, TRANSPARENT);

			// 标题
			RECT titleRect = { 16, 14, ToastWidth - 16, 40 };
			SetTextColor(buffer, RGB(24, 24, 24));
			HGDIOBJ oldFont = SelectObject(buffer, g_titleFont);
			DrawText(buffer, state->title, -1, &titleRect, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			// 正文三行
			SelectObject(buffer, g_bodyFont);
			SetTextColor(buffer, RGB(80, 80, 80));

			RECT bodyRect = { 16, 46, ToastWidth - 16, 64 };
			DrawText(buffer, state->line1, -1, &bodyRect, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			bodyRect.top += 20;
			bodyRect.bottom += 20;
			DrawText(buffer, state->line2, -1, &bodyRect, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			bodyRect.top += 20;
			bodyRect.bottom += 20;
			SetTextColor(buffer, RGB(120, 120, 120));
			DrawText(buffer, state->line3, -1, &bodyRect, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			// 倒计时进度条（在按钮上方）。宽度随剩余时间收缩。
			if (state->timeoutMs > 0 && !state->done) {
				ULONG elapsed = GetTickCount() - state->startTick;
				if (elapsed > state->timeoutMs) {
					elapsed = state->timeoutMs;
				}

				constexpr int barLeft = 16;
				constexpr int barRight = ToastWidth - 16;
				constexpr int barTop = 112;
				constexpr int barHeight = 4;

				RECT track = { barLeft, barTop, barRight, barTop + barHeight };
				HBRUSH trackBrush = CreateSolidBrush(RGB(226, 226, 226));
				FillRect(buffer, &track, trackBrush);
				DeleteObject(trackBrush);

				// 必须"先乘后除"：写成 (remaining/timeout)*width 的话，
				// 整数除法会把比值直接截成 0（除非刚好剩满），条永远不显示。
				const ULONGLONG remaining = static_cast<ULONGLONG>(state->timeoutMs - elapsed);
				const int filled = static_cast<int>(
					(static_cast<ULONGLONG>(barRight - barLeft) * remaining) / state->timeoutMs);

				if (filled > 0) {
					RECT fill = { barLeft, barTop, barLeft + filled, barTop + barHeight };
					HBRUSH fillBrush = CreateSolidBrush(RGB(0, 120, 215));
					FillRect(buffer, &fill, fillBrush);
					DeleteObject(fillBrush);
				}
			}

			SelectObject(buffer, oldFont);

			// 四个按钮
			DrawButton(buffer, ButtonRect(0), L"允许这一次", true);
			DrawButton(buffer, ButtonRect(1), L"拒绝这一次", false);
			DrawButton(buffer, ButtonRect(2), L"始终允许此程序", false);
			DrawButton(buffer, ButtonRect(3), L"始终拒绝此程序", false);

			BitBlt(dc, 0, 0, ToastWidth, ToastHeight, buffer, 0, 0, SRCCOPY);

			SelectObject(buffer, oldBitmap);
			DeleteObject(bitmap);
			DeleteDC(buffer);

			EndPaint(hwnd, &ps);
			return 0;
		}

		case WM_MOUSEMOVE: {
			// 悬停时停止倒计时，避免用户正在读的时候卡片自己消失。
			TRACKMOUSEEVENT track = { sizeof(TRACKMOUSEEVENT), TME_LEAVE, hwnd, 0 };
			TrackMouseEvent(&track);
			return 0;
		}

		case WM_MOUSELEAVE:
			// 鼠标移出窗口 → 取消按下状态，防止"按在 A 上、拖出窗口再松开"
			// 产生错配动作。
			{
				ToastState* state = StateOf(hwnd);
				if (state) {
					state->pressedValid = false;
					state->pressedButton = -1;
				}
			}
			return 0;

		case WM_LBUTTONDOWN: {
			// 只记录"按下了哪个按钮"，**不立即执行动作**。
			// 真正的动作在 WM_LBUTTONUP 里、且坐标仍在同一按钮内才触发。
			POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
			ToastState* state = StateOf(hwnd);
			if (state) {
				state->pressedButton = HitTestButton(point);
				state->pressedPoint = point;
				state->pressedValid = (state->pressedButton >= 0);
			}
			return 0;
		}

		case WM_LBUTTONUP: {
			// ⚠️ 关键：只有当"按下与抬起发生在同一个按钮内"时才生效。
			//    没有配对 WM_LBUTTONDOWN 的裸 up（托盘区误投）一律忽略 ——
			//    否则会静默写入永久 allow/deny 规则。
			POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
			ToastState* state = StateOf(hwnd);

			const int upIndex = HitTestButton(point);
			const bool paired =
				state &&
				state->pressedValid &&
				state->pressedButton >= 0 &&
				state->pressedButton == upIndex;

			if (state) {
				state->pressedValid = false;
				state->pressedButton = -1;
			}

			if (paired) {
				Finish(hwnd, ActionForButton(upIndex));
			}
			return 0;
		}

		case WM_CAPTURECHANGED:
			// 捕获被抢走（例如别的窗口上来）→ 清掉按下状态。
			{
				ToastState* state = StateOf(hwnd);
				if (state) {
					state->pressedValid = false;
					state->pressedButton = -1;
				}
			}
			return 0;

		case WM_KEYDOWN:
			if (wParam == VK_ESCAPE) {
				Finish(hwnd, R3ShieldCoreToast::Action::Deny);
			}
			return 0;

		case WM_CLOSE:
			Finish(hwnd, R3ShieldCoreToast::Action::Deny);
			return 0;

		case WM_TIMER: {
			ToastState* state = StateOf(hwnd);
			if (!state || state->done) {
				return 0;
			}

			if (state->timeoutMs > 0) {
				ULONG elapsed = GetTickCount() - state->startTick;
				if (elapsed >= state->timeoutMs) {
					state->timedOut = true;
					Finish(hwnd, R3ShieldCoreToast::Action::Expired);
					return 0;
				}
			}

			// 刷新进度条
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;
		}

		default:
			break;
		}

		return DefWindowProc(hwnd, message, wParam, lParam);
	}
}

namespace R3ShieldCoreToast
{
	bool Initialize(HINSTANCE instance) noexcept
	{
		if (g_classRegistered) {
			return true;
		}

		g_instance = instance;

		WNDCLASSEX windowClass = { sizeof(WNDCLASSEX) };
		windowClass.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
		windowClass.lpfnWndProc = ToastWndProc;
		windowClass.hInstance = instance;
		windowClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
		windowClass.hbrBackground = nullptr; // 自己画，不要系统擦背景
		windowClass.lpszClassName = ToastClassName;

		if (!RegisterClassEx(&windowClass)) {
			return false;
		}

		g_titleFont = CreateFont(-16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
		g_bodyFont = CreateFont(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
		g_buttonFont = CreateFont(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

		g_classRegistered = true;
		return true;
	}

	void Shutdown() noexcept
	{
		for (HWND toast : g_liveToasts) {
			if (IsWindow(toast)) {
				DestroyWindow(toast);
			}
		}
		g_liveToasts.clear();

		if (g_titleFont) {
			DeleteObject(g_titleFont);
			g_titleFont = nullptr;
		}
		if (g_bodyFont) {
			DeleteObject(g_bodyFont);
			g_bodyFont = nullptr;
		}
		if (g_buttonFont) {
			DeleteObject(g_buttonFont);
			g_buttonFont = nullptr;
		}

		if (g_classRegistered) {
			UnregisterClass(ToastClassName, g_instance);
			g_classRegistered = false;
		}
	}

	void PumpMessages() noexcept
	{
		MSG message = {};
		while (PeekMessage(&message, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage(&message);
			DispatchMessage(&message);
		}
	}

	Action Show(const Request& request) noexcept
	{
		if (!g_classRegistered) {
			return Action::Deny;
		}

		// 超过上限：把最旧的一张按兜底结论收掉，给新的腾位置。
		while (g_liveToasts.size() >= MaxToasts) {
			HWND oldest = g_liveToasts.front();
			ToastState* state = StateOf(oldest);
			if (state) {
				Finish(oldest, Action::Expired);
			}

			// 等它自己走完销毁流程（消息泵会处理）。
			for (int i = 0; i < 40 && IsWindow(oldest); i++) {
				PumpMessages();
				Sleep(5);
			}

			if (IsWindow(oldest)) {
				DestroyWindow(oldest);
			}

			RemoveToast(oldest);
		}

		auto* state = new (std::nothrow) ToastState{};
		if (!state) {
			return Action::Deny;
		}

		state->done = false;
		state->action = Action::None;
		state->hive = request.IsHive;
		state->highRisk = request.IsHighRisk;
		state->timeoutMs = request.TimeoutMs;
		state->timeoutVerdict = request.TimeoutVerdict;
		state->startTick = GetTickCount();
		state->timedOut = false;
		state->pressedButton = -1;
		state->pressedPoint = POINT{ 0, 0 };
		state->pressedValid = false;

		wcsncpy_s(state->title, request.Title ? request.Title : L"", _TRUNCATE);

		// line1: 操作
		swprintf_s(state->line1, L"操作: %s", request.Operation ? request.Operation : L"?");
		// line2: 目标。不同对象类型措辞不同 —— 文件事件说「键」会很怪。
		const WCHAR* targetLabel = L"键";
		PCWSTR secondLabel = L"值";
		switch (static_cast<R3ShieldCore::ObjectType>(request.ObjectType)) {
		case R3ShieldCore::ObjectType::File:
			targetLabel = L"文件";
			secondLabel = L"新路径";
			break;
		case R3ShieldCore::ObjectType::Process:
			targetLabel = L"程序";
			secondLabel = L"父进程";
			break;
		case R3ShieldCore::ObjectType::Thread:
			targetLabel = L"目标进程";
			secondLabel = L"注入方";
			break;
		case R3ShieldCore::ObjectType::Driver:
			targetLabel = L"驱动";
			secondLabel = L"服务名";
			break;
		case R3ShieldCore::ObjectType::Network:
			targetLabel = L"远端";
			secondLabel = L"连接";
			break;
		case R3ShieldCore::ObjectType::Camera:
			targetLabel = L"设备";
			secondLabel = L"接口";
			break;
		case R3ShieldCore::ObjectType::InputHook:
			// KeyPath 放的是"要注入的模块路径"—— 全局钩子的关键情报。
			targetLabel = L"注入模块";
			secondLabel = L"钩子类型";
			break;
		case R3ShieldCore::ObjectType::Screen:
			targetLabel = L"来源";
			secondLabel = L"区域";
			break;
		case R3ShieldCore::ObjectType::DllLoad:
			// KeyPath / DllPath 都是被加载的 DLL 路径，没有第二字段。
			targetLabel = L"待加载 DLL";
			secondLabel = L"补充";
			break;
		case R3ShieldCore::ObjectType::Clipboard:
			targetLabel = L"动作";
			secondLabel = L"格式";
			break;
		case R3ShieldCore::ObjectType::ProcessSpawn:
			targetLabel = L"目标程序";
			secondLabel = L"命令行";
			break;
		case R3ShieldCore::ObjectType::ServiceConfig:
			targetLabel = L"对象";
			secondLabel = L"变更内容";
			break;
		case R3ShieldCore::ObjectType::ComHijack:
			targetLabel = L"CLSID";
			secondLabel = L"服务器";
			break;
		case R3ShieldCore::ObjectType::ScheduledTask:
			targetLabel = L"任务";
			secondLabel = L"动作";
			break;
		default:
			targetLabel = request.IsHive ? L"目标" : L"键";
			secondLabel = request.IsHive ? L"Hive 文件" : L"值";
			break;
		}

		swprintf_s(state->line2, L"%s: %s",
			targetLabel,
			(request.Target && request.Target[0]) ? request.Target : L"(未解析)");
		// line3: 值 / hive 文件 / 服务名 / 父进程 / 网络连接详情
		if (request.NetDetail && request.NetDetail[0]) {
			swprintf_s(state->line3, L"%s: %s", secondLabel, request.NetDetail);
		}
		else if (request.Extra && request.Extra[0]) {
			swprintf_s(state->line3, L"%s: %s", secondLabel, request.Extra);
		}
		else {
			swprintf_s(state->line3, L"%s (PID %u)",
				request.ProcessPath ? request.ProcessPath : L"", request.ProcessId);
		}

		HWND hwnd = CreateWindowEx(
			WS_EX_TOPMOST | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
			ToastClassName, L"R3ShieldCore",
			WS_POPUP,
			0, 0, ToastWidth, ToastHeight,
			nullptr, nullptr, g_instance, nullptr);

		if (!hwnd) {
			delete state;
			return Action::Deny;
		}

		SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
		g_liveToasts.push_back(hwnd);
		LayoutToasts();

		if (state->timeoutMs > 0) {
			SetTimer(hwnd, 1, 50, nullptr);
		}

		ShowWindow(hwnd, SW_SHOWNOACTIVATE);
		UpdateWindow(hwnd);

		// 跑消息泵，直到有结论为止。
		while (!state->done) {
			PumpMessages();

			// 窗口被外部销毁（比如引擎退出）时也要收手。
			if (!IsWindow(hwnd)) {
				state->done = true;
				state->action = Action::Deny;
				break;
			}

			MsgWaitForMultipleObjectsEx(0, nullptr, 30, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
		}

		Action action = state->action;
		bool timedOut = state->timedOut;

		if (state->timeoutMs > 0) {
			KillTimer(hwnd, 1);
		}

		if (IsWindow(hwnd)) {
			DestroyWindow(hwnd);
		}

		RemoveToast(hwnd);

		g_lastTimedOut = timedOut ? 1 : 0;

		delete state;
		return action;
	}

	bool LastWasTimedOut() noexcept
	{
		return g_lastTimedOut != 0;
	}
}
