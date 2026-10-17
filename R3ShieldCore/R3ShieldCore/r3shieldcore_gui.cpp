#include "stdafx.h"
#include "r3shieldcore_gui.h"
#include "r3shieldcore_ark.h"
#include "r3shieldcore_stats.h"
#include "r3shieldcore_superdesk.h"

#include <commctrl.h>
#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "msimg32.lib")
#include <windowsx.h>

#include <algorithm>
#include <cstdio>   // 置顶状态变更留痕（stdout）
#include <string>
#include <vector>

// ---------------------------------------------------------------------
// ★ v80：「高级」页签的编辑台搬到了 `r3shieldcore-cfg.exe`。
//
//   主程序这一页现在只剩一个"把 cfg 叫到前台"的按钮，所以原来为编辑台
//   引入的那一堆头（rules_codec / spoof_apply_codec / registry_spoof_codec /
//   clipboard_spoof_codec / rules_file / advanced_quiz / md_inline）**全部
//   不再需要** —— 它们跟着编辑台一起搬去 cfg 了。
//
//   这里只需要**一个**头：启动 / 激活的契约（窗口类名 / 激活消息 / 页号 /
//   exe 名）。契约只定义一处，两边都 #include 它（铁律 127）。
// ---------------------------------------------------------------------
#include <r3shieldcore/cfg_launch.h>

// ★ 托盘图标（关闭窗口 = 收进托盘）。两个 exe 共用一份实现 —— 铁律 127。
#include <r3shieldcore/tray_icon.h>

// ★ v83：液态玻璃材质（背景模糊 + 圆角 SDF + 折射/色散/rim/噪点/投影）。
//   绘制侧**唯一实现**，cfg 那边 #include 同一份 —— 铁律 127。
#include <r3shieldcore/ui_material.h>

// ★ v84：OpenGL 玻璃后端（真正的着色器实现）。失败会自动退回上面那套 CPU 合成。
#include <r3shieldcore/ui_gl.h>

// ★ v84：界面风格的契约（两个 exe 共用，铁律 127）。
#include <r3shieldcore/ui_style.h>

//
// 界面布局
// ========
//
//   ┌──────────────────────────────────────────────────────┐
//   │  R3ShieldCore — 用户态注册表行为拦截   [默认置顶][超级置顶][模式徽章] │  ← 标题栏（自绘区域）
//   ├──────────────────────────────────────────────────────┤
//   │  运行时长 00:03:21   注入进程 138   事件 12,431       │  ← 概览行
//   │                                                       │
//   │  决策分布                                             │
//   │  ALLOW        ████████████████░░░░  11820            │
//   │  BLOCK        ████░░░░░░░░░░░░░░░░    611            │
//   │                                                       │
//   │  操作分布（Top 6）                                    │
//   │  OpenKey          ████████████░░░░   8203            │
//   │  CreateKey        ██████░░░░░░░░░░   4102            │
//   │  SetValueKey      ██░░░░░░░░░░░░░░   1204            │
//   │                                                       │
//   │  触发最多的进程（Top 6）                              │
//   │  chrome.exe (1234)   ████████████   5201             │
//   │  ...                                                  │
//   ├──────────────────────────────────────────────────────┤
//   │  询问: 显示 12 · 允许 7 · 拒绝 3 · 超时 2             │  ← 询问统计
//   └──────────────────────────────────────────────────────┘
//
// 用 GDI 全程自绘（不用 ListView/静态控件），因为：
//   - 控件默认字体/颜色跟当前主题对不上，还要处理 WM_CTLCOLOR
//   - 柱状图本来就得自己画
//   - 自绘只要一个 WM_PAINT，逻辑集中
//

namespace
{
	constexpr PCWSTR GuiClassName = L"R3ShieldCoreMainWindow";
	constexpr PCWSTR GuiTitle = L"R3ShieldCore 安全控制台";

	// ---------------------------------------------------------------------
	// 图标资源 ID —— 必须和 R3ShieldCore/rsrc/r3shieldcore.rc 里的 `1 ICON` 一致。
	//
	// ★★ 这里**不能**再写 LoadIcon(nullptr, IDI_APPLICATION)（原实现就是这样）：
	//     第一个参数传 nullptr 时，Windows 只去**系统模块**里找图标，
	//     永远看不到我们自己编进 exe 的那一个 —— 于是窗口标题栏和任务栏
	//     一直是系统的空白"应用程序"默认图标。
	//     必须传**本模块句柄**（g_instance）+ 资源 ID。
	//
	// ★ 加载失败要有兜底：万一资源被裁掉（比如某个构建配置漏了 .res），
	//   退回 IDI_APPLICATION 至少不会出现"没有图标"的方框。
	//   但**不要静默** —— 退回时打一行日志，否则这种问题永远查不出来
	//   （铁律 97：布尔判定不可诊断，失败要有原因）。
	// ---------------------------------------------------------------------
	constexpr int IconResourceId = 1;

	// 定义在 g_instance 声明之后（本文件 ~line 175 附近）—— 它要用到那个句柄。
	HICON LoadAppIcon(int cx, int cy);

	constexpr int WindowWidth = 1024;
	constexpr int WindowHeight = 740;
	constexpr int Padding = 20;

	// 底部统计栏的行距（行高 22 + 间隔 4）。
	//
	// ⚠️ **不要拿它直接算布局** —— 行数是变的（1~3 行），
	//    实际高度一律用下面的 `PromptSummaryHeight()`。写死会让
	//    底部栏盖住内容（尤其是事件日志页和进程页列表的底部）。
	constexpr int PromptSummaryRowHeight = 26;

	// 页签栏（标题区下方）。概览 / 事件日志 / 进程 / 配置 / ARK / 高级 六个页签。
	//
	// ★ v62：4 → 5 个页签，TabWidth 92 → 84。
	// ★ v77：5 → 6 个页签（多了「高级」），TabWidth 84 → 70。
	//   ⚠️ 这一步**不是**为了好看 —— 84 宽时第 6 个页签（左缘 480）会被右侧
	//      动作簇的「退出引擎」按钮（左缘 492）**压住**，页签直接点不到。
	//      这个重叠在 `--gui-preview` 的截图上才第一次看得出来（自绘界面
	//      没有控件句柄，靠读代码很容易漏）。
	//   宽度仍是按"页签条不压到右侧动作簇"倒推的：
	//     页签条右缘 = 20 + 6×(70+8) - 8 = 480
	//     动作簇最左（「退出引擎」）左缘 = 客户区宽 - 532
	//   ⇒ 客户区宽 ≥ 1020 才留得出 8px 间隔。所以窗口默认宽 920 → 1024、
	//     最小跟踪宽 980 → 1040（见 WM_GETMINMAXINFO）。
	//   ⚠️ `tools/gui_exit_button_probe.cpp` 与 `gui_copy_all_logs_probe.cpp`
	//      各自**镜像**了这几个常量（它们要靠坐标去点按钮）—— 改这里必须同步改那边。
	constexpr int TabBarHeight = 38;
	constexpr int TabBarTop = 62;  // 紧跟标题区分隔线
	constexpr int TabWidth = 70;

	// 日志页的行高与列宽。窗口宽 560、左右各 20 内边距 → 可用 520。
	//
	// 列宽是实测出来的（tools/textwidth.exe），不是估的：Consolas -12 下
	// ASCII 每字符约 7px，`SetInformationKey` / `EnumerateValueKey` 正好
	// 119px，`pwsh.exe (18724)` 112px，时间/状态码都是 56px。
	//
	// 中文进程名（`哔哩哔哩.exe (13636)`）要宽得多 —— 汉字约 12px/字，
	// 所以进程列给得比"英文进程名刚好够"更宽。放不下的靠 END_ELLIPSIS 兜底。
	// 状态码列只占 46px（状态为 0 时不画，非零时只画低 4 位），
	// 省下的宽度分给进程列和目标列。
	constexpr int LogRowHeight = 22;
	constexpr int LogHeaderHeight = 26;
	constexpr int LogColTimeWidth = 62;      // 56 + 6
	constexpr int LogColSourceWidth = 40;    // "注册表" / "文件" 两字 + 间隙
	constexpr int LogColProcessWidth = 108;  // 中文名 + PID
	constexpr int LogColOpWidth = 134;       // 含 "[危] [拦] " 双前缀 + 最长操作名
	constexpr int LogColStatusWidth = 46;    // 只在非零状态时画

	// 配色（浅色主题）
	constexpr COLORREF ColorBackground = RGB(235, 243, 250);
	constexpr COLORREF ColorHeaderBackground = RGB(247, 251, 255);
	constexpr COLORREF ColorBorder = RGB(207, 221, 235);
	constexpr COLORREF ColorTextPrimary = RGB(24, 24, 24);
	constexpr COLORREF ColorTextSecondary = RGB(110, 110, 110);
	constexpr COLORREF ColorAccent = RGB(0, 120, 215);
	constexpr COLORREF ColorBlocked = RGB(209, 52, 56);
	constexpr COLORREF ColorWouldBlock = RGB(230, 126, 34);
	// v67：替换（Spoof）—— 紫色。既不是"拒绝"（红）也不是"本应拒绝"（橙），
	// 而是"调用成功了但内容是假的"，必须一眼能区分开。
	constexpr COLORREF ColorSpoofed = RGB(123, 31, 162);
	// 完全拦截模式的徽章色：比 BLOCK 更深更沉，一眼能跟普通拦截区分开。
	constexpr COLORREF ColorBlockAll = RGB(139, 0, 0);
	constexpr COLORREF ColorTrack = RGB(232, 232, 232);
	constexpr COLORREF ColorTabActiveBg = RGB(45, 132, 220);
	constexpr COLORREF ColorTabActiveText = RGB(255, 255, 255);
	constexpr COLORREF ColorTabInactiveText = RGB(90, 90, 90);
	// 未选中页签的悬停态（浅蓝底 + 淡蓝描边）。
	constexpr COLORREF ColorTabHoverBg = RGB(226, 240, 253);
	constexpr COLORREF ColorTabHoverBorder = RGB(182, 214, 244);
	constexpr COLORREF ColorLogRowAlt = RGB(241, 247, 252);
	// ★ v54：历史行（上一轮会话回放出来的）底色 —— 比交替色再暗一档，
	// 让"这不是本次会话产生的事件"一眼可见。
	constexpr COLORREF ColorLogRowHistory = RGB(238, 238, 234);
	constexpr COLORREF ColorFileAccent = RGB(16, 124, 16); // 文件事件来源标记
	constexpr COLORREF ColorRegistryAccent = RGB(0, 90, 158); // 注册表事件来源标记（深蓝，与 ALLOW 的 accent 蓝区分）
	constexpr COLORREF ColorHighRisk = RGB(190, 30, 120);  // 高危标记（品红，与红/橙都能区分）
	constexpr COLORREF ColorProcessAccent = RGB(140, 82, 200); // 进程事件来源标记（紫）
	constexpr COLORREF ColorThreadAccent = RGB(0, 140, 150);   // 线程事件来源标记（青）
	constexpr COLORREF ColorDriverAccent = RGB(180, 95, 6);    // 驱动事件来源标记（棕橙）
	constexpr COLORREF ColorNetworkAccent = RGB(46, 125, 50);  // 网络事件来源标记（深绿）
	constexpr COLORREF ColorCameraAccent = RGB(191, 64, 128);  // 摄像头事件来源标记（洋红）
	constexpr COLORREF ColorInputHookAccent = RGB(0, 110, 160); // 输入钩子来源标记（蓝青）
	constexpr COLORREF ColorScreenAccent = RGB(150, 110, 20);   // 截屏事件来源标记（暗金）
	constexpr COLORREF ColorDllLoadAccent = RGB(130, 80, 190);  // DLL 加载来源标记（紫）
	constexpr COLORREF ColorClipboardAccent = RGB(30, 140, 90);  // 剪贴板来源标记（绿松）
	constexpr COLORREF ColorSpawnAccent = RGB(190, 80, 40);      // 进程创建旁路来源标记（橙）
	constexpr COLORREF ColorServiceConfigAccent = RGB(120, 120, 40); // 服务权限变更来源标记（橄榄）
	constexpr COLORREF ColorComAccent = RGB(150, 60, 130);           // COM 激活劫持来源标记（紫红）
	constexpr COLORREF ColorTaskAccent = RGB(60, 110, 150);          // 计划任务来源标记（钢蓝）

	// Win32 liquid-glass shell: keep native resize/caption behavior while asking
	// DWM for a softly tinted acrylic backdrop and modern rounded outer corners.
	struct AccentPolicy { int State; int Flags; DWORD GradientColor; int AnimationId; };
	struct WindowCompositionAttributeData { int Attribute; void* Data; SIZE_T Size; };
	using SetWindowCompositionAttributeFn = BOOL(WINAPI*)(HWND, WindowCompositionAttributeData*);

	void ApplyGlassWindow(HWND hwnd)
	{
		if (!hwnd) return;
		// ★★ v83：**不再**调 `SetWindowCompositionAttribute(ACCENT_ENABLE_ACRYLICBLURBEHIND)`。
		//
		//   原因（实测，血泪）：那套 acrylic 会让 DWM 把**整块客户区**再和
		//   模糊背景混一遍 —— 我们自己画的液态玻璃（背景模糊 + 面板 + 深色文字）
		//   会被它二次淡化，症状是「文字变成白色、几乎看不见」，
		//   而**我们画出来的缓冲完全正常**（把缓冲导成 BMP 是对的）。
		//   ⇒ 界面对不对，在加了 acrylic 之后**用缓冲验证不出来**，极易误判成
		//     "玻璃合成写错了"。现在玻璃完全由我们自绘，DWM 只负责外框圆角。
		//
		// ★ 数值而不是枚举：项目按 Win10 SDK 编译，枚举可能不存在。
		constexpr DWORD DwmwaWindowCornerPreference = 33;
		constexpr int DwmwcpRound = 2;
		DwmSetWindowAttribute(hwnd, DwmwaWindowCornerPreference,
			&DwmwcpRound, sizeof(DwmwcpRound));
	}

	HINSTANCE g_instance = nullptr;
	HWND g_window = nullptr;

	// ---------------------------------------------------------------------
	// v83 液态玻璃：背景缓存 + 面板层缓存 + 本帧画布
	//
	// ★ 为什么用一个**全局**而不是每次 PaintWindow 现建：
	//   背景（屏幕捕获 + 两级模糊）是这块唯一的"重活"，必须跨帧复用；
	//   面板层同理（见 ui_material.h 里 GlassSurface 的"两帧收敛"说明）。
	// ★ 生命周期：进程级，随窗口销毁走 Shutdown()；不持有任何句柄泄漏风险
	//   （Dib32 是 RAII）。
	// ---------------------------------------------------------------------
	R3ShieldCoreUi::GlassSurface g_glass;
	bool g_glassLogged = false;        // 背景来源只打一次日志（避免刷屏）
	bool g_glassWantBackdrop = true;   // 下一次绘制是否强制重建背景
	ULONGLONG g_glassMovedAt = 0;      // 最近一次移动/缩放时间（用于静止收敛）

	// 取当前 DPI 缩放（PerMonitorV2 清单 ⇒ 必须按窗口取，不能用 GetDeviceCaps）
	float GlassDpiScale(HWND hwnd)
	{
		// GetDpiForWindow 是 Win10 1607+ 的 API；旧系统退回 96。
		using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
		static GetDpiForWindowFn fn = nullptr;
		static bool resolved = false;
		if (!resolved) {
			HMODULE user = GetModuleHandleW(L"user32.dll");
			fn = user ? reinterpret_cast<GetDpiForWindowFn>(
				GetProcAddress(user, "GetDpiForWindow")) : nullptr;
			resolved = true;
		}
		UINT dpi = 96;
		if (fn && hwnd) {
			const UINT got = fn(hwnd);
			if (got > 0) {
				dpi = got;
			}
		}
		return static_cast<float>(dpi) / 96.0f;
	}

	// ---------------------------------------------------------------------
	// ★★ v84：**两套界面可切换** —— 「液态玻璃」/「经典」
	//
	//   用户要求（原话）：「做两个可切换的界面版本，一个是用 OpenGL，
	//   另一个是原来的界面」。
	//   · 经典 = v82 那套完全不透明的平面界面（结构一模一样，只是不铺玻璃层）
	//   · 液态玻璃 = GL 着色器（不可用时自动退到 CPU 合成，外观基本一致）
	//
	//   取值与环境变量 / 设置文件的规则**只在 ui_style.h 里写一份**（铁律 127）：
	//   两个 exe 共用，包括托盘里那个「界面：…」文案。
	// ---------------------------------------------------------------------
	using R3ShieldCoreUi::Style;
	Style g_uiStyle = Style::Glass;

	// OpenGL 后端实例（进程级；Init 失败就一直是 CPU 合成）
	R3ShieldCoreUi::GlGlass g_gl;

	// 把 GlassSurface 的面板表翻译成 GL 后端的入参并渲染。
	// ★ 这是 CPU / GPU 两条路唯一的分叉点：都产出同一块 top-down BGRA 缓冲。
	void GlComposeBridge(void* ctx, const R3ShieldCoreUi::Backdrop& bd,
		const R3ShieldCoreUi::PanelRec* panels, int count,
		int headerBand, float headerVeil,
		int w, int h, float dpi, BYTE* out)
	{
		auto* gl = static_cast<R3ShieldCoreUi::GlGlass*>(ctx);
		R3ShieldCoreUi::GlGlass::PanelDraw list[96];
		const int n = count < 96 ? count : 96;
		for (int i = 0; i < n; ++i) {
			list[i].x0 = panels[i].x0;
			list[i].y0 = panels[i].y0;
			list[i].x1 = panels[i].x1;
			list[i].y1 = panels[i].y1;
			list[i].radius = panels[i].radius;
			list[i].tint = panels[i].tint;
			list[i].kind = panels[i].kind;
		}
		if (!gl->Render(bd.full.bits, bd.full.w, bd.full.h, list, n,
			headerBand, headerVeil, w, h, dpi, out)) {
			// ★★ GL 中途失败（设备丢失 / 驱动异常）⇒ **当场退回 CPU**，并把钩子摘掉。
			//   不摘的话每帧都会重试、每帧都要多花一次失败的 GL 调用。
			g_glass.glCompose = nullptr;
			R3ShieldCoreUi::PaintBackdropBase(out, w, h, bd,
				R3ShieldCoreUi::DefaultTheme(), R3ShieldCoreUi::DefaultTheme().veil);
			printf("[glass] 警告：GL 合成本帧失败，已退回 CPU 合成（后续不再尝试 GL）\n");
		}
	}

	// ---------------------------------------------------------------------
	// LoadAppIcon —— 取 exe 资源里的产品图标（ID 见 IconResourceId）。
	//
	// ★★ 为什么不能写 LoadIcon(nullptr, IDI_APPLICATION)（原实现）：
	//     第一参数传 nullptr 时 Windows 只去**系统模块**里找图标，
	//     永远看不到我们自己编进 exe 的那一个 —— 于是窗口标题栏、
	//     任务栏、Alt+Tab 一直是系统的空白"应用程序"默认图标。
	//     必须传**本模块句柄** + 资源 ID。
	//
	// ★ 失败要有兜底**且不静默**：万一资源被裁掉（某个构建配置漏了 .res），
	//   退回 IDI_APPLICATION 至少不会出现空方框；但必须打一行日志 ——
	//   否则这种"图标悄悄变回默认"的问题永远查不出来（铁律 97）。
	//
	// ★ 定义位置：必须在 g_instance 声明**之后**，所以没有跟 IconResourceId
	//   放在一起（那里只有前向声明）。
	// ---------------------------------------------------------------------
	HICON LoadAppIcon(int cx, int cy)
	{
		HICON icon = nullptr;
		if (g_instance) {
			// 先按目标尺寸精确取（比 LR_DEFAULTSIZE 让系统缩放更清晰）
			icon = static_cast<HICON>(LoadImageW(
				g_instance, MAKEINTRESOURCEW(IconResourceId),
				IMAGE_ICON, cx, cy, LR_DEFAULTCOLOR));
			if (!icon) {
				// 指定尺寸取不到时退回"取默认尺寸"，由系统挑最合适的一张
				icon = LoadIconW(g_instance, MAKEINTRESOURCEW(IconResourceId));
			}
		}
		if (!icon) {
			const DWORD err = GetLastError();
			printf("[gui] 警告：加载资源图标 %d 失败（err=%lu），退回系统默认图标；"
			       "多半是构建时漏了 rsrc/r3shieldcore.rc\n",
			       IconResourceId, static_cast<unsigned long>(err));
			icon = LoadIcon(nullptr, IDI_APPLICATION);
		}
		return icon;
	}
	HANDLE g_guiThread = nullptr;
	volatile LONG g_stop = 0;
	volatile LONG g_uiAccessRestartRequest = 0;
	volatile LONG g_quitRequest = 0;   // 用户点了「退出引擎」
	bool g_classRegistered = false;
	bool g_allowUiAccessRestart = true;

	// ★ 托盘：关闭窗口**不退出**，收进通知区（用户 2026-10-17 要求）。
	//
	//   三个状态各管一件事，别混：
	//     · `g_tray.icon`          —— 图标本体（RAII，析构时 NIM_DELETE）；
	//     · `g_tray.windowHidden`  —— 窗口现在是"收起来了"吗（决定双击/菜单是显示还是隐藏）；
	//     · `g_tray.reallyExiting` —— 用户**真的**要退出（托盘菜单选了「退出」）。
	//   ★ 最后这个标志是整套东西的关键：`WM_CLOSE` 与「退出」都走
	//     `DestroyWindow`，**只能靠它区分**。没有它就会出现
	//     "点了退出却只是把窗口收起来、进程还在跑"这种最坏的观感。
	struct {
		R3ShieldCoreTray::TrayIcon icon;
		bool windowHidden = false;
		bool reallyExiting = false;
	} g_tray;

	HFONT g_titleFont = nullptr;
	HFONT g_labelFont = nullptr;
	HFONT g_valueFont = nullptr;
	HFONT g_monoFont = nullptr;
	HFONT g_logFont = nullptr;   // 日志行用更小的等宽字体，一屏塞得下更多
	HFONT g_tabFont = nullptr;
	// ★ v79：Markdown 的 `**加粗**` 要真加粗 —— 与 g_labelFont 同字号同字面，
	//   只差字重，所以同一行里混排时基线不会跳。
	HFONT g_boldFont = nullptr;

	R3ShieldCoreGui::Options g_options = {};

	//
	// ★ v61：底部统计栏的**实际**高度。
	//
	// 为什么是函数而不是常量：行数是变的 ——
	//   第 1 行「状态摘要」恒在；
	//   第 2 行「高危命中」只在 `HighRisk` 开时画（旧行为）；
	//   第 3 行「高危进程」只在 v61 的 `high_risk_process_alert` 开时画。
	//
	// 行距 26（行高 22 + 间隔 4），首行上边距 8，末行下留白 18
	// ⇒ 高度 = 26 × 行数 + 26。两行 = 78（与旧常量一致，不改变既有观感）。
	//
	// 所有布局点（事件日志页、进程页、概览页的底部边界）都必须用这个，
	// 用常量会让底部栏盖住列表最后一行 —— 而那正好是用户最想看的新事件。
	//
	int PromptSummaryHeight() noexcept
	{
		int rows = 1;   // 状态摘要
		if (g_options.HighRisk) {
			rows++;     // 高危命中
		}
		if (g_options.HighRiskProcessAlert != 0) {
			rows++;     // 高危进程
		}
		return (rows + 1) * PromptSummaryRowHeight;
	}

	// 当前页签：0 = 概览，1 = 事件日志，2 = 进程，3 = 配置，4 = ARK。
	int g_activeTab = 0;

	// ---- 日志视图状态（只在 GUI 线程访问）----
	std::vector<R3ShieldCoreStats::LogEntry> g_logRows; // 本地镜像，按时间升序
	ULONG g_logLastSerial = 0;                      // 已取到的最大序号
	int g_logScroll = 0;                            // 从尾部往前偏移多少行（0 = 贴底）
	bool g_logFollowTail = true;                    // 是否自动跟随最新
	bool g_logOnlyBlocked = false;                  // 只看被拦截的
	int g_logSourceFilter = 0;                      // 0=全部 1=注册表 2=文件 3=进程/线程 4=驱动 5=网络 6=摄像头 7=输入钩子 8=截屏 9=DLL加载 10=剪贴板 11=进程旁路 12=服务权限 13=COM 14=计划任务
	bool g_logMoreSinceSerialOverflow = false;      // 上次读取时序号断档（被覆盖过）

	// 主循环喂进来的累计注入数。volatile 足够 —— 单字写，GUI 读到旧值无所谓。
	volatile LONG g_injectedTotal = 0;

	// ------------------------------------------------------------------
	// ★ v62：ARK 页状态（只在 GUI 线程读写）
	// ------------------------------------------------------------------
	//
	// `g_arkSnapshot` 是**本地缓存**：`R3ShieldCoreArk::GetSnapshot()` 每次要
	// 复制几百行（每行两个 wstring），而重绘比扫描频繁得多（鼠标一动就重绘）。
	// 所以按时间节流拉取，绘制只用缓存。
	R3ShieldCoreArk::Snapshot g_arkSnapshot;
	ULONGLONG g_arkFetchedMs = 0;
	ULONG g_arkFetchedScans = 0;
	int g_arkSelectedPid = -1;      // -1 = 未选中
	int g_arkScroll = 0;            // 表格首行索引
	int g_arkHoverAction = -1;      // 悬停的按钮（ArkButton 的整数值）
	int g_arkPressedAction = -1;    // 按下的按钮
	bool g_arkKillArmed = false;    // 「强制结束」已进入二次确认
	int g_arkArmedPid = -1;         // 二次确认针对的 pid（换选中就撤销）

	// 选中进程的"最近事件"缓存。跟随选中项与扫描节流刷新。
	std::vector<R3ShieldCoreStats::LogEntry> g_arkEvents;
	int g_arkEventsPid = -1;
	ULONG g_arkEventsStamp = 0;
	std::vector<R3ShieldCoreArk::ActionRecord> g_arkActions;
	ULONG g_arkActionsSerial = 0;

	// ★ v80：「高级」页签只剩一个按钮（把 cfg 叫到前台）。状态与 ARK 那套一样
	//   单独一份 —— 它的位置随客户区大小变、且只在这一页存在。
	//
	//   `g_advLaunchError` 存**上次跳转失败的原因**。为什么不弹 MessageBox：
	//   弹窗把"为什么点了没反应"变成一个必须点掉的框，而用户此刻可能正在
	//   做别的事；画在页内更安静，而且 `--gui-preview` 的截图能拍到它
	//   （可核对，铁律 24/28）。
	int g_advLaunchHover = -1;
	int g_advLaunchPressed = -1;
	std::wstring g_advLaunchError;

	// ★ v80：**仅预览模式**用的开关 —— 建窗后自动"点一下"跳转按钮。
	//
	//   为什么需要：用户要的核心行为是"点主程序的「高级」→ 跳到 cfg 的
	//   高级页"。这条链路的每一环（窗口类名 / 激活消息 / 页号 / exe 名）
	//   都可能静默对不上 —— 而"点了没反应"和"页面画错了"在截图上分不开。
	//   没有这个开关，就只能靠人眼点一下（铁律 24/28）。
	//
	//   ⚠️ 只在 `--gui-preview` 下由环境变量置起（见 RunPreview）；
	//      生产路径读不到它 ⇒ 不会有人被"自动点击"。
	bool g_previewJumpClick = false;

	// 当前显示用的模式。**不能直接读 g_options.Mode** ——
	// 运行期切模式时引擎线程会改它，而 g_options 是普通结构体
	// （非原子读写 + 撕裂风险）。用一个 LONG 走原子访问。
	volatile LONG g_displayMode = static_cast<LONG>(R3ShieldCore::Mode::Log);

	// 界面线程写、引擎线程取。-1 = 没有待处理请求。
	// 取值用 InterlockedExchange 一次性消费，避免"点了两下只生效一次/生效两次"。
	volatile LONG g_pendingMode = -1;

	// ---- 置顶状态（只在 GUI 线程读写）----
	// 三档：不置顶 / 默认置顶（普通 TOPMOST）/ 超级置顶（UIAccess Band）。
	bool g_topMost = false;          // 当前是否置顶（普通或超级）
	bool g_superTopMost = false;     // 当前是否处于「超级置顶」档
	bool g_superBandApplied = false; // 超级档是否真拿到了 UIAccess Band

	// 超级档的周期重申定时器。id 1 已被"重画"占用（300ms）。
	constexpr UINT_PTR TopMostReinforceTimerId = 2;
	constexpr UINT TopMostReinforceIntervalMs = 250;

	// ★ v63：ARK 页的刷新定时器（id 3），间隔来自 `ark_refresh_ms`。
	//
	// 为什么不复用 id 1（300ms 重画）：
	//   那个定时器是**全页面**的节拍（日志页靠它跟手），改它会连带
	//   影响别的页；而 ARK 的刷新率是**要交给用户配的**，两者需求不同。
	//   单独一个定时器，各自的语义才干净：id 1 管"重画"，
	//   id 3 管"重取数据 + 重画 ARK 页"。
	constexpr UINT_PTR ArkRefreshTimerId = 3;

	int ClientWidth();

	constexpr int ModeButtonWidth = 112;
	constexpr int ActionButtonWidth = 92;
	constexpr int ActionButtonGap = 8;

	// 标题区右侧的两个「置顶」开关（默认置顶 / 超级置顶）。
	// 宽度按 4 个汉字 + 左右内边距给，高度与模式徽章齐平。
	constexpr int HeaderToggleWidth = 88;
	constexpr int HeaderToggleHeight = 26;
	constexpr int HeaderToggleGap = 8;

	// 模式徽章的尺寸。DrawModeBadge 画它、置顶按钮靠它右对齐，
	// 两边共用同一组常量 —— 分开写必然漂移（自绘 UI 的老坑）。
	constexpr int ModeBadgeWidth = 92;
	constexpr int ModeBadgeHeight = 26;
	constexpr int ModeBadgeTop = 18;

	RECT ClearStatsButtonRect()
	{
		const int right = ClientWidth() - Padding - ModeButtonWidth - ActionButtonGap;
		return { right - ActionButtonWidth, TabBarTop + 4,
			right, TabBarTop + TabBarHeight - 4 };
	}

	RECT CopyLogButtonRect()
	{
		RECT clear = ClearStatsButtonRect();
		return { clear.left - ActionButtonGap - ActionButtonWidth, clear.top,
			clear.left - ActionButtonGap, clear.bottom };
	}

	// 「复制全部日志」按钮：紧挨在「复制日志路径」左边。
	//
	// 和「复制日志路径」的区别：那个只复制**路径字符串**（给本机排查用），
	// 这个把**所有 *.log 的内容**拼成一段文本塞进剪贴板 —— 用于"机器已经
	// 快没了、只能靠剪贴板把日志带出去"的场景。
	RECT CopyAllLogsButtonRect()
	{
		RECT copy = CopyLogButtonRect();
		return { copy.left - ActionButtonGap - ActionButtonWidth, copy.top,
			copy.left - ActionButtonGap, copy.bottom };
	}

	// 「退出引擎」按钮：页签栏右侧动作簇的**最左端**（复制全部日志左边）。
	//
	// 为什么单独放一个、还涂成红色：这是**破坏性**动作 —— 一点引擎会话就结束
	// （反注入 + 关窗口）。和「复制日志」那一排挨着有误点风险，所以用红色
	// 描边/文字把它从一排中性按钮里拎出来，同时保持 8px 常规间距、不破坏簇的节奏。
	//
	// ⚠️ 动作簇每加一个按钮，窗口最小宽度都要跟着抬（见 WM_GETMINMAXINFO），
	//   否则最小宽度下它会压到左边四个页签上。
	RECT ExitButtonRect()
	{
		RECT all = CopyAllLogsButtonRect();
		return { all.left - ActionButtonGap - ActionButtonWidth, all.top,
			all.left - ActionButtonGap, all.bottom };
	}

	// 标题区右侧：从左到右依次是「默认置顶」「超级置顶」，再往右是模式徽章。
	// 和徽章一样按**真实客户区宽度**右对齐（窗口是 WS_THICKFRAME，能拉宽，
	// 用常量会在拉宽后浮在中间）。绘制和命中测试都走这两个函数，保证一致。
	RECT SuperTopMostButtonRect()
	{
		const int badgeLeft = ClientWidth() - Padding - ModeBadgeWidth;
		const int top = ModeBadgeTop;
		const int right = badgeLeft - HeaderToggleGap;
		return { right - HeaderToggleWidth, top, right, top + HeaderToggleHeight };
	}

	RECT TopMostButtonRect()
	{
		RECT superRect = SuperTopMostButtonRect();
		return { superRect.left - HeaderToggleGap - HeaderToggleWidth, superRect.top,
			superRect.left - HeaderToggleGap, superRect.bottom };
	}

	void DrawTextSimple(HDC dc, PCWSTR text, RECT rect, HFONT font, COLORREF color, UINT format)
	{
		HGDIOBJ oldFont = SelectObject(dc, font);
		SetBkMode(dc, TRANSPARENT);
		SetTextColor(dc, color);
		DrawText(dc, text, -1, &rect, format | DT_NOPREFIX);
		SelectObject(dc, oldFont);
	}

	// 画一条水平柱状条。value / maxValue 决定填充比例。
	void DrawBar(HDC dc, int left, int top, int width, int height,
		ULONGLONG value, ULONGLONG maxValue, COLORREF color)
	{
		RECT track = { left, top, left + width, top + height };
		HBRUSH trackBrush = CreateSolidBrush(ColorTrack);
		FillRect(dc, &track, trackBrush);
		DeleteObject(trackBrush);

		if (maxValue == 0 || value == 0) {
			return;
		}

		ULONGLONG filled = (static_cast<ULONGLONG>(width) * value) / maxValue;
		if (filled == 0) {
			filled = 2; // 非零值至少画一点点，表示"有"
		}

		RECT fill = { left, top, left + static_cast<int>(filled), top + height };
		HBRUSH fillBrush = CreateSolidBrush(color);
		FillRect(dc, &fill, fillBrush);
		DeleteObject(fillBrush);
	}

	COLORREF DecisionColor(R3ShieldCore::Decision decision)
	{
		switch (decision) {
		case R3ShieldCore::Decision::Allowed: return ColorAccent;
		case R3ShieldCore::Decision::Blocked: return ColorBlocked;
		case R3ShieldCore::Decision::WouldBlock: return ColorWouldBlock;
		case R3ShieldCore::Decision::Spoofed: return ColorSpoofed;
		default: return ColorTextSecondary;
		}
	}

	// 按监控对象类型取来源标记色。日志页「来源」列和操作分布柱状图共用，
	// 保证同一个对象类型在两处颜色一致。
	COLORREF ObjectTypeColor(ULONG objectType)
	{
		switch (static_cast<R3ShieldCore::ObjectType>(objectType)) {
		case R3ShieldCore::ObjectType::Registry: return ColorRegistryAccent;
		case R3ShieldCore::ObjectType::File: return ColorFileAccent;
		case R3ShieldCore::ObjectType::Process: return ColorProcessAccent;
		case R3ShieldCore::ObjectType::Thread: return ColorThreadAccent;
		case R3ShieldCore::ObjectType::Driver: return ColorDriverAccent;
		case R3ShieldCore::ObjectType::Network: return ColorNetworkAccent;
		case R3ShieldCore::ObjectType::Camera: return ColorCameraAccent;
		case R3ShieldCore::ObjectType::InputHook: return ColorInputHookAccent;
		case R3ShieldCore::ObjectType::Screen: return ColorScreenAccent;
		case R3ShieldCore::ObjectType::DllLoad: return ColorDllLoadAccent;
		case R3ShieldCore::ObjectType::Clipboard: return ColorClipboardAccent;
		case R3ShieldCore::ObjectType::ProcessSpawn: return ColorSpawnAccent;
		case R3ShieldCore::ObjectType::ServiceConfig: return ColorServiceConfigAccent;
		case R3ShieldCore::ObjectType::ComHijack: return ColorComAccent;
		case R3ShieldCore::ObjectType::ScheduledTask: return ColorTaskAccent;
		default: return ColorTextSecondary;
		}
	}

	// 日志页「来源」列的中文标签。
	PCWSTR ObjectTypeLabel(ULONG objectType)
	{
		switch (static_cast<R3ShieldCore::ObjectType>(objectType)) {
		case R3ShieldCore::ObjectType::File: return L"文件";
		case R3ShieldCore::ObjectType::Process: return L"进程";
		case R3ShieldCore::ObjectType::Thread: return L"线程";
		case R3ShieldCore::ObjectType::Driver: return L"驱动";
		case R3ShieldCore::ObjectType::Network: return L"网络";
		case R3ShieldCore::ObjectType::Camera: return L"摄像头";
		case R3ShieldCore::ObjectType::InputHook: return L"输入钩子";
		case R3ShieldCore::ObjectType::Screen: return L"截屏";
		case R3ShieldCore::ObjectType::DllLoad: return L"DLL加载";
		case R3ShieldCore::ObjectType::Clipboard: return L"剪贴板";
		case R3ShieldCore::ObjectType::ProcessSpawn: return L"进程旁路";
		case R3ShieldCore::ObjectType::ServiceConfig: return L"服务权限";
		case R3ShieldCore::ObjectType::ComHijack: return L"COM劫持";
		case R3ShieldCore::ObjectType::ScheduledTask: return L"计划任务";
		default: return L"注册表";
		}
	}

	std::wstring FormatNumber(ULONGLONG value)
	{
		WCHAR buffer[64] = {};
		swprintf_s(buffer, L"%llu", value);

		// 每三位插一个逗号，数字大时好读。
		std::wstring digits(buffer);
		std::wstring result;
		int count = 0;
		for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
			if (count > 0 && count % 3 == 0) {
				result.insert(result.begin(), L',');
			}
			result.insert(result.begin(), *it);
			count++;
		}

		return result;
	}

	std::wstring FormatDuration(ULONGLONG milliseconds)
	{
		ULONGLONG totalSeconds = milliseconds / 1000;
		ULONGLONG hours = totalSeconds / 3600;
		ULONGLONG minutes = (totalSeconds % 3600) / 60;
		ULONGLONG seconds = totalSeconds % 60;

		WCHAR buffer[32] = {};
		swprintf_s(buffer, L"%02llu:%02llu:%02llu", hours, minutes, seconds);
		return buffer;
	}

	void DrawOverview(HDC dc, int& y, const R3ShieldCoreStats::Snapshot& snapshot, ULONG injectedTotal)
	{
		const int columnWidth = (ClientWidth() - Padding * 2) / 3;

		struct Metric
		{
			PCWSTR label;
			std::wstring value;
		};

		ULONGLONG uptime = GetTickCount64() - snapshot.StartTick;

		//
		// ★ v54：当统计带了历史基线（跨重启累计）时，另外显示"本次 +N"。
		//
		// 为什么必须分开显示：累计值里混着**上一轮/上一代引擎**的成果。
		// 用户点一下「超级置顶」就换一次引擎，看到"监控事件 12,431"
		// 会以为都是这次弄出来的 —— 那是误导。分开写才说得清。
		//
		const R3ShieldCoreStats::Snapshot session = R3ShieldCoreStats::GetSessionSnapshot();
		const bool hasBaseline = snapshot.TotalEvents > session.TotalEvents;

		std::wstring eventText = FormatNumber(snapshot.TotalEvents);
		if (hasBaseline) {
			eventText += L"  （本次 +" + FormatNumber(session.TotalEvents) + L"）";
		}

		Metric metrics[3] = {
			{ L"运行时长", FormatDuration(uptime) },
			{ L"已注入进程", FormatNumber(injectedTotal) },
			// 注意：这条在累计模式下宽度会超，DrawTextSimple 用 DT_END_ELLIPSIS
			// 截断 —— 所以把"（本次 +N）"放在后面，先保证总数可见。
			{ L"监控事件（累计）", eventText },
		};

		if (hasBaseline) {
			metrics[0].label = L"运行时长（本次）";
		}

		for (int i = 0; i < 3; i++) {
			int left = Padding + i * columnWidth;

			RECT labelRect = { left, y, left + columnWidth, y + 16 };
			DrawTextSimple(dc, metrics[i].label, labelRect, g_labelFont, ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE);

			RECT valueRect = { left, y + 18, left + columnWidth, y + 44 };
			DrawTextSimple(dc, metrics[i].value.c_str(), valueRect, g_valueFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		y += 58;
	}

	// 模式短名（徽章 / 切换按钮共用）。
	PCWSTR ModeShortName(R3ShieldCore::Mode mode)
	{
		switch (mode) {
		case R3ShieldCore::Mode::Block: return L"BLOCK";
		case R3ShieldCore::Mode::Ask: return L"ASK";
		case R3ShieldCore::Mode::BlockAll: return L"全拦";
		case R3ShieldCore::Mode::BlockAllSafe: return L"全拦·安全";
		default: return L"LOG";
		}
	}

	// 点一下按钮走到哪个模式。
	//
	// ⚠️ **两种全拦模式都不在循环里**。它们虽然自 v21 起把"进程创建 / 远程
	//    线程 / 跨进程内存"改成了弹窗，但其余仍旧一律拒绝，第三方程序仍会
	//    大面积失灵 —— 所以不能靠"手滑多点两下"进去，只能改 ini 开。
	//    反过来，如果当前**已经是**全拦（ini 里开的），点一下会退回 LOG，
	//    相当于给了一个不用改 ini 的逃生门。
	R3ShieldCore::Mode NextMode(R3ShieldCore::Mode current)
	{
		switch (current) {
		case R3ShieldCore::Mode::Log: return R3ShieldCore::Mode::Block;
		case R3ShieldCore::Mode::Block: return R3ShieldCore::Mode::Ask;
		case R3ShieldCore::Mode::Ask: return R3ShieldCore::Mode::Log;
		// BlockAll / BlockAllSafe → 退回 LOG（逃生门）
		default: return R3ShieldCore::Mode::Log;
		}
	}

	// 「切换模式」按钮：页签栏右侧。
	//
	// 为什么放这儿而不是标题区：标题区左边被标题文字占满、右边被模式徽章占满，
	// 中间只剩 8px；页签栏右半段本来就是空的。
	//
	// ⚠️ 按**真实客户区宽度**算（窗口能拉宽，用常量会在拉宽后浮在中间）。
	//    DrawModeButton 和 HitTestHeaderAction 都走这个函数，保证画的和点的一致。
	// 真实客户区宽度。窗口是 WS_THICKFRAME（能拉宽），凡是要右对齐的东西
	// 都得用它，不能用 WindowWidth 常量 —— 否则拉宽后全部浮在中间。
	int ClientWidth()
	{
		RECT client = {};
		if (g_window) {
			GetClientRect(g_window, &client);
		}
		else {
			client.right = WindowWidth;
		}
		return client.right;
	}

	RECT ModeButtonRect()
	{
		const int right = ClientWidth() - Padding;
		const int top = TabBarTop + 4;
		RECT rect = { right - ModeButtonWidth, top, right, top + TabBarHeight - 8 };
		return rect;
	}

	// ---- 标题区 / 页签栏上的所有可点区域 ----
	//
	// 集中在一处：绘制和命中测试都从这张表取矩形，避免"画一个地方、点另一个地方"
	// （自绘 UI 的经典坑）。加按钮只改这里 + HitTestHeaderAction + PerformHeaderAction。
	enum class HeaderAction
	{
		None,
		ExitEngine,
		CopyAllLogs,
		CopyLogPath,
		ClearStats,
		ModeSwitch,
		TopMostNormal,
		TopMostSuper,
	};

	// 「复制全部日志」的反馈：动作完成后 2.5 秒内按钮改显示「已复制 / 复制失败」。
	//
	// 为什么要有反馈：这个按钮的用途是**把日志从一台马上要报废的机器里带出去**
	// （盘被写坏 → 日志文件也取不出来，剪贴板是唯一通道）。点完没有任何反馈，
	// 用户不敢确定到底出去了没有，就不敢关机、会反复点。
	// 用 GetTickCount64 的时间戳 + 已有的 300ms 重画定时器即可，不需要额外定时器。
	enum class CopyLogsFeedback { None, Copied, Failed };
	CopyLogsFeedback g_copyLogsFeedback = CopyLogsFeedback::None;
	ULONGLONG g_copyLogsFeedbackUntil = 0;

	// 按钮三态。只在 GUI 线程读写，用普通变量即可（和 g_topMost 一样）。
	enum class ButtonState { Normal, Hover, Pressed };

	// 鼠标当前悬停 / 左键按下的按钮。
	HeaderAction g_hoverButton = HeaderAction::None;
	HeaderAction g_pressedButton = HeaderAction::None;
	// 悬停的页签（-1 = 没有）。页签虽然不算"按钮"，但同在一行，
	// 只让按钮有反馈、页签没有会显得很割裂。
	int g_hoverTab = -1;
	// 是否已向系统登记 WM_MOUSELEAVE。不登记的话鼠标移出窗口后收不到通知，
	// 悬停态会永远留在最后一个元素上。
	bool g_trackingMouseLeave = false;

	// 取某个按钮当前的视觉状态。
	// ★ 按住左键拖离按钮 ⇒ 该按钮回到 Normal（标准按钮语义：拖出去就不算按下）。
	ButtonState StateOf(HeaderAction id)
	{
		if (id != HeaderAction::None && id == g_pressedButton) {
			return id == g_hoverButton ? ButtonState::Pressed : ButtonState::Normal;
		}
		return id == g_hoverButton ? ButtonState::Hover : ButtonState::Normal;
	}

	// 由（是否开启 / 是否危险 / 三态）算出背景、描边、文字三色。
	//
	// 层次：Normal = 白底中性描边；Hover = 浅色底 + 强调色描边文字；
	//       Pressed = 更深一档的底。danger（退出引擎）走红色系，和中性按钮拉开距离。
	void ButtonColors(bool active, bool danger, ButtonState state,
		COLORREF* background, COLORREF* border, COLORREF* text)
	{
		const COLORREF accent = danger ? ColorBlocked : ColorAccent;
		switch (state) {
		case ButtonState::Pressed:
			*background = active ? RGB(198, 222, 245)
				: (danger ? RGB(246, 216, 216) : RGB(213, 230, 248));
			break;
		case ButtonState::Hover:
			*background = active ? RGB(222, 236, 250)
				: (danger ? RGB(252, 235, 235) : RGB(233, 242, 252));
			break;
		default:
			*background = active ? RGB(235, 244, 252) : ColorHeaderBackground;
			break;
		}

		// 开启档：描边/文字用调用方的强调色（超级置顶可能给橙色）。
		// 危险档：始终红。中性档：Normal 时灰、悬停/按下时转强调色（可点的暗示）。
		if (active) {
			*border = accent;
			*text = accent;
		}
		else if (danger) {
			*border = ColorBlocked;
			*text = ColorBlocked;
		}
		else if (state == ButtonState::Normal) {
			*border = ColorBorder;
			*text = ColorTextSecondary;
		}
		else {
			*border = accent;
			*text = accent;
		}
	}

	void DrawModeButton(HDC dc)
	{
		RECT rect = ModeButtonRect();
		const R3ShieldCore::Mode next = NextMode(
			static_cast<R3ShieldCore::Mode>(InterlockedCompareExchange(&g_displayMode, 0, 0)));

		WCHAR text[48] = {};
		swprintf_s(text, L"切换: %s", ModeShortName(next));

		COLORREF background = ColorHeaderBackground;
		COLORREF border = ColorAccent;
		COLORREF textColor = ColorAccent;
		ButtonColors(false, false, StateOf(HeaderAction::ModeSwitch),
			&background, &border, &textColor);
		// 模式按钮本身就是"主按钮"：描边/文字恒为强调色，只让底色随三态变化。
		border = ColorAccent;
		textColor = ColorAccent;

		// ★ v83：主按钮 = 更"厚"一点的小玻璃片（tint 比普通按钮高 2 档），
		//   强调色留在文字与下划线上。
		if (g_glass.active) {
			const ButtonState state = StateOf(HeaderAction::ModeSwitch);
			float tint = 0.22f;
			if (state == ButtonState::Hover) { tint = 0.30f; }
			if (state == ButtonState::Pressed) { tint = 0.36f; }
			g_glass.AddPanel(rect.left, rect.top, rect.right, rect.bottom,
				(rect.bottom - rect.top) * 0.5f, tint, 1);
			{
				RECT underline = { rect.left + 12, rect.bottom - 4, rect.right - 12, rect.bottom - 3 };
				HBRUSH ub = CreateSolidBrush(ColorAccent);
				FillRect(dc, &underline, ub);
				DeleteObject(ub);
			}
		} else {
			HBRUSH brush = CreateSolidBrush(background);
			HGDIOBJ oldBrush = SelectObject(dc, brush);
			HPEN pen = CreatePen(PS_SOLID, 1, border);
			HGDIOBJ oldPen = SelectObject(dc, pen);
			RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 16, 16);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(brush);
			DeleteObject(pen);
		}

		RECT textRect = rect;
		if (StateOf(HeaderAction::ModeSwitch) == ButtonState::Pressed) {
			OffsetRect(&textRect, 0, 1); // 按下时文字下沉 1px，做出"压下去"的手感
		}
		DrawTextSimple(dc, text, textRect, g_tabFont, textColor,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	// active：按钮处于「已开启」档 —— 描边/文字用强调色，一眼看出哪档是开的。
	// accent：可换强调色。超级置顶未进入 UIAccess Band 时用橙色，提示已回退。
	// danger：破坏性动作（退出引擎）。未开启时也把描边/文字涂红，和中性按钮区分开。
	//
	// id 用来查三态（悬停/按下）—— 和 HitTestHeaderAction 用的是同一套 id，
	// 所以"画成什么样"和"点到哪个"不可能对不上。
	void DrawActionButton(HDC dc, HeaderAction id, const RECT& rect, PCWSTR text,
		bool active, COLORREF accent = ColorAccent, bool danger = false)
	{
		const ButtonState state = StateOf(id);
		COLORREF background = ColorHeaderBackground;
		COLORREF border = ColorBorder;
		COLORREF textColor = ColorTextSecondary;
		ButtonColors(active, danger, state, &background, &border, &textColor);

		// ★ v83：按钮 = 一块小玻璃片。语义（危险=红 / 生效=强调色 / 三态）全部
		//   保留在 **文字色** 上；底色只表达"玻璃的厚度"（tint 随三态变化）。
		//   ★ 为什么不把语义色也铺到玻璃上：玻璃是半透明的，一铺色整块就变成
		//     "实色贴纸"，反而丢掉材质感；而且深色文字压在饱和底色上更难读。
		if (g_glass.active) {
			float tint = 0.16f;
			if (state == ButtonState::Hover) { tint = 0.24f; }
			if (state == ButtonState::Pressed) { tint = 0.32f; }
			if (active) { tint += 0.10f; }
			if (danger) { tint += 0.03f; }
			g_glass.AddPanel(rect.left, rect.top, rect.right, rect.bottom,
				(rect.bottom - rect.top) * 0.5f, tint, 1);
		} else {
			HBRUSH brush = CreateSolidBrush(background);
			HPEN pen = CreatePen(PS_SOLID, 1, border);
			HGDIOBJ oldBrush = SelectObject(dc, brush);
			HGDIOBJ oldPen = SelectObject(dc, pen);
			RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 16, 16);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(brush);
			DeleteObject(pen);
		}

		// 按下时文字下沉 1px，做出"压下去"的手感。
		RECT textRect = rect;
		if (state == ButtonState::Pressed) {
			OffsetRect(&textRect, 0, 1);
		}
		DrawTextSimple(dc, text, textRect, g_tabFont, textColor,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);

		// 生效态：底部一条 1px 的语义色下划线（代替原来的实底高亮）
		if (g_glass.active && active) {
			RECT underline = { rect.left + 12, rect.bottom - 4, rect.right - 12, rect.bottom - 3 };
			HBRUSH ub = CreateSolidBrush(border);
			FillRect(dc, &underline, ub);
			DeleteObject(ub);
		}
	}

	void DrawHeaderActions(HDC dc)
	{
		DrawActionButton(dc, HeaderAction::ExitEngine, ExitButtonRect(),
			L"退出引擎", false, ColorAccent, true);

		// 「复制全部日志」：刚复制完的那 2.5 秒改显示「已复制 / 复制失败」——
		// 否则用户按下去没有任何反馈，不敢确定日志到底出去没有。
		PCWSTR copyLogsLabel = L"复制全部日志";
		bool copyLogsActive = false;
		if (g_copyLogsFeedback != CopyLogsFeedback::None &&
			GetTickCount64() < g_copyLogsFeedbackUntil) {
			copyLogsLabel = (g_copyLogsFeedback == CopyLogsFeedback::Copied)
				? L"已复制" : L"复制失败";
			copyLogsActive = (g_copyLogsFeedback == CopyLogsFeedback::Copied);
		}
		DrawActionButton(dc, HeaderAction::CopyAllLogs, CopyAllLogsButtonRect(),
			copyLogsLabel, copyLogsActive);

		DrawActionButton(dc, HeaderAction::CopyLogPath, CopyLogButtonRect(),
			L"复制日志路径", false);
		DrawActionButton(dc, HeaderAction::ClearStats, ClearStatsButtonRect(),
			L"清空统计", false);
	}

	// 标题区右侧的两个置顶开关。默认置顶高亮 = 普通档生效；
	// 超级置顶高亮 = 超级档生效。描边色表示是否真的进入 UIAccess Band。
	//   蓝 = SetWindowBand 成功；橙 = 仅保留普通 TOPMOST
	void DrawTopMostButtons(HDC dc)
	{
		const bool normalActive = g_topMost && !g_superTopMost;
		const bool superActive = g_superTopMost;
		const bool effective = g_superBandApplied || R3ShieldCoreSuperDesk::IsRunning();
		DrawActionButton(dc, HeaderAction::TopMostNormal, TopMostButtonRect(),
			L"默认置顶", normalActive);
		DrawActionButton(dc, HeaderAction::TopMostSuper, SuperTopMostButtonRect(),
			L"超级置顶", superActive, effective ? ColorAccent : ColorWouldBlock);
	}

	HeaderAction HitTestHeaderAction(POINT point)
	{
		RECT exit = ExitButtonRect();
		if (PtInRect(&exit, point)) {
			return HeaderAction::ExitEngine;
		}
		RECT allLogs = CopyAllLogsButtonRect();
		if (PtInRect(&allLogs, point)) {
			return HeaderAction::CopyAllLogs;
		}
		RECT copy = CopyLogButtonRect();
		if (PtInRect(&copy, point)) {
			return HeaderAction::CopyLogPath;
		}
		RECT clear = ClearStatsButtonRect();
		if (PtInRect(&clear, point)) {
			return HeaderAction::ClearStats;
		}
		RECT mode = ModeButtonRect();
		if (PtInRect(&mode, point)) {
			return HeaderAction::ModeSwitch;
		}
		RECT topMost = TopMostButtonRect();
		if (PtInRect(&topMost, point)) {
			return HeaderAction::TopMostNormal;
		}
		RECT superTopMost = SuperTopMostButtonRect();
		if (PtInRect(&superTopMost, point)) {
			return HeaderAction::TopMostSuper;
		}
		return HeaderAction::None;
	}

	// 把一段文本放进剪贴板（CF_UNICODETEXT）。成功返回 true。
	bool SetClipboardText(PCWSTR text) noexcept
	{
		if (!text || !OpenClipboard(g_window)) {
			return false;
		}

		EmptyClipboard();
		const size_t bytes = (wcslen(text) + 1) * sizeof(WCHAR);
		HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
		bool ok = false;
		if (memory) {
			void* target = GlobalLock(memory);
			if (target) {
				memcpy(target, text, bytes);
				GlobalUnlock(memory);
				if (SetClipboardData(CF_UNICODETEXT, memory)) {
					memory = nullptr; // 成功后由剪贴板接管内存所有权。
					ok = true;
				}
			}
		}
		if (memory) {
			GlobalFree(memory);
		}
		CloseClipboard();
		return ok;
	}

	void CopyLogPathToClipboard()
	{
		if (g_options.LogPath) {
			SetClipboardText(g_options.LogPath);
		}
	}

	// -----------------------------------------------------------------
	// 「复制全部日志」
	// -----------------------------------------------------------------
	//
	// 存在的理由：**机器快没了的时候，日志文件本身也拿不出来**。
	// 盘被写坏（分区表没了）→ 系统起不来 → 目录里那几个 .log 一个都读不到。
	// 剪贴板是唯一还能把日志带出去的通道：虚拟机开着共享剪贴板时，
	// 在宿主机 Ctrl+V 就能贴出来。
	//
	// 与「复制日志路径」的分工：那个只给**本机排查**用（路径字符串），
	// 这个给**跨机器抢救**用（全部内容）。

	// 读一个日志文件（最多 maxBytes 字节）。
	//
	// ⚠️ 必须声明 `FILE_SHARE_WRITE`：日志**正在被写**（引擎自己、以及被注入
	//    进程里的 DLL 都会追加）。只声明 FILE_SHARE_READ 会拿到
	//    `ERROR_SHARING_VIOLATION(32)` —— 而"读不到"不等于"没内容"。
	bool ReadLogBytes(PCWSTR path, std::string& out, size_t maxBytes) noexcept
	{
		out.clear();

		HANDLE file = CreateFileW(path, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return false;
		}

		LARGE_INTEGER size = {};
		if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) {
			CloseHandle(file);
			return false;
		}

		const unsigned long long total = static_cast<unsigned long long>(size.QuadPart);
		const size_t want = (total > maxBytes) ? maxBytes : static_cast<size_t>(total);
		out.resize(want);

		DWORD read = 0;
		const BOOL ok = ReadFile(file, &out[0], static_cast<DWORD>(want), &read, nullptr);
		CloseHandle(file);

		out.resize(ok ? read : 0);
		return ok != FALSE && read > 0;
	}

	// 把日志字节转成宽字符。
	//
	// 引擎有两套日志编码（铁律 26）：事件日志是 **UTF-8**（带 BOM），
	// 控制台日志的中文是 **GBK**（printf 的窄字面量）。按 BOM 分派：
	//   ① 有 UTF-8 BOM                      → UTF-8
	//   ② 无 BOM 但**整段**能按 UTF-8 严格解通 → UTF-8
	//   ③ 否则                              → 系统 ANSI（中文系统 = GBK）
	// ② 必须整段成功才算 —— 只看头几个字节会把 GBK 误判成 UTF-8。
	std::wstring DecodeLogBytes(const std::string& bytes)
	{
		if (bytes.empty()) {
			return std::wstring();
		}

		const char* data = bytes.data();
		int length = static_cast<int>(bytes.size());
		UINT codePage = CP_ACP;

		const bool hasUtf8Bom =
			length >= 3 &&
			static_cast<unsigned char>(data[0]) == 0xEF &&
			static_cast<unsigned char>(data[1]) == 0xBB &&
			static_cast<unsigned char>(data[2]) == 0xBF;

		if (hasUtf8Bom) {
			data += 3;
			length -= 3;
			codePage = CP_UTF8;
		}
		else if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, length, nullptr, 0) > 0) {
			codePage = CP_UTF8;
		}

		const int chars = MultiByteToWideChar(codePage, 0, data, length, nullptr, 0);
		if (chars <= 0) {
			return std::wstring();
		}

		std::wstring wide(static_cast<size_t>(chars), L'\0');
		MultiByteToWideChar(codePage, 0, data, length, &wide[0], chars);
		return wide;
	}

	// 引擎自己写过的日志文件名（都在引擎目录下）。
	constexpr PCWSTR kEngineLogNames[] = {
		L"r3shieldcore-events.log",
		L"r3shieldcore-console.log",
		L"r3shieldcore-startup-error.log",
		L"superdesk-panel.log",
	};

	void CopyAllLogsToClipboard()
	{
		// 单文件上限 4 MB、总量上限 4 M 字符 —— 超过就截断，并在文末明说。
		// 剪贴板里塞几十 MB 没意义，粘贴还会把编辑器卡死。
		constexpr size_t kMaxBytesPerFile = 4u * 1024u * 1024u;
		constexpr size_t kMaxTotalChars = 4u * 1024u * 1024u;

		WCHAR modulePath[MAX_PATH * 2] = {};
		GetModuleFileNameW(nullptr, modulePath, _countof(modulePath));
		std::wstring directory(modulePath);
		const size_t slash = directory.find_last_of(L"\\/");
		directory.resize(slash == std::wstring::npos ? 0 : slash + 1);

		// 收集待导出文件：配置里的 r3shieldcore-events.log（`log=` 可能把它指到
		// 别处，比如宿主机共享目录）+ 引擎目录下的已知日志名 + 目录下其它 *.log。
		std::vector<std::wstring> files;
		auto addFile = [&files](const std::wstring& path) {
			if (path.empty()) {
				return;
			}
			for (const std::wstring& existing : files) {
				if (_wcsicmp(existing.c_str(), path.c_str()) == 0) {
					return;
				}
			}
			files.push_back(path);
		};

		if (g_options.LogPath && g_options.LogPath[0] != L'\0') {
			addFile(g_options.LogPath);
		}
		for (PCWSTR name : kEngineLogNames) {
			addFile(directory + name);
		}

		WIN32_FIND_DATAW found = {};
		HANDLE search = FindFirstFileW((directory + L"*.log").c_str(), &found);
		if (search != INVALID_HANDLE_VALUE) {
			do {
				if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
					addFile(directory + found.cFileName);
				}
			} while (FindNextFileW(search, &found));
			FindClose(search);
		}

		std::wstring text;
		text += L"==== R3ShieldCore 日志导出 ====\r\n";
		text += L"引擎目录: " + directory + L"\r\n";

		SYSTEMTIME now = {};
		GetLocalTime(&now);
		WCHAR stamp[64] = {};
		swprintf_s(stamp, _countof(stamp), L"%04u-%02u-%02u %02u:%02u:%02u",
			now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);
		text += L"导出时间: ";
		text += stamp;
		text += L"\r\n候选文件: " + std::to_wstring(files.size()) + L" 个\r\n";

		bool truncated = false;
		size_t exported = 0;
		for (const std::wstring& path : files) {
			std::string bytes;
			if (!ReadLogBytes(path.c_str(), bytes, kMaxBytesPerFile)) {
				continue;   // 不存在 / 空 / 打不开 —— 静默跳过，不占篇幅
			}
			if (bytes.size() >= kMaxBytesPerFile) {
				truncated = true;
			}

			std::wstring body = DecodeLogBytes(bytes);
			if (text.size() + body.size() > kMaxTotalChars) {
				const size_t room = (text.size() < kMaxTotalChars)
					? (kMaxTotalChars - text.size())
					: 0;
				body.resize(room);
				truncated = true;
			}

			text += L"\r\n-------- ";
			text += path;
			text += L"  (";
			text += std::to_wstring(body.size());
			text += L" 字符) --------\r\n";
			text += body;
			if (!text.empty() && text.back() != L'\n') {
				text += L"\r\n";
			}
			exported++;
		}

		if (exported == 0) {
			text += L"\r\n(没有读到任何日志文件)\r\n";
		}
		if (truncated) {
			text += L"\r\n==== [已截断] 日志总量超过 4 MB，只导出了前面部分 ====\r\n";
		}

		// 一个日志都没读到 = 没东西可带出去，按失败反馈（按钮显示「复制失败」）。
		// 否则把整段文本塞进剪贴板；塞失败（剪贴板被别的进程独占）也报失败。
		const bool ok = (exported > 0) && SetClipboardText(text.c_str());
		g_copyLogsFeedback = ok ? CopyLogsFeedback::Copied : CopyLogsFeedback::Failed;
		g_copyLogsFeedbackUntil = GetTickCount64() + 2500;
	}

	// -----------------------------------------------------------------
	// 置顶（always-on-top）：默认置顶 / 超级置顶
	// -----------------------------------------------------------------
	//
	// 默认置顶使用公开 Win32 API；超级置顶先按 KSword 的方法复制 SYSTEM
	// 主令牌并设置 TokenUIAccess，再用带该令牌的新实例调用 SetWindowBand。
	// 父实例确认子进程令牌有效后退出引擎，避免两套注入会话并存。

	bool IsCurrentProcessUiAccessEnabled()
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}
		DWORD enabled = 0;
		DWORD returned = 0;
		const bool result =
			GetTokenInformation(token, TokenUIAccess, &enabled, sizeof(enabled), &returned) != FALSE &&
			enabled != 0;
		CloseHandle(token);
		return result;
	}

	using SetWindowBandFunction = BOOL(WINAPI*)(HWND, HWND, DWORD);

	// user32!SetWindowBand 未文档化（Win7+ 都有），只能按名字取。
	SetWindowBandFunction ResolveSetWindowBand()
	{
		static SetWindowBandFunction function = [] {
			const HMODULE user32 = GetModuleHandleW(L"user32.dll");
			const FARPROC address = user32 ? GetProcAddress(user32, "SetWindowBand") : nullptr;
			return address ? reinterpret_cast<SetWindowBandFunction>(address) : nullptr;
		}();
		return function;
	}

	constexpr DWORD WindowBandDefault = 0;   // 普通波段
	constexpr DWORD WindowBandUiAccess = 2;  // UIAccess 波段（在安全桌面之上）

	// 把窗口抬到当前能拿到的最高档。
	bool ApplyHighestPermittedTopmost(HWND window, bool pinned,
		bool* uiAccessBandApplied, DWORD* bandErrorOut)
	{
		if (uiAccessBandApplied) {
			*uiAccessBandApplied = false;
		}
		if (bandErrorOut) {
			*bandErrorOut = ERROR_SUCCESS;
		}
		if (!window || !IsWindow(window)) {
			if (bandErrorOut) {
				*bandErrorOut = ERROR_INVALID_WINDOW_HANDLE;
			}
			return false;
		}

		const bool uiAccessEnabled = IsCurrentProcessUiAccessEnabled();
		DWORD bandError = uiAccessEnabled ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
		bool bandApiResolved = false;
		bool bandApplied = false;

		// 参数形状按 KSword 的实现固定为 HWND_TOPMOST/HWND_NOTOPMOST。
		if (uiAccessEnabled) {
			if (SetWindowBandFunction setWindowBand = ResolveSetWindowBand()) {
				bandApiResolved = true;
				SetLastError(ERROR_SUCCESS);
				const DWORD band = pinned ? WindowBandUiAccess : WindowBandDefault;
				bandApplied = setWindowBand(window,
					pinned ? HWND_TOPMOST : HWND_NOTOPMOST, band) != FALSE;
				bandError = bandApplied ? ERROR_SUCCESS : GetLastError();
				if (uiAccessBandApplied) {
					*uiAccessBandApplied = bandApplied;
				}
			}
			else {
				bandError = ERROR_PROC_NOT_FOUND;
			}
		}

		printf("[gui] SetWindowBand pid=%lu uiAccess=%d resolved=%d requestedBand=%lu applied=%d err=%lu\n",
			static_cast<unsigned long>(GetCurrentProcessId()),
			uiAccessEnabled ? 1 : 0,
			bandApiResolved ? 1 : 0,
			static_cast<unsigned long>(pinned ? WindowBandUiAccess : WindowBandDefault),
			bandApplied ? 1 : 0,
			static_cast<unsigned long>(bandError));
		if (bandErrorOut) {
			*bandErrorOut = bandError;
		}

		SetLastError(ERROR_SUCCESS);
		if (!SetWindowPos(window, pinned ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER)) {
			printf("[gui] SetWindowPos(%s) FAILED err=%lu\n",
				pinned ? "TOPMOST" : "NOTOPMOST",
				static_cast<unsigned long>(GetLastError()));
			return false;
		}
		if (pinned) {
			BringWindowToTop(window);
		}
		return true;
	}

	void ShowSuperTopMostFailure(DWORD errorCode)
	{
		WCHAR message[320] = {};
		const PCWSTR cause =
			errorCode == ERROR_ACCESS_DENIED || errorCode == ERROR_INVALID_PARAMETER
			? L"当前令牌的 TokenUIAccess 位存在，但 Windows 拒绝了真实 UIAccess Band；已保留普通 TOPMOST。"
			: L"请检查 SYSTEM 令牌复制、TokenUIAccess 校验和新实例启动日志。";
		swprintf_s(message, _countof(message),
			L"超级置顶未启用。当前程序没有成功进入 UIAccess 窗口 Band。\n\n"
			L"已回退到普通置顶。错误码：%lu\n\n%s",
			static_cast<unsigned long>(errorCode), cause);
		MessageBoxW(g_window, message, GuiTitle, MB_OK | MB_ICONWARNING | MB_TOPMOST);
	}

	// 超级档的周期重申：把自己抬回 TOPMOST 队首。
	//
	// ⚠️ 只用 SetWindowPos + SWP_NOACTIVATE —— 绝不 BringWindowToTop /
	//    SetForegroundWindow：那两个对顶层窗口会**激活**它，每 250ms 抢一次焦点，
	//    用户正在输入的东西会被打断（安全桌面上还可能夺走 UAC 提示的键盘输入）。
	void ReinforceSuperTopMost()
	{
		if (!g_window || !IsWindow(g_window) || !g_superTopMost) {
			return;
		}
		SetWindowPos(g_window, HWND_TOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
	}

	// 0 = 取消置顶，1 = 默认置顶，2 = 超级置顶。
	void ApplyTopMostLevel(int level)
	{
		if (!g_window) {
			return;
		}

		if (level == 0) {
			ApplyHighestPermittedTopmost(g_window, false, nullptr, nullptr);
			g_topMost = false;
			g_superTopMost = false;
			g_superBandApplied = false;
		}
		else if (level == 2) {
			// 没有 UIAccess 的实例先按 KSword 的令牌配方重启自己；
			// 新实例会带 --uiaccess-instance，避免无限重启。
			// ★ 防套娃：`--uiaccess-instance` 是**接管实例**，它绝不能再重启一次。
			//
			//   以前这里只靠 IsCurrentProcessUiAccessEnabled() 兜底 —— 一旦 win32k
			//   把子进程的 UIAccess 位清掉（它确实会，见 HANDOVER §3.10m），这个
			//   检查就失效，于是 子进程 → 孙进程 → 曾孙进程 …… **无限套娃**，
			//   每个都是完整 GUI + 完整引擎，几秒内就能把机器拖死。
			//   接管实例没拿到 UIAccess 就老实降级成普通置顶，不再重启。
			const std::wstring selfCommandLine = GetCommandLineW() ? GetCommandLineW() : L"";
			const bool isHandoffInstance =
				selfCommandLine.find(R3ShieldCoreSuperDesk::UiAccessArgument) != std::wstring::npos;
			if (!IsCurrentProcessUiAccessEnabled() && g_allowUiAccessRestart && !isHandoffInstance) {
				DWORD childPid = 0;
				DWORD error = ERROR_SUCCESS;
				if (R3ShieldCoreSuperDesk::LaunchUiAccessInstance(GetCurrentProcessId(), &childPid, &error)) {
					printf("[gui] UIAccess handoff complete child=%lu; requesting engine shutdown\n",
						static_cast<unsigned long>(childPid));
					InterlockedExchange(&g_uiAccessRestartRequest, 1);
					return;
				}
				printf("[gui] UIAccess handoff failed err=%lu; using normal TOPMOST\n",
					static_cast<unsigned long>(error));
			}

			bool bandApplied = false;
			DWORD bandError = ERROR_SUCCESS;
			if (!ApplyHighestPermittedTopmost(g_window, true, &bandApplied, &bandError)) {
				return;
			}
			g_topMost = true;
			// 与 class 相同：请求的模式保持为“超级置顶”，但单独记录
			// SetWindowBand 是否真的成功；Band 失败时仍保留普通 TOPMOST。
			g_superTopMost = true;
			g_superBandApplied = bandApplied;
			if (!bandApplied) {
				printf("[gui] super topmost band unavailable; retained standard TOPMOST err=%lu\\n",
					static_cast<unsigned long>(bandError));
			}
		}
		else {
			ApplyHighestPermittedTopmost(g_window, true, nullptr, nullptr);
			g_topMost = true;
			g_superTopMost = false;
			g_superBandApplied = false;
		}

		// ★ 超级档需要**周期重申**。
		//
		// 为什么必须重申：band 2 在本机拿不到（平台级不可达，5 组配置实测全灭，
		// 见 docs/HANDOVER.md §3.10m），所以"超级"能做的实质只剩一件事 ——
		// **反复把自己抬回 TOPMOST 队首**，把后来居上的普通 TOPMOST 窗口压下去。
		// 普通档刻意不加定时器（没这个需求，也省电）。
		if (g_window) {
			if (level == 2) {
				SetTimer(g_window, TopMostReinforceTimerId, TopMostReinforceIntervalMs, nullptr);
			}
			else {
				KillTimer(g_window, TopMostReinforceTimerId);
			}
		}

		// 留痕：置顶是窗口状态，UI 上只有一个描边颜色可断言 —— 写一行 stdout
		// 让自动化验证（以及事后排查）有个确定性的信号。
		printf("[gui] topmost level=%d (%s) uiAccess=%d bandApplied=%d panel=%d\n",
			level, level == 0 ? "off" : (level == 1 ? "normal" : "super"),
			IsCurrentProcessUiAccessEnabled() ? 1 : 0, g_superBandApplied ? 1 : 0,
			0);

		InvalidateRect(g_window, nullptr, FALSE);
	}

	void DrawModeBadge(HDC dc, int top)
	{
		PCWSTR text = L"LOG";
		COLORREF color = RGB(160, 160, 160);

		switch (static_cast<R3ShieldCore::Mode>(InterlockedCompareExchange(&g_displayMode, 0, 0))) {
		case R3ShieldCore::Mode::Block:
			text = L"BLOCK";
			color = ColorBlocked;
			break;
		case R3ShieldCore::Mode::Ask:
			text = L"ASK";
			color = ColorWouldBlock;
			break;
		case R3ShieldCore::Mode::BlockAll:
			text = L"全拦";
			color = ColorBlockAll;
			break;
		case R3ShieldCore::Mode::BlockAllSafe:
			// 用同一个破坏性配色（它同属"全拦"家族），只是文案区分。
			text = L"全拦·安全";
			color = ColorBlockAll;
			break;
		default:
			break;
		}

		// 尺寸走文件头的共用常量 —— 置顶按钮靠它右对齐，两边必须同源。
		int left = ClientWidth() - Padding - ModeBadgeWidth;

		RECT badge = { left, top, left + ModeBadgeWidth, top + ModeBadgeHeight };
		HBRUSH brush = CreateSolidBrush(color);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HPEN pen = CreatePen(PS_SOLID, 1, color);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, badge.left, badge.top, badge.right, badge.bottom, 13, 13);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

		DrawTextSimple(dc, text, badge, g_labelFont, RGB(255, 255, 255),
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	void DrawDecisionBreakdown(HDC dc, int& y, const R3ShieldCoreStats::Snapshot& snapshot)
	{
		RECT headerRect = { Padding, y, ClientWidth() - Padding, y + 20 };
		DrawTextSimple(dc, L"决策分布", headerRect, g_labelFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE);
		y += 26;

		constexpr int barLeft = Padding + 96;
		constexpr int barWidth = 240;
		const int valueLeft = barLeft + barWidth + 12;

		ULONGLONG maxValue = 0;
		for (ULONG count : snapshot.DecisionCounts) {
			if (count > maxValue) {
				maxValue = count;
			}
		}

		// ★ 4 档：Allowed / Blocked / WouldBlock / Spoofed（v67 新增 Spoofed）。
		//   `DecisionCounts` 本来就是 4 个元素（按 Decision 值索引），别写死 3。
		for (int i = 0; i < 4; i++) {
			auto decision = static_cast<R3ShieldCore::Decision>(i);
			PCWSTR label = L"?";
			switch (decision) {
			case R3ShieldCore::Decision::Allowed:
				label = L"ALLOW";
				break;
			case R3ShieldCore::Decision::Blocked:
				label = L"BLOCK";
				break;
			case R3ShieldCore::Decision::WouldBlock:
				label = L"WOULD-BLOCK";
				break;
			case R3ShieldCore::Decision::Spoofed:
				label = L"SPOOF";
				break;
			default:
				break;
			}

			RECT labelRect = { Padding, y + 4, barLeft - 8, y + 24 };
			DrawTextSimple(dc, label, labelRect, g_monoFont, ColorTextSecondary,
				DT_RIGHT | DT_SINGLELINE | DT_VCENTER);

			DrawBar(dc, barLeft, y + 6, barWidth, 14,
				snapshot.DecisionCounts[i], maxValue, DecisionColor(decision));

			RECT valueRect = { valueLeft, y + 4, ClientWidth() - Padding, y + 24 };
			std::wstring value = FormatNumber(snapshot.DecisionCounts[i]);
			DrawTextSimple(dc, value.c_str(), valueRect, g_monoFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_VCENTER);

			y += 24;
		}

		y += 12;
	}

	void DrawOpBreakdown(HDC dc, int& y, const R3ShieldCoreStats::Snapshot& snapshot, int maxRows)
	{
		RECT headerRect = { Padding, y, ClientWidth() - Padding, y + 20 };
		DrawTextSimple(dc, L"操作分布（按次数）", headerRect, g_labelFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE);

		// 图例：各类各自用**本色**画类型名，从右往左排。
		// ⚠️ 原来是一整条字符串「蓝=注册表 绿=文件 紫=进程 …」，九个条目实测约
		// 515px（g_labelFont 13px × 汉字宽），和左边的标题（20~137px）画在同一行
		// 会**叠字** —— 560px 窗口根本放不下。改成只写类型名 + 本色：
		// 又短，又不用再维护"色名"和实际柱色两套对应关系（旧文案里"蓝=注册表"
		// 本身就是错的，注册表柱一直是 ColorTextSecondary 灰）。
		//
		// ⚠️ ABI v10 后是 12 类，全部平铺实测会超出 560px 窗口宽度。
		//    这里从最小行高挤出一行显示后半段（前 6 类），或者叫用户拉宽窗口。
		//    先把图例截到窗口内：从右往左画，画到 x < 标题右缘就停。
		{
			constexpr int legendMinX = 170; // 标题「操作分布（按次数）」右缘预留
			int x = ClientWidth() - Padding;
			bool drewAny = false;
			for (int i = static_cast<int>(R3ShieldCore::ObjectType::ScheduledTask); i >= 0; i--) {
				const ULONG type = static_cast<ULONG>(i);
				PCWSTR label = ObjectTypeLabel(type);

				SIZE size = {};
				GetTextExtentPoint32W(dc, label, lstrlenW(label), &size);

				if (x - size.cx < legendMinX) {
					break;
				}

				x -= size.cx;
				RECT itemRect = { x, y, x + size.cx + 2, y + 20 };
				DrawTextSimple(dc, label, itemRect, g_labelFont, ObjectTypeColor(type),
					DT_LEFT | DT_SINGLELINE);

				x -= 8; // 条目间距
				drewAny = true;
			}
			(void)drewAny;
		}
		y += 26;

		// 收集并排序
		struct OpEntry
		{
			ULONG op;
			ULONG count;
			ULONG objectType; // R3ShieldCore::ObjectType —— 决定名字怎么翻、用什么颜色
		};

		std::vector<OpEntry> entries;
		for (ULONG i = 1; i < _countof(snapshot.OpCounts); i++) {
			if (snapshot.OpCounts[i] > 0) {
				entries.push_back({ i, snapshot.OpCounts[i],
					static_cast<ULONG>(R3ShieldCore::ObjectType::Registry) });
			}
		}

		// 文件 / 进程 / 线程 / 驱动各是另一套枚举，数值和注册表 op 会撞，
		// 所以分别收集再合并。
		auto collect = [&](const auto& counts, R3ShieldCore::ObjectType type) {
			std::vector<OpEntry> part;
			for (ULONG i = 1; i < _countof(counts); i++) {
				if (counts[i] > 0) {
					part.push_back({ i, counts[i], static_cast<ULONG>(type) });
				}
			}
			std::sort(part.begin(), part.end(),
				[](const OpEntry& a, const OpEntry& b) { return a.count > b.count; });
			return part;
		};

		std::vector<OpEntry> fileEntries = collect(snapshot.FileOpCounts, R3ShieldCore::ObjectType::File);
		std::vector<OpEntry> processEntries = collect(snapshot.ProcessOpCounts, R3ShieldCore::ObjectType::Process);
		std::vector<OpEntry> threadEntries = collect(snapshot.ThreadOpCounts, R3ShieldCore::ObjectType::Thread);
		std::vector<OpEntry> driverEntries = collect(snapshot.DriverOpCounts, R3ShieldCore::ObjectType::Driver);
		std::vector<OpEntry> networkEntries = collect(snapshot.NetworkOpCounts, R3ShieldCore::ObjectType::Network);
		std::vector<OpEntry> cameraEntries = collect(snapshot.CameraOpCounts, R3ShieldCore::ObjectType::Camera);
		std::vector<OpEntry> inputHookEntries = collect(snapshot.InputHookOpCounts, R3ShieldCore::ObjectType::InputHook);
		std::vector<OpEntry> screenEntries = collect(snapshot.ScreenOpCounts, R3ShieldCore::ObjectType::Screen);
		std::vector<OpEntry> dllLoadEntries = collect(snapshot.DllLoadOpCounts, R3ShieldCore::ObjectType::DllLoad);
		std::vector<OpEntry> clipboardEntries = collect(snapshot.ClipboardOpCounts, R3ShieldCore::ObjectType::Clipboard);
		std::vector<OpEntry> spawnEntries = collect(snapshot.SpawnOpCounts, R3ShieldCore::ObjectType::ProcessSpawn);
		std::vector<OpEntry> serviceConfigEntries = collect(snapshot.ServiceConfigOpCounts, R3ShieldCore::ObjectType::ServiceConfig);
		std::vector<OpEntry> comEntries = collect(snapshot.ComOpCounts, R3ShieldCore::ObjectType::ComHijack);
		std::vector<OpEntry> taskEntries = collect(snapshot.ScheduledTaskOpCounts, R3ShieldCore::ObjectType::ScheduledTask);

		std::sort(entries.begin(), entries.end(),
			[](const OpEntry& a, const OpEntry& b) { return a.count > b.count; });

		// 每类各保底留几个名额：只按总数排的话，文件量一大就把注册表
		// 整个挤出榜单，用户会误以为注册表监控没在工作。
		constexpr size_t PerTypeShown = 3;

		std::vector<OpEntry> merged;
		auto appendTop = [&](const std::vector<OpEntry>& source) {
			size_t n = source.size() < PerTypeShown ? source.size() : PerTypeShown;
			for (size_t i = 0; i < n; i++) {
				merged.push_back(source[i]);
			}
		};
		appendTop(entries);
		appendTop(fileEntries);
		appendTop(processEntries);
		appendTop(threadEntries);
		appendTop(driverEntries);
		appendTop(networkEntries);
		appendTop(cameraEntries);
		appendTop(inputHookEntries);
		appendTop(screenEntries);
		appendTop(dllLoadEntries);
		appendTop(clipboardEntries);
		appendTop(spawnEntries);
		appendTop(serviceConfigEntries);
		appendTop(comEntries);
		appendTop(taskEntries);

		// 合并后再按次数排一次，让"最多的操作"整体在上面。
		std::sort(merged.begin(), merged.end(),
			[](const OpEntry& a, const OpEntry& b) { return a.count > b.count; });

		if (merged.empty()) {
			RECT emptyRect = { Padding, y, ClientWidth() - Padding, y + 24 };
			DrawTextSimple(dc, L"(暂无数据)", emptyRect, g_labelFont, ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE);
			y += 34;
			return;
		}

		size_t count = merged.size() < 8 ? merged.size() : 8;
		if (static_cast<int>(count) > maxRows) {
			count = static_cast<size_t>(maxRows > 0 ? maxRows : 0);
		}
		ULONG maxCount = merged[0].count;

		constexpr int barLeft = Padding + 160;
		constexpr int barWidth = 170;
		const int valueLeft = barLeft + barWidth + 12;

		for (size_t i = 0; i < count; i++) {
			// 名字必须按来源翻：文件 op 走 FileOpName、进程走 ProcessOpName……
			// 混用的话文件事件的 op=3(Write) 会被当成注册表的 SetValueKey 显示。
			const char* rawName = R3ShieldCore::AnyOpName(merged[i].objectType, merged[i].op);

			WCHAR label[64] = {};
			MultiByteToWideChar(CP_ACP, 0, rawName, -1, label, _countof(label));

			RECT labelRect = { Padding, y + 4, barLeft - 8, y + 24 };
			DrawTextSimple(dc, label, labelRect, g_monoFont, ColorTextSecondary,
				DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			DrawBar(dc, barLeft, y + 6, barWidth, 14, merged[i].count, maxCount,
				ObjectTypeColor(merged[i].objectType));

			RECT valueRect = { valueLeft, y + 4, ClientWidth() - Padding, y + 24 };
			std::wstring value = FormatNumber(merged[i].count);
			DrawTextSimple(dc, value.c_str(), valueRect, g_monoFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_VCENTER);

			y += 24;
		}

		y += 12;
	}

	void DrawTopProcesses(HDC dc, int& y, const R3ShieldCoreStats::Snapshot& snapshot, int maxRows)
	{
		RECT headerRect = { Padding, y, ClientWidth() - Padding, y + 20 };
		DrawTextSimple(dc, L"触发最多的进程", headerRect, g_labelFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE);
		y += 26;

		if (snapshot.TopProcesses.empty() || maxRows <= 0) {
			RECT emptyRect = { Padding, y, ClientWidth() - Padding, y + 24 };
			DrawTextSimple(dc, L"(暂无数据)", emptyRect, g_labelFont, ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE);
			y += 34;
			return;
		}

		ULONG maxTotal = snapshot.TopProcesses.front().Total;
		constexpr int barLeft = Padding + 220;
		constexpr int barWidth = 150;
		const int valueLeft = barLeft + barWidth + 12;

		size_t count = snapshot.TopProcesses.size() < 6 ? snapshot.TopProcesses.size() : 6;
		if (static_cast<int>(count) > maxRows) {
			count = static_cast<size_t>(maxRows);
		}
		for (size_t i = 0; i < count; i++) {
			const auto& process = snapshot.TopProcesses[i];

			std::wstring name = process.Name.empty()
				? (L"PID " + std::to_wstring(process.ProcessId))
				: (process.Name + L" (" + std::to_wstring(process.ProcessId) + L")");

			RECT labelRect = { Padding, y + 4, barLeft - 8, y + 24 };
			DrawTextSimple(dc, name.c_str(), labelRect, g_monoFont, ColorTextSecondary,
				DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			// 被拦的部分用红色叠在上面，一眼看出"谁被拦得最多"。
			COLORREF color = process.Blocked > 0 ? ColorBlocked : ColorAccent;
			DrawBar(dc, barLeft, y + 6, barWidth, 14, process.Total, maxTotal, color);

			RECT valueRect = { valueLeft, y + 4, ClientWidth() - Padding, y + 24 };
			std::wstring value = FormatNumber(process.Total);
			if (process.Blocked > 0) {
				value += L"  (拦 " + FormatNumber(process.Blocked) + L")";
			}

			DrawTextSimple(dc, value.c_str(), valueRect, g_monoFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			y += 24;
		}

		y += 12;
	}

	void DrawPromptSummary(HDC dc, int clientHeight, const R3ShieldCoreStats::Snapshot& snapshot)
	{
		// 贴底绘制。用真实客户区高度而不是窗口常量 —— 标题栏会吃掉几十像素，
		// 用窗口常量会让这一栏跑到可视区外面去。
		const int top = clientHeight - PromptSummaryHeight();

		RECT separator = { Padding, top, ClientWidth() - Padding, top + 1 };
		HBRUSH brush = CreateSolidBrush(ColorBorder);
		FillRect(dc, &separator, brush);
		DeleteObject(brush);

		// 询问统计记在 DLL 侧（弹窗发生在被注入进程的 hook 里），
		// 由主循环读回来后推给 R3ShieldCoreStats，这里只读快照。
		R3ShieldCoreStats::PromptStat prompt = R3ShieldCoreStats::GetPromptStat();

		const R3ShieldCore::Mode mode =
			static_cast<R3ShieldCore::Mode>(InterlockedCompareExchange(&g_displayMode, 0, 0));

		WCHAR text[512] = {};
		if (mode == R3ShieldCore::Mode::BlockAll) {
			// v21 起全拦模式的进程创建 / 远程线程 / 跨进程内存改为**弹窗询问**，
			// 文案必须跟着改 —— 再说"一律拒绝"就是骗用户了。
			swprintf_s(text,
				L"⚠ 完全拦截：其余一律拒绝；进程创建 / 远程线程 / 跨进程内存改为弹窗   ·   询问 %u 允许 %u 拒绝 %u   ·   丢弃 %u 条",  // gbk-ok：本行只经 GDI DrawTextW 绘制，从不经 WideCharToMultiByte(CP_ACP)
				prompt.Shown, prompt.Allowed, prompt.Denied, snapshot.DroppedEvents);
		}
		else if (mode == R3ShieldCore::Mode::BlockAllSafe) {
			// 与 BlockAll 的唯一区别：可信来源的进程创建直接放行（不弹窗）。
			swprintf_s(text,
				L"⚠ 完全拦截·安全：可信来源的进程创建直接放行；其余一律拒绝，远程线程 / 跨进程内存弹窗   ·   询问 %u 允许 %u 拒绝 %u   ·   丢弃 %u 条",  // gbk-ok：本行只经 GDI DrawTextW 绘制，从不经 WideCharToMultiByte(CP_ACP)
				prompt.Shown, prompt.Allowed, prompt.Denied, snapshot.DroppedEvents);
		}
		else if (mode == R3ShieldCore::Mode::Ask) {
			swprintf_s(text,
				L"询问  %u 次   ·   允许 %u   ·   拒绝 %u   ·   超时 %u",
				prompt.Shown, prompt.Allowed, prompt.Denied, prompt.TimedOut);
		}
		else if (mode == R3ShieldCore::Mode::Block) {
			swprintf_s(text, L"BLOCK：普通行为放行并记录 · 高置信度高危行为直接拦截 · 不弹窗   ·   丢弃 %u 条",
				snapshot.DroppedEvents);
		}
		else {
			if (g_options.HighRisk) {
				// 同上：LOG 下高危也只是记录（WouldBlock），不弹窗、不拦。
				swprintf_s(text, L"LOG：只记录、全部放行   ·   高危也只记录（要拦请切 BLOCK / ASK）   ·   丢弃 %u 条",
					snapshot.DroppedEvents);
			}
			else {
				swprintf_s(text, L"LOG：只记录、全部放行（高危规则已关）   ·   丢弃事件 %u 条",
					snapshot.DroppedEvents);
			}
		}

		const int width = ClientWidth();
		int rowTop = top + 8;

		RECT rect = { Padding, rowTop, width - Padding, rowTop + 22 };
		DrawTextSimple(dc, text, rect, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
		rowTop += PromptSummaryRowHeight;

		// 高危统计单独一行，用警示色 —— 这是用户最该关注的一个数字。
		if (g_options.HighRisk) {
			WCHAR riskText[256] = {};
			swprintf_s(riskText, L"高危命中  %u 次   ·   高危被拒 %u 次",
				snapshot.HighRiskEvents, prompt.HighRiskBlocked);

			RECT riskRect = { Padding, rowTop, width - Padding, rowTop + 22 };
			DrawTextSimple(dc, riskText, riskRect, g_labelFont,
				snapshot.HighRiskEvents > 0 ? ColorHighRisk : ColorTextSecondary,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
			rowTop += PromptSummaryRowHeight;
		}

		//
		// ★ v61：高危进程提示（第三行）。
		//
		// ⚠️ 这一行与上面「高危命中」是**两回事**，别混：
		//   · 上面那个数来自**被注入进程的 hook** —— 只看得见"被监控进程
		//     发起、且落在引擎观测窗内"的创建。
		//   · 这一行来自**引擎自己的全机进程快照** —— 不依赖注入覆盖，
		//     也不依赖观测窗（引擎启动前就在跑的进程一样能看见）。
		//
		// ⚠️ 「0 个」必须带上「已扫描 N 轮」：否则"扫了但没发现"与
		//    "根本没在扫"在界面上长得一模一样（铁律 97）。
		//
		if (g_options.HighRiskProcessAlert != 0) {
			const R3ShieldCoreStats::ProcWatchStat watch = R3ShieldCoreStats::GetProcWatchStat();

			WCHAR watchText[512] = {};
			if (watch.HighRiskFound > 0) {
				swprintf_s(watchText,
					L"⚠ 高危进程  %u 个   ·   最近 %s (pid %u)   ·   %s",  // gbk-ok：本行只经 GDI DrawTextW 绘制，从不经 WideCharToMultiByte(CP_ACP)
					watch.HighRiskFound,
					watch.LatestName.empty() ? L"(未知)" : watch.LatestName.c_str(),
					watch.LatestPid,
					watch.LatestReason.empty() ? L"" : watch.LatestReason.c_str());
			}
			else {
				swprintf_s(watchText,
					L"高危进程  0 个   ·   已扫描 %u 轮（最近一轮 %u 个进程）",
					watch.Scans, watch.LastScanProcesses);
			}

			RECT watchRect = { Padding, rowTop, width - Padding, rowTop + 22 };
			DrawTextSimple(dc, watchText, watchRect, g_labelFont,
				watch.HighRiskFound > 0 ? ColorHighRisk : ColorTextSecondary,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
	}

	void DrawPanel(HDC dc, RECT rect, PCWSTR title)
	{
		// ★ v83：面板的**外观**现在由玻璃层负责（背景模糊 + 圆角 SDF + 边缘折射
		//   + 色散 + rim + 顶光 + 噪点 + 投影），这里只做两件事：
		//   ① 把矩形登记给玻璃层（它会在**下一帧**按这张表合成）；
		//   ② 画标题文字（内容层，每帧都画，压在玻璃上）。
		//
		// ★★ 为什么"登记"而不是"当场画"：玻璃层必须在内容**之前**合成好，
		//   而面板矩形要到绘制过程中才知道 ⇒ 见 ui_material.h 里
		//   GlassSurface::CommitPanels 的"两帧收敛"说明。
		//
		// ★ 玻璃不可用（R3SHIELDCORE_GLASS=off / 建缓冲失败）时退回原来的不透明画法
		//   —— 这条兜底路径必须保留：现场一键回退靠它（不是可选项）。
		if (g_glass.active) {
			const R3ShieldCoreUi::GlassTheme& th = R3ShieldCoreUi::DefaultTheme();
			g_glass.AddPanel(rect.left, rect.top, rect.right, rect.bottom,
				th.panelRadius * GlassDpiScale(g_window), th.tintIdle);
		} else {
			// ---- 兜底：不透明卡片（v82 及之前的外观）----
			RECT shadow = { rect.left + 1, rect.top + 3, rect.right + 1, rect.bottom + 3 };
			HBRUSH shadowBrush = CreateSolidBrush(RGB(220, 231, 242));
			HGDIOBJ oldBrush = SelectObject(dc, shadowBrush);
			HGDIOBJ oldPen = SelectObject(dc, GetStockObject(NULL_PEN));
			RoundRect(dc, shadow.left, shadow.top, shadow.right, shadow.bottom, 18, 18);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(shadowBrush);

			HBRUSH brush = CreateSolidBrush(RGB(250, 253, 255));
			HPEN pen = CreatePen(PS_SOLID, 1, ColorBorder);
			oldBrush = SelectObject(dc, brush);
			oldPen = SelectObject(dc, pen);
			RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 18, 18);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(brush);
			DeleteObject(pen);

			HPEN rim = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));
			oldPen = SelectObject(dc, rim);
			MoveToEx(dc, rect.left + 18, rect.top + 1, nullptr);
			LineTo(dc, rect.right - 18, rect.top + 1);
			SelectObject(dc, oldPen);
			DeleteObject(rim);
		}

		RECT titleRect = { rect.left + 16, rect.top + 12, rect.right - 16, rect.top + 34 };
		DrawTextSimple(dc, title, titleRect, g_labelFont, ColorTextPrimary,
			DT_LEFT | DT_SINGLELINE);
	}

	void DrawProcessPage(HDC dc, const RECT& client)
	{
		const R3ShieldCoreStats::Snapshot snapshot = R3ShieldCoreStats::GetSnapshot();
		const int left = Padding;
		const int right = client.right - Padding;
		const int top = TabBarTop + TabBarHeight + 18;

		struct Metric { PCWSTR label; std::wstring value; COLORREF color; };
		const ULONG blocked = snapshot.BlockedByUs;
		Metric metrics[4] = {
			{ L"活动进程", FormatNumber(snapshot.UniqueProcesses), ColorProcessAccent },
			{ L"最近 1 秒", FormatNumber(snapshot.LastSecondEvents), ColorAccent },
			{ L"已拦截", FormatNumber(blocked), blocked ? ColorBlocked : ColorTextSecondary },
			{ L"丢弃事件", FormatNumber(snapshot.DroppedEvents), snapshot.DroppedEvents ? ColorWouldBlock : ColorTextSecondary },
		};

		const int cardGap = 12;
		const int cardWidth = (right - left - cardGap * 3) / 4;
		for (int i = 0; i < 4; ++i) {
			RECT card = { left + i * (cardWidth + cardGap), top,
				left + i * (cardWidth + cardGap) + cardWidth, top + 82 };
			DrawPanel(dc, card, metrics[i].label);
			RECT value = { card.left + 16, card.top + 38, card.right - 16, card.bottom - 12 };
			DrawTextSimple(dc, metrics[i].value.c_str(), value, g_valueFont, metrics[i].color,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		const int tableTop = top + 104;
		RECT panel = { left, tableTop, right, client.bottom - PromptSummaryHeight() - 12 };
		DrawPanel(dc, panel, L"进程活动明细");

		const int headerTop = tableTop + 44;
		const int colProcess = left + 16;
		const int colPid = left + 300;
		const int colEvents = left + 390;
		const int colBlocked = left + 490;
		const int colWould = left + 585;
		const int colPath = left + 700;
		const int rowHeight = 30;
		DrawTextSimple(dc, L"进程", { colProcess, headerTop, colPid - 8, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"PID", { colPid, headerTop, colEvents - 8, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"事件", { colEvents, headerTop, colBlocked - 8, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"拦截", { colBlocked, headerTop, colWould - 8, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"拟拦截", { colWould, headerTop, colPath - 8, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"镜像路径", { colPath, headerTop, right - 16, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

		const int rowsTop = headerTop + 28;
		const int available = panel.bottom - rowsTop - 12;
		const int maxRows = available > 0 ? available / rowHeight : 0;
		const int count = static_cast<int>(snapshot.TopProcesses.size()) < maxRows
			? static_cast<int>(snapshot.TopProcesses.size()) : maxRows;
		for (int i = 0; i < count; ++i) {
			const auto& process = snapshot.TopProcesses[static_cast<size_t>(i)];
			const int rowTop = rowsTop + i * rowHeight;
			if (i % 2 == 1) {
				RECT stripe = { left + 8, rowTop - 4, right - 8, rowTop + rowHeight - 4 };
				HBRUSH stripeBrush = CreateSolidBrush(ColorLogRowAlt);
				FillRect(dc, &stripe, stripeBrush);
				DeleteObject(stripeBrush);
			}

			std::wstring name = process.Name.empty()
				? (L"PID " + std::to_wstring(process.ProcessId)) : process.Name;
			DrawTextSimple(dc, name.c_str(), { colProcess, rowTop, colPid - 8, rowTop + 20 },
				g_monoFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			DrawTextSimple(dc, std::to_wstring(process.ProcessId).c_str(),
				{ colPid, rowTop, colEvents - 8, rowTop + 20 }, g_monoFont,
				ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
			DrawTextSimple(dc, FormatNumber(process.Total).c_str(),
				{ colEvents, rowTop, colBlocked - 8, rowTop + 20 }, g_monoFont,
				ColorTextPrimary, DT_LEFT | DT_SINGLELINE);
			DrawTextSimple(dc, FormatNumber(process.Blocked).c_str(),
				{ colBlocked, rowTop, colWould - 8, rowTop + 20 }, g_monoFont,
				process.Blocked ? ColorBlocked : ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
			DrawTextSimple(dc, FormatNumber(process.WouldBlock).c_str(),
				{ colWould, rowTop, colPath - 8, rowTop + 20 }, g_monoFont,
				process.WouldBlock ? ColorWouldBlock : ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
			const std::wstring path = process.Path.empty() ? L"(路径未解析)" : process.Path;
			DrawTextSimple(dc, path.c_str(), { colPath, rowTop, right - 16, rowTop + 20 },
				g_monoFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_PATH_ELLIPSIS);
		}

		if (count == 0) {
			DrawTextSimple(dc, L"(暂无进程事件)", { colProcess, rowsTop, right - 16, rowsTop + 24 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		}
	}

	std::wstring FormatLogTime(LONG64 fileTime)
	{
		FILETIME utc = {};
		utc.dwLowDateTime = static_cast<DWORD>(fileTime & 0xFFFFFFFF);
		utc.dwHighDateTime = static_cast<DWORD>(fileTime >> 32);

		FILETIME local = {};
		SYSTEMTIME time = {};
		if (!FileTimeToLocalFileTime(&utc, &local) || !FileTimeToSystemTime(&local, &time)) {
			return L"--:--:--";
		}

		WCHAR buffer[16] = {};
		swprintf_s(buffer, L"%02u:%02u:%02u", time.wHour, time.wMinute, time.wSecond);
		return buffer;
	}

	// =================================================================
	// ★ v62：ARK 页（全机进程列表 + 四种处置）
	// =================================================================
	//
	// 与「进程」页（页签 2）的区别 —— 这就是加这一页的全部理由：
	//
	//   「进程」页的数据来自 `R3ShieldCoreStats`，是**事件聚合**：
	//   只有"产生过事件"的进程才会出现在那里，而"有没有事件"取决于
	//   注入覆盖（`never_inject` / 位数 / 权限）与观测窗（引擎启动之后）。
	//   ⇒ 一个没被注入的进程，在那一页上**根本不存在**。
	//
	//   ARK 页的数据来自 `CreateToolhelp32Snapshot`：**全机**进程，
	//   不受注入覆盖影响，受保护进程（PPL）也在列表里。
	//
	// -----------------------------------------------------------------
	// 安全边界（与 ark_actions.h 同一套，界面这一层要**显式表达**）
	// -----------------------------------------------------------------
	//   · 引擎自己：三个动作全拒（按钮置灰 + 写明原因）。
	//   · 关键系统进程：三个动作全拒（红字标"结束会蓝屏 / 挂起会卡死"）。
	//   · 普通系统进程（svchost / explorer …）：**允许** ——
	//     界面上"系统进程"与"关键进程"分成两列，就是这条边界的体现。
	//   · 「强制结束」需要**二次确认**（第一次点变成"确认…"，再点才执行）：
	//     它是唯一**不可撤销**的动作（内核直接拆地址空间，目标跑不到
	//     任何清理），而且进程一没，用户在界面上连"我干了什么"都看不到。
	//
	// -----------------------------------------------------------------
	// 布局：一个函数同时喂绘制与命中测试
	// -----------------------------------------------------------------
	//   ★ 坐标只算一次。绘制和命中各自算一遍的写法迟早会漂移，
	//     而漂移的症状是"按钮画在这儿、点在那儿"——很难查，且
	//     在自绘界面里没有任何系统控件帮你兜底。

	enum ArkButton
	{
		ArkButtonNone = -1,
		ArkButtonSuspend = 0,
		ArkButtonResume = 1,
		ArkButtonInternalExit = 2,
		ArkButtonForceKill = 3,
		ArkButtonCount = 4,
	};

	constexpr int ArkRowHeight = 22;
	constexpr int ArkDetailWidth = 336;
	constexpr int ArkEventsHeight = 104;
	constexpr int ArkButtonHeight = 28;

	struct ArkLayout
	{
		int Left = 0, Right = 0;
		int SummaryTop = 0;
		int MainTop = 0, MainBottom = 0;
		int TableLeft = 0, TableRight = 0;
		int DetailLeft = 0, DetailRight = 0;
		int RowsTop = 0;
		int MaxRows = 0;
		int EventsTop = 0, EventsBottom = 0;
		bool HasEvents = false;
		RECT Buttons[ArkButtonCount] = {};
	};

	ArkLayout ArkLayoutFor(const RECT& client)
	{
		ArkLayout layout = {};
		layout.Left = Padding;
		layout.Right = client.right - Padding;
		layout.SummaryTop = TabBarTop + TabBarHeight + 12;
		layout.MainTop = layout.SummaryTop + 26;

		const int contentBottom = client.bottom - PromptSummaryHeight() - 10;

		// 底部"最近事件"横条**自适应**：窗口矮的时候先压它。
		// 进程表才是这一页的主体，它必须永远有地方 —— 写死高度会让
		// 最小窗口下表格只剩两三行，甚至被横条盖住。
		constexpr int mainMinHeight = 232;
		int eventsHeight = ArkEventsHeight;
		const int available = contentBottom - layout.MainTop;
		if (available - eventsHeight - 10 < mainMinHeight) {
			eventsHeight = available - 10 - mainMinHeight;
		}
		layout.HasEvents = eventsHeight >= 62;
		if (!layout.HasEvents) {
			eventsHeight = 0;
		}

		layout.MainBottom = contentBottom - (layout.HasEvents ? eventsHeight + 10 : 0);
		layout.EventsTop = layout.MainBottom + 10;
		layout.EventsBottom = contentBottom;

		layout.TableLeft = layout.Left;
		layout.TableRight = layout.Right - ArkDetailWidth - 12;
		layout.DetailLeft = layout.TableRight + 12;
		layout.DetailRight = layout.Right;

		// 面板标题 34 + 表头 26
		layout.RowsTop = layout.MainTop + 34 + 26;
		const int rowsAvailable = layout.MainBottom - layout.RowsTop - 10;
		layout.MaxRows = rowsAvailable > 0 ? rowsAvailable / ArkRowHeight : 0;

		// 四个按钮贴明细面板**底部**（不随文本行数浮动）。
		const int innerWidth = ArkDetailWidth - 16 * 2;
		const int buttonWidth = (innerWidth - 8) / 2;
		const int buttonTop = layout.MainBottom - 12 - (ArkButtonHeight * 2 + 8);
		for (int i = 0; i < ArkButtonCount; i++) {
			const int column = i % 2;
			const int row = i / 2;
			const int left = layout.DetailLeft + 16 + column * (buttonWidth + 8);
			const int top = buttonTop + row * (ArkButtonHeight + 8);
			layout.Buttons[i] = { left, top, left + buttonWidth, top + ArkButtonHeight };
		}

		return layout;
	}

	std::wstring FormatBytes(ULONGLONG bytes)
	{
		WCHAR buffer[64] = {};
		if (bytes >= 1024ULL * 1024ULL * 1024ULL) {
			swprintf_s(buffer, L"%.2f GB",
				static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
		}
		else if (bytes >= 1024ULL * 1024ULL) {
			swprintf_s(buffer, L"%.1f MB",
				static_cast<double>(bytes) / (1024.0 * 1024.0));
		}
		else {
			swprintf_s(buffer, L"%.0f KB", static_cast<double>(bytes) / 1024.0);
		}
		return buffer;
	}

	// 拉取快照 + 选中项的最近事件。按时间节流。
	//
	// 节流而不是"每次重绘都拉"：鼠标一移动就 InvalidateRect，
	// 而每次快照要复制几百行（每行两个 wstring）—— 那样光鼠标划过
	// 就能把 GUI 线程烧满。
	//
	// ★ v63：节流阈值由 `ark_refresh_ms` 配置决定（原来是写死的 400）。
	//   取不到配置时退回 1000 —— **不**退回 0，否则等于关掉节流。
	ULONG ArkRefreshIntervalMs()
	{
		return g_options.ArkRefreshMs ? g_options.ArkRefreshMs : 1000;
	}

	void RefreshArkCache(bool force = false)
	{
		const ULONGLONG now = GetTickCount64();
		if (!force && g_arkFetchedMs != 0
			&& (now - g_arkFetchedMs) < ArkRefreshIntervalMs()) {
			return;
		}
		g_arkFetchedMs = now;

		g_arkSnapshot = R3ShieldCoreArk::GetSnapshot();

		// 选中项可能已经消失（进程退了）—— 保留 pid 但界面显示"已不存在"，
		// 不自动改选。自动改选会让用户"刚点中的行跳走"。
		if (g_arkEventsPid != g_arkSelectedPid
			|| g_arkFetchedScans != g_arkSnapshot.Stat.Scans) {
			g_arkEventsPid = g_arkSelectedPid;
			g_arkEvents = g_arkSelectedPid >= 0
				? R3ShieldCoreStats::GetLogsForPid(static_cast<ULONG>(g_arkSelectedPid), 32)
				: std::vector<R3ShieldCoreStats::LogEntry>();
		}
		g_arkFetchedScans = g_arkSnapshot.Stat.Scans;

		// 动作记录：Serial 变了才重取（它只由主循环写）。
		const std::vector<R3ShieldCoreArk::ActionRecord> latest = R3ShieldCoreArk::GetRecentActions();
		if (!latest.empty() && latest.front().Serial != g_arkActionsSerial) {
			g_arkActionsSerial = latest.front().Serial;
			g_arkActions = latest;
		}
		else if (latest.empty()) {
			g_arkActions.clear();
			g_arkActionsSerial = 0;
		}
	}

	// ★ v62：ARK 动作自检 —— `R3SHIELDCORE_ARK_ACTION=<pid>:<动作号>`。
	//
	// 为什么必须留这么一个开关（**不是**开发时的临时补丁）：
	//
	//   ARK 的四个动作按钮是**自绘**的（没有控件句柄），而且引擎窗口是提权的
	//   —— 自动化点击既过不了 UIPI（铁律 74），也点不准（坐标随客户区大小变，
	//   见 ArkLayoutFor）。没有它，"界面线程 → RequestAction → 队列 →
	//   主循环 Tick → ArkActions::Perform"这条链就只能靠人眼点一下才算验过，
	//   而人眼在本项目里已经出过假绿（铁律 24/28）。
	//
	// 它走的是**和按钮完全同一条路**（`R3ShieldCoreArk::RequestAction`），
	// 只少了鼠标那一环 —— 而那一环（WM_LBUTTONUP → PerformArkAction）
	// 的正确性由 `ArkButtonEnabled` / `HitTestArkButton` 的纯判据保证。
	//
	// ⚠️ 只在**快照真的启动之后**才发（本函数被 `DrawArkPage` 调，
	//    而 `DrawArkPage` 一定在 `R3ShieldCoreArk::Start` 之后才可能被画到）：
	//    早发会被 `RequestAction` 的 `g_initialized` 闸门静默丢掉 ——
	//    那样探针看到的是"什么都没发生"，而真相是"发得太早"。
	void TryArkActionSelfTest()
	{
		static bool fired = false;
		if (fired) {
			return;
		}

		wchar_t text[64] = {};
		const DWORD length = GetEnvironmentVariableW(L"R3SHIELDCORE_ARK_ACTION", text,
			_countof(text));
		if (length == 0 || length >= _countof(text)) {
			// 正常用户运行走这里：不设这个环境变量就没有任何额外开销。
			return;
		}

		// ★ 自检**不能**依赖"页面被画到"。
		//
		// v62 第一次跑端到端探针时踩到：探针用 `-WindowStyle Minimized` 起引擎，
		// 而**最小化窗口永远收不到 WM_PAINT** ⇒ DrawArkPage 从没被调用
		// ⇒ 自检没发 ⇒ 动作没执行 ⇒ 日志里既没有 [ark-selftest] 也没有
		// [ark] 动作行。而"页面没画"和"功能没生效"在日志里长得一模一样
		// （铁律 97：布尔判定 = 不可诊断）。
		//
		// 修法：快照自己拉（只在还没 Started 时才拉，避免正常运行时
		// 让定时器白白多拉快照），并由 WM_TIMER 一起驱动 —— 定时器
		// 与窗口可见性无关，WM_PAINT 不是。
		if (!g_arkSnapshot.Stat.Started) {
			RefreshArkCache();
			if (!g_arkSnapshot.Stat.Started) {
				return;   // 引擎还没起来，下一个 tick 再来
			}
		}

		unsigned pid = 0;
		unsigned action = 0;
		if (swscanf_s(text, L"%u:%u", &pid, &action) != 2
			|| action >= static_cast<unsigned>(R3ShieldCoreArk::ActionCount)) {
			printf("[ark-selftest] R3SHIELDCORE_ARK_ACTION 格式不对（应为 <pid>:<0..3>）：%ls\n",
				text);
			fflush(stdout);
			fired = true;
			return;
		}

		fired = true;
		g_arkSelectedPid = static_cast<int>(pid);
		printf("[ark-selftest] 界面线程发出动作请求 pid=%u 动作=%ls\n",
			pid, R3ShieldCoreArk::ActionText(action));
		fflush(stdout);
		R3ShieldCoreArk::RequestAction(pid, action);
	}

	const R3ShieldCoreArk::Row* FindArkRow(int pid)
	{
		for (const R3ShieldCoreArk::Row& row : g_arkSnapshot.Rows) {
			if (static_cast<int>(row.Pid) == pid) {
				return &row;
			}
		}
		return nullptr;
	}

	// 某个动作按钮是否可用。理由与"为什么不可用"要能对上 ——
	// 置灰的按钮必须能在明细区看到原因，否则用户只会觉得"按钮坏了"。
	bool ArkButtonEnabled(int index)	{
		const R3ShieldCoreArk::Row* row = FindArkRow(g_arkSelectedPid);
		if (!row) {
			return false;
		}
		const bool self = (row->Pid == g_arkSnapshot.Stat.SelfPidOfEngine);
		if (self || row->IsCritical) {
			return false;
		}

		switch (index) {
		case ArkButtonSuspend:
			return !row->SuspendedByArk;
		case ArkButtonResume:
			return row->SuspendedByArk;
		case ArkButtonInternalExit:
			return g_arkSnapshot.Stat.SelfExitSupported;
		case ArkButtonForceKill:
			return true;
		default:
			return false;
		}
	}

	PCWSTR ArkButtonLabel(int index)
	{
		switch (index) {
		case ArkButtonSuspend: return L"挂起";
		case ArkButtonResume: return L"恢复";
		case ArkButtonInternalExit: return L"内部退出";
		case ArkButtonForceKill: return L"强制结束";
		default: return L"";
		}
	}

	int HitTestArkButton(POINT point, const RECT& client)
	{
		if (g_activeTab != 4) {
			return ArkButtonNone;
		}
		const ArkLayout layout = ArkLayoutFor(client);
		for (int i = 0; i < ArkButtonCount; i++) {
			RECT rect = layout.Buttons[i];
			if (PtInRect(&rect, point)) {
				return i;
			}
		}
		return ArkButtonNone;
	}

	void DrawArkButton(HDC dc, const RECT& rect, PCWSTR label, bool enabled,
		bool hovered, bool pressed, bool danger)
	{
		COLORREF fill = ColorHeaderBackground;
		COLORREF border = ColorBorder;
		COLORREF text = ColorTextPrimary;

		if (!enabled) {
			fill = ColorLogRowAlt;
			text = RGB(170, 170, 170);
		}
		else if (danger) {
			fill = pressed ? RGB(150, 30, 34) : (hovered ? RGB(198, 48, 52) : ColorBlocked);
			border = fill;
			text = RGB(255, 255, 255);
		}
		else if (pressed) {
			fill = RGB(200, 222, 244);
			border = ColorAccent;
			text = ColorAccent;
		}
		else if (hovered) {
			fill = ColorTabHoverBg;
			border = ColorTabHoverBorder;
			text = ColorAccent;
		}

		// ★ v83：ARK 页 / 「高级」跳转页的按钮也走玻璃片。
		//   禁用态**不加玻璃**（一块"什么都没写"的玻璃看起来像可点的按钮，
		//   而禁用必须一眼看出"点不动"），危险动作靠**红字 + 红下划线**表达。
		if (g_glass.active) {
			if (enabled) {
				float tint = 0.16f;
				if (hovered) { tint = 0.24f; }
				if (pressed) { tint = 0.32f; }
				g_glass.AddPanel(rect.left, rect.top, rect.right, rect.bottom, 8.0f, tint, 1);
				RECT underline = { rect.left + 10, rect.bottom - 3, rect.right - 10, rect.bottom - 2 };
				HBRUSH ub = CreateSolidBrush(danger ? ColorBlocked : ColorAccent);
				FillRect(dc, &underline, ub);
				DeleteObject(ub);
			}
			text = enabled ? (danger ? ColorBlocked : (hovered || pressed ? ColorAccent : ColorTextPrimary))
				: RGB(170, 170, 170);
		} else {
			HBRUSH brush = CreateSolidBrush(fill);
			HPEN pen = CreatePen(PS_SOLID, 1, border);
			HGDIOBJ oldBrush = SelectObject(dc, brush);
			HGDIOBJ oldPen = SelectObject(dc, pen);
			RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 6, 6);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(brush);
			DeleteObject(pen);
		}

		DrawTextSimple(dc, label, rect, g_labelFont, text,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	void DrawArkPage(HDC dc, const RECT& client)
	{
		RefreshArkCache();
		TryArkActionSelfTest();

		const ArkLayout layout = ArkLayoutFor(client);
		const R3ShieldCoreArk::Stats& stat = g_arkSnapshot.Stat;
		const R3ShieldCoreArk::Row* selected = FindArkRow(g_arkSelectedPid);

		// ★ v62：证明"这一页**真的被画到了**"。
		//
		// 为什么值得单开一行日志：ARK 的动作链是
		//   界面线程 → RequestAction → 队列 → 主循环 Tick → ArkActions::Perform
		// 而"界面线程"那一环在 v62 的第一版实现里只由**本函数**驱动。
		// 于是"页面没被画到"和"动作没生效"在日志里长得一模一样
		// （铁律 97）。加这一行之后，探针能把两者分开：
		//   有 `页面已绘制` 没 `[ark-selftest]` ⇒ 界面画了、但环境变量没进来；
		//   两个都没有                        ⇒ 界面根本没画（例如窗口最小化）。
		//
		// ★ v63：三个分组的实际条数。
		//   直接数 `row.Group`，**不**从 `Stats` 的 SystemCount / InjectedCount
		//   反推 —— 反推要额外处理"既是系统进程、又被注入"的重叠，
		//   很容易算错；而列表本来就已经按分组排好了，数一遍是最不容易错的。
		ULONG groupCounts[3] = {};
		for (const R3ShieldCoreArk::Row& row : g_arkSnapshot.Rows) {
			if (row.Group < 3) {
				groupCounts[row.Group]++;
			}
		}

		// 打两行就够：首次绘制（证明能画）+ 首次带活快照的绘制（证明数据到了）。
		//
		// ★ v63 修正：第二个判据原来是 `stat.Started`，那是**错的**，而且错得
		//   很隐蔽 —— 它让"第二行"永远打不出来：
		//     `Started` 在**第一次绘制时就已经是 true**（模块初始化早于首轮扫描
		//     完成），而首轮扫描要 1 秒以上、首帧在 ~300ms 就画了。
		//     ⇒ 首帧同时满足 `!paintedOnce` 和 `!paintedLive && stat.Started`，
		//       闩锁当场关死，之后再画多少次都不再打印。
		//     ⇒ 日志里只剩 `行数=0 已扫描=0` 那一条，于是"ARK 分组到底有没有
		//       跑起来"根本无从判断；探针拿它做断言就只会得到 0+0+0==0 的
		//       空真结论（铁律 97/108：用来证明"数据到了"的诊断，结构上
		//       不可能证明它）。
		//   改成按**已完成过一次扫描**（`stat.Scans > 0`）判定：首帧必为 0，
		//   扫描完成后必 >0，第二个判据才真的在说"活快照到了"。
		{
			static bool paintedOnce = false;
			static bool paintedLive = false;
			const bool live = stat.Scans > 0;
			if (!paintedOnce || (!paintedLive && live)) {
				paintedOnce = true;
				paintedLive = paintedLive || live;
				printf("[ark] 页面已绘制 行数=%u 已启动=%d 已扫描=%u 已挂起=%u "
					"选中=%d 客户区=%dx%d 分组=%u/%u/%u 刷新=%ums\n",
					static_cast<unsigned>(g_arkSnapshot.Rows.size()),
					stat.Started ? 1 : 0,
					static_cast<unsigned>(stat.Scans),
					static_cast<unsigned>(stat.SuspendedCount),
					g_arkSelectedPid, static_cast<int>(client.right),
					static_cast<int>(client.bottom),
					static_cast<unsigned>(groupCounts[0]),
					static_cast<unsigned>(groupCounts[1]),
					static_cast<unsigned>(groupCounts[2]),
					static_cast<unsigned>(ArkRefreshIntervalMs()));
				fflush(stdout);
			}
		}

		// ---------------- 第 1 行：摘要 ----------------
		{
			std::wstring summary;
			if (!stat.Started) {
				// ★ 三态要分开报（铁律 97）：
				//   未启动 / 启动但被配置关掉 / 已启用 —— 三种都显示"空的列表"
				//   的话，用户根本分不清该去改配置还是该等一等。
				summary = L"ARK 尚未启动（引擎正在初始化）—— 列表暂时为空。";
			}
			else if (!stat.Enabled) {
				summary = L"ARK 未启用（r3shieldcore.ini 里 ark_enabled=0）—— 列表不刷新、动作不可用。";
			}
			else {
				WCHAR buffer[512] = {};
				// ★ v63：摘要里报**分组条数**（列表就是按这个顺序排的），
				//   比原来的"系统 / 已注入"两个独立计数信息量更大：
				//   组 0 = 普通·已注入，组 1 = 普通·未注入，组 2 = 系统。
				//   三者相加 == 进程总数，可以直接对账。
				swprintf_s(buffer, _countof(buffer),
					L"进程 %u  ·  分组：已注入 %u / 未注入 %u / 系统 %u  ·  关键 %u  ·  已挂起 %u  ·  "
					L"扫描 #%u（本轮 %u 项 / %u ms，无路径 %u，模块未知 %u）  ·  "
					L"动作 收到 %u / 成功 %u / 失败 %u / 拒绝 %u",
					stat.LastScanProcesses,
					groupCounts[0], groupCounts[1], groupCounts[2],
					stat.CriticalCount, stat.SuspendedCount,
					stat.Scans, stat.LastScanProcesses, stat.LastScanMs,
					stat.LastScanNoPath, stat.LastScanNoModules,
					stat.ActionRequests, stat.ActionOk, stat.ActionFailed, stat.ActionRefused);
				summary = buffer;

				if (!stat.SelfExitSupported) {
					summary += L"  ·  内部退出不可用（DLL 缺导出）";
				}
				if (stat.SnapshotFailures != 0) {
					WCHAR extra[96] = {};
					swprintf_s(extra, L"  ·  ⚠ 枚举失败 %u 次（err=%lu）",  // gbk-ok：本行只经 GDI DrawTextW 绘制，从不经 WideCharToMultiByte(CP_ACP)
						stat.SnapshotFailures, stat.LastError);
					summary += extra;
				}
			}
			DrawTextSimple(dc, summary.c_str(),
				{ layout.Left, layout.SummaryTop, layout.Right, layout.SummaryTop + 22 },
				g_labelFont, stat.Enabled ? ColorTextSecondary : ColorWouldBlock,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);		}

		// ---------------- 进程表 ----------------
		RECT tablePanel = { layout.TableLeft, layout.MainTop, layout.TableRight, layout.MainBottom };
		DrawPanel(dc, tablePanel, L"全部进程（Toolhelp 快照，含受保护进程）");

		const int headerTop = layout.MainTop + 34;
		const int colName = layout.TableLeft + 16;
		const int colPid = colName + 200;
		const int colCpu = colPid + 62;
		const int colMem = colCpu + 62;
		const int colBits = colMem + 78;
		const int colFlags = colBits + 46;

		DrawTextSimple(dc, L"进程", { colName, headerTop, colPid - 6, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"PID", { colPid, headerTop, colCpu - 6, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"CPU", { colCpu, headerTop, colMem - 6, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"内存", { colMem, headerTop, colBits - 6, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"位数", { colBits, headerTop, colFlags - 6, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, L"标记", { colFlags, headerTop, layout.TableRight - 16, headerTop + 20 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

		const int total = static_cast<int>(g_arkSnapshot.Rows.size());
		if (g_arkScroll > total - layout.MaxRows) {
			g_arkScroll = total - layout.MaxRows;
		}
		if (g_arkScroll < 0) {
			g_arkScroll = 0;
		}

		const int rowsEnd = layout.RowsTop + layout.MaxRows * ArkRowHeight;
		if (layout.MaxRows > 0) {
			const int count = (std::min)(layout.MaxRows, total - g_arkScroll);
			for (int i = 0; i < count; i++) {
				const R3ShieldCoreArk::Row& row = g_arkSnapshot.Rows[static_cast<size_t>(g_arkScroll + i)];
				const int rowTop = layout.RowsTop + i * ArkRowHeight;
				const bool isSelected = (static_cast<int>(row.Pid) == g_arkSelectedPid);

				if (isSelected) {
					RECT mark = { layout.TableLeft + 8, rowTop - 2, layout.TableRight - 8, rowTop + ArkRowHeight - 4 };
					HBRUSH brush = CreateSolidBrush(RGB(214, 232, 250));
					FillRect(dc, &mark, brush);
					DeleteObject(brush);
				}
				else if (i % 2 == 1) {
					RECT stripe = { layout.TableLeft + 8, rowTop - 2, layout.TableRight - 8, rowTop + ArkRowHeight - 4 };
					HBRUSH brush = CreateSolidBrush(ColorLogRowAlt);
					FillRect(dc, &stripe, brush);
					DeleteObject(brush);
				}

				const int textTop = rowTop;
				const int textBottom = rowTop + 20;

				COLORREF nameColor = ColorTextPrimary;
				if (row.IsCritical) {
					nameColor = ColorBlocked;
				}
				else if (row.IsSystem) {
					nameColor = ColorRegistryAccent;
				}
				DrawTextSimple(dc, row.Name.c_str(),
					{ colName, textTop, colPid - 6, textBottom }, g_monoFont, nameColor,
					DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

				DrawTextSimple(dc, std::to_wstring(row.Pid).c_str(),
					{ colPid, textTop, colCpu - 6, textBottom }, g_monoFont,
					ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

				std::wstring cpu = row.CpuValid
					? std::to_wstring(row.CpuPercentX10 / 10) + L"." + std::to_wstring(row.CpuPercentX10 % 10) + L"%"
					: L"—";
				DrawTextSimple(dc, cpu.c_str(), { colCpu, textTop, colMem - 6, textBottom },
					g_monoFont, row.CpuPercentX10 >= 200 ? ColorWouldBlock : ColorTextPrimary,
					DT_LEFT | DT_SINGLELINE);

				const std::wstring mem = row.TimesKnown ? FormatBytes(row.WorkingSetBytes) : L"—";
				DrawTextSimple(dc, mem.c_str(), { colMem, textTop, colBits - 6, textBottom },
					g_monoFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE);

				PCWSTR bits = row.IsWow64 ? L"32" : L"64";
				DrawTextSimple(dc, bits, { colBits, textTop, colFlags - 6, textBottom },
					g_monoFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

				// 标记列：固定槽位，每个槽最多两个字，颜色区分。
				struct Flag { PCWSTR text; COLORREF color; };
				Flag flags[4] = {};
				if (row.IsSystem) {
					flags[0] = { L"系统", ColorRegistryAccent };
				}
				if (row.IsCritical) {
					flags[1] = { L"关键", ColorBlocked };
				}
				if (row.HasOurDll) {
					flags[2] = { L"注入", ColorProcessAccent };
				}
				if (row.SuspendedByArk) {
					flags[3] = { L"挂起", ColorWouldBlock };
				}
				for (int f = 0; f < 4; f++) {
					if (!flags[f].text) {
						continue;
					}
					const int left = colFlags + f * 42;
					DrawTextSimple(dc, flags[f].text, { left, textTop, left + 40, textBottom },
						g_labelFont, flags[f].color, DT_LEFT | DT_SINGLELINE);
				}
			}
		}

		if (total == 0) {
			DrawTextSimple(dc,
				stat.Enabled ? L"(暂无数据 —— 等待第一轮扫描)"
					: L"(ARK 未启用)",
				{ colName, layout.RowsTop, layout.TableRight - 16, layout.RowsTop + 24 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		}
		else if (total > layout.MaxRows) {
			WCHAR hint[64] = {};
			swprintf_s(hint, L"显示 %d–%d / %d（滚轮翻页）",
				g_arkScroll + 1,
				(std::min)(g_arkScroll + layout.MaxRows, total), total);
			DrawTextSimple(dc, hint,
				{ layout.TableLeft + 16, rowsEnd + 2, layout.TableRight - 16, rowsEnd + 20 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		}

		// ---------------- 明细面板 ----------------
		RECT detailPanel = { layout.DetailLeft, layout.MainTop, layout.DetailRight, layout.MainBottom };
		DrawPanel(dc, detailPanel, L"选中进程");

		const int lineLeft = layout.DetailLeft + 16;
		const int lineRight = layout.DetailRight - 16;
		int y = layout.MainTop + 36;
		constexpr int lineGap = 21;

		auto Line = [&](PCWSTR label, const std::wstring& value, COLORREF color, UINT format) {
			DrawTextSimple(dc, label, { lineLeft, y, lineLeft + 66, y + 18 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
			DrawTextSimple(dc, value.c_str(), { lineLeft + 68, y, lineRight, y + 18 },
				g_monoFont, color, format);
			y += lineGap;
		};

		if (!selected) {
			DrawTextSimple(dc,
				g_arkSelectedPid < 0 ? L"（未选中：点左侧列表里的一行）"
					: L"（选中的进程已经不在了）",
				{ lineLeft, y, lineRight, y + 20 }, g_labelFont, ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
		else {
			const std::wstring title = selected->Name + L"  (" + std::to_wstring(selected->Pid) + L")";
			DrawTextSimple(dc, title.c_str(), { lineLeft, y, lineRight, y + 20 },
				g_labelFont, selected->IsCritical ? ColorBlocked : ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			y += lineGap + 2;

			Line(L"文件地址", selected->PathKnown ? selected->Path : L"未知（权限不足，读不到路径）",
				selected->PathKnown ? ColorTextPrimary : ColorWouldBlock, DT_LEFT | DT_SINGLELINE | DT_PATH_ELLIPSIS);

			Line(L"系统进程",
				selected->PathKnown ? (selected->IsSystem ? L"是" : L"否") : L"未知",
				selected->IsSystem ? ColorRegistryAccent : ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE);
			// 关键进程与系统进程**分两行**（不是合并成一行）：
			// 它们是两件事 —— svchost.exe 是系统进程但**不是**关键进程，
			// 而"能不能动它"只取决于后者。
			Line(L"关键进程",
				selected->IsCritical ? L"是（结束会蓝屏 / 挂起会卡死，三个动作全部拒绝）" : L"否",
				selected->IsCritical ? ColorBlocked : ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			Line(L"位数 / 会话",
				(selected->IsWow64 ? L"32 位（WOW64）" : L"64 位")
					+ std::wstring(L"   会话 ") + std::to_wstring(selected->SessionId)
					+ L"   线程 " + std::to_wstring(selected->ThreadCount),
				ColorTextPrimary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			Line(L"CPU / 内存",
				(selected->CpuValid
					? (std::to_wstring(selected->CpuPercentX10 / 10) + L"." + std::to_wstring(selected->CpuPercentX10 % 10) + L"%")
					: std::wstring(L"首轮无基准"))
					+ (selected->TimesKnown ? (L"   内存 " + FormatBytes(selected->WorkingSetBytes)
						+ L"   私有 " + FormatBytes(selected->PrivateBytes)) : std::wstring(L"   （内存不可读）")),
				ColorTextPrimary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			// 注入状态三态：是 / 否 / 未知。**未知不能显示成"否"** ——
			// 受保护进程读不到模块表，把"读不到"说成"没注入"是假结论。
			Line(L"已注入",
				selected->ModuleQueryOk
					? (selected->HasOurDll ? L"是" : L"否")
					: L"未知（受保护进程，读不到模块表）",
				selected->HasOurDll ? ColorProcessAccent : ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			Line(L"挂起状态",
				selected->SuspendedByArk ? L"本引擎已挂起（可点「恢复」）" : L"未挂起",
				selected->SuspendedByArk ? ColorWouldBlock : ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		// ---------------- 四个动作按钮 ----------------
		const bool isSelf = selected && selected->Pid == g_arkSnapshot.Stat.SelfPidOfEngine;
		for (int i = 0; i < ArkButtonCount; i++) {
			const bool enabled = ArkButtonEnabled(i);
			PCWSTR label = ArkButtonLabel(i);

			// 「强制结束」的二次确认：只有已选中的行才谈得上"确认"。
			if (i == ArkButtonForceKill && enabled && g_arkKillArmed
				&& g_arkArmedPid == g_arkSelectedPid) {
				label = L"确认强制结束";
			}

			const bool danger = (i == ArkButtonForceKill) && enabled;
			DrawArkButton(dc, layout.Buttons[i], label, enabled,
				g_arkHoverAction == i, g_arkPressedAction == i, danger);
		}

		// 按钮下方的"为什么不能点"说明。
		{
			std::wstring reason;
			COLORREF color = ColorTextSecondary;
			if (!selected) {
				reason = L"先在左侧列表里选一个进程。";
			}
			else if (isSelf) {
				reason = L"这是引擎自己 —— 三个动作全部拒绝（自杀式操作只会让防护凭空消失）。";
				color = ColorWouldBlock;
			}
			else if (selected->IsCritical) {
				reason = L"关键系统进程：结束会立刻蓝屏（CRITICAL_PROCESS_DIED），挂起会整机卡死。";
				color = ColorBlocked;
			}
			else if (!stat.Enabled) {
				reason = L"ARK 未启用（ark_enabled=0），动作不可用。";
				color = ColorWouldBlock;
			}
			else if (!stat.SelfExitSupported) {
				reason = L"「内部退出」不可用：当前 DLL 没有 GlobalHookSessionSelfExit 导出（旧版 DLL）。";
				color = ColorWouldBlock;
			}
			else if (g_arkKillArmed && g_arkArmedPid == g_arkSelectedPid) {
				reason = L"再点一次「确认强制结束」才真正执行 —— 它不可撤销。";
				color = ColorBlocked;
			}
			else {
				reason = L"「内部退出」= 走目标自己的退出路径；「强制结束」= 内核直接拆，目标跑不到任何清理。";
			}
			DrawTextSimple(dc, reason.c_str(),
				{ layout.DetailLeft + 16, layout.MainBottom - 12 - (ArkButtonHeight * 2 + 8) - 22,
				  layout.DetailRight - 16, layout.MainBottom - 12 - (ArkButtonHeight * 2 + 8) },
				g_labelFont, color, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		// ---------------- 最近事件（选中进程）----------------
		if (!layout.HasEvents) {
			return;
		}

		RECT eventsPanel = { layout.Left, layout.EventsTop, layout.Right, layout.EventsBottom };
		PCWSTR eventsTitle = selected
			? L"最近事件（选中进程）"
			: L"最近事件（先在左侧选一个进程）";
		DrawPanel(dc, eventsPanel, eventsTitle);

		if (!g_arkActions.empty()) {
			// 最近一次处置结果贴在标题右侧 —— "我点了按钮之后到底发生了什么"
			// 是这一页最需要立刻回答的问题。
			const R3ShieldCoreArk::ActionRecord& last = g_arkActions.front();
			std::wstring text = L"上次动作：" + last.Text;
			if (!last.Code.empty()) {
				text += L"  [" + last.Code + L"]";
			}
			if (last.ElapsedMs != 0) {
				text += L"  " + std::to_wstring(last.ElapsedMs) + L"ms";
			}
			DrawTextSimple(dc, text.c_str(),
				{ layout.Left + 200, layout.EventsTop + 12, layout.Right - 16, layout.EventsTop + 34 },
				g_labelFont, last.Ok ? ColorFileAccent : ColorWouldBlock,
				DT_RIGHT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		if (g_arkSelectedPid < 0) {
			return;
		}

		const int eventTop = layout.EventsTop + 38;
		const int eventRowHeight = 20;
		const int maxEventRows = (layout.EventsBottom - 8 - eventTop) / eventRowHeight;
		if (maxEventRows <= 0) {
			return;
		}

		if (g_arkEvents.empty()) {
			DrawTextSimple(dc,
				L"(这个进程还没有产生过被记录的事件 —— 注意：没被注入的进程不会产生事件)",
				{ layout.Left + 16, eventTop, layout.Right - 16, eventTop + 18 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			return;
		}

		// 取最新的 N 条（新的在尾部）。
		const int totalEvents = static_cast<int>(g_arkEvents.size());
		const int first = (std::max)(0, totalEvents - maxEventRows);
		const int colTime = layout.Left + 16;
		const int colSource = colTime + 62;
		const int colOp = colSource + 44;
		const int colTarget = colOp + 132;

		for (int i = first; i < totalEvents; i++) {
			const R3ShieldCoreStats::LogEntry& row = g_arkEvents[static_cast<size_t>(i)];
			const int top = eventTop + (i - first) * eventRowHeight;

			const COLORREF decisionColor = DecisionColor(static_cast<R3ShieldCore::Decision>(row.Decision));
			RECT stripe = { layout.Left + 4, top + 2, layout.Left + 7, top + eventRowHeight - 3 };
			HBRUSH stripeBrush = CreateSolidBrush(row.IsHighRisk ? ColorHighRisk : decisionColor);
			FillRect(dc, &stripe, stripeBrush);
			DeleteObject(stripeBrush);

			DrawTextSimple(dc, FormatLogTime(row.TimeStamp).c_str(),
				{ colTime, top, colSource - 4, top + 18 }, g_logFont,
				ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
			DrawTextSimple(dc, ObjectTypeLabel(row.ObjectType),
				{ colSource, top, colOp - 4, top + 18 }, g_logFont,
				ObjectTypeColor(row.ObjectType), DT_LEFT | DT_SINGLELINE);

			WCHAR opName[64] = {};
			MultiByteToWideChar(CP_ACP, 0, R3ShieldCore::AnyOpName(row.ObjectType, row.Op),
				-1, opName, _countof(opName));
			std::wstring opText = opName;
			if (row.BlockedByUs) {
				opText = L"[拦] " + opText;
			}
			if (row.IsHighRisk) {
				opText = L"[危] " + opText;
			}
			DrawTextSimple(dc, opText.c_str(), { colOp, top, colTarget - 6, top + 18 },
				g_logFont, row.IsHighRisk ? ColorHighRisk : decisionColor,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

			std::wstring target = row.Target;
			if (row.TargetProcessId != 0) {
				target += L"  (" + std::to_wstring(row.TargetProcessId) + L")";
			}
			else if (!row.Value.empty()) {
				target += L"\\" + row.Value;
			}
			if (target.empty()) {
				target = L"(未解析)";
			}
			DrawTextSimple(dc, target.c_str(), { colTarget, top, layout.Right - 16, top + 18 },
				g_logFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE | DT_PATH_ELLIPSIS);
		}
	}

	// 把一次点击变成一次处置请求。
	//
	// ★ 界面线程**只压请求**，真正的执行在引擎主循环里（见 r3shieldcore_ark.h）：
	//   `内部退出` 最长要等 1.5 秒，在这里直接执行会让窗口"未响应"。
	void PerformArkAction(int button)
	{
		if (g_arkSelectedPid < 0) {
			return;
		}
		if (!FindArkRow(g_arkSelectedPid)) {
			return;
		}

		// 「强制结束」二次确认：第一次点只进入"待确认"状态。
		//
		// ★ 待确认状态绑定 pid（`g_arkArmedPid`），换选中就撤销 ——
		//   否则会出现"我以为在确认 A、实际结束了 B"，而它不可撤销。
		if (button == ArkButtonForceKill
			&& !(g_arkKillArmed && g_arkArmedPid == g_arkSelectedPid)) {
			g_arkKillArmed = true;
			g_arkArmedPid = g_arkSelectedPid;
			return;
		}
		g_arkKillArmed = false;
		g_arkArmedPid = -1;

		ULONG action = 0;
		switch (button) {
		case ArkButtonSuspend: action = R3ShieldCoreArk::ActionSuspend; break;
		case ArkButtonResume: action = R3ShieldCoreArk::ActionResume; break;
		case ArkButtonInternalExit: action = R3ShieldCoreArk::ActionInternalExit; break;
		case ArkButtonForceKill: action = R3ShieldCoreArk::ActionForceKill; break;
		default: return;
		}

		R3ShieldCoreArk::RequestAction(static_cast<ULONG>(g_arkSelectedPid), action);
	}

	// ARK 页的表格命中：返回被点到的行索引，-1 = 没点中。
	int HitTestArkRow(POINT point, const RECT& client)
	{
		if (g_activeTab != 4) {
			return -1;
		}
		const ArkLayout layout = ArkLayoutFor(client);
		if (layout.MaxRows <= 0) {
			return -1;
		}
		RECT table = { layout.TableLeft, layout.RowsTop, layout.TableRight,
			layout.RowsTop + layout.MaxRows * ArkRowHeight };
		if (!PtInRect(&table, point)) {
			return -1;
		}
		const int index = g_arkScroll + (point.y - layout.RowsTop) / ArkRowHeight;
		if (index < 0 || index >= static_cast<int>(g_arkSnapshot.Rows.size())) {
			return -1;
		}
		return index;
	}

	PCWSTR ModeDescription(R3ShieldCore::Mode mode)
	{
		switch (mode) {
		case R3ShieldCore::Mode::Block:
			return L"日常主动防御：普通行为放行，高置信度高危行为直接拦截。";		case R3ShieldCore::Mode::Ask:
			return L"高风险行为进入询问通道，由用户决定允许或拒绝。";
		case R3ShieldCore::Mode::BlockAll:
			return L"紧急隔离：探测到的操作默认拒绝，适合样本分析。";
		case R3ShieldCore::Mode::BlockAllSafe:
			return L"紧急隔离安全版：可信进程创建保留，其余高强度拦截。";
		default:
			return L"观察模式：所有行为放行，只记录事件和高危命中。";
		}
	}

	void DrawConfigRow(HDC dc, int x, int y, int width, PCWSTR label, bool enabled)
	{
		RECT dot = { x, y + 5, x + 10, y + 15 };
		HBRUSH brush = CreateSolidBrush(enabled ? RGB(34, 160, 96) : ColorBorder);
		FillRect(dc, &dot, brush);
		DeleteObject(brush);
		DrawTextSimple(dc, label, { x + 18, y, x + width - 54, y + 22 },
			g_labelFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		DrawTextSimple(dc, enabled ? L"已启用" : L"已关闭", { x + width - 50, y, x + width, y + 22 },
			g_labelFont, enabled ? RGB(34, 140, 86) : ColorTextSecondary,
			DT_RIGHT | DT_SINGLELINE);
	}

	void DrawConfigPage(HDC dc, const RECT& client)
	{
		const int left = Padding;
		const int right = client.right - Padding;
		const int top = TabBarTop + TabBarHeight + 18;
		const R3ShieldCore::Mode mode = static_cast<R3ShieldCore::Mode>(
			InterlockedCompareExchange(&g_displayMode, 0, 0));

		RECT modePanel = { left, top, right, top + 104 };
		DrawPanel(dc, modePanel, L"当前防护模式");
		RECT modeName = { left + 16, top + 42, left + 160, top + 76 };
		DrawTextSimple(dc, ModeShortName(mode), modeName, g_valueFont,
			mode == R3ShieldCore::Mode::Block ? ColorBlocked : ColorAccent,
			DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, ModeDescription(mode), { left + 178, top + 46, right - 20, top + 72 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		const int panelsTop = top + 122;
		const int gap = 14;
		const int panelWidth = (right - left - gap) / 2;
		RECT monitorPanel = { left, panelsTop, left + panelWidth, client.bottom - PromptSummaryHeight() - 12 };
		RECT runtimePanel = { left + panelWidth + gap, panelsTop, right, client.bottom - PromptSummaryHeight() - 12 };
		DrawPanel(dc, monitorPanel, L"监控面板");
		DrawPanel(dc, runtimePanel, L"运行参数");

		const int rowStart = panelsTop + 46;
		const int rowGap = 27;
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart, panelWidth - 32, L"高危规则", g_options.HighRisk);
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap, panelWidth - 32, L"注册表只读 / Hive", g_options.HookReads || g_options.HookHive);
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 2, panelWidth - 32, L"文件行为", g_options.HookFile);
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 3, panelWidth - 32, L"进程创建", g_options.HookProcess);
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 4, panelWidth - 32, L"远程线程", g_options.HookThread);
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 5, panelWidth - 32, L"驱动 / 服务", g_options.HookDriver);
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 6, panelWidth - 32, L"本进程线程噪音", g_options.HookSelfThread);
		// ★ v61：高危进程提示。注意它**不是** hook —— 是引擎自己定期快照
		//   全机进程，所以即使"进程创建"那一行是关的，它照样工作。
		DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 7, panelWidth - 32, L"高危进程提示", g_options.HighRiskProcessAlert != 0);
		// ★ v62：ARK 页。同样是"引擎自己枚举"，与 hook 无关。
		//   它只影响 ARK 页的列表刷新与动作可用性，不改变任何拦截行为。
		{
			WCHAR arkBuffer[128] = {};
			// ★ v63：两个间隔都显示出来 —— 它们含义不同（引擎枚举 vs 界面重绘），
			//   只显示一个会让用户以为"改了 ark_refresh_ms 没生效"。
			swprintf_s(arkBuffer, L"ARK 全机进程视图（扫描 %u / 刷新 %u ms）",
				g_options.ArkScanMs ? g_options.ArkScanMs : 2000,
				ArkRefreshIntervalMs());
			DrawConfigRow(dc, monitorPanel.left + 16, rowStart + rowGap * 8, panelWidth - 32,
				arkBuffer, g_options.ArkEnabled);
		}

		WCHAR buffer[256] = {};
		swprintf_s(buffer, L"排除路径：%u 条", g_options.ExcludePathCount);
		DrawConfigRow(dc, runtimePanel.left + 16, rowStart, panelWidth - 32, buffer, true);
		// ★ v51：把「绝不注入」条数也显示出来 —— 理由同启动横幅（app.cpp）：
		//   这是**最容易配错又最难自查**的一项，ini 里少个结尾 `\`、或误写成
		//   文件名而不是完整路径，都会**静默不生效**；而"不生效"的表现是
		//   "某个程序偶尔卡一下"，几乎没人会联想到 ini。
		//   控制台横幅有、GUI 没有 ⇒ 从界面看，用户永远不知道自己有几个程序在裸奔。
		swprintf_s(buffer, L"绝不注入：%u 条", g_options.NeverInjectPathCount);
		DrawConfigRow(dc, runtimePanel.left + 16, rowStart + rowGap, panelWidth - 32, buffer, true);
		swprintf_s(buffer, L"询问超时：%u 秒", g_options.PromptTimeoutMs / 1000);
		DrawConfigRow(dc, runtimePanel.left + 16, rowStart + rowGap * 2, panelWidth - 32, buffer, mode == R3ShieldCore::Mode::Ask);
		DrawConfigRow(dc, runtimePanel.left + 16, rowStart + rowGap * 3, panelWidth - 32, L"日志输出", g_options.LogPath != nullptr && g_options.LogPath[0] != L'\0');
		RECT pathRect = { runtimePanel.left + 16, rowStart + rowGap * 4 + 6, runtimePanel.right - 16, rowStart + rowGap * 6 };
		DrawTextSimple(dc, g_options.LogPath ? g_options.LogPath : L"(未配置日志路径)", pathRect,
			g_monoFont, ColorTextSecondary, DT_LEFT | DT_WORDBREAK | DT_PATH_ELLIPSIS);
		DrawTextSimple(dc, L"使用页签栏的“复制日志路径”按钮复制完整路径。",
			{ runtimePanel.left + 16, rowStart + rowGap * 7, runtimePanel.right - 16, rowStart + rowGap * 8 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// =================================================================
	// ★ v80：「高级」页签 —— 编辑台搬去了 r3shieldcore-cfg.exe，这里只留入口
	// =================================================================
	//
	// 原来这一页是一个 1770 行的编辑台：规则表 + 原生 EDIT + 模板芯片 +
	// 「改前 / 改后」字节对照。v80 把它**整块搬到 cfg 工具**（第 3 个页签）。
	//
	// 为什么搬（不是嫌它长，是**操作节奏不同**）：
	//   · 「配置」页是"看一眼、勾一下"，几秒钟的事；
	//   · 「高级」页是"坐下来写规则"，要打字、要对照、要反复试。
	//   两种节奏挤在一个窗口里，写规则时每敲一个字主程序都要重绘整屏。
	//
	// 现在的分工：
	//   · cfg 侧（r3shieldcore-cfg.exe 第 3 页签）：完整编辑台，
	//     与生产**同一份** codec（`spoof_apply_codec.h` 等，铁律 195）。
	//   · 主程序侧（这一页）：一个按钮 —— 点一下把 cfg 叫到前台并切到
	//     「高级」页；cfg 已经在跑就**激活**，不重复开。
	//   · 主程序启动时顺手把 cfg 拉起来（最小化，不抢焦点）。
	//
	// ★ 为什么按钮不自己写 `CreateProcessW` + 字面量窗口名（铁律 127）：
	//   窗口类名 / 激活消息名 / 页号 / exe 名**只定义一处** —— 共享头
	//   `cfg_launch.h`。这里再抄一份的话，cfg 哪天改了 exe 名，主程序会
	//   "启动成功但窗口永远不出现"：`CreateProcessW` 返回真，没有任何地方
	//   会报错，而用户看到的就是"点了没反应"。
	//
	// ★ 这一页**不注入、不挂钩、不依赖引擎在跑** —— 它只是个启动器。
	//   所以本机（铁律 175：开发机禁止跑引擎）可以安全地打开它看。
	// -----------------------------------------------------------------

	// 跳转页的几何 —— 只在 `AdvLaunchButtonRect` 里算一次，
	// 绘制 / 命中两处共用（铁律 182：坐标只在创建点出现一次）。
	//
	// ★★ v80 修缺陷：原来按钮 top 是**拍脑袋**的 `TabBarTop + TabBarHeight + 104`，
	//   而第二行说明文字的盒子是 `+94 .. +142` ⇒ **按钮整个压在文字上**；
	//   按钮下方那行提示又落在第三行说明文字上（`+154..+178` vs `+158..+178`）。
	//   两处重叠都**只有截图看得出** —— 画按钮/画文字的代码各自都明明白白
	//   （铁律 237 同族：自绘界面里"重叠"不会报错，只会盖住）。
	//   ⇒ 改成"从面板顶按行距**推导**"，并把面板顶抽成函数（面板矩形 / 文字起点 /
	//     按钮几何三处共用同一个来源，铁律 127）。
	constexpr int AdvPanelTopInset = 16;        // 面板顶距页签栏底
	constexpr int AdvTextFirstLineOffset = 46;  // 面板顶 → 第一行文字盒顶
	constexpr int AdvTextLineStep = 32;         // 第一行 → 第二行
	constexpr int AdvTextSecondBoxHeight = 48;  // 第二行（可换行，留两行高）
	constexpr int AdvTextThirdLineStep = 60;    // 第二行盒顶 → 第三行
	constexpr int AdvTextThirdBoxHeight = 24;
	constexpr int AdvButtonTopGap = 16;         // 第三行盒底 → 按钮顶

	constexpr int AdvPanelTop() { return TabBarTop + TabBarHeight + AdvPanelTopInset; }

	// 按钮顶 = 面板顶 + 三行文字占的高度 + 间距（**推导**出来的，不是拍脑袋的）
	constexpr int AdvButtonTopOffset = AdvTextFirstLineOffset + AdvTextLineStep
		+ AdvTextSecondBoxHeight + AdvTextThirdLineStep + AdvTextThirdBoxHeight
		+ AdvButtonTopGap;

	constexpr int AdvLaunchButtonWidth = 240;
	constexpr int AdvLaunchButtonHeight = 40;

	RECT AdvLaunchButtonRect(const RECT& client)
	{
		const int centerX = (client.left + client.right) / 2;
		const int top = AdvPanelTop() + AdvButtonTopOffset;
		RECT rect = { centerX - AdvLaunchButtonWidth / 2, top,
			centerX + AdvLaunchButtonWidth / 2, top + AdvLaunchButtonHeight };
		return rect;
	}

	bool HitTestAdvLaunch(POINT point, const RECT& client)
	{
		const RECT rect = AdvLaunchButtonRect(client);
		return point.x >= rect.left && point.x < rect.right
			&& point.y >= rect.top && point.y < rect.bottom;
	}

	// 真正去叫 cfg。失败**不弹窗** —— 把原因记在 `g_advLaunchError` 里，
	// 由 DrawAdvancedPage 画在按钮下方（理由见该变量的声明处）。
	void AdvLaunchCfg(HWND hwnd)
	{
		R3ShieldCoreCfg::LaunchOptions options;
		options.page = R3ShieldCoreCfg::kPageAdvanced;
		options.quiet = false;   // 用户主动点的 ⇒ 叫到前台并切到「高级」页

		std::wstring error;
		if (R3ShieldCoreCfg::LaunchOrActivate(options, &error)) {
			g_advLaunchError.clear();
		}
		else {
			g_advLaunchError = error;
		}
		InvalidateRect(hwnd, nullptr, FALSE);
	}

	void DrawAdvancedPage(HDC dc, const RECT& client)
	{
		// ★ 版式：文字在上、按钮在下。三行文字的高度与行距是**常量**，
		//   按钮几何用同一组常量推导（`AdvButtonTopOffset`）——
		//   这样"改文案把行数改了"时按钮会跟着走，不会再压住文字。
		const RECT panel = { Padding, AdvPanelTop(),
			client.right - Padding, client.bottom - Padding };
		DrawPanel(dc, panel, L"高级规则编辑台");

		const int left = panel.left + 20;
		const int right = panel.right - 20;
		int y = AdvPanelTop() + AdvTextFirstLineOffset;

		DrawTextSimple(dc, L"规则编辑台已经搬到独立工具 r3shieldcore-cfg.exe。",
			{ left, y, right, y + 24 }, g_labelFont, ColorTextPrimary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		y += AdvTextLineStep;
		DrawTextSimple(dc,
			L"在那儿可以写中文规则、对照 API 返回值的「改前 / 改后」字节，"
			L"并把规则保存下来给引擎用。",
			{ left, y, right, y + AdvTextSecondBoxHeight }, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS);
		y += AdvTextThirdLineStep;
		DrawTextSimple(dc,
			L"cfg 已经跟着主程序一起启动了 —— 点下面的按钮可以把它叫到前台。",
			{ left, y, right, y + AdvTextThirdBoxHeight }, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		// 复用 ARK 那套自绘按钮 —— 它就是本项目的"通用自绘按钮"
		//（铁律 195：同一种外观不抄第二遍）。参数依次是
		// 启用 / 悬停 / 按下 / 危险色，这里只有前三个用得上。
		const RECT button = AdvLaunchButtonRect(client);
		DrawArkButton(dc, button, L"打开高级规则编辑台",
			true, g_advLaunchHover == 0, g_advLaunchPressed == 0, false);

		// 核对日志（探针读它）：证明"这一页真被画到了"。
		//
		// ★ 为什么必须有：`--gui-preview` 下探针只能靠**应用自己的日志**
		//   区分"这一页画到了"和"窗口是空的/画错了页" —— 两者在截图上
		//   分不开（铁律 24/28）。做法与 ARK 页的 `[ark] 页面已绘制` 一致。
		//
		// ⚠️ 每帧都打（WM_PAINT 的频率）。探针读的是"有没有这一句"，
		//    不是出现次数；行内容必须短。
		//    这里顺带把**按钮矩形**报出来 —— 探针可以用它验证
		//    "按钮确实落在客户区内"（几何算错时是最容易看不出来的一类错）。
		printf("[adv] 跳转页已绘制 按钮=%ld,%ld,%ld,%ld 失败=%d 客户区=%ldx%ld\n",
			button.left, button.top, button.right, button.bottom,
			g_advLaunchError.empty() ? 0 : 1,
			client.right, client.bottom);

		if (!g_advLaunchError.empty()) {
			// 失败原因直接画出来（不弹窗）—— 否则用户只看到"点了没反应"。
			DrawTextSimple(dc, g_advLaunchError.c_str(),
				{ button.left - 100, button.bottom + 12,
				  button.right + 100, button.bottom + 60 },
				g_labelFont, ColorBlocked, DT_CENTER | DT_WORDBREAK | DT_END_ELLIPSIS);
		}
		else {
			DrawTextSimple(dc,
				L"（cfg 已在运行时会直接切到它的「高级」页，不会重复开一个）",
				{ button.left - 160, button.bottom + 14,
				  button.right + 160, button.bottom + 34 },
				g_labelFont, ColorTextSecondary, DT_CENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
	}
	// -----------------------------------------------------------------
	// 页签栏
	// -----------------------------------------------------------------
	constexpr int TabCount = 6;
	PCWSTR TabTitle(int index)
	{
		switch (index) {
		case 1: return L"事件日志";
		case 2: return L"进程";
		case 3: return L"配置";
		case 4: return L"ARK";
		case 5: return L"高级";
		default: return L"概览";
		}
	}

	RECT TabRect(int index)
	{
		int left = Padding + index * (TabWidth + 8);
		RECT rect = { left, TabBarTop + 4, left + TabWidth, TabBarTop + TabBarHeight - 4 };
		return rect;
	}

	int HitTestTab(POINT point)
	{
		for (int i = 0; i < TabCount; i++) {
			RECT rect = TabRect(i);
			if (PtInRect(&rect, point)) {
				return i;
			}
		}
		return -1;
	}

	void DrawTabBar(HDC dc)
	{
		const int width = ClientWidth();

		// ★ v83：不再给页签条铺不透明底色 —— 玻璃背景要透上来。
		//   （原来那块 `ColorHeaderBackground` 的 FillRect 是"玻璃感"的头号杀手：
		//     页签条下面一片实色，整条看起来就是贴纸。）
		//   页签条与顶栏共用顶部的"薄纱"（见 PaintWindow 里的 headerBand）。
		for (int i = 0; i < TabCount; i++) {
			RECT rect = TabRect(i);
			const bool active = (i == g_activeTab);
			const bool hover = (i == g_hoverTab);

			if (g_glass.active && (active || hover)) {
				// 页签 = 一块小玻璃片；选中态 tint 更亮（"凸起来"）。
				const R3ShieldCoreUi::GlassTheme& th = R3ShieldCoreUi::DefaultTheme();
				g_glass.AddPanel(rect.left, rect.top, rect.right, rect.bottom,
					(rect.bottom - rect.top) * 0.5f,     // 胶囊：半径 = 半高
					active ? 0.34f : 0.18f, 1);
			}
			else if (active) {
				// 兜底（玻璃不可用）：保留原来的蓝色实底
				HBRUSH brush = CreateSolidBrush(ColorTabActiveBg);
				HGDIOBJ old = SelectObject(dc, brush);
				HPEN pen = CreatePen(PS_SOLID, 1, ColorTabActiveBg);
				HGDIOBJ oldPen = SelectObject(dc, pen);
				RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 16, 16);
				SelectObject(dc, old);
				SelectObject(dc, oldPen);
				DeleteObject(brush);
				DeleteObject(pen);
			}
			else if (hover) {
				HBRUSH brush = CreateSolidBrush(ColorTabHoverBg);
				HGDIOBJ old = SelectObject(dc, brush);
				HPEN pen = CreatePen(PS_SOLID, 1, ColorTabHoverBorder);
				HGDIOBJ oldPen = SelectObject(dc, pen);
				RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 16, 16);
				SelectObject(dc, old);
				SelectObject(dc, oldPen);
				DeleteObject(brush);
				DeleteObject(pen);
			}

			// ★ 文字配色跟着玻璃改：选中/悬停用**深蓝**（玻璃底是浅的，
			//   原来那个"白字压深蓝底"的反色在这里会完全看不见）。
			COLORREF textColor;
			if (g_glass.active) {
				textColor = (active || hover) ? ColorAccent : ColorTabInactiveText;
			}
			else {
				textColor = active ? ColorTabActiveText
					: (hover ? ColorAccent : ColorTabInactiveText);
			}
			DrawTextSimple(dc, TabTitle(i), rect, g_tabFont, textColor,
				DT_CENTER | DT_VCENTER | DT_SINGLELINE);

			// 选中态：底部一条 2px 的蓝色下划线（玻璃上比"整块填色"更清爽，
			// 也更像 iOS 26 那套"玻璃胶囊 + 指示条"）。
			if (g_glass.active && active) {
				RECT underline = { rect.left + 14, rect.bottom - 5, rect.right - 14, rect.bottom - 3 };
				HBRUSH ub = CreateSolidBrush(ColorAccent);
				FillRect(dc, &underline, ub);
				DeleteObject(ub);
			}
		}

		// 右端的操作按钮（页签在左、操作在右，互不重叠）
		DrawHeaderActions(dc);
		DrawModeButton(dc);

		// 页签栏下缘分隔线
		RECT line = { 0, TabBarTop + TabBarHeight, width, TabBarTop + TabBarHeight + 1 };
		HBRUSH lineBrush = CreateSolidBrush(ColorBorder);
		FillRect(dc, &line, lineBrush);
		DeleteObject(lineBrush);
	}

	// -----------------------------------------------------------------
	// 日志页
	// -----------------------------------------------------------------

	// 日志行是否通过当前过滤。
	bool LogRowPassesFilter(const R3ShieldCoreStats::LogEntry& row)
	{
		if (g_logOnlyBlocked) {
			// "只看被拦" = 我们真的处置了它：拒绝（BLOCK / WOULD-BLOCK）**或**
			// 替换（SPOOF）。替换也是处置 —— 调用者没拿到真实数据。
			if (row.Decision != static_cast<ULONG>(R3ShieldCore::Decision::Blocked) &&
				row.Decision != static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock) &&
				row.Decision != static_cast<ULONG>(R3ShieldCore::Decision::Spoofed)) {
				return false;
			}
		}

		if (g_logSourceFilter != 0) {
			// 0=全部 1=注册表 2=文件 3=进程/线程 4=驱动 5=网络 6=摄像头 7=输入钩子
			// 8=截屏 9=DLL加载 10=剪贴板 11=进程旁路 12=服务权限 13=COM 14=计划任务
			const ULONG type = row.ObjectType;
			const bool isRegistry = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::Registry));
			const bool isFile = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::File));
			const bool isProcOrThread =
				(type == static_cast<ULONG>(R3ShieldCore::ObjectType::Process)) ||
				(type == static_cast<ULONG>(R3ShieldCore::ObjectType::Thread));
			const bool isDriver = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::Driver));
			const bool isNetwork = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::Network));
			const bool isCamera = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::Camera));
			const bool isInputHook = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::InputHook));
			const bool isScreen = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::Screen));
			const bool isDllLoad = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::DllLoad));
			const bool isClipboard = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::Clipboard));
			const bool isSpawn = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::ProcessSpawn));
			const bool isServiceConfig = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::ServiceConfig));
			const bool isComHijack = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::ComHijack));
			const bool isScheduledTask = (type == static_cast<ULONG>(R3ShieldCore::ObjectType::ScheduledTask));

			switch (g_logSourceFilter) {
			case 1: if (!isRegistry) { return false; } break;
			case 2: if (!isFile) { return false; } break;
			case 3: if (!isProcOrThread) { return false; } break;
			case 4: if (!isDriver) { return false; } break;
			case 5: if (!isNetwork) { return false; } break;
			case 6: if (!isCamera) { return false; } break;
			case 7: if (!isInputHook) { return false; } break;
			case 8: if (!isScreen) { return false; } break;
			case 9: if (!isDllLoad) { return false; } break;
			case 10: if (!isClipboard) { return false; } break;
			case 11: if (!isSpawn) { return false; } break;
			case 12: if (!isServiceConfig) { return false; } break;
			case 13: if (!isComHijack) { return false; } break;
			case 14: if (!isScheduledTask) { return false; } break;
			default: break;
			}
		}

		return true;
	}

	// 把事件流拉到本地镜像。按需增量读，避免每帧全量拷贝 2000 行。
	void RefreshLogRows()
	{
		ULONG latest = R3ShieldCoreStats::GetLatestLogSerial();

		// 引擎重置过（序号回退）或本地还没数据 —— 重新拉一整屏。
		if (latest < g_logLastSerial || g_logRows.empty()) {
			g_logRows.clear();
			g_logLastSerial = 0;
		}

		if (latest == g_logLastSerial) {
			return;
		}

		// 一次最多拉 512 条；高速率下会分几帧追上去，但界面不会被卡住。
		R3ShieldCoreStats::LogChunk chunk = R3ShieldCoreStats::GetLogsSince(g_logLastSerial, 512);
		if (chunk.Entries.empty()) {
			g_logLastSerial = chunk.LatestSerial;
			return;
		}

		// 序号不连续说明中间的行已被环形缓冲覆盖，本地镜像要丢掉旧段，
		// 否则会出现"新行接在早已过期的旧行后面"的错乱。
		if (!g_logRows.empty() && chunk.Entries.front().Serial > g_logLastSerial + 1) {
			g_logRows.clear();
		}

		for (auto& entry : chunk.Entries) {
			g_logRows.push_back(std::move(entry));
		}

		// 本地镜像保留上限，比环形缓冲略大一点，够滚动回看即可。
		constexpr size_t MirrorLimit = R3ShieldCoreStats::LogCapacity + 512;
		if (g_logRows.size() > MirrorLimit) {
			g_logRows.erase(g_logRows.begin(), g_logRows.begin() +
				static_cast<ptrdiff_t>(g_logRows.size() - MirrorLimit));
		}

		g_logLastSerial = chunk.LatestSerial;
	}

	void DrawLogPage(HDC dc, const RECT& client)
	{
		RefreshLogRows();

		const int top = TabBarTop + TabBarHeight + 1;
		const int bottom = client.bottom - PromptSummaryHeight() - 8;

		// ---- 表头 ----
		const int contentLeft = Padding;
		const int contentRight = client.right - Padding;

		const int colTime = contentLeft;
		const int colSource = colTime + LogColTimeWidth;
		const int colProcess = colSource + LogColSourceWidth;
		const int colOp = colProcess + LogColProcessWidth;
		const int colTarget = colOp + LogColOpWidth;
		const int colStatus = contentRight - LogColStatusWidth;

		RECT headerRect = { contentLeft, top, contentRight, top + LogHeaderHeight };
		HBRUSH headerBrush = CreateSolidBrush(ColorHeaderBackground);
		FillRect(dc, &headerRect, headerBrush);
		DeleteObject(headerBrush);

		RECT timeHeader = { colTime, top + 4, colSource, top + LogHeaderHeight };
		DrawTextSimple(dc, L"时间", timeHeader, g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

		RECT sourceHeader = { colSource, top + 4, colProcess, top + LogHeaderHeight };
		DrawTextSimple(dc, L"来源", sourceHeader, g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

		RECT procHeader = { colProcess, top + 4, colOp, top + LogHeaderHeight };
		DrawTextSimple(dc, L"进程", procHeader, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		RECT opHeader = { colOp, top + 4, colTarget - 4, top + LogHeaderHeight };
		DrawTextSimple(dc, L"操作", opHeader, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		RECT targetHeader = { colTarget, top + 4, colStatus - 6, top + LogHeaderHeight };
		DrawTextSimple(dc, L"目标（键 / 文件 / 进程）", targetHeader, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		RECT statusHeader = { colStatus, top + 4, contentRight, top + LogHeaderHeight };
		DrawTextSimple(dc, L"状态", statusHeader, g_labelFont, ColorTextSecondary,
			DT_RIGHT | DT_SINGLELINE);

		RECT headerLine = { 0, top + LogHeaderHeight, client.right, top + LogHeaderHeight + 1 };
		HBRUSH lineBrush = CreateSolidBrush(ColorBorder);
		FillRect(dc, &headerLine, lineBrush);
		DeleteObject(lineBrush);

		// ---- 行区 ----
		const int rowsTop = top + LogHeaderHeight + 1;
		const int rowsHeight = bottom - rowsTop;
		int visibleRows = rowsHeight / LogRowHeight;
		if (visibleRows < 1) {
			visibleRows = 1;
		}

		// 过滤后可见的行（只有拦截过滤这一种，代价很小）。
		std::vector<const R3ShieldCoreStats::LogEntry*> visible;
		visible.reserve(g_logRows.size());
		for (const auto& row : g_logRows) {
			if (LogRowPassesFilter(row)) {
				visible.push_back(&row);
			}
		}

		if (visible.empty()) {
			RECT emptyRect = { contentLeft, rowsTop + 16, contentRight, rowsTop + 44 };
			DrawTextSimple(dc, g_logRows.empty() ? L"(暂无事件)" : L"(当前过滤条件下没有记录)",
				emptyRect, g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		}
		else {
			// 滚动位置：g_logScroll 是从尾部往前的行数。
			int maxScroll = static_cast<int>(visible.size()) - visibleRows;
			if (maxScroll < 0) {
				maxScroll = 0;
			}
			if (g_logScroll > maxScroll) {
				g_logScroll = maxScroll;
			}
			if (g_logScroll < 0) {
				g_logScroll = 0;
			}

			int end = static_cast<int>(visible.size()) - g_logScroll;
			int start = end - visibleRows;
			if (start < 0) {
				start = 0;
			}

			for (int i = start; i < end; i++) {
				const R3ShieldCoreStats::LogEntry& row = *visible[i];
				int rowTop = rowsTop + (i - start) * LogRowHeight;

				// ★ v54：历史行（上一轮会话回放出来的）用更暗的底色 + 左侧
				//   加一个"史"字标记，和本次会话的行区分开。
				const bool isHistoryRow =
					row.Serial <= R3ShieldCoreStats::HistoryCount();

				// 交替底色，方便横向对行
				if (isHistoryRow || (i - start) % 2 == 1) {
					RECT alt = { 0, rowTop, client.right, rowTop + LogRowHeight };
					HBRUSH altBrush = CreateSolidBrush(
						isHistoryRow ? ColorLogRowHistory : ColorLogRowAlt);
					FillRect(dc, &alt, altBrush);
					DeleteObject(altBrush);
				}

				// 左侧 3px 色条标决策，比整行染色克制得多
				COLORREF decisionColor = DecisionColor(static_cast<R3ShieldCore::Decision>(row.Decision));
				RECT stripe = { 0, rowTop + 2, 3, rowTop + LogRowHeight - 2 };
				HBRUSH stripeBrush = CreateSolidBrush(decisionColor);
				FillRect(dc, &stripe, stripeBrush);
				DeleteObject(stripeBrush);

				int textTop = rowTop + 3;
				int textBottom = rowTop + LogRowHeight - 1;

				RECT timeRect = { colTime, textTop, colSource - 4, textBottom };
				DrawTextSimple(dc, FormatLogTime(row.TimeStamp).c_str(), timeRect, g_logFont,
					ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

				// 来源列：注册表 / 文件 / 进程 / 线程 / 驱动。各用一个颜色，
				// 一眼能区分事件类型。
				RECT sourceRect = { colSource, textTop, colProcess - 4, textBottom };
				DrawTextSimple(dc, ObjectTypeLabel(row.ObjectType), sourceRect, g_logFont,
					ObjectTypeColor(row.ObjectType), DT_LEFT | DT_SINGLELINE);

				std::wstring process = row.ProcessName.empty()
					? (L"PID " + std::to_wstring(row.ProcessId))
					: (row.ProcessName + L" (" + std::to_wstring(row.ProcessId) + L")");
				RECT procRect = { colProcess, textTop, colOp - 6, textBottom };
				DrawTextSimple(dc, process.c_str(), procRect, g_logFont, ColorTextPrimary,
					DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

				WCHAR opName[64] = {};
				MultiByteToWideChar(CP_ACP, 0, R3ShieldCore::AnyOpName(row.ObjectType, row.Op),
					-1, opName, _countof(opName));

				// 被我们自己拦下的加个前缀，一眼区分"系统本来就不让"和"我们不让"
				// 高危命中的再加一个 [危] —— 这种事件要能一眼从滚动列表里挑出来。
				std::wstring opText = opName;
				// ★ v54：历史行加 [史] 前缀（底色已经很淡，再加个字更稳）。
				if (isHistoryRow) {
					opText = L"[史] " + opText;
				}
				if (row.BlockedByUs) {
					opText = L"[拦] " + opText;
				}
				if (row.IsHighRisk) {
					opText = L"[危] " + opText;
				}

				// 高危行的操作名用警示红，其余仍按决策色。
				const COLORREF opColor = row.IsHighRisk ? ColorHighRisk : decisionColor;

				RECT opRect = { colOp, textTop, colTarget - 6, textBottom };
				DrawTextSimple(dc, opText.c_str(), opRect, g_logFont, opColor,
					DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

				// 目标列：
				//   键级     → 键路径 \ 值名
				//   hive 级  → 键路径 ← hive 文件
				//   文件     → 路径（Value 放的是改名后的新名字，用 → 连）
				//   驱动     → .sys 路径（Value 放服务名，用 ← 连）
				//   进程     → 镜像路径 + (pid)
				//   线程     → 目标进程镜像路径 + (pid)
				const auto rowType = static_cast<R3ShieldCore::ObjectType>(row.ObjectType);
				const bool isFile = (rowType == R3ShieldCore::ObjectType::File);

				std::wstring target = row.Target;
				if (rowType == R3ShieldCore::ObjectType::Process ||
					rowType == R3ShieldCore::ObjectType::Thread) {
					if (row.TargetProcessId != 0) {
						target += L"  (" + std::to_wstring(row.TargetProcessId) + L")";
					}
				}
				else if (!row.Value.empty()) {
					if (isFile) {
						target += L"  → " + row.Value;
					}
					else if (rowType == R3ShieldCore::ObjectType::Driver) {
						target += L"   ← " + row.Value;  // ← 服务名
					}
					else {
						target += row.IsHive ? (L"   ← " + row.Value) : (L"\\" + row.Value);
					}
				}
				if (target.empty()) {
					target = L"(未解析)";
				}

				RECT targetRect = { colTarget, textTop, colStatus - 6, textBottom };
				DrawTextSimple(dc, target.c_str(), targetRect, g_logFont, ColorTextPrimary,
					DT_LEFT | DT_SINGLELINE | DT_PATH_ELLIPSIS);

				// 状态码只在非零时画。ALLOW 行的 status 基本都是 0
				// （STATUS_SUCCESS），画满一列 0 只是噪音 —— 真正要看的是
				// "被拒绝时到底是哪个错"，所以非零才醒目地标出来。
				//
				// 只画低 16 位：NTSTATUS 的低 16 位就是对应的 Win32 错误码
				// （0xC0000022 -> 5 = 拒绝访问），4 位十六进制够用且放得下。
				if (row.Status != 0) {
					WCHAR statusText[16] = {};
					swprintf_s(statusText, L"%04X", row.Status & 0xFFFF);
					RECT statusRect = { colStatus, textTop, contentRight, textBottom };
					DrawTextSimple(dc, statusText, statusRect, g_logFont, ColorBlocked,
						DT_RIGHT | DT_SINGLELINE);
				}
			}
		}

		// ---- 左下角状态：条数 / 过滤 / 滚动提示 ----
		WCHAR info[256] = {};
		ULONG total = R3ShieldCoreStats::GetLatestLogSerial();

		PCWSTR sourceText = L"";
		switch (g_logSourceFilter) {
		case 1: sourceText = L"  ·  仅注册表"; break;
		case 2: sourceText = L"  ·  仅文件"; break;
		case 3: sourceText = L"  ·  仅进程/线程"; break;
		case 4: sourceText = L"  ·  仅驱动"; break;
		case 5: sourceText = L"  ·  仅网络"; break;
		case 6: sourceText = L"  ·  仅摄像头"; break;
		case 7: sourceText = L"  ·  仅输入钩子"; break;
		case 8: sourceText = L"  ·  仅截屏"; break;
		case 9: sourceText = L"  ·  仅 DLL 加载"; break;
		case 10: sourceText = L"  ·  仅剪贴板"; break;
		case 11: sourceText = L"  ·  仅进程旁路"; break;
		case 12: sourceText = L"  ·  仅服务权限"; break;
		case 13: sourceText = L"  ·  仅 COM 劫持"; break;
		case 14: sourceText = L"  ·  仅计划任务"; break;
		default: break;
		}

		// 可点击的两个过滤开关：左边「只看拦截」，右边「来源切换」。
		// 提示文字就是反馈 —— 自绘界面没有控件状态可看，只能把状态写出来。
		//
		// ★ v54：把「历史」和「本次」拆开写。用户点「超级置顶」会整体换引擎，
		//   界面上的行会由"读回来的历史"接成一条连续的列表；
		//   不标明来源的话，看到几十条"自己没做过"的记录会以为是别人的。
		const size_t historyCount = R3ShieldCoreStats::HistoryCount();
		const ULONG liveCount = (total > historyCount)
			? static_cast<ULONG>(total - historyCount) : 0;
		PCWSTR historyText = (historyCount > 0) ? L"  ·  含上次会话历史" : L"";

		if (g_logOnlyBlocked) {
			swprintf_s(info, L"只显示拦截%s%s  ·  共 %u 条（历史 %u / 本次 %u）  ·  已滚回 %d 行%s",
				sourceText, historyText, total,
				static_cast<unsigned>(historyCount), liveCount,
				g_logScroll, g_logFollowTail ? L"" : L"（按 End 回到底部）");
		}
		else {
			swprintf_s(info, L"全部事件%s%s  ·  共 %u 条（历史 %u / 本次 %u）%s",
				sourceText, historyText, total,
				static_cast<unsigned>(historyCount), liveCount,
				g_logFollowTail ? L"" : L"  ·  已暂停跟随（按 End 回到底部）");
		}

		const int infoTop = client.bottom - PromptSummaryHeight();
		RECT separator = { Padding, infoTop, ClientWidth() - Padding, infoTop + 1 };
		HBRUSH sepBrush = CreateSolidBrush(ColorBorder);
		FillRect(dc, &separator, sepBrush);
		DeleteObject(sepBrush);

		RECT infoRect = { Padding, infoTop + 8, ClientWidth() - Padding, infoTop + 42 };
		DrawTextSimple(dc, info, infoRect, g_labelFont, ColorTextSecondary,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	void PaintWindow(HWND hwnd)
	{
		PAINTSTRUCT ps = {};
		HDC dc = BeginPaint(hwnd, &ps);

		RECT client = {};
		GetClientRect(hwnd, &client);
		if (client.right <= 0 || client.bottom <= 0) {
			EndPaint(hwnd, &ps);
			return;
		}

		// -----------------------------------------------------------------
		// ★ v83 液态玻璃：先把"背景 + 面板"这一层准备好，再在上面画内容。
		//
		//   玻璃层的内容 = 窗口后方的真实桌面（捕获，已模糊）+ 各面板的
		//   圆角折射/色散/rim/投影。它**不含**任何文字与表格 —— 那些属于内容层，
		//   每帧都要重画（ARK 页 300ms 一刷）。这个切分是性能的关键。
		//
		//   `Begin()` 返回 false（`R3SHIELDCORE_GLASS=off` 或缓冲区建不起来）
		//   ⇒ 走原来的不透明渐变路径，一像素都不变（现场一键回退靠它）。
		// -----------------------------------------------------------------
		const float dpi = GlassDpiScale(hwnd);
		const bool wantBackdrop = g_glassWantBackdrop ||
			(GetTickCount64() - g_glassMovedAt) < 1200;   // 拖动/缩放期间持续刷新
		g_glass.headerBand = TabBarTop + TabBarHeight;   // 顶栏 + 页签条共用一块薄纱
		g_glass.headerVeil = 0.20f;

		// ★ 风格门：经典模式下**不进**玻璃层（`active` 保持 false ⇒ 走老绘制路径）。
		const bool glassWanted = (g_uiStyle == Style::Glass);
		if (!glassWanted) {
			g_glass.active = false;
		}
		if (glassWanted) {
			// GPU 就绪就走 GL；否则 glCompose 为空 ⇒ CPU 合成（ui_material.h）。
			if (g_gl.Ready()) {
				g_glass.glCompose = GlComposeBridge;
				g_glass.glCtx = &g_gl;
			} else {
				g_glass.glCompose = nullptr;
			}
		}
		if (glassWanted && g_glass.Begin(hwnd, client.right, client.bottom, dpi, wantBackdrop)) {
			g_glassWantBackdrop = false;
			if (!g_glassLogged) {
				g_glassLogged = true;
				printf("[glass] 液态玻璃已就绪 背景=%ls 后端=%ls 尺寸=%dx%d dpi=%.2f 标记=%ls\n",
					R3ShieldCoreUi::BackdropSourceName(g_glass.backdrop.source),
					g_glass.backend == 1 ? L"OpenGL" : L"CPU",
					client.right, client.bottom, static_cast<double>(dpi),
					R3ShieldCoreUi::kGenerationMarker);
			}
		} else if (glassWanted) {
			static int s_glassFailLogged = 0;
			if (s_glassFailLogged < 3) {
				++s_glassFailLogged;
				printf("[glass] 诊断：Begin 失败 active=%d enabled=%d client=%dx%d stage=%d\n",
					g_glass.active ? 1 : 0, R3ShieldCoreUi::GlassEnabled() ? 1 : 0,
					client.right, client.bottom, g_glass.failStage);
			}
		}

		// -----------------------------------------------------------------
		// 双缓冲载体：**始终**是兼容位图（与改造前完全一致）。
		//
		// ★★ 为什么不在玻璃层的 32bpp DIB 上直接画内容（踩过）：
		//   GDI 的 ClearType 在 `CreateDIBSection` 出来的 32bpp 表面上**渲染不出
		//   深色字** —— 实测整屏文字变成白色（浅底上几乎看不见），而且不报任何错。
		//   ⇒ 玻璃层只当"背景图"用，`BitBlt` 到兼容位图，内容还是画在兼容位图上。
		//   代价是多一次整幅拷贝（~1ms），换来的是文字渲染路径零变化。
		// -----------------------------------------------------------------
		HDC buffer = CreateCompatibleDC(dc);
		HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
		HGDIOBJ oldBitmap = SelectObject(buffer, bitmap);

		if (g_glass.active) {
			// 玻璃层（背景 + 面板）已成品，直接盖到双缓冲上，随后画内容。
			BitBlt(buffer, 0, 0, client.right, client.bottom, g_glass.layer.dc, 0, 0, SRCCOPY);
		} else {
			// ---- 兜底：原来的不透明渐变（`R3SHIELDCORE_GLASS=off` / 玻璃不可用）----
			TRIVERTEX bodyVertices[2] = {
				{ 0, 0, 0xF100, 0xF700, 0xFC00, 0x0000 },
				{ client.right, client.bottom, 0xE800, 0xF100, 0xFA00, 0x0000 }
			};
			GRADIENT_RECT bodyGradient = { 0, 1 };
			GradientFill(buffer, bodyVertices, 2, &bodyGradient, 1, GRADIENT_FILL_RECT_V);

			RECT header = { 0, 0, client.right, 62 };
			TRIVERTEX headerVertices[2] = {
				{ 0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0x0000 },
				{ client.right, 62, 0xF500, 0xFA00, 0xFF00, 0x0000 }
			};
			GRADIENT_RECT headerGradient = { 0, 1 };
			GradientFill(buffer, headerVertices, 2, &headerGradient, 1, GRADIENT_FILL_RECT_V);
		}

		// 标题文字区右边界要给右侧的「默认置顶 / 超级置顶 / 模式徽章」让位，
		// 否则拉宽/收窄时文字会钻到按钮底下。
		const int headerTextRight = TopMostButtonRect().left - 16;
		RECT headerText = { Padding, 14, headerTextRight, 38 };
		DrawTextSimple(buffer, GuiTitle, headerText, g_titleFont, ColorTextPrimary,
			DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
		RECT subtitle = { Padding, 38, headerTextRight, 56 };
		DrawTextSimple(buffer, L"实时行为监控  ·  注入状态  ·  高危决策  ·  事件取证",
			subtitle, g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);

		DrawTopMostButtons(buffer);
		DrawModeBadge(buffer, ModeBadgeTop);

		RECT headerLine = { 0, 61, client.right, 62 };
		HBRUSH lineBrush = CreateSolidBrush(ColorBorder);
		FillRect(buffer, &headerLine, lineBrush);
		DeleteObject(lineBrush);

		// 页签栏在标题区下方，六个页面共用。
		DrawTabBar(buffer);

		if (g_activeTab == 1) {
			DrawLogPage(buffer, client);
		}
		else if (g_activeTab == 2) {
			DrawProcessPage(buffer, client);
		}
		else if (g_activeTab == 3) {
			DrawConfigPage(buffer, client);
		}
		else if (g_activeTab == 4) {
			DrawArkPage(buffer, client);
		}
		else if (g_activeTab == 5) {
			// ★ v80：「高级」页 —— 只剩一个"跳转到 cfg"的按钮（见上方注释）。
			DrawAdvancedPage(buffer, client);
		}
		else {
			R3ShieldCoreStats::Snapshot snapshot = R3ShieldCoreStats::GetSnapshot();
			ULONG injectedTotal = static_cast<ULONG>(InterlockedCompareExchange(&g_injectedTotal, 0, 0));

			// 布局：底部询问统计栏固定贴底占 PromptSummaryHeight()，
			// 「操作分布」和「触发最多的进程」在这之上平分剩余空间。
			// 窗口可以被拉小（WS_THICKFRAME），所以行数必须按真实客户区高度算，
			// 否则底部那一栏会被内容顶出可视区。
			const int contentBottom = client.bottom - PromptSummaryHeight() - 8;
			constexpr int rowsPerSection = 6;              // 每段最多 6 行
			constexpr int rowHeight = 24;                  // 每行 24px
			constexpr int sectionHeaderHeight = 26 + 12;   // 标题 26 + 尾部间距 12

			// 起点要从页签栏下方开始，否则概览会被页签压住。
			int y = TabBarTop + TabBarHeight + 20;
			DrawOverview(buffer, y, snapshot, injectedTotal);
			DrawDecisionBreakdown(buffer, y, snapshot);

			// 两段都要画，先给每段留出标题高度，剩下的行数平均分。
			int remaining = contentBottom - y - sectionHeaderHeight * 2;
			int rows = remaining > 0 ? remaining / (rowHeight * 2) : 0;
			if (rows > rowsPerSection) {
				rows = rowsPerSection;
			}
			if (rows < 0) {
				rows = 0;
			}

			DrawOpBreakdown(buffer, y, snapshot, rows);
			DrawTopProcesses(buffer, y, snapshot, rows);
			DrawPromptSummary(buffer, client.bottom, snapshot);
		}

		// ★ 诊断：设了 `R3SHIELDCORE_GLASS_DUMP=<路径>` 时，把本帧画好的缓冲
		//   直接落成 BMP（按帧号递增）。这条能区分「画错了」与「屏幕没抓到」。
		{
			static int s_dumpCount = 0;
			static int s_dumpOn = -1;
			if (s_dumpOn < 0) {
				s_dumpOn = GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_DUMP", nullptr, 0) > 0 ? 1 : 0;
			}
			if (s_dumpOn && s_dumpCount < 24) {
				wchar_t path[256];
				_snwprintf_s(path, _countof(path), _TRUNCATE,
					L"D:\\用户态杀软\\docs\\shots\\_f%02d.bmp", s_dumpCount);
				R3ShieldCoreUi::SaveHdcToBmp(buffer, client.right, client.bottom, path);
				++s_dumpCount;
			}
		}

		const BOOL bltOk = BitBlt(dc, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);
		if (!bltOk) {
			// 只在**失败**时留痕：正常路径每帧打日志会把控制台刷爆，
			// 而这个失败一旦发生就是"整窗空白"，必须留下线索（铁律 97）。
			static int s_bltFailLogged = 0;
			if (s_bltFailLogged < 3) {
				++s_bltFailLogged;
				printf("[paint] 警告：BitBlt 上屏失败 err=%lu（整窗会是空白）\n",
					static_cast<unsigned long>(GetLastError()));
			}
		}

		if (g_glass.active) {
			// ★ 本帧记下的面板表若与"已合成的那张"不一致 ⇒ 再刷一帧
			//   （详见 ui_material.h 里 GlassSurface::CommitPanels 的两帧收敛说明）。
			//   典型触发：切页签、窗口缩放、悬停态变化。
			if (g_glass.CommitPanels()) {
				InvalidateRect(hwnd, nullptr, FALSE);
			}
		}

		SelectObject(buffer, oldBitmap);
		DeleteObject(bitmap);
		DeleteDC(buffer);

		EndPaint(hwnd, &ps);
	}

	// 执行一个按钮动作。
	//
	// 只在 **WM_LBUTTONUP 且松手时鼠标仍停在同一个按钮上** 才调用 ——
	// 标准按钮语义。以前是"按下就执行"，那样按错了没法反悔
	//（对「退出引擎」这种破坏性动作尤其危险）。
	void PerformHeaderAction(HWND hwnd, HeaderAction action)
	{
		switch (action) {
		case HeaderAction::ExitEngine:
			// 只置位，真正的收尾在 app.cpp 主循环里做
			//（反注入 → 关窗口 → 退出进程）。界面线程绝不直接退进程 ——
			// 否则引擎还没来得及反注入，被注入的进程里会留下悬空的 hook。
			InterlockedExchange(&g_quitRequest, 1);
			return;

		case HeaderAction::CopyAllLogs:
			// 把引擎目录下所有日志的内容拼成一段文本放进剪贴板 ——
			// 用于"机器马上要报废、日志文件取不出来"的抢救场景。
			CopyAllLogsToClipboard();
			InvalidateRect(hwnd, nullptr, FALSE);
			return;

		case HeaderAction::CopyLogPath:
			CopyLogPathToClipboard();
			InvalidateRect(hwnd, nullptr, FALSE);
			return;

		case HeaderAction::ClearStats:
			R3ShieldCoreStats::Reset();
			g_logRows.clear();
			g_logLastSerial = 0;
			g_logScroll = 0;
			g_logFollowTail = true;
			InvalidateRect(hwnd, nullptr, FALSE);
			return;

		case HeaderAction::ModeSwitch: {
			// 只把目标模式放进 g_pendingMode，真正的切换在引擎主循环里做
			//（界面线程不碰引擎状态）。徽章要等引擎确认后再变 ——
			// 免得切失败了界面却显示成功。
			const R3ShieldCore::Mode next = NextMode(
				static_cast<R3ShieldCore::Mode>(InterlockedCompareExchange(&g_displayMode, 0, 0)));
			InterlockedExchange(&g_pendingMode, static_cast<LONG>(next));
			return;
		}

		// 「默认置顶」：已经是普通档 → 再点一次取消；否则切到普通档
		//（从超级档点这里就是"降级为普通置顶"）。
		case HeaderAction::TopMostNormal:
			ApplyTopMostLevel(g_topMost && !g_superTopMost ? 0 : 1);
			return;

		// 「超级置顶」：开着 → 再点一次取消；否则切到超级档。
		case HeaderAction::TopMostSuper:
			ApplyTopMostLevel(g_superTopMost ? 0 : 2);
			return;

		default:
			return;
		}
	}

	// =====================================================================
	//  托盘（关闭窗口 = 收进通知区）
	//
	//   用户 2026-10-17 要求：关闭窗口 → 最小化/收进托盘。
	//   两个 exe 共用 `shared/r3shieldcore/tray_icon.h`（铁律 127）。
	//
	//   ★★ 这套东西里**最要紧**的一条：必须有一个**能真正退出**的入口。
	//      窗口收起来之后看不出它还在跑；没有退出入口 = "关不掉的程序"，
	//      用户只能去任务管理器强杀，而强杀会跳过引擎收尾（铁律 107）。
	//      ⇒ 托盘右键菜单："显示窗口" / "退出引擎" / "退出"（退出要二次确认）。
	// =====================================================================

	// 当前该用哪个图标/提示（状态文字必须**如实**反映引擎在不在跑 ——
	// 图标收起来了，托盘提示就是用户唯一的信息来源，铁律 97）。
	HICON TrayCurrentIcon()
	{
		// ★ 用窗口类图标（exe 资源里那个），而不是系统默认图标。
		//   取不到就退回 IDI_APPLICATION，至少不出现空白方框。
		HICON icon = LoadAppIcon(GetSystemMetrics(SM_CXSMICON),
			GetSystemMetrics(SM_CYSMICON));
		return icon ? icon : ::LoadIconW(nullptr, IDI_APPLICATION);
	}

	std::wstring TrayTipText()
	{
		std::wstring tip = L"R3 ShieldCore 安全控制台 — 监控运行中";
		if (g_quitRequest) {
			tip += L"（引擎已停）";
		}
		tip += L"\n双击显示窗口，右键更多操作。";
		return tip;
	}

	// 把窗口收进托盘。**已经收着**时是幂等的（重复点关闭不会有副作用）。
	void TrayHideToTray(HWND hwnd)
	{
		if (!g_tray.icon.added()) {
			// ★ 图标没加上就**不要隐藏**：那样窗口会从任务栏和托盘
			//   **同时**消失，用户彻底找不到它 —— 这比"没实现托盘"还糟。
			//   宁可退回到旧行为（最小化到任务栏）。
			printf("[tray] 图标未就绪，退回最小化到任务栏（不隐藏，免得窗口找不到）\n");
			ShowWindow(hwnd, SW_MINIMIZE);
			return;
		}
		const bool firstTime = !g_tray.windowHidden;
		ShowWindow(hwnd, SW_HIDE);
		g_tray.windowHidden = true;
		g_tray.icon.SetTip(TrayTipText());
		printf("[tray] 窗口已收进托盘（进程仍在运行）\n");

		// ★ 只弹**第一次**：每次关闭都弹的话，第二次起就是打扰
		//   （而用户关通知之后，真正要紧的提示也一起被关掉了）。
		if (firstTime) {
			g_tray.icon.Balloon(L"仍在后台运行",
				L"窗口已收进托盘，监控与拦截仍在生效。\n"
				L"双击托盘图标可重新打开；右键可退出。");
		}
	}

	// 从托盘恢复窗口。
	//
	// ★ 这里**不能用** `SetForegroundWindow` 了事：本进程可能是被别的窗口
	//   激活起来的，前台锁会拒绝它（铁律 256 踩过同一个坑）。
	//   用 `SetWindowPos(HWND_TOPMOST → HWND_NOTOPMOST)` 抬 z 序不需要前台权；
	//   `SetForegroundWindow` 只作为"能拿到就拿"的补充。
	void TrayRestoreFromTray(HWND hwnd)
	{
		ShowWindow(hwnd, SW_SHOW);
		if (IsIconic(hwnd)) {
			ShowWindow(hwnd, SW_RESTORE);
		}
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
		SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
		SetForegroundWindow(hwnd);
		SetFocus(hwnd);
		g_tray.windowHidden = false;
		g_tray.icon.SetTip(TrayTipText());
		printf("[tray] 窗口已从托盘恢复\n");
	}

	// 真正退出：先让引擎收尾，再销毁窗口（走 WM_DESTROY → 摘图标）。
	void TrayExitRequested(HWND hwnd)
	{
		// ★★ 二次确认是**必须**的（用户明确要求）。
		//
		//   理由不是"礼貌"，是**后果确实重**：退出后驱动/服务仍会按策略
		//   把引擎重新拉起来（开机自启那套），用户以为"关掉了"而实际没关
		//   —— 不如把话说明白，让他自己决定。
		//   ✓/✗ 用图标而不是只靠文字：中文按钮容易被一眼扫过（铁律 239 家族）。
		const int r = MessageBoxW(hwnd,
			L"退出后将停止监控与拦截，本程序窗口会关闭。\n\n"
			L"（注意：如果引擎由开机自启服务托管，服务可能会再次把它拉起来。）\n\n"
			L"确定要退出吗？",
			L"退出 R3 ShieldCore", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
		if (r != IDYES) {
			printf("[tray] 用户取消了退出\n");
			return;
		}
		printf("[tray] 用户确认退出\n");
		g_tray.reallyExiting = true;
		// ★★ 只置位请求，**不要**在这里 `DestroyWindow` —— 界面线程绝不直接
		//    退进程/毁窗口（见上面 `PerformHeaderAction` 的同款注释）：
		//    真正的收尾顺序是 app.cpp 主循环 `TakeQuitRequest()` → break →
		//    EngineControl 析构（**反注入**，把挂起的进程恢复回去）→
		//    `R3ShieldCoreGui::Stop()` → 关窗口 → 退出进程（铁律 107：
		//    强杀/乱序退出测不出收尾，必须走**有序**那条路）。
		//    ⚠️ 第一版写成了"设标志 + DestroyWindow(hwnd)" —— 那会让 GUI 窗口
		//       在反注入**之前**就被毁掉，等于绕过了有序收尾（正是这条铁律要防的）。
		InterlockedExchange(&g_quitRequest, 1);
	}

	// 托盘图标的回调（鼠标事件都塞在 `lParam` 里 —— 这是 NOTIFYICON_VERSION_4 的约定）。
	void HandleTrayMessage(HWND hwnd, LPARAM lParam)
	{
		switch (LOWORD(lParam)) {
		case WM_LBUTTONUP:
		case WM_LBUTTONDBLCLK:
			// 双击（或单击左键抬起）还原窗口。用户选的是"还原并激活"。
			TrayRestoreFromTray(hwnd);
			return;

		case WM_RBUTTONUP:
		case WM_CONTEXTMENU: {
			// ★ 菜单只放两项：「显示窗口」/「退出」。
			//
			//   ⚠️ 一开始还想加一项「退出引擎」（引擎在跑时显示）—— 想通了才发现
			//      那是**误导**：本程序的"退出引擎"和"退出程序"走的是**同一条**
			//      收尾路径（`g_quitRequest` → break → 反注入 → 关窗口 → 退进程，
			//      见 app.cpp 1114）。两个菜单项做同一件事、后果却写着不一样，
			//      用户会以为"退出引擎只是停引擎、窗口还在"。⇒ 只留「退出」。
			//      （铁律 265 家族：同一个语义不要用两个入口表达。）
			// ★ v84：多一项「界面：…」—— 两套界面的切换入口就在这里。
			//   标签写**目标**（点下去会变成什么），不是当前状态：
			//   "界面：经典" 读作"切到经典"，比"当前：液态玻璃"少一次心算。
			const std::wstring uiLabel = R3ShieldCoreUi::ToggleLabel(g_uiStyle);
			const R3ShieldCoreTray::TrayMenuAction act =
				R3ShieldCoreTray::ShowTrayMenu(hwnd,
					L"显示窗口",
					false,   // 不给独立的「退出引擎」项（见上）
					L"",
					uiLabel);
			switch (act) {
			case R3ShieldCoreTray::TrayMenuAction::ToggleUi: {
				// 切风格：先落盘（下次启动保持），再清掉玻璃缓存重新构图。
				g_uiStyle = (g_uiStyle == Style::Glass) ? Style::Classic : Style::Glass;
				R3ShieldCoreUi::SaveStyle(g_uiStyle);
				g_glass.Shutdown();
				g_glassWantBackdrop = true;
				printf("[ui] 界面风格切换为：%ls\n", R3ShieldCoreUi::StyleName(g_uiStyle));
				InvalidateRect(hwnd, nullptr, FALSE);
				return;
			}
			case R3ShieldCoreTray::TrayMenuAction::ShowWindow:
				TrayRestoreFromTray(hwnd);
				return;
			case R3ShieldCoreTray::TrayMenuAction::Exit:
				TrayExitRequested(hwnd);
				return;
			default:
				return;
			}
		}
		default:
			return;
		}
	}

	LRESULT CALLBACK GuiWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		// ★ 托盘回调消息 —— **必须**在 switch **之前**用 if 判断（铁律 **250**）。
		//
		//   它的 id 是 `RegisterWindowMessageW` 在**运行时**算出来的
		//   （0xC000~0xFFFF 区间），**不是编译期常量** ⇒ 当不了 `case` 标签
		//   （写成 case 直接编不过，或者被当成重复常量）。
		if (message == g_tray.icon.callbackMessage()) {
			HandleTrayMessage(hwnd, lParam);
			return 0;
		}

		// ★ explorer 重启（崩溃重开 / 手动重启）后，通知区被清空 ——
		//   shell 会向所有**顶层窗口**广播 `TaskbarCreated`，收到就得把图标加回去。
		//   不处理这条的话，图标一旦消失就再也不回来，而窗口可能已经收进托盘了
		//   ⇒ **用户再也找不到这个程序**（没有窗口、也没有图标）。
		//   ⚠️ 这个消息名同样要 `RegisterWindowMessageW`（运行时 id ⇒ 又是 if 不能 case）。
		{
			static const UINT taskbarCreated = ::RegisterWindowMessageW(L"TaskbarCreated");
			if (message == taskbarCreated) {
				if (g_tray.icon.Add(hwnd, TrayCurrentIcon(), TrayTipText(),
						R3ShieldCoreTray::kCallbackMessageMain)) {
					printf("[tray] explorer 重启，托盘图标已重新加入\n");
				} else {
					printf("[tray] explorer 重启后重新添加托盘图标失败\n");
				}
				return 0;
			}
		}

		switch (message) {
		case WM_ERASEBKGND:
			return 1;

		case WM_DWMCOMPOSITIONCHANGED:
			ApplyGlassWindow(hwnd);
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;

		case WM_GETMINMAXINFO: {
			MINMAXINFO* info = reinterpret_cast<MINMAXINFO*>(lParam);
			// 最小宽度 1040：页签占满左侧（Padding 20 + 5×(84+8) - 8 = 472），
			// 右侧动作簇现在有 5 个按钮（退出引擎 / 复制全部日志 / 复制日志路径 /
			// 清空统计 / 切换模式），最左的「退出引擎」左边界 = 客户区宽 - 532。
			// 472 + 532 = 1004，再加边框与非客户区 ⇒ 窗口 1040。
			// （v62：4 个页签时是 980；加 ARK 页签后必须同步抬高，否则
			//   最小宽度下页签会压到「退出引擎」上。）
			info->ptMinTrackSize.x = 1040;
			info->ptMinTrackSize.y = 640;
			return 0;
		}

		case WM_PAINT:
			PaintWindow(hwnd);
			return 0;

		// -----------------------------------------------------------------
		// ★ v83：移动/缩放/DPI 变更 ⇒ 背景必须重抓
		//
		//   "背景"是**窗口后方那块屏幕内容**的快照，窗口一动它就对不上了
		//   （玻璃里显示的会是旧位置的桌面）。所以这三个消息都要把
		//   `g_glassWantBackdrop` 置起来、并记下时间 —— 后者让 PaintWindow
		//   在拖动过程中**持续**刷新（静止 1.2 秒后自动停，省 CPU）。
		// -----------------------------------------------------------------
		case WM_MOVE:
		case WM_SIZE:
			if (g_glass.active) {
				g_glassWantBackdrop = true;
				g_glassMovedAt = GetTickCount64();
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;

		case WM_DPICHANGED: {
			// 缩放比例变了 ⇒ 材质参数（圆角/折射带宽/投影半径）全部要按新 DPI 重算。
			// `Begin()` 里比对 dpi 会自己重建，这里只要把背景标记脏。
			g_glassWantBackdrop = true;
			g_glass.InvalidateLayer();
			RECT* suggested = reinterpret_cast<RECT*>(lParam);
			if (suggested) {
				SetWindowPos(hwnd, nullptr,
					suggested->left, suggested->top,
					suggested->right - suggested->left,
					suggested->bottom - suggested->top,
					SWP_NOZORDER | SWP_NOACTIVATE);
			}
			return 0;
		}

		case WM_DISPLAYCHANGE:
		case WM_THEMECHANGED:
			g_glassWantBackdrop = true;
			if (g_glass.active) {
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;

		case WM_MOUSEMOVE: {
			// 登记 WM_MOUSELEAVE。不登记的话鼠标移出窗口收不到通知，
			// 悬停态会永远留在最后碰到的那个按钮上（"假悬停"）。
			if (!g_trackingMouseLeave) {
				TRACKMOUSEEVENT track = {};
				track.cbSize = sizeof(track);
				track.dwFlags = TME_LEAVE;
				track.hwndTrack = hwnd;
				if (TrackMouseEvent(&track)) {
					g_trackingMouseLeave = true;
				}
			}

			const POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
			const HeaderAction hovered = HitTestHeaderAction(point);
			// 页签单独判：它和按钮不同行，也不共用 HeaderAction。
			const int hoveredTab = (hovered == HeaderAction::None) ? HitTestTab(point) : -1;

			// ★ v62：ARK 页的动作按钮也要悬停态（它们不在 HeaderAction 那套里，
			//   因为位置随客户区大小变，且只在 ARK 页存在）。
			int hoveredArk = ArkButtonNone;
			if (g_activeTab == 4) {
				RECT client = {};
				GetClientRect(hwnd, &client);
				hoveredArk = HitTestArkButton(point, client);
			}

			// ★ v80：「高级」页只剩一个跳转按钮（同样不在 HeaderAction 那套里 ——
			//   位置随客户区大小变，且只在这一页存在）。
			int hoveredLaunch = -1;
			if (g_activeTab == 5) {
				RECT client = {};
				GetClientRect(hwnd, &client);
				if (HitTestAdvLaunch(point, client)) {
					hoveredLaunch = 0;
				}
			}

			if (hovered != g_hoverButton || hoveredTab != g_hoverTab
				|| hoveredArk != g_arkHoverAction || hoveredLaunch != g_advLaunchHover) {
				g_hoverButton = hovered;
				g_hoverTab = hoveredTab;
				g_arkHoverAction = hoveredArk;
				g_advLaunchHover = hoveredLaunch;
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;
		}

		case WM_MOUSELEAVE:
			g_trackingMouseLeave = false;
			if (g_hoverButton != HeaderAction::None || g_hoverTab >= 0
				|| g_arkHoverAction != ArkButtonNone || g_advLaunchHover != -1) {
				g_hoverButton = HeaderAction::None;
				g_hoverTab = -1;
				g_arkHoverAction = ArkButtonNone;
				g_advLaunchHover = -1;
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;

		case WM_CAPTURECHANGED:
			// 捕获被抢走（弹了 UAC、别的窗口抢了鼠标）⇒ 清掉按下态，
			// 否则按钮会永远停在"按下"的样子。
			if (g_pressedButton != HeaderAction::None || g_arkPressedAction != ArkButtonNone
				|| g_advLaunchPressed != -1) {
				g_pressedButton = HeaderAction::None;
				g_arkPressedAction = ArkButtonNone;
				g_advLaunchPressed = -1;
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;

		case WM_LBUTTONDOWN: {
			POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };

			// 按钮：按下只进入"按下态" + 捕获鼠标，**真正的动作留到 WM_LBUTTONUP**。
			// 标准按钮语义 —— 按下后拖出去再松手不触发，按错了能反悔。
			const HeaderAction action = HitTestHeaderAction(point);
			if (action != HeaderAction::None) {
				g_pressedButton = action;
				g_hoverButton = action;
				SetCapture(hwnd);
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			int tab = HitTestTab(point);
			if (tab >= 0 && tab != g_activeTab) {
				g_activeTab = tab;
				if (tab == 1) {
					// 首次进日志页直接贴底，不用手动滚。
					g_logScroll = 0;
					g_logFollowTail = true;
				}
				if (tab == 4) {
					// 首次进 ARK 页立刻拉一次，别让用户看着空列表等一个扫描周期。
					RefreshArkCache(true);
				}
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ★ v62：ARK 页 —— 动作按钮 + 表格选中。
			if (g_activeTab == 4) {
				RECT client = {};
				GetClientRect(hwnd, &client);
				RefreshArkCache(true);

				const int button = HitTestArkButton(point, client);
				if (button != ArkButtonNone) {
					if (ArkButtonEnabled(button)) {
						g_arkPressedAction = button;
						SetCapture(hwnd);
					}
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
				}

				const int rowIndex = HitTestArkRow(point, client);
				if (rowIndex >= 0) {
					const int pid = static_cast<int>(g_arkSnapshot.Rows[static_cast<size_t>(rowIndex)].Pid);
					if (pid != g_arkSelectedPid) {
						g_arkSelectedPid = pid;
						// 换选中就撤销「强制结束」的待确认状态（见 PerformArkAction）。
						g_arkKillArmed = false;
						g_arkArmedPid = -1;
						g_arkEventsPid = -1;
					}
				}
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ★ v80：「高级」页 —— 只剩一个跳转按钮。
			if (g_activeTab == 5) {
				RECT client = {};
				GetClientRect(hwnd, &client);
				if (HitTestAdvLaunch(point, client)) {
					g_advLaunchPressed = 0;
					SetCapture(hwnd);
					InvalidateRect(hwnd, nullptr, FALSE);
				}
				// 这一页没有别的可点区域 ⇒ 命中与否都吃掉这次点击
				//（否则会落到下面日志页那条"左下角开关"的判断里）。
				return 0;
			}

			// 日志页左下角：左边点「只看拦截」，右边点「来源切换」。
			// 两个开关都在状态栏那一行，按 x 分开。
			if (g_activeTab == 1) {
				RECT client = {};
				GetClientRect(hwnd, &client);
				const int infoTop = client.bottom - PromptSummaryHeight();
				if (point.y >= infoTop) {
					// 状态栏第一条分句的宽度大约就是 "全部事件" / "只显示拦截"
					// 那几个字，用 160px 作为分界足够（两个开关各自都在这附近）。
					if (point.x < Padding + 160) {
						g_logOnlyBlocked = !g_logOnlyBlocked;
					}
					else {
						// 全部 → 仅注册表 → 仅文件 → 仅进程/线程 → 仅驱动 → 仅网络
						// → 仅摄像头 → 仅输入钩子 → 仅截屏 → 仅DLL加载 → 仅剪贴板
						// → 仅进程旁路 → 仅服务权限 → 仅COM劫持 → 仅计划任务 → 全部
						g_logSourceFilter = (g_logSourceFilter + 1) % 15;
					}
					g_logScroll = 0;
					g_logFollowTail = true;
					InvalidateRect(hwnd, nullptr, FALSE);
				}
			}
			return 0;
		}

		case WM_LBUTTONUP: {
			const POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };

			// ★ v80：「高级」页的跳转按钮（与 ARK 那套同样单独处理 ——
			//   它不在 HeaderAction 那套枚举里）。
			if (g_advLaunchPressed != -1) {
				g_advLaunchPressed = -1;
				if (GetCapture() == hwnd) {
					ReleaseCapture();
				}
				RECT client = {};
				GetClientRect(hwnd, &client);
				// 只有松手时鼠标仍停在**同一个**按钮上才触发（标准按钮语义）。
				if (HitTestAdvLaunch(point, client)) {
					AdvLaunchCfg(hwnd);
				}
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ★ v62：ARK 页的动作按钮（与页头按钮**分开**处理 ——
			//   它们不在 HeaderAction 那套枚举里）。
			if (g_arkPressedAction != ArkButtonNone) {
				const int pressed = g_arkPressedAction;
				g_arkPressedAction = ArkButtonNone;
				if (GetCapture() == hwnd) {
					ReleaseCapture();
				}
				RECT client = {};
				GetClientRect(hwnd, &client);
				if (HitTestArkButton(point, client) == pressed && ArkButtonEnabled(pressed)) {
					PerformArkAction(pressed);
				}
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			const HeaderAction pressed = g_pressedButton;
			if (pressed == HeaderAction::None) {
				return 0;
			}

			g_pressedButton = HeaderAction::None;
			if (GetCapture() == hwnd) {
				ReleaseCapture();
			}

			// 只有松手时鼠标仍停在**同一个**按钮上才触发。
			// 按下后拖出去松手 = 取消（标准按钮语义）。
			if (HitTestHeaderAction(point) == pressed) {
				PerformHeaderAction(hwnd, pressed);
			}
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;
		}

		case WM_MOUSEWHEEL: {
			// ★ v62：ARK 页的进程表滚动。
			if (g_activeTab == 4) {
				int delta = GET_WHEEL_DELTA_WPARAM(wParam);
				g_arkScroll -= delta / WHEEL_DELTA * 3;
				if (g_arkScroll < 0) {
					g_arkScroll = 0;
				}
				// 上界在 DrawArkPage 里按真实行数夹（那里才知道 MaxRows）。
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			if (g_activeTab != 1) {
				return 0;
			}

			// g_logScroll 是"从尾部往回数多少行"，所以向上滚（delta > 0）
			// 要把它加大 —— 加大 = 往更早的历史走。方向搞反的话，
			// 滚轮会永远被夹在 0，看起来"滚不动"。
			int delta = GET_WHEEL_DELTA_WPARAM(wParam);
			int lines = delta / WHEEL_DELTA * 3;
			g_logScroll += lines;
			if (g_logScroll <= 0) {
				g_logScroll = 0;
				g_logFollowTail = true; // 滚到底了，恢复跟随
			}
			else {
				g_logFollowTail = false;
			}
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;
		}

		case WM_KEYDOWN: {
			// ★ v62：ARK 页 —— 上下键移动选中，翻页键翻页，Home/End 跳首尾。
			//
			//   键盘可达性是这一页的**必需品**而不是点缀：列表里全是系统进程，
			//   鼠标滚轮能找到，但"精确选中第 137 行"只有键盘做得到。
			if (g_activeTab == 4) {
				const int total = static_cast<int>(g_arkSnapshot.Rows.size());
				if (total == 0) {
					return 0;
				}

				RECT client = {};
				GetClientRect(hwnd, &client);
				const ArkLayout layout = ArkLayoutFor(client);
				const int page = layout.MaxRows > 1 ? layout.MaxRows - 1 : 1;

				int index = -1;
				for (int i = 0; i < total; i++) {
					if (static_cast<int>(g_arkSnapshot.Rows[static_cast<size_t>(i)].Pid)
						== g_arkSelectedPid) {
						index = i;
						break;
					}
				}

				if (wParam == VK_DOWN) {
					index = (index < 0) ? 0 : (std::min)(index + 1, total - 1);
				}
				else if (wParam == VK_UP) {
					index = (index < 0) ? 0 : (std::max)(index - 1, 0);
				}
				else if (wParam == VK_NEXT) {
					index = (index < 0) ? 0 : (std::min)(index + page, total - 1);
				}
				else if (wParam == VK_PRIOR) {
					index = (index < 0) ? 0 : (std::max)(index - page, 0);
				}
				else if (wParam == VK_HOME) {
					index = 0;
				}
				else if (wParam == VK_END) {
					index = total - 1;
				}
				else {
					break;
				}

				const int pid = static_cast<int>(g_arkSnapshot.Rows[static_cast<size_t>(index)].Pid);
				if (pid != g_arkSelectedPid) {
					g_arkSelectedPid = pid;
					g_arkKillArmed = false;
					g_arkArmedPid = -1;
					g_arkEventsPid = -1;
				}

				// 让选中行始终可见。
				if (index < g_arkScroll) {
					g_arkScroll = index;
				}
				else if (layout.MaxRows > 0 && index >= g_arkScroll + layout.MaxRows) {
					g_arkScroll = index - layout.MaxRows + 1;
				}

				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			if (g_activeTab != 1) {
				break;
			}

			if (wParam == VK_END) {
				g_logScroll = 0;
				g_logFollowTail = true;
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}
			if (wParam == VK_HOME) {
				g_logScroll = 0x7FFFFFFF; // DrawLogPage 内部会夹到上限
				g_logFollowTail = false;
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}
			if (wParam == VK_PRIOR || wParam == VK_NEXT) {
				int lines = (wParam == VK_PRIOR) ? 20 : -20;
				g_logScroll += lines;
				if (g_logScroll < 0) {
					g_logScroll = 0;
					g_logFollowTail = true;
				}
				else {
					g_logFollowTail = false;
				}
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}
			break;
		}

		case WM_TIMER:
			// 定时器 2 = 超级档置顶重申（250ms）。必须先分流，
			// 否则会被下面那条"无脑重画"路径吞掉。
			if (wParam == TopMostReinforceTimerId) {
				ReinforceSuperTopMost();
				return 0;
			}
			// ★ v63：定时器 3 = ARK 页刷新（间隔来自 `ark_refresh_ms`）。
			//   同样必须**先分流** —— 它要的是"**重取**快照再重画"，
			//   而下面那条路径只 InvalidateRect（重画不重取 ⇒ 界面上
			//   永远看不到新数据，正是"配了刷新间隔却没反应"的经典成因）。
			//   不在 ARK 页时直接返回，不做任何工作。
			if (wParam == ArkRefreshTimerId) {
				if (g_activeTab == 4) {
					RefreshArkCache(true);
					InvalidateRect(hwnd, nullptr, FALSE);
				}
				return 0;
			}
			// ★ v62：ARK 动作自检由**定时器**驱动，不能只靠 WM_PAINT。
			//   最小化窗口永远收不到 WM_PAINT —— 只挂在绘制路径上的话，
			//   自动化一用 `-WindowStyle Minimized` 起引擎，"自检没发"
			//   与"功能没生效"就分不开了（铁律 97）。
			//   定时器与窗口可见性无关，这条路径永远会走。
			TryArkActionSelfTest();
			// 定时器 1 = 重画。日志页刷得勤一点（跟随模式下新行进来要立刻看到），
			// 统计页每秒一次足够 —— 数字跳太快反而看不清。
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;

		case WM_CLOSE:
			// 关窗口**不退出程序** —— 收进托盘，引擎继续跑（用户 2026-10-17 要求）。
			//
			// ⚠️ 与旧行为（`SW_MINIMIZE`，留在任务栏）的区别，以及为什么可以改：
			//   旧注释担心"窗口消失会被误认为已关闭"。现在这个担心由**托盘图标**
			//   兜住了 —— 图标可见 = 进程还在。所以这里改成 SW_HIDE。
			//
			// ★★ 但"收起来"必须配一个**能真正退出**的入口，否则就是
			//    "关不掉的程序"（用户只能去任务管理器强杀，而强杀会跳过
			//    引擎的收尾 —— 铁律 107）。那个入口在托盘右键菜单里。
			//
			// ⚠️ 任务管理器「结束任务」走的就是这条友好关闭路径（不是强杀，
			//    原因见旧注释：强杀要 PROCESS_TERMINATE 句柄，已被保护 hook 拦掉）。
			//    ⇒ 用户在那里点"结束任务"时，看到的会是进程**没死**。
			//      这是本需求要接受的取舍：托盘图标 + 收起来时弹一次气泡，
			//      把"它还在跑、怎么真正退出"讲清楚（见 TrayHideToTray）。
			TrayHideToTray(hwnd);
			return 0;

		case WM_DESTROY:
			KillTimer(hwnd, 1);
			KillTimer(hwnd, TopMostReinforceTimerId);
			// ★ v83：玻璃缓存（背景 + 面板层 + 本帧画布，三块整幅 DIB）必须显式放掉。
			//   它们不进窗口类的资源管理，不 Shutdown 就是三份内存泄漏。
			g_glass.Shutdown();
			g_gl.Shutdown();
			// ★ 托盘图标必须先摘掉再销毁窗口：图标消息是投给这个 hwnd 的，
			//   窗口没了还留着图标 = 通知区里一个"点了没反应"的僵尸（铁律 103）。
			g_tray.icon.Remove();
			return 0;

		default:
			break;
		}

		return DefWindowProc(hwnd, message, wParam, lParam);
	}

	DWORD WINAPI GuiThreadProc(void* /*parameter*/)
	{
		// 调试/验证用：R3SHIELDCORE_START_TAB=log 时启动即停在日志页。
		// （提权窗口不接收非提权进程的鼠标输入，UIPI 会拦掉点击，
		//   所以要验证日志页只能靠这个开关，不能靠自动化点击。）
		//
		// ★ v62：加 `ark` —— ARK 页同理，**而且更甚**：
		//   它的动作按钮是自绘的，没有控件句柄，自动化点击既过不了 UIPI
		//   也点不准（坐标随客户区大小变）。没有这个开关，
		//   "ARK 页画得对不对"就只能靠人眼 —— 而本项目已经吃过
		//   "靠人眼 = 假绿"的亏（铁律 24/28）。
		{
			wchar_t tabEnv[16] = {};
			DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_START_TAB", tabEnv, _countof(tabEnv));
			if (n > 0 && _wcsicmp(tabEnv, L"log") == 0) {
				g_activeTab = 1;
			}
			else if (n > 0 && _wcsicmp(tabEnv, L"ark") == 0) {
				g_activeTab = 4;
			}
			// ★ v80：`advanced` —— 「高级」页（现在只剩一个"跳转到 cfg"的按钮）。
			//   理由同 ark：这一页也是自绘、没有控件句柄，自动化点击既过不了
			//   UIPI 也点不准；要核对它只能靠这个开关 + `--gui-preview`。
			else if (n > 0 && _wcsicmp(tabEnv, L"advanced") == 0) {
				g_activeTab = 5;
			}
		}

		g_window = CreateWindowEx(
			WS_EX_APPWINDOW | WS_EX_TOPMOST,
			GuiClassName, GuiTitle,
			// ★ v80：`WS_CLIPCHILDREN` —— **刻意保留**，但理由变了。
			//
			//   v78 加它是因为「高级」页有个原生 EDIT 子控件，而本窗口是
			//   **整块双缓冲**（见 PaintWindow 末尾的 `BitBlt`）—— 没有这个位，
			//   `BitBlt` 会直接盖到子控件上 ⇒ 控件**看不见**，界面上不会有
			//   任何报错，只有截图能看出来（铁律 181）。
			//
			//   v80 把编辑台搬去 cfg 之后，本窗口已经**没有任何子控件**，
			//   这个位现在是空转。留着它是因为代价为零，而"忘了它"的代价
			//   正是铁律 181 那条 —— 以后再加自绘页面上的控件时不会重踩。
			WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME
				| WS_CLIPCHILDREN,
			CW_USEDEFAULT, CW_USEDEFAULT, WindowWidth, WindowHeight,
			nullptr, nullptr, g_instance, nullptr);

		if (g_window) {
			// ★★ v84：界面风格与 GL 后端在窗口建好后立刻定下来。
			//   风格要**在首帧之前**读到 —— 否则第一帧会先按默认风格画一次、
			//   再被下一次重绘纠正，肉眼会看到一闪（铁律 24/28 的"首帧"家族）。
			g_uiStyle = R3ShieldCoreUi::LoadStyle();
			if (g_uiStyle == Style::Glass) {
				if (g_gl.Init()) {
					printf("[glass] OpenGL 后端就绪：%s 标记=%ls\n",
						g_gl.info[0] ? g_gl.info : "(unknown)",
						R3ShieldCoreUi::kGlMarker);
				} else {
					printf("[glass] OpenGL 不可用（阶段=%d）⇒ 退回 CPU 合成 标记=%ls\n",
						g_gl.failStage, R3ShieldCoreUi::kGlMarker);
				}
			} else {
				printf("[ui] 界面风格：经典（不铺玻璃层）标记=%ls\n",
					R3ShieldCoreUi::kStyleMarker);
			}
			ApplyGlassWindow(g_window);
			// ★ v83：外框圆角（"背景透明圆角"）。
			//   优先 DWM 的 `DWMWA_WINDOW_CORNER_PREFERENCE`（Win11 22H2+，由合成器
			//   做**抗锯齿**圆角，圆角外面直接是桌面）；不成就退回 `SetWindowRgn`
			//   硬裁剪（有锯齿，但至少是圆的）。
			//   ★ 判据是**API 返回值**而不是版本号：版本号在"Win11 但关了圆角"的
			//     环境上会骗人（r3shieldcore_gui.cpp 的 ApplyGlassWindow 也同理）。
			const int cornerMode = R3ShieldCoreUi::ApplyRoundedWindow(
				g_window, static_cast<int>(8.0f * GlassDpiScale(g_window) + 0.5f));
			printf("[glass] 外框圆角=%ls 标记=%ls\n",
				cornerMode == 1 ? L"DWM 抗锯齿" : (cornerMode == 2 ? L"region 硬裁剪" : L"不可用"),
				R3ShieldCoreUi::kGenerationMarker);
			// ★ v80：本窗口现在**没有任何子控件**了 —— 规则编辑框（原生 EDIT）
			//   跟着「高级」编辑台一起搬去了 cfg，这里原来那段
			//   `AdvCreateEdit` + 预览预置文本已删除。
			//
			// ★ 图标：注册窗口类时已经给了（hIcon / hIconSm），正常情况这就够了。
			//   这里再显式发一次 WM_SETICON，是为了兜住两种边角情况：
			//     · 类注册发生在**同进程的另一个实例**之后（hIcon 不生效）；
			//     · shell 在窗口创建前就抓过一次图标（任务栏缓存了空白图标）。
			//   两个尺寸都设：ICON_BIG 管 Alt+Tab，ICON_SMALL 管标题栏/任务栏。
			//   ★ 用 SendMessage 而不是 SetClassLongPtr —— 后者只改类的默认值，
			//     对**已经创建**的窗口不追溯，属于"看起来对但没效果"的写法。
			SendMessageW(g_window, WM_SETICON, ICON_BIG,
				reinterpret_cast<LPARAM>(LoadAppIcon(
					GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON))));
			SendMessageW(g_window, WM_SETICON, ICON_SMALL,
				reinterpret_cast<LPARAM>(LoadAppIcon(
					GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON))));

			// 与 class 相同：窗口首次显示前就进入 TOPMOST，避免先显示在
			// 任务管理器下面，再依赖异步置顶改变 Z 序。
			ApplyHighestPermittedTopmost(g_window, true, nullptr, nullptr);

			// 居中到屏幕
			RECT rect = {};
			GetWindowRect(g_window, &rect);
			int width = rect.right - rect.left;
			int height = rect.bottom - rect.top;
			int screenWidth = GetSystemMetrics(SM_CXSCREEN);
			int screenHeight = GetSystemMetrics(SM_CYSCREEN);
			SetWindowPos(g_window, nullptr,
				(screenWidth - width) / 2, (screenHeight - height) / 2,
				0, 0, SWP_NOSIZE | SWP_NOZORDER);

			ShowWindow(g_window, SW_SHOW);
			UpdateWindow(g_window);
			SetFocus(g_window); // 收键盘消息用（End 回底、PgUp/PgDn 翻页）

			// ★ 托盘图标：窗口出来了就注册（"关闭窗口 = 收进托盘"的前提）。
			//
			//   ⚠️ 必须在窗口**建好之后**加：图标消息是投给这个 hwnd 的。
			//   ⚠️ 加不上不能当没事发生 —— `TrayHideToTray` 会检查 `added()`
			//      并退回"最小化到任务栏"（否则窗口从任务栏和托盘同时消失）。
			if (!g_tray.icon.Add(g_window, TrayCurrentIcon(), TrayTipText(),
					R3ShieldCoreTray::kCallbackMessageMain)) {
				printf("[tray] 警告：托盘图标添加失败（Shell_NotifyIcon(NIM_ADD) 失败），"
					"关闭窗口将退回最小化到任务栏\n");
			} else {
				// ★ 带上宽串代次标记（在共享头里，铁律 127）—— 闸门 `check_dist_sync.sh`
				//   用 `strings -el` 查它确认托盘代码编进了 exe。必须 `%ls` 传宽串。
				printf("[tray] 托盘图标已就绪（关闭窗口 = 收进托盘）标记=%ls\n",
					R3ShieldCoreTray::kGenerationMarker);
			}

			SetTimer(g_window, 1, 300, nullptr);
			// ★ v63：ARK 页的刷新定时器。间隔来自 `ark_refresh_ms`；
			//   不在 ARK 页时它只做一次判断就返回（见 WM_TIMER），几乎零成本。
			SetTimer(g_window, ArkRefreshTimerId, ArkRefreshIntervalMs(), nullptr);

			// ★ v80：预览模式下**模拟点一下「打开高级规则编辑台」**。
			//
			//   为什么在**进程内**发消息，而不是让探针从外面点：
			//   按钮矩形只在 `AdvLaunchButtonRect` 里算一次（铁律 182），
			//   探针从外面要么再算一遍（几何抄两份，必然漂），要么去解析
			//   日志里的矩形（而 exe 独占着日志句柄，探针读不到）。
			//   在进程内发用的是**同一份几何**，而且走的是真实消息路径 ——
			//   WM_LBUTTONDOWN → SetCapture → WM_LBUTTONUP → 命中判定
			//   → AdvLaunchCfg，**不是**直接调那个动作函数（那样只验了动作，
			//   没验"按钮到底在不在那儿"）。
			//
			//   ⚠️ 只在 `--gui-preview` 下由环境变量置起（见 RunPreview），
			//      生产路径读不到它。
			if (g_previewJumpClick) {
				RECT client = {};
				GetClientRect(g_window, &client);
				const RECT button = AdvLaunchButtonRect(client);
				const LPARAM at = MAKELPARAM((button.left + button.right) / 2,
					(button.top + button.bottom) / 2);
				printf("[adv] 预览：模拟点击跳转按钮 at=%ld,%ld 页签=%d\n",
					GET_X_LPARAM(at), GET_Y_LPARAM(at), g_activeTab);
				fflush(stdout);   // 铁律 80
				PostMessageW(g_window, WM_LBUTTONDOWN, MK_LBUTTON, at);
				PostMessageW(g_window, WM_LBUTTONUP, 0, at);
			}

			// UIAccess 接管实例启动后必须立即尝试真实 Band；普通实例仍支持
			// R3SHIELDCORE_START_TOPMOST=normal|super 调试入口。
			// 理由同上 —— 提权窗口收不到非提权进程的合成输入，UIPI 会拦掉点击，
			// 自动化验证只能靠这个开关，不能靠点按钮。
			{
				const std::wstring commandLine = GetCommandLineW() ? GetCommandLineW() : L"";
				if (commandLine.find(R3ShieldCoreSuperDesk::UiAccessArgument) != std::wstring::npos) {
					ApplyTopMostLevel(2);
				}
				else {
				wchar_t topMostEnv[16] = {};
				DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_START_TOPMOST", topMostEnv, _countof(topMostEnv));
				if (n > 0 && _wcsicmp(topMostEnv, L"super") == 0) {
					ApplyTopMostLevel(2);
				}
				else if (n > 0 && _wcsicmp(topMostEnv, L"normal") == 0) {
					ApplyTopMostLevel(1);
				}
				else {
					// 普通置顶是默认档；超级置顶必须由用户明确选择。
					ApplyTopMostLevel(1);
				}
				}
			}
		}

		MSG message = {};
		while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
			BOOL result = GetMessage(&message, nullptr, 0, 0);
			if (result == 0) {
				// GetMessage 只在取到 WM_QUIT 时返回 0。外进程可以
				// PostThreadMessage(WM_QUIT) 把窗口弄没（进程仍在）——
				// 和 WM_CLOSE 属同一类误导，直接吞掉继续跑。
				// 真正的退出走 g_stop：R3ShieldCoreGui::Stop() 置位后发 WM_NULL 唤醒，
				// 下一轮 while 条件就会退出。
				// 消息已被 GetMessage 从队列移除，所以 continue 不会空转。
				continue;
			}
			if (result == -1) {
				break; // 真正的错误
			}

			TranslateMessage(&message);
			DispatchMessage(&message);
		}

		if (g_window) {
			DestroyWindow(g_window);
			g_window = nullptr;
		}

		return 0;
	}
}

namespace R3ShieldCoreGui
{
	bool Start(const Options& options) noexcept
	{
		if (g_guiThread) {
			return true;
		}

		g_options = options;
		InterlockedExchange(&g_displayMode, static_cast<LONG>(options.Mode));
		InterlockedExchange(&g_pendingMode, -1);
		InterlockedExchange(&g_uiAccessRestartRequest, 0);
		InterlockedExchange(&g_quitRequest, 0);

		// 交互态归零：窗口是新建的，鼠标还没进来过。
		g_hoverButton = HeaderAction::None;
		g_pressedButton = HeaderAction::None;
		g_hoverTab = -1;
		g_trackingMouseLeave = false;
		g_allowUiAccessRestart = true;
		g_instance = GetModuleHandle(nullptr);

		WNDCLASSEX windowClass = { sizeof(WNDCLASSEX) };
		windowClass.style = CS_HREDRAW | CS_VREDRAW;
		windowClass.lpfnWndProc = GuiWndProc;
		windowClass.hInstance = g_instance;
		// ★ 图标：资源里的那个（见 LoadAppIcon）。大小两个尺寸都要给 ——
		//   hIconSm 管标题栏/任务栏小图标，hIcon 管 Alt+Tab 和资源管理器大图标。
		windowClass.hIcon = LoadAppIcon(GetSystemMetrics(SM_CXICON),
		                                GetSystemMetrics(SM_CYICON));
		windowClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
		windowClass.hbrBackground = nullptr;
		windowClass.lpszClassName = GuiClassName;
		windowClass.hIconSm = LoadAppIcon(GetSystemMetrics(SM_CXSMICON),
		                                  GetSystemMetrics(SM_CYSMICON));

		if (!RegisterClassEx(&windowClass)) {
			return false;
		}

		g_classRegistered = true;

		g_titleFont = CreateFont(-17, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
		g_labelFont = CreateFont(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
		g_valueFont = CreateFont(-22, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
		g_monoFont = CreateFont(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
		// 日志行要在一屏里塞下尽量多行，字号比正文再小一号。
		g_logFont = CreateFont(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
		g_tabFont = CreateFont(-14, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
		// ★ v79：Markdown 加粗用。**字号/字面与 g_labelFont 完全一致**，
		//   只把字重从 FW_NORMAL 换成 FW_BOLD —— 同一行里"加粗的那几个字"
		//   与普通字混排时，字号一致才不会出现基线跳动。
		g_boldFont = CreateFont(-13, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

		InterlockedExchange(&g_stop, 0);

		g_guiThread = CreateThread(nullptr, 0, GuiThreadProc, nullptr, 0, nullptr);
		if (!g_guiThread) {
			return false;
		}

		return true;
	}

	void Stop() noexcept
	{
		if (!g_guiThread) {
			return;
		}

		InterlockedExchange(&g_stop, 1);

		// 给 GUI 线程发个空消息，让它从 GetMessage 里出来看 g_stop。
		if (g_window) {
			PostMessage(g_window, WM_NULL, 0, 0);
		}

		WaitForSingleObject(g_guiThread, 5000);
		CloseHandle(g_guiThread);
		g_guiThread = nullptr;

		if (g_titleFont) { DeleteObject(g_titleFont); g_titleFont = nullptr; }
		if (g_labelFont) { DeleteObject(g_labelFont); g_labelFont = nullptr; }
		if (g_valueFont) { DeleteObject(g_valueFont); g_valueFont = nullptr; }
		if (g_monoFont) { DeleteObject(g_monoFont); g_monoFont = nullptr; }
		if (g_logFont) { DeleteObject(g_logFont); g_logFont = nullptr; }
		if (g_tabFont) { DeleteObject(g_tabFont); g_tabFont = nullptr; }
		if (g_boldFont) { DeleteObject(g_boldFont); g_boldFont = nullptr; }

		if (g_classRegistered) {
			UnregisterClass(GuiClassName, g_instance);
			g_classRegistered = false;
		}
	}

	void Update(ULONG injectedTotal) noexcept
	{
		InterlockedExchange(&g_injectedTotal, static_cast<LONG>(injectedTotal));
	}

	bool TakePendingMode(R3ShieldCore::Mode& mode) noexcept
	{
		// 一次原子取走（顺带清成 -1）。用 Exchange 而不是"读 + 清"两步：
		// 两步会漏 —— 界面在这中间又点了一下，那次请求就被覆盖掉了。
		LONG pending = InterlockedExchange(&g_pendingMode, -1);
		if (pending < 0) {
			return false;
		}

		mode = static_cast<R3ShieldCore::Mode>(pending);
		return true;
	}

	bool TakeUiAccessRestartRequest() noexcept
	{
		return InterlockedExchange(&g_uiAccessRestartRequest, 0) != 0;
	}

	bool TakeQuitRequest() noexcept
	{
		return InterlockedExchange(&g_quitRequest, 0) != 0;
	}

	void SetMode(R3ShieldCore::Mode mode) noexcept
	{
		InterlockedExchange(&g_displayMode, static_cast<LONG>(mode));

		// 立刻重画，别等 300ms 的 WM_TIMER —— 点了按钮要马上看到徽章变。
		if (g_window) {
			InvalidateRect(g_window, nullptr, FALSE);
		}
	}

	int RunTopMostSelfTest() noexcept
	{
		Options options = {};
		options.Mode = R3ShieldCore::Mode::Log;
		if (!Start(options)) {
			printf("[topmost-selftest] GUI start FAILED\n");
			return 1;
		}
		g_allowUiAccessRestart = false;

		for (int attempt = 0; attempt < 40 && !g_window; ++attempt) {
			Sleep(50);
		}
		if (!g_window) {
			printf("[topmost-selftest] window creation FAILED\n");
			Stop();
			return 2;
		}

		ApplyTopMostLevel(1);
		const bool normal =
			(GetWindowLongPtrW(g_window, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
		printf("[topmost-selftest] normal topmost=%d\n", normal ? 1 : 0);

		const bool alreadyUiAccess = IsCurrentProcessUiAccessEnabled();
		ApplyTopMostLevel(2);
		const bool super = !alreadyUiAccess || (g_topMost && g_superTopMost);
		printf("[topmost-selftest] super state=%d band=%d panel=%d\n",
			super ? 1 : 0,
			g_superBandApplied ? 1 : 0,
			R3ShieldCoreSuperDesk::IsRunning() ? 1 : 0);

		ApplyTopMostLevel(0);
		const bool cleared =
			(GetWindowLongPtrW(g_window, GWL_EXSTYLE) & WS_EX_TOPMOST) == 0;
		printf("[topmost-selftest] cleared=%d\n", cleared ? 1 : 0);
		Stop();

		return normal && super && cleared ? 0 : 3;
	}

	// ★ v77：界面预览（`--gui-preview`）—— 建窗、跑着、**不启动引擎**。
	//
	// ★ 为什么需要它
	//   主程序一启动就会开始全局注入，而铁律 175 明令**开发机禁止跑引擎**
	//   （全局注入会 hook 编辑器 ⇒ 崩）。于是"界面画得对不对"长期只能靠
	//   读代码 —— 而本项目已经吃过"靠人眼 = 假绿"的亏（铁律 24/28）。
	//   本模式在**引擎初始化之前**分流（和 `--topmost-selftest` 同一位置，
	//   见 app.cpp），所以可以安全地反复跑、截图核对。
	//
	// ★ 与 `--topmost-selftest` 的区别
	//   那个是"建窗 → 自检置顶 → 立刻退"（跑完就没了，看不到界面）；
	//   本函数是"建窗 → **等你关**"，中间的界面就是发布版的界面。
	//
	// ★ 怎么指定看哪一页
	//   环境变量 `R3SHIELDCORE_START_TAB`（v62 就有，见 GuiThreadProc）：
	//     overview(默认) | log | process | config | ark | advanced
	//   提权窗口收不到非提权进程的自动化点击（UIPI 拦），所以这是
	//   验证某个页签的唯一可靠手段。
	int RunPreview() noexcept
	{
		Options options = {};
		options.Mode = R3ShieldCore::Mode::Log;

		// ★ v80：预览模式下**模拟点一下「高级」页的跳转按钮**。
		//
		//   用户要的核心行为是"点主程序的「高级」→ 跳到 cfg 的高级页"，
		//   而这条链路的每一环（窗口类名 / 激活消息 / 页号 / exe 名）都可能
		//   **静默**对不上 —— "点了没反应"和"页面画错了"在截图上分不开
		//   （铁律 24/28）。有了这个开关，探针只要设环境变量、再检查
		//   cfg 的窗口有没有出现、停在第几页，就能把整条链路钉死。
		//
		//   ⚠️ 只在 `--gui-preview` 里生效（本函数只在 `--gui-preview`
		//      分流时被调用，见 app.cpp）—— 生产路径读不到这个变量。
		{
			wchar_t jumpEnv[16] = {};
			const DWORD jumpLen = GetEnvironmentVariableW(
				L"R3SHIELDCORE_PREVIEW_JUMP", jumpEnv, _countof(jumpEnv));
			if (jumpLen > 0 && _wcsicmp(jumpEnv, L"click") == 0) {
				g_previewJumpClick = true;
			}
		}

		if (!Start(options)) {
			printf("[gui-preview] GUI start FAILED\n");
			return 1;
		}
		g_allowUiAccessRestart = false;

		for (int attempt = 0; attempt < 40 && !g_window; ++attempt) {
			Sleep(50);
		}
		if (!g_window) {
			printf("[gui-preview] window creation FAILED\n");
			Stop();
			return 2;
		}

		printf("[gui-preview] 窗口已建立 %dx%d，当前页签 = %d\n",
			WindowWidth, WindowHeight, g_activeTab);
		printf("[gui-preview] **预览模式**：不注入、不启动引擎、不读屏幕；关窗口即退出。\n");
		printf("[gui-preview] 换页签：设 R3SHIELDCORE_START_TAB=log|process|config|ark|advanced\n");
		printf("[gui-preview] 注：「高级」页现在只是跳转入口，编辑台在 r3shieldcore-cfg.exe。\n");
		printf("[gui-preview] 模拟点跳转按钮（自动核对用）：R3SHIELDCORE_PREVIEW_JUMP=click\n");

		// 喂一个"引擎没在跑"的状态，让概览页有确定内容（否则全是初值）。
		Update(0);

		// 等窗口消失。GUI 线程自己跑消息循环，这里只轮询三件事：
		//   · 模式切换请求 —— 预览模式**不**切引擎，取走即丢（否则会积压）；
		//   · 退出请求（界面上的「退出引擎」按钮）—— 当作"关窗口"；
		//   · UIAccess 重启请求 —— 预览模式不重启，同样取走即丢。
		while (IsWindow(g_window)) {
			R3ShieldCore::Mode m = R3ShieldCore::Mode::Log;
			(void)TakePendingMode(m);
			if (TakeQuitRequest()) break;
			(void)TakeUiAccessRestartRequest();
			Sleep(100);
		}

		Stop();
		printf("[gui-preview] 已退出。\n");
		return 0;
	}
}
