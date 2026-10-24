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
#include <mutex>    // v100：g_notice 跨线程（主循环写 / 窗口线程读）必须加锁
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

// ★ v86：**全窗口 OpenGL 场景渲染器**（背景 → 玻璃 → 实心 → 图标 → 文字）。
//   参考项目 `LiquidGlassControls` 的渲染架构；两个 exe 共用同一份（铁律 127）。
#include <r3shieldcore/ui_scene.h>

// ★ v84：界面风格的契约（两个 exe 共用，铁律 127）。
#include <r3shieldcore/ui_style.h>

// ★ v85：液态玻璃**控件原语**（卡片 / 药丸按钮 / 开关 / 分段 / 进度条 / 徽章）。
//   视觉模型参考 `LiquidGlassControls`；材质仍走上面那两个头，文字仍走 GDI。
//   两个 exe 共用同一份（铁律 127）。
#include <r3shieldcore/ui_controls.h>

// ★ v93：逐帧动画基元（弹簧 / 悬停逼近 / 按 key 存的状态表）。
//   参数与参考项目 `LiquidGlassControls` 一致；驱动方式见本文件里
//   `AnimTimerId` 那一段（有交互才起 16ms 定时器，收敛即停）。
#include <r3shieldcore/ui_anim.h>

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

	// ★★★ v86：本帧的**整个场景**（背景之上的一切：玻璃面板 + 实心块 + 图标 + 文字）。
	//
	//   为什么是全局：每个 DrawXxxPage 的签名都只收 `HDC`，一行行改签名会把
	//   5000 行全部卷进来（diff 无法审）。而它要表达的东西本来就是"本帧画在哪"
	//   —— 每帧在 PaintWindow 里 Begin 一次即可。
	//   ★ 只在 GUI 线程读写，和 g_glass 同生命周期。
	R3ShieldCoreUi::Scene g_scene;

	// 兼容层用的哑 DC：所有绘制都进 g_scene，它只是为了让旧签名不用改。
	HDC g_sceneDc = nullptr;

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

	// ★ v87：卡片内边距。参考项目 CARD_PAD = 24（卡片宽 ~396），这边卡片窄一半，
	//   按比例取 18。所有卡片内容（标题 / 柱状条 / 数值）都从这一条竖线起。
	constexpr int CardPad = 18;

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

		// ★★ v88：把**系统标题栏**也拉到浅色。
		//
		//   为什么这件事属于"界面重构"而不是"系统设置"：客户区是白玻璃，
		//   而标题栏走的是系统主题 —— 这台机器上"在标题栏显示强调色"是开的，
		//   于是窗口顶上挂着一条深蓝黑带，和下面的玻璃界面完全不是一个世界，
		//   截图里第一眼看到的就是它。
		//
		//   `DWMWA_USE_IMMERSIVE_DARK_MODE` 必须一起关：只改 CAPTION_COLOR
		//   的话 DWM 仍按"深色窗口"画那三个系统按钮（− □ ✕）的**浅色字形**，
		//   浅底 + 浅字形 = 按钮直接看不见。
		//
		//   ⚠️ 这几个属性是 Win11 22000+ 才有的；在 Win10 上调用**直接失败**，
		//      返回值忽略即可（失败 = 保持系统默认外观，不是错误路径）。
		constexpr DWORD DwmwaUseImmersiveDarkMode = 20;
		constexpr DWORD DwmwaBorderColor = 34;
		constexpr DWORD DwmwaCaptionColor = 35;
		constexpr DWORD DwmwaTextColor = 36;
		BOOL darkCaption = FALSE;
		DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode,
			&darkCaption, sizeof(darkCaption));
		// 和卡片同一个明度家族：比卡片（约 245）略深一点，
		// 这样标题栏读成"窗口的边框"，不会和顶栏那张玻璃抢。
		const COLORREF captionColor = RGB(242, 245, 250);
		const COLORREF captionText = RGB(24, 24, 24);
		const COLORREF borderColor = RGB(214, 222, 234);
		DwmSetWindowAttribute(hwnd, DwmwaCaptionColor, &captionColor, sizeof(captionColor));
		DwmSetWindowAttribute(hwnd, DwmwaTextColor, &captionText, sizeof(captionText));
		DwmSetWindowAttribute(hwnd, DwmwaBorderColor, &borderColor, sizeof(borderColor));
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

	// ★ v85：控件库的画布句柄（玻璃层 + 目标 HDC + dpi）。
	//
	// 为什么是全局而不是一路传参：这个文件里每个 DrawXxxPage 的签名都只收
	// `HDC`，一行行改签名会把 5000 行全部卷进来（diff 无法审）。而它要表达的
	// 东西本来就是"本帧画在哪" —— 每帧在 PaintWindow 里赋一次即可。
	// ★ 只在 GUI 线程读写，和 g_glass 同生命周期。
	namespace UiCtl = R3ShieldCoreUi::UiCtl;

	float GlassDpiScale(HWND hwnd);   // 定义在下面

	UiCtl::Surface g_ui;

	// ★ v85：概览页两张玻璃卡的纵向范围（y0, y1）。
	//
	//   为什么要记"上一帧"的：玻璃层按登记顺序叠放，卡片必须**先于**
	//   柱状条登记；而卡片高度要到画完才知道 ⇒ 只能记下来给下一帧用。
	//   这不违背"两帧收敛"（本帧的玻璃层本来就是按上一帧的表合成的）。
	//   只在 GUI 线程读写；[0]==[1] 表示还没量过（首帧）。
	int g_overviewCardA[2] = { 0, 0 };
	int g_overviewCardB[2] = { 0, 0 };

	void SyncUiSurface(HDC dc)
	{
		g_ui.dc = dc;
		g_ui.g = &g_glass;
		g_ui.dpi = GlassDpiScale(g_window);
	}

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

	// ★★★ v98：切到"无系统标题栏"。
	//
	//   只在玻璃风格下切 —— 经典模式（`R3SHIELDCORE_GLASS=off`）仍保留
	//   系统标题栏：那是现场的**一键回退路径**，回退后必须还是一个
	//   "能拖、能关"的正常窗口，不能因为去掉了标题栏而变成拖不动的板子。
	//
	//   用 `SetWindowLongPtr + SWP_FRAMECHANGED` 而不是在 CreateWindowEx 里
	//   直接写：风格是窗口建好之后才从配置读出来的（`LoadStyle`），
	//   建窗口那一刻还不知道该不该去标题栏。
	//
	//   `WS_THICKFRAME` 必须留着：DWM 的投影和 Win11 圆角靠它，
	//   缩放命中也靠它（客户区由 WM_NCCALCSIZE 撑满，边框只是不可见）。
	void ApplyCustomFrame(HWND hwnd)
	{
		if (!hwnd || g_uiStyle != Style::Glass) {
			return;
		}
		LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
		style &= ~static_cast<LONG_PTR>(WS_CAPTION | WS_SYSMENU);
		style |= WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
		SetWindowLongPtr(hwnd, GWL_STYLE, style);
		SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
		printf("[glass] 自绘标题栏已启用（去掉系统标题栏，玻璃铺到窗口最上沿）\n");
	}


	// OpenGL 后端实例（进程级；Init 失败就一直是 CPU 合成）
	R3ShieldCoreUi::GlGlass g_gl;

	// 把 GlassSurface 的面板表翻译成 GL 后端的入参并渲染。
	// ★ 这是 CPU / GPU 两条路唯一的分叉点：都产出同一块 top-down BGRA 缓冲。
	//
	// ★★ v86：**内容层也在这里画**（`&g_scene` 作为 `GlSceneHook` 回调进去）。
	//   于是这一帧的成品 = 背景 + 玻璃 + 实心块 + 图标 + 文字，一次上屏
	//   —— 和参考项目 `LiquidGlassControls` 的渲染顺序一致。
	unsigned long long g_lastBgStamp = 0;   // 上次交给 GL 的背景快照代次

	void GlComposeBridge(void* ctx, const R3ShieldCoreUi::Backdrop& bd,
		const R3ShieldCoreUi::PanelRec* panels, int count,
		int headerBand, float headerVeil,
		int w, int h, float dpi, BYTE* out)
	{
		auto* gl = static_cast<R3ShieldCoreUi::GlGlass*>(ctx);

		// `PanelRec`（合成层的记录）与 `GlGlass::PanelDraw`（着色器的入参）
		// 字段一一对应，但**是两个类型**（前者不带任何 GL 依赖，后者在 ui_gl.h 里）。
		// 逐字段搬一次，最多 96 条，代价可以忽略 —— 比 reinterpret_cast 安全
		// （后者依赖"两个结构布局完全一致"，一旦谁加个字段就是静默画错）。
		R3ShieldCoreUi::GlGlass::PanelDraw conv[R3ShieldCoreUi::GlassSurface::kMaxPanels];
		int n = count;
		if (n > R3ShieldCoreUi::GlassSurface::kMaxPanels) {
			n = R3ShieldCoreUi::GlassSurface::kMaxPanels;
		}
		for (int i = 0; i < n; ++i) {
			conv[i].x0 = panels[i].x0;
			conv[i].y0 = panels[i].y0;
			conv[i].x1 = panels[i].x1;
			conv[i].y1 = panels[i].y1;
			conv[i].radius = panels[i].radius;
			conv[i].tint = panels[i].tint;
			conv[i].kind = panels[i].kind;
			conv[i].cr = panels[i].cr;
			conv[i].cg = panels[i].cg;
			conv[i].cb = panels[i].cb;
		}

		// ★ 背景代次没变 ⇒ 跳过整条模糊链（上传 + 5 遍高斯，3~5ms）。
		if (!gl->Render(bd.full.bits, bd.full.w, bd.full.h,
			conv, n,
			headerBand, headerVeil, w, h, dpi,
			R3ShieldCoreUi::DefaultTheme().veil, out, &g_scene,
			bd.refreshStamp != g_lastBgStamp)) {
			// ★★ GL 中途失败（设备丢失 / 驱动异常）⇒ **当场退回 CPU**，并把钩子摘掉。
			//   不摘的话每帧都会重试、每帧都要多花一次失败的 GL 调用。
			g_glass.glCompose = nullptr;
			R3ShieldCoreUi::PaintBackdropBase(out, w, h, bd,
				R3ShieldCoreUi::DefaultTheme(), R3ShieldCoreUi::DefaultTheme().veil);
			printf("[glass] 警告：GL 合成本帧失败，已退回 CPU 合成（后续不再尝试 GL）\n");
			return;
		}
		g_lastBgStamp = bd.refreshStamp;
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

	// ★ v103：最近一次鼠标位置（客户区坐标）。
	//
	// 为什么需要它：以前只有 `WM_MOUSEMOVE` 里才知道鼠标在哪，而
	// `DrawConfigPage` 要判断「应用」按钮是否悬停 —— 绘制期间没有 POINT。
	// 两个选择：① 把 point 一路传进绘制函数（要改一串签名）；
	// ② 记住最后一次位置（一个 POINT，无锁：只有 UI 线程读写）。
	// 选 ② —— 悬停**本来就是"上一帧的位置"**，一个 POINT 就是它的全部含义。
	//
	// ★ 初值 (-1,-1)：客户区外 ⇒ 一开始不会有任何东西显示成悬停态。
	POINT g_mousePoint = { -1, -1 };

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

	// ---- ★ v91：引擎连接状态 + 一次性提示条 ----
	//
	// 为什么必须有这两个东西：界面是 **WINDOWS 子系统**（没有控制台），
	// `printf` 全进日志文件，而日志在运行期是**独占**打不开的
	// ⇒ 任何"静默失败"用户都完全看不到。
	// 实测事故：引擎被上一次会话留成僵尸 ⇒ 界面连不上 ⇒ 点「切换模式」
	// 只往日志里写一行"模式切换失败：引擎未连接"，用户看到的就是
	// **"点了完全没反应、徽章不变"**（2026-10-23）。
	//
	// 所以：① 徽章直接显示"未连接"（状态在窗口里可见）；
	//       ② 切换失败/其它动作失败时，在标题栏右侧画一行红字，8 秒后自己消失。
	// 默认 1（已连接）：避免界面刚起来、主循环还没轮询时闪一下"未连接"。
	volatile LONG g_engineConnected = 1;

	//
	// ★★★ v100：`g_notice` 必须**加锁** —— 这是 2026-10-23 那次
	//   「点了切换之后，连退出都没反应」的真正根因。
	//
	//   写它的线程：`app.cpp` 主循环（`ApplyMode` 失败时调 `ShowNotice`）。
	//   读它的线程：窗口线程（`PaintWindow` 画副标题那一行）。
	//
	//   原来的写法是裸 `std::wstring` 跨线程直接赋值 —— 而 `wstring::operator=`
	//   会**释放旧堆块、分配新块**。于是：
	//     · 窗口线程正拿着 `g_notice.c_str()` 在 `DrawText` 里读；
	//     · 主循环线程同时把这块内存释放掉；
	//     ⇒ 读到已释放内存，且两个线程并发进出 CRT 堆 ⇒ **堆锁死锁**。
	//
	//   症状极具迷惑性：**窗口线程还活着**（还能响应点击、还能打日志），
	//   但主循环线程永久卡住 ⇒ 「退出引擎」的请求再也没人消费
	//   ⇒ 用户看到的是"点了完全没反应"。而触发条件恰好是"切换失败"
	//   （只有失败路径才调 ShowNotice），所以看起来像"一切换就整个界面死了"。
	//
	//   修法：读写都走这把锁，并且**绘制侧先拷贝到局部变量再画**，
	//   把临界区压到最短（不能持锁调 `DrawText`，那会把窗口线程拖进来）。
	std::mutex g_noticeMutex;
	std::wstring g_notice;
	ULONGLONG g_noticeUntil = 0;

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

	// ------------------------------------------------------------------
	// ★★★ v93：逐帧动画时钟（id 4）
	//
	//   参考项目是 `glfwSwapInterval(1)` + 无限循环，每帧都重画 —— 手感是
	//   "60fps 连续推进 + 弹簧"的直接结果。本项目是常驻的安全软件，
	//   "不动鼠标时不占 CPU"是硬要求（ui_controls.h 开头那段）。
	//
	//   所以这里用"按需起表"的模型：
	//     · 任何交互（鼠标移动 / 按下 / 换页 / 换模式）→ EnsureAnimTimer()；
	//     · 16ms 一跳，每跳把 g_anim 里所有弹簧推进一帧并重画；
	//     · 全部收敛（g_anim.Tick 返回 false）→ KillTimer，回到 0 帧。
	//
	//   ⇒ 动画过程与参考项目逐帧同参数（k=320/d=30、press k=720/d=42、
	//     hover 14/s），静止时 CPU 占用为 0。两头都拿到。
	//
	//   ⚠️ 不要把它改成常驻定时器：那等于把"常驻安全软件不该持续重绘"
	//     这条前提推翻了，而且 16ms 一跳会让日志页/统计页的 300ms 节拍
	//     失去意义（数据没变也在重画）。
	constexpr UINT_PTR AnimTimerId = 4;
	constexpr UINT AnimTimerIntervalMs = 16;

	R3ShieldCoreUi::Anim::Bank g_anim;
	ULONGLONG g_animLastMs = 0;
	bool g_animRunning = false;   // 动画时钟是否已经在跑（见 EnsureAnimTimer）

	// ★★★ v95：背景"自己在变"的观察窗
	//
	//   问题（用户 2026-10-18 提的）："不动的时候不渲染，那我的背景变了怎么办？"
	//   —— 静止时我们只剩 id 1 那个 **300ms** 重画定时器，也就是背景以
	//   3.3fps 跟随。背后拖一个窗口时，玻璃会一顿一顿地跳。
	//
	//   参考项目是常驻 60fps 抓屏，所以它跟得死死的。我们不可能常驻
	//   （CPU 成本 + 常驻软件的前提），于是改成**按变化自适应**：
	//     · 每次重画后比对 `backdrop.refreshStamp`；
	//     · 变了 ⇒ 开一个 900ms 的观察窗 + 叫醒 16ms 快时钟；
	//     · 窗内主动抓一次（自己窗口在动 40ms / 其它 100ms，见 PaintWindow）；
	//     · 窗过期（背景 900ms 没再变）⇒ 快时钟自己停，回到 300ms 常态。
	//   ⇒ 背景一动，最多 300ms（一次常态重画）就被锁定，之后 25fps 跟随；
	//     背景一静，立刻回到"几乎不占 CPU"。
	ULONGLONG g_bgWatchUntil = 0;
	ULONGLONG g_bgForceAt = 0;
	unsigned long long g_bgLastStamp = 0;

	// 背景跟随间隔（ms）。默认 100（10fps）：
	//   实测这台机器上**一次带抓屏的重绘 ≈ 23ms**（BitBlt + 调色 + 模糊 +
	//   纹理上传），10fps ⇒ 约 25% 单核；40ms（25fps）会到 50%+。
	//   糊过的背景 10fps 看不出台阶，但"自己窗口被拖动"那 1.2 秒走 40ms，
	//   因为那一段用户盯得最紧。
	//   `R3SHIELDCORE_GLASS_FOLLOW_MS=<ms>` 可以改（想追 60fps 就设 16，
	//   但 CPU 会顶满 —— 帧率也上不去，因为一次重绘就要 23ms）。
	ULONGLONG g_bgFollowMs = 100;

	// 起表（幂等）。已经起着就只重置时间戳，避免第一帧 dt 很大。
	//
	// ⚠️ `g_animLastMs` 只在**从停到起**那一刻对齐。每帧都重置的话
	//   dt 会一直是 ~0，弹簧永远推不动 —— 表现是"动画卡在第一帧"，
	//   而且因为每帧都在画，看起来像"界面卡住了"。
	void EnsureAnimTimer()
	{
		if (!g_window) {
			return;
		}
		if (!g_animRunning) {
			g_animLastMs = GetTickCount64();
			g_animRunning = true;
		}
		SetTimer(g_window, AnimTimerId, AnimTimerIntervalMs, nullptr);
	}
	// 页签滑块的弹簧（x0 / x1 各一个：各页签宽度不同，用一个"索引弹簧"
	// 再插值会在宽度跳变时抖一下）。
	R3ShieldCoreUi::Anim::Spring g_tabThumbX0;
	R3ShieldCoreUi::Anim::Spring g_tabThumbX1;
	bool g_tabThumbInit = false;

	// ★ v94：换页时滑块的"挤压"（参考项目 dock 的 `g_dockW.v = 122` ——
	//   切换瞬间先比正常宽 12px，再弹回 110）。值 = **额外宽度**。
	//   没有它，滑块滑到位是"贴上去"的，缺一口气。
	R3ShieldCoreUi::Anim::Spring g_tabSqueeze;

	// ★ v94：在页签条上按住拖动时记着"正在拖"，鼠标划过哪段就切到哪段
	//   （参考项目 K_SEG 的 `g_dragId` 就是干这个的：按住可以滑过去）。
	int g_tabDrag = -1;

	// 动画 key：同一页上同一个位置的控件，跨帧必须得到同一个 key。
	// 用 (页号, x, y) 拼 —— 位置稳定、页号稳定，就够唯一了。
	// 不用"绘制顺序计数"：一页里某个元素条件出现（比如"无数据"占位）
	// 就会让后面所有 key 整体错位，动画会串到别的控件上。
	int AnimKey(int x, int y)
	{
		return ((g_activeTab & 0x0F) << 24)
			| ((y & 0x0FFF) << 12)
			| (x & 0x0FFF);
	}

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
	// ★★★ v98：自绘标题栏的三个窗口按钮（最小化 / 最大化-还原 / 关闭）
	//
	//   为什么要自绘：窗口已经去掉系统标题栏（`WS_CAPTION`），玻璃从窗口
	//   最上沿开始铺，否则顶上永远压着一条 31px 的系统灰条 —— 那一条既
	//   不透背景、也不跟圆角，整窗的"一块玻璃"就断在那一刀上。
	//
	//   ★ 尺寸/位置和「模式徽章」共用 `ModeBadgeTop` / `ModeBadgeHeight`：
	//     三个按钮和徽章必须在同一条水平线上，差 1px 都看得出来。
	//   ★ 三颗按钮靠右挤成一组（26+2+26+2+26 = 82），把右边的
	//     默认置顶 / 超级置顶 / 模式徽章整体往左让位 —— 见 ModeBadgeLeft()。
	// ------------------------------------------------------------------
	constexpr int CapBtnW = 26;
	constexpr int CapBtnH = 26;
	constexpr int CapBtnGap = 2;
	constexpr int CapClusterWidth = CapBtnW * 3 + CapBtnGap * 2;

	enum class CapBtn { Min = 0, Max = 1, Close = 2, None = -1 };

	RECT CapButtonRect(int i)
	{
		const int left = ClientWidth() - Padding - CapClusterWidth;
		const int x = left + i * (CapBtnW + CapBtnGap);
		return { x, ModeBadgeTop, x + CapBtnW, ModeBadgeTop + CapBtnH };
	}

	CapBtn HitTestCapButton(POINT p)
	{
		for (int i = 0; i < 3; ++i) {
			RECT r = CapButtonRect(i);
			if (PtInRect(&r, p)) {
				return static_cast<CapBtn>(i);
			}
		}
		return CapBtn::None;
	}

	// 模式徽章的左边界：让掉"窗口按钮簇"那一块。
	int ModeBadgeLeft()
	{
		return ClientWidth() - Padding - CapClusterWidth - HeaderToggleGap - ModeBadgeWidth;
	}

	CapBtn g_capHover = CapBtn::None;

	RECT SuperTopMostButtonRect()
	{
		const int badgeLeft = ModeBadgeLeft();
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

	// ------------------------------------------------------------------

	// ---------------------------------------------------------------------
	// ★★★ v86：绘制层接到 OpenGL 场景渲染器
	//
	//   参考项目 `LiquidGlassControls` 把**整个窗口**画在 GL 里：
	//   背景抓屏 + 模糊 → 玻璃层（有序）→ 实心层 → 图标层 → 文字层 → 一次上屏。
	//   本项目原来是"GDI 画内容 + 玻璃层当背景图"，玻璃再准，界面看起来
	//   仍然是"GDI 界面上贴了几张玻璃卡"。
	//
	//   这里做的是**换渲染栈、不换布局**：
	//   · 所有图元（面板 / 实心块 / 圆角 / 分隔线 / 文字）都写进 `g_scene`；
	//   · `g_scene` 由 `ui_gl.h` 在"面板画完、回读之前"回调，一次画完；
	//   · 各页的绘制函数**签名和坐标一个字都没改** —— 探针（`gui_exit_button_probe`、
	//     `gui_copy_all_logs_probe`）镜像了这些坐标，动布局等于让它们静默点空。
	//
	//   ★ 为了让 94 处 `DrawTextSimple` / 21 处 `FillRect` 不用逐个改写，
	//     这里给了两个**同名兼容层**（`DrawTextSimple` / `FillRect`）：
	//     调用写法不变，落点变成场景。`FillRect` 从 brush 里取颜色 ——
	//     `CreateSolidBrush` 造出来的就是 BS_SOLID，颜色能原样取回。
	// ---------------------------------------------------------------------
	R3ShieldCoreUi::SceneFont SceneFontOf(HFONT font)
	{
		using namespace R3ShieldCoreUi;
		if (font && font == g_titleFont) return SF_Title;
		if (font && font == g_valueFont) return SF_Value;
		if (font && (font == g_monoFont || font == g_logFont)) return SF_Mono;
		if (font && font == g_tabFont) return SF_Tab;
		if (font && font == g_boldFont) return SF_Bold;
		return SF_Label;
	}

	// ★ v87：玻璃模式下的三档文字色。
	//
	//   为什么不直接用 ColorTextPrimary / ColorTextSecondary：
	//   那是**不透明界面**上配的色（纯黑 + 中灰）。压在玻璃上时，中灰 (110) 会和
	//   玻璃的灰底糊成一片，整页看起来「没有字」。参考项目的做法是给三档
	//   **带一点冷调的墨色**（Ink / Dim / Faint），在浅玻璃上既有对比又不死黑。
	COLORREF InkColor()   { return g_glass.active ? UiCtl::ToColor(UiCtl::Ink)   : ColorTextPrimary; }
	COLORREF DimColor()   { return g_glass.active ? UiCtl::ToColor(UiCtl::Dim)   : ColorTextSecondary; }
	COLORREF FaintColor() { return g_glass.active ? UiCtl::ToColor(UiCtl::Faint) : ColorTextSecondary; }

	void DrawTextSimple(HDC /*dc*/, PCWSTR text, RECT rect, HFONT font, COLORREF color, UINT format)
	{
		using namespace R3ShieldCoreUi;
		if (!text) {
			return;
		}
		int flags = ST_Left;
		if (format & DT_CENTER) flags |= ST_Center;
		if (format & DT_RIGHT) flags |= ST_Right;
		// ★ GDI 的默认是**顶对齐**（DT_TOP == 0）；场景的默认是竖直居中
		//   ⇒ 没写 DT_VCENTER 的一律按顶对齐，否则整页文字会整体下沉半行。
		if (!(format & DT_VCENTER)) flags |= ST_Top;
		if (format & (DT_END_ELLIPSIS | DT_PATH_ELLIPSIS | DT_WORD_ELLIPSIS)) flags |= ST_Ellipsis;
		if (format & DT_WORDBREAK) flags |= ST_Wrap;
		g_scene.Text(text, rect.left, rect.top, rect.right, rect.bottom,
			SceneFontOf(font), SceneFromColorref(color), 1.0f, flags);
	}

	// 兼容层：`SceneFillRect(dc, &r, brush)` → 场景里一块实心矩形。
	// ★ 颜色从 brush 里取：`CreateSolidBrush` 造的是 BS_SOLID，
	//   `GetObjectW` 拿到的 `lbColor` 就是 RGB —— 调用方连改都不用改。
	int SceneFillRect(HDC /*dc*/, const RECT* rect, HBRUSH brush)
	{
		using namespace R3ShieldCoreUi;
		if (!rect || !brush) {
			return 0;
		}
		LOGBRUSH lb = {};
		if (GetObjectW(brush, sizeof(lb), &lb) != sizeof(lb) || lb.lbStyle != BS_SOLID) {
			return 0;
		}
		g_scene.Fill(rect->left, rect->top, rect->right, rect->bottom,
			SceneFromColorref(lb.lbColor));
		return 1;
	}

	// ---------------------------------------------------------------------
	// 内容层的**半透明**填充（v85 / v86 改成场景）
	// ---------------------------------------------------------------------
	//
	// ★ 玻璃界面里不能用不透明块画行底色 —— 那等于在卡片上盖一张实色贴纸。
	//   场景里直接给 alpha，比原来"1x1 DIB + AlphaBlend"干净得多。
	void BlendFillRect(HDC /*dc*/, const RECT& r, COLORREF c, BYTE alpha)
	{
		if (r.right <= r.left || r.bottom <= r.top || alpha == 0) {
			return;
		}
		g_scene.Fill(r.left, r.top, r.right, r.bottom,
			R3ShieldCoreUi::SceneFromColorref(c), static_cast<float>(alpha) / 255.0f);
	}

	// 登记一块玻璃面板（玻璃不可用时什么也不做）。
	//
	// ★ 面板表登记在 `g_glass.cur[]`（本帧现场登记的），合成时才被用到 ——
	//   所以必须在 `Compose()` **之前**调（见 ui_material.h 的三段式说明）。
	// ★ 为什么不用 `g_scene.Panel()`：场景自己的面板表是给离屏探针
	//   （`_t/scene_probe.cpp`）用的；主程序这条路上"面板"由合成层拥有，
	//   两边各留一份只会让"谁才是真源"变模糊（铁律 127 的精神）。
	void GlassPanel(int x0, int y0, int x1, int y1, float radius, float tint,
		int kind, COLORREF c)
	{
		if (!g_glass.active) {
			return;
		}
		g_glass.AddPanel(x0, y0, x1, y1, radius, tint, kind,
			GetRValue(c), GetGValue(c), GetBValue(c));
	}

	// 画一条水平柱状条。value / maxValue 决定填充比例。
	void DrawBar(HDC /*dc*/, int left, int top, int width, int height,
		ULONGLONG value, ULONGLONG maxValue, COLORREF color)
	{
		using namespace R3ShieldCoreUi;
		// 柱状条 = 一条凹槽 + 一段有色玻璃（和滑块/开关同一套材质）。
		const int radius = height / 2;
		const bool filledEnough = (maxValue != 0 && value != 0);

		if (g_glass.active) {
			GlassPanel(left, top, left + width, top + height, (float)radius,
				0.42f, 2, RGB(150, 160, 178));
			if (!filledEnough) {
				return;
			}
			float frac = static_cast<float>(static_cast<double>(value) / static_cast<double>(maxValue));
			if (frac > 1.0f) frac = 1.0f;
			int filled = static_cast<int>(width * frac);
			if (filled < height) filled = height;   // 非零值至少画一颗"圆头"
			GlassPanel(left, top, left + filled, top + height, (float)radius,
				0.86f, 1, color);
			return;
		}

		// ---- 经典（无玻璃）：凹槽 + 实色填充，v82 原样 ----
		g_scene.Round(left, top, left + width, top + height, (float)radius,
			SceneRgb(232, 236, 242));
		if (!filledEnough) {
			return;
		}
		float frac = static_cast<float>(static_cast<double>(value) / static_cast<double>(maxValue));
		if (frac > 1.0f) frac = 1.0f;
		int filled = static_cast<int>(width * frac);
		if (filled < height) filled = height;
		g_scene.Round(left, top, left + filled, top + height, (float)radius,
			SceneFromColorref(color));
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

	void DrawOverview(HDC dc, const RECT* cards, const R3ShieldCoreStats::Snapshot& snapshot,
		ULONG injectedTotal)
	{
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

		// ★ v87：三张**各自独立**的卡片（原来是不带卡的三列文字）。
		//   参考项目里每一组数据都住在自己的玻璃块里，靠缝分隔；三列文字浮在
		//   同一片底色上，看起来像"一段说明"而不是"三个指标"。
		for (int i = 0; i < 3; i++) {
			const RECT& card = cards[i];

			RECT labelRect = { card.left + CardPad, card.top + 15,
				card.right - CardPad, card.top + 33 };
			DrawTextSimple(dc, metrics[i].label, labelRect, g_labelFont, DimColor(),
				DT_LEFT | DT_SINGLELINE);

			RECT valueRect = { card.left + CardPad, card.top + 36,
				card.right - CardPad, card.bottom - 10 };
			DrawTextSimple(dc, metrics[i].value.c_str(), valueRect, g_valueFont, InkColor(),
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
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

		// ★★ v85：主按钮 = **蓝玻璃胶囊 + 白字**。
		//
		//   v83/v84 的做法是"白玻璃 + 蓝色文字 + 蓝色下划线"，理由是
		//   "彩色玻璃会变成实色贴纸"。结论对了一半：**浅色**玻璃上铺颜色确实脏，
		//   但参考项目的做法是**反过来** —— 玻璃掺得很实（0.88）、文字用**白色**，
		//   于是它读起来是"一块发光的蓝玻璃"，不是贴纸。
		//   蓝底白字对比度也远高于白底蓝字。
		if (g_glass.active) {
			// ★ v93：主按钮同样走逐帧插值（悬停淡入 + 按下缩 2.8%）。
			//   这一颗是顶栏最显眼的按钮，跳变最扎眼。
			const ButtonState state = StateOf(HeaderAction::ModeSwitch);
			R3ShieldCoreUi::Anim::Slot& mb =
				g_anim.Get(AnimKey(rect.left, rect.top), 0.0f);
			mb.hoverTgt = (state == ButtonState::Hover || state == ButtonState::Pressed)
				? 1.0f : 0.0f;
			mb.press.tgt = (state == ButtonState::Pressed) ? 1.0f : 0.0f;
			UiCtl::Pill(g_ui, rect, UiCtl::Btn::Primary, mb.hover, mb.press.v);
			textColor = RGB(255, 255, 255);
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
	// `quiet`：**安静档**。玻璃模式下常态不铺胶囊，只留一行字（悬停才浮出来）。
	//
	// ★ v87：页签那一行挤了 11 个元素（6 个页签 + 5 个动作）。如果每个动作都是
	//   一块胶囊玻璃，整行读起来就是"11 个同等重要的按钮"—— 主次全丢，
	//   而且胶囊边缘互相顶在一起，比"都靠边"更显脏。
	//   参考项目里一行最多两个胶囊（Continue / Cancel），其余都是纯文字。
	//   ⇒ 三个次要动作（复制日志 x2 / 清空统计）降到安静档，主次立刻出来。
	void DrawActionButton(HDC dc, HeaderAction id, const RECT& rect, PCWSTR text,
		bool active, COLORREF accent = ColorAccent, bool danger = false, bool quiet = false)
	{
		const ButtonState state = StateOf(id);
		COLORREF background = ColorHeaderBackground;
		COLORREF border = ColorBorder;
		COLORREF textColor = ColorTextSecondary;
		ButtonColors(active, danger, state, &background, &border, &textColor);

		// ★★ v85：语义色**铺到玻璃上**（参考项目就是这个做法）。
		//   危险 = 红玻璃白字；生效 = 强调色玻璃白字；中性 = 白玻璃深色字。
		//   三档之间一眼就能分出来，不再靠一条 1px 下划线去暗示。
		//
		// ★★★ v93：悬停 / 按下从"三态跳变"改成**逐帧插值**。
		//   参考项目 drawBtn 里是 `c.hover`（14/s 指数逼近）和 `c.press`
		//   （弹簧 k=720 d=42），按下时整块缩 2.8%。这里是同一组参数。
		//   三态仍然决定**目标值**，只是不再直接当开关用。
		if (g_glass.active) {
			R3ShieldCoreUi::Anim::Slot& a = g_anim.Get(AnimKey(rect.left, rect.top), 0.0f);
			a.hoverTgt = (state == ButtonState::Hover || state == ButtonState::Pressed) ? 1.0f : 0.0f;
			a.press.tgt = (state == ButtonState::Pressed) ? 1.0f : 0.0f;
			const float hoverK = a.hover;
			const float pressK = a.press.v;

			if (danger) {
				UiCtl::Pill(g_ui, rect, UiCtl::Btn::Danger, hoverK, pressK);
				textColor = RGB(255, 255, 255);
			} else if (active) {
				UiCtl::PillTone(g_ui, rect, UiCtl::FromColor(accent), 0.86f, hoverK, pressK);
				textColor = RGB(255, 255, 255);
			} else if (quiet && state == ButtonState::Normal) {
				// ★★ v88：安静档从"只有文字"改成"极淡的一层玻璃"。
				//
				//   上一版（v87）常态什么都不画，本意是让这三个次要动作退到
				//   背景里、不和页签凹槽抢注意力。但实测（日志页截图）：
				//   三个 6 字标签之间只有 8px 缝，**没有底色就没有边界** ——
				//   「复制全部日志」和「复制日志路径」连起来读成了
				//   「复制全部日志复制日志路径」一长串。
				//   参考项目的次按钮（Cancel / Details）也是"浅胶囊 + 8px 缝"，
				//   靠一块很淡的底划界，不靠留白。所以退回浅胶囊，
				//   只是掺色压到 0.30（页签凹槽是 0.55）—— 层级仍在页签之下。
				UiCtl::PillTone(g_ui, rect, UiCtl::Raised, 0.30f, hoverK, pressK);
				textColor = UiCtl::ToColor(UiCtl::Dim);
			} else {
				UiCtl::Pill(g_ui, rect, UiCtl::Btn::Glass, hoverK, pressK);
				// 文字色也跟着插值：从 Dim 走到 Ink，不是"一到悬停就跳黑"。
				textColor = UiCtl::ToColor(
					UiCtl::Mix(UiCtl::Dim, UiCtl::Ink, hoverK));
			}
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
		// ★ v85：玻璃模式下不再画那条 1px 下划线 —— 生效态已经靠
		//   "整块彩色玻璃 + 白字"表达，再叠一条线就是冗余。
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
		// ★ v87：这三个是**安静档**（最后一个参数 true）—— 常态只留文字，
		//   悬停才浮出胶囊。理由见 DrawActionButton 的注释。
		DrawActionButton(dc, HeaderAction::CopyAllLogs, CopyAllLogsButtonRect(),
			copyLogsLabel, copyLogsActive, ColorAccent, false, true);

		DrawActionButton(dc, HeaderAction::CopyLogPath, CopyLogButtonRect(),
			L"复制日志路径", false, ColorAccent, false, true);
		DrawActionButton(dc, HeaderAction::ClearStats, ClearStatsButtonRect(),
			L"清空统计", false, ColorAccent, false, true);
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
					// ★ v102：文案从 "requesting engine shutdown" 改成 "detaching"。
					//   旧文案是 v89 拆进程**之前**留下的：那时引擎活在界面进程里，
					//   界面重启必须把引擎一起停掉重建。拆完之后引擎是独立进程，
					//   界面重启只是**让出**管道，引擎继续防护、由新实例接管。
					//   ★ 这句日志是排障第一现场 —— 文案写错会把人直接带偏
					//   （上一轮就是照着 "requesting engine shutdown" 去查引擎为什么没起来）。
					printf("[gui] UIAccess handoff complete child=%lu; detaching from engine"
						" (engine keeps running)\n",
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
		// ★ v88：中性档标记。LOG = "只记录、不拦截"，它**没有**要强调的语义，
		//   而原来给的是 RGB(160,160,160) 掺 0.86 —— 一块深灰实底 + 白字，
		//   成了整个顶栏最重的一块色，比 BLOCK 还抢眼，语义正好反了。
		//   现在中性档走浅玻璃 + 墨色字：它是一枚"状态标签"，不是一枚"告警"。
		bool neutral = true;

		switch (static_cast<R3ShieldCore::Mode>(InterlockedCompareExchange(&g_displayMode, 0, 0))) {
		case R3ShieldCore::Mode::Block:
			text = L"BLOCK";
			color = ColorBlocked;
			neutral = false;
			break;
		case R3ShieldCore::Mode::Ask:
			text = L"ASK";
			color = ColorWouldBlock;
			neutral = false;
			break;
		case R3ShieldCore::Mode::BlockAll:
			text = L"全拦";
			color = ColorBlockAll;
			neutral = false;
			break;
		case R3ShieldCore::Mode::BlockAllSafe:
			// 用同一个破坏性配色（它同属"全拦"家族），只是文案区分。
			text = L"全拦·安全";
			color = ColorBlockAll;
			neutral = false;
			break;
		default:
			break;
		}

		// ★ v91：引擎没连上 ⇒ 徽章直接说"未连接"。
		//
		//   为什么不照旧显示真实模式：模式切换必须经引擎才生效，连不上时点按钮
		//   **一定**失败，而失败原因只进日志（界面是 WINDOWS 子系统，没有控制台；
		//   日志运行期还独占打不开）⇒ 用户看到的就是"点了完全没反应"。
		//   徽章上把状态写出来，比"显示一个切不动的模式"诚实（铁律 97）。
		if (InterlockedCompareExchange(&g_engineConnected, 0, 0) == 0) {
			text = L"未连接";
			color = ColorWouldBlock;   // 复用警示色：这确实是异常状态
			neutral = false;
		}

		// 尺寸走文件头的共用常量 —— 置顶按钮靠它右对齐，两边必须同源。
		int left = ModeBadgeLeft();

		RECT badge = { left, top, left + ModeBadgeWidth, top + ModeBadgeHeight };

		// ★ v85：徽章 = 一块**该模式语义色**的实玻璃（掺 0.86），白字。
		//   原来那个实色 RoundRect 在玻璃界面上像一张贴纸 —— 它下面没有
		//   任何模糊背景透上来，一眼就看得出"这块不是材质"。
		if (g_glass.active) {
			if (neutral) {
				// 中性档：浅玻璃（Raised 掺 0.52），和页签凹槽是同一个明度家族。
				UiCtl::Badge(g_ui, badge, UiCtl::Raised, 0.52f);
			} else {
				UiCtl::Badge(g_ui, badge, UiCtl::FromColor(color), 0.86f);
			}
		} else {
			HBRUSH brush = CreateSolidBrush(color);
			HGDIOBJ oldBrush = SelectObject(dc, brush);
			HPEN pen = CreatePen(PS_SOLID, 1, color);
			HGDIOBJ oldPen = SelectObject(dc, pen);
			RoundRect(dc, badge.left, badge.top, badge.right, badge.bottom, 13, 13);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(brush);
			DeleteObject(pen);
		}

		// 中性档的底是浅玻璃 ⇒ 文字必须是墨色；彩色档（BLOCK/ASK/全拦）
		// 掺 0.86 足够深，白字才站得住。
		const COLORREF badgeText = (g_glass.active && neutral)
			? UiCtl::ToColor(UiCtl::Ink) : RGB(255, 255, 255);
		DrawTextSimple(dc, text, badge, g_labelFont, badgeText,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	// ★★★ v98/v99：三个窗口按钮。
	//
	//   字形**不用字体画，用几何图形画**。这不是洁癖，是被坑出来的：
	//   第一版用文本字形（− / □ / ✕），其中 U+2715 ✕ 在 `Microsoft YaHei UI`
	//   里**根本不存在**（`GetGlyphIndicesW` 返回 0xFFFF），画出来是空白 ——
	//   于是"关闭按钮看不见，但点上去照样关窗口"（命中测试用矩形，不看字形）。
	//   换 `Segoe MDL2 Assets` 的原生码位（E921/E922/E8BB）也不行：本项目
	//   内容层走 `ui_scene.h` 的自带光栅器，它按 (字号,字重) 自己建字体
	//   （`FontFor`），**根本不看调用方传的 HFONT** ⇒ 私有区码位落到
	//   YaHei 的 .notdef，三个按钮画出同一个方框。
	//   ⇒ 一律用 `g_scene.Round()` 画线：不依赖任何字体，1px 精度可控。
	//     这本来也是 Windows 自己画标题栏按钮的方式。
	void DrawCaptionButtons(HDC dc)
	{
		(void)dc;
		if (!g_glass.active) {
			return;   // 经典模式没有自绘标题栏（还留着系统标题栏）
		}
		const bool zoomed = IsZoomed(g_window) != FALSE;
		const CapBtn ids[3] = { CapBtn::Min, CapBtn::Max, CapBtn::Close };

		for (int i = 0; i < 3; ++i) {
			RECT r = CapButtonRect(i);
			const bool hot = (g_capHover == ids[i]);
			if (hot) {
				if (ids[i] == CapBtn::Close) {
					UiCtl::PillTone(g_ui, r, UiCtl::Red, 0.82f, 1.0f, 0.0f);
				} else {
					UiCtl::PillTone(g_ui, r, UiCtl::Raised, 0.42f, 1.0f, 0.0f);
				}
			}
			const COLORREF gc = hot
				? (ids[i] == CapBtn::Close ? RGB(255, 255, 255) : UiCtl::ToColor(UiCtl::Ink))
				: UiCtl::ToColor(UiCtl::Dim);
			const unsigned col = R3ShieldCoreUi::SceneFromColorref(gc);
			const int cx = (r.left + r.right) / 2;
			const int cy = (r.top + r.bottom) / 2;
			auto bar = [&](int x0, int y0, int x1, int y1) {
				g_scene.Round(x0, y0, x1, y1, 0.0f, col, 1.0f);
			};

			if (ids[i] == CapBtn::Min) {
				bar(cx - 5, cy, cx + 5, cy + 1);
			} else if (ids[i] == CapBtn::Max && !zoomed) {
				const int h = 4;
				bar(cx - h, cy - h, cx + h + 1, cy - h + 1);   // 上
				bar(cx - h, cy + h, cx + h + 1, cy + h + 1);   // 下
				bar(cx - h, cy - h, cx - h + 1, cy + h + 1);   // 左
				bar(cx + h, cy - h, cx + h + 1, cy + h + 1);   // 右
			} else if (ids[i] == CapBtn::Max) {
				// 还原：两个错开 2px 的方框（后框只画上/左两条边，被前框压住）
				const int h = 4;
				bar(cx - h - 2, cy - h - 2, cx + h - 1, cy - h - 1);
				bar(cx - h - 2, cy - h - 2, cx - h - 1, cy + h - 1);
				bar(cx - h + 1, cy - h + 1, cx + h + 1, cy - h + 2);
				bar(cx - h + 1, cy + h, cx + h + 1, cy + h + 1);
				bar(cx - h + 1, cy - h + 1, cx - h + 2, cy + h + 1);
				bar(cx + h, cy - h + 1, cx + h + 1, cy + h + 1);
			} else {
				// 关闭：1px 步进的 45° 斜线 —— 每步正好一格，就是 Bresenham，
				// 不需要三角剖分，也不会出现台阶。
				// 每步画 2x1 而不是 1x1：纯 1px 的对角线像素密度只有横线的一半，
				// 看上去会"比 − 和 □ 淡一档"。加宽一格刚好补回来。
				for (int k = -4; k <= 4; ++k) {
					bar(cx + k, cy + k, cx + k + 2, cy + k + 1);
					bar(cx + k, cy - k, cx + k + 2, cy - k + 1);
				}
			}
		}
	}

	void DrawDecisionBreakdown(HDC dc, const RECT& card, const R3ShieldCoreStats::Snapshot& snapshot)
	{
		const int left = card.left + CardPad;
		const int right = card.right - CardPad;

		RECT headerRect = { left, card.top + CardPad, right, card.top + CardPad + 20 };
		// v88：与 DrawPanel 的卡片标题同色（分组标签一档），否则同一页上
		// 会出现两种"卡片标题"，一个深一个浅。
		DrawTextSimple(dc, L"决策分布", headerRect, g_labelFont, FaintColor(), DT_LEFT | DT_SINGLELINE);

		int y = card.top + CardPad + 28;

		// 柱状条按卡片宽度算：标签列固定 104，数值列固定 52，剩下的都给条。
		// ★ 不能写死宽度 —— 窗口能拉宽，写死的话条会浮在卡片左边、右边空一大片。
		//
		// ★★ v88：标签从**右对齐**改成**左对齐**。
		//   右对齐时短标签（SPOOF/ALLOW）会缩到条边上，卡片左边 100px 全是空白，
		//   而"WOULD-BLOCK"又把整列撑到最长 —— 视觉上像"半个卡片是空的"。
		//   左对齐 + 固定列宽后，四个标签从同一条竖线起，条也从同一条竖线起。
		constexpr int labelW = 104;
		constexpr int valueW = 52;
		const int barLeft = left + labelW + 8;
		int barWidth = right - valueW - 8 - barLeft;
		if (barWidth < 40) {
			barWidth = 40;
		}
		const int valueLeft = right - valueW;

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

			// ★ DT_END_ELLIPSIS 是**保险**：文本比矩形宽时，GDI 会
			//   从矩形右缘**往外**画（不裁剪、不报错）—— 自绘界面里就是"字跑到卡片外面"。
			RECT labelRect = { left, y + 4, barLeft - 8, y + 24 };
			DrawTextSimple(dc, label, labelRect, g_monoFont, FaintColor(),
				DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			DrawBar(dc, barLeft, y + 6, barWidth, 14,
				snapshot.DecisionCounts[i], maxValue, DecisionColor(decision));

			RECT valueRect = { valueLeft, y + 4, right, y + 24 };
			std::wstring value = FormatNumber(snapshot.DecisionCounts[i]);
			DrawTextSimple(dc, value.c_str(), valueRect, g_monoFont, InkColor(),
				DT_RIGHT | DT_SINGLELINE | DT_VCENTER);

			y += 32;
		}
	}

	void DrawOpBreakdown(HDC dc, const RECT& card, const R3ShieldCoreStats::Snapshot& snapshot, int maxRows)
	{
		const int left = card.left + CardPad;
		const int right = card.right - CardPad;

		RECT headerRect = { left, card.top + CardPad, right, card.top + CardPad + 20 };
		DrawTextSimple(dc, L"操作分布（按次数）", headerRect, g_labelFont, FaintColor(),
			DT_LEFT | DT_SINGLELINE);

		// ★★ v87：**删掉**了原来挤在标题右边的那 15 条彩色图例。
		//
		//   它本来是"类型 -> 颜色"的对照表，但 15 个中文词平铺在同一行里，
		//   和左边的标题几乎贴在一起，读起来是一片彩色的噪点（v82 的注释里
		//   已经记过"和标题叠字"，当时只是把字号/起点调了调，没解决根本问题）。
		//   现在改成**每行操作名前面一个色点**：颜色和类型的对应关系不用再记，
		//   看哪行就是哪行 —— 参考项目里也没有图例，靠颜色本身说话。
		int y = card.top + CardPad + 28;


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
			RECT emptyRect = { left, y, right, y + 24 };
			DrawTextSimple(dc, L"(暂无数据)", emptyRect, g_labelFont, FaintColor(),
				DT_LEFT | DT_SINGLELINE);
			return;
		}

		size_t count = merged.size() < 8 ? merged.size() : 8;
		if (static_cast<int>(count) > maxRows) {
			count = static_cast<size_t>(maxRows > 0 ? maxRows : 0);
		}
		ULONG maxCount = merged[0].count;

		// ★ v88：与「决策分布」同一套列宽/对齐（左对齐标签 + 右对齐数值），
		//   两卡片并排时列线才会齐；原来是 118/52 且数值左对齐，两张卡的
		//   条起点和数字位置都差几个像素，看起来像"两张没对齐的图"。
		constexpr int labelW = 124;
		constexpr int valueW = 52;
		const int barLeft = left + labelW + 8;
		int barWidth = right - valueW - 8 - barLeft;
		if (barWidth < 40) {
			barWidth = 40;
		}
		const int valueLeft = right - valueW;

		for (size_t i = 0; i < count; i++) {
			// 名字必须按来源翻：文件 op 走 FileOpName、进程走 ProcessOpName……
			// 混用的话文件事件的 op=3(Write) 会被当成注册表的 SetValueKey 显示。
			const char* rawName = R3ShieldCore::AnyOpName(merged[i].objectType, merged[i].op);

			WCHAR label[64] = {};
			MultiByteToWideChar(CP_ACP, 0, rawName, -1, label, _countof(label));

			// 色点：类型 -> 颜色，6px 的小圆，替代原来那排图例。
			const COLORREF typeColor = ObjectTypeColor(merged[i].objectType);
			if (g_glass.active) {
				UiCtl::Piece(g_ui, left, y + 9, left + 6, y + 15, 3.0f, 0.92f,
					UiCtl::FromColor(typeColor), UiCtl::KPiece);
			} else {
				RECT dot = { left, y + 9, left + 6, y + 15 };
				HBRUSH dotBrush = CreateSolidBrush(typeColor);
				SceneFillRect(dc, &dot, dotBrush);
				DeleteObject(dotBrush);
			}

			RECT labelRect = { left + 12, y + 4, barLeft - 8, y + 24 };
			DrawTextSimple(dc, label, labelRect, g_monoFont, FaintColor(),
				DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			DrawBar(dc, barLeft, y + 6, barWidth, 14, merged[i].count, maxCount,
				typeColor);

			RECT valueRect = { valueLeft, y + 4, right, y + 24 };
			std::wstring value = FormatNumber(merged[i].count);
			DrawTextSimple(dc, value.c_str(), valueRect, g_monoFont, InkColor(),
				DT_RIGHT | DT_SINGLELINE | DT_VCENTER);

			y += 32;
		}
	}

	void DrawTopProcesses(HDC dc, const RECT& card, const R3ShieldCoreStats::Snapshot& snapshot, int maxRows)
	{
		const int left = card.left + CardPad;
		const int right = card.right - CardPad;

		RECT headerRect = { left, card.top + CardPad, right, card.top + CardPad + 20 };
		DrawTextSimple(dc, L"触发最多的进程", headerRect, g_labelFont, FaintColor(), DT_LEFT | DT_SINGLELINE);

		int y = card.top + CardPad + 28;

		if (snapshot.TopProcesses.empty() || maxRows <= 0) {
			RECT emptyRect = { left, y, right, y + 24 };
			DrawTextSimple(dc, L"(暂无数据)", emptyRect, g_labelFont, FaintColor(),
				DT_LEFT | DT_SINGLELINE);
			return;
		}

		ULONG maxTotal = snapshot.TopProcesses.front().Total;
		constexpr int labelW = 210;
		constexpr int valueW = 120;
		const int barLeft = left + labelW;
		int barWidth = right - valueW - 10 - barLeft;
		if (barWidth < 60) {
			barWidth = 60;
		}
		const int valueLeft = barLeft + barWidth + 10;

		size_t count = snapshot.TopProcesses.size() < 6 ? snapshot.TopProcesses.size() : 6;
		if (static_cast<int>(count) > maxRows) {
			count = static_cast<size_t>(maxRows);
		}
		for (size_t i = 0; i < count; i++) {
			const auto& process = snapshot.TopProcesses[i];

			std::wstring name = process.Name.empty()
				? (L"PID " + std::to_wstring(process.ProcessId))
				: (process.Name + L" (" + std::to_wstring(process.ProcessId) + L")");

			RECT labelRect = { left, y + 4, barLeft - 8, y + 24 };
			DrawTextSimple(dc, name.c_str(), labelRect, g_monoFont, FaintColor(),
				DT_RIGHT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			// 被拦的部分用红色叠在上面，一眼看出"谁被拦得最多"。
			COLORREF color = process.Blocked > 0 ? ColorBlocked : ColorAccent;
			DrawBar(dc, barLeft, y + 6, barWidth, 14, process.Total, maxTotal, color);

			RECT valueRect = { valueLeft, y + 4, right, y + 24 };
			std::wstring value = FormatNumber(process.Total);
			if (process.Blocked > 0) {
				value += L"  (拦 " + FormatNumber(process.Blocked) + L")";
			}

			DrawTextSimple(dc, value.c_str(), valueRect, g_monoFont, InkColor(),
				DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

			y += 26;
		}
	}

	void DrawPromptSummary(HDC dc, int clientHeight, const R3ShieldCoreStats::Snapshot& snapshot)
	{
		// 贴底绘制。用真实客户区高度而不是窗口常量 —— 标题栏会吃掉几十像素，
		// 用窗口常量会让这一栏跑到可视区外面去。
		const int top = clientHeight - PromptSummaryHeight();

		// ★ v85：底部这一栏也垫玻璃 —— 它是"状态条"，浮在最下面一层，
		//   和上面的内容卡同材质才像一个整体。分隔线在玻璃模式下不画
		//   （卡的边+投影已经够了，再压一条实线反而脏）。
		if (g_glass.active) {
			RECT bar = { Padding - 12, top + 4, ClientWidth() - Padding + 12, clientHeight - 4 };
			UiCtl::Card(g_ui, bar, 0.44f);
		} else {
			RECT separator = { Padding, top, ClientWidth() - Padding, top + 1 };
			HBRUSH brush = CreateSolidBrush(ColorBorder);
			SceneFillRect(dc, &separator, brush);
			DeleteObject(brush);
		}

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
			// ★ v85：卡片 = 奶白玻璃（掺 Card 0.52）。圆角 24 比 v84 的 18 更圆，
			//   跟参考项目一个调门 —— 圆角太小会让"玻璃"读成"圆角矩形"。
			UiCtl::Card(g_ui, rect);
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

		RECT titleRect = { rect.left + CardPad, rect.top + 15,
			rect.right - CardPad, rect.top + 33 };
		// ★ v85：卡片标题用**次要色**而不是主文字色 —— 参考项目里
		//   标题是"分组标签"，不是内容；涂成近黑会和正文抢注意力。
		// ★ v88：Dim(51,56,71) -> Faint(92,97,115)。
		//   实测 Dim 和正文 ColorTextPrimary(24,24,24) 在小字号下**看不出差别**：
		//   配置页的「监控面板」和第一行「高危规则」长得一模一样，标题读成了
		//   内容的一部分。参考项目的分组标签（SWITCHES / SLIDERS）明显更淡一档，
		//   层级是靠**明度**拉开的，不是靠字号 —— 我们字号只有一个，那就只能靠色。
		DrawTextSimple(dc, title, titleRect, g_labelFont, FaintColor(),
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

		// ★ v88：+44 → +52。卡片标题占 top+15~33，表头原来紧跟其后（+44 只差
		//   11px），"进程活动明细"和列名挤成一坨；52 让标题和列名分成两层。
		const int headerTop = tableTop + 52;
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
			// ★ v85：玻璃模式下**不画**斑马纹 —— 不透明实色条会把卡片切成一段段
			//   色带，"玻璃"立刻变回"贴纸"。横向对行靠列对齐 + 行距就够了。
			if (!g_glass.active && i % 2 == 1) {
				RECT stripe = { left + 8, rowTop - 4, right - 8, rowTop + rowHeight - 4 };
				HBRUSH stripeBrush = CreateSolidBrush(ColorLogRowAlt);
				SceneFillRect(dc, &stripe, stripeBrush);
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

		// 面板标题 34 + 表头 26 —— ★ v88：标题区 34 → 46，表头下移
		//   （与进程页 +52 同一节奏：标题 / 列名 / 行 三层要分开）
		layout.RowsTop = layout.MainTop + 46 + 26;
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

		// ★★ v85：ARK / 「高级」跳转页的按钮也统一成**玻璃胶囊**。
		//   禁用态**还是不加玻璃**（一块"什么都没写"的玻璃看起来像可点的按钮，
		//   而禁用必须一眼看出"点不动"）；危险动作走红玻璃 + 白字。
		if (g_glass.active) {
			if (enabled) {
				// ★ v93：ARK / 「高级」页的按钮同样逐帧插值，和顶栏那颗同参数。
				R3ShieldCoreUi::Anim::Slot& ab =
					g_anim.Get(AnimKey(rect.left, rect.top), 0.0f);
				ab.hoverTgt = hovered ? 1.0f : 0.0f;
				ab.press.tgt = pressed ? 1.0f : 0.0f;
				const float hk = ab.hover;
				const float pk = ab.press.v;
				const float radius = static_cast<float>(rect.bottom - rect.top) * 0.5f;
				if (danger) {
					UiCtl::Pill(g_ui, rect, UiCtl::Btn::Danger, hk, pk);
					text = RGB(255, 255, 255);
				} else {
					UiCtl::PieceR(g_ui, rect, radius, 0.62f + 0.05f * hk + 0.05f * pk,
						UiCtl::Raised, UiCtl::KPiece);
					text = UiCtl::ToColor(UiCtl::Mix(UiCtl::Dim, UiCtl::Ink,
						hk > pk ? hk : pk));
				}
			} else {
				// ★ v88：禁用态画成**凹槽**，不是"什么都不画"。
				//   原来禁用时一块底都没有，只剩一行 170 灰的字浮在浅色卡片上 ——
				//   ARK 页在"没选中进程"时四个按钮全禁用，看起来像四行说明文字，
				//   用户根本不知道那儿本来有按钮。
				//   凹槽（kind 2）刚好表达"这里有个位子，但现在按不下去"，
				//   和开关的"关"、柱状条的轨道是同一种语言。
				const float radius = static_cast<float>(rect.bottom - rect.top) * 0.5f;
				UiCtl::PieceR(g_ui, rect, radius, 0.46f, UiCtl::Sunken, UiCtl::KWell);
				text = UiCtl::ToColor(UiCtl::Faint);
			}
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
		// ★★ v90：修「ARK 页一直显示"引擎正在初始化"、列表永远不出来」。
		//
		//   根因：`RefreshArkCache()` 有节流（`ark_refresh_ms`，默认 1000ms）。
		//   窗口一建好就先画了一帧，那一帧取到的是**ARK 模块还没 Start 时**的
		//   零快照（`Started=0 / Scans=0 / Rows=空`）。之后虽然 ARK 起来了，
		//   但只要节流窗口内的那次取快照被跳过，界面就一直捧着这份零快照 ——
		//   而这一页的文案是"ARK 尚未启动（引擎正在初始化）"，
		//   于是用户看到的就是"一直在加载"。
		//   （实测日志：整场只有一行 `[ark] 页面已绘制 行数=0 已启动=0 已扫描=0`，
		//     引擎那边却已经 `[ark] 已启用 …` 并在正常心跳。）
		//
		//   修法：拿**模块自己的状态**跟快照对一下，不一致就强制重取一次。
		//   判据用 `IsEnabled()`（模块真状态）而不是快照里的字段 ——
		//   用快照自己的字段判断，等于让"错的缓存"证明自己没错。
		if (!g_arkSnapshot.Stat.Started && R3ShieldCoreArk::IsEnabled()) {
			RefreshArkCache(true);
		}
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
				//
				// ★ v90：这里再分一层 —— "模块其实已经启用、只是首轮扫描还没完成"
				//   不能写成"引擎正在初始化"，否则用户会以为卡住了（他报的
				//   "ARK 一直显示正在加载"就是这么来的）。
				if (R3ShieldCoreArk::IsEnabled()) {
					summary = L"ARK 已启用，正在等首轮扫描完成 —— 列表马上出来。";
				}
				else {
					summary = L"ARK 尚未启动（引擎正在初始化）—— 列表暂时为空。";
				}
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
			// ★ v88：玻璃模式下给摘要行垫一条**玻璃片**。
			//   原来这行字直接浮在背景上：橙色字压在一片渐变里，读起来像
			//   "一条报错横幅挂在半空"，而且和下面的卡片没有任何关系。
			//   垫上之后它属于"状态条"这一层，和顶栏/页签同一材质。
			if (g_glass.active) {
				RECT strip = { layout.Left, layout.SummaryTop - 3,
					layout.Right, layout.SummaryTop + 21 };
				UiCtl::PieceR(g_ui, strip, (strip.bottom - strip.top) * 0.5f, 0.58f,
					UiCtl::CardTone, UiCtl::KPiece);
			}
			DrawTextSimple(dc, summary.c_str(),
				{ layout.Left + 12, layout.SummaryTop, layout.Right - 12, layout.SummaryTop + 22 },
				g_labelFont, stat.Enabled ? ColorTextSecondary : ColorWouldBlock,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);		}

		// ---------------- 进程表 ----------------
		RECT tablePanel = { layout.TableLeft, layout.MainTop, layout.TableRight, layout.MainBottom };
		DrawPanel(dc, tablePanel, L"全部进程（Toolhelp 快照，含受保护进程）");

		const int headerTop = layout.MainTop + 46;
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

				// ★ v85：选中行改用**半透明**叠色（见 BlendFillRect）——
				//   原来的实色浅蓝在玻璃卡上是一块不透明贴纸，把背景糊掉。
				//   斑马纹在玻璃模式下取消（同进程页）。
				if (isSelected) {
					RECT mark = { layout.TableLeft + 8, rowTop - 2, layout.TableRight - 8, rowTop + ArkRowHeight - 4 };
					if (g_glass.active) {
						BlendFillRect(dc, mark, RGB(64, 132, 220), 56);
					} else {
						HBRUSH brush = CreateSolidBrush(RGB(214, 232, 250));
						SceneFillRect(dc, &mark, brush);
						DeleteObject(brush);
					}
				}
				else if (!g_glass.active && i % 2 == 1) {
					RECT stripe = { layout.TableLeft + 8, rowTop - 2, layout.TableRight - 8, rowTop + ArkRowHeight - 4 };
					HBRUSH brush = CreateSolidBrush(ColorLogRowAlt);
					SceneFillRect(dc, &stripe, brush);
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
			SceneFillRect(dc, &stripe, stripeBrush);
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

	// =================================================================
	// ★★★ v103：「配置」页的开关变成**真能拨的**
	// =================================================================
	//
	// 用户的诉求就一句：「主程序配置页里的开关用不了，点不动」。
	//
	// 以前这一页是**只读**的（v85 的注释里明写着「开关不接受点击，配 ini 才行」）。
	// 问题是：它画成了开关的样子，用户就会去拨；拨不动，第一反应不是
	// "这页只读"，而是**"软件坏了"** —— 按了没反应比不放开关更糟。
	//
	// -----------------------------------------------------------------
	// 设计：**一个寄存区 + 一个按钮**
	// -----------------------------------------------------------------
	//
	// 为什么不"点一下直接写 ini"：
	//   · 这些开关决定的是**注入 DLL 的 hook 面**（`FlagHook*`），落在共享内存的
	//     `Policy` 块里。引擎只在 **LoadLibrary 那一刻**读它；
	//   · 也就是说"改了对已经注入的 233 个进程**没有任何影响**"，必须重新注入。
	//     让用户点一下就"看起来生效了"，是另一种谎。
	//
	// 所以：点开关 ⇒ 只改**待提交值**；右侧多出一颗「应用并重启引擎」，
	// 按下去才真写 ini + 重启引擎。没改动时那颗按钮**不出现**（不占位置、不误导）。
	//
	// ★ 主窗口和 cfg 工具是**同一个 exe 的两份进程**，但这里是主程序 exe 的
	//   源码，cfg 不 include 这个文件 ⇒ 不会牵连到 cfg 的构建。
	enum class ConfigField : int
	{
		None = -1,
		HighRisk = 0,
		HookReads,
		HookFile,
		HookProcess,
		HookThread,
		HookDriver,
		HookSelfThread,
		HighRiskProcessAlert,
		ArkEnabled,
		Count
	};

	// 寄存区：用户拨过、但还没按「应用」的值。`dirty == false` 时一律以
	// 引擎给的真值为准（= 现在绘制出来的那个值）。
	struct PendingConfig
	{
		bool dirty = false;
		bool value[static_cast<int>(ConfigField::Count)] = {};
	};

	PendingConfig g_pendingConfig;

	// 把一个字段的"引擎当前真值"取出来。
	//
	// ★★ 必须和 `app.cpp` 填 `R3ShieldCoreGui::Options` 的口径**逐字一致**
	//   （铁律 127：同一个判断只写一次）。写岔了的后果不是崩溃，而是
	//   "拨完之后开关自己弹回去" —— 用户会以为又没反应。
	bool CurrentConfigValue(ConfigField field)
	{
		switch (field) {
		case ConfigField::HighRisk:
			return g_options.HighRisk;
		case ConfigField::HookReads:
			// ★ 界面上这一行是「注册表只读 / Hive」两项合一 ——
			//   读到的是**或**，但取消时两项都关。这条语义在 Apply 里体现。
			return g_options.HookReads || g_options.HookHive;
		case ConfigField::HookFile:
			return g_options.HookFile;
		case ConfigField::HookProcess:
			return g_options.HookProcess;
		case ConfigField::HookThread:
			return g_options.HookThread;
		case ConfigField::HookDriver:
			return g_options.HookDriver;
		case ConfigField::HookSelfThread:
			return g_options.HookSelfThread;
		case ConfigField::HighRiskProcessAlert:
			return g_options.HighRiskProcessAlert != 0;
		case ConfigField::ArkEnabled:
			return g_options.ArkEnabled;
		default:
			return false;
		}
	}

	// 绘制 / 命中 / 提交三处共用的"显示值"：有改动看寄存区，否则看引擎。
	bool DisplayConfigValue(ConfigField field)
	{
		if (field == ConfigField::None) {
			return false;
		}
		if (!g_pendingConfig.dirty) {
			return CurrentConfigValue(field);
		}
		return g_pendingConfig.value[static_cast<int>(field)];
	}

	void SetPendingConfig(ConfigField field, bool value)
	{
		if (field == ConfigField::None) {
			return;
		}
		g_pendingConfig.value[static_cast<int>(field)] = value;
		g_pendingConfig.dirty = true;
	}

	// 把寄存区里的改动拼成 ini 行（返回给 app.cpp 去写 + 重启引擎）。
	//
	// 为什么返回"行"而不是直接写：**写 ini 和重启引擎是主程序的活**
	// （它才知道 exe 目录、才知道怎么干净地停引擎）。界面线程碰文件 I/O
	// 会卡住整屏重绘 —— v101 就是栽在"在 UI 线程上做重活"。
	//
	// `ark_enabled` 不在 ini 的引擎配置里（它属于界面侧设置），
	// 所以它单独用一条 `ConfigApplyRequest.arkEnabled` 带出去。
	struct ConfigApplyRequest
	{
		bool valid = false;
		std::vector<std::wstring> lines;   // 每行形如 `hook_file=0`
		bool arkPresent = false;
		bool arkEnabled = false;
	};

	ConfigApplyRequest g_configApply;

	// ★ 待处理标记 + 锁必须在**第一次使用之前**声明（`BuildConfigApplyRequest`
	//   和点击处理都在下面）。原来放在文件尾的 `TakeConfigApplyRequest` 旁边，
	//   结果上面两处都成了"未声明的标识符"——编译期才发现，属于好消息。
	std::mutex g_configApplyMutex;
	LONG g_configApplyPending = 0;

	// ★ 前置声明：点击处理（`WndProc` 的 `WM_LBUTTONDOWN`）在文件里出现的
	//   位置比 `ShowNotice` 的**定义**早。C++ 里"先声明后使用"，少这一行就是
	//   `error C3861: 找不到标识符`。
	//
	// ★★ 但这个声明**不能**写在这里 —— 这里还在匿名命名空间（文件顶部
	//   `namespace {`），而 `ShowNotice` 定义在 `namespace R3ShieldCoreGui`
	//   里面。在匿名命名空间里声明一个同名同签名的函数，得到的是**另一个**
	//   函数（mangled name 不同）⇒ 编译全过、链接 `LNK2019: 无法解析`。
	//   ⇒ 用**限定名**声明/调用，见 `WndProc` 里那处 `R3ShieldCoreGui::ShowNotice`。

	// 各字段对应的 ini 键。返回 nullptr = 这一项不能靠写 ini 生效
	// （目前只有 `ark_enabled`，它走单独的字段）。
	PCWSTR ConfigIniKey(ConfigField field)
	{
		switch (field) {
		case ConfigField::HighRisk:
			return L"high_risk";
		case ConfigField::HookFile:
			return L"hook_file";
		case ConfigField::HookProcess:
			return L"hook_process";
		case ConfigField::HookThread:
			return L"hook_thread";
		case ConfigField::HookDriver:
			return L"hook_driver";
		case ConfigField::HookSelfThread:
			return L"hook_self_thread";
		case ConfigField::HookReads:
			// 这一行管**两个**键，由 ApplyPendingConfig 单独展开
			return L"hook_reads+hook_hive";
		case ConfigField::HighRiskProcessAlert:
			return L"high_risk_process_alert";
		default:
			return nullptr;
		}
	}

	// =================================================================
	// 布局：**一个几何函数**同时给绘制和命中使用
	// =================================================================
	//
	// ★ 为什么不做成"绘制时顺手记下矩形"：绘制可能被跳过（换页、GL 分支），
	//   一旦没画过，矩形就是上一页的残值 ⇒ 点哪儿都可能命中。
	//   （铁律 182：坐标只在创建点出现一次；铁律 127：别抄两份。）
	struct ConfigLayout
	{
		RECT monitorPanel = {};
		RECT runtimePanel = {};
		int rowStart = 0;
		int rowGap = 0;
		int rowLeftMonitor = 0;
		int rowLeftRuntime = 0;
		int rowWidth = 0;
		int rowCountMonitor = 0;   // 9 行
		int rowCountRuntime = 0;   // 8 行

		// 右侧「应用」按钮。没改动时 `valid=false`，**既不画也不命中**。
		bool applyVisible = false;
		RECT applyButton = {};
	};

	int PromptSummaryHeight() noexcept;

	// ★ v103：配置页交互诊断开关（`R3SHIELDCORE_CFG_TRACE=1`）。
	//
	// 为什么需要它：这台机器上**截屏判据不可靠** —— 主窗口是 OpenGL 场景
	// （PrintWindow 抓不到 GL 表面，只会给一张空图），而 CopyFromScreen
	// 又被前台锁 + 置顶 IDE 窗口遮住。所以配一个纯日志通道，
	// 让"这一下点没点到 / 拨完状态对不对"能自证。
	//
	// ★★★ 为什么是**写文件**而不是 `printf`（这一步踩过）：
	//   主程序是 **WINDOWS 子系统**（`wWinMain`）—— **根本没有 stdout**。
	//   `printf` 不报错、不抛异常、什么都不发生，连 `--gui-preview`
	//   重定向到文件也是空的（实测：gui_stdout.log 恒为 0 字节）。
	//   所以诊断必须自己 `CreateFileW` 写。
	//
	// 缓存成 static：每次 WM_LBUTTONDOWN 都调 GetEnvironmentVariableW 太浪费。
	bool ConfigTraceEnabled()
	{
		static int s_on = -1;
		if (s_on < 0) {
			s_on = GetEnvironmentVariableW(L"R3SHIELDCORE_CFG_TRACE", nullptr, 0) > 0 ? 1 : 0;
		}
		return s_on != 0;
	}

	// 追加一行诊断。仅 `ConfigTraceEnabled()` 为真时写。
	//
	// 路径固定 `%TEMP%\r3shieldcore-cfg-trace.log`，追加写（多次运行不覆盖）。
	// ★ 只用 ASCII 窄串 —— 中文在 GBK/UTF-8 之间来回转容易出乱码。
	void ConfigTrace(const char* line)
	{
		if (!ConfigTraceEnabled() || line == nullptr) {
			return;
		}
		wchar_t dir[MAX_PATH] = {};
		const DWORD n = GetTempPathW(_countof(dir), dir);
		if (n == 0 || n >= _countof(dir)) {
			return;
		}
		wchar_t path[MAX_PATH] = {};
		_snwprintf_s(path, _countof(path), _TRUNCATE, L"%sr3shieldcore-cfg-trace.log", dir);

		const HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ,
			nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return;
		}
		DWORD written = 0;
		// 每条前面加时间戳（tick），方便对照"哪一下是哪个动作"。
		char buf[512] = {};
		const int len = _snprintf_s(buf, _countof(buf), _TRUNCATE, "[%lu] %s\r\n",
			static_cast<unsigned long>(GetTickCount()), line);
		if (len > 0) {
			WriteFile(file, buf, static_cast<DWORD>(len), &written, nullptr);
		}
		CloseHandle(file);
	}

	// ★★★ v103：**有没有真差异**（不是"用户碰过没有"）。
	//
	// `g_pendingConfig.dirty` 只表示"寄存区里有值"，拨开再拨回去它照样是 true。
	// 「应用」按钮、以及"要不要发请求"必须看这个函数 —— 否则用户会看到
	// 一颗"没什么可应用"的按钮，按下去白重启一次引擎（实测缺陷，见
	// ComputeConfigLayout 里的说明）。
	bool HasPendingConfigDiff()
	{
		if (!g_pendingConfig.dirty) {
			return false;   // 没碰过 ⇒ 必然没差异（常见路径，省一次循环）
		}
		for (int i = 0; i < static_cast<int>(ConfigField::Count); i++) {
			const ConfigField f = static_cast<ConfigField>(i);
			if (g_pendingConfig.value[i] != CurrentConfigValue(f)) {
				return true;
			}
		}
		return false;
	}

	ConfigLayout ComputeConfigLayout(const RECT& client)
	{
		ConfigLayout out;
		const int left = Padding;
		const int right = client.right - Padding;
		const int top = TabBarTop + TabBarHeight + 18;
		const int panelsTop = top + 122;
		const int gap = 14;
		const int panelWidth = (right - left - gap) / 2;

		out.monitorPanel = { left, panelsTop, left + panelWidth,
			client.bottom - PromptSummaryHeight() - 12 };
		out.runtimePanel = { left + panelWidth + gap, panelsTop, right,
			client.bottom - PromptSummaryHeight() - 12 };

		out.rowStart = panelsTop + 46;
		out.rowGap = 30;
		out.rowLeftMonitor = out.monitorPanel.left + 16;
		out.rowLeftRuntime = out.runtimePanel.left + 16;
		out.rowWidth = panelWidth - 32;
		out.rowCountMonitor = 9;
		out.rowCountRuntime = 8;

		// 应用按钮：贴在左侧「监控面板」的标题行右端（那里本来是空的）。
		//
		// ★ 不放在底部：底部是「询问统计」栏，高度随 `HighRiskProcessAlert`
		//   变化（不是常量），贴底的按钮会被它挤掉或盖住。
		//
		// ★★★ v103 修缺陷：判据不能只看 `dirty`。
		//
		//   第一版写的是 `if (g_pendingConfig.dirty)` —— 实测（截图 03_back）：
		//   拨开再拨回去，开关已经回到原样，**「应用」按钮却还挂着**。
		//   用户会以为"我明明没改什么，为什么让我应用"，而且按下会白重启一次引擎。
		//
		//   `dirty` 的含义是"用户碰过开关"，不是"有差异" —— 这两件事在
		//   "拨了又拨回去"时**不相等**。所以这里改成查**真差异**：
		//   任何一个字段的待提交值和引擎真值不同，才算有改动。
		if (HasPendingConfigDiff()) {
			constexpr int kApplyW = 132;
			constexpr int kApplyH = 26;
			const int btnRight = out.monitorPanel.right - 16;
			const int btnTop = panelsTop + 12;
			out.applyButton = { btnRight - kApplyW, btnTop, btnRight, btnTop + kApplyH };
			out.applyVisible = true;
		}
		return out;
	}

	// 命中：返回被点到的字段。
	//
	// ★ 只认**开关那一小块**（右边 60px），不认整行 —— 整行都可点会让
	//   "想选中文字/想拖窗口"变成误触。60px 覆盖 44px 的开关 + 一点余量。
	bool HitTestConfigToggle(POINT point, const RECT& client, ConfigField* out)
	{
		if (g_activeTab != 3) {
			return false;
		}
		const ConfigLayout layout = ComputeConfigLayout(client);
		constexpr int kHitWidth = 60;

		// 左栏 9 行：顺序必须和 `DrawConfigPage` 的绘制顺序**完全一致**。
		const ConfigField kMonitorRows[] = {
			ConfigField::HighRisk,
			ConfigField::HookReads,
			ConfigField::HookFile,
			ConfigField::HookProcess,
			ConfigField::HookThread,
			ConfigField::HookDriver,
			ConfigField::HookSelfThread,
			ConfigField::HighRiskProcessAlert,
			ConfigField::ArkEnabled,
		};
		for (int i = 0; i < layout.rowCountMonitor; i++) {
			const int rowTop = layout.rowStart + layout.rowGap * i;
			RECT hit = { layout.rowLeftMonitor + layout.rowWidth - kHitWidth, rowTop - 4,
				layout.rowLeftMonitor + layout.rowWidth, rowTop + 26 };
			if (PtInRect(&hit, point)) {
				*out = kMonitorRows[i];
				return true;
			}
		}

		// 右栏只有第 0 行（策略项 / 计数）不是开关类 —— 但 ArkEnabled 在左栏，
		// 所以右栏这一版**没有可拨的项**。留空是刻意的：见下面 DrawConfigPage
		// 里右栏的说明（那几行是"计数"不是"开关"，画成开关就得配得上一个动作）。
		return false;
	}

	bool HitTestConfigApply(POINT point, const RECT& client)
	{
		if (g_activeTab != 3) {
			return false;
		}
		const ConfigLayout layout = ComputeConfigLayout(client);
		if (!layout.applyVisible) {
			return false;
		}
		const RECT r = layout.applyButton;
		return point.x >= r.left && point.x < r.right
			&& point.y >= r.top && point.y < r.bottom;
	}

	// 把寄存区里**真正改过的**项拼成 ini 行。
	//
	// ★★★ 关键设计：只写**与引擎当前值不同**的项。
	//
	//   为什么不整份写回：这些开关有一部分（`hook_reads`/`hook_hive`）在界面上
	//   是合并显示的。如果无脑写回，就会出现"用户只拨了'高危规则'，
	//   顺手把注册表那两项也写了一遍" —— 一旦界面的合并口径和 ini 的真实
	//   语义有一丁点偏差（比如用户手改过 ini 里的 `hook_hive=0`），
	//   就会**静默改掉一个用户没碰过的设置**。只写差异项没有这个风险。
	void BuildConfigApplyRequest()
	{
		g_configApply.lines.clear();
		g_configApply.arkPresent = false;
		g_configApply.valid = false;

		if (!g_pendingConfig.dirty) {
			return;
		}

		auto addLine = [](PCWSTR key, bool value) {
			std::wstring line = key;
			line += value ? L"=1" : L"=0";
			g_configApply.lines.push_back(line);
		};

		// 左栏 8 个可写字段（第 9 项 `ark_enabled` 走单独通道）。
		const ConfigField kFields[] = {
			ConfigField::HighRisk,
			ConfigField::HookReads,
			ConfigField::HookFile,
			ConfigField::HookProcess,
			ConfigField::HookThread,
			ConfigField::HookDriver,
			ConfigField::HookSelfThread,
			ConfigField::HighRiskProcessAlert,
		};
		for (const ConfigField f : kFields) {
			const bool next = g_pendingConfig.value[static_cast<int>(f)];
			if (next == CurrentConfigValue(f)) {
				continue;   // 没动过
			}
			switch (f) {
			case ConfigField::HookReads:
				// 这一行管两个键，**两个都写** —— 只写 `hook_reads` 的话，
				// 用户看到开关灭了、但 `hook_hive` 还亮着，行为没变。
				addLine(L"hook_reads", next);
				addLine(L"hook_hive", next);
				break;
			case ConfigField::HighRiskProcessAlert:
				// 它**不是布尔**：0 = 关 / 1 = 仅记录 / 2 = 记录 + 界面。
				// 界面只有一个开关 ⇒ 开 = 恢复成 2（记录 + 界面），关 = 0。
				// ★ 不能写 1 —— 那等于"悄悄把界面提示降级成只记日志"，
				//   用户会以为"开了但看不到任何提示"。
				addLine(L"high_risk_process_alert", next);
				break;
			default: {
				const PCWSTR key = ConfigIniKey(f);
				if (key) {
					addLine(key, next);
				}
				break;
			}
			}
		}

		// ARK 页开关。
		if (g_pendingConfig.value[static_cast<int>(ConfigField::ArkEnabled)]
			!= CurrentConfigValue(ConfigField::ArkEnabled)) {
			g_configApply.arkPresent = true;
			g_configApply.arkEnabled =
				g_pendingConfig.value[static_cast<int>(ConfigField::ArkEnabled)];
		}

		// 一条都没变（用户拨了又拨回去）⇒ 不弹按钮、不发请求。
		//
		// ★ 这里**顺手把 `dirty` 清掉**：`dirty` 的语义是"寄存区有效"，
		//   而"拨回原值"之后寄存区已经没有意义了 —— 留着它会让
		//   `DisplayConfigValue` 一直走寄存区分支，万一以后 `g_options`
		//   被刷新，界面就显示一个跟谁都不一致的陈旧值。
		g_configApply.valid = !g_configApply.lines.empty() || g_configApply.arkPresent;
		if (!g_configApply.valid) {
			g_pendingConfig.dirty = false;   // 回到"以引擎为准"
		}
	}

	void DrawConfigRow(HDC dc, int x, int y, int width, PCWSTR label, bool enabled,
		bool interactive = false)
	{
		// ★★ v85：配置行改成"左边文字 + 右边开关"。
		//
		//   原来是一个 10x10 的实心方块 + 右边「已启用 / 已关闭」四个字：
		//   方块只是"状态指示灯"，而这一页的用户心智是"开关"（他想拨一下）。
		//   参考项目里所有布尔项都是真开关 —— 拨动感本身就是"可信"的一部分。
		//
		// ★★★ v103：这一页**不再是只读**（原注释写着"开关不接受点击"）。
		//   用户原话：「主程序配置页里的开关用不了，点不动」。
		//   画成开关却不给点，比不放开关更糟 —— 用户只会认为软件坏了。
		//   现在的语义：点一下 = 改**待提交值**（寄存区），右侧多出
		//   「应用并重启引擎」；按那颗才真写 ini + 重启（见上方 v103 说明）。
		//
		//   `interactive=false` 的那几行仍然画成开关，但**画得更淡**：
		//   它们是 `Options` 里没有写通道的只读项，拨了没法生效。
		//   ★ 这是同一条原则的两面：能拨的必须真能拨，不能拨的必须看得出不能拨
		//     （只靠注释说明"这页只读"，用户永远读不到）。
		if (g_glass.active) {
			DrawTextSimple(dc, label, { x, y, x + width - UiCtl::SwitchW - 12, y + 22 },
				g_labelFont, UiCtl::ToColor(interactive ? UiCtl::Ink : UiCtl::Faint),
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			// ★ v93：开关的**值**也走弹簧（参考项目 `Spring v`）。
			//   轨道颜色 mix(灰, 蓝, v) + 圆头 lerp 左→右，一起动才是"拨一下"；
			//   只动圆头会像"色块瞬间换掉、圆头慢慢追"。
			//
			// ★ v103：值改成从 `DisplayConfigValue` 取（寄存区优先），
			//   这样拨动后 `sw.v.tgt` 真的会变，弹簧才有得动 ——
			//   原来 `enabled` 来自 `g_options`（只读快照），拨了也不会变。
			//
			// ★ v103：悬停只在 `interactive` 行给（`hover` 参数进 `SwitchV` 的
			//   高光），不可拨的行给出悬停高光就是在骗人。
			float hover = 0.0f;
			if (interactive) {
				const RECT swHit = { x + width - UiCtl::SwitchW - 10, y - 4,
					x + width, y + 26 };
				if (PtInRect(&swHit, g_mousePoint)) {
					hover = 1.0f;
				}
			}
			R3ShieldCoreUi::Anim::Slot& sw =
				g_anim.Get(AnimKey(x + width, y + 11), enabled ? 1.0f : 0.0f);
			sw.v.tgt = enabled ? 1.0f : 0.0f;
			const float v = interactive ? sw.v.v : (enabled ? 1.0f : 0.0f);
			UiCtl::SwitchV(g_ui, x + width, y + 11, v, hover);
			return;
		}

		RECT dot = { x, y + 5, x + 10, y + 15 };
		HBRUSH brush = CreateSolidBrush(enabled ? RGB(34, 160, 96) : ColorBorder);
		SceneFillRect(dc, &dot, brush);
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

		// ★ v103 诊断：把算出来的布局打一次，好和探针用的坐标对账。
		//   只在前 8 次绘制时写，免得日志被重绘刷满。
		if (ConfigTraceEnabled()) {
			static int s_drawTrace = 0;
			if (s_drawTrace < 8) {
				++s_drawTrace;
				const ConfigLayout lay = ComputeConfigLayout(client);
				char trace[384] = {};
				_snprintf_s(trace, _countof(trace), _TRUNCATE,
					"draw client=%ldx%ld panelsTop=%ld rowStart=%d gap=%d "
					"hitX=%ld..%ld row0Y=%d..%d applyVisible=%d",
					client.right, client.bottom,
					static_cast<long>(lay.monitorPanel.top),
					lay.rowStart, lay.rowGap,
					static_cast<long>(lay.rowLeftMonitor + lay.rowWidth - 60),
					static_cast<long>(lay.rowLeftMonitor + lay.rowWidth),
					lay.rowStart - 4, lay.rowStart + 26,
					lay.applyVisible ? 1 : 0);
				ConfigTrace(trace);
			}
		}

		RECT modePanel = { left, top, right, top + 104 };
		DrawPanel(dc, modePanel, L"当前防护模式");
		RECT modeName = { left + 16, top + 42, left + 160, top + 76 };
		DrawTextSimple(dc, ModeShortName(mode), modeName, g_valueFont,
			mode == R3ShieldCore::Mode::Block ? ColorBlocked : ColorAccent,
			DT_LEFT | DT_SINGLELINE);
		// ★ v88：说明文字跟着模式名**动态定位**（原来写死 left+178）。
		//   写死的问题："全拦·安全"这种长名字会压到说明上，而 "LOG" 又
		//   把说明甩到 160px 之外 —— 同一张卡上两种间距，读起来是断开的。
		//   用场景的 Measure 量一下真宽（字形推进量就是排版用的那个数）。
		const int descLeft = left + 16
			+ static_cast<int>(g_scene.Measure(ModeShortName(mode),
				R3ShieldCoreUi::SF_Value) + 0.5f) + 18;
		DrawTextSimple(dc, ModeDescription(mode), { descLeft, top + 46, right - 20, top + 72 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		// ★★★ v103：几何全部走 `ComputeConfigLayout` —— 绘制和命中**同一份**。
		//   原来这里是就地算的，点击处理那边只能再抄一遍（必然漂移，铁律 182）。
		const ConfigLayout configLayout = ComputeConfigLayout(client);
		const RECT monitorPanel = configLayout.monitorPanel;
		const RECT runtimePanel = configLayout.runtimePanel;
		DrawPanel(dc, monitorPanel, L"监控面板");
		DrawPanel(dc, runtimePanel, L"运行参数");

		const int rowStart = configLayout.rowStart;
		// ★ v88：27 → 30。9 行挤在 27px 的节距里，行与行之间只剩 13px 空白，
		//   开关（26px 高）几乎首尾相接；30 才读得出"一行一项"。
		const int rowGap = configLayout.rowGap;
		// ★ v103：每行统一用 "显示值"（寄存区优先）+ interactive=true。
		const int rowX = configLayout.rowLeftMonitor;
		const int rowW = configLayout.rowWidth;
		DrawConfigRow(dc, rowX, rowStart, rowW, L"高危规则",
			DisplayConfigValue(ConfigField::HighRisk), true);
		DrawConfigRow(dc, rowX, rowStart + rowGap, rowW, L"注册表只读 / Hive",
			DisplayConfigValue(ConfigField::HookReads), true);
		DrawConfigRow(dc, rowX, rowStart + rowGap * 2, rowW, L"文件行为",
			DisplayConfigValue(ConfigField::HookFile), true);
		DrawConfigRow(dc, rowX, rowStart + rowGap * 3, rowW, L"进程创建",
			DisplayConfigValue(ConfigField::HookProcess), true);
		DrawConfigRow(dc, rowX, rowStart + rowGap * 4, rowW, L"远程线程",
			DisplayConfigValue(ConfigField::HookThread), true);
		DrawConfigRow(dc, rowX, rowStart + rowGap * 5, rowW, L"驱动 / 服务",
			DisplayConfigValue(ConfigField::HookDriver), true);
		DrawConfigRow(dc, rowX, rowStart + rowGap * 6, rowW, L"本进程线程噪音",
			DisplayConfigValue(ConfigField::HookSelfThread), true);
		// ★ v61：高危进程提示。注意它**不是** hook —— 是引擎自己定期快照
		//   全机进程，所以即使"进程创建"那一行是关的，它照样工作。
		DrawConfigRow(dc, rowX, rowStart + rowGap * 7, rowW, L"高危进程提示",
			DisplayConfigValue(ConfigField::HighRiskProcessAlert), true);
		// ★ v62：ARK 页。同样是"引擎自己枚举"，与 hook 无关。
		//   它只影响 ARK 页的列表刷新与动作可用性，不改变任何拦截行为。
		{
			WCHAR arkBuffer[128] = {};
			// ★ v63：两个间隔都显示出来 —— 它们含义不同（引擎枚举 vs 界面重绘），
			//   只显示一个会让用户以为"改了 ark_refresh_ms 没生效"。
			swprintf_s(arkBuffer, L"ARK 全机进程视图（扫描 %u / 刷新 %u ms）",
				g_options.ArkScanMs ? g_options.ArkScanMs : 2000,
				ArkRefreshIntervalMs());
			DrawConfigRow(dc, rowX, rowStart + rowGap * 8, rowW,
				arkBuffer, DisplayConfigValue(ConfigField::ArkEnabled), true);
		}

		// ★ v103：「应用并重启引擎」——只在有未提交改动时出现。
		//
		//   为什么必须显式这么写：这些开关改的是**注入 DLL 的 hook 面**，
		//   引擎只在 LoadLibrary 那一刻读 Policy 块 ⇒ 不重新注入就等于没改。
		//   按钮文案里直接写"重启引擎"，是为了让用户**预先知道**代价，
		//   而不是点完之后才惊讶"怎么全断了"。
		if (configLayout.applyVisible) {
			const RECT r = configLayout.applyButton;
			const bool hot = HitTestConfigApply(g_mousePoint, client);
			if (g_glass.active) {
				// 参考项目的主按钮就是 `Pill(Primary)` —— 蓝底白字，
				// 和这一页里唯一的"要用户下决心"的动作相称。
				UiCtl::Pill(g_ui, r, UiCtl::Btn::Primary, hot ? 1.0f : 0.0f, 0.0f);
				DrawTextSimple(dc, L"应用并重启引擎", r, g_labelFont,
					UiCtl::PillText(UiCtl::Btn::Primary),
					DT_CENTER | DT_SINGLELINE | DT_VCENTER);
			}
			else {
				HBRUSH b = CreateSolidBrush(hot ? ColorAccent : ColorHeaderBackground);
				SceneFillRect(dc, &r, b);
				DeleteObject(b);
				DrawTextSimple(dc, L"应用并重启引擎", r, g_labelFont,
					hot ? RGB(255, 255, 255) : ColorTextPrimary,
					DT_CENTER | DT_SINGLELINE | DT_VCENTER);
			}
		}

		// ★★★ v103：右栏这 5 行**没有写通道**，必须留 `interactive=false`。
		//
		//   「排除路径 / 绝不注入」是 `exclude_path=` / `never_inject=` 的**多行列表**，
		//   不是布尔项 —— 拨一下没有任何合理语义（关掉就等于"清空整个白名单"，
		//   那是灾难性的，绝不能做成一次误点）。
		//   「询问超时」是数值，「日志输出」是路径。
		//
		//   ⇒ 这几行画成开关只为**和左栏对齐、能一眼看出状态**，
		//     但它们**不能长得像能拨** —— 所以 `DrawConfigRow` 会给
		//     不可交互的行画一个略淡的轨道（见该函数末尾）。
		//     ★ 这条是用户这次抱怨的镜像：能拨的必须能拨，不能拨的必须看得出不能拨。
		WCHAR buffer[256] = {};
		swprintf_s(buffer, L"排除路径：%u 条", g_options.ExcludePathCount);
		DrawConfigRow(dc, configLayout.rowLeftRuntime, rowStart, rowW, buffer, true, false);
		// ★ v51：把「绝不注入」条数也显示出来 —— 理由同启动横幅（app.cpp）：
		//   这是**最容易配错又最难自查**的一项，ini 里少个结尾 `\`、或误写成
		//   文件名而不是完整路径，都会**静默不生效**；而"不生效"的表现是
		//   "某个程序偶尔卡一下"，几乎没人会联想到 ini。
		//   控制台横幅有、GUI 没有 ⇒ 从界面看，用户永远不知道自己有几个程序在裸奔。
		swprintf_s(buffer, L"绝不注入：%u 条", g_options.NeverInjectPathCount);
		DrawConfigRow(dc, configLayout.rowLeftRuntime, rowStart + rowGap, rowW, buffer, true, false);
		swprintf_s(buffer, L"询问超时：%u 秒", g_options.PromptTimeoutMs / 1000);
		DrawConfigRow(dc, configLayout.rowLeftRuntime, rowStart + rowGap * 2, rowW, buffer,
			mode == R3ShieldCore::Mode::Ask, false);
		DrawConfigRow(dc, configLayout.rowLeftRuntime, rowStart + rowGap * 3, rowW, L"日志输出",
			g_options.LogPath != nullptr && g_options.LogPath[0] != L'\0', false);
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
		//
		// ★★ v101：改成**节流**（前 5 次 + 每 200 次一条）。
		//   2026-10-24 现场：这一行刷了 982 条，把整个日志（1361 行）淹掉了 ——
		//   真正有用的 `[btn]` / `[ipc]` / `[procwatch]` 全被埋在里面，
		//   排查时得先把它滤掉才看得见东西。探针判据不受影响：
		//   它要的那一句在前 5 条里就有，而且**留在日志里**不会消失。
		{
			static ULONG s_drawCount = 0;
			s_drawCount++;
			if (s_drawCount <= 5 || (s_drawCount % 200) == 0) {
				printf("[adv] 跳转页已绘制 按钮=%ld,%ld,%ld,%ld 失败=%d 客户区=%ldx%ld"
					" 第%lu次\n",
					button.left, button.top, button.right, button.bottom,
					g_advLaunchError.empty() ? 0 : 1,
					client.right, client.bottom,
					static_cast<unsigned long>(s_drawCount));
			}
		}

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
		//
		// ★★ v85：页签栏改成**分段控件**（一条凹槽 + 一块白滑块），
		//   和参考项目的 dock 是同一个模型。
		//
		//   为什么不能继续"每个页签各自一块玻璃"：没有选中项时（理论上不会，
		//   但悬停时会多出一块）屏幕上就是几块散落的胶囊，读不出"这是一组"。
		//   一个凹槽把它们圈起来，语义立刻就对了 —— 这也是 iOS 分段控件的做法。
		if (g_glass.active) {
			const RECT first = TabRect(0);
			const RECT last = TabRect(TabCount - 1);
			// 左右各外扩 6px（**对称**）。为什么不跟顶栏一样对齐到 8：
			// 右边被动作按钮簇卡住了（页签右缘 480、按钮左缘 492），
			// 只能各留 6 —— 一个凹槽左右不对称比"不跟顶栏对齐"更扎眼。
			RECT trough = { first.left - 6, first.top - 2, last.right + 6, last.bottom + 2 };
			UiCtl::SegmentTrough(g_ui, trough);

			// 滑块放在**文字之前**登记：玻璃层按登记顺序合成，后登记的压在上面。
			if (g_activeTab >= 0 && g_activeTab < TabCount) {
				const RECT t = TabRect(g_activeTab);
				// ★ v93：滑块**滑过去**而不是跳过去（参考项目的 dock 也是弹簧）。
				//   x0/x1 各一个弹簧：各页签宽度不同（"概览"2 字 vs "事件日志"4 字），
				//   用一个"索引弹簧"再插值，会在经过窄页签时宽度跳一下。
				const float tx0 = static_cast<float>(t.left + 1);
				const float tx1 = static_cast<float>(t.right - 1);
				if (!g_tabThumbInit) {
					g_tabThumbX0.Init(tx0);
					g_tabThumbX1.Init(tx1);
					g_tabThumbInit = true;
				}
				g_tabThumbX0.tgt = tx0;
				g_tabThumbX1.tgt = tx1;
				// ★ v94：挤压 —— 换页瞬间滑块比正常宽 12px，再弹回去。
				//   左右各扩一半，中心不动（参考项目 dock 也是原地变宽）。
				const float sq = g_tabSqueeze.v * 0.5f;
				RECT thumb = {
					static_cast<LONG>(g_tabThumbX0.v - sq + 0.5f), t.top + 1,
					static_cast<LONG>(g_tabThumbX1.v + sq + 0.5f), t.bottom - 1
				};
				UiCtl::SegmentThumb(g_ui, thumb);
			}
		}

		for (int i = 0; i < TabCount; i++) {
			RECT rect = TabRect(i);
			const bool active = (i == g_activeTab);
			const bool hover = (i == g_hoverTab);

			if (g_glass.active) {
				// 文字色：选中 = 墨色；悬停 = 次色；其余 = 弱色。
				// ★ v93：悬停是**淡入**的（Faint → Dim 插值），不是一到就跳。
				R3ShieldCoreUi::Anim::Slot& ts =
					g_anim.Get(AnimKey(rect.left, rect.top), 0.0f);
				ts.hoverTgt = hover ? 1.0f : 0.0f;
				const COLORREF textColor = active
					? UiCtl::ToColor(UiCtl::Ink)
					: UiCtl::ToColor(UiCtl::Mix(UiCtl::Faint, UiCtl::Dim, ts.hover));
				DrawTextSimple(dc, TabTitle(i), rect, g_tabFont, textColor,
					DT_CENTER | DT_VCENTER | DT_SINGLELINE);
				continue;
			}

			if (active) {
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

			const COLORREF textColor = active ? ColorTabActiveText
				: (hover ? ColorAccent : ColorTabInactiveText);
			DrawTextSimple(dc, TabTitle(i), rect, g_tabFont, textColor,
				DT_CENTER | DT_VCENTER | DT_SINGLELINE);
		}

		// 右端的操作按钮（页签在左、操作在右，互不重叠）
		DrawHeaderActions(dc);
		DrawModeButton(dc);

		// 页签栏下缘分隔线（玻璃模式下不画：凹槽本身就是边界，
		// 再加一条 1px 实线会把顶栏切成"两个平面"）
		if (!g_glass.active) {
			RECT line = { 0, TabBarTop + TabBarHeight, width, TabBarTop + TabBarHeight + 1 };
			HBRUSH lineBrush = CreateSolidBrush(ColorBorder);
			SceneFillRect(dc, &line, lineBrush);
			DeleteObject(lineBrush);
		}
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

		// ★ v87：+1 -> +16。原来日志页的卡片紧贴页签条下沿（差 1px），
		//   表头那一行看着像被页签压住；其它页都是 +16~+18，这里跟它们对齐。
		const int top = TabBarTop + TabBarHeight + 16;
		const int bottom = client.bottom - PromptSummaryHeight() - 8;
		// ★ v88：卡片顶部内边距。
		//   原来表头凹槽的顶边只比卡片顶边低 3px，而卡片圆角是 24 ——
		//   凹槽两端那两个半圆直接从卡片的圆角里**顶出去**，看起来像
		//   "一条贴纸压在卡片上"，也是这一页最像"没做完"的地方。
		//   参考项目的卡片内边距在 20 上下；这里取 12，够让凹槽躲开圆角
		//   （圆角 24、内缩 8px 处卡片上边界在 top+10.7，凹槽顶在 top+12）。
		const int sheetPad = 12;

		// ---- 表头 ----
		const int contentLeft = Padding;
		const int contentRight = client.right - Padding;

		const int colTime = contentLeft;
		const int colSource = colTime + LogColTimeWidth;
		const int colProcess = colSource + LogColSourceWidth;
		const int colOp = colProcess + LogColProcessWidth;
		const int colTarget = colOp + LogColOpWidth;
		const int colStatus = contentRight - LogColStatusWidth;

		// v85：表头文字在凹槽上，用次色（Dim）而不是 ColorTextSecondary ——
		// 凹槽比卡片暗一档，原来的灰在它上面偏淡。
		const COLORREF logHeaderColor = g_glass.active ? UiCtl::ToColor(UiCtl::Dim)
			: ColorTextSecondary;
		RECT headerRect = { contentLeft, top + sheetPad, contentRight,
			top + sheetPad + LogHeaderHeight };
		// ★ v85：日志页整块垫一张玻璃卡（表头 + 行区 + 底部信息都在上面）。
		//   原来表头是一条**不透明**的 `ColorHeaderBackground` 实色带 ——
		//   在玻璃界面上就是一条白胶带，把上面的玻璃和下面的背景割断。
		if (g_glass.active) {
			RECT sheet = { contentLeft - 12, top, contentRight + 12, bottom + 6 };
			UiCtl::Card(g_ui, sheet, 0.44f);
			// 表头单独一条**凹槽**：它属于"列名"这一层，不像正文那样可以
			// 直接浮在卡上 —— 没有这条，六列标题就是六个孤零零的词。
			// ★ 后登记 ⇒ 压在卡上面（玻璃层按登记顺序合成）。
			// 左右各内缩到 contentLeft-8 / contentRight+8（卡片边在 ±12）——
			// 留 4px 让凹槽整条落在卡片内，不再切角。
			RECT head = { contentLeft - 8, top + sheetPad, contentRight + 8,
				top + sheetPad + LogHeaderHeight };
			UiCtl::PieceR(g_ui, head, (head.bottom - head.top) * 0.5f, 0.55f,
				UiCtl::Sunken, UiCtl::KWell);
		} else {
			HBRUSH headerBrush = CreateSolidBrush(ColorHeaderBackground);
			SceneFillRect(dc, &headerRect, headerBrush);
			DeleteObject(headerBrush);
		}

		RECT timeHeader = { colTime, top + sheetPad + 4, colSource,
			top + sheetPad + LogHeaderHeight };
		DrawTextSimple(dc, L"时间", timeHeader, g_labelFont, logHeaderColor, DT_LEFT | DT_SINGLELINE);

		RECT sourceHeader = { colSource, top + sheetPad + 4, colProcess,
			top + sheetPad + LogHeaderHeight };
		DrawTextSimple(dc, L"来源", sourceHeader, g_labelFont, logHeaderColor, DT_LEFT | DT_SINGLELINE);

		RECT procHeader = { colProcess, top + sheetPad + 4, colOp,
			top + sheetPad + LogHeaderHeight };
		DrawTextSimple(dc, L"进程", procHeader, g_labelFont, logHeaderColor,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		RECT opHeader = { colOp, top + sheetPad + 4, colTarget - 4,
			top + sheetPad + LogHeaderHeight };
		DrawTextSimple(dc, L"操作", opHeader, g_labelFont, logHeaderColor,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		RECT targetHeader = { colTarget, top + sheetPad + 4, colStatus - 6,
			top + sheetPad + LogHeaderHeight };
		DrawTextSimple(dc, L"目标（键 / 文件 / 进程）", targetHeader, g_labelFont, logHeaderColor,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		RECT statusHeader = { colStatus, top + sheetPad + 4, contentRight,
			top + sheetPad + LogHeaderHeight };
		DrawTextSimple(dc, L"状态", statusHeader, g_labelFont, logHeaderColor,
			DT_RIGHT | DT_SINGLELINE);

		RECT headerLine = { 0, top + sheetPad + LogHeaderHeight,
			client.right, top + sheetPad + LogHeaderHeight + 1 };
		if (!g_glass.active) {
			HBRUSH lineBrush = CreateSolidBrush(ColorBorder);
			SceneFillRect(dc, &headerLine, lineBrush);
			DeleteObject(lineBrush);
		}

		// ---- 行区 ----
		const int rowsTop = top + sheetPad + LogHeaderHeight + 1;
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

				// 交替底色，方便横向对行。
				// ★ v85：玻璃模式下**只**给历史行铺一层半透明暖色 ——
				//   ① 斑马纹取消（实色条会把玻璃卡切成色带）；
				//   ② 历史行必须留标记：它是"上一轮会话的事件"，和本次会话
				//      混在一起会误导（v54 起就要求一眼可分）。原来是靠"更暗的
				//      底色 + 史字标记"，但史字标记从来没实现过 ⇒ 底色一取消
				//      就彻底分不出来了，所以这里改成半透明暖色。
				if (g_glass.active) {
					if (isHistoryRow) {
						// ★ v88：原来这里铺的是 {0 .. client.right} —— **整个客户区宽**。
						//   经典模式日志页本来就是通栏的，看不出来；但玻璃模式下的
						//   卡片是左右各内缩 12 的，色带会一直淌到卡片外面，
						//   在卡片圆角两侧露出两条暖色横杠。
						RECT alt = { contentLeft - 12, rowTop,
							contentRight + 12, rowTop + LogRowHeight };
						BlendFillRect(dc, alt, RGB(214, 196, 150), 46);
					}
				} else if (isHistoryRow || (i - start) % 2 == 1) {
					RECT alt = { 0, rowTop, client.right, rowTop + LogRowHeight };
					HBRUSH altBrush = CreateSolidBrush(
						isHistoryRow ? ColorLogRowHistory : ColorLogRowAlt);
					SceneFillRect(dc, &alt, altBrush);
					DeleteObject(altBrush);
				}

				// 左侧 3px 色条标决策，比整行染色克制得多
				COLORREF decisionColor = DecisionColor(static_cast<R3ShieldCore::Decision>(row.Decision));
				RECT stripe = { 0, rowTop + 2, 3, rowTop + LogRowHeight - 2 };
				HBRUSH stripeBrush = CreateSolidBrush(decisionColor);
				SceneFillRect(dc, &stripe, stripeBrush);
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
		SceneFillRect(dc, &separator, sepBrush);
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
		// ★★★ v86：**整窗换成 OpenGL 场景渲染**（照参考项目
		//   `LiquidGlassControls` 的渲染顺序重写，布局与逻辑一个字没改）。
		//
		//   参考项目的顺序是：
		//     抓屏 → 模糊 → 背景 → 玻璃层（有序）→ 实心层 → 图标层 → 文字层 → 上屏
		//   也就是说"这一帧画什么"必须**全部先攒起来**，最后一次性提交。
		//   所以这里的顺序固定成五步，任何一步换位置都会出可见的错：
		//     ① `g_scene.Begin()` + `g_glass.BeginFrame()`  清空本帧顶点/面板表
		//     ② `g_glass.Prepare()`  判断有没有玻璃（`active`）—— **必须**在画之前，
		//        因为各页要靠它决定"登记玻璃 / 画深色字 / 画实色底"
		//     ③ 画顶栏 / 页签 / 各页 —— 全部写进场景，一个 HDC 都不碰
		//     ④ `g_glass.Compose()`  背景 + 玻璃 [+ 内容] 一次合成
		//     ⑤ 上屏
		//   ★ v85 及之前是"先把玻璃层 BitBlt 上来、再拿 GDI 往上画内容"，
		//     那样玻璃再准也还是"GDI 界面上贴了几张玻璃卡"。现在内容也在 GL 里。
		// -----------------------------------------------------------------
		const float dpi = GlassDpiScale(hwnd);

		// ---- v95：背景"自己在变"的自适应跟随 ----
		// 详见 g_bgWatchUntil 的注释。这里做两件事：
		//   ① 上一帧合成时抓到的背景和"上次见到的"不同 ⇒ 开观察窗 + 叫醒快时钟；
		//   ② 观察窗内，每 40ms 主动要求抓一次（25fps），不要等 300ms 常态重画。
		const ULONGLONG nowMs = GetTickCount64();
		if (g_glass.backdrop.refreshStamp != g_bgLastStamp) {
			g_bgLastStamp = g_glass.backdrop.refreshStamp;
			g_bgWatchUntil = nowMs + 900;
			EnsureAnimTimer();
		}
		bool wantBackdrop = g_glassWantBackdrop ||
			(nowMs - g_glassMovedAt) < 1200;   // 拖动/缩放期间持续刷新
		// 跟随间隔：**自己窗口**在拖动/缩放 ⇒ 40ms（这一段最扎眼，必须跟手）；
		// 其它情况（背后有窗口在动 / 动态壁纸）⇒ 100ms。
		//
		// ★ 为什么不一味给 40ms：实测这台机器上**一次完整重绘 ≈ 20ms**
		//   （GL 合成 + 内容层 + 背景上传与模糊）。25fps 就是 50% 单核，
		//   60fps 物理上做不到 —— 再快只会把 CPU 吃满、帧率一点不涨。
		//   100ms（10fps）在"糊过的背景"上看不出台阶，CPU 约 20%。
		const ULONGLONG followMs = (nowMs - g_glassMovedAt) < 1200 ? 40ull : g_bgFollowMs;
		if (!wantBackdrop && nowMs < g_bgWatchUntil && (nowMs - g_bgForceAt) >= followMs) {
			wantBackdrop = true;
		}
		if (wantBackdrop) {
			g_bgForceAt = nowMs;
		}
		// ★ v85：玻璃模式下顶栏自己就是一块**浮起来的玻璃条**（见下面
		//   RegisterHeaderBar），所以**不要**再铺那条全宽的白色薄纱 ——
		//   两者叠在一起会让窗口最上面 100px 变成一片奶白，背景的景深全丢。
		//   经典模式仍然保留薄纱（它不铺玻璃，靠它提亮）。
		g_glass.headerBand = (g_uiStyle == Style::Glass) ? 0 : (TabBarTop + TabBarHeight);
		g_glass.headerVeil = 0.20f;

		// ★ 风格门：经典模式下**不进**玻璃层（`active` 保持 false ⇒ 走老绘制路径）。
		const bool glassWanted = (g_uiStyle == Style::Glass);
		if (!glassWanted) {
			g_glass.active = false;
			g_glass.glCompose = nullptr;
		} else if (g_gl.Ready()) {
			// GPU 就绪就走 GL；否则 glCompose 为空 ⇒ CPU 合成（ui_material.h）。
			g_glass.glCompose = GlComposeBridge;
			g_glass.glCtx = &g_gl;
		} else {
			g_glass.glCompose = nullptr;
		}

		// ①② 场景开帧 + 玻璃层准备（不合成）
		g_scene.Begin(client.right, client.bottom, dpi);
		g_glass.BeginFrame();
		const bool glassActive =
			glassWanted && g_glass.Prepare(hwnd, client.right, client.bottom, dpi, wantBackdrop);
		if (glassActive) {
			g_glassWantBackdrop = false;
			if (!g_glassLogged) {
				g_glassLogged = true;
				printf("[glass] 液态玻璃已就绪 背景=%ls 后端=%ls 尺寸=%dx%d dpi=%.2f 标记=%ls 控件=%ls 场景=%ls\n",
					R3ShieldCoreUi::BackdropSourceName(g_glass.backdrop.source),
					g_glass.glCompose ? L"OpenGL" : L"CPU",
					client.right, client.bottom, static_cast<double>(dpi),
					R3ShieldCoreUi::kGenerationMarker,
					// ★ v85：控件库的代次标记必须**被引用一次**，否则
					//   inline constexpr 的宽串会被链接器当死代码丢掉，
					//   发布闸门就查不到它（v83 踩过：cfg 少一行 ⇒ 闸门 FAIL）。
					UiCtl::kMarker,
					// ★ v86：场景渲染器的代次标记，同理必须被引用。
					R3ShieldCoreUi::kSceneMarker);
			}
		} else if (glassWanted) {
			static int s_glassFailLogged = 0;
			if (s_glassFailLogged < 3) {
				++s_glassFailLogged;
				printf("[glass] 诊断：Prepare 失败 active=%d enabled=%d client=%dx%d stage=%d\n",
					g_glass.active ? 1 : 0, R3ShieldCoreUi::GlassEnabled() ? 1 : 0,
					client.right, client.bottom, g_glass.failStage);
			}
		}

		// -----------------------------------------------------------------
		// 双缓冲载体：**始终**是兼容位图。
		//
		// ★★ 为什么不直接把内容画进玻璃层的 32bpp DIB（v83 踩过）：
		//   GDI 的 ClearType 在 `CreateDIBSection` 出来的 32bpp 表面上**渲染不出
		//   深色字** —— 实测整屏文字变成白色，而且不报任何错。
		//   v86 之后 GL 那条路上文字根本不经 GDI（走字形图集），但**经典模式
		//   和 CPU 回落**仍然要用 GDI 重放场景（`g_scene.PaintGdi`），
		//   所以这张兼容位图必须留着。
		// -----------------------------------------------------------------
		HDC buffer = CreateCompatibleDC(dc);
		HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
		HGDIOBJ oldBitmap = SelectObject(buffer, bitmap);

		// ★ v85：控件库的"本帧画布"。必须在这里同步 —— 下面所有 UiCtl::*
		//   都往 g_ui 上登记面板，dpi 也必须和这一帧的窗口一致。
		SyncUiSurface(buffer);

		if (!glassActive) {
			// ---- 兜底：原来的不透明渐变（经典模式 / 玻璃不可用）----
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

		// ★ v85：顶栏 = 一块**两端留边、四角全圆**的玻璃条（参考项目的做法）。
		//   为什么要留边而不是通栏：通栏玻璃条的左右两端被窗口边切掉，
		//   圆角就没了，"浮起来"的感觉也就没了 —— 而这是液态玻璃的全部。
		if (g_glass.active) {
			// ★ v85：左边距统一 8 —— 顶栏、页签凹槽、内容卡、底部状态条
			//   全部对齐到同一条竖线。差 2px 在自绘界面上**看得见**
			//   （相邻两块玻璃的边缘不齐，比"都靠边"更显脏）。
			const int pad = 8;
			const int top = 8;
			const int bottom = 58;
			UiCtl::Piece(g_ui, pad, top, client.right - pad, bottom,
				20.0f * dpi, 0.62f, UiCtl::CardTone, UiCtl::KPiece);
		}

		// 标题文字区右边界要给右侧的「默认置顶 / 超级置顶 / 模式徽章」让位，
		// 否则拉宽/收窄时文字会钻到按钮底下。
		const int headerTextRight = TopMostButtonRect().left - 16;
		// ★ v87：标题/副标题各上移 2px，副标题不再贴着玻璃条下沿。
		RECT headerText = { Padding, 12, headerTextRight, 36 };
		DrawTextSimple(buffer, GuiTitle, headerText, g_titleFont,
			g_glass.active ? UiCtl::ToColor(UiCtl::Ink) : ColorTextPrimary,
			DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
		RECT subtitle = { Padding, 36, headerTextRight, 55 };
		// ★ v91：有提示时**占用副标题这一行**显示（同一矩形，不会和标题打架）。
		//   为什么复用这一行而不是新开一块：副标题是装饰性文案，让位成本最低；
		//   新开一块要么压页签、要么压底部统计条，都会引入新的重叠问题。
		//
		// ★★★ v100：**必须先拷贝再画**。`g_notice` 由 `app.cpp` 主循环线程写，
		//   这里是窗口线程读 —— 原来直接 `g_notice.c_str()` 交给 `DrawText`，
		//   主循环只要在这期间重新赋值（释放堆块），就是 use-after-free +
		//   并发进出 CRT 堆 ⇒ 堆死锁，主循环永久卡死（2026-10-23 事故）。
		//   锁只包住"判断 + 拷贝"，`DrawText` 在锁外做。
		bool noticeActive = false;
		std::wstring noticeText;
		{
			std::lock_guard<std::mutex> lock(g_noticeMutex);
			noticeActive = !g_notice.empty() && GetTickCount64() < g_noticeUntil;
			if (noticeActive) {
				noticeText = g_notice;
			}
		}
		if (noticeActive) {
			DrawTextSimple(buffer, noticeText.c_str(), subtitle, g_labelFont,
				g_glass.active ? RGB(190, 60, 50) : ColorBlocked,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
		else {
			DrawTextSimple(buffer, L"实时行为监控  ·  注入状态  ·  高危决策  ·  事件取证",
				subtitle, g_labelFont,
				g_glass.active ? UiCtl::ToColor(UiCtl::Faint) : ColorTextSecondary,
				DT_LEFT | DT_SINGLELINE);
		}

		DrawTopMostButtons(buffer);
		DrawModeBadge(buffer, ModeBadgeTop);
		DrawCaptionButtons(buffer);

		// 分隔线：玻璃模式下不画（玻璃条的投影本身就是分隔）
		if (!g_glass.active) {
			RECT headerLine = { 0, 61, client.right, 62 };
			HBRUSH lineBrush = CreateSolidBrush(ColorBorder);
			SceneFillRect(buffer, &headerLine, lineBrush);
			DeleteObject(lineBrush);
		}

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

			// 布局：底部询问统计栏固定贴底占 PromptSummaryHeight()。
			const int contentBottom = client.bottom - PromptSummaryHeight() - 8;

			// ★★★ v87：概览页改成 **3 + 2 + 1 的卡片网格**（参考项目
			//   `LiquidGlassControls` 的节奏）。
			//
			//   原来这里是"两张通栏大卡铺满整窗"：玻璃占了 90% 的面积，卡与卡之间
			//   只有 10px 的缝，缝里什么都看不见 —— 于是"玻璃"和"背景"是同一片灰，
			//   材质写得再准也读不出层次（用户的原话是"好黑啊/边缘很黑"，
			//   但真正的问题是这个：**没有背景可透**）。
			//
			//   参考项目一屏 6 张卡、缝 14~18px，缝里能看见模糊过的桌面。
			//   玻璃的价值全在那条缝里。所以这里第一件事是**留缝**。
			constexpr int gap = 14;
			const int left0 = Padding - 12;
			const int right0 = ClientWidth() - Padding + 12;
			const int avail = right0 - left0;
			const int colW = (avail - gap * 2) / 3;

			int y = TabBarTop + TabBarHeight + 16;

			// ---- 第一行：三个指标，各自一张卡 ----
			RECT metricCards[3] = {};
			for (int i = 0; i < 3; i++) {
				const int x = left0 + i * (colW + gap);
				metricCards[i] = { x, y, x + colW, y + 88 };
				if (g_glass.active) {
					UiCtl::Card(g_ui, metricCards[i], 0.44f);
				}
			}

			// ---- 第二行：决策分布（1/3）+ 操作分布（2/3）；第三行：进程 ----
			const int row2Top = y + 88 + gap;
			const int remain = contentBottom - row2Top - gap;
			int row2H = (remain * 52) / 100;
			int row3H = remain - row2H;
			// 窗口可以被拉小（WS_THICKFRAME）。给两行各留一个下限，
			// 拉得再小也不会出现"标题被卡片裁掉"这种半张脸。
			if (row2H < 156) {
				row2H = 156;
			}
			if (row3H < 120) {
				row3H = 120;
			}

			// ★ v87：第二行不是 1/3 + 2/3，而是 **40% + 60%**。
			//   决策分布只有 4 行、标签最长 11 个字符，1/3（333px）扣掉标签列后
			//   柱子只剩 90px，"比例"根本看不出来；操作分布的名字长
			//   （SetInformationKey 这类 17 个字符），反而需要更宽。
			const int row2LeftW = (avail - gap) * 40 / 100;
			RECT cardDecision = { left0, row2Top, left0 + row2LeftW, row2Top + row2H };
			RECT cardOps = { left0 + row2LeftW + gap, row2Top, right0, row2Top + row2H };
			RECT cardProc = { left0, row2Top + row2H + gap, right0, row2Top + row2H + gap + row3H };

			// ★★★ 登记顺序 = 合成顺序（后登记的压在上面）。
			//   卡片必须在柱状条之前登记 —— 反过来会把整页的条形全部盖住，
			//   症状是"柱状图不见了"，而卡片本身看着完全正常（v85 踩过）。
			if (g_glass.active) {
				UiCtl::Card(g_ui, cardDecision, 0.44f);
				UiCtl::Card(g_ui, cardOps, 0.44f);
				UiCtl::Card(g_ui, cardProc, 0.44f);
			}

			// 行数按卡片高度算（每行 26px，去掉内边距和标题）。
			// ★ v88：行距 26 → 32（与两张分布卡内部的 `y += 32` 一致）。
			//   原来算行数用 26、画的时候也是 26，是对的；改行距时**必须同步**，
			//   否则会多算一行，最后一行压在卡片底边上。
			const int opsRows = (row2H - CardPad * 2 - 28) / 32;
			const int procRows = (row3H - CardPad * 2 - 28) / 32;

			DrawOverview(buffer, metricCards, snapshot, injectedTotal);
			DrawDecisionBreakdown(buffer, cardDecision, snapshot);
			DrawOpBreakdown(buffer, cardOps, snapshot, opsRows);
			DrawTopProcesses(buffer, cardProc, snapshot, procRows);
			DrawPromptSummary(buffer, client.bottom, snapshot);
		}

		// -----------------------------------------------------------------
		// ④ 合成：背景 + 玻璃 [+ 内容] 一次画完。
		//
		//   ★ 必须在**所有页画完之后**才调 —— 内容就是在这里画进 layer 的
		//     （GL 后端把场景回调进着色器管线；CPU 后端则完全不碰内容）。
		// -----------------------------------------------------------------
		g_glass.Compose();

		if (glassActive) {
			// 玻璃层（背景 + 面板，GL 时连内容一起）已成品，盖到双缓冲上。
			BitBlt(buffer, 0, 0, client.right, client.bottom, g_glass.layer.dc, 0, 0, SRCCOPY);
		}

		// ★ CPU 合成 / 经典模式：内容还没画出来 ⇒ 用 GDI 把整个场景重放一遍。
		//   （GL 那条路上内容已经在 layer 里了，再画一遍会变成"文字描两遍"，
		//     深色字会显得发胖。）
		const bool contentInLayer = glassActive && g_glass.glCompose != nullptr;
		if (!contentInLayer) {
			g_scene.PaintGdi(buffer, true);
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

		if (glassActive) {
			// ★ v88：这里是 **SyncPanels**（不是 CommitPanels）。
			//   主程序是"先画内容、后 Compose"，合成已经吃过本帧的 `cur[]` 了，
			//   所以只要把 `used[]` 同步过去当对照即可 —— 用 CommitPanels
			//   会把 layerDirty 置起来，CPU 回落路径就会每帧重跑一遍 box blur。
			g_glass.SyncPanels();
		}

		SelectObject(buffer, oldBitmap);
		DeleteObject(bitmap);
		DeleteDC(buffer);

		EndPaint(hwnd, &ps);
	}

	// =====================================================================
	//  v101：退出看门狗 —— 「退不出去」的最后一道保险
	// =====================================================================
	//
	// 背景（2026-10-24 真机）：`g_quitRequest` 只是一个**标志**，真正退进程
	// 的动作在 `app.cpp` 主循环里。主循环一旦被卡住（那天是被 procwatch 的
	// "每个进程问一次引擎"卡在启动路径上），用户点退出就**只置了标志**：
	// 窗口照常响应、照常重绘，但进程永远不退 —— 观感就是
	// 「点了完全没反应 / 退不出去」，而日志里连一行错误都没有。
	//
	// 设计取舍（每一条都是刻意的）：
	//   · 只在**用户明确要退出**时武装（按钮 / 托盘二次确认），不是常驻线程；
	//   · 15 秒后无条件 `TerminateProcess(自己)`。
	//     为什么敢硬杀：v89 拆进程之后，注入的 DLL 活在**引擎进程**里，
	//     界面进程里一个 hook 都没有 ⇒ 硬杀界面**不会**留下悬空的 hook，
	//     反注入本来也是引擎做。（拆进程之前不能这么干 —— 那会把被挂起的
	//     进程留在半死状态，正是铁律 107 要防的。）
	//   · 15 秒这个数：正常收尾最坏路径 ≈ 引擎 Stop 2s + 等引擎退出 3s +
	//     procwatch 线程 join ≤4s ≈ 10s，留 5s 余量。正常情况根本走不到。
	void ArmExitWatchdog()
	{
		static volatile LONG s_armed = 0;
		if (InterlockedExchange(&s_armed, 1) != 0) {
			return;   // 已武装（用户连点多次，不重复起线程）
		}
		HANDLE h = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
			Sleep(15000);
			// 走到这里 = 主循环 15 秒内没把进程收掉。
			printf("[quit] 退出看门狗触发：主循环 15 秒内未完成收尾，强制结束界面进程"
				"（引擎是独立进程，会继续防护）\n");
			fflush(stdout);
			TerminateProcess(GetCurrentProcess(), 0);
			return 0;
		}, nullptr, 0, nullptr);
		if (h) {
			CloseHandle(h);   // 线程自己会跑完；句柄用完即关
		}
	}

	// 执行一个按钮动作。
	//
	// 只在 **WM_LBUTTONUP 且松手时鼠标仍停在同一个按钮上** 才调用 ——
	// 标准按钮语义。以前是"按下就执行"，那样按错了没法反悔
	//（对「退出引擎」这种破坏性动作尤其危险）。
	void PerformHeaderAction(HWND hwnd, HeaderAction action)
	{
		// ★ v100 诊断：把"按钮确实触发了"留在日志里。没有这行的话，
		//   "点了没反应"永远分不清是 ① 鼠标没到窗口 ② 命中了别的控件
		//   ③ 置位了但主循环没消费 —— 三者都表现为"什么都没发生"。
		printf("[btn] 触发 action=%d\n", static_cast<int>(action));
		fflush(stdout);

		switch (action) {
		case HeaderAction::ExitEngine:
			// 只置位，真正的收尾在 app.cpp 主循环里做
			//（反注入 → 关窗口 → 退出进程）。界面线程绝不直接退进程 ——
			// 否则引擎还没来得及反注入，被注入的进程里会留下悬空的 hook。
			InterlockedExchange(&g_quitRequest, 1);
			// ★ v101：武装看门狗。主循环要是 15 秒内没动静（2026-10-24 那次
			//   就是卡在 procwatch 的启动扫描上），至少还能死得掉。
			ArmExitWatchdog();
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
		// ★ v84：从托盘还原时窗口还是隐藏的 ⇒ 可以重新抓一次真实背景
		//   （用户可能已经切到别的窗口/换了壁纸，重新抓比一直用启动时那张准）。
		if (g_uiStyle == Style::Glass) {
			RECT crc = {};
			GetClientRect(hwnd, &crc);
			g_glass.CaptureBackdropBeforeShow(hwnd, crc.right, crc.bottom);
		}
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
		// ★ v101：和「退出引擎」按钮走**同一条**收尾路径，所以看门狗也要武装。
		//   用户明确说了要退出，就不能出现"窗口收了、进程还在"这种观感。
		ArmExitWatchdog();
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

	// ------------------------------------------------------------------
	// ★ v94：切页签（点击 / 按住拖动共用这一个入口）
	//
	//   为什么要抽出来：参考项目里 dock 是**分段控件**，鼠标按下后按住
	//   横向拖动，滑过哪段就切到哪段（`g_dragId` + `K_SEG` 那段）。
	//   本项目原来只有"点"，拖动时什么都不发生 —— 手感差一截。
	//   两条路径共用同一个函数，才不会出现"点着切了、拖着没切"这种分叉。
	// ------------------------------------------------------------------
	void SelectTab(int tab)
	{
		if (tab < 0 || tab >= TabCount || tab == g_activeTab) {
			return;
		}
		g_activeTab = tab;

		// ★ v93：换页清一次动画表。key 里已经带了页号（不会串），
		//   但不清的话 6 个页面的 key 会一直累积，撑满 192 个槽之后
		//   新控件会静默退化成"不动画"—— 那种 bug 极难看出来。
		//   页签滑块的两个弹簧**不在**表里（见 g_tabThumbX0/X1），
		//   所以滑动不受影响。
		g_anim.Clear();

		// ★ v94：挤压。参考项目切换时把 dock 宽度**瞬间**加 12px
		//   （`g_dockW.v = 122.0f`）再把目标设回 110 ⇒ 先胖一下再收回来。
		//   这里同样：直接改 `v`（不是 tgt），所以是"起手就宽"。
		g_tabSqueeze.v = 12.0f;
		g_tabSqueeze.tgt = 0.0f;

		EnsureAnimTimer();

		if (tab == 1) {
			// 首次进日志页直接贴底，不用手动滚。
			g_logScroll = 0;
			g_logFollowTail = true;
		}
		if (tab == 4) {
			// 首次进 ARK 页立刻拉一次，别让用户看着空列表等一个扫描周期。
			RefreshArkCache(true);
		}
		if (g_window) {
			InvalidateRect(g_window, nullptr, FALSE);
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

		// -----------------------------------------------------------------
		// ★★★ v98：自绘标题栏的两个必备消息
		//
		//   `WM_NCCALCSIZE` 返回 0 ⇒ **客户区 = 整个窗口矩形**，系统标题栏
		//   和边框不再占位，玻璃从窗口最上沿开始铺。这是"去掉标题栏但保留
		//   缩放边框"的标准做法（比 `WS_POPUP` 无边框干净，DWM 阴影和
		//   圆角都还在）。
		//
		//   `WM_NCHITTEST` 负责把"系统原本替我们做的事"补回来：
		//     · 四周 8px 还给缩放；
		//     · 顶栏那条（y < 58）还给拖动（HTCAPTION，双击即最大化）；
		//     · 按钮上必须返回 HTCLIENT，否则点不到（HTCAPTION 会把
		//       点击吞成"拖窗口"）。
		//
		//   ⚠️ 顺序不能反：先判按钮，再判拖动区。
		// -----------------------------------------------------------------
		case WM_NCCALCSIZE:
			if (wParam == TRUE && g_uiStyle == Style::Glass) {
				// ★ v98：最大化时必须**扣掉窗口边框**。
				//
				//   最大化时系统会把窗口矩形撑到"工作区 + 一圈边框"，
				//   而客户区 = 窗口矩形 ⇒ 四周各溢出 7~8px，界面的
				//   最外一圈（圆角、卡片边缘）被切到屏幕外。
				//   实测：不扣的时候最大化客户区是 1934x1094 且原点 (-7,-7)。
				//   非最大化时不能扣 —— 那样又会露出一圈桌面缝。
				NCCALCSIZE_PARAMS* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(lParam);
				if (params && IsZoomed(hwnd)) {
					// 直接用**工作区矩形**（屏幕坐标），不要用"减边框"的算术：
					// 边框宽度和系统实际膨胀量差 1px，减出来的结果四周会各少 1px。
					MONITORINFO mi = {};
					mi.cbSize = sizeof(mi);
					if (GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi)) {
						params->rgrc[0] = mi.rcWork;
					}
				}
				return 0;   // 客户区 = 窗口矩形（最大化时 = 工作区）
			}
			break;

		case WM_NCHITTEST: {
			if (g_uiStyle != Style::Glass) {
				break;   // 经典模式还有系统标题栏，交回默认处理
			}
			POINT screenPt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
			POINT pt = screenPt;
			ScreenToClient(hwnd, &pt);

			RECT client = {};
			GetClientRect(hwnd, &client);
			const bool zoomed = IsZoomed(hwnd) != FALSE;
			// 最大化时不留缩放边（留了会在屏幕边缘出现"拖不动但能触发"的死区）
			const int b = zoomed ? 0 : 8;

			if (b > 0) {
				const bool left = pt.x < b;
				const bool right = pt.x >= client.right - b;
				const bool top = pt.y < b;
				const bool bottom = pt.y >= client.bottom - b;
				if (top && left) return HTTOPLEFT;
				if (top && right) return HTTOPRIGHT;
				if (bottom && left) return HTBOTTOMLEFT;
				if (bottom && right) return HTBOTTOMRIGHT;
				if (left) return HTLEFT;
				if (right) return HTRIGHT;
				if (top) return HTTOP;
				if (bottom) return HTBOTTOM;
			}

			// 标题栏拖动区 = 顶栏玻璃条那一带（0..58），按钮除外
			if (pt.y < 58) {
				if (HitTestCapButton(pt) != CapBtn::None) {
					return HTCLIENT;
				}
				if (HitTestHeaderAction(pt) != HeaderAction::None) {
					return HTCLIENT;
				}
				return HTCAPTION;
			}
			return HTCLIENT;
		}

		case WM_GETMINMAXINFO: {
			MINMAXINFO* info = reinterpret_cast<MINMAXINFO*>(lParam);			// 最小宽度 1040：页签占满左侧（Padding 20 + 5×(84+8) - 8 = 472），
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
			// ★ v103：记住最后位置 —— `DrawConfigPage` 判断「应用」按钮悬停要用。
			//   放在拖动分支**之前**：拖动中也该更新，否则松手后悬停停在旧位置。
			g_mousePoint = point;

			// ★ v94：按住页签拖动 —— 划过哪段就切到哪段（参考项目 K_SEG 的行为）。
			//   必须在悬停判定**之前**处理：拖动过程中用户看的是滑块跟手，
			//   不是"哪个页签变色"。
			if (g_tabDrag >= 0) {
				const int over = HitTestTab(point);
				if (over >= 0) {
					SelectTab(over);
				}
				return 0;
			}

			// ★ v98：自绘标题栏按钮的悬停（它们不在 HeaderAction 那套里 ——
			//   窗口按钮的语义和业务动作不同，也不该走 PerformHeaderAction）。
			const CapBtn capOver = (g_uiStyle == Style::Glass)
				? HitTestCapButton(point) : CapBtn::None;
			if (capOver != g_capHover) {
				g_capHover = capOver;
				InvalidateRect(hwnd, nullptr, FALSE);
			}

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
				// ★ v93：悬停是**逐帧插值**的（参考项目 14/s 指数逼近），
				//   所以状态一变就要把动画时钟叫起来，否则目标值改了但没人推进。
				EnsureAnimTimer();
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;
		}

		case WM_MOUSELEAVE:
			g_trackingMouseLeave = false;
			g_capHover = CapBtn::None;   // v98：窗口按钮的悬停也要一起清
			EnsureAnimTimer();   // 让悬停态淡出，而不是"啪"一下消失
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
			// ★ v94：页签拖动也一样 —— 不清的话 `g_tabDrag` 会一直 >= 0，
			//   之后每一次 WM_MOUSEMOVE 都在"拖动分支"里提前 return，
			//   表现是"整个界面的悬停全部失灵"，而且看不出原因。
			if (g_tabDrag >= 0) {
				g_tabDrag = -1;
			}
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

			// ★ v98：自绘标题栏的窗口按钮。**按 Windows 惯例立即执行**
			//   （不等 WM_LBUTTONUP）—— 标题栏按钮是可以"按下去就生效、
			//   拖走也不取消"的，和普通按钮的语义不同。
			const CapBtn capBtn = (g_uiStyle == Style::Glass)
				? HitTestCapButton(point) : CapBtn::None;
			if (capBtn == CapBtn::Min) {
				ShowWindow(hwnd, SW_MINIMIZE);
				return 0;
			}
			if (capBtn == CapBtn::Max) {
				ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
				return 0;
			}
			if (capBtn == CapBtn::Close) {
				// 与系统 ✕ 完全同义：走 WM_CLOSE ⇒ 收进托盘（引擎继续跑）。
				PostMessageW(hwnd, WM_CLOSE, 0, 0);
				return 0;
			}

			// 按钮：按下只进入"按下态" + 捕获鼠标，**真正的动作留到 WM_LBUTTONUP**。
			// 标准按钮语义 —— 按下后拖出去再松手不触发，按错了能反悔。
			const HeaderAction action = HitTestHeaderAction(point);
			// ★ v100 诊断：按下时命中到哪个 header 按钮（None=-1 表示没命中）。
			//   和 `[btn] 触发` 配对看，就能区分"按下没命中"和"松手被判成拖走"。
			printf("[btn] 按下 (%d,%d) -> action=%d\n", static_cast<int>(point.x),
				static_cast<int>(point.y), static_cast<int>(action));
			fflush(stdout);
			if (action != HeaderAction::None) {
				g_pressedButton = action;
				g_hoverButton = action;
				EnsureAnimTimer();   // v93：按下缩 2.8% 是弹簧，要有人推进
				SetCapture(hwnd);
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			int tab = HitTestTab(point);
			if (tab >= 0) {
				// ★ v94：按住页签 = 进入拖动。参考项目 dock 是分段控件，
				//   按下后横向划过哪段就切到哪段；本项目原来只有"点"。
				//   `g_tabDrag` 记着"这次按下是从页签条开始的"，
				//   WM_MOUSEMOVE 里据此连续切页。
				g_tabDrag = tab;
				SetCapture(hwnd);
				SelectTab(tab);
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

			// ★★★ v103：「配置」页的开关（用户："开关用不了，点不动"）。
			//
			//   语义**故意和别的按钮不同**：这里点一下就立刻拨、立刻重画，
			//   不需要"按下→松手仍在同一处"那套。理由：
			//     · 开关不是"执行一个动作"，是"改一个值" —— 参考项目的开关
			//       也是按下即生效（`Switch` 在 K_SWITCH 的 WM_LBUTTONDOWN 里）；
			//     · 拨动后**并不真的生效**（要按「应用」），所以不存在"误触
			//       造成后果"这回事，可以做得跟手一点。
			//
			//   ★ 拨动只改寄存区，**不写文件、不发 IPC** —— UI 线程上做 I/O
			//     会卡住整屏重绘（v101 的教训）。
			if (g_activeTab == 3) {
				RECT client = {};
				GetClientRect(hwnd, &client);

				ConfigField field = ConfigField::None;
				if (HitTestConfigToggle(point, client, &field)) {
					const bool before = DisplayConfigValue(field);
					SetPendingConfig(field, !before);
					// ★ v103 诊断：`R3SHIELDCORE_CFG_TRACE=1` 时把每次拨动打出来。
					//   加它的理由：这台机器上截屏会被 IDE 窗口遮住（前台锁），
					//   像素判据跑不起来；日志是唯一能自证"这一下点到了"的通道。
					//   ★ 写文件而不是 printf —— WINDOWS 子系统没有 stdout。
					if (ConfigTraceEnabled()) {
						char trace[256] = {};
						_snprintf_s(trace, _countof(trace), _TRUNCATE,
							"toggle field=%d %d->%d dirty=%d diff=%d",
							static_cast<int>(field), before ? 1 : 0,
							DisplayConfigValue(field) ? 1 : 0,
							g_pendingConfig.dirty ? 1 : 0,
							HasPendingConfigDiff() ? 1 : 0);
						ConfigTrace(trace);
					}
					// ★★ 拨完之后**立刻重算一次差异**，让「应用」按钮当场出现/消失。
					//
					//   不这么做的话：拨开 → 按钮出现（因为 `HasPendingConfigDiff`
					//   在绘制时算）；拨回去 → 下一次绘制时按钮消失。看起来也对，
					//   但 `g_pendingConfig.dirty` 会一直挂着 true，`DisplayConfigValue`
					//   就一直走寄存区分支 —— 一旦这期间 `SetOptions` 没被调用
					//   （比如引擎没连上），界面就永远显示寄存区里的陈旧值。
					//   这里借 `BuildConfigApplyRequest` 的"无差异就清 dirty"逻辑
					//   把状态收干净，这是它唯一的副作用。
					BuildConfigApplyRequest();
					EnsureAnimTimer();
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
				}

				if (HitTestConfigApply(point, client)) {
					// 把寄存区拼成请求。**真正的写法在 app.cpp**：
					// 它要写 ini、要干净地停引擎、要重新 LoadLibrary 注入。
					BuildConfigApplyRequest();
					if (ConfigTraceEnabled()) {
						char trace[256] = {};
						_snprintf_s(trace, _countof(trace), _TRUNCATE,
							"apply clicked valid=%d lines=%zu",
							g_configApply.valid ? 1 : 0, g_configApply.lines.size());
						ConfigTrace(trace);
					}
					if (g_configApply.valid) {
						// ★ 顺序不能反：**先写数据、后置标志**。
						//   反过来的话主循环可能看到标志却读到半份数据
						//   （`lines` 还在被 push_back）—— 正是铁律 291 那类
						//   "看起来只是慢一点"的竞态。
						InterlockedExchange(&g_configApplyPending, 1);
						// ★ 限定名调用：`ShowNotice` 属于 `R3ShieldCoreGui`，
						//   而这里在文件顶部的匿名命名空间里。不带限定会去
						//   找匿名命名空间的那个（不存在）⇒ `C3861`；
						//   自己再声明一个 ⇒ `LNK2019`（两个不同的符号）。
						R3ShieldCoreGui::ShowNotice(L"正在写入配置并重启引擎…", 4000);
					}
					SetCapture(hwnd);
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
				}

				// 配置页没有别的可点区域。**必须吃掉这次点击** ——
				// 否则会落到下面「日志页」那条按 x 分界的分支（旧版本就靠这个
				// 巧合躲过去了；一旦以后加了别的页，就会变成跨页误触）。
				if (ConfigTraceEnabled()) {
					char trace[256] = {};
					_snprintf_s(trace, _countof(trace), _TRUNCATE,
						"miss at %ld,%ld (client=%ldx%ld)",
						point.x, point.y, client.right, client.bottom);
					ConfigTrace(trace);
				}
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

			// ★ v94：页签拖动结束。捕获必须在这里放开，否则窗口会一直
			//   吃鼠标消息（表现为"整个桌面点不动"）—— 比动画不对严重得多。
			if (g_tabDrag >= 0) {
				g_tabDrag = -1;
				if (GetCapture() == hwnd) {
					ReleaseCapture();
				}
				return 0;
			}

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
			// ★ v93：动画时钟（16ms）。推进一帧 → 重画 → 全部收敛就停表。
			//   这一条必须在下面"无脑重画"之前分流：那条路只重画不推进弹簧，
			//   动画会永远停在第一帧。
			if (wParam == AnimTimerId) {
				const ULONGLONG now = GetTickCount64();
				const float dt = g_animLastMs
					? static_cast<float>(now - g_animLastMs) / 1000.0f
					: 0.0f;
				g_animLastMs = now;

				// ⚠️ 页签滑块的两个弹簧**不在** g_anim 表里（它们不是"控件状态"，
				//   而是页面级的），必须在这里单独推进 —— 忘了这一步的表现是
				//   "点了页签，页面换了，但滑块还停在上一页"，而且不报错。
				g_tabThumbX0.Step(dt);
				g_tabThumbX1.Step(dt);
				g_tabSqueeze.Step(dt, 190.0f, 15.0f);   // 参考项目 dock 的挤压参数
				const bool busyBank = g_anim.Tick(dt);
				// ★ v95：背景还在变（观察窗内）就**不许停表** ——
				//   停了就退回 300ms 常态，背后拖窗口会一顿一顿。
				const bool bgWatching = now < g_bgWatchUntil;
				const bool busy = busyBank || bgWatching
					|| g_tabThumbX0.Busy() || g_tabThumbX1.Busy()
					|| g_tabSqueeze.Busy();

				InvalidateRect(hwnd, nullptr, FALSE);
				if (!busy) {
					// 收敛：停表。最后一帧已经 Invalidate 了，界面停在终值上。
					KillTimer(hwnd, AnimTimerId);
					g_animRunning = false;
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
			// ★ v85：补上 `process` / `config` —— 探针一直支持这两个页签参数
			//   （见 gui_preview_probe.cpp 的用法说明），但这里从来没实现过：
			//   传 config 会**静默**停在概览页，而截图"看起来完全正常"。
			//   ⇒ 这不是新功能，是补一条"探针说在核对某一页、其实没核对"的假绿。
			else if (n > 0 && _wcsicmp(tabEnv, L"process") == 0) {
				g_activeTab = 2;
			}
			else if (n > 0 && _wcsicmp(tabEnv, L"config") == 0) {
				g_activeTab = 3;
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
					printf("[glass] OpenGL 不可用（阶段=%d）-> 退回 CPU 合成 标记=%ls\n",
						g_gl.failStage, R3ShieldCoreUi::kGlMarker);
				}
			} else {
				printf("[ui] 界面风格：经典（不铺玻璃层）标记=%ls\n",
					R3ShieldCoreUi::kStyleMarker);
			}
			// ★ v98：玻璃风格 ⇒ 去掉系统标题栏（自绘）。必须在
			//   `ApplyGlassWindow` **之前**：切风格会 SWP_FRAMECHANGED
			//   重算一次非客户区，之后设的 DWM 圆角/标题栏配色才落在最终形态上。
			ApplyCustomFrame(g_window);
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

			// ★★★ v89：**删掉了**"窗口显示之前抓一次背景快照"。
			//
			//   那一版的设计意图是"显示前抓，抓到的就是透过窗口该看到的东西"，
			//   但实测在这台机器上是**反的**：
			//       [glass] 快照诊断 请求=1024x701 实际=1024x701 原点=448,201 均值=0
			//       [glass] 背景快照抓取失败 ⇒ 用内置背景兜底
			//   显示前那次抓到的是**全黑**（均值 0），于是直接掉进
			//   `BuildDesignedFull` 的程序化渐变；而 `EnsureBackdrop` 又被
			//   `backdrop.valid` 锁死不再重抓 ⇒ 屏幕上那层"玻璃"透视的
			//   一直是程序自己画的一张图，**不是桌面**。
			//
			//   现在改成和参考项目 `LiquidGlassControls` 一致：
			//   窗口显示之后，由 `EnsureBackdrop` 每 150ms 抓一次
			//   （抓的瞬间才 `SetWindowDisplayAffinity(0x11)` 排除自己）。
			//   第一次成功抓取就把内置背景永久换掉。

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
			// ★ v95：背景跟随间隔（见 g_bgFollowMs）。只在启动时读一次。
			{
				wchar_t msEnv[16] = {};
				if (GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_FOLLOW_MS",
						msEnv, _countof(msEnv)) > 0) {
					const int v = _wtoi(msEnv);
					if (v >= 16 && v <= 2000) {
						g_bgFollowMs = static_cast<ULONGLONG>(v);
						printf("[glass] 背景跟随间隔 = %dms（环境变量覆盖）\n", v);
					}
				}
			}
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
	// ★★★ v103：`Options::LogPath` 的**深拷贝存储**。
	//
	// 为什么必须有：`LogPath` 是裸 `const WCHAR*`，调用方（app.cpp）传进来的
	// 是**栈上 `Policy` 结构体内部**的缓冲。以前 `g_options = options;`
	// 只拷指针 —— 那个 Policy 一出作用域，`g_options.LogPath` 就成了野指针，
	// 而日志页 / 配置页会去画它（Dereference 一个已经归还的栈帧）。
	// 一直没炸只是因为 app.cpp 里那份 Policy 活得比界面久。
	// ★ v103 新增的「应用配置后刷新」会从**函数栈**里喂一份新的 ⇒ 必须真拷。
	static WCHAR g_optionsLogPath[1024] = {};

	void ApplyOptions(const Options& options)
	{
		g_options = options;
		if (options.LogPath != nullptr && options.LogPath[0] != L'\0') {
			wcsncpy_s(g_optionsLogPath, options.LogPath, _TRUNCATE);
			g_options.LogPath = g_optionsLogPath;
		}
		else {
			g_optionsLogPath[0] = L'\0';
			g_options.LogPath = nullptr;
		}
	}

	bool Start(const Options& options) noexcept
	{
		if (g_guiThread) {
			return true;
		}

		ApplyOptions(options);
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

	// ★★★ v103：「配置」页应用完、引擎重启之后，把新的真值喂回界面。
	//
	// ★ 这里**必须**清掉待提交寄存区（`g_pendingConfig.dirty = false`）——
	//   这是"开关不弹回旧值"的**唯一**正确时机：
	//     · 早了（按下「应用」那一刻就清）⇒ 引擎还没重启完，
	//       `g_options` 仍是旧值 ⇒ 开关先弹回旧值，看起来像没生效；
	//     · 晚了 / 不清 ⇒ 用户下次进来看到的是自己拨的位置，
	//       但引擎里根本不是那个值 —— 界面在撒谎。
	//   只有"新值已经到了"这一刻清，`DisplayConfigValue` 才会从
	//   `g_options` 读出**新值**，视觉上无缝。
	void SetOptions(const Options& options) noexcept
	{
		ApplyOptions(options);

		g_pendingConfig.dirty = false;
		for (int i = 0; i < static_cast<int>(ConfigField::Count); i++) {
			g_pendingConfig.value[i] = false;
		}
		g_configApply = ConfigApplyRequest{};
		InterlockedExchange(&g_configApplyPending, 0);

		// 弹簧的旧值也要跟着跳过去（不然会从旧位置滑一段）。
		// ⇒ 直接重画，让 `DrawConfigRow` 用新目标值重建 Slot 的目标。
		if (g_window) {
			EnsureAnimTimer();
			InvalidateRect(g_window, nullptr, FALSE);
		}
		printf("[ui] 配置选项已刷新（hook_file=%d hook_reads=%d）\n",
			options.HookFile ? 1 : 0, options.HookReads ? 1 : 0);
		fflush(stdout);
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

	// ★★★ v103：把「应用并重启引擎」的请求交给主程序。
	//
	// 与 `TakeQuitRequest` 同样的模式：UI 线程**只置一个待处理标记**，
	// 真正的写 ini + 停引擎 + 重新注入由 `app.cpp` 主循环做。
	//
	// ★ 为什么用「标记 + 数据」两段而不是队列：全项目只有**一个**消费者
	//   （主循环），且请求是"整份替换"语义（后一次覆盖前一次）——
	//   用户连点两次「应用」只该应用一次。队列在这里纯属多余。
	//
	// ★ 锁与标记声明在**上方**（`ConfigApplyRequest` 旁边）——
	//   `BuildConfigApplyRequest` 和点击处理都要用它们。
	bool TakeConfigApplyRequest(std::vector<std::wstring>& lines,
		bool& arkPresent, bool& arkEnabled) noexcept
	{
		if (InterlockedCompareExchange(&g_configApplyPending, 0, 0) == 0) {
			return false;   // 常见路径：没请求，**不加锁**
		}
		std::lock_guard<std::mutex> lock(g_configApplyMutex);
		if (!g_configApply.valid) {
			InterlockedExchange(&g_configApplyPending, 0);
			return false;
		}
		lines = g_configApply.lines;
		arkPresent = g_configApply.arkPresent;
		arkEnabled = g_configApply.arkEnabled;

		// 取走即清空 —— 否则同一份改动会被应用第二次（重复重启引擎）。
		g_configApply = ConfigApplyRequest{};
		InterlockedExchange(&g_configApplyPending, 0);
		return true;
	}

	void SetMode(R3ShieldCore::Mode mode) noexcept
	{
		InterlockedExchange(&g_displayMode, static_cast<LONG>(mode));

		// 立刻重画，别等 300ms 的 WM_TIMER —— 点了按钮要马上看到徽章变。
		if (g_window) {
			InvalidateRect(g_window, nullptr, FALSE);
		}
	}

	// ★ v91：引擎连接状态（主循环每轮喂一次，只在变化时重画）。
	void SetEngineConnected(bool connected) noexcept
	{
		const LONG next = connected ? 1 : 0;
		if (InterlockedExchange(&g_engineConnected, next) == next) {
			return;
		}
		if (g_window) {
			InvalidateRect(g_window, nullptr, FALSE);
		}
	}

	// ★ v91：窗口内的一次性提示（8 秒）。
	//
	// 为什么需要它：界面没有控制台，`printf` 的失败原因用户永远看不到。
	// 现在"模式切换失败：引擎未连接"这类结论会**直接画在标题栏副标题那一行**，
	// 不再只写进一个运行期打不开的日志文件。
	void ShowNotice(const std::wstring& text, ULONGLONG durationMs) noexcept
	{
		// ★ 写侧加锁（读侧见 `PaintWindow`）。**`InvalidateRect` 必须留在锁外**：
		//   它会把窗口线程唤醒去重绘，而重绘要拿同一把锁 ——
		//   持锁发重绘请求会让两个线程互相等（虽然 InvalidateRect 本身异步，
		//   但没有理由冒这个险，临界区越短越好）。
		{
			std::lock_guard<std::mutex> lock(g_noticeMutex);
			g_notice = text;
			g_noticeUntil = GetTickCount64() + (durationMs ? durationMs : 8000);
		}
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

		// ★★ v89：预览模式下背景**抓成功一次就冻住**。
		//
		//   为什么不能和生产一样持续重抓：抓背景必须先
		//   `SetWindowDisplayAffinity(hwnd, 0x11)` 把自己排除掉，抓完再恢复。
		//   而本项目的验收探针 `tools/gui_preview_probe.cpp` 是**从屏幕
		//   BitBlt** 截这个窗口的 —— 若每 150ms 就开一次"隐身窗口"，
		//   探针有概率正好落在那 16ms 里，截到一张"窗口是个洞"的图，
		//   闸门会随机假红（而且极难查）。
		//   ⇒ 预览模式只抓一次：既能让截图反映"真实桌面被模糊了"，
		//     又不会和探针抢那个窗口。
		//
		// ★★ v90：但"冻住"对人眼验收是错的 —— 拖着窗口走，玻璃里还是
		//   起步位置那张背景，看起来像贴了一张图（正是 v89 之前那个毛病
		//   的观感）。
		//
		// ★★★ v92：所以**默认改成实时**，反过来给自动化一个"冻住"开关：
		//     · 人看效果（默认）：实时重抓，玻璃跟着窗口/背后的内容走；
		//     · 跑闸门/探针截图：`R3SHIELDCORE_PREVIEW_FREEZEBG=1` 冻住。
		//       （`tools/test_gui_preview.sh` 已经在导出这个变量。）
		//
		//   为什么方向要反过来：默认值决定"用户第一眼看到什么"。
		//   冻背景是给截图用的技术妥协，不该是用户看到的第一印象 ——
		//   v90 之前默认冻住，用户第一反应就是"拖动背景不变"。
		//
		//   ⚠️ v95 改：**实时模式改成"永久排除自身抓屏"**（和正式版一致）。
		//
		//   原来这里是 `permanentWda = false`（每次抓的瞬间开关），理由是想让
		//   预览窗口还能被系统截图拍到。实测这个折中**两头不讨好**：
		//     · 每次开关都要 `DwmFlush` 等一次合成（~16ms×2），300ms 一次也就算了；
		//     · 更要命的是**它自己扰动了自己**：排除/恢复之间抓到的画面
		//       在"桌面"和"自己"之间来回跳，指纹每次都变 ⇒ v95 的
		//       "背景变了就提速"观察窗**永远关不掉**，静止时也会一直
		//       以 25fps 抓屏+调色+模糊，实测 **23% 单核**。
		//     · 而且探针仍有可能截到那个"洞"。
		//   ⇒ 实时模式设永久排除（生产路径本来就是这样，抓屏成本降到一次 BitBlt）；
		//     需要截图时用 `preview.bat <tab> freeze`（冻结模式仍走"抓完就恢复"，
		//     所以截图里窗口是完整的）。
		g_glass.liveCapture = true;
		g_glass.permanentWda = true;
		{
			wchar_t env[8] = {};
			const DWORD n = GetEnvironmentVariableW(
				L"R3SHIELDCORE_PREVIEW_FREEZEBG", env, _countof(env));
			if (n > 0 && _wcsicmp(env, L"1") == 0) {
				g_glass.liveCapture = false;
				// 冻结：只抓一次，之后再也不碰屏幕 ⇒ 不设永久排除，
				// 截图（含验收探针的屏幕 BitBlt）才能拍到窗口。
				g_glass.permanentWda = false;
				printf("[gui-preview] 背景已冻结（供截图判据使用，不跟随窗口）\n");
			} else {
				printf("[gui-preview] 实时背景（玻璃跟随窗口/背后内容变化）\n");
			}
		}

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
