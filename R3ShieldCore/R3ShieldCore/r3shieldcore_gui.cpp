#include "stdafx.h"
#include "r3shieldcore_gui.h"
#include "r3shieldcore_ark.h"
#include "r3shieldcore_stats.h"
#include "r3shieldcore_superdesk.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdio>   // 置顶状态变更留痕（stdout）
#include <string>
#include <vector>

// ---------------------------------------------------------------------
// ★ v77：主程序「高级」页签 —— 与「替换 API 结果」控制台**同一份**逻辑。
//
//   铁律 195（同一份逻辑不抄第二遍）：这一页显示的「改前 / 改后」字节，
//   必须是引擎真跑时会写进去的那些字节，所以四件东西全部**直接复用**：
//     · rules_codec.h        —— 中文规则引擎（含正则）
//     · spoof_apply_codec.h  —— 判定 -> 字节怎么落地
//     · registry_spoof_codec.h   —— **生产同源**的数据区定位
//     · clipboard_spoof_codec.h  —— **生产同源**的替代物构造
//
//   ⚠️ 后两个住在 `R3ShieldCoreLib/`，所以构建脚本要把那个目录放进搜索路径
//      （见 build.sh 的 build_demo：`-I R3ShieldCoreLib`）。漏了会 C1083。
// ---------------------------------------------------------------------
#include <r3shieldcore/rules_codec.h>
#include <r3shieldcore/spoof_apply_codec.h>
#include "registry_spoof_codec.h"
#include "clipboard_spoof_codec.h"

// ★ v78：两样东西也必须**共用同一份**，不能在这一页里再抄一遍。
//
//   · `rules_file.h` —— 规则文件**放在哪**。
//     界面要**写**它、引擎（每个被注入进程）要**读**它，两边必须指向
//     同一个文件。抄两份的后果是"界面显示已保存、引擎一条都不生效"，
//     而且两边都不报错（铁律 195/127）。
//
//   · `advanced_quiz.h` —— 三道闸门题。
//     命令行控制台（tools/spoof_console.cpp）与这一页共用同一套题；
//     抄两份的话会出现"控制台过了、界面过不了"这种谁也看不出原因的分歧。
#include <r3shieldcore/rules_file.h>
#include <r3shieldcore/advanced_quiz.h>

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
	constexpr COLORREF ColorBackground = RGB(250, 250, 250);
	constexpr COLORREF ColorHeaderBackground = RGB(255, 255, 255);
	constexpr COLORREF ColorBorder = RGB(226, 226, 226);
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
	constexpr COLORREF ColorTabActiveBg = RGB(0, 120, 215);
	constexpr COLORREF ColorTabActiveText = RGB(255, 255, 255);
	constexpr COLORREF ColorTabInactiveText = RGB(90, 90, 90);
	// 未选中页签的悬停态（浅蓝底 + 淡蓝描边）。
	constexpr COLORREF ColorTabHoverBg = RGB(233, 242, 252);
	constexpr COLORREF ColorTabHoverBorder = RGB(178, 210, 240);
	constexpr COLORREF ColorLogRowAlt = RGB(246, 246, 246);
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

	HINSTANCE g_instance = nullptr;
	HWND g_window = nullptr;

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

	HFONT g_titleFont = nullptr;
	HFONT g_labelFont = nullptr;
	HFONT g_valueFont = nullptr;
	HFONT g_monoFont = nullptr;
	HFONT g_logFont = nullptr;   // 日志行用更小的等宽字体，一屏塞得下更多
	HFONT g_tabFont = nullptr;

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

	// ★ v77：「高级」页签的两个按钮（自绘，与 ARK 那套一样单独一份状态）。
	//   同样**不**并进 HeaderAction —— 它们的位置随客户区大小变、且只在这一页存在。
	int g_advHoverAction = -1;
	int g_advPressedAction = -1;

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

		HBRUSH brush = CreateSolidBrush(background);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

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

		HBRUSH brush = CreateSolidBrush(background);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

		// 按下时文字下沉 1px，做出"压下去"的手感。
		RECT textRect = rect;
		if (state == ButtonState::Pressed) {
			OffsetRect(&textRect, 0, 1);
		}
		DrawTextSimple(dc, text, textRect, g_tabFont, textColor,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
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
				L"⚠ 完全拦截：其余一律拒绝；进程创建 / 远程线程 / 跨进程内存改为弹窗   ·   询问 %u 允许 %u 拒绝 %u   ·   丢弃 %u 条",
				prompt.Shown, prompt.Allowed, prompt.Denied, snapshot.DroppedEvents);
		}
		else if (mode == R3ShieldCore::Mode::BlockAllSafe) {
			// 与 BlockAll 的唯一区别：可信来源的进程创建直接放行（不弹窗）。
			swprintf_s(text,
				L"⚠ 完全拦截·安全：可信来源的进程创建直接放行；其余一律拒绝，远程线程 / 跨进程内存弹窗   ·   询问 %u 允许 %u 拒绝 %u   ·   丢弃 %u 条",
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
					L"⚠ 高危进程  %u 个   ·   最近 %s (pid %u)   ·   %s",
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
		HBRUSH brush = CreateSolidBrush(ColorHeaderBackground);
		HPEN pen = CreatePen(PS_SOLID, 1, ColorBorder);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

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

		HBRUSH brush = CreateSolidBrush(fill);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 6, 6);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

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
					swprintf_s(extra, L"  ·  ⚠ 枚举失败 %u 次（err=%lu）",
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
	// ★ v77/v78：「高级」页签 —— 规则脚本的**编辑台 + 预览台**
	// =================================================================
	//
	// 这一页回答两个问题：
	//   ① **我写的规则，会把 API 的返回值改成什么？**（v77 起的改前/改后对照）
	//   ② **怎么把规则写出来、存下去，让引擎真的用上？**（v78 起的编辑 + 落盘）
	//
	// ★ 三个界面状态（同一页，互斥）
	//   ① 闸门未过  —— 整块内容区换成**三道 Win32 题**（编辑区锁住）。
	//   ② 刚全对    —— 展示三道题的解析 + 「开始编辑」。
	//   ③ 已解锁    —— 左：规则表 + 编辑区；右：改前/改后字节对照。
	//
	// ★★ 三道题与命令行控制台是**同一套题**（`shared/r3shieldcore/advanced_quiz.h`）
	//   抄两份必然漂（铁律 127）：漂了之后"控制台过了、界面过不了"，
	//   而两边都不会报错。
	//
	// ★★ 规则文件在哪、谁读它（**这一页最容易让人误解的地方**）
	//   · 路径：`%ProgramData%\R3 Shield Core\r3shieldcore-rules.txt`
	//     （目录不存在则回退到本程序所在目录）—— 与 `r3shieldcore.ini` 同目录。
	//   · 引擎侧（`r3shieldcore-lib.dll`，跑在**每个被注入进程**里）**启动时
	//     各读一次**。⇒ **存完规则要重启引擎才生效**，页面上必须写清。
	//   · 路径解析是**同一份**代码（`shared/r3shieldcore/rules_file.h`）——
	//     界面存到 A、引擎读 B 是最难查的一类"存了没用"。
	//
	// ★★ 规则的**总闸**仍是 ini 的三个开关（`spoof_reg` / `spoof_clipboard` /
	//   `spoof_reg_enum`，默认**关**）。开关关着 ⇒ 规则一律不生效。
	//   页面必须把这件事**显示出来**（读的是引擎真正读到的那份配置）——
	//   否则用户写完规则没反应，界面上看不出任何原因（铁律 97）。
	//
	// ★ 它**不注入、不跑引擎、不碰真实 API**（铁律 175 因此不适用）：
	//   注册表样例是**本进程栈上的合成缓冲区**，剪贴板样例是**本进程自己
	//   GlobalAlloc 出来的** HGLOBAL。所以开发机上可以放心跑，配合
	//   `--gui-preview` 就能建窗截图核对。
	//
	// ★ 「改后」是怎么算出来的（每一步都走**生产路径**，不是"照着生产写的"）
	//   注册表值  ：`RSpoof::LocateDataRegion` 定位 -> `RApply::ApplyRegValue` 落值
	//   剪贴板    ：`RClip::FormatLabel` 出格式名 -> 命中规则走
	//               `RApply::BuildClipText`；没命中回落**生产** `RClip::BuildFake`
	//   注册表枚举：`RRule::Eval` 逐个子键问规则，命中「隐藏」的从列表去掉
	//               ⚠️ 未命中**一律保留** —— 这一页**不**模拟 `protect_reg` 判据
	//                  （那是引擎侧配置，界面拿不到；硬编一个假判据才是骗人）。
	//   ⚠️ 这一页只证明"规则 -> 字节"这一步；**引擎真的照做**由
	//      `tools/v78_guard_ut.cpp` 直接驱动生产的 `Evaluate` 证明。

	namespace RRule = R3ShieldCoreRuleScript;
	namespace RApply = R3ShieldCoreSpoofApply;
	namespace RClip = R3ShieldCoreClipboardSpoof;
	namespace RSpoof = R3ShieldCoreRegistrySpoof;

	// ================================================================
	// 闸门状态（v78）
	// ================================================================
	bool g_advQuizPassed = false;      // 三道题全对
	bool g_advWhyDismissed = false;    // 解析看完、开始编辑
	int  g_advPick[3] = { -1, -1, -1 }; // 每题选了什么（0..3 = A..D，-1 = 没选）
	int  g_advWrongMask = 0;           // 上次提交时哪几题错（bit i 置 1）
	bool g_advSubmitted = false;       // 提交过至少一次
	int  g_advAttempts = 0;            // 提交次数（诊断用）

	// ================================================================
	// 编辑状态（v78）
	// ================================================================
	HWND g_advEdit = nullptr;          // 原生 EDIT 子控件（中文输入必须靠它）
	int  g_advSelected = -1;           // 规则表里选中的序号（-1 = 没选）
	int  g_advHoverChip = -1;          // 悬停的模板按钮
	int  g_advPressedChip = -1;        // 按下的模板按钮
	std::wstring g_advStatus;          // 编辑区下方那行状态（保存/载入结果）
	WCHAR g_advPath[MAX_PATH] = L"";   // 规则文件路径（解析一次后缓存）

	// ★ v78：**仅预览模式**用的规则文件路径重定向（空 = 不重定向）。
	//
	//   只有 `RunPreview`（`--gui-preview`）会填它，生产路径永远是空的 ——
	//   所以引擎读的、界面写的仍然是 `rules_file.h` 解析出来的那**同一个**
	//   真实路径（铁律 195 没有被破坏）。
	//
	//   为什么需要它：自动核对要的是**确定性**。不重定向的话，探针读到的
	//   规则条数取决于这台机器上 `%ProgramData%\R3 Shield Core\` 里
	//   有没有那个文件、里面有几条 —— 于是"规则=3"这条判据在别人机器上
	//   会随机红，而真正要验证的（页面画出来没有）反而被淹没。
	//   顺带一个好处：自动核对**完全不碰**用户的真实规则文件。
	WCHAR g_previewRulesPath[MAX_PATH] = L"";

	// ---------------- 按钮 ----------------
	//
	// ★ 一次把**所有**按钮列出来，再按界面状态决定"这一屏显示哪几个" ——
	//   不这么做的话，"按钮位置"会在三个状态里各写一份布局（铁律 127）。
	enum AdvButton
	{
		AdvButtonNone = -1,
		AdvButtonQuizSubmit = 0,   // ① 提交答案
		AdvButtonQuizReset = 1,    // ① 清空作答
		AdvButtonWhyDone = 2,      // ② 开始编辑
		AdvButtonApply = 3,        // ③ 把编辑框内容加为新规则 / 更新选中那条
		AdvButtonDelete = 4,       // ③ 删除选中
		AdvButtonSave = 5,         // ③ 保存到规则文件
		AdvButtonLoad = 6,         // ③ 从规则文件载入
		AdvButtonSeed = 7,         // ③ 重置为示例规则
		AdvButtonClear = 8,        // ③ 清空规则表
		AdvButtonAll = 9,
	};

	// 当前状态该显示哪些按钮。
	bool AdvButtonVisible(int index)
	{
		if (!g_advQuizPassed) {
			return index == AdvButtonQuizSubmit || index == AdvButtonQuizReset;
		}
		if (!g_advWhyDismissed) {
			return index == AdvButtonWhyDone;
		}
		return index == AdvButtonApply || index == AdvButtonDelete
			|| index == AdvButtonSave || index == AdvButtonLoad
			|| index == AdvButtonSeed || index == AdvButtonClear;
	}

	PCWSTR AdvButtonLabel(int index)
	{
		switch (index) {
		case AdvButtonQuizSubmit: return L"提交答案";
		case AdvButtonQuizReset:  return L"清空作答";
		case AdvButtonWhyDone:    return L"开始编辑规则";
		case AdvButtonApply:      return L"加入 / 更新规则";
		case AdvButtonDelete:     return L"删除选中";
		case AdvButtonSave:       return L"保存到规则文件";
		case AdvButtonLoad:       return L"从规则文件载入";
		case AdvButtonSeed:       return L"重置为示例规则";
		case AdvButtonClear:      return L"清空规则表";
		default: return L"";
		}
	}

	// ---------------- 模板（结构化点选搭骨架） ----------------
	//
	// ★ 点「面」＝插入一整条骨架；点「算子」「动作」＝在光标处插入该词。
	//   骨架用**中文 DSL 原文**（不是直接拼 Rule 结构体）—— 必须走用户手敲
	//   那条**同一条解析路径**（铁律 22）。
	PCWSTR kAdvFaceChips[3] = {
		L"当 注册表值 的 值名 含 \"\" 时 替换为 \"\"",
		L"当 注册表枚举 的 子键名 含 \"\" 时 隐藏",
		L"当 剪贴板 的 格式 等于 文本 时 替换为 \"\"",
	};
	PCWSTR kAdvFaceChipLabel[3] = { L"注册表值", L"注册表枚举", L"剪贴板" };

	PCWSTR kAdvOpChips[5] = { L"等于", L"含", L"匹配 /正则/", L"开头", L"结尾" };
	PCWSTR kAdvOpChipText[5] = { L"等于", L"含", L"匹配 //", L"开头", L"结尾" };

	PCWSTR kAdvActChips[6] = { L"替换为 \"\"", L"替换为 空", L"替换为 全零",
		L"隐藏", L"拒绝", L"放行" };

	constexpr int kAdvChipRowA = 3;    // 面
	constexpr int kAdvChipRowB = 5;    // 算子
	constexpr int kAdvChipRowC = 6;    // 动作
	constexpr int kAdvChipCount = kAdvChipRowA + kAdvChipRowB + kAdvChipRowC;

	PCWSTR AdvChipLabel(int index)
	{
		if (index < kAdvChipRowA) {
			return kAdvFaceChipLabel[index];
		}
		index -= kAdvChipRowA;
		if (index < kAdvChipRowB) {
			return kAdvOpChips[index];
		}
		return kAdvActChips[index - kAdvChipRowB];
	}

	// 芯片宽度：首次调用测一次，之后查表。
	//
	// ★ 为什么不在布局函数里测：布局函数会被**命中测试**调用（没有 DC），
	//   在那里量文字要么传 DC 要么再建一个 —— 两条路都会让"画"和"点"
	//   用上不同的宽度。缓存一次，两边读同一张表。
	int AdvChipWidth(int index)
	{
		static int widths[kAdvChipCount] = {};
		static bool ready = false;
		if (!ready) {
			HDC dc = GetDC(nullptr);
			HGDIOBJ old = SelectObject(dc, g_labelFont);
			for (int i = 0; i < kAdvChipCount; i++) {
				RECT r = { 0, 0, 0, 0 };
				DrawTextW(dc, AdvChipLabel(i), -1, &r, DT_CALCRECT | DT_SINGLELINE);
				widths[i] = (r.right - r.left) + 20;   // 左右各 10px 内边距
				if (widths[i] < 52) {
					widths[i] = 52;
				}
			}
			SelectObject(dc, old);
			ReleaseDC(nullptr, dc);
			ready = true;
		}
		return widths[index];
	}

	// ---------------- 布局（绘制与命中共用一份，避免"画在这儿点在那儿"） ----------------
	constexpr int AdvButtonHeight = 28;
	constexpr int AdvButtonWidth = 140;
	constexpr int AdvLineHeight = 21;
	constexpr int AdvMaxHexBytes = 16;   // 每行最多显示多少字节（超了打 "..."）
	constexpr int AdvTableRowHeight = 19;
	constexpr int AdvChipHeight = 22;
	constexpr int AdvChipGap = 4;
	constexpr int AdvEditHeight = 26;

	struct AdvLayout
	{
		int Left = 0, Right = 0;
		int SummaryTop = 0;
		// ★ 摘要行下面那一行说明（"编辑区已锁定…" / "全对 —— 闸门打开…"）。
		//   单独一个字段而不是"PanelTop - 22"：那样写的话，一旦有人调
		//   PanelTop 的偏移，说明行会**无声地叠到摘要行上** ——
		//   自绘界面里两张文字叠在一起没有任何报错，只有截图看得出来
		//   （实测过一次：两行字糊成一团）。
		int NoteTop = 0;
		int PanelTop = 0, PanelBottom = 0;
		int RulesLeft = 0, RulesRight = 0;
		int DiffLeft = 0, DiffRight = 0;
		int ButtonTop = 0;
		RECT Buttons[AdvButtonAll] = {};

		// 编辑区（只在"已解锁"状态用得上）
		int TableTop = 0, TableBottom = 0;
		int ChipTop = 0;
		RECT ChipRow[3][6] = {};
		int EditTop = 0, EditBottom = 0;
		int StatusTop = 0;

		// 闸门（只在"未过 / 刚全对"状态用得上）
		int QuizColTop = 0, QuizColWidth = 0;
		int QuizOptTop = 0;
	};

	AdvLayout AdvLayoutFor(const RECT& client)
	{
		AdvLayout layout = {};
		layout.Left = Padding;
		layout.Right = client.right - Padding;
		layout.SummaryTop = TabBarTop + TabBarHeight + 12;
		// 摘要行 22px + 说明行 18px + 间距 ⇒ 面板从摘要行下方 46px 起。
		// 之前是 26px，导致说明行（画在 PanelTop-22）正好压在摘要行上。
		layout.NoteTop = layout.SummaryTop + 24;
		layout.PanelTop = layout.NoteTop + 22;

		// 底部按钮条固定贴底（在询问统计栏之上）—— 与其它页同一套算法，
		// 窗口被拉矮时按钮不会跑到可视区外。
		layout.ButtonTop = client.bottom - PromptSummaryHeight() - 12 - AdvButtonHeight;
		layout.PanelBottom = layout.ButtonTop - 34;   // 再往上留一行状态文字

		const int gap = 14;
		const int contentWidth = layout.Right - layout.Left - gap;
		const int rulesWidth = contentWidth * 52 / 100;
		layout.RulesLeft = layout.Left;
		layout.RulesRight = layout.Left + rulesWidth;
		layout.DiffLeft = layout.RulesRight + gap;
		layout.DiffRight = layout.Right;

		// 按钮：只给**当前状态该显示**的那些分配位置，从左往右排。
		int x = layout.Left;
		for (int i = 0; i < AdvButtonAll; i++) {
			if (!AdvButtonVisible(i)) {
				continue;
			}
			layout.Buttons[i] = { x, layout.ButtonTop, x + AdvButtonWidth,
				layout.ButtonTop + AdvButtonHeight };
			x += AdvButtonWidth + 8;
		}

		// ---- 编辑区（左栏内）----
		layout.TableTop = layout.PanelTop + 46;
		layout.TableBottom = layout.TableTop + 6 * AdvTableRowHeight + 4;
		layout.ChipTop = layout.TableBottom + 10;
		for (int row = 0; row < 3; row++) {
			const int count = (row == 0) ? kAdvChipRowA : (row == 1 ? kAdvChipRowB : kAdvChipRowC);
			int cx = layout.RulesLeft + 16;
			const int cy = layout.ChipTop + row * (AdvChipHeight + AdvChipGap);
			for (int i = 0; i < count; i++) {
				const int global = (row == 0) ? i
					: (row == 1 ? kAdvChipRowA + i : kAdvChipRowA + kAdvChipRowB + i);
				const int w = AdvChipWidth(global);
				layout.ChipRow[row][i] = { cx, cy, cx + w, cy + AdvChipHeight };
				cx += w + AdvChipGap;
			}
		}
		layout.EditTop = layout.ChipTop + 3 * (AdvChipHeight + AdvChipGap) + 8;
		layout.EditBottom = layout.EditTop + AdvEditHeight;
		layout.StatusTop = layout.EditBottom + 8;

		// ---- 闸门（整块内容区，三列）----
		layout.QuizColTop = layout.PanelTop + 40;
		const int quizGap = 12;
		layout.QuizColWidth = (layout.Right - layout.Left - quizGap * 2) / 3;
		layout.QuizOptTop = layout.QuizColTop + 26 + 96;   // 标题 + 题干框

		return layout;
	}

	// 闸门第 col 列第 opt 个选项的矩形（0..3 = A..D）。
	//
	// ★ 高度给 **48**（三行文字）而不是 22：选项原文里带着**对齐用的连续空格**
	//   （与控制台共用同一份文本，不能改），而这一页每列只有 ~300px 宽 ——
	//   一行放不下。22px + 单行 + `DT_END_ELLIPSIS` 会把括号里的关键部分
	//   截掉（实测截成 `A. STATUS_OBJECT_NAME_NOT_FOUND (0...`），
	//   而**被截掉的那半截往往正是区分对错的地方**。
	//   ⚠️ 高度是**定值**不是"按内容算"：命中测试要用同一个矩形，
	//      变高的行会让"画在这儿、点在那儿"。
	constexpr int AdvQuizOptHeight = 48;
	constexpr int AdvQuizOptStep = AdvQuizOptHeight + 4;

	RECT AdvQuizOptionRect(const AdvLayout& layout, int col, int opt)
	{
		const int left = layout.Left + col * (layout.QuizColWidth + 12);
		const int top = layout.QuizOptTop + opt * AdvQuizOptStep;
		return { left + 8, top, left + layout.QuizColWidth - 8, top + AdvQuizOptHeight };
	}

	int HitTestAdvButton(POINT point, const RECT& client)
	{
		if (g_activeTab != 5) {
			return AdvButtonNone;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		for (int i = 0; i < AdvButtonAll; i++) {
			if (!AdvButtonVisible(i)) {
				continue;
			}
			if (PtInRect(&layout.Buttons[i], point)) {
				return i;
			}
		}
		return AdvButtonNone;
	}

	int HitTestAdvChip(POINT point, const RECT& client)
	{
		if (g_activeTab != 5 || !g_advQuizPassed || !g_advWhyDismissed) {
			return -1;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		for (int row = 0; row < 3; row++) {
			const int count = (row == 0) ? kAdvChipRowA : (row == 1 ? kAdvChipRowB : kAdvChipRowC);
			for (int i = 0; i < count; i++) {
				if (PtInRect(&layout.ChipRow[row][i], point)) {
					return (row == 0) ? i
						: (row == 1 ? kAdvChipRowA + i : kAdvChipRowA + kAdvChipRowB + i);
				}
			}
		}
		return -1;
	}

	// 闸门选项的命中（未过闸门时才有效）。
	// 返回 列号（0..2）；`optOut` 收选项号（0..3）。没命中返回 -1。
	int HitTestAdvQuizOption(POINT point, const RECT& client, int* optOut)
	{
		if (g_activeTab != 5 || g_advQuizPassed) {
			return -1;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		for (int col = 0; col < R3ShieldCoreQuiz::Count(); col++) {
			for (int opt = 0; opt < 4; opt++) {
				RECT r = AdvQuizOptionRect(layout, col, opt);
				if (PtInRect(&r, point)) {
					if (optOut) {
						*optOut = opt;
					}
					return col;
				}
			}
		}
		return -1;
	}

	// 规则表某一行的命中（已解锁状态才有效）。
	//
	// ★ 行数上限必须与 `AdvDrawEditor` 里画的那 6 行**同一个数** ——
	//   画 6 行、这里判 8 行的话，点"第 7 行"（画面上是空白）会选中一条
	//   看不见的规则；反过来则是"看得见却点不中"。所以两边都读
	//   `AdvTableRowHeight` 与同一个 maxRows。
	int HitTestAdvTableRow(POINT point, const RECT& client)
	{
		if (g_activeTab != 5 || !g_advQuizPassed || !g_advWhyDismissed) {
			return -1;
		}
		const int total = RRule::Count();
		if (total <= 0) {
			return -1;
		}
		const int maxRows = 6;
		const int rows = (total < maxRows) ? total : maxRows;
		const AdvLayout layout = AdvLayoutFor(client);
		const int bottom = layout.TableTop + rows * AdvTableRowHeight;
		if (point.x < layout.RulesLeft + 8 || point.x > layout.RulesRight - 8) {
			return -1;
		}
		if (point.y < layout.TableTop || point.y >= bottom) {
			return -1;
		}
		return (point.y - layout.TableTop) / AdvTableRowHeight;
	}

	// ---------------- EDIT 子控件（v78） ----------------
	//
	// ★ 为什么非要用**原生** EDIT：这一页是纯自绘窗口（一个子控件都没有），
	//   而中文规则必须能敲中文 ⇒ 需要 **IME**。自绘 + 自己处理
	//   `WM_IME_*` 等于重写一个输入框，代价和风险都不划算。
	//
	// ★ 与双缓冲的冲突（铁律 181）：主窗口整块 `BitBlt` 会**盖掉**子控件。
	//   解法是给主窗口加 `WS_CLIPCHILDREN` —— 父窗口的绘制区里"子控件占的
	//   那块"被裁掉，`BitBlt` 就不会画到 EDIT 上。这是必须的前提，不是优化。
	//   ⚠️ 加了之后**父窗口不能再指望自己画子控件底下的像素** ⇒ EDIT 自己
	//      带 `WS_BORDER` 且用 `WM_CTLCOLOREDIT` 给它白底（见 WndProc）。
	//
	// ★ 位置只在 `AdvLayoutFor` 里算一次（铁律 182：坐标只在创建点出现一次
	//   的控件 = 定时炸弹）。本函数只负责"把算出来的位置应用上去"。
	void AdvCreateEdit(HWND parent)
	{
		if (g_advEdit) {
			return;
		}
		g_advEdit = CreateWindowExW(
			0, L"EDIT", L"",
			WS_CHILD | ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
			0, 0, 10, 10, parent, nullptr, g_instance, nullptr);
		if (g_advEdit && g_monoFont) {
			SendMessageW(g_advEdit, WM_SETFONT,
				reinterpret_cast<WPARAM>(g_monoFont), TRUE);
		}
	}

	// 「编辑框这一刻该不该显示」—— **唯一一处**判据。
	//
	// ★ 为什么要抽出来：这个条件有两个读者 —— `AdvSyncEdit`（真的去
	//   ShowWindow/SW_HIDE）和 `DrawAdvancedPage` 的核对日志（报给探针看）。
	//   写两遍必然漂（铁律 127）：漂了之后日志说"编辑框=1"、屏幕上却没有，
	//   于是探针判据变成**恒真**，而它本来是"编辑台画出来了"的唯一证据。
	bool AdvEditShouldShow()
	{
		return g_advEdit != nullptr
			&& g_activeTab == 5
			&& g_advQuizPassed
			&& g_advWhyDismissed;
	}

	// 编辑框左边留给「规则行」标签的宽度。
	//
	// ★ 为什么要有这一段：原生 EDIT 会**盖住**它底下的像素（父窗口加了
	//   `WS_CLIPCHILDREN`，父窗口画的东西进不到控件区域里）。所以标签不能
	//   和编辑框重叠 —— 重叠的表现是"标签根本没画"，而代码里明明有那一句
	//   `DrawTextSimple`，读代码永远查不出来（实测：截图里找不到"规则行"）。
	constexpr int AdvEditLabelWidth = 56;

	void AdvSyncEdit(HWND hwnd, const RECT& client)
	{
		if (!g_advEdit) {
			return;
		}
		if (!AdvEditShouldShow()) {
			if (IsWindowVisible(g_advEdit)) {
				ShowWindow(g_advEdit, SW_HIDE);
			}
			return;
		}

		const AdvLayout layout = AdvLayoutFor(client);
		const int editLeft = layout.RulesLeft + 16 + AdvEditLabelWidth;
		const int w = layout.RulesRight - 16 - editLeft;
		const int h = layout.EditBottom - layout.EditTop;
		if (w <= 0 || h <= 0) {
			return;
		}

		RECT want = { editLeft, layout.EditTop, editLeft + w, layout.EditTop + h };
		RECT have = {};
		GetWindowRect(g_advEdit, &have);
		MapWindowPoints(nullptr, hwnd, reinterpret_cast<POINT*>(&have), 2);

		if (!IsWindowVisible(g_advEdit)
			|| have.left != want.left || have.top != want.top
			|| (have.right - have.left) != w || (have.bottom - have.top) != h) {
			SetWindowPos(g_advEdit, nullptr, want.left, want.top, w, h,
				SWP_NOZORDER | SWP_NOACTIVATE);
			ShowWindow(g_advEdit, SW_SHOWNA);
		}
	}

	// 取编辑框内容（没控件时返回空串）。
	std::wstring AdvEditText()
	{
		if (!g_advEdit) {
			return L"";
		}
		const int len = GetWindowTextLengthW(g_advEdit);
		if (len <= 0) {
			return L"";
		}
		std::wstring s(static_cast<size_t>(len) + 1, L'\0');
		GetWindowTextW(g_advEdit, &s[0], len + 1);
		s.resize(static_cast<size_t>(len));
		return s;
	}

	void AdvSetEditText(const std::wstring& text)
	{
		if (g_advEdit) {
			SetWindowTextW(g_advEdit, text.c_str());
		}
	}

	// 在光标处插入一段文本（模板按钮用）。
	void AdvInsertEditText(const std::wstring& insert)
	{
		if (!g_advEdit) {
			return;
		}
		SendMessageW(g_advEdit, EM_REPLACESEL, TRUE,
			reinterpret_cast<LPARAM>(insert.c_str()));
		SetFocus(g_advEdit);
	}

	// ---------------- 示例规则 ----------------
	//
	// ★ 三条覆盖三个面 × 三种动作：
	//   #0 注册表值  ：正则匹配 -> 替换为文本（真会写进数据区）
	//   #1 剪贴板    ：等于    -> 替换为文本
	//   #2 注册表枚举：含      -> 隐藏（从列表里去掉）
	PCWSTR kAdvDemoRules[] = {
		L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"",
		L"当 剪贴板 的 格式 等于 文本 时 替换为 \"[已替换]\"",
		L"当 注册表枚举 的 子键名 含 \"Secret\" 时 隐藏",
	};

	void AdvLoadDemoRules()
	{
		RRule::Clear();
		for (PCWSTR line : kAdvDemoRules) {
			std::wstring err;
			RRule::Add(line, err, nullptr);
		}
		g_advSelected = -1;
	}

	// 规则文件的路径（解析一次后缓存）。
	const WCHAR* AdvRulesPath()
	{
		if (g_advPath[0] == L'\0') {
			// 预览模式的重定向优先（生产路径下 `g_previewRulesPath` 恒为空，
			// 见它的声明处 —— 这不是"另一条路径解析"，只是一个测试替身）。
			if (g_previewRulesPath[0] != L'\0') {
				wcsncpy_s(g_advPath, g_previewRulesPath, _TRUNCATE);
				return g_advPath;
			}
			if (!R3ShieldCoreRulesFile::ResolveRulesPath(nullptr, g_advPath, _countof(g_advPath))) {
				wcsncpy_s(g_advPath, L"(解析规则文件路径失败)", _TRUNCATE);
			}
		}
		return g_advPath;
	}

	// 首次进这一页：先试着从规则文件读；读不到再铺示例规则。
	//
	// ★ 顺序很重要：直接铺示例会把用户存过的规则**顶掉**（他下次一看
	//   "我写的规则没了"）。先读文件才是对的。
	// ★ 读不到也要**说清楚**（不能静默铺示例 —— 那与"用户存过但读失败"
	//   长得一模一样，铁律 97）。
	void AdvInitialLoad()
	{
		int ok = 0;
		int bad = 0;
		std::wstring firstErr;
		const WCHAR* path = AdvRulesPath();
		// ★ 来源要**显式打出来**：`来源=文件` / `来源=示例`。
		//   只打条数的话，"从文件读到 3 条"和"文件没有、铺了 3 条示例"
		//   在日志里长得一模一样 —— 而这两件事的后续行为完全不同
		//   （前者用户点「保存」会覆盖他自己的规则，后者是新建）。
		const WCHAR* source = L"示例";
		if (RRule::LoadFile(path, &ok, &bad, firstErr)) {
			source = L"文件";
			WCHAR buf[512] = {};
			swprintf_s(buf, L"已从规则文件载入 %d 条（无效 %d 条）：%s", ok, bad, path);
			g_advStatus = buf;
		}
		else {
			AdvLoadDemoRules();
			WCHAR buf[512] = {};
			swprintf_s(buf, L"还没有规则文件，已铺 3 条示例（保存后写入 %s）", path);
			g_advStatus = buf;
		}
		printf("[adv] 初始规则=%d 来源=%ls 路径=%ls\n", RRule::Count(), source, path);
		fflush(stdout);
	}

	// ---------------- 动作 ----------------
	void AdvQuizSubmit()
	{
		g_advSubmitted = true;
		g_advAttempts++;
		int wrongMask = 0;
		int wrong = 0;
		const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();
		for (int i = 0; i < R3ShieldCoreQuiz::Count(); i++) {
			const bool ok = (g_advPick[i] >= 0)
				&& (static_cast<WCHAR>(L'A' + g_advPick[i]) == q[i].answer);
			if (!ok) {
				wrongMask |= (1 << i);
				wrong++;
			}
		}
		g_advWrongMask = wrongMask;

		if (wrong == 0) {
			g_advQuizPassed = true;
			g_advWhyDismissed = false;
		}
		// ★ 只报"哪几题错"，**不报答案** —— 报了答案这道闸门就白设了。
		printf("[adv] 闸门提交 第%d次 错%d题 通过=%d\n", g_advAttempts, wrong,
			g_advQuizPassed ? 1 : 0);
		fflush(stdout);
	}

	void AdvQuizReset()
	{
		g_advPick[0] = g_advPick[1] = g_advPick[2] = -1;
		g_advWrongMask = 0;
		g_advSubmitted = false;
	}

	// 把编辑框里那行加入规则表（选中了就是**更新**）。
	void AdvApplyRule()
	{
		const std::wstring line = AdvEditText();
		if (line.empty()) {
			g_advStatus = L"编辑框是空的 —— 先点上面的模板按钮搭一条骨架。";
			return;
		}
		if (g_advSelected >= 0 && g_advSelected < RRule::Count()) {
			if (!RRule::RemoveAt(g_advSelected)) {
				g_advStatus = L"更新失败：选中的规则已经不在表里了。";
				return;
			}
		}
		std::wstring err;
		int index = -1;
		if (!RRule::Add(line.c_str(), err, &index)) {
			g_advStatus = L"这一行解析不了：" + err;
			return;
		}
		g_advSelected = index;
		WCHAR buf[256] = {};
		swprintf_s(buf, L"已写入第 %d 条规则（共 %d 条）。记得点「保存到规则文件」。",
			index, RRule::Count());
		g_advStatus = buf;
	}

	void AdvDeleteSelected()
	{
		if (g_advSelected < 0 || g_advSelected >= RRule::Count()) {
			g_advStatus = L"先在左边规则表里点一行。";
			return;
		}
		const int removed = g_advSelected;
		RRule::RemoveAt(removed);
		g_advSelected = -1;
		AdvSetEditText(L"");
		WCHAR buf[160] = {};
		swprintf_s(buf, L"已删除第 %d 条（还剩 %d 条）。", removed, RRule::Count());
		g_advStatus = buf;
	}

	void AdvSaveRules()
	{
		const WCHAR* path = AdvRulesPath();
		R3ShieldCoreRulesFile::EnsureParentDirectory(path);
		int count = 0;
		if (!RRule::SaveFile(path, &count)) {
			g_advStatus = std::wstring(L"保存失败（写不进去）：") + path;
			return;
		}
		WCHAR buf[600] = {};
		swprintf_s(buf, L"已保存 %d 条到 %s —— 引擎在**下次启动**时读取（每个被注入进程各读一次）。",
			count, path);
		g_advStatus = buf;
		printf("[adv] 已保存规则 %d 条 路径=%ls\n", count, path);
		fflush(stdout);
	}

	void AdvLoadRules()
	{
		const WCHAR* path = AdvRulesPath();
		int ok = 0;
		int bad = 0;
		std::wstring firstErr;
		if (!RRule::LoadFile(path, &ok, &bad, firstErr)) {
			g_advStatus = std::wstring(L"载入失败（文件打不开）：") + path;
			return;
		}
		g_advSelected = -1;
		AdvSetEditText(L"");
		WCHAR buf[600] = {};
		if (bad > 0) {
			swprintf_s(buf, L"已载入 %d 条（**%d 条解析失败**，第一条：%s）", ok, bad, firstErr.c_str());
		}
		else {
			swprintf_s(buf, L"已载入 %d 条（全部解析成功）：%s", ok, path);
		}
		g_advStatus = buf;
	}

	void PerformAdvAction(int index)
	{
		switch (index) {
		case AdvButtonQuizSubmit: AdvQuizSubmit(); break;
		case AdvButtonQuizReset:  AdvQuizReset(); break;
		case AdvButtonWhyDone:    g_advWhyDismissed = true; break;
		case AdvButtonApply:      AdvApplyRule(); break;
		case AdvButtonDelete:     AdvDeleteSelected(); break;
		case AdvButtonSave:       AdvSaveRules(); break;
		case AdvButtonLoad:       AdvLoadRules(); break;
		case AdvButtonSeed:
			AdvLoadDemoRules();
			g_advStatus = L"已重置为 3 条示例规则。";
			break;
		case AdvButtonClear:
			RRule::Clear();
			g_advSelected = -1;
			AdvSetEditText(L"");
			g_advStatus = L"规则表已清空（文件里的没动 —— 要清文件得点「保存到规则文件」）。";
			break;
		default: break;
		}
		printf("[adv] 动作 #%d 规则=%d\n", index, RRule::Count());
		fflush(stdout);
	}

	// 点规则表某一行：载入编辑框。
	void AdvSelectRule(int index)
	{
		if (index < 0 || index >= RRule::Count()) {
			return;
		}
		g_advSelected = index;
		std::wstring desc;
		if (RRule::DescribeAt(index, desc)) {
			AdvSetEditText(desc);
		}
		if (g_advEdit) {
			SetFocus(g_advEdit);
		}
	}

	// 点模板按钮。
	void AdvClickChip(int index)
	{
		if (index < 0 || index >= kAdvChipCount) {
			return;
		}
		if (index < kAdvChipRowA) {
			// 「面」= 整条骨架（替换掉编辑框内容 —— 骨架是"起手式"，
			// 追加会越积越长，反而更难改）。
			AdvSetEditText(kAdvFaceChips[index]);
		}
		else if (index < kAdvChipRowA + kAdvChipRowB) {
			AdvInsertEditText(kAdvOpChipText[index - kAdvChipRowA]);
		}
		else {
			AdvInsertEditText(kAdvActChips[index - kAdvChipRowA - kAdvChipRowB]);
		}
		if (g_advEdit) {
			SetFocus(g_advEdit);
		}
	}

	// ---------------- 显示辅助 ----------------
	std::wstring AdvHex(const BYTE* data, size_t length)
	{
		if (!data || length == 0) {
			return L"(空)";
		}
		std::wstring out;
		WCHAR cell[8] = {};
		const size_t n = (length < AdvMaxHexBytes) ? length : AdvMaxHexBytes;
		for (size_t i = 0; i < n; i++) {
			swprintf_s(cell, L"%02X ", data[i]);
			out += cell;
		}
		if (n < length) {
			out += L"...";
		}
		return out;
	}

	// 判定 -> 一句话。复用规则引擎自己的 Describe，别在这里再拼一遍语法
	// （拼两遍必然与解析器漂移 —— 那正是 v74 收敛 Action 枚举要防的事）。
	std::wstring AdvVerdictText(const RRule::Verdict& v)
	{
		if (!v.hit) {
			return L"未命中规则 · 回落内置默认行为";
		}
		std::wstring desc;
		if (!RRule::DescribeAt(v.index, desc)) {
			return L"命中规则";
		}
		WCHAR head[32] = {};
		swprintf_s(head, L"命中 #%d · ", v.index);
		return std::wstring(head) + desc;
	}

	// 造一个"真实剪贴板文本"（UTF-16 带结尾 NUL）—— 只为喂给**生产**
	// `RClip::BuildFake`，让"回落"那一格走的是真生产路径而不是模仿。
	HGLOBAL AdvBuildRealUnicodeText(const WCHAR* text)
	{
		const size_t chars = text ? wcslen(text) : 0;
		HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,
			(chars + 1) * sizeof(WCHAR));
		if (!h) {
			return nullptr;
		}
		void* p = GlobalLock(h);
		if (!p) {
			GlobalFree(h);
			return nullptr;
		}
		if (chars) {
			memcpy(p, text, chars * sizeof(WCHAR));
		}
		GlobalUnlock(h);
		return h;
	}

	void AdvDrawButton(HDC dc, const RECT& rect, PCWSTR label, bool hovered, bool pressed)
	{
		COLORREF fill = ColorHeaderBackground;
		COLORREF border = ColorBorder;
		COLORREF text = ColorTextPrimary;
		if (pressed) {
			fill = RGB(200, 222, 244);
			border = ColorAccent;
			text = ColorAccent;
		}
		else if (hovered) {
			fill = ColorTabHoverBg;
			border = ColorTabHoverBorder;
			text = ColorAccent;
		}

		HBRUSH brush = CreateSolidBrush(fill);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 6, 6);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

		DrawTextSimple(dc, label, rect, g_labelFont, text,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	// 模板按钮（比普通按钮矮、圆角小）。
	void AdvDrawChip(HDC dc, const RECT& rect, PCWSTR label, bool hovered)
	{
		COLORREF fill = ColorTabHoverBg;
		COLORREF border = ColorTabHoverBorder;
		if (hovered) {
			fill = RGB(214, 232, 250);
			border = ColorAccent;
		}
		HBRUSH brush = CreateSolidBrush(fill);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 5, 5);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);
		DrawTextSimple(dc, label, rect, g_labelFont, ColorAccent,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// 一行「标签 : 值」
	void AdvRow(HDC dc, int left, int right, int y, PCWSTR label,
		const std::wstring& value, COLORREF color)
	{
		DrawTextSimple(dc, label, { left, y, left + 48, y + 18 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, value.c_str(), { left + 48, y, right, y + 18 },
			g_monoFont, color, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// 把开关状态画成一行（"总闸"）—— 用户"写了规则没生效"时第一个要看的东西。
	void AdvDrawGates(HDC dc, int left, int right, int y)
	{
		WCHAR buf[256] = {};
		swprintf_s(buf, L"总闸（ini）：spoof_reg=%s  spoof_clipboard=%s  spoof_reg_enum=%s",
			g_options.SpoofReg ? L"开" : L"关",
			g_options.SpoofClipboard ? L"开" : L"关",
			g_options.SpoofRegEnum ? L"开" : L"关");
		const bool anyOn = g_options.SpoofReg || g_options.SpoofClipboard
			|| g_options.SpoofRegEnum;
		DrawTextSimple(dc, buf, { left, y, right, y + 18 },
			g_labelFont, anyOn ? ColorTextPrimary : ColorBlocked,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// 把连续空格折成一个、并去掉首尾空格。
	//
	// ★ 只用于**显示**：闸门题的选项原文为了在控制台里对齐括号，塞了一串
	//   空格；在这一页 ~300px 宽的列里那串空格会把文字挤出可视高度。
	//   折叠是"换一种排法"，不改共享文本（`advanced_quiz.h` 一字不动）。
	//   折叠之后 `A. STATUS_INVALID_HANDLE (0xC0000008)` 这种刚好两行。
	std::wstring AdvCollapseSpaces(const WCHAR* s)
	{
		std::wstring out;
		if (!s) {
			return out;
		}
		bool prevSpace = false;
		for (const WCHAR* p = s; *p; ++p) {
			const bool isSpace = (*p == L' ' || *p == L'\t');
			if (isSpace) {
				if (!prevSpace && !out.empty()) {
					out.push_back(L' ');
				}
				prevSpace = true;
			}
			else {
				out.push_back(*p);
				prevSpace = false;
			}
		}
		while (!out.empty() && out.back() == L' ') {
			out.pop_back();
		}
		return out;
	}

	// ---------------- 闸门：未通过 ----------------
	void AdvDrawQuiz(HDC dc, const AdvLayout& layout)
	{
		const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();

		// 顶部一句说明（"为什么锁着"）。
		DrawTextSimple(dc,
			L"编辑区已锁定 —— 答对下面三道 Win32 题解锁（题目都是这个项目真踩过的坑，全对才开门）。",
			{ layout.Left, layout.NoteTop, layout.Right, layout.NoteTop + 18 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		for (int col = 0; col < R3ShieldCoreQuiz::Count(); col++) {
			const int left = layout.Left + col * (layout.QuizColWidth + 12);
			const int right = left + layout.QuizColWidth;
			RECT panel = { left, layout.PanelTop, right, layout.PanelBottom };
			DrawPanel(dc, panel, L"");

			WCHAR title[32] = {};
			swprintf_s(title, L"第 %d 题", col + 1);
			DrawTextSimple(dc, title, { left + 10, layout.QuizColTop, right - 10, layout.QuizColTop + 20 },
				g_labelFont, ColorAccent, DT_LEFT | DT_SINGLELINE);

			// 题干（原样，含换行 —— 与控制台**同一份**文本）。
			DrawTextSimple(dc, q[col].text,
				{ left + 10, layout.QuizColTop + 22, right - 10, layout.QuizColTop + 22 + 92 },
				g_labelFont, ColorTextPrimary, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS);

			for (int opt = 0; opt < 4; opt++) {
				const RECT r = AdvQuizOptionRect(layout, col, opt);
				const bool picked = (g_advPick[col] == opt);
				const bool wrong = g_advSubmitted && (g_advWrongMask & (1 << col))
					&& (g_advPick[col] == opt);

				COLORREF fill = picked ? ColorTabHoverBg : ColorHeaderBackground;
				COLORREF border = picked ? ColorAccent : ColorBorder;
				if (wrong) {
					fill = RGB(253, 233, 233);
					border = ColorBlocked;
				}
				HBRUSH brush = CreateSolidBrush(fill);
				HPEN pen = CreatePen(PS_SOLID, 1, border);
				HGDIOBJ ob = SelectObject(dc, brush);
				HGDIOBJ op = SelectObject(dc, pen);
				RoundRect(dc, r.left, r.top, r.right, r.bottom, 4, 4);
				SelectObject(dc, ob);
				SelectObject(dc, op);
				DeleteObject(brush);
				DeleteObject(pen);

				WCHAR line[512] = {};
				swprintf_s(line, L"%lc. %ls", static_cast<WCHAR>(L'A' + opt), q[col].opt[opt]);
				// ★ 三行 + 自动换行 + **折叠连续空格**，不要 `DT_END_ELLIPSIS`：
				//   选项原文里带对齐用的连续空格（为了在**控制台**里把括号对齐），
				//   在这一页 ~300px 宽的列里那串空格会把文字挤到第三行之外，
				//   省略号再把括号里的状态码截掉 —— 而那半截往往正是区分对错的地方。
				//   折叠只影响**显示**，不动共享的题目文本（铁律 195）。
				DrawTextSimple(dc, AdvCollapseSpaces(line).c_str(),
					{ r.left + 8, r.top + 3, r.right - 6, r.bottom - 3 },
					g_labelFont, wrong ? ColorBlocked : ColorTextPrimary,
					DT_LEFT | DT_TOP | DT_WORDBREAK);
			}

			// 这一列的结果（只报对错，不报答案）。
			if (g_advSubmitted) {
				const bool ok = (g_advWrongMask & (1 << col)) == 0;
				const int resultTop = layout.QuizOptTop + 4 * AdvQuizOptStep + 2;
				DrawTextSimple(dc, ok ? L"这一题：对" : L"这一题：错（可重选）",
					{ left + 10, resultTop, right - 10, resultTop + 18 },
					g_labelFont, ok ? ColorAccent : ColorBlocked,
					DT_LEFT | DT_SINGLELINE);
			}
		}

		// 底部状态行（"错了几题"）。
		std::wstring status;
		if (!g_advSubmitted) {
			status = L"三道题都选好之后点「提交答案」。";
		}
		else if (g_advQuizPassed) {
			status = L"全对 —— 闸门打开。";
		}
		else {
			int wrong = 0;
			for (int i = 0; i < 3; i++) {
				if (g_advWrongMask & (1 << i)) {
					wrong++;
				}
			}
			WCHAR buf[160] = {};
			swprintf_s(buf, L"错 %d 题（红色那几题），改完再提交。", wrong);
			status = buf;
		}
		DrawTextSimple(dc, status.c_str(),
			{ layout.Left, layout.ButtonTop - 26, layout.Right, layout.ButtonTop - 6 },
			g_labelFont, g_advQuizPassed ? ColorAccent : ColorTextSecondary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// ---------------- 闸门：刚全对，展示解析 ----------------
	void AdvDrawWhy(HDC dc, const AdvLayout& layout)
	{
		const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();

		DrawTextSimple(dc, L"全对 —— 闸门打开。下面把三道题的答案讲清楚（看懂了再点「开始编辑规则」）。",
			{ layout.Left, layout.NoteTop, layout.Right, layout.NoteTop + 18 },
			g_labelFont, ColorAccent, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		for (int col = 0; col < R3ShieldCoreQuiz::Count(); col++) {
			const int left = layout.Left + col * (layout.QuizColWidth + 12);
			const int right = left + layout.QuizColWidth;
			DrawPanel(dc, { left, layout.PanelTop, right, layout.PanelBottom }, L"");

			WCHAR title[64] = {};
			swprintf_s(title, L"第 %d 题 · 正确答案 %lc", col + 1, q[col].answer);
			DrawTextSimple(dc, title,
				{ left + 10, layout.QuizColTop, right - 10, layout.QuizColTop + 20 },
				g_labelFont, ColorAccent, DT_LEFT | DT_SINGLELINE);

			DrawTextSimple(dc, q[col].why,
				{ left + 10, layout.QuizColTop + 26, right - 10, layout.PanelBottom - 10 },
				g_labelFont, ColorTextPrimary, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS);
		}
	}

	// ---------------- 已解锁：规则表 + 编辑区（左） ----------------
	void AdvDrawEditor(HDC dc, const AdvLayout& layout)
	{
		RECT rulesPanel = { layout.RulesLeft, layout.PanelTop, layout.RulesRight, layout.PanelBottom };
		DrawPanel(dc, rulesPanel, L"规则表（点一行载入编辑框）");

		std::vector<std::wstring> all;
		RRule::ListAll(all);

		int y = layout.TableTop;
		if (all.empty()) {
			DrawTextSimple(dc, L"（还没有规则 —— 点下面的模板按钮搭一条，或「重置为示例规则」）",
				{ rulesPanel.left + 16, y, rulesPanel.right - 16, y + 20 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
		else {
			const int maxRows = 6;
			for (size_t i = 0; i < all.size() && static_cast<int>(i) < maxRows; i++) {
				const bool selected = (static_cast<int>(i) == g_advSelected);
				if (selected) {
					RECT hl = { rulesPanel.left + 8, y - 1, rulesPanel.right - 8, y + AdvTableRowHeight - 1 };
					HBRUSH b = CreateSolidBrush(ColorTabHoverBg);
					FillRect(dc, &hl, b);
					DeleteObject(b);
				}
				WCHAR index[16] = {};
				swprintf_s(index, L"#%u", static_cast<unsigned>(i));
				DrawTextSimple(dc, index, { rulesPanel.left + 16, y, rulesPanel.left + 46, y + 17 },
					g_monoFont, ColorAccent, DT_LEFT | DT_SINGLELINE);
				DrawTextSimple(dc, all[i].c_str(),
					{ rulesPanel.left + 50, y, rulesPanel.right - 16, y + 17 },
					g_monoFont, ColorTextPrimary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
				y += AdvTableRowHeight;
			}
			if (static_cast<int>(all.size()) > 6) {
				WCHAR more[64] = {};
				swprintf_s(more, L"… 还有 %d 条（编辑区仍然能改它们）",
					static_cast<int>(all.size()) - 6);
				DrawTextSimple(dc, more, { rulesPanel.left + 16, y, rulesPanel.right - 16, y + 17 },
					g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE);
			}
		}

		// 模板按钮（三行）。
		for (int row = 0; row < 3; row++) {
			const int count = (row == 0) ? kAdvChipRowA : (row == 1 ? kAdvChipRowB : kAdvChipRowC);
			for (int i = 0; i < count; i++) {
				const int global = (row == 0) ? i
					: (row == 1 ? kAdvChipRowA + i : kAdvChipRowA + kAdvChipRowB + i);
				AdvDrawChip(dc, layout.ChipRow[row][i], AdvChipLabel(global),
					g_advHoverChip == global || g_advPressedChip == global);
			}
		}
		// 编辑框的框线由原生 EDIT 自己画（`WS_BORDER`）；这里只画个标签。
		// ⚠️ 宽度必须 ≤ `AdvEditLabelWidth` —— 超了就会被 EDIT 盖掉一截
		//   （EDIT 的左缘 = RulesLeft + 16 + AdvEditLabelWidth，见 AdvSyncEdit）。
		DrawTextSimple(dc, L"规则行",
			{ rulesPanel.left + 16, layout.EditTop,
			  rulesPanel.left + 16 + AdvEditLabelWidth - 8, layout.EditBottom },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		// ⚠️ 原生 EDIT 会盖住 [RulesLeft+16, RulesRight-16] 这一段 ——
		//   主窗口有 `WS_CLIPCHILDREN`，所以这里画的任何东西都不会渗进 EDIT 里。

		if (!g_advStatus.empty()) {
			DrawTextSimple(dc, g_advStatus.c_str(),
				{ rulesPanel.left + 16, layout.StatusTop, rulesPanel.right - 16, layout.StatusTop + 18 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		// 语法速查 + 规则文件路径 + 总闸。
		{
			const int sy = layout.PanelBottom - 76;
			DrawTextSimple(dc, L"语法：当 <面> [的 <字段>] <算子> <模式> 时 <动作>",
				{ rulesPanel.left + 16, sy, rulesPanel.right - 16, sy + 18 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			DrawTextSimple(dc, L"面 = 注册表值 / 注册表枚举 / 剪贴板；算子 = 等于 / 含 / 匹配(/正则/) / 开头 / 结尾",
				{ rulesPanel.left + 16, sy + 19, rulesPanel.right - 16, sy + 37 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			DrawTextSimple(dc, L"动作 = 替换为 \"文本\"|全零|全FF|空 · 隐藏 · 拒绝 · 放行",
				{ rulesPanel.left + 16, sy + 38, rulesPanel.right - 16, sy + 56 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			AdvDrawGates(dc, rulesPanel.left + 16, rulesPanel.right - 16, sy + 57);
		}
	}

	// ---------------- 已解锁：改前 / 改后 字节对照（右） ----------------
	void AdvDrawPreview(HDC dc, const AdvLayout& layout)
	{
		RECT diffPanel = { layout.DiffLeft, layout.PanelTop, layout.DiffRight, layout.PanelBottom };
		DrawPanel(dc, diffPanel, L"改前 / 改后 字节对照（生产同源 codec）");

		int dy = layout.PanelTop + 46;
		const int dleft = diffPanel.left + 16;
		const int dright = diffPanel.right - 16;

		// ---- 样例 1：注册表值（REG_SZ）----
		{
			const WCHAR* keyPath = L"HKEY_CURRENT_USER\\Software\\R3ShieldCoreDemo\\Vault";
			const WCHAR* valueName = L"Password";
			const WCHAR* secret = L"hunter2";

			// 合成一个 class 2 的 KEY_VALUE_PARTIAL_INFORMATION：
			//   +0 TitleIndex   +4 Type   +8 DataLength   +12 Data[]
			const size_t secretBytes = (wcslen(secret) + 1) * sizeof(WCHAR);
			BYTE buffer[12 + 64] = {};
			ULONG type = 1 /*REG_SZ*/;
			ULONG dataLength = static_cast<ULONG>(secretBytes);
			memcpy(buffer + 4, &type, sizeof(type));
			memcpy(buffer + 8, &dataLength, sizeof(dataLength));
			memcpy(buffer + 12, secret, secretBytes);
			const ULONG total = static_cast<ULONG>(12 + secretBytes);

			RSpoof::DataRegion region = {};
			const bool located = RSpoof::LocateDataRegion(2, buffer, sizeof(buffer), total, region);
			const size_t regionOffset = located ? region.offset : 12;
			const size_t regionLength = located ? region.length : secretBytes;

			BYTE before[64] = {};
			memcpy(before, buffer + regionOffset, regionLength);

			const RRule::Verdict v = RRule::Eval(RRule::Face::RegValue, keyPath, valueName, nullptr);
			const RApply::Effect effect = RApply::ApplyRegValue(v, v.hit, buffer,
				sizeof(buffer), regionOffset, regionLength, 0);

			DrawTextSimple(dc, L"① 注册表值 · Password（REG_SZ）",
				{ dleft, dy, dright, dy + 18 }, g_labelFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"判定", AdvVerdictText(v),
				v.hit ? ColorSpoofed : ColorTextSecondary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改前", AdvHex(before, regionLength), ColorTextPrimary);
			dy += AdvLineHeight;

			std::wstring afterText;
			COLORREF afterColor = ColorSpoofed;
			if (effect == RApply::Effect::Rejected) {
				afterText = L"（拒绝 —— 调用方拿到 STATUS_ACCESS_DENIED）";
				afterColor = ColorBlocked;
			}
			else if (effect == RApply::Effect::PassThrough) {
				afterText = AdvHex(before, regionLength) + L"   （规则要求放行，原样返回）";
				afterColor = ColorTextSecondary;
			}
			else {
				afterText = AdvHex(buffer + regionOffset, regionLength);
				afterText += L"   （";
				afterText += RApply::EffectName(effect);
				afterText += L"）";
			}
			AdvRow(dc, dleft, dright, dy, L"改后", afterText, afterColor);
			dy += AdvLineHeight + 10;
		}

		// ---- 样例 2：剪贴板（CF_UNICODETEXT）----
		{
			const UINT format = 13 /*CF_UNICODETEXT*/;
			const WCHAR* realText = L"账号=admin 口令=hunter2";
			const size_t realLength = (wcslen(realText) + 1) * sizeof(WCHAR);

			HGLOBAL real = AdvBuildRealUnicodeText(realText);
			const BYTE* realBytes = real
				? static_cast<const BYTE*>(GlobalLock(real)) : nullptr;

			// ★ 必须**先**把「改前」的字节抓成字符串，再解锁 / 释放。
			//   否则后面显示用的是已经还回去的内存（use-after-free）。
			//   实测症状很隐蔽：程序**不崩**，只是"改前"那一行变成两个指针值
			//   （`70 2D 61 E5 5B 02 00 00 ...`），而不是真实的 UTF-16 文本 ——
			//   自绘界面里没有任何东西会报错，只有截图能看出来。
			const std::wstring beforeHex = AdvHex(realBytes, realLength);

			WCHAR fmtBuffer[32] = {};
			const WCHAR* fmtLabel = RClip::FormatLabel(format, fmtBuffer, _countof(fmtBuffer));
			const RRule::Verdict v = RRule::Eval(RRule::Face::Clip, nullptr, nullptr, fmtLabel);

			HGLOBAL fake = nullptr;
			std::wstring afterText;
			COLORREF afterColor = ColorSpoofed;
			const WCHAR* afterWhat = L"";

			if (v.hit && v.act == RRule::Act::Block) {
				afterText = L"（拒绝 —— 调用方拿到 NULL + err=5）";
				afterColor = ColorBlocked;
			}
			else if (v.hit && v.act == RRule::Act::Pass) {
				afterText = beforeHex + L"   （规则要求放行，原样返回）";
				afterColor = ColorTextSecondary;
			}
			else if (v.hit) {
				const WCHAR* text = (v.act == RRule::Act::ReplaceText) ? v.text.c_str() : L"";
				fake = RApply::BuildClipText(format, text);
				afterWhat = (v.act == RRule::Act::ReplaceText)
					? L"写入了规则指定的文本" : L"内容变空串";
			}
			else {
				// ★ 回落 = **生产**路径：文本类 -> 空串（BuildEmptyText）
				fake = RClip::BuildFake(format, real);
				afterWhat = L"生产回落：文本内容变空串";
				afterColor = ColorTextSecondary;
			}

			if (fake) {
				const BYTE* fakeBytes = static_cast<const BYTE*>(GlobalLock(fake));
				const size_t fakeLength = static_cast<size_t>(GlobalSize(fake));
				afterText = AdvHex(fakeBytes, fakeLength);
				afterText += L"   （";
				afterText += afterWhat;
				afterText += L"）";
				GlobalUnlock(fake);
				RClip::FreeFake(format, fake);
			}

			if (realBytes) {
				GlobalUnlock(real);
			}
			if (real) {
				GlobalFree(real);
			}

			DrawTextSimple(dc, L"② 剪贴板 · CF_UNICODETEXT（文本）",
				{ dleft, dy, dright, dy + 18 }, g_labelFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"判定", AdvVerdictText(v),
				v.hit ? ColorSpoofed : ColorTextSecondary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改前", beforeHex, ColorTextPrimary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改后", afterText, afterColor);
			dy += AdvLineHeight + 10;
		}

		// ---- 样例 3：注册表枚举（隐藏）----
		{
			const WCHAR* keyPath = L"HKEY_CURRENT_USER\\Software\\R3ShieldCoreDemo\\Vault";
			PCWSTR children[] = { L"SecretKey", L"PublicKey", L"SecretToken", L"Password" };
			const int childCount = static_cast<int>(_countof(children));

			std::wstring beforeList;
			std::wstring afterList;
			std::wstring hitText;
			int hidden = 0;
			for (int i = 0; i < childCount; i++) {
				if (!beforeList.empty()) {
					beforeList += L" · ";
				}
				beforeList += children[i];

				const RRule::Verdict v = RRule::Eval(RRule::Face::RegEnum, keyPath, children[i], nullptr);
				if (v.hit && v.act == RRule::Act::Hide) {
					hidden++;
					if (hitText.empty()) {
						hitText = AdvVerdictText(v);
					}
					continue;
				}
				if (!afterList.empty()) {
					afterList += L" · ";
				}
				afterList += children[i];
			}
			if (afterList.empty()) {
				afterList = L"（全被隐藏）";
			}

			DrawTextSimple(dc, L"③ 注册表枚举 · 子键列表（隐藏）",
				{ dleft, dy, dright, dy + 18 }, g_labelFont, ColorTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"判定",
				hidden ? hitText : std::wstring(L"未命中规则 · 一项都不隐藏"),
				hidden ? ColorSpoofed : ColorTextSecondary);
			dy += AdvLineHeight;
			// ★ 不带"共 N 项"后缀：这一行本来就长（4 个名字），加了会被
			//   DT_END_ELLIPSIS 截掉尾巴，反而看不出藏的是谁。条数由「改后」那行说。
			AdvRow(dc, dleft, dright, dy, L"改前", beforeList, ColorTextPrimary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改后",
				afterList + L"   （隐藏 " + std::to_wstring(hidden) + L" 项）",
				hidden ? ColorSpoofed : ColorTextSecondary);
			dy += AdvLineHeight + 10;
		}

		// 一句诚实标注：这一页**不**模拟引擎侧的 protect_reg 判据。
		DrawTextSimple(dc, L"注：枚举面未命中即「保留」（不模拟 protect_reg 判据）。",
			{ dleft, layout.PanelBottom - 24, dright, layout.PanelBottom - 6 },
			g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// ---------------- 页面主入口 ----------------
	void DrawAdvancedPage(HDC dc, const RECT& client)
	{
		// ★ 首次进这一页：先从规则文件读，读不到再铺示例 —— 只做一次。
		{
			static bool seeded = false;
			if (!seeded) {
				seeded = true;
				AdvInitialLoad();
			}
		}

		const AdvLayout layout = AdvLayoutFor(client);

		// ★ 证明"这一页真的被画到了"（与 ARK 页同一套路，铁律 97）。
		//   为什么值得单开一行日志：`--gui-preview` 的核对完全建立在
		//   "窗口画出来了"这件事上，而"页面没被画到"与"画了但内容不对"
		//   在一张截图上长得一模一样 —— 截到空窗口时分不清是哪种。
		{
			static bool paintedOnce = false;
			if (!paintedOnce) {
				paintedOnce = true;
				// ★ v78：`闸门=` 与 `编辑框=` 是**两个**开关，必须分开报 ——
				//   只报一个的话，"闸门过了但解析屏还没点掉"这种中间态
				//   在日志里看不出来，而它正好是三个界面状态里的第二个。
				//   `编辑框=` 报的是 `AdvEditShouldShow()`（与真正去
				//   ShowWindow 的是**同一个函数**），不是"句柄存不存在" ——
				//   后者在闸门屏也是 1（控件早建好了，只是隐藏着），
				//   报它等于给探针一条**恒真**的判据。
				printf("[adv] 页面已绘制 规则=%d 页签=%d 闸门=%d 编辑框=%d 客户区=%dx%d\n",
					RRule::Count(), g_activeTab, g_advQuizPassed ? 1 : 0,
					AdvEditShouldShow() ? 1 : 0,
					static_cast<int>(client.right), static_cast<int>(client.bottom));
				fflush(stdout);
			}
		}

		// ---------------- 摘要行 ----------------
		{
			WCHAR buffer[320] = {};
			if (!g_advQuizPassed) {
				swprintf_s(buffer, _countof(buffer),
					L"替换 API 结果 · 规则引擎编辑台 —— 编辑区**已锁定**（先过三道题闸门）· 规则 %d 条",
					RRule::Count());
			}
			else if (!g_advWhyDismissed) {
				swprintf_s(buffer, _countof(buffer),
					L"替换 API 结果 · 规则引擎编辑台 —— 闸门已通过，看完解析点「开始编辑规则」");
			}
			else {
				swprintf_s(buffer, _countof(buffer),
					L"替换 API 结果 · 规则引擎编辑台 —— 规则 %d 条 · first-match wins，未命中回落内置默认行为",
					RRule::Count());
			}
			DrawTextSimple(dc, buffer,
				{ layout.Left, layout.SummaryTop, layout.Right, layout.SummaryTop + 22 },
				g_labelFont, ColorTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		// ---------------- 三个状态 ----------------
		if (!g_advQuizPassed) {
			AdvDrawQuiz(dc, layout);
		}
		else if (!g_advWhyDismissed) {
			AdvDrawWhy(dc, layout);
		}
		else {
			AdvDrawEditor(dc, layout);
			AdvDrawPreview(dc, layout);
		}

		// ---------------- 底部按钮 + 说明 ----------------
		int lastButtonRight = layout.Left;
		for (int i = 0; i < AdvButtonAll; i++) {
			if (!AdvButtonVisible(i)) {
				continue;
			}
			AdvDrawButton(dc, layout.Buttons[i], AdvButtonLabel(i),
				g_advHoverAction == i, g_advPressedAction == i);
			lastButtonRight = layout.Buttons[i].right;
		}
		{
			PCWSTR hint = L"";
			if (g_advQuizPassed && g_advWhyDismissed) {
				// ★ 编辑态有 6 个按钮，右边只剩百来像素 —— 这句必须短。
				//   写长了会被 DT_END_ELLIPSIS 截成"规则文件路径…"，
				//   等于什么都没说（路径本来就印在左栏底部）。
				hint = L"重启引擎后生效";
			}
			else if (!g_advQuizPassed) {
				hint = L"闸门与命令行控制台共用同一套题（advanced_quiz.h）。";
			}
			// ★ 说明行接在**最后一个可见按钮**右边 —— 不能写死
			//   "Left + AdvButtonWidth*3 + 32"：三个状态各显示 2 / 1 / 6 个按钮，
			//   写死的话编辑态那 6 个按钮会被这行说明**压在底下**
			//   （实测：截图里「重置为示例规则」「清空规则表」两个按钮上叠着字，
			//    而日志和像素判据都完全看不出来）。
			DrawTextSimple(dc, hint,
				{ lastButtonRight + 16, layout.ButtonTop,
				  layout.Right, layout.ButtonTop + AdvButtonHeight },
				g_labelFont, ColorTextSecondary,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
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

		// 页面底色（跟标题区一致，让页签看起来是"挂在"上方内容区上的）
		RECT strip = { 0, TabBarTop, width, TabBarTop + TabBarHeight };
		HBRUSH stripBrush = CreateSolidBrush(ColorHeaderBackground);
		FillRect(dc, &strip, stripBrush);
		DeleteObject(stripBrush);

		for (int i = 0; i < TabCount; i++) {
			RECT rect = TabRect(i);
			bool active = (i == g_activeTab);

			if (active) {
				HBRUSH brush = CreateSolidBrush(ColorTabActiveBg);
				HGDIOBJ old = SelectObject(dc, brush);
				HPEN pen = CreatePen(PS_SOLID, 1, ColorTabActiveBg);
				HGDIOBJ oldPen = SelectObject(dc, pen);
				RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
				SelectObject(dc, old);
				SelectObject(dc, oldPen);
				DeleteObject(brush);
				DeleteObject(pen);
			}
			else if (i == g_hoverTab) {
				// 未选中页签的悬停态：浅底 + 淡描边，暗示"这里可以点"。
				HBRUSH brush = CreateSolidBrush(ColorTabHoverBg);
				HGDIOBJ old = SelectObject(dc, brush);
				HPEN pen = CreatePen(PS_SOLID, 1, ColorTabHoverBorder);
				HGDIOBJ oldPen = SelectObject(dc, pen);
				RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
				SelectObject(dc, old);
				SelectObject(dc, oldPen);
				DeleteObject(brush);
				DeleteObject(pen);
			}

			DrawTextSimple(dc, TabTitle(i), rect, g_tabFont,
				active ? ColorTabActiveText
					: (i == g_hoverTab ? ColorAccent : ColorTabInactiveText),
				DT_CENTER | DT_VCENTER | DT_SINGLELINE);
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

		// 双缓冲
		HDC buffer = CreateCompatibleDC(dc);
		HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
		HGDIOBJ oldBitmap = SelectObject(buffer, bitmap);

		HBRUSH background = CreateSolidBrush(ColorBackground);
		FillRect(buffer, &client, background);
		DeleteObject(background);

		// 顶部标题区
		RECT header = { 0, 0, client.right, 62 };
		HBRUSH headerBrush = CreateSolidBrush(ColorHeaderBackground);
		FillRect(buffer, &header, headerBrush);
		DeleteObject(headerBrush);

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
			// ★ v77：「高级」页 —— 替换 API 结果的规则引擎预览台。
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

		// ★ v78：「高级」页的 EDIT 子控件同步（显示 / 隐藏 / 摆位）。
		//
		//   为什么放在 BitBlt **之前**：`AdvSyncEdit` 只做"把 AdvLayoutFor 算
		//   出来的矩形应用到控件上"，与画的内容无关；放前面是为了让
		//   "控件位置"和"同一帧里画的框线/标签"用**同一次**布局计算，
		//   否则窗口尺寸刚变的那一帧会出现"标签在新位置、编辑框还在旧位置"。
		//
		//   ⚠️ 它在非「高级」页 / 闸门未过时会直接 SW_HIDE —— 所以不需要
		//      在切页签的地方再写一遍"隐藏编辑框"（那种分散的开关状态
		//      正是"切了页签编辑框还浮在上面"的成因）。
		AdvSyncEdit(hwnd, client);

		BitBlt(dc, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);

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

	LRESULT CALLBACK GuiWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
	{
		switch (message) {
		case WM_ERASEBKGND:
			return 1;

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

		case WM_CTLCOLOREDIT: {
			// ★ v78：「高级」页的规则编辑框要**白底深字**。
			//
			//   为什么必须显式处理：主窗口是自绘的，但原生 EDIT 不归我们画 ——
			//   它会用**系统主题色**填背景（深色主题下就是深灰/黑），
			//   于是"白底深字"的自绘页面里突然出现一个黑框，看起来像画错了。
			//
			//   ⚠️ 返回的刷子**不能是临时创建又没人删的**（每次重绘漏一个 GDI 对象，
			//      拖久了进程会耗尽 GDI 句柄）。`GetStockObject(WHITE_BRUSH)`
			//      是系统共享对象：不需要（也不能）DeleteObject。
			HDC dc = reinterpret_cast<HDC>(wParam);
			SetTextColor(dc, ColorTextPrimary);
			SetBkColor(dc, RGB(255, 255, 255));
			return reinterpret_cast<LRESULT>(GetStockObject(WHITE_BRUSH));
		}

		case WM_PAINT:
			PaintWindow(hwnd);
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

			// ★ v77：「高级」页的两个按钮（同样不在 HeaderAction 那套里 ——
			//   位置随客户区大小变，且只在这一页存在）。
			// ★ v78：外加**模板芯片**的悬停（闸门过了、进了编辑态才有）。
			int hoveredAdv = AdvButtonNone;
			int hoveredChip = -1;
			if (g_activeTab == 5) {
				RECT client = {};
				GetClientRect(hwnd, &client);
				hoveredAdv = HitTestAdvButton(point, client);
				hoveredChip = HitTestAdvChip(point, client);
			}

			if (hovered != g_hoverButton || hoveredTab != g_hoverTab
				|| hoveredArk != g_arkHoverAction || hoveredAdv != g_advHoverAction
				|| hoveredChip != g_advHoverChip) {
				g_hoverButton = hovered;
				g_hoverTab = hoveredTab;
				g_arkHoverAction = hoveredArk;
				g_advHoverAction = hoveredAdv;
				g_advHoverChip = hoveredChip;
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;
		}

		case WM_MOUSELEAVE:
			g_trackingMouseLeave = false;
			if (g_hoverButton != HeaderAction::None || g_hoverTab >= 0
				|| g_arkHoverAction != ArkButtonNone || g_advHoverAction != AdvButtonNone
				|| g_advHoverChip != -1) {
				g_hoverButton = HeaderAction::None;
				g_hoverTab = -1;
				g_arkHoverAction = ArkButtonNone;
				g_advHoverAction = AdvButtonNone;
				g_advHoverChip = -1;
				InvalidateRect(hwnd, nullptr, FALSE);
			}
			return 0;

		case WM_CAPTURECHANGED:
			// 捕获被抢走（弹了 UAC、别的窗口抢了鼠标）⇒ 清掉按下态，
			// 否则按钮会永远停在"按下"的样子。
			if (g_pressedButton != HeaderAction::None || g_arkPressedAction != ArkButtonNone
				|| g_advPressedAction != AdvButtonNone || g_advPressedChip != -1) {
				g_pressedButton = HeaderAction::None;
				g_arkPressedAction = ArkButtonNone;
				g_advPressedAction = AdvButtonNone;
				g_advPressedChip = -1;
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

			// ★ v77/v78：「高级」页 —— 三种可点区域，按**界面状态**分派。
			//
			//   闸门未过 ⇒ 只有「三道题的选项」可点（编辑区锁着，连按钮都
			//   只剩「提交答案 / 清空作答」两个，见 AdvButtonVisible）。
			//   闸门过了 ⇒ 模板芯片 / 规则表行 / 底部按钮。
			//
			//   ⚠️ 这三种命中函数各自都**自带状态判断**（不在对应状态时直接
			//      返回"没命中"）—— 所以这里不需要再写一遍 if 分支去区分，
			//      少一处分支就少一处"状态和分支对不上"的机会。
			if (g_activeTab == 5) {
				RECT client = {};
				GetClientRect(hwnd, &client);

				// ① 闸门选项（只在未通过时命中）。
				int quizOpt = -1;
				const int quizCol = HitTestAdvQuizOption(point, client, &quizOpt);
				if (quizCol >= 0) {
					g_advPick[quizCol] = quizOpt;
					// ★ 重选就**撤掉这一题的"错"标记** —— 否则用户改对了，
					//   界面上那题还是红的，他会以为没点上（判据滞后于输入）。
					g_advWrongMask &= ~(1 << quizCol);
					printf("[adv] 第%d题 选了 %c\n", quizCol + 1,
						static_cast<char>('A' + quizOpt));
					fflush(stdout);
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
				}

				// ② 模板芯片（只在已解锁时命中）。
				const int chip = HitTestAdvChip(point, client);
				if (chip >= 0) {
					g_advPressedChip = chip;
					SetCapture(hwnd);
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
				}

				// ③ 规则表某一行（只在已解锁时命中）。
				const int row = HitTestAdvTableRow(point, client);
				if (row >= 0) {
					AdvSelectRule(row);
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
				}

				// ④ 底部按钮。
				const int button = HitTestAdvButton(point, client);
				if (button != AdvButtonNone) {
					g_advPressedAction = button;
					SetCapture(hwnd);
					InvalidateRect(hwnd, nullptr, FALSE);
					return 0;
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

			// ★ v78：「高级」页的**模板芯片**（比按钮先判 —— 芯片和按钮
			//   的按下态是两个独立的变量，同时为真的情况不会出现，
			//   但先判谁决定了"万一同时为真"时的行为，写清楚更好读）。
			if (g_advPressedChip != -1) {
				const int pressed = g_advPressedChip;
				g_advPressedChip = -1;
				if (GetCapture() == hwnd) {
					ReleaseCapture();
				}
				RECT client = {};
				GetClientRect(hwnd, &client);
				// 标准按钮语义：松手时仍停在**同一个**芯片上才触发。
				if (HitTestAdvChip(point, client) == pressed) {
					AdvClickChip(pressed);
				}
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ★ v77：「高级」页的按钮（与 ARK 那套同样单独处理）。
			if (g_advPressedAction != AdvButtonNone) {
				const int pressed = g_advPressedAction;
				g_advPressedAction = AdvButtonNone;
				if (GetCapture() == hwnd) {
					ReleaseCapture();
				}
				RECT client = {};
				GetClientRect(hwnd, &client);
				// 只有松手时鼠标仍停在**同一个**按钮上才触发（标准按钮语义）。
				if (HitTestAdvButton(point, client) == pressed) {
					PerformAdvAction(pressed);
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
			// 关窗口不退出程序（引擎还得继续跑）。
			//
			// ⚠️ 为什么是 SW_MINIMIZE 而不是 SW_HIDE：
			// 任务管理器「进程 / 应用」页的"结束任务"走的是**友好关闭** ——
			// 给主窗口发 WM_CLOSE，不是 TerminateProcess（后者在「详细信息」页，
			// 需要 PROCESS_TERMINATE 句柄，已被 NtOpenProcess 的保护 hook 拦掉）。
			// WM_CLOSE 是窗口消息，不需要进程句柄，保护 hook 不在链路上，
			// 所以这条路径拦不住 —— 只能靠窗口过程自己决定怎么响应。
			//
			// 但窗口消息的处置权天然就在 WndProc 里，**不需要 hook 任何人**：
			// 无论谁发、走 PostMessage 还是直调 NtUserMessageCall，
			// 最终都要经过这里。改这里比 hook 发送方更彻底。
			//
			// 用 SW_HIDE 的问题是：窗口消失后任务管理器判定"结束成功"、
			// 不再升级到 TerminateProcess，用户以为引擎已关闭 —— 而监控和拦截
			// 全都还在生效，这是个危险的误导。最小化则始终留在任务栏上，
			// 用户一眼就知道它没被关掉。
			ShowWindow(hwnd, SW_MINIMIZE);
			return 0;

		case WM_DESTROY:
			KillTimer(hwnd, 1);
			KillTimer(hwnd, TopMostReinforceTimerId);
			// ★ v78：「高级」页的 EDIT 子控件。
			//   必须显式销毁 —— 它是本窗口的子窗口，DestroyWindow 会连带销毁，
			//   但**不销毁也不会报错**（所以这不是防崩，是防"g_advEdit 变成
			//   悬空句柄"）：GUI 线程可能被 Start() 再拉起来一次
			//   （UIAccess 接管实例），那时 `AdvCreateEdit` 会看到
			//   `g_advEdit != nullptr` 而**直接返回**，新的编辑框永远建不出来。
			//   那种故障的表现是"规则编辑框不见了"，且没有任何日志。
			if (g_advEdit) {
				DestroyWindow(g_advEdit);
				g_advEdit = nullptr;
			}
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
			// ★ v77：`advanced` —— 「高级」页（规则引擎预览台）。
			//   理由同 ark：这一页也是自绘、没有控件句柄，自动化点击既过不了
			//   UIPI 也点不准；要核对它只能靠这个开关 + `--gui-preview`。
			else if (n > 0 && _wcsicmp(tabEnv, L"advanced") == 0) {
				g_activeTab = 5;
			}
		}

		g_window = CreateWindowEx(
			WS_EX_APPWINDOW | WS_EX_TOPMOST,
			GuiClassName, GuiTitle,
			// ★★ v78：`WS_CLIPCHILDREN` 是**必须的**，不是优化。
			//   「高级」页有一个原生 EDIT 子控件，而本窗口是**整块双缓冲**
			//   （见 PaintWindow 末尾的 `BitBlt`）。没有这个位，`BitBlt` 会
			//   直接盖到 EDIT 上 ⇒ 编辑框**看不见**（连边框都没了），
			//   而界面上不会有任何报错，只有截图能看出来（铁律 181）。
			//   加上之后父窗口的绘制区自动挖掉子控件占的那块。
			WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME
				| WS_CLIPCHILDREN,
			CW_USEDEFAULT, CW_USEDEFAULT, WindowWidth, WindowHeight,
			nullptr, nullptr, g_instance, nullptr);

		if (g_window) {
			// ★ v78：「高级」页的规则编辑框（原生 EDIT）。
			//
			//   为什么在**这里**建、而不是 WM_CREATE 里：
			//   子控件的创建必须发生在**拥有它的线程**上，而这段代码本来就跑在
			//   GUI 线程（GuiThreadProc）里 —— 与后面 SetTimer/ShowWindow 同一处，
			//   顺序一眼能看清。放 WM_CREATE 也行，但那样"谁建了控件"要翻两处。
			//
			//   ⚠️ 建出来是**隐藏**的（没调 ShowWindow），位置由 PaintWindow 里
			//      的 `AdvSyncEdit` 按当前页签/闸门状态决定要不要显示 ——
			//      位置只在 `AdvLayoutFor` 里算一次（铁律 182）。
			AdvCreateEdit(g_window);

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
			SetTimer(g_window, 1, 300, nullptr);
			// ★ v63：ARK 页的刷新定时器。间隔来自 `ark_refresh_ms`；
			//   不在 ARK 页时它只做一次判断就返回（见 WM_TIMER），几乎零成本。
			SetTimer(g_window, ArkRefreshTimerId, ArkRefreshIntervalMs(), nullptr);

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

		// ★ v78：预览模式下**预置「高级」页的状态**。
		//
		//   为什么需要：这一页有**三个互斥的界面状态**（闸门未过 / 刚全对 /
		//   已解锁编辑）。没有这两个开关，探针永远只能截到"闸门那一屏"，
		//   而**新加的编辑台（表格 + 芯片 + 原生 EDIT）长什么样**就又回到
		//   "只能靠人眼"——本项目吃过这个亏（铁律 24/28）。
		//
		//   ⚠️ 这两个环境变量**只在 `--gui-preview` 里生效**（本函数只在
		//      `--gui-preview` 分流时被调用，见 app.cpp）。它们解锁的只是
		//      **界面**上的编辑区 —— 引擎读规则文件这件事完全不经过这里
		//      （规则是否生效仍由 ini 的三个开关决定）。所以这不是一道
		//      "能被绕过的安全闸门"，它本来就只是防误操作的 UX 闸门。
		//
		//   · R3SHIELDCORE_PREVIEW_ADV = why | editor
		//       why    -> 当成"三道题刚全对"，截解析屏
		//       editor -> 再往前一步，截编辑台
		//   · R3SHIELDCORE_PREVIEW_GATES = all | 1
		//       把三个总闸显示成"开"（只为截图能同时看到两种配色）
		{
			wchar_t advEnv[32] = {};
			const DWORD advLen = GetEnvironmentVariableW(
				L"R3SHIELDCORE_PREVIEW_ADV", advEnv, _countof(advEnv));
			if (advLen > 0 && _wcsicmp(advEnv, L"why") == 0) {
				g_advQuizPassed = true;
			}
			else if (advLen > 0 && _wcsicmp(advEnv, L"editor") == 0) {
				g_advQuizPassed = true;
				g_advWhyDismissed = true;
			}

			wchar_t gatesEnv[32] = {};
			const DWORD gatesLen = GetEnvironmentVariableW(
				L"R3SHIELDCORE_PREVIEW_GATES", gatesEnv, _countof(gatesEnv));
			if (gatesLen > 0 && (_wcsicmp(gatesEnv, L"all") == 0 || wcscmp(gatesEnv, L"1") == 0)) {
				options.SpoofReg = true;
				options.SpoofClipboard = true;
				options.SpoofRegEnum = true;
			}

			// R3SHIELDCORE_PREVIEW_RULES = <规则文件路径>
			//   把这一页读/写的规则文件重定向到一个**临时文件**。
			//   自动核对要的是确定性（"规则=3 来源=示例"这条判据在别人机器上
			//   不该因为 ProgramData 里恰好有个规则文件而变红），同时也让
			//   自动核对**完全不碰**用户的真实规则文件。
			//   ⚠️ 只有本函数（`--gui-preview`）会读这个变量 ⇒ 生产路径下
			//      `g_previewRulesPath` 恒为空，界面与引擎仍然指向同一个真实路径。
			wchar_t rulesEnv[MAX_PATH] = {};
			const DWORD rulesLen = GetEnvironmentVariableW(
				L"R3SHIELDCORE_PREVIEW_RULES", rulesEnv, _countof(rulesEnv));
			if (rulesLen > 0 && rulesLen < _countof(rulesEnv)) {
				wcsncpy_s(g_previewRulesPath, rulesEnv, _TRUNCATE);
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
		// ★ v78：「高级」页有**三个互斥的界面状态**，一个页签名看不全 ——
		//   下面这两个变量用来把另外两屏也截出来（详见函数开头的注释）。
		printf("[gui-preview] 「高级」页状态：R3SHIELDCORE_PREVIEW_ADV=why|editor；"
			"总闸显示：R3SHIELDCORE_PREVIEW_GATES=all\n");
		printf("[gui-preview] 规则文件重定向（自动核对用）：R3SHIELDCORE_PREVIEW_RULES=<路径>\n");

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
