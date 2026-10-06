#include "stdafx.h"
#include "r3shieldcore_sentinel.h"

#include <cstdio>
#include <vector>
#include <psapi.h>   // EnumProcessModulesEx / GetModuleBaseNameW（远程 ExitProcess 用）

//
// 全屏置顶覆盖层反制。设计说明见 r3shieldcore_sentinel.h。
//
// ⚠️ 本模块跑在**引擎进程的主线程**上（由 app.cpp 主循环每 100ms 调 Tick()），
//    所以任何“动作 + 验证”的等待都必须很短，且一次扫描最多处理一个窗口 ——
//    否则会把主循环拖慢，界面卡顿、事件排空延迟。
//
namespace
{
	// 节流与安全参数。
	constexpr ULONGLONG kScanIntervalMs = 500;   // 两次实际扫描之间至少间隔
	constexpr ULONGLONG kGraceMs = 3000;         // 新窗口先观察这么久再动手
	constexpr ULONGLONG kCooldownMs = 1500;      // 同一窗口两次动作之间
	constexpr ULONGLONG kRetentionMs = 60000;    // 未升级条目：窗口/进程消失后保留多久
	// 已升级条目（rungs>0）保留更久：一个"杀不死"的覆盖层如果 60s 就被清掉，
	// rungs 会归零、阶梯重置回 ① —— 等于放弃反制。这里给它 10 分钟，
	// 既避免无限增长，又不会把还在硬扛的进程"洗白"。
	constexpr ULONGLONG kRetentionProgressMs = 600000;
	// 观察表容量。旧值 64，加大到 128 是因为"覆盖层攻击"常常一次开出**一堆**
	// 全屏无边框置顶窗口（真假混杂）。表满时若按"最老"淘汰，一串诱饵就能把
	// 真目标的条目挤掉 —— 条目没了，rungs 归零，升级阶梯被重置。
	// （淘汰策略也一并改成"优先淘汰没动过手的"，见 InsertEntry。）
	constexpr int kMaxWatch = 128;

	// ★ v59：心跳间隔。让"引擎到底有没有在扫桌面"在日志里可见 ——
	//   没有它的时候，"没反制"与"没扫"在 r3shieldcore-console.log 里完全一样。
	constexpr ULONGLONG kHeartbeatMs = 60000;

	// ★ v59：询问**超时**连续多少次才放弃（见 AskAnswer::AskTimeout 的注释）。
	//    超时 != 用户拒绝 —— 覆盖层很可能把弹窗盖住，用户压根没看见。
	constexpr int kMaxAskTimeouts = 3;

	// ★ v59：最多为多少个 hwnd 打过诊断日志（"差一点命中" + "命中详情"），
	//    避免每 500ms 刷屏。
	constexpr int kMaxNearMiss = 32;

	// 隐藏父窗口的类名（第 ③ 级用）。
	const wchar_t* kHiddenParentClass = L"R3ShieldCoreSentinelHiddenParent";

	// 询问弹窗的类名（级别 2 用）。
	const wchar_t* kAskClass = L"R3ShieldCoreSentinelAsk";

	// 询问弹窗尺寸与按钮（居中摆放，见 AskThreadProc）。
	//
	// ⚠️ 宽度必须容得下**一行三个按钮**：`kButtonW + 40` × 3 + 间隙×2。
	//    132+40=172 ⇒ 3×172 + 2×14 = 544，再加上左右各 22 的边距要 588，
	//    所以窗口宽取 640（客户区 ~632）才不挤。旧值 560 会让第三个按钮
	//    溢出到客户区外面 —— 用户根本点不到「不再询问」。
	constexpr int kAskWidth = 640;
	constexpr int kAskHeight = 268;
	constexpr int kButtonW = 132;
	constexpr int kButtonH = 36;
	constexpr int kButtonGap = 14;
	constexpr int kAskMargin = 22;

	// 询问默认超时（ini 的 prompt_timeout 会覆盖它）。
	constexpr ULONG kDefaultAskTimeoutMs = 20000;

	// 询问结果（由弹窗线程写，主线程读）。
	//
	// ★ v59：**超时必须与"用户点了跳过"分开** —— 两者都叫"没动手"，但结论相反：
	//    超时 = 用户可能根本没看见弹窗（覆盖层把它盖住了）→ 应当重试；
	//    跳过 = 用户明确表态"别动它" → 应当尊重、不再打扰。
	enum AskAnswer
	{
		AskNone = 0,        // 还没作答
		AskAllow = 1,       // 反制（只这一次）
		AskSkip = 2,        // 用户明确选择"跳过"（点按钮 / 按 Esc / 点 X）
		AskAllowAlways = 3, // 不再询问（本次运行内）
		AskTimeout = 4,     // ★ 超时（无人应答）—— 只代表"这次没结论"
	};

	// 按钮 id
	constexpr int kIdAllow = 1001;
	constexpr int kIdSkip = 1002;
	constexpr int kIdAlways = 1003;

	// 弹窗上的定时器 id：既做超时判定，也周期性重申置顶。
	constexpr UINT_PTR kAskTimerId = 1;
	constexpr UINT kAskTimerMs = 200;

	// 观察条目 —— ★按**进程**（pid）而不是按窗口（hwnd）记账。
	//
	// ⚠️ 为什么必须以 pid 为键（这是"窗口反制没效果"的根因）：
	//    第 ③ 级 DestroyWindow 把窗口拿掉后，**顽固程序会重建一个新窗口** ——
	//    新窗口 = 新 hwnd。若按 hwnd 记账，旧条目被清、新条目 rungs=0，
	//    升级阶梯永远卡在 ①，④⑤ 根本走不到。
	//    （这正是用户反馈"窗口反制还是没效果"的场景：窗口杀不死。）
	//    改成按 pid 记账后，同一个进程换多少个窗口，rungs 都连续累加。
	//
	// hwnd 只记"当前代表窗口"，每次扫描刷新；动作仍然作用在这个 hwnd 上。
	struct WatchEntry
	{
		DWORD pid = 0;
		HWND hwnd = nullptr;        // 当前代表窗口（程序重建后会被刷新）
		ULONGLONG firstSeenMs = 0;
		ULONGLONG lastActionMs = 0;
		ULONGLONG lastAskMs = 0;
		int rungs = 0;              // 已尝试的级别数（0=未动 … 4=已杀进程）
		bool askPending = false;    // 本进程正在等用户作答
		bool userDeclined = false;  // 用户选了"跳过" → 不再打扰这个进程
		int askTimeouts = 0;        // ★ v59：本进程询问**超时**的累计次数
	};

	bool g_enabled = false;
	bool g_classRegistered = false;
	bool g_askClassRegistered = false;
	bool g_handledThisScan = false;
	ULONGLONG g_lastScanMs = 0;
	ULONGLONG g_lastHeartbeatMs = 0;   // ★ v59：上次打心跳的时刻
	R3ShieldCoreSentinel::Stats g_stats = {};
	WatchEntry g_watch[kMaxWatch] = {};

	// ★ v59：已经为哪些 hwnd 打过诊断（"差一点命中" / "命中详情"），
	//   每 hwnd 一次，避免每 500ms 刷屏。
	HWND g_loggedHwnd[kMaxNearMiss] = {};
	int g_loggedHwndCount = 0;

	// ★ v60：**本扫描**的命中数（`g_stats.Detected` 是累计值）。
	//   旧心跳只打累计值 ⇒ 看到 "命中=15" 永远不变时，分不清
	//   "这个扫描周期一个都没命中" 与 "累计就是 15"。两个数一起打就没有歧义。
	ULONG g_lastScanMatched = 0;

	// ---- 询问级别（0=关 1=不问 2=询问）----
	ULONG g_level = 0;
	ULONG g_askTimeoutMs = kDefaultAskTimeoutMs;

	// ---- 询问状态 ----
	volatile LONG g_askRunning = 0;   // 1 = 弹窗线程还活着
	volatile LONG g_askResult = AskNone;
	HWND g_askTargetHwnd = nullptr;   // 本次询问针对哪个窗口（仅主线程读写）
	HWND g_askHwnd = nullptr;         // 弹窗自身（Stop() 要能把它关掉）
	ULONGLONG g_askStartedMs = 0;
	bool g_askAlwaysAllow = false;    // 用户选了"不再询问"
	DWORD g_askPid = 0;
	ULONG g_askRung = 0;
	WCHAR g_askProcessName[MAX_PATH] = {};

	// ------------------------------------------------------------------
	// 小工具
	// ------------------------------------------------------------------

	// 完整性级别 RID（Medium=0x2000 / High=0x3000 / System=0x4000 …）。
	bool GetIntegrityRid(HANDLE process, DWORD& rid) noexcept
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
			return false;
		}

		DWORD size = 0;
		GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
		if (size == 0) {
			CloseHandle(token);
			return false;
		}

		std::vector<BYTE> buffer(size);
		const BOOL ok = GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), size, &size);
		CloseHandle(token);
		if (!ok) {
			return false;
		}

		auto* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
		const DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
		if (count == 0) {
			return false;
		}
		rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
		return true;
	}

	DWORD SelfIntegrityRid() noexcept
	{
		static DWORD cached = 0;
		static bool resolved = false;
		if (!resolved) {
			resolved = true;
			DWORD rid = 0;
			if (GetIntegrityRid(GetCurrentProcess(), rid)) {
				cached = rid;
			}
		}
		return cached;
	}

	// 外壳 / 系统关键窗口类：即使它们碰巧是全屏置顶也不动。
	bool IsShellClass(HWND hwnd) noexcept
	{
		WCHAR cls[128] = {};
		if (GetClassNameW(hwnd, cls, _countof(cls)) == 0) {
			return false;
		}

		static const PCWSTR kShellClasses[] = {
			L"Shell_TrayWnd", L"Shell_SecondaryTrayWnd", L"Progman", L"WorkerW",
			L"TaskManagerWindow", L"SysShadow", L"ForegroundStaging",
			L"MultitaskingViewFrame", L"XamlExplorerHostIslandWindow",
			L"TopLevelWindowForOverflowXamlIsland", L"LockScreenBackstopFrame",
			L"ApplicationManager_DesktopShellWindow", L"EdgeUiInputTopWndClass",
			L"Windows.Internal.Shell.TabProxyWindow",
		};
		for (PCWSTR name : kShellClasses) {
			if (_wcsicmp(cls, name) == 0) {
				return true;
			}
		}
		return false;
	}

	// 能不能对目标进程的窗口动手（跨进程窗口操作受 UIPI 约束）。
	bool CanActOnProcess(DWORD pid) noexcept
	{
		if (pid == 0 || pid == GetCurrentProcessId()) {
			return false;
		}

		wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
		if (!process) {
			return false;
		}

		WCHAR path[MAX_PATH * 2] = {};
		DWORD length = _countof(path);
		if (QueryFullProcessImageNameW(process.get(), 0, path, &length) && length > 0) {
			PCWSTR base = wcsrchr(path, L'\\');
			base = base ? base + 1 : path;

			static const PCWSTR kSkipProcesses[] = {
				L"explorer.exe", L"dwm.exe", L"winlogon.exe", L"LogonUI.exe",
				L"consent.exe", L"csrss.exe", L"wininit.exe", L"services.exe",
				L"lsass.exe", L"smss.exe", L"LockApp.exe",
				L"ShellExperienceHost.exe", L"StartMenuExperienceHost.exe",
				L"SearchHost.exe", L"TextInputHost.exe",
				// ★ v60：真机日志实证的**误报** —— SearchApp.exe 是 Win10 的搜索 UI
				//   （Win11 改叫 SearchHost.exe，上面已列）。它的全屏搜索层
				//   style=0x94000000（无 WS_CAPTION）+ 置顶 + 盖满整屏，
				//   恰好满足"覆盖层签名"⇒ 引擎把系统自己的搜索界面当成病毒反制了。
				//   证据：2026-10-05 13:27 真机日志
				//   `[sentinel] 命中覆盖层 pid=6756 进程=SearchApp.exe rect=(0,0,1718,918)`。
				L"SearchApp.exe",
				// 同类系统宿主：UWP 应用的外框窗口都属于它，动它 = 关掉别的应用。
				L"ApplicationFrameHost.exe",
			};
			for (PCWSTR name : kSkipProcesses) {
				if (_wcsicmp(base, name) == 0) {
					return false;
				}
			}
		}

		// 完整性级别：不能动比自己高的（UIPI 会挡，且那是提权/安全桌面 —— 本就不该动）。
		DWORD targetRid = 0;
		if (GetIntegrityRid(process.get(), targetRid)) {
			const DWORD selfRid = SelfIntegrityRid();
			if (selfRid != 0 && targetRid > selfRid) {
				return false;
			}
		}

		return true;
	}

	// 窗口矩形是否盖住某块显示器的**整屏**（`rcMonitor`，含任务栏条带）
	// 或**工作区**（`rcWork`，不含任务栏）。
	//
	// ⚠️ 关键：命中判据比的是 `rcMonitor`（整屏，**含任务栏所占条带**），
	//    **不是** `rcWork`（工作区，不含任务栏）。
	//      · 普通最大化窗口只覆盖 rcWork（任务栏仍露在外面）⇒ 天然被排除；
	//      · 只有真正全屏（全屏游戏 / 锁屏勒索覆盖层）才覆盖 rcMonitor。
	//    ⚠️ 若任务栏设了“自动隐藏”，rcWork == rcMonitor，这条就不再能区分 ——
	//       此时靠“无标题栏 + 置顶”再区分（最大化窗口有 WS_CAPTION，已被排除）。
	//    rcWork 那一档**只用于诊断**（"差一点命中"里报告它盖到了哪一层），
	//    **不参与命中判定** —— 用户明确要求过：全屏 = 盖住任务栏那种全屏。
	bool CoversMonitorRect(HWND hwnd, bool workArea) noexcept
	{
		RECT windowRect = {};
		if (!GetWindowRect(hwnd, &windowRect)) {
			return false;
		}

		HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
		MONITORINFO info = { sizeof(info) };
		if (!GetMonitorInfoW(monitor, &info)) {
			return false;
		}

		const int tol = 2;
		const RECT& full = workArea ? info.rcWork : info.rcMonitor;
		return windowRect.left <= full.left + tol && windowRect.top <= full.top + tol
			&& windowRect.right >= full.right - tol && windowRect.bottom >= full.bottom - tol;
	}

	bool CoversWholeMonitor(HWND hwnd) noexcept
	{
		return CoversMonitorRect(hwnd, /*workArea=*/false);
	}

	// ------------------------------------------------------------------
	// 判定分档（★ v59）
	//
	// 旧版是一个布尔函数，窗口没被反制时**日志里一个字都没有** —— 于是
	// 「没扫到」「扫到但被签名挡掉」「反制动作失败」三种完全不同的结论
	// 在日志里长得一样。这里把结论拆开，好让调用方能打出来。
	// ------------------------------------------------------------------
	enum class OverlayVerdict
	{
		Match = 0,       // 命中覆盖层签名
		Invalid,         // 句柄无效 / 不可见 / 已最小化 / 桌面窗口本身
		HasCaption,      // 有标题栏或系统菜单 = 普通窗口（最主要的排除项）
		NotTopmost,      // 无边框，但没置顶
		NotFullscreen,   // 无边框 + 置顶，但没盖住任务栏（只盖了工作区）
	};

	const char* VerdictNameNarrow(OverlayVerdict v) noexcept
	{
		switch (v) {
		case OverlayVerdict::Match: return "命中";
		case OverlayVerdict::HasCaption: return "有标题栏/系统菜单（非无边框）";
		case OverlayVerdict::NotTopmost: return "无边框但没置顶";
		case OverlayVerdict::NotFullscreen: return "置顶但没盖住任务栏（只盖了工作区）";
		default: return "不可见/已最小化/桌面";
		}
	}

	// 视觉签名：全屏（盖住任务栏）+ 置顶 + 无边框。不含进程/排除判断。
	OverlayVerdict ClassifyOverlay(HWND hwnd) noexcept
	{
		if (!hwnd || !IsWindow(hwnd)) {
			return OverlayVerdict::Invalid;
		}
		if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
			return OverlayVerdict::Invalid;
		}
		if (hwnd == GetDesktopWindow()) {
			return OverlayVerdict::Invalid;
		}

		const LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
		if (style & (WS_CAPTION | WS_SYSMENU)) {
			return OverlayVerdict::HasCaption;   // 有标题栏/系统菜单 = 普通窗口
		}

		const LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
		if ((exStyle & WS_EX_TOPMOST) == 0) {
			return OverlayVerdict::NotTopmost;
		}

		// 必须是「盖住任务栏那种全屏」，不是普通最大化窗口。
		if (!CoversWholeMonitor(hwnd)) {
			return OverlayVerdict::NotFullscreen;
		}
		return OverlayVerdict::Match;
	}

	bool MatchesOverlaySignature(HWND hwnd) noexcept
	{
		return ClassifyOverlay(hwnd) == OverlayVerdict::Match;
	}

	// 进程名（只取文件名部分）—— 定义在本文件后面（弹窗与诊断共用）。
	void ProcessNameOf(DWORD pid, WCHAR* out, size_t cch) noexcept;

	// ------------------------------------------------------------------
	// "差一点命中"的诊断（★ v59）
	//
	// 只对**真的像覆盖层**的窗口打：可见 + 未最小化 + 无边框 + 至少盖满工作区。
	// 普通最大化窗口有标题栏 ⇒ 不会进这里（否则每个最大化的资源管理器都要刷一行）。
	// 每个 hwnd 只打一次；总数上限 kMaxNearMiss。
	// ------------------------------------------------------------------
	bool AlreadyLoggedHwnd(HWND hwnd) noexcept
	{
		for (int i = 0; i < g_loggedHwndCount; i++) {
			if (g_loggedHwnd[i] == hwnd) {
				return true;
			}
		}
		return false;
	}

	void RememberLoggedHwnd(HWND hwnd) noexcept
	{
		if (g_loggedHwndCount < kMaxNearMiss) {
			g_loggedHwnd[g_loggedHwndCount++] = hwnd;
		}
	}

	// ★ v59：把已经失效的 hwnd 从"已打过日志"表里剔除。
	//
	// ⚠️ 为什么必须有：表只有 kMaxNearMiss 个槽，而**句柄会被系统回收复用**。
	//    长跑一轮（覆盖层攻击常开一堆真假窗口）很容易把 32 个槽占满 ——
	//    之后**真正**需要诊断的窗口就再也打不出日志了，可诊断性当场失效。
	//    心跳（60s）时顺手清一遍即可。
	void PruneLoggedHwnds() noexcept
	{
		int write = 0;
		for (int read = 0; read < g_loggedHwndCount; read++) {
			if (IsWindow(g_loggedHwnd[read])) {
				g_loggedHwnd[write++] = g_loggedHwnd[read];
			}
		}
		g_loggedHwndCount = write;
	}

	void LogNearMiss(HWND hwnd, DWORD pid, OverlayVerdict verdict) noexcept
	{
		if (AlreadyLoggedHwnd(hwnd)) {
			return;
		}
		RememberLoggedHwnd(hwnd);
		g_stats.NearMiss++;

		RECT wr = {};
		GetWindowRect(hwnd, &wr);
		HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
		MONITORINFO info = { sizeof(info) };
		RECT mon = {};
		RECT work = {};
		if (GetMonitorInfoW(monitor, &info)) {
			mon = info.rcMonitor;
			work = info.rcWork;
		}

		WCHAR name[MAX_PATH] = {};
		ProcessNameOf(pid, name, _countof(name));

		// ★ v60：把"**能不能动手**"也打出来。
		//   否则"看见了但被进程门控挡掉"（自我/系统进程/完整性更高）依然是黑盒 ——
		//   这也是 v59 日志里查不出来的第二种静默成因。
		const bool actionable = CanActOnProcess(pid);

		printf("[sentinel] 差一点命中 hwnd=%p pid=%u 进程=%ls 原因=%s 可动=%s "
			"style=0x%08llX ex=0x%08llX rect=(%ld,%ld,%ld,%ld) "
			"rcMonitor=(%ld,%ld,%ld,%ld) rcWork=(%ld,%ld,%ld,%ld)\n",
			static_cast<void*>(hwnd), pid, name[0] ? name : L"(未知)",
			VerdictNameNarrow(verdict), actionable ? "是" : "否",
			static_cast<unsigned long long>(GetWindowLongPtrW(hwnd, GWL_STYLE)),
			static_cast<unsigned long long>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)),
			wr.left, wr.top, wr.right, wr.bottom,
			mon.left, mon.top, mon.right, mon.bottom,
			work.left, work.top, work.right, work.bottom);
		fflush(stdout);
	}

	// 这个窗口值不值得打一行"差一点命中"（见 LogNearMiss 的注释）。
	//
	// ★ v60 关键修正：**诊断口径必须比触发判据更宽，绝不能更窄。**
	//
	//   v59 的门槛是"无边框 + 至少盖满工作区"。真机复盘发现：覆盖层**完全可能带标题栏**
	//   （Delphi `TForm` 默认边框 + `WindowState=wsMaximized` + `FormStyle=fsStayOnTop`
	//    ⇒ 有 WS_CAPTION、置顶、盖满工作区）。这种窗口：
	//     · 不满足触发判据（要求无边框）⇒ 不反制 —— 这是对的；
	//     · 也**不**满足 v59 的诊断门槛（同样要求无边框）⇒ 连一行日志都不打。
	//   于是真机上"窗口反制没反应"与"根本没扫到"在日志里长得一模一样 ——
	//   2026-10-05 的真机日志就是这么一片空白（`差一点命中=0`，见 docs/HANDOVER.md 附录 G）。
	//
	//   现在的口径 = "大 **或** 置顶"（不再要求无边框）：
	//     ① 盖住整屏（rcMonitor，含任务栏条带）—— 任何样式都记；
	//     ② 无边框 + 盖满工作区（v59 旧口径，保留）；
	//     ③ 置顶 + 盖满工作区（v60 新增，抓"带标题栏的最大化置顶"）。
	//   普通最大化窗口只盖 rcWork 且不置顶 ⇒ ①②③ 都不满足 ⇒ 不会刷屏。
	bool IsNearMissCandidate(HWND hwnd) noexcept
	{
		if (!hwnd || !IsWindow(hwnd) || !IsWindowVisible(hwnd) || IsIconic(hwnd)) {
			return false;
		}
		if (hwnd == GetDesktopWindow()) {
			return false;
		}

		// ① 盖住整屏（含任务栏）= 无论有没有标题栏，都值得记一笔。
		if (CoversMonitorRect(hwnd, /*workArea=*/false)) {
			return true;
		}

		const LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
		const LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
		const bool borderless = (style & (WS_CAPTION | WS_SYSMENU)) == 0;
		const bool topmost = (exStyle & WS_EX_TOPMOST) != 0;

		// ② 无边框 + 盖满工作区（v59 旧口径，保留）。
		if (borderless && CoversMonitorRect(hwnd, /*workArea=*/true)) {
			return true;
		}

		// ③ 置顶 + 盖满工作区（v60 新增）。
		if (topmost && CoversMonitorRect(hwnd, /*workArea=*/true)) {
			return true;
		}

		return false;
	}


	// ------------------------------------------------------------------
	// 观察表（★按 pid 记账，见 WatchEntry 注释）
	// ------------------------------------------------------------------
	int FindEntry(DWORD pid) noexcept
	{
		for (int i = 0; i < kMaxWatch; i++) {
			if (g_watch[i].pid == pid) {
				return i;
			}
		}
		return -1;
	}

	// 进程是否还活着。打不开句柄时**当作活着**（保守）：宁可留一条过期记录，
	// 也不要把"其实还活着"的进程条目清掉、把它的升级进度重置。
	bool IsProcessAlive(DWORD pid) noexcept
	{
		wil::unique_handle process(OpenProcess(
			SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
		if (!process) {
			return true;
		}
		return WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT;
	}

	int InsertEntry(DWORD pid, HWND hwnd, ULONGLONG now) noexcept
	{
		int freeSlot = -1;
		int oldestIdle = -1;      // 还没动过手的最老条目（首选淘汰）
		int oldestProgress = -1;  // 已升级过的最老条目（次选）
		for (int i = 0; i < kMaxWatch; i++) {
			if (g_watch[i].pid == 0) {
				freeSlot = i;
				break;
			}
			if (g_watch[i].rungs > 0) {
				if (oldestProgress < 0
					|| g_watch[i].firstSeenMs < g_watch[oldestProgress].firstSeenMs) {
					oldestProgress = i;
				}
			}
			else if (oldestIdle < 0
				|| g_watch[i].firstSeenMs < g_watch[oldestIdle].firstSeenMs) {
				oldestIdle = i;
			}
		}

		// ⚠️ 表满时**优先淘汰没动过手的**条目：这样"开一堆诱饵窗口把真目标的
		//    升级进度挤掉"这条绕过路径就失效了 —— 诱饵永远先被淘汰。
		int slot = freeSlot;
		if (slot < 0) {
			slot = (oldestIdle >= 0) ? oldestIdle : oldestProgress;
		}
		if (slot < 0) {
			return -1;   // 表里全是已升级条目（理论上到不了：进程退出会被 Purge）
		}

		// ⚠️ 显式逐字段赋值，不用聚合初始化：
		//    WatchEntry 字段会随版本增加，聚合初始化漏一个就静默按默认值填，
		//    容易埋"新字段没清干净"的坑。
		WatchEntry& entry = g_watch[slot];
		entry = {};
		entry.pid = pid;
		entry.hwnd = hwnd;
		entry.firstSeenMs = now;
		return slot;
	}

	// ⚠️ 清理条件**不再是"窗口没了"** —— 窗口没了但进程还在（重建窗口）时
	//    必须保留条目，否则 rungs 归零、阶梯被重置（见 WatchEntry 注释）。
	void PurgeEntries(ULONGLONG now) noexcept
	{
		for (int i = 0; i < kMaxWatch; i++) {
			if (g_watch[i].pid == 0) {
				continue;
			}
			const bool processGone = !IsProcessAlive(g_watch[i].pid);
			const ULONGLONG keepMs = (g_watch[i].rungs > 0) ? kRetentionProgressMs : kRetentionMs;
			const bool expired = (now - g_watch[i].firstSeenMs) > keepMs;
			if (processGone || expired) {
				g_watch[i] = {};
			}
		}
	}

	// ------------------------------------------------------------------
	// 三级动作
	// ------------------------------------------------------------------
	bool TryMinimize(HWND hwnd) noexcept
	{
		ShowWindow(hwnd, SW_MINIMIZE);
		Sleep(100);
		return IsIconic(hwnd) != FALSE;
	}

	bool TryClose(HWND hwnd) noexcept
	{
		PostMessageW(hwnd, WM_CLOSE, 0, 0);
		Sleep(250);
		return !IsWindow(hwnd);
	}

	// 第 ③ 级：建隐藏父窗口 → SetParent(目标, 父) → DestroyWindow(父)。
	//
	// ⚠️ 与 tools/overlay_ladder_probe.cpp 实证一致：
	//    · 跨进程 SetParent 成功后，关系体现在 GetAncestor(GA_PARENT) 上
	//      （GetParent / IsChild 仍是 0/false —— SetParent 不改 WS_CHILD/WS_POPUP）；
	//    · 真正“杀窗口”的是 DestroyWindow(父)（它会连带销毁 owned 子窗口），
	//      单纯挂靠不销毁不会杀（探针场景 F 对照）。
	//
	// ★ v59：`outDetail` 回填**失败原因**。这一级有两种**完全不同**的失败：
	//    a) SetParent 没生效（窗口拒绝挂靠）—— 目标**纹丝不动**，用户看不出变化；
	//    b) SetParent 生效了、但 DestroyWindow(父) 没把目标带走 —— 目标已经变成
	//       一个"挂在已销毁父窗口下"的子窗口，**视觉上会消失/变黑**，但窗口还在。
	//    用户报的"窗口直接黑屏但是窗口并没有被关掉"就是 (b)。不把这两种分开，
	//    日志里只有一个"失败"，完全没法定位。
	bool DestroyViaHiddenParent(HWND target, const char** outDetail) noexcept
	{
		if (outDetail) {
			*outDetail = "";
		}

		HWND parent = CreateWindowExW(0, kHiddenParentClass, L"", WS_POPUP,
			0, 0, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
		if (!parent) {
			if (outDetail) {
				*outDetail = "建隐藏父窗口失败";
			}
			return false;
		}

		SetParent(target, parent);
		const HWND ancestor = GetAncestor(target, GA_PARENT);
		const bool reparented = (ancestor == parent) || (GetParent(target) == parent)
			|| (IsChild(parent, target) != FALSE);

		if (!reparented) {
			DestroyWindow(parent);
			if (outDetail) {
				*outDetail = "SetParent 未生效（窗口拒绝挂靠，目标纹丝不动）";
			}
			return false;
		}

		// 销毁父窗口会连带销毁 owned 子窗口，但**子窗口属于别的进程/线程，
		// 销毁是异步的** —— DestroyWindow 返回时目标可能还在，稍后才消失。
		// （实测：不留等待直接判定会误报“失败”，而窗口其实已经没了。）
		DestroyWindow(parent);

		for (int i = 0; i < 6; i++) {
			if (!IsWindow(target)) {
				return true;
			}
			Sleep(40);
		}
		if (!IsWindow(target)) {
			return true;
		}

		if (outDetail) {
			*outDetail = "已挂靠成功但 DestroyWindow(父) 没带走它"
				"（窗口仍在，且已变成不可见的子窗口 —— 用户会看到'黑屏但窗口没关掉'）";
		}
		return false;
	}

	// 进程名（只取文件名部分），用于弹窗里给用户看。
	void ProcessNameOf(DWORD pid, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch == 0) {
			return;
		}
		out[0] = L'\0';

		wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
		if (!process) {
			return;
		}

		WCHAR path[MAX_PATH * 2] = {};
		DWORD length = _countof(path);
		if (!QueryFullProcessImageNameW(process.get(), 0, path, &length) || length == 0) {
			return;
		}

		PCWSTR base = wcsrchr(path, L'\\');
		base = base ? base + 1 : path;
		wcsncpy_s(out, cch, base, _TRUNCATE);
	}

	//
	// 第 ④ 级 · 第一招：请求目标线程退出它的消息循环。
	//
	// `PostThreadMessage(WM_QUIT)` 会让目标线程的 `GetMessage` 返回 0 ⇒
	// 消息循环结束 ⇒ 该线程的函数返回 ⇒ 进程走**自己的正常退出路径**
	// （CRT 清理 / atexit / DllMain(DETACH) 全都跑到）。
	//
	// 优点：不需要注入、不需要远程线程、**32/64 位通吃**、权限门槛低
	//       （只需要能 PostMessage 到那个线程）。
	// 局限：只对"有消息循环的线程"有效。窗口线程一定有，但若主线程不是
	//       窗口线程（少见），进程可能不死 —— 那就交给下一招。
	//
	bool TryThreadQuit(HWND hwnd, DWORD pid) noexcept
	{
		const DWORD threadId = GetWindowThreadProcessId(hwnd, nullptr);
		if (threadId == 0) {
			return false;
		}

		// 先礼后兵：WM_CLOSE 已经试过了（第 ② 级），这里直接让消息循环退出。
		if (!PostThreadMessageW(threadId, WM_QUIT, 0, 0)) {
			return false;
		}

		// 给目标一点时间跑清理。
		wil::unique_handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
			FALSE, pid));
		if (!process) {
			return false;
		}
		return WaitForSingleObject(process.get(), 1200) == WAIT_OBJECT_0;
	}

	//
	// 第 ④ 级 · 第二招：在目标进程里**远程调用退出函数**（kernel32!ExitProcess）。
	//
	// 为什么不是"注入自己的 DLL 再调"：`ExitProcess` 就在每个进程都加载的
	// kernel32 里，用 `CreateRemoteThread` 直接把起点设成它即可 ——
	// 少一份载荷 DLL、少一次 LoadLibrary、也少一个被杀软盯上的特征。
	// 效果一样：**跑目标进程自己的退出路径**（不是内核强拆）。
	//
	// ⚠️ 关键：**不能**直接把自己进程的 `GetProcAddress` 结果传过去。
	//    ASLR 下每个进程的 kernel32 基址不一定相同。正确做法是枚举
	//    **目标进程**的模块拿到它自己的 kernel32 基址，再加上
	//    "ExitProcess 相对基址的偏移"（偏移在同一份 DLL 里是固定的）。
	//
	// ⚠️ `ExitProcess` 的签名是 `void ExitProcess(UINT)`；`CreateRemoteThread`
	//    的 `lpParameter` 正好落在第一个参数位（x64=RCX，x86=栈），
	//    所以把退出码当参数传进去即可。
	//
	// ⚠️ WOW64：64 位引擎要枚举 32 位目标的模块必须带 `LIST_MODULES_32BIT`，
	//    拿到的才是 32 位地址。若跨位数调用失败，本函数返回 false，
	//    由第 ⑤ 级（TerminateProcess，不分位数）兜底。
	//
	bool CallRemoteExitProcess(DWORD pid, UINT exitCode) noexcept
	{
		wil::unique_handle process(OpenProcess(
			PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_READ,
			FALSE, pid));
		if (!process) {
			return false;
		}

		HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
		if (!localKernel32) {
			return false;
		}
		const ULONG_PTR localExit = reinterpret_cast<ULONG_PTR>(
			GetProcAddress(localKernel32, "ExitProcess"));
		if (localExit == 0) {
			return false;
		}
		const ULONG_PTR offset = localExit - reinterpret_cast<ULONG_PTR>(localKernel32);

		// 目标进程自己的 kernel32 基址。
		HMODULE modules[1024] = {};
		DWORD needed = 0;
		if (!EnumProcessModulesEx(process.get(), modules, sizeof(modules), &needed,
			LIST_MODULES_ALL)) {
			return false;
		}

		ULONG_PTR remoteKernel32 = 0;
		const DWORD count = needed / sizeof(HMODULE);
		for (DWORD i = 0; i < count && i < _countof(modules); i++) {
			WCHAR name[MAX_PATH] = {};
			if (GetModuleBaseNameW(process.get(), modules[i], name, _countof(name)) == 0) {
				continue;
			}
			if (_wcsicmp(name, L"kernel32.dll") == 0) {
				remoteKernel32 = reinterpret_cast<ULONG_PTR>(modules[i]);
				break;
			}
		}
		if (remoteKernel32 == 0) {
			return false;
		}

		wil::unique_handle thread(CreateRemoteThread(process.get(), nullptr, 0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteKernel32 + offset),
			reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(exitCode)), 0, nullptr));
		if (!thread) {
			return false;
		}

		return WaitForSingleObject(process.get(), 1500) == WAIT_OBJECT_0;
	}

	// 第 ④ 级总入口：先温和（消息循环退出），再直接（远程 ExitProcess）。
	bool TryExitFunction(HWND hwnd, DWORD pid) noexcept
	{
		if (TryThreadQuit(hwnd, pid)) {
			return true;
		}
		return CallRemoteExitProcess(pid, 0);
	}

	//
	// 第 ⑤ 级：暴力杀进程（最后手段）。
	//
	// `TerminateProcess` 是内核直接拆地址空间 —— 目标**跑不到任何清理代码**。
	// 这就是它排在最末、且级别 2 下必须先问过用户的原因。
	//
	// ⚠️ 权限门槛比 ④ 低（只要 `PROCESS_TERMINATE`），所以 ④ 失败时它往往还能成。
	//
	bool TryTerminateProcess(DWORD pid) noexcept
	{
		wil::unique_handle process(OpenProcess(
			PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
		if (!process) {
			return false;
		}

		if (!TerminateProcess(process.get(), 1)) {
			return false;
		}

		return WaitForSingleObject(process.get(), 1500) == WAIT_OBJECT_0;
	}

	LRESULT CALLBACK HiddenParentProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept
	{
		return DefWindowProcW(hwnd, msg, wp, lp);
	}

	void EnsureClassRegistered() noexcept
	{
		if (g_classRegistered) {
			return;
		}
		WNDCLASSEXW wc = { sizeof(wc) };
		wc.lpfnWndProc = HiddenParentProc;
		wc.hInstance = GetModuleHandleW(nullptr);
		wc.lpszClassName = kHiddenParentClass;
		RegisterClassExW(&wc);   // 已注册会返回 0 + ERROR_CLASS_ALREADY_EXISTS，无妨
		g_classRegistered = true;
	}

	// ------------------------------------------------------------------
	// 询问弹窗（级别 2）
	//
	// ⚠️ 为什么跑在**独立线程**上：`Tick()` 在主循环里（每 100ms），
	//    如果在这里弹一个模态窗等用户点，事件排空与进程注入会整个停摆
	//    —— 用户盯着弹窗不动时，引擎等于停转。所以弹窗自己一个线程，
	//    主线程只查结果。
	//
	// ⚠️ 为什么必须**置顶 + 居中在目标显示器**：
	//    覆盖层的特征就是"全屏 + 置顶"，弹窗要是被它盖住，用户根本看不见
	//    —— 那就退化成了静默超时跳过（= 什么都没做）。
	// ------------------------------------------------------------------

	HFONT g_askFont = nullptr;

	// ⚠️ 必须是**宽**字符串：窄字符串里的中文在 `-source-charset:utf-8` 下会按
	//    系统 ANSI（GBK）落地，再用 `%S` 往宽字符转时依赖当前 locale ——
	//    默认 "C" locale 下会转成乱码。宽字面量直接就是 UTF-16，没有这个问题。
	PCWSTR RungActionName(ULONG rung) noexcept
	{
		switch (rung) {
		case 0: return L"① 最小化窗口";
		case 1: return L"② 请求关闭窗口";
		case 2: return L"③ 销毁窗口";
		case 3: return L"④ 结束目标进程（调用退出函数）";
		default: return L"⑤ 强制终止目标进程";
		}
	}

	// 日志用的**窄**版本：r3shieldcore-console.log 里其它中文都是窄字面量（GBK），
	// 这里跟着一致，免得同一个文件里混进两种编码（铁律 26）。
	const char* RungActionNameNarrow(int rung) noexcept
	{
		switch (rung) {
		case 0: return "最小化";
		case 1: return "请求关闭";
		case 2: return "销毁窗口";
		case 3: return "调用退出函数";
		default: return "强制杀进程";
		}
	}

	// AskProc 定义在下面（EnsureAskClassRegistered 里要用它的地址）。
	LRESULT CALLBACK AskProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept;

	void EnsureAskClassRegistered() noexcept
	{
		if (g_askClassRegistered) {
			return;
		}
		WNDCLASSEXW wc = { sizeof(wc) };
		wc.lpfnWndProc = AskProc;
		wc.hInstance = GetModuleHandleW(nullptr);
		wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
		wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
		wc.lpszClassName = kAskClass;
		RegisterClassExW(&wc);
		g_askClassRegistered = true;
	}

	// 把弹窗重新顶到最前（覆盖层会不停重申置顶，所以要周期性抢回来）。
	//
	// ★ v59：抢不到前台时**必须让用户能发现这个弹窗** —— 覆盖层攻击的场景里
	//   弹窗大概率被盖住，用户根本不知道有东西在问。这里额外闪任务栏按钮
	//   （`FLASHW_TIMERNOFG` = 一直闪到它变成前台窗口）。为此弹窗**不能再带
	//   `WS_EX_TOOLWINDOW`**（带它就没有任务栏按钮，闪无可闪、Alt-Tab 也找不到）。
	void ReassertTopmost(HWND hwnd) noexcept
	{
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

		// 我们大概率不是前台进程（前台是那个覆盖层），直接 SetForegroundWindow
		// 会被系统拒绝（只闪任务栏）。临时把输入队列挂到前台线程上再抢。
		HWND foreground = GetForegroundWindow();
		if (foreground == hwnd) {
			return;
		}
		const DWORD foregroundThread = foreground
			? GetWindowThreadProcessId(foreground, nullptr) : 0;
		const DWORD selfThread = GetCurrentThreadId();

		if (foregroundThread != 0 && foregroundThread != selfThread) {
			AttachThreadInput(foregroundThread, selfThread, TRUE);
			SetForegroundWindow(hwnd);
			AttachThreadInput(foregroundThread, selfThread, FALSE);
		}
		else {
			SetForegroundWindow(hwnd);
		}

		if (GetForegroundWindow() != hwnd) {
			FLASHWINFO info = { sizeof(info) };
			info.hwnd = hwnd;
			info.dwFlags = FLASHW_ALL | FLASHW_TIMERNOFG;
			FlashWindowEx(&info);
		}
	}

	LRESULT CALLBACK AskProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) noexcept
	{
		switch (msg) {
		case WM_CREATE:
		{
			HINSTANCE instance = GetModuleHandleW(nullptr);
			RECT client = {};
			GetClientRect(hwnd, &client);
			const int clientW = client.right - client.left;
			const int clientH = client.bottom - client.top;

			WCHAR text[1024] = {};
			swprintf_s(text,
				L"检测到疑似「全屏置顶覆盖层」窗口，可能是锁屏勒索 / 假登录框 / 假 UAC。\n\n"
				L"目标程序：%s  (PID %lu)\n"
				L"即将执行：%s\n\n"
				L"是否执行反制？（不理会、超时或关掉本窗 = 跳过，不会动它）",
				g_askProcessName[0] ? g_askProcessName : L"(未知)",
				static_cast<unsigned long>(g_askPid),
				RungActionName(g_askRung));

			HWND label = CreateWindowExW(0, L"STATIC", text,
				WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
				kAskMargin, 14, clientW - 2 * kAskMargin, clientH - 14 - kButtonH - 3 * kButtonGap,
				hwnd, nullptr, instance, nullptr);
			if (label && g_askFont) {
				SendMessageW(label, WM_SETFONT, reinterpret_cast<WPARAM>(g_askFont), TRUE);
			}

			// 按钮：居中排一行。[反制] [跳过] [反制（不再询问）]
			//
			// ⚠️ 按钮宽是**算出来的**，不是拍死的：三个按钮加起来若超过客户区，
			//    就按可用宽度均分缩小 —— 否则第三个按钮会被挤到窗口外点不到。
			struct ButtonSpec { int id; PCWSTR text; };
			const ButtonSpec specs[] = {
				{ kIdAllow,  L"反制" },
				{ kIdSkip,   L"跳过" },
				{ kIdAlways, L"反制（不再询问）" },
			};

			const int count = _countof(specs);
			const int availW = clientW - 2 * kAskMargin;
			int buttonW = kButtonW + 40;   // "不再询问"那个字多一点
			const int rowW = count * buttonW + (count - 1) * kButtonGap;
			if (rowW > availW) {
				buttonW = (availW - (count - 1) * kButtonGap) / count;
			}
			const int totalW = count * buttonW + (count - 1) * kButtonGap;
			int x = (clientW - totalW) / 2;
			if (x < kAskMargin) {
				x = kAskMargin;
			}
			const int y = clientH - kAskMargin - kButtonH;

			for (const ButtonSpec& spec : specs) {
				HWND button = CreateWindowExW(0, L"BUTTON", spec.text,
					WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
					x, y, buttonW, kButtonH, hwnd,
					reinterpret_cast<HMENU>(static_cast<INT_PTR>(spec.id)), instance, nullptr);
				if (button && g_askFont) {
					SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(g_askFont), TRUE);
				}
				x += buttonW + kButtonGap;
			}

			return 0;
		}

		case WM_COMMAND:
			switch (LOWORD(wp)) {
			case kIdAllow:
				InterlockedExchange(&g_askResult, AskAllow);
				DestroyWindow(hwnd);
				return 0;
			case kIdAlways:
				InterlockedExchange(&g_askResult, AskAllowAlways);
				DestroyWindow(hwnd);
				return 0;
			case kIdSkip:
			case IDCANCEL:
				InterlockedExchange(&g_askResult, AskSkip);
				DestroyWindow(hwnd);
				return 0;
			default:
				return 0;
			}

		case WM_TIMER:
			if (wp == kAskTimerId) {
				if (g_askStartedMs != 0 &&
					(GetTickCount64() - g_askStartedMs) >= g_askTimeoutMs) {
					// ★ v59：超时**不是**用户拒绝（见 AskAnswer::AskTimeout）。
					//    结论是"这次没问出结果"，主线程会决定重试还是放弃。
					InterlockedExchange(&g_askResult, AskTimeout);
					DestroyWindow(hwnd);
					return 0;
				}
				ReassertTopmost(hwnd);
			}
			return 0;

		case WM_CLOSE:
			// 用户**主动**点了 X（弹窗有标题栏，关它是有意为之）→ 尊重，按"跳过"。
			InterlockedExchange(&g_askResult, AskSkip);
			DestroyWindow(hwnd);
			return 0;

		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;

		default:
			return DefWindowProcW(hwnd, msg, wp, lp);
		}
	}

	DWORD WINAPI AskThreadProc(LPVOID) noexcept
	{
		HINSTANCE instance = GetModuleHandleW(nullptr);

		g_askFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
		if (!g_askFont) {
			g_askFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
		}

		// 居中在**目标窗口所在的那块显示器**上（多屏时这很关键：
		// 覆盖层在副屏，弹窗跑到主屏去用户一样看不见）。
		HMONITOR monitor = g_askTargetHwnd
			? MonitorFromWindow(g_askTargetHwnd, MONITOR_DEFAULTTONEAREST)
			: MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY);

		MONITORINFO info = { sizeof(info) };
		int x = 0;
		int y = 0;
		if (GetMonitorInfoW(monitor, &info)) {
			const int width = info.rcMonitor.right - info.rcMonitor.left;
			const int height = info.rcMonitor.bottom - info.rcMonitor.top;
			x = info.rcMonitor.left + (width - kAskWidth) / 2;
			y = info.rcMonitor.top + (height - kAskHeight) / 2;
		}

		// ★ v59：**不要 `WS_EX_TOOLWINDOW`**。旧版带它 ⇒ 弹窗没有任务栏按钮、
		//   也不出现在 Alt-Tab 里；而它的宿命恰恰是"被全屏覆盖层盖住" ——
		//   于是用户**没有任何办法**把它翻出来，只能等超时（= 反制白做）。
		//   带任务栏按钮后，用户至少能从任务栏点回来（配合 ReassertTopmost 的闪烁）。
		HWND hwnd = CreateWindowExW(
			WS_EX_TOPMOST,
			kAskClass, L"R3ShieldCore · 覆盖层反制",
			WS_POPUP | WS_CAPTION | WS_SYSMENU,
			x, y, kAskWidth, kAskHeight,
			nullptr, nullptr, instance, nullptr);

		if (!hwnd) {
			// 建不出窗口 → 不能静默杀进程，按"跳过"处理。
			InterlockedExchange(&g_askResult, AskSkip);
			InterlockedExchange(&g_askRunning, 0);
			return 0;
		}

		g_askStartedMs = GetTickCount64();
		g_askHwnd = hwnd;

		ShowWindow(hwnd, SW_SHOW);
		ReassertTopmost(hwnd);
		SetTimer(hwnd, kAskTimerId, kAskTimerMs, nullptr);

		MSG message;
		while (GetMessageW(&message, nullptr, 0, 0) > 0) {
			TranslateMessage(&message);
			DispatchMessageW(&message);
		}

		KillTimer(hwnd, kAskTimerId);
		g_askHwnd = nullptr;
		if (g_askFont) {
			DeleteObject(g_askFont);
			g_askFont = nullptr;
		}

		// 线程退出前保证一定有个结论（关窗/异常路径都不留 AskNone）。
		// ★ v59：兜底结论用 **AskTimeout** 而不是 AskSkip —— 这条路径上**没有人**
		//    表过态，按"用户拒绝"处理会白白永久放弃反制。
		InterlockedCompareExchange(&g_askResult, AskTimeout, AskNone);

		InterlockedExchange(&g_askRunning, 0);
		return 0;
	}

	void StartAsk(HWND hwnd, DWORD pid, ULONG rung, ULONG timeoutMs) noexcept
	{
		EnsureAskClassRegistered();

		InterlockedExchange(&g_askResult, AskNone);
		g_askTargetHwnd = hwnd;
		g_askPid = pid;
		g_askRung = rung;
		g_askTimeoutMs = (timeoutMs != 0) ? timeoutMs : kDefaultAskTimeoutMs;
		g_askStartedMs = 0;
		ProcessNameOf(pid, g_askProcessName, _countof(g_askProcessName));

		InterlockedExchange(&g_askRunning, 1);

		wil::unique_handle thread(CreateThread(nullptr, 0, AskThreadProc, nullptr, 0, nullptr));
		if (!thread) {
			// 起不了弹窗线程 = 问不出去，**不是**用户拒绝（见 AskTimeout 注释）。
			InterlockedExchange(&g_askRunning, 0);
			InterlockedExchange(&g_askResult, AskTimeout);
		}
	}

	// 是否已有**别的**进程正在等用户作答。
	//
	// ⚠️ 为什么需要它：结果槽（g_askResult）是**全局唯一**的，一次只能问一个。
	//    若在 A 的答案还没被收走时就为 B 发起新询问，StartAsk 会把结果槽清成
	//    AskNone ⇒ A 的答案被覆盖丢失（A 会被误判成"超时跳过"）。
	//    所以发起新询问前必须确认没有任何条目处于 askPending。
	bool AnyAskPending() noexcept
	{
		for (int i = 0; i < kMaxWatch; i++) {
			if (g_watch[i].askPending) {
				return true;
			}
		}
		return false;
	}

	// 记一次"没问出结果"（超时 / 弹窗线程异常退出 / 结果迟迟不收尾）。
	//
	// ★ v59 的核心修法：**超时不是用户拒绝**。
	//    旧版把超时直接当 AskSkip ⇒ `userDeclined=true` ⇒ 这个进程在保留期
	//    （未升级 60s / 已升级 600s）内**再也不会被反制**。而覆盖层攻击的
	//    场景里弹窗恰恰**最可能被覆盖层盖住** —— 用户根本没看见、也就没作答，
	//    反制于是在第一级就被永久关掉。这正是用户报的"窗口反制好像用不了"。
	//    现在改成有限重试：连续 kMaxAskTimeouts 次无应答才放弃，并且明确
	//    告诉用户"要强制就改成 neutralize_overlay=1"。
	void NoteAskTimeout(WatchEntry& entry, DWORD pid, ULONGLONG now) noexcept
	{
		entry.askPending = false;
		entry.askTimeouts++;
		entry.lastAskMs = now;
		entry.lastActionMs = now;   // 让 kCooldownMs 生效，别连着弹
		g_stats.AskTimeouts++;
		g_handledThisScan = true;

		if (entry.askTimeouts >= kMaxAskTimeouts) {
			entry.userDeclined = true;
			g_stats.Declined++;
			printf("[sentinel] 询问连续 %d 次无人应答 -> 放弃反制 pid=%u "
				"（覆盖层可能盖住了弹窗；要强制反制请把 ini 改成 neutralize_overlay=1）\n",
				entry.askTimeouts, pid);
		}
		else {
			printf("[sentinel] 询问超时（第 %d/%d 次）pid=%u -> 稍后重试\n",
				entry.askTimeouts, kMaxAskTimeouts, pid);
		}
	}

	void HandleCandidate(HWND hwnd, DWORD pid, ULONGLONG now) noexcept
	{
		// ★ 按 pid 查条目（不是 hwnd）：同一个进程重建窗口后仍接着原来的阶梯走。
		int index = FindEntry(pid);
		if (index < 0) {
			InsertEntry(pid, hwnd, now);
			return;   // 进入观察期
		}

		WatchEntry& entry = g_watch[index];
		// 刷新代表窗口 —— 顽固程序被 DestroyWindow 后常会重建一个新窗口，
		// 但它的升级进度（rungs）必须接着算，不能因为换了 hwnd 就归零。
		entry.hwnd = hwnd;

		// 用户已经对这个进程说过"跳过" → 不再打扰
		// （进程退出、或 60s 保留期到期后条目会被清掉，届时可重新判定）。
		if (entry.userDeclined) {
			return;
		}

		if ((now - entry.firstSeenMs) < kGraceMs) {
			return;
		}
		if (entry.lastActionMs != 0 && (now - entry.lastActionMs) < kCooldownMs) {
			return;
		}

		// ④⑤ 是"结束进程"。到第 ⑤ 级就不再往上加 —— 失败就按冷却重试，
		// 而不是把 rungs 无限递增（旧版 else 分支会把 3、4、5… 全当"销毁"）。
		int rung = entry.rungs;
		if (rung > 4) {
			rung = 4;
		}

		// ------------------------------------------------------------------
		// 级别 2：动手之前先弹窗问用户
		//
		// ⚠️ 询问是**异步**的：StartAsk 起一个线程去弹窗，这里立刻返回。
		//    下一次 Tick（100ms 后）再来收结果。所以本函数**不会**卡主循环。
		// ------------------------------------------------------------------
		if (g_level >= 2 && !g_askAlwaysAllow) {
			const LONG answer = InterlockedCompareExchange(&g_askResult, AskNone, AskNone);

			// ★ 用 pid 而不是 hwnd 认领结果：等待期间程序可能已经把窗口重建了，
			//    hwnd 变了但用户答的还是同一个进程，不能因此把答案丢掉。
			if (g_askPid == pid && answer != AskNone) {
				// 本窗口的询问有结论了 → 收掉。
				InterlockedExchange(&g_askResult, AskNone);
				entry.askPending = false;

				if (answer == AskTimeout) {
					// ★ 超时 != 用户拒绝（见 NoteAskTimeout 注释）→ 有限重试。
					NoteAskTimeout(entry, pid, now);
					return;
				}

				if (answer == AskSkip) {
					// 用户**明确**表态（点「跳过」/ Esc / 点 X）→ 尊重，不再打扰。
					entry.userDeclined = true;
					entry.lastActionMs = now;
					g_stats.Declined++;
					g_handledThisScan = true;
					printf("[sentinel] 用户选择跳过：hwnd=%p pid=%u（本进程不再打扰）\n",
						static_cast<void*>(hwnd), pid);
					return;
				}

				if (answer == AskAllowAlways) {
					g_askAlwaysAllow = true;
					printf("[sentinel] 用户选择「不再询问」：本次运行内后续反制不再弹窗\n");
				}
				// AskAllow / AskAllowAlways → 落下去执行本 rung。
			}
			else if (entry.askPending) {
				// 还在等用户作答。两个"卡死"兜底：
				//   ① 弹窗线程异常死掉（结果永远是 AskNone）
				//   ② 结果迟迟不收尾（超过 timeout + 5s）
				// 命中任一 → 记一次**超时**（不是"用户拒绝"），绝不把窗口永久
				// 卡在"等待中"，也不白扔反制机会。
				const bool threadDead =
					InterlockedCompareExchange(&g_askRunning, 0, 0) == 0;
				const bool overran = entry.lastAskMs != 0 &&
					(now - entry.lastAskMs) > (static_cast<ULONGLONG>(g_askTimeoutMs) + 5000);

				if (threadDead || overran) {
					InterlockedExchange(&g_askResult, AskNone);
					printf("[sentinel] 询问未收尾（%s）hwnd=%p\n",
						threadDead ? "弹窗线程已退出" : "结果迟迟不收尾",
						static_cast<void*>(hwnd));
					NoteAskTimeout(entry, pid, now);
					return;
				}
				return;
			}
			else if (!AnyAskPending() && InterlockedCompareExchange(&g_askRunning, 0, 0) == 0) {
				// 没有别的询问在跑、也没有没被收走的答案 → 发起本次询问。
				StartAsk(hwnd, pid, static_cast<ULONG>(rung), g_askTimeoutMs);
				entry.askPending = true;
				entry.lastAskMs = now;
				g_stats.Asked++;
				g_handledThisScan = true;
				printf("[sentinel] 询问用户：hwnd=%p pid=%u 动作=%s\n",
					static_cast<void*>(hwnd), pid, RungActionNameNarrow(rung));
				return;
			}
			else {
				// 别的进程正在被询问（或它的答案还没被收走）—— 本次不动手。
				// ★ 绝不能在这里发起新询问：结果槽是全局唯一的，会覆盖掉
				//   前一个进程的答案（见 AnyAskPending 注释）。
				return;
			}
		}

		const char* actionName = RungActionNameNarrow(rung);
		const char* detail = "";
		bool ok = false;

		if (rung == 0) {
			ok = TryMinimize(hwnd);
			g_stats.Minimized++;
		}
		else if (rung == 1) {
			ok = TryClose(hwnd);
			g_stats.Closed++;
		}
		else if (rung == 2) {
			ok = DestroyViaHiddenParent(hwnd, &detail);
			g_stats.Destroyed++;
		}
		else if (rung == 3) {
			// ④：先让目标自己的消息循环退出；不行再远程调它的 ExitProcess。
			ok = TryExitFunction(hwnd, pid);
			g_stats.ExitRequested++;
		}
		else {
			// ⑤：内核直接拆地址空间，目标跑不到任何清理代码。
			ok = TryTerminateProcess(pid);
			g_stats.Terminated++;
		}

		entry.lastActionMs = now;
		entry.rungs = rung + 1;
		g_handledThisScan = true;

		g_stats.LastHwnd = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(hwnd));
		g_stats.LastAction = static_cast<ULONG>(rung + 1);
		g_stats.LastResult = ok ? 1u : 0u;

		// ★ v59：失败时把**原因**打出来（尤其第 ③ 级有两种完全不同的失败，
		//    见 DestroyViaHiddenParent 注释）—— 否则"黑屏但窗口没关掉"这种
		//    现象在日志里只剩一个"失败"，根本没法定位。
		if (!ok && detail && detail[0] != '\0') {
			printf("[sentinel] 反制覆盖层 hwnd=%p pid=%u 动作=%s 结果=失败（%s）\n",
				static_cast<void*>(hwnd), pid, actionName, detail);
		}
		else {
			printf("[sentinel] 反制覆盖层 hwnd=%p pid=%u 动作=%s 结果=%s\n",
				static_cast<void*>(hwnd), pid, actionName, ok ? "成功" : "失败");
		}
		fflush(stdout);
	}

	BOOL CALLBACK EnumProc(HWND hwnd, LPARAM param) noexcept
	{
		const ULONGLONG now = static_cast<ULONGLONG>(param);

		const OverlayVerdict verdict = ClassifyOverlay(hwnd);

		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);

		if (verdict != OverlayVerdict::Match) {
			// ★ v59：只对"真的像覆盖层"的窗口打一行诊断（见 LogNearMiss 注释）。
			//    没有它，"没反制"在日志里永远是空白 —— 分不清"没扫到"和"被签名挡掉"。
			//
			// ★ v60：**不再用 `CanActOnProcess` 卡诊断**。原来"能不能动手"为假时连
			//    一行都不打 ⇒ 又一处静默（进程被跳过表命中 / 完整性更高时同样查不出来）。
			//    现在一律打，并把"可动=是/否"写进那一行（见 LogNearMiss）。
			if (verdict != OverlayVerdict::Invalid
				&& IsNearMissCandidate(hwnd)
				&& !IsShellClass(hwnd)) {
				LogNearMiss(hwnd, pid, verdict);
			}
			return TRUE;
		}

		if (IsShellClass(hwnd) || !CanActOnProcess(pid)) {
			g_stats.Skipped++;
			return TRUE;
		}

		g_stats.Detected++;
		g_lastScanMatched++;

		// 一次扫描最多处理一个窗口：动作里有短 Sleep，避免拖慢主循环。
		if (!g_handledThisScan) {
			// ★ v59：命中的**是什么窗口**要落一次日志（每 hwnd 一次，不刷屏）。
			//    用户报"反制没效果"时，这几行能直接看出命中的是不是病毒那个窗口。
			if (!AlreadyLoggedHwnd(hwnd)) {
				RememberLoggedHwnd(hwnd);
				RECT wr = {};
				GetWindowRect(hwnd, &wr);
				WCHAR name[MAX_PATH] = {};
				ProcessNameOf(pid, name, _countof(name));
				printf("[sentinel] 命中覆盖层 hwnd=%p pid=%u 进程=%ls "
					"style=0x%08llX ex=0x%08llX rect=(%ld,%ld,%ld,%ld)\n",
					static_cast<void*>(hwnd), pid, name[0] ? name : L"(未知)",
					static_cast<unsigned long long>(GetWindowLongPtrW(hwnd, GWL_STYLE)),
					static_cast<unsigned long long>(GetWindowLongPtrW(hwnd, GWL_EXSTYLE)),
					wr.left, wr.top, wr.right, wr.bottom);
				fflush(stdout);
			}
			HandleCandidate(hwnd, pid, now);
		}
		return TRUE;
	}
}

namespace R3ShieldCoreSentinel
{
	void Start(ULONG level, ULONG askTimeoutMs) noexcept
	{
		Stop();
		g_level = (level <= 2) ? level : 2;
		g_enabled = (g_level != 0);
		g_askTimeoutMs = (askTimeoutMs != 0) ? askTimeoutMs : kDefaultAskTimeoutMs;
		g_askAlwaysAllow = false;
		g_lastScanMs = 0;
		g_lastHeartbeatMs = 0;
		g_stats = {};

		// ★ v59：诊断状态也要清 —— 否则重启后"差一点命中"再也打不出来
		//    （旧 hwnd 还在表里，或者干脆表满了）。
		for (int i = 0; i < kMaxNearMiss; i++) {
			g_loggedHwnd[i] = nullptr;
		}
		g_loggedHwndCount = 0;

		if (g_enabled) {
			EnsureClassRegistered();
		}
	}

	void Stop() noexcept
	{
		g_enabled = false;
		g_level = 0;
		for (int i = 0; i < kMaxWatch; i++) {
			g_watch[i] = {};
		}

		// 询问状态清干净 —— 否则下次 Start 会捡到一个陈旧的 AskNone/AskRunning，
		// 而且弹窗还会留在屏幕上。
		if (g_askHwnd) {
			PostMessageW(g_askHwnd, WM_CLOSE, 0, 0);
		}
		InterlockedExchange(&g_askResult, AskNone);
		g_askTargetHwnd = nullptr;
		g_askPid = 0;
		g_askStartedMs = 0;
		g_askAlwaysAllow = false;
	}

	bool IsEnabled() noexcept
	{
		return g_enabled;
	}

	ULONG Level() noexcept
	{
		return g_level;
	}

	void Tick() noexcept
	{
		if (!g_enabled) {
			return;
		}

		g_stats.Ticks++;

		const ULONGLONG now = GetTickCount64();
		if (g_lastScanMs != 0 && (now - g_lastScanMs) < kScanIntervalMs) {
			return;
		}
		g_lastScanMs = now;
		g_stats.Scans++;
		g_handledThisScan = false;
		g_lastScanMatched = 0;   // ★ v60：本扫描命中数（累计值另计，见心跳注释）

		EnumWindows(&EnumProc, static_cast<LPARAM>(now));
		PurgeEntries(now);

		// ★ v59 心跳：没有它的时候，"没反制"与"根本没扫"在 r3shieldcore-console.log
		//    里完全一样（铁律 75：日志里没有 != 没跑）。这一行让"引擎在扫、
		//    扫到了 N 个、其中 M 个不满足签名"变成**可读**的。
		//
		// ⚠️ **第一次扫描就立刻打一行**（不等 60s）：否则短命测试（几秒就停引擎）
		//    里根本看不到这一行，等于"sentinel 到底起没起来"还是查不出来。
		if (g_lastHeartbeatMs == 0 || (now - g_lastHeartbeatMs) >= kHeartbeatMs) {
			g_lastHeartbeatMs = now;
			// 顺手把失效的 hwnd 从"已打过日志"表里剔除（见 PruneLoggedHwnds）。
			PruneLoggedHwnds();
			printf("[sentinel] 心跳 级别=%u 扫描=%u 本扫描命中=%u 累计命中=%u 排除=%u 差一点命中=%u "
				"动作[最小化=%u 关闭=%u 销毁=%u 退出=%u 杀进程=%u] "
				"询问[发起=%u 超时=%u 用户跳过=%u]\n",
				static_cast<unsigned long>(g_level),
				static_cast<unsigned long>(g_stats.Scans),
				static_cast<unsigned long>(g_lastScanMatched),
				static_cast<unsigned long>(g_stats.Detected),
				static_cast<unsigned long>(g_stats.Skipped),
				static_cast<unsigned long>(g_stats.NearMiss),
				static_cast<unsigned long>(g_stats.Minimized),
				static_cast<unsigned long>(g_stats.Closed),
				static_cast<unsigned long>(g_stats.Destroyed),
				static_cast<unsigned long>(g_stats.ExitRequested),
				static_cast<unsigned long>(g_stats.Terminated),
				static_cast<unsigned long>(g_stats.Asked),
				static_cast<unsigned long>(g_stats.AskTimeouts),
				static_cast<unsigned long>(g_stats.Declined));
			// ★ v60：立刻刷出去。
			//   ⚠️ 别把这条当"修了行被拆断的 bug" —— 实测（`grep -c '^ 询问\['`
			//      = 0 续行）日志行**本来就是完整的**，早先看到的"拆行"是终端
			//      在 ~140 列处折行造成的**显示**假象，不是文件内容。
			//   真正的理由：引擎自己重定向 stdout 时用的是 `_IONBF`（这里 flush 是
			//   空操作）；但本模块**也被探针/测试脚手架直接链接**（sentinel_probe），
			//   那里的 stdout 是**默认全缓冲**的 —— 不 flush 就会让这一行滞留在
			//   缓冲区里，几秒就结束的测试根本读不到它（"日志里没有 != 没跑"）。
			fflush(stdout);
		}
	}

	Stats GetStats() noexcept
	{
		return g_stats;
	}
}
