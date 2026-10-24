#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>
#include <string>
#include <vector>

//
// 简易 Win32 主窗口面板。
//
// 工程使用 Windows 子系统；app.cpp 的 stdout/stderr 会重定向到
// r3shieldcore-console.log，GUI 窗口显示统计和状态。
//
// 界面以只读监控为主：概览、事件日志、进程、配置四页由 GUI 线程绘制。
// 可操作项包括模式切换、清空内存统计、复制日志路径；模式切换只往一个
// 原子变量里放请求，真正的引擎状态变更由 app.cpp 的主循环执行。
//
namespace R3ShieldCoreGui
{
	struct Options
	{
		R3ShieldCore::Mode Mode;
		bool HookReads;
		bool HookHive;
		bool HookSetInfo;
		bool HookFile;
		bool HookProcess;  // 进程创建/终止监控
		bool HookThread;   // 线程创建监控（远程）
		bool HookSelfThread; // 是否连本进程线程也记录
		bool HookDriver;   // 驱动加载/卸载监控
		bool HighRisk;   // 高危规则是否开启（关闭则底部不显示高危统计行）
		const WCHAR* LogPath;
		ULONG ExcludePathCount;
		// ★ v51：`never_inject=` 名单条数。控制台横幅（app.cpp）早就打了，
		//   但 GUI 一直没显示 —— 于是从界面看，用户永远不知道自己有几个
		//   程序正在**裸奔**（一个 hook 都没有）。
		ULONG NeverInjectPathCount;
		ULONG PromptTimeoutMs;
		// ★ v61：高危进程提示级别（0 = 关 / 1 = 仅记录 / 2 = 记录 + 界面）。
		// 界面用它决定底部栏要不要**多画一行** —— 见 r3shieldcore_procwatch.h。
		// 高度不能写死常量，否则开启后底部栏会盖住内容。
		ULONG HighRiskProcessAlert;
		// ★ v62：ARK 页开关与扫描间隔（ini `ark_enabled` / `ark_scan_ms`）。
		// 配置页只做展示 —— 改它要改 ini 并重启引擎（与其它开关一致）。
		bool ArkEnabled;
		ULONG ArkScanMs;
		// ★ v63：ARK 页的**界面刷新间隔**（ini `ark_refresh_ms`）。
		// 它只决定"界面多久重取 + 重绘一次"，不改变引擎的枚举节奏
		// （那是 `ArkScanMs`）—— 两者区别见 r3shieldcore_config.h。
		ULONG ArkRefreshMs;
		// ★ v78：「高级」页要显示**规则的总闸**。
		//
		// 规则的三个面各自受一个 ini 开关管辖（`spoof_reg` / `spoof_clipboard` /
		// `spoof_reg_enum`，默认**全关**）。开关关着 ⇒ 规则一律不生效。
		// 界面上必须把这件事**显示出来** —— 否则用户写完规则、存了、重启引擎，
		// 什么都没发生，而界面上看不出任何原因（铁律 97）。
		//
		// ⚠️ 这三个值来自**引擎真正读到的那份配置**（`policy.Flags2`），
		//    不是界面自己再解析一遍 ini —— 再解析一遍就会出现"界面显示开、
		//    引擎其实是关"的假象，比不显示更坏（铁律 195）。
		bool SpoofReg;
		bool SpoofClipboard;
		bool SpoofRegEnum;
	};

	// 建立窗口（非阻塞，内部起一个 GUI 线程）。
	bool Start(const Options& options) noexcept;

	// 不启动引擎，只验证窗口置顶状态。
	// 供发布包自检使用。
	int RunTopMostSelfTest() noexcept;

	// ★ v77：**界面预览**模式（`--gui-preview`）。
	//   把完整窗口建起来并一直跑着，但**不初始化注入引擎** ——
	//   所以可以在开发机上安全地反复看界面、截图核对（铁律 175 禁跑引擎）。
	//   和 RunTopMostSelfTest 是同一位置分流（引擎初始化之前），
	//   区别是它"建窗→自检→立刻退"，本函数"建窗→等你关"。
	//   配合环境变量 `R3SHIELDCORE_START_TAB` 可直接停在指定页签。
	int RunPreview() noexcept;

	// 销毁窗口并结束 GUI 线程。
	void Stop() noexcept;

	// 主循环里定期调用，把最新的引擎状态喂给窗口。
	// injectedTotal = 累计注入进程数。
	void Update(ULONG injectedTotal) noexcept;

	// ★★★ v103：「配置」页应用完、引擎重启之后，把新的真值喂回界面。
	//
	// 同时会**清掉待提交寄存区** —— 那是"开关不弹回旧值"的唯一正确时机
	// （早清 ⇒ 引擎还没重启完，开关先弹回旧值；不清 ⇒ 界面显示的值
	// 与引擎里的真实值不一致，界面在撒谎）。
	//
	// ★ `options.LogPath` 会被**深拷贝**进界面自己的缓冲，调用方传
	//   栈上局部量也安全（v103 之前这里只拷指针，是个潜伏的野指针）。
	void SetOptions(const Options& options) noexcept;

	// ★ v91：引擎是否连上（主循环每轮喂一次）。
	//
	// 为什么必须有：界面是 **WINDOWS 子系统**（没有控制台），`printf` 全进日志，
	// 而日志在运行期是**独占**打不开的 ⇒ 任何"静默失败"用户都看不到。
	// 实测事故：上一次会话留下的僵尸引擎占着单实例互斥体与管道 ⇒ 新界面连不上
	// ⇒ 点「切换模式」只写一行日志，用户看到的就是"点了完全没反应、徽章不变"。
	// 现在徽章会直接显示「未连接」。
	void SetEngineConnected(bool connected) noexcept;

	// ★ v91：窗口内的一次性提示（默认 8 秒）。
	//
	// 占用标题栏**副标题那一行**（同矩形，不与标题/按钮打架），红字。
	// 用于"模式切换失败：引擎未连接"这类必须让用户看见、但又只出现在日志里的结论。
	void ShowNotice(const std::wstring& text, ULONGLONG durationMs = 8000) noexcept;

	// 界面线程 → 引擎线程：把「点了切换模式按钮」这件事传出去。
	// 返回 true 表示这次取到了一个待处理的请求（取走即清空）。
	// 引擎线程调用，不阻塞。
	bool TakePendingMode(R3ShieldCore::Mode& mode) noexcept;

	// GUI 线程请求当前引擎会话退出，让已经通过 TokenUIAccess 握手的新实例接管。
	bool TakeUiAccessRestartRequest() noexcept;

	// 界面线程 → 引擎线程：用户点了「退出引擎」按钮。
	// 返回 true 表示这次取到了退出请求（取走即清空）。
	// 和模式切换、UIAccess 接管一样，界面线程只置位，真正的收尾由 app.cpp
	// 主循环做（反注入 → 关窗口 → 退出进程），界面线程绝不直接退进程。
	bool TakeQuitRequest() noexcept;

	// ★★★ v103：界面线程 → 引擎线程：用户在「配置」页按下了
	// 「应用并重启引擎」。
	//
	// 为什么必须走这条路，而不是界面自己写 ini：
	//   · 写 ini 和**重启引擎**是主程序的活（只有它知道 exe 目录、
	//     才知道怎么干净地停引擎并反注入）；
	//   · 界面线程上做文件 I/O + 停引擎，会把整屏重绘卡住
	//     （v101 就是栽在"在 UI 线程上做重活"）。
	//
	// `lines` 每条形如 `hook_file=1`，**只含与当前值不同的项**。
	// 取走即清空；返回值 false 表示没有待处理的请求。
	bool TakeConfigApplyRequest(std::vector<std::wstring>& lines,
		bool& arkPresent, bool& arkEnabled) noexcept;

	// 引擎线程 → 界面：告诉窗口当前模式已经变成什么了（刷新徽章）。
	void SetMode(R3ShieldCore::Mode mode) noexcept;
}
