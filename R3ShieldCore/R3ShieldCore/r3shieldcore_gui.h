#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

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
	};

	// 建立窗口（非阻塞，内部起一个 GUI 线程）。
	bool Start(const Options& options) noexcept;

	// 不启动引擎，只验证窗口置顶状态。
	// 供发布包自检使用。
	int RunTopMostSelfTest() noexcept;

	// 销毁窗口并结束 GUI 线程。
	void Stop() noexcept;

	// 主循环里定期调用，把最新的引擎状态喂给窗口。
	// injectedTotal = 累计注入进程数。
	void Update(ULONG injectedTotal) noexcept;

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

	// 引擎线程 → 界面：告诉窗口当前模式已经变成什么了（刷新徽章）。
	void SetMode(R3ShieldCore::Mode mode) noexcept;
}
