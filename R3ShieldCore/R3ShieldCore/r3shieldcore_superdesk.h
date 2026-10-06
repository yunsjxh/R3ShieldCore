#pragma once

#include <windows.h>

//
// UIAccess 令牌启动和旧版 Winlogon 面板自检实现。
//
// UIAccess 置顶配方照搬 KSword：优先同会话 winlogon.exe 的 SYSTEM 令牌，
// 临时模拟 SYSTEM，复制 SYSTEM primary token，改写 TokenSessionId，设置并复查
// TokenUIAccess，然后用 CreateProcessWithTokenW/CreateProcessAsUserW 启动默认桌面实例。
// 旧的 Winlogon 面板入口仍用于独立安全桌面自检，不参与主窗口超级置顶结果。
//
namespace R3ShieldCoreSuperDesk
{
	// 带 UIAccess 令牌启动当前 GUI 的新实例。新实例在默认交互桌面运行，
	// 不启动安全桌面面板；确认子进程令牌有效后，父实例退出自己的引擎会话。
	bool LaunchUiAccessInstance(DWORD parentPid, DWORD* childPid, DWORD* errorCode) noexcept;
	bool WaitForUiAccessParentExit(DWORD timeoutMs, DWORD* errorCode) noexcept;

	// 旧版安全桌面面板命令行标记。带这个参数的实例只跑面板，不启动引擎。
	constexpr PCWSTR PanelArgument = L"--super-panel";
	constexpr PCWSTR UiAccessArgument = L"--uiaccess-instance";

	// 全链路自检标记。带这个参数的实例当"引擎"用：走完整条 A 配方
	//（造 SYSTEM 令牌 → 改会话 → 设 TokenUIAccess → CreateProcessWithTokenW
	// 到 winsta0\Winlogon），把面板拉起来，等它自己退（6 秒），然后收尾。
	//
	// ⚠️ 与 PanelArgument 的区别很重要：
	//   --super-panel        只跑面板窗口本身，**在当前桌面上**，
	//                        只能验证"窗口画得出来"，验证不了 A 配方。
	//   --superdesk-selftest 跑的是**整条配方**，面板在 winsta0\Winlogon 上，
	//                        这才是"能不能在安全桌面上显示"的判定依据。
	constexpr PCWSTR SelfTestArgument = L"--superdesk-selftest";

	// ★ UIAccess 重启链路自检标记（v33）。
	//
	// ⚠️ 与 SelfTestArgument 的区别（**这两条路以前被搞混过，见铁律 22**）：
	//   --superdesk-selftest  跑 A 配方（Launch()）→ 安全桌面面板。**不碰按钮路径**。
	//   --uiaccess-selftest   跑 **LaunchUiAccessInstance()** —— 也就是用户
	//                         **点「超级置顶」按钮**时真正走的那条路。
	//
	//   加这个入口的原因：A 配方自检全绿，但用户点按钮仍然失败
	//   （`[gui] UIAccess handoff failed err=1460`）。因为两者是**两个独立函数**，
	//   自检覆盖不到按钮路径。这个入口就是用来补这个洞的。
	constexpr PCWSTR UiAccessSelfTestArgument = L"--uiaccess-selftest";

	// 当前进程是不是被当成 UIAccess 链路自检拉起来的。
	bool IsUiAccessSelfTestInvocation() noexcept;

	// UIAccess 链路自检入口（由 app.cpp 在启动引擎之前调用）。
	// 返回 0 = LaunchUiAccessInstance 成功，非 0 = 失败（细节写在 superdesk-panel.log）。
	int RunUiAccessSelfTest() noexcept;

	// 面板子进程入口（由 app.cpp 在启动引擎之前调用）。
	int RunPanel() noexcept;

	// 全链路自检入口（由 app.cpp 在启动引擎之前调用）。
	// 返回 0 = 配方成功，非 0 = 失败（细节写在 superdesk-panel.log）。
	int RunSelfTest() noexcept;

	// 当前进程是不是被当成面板拉起来的（命令行含 --super-panel）。
	bool IsPanelInvocation() noexcept;

	// 当前进程是不是被当成自检拉起来的（命令行含 --superdesk-selftest）。
	bool IsSelfTestInvocation() noexcept;

	// 引擎侧：在 winsta0\Winlogon 上拉起面板。
	// 成功返回 true，*panelPid 为面板进程 id；失败返回 false 并填 *errorCode。
	bool Launch(DWORD enginePid, DWORD* panelPid, DWORD* errorCode) noexcept;

	// 引擎侧：通知面板退出（不阻塞、不等它退完）。
	void Stop() noexcept;

	// 引擎侧：面板是否还活着。只在 GUI 线程调用。
	bool IsRunning() noexcept;
}
