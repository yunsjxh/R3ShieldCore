#pragma once

//
// 输入钩子监控层（鼠标 / 键盘）。
//
// 键盘记录器 / 鼠标记录器在用户态只有两条路：
//   ① SetWindowsHookEx 装钩子
//        WH_KEYBOARD_LL(13) / WH_MOUSE_LL(14)  —— 低级钩子，全系统监听，
//          不需要往别人进程里注入 DLL（我们的 DLL 在钩子回调里被调）
//        WH_KEYBOARD(2) / WH_MOUSE(7) + dwThreadId==0 —— 全局钩子，
//          系统会把 lpfn 所在的 DLL 注入到**所有**同类 GUI 线程
//        WH_JOURNALRECORD(0) / WH_JOURNALPLAYBACK(1) —— 直接录制/回放输入
//   ② RegisterRawInputDevices 注册原始输入设备（不装钩子，直接读设备）
//        带 RIDEV_INPUTSINK 时窗口不在前台也收 —— 后台偷输入
//
// ⚠️ 能力边界：
//   - GetAsyncKeyState / GetKeyState 轮询式记录看不到（太热，没法挂）
//   - 内核驱动级别的键盘过滤（kbdclass 之上）看不到
//   - 通过 COM（如 UI Automation）读输入看不到
//   - 挂钩子的进程如果是**提权进程**，我们的 hook 在它里面照样生效
//     （注入不分权限），但普通权限的我们拦不住它去做别的事
//
//   定位仍是**可见性**：让用户知道"有程序在监听我的输入"。
//
// 判据分层（见 r3shieldcore_rules.cpp 的 IsHighRiskInputHook）：
//   低级钩子 / 全局钩子 / 输入日志 / INPUTSINK → 高危
//   线程内钩子 / 普通原始输入                  → 只记录
//
namespace InputHookGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	//
	// 收尾：等所有"在飞"的 hook 跑完。
	//
	// 与其它 guard 同理，必须先把 hook 停用再调这个，
	// 然后才能 MH_Uninitialize()。见 registry_guard.h 的详细说明。
	//
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
