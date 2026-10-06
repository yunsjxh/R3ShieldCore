#pragma once

//
// 文件行为拦截层。
//
// 与 RegistryGuard 并列：同一个进程里两个模块都可能在 Install() 时挂 hook，
// 各自独立判断本进程是否被排除。跳过判定（系统程序/引擎自身/排除项）
// 复用 RegistryGuard::IsBypassed 的结果，见 file_guard.cpp 的 Install。
//
// 文件系统比注册表热得多（一个浏览器每秒可能开几百个文件），所以：
//   - 默认**不挂**，必须 r3shieldcore.ini 里 hook_file=1 显式开启
//   - 只挂写类操作，不挂 NtOpenFile 的读打开
//   - 路径只在需要上报时才解析（NtQueryObject 不便宜）
//
namespace FileGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// NtSetSecurityObject 只能由一个 guard 创建 MinHook。
	bool OwnsNtSetSecurityObjectHook() noexcept;

	//
	// 收尾：等所有"在飞"的 hook 跑完。
	//
	// 与 RegistryGuard 同理，必须先把 hook 停用再调这个，
	// 然后才能 MH_Uninitialize()。见 registry_guard.h 的详细说明。
	//
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
