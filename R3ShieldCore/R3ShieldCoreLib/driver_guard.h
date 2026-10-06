#pragma once

//
// 内核驱动加载监控层。
//
// 用户态能观察到"驱动被加载"的唯一入口是 NtLoadDriver ——
// 它吃的是 HKLM\SYSTEM\CurrentControlSet\Services\<名> 里的 ImagePath，
// 由 SCM（服务控制管理器）或直接调用者触发加载 .sys 进内核。
//
// 覆盖：
//   NtLoadDriver   —— 加载驱动（高危：非系统目录的 .sys 一律询问）
//   NtUnloadDriver —— 卸载驱动（反取证：干掉别人的防护驱动）
//
// ⚠️ 这一层的局限（必须说清楚）：
//   用户态只能挡住"服务方式加载"，挡不住真正内核层的加载路径
//   （ZwLoadDriver 直接调、内核回调里加载、或已有驱动自己做事）。
//   要完整覆盖驱动加载/模块加载，需要内核驱动挂
//   PsSetLoadImageNotifyRoutine —— 那是另一套东西，不在当前范围。
//
//   .sys 文件本身的"落地"（被写进磁盘）由 FileGuard 覆盖，
//   规则表里 \Windows\System32\drivers\ 已经是高危路径。
//
namespace DriverGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（同 RegistryGuard / FileGuard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
