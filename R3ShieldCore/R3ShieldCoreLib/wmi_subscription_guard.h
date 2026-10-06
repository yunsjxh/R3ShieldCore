#pragma once

//
// WMI 事件订阅持久化监控层（v13）。
//
// ⚠️ 先读这段，搞清楚它拦什么、为什么这么设计。
//
// 攻击模式（"无文件持久化"的代表，MITRE T1546.003）：
//   攻击者在 root\subscription 命名空间里摆三件套：
//     ① __EventFilter              —— "什么事件触发"（如开机后 5 分钟 / 某进程启动）
//     ② __EventConsumer            —— "触发后干什么"（CommandLineEventConsumer
//                                     直接跑命令行 → 完全无文件落地）
//     ③ __FilterToConsumerBinding  —— 把 ① 和 ② 绑起来（不绑不生效）
//   三件套摆好后就永久生效（重启后 WMI 服务自动加载），而且
//   **磁盘上没有可执行文件** —— 传统 AV 扫文件扫不到。
//
// 挂载点（实测 vtable 槽位，见 tools/wmiprobe.exe）：
//   wbemprox!?             —— 无导出可挂，只能 vtable patch
//   IWbemLocator::ConnectServer         = slot 3   （vtable 在 wbemprox.dll）
//   IWbemServices::PutInstance          = slot 14  （vtable 在 fastprox.dll）
//   IWbemServices::ExecQuery            = slot 20
//   IWbemServices::ExecNotificationQuery= slot 22
//   IWbemServices::ExecMethod           = slot 24
//
// ★ 与 ScheduledTaskGuard（v12）的关键差别 —— 这里**不需要懒 patch**：
//     IWbemServices 是 `ConnectServer` 的**返回值** —— 我们挂了
//     ConnectServer，就能在它返回后立刻拿到 services 指针并 patch 它的
//     vtable。而 `ConnectServer` 是**唯一**拿到 IWbemServices 的标准路径，
//     所以这个链是完整的。（计划任务那边没有这样一个"唯一的产出点"，
//     才不得不靠 CoCreateInstance 补刀。）
//
// ★ 命名空间是第一道闸（判据存活关键）：
//     WMI 是 Windows 的管理总线，**正常软件大量使用** —— 系统中心、
//     杀软、设备管理、Office、甚至我们的系统 API 都在 root\cimv2 里
//     查东西。只有 `root\subscription` 才是持久化的地盘。
//     所以：ConnectServer 时先看命名空间是不是 root\subscription；
//     不是 → 那个 IWbemServices **不 patch**（零开销、零噪音）。
//
// ⚠️ 看不到的：
//   · 直连 DCOM（RPC 到远程机器的 WMI）—— 本 guard 只覆盖本机 inproc
//   · 用 WMI 的 .NET / PowerShell 包装（System.Management）—— 底层仍是
//     这些接口，所以**能看到**（除非用了别的 provider 绕开）
//   · 直接写 WMI 仓库文件（OBJECTS.DATA）—— 那是另一个面（文件监控）
//   定位是**可见性**。
//
namespace WmiSubscriptionGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（同其它 guard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;

	// 已 patch 的 IWbemServices vtable 数量（供自检 / 日志）。
	int PatchedServicesCount() noexcept;

	//
	// 懒 patch（v13）。
	//
	// ⚠️ 与 ScheduledTaskGuard::TryPatchTaskService 同一个坑与同一个解法：
	//    WMI 的对象是"用到才激活"的 COM 对象 —— 注入那一刻 IWbemLocator
	//    通常还没被创建（注入线程上的 CoInitializeEx 也未必成功）。
	//    所以由 ComHijackGuard 的 CoCreateInstance hook 在**原函数返回后**
	//    按 riid == IID_IWbemLocator 补装。
	//
	// 返回 true 表示这次确实 patch 上了（或此前已 patch）。
	//
	bool TryPatchWbemLocator(void* pv, const GUID& riid) noexcept;
}
