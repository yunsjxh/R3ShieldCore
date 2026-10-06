#pragma once

//
// 令牌窃取 / 冒充监控层（v13）。
//
// ⚠️ 先读这段，搞清楚它到底拦什么、拦不住什么。
//
// 挂载点（全部在 advapi32.dll，实测均为直接导出，可 MinHook 挂）：
//
//   一档 · 准备（只记录，不上报高危）
//     advapi32!OpenProcessToken        → TokenTheftOp::OpenProcessToken
//     advapi32!OpenThreadToken         → TokenTheftOp::OpenThreadToken
//
//   二档 · 使用（高危）
//     advapi32!DuplicateTokenEx        → TokenTheftOp::DuplicateTokenEx
//     advapi32!ImpersonateLoggedOnUser → TokenTheftOp::ImpersonateLoggedOnUser
//     advapi32!SetThreadToken          → TokenTheftOp::SetThreadToken
//     （CreateProcessWithTokenW 已在 SpawnGuard 里挂 —— 见下方说明）
//
//   三档 · 铺路（高危，但**精细判据**：只有启用 SeDebug/SeImpersonate/SeTcb
//         这几个"能拿到别人令牌"的特权才报）
//     advapi32!AdjustTokenPrivileges   → TokenTheftOp::AdjustTokenPrivileges
//
// ⚠️ 为什么一档不判高危（**这是本 guard 存活的关键**）：
//    OpenProcessToken 是"拿一个可以复制/被冒充的令牌句柄"。这句话听起来
//    很可怕，但调用它的正常程序非常多：
//      · 进程管理器 / 任务管理器（读对方的令牌信息）
//      · 调试器（判断目标权限）
//      · 备份/同步软件（判断谁能访问某个文件）
//      · **我们自己的 ProcessGuard 自我保护 hook**（剥句柄权限时反查）
//      · 大量安装器（判断是否提权）
//    实测教训（v10 的 hosts、v12 的 SetSecurityInfo）：只要把"看起来很危险
//    但满天飞"的调用判高危，噪音就会淹没真信号 —— 功能性失效。
//    所以一档降级为"关联判据的一环"：见下面 TokenChainState。
//
// ⚠️ 为什么 CreateProcessWithTokenW 只在 SpawnGuard 里挂：
//    它同时是"进程创建旁路"和"令牌使用"。两处都挂 = 同一件事两条事件。
//    这里通过 **共享的 TokenChainState**（见下）让 SpawnGuard 那次事件
//    带上序列信息 —— 不重复挂 API。
//
// ⚠️ 看不到的（写清楚，别让人误以为全覆盖）：
//    · 直 syscall（NtOpenProcessToken / NtDuplicateToken / NtSetInformationThread）
//    · 内核态令牌操作
//    · 用命名管道 / COM 模拟（CoImpersonateClient）一类的隐式冒充
//    · 通过 RPC 让别人的进程替他做事（根本没有本地令牌操作）
//    定位是**可见性**，不是"保证偷不到令牌"。
//
namespace TokenTheftGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（同其它 guard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;

	//
	// 令牌链关联状态（跨 guard 共享，v13）。
	//
	// 为什么要跨 guard：完整的窃取链是
	//     OpenProcessToken（本 guard 一档）
	//       → DuplicateTokenEx（本 guard 二档）
	//         → CreateProcessWithTokenW（在 SpawnGuard）
	// 只在本 guard 内部记状态的话，第三步接不上。
	//
	// 用 `thread_local` 而不是全局变量：令牌窃取是**单线程顺序**行为
	// （同一个线程一步步走完），而同一进程里别的线程在干别的事 ——
	// 用全局状态会被无关线程的调用污染。
	//
	// 用法：
	//   一档调用后 → MarkTokenPrepared()
	//   二档调用前 → WasTokenPreparedRecently()  取关联
	//   二档调用后 → ClearTokenPrepared()        （链已走完，清掉）
	//
	void MarkTokenPrepared() noexcept;
	bool WasTokenPreparedRecently() noexcept;
	void ClearTokenPrepared() noexcept;
}
