#pragma once

//
// 进程创建旁路监控层。
//
// ⚠️ 和 ProcessGuard（已挂 NtCreateUserProcess）是互补关系，不是重复：
//
//   NtCreateUserProcess 是**最终出口** —— 所有进程创建最终都经过它，
//   所以"谁起了谁、起了什么" ProcessGuard 已经在看了。
//
//   这一层看的是**上下文差异**，只有下面这些应用层 API 才能提供的信号：
//     CreateProcessWithTokenW   → token 被换过（提权 / 窃取 token 后横向）
//     CreateProcessWithLogonW   → 带着**别人的凭据**起进程（凭据滥用）
//     ShellExecuteEx            → 走 shell 关联解析，可能被劫持（.lnk/.bat/COM 关联）
//     WinExec / system          → shellcode 与老载荷最常用的一层
//
//   这些 API 的调用频率比 NtCreateUserProcess 低几个数量级，
//   所以**可以全部判高危**，不用担心噪音。真正高频的 CreateProcessW
//   走 NtCreateUserProcess，不在这里重复报（避免同一件事出两条事件）。
//
// ⚠️ 能力边界：用户态出口。直调 ntdll!NtCreateUserProcess（配合
//    NtCreateProcessEx / RtlCreateUserProcess）能完全绕开这几个 API。
//    所以定位是 **可见性**：把"用特殊上下文起进程"这件事暴露出来，
//    而不是"保证起不了进程"。真边界在内核（进程/线程创建回调）。
//
namespace SpawnGuard
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
