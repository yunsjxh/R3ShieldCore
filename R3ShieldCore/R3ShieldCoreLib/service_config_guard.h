#pragma once

//
// 服务 / 安全对象权限变更监控层（v11）。
//
// ⚠️ 补的是哪一类缺口：
//
//   DriverGuard 那层挂的是"装服务 / 改服务二进制 / 启服务"，判据是
//   **二进制路径 + 服务类型**（内核驱动才重点报）。它覆盖不了另一条
//   经典提权链 —— **改服务的安全描述符**：
//
//       sc sdset <服务名> "D:(A;;RPWPCR;;;WD)"
//       ↑ 给 Everyone 加上"启动/停止/改配置/读取"权限
//       ↓
//       普通用户从此能：
//          sc config <服务名> binPath= C:\evil.exe   改这个 SYSTEM 服务的二进制
//          sc start  <服务名>                         用它起的 SYSTEM 身份执行
//
//   整条链**不写任何服务键、不动任何二进制路径**，所以 DriverGuard 的
//   判据一个都不命中。而在用户态能观察到的唯一入口就是
//   advapi32!SetServiceObjectSecurity（sc sdset 的落点）。
//
//   NtSetSecurityObject 是更底层的那条 —— 它能改**任意内核对象**的 ACL
//   （进程 / 线程 / 文件 / 注册表键 / 服务对象…）。挂在 ntdll 上，
//   serve 的是"绕过 advapi32 直接改 ACL"的场景。
//
// ⚠️ 能力边界（照旧要说清）：
//   · 直 syscall NtSetSecurityObject 能绕过 ntdll hook。
//   · 改注册表里服务的 Security 值（HKLM\SYSTEM\...\Services\<名>\Security）
//     也能达到同样效果 —— 那条路走的是注册表 hook（RegistryGuard 已覆盖
//     \REGISTRY\MACHINE\SYSTEM 的写操作，但**是否判高危**要看规则表）。
//   · 真正的执法点是内核对象回调（ObRegisterCallbacks）+ 服务 DACL 解析，
//     用户态 hook 只是"让用户知情"。
//
namespace ServiceConfigGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（顺序约束同其它 guard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
