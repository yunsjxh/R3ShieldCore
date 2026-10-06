#pragma once

//
// 进程 / 线程行为监控层。
//
// 与 RegistryGuard / FileGuard 并列的第三、第四类监控对象，同一个进程里
// 各自独立 Install。跳过判定（系统程序 / 引擎自身 / 排除项）复用
// RegistryGuard::IsBypassed 的结果。
//
// 覆盖范围：
//   进程创建  NtCreateUserProcess（Win7+ 的正路）、NtCreateProcessEx（底层）
//             NtCreateProcess（v18 老 API —— 无参数块、拿不到路径，按特征判）
//   进程终止  NtTerminateProcess（只记录 —— 调用即生效，没有询问的余地）
//   线程创建  NtCreateThreadEx（远程线程 = 注入的核心手法）
//             NtCreateThread（v18 老 API —— 独立 detour，判据同远程线程）
//   线程终止  NtTerminateThread（只记录）
//
// 拦截策略是"高危才拦"：
//   普通进程/线程创建只在 LOG 语义下记录，不弹窗不拒绝 ——
//   系统每秒创建大量线程，一刀切会把机器打瘫。
//   命中高危规则（System32/临时目录起进程、Office→cmd、远程线程注入…）
//   才强制走询问路径。
//
namespace ProcessGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（同 RegistryGuard / FileGuard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
