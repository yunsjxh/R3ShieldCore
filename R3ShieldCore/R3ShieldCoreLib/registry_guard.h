#pragma once

//
// 注册表行为拦截层。
//
// 在每个被注入的进程里调用一次 Install()：
//   - 系统进程 / 引擎自身 / 策略排除项  → 不挂载任何 hook，零开销
//   - 其余进程                          → 挂载 ntdll 注册表 API
//
// hook 内的判定只看一个缓存好的 bool（IsBypassed），不做路径比较、不加锁。
//
namespace RegistryGuard
{
	// engineProcess 是引擎进程句柄，可为 NULL（此时无法识别引擎自身）。
	bool Install(HANDLE engineProcess) noexcept;

	// 当前进程是否被排除在监控之外。
	bool IsBypassed() noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	//
	// 收尾：等所有"在飞"的 hook 跑完。
	//
	// 调用方必须先把 hook 停用（MH_DisableHook(MH_ALL_HOOKS)）再调这个，
	// 然后才能安全地 MH_Uninitialize()。否则会释放掉别人正在用的 trampoline，
	// 那个线程返回时就是野指针 —— 实测会让宿主进程 c0000005 崩在
	// "r3shieldcore-lib.dll_unloaded"。
	//
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
