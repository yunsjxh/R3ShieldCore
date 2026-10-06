#pragma once

//
// 计划任务持久化监控层（v12）。
//
// ⚠️ 补的是哪一类缺口 —— 以及为什么必须用 vtable patch：
//
//   计划任务（schtasks / 任务计划程序 / 各种工具箱）是**持久化**最常用的
//   一招：注册一个任务，重启后自动执行。整条链是：
//
//     应用（schtasks.exe / 工具箱）
//       → CoCreateInstance(CLSID_TaskScheduler)   ← 拿 ITaskService
//       → ITaskService::Connect
//       → ITaskFolder::RegisterTaskDefinition      ← ★ 真正的落点
//       → RPC 到 svchost 里的 Task Scheduler 服务 ← 白名单，挂不上
//       → 写 HKLM\...\Schedule\TaskCache\...
//
//   和驱动那层的 SCM 盲区**完全同一个结构**：真正的执行者在 svchost，
//   在白名单里，一个 hook 都不挂。所以必须在**调用方一侧**拦。
//
//   但和驱动那层不同的是：服务 API 是**导出函数**（CreateServiceW），
//   可以直接 GetProcAddress + MinHook；而 Task Scheduler 是**纯 COM 接口**，
//   没有任何导出函数可挂 —— 只有 vtable。
//
//   ⇒ 所以本 guard 用 **vtable patch**：CoCreateInstance 拿到 ITaskService 后，
//     把它 vtable 里 RegisterTaskDefinition 那一格（**slot 11**）换成我们的函数。
//
// ⚠️ vtable 槽位不是猜的 —— 槽位表由 tools/taskprobe.cpp 在实机上验证过
//    （该探针打印 vtable 并实际调用 GetFolder/slot 4 反证槽位对齐）：
//
//     ITaskFolderVtbl 布局（含 IDispatch 那 7 个槽）：
//       [0..2]   IUnknown       QueryInterface / AddRef / Release
//       [3..6]   IDispatch      GetTypeInfoCount / GetTypeInfo / GetIDsOfNames / Invoke
//       [7]      get_Name
//       [8]      get_Path
//       [9]      GetFolder
//       [10]     GetFolders
//       [11]     CreateFolder
//       [12]     DeleteFolder
//       [13]     GetTask
//       [14]     GetTasks
//       [15]     DeleteTask
//       [16]     RegisterTask
//       [17]     RegisterTaskDefinition   ← ★ 拦截点
//       [18]     GetSecurityDescriptor
//       [19]     SetSecurityDescriptor
//
//    ⚠️⚠️ **同一个接口的正确槽位必须与 taskprobe.exe 的输出对账** ——
//        "GetFolder 在 slot 4"那个实测结论是对 ITaskService 说的；
//        ITaskFolder 的槽位表要按上面这份 IDispatch 版数（+7 偏移）。
//        改这个常量前**先在目标系统上跑 taskprobe --vt 数一遍**。
//
// ⚠️ 能力边界（写清楚）：
//   · **同一个 ITaskFolder 实例只 patch 一次**（按 vtable 地址去重）——
//     否则每次 CoCreateInstance 都新建一个 vtable 保护区，越挂越多。
//     vtable 是**模块级共享**的（同一 DLL 里所有实例共用一个 vtable），
//     所以 patch 一次就够，后面 CoCreateInstance 拿到的实例自动生效。
//   · vtable patch 会被 DEP/CFG 影响吗：本场景是改**可读写数据段里的
//     函数指针**（combase 的 vtable 在 .rdata，需 VirtualProtect 成 RW），
//     不是改代码，不受 CFG 限制。但**改 .rdata 是全局影响**——
//     本进程内所有 ITaskFolder 都受影响，这正是想要的。
//   · 直接写 TaskCache 注册表绕过 COM → 不由本 guard 覆盖，
//     走注册表规则表（TaskCacheWrite 那一档，见 ScheduledTaskOp）。
//   · 从别的进程 RPC 直调 —— 不覆盖（那是内核/ETW 的活）。
//
namespace ScheduledTaskGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// ★ 懒 patch 入口 —— 由 ComHijackGuard 的 CoCreateInstance hook 调用。
	//
	//   为什么必须有这个（实测踩到的坑）：
	//     Install() 在**注入那一刻**跑。注入发生在进程启动初期，
	//     此时 COM 通常**还没初始化** → Install 里的
	//     CoCreateInstance(CLSID_TaskScheduler) 返回 CO_E_NOTINITIALIZED
	//     → 拿不到 ITaskService 实例 → **vtable patch 根本没装**。
	//     等目标进程后来自己 CoInitialize + CoCreateInstance 时，
	//     我们的一条 hook 都没有 → 整条链静默抓不到。
	//
	//   所以补一条可靠的触发点：ComHijackGuard 已经挂了 combase!CoCreateInstance，
	//   在它的 hook 里（原函数返回后）把成功创建的 ITaskService 交给这里 patch。
	//   riid 用来判定"这确实是要 ITaskService 的那次激活"。
	//
	//   参数 pv 是 CoCreateInstance 产出的接口指针（可能为 null）。
	//   返回值仅作日志参考。
	bool TryPatchTaskService(void* pv, const GUID& riid) noexcept;

	// 已 patch 的 vtable 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（顺序约束同其它 guard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
