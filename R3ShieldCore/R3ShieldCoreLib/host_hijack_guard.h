#pragma once

//
// 宿主劫持 / 加载器监控层（v15）。
//
// ⚠️ 补的是哪一类缺口：
//
//   前面所有 guard 都在问"你（当前进程）干了什么危险的事"。
//   这一层问的是"**你有没有在劫持一个可信宿主，让它以后替我们干活**" ——
//   攻击者自己不加载、不执行，是把配置留在系统里，等 explorer / lsass /
//   每个新进程 / 登录界面去按配置加载。
//
// 四个子面（对应 ObjectType::HostHijack 的 HostHijackOp）：
//
//   ① 注册表全局注入键（HostHijackOp::InjectionRegistryKey）
//      AppInit_DLLs / AppCertDlls / IFEO Debugger / LSA 认证包 /
//      Winlogon Notify / ShellServiceObjectDelayLoad / BootExecute。
//      ⚠️ 挂载点**不在本 guard** —— 写键的是 NtSetValueKey，已由
//      RegistryGuard 挂住。本 guard 提供一个回调
//      EvaluateInjectionKeyWrite()，RegistryGuard 在写完键值后调它，
//      由它读回值内容做"是否指向用户可写目录"的判定。
//      这样避免同一个 API 挂两次（MinHook 不允许重复 detour 同一地址）。
//
//   ② 加载器侧加载变体（LoadLibraryEx / RegisterDllNotification）
//      LoadLibraryExW —— 带 flags 的加载（可挂起加载、从数据文件加载）。
//      LdrRegisterDllNotification —— 注册"加载通知回调"，等于在加载决策
//      链上插一手。LdrLoadDll 已由 DllLoadGuard 挂住，这里只补这两条出口。
//
//   ③ 远程映射注入（MapSectionRemote / QueueApcRemote）
//      NtMapViewOfSection 目标 **不是** 自己进程 → 反射式/手工映射注入。
//      QueueUserAPC 目标 **不是** 自己进程 → APC 注入。
//      ⚠️ 这是 v14 注入链（Allocate/Write/Protect/CreateThread）之外的
//      **第二条注入路径**：不写内存、不起线程，靠映射已有 section +
//      劫持目标进程里已有的线程（APC）。
//
//   ④ 凭据宿主劫持（CredentialHost）
//      Security Packages / Credential Provider 注册。也走注册表写，
//      同样由 RegistryGuard 转调 EvaluateInjectionKeyWrite()。
//
// ⚠️ 能力边界：
//   · 注册表侧依赖 RegistryGuard 已挂 NtSetValueKey —— 若用户把
//     hook_registry 关了，这一面也失效（本 guard 不重复挂）。
//   · NtMapViewOfSection 与 DllLoadGuard 都挂同一个 API —— MinHook
//     不允许同一地址两次 detour，所以**本 guard 只在 DllLoadGuard 未挂
//     映射 hook 时**才挂（见 Install 里的协调逻辑）；两者都挂会有一方失败。
//     实际做法：映射判定合并进本 guard 的 hook，DllLoadGuard 侧保留原样
//     （DllLoad 判"加载了哪个 DLL"，HostHijack 判"跨进程映射这段"）。
//
namespace HostHijackGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（顺序约束同其它 guard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;

	//
	// 注册表注入键写的评估入口（由 RegistryGuard 在 NtSetValueKey
	// 成功后调用）。
	//
	// keyPath   —— 归一化后的注册表路径（\REGISTRY\MACHINE\...）
	// valueName —— 值名（如 "AppInit_DLLs" / "Debugger" / "Shell"）
	// value     —— 值内容（DLL/程序路径；可能是空或非路径）
	//
	// 返回 true 表示"这次写入构成宿主劫持"（已自行上报事件）。
	// 返回 false 表示"不是劫持或本 guard 未启用" —— 调用方无需处理。
	//
	bool EvaluateInjectionKeyWrite(PCWSTR keyPath, PCWSTR valueName, PCWSTR value) noexcept;

	//
	// 跨进程映射的补充评估（由 DllLoadGuard 的 NtMapViewOfSection hook 调用）。
	//
	// ⚠️ 为什么是"补充"而不是"取代"：
	//    NtMapViewOfSection 已被 DllLoadGuard 挂住（MinHook 不允许同一地址两次
	//    detour）。DllLoadGuard 已经能判"是不是跨进程映像映射"，并报一个
	//    DllLoad 事件。本函数在此之上再报一条 **HostHijack** 语义的事件
	//    （HostHijackOp::MapSectionRemote），让宿主劫持页签能看到这条注入。
	//
	// 调用契约：**只在 DllLoadGuard 已经确认 remote == true 时才调**。
	// 本进程映射不调（那是反射式加载，归 DllLoad 管）。
	//
	// 返回 true 表示本 guard 决定拦（调用方应把 NTSTATUS 改成 STATUS_ACCESS_DENIED）。
	//
	bool EvaluateRemoteMapSection(HANDLE targetProcessHandle) noexcept;
}
