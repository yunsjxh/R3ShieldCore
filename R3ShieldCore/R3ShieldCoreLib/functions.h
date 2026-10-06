#pragma once

BOOL GetFullAccessSecurityDescriptor(
    _Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
    _Out_opt_ PULONG SecurityDescriptorSize);

// 当前进程是否提权运行。
bool IsProcessElevated() noexcept;

// UAC / 安全桌面进程不能接受本用户态注入。
//
// v42：判定逻辑搬到 `inject_policy.{h,cpp}`（三档：Skip / Thin / Full）。
//       本函数只回答"要不要**跳过**"（即 Thin 与 Full 都返回 false）。
//       瘦名单成员会被**注入**，但只装 `CreateProcessInternalW`。
bool ShouldSkipProcessInjection(HANDLE process) noexcept;

// 瘦注入是否被允许（Policy 位 `FlagInjectShellThin`，ini: `inject_shell_thin`）。
// ★ Policy 不可用时返回 **true**（默认允许）—— 否则瘦会话里的进程创建 hook
//   会因为"读不到策略"而把自己锁死。
bool IsThinInjectAllowed() noexcept;

// ★ v49：镜像路径是否命中**用户自定义**的「绝不注入」名单（ini: `never_inject=`）。
//   语义 = 完整路径前缀 + 路径边界（见 `InjectPolicy::MatchesNeverInjectPath`）。
// ★ Policy 不可用时返回 **false** ⇒ 照常注入（安全方向：多监控，不是漏监控）。
bool IsUserNeverInject(PCWSTR imagePath) noexcept;

//
// 共享对象（互斥体、共享内存）用的安全描述符。
//
// 提权时返回全放行 + Untrusted 完整性标签的版本，低完整性进程也能打开；
// 没提权时退化成仅 DACL 的版本。
//
// 为什么必须区分：带 SACL 的描述符需要 SeSecurityPrivilege 才能在对象上生效，
// 没提权时 CreateMutex / CreateFileMapping 会直接以 ERROR_PRIVILEGE_NOT_HELD
// 失败 —— 整个通道都建不起来。实测踩过这个坑。
//
// 失败返回空指针，调用方自己决定要不要继续。
// allowWrite=false 用于策略映射：被注入进程只能以 FILE_MAP_READ 打开。
wil::unique_hlocal GetSharedObjectSecurityDescriptor(bool allowWrite = true) noexcept;
