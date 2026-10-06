#include "stdafx.h"
#include "service_config_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

// v12：SetSecurityInfo / SetNamedSecurityInfoW 的 objectType 形参用 SE_OBJECT_TYPE
//       （以及 SE_SERVICE / SE_KERNEL_OBJECT 常量）—— 这两个都在 AccCtrl.h 里。
//       ⚠️ 不引这个头的话，MSVC 会把 SE_OBJECT_TYPE 当成未知类型，
//          连带着**整个函数形参列表作废**，报的却是函数体内"objectType 未声明"
//          （假象：看起来像作用域问题，实际是类型没定义）。
#include <accctrl.h>
#include "file_guard.h"

//
// 服务 / 安全对象权限变更监控层（v11）。
//
// 挂载点：
//   advapi32!SetServiceObjectSecurity  → ServiceConfigOp::SetServiceSecurity
//   ntdll!NtSetSecurityObject          → ServiceConfigOp::SetKernelObjectSecurity
//
// ⚠️ WIN32_LEAN_AND_MEAN 把 winsvc.h 排除掉了 —— SE_SERVICE / SERVICE_*
//    这些常量得自己引（与 driver_guard.cpp 同理）。这里不引 winsvc.h
//    而是列出用到的几个常量值，避免和 windows.h 的宏打架。
//
// ntstatus.h 直接 include 会和 winnt.h 的重复定义打架，所以按项目里
// 既有的做法（process_guard.cpp 同款）用带保护的宏自己定义。
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

namespace
{
	// ------------------------------------------------------------------
	// 常量（winsvc.h 里的值，避免引头文件）
	// ------------------------------------------------------------------
	constexpr SECURITY_INFORMATION SI_SERVICE_ALL = OWNER_SECURITY_INFORMATION
		| GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;

	// 权限位：服务控制权。用于在日志里把"给了哪些权限"翻成人话。
	// 这些是 SC_MANAGER / SERVICE 的访问位（winsvc.h）。
	constexpr DWORD SVC_QUERY_CONFIG = 0x0001;
	constexpr DWORD SVC_CHANGE_CONFIG = 0x0002;
	constexpr DWORD SVC_QUERY_STATUS = 0x0004;
	constexpr DWORD SVC_ENUMERATE_DEPENDENTS = 0x0008;
	constexpr DWORD SVC_START = 0x0010;
	constexpr DWORD SVC_STOP = 0x0020;

	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef BOOL(WINAPI* SetServiceObjectSecurityPtr)(SC_HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
	typedef NTSTATUS(NTAPI* NtSetSecurityObjectPtr)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);

	// v12 补强：SetServiceObjectSecurity 的**底层旁路**。
	//   实测（tools/apiprobe.exe）：两者都在 advapi32 直接导出，可挂。
	//   · SetSecurityInfo       —— handle 版，SetServiceObjectSecurity 内部最终调它。
	//   · SetNamedSecurityInfoW —— 名字版，`sc sdset` 实际走的是这条（传服务名）。
	//   只挂上层 SetServiceObjectSecurity 的话，攻击者直调这两条就绕过了。
	typedef DWORD(WINAPI* SetSecurityInfoPtr)(
		HANDLE handle, SE_OBJECT_TYPE objectType, SECURITY_INFORMATION securityInfo,
		PSID owner, PSID group, PACL dacl, PACL sacl);

	typedef DWORD(WINAPI* SetNamedSecurityInfoWPtr)(
		LPWSTR objectName, SE_OBJECT_TYPE objectType, SECURITY_INFORMATION securityInfo,
		PSID owner, PSID group, PACL dacl, PACL sacl);

	SetServiceObjectSecurityPtr pOriginalSetServiceObjectSecurity = nullptr;
	NtSetSecurityObjectPtr pOriginalNtSetSecurityObject = nullptr;
	SetSecurityInfoPtr pOriginalSetSecurityInfo = nullptr;
	SetNamedSecurityInfoWPtr pOriginalSetNamedSecurityInfoW = nullptr;

	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;

	enum class Action
	{
		Pass,
		Record,
		Block,
	};

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// ------------------------------------------------------------------
	// 上报与判定
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ServiceConfig);
		if (event.TimeStamp == 0) {
			event.TimeStamp = NowFileTime();
		}
		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();

		R3ShieldCoreChannel::Publish(event);
	}

	R3ShieldCore::Verdict PromptFallbackVerdict() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
			return static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
		}

		return R3ShieldCore::Verdict::Deny;
	}

	Action Evaluate(R3ShieldCore::ServiceConfigOp op, R3ShieldCore::Event& event, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ServiceConfig);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all）----
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskServiceConfig(static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				// 复用"来自 SCM 服务 API"的标记 —— UI 据此上色。
				event.Flags |= R3ShieldCore::FlagEventServiceInstall;
			}
		}

		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// ⚠️ 与其它 guard 一致：必须再判一次 mode == Ask（理由见 registry_guard.h）。
		const bool canAsk = allowAsk && (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask));
		if (!canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return Action::Block;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：走“通道可用性”包装 —— 管理员启动引擎时通道打不开，
		//   LOG 模式下降级放行（否则高危操作被静默拒，不可识别）。
		//   见 r3shieldcore_prompt.h 的 AskWithChannelGuard 说明。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return Action::Record;
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return Action::Block;
	}

	// 把 SECURITY_INFORMATION 翻成人话，写进 ValueName。
	void SetSecurityInfoDetail(R3ShieldCore::Event& event, SECURITY_INFORMATION info) noexcept
	{
		WCHAR buffer[128] = {};
		size_t offset = 0;

		auto append = [&](PCWSTR text) noexcept {
			if (offset > 0) {
				wcsncat_s(buffer, _countof(buffer), L"+", _TRUNCATE);
			}
			wcsncat_s(buffer, _countof(buffer), text, _TRUNCATE);
			offset = wcslen(buffer);
		};

		if ((info & OWNER_SECURITY_INFORMATION) != 0) { append(L"所有者"); }
		if ((info & GROUP_SECURITY_INFORMATION) != 0) { append(L"组"); }
		if ((info & DACL_SECURITY_INFORMATION) != 0) { append(L"DACL"); }
		if ((info & SACL_SECURITY_INFORMATION) != 0) { append(L"SACL"); }

		if (offset == 0) {
			swprintf_s(buffer, L"info=0x%X", static_cast<unsigned>(info));
		}

		wcsncpy_s(event.ValueName, buffer, _TRUNCATE);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
	}

	// 从 SECURITY_DESCRIPTOR 里尽量摘出 DACL 是否存在 —— 只做展示，
	// 不解析 ACE 内容（解析 SDDL 是另一个量级的活）。
	void TryAnnotateDescriptor(R3ShieldCore::Event& event, PSECURITY_DESCRIPTOR descriptor) noexcept
	{
		if (!descriptor) {
			return;
		}

		SECURITY_DESCRIPTOR_CONTROL control = 0;
		DWORD revision = 0;
		if (!GetSecurityDescriptorControl(descriptor, &control, &revision)) {
			return;
		}

		WCHAR suffix[96] = {};
		swprintf_s(suffix, L"（描述符 rev=%u ctrl=0x%04X%s）", revision, control,
			(control & SE_DACL_PRESENT) ? L"，含 DACL" : L"");
		wcsncat_s(event.ValueName, suffix, _TRUNCATE);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
	}

	// ------------------------------------------------------------------
	// hook：SetServiceObjectSecurity
	// ------------------------------------------------------------------
	BOOL WINAPI SetServiceObjectSecurity_Hook(SC_HANDLE service, SECURITY_INFORMATION info,
		PSECURITY_DESCRIPTOR descriptor)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"修改服务安全描述符（服务对象 DACL/SACL）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		SetSecurityInfoDetail(event, info);
		TryAnnotateDescriptor(event, descriptor);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ServiceConfigOp::SetServiceSecurity, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalSetServiceObjectSecurity(service, info, descriptor);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：NtSetSecurityObject
	// ------------------------------------------------------------------
	//
	// ⚠️ 这是更底层、更热的一条 —— 任何"改 ACL"的动作最终都到它
	//    （SetSecurityInfo / SetNamedSecurityInfo / 文件权限修改 …）。
	//    所以**必须做前置过滤**，否则日志会被 ACL 操作刷爆：
	//    只对"DACL/SACL 变更"上报，纯 OWNER/GROUP 变更放行。
	//
	//    另外：SE_DACL_AUTO_INHERITED 之类的系统正常维护也走这里，
	//    这里按"改了 DACL/SACL"这一条统一记，交给用户判断。
	//
	NTSTATUS NTAPI NtSetSecurityObject_Hook(HANDLE handle, SECURITY_INFORMATION info,
		PSECURITY_DESCRIPTOR descriptor)
	{
		// 热路径过滤：只在带 ACL 变更意图时才上报。
		const bool touchesAcl = (info & (DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)) != 0;
		if (!touchesAcl) {
			return pOriginalNtSetSecurityObject(handle, info, descriptor);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"修改内核对象安全描述符（DACL/SACL）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		SetSecurityInfoDetail(event, info);
		TryAnnotateDescriptor(event, descriptor);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ServiceConfigOp::SetKernelObjectSecurity, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		const NTSTATUS result = pOriginalNtSetSecurityObject(handle, info, descriptor);
		event.Status = static_cast<ULONG>(result);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：SetSecurityInfo / SetNamedSecurityInfoW（v12 补强）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么要补这两条（铁律 12「挂了一个 API ≠ 挂了这件事」）：
	//    SetServiceObjectSecurity(SC_HANDLE) 只是一个**便利包装**，它内部
	//    把 SC_HANDLE 转成底层句柄再调 SetSecurityInfo。攻击者只要直接
	//    CreateService + OpenService 拿句柄，或干脆按**服务名**调
	//    SetNamedSecurityInfoW（这正是 `sc sdset` 的实现路径），
	//    就完全绕开了我们唯一挂着的那个导出。
	//
	// ⚠️ 两条都是**极热**路径（改任意文件/注册表/内核对象 ACL 都经过），
	//    所以必须做 objectType 前置过滤 —— 只对"服务 / 内核对象"上报，
	//    文件/注册表/打印机等交给各自 guard（或直接放行），否则日志雪崩。
	//
	//    过滤规则：
	//      · SE_SERVICE(2)       → 服务 ACL 变更，正是"服务权限提升"的核心。
	//      · SE_KERNEL_OBJECT(6) → 任意内核对象（进程/线程/事件/互斥体…），
	//                              放宽它常被用来让普通用户拿到高权限对象。
	//      其余 objectType 一律**直接透传**，不进 CHANNEL。
	//
	//    另外：必须带 DACL/SACL 变更意图（与 NtSetSecurityObject 同款过滤）。
	//    纯 OWNER/GROUP 变更不算提权路径，放行。
	//
	//    为什么**只对 SE_SERVICE 上报**（v12 实测修正）：
	//      SE_KERNEL_OBJECT 是**极热**的 —— 实测 msedge 每创建一个渲染进程
	//      就会改一次内核对象（进程/线程/作业）的 DACL，一次会话刷几百条。
	//      这正是 v10 那个"噪音淹没真信号"的老坑换个地方复发：
	//      真正的"服务权限提升"信号被 msedge 的日常行为淹没 = 功能性失效。
	//
	//      而且内核对象这条路**本来就有一条更可靠的汇合点**：
	//      任何 ACL 变更最终都会到 `ntdll!NtSetSecurityObject`
	//      （我们已挂，且它带 DACL/SACL 过滤）。
	//      所以这里对内核对象**直接透传**，不重复上报 —— 避免同一次调用
	//      在日志里出现两行（SetSecurityInfo 一行 + NtSetSecurityObject 一行）。
	//
	//      ⇒ 判据收紧为：只有「服务对象」的 ACL 变更才在这里上报。
	//        （这才是 `sc sdset` / 给普通用户授予服务控制权那条提权链。）
	//
	bool IsServicePermissionObject(SE_OBJECT_TYPE objectType, SECURITY_INFORMATION info) noexcept
	{
		if ((info & (DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION)) == 0) {
			return false;
		}

		return objectType == SE_SERVICE;
	}

	DWORD WINAPI SetSecurityInfo_Hook(HANDLE handle, SE_OBJECT_TYPE objectType,
		SECURITY_INFORMATION info, PSID owner, PSID group, PACL dacl, PACL sacl)
	{
		// 热路径：非服务对象直接透传，零开销。
		if (!IsServicePermissionObject(objectType, info)) {
			return pOriginalSetSecurityInfo(handle, objectType, info, owner, group, dacl, sacl);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath,
			L"修改服务安全描述符（SetSecurityInfo —— 服务对象 DACL/SACL）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		SetSecurityInfoDetail(event, info);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ServiceConfigOp::SetServiceSecurity, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return ERROR_ACCESS_DENIED;
		}

		const DWORD result = pOriginalSetSecurityInfo(handle, objectType, info, owner, group, dacl, sacl);
		event.Status = result;
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	DWORD WINAPI SetNamedSecurityInfoW_Hook(LPWSTR objectName, SE_OBJECT_TYPE objectType,
		SECURITY_INFORMATION info, PSID owner, PSID group, PACL dacl, PACL sacl)
	{
		if (!IsServicePermissionObject(objectType, info)) {
			return pOriginalSetNamedSecurityInfoW(objectName, objectType, info, owner, group, dacl, sacl);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		// ⚠️ 不要把条件表达式/字符串字面量直接塞进 wcsncpy_s 的第 2 个参数 ——
		//    数组实参会退化成指针，编译器会改选 (ptr, size_t, src, size_t) 那个
		//    重载，于是报"只给了 2 个参数"。先落到具名指针变量再传（或用 _TRUNCATE）。
		wcsncpy_s(event.KeyPath,
			L"按名称修改服务安全描述符（SetNamedSecurityInfoW）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		// 服务名带进 ValueName 便于溯源（这正是 `sc sdset <服务名> ...` 传的那个参数）。
		if (objectName && objectName[0]) {
			wcsncpy_s(event.ValueName, objectName, _TRUNCATE);
			event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		} else {
			SetSecurityInfoDetail(event, info);
		}
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ServiceConfigOp::SetServiceSecurity, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return ERROR_ACCESS_DENIED;
		}

		const DWORD result = pOriginalSetNamedSecurityInfoW(objectName, objectType, info, owner, group, dacl, sacl);
		event.Status = result;
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// 挂载
	// ------------------------------------------------------------------
	bool QueueHook(LPCSTR moduleName, LPCSTR functionName, LPVOID detour,
		LPVOID* original, bool required) noexcept
	{
		HMODULE module = GetModuleHandleA(moduleName);
		if (!module) {
			if (required) {
				LOG(L"ServiceConfigGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"ServiceConfigGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"ServiceConfigGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"ServiceConfigGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace ServiceConfigGuard
{
	int HookCount() noexcept
	{
		return g_hookCount;
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"ServiceConfigGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	bool Install(HANDLE /*engineProcess*/) noexcept
	{
		if (g_installed) {
			return true;
		}

		if (RegistryGuard::IsBypassed()) {
			g_bypass = true;
			g_installed = true;
			return true;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookServiceConfig) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ServiceConfigGuard: hook_service_config 未开启，本进程不挂服务权限 hook");
			return true;
		}

		g_bypass = false;

		// advapi32（SetServiceObjectSecurity）与 ntdll（NtSetSecurityObject）
		// 在任何进程里都已加载，不需要主动 LoadLibrary。
		HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		if (advapi32) {
			QueueHook("advapi32.dll", "SetServiceObjectSecurity",
				reinterpret_cast<LPVOID>(SetServiceObjectSecurity_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalSetServiceObjectSecurity), true);

			// v12 补强：底层旁路两条（见上面 hook 处注释）。
			// 都用 false —— 补强失败不该让整个 guard 挂不上。
			QueueHook("advapi32.dll", "SetSecurityInfo",
				reinterpret_cast<LPVOID>(SetSecurityInfo_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalSetSecurityInfo), false);

			QueueHook("advapi32.dll", "SetNamedSecurityInfoW",
				reinterpret_cast<LPVOID>(SetNamedSecurityInfoW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalSetNamedSecurityInfoW), false);
		}

		if (ntdll && !FileGuard::OwnsNtSetSecurityObjectHook()) {
			// NtSetSecurityObject 热（所有 ACL 变更都到它），用非必需挂载 ——
			// 挂不上也别让整个 guard 失败。
			QueueHook("ntdll.dll", "NtSetSecurityObject",
				reinterpret_cast<LPVOID>(NtSetSecurityObject_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtSetSecurityObject), false);
		}
		else if (ntdll) {
			LOG(L"ServiceConfigGuard: NtSetSecurityObject 已由 FileGuard 接管，跳过重复 MinHook");
		}

		g_installed = true;

		LOG(L"ServiceConfigGuard: 已挂载 %d 个服务权限 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
