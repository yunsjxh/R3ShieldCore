#include "stdafx.h"
#include "host_hijack_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "inject_activity.h"
#include "logger.h"

// _ReturnAddress —— 判断调用者模块（同 dll_load_guard）。
#include <intrin.h>

//
// 宿主劫持 / 加载器监控层（v15）。
// 设计说明见 host_hijack_guard.h 的文件头。
//
// 挂载点：
//   kernel32!LoadLibraryExW            → HostHijackOp::LoadLibraryEx
//   ntdll!LdrRegisterDllNotification   → HostHijackOp::RegisterDllNotification
//   ntdll!NtQueueApcThread             → HostHijackOp::QueueApcRemote（只判跨进程）
//   kernel32!QueueUserAPC              → HostHijackOp::QueueApcRemote（只判跨进程）
//
// ⚠️ NtMapViewOfSection **不在这里挂** —— DllLoadGuard 已经挂了同一个地址，
//    MinHook 不允许同一地址两次 detour。跨进程映射的判定改由 DllLoadGuard
//    的 map hook 转调本 guard 的 EvaluateRemoteMapSection()（见下）。
//
// ⚠️ 注册表注入键（AppInit_DLLs / IFEO / LSA / Winlogon）也不在这里挂 ——
//    NtSetValueKey 由 RegistryGuard 挂住，它写完值后调本 guard 的
//    EvaluateInjectionKeyWrite()。同一 API 只挂一次。
//
// ntstatus.h 直接 include 会和 winnt.h 打架，按项目惯例自带保护宏。
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef HMODULE(WINAPI* LoadLibraryExWPtr)(LPCWSTR, HANDLE, DWORD);
	typedef NTSTATUS(NTAPI* LdrRegisterDllNotificationPtr)(ULONG flags, PVOID callback, PVOID context, PVOID* cookie);
	typedef DWORD(WINAPI* QueueUserAPCPtr)(PAPCFUNC, HANDLE, ULONG_PTR);

	// ⚠️ NtQueueApcThread 与 QueueUserAPC **签名不同**（前者 NTAPI / NTSTATUS / 5 参数，
	//    后者 WINAPI / DWORD / 3 参数）—— 不能共用一个 detour。分别 typedef。
	typedef NTSTATUS(NTAPI* NtQueueApcThreadPtr)(HANDLE threadHandle, PVOID apcRoutine,
		PVOID apcArgument1, PVOID apcArgument2, PVOID apcArgument3);

	LoadLibraryExWPtr pOriginalLoadLibraryExW = nullptr;
	LdrRegisterDllNotificationPtr pOriginalLdrRegisterDllNotification = nullptr;
	QueueUserAPCPtr pOriginalQueueUserAPC = nullptr;
	NtQueueApcThreadPtr pOriginalNtQueueApcThread = nullptr;

	// ------------------------------------------------------------------
	// 本地 ContainsNoCase（不区分大小写的子串查找）。
	//
	// ⚠️ r3shieldcore_rules.cpp 里的同名函数在**匿名 namespace**，本文件不可见
	//    （wmi_subscription_guard.cpp 也遇到过同一问题，它自建了
	//    ContainsNoCaseW）。项目惯例：guard 侧自带一份。
	// ------------------------------------------------------------------
	bool ContainsNoCaseLocal(PCWSTR text, PCWSTR fragment) noexcept
	{
		if (!text || !fragment || !fragment[0]) {
			return false;
		}

		const size_t fragmentLength = wcslen(fragment);
		for (PCWSTR cursor = text; *cursor; ++cursor) {
			if (_wcsnicmp(cursor, fragment, fragmentLength) == 0) {
				return true;
			}
		}

		return false;
	}

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

	Action ExceptionAction(R3ShieldCore::Event& event) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}
		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		return Action::Block;
	}

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// 路径是否系统目录 —— 与 dll_load_guard 同一口径（前缀比较，不碰文件系统）。
	// 命中即透传，是性能命门。
	bool IsSystemPath(PCWSTR path) noexcept
	{
		if (!path || !path[0]) {
			return true;
		}

		if (wcschr(path, L'\\') == nullptr && wcschr(path, L'/') == nullptr) {
			return true;
		}

		static WCHAR cachedWindows[MAX_PATH] = {};
		static WCHAR cachedProgramFiles[MAX_PATH] = {};
		static WCHAR cachedProgramFilesX86[MAX_PATH] = {};
		static bool initialized = false;

		if (!initialized) {
			UINT len = GetWindowsDirectoryW(cachedWindows, _countof(cachedWindows));
			if (len == 0 || len >= _countof(cachedWindows)) cachedWindows[0] = L'\0';
			DWORD len2 = GetEnvironmentVariableW(L"ProgramFiles", cachedProgramFiles, _countof(cachedProgramFiles));
			if (len2 == 0 || len2 >= _countof(cachedProgramFiles)) cachedProgramFiles[0] = L'\0';
			DWORD len3 = GetEnvironmentVariableW(L"ProgramFiles(x86)", cachedProgramFilesX86, _countof(cachedProgramFilesX86));
			if (len3 == 0 || len3 >= _countof(cachedProgramFilesX86)) cachedProgramFilesX86[0] = L'\0';
			initialized = true;
		}

		PCWSTR prefixes[3] = { cachedWindows, cachedProgramFiles, cachedProgramFilesX86 };
		for (PCWSTR prefix : prefixes) {
			if (prefix[0] && _wcsnicmp(path, prefix, wcslen(prefix)) == 0) {
				PCWSTR rest = path + wcslen(prefix);
				if (*rest == L'\\' || *rest == L'/') {
					return true;
				}
			}
		}

		return false;
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::HostHijack);
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

	// 通用判定骨架（同 dll_load_guard / com_hijack_guard）。
	//
	// highRiskByRule 由调用方算好（因为各 op 的判据函数签名不同）。
	// targetPath 用于填 KeyPath/DllPath（展示用），可为 nullptr。
	Action Evaluate(R3ShieldCore::HostHijackOp op, R3ShieldCore::Event& event,
		bool highRiskByRule, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::HostHijack);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式 ----
		//
		// ⚠️ 与其它 guard 的差别：宿主劫持的**配置写入**本身是低频、
		//    目的明确的操作（不像 CoCreateInstance 那样每秒都在调），
		//    所以 BlockAll 下**探测范围内一律拦**，不需要"能解析出路径才拦"的
		//    保守处理 —— 能走到这里的已经被 hook 层过滤过（系统路径提前透传、
		//    本进程映射提前透传），一定是可疑动作。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			highRisk = highRiskByRule;
			if (highRisk) {
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		// ---- 非高危：**不产生事件，直接放行** ----
		//
		// ⚠️ 同 com_hijack：LoadLibraryExW / QueueUserAPC / NtSetValueKey
		//    都是热函数，非高危上报会把日志刷爆。判定层已经把"系统路径 /
		//    本进程 / 非路径值"都过滤成非高危了，这里直接 Pass。
		if (!highRisk) {
			return Action::Pass;
		}

		// 高危但拿不到 mode == Ask 的询问能力 → 按 Block/Record 处理。
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

	// 填"目标"展示列。KeyPath 是各 guard 通用的名称列。
	void SetHostTarget(R3ShieldCore::Event& event, PCWSTR target) noexcept
	{
		if (target && target[0]) {
			wcsncpy_s(event.KeyPath, target, _TRUNCATE);
		}
		else {
			wcsncpy_s(event.KeyPath, L"(宿主劫持)", _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (target && target[0]) {
			wcsncpy_s(event.DllPath, target, _TRUNCATE);
		}
	}

	// ------------------------------------------------------------------
	// hook：LoadLibraryExW
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么单挂它（LdrLoadDll 已在 DllLoadGuard 挂）：
	//    LoadLibraryExW 是 kernel32 层出口，最终也会走 LdrLoadDll ——
	//    但带 flags 的加载是**特殊语义**：
	//      DONT_RESOLVE_DLL_REFERENCES / LOAD_LIBRARY_AS_DATAFILE /
	//      LOAD_LIBRARY_AS_IMAGE_RESOURCE —— 这些 flag 让 DLL 被映射
	//      **但不执行初始化**，是手工映射注入的常用铺垫（先映射，再
	//      自己解析导出表调 DllMain）。普通 LoadLibrary 不带这些。
	//    所以这里只对"带特殊 flag"或"路径用户可写"的加载上报。
	//
	HMODULE WINAPI LoadLibraryExW_Hook(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
	{
		// 系统路径 + 无特殊 flag → 极热路径，零副作用透传。
		const bool specialFlags = (dwFlags & (DONT_RESOLVE_DLL_REFERENCES |
			LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)) != 0;

		if (!lpLibFileName || (IsSystemPath(lpLibFileName) && !specialFlags)) {
			return pOriginalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		HMODULE result = nullptr;

		__try {
			SetHostTarget(event, lpLibFileName);

			const bool manualMap = specialFlags;
			const bool highRisk = R3ShieldCoreRules::IsHighRiskHostHijack(
				static_cast<ULONG>(R3ShieldCore::HostHijackOp::LoadLibraryEx),
				lpLibFileName, false, manualMap);

			action = Evaluate(R3ShieldCore::HostHijackOp::LoadLibraryEx, event, highRisk, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		result = pOriginalLoadLibraryExW(lpLibFileName, hFile, dwFlags);

		if (action == Action::Record) {
			event.Status = result ? 0 : static_cast<ULONG>(GetLastError());
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：LdrRegisterDllNotification
	// ------------------------------------------------------------------
	//
	// ⚠️ 这条是"劫持加载决策"：注册一个回调，任何 DLL 加载/卸载时
	//    系统都会先回调它 —— 回调可以拒绝加载（把 LoadCount 设 0 让
	//    加载失败）、可以换掉路径。安全产品用它做白名单，恶意软件用它
	//    做反检测（拦掉杀软 DLL 的加载）。所以"注册者是谁"没意义
	//    （谁都合法），要判的是**注册时机/注册者模块**是否可疑：
	//    首次注册本身不是危害，我们把它记为**可疑信号**（非高危），
	//    只有当注册者不是系统模块时才上报。
	//
	// 实现上这条 hook 只做一件事：记录"有人在本进程注册了加载通知"，
	// 用调用者模块判断是否系统模块。规则层对 RegisterDllNotification
	// 的判据是"manualMap / 用户可写目录" —— 注册本身不带路径，
	// 所以这里用一个固定的非路径目标，交给规则层按 op 判定。
	NTSTATUS NTAPI LdrRegisterDllNotification_Hook(ULONG Flags, PVOID NotificationFunction,
		PVOID Context, PVOID* Cookie)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = 0;

		__try {
			// 注册者是哪个模块 —— 系统模块（ntdll/kernel32/known dlls）算正常。
			PVOID caller = _ReturnAddress();
			HMODULE callerModule = nullptr;
			GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
				GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCWSTR>(caller), &callerModule);

			WCHAR callerPath[MAX_PATH] = {};
			if (callerModule) {
				GetModuleFileNameW(callerModule, callerPath, _countof(callerPath));
			}

			SetHostTarget(event, callerPath[0] ? callerPath : L"(加载通知注册)");

			// 注册者路径传给判据 —— 系统模块路径会被 IsUserWritableHostPath
			// 判为非高危，非系统模块才可能高危。
			const bool highRisk = R3ShieldCoreRules::IsHighRiskHostHijack(
				static_cast<ULONG>(R3ShieldCore::HostHijackOp::RegisterDllNotification),
				callerPath[0] ? callerPath : nullptr, false, false);

			action = Evaluate(R3ShieldCore::HostHijackOp::RegisterDllNotification, event, highRisk, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		status = pOriginalLdrRegisterDllNotification(Flags, NotificationFunction, Context, Cookie);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ------------------------------------------------------------------
	// hook：QueueUserAPC
	// ------------------------------------------------------------------
	//
	// ⚠️ 跨进程 APC 注入的入口。QueueUserAPC 把函数塞进**目标线程**的
	//    APC 队列，目标线程下次进 alertable wait（SleepEx / WaitForSingleObjectEx /
	//    MsgWaitForMultipleObjectsEx 等）时执行。
	//
	//    判据：**目标进程 ≠ 自己**才是注入。本进程给自己线程投 APC 是
	//    极常见的（线程池、异步 IO 完成回调都走这个）—— 必须放行。
	//
	DWORD WINAPI QueueUserAPC_Hook(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		DWORD result = 0;

		__try {
			// 目标线程 → 目标进程。
			DWORD targetPid = GetProcessIdOfThread(hThread);
			const bool crossProcess = (targetPid != 0) && (targetPid != GetCurrentProcessId());

			// 本进程 / 取不到 pid → 直接透传（APC 在本进程里是常态）。
			if (!crossProcess) {
				InterlockedDecrement(&g_activeHooks);
				return pOriginalQueueUserAPC(pfnAPC, hThread, dwData);
			}

			// ★★★ v48：引擎**自己**的注入也要走 APC —— 必须放行。
			//
			//   同步注入路（`NewProcessInjector::CreateProcessInternalW_Hook` →
			//   `DllInject`）在 `hThreadForAPC != nullptr` 时用
			//   `MyQueueUserAPC` 把 shellcode 投到**新子进程的主线程**上；
			//   轮询路的 APC 分支同理。这一步**跑在调用方进程里**。
			//
			//   如果调用方是**全量注入**的（有本 guard），这次"跨进程 APC"会被
			//   本函数判成 `QueueApcRemote = HIGH` ⇒ Block 模式下直接拒 ⇒
			//   `DllInject` 抛异常 ⇒ v47 的 fail-closed 把**刚建出来的子进程
			//   直接 TerminateProcess** ⇒ `CreateProcess` 返回 FALSE、
			//   `GetLastError()=1114`。
			//
			//   ⇒ 后果是**全量注入的进程一个子进程都拉不起来**（记事本、浏览器、
			//     脚本解释器、甚至引擎自己的部署脚本全废）。
			//
			//   真机铁证（`r3shieldcore-events.log`，同一毫秒）：
			//     PROC ALLOW      CreateProcess    image=...\tasklist.exe  (pid=16920)
			//     HOST BLOCK HIGH QueueApcRemote   key=APC@... → pid 16920 (ntdll)  <- 自己拦自己
			//     PROC ALLOW      TerminateProcess                                   <- fail-closed 收拾残局
			//
			//   放行判据与内存/线程钩子**完全一致**（见 inject_activity.h）：
			//   本线程此刻正在注入的 pid（`g_injectTargetPid`）或本 CreateProcess
			//   窗口内刚建出来的子进程（`g_createdChildPid`）。最小授权、线程级、
			//   窗口极窄。**别的**进程照样判。
			if (R3ShieldCoreInjectActivity::IsInjectingInto(targetPid)) {
				InterlockedDecrement(&g_activeHooks);
				return pOriginalQueueUserAPC(pfnAPC, hThread, dwData);
			}

			// 展示：把 APC 函数地址写成目标 —— 这才是"投递了什么"。
			WCHAR buf[64] = {};
			swprintf_s(buf, L"APC@%p → pid %u", pfnAPC, targetPid);
			SetHostTarget(event, buf);
			event.Flags2 |= R3ShieldCore::FlagEvent2HostCrossProc;

			const bool highRisk = R3ShieldCoreRules::IsHighRiskHostHijack(
				static_cast<ULONG>(R3ShieldCore::HostHijackOp::QueueApcRemote),
				nullptr, true, false);

			action = Evaluate(R3ShieldCore::HostHijackOp::QueueApcRemote, event, highRisk, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return 0;
		}

		result = pOriginalQueueUserAPC(pfnAPC, hThread, dwData);

		if (action == Action::Record) {
			event.Status = result;
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：NtQueueApcThread（ntdll 原生层，与 QueueUserAPC 签名不同）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么要单独写一个：
	//   kernel32!QueueUserAPC 内部会转发到 ntdll!NtQueueApcThread，但两者签名
	//   不同（NTSTATUS NTAPI(HANDLE,PVOID,PVOID,PVOID,PVOID) vs
	//   DWORD WINAPI(PAPCFUNC,HANDLE,ULONG_PTR)）。同一个 detour 函数套到两个
	//   地址上，参数会错位（第 2 个参数在 ntdll 版里是函数指针、在 kernel32 版
	//   里是线程句柄）—— 必须各写一个。
	//
	//   挂 ntdll 这一层的好处：绕过 kernel32 直调 ntdll 的注入（恶意软件常用）
	//   也会被看到。两者都挂，谁生效都能拦（MinHook 挂不同地址，不冲突）。
	//
	NTSTATUS NTAPI NtQueueApcThread_Hook(HANDLE ThreadHandle, PVOID ApcRoutine,
		PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = 0;

		__try {
			DWORD targetPid = GetProcessIdOfThread(ThreadHandle);
			const bool crossProcess = (targetPid != 0) && (targetPid != GetCurrentProcessId());

			// 本进程 / 取不到 pid → 直接透传。
			if (!crossProcess) {
				InterlockedDecrement(&g_activeHooks);
				return pOriginalNtQueueApcThread(ThreadHandle, ApcRoutine,
					ApcArgument1, ApcArgument2, ApcArgument3);
			}

			// ★★★ v48：与 `QueueUserAPC_Hook` 同一条判据 —— 引擎自己注入时
			//   `MyQueueUserAPC` 最终会走到 ntdll 这一层，必须放行。
			//   详见上面 QueueUserAPC_Hook 里的长注释。
			if (R3ShieldCoreInjectActivity::IsInjectingInto(targetPid)) {
				InterlockedDecrement(&g_activeHooks);
				return pOriginalNtQueueApcThread(ThreadHandle, ApcRoutine,
					ApcArgument1, ApcArgument2, ApcArgument3);
			}

			WCHAR buf[64] = {};
			swprintf_s(buf, L"APC@%p → pid %u (ntdll)", ApcRoutine, targetPid);
			SetHostTarget(event, buf);
			event.Flags2 |= R3ShieldCore::FlagEvent2HostCrossProc;

			const bool highRisk = R3ShieldCoreRules::IsHighRiskHostHijack(
				static_cast<ULONG>(R3ShieldCore::HostHijackOp::QueueApcRemote),
				nullptr, true, false);

			action = Evaluate(R3ShieldCore::HostHijackOp::QueueApcRemote, event, highRisk, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		status = pOriginalNtQueueApcThread(ThreadHandle, ApcRoutine,
			ApcArgument1, ApcArgument2, ApcArgument3);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}
	bool QueueHook(HMODULE module, PCSTR moduleName, PCSTR functionName, LPVOID detour,
		LPVOID* original, bool required) noexcept
	{
		if (!module) {
			if (required) {
				LOG(L"HostHijackGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"HostHijackGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"HostHijackGuard: MH_CreateHook(%S!%S) 失败，状态 %d", moduleName, functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"HostHijackGuard: MH_QueueEnableHook(%S!%S) 失败，状态 %d", moduleName, functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace HostHijackGuard
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
				LOG(L"HostHijackGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	//
	// 注册表注入键写的评估（由 RegistryGuard 在 NtSetValueKey 后调用）。
	//
	// ⚠️ 关键判据：**值内容**才是危害所在。
	//    AppInit_DLLs 的值 = 要注入的 DLL 路径；
	//    IFEO Debugger 的值 = 调试器路径；
	//    Winlogon Shell/Userinit 的值 = 启动程序；
	//    LSA Security Packages 的值 = 要加载的 DLL。
	//    只有"值指向用户可写目录"才是真劫持（系统以后加载的就是攻击者的东西）。
	//
	bool EvaluateInjectionKeyWrite(PCWSTR keyPath, PCWSTR valueName, PCWSTR value) noexcept
	{
		if (g_bypass || !g_installed) {
			return false;
		}

		if (!R3ShieldCoreChannel::IsOpen()) {
			return false;
		}

		// ---- 快速预筛：键路径不命中注入表 → 直接返回，不做任何事 ----
		//
		// ⚠️ 这是性能命门：NtSetValueKey 极热（登录后每秒几百上千次），
		//    绝大多数与本 guard 无关。先用便宜的键前缀筛掉，
		//    命中才去读值内容（值内容比对更贵）。
		const char* keyReason = R3ShieldCoreRules::HostInjectionKeyReason(keyPath);
		if (!keyReason) {
			return false;
		}

		// ---- 值内容判定 ----
		//
		// ⚠️ valueName 也是关键一环：同一个键下，AppInit_DLLs 值名写
		//    "AppInit_DLLs" 才危险，写 "LoadAppInit_DLLs"=1 只是开关；
		//    Winlogon 下 "Shell" / "Userinit" / "Notify" 才是劫持点，
		//    写 "DefaultUserName" 是正常配置。
		//
		//    但这里简化处理：keyReason 命中 + 值指向用户可写目录 = 高危。
		//    值指向系统目录 / 为空 / 非路径 → 非高危（用户自己配的正常值）。
		//    RegistryGuard 的高危注册表规则会照常记录写键这件事，
		//    本 guard 只补"值是用户可写 → 真劫持"这一档。
		const bool highRisk = R3ShieldCoreRules::IsHighRiskHostInjectionKey(keyPath, value);
		if (!highRisk) {
			return false;
		}

		// ---- 组装事件并走统一判定 ----
		R3ShieldCore::Event event = {};

		// KeyPath 放注册表路径（这是"改了什么"），ValueName 放值名，
		// DllPath 放值内容（"写进去什么"）。
		wcsncpy_s(event.KeyPath, keyPath ? keyPath : L"", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (valueName && valueName[0]) {
			wcsncpy_s(event.ValueName, valueName, _TRUNCATE);
			event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		}

		if (value && value[0]) {
			wcsncpy_s(event.DllPath, value, _TRUNCATE);
		}

		// 附加语义：值指向用户可写目录 + 凭据宿主。
		event.Flags2 |= R3ShieldCore::FlagEvent2HostUserWritable;
		if (ContainsNoCaseLocal(keyPath, L"\\Lsa") || ContainsNoCaseLocal(keyPath, L"Credential")) {
			event.Flags2 |= R3ShieldCore::FlagEvent2HostCredential;
		}

		// registry_guard 已在 NtSetValueKey 里判过一轮，这里传 allowAsk=false：
		// 避免同一个写入弹两次窗（一次注册表规则、一次宿主劫持）。
		// 要弹窗的话，由注册表那条高危规则负责；本 guard 只补充记录。
		//
		// ⚠️ 但 Block 模式下仍然要能拦 —— 所以 Evaluate 里 Block 分支照常生效
		//    （allowAsk=false 只影响 Ask 分支）。
		const Action action = Evaluate(R3ShieldCore::HostHijackOp::InjectionRegistryKey,
			event, true, false);

		// 回报：action 为 Block 时说明本 guard 决定拦 —— 但评估发生在
		// NtSetValueKey **成功之后**（registry_guard 已放行写入了），
		// 无法再拦。所以这里只上报事件，返回值恒为 true（"构成劫持"）。
		// LOG 模式：WouldBlock；BLOCK 模式：Blocked（但写入已发生，
		// 由 registry_guard 侧的高危规则提前拦 —— 见其调用注释）。
		Publish(event);

		return action == Action::Block || action == Action::Record;
	}

	//
	// 跨进程映射的补充评估（由 DllLoadGuard 的 NtMapViewOfSection hook 调用）。
	//
	// ⚠️ 与 EvaluateInjectionKeyWrite 的区别：这个**能真的拦**。
	//    因为 DllLoadGuard 是在**调用原函数之前**调的（映射还没发生），
	//    本函数返回 true 时 DllLoadGuard 会直接返回 STATUS_ACCESS_DENIED，
	//    不做映射。
	//
	bool EvaluateRemoteMapSection(HANDLE targetProcessHandle) noexcept
	{
		if (g_bypass || !g_installed) {
			return false;
		}

		if (!R3ShieldCoreChannel::IsOpen()) {
			return false;
		}

		// 本进程 → 不归本 guard 管（DllLoad 的反射式加载处理）。
		if (!targetProcessHandle || targetProcessHandle == GetCurrentProcess()) {
			return false;
		}

		const DWORD targetPid = GetProcessId(targetProcessHandle);
		if (targetPid == 0 || targetPid == GetCurrentProcessId()) {
			return false;
		}

		R3ShieldCore::Event event = {};

		WCHAR buf[64] = {};
		swprintf_s(buf, L"NtMapViewOfSection → pid %u", targetPid);
		SetHostTarget(event, buf);
		event.Flags2 |= R3ShieldCore::FlagEvent2HostCrossProc;

		// 跨进程映射 —— 机制即注入，跨进程就是高危（不看路径）。
		const bool highRisk = R3ShieldCoreRules::IsHighRiskHostHijack(
			static_cast<ULONG>(R3ShieldCore::HostHijackOp::MapSectionRemote),
			nullptr, true, false);

		// allowAsk = true：与 DllLoad 那条事件是**不同页签的两条记录**，
		// 不算重复弹窗。
		const Action action = Evaluate(R3ShieldCore::HostHijackOp::MapSectionRemote,
			event, highRisk, true);

		if (action == Action::Record) {
			Publish(event);
		}
		else if (action == Action::Block) {
			// Block 时事件由调用方（DllLoadGuard）报，这里只回报"要拦"。
			return true;
		}

		return false;
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
		if (!policy || (policy->Flags2 & R3ShieldCore::FlagHookHostHijack) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"HostHijackGuard: hook_host_hijack 未开启，本进程不挂宿主劫持 hook");
			return true;
		}

		g_bypass = false;

		//
		// ⚠️ 主动加载 kernel32（LoadLibraryExW 在它里面）。
		//    任何进程都已加载 kernel32，这里只是拿句柄。
		//
		HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		if (kernel32) {
			QueueHook(kernel32, "kernel32", "LoadLibraryExW",
				reinterpret_cast<LPVOID>(LoadLibraryExW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalLoadLibraryExW), true);
		}
		else {
			LOG(L"HostHijackGuard: kernel32 未加载，LoadLibraryExW 覆盖缺失");
		}

		if (ntdll) {
			// LdrRegisterDllNotification 是 ntdll 的**未文档化但稳定**导出，
			// 从 XP 起就有。GetProcAddress 拿不到就跳过（非必需）。
			QueueHook(ntdll, "ntdll", "LdrRegisterDllNotification",
				reinterpret_cast<LPVOID>(LdrRegisterDllNotification_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalLdrRegisterDllNotification), false);

			// ntdll!NtQueueApcThread —— 原生层，绕过 kernel32 的注入也能看到。
			QueueHook(ntdll, "ntdll", "NtQueueApcThread",
				reinterpret_cast<LPVOID>(NtQueueApcThread_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtQueueApcThread), false);
		}

		// kernel32!QueueUserAPC —— Win32 层，签名与 ntdll 版不同，用各自的 detour。
		if (kernel32) {
			QueueHook(kernel32, "kernel32", "QueueUserAPC",
				reinterpret_cast<LPVOID>(QueueUserAPC_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalQueueUserAPC), false);
		}

		g_installed = true;

		LOG(L"HostHijackGuard: 已挂载 %d 个宿主劫持 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
