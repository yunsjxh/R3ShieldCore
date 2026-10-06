#include "stdafx.h"
#include "spawn_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// WIN32_LEAN_AND_MEAN 把 shellapi.h 排除掉了，ShellExecuteEx 的常量/结构体
// 得自己引。与 driver_guard.cpp 引 winsvc.h 同理。
//
#include <shellapi.h>

// ⚠️ shellapi.h 会定义 `#define ShellExecute ShellExecuteW` —— 这会让我们
//    下面的 `R3ShieldCore::SpawnOp::ShellExecute` 被宏替换成
//    `R3ShieldCore::SpawnOp::ShellExecuteW`，直接编译失败。
//    ShellExecuteEx 同理。这里立刻撤掉这两个宏 —— 我们只用 ShellExecuteEx
//    的 **W/A 明确版本**和结构体，不需要这两个别名宏。
#undef ShellExecute
#undef ShellExecuteEx

//
// 进程创建旁路监控层。
//
// 挂载点：
//   kernel32!WinExec                    → SpawnOp::WinExec
//   kernel32!CreateProcessW? 不挂        ← 见下
//   shell32!ShellExecuteExW / A         → SpawnOp::ShellExecute
//   advapi32!CreateProcessWithTokenW    → SpawnOp::WithToken
//   advapi32!CreateProcessWithLogonW    → SpawnOp::WithLogon
//
// ⚠️ 为什么不挂 CreateProcessW：
//     CreateProcessW → CreateProcessInternalW → NtCreateUserProcess，
//     最终都在 ProcessGuard 的 NtCreateUserProcess hook 里过一遍。
//     在这里再挂一次 = 同一件事出两条事件（噪音翻倍）。
//     这一层只覆盖"换了上下文 / 走了别的路"的 API。
//
// ⚠️ system / _wsystem 是 CRT 函数，**没有可挂载的导出**（静态链接进
//     每个模块的 CRT）。所以 SpawnOp::System 只在规则表里留了位置，
//     实际不会产生事件 —— 但 system() 内部会调 CreateProcessW，
//     最终仍走 NtCreateUserProcess 被发现。注释在此，免得以后误以为漏挂。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef UINT(WINAPI* WinExecPtr)(LPCSTR, UINT);
	typedef BOOL(WINAPI* ShellExecuteExWPtr)(SHELLEXECUTEINFOW*);
	typedef BOOL(WINAPI* ShellExecuteExAPtr)(SHELLEXECUTEINFOA*);
	typedef BOOL(WINAPI* CreateProcessWithTokenWPtr)(HANDLE, DWORD, LPCWSTR, LPWSTR,
		DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	typedef BOOL(WINAPI* CreateProcessWithLogonWPtr)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD,
		LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
	typedef BOOL(WINAPI* CreateProcessAsUserWPtr)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
		LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

	WinExecPtr pOriginalWinExec = nullptr;
	ShellExecuteExWPtr pOriginalShellExecuteExW = nullptr;
	ShellExecuteExAPtr pOriginalShellExecuteExA = nullptr;
	CreateProcessWithTokenWPtr pOriginalCreateProcessWithTokenW = nullptr;
	CreateProcessWithLogonWPtr pOriginalCreateProcessWithLogonW = nullptr;
	CreateProcessAsUserWPtr pOriginalCreateProcessAsUserW = nullptr;

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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ProcessSpawn);
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

	Action Evaluate(R3ShieldCore::SpawnOp op, R3ShieldCore::Event& event, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ProcessSpawn);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all）----
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		// 这一层挂的全是低频、上下文特殊的 API，一律高危。
		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskSpawn(static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
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

		// 高危。
		//
		// ⚠️ 必须再判一次 mode == Ask。Ask 依赖引擎侧 UI 线程，
		//    而那个线程只在 ASK 模式启动 —— LOG/BLOCK 下调 Ask 会等
		//    一个永远不来的答复（实测表现：LOG 模式被当成 Deny 直接拦）。
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

	// 填"要起什么"：KeyPath 放可执行路径摘要，CommandLine 放完整命令行。
	// 两处都是宽字符；A 版 API 传进来的是窄串，调用方负责先转宽。
	void SetSpawnTarget(R3ShieldCore::Event& event, PCWSTR image, PCWSTR commandLine) noexcept
	{
		if (image && image[0]) {
			wcsncpy_s(event.KeyPath, image, _TRUNCATE);
		}
		else {
			wcsncpy_s(event.KeyPath, L"(未指定可执行路径)", _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (commandLine && commandLine[0]) {
			wcsncpy_s(event.CommandLine, commandLine, _TRUNCATE);
		}
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.CommandLine));
	}

	// 窄串转宽（A 版 API 的参数），失败就置空。
	void NarrowToWide(PCWSTR /*unused*/, PCSTR narrow, WCHAR* out, size_t cch) noexcept
	{
		out[0] = L'\0';
		if (!narrow || !narrow[0] || cch == 0) {
			return;
		}
		MultiByteToWideChar(CP_ACP, 0, narrow, -1, out, static_cast<int>(cch));
	}

	// ------------------------------------------------------------------
	// hook：WinExec
	// ------------------------------------------------------------------
	UINT WINAPI WinExec_Hook(LPCSTR lpCmdLine, UINT uCmdShow)
	{
		InterlockedIncrement(&g_activeHooks);

		WCHAR wide[512] = {};
		NarrowToWide(nullptr, lpCmdLine, wide, _countof(wide));

		R3ShieldCore::Event event = {};
		SetSpawnTarget(event, wide, wide);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::SpawnOp::WinExec, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			SetLastError(ERROR_ACCESS_DENIED);
			return 0;
		}

		// ⚠️ WinExec 的返回值语义特殊（< 32 都是错误码，不是 GetLastError）。
		//    这里如实填原始返回值，不要覆盖。
		const UINT result = pOriginalWinExec(lpCmdLine, uCmdShow);
		event.Status = result;
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：ShellExecuteExW / A
	// ------------------------------------------------------------------
	BOOL WINAPI ShellExecuteExW_Hook(SHELLEXECUTEINFOW* info)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		// lpFile = 要操作的对象（程序 / 文档 / URL），lpParameters = 参数。
		// 走 shell 时 lpFile 可能是一个文档后缀 → 由关联决定真正执行什么，
		// 这正是"关联劫持"能生效的地方。
		SetSpawnTarget(event, info ? info->lpFile : nullptr, info ? info->lpParameters : nullptr);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::SpawnOp::ShellExecute, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalShellExecuteExW(info);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	BOOL WINAPI ShellExecuteExA_Hook(SHELLEXECUTEINFOA* info)
	{
		InterlockedIncrement(&g_activeHooks);

		WCHAR fileW[R3ShieldCore::MaxImagePathChars] = {};
		WCHAR paramsW[512] = {};
		if (info) {
			NarrowToWide(nullptr, info->lpFile, fileW, _countof(fileW));
			NarrowToWide(nullptr, info->lpParameters, paramsW, _countof(paramsW));
		}

		R3ShieldCore::Event event = {};
		SetSpawnTarget(event, fileW, paramsW);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::SpawnOp::ShellExecute, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalShellExecuteExA(info);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：CreateProcessWithTokenW / WithLogonW
	// ------------------------------------------------------------------
	BOOL WINAPI CreateProcessWithTokenW_Hook(HANDLE hToken, DWORD dwLogonFlags,
		LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags,
		LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
		LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetSpawnTarget(event, lpApplicationName, lpCommandLine);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::SpawnOp::WithToken, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalCreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName,
			lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	BOOL WINAPI CreateProcessWithLogonW_Hook(LPCWSTR lpUsername, LPCWSTR lpDomain,
		LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetSpawnTarget(event, lpApplicationName, lpCommandLine);
		// 用户名放进 ValueName 太挤，放 KeyPath 的尾部也不合适。
		// 用 CommandLine 已经能说明"起了什么"，用户名只作补充信息写进日志旁路。
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::SpawnOp::WithLogon, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalCreateProcessWithLogonW(lpUsername, lpDomain, lpPassword,
			dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：CreateProcessAsUserW（v11）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么必须补这一类：换成"别人的身份"起进程有三条路 ——
	//      CreateProcessWithTokenW / CreateProcessWithLogonW  → 走 seclogon 服务
	//      CreateProcessAsUserW                              → **不走服务**
	//    CreateProcessAsUser 直接吃调用方已持有的 token，因此：
	//      · 不依赖 Secondary Logon 服务（提权环境里这个服务常被关掉）
	//      · 拿到 SYSTEM token 后用它起一个普通会话进程做落地 —— 服务型
	//        恶意代码的标准动作
	//    它比另两条更容易被利用，必须单独挂。
	//
	BOOL WINAPI CreateProcessAsUserW_Hook(HANDLE hToken,
		LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetSpawnTarget(event, lpApplicationName, lpCommandLine);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::SpawnOp::AsUser, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine,
			lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		if (result) {
			event.Flags |= R3ShieldCore::FlagEventNewProcess;
			event.TargetProcessId = lpProcessInformation ? lpProcessInformation->dwProcessId : 0;
		}
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
				LOG(L"SpawnGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"SpawnGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"SpawnGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"SpawnGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace SpawnGuard
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
				LOG(L"SpawnGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookSpawn) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"SpawnGuard: hook_spawn 未开启，本进程不挂进程创建旁路 hook");
			return true;
		}

		g_bypass = false;

		// kernel32（WinExec）与 advapi32（WithToken/WithLogon）在绝大多数
		// 进程里已加载。shell32 不一定 —— ShellExecuteEx 是 shell 功能，
		// 很多服务/控制台进程没加载它。这里**不主动 LoadLibrary**：
		// 没加载 shell32 的进程本来就调不了 ShellExecuteEx。
		HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
		HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
		HMODULE shell32 = GetModuleHandleW(L"shell32.dll");

		if (!kernel32 && !advapi32 && !shell32) {
			LOG(L"SpawnGuard: 目标模块都未加载，本进程不挂进程创建旁路 hook");
			g_installed = true;
			return true;
		}

		if (kernel32) {
			// ⚠️ kernel32!WinExec 是**转发导出**（真正实现在 kernelbase.dll，
			//    Win10+ 起 kernel32 只是转发层）。GetProcAddress 会自动解析
			//    转发，返回 kernelbase 里的真实地址 —— 挂它就等于挂了所有到达路径。
			QueueHook("kernel32.dll", "WinExec", reinterpret_cast<LPVOID>(WinExec_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalWinExec), true);
		}

		if (shell32) {
			QueueHook("shell32.dll", "ShellExecuteExW", reinterpret_cast<LPVOID>(ShellExecuteExW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalShellExecuteExW), true);
			QueueHook("shell32.dll", "ShellExecuteExA", reinterpret_cast<LPVOID>(ShellExecuteExA_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalShellExecuteExA), false);
		}

		if (advapi32) {
			QueueHook("advapi32.dll", "CreateProcessWithTokenW",
				reinterpret_cast<LPVOID>(CreateProcessWithTokenW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCreateProcessWithTokenW), true);
			QueueHook("advapi32.dll", "CreateProcessWithLogonW",
				reinterpret_cast<LPVOID>(CreateProcessWithLogonW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCreateProcessWithLogonW), false);
			// v11：第三条"换身份"路径，不走 seclogon —— 详见上面的说明。
			QueueHook("advapi32.dll", "CreateProcessAsUserW",
				reinterpret_cast<LPVOID>(CreateProcessAsUserW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCreateProcessAsUserW), false);
		}

		g_installed = true;

		LOG(L"SpawnGuard: 已挂载 %d 个进程创建旁路 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
