#include "stdafx.h"
#include "com_hijack_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

// v12：CoCreateInstance 返回后顺手给 ITaskService 做计划任务 vtable 懒 patch。
//       （详见 scheduled_task_guard.h 里 TryPatchTaskService 的说明。）
#include "scheduled_task_guard.h"

// v13：同一个道理，CoCreateInstance 返回后顺手给 IWbemLocator 做 WMI 懒 patch。
//       注入那一刻 COM 未初始化 → WmiSubscriptionGuard::Install 里的
//       PatchWbemLocatorVtable() 拿不到对象，只能等这里补刀。
#include "wmi_subscription_guard.h"

//
// COM / OLE 激活劫持监控层（v12）。
// 设计说明见 com_hijack_guard.h 的文件头。
//
// 挂载点：
//   combase!CoCreateInstance    → ComOp::CreateInstance
//   combase!CoCreateInstanceEx  → ComOp::CreateInstanceEx
//   combase!CoGetClassObject    → ComOp::GetClassObject
//
// ⚠️ 解析 CLSID → 服务器路径**必须用 RegGetValue 读注册表**，不能调
//    CoGetClassObject 之类 —— 那会递归回我们自己的 hook（重入）。
//    这与 driver_guard 读服务 ImagePath 的做法一致。
//
// ntstatus.h 直接 include 会和 winnt.h 打架，按项目惯例自带保护宏。
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef REGDB_E_CLASSNOTREG
#define REGDB_E_CLASSNOTREG ((HRESULT)0x80040154L)
#endif

namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef HRESULT(WINAPI* CoCreateInstancePtr)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
	typedef HRESULT(WINAPI* CoCreateInstanceExPtr)(REFCLSID, LPUNKNOWN, DWORD, COSERVERINFO*, ULONG, MULTI_QI*);
	typedef HRESULT(WINAPI* CoGetClassObjectPtr)(REFCLSID, DWORD, COSERVERINFO*, REFIID, LPVOID*);

	CoCreateInstancePtr pOriginalCoCreateInstance = nullptr;
	CoCreateInstanceExPtr pOriginalCoCreateInstanceEx = nullptr;
	CoGetClassObjectPtr pOriginalCoGetClassObject = nullptr;

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

	// ------------------------------------------------------------------
	// CLSID → 服务器路径解析
	// ------------------------------------------------------------------

	// 把 GUID 格式化成注册表里用的 {xxxxxxxx-xxxx-...} 形式。
	void FormatClsid(REFCLSID clsid, WCHAR* out, size_t cch) noexcept
	{
		swprintf_s(out, cch,
			L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
			clsid.Data1, clsid.Data2, clsid.Data3,
			clsid.Data4[0], clsid.Data4[1], clsid.Data4[2], clsid.Data4[3],
			clsid.Data4[4], clsid.Data4[5], clsid.Data4[6], clsid.Data4[7]);
	}

	// 读 HKCR\CLSID\{guid}\<subkey>\<value>，把路径展开环境变量后拷出来。
	//
	// ⚠️ HKCR 是被合并的视图：HKCU\Software\Classes\CLSID 优先于
	//    HKLM\SOFTWARE\Classes\CLSID。**用户级劫持就藏在 HKCU 那一侧**，
	//    所以必须用 HKEY_CLASSES_ROOT（它自己处理优先级），不能直接读 HKLM。
	//
	// 返回 true 表示拿到了非空路径。
	bool ReadServerPath(PCWSTR clsidText, PCWSTR subKey, PCWSTR valueName, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch == 0) {
			return false;
		}

		out[0] = L'\0';

		WCHAR keyPath[512] = {};
		if (swprintf_s(keyPath, L"CLSID\\%s\\%s", clsidText, subKey) < 0) {
			return false;
		}

		WCHAR raw[R3ShieldCore::MaxImagePathChars] = {};
		DWORD size = sizeof(raw);
		DWORD type = 0;
		if (RegGetValueW(HKEY_CLASSES_ROOT, keyPath, valueName,
				RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, &type, raw, &size) != ERROR_SUCCESS) {
			return false;
		}

		if (raw[0] == L'\0') {
			return false;
		}

		// REG_EXPAND_SZ 里可能有 %SystemRoot% / %ProgramFiles% → 展开。
		// 展开后可能带引号与参数（LocalServer32 常见）→ 去引号/去参数。
		WCHAR expanded[R3ShieldCore::MaxImagePathChars] = {};
		if (type == REG_EXPAND_SZ) {
			DWORD result = ExpandEnvironmentStringsW(raw, expanded, _countof(expanded));
			if (result == 0 || result > _countof(expanded)) {
				wcsncpy_s(expanded, raw, _TRUNCATE);
			}
		}
		else {
			wcsncpy_s(expanded, raw, _TRUNCATE);
		}

		PCWSTR begin = expanded;
		while (*begin == L' ' || *begin == L'\t') {
			begin++;
		}

		// 引号形式：取到下一个引号为止（引号后是命令行参数）。
		if (*begin == L'"') {
			begin++;
			size_t i = 0;
			while (begin[i] && begin[i] != L'"' && i + 1 < cch) {
				out[i] = begin[i];
				i++;
			}
			out[i] = L'\0';
			return out[0] != L'\0';
		}

		// 无引号：默认整串都是路径。只有"第一个空格之前以 .dll/.exe 结尾"
		// 时才把空格之后当参数丢掉 —— 否则 C:\Program Files\Foo\x.dll
		// 会被截断成 C:\Program。
		size_t take = wcslen(begin);
		if (PCWSTR space = wcschr(begin, L' ')) {
			const size_t headLength = static_cast<size_t>(space - begin);
			constexpr size_t suffixLength = 4;
			if (headLength > suffixLength &&
				(_wcsnicmp(space - suffixLength, L".dll", suffixLength) == 0 ||
				 _wcsnicmp(space - suffixLength, L".exe", suffixLength) == 0)) {
				take = headLength;
			}
		}

		if (take >= cch) {
			take = cch - 1;
		}

		wcsncpy_s(out, cch, begin, take);
		return out[0] != L'\0';
	}

	// 解析一个 CLSID 的服务器：先试 InprocServer32（DLL），再试 LocalServer32（EXE）。
	// inproc 输出"是不是进程内服务器"。返回 true 表示解析到了路径。
	bool ResolveComServer(REFCLSID clsid, WCHAR* path, size_t cch, bool& inproc) noexcept
	{
		inproc = false;

		WCHAR clsidText[64] = {};
		FormatClsid(clsid, clsidText, _countof(clsidText));

		// 进程内服务器优先（劫持绝大多数用这个 —— 不需要起进程，直接注入宿主）。
		if (ReadServerPath(clsidText, L"InprocServer32", L"", path, cch)) {
			inproc = true;
			return true;
		}

		// 有些 InprocServer32 的默认值留空、路径在 ThreadingModel 同级？
		// 不会 —— 默认值就是路径。空就是没有。改试 LocalServer32。
		if (ReadServerPath(clsidText, L"LocalServer32", L"", path, cch)) {
			inproc = false;
			return true;
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ComHijack);
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

	Action Evaluate(R3ShieldCore::ComOp op, R3ShieldCore::Event& event, PCWSTR serverPath, bool inproc) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ComHijack);
		event.Op = static_cast<ULONG>(op);

		if (inproc) {
			event.Flags2 |= R3ShieldCore::FlagEvent2ComInproc;
		}
		else {
			event.Flags2 |= R3ShieldCore::FlagEvent2ComLocalServer;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式 ----
		//
		// A missing server path is an unknown result, not proof of safety. Keep
		// the event visible and fail closed in the explicit BlockAll modes.
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			if (!serverPath || !serverPath[0]) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				return Action::Block;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskComHijack(serverPath, inproc)) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				event.Flags2 |= R3ShieldCore::FlagEvent2ComUserWritable;
			}
		}

		// ---- 非高危：**不产生事件** ----
		//
		// ⚠️ 这一条与其它 guard 不同，是本 guard 的**存活关键**。
		//    CoCreateInstance 是 Windows 上最热的 API 之一（一个浏览器进程
		//    每秒都在调）。如果非高危也 Record，日志会被瞬间刷爆、
		//    环形缓冲持续丢弃 —— 就是"噪音淹没真信号"。
		//    所以这里直接 Pass，连事件都不进通道。
		if (!highRisk) {
			return Action::Pass;
		}

		const bool canAsk = (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask));

		if (!canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return Action::Block;
			}

			// LOG：只记录，放行。
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

	// 组装事件：KeyPath = CLSID 文本，ValueName = 服务器路径。
	// 日志/弹窗要同时看到"哪个 CLSID"和"它指向哪"。
	void BuildEvent(R3ShieldCore::Event& event, REFCLSID clsid, PCWSTR serverPath, bool inproc) noexcept
	{
		WCHAR clsidText[64] = {};
		FormatClsid(clsid, clsidText, _countof(clsidText));
		wcsncpy_s(event.KeyPath, clsidText, _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		// 值名放服务器路径 —— 但 ValueName 只有 128 字符，长路径会截断。
		// 完整路径另有 DllPath（260）可放，这里两个都填：
		//   ValueName = 路径（供日志第二列）
		//   DllPath   = 路径（供需要完整路径的界面/导出）
		if (serverPath && serverPath[0]) {
			wcsncpy_s(event.ValueName, serverPath, _TRUNCATE);
			event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
			wcsncpy_s(event.DllPath, serverPath, _TRUNCATE);
		}
		else {
			wcsncpy_s(event.ValueName, inproc ? L"(无法解析 InprocServer32)" : L"(无法解析 LocalServer32)", _TRUNCATE);
			event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		}
	}

	// ------------------------------------------------------------------
	// 共用实现：三条 hook 的骨架完全一致，只有 op 不同。
	// ------------------------------------------------------------------
	//
	// 返回 Action，让各 hook 自己决定怎么落地（三条 hook 的返回类型不同）。
	Action Prepare(REFCLSID clsid, R3ShieldCore::ComOp op, R3ShieldCore::Event& event) noexcept
	{
		WCHAR serverPath[R3ShieldCore::MaxImagePathChars] = {};
		bool inproc = false;
		const bool resolved = ResolveComServer(clsid, serverPath, _countof(serverPath), inproc);

		if (!resolved) {
			// 未解析到路径时不能在 BlockAll 下当作安全对象放行。
			event.Op = static_cast<ULONG>(op);
			event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ComHijack);
			R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
			const ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				return Action::Block;
			}
			return Action::Pass;
		}

		BuildEvent(event, clsid, serverPath, inproc);
		return Evaluate(op, event, serverPath, inproc);
	}

	// ------------------------------------------------------------------
	// hook：CoCreateInstance
	// ------------------------------------------------------------------
	HRESULT WINAPI CoCreateInstance_Hook(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
		REFIID riid, LPVOID* ppv)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		HRESULT result = REGDB_E_CLASSNOTREG;

		__try {
			action = Prepare(rclsid, R3ShieldCore::ComOp::CreateInstance, event);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(REGDB_E_CLASSNOTREG);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			result = REGDB_E_CLASSNOTREG;
		}
		else {
			result = pOriginalCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);

			// ★ 顺势做计划任务的"懒 patch"（v12）。
			//   注入那一刻 COM 通常没初始化 → ScheduledTaskGuard::Install
			//   拿不到 ITaskService 实例，vtable patch 装不上。
			//   这里是**唯一可靠的补装点**：目标进程自己激活 ITaskService 时，
			//   我们在原函数返回后立刻把它的 vtable 改掉。
			//   TryPatchTaskService 内部会自行判定 riid 是否为 IID_ITaskService。
			if (SUCCEEDED(result) && ppv && *ppv) {
				__try {
					ScheduledTaskGuard::TryPatchTaskService(*ppv, riid);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					// 补装失败不影响这次激活。
				}

				// ★ 同点位补 WMI（v13）。TryPatchWbemLocator 内部自行判定
				//   riid 是否为 IID_IWbemLocator，不是就直接返回 false。
				//   补上之后，目标进程后续 ConnectServer / PutInstance 才会
				//   走我们的 hook；否则调用照样返 S_OK 但日志一条没有。
				__try {
					WmiSubscriptionGuard::TryPatchWbemLocator(*ppv, riid);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					// 补装失败不影响这次激活。
				}
			}

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(result);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：CoCreateInstanceEx
	// ------------------------------------------------------------------
	HRESULT WINAPI CoCreateInstanceEx_Hook(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext,
		COSERVERINFO* pServerInfo, ULONG cmq, MULTI_QI* pResults)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		HRESULT result = REGDB_E_CLASSNOTREG;

		__try {
			// ⚠️ 只在"本地激活"时判 —— pServerInfo 指向远程机器时
			//    本地注册表里的 CLSID 映射不适用（走的是远程的注册表）。
			if (pServerInfo && pServerInfo->pwszName && pServerInfo->pwszName[0]) {
				action = Action::Pass;
			}
			else {
				action = Prepare(rclsid, R3ShieldCore::ComOp::CreateInstanceEx, event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(REGDB_E_CLASSNOTREG);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			result = REGDB_E_CLASSNOTREG;
		}
		else {
			result = pOriginalCoCreateInstanceEx(rclsid, pUnkOuter, dwClsContext, pServerInfo, cmq, pResults);

			// v13：MULTI_QI 走的是 Ex 版，IWbemLocator 也可能从这条路径拿到 →
			//       逐条补 vtable patch。
			if (SUCCEEDED(result) && pResults) {
				__try {
					if (pResults->pItf && pResults->hr == S_OK && pResults->pIID) {
						ScheduledTaskGuard::TryPatchTaskService(pResults->pItf, *pResults->pIID);
						WmiSubscriptionGuard::TryPatchWbemLocator(pResults->pItf, *pResults->pIID);
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
				}
			}

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(result);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：CoGetClassObject
	// ------------------------------------------------------------------
	HRESULT WINAPI CoGetClassObject_Hook(REFCLSID rclsid, DWORD dwClsContext, COSERVERINFO* pServerInfo,
		REFIID riid, LPVOID* ppv)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		HRESULT result = REGDB_E_CLASSNOTREG;

		__try {
			if (pServerInfo && pServerInfo->pwszName && pServerInfo->pwszName[0]) {
				action = Action::Pass;
			}
			else {
				action = Prepare(rclsid, R3ShieldCore::ComOp::GetClassObject, event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(REGDB_E_CLASSNOTREG);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			result = REGDB_E_CLASSNOTREG;
		}
		else {
			result = pOriginalCoGetClassObject(rclsid, dwClsContext, pServerInfo, riid, ppv);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(result);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// 挂载
	// ------------------------------------------------------------------
	bool QueueHook(HMODULE module, PCSTR moduleName, LPCSTR functionName, LPVOID detour,
		LPVOID* original, bool required) noexcept
	{
		if (!module) {
			if (required) {
				LOG(L"ComHijackGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"ComHijackGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"ComHijackGuard: MH_CreateHook(%S!%S) 失败，状态 %d", moduleName, functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"ComHijackGuard: MH_QueueEnableHook(%S!%S) 失败，状态 %d", moduleName, functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace ComHijackGuard
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
				LOG(L"ComHijackGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookComHijack) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ComHijackGuard: hook_com_hijack 未开启，本进程不挂 COM 激活 hook");
			return true;
		}

		g_bypass = false;

		//
		// ⚠️ 必须主动 LoadLibraryW("combase.dll")。
		//
		//    Win7 之后 CoCreateInstance 等实现在 **combase.dll**，而
		//    ole32.dll 只是转发。注入发生时进程未必已经加载 combase，
		//    不主动加载就 GetProcAddress 不到（与 network_guard 主动加载
		//    ws2_32、camera_guard 主动加载 avicap32 同一个理由）。
		//
		//    combase 加载失败则退回 ole32（老系统）。
		//
		HMODULE combase = LoadLibraryW(L"combase.dll");
		HMODULE ole32 = nullptr;
		if (!combase) {
			ole32 = LoadLibraryW(L"ole32.dll");
		}

		if (combase) {
			QueueHook(combase, "combase", "CoCreateInstance",
				reinterpret_cast<LPVOID>(CoCreateInstance_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCoCreateInstance), true);
			QueueHook(combase, "combase", "CoCreateInstanceEx",
				reinterpret_cast<LPVOID>(CoCreateInstanceEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCoCreateInstanceEx), false);
			QueueHook(combase, "combase", "CoGetClassObject",
				reinterpret_cast<LPVOID>(CoGetClassObject_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCoGetClassObject), false);
		}
		else if (ole32) {
			QueueHook(ole32, "ole32", "CoCreateInstance",
				reinterpret_cast<LPVOID>(CoCreateInstance_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCoCreateInstance), true);
			QueueHook(ole32, "ole32", "CoCreateInstanceEx",
				reinterpret_cast<LPVOID>(CoCreateInstanceEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCoCreateInstanceEx), false);
			QueueHook(ole32, "ole32", "CoGetClassObject",
				reinterpret_cast<LPVOID>(CoGetClassObject_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCoGetClassObject), false);
		}
		else {
			LOG(L"ComHijackGuard: combase/ole32 都没加载上，COM 激活覆盖缺失");
		}

		g_installed = true;

		LOG(L"ComHijackGuard: 已挂载 %d 个 COM hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
