#include "stdafx.h"
#include "scheduled_task_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 计划任务持久化监控层（v12）。
// 设计说明、槽位表、能力边界见 scheduled_task_guard.h 的文件头。
//
// 与其它 guard 的根本区别：**没有 MinHook，全是 vtable patch**。
//   MinHook 只能挂"有导出地址的函数"；Task Scheduler 是纯 COM 接口。
//

// taskschd.h 会把 oleauto.h / oaidl.h 拉进来（IDispatch 的定义在这里）。
#include <taskschd.h>
#include <oleauto.h>

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

namespace
{
	// ------------------------------------------------------------------
	// vtable 槽位（含 IDispatch 7 槽）
	//
	// ⚠️ 这些常量由 tools/taskprobe.cpp 在实机上验证。
	//    改动前先跑 `taskprobe.exe --vt` 数一遍，别凭记忆改。
	// ------------------------------------------------------------------
	constexpr int kSlotITaskFolder_RegisterTaskDefinition = 17; // 见 .h 里的槽位表
	constexpr int kSlotITaskFolder_GetFolder = 9;

	// ITaskService 的槽位（不含 IDispatch —— ITaskService 继承 IDispatch）：
	//   [0..2] IUnknown, [3..6] IDispatch, [7] Connect, [8] GetFolder,
	//   [9] GetRunningTasks, [10] NewTask
	constexpr int kSlotITaskService_GetFolder = 8;

	// ------------------------------------------------------------------
	// 原函数指针
	// ------------------------------------------------------------------
	using RegisterTaskDefinitionFn = HRESULT(STDMETHODCALLTYPE*)(
		ITaskFolder*, BSTR, ITaskDefinition*, LONG, VARIANT, VARIANT,
		TASK_LOGON_TYPE, VARIANT, IRegisteredTask**);

	using GetFolderFn = HRESULT(STDMETHODCALLTYPE*)(ITaskFolder*, BSTR, ITaskFolder**);

	using GetFolderSvcFn = HRESULT(STDMETHODCALLTYPE*)(ITaskService*, BSTR, ITaskFolder**);

	// 每个被 patch 的 vtable 存一份原函数（同一个 vtable 只 patch 一次）。
	struct PatchedVtable
	{
		void** vtable;
		GetFolderFn originalGetFolder;
		RegisterTaskDefinitionFn originalRegisterTaskDefinition;
	};

	constexpr int kMaxPatchedVtables = 8;
	PatchedVtable g_patched[kMaxPatchedVtables] = {};
	volatile LONG g_patchedCount = 0;

	// GetFolder wrapper 需要找到"调用者的 vtable"以取回原函数 ——
	// 用 this 反查（vtable 在 this 的第 0 项）。
	PatchedVtable* FindByThis(void* self) noexcept
	{
		if (!self) {
			return nullptr;
		}

		void** vt = *reinterpret_cast<void***>(self);
		const LONG count = InterlockedCompareExchange(&g_patchedCount, 0, 0);
		for (LONG i = 0; i < count && i < kMaxPatchedVtables; ++i) {
			if (g_patched[i].vtable == vt) {
				return &g_patched[i];
			}
		}

		return nullptr;
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

	// ------------------------------------------------------------------
	// 把 ITaskDefinition 的"第一个动作的执行路径"摘出来
	// ------------------------------------------------------------------
	//
	// ⚠️ 内部大量 __try/__except 包住：COM 调用会走 RPC，参数不合法
	//    或对象已释放都可能抛异常，不能让异常穿透 hook。
	//
	// 返回 true 表示拿到了非空路径。
	bool ExtractTaskExecPath(ITaskDefinition* definition, WCHAR* out, size_t cch,
		bool& isExe, bool& runAsSystem) noexcept
	{
		out[0] = L'\0';
		isExe = false;
		runAsSystem = false;

		if (!definition) {
			return false;
		}

		__try {
			// 动作集合 → 取第 1 个 → 看类型 → 是"运行程序"就取路径。
			IActionCollection* actions = nullptr;
			if (FAILED(definition->get_Actions(&actions)) || !actions) {
				return false;
			}

			long count = 0;
			actions->get_Count(&count);
			if (count <= 0) {
				actions->Release();
				return false;
			}

			IAction* action = nullptr;
			if (SUCCEEDED(actions->get_Item(1, &action)) && action) {
				TASK_ACTION_TYPE type = TASK_ACTION_EXEC;
				action->get_Type(&type);
				isExe = (type == TASK_ACTION_EXEC);

				// IExecAction 继承 IAction —— QueryInterface 到它才有 get_Path。
				if (isExe) {
					IExecAction* exec = nullptr;
					if (SUCCEEDED(action->QueryInterface(IID_IExecAction,
							reinterpret_cast<void**>(&exec))) && exec) {
						BSTR path = nullptr;
						if (SUCCEEDED(exec->get_Path(&path)) && path && path[0]) {
							wcsncpy_s(out, cch, path, _TRUNCATE);
						}
						if (path) {
							SysFreeString(path);
						}
						exec->Release();
					}
				}

				action->Release();
			}

			actions->Release();

			// 运行身份：Principal 的 RunLevel 是"最高权限"就算 SYSTEM 档。
			IPrincipal* principal = nullptr;
			if (SUCCEEDED(definition->get_Principal(&principal)) && principal) {
				TASK_RUNLEVEL_TYPE runLevel = TASK_RUNLEVEL_LUA;
				if (SUCCEEDED(principal->get_RunLevel(&runLevel))) {
					runAsSystem = (runLevel == TASK_RUNLEVEL_HIGHEST);
				}
				principal->Release();
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}

		return out[0] != L'\0';
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ScheduledTask);
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

	Action Evaluate(R3ShieldCore::ScheduledTaskOp op, R3ShieldCore::Event& event,
		bool isExe, bool runAsSystem) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::ScheduledTask);
		event.Op = static_cast<ULONG>(op);

		if (isExe) {
			event.Flags2 |= R3ShieldCore::FlagEvent2TaskActionExe;
		}
		if (runAsSystem) {
			event.Flags2 |= R3ShieldCore::FlagEvent2TaskSystem;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式 ----
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskScheduledTask(static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				// 复用"来自 SCM/服务 API"的标记 —— 计划任务服务也是服务。
				event.Flags |= R3ShieldCore::FlagEventServiceInstall;
			}
		}

		if (!highRisk) {
			// CreateFolder 之类不算高危 —— 不产生事件（同 ComHijack 的取向）。
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

	// ------------------------------------------------------------------
	// patch 后的函数
	// ------------------------------------------------------------------

	// GetFolder 的 wrapper —— 不拦截，只用来"顺手把返回的 ITaskFolder
	// 也 patch 上"。因为 ITaskService::Connect 之后拿的 folder 是**新实例**，
	// 但我们已经在 vtable 层面改过，同一个 vtable 的实例自动生效。
	// ⚠️ 所以这个 wrapper 其实只需要**返回一个 patch 过的 folder** ——
	//    由于 vtable 是共享的，只要 patch 过一次就够。这里保留它是为了
	//    在"第一次 GetFolder 之前 vtable 还没 patch"的场景下补刀。
	HRESULT STDMETHODCALLTYPE GetFolder_Hook(ITaskFolder* self, BSTR path, ITaskFolder** folder)
	{
		PatchedVtable* entry = FindByThis(self);
		if (!entry || !entry->originalGetFolder) {
			return E_FAIL;
		}

		return entry->originalGetFolder(self, path, folder);
	}

	// ★ 主拦截点：ITaskFolder::RegisterTaskDefinition
	HRESULT STDMETHODCALLTYPE RegisterTaskDefinition_Hook(
		ITaskFolder* self, BSTR path, ITaskDefinition* definition, LONG flags,
		VARIANT userId, VARIANT password, TASK_LOGON_TYPE logonType,
		VARIANT sddl, IRegisteredTask** task)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		HRESULT result = E_FAIL;

		bool isExe = false;
		bool runAsSystem = false;

		__try {
			// KeyPath = 任务路径（"\\MyTask"），ValueName = 动作执行路径。
			if (path) {
				wcsncpy_s(event.KeyPath, path, _TRUNCATE);
				event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
			}

			WCHAR execPath[R3ShieldCore::MaxImagePathChars] = {};
			if (ExtractTaskExecPath(definition, execPath, _countof(execPath), isExe, runAsSystem)) {
				wcsncpy_s(event.ValueName, execPath, _TRUNCATE);
				event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
				wcsncpy_s(event.CommandLine, execPath, _TRUNCATE);
			}
			else {
				wcsncpy_s(event.ValueName, L"(无法解析任务动作)", _TRUNCATE);
				event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
			}

			action = Evaluate(R3ShieldCore::ScheduledTaskOp::RegisterTaskDefinition, event,
				isExe, runAsSystem);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(E_ACCESSDENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			result = E_ACCESSDENIED;
		}
		else {
			PatchedVtable* entry = FindByThis(self);
			if (!entry || !entry->originalRegisterTaskDefinition) {
				result = E_FAIL;
			}
			else {
				result = entry->originalRegisterTaskDefinition(self, path, definition, flags,
					userId, password, logonType, sddl, task);
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
	// vtable patch
	// ------------------------------------------------------------------

	// 把 vtable 的第 slot 项换成 detour，原值写回 original。
	// .rdata 默认只读 → VirtualProtect 成 PAGE_READWRITE。
	bool PatchSlot(void** vtable, int slot, void* detour, void** original) noexcept
	{
		DWORD oldProtect = 0;
		void** target = &vtable[slot];

		if (!VirtualProtect(target, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
			LOG(L"ScheduledTaskGuard: VirtualProtect 失败（slot=%d, err=%u）", slot, GetLastError());
			return false;
		}

		*original = *target;
		*target = detour;

		DWORD ignored = 0;
		VirtualProtect(target, sizeof(void*), oldProtect, &ignored);
		return true;
	}

	// 给一个 ITaskFolder 实例的 vtable 打补丁。同一个 vtable 只打一次。
	bool PatchFolderVtable(ITaskFolder* folder) noexcept
	{
		if (!folder) {
			return false;
		}

		void** vtable = *reinterpret_cast<void***>(folder);

		// 去重：这个 vtable 已经 patch 过就跳过。
		{
			const LONG count = InterlockedCompareExchange(&g_patchedCount, 0, 0);
			for (LONG i = 0; i < count && i < kMaxPatchedVtables; ++i) {
				if (g_patched[i].vtable == vtable) {
					return true;
				}
			}
		}

		const LONG index = InterlockedIncrement(&g_patchedCount) - 1;
		if (index >= kMaxPatchedVtables) {
			LOG(L"ScheduledTaskGuard: vtable 表已满，跳过 patch");
			return false;
		}

		PatchedVtable& entry = g_patched[index];
		entry.vtable = vtable;

		// 槽位常量由 taskprobe.exe 在实机验证（见 .h 的槽位表）。
		const bool okRegister = PatchSlot(vtable, kSlotITaskFolder_RegisterTaskDefinition,
			reinterpret_cast<void*>(RegisterTaskDefinition_Hook),
			reinterpret_cast<void**>(&entry.originalRegisterTaskDefinition));

		const bool okGetFolder = PatchSlot(vtable, kSlotITaskFolder_GetFolder,
			reinterpret_cast<void*>(GetFolder_Hook),
			reinterpret_cast<void**>(&entry.originalGetFolder));

		if (okRegister) {
			g_hookCount++;
		}

		LOG(L"ScheduledTaskGuard: patch vtable=%p（RegisterTaskDefinition=%s GetFolder=%s）",
			vtable, okRegister ? L"OK" : L"FAIL", okGetFolder ? L"OK" : L"FAIL");

		return okRegister;
	}

	// ITaskService::GetFolder 的 wrapper —— 拿到 folder 后立刻给它打补丁，
	// 再返回给调用方。**这是把 patch 装上"活实例"的关键**。
	GetFolderSvcFn g_originalServiceGetFolder = nullptr;

	HRESULT STDMETHODCALLTYPE ServiceGetFolder_Hook(ITaskService* self, BSTR path, ITaskFolder** folder)
	{
		if (!g_originalServiceGetFolder) {
			return E_FAIL;
		}

		HRESULT hr = g_originalServiceGetFolder(self, path, folder);

		// 拿到 folder 就补刀 —— 后面的 RegisterTaskDefinition 就到我们的 hook 里了。
		if (SUCCEEDED(hr) && folder && *folder) {
			__try {
				PatchFolderVtable(*folder);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// 补丁失败不影响调用方 —— 只是这一条链抓不到。
			}
		}

		return hr;
	}
}

namespace ScheduledTaskGuard
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
				LOG(L"ScheduledTaskGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookScheduledTask) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ScheduledTaskGuard: hook_scheduled_task 未开启，本进程不挂计划任务 hook");
			return true;
		}

		g_bypass = false;

		//
		// ⚠️ 必须先 LoadLibraryW("taskschd.dll")。
		//
		//    这个代理 DLL 才是注册 CLSID_TaskScheduler 的地方。不主动加载的话，
		//    taskschd 里那个 ITaskService 实现根本不存在 —— 但这不影响
		//    **我们** 在调用方进程里 patch：只要目标进程自己 LoadLibrary 了
		//    taskschd（走 COM 就会走），vtable 就存在。
		//
		//    所以这里主动加载的目的是"提前把 vtable 拿在手上"，让 patch
		//    发生在对方调用之前 —— 而不是等对方加载完再补。
		//
		HMODULE taskschd = LoadLibraryW(L"taskschd.dll");
		if (!taskschd) {
			LOG(L"ScheduledTaskGuard: taskschd.dll 加载失败，计划任务覆盖缺失");
			// 不置 g_installed = true，允许后面重试。
			return false;
		}

		// InjectInit runs on a worker thread that may not have a COM apartment.
		// Initialize only this thread; an incompatible existing apartment is left
		// untouched and the lazy CoCreateInstance path remains available.
		const HRESULT comInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		const bool initializedCom = SUCCEEDED(comInit);

		//
		// 立刻用一次 CoCreateInstance 拿到一个 live ITaskService，
		// 把它的 vtable patch 掉。之后对方再 CoCreateInstance 拿到的实例
		// 因为 vtable 共享，自动走我们的 hook。
		//
		// ⚠️ 这一步在 DLL 的初始化路径里调 COM 是有风险的（重入 / STA 问题），
		//    但注入发生在进程已经起来之后，COM 已经初始化过；
		//    如果没初始化，CoCreateInstance 会返回 CO_E_NOTINITIALIZED，
		//    此时**不视为失败** —— 第一次真正调用时 worker 会自己 patch。
		//
		IServiceProvider* dummy = nullptr;
		(void)dummy;

		ITaskService* service = nullptr;
		HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
			IID_ITaskService, reinterpret_cast<void**>(&service));

		if (SUCCEEDED(hr) && service) {
			// patch ITaskService::GetFolder —— 拿到 folder 时补刀。
			void** svcVtable = *reinterpret_cast<void***>(service);
			PatchSlot(svcVtable, kSlotITaskService_GetFolder,
				reinterpret_cast<void*>(ServiceGetFolder_Hook),
				reinterpret_cast<void**>(&g_originalServiceGetFolder));

			// 顺手把当前已存在的根 folder 也 patch 一遍（有人在注入前
			// 已经拿过 folder 的场景）。
			VARIANT empty;
			VariantInit(&empty);
			if (SUCCEEDED(service->Connect(empty, empty, empty, empty))) {
				BSTR rootPath = SysAllocString(L"\\");
				ITaskFolder* root = nullptr;
				if (SUCCEEDED(service->GetFolder(rootPath, &root)) && root) {
					PatchFolderVtable(root);
					root->Release();
				}
				SysFreeString(rootPath);
			}

			service->Release();
			if (initializedCom) {
				CoUninitialize();
			}

			g_installed = true;
			LOG(L"ScheduledTaskGuard: 已 patch %d 个 vtable (pid=%u)", g_hookCount, GetCurrentProcessId());
			return true;
		}

		//
		// ⚠️ COM 未初始化（CO_E_NOTINITIALIZED）是**最常见**的路径 ——
		//    Install 跑在注入那一刻，进程自己的 COM 往往还没起来。
		//    这时**绝不能**设 g_installed = true（那等于永久放弃）；
		//    改成依赖 ComHijackGuard 的 CoCreateInstance hook 做懒 patch
		//    （ScheduledTaskGuard::TryPatchTaskService）。
		//    这里仍把 taskschd 的 vtable 拿在手上是没意义的 —— 实例还没有。
		//
		LOG(L"ScheduledTaskGuard: Install 阶段拿不到 ITaskService（hr=0x%08X，"
			L"通常是 COM 未初始化）→ 改由 CoCreateInstance 懒 patch 补装",
			static_cast<unsigned>(hr));
		if (initializedCom) {
			CoUninitialize();
		}
		return true;
	}

	// ------------------------------------------------------------------
	// 懒 patch：由 ComHijackGuard 的 CoCreateInstance hook 驱动
	// ------------------------------------------------------------------
	bool TryPatchTaskService(void* pv, const GUID& riid) noexcept
	{
		if (!pv) {
			return false;
		}

		// 只对"要 ITaskService"的那次激活动手；其它 CLSID 与我们无关。
		if (!IsEqualIID(riid, IID_ITaskService)) {
			return false;
		}

		__try {
			ITaskService* service = static_cast<ITaskService*>(pv);

			// patch ITaskService::GetFolder —— 拿到 folder 时补刀。
			void** svcVtable = *reinterpret_cast<void***>(service);
			if (svcVtable) {
				PatchSlot(svcVtable, kSlotITaskService_GetFolder,
					reinterpret_cast<void*>(ServiceGetFolder_Hook),
					reinterpret_cast<void**>(&g_originalServiceGetFolder));
			}

			// 顺手把当前已存在的根 folder 也 patch 一遍。
			VARIANT empty;
			VariantInit(&empty);
			if (SUCCEEDED(service->Connect(empty, empty, empty, empty))) {
				BSTR rootPath = SysAllocString(L"\\");
				ITaskFolder* root = nullptr;
				if (SUCCEEDED(service->GetFolder(rootPath, &root)) && root) {
					PatchFolderVtable(root);
					root->Release();
				}
				SysFreeString(rootPath);
			}

			LOG(L"ScheduledTaskGuard: 懒 patch 生效（CoCreateInstance 后补装，vtable 数=%d）", g_hookCount);
			return g_hookCount > 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LOG(L"ScheduledTaskGuard: 懒 patch 异常");
			return false;
		}
	}
}
