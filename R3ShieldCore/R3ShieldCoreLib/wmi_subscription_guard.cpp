#include "stdafx.h"
#include "wmi_subscription_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// WMI 事件订阅持久化监控层（v13）。
//
// 见 wmi_subscription_guard.h 的详细说明。
//
// 实现要点（按重要性排序）：
//
//  1. **两道闸**：命名空间（root\subscription）→ 类名（三件套）。
//     缺任何一道都会刷屏（见头文件）。命名空间闸在 ConnectServer 上，
//     类名闸在 PutInstance 上。
//
//  2. **不需要懒 patch**：services 是 ConnectServer 的返回值，
//     我们在自己的 ConnectServer hook 里拿到它后立刻 patch。
//     （与 ScheduledTaskGuard 的最大差别。）
//
//  3. **只 patch root\subscription 的 services**：其它命名空间的对象
//     从不清 patch —— 连事件都不产生。
//
//  4. **类名怎么拿**：PutInstance 的 pInst 是 IWbemClassObject*，
//     取它的类名要走 `IWbemClassObject::Get(L"__CLASS", 0, ...)` ——
//     这是 vtable slot 4（Get）。实测 fastprox 的 IWbemClassObject。
//     拿不到类名就**不报**（宁可不报，也不刷假 HIGH）。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	//
	// 我们用最小签名（void* 代替接口指针）—— 避免拉进 wbemidl.h
	// 的一堆依赖，也避免与 COM 的 this 调用约定纠缠。
	// 参数顺序与真实接口完全一致，见 wmiprobe 实测。

	typedef HRESULT(STDMETHODCALLTYPE* ConnectServerPtr)(
		void* self, void* namespaceBstr, void* user, void* password,
		void* locale, LONG securityFlags, void* authority,
		void* context, void** services);

	// IWbemServices::PutInstance(IWbemClassObject* pInst, LONG lFlags,
	//                            IWbemContext* pCtx, IWbemCallResult** ppCallResult)
	//
	// ⚠️ **必须是 4 个参数**（实测踩到的大坑）：
	//    wbemcli.h 里 PutInstance 的第 4 个参数是 `IWbemCallResult** ppCallResult`
	//    （很容易误以为只有 3 个 —— PutInstanceAsync 才是 IWbemObjectSink*）。
	//    我们的 detour 若只声明 3 个，调用方传进来的第 4 个参数（r9）会被丢掉，
	//    转发给原函数时该寄存器是垃圾值 → 原函数往垃圾地址写
	//    → **栈/堆破坏**（症状：`__try/__except` 都兜不住，进程直接 SIGSEGV）。
	//    教训：vtable detour 的参数个数必须与 SDK 头文件**逐字对齐**。
	typedef HRESULT(STDMETHODCALLTYPE* PutInstancePtr)(
		void* self, void* instance, LONG flags, void* context, void** callResult);

	// IWbemServices::ExecMethod(BSTR strObjectPath, BSTR strMethodName, LONG lFlags,
	//                           IWbemContext* pCtx, IWbemClassObject* pInParams,
	//                           IWbemClassObject** ppOutParams, IWbemCallResult** ppCallResult)
	typedef HRESULT(STDMETHODCALLTYPE* ExecMethodPtr)(
		void* self, void* objectPath, void* methodName, LONG flags, void* context,
		void* inParams, void** outParams, void* callResult);

	// IWbemServices::ExecNotificationQuery(BSTR strQueryLanguage, BSTR strQuery,
	//                                      LONG lFlags, IWbemContext* pCtx,
	//                                      IEnumWbemClassObject** ppEnum)
	typedef HRESULT(STDMETHODCALLTYPE* ExecNotificationQueryPtr)(
		void* self, void* queryLanguage, void* query, LONG flags, void* context,
		void** enumerator);

	// IWbemClassObject::Get(LPCWSTR wszName, LONG lFlags, VARIANT* pVal,
	//                       CIMTYPE* pType, LONG* plFlavor)
	typedef HRESULT(STDMETHODCALLTYPE* ClassObjectGetPtr)(
		void* self, const WCHAR* name, LONG flags, VARIANT* value, LONG* type, LONG* flavor);

	ConnectServerPtr pOriginalConnectServer = nullptr;
	PutInstancePtr pOriginalPutInstance = nullptr;
	ExecMethodPtr pOriginalExecMethod = nullptr;
	ExecNotificationQueryPtr pOriginalExecNotificationQuery = nullptr;

	// 已 patch 的 IWbemServices vtable 去重表容量。
	constexpr int kMaxPatchedServices = 16;

	// 每个被 patch 的 IWbemServices vtable 各存一份原函数指针
	// （不同 vtable 的原函数可能来自不同环境，混用会崩 —— 见 PatchServicesVtable 里的说明）。
	PutInstancePtr g_originalPutInstance[kMaxPatchedServices] = {};
	ExecNotificationQueryPtr g_originalExecNotificationQuery[kMaxPatchedServices] = {};
	ExecMethodPtr g_originalExecMethod[kMaxPatchedServices] = {};

	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;
	void* g_patchedServices[kMaxPatchedServices] = {};
	int g_patchedServicesCount = 0;

	// vtable 槽位。
	//
	// ⚠️ 必须按 wbemcli.h 的**声明顺序**数（IUnknown 占 0/1/2，之后逐个 +1）。
	//    实测踩到的大坑：曾误用 14/22/24，结果 14 实际是 **ExecQueryAsync**
	//    （签名与 PutInstance 完全不同）→ detour 参数错位 → 原函数里栈破坏 →
	//    `__try/__except` 都兜不住，进程直接 SIGSEGV。
	//    数法（wbemcli.h 中 IWbemServices 的方法序）：
	//      3 DeleteClass / 4 DeleteClassAsync / 5 CreateClassEnum /
	//      6 CreateClassEnumAsync / 7 **PutInstance** / 8 PutInstanceAsync /
	//      9 DeleteInstance / 10 DeleteInstanceAsync / 11 CreateInstanceEnum /
	//      12 CreateInstanceEnumAsync / 13 ExecQuery / 14 ExecQueryAsync /
	//      15 **ExecNotificationQuery** / 16 ExecNotificationQueryAsync /
	//      17 **ExecMethod** / 18 ExecMethodAsync
	constexpr int kSlotIWbemLocator_ConnectServer = 3;
	constexpr int kSlotIWbemServices_PutInstance = 7;
	constexpr int kSlotIWbemServices_ExecNotificationQuery = 15;
	constexpr int kSlotIWbemServices_ExecMethod = 17;
	constexpr int kSlotIWbemClassObject_Get = 4;

	enum class Action
	{
		Pass,
		Record,
		Block,
	};

	bool BlockAllOnException() noexcept
	{
		const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy && R3ShieldCore::IsAnyBlockAllMode(policy->Mode);
	}

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// 判断某个地址是否落在**我们自己**的 DLL 里（R3ShieldCoreLib）。
	// 用途：诊断"保存下来的原函数指针是不是被我们自己的 detour 覆盖了"
	//      （那会导致自递归 / 崩）。用模块基址比较，不用字符串（铁律：-O2 下
	//      编译器可能把 rdata 字符串的写入与读取重排）。
	//
	// ⚠️ GetModuleHandleExW(FROM_ADDRESS) 的语义是"**任意**包含该地址的模块"，
	//    只要地址有效就返回非空 —— 所以**必须**再跟本 DLL 的基址比对，
	//    否则任何 wbemprox/fastprox 地址都会被误判成"在我们模块里"（实测踩到）。
	bool IsInGuardModule(const void* address) noexcept
	{
		if (!address) {
			return false;
		}
		HMODULE self = nullptr;
		if (!GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(address), &self)) {
			return false;
		}
		if (!self) {
			return false;
		}
		// 本模块的基址 —— 只算一次。
		static HMODULE s_self = nullptr;
		if (!s_self) {
			HMODULE probe = nullptr;
			if (GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
				| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCWSTR>(&IsInGuardModule), &probe)) {
				s_self = probe;
			}
		}
		return s_self != nullptr && self == s_self;
	}

	// 工具：宽字符不区分大小写包含（本地版本，避免跨 TU 依赖）。
	// ⚠️ 必须定义在使用点**之前**。
	bool ContainsNoCaseW(PCWSTR text, PCWSTR fragment) noexcept
	{
		if (!text || !fragment || !fragment[0]) {
			return false;
		}
		const size_t fragLen = wcslen(fragment);
		for (const WCHAR* p = text; *p; p++) {
			if (_wcsnicmp(p, fragment, fragLen) == 0) {
				return true;
			}
		}
		return false;
	}

	// ------------------------------------------------------------------
	// 命名空间判定
	// ------------------------------------------------------------------
	//
	// ConnectServer 的第 1 个参数是 BSTR 命名空间（可能是 "root\subscription"
	// 或 "ROOT\\SUBSCRIPTION"，大小写与反斜杠数不固定）。
	// **不区分大小写**（铁律 6）—— 用 _wcsicmp 的一族，不用 wcsstr/wcscmp。
	//
	bool IsSubscriptionNamespace(void* namespaceBstr) noexcept
	{
		if (!namespaceBstr) {
			// 没有命名空间参数（少见）→ 不是我们要的。
			return false;
		}

		const WCHAR* ns = static_cast<const WCHAR*>(namespaceBstr);
		if (!ns || !ns[0]) {
			return false;
		}

		// 允许 "root\subscription" / "ROOT\\SUBSCRIPTION" / "\\root\\subscription"
		// 等写法：统一去掉前导反斜杠后比较。
		const WCHAR* p = ns;
		while (*p == L'\\') {
			p++;
		}

		return _wcsicmp(p, L"root\\subscription") == 0
			|| _wcsicmp(p, L"root/subscription") == 0;
	}

	// 从 IWbemClassObject 取一个字符串属性（安全实现见下方定义）。
	bool TryGetStringProp(void* classObject, const WCHAR* prop, WCHAR* out, size_t cch) noexcept;

	// 从 IWbemClassObject 取类名（__CLASS 属性）。
	// 拿到返回 true。任何一步不对返回 false（调用方不报）。
	// ⚠️ 不能有需要析构的对象。
	bool TryGetClassName(void* classObject, WCHAR* out, size_t cch) noexcept
	{
		return TryGetStringProp(classObject, L"__CLASS", out, cch);
	}

	// 从 IWbemClassObject 取一个字符串属性（用于展示消费者要跑什么）。
	//
	// ⚠️ 实现上的三条硬约束（都是实测踩出来的，别改回去）：
	//
	//   ① **不调用任何 CRT 字符串函数**（wcsncpy_s / wcslen / VariantClear）。
	//      这些"安全"函数内部会走 CRT 的检查路径（invalid parameter handler /
	//      __report_rangecheckfailure 等），那是一条**独立于 SEH 的异常通路**。
	//      实测症状：get() 成功返回 VT_BSTR 之后，wcsncpy_s 里直接 SIGSEGV，
	//      外面套着 __try/__except 完全兜不住（崩的是 CRT 内部，不是本帧）。
	//      改成手写 memcpy 逐字符拷贝，不经过 CRT。
	//
	//   ② **不调 VariantClear**，只对 VT_BSTR 显式 SysFreeString。
	//      VariantClear 对非 BSTR/未知 vt 会走 general 分支，同样碰 CRT。
	//
	//   ③ 全程 __try 兜底（虽然上面两条已把风险降到很低）。
	bool TryGetStringProp(void* classObject, const WCHAR* prop, WCHAR* out, size_t cch) noexcept
	{
		if (!classObject || !prop || !out || cch == 0) {
			return false;
		}
		out[0] = L'\0';

		__try {
			void** vtable = *reinterpret_cast<void***>(classObject);
			if (!vtable) {
				return false;
			}
			auto get = reinterpret_cast<ClassObjectGetPtr>(vtable[kSlotIWbemClassObject_Get]);
			if (!get) {
				return false;
			}

			// VARIANT 自己手工清零，不调 VariantInit（同样是 CRT）。
			VARIANT value = {};
			LONG type = 0;
			LONG flavor = 0;
			const HRESULT hr = get(classObject, prop, 0, &value, &type, &flavor);

			bool ok = false;
			if (SUCCEEDED(hr) && value.vt == VT_BSTR && value.bstrVal) {
				// 逐字符拷贝（不用 CRT），留一个结尾 NUL。
				size_t i = 0;
				while (i + 1 < cch && value.bstrVal[i] != L'\0') {
					out[i] = value.bstrVal[i];
					i++;
				}
				out[i] = L'\0';
				ok = (i > 0);
			}

			// 只在自己确认是 BSTR 时才释放。
			if (SUCCEEDED(hr) && value.vt == VT_BSTR && value.bstrVal) {
				SysFreeString(value.bstrVal);
			}
			return ok;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::WmiSubscription);
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

	//
	// 判定骨架。**非高危不进通道**（与 ComHijackGuard 同思路）——
	// root\cimv2 上的 WMI 操作满天飞，一个事件都不该产生。
	//
	Action Evaluate(R3ShieldCore::WmiSubscriptionOp op, R3ShieldCore::Event& event,
		bool allowAsk, bool inSubscriptionNs, PCWSTR wmiClass) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::WmiSubscription);
		event.Op = static_cast<ULONG>(op);

		const char* reason = R3ShieldCoreRules::WmiSubscriptionRiskReason(
			static_cast<ULONG>(op), inSubscriptionNs, wmiClass);
		if (!reason) {
			// 不是高危 → 不进通道。
			return Action::Pass;
		}

		// 打三件套标记。
		if (wmiClass) {
			if (ContainsNoCaseW(wmiClass, L"__EventFilter")) {
				event.Flags2 |= R3ShieldCore::FlagEvent2WmiFilter;
			}
			if (ContainsNoCaseW(wmiClass, L"EventConsumer")) {
				event.Flags2 |= R3ShieldCore::FlagEvent2WmiConsumer;
				if (ContainsNoCaseW(wmiClass, L"CommandLine")) {
					event.Flags2 |= R3ShieldCore::FlagEvent2WmiFileless;
				}
			}
			if (ContainsNoCaseW(wmiClass, L"__FilterToConsumerBinding")) {
				event.Flags2 |= R3ShieldCore::FlagEvent2WmiBinding;
			}
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式 ----
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
			event.Flags |= R3ShieldCore::FlagEventHighRisk;
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
		event.Flags |= R3ShieldCore::FlagEventHighRisk;

		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) == 0) {
			// 高危规则被关了 —— 只记录。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// ---- 高危 ----
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

	// 工具：宽字符不区分大小写包含的本地实现见文件上方。
	void SetTarget(R3ShieldCore::Event& event, PCWSTR text) noexcept
	{
		if (text && text[0]) {
			wcsncpy_s(event.KeyPath, text, _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
	}

	void SetDetail(R3ShieldCore::Event& event, PCWSTR text) noexcept
	{
		if (text && text[0]) {
			wcsncpy_s(event.ValueName, text, _TRUNCATE);
		}
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
	}

	// ------------------------------------------------------------------
	// vtable patch
	// ------------------------------------------------------------------
	// 三个 detour 的前向声明（定义在下方）。必须放在 AlreadyPatchedServices
	// 之前 —— 那个函数要拿 detour 地址去校验槽内容。
	HRESULT STDMETHODCALLTYPE PutInstance_Hook(void*, void*, LONG, void*, void**);
	HRESULT STDMETHODCALLTYPE ExecNotificationQuery_Hook(void*, void*, void*, LONG, void*, void**);
	HRESULT STDMETHODCALLTYPE ExecMethod_Hook(
		void*, void*, void*, LONG, void*, void*, void**, void*);

	// PutInstance 的实际逻辑（被 PutInstance_Hook 的 SEH 壳调用）。
	HRESULT PutInstance_Impl(void* self, void* instance, LONG flags, void* context,
		void** callResult);

	// 按实例反查"它那个 vtable 对应的原函数"。
	// 不同 vtable 的原函数可能来自不同环境，混用会崩（见 PatchServicesVtable）。
	void FindOriginals(void* self, PutInstancePtr* outPut,
		ExecNotificationQueryPtr* outQuery, ExecMethodPtr* outMethod) noexcept;

	// ConnectServer 的实际逻辑（被 ConnectServer_Hook 的 SEH 壳调用）。
	HRESULT ConnectServer_Impl(void* self, void* namespaceBstr, void* user,
		void* password, void* locale, LONG securityFlags, void* authority,
		void* context, void** services);

	// ExecNotificationQuery / ExecMethod 的实际逻辑（同上的 SEH 壳）。
	HRESULT ExecNotificationQuery_Impl(void* self, void* queryLanguage, void* query,
		LONG flags, void* context, void** enumerator);
	HRESULT ExecMethod_Impl(void* self, void* objectPath, void* methodName,
		LONG flags, void* context, void* inParams, void** outParams, void* callResult);

	// 判断这个 vtable 是否**当前仍然**被我们 patch 着。
	//
	// ⚠️ 不能只比地址：fastprox.dll 若卸载后重新加载，新映像的 .rdata
	//    有机会被分配到**同一个地址**，只比地址会误判"已 patch"从而跳过
	//    重新打补丁（症状：宿主拿到的 IWbemServices 全是原函数）。
	//    所以额外校验一个槽的实际内容是不是我们的 detour。
	bool AlreadyPatchedServices(void* vtable) noexcept
	{
		for (int i = 0; i < g_patchedServicesCount; i++) {
			if (g_patchedServices[i] != vtable) {
				continue;
			}
			// 地址命中 —— 再确认三个槽里确实还是我们的函数。
			//
			// ⚠️ 只校验一个槽不够：三个槽是分别 VirtualProtect 的，
			//    极端情况下可能出现"部分槽被还原"。只要 PutInstance 槽
			//    是我们的，就认为整张表还在（另外两个槽跟它同页同批次写）。
			__try {
				void** vt = static_cast<void**>(vtable);
				if (vt[kSlotIWbemServices_PutInstance] ==
					reinterpret_cast<void*>(PutInstance_Hook)) {
					return true;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// 读不到就当没 patch 过，走重新 patch 路径。
			}
			return false;  // 地址是同一个，但内容已被还原 → 需要重新 patch
		}
		return false;
	}

	// 按实例反查"它那个 vtable 对应的原函数"。
	// 找不到（理论上不该发生）就退回当前全局的那一份。
	void FindOriginals(void* self, PutInstancePtr* outPut,
		ExecNotificationQueryPtr* outQuery, ExecMethodPtr* outMethod) noexcept
	{
		*outPut = pOriginalPutInstance;
		*outQuery = pOriginalExecNotificationQuery;
		*outMethod = pOriginalExecMethod;

		if (!self) {
			return;
		}
		__try {
			void** vtable = *reinterpret_cast<void***>(self);
			for (int i = 0; i < g_patchedServicesCount; i++) {
				if (g_patchedServices[i] == vtable) {
					*outPut = g_originalPutInstance[i];
					*outQuery = g_originalExecNotificationQuery[i];
					*outMethod = g_originalExecMethod[i];
					return;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// 读不到就保持全局兜底值。
		}
	}

	// 把一个 IWbemServices 的 vtable 上的三个相关槽换掉。**只 patch 一次**。
	bool PatchServicesVtable(void* services) noexcept
	{
		if (!services) {
			return false;
		}

		__try {
			void** vtable = *reinterpret_cast<void***>(services);
			if (!vtable || AlreadyPatchedServices(vtable)) {
				return true;
			}
			if (g_patchedServicesCount >= kMaxPatchedServices) {
				return false;
			}

			// 三个槽连续（14/22/24 不连续）—— 所以逐个改，不做整段保护。
			// 这里用一个小的结构表，逐个 VirtualProtect，稳妥。
			struct SlotDesc {
				int index;
				void* detour;
			};
			const SlotDesc slots[] = {
				{ kSlotIWbemServices_PutInstance,
					reinterpret_cast<void*>(PutInstance_Hook) },
				{ kSlotIWbemServices_ExecNotificationQuery,
					reinterpret_cast<void*>(ExecNotificationQuery_Hook) },
				{ kSlotIWbemServices_ExecMethod,
					reinterpret_cast<void*>(ExecMethod_Hook) },
			};

			// ★ 原函数指针必须**按 vtable 分别保存**，不能只留一份全局的。
			//
			//   实测踩到的坑：同一个进程里 wbemprox 可能给出多个不同的
			//   IWbemServices vtable（不同命名空间/不同上下文各一套）。若只用
			//   一个全局 pOriginalPutInstance，第二次 patch 会把它覆盖成"第二个
			//   vtable 的原函数"；而第一个 vtable 上的 detour 还在，它转发时
			//   调用的却是第二个环境下的函数 —— 参数语义不同，直接崩。
			//   症状：Evaluate 判定完成、日志打到"→ 调原函数"就 SIGSEGV。
			const int slotIndex = g_patchedServicesCount;
			if (slotIndex < 0 || slotIndex >= kMaxPatchedServices) {
				return false;
			}

			g_originalPutInstance[slotIndex] = reinterpret_cast<PutInstancePtr>(
				vtable[kSlotIWbemServices_PutInstance]);
			g_originalExecNotificationQuery[slotIndex] =
				reinterpret_cast<ExecNotificationQueryPtr>(
					vtable[kSlotIWbemServices_ExecNotificationQuery]);
			g_originalExecMethod[slotIndex] = reinterpret_cast<ExecMethodPtr>(
				vtable[kSlotIWbemServices_ExecMethod]);

			// ★ 关键自检：如果"原函数"落在我们自己的 DLL 里，说明这个槽
			//   早就被我们 patch 过（第二次进入本函数 / 别的路径换过道），
			//   保存下来的会是**我们自己的 detour** → hook 转发时自递归 → 崩。
			//   这种 vtable 必须**整个跳过**，不能写第二遍（写第二遍还会把
			//   真原函数彻底丢掉）。
			if (IsInGuardModule(reinterpret_cast<const void*>(
					g_originalPutInstance[slotIndex]))) {
				LOG(L"WmiSubscriptionGuard: vtable=%p 的 PutInstance 槽已是本模块函数"
					L"（origPut=%p）→ 跳过，不重复 patch",
					vtable, reinterpret_cast<void*>(g_originalPutInstance[slotIndex]));
				return true;
			}

			// 当前生效的那一份（hook 里转发时按 self 反查，见 FindOriginals）。
			pOriginalPutInstance = g_originalPutInstance[slotIndex];
			pOriginalExecNotificationQuery = g_originalExecNotificationQuery[slotIndex];
			pOriginalExecMethod = g_originalExecMethod[slotIndex];

			for (const SlotDesc& slot : slots) {
				DWORD oldProtect = 0;
				if (!VirtualProtect(&vtable[slot.index], sizeof(void*),
					PAGE_READWRITE, &oldProtect)) {
					LOG(L"WmiSubscriptionGuard: services vtable[%d] 改保护失败 err=%u",
						slot.index, GetLastError());
					continue;
				}
				vtable[slot.index] = slot.detour;
				DWORD ignored = 0;
				VirtualProtect(&vtable[slot.index], sizeof(void*), oldProtect, &ignored);
			}

			g_patchedServices[g_patchedServicesCount++] = vtable;

			// 同 IWbemLocator 的道理：把 fastprox.dll 钉住，
			// 免得它卸载重载后 .rdata vtable 恢复原样、patch 凭空消失。
			::LoadLibraryW(L"fastprox.dll");

			LOG(L"WmiSubscriptionGuard: IWbemServices vtable 已 patch（vtable=%p，累计 %d，"
				L"origPut=%p）",
				vtable, g_patchedServicesCount,
				reinterpret_cast<void*>(g_originalPutInstance[slotIndex]));
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LOG(L"WmiSubscriptionGuard: patch services vtable 异常");
			return false;
		}
	}

	// ------------------------------------------------------------------
	// hook：IWbemLocator::ConnectServer
	// ------------------------------------------------------------------
	//
	// ★ 两个作用：
	//   ① 判断命名空间（root\subscription 才继续）
	//   ② 原函数返回后，拿到 services 指针 → **立刻 patch**
	HRESULT STDMETHODCALLTYPE ConnectServer_Hook(void* self, void* namespaceBstr,
		void* user, void* password, void* locale, LONG securityFlags,
		void* authority, void* context, void** services)
	{
		InterlockedIncrement(&g_activeHooks);

		// 同上：vtable detour 必须自兜底，崩了会带走宿主。
		__try {
			return ConnectServer_Impl(self, namespaceBstr, user, password, locale,
				securityFlags, authority, context, services);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			InterlockedDecrement(&g_activeHooks);
			if (BlockAllOnException()) {
				return E_ACCESSDENIED;
			}
			return pOriginalConnectServer
				? pOriginalConnectServer(self, namespaceBstr, user, password, locale,
					securityFlags, authority, context, services)
				: E_FAIL;
		}
	}

	HRESULT ConnectServer_Impl(void* self, void* namespaceBstr,
		void* user, void* password, void* locale, LONG securityFlags,
		void* authority, void* context, void** services)
	{
		const bool inSubscriptionNs = IsSubscriptionNamespace(namespaceBstr);

		const HRESULT hr = pOriginalConnectServer
			? pOriginalConnectServer(self, namespaceBstr, user, password, locale,
				securityFlags, authority, context, services)
			: E_FAIL;

		// ★ 只有 root\subscription 的 services 才 patch —— 其它命名空间
		//   零开销、零噪音（这是本 guard 存活的关键）。
		if (inSubscriptionNs && SUCCEEDED(hr) && services && *services) {
			PatchServicesVtable(*services);
		}

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	// ------------------------------------------------------------------
	// hook：IWbemServices::PutInstance（主拦截点）
	// ------------------------------------------------------------------
	HRESULT STDMETHODCALLTYPE PutInstance_Hook(void* self, void* instance,
		LONG flags, void* context, void** callResult)
	{
		InterlockedIncrement(&g_activeHooks);

		// ★ 整个 body 用 SEH 包住。
		//
		//   这是 vtable detour 的**必守规矩**：宿主进程随时可能传进来我们
		//   意料之外的对象（不同 WMI provider / 不同 IWbemClassObject 实现 /
		//   对象已被释放），我们读它的 vtable、读属性都有可能触发访问违例。
		//   hook 里崩掉 = 宿主整个进程崩掉 —— 这比"漏报"严重得多。
		__try {
			return PutInstance_Impl(self, instance, flags, context, callResult);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			InterlockedDecrement(&g_activeHooks);
			if (BlockAllOnException()) {
				return E_ACCESSDENIED;
			}
			return pOriginalPutInstance
				? pOriginalPutInstance(self, instance, flags, context, callResult)
				: E_FAIL;
		}
	}

	// 真正干活的部分（被上面的 SEH 壳包住）。
	HRESULT PutInstance_Impl(void* self, void* instance,
		LONG flags, void* context, void** callResult)
	{
		LOG(L"WmiSubscriptionGuard: PutInstance 进入 self=%p inst=%p flags=0x%X",
			self, instance, flags);

		// 取类名 —— 拿不到就不报（宁可不报也不刷假 HIGH）。
		WCHAR className[128] = {};
		const bool gotClass = TryGetClassName(instance, className, _countof(className));

		R3ShieldCore::Event event = {};

		if (!gotClass) {
			// 类名读不到 → 不判定，直接透传（不进通道）。
			const HRESULT hr = pOriginalPutInstance
				? pOriginalPutInstance(self, instance, flags, context, callResult)
				: E_FAIL;
			InterlockedDecrement(&g_activeHooks);
			return hr;
		}

		// 命名空间闸已经在 ConnectServer 上过了一遍 —— 能走到这里的
		// services 都是 root\subscription 的（我们只 patch 了那些）。
		// 所以这里直接按"在订阅命名空间"处理。
		SetTarget(event, className);

		// 如果消费者带 CommandLineTemplate，把它也读出来展示（"要跑什么"）。
		WCHAR cmdLine[512] = {};
		if (ContainsNoCaseW(className, L"CommandLine")) {
			if (TryGetStringProp(instance, L"CommandLineTemplate",
				cmdLine, _countof(cmdLine))) {
				SetDetail(event, cmdLine);
			}
		}
		else if (ContainsNoCaseW(className, L"__EventFilter")) {
			WCHAR query[512] = {};
			if (TryGetStringProp(instance, L"Query", query, _countof(query))) {
				SetDetail(event, query);
			}
		}
		else if (ContainsNoCaseW(className, L"__FilterToConsumerBinding")) {
			WCHAR filter[512] = {};
			if (TryGetStringProp(instance, L"Filter", filter, _countof(filter))) {
				SetDetail(event, filter);
			}
		}
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::WmiSubscriptionOp::PutInstance,
			event, true, /*inSubscriptionNs=*/true, className);

		// ★ 按实例反查原函数（不能直接用全局那份 —— 多 vtable 场景下会串）。
		PutInstancePtr origPut = pOriginalPutInstance;
		ExecNotificationQueryPtr origQuery = pOriginalExecNotificationQuery;
		ExecMethodPtr origMethod = pOriginalExecMethod;
		FindOriginals(self, &origPut, &origQuery, &origMethod);

		if (action == Action::Pass) {
			// 不是三件套之一 → 不产生事件，直接透传。
			const HRESULT hr = origPut
				? origPut(self, instance, flags, context, callResult)
				: E_FAIL;
			InterlockedDecrement(&g_activeHooks);
			return hr;
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return E_ACCESSDENIED;
		}

		const HRESULT hr = origPut
			? origPut(self, instance, flags, context, callResult)
			: E_FAIL;
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	// ------------------------------------------------------------------
	// hook：IWbemServices::ExecNotificationQuery（订阅事件）
	// ------------------------------------------------------------------
	HRESULT STDMETHODCALLTYPE ExecNotificationQuery_Hook(void* self, void* queryLanguage,
		void* query, LONG flags, void* context, void** enumerator)
	{
		InterlockedIncrement(&g_activeHooks);

		__try {
			return ExecNotificationQuery_Impl(self, queryLanguage, query, flags,
				context, enumerator);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			InterlockedDecrement(&g_activeHooks);
			if (BlockAllOnException()) {
				return E_ACCESSDENIED;
			}
			return pOriginalExecNotificationQuery
				? pOriginalExecNotificationQuery(self, queryLanguage, query, flags,
					context, enumerator)
				: E_FAIL;
		}
	}

	HRESULT ExecNotificationQuery_Impl(void* self, void* queryLanguage,
		void* query, LONG flags, void* context, void** enumerator)
	{
		// 查询语句里通常含目标类名 —— 用它做类名线索（拿不到就传 nullptr，
		// 规则层对 Subscribe 不依赖类名）。
		PCWSTR queryText = query ? static_cast<PCWSTR>(query) : nullptr;

		R3ShieldCore::Event event = {};
		SetTarget(event, L"订阅 WMI 事件（ExecNotificationQuery）");
		if (queryText) {
			SetDetail(event, queryText);
		}
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::WmiSubscriptionOp::Subscribe,
			event, true, /*inSubscriptionNs=*/true, nullptr);

		// 按实例反查原函数（同 PutInstance_Impl）。
		PutInstancePtr origPut = pOriginalPutInstance;
		ExecNotificationQueryPtr origQuery = pOriginalExecNotificationQuery;
		ExecMethodPtr origMethod = pOriginalExecMethod;
		FindOriginals(self, &origPut, &origQuery, &origMethod);

		if (action == Action::Pass) {
			const HRESULT hr = origQuery
				? origQuery(self, queryLanguage, query, flags, context, enumerator)
				: E_FAIL;
			InterlockedDecrement(&g_activeHooks);
			return hr;
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return E_ACCESSDENIED;
		}

		const HRESULT hr = origQuery
			? origQuery(self, queryLanguage, query, flags, context, enumerator)
			: E_FAIL;
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	// ------------------------------------------------------------------
	// hook：IWbemServices::ExecMethod（可能直接触发消费者）
	// ------------------------------------------------------------------
	HRESULT STDMETHODCALLTYPE ExecMethod_Hook(void* self, void* objectPath,
		void* methodName, LONG flags, void* context, void* inParams,
		void** outParams, void* callResult)
	{
		InterlockedIncrement(&g_activeHooks);

		__try {
			return ExecMethod_Impl(self, objectPath, methodName, flags, context,
				inParams, outParams, callResult);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			InterlockedDecrement(&g_activeHooks);
			if (BlockAllOnException()) {
				return E_ACCESSDENIED;
			}
			return pOriginalExecMethod
				? pOriginalExecMethod(self, objectPath, methodName, flags, context,
					inParams, outParams, callResult)
				: E_FAIL;
		}
	}

	HRESULT ExecMethod_Impl(void* self, void* objectPath,
		void* methodName, LONG flags, void* context, void* inParams,
		void** outParams, void* callResult)
	{
		PCWSTR method = methodName ? static_cast<PCWSTR>(methodName) : nullptr;

		R3ShieldCore::Event event = {};
		SetTarget(event, L"调用 WMI 对象方法（ExecMethod）");
		if (method) {
			SetDetail(event, method);
		}
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::WmiSubscriptionOp::ExecMethod,
			event, true, /*inSubscriptionNs=*/true, nullptr);

		// 按实例反查原函数（同 PutInstance_Impl）。
		PutInstancePtr origPut = pOriginalPutInstance;
		ExecNotificationQueryPtr origQuery = pOriginalExecNotificationQuery;
		ExecMethodPtr origMethod = pOriginalExecMethod;
		FindOriginals(self, &origPut, &origQuery, &origMethod);

		if (action == Action::Pass) {
			const HRESULT hr = origMethod
				? origMethod(self, objectPath, methodName, flags, context,
					inParams, outParams, callResult)
				: E_FAIL;
			InterlockedDecrement(&g_activeHooks);
			return hr;
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return E_ACCESSDENIED;
		}

		const HRESULT hr = origMethod
			? origMethod(self, objectPath, methodName, flags, context,
				inParams, outParams, callResult)
			: E_FAIL;
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
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
				LOG(L"WmiSubscriptionGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"WmiSubscriptionGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"WmiSubscriptionGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"WmiSubscriptionGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}

	// ------------------------------------------------------------------
	// 对一个 IWbemLocator 实例做 patch（**幂等**，按 vtable 去重）
	// ------------------------------------------------------------------
	//
	// IWbemLocator 的 vtable 在 wbemprox.dll（模块级共享），所以
	// patch 一次全局生效 —— 后续任何实例都已经是 patch 过的。
	//
	// 两条调用路径：
	//   ① Install 时主动建一个 locator（快速路径，多数进程可行）
	//   ② ComHijackGuard 的 CoCreateInstance hook 在原函数返回后补装
	//      （懒 patch —— 注入那刻 COM 未就绪时的兜底）
	bool g_locatorPatched = false;

	// 重入守卫（thread_local）。
	//
	// ⚠️ PatchWbemLocatorVtable 内部会调 CoCreateInstance —— 而它**会经过
	//    ComHijackGuard 的 CoCreateInstance hook**，那个 hook 在原函数返回后
	//    会调 TryPatchWbemLocator(*ppv, riid) → 又进 PatchLocatorInstance。
	//    虽然是幂等的（第二次 current 已是我们的函数），但"在拿到对象的同
	//    一刻就在我们自己手里 patch 一遍"是多余且危险的：
	//      · 此时对象的引用计数只有 1，我们还在用它；
	//      · 若中途抛异常，外层 PatchWbemLocatorVtable 的 __except 会吞掉，
	//        留下半 patch 状态。
	//    所以：本线程正在 PatchWbemLocatorVtable 里跑时，懒 patch 直接跳过，
	//    由本函数自己统一处理（它会 patch + LoadLibrary 钉住 + 不 Release）。
	bool g_inLocatorPatch = false;

	bool PatchLocatorInstance(void* locator) noexcept
	{
		if (!locator) {
			return false;
		}

		__try {
			void** vtable = *reinterpret_cast<void***>(locator);
			if (!vtable) {
				return false;
			}

			// 已经是我们的函数了 → 视作成功（幂等）。
			//
			// ⚠️ 必须每次都真检查，**不能**用 g_locatorPatched 提前 return。
			//    实测踩到的坑：wbemprox.dll 是按需加载的 WMI proxy ——
			//    Install 里 CoCreateInstance 把它拉起来、patch 掉它的 .rdata
			//    vtable 之后，如果该 DLL 的引用计数归零（Install 线程
			//    CoUninitialize，而宿主线程当时还没初始化 COM），wbemprox
			//    会被卸载；宿主之后自己 CoCreateInstance 时 DLL **重新加载**，
			//    .rdata 是全新页 —— 之前的 patch 就凭空消失了。
			//    （音频那套不会出这个问题：MMDevApi 是常驻的，不卸载。）
			//
			//    所以这里只认"当前槽是不是我们的函数"，是就返回，
			//    不是就**再补一刀**。这正是懒 patch 该有的语义。
			void* current = vtable[kSlotIWbemLocator_ConnectServer];
			if (current == reinterpret_cast<void*>(ConnectServer_Hook)) {
				g_locatorPatched = true;
				return true;
			}
			if (current == nullptr) {
				return false;
			}

			DWORD oldProtect = 0;
			if (!VirtualProtect(&vtable[kSlotIWbemLocator_ConnectServer], sizeof(void*),
				PAGE_READWRITE, &oldProtect)) {
				LOG(L"WmiSubscriptionGuard: locator vtable 改保护失败 err=%u", GetLastError());
				return false;
			}

			pOriginalConnectServer = reinterpret_cast<ConnectServerPtr>(current);
			vtable[kSlotIWbemLocator_ConnectServer] =
				reinterpret_cast<void*>(ConnectServer_Hook);

			DWORD ignored = 0;
			VirtualProtect(&vtable[kSlotIWbemLocator_ConnectServer], sizeof(void*),
				oldProtect, &ignored);

			g_locatorPatched = true;
			g_hookCount++;
			LOG(L"WmiSubscriptionGuard: IWbemLocator::ConnectServer 已 patch（vtable=%p）", vtable);
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LOG(L"WmiSubscriptionGuard: PatchLocatorInstance 异常");
			return false;
		}
	}

	// ------------------------------------------------------------------
	// 主动建一个 IWbemLocator 并 patch（Install 的快速路径）
	// ------------------------------------------------------------------
	// 主动建一个 IWbemLocator 并 patch（Install 的快速路径）。
	// 实际逻辑拆到 PatchWbemLocatorVtableInner —— 便于统一复位重入标志
	// （__try 体内有多个 return，直接复位容易漏）。
	bool PatchWbemLocatorVtableInner() noexcept
	{
		__try {
			const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
			const bool weInitialized = SUCCEEDED(hrInit);
			if (FAILED(hrInit) && hrInit != RPC_E_CHANGED_MODE) {
				// ⚠️ 注入线程上 COM 没初始化是**常态**（v12 的坑）。
				//    这里不当作错误 —— 交给 ComHijackGuard 的懒 patch 兜底。
				LOG(L"WmiSubscriptionGuard: CoInitializeEx 失败 hr=0x%08X（等懒 patch）", hrInit);
				return false;
			}

			// CLSID_WbemLocator = {4590F811-1D3A-11D0-891F-00AA004B2E24}
			const GUID clsidWbemLocator =
				{ 0x4590f811, 0x1d3a, 0x11d0, { 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
			// IID_IWbemLocator = {DC12A687-737F-11CF-884D-00AA004B2E24}
			const GUID iidWbemLocator =
				{ 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };

			void* locator = nullptr;
			// ⚠️ 注意：这里走的是**我们自己的 CoCreateInstance** —— 如果
			//    ComHijackGuard 已经装上了 CoCreateInstance hook，这次调用
			//    会经过它（多一次判定）。重入守卫已让内层懒 patch 直接跳过，
			//    统一由本函数处理。
			HRESULT hr = CoCreateInstance(clsidWbemLocator, nullptr, CLSCTX_INPROC_SERVER,
				iidWbemLocator, &locator);
			if (FAILED(hr) || !locator) {
				LOG(L"WmiSubscriptionGuard: 建 IWbemLocator 失败 hr=0x%08X（等懒 patch）", hr);
				if (weInitialized) CoUninitialize();
				return false;
			}

			const bool patched = PatchLocatorInstance(locator);

			// ★ 把 wbemprox.dll 钉住（有意不 Release 这个引用）。
			//
			//   为什么必须钉：wbemprox.dll 是按需加载的 WMI proxy，我们刚
			//   patch 掉的是它 .rdata 里的静态 vtable。如果它被卸载再重新
			//   加载，新的 .rdata 页是干净的 —— patch 凭空消失（实测踩到，
			//   症状是"日志说 patch 成功、宿主读到的还是原函数"）。
			//   钉一个引用是最省事的固化手段，代价是一次 LoadLibrary 的
			//   DllMain（本进程内只做一次）。
			::LoadLibraryW(L"wbemprox.dll");

			reinterpret_cast<IUnknown*>(locator)->Release();

			// ⚠️ 这里**有意不 CoUninitialize**：一旦撤销 COM 初始化，
			//    wbemprox.dll 的引用计数可能归零而被卸载（见上）。
			//    注入线程保留一次 COM 初始化，对宿主无害。
			(void)weInitialized;
			return patched;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LOG(L"WmiSubscriptionGuard: PatchWbemLocatorVtable 异常");
			return false;
		}
	}

	bool PatchWbemLocatorVtable() noexcept
	{
		if (g_locatorPatched) {
			return true;
		}

		// 重入守卫：本线程已经在 patch 流程中（含我们自己的 CoCreateInstance
		// 触发的懒 patch）→ 直接跳过，避免嵌套 patch 同一个对象。
		if (g_inLocatorPatch) {
			return false;
		}
		g_inLocatorPatch = true;

		const bool ok = PatchWbemLocatorVtableInner();

		g_inLocatorPatch = false;
		return ok;
	}
}

namespace WmiSubscriptionGuard
{
	int HookCount() noexcept
	{
		return g_hookCount;
	}

	int PatchedServicesCount() noexcept
	{
		return g_patchedServicesCount;
	}

	// 懒 patch 入口（由 ComHijackGuard 的 CoCreateInstance hook 调用）。
	bool TryPatchWbemLocator(void* pv, const GUID& riid) noexcept
	{
		if (!pv) {
			return false;
		}
		// IID_IWbemLocator = {DC12A687-737F-11CF-884D-00AA004B2E24}
		static const GUID kIidWbemLocator =
			{ 0xdc12a687, 0x737f, 0x11cf, { 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 } };
		if (!IsEqualGUID(riid, kIidWbemLocator)) {
			return false;
		}
		return PatchLocatorInstance(pv);
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"WmiSubscriptionGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookWmiSubscription) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"WmiSubscriptionGuard: hook_wmi_subscription 未开启，本进程不挂 WMI 订阅 hook");
			return true;
		}

		g_bypass = false;

		// WMI 是纯 COM（无导出可挂）—— 只能 vtable patch。
		// 主动建一个 IWbemLocator 拿它的 vtable（模块级共享，patch 一次全局生效）。
		//
		// ⚠️ 这里**不置 g_installed 的失败分支** —— 如果这次没 patch 上
		//    （比如 COM 不可用），允许后续重试（Install 可能被多次调用）。
		if (PatchWbemLocatorVtable()) {
			g_installed = true;
		}
		else {
			LOG(L"WmiSubscriptionGuard: IWbemLocator patch 未成功，拒绝报告安装成功");
			return false;
		}

		LOG(L"WmiSubscriptionGuard: 挂载完成，hook=%d (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
