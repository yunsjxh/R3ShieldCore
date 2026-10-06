#include "stdafx.h"
#include "r3shieldcore_prompt_ui.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_toast.h"
#include "logger.h"

#include <commctrl.h>

namespace
{
	constexpr ULONG MaxRules = 256;

	// 决策缓存。只有 UI 线程碰它，所以不需要加锁。
	//
	// ⚠️ objectType / op 必须参与匹配。
	//   早期版本只比 (进程路径, 目标路径前缀) —— 后果是用户在
	//   「CreateFile（打开/创建）」上点一次「始终允许」，同一个进程对该
	//   目标的「删除 / 改名 / 改 ACL / 截断」也全部自动放行，因为它们
	//   共享同一条规则。语义上是"我信任它打开这个文件"≠"我信任它删这个文件"，
	//   必须区分。踩过的实例：误点 hosts 的 CreateFile「始终允许」后，
	//   该进程后续对 hosts 的任何操作都不再弹窗。
	struct Rule
	{
		bool used;
		bool allow;
		ULONG objectType;	// R3ShieldCore::ObjectType，必须一致
		ULONG op;			// 各自枚举空间下的操作码，必须一致
		WCHAR processPath[R3ShieldCore::MaxProcessPathChars];
		WCHAR keyPath[R3ShieldCore::MaxKeyPathChars];
	};

	Rule g_rules[MaxRules];
	ULONG g_nextRuleSlot = 0;

	HANDLE g_uiThread = nullptr;
	volatile LONG g_stop = 0;
	ULONG g_timeoutMs = 30000;
	R3ShieldCore::Verdict g_timeoutVerdict = R3ShieldCore::Verdict::Deny;

	// 前缀匹配，但要求边界落在 '\' 上，
	// 否则规则 ...\Software\Foo 会误命中 ...\Software\FooBar
	bool IsKeyPrefixMatch(PCWSTR prefix, PCWSTR path) noexcept
	{
		size_t prefixLength = wcslen(prefix);
		if (prefixLength == 0 || _wcsnicmp(prefix, path, prefixLength) != 0) {
			return false;
		}

		WCHAR next = path[prefixLength];
		return next == L'\0' || next == L'\\';
	}

	bool LookupCached(const R3ShieldCore::PromptSlot& request, R3ShieldCore::Verdict& verdict) noexcept
	{
		for (ULONG i = 0; i < MaxRules; i++) {
			if (!g_rules[i].used) {
				continue;
			}

			if (_wcsicmp(g_rules[i].processPath, request.ProcessPath) != 0) {
				continue;
			}

			// 对象类型 + 操作类型都必须一致。
			// 「允许打开」不等于「允许删除」，不能复用同一条决策。
			if (g_rules[i].objectType != request.ObjectType) {
				continue;
			}

			if (g_rules[i].op != request.Op) {
				continue;
			}

			if (!IsKeyPrefixMatch(g_rules[i].keyPath, request.KeyPath)) {
				continue;
			}

			verdict = g_rules[i].allow ? R3ShieldCore::Verdict::Allow : R3ShieldCore::Verdict::Deny;
			return true;
		}

		return false;
	}

	void AddRule(const R3ShieldCore::PromptSlot& request, bool allow) noexcept
	{
		Rule& rule = g_rules[g_nextRuleSlot % MaxRules];
		g_nextRuleSlot++;

		rule.used = true;
		rule.allow = allow;
		rule.objectType = request.ObjectType;
		rule.op = request.Op;
		wcsncpy_s(rule.processPath, request.ProcessPath, _TRUNCATE);
		wcsncpy_s(rule.keyPath, request.KeyPath, _TRUNCATE);
	}

	// 进程名（含扩展名），用于通知标题。
	PCWSTR ProcessNameOf(PCWSTR processPath) noexcept
	{
		PCWSTR name = wcsrchr(processPath, L'\\');
		name = name ? name + 1 : processPath;
		return (name && name[0]) ? name : L"(未知程序)";
	}

	// 弹一张右下角通知卡片，等用户点按钮。
	R3ShieldCore::Verdict ShowPromptToast(const R3ShieldCore::PromptSlot& request) noexcept
	{
		PCWSTR processName = ProcessNameOf(request.ProcessPath);
		const auto objectType = static_cast<R3ShieldCore::ObjectType>(request.ObjectType);
		const bool isFile = (objectType == R3ShieldCore::ObjectType::File);
		const bool isNetwork = (objectType == R3ShieldCore::ObjectType::Network);
		const bool hive = !isNetwork &&
			(request.TargetKind == static_cast<ULONG>(R3ShieldCore::TargetKind::Hive));
		const bool highRisk = (request.Flags & R3ShieldCore::FlagEventHighRisk) != 0;

		//
		// 标题。高危优先 —— "这件事很敏感"要写在标题里，
		// 用户扫一眼卡片标题就该知道要不要仔细看。
		// 高危之下再按对象类型分措辞。
		//
		WCHAR title[512] = {};
		if (highRisk) {
			switch (objectType) {
			case R3ShieldCore::ObjectType::Process:
				swprintf_s(title, L"⚠ %s 想要启动高危程序", processName);
				break;
			case R3ShieldCore::ObjectType::Thread:
				swprintf_s(title, L"⚠ %s 想要向其他进程注入线程", processName);
				break;
			case R3ShieldCore::ObjectType::Driver:
				swprintf_s(title, L"⚠ %s 想要加载内核驱动", processName);
				break;
			case R3ShieldCore::ObjectType::Network:
				swprintf_s(title, L"⚠ %s 想要连接敏感网络目标", processName);
				break;
			case R3ShieldCore::ObjectType::Camera:
				swprintf_s(title, L"⚠ %s 想要打开摄像头/麦克风", processName);
				break;
			case R3ShieldCore::ObjectType::InputHook:
				swprintf_s(title, L"⚠ %s 想要监听鼠标/键盘输入", processName);
				break;
			case R3ShieldCore::ObjectType::Screen:
				swprintf_s(title, L"⚠ %s 想要截取屏幕内容", processName);
				break;
			case R3ShieldCore::ObjectType::DllLoad:
				swprintf_s(title, L"⚠ %s 想要加载非系统目录的 DLL", processName);
				break;
			case R3ShieldCore::ObjectType::Clipboard:
				swprintf_s(title, L"⚠ %s 想要读取剪贴板内容", processName);
				break;
			case R3ShieldCore::ObjectType::ProcessSpawn:
				swprintf_s(title, L"⚠ %s 想要用特殊上下文启动程序", processName);
				break;
			case R3ShieldCore::ObjectType::ServiceConfig:
				swprintf_s(title, L"⚠ %s 想要修改服务/对象的访问权限", processName);
				break;
			case R3ShieldCore::ObjectType::ComHijack:
				swprintf_s(title, L"⚠ %s 想要加载用户可写目录里的 COM 服务器", processName);
				break;
			case R3ShieldCore::ObjectType::ScheduledTask:
				swprintf_s(title, L"⚠ %s 想要注册 / 运行计划任务", processName);
				break;
			default:
				swprintf_s(title, L"⚠ %s 想要修改系统关键设置", processName);
				break;
			}
		}
		else if (isFile) {
			// 文件这边动作差异很大（写一个字节 vs 删掉整个目录），
			// 标题不写具体动作，让下面的操作行去说，避免措辞过重。
			swprintf_s(title, L"%s 想要修改文件", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Process) {
			swprintf_s(title, L"%s 想要启动程序", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Thread) {
			swprintf_s(title, L"%s 想要创建线程", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Driver) {
			swprintf_s(title, L"%s 想要加载或卸载驱动", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Network) {
			swprintf_s(title, L"%s 想要访问网络", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Camera) {
			swprintf_s(title, L"%s 想要访问摄像头设备", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::InputHook) {
			swprintf_s(title, L"%s 想要安装输入钩子", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Screen) {
			swprintf_s(title, L"%s 想要抓取屏幕", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::DllLoad) {
			swprintf_s(title, L"%s 想要加载 DLL", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::Clipboard) {
			swprintf_s(title, L"%s 想要访问剪贴板", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::ProcessSpawn) {
			swprintf_s(title, L"%s 想要启动程序", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::ServiceConfig) {
			swprintf_s(title, L"%s 想要修改服务权限", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::ComHijack) {
			swprintf_s(title, L"%s 想要创建 COM 对象", processName);
		}
		else if (objectType == R3ShieldCore::ObjectType::ScheduledTask) {
			swprintf_s(title, L"%s 想要访问计划任务", processName);
		}
		else if (hive) {
			// hive 级操作是把整个「注册表配置单元」挂上/导出/覆盖，
			// 影响面远大于改一个值，措辞必须让用户意识到这一点。
			swprintf_s(title, L"%s 想要挂载或替换注册表配置单元", processName);
		}
		else {
			swprintf_s(title, L"%s 想要修改注册表", processName);
		}

		// OpName 返回窄字符串（ASCII），转成宽字符给通知用。
		// 必须按对象类型取名字，否则文件事件会把 op 数值当注册表 op 解释。
		WCHAR operation[64] = {};
		MultiByteToWideChar(CP_ACP, 0, R3ShieldCore::AnyOpName(request.ObjectType, request.Op),
			-1, operation, _countof(operation));

		R3ShieldCoreToast::Request toast = {};
		toast.Title = title;
		toast.Operation = operation;

		// 网络事件的第二个字段（端口/协议/本端）不在 ValueName 里，
		// 需要现拼。缓冲放在函数作用域内，toast 只持指针。
		WCHAR netDetail[192] = {};
		if (isNetwork) {
			if (static_cast<R3ShieldCore::NetOp>(request.Op) == R3ShieldCore::NetOp::DnsQuery) {
				wcsncpy_s(netDetail, L"域名解析请求", _TRUNCATE);
			}
			else if (request.TargetPort != 0) {
				WCHAR wideProto[16] = {};
				MultiByteToWideChar(CP_ACP, 0,
					R3ShieldCore::NetProtocolName(request.NetProtocol),
					-1, wideProto, _countof(wideProto));
				swprintf_s(netDetail, L"端口 %u (%s)", request.TargetPort, wideProto);
			}
			else {
				wcsncpy_s(netDetail, L"(无端口)", _TRUNCATE);
			}

			if (request.LocalPort != 0 && request.LocalAddress[0]) {
				WCHAR local[96] = {};
				swprintf_s(local, L"本端 %s:%u", request.LocalAddress, request.LocalPort);
				size_t used = wcslen(netDetail);
				if (used + 4 + wcslen(local) < _countof(netDetail)) {
					wcscat_s(netDetail, L"  ·  ");
					wcscat_s(netDetail, local);
				}
			}
		}

		toast.Target = request.KeyPathLength ? request.KeyPath : L"(未解析)";

		// 第二字段按对象类型选：
		//   进程旁路 → CommandLine（真正"起了什么"在这条命令行里）
		//   其余     → ValueName（DLL 加载没有第二字段，置 null）
		if (objectType == R3ShieldCore::ObjectType::ProcessSpawn) {
			toast.Extra = (request.CommandLine[0]) ? request.CommandLine : nullptr;
		}
		else if (objectType == R3ShieldCore::ObjectType::DllLoad) {
			toast.Extra = nullptr;
		}
		else {
			toast.Extra = request.ValueNameLength ? request.ValueName : nullptr;
		}
		toast.NetDetail = isNetwork ? netDetail : nullptr;
		toast.ProcessPath = request.ProcessPath;
		toast.ProcessId = request.ProcessId;
		toast.ObjectType = request.ObjectType;
		toast.TargetProcessId = 0;
		toast.IsHive = hive;
		toast.IsFile = isFile;
		toast.IsHighRisk = highRisk;
		toast.TimeoutMs = g_timeoutMs;
		toast.TimeoutVerdict = g_timeoutVerdict;

		R3ShieldCoreToast::Action action = R3ShieldCoreToast::Show(toast);
		bool timedOut = R3ShieldCoreToast::LastWasTimedOut();

		R3ShieldCore::Verdict verdict = g_timeoutVerdict;
		switch (action) {
		case R3ShieldCoreToast::Action::Allow:
			verdict = R3ShieldCore::Verdict::Allow;
			break;
		case R3ShieldCoreToast::Action::Deny:
			verdict = R3ShieldCore::Verdict::Deny;
			break;
		case R3ShieldCoreToast::Action::AllowAlways:
			verdict = R3ShieldCore::Verdict::AllowAlways;
			break;
		case R3ShieldCoreToast::Action::DenyAlways:
			verdict = R3ShieldCore::Verdict::DenyAlways;
			break;
		case R3ShieldCoreToast::Action::Expired:
		case R3ShieldCoreToast::Action::None:
		default:
			verdict = g_timeoutVerdict;
			break;
		}

		// 记一次询问统计（引擎侧 GUI 面板会读）。
		R3ShieldCorePromptUi::NotePromptResult(verdict, timedOut);
		return verdict;
	}

	DWORD WINAPI UiThreadProc(void* /*parameter*/)
	{
		// 通知窗口类必须在这个线程上注册 —— 之后所有卡片都在这里创建和销毁。
		// HINSTANCE 用 DLL 自身的模块句柄（这个 DLL 的窗口类只能在本模块注册）。
		HMODULE instance = nullptr;
		GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<PCWSTR>(&UiThreadProc), &instance);

		if (!R3ShieldCoreToast::Initialize(instance)) {
			LOG(L"R3ShieldCore: 询问通知窗口类注册失败，将退回无界面（直接按兜底结论处理）");
		}

		while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
			R3ShieldCore::PromptHeader* header = R3ShieldCorePrompt::Header();
			ULONG count = R3ShieldCorePrompt::SlotCount();
			bool handledAny = false;

			if (header && count > 0) {
				R3ShieldCore::PromptSlot* slots = R3ShieldCore::PromptSlotBase(header);

				for (ULONG i = 0; i < count; i++) {
					if (slots[i].State != R3ShieldCore::PromptSlotPending) {
						continue;
					}

					// 先快照：DLL 可能随时超时把槽释放掉。
					R3ShieldCore::PromptSlot request;
					memcpy(&request, &slots[i], sizeof(R3ShieldCore::PromptSlot));
					LONG generation = request.Generation;

					R3ShieldCore::Verdict verdict;
					if (LookupCached(request, verdict)) {
						// 命中决策缓存，不弹窗，直接答复。
					}
					else {
						verdict = ShowPromptToast(request);

						if (verdict == R3ShieldCore::Verdict::AllowAlways) {
							AddRule(request, true);
						}
						else if (verdict == R3ShieldCore::Verdict::DenyAlways) {
							AddRule(request, false);
						}
					}

					R3ShieldCorePrompt::Answer(i, generation, verdict);
					handledAny = true;
				}
			}

			if (handledAny) {
				continue;
			}

			HANDLE requestEvent = R3ShieldCorePrompt::RequestEvent();
			if (!requestEvent) {
				break;
			}

			WaitForSingleObject(requestEvent, 200);
		}

		// 收尾：把还挂着的卡片全部清掉。
		R3ShieldCoreToast::Shutdown();
		return 0;
	}
}

namespace R3ShieldCorePromptUi
{
	bool Start() noexcept
	{
		if (g_uiThread) {
			return true;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy) {
			if (policy->PromptTimeoutMs > 0) {
				g_timeoutMs = policy->PromptTimeoutMs;
			}

			if (policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
				g_timeoutVerdict = static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
			}
		}

		InterlockedExchange(&g_stop, 0);

		g_uiThread = CreateThread(nullptr, 0, UiThreadProc, nullptr, 0, nullptr);
		if (!g_uiThread) {
			LOG(L"R3ShieldCore: 询问 UI 线程创建失败，错误 %u", GetLastError());
			return false;
		}

		LOG(L"R3ShieldCore: 询问 UI 已启动（右下角通知），超时 %u ms，兜底 %S",
			g_timeoutMs,
			g_timeoutVerdict == R3ShieldCore::Verdict::Allow ? "允许" : "拒绝");
		return true;
	}

	void Stop() noexcept
	{
		if (!g_uiThread) {
			return;
		}

		InterlockedExchange(&g_stop, 1);

		HANDLE requestEvent = R3ShieldCorePrompt::RequestEvent();
		if (requestEvent) {
			// 叫醒它，让它看到 g_stop。
			SetEvent(requestEvent);
		}

		WaitForSingleObject(g_uiThread, 5000);
		CloseHandle(g_uiThread);
		g_uiThread = nullptr;
	}

	void NotePromptResult(R3ShieldCore::Verdict verdict, bool timedOut) noexcept
	{
		// 累计询问统计，写进共享内存的 Policy 块（引擎只读）。
		// 这块区域本来是只读的策略，但末尾留了统计槽，见 r3shieldcore_shared.h。
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy) {
			return;
		}

		InterlockedIncrement(&policy->PromptShown);
		if (timedOut) {
			InterlockedIncrement(&policy->PromptTimedOut);
		}

		switch (verdict) {
		case R3ShieldCore::Verdict::Allow:
		case R3ShieldCore::Verdict::AllowAlways:
			InterlockedIncrement(&policy->PromptAllowed);
			break;
		case R3ShieldCore::Verdict::Deny:
		case R3ShieldCore::Verdict::DenyAlways:
			InterlockedIncrement(&policy->PromptDenied);
			break;
		default:
			break;
		}
	}

	void ReadPromptStats(ULONG& shown, ULONG& allowed, ULONG& denied, ULONG& timedOut) noexcept
	{
		shown = allowed = denied = timedOut = 0;

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy) {
			return;
		}

		shown = static_cast<ULONG>(InterlockedCompareExchange(&policy->PromptShown, 0, 0));
		allowed = static_cast<ULONG>(InterlockedCompareExchange(&policy->PromptAllowed, 0, 0));
		denied = static_cast<ULONG>(InterlockedCompareExchange(&policy->PromptDenied, 0, 0));
		timedOut = static_cast<ULONG>(InterlockedCompareExchange(&policy->PromptTimedOut, 0, 0));
	}
}
