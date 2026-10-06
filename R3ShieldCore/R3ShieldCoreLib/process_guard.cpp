#include "stdafx.h"
#include "process_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "inject_activity.h"
#include "logger.h"

//
// 进程 / 线程行为监控层。
//
// 与 registry_guard.cpp / file_guard.cpp 是同一套骨架（判定 → 上报 / 拒绝 →
// 等排空），差别在：
//
//   1. 这里有两个对象类型（Process / Thread），靠 event.ObjectType 区分。
//   2. 拦截策略是"高危才拦" —— 普通创建只在 LOG 语义下记录。
//      原因：线程创建极高频（Chrome 每秒几十上百个），一刀切会打瘫系统。
//      只有高危（远程线程注入、System32/临时目录起进程、Office→cmd…）
//      才走询问。
//   3. 进程创建成功后，新进程的 pid 在返回参数里（不是入参），
//      所以事件必须在原函数返回之后才组装。
//
// 不 include <winternl.h> 的原因同 registry_guard.cpp：项目 stdafx.h 带了
// ntsecapi.h → SubAuth.h，会定义 NTSTATUS / UNICODE_STRING，重复定义会冲突。
// 这里自己写布局等价的本地类型。
//
namespace
{
	struct PG_UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};

	struct PG_OBJECT_ATTRIBUTES
	{
		ULONG Length;
		HANDLE RootDirectory;
		PG_UNICODE_STRING* ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	};

	struct PG_CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	};

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

	// ntdll 原型。
	//
	// NtCreateUserProcess 有 11 个参数，而且 RTL_USER_PROCESS_PARAMETERS
	// 的结构版本相关 —— 我们不解析它，只在返回后看 ProcessHandle 反查 pid。
	typedef NTSTATUS(NTAPI* NtCreateUserProcessPtr)(PHANDLE, PHANDLE, ACCESS_MASK,
		ACCESS_MASK, PVOID, PVOID, ULONG, ULONG, PVOID, PVOID, PVOID);
	typedef NTSTATUS(NTAPI* NtCreateProcessExPtr)(PHANDLE, ACCESS_MASK,
		const PG_OBJECT_ATTRIBUTES*, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);
	typedef NTSTATUS(NTAPI* NtTerminateProcessPtr)(HANDLE, NTSTATUS);

	//
	// v18：老 API（不是 Ex 变体）。
	//
	//   NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes,
	//                   ParentProcess, InheritObjectTable, SectionHandle,
	//                   DebugPort, ExceptionPort)          ← 8 参，无 Flags
	//
	//   NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes,
	//                  ProcessHandle, ClientId, ThreadContext,
	//                  InitialTeb, CreateSuspended)        ← 8 参，有 ClientId
	//
	typedef NTSTATUS(NTAPI* NtCreateProcessPtr)(PHANDLE, ACCESS_MASK,
		const PG_OBJECT_ATTRIBUTES*, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
	typedef NTSTATUS(NTAPI* NtCreateThreadPtr)(PHANDLE, ACCESS_MASK,
		const PG_OBJECT_ATTRIBUTES*, HANDLE, PG_CLIENT_ID*, PVOID, PVOID, BOOLEAN);
	typedef NTSTATUS(NTAPI* NtCreateThreadExPtr)(PHANDLE, ACCESS_MASK,
		const PG_OBJECT_ATTRIBUTES*, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T,
		SIZE_T, PVOID);
	typedef NTSTATUS(NTAPI* NtTerminateThreadPtr)(HANDLE, NTSTATUS);
	typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtOpenProcessPtr)(PHANDLE, ACCESS_MASK,
		const PG_OBJECT_ATTRIBUTES*, const PG_CLIENT_ID*);

	//
	// v14：代码注入链前三步。
	//
	// 原型取自 ntdll 导出（PHNT / ntifs.h）：
	//   NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)
	//   NtProtectVirtualMemory (HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)
	//   NtWriteVirtualMemory   (HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T)
	//
	// ⚠️ 第 1 个参数是**目标进程句柄**（不是 pid）—— 要靠 PidFromHandle 反查。
	typedef NTSTATUS(NTAPI* NtAllocateVirtualMemoryPtr)(HANDLE, PVOID*, ULONG_PTR,
		PSIZE_T, ULONG, ULONG);
	typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryPtr)(HANDLE, PVOID*, PSIZE_T,
		ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryPtr)(HANDLE, PVOID, PVOID, SIZE_T,
		PSIZE_T);

	NtCreateUserProcessPtr pOriginalNtCreateUserProcess = nullptr;
	NtCreateProcessExPtr pOriginalNtCreateProcessEx = nullptr;
	NtCreateProcessPtr pOriginalNtCreateProcess = nullptr;   // v18
	NtCreateThreadPtr pOriginalNtCreateThread = nullptr;     // v18
	NtTerminateProcessPtr pOriginalNtTerminateProcess = nullptr;
	NtCreateThreadExPtr pOriginalNtCreateThreadEx = nullptr;
	NtTerminateThreadPtr pOriginalNtTerminateThread = nullptr;
	NtOpenProcessPtr pOriginalNtOpenProcess = nullptr;
	NtAllocateVirtualMemoryPtr pOriginalNtAllocateVirtualMemory = nullptr;
	NtProtectVirtualMemoryPtr pOriginalNtProtectVirtualMemory = nullptr;
	NtWriteVirtualMemoryPtr pOriginalNtWriteVirtualMemory = nullptr;

	// NtQueryInformationProcess 不挂 hook，只留干净指针反查 pid。
	NtQueryInformationProcessPtr pOriginalNtQueryInformationProcess = nullptr;

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

	constexpr ULONG ProcessBasicInformation = 0;

	struct PG_PROCESS_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR InheritedFromUniqueProcessId;
	};

	// ------------------------------------------------------------------
	// 工具
	// ------------------------------------------------------------------
	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	void CopyUnicodeString(const PG_UNICODE_STRING* source, WCHAR* destination,
		ULONG capacity, ULONG& length) noexcept
	{
		length = 0;
		if (!source || !source->Buffer || source->Length == 0) {
			return;
		}

		ULONG chars = source->Length / sizeof(WCHAR);
		if (chars > capacity) {
			chars = capacity;
		}

		memcpy(destination, source->Buffer, chars * sizeof(WCHAR));
		length = chars;
	}

	// \??\C:\Foo → C:\Foo。这里是复刻 file_guard 的逻辑 ——
	// 不共享是因为两边都在 anonymous namespace 里，导出会引入耦合。
	void NormalizeDosPrefix(WCHAR* path, ULONG capacity) noexcept
	{
		if (capacity < 5) {
			return;
		}

		if (wcsncmp(path, L"\\??\\", 4) == 0) {
			size_t length = wcslen(path + 4);
			memmove(path, path + 4, (length + 1) * sizeof(WCHAR));
			return;
		}

		if (_wcsnicmp(path, L"\\DosDevices\\", 12) == 0) {
			size_t length = wcslen(path + 12);
			memmove(path, path + 12, (length + 1) * sizeof(WCHAR));
		}
	}

	bool DevicePathToDosPath(WCHAR* path, ULONG capacity) noexcept
	{
		if (capacity == 0 || _wcsnicmp(path, L"\\Device\\", 8) != 0) {
			return false;
		}

		PCWSTR rest = path + 8;
		PCWSTR slash = wcschr(rest, L'\\');
		if (!slash) {
			return false;
		}

		size_t deviceNameChars = static_cast<size_t>(slash - path);

		WCHAR deviceName[R3ShieldCore::MaxImagePathChars] = {};
		if (deviceNameChars >= _countof(deviceName)) {
			return false;
		}

		wcsncpy_s(deviceName, path, deviceNameChars);

		for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
			WCHAR drive[3] = { letter, L':', L'\0' };
			WCHAR target[R3ShieldCore::MaxImagePathChars] = {};
			if (QueryDosDevice(drive, target, _countof(target)) == 0) {
				continue;
			}

			if (_wcsicmp(target, deviceName) != 0) {
				continue;
			}

			WCHAR converted[R3ShieldCore::MaxKeyPathChars] = {};
			if (swprintf_s(converted, L"%s%s", drive, slash) < 0) {
				return false;
			}

			if (wcslen(converted) >= capacity) {
				return false;
			}

			wcscpy_s(path, capacity, converted);
			return true;
		}

		return false;
	}

	void NormalizeFilePath(WCHAR* path, ULONG capacity) noexcept
	{
		NormalizeDosPrefix(path, capacity);
		DevicePathToDosPath(path, capacity);
	}

	// 由进程句柄反查 pid。NtQueryInformationProcess 走干净指针，不会递归。
	ULONG PidFromHandle(HANDLE processHandle) noexcept
	{
		if (!processHandle || processHandle == INVALID_HANDLE_VALUE ||
			!pOriginalNtQueryInformationProcess) {
			return 0;
		}

		PG_PROCESS_BASIC_INFORMATION info = {};
		ULONG length = 0;
		NTSTATUS status = pOriginalNtQueryInformationProcess(processHandle,
			ProcessBasicInformation, &info, sizeof(info), &length);
		if (status < 0) {
			return 0;
		}

		return static_cast<ULONG>(info.UniqueProcessId);
	}

	// 拿父进程镜像路径。用于"可疑父子关系"判定。
	// 失败返回空 —— 判不出父子关系不算高危，只是少一条规则。
	void ParentImagePath(ULONG parentPid, WCHAR* buffer, ULONG capacity) noexcept
	{
		buffer[0] = L'\0';

		if (parentPid == 0) {
			return;
		}

		HANDLE parent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
		if (!parent) {
			return;
		}

		DWORD size = capacity;
		if (QueryFullProcessImageName(parent, 0, buffer, &size)) {
			buffer[capacity - 1] = L'\0';
		}
		else {
			buffer[0] = L'\0';
		}

		CloseHandle(parent);
	}

	// ------------------------------------------------------------------
	// 上报
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event, R3ShieldCore::ObjectType objectType) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(objectType);
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

	// ------------------------------------------------------------------
	// 该模式下的"进程/线程/内存"判定，遇到本该拦的操作时，是**弹窗问**
	// 还是**直接拒**？
	//
	//   Ask 模式               → 弹窗（原有语义）
	//   block_all / _safe      → **直接拒**（★ v66 起恢复为硬拒，见下）
	//   其余（log / block）    → 不弹窗（保持原样）
	//
	// ⚠️ 为什么全拦模式**不弹窗**（v66 撤销了 v21 的"先问再拦"）：
	//    ① 语义：`block_all` 的名字就是"全拦"。v21 起它命中后弹窗、
	//       用户点「允许」即放行 —— 那等于把"是否拦"交给被拦者去按，
	//       与"全拦"自相矛盾，也给了社工/诱导点击的入口。
	//    ② 可用性代价**已经不存在**：v21 当初改成弹窗，是因为 v20 的
	//       硬拒把 UAC 提权链一起拒了（用户实测：金山毒霸的 UAC 组件、
	//       VMware Tools 被一刀切拒掉 ⇒"Windows 无法访问设备"）。
	//       但 **v42 引入瘦注入后，这条链已经结构性地不受监控**：
	//       提权链的父进程是 `svchost.exe`（AppInfo 服务），而
	//       `explorer.exe` / `svchost.exe` / `runtimebroker.exe` 走的是
	//       **瘦会话 —— 一个 guard 都不装**（见 customization_session.cpp）。
	//       ⇒ AppInfo 拉起 `consent.exe`、以及随后的提权进程，**根本不经过
	//       本函数**，硬拒碰不到它们。所以 v21 那个"为了保 UAC"的理由
	//       在 v42 之后已经不成立。
	//    ③ 兜底仍然保留：万一将来注入策略变了（例如关掉 `inject_shell_thin`
	//       又改成全量注入 `svchost.exe`），`IsUacConsentImage` 这道最小
	//       白名单会挡住"把 UAC 同意框拒掉"这一种致命后果。
	//
	// ⚠️ 硬拒**不看 `prompt_default`**：`prompt_timeout` / `prompt_default`
	//    这两个键从此**只对 Ask 模式有效**。全拦模式下即使把
	//    `prompt_default=allow` 也依然是拒 —— 否则"全拦"又能被一行配置放水。
	//
	// ⚠️ 前提：UI 线程必须真的在 —— 这条现在**只对 Ask 模式**有意义。
	//    启动路径上是无条件建的（main.cpp 的 R3ShieldCorePrompt::Create +
	//    R3ShieldCorePromptUi::Start）。若 UI 线程不在，Ask 模式下
	//    `R3ShieldCorePrompt::Ask` 会**立刻**返回 fallback，只是不会卡超时。
	// ------------------------------------------------------------------
	bool ModeAllowsAsk(ULONG mode) noexcept
	{
		// ★ v66：**只有 Ask 模式弹窗**。全拦模式（block_all / block_all_safe）
		//   一律走各自分支里的"直接拒"，不再经过这里。
		return mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
	}

	// ------------------------------------------------------------------
	// 核心判定（进程）。
	//
	// 语义：高危 → 询问；普通 → 只按 LOG 记录，绝不拦。
	// 这是和注册表/文件那两套最大的不同 —— 那边是"按 mode 一刀切"，
	// 这边必须"只拦高危"，否则一个 block 模式就把系统打死。
	// ------------------------------------------------------------------
	struct Decision
	{
		Action action;
		bool highRisk;
	};

	// allowAsk 的意义：
	//   决定"本该拦的操作"是弹窗询问还是直接拒绝。见 ModeAllowsAsk ——
	//   Ask 模式与全拦模式（block_all / block_all_safe）都是 true。
	//   LOG/BLOCK 下若还调 R3ShieldCorePrompt::Ask，就是在等一个永远不会来的
	//   答复，白等满 prompt_timeout 秒（默认 30s）然后返回 fallback=deny ——
	//   表现为"LOG 模式本该全放行，却把高危操作拒了，还卡半分钟"。
	//   所以 LOG/BLOCK 下高危只记录（标 WouldBlock），不弹窗不阻塞。
	Decision EvaluateProcess(R3ShieldCore::Event& event, PCWSTR imagePath, ULONG newPid,
		ULONG parentPid, bool blockable, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Process);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all / block_all_safe）----
		//
		// ★ v66：判定顺序（**恢复为硬拒**，撤销 v21 的"先问再拦"）：
		//
		//   ① block_all_safe 且来源可信（系统目录 + 微软签名）
		//        → 直接放行。这一条**只属于 block_all_safe**。
		//
		//   ② UAC 提权链的"同意框本体"（`consent.exe` 等，且限 System32）
		//        → 直接放行。这是硬拒之后唯一保留的缝 —— 见
		//          `R3ShieldCoreRules::IsUacConsentImage` 的理由。
		//
		//   ③ 其余**一律直接拒**：不弹窗、不问用户、**不看 `prompt_default`**。
		//
		// ★ 为什么不再用"父进程是不是人操作中介"来分档：
		//    v22 引入 `IsUserInitiatedLaunch(parentPath)`，是为了在"弹窗"
		//    与"直接拒"之间选一个。现在全拦模式下两条路都归为"直接拒"，
		//    这个判据在本分支里已无用处 ⇒ 一并删掉，少一层可被绕的判据。
		//    （该函数本身仍被 Ask 模式与规则层使用，**没有删函数**。）
		//
		// ★ 可用性为什么不受影响（v21 当初改成弹窗的理由已失效）：
		//    v21 改弹窗是为了保 UAC 提权链（v20 硬拒把金山毒霸 UAC 组件、
		//    VMware Tools 一起拒了）。但 **v42 的瘦注入**已经让这条链
		//    **结构性不受监控**：提权链的父进程 `svchost.exe`（AppInfo）
		//    走瘦会话、**一个 guard 都不装** ⇒ AppInfo 拉起的 `consent.exe`
		//    与提权进程根本不进本函数。所以硬拒碰不到它们。
		//    ② 那道白名单是**兜底**：万一将来又改成全量注入 svchost。
		//
		// ⚠️ 计数口径：本分支**不再** `HighRiskAsked++`（不问任何人），
		//    被拒的事件仍写 `Decision=Blocked` + `FlagEventBlocked` 进日志，
		//    与 v20 的硬拒口径一致（不额外动 `HighRiskBlocked` 计数）。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			// ① block_all_safe：可信来源直接放行。
			if (R3ShieldCore::IsBlockAllSafeMode(mode) &&
				R3ShieldCoreRules::IsTrustedLaunchImage(imagePath)) {
				// 来源可信 → 放行创建，不弹窗。后续的跨进程内存 / 线程 /
				// APC 仍全拦，所以 RunPE 链路依然会在"写内存"那一步断掉。
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return { Action::Record, false };
			}

			// ② ★ v66：UAC 提权链最小白名单（同意框本体）。
			//
			//    只放行 `%SystemRoot%\System32\` 下的 consent.exe /
			//    CredentialUIBroker.exe / LogonUI.exe。**不放行**被提权的
			//    目标程序（那是任意镜像，路径判据认不出来，硬拒是对的）。
			if (R3ShieldCoreRules::IsUacConsentImage(imagePath)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return { Action::Record, false };
			}

			// ③ 其余一律直接拒。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return { Action::Block, true };
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			// 先看"可执行来源"规则，再看"父子关系"规则。
			if (R3ShieldCoreRules::IsHighRiskProcessImage(imagePath,
					static_cast<ULONG>(R3ShieldCore::ProcessOp::Create), parentPid)) {
				highRisk = true;
			}
			else {
				WCHAR parentPath[R3ShieldCore::MaxImagePathChars] = {};
				ParentImagePath(parentPid, parentPath, _countof(parentPath));
				if (parentPath[0] &&
					R3ShieldCoreRules::ProcessPairRiskReason(parentPath, imagePath) != nullptr) {
					highRisk = true;
				}
			}

			if (highRisk) {
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		if (!blockable) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		//
		// 阻断/询问判定。注意：普通进程创建**不按 mode 拦**。
		//
		// 只有高危才拦 —— 这是刻意的设计，不是漏了。
		//
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return { Action::Record, highRisk };
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block) && !highRisk) {
			// BLOCK 模式下普通进程创建也不拦！只记录。
			//
			// 理由：进程创建是系统正常运转的基础。BLOCK 模式的本意是
			// "拒绝非系统程序的写操作"，不是"禁止起新进程"。
			// 一刀切拒绝会导致任何程序（包括资源管理器双击）都打不开。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask) && !highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		// 走到这里 = highRisk。
		//
		// ASK 模式弹窗询问；BLOCK 模式**直接拒绝**（BLOCK 的本意就是拦，
		// 而且不需要 UI，也就不存在"白等 prompt 超时"的问题）；LOG 模式只记录。
		if (!allowAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return { Action::Block, highRisk };
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return { Action::Record, highRisk };
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：通道不可用时降级。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return { Action::Record, highRisk };
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return { Action::Block, highRisk };
	}

	// ------------------------------------------------------------------
	// 核心判定（线程）。
	//
	// 只判一个问题：是不是跨进程（远程）线程。是 → 高危 → 询问。
	// 本进程内的线程创建完全正常，按开关决定记不记（默认不记）。
	// ------------------------------------------------------------------
	Decision EvaluateThread(R3ShieldCore::Event& event, ULONG targetPid, ULONG selfPid,
		bool blockable, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Thread);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		const bool remote = (targetPid != 0) && (targetPid != selfPid);
		if (remote) {
			event.Flags |= R3ShieldCore::FlagEventRemoteThread;
		}
		else {
			event.Flags |= R3ShieldCore::FlagEventSelfThread;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskThread(targetPid, selfPid,
					static_cast<ULONG>(R3ShieldCore::ThreadOp::Create))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		// 本进程线程：默认连记录都不做（除非显式开了 hook_self_thread）。
		if (!remote) {
			if (!policy || (policy->Flags & R3ShieldCore::FlagHookSelfThread) == 0) {
				return { Action::Pass, false };
			}
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, false };
		}

		// ---- 完全拦截模式（ini: mode=block_all / block_all_safe）----
		//
		// ★ v66：**恢复为直接拒**（撤销 v21 的"先问再拦"）。
		//   远程线程 = 注入本身（样本 RunPE 靠 NtResumeThread /
		//   QueueApcThread 落地），是最该一刀切的一类，没有任何"问一下"的
		//   余地 —— 放行一次就等于放行整条注入链。
		//
		// ★ block_all_safe **不在这里开豁免**（维持原判据）：它只放行
		//   "可信来源的进程创建"，不放行远程线程。放行进程创建是为了让
		//   正常程序能起来；放行远程线程等于放行注入。二者不可混。
		//
		// ⚠️ 不看 `prompt_default`：全拦模式下 `prompt_default=allow`
		//    也依然是拒（否则"全拦"能被一行配置放水）。见 ModeAllowsAsk。
		// ⚠️ 本分支**不弹窗** ⇒ 也不会出现"白等 prompt_timeout 秒"。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return { Action::Block, false };
		}

		if (!blockable) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		// 远程线程 = 高危。ASK 模式弹窗；BLOCK 模式直接拒绝；LOG 只记录。
		if (!highRisk) {
			// 理论上 remote 一定 highRisk（规则就是判 remote），
			// 但万一高危开关被关掉，这里退化成只记录。
			event.Decision = (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log))
				? static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock)
				: static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, false };
		}

		if (!allowAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return { Action::Block, highRisk };
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return { Action::Record, highRisk };
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：通道不可用时降级。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return { Action::Record, highRisk };
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return { Action::Block, highRisk };
	}

	// ------------------------------------------------------------------
	// 核心判定（跨进程内存操作 / 代码注入链，v14）。
	//
	// 语义同上：**本进程一律 Pass**（存活前提），跨进程高危才拦。
	// 判据全在 R3ShieldCoreRules::IsHighRiskMemoryOp 里（本进程放行 + 权限位分档），
	// 这里只负责按 mode 决定 Record / Block / Ask。
	//
	// ⚠️ 与 EvaluateThread 一样，LOG/BLOCK 下高危不弹窗（allowAsk 只在 ASK
	//    模式为 true，否则白等 30s 超时）。
	// ------------------------------------------------------------------
	Decision EvaluateMemoryOp(R3ShieldCore::Event& event, ULONG targetPid, ULONG selfPid,
		ULONG processOp, ULONG protect, ULONG allocationType,
		bool blockable, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Process);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 本进程放行（存活前提）----
		//
		// 这是**在任何模式之前**的短路：即使 BlockAll 也不判本进程的内存操作，
		// 否则引擎自己（含被注入的每个进程）一 Protect 自己的页就被拦，系统瘫。
		const bool remote = (targetPid != 0) && (selfPid != 0) && (targetPid != selfPid);
		if (!remote) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Pass, false };
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskMemoryOp(targetPid, selfPid, processOp,
					protect, allocationType)) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		// ---- 完全拦截模式：命中即**直接拒**（★ v66 恢复，撤销 v21 的弹窗）----
		//
		//   跨进程写内存 / 改保护 = 注入的真身（RunPE 的 NtWriteVirtualMemory
		//   + NtProtectVirtualMemory）。它和远程线程一样，是最该一刀切的一类：
		//   放行一次就等于把注入链完整放行。所以这里**不问用户、不看
		//   `prompt_default`**，一律拒。
		//
		// ★ block_all_safe **不在这里开豁免**（维持原判据）：它只放行
		//   "可信来源的进程创建"。放行进程创建是为了让正常程序能起来；
		//   放行跨进程内存等于把 block_all_safe 退化成 log。
		//
		// ⚠️ 本分支**不弹窗** ⇒ 也不会出现"白等 prompt_timeout 秒"。
		//    守卫自身的注入由 hook 层的 `IsInjectingInto` 提前放行，
		//    不经过本分支（否则会把同步注入路自己掐死）。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return { Action::Block, false };
		}

		// ---- 跨进程但非高危（如改 RW、RESERVE）：只记录 ----
		if (!highRisk) {
			event.Decision = (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log))
				? static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock)
				: static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, false };
		}

		if (!blockable) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		if (!allowAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return { Action::Block, highRisk };
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return { Action::Record, highRisk };
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：通道不可用时降级。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return { Action::Record, highRisk };
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, highRisk };
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return { Action::Block, highRisk };
	}

	// ==================================================================
	// hook
	// ==================================================================

	//
	// 从 RTL_USER_PROCESS_PARAMETERS 里提前抠出镜像路径。
	//
	// 为什么要冒这个险：CreateProcess 走 NtCreateUserProcess 时，要执行的
	// exe 路径只在 ProcessParameters 指向的未文档化结构里。不读它就只能在
	// 进程**创建之后**反查 —— 那时进程已经在（虽然主线程还没 Resume），
	// 想"拦"就得靠杀掉它，属于补救而不是阻止。
	//
	// 结构布局随 Windows 版本变，所以我们**不硬编码单一偏移**，而是：
	//   1. 从结构头部按已知的几个候选偏移依次试探（不同版本 ImagePathName
	//      落在不同位置）；
	//   2. 每个候选都用 __try 包住（越界会抛异常，被 except 吞掉，不崩宿主）；
	//   3. 结果必须像一个"绝对路径"（有盘符或 \??\ 前缀）才接受 —— 否则
	//      偏移猜错了会读出一串垃圾，用这个特征过滤掉。
	//
	// 这层是"尽力而为"：读不到就返回 false，上层退回"创建后反查"的老路。
	//
	bool TryReadImagePathFromParameters(PVOID parameters, WCHAR* out, ULONG cch) noexcept
	{
		if (out == nullptr || cch == 0) {
			return false;
		}
		out[0] = L'\0';
		if (parameters == nullptr) {
			return false;
		}

		// RTL_USER_PROCESS_PARAMETERS 里 ImagePathName 的候选字节偏移。
		// 经验值来自 Win7 起各版本（x86/x64 同构，因为都是指针/整数对齐）：
		//   0x38 — Win7 / Win8
		//   0x40 — Win10 早期
		//   0x48 — Win10 后期 / Win11
		//   0x50 — 部分 Win11 版本
		// 注意：这些只是"先试哪个"，试不到就往后走，出错也不会崩。
		//
		// ⚠️ 光看"像绝对路径"不够 —— 结构里有好几个 UNICODE_STRING 都是
		//    绝对路径（CurrentDirectory、CommandLine…），试错会读到它们。
		//    这里加一道"必须是存在的 .exe 文件"的校验，能可靠区分开。
		const ULONG kCandidates[] = { 0x38, 0x40, 0x48, 0x50, 0x30, 0x60 };

		for (ULONG offset : kCandidates) {
			__try {
				const BYTE* base = static_cast<const BYTE*>(parameters);
				const PG_UNICODE_STRING* candidate =
					reinterpret_cast<const PG_UNICODE_STRING*>(base + offset);

				USHORT length = candidate->Length;
				PWSTR buffer = candidate->Buffer;

				// 合法性检查：长度非零、偶数、够小；缓冲区在用户地址空间。
				if (buffer == nullptr || length < 6 || length > 2048 ||
					(length % sizeof(WCHAR)) != 0) {
					continue;
				}
				if (reinterpret_cast<ULONG_PTR>(buffer) < 0x10000) {
					continue;
				}

				// 像不像"绝对路径"：盘符（X:\）或 \??\ 前缀。
				const bool looksDos = (buffer[1] == L':') &&
					(buffer[2] == L'\\' || buffer[2] == L'/');
				const bool looksNt = (length >= 8) &&
					wcsncmp(buffer, L"\\??\\", 4) == 0;

				if (!looksDos && !looksNt) {
					continue;
				}

				ULONG chars = length / sizeof(WCHAR);
				if (chars >= cch) {
					chars = cch - 1;
				}
				memcpy(out, buffer, chars * sizeof(WCHAR));
				out[chars] = L'\0';

				// 归一化（剥 \??\）后必须是"存在的 .exe 文件"。
				// 这一条能把 CurrentDirectory / CommandLine 之类的
				// 干扰项排除掉 —— 它们要么不是 .exe，要么文件不存在。
				NormalizeDosPrefix(out, cch);
				DevicePathToDosPath(out, cch);

				size_t outLen = wcslen(out);
				if (outLen < 5) {
					out[0] = L'\0';
					continue;
				}
				if (_wcsicmp(out + outLen - 4, L".exe") != 0) {
					out[0] = L'\0';
					continue;
				}
				const DWORD attrs = GetFileAttributesW(out);
				if (attrs == INVALID_FILE_ATTRIBUTES ||
					(attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
					out[0] = L'\0';
					continue;
				}

				return true;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// 这个偏移越界了，试下一个。
				out[0] = L'\0';
				continue;
			}
		}

		return false;
	}

	//
	// NtCreateUserProcess —— Win7+ 上 CreateProcess 的**正路**。
	//
	// 这是用户态起进程最常走的那个导出。它和 NtCreateProcessEx 是并列的
	// ntdll 导出（内核里 NtCreateUserProcess 内部会走到 NtCreateProcessEx
	// 的底层逻辑，但**不是**通过 ntdll 的这个导出调用的），所以两个都要挂。
	//
	// 两条路取镜像路径：
	//   A. 提前读：从 ProcessParameters（RTL_USER_PROCESS_PARAMETERS）里抠。
	//      见 TryReadImagePathFromParameters。读到了就能在**调用前**判定，
	//      高危直接拒绝 —— 真正的"拦"。
	//   B. 兜底反查：A 失败时先放行，用返回句柄 QueryFullProcessImageName。
	//      此时进程已建好（主线程未 Resume），能识别、能记录，但拦不住；
	//      高危走"询问后杀进程"（见下）。
	//
	// 另外我们**主动给创建加 CREATE_SUSPENDED**：这样无论 A/B，返回时新
	// 进程主线程都是挂起的，给了我们一个"它还没执行任何代码"的安全窗口，
	// 拒绝时 TerminateProcess 掉干净、无副作用。
	//
	NTSTATUS NTAPI NtCreateUserProcess_Hook(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
		ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
		PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes,
		ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters,
		PVOID CreateInfo, PVOID AttributeList)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		WCHAR earlyPath[R3ShieldCore::MaxImagePathChars] = {};
		bool haveEarlyPath = false;

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		const ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
		const bool allowAsk = ModeAllowsAsk(mode);

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::Create);
			event.CreatorProcessId = GetCurrentProcessId();

			// A. 提前读镜像路径（尽力而为，读不到不报错）。
			if (TryReadImagePathFromParameters(ProcessParameters, earlyPath,
					_countof(earlyPath))) {
				NormalizeFilePath(earlyPath, _countof(earlyPath));
				haveEarlyPath = true;
				wcsncpy_s(event.KeyPath, earlyPath, _TRUNCATE);
				event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

				// 用父进程 pid（就是当前进程）判高危 + 父子关系。
				Decision decision = EvaluateProcess(event, event.KeyPath, 0,
					GetCurrentProcessId(), true, allowAsk);
				if (decision.action == Action::Block) {
					// 调用前就拒了 —— 进程根本没被创建。
					event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event, R3ShieldCore::ObjectType::Process);
					InterlockedDecrement(&g_activeHooks);
					return STATUS_ACCESS_DENIED;
				}
				action = decision.action;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			haveEarlyPath = false;
			action = ExceptionAction(event);
		}

		// 主动加 CREATE_SUSPENDED：保证返回时新进程还没跑起来，
		// 留出"拒绝 → 干净终止"的窗口。调用方（CreateProcess）本来就会
		// 自己 Resume，所以对正常流程无影响（我们不做额外 Resume）。
		const ULONG forcedFlags = ProcessFlags | CREATE_SUSPENDED;

		status = pOriginalNtCreateUserProcess(ProcessHandle, ThreadHandle,
			ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes,
			ThreadObjectAttributes, forcedFlags, ThreadFlags, ProcessParameters,
			CreateInfo, AttributeList);

		// ★★★ v46：回报"本线程在这个 CreateProcess 窗口里刚建出来的子进程"。
		//
		//   为什么必须在**这里**、而不是在 DllInject 里：`CreateProcessInternalW`
		//   紧接着就要用 `NtWriteVirtualMemory` 往这个子进程写
		//   `RTL_USER_PROCESS_PARAMETERS`（环境块 / 命令行 / 当前目录）。那一次
		//   跨进程写会被我们自己的钩子判成 HIGH ⇒ Block 模式下直接拒 ⇒
		//   `CreateProcessInternalW` 回滚、返回 FALSE、err=5 ⇒ **根本走不到 DllInject**。
		//
		//   所以要在"子进程刚建出来"的第一时间就把 pid 记进线程级窗口标记
		//   （只有本线程确实在 `CreateProcessInternalW` 窗口内才会被记，见
		//   inject_activity.h 的 NoteCreatedChild），让紧随其后的那次写透传。
		if (status >= 0 && ProcessHandle && *ProcessHandle) {
			__try {
				R3ShieldCoreInjectActivity::NoteCreatedChild(PidFromHandle(*ProcessHandle));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
			}
		}

		// B. 没提前拿到路径 → 创建后反查 + （高危且 ASK）询问后杀进程。
		if (!haveEarlyPath && status >= 0 && ProcessHandle && *ProcessHandle) {
			__try {
				event.TargetProcessId = PidFromHandle(*ProcessHandle);
				event.Flags |= R3ShieldCore::FlagEventNewProcess;

				WCHAR imagePath[R3ShieldCore::MaxImagePathChars] = {};
				DWORD size = _countof(imagePath);
				if (QueryFullProcessImageName(*ProcessHandle, 0, imagePath, &size)) {
					NormalizeFilePath(imagePath, _countof(imagePath));
					wcsncpy_s(event.KeyPath, imagePath, _TRUNCATE);
					event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
				}

				Decision decision = EvaluateProcess(event, event.KeyPath,
					event.TargetProcessId, GetCurrentProcessId(), true, allowAsk);

				// 高危被拒 → 趁新进程还挂着，直接终结它。
				// 这是"创建后补救"，但因为在 CREATE_SUSPENDED 状态下，
				// 它一条指令都没执行过，杀掉等价于"从未启动"。
				if (decision.action == Action::Block) {
					pOriginalNtTerminateProcess(*ProcessHandle, STATUS_ACCESS_DENIED);
					event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event, R3ShieldCore::ObjectType::Process);
					InterlockedDecrement(&g_activeHooks);
					return STATUS_ACCESS_DENIED;
				}

				action = decision.action;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				action = ExceptionAction(event);
			}
		}
		else if (haveEarlyPath && status >= 0 && ProcessHandle && *ProcessHandle) {
			// 提前判过的那条路：补上 pid，再按判定结果上报。
			__try {
				event.TargetProcessId = PidFromHandle(*ProcessHandle);
				event.Flags |= R3ShieldCore::FlagEventNewProcess;
				event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
			}
		}

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event, R3ShieldCore::ObjectType::Process);
		}

		if (!haveEarlyPath || action != Action::Record) {
			// 什么都没有（没路径、没记录）时也要把创建事件留下痕迹。
			if (action == Action::Pass) {
				event.TargetProcessId = (status >= 0 && ProcessHandle && *ProcessHandle)
					? PidFromHandle(*ProcessHandle) : 0;
				event.Status = static_cast<ULONG>(status);
				Publish(event, R3ShieldCore::ObjectType::Process);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtCreateProcessEx —— 底层进程创建。
	//
	// 注意：现代 Windows 上用户态走的是 NtCreateUserProcess（内核里
	// 再调 NtCreateProcessEx）。我们只能挂到 ntdll 导出的这一层，
	// 所以 NtCreateUserProcess 也会经过这里的一部分路径 —— 但两者
	// 是**并列**的导出，不是调用关系。要覆盖全，两个都得挂。
	//
	// 这里只挂 NtCreateProcessEx：它是所有进程创建的必经底层（内核态
	// 调用），也是 CreateProcess 内部最终到的那一层。NtCreateUserProcess
	// 在 ntdll 里是独立实现，见下面单独的处理。
	//
	NTSTATUS NTAPI NtCreateProcessEx_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
		const PG_OBJECT_ATTRIBUTES* /*ObjectAttributes*/, HANDLE ParentProcess,
		ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort,
		ULONG /*JobMemberLevel*/)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::Create);
			event.CreatorProcessId = GetCurrentProcessId();

			// 父进程 pid（NtCreateProcessEx 只给句柄，反查一下）。
			event.TargetProcessId = PidFromHandle(ParentProcess);

			// 镜像路径拿不到（NtCreateProcessEx 不接路径，只接 section），
			// 留空 —— 事件仍会被记录，只是没有路径可判高危。
			event.KeyPath[0] = L'\0';

			R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
			const bool allowAsk = ModeAllowsAsk(
				policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log));

			Decision decision = EvaluateProcess(event, event.KeyPath, 0,
				event.TargetProcessId, true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Process);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtCreateProcessEx(ProcessHandle, DesiredAccess,
				nullptr, ParentProcess, Flags, SectionHandle, DebugPort,
				ExceptionPort, 0);

			// ★ v46：与 NtCreateUserProcess_Hook 同理 —— 子进程刚建出来就回报 pid，
			//   让随后的进程参数写入（NtWriteVirtualMemory）透传。见 inject_activity.h。
			if (status >= 0 && ProcessHandle && *ProcessHandle) {
				__try {
					R3ShieldCoreInjectActivity::NoteCreatedChild(PidFromHandle(*ProcessHandle));
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
				}
			}

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				if (status >= 0 && ProcessHandle) {
					event.TargetProcessId = PidFromHandle(*ProcessHandle);
					event.Flags |= R3ShieldCore::FlagEventNewProcess;
				}
				Publish(event, R3ShieldCore::ObjectType::Process);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtCreateProcess —— 老 API（v18）。
	//
	// ⚠️⚠️ 这个 hook 的判据**与 NtCreateProcessEx 完全不同**，别照抄。
	//
	//   区别的根子：NtCreateProcess **不接受 RTL_USER_PROCESS_PARAMETERS**。
	//   它只有 8 个参数，没有 Flags、没有参数块 —— 也就意味着
	//     · 没有命令行（CommandLine）
	//     · 没有当前目录（CurrentDirectory）
	//     · 没有环境块（Environment）
	//     · **没有镜像路径**（ImagePathName 在参数块里！）
	//
	//   所以 NtCreateUserProcess 那套"从 ProcessParameters 抠 ImagePath"在这里
	//   **一个字都用不上**：进程参数根本不存在，连试都不用试。
	//   而 NtCreateProcessEx 至少还能靠 SectionHandle 反推，这个连 section
	//   都可能没有。
	//
	//   那判什么？判**特征**（判据在 R3ShieldCoreRules::ProcessRiskReason 的
	//   CreateLegacy 分支里，那里有完整理由）：
	//     ① 这个 API 在正常系统上几乎不出现（Windows 自身走 NtCreateUserProcess）
	//     ② 出现即意味着调用方自己先建了 image section 再裸起进程 ——
	//        进程镂空 / 反射加载的经典手法
	//   因此这里不传 imagePath（传了也是空），交给规则层按特征判。
	//
	// ⚠️ 另一个坑：**不能想当然加 CREATE_SUSPENDED**。
	//   NtCreateProcess 没有 Flags 参数，压根没地方塞 —— 这跟 Ex 变体不一样。
	//   所以这里**没有**"创建后可干净终止"的窗口：一旦调用成功，进程对象
	//   就存在了（但主线程还没建，真正执行要靠后续 NtCreateThread）。
	//   好在判据是"调用前判定"（CreateLegacy 恒高危），Block 时直接不调原函数。
	//
	NTSTATUS NTAPI NtCreateProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
		const PG_OBJECT_ATTRIBUTES* /*ObjectAttributes*/, HANDLE ParentProcess,
		BOOLEAN /*InheritObjectTable*/, HANDLE SectionHandle, HANDLE DebugPort,
		HANDLE ExceptionPort)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::CreateLegacy);
			event.CreatorProcessId = GetCurrentProcessId();

			// 父进程（调用方给的句柄反查）—— 用于展示"谁起的"。
			event.TargetProcessId = PidFromHandle(ParentProcess);

			// 镜像路径：**拿不到**（没有参数块）。留空，
			// 规则层按 CreateLegacy 特征判（无路径也判高危）。
			event.KeyPath[0] = L'\0';

			// 把几个"更可疑"的辅助信号塞进 DesiredAccess 复用字段？
			// 不 —— 复用字段会污染日志语义。改用一个明确的语义位：
			// 传了 DebugPort / ExceptionPort 说明调用方在接管调试/异常，
			// 正常创建不会这么做。这里只在**没有**这些端口时降低可信度，
			// 但仍按特征判（因为 API 本身罕见）。当前实现保持"调用即高危"，
			// 把细节留给后续版本。

			const ULONG mode = []() -> ULONG {
				R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				return policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			}();
			const bool allowAsk = ModeAllowsAsk(mode);

			Decision decision = EvaluateProcess(event, nullptr, 0,
				event.TargetProcessId, true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Process);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		status = pOriginalNtCreateProcess(ProcessHandle, DesiredAccess, nullptr,
			ParentProcess, 0, SectionHandle, DebugPort, ExceptionPort);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			if (status >= 0 && ProcessHandle && *ProcessHandle) {
				event.TargetProcessId = PidFromHandle(*ProcessHandle);
				event.Flags |= R3ShieldCore::FlagEventNewProcess;
			}
			Publish(event, R3ShieldCore::ObjectType::Process);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtCreateThread —— 老 API（v18）。
	//
	// 与 NtCreateThreadEx 的判据**同一条**（目标进程 ≠ 当前进程 = 远程线程），
	// 因为两者都显式收 ProcessHandle。差别只在参数表：
	//   · NtCreateThread 多一个 ClientId（可指定线程 id）；
	//   · 没有 CreateFlags / StackSize 等（用 ThreadContext + InitialTeb 表达）。
	//
	// ⚠️ 因此**不能**和 NtCreateThreadEx 共用一个 detour（一个地址一个 detour，
	//    参数表不同，共用 = 参数错位 → 崩）。这是 §10-35 的老坑的又一例。
	//
	NTSTATUS NTAPI NtCreateThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
		const PG_OBJECT_ATTRIBUTES* ObjectAttributes, HANDLE ProcessHandle,
		PG_CLIENT_ID* /*ClientId*/, PVOID ThreadContext, PVOID InitialTeb,
		BOOLEAN /*CreateSuspended*/)
	{
		// ★ v46：与 NtCreateThreadEx_Hook 同款短路 —— 引擎自己在注入时，
		//   远程建线程是注入机制的一环（老 API 路径）。见 inject_activity.h。
		if (R3ShieldCoreInjectActivity::IsInjectingInto(PidFromHandle(ProcessHandle))) {
			return pOriginalNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes,
				ProcessHandle, nullptr, ThreadContext, InitialTeb, 0);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ThreadOp::CreateLegacy);

			const ULONG selfPid = GetCurrentProcessId();
			event.TargetProcessId = PidFromHandle(ProcessHandle);
			event.CreatorProcessId = selfPid;

			// 远程线程时把目标镜像路径带上（展示"注入到哪个进程"）。
			if (event.TargetProcessId != selfPid && ProcessHandle) {
				WCHAR imagePath[R3ShieldCore::MaxImagePathChars] = {};
				DWORD size = _countof(imagePath);
				if (QueryFullProcessImageName(ProcessHandle, 0, imagePath, &size)) {
					wcsncpy_s(event.KeyPath, imagePath, _TRUNCATE);
					event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
				}
			}

			const ULONG mode = []() -> ULONG {
				R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				return policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			}();
			const bool allowAsk = ModeAllowsAsk(mode);

			// ⚠️ 显式传 CreateLegacy（不是硬编码 Create）—— 保证规则层
			//    走到 CreateLegacy 分支（§10-33：新 Op 掉 default = 静默非高危）。
			Decision decision = EvaluateThread(event, event.TargetProcessId, selfPid,
				true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Thread);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		status = pOriginalNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes,
			ProcessHandle, nullptr, ThreadContext, InitialTeb, 0);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event, R3ShieldCore::ObjectType::Thread);
		}
		else if (action == Action::Pass) {
			// 本进程线程（默认不记）—— 不产生日志，直接返回。
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ------------------------------------------------------------------
	// 核心判定（终止进程，v36）。
	//
	// 语义：放行自己 / 自己的后代 / 同镜像；其余按 mode 处置。
	//   LOG       → 只记录（标 WouldBlock），绝不拦
	//   BLOCK     → 直接拒（STATUS_ACCESS_DENIED）
	//   ASK/全拦  → 弹窗询问
	//
	// allowAsk 的意义同 EvaluateThread：LOG/BLOCK 下**不能**弹窗，
	//   否则会白等满 prompt_timeout（默认 30s）再返回 fallback ——
	//   表现成"LOG 模式本该全放行，却把操作拒了还卡半分钟"。
	// ------------------------------------------------------------------
	Decision EvaluateTerminate(R3ShieldCore::Event& event, ULONG targetPid, ULONG selfPid,
		bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Process);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		const ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		const bool highRisk = R3ShieldCoreRules::IsHighRiskTerminate(targetPid, selfPid);

		if (!highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, false };
		}

		event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
		event.Flags |= R3ShieldCore::FlagEventHighRisk;

		if (!allowAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return { Action::Block, true };
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return { Action::Record, true };
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		if (event.TimeStamp == 0) {
			event.TimeStamp = NowFileTime();
		}

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ 与 v26/v28/v29 同构：通道打不开 = 问不出去 → **降级放行**。
		//   这里比注册表那边更要命：静默拒会掐断正常的进程管理行为，
		//   而"问不出去"本身不是用户的决定。
		if (!R3ShieldCorePrompt::IsOpen()) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return { Action::Record, true };
		}

		const R3ShieldCore::Verdict verdict = R3ShieldCorePrompt::Ask(event, PromptFallbackVerdict());

		// 通道在"调用中失效"（引擎退出）→ 同样降级放行。
		if (!R3ShieldCorePrompt::IsOpen()) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return { Action::Record, true };
		}

		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return { Action::Record, true };
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return { Action::Block, true };
	}

	//
	// NtTerminateProcess —— v36 起：**按判据放行/拦截**（v36 之前只记录）。
	//
	// 为什么现在能拦：detour 跑在**原函数之前** —— 不调原函数、直接返回
	//   STATUS_ACCESS_DENIED 就是拦截。实测 tools/terminate_block_probe.cpp：
	//   调用方拿到 FALSE + GetLastError()==5，目标进程**确实存活**。
	//
	// ⚠️ "能拦" ≠ "拦得住"：本 hook 只在**被注入的进程**里存在，且只挡走
	//    ntdll 导出的调用 —— 直 syscall / 驱动 / NtTerminateJobObject 都绕得过去。
	//    真正的自我保护仍靠 NtOpenProcess 剥句柄权限（内核在句柄对象上强制）。
	//
	// ⚠️ 判据（放行自己/后代/同镜像）不能省 —— 见 r3shieldcore_rules.cpp
	//    TerminateRiskReason 的说明：无差别拦会把 ExitProcess 的干净退出
	//    破坏成 0xC0000005 异常退出（实测可复现）。
	//
	NTSTATUS NTAPI NtTerminateProcess_Hook(HANDLE ProcessHandle, NTSTATUS ExitStatus)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::Terminate);

			const ULONG selfPid = GetCurrentProcessId();
			const ULONG targetPid = PidFromHandle(ProcessHandle);
			event.TargetProcessId = targetPid;
			event.CreatorProcessId = selfPid;

			R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
			const bool containEnabled = !policy ||
				(policy->Flags2 & R3ShieldCore::FlagHookTerminateContain) != 0;

			// 取不到 pid（含 NtCurrentProcess() 伪句柄 = 结束自己）→ 直接放行。
			// 这一条是**存活前提**：判错会把进程的正常退出弄坏。
			// 判据（自己/后代/同镜像）全在规则层 —— 那边能单独跑探针验证，
			// 这里只负责按 mode 决定 Record / Block / Ask。
			//
			// ⚠️ v37：`targetPid == 0` 的**正常来源**只剩"句柄没带查询权限"这一类
			//   （本进程内 `OpenProcess` 已被 NtOpenProcess_Hook 补过权限；剩下的
			//    是 DuplicateHandle 复制来的 / 继承来的 / 注入前已打开的句柄）。
			//   按项目策略**降级放行 + 打标记**（绝不为"机制不可用"静默拒 ——
			//   铁律 12/13），日志里打 `[PID-UNKNOWN]` 便于审计这条旁路。
			if (targetPid == 0 || targetPid == selfPid || !containEnabled) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				if (targetPid == 0 && containEnabled && ProcessHandle != nullptr) {
					event.Flags2 |= R3ShieldCore::FlagEvent2TerminatePidUnknown;
				}
				action = Action::Record;
			}
			else {
				const ULONG mode = policy ? policy->Mode
					: static_cast<ULONG>(R3ShieldCore::Mode::Log);
				const Decision decision = EvaluateTerminate(event, targetPid, selfPid,
					ModeAllowsAsk(mode));
				action = decision.action;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Process);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtTerminateProcess(ProcessHandle, ExitStatus);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event, R3ShieldCore::ObjectType::Process);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtCreateThreadEx —— 线程创建。这是线程监控的重点。
	//
	// 判定：ProcessHandle 指向的进程 != 当前进程 → 远程线程（注入）。
	// 远程线程是绝大多数注入技术的共同特征，也是我们这个项目自己在做的事
	// （用 APC + shellcode 注入），所以打开这个监控能"看到自己被谁注入"。
	//
	NTSTATUS NTAPI NtCreateThreadEx_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
		const PG_OBJECT_ATTRIBUTES* ObjectAttributes, HANDLE ProcessHandle,
		PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
		SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
	{
		// ★ v46：引擎自己正在注入这个目标 ⇒ 这次"远程建线程"是注入机制的一环
		//   （DllInject 建远程线程去 LoadLibrary），不是攻击行为 → 直接透传。
		//   只放行"正在注入的那个目标 pid"，别的目标照判。见 inject_activity.h。
		if (R3ShieldCoreInjectActivity::IsInjectingInto(PidFromHandle(ProcessHandle))) {
			return pOriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
				ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits,
				StackSize, MaximumStackSize, AttributeList);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ThreadOp::Create);

			const ULONG selfPid = GetCurrentProcessId();
			event.TargetProcessId = PidFromHandle(ProcessHandle);
			event.CreatorProcessId = selfPid;

			// 目标镜像路径（远程线程时用来展示"注入到哪个进程"）。
			if (event.TargetProcessId != selfPid && ProcessHandle) {
				WCHAR imagePath[R3ShieldCore::MaxImagePathChars] = {};
				DWORD size = _countof(imagePath);
				if (QueryFullProcessImageName(ProcessHandle, 0, imagePath, &size)) {
					wcsncpy_s(event.KeyPath, imagePath, _TRUNCATE);
					event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
				}
			}

			// 只有 ASK 模式才允许弹窗（UI 线程只在 ASK 模式起来）。
			const ULONG mode = []() -> ULONG {
				R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				return policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			}();
			const bool allowAsk = ModeAllowsAsk(mode);

			Decision decision = EvaluateThread(event, event.TargetProcessId, selfPid, true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Thread);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
				ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits,
				StackSize, MaximumStackSize, AttributeList);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event, R3ShieldCore::ObjectType::Thread);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtTerminateThread_Hook(HANDLE ThreadHandle, NTSTATUS ExitStatus)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ThreadOp::Terminate);
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			status = pOriginalNtTerminateThread(ThreadHandle, ExitStatus);
			event.Status = static_cast<ULONG>(status);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = pOriginalNtTerminateThread(ThreadHandle, ExitStatus);
		}

		Publish(event, R3ShieldCore::ObjectType::Thread);
		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// 代码注入链前三步（v14）
	// ==================================================================
	//
	// ⚠️ 三个 hook 共用一套骨架，差别只在参数与"取哪个值判高危"。
	//
	// 关键点（选一个说透，其余同理）：
	//
	//   1. **第一参数是进程句柄，不是 pid**。要用 PidFromHandle 反查目标 pid，
	//      才能判"是不是跨进程"。反查走的是干净的 NtQueryInformationProcess。
	//
	//   2. **提前放行本进程**。这是存活前提：JIT/堆/GC 每秒都在自己进程里
	//      调这三个 API。快速路径必须"取 pid → 等于自己 → 立刻透传"，
	//      连 event 都不组装（避免高频路径上填 KeyPath 的开销）。
	//      注意：句柄取不到 pid（如 KernelHandle=NtCurrentProcess() 伪句柄）
	//      时按"本进程"处理 → 放行 —— 宁可漏也不瘫。
	//
	//   3. **必须在原函数之前判定**（这三个都是"预检"型：拦了就没有副作用）。
	//      与 NtCreateThreadEx 一致：Block 时直接返 STATUS_ACCESS_DENIED，
	//      不调原函数。
	//
	//   4. 阻止策略 = 返回 ACCESS_DENIED + Publish 一条 Blocked 事件。
	//      因为拦在调用之前，没有"事后补救"的问题。
	//

	//
	// NtAllocateVirtualMemory —— 在目标进程里申请内存。
	//
	// 判高危的条件（见规则层）：跨进程 + MEM_COMMIT + 含 PAGE_EXECUTE_*。
	//
	NTSTATUS NTAPI NtAllocateVirtualMemory_Hook(HANDLE ProcessHandle, PVOID* BaseAddress,
		ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
	{
		// ---- 快速路径：本进程 / 取不到目标 → 原样透传 ----
		//
		// ★ v46 第三条件：**引擎自己正在注入这个进程** → 也透传。
		//   同步注入路跑在父进程里（见 inject_activity.h），父进程若被全量注入，
		//   注入器自己的 VirtualAllocEx 会被本钩子判成"跨进程改内存"而拦掉。
		//   ⚠️ 只放行"正在注入的那个目标 pid"，别的目标照判。
		const ULONG selfPid = GetCurrentProcessId();
		const ULONG targetPid = PidFromHandle(ProcessHandle);
		if (targetPid == 0 || targetPid == selfPid ||
			R3ShieldCoreInjectActivity::IsInjectingInto(targetPid)) {
			return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
				RegionSize, AllocationType, Protect);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		const ULONG requestedProtect = Protect;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::AllocateMemory);
			event.TargetProcessId = targetPid;
			event.CreatorProcessId = selfPid;
			event.DesiredAccess = requestedProtect; // 复用字段承载保护值，便于日志展示

			const ULONG mode = []() -> ULONG {
				R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				return policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			}();
			const bool allowAsk = ModeAllowsAsk(mode);

			Decision decision = EvaluateMemoryOp(event, targetPid, selfPid,
				static_cast<ULONG>(R3ShieldCore::ProcessOp::AllocateMemory),
				requestedProtect, AllocationType, true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Process);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		const NTSTATUS status = pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress,
			ZeroBits, RegionSize, AllocationType, Protect);
		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event, R3ShieldCore::ObjectType::Process);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtProtectVirtualMemory —— 改目标进程内存页权限。
	//
	// 判高危的条件：跨进程 + 新保护值含 PAGE_EXECUTE_*。
	// 注意 OldProtect 是**出参**，要传给原函数之后才有意义，不能提前读。
	//
	NTSTATUS NTAPI NtProtectVirtualMemory_Hook(HANDLE ProcessHandle, PVOID* BaseAddress,
		PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
	{
		const ULONG selfPid = GetCurrentProcessId();
		const ULONG targetPid = PidFromHandle(ProcessHandle);
		if (targetPid == 0 || targetPid == selfPid ||
			R3ShieldCoreInjectActivity::IsInjectingInto(targetPid)) {
			return pOriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress,
				RegionSize, NewProtect, OldProtect);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::ProtectMemory);
			event.TargetProcessId = targetPid;
			event.CreatorProcessId = selfPid;
			event.DesiredAccess = NewProtect;

			const ULONG mode = []() -> ULONG {
				R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				return policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			}();
			const bool allowAsk = ModeAllowsAsk(mode);

			Decision decision = EvaluateMemoryOp(event, targetPid, selfPid,
				static_cast<ULONG>(R3ShieldCore::ProcessOp::ProtectMemory),
				NewProtect, 0, true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Process);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		const NTSTATUS status = pOriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress,
			RegionSize, NewProtect, OldProtect);
		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event, R3ShieldCore::ObjectType::Process);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtWriteVirtualMemory —— 往目标进程写内存。
	//
	// ★ 这是注入链里**最直接的铁证**：跨进程写内存本身就该被看见。
	// 判高危的条件：跨进程即高危（不看内容 —— 内容看不到，也不需要看）。
	// 调试器读内存是 ReadProcessMemory，不走这里。
	//
	NTSTATUS NTAPI NtWriteVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress,
		PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
	{
		const ULONG selfPid = GetCurrentProcessId();
		const ULONG targetPid = PidFromHandle(ProcessHandle);
		// ★★★ v46：第三条件「引擎自己正在注入这个进程」是**本铁律的核心**。
		//
		//   它覆盖两种情形（见 inject_activity.h）：
		//     A. `DllInject` 已经在跑（`g_injectTargetPid`）—— 分配/写/改保护/建线程。
		//     B. 还在 `CreateProcessInternalW` **内部**：原函数自己正往刚建出来的
		//        子进程写进程参数（`g_createWindowDepth>0` + `g_createdChildPid`）。
		//        这一次若被拦，`CreateProcessInternalW` 会回滚并返回 FALSE(err=5)，
		//        整条同步注入路**在到达 DllInject 之前**就死掉（真机 + 本地复现双证）。
		//
		//   ⚠️ 仍然只放行"正在注入的那个目标 pid"，别的目标照判。
		if (targetPid == 0 || targetPid == selfPid ||
			R3ShieldCoreInjectActivity::IsInjectingInto(targetPid)) {
			return pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
				NumberOfBytesToWrite, NumberOfBytesWritten);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::WriteMemory);
			event.TargetProcessId = targetPid;
			event.CreatorProcessId = selfPid;
			event.DesiredAccess = static_cast<ULONG>(NumberOfBytesToWrite); // 写入字节数，供日志展示

			const ULONG mode = []() -> ULONG {
				R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				return policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);
			}();
			const bool allowAsk = ModeAllowsAsk(mode);

			Decision decision = EvaluateMemoryOp(event, targetPid, selfPid,
				static_cast<ULONG>(R3ShieldCore::ProcessOp::WriteMemory), 0, 0, true, allowAsk);
			action = decision.action;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event, R3ShieldCore::ObjectType::Process);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		const NTSTATUS status = pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress,
			Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event, R3ShieldCore::ObjectType::Process);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// NtOpenProcess —— 自我保护（剥句柄权限）
	// ==================================================================
	//
	// 为什么挂在 OpenProcess 上，而不是拦 NtTerminateProcess：
	//
	//   拦 API 只挡得住"那一次调用" —— 攻击者改用直 syscall（不经 ntdll 导出）
	//   就绕过去了。剥句柄权限不一样：限制落在**内核里的句柄对象**上。
	//   攻击者后面不管怎么调 NtTerminateProcess / NtWriteVirtualMemory /
	//   NtCreateThreadEx（哪怕全程直 syscall），内核都会因为句柄权限不足
	//   直接返回 STATUS_ACCESS_DENIED。这就是业界防杀软都挂 OpenProcess 的原因。
	//
	// 覆盖范围：本 hook 挂在**所有**进程里（含 bypass 的 System32 / WindowsApps /
	// exclude 路径）—— 见 Install() 里的说明。快速路径是一次空指针判断 + 两次
	// 整数比较，命中受保护目标才做剥离和记录。
	//
	constexpr ACCESS_MASK kDangerousProcessAccess =
		PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION |
		PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME |
		WRITE_DAC | WRITE_OWNER;

	// 重入保护：判定受保护目标时要 OpenProcess 反查镜像路径，那次调用会再进
	// 本 hook —— 用线程局部标志直接放行，避免无限递归。
	__declspec(thread) bool g_inOpenProcessHook = false;

	// 目标 pid 是不是受保护对象（引擎自身 + protect_process= 列表）。
	bool IsProtectedTarget(ULONG targetPid, ULONG enginePid) noexcept
	{
		if (targetPid == 0) {
			return false;
		}

		// 1) 引擎自身 —— 一次整数比较，最便宜。
		if (enginePid != 0 && targetPid == enginePid) {
			return true;
		}

		// 2) protect_process= 列表 —— 要反查目标镜像路径，贵。
		//    列表为空时（默认）直接跳过。
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy || policy->ProtectProcessCount == 0) {
			return false;
		}

		HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
		if (!target) {
			return false;
		}

		WCHAR imagePath[R3ShieldCore::MaxImagePathChars] = {};
		DWORD size = static_cast<DWORD>(_countof(imagePath));
		const BOOL ok = QueryFullProcessImageName(target, 0, imagePath, &size);
		CloseHandle(target);

		if (!ok || imagePath[0] == L'\0') {
			return false;
		}

		return R3ShieldCoreRules::MatchesUserProtectProcess(imagePath);
	}

	// 命中受保护目标吗？命中则输出"剥掉危险位之后"的 DesiredAccess。
	bool ComputeProtectedAccess(ULONG targetPid, ULONG enginePid,
		ACCESS_MASK desiredAccess, ACCESS_MASK* strippedAccess) noexcept
	{
		g_inOpenProcessHook = true;
		bool protectedTarget = false;
		__try {
			protectedTarget = IsProtectedTarget(targetPid, enginePid);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			protectedTarget = false;
		}
		g_inOpenProcessHook = false;

		if (!protectedTarget) {
			return false;
		}

		const ACCESS_MASK stripped = desiredAccess & ~kDangerousProcessAccess;
		if (stripped == desiredAccess) {
			// 调用方本来就没要危险权限（例如只查信息）—— 不算一次拦截。
			return false;
		}

		*strippedAccess = stripped;
		return true;
	}

	// 事件里的目标镜像路径。要在重入保护下做（内部会 OpenProcess）。
	void FillProtectedImagePath(R3ShieldCore::Event& event, ULONG targetPid) noexcept
	{
		g_inOpenProcessHook = true;
		__try {
			HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
			if (target) {
				DWORD size = static_cast<DWORD>(_countof(event.KeyPath));
				if (QueryFullProcessImageName(target, 0, event.KeyPath, &size) &&
					event.KeyPath[0] != L'\0') {
					event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
				}
				CloseHandle(target);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
		g_inOpenProcessHook = false;
	}

	NTSTATUS NTAPI NtOpenProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
		const PG_OBJECT_ATTRIBUTES* ObjectAttributes, const PG_CLIENT_ID* ClientId)
	{
		// ---- 快速路径：绝大多数调用在这里就返回 ----
		// 没有 ClientId（打开自己）、打开自己、或正在重入 → 原样透传。
		if (!ClientId || !ClientId->UniqueProcess || g_inOpenProcessHook) {
			return pOriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}

		const ULONG targetPid = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(ClientId->UniqueProcess));
		const ULONG selfPid = GetCurrentProcessId();
		if (targetPid == selfPid) {
			return pOriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		const ULONG enginePid = policy ? policy->EngineProcessId : 0;

		// ---- (1) 自我保护：剥掉受保护目标的危险权限 ----
		// ⚠️ 只在 self_protect 开时做。本 hook 现在也会因为"终止收敛"而挂上
		//    （见 Install），那种场景下不该顺带改变句柄权限语义。
		if (policy && (policy->Flags & R3ShieldCore::FlagSelfProtect) != 0) {
			ACCESS_MASK strippedAccess = 0;
			if (ComputeProtectedAccess(targetPid, enginePid, DesiredAccess, &strippedAccess)) {
				// ---- 命中：用剥过的权限调原函数，句柄拿得到但没牙 ----
				InterlockedIncrement(&g_activeHooks);
				const NTSTATUS status = pOriginalNtOpenProcess(ProcessHandle, strippedAccess,
					ObjectAttributes, ClientId);

				R3ShieldCore::Event event = {};
				event.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::Open);
				event.TargetProcessId = targetPid;
				event.CreatorProcessId = selfPid;
				event.DesiredAccess = static_cast<ULONG>(DesiredAccess);
				event.Status = static_cast<ULONG>(status);
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk | R3ShieldCore::FlagEventBlocked;
				FillProtectedImagePath(event, targetPid);
				Publish(event, R3ShieldCore::ObjectType::Process);

				InterlockedDecrement(&g_activeHooks);
				return status;
			}
		}

		// ---- (2) v37：终止收敛辅助 —— 让后续 NtTerminateProcess 能反查 pid ----
		//
		// ★ 为什么必须补权限（e2e 实测，2026-10-03）：
		//   `NtTerminateProcess` 只拿到"进程句柄"，要靠
		//   `NtQueryInformationProcess(ProcessBasicInformation)` 反查目标 pid，
		//   而该查询要求句柄带 `PROCESS_QUERY_LIMITED_INFORMATION`。
		//   最常见的杀进程写法 `OpenProcess(PROCESS_TERMINATE)` **恰恰没有它**
		//   ⇒ 反查得 0 ⇒ 收敛规则被整个绕过（实测：T3 杀无关进程 / T4 杀 shell
		//   都拦不住，TerminateProcess 返回 TRUE、目标真的死了）。
		//
		// ★ 安全性：只在调用方**已经**要了 PROCESS_TERMINATE（危险得多）时才补一个
		//   **只读**权限位，不泄露任何新能力。若因补权限反而打不开，则**退回原
		//   权限**重试 —— 绝不因本改动让原本能打开的句柄打不开。
		const bool containEnabled = policy &&
			(policy->Flags2 & R3ShieldCore::FlagHookTerminateContain) != 0;
		if (containEnabled && (DesiredAccess & PROCESS_TERMINATE) != 0 &&
			(DesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION) == 0) {
			const ACCESS_MASK augmented = DesiredAccess | PROCESS_QUERY_LIMITED_INFORMATION;
			NTSTATUS status = pOriginalNtOpenProcess(ProcessHandle, augmented,
				ObjectAttributes, ClientId);
			if (status < 0) {
				status = pOriginalNtOpenProcess(ProcessHandle, DesiredAccess,
					ObjectAttributes, ClientId);
			}
			return status;
		}

		return pOriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}

	// ==================================================================
	// 挂载
	// ==================================================================
	bool QueueHook(LPCSTR functionName, LPVOID detour, LPVOID* original, bool required) noexcept
	{
		HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
		if (!ntdll) {
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(ntdll, functionName));
		if (!target) {
			if (required) {
				LOG(L"ProcessGuard: ntdll 缺少导出 %S", functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"ProcessGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"ProcessGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace ProcessGuard
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
				LOG(L"ProcessGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();

		//
		// ---- 自我保护 hook：挂到**所有**进程，不看 bypass ----
		//
		// 这是唯一一处刻意绕过 bypass 的地方，理由：
		//   bypass 里的 %SystemRoot% / WindowsApps / exclude 路径都是"我们不去监控"
		//   的进程。但**保护引擎自己**恰恰需要在这些进程里也在场 —— 否则
		//   任务管理器（System32）、或者往 C:\Windows\Temp 里落地的东西
		//   照样能一句 TerminateProcess 把引擎干掉。
		//
		// 代价可控：它只对"受保护目标"做处理，其余是一次空指针判断 +
		//   两次整数比较就透传；不产生任何日志。
		//
		// v37：**终止收敛**同样需要 NtOpenProcess 在场 —— 它给带
		//   PROCESS_TERMINATE 的句柄补 PROCESS_QUERY_LIMITED_INFORMATION，
		//   否则 NtTerminateProcess 反查不到目标 pid、收敛规则被绕过。
		//   所以本 hook 的挂载条件是 `self_protect || hook_terminate_contain`。
		//
		const bool selfProtectEnabled =
			policy && (policy->Flags & R3ShieldCore::FlagSelfProtect) != 0;
		const bool containEnabled =
			policy && (policy->Flags2 & R3ShieldCore::FlagHookTerminateContain) != 0;

		if (selfProtectEnabled || containEnabled) {
			HMODULE ntdllForProtect = GetModuleHandle(L"ntdll.dll");
			if (ntdllForProtect) {
				pOriginalNtOpenProcess = reinterpret_cast<NtOpenProcessPtr>(
					GetProcAddress(ntdllForProtect, "NtOpenProcess"));
			}

			QueueHook("NtOpenProcess", reinterpret_cast<LPVOID>(NtOpenProcess_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtOpenProcess), true);
		}

		//
		// 跳过判定复用 RegistryGuard 的结果（同 FileGuard）。
		// 顺序约束：必须先 Install RegistryGuard 再到这里。
		//
		if (RegistryGuard::IsBypassed()) {
			g_bypass = true;
			g_installed = true;
			return true;
		}

		const bool hookProcess = policy && (policy->Flags & R3ShieldCore::FlagHookProcess) != 0;
		const bool hookThread = policy && (policy->Flags & R3ShieldCore::FlagHookThread) != 0;
		const bool hookMemoryOp = policy && (policy->Flags2 & R3ShieldCore::FlagHookMemoryOp) != 0;

		if (!hookProcess && !hookThread && !hookMemoryOp) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ProcessGuard: hook_process / hook_thread / hook_memory_op 都未开启，本进程不挂进程/线程 hook");
			return true;
		}

		g_bypass = false;

		HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
		if (ntdll) {
			pOriginalNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessPtr>(
				GetProcAddress(ntdll, "NtQueryInformationProcess"));
		}

		if (hookProcess) {
			// NtCreateUserProcess 是 Win7+ 上 CreateProcess 的正路。
			QueueHook("NtCreateUserProcess", reinterpret_cast<LPVOID>(NtCreateUserProcess_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtCreateUserProcess), false);

			// NtCreateProcessEx 是所有进程创建的底层必经之路。
			QueueHook("NtCreateProcessEx", reinterpret_cast<LPVOID>(NtCreateProcessEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtCreateProcessEx), true);

			// v18：NtCreateProcess —— 老 API，无参数块、拿不到路径。
			// 判据靠特征（见 NtCreateProcess_Hook 的说明）。
			// required=false：极少数情况这个导出可能不存在，缺了不该拖垮整层。
			QueueHook("NtCreateProcess", reinterpret_cast<LPVOID>(NtCreateProcess_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtCreateProcess), false);

			// NtTerminateProcess 只记录。
			QueueHook("NtTerminateProcess", reinterpret_cast<LPVOID>(NtTerminateProcess_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtTerminateProcess), false);
		}

		if (hookThread) {
			// NtCreateThreadEx 是核心：远程线程 = 注入。
			QueueHook("NtCreateThreadEx", reinterpret_cast<LPVOID>(NtCreateThreadEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtCreateThreadEx), true);

			// v18：NtCreateThread —— 老 API。参数表与 Ex 不同，
			// **必须独立一个 detour**（共用 = 参数错位 → SIGSEGV，§10-35）。
			QueueHook("NtCreateThread", reinterpret_cast<LPVOID>(NtCreateThread_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtCreateThread), false);

			QueueHook("NtTerminateThread", reinterpret_cast<LPVOID>(NtTerminateThread_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtTerminateThread), false);
		}

		if (hookMemoryOp) {
			//
			// v14：代码注入链前三步。补上以后，整条链就齐了：
			//   Allocate（本） → Write（本） → Protect（本） → CreateThreadEx（v13 已有）
			// 反射式注入 / shellcode 注入 / 进程镂空 / APC 注入都走这条链。
			//
			// 三个都标 required=false：个别精简版系统可能缺其中某个导出，
			//   缺一个不该让整层不挂（与 NtCreateUserProcess 的处理一致）。
			//
			QueueHook("NtAllocateVirtualMemory",
				reinterpret_cast<LPVOID>(NtAllocateVirtualMemory_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtAllocateVirtualMemory), false);

			QueueHook("NtProtectVirtualMemory",
				reinterpret_cast<LPVOID>(NtProtectVirtualMemory_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtProtectVirtualMemory), false);

			QueueHook("NtWriteVirtualMemory",
				reinterpret_cast<LPVOID>(NtWriteVirtualMemory_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtWriteVirtualMemory), false);
		}

		g_installed = true;

		LOG(L"ProcessGuard: 已挂载 %d 个进程/线程 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
