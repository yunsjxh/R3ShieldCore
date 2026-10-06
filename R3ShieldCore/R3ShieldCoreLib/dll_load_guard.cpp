#include "stdafx.h"
#include "dll_load_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "host_hijack_guard.h"
#include "logger.h"

// _ReturnAddress / _AddressOfReturnAddress —— 用来判断调用者模块。
#include <intrin.h>

// process_guard.cpp 里的同款定义：windows.h 默认不带 STATUS_* 常量。
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

//
// DLL 加载 / 劫持监控层。
//
// 挂载点（都在 ntdll）：
//   LdrLoadDll            ← LoadLibrary* 的底层出口，见 dll_load_guard.h
//   NtMapViewOfSection    ← 映射 DLL 映像的出口（只判 SEC_IMAGE）
//
// ⚠️ LdrLoadDll 是**极热**函数 —— 任何 DLL 加载都走它，而进程启动时
//    会加载几十上百个模块。所以这里的过滤是最关键的一步：
//
//      hook 一进来，先看 DllName 指向的路径是不是系统目录
//      （%SystemRoot% / Program Files）→ 是则立刻转原函数，
//      不计数、不上报、不判定。
//
//    判"是不是系统目录"要**尽可能便宜**：只做前缀比较，不碰文件系统。
//    一次 _wcsnicmp 对上百次启动加载来说完全不构成负担。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef NTSTATUS(NTAPI* LdrLoadDllPtr)(PWSTR searchPath, PULONG dllCharacteristics,
		PUNICODE_STRING dllName, PVOID* dllHandle);
	typedef NTSTATUS(NTAPI* NtMapViewOfSectionPtr)(HANDLE sectionHandle, HANDLE processHandle,
		PVOID* baseAddress, ULONG_PTR zeroBits, SIZE_T commitSize,
		PLARGE_INTEGER sectionOffset, PSIZE_T viewSize, DWORD inheritDisposition,
		ULONG allocationType, ULONG win32Protect);

	// NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize,
	//                 SectionPageProtection, AllocationAttributes, FileHandle)
	typedef NTSTATUS(NTAPI* NtCreateSectionPtr)(PHANDLE sectionHandle, ACCESS_MASK desiredAccess,
		PVOID objectAttributes, PLARGE_INTEGER maximumSize, ULONG sectionPageProtection,
		ULONG allocationAttributes, HANDLE fileHandle);
	constexpr ULONG DG_SEC_IMAGE = 0x01000000;

	// ------------------------------------------------------------------
	// 映像分区句柄表
	// ------------------------------------------------------------------
	//
	// 判"某个 NtMapViewOfSection 是不是在映射映像"的正解：
	//   NtQuerySection 要 SECTION_QUERY 权限，靠不住（见上）。
	//   改成**在 NtCreateSection 侧记录**：凡是带 SEC_IMAGE 建出来的分区，
	//   把它的句柄记下来。map hook 再拿句柄来这张表里查。
	//
	// 表用固定大小的环形缓冲 + 线性查找（几十项，够用；不做堆分配，
	// 避免在 hook 里引额外依赖）。句柄值可能被回收复用，所以只看
	// "最近建的"，环满即覆盖最旧的 —— 对实时匹配来说足够。
	//
	// ⚠️ 只能记录**本进程**建的 section。跨进程映射（注入器在自己进程里
	//    NtCreateSection，再 NtMapViewOfSection 到目标进程）在建 section 的
	//    那一刻也是本进程上下文，所以照样记得到 —— 这正是手工注入的典型路径。
	constexpr int DG_SECTION_RING = 64;

	struct SectionRing
	{
		HANDLE handles[DG_SECTION_RING];
		volatile LONG head;
		volatile LONG count;
	};

	SectionRing g_imageSections = {};

	void RememberImageSection(HANDLE handle) noexcept
	{
		if (!handle) {
			return;
		}
		// 环形推进：槽位写在 hand % RING 处，count 只增不减（上限 RING）。
		const LONG slot = InterlockedIncrement(&g_imageSections.head) - 1;
		g_imageSections.handles[slot % DG_SECTION_RING] = handle;
		if (g_imageSections.count < DG_SECTION_RING) {
			InterlockedIncrement(&g_imageSections.count);
		}
	}

	bool IsKnownImageSection(HANDLE handle) noexcept
	{
		if (!handle) {
			return false;
		}
		const LONG n = g_imageSections.count;
		for (LONG i = 0; i < n && i < DG_SECTION_RING; ++i) {
			if (g_imageSections.handles[i] == handle) {
				return true;
			}
		}
		return false;
	}

	LdrLoadDllPtr pOriginalLdrLoadDll = nullptr;
	NtMapViewOfSectionPtr pOriginalNtMapViewOfSection = nullptr;
	NtCreateSectionPtr pOriginalNtCreateSection = nullptr;

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

	bool StartsWithNoCaseLocal(PCWSTR text, PCWSTR prefix) noexcept
	{
		if (!text || !prefix) {
			return false;
		}
		return _wcsnicmp(text, prefix, wcslen(prefix)) == 0;
	}

	// ------------------------------------------------------------------
	// 前置过滤：这个 DLL 路径是不是"系统目录"
	// ------------------------------------------------------------------
	//
	// 这是整个 guard 的性能命门。命中即透传 —— 一个进程启动时
	// 几十上百次 LdrLoadDll 调用里，99% 都会在这里被挡回去。
	//
	// 判据用**前缀比较**，不碰文件系统（不做 GetFileAttributes、
	// 不做路径归一化）—— 因为我们要判的是"来源目录"，不是"文件是否存在"。
	//
	// 归一到 DOS 路径：LdrLoadDll 的 DllName 通常是完整 DOS 路径
	// （"C:\Windows\System32\ntdll.dll"）或纯文件名（"xxx.dll"）。
	// 纯文件名的由 LdrLoadDll 自己按搜索路径解析，我们**看不到真实位置**，
	// 只能保守放行（这类通常是系统加载器自己找的 System32 依赖）。
	//
	bool IsSystemDllPath(PCWSTR path) noexcept
	{
		if (!path || !path[0]) {
			// 拿不到路径 —— 保守放行。
			return true;
		}

		// 路径里没有反斜杠 = 纯文件名（loader 自己解析）。
		// 无法判断来源，保守当系统处理。
		if (wcschr(path, L'\\') == nullptr && wcschr(path, L'/') == nullptr) {
			return true;
		}

		static WCHAR cachedWindows[MAX_PATH] = {};
		static WCHAR cachedProgramFiles[MAX_PATH] = {};
		static WCHAR cachedProgramFilesX86[MAX_PATH] = {};
		static bool initialized = false;

		if (!initialized) {
			UINT len = GetWindowsDirectoryW(cachedWindows, _countof(cachedWindows));
			if (len == 0 || len >= _countof(cachedWindows)) {
				cachedWindows[0] = L'\0';
			}
			DWORD len2 = GetEnvironmentVariableW(L"ProgramFiles", cachedProgramFiles, _countof(cachedProgramFiles));
			if (len2 == 0 || len2 >= _countof(cachedProgramFiles)) {
				cachedProgramFiles[0] = L'\0';
			}
			DWORD len3 = GetEnvironmentVariableW(L"ProgramFiles(x86)", cachedProgramFilesX86, _countof(cachedProgramFilesX86));
			if (len3 == 0 || len3 >= _countof(cachedProgramFilesX86)) {
				cachedProgramFilesX86[0] = L'\0';
			}
			initialized = true;
		}

		// %SystemRoot%\ 下全部（System32 / SysWOW64 / WinSxS / servicing …）
		if (cachedWindows[0] && StartsWithNoCaseLocal(path, cachedWindows)) {
			PCWSTR rest = path + wcslen(cachedWindows);
			if (*rest == L'\\' || *rest == L'/') {
				return true;
			}
		}

		// Program Files / Program Files (x86) —— 安装的程序目录，也算系统可信区。
		if (cachedProgramFiles[0] && StartsWithNoCaseLocal(path, cachedProgramFiles)) {
			PCWSTR rest = path + wcslen(cachedProgramFiles);
			if (*rest == L'\\' || *rest == L'/') {
				return true;
			}
		}

		if (cachedProgramFilesX86[0] && StartsWithNoCaseLocal(path, cachedProgramFilesX86)) {
			PCWSTR rest = path + wcslen(cachedProgramFilesX86);
			if (*rest == L'\\' || *rest == L'/') {
				return true;
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::DllLoad);
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

	Action Evaluate(R3ShieldCore::DllLoadOp op, R3ShieldCore::Event& event, bool manualMap, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::DllLoad);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all）----
		//
		// ★ v23 重要修正：这里**不能一刀切 Block**。
		//
		//   实测（用户桌面 r3shieldcore-events.log，1130 行）：
		//     579 条 DLL BLOCK MapSection —— 是全部 BLOCK 里最多的一类，
		//     且**没有一条带 HIGH 标记**、没有一条是真实注入。
		//     被拦的都是系统进程自己的正常映像映射（msedge / TextInputHost /
		//     WerFault / vmtoolsd / 各种 [?] 系统服务）。
		//
		//   为什么它们会走到这里（hook 层三重过滤都过了）：
		//     ① g_loaderDepth > 0        —— 只覆盖"引擎 hook 已装上之后"的加载
		//     ② IsKnownImageSection      —— 只认 NtCreateSection 记过的 SEC_IMAGE
		//     ③ 调用者模块 == ntdll       —— 引擎是**异步注入**的，进程启动时
		//        连续映射几十个映像，hook 刚好装在这个窗口中间时，有若干次映射
		//        的**调用者不在 ntdll**（ntdll 自身重定位/延迟加载路径），
		//        于是被误判成"手工映射"。原注释（:540-545）自己就承认了这个窗口。
		//
		//   后果：这些进程的映像映射被拒（STATUS_ACCESS_DENIED）→ 进程起不来 /
		//   崩 → WerFault 启动 → WerFault 又去映射 / 写
		//   `Windows Error Reporting` 注册表 → 也被拒 → 用户看到
		//   **"Windows 无法访问指定设备、路径或文件"**。
		//   桌面那个 `setup for win10win11.exe` 就是这么死的（它的进程
		//   甚至还没走到 CreateProcess 那一步就在加载期被拒了）。
		//
		//   正确做法：与进程创建（§3.10d v22）保持一致 ——
		//     · 手工映射判定**保留**，但"拒"降级为"记录"；
		//     · 真正确凿的注入由 HostHijack 层（跨进程映射）在**调用原函数之前**
		//       就拦掉了（见上面 remote 分支），不依赖这里；
		//     · 本进程内的 MapSection 无法区分"引擎注入窗口的误判"与"反射式
		//       加载"，一刀切 Block 的代价（系统进程全崩）远大于收益。
		//
		//   ⚠️ 这不是放松安全：跨进程映像映射（注入的强信号）仍在上面的
		//      `remote` 分支被 HostHijackGuard 拦；真正断注入链的仍是
		//      WriteVirtualMemory / ProtectVirtualMemory / CreateThreadEx。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			// A confirmed manual-map signal is an injection primitive. It must not
			// be converted into an Allowed event by BlockAll.
			if (manualMap || op == R3ShieldCore::DllLoadOp::ManualMap) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				event.Flags |= R3ShieldCore::FlagEventManualMap;
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				return Action::Block;
			}
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskDllLoad(event.DllPath, static_cast<ULONG>(op), manualMap)) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				event.Flags |= R3ShieldCore::FlagEventNonSystemDll;
				if (manualMap || op == R3ShieldCore::DllLoadOp::ManualMap) {
					event.Flags |= R3ShieldCore::FlagEventManualMap;
				}
			}
		}

		if (!highRisk) {
			// 非高危 = "非系统目录但也不是可写目录"的正常加载
			//（Program Files 下的自装软件、自建安装目录）。
			// **只记录，标 Allowed** —— 不能标 WouldBlock，否则像
			// PowerShell 7 这种 D:\Program Files 下的程序一启动就刷 200+ 条
			// "本应拒绝"，把日志页淹掉（噪音淹没真信号）。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// 高危：可写目录 / 手工映射 / protect_file 的 DLL 加载。
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

	// 把事件里"被加载的 DLL 路径"填好。同时用 KeyPath 放一份短摘要，
	// 便于 GUI 的"来源"列直接渲染（KeyPath 是各 guard 通用的名称列）。
	void SetDllTarget(R3ShieldCore::Event& event, PCWSTR dllPath) noexcept
	{
		if (dllPath && dllPath[0]) {
			wcsncpy_s(event.DllPath, dllPath, _TRUNCATE);
			wcsncpy_s(event.KeyPath, dllPath, _TRUNCATE);
		}
		else {
			wcsncpy_s(event.DllPath, L"(未知来源)", _TRUNCATE);
			wcsncpy_s(event.KeyPath, L"(未知来源)", _TRUNCATE);
		}

		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.DllPath));
	}

	// ------------------------------------------------------------------
	// "当前线程正在走 LdrLoadDll" 标记
	// ------------------------------------------------------------------
	//
	// ⚠️ 这是 NtMapViewOfSection 不误报的关键。
	//
	//   LoadLibrary 的正常路径是：LdrLoadDll → （内部）NtMapViewOfSection
	//   把映像映射进来 → 登记模块表。也就是说**每一次正常的 DLL 加载，
	//   都会伴随一次映像映射**。
	//
	//   如果 map hook 只判"这是不是映像分区"，就会把**每一个正常加载**
	//   都再报一遍 —— 实测直接刷出几百条 MapSection HIGH（每个进程启动
	//   都要映射自己的 r3shieldcore-lib.dll 和其它非系统模块）。
	//   这是第三次踩同一个坑（噪音淹没真信号）。
	//
	//   正确做法：用 thread_local 标记"当前线程正在 LdrLoadDll 里面"。
	//   LdrLoadDll hook 在调原函数**之前**置位、**之后**清位；
	//   map hook 一进来看到置位就说明"这次映射是加载器干的"，直接透传。
	//   只有"没有任何 LdrLoadDll 调用者"的映像映射才可能是手工映射。
	//
	//   为什么用 thread_local：LdrLoadDll 是同步的，映射发生在同一个线程上；
	//   而且是加载器的内部调用，不可能跨线程。
	//
	//   ⚠️ 必须用深度计数而不是 bool：LdrLoadDll 可能递归（依赖 DLL 的
	//      依赖又触发 LdrLoadDll）。用 bool 的话内层清位会把外层也清掉。
	__declspec(thread) int g_loaderDepth = 0;

	struct LoaderScope
	{
		LoaderScope() noexcept { ++g_loaderDepth; }
		~LoaderScope() noexcept { --g_loaderDepth; }
	};

	// ------------------------------------------------------------------
	// hook：LdrLoadDll
	// ------------------------------------------------------------------
	// 把 dllName->Buffer 抄到调用方缓冲。Buffer 不保证 NUL 结尾，也可能是野指针，
	// 所以整段用 __try 包住。
	//
	// ⚠️ 单独抽成函数是必须的：hook 里同时要用 LoaderScope（有析构函数的类），
	//    而 MSVC 不允许"同一函数里既有 __try 又有需要对象展开的对象"（C2712）。
	//    把 __try 挪到独立函数里，两边就都能用。
	bool CopyDllNameToBuffer(PUNICODE_STRING dllName, PWSTR buffer, ULONG bufferChars) noexcept
	{
		bool ok = false;
		__try {
			if (dllName && dllName->Buffer && dllName->Length > 0) {
				ULONG chars = dllName->Length / sizeof(WCHAR);
				if (chars >= bufferChars) {
					chars = bufferChars - 1;
				}
				for (ULONG i = 0; i < chars; i++) {
					buffer[i] = dllName->Buffer[i];
				}
				buffer[chars] = L'\0';
				ok = true;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			ok = false;
		}
		return ok;
	}

	NTSTATUS NTAPI LdrLoadDll_Hook(PWSTR searchPath, PULONG dllCharacteristics,
		PUNICODE_STRING dllName, PVOID* dllHandle)
	{
		// ---- 第一道也是最热的一道：把 UNICODE_STRING 抄成本地缓冲 ----
		WCHAR localPath[R3ShieldCore::MaxImagePathChars + 1] = {};
		const bool havePath = CopyDllNameToBuffer(dllName, localPath, _countof(localPath));

		// ---- 系统目录：透传，零副作用 ----
		// 也要在 loader scope 里 —— 这次加载内部的映像映射同样不该被
		// 当成手工映射上报。
		if (!havePath || IsSystemDllPath(localPath)) {
			LoaderScope scope;
			return pOriginalLdrLoadDll(searchPath, dllCharacteristics, dllName, dllHandle);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetDllTarget(event, localPath);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::DllLoadOp::LoadLibrary, event, false, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		NTSTATUS result = 0;
		{
			// 原函数执行期间，本线程的映像映射都算加载器行为。
			LoaderScope scope;
			result = pOriginalLdrLoadDll(searchPath, dllCharacteristics, dllName, dllHandle);
		}
		event.Status = static_cast<ULONG>(result);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：NtCreateSection
	// ------------------------------------------------------------------
	//
	// 只做一件事：**记住"带 SEC_IMAGE 建出来的分区句柄"**，供
	// NtMapViewOfSection hook 判"这是不是映像映射"。
	//
	// 为什么要绕这一圈：NtQuerySection(SectionImageInformation) 需要
	// SECTION_QUERY 权限，绝大多数调用方不申请，查询会返回 ACCESS_DENIED，
	// 拿不到"是不是映像"的答案（详见上面 NtQuerySectionPtr 的注释）。
	// 建分区时我们自己能看到 AllocationAttributes，这是最可靠的观测点。
	//
	// 不产生任何事件、不做判定 —— 纯粹记账，开销极小。
	NTSTATUS NTAPI NtCreateSection_Hook(PHANDLE sectionHandle, ACCESS_MASK desiredAccess,
		PVOID objectAttributes, PLARGE_INTEGER maximumSize, ULONG sectionPageProtection,
		ULONG allocationAttributes, HANDLE fileHandle)
	{
		const NTSTATUS result = pOriginalNtCreateSection(sectionHandle, desiredAccess,
			objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle);

		if (result >= 0 && sectionHandle && *sectionHandle &&
			(allocationAttributes & DG_SEC_IMAGE) != 0) {
			RememberImageSection(*sectionHandle);
		}

		return result;
	}

	// ------------------------------------------------------------------
	// hook：NtMapViewOfSection
	// ------------------------------------------------------------------
	//
	// ⚠️ 这个函数**极热** —— 任何内存映射都走它（文件映射、堆、共享内存、
	//    映像）。所以前置过滤必须尽可能早、尽可能便宜。
	//
	// ⚠️⚠️ 关于怎么判"这是在映射一个 DLL 映像" —— 这里踩过一个大坑，记下来：
	//
	//   一开始想当然地写 `(allocationType & MEM_IMAGE) == 0 → 透传`。
	//   **这是错的**：MEM_IMAGE(0x01000000) 只是 NtQueryVirtualMemory 返回的
	//   **内存区域类型**（MEMORY_BASIC_INFORMATION::Type），它**不是**
	//   NtMapViewOfSection 的输入参数。把 MEM_IMAGE 塞进 AllocationType
	//   一定失败（实测穷举了全部 AllocationType × Protect 组合，
	//   见 tools/mapfind.cpp：任何含 0x01000000 的组合都返回
	//   0xC0000045 / 0xC000000D / 0xC0000022，从未成功）。
	//   能成功的只有 AllocationType = ViewShare(1)|ViewUnmap(2) +
	//   Protect = PAGE_READONLY(0x02)，而且 ViewSize 必须传 0。
	//
	//   所以按原写法，这个 hook **永远不会命中**（写死也不会报错，
	//   属于"静默失效"）。
	//
	//   接着试了第二条路 —— 用 NtQuerySection(handle, SectionImageInformation)
	//   问内核"这个分区是不是映像"。**这条也不通**：
	//   SectionImageInformation 查询要求句柄带 SECTION_QUERY(0x0001) 权限，
	//   而调用方建分区时普遍只要 SECTION_MAP_READ(0x0004)。
	//   实测：一个确实是 SEC_IMAGE 建出来的分区，NtQuerySection 返回
	//   0xC0000022 (ACCESS_DENIED)，按"成功才是映像"判 → 真映像全被漏掉，
	//   hook 又一次静默失效。
	//
	//   **最终方案**：不在 map 侧判，改在 create 侧记账 ——
	//     另挂 ntdll!NtCreateSection，凡是带 SEC_IMAGE 建出来的分区，
	//     把它的句柄记进 g_imageSections 环形表。
	//     map hook 拿句柄来表里查即可（见 IsKnownImageSection）。
	//   这是唯一在"调用方不申请额外权限"的前提下也能拿准的办法。
	NTSTATUS NTAPI NtMapViewOfSection_Hook(HANDLE sectionHandle, HANDLE processHandle,
		PVOID* baseAddress, ULONG_PTR zeroBits, SIZE_T commitSize,
		PLARGE_INTEGER sectionOffset, PSIZE_T viewSize, DWORD inheritDisposition,
		ULONG allocationType, ULONG win32Protect)
	{
		// ⚠️ 第一道过滤：加载器上下文。
		//   本次映射如果是在 LdrLoadDll 里发生的，就是**正常加载的附带映射**，
		//   LdrLoadDll hook 已经报过了，这里不能重复报（否则噪音爆炸）。
		if (g_loaderDepth > 0) {
			return pOriginalNtMapViewOfSection(sectionHandle, processHandle, baseAddress, zeroBits,
				commitSize, sectionOffset, viewSize, inheritDisposition, allocationType, win32Protect);
		}

		// ---- 判"这是不是映像映射" ----
		//
		// 用 NtCreateSection hook 记下来的"SEC_IMAGE 句柄表"来查（见上）。
		// 查不到 → 一定是数据分区/共享内存，与 DLL 加载无关，直接透传。
		// 这一条就把绝大多数的 NtMapViewOfSection 调用挡掉了（堆、文件映射…）。
		if (!IsKnownImageSection(sectionHandle)) {
			return pOriginalNtMapViewOfSection(sectionHandle, processHandle, baseAddress, zeroBits,
				commitSize, sectionOffset, viewSize, inheritDisposition, allocationType, win32Protect);
		}

		// ---- 判断调用者是不是加载器自己 ----
		//
		// ⚠️ 这是"不误报"的第二道关键（第一道是 g_loaderDepth）。
		//
		//   为什么光靠 g_loaderDepth 不够：
		//     引擎是"发现进程 → 远程注入 → 装 hook"的异步流程。注入存在**时间窗**，
		//     而进程启动时会连续映射几十个映像。如果 hook 恰好在这个窗口中间装上，
		//     就会有若干次映射"没赶上 LdrLoadDll 的 scope"（因为 scope 由我们的
		//     LdrLoadDll hook 置位，装 hook 之前发生的加载不会置位）——
		//     实测就是这样冒出成片的假 MapSection HIGH（pid 各不相同）。
		//
		//   可靠的判据：看**返回地址落在哪个模块**。
		//     正常加载的映像映射，调用者是 ntdll 里的加载器代码
		//     （LdrpMapDll / LdrpLoadDll 等）。手工映射的调用者一定在
		//     **别的模块**（注入器自己的代码，或者一段 shellcode）。
		PVOID callerAddress = _ReturnAddress();
		HMODULE callerModule = nullptr;
		GetModuleHandleExW(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(callerAddress), &callerModule);

		static HMODULE cachedNtdll = GetModuleHandleW(L"ntdll.dll");
		if (callerModule != nullptr && callerModule == cachedNtdll) {
			// 调用者在 ntdll 里 = 加载器内部映射 = 正常加载，不报。
			return pOriginalNtMapViewOfSection(sectionHandle, processHandle, baseAddress, zeroBits,
				commitSize, sectionOffset, viewSize, inheritDisposition, allocationType, win32Protect);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		// 区分"映射到自己"和"映射到别的进程"：
		//   · 映射到远端进程 = 注入的强信号（把自己的映像塞进别人）
		//   · 映射到自己但没有 LdrLoadDll 上下文 = 反射式加载/手工映射
		const bool remote = (processHandle != nullptr) &&
			(processHandle != GetCurrentProcess()) &&
			(GetProcessId(processHandle) != GetCurrentProcessId());

		// ---- 宿主劫持补充判定（v15）----
		//
		// ⚠️ 跨进程映射是 v14 注入链之外的第二条注入路径，归 HostHijack 页签。
		//    NtMapViewOfSection 已被本 guard 挂住（不能重复挂），所以由本 guard
		//    在**调用原函数之前**转调 HostHijackGuard::EvaluateRemoteMapSection()。
		//    它返回 true 表示宿主劫持层决定拦 —— 这里直接拒掉映射。
		//
		//    只在 remote == true 时调（本进程映射是反射式加载，归 DllLoad 管）。
		if (remote && HostHijackGuard::EvaluateRemoteMapSection(processHandle)) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		if (remote) {
			SetDllTarget(event, L"（跨进程映像映射 / NtMapViewOfSection —— 注入特征）");
		}
		else {
			SetDllTarget(event, L"（映像映射 / NtMapViewOfSection —— 无模块登记的手工映射特征）");
		}
		event.Status = 0;

		// manualMap = true —— 已经排除了"由 LdrLoadDll 触发的正常加载"，
		// 走到这里的映像映射要么跨进程、要么没有加载器上下文，都是手工映射特征。
		const Action action = Evaluate(R3ShieldCore::DllLoadOp::MapSection, event, true, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return STATUS_ACCESS_DENIED;
		}

		const NTSTATUS result = pOriginalNtMapViewOfSection(sectionHandle, processHandle, baseAddress,
			zeroBits, commitSize, sectionOffset, viewSize, inheritDisposition, allocationType, win32Protect);
		event.Status = static_cast<ULONG>(result);
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
			LOG(L"DllLoadGuard: 模块 %S 未加载 (required=%d)", moduleName, (int)required);
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			LOG(L"DllLoadGuard: %S!%S 找不到 (required=%d)", moduleName, functionName, (int)required);
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"DllLoadGuard: MH_CreateHook(%S) 失败，状态 %d (target=%p)", functionName, (int)status, target);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"DllLoadGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, (int)status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace DllLoadGuard
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
				LOG(L"DllLoadGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookDllLoad) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"DllLoadGuard: hook_dll_load 未开启，本进程不挂 DLL 加载 hook");
			return true;
		}

		g_bypass = false;

		// ntdll 在任何进程里都已加载（它就是加载器自己）。
		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
		if (!ntdll) {
			LOG(L"DllLoadGuard: ntdll.dll 未加载（不可能），跳过");
			g_installed = true;
			return true;
		}

		// 必需项：LdrLoadDll（常规加载出口）+ NtCreateSection（记账映像句柄）。
		QueueHook("ntdll.dll", "LdrLoadDll", reinterpret_cast<LPVOID>(LdrLoadDll_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalLdrLoadDll), true);
		QueueHook("ntdll.dll", "NtCreateSection", reinterpret_cast<LPVOID>(NtCreateSection_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtCreateSection), true);

		// NtMapViewOfSection 依赖 NtCreateSection 的记账，两者要一起可用。
		QueueHook("ntdll.dll", "NtMapViewOfSection", reinterpret_cast<LPVOID>(NtMapViewOfSection_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtMapViewOfSection), true);

		g_installed = true;

		LOG(L"DllLoadGuard: 已挂载 %d 个 DLL 加载 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
