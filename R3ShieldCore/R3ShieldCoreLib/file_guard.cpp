#include "stdafx.h"
#include "file_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 文件行为拦截层。
//
// 与 registry_guard.cpp 是同一套骨架（判定 → 上报 / 拒绝 → 等排空），
// 差别只在 hook 的 API 和"什么叫写意图"的判定上：
//
//   注册表：一次调用一个动作，NtSetValueKey 就是写。
//   文件：  NtCreateFile 一个调用可能同时"打开 + 新建 + 截断"，
//           动作得从 DesiredAccess + CreateDisposition + CreateOptions
//           三处合起来推。
//
// 不 include <winternl.h> 的原因同 registry_guard.cpp：项目 stdafx.h 带了
// ntsecapi.h，会牵进 SubAuth.h，而它会定义 NTSTATUS / UNICODE_STRING。
// 这里自己定义布局等价的本地类型避开重定义。
//
namespace
{
	struct FG_UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};

	struct FG_OBJECT_ATTRIBUTES
	{
		ULONG Length;
		HANDLE RootDirectory;
		FG_UNICODE_STRING* ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	};

	struct FG_IO_STATUS_BLOCK
	{
		union
		{
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	};

	//
	// FILE_RENAME_INFORMATION 的本地定义（winternl.h 里叫
	// FILE_RENAME_INFORMATION，但项目不 include 它，所以自己定义一份）。
	//
	// 布局：RootDirectory（可空）+ FileNameLength + FileName[]。
	// FileName 紧跟其后，长度由 FileNameLength 给出，**不是** NUL 结尾，
	// 这一点和普通字符串不同，取的时候要按长度拷。
	//
	struct FILE_RENAME_INFORMATION_LOCAL
	{
		union
		{
			BOOLEAN ReplaceIfExists;
			ULONG Flags;
		};
		HANDLE RootDirectory;
		ULONG FileNameLength;
		WCHAR FileName[1];
	};

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

	// ntdll 文件 API 原型。用 _Ptr 后缀避开 winternl.h 里可能已有的声明。
	typedef NTSTATUS(NTAPI* NtCreateFilePtr)(PHANDLE, ACCESS_MASK, const FG_OBJECT_ATTRIBUTES*,
		FG_IO_STATUS_BLOCK*, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
	typedef NTSTATUS(NTAPI* NtOpenFilePtr)(PHANDLE, ACCESS_MASK, const FG_OBJECT_ATTRIBUTES*,
		FG_IO_STATUS_BLOCK*, ULONG, ULONG);
	typedef NTSTATUS(NTAPI* NtWriteFilePtr)(HANDLE, HANDLE, PVOID, PVOID, FG_IO_STATUS_BLOCK*,
		PVOID, ULONG, PLARGE_INTEGER, PULONG);
	typedef NTSTATUS(NTAPI* NtSetInformationFilePtr)(HANDLE, FG_IO_STATUS_BLOCK*, PVOID, ULONG, ULONG);
	typedef NTSTATUS(NTAPI* NtSetSecurityObjectPtr)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
	typedef NTSTATUS(NTAPI* NtSetEaFilePtr)(HANDLE, FG_IO_STATUS_BLOCK*, PVOID, ULONG);
	typedef NTSTATUS(NTAPI* NtQueryObjectPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);

	NtCreateFilePtr pOriginalNtCreateFile = nullptr;
	NtOpenFilePtr pOriginalNtOpenFile = nullptr;
	NtWriteFilePtr pOriginalNtWriteFile = nullptr;
	NtSetInformationFilePtr pOriginalNtSetInformationFile = nullptr;
	NtSetSecurityObjectPtr pOriginalNtSetSecurityObject = nullptr;
	NtSetEaFilePtr pOriginalNtSetEaFile = nullptr;

	// NtQueryObject 不挂 hook，只留一个干净指针用来还原句柄路径。
	// 不挂 = 不可能递归（和 registry_guard 的 NtQueryKey 同理）。
	NtQueryObjectPtr pOriginalNtQueryObject = nullptr;

	bool g_installed = false;
	bool g_bypass = false;
	bool g_ownsNtSetSecurityObjectHook = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;

	// ------------------------------------------------------------------
	// FILE_INFORMATION_CLASS 里我们关心的几个。
	//
	// 这几个值从 Windows 2000 起就没变过，是稳定的 ABI。
	// ------------------------------------------------------------------
	constexpr ULONG FileBasicInformation = 4;      // 时间戳 / 属性
	constexpr ULONG FileRenameInformation = 10;    // 改名 / 移动（不带根句柄）
	constexpr ULONG FileDispositionInformation = 13; // 标记删除
	constexpr ULONG FileEndOfFileInformation = 20; // 截断 / 扩容
	constexpr ULONG FileRenameInformationEx = 65;  // Win10 RS1+，带 flags
	constexpr ULONG FileDispositionInformationEx = 64; // Win10 RS1+

	// CreateDisposition 值
	constexpr ULONG FILE_SUPERSEDE = 0;
	constexpr ULONG FILE_OPEN = 1;
	constexpr ULONG FILE_CREATE = 2;
	constexpr ULONG FILE_OPEN_IF = 3;
	constexpr ULONG FILE_OVERWRITE = 4;
	constexpr ULONG FILE_OVERWRITE_IF = 5;

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

	// ------------------------------------------------------------------
	// 工具
	// ------------------------------------------------------------------
	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	//
	// 这个打开请求是否带"写"的意图。
	//
	// 和注册表那边不同，文件这边不能只看 DesiredAccess —— 真正的破坏性
	// 动作有很大一部分藏在 CreateDisposition 里：
	//   FILE_SUPERSEDE / FILE_OVERWRITE / FILE_OVERWRITE_IF
	// 这三个是"把已有内容干掉（或准备干掉）"，即使 DesiredAccess
	// 只要了 FILE_WRITE_DATA 也已经是破坏性的。
	//
	// 注意排除项：FILE_READ_ATTRIBUTES / FILE_WRITE_ATTRIBUTES 很常见且无害，
	// 所以**不**把它们算进写意图，否则光是在资源管理器里滚动目录就会刷屏。
	//
	// ⚠️ 踩过的坑：早期版本把 FILE_WRITE_ATTRIBUTES 写进了 WriteAccess，
	//    和上面这句注释直接矛盾。后果是任何"只为改时间戳/属性而打开"的
	//    调用都被判成有写意图的 Create —— 走在敏感路径（hosts）上就是
	//    一次高危弹窗。实测：探针用 FILE_WRITE_ATTRIBUTES 打开 hosts 被
	//    拦了 9.5 秒（等超时）。改属性本身由 NtSetInformationFile
	//    (FileBasicInformation) 覆盖，那才是真正的入口，无需在这里拦。
	//
	// ⚠️★ v39：**必须带上 GENERIC_ALL（0x10000000）**。
	//
	//    踩过的坑（真实绕过）：样本写引导区用的是
	//      CreateFileA("\\\\.\\PhysicalDrive0", 0x10000000, ...)
	//    `0x10000000` 是 **GENERIC_ALL**（不是 GENERIC_WRITE ——
	//    GENERIC_WRITE 是 0x40000000）。而原来的掩码只列了
	//    GENERIC_WRITE 和各 FILE_* 具体权限，**没有 GENERIC_ALL**，
	//    于是 `IsWriteIntent(0x10000000, FILE_OPEN)` 返回 false
	//    ⇒ 这次打开被判成"没有写意图" ⇒ 直接 Pass，连 Evaluate 都进不去。
	//
	//    注意这四个 generic 位是**在打开时才由 I/O 管理器映射**成具体权限的，
	//    hook 拿到的是映射**之前**的原始 DesiredAccess，所以必须自己把
	//    generic 位翻译过来。只认 GENERIC_WRITE 是不够的。
	//
	//    影响面**远不止裸盘**：任何用 GENERIC_ALL 打开的敏感文件
	//    （hosts / System32 / 启动目录）原本都被判成"无写意图"而放行。
	bool IsWriteIntent(ULONG desiredAccess, ULONG disposition) noexcept
	{
		constexpr ULONG WriteAccess =
			FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
			DELETE | WRITE_DAC | WRITE_OWNER |
			FILE_DELETE_CHILD | GENERIC_WRITE | GENERIC_ALL;

		if ((desiredAccess & WriteAccess) != 0) {
			return true;
		}

		switch (disposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE:
		case FILE_OVERWRITE_IF:
		case FILE_CREATE:
			return true;
		default:
			return false;
		}
	}

	// 这个 disposition 是否会新建对象。
	bool IsCreateDisposition(ULONG disposition) noexcept
	{
		return disposition == FILE_SUPERSEDE || disposition == FILE_CREATE ||
			disposition == FILE_OPEN_IF || disposition == FILE_OVERWRITE_IF;
	}

	// 这个 disposition 是否带覆盖意图（已有内容会被干掉）。
	bool IsOverwriteDisposition(ULONG disposition) noexcept
	{
		return disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE ||
			disposition == FILE_OVERWRITE_IF;
	}

	void CopyUnicodeString(const FG_UNICODE_STRING* source, WCHAR* destination,
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

	// ------------------------------------------------------------------
	// 路径解析
	// ------------------------------------------------------------------
	//
	// 文件路径有两种来源：
	//   1. NtCreateFile / NtOpenFile 的 ObjectAttributes->ObjectName
	//      → 通常是 \??\C:\Foo 或相对路径（带 RootDirectory）
	//   2. 已有句柄（NtWriteFile / NtSetInformationFile 等）
	//      → NtQueryObject 拿 \Device\HarddiskVolume2\Foo
	//
	// 两种最后都要归一成能在界面上看懂的形式。

	// \??\C:\Foo → C:\Foo
	void NormalizeDosPrefix(WCHAR* path, ULONG capacity) noexcept
	{
		if (capacity < 5) {
			return;
		}

		// \??\ 前缀
		if (wcsncmp(path, L"\\??\\", 4) == 0) {
			size_t length = wcslen(path + 4);
			memmove(path, path + 4, (length + 1) * sizeof(WCHAR));
			return;
		}

		// \DosDevices\ 前缀（等价写法）
		if (_wcsnicmp(path, L"\\DosDevices\\", 12) == 0) {
			size_t length = wcslen(path + 12);
			memmove(path, path + 12, (length + 1) * sizeof(WCHAR));
		}
	}

	// \Device\HarddiskVolumeN\Foo → C:\Foo。转不了就原样保留。
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

	// 把路径统一成"能在界面上看懂"的形式。
	void NormalizeFilePath(WCHAR* path, ULONG capacity) noexcept
	{
		NormalizeDosPrefix(path, capacity);
		DevicePathToDosPath(path, capacity);
	}

	// 用句柄拿路径。NtQueryObject 走的是干净指针，不会递归。
	ULONG ResolveHandlePath(HANDLE objectHandle, WCHAR* buffer, ULONG capacity) noexcept
	{
		if (!objectHandle || objectHandle == INVALID_HANDLE_VALUE ||
			!pOriginalNtQueryObject || capacity == 0) {
			return 0;
		}

		constexpr ULONG ObjectNameInformation = 1;

		struct OBJECT_NAME_INFORMATION_LOCAL
		{
			FG_UNICODE_STRING Name;
			WCHAR Buffer[1];
		};

		BYTE raw[sizeof(OBJECT_NAME_INFORMATION_LOCAL) + (R3ShieldCore::MaxKeyPathChars + 1) * sizeof(WCHAR)] = {};
		ULONG resultLength = 0;

		NTSTATUS status = pOriginalNtQueryObject(objectHandle, ObjectNameInformation,
			raw, sizeof(raw), &resultLength);
		if (status < 0) {
			return 0;
		}

		auto* information = reinterpret_cast<OBJECT_NAME_INFORMATION_LOCAL*>(raw);
		ULONG chars = information->Name.Length / sizeof(WCHAR);
		if (chars >= capacity) {
			chars = capacity - 1;
		}

		if (chars > 0 && information->Name.Buffer) {
			memcpy(buffer, information->Name.Buffer, chars * sizeof(WCHAR));
		}

		return chars;
	}

	// 句柄路径解析 + 归一化，落进 event。
	void CaptureHandlePath(HANDLE fileHandle, R3ShieldCore::Event& event) noexcept
	{
		WCHAR path[R3ShieldCore::MaxKeyPathChars] = {};
		ULONG chars = ResolveHandlePath(fileHandle, path, _countof(path));
		if (chars == 0) {
			return;
		}

		path[chars] = L'\0';
		NormalizeFilePath(path, _countof(path));

		wcsncpy_s(event.KeyPath, path, _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
	}

	// ------------------------------------------------------------------
	// 上报
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::File);
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
	// 这个"文件"到底是不是普通磁盘文件。
	//
	// NtCreateFile / NtWriteFile 的适用面远不止文件：命名管道、邮件槽、
	// 套接字、设备、控制台都走同一套 API。把它们当文件处理会直接破坏
	// 系统 —— 实测 BLOCK 模式下 Chrome 的 mojo 管道、控制台 stdout、
	// 以及 \Device\Afd（套接字）全被拒，连探针自己的 printf 都打不出来
	// （stdout 在重定向时是管道），网络通信也会断掉。
	//
	// 判据用路径前缀：不是 \Device\HarddiskVolumeN / C: 这类卷上路径的，
	// 一律不算磁盘文件。
	//
	// 常见的非磁盘对象：
	//   \Device\NamedPipe\...    命名管道（IPC）
	//   \Device\Mailslot\...     邮件槽（IPC）
	//   \Device\Afd              套接字（网络）
	//   \Device\ConDrv\...       控制台
	//   \Device\Nsi / \Device\*  各种内核设备
	//
	// 这个判定必须在**任何**模式（含 BLOCK）下生效，不能只在 ASK 里做 ——
	// BLOCK 是最容易把系统打崩的模式。
	bool IsDiskFile(PCWSTR path) noexcept
	{
		if (!path || path[0] == L'\0') {
			// 路径都没解析出来，不能凭这个就处理（可能是相对路径 + RootDirectory）。
			return false;
		}

		// 盘符路径 C:\...
		if (path[0] != L'\\' && path[1] == L':') {
			return true;
		}

		// 设备路径：只有卷设备算磁盘文件。
		if (_wcsnicmp(path, L"\\Device\\HarddiskVolume", 22) == 0) {
			return true;
		}

		// 其余一律不算。
		return false;
	}

	//
	// 这一类路径在**任何模式**下都彻底无视，连记录都不做。
	//
	// 判据是"它根本不是一个文件"（管道/套接字/设备），而不是
	// "它是文件但我不想管"。前者对一个"文件监控"来说属于噪音源，
	// 记了没有信息量：mojo 管道每秒几十条，路径还带随机后缀。
	//
	// 实测：LOG 模式下不排除这些，87 条事件里 77 条是管道，
	// 真正的文件写入（bilibili 的 Cache_Data）只有 7 条，
	// 完全被淹没。
	bool IsNonFileObject(PCWSTR path) noexcept
	{
		return !IsDiskFile(path);
	}

	// 不区分大小写的子串查找（路径大小写不固定，`wcsstr` 会漏）。
	// 与 r3shieldcore_rules.cpp 里同名工具保持一致，各自 TU 内部使用。
	bool ContainsNoCase(PCWSTR text, PCWSTR fragment) noexcept
	{
		if (!text || !fragment || fragment[0] == L'\0') {
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

	//
	// 磁盘文件里，哪些不该拦、也不该问的路径。
	//
	// 与 IsNonFileObject 的区别很重要：
	//   非文件对象（管道/套接字）→ 彻底无视，任何模式都不记录
	//   这个函数命中的路径       → 不拦不问，但 LOG 模式下仍然记录
	//
	// 系统目录（C:\Windows 等）和临时目录在 BLOCK 模式下也**必须**放行：
	// 实测 BLOCK 一开，系统组件写 C:\Windows\* 失败会引发各种奇怪故障，
	// 而且 %TEMP% 是所有程序都在写的，拦了等于把系统弄坏。
	//
	// 高频缓存目录（浏览器/Electron 的 Cache、GPUCache、ShaderCache…）
	// 必须排除，否则 ASK 模式下就是弹窗机关枪 —— 实测 Chrome 的
	// QuotaManager-journal 每秒被写十几次，每一秒都在弹窗。
	bool IsExemptDiskPath(PCWSTR path) noexcept
	{
		if (!path || path[0] == L'\0') {
			return true; // 拿不到路径就别拦
		}

		static const PCWSTR prefixes[] = {
			L"C:\\Windows\\",
			L"C:\\ProgramData\\Microsoft\\Windows\\",
			L"C:\\$Recycle.Bin\\",
			L"C:\\Recovery\\",
			L"C:\\System Volume Information\\",
		};

		for (PCWSTR prefix : prefixes) {
			if (_wcsnicmp(path, prefix, wcslen(prefix)) == 0) {
				return true;
			}
		}

		//
		// 高频缓存目录。这些目录的写入是"程序内部状态"，不是用户数据：
		//   \<任意>\...\Cache\Cache_Data\...    Chromium 系磁盘缓存
		//   \ShaderCache\ / \GPUCache\ / \DawnCache\ / \GrShaderCache\
		//   以及 ...\WebStorage\...            站点存储
		//
		// 用"路径里含某段"来判而不是完整前缀，因为每个浏览器/Electron
		// 应用的根目录都不同，但内部结构是同一套（都基于 Chromium）。
		static const PCWSTR noisySegments[] = {
			L"\\ShaderCache\\",
			L"\\GrShaderCache\\",
			L"\\GPUCache\\",
			L"\\DawnCache\\",
			L"\\DawnGraphiteCache\\",
			L"\\DawnWebGPUCache\\",
			L"\\Cache\\Cache_Data\\",
			L"\\WebStorage\\",
			L"\\Code Cache\\",
			L"\\Service Worker\\",
		};

		for (PCWSTR segment : noisySegments) {
			// ⚠️ 必须不区分大小写：路径大小写不固定（`C:\WINDOWS` /
			//    `\AppData\Local\Google\Chrome\...` 实际写法五花八门），
			//    用 wcsstr 会漏掉一部分 → 漏掉的那些就变成弹窗噪音。
			//    同 r3shieldcore_rules.cpp 的 ContainsNoCase。
			if (ContainsNoCase(path, segment)) {
				return true;
			}
		}

		// 临时目录：%TEMP% / %TMP%。
		WCHAR temp[R3ShieldCore::MaxImagePathChars] = {};
		for (PCWSTR variable : { L"TEMP", L"TMP" }) {
			DWORD length = GetEnvironmentVariable(variable, temp, _countof(temp));
			if (length > 0 && length < _countof(temp)) {
				if (_wcsnicmp(path, temp, length) == 0) {
					WCHAR next = path[length];
					if (next == L'\0' || next == L'\\') {
						return true;
					}
				}
			}
		}

		return false;
	}

	// ------------------------------------------------------------------
	// block-all 的**探测边界**（v25）：这一条到底是不是"写"？
	// ------------------------------------------------------------------
	//
	// 为什么需要：`Evaluate` 只被"带写意图"的调用点调到（`NtCreateFile_Hook`
	// 用 `IsWriteIntent` 过滤过），但两个例外会漏进来：
	//
	//   · `NtSetInformationFile_Hook` —— 它的 `blockable=false` 分支
	//     （`FileBasicInformation` / `FilePositionInformation` 之类**只读信息类**）
	//     也会进 `Evaluate`；
	//   · 拿不到路径 / 描述符的 `OpenFile` 变体。
	//
	// block-all 下把这类"打开看看"放进弹窗没有价值 —— 用户无法判断
	// "程序想看一个文件"是不是恶意，问了只会变成噪音，还会让
	// `FILE BLOCK` 计数虚高（历史日志里 `FILE BLOCK` 为 0 正是因为
	// 探测边界把它们挡在 `Evaluate` 之外，这里要保持同样的效果）。
	//
	// 返回 true = "这不是一次写" → 调用方**直接拒且不问**。
	//
	// ⚠️ 只用 `event` 里**确实存在**的字段判定，不额外接参数：
	//    `event.DesiredAccess` 由各 Hook 在调用 `Evaluate` 前填好，
	//    `CreateDisposition` 走参数传（`Evaluate` 内不落 event，见 v25）。
	//    早期草稿试图再判 `CreateOptions & FILE_DIRECTORY_FILE`，但
	//    `FILE_DIRECTORY_FILE` 需要 `ntifs.h` / `winternl.h`，本项目**没有**
	//    包含 —— 而且那个分支无论如何都落到最后的 `return true`，**不改结果**。
	//    依赖一个未声明宏去换零信息量 → 删掉（编译期 C2065 已证实）。
	bool IsBlockAllProbeBoundary(const R3ShieldCore::Event& event,
		ULONG createDisposition) noexcept
	{
		const ULONG op = event.Op;

		// 只有 `Create` / `Open` 两种带"打开"语义的 op 才可能是探测边界。
		// `Write` / `SetInformation` / `SetSecurity` / `SetEa` 都是确凿的写 —— 必须问。
		if (op != static_cast<ULONG>(R3ShieldCore::FileOp::Create) &&
			op != static_cast<ULONG>(R3ShieldCore::FileOp::Open)) {
			return false;
		}

		// 带写意图 → 不是边界，照常弹窗。
		if (IsWriteIntent(event.DesiredAccess, createDisposition)) {
			return false;
		}

		// 没有写意图的打开 = 探测边界，直接拒且不问。
		return true;
	}

	// ------------------------------------------------------------------
	// 核心判定。绝不抛异常、绝不分配内存。
	//
	// `createDisposition` 只被 block-all 的探测边界判据
	// （`IsBlockAllProbeBoundary`）使用 —— 见 v25。其余路径不用它。
	// ------------------------------------------------------------------
	Action Evaluate(
		R3ShieldCore::FileOp op,
		R3ShieldCore::Event& event,
		bool blockable,
		ULONG createDisposition = 0) noexcept
	{
		// 调用方已经把 KeyPath / Flags / DesiredAccess 填好了，
		// 这里只负责决策，不 ZeroMemory —— 否则会把路径清掉。

		//
		// 对象类型必须在这里就定下来，不能等 Publish。
		//
		// Evaluate 内部可能会走 Ask（弹窗询问），而 Ask 会把 event 的内容
		// 填进共享内存槽给 UI 线程。如果此刻 ObjectType 还是 0（Registry），
		// 弹窗就会把文件操作显示成"想要修改注册表 / CreateKey"。
		// 实测确认过：Ask 时 objType=0 op=1，而 op=1 在注册表枚举里是 CreateKey。
		//
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::File);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		//
		// ★ v39：裸盘 / 物理盘（写引导区）—— 必须抢在"非文件对象"**之前**。
		//
		// 裸盘路径（`PhysicalDrive0` / `\Device\Harddisk0\DR0`）在
		// `IsNonFileObject` 眼里和管道、套接字同档 —— 都是"设备" ⇒ 会被
		// 直接 `Pass`，**连记录都没有**。但它恰恰是最该拦的一类：
		// 写它 = 改 MBR / 引导扇区（bootkit）。
		//
		// 实测绕过：样本只用 `CreateFileA("\\.\PhysicalDrive0", GENERIC_ALL)`
		// + `WriteFile` 就改掉了引导区 —— 正是卡在这一步。
		//
		// `FlagHookRawDisk` 关掉时 `rawDisk` 恒为 false ⇒ 行为退回旧版。
		const bool rawDiskHookOn =
			!policy || (policy->Flags2 & R3ShieldCore::FlagHookRawDisk) != 0;
		const bool rawDisk =
			rawDiskHookOn && R3ShieldCoreRules::IsRawDiskDevicePath(event.KeyPath);

		if (!rawDisk) {
			//
			// 第一道：根本不是文件（管道 / 套接字 / 内核设备）。
			//
			// 任何模式都彻底无视 —— 连记录都不做。这不是"放行一个文件"，
			// 而是"这个事件不属于文件监控的范畴"。实测不排除的话，
			// LOG 模式下 87 条事件里 77 条是 mojo 管道。
			//
			if (IsNonFileObject(event.KeyPath)) {
				return Action::Pass;
			}

			//
			// ★ v39：`hook_file=0` 时普通文件**完全静默**。
			//
			// `Install` 现在只要 `hook_file || hook_raw_disk` 任一开就会挂
			// 文件 hook（裸盘保护必须独立于 hook_file 才能进发布默认包）。
			// 但 `hook_file=0` 的语义是"不要文件监控"—— 所以这里得把普通
			// 文件挡回去，否则挂上 hook 会让事件日志冒出所有文件写记录，
			// 与"hook_file 关 = 零噪音"的承诺矛盾。
			//
			// 注意 `IsNonFileObject` 已经在上面处理过非磁盘对象，能走到
			// 这里的都是**卷上的普通文件**（`X:\...` / `\Device\HarddiskVolumeN`）。
			//
			if (policy && (policy->Flags & R3ShieldCore::FlagHookFile) == 0) {
				return Action::Pass;
			}
		}

		// ---- 完全拦截模式（ini: mode=block_all / block_all_safe）----
		//
		// ★ v66：**不再弹窗**（撤销 v25/v26 的"先问再拦"）。
		//
		// v25 之前这里是"一律直接拒、不弹窗"，实测后果是**正常软件写自己的
		// 配置 / 日志 / 缓存也静默失败** —— 系统弹「Windows 无法访问指定设备、
		// 路径或文件」（0xC0000022）而没有任何提示。用户报"桌面软件全打不开"。
		// v25 的解法是"改成弹窗"；v66 换成"**静默放行**"（见下面 ③）。
		//
		// 判定顺序：
		//
		//   ① 高危规则表命中（`IsHighRiskFile`）
		//        → **直接拒**。System32 / 启动目录 / hosts / 计划任务 / 驱动安装点
		//          —— 样本的落地动作全在册，连问都不问。
		//
		//   ② 诊断类**探测边界**（`IsBlockAllProbeBoundary` = 只有没有
		//      可写意图的打开 / 目录遍历）→ **直接拒**。这类操作在
		//      block-all 下没有询问的价值（"打开看看"和"写"是两件事）。
		//
		//   ③ 其余（非高危、非探测边界）→ **静默放行**。这一档是"正常软件
		//      写自己的东西"，拒它就会复现 v25 事故。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			// ① 高危：直接拒，不问。
			bool blockAllHighRisk = false;
			if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
				if (R3ShieldCoreRules::IsHighRiskFile(event.KeyPath, static_cast<ULONG>(op))) {
					blockAllHighRisk = true;
					event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
					event.Flags |= R3ShieldCore::FlagEventHighRisk;
				}
			}

			// ★ v39：裸盘写入在 block-all 下也**直接拒、不弹窗**（同 high_risk 档）。
			//   同上的理由：写引导区不该给"点一下放行"的机会。
			if (rawDisk) {
				blockAllHighRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}

			const bool probeOnly = IsBlockAllProbeBoundary(event, createDisposition);

			// ★ v66：非高危、非探测边界 → **静默放行**（原来是弹窗）。
			//
			//   这一档正是"正常软件写自己的配置 / 日志 / 缓存"。v25 的实测
			//   事故就是把它静默拒掉 ⇒ 系统弹「Windows 无法访问指定设备、
			//   路径或文件」（0xC0000022）且无提示 ⇒ 用户报"桌面软件全打不开"。
			//   一律拒 = 原样复现 v25，与"不影响程序启动"直接冲突。
			//
			//   ★ 与 v26 的降级放行**同向**：v26 已认定这一档"通道不在时
			//     放行比静默全拒更符合原意"。v66 只是把"通道不在才放行"
			//     改成"一律放行"，同时把"问"彻底去掉。
			//   ★ 安全边界不变：样本的落地动作全在 `blockAllHighRisk` 那一档
			//     （`IsHighRiskFile` + 裸盘），照样直接拒。
			if (!blockAllHighRisk && !probeOnly) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return Action::Record;
			}

			// ①② 高危 / 裸盘 / 探测边界 → 直接拒。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}


		//
		// 第二道（提前到豁免之前）：高危文件判定。
		//
		// 顺序很关键 —— 高危路径（System32、启动目录、hosts）恰好都落在
		// IsExemptDiskPath 的豁免范围内。如果先走豁免，这些必拦目标会被
		// 当成"系统目录噪音"直接放过，规则表就形同虚设。
		//
		// 所以：先判高危 → 命中就强制询问（不看 Mode、不看豁免）。
		//
		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskFile(event.KeyPath, static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		//
		// ★ v39：裸盘写入**不受 `high_risk` 开关影响**。
		//
		// 它不是"一条可调的高危规则"，而是"写引导区"这个动作本身的性质 ——
		// 关掉高危规则表（`high_risk=0`）是为了减少误报噪音，不该顺带把
		// 引导区写入也放行。
		//
		// （`IsHighRiskFile` 在 `high_risk=1` 时也会命中它，这里重复判一次
		//   只为覆盖 `high_risk=0`，代价是一次字符串前缀比较。）
		//
		if (rawDisk) {
			highRisk = true;
			event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
			event.Flags |= R3ShieldCore::FlagEventHighRisk;
		}

		//
		// 第三道：豁免的磁盘路径（系统目录 / 临时目录 / 高频缓存）。
		//
		// BLOCK / ASK → 完全放过且不记录（每秒几百条，记了淹信号）。
		// LOG        → 仍然记录，但标 ALLOW 而非 WOULD-BLOCK
		//              （LOG 模式的意义就是"先看看都发生了什么"）。
		//
		// 高危路径不走豁免，直接落到下面的询问分支。
		//
		const bool exempt = !highRisk && IsExemptDiskPath(event.KeyPath);
		if (exempt && mode != static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
			return Action::Pass;
		}

		if (!blockable) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !highRisk) {
			event.Decision = static_cast<ULONG>(exempt
				? R3ShieldCore::Decision::Allowed
				: R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		// BLOCK is intended for normal operation, so ordinary application data,
		// logs, caches, and documents remain writable. The high-risk path below
		// is the only automatic denial path in this mode.
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block) && !highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// Keep BLOCK deterministic and independent of the prompt mapping. This
		// prevents a broken cross-integrity prompt channel from masquerading as
		// a file permission failure.
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block) && highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
				InterlockedIncrement(&channel->HighRiskBlocked);
			}
			return Action::Block;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask)) {
			// ------------------------------------------------------------------
			// ★ v28：LOG 模式下"该问但问不出去" → 降级放行
			// ------------------------------------------------------------------
			//
			// 论证与注册表侧（`registry_guard.cpp` 同名分支）**逐字相同**，
			// 这里只重复要点：
			//   · `mode=log` + `high_risk=1` 时高危写**照样进这个分支**；
			//   · `Ask()` 在询问通道拿不到时**立刻返回 fallback**（`prompt_default=deny`）
			//     → 下面把 deny 当"用户拒绝" → `Action::Block` → 调用方
			//     `return STATUS_ACCESS_DENIED` → 用户看到
			//     「Windows 无法访问指定设备、路径或文件」(0xC0000022) **且无弹窗**；
			//   · 触发条件：引擎**以管理员启动** → 跨完整性 / UIPI / 会话边界
			//     → 被注入进程打不开询问通道 → `IsOpen() == false`；
			//   · `mode=log` 承诺"只记录、全部放行"，静默拒直接违背它；
			//   · v26 只修了 block_all 分支，漏了这条。
			//
			// ★ 安全边界不降：**仅 LOG 模式**降级；BLOCK/ASK 是用户明确的
			//   "要拦 / 要问"，通道坏了也不该放行。
			const bool promptAvailable = R3ShieldCorePrompt::IsOpen();

			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !promptAvailable) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
				return Action::Record;
			}

			// Ask 需要进程/线程/时间做展示和去重。
			event.ProcessId = GetCurrentProcessId();
			event.ThreadId = GetCurrentThreadId();
			event.TimeStamp = NowFileTime();

			if (highRisk) {
				// 计数器必须写在 Events 通道头里 —— Policy 是只读映射。
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskAsked);
				}
			}

			R3ShieldCore::Verdict verdict = R3ShieldCorePrompt::Ask(event, PromptFallbackVerdict());

			if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return Action::Record;
			}

			// ★ v28：通道在"调用中失效"（引擎退出）→ LOG 模式同样降级放行。
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !R3ShieldCorePrompt::IsOpen()) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			if (highRisk) {
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
			}
			return Action::Block;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
		return Action::Record;
	}

	// ==================================================================
	// hook
	//
	// 每个 hook 都是同一副骨架：
	//   InterlockedIncrement(在飞计数)
	//   __try { 组 event + 判定 } __except { 放行 }
	//   Block → 直接返回 STATUS_ACCESS_DENIED，不调原函数
	//   否则 → 调原函数，按结果补全状态和路径，Record 时上报
	//   InterlockedDecrement(在飞计数)
	//
	// 注意：函数体内不放需要析构的对象（否则撞 C2712，__try 不能和
	// 需要展开的对象共存）。
	// ==================================================================

	NTSTATUS NTAPI NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
		const FG_OBJECT_ATTRIBUTES* ObjectAttributes, FG_IO_STATUS_BLOCK* IoStatusBlock,
		PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
		ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::FileOp::Create);
			event.DesiredAccess = DesiredAccess;

			if (ObjectAttributes && ObjectAttributes->ObjectName) {
				CopyUnicodeString(ObjectAttributes->ObjectName, event.KeyPath,
					static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars), event.KeyPathLength);
				NormalizeFilePath(event.KeyPath, static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars));
				event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
			}

			if (IsCreateDisposition(CreateDisposition)) {
				event.Flags |= R3ShieldCore::FlagEventCreate;
			}
			if (IsOverwriteDisposition(CreateDisposition)) {
				event.Flags |= R3ShieldCore::FlagEventOverwrite;
			}

			action = IsWriteIntent(DesiredAccess, CreateDisposition)
				? Evaluate(R3ShieldCore::FileOp::Create, event, true, CreateDisposition)
				: Action::Pass;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
				IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
				CreateDisposition, CreateOptions, EaBuffer, EaLength);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtOpenFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
		const FG_OBJECT_ATTRIBUTES* ObjectAttributes, FG_IO_STATUS_BLOCK* IoStatusBlock,
		ULONG ShareAccess, ULONG OpenOptions)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::FileOp::Open);
			event.DesiredAccess = DesiredAccess;

			if (ObjectAttributes && ObjectAttributes->ObjectName) {
				CopyUnicodeString(ObjectAttributes->ObjectName, event.KeyPath,
					static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars), event.KeyPathLength);
				NormalizeFilePath(event.KeyPath, static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars));
				event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
			}

			// NtOpenFile 本身不创建，disposition 恒为 FILE_OPEN。
			action = IsWriteIntent(DesiredAccess, FILE_OPEN)
				? Evaluate(R3ShieldCore::FileOp::Open, event, true, FILE_OPEN)
				: Action::Pass;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
				IoStatusBlock, ShareAccess, OpenOptions);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtWriteFile_Hook(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
		PVOID ApcContext, FG_IO_STATUS_BLOCK* IoStatusBlock, PVOID Buffer,
		ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::FileOp::Write);
			event.DesiredAccess = FILE_WRITE_DATA;
			CaptureHandlePath(FileHandle, event);

			// 写句柄是更高层的动作，语义明确，直接判。
			action = Evaluate(R3ShieldCore::FileOp::Write, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
				IoStatusBlock, Buffer, Length, ByteOffset, Key);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	//
	// NtSetInformationFile 是文件这边最关键的一个 hook：
	// 删除、改名、截断、改时间戳全都走它，靠 FileInformationClass 区分。
	//
	// 之前这三个动作分别对应 MoveFile / DeleteFile / SetFileTime 这些
	// Win32 API，但它们**全部**收敛到这一个 Nt 调用上。
	// 只挂这一个就等于同时覆盖了文件的改名、删除、时间戳伪造。
	//
	NTSTATUS NTAPI NtSetInformationFile_Hook(HANDLE FileHandle, FG_IO_STATUS_BLOCK* IoStatusBlock,
		PVOID FileInformation, ULONG Length, ULONG FileInformationClass)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			R3ShieldCore::FileOp op = R3ShieldCore::FileOp::SetBasicInfo;
			bool blockable = true;

			switch (FileInformationClass) {
			case FileDispositionInformation:
			case FileDispositionInformationEx:
				op = R3ShieldCore::FileOp::Delete;
				break;
			case FileRenameInformation:
			case FileRenameInformationEx:
				op = R3ShieldCore::FileOp::Rename;
				break;
			case FileEndOfFileInformation:
				op = R3ShieldCore::FileOp::Truncate;
				break;
			case FileBasicInformation:
				// 改时间戳/属性。这是典型的"反取证"动作（把最后写入时间
				// 抹回原始值），但要拦就得拦，只是它也确实常被正常程序用。
				op = R3ShieldCore::FileOp::SetBasicInfo;
				break;
			default:
				// 其他 information class（位置、模式、压缩、校验和……）
				// 太杂且大多无害，只记录不拦。
				op = R3ShieldCore::FileOp::SetBasicInfo;
				blockable = false;
				break;
			}

			event.Op = static_cast<ULONG>(op);
			CaptureHandlePath(FileHandle, event);

			// 改名的话，新名字在 FileInformation 里（FileNameInformation
			// 结构的 FileName 字段），挪进 ValueName 槽展示。
			if (op == R3ShieldCore::FileOp::Rename && FileInformation && Length >= sizeof(ULONG)) {
				auto* rename = static_cast<FILE_RENAME_INFORMATION_LOCAL*>(FileInformation);
				ULONG chars = rename->FileNameLength / sizeof(WCHAR);
				if (chars >= R3ShieldCore::MaxValueNameChars) {
					chars = static_cast<ULONG>(R3ShieldCore::MaxValueNameChars) - 1;
				}
				if (chars > 0) {
					memcpy(event.ValueName, rename->FileName, chars * sizeof(WCHAR));
					event.ValueName[chars] = L'\0';
					// 新名字也可能是 \??\C:\... 形式，同样要归一化，
					// 否则日志里会一半干净一半带前缀。
					NormalizeFilePath(event.ValueName, static_cast<ULONG>(R3ShieldCore::MaxValueNameChars));
					event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
				}
			}

			action = Evaluate(op, event, blockable);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtSetInformationFile(FileHandle, IoStatusBlock,
				FileInformation, Length, FileInformationClass);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtSetSecurityObject_Hook(HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
		PSECURITY_DESCRIPTOR SecurityDescriptor)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::FileOp::SetSecurity);
			event.DesiredAccess = SecurityInformation;
			CaptureHandlePath(Handle, event);
			action = Evaluate(R3ShieldCore::FileOp::SetSecurity, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtSetEaFile_Hook(HANDLE FileHandle, FG_IO_STATUS_BLOCK* IoStatusBlock,
		PVOID Buffer, ULONG Length)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::FileOp::SetEa);
			CaptureHandlePath(FileHandle, event);
			action = Evaluate(R3ShieldCore::FileOp::SetEa, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtSetEaFile(FileHandle, IoStatusBlock, Buffer, Length);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
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
				LOG(L"FileGuard: ntdll 缺少导出 %S", functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"FileGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"FileGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace FileGuard
{
	int HookCount() noexcept
	{
		return g_hookCount;
	}

	bool OwnsNtSetSecurityObjectHook() noexcept
	{
		return g_ownsNtSetSecurityObjectHook;
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"FileGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	bool Install(HANDLE engineProcess) noexcept
	{
		if (g_installed) {
			return true;
		}

		//
		// 排除判定复用 RegistryGuard 的结果。
		//
		// 两边判的是同一件事（这个进程要不要监控），分开算只会引入
		// 不一致的风险。RegistryGuard 在 Install 时已经把通道开好、
		// 把 g_bypass 算完，这里直接问它。
		//
		// 顺序约束：customization_session 必须**先** Install
		// RegistryGuard、再 Install FileGuard。见那边的注释。
		//
		if (RegistryGuard::IsBypassed()) {
			g_bypass = true;
			g_installed = true;
			return true;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();

		//
		// 文件 hook 默认关：文件系统比注册表热得多，挂了就是几千条/秒。
		//
		// ★ v39：裸盘监控（`hook_raw_disk`，默认开）**独立于** `hook_file` ——
		//    任一开就装 hook。理由：发布默认包是 `hook_file=0`，如果裸盘保护
		//    挂在 `hook_file` 下面，它在发布默认配置里**永远不会生效**
		//    （真实绕过正是发生在这个配置下）。
		//
		//    而 `hook_file=0` 时"不要文件噪音"的承诺由 `Evaluate` 兜住：
		//    它对普通文件直接 `Pass`，只保留裸盘这一条通道。
		//
		const bool fileHookOn =
			policy && (policy->Flags & R3ShieldCore::FlagHookFile) != 0;
		const bool rawDiskHookOn =
			policy && (policy->Flags2 & R3ShieldCore::FlagHookRawDisk) != 0;

		if (!policy || (!fileHookOn && !rawDiskHookOn)) {
			g_bypass = true;
			g_installed = true;
			LOG(L"FileGuard: hook_file / hook_raw_disk 均未开启，本进程不挂文件 hook");
			return true;
		}

		LOG(L"FileGuard: 挂载中 (file=%d rawdisk=%d, pid=%u)",
			fileHookOn ? 1 : 0, rawDiskHookOn ? 1 : 0, GetCurrentProcessId());

		g_bypass = false;

		HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
		if (ntdll) {
			pOriginalNtQueryObject =
				reinterpret_cast<NtQueryObjectPtr>(GetProcAddress(ntdll, "NtQueryObject"));
		}

		// 写类：可拦截。前三个是核心（建/写/删改），后面的是补充覆盖。
		QueueHook("NtCreateFile", reinterpret_cast<LPVOID>(NtCreateFile_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtCreateFile), true);
		QueueHook("NtWriteFile", reinterpret_cast<LPVOID>(NtWriteFile_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtWriteFile), true);
		QueueHook("NtSetInformationFile", reinterpret_cast<LPVOID>(NtSetInformationFile_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtSetInformationFile), true);

		// NtOpenFile 不是所有系统版本都导出（Win7 有，更早的不确定），
		// 而且它的作用被 NtCreateFile(FILE_OPEN) 覆盖，按非必需挂。
		QueueHook("NtOpenFile", reinterpret_cast<LPVOID>(NtOpenFile_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtOpenFile), false);

		// 改 ACL / 改扩展属性：可选覆盖。
		const int hooksBeforeSecurityObject = g_hookCount;
		QueueHook("NtSetSecurityObject", reinterpret_cast<LPVOID>(NtSetSecurityObject_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtSetSecurityObject), false);
		g_ownsNtSetSecurityObjectHook = g_hookCount > hooksBeforeSecurityObject;
		QueueHook("NtSetEaFile", reinterpret_cast<LPVOID>(NtSetEaFile_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtSetEaFile), false);

		g_installed = true;

		LOG(L"FileGuard: 已挂载 %d 个文件 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
