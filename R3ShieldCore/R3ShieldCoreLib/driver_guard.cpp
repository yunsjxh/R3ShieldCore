#include "stdafx.h"
#include "driver_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

// WIN32_LEAN_AND_MEAN 把 winsvc.h 排除掉了，服务 API 的常量/结构体得自己引。
#include <winsvc.h>

//
// 内核驱动监控层。
//
// 与前面几个 guard 同一套骨架。这里的特殊之处全在**路径还原**上。
//
// ==================================================================
// ⚠️ 为什么不能只挂 NtLoadDriver（2026-09-25 实测踩到）
// ==================================================================
//
// Windows 上驱动加载的正常路径是：
//
//   应用 Ksword5.1.exe
//     → advapi32!CreateServiceW          ← 调用方是应用（我们能 hook）
//     → RPC(\pipe\ntsvcs)
//     → services.exe (SCM)
//          ├─ 写 HKLM\SYSTEM\CurrentControlSet\Services\<名>   ← 写的人不是应用
//          └─ 调 NtLoadDriver                                  ← 调的人不是应用
//
// 也就是说 **写服务键和调 NtLoadDriver 都发生在 services.exe 里**，而
// services.exe 是 C:\Windows\System32\services.exe → 命中 ComputeBypass 的
// %SystemRoot%\ 规则 → **一个 hook 都不挂**。
//
// 实测后果：全拦模式（block_all）下驱动服务照样装成功，而自家日志里
// DRV 事件 0 条、连服务键的 CreateKey 都没有。系统事件日志（SCM 7045）
// 才是唯一能看到它的地方。
//
// 所以本 guard 挂**两组** hook：
//   ① ntdll!NtLoadDriver / NtUnloadDriver —— 只在调用方不在白名单时有效；
//   ② advapi32!CreateServiceW / ChangeServiceConfigW / StartServiceW ——
//      **补 SCM 盲区的主力**，调用方就是那个不受信任的应用。
//
// 残余盲区（补了也拦不到，写在文档里别让人误以为全覆盖）：
//   · 用 System32 里的 LOLBin 装（sc.exe / powershell.exe / cmd.exe 都在
//     %SystemRoot%\ 下 → bypass）。要么把白名单收窄，要么上内核；
//   · 直调 RPC / \Device\NtControlPipe；
//   · 内核态 ZwLoadDriver —— 真边界要 PsSetLoadImageNotifyRoutine。
//
// ==================================================================
// 路径还原
// ==================================================================
//
// ① NtLoadDriver 的入参是一段**注册表路径**：
//     \Registry\Machine\System\CurrentControlSet\Services\MyDrv
//   它不是文件路径。要判"这个驱动从哪加载"，得去读那个服务键的
//   ImagePath 值，再把它解析成真正的 .sys 文件路径。
//
//   ImagePath 有四形态，必须逐个处理：
//     1. \SystemRoot\System32\drivers\x.sys   ← 最常见
//     2. \??\C:\path\x.sys                    ← 绝对 DOS 路径
//     3. system32\drivers\x.sys               ← 相对 %SystemRoot%
//     4. C:\path\x.sys                        ← 已经是 DOS 路径
//
//   解析不出来就退化成"用服务名判"—— 拿不到路径时按高危处理更安全。
//
// ② 服务 API 的 lpBinaryPathName 形态更多，还带引号和环境变量：
//     "%SystemRoot%\system32\drivers\x.sys"
//     "C:\Program Files\Foo\svc.exe" -k run
//     C:\Program Files\Foo\svc.exe           ← 没引号、路径里有空格
//   所以要先展开环境变量、再去引号/去参数，最后交给同一套 ResolveImagePath。
//
// 为什么不直接读文件：NtLoadDriver 调用时驱动还没加载，磁盘上的 .sys
// 是待加载的源文件，读它的路径就是我们要的信息。
//
namespace
{
	// NtLoadDriver / NtUnloadDriver 都吃 UNICODE_STRING 指针。
	struct DG_UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

	typedef NTSTATUS(NTAPI* NtLoadDriverPtr)(const DG_UNICODE_STRING*);
	typedef NTSTATUS(NTAPI* NtUnloadDriverPtr)(const DG_UNICODE_STRING*);

	// advapi32 服务 API。参数列表必须和 winsvc.h 完全一致，否则栈会错位。
	typedef SC_HANDLE(WINAPI* CreateServiceWPtr)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD,
		DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
	typedef BOOL(WINAPI* ChangeServiceConfigWPtr)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR,
		LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
	typedef BOOL(WINAPI* StartServiceWPtr)(SC_HANDLE, DWORD, LPCWSTR*);
	typedef BOOL(WINAPI* QueryServiceConfigWPtr)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);

	NtLoadDriverPtr pOriginalNtLoadDriver = nullptr;
	NtUnloadDriverPtr pOriginalNtUnloadDriver = nullptr;
	CreateServiceWPtr pOriginalCreateServiceW = nullptr;
	ChangeServiceConfigWPtr pOriginalChangeServiceConfigW = nullptr;
	StartServiceWPtr pOriginalStartServiceW = nullptr;

	// 这个只用来**查**，不挂 hook。
	QueryServiceConfigWPtr pOriginalQueryServiceConfigW = nullptr;

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
	// 路径还原
	// ------------------------------------------------------------------

	// \Registry\Machine\... → 可读的注册表路径（保留原样即可，够用）。
	void CopyUnicodeString(const DG_UNICODE_STRING* source, WCHAR* destination,
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

	// 把驱动服务名（\Registry\...\Services\X）取出来。
	// 拿不到返回 false。
	bool ServiceNameFromRegistryPath(PCWSTR registryPath, WCHAR* name, size_t cch) noexcept
	{
		if (!registryPath || !name || cch == 0) {
			return false;
		}

		name[0] = L'\0';

		// 找最后一个 Services\ 之后的段。
		PCWSTR marker = nullptr;
		for (PCWSTR p = registryPath; *p; p++) {
			if (_wcsnicmp(p, L"Services\\", 9) == 0) {
				marker = p + 9;
			}
		}

		if (!marker || !*marker) {
			// 没有 Services\ 段 —— 也许调用方直接给了服务名。
			const bool looksLikePath = (wcschr(registryPath, L'\\') != nullptr);
			if (!looksLikePath) {
				wcsncpy_s(name, cch, registryPath, _TRUNCATE);
				return true;
			}
			return false;
		}

		// 服务名到下一个 \ 或结尾为止。
		size_t n = 0;
		while (marker[n] && marker[n] != L'\\' && n + 1 < cch) {
			name[n] = marker[n];
			n++;
		}
		name[n] = L'\0';
		return n > 0;
	}

	// 把 ImagePath 解析成 DOS 路径。解析不了返回空。
	//
	//   形态 1/3 需要 %SystemRoot% → C:\Windows
	void ResolveImagePath(PCWSTR imagePath, WCHAR* out, size_t cch) noexcept
	{
		if (!imagePath || !out || cch == 0) {
			return;
		}

		out[0] = L'\0';

		WCHAR systemRoot[R3ShieldCore::MaxImagePathChars] = {};
		DWORD rootLength = GetWindowsDirectory(systemRoot, _countof(systemRoot));
		if (rootLength == 0) {
			return;
		}

		// 形态 2：\??\C:\... → 去掉前缀就是 DOS 路径。
		if (wcsncmp(imagePath, L"\\??\\", 4) == 0) {
			wcsncpy_s(out, cch, imagePath + 4, _TRUNCATE);
			return;
		}

		// 形态 1：\SystemRoot\... → %SystemRoot%\...
		if (_wcsnicmp(imagePath, L"\\SystemRoot\\", 12) == 0) {
			swprintf_s(out, cch, L"%s\\%s", systemRoot, imagePath + 12);
			return;
		}

		// 形态 4：已经是盘符绝对路径。
		if (imagePath[1] == L':') {
			wcsncpy_s(out, cch, imagePath, _TRUNCATE);
			return;
		}

		// 形态 3：相对 %SystemRoot% 的路径（如 system32\drivers\x.sys）。
		if (imagePath[0] != L'\\') {
			swprintf_s(out, cch, L"%s\\%s", systemRoot, imagePath);
			return;
		}

		// 其他 \ 开头但不是 SystemRoot / ?? 的：无法可靠解析，
		// 保留原样，让"非系统目录"规则兜住。
		wcsncpy_s(out, cch, imagePath, _TRUNCATE);
	}

	// 从服务注册表键里读 ImagePath。
	// 拿不到就返回空（此时会退化用服务名判，按高危处理）。
	void ReadServiceImagePath(PCWSTR serviceName, WCHAR* out, size_t cch) noexcept
	{
		if (!serviceName || !serviceName[0] || !out || cch == 0) {
			return;
		}

		out[0] = L'\0';

		WCHAR keyPath[R3ShieldCore::MaxKeyPathChars] = {};
		if (swprintf_s(keyPath, L"SYSTEM\\CurrentControlSet\\Services\\%s", serviceName) < 0) {
			return;
		}

		//
		// 用 advapi32 的 RegGetValue 直接读 —— 它内部走 NtOpenKey/QueryValueKey，
		// 而我们的 registry hook 只拦写操作，读不影响，不会递归回自己。
		//
		WCHAR value[R3ShieldCore::MaxKeyPathChars] = {};
		DWORD size = sizeof(value);
		DWORD type = 0;
		if (RegGetValue(HKEY_LOCAL_MACHINE, keyPath, L"ImagePath",
				RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ, &type, value, &size) != ERROR_SUCCESS) {
			return;
		}

		// REG_EXPAND_SZ 里可能有 %SystemRoot% 之类的环境变量，展开一下。
		WCHAR expanded[R3ShieldCore::MaxKeyPathChars] = {};
		if (type == REG_EXPAND_SZ) {
			DWORD result = ExpandEnvironmentStrings(value, expanded, _countof(expanded));
			if (result > 0 && result <= _countof(expanded)) {
				wcsncpy_s(value, expanded, _TRUNCATE);
			}
		}

		ResolveImagePath(value, out, cch);
	}

	// 把服务 API 的 lpBinaryPathName / ImagePath 值归一化成 DOS 路径。
	//
	// 形态（比 NtLoadDriver 那条路脏得多）：
	//   "%SystemRoot%\system32\drivers\x.sys"     ← 带引号 + 环境变量
	//   "C:\Program Files\Foo\svc.exe" -k run     ← 带引号 + 命令行参数
	//   C:\Program Files\Foo\svc.exe              ← 无引号但路径里有空格
	//   \??\C:\path\x.sys                         ← 内核风格前缀
	//   system32\drivers\x.sys                    ← 相对 %SystemRoot%
	//
	// 步骤：展开环境变量 → 去引号/去参数 → 交给 ResolveImagePath。
	void NormalizeServiceBinaryPath(PCWSTR source, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch == 0) {
			return;
		}

		out[0] = L'\0';

		if (!source || !source[0]) {
			return;
		}

		WCHAR expanded[R3ShieldCore::MaxImagePathChars] = {};
		DWORD expandedLength = ExpandEnvironmentStrings(source, expanded, _countof(expanded));
		if (expandedLength == 0 || expandedLength > _countof(expanded)) {
			// 展开失败（含缓冲区不够）：原样用，别丢信息。
			wcsncpy_s(expanded, source, _TRUNCATE);
		}

		PCWSTR begin = expanded;
		while (*begin == L' ' || *begin == L'\t') {
			begin++;
		}

		WCHAR trimmed[R3ShieldCore::MaxImagePathChars] = {};

		if (*begin == L'"') {
			// 引号形式：取到下一个引号为止（引号之后是参数，丢掉）。
			begin++;
			size_t i = 0;
			while (begin[i] && begin[i] != L'"' && i + 1 < _countof(trimmed)) {
				trimmed[i] = begin[i];
				i++;
			}
			trimmed[i] = L'\0';
		}
		else {
			// 无引号：默认整串都是路径（路径里可能有空格）。
			// 只有"第一个空格之前确实以 .sys/.exe/.dll 结尾"时才把空格之后
			// 当参数丢掉 —— 否则 C:\Program Files\Foo\svc.exe 会被截成
			// C:\Program，把判定方向搞反。
			size_t take = wcslen(begin);
			if (PCWSTR space = wcschr(begin, L' ')) {
				const size_t headLength = static_cast<size_t>(space - begin);
				constexpr size_t suffixLength = 4; // ".sys" / ".exe" / ".dll"
				if (headLength > suffixLength &&
					(_wcsnicmp(space - suffixLength, L".sys", suffixLength) == 0 ||
					 _wcsnicmp(space - suffixLength, L".exe", suffixLength) == 0 ||
					 _wcsnicmp(space - suffixLength, L".dll", suffixLength) == 0)) {
					take = headLength;
				}
			}

			if (take >= _countof(trimmed)) {
				take = _countof(trimmed) - 1;
			}

			wcsncpy_s(trimmed, begin, take);
		}

		if (trimmed[0] == L'\0') {
			return;
		}

		ResolveImagePath(trimmed, out, cch);
	}

	// 从服务句柄查"服务类型 + 二进制路径"。
	//
	// StartServiceW / ChangeServiceConfigW 的入参里可能没有类型或路径
	// （传 SERVICE_NO_CHANGE / NULL 表示"不改"），得从现有配置补。
	//
	// ⚠️ 这里调的是**原函数**（pOriginalQueryServiceConfigW），不是 hook ——
	//    我们只挂 Create/Change/Start，Query 不挂，所以不会递归回自己。
	//    注意别 CloseServiceHandle：句柄是调用方的，不归我们。
	bool QueryServiceInfo(SC_HANDLE service, DWORD& serviceType, WCHAR* path, size_t pathCch,
		WCHAR* displayName, size_t displayCch) noexcept
	{
		serviceType = 0;

		if (path && pathCch) {
			path[0] = L'\0';
		}

		if (displayName && displayCch) {
			displayName[0] = L'\0';
		}

		if (!service || !pOriginalQueryServiceConfigW) {
			return false;
		}

		DWORD needed = 0;
		pOriginalQueryServiceConfigW(service, nullptr, 0, &needed);

		// 失败时 needed 给的是所需字节数；给 0 或离谱的大值就当失败。
		if (needed == 0 || needed > sizeof(QUERY_SERVICE_CONFIGW) + 64 * 1024) {
			return false;
		}

		// QueryServiceConfigW 要"结构体 + 追加字符串"的连续空间，结构体里有
		// 指针，必须按指针宽度对齐 —— 所以用 alignas 的字节数组，不用 WCHAR 数组。
		alignas(QUERY_SERVICE_CONFIGW) BYTE buffer[8192] = {};
		if (needed > sizeof(buffer)) {
			return false;
		}

		DWORD written = 0;
		if (!pOriginalQueryServiceConfigW(service,
				reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer), sizeof(buffer), &written)) {
			return false;
		}

		auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer);
		serviceType = config->dwServiceType;

		if (path && pathCch && config->lpBinaryPathName && config->lpBinaryPathName[0]) {
			NormalizeServiceBinaryPath(config->lpBinaryPathName, path, pathCch);
		}

		// 服务**键名**在 QUERY_SERVICE_CONFIGW 里没有，只有显示名 ——
		// 显示名对日志/弹窗来说够用（服务名拿不到就算了，不额外做 RPC）。
		if (displayName && displayCch && config->lpDisplayName && config->lpDisplayName[0]) {
			wcsncpy_s(displayName, displayCch, config->lpDisplayName, _TRUNCATE);
		}

		return true;
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Driver);
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

	// 这个 op 是不是"服务类操作"（advapi32 那一组）。
	bool IsServiceOp(R3ShieldCore::DriverOp op) noexcept
	{
		return op == R3ShieldCore::DriverOp::CreateService ||
			op == R3ShieldCore::DriverOp::ChangeServiceConfig ||
			op == R3ShieldCore::DriverOp::StartService;
	}

	// kernelDriverService：这次操作针对的是不是**内核驱动服务**
	// （SERVICE_KERNEL_DRIVER / SERVICE_FILE_SYSTEM_DRIVER）。
	// NtLoadDriver / NtUnloadDriver 传 true —— 它们只可能是驱动。
	Action Evaluate(R3ShieldCore::DriverOp op, R3ShieldCore::Event& event, PCWSTR driverPath,
		bool blockable, bool kernelDriverService) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Driver);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all）----
		//
		// 探测范围内一律拒绝：不判豁免、不判高危、不弹窗。
		// 能走到这里的操作都已经被更早的"探测边界"判定为"被探测到的"
		// （非文件对象、没开 hook 的只读打开、不被注入的进程都在前面返回了），
		// 所以这里不再做任何区分。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskDriverLoad(driverPath, static_cast<ULONG>(op),
					kernelDriverService)) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		// ---- 非高危的 Win32 服务操作：不上报 ----
		//
		// 装/改/启 Win32 服务是安装器、运维脚本的日常动作（"装个服务"本身
		// 完全合法），逐个上报会把日志刷爆，而它们对我们关心的"驱动"没有
		// 信息量。所以只有**内核驱动服务**（上面那档规则）或命中高危规则
		// （二进制落在用户可写目录）才继续走判定。
		//
		// ⚠️ 注意位置：放在 BlockAll 短路**之后** —— 全拦模式下这些照样被拒，
		//    这里只决定"平时记不记"。
		if (IsServiceOp(op) && !kernelDriverService && !highRisk) {
			return Action::Pass;
		}

		if (!blockable) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		//
		// ⚠️ 能不能弹窗：★ 注意 `main.cpp:99` 已改成**无条件**建询问通道 +
		//    UI 线程（原意是支持"运行期切 ASK"），所以下面那句"UI 线程只在
		//    ASK 模式启动"**是过时的** —— 同会话、同完整性级别下 LOG 模式
		//    其实也有 UI。保留原文只为说明"当初为什么会踩这个坑"。
		//
		//    ★ 但**语义矛盾仍在**：询问通道**拿不到**时（引擎以管理员启动 →
		//    跨完整性级别 / UIPI / 会话边界 → 被注入进程 OpenFileMapping 失败），
		//    `R3ShieldCorePrompt::Ask` 会**立刻**返回 fallback(deny) —— 于是
		//    "LOG 模式却把操作拦了"，和 ini 里写的"log = 只记录、全部放行"
		//    直接矛盾。v26 在 block_all 分支、v28 在常规分支各补了一层
		//    `IsOpen()` 前置探测 + 降级放行（打 `[ASK-UNAVAIL→ALLOW]`）。
		//
		//    同一类 bug 在 process/thread guard 里最早修过（加了 allowAsk
		//    参数），driver guard 当时漏了；后来 registry/file 的**常规分支**
		//    也漏了（v26 只补了 block_all，v28 才补齐）。**凡"Ask 分支"都要
		//    过一遍"通道不在时算什么"，一个都不能漏。**
		//
		const bool canAsk = (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask));

		if (highRisk && !canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				// LOG 模式：只记录，放行。
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}

			// BLOCK 模式：高危没有放行的理由，直接拦。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
				InterlockedIncrement(&channel->HighRiskBlocked);
			}
			return Action::Block;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		// With the high-risk rules disabled, BLOCK still remains usable: an
		// unresolved or otherwise ordinary service operation is recorded and
		// allowed instead of becoming a blanket service-killer.
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block) && !highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask) || highRisk) {
			event.ProcessId = GetCurrentProcessId();
			event.ThreadId = GetCurrentThreadId();
			event.TimeStamp = NowFileTime();

			if (highRisk) {
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskAsked);
				}
			}

			// ★ v29：走"通道可用性"包装。ASK 模式 + 通道不可用 → 保持原语义
			//   （按 fallback 拒），但会打上可识别的标记；LOG 模式降级放行。
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

	// 组装事件：KeyPath 放解析出来的 .sys 路径，ValueName 放服务名。
	// 解析不出路径时 KeyPath 退化成服务注册表路径，保证事件总有内容可看。
	void BuildEvent(R3ShieldCore::Event& event, PCWSTR registryPath, PCWSTR serviceName) noexcept
	{
		WCHAR imagePath[R3ShieldCore::MaxKeyPathChars] = {};
		ReadServiceImagePath(serviceName, imagePath, _countof(imagePath));

		if (imagePath[0]) {
			wcsncpy_s(event.KeyPath, imagePath, _TRUNCATE);
		}
		else {
			// 拿不到 ImagePath：把服务注册表路径当目标展示。
			wcsncpy_s(event.KeyPath, registryPath, _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (serviceName && serviceName[0]) {
			wcsncpy_s(event.ValueName, serviceName, _TRUNCATE);
			event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		}
	}

	// 服务类事件的组装：KeyPath = 归一化后的二进制路径，ValueName = 服务名。
	// 与 BuildEvent 同一套字段约定（日志侧 `driver=` / `service=`），
	// 区别只是路径来自调用方入参而不是去读服务键。
	void BuildServiceEvent(R3ShieldCore::Event& event, PCWSTR binaryPath, PCWSTR serviceName) noexcept
	{
		if (binaryPath && binaryPath[0]) {
			wcsncpy_s(event.KeyPath, binaryPath, _TRUNCATE);
		}

		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (serviceName && serviceName[0]) {
			wcsncpy_s(event.ValueName, serviceName, _TRUNCATE);
			event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		}
	}

	// ==================================================================
	// hook
	// ==================================================================
	NTSTATUS NTAPI NtLoadDriver_Hook(const DG_UNICODE_STRING* DriverServiceName)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		WCHAR registryPath[R3ShieldCore::MaxKeyPathChars] = {};
		WCHAR serviceName[128] = {};

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::DriverOp::Load);
			event.Flags |= R3ShieldCore::FlagEventDriverLoad;

			CopyUnicodeString(DriverServiceName, registryPath,
				static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars), event.KeyPathLength);
			registryPath[R3ShieldCore::MaxKeyPathChars - 1] = L'\0';
			event.KeyPathLength = static_cast<ULONG>(wcslen(registryPath));

			ServiceNameFromRegistryPath(registryPath, serviceName, _countof(serviceName));
			BuildEvent(event, registryPath, serviceName);

			// NtLoadDriver 只可能是驱动，kernelDriverService 恒为 true。
			action = Evaluate(R3ShieldCore::DriverOp::Load, event, event.KeyPath, true, true);
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
			status = pOriginalNtLoadDriver(DriverServiceName);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtUnloadDriver_Hook(const DG_UNICODE_STRING* DriverServiceName)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		WCHAR registryPath[R3ShieldCore::MaxKeyPathChars] = {};
		WCHAR serviceName[128] = {};

		__try {
			event.Op = static_cast<ULONG>(R3ShieldCore::DriverOp::Unload);

			CopyUnicodeString(DriverServiceName, registryPath,
				static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars), event.KeyPathLength);
			registryPath[R3ShieldCore::MaxKeyPathChars - 1] = L'\0';
			event.KeyPathLength = static_cast<ULONG>(wcslen(registryPath));

			ServiceNameFromRegistryPath(registryPath, serviceName, _countof(serviceName));
			BuildEvent(event, registryPath, serviceName);

			action = Evaluate(R3ShieldCore::DriverOp::Unload, event, event.KeyPath, true, true);
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
			status = pOriginalNtUnloadDriver(DriverServiceName);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// advapi32 服务 API（补 SCM 盲区，ABI v9）
	//
	// 这三个 hook 的意义见文件头的长注释：驱动加载的实际执行者是
	// services.exe（在白名单里），所以必须在**调用方一侧**判。
	// ==================================================================

	// 服务类型里有没有"内核驱动"位。
	bool IsKernelDriverType(DWORD serviceType) noexcept
	{
		return (serviceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
	}

	// 二进制路径拿不到时的兜底：用服务名当"路径"参与判定。
	// 服务名里不会含 \Windows\System32\drivers\，所以内核驱动服务会被
	// 判成高危 —— 拿不到证据时按高危处理更安全。
	void FallbackToServiceName(WCHAR* path, size_t cch, PCWSTR serviceName) noexcept
	{
		if (path[0] != L'\0' || !serviceName || !serviceName[0]) {
			return;
		}

		wcsncpy_s(path, cch, serviceName, _TRUNCATE);
	}

	// CreateServiceW —— 装服务。**最关键的一个**：驱动服务就是这么装上的。
	SC_HANDLE WINAPI CreateServiceW_Hook(
		SC_HANDLE scManager,
		LPCWSTR serviceName,
		LPCWSTR displayName,
		DWORD desiredAccess,
		DWORD serviceType,
		DWORD startType,
		DWORD errorControl,
		LPCWSTR binaryPathName,
		LPCWSTR loadOrderGroup,
		LPDWORD tagId,
		LPCWSTR dependencies,
		LPCWSTR serviceStartName,
		LPCWSTR password)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		SC_HANDLE result = nullptr;

		__try {
			const bool kernelDriver = IsKernelDriverType(serviceType);

			event.Op = static_cast<ULONG>(R3ShieldCore::DriverOp::CreateService);
			event.Flags |= R3ShieldCore::FlagEventServiceInstall;
			if (kernelDriver) {
				event.Flags |= R3ShieldCore::FlagEventKernelDriver;
			}

			WCHAR driverPath[R3ShieldCore::MaxKeyPathChars] = {};
			NormalizeServiceBinaryPath(binaryPathName, driverPath, _countof(driverPath));
			FallbackToServiceName(driverPath, _countof(driverPath), serviceName);

			BuildServiceEvent(event, driverPath, serviceName);
			action = Evaluate(R3ShieldCore::DriverOp::CreateService, event, event.KeyPath, true,
				kernelDriver);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		else {
			result = pOriginalCreateServiceW(scManager, serviceName, displayName, desiredAccess,
				serviceType, startType, errorControl, binaryPathName, loadOrderGroup, tagId,
				dependencies, serviceStartName, password);

			if (action == Action::Record) {
				event.Status = result ? 0 : static_cast<ULONG>(GetLastError());
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ChangeServiceConfigW —— 改已有服务的配置（含把 ImagePath 指到别的 .sys，
	// 以及把类型从 Win32 服务改成内核驱动）。这两个都是典型的劫持手法。
	BOOL WINAPI ChangeServiceConfigW_Hook(
		SC_HANDLE service,
		DWORD serviceType,
		DWORD startType,
		DWORD errorControl,
		LPCWSTR binaryPathName,
		LPCWSTR loadOrderGroup,
		LPDWORD tagId,
		LPCWSTR dependencies,
		LPCWSTR serviceStartName,
		LPCWSTR password,
		LPCWSTR displayName)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		BOOL result = FALSE;

		__try {
			// 只在**真的改了危险项**时才判：
			//   · binaryPathName 非空 → 改二进制路径（可指向别的 .sys）
			//   · serviceType != SERVICE_NO_CHANGE → 改类型（可把 Win32 服务改成内核驱动）
			// 只改启动类型/显示名/失败动作（两者都是"不改"）的调用直接放行 ——
			// 否则 `sc config MyDrv start= demand` 这种日常运维会被误拦。
			const bool changesBinary = (binaryPathName != nullptr && binaryPathName[0] != L'\0');
			const bool changesType = (serviceType != SERVICE_NO_CHANGE);

			if (changesBinary || changesType) {
				// 传 SERVICE_NO_CHANGE / NULL 表示"这一项不改"，实际值要从现有配置取。
				DWORD currentType = 0;
				WCHAR currentPath[R3ShieldCore::MaxKeyPathChars] = {};
				WCHAR displayNameBuffer[256] = {};
				const bool queried = QueryServiceInfo(service, currentType, currentPath,
					_countof(currentPath), displayNameBuffer, _countof(displayNameBuffer));

				const DWORD effectiveType = changesType ? serviceType : currentType;
				const bool kernelDriver = IsKernelDriverType(effectiveType);

				event.Op = static_cast<ULONG>(R3ShieldCore::DriverOp::ChangeServiceConfig);
				event.Flags |= R3ShieldCore::FlagEventServiceInstall;
				if (kernelDriver) {
					event.Flags |= R3ShieldCore::FlagEventKernelDriver;
				}

				WCHAR driverPath[R3ShieldCore::MaxKeyPathChars] = {};
				if (changesBinary) {
					NormalizeServiceBinaryPath(binaryPathName, driverPath, _countof(driverPath));
				}
				else if (queried) {
					wcsncpy_s(driverPath, currentPath, _TRUNCATE);
				}

				BuildServiceEvent(event, driverPath, displayNameBuffer);
				action = Evaluate(R3ShieldCore::DriverOp::ChangeServiceConfig, event, event.KeyPath, true,
					kernelDriver);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		else {
			result = pOriginalChangeServiceConfigW(service, serviceType, startType, errorControl,
				binaryPathName, loadOrderGroup, tagId, dependencies, serviceStartName, password,
				displayName);

			if (action == Action::Record) {
				event.Status = result ? 0 : static_cast<ULONG>(GetLastError());
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// StartServiceW —— 启动服务，驱动就是在这里真正进内核的。
	// 类型/路径只能从服务句柄反查（入参里没有）。
	BOOL WINAPI StartServiceW_Hook(SC_HANDLE service, DWORD numArgs, LPCWSTR* args)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		Action action = Action::Pass;
		BOOL result = FALSE;

		__try {
			DWORD serviceType = 0;
			WCHAR driverPath[R3ShieldCore::MaxKeyPathChars] = {};
			WCHAR displayName[256] = {};
			const bool queried = QueryServiceInfo(service, serviceType, driverPath,
				_countof(driverPath), displayName, _countof(displayName));

			if (queried && IsKernelDriverType(serviceType)) {
				event.Op = static_cast<ULONG>(R3ShieldCore::DriverOp::StartService);
				event.Flags |= R3ShieldCore::FlagEventServiceInstall;
				event.Flags |= R3ShieldCore::FlagEventKernelDriver;

				// 启动驱动服务 = 驱动加载，沿用"加载"语义（vs 卸载）。
				event.Flags |= R3ShieldCore::FlagEventDriverLoad;

				BuildServiceEvent(event, driverPath, displayName);
				action = Evaluate(R3ShieldCore::DriverOp::StartService, event, event.KeyPath, true, true);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(ERROR_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		else {
			result = pOriginalStartServiceW(service, numArgs, args);

			if (action == Action::Record) {
				event.Status = result ? 0 : static_cast<ULONG>(GetLastError());
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ==================================================================
	// 挂载
	// ==================================================================

	// moduleName 只用于日志（GetProcAddress 已经能定位模块）。
	bool QueueHook(HMODULE module, PCSTR moduleName, LPCSTR functionName,
		LPVOID detour, LPVOID* original, bool required) noexcept
	{
		if (!module) {
			if (required) {
				LOG(L"DriverGuard: 模块 %S 未加载，跳过 %S", moduleName, functionName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"DriverGuard: %S 缺少导出 %S", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"DriverGuard: MH_CreateHook(%S!%S) 失败，状态 %d", moduleName, functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"DriverGuard: MH_QueueEnableHook(%S!%S) 失败，状态 %d", moduleName, functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace DriverGuard
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
				LOG(L"DriverGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookDriver) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"DriverGuard: hook_driver 未开启，本进程不挂驱动 hook");
			return true;
		}

		g_bypass = false;

		HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

		QueueHook(ntdll, "ntdll", "NtLoadDriver", reinterpret_cast<LPVOID>(NtLoadDriver_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtLoadDriver), true);
		QueueHook(ntdll, "ntdll", "NtUnloadDriver", reinterpret_cast<LPVOID>(NtUnloadDriver_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtUnloadDriver), false);

		//
		// ⚠️ 补 SCM 盲区（ABI v9）。见文件头注释：
		//    驱动加载走 services.exe，而它在白名单里 → NtLoadDriver hook 抓不到
		//    调用方。所以必须在**应用一侧**挂 advapi32 的服务 API。
		//
		//    advapi32.dll 在多数进程里已经加载，但注入发生在进程刚起来的时候，
		//    未必已经 import 到它 —— 主动 LoadLibraryW 保证能挂上。
		//    （和 network_guard 主动加载 ws2_32 是同一个理由。）
		//
		HMODULE advapi = LoadLibraryW(L"advapi32.dll");
		if (advapi) {
			// Query 只用来查（拿服务类型/二进制路径），不挂 hook。
			pOriginalQueryServiceConfigW = reinterpret_cast<QueryServiceConfigWPtr>(
				GetProcAddress(advapi, "QueryServiceConfigW"));
			if (!pOriginalQueryServiceConfigW) {
				LOG(L"DriverGuard: advapi32 缺少 QueryServiceConfigW，StartService 覆盖会退化");
			}

			QueueHook(advapi, "advapi32", "CreateServiceW",
				reinterpret_cast<LPVOID>(CreateServiceW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCreateServiceW), true);
			QueueHook(advapi, "advapi32", "ChangeServiceConfigW",
				reinterpret_cast<LPVOID>(ChangeServiceConfigW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalChangeServiceConfigW), false);
			QueueHook(advapi, "advapi32", "StartServiceW",
				reinterpret_cast<LPVOID>(StartServiceW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalStartServiceW), false);
		}
		else {
			LOG(L"DriverGuard: advapi32.dll 加载失败，服务 API 覆盖缺失（只剩 NtLoadDriver）");
		}

		g_installed = true;

		LOG(L"DriverGuard: 已挂载 %d 个驱动 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
