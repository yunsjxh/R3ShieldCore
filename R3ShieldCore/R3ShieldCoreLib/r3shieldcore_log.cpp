#include "stdafx.h"
#include "r3shieldcore_log.h"
#include "r3shieldcore_channel.h"
#include "logger.h"

namespace
{
	wil::unique_hfile g_file;

	constexpr char Utf8Bom[] = "\xEF\xBB\xBF";

	// 把宽字符按指定长度转成 UTF-8，失败则回退成问号。
	int ToUtf8(const WCHAR* source, int sourceChars, char* destination, int destinationBytes) noexcept
	{
		if (!source || sourceChars <= 0 || !destination || destinationBytes <= 0) {
			return 0;
		}

		int written = WideCharToMultiByte(CP_UTF8, 0, source, sourceChars,
			destination, destinationBytes - 1, nullptr, nullptr);
		if (written <= 0) {
			return 0;
		}

		destination[written] = '\0';
		return written;
	}

	// ------------------------------------------------------------------
	// PID -> 进程名 解析（带缓存）。
	//
	// 为什么需要：Event 结构里**只有 ProcessId，没有进程名/镜像路径**
	// （见 r3shieldcore_shared.h 的 struct Event）。GUI 面板有统计表可以反查，
	// 但落盘日志是 DLL 侧独立消费事件流（R3ShieldCoreChannel::Drain），
	// 拿不到引擎的统计表 —— 所以必须在这里自己反查。
	//
	// 为什么必须缓存：实测一台机上单个 PID 会贡献几百条事件
	// （日志里 pid=6772 有 517 条）。若每条都 OpenProcess + 查询，
	// 既慢又吵。这里用一个小的直接映射缓存：PID 低位做槽位，
	// 命中即复用。进程名在同一次运行里不会变，缓存永不失效。
	//
	// 线程安全：DrainAndWrite 只被引擎主循环单线程调用，缓存无需加锁。
	// ------------------------------------------------------------------
	constexpr ULONG NameCacheSlots = 64; // 2 的幂，PID 低位取模

	struct NameCacheEntry
	{
		ULONG ProcessId;   // 0 = 空槽
		char  Name[128];   // 进程名（含扩展名），UTF-8
	};

	NameCacheEntry g_nameCache[NameCacheSlots] = {};

	// 返回缓存的进程名（UTF-8）；取不到返回空串指针。
	const char* ResolveProcessName(ULONG processId) noexcept
	{
		if (processId == 0) {
			return "";
		}

		const ULONG slot = processId & (NameCacheSlots - 1);

		// 命中：同 PID 直接返回。
		if (g_nameCache[slot].ProcessId == processId) {
			return g_nameCache[slot].Name;
		}

		// 未命中原槽主：先清空，再尝试填充。
		g_nameCache[slot].ProcessId = 0;
		g_nameCache[slot].Name[0] = '\0';

		wil::unique_handle process(OpenProcess(
			PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
		if (!process) {
			// 进程可能已退出（短命进程最常见）。用一个"占位"标记
			// 避免反复 OpenProcess：把 PID 记下、名字留空。
			g_nameCache[slot].ProcessId = processId;
			return g_nameCache[slot].Name;
		}

		WCHAR path[MAX_PATH] = {};
		DWORD size = _countof(path);
		if (!QueryFullProcessImageName(process.get(), 0, path, &size)) {
			g_nameCache[slot].ProcessId = processId;
			return g_nameCache[slot].Name;
		}

		// 只要文件名部分，去掉目录（日志里放完整路径会挤爆一屏）。
		const WCHAR* name = wcsrchr(path, L'\\');
		name = name ? (name + 1) : path;

		ToUtf8(name, static_cast<int>(wcslen(name)),
			g_nameCache[slot].Name, sizeof(g_nameCache[slot].Name));
		g_nameCache[slot].ProcessId = processId;
		return g_nameCache[slot].Name;
	}

	void WriteEventLine(const R3ShieldCore::Event& event, void* /*context*/) noexcept
	{
		if (!g_file) {
			return;
		}
		FILETIME fileTime;
		fileTime.dwLowDateTime = static_cast<DWORD>(event.TimeStamp & 0xFFFFFFFF);
		fileTime.dwHighDateTime = static_cast<DWORD>(event.TimeStamp >> 32);

		FILETIME localFileTime;
		SYSTEMTIME systemTime = {};
		if (FileTimeToLocalFileTime(&fileTime, &localFileTime) && FileTimeToSystemTime(&localFileTime, &systemTime)) {
			// 已转换成功
		}
		else {
			GetLocalTime(&systemTime);
		}

		char keyPath[1024] = {};
		char valueName[512] = {};
		ToUtf8(event.KeyPath, static_cast<int>(event.KeyPathLength), keyPath, sizeof(keyPath));
		ToUtf8(event.ValueName, static_cast<int>(event.ValueNameLength), valueName, sizeof(valueName));

		// 进程旁路事件的第二字段是 CommandLine（不是 ValueName）。
		// DLL 加载事件没有第二字段（KeyPath 已经是完整 DLL 路径）。
		char spawnCmd[1200] = {};
		const bool objectIsSpawn = (static_cast<R3ShieldCore::ObjectType>(event.ObjectType)
			== R3ShieldCore::ObjectType::ProcessSpawn);
		if (objectIsSpawn) {
			ToUtf8(event.CommandLine, static_cast<int>(wcslen(event.CommandLine)),
				spawnCmd, sizeof(spawnCmd));
		}

		// 不同对象类型的第二个字段含义不同，标签必须区分，否则日志读串：
		//   文件     → ValueName 是改名后的新名字
		//   驱动     → ValueName 是服务名
		//   网络     → 无 ValueName，第二个字段由 TargetPort/NetProtocol 合成
		//   hive 级  → ValueName 是 hive 文件路径
		//   键级     → ValueName 才是值名
		//   进程/线程 → 无第二个字段（pid 跟在路径后面）
		//   摄像头   → 无第二个字段（KeyPath 是设备/接口说明）
		//   输入钩子 → KeyPath 是注入的模块路径，ValueName 是钩子类型
		//   截屏     → KeyPath 是来源（屏幕 DC / 窗口），ValueName 是区域
		//   DLL加载  → KeyPath / DllPath 都是被加载的 DLL 路径，无第二字段
		//   剪贴板   → KeyPath 是"打开/读取"，ValueName 是格式
		//   进程旁路 → KeyPath 是目标映像，CommandLine 是命令行（第二字段）
		const auto objectType = static_cast<R3ShieldCore::ObjectType>(event.ObjectType);
		const bool isFile = (objectType == R3ShieldCore::ObjectType::File);
		const bool isDriver = (objectType == R3ShieldCore::ObjectType::Driver);
		const bool isProc = (objectType == R3ShieldCore::ObjectType::Process);
		const bool isThread = (objectType == R3ShieldCore::ObjectType::Thread);
		const bool isNetwork = (objectType == R3ShieldCore::ObjectType::Network);
		const bool isCamera = (objectType == R3ShieldCore::ObjectType::Camera);
		const bool isInputHook = (objectType == R3ShieldCore::ObjectType::InputHook);
		const bool isScreen = (objectType == R3ShieldCore::ObjectType::Screen);
		const bool isDllLoad = (objectType == R3ShieldCore::ObjectType::DllLoad);
		const bool isClipboard = (objectType == R3ShieldCore::ObjectType::Clipboard);
		const bool isSpawn = (objectType == R3ShieldCore::ObjectType::ProcessSpawn);
		const bool isServiceConfig = (objectType == R3ShieldCore::ObjectType::ServiceConfig);
		const bool isComHijack = (objectType == R3ShieldCore::ObjectType::ComHijack);
		const bool isScheduledTask = (objectType == R3ShieldCore::ObjectType::ScheduledTask);
		const bool isTokenTheft = (objectType == R3ShieldCore::ObjectType::TokenTheft);
		const bool isWmiSubscription = (objectType == R3ShieldCore::ObjectType::WmiSubscription);
		const bool hive = !isFile && !isDriver && !isProc && !isThread && !isNetwork &&
			!isCamera && !isInputHook && !isScreen && !isDllLoad && !isClipboard && !isSpawn &&
			!isServiceConfig && !isComHijack && !isScheduledTask &&
			!isTokenTheft && !isWmiSubscription &&
			(event.TargetKind == static_cast<ULONG>(R3ShieldCore::TargetKind::Hive));

		const char* secondLabel = isDriver ? "  service="
			: (isFile ? "  rename="
			: (isInputHook ? "  hook="
			: (isScreen ? "  area="
			: (isClipboard ? "  format="
			: (isSpawn ? "  cmd="
			: (isServiceConfig ? "  detail="
			: (isComHijack ? "  server="
			: (isScheduledTask ? "  action="
			: (isTokenTheft ? "  detail="
			: (isWmiSubscription ? "  detail="
			: (hive ? "  file=" : "  value=")))))))))));
		const char* firstLabel = isDriver ? "driver="
			: (isFile ? "path="
			: (isNetwork ? "peer="
			: (isCamera ? "device="
			: (isInputHook ? "module="
			: (isScreen ? "source="
			: (isDllLoad ? "dll="
			: (isClipboard ? "what="
			: (isSpawn ? "image="
			: (isServiceConfig ? "object="
			: (isComHijack ? "clsid="
			: (isScheduledTask ? "task="
			: (isTokenTheft ? "target="
			: (isWmiSubscription ? "class="
			: (isProc ? "image=" : (isThread ? "target=" : (hive ? "target=" : "key="))))))))))))))));

		// 进程/线程事件把 pid 跟成 "(pid=N)"，拼进 keyPath 缓冲之后。
		char procSuffix[32] = {};
		if ((isProc || isThread) && event.TargetProcessId != 0) {
			snprintf(procSuffix, sizeof(procSuffix), "  (pid=%u)", event.TargetProcessId);
		}

		// 网络事件：把端口/协议合成第二字段（ValueName 是空的）。
		char netDetail[160] = {};
		if (isNetwork) {
			if (event.Op == static_cast<ULONG>(R3ShieldCore::NetOp::DnsQuery)) {
				strcpy_s(netDetail, "dns");
			}
			else if (event.TargetPort != 0) {
				snprintf(netDetail, sizeof(netDetail), "%u/%s",
					event.TargetPort, R3ShieldCore::NetProtocolName(event.NetProtocol));
			}
			else {
				strcpy_s(netDetail, "n/a");
			}
		}

		// 尾部标记。高危优先显示，和"[by R3ShieldCore]"可以并存。
		char tags[128] = {};
		if (event.Flags & R3ShieldCore::FlagEventHighRisk) {
			strcat_s(tags, "  [HIGH-RISK]");
		}
		if (event.Flags & R3ShieldCore::FlagEventBlocked) {
			strcat_s(tags, "  [by R3ShieldCore]");
		}
		// ★ v26：全拦模式下"可问项因询问通道不可用而降级放行"。
		//
		//   为什么必须在日志里显式标出来：这种放行**不是判定结论**，
		//   而是"该问没问成"的降级。如果日志里看不出来，事后审计会以为
		//   "这条本来就不该拦"，掩盖了"引擎询问通道坏了"这个真问题
		//   （VM 实测 2026-09-30：17 条 `key=Software` 静默被拒，
		//    看日志**完全看不出**是因为通道不可用才走的 fallback）。
		if (event.Flags2 & R3ShieldCore::FlagEvent2AskUnavailable) {
			strcat_s(tags, "  [ASK-UNAVAIL→ALLOW]");
		}

		char line[2048] = {};
		// ⚠️ 格式串的 %s 个数必须和后面传的实参**严格一致**。
		//    多一个 %s 会让 snprintf 去读一个不存在的指针 → 立刻 0xC0000005。
		//    头部 2 个 %s：进程名（紧跟 pid= 方括号内）；
		//    尾部 6 个 %s：firstLabel / keyPath / procSuffix / 第二字段标签 /
		//                  第二字段值 / tags。
		//    合计 8 个 %s，逐个核对下面的实参。
		//
		// 第二字段的取值按对象类型分流：
		//   网络     → 合成的 proto/detail（在 netDetail 里）
		//   进程旁路 → CommandLine（spawnCmd）
		//   其余     → ValueName（没有就整段留空）
		const bool hasSecondField = isNetwork || objectIsSpawn || valueName[0];
		const char* secondTag = isNetwork ? "  proto="
			: (objectIsSpawn ? secondLabel : (valueName[0] ? secondLabel : ""));
		const char* secondValue = isNetwork ? netDetail
			: (objectIsSpawn ? spawnCmd : (valueName[0] ? valueName : ""));

		// 进程名。取不到时退化成 "pid=<N>" 独占（保持原有信息不丢）。
		const char* processName = ResolveProcessName(event.ProcessId);

		int length = snprintf(line, sizeof(line),
			"%04u-%02u-%02u %02u:%02u:%02u.%03u  pid=%-6u[%s] tid=%-6u  %-4s %-11s %-4s %-16s  status=0x%08X  %s%s%s%s%s%s\r\n",
			systemTime.wYear, systemTime.wMonth, systemTime.wDay,
			systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds,
			event.ProcessId, processName[0] ? processName : "?",
			event.ThreadId,
			R3ShieldCore::ObjectTypeName(event.ObjectType),
			R3ShieldCore::DecisionName(event.Decision),
			(event.Flags & R3ShieldCore::FlagEventHighRisk) ? "HIGH" : "",
			R3ShieldCore::AnyOpName(event.ObjectType, event.Op),
			event.Status,
			firstLabel,
			keyPath[0] ? keyPath : "(unknown)",
			procSuffix,
			hasSecondField ? secondTag : "",
			hasSecondField ? secondValue : "",
			tags);

		if (length <= 0) {
			return;
		}

		if (length > static_cast<int>(sizeof(line))) {
			length = static_cast<int>(sizeof(line));
		}

		DWORD written = 0;
		WriteFile(g_file.get(), line, static_cast<DWORD>(length), &written, nullptr);
	}
}

namespace R3ShieldCoreLog
{
	bool IsOpen() noexcept
	{
		return static_cast<bool>(g_file);
	}

	bool Open(const WCHAR* path) noexcept
	{
		Close();

		if (!path || !path[0]) {
			return false;
		}

		wil::unique_hfile file(CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
		if (!file) {
			LOG(L"R3ShieldCore: 无法打开日志文件 %s (错误 %u)", path, GetLastError());
			return false;
		}

		SetFilePointer(file.get(), 0, nullptr, FILE_END);

		// 只在文件为空时写 BOM，方便追加。
		LARGE_INTEGER size = {};
		if (GetFileSizeEx(file.get(), &size) && size.QuadPart == 0) {
			DWORD written = 0;
			WriteFile(file.get(), Utf8Bom, sizeof(Utf8Bom) - 1, &written, nullptr);
		}

		g_file = std::move(file);
		return true;
	}

	int DrainAndWrite() noexcept
	{
		return R3ShieldCoreChannel::Drain(&WriteEventLine, nullptr);
	}

	void Close() noexcept
	{
		g_file.reset();
	}
}
