#include "stdafx.h"
#include "r3shieldcore_stats.h"

#include <algorithm>
#include <psapi.h>

namespace
{
	// 事件主计数。只有引擎主线程写（Drain 在同一个线程），
	// UI 线程读 —— 所以加一把轻量锁，避免读到中间态。
	CRITICAL_SECTION g_lock;
	bool g_lockReady = false;

	ULONGLONG g_startTick = 0;
	ULONGLONG g_totalEvents = 0;
	ULONG g_opCounts[32] = {};
	ULONG g_decisionCounts[4] = {};
	ULONG g_targetKindCounts[2] = {};
	ULONG g_objectTypeCounts[16] = {};
	ULONG g_fileOpCounts[16] = {};
	ULONG g_processOpCounts[8] = {};
	ULONG g_threadOpCounts[8] = {};
	ULONG g_driverOpCounts[8] = {};
	ULONG g_networkOpCounts[8] = {};
	ULONG g_cameraOpCounts[8] = {};
	ULONG g_inputHookOpCounts[8] = {};
	ULONG g_screenOpCounts[8] = {};
	ULONG g_dllLoadOpCounts[8] = {};
	ULONG g_clipboardOpCounts[8] = {};
	ULONG g_spawnOpCounts[8] = {};
	ULONG g_serviceConfigOpCounts[8] = {};
	ULONG g_comOpCounts[8] = {};
	ULONG g_scheduledTaskOpCounts[8] = {};
	ULONG g_blockedByUs = 0;
	ULONG g_highRiskEvents = 0;
	ULONG g_droppedEvents = 0;

	// 最近一秒速率：滑动窗口，保留最近 8 个 1 秒桶。
	constexpr int RateBuckets = 8;
	ULONG g_rateBuckets[RateBuckets] = {};
	int g_rateCursor = 0;
	ULONGLONG g_rateBucketStart = 0;

	R3ShieldCoreStats::PromptStat g_promptStat = {};
	R3ShieldCoreStats::ProcWatchStat g_procWatchStat = {};

	// -----------------------------------------------------------------
	// 日志环形缓冲
	// -----------------------------------------------------------------
	// 固定容量，满了覆盖最旧的。用环形而不是 deque：
	// 事件可能每秒几百条，deque 的 pop_front 虽然有摊销，但环形缓冲
	// 完全没有分配/释放，长时间跑（几小时）也不会有堆碎片。
	std::vector<R3ShieldCoreStats::LogEntry> g_logRing(R3ShieldCoreStats::LogCapacity);

	// 已写过的总条数（只增不减）。行 i 的落点是 i % LogCapacity。
	// 这样 "最旧可用序号" = TotalWritten - min(TotalWritten, Capacity) + 1。
	ULONG g_logTotalWritten = 0;

	// 最近一次命中的进程名缓存：日志行只带进程名（不带完整路径），
	// 复用统计表里的名字，避免每条事件都开进程。
	ULONG g_logNameCachePid = 0;
	std::wstring g_logNameCacheName;

	// ★ v54：已灌入的历史条数。0 = 没灌 / 灌过之后被 Reset 清了。
	// 语义上等价于"实时事件从哪个 Serial 开始"，GUI 只用它决定
	// 要不要画"以下为上次会话"的分隔横幅。
	size_t g_historyCount = 0;

	// ★ v54：统计落盘。
	//
	// g_persistPath 为空 = 没启用；g_persistLoadedTotal = 上次落盘的总事件数
	// （回放的统计基线）；g_sessionTotalEvents = 本进程**自己**累加的那部分，
	// 用来显示"（本次 +N）"。
	std::filesystem::path g_persistPath;
	ULONGLONG g_persistLoadedTotal = 0;
	ULONGLONG g_sessionTotalEvents = 0;
	ULONGLONG g_sessionStartTick = 0;
	ULONG g_injectedBase = 0;   // 注入进程数的持久化基值（见 SetInjectedBase）

	struct ProcEntry
	{
		ULONG ProcessId;
		ULONG Total;
		ULONG Blocked;
		ULONG WouldBlock;
		ULONG NameAttempts; // 名字查不到时的重试次数，避免每条事件都开进程
		std::wstring Name;
		std::wstring Path;
	};

	// 简单开放寻址表：PID -> 计数。进程数不多（几百），线性查找也够快，
	// 但为了稳定用个小 vector + 线性查找，条目满时丢最久没动的。
	std::vector<ProcEntry> g_processes;

	ProcEntry& FindOrAddProcess(ULONG processId)
	{
		for (auto& entry : g_processes) {
			if (entry.ProcessId == processId) {
				return entry;
			}
		}

		// 上限 512 个进程，超了就从最少的开始挤掉。
		if (g_processes.size() >= 512) {
			auto smallest = std::min_element(g_processes.begin(), g_processes.end(),
				[](const ProcEntry& a, const ProcEntry& b) { return a.Total < b.Total; });
			*smallest = ProcEntry{};
			smallest->ProcessId = processId;
			return *smallest;
		}

		g_processes.push_back(ProcEntry{});
		ProcEntry& entry = g_processes.back();
		entry.ProcessId = processId;
		return entry;
	}

	// 从 PID 拿进程名和完整路径。
	//
	// 注意：进程可能在事件产生之后、统计读取之前就退出了，这时 OpenProcess
	// 会失败。不能在第一条事件上就放弃 —— 短命进程恰恰是最需要看名字的。
	// 但也不能每条事件都试（每条都开进程太贵），所以限次数重试。
	void FillProcessIdentity(ProcEntry& entry)
	{
		if (!entry.Path.empty()) {
			return;
		}

		constexpr ULONG MaxAttempts = 8;
		if (entry.NameAttempts >= MaxAttempts) {
			return;
		}
		entry.NameAttempts++;

		wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.ProcessId));
		if (!process) {
			return;
		}

		WCHAR path[MAX_PATH] = {};
		DWORD size = _countof(path);
		if (!QueryFullProcessImageName(process.get(), 0, path, &size)) {
			return;
		}

		entry.Path.assign(path, size);
		const WCHAR* name = wcsrchr(entry.Path.c_str(), L'\\');
		entry.Name = name ? (name + 1) : entry.Path.c_str();
	}

	// 日志行只展示进程名，不带完整路径 —— 路径已经能在"触发最多的进程"
	// 那块（未来可加）以及落盘的日志文件里看到，一屏日志塞完整路径会挤爆。
	// 名字直接从统计表里取，最新一条同 PID 的事件先 FillProcessIdentity 过，
	// 所以绝大多数情况下这里直接命中，不用再开进程。
	//
	// 调用方必须已持有 g_lock。
	const std::wstring& LookupProcessNameLocked(ULONG processId)
	{
		if (g_logNameCachePid == processId && !g_logNameCacheName.empty()) {
			return g_logNameCacheName;
		}

		for (const auto& entry : g_processes) {
			if (entry.ProcessId == processId && !entry.Name.empty()) {
				g_logNameCachePid = processId;
				g_logNameCacheName = entry.Name;
				return g_logNameCacheName;
			}
		}

		// 统计表里还没有（或名字还没取到）。返回空，GUI 会退化成显示 PID。
		static const std::wstring empty;
		return empty;
	}

	void TickRate()
	{
		ULONGLONG now = GetTickCount64();
		if (g_rateBucketStart == 0) {
			g_rateBucketStart = now;
			return;
		}

		ULONGLONG elapsed = now - g_rateBucketStart;
		if (elapsed < 1000) {
			return;
		}

		// 跨过了几个 1 秒桶就把中间的空桶清零。
		ULONGLONG buckets = elapsed / 1000;
		if (buckets > RateBuckets) {
			buckets = RateBuckets;
		}

		for (ULONGLONG i = 0; i < buckets; i++) {
			g_rateCursor = (g_rateCursor + 1) % RateBuckets;
			g_rateBuckets[g_rateCursor] = 0;
		}

		g_rateBucketStart += buckets * 1000;
	}
}

namespace R3ShieldCoreStats
{
	void Reset() noexcept
	{
		EnterCriticalSection(&g_lock);

		g_startTick = GetTickCount64();
		g_totalEvents = 0;
		ZeroMemory(g_opCounts, sizeof(g_opCounts));
		ZeroMemory(g_decisionCounts, sizeof(g_decisionCounts));
		ZeroMemory(g_targetKindCounts, sizeof(g_targetKindCounts));
		ZeroMemory(g_objectTypeCounts, sizeof(g_objectTypeCounts));
		ZeroMemory(g_fileOpCounts, sizeof(g_fileOpCounts));
		ZeroMemory(g_processOpCounts, sizeof(g_processOpCounts));
		ZeroMemory(g_threadOpCounts, sizeof(g_threadOpCounts));
		ZeroMemory(g_driverOpCounts, sizeof(g_driverOpCounts));
		ZeroMemory(g_networkOpCounts, sizeof(g_networkOpCounts));
		ZeroMemory(g_cameraOpCounts, sizeof(g_cameraOpCounts));
		ZeroMemory(g_inputHookOpCounts, sizeof(g_inputHookOpCounts));
		ZeroMemory(g_screenOpCounts, sizeof(g_screenOpCounts));
		ZeroMemory(g_dllLoadOpCounts, sizeof(g_dllLoadOpCounts));
		ZeroMemory(g_clipboardOpCounts, sizeof(g_clipboardOpCounts));
		ZeroMemory(g_spawnOpCounts, sizeof(g_spawnOpCounts));
		ZeroMemory(g_serviceConfigOpCounts, sizeof(g_serviceConfigOpCounts));
		ZeroMemory(g_comOpCounts, sizeof(g_comOpCounts));
		ZeroMemory(g_scheduledTaskOpCounts, sizeof(g_scheduledTaskOpCounts));
		g_blockedByUs = 0;
		g_highRiskEvents = 0;
		g_droppedEvents = 0;
		ZeroMemory(g_rateBuckets, sizeof(g_rateBuckets));
		g_rateCursor = 0;
		g_rateBucketStart = g_startTick;
		g_promptStat = PromptStat{};
		g_procWatchStat = R3ShieldCoreStats::ProcWatchStat{};
		g_processes.clear();

		for (auto& entry : g_logRing) {
			entry = R3ShieldCoreStats::LogEntry{};
		}
		g_logTotalWritten = 0;
		g_historyCount = 0;   // ★ v54：清空统计 = 历史分隔横幅也消失
		g_sessionTotalEvents = 0;   // ★ v54：清空统计 = 本次增量也归零
		g_sessionStartTick = GetTickCount64();   // ★ v54
		g_logNameCachePid = 0;
		g_logNameCacheName.clear();

		LeaveCriticalSection(&g_lock);
	}

	void OnEvent(const R3ShieldCore::Event& event) noexcept
	{
		EnterCriticalSection(&g_lock);

		g_totalEvents++;
		g_sessionTotalEvents++;   // ★ v54：本进程自己的增量（界面显示"本次 +N"）

		// Op 的数值空间按对象类型分开：注册表 op 进 g_opCounts，
		// 文件 op 进 g_fileOpCounts，进程/线程/驱动各进各的。
		// 互不相同的枚举数值会撞（都是从 1 开始），
		// 所以必须先看 ObjectType，不能只看 Op。
		const auto objectType = static_cast<R3ShieldCore::ObjectType>(event.ObjectType);
		const bool isFile = (objectType == R3ShieldCore::ObjectType::File);

		if (isFile) {
			if (event.Op < _countof(g_fileOpCounts)) {
				g_fileOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Process) {
			if (event.Op < _countof(g_processOpCounts)) {
				g_processOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Thread) {
			if (event.Op < _countof(g_threadOpCounts)) {
				g_threadOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Driver) {
			if (event.Op < _countof(g_driverOpCounts)) {
				g_driverOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Network) {
			if (event.Op < _countof(g_networkOpCounts)) {
				g_networkOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Camera) {
			if (event.Op < _countof(g_cameraOpCounts)) {
				g_cameraOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::InputHook) {
			if (event.Op < _countof(g_inputHookOpCounts)) {
				g_inputHookOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Screen) {
			if (event.Op < _countof(g_screenOpCounts)) {
				g_screenOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::DllLoad) {
			if (event.Op < _countof(g_dllLoadOpCounts)) {
				g_dllLoadOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::Clipboard) {
			if (event.Op < _countof(g_clipboardOpCounts)) {
				g_clipboardOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::ProcessSpawn) {
			if (event.Op < _countof(g_spawnOpCounts)) {
				g_spawnOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::ServiceConfig) {
			if (event.Op < _countof(g_serviceConfigOpCounts)) {
				g_serviceConfigOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::ComHijack) {
			if (event.Op < _countof(g_comOpCounts)) {
				g_comOpCounts[event.Op]++;
			}
		}
		else if (objectType == R3ShieldCore::ObjectType::ScheduledTask) {
			if (event.Op < _countof(g_scheduledTaskOpCounts)) {
				g_scheduledTaskOpCounts[event.Op]++;
			}
		}
		else if (event.Op < _countof(g_opCounts)) {
			g_opCounts[event.Op]++;
		}

		if (event.ObjectType < _countof(g_objectTypeCounts)) {
			g_objectTypeCounts[event.ObjectType]++;
		}

		if (event.Decision < _countof(g_decisionCounts)) {
			g_decisionCounts[event.Decision]++;
		}

		if (event.TargetKind < _countof(g_targetKindCounts)) {
			g_targetKindCounts[event.TargetKind]++;
		}

		if (event.Flags & R3ShieldCore::FlagEventBlocked) {
			g_blockedByUs++;
		}

		if (event.Flags & R3ShieldCore::FlagEventHighRisk) {
			g_highRiskEvents++;
		}

		// 速率桶
		TickRate();
		g_rateBuckets[g_rateCursor]++;

		ProcEntry& process = FindOrAddProcess(event.ProcessId);
		process.Total++;
		if (event.Flags & R3ShieldCore::FlagEventBlocked) {
			process.Blocked++;
		}
		if (event.Decision == static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock)) {
			process.WouldBlock++;
		}

		// 每来一条事件都试着补名字（内部限次数）。进程名对排障很关键。
		FillProcessIdentity(process);

		// ---- 追加一行日志明细 ----
		{
			// 序号从 1 开始，落点是 serial % Capacity —— 读取端用同样的
			// 公式定位，两边必须一致，否则会"写进去但一条都读不出来"。
			const ULONG serial = g_logTotalWritten + 1;
			R3ShieldCoreStats::LogEntry& row = g_logRing[serial % R3ShieldCoreStats::LogCapacity];
			g_logTotalWritten = serial;

			row.Serial = serial;
			row.TimeStamp = event.TimeStamp;
			row.ProcessId = event.ProcessId;
			row.ObjectType = event.ObjectType;
			row.Op = event.Op;
			row.Decision = event.Decision;
			row.Status = event.Status;
			row.Flags = event.Flags;
			row.TargetProcessId = event.TargetProcessId;
			row.BlockedByUs = (event.Flags & R3ShieldCore::FlagEventBlocked) != 0;
			row.IsHive = !isFile && R3ShieldCore::IsHiveOp(event.Op);
			row.IsHighRisk = (event.Flags & R3ShieldCore::FlagEventHighRisk) != 0;

			row.ProcessName = LookupProcessNameLocked(event.ProcessId);

			// KeyPath / ValueName 是定长宽字符数组，长度单独给，
			// 不依赖结尾 NUL（生产者可能刚好填满整段）。
			size_t keyLen = event.KeyPathLength;
			if (keyLen >= R3ShieldCore::MaxKeyPathChars) {
				keyLen = R3ShieldCore::MaxKeyPathChars - 1;
			}
			row.Target.assign(event.KeyPath, keyLen);

			size_t valueLen = event.ValueNameLength;
			if (valueLen >= R3ShieldCore::MaxValueNameChars) {
				valueLen = R3ShieldCore::MaxValueNameChars - 1;
			}
			row.Value.assign(event.ValueName, valueLen);

			// 网络事件：KeyPath 是远端地址，端口/协议不在 ValueName 里，
			// 而是结构化的 TargetPort / NetProtocol 字段。这里合成一段
			// 便于展示的文本塞进 Value —— 日志层没有单独的端口列，
			// 而"地址 + 端口"必须一起看才有意义。
			if (objectType == R3ShieldCore::ObjectType::Network) {
				WCHAR detail[128] = {};
				if (event.Op == static_cast<ULONG>(R3ShieldCore::NetOp::DnsQuery)) {
					wcsncpy_s(detail, L"域名解析", _TRUNCATE);
				}
				else if (event.TargetPort != 0) {
					const char* proto = R3ShieldCore::NetProtocolName(event.NetProtocol);
					WCHAR wideProto[16] = {};
					MultiByteToWideChar(CP_ACP, 0, proto, -1, wideProto, _countof(wideProto));
					swprintf_s(detail, L"端口 %u (%s)", event.TargetPort, wideProto);
				}
				else {
					wcsncpy_s(detail, L"(无端口)", _TRUNCATE);
				}

				// 本端端点也带上 —— "谁在本地起的这条连接"对定位很有用。
				if (event.LocalPort != 0 && event.LocalAddress[0]) {
					WCHAR local[96] = {};
					swprintf_s(local, L"本端 %s:%u", event.LocalAddress, event.LocalPort);
					// 拼在端口说明后面。
					size_t used = wcslen(detail);
					if (used + 4 + wcslen(local) < _countof(detail)) {
						wcscat_s(detail, L"  ·  ");
						wcscat_s(detail, local);
					}
				}

				row.Value.assign(detail);
			}
		}

		LeaveCriticalSection(&g_lock);
	}

	void SetDroppedCount(ULONG dropped) noexcept
	{
		EnterCriticalSection(&g_lock);
		g_droppedEvents = dropped;
		LeaveCriticalSection(&g_lock);
	}

	void SetPromptStat(const PromptStat& stat) noexcept
	{
		EnterCriticalSection(&g_lock);
		g_promptStat = stat;
		LeaveCriticalSection(&g_lock);
	}

	void SetProcWatchStat(const ProcWatchStat& stat) noexcept
	{
		EnterCriticalSection(&g_lock);
		g_procWatchStat = stat;
		LeaveCriticalSection(&g_lock);
	}

	Snapshot GetSnapshot() noexcept
	{
		Snapshot snapshot = {};

		EnterCriticalSection(&g_lock);

		snapshot.StartTick = g_startTick;
		snapshot.TotalEvents = g_totalEvents;
		memcpy(snapshot.OpCounts, g_opCounts, sizeof(snapshot.OpCounts));
		memcpy(snapshot.DecisionCounts, g_decisionCounts, sizeof(snapshot.DecisionCounts));
		memcpy(snapshot.TargetKindCounts, g_targetKindCounts, sizeof(snapshot.TargetKindCounts));
		memcpy(snapshot.ObjectTypeCounts, g_objectTypeCounts, sizeof(snapshot.ObjectTypeCounts));
		memcpy(snapshot.FileOpCounts, g_fileOpCounts, sizeof(snapshot.FileOpCounts));
		memcpy(snapshot.ProcessOpCounts, g_processOpCounts, sizeof(snapshot.ProcessOpCounts));
		memcpy(snapshot.ThreadOpCounts, g_threadOpCounts, sizeof(snapshot.ThreadOpCounts));
		memcpy(snapshot.DriverOpCounts, g_driverOpCounts, sizeof(snapshot.DriverOpCounts));
		memcpy(snapshot.NetworkOpCounts, g_networkOpCounts, sizeof(snapshot.NetworkOpCounts));
		memcpy(snapshot.CameraOpCounts, g_cameraOpCounts, sizeof(snapshot.CameraOpCounts));
		memcpy(snapshot.InputHookOpCounts, g_inputHookOpCounts, sizeof(snapshot.InputHookOpCounts));
		memcpy(snapshot.ScreenOpCounts, g_screenOpCounts, sizeof(snapshot.ScreenOpCounts));
		memcpy(snapshot.DllLoadOpCounts, g_dllLoadOpCounts, sizeof(snapshot.DllLoadOpCounts));
		memcpy(snapshot.ClipboardOpCounts, g_clipboardOpCounts, sizeof(snapshot.ClipboardOpCounts));
		memcpy(snapshot.SpawnOpCounts, g_spawnOpCounts, sizeof(snapshot.SpawnOpCounts));
		memcpy(snapshot.ServiceConfigOpCounts, g_serviceConfigOpCounts, sizeof(snapshot.ServiceConfigOpCounts));
		memcpy(snapshot.ComOpCounts, g_comOpCounts, sizeof(snapshot.ComOpCounts));
		memcpy(snapshot.ScheduledTaskOpCounts, g_scheduledTaskOpCounts, sizeof(snapshot.ScheduledTaskOpCounts));
		snapshot.BlockedByUs = g_blockedByUs;
		snapshot.HighRiskEvents = g_highRiskEvents;
		snapshot.DroppedEvents = g_droppedEvents;

		TickRate();
		ULONG rate = 0;
		for (int i = 0; i < RateBuckets; i++) {
			rate += g_rateBuckets[i];
		}
		snapshot.LastSecondEvents = rate;

		snapshot.UniqueProcesses = static_cast<ULONG>(g_processes.size());

		// 取 Top 8 进程。
		std::vector<ProcEntry> sorted = g_processes;
		std::sort(sorted.begin(), sorted.end(),
			[](const ProcEntry& a, const ProcEntry& b) { return a.Total > b.Total; });

		size_t count = sorted.size() < 8 ? sorted.size() : 8;
		snapshot.TopProcesses.reserve(count);
		for (size_t i = 0; i < count; i++) {
			ProcessStat stat = {};
			stat.ProcessId = sorted[i].ProcessId;
			stat.Total = sorted[i].Total;
			stat.Blocked = sorted[i].Blocked;
			stat.WouldBlock = sorted[i].WouldBlock;
			stat.Name = sorted[i].Name;
			stat.Path = sorted[i].Path;
			snapshot.TopProcesses.push_back(std::move(stat));
		}

		LeaveCriticalSection(&g_lock);
		return snapshot;
	}

	PromptStat GetPromptStat() noexcept
	{
		EnterCriticalSection(&g_lock);
		PromptStat stat = g_promptStat;
		LeaveCriticalSection(&g_lock);
		return stat;
	}

	ProcWatchStat GetProcWatchStat() noexcept
	{
		EnterCriticalSection(&g_lock);
		ProcWatchStat stat = g_procWatchStat;
		LeaveCriticalSection(&g_lock);
		return stat;
	}

	LogChunk GetLogsSince(ULONG sinceSerial, size_t maxCount) noexcept
	{
		LogChunk chunk = {};
		if (maxCount == 0) {
			maxCount = 256;
		}

		EnterCriticalSection(&g_lock);

		chunk.LatestSerial = g_logTotalWritten;
		chunk.TotalWritten = g_logTotalWritten;

		if (g_logTotalWritten == 0) {
			LeaveCriticalSection(&g_lock);
			return chunk;
		}

		// 环形缓冲里最旧的序号。被覆盖过的行不再可取。
		ULONG oldest = 1;
		if (g_logTotalWritten > R3ShieldCoreStats::LogCapacity) {
			oldest = g_logTotalWritten - static_cast<ULONG>(R3ShieldCoreStats::LogCapacity) + 1;
		}

		// 起点：比用户要的新一条；如果用户要的已经被覆盖，就从最旧可用开始。
		ULONG start = sinceSerial + 1;
		if (start < oldest) {
			start = oldest;
		}
		if (start > g_logTotalWritten) {
			LeaveCriticalSection(&g_lock);
			return chunk;
		}

		ULONG available = g_logTotalWritten - start + 1;
		ULONG take = available;
		if (take > maxCount) {
			// 只取最新的那批（首屏和高速率场景都要看尾部）。
			start = g_logTotalWritten - static_cast<ULONG>(maxCount) + 1;
			take = static_cast<ULONG>(maxCount);
		}

		chunk.Entries.reserve(take);
		for (ULONG serial = start; serial <= g_logTotalWritten; serial++) {
			const R3ShieldCoreStats::LogEntry& row = g_logRing[serial % R3ShieldCoreStats::LogCapacity];
			if (row.Serial != serial) {
				continue; // 不该发生，防御性跳过
			}
			chunk.Entries.push_back(row);
		}

		LeaveCriticalSection(&g_lock);
		return chunk;
	}

	ULONG GetLatestLogSerial() noexcept
	{
		EnterCriticalSection(&g_lock);
		ULONG serial = g_logTotalWritten;
		LeaveCriticalSection(&g_lock);
		return serial;
	}

	std::vector<R3ShieldCoreStats::LogEntry> GetLogsForPid(ULONG pid, size_t maxCount) noexcept
	{
		std::vector<R3ShieldCoreStats::LogEntry> rows;
		if (maxCount == 0) {
			maxCount = 32;
		}

		EnterCriticalSection(&g_lock);

		if (g_logTotalWritten != 0) {
			// ★ 必须**从新往旧**扫：从旧往新扫再截断，慢进程（事件稀疏）
			//   永远挤不进前 N 条 —— 而那恰恰是最需要看历史的进程。
			ULONG oldest = 1;
			if (g_logTotalWritten > R3ShieldCoreStats::LogCapacity) {
				oldest = g_logTotalWritten - static_cast<ULONG>(R3ShieldCoreStats::LogCapacity) + 1;
			}

			rows.reserve(maxCount);
			for (ULONG serial = g_logTotalWritten; serial >= oldest; serial--) {
				const R3ShieldCoreStats::LogEntry& row =
					g_logRing[serial % R3ShieldCoreStats::LogCapacity];
				if (row.Serial != serial) {
					continue;   // 防御性跳过（不该发生）
				}
				if (row.ProcessId != pid && row.TargetProcessId != pid) {
					continue;
				}
				rows.push_back(row);
				if (rows.size() >= maxCount) {
					break;
				}
				if (serial == oldest) {
					break;   // ULONG 无符号回绕保护
				}
			}
		}

		LeaveCriticalSection(&g_lock);

		// 反转为时间升序（与 GetLogsSince 一致）。
		std::reverse(rows.begin(), rows.end());
		return rows;
	}

	//
	// ★ v54：把历史事件预填进日志环。
	//
	// 调用时机：引擎刚起、`EngineControl` 已就绪、`SetEventObserver` 之前。
	// 此刻日志环必然是空的（实时事件还没到），所以 Serial 1..N 一定空闲。
	//
	// ⚠️ 只灌**一次**：`g_logTotalWritten != 0` 或 `g_historyCount != 0` 时直接返回。
	//    这不只是幂等保护 —— 如果引擎运行中再灌一次，会把实时事件的行
	//    **覆盖掉**（Serial 从 1 重算），表现是"事件列表莫名其妙跳回开头"。
	//
	// ⚠️ 灌进来的条目 `Serial` 由**本函数**重新赋值（1..N），
	//    调用方传进来的 Serial 被忽略 —— 因为日志文件里的行没有序号列，
	//    重建时必须按"读到的时间顺序"重新编号。
	//
	void SeedHistory(const std::vector<LogEntry>& entries, ULONGLONG baselineTotalEvents) noexcept
	{
		EnterCriticalSection(&g_lock);

		if (g_logTotalWritten != 0 || g_historyCount != 0) {
			LeaveCriticalSection(&g_lock);
			return;
		}

		// 只保留尾部 Capacity 条 —— 多了也存不下，而且用户看的本来就是最近发生了什么。
		size_t begin = 0;
		if (entries.size() > LogCapacity) {
			begin = entries.size() - LogCapacity;
		}

		ULONG serial = 0;
		for (size_t i = begin; i < entries.size(); ++i) {
			const LogEntry& source = entries[i];

			++serial;
			LogEntry& row = g_logRing[serial % LogCapacity];
			row = source;          // 复制全部字段（含两条 wstring）
			row.Serial = serial;   // ★ 重新编号，必须是 1..N 连续
		}

		g_logTotalWritten = serial;
		g_historyCount = entries.size() - begin;

		// 总事件数从历史基线起算，让"监控事件"这个数字跨重启连续。
		// 注意：baseline 是**上一轮落盘时的总事件数**，不是历史条数 ——
		// 历史条数被容量截断过（只留尾部 2000 条），拿它当基线会少算。
		if (baselineTotalEvents > g_totalEvents) {
			g_totalEvents = baselineTotalEvents;
		}

		LeaveCriticalSection(&g_lock);

		printf("[R3ShieldCore] 已回放历史事件 %u 条（实时事件将从序号 %u 继续）\n",
			static_cast<unsigned>(g_historyCount),
			static_cast<unsigned>(g_logTotalWritten + 1));
	}

	size_t HistoryCount() noexcept
	{
		EnterCriticalSection(&g_lock);
		size_t count = g_historyCount;
		LeaveCriticalSection(&g_lock);
		return count;
	}

	//
	// ======================================================================
	// ★ v54：统计落盘
	// ======================================================================
	//
	// 为什么"自己手写 JSON"而不是引一个库：
	//   要写的字段就 20 来个标量 + 8 条进程记录，格式是我们自己读自己写。
	//   为这点东西引 nlohmann/json（几十万行头文件）会显著拖慢编译，
	//   而这里连转义都不需要 —— 所有值都是数字，唯一的字符串是进程名/路径，
	//   按 JSON 规则转义一下反斜杠和引号就够了。
	//
	// 为什么用临时文件 + 原子替换：
	//   引擎随时可能被 kill（用户点退出、或 UIAccess 接管时老引擎退出）。
	//   直接在目标文件上写，写到一半被杀 ⇒ 留下半截 JSON ⇒
	//   下次启动解析失败 ⇒ 用户看到"统计又归零了"，而且不知道为什么。
	//

	namespace
	{
		// 极简 JSON 字符串转义（只处理必须转义的字符）。
		std::string JsonEscape(const std::wstring& text)
		{
			std::string utf8;
			if (!text.empty()) {
				const int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
					static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
				if (needed > 0) {
					utf8.resize(static_cast<size_t>(needed));
					WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
						static_cast<int>(text.size()), utf8.data(), needed, nullptr, nullptr);
				}
			}

			std::string escaped;
			escaped.reserve(utf8.size() + 8);
			for (char ch : utf8) {
				switch (ch) {
				case '"':  escaped += "\\\""; break;
				case '\\': escaped += "\\\\"; break;
				case '\n': escaped += "\\n"; break;
				case '\r': escaped += "\\r"; break;
				case '\t': escaped += "\\t"; break;
				default:
					if (static_cast<unsigned char>(ch) < 0x20) {
						char buffer[8] = {};
						snprintf(buffer, sizeof(buffer), "\\u%04X",
							static_cast<unsigned>(static_cast<unsigned char>(ch)));
						escaped += buffer;
					}
					else {
						escaped += ch;
					}
				}
			}
			return escaped;
		}

		// 从 JSON 文本里取一个整数键的值。找不到返回 false。
		// 够用的极简解析 —— 我们只写数字和字符串，没有嵌套。
		bool JsonGetU64(const std::string& json, const std::string& key, ULONGLONG& out)
		{
			const std::string needle = "\"" + key + "\"";
			size_t at = json.find(needle);
			if (at == std::string::npos) {
				return false;
			}
			at = json.find(':', at + needle.size());
			if (at == std::string::npos) {
				return false;
			}
			++at;
			while (at < json.size() && (json[at] == ' ' || json[at] == '\t')) {
				++at;
			}
			char* stop = nullptr;
			const unsigned long long value = strtoull(json.c_str() + at, &stop, 10);
			if (stop == json.c_str() + at) {
				return false;
			}
			out = static_cast<ULONGLONG>(value);
			return true;
		}

		// 从 JSON 文本里取一个字符串键的值（已反转义的最简形式：只认 \\ \" \n \r \t）。
		bool JsonGetString(const std::string& json, const std::string& key, std::string& out)
		{
			const std::string needle = "\"" + key + "\"";
			size_t at = json.find(needle);
			if (at == std::string::npos) {
				return false;
			}
			at = json.find(':', at + needle.size());
			if (at == std::string::npos) {
				return false;
			}
			at = json.find('"', at);
			if (at == std::string::npos) {
				return false;
			}
			++at;

			std::string value;
			while (at < json.size() && json[at] != '"') {
				if (json[at] == '\\' && at + 1 < json.size()) {
					const char next = json[at + 1];
					switch (next) {
					case 'n': value += '\n'; break;
					case 'r': value += '\r'; break;
					case 't': value += '\t'; break;
					case '"': value += '"'; break;
					case '\\': value += '\\'; break;
					default: value += next; break;
					}
					at += 2;
					continue;
				}
				value += json[at];
				++at;
			}
			out = value;
			return true;
		}
	}

	void EnablePersistence(const std::filesystem::path& path) noexcept
	{
		if (path.empty()) {
			return;
		}

		EnterCriticalSection(&g_lock);
		g_persistPath = path;
		LeaveCriticalSection(&g_lock);

		//
		// 载入上次的值。读不到 / 解析失败都**不算错误** ——
		// 第一次跑本来就没有文件。
		//
		std::string blob;
		{
			// ⚠️ 带 FILE_SHARE_WRITE：正常退出时文件刚被自己写过，
			//    极短的窗口里可能还持有句柄（铁律 57 同族）。
			HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, nullptr);
			if (file != INVALID_HANDLE_VALUE) {
				LARGE_INTEGER size = {};
				if (GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart < (1 << 20)) {
					blob.resize(static_cast<size_t>(size.QuadPart));
					DWORD got = 0;
					if (!ReadFile(file, blob.data(), static_cast<DWORD>(blob.size()), &got, nullptr)) {
						blob.clear();
					}
					else {
						blob.resize(got);
					}
				}
				CloseHandle(file);
			}
		}

		if (!blob.empty()) {
			ULONGLONG total = 0;
			if (JsonGetU64(blob, "totalEvents", total)) {
				EnterCriticalSection(&g_lock);
				g_persistLoadedTotal = total;
				// 基线：把历史累计值垫到当前计数下面。
				if (total > g_totalEvents) {
					g_totalEvents = total;
				}
				LeaveCriticalSection(&g_lock);

				printf("[R3ShieldCore] 已载入累计统计 totalEvents=%llu\n",
					static_cast<unsigned long long>(total));
			}
			else {
				// 文件存在但读不出 totalEvents —— 格式可能被改坏了，要能看出来
				printf("[R3ShieldCore] stats.json 存在（%u 字节）但解析不出 totalEvents\n",
					static_cast<unsigned>(blob.size()));
			}
		}
		else {
			// 首次运行 / 上次退出没落盘 —— 这是"没有历史"，不是错误
			printf("[R3ShieldCore] 无可载入的统计文件（首次运行或上次未落盘）\n");
		}

		//
		// 注入进程数（injectedTotal）也一并载入 —— 它是 app.cpp 的局部 atomic，
		// 通过下面的 SetInjectedBase/GetInjectedBase 与统计模块共享。
		//
		{
			ULONGLONG injected = 0;
			if (JsonGetU64(blob, "injectedProcesses", injected)) {
				SetInjectedBase(static_cast<ULONG>(injected));
			}
		}
	}

	void SaveNow() noexcept
	{
		std::filesystem::path path;
		{
			EnterCriticalSection(&g_lock);
			path = g_persistPath;
			LeaveCriticalSection(&g_lock);
		}
		if (path.empty()) {
			return;
		}

		// 快照要在锁里取，序列化在锁外做（I/O 不能占着锁）。
		Snapshot snapshot = {};
		std::vector<ProcessStat> processes;
		ULONGLONG totalEvents = 0;
		{
			EnterCriticalSection(&g_lock);
			memcpy(snapshot.OpCounts, g_opCounts, sizeof(snapshot.OpCounts));
			memcpy(snapshot.FileOpCounts, g_fileOpCounts, sizeof(snapshot.FileOpCounts));
			memcpy(snapshot.ProcessOpCounts, g_processOpCounts, sizeof(snapshot.ProcessOpCounts));
			memcpy(snapshot.ThreadOpCounts, g_threadOpCounts, sizeof(snapshot.ThreadOpCounts));
			memcpy(snapshot.DriverOpCounts, g_driverOpCounts, sizeof(snapshot.DriverOpCounts));
			memcpy(snapshot.NetworkOpCounts, g_networkOpCounts, sizeof(snapshot.NetworkOpCounts));
			memcpy(snapshot.CameraOpCounts, g_cameraOpCounts, sizeof(snapshot.CameraOpCounts));
			memcpy(snapshot.InputHookOpCounts, g_inputHookOpCounts, sizeof(snapshot.InputHookOpCounts));
			memcpy(snapshot.ScreenOpCounts, g_screenOpCounts, sizeof(snapshot.ScreenOpCounts));
			memcpy(snapshot.DllLoadOpCounts, g_dllLoadOpCounts, sizeof(snapshot.DllLoadOpCounts));
			memcpy(snapshot.ClipboardOpCounts, g_clipboardOpCounts, sizeof(snapshot.ClipboardOpCounts));
			memcpy(snapshot.SpawnOpCounts, g_spawnOpCounts, sizeof(snapshot.SpawnOpCounts));
			memcpy(snapshot.ServiceConfigOpCounts, g_serviceConfigOpCounts, sizeof(snapshot.ServiceConfigOpCounts));
			memcpy(snapshot.ComOpCounts, g_comOpCounts, sizeof(snapshot.ComOpCounts));
			memcpy(snapshot.ScheduledTaskOpCounts, g_scheduledTaskOpCounts, sizeof(snapshot.ScheduledTaskOpCounts));
			memcpy(snapshot.DecisionCounts, g_decisionCounts, sizeof(snapshot.DecisionCounts));
			memcpy(snapshot.ObjectTypeCounts, g_objectTypeCounts, sizeof(snapshot.ObjectTypeCounts));
			snapshot.BlockedByUs = g_blockedByUs;
			snapshot.HighRiskEvents = g_highRiskEvents;
			snapshot.DroppedEvents = g_droppedEvents;
			totalEvents = g_totalEvents;

			// Top 8 进程。
			std::vector<ProcEntry> sorted = g_processes;
			std::sort(sorted.begin(), sorted.end(),
				[](const ProcEntry& a, const ProcEntry& b) { return a.Total > b.Total; });
			const size_t count = sorted.size() < 8 ? sorted.size() : 8;
			for (size_t i = 0; i < count; ++i) {
				ProcessStat stat = {};
				stat.ProcessId = sorted[i].ProcessId;
				stat.Total = sorted[i].Total;
				stat.Blocked = sorted[i].Blocked;
				stat.WouldBlock = sorted[i].WouldBlock;
				stat.Name = sorted[i].Name;
				stat.Path = sorted[i].Path;
				processes.push_back(std::move(stat));
			}
			LeaveCriticalSection(&g_lock);
		}

		// ---- 序列化 ----
		std::string out;
		out.reserve(8192);
		out += "{\n";
		out += "  \"version\": 1,\n";
		out += "  \"savedAt\": " + std::to_string(static_cast<unsigned long long>(
			(static_cast<ULONGLONG>(time(nullptr)) + 11644473600ull) * 10000000ull)) + ",\n";
		out += "  \"totalEvents\": " + std::to_string(static_cast<unsigned long long>(totalEvents)) + ",\n";
		out += "  \"injectedProcesses\": " + std::to_string(
			static_cast<unsigned long long>(GetInjectedBase())) + ",\n";

		auto appendArray = [&out](const char* name, const ULONG* values, size_t count) {
			out += "  \"";
			out += name;
			out += "\": [";
			for (size_t i = 0; i < count; ++i) {
				if (i) out += ",";
				out += std::to_string(static_cast<unsigned long long>(values[i]));
			}
			out += "],\n";
		};

		appendArray("opCounts", snapshot.OpCounts, _countof(snapshot.OpCounts));
		appendArray("fileOpCounts", snapshot.FileOpCounts, _countof(snapshot.FileOpCounts));
		appendArray("processOpCounts", snapshot.ProcessOpCounts, _countof(snapshot.ProcessOpCounts));
		appendArray("threadOpCounts", snapshot.ThreadOpCounts, _countof(snapshot.ThreadOpCounts));
		appendArray("driverOpCounts", snapshot.DriverOpCounts, _countof(snapshot.DriverOpCounts));
		appendArray("networkOpCounts", snapshot.NetworkOpCounts, _countof(snapshot.NetworkOpCounts));
		appendArray("cameraOpCounts", snapshot.CameraOpCounts, _countof(snapshot.CameraOpCounts));
		appendArray("inputHookOpCounts", snapshot.InputHookOpCounts, _countof(snapshot.InputHookOpCounts));
		appendArray("screenOpCounts", snapshot.ScreenOpCounts, _countof(snapshot.ScreenOpCounts));
		appendArray("dllLoadOpCounts", snapshot.DllLoadOpCounts, _countof(snapshot.DllLoadOpCounts));
		appendArray("clipboardOpCounts", snapshot.ClipboardOpCounts, _countof(snapshot.ClipboardOpCounts));
		appendArray("spawnOpCounts", snapshot.SpawnOpCounts, _countof(snapshot.SpawnOpCounts));
		appendArray("serviceConfigOpCounts", snapshot.ServiceConfigOpCounts, _countof(snapshot.ServiceConfigOpCounts));
		appendArray("comOpCounts", snapshot.ComOpCounts, _countof(snapshot.ComOpCounts));
		appendArray("scheduledTaskOpCounts", snapshot.ScheduledTaskOpCounts, _countof(snapshot.ScheduledTaskOpCounts));
		appendArray("decisionCounts", snapshot.DecisionCounts, _countof(snapshot.DecisionCounts));
		appendArray("objectTypeCounts", snapshot.ObjectTypeCounts, _countof(snapshot.ObjectTypeCounts));

		out += "  \"blockedByUs\": " + std::to_string(
			static_cast<unsigned long long>(snapshot.BlockedByUs)) + ",\n";
		out += "  \"highRiskEvents\": " + std::to_string(
			static_cast<unsigned long long>(snapshot.HighRiskEvents)) + ",\n";

		out += "  \"topProcesses\": [\n";
		for (size_t i = 0; i < processes.size(); ++i) {
			const ProcessStat& stat = processes[i];
			out += "    {\"pid\": " + std::to_string(static_cast<unsigned long long>(stat.ProcessId));
			out += ", \"total\": " + std::to_string(static_cast<unsigned long long>(stat.Total));
			out += ", \"blocked\": " + std::to_string(static_cast<unsigned long long>(stat.Blocked));
			out += ", \"wouldBlock\": " + std::to_string(static_cast<unsigned long long>(stat.WouldBlock));
			out += ", \"name\": \"" + JsonEscape(stat.Name) + "\"";
			out += ", \"path\": \"" + JsonEscape(stat.Path) + "\"}";
			out += (i + 1 < processes.size()) ? ",\n" : "\n";
		}
		out += "  ]\n";
		out += "}\n";

		// ---- 原子写 ----
		std::filesystem::path temp = path;
		temp += L".tmp";

		HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			printf("[R3ShieldCore] 统计落盘失败（建临时文件 err=%u）\n", GetLastError());
			return;
		}

		DWORD written = 0;
		const BOOL ok = WriteFile(file, out.data(),
			static_cast<DWORD>(out.size()), &written, nullptr);
		CloseHandle(file);

		if (!ok || written != out.size()) {
			printf("[R3ShieldCore] 统计落盘失败（写临时文件 err=%u）\n", GetLastError());
			DeleteFileW(temp.c_str());
			return;
		}

		// 原子替换。MOVEFILE_REPLACE_EXISTING 保证"要么旧内容、要么新内容"，
		// 不会出现半截文件。
		if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
			printf("[R3ShieldCore] 统计落盘失败（替换目标 err=%u）\n", GetLastError());
			DeleteFileW(temp.c_str());
		}
	}

	ULONGLONG PersistedTotalEvents() noexcept
	{
		EnterCriticalSection(&g_lock);
		ULONGLONG value = g_persistLoadedTotal;
		LeaveCriticalSection(&g_lock);
		return value;
	}

	Snapshot GetSessionSnapshot() noexcept
	{
		// 与 GetSnapshot 同源，区别只有 StartTick 用**本次会话**的起点，
		// 以及 TotalEvents 只报本进程增量。GUI 用它渲染"（本次 +N）"。
		Snapshot snapshot = GetSnapshot();

		EnterCriticalSection(&g_lock);
		snapshot.StartTick = g_sessionStartTick;
		snapshot.TotalEvents = g_sessionTotalEvents;
		LeaveCriticalSection(&g_lock);

		return snapshot;
	}

	void SetInjectedBase(ULONG value) noexcept
	{
		EnterCriticalSection(&g_lock);
		if (value > g_injectedBase) {
			g_injectedBase = value;
		}
		LeaveCriticalSection(&g_lock);
	}

	ULONG GetInjectedBase() noexcept
	{
		EnterCriticalSection(&g_lock);
		ULONG value = g_injectedBase;
		LeaveCriticalSection(&g_lock);
		return value;
	}

	// 延迟初始化。CRITICAL_SECTION 不能静态零初始化，必须显式建。
	struct Initializer
	{
		Initializer()
		{
			InitializeCriticalSection(&g_lock);
			g_lockReady = true;
			Reset();
		}
	};

	Initializer g_initializer;
}
