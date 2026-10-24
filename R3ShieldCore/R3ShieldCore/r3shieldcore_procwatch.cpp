#include "stdafx.h"
#include "r3shieldcore_procwatch.h"

#include <tlhelp32.h>

namespace
{
	using namespace R3ShieldCoreProcWatch;

	// 心跳间隔。与 sentinel 保持一致（60s）—— 它存在的意义是让
	// "引擎到底有没有在扫进程"在 r3shieldcore-console.log 里可见。
	constexpr ULONGLONG kHeartbeatMs = 60000;

	// 单轮最多打多少条告警。一批伪装进程同时出现时不刷爆日志；
	// 被截断的条数会进心跳，所以"截断了多少"看得见（不是静默丢弃）。
	constexpr ULONG kMaxAlertsPerScan = 16;

	// 去重表容量。按 (pid, 映像路径) 去重：同一个高危进程只报一次。
	// 满了覆盖最旧的（环形）⇒ 内存有界；代价是极旧的条目可能被重新报一次，
	// 这比"无上限增长"和"满了就再也不报"都好。
	constexpr ULONG kDedupCapacity = 512;

	// 扫描间隔的合法范围。下限 200ms：枚举 + 逐个查路径是**真开销**
	// （不是空转），比 sentinel 的 EnumWindows 贵得多，再快没有意义。
	constexpr ULONG kMinScanIntervalMs = 200;
	constexpr ULONG kMaxScanIntervalMs = 60000;

	struct DedupEntry
	{
		ULONG Pid = 0;
		ULONG PathHash = 0;
		bool Used = false;
	};

	ULONG g_level = 0;
	ULONG g_scanIntervalMs = 1000;
	CheckFn g_check = nullptr;
	WCHAR g_systemRoot[MAX_PATH] = {};
	bool g_started = false;

	ULONGLONG g_lastScanMs = 0;
	ULONGLONG g_lastHeartbeatMs = 0;

	// ★★★ v101：扫描搬到**专用线程**。
	//
	//   为什么必须搬（2026-10-24 真机现场，用户原话「还是不行，退不出去怎么办」）：
	//   `ScanOnce` 对**每一个进程**问一次引擎（加密 IPC，单次超时 400ms）。
	//   全机 288 个进程 ⇒ 一轮就是几百次往返。原先这一轮是在 `Start()` 里
	//   **同步**跑的，而 `Start()` 在 `app.cpp` 主循环**之前** ⇒
	//   主循环整场都没跑起来 ⇒ 界面线程照常画、照常响应点击，但
	//   「切换模式」置的 `g_pendingMode` 和「退出引擎」置的 `g_quitRequest`
	//   **没有任何人消费** ⇒ 用户看到的就是"点了完全没反应"。
	//
	//   日志上的铁证：整场 `[loop] 主循环存活` **0 行**，而
	//   `[procwatch] 心跳` → `[ark] 已启用` 的先后顺序证明主线程一直卡在
	//   `ProcWatch::Start` 里面，直到用户关窗口那一刻才走完。
	//
	//   ⇒ 扫描与本模块的心跳都改在 `ScanThreadProc` 里做；`Tick()` 变成空实现
	//     （保留函数只为不动 `app.cpp` 的调用点）。主线程从此**永不**阻塞在扫描上。
	HANDLE g_scanThread = nullptr;

	// 停止事件：**只建一次、永不关闭**。
	//   为什么不像别的句柄那样在 Stop 里 CloseHandle：万一 join 超时，
	//   线程还在这上面 Wait，关掉句柄会让它拿到 WAIT_FAILED 后死循环。
	HANDLE g_scanStop = nullptr;
	volatile LONG g_scanStopFlag = 0;

	// `g_stats` 现在由**扫描线程**写、界面线程读 ⇒ 必须加锁。
	//   （以前是主循环写、界面读，同样是竞态，只是概率低到没被看见。）
	CRITICAL_SECTION g_statsLock;
	volatile LONG g_statsLockReady = 0;

	// 单轮时间预算。超了就收尾，剩下的进程下一轮再看。
	//   宁可"这轮没扫完"，也不能让一轮无限拖长 —— 退出时要 join 这个线程，
	//   一轮太长会拖慢退出（那正是用户抱怨的"退不出去"）。
	constexpr ULONGLONG kRoundBudgetMs = 4000;

	Stats g_stats = {};
	DedupEntry g_dedup[kDedupCapacity] = {};
	ULONG g_dedupCursor = 0;
	ULONG g_dedupUsed = 0;

	// FNV-1a，大小写不敏感（Windows 路径本来就大小写不敏感）。
	ULONG HashPath(PCWSTR path) noexcept
	{
		ULONG hash = 2166136261u;
		for (PCWSTR p = path; *p; p++) {
			hash ^= static_cast<ULONG>(towlower(*p));
			hash *= 16777619u;
		}
		return hash;
	}

	bool IsDuplicate(ULONG pid, ULONG pathHash) noexcept
	{
		for (const DedupEntry& entry : g_dedup) {
			if (entry.Used && entry.Pid == pid && entry.PathHash == pathHash) {
				return true;
			}
		}
		return false;
	}

	void Remember(ULONG pid, ULONG pathHash) noexcept
	{
		DedupEntry& slot = g_dedup[g_dedupCursor];
		if (!slot.Used) {
			g_dedupUsed++;
		}
		slot.Pid = pid;
		slot.PathHash = pathHash;
		slot.Used = true;
		g_dedupCursor = (g_dedupCursor + 1) % kDedupCapacity;
	}

	// 取进程映像的完整 DOS 路径。
	//
	// `PROCESS_QUERY_LIMITED_INFORMATION` 是 Vista+ 的最小权限查询权限；
	// 受保护进程（PPL）会返回 access denied —— 那是**预期**的，计数即可，
	// 不要报错刷屏。
	bool QueryImagePath(ULONG pid, WCHAR* out, size_t cch) noexcept
	{
		out[0] = L'\0';

		wil::unique_process_handle process(
			OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
		if (!process) {
			return false;
		}

		DWORD size = static_cast<DWORD>(cch);
		if (!QueryFullProcessImageNameW(process.get(), 0, out, &size)) {
			out[0] = L'\0';
			return false;
		}

		return size > 0 && out[0] != L'\0';
	}

	// 把判据返回的窄字符串（执行字符集 = 系统 ANSI）转成宽字符给界面用。
	void NarrowToWide(const char* text, WCHAR* out, size_t cch) noexcept
	{
		out[0] = L'\0';
		if (!text || !text[0] || cch == 0) {
			return;
		}

		const int written = MultiByteToWideChar(CP_ACP, 0, text, -1, out,
			static_cast<int>(cch));
		if (written <= 0) {
			out[0] = L'\0';
		}
	}

	// =====================================================================
	//  v101：统计的发布/快照（跨线程）
	// =====================================================================
	void PublishStats(const Stats& s) noexcept
	{
		if (!g_statsLockReady) {
			g_stats = s;
			return;
		}
		EnterCriticalSection(&g_statsLock);
		g_stats = s;
		LeaveCriticalSection(&g_statsLock);
	}

	Stats SnapshotStats() noexcept
	{
		if (!g_statsLockReady) {
			return g_stats;
		}
		EnterCriticalSection(&g_statsLock);
		const Stats s = g_stats;
		LeaveCriticalSection(&g_statsLock);
		return s;
	}

	//
	// 扫一轮。
	//
	// ★ v101：`check` 改成**参数**而不是读全局 `g_check`。
	//   理由：`Stop()` 里 join 超时（极罕见）时会把 `g_check` 清空，
	//   这时还活着的线程必须**立刻**拿到 nullptr 并放手，而不是继续
	//   拿一个正在被析构的引擎客户端去发 IPC。
	//
	// ★ v101：加了**单轮预算** + **退出标志检查**。
	//   每个进程都问一次引擎，引擎没响应时每次就是一个超时；
	//   没有这两条，一轮能拖几十秒，退出时 join 也会跟着拖。
	//
	void ScanOnce(CheckFn check) noexcept
	{
		Stats s = SnapshotStats();

		s.LastScanProcesses = 0;
		s.LastScanNoPath = 0;
		s.LastScanCandidates = 0;
		s.LastScanTruncated = 0;
		s.LastScanBudgetHit = false;

		wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (!snapshot) {
			s.SnapshotFailed = true;
			s.DedupEntries = g_dedupUsed;
			PublishStats(s);
			printf("[procwatch] 枚举进程失败：CreateToolhelp32Snapshot err=%lu\n",
				GetLastError());
			fflush(stdout);
			return;
		}
		s.SnapshotFailed = false;

		ULONG alertsThisScan = 0;
		const ULONGLONG budgetStart = GetTickCount64();

		PROCESSENTRY32W entry = {};
		entry.dwSize = sizeof(entry);

		if (!Process32FirstW(snapshot.get(), &entry)) {
			s.DedupEntries = g_dedupUsed;
			PublishStats(s);
			return;
		}

		do
		{
			// 退出中：立刻放手。别让 `Stop()` 的 join 白等满一个预算。
			if (InterlockedCompareExchange(&g_scanStopFlag, 0, 0) != 0) {
				s.LastScanBudgetHit = true;
				break;
			}
			// 单轮预算到点：剩下的进程下一轮再看（心跳里报 `预算超时=1`）。
			if (GetTickCount64() - budgetStart > kRoundBudgetMs) {
				s.LastScanBudgetHit = true;
				break;
			}

			const ULONG pid = entry.th32ProcessID;

			// pid 0 = Idle，pid 4 = System：都拿不到映像路径，直接跳过。
			if (pid == 0 || pid == 4) {
				continue;
			}

			s.LastScanProcesses++;

			WCHAR path[MAX_PATH] = {};
			if (!QueryImagePath(pid, path, ARRAYSIZE(path))) {
				s.LastScanNoPath++;
				continue;
			}

			const char* reason = check ? check(path, g_systemRoot) : nullptr;
			if (!reason) {
				continue;
			}

			s.LastScanCandidates++;

			const ULONG hash = HashPath(path);
			if (IsDuplicate(pid, hash)) {
				continue;   // 同一个高危进程只报一次
			}
			Remember(pid, hash);
			s.HighRiskFound++;

			// ★ 去重与"打不打日志"分开：即使被单轮上限截断，也**已经记住**了，
			//   所以下一轮不会再重复计入 —— 否则截断会让计数虚高。
			if (alertsThisScan >= kMaxAlertsPerScan) {
				s.LastScanTruncated++;
				continue;
			}
			alertsThisScan++;
			s.Alerts++;

			s.LatestPid = pid;
			wcsncpy_s(s.LatestName, entry.szExeFile, _TRUNCATE);
			wcsncpy_s(s.LatestPath, path, _TRUNCATE);
			NarrowToWide(reason, s.LatestReason, ARRAYSIZE(s.LatestReason));

			printf("[procwatch] 高危进程 pid=%u 进程=%ls 原因=%s 路径=%ls\n",
				pid, entry.szExeFile, reason, path);
			fflush(stdout);
		}
		while (Process32NextW(snapshot.get(), &entry));

		s.Scans++;
		s.DedupEntries = g_dedupUsed;
		PublishStats(s);
	}

	void PrintHeartbeat() noexcept
	{
		const Stats s = SnapshotStats();
		// ⚠️ 字段叫 `LastScanBudgetHit`，但它的语义是「**本轮没扫完**」——
		//   既包括"时间预算到点"，也包括"正在退出、立刻放手"。
		//   所以日志标签写「本轮未扫完」，不写「预算超时」：
		//   标签写得比实际窄，就是在制造下一次误判（铁律 97 家族）。
		printf("[procwatch] 心跳 级别=%u 扫描=%u 本轮进程=%u 本轮无路径=%u "
			"本轮候选=%u 累计高危=%u 累计告警=%u 本轮截断=%u 本轮未扫完=%u 去重表=%u/%u\n",
			g_level,
			s.Scans,
			s.LastScanProcesses,
			s.LastScanNoPath,
			s.LastScanCandidates,
			s.HighRiskFound,
			s.Alerts,
			s.LastScanTruncated,
			s.LastScanBudgetHit ? 1u : 0u,
			g_dedupUsed,
			kDedupCapacity);
		fflush(stdout);
	}

	// =====================================================================
	//  v101：扫描线程
	// =====================================================================
	//
	// 先扫一轮再等间隔 —— 「引擎启动**之前**就在跑的高危进程不用等一个间隔」
	// 这条价值不变（那是本功能相对注入路的核心意义），只是不再占用主线程。
	//
	DWORD WINAPI ScanThreadProc(LPVOID)
	{
		// 判据指针取一次快照：`Stop()` 之后 `g_check` 会被清空，
		// 这里的局部副本保证"本轮的判据"不会在中途变成野指针。
		for (;;) {
			ScanOnce(g_check);

			const ULONGLONG now = GetTickCount64();
			g_lastScanMs = now;
			if (g_lastHeartbeatMs == 0 || (now - g_lastHeartbeatMs) >= kHeartbeatMs) {
				g_lastHeartbeatMs = now;
				PrintHeartbeat();
			}

			if (WaitForSingleObject(g_scanStop, g_scanIntervalMs) == WAIT_OBJECT_0) {
				break;
			}
		}
		return 0;
	}
}

namespace R3ShieldCoreProcWatch
{
	void Start(ULONG level, ULONG scanIntervalMs, CheckFn check) noexcept
	{
		Stop();

		if (level == 0) {
			// 关闭也要说一句 —— 否则"用户配了 0"与"配置没读进来"
			// 在日志里长得一样（铁律 97）。
			printf("[procwatch] 未启用：high_risk_process_alert=0\n");
			fflush(stdout);
			return;
		}

		if (!check) {
			printf("[procwatch] 未启用：当前 r3shieldcore-lib.dll 没有提供高危进程"
				"判据导出（旧版 DLL？）—— 换成本次发布的 64/32 目录下的 DLL 即可\n");
			fflush(stdout);
			return;
		}

		// ★ %SystemRoot% 取不到就**整体停用**，不是"降级继续"。
		//   判不出"在不在系统目录"时，`C:\Windows\System32\svchost.exe`
		//   会被判成伪装 —— 那不是漏报，是**误报**，而且会刷满日志。
		const UINT rootLength = GetWindowsDirectoryW(g_systemRoot, ARRAYSIZE(g_systemRoot));
		if (rootLength == 0 || rootLength >= ARRAYSIZE(g_systemRoot)) {
			g_systemRoot[0] = L'\0';
			printf("[procwatch] 未启用：取不到 %%SystemRoot%%（GetWindowsDirectoryW "
				"返回 %u，err=%lu）—— 判不出系统目录会把真正的 svchost.exe "
				"报成伪装，宁可不启用\n",
				rootLength, GetLastError());
			fflush(stdout);
			return;
		}

		g_level = level;
		g_scanIntervalMs = scanIntervalMs;
		if (g_scanIntervalMs < kMinScanIntervalMs) {
			g_scanIntervalMs = kMinScanIntervalMs;
		}
		if (g_scanIntervalMs > kMaxScanIntervalMs) {
			g_scanIntervalMs = kMaxScanIntervalMs;
		}
		g_check = check;
		g_started = true;
		g_lastScanMs = 0;
		g_lastHeartbeatMs = 0;

		// ★ 铁律 97：首行立即打。没有它，"功能没生效"与"生效了但没发现
		//   高危进程"在日志里长得一模一样。
		printf("[procwatch] 已启用 级别=%u 扫描间隔=%ums systemRoot=%ls "
			"判据=伪装系统进程名/形近伪装/已知攻击工具/protect_process 点名"
			"（v101：扫描在专用线程，不占主循环）\n",
			g_level, g_scanIntervalMs, g_systemRoot);
		fflush(stdout);

		// ★★★ v101：**不再同步扫第一轮**。
		//
		//   以前这里是 `Tick()` —— 它在主循环**之前**跑完一整轮全机扫描，
		//   而每个进程都要问一次引擎（加密 IPC）。288 个进程 ⇒ 主循环
		//   几十秒到几分钟都起不来 ⇒ 「切换模式」和「退出引擎」全部石沉大海。
		//   现在改成起线程：首轮照样立刻开始（价值不变），但主线程立刻返回。
		if (!g_scanStop) {
			g_scanStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		}
		if (!g_scanStop) {
			printf("[procwatch] 未启用：建停止事件失败（err=%lu）\n",
				static_cast<unsigned long>(GetLastError()));
			fflush(stdout);
			g_check = nullptr;
			g_started = false;
			return;
		}
		ResetEvent(g_scanStop);
		InterlockedExchange(&g_scanStopFlag, 0);

		if (!g_statsLockReady) {
			InitializeCriticalSection(&g_statsLock);
			InterlockedExchange(&g_statsLockReady, 1);
		}

		g_scanThread = CreateThread(nullptr, 0, ScanThreadProc, nullptr, 0, nullptr);
		if (!g_scanThread) {
			printf("[procwatch] 未启用：起扫描线程失败（err=%lu）\n",
				static_cast<unsigned long>(GetLastError()));
			fflush(stdout);
			g_check = nullptr;
			g_started = false;
			return;
		}
	}

	void Stop() noexcept
	{
		// ★★★ v101：顺序很重要 —— **先停线程，再清全局**。
		//   `g_check` 指向引擎 IPC 客户端；调用方在 `Stop()` 返回后会销毁它。
		//   线程如果还活着就会拿着野指针发请求。
		InterlockedExchange(&g_scanStopFlag, 1);
		if (g_scanStop) {
			SetEvent(g_scanStop);
		}
		if (g_scanThread) {
			const DWORD waited = WaitForSingleObject(g_scanThread, 8000);
			if (waited != WAIT_OBJECT_0) {
				// 单轮预算 4s + 退出标志每个进程都查 ⇒ 正常情况下绝不会到这里。
				// 真到了这里就**如实说**，并把判据立刻摘掉（线程下一轮拿到
				// nullptr 会直接放手），别让它继续碰引擎客户端。
				printf("[procwatch] 扫描线程 8000ms 内没停下来 —— 摘掉判据并放弃等待\n");
				fflush(stdout);
			}
			CloseHandle(g_scanThread);
			g_scanThread = nullptr;
		}
		g_check = nullptr;

		const Stats s = SnapshotStats();
		if (g_started) {
			printf("[procwatch] 已停止 扫描=%u 累计高危=%u 累计告警=%u\n",
				s.Scans, s.HighRiskFound, s.Alerts);
			fflush(stdout);
		}

		g_started = false;
		g_level = 0;
		g_scanIntervalMs = 1000;
		g_systemRoot[0] = L'\0';
		g_lastScanMs = 0;
		g_lastHeartbeatMs = 0;

		for (DedupEntry& entry : g_dedup) {
			entry = DedupEntry{};
		}
		g_dedupCursor = 0;
		g_dedupUsed = 0;

		g_stats = Stats{};
	}

	bool IsEnabled() noexcept
	{
		return g_started && g_level != 0;
	}

	void Tick() noexcept
	{
		// ★★★ v101：**空实现**。
		//
		//   扫描与心跳都搬进了 `ScanThreadProc`（理由见 `g_scanThread` 那段注释）。
		//   这里刻意保留函数、刻意什么都不做：
		//     · `app.cpp` 的调用点不用改（主循环每 100ms 调一次，空函数零开销）；
		//     · 更重要的是 —— **主循环再也不可能被扫描阻塞**。
		//   如果将来有人想"顺手在这儿扫一轮"，请先回去读 `ScanOnce` 上面那段：
		//   每个进程一次 IPC 往返，放在主线程上就是"退出按钮没反应"。
	}

	Stats GetStats() noexcept
	{
		Stats snapshot = SnapshotStats();
		snapshot.DedupEntries = g_dedupUsed;
		snapshot.DedupCapacity = kDedupCapacity;
		return snapshot;
	}
}
