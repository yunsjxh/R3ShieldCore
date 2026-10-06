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

	void ScanOnce() noexcept
	{
		g_stats.LastScanProcesses = 0;
		g_stats.LastScanNoPath = 0;
		g_stats.LastScanCandidates = 0;
		g_stats.LastScanTruncated = 0;

		wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (!snapshot) {
			g_stats.SnapshotFailed = true;
			printf("[procwatch] 枚举进程失败：CreateToolhelp32Snapshot err=%lu\n",
				GetLastError());
			fflush(stdout);
			return;
		}
		g_stats.SnapshotFailed = false;

		ULONG alertsThisScan = 0;

		PROCESSENTRY32W entry = {};
		entry.dwSize = sizeof(entry);

		if (!Process32FirstW(snapshot.get(), &entry)) {
			return;
		}

		do
		{
			const ULONG pid = entry.th32ProcessID;

			// pid 0 = Idle，pid 4 = System：都拿不到映像路径，直接跳过。
			if (pid == 0 || pid == 4) {
				continue;
			}

			g_stats.LastScanProcesses++;

			WCHAR path[MAX_PATH] = {};
			if (!QueryImagePath(pid, path, ARRAYSIZE(path))) {
				g_stats.LastScanNoPath++;
				continue;
			}

			const char* reason = g_check(path, g_systemRoot);
			if (!reason) {
				continue;
			}

			g_stats.LastScanCandidates++;

			const ULONG hash = HashPath(path);
			if (IsDuplicate(pid, hash)) {
				continue;   // 同一个高危进程只报一次
			}
			Remember(pid, hash);
			g_stats.HighRiskFound++;

			// ★ 去重与"打不打日志"分开：即使被单轮上限截断，也**已经记住**了，
			//   所以下一轮不会再重复计入 —— 否则截断会让计数虚高。
			if (alertsThisScan >= kMaxAlertsPerScan) {
				g_stats.LastScanTruncated++;
				continue;
			}
			alertsThisScan++;
			g_stats.Alerts++;

			g_stats.LatestPid = pid;
			wcsncpy_s(g_stats.LatestName, entry.szExeFile, _TRUNCATE);
			wcsncpy_s(g_stats.LatestPath, path, _TRUNCATE);
			NarrowToWide(reason, g_stats.LatestReason, ARRAYSIZE(g_stats.LatestReason));

			printf("[procwatch] 高危进程 pid=%u 进程=%ls 原因=%s 路径=%ls\n",
				pid, entry.szExeFile, reason, path);
			fflush(stdout);
		}
		while (Process32NextW(snapshot.get(), &entry));

		g_stats.Scans++;
	}

	void PrintHeartbeat() noexcept
	{
		printf("[procwatch] 心跳 级别=%u 扫描=%u 本轮进程=%u 本轮无路径=%u "
			"本轮候选=%u 累计高危=%u 累计告警=%u 本轮截断=%u 去重表=%u/%u\n",
			g_level,
			g_stats.Scans,
			g_stats.LastScanProcesses,
			g_stats.LastScanNoPath,
			g_stats.LastScanCandidates,
			g_stats.HighRiskFound,
			g_stats.Alerts,
			g_stats.LastScanTruncated,
			g_dedupUsed,
			kDedupCapacity);
		fflush(stdout);
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
			"判据=伪装系统进程名/形近伪装/已知攻击工具/protect_process 点名\n",
			g_level, g_scanIntervalMs, g_systemRoot);
		fflush(stdout);

		// 立刻扫一轮：引擎启动**之前**就在跑的高危进程不用等一个间隔 ——
		// 这正是本功能相对注入路的价值所在（不依赖观测窗）。
		Tick();
	}

	void Stop() noexcept
	{
		if (g_started) {
			printf("[procwatch] 已停止 扫描=%u 累计高危=%u 累计告警=%u\n",
				g_stats.Scans, g_stats.HighRiskFound, g_stats.Alerts);
			fflush(stdout);
		}

		g_started = false;
		g_level = 0;
		g_scanIntervalMs = 1000;
		g_check = nullptr;
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
		if (!g_started || g_level == 0 || !g_check) {
			return;
		}

		const ULONGLONG now = GetTickCount64();

		if (g_lastScanMs != 0 && (now - g_lastScanMs) < g_scanIntervalMs) {
			return;
		}
		g_lastScanMs = now;

		ScanOnce();

		if (g_lastHeartbeatMs == 0 || (now - g_lastHeartbeatMs) >= kHeartbeatMs) {
			g_lastHeartbeatMs = now;
			PrintHeartbeat();
		}
	}

	Stats GetStats() noexcept
	{
		Stats snapshot = g_stats;
		snapshot.DedupEntries = g_dedupUsed;
		snapshot.DedupCapacity = kDedupCapacity;
		return snapshot;
	}
}
