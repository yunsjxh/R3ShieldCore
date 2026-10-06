#include "stdafx.h"
#include "r3shieldcore_ark.h"

#include "ark_actions.h"

#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <vector>

namespace
{
	using namespace R3ShieldCoreArk;

	// 心跳间隔。与 sentinel / procwatch 保持一致（60s）——
	// 它存在的意义是让"引擎到底有没有在扫进程"在 r3shieldcore-console.log 里可见。
	constexpr ULONGLONG kHeartbeatMs = 60000;

	// 处置请求队列。GUI 线程压、主循环取。满了丢弃并计数（**不阻塞界面**）。
	//
	// 16 是刻意的小值：这是人点按钮产生的，不是数据流。队列长期非空
	// 说明主循环卡住了 —— 那本身就该被看见（心跳里报队列深度）。
	constexpr ULONG kQueueCapacity = 16;
	constexpr ULONG kRecentCapacity = 32;

	// 扫描间隔合法范围。下限 500ms：枚举 + 逐个打开进程是**真开销**
	// （每个进程 1~2 次 OpenProcess + 若干次查询），不是空转。
	constexpr ULONG kMinScanIntervalMs = 500;
	constexpr ULONG kMaxScanIntervalMs = 60000;

	struct ActionRequest
	{
		ULONG Pid = 0;
		ULONG Action = 0;
	};

	struct SuspendedEntry
	{
		ULONG Pid = 0;
		ULONGLONG CreateTime = 0;   // pid 复用防护：创建时间不同 = 不是同一个进程
		bool Used = false;
	};

	struct CpuSample
	{
		ULONGLONG CpuTimeMs = 0;
		ULONGLONG AtMs = 0;
		ULONGLONG CreateTime = 0;
	};

	// ------------------------------------------------------------------
	// 锁
	// ------------------------------------------------------------------
	//
	// ★ 为什么是"函数局部静态 + **永不销毁**"，而不是
	//   `InitializeCriticalSection` / `DeleteCriticalSection` 配对：
	//
	//   引擎线程调 `Stop()` 时，GUI 线程可能正走在 `GetSnapshot()` 里。
	//   "先 Enter/Leave 再 Delete" 看起来是对的，但**删掉之后** GUI 线程
	//   可能已经通过了 `g_initialized` 检查、正要 Enter 一个已删除的临界区
	//   —— 那是未定义行为（Debug 下直接断言，Release 下是随机崩）。
	//   要修就得让"检查"与"加锁"原子化，那是另一套复杂度。
	//
	//   临界区只有几十字节，进程退出时随地址空间一起消失。
	//   用"泄漏一个临界区"换"任何时刻加锁都安全"，这笔账很划算。
	CRITICAL_SECTION& Lock() noexcept
	{
		static CRITICAL_SECTION cs;
		static std::once_flag once;
		std::call_once(once, []() noexcept { InitializeCriticalSection(&cs); });
		return cs;
	}

	struct LockGuard
	{
		LockGuard() noexcept { EnterCriticalSection(&Lock()); }
		~LockGuard() noexcept { LeaveCriticalSection(&Lock()); }
		LockGuard(const LockGuard&) = delete;
		LockGuard& operator=(const LockGuard&) = delete;
	};

	// 是否已经 `Start` 过（`Stop` 之后归 false）。
	//
	// ★ 它是**跨线程读的**（引擎线程写、GUI 线程在 GetSnapshot/RequestAction
	//   里读），所以必须是 atomic —— 用普通 bool 就是数据竞争（形式上 UB，
	//   实际表现是"偶尔读到撕裂值"）。它只当快速路径的闸门用；
	//   **真正保护共享状态的是 `Lock()`**，不是它。
	std::atomic<bool> g_initialized{ false };

	Config g_config = {};
	bool g_started = false;

	ULONG g_systemRootLength = 0;
	WCHAR g_systemRoot[MAX_PATH] = {};
	ULONG g_cores = 1;

	ULONGLONG g_lastScanMs = 0;
	ULONGLONG g_lastHeartbeatMs = 0;

	// ---- 受锁保护的状态 ----
	std::vector<Row> g_rows;
	Stats g_stats = {};
	ULONGLONG g_totalScanMs = 0;   // 累计扫描耗时（算平均用）

	ActionRequest g_queue[kQueueCapacity] = {};
	ULONG g_queueHead = 0;
	ULONG g_queueCount = 0;

	ActionRecord g_recent[kRecentCapacity] = {};
	ULONG g_recentHead = 0;        // 下一个写入位置
	ULONG g_recentCount = 0;
	ULONG g_recentSerial = 0;

	SuspendedEntry g_suspended[kRecentCapacity] = {};
	std::map<ULONG, CpuSample> g_cpuSamples;

	// ------------------------------------------------------------------
	// 小工具
	// ------------------------------------------------------------------

	// FILETIME → 100ns 计数（可当 ULONGLONG 比较）。
	ULONGLONG FileTimeToU64(const FILETIME& ft) noexcept
	{
		ULARGE_INTEGER value = {};
		value.LowPart = ft.dwLowDateTime;
		value.HighPart = ft.dwHighDateTime;
		return value.QuadPart;
	}

	// `ArkActions` 返回的结果码是 **ASCII 窄串**（`ResultCode`）—— 日志要它，
	// 界面也要它。转一次宽串给界面，日志继续用窄串。
	std::wstring NarrowToWide(const char* text) noexcept
	{
		if (!text || !text[0]) {
			return std::wstring();
		}
		WCHAR buffer[64] = {};
		const int written = MultiByteToWideChar(CP_ACP, 0, text, -1, buffer,
			_countof(buffer));
		if (written <= 0) {
			return std::wstring();
		}
		return std::wstring(buffer);
	}

	// 把 %SystemRoot% 之下的判定交给 `ArkActions::IsSystemImagePath` ——
	// 前缀边界（`C:\WindowsApps`）那个坑只该有**一处**实现。
	bool IsSystemPath(PCWSTR path) noexcept
	{
		if (!path || !path[0] || g_systemRootLength == 0) {
			return false;
		}
		return ArkActions::IsSystemImagePath(path, g_systemRoot);
	}

	// ------------------------------------------------------------------
	// 进程信息采集
	// ------------------------------------------------------------------

	// 一次进程信息采集的结果。分成两个权限档：
	//   · 完整档 `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` ⇒ 能读模块表；
	//   · 受限档 `PROCESS_QUERY_LIMITED_INFORMATION` ⇒ 路径/时间/内存，
	//     但**读不到模块表**（PPL 走这一档，甚至这一档也拿不到）。
	//
	// ★ 为什么两档而不是"一个权限不够就全放弃"：
	//   `csrss.exe` / `lsass.exe` 这类 PPL 走受限档就能拿到路径与 CPU，
	//   它们恰恰是用户最想看的进程。只有"注入状态"这一列会显示"未知"。
	struct ProcessFacts
	{
		bool PathKnown = false;
		bool TimesKnown = false;
		bool ModuleQueryOk = false;
		bool HasOurDll = false;
		bool IsWow64 = false;
		bool IsProtected = false;
		ULONGLONG WorkingSetBytes = 0;
		ULONGLONG PrivateBytes = 0;
		ULONGLONG CpuTimeMs = 0;
		ULONGLONG CreateTime = 0;
	};

	bool ModuleListHasOurDll(HANDLE process) noexcept
	{
		HMODULE modules[1024] = {};
		DWORD needed = 0;
		if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed,
			LIST_MODULES_ALL)) {
			return false;
		}

		const DWORD count = needed / sizeof(HMODULE);
		for (DWORD i = 0; i < count && i < _countof(modules); i++) {
			WCHAR name[MAX_PATH] = {};
			if (GetModuleBaseNameW(process, modules[i], name, _countof(name)) == 0) {
				continue;
			}
			if (_wcsicmp(name, L"r3shieldcore-lib.dll") == 0) {
				return true;
			}
		}
		return false;
	}

	void QueryFacts(ULONG pid, WCHAR* pathOut, size_t cch, ProcessFacts* facts) noexcept
	{
		*facts = ProcessFacts();
		if (pathOut && cch) {
			pathOut[0] = L'\0';
		}

		// ---- 第一档：完整权限 ----
		HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE, pid);
		bool limited = false;
		if (!process) {
			// ---- 第二档：受限权限 ----
			process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			limited = true;
		}
		if (!process) {
			// 连受限都拿不到（真 PPL / 已退出）。
			facts->IsProtected = true;
			return;
		}

		wil::unique_process_handle owned(process);

		if (pathOut && cch) {
			DWORD size = static_cast<DWORD>(cch);
			if (QueryFullProcessImageNameW(owned.get(), 0, pathOut, &size)
				&& size > 0 && pathOut[0] != L'\0') {
				facts->PathKnown = true;
			}
			else {
				pathOut[0] = L'\0';
			}
		}

		BOOL wow64 = FALSE;
		if (IsWow64Process(owned.get(), &wow64)) {
			facts->IsWow64 = wow64 != FALSE;
		}

		FILETIME create = {};
		FILETIME exit = {};
		FILETIME kernel = {};
		FILETIME user = {};
		if (GetProcessTimes(owned.get(), &create, &exit, &kernel, &user)) {
			facts->TimesKnown = true;
			facts->CreateTime = FileTimeToU64(create);
			facts->CpuTimeMs =
				(FileTimeToU64(kernel) + FileTimeToU64(user)) / 10000ULL;
		}

		PROCESS_MEMORY_COUNTERS_EX memory = {};
		memory.cb = sizeof(memory);
		if (GetProcessMemoryInfo(owned.get(),
			reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory))) {
			facts->TimesKnown = true;
			facts->WorkingSetBytes = memory.WorkingSetSize;
			facts->PrivateBytes = memory.PrivateUsage;
		}

		// 受限档读不了模块表 —— 明确记成"没查过"，界面显示"未知"，
		// 而不是显示"未注入"（那是在没有证据的情况下下结论）。
		if (!limited) {
			facts->ModuleQueryOk = true;
			facts->HasOurDll = ModuleListHasOurDll(owned.get());
		}
	}

	// ------------------------------------------------------------------
	// 挂起记账
	// ------------------------------------------------------------------

	bool IsSuspendedEntry(ULONG pid, ULONGLONG createTime) noexcept
	{
		for (const SuspendedEntry& entry : g_suspended) {
			if (entry.Used && entry.Pid == pid && entry.CreateTime == createTime) {
				return true;
			}
		}
		return false;
	}

	void RememberSuspended(ULONG pid, ULONGLONG createTime) noexcept
	{
		for (SuspendedEntry& entry : g_suspended) {
			if (entry.Used && entry.Pid == pid) {
				entry.CreateTime = createTime;
				return;
			}
		}
		for (SuspendedEntry& entry : g_suspended) {
			if (!entry.Used) {
				entry.Pid = pid;
				entry.CreateTime = createTime;
				entry.Used = true;
				return;
			}
		}
		// 表满：覆盖第一个（环形退化）。32 个同时被挂起的进程已经远超正常使用。
		g_suspended[0].Pid = pid;
		g_suspended[0].CreateTime = createTime;
		g_suspended[0].Used = true;
	}

	void ForgetSuspended(ULONG pid) noexcept
	{
		for (SuspendedEntry& entry : g_suspended) {
			if (entry.Used && entry.Pid == pid) {
				entry = SuspendedEntry();
			}
		}
	}

	ULONG SuspendedCount() noexcept
	{
		ULONG count = 0;
		for (const SuspendedEntry& entry : g_suspended) {
			if (entry.Used) {
				count++;
			}
		}
		return count;
	}

	// ------------------------------------------------------------------
	// 扫描
	// ------------------------------------------------------------------

	void ScanOnce() noexcept
	{
		const ULONGLONG scanStart = GetTickCount64();
		const ULONGLONG now = scanStart;

		wil::unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (!snapshot) {
			g_stats.SnapshotFailures++;
			g_stats.LastError = GetLastError();
			printf("[ark] 枚举进程失败：CreateToolhelp32Snapshot err=%lu\n",
				g_stats.LastError);
			fflush(stdout);
			return;
		}

		std::vector<Row> rows;
		rows.reserve(384);

		std::map<ULONG, CpuSample> samples;

		ULONG noPath = 0;
		ULONG protectedCount = 0;
		ULONG noModules = 0;
		ULONG systemCount = 0;
		ULONG criticalCount = 0;
		ULONG injectedCount = 0;

		PROCESSENTRY32W entry = {};
		entry.dwSize = sizeof(entry);
		if (!Process32FirstW(snapshot.get(), &entry)) {
			g_stats.SnapshotFailures++;
			g_stats.LastError = GetLastError();
			printf("[ark] Process32FirstW 失败 err=%lu\n", g_stats.LastError);
			fflush(stdout);
			return;
		}

		do
		{
			Row row = {};
			row.Pid = entry.th32ProcessID;
			row.ParentPid = entry.th32ParentProcessID;
			row.ThreadCount = entry.cntThreads;
			// `PROCESSENTRY32W` **没有**会话号字段，得单独查。
			// `ProcessIdToSessionId` 不需要进程句柄 ⇒ PPL 也能拿到
			// （会话 0 = 服务会话，这一列对判断"这是不是服务"很有用）。
			{
				DWORD session = 0;
				if (ProcessIdToSessionId(row.Pid, &session)) {
					row.SessionId = session;
				}
			}
			row.Name = entry.szExeFile;
			row.IsCritical = ArkActions::IsCriticalProcessName(entry.szExeFile);

			// pid 0（Idle）与 pid 4（System）是**内核伪进程**：没有映像、
			// 也没有可打开的进程对象。但它们确实"在列表里"，而且是最关键的。
			// ⇒ 不跳过，直接按已知事实填。
			if (row.Pid == 0 || row.Pid == 4) {
				row.IsSystem = true;
				row.IsCritical = true;
				row.PathKnown = false;
				row.TimesKnown = false;
				if (row.Pid == 0 && row.Name.empty()) {
					row.Name = L"[System Process]";
				}
				if (row.Pid == 4 && row.Name.empty()) {
					row.Name = L"System";
				}
			}
			else {
				WCHAR path[MAX_PATH * 2] = {};
				ProcessFacts facts = {};
				QueryFacts(row.Pid, path, _countof(path), &facts);
				if (!facts.PathKnown) {
					noPath++;
				}
				if (facts.IsProtected) {
					protectedCount++;
				}
				if (!facts.ModuleQueryOk) {
					noModules++;
				}

				row.PathKnown = facts.PathKnown;
				if (facts.PathKnown) {
					row.Path = path;
				}
				row.IsWow64 = facts.IsWow64;
				row.IsProtected = facts.IsProtected;
				row.TimesKnown = facts.TimesKnown;
				row.WorkingSetBytes = facts.WorkingSetBytes;
				row.PrivateBytes = facts.PrivateBytes;
				row.CpuTimeMs = facts.CpuTimeMs;
				row.ModuleQueryOk = facts.ModuleQueryOk;
				row.HasOurDll = facts.HasOurDll;

				// ★ 只有**路径可读**时才敢判"系统进程"。
				//   路径读不出来（PPL）时保持 false 并在界面显示"未知" ——
				//   拿"名字像系统进程"去填就是铁律 4/102 那个坑。
				row.IsSystem = row.PathKnown && IsSystemPath(row.Path.c_str());

				// CPU 百分比：与上一轮采样做差。
				if (facts.TimesKnown) {
					CpuSample sample = {};
					sample.CpuTimeMs = facts.CpuTimeMs;
					sample.AtMs = now;
					sample.CreateTime = facts.CreateTime;
					samples[row.Pid] = sample;

					auto previous = g_cpuSamples.find(row.Pid);
					if (previous != g_cpuSamples.end()
						&& previous->second.CreateTime == facts.CreateTime
						&& now > previous->second.AtMs
						&& facts.CpuTimeMs >= previous->second.CpuTimeMs) {
						const ULONGLONG deltaCpu = facts.CpuTimeMs - previous->second.CpuTimeMs;
						const ULONGLONG deltaMs = now - previous->second.AtMs;
						const ULONGLONG denom = deltaMs * (g_cores ? g_cores : 1);
						if (denom > 0) {
							ULONGLONG percentX10 = deltaCpu * 1000ULL / denom;
							// 相对**整机**（任务管理器口径），所以上限 100.0%。
							if (percentX10 > 1000ULL) {
								percentX10 = 1000ULL;
							}
							row.CpuPercentX10 = static_cast<ULONG>(percentX10);
							row.CpuValid = true;
						}
					}
				}

				row.SuspendedByArk = facts.TimesKnown
					&& IsSuspendedEntry(row.Pid, facts.CreateTime);
			}

			if (row.IsSystem) {
				systemCount++;
			}
			if (row.IsCritical) {
				criticalCount++;
			}
			if (row.HasOurDll) {
				injectedCount++;
			}

			rows.push_back(row);
		}
		while (Process32NextW(snapshot.get(), &entry));

		// ---- ★ v63：打分组 + 排序（普通·已注入 → 普通·未注入 → 系统）----
		//
		// 为什么排序放在**引擎侧**而不是界面里：
		//   ① 界面按 `ark_refresh_ms` 反复重绘；在渲染路径上排序 =
		//      每次重绘都排一遍几百行，纯浪费（而且渲染是 GUI 线程，
		//      主循环本来就比它轻）；
		//   ② 排序结果只体现在这一块屏幕上 —— 别的消费者（以后的导出 /
		//      命令行 / 日志）看到的还是乱序。
		//   在这里排一次 = **一份数据只有一种顺序**。
		//
		// `std::stable_sort` + `ArkRowLess`：组内按 pid 升序，稳定，
		// 所以两次扫描之间顺序不会自己抖（抖了用户就点不准）。
		for (Row& row : rows) {
			row.Group = GroupRankOf(row);
		}
		std::stable_sort(rows.begin(), rows.end(), ArkRowLess);

		// ---- 写回（持锁）----
		{
			LockGuard guard;

			// 已经消失的进程：清掉它的挂起记账与 CPU 采样，
			// 否则 pid 复用后会把新进程误标成"已挂起"。
			for (int i = 0; i < static_cast<int>(_countof(g_suspended)); i++) {
				if (!g_suspended[i].Used) {
					continue;
				}
				bool alive = false;
				for (const Row& row : rows) {
					if (row.Pid == g_suspended[i].Pid
						&& row.SuspendedByArk) {
						alive = true;
						break;
					}
				}
				if (!alive) {
					g_suspended[i] = SuspendedEntry();
				}
			}

			g_cpuSamples.swap(samples);
			g_rows.swap(rows);

			g_stats.Scans++;
			g_stats.LastScanProcesses = static_cast<ULONG>(g_rows.size());
			g_stats.LastScanNoPath = noPath;
			g_stats.LastScanProtected = protectedCount;
			g_stats.LastScanNoModules = noModules;
			g_stats.SystemCount = systemCount;
			g_stats.CriticalCount = criticalCount;
			g_stats.InjectedCount = injectedCount;
			g_stats.SuspendedCount = SuspendedCount();
			g_stats.QueueDepth = g_queueCount;
			g_stats.LastScanMs = static_cast<ULONG>(GetTickCount64() - scanStart);
			g_totalScanMs += g_stats.LastScanMs;
		}
	}

	// ------------------------------------------------------------------
	// 处置执行
	// ------------------------------------------------------------------

	void PushRecent(const ActionRecord& record) noexcept
	{
		g_recent[g_recentHead] = record;
		g_recentHead = (g_recentHead + 1) % kRecentCapacity;
		if (g_recentCount < kRecentCapacity) {
			g_recentCount++;
		}
	}

	// 该动作是否属于"被安全边界拒"（而不是执行失败）。
	bool IsRefusal(ArkActions::Result result) noexcept
	{
		return result == ArkActions::Result::RefusedSelf
			|| result == ArkActions::Result::RefusedCritical;
	}

	void ExecuteAction(ULONG pid, ULONG actionValue) noexcept
	{
		if (actionValue > static_cast<ULONG>(ArkActions::Action::ForceKill)) {
			return;
		}
		const ArkActions::Action action =
			static_cast<ArkActions::Action>(actionValue);

		// 动作执行前先把"名字 / 创建时间"读出来 —— 动作之后目标可能就没了，
		// 那时再去查名字只会拿到空（日志里就只剩一个 pid，事后无法回溯）。
		WCHAR name[64] = {};
		ULONGLONG createTime = 0;
		{
			LockGuard guard;
			for (const Row& row : g_rows) {
				if (row.Pid == pid) {
					wcsncpy_s(name, row.Name.c_str(), _TRUNCATE);
					auto sample = g_cpuSamples.find(pid);
					if (sample != g_cpuSamples.end()) {
						createTime = sample->second.CreateTime;
					}
					break;
				}
			}
		}

		const ArkActions::Outcome outcome = ArkActions::Perform(
			pid, action, g_config.SelfPid, g_config.LocalDllBase);

		ActionRecord record = {};
		record.Pid = pid;
		record.Action = actionValue;
		record.Ok = (outcome.Code == ArkActions::Result::Ok);
		record.ElapsedMs = outcome.ElapsedMs;
		record.Win32Error = outcome.Win32Error;
		record.Name = name;
		record.Code = NarrowToWide(ArkActions::ResultCode(outcome.Code));
		record.Text = std::wstring(ArkActions::ActionText(action))
			+ L" → " + ArkActions::ResultText(outcome.Code);

		{
			LockGuard guard;
			g_recentSerial++;
			record.Serial = g_recentSerial;
			PushRecent(record);

			g_stats.ActionRequests++;
			if (record.Ok) {
				g_stats.ActionOk++;
			}
			else if (IsRefusal(outcome.Code)) {
				g_stats.ActionRefused++;
			}
			else {
				g_stats.ActionFailed++;
			}

			// 挂起/恢复记账。只有**成功**才改状态 ——
			// 失败还记账会让界面显示一个不存在的状态（铁律 98）。
			if (record.Ok) {
				if (action == ArkActions::Action::Suspend) {
					RememberSuspended(pid, createTime);
				}
				else if (action == ArkActions::Action::Resume) {
					ForgetSuspended(pid);
				}
				else {
					// 内部退出 / 强制结束：进程要没了，挂起记账跟着清。
					ForgetSuspended(pid);
				}
			}
			g_stats.SuspendedCount = SuspendedCount();
		}

		// 日志一行搞定全部要素。ASCII 结果码在前，方便 grep。
		printf("[ark] 动作 pid=%u 进程=%ls 动作=%ls 结果=%s 耗时=%ums "
			"Win32=%lu DLL=%d/%d\n",
			pid, name[0] ? name : L"(未知)", ArkActions::ActionText(action),
			ArkActions::ResultCode(outcome.Code), record.ElapsedMs, record.Win32Error,
			outcome.DllPresent ? 1 : 0, outcome.DllSameBuild ? 1 : 0);
		fflush(stdout);
	}

	void DrainActions() noexcept
	{
		for (;;) {
			ActionRequest request = {};
			{
				LockGuard guard;
				if (g_queueCount == 0) {
					break;
				}
				request = g_queue[g_queueHead];
				g_queueHead = (g_queueHead + 1) % kQueueCapacity;
				g_queueCount--;
				g_stats.QueueDepth = g_queueCount;
			}
			// ★ 锁外执行：动作最长要等 1.5 秒（等目标退出），
			//   持锁执行会让 GUI 线程的 GetSnapshot 卡住同样长的时间。
			ExecuteAction(request.Pid, request.Action);
		}
	}

	// ------------------------------------------------------------------
	// 心跳
	// ------------------------------------------------------------------

	void PrintHeartbeat() noexcept
	{
		LockGuard guard;
		printf("[ark] 心跳 扫描=%u 本轮进程=%u 本轮耗时=%ums 平均耗时=%ums "
			"无路径=%u 受保护=%u 模块未知=%u 系统进程=%u 关键进程=%u 已注入=%u "
			"已挂起=%u 动作=%u(成功%u/失败%u/拒绝%u/丢弃%u) 队列=%u 快照失败=%u\n",
			g_stats.Scans,
			g_stats.LastScanProcesses,
			g_stats.LastScanMs,
			g_stats.Scans ? static_cast<ULONG>(g_totalScanMs / g_stats.Scans) : 0,
			g_stats.LastScanNoPath,
			g_stats.LastScanProtected,
			g_stats.LastScanNoModules,
			g_stats.SystemCount,
			g_stats.CriticalCount,
			g_stats.InjectedCount,
			g_stats.SuspendedCount,
			g_stats.ActionRequests,
			g_stats.ActionOk,
			g_stats.ActionFailed,
			g_stats.ActionRefused,
			g_stats.ActionDropped,
			g_stats.QueueDepth,
			g_stats.SnapshotFailures);
		fflush(stdout);
	}
}

namespace R3ShieldCoreArk
{
	// ★ 把界面用的整数契约与动作层的枚举**钉死**。
	//   两边顺序一旦不一致，"点挂起"会执行成"点强杀" —— 编译期无提示、
	//   运行期不可逆。static_assert 让它在编译期就炸。
	static_assert(static_cast<int>(ActionSuspend)
		== static_cast<int>(ArkActions::Action::Suspend), "ActionId 顺序与 ArkActions::Action 不一致");
	static_assert(static_cast<int>(ActionResume)
		== static_cast<int>(ArkActions::Action::Resume), "ActionId 顺序与 ArkActions::Action 不一致");
	static_assert(static_cast<int>(ActionInternalExit)
		== static_cast<int>(ArkActions::Action::InternalExit), "ActionId 顺序与 ArkActions::Action 不一致");
	static_assert(static_cast<int>(ActionForceKill)
		== static_cast<int>(ArkActions::Action::ForceKill), "ActionId 顺序与 ArkActions::Action 不一致");

	void Start(const Config& config) noexcept
	{
		Stop();

		// 临界区在 `Lock()` 里按需初始化、永不销毁（见上面的说明）。
		g_initialized.store(true, std::memory_order_release);

		g_config = config;

		// %SystemRoot%：判"系统进程"要用。取不到就**如实标未知**
		// （不启用整套功能是不对的 —— ARK 的主要用途是列进程 + 处置，
		//  只有"系统进程"那一列会退化成"未知"）。
		const UINT rootLength = GetWindowsDirectoryW(g_systemRoot, _countof(g_systemRoot));
		if (rootLength == 0 || rootLength >= _countof(g_systemRoot)) {
			g_systemRoot[0] = L'\0';
			g_systemRootLength = 0;
		}
		else {
			g_systemRootLength = rootLength;
		}

		SYSTEM_INFO info = {};
		GetSystemInfo(&info);
		g_cores = info.dwNumberOfProcessors ? info.dwNumberOfProcessors : 1;

		ULONG interval = config.ScanIntervalMs;
		if (interval < kMinScanIntervalMs) {
			interval = kMinScanIntervalMs;
		}
		if (interval > kMaxScanIntervalMs) {
			interval = kMaxScanIntervalMs;
		}
		g_stats = Stats();
		g_stats.ScanIntervalMs = interval;
		g_stats.SystemRootKnown = g_systemRootLength != 0;
		g_stats.SelfExitSupported = config.SelfExitSupported;
		g_stats.SelfPidOfEngine = config.SelfPid;

		if (config.Level == 0) {
			// 关闭也要说一句 —— 否则"用户配了 0"与"配置没读进来"
			// 在日志里长得一样（铁律 97）。
			printf("[ark] 未启用：ark_enabled=0（界面上的 ARK 页签仍会显示，"
				"但列表不刷新、动作不可用）\n");
			fflush(stdout);
			g_started = false;
			g_stats.Started = false;
			return;
		}

		g_started = true;
		g_stats.Started = true;
		g_stats.Enabled = true;
		g_lastScanMs = 0;
		g_lastHeartbeatMs = 0;

		// ★ 铁律 97：首行立即打，把"这套东西拿到的到底是什么"写清楚。
		printf("[ark] 已启用 扫描间隔=%ums 本进程 pid=%lu DLL基址=0x%llX "
			"内部退出=%s systemRoot=%ls 核心数=%u 动作=挂起/恢复/内部退出/强制结束 "
			"拒绝名单=本进程 + 关键系统进程（结束会蓝屏 / 挂起会卡死）\n",
			g_stats.ScanIntervalMs,
			config.SelfPid,
			static_cast<unsigned long long>(config.LocalDllBase),
			config.SelfExitSupported ? "可用" : "不可用（DLL 缺 GlobalHookSessionSelfExit）",
			g_systemRootLength ? g_systemRoot : L"(取不到)",
			g_cores);
		fflush(stdout);

		// 立刻扫一轮：界面一打开就有内容，不用等一个间隔。
		ScanOnce();
		PrintHeartbeat();
	}

	void Stop() noexcept
	{
		if (!g_initialized.load(std::memory_order_acquire)) {
			return;
		}

		if (g_started) {
			printf("[ark] 已停止 扫描=%u 动作=%u(成功%u/失败%u/拒绝%u)\n",
				g_stats.Scans, g_stats.ActionRequests, g_stats.ActionOk,
				g_stats.ActionFailed, g_stats.ActionRefused);
			fflush(stdout);
		}

		// ★ 退出前把**本引擎挂起过**的进程恢复回去。
		//
		//   不恢复的后果很严重：引擎一关，那些进程就永远冻在那儿，
		//   用户不知道是谁干的，也找不到"恢复"按钮（引擎都没了）。
		//   这是"动作的记账单位（引擎会话）结束"时**必须**做的收尾。
		ULONG resumed = 0;
		ULONG failed = 0;
		for (const SuspendedEntry& entry : g_suspended) {
			if (!entry.Used) {
				continue;
			}
			const ArkActions::Outcome outcome = ArkActions::Perform(
				entry.Pid, ArkActions::Action::Resume, g_config.SelfPid, 0);
			if (outcome.Code == ArkActions::Result::Ok) {
				resumed++;
			}
			else if (outcome.Code != ArkActions::Result::ProcessGone) {
				// "进程已经不在"不算失败 —— 它自己退了。
				failed++;
			}
		}
		if (resumed || failed) {
			printf("[ark] 停止前恢复挂起：成功=%u 失败=%u（失败的多半是已退出）\n",
				resumed, failed);
			fflush(stdout);
		}

		g_started = false;
		g_config = Config();
		g_systemRoot[0] = L'\0';
		g_systemRootLength = 0;
		g_lastScanMs = 0;
		g_lastHeartbeatMs = 0;

		// 清状态必须在锁内，且**不能**把上面那段 `Perform(Resume)` 包进来
		// —— 它最长要等 1.5 秒，持锁会让 GUI 线程的 `GetSnapshot`
		// 卡住同样长的时间。
		//
		// ⚠️ 临界区**不删除**（见 `Lock()` 的说明）：GUI 线程随时可能正在
		//    `GetSnapshot` 里，删掉它 = 让对面 Enter 一个已删除的临界区。
		{
			LockGuard guard;
			g_rows.clear();
			g_cpuSamples.clear();
			g_queueHead = 0;
			g_queueCount = 0;
			g_recentHead = 0;
			g_recentCount = 0;
			g_recentSerial = 0;
			g_totalScanMs = 0;
			for (SuspendedEntry& entry : g_suspended) {
				entry = SuspendedEntry();
			}
			g_stats = Stats();
		}

		g_initialized.store(false, std::memory_order_release);
	}

	bool IsEnabled() noexcept
	{
		return g_started && g_stats.Enabled;
	}

	void Tick() noexcept
	{
		if (!g_initialized.load(std::memory_order_acquire)) {
			return;
		}

		// ★ 动作队列**先于**扫描处理：用户点了按钮就该尽快生效，
		//   不该等下一轮扫描（而且扫描本身还要持锁写回）。
		if (g_started) {
			DrainActions();
		}

		if (!g_started) {
			return;
		}

		const ULONGLONG now = GetTickCount64();
		if (g_lastScanMs != 0 && (now - g_lastScanMs) < g_stats.ScanIntervalMs) {
			return;
		}
		g_lastScanMs = now;

		ScanOnce();

		if (g_lastHeartbeatMs == 0 || (now - g_lastHeartbeatMs) >= kHeartbeatMs) {
			g_lastHeartbeatMs = now;
			PrintHeartbeat();
		}
	}

	Snapshot GetSnapshot() noexcept
	{
		Snapshot snapshot;
		if (!g_initialized.load(std::memory_order_acquire)) {
			return snapshot;
		}

		LockGuard guard;
		snapshot.Rows = g_rows;
		snapshot.Stat = g_stats;
		snapshot.Stat.SuspendedCount = SuspendedCount();
		snapshot.Stat.QueueDepth = g_queueCount;
		return snapshot;
	}

	void RequestAction(ULONG pid, ULONG action) noexcept
	{
		if (!g_initialized.load(std::memory_order_acquire)) {
			return;
		}

		LockGuard guard;
		if (g_queueCount >= kQueueCapacity) {
			// 丢弃并计数。**不阻塞 GUI 线程** —— 界面卡住比丢一个请求更糟。
			g_stats.ActionDropped++;
			printf("[ark] 动作请求队列已满（%u），丢弃 pid=%u 动作=%u\n",
				kQueueCapacity, pid, action);
			fflush(stdout);
			return;
		}

		const ULONG tail = (g_queueHead + g_queueCount) % kQueueCapacity;
		g_queue[tail].Pid = pid;
		g_queue[tail].Action = action;
		g_queueCount++;
		g_stats.QueueDepth = g_queueCount;
	}

	std::vector<ActionRecord> GetRecentActions() noexcept
	{
		std::vector<ActionRecord> records;
		if (!g_initialized.load(std::memory_order_acquire)) {
			return records;
		}

		LockGuard guard;
		records.reserve(g_recentCount);
		// 新的在前。
		for (ULONG i = 0; i < g_recentCount; i++) {
			const ULONG index = (g_recentHead + kRecentCapacity - 1 - i) % kRecentCapacity;
			records.push_back(g_recent[index]);
		}
		return records;
	}

	const wchar_t* ActionText(ULONG action) noexcept
	{
		if (action > static_cast<ULONG>(ArkActions::Action::ForceKill)) {
			return L"未知动作";
		}
		return ArkActions::ActionText(static_cast<ArkActions::Action>(action));
	}

	const wchar_t* ResultText(ULONG result) noexcept
	{
		return ArkActions::ResultText(static_cast<ArkActions::Result>(result));
	}
}
