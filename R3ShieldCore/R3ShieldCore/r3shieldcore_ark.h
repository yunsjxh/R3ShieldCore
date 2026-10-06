#pragma once

#include <windows.h>

#include <string>
#include <vector>

//
// ★ v62 ARK（Anti-Rootkit 视图 + 处置）
//
// ------------------------------------------------------------------
// 为什么单独成模块
// ------------------------------------------------------------------
// 引擎已有的「进程」页（`R3ShieldCoreStats::TopProcesses`）只列**产生过事件的**
// 进程 —— 那是"hook 的副产品"，覆盖面取决于注入覆盖与观测窗。
// ARK 要的是**另一件事**：不管有没有事件、不管是不是引擎启动前就在跑的，
// 把**全机进程**列出来，并且能对其中任意一个动手。
//
// 数据来源只有一条：`CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`。
// 它不需要打开进程就能拿到 pid / 父 pid / 映像名 / 线程数，
// 所以**受保护进程（PPL）也能列出来** —— 这是"列全"的关键。
// 其余字段（路径 / CPU / 内存 / 模块表）靠打开进程补，取不到的**如实标未知**，
// 不用"名字像系统进程"这种猜测去填（铁律 4/102：只看名字 = 假判）。
//
// ------------------------------------------------------------------
// 处置动作走 `ArkActions`（同目录 ark_actions.h）
// ------------------------------------------------------------------
//   · 挂起 / 恢复：NtSuspendProcess / NtResumeProcess
//   · 内部退出：在目标里执行**我们那份 DLL** 的 `GlobalHookSessionSelfExit`
//   · 强制结束：TerminateProcess
//
// ★ 动作**不在 GUI 线程里执行**。GUI 只把请求压进队列，引擎主循环
//   （`Tick`）取出执行。理由：
//     - `InternalExit` 内部最长要等 1.5 秒（等目标退出），
//       GUI 线程卡 1.5 秒 = 窗口"未响应"；
//     - 动作会改全机进程状态，而 GUI 线程同时在渲染快照 —— 放在同一个
//       线程里做，"快照"和"现实"之间就没有明确的先后关系了。
//
// ------------------------------------------------------------------
// 可诊断性（铁律 97：布尔判定 = 不可诊断）
// ------------------------------------------------------------------
//   · `Start()` 无论启用与否都打一行（级别 / 间隔 / 本地 DLL 基址 /
//     自退出导出是否可用）。
//   · 心跳（60s）：扫描轮数 / 本轮进程数 / 无路径数 / 受保护数 /
//     系统进程数 / 关键进程数 / 已注入数 / 已挂起数 / 动作统计 / 队列深度。
//   · 每次动作单独一行，带 **ASCII 结果码**（`OK` / `REFUSED_CRITICAL` /
//     `DLL_NOT_LOADED` …）—— r3shieldcore-console.log 是 GBK，ASCII 码能直接 grep。
//   · 扫描**失败**（快照建不出来）单独计数并打一行，不静默。
//
namespace R3ShieldCoreArk
{
	// 一个进程在界面上的全部信息。
	struct Row
	{
		ULONG Pid = 0;
		ULONG ParentPid = 0;
		ULONG ThreadCount = 0;
		ULONG SessionId = 0;

		// 内存 / CPU。取不到时保持 0，靠 `TimesKnown` 区分
		// "真的是 0" 与 "读不出来"。
		ULONGLONG WorkingSetBytes = 0;
		ULONGLONG PrivateBytes = 0;
		ULONGLONG CpuTimeMs = 0;
		ULONG CpuPercentX10 = 0;   // 占用 ×10（0.1% 精度，整数便于比较）
		bool TimesKnown = false;   // CPU / 内存读到了
		bool CpuValid = false;     // 有上一轮基准，百分比才有意义（首轮必然 false）

		bool PathKnown = false;    // 拿到了完整映像路径
		bool IsWow64 = false;      // 32 位进程跑在 64 位系统上
		bool IsProtected = false;  // 连 PROCESS_QUERY_LIMITED_INFORMATION 都拿不到
		bool IsSystem = false;     // 映像在 %SystemRoot% 之下（路径可读时才可信）
		bool IsCritical = false;   // 结束会蓝屏 / 挂起会卡死（按映像名判）
		bool HasOurDll = false;    // 模块表里有 r3shieldcore-lib.dll
		bool ModuleQueryOk = false;// 模块表查过了（权限不足时为 false ⇒ 注入状态未知）
		bool SuspendedByArk = false; // 本引擎通过 ARK 挂起过它（"恢复"可达）

		// ★ v63：列表分组。0 = 普通·已注入 / 1 = 普通·未注入 / 2 = 系统进程。
		//   由 `GroupRankOf()` 算出，扫描时写进每一行；`Snapshot::Rows`
		//   已经按 (Group, Pid) 排好序 —— 界面**不需要**自己再排一遍。
		//   把它存成字段而不是"渲染时现算"：这样界面、单测、以后的导出
		//   看到的是**同一个结论**，而不是各自实现一遍判据。
		ULONG Group = 0;

		std::wstring Name;         // 映像名（Toolhelp，PPL 也有）
		std::wstring Path;         // 完整路径（可能为空）
	};

	// ------------------------------------------------------------------
	// ★ v63：列表分组判据（纯函数 —— 放在头里是为了让单测能直接钉住它）
	// ------------------------------------------------------------------
	// 顺序：① 普通·已注入 → ② 普通·未注入 → ③ 系统进程。
	//
	// 为什么"已注入"排最前：这才是用户在这个页面上**最常找的东西** ——
	//   引擎到底覆盖到了哪些进程、有没有漏。系统进程放最后，因为它们
	//   数量稳定、而且绝大多数情况下不需要动手（关键进程还会被直接拒）。
	//
	// ★ 判据只用**已经算出来的事实**，不引入新的猜测：
	//   `IsSystem` 的定义已经是"映像在 %SystemRoot% 之下（路径可读时才可信）"。
	//   路径读不出来时 `IsSystem=false` ⇒ 归"普通" —— 这是**刻意**的：
	//   宁可让它混在普通进程里（用户在界面上能看到它的路径是"未知"），
	//   也不要凭"名字像系统进程"把它塞进系统组（铁律 4/102：只看名字 = 假判）。
	//
	// ★ `ModuleQueryOk=false`（模块表读不出，例如 PPL）时 `HasOurDll` 是 false，
	//   但语义是"**未知**"而不是"确认没有"。它同样归第 ② 组 —— 分组只决定
	//   **排序**，不改变界面上的标记（界面照旧把注入状态显示成"?"）。
	inline ULONG GroupRankOf(const Row& row) noexcept
	{
		if (row.IsSystem) {
			return 2;
		}
		return row.HasOurDll ? 0 : 1;
	}

	// 列表顺序：先按分组，组内按 pid 升序。
	// ★ 组内用 pid 而不是名字：pid 是这一轮扫描里唯一的稳定键，
	//   按名字排会在"同名进程"（多开浏览器、svchost 的多个实例）之间
	//   产生不确定的顺序，列表每轮自己抖，用户根本点不准。
	inline bool ArkRowLess(const Row& a, const Row& b) noexcept
	{
		const ULONG groupA = GroupRankOf(a);
		const ULONG groupB = GroupRankOf(b);
		if (groupA != groupB) {
			return groupA < groupB;
		}
		return a.Pid < b.Pid;
	}

	// 一次处置的记录。界面用来显示"上一次操作的结果"。
	struct ActionRecord
	{
		ULONG Serial = 0;
		ULONG Pid = 0;
		ULONG Action = 0;       // ArkActions::Action
		bool Ok = false;
		ULONG ElapsedMs = 0;
		ULONG Win32Error = 0;
		std::wstring Name;
		std::wstring Text;      // 例："挂起 → 成功"
		std::wstring Code;      // ASCII 结果码（日志/界面同源）
	};

	struct Stats
	{
		bool Started = false;
		bool Enabled = false;
		ULONG ScanIntervalMs = 0;
		bool SystemRootKnown = false;
		bool SelfExitSupported = false;

		// 引擎自己的 pid。界面用它把"这一行就是我自己"标出来并置灰按钮 ——
		// 光靠名字判会误伤（用户可能把引擎 exe 复制一份改名）。
		ULONG SelfPidOfEngine = 0;

		ULONG Scans = 0;
		ULONG LastScanProcesses = 0;   // 本轮列出的进程数
		ULONG LastScanMs = 0;          // 本轮耗时（**只用于展示**，不参与判据）
		ULONG LastScanNoPath = 0;
		ULONG LastScanProtected = 0;
		ULONG LastScanNoModules = 0;

		ULONG SystemCount = 0;
		ULONG CriticalCount = 0;
		ULONG InjectedCount = 0;
		ULONG SuspendedCount = 0;

		ULONG ActionRequests = 0;   // 收到多少次请求
		ULONG ActionOk = 0;
		ULONG ActionFailed = 0;
		ULONG ActionRefused = 0;    // 被安全边界拒（自己 / 关键进程）
		ULONG ActionDropped = 0;    // 队列满丢弃
		ULONG QueueDepth = 0;

		// 快照/枚举层面的失败，单独计数 —— "列不出来"与"列出来是空的"必须分得开。
		ULONG SnapshotFailures = 0;
		ULONG LastError = 0;
	};

	struct Snapshot
	{
		std::vector<Row> Rows;
		Stats Stat;
	};

	struct Config
	{
		ULONG Level = 0;               // 0 = 关，非 0 = 开
		ULONG ScanIntervalMs = 2000;
		DWORD SelfPid = 0;
		ULONG_PTR LocalDllBase = 0;    // 引擎加载的那份 DLL 的基址
		bool SelfExitSupported = false;// DLL 里有没有 GlobalHookSessionSelfExit
	};

	// ------------------------------------------------------------------
	// 处置动作的整数契约
	// ------------------------------------------------------------------
	// ★ 刻意**不**在界面里复用 `ArkActions::Action`：
	//   GUI 不该 include `ark_actions.h` —— 那是引擎的动作层，
	//   里面是 OpenProcess / CreateRemoteThread 这些东西，跟渲染毫无关系。
	//   这里给出一份稳定的整数契约，并在 `r3shieldcore_ark.cpp` 用 static_assert
	//   把两边的顺序**钉死**（顺序一错，"点挂起"会变成"点强杀"，
	//   而且编译期毫无提示 —— 这正是必须钉住它的理由）。
	enum ActionId
	{
		ActionSuspend = 0,
		ActionResume = 1,
		ActionInternalExit = 2,
		ActionForceKill = 3,
		ActionCount = 4,
	};

	// 启动 / 停止。`Start` 无论启用与否都会在 r3shieldcore-console.log 打一行。
	void Start(const Config& config) noexcept;
	void Stop() noexcept;
	bool IsEnabled() noexcept;

	// 引擎主循环定期调用：按间隔刷新快照，并**执行待处理的处置动作**。
	void Tick() noexcept;

	// 取一份完整快照（含统计）。GUI 线程调用，内部加锁。
	Snapshot GetSnapshot() noexcept;

	// ------------------------------------------------------------------
	// 处置：GUI 线程 → 引擎主循环
	// ------------------------------------------------------------------
	// GUI 线程只压请求，绝不自己执行。队列满时丢弃并计数（不阻塞界面）。
	// `action` 是 `ArkActions::Action` 的整数值。
	void RequestAction(ULONG pid, ULONG action) noexcept;

	// 最近若干条处置记录（新的在前）。
	std::vector<ActionRecord> GetRecentActions() noexcept;

	// 把 `ArkActions::Action` / `Result` 转成界面文字。
	// 转发到 `ArkActions` 的实现，放在这里是为了让 GUI 只依赖本模块。
	const wchar_t* ActionText(ULONG action) noexcept;
	const wchar_t* ResultText(ULONG result) noexcept;
}
