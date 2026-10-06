#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

#include <filesystem>
#include <string>
#include <vector>

//
// 事件统计聚合。挂在 EngineControl::DrainEvents 的回调链上累加，
// 供 GUI 面板渲染。
//
// 不持有任何内核/共享内存资源 —— 纯内存计数，随时可清空。
//
namespace R3ShieldCoreStats
{
	// 每个进程的计数。
	struct ProcessStat
	{
		ULONG ProcessId;
		ULONG Total;
		ULONG Blocked;     // 被 R3ShieldCore 主动拒绝
		ULONG WouldBlock;  // LOG 模式下本应拒绝
		std::wstring Name; // 进程名（含扩展名，从镜像路径取）
		std::wstring Path; // 完整镜像路径（能取到时）
	};

	// 全量统计快照。GUI 每帧渲染一份。
	struct Snapshot
	{
		ULONGLONG StartTick;

		ULONGLONG TotalEvents;
		ULONG OpCounts[32];              // 按 R3ShieldCore::Op 索引
		ULONG DecisionCounts[4];         // 按 R3ShieldCore::Decision 索引
		ULONG TargetKindCounts[2];       // 按 R3ShieldCore::TargetKind 索引
		ULONG ObjectTypeCounts[16];      // 按 R3ShieldCore::ObjectType 索引（0..14，留一倍余量）

		// 文件操作单独一份计数（FileOp 是另一套枚举，不能混进 OpCounts）。
		ULONG FileOpCounts[16];

		// 进程 / 线程 / 驱动 / 网络 / 摄像头 / 输入钩子 / 截屏各自一套计数。
		ULONG ProcessOpCounts[8];
		ULONG ThreadOpCounts[8];
		ULONG DriverOpCounts[8];
		ULONG NetworkOpCounts[8];
		ULONG CameraOpCounts[8];
		ULONG InputHookOpCounts[8];
		ULONG ScreenOpCounts[8];

		// DLL 加载 / 剪贴板 / 进程创建旁路各自一套计数（v10）。
		ULONG DllLoadOpCounts[8];
		ULONG ClipboardOpCounts[8];
		ULONG SpawnOpCounts[8];

		// 服务 / 安全对象权限变更（v11）。
		ULONG ServiceConfigOpCounts[8];

		// COM 激活劫持 / 计划任务持久化（v12）。
		ULONG ComOpCounts[8];
		ULONG ScheduledTaskOpCounts[8];

		ULONG BlockedByUs;    // FlagEventBlocked 置位的事件数
		ULONG HighRiskEvents; // FlagEventHighRisk 置位的事件数
		ULONG UniqueProcesses;
		ULONG DroppedEvents;  // 环形缓冲丢弃数
		ULONG LastSecondEvents; // 最近一秒的事件速率

		std::vector<ProcessStat> TopProcesses; // 按 Total 降序，最多 8 条
	};

	// 询问通道的统计 —— 与事件统计分开记，因为一次询问可能对应多条事件。
	struct PromptStat
	{
		ULONG Shown;         // 弹窗次数
		ULONG Allowed;       // 点了"允许这一次"/"始终允许"
		ULONG Denied;        // 点了"拒绝这一次"/"始终拒绝"
		ULONG TimedOut;      // 倒计时走完
		ULONG HighRiskAsked;   // 其中因为是高危而弹窗的次数
		ULONG HighRiskBlocked; // 高危操作最终被拒的次数
	};

	// -----------------------------------------------------------------
	// 日志环形缓冲
	// -----------------------------------------------------------------
	// 与统计计数并存：统计只累加，日志保留原始明细。
	// 事件流是"生产者多、消费者单"（各注入进程写、引擎一个线程读），
	// 但引擎把这个回调也用来喂统计，所以这里只被引擎主线程写、
	// GUI 线程读 —— 一把锁足够。
	//
	// 满了覆盖最旧的，不做扩容：日志是"最近发生了什么"，
	// 保留全部历史只会吃内存，而且用户要看的本来就只有尾部。
	constexpr size_t LogCapacity = 2000;

	struct LogEntry
	{
		ULONG Serial;       // 全局递增序号（从 1 开始），GUI 用来判断是否有新行
		LONG64 TimeStamp;   // FILETIME，绘制时转成本地时间
		ULONG ProcessId;
		ULONG ObjectType;   // R3ShieldCore::ObjectType —— 决定 Op 按哪套枚举解释
		ULONG Op;           // R3ShieldCore::Op 或 R3ShieldCore::FileOp
		ULONG Decision;     // R3ShieldCore::Decision
		ULONG Status;       // 原始 NTSTATUS
		ULONG Flags;        // R3ShieldCore::FlagEvent*
		ULONG TargetProcessId; // 进程/线程事件的 pid（进程=新建的，线程=被注入的）
		bool BlockedByUs;   // FlagEventBlocked
		bool IsHive;
		bool IsHighRisk;    // FlagEventHighRisk —— 命中了高危规则
		std::wstring ProcessName; // 进程名，取不到就空
		std::wstring Target;      // 键路径 / 文件路径 / hive 文件路径
		std::wstring Value;       // 值名（键级）/ hive 文件（hive 级）/ 新文件名（改名）
	};

	// 一次批量取回的日志区块。GUI 传上一次拿到的 Serial，只取更新的部分。
	struct LogChunk
	{
		std::vector<LogEntry> Entries; // 按时间升序
		ULONG LatestSerial;            // 当前最新序号（下次传回来）
		ULONG TotalWritten;            // 累计写过多少条（含被覆盖的）
	};

	void Reset() noexcept;

	// 事件计数。在 Drain 回调里每条调用一次。
	void OnEvent(const R3ShieldCore::Event& event) noexcept;

	// 从引擎读丢弃计数（引擎主循环里定期同步）。
	void SetDroppedCount(ULONG dropped) noexcept;

	// -----------------------------------------------------------------
	// ★ v61：高危进程提示的统计
	// -----------------------------------------------------------------
	//
	// 与 PromptStat 一样，真正干活的是 `R3ShieldCoreProcWatch`（引擎侧周期扫描），
	// 主循环把它的快照读回来推给这里，GUI 线程只读。
	//
	// 为什么不用事件通道：本功能的判据跑在**引擎进程自己**里（全机进程快照），
	// 不经过任何被注入进程 —— 没有"事件"可投递，它本来就不是 hook 的产物。
	struct ProcWatchStat
	{
		ULONG Scans = 0;              // 已完成的扫描轮数
		ULONG LastScanProcesses = 0;  // 最近一轮枚举到的进程数
		ULONG HighRiskFound = 0;      // 累计发现的高危进程数（去重后）
		ULONG Alerts = 0;             // 累计打出的告警条数
		ULONG DedupEntries = 0;       // 去重表占用
		ULONG DedupCapacity = 0;      // 去重表容量

		// 最近一条告警的明细（界面底部栏显示用）。
		ULONG LatestPid = 0;
		std::wstring LatestName;
		std::wstring LatestPath;
		std::wstring LatestReason;
	};

	// 询问统计由主循环从 DLL 读回来后推给这里（GUI 线程只读）。
	void SetPromptStat(const PromptStat& stat) noexcept;

	// ★ v61：高危进程统计同样由主循环推给这里。
	void SetProcWatchStat(const ProcWatchStat& stat) noexcept;

	Snapshot GetSnapshot() noexcept;
	PromptStat GetPromptStat() noexcept;
	ProcWatchStat GetProcWatchStat() noexcept;

	// 取序号 > sinceSerial 的日志条目（最多 maxCount 条，取最新的那批）。
	// 返回的 LatestSerial 下次原样传回来即可增量读取。
	//
	// 如果 sinceSerial 太旧、对应的行已被环形缓冲覆盖，会返回一批
	// "从最旧可用开始" 的条目，GUI 靠 Serial 连续性自己判断要不要重置视图。
	LogChunk GetLogsSince(ULONG sinceSerial, size_t maxCount) noexcept;

	// 当前最新序号（用于首次打开日志页时定位到尾部）。
	ULONG GetLatestLogSerial() noexcept;

	// -----------------------------------------------------------------
	// ★ v62：ARK 页"该进程最近的事件"
	// -----------------------------------------------------------------
	//
	// 按 pid 过滤日志环，取**最新的** maxCount 条（返回按时间升序，
	// 和 GetLogsSince 一致，方便界面按同样方式渲染）。
	//
	// 为什么不复用 GetLogsSince：那个是按 Serial 增量取的，用于"实时流"；
	// 这里要的是"某个进程的历史尾部" —— 过滤器不同、遍历方向也不同
	// （必须从新往旧扫，否则慢进程永远挤不进前 N 条）。
	//
	// ⚠️ pid 复用：日志里的 pid 是**当时**的 pid。引擎重启后 pid 会被复用，
	//    所以这个列表只能当"线索"看，不能当"这个进程干过什么"的定论。
	std::vector<LogEntry> GetLogsForPid(ULONG pid, size_t maxCount) noexcept;

	// -----------------------------------------------------------------
	// ★ v54：历史事件回放（跨重启保留事件列表）
	// -----------------------------------------------------------------
	//
	// 背景：引擎每次启动序列号都从 1 开始，界面事件列表**启动即空**。
	// 用户点「超级置顶」会整体换引擎（见 r3shieldcore_gui.cpp ApplyTopMostLevel
	// 的 UIAccess 接管路径），于是"刚点完置顶，事件列表就空了"。
	//
	// 做法：启动时把 `r3shieldcore-events.log` 的尾部若干条**预填进日志环**，
	// 占用 Serial 1..N；之后的实时事件从 N+1 继续。
	//
	// ⚠️ 为什么必须占 Serial 1..N、而不是另开一段：
	//   GUI 的 `RefreshLogRows()` 靠 Serial **连续性**判断是否要重置视图
	//   （见 r3shieldcore_gui.cpp：`chunk.Entries.front().Serial > g_logLastSerial + 1`
	//   就 clear）。另开一段（比如负数或大偏移）会让每一次实时事件都触发
	//   一次全量 clear ⇒ 表现是"列表每来一条就闪一下、历史全丢"。
	//   占住 1..N 是唯一**不用改 GUI 一行**就能接上的做法。
	//
	// 必须在 `SetEventObserver` 之前、任何实时事件到达之前调用一次。
	// 重复调用会被忽略（历史已经灌过了）。
	void SeedHistory(const std::vector<LogEntry>& entries,
		ULONGLONG baselineTotalEvents) noexcept;

	// 已灌入的历史条数（0 = 没灌 / 已关）。GUI 用来决定要不要画分隔横幅。
	size_t HistoryCount() noexcept;

	// -----------------------------------------------------------------
	// ★ v54：统计落盘（跨重启累计）
	// -----------------------------------------------------------------
	//
	// 把累计计数写进 `path`（JSON，自己手写 —— 格式极简，引第三方库不值当），
	// 下次启动由 `EnablePersistence` 载入，让概览行的数字不归零。
	//
	// ⚠️ 存的是**累计值**。界面另外显示"本次"增量（GetSessionSnapshot），
	//    所以不会把上一轮的成果冒充成本轮的。
	//
	// ⚠️ 落盘用「临时文件 + MoveFileEx(REPLACE_EXISTING)」原子替换，
	//    避免引擎正好在写的时候被 kill 掉，留下一个半截 JSON 让下次启动解析失败。
	void EnablePersistence(const std::filesystem::path& path) noexcept;

	// 立刻写一次（引擎正常退出时调；运行期每 30s 也调一次兜底）。
	// 未 EnablePersistence 时是 no-op。
	void SaveNow() noexcept;

	// 上次落盘时的总事件数（没落过盘返回 0）。回放的统计基线用它。
	ULONGLONG PersistedTotalEvents() noexcept;

	// 本次会话（本进程）的增量快照 —— 与 GetSnapshot 的区别是
	// 那些计数器**不含**历史基线。界面用它显示"（本次 +N）"。
	Snapshot GetSessionSnapshot() noexcept;

	// -----------------------------------------------------------------
	// 注入进程数的持久化基值
	// -----------------------------------------------------------------
	//
	// `injectedTotal` 是 app.cpp 主循环里的局部 atomic（注入线程累加）。
	// 落盘时它要跟着统计一起存，载入时要垫回起点，
	// 所以放在这里做一个共享的小状态 —— 不值得为它单开一个模块。
	void SetInjectedBase(ULONG value) noexcept;
	ULONG GetInjectedBase() noexcept;

} // namespace R3ShieldCoreStats
