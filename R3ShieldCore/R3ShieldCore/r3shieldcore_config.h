#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>
#include <filesystem>

//
// 读取 exe 同目录下的 r3shieldcore.ini，填充共享内存里的策略块。
// 文件不存在时用安全默认值：LOG 模式、不挂读操作、日志落在 exe 同目录。
//
// 格式：
//   # 井号或分号开头是注释
//   mode=log            ; log | block | ask | block_all
//   hook_reads=0        ; 1 = 连读操作一起记录（噪音很大）
//   log_all_open=0      ; 1 = NtOpenKey 无论读写意图都记录
//   hook_hive=1         ; 1 = 挂 hive 级操作（Load/Save/Restore/Replace），默认开
//   hook_set_info=1     ; 1 = 挂 NtSetInformationKey，默认开
//   log=r3shieldcore-events.log
//   exclude=C:\Tools    ; 可重复，前缀匹配
//
namespace R3ShieldCoreConfig
{
	// ------------------------------------------------------------------
	// ★ v66：**配置文件的真实路径**。
	// ------------------------------------------------------------------
	//
	// 查找顺序（见 r3shieldcore_config.cpp 的实现注释）：
	//   ① `%ProgramData%\R3 Shield Core\r3shieldcore.ini` —— 安装程序铺的，
	//      只对该目录授了 `Users:(OI)(CI)M`，普通用户能直接改、能保存。
	//   ② 回退 `exeDirectory\r3shieldcore.ini` —— 绿色包 / v65 及以前的旧安装。
	//
	// ★ `Load` / `SaveMode` / `LoadEngineSettings` 三个入口**都**走它 ——
	//   保证"读哪份就写哪份"，不会出现"改了不生效"。
	// ★ app.cpp 的启动横幅会把它印出来（诊断口径 ≥ 触发口径，铁律 99）：
	//   用户看到"配置文件 : <路径>"就知道该改哪个文件。
	std::filesystem::path ResolveConfigPath(const std::filesystem::path& exeDirectory);

	void Load(R3ShieldCore::Policy& policy, const std::filesystem::path& exeDirectory);

	// 模式 → ini 里那个值（"log" / "block" / "ask" / "block_all"）。
	// 认不出来时返回 nullptr。
	const char* ModeIniText(ULONG mode) noexcept;

	// 把**生效的那份** r3shieldcore.ini 里的 `mode=` 改成新值（界面按钮切换后
	// 调用，让切换结果活过下次重启）。路径由 ResolveConfigPath 决定。
	//
	// 只重写那一行，其余字节原样保留 —— 这个文件里有大段中文说明，
	// 整文件重排既没必要也容易把编码搞坏。
	// 返回 false = 文件打不开或写不进去（此时运行期切换仍然有效，只是不持久）。
	bool SaveMode(ULONG mode, const std::filesystem::path& exeDirectory);

	//
	// 引擎侧（非 DLL 共享）开关。这些只影响**引擎进程自身**的主动行为，
	// 不进 Policy 共享内存，所以放在这里而不是 R3ShieldCore::Policy。
	//
	struct EngineSettings
	{
		// 反制全屏置顶覆盖层（反锁屏勒索 / 假 UAC / 覆盖层攻击）。
		//
		//   ini `neutralize_overlay=`  含义
		//     0                        关闭
		//     1                        开启，反制时**不问**（每级直接执行）
		//     2                        开启，每级执行前**弹窗询问**（居中置顶）
		//
		// ⚠️ 旧版这是个 bool（0/1），语义向后兼容：`1` 仍是“开且不问”。
		//    默认 **2（询问）** —— 因为 ④⑤ 两级会**结束目标进程**，
		//    静默杀进程对正常全屏程序（游戏/播放器）代价太大。
		//
		// ★ v59：级别 2 下「用户点跳过」与「超时无人应答」**分开处理** ——
		//    超时**不是**拒绝（覆盖层很可能把弹窗盖住），会重试，连续
		//    kMaxAskTimeouts(3) 次无应答才放弃。详见 r3shieldcore_sentinel.h。
		ULONG NeutralizeOverlayLevel = 2;

		// 便捷判据：是否启用（0 = 关）。
		bool NeutralizeOverlayEnabled() const noexcept { return NeutralizeOverlayLevel != 0; }

		//
		// ★★★ 新进程注入的**扫描间隔**（毫秒）。ini `inject_interval_ms=`。
		//
		// 为什么需要它（**真实绕过，v41**）：
		//
		//   引擎的用户态注入只有两条路：
		//     ① 同步路 —— 在被注入的**父进程**里 hook `CreateProcessInternalW`，
		//        强制 `CREATE_SUSPENDED` → 注入 → 再 `ResumeThread`。
		//        子进程**跑第一行代码之前**就已经被挂上 hook。
		//     ② 轮询路 —— 引擎主循环定期枚举新进程再注入（`AllProcessesInjector`）。
		//
		//   而"双击运行"的父进程是 **explorer.exe**（提权后是 `svchost.exe`），
		//   这两个都在 `ShouldSkipProcessInjection` 的 `kNeverInject[]` 里
		//   （注入 shell / 服务宿主会破坏系统）⇒ **同步路用不上**，
		//   只剩轮询路。原来轮询挂在主循环上，**1000ms 一轮**。
		//
		//   样本 `Windows XP Horror` 在 `FormCreate` 里（进程启动后**几十~几百 ms**）
		//   就 `CreateFileA("\\.\PhysicalDrive0")` + `WriteFile` 写掉 MBR ⇒
		//   整个写入落在 1000ms 的盲区里 ⇒ **block 模式没拦住**。
		//
		// 修法：把轮询从主循环里搬出来，交给**专用线程**，间隔收到毫秒级。
		// 空转时一次轮询只是**一次 `NtGetNextProcess` 系统调用**（立刻返回
		// `STATUS_NO_MORE_ENTRIES`），所以 10ms 间隔的开销可以忽略。
		//
		// ★★ 注意 Windows 的**默认时钟粒度是 15.6ms** —— 不提高分辨率的话
		//    `Sleep(10)` 实际会睡 ~15.6ms，把本项调到 10 以下**毫无意义**。
		//    所以注入线程在间隔 < 16ms 时会调 `NtSetTimerResolution(1ms)`
		//    把粒度降下来（代价是全系统时钟中断变密，故只在需要时才动）。
		//
		// 范围 1..1000，默认 10。★ 调大 = 更省 CPU、但盲区变大（不安全）。
		ULONG InjectionIntervalMs = 10;

		// ------------------------------------------------------------------
		// ★ v54：跨重启保留界面信息
		// ------------------------------------------------------------------
		//
		// 起因（用户实测反馈）：点界面上的「超级置顶」会把整个引擎换掉 ——
		// UIAccess 接管路径要求老引擎先退出（新的要等它 15s），老引擎一退，
		// 所有被注入进程里的 DLL 立刻 `UninitSession()` 摘掉全部 hook，
		// 而新引擎是从**全零**开始的（统计是纯内存的，事件通道名带 pid
		// 所以也是一条全新空通道）⇒ 用户看到的是"刚点置顶，事件列表就空了"。
		//
		// 这两项就是用来把"看起来像坏了"变成"看得出来在接力"。
		//

		// ini `replay_history_log=`（默认 1）
		//
		//   1 = 引擎启动时读 `log=` 指向的文件尾部若干条，预填进界面的
		//       事件列表（占用序号 1..N，实时事件从 N+1 继续）。
		//   0 = 完全不读，沿用旧行为（启动即空）。
		//
		// ⚠️ 只影响**界面显示**，不影响任何判定 —— 回放出来的条目
		//    绝不会被再次当成事件送进统计或规则层。
		bool ReplayHistoryLog = true;

		// ini `persist_stats=`（默认 1）
		//
		//   1 = 把累计统计（总事件数、注入进程数、各 Op 计数、Top 进程）
		//       落盘到引擎目录的 `r3shieldcore-stats.json`，下次启动载入，
		//       让概览行的数字跨重启连续。
		//   0 = 不落盘也不载入。
		//
		// ⚠️ 落盘的是**累计值**；界面同时显示"本次"增量，
		//    所以看到的是"累计 12,431（本次 +328）"这种形式，
		//    不存在"把上一轮的数字冒充成本轮成果"的问题。
		bool PersistStats = true;

		// 回放条数上限（ini `replay_history_limit=`，默认 200，0 = 用默认值）。
		// 大文件全读会拖慢启动，而用户要看的本来就是最近的。
		ULONG ReplayHistoryLimit = 200;

		// ------------------------------------------------------------------
		// ★ v61：高危进程提示
		// ------------------------------------------------------------------
		//
		// ini `high_risk_process_alert=`（默认 **2**）
		//
		//   0 = 关闭
		//   1 = 仅记录（r3shieldcore-console.log + 统计）
		//   2 = 记录 + 界面提示（GUI 底部栏显示最近一条）
		//
		// 与 `neutralize_overlay` 一样**不用 bool** —— 0/1/2 三档语义
		// 用 bool 表达不了，而且旧配置里的 `1` 仍要能读（"开，仅记录"）。
		//
		// 为什么默认**开**：它只"告知"不"拦截"，误报代价是日志里多一行；
		// 而判据本身刻意收窄（伪装系统进程名 / 形近伪装 / 已知攻击工具），
		// 正常机器上基本没有输出。
		//
		// ⚠️ 引擎**定期快照全机进程**判定，**不依赖注入覆盖、也不依赖观测窗**
		//    —— 这正是它相对 `process_guard` 的价值（见 r3shieldcore_procwatch.h）。
		//
		ULONG HighRiskProcessAlert = 2;

		// 扫描间隔（毫秒，ini `high_risk_process_scan_ms=`，默认 1000）。
		// 实际会被夹到 200..60000。
		//
		// **比注入轮询（默认 10ms）慢两个数量级是刻意的**：
		//   注入轮询要抢在样本写盘之前（毫秒级窗口），而本功能是"告知"，
		//   1 秒足够；而且枚举 + 逐个查映像路径是**真开销**（系统调用 +
		//   打开进程），不是空转。
		ULONG HighRiskProcessScanMs = 1000;

		// 便捷判据：是否启用（0 = 关）。
		bool HighRiskProcessAlertEnabled() const noexcept { return HighRiskProcessAlert != 0; }

		// ------------------------------------------------------------------
		// ★ v62：ARK 页（全机进程列表 + 挂起 / 内部退出 / 强制结束）
		// ------------------------------------------------------------------
		//
		// ini `ark_enabled=`（默认 **1**）
		//
		//   ⚠️ 这里用 **bool** 而不是 0/1/2 三档，因为它**没有**"仅记录"这一档：
		//      ARK 是**纯界面功能** —— 关掉它，引擎不做任何额外的事
		//      （不扫描、不弹窗、不拦截），只是 ARK 页签不刷新、动作不可用。
		//      没有"半开"的语义，用三档只会让人以为存在。
		//
		// 为什么默认**开**：它不做任何主动行为，只是定期快照一次进程列表。
		// 代价是一轮枚举（几百微秒到几十毫秒，见 `ark_scan_ms`），
		// 收益是用户随时能看清机器上跑着什么、并对可疑进程动手。
		//
		// ⚠️ 动作（挂起 / 内部退出 / 强制结束）**只由用户点击触发**，
		//    引擎绝不会自己动手。关掉 `ark_enabled` 之后连按钮都不可用。
		bool ArkEnabled = true;

		// 扫描间隔（毫秒，ini `ark_scan_ms=`，默认 2000）。
		// 实际会被夹到 500..60000。
		//
		// 比 `high_risk_process_scan_ms`（默认 1000）再慢一倍是刻意的：
		//   本功能的每一轮都要**打开每个进程**（路径 / CPU / 内存 / 模块表），
		//   比 procwatch 只查路径贵得多；而它服务的是"人看的列表"，
		//   2 秒的刷新率已经完全够用。
		ULONG ArkScanMs = 2000;

		// ★ v63：ARK 页的**界面刷新间隔**（毫秒，ini `ark_refresh_ms=`，默认 1000）。
		// 实际会被夹到 200..60000。
		//
		// ⚠️ 它和 `ark_scan_ms` 是**两件事**，别混：
		//     `ark_scan_ms`    = 引擎多久**重新枚举**一次全机进程（数据新鲜度）
		//     `ark_refresh_ms` = 界面多久**重取 + 重绘**一次（显示新鲜度）
		//
		//   刷新比扫描快是**正常且常见**的配置：快照本身是引擎侧缓存，
		//   重取它几乎不花钱（一次加锁 + 拷贝几百行），但能让"点了按钮 /
		//   换了选中项 / 动作结果回来"这些**界面侧**变化立刻反映出来，
		//   而不用等下一轮扫描。
		//
		//   ⇒ 数据本身的变化最快也只能跟上 `ark_scan_ms`；
		//     把 `ark_refresh_ms` 调到比 `ark_scan_ms` 小**不会**让进程列表
		//     更新得更快，只是让界面更跟手。反过来调大则纯粹是省 CPU。
		//
		// 下限 200ms：比这更密就只是白烧 GUI 线程（人眼也分辨不出）。
		ULONG ArkRefreshMs = 1000;
	};

	EngineSettings LoadEngineSettings(const std::filesystem::path& exeDirectory);
}
