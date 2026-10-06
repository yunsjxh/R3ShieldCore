#pragma once

#include <windows.h>

//
// ★ v61 高危进程提示（引擎侧主动行为）
//
// 为什么需要它（v60b 真机复盘的直接结论）：
//
//   `process_guard.cpp` 判的是「**这一次创建**该不该拦」，数据来自被注入进程
//   里的 hook ⇒ **只看得见被监控进程发起、且落在引擎观测窗内**的创建。
//   v60b 复盘里病毒的症状键（SwapMouseButtons / HideIcons / Wallpaper）
//   在整份日志里 **0 命中** —— 破坏发生在观测窗之前，注入路根本看不见。
//
//   本模块走另一条路：**引擎自己定期快照全机进程**，逐个查映像路径并过判据。
//   不依赖注入覆盖、也不依赖观测窗（引擎启动前就在跑的进程一样能看见）。
//
// ------------------------------------------------------------------
// 判据（只有三条；"度"是刻意收窄的，详见 r3shieldcore_rules.cpp 的大段说明）
// ------------------------------------------------------------------
//   ① 系统进程名伪装：文件名 == 受保护系统组件名，但不在其规范目录
//   ② 形近伪装：归一化后 == 系统组件名，或只差一对相邻字符交换
//      （`lsass .exe` / `svch0st.exe` / `scvhost.exe`）
//   ③ 已知攻击工具：文件名（去扩展名）在攻击工具名单里
//
// ⚠️ 判据**不在本模块**，而在 `r3shieldcore_rules.cpp` —— 通过 DLL 导出
//    `GlobalHookSessionCheckHighRiskProcess` 拿。理由：引擎 exe **不链接**
//    lib 的源码（见 build.sh 的 build_demo），而判据表必须只有一份，
//    否则两份真相必然漂移。本模块只负责"枚举 + 去重 + 告警 + 心跳"。
//
// ------------------------------------------------------------------
// 级别（ini: high_risk_process_alert = 0 / 1 / 2）
// ------------------------------------------------------------------
//   0 = 关闭
//   1 = 仅记录（r3shieldcore-console.log + 统计）
//   2 = 记录 + 界面提示（GUI 底部栏显示最近一条）
//
// ⚠️ 为什么**不做弹窗**：这是一个**周期性扫描**，一次可能同时发现多个；
//    弹窗会打断用户且可能连环弹。引擎已有的 `Ask()` 弹窗留给"拦不拦"
//    这种必须当场决策的场景。本功能是"告知"，落在日志 + 界面。
//
// ------------------------------------------------------------------
// 可诊断性（铁律 97：布尔判定 = 不可诊断）
// ------------------------------------------------------------------
//   · **首行立即打**：`Start()` 里不管启用与否都打一行，写明级别 / 间隔 /
//     systemRoot / 判据 —— 没有它，"功能没生效"与"生效了但没发现高危进程"
//     在日志里长得一模一样（正是 v60 那个"诊断口径比触发口径窄"的坑）。
//   · **心跳**（60s）：扫描轮数 / 本轮进程数 / 累计高危 / 累计告警 /
//     去重表占用 / 本轮截断数 —— "没告警"与"没扫描"必须分得开。
//   · **单轮告警上限**：一批伪装进程同时出现时不会刷爆日志；
//     被截断的条数进心跳，所以"截断了多少"看得见，不是静默丢弃。
//
namespace R3ShieldCoreProcWatch
{
	//
	// 判据回调。返回原因（DLL 里的静态字符串），nullptr = 不是高危。
	// systemRoot 由本模块解析后传回，判据用它判断"在不在系统目录"。
	//
	using CheckFn = const char* (*)(const wchar_t* imagePath, const wchar_t* systemRoot);

	struct Stats
	{
		ULONG Scans = 0;              // 已完成的扫描轮数
		ULONG LastScanProcesses = 0;  // 最近一轮枚举到的进程数
		ULONG LastScanNoPath = 0;     // 最近一轮取不到映像路径的进程数（权限不足）
		ULONG LastScanCandidates = 0; // 最近一轮判成高危的进程数（去重前）
		ULONG LastScanTruncated = 0;  // 最近一轮因单轮上限没打出来的告警数
		ULONG HighRiskFound = 0;      // 累计发现的高危进程数（去重后）
		ULONG Alerts = 0;             // 累计打出的告警条数
		ULONG DedupEntries = 0;       // 去重表占用
		ULONG DedupCapacity = 0;      // 去重表容量
		bool  SnapshotFailed = false; // 最近一轮 CreateToolhelp32Snapshot 是否失败

		// 最近一条告警的明细，供界面底部栏显示。
		ULONG LatestPid = 0;
		WCHAR LatestName[64] = {};
		WCHAR LatestPath[MAX_PATH] = {};
		WCHAR LatestReason[64] = {};
	};

	//
	// 启动。level == 0 或 check == nullptr 或取不到 %SystemRoot% 时
	// **不启用**，但每种情况都会打一行写明原因（绝不静默）。
	//
	// check 传 nullptr 的典型场景：加载到的是**旧版 DLL**（没有这个导出）。
	// 调用方应先查 `EngineControl::SupportsHighRiskProcessCheck()`。
	//
	void Start(ULONG level, ULONG scanIntervalMs, CheckFn check) noexcept;

	void Stop() noexcept;

	bool IsEnabled() noexcept;

	// 引擎主循环定期调用（内部按 scanIntervalMs 节流）。
	void Tick() noexcept;

	Stats GetStats() noexcept;
}
