#pragma once

#include "r3shieldcore_stats.h"

#include <filesystem>
#include <vector>

//
// ★ v54：把 `r3shieldcore-events.log` 的尾部读回来，重建成 LogEntry 列表，
//   交给 `R3ShieldCoreStats::SeedHistory()` 预填进界面的事件列表。
//
// 目的：引擎每次启动（尤其是点「超级置顶」触发 UIAccess 接管换引擎时）
//       事件列表都是空的。文件里明明有全部历史，只是界面不读它。
//
// 设计取舍：
//   · 只回放**尾部 N 条**（默认 200）—— 大文件（几万行）全读会拖慢启动，
//     而用户要看的本来就是"最近发生了什么"。
//   · 解析**尽力而为**：任何一行看不懂就跳过那一行，绝不抛异常、绝不阻断启动。
//     日志是排障辅助，不能因为它格式变了就让引擎起不来。
//   · 只读不写、只增不改 —— 不碰 `r3shieldcore-events.log` 本身。
//
namespace R3ShieldCoreLogReplay
{
	// 回放结果。
	struct Result
	{
		std::vector<R3ShieldCoreStats::LogEntry> Entries; // 按文件顺序（时间升序）
		size_t LinesRead = 0;    // 实际读到的行数（含解析失败的）
		size_t LinesParsed = 0;  // 成功解析的条数
		ULONGLONG FileBytes = 0; // 文件大小，仅用于日志
	};

	//
	// 读 `logPath` 的尾部最近 `maxEntries` 条事件。
	//
	// ⚠️ 必须用 `FILE_SHARE_READ | FILE_SHARE_WRITE` 打开 ——
	//    引擎在跑时这个文件**正被另一个进程写**（引擎自己的日志线程），
	//    不带 SHARE_WRITE 会拿到 ERROR_SHARING_VIOLATION(32)，
	//    表现为"读不到"，而那不是"没有历史"（铁律 57）。
	//
	// ⚠️ 文件不存在 / 空 / 全读不懂 ⇒ 返回空 Result，调用方照常启动。
	//
	// maxEntries = 0 时用默认值 200。
	Result ReadTail(const std::filesystem::path& logPath, size_t maxEntries = 200) noexcept;

	//
	// 单行解析（导出**只为**让 `tools/replay_probe.cpp` 能对着真日志逐行测）。
	//
	// 为什么必须导出：`ReadTail` 是"能解析出几条"的黑盒 —— 失败时
	// 只看得到"0 条"，看不出**卡在哪个字段**。本项目已经因为"黑盒断言"
	// 吃过亏（铁律 34：挂了 API ≠ 行为被覆盖），所以解析器必须能逐行体检。
	//
	// 返回 false = 这一行不认识（调用方应跳过而不是中断）。
	// 成功时 `entry` 里的 `Serial` 是 0，由 SeedHistory 统一重编号。
	//
	bool ParseLineForTest(const std::string& line, R3ShieldCoreStats::LogEntry& entry) noexcept;

	// 最后一次解析失败停在哪一步（形如 "step3"）。仅诊断用。
	const char* LastFailureStage() noexcept;
}
