//
// v54_config_probe.cpp —— 一次性定位"回放没生效"的环节。
//
// 分两段独立验证：
//   A) LoadEngineSettings(目录) 有没有把 replay_history_log / persist_stats /
//      replay_history_limit 解析出来（→ 排除"ini 没读到"）
//   B) R3ShieldCoreLogReplay::ReadTail(logPath, 200) 能不能从**真实日志**读出来
//      （→ 排除"读文件/解析"）
//
// 用法: v54_config_probe.exe <部署目录>
//
#include "stdafx.h"

#include "r3shieldcore_config.h"
#include "r3shieldcore_log_replay.h"

#include <cstdio>
#include <filesystem>

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	if (argc < 2) {
		wprintf(L"用法: v54_config_probe <部署目录>\n");
		return 2;
	}

	const std::filesystem::path dir = argv[1];
	wprintf(L"部署目录: %s\n\n", dir.c_str());

	// ---- A) 配置解析 ----
	const R3ShieldCoreConfig::EngineSettings s = R3ShieldCoreConfig::LoadEngineSettings(dir);
	wprintf(L"=== A. LoadEngineSettings ===\n");
	wprintf(L"  ReplayHistoryLog   = %d   （期望 1）\n", s.ReplayHistoryLog ? 1 : 0);
	wprintf(L"  PersistStats       = %d   （期望 1）\n", s.PersistStats ? 1 : 0);
	wprintf(L"  ReplayHistoryLimit = %u   （期望 200）\n", static_cast<unsigned>(s.ReplayHistoryLimit));

	// ---- B) ReadTail ----
	const std::filesystem::path logPath = dir / L"r3shieldcore-events.log";
	wprintf(L"\n=== B. ReadTail ===\n");
	wprintf(L"  目标文件: %s\n", logPath.c_str());

	const R3ShieldCoreLogReplay::Result r = R3ShieldCoreLogReplay::ReadTail(logPath, 200);
	wprintf(L"  FileBytes   = %llu\n", static_cast<unsigned long long>(r.FileBytes));
	wprintf(L"  LinesRead   = %u\n", static_cast<unsigned>(r.LinesRead));
	wprintf(L"  LinesParsed = %u\n", static_cast<unsigned>(r.LinesParsed));
	wprintf(L"  Entries     = %u\n\n", static_cast<unsigned>(r.Entries.size()));

	for (size_t i = 0; i < r.Entries.size() && i < 5; ++i) {
		const auto& e = r.Entries[i];
		wprintf(L"    [%u] type=%u op=%u dec=%u pid=%u\n",
			static_cast<unsigned>(i + 1), e.ObjectType, e.Op, e.Decision, e.ProcessId);
	}

	// ---- 判定 ----
	const bool configOk = s.ReplayHistoryLog && s.PersistStats && s.ReplayHistoryLimit == 200;
	const bool readOk = r.Entries.size() > 0;

	wprintf(L"\n");
	if (!configOk) {
		wprintf(L"[FAIL-A] 配置没解析出来（ini 里没这三项 / 写错位置）\n");
	}
	if (!readOk) {
		wprintf(L"[FAIL-B] ReadTail 读不出条目（文件路径错 / 读权限 / 解析失败）\n");
	}
	if (configOk && readOk) {
		wprintf(L"[PASS] 配置 OK，ReadTail 读出 %u 条\n", static_cast<unsigned>(r.Entries.size()));
		return 0;
	}
	return 1;
}
