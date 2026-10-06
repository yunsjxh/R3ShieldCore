//
// replay_probe —— `r3shieldcore_log_replay` 解析器的独立探针。
//
// 为什么不启引擎测：解析器是**纯函数**（读文件 → 返回 LogEntry 列表），
// 起引擎反而会引入"引擎把工具链锁死"（铁律 76）和"ACL 让 DLL 载不进来"
// 这类与解析无关的干扰。先把纯的那部分测干净。
//
// 用法：
//   replay_probe.exe <log 路径> [条数上限]
//
// 输出：每条解析出来的记录，以及"读了几行 / 解析出几条"的汇总。
//
#include "stdafx.h"

#include "r3shieldcore_log_replay.h"

#include <algorithm>
#include <clocale>
#include <cstdio>
#include <string>

namespace
{
	// "%04u-%02u-%02u %02u:%02u:%02u.%03u" —— FILETIME(100ns since 1601) -> 本地时间字符串
	std::wstring FormatFileTime(LONG64 stamp)
	{
		if (stamp == 0) {
			return L"(时间未解析)";
		}

		// 日志里存的是 FILETIME（UTC 计数）。显示时转回本地时间。
		FILETIME utc = {};
		utc.dwLowDateTime = static_cast<DWORD>(stamp & 0xFFFFFFFF);
		utc.dwHighDateTime = static_cast<DWORD>(static_cast<ULONGLONG>(stamp) >> 32);

		FILETIME local = {};
		SYSTEMTIME st = {};
		if (!FileTimeToLocalFileTime(&utc, &local) || !FileTimeToSystemTime(&local, &st)) {
			return L"(时间转换失败)";
		}

		WCHAR buffer[64] = {};
		swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		return buffer;
	}
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	if (argc < 2) {
		wprintf(L"用法: replay_probe <log 路径> [条数上限]\n");
		wprintf(L"      replay_probe --lines <log 路径>   逐行体检（看每行卡在哪）\n");
		return 2;
	}

	// ---- 逐行体检模式 ----
	if (std::wstring(argv[1]) == L"--lines") {
		if (argc < 3) {
			wprintf(L"用法: replay_probe --lines <log 路径>\n");
			return 2;
		}
		const std::filesystem::path path = argv[2];

		HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			wprintf(L"打不开文件 err=%u\n", GetLastError());
			return 1;
		}
		LARGE_INTEGER size = {};
		GetFileSizeEx(file, &size);
		std::string blob(static_cast<size_t>(size.QuadPart), '\0');
		DWORD got = 0;
		ReadFile(file, blob.data(), static_cast<DWORD>(blob.size()), &got, nullptr);
		CloseHandle(file);
		blob.resize(got);

		int lineNo = 0;
		int okCount = 0;
		int failCount = 0;
		size_t pos = 0;
		while (pos < blob.size()) {
			size_t nl = blob.find('\n', pos);
			if (nl == std::string::npos) nl = blob.size();
			size_t end = nl;
			if (end > pos && blob[end - 1] == '\r') --end;

			if (end > pos) {
				++lineNo;
				const std::string line = blob.substr(pos, end - pos);
				R3ShieldCoreStats::LogEntry entry = {};
				const bool ok = R3ShieldCoreLogReplay::ParseLineForTest(line, entry);

				// 显示前 70 字符便于肉眼比对
				std::wstring preview;
				{
					const std::string head = line.substr(0, std::min<size_t>(70, line.size()));
					const int needed = MultiByteToWideChar(CP_UTF8, 0, head.c_str(),
						static_cast<int>(head.size()), nullptr, 0);
					if (needed > 0) {
						preview.resize(static_cast<size_t>(needed));
						MultiByteToWideChar(CP_UTF8, 0, head.c_str(),
							static_cast<int>(head.size()), preview.data(), needed);
					}
				}

				if (ok) {
					++okCount;
					wprintf(L"[%3d] OK   type=%-3u op=%-3u dec=%-3u pid=%u  %s\n",
						lineNo, entry.ObjectType, entry.Op, entry.Decision,
						entry.ProcessId, preview.c_str());
				}
				else {
					++failCount;
					wprintf(L"[%3d] FAIL @%-8S                           %s\n",
						lineNo, R3ShieldCoreLogReplay::LastFailureStage(), preview.c_str());
				}
			}
			pos = nl + 1;
		}

		wprintf(L"\n合计: %d 行, 成功 %d, 失败 %d\n", lineNo, okCount, failCount);
		return failCount == 0 ? 0 : 1;
	}

	const std::filesystem::path logPath = argv[1];
	const size_t limit = (argc >= 3) ? static_cast<size_t>(_wtoi(argv[2])) : 200;

	wprintf(L"读取: %s（上限 %u 条）\n\n", logPath.c_str(), static_cast<unsigned>(limit));

	const R3ShieldCoreLogReplay::Result result = R3ShieldCoreLogReplay::ReadTail(logPath, limit);

	wprintf(L"文件大小 : %llu 字节\n", static_cast<unsigned long long>(result.FileBytes));
	wprintf(L"读到行数 : %u\n", static_cast<unsigned>(result.LinesRead));
	wprintf(L"解析成功 : %u\n", static_cast<unsigned>(result.LinesParsed));
	wprintf(L"回放条数 : %u\n\n", static_cast<unsigned>(result.Entries.size()));

	for (size_t i = 0; i < result.Entries.size(); ++i) {
		const R3ShieldCoreStats::LogEntry& e = result.Entries[i];
		wprintf(L"[%2u] %s  pid=%-6u [%s]\n",
			static_cast<unsigned>(i + 1),
			FormatFileTime(e.TimeStamp).c_str(),
			e.ProcessId,
			e.ProcessName.empty() ? L"?" : e.ProcessName.c_str());
		wprintf(L"       type=%-3u op=%-3u decision=%-3u status=0x%08X  blocked=%d high=%d hive=%d targetPid=%u\n",
			e.ObjectType, e.Op, e.Decision, e.Status,
			e.BlockedByUs ? 1 : 0, e.IsHighRisk ? 1 : 0, e.IsHive ? 1 : 0,
			e.TargetProcessId);
		wprintf(L"       target=%s\n", e.Target.empty() ? L"(空)" : e.Target.c_str());
		if (!e.Value.empty()) {
			wprintf(L"       value =%s\n", e.Value.c_str());
		}
	}

	// ---- 判定 ----
	// 有文件、有行，却一条都解析不出来 = 格式对不上（这是真正要抓的失败）。
	// "文件为空"和"解析失败"必须分得开（铁律 57 同族）。
	const bool parsedAnything = result.LinesParsed > 0;
	const bool fileHadContent = result.FileBytes > 0;

	wprintf(L"\n");
	if (fileHadContent && result.LinesRead == 0) {
		wprintf(L"[FAIL] 文件有内容（%llu 字节）却读不到任何行\n",
			static_cast<unsigned long long>(result.FileBytes));
		return 1;
	}
	if (fileHadContent && !parsedAnything) {
		wprintf(L"[FAIL] 读到 %u 行但一条都没解析出来 —— 格式对不上\n",
			static_cast<unsigned>(result.LinesRead));
		return 1;
	}
	if (!fileHadContent) {
		wprintf(L"[PASS] 文件为空/不存在 -> 回放 0 条（这是合法结果，不是失败）\n");
		return 0;
	}

	wprintf(L"[PASS] 回放 %u 条\n", static_cast<unsigned>(result.Entries.size()));
	return 0;
}
