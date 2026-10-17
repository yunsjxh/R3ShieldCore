#include "stdafx.h"
#include "r3shieldcore_log.h"
#include "r3shieldcore_channel.h"
#include "logger.h"

// ★ v81：事件日志行的**格式化实现**（唯一一份，铁律 127）。
//   原来这段逻辑就在本文件的 `WriteEventLine` 里；v81 起引擎侧也要同一份
//   文本（配置工具向引擎要数据，而不是去读日志文件），所以搬进共享头。
//   ⇒ 本文件不再保留任何行格式化的副本。
#include <r3shieldcore/log_line.h>

namespace
{
	wil::unique_hfile g_file;

	constexpr char Utf8Bom[] = "\xEF\xBB\xBF";

	// 把宽字符按指定长度转成 UTF-8，失败则回退成问号。
	int ToUtf8(const WCHAR* source, int sourceChars, char* destination, int destinationBytes) noexcept
	{
		if (!source || sourceChars <= 0 || !destination || destinationBytes <= 0) {
			return 0;
		}

		int written = WideCharToMultiByte(CP_UTF8, 0, source, sourceChars,
			destination, destinationBytes - 1, nullptr, nullptr);
		if (written <= 0) {
			return 0;
		}

		destination[written] = '\0';
		return written;
	}

	// ------------------------------------------------------------------
	// PID -> 进程名 解析（带缓存）。
	//
	// 为什么需要：Event 结构里**只有 ProcessId，没有进程名/镜像路径**
	// （见 r3shieldcore_shared.h 的 struct Event）。GUI 面板有统计表可以反查，
	// 但落盘日志是 DLL 侧独立消费事件流（R3ShieldCoreChannel::Drain），
	// 拿不到引擎的统计表 —— 所以必须在这里自己反查。
	//
	// 为什么必须缓存：实测一台机上单个 PID 会贡献几百条事件
	// （日志里 pid=6772 有 517 条）。若每条都 OpenProcess + 查询，
	// 既慢又吵。这里用一个小的直接映射缓存：PID 低位做槽位，
	// 命中即复用。进程名在同一次运行里不会变，缓存永不失效。
	//
	// 线程安全：DrainAndWrite 只被引擎主循环单线程调用，缓存无需加锁。
	// ------------------------------------------------------------------
	constexpr ULONG NameCacheSlots = 64; // 2 的幂，PID 低位取模

	struct NameCacheEntry
	{
		ULONG ProcessId;   // 0 = 空槽
		char  Name[128];   // 进程名（含扩展名），UTF-8
	};

	NameCacheEntry g_nameCache[NameCacheSlots] = {};

	// 返回缓存的进程名（UTF-8）；取不到返回空串指针。
	const char* ResolveProcessName(ULONG processId) noexcept
	{
		if (processId == 0) {
			return "";
		}

		const ULONG slot = processId & (NameCacheSlots - 1);

		// 命中：同 PID 直接返回。
		if (g_nameCache[slot].ProcessId == processId) {
			return g_nameCache[slot].Name;
		}

		// 未命中原槽主：先清空，再尝试填充。
		g_nameCache[slot].ProcessId = 0;
		g_nameCache[slot].Name[0] = '\0';

		wil::unique_handle process(OpenProcess(
			PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId));
		if (!process) {
			// 进程可能已退出（短命进程最常见）。用一个"占位"标记
			// 避免反复 OpenProcess：把 PID 记下、名字留空。
			g_nameCache[slot].ProcessId = processId;
			return g_nameCache[slot].Name;
		}

		WCHAR path[MAX_PATH] = {};
		DWORD size = _countof(path);
		if (!QueryFullProcessImageName(process.get(), 0, path, &size)) {
			g_nameCache[slot].ProcessId = processId;
			return g_nameCache[slot].Name;
		}

		// 只要文件名部分，去掉目录（日志里放完整路径会挤爆一屏）。
		const WCHAR* name = wcsrchr(path, L'\\');
		name = name ? (name + 1) : path;

		ToUtf8(name, static_cast<int>(wcslen(name)),
			g_nameCache[slot].Name, sizeof(g_nameCache[slot].Name));
		g_nameCache[slot].ProcessId = processId;
		return g_nameCache[slot].Name;
	}

	void WriteEventLine(const R3ShieldCore::Event& event, void* /*context*/) noexcept
	{
		if (!g_file) {
			return;
		}

		// ★ v81：这一行的**格式**搬去了共享头 `shared/r3shieldcore/log_line.h`
		//   （铁律 127）。为什么必须搬：
		//
		//     这一行文本原来只有 DLL 需要（它落盘）。v81 起引擎（主程序）也需要
		//     **同一份文本** —— 配置工具要“向引擎要数据”，而不是自己去读日志文件。
		//     如果引擎那边照着重写一遍格式化，两边迟早漂：改个标签、多个空格
		//     都不会报错，只是“界面上看到的”和“日志文件里看到的”变成两种东西。
		//
		//   ⚠️ 本函数现在只做两件事：解析进程名（DLL 侧有它自己的窄字符缓存）、
		//      把返回值**逐字节**写出去（含行尾 CRLF，由 FormatEventLine 带）。
		//      格式化逻辑一个字都不许在这里重复。
		const std::string line = R3ShieldCoreLogLine::FormatEventLine(
			event, ResolveProcessName(event.ProcessId));

		if (line.empty()) {
			return;
		}

		DWORD written = 0;
		WriteFile(g_file.get(), line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
	}
}

namespace R3ShieldCoreLog
{
	bool IsOpen() noexcept
	{
		return static_cast<bool>(g_file);
	}

	bool Open(const WCHAR* path) noexcept
	{
		Close();

		if (!path || !path[0]) {
			return false;
		}

		wil::unique_hfile file(CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
		if (!file) {
			LOG(L"R3ShieldCore: 无法打开日志文件 %s (错误 %u)", path, GetLastError());
			return false;
		}

		SetFilePointer(file.get(), 0, nullptr, FILE_END);

		// 只在文件为空时写 BOM，方便追加。
		LARGE_INTEGER size = {};
		if (GetFileSizeEx(file.get(), &size) && size.QuadPart == 0) {
			DWORD written = 0;
			WriteFile(file.get(), Utf8Bom, sizeof(Utf8Bom) - 1, &written, nullptr);
		}

		g_file = std::move(file);
		return true;
	}

	int DrainAndWrite() noexcept
	{
		return R3ShieldCoreChannel::Drain(&WriteEventLine, nullptr);
	}

	void Close() noexcept
	{
		g_file.reset();
	}
}
