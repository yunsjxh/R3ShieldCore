#include "stdafx.h"
#include "r3shieldcore_superdesk.h"

#include <r3shieldcore/r3shieldcore_shared.h>

#include <tlhelp32.h>
#include <windowsx.h>

#include <cstdarg>
#include <cstdio>
#include <fstream>
#include <source_location>
#include <string>
#include <vector>

//
// 「超级置顶」A 配方的实现。
//
// 两个角色在同一个文件里：
//   引擎侧  Launch() / Stop() / IsRunning() —— 造 SYSTEM 令牌、把面板拉到安全桌面
//   面板侧  RunPanel()                     —— 面板自己的窗口与消息循环
//
// 面板是**同一个 exe 的另一个实例**（命令行带 --super-panel），
// 所以 app.cpp 必须在启动引擎之前先判断 IsPanelInvocation()。
//

namespace
{
	// =====================================================================
	// 通用小工具
	// =====================================================================

	// 本 exe 的完整路径。不用 wil::GetModuleFileName —— 那个走 THROW_IF_FAILED，
	// 而这两个调用点都在 noexcept 的窗口过程链路上，抛出来会直接 std::terminate。
	std::wstring ModulePath() noexcept
	{
		wchar_t path[MAX_PATH * 4] = {};
		const DWORD length = GetModuleFileNameW(nullptr, path, _countof(path));
		if (length == 0 || length >= _countof(path)) {
			return std::wstring();
		}
		return std::wstring(path, length);
	}

	// 把一行文本按 UTF-8 追加到 exe 同目录的指定日志。
	//
	// ⚠️ 编码陷阱：build.sh 只设了 -source-charset:utf-8，**没动 execution
	//    charset**，所以本文件里窄字符串字面量的中文是 **CP936（GBK）字节**，
	//    不是 UTF-8。直接倒进文件会写出 GBK 混排，UTF-8 阅读器看到乱码。
	//    这里显式 ACP → UTF-16 → UTF-8 转一道再落盘。
	//    （同类教训：tools 下的探针曾把 CP936 窄串写进 ccs=UTF-8 的 FILE*，
	//      被 invalid parameter handler 直接干掉，只剩 BOM。）
	void AppendLogLine(const wchar_t* fileName, const char* line) noexcept
	{
		try {
			const std::wstring modulePath = ModulePath();
			if (modulePath.empty()) {
				return;
			}
			const std::filesystem::path logPath =
				std::filesystem::path(modulePath).parent_path() / fileName;
			std::ofstream output(logPath, std::ios::out | std::ios::app);
			if (!output) {
				return;
			}

			wchar_t wide[1024] = {};
			char utf8[2048] = {};
			if (MultiByteToWideChar(CP_ACP, 0, line, -1, wide, _countof(wide)) > 0 &&
				WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, _countof(utf8),
					nullptr, nullptr) > 0) {
				output << utf8 << std::endl;
				return;
			}
			// 转换失败（极不可能）就退回原样，至少不丢日志。
			output << line << std::endl;
		}
		catch (...) {
		}
	}

	// 面板是 SYSTEM + 安全桌面，没有控制台可看，所以留一份文件日志。
	// 写失败就算了，绝不影响面板本身。
	void PanelLog(const char* format, ...) noexcept
	{
		char line[1024] = {};
		va_list args;
		va_start(args, format);
		_vsnprintf_s(line, sizeof(line), _TRUNCATE, format, args);
		va_end(args);
		AppendLogLine(L"superdesk-panel.log", line);
	}

	// ★ 铁律 23 的落地：握手/自检诊断**直接写 r3shieldcore-console.log**，不经过 printf。
	//
	// 为什么必须这样：本 exe 是 **GUI 子系统**（没有控制台），printf 能否落盘
	// 完全取决于 `app.cpp:RedirectDiagnosticsToFile()` 的 stdout 重定向是否成功。
	// v33 实测：提权跑自检时 `r3shieldcore-console.log` **一行不加**（连兜底文件都没生成），
	// 而**同一个目录**的 `superdesk-panel.log` 却写得进去 ⇒
	// **ofstream 才是可靠通道**，stdout 不是。诊断绝不能赌重定向成没成。
	void ConsoleLog(const char* format, ...) noexcept
	{
		char line[1024] = {};
		va_list args;
		va_start(args, format);
		_vsnprintf_s(line, sizeof(line), _TRUNCATE, format, args);
		va_end(args);
		AppendLogLine(L"r3shieldcore-console.log", line);
	}

	// 自检开始前清空日志 —— 一次运行一份干净记录，断言不用去猜边界。
	void TruncatePanelLog() noexcept
	{
		try {
			const std::wstring modulePath = ModulePath();
			if (modulePath.empty()) {
				return;
			}
			const std::filesystem::path logPath =
				std::filesystem::path(modulePath).parent_path() / L"superdesk-panel.log";
			std::ofstream output(logPath, std::ios::out | std::ios::trunc);
		}
		catch (...) {
		}
	}

	bool EnablePrivilege(HANDLE token, LPCWSTR name, DWORD* errorCode = nullptr) noexcept
	{
		if (errorCode) {
			*errorCode = ERROR_SUCCESS;
		}
		LUID luid = {};
		if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
			if (errorCode) *errorCode = GetLastError();
			return false;
		}
		TOKEN_PRIVILEGES privileges = {};
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		SetLastError(ERROR_SUCCESS);
		const BOOL ok = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
		const DWORD lastError = GetLastError();
		if (errorCode) *errorCode = lastError;
		// ⚠️ AdjustTokenPrivileges 返回 TRUE 也可能一个特权都没给（令牌里没有），
		//    这时 GetLastError 是 ERROR_NOT_ALL_ASSIGNED(1300)。必须两个都看。
		return ok != FALSE && lastError == ERROR_SUCCESS;
	}

	bool TokenIsLocalSystem(HANDLE token) noexcept
	{
		DWORD required = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &required);
		if (required == 0) {
			return false;
		}
		std::vector<BYTE> buffer(required);
		if (!GetTokenInformation(token, TokenUser, buffer.data(), required, &required)) {
			return false;
		}
		BYTE systemSid[SECURITY_MAX_SID_SIZE] = {};
		DWORD sidSize = sizeof(systemSid);
		if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid, &sidSize)) {
			return false;
		}
		const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(buffer.data());
		return EqualSid(tokenUser->User.Sid, systemSid) != FALSE;
	}

	DWORD TokenUIAccessFlag(HANDLE token) noexcept
	{
		DWORD value = 0;
		DWORD returned = 0;
		if (!token) {
			return 0;
		}
		GetTokenInformation(token, TokenUIAccess, &value, sizeof(value), &returned);
		return value;
	}

	DWORD SelfUIAccessFlag() noexcept
	{
		HANDLE token = nullptr;
		DWORD value = 0;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			value = TokenUIAccessFlag(token);
			CloseHandle(token);
		}
		return value;
	}

	bool SelfIsLocalSystem() noexcept
	{
		HANDLE token = nullptr;
		bool result = false;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			result = TokenIsLocalSystem(token);
			CloseHandle(token);
		}
		return result;
	}

	bool SelfIsElevated() noexcept
	{
		HANDLE token = nullptr;
		TOKEN_ELEVATION elevation = {};
		DWORD returned = 0;
		bool result = false;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			result = GetTokenInformation(token, TokenElevation, &elevation,
				sizeof(elevation), &returned) != FALSE && elevation.TokenIsElevated != 0;
			CloseHandle(token);
		}
		return result;
	}

	// 优先本会话的 winlogon.exe —— 它的令牌就是当前登录会话的 LocalSystem。
	DWORD FindSystemTokenSource(DWORD sessionId) noexcept
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return 0;
		}
		DWORD bestPid = 0;
		int bestRank = 0;
		PROCESSENTRY32W entry = { sizeof(entry) };
		if (Process32FirstW(snapshot, &entry)) {
			do {
				DWORD candidateSession = 0;
				ProcessIdToSessionId(entry.th32ProcessID, &candidateSession);
				const bool sameSession = candidateSession == sessionId;
				int rank = 0;
				if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) {
					rank = sameSession ? 40 : 30;
				}
				else if (_wcsicmp(entry.szExeFile, L"services.exe") == 0) {
					rank = sameSession ? 20 : 10;
				}
				if (rank > bestRank) {
					bestRank = rank;
					bestPid = entry.th32ProcessID;
				}
			} while (Process32NextW(snapshot, &entry));
		}
		CloseHandle(snapshot);
		return bestPid;
	}

	const wchar_t* CurrentDesktopName() noexcept
	{
		static wchar_t name[128] = {};
		name[0] = 0;
		HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
		if (!desktop) {
			return L"(未知)";
		}
		DWORD length = 0;
		GetUserObjectInformationW(desktop, UOI_NAME, nullptr, 0, &length);
		if (length == 0 || length > sizeof(name)) {
			return L"(未知)";
		}
		if (!GetUserObjectInformationW(desktop, UOI_NAME, name, sizeof(name), &length)) {
			return L"(未知)";
		}
		return name;
	}

	// =====================================================================
	// 命令行解析
	// =====================================================================
	// 故意不走 main(argc, argv)：app.cpp 的 main 是无参的，而且面板这条路
	// 要在**任何引擎初始化之前**就分流出去。直接看 GetCommandLineW 最省事。

	std::wstring CommandLineText() noexcept
	{
		PCWSTR raw = GetCommandLineW();
		return raw ? std::wstring(raw) : std::wstring();
	}

	// 取 "--name=value" 的 value；没有返回 0。
	DWORD CommandLineNumber(PCWSTR name) noexcept
	{
		const std::wstring commandLine = CommandLineText();
		const std::wstring needle = std::wstring(name) + L"=";
		const size_t at = commandLine.find(needle);
		if (at == std::wstring::npos) {
			return 0;
		}
		return static_cast<DWORD>(_wcstoui64(commandLine.c_str() + at + needle.size(), nullptr, 10));
	}

	std::wstring CommandLineTextValue(PCWSTR name) noexcept
	{
		const std::wstring commandLine = CommandLineText();
		const std::wstring needle = std::wstring(name) + L"=";
		const size_t at = commandLine.find(needle);
		if (at == std::wstring::npos) {
			return std::wstring();
		}
		size_t valueStart = at + needle.size();
		if (valueStart < commandLine.size() && commandLine[valueStart] == L'"') {
			++valueStart;
			const size_t end = commandLine.find(L'"', valueStart);
			return commandLine.substr(valueStart,
				end == std::wstring::npos ? std::wstring::npos : end - valueStart);
		}
		size_t end = commandLine.find(L' ', valueStart);
		if (end == std::wstring::npos) {
			end = commandLine.size();
		}
		return commandLine.substr(valueStart, end - valueStart);
	}

	// =====================================================================
	// 面板窗口
	// =====================================================================

	constexpr PCWSTR PanelClassName = L"R3ShieldCoreSuperDeskPanel";
	constexpr PCWSTR PanelTitleText = L"R3ShieldCore \u00b7 超级置顶面板";

	constexpr int PanelWidth = 424;
	constexpr int PanelHeight = 292;
	constexpr int PanelTitleHeight = 40;
	constexpr int PanelPadding = 16;
	constexpr int PanelRowHeight = 26;
	constexpr int PanelLabelWidth = 76;
	constexpr int PanelCloseSize = 30;
	constexpr int PanelTimerId = 1;

	// 配色跟控制台保持一致（浅色主题）。面板在安全桌面上，
	// 背景必须是**不透明**的 —— 安全桌面没有 DWM 合成，半透明会变成黑块。
	constexpr COLORREF PanelColorBackground = RGB(250, 250, 250);
	constexpr COLORREF PanelColorHeader = RGB(255, 255, 255);
	constexpr COLORREF PanelColorBorder = RGB(226, 226, 226);
	constexpr COLORREF PanelColorTextPrimary = RGB(24, 24, 24);
	constexpr COLORREF PanelColorTextSecondary = RGB(110, 110, 110);
	constexpr COLORREF PanelColorAccent = RGB(0, 120, 215);
	constexpr COLORREF PanelColorOk = RGB(16, 124, 16);
	constexpr COLORREF PanelColorBad = RGB(209, 52, 56);
	constexpr COLORREF PanelColorWouldBlock = RGB(230, 126, 34);

	struct PanelState
	{
		HANDLE stopEvent = nullptr;
		std::wstring stopFilePath;
		HANDLE engineProcess = nullptr;
		DWORD enginePid = 0;
		DWORD startedTick = 0;

		HANDLE policyMapping = nullptr;
		const R3ShieldCore::Policy* policy = nullptr;
		HANDLE channelMapping = nullptr;
		const volatile R3ShieldCore::ChannelHeader* channel = nullptr;

		HFONT titleFont = nullptr;
		HFONT labelFont = nullptr;
		HFONT valueFont = nullptr;
		HFONT smallFont = nullptr;

		bool dragging = false;
	};

	PanelState g_panel;

	// 引擎侧的句柄。只在 GUI 线程读写（Launch / Stop / IsRunning 都从那里调）。
	// 面板侧不会用到这两个 —— 它有自己的 g_panel.stopEvent / engineProcess。
	HANDLE g_panelProcess = nullptr;
	HANDLE g_panelStopEvent = nullptr;
	std::wstring g_panelStopFilePath;

	// 把事件通道映射进来（只读）。失败不算致命 —— 面板照样能显示身份与桌面。
	//
	// ⚠️ 前缀必须**跟引擎一致**：引擎建通道时先试 Global\、失败才退回会话命名
	//    （r3shieldcore_channel.cpp:211/219）。提权运行时基本都会用上 Global\，
	//    所以这里两个都试，别只认会话命名 —— 只认一个会静默变成"未连上引擎"。
	void AttachSharedObjects(DWORD enginePid) noexcept
	{
		const PCWSTR prefixes[] = { R3ShieldCore::GlobalNamePrefix, R3ShieldCore::SessionNamePrefix };
		wchar_t name[R3ShieldCore::ObjectNameCapacity] = {};

		for (PCWSTR prefix : prefixes) {
			if (g_panel.policy) {
				break;
			}
			R3ShieldCore::MakePolicyName(name, _countof(name), prefix, enginePid);
			HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
			if (!mapping) {
				continue;
			}
			const void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
			if (view) {
				const auto* policy = static_cast<const R3ShieldCore::Policy*>(view);
				if (policy->Magic == R3ShieldCore::PolicyMagic &&
					policy->EngineProcessId == enginePid) {
					g_panel.policy = policy;
					g_panel.policyMapping = mapping;
					continue;
				}
				UnmapViewOfFile(view);
			}
			CloseHandle(mapping);
		}

		for (PCWSTR prefix : prefixes) {
			if (g_panel.channel) {
				break;
			}
			R3ShieldCore::MakeChannelName(name, _countof(name), prefix, enginePid);
			HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, name);
			if (!mapping) {
				continue;
			}
			const void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
			if (view) {
				const auto* header = static_cast<const R3ShieldCore::ChannelHeader*>(view);
				if (header->Magic == R3ShieldCore::ChannelMagic) {
					g_panel.channel = header;
					g_panel.channelMapping = mapping;
					continue;
				}
				UnmapViewOfFile(view);
			}
			CloseHandle(mapping);
		}
	}

	PCWSTR ModeText(ULONG mode) noexcept
	{
		switch (static_cast<R3ShieldCore::Mode>(mode)) {
		case R3ShieldCore::Mode::Block: return L"BLOCK";
		case R3ShieldCore::Mode::Ask: return L"ASK";
		case R3ShieldCore::Mode::BlockAll: return L"BLOCK_ALL";
		case R3ShieldCore::Mode::BlockAllSafe: return L"BLOCK_ALL_SAFE";
		default: return L"LOG";
		}
	}

	COLORREF ModeColor(ULONG mode) noexcept
	{
		switch (static_cast<R3ShieldCore::Mode>(mode)) {
		case R3ShieldCore::Mode::Block: return PanelColorWouldBlock;
		case R3ShieldCore::Mode::Ask: return PanelColorAccent;
		case R3ShieldCore::Mode::BlockAll:
		case R3ShieldCore::Mode::BlockAllSafe: return PanelColorBad;
		default: return PanelColorTextSecondary;
		}
	}

	void FillRectColor(HDC dc, const RECT& rect, COLORREF color) noexcept
	{
		HBRUSH brush = CreateSolidBrush(color);
		FillRect(dc, &rect, brush);
		DeleteObject(brush);
	}

	void DrawTextIn(HDC dc, PCWSTR text, const RECT& rect, HFONT font,
		COLORREF color, UINT format) noexcept
	{
		HGDIOBJ oldFont = SelectObject(dc, font);
		SetBkMode(dc, TRANSPARENT);
		SetTextColor(dc, color);
		DrawTextW(dc, text, -1, const_cast<RECT*>(&rect), format | DT_NOPREFIX);
		SelectObject(dc, oldFont);
	}

	RECT PanelCloseRect() noexcept
	{
		return { PanelWidth - PanelPadding - PanelCloseSize, 5,
			PanelWidth - PanelPadding, 5 + PanelCloseSize };
	}

	// 一行「标签 + 值」。valueColor 单独给，好把"是/否"染成绿/红。
	int DrawPanelRow(HDC dc, int top, int labelLeft, int valueLeft,
		PCWSTR label, PCWSTR value, COLORREF valueColor) noexcept
	{
		RECT labelRect = { labelLeft, top, valueLeft - 6, top + PanelRowHeight };
		DrawTextIn(dc, label, labelRect, g_panel.labelFont, PanelColorTextSecondary,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		RECT valueRect = { valueLeft, top, PanelWidth - PanelPadding, top + PanelRowHeight };
		DrawTextIn(dc, value, valueRect, g_panel.valueFont, valueColor,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
		return top + PanelRowHeight;
	}

	void PaintPanel(HWND window) noexcept
	{
		PAINTSTRUCT paint = {};
		HDC dc = BeginPaint(window, &paint);
		if (!dc) {
			return;
		}

		// 双缓冲：安全桌面下直接画会有明显闪烁。
		HDC buffer = CreateCompatibleDC(dc);
		HBITMAP bitmap = CreateCompatibleBitmap(dc, PanelWidth, PanelHeight);
		HGDIOBJ oldBitmap = SelectObject(buffer, bitmap);

		RECT full = { 0, 0, PanelWidth, PanelHeight };
		FillRectColor(buffer, full, PanelColorBackground);

		// 标题栏
		RECT header = { 0, 0, PanelWidth, PanelTitleHeight };
		FillRectColor(buffer, header, PanelColorHeader);
		RECT headerLine = { 0, PanelTitleHeight - 1, PanelWidth, PanelTitleHeight };
		FillRectColor(buffer, headerLine, PanelColorBorder);

		RECT titleRect = { PanelPadding, 0, PanelWidth - PanelPadding - PanelCloseSize - 6, PanelTitleHeight };
		DrawTextIn(buffer, PanelTitleText, titleRect, g_panel.titleFont, PanelColorTextPrimary,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE);

		// 关闭按钮
		RECT closeRect = PanelCloseRect();
		DrawTextIn(buffer, L"\u00d7", closeRect, g_panel.titleFont, PanelColorTextSecondary,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);

		// ---- 正文 ----
		const int labelLeft = PanelPadding;
		const int valueLeft = PanelPadding + PanelLabelWidth;
		const int secondLeft = PanelWidth / 2 + 8;
		int y = PanelTitleHeight + 16;

		wchar_t text[256] = {};

		// 桌面 —— 这一行就是整个配方的证据：它必须显示 Winlogon。
		swprintf_s(text, _countof(text), L"%s%s", CurrentDesktopName(),
			_wcsicmp(CurrentDesktopName(), L"Winlogon") == 0 ? L"（UAC 安全桌面）" : L"（不是安全桌面！）");
		y = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"桌面", text,
			_wcsicmp(CurrentDesktopName(), L"Winlogon") == 0 ? PanelColorOk : PanelColorBad);

		// 身份
		const bool isSystem = SelfIsLocalSystem();
		const bool hasUiAccess = SelfUIAccessFlag() != 0;
		const bool isElevated = SelfIsElevated();
		swprintf_s(text, _countof(text), L"SYSTEM %s    UIAccess %s    提权 %s",
			isSystem ? L"是" : L"否", hasUiAccess ? L"是" : L"否", isElevated ? L"是" : L"否");
		y = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"身份", text,
			(isSystem && isElevated) ? PanelColorOk : PanelColorBad);

		// 模式
		const ULONG mode = g_panel.policy ? g_panel.policy->Mode : 0;
		swprintf_s(text, _countof(text), L"%s%s", ModeText(mode),
			g_panel.policy ? L"" : L"（未连上引擎）");
		y = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"模式", text,
			g_panel.policy ? ModeColor(mode) : PanelColorTextSecondary);

		// 分隔线
		y += 6;
		RECT separator = { PanelPadding, y, PanelWidth - PanelPadding, y + 1 };
		FillRectColor(buffer, separator, PanelColorBorder);
		y += 12;

		// 统计（来自共享事件通道的头部计数）
		unsigned long long totalEvents = 0;
		long highRiskAsked = 0;
		long highRiskBlocked = 0;
		long dropped = 0;
		if (g_panel.channel) {
			totalEvents = static_cast<unsigned long long>(
				static_cast<unsigned long>(g_panel.channel->WriteIndex));
			highRiskAsked = g_panel.channel->HighRiskAsked;
			highRiskBlocked = g_panel.channel->HighRiskBlocked;
			dropped = g_panel.channel->DroppedCount;
		}

		swprintf_s(text, _countof(text), L"事件总数 %llu", totalEvents);
		const int rowLeft = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"统计", text,
			PanelColorTextPrimary);
		swprintf_s(text, _countof(text), L"高危询问 %ld", highRiskAsked);
		DrawPanelRow(buffer, y, secondLeft, secondLeft + PanelLabelWidth, L"", text,
			highRiskAsked > 0 ? PanelColorWouldBlock : PanelColorTextPrimary);
		y = rowLeft;

		swprintf_s(text, _countof(text), L"丢弃 %ld", dropped);
		const int rowLeft2 = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"", text,
			dropped > 0 ? PanelColorBad : PanelColorTextPrimary);
		swprintf_s(text, _countof(text), L"高危拦截 %ld", highRiskBlocked);
		DrawPanelRow(buffer, y, secondLeft, secondLeft + PanelLabelWidth, L"", text,
			highRiskBlocked > 0 ? PanelColorBad : PanelColorTextPrimary);
		y = rowLeft2;

		// 进程与心跳
		swprintf_s(text, _countof(text), L"面板 %lu  ·  引擎 %lu",
			static_cast<unsigned long>(GetCurrentProcessId()),
			static_cast<unsigned long>(g_panel.enginePid));
		y = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"进程", text, PanelColorTextPrimary);

		swprintf_s(text, _countof(text), L"%lu 秒",
			static_cast<unsigned long>((GetTickCount() - g_panel.startedTick) / 1000));
		y = DrawPanelRow(buffer, y, labelLeft, valueLeft, L"心跳", text, PanelColorTextSecondary);

		// 底部提示
		RECT hintRect = { PanelPadding, PanelHeight - 34, PanelWidth - PanelPadding, PanelHeight - 12 };
		DrawTextIn(buffer, L"按 Esc 或点右上角关闭；主引擎退出时本面板自动结束",
			hintRect, g_panel.smallFont, PanelColorTextSecondary,
			DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

		// 外框
		RECT border = { 0, 0, PanelWidth, PanelHeight };
		HBRUSH frame = CreateSolidBrush(PanelColorBorder);
		FrameRect(buffer, &border, frame);
		DeleteObject(frame);

		BitBlt(dc, 0, 0, PanelWidth, PanelHeight, buffer, 0, 0, SRCCOPY);

		SelectObject(buffer, oldBitmap);
		DeleteObject(bitmap);
		DeleteDC(buffer);
		EndPaint(window, &paint);
	}

	LRESULT CALLBACK PanelWndProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) noexcept
	{
		switch (message) {
		case WM_ERASEBKGND:
			return 1;

		case WM_PAINT:
			PaintPanel(window);
			return 0;

		case WM_NCHITTEST: {
			// 无边框窗口要自己给拖动能力：标题栏（除关闭按钮外）报 HTCAPTION。
			POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
			RECT client = {};
			GetWindowRect(window, &client);
			point.x -= client.left;
			point.y -= client.top;
			RECT closeRect = PanelCloseRect();
			if (PtInRect(&closeRect, point)) {
				return HTCLIENT;
			}
			if (point.y >= 0 && point.y < PanelTitleHeight && point.x >= 0 && point.x < PanelWidth) {
				return HTCAPTION;
			}
			return HTCLIENT;
		}

		case WM_LBUTTONDOWN: {
			POINT point = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
			RECT closeRect = PanelCloseRect();
			if (PtInRect(&closeRect, point)) {
				PanelLog("[panel] close button clicked");
				DestroyWindow(window);
			}
			return 0;
		}

		case WM_KEYDOWN:
			if (wParam == VK_ESCAPE) {
				PanelLog("[panel] Esc pressed");
				DestroyWindow(window);
				return 0;
			}
			break;

		case WM_TIMER:
			// ★ 每秒重申一次 topmost。
			//   面板是"点超级置顶"那一刻就建好的，而 consent.exe（UAC 提示）的
			//   窗口是**之后**才在 Winlogon 桌面上建出来的 —— 两个都是 topmost
			//   时后建的在上，面板会被 UAC 提示盖住。周期性重申把它抬回去。
			//   ⚠️ SWP_NOACTIVATE 不能省：安全桌面上正在显示的是 UAC 提示，
			//      抢走它的键盘输入是绝对不行的。
			SetWindowPos(window, HWND_TOPMOST, 0, 0, 0, 0,
				SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
			InvalidateRect(window, nullptr, FALSE);
			if (!g_panel.stopFilePath.empty() &&
				GetFileAttributesW(g_panel.stopFilePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
				PanelLog("[panel] stop reason=stop file removed");
				DestroyWindow(window);
			}
			return 0;

		case WM_DESTROY:
			KillTimer(window, PanelTimerId);
			PostQuitMessage(0);
			return 0;

		default:
			break;
		}

		return DefWindowProcW(window, message, wParam, lParam);
	}

	bool CreatePanelFonts() noexcept
	{
		auto makeFont = [](int height, int weight, PCWSTR face) -> HFONT {
			return CreateFontW(height, 0, 0, 0, weight, FALSE, FALSE, FALSE,
				DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
				CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
		};
		// 安全桌面上字体跟普通桌面同一套；用雅黑保证中文不落回点阵宋体。
		g_panel.titleFont = makeFont(-16, FW_SEMIBOLD, L"Microsoft YaHei UI");
		g_panel.labelFont = makeFont(-13, FW_NORMAL, L"Microsoft YaHei UI");
		g_panel.valueFont = makeFont(-14, FW_NORMAL, L"Microsoft YaHei UI");
		g_panel.smallFont = makeFont(-12, FW_NORMAL, L"Microsoft YaHei UI");
		return g_panel.titleFont && g_panel.labelFont && g_panel.valueFont && g_panel.smallFont;
	}

	void DestroyPanelFonts() noexcept
	{
		HFONT* fonts[] = { &g_panel.titleFont, &g_panel.labelFont, &g_panel.valueFont, &g_panel.smallFont };
		for (HFONT* font : fonts) {
			if (*font) {
				DeleteObject(*font);
				*font = nullptr;
			}
		}
	}
}

namespace R3ShieldCoreSuperDesk
{
	bool LaunchUiAccessInstance(DWORD parentPid, DWORD* childPid, DWORD* errorCode) noexcept
	{
		if (childPid) *childPid = 0;
		if (errorCode) *errorCode = ERROR_SUCCESS;

		HANDLE selfToken = nullptr;
		HANDLE sourceProcess = nullptr;
		HANDLE sourceToken = nullptr;
		HANDLE impersonationToken = nullptr;
		HANDLE primaryToken = nullptr;
		PROCESS_INFORMATION process{};
		bool impersonating = false;
		DWORD failure = ERROR_SUCCESS;
		bool created = false;

		// ★ 带行号的失败记录。
		//
		// 以前这里只记错误码，排查 `[gui] UIAccess handoff failed err=1460` 时
		// **完全不知道该看哪一行** —— 因为 1460(ERROR_TIMEOUT) 在本文件里字面上
		// 只出现在 WaitForUiAccessParentExit，而那条路根本不经过这里，
		// 静态读代码会得出"不可能"的结论。加行号后一次实测就能定位。
		auto fail = [&](DWORD code,
			const std::source_location& location = std::source_location::current()) noexcept {
			failure = code ? code : GetLastError();
			ConsoleLog("[gui] UIAccess handoff FAILED at %s:%d err=%lu\n",
				location.file_name(), static_cast<int>(location.line()),
				static_cast<unsigned long>(failure));
		};

		ConsoleLog("[gui] UIAccess handoff BEGIN pid=%lu\n",
			static_cast<unsigned long>(GetCurrentProcessId()));

		do {
			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ASSIGN_PRIMARY,
				&selfToken)) {
				fail(GetLastError());
				break;
			}
			EnablePrivilege(selfToken, SE_DEBUG_NAME);
			EnablePrivilege(selfToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			EnablePrivilege(selfToken, SE_INCREASE_QUOTA_NAME);
			EnablePrivilege(selfToken, SE_IMPERSONATE_NAME);
			EnablePrivilege(selfToken, SE_TCB_NAME);

			DWORD sessionId = 0;
			if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
				fail(GetLastError());
				break;
			}
			const DWORD sourcePid = FindSystemTokenSource(sessionId);
			if (!sourcePid) {
				fail(ERROR_NOT_FOUND);
				break;
			}

			sourceProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
			if (!sourceProcess || !OpenProcessToken(sourceProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &sourceToken)) {
				fail(GetLastError());
				break;
			}
			if (!TokenIsLocalSystem(sourceToken)) {
				fail(ERROR_INVALID_OWNER);
				break;
			}

			SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, FALSE};
			if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &attributes,
				SecurityImpersonation, TokenImpersonation, &impersonationToken)) {
				fail(GetLastError());
				break;
			}
			if (!ImpersonateLoggedOnUser(impersonationToken)) {
				fail(GetLastError());
				break;
			}
			impersonating = true;
			EnablePrivilege(impersonationToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			EnablePrivilege(impersonationToken, SE_INCREASE_QUOTA_NAME);
			EnablePrivilege(impersonationToken, SE_TCB_NAME);

			// ★ 与 KSword `MainWindow::launchSelfWithSystemUiAccessToken` 对齐：
			//   主令牌复制的是 **SYSTEM 源**，不是本进程自己的令牌。
			//
			//   为什么必须换源：win32k 判定 UIAccess 只看**进程创建那一刻的有效令牌**。
			//   用「自己的管理员令牌 + 就地设 TokenUIAccess」这条路，实测 5 组配置全灭
			//   （docs/HANDOVER.md §3.10m「实测二」）—— 令牌上那个位复查 = 1，
			//   但 win32k 创建进程时不认，子进程出生即 uiAccess=0 ⇒
			//   ApplyHighestPermittedTopmost 里 `if (uiAccessEnabled)` 直接挡住，
			//   SetWindowBand 压根不会被调用。KSword 能用的原因正是它复制 SYSTEM 令牌。
			if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &attributes,
				SecurityImpersonation, TokenPrimary, &primaryToken)) {
				fail(GetLastError());
				break;
			}
			EnablePrivilege(primaryToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			EnablePrivilege(primaryToken, SE_INCREASE_QUOTA_NAME);
			EnablePrivilege(primaryToken, SE_TCB_NAME);

			// ★ 会话号必须从**源令牌**查 —— primaryToken 现在复制的是 SYSTEM 源，
			//   它的会话号可能不是本进程的（winlogon 有 rank 30 的跨会话候选）。
			//   拿错会话建进程，窗口会生在当前没被显示的会话里。
			DWORD sourceSession = 0;
			DWORD returned = 0;
			if (!GetTokenInformation(sourceToken, TokenSessionId, &sourceSession,
				sizeof(sourceSession), &returned)) {
				fail(GetLastError());
				break;
			}
			if (sourceSession != sessionId) {
				if (!SetTokenInformation(primaryToken, TokenSessionId, &sessionId, sizeof(sessionId))) {
					fail(GetLastError());
					break;
				}
			}

			DWORD uiAccess = 1;
			if (!SetTokenInformation(primaryToken, TokenUIAccess, &uiAccess, sizeof(uiAccess))) {
				fail(GetLastError());
				break;
			}
			DWORD verified = 0;
			if (!GetTokenInformation(primaryToken, TokenUIAccess, &verified,
				sizeof(verified), &returned) || verified == 0) {
				fail(GetLastError() ? GetLastError() : ERROR_INVALID_DATA);
				break;
			}

			const std::wstring selfPath = ModulePath();
			if (selfPath.empty()) {
				fail(ERROR_FILE_NOT_FOUND);
				break;
			}

			std::wstring commandLine = L"\"" + selfPath + L"\" " + UiAccessArgument
				+ L" --uiaccess-parent-pid=" + std::to_wstring(parentPid);
			STARTUPINFOW startup{sizeof(startup)};
			wchar_t desktop[] = L"winsta0\\default";
			startup.lpDesktop = desktop;

			// 走到这里 = 令牌链全通（复制 SYSTEM → 改会话号 → 设 TokenUIAccess → 复查）。
			// 记一行，用来区分"失败在令牌链"还是"失败在 CreateProcess"。
			ConsoleLog("[gui] UIAccess handoff: tokens ready (selfSession=%lu sourceSession=%lu uiAccess=%lu), launching\n",
				static_cast<unsigned long>(sessionId),
				static_cast<unsigned long>(sourceSession),
				static_cast<unsigned long>(verified));

			// 与 KSword MainWindow::launchSelfWithSystemUiAccessToken 相同：
			// CreateProcessAsUserW 必须在 SYSTEM 模拟上下文中调用。
			// 先 RevertToSelf 再调用它时，调用者会退回普通管理员令牌，
			// 即使 primaryToken 已经是 SYSTEM，也可能因缺少
			// SeAssignPrimaryToken/SeIncreaseQuota 而返回 ERROR_PRIVILEGE_NOT_HELD。
			SetLastError(ERROR_SUCCESS);
			created = CreateProcessAsUserW(primaryToken, selfPath.c_str(), commandLine.data(),
				nullptr, nullptr, FALSE,
				CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
				nullptr, nullptr, &startup, &process) != FALSE;
			if (created) {
				ConsoleLog("[gui] UIAccess CreateProcessAsUserW succeeded child=%lu\n",
					static_cast<unsigned long>(process.dwProcessId));
				RevertToSelf();
				impersonating = false;
			}
			else {
				const DWORD asUserError = GetLastError();
				ConsoleLog("[gui] UIAccess CreateProcessAsUserW failed err=%lu, retrying CreateProcessWithTokenW\n",
					static_cast<unsigned long>(asUserError));
				RevertToSelf();
				impersonating = false;
				SetLastError(ERROR_SUCCESS);
				created = CreateProcessWithTokenW(primaryToken, LOGON_NETCREDENTIALS_ONLY,
					selfPath.c_str(), commandLine.data(),
					CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
					nullptr, nullptr, &startup, &process) != FALSE;
				if (created) {
					ConsoleLog("[gui] UIAccess CreateProcessWithTokenW succeeded child=%lu\n",
						static_cast<unsigned long>(process.dwProcessId));
				}
				else {
					ConsoleLog("[gui] UIAccess CreateProcessWithTokenW failed err=%lu\n",
						static_cast<unsigned long>(GetLastError()));
				}
			}
			if (!created) {
				fail(GetLastError());
				break;
			}

			// CreateProcess 成功不等于子进程实际继承了 UIAccess；先查询
			// 子进程令牌，确认接管实例具备 class/src/main.cpp 所需的令牌状态。
			HANDLE launchedToken = nullptr;
			DWORD launchedUiAccess = 0;
			DWORD launchedReturned = 0;
			DWORD launchedTokenError = ERROR_SUCCESS;
			const bool launchedTokenOpened =
				OpenProcessToken(process.hProcess, TOKEN_QUERY, &launchedToken) != FALSE;
			if (!launchedTokenOpened) {
				launchedTokenError = GetLastError();
			}
			const bool launchedUiAccessQueried = launchedTokenOpened &&
				GetTokenInformation(launchedToken, TokenUIAccess, &launchedUiAccess,
					sizeof(launchedUiAccess), &launchedReturned) != FALSE;
			if (launchedTokenOpened && !launchedUiAccessQueried) {
				launchedTokenError = GetLastError();
			}
			ConsoleLog("[gui] UIAccess child pid=%lu tokenUIAccess=%lu queried=%d\n",
				static_cast<unsigned long>(process.dwProcessId),
				static_cast<unsigned long>(launchedUiAccess),
				launchedUiAccessQueried ? 1 : 0);
			if (launchedToken) {
				CloseHandle(launchedToken);
			}
			if (!launchedUiAccessQueried || launchedUiAccess == 0) {
				failure = launchedUiAccessQueried ? ERROR_PRIVILEGE_NOT_HELD :
					(launchedTokenError ? launchedTokenError : ERROR_INVALID_DATA);
				ConsoleLog("[gui] UIAccess child token verification failed err=%lu\n",
					static_cast<unsigned long>(failure));
				TerminateProcess(process.hProcess, 1);
				break;
			}

			if (WaitForSingleObject(process.hProcess, 0) != WAIT_TIMEOUT) {
				failure = ERROR_PROCESS_ABORTED;
				break;
			}
			if (childPid) *childPid = process.dwProcessId;
			ConsoleLog("[gui] UIAccess instance created pid=%lu tokenUIAccess=1\n",
				static_cast<unsigned long>(process.dwProcessId));
		} while (false);

		if (impersonating) RevertToSelf();
		if (process.hThread) CloseHandle(process.hThread);
		if (process.hProcess) CloseHandle(process.hProcess);
		if (primaryToken) CloseHandle(primaryToken);
		if (impersonationToken) CloseHandle(impersonationToken);
		if (sourceToken) CloseHandle(sourceToken);
		if (sourceProcess) CloseHandle(sourceProcess);
		if (selfToken) CloseHandle(selfToken);
		const bool handoffOk = created && failure == ERROR_SUCCESS;
		if (!handoffOk && errorCode) *errorCode = failure;
		return handoffOk;
	}

	bool WaitForUiAccessParentExit(DWORD timeoutMs, DWORD* errorCode) noexcept
	{
		if (errorCode) *errorCode = ERROR_SUCCESS;
		const std::wstring commandLine = GetCommandLineW() ? GetCommandLineW() : L"";
		const std::wstring marker = L"--uiaccess-parent-pid=";
		const size_t start = commandLine.find(marker);
		if (start == std::wstring::npos) return true;
		const DWORD parentPid = wcstoul(commandLine.c_str() + start + marker.size(), nullptr, 10);
		if (!parentPid || parentPid == GetCurrentProcessId()) {
			if (errorCode) *errorCode = ERROR_INVALID_PARAMETER;
			return false;
		}
		HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
		if (!parent) {
			const DWORD error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER) return true;
			if (errorCode) *errorCode = error;
			return false;
		}

		//
		// ★★★ v54：改成**步进轮询**，一发现父进程退出就立刻返回。
		//
		// 为什么不能再用 `WaitForSingleObject(parent, timeoutMs)` 一次等满：
		//
		//   这条路的语义是"等旧引擎把会话拆完、我们才能去建自己的引擎"
		//   （两个引擎同时存在会抢 Policy/Events 共享内存、而且互相
		//     `IsProtectedTarget` 打架）。但旧引擎退出是**异步**的 ——
		//   它要先反注入（`GlobalHookSessionEnd`）、关通道、停 GUI。
		//
		//   用一次性 wait 的时候，"父进程什么时候真的死"这件事由内核
		//   通知，理论上和我们没差别……**但实测有差别**（铁律 21 同族）：
		//   一次 wait 期间本进程被完全阻塞，界面线程也是僵的，
		//   用户看到的是"点了超级置顶之后窗口卡住不动"。
		//   而旧引擎退出只要几百毫秒，剩下 14 秒纯粹是在"等一个已经发生的事"。
		//
		//   步进轮询（50ms 一跳）的好处：
		//     ① 父进程一死立刻继续，通常几百毫秒就进到建引擎那一步；
		//     ② 轮询间隙可以 `Sleep` 出让 CPU，界面线程能画"正在接管…"；
		//     ③ 超时仍然保留（15s），父进程真卡死时行为不变。
		//
		constexpr DWORD kStepMs = 50;
		DWORD waited = 0;
		DWORD wait = WAIT_TIMEOUT;
		while (waited < timeoutMs) {
			const DWORD slice = (timeoutMs - waited < kStepMs) ? (timeoutMs - waited) : kStepMs;
			wait = WaitForSingleObject(parent, slice);
			if (wait != WAIT_TIMEOUT) {
				break;
			}
			waited += slice;
		}

		CloseHandle(parent);
		if (wait == WAIT_OBJECT_0) return true;
		if (errorCode) *errorCode = (wait == WAIT_TIMEOUT) ? ERROR_TIMEOUT : GetLastError();
		return false;
	}

	bool IsPanelInvocation() noexcept
	{
		const std::wstring commandLine = CommandLineText();
		return commandLine.find(PanelArgument) != std::wstring::npos;
	}

	bool IsSelfTestInvocation() noexcept
	{
		const std::wstring commandLine = CommandLineText();
		return commandLine.find(SelfTestArgument) != std::wstring::npos;
	}

	bool IsUiAccessSelfTestInvocation() noexcept
	{
		const std::wstring commandLine = CommandLineText();
		return commandLine.find(UiAccessSelfTestArgument) != std::wstring::npos;
	}

	int RunPanel() noexcept
	{
		g_panel.enginePid = CommandLineNumber(L"--engine-pid");
		const std::wstring stopEventName = CommandLineTextValue(L"--stop-event");
		g_panel.stopFilePath = CommandLineTextValue(L"--stop-file");
		g_panel.startedTick = GetTickCount();

		PanelLog("[panel] start pid=%lu engine=%lu desktop=%ls system=%d uiaccess=%lu elevated=%d",
			static_cast<unsigned long>(GetCurrentProcessId()),
			static_cast<unsigned long>(g_panel.enginePid),
			CurrentDesktopName(),
			SelfIsLocalSystem() ? 1 : 0,
			static_cast<unsigned long>(SelfUIAccessFlag()),
			SelfIsElevated() ? 1 : 0);

		// 面板在安全桌面上，把一行摘要也写入诊断日志。
		ConsoleLog("[superdesk] panel pid=%lu engine=%lu desktop=%ls system=%d uiAccess=%lu\n",
			static_cast<unsigned long>(GetCurrentProcessId()),
			static_cast<unsigned long>(g_panel.enginePid),
			CurrentDesktopName(),
			SelfIsLocalSystem() ? 1 : 0,
			static_cast<unsigned long>(SelfUIAccessFlag()));

		if (!stopEventName.empty()) {
			g_panel.stopEvent = OpenEventW(SYNCHRONIZE, FALSE, stopEventName.c_str());
			PanelLog("[panel] stop event name=%ls opened=%d err=%lu",
				stopEventName.c_str(), g_panel.stopEvent ? 1 : 0,
				g_panel.stopEvent ? ERROR_SUCCESS : GetLastError());
		}
		if (!g_panel.stopFilePath.empty()) {
			PanelLog("[panel] stop file=%ls present=%d",
				g_panel.stopFilePath.c_str(),
				GetFileAttributesW(g_panel.stopFilePath.c_str()) != INVALID_FILE_ATTRIBUTES ? 1 : 0);
		}
		if (g_panel.enginePid != 0) {
			g_panel.engineProcess = OpenProcess(SYNCHRONIZE, FALSE, g_panel.enginePid);
			PanelLog("[panel] engine wait handle opened=%d err=%lu",
				g_panel.engineProcess ? 1 : 0,
				g_panel.engineProcess ? ERROR_SUCCESS : GetLastError());
		}
		AttachSharedObjects(g_panel.enginePid);

		// 面板是 SYSTEM + 安全桌面，属于系统基础设施 —— 显式声明 DPI 感知，
		// 免得在高 DPI 上被位图拉伸（安全桌面同样受 DPI 影响）。
		SetProcessDPIAware();

		if (!CreatePanelFonts()) {
			PanelLog("[panel] CreateFontW failed err=%lu", static_cast<unsigned long>(GetLastError()));
			return 2;
		}

		WNDCLASSEXW windowClass = { sizeof(windowClass) };
		windowClass.style = CS_HREDRAW | CS_VREDRAW;
		windowClass.lpfnWndProc = PanelWndProc;
		windowClass.hInstance = GetModuleHandleW(nullptr);
		windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
		windowClass.hbrBackground = nullptr;
		windowClass.lpszClassName = PanelClassName;
		if (!RegisterClassExW(&windowClass)) {
			const DWORD error = GetLastError();
			PanelLog("[panel] RegisterClassExW failed err=%lu", static_cast<unsigned long>(error));
			DestroyPanelFonts();
			return 3;
		}

		const int screenWidth = GetSystemMetrics(SM_CXSCREEN);
		const int screenHeight = GetSystemMetrics(SM_CYSCREEN);
		HWND window = CreateWindowExW(
			WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
			PanelClassName, PanelTitleText,
			WS_POPUP,
			screenWidth - PanelWidth - 40,
			screenHeight - PanelHeight - 120,
			PanelWidth, PanelHeight,
			nullptr, nullptr, windowClass.hInstance, nullptr);
		if (!window) {
			const DWORD error = GetLastError();
			PanelLog("[panel] CreateWindowExW failed err=%lu", static_cast<unsigned long>(error));
			DestroyPanelFonts();
			return 4;
		}

		// ⚠️ 必须 SW_SHOWNOACTIVATE / SWP_NOACTIVATE：安全桌面上正在显示的是
		//    UAC 提示，抢焦点会把它的键盘输入夺走。
		ShowWindow(window, SW_SHOWNOACTIVATE);
		SetWindowPos(window, HWND_TOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
		UpdateWindow(window);
		SetTimer(window, PanelTimerId, 1000, nullptr);

		// 留痕：面板在安全桌面上，屏幕抓不到（PrintWindow 在安全桌面也拿不到），
		// 所以把"窗口确实建出来并且是置顶可见的"写进日志 —— 这是可断言的证据。
		{
			RECT windowRect = {};
			GetWindowRect(window, &windowRect);
			PanelLog("[panel] window created hwnd=%p visible=%d topmost=%d rect=%ld,%ld,%ld,%ld",
				window,
				IsWindowVisible(window) ? 1 : 0,
				(GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_TOPMOST) ? 1 : 0,
				windowRect.left, windowRect.top, windowRect.right, windowRect.bottom);
		}

		// enginePid == 0 = 独立自检模式（不经引擎、直接命令行拉起）。
		// 给它一个固定寿命，否则只能靠人手动关 —— 自动化验证没法收尾。
		//
		// ★ 必须按**绝对截止时刻**算，不能把时长直接丢给
		//   MsgWaitForMultipleObjects —— 那个超时**每收到一条消息就重新计时**，
		//   而面板每秒都有一个 WM_TIMER，等于无限续期、永不退出。
		//   （实测：第一次自检的日志只有 "auto exit in 6000 ms"，没有 exit 行。）
		constexpr ULONGLONG SelfTestLifetimeMs = 6000;
		const ULONGLONG deadlineTick = (g_panel.enginePid == 0)
			? GetTickCount64() + SelfTestLifetimeMs
			: 0;
		if (g_panel.enginePid == 0) {
			PanelLog("[panel] standalone self-test mode: auto exit in %llu ms (deadline)",
				SelfTestLifetimeMs);
		}

		MSG message = {};
		bool running = true;
		while (running) {
			// 等三样东西：消息、停止事件、引擎进程退出。
			HANDLE waits[2] = {};
			DWORD waitCount = 0;
			if (g_panel.stopEvent) {
				waits[waitCount++] = g_panel.stopEvent;
			}
			if (g_panel.engineProcess) {
				waits[waitCount++] = g_panel.engineProcess;
			}

			// 自检模式：每次循环按**剩余时间**给超时（见上面 deadlineTick 的说明）。
			DWORD waitMs = INFINITE;
			if (deadlineTick != 0) {
				const ULONGLONG now = GetTickCount64();
				waitMs = (now >= deadlineTick)
					? 0
					: static_cast<DWORD>(deadlineTick - now);
			}

			const DWORD result = MsgWaitForMultipleObjects(waitCount, waits, FALSE, waitMs, QS_ALLINPUT);
			if (result == WAIT_OBJECT_0 + waitCount) {
				// 有消息
				while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
					if (message.message == WM_QUIT) {
						running = false;
						break;
					}
					TranslateMessage(&message);
					DispatchMessageW(&message);
				}
				continue;
			}
			if (result >= WAIT_OBJECT_0 && result < WAIT_OBJECT_0 + waitCount) {
				PanelLog("[panel] stop reason=event(%lu) result=%lu",
					static_cast<unsigned long>(result - WAIT_OBJECT_0),
					static_cast<unsigned long>(result));
				break;
			}
			if (result == WAIT_TIMEOUT) {
				PanelLog("[panel] stop reason=self-test deadline reached");
				break;
			}
			if (result == WAIT_FAILED) {
				PanelLog("[panel] MsgWaitForMultipleObjects failed err=%lu",
					static_cast<unsigned long>(GetLastError()));
				break;
			}
		}

		if (IsWindow(window)) {
			DestroyWindow(window);
		}
		if (g_panel.stopEvent) {
			CloseHandle(g_panel.stopEvent);
			g_panel.stopEvent = nullptr;
		}
		if (g_panel.engineProcess) {
			CloseHandle(g_panel.engineProcess);
			g_panel.engineProcess = nullptr;
		}
		if (g_panel.policy) {
			UnmapViewOfFile(static_cast<const void*>(g_panel.policy));
			g_panel.policy = nullptr;
		}
		if (g_panel.policyMapping) {
			CloseHandle(g_panel.policyMapping);
			g_panel.policyMapping = nullptr;
		}
		if (g_panel.channel) {
			// channel 是 volatile const（跨进程共享内存），UnmapViewOfFile 要
			// 非 volatile 的指针 —— 这里只是把映射还回去，不改内容。
			UnmapViewOfFile(const_cast<const void*>(
				static_cast<const volatile void*>(g_panel.channel)));
			g_panel.channel = nullptr;
		}
		if (g_panel.channelMapping) {
			CloseHandle(g_panel.channelMapping);
			g_panel.channelMapping = nullptr;
		}
		DestroyPanelFonts();
		PanelLog("[panel] exit pid=%lu", static_cast<unsigned long>(GetCurrentProcessId()));
		return 0;
	}

	// =====================================================================
	// 全链路自检（--superdesk-selftest）
	// =====================================================================
	//
	// 这个入口是给"自动化 / 人肉验证"用的：它自己扮演引擎，走完整条 A 配方，
	// 把面板拉到 winsta0\Winlogon 上，等面板自己退（6 秒），再收尾。
	//
	// ⚠️ 面板在**安全桌面**上，正常用眼看**看不到** —— 屏幕上显示的是 Default
	//    桌面。要真的看见它，得让系统切到安全桌面：
	//      · 触发一个 UAC 提示（会切过去），或
	//      · Win+L 锁屏（锁屏界面就在 Winlogon 桌面上）
	//    所以自检的判定依据是**日志**，不是眼睛。
	//
	// 判定标准（superdesk-panel.log 里应当出现）：
	//    [panel] start ... desktop=Winlogon system=1 uiaccess=1 elevated=1
	//    [panel] window created ... visible=1 topmost=1
	//    [panel] stop reason=self-test deadline reached
	//    [panel] exit pid=...
	// 其中 desktop=Winlogon + system=1 是"配方真的走通了"的硬证据。
	int RunSelfTest() noexcept
	{
		TruncatePanelLog();

		DWORD sessionId = 0;
		ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

		PanelLog("=== superdesk selftest BEGIN pid=%lu ===",
			static_cast<unsigned long>(GetCurrentProcessId()));
		PanelLog("[selftest] self: desktop=%ls system=%d uiaccess=%lu elevated=%d session=%lu",
			CurrentDesktopName(),
			SelfIsLocalSystem() ? 1 : 0,
			static_cast<unsigned long>(SelfUIAccessFlag()),
			SelfIsElevated() ? 1 : 0,
			static_cast<unsigned long>(sessionId));

		const DWORD sourcePid = FindSystemTokenSource(sessionId);
		PanelLog("[selftest] token source pid=%lu (winlogon.exe 优先，services.exe 兜底)",
			static_cast<unsigned long>(sourcePid));
		if (sourcePid == 0) {
			PanelLog("[selftest] FAILED: 找不到 SYSTEM 令牌源");
			ConsoleLog("[selftest] FAILED: no SYSTEM token source\n");
			return 1;
		}

		DWORD panelPid = 0;
		DWORD error = ERROR_SUCCESS;
		if (!Launch(0, &panelPid, &error)) {
			PanelLog("[selftest] FAILED: Launch err=%lu", static_cast<unsigned long>(error));
			ConsoleLog("[selftest] FAILED: Launch err=%lu\n", static_cast<unsigned long>(error));
			return 1;
		}
		PanelLog("[selftest] panel launched pid=%lu (目标桌面 winsta0\\Winlogon)",
			static_cast<unsigned long>(panelPid));
		ConsoleLog("[selftest] panel pid=%lu launched on winsta0\\Winlogon\n",
			static_cast<unsigned long>(panelPid));

		// 面板在安全桌面上，看不到 —— 等它自己按 6 秒寿命退掉。
		HANDLE panelProcess = OpenProcess(SYNCHRONIZE, FALSE, panelPid);
		if (panelProcess) {
			const DWORD waited = WaitForSingleObject(panelProcess, 20000);
			PanelLog("[selftest] panel %s",
				waited == WAIT_OBJECT_0 ? "exited" : "wait TIMED OUT (20000 ms)");
			CloseHandle(panelProcess);
		}
		else {
			PanelLog("[selftest] OpenProcess(panel pid=%lu) failed err=%lu",
				static_cast<unsigned long>(panelPid),
				static_cast<unsigned long>(GetLastError()));
		}
		Stop();

		PanelLog("=== superdesk selftest END rc=0 ===");
		ConsoleLog("[selftest] DONE rc=0\n");
		return 0;
	}

	// =====================================================================
	// UIAccess 重启链路自检（--uiaccess-selftest）
	// =====================================================================
	//
	// ★ 存在的理由（铁律 22）：`--superdesk-selftest` 走的是 `Launch()`
	//   （A 配方 → 安全桌面面板），而**用户点「超级置顶」按钮**走的是
	//   `LaunchUiAccessInstance()` —— 两条**完全独立**的代码路径。
	//   所以 A 配方自检全绿，用户点按钮照样可能失败（实测：
	//   `[gui] UIAccess handoff failed err=1460`）。这个入口专门补这个洞。
	//
	// 判定标准（superdesk-panel.log）：
	//     [uitest] LaunchUiAccessInstance ok=1 child=<pid> err=0
	//     [uitest] child alive after 3s=1
	//     === uiaccess selftest END rc=0 ===
	// ok=0 时 err 就是失败点，配合 HANDOVER §3.10m 的错误码表定位。
	int RunUiAccessSelfTest() noexcept
	{
		TruncatePanelLog();
		PanelLog("=== uiaccess selftest BEGIN pid=%lu ===",
			static_cast<unsigned long>(GetCurrentProcessId()));
		PanelLog("[uitest] self: desktop=%ls system=%d uiaccess=%lu elevated=%d",
			CurrentDesktopName(),
			SelfIsLocalSystem() ? 1 : 0,
			static_cast<unsigned long>(SelfUIAccessFlag()),
			SelfIsElevated() ? 1 : 0);

		DWORD childPid = 0;
		DWORD error = ERROR_SUCCESS;
		const bool ok = LaunchUiAccessInstance(GetCurrentProcessId(), &childPid, &error);
		PanelLog("[uitest] LaunchUiAccessInstance ok=%d child=%lu err=%lu",
			ok ? 1 : 0, static_cast<unsigned long>(childPid),
			static_cast<unsigned long>(error));
		ConsoleLog("[uitest] LaunchUiAccessInstance ok=%d child=%lu err=%lu\n",
			ok ? 1 : 0, static_cast<unsigned long>(childPid),
			static_cast<unsigned long>(error));

		// ★ 自检是安全的：子实例启动后会先 `WaitForUiAccessParentExit` 等**本进程**
		//   退出，所以这几秒里它**不会**启动第二份引擎（不会全局注入）。
		//   确认它还活着，然后收掉，避免留下孤儿 SYSTEM 进程。
		if (ok && childPid) {
			HANDLE child = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, childPid);
			if (child) {
				const DWORD wait = WaitForSingleObject(child, 3000);
				PanelLog("[uitest] child alive after 3s=%d", wait == WAIT_TIMEOUT ? 1 : 0);
				TerminateProcess(child, 0);
				CloseHandle(child);
			}
			else {
				PanelLog("[uitest] OpenProcess(child=%lu) failed err=%lu",
					static_cast<unsigned long>(childPid),
					static_cast<unsigned long>(GetLastError()));
			}
		}
		PanelLog("=== uiaccess selftest END rc=%d ===", ok ? 0 : 1);
		ConsoleLog("[uitest] DONE rc=%d\n", ok ? 0 : 1);
		return ok ? 0 : 1;
	}

	bool Launch(DWORD enginePid, DWORD* panelPid, DWORD* errorCode) noexcept
	{
		if (errorCode) {
			*errorCode = ERROR_SUCCESS;
		}
		if (panelPid) {
			*panelPid = 0;
		}
		if (IsRunning()) {
			return true;
		}

		HANDLE selfToken = nullptr;
		HANDLE sourceProcess = nullptr;
		HANDLE sourceToken = nullptr;
		HANDLE impToken = nullptr;
		HANDLE primaryToken = nullptr;
		HANDLE stopEvent = nullptr;
		std::wstring stopFilePath;
		bool impersonating = false;
		bool ok = false;
		DWORD failure = ERROR_SUCCESS;

		auto fail = [&](DWORD code) {
			failure = code ? code : GetLastError();
		};

		do {
			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ASSIGN_PRIMARY,
				&selfToken)) {
				fail(GetLastError());
				break;
			}
			EnablePrivilege(selfToken, SE_DEBUG_NAME);
			EnablePrivilege(selfToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			EnablePrivilege(selfToken, SE_INCREASE_QUOTA_NAME);
			EnablePrivilege(selfToken, SE_IMPERSONATE_NAME);
			// SeTcb 在**管理员令牌**里通常根本不存在（AdjustTokenPrivileges 会返
			// ERROR_NOT_ALL_ASSIGNED=1300）。这里调它只是为了"有就用"，真正
			// 能设上 TokenUIAccess 靠的是下面那段 SYSTEM 模拟。
			EnablePrivilege(selfToken, SE_TCB_NAME);

			DWORD sessionId = 0;
			ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
			const DWORD sourcePid = FindSystemTokenSource(sessionId);
			if (sourcePid == 0) {
				fail(ERROR_NOT_FOUND);
				break;
			}
			sourceProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
			if (!sourceProcess || !OpenProcessToken(sourceProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &sourceToken)) {
				fail(GetLastError());
				break;
			}
			if (!TokenIsLocalSystem(sourceToken)) {
				fail(ERROR_INVALID_OWNER);
				break;
			}

			SECURITY_ATTRIBUTES attributes = { sizeof(attributes), nullptr, FALSE };
			if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &attributes, SecurityImpersonation,
				TokenImpersonation, &impToken)) {
				fail(GetLastError());
				break;
			}
			if (!ImpersonateLoggedOnUser(impToken)) {
				fail(GetLastError());
				break;
			}
			impersonating = true;
			EnablePrivilege(impToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			EnablePrivilege(impToken, SE_INCREASE_QUOTA_NAME);
			EnablePrivilege(impToken, SE_TCB_NAME);

			// ★ 关键：primary 令牌复制的是 **SYSTEM 源**，不是本进程自己的。
			if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &attributes, SecurityImpersonation,
				TokenPrimary, &primaryToken)) {
				fail(GetLastError());
				break;
			}
			EnablePrivilege(primaryToken, SE_ASSIGNPRIMARYTOKEN_NAME);
			EnablePrivilege(primaryToken, SE_INCREASE_QUOTA_NAME);
			EnablePrivilege(primaryToken, SE_TCB_NAME);

			// ★ 令牌源的会话号必须改写成**我们自己所在的会话**。
			//   令牌源排序里允许选"非本会话的 winlogon"（rank 30），
			//   那种令牌的会话号跟我们对不上 —— 拿它建进程，窗口会生在一个
			//   当前根本没被显示出来的会话里，等于白做（看得见才算数）。
			//   SetTokenInformation(TokenSessionId) 需要 SeTcb，所以必须在
			//   RevertToSelf 之前、SYSTEM 模拟态还在的时候做。
			//   （KSword UacDesk.cpp:782 同款，顺序也是"先开特权再改会话"。）
			{
				DWORD sourceSession = 0;
				DWORD sourceSessionLength = 0;
				const bool queried = GetTokenInformation(sourceToken, TokenSessionId,
					&sourceSession, sizeof(sourceSession), &sourceSessionLength) != FALSE;
				if (!queried) {
					fail(GetLastError());
					break;
				}
				if (sourceSession != sessionId) {
					SetLastError(ERROR_SUCCESS);
					if (!SetTokenInformation(primaryToken, TokenSessionId,
						&sessionId, sizeof(sessionId))) {
						fail(GetLastError());
						break;
					}
				}
			}

			DWORD uiAccess = 1;
			SetLastError(ERROR_SUCCESS);
			if (!SetTokenInformation(primaryToken, TokenUIAccess, &uiAccess, sizeof(uiAccess))) {
				fail(GetLastError());
				break;
			}
			if (TokenUIAccessFlag(primaryToken) == 0) {
				fail(ERROR_INVALID_DATA);
				break;
			}

			// ★ 模拟到这里就该撤了：SetTokenInformation 已经把 SeTcb 用完了，
			//   而下面 CreateProcessWithTokenW 走的是 seclogon 服务、按**调用者**
			//   身份提交，带着 SYSTEM 模拟态去调只会多一层不确定。
			//   （KSword 的 ScopedImpersonation 也是函数一返回就 RevertToSelf。）
			RevertToSelf();
			impersonating = false;

			// 停止事件。用会话命名空间（引擎与面板同在登录会话），
			// 名字原样传给面板，不靠两边各自猜前缀。
			wchar_t eventName[R3ShieldCore::ObjectNameCapacity] = {};
			swprintf_s(eventName, _countof(eventName),
				L"Global\\R3ShieldCore-SuperPanel-stop-pid=%u", enginePid);
			stopEvent = CreateEventW(nullptr, TRUE, FALSE, eventName);
			ConsoleLog("[gui] superdesk stop event name=%ls created=%d err=%lu\n",
				eventName, stopEvent ? 1 : 0, stopEvent ? ERROR_SUCCESS : GetLastError());

			// 面板 = 同一个 exe 的另一个实例。
			const std::wstring selfPath = ModulePath();
			if (selfPath.empty()) {
				fail(ERROR_FILE_NOT_FOUND);
				break;
			}
			stopFilePath = (std::filesystem::path(selfPath).parent_path() /
				(L"superdesk-stop-" + std::to_wstring(enginePid) + L".signal")).wstring();
			DeleteFileW(stopFilePath.c_str());
			HANDLE stopFile = CreateFileW(stopFilePath.c_str(), GENERIC_WRITE, 0, nullptr,
				CREATE_NEW, FILE_ATTRIBUTE_HIDDEN, nullptr);
			if (stopFile == INVALID_HANDLE_VALUE) {
				fail(GetLastError());
				break;
			}
			CloseHandle(stopFile);
			wchar_t commandLine[1024] = {};
			swprintf_s(commandLine, _countof(commandLine),
				L"\"%s\" %s --engine-pid=%u --stop-event=%s --stop-file=\"%s\"",
				selfPath.c_str(), PanelArgument, enginePid,
				stopEvent ? eventName : L"", stopFilePath.c_str());

			STARTUPINFOW startup = { sizeof(startup) };
			// ★ 这就是 A 配方的落点：把窗口生在 **winsta0\Winlogon** 上。
			//   安全桌面显示的就是这个桌面，所以面板天然盖在 UAC 提示上面。
			wchar_t desktop[] = L"winsta0\\Winlogon";
			startup.lpDesktop = desktop;
			PROCESS_INFORMATION process = {};

			SetLastError(ERROR_SUCCESS);
			BOOL created = CreateProcessWithTokenW(primaryToken, LOGON_NETCREDENTIALS_ONLY,
				selfPath.c_str(), commandLine,
				CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
				nullptr, nullptr, &startup, &process);
			DWORD createError = GetLastError();
			if (!created) {
				// CreateProcessWithTokenW 依赖 seclogon（Secondary Logon）服务。
				// 那个服务被禁用/停用时它会直接失败 —— 退到 CreateProcessAsUser，
				// 后者不需要那个服务，只要求令牌可分配（SeAssignPrimaryToken 已开）。
				ConsoleLog("[gui] CreateProcessWithTokenW 失败 err=%lu，改用 CreateProcessAsUser 重试\n",
					static_cast<unsigned long>(createError));
				SetLastError(ERROR_SUCCESS);
				created = CreateProcessAsUserW(primaryToken, selfPath.c_str(), commandLine,
					nullptr, nullptr, FALSE,
					CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
					nullptr, nullptr, &startup, &process);
				if (!created) {
					fail(GetLastError());
					break;
				}
			}

			if (panelPid) {
				*panelPid = process.dwProcessId;
			}
			if (g_panelProcess) {
				CloseHandle(g_panelProcess);
			}
			g_panelProcess = process.hProcess;
			g_panelStopEvent = stopEvent;
			g_panelStopFilePath = stopFilePath;
			stopEvent = nullptr;
			if (process.hThread) {
				CloseHandle(process.hThread);
			}
			ok = true;
		} while (false);

		if (impersonating) {
			RevertToSelf();
		}
		if (stopEvent) {
			CloseHandle(stopEvent);
		}
		if (!ok && !stopFilePath.empty()) {
			DeleteFileW(stopFilePath.c_str());
		}
		if (primaryToken) {
			CloseHandle(primaryToken);
		}
		if (impToken) {
			CloseHandle(impToken);
		}
		if (sourceToken) {
			CloseHandle(sourceToken);
		}
		if (sourceProcess) {
			CloseHandle(sourceProcess);
		}
		if (selfToken) {
			CloseHandle(selfToken);
		}

		if (!ok && errorCode) {
			*errorCode = failure;
		}
		return ok;
	}

	void Stop() noexcept
	{
		if (g_panelStopEvent) {
			const BOOL signaled = SetEvent(g_panelStopEvent);
			ConsoleLog("[gui] superdesk stop event signaled=%d err=%lu\n",
				signaled ? 1 : 0, signaled ? ERROR_SUCCESS : GetLastError());
			CloseHandle(g_panelStopEvent);
			g_panelStopEvent = nullptr;
		}
		if (!g_panelStopFilePath.empty()) {
			DeleteFileW(g_panelStopFilePath.c_str());
		}
		if (g_panelProcess) {
			// 安全桌面切换和窗口销毁可能比普通桌面慢；给正常事件退出足够时间。
			const DWORD waitResult = WaitForSingleObject(g_panelProcess, 10000);
			ConsoleLog("[gui] superdesk stop wait=%lu\n",
				static_cast<unsigned long>(waitResult));
			if (waitResult == WAIT_TIMEOUT) {
				// 最后的兜底，避免引擎退出后遗留 SYSTEM 面板。
				TerminateProcess(g_panelProcess, 0);
			}
			CloseHandle(g_panelProcess);
			g_panelProcess = nullptr;
		}
		g_panelStopFilePath.clear();
	}

	bool IsRunning() noexcept
	{
		if (!g_panelProcess) {
			return false;
		}
		if (WaitForSingleObject(g_panelProcess, 0) == WAIT_TIMEOUT) {
			return true;
		}
		// 已经退了：把句柄收掉，状态回到"没有面板"。
		CloseHandle(g_panelProcess);
		g_panelProcess = nullptr;
		if (g_panelStopEvent) {
			CloseHandle(g_panelStopEvent);
			g_panelStopEvent = nullptr;
		}
		if (!g_panelStopFilePath.empty()) {
			DeleteFileW(g_panelStopFilePath.c_str());
			g_panelStopFilePath.clear();
		}
		return false;
	}
}
