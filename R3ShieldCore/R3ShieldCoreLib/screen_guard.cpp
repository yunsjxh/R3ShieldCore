#include "stdafx.h"
#include "screen_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 屏幕捕获监控层（GDI 截屏路径）。
//
// 骨架与其它 guard 一致：判定 → 上报 / 拒绝 → 等排空。
// 特殊之处：
//   1. **必须做前置过滤**。BitBlt 是 GDI 里最热的函数之一（窗口重绘、
//      滚动、图标合成、贴图全走它），每次调用都上报的话日志会被刷爆，
//      而且判定本身（弹窗询问）会被重绘触发 —— 完全不可用。
//      过滤条件：源 DC 必须是屏幕/桌面 DC（见 IsScreenSourceDc）。
//   2. 过滤判据是实测出来的，不是查文档猜的 —— 见 screen_guard.h
//      和 tools/dctest.cpp。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef BOOL(WINAPI* BitBltPtr)(HDC, int, int, int, int, HDC, int, int, DWORD);
	typedef BOOL(WINAPI* StretchBltPtr)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
	typedef BOOL(WINAPI* PrintWindowPtr)(HWND, HDC, UINT);
	typedef int(WINAPI* GetDIBitsPtr)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);

	BitBltPtr pOriginalBitBlt = nullptr;
	StretchBltPtr pOriginalStretchBlt = nullptr;
	PrintWindowPtr pOriginalPrintWindow = nullptr;
	GetDIBitsPtr pOriginalGetDIBits = nullptr;

	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;

	enum class Action
	{
		Pass,
		Record,
		Block,
	};

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// ------------------------------------------------------------------
	// 前置过滤：源 DC 是不是屏幕/桌面 DC
	// ------------------------------------------------------------------
	//
	// 实测结论（tools/dctest.cpp 的输出）：
	//     GetDC(NULL)                  → WindowFromDC = 桌面窗口句柄  ← 屏幕 DC
	//     GetDC(GetDesktopWindow())    → WindowFromDC = 桌面窗口句柄  ← 屏幕 DC
	//     CreateCompatibleDC(screen)   → WindowFromDC = NULL          ← 内存 DC
	//     GetDC(任意窗口)              → WindowFromDC = 该窗口句柄
	//
	// GetDeviceCaps(TECHNOLOGY) 在以上三种上全是 DT_RASDISPLAY(1)，
	// 没有区分能力，所以只能用 WindowFromDC。
	//
	// 性能：WindowFromDC 是 user32 里的一次句柄表查找，开销远小于
	// 一次真实 BitBlt 拷贝（后者动辄几百微秒）。普通重绘路径多花
	// 这一百来纳秒可以接受 —— 换来的是日志里一条噪音都没有。
	//
	bool IsScreenSourceDc(HDC dc) noexcept
	{
		if (!dc) {
			return false;
		}

		__try {
			return WindowFromDC(dc) == GetDesktopWindow();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// 传进来的 DC 是野句柄（调用方自己传错）—— 当普通调用放行，
			// 让原函数去报错，别在这里拦。
			return false;
		}
	}

	// ------------------------------------------------------------------
	// 上报与判定
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Screen);
		if (event.TimeStamp == 0) {
			event.TimeStamp = NowFileTime();
		}
		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();

		R3ShieldCoreChannel::Publish(event);
	}

	R3ShieldCore::Verdict PromptFallbackVerdict() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
			return static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
		}

		return R3ShieldCore::Verdict::Deny;
	}

	Action Evaluate(R3ShieldCore::ScreenOp op, R3ShieldCore::Event& event, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Screen);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all）----
		//
		// 探测范围内一律拒绝：不判豁免、不判高危、不弹窗。
		// 能走到这里的操作都已经被更早的"探测边界"判定为"被探测到的"
		// （非文件对象、没开 hook 的只读打开、不被注入的进程都在前面返回了），
		// 所以这里不再做任何区分。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		// 能走到这里的只有"源是屏幕 DC 的 BitBlt/StretchBlt"和
		// "PrintWindow"，三条都是高危（过滤在 hook 层，不在规则层）。
		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskScreen(static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				if (op == R3ShieldCore::ScreenOp::PrintWindow) {
					event.Flags |= R3ShieldCore::FlagEventWindowCapture;
				}
				else {
					event.Flags |= R3ShieldCore::FlagEventScreenDC;
				}
			}
		}

		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// 高危：截屏。
		//
		// 与其它 guard 一致 —— LOG 只记录，BLOCK 直接拒，ASK 弹窗。
		// 注意这里**没有**"BLOCK 下一刀切"的问题：能到这一步的
		// 一定是真截屏，不存在误伤普通绘制的风险。
		//
		// ⚠️ 这里必须再与一次 mode == Ask。Ask 依赖引擎侧 UI 线程，
		//    而那个线程**只在 ASK 模式启动** —— LOG/BLOCK 下调 Ask 会等
		//    一个永远不来的答复（实测表现：LOG 模式下被当成 Deny，
		//    直接 BLOCK 掉，而 LOG 模式不该拦任何东西）。
		const bool canAsk = allowAsk && (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask));
		if (!canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return Action::Block;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：走“通道可用性”包装 —— 管理员启动引擎时通道打不开，
		//   LOG 模式下降级放行（否则高危操作被静默拒，不可识别）。
		//   见 r3shieldcore_prompt.h 的 AskWithChannelGuard 说明。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return Action::Record;
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return Action::Block;
	}

	// 第二字段放"拷贝区域"，用于区分"1x1 取色"和"整屏抓走"。
	void SetRectDetail(R3ShieldCore::Event& event, int x, int y, int width, int height) noexcept
	{
		swprintf_s(event.ValueName, L"%dx%d @ (%d,%d)", width, height, x, y);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
	}

	// ------------------------------------------------------------------
	// hook：BitBlt / StretchBlt
	// ------------------------------------------------------------------
	BOOL WINAPI BitBlt_Hook(HDC hdcDest, int xDest, int yDest, int width, int height,
		HDC hdcSrc, int xSrc, int ySrc, DWORD rop)
	{
		// ⚠️ 热路径。绝大多数调用（普通重绘）在这里就被挡回去，
		//    不进计数、不上报、不判定 —— 只多一次 WindowFromDC。
		if (!IsScreenSourceDc(hdcSrc)) {
			return pOriginalBitBlt(hdcDest, xDest, yDest, width, height, hdcSrc, xSrc, ySrc, rop);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"屏幕/桌面 DC", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		SetRectDetail(event, xSrc, ySrc, width, height);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ScreenOp::BitBlt, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalBitBlt(hdcDest, xDest, yDest, width, height, hdcSrc, xSrc, ySrc, rop);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	BOOL WINAPI StretchBlt_Hook(HDC hdcDest, int xDest, int yDest, int widthDest, int heightDest,
		HDC hdcSrc, int xSrc, int ySrc, int widthSrc, int heightSrc, DWORD rop)
	{
		if (!IsScreenSourceDc(hdcSrc)) {
			return pOriginalStretchBlt(hdcDest, xDest, yDest, widthDest, heightDest,
				hdcSrc, xSrc, ySrc, widthSrc, heightSrc, rop);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"屏幕/桌面 DC（缩放）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		SetRectDetail(event, xSrc, ySrc, widthSrc, heightSrc);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ScreenOp::StretchBlt, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalStretchBlt(hdcDest, xDest, yDest, widthDest, heightDest,
			hdcSrc, xSrc, ySrc, widthSrc, heightSrc, rop);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：PrintWindow
	// ------------------------------------------------------------------
	BOOL WINAPI PrintWindow_Hook(HWND hwnd, HDC hdcBlt, UINT flags)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		WCHAR title[192] = {};
		WCHAR className[96] = {};
		GetWindowTextW(hwnd, title, _countof(title));
		GetClassNameW(hwnd, className, _countof(className));

		if (title[0]) {
			swprintf_s(event.KeyPath, L"%s [%s]", title, className);
		}
		else {
			swprintf_s(event.KeyPath, L"(无标题窗口) [%s]", className);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"flags=0x%X", flags);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ScreenOp::PrintWindow, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalPrintWindow(hwnd, hdcBlt, flags);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：GetDIBits（截屏的第三条路，v11）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么需要它：前面挂了 BitBlt/StretchBlt，判据是"源 DC 是屏幕 DC"。
	//    但**截屏不必经过 BitBlt** —— GetDC(NULL) 拿到屏幕 DC 后直接
	//    GetDIBits(screenDc, hbm, ...) 就能读走像素，少一步拷贝。
	//
	//    实测（tools/dibprobe.cpp）：
	//      screen DC + screen bitmap      → WindowFromDC = 桌面窗口  ← 判据命中
	//      memory DC (SelectObject 后)    → WindowFromDC = NULL
	//      memory DC + DIB section        → WindowFromDC = NULL
	//      taskbar 窗口 DC                → WindowFromDC = 该窗口句柄
	//      GetDIBits(NULL, ...)           → 直接 err=87（真实调用一定带 DC）
	//
	//    所以同一个 IsScreenSourceDc 判据在这里依然有效，不需要新判据。
	//
	// ⚠️ GetDIBits 是**高频**函数（任何读回位图像素的操作都走它，屏幕重绘、
	//    截图工具、字体渲染都在用）。过滤在 hook 层：只对"屏幕 DC"上报。
	//
	int WINAPI GetDIBits_Hook(HDC hdc, HBITMAP hbm, UINT start, UINT lines,
		LPVOID bits, LPBITMAPINFO info, UINT usage)
	{
		// 热路径：绝大多数调用（内存 DC 读回自己的位图）在这里就被挡回去。
		if (!IsScreenSourceDc(hdc)) {
			return pOriginalGetDIBits(hdc, hbm, start, lines, bits, info, usage);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"屏幕/桌面 DC（GetDIBits 直读）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		// 详细字段放"读了几行 + 位深"，用于区分"1x1 取色"和"整屏抓走"。
		int width = 0;
		int height = 0;
		WORD bitCount = 0;
		if (info) {
			width = info->bmiHeader.biWidth;
			height = info->bmiHeader.biHeight;
			bitCount = info->bmiHeader.biBitCount;
		}
		swprintf_s(event.ValueName, L"%dx%d @ %u bit，本次读 %u 行", width, height, bitCount, lines);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ScreenOp::GetDIBits, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return 0;
		}

		const int result = pOriginalGetDIBits(hdc, hbm, start, lines, bits, info, usage);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// 挂载
	// ------------------------------------------------------------------
	bool QueueHook(LPCSTR moduleName, LPCSTR functionName, LPVOID detour,
		LPVOID* original, bool required) noexcept
	{
		HMODULE module = GetModuleHandleA(moduleName);
		if (!module) {
			if (required) {
				LOG(L"ScreenGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"ScreenGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"ScreenGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"ScreenGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace ScreenGuard
{
	int HookCount() noexcept
	{
		return g_hookCount;
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"ScreenGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	bool Install(HANDLE /*engineProcess*/) noexcept
	{
		if (g_installed) {
			return true;
		}

		if (RegistryGuard::IsBypassed()) {
			g_bypass = true;
			g_installed = true;
			return true;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookScreen) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ScreenGuard: hook_screen 未开启，本进程不挂截屏 hook");
			return true;
		}

		g_bypass = false;

		// gdi32 / user32 在任何有 GUI 的进程里都已加载。纯控制台进程
		// 挂不上也无所谓 —— 它们本来也不截屏。
		//
		// ⚠️ gdi32.dll 的 BitBlt 是**转发导出**（真正的实现在 gdi32full.dll）。
		//    GetProcAddress 会自动解析转发，返回 gdi32full 里的真实地址，
		//    MinHook 改的就是它 —— 调用方无论从哪条路径进来都会命中。
		HMODULE gdi32 = GetModuleHandleW(L"gdi32.dll");
		HMODULE user32 = GetModuleHandleW(L"user32.dll");

		if (!gdi32 && !user32) {
			LOG(L"ScreenGuard: gdi32/user32 都未加载，本进程不挂截屏 hook");
			g_installed = true;
			return true;
		}

		if (gdi32) {
			QueueHook("gdi32.dll", "BitBlt", reinterpret_cast<LPVOID>(BitBlt_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalBitBlt), true);
			QueueHook("gdi32.dll", "StretchBlt", reinterpret_cast<LPVOID>(StretchBlt_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalStretchBlt), false);
			// v11：截屏第三条路（GetDIBits 直读屏幕 DC）。不是必需的 ——
			// 老系统/转发导出差异下挂不上也不该让整个 guard 失败。
			QueueHook("gdi32.dll", "GetDIBits", reinterpret_cast<LPVOID>(GetDIBits_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalGetDIBits), false);
		}

		if (user32) {
			QueueHook("user32.dll", "PrintWindow", reinterpret_cast<LPVOID>(PrintWindow_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalPrintWindow), false);
		}

		g_installed = true;

		LOG(L"ScreenGuard: 已挂载 %d 个截屏 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
