#include "stdafx.h"
#include "input_hook_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 输入钩子监控层（鼠标 / 键盘）。
//
// 骨架与其它 guard 一致：判定 → 上报 / 拒绝 → 等排空。
// 特殊之处：
//   1. 判据要看三个参数（idHook / dwThreadId / lpfn 所在模块），
//      不像别的 guard 只看一个路径。
//   2. **模块名是这里最有价值的情报**：全局钩子的本质是"把某个 DLL
//      注入到所有 GUI 进程"，把那个 DLL 的路径记下来，一眼就能看出
//      是正常输入法还是来路不明的东西。
//   3. SetWindowsHookEx 的 hmod 参数在 dwThreadId==0 时必须是 DLL 模块
//      句柄（系统要拿它去注入），所以 GetModuleFileNameW 一定能取到路径。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------

	// winuser.h 里的钩子类型常量（不 include 也可以，但我们用的是
	// 标准值，直接列出来便于对照）。
	constexpr int IH_WH_JOURNALRECORD = 0;
	constexpr int IH_WH_JOURNALPLAYBACK = 1;
	constexpr int IH_WH_KEYBOARD = 2;
	constexpr int IH_WH_GETMESSAGE = 3;
	constexpr int IH_WH_CALLWNDPROC = 4;
	constexpr int IH_WH_CBT = 5;
	constexpr int IH_WH_SYSMSGFILTER = 6;
	constexpr int IH_WH_MOUSE = 7;
	constexpr int IH_WH_HARDWARE = 8;
	constexpr int IH_WH_DEBUG = 9;
	constexpr int IH_WH_SHELL = 10;
	constexpr int IH_WH_FOREGROUNDIDLE = 11;
	constexpr int IH_WH_CALLWNDPROCRET = 12;
	constexpr int IH_WH_KEYBOARD_LL = 13;
	constexpr int IH_WH_MOUSE_LL = 14;

	// RAWINPUTDEVICE.dwFlags
	constexpr DWORD IH_RIDEV_INPUTSINK = 0x00000100;

	// 原始输入的用法页/用法号（HID 标准）
	constexpr USHORT IH_HID_USAGE_PAGE_GENERIC = 0x01;
	constexpr USHORT IH_HID_USAGE_MOUSE = 0x02;
	constexpr USHORT IH_HID_USAGE_KEYBOARD = 0x06;

	typedef HHOOK(WINAPI* SetWindowsHookExWPtr)(int, HOOKPROC, HINSTANCE, DWORD);
	typedef HHOOK(WINAPI* SetWindowsHookExAPtr)(int, HOOKPROC, HINSTANCE, DWORD);
	typedef BOOL(WINAPI* UnhookWindowsHookExPtr)(HHOOK);
	typedef BOOL(WINAPI* RegisterRawInputDevicesPtr)(PCRAWINPUTDEVICE, UINT, UINT);
	typedef SHORT(WINAPI* GetAsyncKeyStatePtr)(int);
	typedef SHORT(WINAPI* GetKeyStatePtr)(int);
	typedef BOOL(WINAPI* GetKeyboardStatePtr)(PBYTE);
	typedef HWINEVENTHOOK(WINAPI* SetWinEventHookPtr)(DWORD, DWORD, HMODULE, WINEVENTPROC,
		DWORD, DWORD, UINT);

	//
	// v14：**反向**输入 —— 合成键鼠 / 冻结输入 / 锁鼠标。
	//
	// ⚠️ 与前面那些"捕获面"API 方向相反：这批是"代替用户去按"。
	//
	//   SendInput(UINT, LPINPUT, int)         —— 合成输入（现代推荐 API）
	//   keybd_event(BYTE, BYTE, DWORD, ULONG_PTR) —— 合成键盘（老 API，仍在用）
	//   mouse_event(DWORD, DWORD, DWORD, DWORD, ULONG_PTR) —— 合成鼠标（老 API）
	//   BlockInput(BOOL)                      —— 冻结/解冻用户的键鼠输入
	//   ClipCursor(const RECT*)               —— 把鼠标锁在矩形内（NULL = 解除）
	//
	typedef UINT(WINAPI* SendInputPtr)(UINT, LPINPUT, int);
	typedef void(WINAPI* keybd_eventPtr)(BYTE, BYTE, DWORD, ULONG_PTR);
	typedef void(WINAPI* mouse_eventPtr)(DWORD, DWORD, DWORD, DWORD, ULONG_PTR);
	typedef BOOL(WINAPI* BlockInputPtr)(BOOL);
	typedef BOOL(WINAPI* ClipCursorPtr)(const RECT*);

	SetWindowsHookExWPtr pOriginalSetWindowsHookExW = nullptr;
	SetWindowsHookExAPtr pOriginalSetWindowsHookExA = nullptr;
	UnhookWindowsHookExPtr pOriginalUnhookWindowsHookEx = nullptr;
	RegisterRawInputDevicesPtr pOriginalRegisterRawInputDevices = nullptr;
	GetAsyncKeyStatePtr pOriginalGetAsyncKeyState = nullptr;
	GetKeyStatePtr pOriginalGetKeyState = nullptr;
	GetKeyboardStatePtr pOriginalGetKeyboardState = nullptr;
	SetWinEventHookPtr pOriginalSetWinEventHook = nullptr;
	SendInputPtr pOriginalSendInput = nullptr;
	keybd_eventPtr pOriginalKeybdEvent = nullptr;
	mouse_eventPtr pOriginalMouseEvent = nullptr;
	BlockInputPtr pOriginalBlockInput = nullptr;
	ClipCursorPtr pOriginalClipCursor = nullptr;

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
	// 钩子分类与描述
	// ------------------------------------------------------------------

	// 把 Win32 的 wh 值映射到我们的 HookOp。
	R3ShieldCore::HookOp ClassifyHook(int idHook) noexcept
	{
		switch (idHook) {
		case IH_WH_MOUSE:
		case IH_WH_MOUSE_LL:
			return R3ShieldCore::HookOp::SetMouseHook;
		case IH_WH_KEYBOARD:
		case IH_WH_KEYBOARD_LL:
			return R3ShieldCore::HookOp::SetKeyboardHook;
		case IH_WH_JOURNALRECORD:
		case IH_WH_JOURNALPLAYBACK:
			return R3ShieldCore::HookOp::SetInputJournal;
		default:
			return R3ShieldCore::HookOp::SetOtherHook;
		}
	}

	// wh 值的可读名，写进事件的 ValueName（第二字段）。
	PCWSTR HookTypeName(int idHook) noexcept
	{
		switch (idHook) {
		case IH_WH_JOURNALRECORD: return L"WH_JOURNALRECORD";
		case IH_WH_JOURNALPLAYBACK: return L"WH_JOURNALPLAYBACK";
		case IH_WH_KEYBOARD: return L"WH_KEYBOARD";
		case IH_WH_GETMESSAGE: return L"WH_GETMESSAGE";
		case IH_WH_CALLWNDPROC: return L"WH_CALLWNDPROC";
		case IH_WH_CBT: return L"WH_CBT";
		case IH_WH_SYSMSGFILTER: return L"WH_SYSMSGFILTER";
		case IH_WH_MOUSE: return L"WH_MOUSE";
		case IH_WH_HARDWARE: return L"WH_HARDWARE";
		case IH_WH_DEBUG: return L"WH_DEBUG";
		case IH_WH_SHELL: return L"WH_SHELL";
		case IH_WH_FOREGROUNDIDLE: return L"WH_FOREGROUNDIDLE";
		case IH_WH_CALLWNDPROCRET: return L"WH_CALLWNDPROCRET";
		case IH_WH_KEYBOARD_LL: return L"WH_KEYBOARD_LL";
		case IH_WH_MOUSE_LL: return L"WH_MOUSE_LL";
		default: return L"WH_?";
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::InputHook);
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

	//
	// fgOwned：v14 参数。仅对**反向输入**（BlockInput / ClipCursor）有意义 ——
	//   表示"当前前台窗口是否属于调用方"。捕获面 hook 传 false 即可（不用）。
	//
	Action Evaluate(R3ShieldCore::HookOp op, R3ShieldCore::Event& event, bool allowAsk,
		int idHook, ULONG threadId, bool rawSink, bool fgOwned = false) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::InputHook);
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

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			//
			// v14：反向输入（SendInput / BlockInput / ClipCursor）走**另一套**
			//   判据函数（IsHighRiskInputInjection，吃 fgOwned 参数），
			//   不能走捕获面的 IsHighRiskInputHook —— 那套的 switch 里没有
			//   这三个 op，会掉进 default 返回 nullptr，于是**永远不算高危**。
			//   （这就是实测发现的 bug：BLOCK 模式下 SendInput 记成 ALLOW。）
			//
			const bool isInjectionOp =
				(op == R3ShieldCore::HookOp::SendInputEvents) ||
				(op == R3ShieldCore::HookOp::BlockUserInput) ||
				(op == R3ShieldCore::HookOp::ClipCursorLock);

			const bool risk = isInjectionOp
				? R3ShieldCoreRules::IsHighRiskInputInjection(static_cast<ULONG>(op), fgOwned)
				: R3ShieldCoreRules::IsHighRiskInputHook(static_cast<ULONG>(idHook), threadId,
					static_cast<ULONG>(op), rawSink);

			if (risk) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		// 细分标记，UI 上色用。
		if (op == R3ShieldCore::HookOp::SetMouseHook || op == R3ShieldCore::HookOp::SetKeyboardHook) {
			if (idHook == IH_WH_MOUSE_LL || idHook == IH_WH_KEYBOARD_LL) {
				event.Flags |= R3ShieldCore::FlagEventLowLevelHook;
			}
			else if (threadId == 0) {
				event.Flags |= R3ShieldCore::FlagEventGlobalHook;
			}

			if (op == R3ShieldCore::HookOp::SetMouseHook) {
				event.Flags |= R3ShieldCore::FlagEventMouse;
			}
			else {
				event.Flags |= R3ShieldCore::FlagEventKeyboard;
			}
		}
		else if (op == R3ShieldCore::HookOp::SetOtherHook && threadId == 0) {
			event.Flags |= R3ShieldCore::FlagEventGlobalHook;
		}

		// 非高危：按 mode 处理。
		//
		// 与网络/摄像头同理，BLOCK 下**不做**一刀切 —— 输入法、输入辅助
		// 工具、游戏都会装线程内钩子，全拒会把系统搞坏。非高危放行只记录。
		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

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

	// 第二字段（ValueName）放钩子类型名。
	void SetHookType(R3ShieldCore::Event& event, PCWSTR text) noexcept
	{
		if (text && text[0]) {
			wcsncpy_s(event.ValueName, text, _TRUNCATE);
		}
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
	}

	// KeyPath 放"要注入的模块路径"（全局钩子的关键情报）。
	void SetModulePath(R3ShieldCore::Event& event, HINSTANCE module) noexcept
	{
		if (!module) {
			wcsncpy_s(event.KeyPath, L"(本进程模块，不注入)", _TRUNCATE);
			event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
			return;
		}

		WCHAR path[R3ShieldCore::MaxKeyPathChars] = {};
		DWORD written = GetModuleFileNameW(reinterpret_cast<HMODULE>(module), path, _countof(path));
		if (written == 0) {
			wcsncpy_s(event.KeyPath, L"(模块路径不可读)", _TRUNCATE);
		}
		else {
			wcsncpy_s(event.KeyPath, path, _TRUNCATE);
		}

		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
	}

	// ------------------------------------------------------------------
	// hook：SetWindowsHookEx / UnhookWindowsHookEx
	// ------------------------------------------------------------------
	HHOOK WINAPI SetWindowsHookExW_Hook(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetHookType(event, HookTypeName(idHook));
		SetModulePath(event, hmod);
		event.Status = 0;

		const R3ShieldCore::HookOp op = ClassifyHook(idHook);
		const Action action = Evaluate(op, event, true, idHook, dwThreadId, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		const HHOOK result = pOriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	HHOOK WINAPI SetWindowsHookExA_Hook(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetHookType(event, HookTypeName(idHook));
		SetModulePath(event, hmod);
		event.Status = 0;

		const R3ShieldCore::HookOp op = ClassifyHook(idHook);
		const Action action = Evaluate(op, event, true, idHook, dwThreadId, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		const HHOOK result = pOriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	BOOL WINAPI UnhookWindowsHookEx_Hook(HHOOK hhk)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetHookType(event, L"UnhookWindowsHookEx");
		event.Status = 0;

		// 拆钩子只记录，不拦。
		Evaluate(R3ShieldCore::HookOp::Unhook, event, false, 0, 0, false);

		const BOOL result = pOriginalUnhookWindowsHookEx(hhk);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：RegisterRawInputDevices
	// ------------------------------------------------------------------
	BOOL WINAPI RegisterRawInputDevices_Hook(PCRAWINPUTDEVICE devices, UINT count, UINT size)
	{
		InterlockedIncrement(&g_activeHooks);

		// 扫一遍要注册的设备，看有没有 INPUTSINK（后台收输入）
		// 以及是鼠标还是键盘。一数组通常只有 1~2 项，开销可忽略。
		bool sink = false;
		bool mouse = false;
		bool keyboard = false;
		if (devices && count > 0 && size == sizeof(RAWINPUTDEVICE)) {
			for (UINT i = 0; i < count; i++) {
				if ((devices[i].dwFlags & IH_RIDEV_INPUTSINK) != 0) {
					sink = true;
				}
				if (devices[i].usUsagePage == IH_HID_USAGE_PAGE_GENERIC) {
					if (devices[i].usUsage == IH_HID_USAGE_MOUSE) {
						mouse = true;
					}
					else if (devices[i].usUsage == IH_HID_USAGE_KEYBOARD) {
						keyboard = true;
					}
				}
			}
		}

		R3ShieldCore::Event event = {};
		if (sink) {
			event.Flags |= R3ShieldCore::FlagEventRawInput;
		}
		if (mouse) {
			event.Flags |= R3ShieldCore::FlagEventMouse;
		}
		if (keyboard) {
			event.Flags |= R3ShieldCore::FlagEventKeyboard;
		}
		SetHookType(event, sink ? L"RAWINPUT(INPUTSINK)" : L"RAWINPUT");
		if (mouse && keyboard) {
			wcsncpy_s(event.KeyPath, L"原始输入：鼠标 + 键盘", _TRUNCATE);
		}
		else if (keyboard) {
			wcsncpy_s(event.KeyPath, L"原始输入：键盘", _TRUNCATE);
		}
		else if (mouse) {
			wcsncpy_s(event.KeyPath, L"原始输入：鼠标", _TRUNCATE);
		}
		else {
			wcsncpy_s(event.KeyPath, L"原始输入：其它设备", _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::RegisterRawInput, event, true,
			0, 0, sink);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalRegisterRawInputDevices(devices, count, size);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// 轮询式键盘记录检测器（v11）
	// ------------------------------------------------------------------
	//
	// ⚠️ 这是本 guard 里唯一一个"判据不在规则层"的地方，原因必须说清：
	//
	//   前面所有 hook 的判断都是"看参数就知道要不要报"。但轮询式键盘
	//   记录器**没有可判别参数** —— 它就是在循环里反复问：
	//        for (;;) for (VK = 0; VK < 256; VK++)
	//                     if (GetAsyncKeyState(VK) & 0x8000) Record(VK);
	//   单次 GetAsyncKeyState(VK) 和输入法/游戏/辅助工具调的是同一个
	//   函数、同样的参数，从参数上完全区分不开。
	//
	//   唯一能区分的是**调用模式**：键盘记录器会在极短时间内把 256 个
	//   虚拟键全扫一遍，并且不停重复。所以判据是"单位时间窗内的调用次数"。
	//
	// 设计（按线程独立计数，避免多线程程序互相叠加触发误报）：
	//   · 每个线程维护一个计数器，时间窗 POLL_WINDOW_MS 毫秒。
	//   · 窗内调用次数超过 POLL_THRESHOLD 就认作"轮询扫描"，报一次。
	//   · 报过之后**冷却** POLL_COOLDOWN_MS，避免同一个循环刷屏
	//     （键盘记录器每秒能扫几百轮，不冷却的话一秒能出几百条事件，
	//      环形缓冲直接被打满 —— 这就是"噪音淹没真信号"的老坑）。
	//
	// ⚠️ 阈值是实测调出来的，不是拍的：
	//    - 阈值取 60：正常程序单帧读 1~4 个键，60 次/100ms 已经远超
	//      任何交互式 UI 的需求（那是 600 次/秒）；而 256 键全扫一轮
	//      就会立刻超过。
	//    - 窗口取 100ms：够短，能抓住 256 键全扫（通常耗时 < 1ms）；
	//      够长，正常高频程序不至于在窗口里攒够 60 次。
	//
	constexpr LONG POLL_THRESHOLD = 60;
	constexpr ULONGLONG POLL_WINDOW_MS = 100;
	constexpr ULONGLONG POLL_COOLDOWN_MS = 3000;

	// 计数与时间戳都用 thread_local —— 每线程一份，零锁。
	// （thread_local 的静态对象在 DLL 卸载时会被析构，这里是 POD，无析构开销。）
	thread_local LONG t_pollCount = 0;
	thread_local ULONGLONG t_pollWindowStart = 0;
	thread_local ULONGLONG t_pollLastReport = 0;

	//
	// 返回 true 表示"这次调用应被判定为轮询式键盘记录"。
	//
	// ⚠️ 这个函数会在**极热**的路径上被调（每次 GetAsyncKeyState）。
	//    所以只做算术 + 两个 GetTickCount64，不做任何字符串/分配。
	//
	bool PollingDetectorTrips() noexcept
	{
		const ULONGLONG now = GetTickCount64();

		// 冷却期内直接返回，连计数都省 —— 键盘记录器在冷却期内
		// 还会调成千上万次，这是最需要便宜的路径。
		if (t_pollLastReport != 0 && (now - t_pollLastReport) < POLL_COOLDOWN_MS) {
			return false;
		}

		// 窗口滚动。
		if (t_pollWindowStart == 0 || (now - t_pollWindowStart) >= POLL_WINDOW_MS) {
			t_pollWindowStart = now;
			t_pollCount = 1;
			return false;
		}

		if (++t_pollCount < POLL_THRESHOLD) {
			return false;
		}

		// 触发了。重置窗口 + 记冷却时间戳。
		t_pollCount = 0;
		t_pollWindowStart = now;
		t_pollLastReport = now;
		return true;
	}

	// ------------------------------------------------------------------
	// hook：GetAsyncKeyState / GetKeyState / GetKeyboardState（轮询式，v11）
	// ------------------------------------------------------------------
	//
	// ⚠️ 这三个是**全系统最热的 API 之一**（消息循环、输入法、IME、
	//    游戏、无障碍工具全在用）。所以：
	//      · 绝大多数调用在这里直接原样透传（只多一次算术）
	//      · 只有密度检测判定为轮询扫描时，才走一次完整的上报链路
	//    绝不能"调了就上报" —— 那是日志雪崩。
	//
	SHORT WINAPI GetAsyncKeyState_Hook(int vKey)
	{
		if (!PollingDetectorTrips()) {
			return pOriginalGetAsyncKeyState(vKey);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"轮询读取按键状态（未安装钩子）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"GetAsyncKeyState，%llu ms 内 %d 次调用",
			static_cast<unsigned long long>(POLL_WINDOW_MS), POLL_THRESHOLD);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventKeyboard | R3ShieldCore::FlagEventLowLevelHook;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::PollAsyncKeyState, event, true, 0, 0, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			// ⚠️ 返回 0 = "这个键当前没按下"。键盘记录器据此判定为"没按"，
			//    也就记不到东西 —— 这是对轮询式记录器有效的阻断方式
			//    （它没有别的方式拿到状态）。
			return 0;
		}

		const SHORT result = pOriginalGetAsyncKeyState(vKey);
		event.Status = 0;
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	SHORT WINAPI GetKeyState_Hook(int vKey)
	{
		if (!PollingDetectorTrips()) {
			return pOriginalGetKeyState(vKey);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"轮询读取按键状态（未安装钩子）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		wcsncpy_s(event.ValueName, L"GetKeyState（高频轮询）", _TRUNCATE);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventKeyboard | R3ShieldCore::FlagEventLowLevelHook;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::PollKeyState, event, true, 0, 0, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return 0;
		}

		const SHORT result = pOriginalGetKeyState(vKey);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	BOOL WINAPI GetKeyboardState_Hook(PBYTE keys)
	{
		// ⚠️ GetKeyboardState 一次就把 256 个键全拿走 —— 它**天生**是
		//    "批量读"，不需要循环。所以它比另两个更危险（一次调用 = 全键盘
		//    状态），但也因此更容易被正常程序调用（一次读全表省事）。
		//    判据仍然用密度：正常程序一帧调 1 次，记录器会连调。
		if (!PollingDetectorTrips()) {
			return pOriginalGetKeyboardState(keys);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"轮询读取全键盘状态（未安装钩子）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		wcsncpy_s(event.ValueName, L"GetKeyboardState（一次读走 256 键）", _TRUNCATE);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventKeyboard | R3ShieldCore::FlagEventLowLevelHook;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::PollKeyState, event, true, 0, 0, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalGetKeyboardState(keys);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：SetWinEventHook（v11）
	// ------------------------------------------------------------------
	//
	// ⚠️ SetWinEventHook 本身**不算高危**（无障碍工具、窗口管理器都在用），
	//    但它能拿到"前台窗口切换"这类事件流 —— 是行为画像/窗口跟踪的骨架。
	//    这里无差别记录（频率极低，一个进程通常装个位数个），
	//    高危判定交给规则层（当前返回 nullptr，即 Mode 决定）。
	//
	HWINEVENTHOOK WINAPI SetWinEventHook_Hook(DWORD eventMin, DWORD eventMax, HMODULE hmodWinEventProc,
		WINEVENTPROC pfnWinEventProc, DWORD idProcess, DWORD idThread, UINT dwFlags)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		if (eventMin == 0x0003 /*EVENT_SYSTEM_FOREGROUND*/
			|| (eventMin <= 0x0003 && eventMax >= 0x0003)) {
			wcsncpy_s(event.KeyPath, L"监听前台窗口切换（EVENT_SYSTEM_FOREGROUND）", _TRUNCATE);
		}
		else {
			swprintf_s(event.KeyPath, L"监听系统事件（范围 0x%04X-0x%04X）", eventMin, eventMax);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		// WINEVENT_OUTOFCONTEXT = 0x0000，表示事件在本进程处理、不注入别的进程；
		// 带 INCONTEXT 才是往目标进程注入。
		if ((dwFlags & 0x0000) == 0 && (dwFlags & 0x0004) == 0 /*WINEVENT_SKIPOWNPROCESS*/) {
			// 仅用于展示：不一定有 INCONTEXT 标志
		}
		swprintf_s(event.ValueName, L"flags=0x%X，进程过滤=%u，线程过滤=%u", dwFlags, idProcess, idThread);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::SetEventHook, event, true, 0, idThread, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		const HWINEVENTHOOK result = pOriginalSetWinEventHook(eventMin, eventMax, hmodWinEventProc,
			pfnWinEventProc, idProcess, idThread, dwFlags);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ==================================================================
	// 反向输入 —— 合成键鼠 / 冻结输入 / 锁鼠标（v14）
	// ==================================================================
	//
	// ⚠️ 三类判据截然不同，分开说：
	//
	//   SendInput / keybd_event / mouse_event —— **密度判据**
	//     为什么不能"调了就报"：自动化外挂、宏、脚本、无障碍工具、
	//     远程桌面客户端、KVM 软件全在用，而且很多是**合法高频**
	//     （自动化测试一秒能发上千个事件）。
	//     所以用一个独立的密度检测器（与轮询检测器分开 —— 语义不同：
	//     那个数"读"的次数，这个数"发"的事件数），
	//     只有在一个时间窗内**批量伪造输入**才认定。
	//
	//   BlockInput / ClipCursor —— **前台窗口归属判据**
	//     正常用法是"我的窗口在前台时，我限制输入"（演示/游戏/安装器）。
	//     攻击用法是"**后台**进程干预用户"：冻结输入锁屏勒索、
	//     锁鼠标困住用户骗密码。所以看 GetForegroundWindow() 的
	//     进程是不是调用方自己 —— 不是就高危。
	//
	//     判据文案在规则层（InputInjectionRiskReason）。

	//
	// 合成输入的密度检测器。
	//
	// ⚠️ 参数是 **inputCount**（这次调用要注入几个事件），不是次数 ——
	//    SendInput 一次就能带走一整个 INPUT 数组（几百个事件）。
	//    所以这里累加事件数，不是累加调用数。
	//
	// 阈值取 120 事件 / 200ms：
	//   · 正常交互：人手一次点击 = 2~3 个事件（down+up），
	//     键盘连打也就几秒几十个 —— 远低于阈值。
	//   · 宏/外挂/自动化：一秒几百上千个事件 → 立刻超过。
	//   · 窗口取 200ms 比轮询检测器（100ms）长：因为合成输入通常
	//     是"突发一批"（一个循环里连发几百个），而不是持续轮询。
	//
	constexpr LONG SYNTH_THRESHOLD = 120;
	constexpr ULONGLONG SYNTH_WINDOW_MS = 200;
	constexpr ULONGLONG SYNTH_COOLDOWN_MS = 3000;

	thread_local LONG t_synthCount = 0;
	thread_local ULONGLONG t_synthWindowStart = 0;
	thread_local ULONGLONG t_synthLastReport = 0;

	// 返回 true 表示"这次批量注入应被判为合成输入"。
	// ⚠️ 极热路径（自动化程序每秒调用成千上万次），只做算术。
	bool SyntheticInputDetectorTrips(ULONG inputCount) noexcept
	{
		// 一次调用携带的事件数就直接超阈值（如 SendInput 一次发 256 个）→ 立即认定。
		if (inputCount >= SYNTH_THRESHOLD) {
			const ULONGLONG now = GetTickCount64();
			if (t_synthLastReport == 0 || (now - t_synthLastReport) >= SYNTH_COOLDOWN_MS) {
				t_synthLastReport = now;
				t_synthCount = 0;
				t_synthWindowStart = now;
				return true;
			}
			return false;
		}

		const ULONGLONG now = GetTickCount64();

		if (t_synthLastReport != 0 && (now - t_synthLastReport) < SYNTH_COOLDOWN_MS) {
			return false;
		}

		if (t_synthWindowStart == 0 || (now - t_synthWindowStart) >= SYNTH_WINDOW_MS) {
			t_synthWindowStart = now;
			t_synthCount = static_cast<LONG>(inputCount);
			return false;
		}

		t_synthCount += static_cast<LONG>(inputCount);
		if (t_synthCount < SYNTH_THRESHOLD) {
			return false;
		}

		t_synthCount = 0;
		t_synthWindowStart = now;
		t_synthLastReport = now;
		return true;
	}

	// 当前前台窗口是不是本进程的（本进程的线程拥有的窗口）。
	//
	// 用途：BlockInput / ClipCursor 的合法性判据 ——
	//   自己前台时限制输入 = 正常（演示/游戏）；
	//   后台限制输入 = 勒索锁屏 / 伪造登录框。
	//
	// ⚠️ GetForegroundWindow 拿到的窗口，归属进程要用 GetWindowThreadProcessId
	//    反查。失败（无前台窗口）按"不是自己"处理 → 更保守。
	bool ForegroundOwnedByCaller() noexcept
	{
		__try {
			HWND foreground = GetForegroundWindow();
			if (!foreground) {
				return false;
			}

			DWORD ownerPid = 0;
			GetWindowThreadProcessId(foreground, &ownerPid);
			return ownerPid == GetCurrentProcessId();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	//
	// SendInput —— 现代合成输入 API。
	//
	// ⚠️ pInputs 可能是内核可写的用户缓冲，我们**不解析它**（解析会
	//    引入崩溃面，且没必要 —— 判据只看"批量"）。只累加事件数。
	//
	UINT WINAPI SendInput_Hook(UINT cInputs, LPINPUT pInputs, int cbSize)
	{
		if (!SyntheticInputDetectorTrips(cInputs)) {
			return pOriginalSendInput(cInputs, pInputs, cbSize);
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"合成键鼠输入（SendInput）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"%u 个事件，%llu ms 内累计超过 %d",
			cInputs, static_cast<unsigned long long>(SYNTH_WINDOW_MS), SYNTH_THRESHOLD);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventKeyboard | R3ShieldCore::FlagEventMouse;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::SendInputEvents, event, true, 0, 0, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return 0; // 0 = 一个事件都没注入成功
		}

		const UINT result = pOriginalSendInput(cInputs, pInputs, cbSize);
		event.Status = (result == cInputs) ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	//
	// keybd_event —— 老式合成键盘。一次 = 1 个事件。
	//
	void WINAPI keybd_event_Hook(BYTE bVk, BYTE bScan, DWORD dwFlags, ULONG_PTR dwExtraInfo)
	{
		if (!SyntheticInputDetectorTrips(1)) {
			pOriginalKeybdEvent(bVk, bScan, dwFlags, dwExtraInfo);
			return;
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"合成键盘输入（keybd_event）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"虚拟键 0x%02X，%llu ms 内累计超过 %d",
			bVk, static_cast<unsigned long long>(SYNTH_WINDOW_MS), SYNTH_THRESHOLD);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventKeyboard;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::SendInputEvents, event, true, 0, 0, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return; // void：直接吞掉这次合成按键
		}

		pOriginalKeybdEvent(bVk, bScan, dwFlags, dwExtraInfo);
		event.Status = 0;
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
	}

	//
	// mouse_event —— 老式合成鼠标。一次 = 1 个事件。
	//
	void WINAPI mouse_event_Hook(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo)
	{
		if (!SyntheticInputDetectorTrips(1)) {
			pOriginalMouseEvent(dwFlags, dx, dy, dwData, dwExtraInfo);
			return;
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"合成鼠标输入（mouse_event）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"flags=0x%X，%llu ms 内累计超过 %d",
			dwFlags, static_cast<unsigned long long>(SYNTH_WINDOW_MS), SYNTH_THRESHOLD);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventMouse;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::SendInputEvents, event, true, 0, 0, false);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return;
		}

		pOriginalMouseEvent(dwFlags, dx, dy, dwData, dwExtraInfo);
		event.Status = 0;
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
	}

	//
	// BlockInput —— 冻结/解冻用户的键鼠输入。
	//
	// 判据 = 前台窗口归属（见 ForegroundOwnedByCaller 的注释）。
	// ⚠️ fBlock=TRUE 冻结、FALSE 解冻 —— 解冻永远无害，直接放行
	//    （不判高危、不记录），否则会出现"解冻也要过审"的荒唐局面。
	//
	BOOL WINAPI BlockInput_Hook(BOOL fBlock)
	{
		// 解冻：无条件放行。
		if (!fBlock) {
			return pOriginalBlockInput(fBlock);
		}

		InterlockedIncrement(&g_activeHooks);

		const bool fgOwned = ForegroundOwnedByCaller();

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"冻结用户键鼠输入（BlockInput）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"前台窗口%s本进程", fgOwned ? L"属于" : L"不属于");
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventKeyboard | R3ShieldCore::FlagEventMouse;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::BlockUserInput, event, true, 0, 0, false, fgOwned);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalBlockInput(fBlock);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	//
	// ClipCursor —— 把鼠标锁在一个矩形内。
	//
	// 判据同 BlockInput：前台属主锁自己 = 游戏合法；
	// 后台锁鼠标 = 伪造登录框 / 困住用户。
	//
	// ⚠️ pRect == NULL 表示**解除**锁定 → 永远放行（同 BlockInput 解冻）。
	//
	BOOL WINAPI ClipCursor_Hook(const RECT* pRect)
	{
		if (!pRect) {
			return pOriginalClipCursor(pRect);
		}

		InterlockedIncrement(&g_activeHooks);

		const bool fgOwned = ForegroundOwnedByCaller();

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"锁定鼠标到指定区域（ClipCursor）", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		swprintf_s(event.ValueName, L"矩形(%ld,%ld,%ld,%ld)，前台窗口%s本进程",
			pRect->left, pRect->top, pRect->right, pRect->bottom,
			fgOwned ? L"属于" : L"不属于");
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventMouse;
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::HookOp::ClipCursorLock, event, true, 0, 0, false, fgOwned);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return FALSE;
		}

		const BOOL result = pOriginalClipCursor(pRect);
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
				LOG(L"InputHookGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"InputHookGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"InputHookGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"InputHookGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace InputHookGuard
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
				LOG(L"InputHookGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		const bool hookCapture = policy && (policy->Flags & R3ShieldCore::FlagHookInputHook) != 0;
		const bool hookInject = policy && (policy->Flags2 & R3ShieldCore::FlagHookInputInject) != 0;
		if (!policy || (!hookCapture && !hookInject)) {
			g_bypass = true;
			g_installed = true;
			LOG(L"InputHookGuard: hook_input / hook_input_inject 都未开启，本进程不挂输入钩子 hook");
			return true;
		}

		g_bypass = false;

		// user32 在任何有窗口的进程里都已经加载；无窗口的进程
		// （服务、控制台工具）挂不上也没关系 —— 它们本来也不装钩子。
		HMODULE user32 = GetModuleHandleW(L"user32.dll");
		if (!user32) {
			LOG(L"InputHookGuard: user32 未加载，本进程不挂输入钩子 hook");
			g_installed = true;
			return true;
		}

		if (hookCapture) {
		QueueHook("user32.dll", "SetWindowsHookExW",
			reinterpret_cast<LPVOID>(SetWindowsHookExW_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalSetWindowsHookExW), true);
		QueueHook("user32.dll", "SetWindowsHookExA",
			reinterpret_cast<LPVOID>(SetWindowsHookExA_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalSetWindowsHookExA), false);
		QueueHook("user32.dll", "UnhookWindowsHookEx",
			reinterpret_cast<LPVOID>(UnhookWindowsHookEx_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalUnhookWindowsHookEx), false);
		QueueHook("user32.dll", "RegisterRawInputDevices",
			reinterpret_cast<LPVOID>(RegisterRawInputDevices_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalRegisterRawInputDevices), false);

		// v11：不装钩子的键盘记录路径。
		//
		// ⚠️ 这三个 API 极热（消息循环、输入法、游戏都在调），所以
		//    它们**一律用非必需挂载**：某个挂不上就跳过，绝不让整个
		//    guard 失败。真正的过滤在 PollingDetector 里（按密度）。
		QueueHook("user32.dll", "GetAsyncKeyState",
			reinterpret_cast<LPVOID>(GetAsyncKeyState_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalGetAsyncKeyState), false);
		QueueHook("user32.dll", "GetKeyState",
			reinterpret_cast<LPVOID>(GetKeyState_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalGetKeyState), false);
		QueueHook("user32.dll", "GetKeyboardState",
			reinterpret_cast<LPVOID>(GetKeyboardState_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalGetKeyboardState), false);

		// SetWinEventHook：低频，无差别记录。
		QueueHook("user32.dll", "SetWinEventHook",
			reinterpret_cast<LPVOID>(SetWinEventHook_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalSetWinEventHook), false);
		}

		//
		// v14：反向输入面 —— 合成键鼠 / 冻结输入 / 锁鼠标。
		//
		// 单独开关 hook_input_inject（Flags2），与捕获面（hook_input）分开：
		//   捕获面异常 → 窃听（键盘记录/截屏）；
		//   反向面异常 → 操控（远控代操作 / 锁屏勒索 / UAC 绕过点"是"）。
		// 默认都开。
		//
		// ⚠️ 全部 required=false：SendInput 在 user32 但 keybd_event /
		//    mouse_event 是兼容层导出，个别精简系统可能缺；
		//    BlockInput / ClipCursor 也是可选能力。缺一个不该让整层失败。
		//
		if (hookInject) {
			QueueHook("user32.dll", "SendInput",
				reinterpret_cast<LPVOID>(SendInput_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalSendInput), false);
			QueueHook("user32.dll", "keybd_event",
				reinterpret_cast<LPVOID>(keybd_event_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalKeybdEvent), false);
			QueueHook("user32.dll", "mouse_event",
				reinterpret_cast<LPVOID>(mouse_event_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalMouseEvent), false);
			QueueHook("user32.dll", "BlockInput",
				reinterpret_cast<LPVOID>(BlockInput_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalBlockInput), false);
			QueueHook("user32.dll", "ClipCursor",
				reinterpret_cast<LPVOID>(ClipCursor_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalClipCursor), false);
		}

		g_installed = true;

		LOG(L"InputHookGuard: 已挂载 %d 个输入钩子 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
