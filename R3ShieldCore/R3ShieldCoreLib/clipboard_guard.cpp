#include "stdafx.h"
#include "clipboard_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 剪贴板读取监控层。
//
// 挂载点（都在 user32）：
//   OpenClipboard    ← 打开剪贴板（读写的敲门砖）→ 只记录
//   GetClipboardData ← 真正取走内容              → 高危
//
// ⚠️ 噪音控制的要点：
//   OpenClipboard 频率不低（每次粘贴、每次截图工具、输入法都会调），
//   但**不能挂成"只记录"就不管** —— 记录本身也要走环形缓冲。
//   好在它比 BitBlt 那种热路径温和得多（人操作剪贴板的频率是人手频率），
//   所以这里不额外过滤，如实记录即可。
//
//   GetClipboardData 相对低频，且一旦出现就值得让用户看到，直接高危。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------
	typedef BOOL(WINAPI* OpenClipboardPtr)(HWND);
	typedef HANDLE(WINAPI* GetClipboardDataPtr)(UINT);

	OpenClipboardPtr pOriginalOpenClipboard = nullptr;
	GetClipboardDataPtr pOriginalGetClipboardData = nullptr;

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
	// 上报与判定
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Clipboard);
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

	Action Evaluate(R3ShieldCore::ClipboardOp op, R3ShieldCore::Event& event, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Clipboard);
		event.Op = static_cast<ULONG>(op);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式 ----
		// Open is part of the read path; allowing it would leave a detectable
		// operation outside the advertised BlockAll boundary.
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
		return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskClipboard(static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				event.Flags |= R3ShieldCore::FlagEventClipboardRead;
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

		// 高危：读取剪贴板内容。
		//
		// ⚠️ 必须再判一次 mode == Ask。Ask 依赖引擎侧 UI 线程，
		//    而那个线程只在 ASK 模式启动 —— LOG/BLOCK 下调 Ask 会等
		//    一个永远不来的答复（实测表现：LOG 模式被当成 Deny 直接拦）。
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

	// 常用剪贴板格式名。只是给用户看个大概 —— 格式号可以是任意注册格式，
	// 没命中就退回数字。不 include winuser.h 里的常量表含义注释。
	const char* ClipboardFormatName(UINT format) noexcept
	{
		switch (format) {
		case 1:  return "CF_TEXT（文本）";
		case 2:  return "CF_BITMAP（位图）";
		case 3:  return "CF_METAFILEPICT";
		case 8:  return "CF_DIB（设备无关位图）";
		case 13: return "CF_UNICODETEXT（Unicode 文本）";
		case 16: return "CF_LOCALE";
		case 17: return "CF_DIBV5";
		default: return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// hook：OpenClipboard（只记录）
	// ------------------------------------------------------------------
	BOOL WINAPI OpenClipboard_Hook(HWND newOwner)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"打开剪贴板", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
		event.Status = 0;

		// 只记录：allowAsk = false，且即使判定返回 Block 也不会拦开。
		// 走到 Open 的调用绝大多数是正常粘贴/复制，不该打断。
		Evaluate(R3ShieldCore::ClipboardOp::Open, event, false);

		const BOOL result = pOriginalOpenClipboard(newOwner);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：GetClipboardData（高危）
	// ------------------------------------------------------------------
	HANDLE WINAPI GetClipboardData_Hook(UINT format)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		wcsncpy_s(event.KeyPath, L"读取剪贴板内容", _TRUNCATE);
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		if (const char* name = ClipboardFormatName(format)) {
			// %S 把窄串按当前 ANSI 代码页转宽 —— 这里全是 ASCII，安全。
			swprintf_s(event.ValueName, L"格式 %u：%S", format, name);
		}
		else {
			swprintf_s(event.ValueName, L"格式 %u", format);
		}
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::ClipboardOp::Read, event, true);
		if (action == Action::Block) {
			event.Status = ERROR_ACCESS_DENIED;
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		const HANDLE result = pOriginalGetClipboardData(format);
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
				LOG(L"ClipboardGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"ClipboardGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"ClipboardGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"ClipboardGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace ClipboardGuard
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
				LOG(L"ClipboardGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookClipboard) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"ClipboardGuard: hook_clipboard 未开启，本进程不挂剪贴板 hook");
			return true;
		}

		g_bypass = false;

		// user32 在绝大多数有 GUI 的进程里已加载；纯控制台进程不挂也无所谓。
		// 与 ScreenGuard 同理，这里**不主动 LoadLibrary** —— 剪贴板是
		// 交互功能，没加载 user32 的进程本来也不会碰剪贴板。
		HMODULE user32 = GetModuleHandleW(L"user32.dll");
		if (!user32) {
			LOG(L"ClipboardGuard: user32.dll 未加载，本进程不挂剪贴板 hook");
			g_installed = true;
			return true;
		}

		QueueHook("user32.dll", "OpenClipboard", reinterpret_cast<LPVOID>(OpenClipboard_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalOpenClipboard), true);
		QueueHook("user32.dll", "GetClipboardData", reinterpret_cast<LPVOID>(GetClipboardData_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalGetClipboardData), true);

		g_installed = true;

		LOG(L"ClipboardGuard: 已挂载 %d 个剪贴板 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
