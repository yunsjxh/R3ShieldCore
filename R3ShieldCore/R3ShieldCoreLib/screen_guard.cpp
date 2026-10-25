#include "stdafx.h"
#include "screen_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"
// ★ v134：替换内容可以来自**外部图片**（ini `spoof_screen_image=`）。
//   生产与单测**共用同一份**实现（铁律 127：探针别自己重写一遍替换逻辑，
//   否则"探针通过"证明不了生产代码）。
#include "screen_spoof_image.h"
// ★ v135：截屏面接进中文规则表（按调用方进程名决定换成哪张图）。
//   命名空间必须与「编译期高危规则表」分得开 —— 见 rules_codec.h 头部（v78）。
#include <r3shieldcore/rules_codec.h>
#include "rules_script_runtime.h"
namespace RScript = R3ShieldCoreRuleScript;

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

	// v74：决策档位收敛到共享 ABI（`R3ShieldCore::Action`，见
	//   shared/r3shieldcore/r3shieldcore_shared.h）。本文件**不再**自己定义。
	//   ★ 本面是 `Spoof` 的**第一个**落地形态（v67）：截屏调用**成功**返回，
	//     但目标位图被涂成黑帧。
	using Action = R3ShieldCore::Action;

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

	// ------------------------------------------------------------------
	// v67：替换（Spoof）相关
	// ------------------------------------------------------------------
	//
	// 判据只有一条：ini `spoof_screen=1`（Policy::Flags2 的 FlagSpoofScreen，默认关）。
	// 触发点只有"本应拒绝"的地方 —— 见 RejectOrSpoof。
	//
	bool SpoofScreenEnabled() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy && (policy->Flags2 & R3ShieldCore::FlagSpoofScreen) != 0;
	}

	// 把一块 DC 区域涂黑。返回 true 表示**替换真的发生了**。
	//
	// ⚠️ PatBlt 不在本 guard 的挂载表里 ⇒ 无递归（不会回头进 BitBlt_Hook）。
	// ⚠️ 用 __try 护住：目标 DC 可能是野句柄 / 已被销毁
	//    （铁律 97：失败必须可见，不能只有"没生效"）。
	bool BlackenRect(HDC dc, int x, int y, int width, int height) noexcept
	{
		if (!dc || width <= 0 || height <= 0) {
			return false;
		}

		__try {
			return PatBlt(dc, x, y, width, height, BLACKNESS) != FALSE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	// 把 GetDIBits 的像素缓冲区涂黑（BI_RGB 下"全 0"即黑色）。
	//
	// ⚠️ 必须按**位深算行距**（24/16/8bpp 的行是 4 字节对齐的），
	//    不能想当然按 32bpp 算 —— 那会少涂一半或越界。
	//    （探针实测：DIB 32bpp 像素 DWORD 是 BGRA 内存序，全 0 = 黑。）
	// ⚠️ 只涂**本次真正写入的行数**（rowsWritten）—— 调用者可能只请求了
	//    中间几行、缓冲区也只有那么大。
	bool BlackenDibBits(LPVOID bits, const BITMAPINFO* info, int rowsWritten) noexcept
	{
		if (!bits || !info || rowsWritten <= 0) {
			return false;
		}

		const BITMAPINFOHEADER& header = info->bmiHeader;
		if (header.biWidth <= 0) {
			return false;
		}
		// 压缩格式（RLE / JPEG / PNG）的字节布局不是"每像素固定位数"，不猜。
		if (header.biCompression != BI_RGB && header.biCompression != BI_BITFIELDS) {
			return false;
		}

		const LONG totalRows = header.biHeight < 0 ? -header.biHeight : header.biHeight;
		LONG rows = rowsWritten;
		if (rows > totalRows) {
			rows = totalRows;
		}

		size_t stride = 0;
		switch (header.biBitCount) {
		case 32: stride = static_cast<size_t>(header.biWidth) * 4; break;
		case 24: stride = (static_cast<size_t>(header.biWidth) * 3 + 3) & ~static_cast<size_t>(3); break;
		case 16: stride = (static_cast<size_t>(header.biWidth) * 2 + 3) & ~static_cast<size_t>(3); break;
		case 8:  stride = (static_cast<size_t>(header.biWidth) + 3) & ~static_cast<size_t>(3); break;
		default: return false;   // 1/4bpp 调色板格式少见，不猜
		}

		const size_t bytes = stride * static_cast<size_t>(rows);
		__try {
			memset(bits, 0, bytes);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;   // 目标页只读 / 缓冲区不够 —— 替换失败，别崩宿主
		}
		return true;
	}

	// ------------------------------------------------------------------
	// ★ v134：替换的**内容来源**（外部图片 vs 黑帧）
	// ------------------------------------------------------------------
	//
	// 语义：`spoof_screen=1` **且** `spoof_screen_image=` 非空 ⇒ 把那张图
	//   **拉伸铺满**被截取的区域；否则 ⇒ 保持 v67 的黑帧（默认行为一字不改）。
	//
	// ★★★ 失败方向必须**更像假**，不能更像真：
	//   图片读不到 / 画不上（DC 不可写 / 格式不支持）时，一律**回落黑帧**，
	//   绝不"那就把真画面放过去"。所以这里写成"先试图片，失败再涂黑"，
	//   而**不是**"有图就不涂黑"。这条是替换功能的底线（铁律 12/13 同款）。
	//
	// ⚠️ 为什么每个 hook 点都调这两个包装、而不是各自判断：
	//   四个替换点（BitBlt / StretchBlt / PrintWindow / GetDIBits）如果各写一遍
	//   "有没有配图 / 图能不能用"，迟早有一处漏掉 ⇒ 表现为"截图一半是图、
	//   一半是黑"，而那种现象极难归因。
	R3ShieldCore::Policy* SpoofPolicy() noexcept
	{
		return R3ShieldCoreChannel::Policy();
	}

	// 配了图片吗（且非空）。NULL 表示"没配"。
	const WCHAR* SpoofImagePath() noexcept
	{
		R3ShieldCore::Policy* policy = SpoofPolicy();
		if (policy && policy->SpoofScreenImagePath[0] != L'\0')
		{
			return policy->SpoofScreenImagePath;
		}
		return nullptr;
	}

	// ------------------------------------------------------------------
	// ★ v135：截屏面接进中文规则表 —— 按**调用方进程名**决定"换成什么"
	// ------------------------------------------------------------------
	//
	// 规则示例：`当 截屏 的 进程 含 "OBS" 时 替换为图 "C:\fake\desktop.bmp"`
	//
	// ★ 为什么"调用方"就是**当前进程**：
	//   hook 是注入到被截屏的那个进程里的，`BitBlt` 的调用者就是它自己
	//   （跨进程截屏也是"在 A 进程里 BitBlt B 的窗口 DC"，hook 仍在 A 里）。
	//   ⇒ 取自己的 exe 名就够了，**一次缓存、之后零成本**。
	//   ⚠️ 不要为这个去查窗口标题：`BitBlt` 的 DC 大多拿不到来源窗口。
	//
	// ★ 进程名只取一次：`GetModuleFileNameW` 每次调用都要查进程参数块，
	//   而这条路径可能一秒跑几十次（每帧截屏）。
	const WCHAR* CurrentProcessExeName() noexcept
	{
		static WCHAR s_name[MAX_PATH] = {};
		static volatile LONG s_ready = 0;
		if (s_ready == 0)
		{
			WCHAR full[MAX_PATH] = {};
			const DWORD n = GetModuleFileNameW(nullptr, full, MAX_PATH);
			if (n > 0 && n < MAX_PATH)
			{
				const WCHAR* slash = wcsrchr(full, L'\\');
				wcsncpy_s(s_name, slash ? slash + 1 : full, _TRUNCATE);
			}
			// 并发下两个线程可能都写一遍 —— 写的是同一个值，无害。
			InterlockedExchange(&s_ready, 1);
		}
		return s_name;
	}

	enum class ScreenSpoofMode
	{
		Black,   // 涂黑（默认；也是"图读不到"的回落方向）
		Image,   // 画指定图片
		Pass,    // 规则明确要求放行：本次**不替换**，返回真实画面
	};

	// 决定本次替换"怎么做"。`imageOut` 非空时写入图片路径（空串 = 没有图）。
	//
	// ★★★ 为什么用**输出缓冲区**而不是返回 `const WCHAR*`：
	//   规则命中时路径来自 `Verdict::text`（一个 `std::wstring`），
	//   `Verdict` 是**局部变量** —— 把它的 `c_str()` 返回出去就是
	//   **悬垂指针**，而这条路径在热区里，表现为"偶发画出乱七八糟的图"
	//   或直接崩在被注入进程里。拷贝一份就没有这个问题。
	//
	// ★ 叠加语义（用户选的那个）：ini 的 `spoof_screen` 开关已经在外面判过
	//   （只有 `action == Action::Spoof` 才进来）；这里规则**再细分**。
	//   规则一条都没命中 ⇒ 回落 v134 的全局图片；没配图 ⇒ 黑帧。
	ScreenSpoofMode ScreenMode(WCHAR* imageOut, size_t cap) noexcept
	{
		if (imageOut && cap > 0)
		{
			imageOut[0] = L'\0';
		}

		if (RScript::HasFace(RScript::Face::Screen))
		{
			const RScript::Verdict v = RScript::Eval(
				RScript::Face::Screen, nullptr, CurrentProcessExeName(), nullptr);
			if (v.hit)
			{
				switch (v.act)
				{
				case RScript::Act::Pass:
					return ScreenSpoofMode::Pass;
				case RScript::Act::ReplaceImage:
					if (imageOut && cap > 0 && !v.text.empty())
					{
						wcsncpy_s(imageOut, cap, v.text.c_str(), _TRUNCATE);
						return ScreenSpoofMode::Image;
					}
					// 图路径是空串 ⇒ 等于没配图 ⇒ 黑帧（失败方向"更像假"）。
					return ScreenSpoofMode::Black;
				default:
					return ScreenSpoofMode::Black;
				}
			}
		}

		const WCHAR* ini = SpoofImagePath();
		if (ini && imageOut && cap > 0)
		{
			wcsncpy_s(imageOut, cap, ini, _TRUNCATE);
			return ScreenSpoofMode::Image;
		}
		return ScreenSpoofMode::Black;
	}

	// DC 路径：图片优先，失败回落黑帧。返回 true = 替换真的发生了。
	//
	// ★ v135：图片路径由调用方传进来（`ScreenMode` 已经决定好了），
	//   而不是在这里再读一次 policy —— 否则规则会被求值两遍，
	//   两遍之间还可能因为规则表变化而给出不同答案。
	bool SpoofRect(HDC dc, int x, int y, int width, int height, const WCHAR* image) noexcept
	{
		if (image && R3ShieldCoreScreenImage::PaintRect(dc, x, y, width, height, image))
		{
			return true;
		}
		return BlackenRect(dc, x, y, width, height);
	}

	// GetDIBits 路径：图片优先，失败回落 memset(0)。
	bool SpoofDibBits(LPVOID bits, const BITMAPINFO* info, int rowsWritten,
		const WCHAR* image) noexcept
	{
		if (image && R3ShieldCoreScreenImage::PaintDib(bits, info, rowsWritten, image))
		{
			return true;
		}
		return BlackenDibBits(bits, info, rowsWritten);
	}

	// 「本应拒绝」时的统一出口。
	//
	// ★ v67：开关打开 ⇒ **替换**（调用成功 + 黑帧 / v134 起可为外部图片）；
	//   否则 ⇒ 拒绝（原行为，一字不改）。
	// ⚠️ 返回 Spoof 时，detour 层**不得**返回失败码 —— 要真调原函数后返回它的结果。
	// ⚠️ 本函数**不**负责置 FlagEvent2Spoofed：那是 detour 层按"涂黑是否真成功"置的。
	Action RejectOrSpoof(R3ShieldCore::Event& event) noexcept
	{
		if (SpoofScreenEnabled()) {
			// 替换不是"被拦"：不置 FlagEventBlocked，不计 HighRiskBlocked。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Spoofed);
			return Action::Spoof;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return Action::Block;
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
		// ★ v132：这一面的处置档由配置决定（ini: privacy_screen=record|ask|block）。
		const R3ShieldCore::ObjectType face =
			static_cast<R3ShieldCore::ObjectType>(event.ObjectType);
		const R3ShieldCore::PrivacyAction privacy =
			R3ShieldCore::PrivacyActionOf(policy ? policy->Flags2 : 0, face);
		const bool privacyAsk = R3ShieldCore::IsPrivacyFace(face)
			&& privacy == R3ShieldCore::PrivacyAction::Ask
			&& mode == static_cast<ULONG>(R3ShieldCore::Mode::Block);

		const bool canAsk = allowAsk
			&& (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask) || privacyAsk);
		if (!canAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				// ★ v132：非 Block 档（Record / 问不了的 Ask）⇒ 只记录。
				//   截屏是"知情类"：截图工具、录屏、会议共享都会走这里，
				//   硬拒的表现是"黑屏 / 截出来是空的"，用户会当成软件坏了。
				if (R3ShieldCore::IsPrivacyFace(face)
						&& privacy != R3ShieldCore::PrivacyAction::Block) {
					// ★ 先看能不能替换：开了 spoof_screen 时给"黑帧"，
					//   截图工具照常工作但拿不到真实画面 —— 比"只记录"更好。
					//   （v129 第一版直接 return Record，把替换路径挡住了，是回归。）
					if (SpoofScreenEnabled()) {
						return RejectOrSpoof(event);
					}
					event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
					return Action::Record;
				}

				// ★ v67：这里本应直接拒 —— 开关打开时改为"成功 + 黑帧"。
				return RejectOrSpoof(event);
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

		// 用户点了"拒绝"（或超时按兜底结论）：★ v67 —— 同样走 RejectOrSpoof。
		return RejectOrSpoof(event);
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

		// ★ v67：替换 —— 真调已发生（目标 DC 的句柄/尺寸都真实），
		//    再把目标区域涂黑。**返回 result（= 成功）**，调用者看不出区别。
		if (action == Action::Spoof && result) {
			// ★ v134：换成 `SpoofRect` —— 配了 `spoof_screen_image=` 就画那张图，
			//   没配 / 画不上就照旧涂黑（失败方向永远"更像假"）。
			// ★ v135：图片路径改由 `ScreenMode` 决定（规则可覆盖 ini 那张）。
			WCHAR spoofImage[260] = {};
			if (ScreenMode(spoofImage, _countof(spoofImage)) == ScreenSpoofMode::Pass) {
				// 规则明确放行 ⇒ **口径必须跟着改**，不能继续报 Spoofed（铁律 97）。
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			}
			else if (SpoofRect(hdcDest, xDest, yDest, width, height,
					spoofImage[0] ? spoofImage : nullptr)) {
				event.Flags2 |= R3ShieldCore::FlagEvent2Spoofed;
			}
			else {
				LOG(L"ScreenGuard: BitBlt 替换失败（目标 DC 不可写），本次返回真实内容");
			}
		}

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

		// ★ v67：替换 —— 同 BitBlt，涂的是**目标**矩形（缩放后的尺寸）。
		if (action == Action::Spoof && result) {
			WCHAR spoofImage[260] = {};
			if (ScreenMode(spoofImage, _countof(spoofImage)) == ScreenSpoofMode::Pass) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			}
			else if (SpoofRect(hdcDest, xDest, yDest, widthDest, heightDest,
					spoofImage[0] ? spoofImage : nullptr)) {
				event.Flags2 |= R3ShieldCore::FlagEvent2Spoofed;
			}
			else {
				LOG(L"ScreenGuard: StretchBlt 替换失败（目标 DC 不可写），本次返回真实内容");
			}
		}

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

		// ★ v67：替换 —— 把窗口画到 hdcBlt 之后再涂黑整块目标 DC。
		//    hdcBlt 的尺寸用 GetClipBox 取（内存 DC 上即"位图范围"）。
		if (action == Action::Spoof && result) {
			WCHAR spoofImage[260] = {};
			const ScreenSpoofMode mode = ScreenMode(spoofImage, _countof(spoofImage));
			RECT rect = {};
			if (mode == ScreenSpoofMode::Pass) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			}
			else if (GetClipBox(hdcBlt, &rect) != ERROR &&
				rect.right > rect.left && rect.bottom > rect.top &&
				SpoofRect(hdcBlt, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
					spoofImage[0] ? spoofImage : nullptr)) {
				event.Flags2 |= R3ShieldCore::FlagEvent2Spoofed;
			}
			else {
				LOG(L"ScreenGuard: PrintWindow 替换失败（取不到目标 DC 尺寸或不可写），本次返回真实内容");
			}
		}

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

		// ★ v67：替换 —— 真调已把真实像素写进调用者的缓冲区，现在把它涂黑。
		//    只涂**本次真正写入的行数**（result），按位深算行距。
		if (action == Action::Spoof && result > 0) {
			// ★ v134：`SpoofDibBits` —— 图片优先，失败回落 memset(0)。
			WCHAR spoofImage[260] = {};
			if (ScreenMode(spoofImage, _countof(spoofImage)) == ScreenSpoofMode::Pass) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			}
			else if (SpoofDibBits(bits, info, result,
					spoofImage[0] ? spoofImage : nullptr)) {
				event.Flags2 |= R3ShieldCore::FlagEvent2Spoofed;
			}
			else {
				LOG(L"ScreenGuard: GetDIBits 替换失败（缓冲区不可写或格式不支持），本次返回真实像素");
			}
		}

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

// ==================================================================
// ★ v129：单测专用入口（宏 SCREENGUARD_GUARD_UT 打开）
// ==================================================================
//
// `Evaluate` 在本文件的匿名 namespace 里，外部 TU 拿不到；而 v129 要验的
// 恰恰是"block 模式下**要不要走到** RejectOrSpoof" —— 只断言 RejectOrSpoof
// 的返回值等于假设它被调到了，那正好是要验的东西。
// 用编译宏隔离（`build_guard_ut.sh` 带、`build.sh` 不带）⇒ 导出表不变。
#ifdef SCREENGUARD_GUARD_UT
namespace ScreenGuardTest
{
	// ★ v132：`allowAsk` 从形参传进来（v129 时写死 false）。
	int EvaluateForTest(ULONG op, bool allowAsk, int* decisionOut, ULONG* flagsOut) noexcept
	{
		R3ShieldCore::Event event = {};
		const Action action = Evaluate(static_cast<R3ShieldCore::ScreenOp>(op),
			event, allowAsk);
		if (decisionOut) *decisionOut = static_cast<int>(event.Decision);
		if (flagsOut)    *flagsOut = event.Flags;
		return static_cast<int>(action);
	}

	// ★ v135：截屏面的规则求值（`ScreenMode`）同样在匿名 namespace 里。
	//   返回 0 = 黑帧，1 = 画图（路径抄进 imageOut），2 = 放行。
	//   ★ 为什么一定要能测：`Pass` 会把上报口径从 `Spoofed` 改成 `Allowed`
	//     （铁律 97：口径必须与实际一致）—— 而这个改动**只在运行时生效**，
	//     光看代码看不出来"这一次到底是放行还是替换"。
	int ScreenModeForTest(WCHAR* imageOut, int cap) noexcept
	{
		const ScreenSpoofMode m = ScreenMode(imageOut, static_cast<size_t>(cap));
		if (m == ScreenSpoofMode::Image) return 1;
		if (m == ScreenSpoofMode::Pass)  return 2;
		return 0;
	}

	// 规则是按"调用方进程名"匹配的，单测得先知道自己的名字才能写出命中的规则。
	const WCHAR* ProcessExeNameForTest() noexcept
	{
		return CurrentProcessExeName();
	}
}
#endif // SCREENGUARD_GUARD_UT
