#include "stdafx.h"
#include "camera_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

// v13：音频采集。只引类型与常量，不引链接库 ——
//   这两个头都在 SDK 里，且不含需要链接的实现。
//   ⚠️ mmdeviceapi.h 会拉进 mmreg.h / ksmedia.h 一类的定义，
//      编译时间多一点，但换来类型安全（WAVEFORMATEX / MMRESULT）。
#include <mmsystem.h>
#include <mmdeviceapi.h>

//
// 摄像头 / 麦克风访问监控层。
//
// 骨架与其它 guard 一致：判定 → 上报 / 拒绝 → 等排空。
// 特殊之处：
//   1. 目标 DLL（avicap32 / mfplat / mfreadwrite）在多数进程里**没加载**。
//      不主动 LoadLibrary 的话，GetModuleHandle 返回 0，hook 就挂不上 ——
//      而等程序自己加载时我们已经没有机会了（除非去挂 LoadLibrary，
//      那是另一种侵入性）。所以这里主动加载，与 NetworkGuard 对 ws2_32
//      的做法一致。
//   2. Media Foundation 的设备名在 IMFAttributes 里，要读出来得走
//      COM 虚函数（vtable 第 12 项 GetString）。这一步用 __try 包住，
//      读不到就退回通用文案 —— 设备名只是"好看"，不影响拦截判定。
//
// 判据：打开就报（见 r3shieldcore_rules.cpp 的 IsHighRiskCamera）。
//
namespace
{
	// ------------------------------------------------------------------
	// 类型与原型
	// ------------------------------------------------------------------

	// VFW：avicap32.dll
	typedef HWND(WINAPI* capCreateCaptureWindowWPtr)(LPCWSTR, DWORD, int, int, int, int, HWND, int);
	typedef HWND(WINAPI* capCreateCaptureWindowAPtr)(LPCSTR, DWORD, int, int, int, int, HWND, int);

	// Media Foundation：设备源在 mf.dll，读取器在 mfreadwrite.dll
	// 只用到指针参数，不需要 IMFAttributes 的完整定义。
	//
	// ⚠️ 模块归属是 dumpbin 实测出来的，不是猜的：
	//      mf.dll!MFCreateDeviceSource          → 转发到 mfcore.dll
	//      mf.dll!MFCreateDeviceSourceActivate  → 转发到 mfcore.dll
	//      mf.dll!MFEnumDeviceSources           → 转发到 mfcore.dll
	//      mfreadwrite.dll!MFCreateSourceReaderFromMediaSource
	//      mfplat.dll!MFCreateAttributes        ← 注意这个在 mfplat，不在 mf
	//    转发导出用 GetProcAddress 会解析到 mfcore 里的真实地址，
	//    挂它就等于挂了所有到达路径。
	typedef HRESULT(WINAPI* MFCreateDeviceSourcePtr)(void*, void**);
	typedef HRESULT(WINAPI* MFCreateDeviceSourceActivatePtr)(void*, void**);
	typedef HRESULT(WINAPI* MFEnumDeviceSourcesPtr)(void*, void***, UINT32*);
	typedef HRESULT(WINAPI* MFCreateSourceReaderFromMediaSourcePtr)(void*, void*, void**);

	capCreateCaptureWindowWPtr pOriginalCapCreateW = nullptr;
	capCreateCaptureWindowAPtr pOriginalCapCreateA = nullptr;
	MFCreateDeviceSourcePtr pOriginalMFCreateDeviceSource = nullptr;
	MFCreateDeviceSourceActivatePtr pOriginalMFCreateDeviceSourceActivate = nullptr;
	MFEnumDeviceSourcesPtr pOriginalMFEnumDeviceSources = nullptr;
	MFCreateSourceReaderFromMediaSourcePtr pOriginalMFCreateSourceReader = nullptr;

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

	// 我们主动拒绝时给调用方看的错误码。
	constexpr HRESULT CG_E_ACCESSDENIED = static_cast<HRESULT>(0x80070005L); // E_ACCESSDENIED

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// ------------------------------------------------------------------
	// 设备名读取（Media Foundation）
	// ------------------------------------------------------------------
	//
	// MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME
	//   {60D0E559-52F8-4FA2-BBCE-ACDB34A8439D}
	//
	// 不 include mfapi.h —— 那会拉进 mfplat.lib 的链接依赖，
	// 而且我们只需要这一个 GUID 和一次 vtable 调用。
	//
	struct CG_GUID
	{
		ULONG Data1;
		USHORT Data2;
		USHORT Data3;
		UCHAR Data4[8];
	};

	const CG_GUID MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME_ =
		{ 0x60d0e559, 0x52f8, 0x4fa2, { 0xbb, 0xce, 0xac, 0xdb, 0x34, 0xa8, 0x43, 0x9d } };

	typedef HRESULT(STDMETHODCALLTYPE* IMFAttributesGetStringPtr)(
		void* self, const CG_GUID* key, LPWSTR value, UINT32 cch, UINT32* length);

	// IMFAttributes 的 vtable 顺序（IUnknown 占前 3 项）：
	//   0 QI  1 AddRef  2 Release  3 GetItem  4 GetItemType  5 CompareItem
	//   6 Compare  7 GetUINT32  8 GetUINT64  9 GetDouble  10 GetGUID
	//   11 GetStringLength  12 GetString
	constexpr int CG_IMFATTRIBUTES_GETSTRING_INDEX = 12;

	// 读设备名。任何一步不对就返回 false，调用方退回通用文案。
	// ⚠️ 这个函数里不能有需要析构的 C++ 对象，否则 __try 编不过（C2712）。
	bool TryReadFriendlyName(void* attributes, WCHAR* out, size_t cch) noexcept
	{
		if (!attributes || !out || cch == 0) {
			return false;
		}

		__try {
			void** vtable = *reinterpret_cast<void***>(attributes);
			if (!vtable) {
				return false;
			}

			auto getString = reinterpret_cast<IMFAttributesGetStringPtr>(
				vtable[CG_IMFATTRIBUTES_GETSTRING_INDEX]);
			if (!getString) {
				return false;
			}

			UINT32 length = 0;
			const HRESULT hr = getString(attributes, &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME_,
				out, static_cast<UINT32>(cch), &length);
			return SUCCEEDED(hr) && out[0] != L'\0';
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
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
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Camera);
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

	// 结果判定。allowAsk 决定高危时能不能真的弹窗 ——
	// LOG/BLOCK 模式下 UI 线程根本没起，Ask 会白等满超时。
	Action Evaluate(R3ShieldCore::CameraOp op, R3ShieldCore::Event& event, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Camera);
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
			// v13：音频判据与摄像头判据**分开调** —— 两者按 op 值域
			// 各管一片（音频那三个 op 只有 IsHighRiskAudio 认，
			// 摄像头那几个只有 IsHighRiskCamera 认），不会重复上报。
			const bool cameraRisk =
				R3ShieldCoreRules::IsHighRiskCamera(static_cast<ULONG>(op));
			const bool audioRisk =
				R3ShieldCoreRules::IsHighRiskAudio(static_cast<ULONG>(op));

			if (cameraRisk || audioRisk) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
				if (cameraRisk && op != R3ShieldCore::CameraOp::EnumDevice) {
					event.Flags |= R3ShieldCore::FlagEventCameraOpen;
				}
				// v13：音频事件打音频专属位（环回 / 麦克风分档），
				// 供日志与统计区分"这次是录屏还是录音"。
				if (audioRisk) {
					if (op == R3ShieldCore::CameraOp::WasapiLoopback) {
						event.Flags2 |= R3ShieldCore::FlagEvent2AudioLoopback;
					} else {
						event.Flags2 |= R3ShieldCore::FlagEvent2AudioMic;
					}
				}
			}
		}

		// 非高危（枚举设备）：按 mode 处理。
		//
		// 与网络同理，BLOCK 模式下**不做**一刀切拦截 —— 摄像头监控的
		// BLOCK 语义是"拒绝打开设备"，枚举只是列个清单，拒掉它会让
		// 相机应用直接报错，没有意义。所以非高危一律放行，只记录。
		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// ---- 高危：打开摄像头/麦克风 ----
		//
		// ⚠️ 这里必须再与一次 mode == Ask。Ask 依赖引擎侧 UI 线程，
		//    而那个线程**只在 ASK 模式启动** —— LOG/BLOCK 下调 Ask 会等
		//    一个永远不来的答复（实测表现：LOG 模式下被当成 Deny，
		//    直接 BLOCK 掉，LOG 模式不该拦任何东西）。
		//    这是本项目踩过的坑，别把这一层去掉。
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

	// KeyPath 里放"目标是哪个设备"，长度字段一并填好。
	void SetTarget(R3ShieldCore::Event& event, PCWSTR text) noexcept
	{
		if (text && text[0]) {
			wcsncpy_s(event.KeyPath, text, _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));
	}

	// ------------------------------------------------------------------
	// hook：VFW
	// ------------------------------------------------------------------
	HWND WINAPI capCreateCaptureWindowW_Hook(LPCWSTR lpszWindowName, DWORD dwStyle,
		int x, int y, int nWidth, int nHeight, HWND hwndParent, int nID)
	{
		InterlockedIncrement(&g_activeHooks);

		HWND result = nullptr;
		R3ShieldCore::Event event = {};
		SetTarget(event, L"VFW 摄像头");
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::OpenDevice, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		result = pOriginalCapCreateW(lpszWindowName, dwStyle, x, y, nWidth, nHeight, hwndParent, nID);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	HWND WINAPI capCreateCaptureWindowA_Hook(LPCSTR lpszWindowName, DWORD dwStyle,
		int x, int y, int nWidth, int nHeight, HWND hwndParent, int nID)
	{
		InterlockedIncrement(&g_activeHooks);

		HWND result = nullptr;
		R3ShieldCore::Event event = {};
		SetTarget(event, L"VFW 摄像头");
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::OpenDevice, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			SetLastError(ERROR_ACCESS_DENIED);
			InterlockedDecrement(&g_activeHooks);
			return nullptr;
		}

		result = pOriginalCapCreateA(lpszWindowName, dwStyle, x, y, nWidth, nHeight, hwndParent, nID);
		event.Status = result ? 0u : static_cast<ULONG>(GetLastError());
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ------------------------------------------------------------------
	// hook：Media Foundation
	// ------------------------------------------------------------------
	HRESULT WINAPI MFCreateDeviceSource_Hook(void* attributes, void** source)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		WCHAR friendly[192] = {};
		if (!TryReadFriendlyName(attributes, friendly, _countof(friendly))) {
			wcsncpy_s(friendly, L"Media Foundation 设备源（摄像头/麦克风）", _TRUNCATE);
		}
		SetTarget(event, friendly);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::CreateDeviceSource, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return CG_E_ACCESSDENIED;
		}

		const HRESULT hr = pOriginalMFCreateDeviceSource(attributes, source);
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	HRESULT WINAPI MFCreateDeviceSourceActivate_Hook(void* attributes, void** activate)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		WCHAR friendly[192] = {};
		if (!TryReadFriendlyName(attributes, friendly, _countof(friendly))) {
			wcsncpy_s(friendly, L"Media Foundation 设备激活对象（摄像头/麦克风）", _TRUNCATE);
		}
		SetTarget(event, friendly);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::CreateDeviceSource, event, true);
		if (action == Action::Block) {
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return CG_E_ACCESSDENIED;
		}

		const HRESULT hr = pOriginalMFCreateDeviceSourceActivate(attributes, activate);
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	HRESULT WINAPI MFCreateSourceReaderFromMediaSource_Hook(void* mediaSource, void* attributes, void** reader)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetTarget(event, L"媒体源读取器（开始取帧）");
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::CreateSourceReader, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return CG_E_ACCESSDENIED;
		}

		const HRESULT hr = pOriginalMFCreateSourceReader(mediaSource, attributes, reader);
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	HRESULT WINAPI MFEnumDeviceSources_Hook(void* attributes, void*** devices, UINT32* count)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetTarget(event, L"(枚举摄像头/麦克风设备)");
		event.Status = 0;

		// 枚举只记录，不拦 —— 所以这里不接 allowAsk，也不走 Block 分支。
		const Action action = Evaluate(R3ShieldCore::CameraOp::EnumDevice, event, false);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return CG_E_ACCESSDENIED;
		}

		const HRESULT hr = pOriginalMFEnumDeviceSources(attributes, devices, count);
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
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
				LOG(L"CameraGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"CameraGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"CameraGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"CameraGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}

	// ==================================================================
	// v13：音频采集 / 环回
	// ==================================================================
	//
	// 两条路：
	//   ① winmm!waveInOpen / waveInPrepareHeader —— 老式波形录音（导出可挂）
	//   ② WASAPI IAudioClient::Initialize —— 纯 COM（vtable patch）
	//
	// ⚠️ 为什么必须两条都挂（铁律 12）：
	//    麦克风采集在现代程序里几乎全走 WASAPI（MMDevice → IAudioClient
	//    → Initialize），而 waveIn 是 90 年代的接口。但**正因如此**：
	//    老接口的实现往往被忽略 —— 而且它只要三行就能录到麦克风。
	//    补变体是性价比最高的一类补强。

	// ---- winmm：waveInOpen ----
	typedef MMRESULT(WINAPI* waveInOpenPtr)(HWAVEIN*, UINT, const void*, DWORD_PTR, DWORD_PTR, DWORD);
	typedef MMRESULT(WINAPI* mciSendCommandWPtr)(MCIDEVICEID, UINT, DWORD_PTR, DWORD_PTR);

	waveInOpenPtr pOriginalWaveInOpen = nullptr;
	mciSendCommandWPtr pOriginalMciSendCommandW = nullptr;

	// MCI_OPEN 的 dwMessage（winmm 的 mmsystem.h 常量）。
	// 直接用数值避免 header 依赖：MCI_OPEN = 0x0803。
	constexpr UINT CG_MCI_OPEN = 0x0803;

	MMRESULT WINAPI waveInOpen_Hook(HWAVEIN* handle, UINT deviceId, const void* format,
		DWORD_PTR callback, DWORD_PTR instance, DWORD flags)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		WCHAR target[128] = {};
		if (deviceId == static_cast<UINT>(WAVE_MAPPER)) {
			wcsncpy_s(target, L"默认录音设备（WAVE_MAPPER）", _TRUNCATE);
		} else {
			swprintf_s(target, L"录音设备 #%u", deviceId);
		}
		SetTarget(event, target);
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::MicOpen, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(MMSYSERR_NOTENABLED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return MMSYSERR_NOTENABLED;
		}

		const MMRESULT mr = pOriginalWaveInOpen
			? pOriginalWaveInOpen(handle, deviceId, format, callback, instance, flags)
			: MMSYSERR_NOTENABLED;
		event.Status = static_cast<ULONG>(mr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return mr;
	}

	MMRESULT WINAPI mciSendCommandW_Hook(MCIDEVICEID id, UINT msg, DWORD_PTR flags, DWORD_PTR param)
	{
		// 只有 MCI_OPEN 且打开的是录音设备才报 —— 其它 MCI 命令
		// （放音、CD、MIDI…）与录音无关，直接透传，不进判定。
		if (msg != CG_MCI_OPEN) {
			return pOriginalMciSendCommandW
				? pOriginalMciSendCommandW(id, msg, flags, param)
				: MMSYSERR_NOTENABLED;
		}

		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event = {};
		SetTarget(event, L"MCI 打开录音设备（waveaudio）");
		event.Status = 0;

		const Action action = Evaluate(R3ShieldCore::CameraOp::MicOpen, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(MMSYSERR_NOTENABLED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return MMSYSERR_NOTENABLED;
		}

		const MMRESULT mr = pOriginalMciSendCommandW(id, msg, flags, param);
		event.Status = static_cast<ULONG>(mr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return mr;
	}

	// ==================================================================
	// WASAPI IAudioClient vtable patch（v13）
	// ==================================================================
	//
	// 实机确认（tools/audioprobe.exe vtable）：
	//   vtable 所有者 AUDIOSES.DLL，Initialize = slot 3
	//   签名：HRESULT Initialize(AUDCLNT_SHAREMODE SharedMode, DWORD StreamFlags,
	//                            REFERENCE_TIME hnsBufferDuration,
	//                            REFERENCE_TIME hnsPeriodicity,
	//                            const WAVEFORMATEX* pFormat,
	//                            LPCGUID AudioSessionGuid)
	//   AUDCLNT_STREAMFLAGS_LOOPBACK = 0x00020000 → 环回 = 录系统输出
	//
	// 与 ScheduledTaskGuard 同一个坑：对象是"用到才激活"的，
	// 注入那一刻不存在 → **懒 patch**，由 IMMDevice::Activate / 
	// IAudioClient 首次出现时补刀。
	//
	constexpr int CG_SLOT_IAUDIOCLIENT_INITIALIZE = 3;
	constexpr DWORD CG_AUDCLNT_STREAMFLAGS_LOOPBACK = 0x00020000;

	typedef HRESULT(STDMETHODCALLTYPE* AudioClientInitializePtr)(
		void* self, int shareMode, DWORD streamFlags, LONG64 bufferDuration,
		LONG64 periodicity, const void* format, const void* sessionGuid);

	AudioClientInitializePtr pOriginalAudioInitialize = nullptr;

	// 已 patch 的 vtable 去重表（同 ScheduledTaskGuard 的做法：
	// 同一个接口的 vtable 是模块级共享的，patch 一次就够）。
	constexpr int CG_MAX_PATCHED_VTABLES = 16;
	void* g_patchedAudioVtables[CG_MAX_PATCHED_VTABLES] = {};
	int g_patchedAudioVtableCount = 0;

	bool AlreadyPatchedAudio(void* vtable) noexcept
	{
		for (int i = 0; i < g_patchedAudioVtableCount; i++) {
			if (g_patchedAudioVtables[i] == vtable) {
				return true;
			}
		}
		return false;
	}

	// 从参数里读出采样率等信息，只用于"事件可读性"（失败不影响判定）。
	// ⚠️ 不能有需要析构的对象，否则 __try 编不过。
	void DescribeAudioFormat(const void* format, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch == 0) {
			return;
		}
		out[0] = L'\0';
		if (!format) {
			wcsncpy_s(out, cch, L"(未指定格式)", _TRUNCATE);
			return;
		}

		__try {
			// WAVEFORMATEX：wFormatTag(2) nChannels(2) nSamplesPerSec(4)
			//               nAvgBytesPerSec(4) nBlockAlign(2) wBitsPerSample(2)
			const BYTE* p = static_cast<const BYTE*>(format);
			const USHORT channels = *reinterpret_cast<const USHORT*>(p + 2);
			const ULONG sampleRate = *reinterpret_cast<const ULONG*>(p + 4);
			const USHORT bits = *reinterpret_cast<const USHORT*>(p + 14);
			swprintf_s(out, cch, L"%u 通道 / %lu Hz / %u bit",
				static_cast<unsigned>(channels), sampleRate, static_cast<unsigned>(bits));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			wcsncpy_s(out, cch, L"(格式读取失败)", _TRUNCATE);
		}
	}

	HRESULT STDMETHODCALLTYPE AudioInitialize_Hook(void* self, int shareMode, DWORD streamFlags,
		LONG64 bufferDuration, LONG64 periodicity, const void* format, const void* sessionGuid)
	{
		InterlockedIncrement(&g_activeHooks);

		// ★ 判据就是这一个标志位 —— 环回 = 录系统输出。
		const bool loopback = (streamFlags & CG_AUDCLNT_STREAMFLAGS_LOOPBACK) != 0;
		const R3ShieldCore::CameraOp op = loopback
			? R3ShieldCore::CameraOp::WasapiLoopback
			: R3ShieldCore::CameraOp::WasapiCapture;

		R3ShieldCore::Event event = {};
		WCHAR desc[128] = {};
		DescribeAudioFormat(format, desc, _countof(desc));
		WCHAR target[256] = {};
		swprintf_s(target, loopback
			? L"WASAPI 环回流（录系统输出）%s"
			: L"WASAPI 采集流（麦克风）%s",
			desc);
		SetTarget(event, target);
		event.Status = 0;

		const Action action = Evaluate(op, event, true);
		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(CG_E_ACCESSDENIED);
			Publish(event);
			InterlockedDecrement(&g_activeHooks);
			return CG_E_ACCESSDENIED;
		}

		const HRESULT hr = pOriginalAudioInitialize
			? pOriginalAudioInitialize(self, shareMode, streamFlags, bufferDuration,
				periodicity, format, sessionGuid)
			: CG_E_ACCESSDENIED;
		event.Status = static_cast<ULONG>(hr);
		Publish(event);

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	// 把一个 vtable 的 Initialize 槽换成我们的 detour。**只 patch 一次**。
	bool PatchAudioVtable(void* obj) noexcept
	{
		if (!obj) {
			return false;
		}

		__try {
			void** vtable = *reinterpret_cast<void***>(obj);
			if (!vtable || AlreadyPatchedAudio(vtable)) {
				return g_patchedAudioVtableCount > 0; // 已 patch 视作成功
			}
			if (g_patchedAudioVtableCount >= CG_MAX_PATCHED_VTABLES) {
				return false;
			}

			DWORD oldProtect = 0;
			if (!VirtualProtect(&vtable[CG_SLOT_IAUDIOCLIENT_INITIALIZE], sizeof(void*),
				PAGE_READWRITE, &oldProtect)) {
				LOG(L"CameraGuard: IAudioClient vtable 改保护失败 err=%u", GetLastError());
				return false;
			}

			pOriginalAudioInitialize = reinterpret_cast<AudioClientInitializePtr>(
				vtable[CG_SLOT_IAUDIOCLIENT_INITIALIZE]);
			vtable[CG_SLOT_IAUDIOCLIENT_INITIALIZE] =
				reinterpret_cast<void*>(AudioInitialize_Hook);

			DWORD ignored = 0;
			VirtualProtect(&vtable[CG_SLOT_IAUDIOCLIENT_INITIALIZE], sizeof(void*),
				oldProtect, &ignored);

			g_patchedAudioVtables[g_patchedAudioVtableCount++] = vtable;
			LOG(L"CameraGuard: IAudioClient::Initialize 已 patch（vtable=%p，累计 %d）",
				vtable, g_patchedAudioVtableCount);
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LOG(L"CameraGuard: patch IAudioClient vtable 异常");
			return false;
		}
	}

	// IMMDevice::Activate —— 靶子（返回的 IAudioClient 就是我们要 patch 的）。
	// vtable 在 MMDevApi.dll（实测 slot 3）。
	//
	// ⚠️ 这是"拿到 IAudioClient 的那一刻"最可靠的补刀点：
	//    任何走标准 WASAPI 的进程都要经过它。
	typedef HRESULT(STDMETHODCALLTYPE* IMMDeviceActivatePtr)(
		void* self, const GUID* iid, DWORD clsctx, void* activationParams, void** ppInterface);

	IMMDeviceActivatePtr pOriginalDeviceActivate = nullptr;

	// 判断请求的是不是 IAudioClient（或其派生）。
	// IAudioClient   IID = {1CB9AD4C-DBFA-4c32-B178-C2F568A703B2}
	// IAudioClient2  IID = {726778CD-F60A-4EDA-82DE-E47610CD78AA}
	// IAudioClient3  IID = {7ED4EE07-8E67-4CD4-8C1A-2B7A5987AD42}
	//
	// ⚠️ 派生接口的 vtable **前 15 项与基接口完全相同**（COM 接口继承规则），
	//    所以派生接口的对象同样用 slot 3 —— patch 基 vtable 即可。
	bool IsAudioClientIID(const GUID& iid) noexcept
	{
		static const GUID kAudioClient =
			{ 0x1cb9ad4c, 0xdbfa, 0x4c32, { 0xb1, 0x78, 0xc2, 0xf5, 0x68, 0xa7, 0x03, 0xb2 } };
		static const GUID kAudioClient2 =
			{ 0x726778cd, 0xf60a, 0x4eda, { 0x82, 0xde, 0xe4, 0x76, 0x10, 0xcd, 0x78, 0xaa } };
		static const GUID kAudioClient3 =
			{ 0x7ed4ee07, 0x8e67, 0x4cd4, { 0x8c, 0x1a, 0x2b, 0x7a, 0x59, 0x87, 0xad, 0x42 } };

		return IsEqualGUID(iid, kAudioClient)
			|| IsEqualGUID(iid, kAudioClient2)
			|| IsEqualGUID(iid, kAudioClient3);
	}

	HRESULT STDMETHODCALLTYPE IMMDeviceActivate_Hook(void* self, const GUID* iid, DWORD clsctx,
		void* activationParams, void** ppInterface)
	{
		InterlockedIncrement(&g_activeHooks);

		const HRESULT hr = pOriginalDeviceActivate
			? pOriginalDeviceActivate(self, iid, clsctx, activationParams, ppInterface)
			: CG_E_ACCESSDENIED;

		// ★ 原函数返回后补刀：如果拿到的是 IAudioClient，patch 它的 vtable。
		if (SUCCEEDED(hr) && iid && ppInterface && *ppInterface && IsAudioClientIID(*iid)) {
			PatchAudioVtable(*ppInterface);
		}

		InterlockedDecrement(&g_activeHooks);
		return hr;
	}

	// IMMDevice vtable 的 Activate 槽（实测：slot 3，vtable 在 MMDevApi.dll）。
	constexpr int CG_SLOT_IMMDEVICE_ACTIVATE = 3;

	bool g_imDevicePatched = false;

	// 主动建一个 IMMDeviceEnumerator → GetDefaultAudioEndpoint → IMMDevice，
	// 把 IMMDevice 的 vtable 的 Activate 槽换掉。
	//
	// ⚠️ 为什么这样可以"一次 patch 管全局"：
	//    IMMDevice 是 mmdevapi 里同一个 C++ 类（CMmDevice）的实例，
	//    它们的 vtable 指针指向**同一个只读 vtable 数组**（在 MMDevApi.dll
	//    的 .rdata 里）—— 实测所有 IMMDevice 实例的 vtable 地址相同。
	//    所以改一次这个数组就够，后续任何进程内新建的 IMMDevice 都生效。
	//
	// ⚠️ 副作用：我们自己在被注入进程里 CoCreateInstance 了一个枚举器。
	//    这是只读查询（拿设备列表），不会打开任何流，用户无感。
	//    若机器无声卡/无桌面会话则建不出来 → 静默跳过（不是错误，
	//    bash 会话里跑探针就是这个表现）。
	bool PatchIMMDeviceVtable() noexcept
	{
		if (g_imDevicePatched) {
			return true;
		}

		// ⚠️ 这里不能用需要析构的 C++ 对象跨 __try —— 用一个裸的
		//    RAII 替身：手写释放。整段包 __try 防 COM 内部异常。
		__try {
			// 先确保 COM 可用。若调用方已初始化（多数 GUI 进程会），
			// 这里 CoInitializeEx 会返回 S_FALSE 或 RPC_E_CHANGED_MODE，
			// 都不影响我们继续（我们只是借用一下接口指针）。
			const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
			const bool weInitialized = SUCCEEDED(hrInit);

			if (hrInit == RPC_E_CHANGED_MODE) {
				// 别的线程已用 STA 初始化 —— COM 可用，继续。
			}
			else if (FAILED(hrInit)) {
				// COM 完全不可用。但我们仍可以退一步：直接用已有的
				// mmdevapi 类厂？太复杂。这里直接放弃，靠
				// TryPatchAudioClient 的外部调用兜底。
				LOG(L"CameraGuard: CoInitializeEx 失败 hr=0x%08X，跳过 IMMDevice patch", hrInit);
				return false;
			}

			// CLSID_MMDeviceEnumerator = {BCDE0395-E52F-467C-8E3D-C4579291692E}
			const GUID clsidEnumerator =
				{ 0xbcde0395, 0xe52f, 0x467c, { 0x8e, 0x3d, 0xc4, 0x57, 0x92, 0x91, 0x69, 0x2e } };
			// IID_IMMDeviceEnumerator = {A95664D2-9614-4F35-A746-DE8DB63617E6}
			const GUID iidEnumerator =
				{ 0xa95664d2, 0x9614, 0x4f35, { 0xa7, 0x46, 0xde, 0x8d, 0xb6, 0x36, 0x17, 0xe6 } };
			// IID_IMMDevice = {D666063F-1587-4E43-81F1-B948E807363F}
			const GUID iidDevice =
				{ 0xd666063f, 0x1587, 0x4e43, { 0x81, 0xf1, 0xb9, 0x48, 0xe8, 0x07, 0x36, 0x3f } };

			void* enumerator = nullptr;
			HRESULT hr = CoCreateInstance(clsidEnumerator, nullptr, CLSCTX_ALL,
				iidEnumerator, &enumerator);
			if (FAILED(hr) || !enumerator) {
				LOG(L"CameraGuard: 建 MMDeviceEnumerator 失败 hr=0x%08X", hr);
				if (weInitialized) CoUninitialize();
				return false;
			}

			// vtable[3] = EnumAudioEndpoints, vtable[4] = GetDefaultAudioEndpoint
			void** enumVt = *reinterpret_cast<void***>(enumerator);
			typedef HRESULT(STDMETHODCALLTYPE* GetDefaultEndpointPtr)(
				void*, int flow, int role, void** device);
			auto getDefault = reinterpret_cast<GetDefaultEndpointPtr>(enumVt[4]);

			void* device = nullptr;
			hr = getDefault(enumerator, /*eRender*/ 0, /*eConsole*/ 0, &device);
			if (FAILED(hr) || !device) {
				LOG(L"CameraGuard: GetDefaultAudioEndpoint 失败 hr=0x%08X（可能无声卡）", hr);
				reinterpret_cast<IUnknown*>(enumerator)->Release();
				if (weInitialized) CoUninitialize();
				return false;
			}
			(void)iidDevice;

			// ★ 核心：改 IMMDevice 的 Activate 槽。
			void** devVt = *reinterpret_cast<void***>(device);
			DWORD oldProtect = 0;
			if (VirtualProtect(&devVt[CG_SLOT_IMMDEVICE_ACTIVATE], sizeof(void*),
				PAGE_READWRITE, &oldProtect)) {
				pOriginalDeviceActivate = reinterpret_cast<IMMDeviceActivatePtr>(
					devVt[CG_SLOT_IMMDEVICE_ACTIVATE]);
				devVt[CG_SLOT_IMMDEVICE_ACTIVATE] =
					reinterpret_cast<void*>(IMMDeviceActivate_Hook);

				DWORD ignored = 0;
				VirtualProtect(&devVt[CG_SLOT_IMMDEVICE_ACTIVATE], sizeof(void*),
					oldProtect, &ignored);

				g_imDevicePatched = true;
				g_hookCount++;
				LOG(L"CameraGuard: IMMDevice::Activate 已 patch（vtable=%p → 后续 IAudioClient 全部补刀）",
					devVt);
			}
			else {
				LOG(L"CameraGuard: IMMDevice vtable 改保护失败 err=%u", GetLastError());
			}

			reinterpret_cast<IUnknown*>(device)->Release();
			reinterpret_cast<IUnknown*>(enumerator)->Release();
			if (weInitialized) CoUninitialize();

			return g_imDevicePatched;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			LOG(L"CameraGuard: PatchIMMDeviceVtable 异常");
			return false;
		}
	}
}

namespace CameraGuard
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
				LOG(L"CameraGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
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
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookCamera) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"CameraGuard: hook_camera 未开启，本进程不挂摄像头 hook");
			return true;
		}

		g_bypass = false;

		// ⚠️ 必须先确保目标模块已加载。多数进程启动时既没 import avicap32
		//    也没 import mf/mfplat/mfreadwrite，GetModuleHandle 返回 0，
		//    hook 就挂不上 —— 而等程序自己去 LoadLibrary 时我们已经没机会了。
		//
		//    主动加载的代价：每个被注入进程多映射几个系统 DLL。
		//    avicap32 很小（~50KB）；mf/mfplat/mfreadwrite 大一些，
		//    但 DLL 代码页是全系统共享的，实际物理内存只多一份。
		//    加载失败（受限进程 / 精简系统）就直接跳过，不影响其它 guard。
		HMODULE avicap = LoadLibraryW(L"avicap32.dll");
		HMODULE mf = LoadLibraryW(L"mf.dll");
		HMODULE mfplat = LoadLibraryW(L"mfplat.dll");
		HMODULE mfreadwrite = LoadLibraryW(L"mfreadwrite.dll");

		if (!avicap && !mf && !mfreadwrite) {
			LOG(L"CameraGuard: 三个目标模块都加载失败，本进程不挂摄像头 hook");
			g_installed = true;
			return true;
		}

		// ---- VFW（老接口，很多国产会议软件还在用）----
		if (avicap) {
			QueueHook("avicap32.dll", "capCreateCaptureWindowW",
				reinterpret_cast<LPVOID>(capCreateCaptureWindowW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCapCreateW), true);
			QueueHook("avicap32.dll", "capCreateCaptureWindowA",
				reinterpret_cast<LPVOID>(capCreateCaptureWindowA_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalCapCreateA), false);
		}

		// ---- Media Foundation（现代路径）----
		// 设备源相关三个 API 在 **mf.dll**（转发到 mfcore.dll），
		// 不在 mfplat.dll —— 这一点是 dumpbin 实测确认的。
		if (mf) {
			QueueHook("mf.dll", "MFCreateDeviceSource",
				reinterpret_cast<LPVOID>(MFCreateDeviceSource_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalMFCreateDeviceSource), true);
			QueueHook("mf.dll", "MFCreateDeviceSourceActivate",
				reinterpret_cast<LPVOID>(MFCreateDeviceSourceActivate_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalMFCreateDeviceSourceActivate), false);
			QueueHook("mf.dll", "MFEnumDeviceSources",
				reinterpret_cast<LPVOID>(MFEnumDeviceSources_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalMFEnumDeviceSources), false);
		}
		else {
			LOG(L"CameraGuard: mf.dll 加载失败，Media Foundation 设备源路径未覆盖");
		}

		if (mfreadwrite) {
			QueueHook("mfreadwrite.dll", "MFCreateSourceReaderFromMediaSource",
				reinterpret_cast<LPVOID>(MFCreateSourceReaderFromMediaSource_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalMFCreateSourceReader), true);
		}

		// mfplat 只是 MF 的平台基础层（属性存储、内存缓冲）。
		// 这里不挂它的函数 —— 它的导出没有"打开摄像头"的语义，
		// 挂了只会产生噪音。加载它只是为了确保 MF 栈可用。
		(void)mfplat;

		// ---- v13：音频采集 / 环回 ----
		//
		// ① winmm（waveInOpen / mciSendCommandW）—— 老式录音接口，导出可挂。
		//    实测（tools/apiprobe.exe）：waveInOpen / mciSendCommandW
		//    都在 winmm.dll 直接导出，非转发。
		// ② WASAPI —— 纯 COM，只能 vtable patch，靶子是 IMMDevice::Activate
		//    （在 mmdevapi.dll）。挂它的意义在于：**这是拿到 IAudioClient
		//    的唯一标准路径**，拿到就补刀 patch。
		HMODULE winmm = LoadLibraryW(L"winmm.dll");
		HMODULE mmdevapi = LoadLibraryW(L"mmdevapi.dll");

		if (winmm) {
			QueueHook("winmm.dll", "waveInOpen",
				reinterpret_cast<LPVOID>(waveInOpen_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalWaveInOpen), true);
			QueueHook("winmm.dll", "mciSendCommandW",
				reinterpret_cast<LPVOID>(mciSendCommandW_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalMciSendCommandW), false);
		}
		else {
			LOG(L"CameraGuard: winmm.dll 加载失败，waveIn/MCI 录音路径未覆盖");
		}

		if (mmdevapi) {
			// ⚠️ WASAPI 的对象是"用到才激活"的 COM 对象：
			//    IAudioClient 在注入那一刻并不存在 → 无法提前 patch。
			//
			//    解法（与 v12 ScheduledTaskGuard 同一个思路的强化版）：
			//    **主动把一个 IMMDeviceEnumerator 建出来**，拿到 IMMDevice
			//    的 vtable 就把它的 Activate 槽换掉。IMMDevice 的 vtable
			//    是模块级共享的（实测 vtable 在 MMDevApi.dll 的 .rdata，
			//    所有 IMMDevice 实例共用同一份），所以 patch 一次即全局生效。
			//
			//    之后任何程序 Activate(IAudioClient) 都会走到我们的
			//    IMMDeviceActivate_Hook → 顺手 patch 那个 IAudioClient。
			//
			//    这条链完整覆盖了"标准 WASAPI 路径"。
			//    （UWP 的 ActivateAudioInterfaceAsync 最终也会落到
			//      IMMDevice::Activate 上，不需要单独挂。）
			PatchIMMDeviceVtable();
		}
		else {
			LOG(L"CameraGuard: mmdevapi.dll 加载失败，WASAPI 环回路径未覆盖");
		}

		g_installed = true;

		LOG(L"CameraGuard: 已挂载 %d 个摄像头/音频 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}

	// ------------------------------------------------------------------
	// v13：WASAPI 懒 patch 的对外入口
	// ------------------------------------------------------------------
	//
	// 由别处（例如 future 的 ActivateAudioInterfaceAsync hook、或任何
	// 拿到 IAudioClient 的地方）调用。这里把对象交给内部 PatchAudioVtable。
	bool TryPatchAudioClient(void* pv, const GUID& riid) noexcept
	{
		if (!pv) {
			return false;
		}
		if (!IsAudioClientIID(riid)) {
			return false;
		}
		return PatchAudioVtable(pv);
	}

	int PatchedAudioVtableCount() noexcept
	{
		return g_patchedAudioVtableCount;
	}
}
