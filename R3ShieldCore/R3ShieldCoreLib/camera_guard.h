#pragma once

//
// 摄像头 / 麦克风 / 音频环回访问监控层。
//
// ⚠️ 先读这段，免得误以为这是"摄像头锁"：
//
//   这里挂的是**用户态**入口，分两族：
//
//   一、视频 / 通用 MF（v6 起）
//     ① avicap32!capCreateCaptureWindowA/W —— VFW 老接口
//     ② mf!MFCreateDeviceSource / MFEnumDeviceSources
//        + mfreadwrite!MFCreateSourceReaderFromMediaSource —— Media Foundation
//
//   二、音频（v13 新增）
//     ③ winmm!waveInOpen / waveInPrepareHeader / mciSendCommandW —— 老式波形录音
//     ④ WASAPI：IAudioClient::Initialize —— 纯 COM 虚函数，**只能 vtable patch**
//        （实机确认：vtable 在 AUDIOSES.DLL，Initialize 是 slot 3；
//          AUDCLNT_STREAMFLAGS_LOOPBACK 在第 5 个参数上 → 环回 = 录系统输出）
//
//   绕过它很容易：
//     - DirectShow：CoCreateInstance(CLSID_VideoInputDeviceCategory) 之后
//       全是 COM 虚函数调用，没有任何可 hook 的导出
//     - 自带驱动直连内核流（ks.sys / \Device\Video* / \Device\Audio*）
//     - 用 Windows.Media.Capture（WinRT）—— 内部也是 MF，但走的是
//       另一条 CoCreateInstance 路径，未必经过 MFCreateDeviceSource
//     - 直调 WASAPI 底层（audioses 内部对象）绕过我们的 vtable patch
//     - 32 位宿主里加载的可能是 SysWOW64 的另一份 DLL（我们会分别挂，
//       但 WOW64 进程的注入本身就是另一套逻辑）
//
//   所以定位是 **可见性**：回答"这台机器上有程序在用摄像头/麦克风/在录系统声音吗"，
//   而不是"保证设备打不开"。真正的执法要么在内核（KS 过滤驱动），
//   要么靠 Windows 自带的隐私开关（CapabilityAccessManager）。
//
// 判据：
//   · 视频 / MF 设备源：**打开就报**（OpenDevice / CreateDeviceSource /
//     CreateSourceReader 一律高危），枚举设备只记录。
//   · 音频：麦克风采集（WasapiCapture / MicOpen）高危；**环回
//     （WasapiLoopback）高危** —— 录系统输出 = 录通话/会议，意图最明确。
//   理由：都是隐私设备，正常软件开它时用户应该在场，宁可多问一次
//   —— 用户信任某个程序就点「始终允许」。
//
namespace CameraGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	//
	// 收尾：等所有"在飞"的 hook 跑完。
	//
	// 与其它 guard 同理，必须先把 hook 停用再调这个，
	// 然后才能 MH_Uninitialize()。见 registry_guard.h 的详细说明。
	//
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;

	//
	// 音频侧的懒 patch（v13）。
	//
	// ⚠️ 与 ScheduledTaskGuard 同一个坑：WASAPI 的 IAudioClient 是
	//    "用到才激活"的 COM 对象 —— 注入那一刻它还不存在，无法提前 patch。
	//    所以在拿到 IAudioClient 指针的那一刻（IMMDevice::Activate 返回后）
	//    补刀。
	//
	// 返回 true 表示这次确实 patch 上了（或已 patch 过）。
	// pv 为 IAudioClient*，riid 为激活时请求的接口 IID。
	//
	bool TryPatchAudioClient(void* pv, const GUID& riid) noexcept;

	// 已 patch 过的 IAudioClient vtable 数量（供自检 / 日志）。
	int PatchedAudioVtableCount() noexcept;
}
