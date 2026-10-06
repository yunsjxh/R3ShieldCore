//
// audioprobe.cpp - 实测 WASAPI / 音频采集接口的真实形态。
//
// 为什么必须实测而不是查文档：
//   1. **vtable 槽位号**必须数准 —— IAudioClient 有多个版本（IAudioClient /
//      IAudioClient2 / IAudioClient3），Initialize 在基接口里的槽位与
//      派生接口不同。槽位数错一位 = patch 到别的函数 = 静默失效
//      （v12 计划任务那次就是这么栽的）。
//   2. **AUDCLNT_STREAMFLAGS_LOOPBACK 到底传在哪个参数上** —— 文档说在
//      Initialize 的第 5 个参数 StreamFlags，实测确认。
//   3. waveInOpen 的参数布局（回调 / 设备 ID）要确认，判据里要看设备类型。
//
// 用法：
//   audioprobe.exe vtable   —— 打印 IAudioClient / IMMDeviceEnumerator 的 vtable
//                              每个槽位落在哪个模块（定位 Initialize / GetDefaultAudioEndpoint）
//   audioprobe.exe wavein    —— 实调 waveInOpen（只打开不采集，立即关闭）
//   audioprobe.exe loopback  —— 实建一个环回 IAudioClient 并调 Initialize，
//                              用 AUDCLNT_STREAMFLAGS_LOOPBACK 验证参数位置
//   audioprobe.exe all       —— 全跑
//
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <mmsystem.h>
#include <stdio.h>
#include <locale.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "winmm.lib")

// ------------------------------------------------------------------
// 工具：打印一个 vtable 的各个槽位落在哪个模块
// ------------------------------------------------------------------
static const char* ModuleOf(void* address, char* buffer, size_t cch)
{
	HMODULE owner = nullptr;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(address), &owner)) {
		return "(未知)";
	}
	char path[MAX_PATH] = {};
	GetModuleFileNameA(owner, path, MAX_PATH);
	const char* slash = strrchr(path, '\\');
	const char* name = slash ? slash + 1 : path;
	strncpy_s(buffer, cch, name, _TRUNCATE);
	return buffer;
}

static void DumpVtable(const char* who, void* obj, int count)
{
	if (!obj) {
		printf("  %s: (null)\n", who);
		return;
	}
	__try {
		void** vtable = *reinterpret_cast<void***>(obj);
		printf("  %s  vtable=%p\n", who, (void*)vtable);
		for (int i = 0; i < count; i++) {
			char buf[128] = {};
			void* fn = vtable[i];
			printf("    slot[%2d] %p  %s\n", i, fn, ModuleOf(fn, buf, sizeof(buf)));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("  %s: 读 vtable 异常\n", who);
	}
}

// ------------------------------------------------------------------
// 1. vtable 探测
// ------------------------------------------------------------------
static void ProbeVtable()
{
	printf("=== 1. WASAPI 接口 vtable ===\n");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	const bool needUninit = SUCCEEDED(hr);
	if (hr == RPC_E_CHANGED_MODE) hr = S_OK;

	IMMDeviceEnumerator* enumerator = nullptr;
	hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
		__uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(&enumerator));
	if (FAILED(hr) || !enumerator) {
		printf("  CoCreateInstance(MMDeviceEnumerator) 失败 hr=0x%08X\n", hr);
		printf("  （本会话可能没有音频设备 —— 这是环境问题，不是探针问题）\n");
		if (needUninit) CoUninitialize();
		return;
	}

	// IMMDeviceEnumerator vtable 顺序（IUnknown 3 槽 + 自身 5 槽）：
	//   0 QI 1 AddRef 2 Release
	//   3 EnumAudioEndpoints  4 GetDefaultAudioEndpoint  5 GetDevice
	//   6 RegisterEndpointNotificationCallback  7 UnregisterEndpointNotificationCallback
	printf("\n  [IMMDeviceEnumerator]\n");
	DumpVtable("IMMDeviceEnumerator", enumerator, 8);

	IMMDevice* device = nullptr;
	hr = enumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device);
	if (FAILED(hr) || !device) {
		printf("  没有默认渲染设备（无声卡 / 无桌面会话）hr=0x%08X\n", hr);
		enumerator->Release();
		if (needUninit) CoUninitialize();
		return;
	}

	// IMMDevice vtable：0 QI 1 AddRef 2 Release 3 Activate 4 OpenPropertyStore
	//                  5 GetId 6 GetState
	printf("\n  [IMMDevice]  （Activate 在 slot 3）\n");
	DumpVtable("IMMDevice", device, 7);

	// 激活 IAudioClient —— 关键：环回采集就是拿这个接口后 Initialize
	IAudioClient* audioClient = nullptr;
	hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
		reinterpret_cast<void**>(&audioClient));
	if (FAILED(hr) || !audioClient) {
		printf("  Activate(IAudioClient) 失败 hr=0x%08X\n", hr);
		device->Release();
		enumerator->Release();
		if (needUninit) CoUninitialize();
		return;
	}

	// IAudioClient vtable（IUnknown 3 槽 + 自身 9 槽 = 12）：
	//   0 QI 1 AddRef 2 Release
	//   3 Initialize             ← ★ 环回标志就在这里
	//   4 GetBufferSize
	//   5 GetStreamLatency
	//   6 GetCurrentPadding
	//   7 IsFormatSupported
	//   8 GetMixFormat
	//   9 GetDevicePeriod
	//   10 Start
	//   11 Stop
	//   12 Reset
	//   13 SetEventHandle
	//   14 GetService
	//  ⚠️ 实测数清楚，别信文档（不同 SDK 版本可能有出入）。
	printf("\n  [IAudioClient]  ★ Initialize 应当落在 slot 3\n");
	DumpVtable("IAudioClient", audioClient, 15);

	audioClient->Release();
	device->Release();
	enumerator->Release();
	if (needUninit) CoUninitialize();
}

// ------------------------------------------------------------------
// 2. waveInOpen（老式波形录音）
// ------------------------------------------------------------------
static void ProbeWaveIn()
{
	printf("\n=== 2. waveInOpen（老式波形录音）===\n");

	WAVEFORMATEX fmt = {};
	fmt.wFormatTag = WAVE_FORMAT_PCM;
	fmt.nChannels = 1;
	fmt.nSamplesPerSec = 8000;
	fmt.wBitsPerSample = 8;
	fmt.nBlockAlign = fmt.nChannels * fmt.wBitsPerSample / 8;
	fmt.nAvgBytesPerSec = fmt.nSamplesPerSec * fmt.nBlockAlign;

	HWAVEIN handle = nullptr;
	// WAVE_MAPPER 让系统挑默认输入设备。CALLBACK_NULL 表示不用回调。
	MMRESULT mr = waveInOpen(&handle, WAVE_MAPPER, &fmt, 0, 0, CALLBACK_NULL);
	printf("  waveInOpen(WAVE_MAPPER) mr=%u %s\n", mr,
		mr == MMSYSERR_NOERROR ? "OK" : "(无录音设备或已被占用，环境问题)");

	if (mr == MMSYSERR_NOERROR && handle) {
		waveInClose(handle);
		printf("  已关闭（只验证接口可达，不实际采集）\n");
	}

	// 再试设备 0
	mr = waveInOpen(&handle, 0, &fmt, 0, 0, CALLBACK_NULL);
	printf("  waveInOpen(device 0)    mr=%u %s\n", mr,
		mr == MMSYSERR_NOERROR ? "OK" : "(同上)");
	if (mr == MMSYSERR_NOERROR && handle) {
		waveInClose(handle);
	}
}

// ------------------------------------------------------------------
// 3. 环回 Initialize 实测（★ 确认 AUDCLNT_STREAMFLAGS_LOOPBACK 的作用位置）
// ------------------------------------------------------------------
static void ProbeLoopback()
{
	printf("\n=== 3. 环回 Initialize 实测 ===\n");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	const bool needUninit = SUCCEEDED(hr);
	if (hr == RPC_E_CHANGED_MODE) hr = S_OK;

	IMMDeviceEnumerator* enumerator = nullptr;
	hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
		__uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(&enumerator));
	if (FAILED(hr) || !enumerator) {
		printf("  枚举器创建失败 hr=0x%08X（无音频设备）\n", hr);
		if (needUninit) CoUninitialize();
		return;
	}

	// 环回采集的是**渲染设备**（eRender），不是捕获设备 —— 这是关键：
	// 录系统输出 = 从渲染端点拿数据。
	IMMDevice* device = nullptr;
	hr = enumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device);
	if (FAILED(hr) || !device) {
		printf("  无渲染端点 hr=0x%08X\n", hr);
		enumerator->Release();
		if (needUninit) CoUninitialize();
		return;
	}

	IAudioClient* audioClient = nullptr;
	hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
		reinterpret_cast<void**>(&audioClient));
	if (FAILED(hr) || !audioClient) {
		printf("  Activate 失败 hr=0x%08X\n", hr);
		device->Release();
		enumerator->Release();
		if (needUninit) CoUninitialize();
		return;
	}

	WAVEFORMATEX* mix = nullptr;
	hr = audioClient->GetMixFormat(&mix);
	if (FAILED(hr) || !mix) {
		printf("  GetMixFormat 失败 hr=0x%08X\n", hr);
		audioClient->Release();
		device->Release();
		enumerator->Release();
		if (needUninit) CoUninitialize();
		return;
	}
	printf("  混音格式: %u ch, %u Hz, %u bit\n", mix->nChannels,
		mix->nSamplesPerSec, mix->wBitsPerSample);

	// ★ 核心：带 AUDCLNT_STREAMFLAGS_LOOPBACK 的 Initialize
	//   （第 5 个参数 StreamFlags 传 LOOPBACK）
	hr = audioClient->Initialize(
		AUDCLNT_SHAREMODE_SHARED,
		AUDCLNT_STREAMFLAGS_LOOPBACK,
		10000000,   // 1 秒缓冲
		0, mix, nullptr);
	printf("  Initialize(SHARED, LOOPBACK) hr=0x%08X %s\n", hr,
		SUCCEEDED(hr) ? "← 环回可用（成功建立环回流）" : "（失败，可能无声卡）");

	if (SUCCEEDED(hr)) {
		// 不 Start，直接销毁 —— 只验证"环回 Initialize 能成功"这一事实。
		printf("  环流已建立，未 Start（只验证参数语义）\n");
	}

	CoTaskMemFree(mix);
	audioClient->Release();
	device->Release();
	enumerator->Release();
	if (needUninit) CoUninitialize();
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	const char* mode = (argc > 1) ? argv[1] : "all";
	printf("R3ShieldCore 音频采集探针  (pid=%u)  mode=%s\n\n", GetCurrentProcessId(), mode);

	if (strcmp(mode, "vtable") == 0 || strcmp(mode, "all") == 0) ProbeVtable();
	if (strcmp(mode, "wavein") == 0 || strcmp(mode, "all") == 0) ProbeWaveIn();
	if (strcmp(mode, "loopback") == 0 || strcmp(mode, "all") == 0) ProbeLoopback();

	printf("\ndone\n");
	return 0;
}
