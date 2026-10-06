//
// v13probe.cpp - R3ShieldCore v13 新增事件的触发探针 + 自检工具。
//
// 用途（逐个跑，验证 hook 有没有装上、判据有没有生效）：
//   v13probe.exe audio     触发 WASAPI 环回采集（CameraGuard 音频判据）
//   v13probe.exe audiomic  触发 WASAPI 麦克风采集
//   v13probe.exe wavein    触发 waveInOpen（传统波形录音判据）
//   v13probe.exe token     触发令牌窃取链（OpenProcessToken -> DuplicateTokenEx
//                          -> ImpersonateLoggedOnUser -> AdjustTokenPrivileges）
//   v13probe.exe wmi       在 root\subscription 建三件套（Filter/Consumer/Binding）
//                          然后清理
//   v13probe.exe dump      **自检**：打印关键 vtable 的槽位落在哪个模块
//                          （r3shieldcore-lib.dll = patch 成功；原模块 = 没装上）
//   v13probe.exe dbg       dump 的免等待版
//
// 所有模式（除 dbg）先 Sleep(3000) —— 引擎注入 + guard 安装需要时间，
// 太早的话 guard 还没装上，等于什么测不出来。
//
// 用法：先启引擎，再跑本探针。
//
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <mmsystem.h>
#include <wbemidl.h>
#include <comdef.h>
#include <stdio.h>
#include <locale.h>
#include <psapi.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

// ------------------------------------------------------------------
// vtable 槽位辅助（dump 用）
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

// 判断某个地址是否落在 r3shieldcore-lib.dll 里。
//
// ⚠️ 不要用 `strstr(buf, "R3ShieldCoreLib")` 这种字符串比对 ——
//    ModuleOf 写出 buffer 与 strstr 读取 buffer 之间没有序列化保证，
//    -O2 下编译器会认为 buffer 仍是空串，判定永远为 false（探针第二次
//    踩的同一个坑）。这里直接比较**模块基址**，没有字符串/内存可见性问题。
static bool IsInGuardDll(void* address)
{
	static HMODULE s_guard = nullptr;
	static bool s_resolved = false;

	if (!s_resolved) {
		s_resolved = true;

		HMODULE mods[512] = {};
		DWORD needed = 0;
		if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
			const DWORD count = needed / sizeof(HMODULE);
			for (DWORD i = 0; i < count; ++i) {
				char path[MAX_PATH] = {};
				if (!GetModuleFileNameA(mods[i], path, MAX_PATH)) {
					continue;
				}
				char lower[MAX_PATH] = {};
				size_t n = 0;
				for (; path[n] && n + 1 < MAX_PATH; ++n) {
					const char c = path[n];
					lower[n] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
				}
				lower[n] = 0;
				if (strstr(lower, "R3ShieldCoreLib") != nullptr) {
					s_guard = mods[i];
					break;
				}
			}
		}
	}

	if (!s_guard) {
		return false;
	}

	HMODULE owner = nullptr;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(address), &owner)) {
		return false;
	}
	return owner == s_guard;
}

static void ReportSlot(const char* who, void* obj, int slot, const char* what)
{
	if (!obj) {
		printf("  %-22s : (对象为空)\n", who);
		return;
	}
	__try {
		void** vtable = *reinterpret_cast<void***>(obj);
		char buf[128] = {};
		const char* mod = ModuleOf(vtable[slot], buf, sizeof(buf));
		const bool hooked = IsInGuardDll(vtable[slot]);
		printf("  %-22s slot[%2d]=%-24s %s  <- %s\n", who, slot,
			mod, hooked ? "[已拦]" : "[未拦]", what);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("  %-22s : 读 vtable 异常\n", who);
	}
}

// ------------------------------------------------------------------
// 模式：audio
// ------------------------------------------------------------------
static int ModeAudio(bool loopback)
{
	printf("=== 触发 WASAPI %s ===\n", loopback ? "环回采集（系统声音）" : "麦克风采集");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
		printf("CoInitializeEx 失败 hr=0x%08X\n", hr);
		return 1;
	}

	IMMDeviceEnumerator* enumerator = nullptr;
	hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
		__uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(&enumerator));
	if (FAILED(hr)) {
		printf("MMDeviceEnumerator 创建失败 hr=0x%08X（本会话无音频？）\n", hr);
		return 1;
	}

	// 环回 → 渲染端点；采集 → 捕获端点
	const EDataFlow flow = loopback ? eRender : eCapture;
	IMMDevice* device = nullptr;
	hr = enumerator->GetDefaultAudioEndpoint(flow, eConsole, &device);
	if (FAILED(hr) || !device) {
		printf("GetDefaultAudioEndpoint 失败 hr=0x%08X（本会话没有音频设备？）\n", hr);
		enumerator->Release();
		return 1;
	}

	// 这一步会触发 IMMDevice::Activate 的 vtable patch，然后拿到的
	// IAudioClient 的 Initialize 已被我们接管。
	IAudioClient* audioClient = nullptr;
	hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
		reinterpret_cast<void**>(&audioClient));
	if (FAILED(hr) || !audioClient) {
		printf("Activate(IAudioClient) 失败 hr=0x%08X\n", hr);
		device->Release();
		enumerator->Release();
		return 1;
	}

	WAVEFORMATEX* mix = nullptr;
	hr = audioClient->GetMixFormat(&mix);
	if (FAILED(hr) || !mix) {
		printf("GetMixFormat 失败 hr=0x%08X\n", hr);
		audioClient->Release();
		device->Release();
		enumerator->Release();
		return 1;
	}

	// 真正触发判据的调用（环回带 LOOPBACK 标志）。
	hr = audioClient->Initialize(AUDCLNT_SHAREMODE_SHARED,
		loopback ? AUDCLNT_STREAMFLAGS_LOOPBACK : 0,
		10000000, 0, mix, nullptr);
	printf("Initialize(%s) hr=0x%08X %s\n",
		loopback ? "LOOPBACK" : "capture", hr,
		SUCCEEDED(hr) ? "-> 已进入判据，应已采集到一条"
			: "-> 失败（无声卡/设备忙）");

	CoTaskMemFree(mix);
	audioClient->Release();
	device->Release();
	enumerator->Release();
	return 0;
}

// ------------------------------------------------------------------
// 模式：wavein
// ------------------------------------------------------------------
static int ModeWaveIn()
{
	printf("=== 触发 waveInOpen（传统录音）===\n");

	WAVEFORMATEX fmt = {};
	fmt.wFormatTag = WAVE_FORMAT_PCM;
	fmt.nChannels = 1;
	fmt.nSamplesPerSec = 8000;
	fmt.wBitsPerSample = 8;
	fmt.nBlockAlign = fmt.nChannels * fmt.wBitsPerSample / 8;
	fmt.nAvgBytesPerSec = fmt.nSamplesPerSec * fmt.nBlockAlign;

	HWAVEIN handle = nullptr;
	MMRESULT mr = waveInOpen(&handle, WAVE_MAPPER, &fmt, 0, 0, CALLBACK_NULL);
	printf("waveInOpen mr=%u %s\n", mr,
		mr == MMSYSERR_NOERROR ? "-> 成功，应已采集到一条（返回值 0）" : "-> 非 0（无声卡或设备忙）");
	if (mr == MMSYSERR_NOERROR && handle) {
		waveInClose(handle);
	}
	return 0;
}

// ------------------------------------------------------------------
// 模式：token
// ------------------------------------------------------------------
static void ShowSelfPriv(const char* note)
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		printf("  [%s] OpenProcessToken(QUERY) 失败 err=%u\n", note, GetLastError());
		return;
	}
	DWORD len = 0;
	GetTokenInformation(token, TokenElevation, nullptr, 0, &len);
	BYTE buf[64] = {};
	if (GetTokenInformation(token, TokenElevation, buf, sizeof(buf), &len)) {
		auto* elev = reinterpret_cast<TOKEN_ELEVATION*>(buf);
		printf("  [%s] 当前进程是否提权: %s\n", note, elev->TokenIsElevated ? "是" : "否");
	}
	CloseHandle(token);
}

static int ModeToken()
{
	printf("=== 触发令牌窃取链 ===\n");

	ShowSelfPriv("前置");

	// ---- 一档：OpenProcessToken（guard 只改关联状态，不上报）----
	HANDLE processToken = nullptr;
	// 对自己进程开令牌 —— 这是"合法"行为（调试器也调同一个 API），
	// 所以应**不上报**（一档）。这里是要验证"不刷屏"。
	BOOL ok = OpenProcessToken(GetCurrentProcess(),
		TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &processToken);
	printf("[一档] OpenProcessToken(自己) ok=%d err=%u  （预期：不进**事件** —— 一档只记状态）\n",
		ok, ok ? 0 : GetLastError());

	if (!ok || !processToken) {
		printf("该环境对自己开令牌，无法继续后续档位\n");
		return 1;
	}

	// ---- 二档：DuplicateTokenEx（高危）----
	HANDLE dupToken = nullptr;
	ok = DuplicateTokenEx(processToken, TOKEN_QUERY | TOKEN_IMPERSONATE,
		nullptr, SecurityImpersonation, TokenImpersonation, &dupToken);
	printf("[二档] DuplicateTokenEx ok=%d err=%u  （预期：TOKEN HIGH）\n",
		ok, ok ? 0 : GetLastError());

	// ---- 二档：ImpersonateLoggedOnUser（高危）----
	if (dupToken) {
		ok = ImpersonateLoggedOnUser(dupToken);
		printf("[二档] ImpersonateLoggedOnUser ok=%d err=%u  （预期：TOKEN HIGH）\n",
			ok, ok ? 0 : GetLastError());
		if (ok) {
			RevertToSelf();
		}
		CloseHandle(dupToken);
	}

	// ---- 三档：AdjustTokenPrivileges 启用 SeDebugPrivilege（高危）----
	{
		HANDLE adjToken = nullptr;
		if (OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &adjToken)) {
			LUID luid = {};
			if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
				TOKEN_PRIVILEGES tp = {};
				tp.PrivilegeCount = 1;
				tp.Privileges[0].Luid = luid;
				tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				BOOL r = AdjustTokenPrivileges(adjToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
				printf("[三档] AdjustTokenPrivileges(启用 SeDebug) ok=%d err=%u  （预期：TOKEN HIGH）\n",
					r, GetLastError());
			}
			else {
				printf("[三档] LookupPrivilegeValueW(SeDebug) 失败 err=%u\n", GetLastError());
			}
			CloseHandle(adjToken);
		}
	}

	CloseHandle(processToken);
	return 0;
}

// ------------------------------------------------------------------
// 模式：wmi
// ------------------------------------------------------------------
static int ModeWmi(bool cleanupOnly)
{
	printf("=== WMI 事件订阅三件套 ===\n");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
		printf("CoInitializeEx 失败 hr=0x%08X\n", hr);
		return 1;
	}
	CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);

	IWbemLocator* locator = nullptr;
	hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, reinterpret_cast<void**>(&locator));
	if (FAILED(hr)) {
		printf("IWbemLocator 创建失败 hr=0x%08X\n", hr);
		return 1;
	}

	BSTR ns = SysAllocString(L"ROOT\\SUBSCRIPTION");
	ReportSlot("IWbemLocator", locator, 3, "ConnectServer 前（本进程实测）");
	IWbemServices* services = nullptr;
	hr = locator->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services);
	printf("ConnectServer(root\\subscription) hr=0x%08X\n", hr);
	if (FAILED(hr) || !services) {
		SysFreeString(ns);
		locator->Release();
		return 1;
	}
	ReportSlot("IWbemServices", services, 7, "PutInstance 前（本进程实测）");

	// ★ 必须用**原始 vtable 调用**来触发 PutInstance。
	//
	//   为什么：`IWbemServices` 在 wbemidl.h 里是 `__RPC__` 接口，MSVC 会把
	//   `services->PutInstance(...)` 变成 RPC/stub 包装调用，**不**经过
	//   vtable[7]。实测：走 C++ 语法时返回的是原函数结果（0x80041003）、
	//   hook 一点反应都没有；改成本文件里的 raw 调用后立刻进 hook，且
	//   BLOCK 模式下返回我们的 E_ACCESSDENIED(0x80070005)。
	//   真实的攻击者（脚本宿主 / COM 客户端 / 直调 vtable）走的就是 raw 路径 ——
	//   所以 raw 才是"真实行为"的忠实模拟。
	auto rawPutInstance = [](IWbemServices* svc, IWbemClassObject* inst) -> HRESULT {
		typedef HRESULT(STDMETHODCALLTYPE* RawPutInstance)(
			void*, void*, LONG, void*, void**);
		void** vt = *reinterpret_cast<void***>(svc);
		RawPutInstance raw = reinterpret_cast<RawPutInstance>(vt[7]);
		return raw(svc, inst, WBEM_FLAG_CREATE_OR_UPDATE, nullptr, nullptr);
	};
	printf("  [diag] vtable slot7=%p（raw 调用点）\n", (*reinterpret_cast<void***>(services))[7]);

	const WCHAR* kFilterName = L"R3ShieldCoreV13ProbeFilter";
	const WCHAR* kConsumerName = L"R3ShieldCoreV13ProbeConsumer";
	const WCHAR* kFilterPath = L"__EventFilter.Name=\"R3ShieldCoreV13ProbeFilter\"";
	const WCHAR* kConsumerPath = L"CommandLineEventConsumer.Name=\"R3ShieldCoreV13ProbeConsumer\"";

	auto deleteInstance = [&](const WCHAR* cls, const WCHAR* path) {
		BSTR c = SysAllocString(cls);
		BSTR p = SysAllocString(path);
		HRESULT d = services->DeleteInstance(p, 0, nullptr, nullptr);
		printf("  清理 %ls -> hr=0x%08X\n", path, d);
		SysFreeString(c);
		SysFreeString(p);
	};

	if (cleanupOnly) {
		deleteInstance(L"__EventFilter", kFilterPath);
		deleteInstance(L"CommandLineEventConsumer", kConsumerPath);
		deleteInstance(L"__FilterToConsumerBinding",
			L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"R3ShieldCoreV13ProbeFilter\\\"\"");
		services->Release();
		SysFreeString(ns);
		locator->Release();
		return 0;
	}

	// 先清一次（幂等）
	deleteInstance(L"__EventFilter", kFilterPath);
	deleteInstance(L"CommandLineEventConsumer", kConsumerPath);

	// ---- ① 建 __EventFilter ----
	{
		BSTR cls = SysAllocString(L"__EventFilter");
		IWbemClassObject* classObj = nullptr;
		hr = services->GetObject(cls, 0, nullptr, &classObj, nullptr);
		if (SUCCEEDED(hr) && classObj) {
			IWbemClassObject* inst = nullptr;
			if (SUCCEEDED(classObj->SpawnInstance(0, &inst)) && inst) {
				VARIANT v; VariantInit(&v);
				v.vt = VT_BSTR; v.bstrVal = SysAllocString(kFilterName);
				inst->Put(L"Name", 0, &v, 0);
				VariantClear(&v);

				VariantInit(&v);
				v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'");
				inst->Put(L"Query", 0, &v, 0);
				VariantClear(&v);

				VariantInit(&v);
				v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"WQL");
				inst->Put(L"QueryLanguage", 0, &v, 0);
				VariantClear(&v);

				VariantInit(&v);
				v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"root\\cimv2");
				inst->Put(L"EventNamespace", 0, &v, 0);
				VariantClear(&v);

				hr = rawPutInstance(services, inst);
				printf("① PutInstance(__EventFilter) hr=0x%08X  （预期：WMI HIGH class=__EventFilter）\n", hr);
				inst->Release();
			}
			classObj->Release();
		}
		else {
			printf("① GetObject(__EventFilter) 失败 hr=0x%08X\n", hr);
		}
		SysFreeString(cls);
	}

	// ---- ② 建 CommandLineEventConsumer ----
	{
		BSTR cls = SysAllocString(L"CommandLineEventConsumer");
		IWbemClassObject* classObj = nullptr;
		hr = services->GetObject(cls, 0, nullptr, &classObj, nullptr);
		if (SUCCEEDED(hr) && classObj) {
			IWbemClassObject* inst = nullptr;
			if (SUCCEEDED(classObj->SpawnInstance(0, &inst)) && inst) {
				VARIANT v; VariantInit(&v);
				v.vt = VT_BSTR; v.bstrVal = SysAllocString(kConsumerName);
				inst->Put(L"Name", 0, &v, 0);
				VariantClear(&v);

				VariantInit(&v);
				// 无害动作：只是 echo 到临时文件（不真执行恶意行为）
				v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"cmd.exe /c echo R3ShieldCoreV13Probe > %TEMP%\\rg_v13_probe.txt");
				inst->Put(L"CommandLineTemplate", 0, &v, 0);
				VariantClear(&v);

				hr = rawPutInstance(services, inst);
				printf("② PutInstance(CommandLineEventConsumer) hr=0x%08X  （预期：WMI HIGH + fileless）\n", hr);
				inst->Release();
			}
			classObj->Release();
		}
		else {
			printf("② GetObject(CommandLineEventConsumer) 失败 hr=0x%08X\n", hr);
		}
		SysFreeString(cls);
	}

	// ---- ③ 建 __FilterToConsumerBinding ----
	{
		BSTR cls = SysAllocString(L"__FilterToConsumerBinding");
		IWbemClassObject* classObj = nullptr;
		hr = services->GetObject(cls, 0, nullptr, &classObj, nullptr);
		if (SUCCEEDED(hr) && classObj) {
			IWbemClassObject* inst = nullptr;
			if (SUCCEEDED(classObj->SpawnInstance(0, &inst)) && inst) {
				VARIANT v; VariantInit(&v);
				v.vt = VT_BSTR;
				v.bstrVal = SysAllocString(L"__EventFilter.Name=\"R3ShieldCoreV13ProbeFilter\"");
				inst->Put(L"Filter", 0, &v, 0);
				VariantClear(&v);

				VariantInit(&v);
				v.vt = VT_BSTR;
				v.bstrVal = SysAllocString(L"CommandLineEventConsumer.Name=\"R3ShieldCoreV13ProbeConsumer\"");
				inst->Put(L"Consumer", 0, &v, 0);
				VariantClear(&v);

				hr = rawPutInstance(services, inst);
				printf("③ PutInstance(__FilterToConsumerBinding) hr=0x%08X  （预期：WMI HIGH binding）\n", hr);
				inst->Release();
			}
			classObj->Release();
		}
		else {
			printf("③ GetObject(__FilterToConsumerBinding) 失败 hr=0x%08X\n", hr);
		}
		SysFreeString(cls);
	}

	// ---- 清理（探针不留痕）----
	printf("\n--- 清理 ---\n");
	deleteInstance(L"__FilterToConsumerBinding",
		L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"R3ShieldCoreV13ProbeFilter\\\"\"");
	deleteInstance(L"CommandLineEventConsumer", kConsumerPath);
	deleteInstance(L"__EventFilter", kFilterPath);

	services->Release();
	SysFreeString(ns);
	locator->Release();
	return 0;
}

// ------------------------------------------------------------------
// 模式：dump（自检）
// ------------------------------------------------------------------
static int ModeDump()
{
	printf("=== v13 自检：vtable 槽位归属 ===\n");
	printf("（r3shieldcore-lib.dll = 已拦截；原模块 = 未拦截）\n\n");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
		printf("CoInitializeEx 失败 hr=0x%08X\n", hr);
		return 1;
	}

	// --- IMMDevice::Activate / IAudioClient::Initialize ---
	IMMDeviceEnumerator* enumerator = nullptr;
	if (SUCCEEDED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
		__uuidof(IMMDeviceEnumerator), reinterpret_cast<void**>(&enumerator))) && enumerator) {
		ReportSlot("IMMDeviceEnumerator", enumerator, 4, "GetDefaultAudioEndpoint（对照）");

		IMMDevice* device = nullptr;
		if (SUCCEEDED(enumerator->GetDefaultAudioEndpoint(eRender, eConsole, &device)) && device) {
			ReportSlot("IMMDevice", device, 3, "Activate ★ 应已 patch");

			IAudioClient* audio = nullptr;
			if (SUCCEEDED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
				reinterpret_cast<void**>(&audio))) && audio) {
				ReportSlot("IAudioClient", audio, 3, "Initialize ★ 应已 patch");
				audio->Release();
			}
			else {
				printf("  IAudioClient 激活失败（无声卡？）\n");
			}
			device->Release();
		}
		else {
			printf("  无默认渲染设备（本会话无音频）\n");
		}
		enumerator->Release();
	}
	else {
		printf("  MMDeviceEnumerator 创建失败\n");
	}

	// --- IWbemLocator::ConnectServer / IWbemServices 三个槽 ---
	IWbemLocator* locator = nullptr;
	if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, reinterpret_cast<void**>(&locator))) && locator) {
		ReportSlot("IWbemLocator", locator, 3, "ConnectServer ★ 应已 patch");

		CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
			RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
		BSTR ns = SysAllocString(L"ROOT\\SUBSCRIPTION");
		IWbemServices* services = nullptr;
		if (SUCCEEDED(locator->ConnectServer(ns, nullptr, nullptr, nullptr, 0,
			nullptr, nullptr, &services)) && services) {
			ReportSlot("IWbemServices", services, 7, "PutInstance ★ 应已 patch");
			ReportSlot("IWbemServices", services, 15, "ExecNotificationQuery ★ 应已 patch");
			ReportSlot("IWbemServices", services, 17, "ExecMethod ★ 应已 patch");
			services->Release();
		}
		else {
			printf("  ConnectServer(root\\subscription) 失败\n");
		}
		SysFreeString(ns);
		locator->Release();
	}
	else {
		printf("  IWbemLocator 创建失败\n");
	}

	return 0;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	// 关掉 stdout 缓冲 —— 探针如果在某个 hook 里崩了，
	// 全缓冲会把崩之前的输出全丢掉，现场就没了。
	setvbuf(stdout, nullptr, _IONBF, 0);

	const char* mode = (argc > 1) ? argv[1] : "dump";
	// dump 也要等注入 —— 否则会说"还没注入"，音频/wmi 全显示未拦截。
	const bool noWait = (strcmp(mode, "dbg") == 0);

	printf("R3ShieldCore v13 探针  (pid=%u)  mode=%s\n", GetCurrentProcessId(), mode);

	if (!noWait) {
		printf("[v13probe] 等待 3s 让引擎完成注入与 guard 安装...\n");
		Sleep(3000);
	}
	printf("\n");

	int rc = 0;
	if (strcmp(mode, "audio") == 0) {
		rc = ModeAudio(true);          // 默认测环回（更危险的采集面）
	}
	else if (strcmp(mode, "audiomic") == 0) {
		rc = ModeAudio(false);         // 麦克风采集
	}
	else if (strcmp(mode, "wavein") == 0) {
		rc = ModeWaveIn();
	}
	else if (strcmp(mode, "token") == 0) {
		rc = ModeToken();
	}
	else if (strcmp(mode, "wmi") == 0) {
		rc = ModeWmi(false);
	}
	else if (strcmp(mode, "wmirm") == 0) {
		rc = ModeWmi(true);
	}
	else if (strcmp(mode, "dump") == 0) {
		rc = ModeDump();
	}
	else {
		printf("未知模式，可用：audio / audiomic / wavein / token / wmi / wmirm / dump\n");
		rc = 1;
	}

	printf("\ndone\n");
	return rc;
}
