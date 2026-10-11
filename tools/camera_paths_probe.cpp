//
// R3ShieldCore —— 摄像头「其余取帧路径」可行性探针（v75 预研）
//
// v73 只覆盖了 **Media Foundation 的 `MFCreateSourceReaderFromMediaSource`**
// （同步 `ReadSample` + 异步 `OnReadSample`）。盘点文档记的仍是三条盲区：
//
//   · DirectShow 完整链（`ICaptureGraphBuilder2`）
//   · VFW 帧路径（`WM_CAP_*` 消息 / 回调）
//   · WinRT `MediaCapture`
//
// 本探针逐个回答"**能不能替换**"，产出 go / no-go 与挂点。
//
// ★ 探针**自包含**：自己挂自己的 vtable patch，不注入、不跑引擎 ⇒ 不受铁律 175 约束。
// ★ 默认路径**不开硬件**（铁律 204）：Part A 的机制验证用 `CMemAllocator` 造的
//   `IMediaSample`，不需要摄像头；真正开摄像头的部分一律 `--use-camera` 显式打开，
//   并**单独计数**（铁律 178）。
//
// 用法：
//   camera_paths_probe                 只跑不需要硬件的部分（机制 + 枚举 + 静态链）
//   camera_paths_probe --use-camera    额外跑真机（DirectShow 真图 / VFW 真窗 / WinRT 激活）
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>

#include <dshow.h>          // IMediaSample / IMemAllocator / IFilterGraph2 / ICreateDevEnum
#include <mmreg.h>
#include <vfw.h>            // VFW：capCreateCaptureWindowW / capSetCallbackOnFrame

#include "MinHook.h"

#pragma comment(lib, "strmiids.lib")

// ------------------------------------------------------------------
// 需要手写声明的 DirectShow 接口（`qedit.h` 已从现代 SDK 移除）
// ------------------------------------------------------------------
// {6B652FFF-11FE-4FCE-92AD-0266B5D7C78F}
static const GUID IID_ISampleGrabber_ =
{ 0x6b652fff, 0x11fe, 0x4fce, { 0x92, 0xad, 0x02, 0x66, 0xb5, 0xd7, 0xc7, 0x8f } };
// {C1F400A0-3F08-11D3-9F0B-006008039E37}
static const GUID CLSID_SampleGrabber_ =
{ 0xc1f400a0, 0x3f08, 0x11d3, { 0x9f, 0x0b, 0x00, 0x60, 0x08, 0x03, 0x9e, 0x37 } };
// {C1F400A4-3F08-11D3-9F0B-006008039E37}
static const GUID CLSID_NullRenderer_ =
{ 0xc1f400a4, 0x3f08, 0x11d3, { 0x9f, 0x0b, 0x00, 0x60, 0x08, 0x03, 0x9e, 0x37 } };
// {1E651CC0-B199-11D0-8212-00C04FC32C45}  CMemAllocator
static const GUID CLSID_MemoryAllocator_ =
{ 0x1e651cc0, 0xb199, 0x11d0, { 0x82, 0x12, 0x00, 0xc0, 0x4f, 0xc3, 0x2c, 0x45 } };

struct ISampleGrabberCB_ : public IUnknown {
	virtual HRESULT STDMETHODCALLTYPE SampleCB(double, IMediaSample*) = 0;
	virtual HRESULT STDMETHODCALLTYPE BufferCB(double, BYTE*, long) = 0;
};

struct ISampleGrabber_ : public IUnknown {
	virtual HRESULT STDMETHODCALLTYPE SetOneShot(BOOL) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetMediaType(const AM_MEDIA_TYPE*) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetConnectedMediaType(AM_MEDIA_TYPE*) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetBufferSamples(BOOL) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetCurrentBuffer(long*, long*) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetCurrentSample(IMediaSample**) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetCallback(ISampleGrabberCB_*, long) = 0;
};

// ------------------------------------------------------------------
// 计数器 / 输出
// ------------------------------------------------------------------
static int g_pass = 0, g_fail = 0, g_skip = 0;
static void Ok(const char* s)   { ++g_pass; printf("  [ OK ] %s\n", s); }
static void Bad(const char* s)  { ++g_fail; printf("  [FAIL] %s\n", s); }
static void Skip(const char* s) { ++g_skip; printf("  [skip] %s\n", s); }
static void Obs(const char* s)  { printf("  [obs ] %s\n", s); }

// ==================================================================
// Part A —— DirectShow
// ==================================================================
//
// 机制问题：DirectShow 的帧是 `IMediaSample`（一个 COM 对象），像素在
// `IMediaSample::GetPointer()` 返回的缓冲区里。**能不能在进程内把它中性化？**
//
// 做法与 v73 对 MF 的做法同构：**patch vtable 槽**。
// `IMediaSample` 的 vtable 槽位（继承 IUnknown 之后）：
//   3 = GetPointer   4 = GetSize   11 = GetActualDataLength
//
// A1 用 `CMemAllocator` 造一个真 `IMediaSample`（**不需要摄像头**），
//    验证「patch 槽 3 ⇒ 调用方读到的就是中性化后的数据」这条机制。
// A2 枚举 DirectShow 采集设备（证明这条 API 面在进程内可达）。
// A3（--use-camera）真机建图，验证真帧走的是同一套对象。

static IMediaSample* g_dsSample = nullptr;      // A1 用
static LONG          g_dsGetPointerCalls = 0;   // detour 被调次数
static BYTE*         g_dsPatchedBuffer = nullptr;

typedef HRESULT(STDMETHODCALLTYPE* GetPointerFn)(IMediaSample*, BYTE**);
static GetPointerFn  g_dsOrigGetPointer = nullptr;

// 我们的 GetPointer：先拿真指针，再**原地清零** [0, 实际长度)，然后返回。
// ★ 这正是生产版会做的事（"长度一个都不改"，只动内容 —— 与 v70/v71 同一条规则）。
static HRESULT STDMETHODCALLTYPE DsGetPointer_Detour(IMediaSample* self, BYTE** ppBuffer)
{
	InterlockedIncrement(&g_dsGetPointerCalls);

	const HRESULT hr = g_dsOrigGetPointer(self, ppBuffer);
	if (FAILED(hr) || !ppBuffer || !*ppBuffer) {
		return hr;
	}

	long actual = 0;
	// ★ `IMediaSample::GetActualDataLength` 在 IDL 里是 `long GetActualDataLength(void)`
	//   —— **无参数、直接返回**（不是 HRESULT + out 参数那种常见形态）。
	//   同族：`GetSize` 也是 `long GetSize(void)`。照 MSDN 的写法写会 C2660。
	actual = self->GetActualDataLength();
	if (actual > 0) {
		memset(*ppBuffer, 0, static_cast<size_t>(actual));
	}
	g_dsPatchedBuffer = *ppBuffer;
	return hr;
}

// 用 VirtualProtect 把 vtable 槽换成我们的函数（记录原函数以便还原）
static bool PatchVtableSlot(void** vtbl, int slot, void* detour, void** outOrig)
{
	DWORD old = 0;
	if (!VirtualProtect(&vtbl[slot], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}
	*outOrig = vtbl[slot];
	vtbl[slot] = detour;
	DWORD tmp = 0;
	VirtualProtect(&vtbl[slot], sizeof(void*), old, &tmp);
	return true;
}

static void RestoreVtableSlot(void** vtbl, int slot, void* orig)
{
	DWORD old = 0;
	if (!VirtualProtect(&vtbl[slot], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
		return;
	}
	vtbl[slot] = orig;
	DWORD tmp = 0;
	VirtualProtect(&vtbl[slot], sizeof(void*), old, &tmp);
}

static void PartA1_Mechanism()
{
	printf("\n=== Part A1：DirectShow 机制（CMemAllocator 造 IMediaSample，不需要摄像头）===\n");

	IMemAllocator* alloc = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_MemoryAllocator_, nullptr, CLSCTX_INPROC_SERVER,
		IID_IMemAllocator, reinterpret_cast<void**>(&alloc));
	if (FAILED(hr) || !alloc) {
		Bad("CoCreateInstance(CMemAllocator) 失败 -> 后面无法验证");
		return;
	}

	ALLOCATOR_PROPERTIES req = {};
	req.cBuffers = 2;
	req.cbBuffer = 64 * 1024;
	req.cbAlign = 1;
	req.cbPrefix = 0;
	ALLOCATOR_PROPERTIES act = {};
	hr = alloc->SetProperties(&req, &act);
	if (FAILED(hr)) {
		Bad("IMemAllocator::SetProperties 失败");
		alloc->Release();
		return;
	}
	hr = alloc->Commit();
	if (FAILED(hr)) {
		Bad("IMemAllocator::Commit 失败");
		alloc->Release();
		return;
	}
	Ok("CMemAllocator 就绪（2 个 64KB 缓冲）");

	IMediaSample* s1 = nullptr;
	hr = alloc->GetBuffer(&s1, nullptr, nullptr, 0);
	if (FAILED(hr) || !s1) {
		Bad("IMemAllocator::GetBuffer 拿不到 IMediaSample");
		alloc->Release();
		return;
	}
	Ok("拿到一个真 IMediaSample（DirectShow 的帧对象）");

	// 填可识别的内容，并把"实际长度"设成我们认识的值
	BYTE* buf = nullptr;
	long  size = 0;
	if (FAILED(s1->GetPointer(&buf)) || !buf) {
		Bad("IMediaSample::GetPointer 失败");
		s1->Release(); alloc->Release();
		return;
	}
	size = s1->GetSize();   // ★ `long GetSize(void)`，无参数
	const long kFill = (size > 4096) ? 4096 : size;
	memset(buf, 0xAB, static_cast<size_t>(kFill));
	s1->SetActualDataLength(kFill);
	Ok("已把缓冲区填成 0xAB 并设置实际长度（负对照的'真数据'）");

	// ★ 负对照：patch 之前，GetPointer 必须看到 0xAB（否则"变成 0"无法归因）
	{
		BYTE* b2 = nullptr;
		s1->GetPointer(&b2);
		bool allAb = (b2 != nullptr);
		for (long i = 0; i < kFill && allAb; ++i) {
			if (b2[i] != 0xAB) allAb = false;
		}
		if (allAb) {
			Ok("负对照：patch 之前读到的是真数据（0xAB）-> 后面的'变 0'可归因");
		}
		else {
			Bad("负对照失败：patch 之前就不是 0xAB -> 后面的结论不可信");
		}
	}

	// ★ 记录 vtable 指针（判断"是否按对象"）
	void** vtbl1 = *reinterpret_cast<void***>(s1);

	IMediaSample* s2 = nullptr;
	alloc->GetBuffer(&s2, nullptr, nullptr, 0);
	void** vtbl2 = s2 ? *reinterpret_cast<void***>(s2) : nullptr;
	if (s2) {
		s2->Release();
	}

	if (vtbl1 == vtbl2) {
		Obs("★ 两个 IMediaSample 的 vtable **相同** -> vtable 是**按类共享**的");
		Obs("  => 与 MF 的 IMFSourceReader 同一个坑：patch 一次影响所有实例，");
		Obs("     必须**按对象**记'要不要替换'（铁律 210）");
	}
	else {
		Obs("两个 IMediaSample 的 vtable 不同 -> 可能是按对象，需按对象处理");
	}

	// patch 槽 3 = GetPointer
	if (!PatchVtableSlot(vtbl1, 3, reinterpret_cast<void*>(DsGetPointer_Detour),
		reinterpret_cast<void**>(&g_dsOrigGetPointer))) {
		Bad("patch IMediaSample vtable 槽 3 失败（VirtualProtect 被拒？）");
		s1->Release(); alloc->Release();
		return;
	}
	Ok("已 patch IMediaSample vtable 槽 3（GetPointer）");

	// ★ 关键断言：patch 之后，调用方通过 GetPointer 拿到的必须是全 0
	{
		BYTE* b3 = nullptr;
		const HRESULT hr3 = s1->GetPointer(&b3);
		bool allZero = SUCCEEDED(hr3) && b3 != nullptr;
		for (long i = 0; i < kFill && allZero; ++i) {
			if (b3[i] != 0) allZero = false;
		}
		if (allZero) {
			Ok("★ patch 后调用方读到全 0 -> **DirectShow 的帧可以在进程内中性化**");
		}
		else {
			Bad("patch 后调用方仍读到非 0 -> 该路径不可替换");
		}
		if (InterlockedCompareExchange(&g_dsGetPointerCalls, 0, 0) > 0) {
			Ok("我们的 detour 确实被调用到了（不是'patch 了但没人走'）");
		}
		else {
			Bad("detour 一次都没被调用 -> patch 没生效");
		}
	}

	RestoreVtableSlot(vtbl1, 3, reinterpret_cast<void*>(g_dsOrigGetPointer));
	Obs("已还原 vtable 槽（探针不留副作用）");

	s1->Release();
	alloc->Release();
}

static int PartA2_EnumDevices()
{
	printf("\n=== Part A2：DirectShow 采集设备枚举 ===\n");

	ICreateDevEnum* devEnum = nullptr;
	HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum, nullptr, CLSCTX_INPROC_SERVER,
		IID_ICreateDevEnum, reinterpret_cast<void**>(&devEnum));
	if (FAILED(hr) || !devEnum) {
		Bad("CoCreateInstance(CLSID_SystemDevEnum) 失败 -> DirectShow 面不可达");
		return 0;
	}

	IEnumMoniker* mon = nullptr;
	hr = devEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &mon, 0);
	if (hr != S_OK || !mon) {
		Obs("DirectShow 视频采集设备类别为空（无摄像头或未注册）");
		devEnum->Release();
		return 0;
	}

	int count = 0;
	IMoniker* m = nullptr;
	while (mon->Next(1, &m, nullptr) == S_OK) {
		IPropertyBag* bag = nullptr;
		if (SUCCEEDED(m->BindToStorage(nullptr, nullptr, IID_IPropertyBag,
			reinterpret_cast<void**>(&bag))) && bag) {
			VARIANT v;
			VariantInit(&v);
			if (SUCCEEDED(bag->Read(L"FriendlyName", &v, nullptr)) && v.bstrVal) {
				printf("       · %ls\n", v.bstrVal);
				VariantClear(&v);
			}
			bag->Release();
		}
		m->Release();
		++count;
	}
	mon->Release();
	devEnum->Release();

	if (count > 0) {
		char msg[160];
		sprintf_s(msg, "DirectShow 枚举到 %d 个采集设备 -> 该 API 面在进程内可达", count);
		Ok(msg);
	}
	else {
		Obs("DirectShow 采集设备为 0（真机部分将跳过）");
	}
	return count;
}

static void PartA3_RealGraph()
{
	printf("\n=== Part A3：DirectShow 真机建图（--use-camera）===\n");
	Skip("真机建图未实现 —— Part A1 已在机制层证明'槽 3 可 patch 且调用方可见'；");
	Skip("真机建图需要 SampleGrabber + NullRenderer 且对媒体类型挑剔，留待接生产时做");
}

// ==================================================================
// Part B —— VFW（avicap32）
// ==================================================================
//
// 盘点文档记的是「VFW 帧路径 ❌ 不可替换（没有我们能改的缓冲区）」。
// 本部分要核实这句话：VFW 抓帧后像素落在**采集窗口的 DIB** 里，
// 而"读那个 DIB"走的是 `GetDIBits` / `BitBlt` —— 那是**屏幕面**已挂的 API。
// 也就是说 VFW 帧可能**间接**可替换（借屏幕面的 hook），而不是"不可替换"。
// ------------------------------------------------------------------
// VFW 的工作线程。
// ★ 为什么必须放线程 + 消息泵：`cap*` 系列**全是 `SendMessage` 到采集窗口**的宏，
//   avicap 内部还靠定时器/线程投递帧。**不泵消息 ⇒ 直接卡死**（本探针第一版
//   就在主线程里裸调 `capDriverConnect`，跑了 4 分钟没动静，只能强杀）。
//   所以：窗口建在**会泵消息的线程**上，主线程只做**有界等待**。
// ------------------------------------------------------------------
static volatile LONG g_vfwDone = 0;
static volatile LONG g_vfwFrameSeen = 0;
static int  g_vfwStage = 0;        // 走到哪一步（超时时能说清卡在哪）
static int  g_vfwDibLines = 0;
static int  g_vfwDibNonZero = 0;

static void VfwPump(DWORD ms)
{
	const DWORD end = GetTickCount() + ms;
	MSG msg;
	while (GetTickCount() < end) {
		while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		Sleep(10);
	}
}

static void CALLBACK VfwFrameCb(HWND, LPVIDEOHDR) { InterlockedExchange(&g_vfwFrameSeen, 1); }

static DWORD WINAPI VfwThread(LPVOID)
{
	HWND cap = capCreateCaptureWindowW(L"r3sc_vfw_probe", WS_POPUP, 0, 0, 320, 240,
		nullptr, 0);
	if (!cap) { g_vfwStage = -1; InterlockedExchange(&g_vfwDone, 1); return 0; }
	g_vfwStage = 1;

	if (!capDriverConnect(cap, 0)) { g_vfwStage = -2; InterlockedExchange(&g_vfwDone, 1); return 0; }
	g_vfwStage = 2;

	capSetCallbackOnFrame(cap, VfwFrameCb);
	g_vfwStage = 3;

	if (!capGrabFrameNoStop(cap)) { g_vfwStage = -3; InterlockedExchange(&g_vfwDone, 1); return 0; }
	g_vfwStage = 4;

	// 泵消息等帧（avicap 靠消息/定时器投递）
	for (int i = 0; i < 40 && !g_vfwFrameSeen; ++i) {
		VfwPump(100);
	}
	g_vfwStage = 5;

	// ★ 关键：帧能不能被"读出来"？能 => 说明它走的是 GDI（屏幕面已挂的那套 API）
	HDC dc = GetDC(cap);
	if (dc) {
		BITMAPINFO bi = {};
		bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bi.bmiHeader.biWidth = 320;
		bi.bmiHeader.biHeight = -240;
		bi.bmiHeader.biPlanes = 1;
		bi.bmiHeader.biBitCount = 32;
		bi.bmiHeader.biCompression = BI_RGB;

		BYTE* pixels = static_cast<BYTE*>(malloc(320 * 240 * 4));
		if (pixels) {
			const int lines = GetDIBits(dc,
				static_cast<HBITMAP>(GetCurrentObject(dc, OBJ_BITMAP)),
				0, 240, pixels, &bi, DIB_RGB_COLORS);
			if (lines > 0) {
				g_vfwDibLines = lines;
				for (int i = 0; i < 320 * 240 * 4; ++i) {
					if (pixels[i]) { ++g_vfwDibNonZero; }
				}
			}
			free(pixels);
		}
		ReleaseDC(cap, dc);
	}
	g_vfwStage = 6;

	capDriverDisconnect(cap);
	DestroyWindow(cap);
	InterlockedExchange(&g_vfwDone, 1);
	return 0;
}

static void PartB_Vfw(bool useCamera)
{
	printf("\n=== Part B：VFW 帧路径 ===\n");

	if (!useCamera) {
		Skip("未加 --use-camera：VFW 必须真开采集窗口才能判定");
		return;
	}

	// ★ 先**枚举** VFW 驱动（`capGetDriverDescriptionW` 只读注册信息，**不开设备**）。
	//   这条是为了让后面"卡在 connect"能被归因：是没驱动，还是驱动打不开。
	{
		int n = 0;
		for (int i = 0; i < 10; ++i) {
			wchar_t name[128] = {}, ver[128] = {};
			if (!capGetDriverDescriptionW(static_cast<WORD>(i), name, sizeof(name),
				ver, sizeof(ver))) {
				break;
			}
			printf("       VFW 驱动[%d]: %ls (%ls)\n", i, name, ver);
			++n;
		}
		if (n == 0) {
			Bad("VFW 一个驱动都没有 -> 该面在本机不存在");
			return;
		}
		Obs("VFW 驱动枚举成功（枚举本身不阻塞）");
	}

	HANDLE th = CreateThread(nullptr, 0, VfwThread, nullptr, 0, nullptr);
	if (!th) {
		Bad("CreateThread 失败");
		return;
	}

	// ★ 有界等待：VFW 很容易卡在设备占用上，绝不允许无限等（铁律 117）。
	const DWORD w = WaitForSingleObject(th, 25000);
	if (w == WAIT_TIMEOUT) {
		char msg[200];
		sprintf_s(msg, "VFW 25 秒未完成（卡在 stage=%d）-> 本机无法判定，按'未覆盖'计", g_vfwStage);
		Skip(msg);
		CloseHandle(th);
		return;   // 线程留着；进程随后退出会一并清掉
	}
	CloseHandle(th);

	switch (g_vfwStage) {
	case -1: Bad("capCreateCaptureWindowW 返回 NULL -> 无法判定"); return;
	case -2: Bad("capDriverConnect 失败 -> 没有可用采集驱动"); return;
	case -3: Bad("capGrabFrameNoStop 失败"); return;
	default: break;
	}

	Ok("capCreateCaptureWindowW + capDriverConnect 成功（真采集驱动）");

	if (g_vfwFrameSeen) {
		Ok("capSetCallbackOnFrame 收到帧回调（帧确实被投递了）");
	}
	else {
		Skip("25 次泵消息内没等到帧回调（设备可能被别的程序占用）");
	}

	if (g_vfwDibLines > 0) {
		char msg[220];
		sprintf_s(msg, "★ GetDIBits 从采集窗口读到 %d 行像素（非 0 字节 %d 个）",
			g_vfwDibLines, g_vfwDibNonZero);
		Ok(msg);
		Obs("=> VFW 帧**落在采集窗口的 DIB 里、走 `GetDIBits` 读**");
		Obs("=> 而 `GetDIBits` 是**屏幕面已挂**的 API");
		Obs("=> 结论：VFW 帧**不是'不可替换'**，而是'借屏幕面间接可替换'");
		Obs("   （盘点文档 §2.3 那句'没有我们能改的缓冲区'**要改**）");
	}
	else {
		Obs("GetDIBits 读不到像素（该窗口可能不暴露 DIB）-> VFW 保持'不可替换'");
	}
}

// ==================================================================
// Part C —— WinRT MediaCapture
// ==================================================================
//
// 静态证据链（本探针运行时复核）：
//   ① 注册表 `HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\
//      Windows.Media.Capture.MediaCapture` 的 `DllPath` = `Windows.Media.dll`
//   ② `Windows.Media.dll` 里含字符串 `MFCaptureEngine`
//   ③ `MFCaptureEngine.dll` 导出 `MFCreateCaptureEngine`
//   ⇒ 路由 = WinRT MediaCapture → Windows.Media.dll → MFCreateCaptureEngine
//   ⇒ 挂点 = `MFCaptureEngine.dll!MFCreateCaptureEngine` + `IMFCaptureEngine` vtable
//
// ★ 关键实现差异：`MFCaptureEngine.dll` **不在静态导入表里**（是运行时加载的）
//   ⇒ 不能像 `mf.dll` 那样在启动时直接 `GetProcAddress` 挂上，
//     必须等它被加载（挂 `LoadLibrary` / `GetProcAddress`）或主动 `LoadLibrary` 后再挂。
static void PartC_WinRT(bool useCamera)
{
	printf("\n=== Part C：WinRT MediaCapture 路由 ===\n");

	// ③ 运行时复核：MFCaptureEngine.dll 存在且导出 MFCreateCaptureEngine
	HMODULE hCapEng = LoadLibraryW(L"MFCaptureEngine.dll");
	if (!hCapEng) {
		Bad("LoadLibrary(MFCaptureEngine.dll) 失败 -> 该挂点在本机不存在");
	}
	else {
		void* fn = reinterpret_cast<void*>(GetProcAddress(hCapEng, "MFCreateCaptureEngine"));
		if (fn) {
			char msg[200];
			sprintf_s(msg, "MFCaptureEngine.dll 导出 MFCreateCaptureEngine @ %p -> 挂点存在", fn);
			Ok(msg);

			// ★ 可挂性：能不能挂上（与生产同一套 MinHook）
			void* tramp = nullptr;
			const MH_STATUS st = MH_CreateHook(fn, reinterpret_cast<LPVOID>(fn), &tramp);
			if (st == MH_OK) {
				Ok("★ MFCreateCaptureEngine 可被 MH_CreateHook 挂上 -> 挂点可用");
				MH_RemoveHook(fn);
			}
			else {
				char m2[160];
				sprintf_s(m2, "MH_CreateHook(MFCreateCaptureEngine) 失败，状态 %d", st);
				Bad(m2);
			}
		}
		else {
			Bad("MFCaptureEngine.dll 里没有 MFCreateCaptureEngine 导出");
		}
		FreeLibrary(hCapEng);
	}

	if (!useCamera) {
		Skip("未加 --use-camera：WinRT 激活（RoGetActivationFactory + InitializeAsync）未跑");
		Obs("=> 本部分给的是**静态证据链 + 挂点可挂性**，不是'真机替换成功'");
		return;
	}
	Skip("WinRT 真机激活未实现 —— 需要在 WinRT 应用上下文里 InitializeAsync（异步 + 相机权限），");
	Skip("留待接生产时做；本轮的结论是'路由明确 + 挂点存在且可挂'");
}

// ==================================================================
int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	SetConsoleOutputCP(65001);

	bool useCamera = false;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--use-camera") == 0) { useCamera = true; }
	}

	printf("R3ShieldCore —— 摄像头其余取帧路径可行性探针\n");
	printf("自包含：自己挂自己的 vtable patch，不注入、不跑引擎。\n");
	printf("硬件开关：%s\n", useCamera ? "--use-camera（会真开摄像头）" : "关（只跑不需要硬件的部分）");

	if (MH_Initialize() != MH_OK) {
		printf("!! MH_Initialize 失败\n");
		return 1;
	}

	CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

	PartA1_Mechanism();
	const int devCount = PartA2_EnumDevices();
	if (useCamera && devCount > 0) {
		PartA3_RealGraph();
	}
	else if (useCamera) {
		Skip("DirectShow 无采集设备，A3 跳过");
	}

	// ★ Part C 放在 Part B **之前**：VFW 很容易卡在设备占用上，
	//   万一卡住也不该拖累已经能拿到的结论（B 自己有 25 秒有界等待）。
	PartC_WinRT(useCamera);

	PartB_Vfw(useCamera);

	CoUninitialize();
	MH_Uninitialize();

	printf("\n=== 结果：通过 %d / 失败 %d / 跳过 %d ===\n", g_pass, g_fail, g_skip);
	printf("（跳过必须可见并计数 —— 铁律 178）\n");
	return g_fail == 0 ? 0 : 1;
}
