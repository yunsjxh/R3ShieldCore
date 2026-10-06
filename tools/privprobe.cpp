// privprobe.cpp —— 摄像头 / 输入钩子 / 截屏 三类新监控的实测探针。
//
// 用法：
//   privprobe <case> [outFile]
//
// case：
//   cam-enum            枚举摄像头设备（Media Foundation，应"只记录"）
//   cam-mf-open         MFCreateDeviceSource（应高危）
//   cam-vfw-open        capCreateCaptureWindowW（VFW，应高危）
//   hook-mouse-ll       SetWindowsHookEx(WH_MOUSE_LL)（应高危）
//   hook-kbd-ll         SetWindowsHookEx(WH_KEYBOARD_LL)（应高危）
//   hook-mouse-thread   SetWindowsHookEx(WH_MOUSE, 本线程)（应只记录）
//   hook-cbt-global     SetWindowsHookEx(WH_CBT, 全局)（应高危）
//   raw-sink            RegisterRawInputDevices + RIDEV_INPUTSINK（应高危）
//   raw-plain           RegisterRawInputDevices 普通（应只记录）
//   unhook              UnhookWindowsHookEx（应只记录）
//   screen-capture      BitBlt(内存DC <- 屏幕DC)（应高危）
//   screen-normal       BitBlt(内存DC <- 内存DC)（应**无事件**，这是噪音测试）
//   screen-draw         BitBlt(屏幕DC <- 内存DC)（正常绘制，应**无事件**）
//   screen-print        PrintWindow（应高危）
//   all                 全部跑一遍
//
// 编译：
//   cl /nologo /EHsc /std:c++17 -source-charset:utf-8 privprobe.cpp /Fe:privprobe.exe
//      /link user32.lib gdi32.lib

#include <windows.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------
// Media Foundation 最小声明（不 include mfapi.h，避免拉进 mfplat.lib）
// ---------------------------------------------------------------------
struct PG_GUID
{
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
};

static const PG_GUID GUID_MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE =
    { 0xc60ac5fe, 0x252a, 0x478f, { 0xa0, 0xef, 0xbc, 0x8f, 0xa5, 0xf7, 0xca, 0xd3 } };
static const PG_GUID GUID_MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP =
    { 0x8ac3587a, 0x4ae7, 0x42d8, { 0x99, 0xe0, 0x0a, 0x60, 0x13, 0xee, 0xf9, 0x0f } };

typedef HRESULT(WINAPI* MFCreateAttributesFn)(void** attributes, UINT32 initialSize);
typedef HRESULT(WINAPI* MFCreateDeviceSourceFn)(void* attributes, void** source);
typedef HRESULT(WINAPI* MFEnumDeviceSourcesFn)(void* attributes, void*** devices, UINT32* count);

// IMFAttributes::SetGUID 在 vtable 里的下标（IUnknown 占 0..2）
//   3 GetItem 4 GetItemType 5 CompareItem 6 Compare 7 GetUINT32 8 GetUINT64
//   9 GetDouble 10 GetGUID 11 GetStringLength 12 GetString 13 GetAllocatedString
//   14 GetBlobSize 15 GetBlob 16 SetItem 17 DeleteItem 18 SetUINT32
//   19 SetUINT64 20 SetDouble 21 SetGUID
typedef HRESULT(STDMETHODCALLTYPE* SetGUIDFn)(void* self, const PG_GUID* key, const PG_GUID* value);
static const int VTBL_SETGUID = 21;

// ---------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------
static FILE* g_out = nullptr;

static void Say(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);

    if (g_out) {
        va_start(args, format);
        vfprintf(g_out, format, args);
        va_end(args);
        fflush(g_out);
    }
}

// ---------------------------------------------------------------------
// 钩子回调（只是占位，不需要真的做事）
// ---------------------------------------------------------------------
static LRESULT CALLBACK DummyHookProc(int code, WPARAM w, LPARAM l)
{
    return CallNextHookEx(nullptr, code, w, l);
}

// ---------------------------------------------------------------------
// 摄像头
// ---------------------------------------------------------------------
static void* MakeVideoCaptureAttributes(MFCreateAttributesFn createAttributes)
{
    if (!createAttributes) {
        return nullptr;
    }

    void* attributes = nullptr;
    HRESULT hr = createAttributes(&attributes, 1);
    if (FAILED(hr) || !attributes) {
        Say("MFCreateAttributes 失败 hr=0x%08X\n", (unsigned)hr);
        return nullptr;
    }

    void** vtable = *reinterpret_cast<void***>(attributes);
    auto setGuid = reinterpret_cast<SetGUIDFn>(vtable[VTBL_SETGUID]);
    hr = setGuid(attributes, &GUID_MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        &GUID_MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP);
    Say("SetGUID(SOURCE_TYPE=VIDCAP) hr=0x%08X\n", (unsigned)hr);
    return attributes;
}

static void CaseCamEnum()
{
    // ⚠️ 模块归属：MFCreateAttributes 在 mfplat.dll，
    //    而 MFEnumDeviceSources / MFCreateDeviceSource 在 **mf.dll**
    //    （转发到 mfcore.dll）。这是 dumpbin 实测确认的。
    HMODULE mfplat = LoadLibraryW(L"mfplat.dll");
    HMODULE mf = LoadLibraryW(L"mf.dll");
    if (!mfplat || !mf) {
        Say("mfplat.dll / mf.dll 加载失败\n");
        return;
    }

    auto createAttributes = reinterpret_cast<MFCreateAttributesFn>(
        GetProcAddress(mfplat, "MFCreateAttributes"));
    auto enumSources = reinterpret_cast<MFEnumDeviceSourcesFn>(
        GetProcAddress(mf, "MFEnumDeviceSources"));
    if (!createAttributes || !enumSources) {
        Say("MFCreateAttributes / MFEnumDeviceSources 找不到\n");
        return;
    }

    void* attributes = MakeVideoCaptureAttributes(createAttributes);
    void** devices = nullptr;
    UINT32 count = 0;
    HRESULT hr = enumSources(attributes, &devices, &count);
    Say("MFEnumDeviceSources hr=0x%08X  count=%u\n", (unsigned)hr, count);
    Say("  → 期望：摄像头 EnumCamera 事件，Decision=WOULD-BLOCK（只记录，不拦）\n");
}

static void CaseCamMfOpen()
{
    HMODULE mfplat = LoadLibraryW(L"mfplat.dll");
    HMODULE mf = LoadLibraryW(L"mf.dll");
    if (!mfplat || !mf) {
        Say("mfplat.dll / mf.dll 加载失败\n");
        return;
    }

    auto createAttributes = reinterpret_cast<MFCreateAttributesFn>(
        GetProcAddress(mfplat, "MFCreateAttributes"));
    auto createDeviceSource = reinterpret_cast<MFCreateDeviceSourceFn>(
        GetProcAddress(mf, "MFCreateDeviceSource"));
    if (!createDeviceSource) {
        Say("MFCreateDeviceSource 找不到\n");
        return;
    }

    void* attributes = MakeVideoCaptureAttributes(createAttributes);
    void* source = nullptr;
    HRESULT hr = createDeviceSource(attributes, &source);
    Say("MFCreateDeviceSource hr=0x%08X  source=%p\n", (unsigned)hr, source);
    Say("  → 期望：CameraDeviceSource 事件，高危\n");
}

static void CaseCamVfwOpen()
{
    HMODULE avicap = LoadLibraryW(L"avicap32.dll");
    if (!avicap) {
        Say("avicap32.dll 加载失败\n");
        return;
    }

    typedef HWND(WINAPI* capCreateFn)(LPCWSTR, DWORD, int, int, int, int, HWND, int);
    auto capCreate = reinterpret_cast<capCreateFn>(
        GetProcAddress(avicap, "capCreateCaptureWindowW"));
    if (!capCreate) {
        Say("capCreateCaptureWindowW 找不到\n");
        return;
    }

    HWND wnd = capCreate(L"privprobe", WS_OVERLAPPEDWINDOW, 0, 0, 160, 120, nullptr, 0);
    Say("capCreateCaptureWindowW -> hwnd=%p  GetLastError=%lu\n", (void*)wnd, GetLastError());
    Say("  → 期望：OpenCamera 事件，高危（本机没摄像头时 hwnd 可能为 NULL，但事件应照样上报）\n");
    if (wnd) {
        DestroyWindow(wnd);
    }
}

// ---------------------------------------------------------------------
// 输入钩子
// ---------------------------------------------------------------------
static void ReportHook(const char* what, HHOOK hook)
{
    Say("%s -> hook=%p  GetLastError=%lu\n", what, (void*)hook, GetLastError());
    if (hook) {
        UnhookWindowsHookEx(hook);
    }
}

static void CaseHookMouseLl()
{
    HMODULE self = GetModuleHandleW(nullptr);
    ReportHook("SetWindowsHookExW(WH_MOUSE_LL=14, 本模块, tid=0)",
        SetWindowsHookExW(14, DummyHookProc, self, 0));
    Say("  → 期望：SetMouseHook 事件，高危（低级钩子 = 全系统监听）\n");
}

static void CaseHookKbdLl()
{
    HMODULE self = GetModuleHandleW(nullptr);
    ReportHook("SetWindowsHookExW(WH_KEYBOARD_LL=13, 本模块, tid=0)",
        SetWindowsHookExW(13, DummyHookProc, self, 0));
    Say("  → 期望：SetKeyboardHook 事件，高危（键盘记录器特征）\n");
}

static void CaseHookMouseThread()
{
    HMODULE self = GetModuleHandleW(nullptr);
    DWORD tid = GetCurrentThreadId();
    ReportHook("SetWindowsHookExW(WH_MOUSE=7, 本模块, 本线程)",
        SetWindowsHookExW(7, DummyHookProc, self, tid));
    Say("  → 期望：SetMouseHook 事件，**非高危**（只作用于自己进程）\n");
}

static void CaseHookCbtGlobal()
{
    HMODULE self = GetModuleHandleW(nullptr);
    ReportHook("SetWindowsHookExW(WH_CBT=5, 本模块, tid=0)",
        SetWindowsHookExW(5, DummyHookProc, self, 0));
    Say("  → 期望：SetWindowsHook 事件，高危（全局钩子 = 往所有 GUI 进程注入）\n");
}

static void CaseRawInput(bool sink)
{
    RAWINPUTDEVICE device = {};
    device.usUsagePage = 0x01; // HID_USAGE_PAGE_GENERIC
    device.usUsage = 0x02;     // HID_USAGE_MOUSE
    device.dwFlags = sink ? RIDEV_INPUTSINK : 0;
    device.hwndTarget = GetConsoleWindow();

    BOOL ok = RegisterRawInputDevices(&device, 1, sizeof(device));
    Say("RegisterRawInputDevices(mouse, %s) -> %d  GetLastError=%lu\n",
        sink ? "RIDEV_INPUTSINK" : "无标志", ok, GetLastError());
    Say("  → 期望：RegisterRawInput 事件，%s\n", sink ? "高危（后台收输入）" : "**非高危**（普通原始输入）");
}

static void CaseUnhook()
{
    HMODULE self = GetModuleHandleW(nullptr);
    HHOOK hook = SetWindowsHookExW(14, DummyHookProc, self, 0);
    Say("先装一个钩子 hook=%p\n", (void*)hook);
    BOOL ok = UnhookWindowsHookEx(hook);
    Say("UnhookWindowsHookEx -> %d  GetLastError=%lu\n", ok, GetLastError());
    Say("  → 期望：Unhook 事件，**非高危**（只记录）\n");
}

// ---------------------------------------------------------------------
// 截屏
// ---------------------------------------------------------------------
static void CaseScreenCapture()
{
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, 200, 150);
    HGDIOBJ old = SelectObject(mem, bmp);

    BOOL ok = BitBlt(mem, 0, 0, 200, 150, screen, 0, 0, SRCCOPY);
    Say("BitBlt(内存DC <- 屏幕DC, 200x150) -> %d  GetLastError=%lu\n", ok, GetLastError());
    Say("  → 期望：ScreenBitBlt 事件，高危\n");

    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
}

static void CaseScreenNormal()
{
    // 内存 DC 之间的 BitBlt —— 普通图形处理，不该产生任何事件。
    HDC mem1 = CreateCompatibleDC(nullptr);
    HDC mem2 = CreateCompatibleDC(nullptr);
    HBITMAP bmp1 = CreateCompatibleBitmap(mem1, 64, 64);
    HBITMAP bmp2 = CreateCompatibleBitmap(mem2, 64, 64);
    HGDIOBJ old1 = SelectObject(mem1, bmp1);
    HGDIOBJ old2 = SelectObject(mem2, bmp2);

    BOOL ok = BitBlt(mem1, 0, 0, 64, 64, mem2, 0, 0, SRCCOPY);
    Say("BitBlt(内存DC <- 内存DC, 64x64) -> %d\n", ok);
    Say("  → 期望：**无任何事件**（这是噪音测试，有事件就是误报）\n");

    SelectObject(mem1, old1);
    SelectObject(mem2, old2);
    DeleteObject(bmp1);
    DeleteObject(bmp2);
    DeleteDC(mem1);
    DeleteDC(mem2);
}

static void CaseScreenDraw()
{
    // 屏幕 DC 当**目标**（正常绘制），源是内存 DC —— 不该产生事件。
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, 64, 64);
    HGDIOBJ old = SelectObject(mem, bmp);

    BOOL ok = BitBlt(screen, 0, 0, 64, 64, mem, 0, 0, SRCCOPY);
    Say("BitBlt(屏幕DC <- 内存DC, 64x64) -> %d\n", ok);
    Say("  → 期望：**无任何事件**（源不是屏幕 DC，是正常绘制）\n");

    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
}

static void CaseScreenPrint()
{
    HWND hwnd = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (!hwnd) {
        hwnd = GetDesktopWindow();
    }

    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, 200, 60);
    HGDIOBJ old = SelectObject(mem, bmp);

    BOOL ok = PrintWindow(hwnd, mem, 0);
    Say("PrintWindow(hwnd=%p) -> %d  GetLastError=%lu\n", (void*)hwnd, ok, GetLastError());
    Say("  → 期望：PrintWindow 事件，高危\n");

    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
}

// ---------------------------------------------------------------------
int main(int argc, char** argv)
{
    const char* testCase = (argc > 1) ? argv[1] : "all";

    if (argc > 2) {
        fopen_s(&g_out, argv[2], "wb");
        if (g_out) {
            // UTF-8 BOM，方便直接看
            fwrite("\xEF\xBB\xBF", 1, 3, g_out);
        }
    }

    Say("privprobe pid=%lu  case=%s\n", GetCurrentProcessId(), testCase);
    Say("=========================================================\n");

    bool all = (strcmp(testCase, "all") == 0);

    if (all || strcmp(testCase, "cam-enum") == 0) { CaseCamEnum(); }
    if (all || strcmp(testCase, "cam-mf-open") == 0) { CaseCamMfOpen(); }
    if (all || strcmp(testCase, "cam-vfw-open") == 0) { CaseCamVfwOpen(); }
    if (all || strcmp(testCase, "hook-mouse-ll") == 0) { CaseHookMouseLl(); }
    if (all || strcmp(testCase, "hook-kbd-ll") == 0) { CaseHookKbdLl(); }
    if (all || strcmp(testCase, "hook-mouse-thread") == 0) { CaseHookMouseThread(); }
    if (all || strcmp(testCase, "hook-cbt-global") == 0) { CaseHookCbtGlobal(); }
    if (all || strcmp(testCase, "raw-sink") == 0) { CaseRawInput(true); }
    if (all || strcmp(testCase, "raw-plain") == 0) { CaseRawInput(false); }
    if (all || strcmp(testCase, "unhook") == 0) { CaseUnhook(); }
    if (all || strcmp(testCase, "screen-capture") == 0) { CaseScreenCapture(); }
    if (all || strcmp(testCase, "screen-normal") == 0) { CaseScreenNormal(); }
    if (all || strcmp(testCase, "screen-draw") == 0) { CaseScreenDraw(); }
    if (all || strcmp(testCase, "screen-print") == 0) { CaseScreenPrint(); }

    Say("=========================================================\n");
    Say("完成\n");

    if (g_out) {
        fclose(g_out);
    }

    return 0;
}
