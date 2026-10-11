//
// spoof_clipboard_probe.cpp —— 实证：剪贴板「拦截并替换回传数据」到底行不行。
//
// 这是《回传数据替换Hook-技术预研》Phase 1 第 2 个面（剪贴板）的机制探针。
// 它**不经过引擎**、**不需要注入器**，在一个进程里自己挂自己的 hook，
// 回答五个问题：
//
//   A. 基线（负对照）：不挂 hook 时，GetClipboardData 拿到的是真实内容吗？
//      —— 没有这一条，后面"变成了空的"无法归因（铁律 110：空真）。
//   B. 替换回传句柄：detour 里「先真调原函数 → 再造一块自己的替代物 →
//      返回替代物」，调用者拿到的是中性化内容吗？返回码还完好（= 调用
//      "成功"）吗？—— 这正是 Spoof 与 Block 的分水岭：Block 返回 nullptr +
//      err=5，Spoof 返回**一个能用的句柄**。
//   C. **句柄所有权**（这个面特有的坑）：替代物必须由**我们自己**在
//      `CloseClipboard` 时回收，既不能提前（对方正在读 ⇒ 野指针），
//      也不能不回收（泄漏）。这一条专门验证"契约终点回收"。
//   D. 未误伤源：替换只改**返回值**，剪贴板**本体**没被改动 —— 也就是
//      "未挂钩的路径仍能拿到真数据"（多路径戳穿在剪贴板面的体现）。
//   E. 不可伪造的格式：`BuildFake` 必须返回 nullptr（调用方据此回落"拒绝"），
//      而不是硬造一个长度不对的块让调用者读越界。
//
// ★★ 关键：伪造逻辑**不是抄的** —— 直接 `#include "clipboard_spoof_codec.h"`，
//    与生产 `clipboard_guard.cpp` 用的是**同一份**代码（铁律 127：
//    同一份清单拷贝多份必然漂移，且漂了之后探针照样全绿）。
//
// ⚠️ 本探针只碰**自己进程内自己放到剪贴板上的**内容，不注入任何进程、
//    不读屏幕、不写盘。因此**不受**「本机禁止运行引擎」那条约束（铁律 175）。
//
// 编译：bash build_spoof_clipboard_probe.sh
// 运行：./tools/spoof_clipboard_probe.exe
//
#include <windows.h>
#include <stdio.h>
#include <MinHook.h>

#include "clipboard_spoof_codec.h"   // ← 生产同款（不抄）

using namespace R3ShieldCoreClipboardSpoof;

// ------------------------------------------------------------------ 状态
static int g_pass = 0;
static int g_fail = 0;

typedef HANDLE(WINAPI* GetClipboardData_t)(UINT);
typedef BOOL(WINAPI* CloseClipboard_t)();

static GetClipboardData_t g_origGetClipboardData = nullptr;
static CloseClipboard_t   g_origCloseClipboard = nullptr;

static volatile LONG g_spoofOn = 0;   // 1 = detour 允许替换
static volatile LONG g_hits = 0;
static volatile LONG g_built = 0;

// detour 里顺手记下的"真实句柄"，供"未误伤源"核对。
// ⚠️ 它只在**剪贴板开着**这段时间内有效（契约），所以核对必须在
//    CloseClipboard 之前做完。
static HANDLE g_lastRealHandle = nullptr;
static UINT   g_lastFormat = 0;

// ------------------------------------------------------------------ 与生产同构的槽
//
// 只为验证"CloseClipboard 时回收"这条契约。生产里的实现见
// clipboard_guard.cpp 的 TrackFake / ReleaseAllFakes。
static const int kSlots = 8;
static struct FakeSlot { volatile LONG inUse; UINT format; HANDLE handle; } g_slots[kSlots] = {};
static volatile LONG g_released = 0;
static volatile LONG g_overflow = 0;

static void Track(UINT format, HANDLE handle)
{
    if (!handle) return;
    for (int i = 0; i < kSlots; ++i) {
        if (InterlockedCompareExchange(&g_slots[i].inUse, 1, 0) == 0) {
            g_slots[i].format = format;
            g_slots[i].handle = handle;
            return;
        }
    }
    // 槽满：宁可泄漏，也不提前释放（与生产同一取舍）。
    InterlockedIncrement(&g_overflow);
}

static void ReleaseAll()
{
    for (int i = 0; i < kSlots; ++i) {
        if (InterlockedCompareExchange(&g_slots[i].inUse, 0, 1) == 1) {
            const UINT f = g_slots[i].format;
            HANDLE h = g_slots[i].handle;
            g_slots[i].handle = nullptr;
            g_slots[i].format = 0;
            FreeFake(f, h);
            InterlockedIncrement(&g_released);
        }
    }
}

static bool AnySlotInUse()
{
    for (int i = 0; i < kSlots; ++i) {
        if (InterlockedCompareExchange(&g_slots[i].inUse, 0, 0) != 0) return true;
    }
    return false;
}

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ detour
static HANDLE WINAPI GetClipboardData_Detour(UINT format)
{
    InterlockedIncrement(&g_hits);

    // (1) 真调原函数 —— 真实内容、真实副作用。
    HANDLE real = g_origGetClipboardData(format);
    if (g_spoofOn == 0 || !real) {
        return real;
    }

    // (2) 造替代物 —— 用的是生产那份 codec。
    HANDLE fake = BuildFake(format, real);
    if (!fake) {
        // 造不出来（格式不支持 / 分配失败）⇒ 如实返回真实句柄。
        // 生产里这一步会**回落 Block**（在决策层就分了），这里只记录。
        return real;
    }

    // (3) 登记，等 CloseClipboard 回收；返回**替代物**（调用者看不出区别）。
    Track(format, fake);
    g_lastRealHandle = real;
    g_lastFormat = format;
    InterlockedIncrement(&g_built);
    return fake;
}

static BOOL WINAPI CloseClipboard_Detour()
{
    const BOOL result = g_origCloseClipboard();
    if (result) {
        // 契约终点：这一轮会话里发出去的替代物，现在才没人该再用。
        ReleaseAll();
    }
    return result;
}

// ------------------------------------------------------------------ 工具
static LPVOID ProcOf(LPCWSTR module, LPCSTR name)
{
    HMODULE m = GetModuleHandleW(module);
    if (!m) return nullptr;
    return reinterpret_cast<LPVOID>(GetProcAddress(m, name));
}

// 打开剪贴板（有界重试：别的进程可能正占着）。
static bool OpenClipboardRetry(int attempts)
{
    for (int i = 0; i < attempts; ++i) {
        if (OpenClipboard(nullptr)) return true;
        Sleep(50);
    }
    return false;
}

// 造一块真实的 32bpp DIB（BITMAPINFOHEADER + 像素），像素填 color。
static HGLOBAL MakeRealDib(int w, int h, DWORD color, SIZE_T* sizeOut)
{
    const SIZE_T bytes = sizeof(BITMAPINFOHEADER) + static_cast<SIZE_T>(w) * h * 4;
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hg) return nullptr;

    BYTE* p = static_cast<BYTE*>(GlobalLock(hg));
    if (!p) { GlobalFree(hg); return nullptr; }

    BITMAPINFOHEADER* bi = reinterpret_cast<BITMAPINFOHEADER*>(p);
    ZeroMemory(bi, sizeof(*bi));
    bi->biSize = sizeof(BITMAPINFOHEADER);
    bi->biWidth = w;
    bi->biHeight = -h;          // 负高度 = top-down
    bi->biPlanes = 1;
    bi->biBitCount = 32;
    bi->biCompression = BI_RGB;
    bi->biSizeImage = static_cast<DWORD>(static_cast<SIZE_T>(w) * h * 4);

    DWORD* px = reinterpret_cast<DWORD*>(p + sizeof(BITMAPINFOHEADER));
    for (int i = 0; i < w * h; ++i) px[i] = color;

    GlobalUnlock(hg);
    if (sizeOut) *sizeOut = bytes;
    return hg;
}

// 把 HGLOBAL 里的 DIB 当图读：头部合法性 + 像素是否全 0。
static bool DibHeaderOf(HGLOBAL hg, size_t* headerBytes)
{
    const SIZE_T total = GlobalSize(hg);
    const BYTE* p = static_cast<const BYTE*>(GlobalLock(hg));
    if (!p) return false;
    const bool ok = DibHeaderBytes(p, static_cast<size_t>(total), *headerBytes);
    GlobalUnlock(hg);
    return ok;
}

static bool DibPixelsAllZero(HGLOBAL hg, size_t headerBytes)
{
    const SIZE_T total = GlobalSize(hg);
    const BYTE* p = static_cast<const BYTE*>(GlobalLock(hg));
    if (!p) return false;
    bool allZero = true;
    for (SIZE_T i = headerBytes; i < total; ++i) {
        if (p[i] != 0) { allZero = false; break; }
    }
    GlobalUnlock(hg);
    return allZero;
}

// 读回一个 HBITMAP 的像素（走 GetDIBits —— 本探针没挂它，读到的是真内容）。
static bool BitmapPixelAt(HBITMAP bm, int x, int y, DWORD* out)
{
    BITMAP bmi2 = {};
    if (GetObjectW(bm, sizeof(bmi2), &bmi2) == 0) return false;

    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = bmi2.bmWidth;
    bi.bmiHeader.biHeight = -bmi2.bmHeight;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    const size_t n = static_cast<size_t>(bmi2.bmWidth) * static_cast<size_t>(bmi2.bmHeight);
    DWORD* buf = static_cast<DWORD*>(HeapAlloc(GetProcessHeap(), 0, n * sizeof(DWORD)));
    if (!buf) return false;

    HDC screen = GetDC(nullptr);
    const int lines = GetDIBits(screen, bm, 0, static_cast<UINT>(bmi2.bmHeight), buf, &bi, DIB_RGB_COLORS);
    ReleaseDC(nullptr, screen);

    const bool ok = lines > 0 && x >= 0 && y >= 0 && x < bmi2.bmWidth && y < bmi2.bmHeight;
    if (ok) *out = buf[static_cast<size_t>(y) * bmi2.bmWidth + x];
    HeapFree(GetProcessHeap(), 0, buf);
    return ok;
}

// ------------------------------------------------------------------ main
int main()
{
    printf("=== 剪贴板回传数据替换探针（自挂自测，不经过引擎）===\n");
    printf("进程 pid=%u  架构=%s\n", GetCurrentProcessId(),
#ifdef _WIN64
        "x64"
#else
        "x86"
#endif
    );
    printf("伪造逻辑来源：clipboard_spoof_codec.h（与生产同一份）\n");

    const int W = 4, H = 4;
    const DWORD kRealRed = 0x000000FF;   // DIB 32bpp 内存序是 BGRA ⇒ 0x00RRGGBB 里 R 在低位
    const wchar_t* kSecret = L"SECRET-TOKEN-12345";

    // ---- 准备：把真实内容放进剪贴板 ----
    //   CF_UNICODETEXT = 一段"秘密"文本
    //   CF_DIB         = 4x4 红图
    //   CF_BITMAP      = 4x4 红位图（走的是 HBITMAP 分支，释放路径不同）
    if (!OpenClipboardRetry(20)) {
        printf("OpenClipboard 失败 err=%lu（别的进程占着剪贴板？）\n", GetLastError());
        return 2;
    }
    EmptyClipboard();

    HGLOBAL textHg = GlobalAlloc(GMEM_MOVEABLE, (wcslen(kSecret) + 1) * sizeof(wchar_t));
    if (textHg) {
        void* p = GlobalLock(textHg);
        memcpy(p, kSecret, (wcslen(kSecret) + 1) * sizeof(wchar_t));
        GlobalUnlock(textHg);
        if (!SetClipboardData(CF_UNICODETEXT, textHg)) {
            printf("SetClipboardData(CF_UNICODETEXT) 失败 err=%lu\n", GetLastError());
            GlobalFree(textHg);
        }
    }

    SIZE_T realDibSize = 0;
    HGLOBAL dibHg = MakeRealDib(W, H, kRealRed, &realDibSize);
    if (dibHg && !SetClipboardData(CF_DIB, dibHg)) {
        printf("SetClipboardData(CF_DIB) 失败 err=%lu\n", GetLastError());
        GlobalFree(dibHg);
        dibHg = nullptr;
    }

    HBITMAP realBmp = nullptr;
    {
        HDC screen = GetDC(nullptr);
        realBmp = CreateCompatibleBitmap(screen, W, H);
        HDC mem = CreateCompatibleDC(screen);
        HGDIOBJ old = SelectObject(mem, realBmp);
        RECT rc = { 0, 0, W, H };
        HBRUSH br = CreateSolidBrush(RGB(255, 0, 0));
        FillRect(mem, &rc, br);
        DeleteObject(br);
        SelectObject(mem, old);
        DeleteDC(mem);
        ReleaseDC(nullptr, screen);
    }
    if (realBmp && !SetClipboardData(CF_BITMAP, realBmp)) {
        printf("SetClipboardData(CF_BITMAP) 失败 err=%lu\n", GetLastError());
        DeleteObject(realBmp);
        realBmp = nullptr;
    }

    CloseClipboard();

    // ============================================================= 阶段 0：基线
    printf("\n--- 阶段 0：基线（未挂任何 hook，负对照）---\n");
    wchar_t baseText[128] = {};
    bool baseTextOk = false;
    {
        if (!OpenClipboardRetry(20)) { printf("  OpenClipboard 失败\n"); return 2; }
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (h) {
            const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
            if (p) {
                wcsncpy_s(baseText, p, _TRUNCATE);
                GlobalUnlock(h);
                baseTextOk = true;
            }
        }
        CloseClipboard();
    }
    printf("  读回文本 = \"%ls\"\n", baseTextOk ? baseText : L"(失败)");

    bool baseDibOk = false;
    {
        if (!OpenClipboardRetry(20)) { printf("  OpenClipboard 失败\n"); return 2; }
        HANDLE h = GetClipboardData(CF_DIB);
        if (h) {
            size_t hb = 0;
            baseDibOk = DibHeaderOf(h, &hb) && !DibPixelsAllZero(h, hb);
        }
        CloseClipboard();
    }

    DWORD baseBmpPx = 0;
    bool baseBmpOk = false;
    {
        if (!OpenClipboardRetry(20)) { printf("  OpenClipboard 失败\n"); return 2; }
        HANDLE h = GetClipboardData(CF_BITMAP);
        if (h) baseBmpOk = BitmapPixelAt(static_cast<HBITMAP>(h), 0, 0, &baseBmpPx);
        CloseClipboard();
    }
    printf("  位图像素[0,0] = 0x%08lX\n", static_cast<unsigned long>(baseBmpPx));

    Check("基线：GetClipboardData 读到真实文本", baseTextOk && wcscmp(baseText, kSecret) == 0);
    Check("基线：CF_DIB 是真实内容（头部合法且像素非全 0）", baseDibOk);
    Check("基线：CF_BITMAP 是真实内容（非黑）", baseBmpOk && baseBmpPx != 0);

    // ============================================================= 阶段 1：挂 hook
    printf("\n--- 阶段 1：挂 user32!GetClipboardData + CloseClipboard（替换开）---\n");
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        printf("  MH_Initialize = %d (%s)\n", st, MH_StatusToString(st));
        return 2;
    }

    st = MH_CreateHook(ProcOf(L"user32.dll", "GetClipboardData"),
        reinterpret_cast<LPVOID>(GetClipboardData_Detour),
        reinterpret_cast<LPVOID*>(&g_origGetClipboardData));
    printf("  MH_CreateHook(GetClipboardData) = %d (%s)\n", st, MH_StatusToString(st));
    if (st != MH_OK) {
        Check("能挂上 user32!GetClipboardData", false);
        MH_Uninitialize();
        return 1;
    }

    st = MH_CreateHook(ProcOf(L"user32.dll", "CloseClipboard"),
        reinterpret_cast<LPVOID>(CloseClipboard_Detour),
        reinterpret_cast<LPVOID*>(&g_origCloseClipboard));
    printf("  MH_CreateHook(CloseClipboard) = %d (%s)\n", st, MH_StatusToString(st));
    if (st != MH_OK) {
        Check("能挂上 user32!CloseClipboard", false);
        MH_Uninitialize();
        return 1;
    }

    MH_EnableHook(MH_ALL_HOOKS);
    InterlockedExchange(&g_spoofOn, 1);

    // ---- B. 替换回传句柄 ----
    wchar_t spoofText[128] = {};
    HANDLE spoofTextHandle = nullptr;
    HANDLE realTextHandleSeen = nullptr;
    HGLOBAL spoofDibHandle = nullptr;
    HANDLE realDibHandleSeen = nullptr;
    HBITMAP spoofBmpHandle = nullptr;
    HANDLE realBmpHandleSeen = nullptr;
    {
        if (!OpenClipboardRetry(20)) { printf("  OpenClipboard 失败\n"); return 2; }

        // ⚠️ 每读完一次**立刻**把 detour 记下的真实句柄抓走 —— 它下一次
        //    调用就会被覆盖，而且只在"剪贴板开着"这段时间有效。

        // ① 文本
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        realTextHandleSeen = g_lastRealHandle;
        if (h) {
            spoofTextHandle = h;
            const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
            if (p) {
                wcsncpy_s(spoofText, p, _TRUNCATE);
                GlobalUnlock(h);
            }
        }

        // ② DIB
        HANDLE h2 = GetClipboardData(CF_DIB);
        realDibHandleSeen = g_lastRealHandle;
        if (h2) spoofDibHandle = static_cast<HGLOBAL>(h2);

        // ③ 位图
        HANDLE h3 = GetClipboardData(CF_BITMAP);
        realBmpHandleSeen = g_lastRealHandle;
        if (h3) spoofBmpHandle = static_cast<HBITMAP>(h3);

        // ---- D. 未误伤源：真实 DIB 句柄此刻**还在契约有效期内**，核对它 ----
        bool realIntact = false;
        size_t realHeaderBytes = 0;
        if (realDibHandleSeen) {
            realIntact = DibHeaderOf(realDibHandleSeen, &realHeaderBytes)
                && !DibPixelsAllZero(realDibHandleSeen, realHeaderBytes);
        }

        printf("  读回文本 = \"%ls\"（长度 %zu）\n", spoofText, wcslen(spoofText));
        printf("  detour 命中=%ld 次  造出替代物=%ld 个\n", g_hits, g_built);

        Check("替换生效：文本被换成空串", spoofText[0] == L'\0');
        Check("替换生效：返回的文本句柄 ≠ 真实文本句柄（是另一块内存）",
            spoofTextHandle != nullptr && realTextHandleSeen != nullptr
            && spoofTextHandle != realTextHandleSeen);
        Check("替换生效：返回的位图句柄 ≠ 真实位图句柄",
            spoofBmpHandle != nullptr && realBmpHandleSeen != nullptr
            && reinterpret_cast<HANDLE>(spoofBmpHandle) != realBmpHandleSeen);
        Check("返回码完好：拿到的是**可用句柄**而非 nullptr（与 Block 的分水岭）",
            spoofTextHandle != nullptr && spoofDibHandle != nullptr && spoofBmpHandle != nullptr);
        Check("原函数确实被调用过（detour 命中 >= 1）", g_hits >= 1);
        Check("未误伤源：剪贴板本体的真实 DIB 仍是真内容（只换了返回值）", realIntact);

        // ---- 内容合法性（"同格式"而不是"随便一块内存"）----
        if (spoofDibHandle) {
            size_t hb = 0;
            const bool hdrOk = DibHeaderOf(spoofDibHandle, &hb);
            const SIZE_T fakeSize = GlobalSize(spoofDibHandle);

            const BYTE* fp = static_cast<const BYTE*>(GlobalLock(spoofDibHandle));
            int fw = 0, fhc = 0; WORD fbc = 0;
            bool headerSame = false;
            if (fp) {
                const BITMAPINFOHEADER* fh = reinterpret_cast<const BITMAPINFOHEADER*>(fp);
                fw = fh->biWidth;
                fhc = fh->biHeight;
                fbc = fh->biBitCount;
                if (realDibHandleSeen && realHeaderBytes != 0) {
                    const BYTE* rp = static_cast<const BYTE*>(GlobalLock(realDibHandleSeen));
                    if (rp) {
                        headerSame = memcmp(fp, rp, realHeaderBytes) == 0;
                        GlobalUnlock(realDibHandleSeen);
                    }
                }
                GlobalUnlock(spoofDibHandle);
            }

            printf("  替代 DIB：%d x %d @ %u bit，共 %lu 字节（真实请求 %lu 字节）\n",
                fw, fhc, fbc, static_cast<unsigned long>(fakeSize),
                static_cast<unsigned long>(realDibSize));

            Check("替代 DIB：头部合法（DibHeaderBytes 认得出）", hdrOk);
            Check("替代 DIB：与真实**同尺寸同位深**（\"同格式\"而非随便一块）",
                fw == W && (fhc == H || fhc == -H) && fbc == 32);
            Check("替代 DIB：头部 + 调色板字节与真实**逐字节相同**", headerSame);
            Check("替代 DIB：不小于真实大小（没有截断）", fakeSize >= realDibSize);
            Check("替代 DIB：像素字节全 0（内容被中性化）",
                hb != 0 && DibPixelsAllZero(spoofDibHandle, hb));
        }
        else {
            Check("替代 DIB 存在", false);
        }

        if (spoofBmpHandle) {
            BITMAP bm = {};
            const int got = GetObjectW(spoofBmpHandle, sizeof(bm), &bm);
            DWORD px = 0xFFFFFFFF;
            const bool pxOk = BitmapPixelAt(spoofBmpHandle, 0, 0, &px);
            printf("  替代位图：%ld x %ld @ %u bit，像素[0,0]=0x%08lX\n",
                bm.bmWidth, bm.bmHeight, bm.bmBitsPixel, static_cast<unsigned long>(px));
            Check("替代位图：是合法 HBITMAP 且同尺寸",
                got != 0 && bm.bmWidth == W && bm.bmHeight == H);
            Check("替代位图：内容全黑", pxOk && px == 0);
        }
        else {
            Check("替代位图存在", false);
        }

        // ---- C. 契约终点：CloseClipboard 回收 ----
        const LONG releasedBefore = g_released;
        CloseClipboard();
        const LONG releasedAfter = g_released;

        printf("  CloseClipboard 后：回收 %ld 个（此前累计 %ld）\n",
            releasedAfter - releasedBefore, releasedBefore);

        Check("CloseClipboard 时替代物被回收（3 个：文本 + DIB + 位图）",
            releasedAfter - releasedBefore == 3);
        Check("回收后再查：替代 DIB 句柄已失效（GlobalSize == 0）",
            spoofDibHandle != nullptr && GlobalSize(spoofDibHandle) == 0);
        // ⚠️ 判据串里不要写 `⇒` 这类非 CP936 字符：窄字符串会被按 ANSI
        //    代码页编码，落在 CP936 之外就报 C4566（铁律 133）。
        Check("回收后所有槽都已清空（没有残留，不会重复释放）", !AnySlotInUse());
        Check("槽没有溢出（正常 open/close 配对下不该发生）", g_overflow == 0);
    }

    // ---- E. 不可伪造的格式 ----
    printf("\n--- 阶段 2：不可伪造的格式必须拒绝伪造 ---\n");
    {
        // CF_HDROP(15)：文件列表，布局我们造不出。
        const FakeKind k15 = ClassifyFormat(15);
        // 注册格式（>= 0xC000）同理。
        const FakeKind kReg = ClassifyFormat(0xC001);

        Check("CF_HDROP(15) 判为不可伪造", k15 == FakeKind::Unsupported);
        Check("注册格式(0xC001) 判为不可伪造", kReg == FakeKind::Unsupported);
        Check("BuildFake 对不可伪造格式返回 nullptr（调用方据此回落拒绝）",
            BuildFake(15, reinterpret_cast<HANDLE>(dibHg)) == nullptr);

        // 反向：支持的那几个必须**判为支持**（否则闸门只会"永远绿"）。
        Check("CF_TEXT(1)/CF_BITMAP(2)/CF_OEMTEXT(7)/CF_DIB(8)/CF_UNICODETEXT(13)/CF_DIBV5(17) 判为可伪造",
            ClassifyFormat(1) == FakeKind::Text &&
            ClassifyFormat(2) == FakeKind::Bitmap &&
            ClassifyFormat(7) == FakeKind::Text &&
            ClassifyFormat(8) == FakeKind::Dib &&
            ClassifyFormat(13) == FakeKind::Text &&
            ClassifyFormat(17) == FakeKind::Dib);
    }

    // ---- 关掉替换：必须回到"原样返回" ----
    printf("\n--- 阶段 3：关掉替换（负对照 —— 必须拿到真内容）---\n");
    InterlockedExchange(&g_spoofOn, 0);
    {
        wchar_t offText[128] = {};
        bool ok = false;
        if (OpenClipboardRetry(20)) {
            HANDLE h = GetClipboardData(CF_UNICODETEXT);
            if (h) {
                const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
                if (p) { wcsncpy_s(offText, p, _TRUNCATE); GlobalUnlock(h); ok = true; }
            }
            CloseClipboard();
        }
        printf("  读回文本 = \"%ls\"\n", ok ? offText : L"(失败)");
        Check("关掉替换后拿到的是真实内容（证明前面的\"空串\"确实来自替换）",
            ok && wcscmp(offText, kSecret) == 0);
    }

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    // ---- 清理 ----
    if (OpenClipboardRetry(20)) {
        EmptyClipboard();
        CloseClipboard();
    }

    printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("结论：detour 内「真调原函数 → 换成自己的句柄 → 返回成功」在剪贴板面可行；\n");
        printf("      且句柄所有权（CloseClipboard 回收）能按契约闭合。\n");
    }

    return g_fail == 0 ? 0 : 1;
}
