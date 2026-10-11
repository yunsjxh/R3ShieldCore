//
// spoof_retdata_probe.cpp —— 实证：detour 内「拦截并替换回传数据」到底行不行。
//
// 这是《回传数据替换Hook-技术预研》的 Phase 1 验证探针。它**不经过引擎**、
// **不需要注入器**，在一个进程里自己挂自己的 hook，回答四个问题：
//
//   A. 基线（负对照）：不挂 hook 时，GetDIBits 读回的像素是真实内容吗？
//      —— 没有这一条，后面的"变成了黑"无法归因（铁律 110：空真）。
//   B. 替换 out 缓冲区：detour 里「先真调原函数 → 再把 lpvBits 覆盖成伪造内容 →
//      返回原返回值」，调用者拿到的是伪造内容吗？返回码还完好（= 调用"成功"）吗？
//      —— 这正是 Spoof 与 Block 的分水岭：Block 返回**失败**，Spoof 返回**成功 + 假数据**。
//   C. 多路径戳穿：只替换 GetDIBits，同一张位图用 GetPixel 读，是真实还是伪造？
//      —— 若仍是真实，则实证「替换一条路径 ≠ 覆盖这件事」（预研 §6.2）。
//   D. 对象状态替换：BitBlt 的"回传数据"不是 out 指针，而是目标 DC 的内容。
//      detour 里真调原函数后把目标区域涂黑，目标 DC 读回是黑的吗？源 DC 未受影响吗？
//
// 为什么能这么测：hook 与调用者在**同一进程**，out 参数就在调用者地址空间，
// 可直接读写。真实引擎里多出来的只是「注入」与「判据来源」，机制完全相同。
//
// ⚠️ 本探针只碰**自己进程内自己创建的位图**，不注入任何进程、不读屏幕、不写盘。
//
// 编译：bash build_spoof_probe.sh
// 运行：./tools/spoof_retdata_probe.exe
//
#include <windows.h>
#include <stdio.h>
#include <MinHook.h>

// ------------------------------------------------------------------ 状态
static int g_pass = 0;
static int g_fail = 0;

typedef int  (WINAPI* GetDIBits_t)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);
typedef BOOL (WINAPI* BitBlt_t)(HDC, int, int, int, int, HDC, int, int, DWORD);

static GetDIBits_t g_origGetDIBits = nullptr;
static BitBlt_t    g_origBitBlt    = nullptr;

static volatile LONG g_spoofGetDIBits = 0;   // 1 = 允许 detour 改写像素
static volatile LONG g_spoofBitBlt    = 0;   // 1 = 允许 detour 涂黑目标

static volatile LONG g_getDibitsHits   = 0;
static volatile LONG g_bitbltHits      = 0;
static volatile LONG g_spoofedDibPixels = 0;

// DIB 32bpp 像素的 DWORD 是 BGRA 内存序（0x00RRGGBB 读法）——
// 与 GetPixel 的 COLORREF（0x00BBGGRR）**顺序相反**，别混（铁律 172：打印核对）。
static const DWORD kRealRedDib  = 0x00FF0000;  // 红：B=00 G=00 R=FF
static const DWORD kFakeBlack   = 0x00000000;  // 伪造：全黑
static const DWORD kDstInit     = 0x00112233;  // 目标初始色（可识别，非黑非红）

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ detour: GetDIBits
//
// GetDIBits 的"回传数据"= out 参数 lpvBits 指向的像素缓冲区，外加返回的扫描行数。
// 替换策略：**先真调**（拿到真实句柄状态与真实行数），**再改缓冲区**，
// **返回原返回值** —— 调用者完全看不出发生过什么。
//
static int WINAPI GetDIBits_Detour(HDC hdc, HBITMAP hbm, UINT start, UINT cLines,
                                   LPVOID lpvBits, LPBITMAPINFO lpbmi, UINT usage)
{
    InterlockedIncrement(&g_getDibitsHits);

    // (1) 真调原函数 —— 真实数据写进 lpvBits，真实副作用发生。
    const int lines = g_origGetDIBits(hdc, hbm, start, cLines, lpvBits, lpbmi, usage);

    // (2) 改写回传数据 —— 只在"要求替换"且确实是 32bpp 像素输出时动手。
    if (g_spoofGetDIBits != 0 && lines > 0 && lpvBits != nullptr && lpbmi != nullptr
        && lpbmi->bmiHeader.biBitCount == 32)
    {
        __try {
            // out 参数在**调用者地址空间**，同进程可直接写。
            // 但目标页可能只读 / 已释放 ⇒ 必须 __try 护住（铁律 97：失败要可见）。
            DWORD* px = reinterpret_cast<DWORD*>(lpvBits);
            const LONG w = lpbmi->bmiHeader.biWidth;
            LONG h = lpbmi->bmiHeader.biHeight;
            if (h < 0) h = -h;
            LONG rows = static_cast<LONG>(lines);
            if (rows > h) rows = h;
            const size_t n = static_cast<size_t>(w) * static_cast<size_t>(rows);
            for (size_t i = 0; i < n; ++i) {
                px[i] = kFakeBlack;
            }
            InterlockedExchange(&g_spoofedDibPixels, static_cast<LONG>(n));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("    (detour) 写 lpvBits 抛异常，替换未生效\n");
        }
    }

    // (3) 返回**原**返回值 —— 调用者看到"成功"（与 Block 的分水岭）。
    return lines;
}

// ------------------------------------------------------------------ detour: BitBlt
//
// BitBlt 没有 out 指针；它的"回传数据"是**目标 DC 的内容**（对象状态）。
// 替换策略：真调原函数（真实拷贝发生）→ 再把目标区域涂黑。
// PatBlt 不经 BitBlt ⇒ 无递归。
//
static BOOL WINAPI BitBlt_Detour(HDC hdcDest, int x, int y, int cx, int cy,
                                 HDC hdcSrc, int x1, int y1, DWORD rop)
{
    InterlockedIncrement(&g_bitbltHits);

    const BOOL ok = g_origBitBlt(hdcDest, x, y, cx, cy, hdcSrc, x1, y1, rop);

    if (g_spoofBitBlt != 0 && ok) {
        PatBlt(hdcDest, x, y, cx, cy, BLACKNESS);
    }
    return ok;
}

// ------------------------------------------------------------------ 工具
static void FillDib(void* bits, int w, int h, DWORD color)
{
    DWORD* px = reinterpret_cast<DWORD*>(bits);
    const size_t n = static_cast<size_t>(w) * static_cast<size_t>(h);
    for (size_t i = 0; i < n; ++i) px[i] = color;
}

// 走 GetDIBits 读一张位图（会被 detour 拦截）。
static int ReadDib(HDC dc, HBITMAP bm, int w, int h, DWORD* out)
{
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;   // 负高度 = top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    ZeroMemory(out, sizeof(DWORD) * static_cast<size_t>(w) * static_cast<size_t>(h));
    SetLastError(0);
    return GetDIBits(dc, bm, 0, static_cast<UINT>(h), out, &bi, DIB_RGB_COLORS);
}

static LPVOID ProcOf(LPCWSTR module, LPCSTR name)
{
    HMODULE m = GetModuleHandleW(module);
    if (!m) return nullptr;
    return reinterpret_cast<LPVOID>(GetProcAddress(m, name));
}

// ------------------------------------------------------------------ main
int main()
{
    printf("=== 回传数据替换探针（自挂自测，不经过引擎）===\n");
    printf("进程 pid=%u  架构=%s\n", GetCurrentProcessId(),
#ifdef _WIN64
        "x64"
#else
        "x86"
#endif
    );

    const int W = 8, H = 4;
    DWORD readback[W * H] = {};

    // ---- 造"真实内容"：源 DIB 填红 ----
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = W;
    bmi.bmiHeader.biHeight = -H;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    HDC screen = GetDC(nullptr);
    void* srcBits = nullptr;
    HBITMAP srcBmp = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &srcBits, nullptr, 0);
    HDC srcDc = CreateCompatibleDC(screen);
    if (!srcBmp || !srcBits || !srcDc) {
        printf("CreateDIBSection/CreateCompatibleDC 失败 err=%lu\n", GetLastError());
        return 2;
    }
    FillDib(srcBits, W, H, kRealRedDib);
    HGDIOBJ oldSrc = SelectObject(srcDc, srcBmp);

    void* dstBits = nullptr;
    HBITMAP dstBmp = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &dstBits, nullptr, 0);
    HDC dstDc = CreateCompatibleDC(screen);
    if (!dstBmp || !dstBits || !dstDc) {
        printf("目标位图创建失败 err=%lu\n", GetLastError());
        return 2;
    }
    FillDib(dstBits, W, H, kDstInit);
    HGDIOBJ oldDst = SelectObject(dstDc, dstBmp);

    // 打印实际像素值核对（铁律 172：别靠推断）。
    printf("源位图 直读内存像素[0] = 0x%08lX\n", reinterpret_cast<DWORD*>(srcBits)[0]);
    printf("目标位图 直读内存像素[0] = 0x%08lX\n", reinterpret_cast<DWORD*>(dstBits)[0]);

    // ============================================================= 阶段 0：基线
    printf("\n--- 阶段 0：基线（未挂任何 hook）---\n");
    int lines = ReadDib(srcDc, srcBmp, W, H, readback);
    const DWORD baseDib = readback[0];
    const COLORREF baseClr = GetPixel(srcDc, 0, 0);
    printf("  GetDIBits 返回行数=%d  像素[0]=0x%08lX\n", lines, baseDib);
    printf("  GetPixel(src,0,0)=0x%08lX (CLR_INVALID=0xFFFFFFFF)\n",
        static_cast<unsigned long>(baseClr));

    Check("基线：GetDIBits 读到真实内容（= 内存直读值，非黑）",
        baseDib == kRealRedDib && baseDib == reinterpret_cast<DWORD*>(srcBits)[0]);
    Check("基线：GetPixel 读到真实内容（两条路径一致，都非黑）",
        baseClr != CLR_INVALID && baseClr != 0);

    // ============================================================= 阶段 1：替换 GetDIBits
    printf("\n--- 阶段 1：只挂 gdi32!GetDIBits ---\n");
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        printf("  MH_Initialize = %d (%s)\n", st, MH_StatusToString(st));
        return 2;
    }

    st = MH_CreateHook(ProcOf(L"gdi32.dll", "GetDIBits"),
                       reinterpret_cast<LPVOID>(GetDIBits_Detour),
                       reinterpret_cast<LPVOID*>(&g_origGetDIBits));
    printf("  MH_CreateHook(GetDIBits) = %d (%s)\n", st, MH_StatusToString(st));
    if (st != MH_OK) {
        Check("能挂上 gdi32!GetDIBits", false);
    }
    else {
        st = MH_EnableHook(MH_ALL_HOOKS);
        printf("  MH_EnableHook = %d (%s)\n", st, MH_StatusToString(st));
        InterlockedExchange(&g_spoofGetDIBits, 1);

        lines = ReadDib(srcDc, srcBmp, W, H, readback);
        const DWORD spoofDib = readback[0];
        printf("  GetDIBits 返回行数=%d  像素[0]=0x%08lX\n", lines, spoofDib);
        printf("  detour 命中=%ld 次  改写像素=%ld 个\n",
            g_getDibitsHits, g_spoofedDibPixels);

        Check("替换生效：调用者拿到伪造像素（全黑）", spoofDib == kFakeBlack);
        Check("返回码完好：返回行数 > 0（调用者看到\"成功\"，非 Block）", lines > 0);
        Check("原函数确实被调用过（detour 命中 >= 1）", g_getDibitsHits >= 1);

        // ---- C. 多路径戳穿：换一条不经 GetDIBits 的读取路径 ----
        const COLORREF clrAfter = GetPixel(srcDc, 0, 0);
        printf("  GetPixel(src,0,0)=0x%08lX  （不经过 GetDIBits）\n",
            static_cast<unsigned long>(clrAfter));
        Check("多路径戳穿：GetPixel 仍读到真实内容（替换只覆盖了一条路）",
            clrAfter == baseClr && clrAfter != 0);

        MH_DisableHook(MH_ALL_HOOKS);
        InterlockedExchange(&g_spoofGetDIBits, 0);
    }

    // ============================================================= 阶段 2：替换 BitBlt
    printf("\n--- 阶段 2：只挂 gdi32!BitBlt ---\n");
    st = MH_CreateHook(ProcOf(L"gdi32.dll", "BitBlt"),
                       reinterpret_cast<LPVOID>(BitBlt_Detour),
                       reinterpret_cast<LPVOID*>(&g_origBitBlt));
    printf("  MH_CreateHook(BitBlt) = %d (%s)\n", st, MH_StatusToString(st));
    if (st != MH_OK) {
        Check("能挂上 gdi32!BitBlt", false);
    }
    else {
        MH_EnableHook(MH_ALL_HOOKS);
        InterlockedExchange(&g_spoofBitBlt, 1);

        SetLastError(0);
        const BOOL blt = BitBlt(dstDc, 0, 0, W, H, srcDc, 0, 0, SRCCOPY);
        const DWORD bltErr = GetLastError();

        // GetDIBits hook 已 Disable ⇒ 这里读回的是真实内容。
        const int dstLines = ReadDib(dstDc, dstBmp, W, H, readback);
        const DWORD dstPix = readback[0];
        const COLORREF dstClr = GetPixel(dstDc, 0, 0);

        const int srcLines = ReadDib(srcDc, srcBmp, W, H, readback);
        const DWORD srcPix = readback[0];
        (void)srcLines;

        printf("  BitBlt 返回=%d err=%lu  detour 命中=%ld 次\n", blt, bltErr, g_bitbltHits);
        printf("  目标 DC 像素[0]=0x%08lX (GetPixel=0x%08lX)  读回行数=%d\n",
            dstPix, static_cast<unsigned long>(dstClr), dstLines);
        printf("  源   DC 像素[0]=0x%08lX\n", srcPix);

        Check("对象状态替换：目标 DC 被涂黑（调用者看到 BitBlt 成功但内容是假的）",
            blt == TRUE && dstPix == kFakeBlack);
        Check("返回码完好：BitBlt 返回 TRUE", blt == TRUE);
        Check("未误伤源 DC：源仍是真实内容", srcPix == kRealRedDib);

        MH_DisableHook(MH_ALL_HOOKS);
        InterlockedExchange(&g_spoofBitBlt, 0);
    }

    MH_Uninitialize();

    // ============================================================= 汇总
    printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("结论：detour 内「真调原函数 → 改写回传数据 → 返回成功」在本机可行；\n");
        printf("      且实测到「多路径戳穿」——只替换一条获取路径，另一条仍给真实值。\n");
    }

    SelectObject(srcDc, oldSrc);
    SelectObject(dstDc, oldDst);
    DeleteObject(srcBmp);
    DeleteObject(dstBmp);
    DeleteDC(srcDc);
    DeleteDC(dstDc);
    ReleaseDC(nullptr, screen);

    return g_fail == 0 ? 0 : 1;
}
