// r3shot.cpp —— 通用截图器：窗口 / 矩形 / 全屏 / 鼠标拖框选区。
//
// 为什么要有它（与 gui_preview_probe 的分工）：
//   `gui_preview_probe` 是**闸门**：它自己拉起 exe、自己抓、自己断言，只认
//   `--gui-preview` 那一套几何，**抓不了"用户此刻看到的任意窗口"**。
//   而排查界面问题（"下拉框不圆""背景不跟"）时最缺的恰恰是
//   "把用户眼前那一下抓下来"的能力 —— 上一轮为了抓一张 cfg 图，得写
//   `gui_preview_probe.exe <exe> <tab> <out.bmp> "" <app>` 一长串，还得记住
//   `R3SHIELDCORE_PREVIEW_FREEZEBG=1`。本工具只做一件事：
//   **把屏幕上的任意矩形存成图片**，不带任何断言、不启动任何进程。
//
// 输出格式（两种，各有用处）：
//   · `.bmp` —— 32bpp BI_RGB **top-down**。与 `tools/check_cfg_pills.py` 的
//     `load_bmp()` 完全兼容（它只认这一种）⇒ **抓完可以直接喂判据**，
//     不用先转 PNG 再转回来。
//   · `.png` —— 走 GDI+，给 Read 工具 / 人眼看。
//
// 用法：
//   r3shot.exe                          交互：全屏冻结，鼠标拖框（Esc/右键取消）
//   r3shot.exe -o _t/a.png              同上，指定输出
//   r3shot.exe --full -o _t/full.bmp    整个虚拟桌面（多显示器合起来）
//   r3shot.exe --window cfg -o _t/c.png 标题含 "cfg" 的窗口
//   r3shot.exe --window cfg --client    只抓客户区（自绘窗口 = 内容区，无边框）
//   r3shot.exe --class R3ShieldCoreCfgWnd
//   r3shot.exe --pid 1234               该进程**最大**的可见顶层窗口
//   r3shot.exe --rect 182,182,1024,740  屏幕坐标矩形
//   r3shot.exe --list                   列出可见顶层窗口（hwnd/类名/标题/矩形）
//   --delay 800                         抓之前等 800ms（抓下拉展开、悬停态）
//   --raise                             抓窗口前先把它提到前台（否则抓到的可能是遮挡物）
//   --print-rect                        只打印目标矩形，不抓（配合 --rect 用）
//
// ★ 不带 `--full/--window/--class/--pid/--rect/--list` 时默认走**交互**模式。
//
// ⚠️ 抓不到东西的三种典型原因（工具会自己提示）：
//   1. 窗口被 `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` 排除
//      —— 抓出来是**纯黑**。本项目自己的探针就长期开着永久 WDA，踩过多次。
//   2. 窗口最小化（`IsIconic`）—— `GetWindowRect` 返回 (-32000,...)。
//   3. 被别的窗口完全遮住 —— 屏幕 DC 抓到的是遮挡物，加 `--raise`。
//
// 编译：bash build_r3shot.sh
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// GDI+ 的 C++ 头依赖这些先被包含（与 tools/bmp2png.cpp 同序）。
#include <objidl.h>
#include <gdiplus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <string>
#include <vector>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "msimg32.lib")

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

struct Image
{
    int w = 0;
    int h = 0;
    std::vector<unsigned char> px;   // BGRA，top-down（第 0 行是图像顶边）
};

// ★ 不用 printf("%ls")：默认 "C" locale 下它会**整行静默截断**（铁律 252，
//   本项目的探针踩过一次，区域名全打成空）。统一走 UTF-8 直出。
static void PrintW(const wchar_t* s)
{
    if (!s || !*s) {
        return;
    }
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
        return;
    }
    std::vector<char> buf((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, s, -1, buf.data(), n, nullptr, nullptr);
    fputs(buf.data(), stdout);
}

static void EnableDpiAwareness()
{
    // 不声明 DPI 感知的话：GetWindowRect 返回**被系统缩放过的逻辑坐标**，
    // 而 BitBlt 用的是物理像素 ⇒ 在 125%/150% 缩放下抓出来的图**错位且缺一块**。
    // 这个坑在截图工具上比在任何地方都更致命（图看着"就是不对"，但说不清哪不对）。
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (u32) {
        typedef BOOL(WINAPI* SetCtxFn)(HANDLE);
        auto fn = (SetCtxFn)GetProcAddress(u32, "SetProcessDpiAwarenessContext");
        // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4
        if (fn && fn((HANDLE)-4)) {
            return;
        }
    }
    SetProcessDPIAware();   // Win7/8 以及旧 Win10
}

static bool ContainsCI(const std::wstring& hay, const std::wstring& needle)
{
    if (needle.empty()) {
        return true;
    }
    if (hay.size() < needle.size()) {
        return false;
    }
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        size_t j = 0;
        for (; j < needle.size(); ++j) {
            wchar_t a = hay[i + j];
            wchar_t b = needle[j];
            if (a >= L'A' && a <= L'Z') { a = (wchar_t)(a - L'A' + L'a'); }
            if (b >= L'A' && b <= L'Z') { b = (wchar_t)(b - L'A' + L'a'); }
            if (a != b) {
                break;
            }
        }
        if (j == needle.size()) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// 抓屏
// ---------------------------------------------------------------------------

// 把屏幕坐标 (x,y,w,h) 抓进 out。
// ★ 全程只用**屏幕 DC + BitBlt**，不用 PrintWindow：
//   PrintWindow 对 OpenGL / 自绘窗口经常返回**全黑**（本项目的 cfg 就是自绘
//   OpenGL 场景），而屏幕 DC 拿到的是"用户真正看到的像素"，这才是有意义的那张。
static bool CaptureRect(int x, int y, int w, int h, Image& out)
{
    if (w <= 0 || h <= 0) {
        printf("r3shot: bad rect %dx%d\n", w, h);
        return false;
    }

    HDC screen = GetDC(nullptr);
    if (!screen) {
        printf("r3shot: GetDC(NULL) failed\n");
        return false;
    }
    HDC mem = CreateCompatibleDC(screen);

    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;          // ★ 负高度 = top-down，与判据脚本的约定一致
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP dib = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!dib || !bits) {
        printf("r3shot: CreateDIBSection failed (%dx%d)\n", w, h);
        DeleteDC(mem);
        ReleaseDC(nullptr, screen);
        return false;
    }

    HGDIOBJ old = SelectObject(mem, dib);
    // ★ CAPTUREBLT 必须有：不加的话 **WS_EX_LAYERED 窗口**整块抓不到
    //   （抓出来是它背后的东西）。玻璃卡片、通知气泡都是 layered 的。
    BOOL ok = BitBlt(mem, 0, 0, w, h, screen, x, y, SRCCOPY | CAPTUREBLT);
    GdiFlush();

    out.w = w;
    out.h = h;
    out.px.assign((unsigned char*)bits, (unsigned char*)bits + (size_t)w * (size_t)h * 4);

    // ★★★ 必须把 alpha 通道强制成 255。
    //   BitBlt 到 32bpp DIB section **不写第 4 字节**（它按 24/32bpp RGB 拷，
    //   第 4 字节保持 CreateDIBSection 时的 0）⇒ 直接交给 GDI+ 存 PNG，
    //   GDI+ 按 32bppARGB 解释 ⇒ **整张图全透明**（看着像"存了个空白"）。
    //   这一步在 CaptureRect 里做一次，交互模式裁剪出来的图也就跟着对了。
    {
        unsigned char* p = out.px.data();
        size_t n = (size_t)w * (size_t)h;
        for (size_t i = 0; i < n; ++i) {
            p[i * 4 + 3] = 255;
        }
    }

    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);

    if (!ok) {
        printf("r3shot: BitBlt failed (err=%lu)\n", (unsigned long)GetLastError());
        return false;
    }
    return true;
}

// 抽样判断"整张图是不是纯黑" —— 这是 WDA 排除 / 最小化 / DWM 没合成的共同症状。
// 不判的话用户只会看到一张黑图，然后去怀疑"截图器坏了"。
static bool LooksBlack(const Image& im)
{
    if (im.px.empty()) {
        return true;
    }
    const int stepX = im.w > 40 ? im.w / 20 : 1;
    const int stepY = im.h > 40 ? im.h / 20 : 1;
    for (int y = 0; y < im.h; y += stepY) {
        for (int x = 0; x < im.w; x += stepX) {
            size_t i = ((size_t)y * (size_t)im.w + (size_t)x) * 4;
            if (im.px[i] > 8 || im.px[i + 1] > 8 || im.px[i + 2] > 8) {
                return false;
            }
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// 存盘
// ---------------------------------------------------------------------------

static bool SaveBmp(const wchar_t* path, const Image& im)
{
    BITMAPFILEHEADER fh = {};
    BITMAPINFOHEADER ih = {};
    ih.biSize = sizeof(ih);
    ih.biWidth = im.w;
    ih.biHeight = -im.h;                 // top-down
    ih.biPlanes = 1;
    ih.biBitCount = 32;
    ih.biCompression = BI_RGB;
    ih.biSizeImage = (DWORD)((size_t)im.w * (size_t)im.h * 4);

    fh.bfType = 0x4D42;                  // "BM"
    fh.bfOffBits = sizeof(fh) + sizeof(ih);
    fh.bfSize = fh.bfOffBits + ih.biSizeImage;

    FILE* f = _wfopen(path, L"wb");
    if (!f) {
        printf("r3shot: cannot open output for write\n");
        return false;
    }
    bool ok = fwrite(&fh, sizeof(fh), 1, f) == 1 &&
              fwrite(&ih, sizeof(ih), 1, f) == 1 &&
              fwrite(im.px.data(), 1, im.px.size(), f) == im.px.size();
    fclose(f);
    return ok;
}

static int GetEncoderClsid(const WCHAR* mime, CLSID* clsid)
{
    UINT num = 0;
    UINT size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) {
        return -1;
    }
    std::vector<BYTE> buf((size_t)size);
    auto* codecs = (Gdiplus::ImageCodecInfo*)buf.data();
    Gdiplus::GetImageEncoders(num, size, codecs);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(codecs[i].MimeType, mime) == 0) {
            *clsid = codecs[i].Clsid;
            return (int)i;
        }
    }
    return -1;
}

static bool g_gdipOk = false;   // GdiPlusScope 构造成功后置位，SavePng 用它兜底

static bool SavePng(const wchar_t* path, const Image& im)
{
    if (!g_gdipOk) {
        printf("r3shot: GDI+ unavailable - use a .bmp output path\n");
        return false;
    }
    HDC screen = GetDC(nullptr);
    if (!screen) {
        return false;
    }

    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = im.w;
    bi.bmiHeader.biHeight = -im.h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP hbm = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, screen);
    if (!hbm || !bits) {
        return false;
    }
    memcpy(bits, im.px.data(), im.px.size());

    bool ok = false;
    {
        Gdiplus::Bitmap bmp(hbm, nullptr);
        CLSID clsid;
        if (GetEncoderClsid(L"image/png", &clsid) >= 0) {
            ok = (bmp.Save(path, &clsid, nullptr) == Gdiplus::Ok);
        }
    }
    DeleteObject(hbm);
    return ok;
}

// GDI+ 的生命周期。
// ★ 忘了 `GdiplusStartup` 就调 `GetImageEncodersSize` / `Bitmap::Save`，
//   在 x64 上**直接段错误**（不是返回错误码 —— 上一版就是这么崩的，
//   而 `--full -o *.bmp` 走的是自己写的 BMP 头，所以"BMP 好好的、PNG 一崩"）。
//   用 RAII 而不是在 wmain 里手工 Startup/Shutdown：wmain 有 5 条 return 路径。
struct GdiPlusScope
{
    ULONG_PTR token = 0;
    bool ok = false;

    GdiPlusScope()
    {
        Gdiplus::GdiplusStartupInput in;
        ok = (Gdiplus::GdiplusStartup(&token, &in, nullptr) == Gdiplus::Ok);
    }
    ~GdiPlusScope()
    {
        if (ok) {
            Gdiplus::GdiplusShutdown(token);
        }
    }
    GdiPlusScope(const GdiPlusScope&) = delete;
    GdiPlusScope& operator=(const GdiPlusScope&) = delete;
};

static bool HasSuffixCI(const std::wstring& s, const wchar_t* suffix)
{
    size_t n = wcslen(suffix);
    if (s.size() < n) {
        return false;
    }
    return _wcsicmp(s.c_str() + (s.size() - n), suffix) == 0;
}

static bool SaveAny(const std::wstring& path, const Image& im)
{
    // 扩展名决定格式：`.bmp` 走自己写的 40 头（判据脚本吃这个），
    // 其余（含无扩展名）一律 PNG。
    if (HasSuffixCI(path, L".bmp")) {
        return SaveBmp(path.c_str(), im);
    }
    return SavePng(path.c_str(), im);
}

static std::wstring DefaultOutPath(const std::wstring& wantExt)
{
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    wchar_t buf[96] = {};
    swprintf_s(buf, L"shot-%04d%02d%02d-%02d%02d%02d%s",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        wantExt.empty() ? L".png" : wantExt.c_str());
    return buf;
}

// ---------------------------------------------------------------------------
// 窗口枚举
// ---------------------------------------------------------------------------

struct WinInfo
{
    HWND hwnd = nullptr;
    std::wstring cls;
    std::wstring title;
    RECT rc = {};
};

static BOOL CALLBACK EnumProc(HWND h, LPARAM lp)
{
    auto* out = (std::vector<WinInfo>*)lp;
    if (!IsWindowVisible(h)) {
        return TRUE;
    }
    RECT rc = {};
    GetWindowRect(h, &rc);
    if (rc.right <= rc.left || rc.bottom <= rc.top) {
        return TRUE;
    }
    wchar_t cls[256] = {};
    GetClassNameW(h, cls, 256);
    wchar_t title[512] = {};
    GetWindowTextW(h, title, 512);

    WinInfo wi;
    wi.hwnd = h;
    wi.cls = cls;
    wi.title = title;
    wi.rc = rc;
    out->push_back(wi);
    return TRUE;
}

// 列出窗口。★ 不过滤"没标题"的窗口：排查时最有用的往往就是那些
// 没有标题的壳（Progman / WorkerW / 各种 IME 宿主），过滤掉等于自断线索。
static void ListWindows()
{
    std::vector<WinInfo> all;
    EnumWindows(EnumProc, (LPARAM)&all);

    wprintf(L"%-12s %-34s %-40s %s\n", L"HWND", L"CLASS", L"TITLE", L"RECT");
    for (const auto& w : all) {
        wchar_t line[256] = {};
        swprintf_s(line, L"%d,%d %dx%d",
            (int)w.rc.left, (int)w.rc.top,
            (int)(w.rc.right - w.rc.left), (int)(w.rc.bottom - w.rc.top));
        wprintf(L"0x%08p  ", (void*)w.hwnd);
        PrintW(w.cls.c_str());
        printf("%s", w.cls.size() < 32 ? "                                " : "  ");
        PrintW(w.title.c_str());
        printf("  ");
        PrintW(line);
        printf("\n");
    }
    printf("\n%d window(s)\n", (int)all.size());
}

// ---------------------------------------------------------------------------
// 交互：全屏冻结 + 拖框
// ---------------------------------------------------------------------------

namespace pick
{
    Image g_frozen;
    HDC g_frozenDc = nullptr;
    HBITMAP g_frozenBmp = nullptr;
    int g_w = 0;
    int g_h = 0;

    bool g_drag = false;
    POINT g_start = {};
    RECT g_sel = {};
    bool g_ok = false;

    // 8x8 纯黑、alpha=110 的位图，用来把选区**外面**压暗。
    // 为什么不用棋盘刷：棋盘在亮背景上像马赛克，看着像抓坏了；
    // AlphaBlend 出来的才是"变暗"的正常观感。
    HBITMAP g_dimBmp = nullptr;
    HDC g_dimDc = nullptr;

    const wchar_t* kClass = L"R3ShotPickWnd";

    void MakeDimBitmap()
    {
        HDC screen = GetDC(nullptr);
        BITMAPINFO bi = {};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = 8;
        bi.bmiHeader.biHeight = -8;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;

        void* bits = nullptr;
        g_dimBmp = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (g_dimBmp && bits) {
            // BGRA = 0,0,0,110（黑 + 43% 不透明）
            unsigned char* p = (unsigned char*)bits;
            for (int i = 0; i < 8 * 8; ++i) {
                p[i * 4 + 0] = 0;
                p[i * 4 + 1] = 0;
                p[i * 4 + 2] = 0;
                p[i * 4 + 3] = 110;
            }
            g_dimDc = CreateCompatibleDC(screen);
            SelectObject(g_dimDc, g_dimBmp);
        }
        ReleaseDC(nullptr, screen);
    }

    void DimRect(HDC dc, int x, int y, int w, int h)
    {
        if (w <= 0 || h <= 0 || !g_dimDc) {
            return;
        }
        BLENDFUNCTION bf = {};
        bf.BlendOp = AC_SRC_OVER;
        bf.SourceConstantAlpha = 255;   // 透明度已在像素 alpha 里
        bf.AlphaFormat = AC_SRC_ALPHA;
        AlphaBlend(dc, x, y, w, h, g_dimDc, 0, 0, 8, 8, bf);
    }

    void DrawSelection(HDC dc)
    {
        RECT s = g_sel;
        // 归一化（用户可以从右下往左上拖）
        if (s.right < s.left) { int t = s.left; s.left = s.right; s.right = t; }
        if (s.bottom < s.top) { int t = s.top; s.top = s.bottom; s.bottom = t; }
        if (s.right - s.left <= 0 || s.bottom - s.top <= 0) {
            return;
        }

        // 选区外压暗（4 块）
        DimRect(dc, 0, 0, g_w, s.top);
        DimRect(dc, 0, s.bottom, g_w, g_h - s.bottom);
        DimRect(dc, 0, s.top, s.left, s.bottom - s.top);
        DimRect(dc, s.right, s.top, g_w - s.right, s.bottom - s.top);

        // 边框：外 1px 深色 + 内 1px 亮色 ⇒ 在亮背景和暗背景上都看得见。
        HPEN dark = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
        HPEN light = CreatePen(PS_SOLID, 1, RGB(0, 174, 255));
        HGDIOBJ oldPen = SelectObject(dc, dark);
        HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        Rectangle(dc, s.left, s.top, s.right, s.bottom);
        SelectObject(dc, light);
        Rectangle(dc, s.left + 1, s.top + 1, s.right - 1, s.bottom - 1);
        SelectObject(dc, oldBrush);
        SelectObject(dc, oldPen);
        DeleteObject(dark);
        DeleteObject(light);

        // 尺寸标签：贴在选框**上方**（放里面会盖住要看的内容）
        wchar_t label[64] = {};
        swprintf_s(label, L"%d x %d", (int)(s.right - s.left), (int)(s.bottom - s.top));

        HDC dcTmp = dc;
        SetBkMode(dcTmp, TRANSPARENT);
        HFONT font = CreateFontW(-16, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        HGDIOBJ oldFont = SelectObject(dcTmp, font);

        SIZE sz = {};
        GetTextExtentPoint32W(dcTmp, label, (int)wcslen(label), &sz);
        int tx = s.left;
        int ty = s.top - sz.cy - 6;
        if (ty < 0) {
            ty = s.top + 4;          // 顶到屏幕外就翻到里面
        }
        RECT bg = { tx - 4, ty - 2, tx + sz.cx + 4, ty + sz.cy + 2 };
        HBRUSH bb = CreateSolidBrush(RGB(0, 120, 200));
        FillRect(dcTmp, &bg, bb);
        DeleteObject(bb);
        SetTextColor(dcTmp, RGB(255, 255, 255));
        TextOutW(dcTmp, tx, ty, label, (int)wcslen(label));

        SelectObject(dcTmp, oldFont);
        DeleteObject(font);
    }

    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        switch (msg) {
        case WM_SETCURSOR:
            SetCursor(LoadCursorW(nullptr, IDC_CROSS));
            return TRUE;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            if (g_frozenDc) {
                BitBlt(dc, 0, 0, g_w, g_h, g_frozenDc, 0, 0, SRCCOPY);
            }
            if (g_drag) {
                DrawSelection(dc);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_LBUTTONDOWN:
            SetCapture(hwnd);
            g_drag = true;
            g_start.x = (LONG)(short)LOWORD(lp);
            g_start.y = (LONG)(short)HIWORD(lp);
            g_sel = { g_start.x, g_start.y, g_start.x, g_start.y };
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;

        case WM_MOUSEMOVE:
            if (g_drag) {
                POINT p = { (LONG)(short)LOWORD(lp), (LONG)(short)HIWORD(lp) };
                g_sel = { g_start.x, g_start.y, p.x, p.y };
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;

        case WM_LBUTTONUP: {
            ReleaseCapture();
            g_drag = false;
            POINT p = { (LONG)(short)LOWORD(lp), (LONG)(short)HIWORD(lp) };
            g_sel = { g_start.x, g_start.y, p.x, p.y };
            // 归一化后再判"有没有真的选到东西"
            if (g_sel.right < g_sel.left) { LONG t = g_sel.left; g_sel.left = g_sel.right; g_sel.right = t; }
            if (g_sel.bottom < g_sel.top) { LONG t = g_sel.top; g_sel.top = g_sel.bottom; g_sel.bottom = t; }
            g_ok = (g_sel.right - g_sel.left >= 2 && g_sel.bottom - g_sel.top >= 2);
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            return 0;
        }

        case WM_RBUTTONDOWN:
        case WM_MBUTTONDOWN:
            g_ok = false;
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            return 0;

        case WM_KEYDOWN:
            if (wp == VK_ESCAPE) {
                g_ok = false;
                PostMessageW(hwnd, WM_CLOSE, 0, 0);
            }
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;

        default:
            break;
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

// 交互选区。返回 false = 用户取消。
// vx/vy/vw/vh = 虚拟屏（多显示器合起来的那个矩形）。
static bool RunInteractive(int vx, int vy, int vw, int vh, Image& out, RECT& selScreen)
{
    using namespace pick;

    if (!CaptureRect(vx, vy, vw, vh, g_frozen)) {
        return false;
    }
    g_w = vw;
    g_h = vh;

    // 冻结图放进一个内存 DC，WM_PAINT 里反复贴
    HDC screen = GetDC(nullptr);
    g_frozenDc = CreateCompatibleDC(screen);
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = g_w;
    bi.bmiHeader.biHeight = -g_h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    g_frozenBmp = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, screen);
    if (!g_frozenBmp || !bits) {
        printf("r3shot: cannot build frozen bitmap\n");
        return false;
    }
    memcpy(bits, g_frozen.px.data(), g_frozen.px.size());
    SelectObject(g_frozenDc, g_frozenBmp);

    MakeDimBitmap();

    HINSTANCE hinst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hinst;
    wc.hCursor = LoadCursorW(nullptr, IDC_CROSS);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kClass;
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        kClass, L"r3shot",
        WS_POPUP,
        vx, vy, vw, vh,
        nullptr, nullptr, hinst, nullptr);
    if (!hwnd) {
        printf("r3shot: CreateWindowEx failed (err=%lu)\n", (unsigned long)GetLastError());
        return false;
    }

    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    SetFocus(hwnd);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    bool ok = g_ok;
    if (ok) {
        // 从冻结图里裁出选区（注意减去虚拟屏原点）
        int x = (int)g_sel.left;
        int y = (int)g_sel.top;
        int w = (int)(g_sel.right - g_sel.left);
        int h = (int)(g_sel.bottom - g_sel.top);

        out.w = w;
        out.h = h;
        out.px.resize((size_t)w * (size_t)h * 4);
        for (int row = 0; row < h; ++row) {
            size_t src = ((size_t)(y + row) * (size_t)g_w + (size_t)x) * 4;
            memcpy(out.px.data() + (size_t)row * (size_t)w * 4,
                   g_frozen.px.data() + src, (size_t)w * 4);
        }
        selScreen.left = vx + x;
        selScreen.top = vy + y;
        selScreen.right = selScreen.left + w;
        selScreen.bottom = selScreen.top + h;
    }

    if (g_dimDc) { DeleteDC(g_dimDc); }
    if (g_dimBmp) { DeleteObject(g_dimBmp); }
    if (g_frozenDc) { DeleteDC(g_frozenDc); }
    if (g_frozenBmp) { DeleteObject(g_frozenBmp); }
    return ok;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

static void Usage()
{
    printf(
        "r3shot - screen capture (window / rect / full / drag-select)\n"
        "\n"
        "  r3shot.exe                          interactive: freeze screen, drag a box\n"
        "  r3shot.exe --full                   whole virtual desktop\n"
        "  r3shot.exe --window <substr>        window whose title contains <substr>\n"
        "  r3shot.exe --class <substr>         window whose class name contains <substr>\n"
        "  r3shot.exe --pid <n>                largest visible window of process <n>\n"
        "  r3shot.exe --rect x,y,w,h           screen rectangle\n"
        "  r3shot.exe --list                   list visible top-level windows\n"
        "\n"
        "  -o, --out <path>   output; .bmp = 32bpp top-down (feeds check_cfg_pills.py),\n"
        "                     anything else = png. default: shot-<timestamp>.png\n"
        "  --client           capture client area only (no border/title)\n"
        "  --delay <ms>       wait before capturing (for open dropdowns / hover)\n"
        "  --raise            bring the target window to front before capturing\n"
        "  --print-rect       only print the target rect, do not capture\n"
        "  -h, --help         this help\n"
        "\n"
        "notes:\n"
        "  * a pure-black capture usually means the window is excluded from capture\n"
        "    (SetWindowDisplayAffinity / WDA_EXCLUDEFROMCAPTURE) or minimized.\n"
        "  * the screen DC is used on purpose: PrintWindow returns black for\n"
        "    OpenGL / self-drawn windows.\n");
}

int wmain(int argc, wchar_t** argv)
{
    EnableDpiAwareness();

    // ★ 必须在任何 GDI+ 调用之前（见 GdiPlusScope 注释）。
    GdiPlusScope gdip;
    g_gdipOk = gdip.ok;
    if (!gdip.ok) {
        printf("r3shot: GdiplusStartup failed - png output unavailable\n");
    }

    std::wstring outPath;
    std::wstring titleNeedle;
    std::wstring classNeedle;
    DWORD pid = 0;
    RECT rect = {};
    bool haveRect = false;
    bool wantFull = false;
    bool wantList = false;
    bool wantClient = false;
    bool wantRaise = false;
    bool printRectOnly = false;
    int delayMs = 0;

    for (int i = 1; i < argc; ++i) {
        const wchar_t* a = argv[i];
        if (!wcscmp(a, L"-h") || !wcscmp(a, L"--help")) {
            Usage();
            return 0;
        } else if (!wcscmp(a, L"-o") || !wcscmp(a, L"--out")) {
            if (i + 1 < argc) { outPath = argv[++i]; }
        } else if (!wcscmp(a, L"--full")) {
            wantFull = true;
        } else if (!wcscmp(a, L"--list")) {
            wantList = true;
        } else if (!wcscmp(a, L"--window")) {
            if (i + 1 < argc) { titleNeedle = argv[++i]; }
        } else if (!wcscmp(a, L"--class")) {
            if (i + 1 < argc) { classNeedle = argv[++i]; }
        } else if (!wcscmp(a, L"--pid")) {
            if (i + 1 < argc) { pid = (DWORD)_wtoi(argv[++i]); }
        } else if (!wcscmp(a, L"--rect")) {
            if (i + 1 < argc) {
                int x = 0, y = 0, w = 0, h = 0;
                if (swscanf_s(argv[++i], L"%d,%d,%d,%d", &x, &y, &w, &h) == 4) {
                    rect.left = x; rect.top = y;
                    rect.right = x + w; rect.bottom = y + h;
                    haveRect = true;
                } else {
                    printf("r3shot: --rect needs x,y,w,h\n");
                    return 2;
                }
            }
        } else if (!wcscmp(a, L"--client")) {
            wantClient = true;
        } else if (!wcscmp(a, L"--delay")) {
            if (i + 1 < argc) { delayMs = _wtoi(argv[++i]); }
        } else if (!wcscmp(a, L"--raise")) {
            wantRaise = true;
        } else if (!wcscmp(a, L"--print-rect")) {
            printRectOnly = true;
        } else {
            printf("r3shot: unknown option\n");
            PrintW(a);
            printf("\n");
            Usage();
            return 2;
        }
    }

    if (wantList) {
        ListWindows();
        return 0;
    }

    if (delayMs > 0) {
        Sleep((DWORD)delayMs);
    }

    // ---- 决定抓哪儿 ----
    Image shot;
    RECT sel = {};

    bool needWindow = !titleNeedle.empty() || !classNeedle.empty() || pid != 0;

    if (haveRect) {
        sel = rect;
    } else if (wantFull) {
        sel.left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        sel.top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        sel.right = sel.left + GetSystemMetrics(SM_CXVIRTUALSCREEN);
        sel.bottom = sel.top + GetSystemMetrics(SM_CYVIRTUALSCREEN);
    } else if (needWindow) {
        std::vector<WinInfo> all;
        EnumWindows(EnumProc, (LPARAM)&all);

        // ★★ 选**面积最大**的那个，不是"第一个匹配的"。
        //   一个进程（甚至一个类名）往往挂着好几个可见顶层窗口：
        //   explorer 名下就有 `ThumbnailDeviceHelperWnd`(1x1)、
        //   `Progman`、`Shell_TrayWnd`、真正的文件夹窗口……
        //   取第一个 ⇒ `--pid <explorer>` 会抓到那个 **1x1 的辅助窗**，
        //   输出一张 1x1 的图，看着像工具坏了（实测就是这么踩到的）。
        const WinInfo* hit = nullptr;
        long bestArea = -1;
        int candidates = 0;
        for (const auto& w : all) {
            if (!titleNeedle.empty() && !ContainsCI(w.title, titleNeedle)) {
                continue;
            }
            if (!classNeedle.empty() && !ContainsCI(w.cls, classNeedle)) {
                continue;
            }
            if (pid != 0) {
                DWORD wp = 0;
                GetWindowThreadProcessId(w.hwnd, &wp);
                if (wp != pid) {
                    continue;
                }
            }
            ++candidates;
            long area = (long)(w.rc.right - w.rc.left) * (long)(w.rc.bottom - w.rc.top);
            if (area > bestArea) {
                bestArea = area;
                hit = &w;
            }
        }
        if (!hit) {
            printf("r3shot: no visible window matched (try --list)\n");
            return 3;
        }
        if (candidates > 1) {
            printf("r3shot: %d windows matched, picked the largest\n", candidates);
        }
        if (IsIconic(hit->hwnd)) {
            printf("r3shot: target window is minimized\n");
            return 3;
        }
        if (wantRaise) {
            SetForegroundWindow(hit->hwnd);
            Sleep(220);      // 让 DWM 把新 Z 序合成完，否则抓到的是旧的遮挡关系
        }
        if (wantClient) {
            RECT cr = {};
            GetClientRect(hit->hwnd, &cr);
            POINT tl = { 0, 0 };
            ClientToScreen(hit->hwnd, &tl);
            sel.left = tl.x;
            sel.top = tl.y;
            sel.right = tl.x + (cr.right - cr.left);
            sel.bottom = tl.y + (cr.bottom - cr.top);
        } else {
            sel = hit->rc;
        }
        printf("r3shot: hwnd=0x%08p ", (void*)hit->hwnd);
        PrintW(hit->cls.c_str());
        printf(" \"");
        PrintW(hit->title.c_str());
        printf("\"\n");
    } else {
        // ---- 交互选区 ----
        int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (!RunInteractive(vx, vy, vw, vh, shot, sel)) {
            printf("r3shot: cancelled\n");
            return 1;
        }
        if (outPath.empty()) {
            outPath = DefaultOutPath(L".png");
        }
        bool saved = SaveAny(outPath, shot);
        printf("r3shot: %dx%d at (%d,%d) -> ", shot.w, shot.h, (int)sel.left, (int)sel.top);
        PrintW(outPath.c_str());
        printf("%s\n", saved ? "" : "  [SAVE FAILED]");
        return saved ? 0 : 4;
    }

    int w = (int)(sel.right - sel.left);
    int h = (int)(sel.bottom - sel.top);
    if (printRectOnly) {
        printf("%d,%d,%d,%d\n", (int)sel.left, (int)sel.top, w, h);
        return 0;
    }

    if (!CaptureRect((int)sel.left, (int)sel.top, w, h, shot)) {
        return 4;
    }

    if (outPath.empty()) {
        outPath = DefaultOutPath(L".png");
    }
    bool saved = SaveAny(outPath, shot);

    printf("r3shot: %dx%d at (%d,%d) -> ", w, h, (int)sel.left, (int)sel.top);
    PrintW(outPath.c_str());
    printf("%s\n", saved ? "" : "  [SAVE FAILED]");

    if (saved && LooksBlack(shot)) {
        printf("r3shot: WARNING - capture is almost entirely black.\n"
               "        likely the window is excluded from capture\n"
               "        (SetWindowDisplayAffinity / WDA_EXCLUDEFROMCAPTURE),\n"
               "        minimized, or nothing was drawn yet. try --raise or --delay.\n");
    }

    return saved ? 0 : 4;
}
