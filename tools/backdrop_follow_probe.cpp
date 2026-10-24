// backdrop_follow_probe.cpp -- 量「玻璃到底跟不跟背景」。
//
// 为什么需要它（用户原话："文字的背景没变吗？我拖动了都没变化的"）：
//
//   玻璃面板的最终颜色是 `面板色 = tint × 色调 + (1 - tint) × 背后的玻璃`。
//   `tint` 越大越像"实色板"，背后的东西就透不出来 —— 拖窗口时整块界面
//   一动不动，观感就是**贴了一张静态图**。
//
//   v117 把面板从 `Card()`(tint 0.70) 换成 `PieceR(..., 0.72f, Sunken, KCard)`
//   —— 为了让面板比画布**暗一档**（分区），tint 反而更实了。
//   于是"分区"有了、"跟手"没了。这两个指标是**互相拉扯**的，光看截图分不清
//   到底是"透得少"还是"根本没重抓"，所以必须量。
//
// 怎么量（不需要人眼、不需要拖动鼠标）：
//
//   1. 在窗口**背后**放一块纯色窗口（全屏，垫到 HWND_BOTTOM）；
//   2. 起 cfg（`--page 0`，不连引擎、不注入）；
//   3. 依次做三件事，每次做完等界面稳定再抓一次屏幕：
//        ① 背景=红，窗口@A          -> 基线
//        ② 背景=蓝，窗口**不动**    -> 量"背景变了跟不跟"
//        ③ 背景=蓝，窗口移到 B      -> 量"窗口动了跟不跟"
//   4. 报两个数：
//        · 面板跟随率 = Δ面板 / Δ画布   （0 = 死色板；0.28 = tint 0.72 的理论值）
//        · 分区强度   = 画布 − 面板     （v117 的判据要求 >= 25）
//
//   ★ 判据必须是"跟不跟"，不能是"颜色好不好看" —— 后者没法自动判。
//
// 用法:
//   tools/backdrop_follow_probe.exe ["<cfg.exe 的绝对路径>"]
//   不带参数就用 dist 里那份（发布布局，和用户看到的一致）。
//
// ⚠️ 全程 `--page 0`：**不初始化引擎、不注入**（铁律 175 不适用）。

#include <windows.h>
#include <stdio.h>

#include <string>

#include <r3shieldcore/cfg_launch.h>

namespace {

// ---- 取样区域（**客户区**坐标，与 tools/check_cfg_pills.py 同一套）---------
//   面板 = 配置页表单面板内部的空白处；
//   画布 = 左右两块面板之间那道缝（不受面板影响，只反映背景）。
struct Region { int x0, y0, x1, y1; const char* name; };
const Region kRegions[] = {
    { 700, 480, 820, 560, "面板" },
    { 222, 420, 234, 600, "画布" },
    { 660, 218, 800, 232, "字段" },
};
const int kRegionCount = static_cast<int>(sizeof(kRegions) / sizeof(kRegions[0]));

// ---- 背景窗口 ------------------------------------------------------------
COLORREF g_backdropColor = RGB(220, 30, 30);
HWND     g_backdropWnd = nullptr;

LRESULT CALLBACK BackdropProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_ERASEBKGND: {
        RECT rc = {};
        GetClientRect(hwnd, &rc);
        HBRUSH br = CreateSolidBrush(g_backdropColor);
        FillRect(reinterpret_cast<HDC>(wp), &rc, br);
        DeleteObject(br);
        return 1;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps = {};
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc = {};
        GetClientRect(hwnd, &rc);
        HBRUSH br = CreateSolidBrush(g_backdropColor);
        FillRect(dc, &rc, br);
        DeleteObject(br);
        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

bool CreateBackdrop()
{
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = BackdropProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hbrBackground = nullptr;   // 自己填，避免闪烁
    wc.lpszClassName = L"R3ScBackdropProbeWnd";
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    const int sw = GetSystemMetrics(SM_CXSCREEN);
    const int sh = GetSystemMetrics(SM_CYSCREEN);
    g_backdropWnd = CreateWindowExW(0, wc.lpszClassName, L"backdrop",
        WS_POPUP | WS_VISIBLE, 0, 0, sw, sh,
        nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_backdropWnd) {
        return false;
    }
    // ★ 不要 `HWND_BOTTOM`：那是 Z 序**最底**，会掉到 Progman（桌面）下面 ⇒
    //   窗口存在、但屏幕上根本看不见（踩过：抓到的背景均值 245 = 白桌面，
    //   玻璃只能变白卡片，看着像"玻璃不跟背景"）。
    //   新建窗口本来就在非 topmost 的最上面，cfg 起来后自然压在它上面。
    UpdateWindow(g_backdropWnd);
    return true;
}

void SetBackdrop(COLORREF c)
{
    g_backdropColor = c;
    if (g_backdropWnd) {
        InvalidateRect(g_backdropWnd, nullptr, TRUE);
        UpdateWindow(g_backdropWnd);
    }
}

// ---- 找窗口 --------------------------------------------------------------
BOOL CALLBACK FindProc(HWND hwnd, LPARAM lp)
{
    wchar_t cls[128] = {};
    if (GetClassNameW(hwnd, cls, _countof(cls)) > 0
        && wcscmp(cls, R3ShieldCoreCfg::kWindowClass) == 0) {
        *reinterpret_cast<HWND*>(lp) = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND FindCfgWindow()
{
    HWND found = nullptr;
    EnumWindows(FindProc, reinterpret_cast<LPARAM>(&found));
    return found;
}

// ---- 抓图 + 取样 ---------------------------------------------------------
struct Sample { double r, g, b; };

bool CaptureRegion(HWND hwnd, Sample* out, int count)
{
    // ★ 只在这里做一次 ClientToScreen：传进来的是**客户区**坐标（0,0 起）。
    //   踩过：外层先把 `GetWindowRect` 的**屏幕**矩形传进来，这里又
    //   ClientToScreen 一次 ⇒ 抓图原点被平移了两倍窗口位置，量的是别处的像素
    //   （症状：面板比画布还亮、画布恒 242 一动不动）。
    POINT origin = { 0, 0 };
    ClientToScreen(hwnd, &origin);
    RECT clientRc = {};
    GetClientRect(hwnd, &clientRc);
    const int w = clientRc.right - clientRc.left;
    const int h = clientRc.bottom - clientRc.top;
    if (w <= 0 || h <= 0) {
        return false;
    }

    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;   // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP dib = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!dib) {
        DeleteDC(mem);
        ReleaseDC(nullptr, screen);
        return false;
    }
    HGDIOBJ oldBmp = SelectObject(mem, dib);
    const BOOL ok = BitBlt(mem, 0, 0, w, h, screen, origin.x, origin.y, SRCCOPY);
    SelectObject(mem, oldBmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);

    if (!ok) {
        DeleteObject(dib);
        return false;
    }

    const BYTE* px = static_cast<const BYTE*>(bits);
    for (int i = 0; i < count; ++i) {
        const Region& rg = kRegions[i];
        const int x0 = rg.x0;
        const int y0 = rg.y0;
        const int x1 = rg.x1;
        const int y1 = rg.y1;
        long long sr = 0, sg = 0, sb = 0;
        long long n = 0;
        for (int y = y0; y < y1 && y < h; ++y) {
            for (int x = x0; x < x1 && x < w; ++x) {
                if (x < 0 || y < 0) { continue; }
                const BYTE* p = px + (static_cast<size_t>(y) * w + x) * 4;
                sb += p[0]; sg += p[1]; sr += p[2];
                ++n;
            }
        }
        out[i].r = n ? static_cast<double>(sr) / n : 0.0;
        out[i].g = n ? static_cast<double>(sg) / n : 0.0;
        out[i].b = n ? static_cast<double>(sb) / n : 0.0;
    }
    DeleteObject(dib);
    return true;
}

void PrintRow(const char* tag, const Sample* s, int count)
{
    // ★ 一律用**窄**字面量 + %s：`printf("%ls")` 依赖 C locale，
    //   默认 "C" 时整行**静默截断**（铁律 252，这个坑踩过一次）。
    printf("%s", tag);
    for (int i = 0; i < count; ++i) {
        printf("  %s=(%3.0f,%3.0f,%3.0f)", kRegions[i].name, s[i].r, s[i].g, s[i].b);
    }
    printf("\n");
    fflush(stdout);
}

// 亮度：判"跟不跟"要看**总量**，别被某一个通道的偶然同向抵消。
double Lum(const Sample& s) { return 0.299 * s.r + 0.587 * s.g + 0.114 * s.b; }

// 三个通道差里最大的那个（取绝对值）—— 与 check_cfg_pills.py 同口径。
double Max3(double a, double b, double c)
{
    double m = (a < 0 ? -a : a);
    const double b2 = (b < 0 ? -b : b);
    const double c2 = (c < 0 ? -c : c);
    if (b2 > m) { m = b2; }
    if (c2 > m) { m = c2; }
    return m;
}

}  // namespace

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(936);

    wchar_t exe[MAX_PATH] = {};
    if (argc >= 2 && argv[1][0]) {
        wcscpy_s(exe, argv[1]);
    } else {
        wcscpy_s(exe, L"dist\\R3ShieldCore-x64\\r3shieldcore-cfg.exe");
    }
    wchar_t full[MAX_PATH] = {};
    if (!GetFullPathNameW(exe, MAX_PATH, full, nullptr)) {
        printf("[败] 路径不合法: %ls\n", exe);
        return 2;
    }
    if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) {
        printf("[败] 找不到 %ls\n", full);
        return 2;
    }

    if (!CreateBackdrop()) {
        printf("[败] 建不出背景窗口（err=%lu）\n", GetLastError());
        return 2;
    }

    // ---- 起 cfg（--page 0 = 配置页；不连引擎、不注入）----
    //
    // ★ 诊断必须落到**文件**：cfg 的 `[glass] ...` 全在 stdout，而探针最后是
    //   TerminateProcess 收尾 —— 块缓冲里的内容会整段丢掉（实测：不落盘就一行
    //   日志都看不到，只能靠猜）。cfg 自己认 `R3SHIELDCORE_PREVIEW_LOG`，
    //   所以这里只给路径，不要自己接句柄（铁律 127：同一件事不写两遍）。
    // ★ 路径必须**绝对**：cfg 用 `_wfreopen_s` 打开它，而子进程的 cwd 是
    //   exe 所在目录（dist）—— 相对路径会落到那边一个不存在的目录里，
    //   freopen 静默失败，一行日志都拿不到（踩过）。
    wchar_t kChildLog[MAX_PATH] = {};
    {
        wchar_t here[MAX_PATH] = {};
        GetCurrentDirectoryW(MAX_PATH, here);
        _snwprintf_s(kChildLog, MAX_PATH, _TRUNCATE,
            L"%s\\obj\\probe\\backdrop_follow_child.log", here);
        CreateDirectoryW(L"obj\\probe", nullptr);
        DeleteFileW(kChildLog);
    }
    SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_LOG", kChildLog);

    // ★ 必须关掉"永久排除自身抓屏"（`WDA_EXCLUDEFROMCAPTURE`）。
    //
    //   v106 起 cfg 默认 `liveCapture = true` ⇒ `EnsureBackdrop()` 会把窗口
    //   **永久**排除在屏幕捕获之外。那个排除对用户是好事（录屏看不到它），
    //   但探针正是靠 BitBlt 屏幕读它的像素 ⇒ 读到的是**背后的背景**，
    //   三个取样点会一模一样（实测：面板/画布/字段全是 (220,30,30)）。
    //   关掉之后 `CaptureRegion` 仍然会在抓的瞬间**临时**排除一次，
    //   所以玻璃自己抓到的背景依然是对的（日志仍写"来源=真桌面"）。
    SetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_NO_WDA", L"1");

    std::wstring cmd = L"\"" + std::wstring(full) + L"\" --page 0";
    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::wstring cwd(full);
    const size_t slash = cwd.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        cwd.resize(slash);
    }
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                        0, nullptr, cwd.c_str(), &si, &pi)) {
        printf("[败] 起不来 cfg（err=%lu）\n", GetLastError());
        DestroyWindow(g_backdropWnd);
        return 2;
    }

    HWND hwnd = nullptr;
    for (int i = 0; i < 100 && !hwnd; ++i) {
        Sleep(100);
        hwnd = FindCfgWindow();
    }
    if (!hwnd) {
        printf("[败] 10s 内没等到 cfg 窗口（class=%ls）\n", R3ShieldCoreCfg::kWindowClass);
        TerminateProcess(pi.hProcess, 0);
        DestroyWindow(g_backdropWnd);
        return 2;
    }

    RECT cr = {};
    GetClientRect(hwnd, &cr);
    printf("[probe] cfg 客户区 %dx%d\n",
        static_cast<int>(cr.right), static_cast<int>(cr.bottom));

    // 只负责摆位置。抓图范围由 CaptureRegion 自己从**客户区**算
    // —— 不要在这里把 GetWindowRect 的屏幕矩形传下去：那边还会再
    //    ClientToScreen 一次，原点被平移两倍（踩过，症状是画布恒 242 不动）。
    auto placeAt = [&](int x, int y) {
        SetWindowPos(hwnd, HWND_TOP, x, y, 0, 0,
            SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
        // 摆完先把 WM_MOVE 的处理（重抓背景 + 重绘）走完
        UpdateWindow(hwnd);
    };

    Sample s1[kRegionCount] = {}, s2[kRegionCount] = {}, s3[kRegionCount] = {};

    // ① 基线：红背景，窗口在 A
    SetBackdrop(RGB(220, 30, 30));
    placeAt(120, 90);
    Sleep(1000);
    if (!CaptureRegion(hwnd, s1, kRegionCount)) {
        printf("[败] 抓图失败\n");
        TerminateProcess(pi.hProcess, 0);
        DestroyWindow(g_backdropWnd);
        return 2;
    }
    PrintRow("[1] 背景=红 窗口@A", s1, kRegionCount);

    // ② 只换背景，窗口**不动** —— 量"背景变了跟不跟"
    SetBackdrop(RGB(30, 40, 220));
    Sleep(1000);
    if (!CaptureRegion(hwnd, s2, kRegionCount)) {
        printf("[败] 抓图失败\n");
        TerminateProcess(pi.hProcess, 0);
        DestroyWindow(g_backdropWnd);
        return 2;
    }
    PrintRow("[2] 背景=蓝 窗口@A", s2, kRegionCount);

    // ③ 再动窗口 —— 量"窗口动了跟不跟"
    placeAt(230, 170);
    Sleep(1000);
    if (!CaptureRegion(hwnd, s3, kRegionCount)) {
        printf("[败] 抓图失败\n");
        TerminateProcess(pi.hProcess, 0);
        DestroyWindow(g_backdropWnd);
        return 2;
    }
    PrintRow("[3] 背景=蓝 窗口@B", s3, kRegionCount);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DestroyWindow(g_backdropWnd);

    // ---- 结论 ------------------------------------------------------------
    //
    // 判据用**亮度**：红→蓝 这一步画布亮度变化很大（红 220,30,30 的亮度 ~89，
    // 蓝 30,40,220 的亮度 ~59 —— 差 30 级）。若面板/字段一级都不动，
    // 说明它们没跟着背景走。
    //
    // 理论值（tint=0.72）：面板跟随率应当是 **0.28**。
    // 所以判据分三档，能直接告诉人"该改什么"：
    //   >= 0.15  : 跟得上（玻璃感在）
    //   0.05~0.15: 太钝（tint 偏实，拖窗口几乎看不出变化）
    //   < 0.05   : 没跟（背景根本没重抓，或者被实色盖住了）
    printf("\n==== 结论 ====\n");
    const double canvas1 = Lum(s1[1]), canvas2 = Lum(s2[1]), canvas3 = Lum(s3[1]);
    printf("画布亮度: %.1f -> %.1f（换背景） -> %.1f（移动窗口）\n",
        canvas1, canvas2, canvas3);

    int bad = 0;
    for (int i = 0; i < kRegionCount; ++i) {
        if (i == 1) { continue; }   // 画布本身是参考，不判
        const double d12 = Lum(s2[i]) - Lum(s1[i]);   // 换背景引起的变化
        const double d13 = Lum(s3[i]) - Lum(s1[i]);   // 移动窗口引起的变化
        const double dRef = canvas2 - canvas1;
        const double ratio = (dRef > 1.0 || dRef < -1.0) ? (d12 / dRef) : 0.0;
        const wchar_t* verdict = (ratio >= 0.15) ? L"跟得上"
            : (ratio >= 0.05 ? L"太钝（tint 偏实）" : L"没跟（死色板）");
        printf("  %ls: 换背景 Δ=%+5.1f  移动窗口 Δ=%+5.1f  跟随率=%+.2f  -> %ls\n",
            kRegions[i].name, d12, d13, ratio, verdict);
        if (ratio < 0.15) {
            ++bad;
        }
    }

    // ---- 分区强度：用**最大单通道差**，不用亮度差 ------------------------
    //
    // ★ 为什么不能用亮度差：
    //   玻璃面板是"背景的调色版"。在高饱和背景上（实测纯蓝 145,150,233），
    //   面板 (147,152,207) 的**亮度**和画布几乎一样，但蓝通道差 26 ——
    //   肉眼一眼就能分出两块。亮度差判据会把这个正常结果判成红，
    //   逼着人把面板做成实色板，那正是 v117 走过的弯路（分区有了、不跟背景）。
    //   ⇒ 与 `tools/check_cfg_pills.py` 第 ⑧ 条同一个口径：最大单通道差 >= 20。
    const double dR = s3[0].r - s3[1].r;
    const double dG = s3[0].g - s3[1].g;
    const double dB = s3[0].b - s3[1].b;
    const double sepMax = Max3(dR, dG, dB);
    printf("  分区强度（面板 vs 画布，最大单通道差）= %.1f（要求 >= 20；"
           "亮度比 %.2f 只作参考）\n", sepMax,
           (canvas3 > 1.0) ? (Lum(s3[0]) / canvas3) : 1.0);
    if (sepMax < 20.0) {
        ++bad;
    }

    printf("\n%ls\n", bad == 0 ? L"PASS：面板/字段都跟着背景走，且分区还在"
                              : L"FAIL：见上面逐项");
    return bad == 0 ? 0 : 1;
}
