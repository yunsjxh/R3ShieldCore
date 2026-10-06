// gui_copy_all_logs_probe.cpp -- 端到端验证「复制全部日志」按钮。
//
// 这个按钮的用途：机器快被病毒毁了、日志文件马上取不出来时，把**引擎目录下
// 所有 *.log 的内容**拼成一段文本塞进剪贴板 —— 剪贴板是系统被毁前唯一还能把
// 证据带出去的通道（虚拟机开共享剪贴板时，在宿主机 Ctrl+V 即可）。
//
// 做法（遵循 win32-selfdrawn-ui-verify）：
//   1. 拉起**免提权**的 BuildCheck exe（同完整性级别，否则 UIPI 静默丢输入）。
//   2. 按类名找到窗口，记客户区宽 + 屏幕原点。
//   3. 用**和 app 同一套公式**算出「复制全部日志」按钮矩形（镜像 CopyAllLogsButtonRect）。
//   4. 从**屏幕** BitBlt 该矩形，取"像素指纹"（证明按钮画出来了、点完变了）。
//   5. **反向对照**：先点一个中性点 —— 剪贴板必须**没变**（证明确实是按钮干的）。
//   6. 点按钮 -> 读剪贴板 -> 必须含导出头 + 引擎目录 + 预先放好的 marker 日志内容。
//
// 断言优先级：剪贴板内容（确定性，能证"内容对"） > 像素（只证"画成什么样"）。
//
// ★ 一个已知干扰：发布的 r3shieldcore.ini 里 mode=block + hook_clipboard=1，
//   而 clipboard_guard 把 ClipboardOp::Read（GetClipboardData）判高危并在
//   block 下**真拦**（clipboard_guard.cpp:128）。也就是说：引擎活着时，本探针
//   自己读剪贴板会被引擎拦掉 —— 这不是 bug，是引擎在正常工作。
//   所以跑这个探针时，BuildCheck/r3shieldcore.ini 要把 hook_clipboard 关掉
//   （只关这一条，其余保持发布配置）。探针会把 Open/Get 的 err 打出来，
//   如果看到 err=5 且剪贴板没变，先查这一条。

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>

namespace {

constexpr PCWSTR kClassName = L"R3ShieldCoreMainWindow";

// ---- 与 r3shieldcore_gui.cpp 保持一致的布局常量（改那边要同步改这里）----
constexpr int Padding = 20;
constexpr int TabBarTop = 62;
constexpr int TabBarHeight = 38;
constexpr int ModeButtonWidth = 112;
constexpr int ActionButtonWidth = 92;
constexpr int ActionButtonGap = 8;
constexpr int TabWidth = 84;
constexpr int TabCount = 5;   // v62: 多了 ARK 页

struct Rect { int left, top, right, bottom; };

// 镜像 r3shieldcore_gui.cpp 的：
//   ClearStats   = { cw - Pad - ModeW - Gap - ActionW .. }
//   CopyLog      = ClearStats 左边一个
//   CopyAllLogs  = CopyLog 左边一个
//   ExitEngine   = CopyAllLogs 左边一个
Rect CopyAllLogsButtonRect(int clientWidth)
{
    const int clearRight = clientWidth - Padding - ModeButtonWidth - ActionButtonGap;
    const int clearLeft = clearRight - ActionButtonWidth;
    const int copyLeft = clearLeft - ActionButtonGap - ActionButtonWidth;
    const int allLeft = copyLeft - ActionButtonGap - ActionButtonWidth;
    const int allRight = copyLeft - ActionButtonGap;
    return { allLeft, TabBarTop + 4, allRight, TabBarTop + TabBarHeight - 4 };
}

int TabStripRight()
{
    return Padding + TabCount * (TabWidth + 8) - 8;
}

struct Signature
{
    int nonWhite = 0;
    unsigned long long checksum = 0;
    bool valid = false;

    bool operator==(const Signature& other) const
    {
        return nonWhite == other.nonWhite && checksum == other.checksum;
    }
    std::string Text() const
    {
        char buffer[128] = {};
        sprintf_s(buffer, "nonWhite=%d sum=%016llx", nonWhite, checksum);
        return buffer;
    }
};

// 从屏幕 BitBlt 指定客户区矩形，算指纹。
// ★ 用屏幕 BitBlt 而不是 PrintWindow —— 后者拿的是 DWM 合成缓存，动态内容
//   （点了按钮后文字变「已复制」）永远"没变"。
Signature CaptureSignature(HWND hwnd, const Rect& clientRect)
{
    Signature result;

    POINT origin = { 0, 0 };
    if (!ClientToScreen(hwnd, &origin)) {
        return result;
    }
    const int sx = origin.x + clientRect.left;
    const int sy = origin.y + clientRect.top;
    const int w = clientRect.right - clientRect.left;
    const int h = clientRect.bottom - clientRect.top;
    if (w <= 0 || h <= 0) {
        return result;
    }

    HDC screen = GetDC(nullptr);
    HDC memory = CreateCompatibleDC(screen);
    HBITMAP bitmap = CreateCompatibleBitmap(screen, w, h);
    HGDIOBJ oldBitmap = SelectObject(memory, bitmap);

    const BOOL blt = BitBlt(memory, 0, 0, w, h, screen, sx, sy, SRCCOPY);

    BITMAPINFO info = {};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = w;
    info.bmiHeader.biHeight = -h; // 自上而下
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    std::vector<unsigned char> pixels(static_cast<size_t>(w) * h * 4);
    const int lines = GetDIBits(memory, bitmap, 0, h, pixels.data(), &info, DIB_RGB_COLORS);

    SelectObject(memory, oldBitmap);
    DeleteObject(bitmap);
    DeleteDC(memory);
    ReleaseDC(nullptr, screen);

    if (!blt || lines == 0) {
        printf("[probe] WARN: BitBlt/GetDIBits failed (blt=%d lines=%d)\n", blt, lines);
        return result;
    }

    for (int i = 0; i < w * h; ++i) {
        const unsigned char b = pixels[i * 4 + 0];
        const unsigned char g = pixels[i * 4 + 1];
        const unsigned char r = pixels[i * 4 + 2];
        if (!(r > 245 && g > 245 && b > 245)) {
            ++result.nonWhite;
        }
        result.checksum = result.checksum * 1000003ULL + (r << 16 | g << 8 | b);
    }
    result.valid = true;
    return result;
}

void PostMouse(HWND hwnd, UINT message, int x, int y, WPARAM button)
{
    PostMessage(hwnd, message, button, MAKELPARAM(x, y));
}

// ---- 剪贴板助手（都要重试：剪贴板经常被别的进程短时占用）----
bool SetClipboardUtf16(const std::wstring& text, DWORD* err)
{
    for (int i = 0; i < 20; ++i) {
        if (!OpenClipboard(nullptr)) {
            *err = GetLastError();
            Sleep(50);
            continue;
        }
        EmptyClipboard();
        const size_t bytes = (text.size() + 1) * sizeof(WCHAR);
        HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (!mem) {
            *err = GetLastError();
            CloseClipboard();
            Sleep(50);
            continue;
        }
        void* p = GlobalLock(mem);
        if (!p) {
            *err = GetLastError();
            GlobalFree(mem);
            CloseClipboard();
            Sleep(50);
            continue;
        }
        memcpy(p, text.c_str(), bytes);
        GlobalUnlock(mem);
        if (SetClipboardData(CF_UNICODETEXT, mem)) {
            CloseClipboard();
            return true;   // 成功后剪贴板接管这块内存，不能 GlobalFree
        }
        *err = GetLastError();
        GlobalFree(mem);
        CloseClipboard();
        Sleep(50);
    }
    return false;
}

bool GetClipboardUtf16(std::wstring* out, DWORD* err)
{
    for (int i = 0; i < 20; ++i) {
        if (!OpenClipboard(nullptr)) {
            *err = GetLastError();
            Sleep(50);
            continue;
        }
        HANDLE h = GetClipboardData(CF_UNICODETEXT);
        if (!h) {
            *err = GetLastError();
            CloseClipboard();
            return false;   // 打开了但没文本 —— 不再重试
        }
        const WCHAR* p = static_cast<const WCHAR*>(GlobalLock(h));
        if (!p) {
            *err = GetLastError();
            CloseClipboard();
            return false;
        }
        *out = p;
        GlobalUnlock(h);
        CloseClipboard();
        return true;
    }
    return false;
}

int g_pass = 0;
int g_fail = 0;

void Check(const char* what, bool ok)
{
    printf("[probe] %-56s %s\n", what, ok ? "OK" : "**FAIL**");
    if (ok) {
        ++g_pass;
    }
    else {
        ++g_fail;
    }
}

std::string Narrow(const std::wstring& wide)
{
    if (wide.empty()) {
        return {};
    }
    const int need = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
        nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
        out.data(), need, nullptr, nullptr);
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    const char* exePath = (argc > 1) ? argv[1] : "BuildCheck\\R3 ShieldCore.exe";
    const char* markerPath = "BuildCheck\\probe-marker.log";
    const char* markerText = "PROBE-MARKER-COPY-ALL-LOGS-20261004";

    // 放一个内容已知的 marker 日志，让断言不依赖引擎日志的具体文字。
    {
        FILE* f = nullptr;
        if (fopen_s(&f, markerPath, "wb") == 0 && f) {
            fprintf(f, "%s\n", markerText);
            fclose(f);
        }
        else {
            printf("[probe] FAIL: cannot create %s\n", markerPath);
            return 1;
        }
    }

    // 清掉上次残留的 r3shieldcore-console.log（探针要断言"引擎这次确实写了日志"）。
    DeleteFileW(L"BuildCheck\\r3shieldcore-console.log");

    std::string commandLine = std::string("\"") + exePath + "\"";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(exePath, commandLine.data(), nullptr, nullptr, FALSE,
            0, nullptr, nullptr, &si, &pi)) {
        printf("[probe] FAIL: CreateProcess err=%lu\n", GetLastError());
        return 1;
    }
    printf("[probe] launched pid=%lu\n", pi.dwProcessId);

    HWND window = nullptr;
    for (int i = 0; i < 200 && !window; ++i) {   // 最多 20s
        window = FindWindowW(kClassName, nullptr);
        if (!window) {
            Sleep(100);
        }
    }
    if (!window) {
        printf("[probe] FAIL: window '%ls' not found (app exited early?)\n", kClassName);
        TerminateProcess(pi.hProcess, 1);
        return 2;
    }

    RECT client = {};
    GetClientRect(window, &client);
    const int cw = client.right;
    const Rect allRect = CopyAllLogsButtonRect(cw);

    printf("[probe] window=%p clientWidth=%d clientHeight=%d\n",
        (void*)window, cw, client.bottom);
    printf("[probe] tab strip ends at x=%d ; copy-all-logs button = [%d..%d] x [%d..%d]\n",
        TabStripRight(), allRect.left, allRect.right, allRect.top, allRect.bottom);
    Check("copy-all-logs button does not overlap tab strip", allRect.left > TabStripRight());

    auto alive = [&]() { return WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT; };

    // ★ 引擎初始化完（免提权 + 受保护目录下会真加载引擎）之后进程必须还活着。
    //   否则窗口已销毁，后面所有像素断言都是"全白"的假结果 —— 必须早退。
    Sleep(1500);
    if (!alive()) {
        printf("[probe] FAIL: app died during startup -- engine refused to load?\n");
        printf("[probe]       harden the DLL dir ACL first (HANDOVER 3.12):\n");
        printf("[probe]         icacls <dir> /inheritance:d\n");
        printf("[probe]         icacls <dir> /remove:g \"NT AUTHORITY\\Authenticated Users\"\n");
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }

    POINT savedCursor = {};
    GetCursorPos(&savedCursor);

    auto moveCursorToClient = [&](int x, int y) {
        POINT p = { x, y };
        if (ClientToScreen(window, &p)) {
            SetCursorPos(p.x, p.y);
        }
    };

    // ---- 基线（真光标挪到窗口外，确保无悬停）----
    SetCursorPos(4, 4);
    Sleep(400);
    const Signature baseline = CaptureSignature(window, allRect);
    printf("[probe] baseline   : %s\n", baseline.Text().c_str());
    Check("captured button pixels (button is rendered)", baseline.valid && baseline.nonWhite > 100);

    const int bx = (allRect.left + allRect.right) / 2;
    const int by = (allRect.top + allRect.bottom) / 2;
    // 一个确定不在任何按钮/页签上的中性点（内容区中部）。
    const int nx = cw / 2;
    const int ny = client.bottom - 60;

    // ---- 先放一个哨兵到剪贴板，作为"剪贴板到底有没有被动过"的判据 ----
    const std::wstring sentinel = L"SENTINEL-BEFORE-COPY-ALL-LOGS";
    DWORD err = 0;
    const bool sentinelOk = SetClipboardUtf16(sentinel, &err);
    printf("[probe] set sentinel: %s (err=%lu)\n", sentinelOk ? "OK" : "FAIL", err);
    Check("sentinel written to clipboard", sentinelOk);

    // ---- 反向对照：点中性点，剪贴板必须**没变** ----
    moveCursorToClient(nx, ny);
    Sleep(150);
    PostMouse(window, WM_LBUTTONDOWN, nx, ny, MK_LBUTTON);
    Sleep(120);
    PostMouse(window, WM_LBUTTONUP, nx, ny, 0);
    Sleep(500);

    std::wstring afterNeutral;
    err = 0;
    const bool neutralRead = GetClipboardUtf16(&afterNeutral, &err);
    printf("[probe] neutral click -> clipboard read=%d err=%lu len=%zu\n",
        neutralRead ? 1 : 0, err, afterNeutral.size());
    Check("negative control: neutral click does NOT touch the clipboard",
        neutralRead && afterNeutral == sentinel);

    // ---- 点「复制全部日志」按钮：按下 + 原地松手 ----
    moveCursorToClient(bx, by);
    Sleep(200);
    PostMouse(window, WM_LBUTTONDOWN, bx, by, MK_LBUTTON);
    Sleep(150);
    PostMouse(window, WM_LBUTTONUP, bx, by, 0);
    Sleep(300);

    // 按钮文字应变成「已复制」（2.5s 内）—— 像素必然与基线不同。
    const Signature afterClick = CaptureSignature(window, allRect);
    printf("[probe] after click: %s\n", afterClick.Text().c_str());
    Check("button pixels change after click (label -> 已复制)", afterClick.valid && !(afterClick == baseline));

    // ---- 主判据：读剪贴板，内容必须是日志导出 ----
    std::wstring clip;
    err = 0;
    const bool clipOk = GetClipboardUtf16(&clip, &err);
    printf("[probe] clipboard read=%d err=%lu len=%zu\n", clipOk ? 1 : 0, err, clip.size());

    if (!clipOk) {
        printf("[probe] HINT: err=5 通常是引擎在 block 模式拦了 GetClipboardData\n");
        printf("[probe]       (clipboard_guard.cpp:128) -- 跑本探针请先关 hook_clipboard\n");
    }

    Check("clipboard is no longer the sentinel", clipOk && clip != sentinel);
    Check("clipboard has the export header",
        clipOk && clip.find(L"==== R3ShieldCore 日志导出 ====") != std::wstring::npos);
    Check("clipboard names the engine directory",
        clipOk && clip.find(L"引擎目录:") != std::wstring::npos);
    Check("clipboard contains at least one file section",
        clipOk && clip.find(L"-------- ") != std::wstring::npos);

    const std::wstring markerWide(markerText, markerText + strlen(markerText));
    const bool hasMarker = clipOk && clip.find(markerWide) != std::wstring::npos;
    printf("[probe] marker '%s' present: %s\n", markerText, hasMarker ? "YES" : "NO");
    Check("clipboard contains the probe marker log content", hasMarker);

    if (clipOk) {
        std::wstring head = clip.substr(0, clip.size() < 400 ? clip.size() : 400);
        printf("[probe] ---- clipboard head (first 400 chars) ----\n%s\n[probe] ----\n",
            Narrow(head).c_str());
    }

    // ---- 收尾 ----
    if (alive()) {
        TerminateProcess(pi.hProcess, 1);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    SetCursorPos(savedCursor.x, savedCursor.y);

    printf("\n[probe] RESULT: %d passed, %d failed -> %s\n",
        g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 6;
}
