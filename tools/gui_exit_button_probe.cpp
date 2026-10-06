// gui_exit_button_probe.cpp -- 端到端验证「退出引擎」按钮 + 它的三态交互。
//
// 做法（遵循 win32-selfdrawn-ui-verify）：
//   1. 拉起**免提权**的 BuildCheck exe（同完整性级别，否则 UIPI 会静默丢输入）。
//   2. 按类名找到窗口，记客户区宽高 + 屏幕原点。
//   3. 用**和 app 同一套公式**算出「退出引擎」按钮矩形（见 ExitButtonRect 镜像）。
//   4. 从**屏幕** BitBlt 该矩形，取"像素指纹"（非白像素数 / 红像素数 / 校验和）。
//   5. 逐个验证交互态：
//        hover          -> 指纹必须变
//        移开           -> 指纹必须变回基线
//        按下           -> 指纹必须变，且**进程不能退**（动作在 UP 才触发）
//        按住拖走       -> 指纹回到非按下态
//        拖走后松手     -> **进程不能退**（拖出去 = 取消）
//        原地按下+松手  -> 进程退出（主判据）
//   6. 最后检查 r3shieldcore-console.log 里有那行中文。
//
// 断言优先级：进程存活/退出 + 日志（确定性） > 像素（仅证明"画成什么样"）。

#include <cstdio>
#include <cstdlib>
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

// 镜像 r3shieldcore_gui.cpp 的 ExitButtonRect()。
Rect ExitButtonRect(int clientWidth)
{
    const int clearRight = clientWidth - Padding - ModeButtonWidth - ActionButtonGap;
    const int clearLeft = clearRight - ActionButtonWidth;
    const int copyLeft = clearLeft - ActionButtonGap - ActionButtonWidth;
    const int exitLeft = copyLeft - ActionButtonGap - ActionButtonWidth;
    const int exitRight = copyLeft - ActionButtonGap;
    return { exitLeft, TabBarTop + 4, exitRight, TabBarTop + TabBarHeight - 4 };
}

int TabStripRight()
{
    return Padding + TabCount * (TabWidth + 8) - 8;
}

struct Signature
{
    int nonWhite = 0;
    int red = 0;
    unsigned long long checksum = 0;
    bool valid = false;

    bool operator==(const Signature& other) const
    {
        return nonWhite == other.nonWhite && red == other.red && checksum == other.checksum;
    }
    std::string Text() const
    {
        char buffer[128] = {};
        sprintf_s(buffer, "nonWhite=%d red=%d sum=%016llx", nonWhite, red, checksum);
        return buffer;
    }
};

// 从屏幕 BitBlt 指定客户区矩形，算指纹。
// ★ 用屏幕 BitBlt 而不是 PrintWindow —— 后者拿的是 DWM 合成缓存，
//   动态内容（悬停高亮）永远"没变"。
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
        // ColorBlocked = RGB(209,52,56)，给足容差（抗锯齿会让边缘变浅）。
        if (r > 150 && g < 110 && b < 110 && (r - g) > 80) {
            ++result.red;
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

int g_pass = 0;
int g_fail = 0;

void Check(const char* what, bool ok)
{
    printf("[probe] %-52s %s\n", what, ok ? "OK" : "**FAIL**");
    if (ok) {
        ++g_pass;
    }
    else {
        ++g_fail;
    }
}

} // namespace

int main(int argc, char** argv)
{
    const char* exePath = (argc > 1) ? argv[1] : "BuildCheck\\R3 ShieldCore.exe";

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
    const Rect exitRect = ExitButtonRect(cw);

    printf("[probe] window=%p clientWidth=%d clientHeight=%d\n", (void*)window, cw, client.bottom);
    printf("[probe] tab strip ends at x=%d ; exit button = [%d..%d] x [%d..%d]\n",
        TabStripRight(), exitRect.left, exitRect.right, exitRect.top, exitRect.bottom);
    Check("exit button does not overlap tab strip", exitRect.left > TabStripRight());

    const int bx = (exitRect.left + exitRect.right) / 2;
    const int by = (exitRect.top + exitRect.bottom) / 2;
    // 一个确定不在任何按钮/页签上的中性点（内容区中部）。
    const int nx = cw / 2;
    const int ny = client.bottom - 60;

    auto alive = [&]() { return WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT; };

    // ★ 引擎初始化完（免提权 + 受保护目录下会真加载引擎）之后进程必须还活着。
    //   若这里就死了，多半是 "Refusing to load an engine DLL from a user-writable
    //   deployment directory"（见 HANDOVER §3.12）—— 这时窗口已经销毁，
    //   后面所有像素断言都会得到"全白"的假结果，必须早退而不是继续跑。
    Sleep(1500);
    if (!alive()) {
        printf("[probe] FAIL: app died during startup -- engine refused to load?\n");
        printf("[probe]       harden the DLL dir ACL first (see HANDOVER 3.12):\n");
        printf("[probe]         icacls <dir> /inheritance:d\n");
        printf("[probe]         icacls <dir> /remove:g \"NT AUTHORITY\\Authenticated Users\"\n");
        TerminateProcess(pi.hProcess, 1);
        return 3;
    }

    // ---- 基线（把真光标挪到窗口外，确保没有任何悬停）----
    //
    // ★ 悬停必须用 **SetCursorPos 移动真光标** 来测，不能 PostMessage(WM_MOUSEMOVE)：
    //   贴一条假的 WM_MOUSEMOVE 确实会把 g_hoverButton 置上，但窗口在处理它时
    //   会调 TrackMouseEvent(TME_LEAVE)，而**真实**光标并不在窗口里 ⇒ 系统立刻
    //   补一条 WM_MOUSELEAVE 把悬停清掉。于是"悬停看起来没生效"（实测踩过）。
    POINT savedCursor = {};
    GetCursorPos(&savedCursor);

    auto moveCursorToClient = [&](int x, int y) {
        POINT p = { x, y };
        if (ClientToScreen(window, &p)) {
            SetCursorPos(p.x, p.y);
        }
    };

    SetCursorPos(4, 4); // 屏幕左上角，肯定不在窗口上
    Sleep(400);
    const Signature baseline = CaptureSignature(window, exitRect);
    printf("[probe] baseline  : %s\n", baseline.Text().c_str());
    Check("captured baseline pixels", baseline.valid && baseline.nonWhite > 100);

    // ---- 悬停（真光标移到按钮上）----
    moveCursorToClient(bx, by);
    Sleep(400);
    const Signature hover = CaptureSignature(window, exitRect);
    printf("[probe] hover     : %s\n", hover.Text().c_str());
    Check("hover changes the button pixels", hover.valid && !(hover == baseline));

    // ---- 移到窗口内但不在按钮上 → 必须变回基线 ----
    moveCursorToClient(nx, ny);
    Sleep(400);
    const Signature afterLeave = CaptureSignature(window, exitRect);
    printf("[probe] un-hover  : %s\n", afterLeave.Text().c_str());
    Check("un-hover restores the baseline", afterLeave.valid && afterLeave == baseline);

    // ---- 移出窗口 → 走 WM_MOUSELEAVE 路径，仍应是基线 ----
    SetCursorPos(4, 4);
    Sleep(400);
    const Signature afterExit = CaptureSignature(window, exitRect);
    printf("[probe] leave win : %s\n", afterExit.Text().c_str());
    Check("WM_MOUSELEAVE clears hover", afterExit.valid && afterExit == baseline);

    // ---- 按下（动作**不该**触发）----
    PostMouse(window, WM_LBUTTONDOWN, bx, by, MK_LBUTTON);
    Sleep(300);
    const Signature pressed = CaptureSignature(window, exitRect);
    printf("[probe] pressed   : %s\n", pressed.Text().c_str());
    Check("pressed differs from hover", pressed.valid && !(pressed == hover));
    Check("LBUTTONDOWN alone does NOT quit (action is on UP)", alive());

    // ---- 按住拖走 → 按下态应被取消 ----
    PostMouse(window, WM_MOUSEMOVE, nx, ny, MK_LBUTTON);
    Sleep(300);
    const Signature dragOff = CaptureSignature(window, exitRect);
    printf("[probe] drag-off  : %s\n", dragOff.Text().c_str());
    Check("dragging off cancels the pressed look", dragOff.valid && !(dragOff == pressed));

    // ---- 拖走后松手 → 必须不退出 ----
    PostMouse(window, WM_LBUTTONUP, nx, ny, 0);
    Sleep(400);
    Check("release outside does NOT quit (cancel works)", alive());

    // ---- 正常点击：光标移到按钮上，按下 + 原地松手 → 退出 ----
    moveCursorToClient(bx, by);
    Sleep(200);
    PostMouse(window, WM_LBUTTONDOWN, bx, by, MK_LBUTTON);
    Sleep(200);
    PostMouse(window, WM_LBUTTONUP, bx, by, 0);

    const DWORD wait = WaitForSingleObject(pi.hProcess, 30000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    printf("[probe] WaitForSingleObject=%lu (0=signaled) exitCode=%lu\n",
        wait, (unsigned long)exitCode);
    const bool exited = (wait == WAIT_OBJECT_0);
    Check("click quits the engine", exited);

    // ---- 日志断言 ----
    // ⚠️ r3shieldcore-console.log 是**混合编码**：printf 走执行字符集（本机 = GBK），
    //   而 ConsoleLog/ofstream 那条路显式转成 UTF-8。两种编码都要找。
    bool logUtf8 = false;
    bool logGbk = false;
    {
        FILE* f = nullptr;
        if (fopen_s(&f, "BuildCheck\\r3shieldcore-console.log", "rb") == 0 && f) {
            fseek(f, 0, SEEK_END);
            const long size = ftell(f);
            fseek(f, 0, SEEK_SET);
            std::string content(static_cast<size_t>(size > 0 ? size : 0), '\0');
            if (size > 0) {
                fread(content.data(), 1, static_cast<size_t>(size), f);
            }
            fclose(f);
            // 「退出引擎」= U+9000 U+51FA U+5F15 U+64CE
            logUtf8 = content.find("\xE9\x80\x80\xE5\x87\xBA\xE5\xBC\x95\xE6\x93\x8E") != std::string::npos;
            logGbk = content.find("\xCD\xCB\xB3\xF6\xD2\xFD\xC7\xE6") != std::string::npos;
        }
    }
    printf("[probe] log exit marker: %s (utf8=%d gbk=%d)\n",
        (logUtf8 || logGbk) ? "YES" : "NO", logUtf8 ? 1 : 0, logGbk ? 1 : 0);
    Check("r3shieldcore-console.log records the quit", logUtf8 || logGbk);

    if (!exited) {
        TerminateProcess(pi.hProcess, 1);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // 把用户的鼠标还回去（测试期间挪动过）。
    SetCursorPos(savedCursor.x, savedCursor.y);

    printf("\n[probe] RESULT: %d passed, %d failed -> %s\n",
        g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 6;
}
