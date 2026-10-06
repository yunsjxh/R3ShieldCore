// overlay_ladder_probe.cpp
//
// 验证「全屏+置顶覆盖层」反制的三级升级链是否真的可行，尤其是第 3 级：
//   ① ShowWindow(hwnd, SW_MINIMIZE)                      最小化
//   ② PostMessage(hwnd, WM_CLOSE)                        关闭
//   ③ CreateWindowExW(隐藏父) + SetParent(目标, 父) +
//      DestroyWindow(父)                                  借父窗口销毁目标
//
// 第 3 级的疑点（必须实证，不能靠文档）：跨进程 SetParent 是否成功？
// 销毁属于**别的进程**的子窗口时，父窗口的 DestroyWindow 是否真能把它销毁？
//
// 设计：本程序自己分饰两角。
//   --victim [stubborn]   子进程：创建一个「全屏 + WS_EX_TOPMOST + 无边框」
//                         的窗口（类名 R3ShieldCoreLadderVictim）。stubborn 时
//                         额外**拒绝最小化、忽略 WM_CLOSE**，用来逼出第 3 级。
//   （无参数）             父进程：拉起 victim，逐级反制并逐步断言。
//
// 只碰自己创建的 victim 窗口，绝不动桌面上的任何其它窗口。

#include <windows.h>
#include <stdio.h>
#include <string>
#include <string.h>

static const wchar_t* kVictimClass = L"R3ShieldCoreLadderVictim";
static const wchar_t* kParentClass = L"R3ShieldCoreLadderParent";

static bool g_stubborn = false;
static bool g_plainVictim = false;
static int  g_pass = 0;
static int  g_fail = 0;

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

// ---- victim 窗口过程：可选地拒绝最小化 / 忽略关闭 ----
static LRESULT CALLBACK VictimProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (g_stubborn)
    {
        if (msg == WM_SYSCOMMAND && (wp & 0xFFF0) == SC_MINIMIZE)
            return 0;                 // 拒绝最小化
        if (msg == WM_CLOSE)
            return 0;                 // 忽略关闭
        if (msg == WM_NCLBUTTONDOWN)
            return 0;
    }
    if (msg == WM_DESTROY)
        PostQuitMessage(0);
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// ---- 父窗口过程：只用来做第 3 级的“隐藏父容器” ----
static LRESULT CALLBACK ParentProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void RegisterClasses(HINSTANCE hInst)
{
    WNDCLASSEXW vc = { sizeof(vc) };
    vc.lpfnWndProc = VictimProc;
    vc.hInstance = hInst;
    vc.lpszClassName = kVictimClass;
    RegisterClassExW(&vc);

    WNDCLASSEXW pc = { sizeof(pc) };
    pc.lpfnWndProc = ParentProc;
    pc.hInstance = hInst;
    pc.lpszClassName = kParentClass;
    RegisterClassExW(&pc);
}

static void PrimaryMonitorRect(RECT& out)
{
    POINT origin = { 0, 0 };
    HMONITOR mon = MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO mi = { sizeof(mi) };
    if (GetMonitorInfoW(mon, &mi)) out = mi.rcMonitor;
    else { out.left = 0; out.top = 0; out.right = GetSystemMetrics(SM_CXSCREEN); out.bottom = GetSystemMetrics(SM_CYSCREEN); }
}

// ---- 与 sentinel 检测判据同形：这个窗口“像不像覆盖层” ----
static bool LooksLikeOverlay(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd)) return false;
    if (!IsWindowVisible(hwnd)) return false;
    if (IsIconic(hwnd)) return false;

    LONG_PTR ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    if ((ex & WS_EX_TOPMOST) == 0) return false;

    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    if (style & WS_CAPTION) return false;
    if (style & WS_SYSMENU) return false;

    RECT wr = {};
    if (!GetWindowRect(hwnd, &wr)) return false;

    HMONITOR mon = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO mi = { sizeof(mi) };
    if (!GetMonitorInfoW(mon, &mi)) return false;

    const int tol = 2;
    const RECT& mr = mi.rcMonitor;
    return wr.left <= mr.left + tol && wr.top <= mr.top + tol &&
           wr.right >= mr.right - tol && wr.bottom >= mr.bottom - tol;
}

// ---- victim 模式 ----
static int RunVictim()
{
    RegisterClasses(GetModuleHandleW(nullptr));

    RECT mr = {};
    PrimaryMonitorRect(mr);

    HWND hwnd = nullptr;
    if (g_plainVictim)
    {
        // 普通窗口：非置顶、非全屏、有标题栏。用来隔离“是不是 topmost/全屏 才让 SetParent 失败”。
        hwnd = CreateWindowExW(0, kVictimClass, L"ladder-victim-plain",
            WS_OVERLAPPEDWINDOW, 100, 100, 400, 300,
            nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    }
    else
    {
        hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            kVictimClass, L"ladder-victim",
            WS_POPUP,
            mr.left, mr.top, mr.right - mr.left, mr.bottom - mr.top,
            nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    }

    if (!hwnd)
    {
        printf("VICTIM: CreateWindowEx failed err=%lu\n", GetLastError());
        return 2;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    printf("VICTIM: hwnd=%p pid=%lu stubborn=%d plain=%d rect=(%ld,%ld,%ld,%ld)\n",
        (void*)hwnd, GetCurrentProcessId(), g_stubborn ? 1 : 0, g_plainVictim ? 1 : 0,
        mr.left, mr.top, mr.right, mr.bottom);
    fflush(stdout);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

// ---- 第 3 级：隐藏父窗口 + SetParent + DestroyWindow(父) ----
static bool LadderStep3_DestroyViaHiddenParent(HWND target, std::string& detail)
{
    // 父窗口必须“不显示”：不调用 ShowWindow，创建即隐藏（WS_POPUP 不 show 就不显示）。
    HWND parent = CreateWindowExW(
        0, kParentClass, L"hidden-parent", WS_POPUP,
        0, 0, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!parent)
    {
        detail = "CreateWindowEx(parent) failed";
        return false;
    }

    // 跨进程 SetParent —— 这是本级的核心疑点之一。
    HWND prev = SetParent(target, parent);
    DWORD setErr = GetLastError();
    HWND nowParent = GetParent(target);
    HWND ancestor = GetAncestor(target, GA_PARENT);
    BOOL isChild = IsChild(parent, target);
    LONG_PTR style = GetWindowLongPtrW(target, GWL_STYLE);
    LONG_PTR ex = GetWindowLongPtrW(target, GWL_EXSTYLE);

    bool reparented = (nowParent == parent) || (ancestor == parent) || isChild;

    char buf[512];
    sprintf_s(buf, "SetParent prev=%p err=%lu | GetParent=%p GetAncestor=%p IsChild=%d "
        "style=0x%08llX ex=0x%08llX -> reparented=%d",
        (void*)prev, setErr, (void*)nowParent, (void*)ancestor, isChild,
        (unsigned long long)style, (unsigned long long)ex, reparented ? 1 : 0);
    detail = buf;

    if (!reparented)
    {
        DestroyWindow(parent);
        return false;
    }

    // 销毁父窗口 —— 期望系统连带销毁子窗口（即使子窗口属于别的进程）。
    DestroyWindow(parent);
    Sleep(200);

    return !IsWindow(target);
}

// ---- 父进程：拉起一个 victim 并返回其窗口句柄 ----
struct LaunchedVictim
{
    PROCESS_INFORMATION pi = {};
    HWND hwnd = nullptr;
};

static LaunchedVictim LaunchVictim(bool stubborn, bool plain = false)
{
    LaunchedVictim vp;
    wchar_t self[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, self, _countof(self));

    std::wstring cmd = std::wstring(self) + L" --victim";
    if (stubborn) cmd += L" stubborn";
    if (plain) cmd += L" plain";
    cmd.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &vp.pi))
    {
        printf("CreateProcess(victim) failed err=%lu\n", GetLastError());
        g_fail++;
        return vp;
    }

    for (int i = 0; i < 100 && !vp.hwnd; i++)
    {
        vp.hwnd = FindWindowW(kVictimClass, nullptr);
        if (!vp.hwnd) Sleep(50);
    }
    return vp;
}

static void KillVictim(LaunchedVictim& vp)
{
    if (vp.pi.hProcess)
    {
        TerminateProcess(vp.pi.hProcess, 0);
        WaitForSingleObject(vp.pi.hProcess, 2000);
        CloseHandle(vp.pi.hThread);
        CloseHandle(vp.pi.hProcess);
    }
    Sleep(150);
}

// ---- 对照用：只挂靠，不销毁父窗口 ----
static HWND LadderStep3_ReparentOnly(HWND target)
{
    HWND parent = CreateWindowExW(0, kParentClass, L"hidden-parent2", WS_POPUP,
        0, 0, 1, 1, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!parent) return nullptr;
    SetParent(target, parent);
    return parent;
}

// ---- 父进程入口 ----
static int RunDriver()
{
    RegisterClasses(GetModuleHandleW(nullptr));   // ← 关键：父进程也要注册类，否则 CreateWindowEx(parent) 失败

    // 场景 A：普通窗口 → step1 最小化
    {
        LaunchedVictim vp = LaunchVictim(false);
        printf("\n=== A. step1 最小化（普通窗口）===\n");
        if (!vp.hwnd) { printf("  [FAIL] victim 未出现\n"); g_fail++; }
        else
        {
            Check("victim 命中覆盖层判据", LooksLikeOverlay(vp.hwnd));
            ShowWindow(vp.hwnd, SW_MINIMIZE);
            Sleep(300);
            Check("step1 最小化生效", IsIconic(vp.hwnd) != FALSE);
        }
        KillVictim(vp);
    }

    // 场景 B：普通窗口 → step2 关闭
    {
        LaunchedVictim vp = LaunchVictim(false);
        printf("\n=== B. step2 关闭（普通窗口，应被关掉）===\n");
        if (!vp.hwnd) { printf("  [FAIL] victim 未出现\n"); g_fail++; }
        else
        {
            PostMessageW(vp.hwnd, WM_CLOSE, 0, 0);
            Sleep(500);
            Check("step2 关闭生效", !IsWindow(vp.hwnd));
        }
        KillVictim(vp);
    }

    // 场景 C：顽固窗口 → step2 关闭应**失败**（证明“关闭可被拒绝”，第 3 级才有存在意义）
    {
        LaunchedVictim vp = LaunchVictim(true);
        printf("\n=== C. step2 关闭（顽固窗口，忽略 WM_CLOSE，应存活）===\n");
        if (!vp.hwnd) { printf("  [FAIL] victim 未出现\n"); g_fail++; }
        else
        {
            PostMessageW(vp.hwnd, WM_CLOSE, 0, 0);
            Sleep(500);
            Check("顽固窗口拒绝 WM_CLOSE（仍存活）", IsWindow(vp.hwnd));
        }
        KillVictim(vp);
    }

    // 场景 D：顽固窗口 → step3 借隐藏父窗口销毁（本探针的核心断言）
    {
        LaunchedVictim vp = LaunchVictim(true);
        printf("\n=== D. step3 隐藏父窗口销毁（顽固窗口，应被销毁）===\n");
        if (!vp.hwnd) { printf("  [FAIL] victim 未出现\n"); g_fail++; }
        else
        {
            Check("victim 存在", IsWindow(vp.hwnd));
            std::string detail;
            bool destroyed = LadderStep3_DestroyViaHiddenParent(vp.hwnd, detail);
            printf("    %s\n", detail.c_str());
            Check("step3 借父窗口销毁生效", destroyed);
        }
        KillVictim(vp);
    }

    // 场景 E：普通窗口（非置顶/非全屏）→ 单独看跨进程 SetParent 能否成功
    {
        LaunchedVictim vp = LaunchVictim(false, true);
        printf("\n=== E. step3 跨进程 SetParent（普通窗口，隔离变量）===\n");
        if (!vp.hwnd) { printf("  [FAIL] victim 未出现\n"); g_fail++; }
        else
        {
            std::string detail;
            bool destroyed = LadderStep3_DestroyViaHiddenParent(vp.hwnd, detail);
            printf("    %s\n", detail.c_str());
            printf("    -> destroyed=%d\n", destroyed ? 1 : 0);
        }
        KillVictim(vp);
    }

    // 场景 F：对照 —— 只挂靠、不销毁父窗口，窗口应存活（证明“销毁”才是杀招）
    {
        LaunchedVictim vp = LaunchVictim(true);
        printf("\n=== F. 对照：只 SetParent 不销毁父窗口（窗口应存活）===\n");
        if (!vp.hwnd) { printf("  [FAIL] victim 未出现\n"); g_fail++; }
        else
        {
            HWND parent = LadderStep3_ReparentOnly(vp.hwnd);
            Sleep(250);
            Check("只挂靠不销毁 -> 窗口仍存活", IsWindow(vp.hwnd));
            if (parent) DestroyWindow(parent);   // 清理：此时才会连带销毁
        }
        KillVictim(vp);
    }

    printf("\nSUMMARY: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; i++)
    {
        if (_stricmp(argv[i], "--victim") == 0)
        {
            for (int j = i + 1; j < argc; j++)
            {
                if (_stricmp(argv[j], "stubborn") == 0) g_stubborn = true;
                if (_stricmp(argv[j], "plain") == 0) g_plainVictim = true;
            }
            return RunVictim();
        }
    }
    return RunDriver();
}
