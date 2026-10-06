// sentinel_probe.cpp
//
// 端到端验证 **真正的** R3ShieldCoreSentinel 模块（不是复制一份逻辑）：
//   --victim [workarea] [recreate] [notopmost] [caption]
//              子进程：创建一个「全屏 + WS_EX_TOPMOST + 无边框」窗口，
//              并且**顽固**：被最小化后 300ms 自动还原、忽略 WM_CLOSE。
//                workarea  —— 只覆盖工作区（任务栏露在外面），不该被反制
//                recreate  —— 窗口被销毁后**立刻重建一个新窗口**
//                             （模拟"窗口反制没效果"的顽固覆盖层，
//                               用来证明升级能走到 ④ 而不是卡在 ①）
//                notopmost —— 全屏无边框但**不置顶**：不该被反制，但必须
//                             被"差一点命中"诊断**看见**（v59 可诊断性）
//                caption   —— 全屏置顶但**带标题栏**（WS_CAPTION|WS_SYSMENU）：
//                             判据不该放宽（不反制），但诊断**必须**看见（v60）
//   （无参数） 父进程：跑七个场景，断言行为，打印模块统计。
//
// 只碰自己创建的 victim 窗口。

#include "r3shieldcore_sentinel.h"

#include <windows.h>
#include <cstdio>
#include <string>

static const wchar_t* kVictimClass = L"R3ShieldCoreSentinelVictim";
static const UINT kMsgRecreate = WM_APP + 1;   // 线程消息：重建窗口

static int g_pass = 0;
static int g_fail = 0;
static bool g_workarea = false;   // true = 只覆盖工作区（任务栏露在外面），不该被反制
static bool g_recreate = false;   // true = 窗口被销毁后重建（顽固覆盖层）
static bool g_noTopmost = false;  // true = 全屏无边框但不置顶（应被诊断看见、不被反制）
static bool g_caption = false;    // true = 全屏置顶但**带标题栏**（v60：必须被诊断看见）

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

static LRESULT CALLBACK VictimProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
        SetTimer(hwnd, 1, 300, nullptr);   // 定期检查：被最小化就立刻还原
        return 0;
    case WM_TIMER:
        if (IsIconic(hwnd))
            ShowWindow(hwnd, SW_RESTORE);  // “覆盖层自我重显”
        return 0;
    case WM_SYSCOMMAND:
        if ((wp & 0xFFF0) == SC_MINIMIZE) return 0;
        break;
    case WM_CLOSE:
        return 0;                          // 忽略关闭
    case WM_DESTROY:
        // ⚠️ 关键分支：recreate 模式下**不退出**，而是请自己的线程再建一个窗口
        //    —— 这正是"③ 销毁窗口没效果"的成因，也是 ④⑤ 存在的理由。
        //    用 PostThreadMessage 发线程消息（hwnd==NULL），在消息循环里处理。
        if (g_recreate)
            PostThreadMessageW(GetCurrentThreadId(), kMsgRecreate, 0, 0);
        else
            PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// 在**当前线程**上建一个全屏置顶无边框窗口。
static HWND CreateVictimWindow()
{
    POINT origin = { 0, 0 };
    HMONITOR mon = MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfoW(mon, &mi);

    // workarea 模式：只覆盖工作区（= 普通最大化窗口的覆盖范围，任务栏仍可见）。
    // 全屏模式：覆盖整块显示器（含任务栏条带）= 真正的“全屏”。
    const RECT& r = g_workarea ? mi.rcWork : mi.rcMonitor;

    // ★ v59：notopmost 模式去掉 WS_EX_TOPMOST —— 用来钉"差一点命中"诊断：
    //   这种窗口不该被反制（用户明确要求过"全屏 = 盖住任务栏那种全屏"且要置顶），
    //   但必须在日志里**看得见**，否则"没反制"永远无法与"没扫到"区分。
    const DWORD exStyle = WS_EX_TOOLWINDOW | (g_noTopmost ? 0u : WS_EX_TOPMOST);

    // ★ v60：caption 模式 = 全屏 + 置顶 + **带标题栏**（WS_CAPTION|WS_SYSMENU）。
    //   这正是 2026-10-05 真机日志里那个"连差一点命中都不打"的形态：
    //   Delphi `TForm` 默认边框 + 最大化 + StayOnTop ⇒ 有 WS_CAPTION。
    //   · 触发判据要求"无边框" ⇒ 不该被反制（正确，本场景断言 detected==0）；
    //   · 但 v59 的**诊断门槛也要求无边框** ⇒ 真机上完全静默（这就是要修的 bug）。
    const DWORD style = g_caption
        ? (WS_POPUP | WS_CAPTION | WS_SYSMENU)
        : WS_POPUP;

    HWND hwnd = CreateWindowExW(exStyle, kVictimClass,
        L"sentinel-victim", style,
        r.left, r.top, r.right - r.left, r.bottom - r.top,
        nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!hwnd)
    {
        printf("VICTIM: CreateWindowEx failed err=%lu\n", GetLastError());
        return nullptr;
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    printf("VICTIM: hwnd=%p pid=%lu workarea=%d recreate=%d notopmost=%d caption=%d rect=(%ld,%ld,%ld,%ld)\n",
        (void*)hwnd, GetCurrentProcessId(), g_workarea ? 1 : 0, g_recreate ? 1 : 0,
        g_noTopmost ? 1 : 0, g_caption ? 1 : 0,
        r.left, r.top, r.right, r.bottom);
    fflush(stdout);
    return hwnd;
}

static int RunVictim()
{
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = VictimProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kVictimClass;
    RegisterClassExW(&wc);

    if (!CreateVictimWindow())
        return 2;

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        // 线程消息（hwnd==NULL）：重建窗口请求。
        if (msg.hwnd == nullptr && msg.message == kMsgRecreate)
        {
            CreateVictimWindow();
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}

struct ScenarioResult
{
    bool processAlive = false;
    bool anyWindowAlive = false;
    R3ShieldCoreSentinel::Stats stats = {};
};

static ScenarioResult RunSentinelAgainst(bool workarea, bool recreate,
    ULONG level, ULONG askTimeoutMs, int seconds, bool noTopmost = false,
    bool caption = false)
{
    ScenarioResult r = {};

    wchar_t self[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, self, _countof(self));
    std::wstring cmd = std::wstring(self) + L" --victim";
    if (workarea) cmd += L" workarea";
    if (recreate) cmd += L" recreate";
    if (noTopmost) cmd += L" notopmost";
    if (caption) cmd += L" caption";
    cmd.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
    {
        printf("CreateProcess(victim) failed err=%lu\n", GetLastError());
        g_fail++;
        return r;
    }

    HWND victim = nullptr;
    for (int i = 0; i < 100 && !victim; i++)
    {
        victim = FindWindowW(kVictimClass, nullptr);
        if (!victim) Sleep(50);
    }

    R3ShieldCoreSentinel::Start(level, askTimeoutMs);
    for (int i = 0; i < seconds * 10; i++)
    {
        R3ShieldCoreSentinel::Tick();
        Sleep(100);
        // ★ 以**进程**存活为循环条件（不是窗口）：recreate 模式下旧 hwnd 会
        //   很快失效，但进程还活着、还在重建窗口 —— 只看窗口会提前收工。
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) break;
    }

    r.processAlive = WaitForSingleObject(pi.hProcess, 0) != WAIT_OBJECT_0;
    r.anyWindowAlive = FindWindowW(kVictimClass, nullptr) != nullptr;
    r.stats = R3ShieldCoreSentinel::GetStats();
    R3ShieldCoreSentinel::Stop();

    if (r.processAlive) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 2000);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    Sleep(150);
    return r;
}

static void PrintStats(const R3ShieldCoreSentinel::Stats& s)
{
    printf("  stats: detected=%u minimized=%u closed=%u destroyed=%u exit=%u term=%u "
        "asked=%u askTimeouts=%u declined=%u nearMiss=%u\n",
        s.Detected, s.Minimized, s.Closed, s.Destroyed,
        s.ExitRequested, s.Terminated, s.Asked, s.AskTimeouts, s.Declined, s.NearMiss);
}

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; i++)
    {
        if (_stricmp(argv[i], "--victim") == 0)
        {
            for (int j = i + 1; j < argc; j++)
            {
                if (_stricmp(argv[j], "workarea") == 0) g_workarea = true;
                if (_stricmp(argv[j], "recreate") == 0) g_recreate = true;
                if (_stricmp(argv[j], "notopmost") == 0) g_noTopmost = true;
                if (_stricmp(argv[j], "caption") == 0) g_caption = true;
            }
            return RunVictim();
        }
    }

    printf("=== 场景1：真全屏（盖住任务栏）的顽固覆盖层 —— 应被反制（级别1，不问）===\n");
    {
        ScenarioResult r = RunSentinelAgainst(false, false, 1, 0, 15);
        PrintStats(r.stats);
        Check("真全屏覆盖层最终被销毁/结束", !r.anyWindowAlive);
        Check("①②③ 都尝试过（minimize/close/destroy >= 1）",
            r.stats.Minimized >= 1 && r.stats.Closed >= 1 && r.stats.Destroyed >= 1);
    }

    printf("\n=== 场景2：只盖工作区（任务栏可见，非真全屏）—— 不该被反制 ===\n");
    {
        ScenarioResult r = RunSentinelAgainst(true, false, 1, 0, 8);
        PrintStats(r.stats);
        Check("工作区窗口未被反制（仍存活）", r.anyWindowAlive);
        Check("未被判定为覆盖层（detected==0）", r.stats.Detected == 0);
    }

    // ★ 场景3 是本次新增的核心：窗口被销毁后立刻重建 ⇒ 若升级进度按 hwnd 记账，
    //   新窗口会让 rungs 归零、永远卡在 ①，④ 永远不可达。这条断言就是钉它。
    printf("\n=== 场景3：窗口销毁后**重建**的顽固覆盖层 —— 应升到 ④ 结束进程 ===\n");
    {
        ScenarioResult r = RunSentinelAgainst(false, true, 1, 0, 30);
        PrintStats(r.stats);
        Check("窗口被销毁过（③ 生效）", r.stats.Destroyed >= 1);
        Check("升级到了 ④（调用退出函数）", r.stats.ExitRequested >= 1);
        Check("④ 成功结束了目标进程（process 已退出）", !r.processAlive);
        Check("没有白跑到 ⑤（④ 已经解决）", r.stats.Terminated == 0);
    }

    // ★ 场景4：级别2（弹窗询问）。不点按钮 ⇒ 走超时兜底。
    //   ★ v59 关键断言：超时**只代表"这次没结论"**，绝不能当成"用户拒绝"——
    //     否则覆盖层把弹窗盖住（用户根本没看见）时，反制会在第一级就被永久关掉。
    //     所以这里要求：asked>=1、askTimeouts>=1、**declined==0**、且没动手。
    printf("\n=== 场景4：级别2 弹窗询问，不理会 -> 超时应**重试**而非永久放弃 ===\n");
    {
        ScenarioResult r = RunSentinelAgainst(false, false, 2, 2000, 6);
        PrintStats(r.stats);
        Check("确实弹出了询问（asked >= 1）", r.stats.Asked >= 1);
        Check("超时被单独记账（askTimeouts >= 1）", r.stats.AskTimeouts >= 1);
        Check("超时**不**算用户拒绝（declined == 0）", r.stats.Declined == 0);
        Check("超时期间未执行任何动作（minimize/close/destroy 均为 0）",
            r.stats.Minimized == 0 && r.stats.Closed == 0 && r.stats.Destroyed == 0);
        Check("超时期间未结束进程（窗口仍在）", r.anyWindowAlive);
    }

    // ★ 场景5：连续超时达到上限（3 次）后才放弃 —— 钉住"有限重试"的上界，
    //   防止改成"永远重试"（会把用户烦死）或"一次就放弃"（旧版缺陷）。
    printf("\n=== 场景5：级别2 连续超时 3 次 -> 才记为放弃（declined>=1）===\n");
    {
        ScenarioResult r = RunSentinelAgainst(false, false, 2, 1000, 14);
        PrintStats(r.stats);
        Check("确实弹了不止一次（asked >= 2）", r.stats.Asked >= 2);
        Check("连续超时被累计（askTimeouts >= 3）", r.stats.AskTimeouts >= 3);
        Check("达到上限后记为放弃（declined >= 1）", r.stats.Declined >= 1);
        Check("整个过程中始终未动手（minimize/close/destroy 均为 0）",
            r.stats.Minimized == 0 && r.stats.Closed == 0 && r.stats.Destroyed == 0);
        Check("窗口仍在（超时兜底从不静默杀进程）", r.anyWindowAlive);
    }

    // ★ 场景6：可诊断性 —— 全屏无边框但**不置顶**的窗口。
    //   它**不该**被反制（用户明确要求过判据要"全屏 + 置顶 + 无边框"），
    //   但必须在日志/统计里**看得见**（nearMiss>=1）。否则用户报"窗口反制用不了"
    //   时，日志里一片空白，根本分不清"没扫到"与"扫到但被签名挡掉"。
    printf("\n=== 场景6：全屏无边框但**不置顶** -> 不反制，但必须被诊断看见 ===\n");
    {
        ScenarioResult r = RunSentinelAgainst(false, false, 1, 0, 6, /*noTopmost=*/true);
        PrintStats(r.stats);
        Check("未被判定为覆盖层（detected == 0）", r.stats.Detected == 0);
        Check("未被反制（minimize/close/destroy 均为 0）",
            r.stats.Minimized == 0 && r.stats.Closed == 0 && r.stats.Destroyed == 0);
        Check("窗口仍存活", r.anyWindowAlive);
        Check("但被\"差一点命中\"诊断看见（nearMiss >= 1）", r.stats.NearMiss >= 1);
    }

    // ★ 场景7（v60 新增，钉死 2026-10-05 真机失守的那个盲区）：
    //   **带标题栏的真全屏**（WS_CAPTION|WS_SYSMENU + 置顶 + 盖住任务栏）。
    //   真机日志证据：病毒启动后引擎连打 3 次心跳，`差一点命中=0` —— 因为 v59 的
    //   诊断门槛要求"无边框"，而 Delphi `TForm` 全屏窗口带 WS_CAPTION ⇒ 既没命中
    //   也没诊断，日志一片空白。本场景要求：
    //     · 触发判据**不放宽**（仍然 detected==0、不动手）—— 判据是用户定的；
    //     · 但诊断**必须看见**（nearMiss>=1）—— 否则下次还是查不出来。
    printf("\n=== 场景7：带标题栏的真全屏（置顶）-> 不反制，但**必须**被诊断看见 ===\n");
    {
        ScenarioResult r = RunSentinelAgainst(false, false, 1, 0, 6,
            /*noTopmost=*/false, /*caption=*/true);
        PrintStats(r.stats);
        Check("未被判定为覆盖层（detected == 0，判据未放宽）", r.stats.Detected == 0);
        Check("未被反制（minimize/close/destroy 均为 0）",
            r.stats.Minimized == 0 && r.stats.Closed == 0 && r.stats.Destroyed == 0);
        Check("窗口仍存活", r.anyWindowAlive);
        Check("带标题栏的全屏也必须被\"差一点命中\"看见（nearMiss >= 1）",
            r.stats.NearMiss >= 1);
    }

    printf("\nSUMMARY: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
