//
// 探针：user32!SetWindowBand（未文档化）在本机的真实行为。
//
// 为什么要探：R3ShieldCore 控制台新增的「超级置顶」按钮照搬了 jiyu 的取法 ——
//   if (进程有 UIAccess) SetWindowBand(hwnd, HWND_TOPMOST, 2);
// 但本机 exe 的清单是 requireAdministrator + uiAccess='false'，
// 所以**必须实测**：没有 UIAccess 时这个调用
//   ① 返回 TRUE 还是 FALSE？（决定 UI 上按钮是高亮蓝还是降级橙）
//   ② 返回 TRUE 的话，窗口是不是真被抬到别的置顶窗口之上？（决定它算不算"超级"）
//
// 方法（沿用 win-api-behavior-probe 的规矩）：
//   - 先取"对照"基线：两个置顶窗口，最后抬 B ⇒ A 应在 B 之下。
//   - 再测：SetWindowBand(A, ..., 2) 之后**故意再抬一次 B**，看 A 还在不在 B 之上。
//     只在 band 真的生效时 A 才会压住 B；否则与基线一致。
//   - 单次调用不足以定论 ⇒ 三个阶段各测一次并打印返回码 + GetLastError。
//
// 用法：topband_probe.exe          （跑全部）
//       topband_probe.exe clean    （无对象可清，仅占位，便于统一调用）
//

#include <windows.h>
#include <stdio.h>
#include <string.h>

using SetWindowBandFn = BOOL(WINAPI*)(HWND, HWND, DWORD);

static const wchar_t* kClassName = L"TopBandProbeWnd";

static bool ProcessElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation = {};
    DWORD returned = 0;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

static SetWindowBandFn ResolveSetWindowBand()
{
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (!user32) {
        return nullptr;
    }
    FARPROC p = GetProcAddress(user32, "SetWindowBand");
    return p ? reinterpret_cast<SetWindowBandFn>(p) : nullptr;
}

static bool ProcessHasUiAccess()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    DWORD enabled = 0;
    DWORD returned = 0;
    BOOL ok = GetTokenInformation(token, TokenUIAccess, &enabled, sizeof(enabled), &returned);
    CloseHandle(token);
    return ok && enabled != 0;
}

// 沿 z 序从 hwnd 往上走，先遇到 target ⇒ target 在 hwnd **之上**。
// （注意：GW_HWNDPREV = 更靠近屏幕顶端的那个窗口。）
static bool TargetIsAbove(HWND hwnd, HWND target)
{
    if (hwnd == target) {
        return false;
    }
    for (HWND w = GetWindow(hwnd, GW_HWNDPREV); w; w = GetWindow(w, GW_HWNDPREV)) {
        if (w == target) {
            return true;
        }
        if (w == GetDesktopWindow()) {
            break;
        }
    }
    return false;
}

// 泵几轮消息 + 沉降，让 z 序变更真正落到窗口管理器里。
static void Pump()
{
    for (int i = 0; i < 3; ++i) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(40);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void Report(const char* tag, HWND a, HWND b, BOOL ret, DWORD err)
{
    // 判据：**故意最后抬 B** 之后，B 是否还在 A 之上。
    //   B 仍在 A 之上 ⇒ band 没生效（A 只是普通置顶，谁最后抬谁在上）。
    //   B 落到 A 之下 ⇒ band 生效（A 被钉在更高的波段，抬 B 也压不住）。
    const bool bAbove = TargetIsAbove(a, b);
    printf("%-30s ret=%-5s err=%-4lu  抬B后B仍在A之上=%s  -> %s\n",
        tag, ret ? "TRUE" : "FALSE", (unsigned long)err,
        bAbove ? "是" : "否",
        bAbove ? "band 未生效" : "band 生效");
}

static void TryBand(SetWindowBandFn fn, HWND hwnd, HWND insertAfter, DWORD band, const char* tag)
{
    if (!fn) {
        printf("%-30s (SetWindowBand 未解析)\n", tag);
        return;
    }
    SetLastError(0);
    BOOL ret = fn(hwnd, insertAfter, band);
    DWORD err = GetLastError();
    printf("%-30s ret=%-5s err=%lu\n", tag, ret ? "TRUE" : "FALSE", (unsigned long)err);
}

int main(int argc, char** argv)
{
    if (argc > 1 && _stricmp(argv[1], "clean") == 0) {
        printf("(本探针不创建持久对象，无需清理)\n");
        return 0;
    }

    printf("=== SetWindowBand 行为探针 ===\n");
    printf("进程 pid=%lu  UIAccess=%s  提权=%s\n",
        (unsigned long)GetCurrentProcessId(),
        ProcessHasUiAccess() ? "有" : "无",
        ProcessElevated() ? "是" : "否");

    SetWindowBandFn setWindowBand = ResolveSetWindowBand();
    printf("user32!SetWindowBand 解析=%s\n\n", setWindowBand ? "成功" : "失败");

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClassName;
    RegisterClassExW(&wc);

    HWND a = CreateWindowExW(WS_EX_TOOLWINDOW, kClassName, L"A", WS_POPUP,
        0, 0, 120, 30, nullptr, nullptr, wc.hInstance, nullptr);
    HWND b = CreateWindowExW(WS_EX_TOOLWINDOW, kClassName, L"B", WS_POPUP,
        140, 0, 120, 30, nullptr, nullptr, wc.hInstance, nullptr);
    if (!a || !b) {
        printf("窗口创建失败 err=%lu\n", (unsigned long)GetLastError());
        return 1;
    }
    ShowWindow(a, SW_SHOWNOACTIVATE);
    ShowWindow(b, SW_SHOWNOACTIVATE);
    Pump();

    printf("--- 阶段 1：对照基线（两个都是普通置顶，最后抬 B）---\n");
    SetWindowPos(a, HWND_TOPMOST, 0, 0, 120, 30, SWP_NOACTIVATE);
    SetWindowPos(b, HWND_TOPMOST, 140, 0, 120, 30, SWP_NOACTIVATE);
    Pump();
    Report("基线（未调用 SetWindowBand）", a, b, TRUE, 0);

    printf("\n--- 阶段 2：SetWindowBand(A, HWND_TOPMOST, 2) 后**故意再抬 B** ---\n");
    SetLastError(0);
    BOOL r2 = setWindowBand ? setWindowBand(a, HWND_TOPMOST, 2) : FALSE;
    DWORD e2 = GetLastError();
    Pump();
    SetWindowPos(b, HWND_TOPMOST, 140, 0, 120, 30, SWP_NOACTIVATE);
    Pump();
    Report("band=2 (HWND_TOPMOST)", a, b, r2, e2);

    printf("\n--- 阶段 3：其它参数组合的返回码（探明 87 / 5 的来历）---\n");
    TryBand(setWindowBand, a, HWND_TOP, 2, "band=2 (HWND_TOP)");
    TryBand(setWindowBand, a, HWND_TOPMOST, 1, "band=1 (HWND_TOPMOST)");
    TryBand(setWindowBand, a, HWND_TOP, 1, "band=1 (HWND_TOP)");
    TryBand(setWindowBand, a, HWND_TOPMOST, 0, "band=0 (HWND_TOPMOST)");
    TryBand(setWindowBand, a, HWND_TOP, 0, "band=0 (HWND_TOP)");
    TryBand(setWindowBand, a, HWND_NOTOPMOST, 0, "band=0 (HWND_NOTOPMOST)");

    printf("\n--- 阶段 4：复位后对照（普通置顶下 A 应又回到 B 之下）---\n");
    SetWindowPos(a, HWND_TOPMOST, 0, 0, 120, 30, SWP_NOACTIVATE);
    SetWindowPos(b, HWND_TOPMOST, 140, 0, 120, 30, SWP_NOACTIVATE);
    Pump();
    Report("复位后（无 band）", a, b, TRUE, 0);

    DestroyWindow(a);
    DestroyWindow(b);
    UnregisterClassW(kClassName, wc.hInstance);
    printf("\n完成。\n");
    return 0;
}
