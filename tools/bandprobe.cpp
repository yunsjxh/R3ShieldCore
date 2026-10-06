// bandprobe.cpp —— 用最小实验判定 user32!SetWindowBand 的真实行为。
//
// 要回答的三个问题（此前只能靠猜）：
//   1. SetWindowBand(hwnd, HWND_TOPMOST, band) 会不会顺手置上 WS_EX_TOPMOST？
//      —— 决定「S3 只扫 WS_EX_TOPMOST」会不会漏掉带 band 的窗口。
//   2. band=2（UIAccess 波段）在没有 UIAccess 令牌时会不会失败？失败码是什么？
//   3. GetWindowBand 是否存在、能读出什么。
//
// 只创建隐藏窗口，不抢焦点、不改 Z 序可见结果，跑完即退。

#include <windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* SetWindowBandFn)(HWND, HWND, DWORD);
typedef BOOL(WINAPI* GetWindowBandFn)(HWND, PDWORD);

static SetWindowBandFn g_setBand = nullptr;
static GetWindowBandFn g_getBand = nullptr;

static LRESULT CALLBACK ProbeProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    return DefWindowProcW(h, m, w, l);
}

static const char* TopMostBit(HWND h)
{
    const LONG_PTR ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
    return (ex & WS_EX_TOPMOST) ? "WS_EX_TOPMOST=1" : "WS_EX_TOPMOST=0";
}

static void ReportBand(HWND h, const char* tag)
{
    DWORD band = 0xDEADBEEF;
    const BOOL ok = g_getBand ? g_getBand(h, &band) : FALSE;
    if (!g_getBand) {
        printf("  [%s] GetWindowBand: 导出不存在\n", tag);
        return;
    }
    if (ok) {
        printf("  [%s] GetWindowBand ok=%d band=%lu   %s\n", tag, ok, (unsigned long)band, TopMostBit(h));
    } else {
        printf("  [%s] GetWindowBand FAIL err=%lu   %s\n", tag, (unsigned long)GetLastError(), TopMostBit(h));
    }
}

static void TrySet(HWND h, HWND insertAfter, DWORD band, const char* tag)
{
    if (!g_setBand) {
        printf("  [%s] SetWindowBand: 导出不存在\n", tag);
        return;
    }
    SetLastError(ERROR_SUCCESS);
    const BOOL ok = g_setBand(h, insertAfter, band);
    const DWORD err = ok ? 0 : GetLastError();
    printf("  [%s] SetWindowBand(insertAfter=%s band=%lu) -> ok=%d err=%lu   %s\n",
        tag,
        insertAfter == HWND_TOPMOST ? "HWND_TOPMOST" : (insertAfter == HWND_NOTOPMOST ? "HWND_NOTOPMOST" : "other"),
        (unsigned long)band, ok, (unsigned long)err, TopMostBit(h));
    ReportBand(h, tag);
}

int main()
{
    const HMODULE user32 = GetModuleHandleW(L"user32.dll");
    g_setBand = user32 ? (SetWindowBandFn)(void*)GetProcAddress(user32, "SetWindowBand") : nullptr;
    g_getBand = user32 ? (GetWindowBandFn)(void*)GetProcAddress(user32, "GetWindowBand") : nullptr;

    printf("=== user32!SetWindowBand 行为探针 ===\n");
    printf("SetWindowBand 导出: %s\n", g_setBand ? "存在" : "不存在");
    printf("GetWindowBand 导出: %s\n", g_getBand ? "存在" : "不存在");

    // 本进程是否带 UIAccess —— 决定 band=2 能不能成
    HANDLE token = nullptr;
    DWORD uiAccess = 0, returned = 0;
    bool haveUiAccess = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenUIAccess, &uiAccess, sizeof(uiAccess), &returned)) {
            haveUiAccess = uiAccess != 0;
        }
        CloseHandle(token);
    }
    printf("本进程 UIAccess = %d   （band=2 的成败应当与之相关）\n\n", haveUiAccess ? 1 : 0);

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = ProbeProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"R3ShieldCoreBandProbe";
    if (!RegisterClassExW(&wc)) {
        printf("RegisterClassExW failed err=%lu\n", (unsigned long)GetLastError());
        return 2;
    }

    HWND h = CreateWindowExW(WS_EX_TOOLWINDOW, wc.lpszClassName, L"bandprobe",
        WS_POPUP, 0, 0, 100, 100, nullptr, nullptr, wc.hInstance, nullptr);
    if (!h) {
        printf("CreateWindowExW failed err=%lu\n", (unsigned long)GetLastError());
        return 3;
    }

    ReportBand(h, "初始");
    printf("\n-- 矩阵：insertAfter x band（找出有没有能成功的组合）--\n");
    struct { HWND after; const char* name; } afters[] = {
        { HWND_TOPMOST,    "TOPMOST"    },
        { HWND_NOTOPMOST,  "NOTOPMOST"  },
        { HWND_TOP,        "TOP"        },
        { HWND_BOTTOM,     "BOTTOM"     },
        { nullptr,         "NULL"       },
    };
    for (const auto& a : afters) {
        for (DWORD band = 0; band <= 4; ++band) {
            char tag[64];
            sprintf_s(tag, "%s/band%lu", a.name, (unsigned long)band);
            TrySet(h, a.after, band, tag);
        }
    }
    printf("\n-- 归还：NOTOPMOST + band0 --\n");
    TrySet(h, HWND_NOTOPMOST, 0, "reset");

    DestroyWindow(h);
    printf("\n=== done ===\n");
    return 0;
}
