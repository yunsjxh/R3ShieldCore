// _screen_probe.cpp -- 为什么从屏幕 BitBlt 失败？
#include <cstdio>
#include <windows.h>

int main()
{
    // 当前进程挂在哪个窗口站 / 桌面
    HWINSTA ws = GetProcessWindowStation();
    HDESK dk = GetThreadDesktop(GetCurrentThreadId());
    char wsName[256] = {};
    char dkName[256] = {};
    DWORD need = 0;
    if (ws) {
        GetUserObjectInformationA(ws, UOI_NAME, wsName, sizeof(wsName) - 1, &need);
    }
    if (dk) {
        GetUserObjectInformationA(dk, UOI_NAME, dkName, sizeof(dkName) - 1, &need);
    }
    printf("windowstation = '%s'\n", wsName);
    printf("desktop       = '%s'\n", dkName);

    printf("SM_CXSCREEN=%d SM_CYSCREEN=%d\n",
        GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    printf("SM_CXVIRTUALSCREEN=%d SM_CYVIRTUALSCREEN=%d\n",
        GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));

    HDC screen = GetDC(nullptr);
    printf("GetDC(NULL) = %p (err=%lu)\n", (void*)screen, GetLastError());
    if (!screen) {
        return 1;
    }

    const int w = 64, h = 32;
    HDC memory = CreateCompatibleDC(screen);
    printf("CreateCompatibleDC = %p (err=%lu)\n", (void*)memory, GetLastError());
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    printf("CreateCompatibleBitmap = %p (err=%lu)\n", (void*)bmp, GetLastError());

    SetLastError(0);
    const BOOL blt = BitBlt(memory, 0, 0, w, h, screen, 0, 0, SRCCOPY | CAPTUREBLT);
    const DWORD e1 = GetLastError();
    printf("BitBlt(SRCCOPY|CAPTUREBLT) = %d err=%lu\n", blt, e1);

    SetLastError(0);
    const BOOL blt2 = BitBlt(memory, 0, 0, w, h, screen, 0, 0, SRCCOPY);
    const DWORD e2 = GetLastError();
    printf("BitBlt(SRCCOPY) = %d err=%lu\n", blt2, e2);

    // 换一种：用 GetDC(NULL) 的兼容位图 + GetPixel 直接读屏幕
    SetLastError(0);
    const COLORREF px = GetPixel(screen, 5, 5);
    printf("GetPixel(screen,5,5) = 0x%08lX (CLR_INVALID=0xFFFFFFFF) err=%lu\n",
        (unsigned long)px, GetLastError());

    return 0;
}
