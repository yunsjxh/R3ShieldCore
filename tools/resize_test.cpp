// 把 GUI 窗口改小，验证自适布局（底部统计栏必须还在）。
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) { printf("usage: resize_test <w> <h>\n"); return 1; }
    int w = _wtoi(argv[1]);
    int h = _wtoi(argv[2]);

    HWND hwnd = FindWindowW(L"R3ShieldCoreMainWindow", nullptr);
    if (!hwnd) { printf("main window not found\n"); return 1; }

    SetWindowPos(hwnd, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
    printf("resized to %dx%d\n", w, h);
    Sleep(600);
    return 0;
}
