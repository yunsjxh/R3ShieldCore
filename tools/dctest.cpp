// dctest.cpp —— 验证"如何区分屏幕 DC / 窗口 DC / 内存 DC"。
//
// 截屏拦截的判据全押在一件事上：BitBlt 的源 DC 是不是屏幕 DC。
// 这个探针把 WindowFromDC / GetDeviceCaps 在三种 DC 上的真实返回值打出来，
// 免得靠文档猜。
//
// 编译（见 tools/ 目录下的编译命令）：
//   cl /nologo /EHsc /std:c++17 dctest.cpp /Fe:dctest.exe /link user32.lib gdi32.lib

#include <windows.h>
#include <stdio.h>

static void Dump(const char* label, HDC dc)
{
    HWND desktop = GetDesktopWindow();
    HWND fromDc = dc ? WindowFromDC(dc) : nullptr;

    printf("%-28s dc=%p  WindowFromDC=%p  ==Desktop(%p)? %s   tech=%d  HORZRES=%d VERTRES=%d\n",
        label,
        (void*)dc,
        (void*)fromDc,
        (void*)desktop,
        (fromDc == desktop) ? "YES" : "no",
        dc ? GetDeviceCaps(dc, TECHNOLOGY) : -1,
        dc ? GetDeviceCaps(dc, HORZRES) : -1,
        dc ? GetDeviceCaps(dc, VERTRES) : -1);
}

int main()
{
    printf("DT_RASDISPLAY=%d  DT_RASPRINTER=%d  DT_RASPRINTER?\n", DT_RASDISPLAY, DT_RASPRINTER);

    // 1) 屏幕 DC：GetDC(NULL)
    HDC screen = GetDC(NULL);
    Dump("GetDC(NULL)", screen);

    // 2) 屏幕 DC 的另一种拿法：GetDC(GetDesktopWindow())
    HDC screen2 = GetDC(GetDesktopWindow());
    Dump("GetDC(GetDesktopWindow())", screen2);

    // 3) 内存 DC（CreateCompatibleDC）—— 截屏时当目标用
    HDC mem = screen ? CreateCompatibleDC(screen) : nullptr;
    Dump("CreateCompatibleDC(screen)", mem);

    // 4) 普通窗口 DC：拿任务栏当靶子
    HWND taskbar = FindWindowW(L"Shell_TrayWnd", nullptr);
    printf("Shell_TrayWnd = %p\n", (void*)taskbar);
    if (taskbar) {
        HDC winDc = GetDC(taskbar);
        Dump("GetDC(taskbar)", winDc);
        if (winDc) {
            ReleaseDC(taskbar, winDc);
        }
    }

    // 5) 真正做一次"截屏"：屏幕 DC → 内存 DC 的 BitBlt
    if (screen && mem) {
        HBITMAP bmp = CreateCompatibleBitmap(screen, 64, 64);
        HGDIOBJ old = SelectObject(mem, bmp);
        BOOL ok = BitBlt(mem, 0, 0, 64, 64, screen, 0, 0, SRCCOPY);
        printf("BitBlt(mem <- screen) = %d  GetLastError=%lu\n", ok, GetLastError());

        // 反向：内存 DC → 屏幕 DC（正常绘制路径，不该被判成截屏）
        BOOL ok2 = BitBlt(screen, 0, 0, 64, 64, mem, 0, 0, SRCCOPY);
        printf("BitBlt(screen <- mem) = %d  GetLastError=%lu\n", ok2, GetLastError());

        SelectObject(mem, old);
        DeleteObject(bmp);
    }

    if (mem) { DeleteDC(mem); }
    if (screen2) { ReleaseDC(GetDesktopWindow(), screen2); }
    if (screen) { ReleaseDC(NULL, screen); }

    printf("done\n");
    return 0;
}
