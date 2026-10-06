// dibprobe.cpp —— 验证 GetDIBits 作为"截屏判据"是否可行。
//
// 背景：ScreenGuard 现在挂 gdi32!BitBlt，判据是"源 DC 是屏幕 DC"。
// 但存在第三条截屏路径：GetDC(NULL) 拿屏幕 DC 后**不走 BitBlt**，
// 而是直接 GetDIBits(screenDc, ...) 读像素。这条路径现在完全没有监控。
//
// 问题是 GetDIBits 极其常用（任何读回位图像素的操作都走它），
// 所以不能无差别上报。这个探针要回答的是：
//
//   Q1  GetDIBits 的第一个参数 hdc 在"屏幕截屏"和"普通位图读回"两种
//       场景下，分别是什么？能否用同一个 WindowFromDC 判据区分？
//
//   Q2  屏幕 DC 到底能不能直接传给 GetDIBits？（文档说 hdc 必须与
//       hbm 兼容，屏幕 DC 传进去会不会直接失败？）
//
// 编译：
//   cl /nologo /EHsc /std:c++17 dibprobe.cpp /Fe:dibprobe.exe /link user32.lib gdi32.lib

#include <windows.h>
#include <stdio.h>

namespace
{
    void Probe(const char* label, HDC hdc, HBITMAP hbm)
    {
        if (!hdc || !hbm) {
            printf("%-34s hdc=%p hbm=%p  (无法测试)\n", label, (void*)hdc, (void*)hbm);
            return;
        }

        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = 4;
        bmi.bmiHeader.biHeight = -4;
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        DWORD pixels[16] = {};
        SetLastError(0);

        int lines = GetDIBits(hdc, hbm, 0, 4, pixels, &bmi, DIB_RGB_COLORS);
        const DWORD err = GetLastError();

        HWND fromDc = nullptr;
        __try {
            fromDc = WindowFromDC(hdc);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            fromDc = (HWND)-1;
        }

        printf("%-34s GetDIBits=%d err=%-5lu  WindowFromDC=%p ==Desktop? %s\n",
            label, lines, err, (void*)fromDc,
            (fromDc == GetDesktopWindow()) ? "YES" : "no");
    }
}

int main()
{
    printf("GetDIBits 截屏判据探测\n");
    printf("DesktopWindow = %p\n\n", (void*)GetDesktopWindow());

    // ---- 场景 1：直接对屏幕 DC 调 GetDIBits（"第三条截屏路径"）----
    HDC screen = GetDC(NULL);
    HBITMAP screenBmp = screen ? CreateCompatibleBitmap(screen, 4, 4) : nullptr;
    Probe("screen DC + screen bitmap", screen, screenBmp);

    // ---- 场景 2：内存 DC（普通读回位图）----
    HDC mem = screen ? CreateCompatibleDC(screen) : nullptr;
    HBITMAP memBmp = screen ? CreateCompatibleBitmap(screen, 4, 4) : nullptr;
    if (mem && memBmp) {
        HGDIOBJ old = SelectObject(mem, memBmp);
        Probe("memory DC (SelectObject 后)", mem, memBmp);
        SelectObject(mem, old);
    }

    // ---- 场景 3：DIB section —— 现代截屏/编解码最常用的路径 ----
    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 4;
    bmi.bmiHeader.biHeight = -4;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP dibSection = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (mem && dibSection) {
        HGDIOBJ old = SelectObject(mem, dibSection);
        if (screen) {
            BitBlt(mem, 0, 0, 4, 4, screen, 0, 0, SRCCOPY);
        }
        Probe("memory DC + DIB section (BitBlt 后)", mem, dibSection);
        SelectObject(mem, old);
    }

    // ---- 场景 4：窗口 DC ----
    HWND taskbar = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (taskbar) {
        HDC winDc = GetDC(taskbar);
        HBITMAP winBmp = winDc ? CreateCompatibleBitmap(winDc, 4, 4) : nullptr;
        Probe("taskbar 窗口 DC", winDc, winBmp);
        if (winBmp) { DeleteObject(winBmp); }
        if (winDc) { ReleaseDC(taskbar, winDc); }
    }

    // ---- 关键结论验证：GetDIBits 的 hdc 一定要传吗？传 NULL 能行吗？----
    printf("\n--- hdc=NULL 的边界 ---\n");
    {
        HDC nullCase = nullptr;
        BITMAPINFO info = {};
        info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info.bmiHeader.biWidth = 4;
        info.bmiHeader.biHeight = -4;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        DWORD px[16] = {};
        SetLastError(0);
        int lines = GetDIBits(nullCase, dibSection, 0, 4, px, &info, DIB_RGB_COLORS);
        printf("GetDIBits(NULL, dibSection...) = %d  err=%lu\n", lines, GetLastError());
    }

    if (dibSection) { DeleteObject(dibSection); }
    if (memBmp) { DeleteObject(memBmp); }
    if (mem) { DeleteDC(mem); }
    if (screenBmp) { DeleteObject(screenBmp); }
    if (screen) { ReleaseDC(NULL, screen); }

    printf("\ndone\n");
    return 0;
}
