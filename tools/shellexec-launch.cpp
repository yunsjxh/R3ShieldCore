// shellexec-launch.exe —— 模拟"双击"启动一个程序。
//
// 为什么需要：`cmd /c start` 的父进程是 cmd（被 R3ShieldCore 直接拒），
// 而真正的"双击"父进程是 explorer。ShellExecuteEx 会走 Shell 的执行路径，
// 与双击最接近（对 .exe 会直接起进程，对文档会走关联程序）。
//
// 用法：shellexec-launch.exe <full-path-to-exe>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) {
        wprintf(L"usage: shellexec-launch.exe <exe-path>\n");
        return 2;
    }

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"open";
    sei.lpFile = argv[1];
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        wprintf(L"ShellExecuteEx failed: %lu (0x%08X)\n", err, err);
        return 1;
    }

    wprintf(L"launched, hProcess=%p\n", sei.hProcess);

    if (sei.hProcess) {
        DWORD wait = WaitForSingleObject(sei.hProcess, 3000);
        DWORD code = 0;
        GetExitCodeProcess(sei.hProcess, &code);
        wprintf(L"wait=%lu exitCode=0x%08X\n", wait, code);
        CloseHandle(sei.hProcess);
    }

    return 0;
}
