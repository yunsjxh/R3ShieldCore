// probe_launch.cpp —— 以管理员身份启动引擎，等 12 秒，报告存活 + 读输出。
//
// 用途：本环境里 PowerShell 工具的 Start-Process -Verb RunAs 时常返回空；
// 改用原生 ShellExecuteEx("runas") 更可控。
//
// 用法：probe_launch.exe <engine.exe> <workdir> <stdout.log> <stderr.log>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string>

static std::wstring Quote(const std::wstring& s) { return L"\"" + s + L"\""; }

int wmain(int argc, wchar_t** argv)
{
    if (argc < 5) {
        wprintf(L"usage: probe_launch.exe <engine.exe> <workdir> <out.log> <err.log>\n");
        return 2;
    }

    std::wstring exe = argv[1], wd = argv[2], outl = argv[3], errl = argv[4];

    // 用 cmd 重定向，父是 cmd —— 但我们是 runas 提升，"人启动"判据不看 cmd 与否
    // （这里只是为了拿到输出，不影响被测行为）。
    // cmd.exe needs an extra quote pair when the command itself is quoted;
    // without it, the redirections can be parsed as part of the executable
    // token and no diagnostic files are created.
    std::wstring cmd = L"/d /c \"\"" + exe + L"\" > \"" + outl + L"\" 2> \"" + errl + L"\"\"";

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = L"runas";
    sei.lpFile = L"cmd.exe";
    sei.lpParameters = cmd.c_str();
    sei.lpDirectory = wd.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        wprintf(L"ShellExecuteEx(runas) failed: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"launched (elevated). waiting 12s...\n");
    Sleep(12000);

    // 检查引擎是否还在（用 tasklist 结果文件判断更简单：这里只看退出码）
    DWORD code = 0;
    DWORD w = WaitForSingleObject(sei.hProcess, 0);
    if (w == WAIT_TIMEOUT) {
        wprintf(L"status=ALIVE\n");
    } else {
        GetExitCodeProcess(sei.hProcess, &code);
        wprintf(L"status=DEAD exitCode=0x%08X (%lu)\n", code, code);
    }
    CloseHandle(sei.hProcess);
    return 0;
}
