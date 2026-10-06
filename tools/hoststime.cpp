// hoststime.cpp —— 最小探针：对 hosts 文件做 SetFileTime（改时间戳）
// 用于验证「高危文件操作在 ASK 模式是否弹窗」。
// 用法：hoststime [path]
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* path = (argc > 1) ? argv[1] : L"C:\\Windows\\System32\\drivers\\etc\\hosts";

    wprintf(L"hoststime 探针 pid=%lu\n", GetCurrentProcessId());
    wprintf(L"目标: %s\n", path);

    HANDLE h = CreateFileW(path, FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFile(FILE_WRITE_ATTRIBUTES) 失败: %lu\n", GetLastError());
        return 1;
    }
    wprintf(L"CreateFile OK\n");

    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);

    SetLastError(0);
    BOOL ok = SetFileTime(h, nullptr, nullptr, &ft);
    DWORD err = GetLastError();
    wprintf(L"SetFileTime -> %s (err=%lu)\n", ok ? L"OK" : L"FAILED", err);

    CloseHandle(h);
    wprintf(L"完成。\n");
    return ok ? 0 : 2;
}
