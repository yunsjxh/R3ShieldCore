//
// opstep.cpp —— 单步版探针，用于手动验证「始终允许」的 Op 隔离。
//
// 每次只做一个操作，做完就退出。这样可以在两次调用之间
// 用 toastclick 精确点击，观察第二次是否仍然弹窗。
//
// 用法：
//   opstep create <path>   建/覆盖文件（CREATE_ALWAYS）
//   opstep del    <path>   删除文件
//   opstep time   <path>   改时间戳
//
#include <windows.h>
#include <stdio.h>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) {
        wprintf(L"usage: opstep <create|del|time> <path>\n");
        return 1;
    }

    const wchar_t* action = argv[1];
    const wchar_t* path = argv[2];

    wprintf(L"opstep pid=%lu action=%s\n", GetCurrentProcessId(), action);
    wprintf(L"path=%s\n", path);

    if (_wcsicmp(action, L"create") == 0) {
        HANDLE h = CreateFileW(path, GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            wprintf(L"CreateFile FAILED err=%lu\n", GetLastError());
            return 2;
        }
        wprintf(L"CreateFile OK\n");
        CloseHandle(h);
    }
    else if (_wcsicmp(action, L"del") == 0) {
        SetLastError(0);
        if (!DeleteFileW(path)) {
            wprintf(L"DeleteFile FAILED err=%lu\n", GetLastError());
            return 3;
        }
        wprintf(L"DeleteFile OK\n");
    }
    else if (_wcsicmp(action, L"time") == 0) {
        HANDLE h = CreateFileW(path, FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            wprintf(L"CreateFile(W_ATTR) FAILED err=%lu\n", GetLastError());
            return 4;
        }
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        SetLastError(0);
        if (!SetFileTime(h, nullptr, nullptr, &ft)) {
            wprintf(L"SetFileTime FAILED err=%lu\n", GetLastError());
            CloseHandle(h);
            return 5;
        }
        wprintf(L"SetFileTime OK\n");
        CloseHandle(h);
    }
    else {
        wprintf(L"unknown action\n");
        return 1;
    }

    wprintf(L"done\n");
    return 0;
}
