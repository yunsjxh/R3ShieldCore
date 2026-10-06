//
// opcache.cpp —— 验证「始终允许」的决策缓存是否区分操作类型。
//
// 场景：对同一个敏感路径，先做 A 操作（CreateFile 建/覆盖），
// 再做 B 操作（SetFileTime 改时间戳）。
//
// 期望（修复后）：
//   在 A 的弹窗上点「始终允许」→ 只对该 (进程,路径,操作A) 放行；
//   B 仍然要单独弹窗询问（因为 Op 不同）。
//
// 用法：opcache.exe [path]
//
#include <windows.h>
#include <stdio.h>

static void DoCreate(const wchar_t* path)
{
    wprintf(L"\n[操作A] CreateFile (CREATE_ALWAYS = 建/覆盖)\n");
    HANDLE h = CreateFileW(path, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"  -> FAILED, err=%lu\n", GetLastError());
        return;
    }
    wprintf(L"  -> OK\n");
    CloseHandle(h);
}

static void DoSetTime(const wchar_t* path)
{
    wprintf(L"\n[操作B] SetFileTime (改时间戳)\n");
    HANDLE h = CreateFileW(path, FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"  -> CreateFile(W_ATTR) FAILED, err=%lu\n", GetLastError());
        return;
    }
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    SetLastError(0);
    BOOL ok = SetFileTime(h, nullptr, nullptr, &ft);
    wprintf(L"  -> SetFileTime %s, err=%lu\n", ok ? L"OK" : L"FAILED", GetLastError());
    CloseHandle(h);
}

static void DoDelete(const wchar_t* path)
{
    wprintf(L"\n[操作C] DeleteFile\n");
    SetLastError(0);
    BOOL ok = DeleteFileW(path);
    wprintf(L"  -> DeleteFile %s, err=%lu\n", ok ? L"OK" : L"FAILED", GetLastError());
}

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* path = (argc > 1) ? argv[1]
        : L"C:\\Windows\\System32\\R3ShieldCoreOpCacheTest.txt";

    wprintf(L"opcache 探针 pid=%lu\n目标: %s\n", GetCurrentProcessId(), path);

    DoCreate(path);   // A：建/覆盖
    DoSetTime(path);  // B：改时间戳（应与 A 不同的 Op，需单独询问）
    DoDelete(path);   // C：删除（与 A 也不同的 Op）

    wprintf(L"\n完成。\n");
    return 0;
}
