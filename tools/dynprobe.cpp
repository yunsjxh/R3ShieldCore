// dynprobe.cpp —— DLL加载 / 剪贴板 / 进程创建旁路 三类新监控的实测探针。
//
// 用法：
//   dynprobe <case> [outFile]
//
// case：
//   dll-temp           从 %TEMP% 加载一个临时 DLL（应高危：可写目录白加黑特征）
//   dll-system         从 System32 加载一个系统 DLL（应**无事件**：hook 层过滤掉）
//   dll-self           加载本进程同目录 DLL（非系统、非可写目录，应记录非高危）
//   dll-mapload        用 NtMapViewOfSection(SEC_IMAGE) 映射一个 DLL 映像（应高危）
//   clip-open          OpenClipboard（应只记录，非高危）
//   clip-read          OpenClipboard + GetClipboardData（应高危）
//   clip-roundtrip     写一段文本再读出（应产生 Open + Read 两类事件）
//   spawn-winexec      WinExec（应高危）
//   spawn-shellex      ShellExecuteExW（应高危）
//   spawn-token        CreateProcessWithTokenW（应高危；无权限时调用失败但事件照样上报）
//   spawn-logon        CreateProcessWithLogonW（应高危；需要密码，这里故意用假凭据）
//   all                全部跑一遍
//
// 编译：
//   cl /nologo /EHsc /std:c++17 /MT -source-charset:utf-8 dynprobe.cpp /Fe:dynprobe.exe
//      /link user32.lib gdi32.lib advapi32.lib shell32.lib ntdll.lib
//
// ⚠️ 探针自身会产生被监控的行为，所以引擎的 exclude= **不能**包含 tools 目录，
//    否则探针进程被 bypass、一个 hook 都不挂（见 HANDOVER §3.9）。

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// windows.h 默认不带 NTSTATUS（除非引 ntdef.h）。手工补上。
typedef LONG NTSTATUS;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// ---------------------------------------------------------------------
// 输出
// ---------------------------------------------------------------------
static FILE* g_out = nullptr;
static WCHAR g_tempDir[MAX_PATH] = {};

static void Say(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);

    if (g_out) {
        va_start(args, format);
        vfprintf(g_out, format, args);
        va_end(args);
        fflush(g_out);
    }
}

// ---------------------------------------------------------------------
// DLL 加载
// ---------------------------------------------------------------------

// 造一个最小合法 DLL 落在指定目录（避免依赖预先存在的样本）。
// 内容是一个极简 PE：这里直接用系统已有 DLL **复制**一份到目标目录，
// 这样一定是合法 PE，且路径可控。
static bool CopySampleDll(const WCHAR* destination) noexcept
{
    WCHAR systemDir[MAX_PATH] = {};
    GetSystemDirectoryW(systemDir, _countof(systemDir));

    // 挑一个很小、在几乎任何进程里都已加载过的系统 DLL 当样本。
    // 复制出来加载时才不会被"已加载同路径"短路掉。
    WCHAR source[MAX_PATH] = {};
    _snwprintf_s(source, _countof(source), _TRUNCATE, L"%s\\version.dll", systemDir);

    if (!CopyFileW(source, destination, FALSE)) {
        // version.dll 拿不到就退而求其次。
        _snwprintf_s(source, _countof(source), _TRUNCATE, L"%s\\wintrust.dll", systemDir);
        if (!CopyFileW(source, destination, FALSE)) {
            Say("  复制样本 DLL 失败（source=%ls，GetLastError=%lu）\n", source, GetLastError());
            return false;
        }
    }

    return true;
}

static void CaseDllTemp()
{
    WCHAR target[MAX_PATH] = {};
    _snwprintf_s(target, _countof(target), _TRUNCATE, L"%s\\dynprobe-payload.dll", g_tempDir);

    Say("样本落地点: %ls\n", target);
    if (!CopySampleDll(target)) {
        return;
    }

    HMODULE module = LoadLibraryW(target);
    Say("LoadLibraryW(%ls) -> %p  GetLastError=%lu\n", target, (void*)module, GetLastError());
    Say("  → 期望：DLL 事件 op=LoadLibrary，高危（从用户可写目录加载 = 白加黑特征）\n");

    if (module) {
        FreeLibrary(module);
    }
}

static void CaseDllSystem()
{
    // System32 里的 DLL —— 这是最热的加载路径，hook 层直接过滤，
    // 不该产生任何事件。这是**噪音测试**。
    HMODULE module = LoadLibraryW(L"C:\\Windows\\System32\\version.dll");
    Say("LoadLibraryW(System32\\version.dll) -> %p  GetLastError=%lu\n",
        (void*)module, GetLastError());
    Say("  → 期望：**无任何事件**（系统目录在 hook 层被过滤掉）\n");

    if (module) {
        FreeLibrary(module);
    }
}

static void CaseDllSelf()
{
    // 探针自己所在目录的 DLL —— 非系统目录也不是常见的可写目录。
    // 会记录，但文案是"加载非系统目录 DLL"（普通档）。
    WCHAR selfPath[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, selfPath, _countof(selfPath));
    WCHAR* slash = wcsrchr(selfPath, L'\\');
    if (slash) {
        *(slash + 1) = L'\0';
    }

    WCHAR target[MAX_PATH] = {};
    _snwprintf_s(target, _countof(target), _TRUNCATE, L"%sdynprobe-payload-self.dll", selfPath);
    if (!CopySampleDll(target)) {
        return;
    }

    HMODULE module = LoadLibraryW(target);
    Say("LoadLibraryW(%ls) -> %p  GetLastError=%lu\n", target, (void*)module, GetLastError());
    Say("  → 期望：DLL 事件，非高危（非系统目录但不属于常见可写目录）\n");

    if (module) {
        FreeLibrary(module);
    }
}

static void CaseDllMap()
{
    // 用 NtMapViewOfSection(SEC_IMAGE) 直接映射一个 DLL 映像。
    // 这是"手工映射"的形态：不经过 LdrLoadDll。
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        Say("ntdll.dll 未加载\n");
        return;
    }

    typedef NTSTATUS(NTAPI* NtOpenFileFn)(PHANDLE, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG);
    typedef NTSTATUS(NTAPI* NtCreateSectionFn)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    typedef NTSTATUS(NTAPI* NtMapViewOfSectionFn)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
        PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    typedef VOID(NTAPI* RtlInitUnicodeStringFn)(PVOID, PCWSTR);
    typedef NTSTATUS(NTAPI* NtCloseFn)(HANDLE);

    struct UNICODE_STRING_LOCAL
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    struct OBJECT_ATTRIBUTES_LOCAL
    {
        ULONG Length;
        HANDLE RootDirectory;
        UNICODE_STRING_LOCAL* ObjectName;
        ULONG Attributes;
        PVOID SecurityDescriptor;
        PVOID SecurityQualityOfService;
    };

    struct IO_STATUS_BLOCK_LOCAL
    {
        union { NTSTATUS Status; PVOID Pointer; };
        ULONG_PTR Information;
    };

    auto ntOpenFile = reinterpret_cast<NtOpenFileFn>(GetProcAddress(ntdll, "NtOpenFile"));
    auto ntCreateSection = reinterpret_cast<NtCreateSectionFn>(GetProcAddress(ntdll, "NtCreateSection"));
    auto ntMapView = reinterpret_cast<NtMapViewOfSectionFn>(GetProcAddress(ntdll, "NtMapViewOfSection"));
    auto rtlInitUnicode = reinterpret_cast<RtlInitUnicodeStringFn>(GetProcAddress(ntdll, "RtlInitUnicodeString"));
    auto ntClose = reinterpret_cast<NtCloseFn>(GetProcAddress(ntdll, "NtClose"));

    if (!ntOpenFile || !ntCreateSection || !ntMapView || !rtlInitUnicode) {
        Say("ntdll 导出找不到\n");
        return;
    }

    // 用一个 %TEMP% 里的 DLL 当映射源。
    WCHAR target[MAX_PATH] = {};
    _snwprintf_s(target, _countof(target), _TRUNCATE, L"%s\\dynprobe-payload.dll", g_tempDir);
    if (!CopySampleDll(target)) {
        return;
    }

    // 转成 \??\C:\... 形式
    WCHAR ntPath[MAX_PATH + 8] = {};
    _snwprintf_s(ntPath, _countof(ntPath), _TRUNCATE, L"\\??\\%s", target);

    UNICODE_STRING_LOCAL name = {};
    rtlInitUnicode(&name, ntPath);

    OBJECT_ATTRIBUTES_LOCAL attributes = {};
    attributes.Length = sizeof(attributes);
    attributes.ObjectName = &name;
    attributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

    IO_STATUS_BLOCK_LOCAL iosb = {};
    HANDLE file = nullptr;
    // NtOpenFile(ph, access, oa, iosb, shareAccess, openOptions)
    //   access       = GENERIC_READ(0x80000000) | SYNCHRONIZE(0x00100000)
    //   shareAccess  = FILE_SHARE_READ(1) | FILE_SHARE_WRITE(2) | FILE_SHARE_DELETE(4)
    //   openOptions  = FILE_NON_DIRECTORY_FILE(0x40) | FILE_SYNCHRONOUS_IO_NONALERT(0x20)
    NTSTATUS status = ntOpenFile(&file, 0x80000000 | 0x00100000,
        &attributes, &iosb, 0x1 | 0x2 | 0x4, 0x40 | 0x20);
    Say("NtOpenFile -> 0x%08X file=%p\n", (unsigned)status, file);
    if (status < 0) {
        return;
    }

    HANDLE section = nullptr;
    // NtCreateSection 参数：(SectionHandle, DesiredAccess, ObjectAttributes,
    //                        MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)
    // 要点：
    //   · DesiredAccess        = SECTION_MAP_READ(0x0004)
    //   · SectionPageProtection= PAGE_READONLY(0x02)
    //   · AllocationAttributes = SEC_IMAGE(0x01000000)   ← 别写成 0x02000000（那是 SEC_COMMIT）
    // 实测把 SEC_IMAGE 写成 0x02000000 时不会报错，但建出来的是**普通数据分区**，
    // 后面按映像映射才会失败 —— 这种静默错配最难查。
    status = ntCreateSection(&section, 0x0004 /* SECTION_MAP_READ */, nullptr, nullptr,
        0x02 /* PAGE_READONLY */, 0x01000000 /* SEC_IMAGE */, file);
    Say("NtCreateSection(SEC_IMAGE) -> 0x%08X section=%p\n", (unsigned)status, section);

    if (status >= 0 && section) {
        PVOID base = nullptr;
        SIZE_T viewSize = 0;
        // ⚠️ 实测定参（tools/mapfind.cpp 穷举得到，别再改）：
        //   SEC_IMAGE 分区用 NtMapViewOfSection 映射到当前进程时，唯一能成功的一组是
        //     AllocationType = ViewShare(1)
        //     Protect        = PAGE_READONLY(0x02)   ← 不是 0
        //     ViewSize       = 0（内核回填真实大小）
        //   常见错配的返回值：
        //     ViewUnmap(2) + ViewSize=0        → 0xC0000045 STATUS_INVALID_VIEW_SIZE
        //     ViewShare  + Protect=0           → 0xC0000045
        //     ViewShare  + Protect=PAGE_READWRITE 类 → 0xC0000022 ACCESS_DENIED（映像只读）
        status = ntMapView(section, GetCurrentProcess(), &base, 0, 0, nullptr, &viewSize,
            1 /* ViewShare */, 0 /* 忽略 */, 0x02 /* PAGE_READONLY */);
        Say("NtMapViewOfSection(SEC_IMAGE) -> 0x%08X base=%p vs=0x%zX\n",
            (unsigned)status, base, viewSize);
        Say("  → 期望：DLL 事件 op=MapSection，高危（手工映射特征）\n");
        ntClose(section);
    }

    ntClose(file);
    DeleteFileW(target);
}

// ---------------------------------------------------------------------
// 剪贴板
// ---------------------------------------------------------------------
static void CaseClipOpen()
{
    BOOL ok = OpenClipboard(nullptr);
    Say("OpenClipboard(NULL) -> %d  GetLastError=%lu\n", ok, GetLastError());
    Say("  → 期望：CLIP 事件 op=OpenClipboard，**非高危**（只记录）\n");
    if (ok) {
        CloseClipboard();
    }
}

static void CaseClipRoundtrip()
{
    // 先放一段文本进剪贴板，再读回来。
    if (!OpenClipboard(nullptr)) {
        Say("OpenClipboard 失败 GetLastError=%lu\n", GetLastError());
        return;
    }

    EmptyClipboard();

    const WCHAR* secret = L"R3ShieldCore-dynprobe-clipboard-secret";
    size_t bytes = (wcslen(secret) + 1) * sizeof(WCHAR);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory) {
        void* locked = GlobalLock(memory);
        if (locked) {
            memcpy(locked, secret, bytes);
            GlobalUnlock(memory);
            SetClipboardData(CF_UNICODETEXT, memory);
        }
    }

    CloseClipboard();
    Say("已写入剪贴板文本: %ls\n", secret);

    // 读回
    if (OpenClipboard(nullptr)) {
        HANDLE data = GetClipboardData(CF_UNICODETEXT);
        Say("GetClipboardData(CF_UNICODETEXT=13) -> %p  GetLastError=%lu\n", data, GetLastError());
        Say("  → 期望：CLIP 事件 op=OpenClipboard（非高危）+ op=GetClipboardData（高危）\n");
        CloseClipboard();
    }
}

// ---------------------------------------------------------------------
// 进程创建旁路
// ---------------------------------------------------------------------
static void CaseSpawnWinExec()
{
    UINT result = WinExec("cmd.exe /c exit", SW_HIDE);
    Say("WinExec(\"cmd.exe /c exit\") -> %u  GetLastError=%lu\n", result, GetLastError());
    Say("  → 期望：SPAWN 事件 op=WinExec，高危\n");
}

static void CaseSpawnShellExec()
{
    SHELLEXECUTEINFOW info = {};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    info.lpFile = L"cmd.exe";
    info.lpParameters = L"/c exit";
    info.nShow = SW_HIDE;

    BOOL ok = ShellExecuteExW(&info);
    Say("ShellExecuteExW(cmd.exe /c exit) -> %d  GetLastError=%lu\n", ok, GetLastError());
    Say("  → 期望：SPAWN 事件 op=ShellExecute，高危\n");

    if (ok && info.hProcess) {
        WaitForSingleObject(info.hProcess, 3000);
        CloseHandle(info.hProcess);
    }
}

static void CaseSpawnToken()
{
    // 用当前进程的 token 调 CreateProcessWithTokenW。
    // 非提权进程调用通常会失败（需要 SE_IMPERSONATE_NAME 或 SeAssignPrimaryToken），
    // 但**调用本身**会先进我们的 hook —— 事件照样上报。
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &token)) {
        Say("OpenProcessToken 失败 GetLastError=%lu\n", GetLastError());
        return;
    }

    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION processInfo = {};

    WCHAR cmd[] = L"cmd.exe /c exit";
    BOOL ok = CreateProcessWithTokenW(token, 0, nullptr, cmd, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &processInfo);
    Say("CreateProcessWithTokenW -> %d  GetLastError=%lu（非提权时失败是正常的）\n",
        ok, GetLastError());
    Say("  → 期望：SPAWN 事件 op=CreateProcessWithToken，高危（哪怕调用失败，事件也应上报）\n");

    if (ok) {
        WaitForSingleObject(processInfo.hProcess, 3000);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }

    CloseHandle(token);
}

static void CaseSpawnLogon()
{
    // 故意用假凭据 —— 调用一定失败，但**调用本身**会先经过我们的 hook。
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION processInfo = {};

    WCHAR cmd[] = L"cmd.exe /c exit";
    BOOL ok = CreateProcessWithLogonW(L"dynprobe_nobody", L".", L"wrong_password",
        LOGON_WITH_PROFILE, nullptr, cmd, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &processInfo);
    Say("CreateProcessWithLogonW(假凭据) -> %d  GetLastError=%lu（失败是预期的）\n",
        ok, GetLastError());
    Say("  → 期望：SPAWN 事件 op=CreateProcessWithLogon，高危\n");

    if (ok) {
        WaitForSingleObject(processInfo.hProcess, 3000);
        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }
}

// ---------------------------------------------------------------------
int main(int argc, char** argv)
{
    const char* testCase = (argc > 1) ? argv[1] : "all";

    if (argc > 2) {
        fopen_s(&g_out, argv[2], "wb");
        if (g_out) {
            fwrite("\xEF\xBB\xBF", 1, 3, g_out);
        }
    }

    GetTempPathW(_countof(g_tempDir), g_tempDir);
    // GetTempPathW 返回的路径**带末尾反斜杠**（`C:\Users\...\Temp\`）。
    // 后面所有拼路径的地方都写 `%s\\xxx` → 会拼出 `Temp\\xxx` 双反斜杠，
    // 传给 NtOpenFile 就是 STATUS_OBJECT_NAME_INVALID(0xC0000033)。
    // 这里统一去掉末尾反斜杠，一处修好所有调用点。
    for (size_t i = wcslen(g_tempDir); i > 0 && (g_tempDir[i - 1] == L'\\' || g_tempDir[i - 1] == L'/'); --i) {
        g_tempDir[i - 1] = L'\0';
    }

    Say("dynprobe pid=%lu  case=%s\n", GetCurrentProcessId(), testCase);
    Say("=========================================================\n");

    // ⚠️ 必须等注入完成再做任何事。
    //
    // 引擎是"发现新进程 → 远程注入 → DLL 在目标进程里装 hook"的异步流程，
    // 从进程创建到 hook 真正生效有几十毫秒窗口。探针如果一起来就干活，
    // 常出现"这次拦到了、下次没拦到"的假象（实测 dll-mapload 就这样：
    // 同样的代码时好时坏，其实是注入没跑完）。
    // 睡足再开始 —— 这个等待只影响探针，不影响被测代码本身。
    const char* waitEnv = getenv("DYNPROBE_WAIT_MS");
    DWORD waitMs = waitEnv ? (DWORD)atoi(waitEnv) : 1500;
    if (waitMs > 0) {
        Say("等待注入完成 %lu ms ...\n", waitMs);
        Sleep(waitMs);
    }

    bool all = (strcmp(testCase, "all") == 0);

    if (all || strcmp(testCase, "dll-temp") == 0) { CaseDllTemp(); }
    if (all || strcmp(testCase, "dll-system") == 0) { CaseDllSystem(); }
    if (all || strcmp(testCase, "dll-self") == 0) { CaseDllSelf(); }
    if (all || strcmp(testCase, "dll-mapload") == 0) { CaseDllMap(); }
    if (all || strcmp(testCase, "clip-open") == 0) { CaseClipOpen(); }
    if (all || strcmp(testCase, "clip-read") == 0) { CaseClipRoundtrip(); }
    if (all || strcmp(testCase, "clip-roundtrip") == 0) { CaseClipRoundtrip(); }
    if (all || strcmp(testCase, "spawn-winexec") == 0) { CaseSpawnWinExec(); }
    if (all || strcmp(testCase, "spawn-shellex") == 0) { CaseSpawnShellExec(); }
    if (all || strcmp(testCase, "spawn-token") == 0) { CaseSpawnToken(); }
    if (all || strcmp(testCase, "spawn-logon") == 0) { CaseSpawnLogon(); }

    Say("=========================================================\n");
    Say("完成\n");

    if (g_out) {
        fclose(g_out);
    }

    return 0;
}
