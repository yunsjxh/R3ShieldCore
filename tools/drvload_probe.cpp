// ============================================================================
//  drvload_probe.cpp —— 内核驱动"能不能被加载"的**实证**探针
//
//  为什么写这个：
//    用 signtool verify /kp 得到的结论是"证书链终止于不受信任的根"，
//    但这只是**用户态信任库**的看法。内核加载驱动走的是一条**不同的**判定路径
//    （ci.dll / Code Integrity，看的是签名策略、testsigning 位、EKU、以及
//     有没有 cat 目录），两者并不等价。
//    "实践是检验真理的唯一标准" —— 所以这里不复用任何签名工具的结论，
//    直接把服务建出来、StartService 一次，看内核**实际**返回什么。
//
//  判据（必须是内核给的原话，不是我们推断的）：
//    A. StartService 返回码（Win32，需翻译成 NTSTATUS）
//    B. 系统事件日志里 Code Integrity / 内核加载器 记的具体消息
//
//  ★ 本程序**可逆**：跑完自动删服务、删驱动文件（除非 -keep）。
//  ★ 本程序不碰引导配置、不开 testsigning —— 只测"现在这个状态认不认"。
//
//  构建（见 build_drvload_probe.sh）：
//    cl /nologo /EHsc /std:c++17 /MT /O2 drvload_probe.cpp advapi32.lib wevtapi.lib
//
//  用法：
//    drvload_probe.exe <driver.sys> [服务名] [--keep] [--start-type boot|system|demand]
//                      [--no-pause] [--log <path>]
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winver.h>
#include <winevt.h>
#include <clocale>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wevtapi.lib")

// ---------------------------------------------------------------------------
//  日志：同时打控制台和文件。
//  ★ 铁律 72：requireAdministrator 的程序从 PowerShell -Verb RunAs 起来时
//    没法重定向 stdout（-Verb 与 -Redirect* 互斥）。所以自己写日志文件。
// ---------------------------------------------------------------------------
static FILE* g_log = nullptr;
static bool  g_nopause = false;   // --no-pause：脚本/提权场景确定性地不等回车
static bool IsElevated();   // 前向声明（定义在下面）

static void LogOpen(const wchar_t* path) { g_log = _wfopen(path, L"wb"); }

static void P(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
    fflush(stdout);
    if (g_log) {
        va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
        fflush(g_log);
    }
}
#define printf(...) P(__VA_ARGS__)

// ---------------------------------------------------------------------------
//  不加参数就能跑的自检：把"内核愿不愿意加载驱动"的几个**前提**直接读出来。
//  这些都是注册表/系统变量，不需要 shell out（铁律 155）。
// ---------------------------------------------------------------------------
static void DumpLoadPrereqs()
{
    printf("\n---- 加载前提自检 ----\n");
    // 1. Secure Boot（SecureBoot\State\UEFISecureBootEnabled）
    DWORD sb = 0, sz = sizeof(sb), type = 0;
    HKEY k = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                      0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"UEFISecureBootEnabled", nullptr, &type, (BYTE*)&sb, &sz) == ERROR_SUCCESS)
            printf("  Secure Boot            : %s (%lu)  %s\n",
                   sb ? "ON" : "OFF", (unsigned long)sb,
                   sb ? "  <== 自签名驱动**一定**加载不了" : "");
        else
            printf("  Secure Boot            : 读不到值（可能传统 BIOS）\n");
        RegCloseKey(k);
    } else {
        printf("  Secure Boot            : 注册表项不存在（多为传统 BIOS / 无 UEFI）\n");
    }

    // 2. Code Integrity 策略强制状态（DeviceGuard）
    DWORD ci = 0xFFFFFFFF; sz = sizeof(ci);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                      0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, L"Enabled", nullptr, &type, (BYTE*)&ci, &sz) == ERROR_SUCCESS)
            printf("  HVCI (内存完整性)      : %lu\n", (unsigned long)ci);
        RegCloseKey(k);
    }
    DWORD scen = 0xFFFFFFFF; sz = sizeof(scen);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy",
                      0, KEY_READ, &k) == ERROR_SUCCESS) {
        printf("  CI\\Policy 键存在       : 有自定义 CI 策略\n");
        RegCloseKey(k);
    } else {
        printf("  CI\\Policy 键           : 无\n");
    }

    // 3. BCD testsigning —— 直接读 BCD 存储（HKLM\BCD00000000）
    //    testsigning 元素 = 0x26000009（BOOL，值为 1 表示开）
    bool foundTs = false;
    HKEY hBcd = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"BCD00000000\\Objects", 0, KEY_READ, &hBcd) == ERROR_SUCCESS) {
        wchar_t sub[256]; DWORD idx = 0, subLen;
        while (true) {
            subLen = 256;
            if (RegEnumKeyExW(hBcd, idx++, sub, &subLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;
            std::wstring p = std::wstring(L"BCD00000000\\Objects\\") + sub + L"\\Elements\\26000009";
            HKEY he = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, p.c_str(), 0, KEY_READ, &he) == ERROR_SUCCESS) {
                BYTE buf[64]{}; DWORD bs = sizeof(buf), t2 = 0;
                if (RegQueryValueExW(he, L"Element", nullptr, &t2, buf, &bs) == ERROR_SUCCESS) {
                    printf("  BCD testsigning        : 元素已设置（对象 %ls, %lu 字节）"
                           "  <== 测试签名模式**已开**\n", sub, (unsigned long)bs);
                    foundTs = true;
                }
                RegCloseKey(he);
            }
        }
        RegCloseKey(hBcd);
    }
    if (!foundTs)
        printf("  BCD testsigning        : 未设置  <== 说明**没开**测试签名模式\n");

    // 4. 当前进程是否 System（内核加载器视角）
    printf("  当前进程               : %ls\n", IsElevated() ? L"已提权" : L"未提权");
}

// ---------------------------------------------------------------------------
//  ★ 铁律 157：控制台双击"一闪就过" = 窗口随进程退出关闭。
//    自停 + 等一次回车，让用户能看见结果。
// ---------------------------------------------------------------------------
static void MaybePause()
{
    // ★ 铁律 157：双击时窗口随进程退出关闭 → 自停一次。
    //   但**自动化运行**必须不阻塞。两条路都要有：
    //     ① 环境变量 R3SC_NOPAUSE=1 —— 同控制台调用时够用；
    //     ② --no-pause 开关 —— UAC 提权会换令牌、环境变量不保证传进去
    //        （Start-Process -Verb RunAs 实测会停在"按回车"⇒ -Wait 永久阻塞）。
    bool nopause = g_nopause;
    wchar_t env[8]{};
    if (GetEnvironmentVariableW(L"R3SC_NOPAUSE", env, 8) && env[0] == L'1')
        nopause = true;
    if (g_log) { fflush(g_log); fclose(g_log); g_log = nullptr; }
    if (nopause) return;
    DWORD owners[2] = { 0, 0 };
    DWORD n = GetConsoleProcessList(owners, 2);
    // 只有本进程独占总控制台（n<=1）才等 —— 从管道/CI 里跑不该卡住
    if (n <= 1) {
        printf("\n按回车退出...");
        fflush(stdout);
        char buf[8];
        if (fgets(buf, sizeof(buf), stdin)) {}
    }
}

static const char* Win32ErrName(DWORD e)
{
    switch (e) {
    case ERROR_SUCCESS:                          return "ERROR_SUCCESS (0)";
    case ERROR_ACCESS_DENIED:                    return "ERROR_ACCESS_DENIED (5)";
    case ERROR_INVALID_PARAMETER:                return "ERROR_INVALID_PARAMETER (87)";
    case ERROR_FILE_NOT_FOUND:                   return "ERROR_FILE_NOT_FOUND (2)";
    case ERROR_PATH_NOT_FOUND:                   return "ERROR_PATH_NOT_FOUND (3)";
    case ERROR_SERVICE_DOES_NOT_EXIST:           return "ERROR_SERVICE_DOES_NOT_EXIST (1060)";
    case ERROR_SERVICE_EXISTS:                   return "ERROR_SERVICE_EXISTS (1073)";
    case ERROR_SERVICE_MARKED_FOR_DELETE:        return "ERROR_SERVICE_MARKED_FOR_DELETE (1072)";
    case ERROR_INVALID_SERVICE_ACCOUNT:          return "ERROR_INVALID_SERVICE_ACCOUNT (1057)";
    case ERROR_SERVICE_ALREADY_RUNNING:          return "ERROR_SERVICE_ALREADY_RUNNING (1056)";
    // ---- ★ 下面这几条才是关键，是内核加载器的判据 ----
    case ERROR_INVALID_IMAGE_HASH:               return "ERROR_INVALID_IMAGE_HASH (577)  <== 镜像哈希不在允许的签名里（签名/信任判定失败）";
    case ERROR_DRIVER_FAILED_PRIOR_UNLOAD:       return "ERROR_DRIVER_FAILED_PRIOR_UNLOAD (654)";
    case ERROR_DRIVER_FAILED_SLEEP:              return "ERROR_DRIVER_FAILED_SLEEP (653)";
    case ERROR_DRIVER_CANCEL_TIMEOUT:            return "ERROR_DRIVER_CANCEL_TIMEOUT (594)";
    case ERROR_DRIVER_BLOCKED:                   return "ERROR_DRIVER_BLOCKED (1275)";
    case ERROR_SERVICE_DEPENDENCY_FAIL:          return "ERROR_SERVICE_DEPENDENCY_FAIL (1068)";
    default:                                     return "(见上表未列出的码)";
    }
}

// StartService 失败时 GetLastError 给的是 Win32 码；内核实际返回的是 NTSTATUS。
// 对驱动来说 Windows 会把 NTSTATUS 塞进 Win32 错误里，常见映射：
static void ExplainWin32(DWORD e)
{
    printf("       Win32 码 : %lu  %s\n", (unsigned long)e, Win32ErrName(e));
    switch (e) {
    case ERROR_INVALID_IMAGE_HASH: // 577
        printf("       ^ 解读   : 内核把驱动镜像算哈希后，发现它不在可接受的签名集合里。\n");
        printf("                 典型成因：未开 testsigning 且证书不在 TrustedPublisher/Root；\n");
        printf("                 或开了 Secure Boot；或驱动是 BOOT_START 但没有嵌入签名。\n");
        break;
    case ERROR_ACCESS_DENIED: // 5
        printf("       ^ 解读   : 常见于「驱动没有签名」（x64 上内核直接拒绝）或权限不足。\n");
        break;
    case ERROR_INVALID_PARAMETER: // 87
        printf("       ^ 解读   : 参数问题（服务类型/路径），与签名无关。\n");
        break;
    default:
        break;
    }
    // 0xC0000428 = STATUS_INVALID_IMAGE_HASH；0xC000036B = STATUS_IMAGE_CERT_REVOKED 等
    if (e == 577u) printf("       NTSTATUS : 0xC0000428 (STATUS_INVALID_IMAGE_HASH)\n");
    if (e == 5u)   printf("       NTSTATUS : 可能 0xC0000022 (STATUS_ACCESS_DENIED) 或 0xC0000428\n");
}

static bool IsElevated()
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION el{}; DWORD cb = 0;
    bool ok = false;
    if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &cb)) ok = (el.TokenIsElevated != 0);
    CloseHandle(tok);
    return ok;
}

// ---- 查系统事件日志里最近的内核加载/CI 消息（Program: CodeIntegrity / Kernel-PnP）----
static void DumpRecentKernelEvents(DWORD sinceSeconds)
{
    const wchar_t* channels[] = { L"Microsoft-Windows-CodeIntegrity/Operational", L"System" };
    printf("\n---- 事件日志（最近 %lu 秒内的驱动加载相关） ----\n", (unsigned long)sinceSeconds);

    FILETIME ftNow; GetSystemTimeAsFileTime(&ftNow);
    ULARGE_INTEGER u; u.LowPart = ftNow.dwLowDateTime; u.HighPart = ftNow.dwHighDateTime;
    u.QuadPart -= (ULONGLONG)sinceSeconds * 10000000ULL; // 秒 -> 100ns
    FILETIME ftFrom; ftFrom.dwLowDateTime = u.LowPart; ftFrom.dwHighDateTime = u.HighPart;

    const wchar_t* xpath = L"*[System[TimeCreated[timediff(@SystemTime) <= 300000]]]"; // 5 分钟内
    int total = 0;
    for (const wchar_t* ch : channels) {
        EVT_HANDLE hq = EvtQuery(nullptr, ch, xpath,
                                 EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!hq) {
            printf("  [%ls] 查询失败 (%lu)\n", ch, (unsigned long)GetLastError());
            continue;
        }
        EVT_HANDLE evs[8]{};
        DWORD got = 0;
        if (EvtNext(hq, 8, evs, 2000, 0, &got)) {
            for (DWORD i = 0; i < got; i++) {
                // 取消息文本
                DWORD used = 0, propCount = 0;
                EvtRender(nullptr, evs[i], EvtRenderEventXml, 0, nullptr, &used, &propCount);
                std::vector<wchar_t> buf(used ? used : 4096);
                if (EvtRender(nullptr, evs[i], EvtRenderEventXml, (DWORD)(buf.size() * sizeof(wchar_t)),
                              buf.data(), &used, &propCount)) {
                    std::wstring xml(buf.data());
                    // 只挑跟驱动/完整性有关的
                    bool relevant = xml.find(L"r3shieldcore") != std::wstring::npos ||
                                    xml.find(L"R3ShieldCore")   != std::wstring::npos ||
                                    xml.find(L"CodeIntegrity")  != std::wstring::npos ||
                                    xml.find(L"integrity")      != std::wstring::npos ||
                                    xml.find(L"签名")            != std::wstring::npos;
                    if (relevant) {
                        printf("  [%ls] %ls\n", ch, xml.c_str());
                        total++;
                    }
                }
                if (evs[i]) EvtClose(evs[i]);
            }
        }
        EvtClose(hq);
    }
    if (!total) printf("  （没抓到直接相关的条目；可能是被限制了读取，或内核没记）\n");
}

int wmain(int argc, wchar_t** argv)
{
    // ★ 铁律 55：窄 printf 的 %ls 在默认 "C" locale 下会截断宽字符串（只出第一个字符）。
    //    本程序大量用 %ls 打印宽路径，必须先设 locale。
    setlocale(LC_ALL, "");

    if (argc < 2) {
        printf("用法: drvload_probe.exe <driver.sys> [服务名] [--keep] [--start-type boot|system|demand] [--no-pause]\n");
        printf("      drvload_probe.exe --dump-config     # 只读前提自检，不碰驱动\n");
        MaybePause();
        return 2;
    }

    // 预扫描 --no-pause：--dump-config 与用法分支都走早返回，不经过下面的参数循环
    for (int i = 1; i < argc; i++)
        if (std::wstring(argv[i]) == L"--no-pause") g_nopause = true;

    // --dump-config：只读前提，不建服务、不加载。
    if (std::wstring(argv[1]) == L"--dump-config") {
        std::wstring lp = (argc >= 4 && std::wstring(argv[2]) == L"--log") ? argv[3]
                                                                            : L"drvload_cfg.txt";
        LogOpen(lp.c_str());
        printf("=======================================================================\n");
        printf("  内核驱动加载前提自检（只读，不加载任何驱动）\n");
        printf("=======================================================================\n");
        DumpLoadPrereqs();
        printf("\n（本模式不修改系统任何状态）\n");
        MaybePause();
        return 0;
    }

    std::wstring src = argv[1];
    std::wstring svc = L"R3ShieldCoreKernelLoadTest";
    std::wstring logPath = L"drvload_out.txt";
    bool keep = false;
    DWORD startType = SERVICE_BOOT_START;
    for (int i = 2; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--keep") keep = true;
        else if (a == L"--no-pause") g_nopause = true;
        else if (a == L"--log" && i + 1 < argc) logPath = argv[++i];
        else if (a == L"--start-type" && i + 1 < argc) {
            std::wstring t = argv[++i];
            if (t == L"boot")        startType = SERVICE_BOOT_START;
            else if (t == L"system") startType = SERVICE_SYSTEM_START;
            else                     startType = SERVICE_DEMAND_START;
        }
        else svc = a;
    }

    // 目标文件名**按服务名派生**，不写死：写死会让两个不同服务撞同一个文件，
    // 而加载成功后该文件被内核引用（重启前删不掉/覆盖不了）⇒ 第二次测试会
    // 静默地拿旧镜像去测。文件名只用 [a-z0-9_-]，避免大小写/空格在 SCM 里出岔子。
    std::wstring leaf;
    for (wchar_t c : svc) {
        if ((c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'-' || c == L'_')
            leaf.push_back(c);
        else if (c >= L'A' && c <= L'Z')
            leaf.push_back((wchar_t)(c - L'A' + L'a'));
    }
    if (leaf.empty()) leaf = L"drvloadtest";
    leaf += L".sys";

    LogOpen(logPath.c_str());

    printf("=======================================================================\n");
    printf("  内核驱动加载实证探针（不使用 signtool）\n");
    printf("=======================================================================\n");
    printf("  驱动源文件 : %ls\n", src.c_str());
    printf("  测试服务名 : %ls\n", svc.c_str());
    printf("  启动类型   : %lu (%ls)\n", (unsigned long)startType,
           startType == SERVICE_BOOT_START ? L"BOOT_START" :
           startType == SERVICE_SYSTEM_START ? L"SYSTEM_START" : L"DEMAND_START");
    printf("  当前提权   : %ls\n", IsElevated() ? L"是" : L"否");
    printf("  落盘文件名 : %ls\n", leaf.c_str());

    // ---- 0. 源文件存在性 ----
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(src.c_str(), GetFileExInfoStandard, &fad)) {
        printf("\n[FAIL] 找不到驱动文件 (err=%lu)\n", (unsigned long)GetLastError());
        MaybePause(); return 3;
    }
    LARGE_INTEGER sz; sz.HighPart = fad.nFileSizeHigh; sz.LowPart = fad.nFileSizeLow;
    printf("  文件大小   : %lld 字节\n", (long long)sz.QuadPart);

    if (!IsElevated()) {
        printf("\n需要管理员权限才能建内核服务。请以管理员身份运行。\n");
        MaybePause(); return 4;
    }

    // ---- 1. 复制到 drivers 目录（内核从那里加载）----
    wchar_t dst[MAX_PATH]; 
    GetSystemDirectoryW(dst, MAX_PATH);
    std::wstring dstPath = std::wstring(dst) + L"\\drivers\\" + leaf;
    printf("\n[1/5] 复制驱动到 %ls ...\n", dstPath.c_str());
    if (!CopyFileW(src.c_str(), dstPath.c_str(), FALSE)) {
        printf("      [FAIL] 复制失败 (err=%lu)\n", (unsigned long)GetLastError());
        MaybePause(); return 5;
    }
    printf("      完成\n");

    // ---- 2. 建服务 ----
    printf("[2/5] 建内核服务 type=kernel start=%lu ...\n", (unsigned long)startType);
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("      [FAIL] OpenSCManager 失败 (err=%lu)\n", (unsigned long)GetLastError());
        DeleteFileW(dstPath.c_str());
        MaybePause(); return 6;
    }

    // 先清掉可能残留的同名服务
    SC_HANDLE old = OpenServiceW(hScm, svc.c_str(), SERVICE_ALL_ACCESS);
    if (old) {
        SERVICE_STATUS ss{}; ControlService(old, SERVICE_CONTROL_STOP, &ss);
        DeleteService(old);
        CloseServiceHandle(old);
        printf("      （清掉了一个已存在的同名服务）\n");
    }

    std::wstring bin = L"System32\\drivers\\" + leaf;
    SC_HANDLE hSvc = CreateServiceW(
        hScm, svc.c_str(), L"R3ShieldCore Driver Load Probe",
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, startType,
        SERVICE_ERROR_NORMAL, bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!hSvc) {
        DWORD e = GetLastError();
        printf("      [FAIL] CreateService 失败 (err=%lu)\n", (unsigned long)e);
        CloseServiceHandle(hScm);
        DeleteFileW(dstPath.c_str());
        MaybePause(); return 7;
    }
    printf("      服务已建立\n");

    // ---- 3. ★ 关键一步：StartService，让内核**真的**去加载 ----
    printf("[3/5] StartService —— 让内核真的加载它（这一步就是判据）...\n");
    BOOL started = StartServiceW(hSvc, 0, nullptr);
    DWORD startErr = started ? ERROR_SUCCESS : GetLastError();

    printf("\n");
    if (started) {
        printf("  ============================================================\n");
        printf("  ★ 结果：内核【接受了】这个驱动 —— StartService 成功\n");
        printf("  ============================================================\n");
        SERVICE_STATUS ss{};
        if (QueryServiceStatus(hSvc, &ss)) {
            printf("     当前状态: %lu (4=RUNNING)\n", (unsigned long)ss.dwCurrentState);
        }
    } else {
        printf("  ============================================================\n");
        printf("  ★ 结果：内核【拒绝了】这个驱动 —— StartService 失败\n");
        printf("  ============================================================\n");
        ExplainWin32(startErr);
    }

    // ---- 4. 事件日志 -----------------------------------------------------------------
    Sleep(1200); // 给 CI 一点时间把事件写进去
    DumpRecentKernelEvents(300);

    // ---- 5. 回滚（默认）----
    printf("\n[5/5] 清理...\n");
    if (started) {
        SERVICE_STATUS ss{};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    }
    if (keep) {
        printf("      --keep 指定，保留服务与文件（服务名 %ls）\n", svc.c_str());
    } else {
        if (DeleteService(hSvc))
            printf("      已删除服务\n");
        else
            printf("      删服务失败 (err=%lu) —— 重启后自动消失\n", (unsigned long)GetLastError());
    }
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);

    if (!keep && !started) {
        // 没加载成功 ⇒ 文件没用内核引用，可以直接删
        if (DeleteFileW(dstPath.c_str())) printf("      已删除驱动文件\n");
        else printf("      删文件失败 (err=%lu)\n", (unsigned long)GetLastError());
    } else if (!keep && started) {
        printf("      驱动此前被加载过，文件可能仍被内核引用，留待重启后删: %ls\n", dstPath.c_str());
    }

    printf("\n结论：以上是**内核实际行为**，不是签名工具的推断。\n");
    printf("      成功 -> 内核认可该签名链；失败 -> 打印的 Win32/NTSTATUS 即真实原因。\n\n");
    MaybePause();
    return started ? 0 : 1;
}
