/*
 * r3shieldcore_svc.c -- R3 ShieldCore 开机启动服务
 * ==================================================
 *
 * 它**只做一件事**：把 R3 ShieldCore 引擎拉进「有交互用户的那个会话」。
 *
 * 为什么需要它（三层架构的中间那层）
 * ---------------------------------
 *   驱动 (boot/auto)          —— 只负责"开机就加载"，本身不启动任何用户态进程
 *   本服务 (SYSTEM, auto)     —— 开机就起，等有会话了把引擎拉起来
 *   引擎 (用户会话, 提权)      —— 真正干活的用户态防护
 *
 *   只靠计划任务 (`schtasks /sc onlogon`) 是不行的：
 *     · 它只在**登录后**才触发，开机到登录这段窗口没有任何防护；
 *     · 它登记在任务计划程序里，用户随手就能禁用/删除；
 *     · 它是以"登录用户 + highest"跑的，行为随用户权限而变。
 *   服务是 SCM 管的：开机即起、以 LocalSystem 跑、不依赖任何用户登录。
 *
 * ★★★ 本程序**刻意不做**的事（用户明确要求，也是刻意的边界）★★★
 *   · 不做自我保护（不挂钩子、不防杀、不改自己的 ACL）；
 *   · 不做看门狗（引擎被杀掉**不会**自动重启，见下面"同一会话只拉一次"）；
 *   · 不加载/不管理内核驱动（驱动由安装程序注册，自己管自己）。
 *   换句话说：本服务是**启动器**，不是防护组件。它崩了/被停了，
 *   引擎该在还在，只是下次开机不会自动起来。
 *
 * ★★★ 同一会话**只拉一次**（这不是偷懒，是防"两份引擎"）★★★
 *   引擎没有单实例互斥体（grep 过：全仓没有 CreateMutex 式的单实例保护），
 *   两份引擎 = 两套全局注入 + 两套 hook + 日志互相打架（app.cpp 里
 *   超级置顶面板那段注释已经写过这个坑）。
 *   所以本服务对每个会话只成功拉起**一次**，之后即使引擎被关掉也不重拉。
 *   好处有两个：
 *     1) 卸载脚本用 dskill 杀掉引擎后，服务不会在下一个 tick 把它拉回来
 *        （否则卸载和自启会打起来，而且卸载脚本里 sc.exe 还被引擎拦着，
 *         根本没法先停服务 —— 见 uninstall.bat 文件头的顺序说明）；
 *     2) 语义诚实：这就是"开机自启"，不是"常驻守护"。
 *
 * 触发：三条路，都汇到 TryLaunchForSession() 这一个入口
 * ---------------------------------------------------
 *   ① 服务启动时先试一次 —— 覆盖"服务比用户登录晚起"（手工 sc start、重启服务）；
 *   ② SERVICE_CONTROL_SESSIONCHANGE 的 LOGON / UNLOCK / CONSOLE_CONNECT；
 *   ③ 每 RETRY_MS 兜一次底。
 *   ★ 事件驱动**必须**配兜底 tick：WTS_SESSION_LOGON 到达时令牌可能刚建好，
 *     桌面还不一定能承载进程 —— 事件只保证"该看一眼了"，不保证"现在能拉"。
 *
 * 判据：什么叫"会话真的可用"（SessionUsable，四条全过才拉）
 * ------------------------------------------------------
 *   ① WTSUserName 非空 —— 真的有人登录。
 *      ★ 反直觉但关键：Win10/11 的登录界面（LogonUI）跑在**控制台会话**里，
 *        所以**没人登录时 WTSGetActiveConsoleSessionId() 也会返回有效会话号**。
 *        "有会话" != "有人"。
 *   ② WTSConnectState == WTSActive —— 会话是活动的（不是 Disconnected 却还留着）。
 *   ③ WTSQueryUserToken 成功 —— **决定性**的一条：它拿到的就是下一步要交给
 *      CreateProcessAsUser 的那个令牌。前面两条是便宜的先筛，这条是真前提。
 *   ④ 该会话里有 explorer.exe —— 桌面已经起来了。
 *      ★ Windows **没有**"shell 就绪"事件，WTS_SESSION_LOGON 只保证令牌存在。
 *        所以"猜"不如"看"：explorer 起来了 = 桌面真的活了 = GUI 能承载。
 *        这是**外部**证据，不依赖任何本程序自己设的状态。
 *   ★ 任一条不过 => **不记账**，30s 后重试。理由：失败要分"还没到点"和"坏了"
 *     两种（铁律 98），登录瞬间失败属于"还没到点"，不该被判死刑。
 *
 * 拉起之后还要**存活确认**（这才是"启动成功"的定义）
 * ------------------------------------------------
 *   CreateProcessAsUser 返回 TRUE 只说明进程被创建。桌面没就绪 / 引擎自己
 *   初始化失败时会**秒退** —— 这时如果记账，AlreadyLaunched() 会让这个会话
 *   **永远不再重试**，结果是"开机自启静默失效，而日志写着已拉起 pid=xxxx"
 *   （铁律 124 的空真形态：把"调用成功"当成"目标达成"）。
 *   所以：等 LAUNCH_GRACE_MS，没退出才算成功；再用一次独立快照交叉确认。
 *
 * 令牌：为什么"取到会话令牌"还不够（v1.2.0 修 —— 开机不自启的真根因）
 * -------------------------------------------------------------------
 *   引擎的清单是 requireAdministrator。而：
 *     · WTSQueryUserToken 返回的是 **UAC 过滤后**的未提权令牌
 *       （ElevationType = Limited，管理员账户也是这个）；
 *     · 用未提权令牌 CreateProcessAsUser 一个 requireAdministrator 的程序，
 *       内核**直接拒**：err=740 (ERROR_ELEVATION_REQUIRED)；
 *     · Explorer 双击走 ShellExecuteEx(runas)，由 AppInfo 服务弹 UAC 换成
 *       已提权令牌再建进程 -> 所以"双击能开、开机不自启"。
 *   所以拉之前必须做两步：
 *     ① EnablePrivilege 打开 SeTcb / SeAssignPrimaryToken / SeIncreaseQuota /
 *        SeImpersonate / SeDebug —— 令牌里"有"特权 != "能用"（默认全是关的），
 *        不打开则 WTSQueryUserToken / CreateProcessAsUser 都以 err=1314 失败；
 *     ② 把过滤令牌升级成**已提权**的关联令牌（TokenLinkedToken）；
 *        升级不了（没有 SeTcbPrivilege 时 DuplicateTokenEx 会 err=1346）
 *        就退到本进程（SYSTEM）令牌 + SetTokenInformation(TokenSessionId)。
 *   ★ 实测探针：tools/probe_elev_launch.cpp（build_elev_launch_probe.sh）、
 *     tools/probe_linked_token.cpp —— 结论都写进了代码注释。
 *
 * ★ 刻意**不覆盖**远端（RDP）会话 —— 这是一个**显式决定**，不是碰巧
 * ------------------------------------------------------------------
 *   兜底 tick 只查 WTSGetActiveConsoleSessionId()（本机控制台会话），
 *   SESSIONCHANGE 也**不**处理 WTS_REMOTE_CONNECT。
 *   理由有两条，第二条是硬的：
 *     1) 语义：本服务要保护的是"坐在这台机器前面的人"的那个会话；
 *     2) **引擎没有单实例互斥体**。若同时覆盖控制台 + 远端会话，
 *        两个会话各拉一份 = **两份引擎互咬**（两套全局注入 + 两套 hook）。
 *        要覆盖多会话，前提是先给引擎加单实例保护 —— 那是另一件事。
 *   要改的话：加 WTS_REMOTE_CONNECT 事件 + 让兜底 tick 扫所有会话，
 *   并且**同时**给引擎加单实例保护。缺一不可。
 *
 * 诊断
 * ----
 *   日志落在**自己所在目录**的 r3shieldcore-svc.log，UTF-8（带 BOM）。
 *   ★ 刻意**不**复用引擎的 r3shieldcore-console.log：
 *     那个文件是引擎用 "a" 追加打开的，两个进程交叉写会互相插行
 *     （铁律 26/83），而且编码还不一样（printf=GBK）。
 *
 * ★★★ 安全模式：**不拉起引擎** ★★★
 *   驱动是 SERVICE_BOOT_START —— 安全模式**也会**加载它（这是 BOOT_START
 *   的固有性质，改不了）。内核组件自己不启动任何进程，所以"安全模式下
 *   R3 ShieldCore 不激活"这件事，唯一能落实的地方就是这里。
 *   判据：GetSystemMetrics(SM_CLEANBOOT) != 0（见 IsSafeMode 的注释）。
 *   闸门挂在 TryLaunchForSession() 上 —— 那是**所有**拉起路径的唯一入口。
 *
 * 命令行
 * ------
 *   （无参数）      由 SCM 启动，走 StartServiceCtrlDispatcherW
 *   --selftest      只做诊断：引擎路径 / 存在性 / 当前会话 / 是否安全模式 / 引擎是否在跑
 *   --selftest --launch
 *                   诊断 + 用**当前进程令牌**真拉一次引擎（前台可见）
 *   --selftest --launch --fake-safemode
 *                   把"安全模式"强制打开 —— 用来验证闸门**真的会拦**（负对照）
 *   --console       以前台方式跑主循环（调试用，Ctrl+C 退出）
 *   --version       打印版本
 *
 * ★ 本文件必须能整体用 CP936 编码（闸门 tools/check_source_gbk.py）：
 *   注释里不要用 -> 以外的箭头、不要用 emoji。
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <sddl.h>      /* ConvertSidToStringSidW */
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <wchar.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */

/* 服务名：**不带空格**。
 * ★ 这个名字要穿过 cmd.exe / sc.exe / 注册表多处，带空格就多一层引号转义，
 *   多一层转义就多一个静默失败点（铁律 115 的形态）。 */
#define SVC_NAME        L"R3ShieldCoreGuard"
#define SVC_DISPLAY     L"R3 ShieldCore 开机启动服务"

/* 引擎文件名。★ 带空格 —— 服务内部引用时**每一处**都要加引号。
 *   闸门 tools/check_payload_manifest.py 会比对它和 payload 清单里的一致。 */
#define ENGINE_EXE      L"R3 ShieldCore.exe"

#define LOG_NAME        L"r3shieldcore-svc.log"

/* 兜底重试间隔：只在"该会话还没成功拉过"时才有意义 */
#define RETRY_MS        30000

/* 拉起后的**存活确认**宽限期。
 *
 * CreateProcessAsUser 成功**只说明进程被创建**，不说明引擎活着（见
 * LaunchInSession 里的存活确认注释）。这里等它最多 GRACE 毫秒：
 *   WAIT_TIMEOUT  = 它没退出 = 活着 = **成功**
 *   WAIT_OBJECT_0 = 秒退 = 失败（不记账，下轮重试）
 *
 * ★ 所以这个值**短不会误判**：判据是"等它退出"，超时才是好消息。
 *   它只决定"多晚的崩溃还算启动失败"。3s 足够覆盖"桌面没就绪 -> 立刻退出"
 *   这个主要场景（那是亚秒级的）。
 * ★ 为什么不用更长：这段时间里 TryLaunchForSession 持有 g_launchLock，
 *   而 SCM 的控制事件（含 STOP）是**同一个线程**串行投递的 ——
 *   等太久会把"停止服务"也一起拖住。 */
#define LAUNCH_GRACE_MS 3000

/* 最多记住多少个会话（正常机器不会超过个位数） */
#define MAX_SESSIONS    64

/* ★ 1.1.0：加了"会话可用性四条判据" + 拉起后的"存活确认"。
 * ★ 1.2.0：修"开机不自启"的两个真断点 ——
 *     ① 服务从来没 EnablePrivilege 过（令牌里"有"特权 != "能用"），
 *        导致 WTSQueryUserToken / CreateProcessAsUser 直接 err=1314；
 *     ② WTSQueryUserToken 返回的是 **UAC 过滤令牌**，拿它建
 *        requireAdministrator 的引擎必 **err=740**；原兜底只认 1314。
 *      现在：打开特权 -> 过滤令牌升级成已提权关联令牌 -> 升不了就退
 *      本进程（SYSTEM）令牌 + 改会话号。每一步都记日志。
 *   版本号要动 —— 行为变了，光看文件名分不出新旧（铁律 61：体积相同
 *   证明不了内容相同）。 */
#define VERSION_STR     L"1.2.0"

/* ------------------------------------------------------------------ */
/* 日志（UTF-8 + BOM，独立文件，不碰引擎的 console log）                */
/* ------------------------------------------------------------------ */

static HANDLE g_log = INVALID_HANDLE_VALUE;

static void LogInit(void)
{
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return;
    }

    wchar_t* slash = wcsrchr(self, L'\\');
    if (slash == NULL) {
        return;
    }
    *(slash + 1) = L'\0';

    wchar_t path[MAX_PATH + 32];
    if (swprintf_s(path, _countof(path), L"%s%s", self, LOG_NAME) < 0) {
        return;
    }

    g_log = CreateFileW(path, FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_log == INVALID_HANDLE_VALUE) {
        return;
    }

    /* 新建的空文件先写 BOM，读回来时编码没有歧义 */
    LARGE_INTEGER size;
    size.QuadPart = 0;
    if (GetFileSizeEx(g_log, &size) && size.QuadPart == 0) {
        const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
        DWORD written = 0;
        WriteFile(g_log, bom, 3, &written, NULL);
    }
}

static void LogClose(void)
{
    if (g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
    }
}

static void Log(const wchar_t* fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;

    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    /* 前台跑（--selftest / --console）时直接看得见；被 SCM 拉起时没有控制台，
     * wprintf 静默失败，无害。 */
    wprintf(L"%s\n", buf);
    fflush(stdout);

    if (g_log == INVALID_HANDLE_VALUE) {
        return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t line[1280];
    if (_snwprintf_s(line, _countof(line), _TRUNCATE,
                     L"%04d-%02d-%02d %02d:%02d:%02d.%03d  %s\r\n",
                     st.wYear, st.wMonth, st.wDay,
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                     buf) < 0) {
        return;
    }

    int need = WideCharToMultiByte(CP_UTF8, 0, line, -1, NULL, 0, NULL, NULL);
    if (need <= 1) {
        return;
    }

    char* utf8 = (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)need);
    if (utf8 == NULL) {
        return;
    }

    WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8, need, NULL, NULL);
    DWORD written = 0;
    WriteFile(g_log, utf8, (DWORD)(need - 1), &written, NULL);
    HeapFree(GetProcessHeap(), 0, utf8);
}

/* ------------------------------------------------------------------ */
/* 路径                                                                */
/* ------------------------------------------------------------------ */

/* 引擎路径 = 本 exe 所在目录 + ENGINE_EXE。
 * ★ 刻意用**自己所在目录**推导，而不是读注册表/写死安装路径：
 *   服务二进制和引擎是同一个安装包解出来的，永远同目录（铁律 121 的教训：
 *   要从自己真正所在的地方取东西）。 */
static BOOL EnginePath(wchar_t* out, size_t cch)
{
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return FALSE;
    }

    wchar_t* slash = wcsrchr(self, L'\\');
    if (slash == NULL) {
        return FALSE;
    }
    *(slash + 1) = L'\0';

    return swprintf_s(out, cch, L"%s%s", self, ENGINE_EXE) >= 0;
}

/* 某个**指定名字**的进程是否正在某个会话里跑着。
 *
 * ★ 判据是**映像名 + 会话号**，不是只看名字：名字相同但在别的会话里，不算。
 *   两处用它：
 *     · 查引擎 —— 这是"两份引擎"的唯一防线；
 *     · 查 explorer.exe —— "桌面已经起来"的外部证据（见 SessionUsable）。
 * ★ `noisy=TRUE` 时打诊断行（查引擎时要留痕），FALSE 时安静（判据轮询别刷屏）。 */
static BOOL ProcessRunningInSession(const wchar_t* exe, DWORD session, BOOL noisy)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Log(L"  [警告] CreateToolhelp32Snapshot 失败 err=%lu —— "
            L"查不到 %s 在不在，按\"不在\"处理", GetLastError(), exe);
        return FALSE;
    }

    PROCESSENTRY32W pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    BOOL found = FALSE;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe) != 0) {
                continue;
            }
            DWORD sid = 0;
            if (!ProcessIdToSessionId(pe.th32ProcessID, &sid)) {
                if (noisy) {
                    Log(L"  [警告] pid=%lu 的 ProcessIdToSessionId 失败 err=%lu，跳过",
                        (unsigned long)pe.th32ProcessID, GetLastError());
                }
                continue;
            }
            if (sid == session) {
                if (noisy) {
                    Log(L"  已发现 %s pid=%lu（会话 %lu）",
                        exe, (unsigned long)pe.th32ProcessID, (unsigned long)sid);
                }
                found = TRUE;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return found;
}

/* 引擎是否已经在某个会话里跑着 —— "两份引擎"的唯一防线，所以留痕。 */
static BOOL EngineRunningInSession(DWORD session)
{
    return ProcessRunningInSession(ENGINE_EXE, session, TRUE);
}

/* ------------------------------------------------------------------ */
/* 会话可用性（四条判据）                                               */
/* ------------------------------------------------------------------ */

/* "这个会话现在真的能承载一个 GUI 进程吗？"
 *
 * 全过才返回 TRUE；不过时把**原因**写进 why（why 是给日志/自检用的）。
 *
 * ★ 为什么不能只看 WTSGetActiveConsoleSessionId()：
 *   它返回的是"控制台会话号"，**没人登录时也有值** —— Win10/11 的登录界面
 *   自己就跑在那个会话里。所以"有会话"必须再往下判"有人 + 活动 + 桌面 + 令牌"。
 * ★ 为什么把 explorer.exe 当判据：
 *   Windows 没有"shell 就绪"的事件。WTS_SESSION_LOGON 只保证令牌建好了，
 *   不保证 winsta0\default 能承载进程。看 explorer 在不在，是把"猜"换成"看"。
 * ★ 为什么令牌判据放最后：它是**决定性**的那条（我们就是要拿它去
 *   CreateProcessAsUser），前三条是便宜的先筛，先筛掉能少做一次快照。 */
static BOOL SessionUsable(DWORD session, wchar_t* why, size_t whyCch)
{
    if (whyCch > 0) {
        why[0] = L'\0';
    }

    /* ---- 判据 1：真的有人登录 ---- */
    LPWSTR user = NULL;
    DWORD bytes = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session,
                                     WTSUserName, &user, &bytes)) {
        _snwprintf_s(why, whyCch, _TRUNCATE,
                     L"WTSUserName 查询失败 err=%lu", GetLastError());
        return FALSE;
    }
    BOOL hasUser = (user != NULL && user[0] != L'\0');
    if (user != NULL) {
        WTSFreeMemory(user);
    }
    if (!hasUser) {
        _snwprintf_s(why, whyCch, _TRUNCATE,
                     L"会话里还没有用户登录（可能停在登录界面）");
        return FALSE;
    }

    /* ---- 判据 2：会话是活动的 ---- */
    DWORD* state = NULL;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session,
                                     WTSConnectState, (LPWSTR*)&state, &bytes)) {
        _snwprintf_s(why, whyCch, _TRUNCATE,
                     L"WTSConnectState 查询失败 err=%lu", GetLastError());
        return FALSE;
    }
    DWORD cs = (state != NULL) ? *state : 0xFFFFFFFFu;
    if (state != NULL) {
        WTSFreeMemory(state);
    }
    if (cs != (DWORD)WTSActive) {
        _snwprintf_s(why, whyCch, _TRUNCATE,
                     L"会话不是活动态（WTSConnectState=%lu，活动态=%d）",
                     (unsigned long)cs, (int)WTSActive);
        return FALSE;
    }

    /* ---- 判据 3：能拿到交互用户令牌（决定性）---- */
    HANDLE token = NULL;
    SetLastError(0);
    if (!WTSQueryUserToken(session, &token)) {
        DWORD e = GetLastError();
        /* ★ 失败要**分型**（铁律 98）：1314 不是"会话不可用"，而是"**我**没权限问"
         *   —— WTSQueryUserToken 需要 SeTcbPrivilege，只有 SYSTEM 才有。
         *   以普通用户跑 --selftest 时必然踩这条；把它和"真的没人登录"混成
         *   一句话，会让人以为会话有问题。 */
        if (e == ERROR_PRIVILEGE_NOT_HELD) {
            _snwprintf_s(why, whyCch, _TRUNCATE,
                         L"取不到交互用户令牌 err=1314（缺 SeTcbPrivilege —— "
                         L"本进程不是以 SYSTEM 跑，属正常，不代表会话不可用）");
        }
        else {
            _snwprintf_s(why, whyCch, _TRUNCATE,
                         L"取不到交互用户令牌 err=%lu", e);
        }
        return FALSE;
    }
    CloseHandle(token);

    /* ---- 判据 4：桌面已经起来（外部证据）---- */
    if (!ProcessRunningInSession(L"explorer.exe", session, FALSE)) {
        _snwprintf_s(why, whyCch, _TRUNCATE,
                     L"桌面还没起来（该会话里没有 explorer.exe）");
        return FALSE;
    }

    return TRUE;
}

/* "还不能拉"的原因**只在变化时**打一行。
 * ★ 兜底 tick 每 30s 一次：如果用户一直停在登录界面，每 30s 打一行同样的
 *   日志会刷出几百行。但**原因一变必须立刻可见**（铁律 97：要有原因）——
 *   所以按 (会话, 原因) 去重，不是按时间节流。 */
static DWORD   g_whySession = 0xFFFFFFFFu;
static wchar_t g_whyLast[256] = L"";

static void LogNotUsable(DWORD session, const wchar_t* why)
{
    if (g_whySession == session && wcscmp(g_whyLast, why) == 0) {
        return;
    }
    g_whySession = session;
    wcsncpy_s(g_whyLast, _countof(g_whyLast), why, _TRUNCATE);
    Log(L"  会话 %lu 还不能拉起：%s（不记账，%lu ms 后重试）",
        (unsigned long)session, why, (unsigned long)RETRY_MS);
}

/* ------------------------------------------------------------------ */
/* 令牌诊断                                                            */
/* ------------------------------------------------------------------ */

/* 打印令牌的**用户**和**是否提权**。
 * ★ 这两行是"引擎会不会半残"的**前提证据**：
 *   引擎是 requireAdministrator，如果被一个未提权的令牌拉起来，
 *   它会打印"当前没有管理员权限"并大面积失效（全局注入 err=5）。
 *   所以拉之前先把令牌事实记下来，出问题能一眼分清是"服务没拉起来"
 *   还是"拉起来了但令牌不对"（铁律 97/98：动作失败必须分型）。 */
static void LogTokenFacts(HANDLE token, const wchar_t* what)
{
    TOKEN_ELEVATION el;
    DWORD ret = 0;
    BOOL elevated = FALSE;
    ZeroMemory(&el, sizeof(el));
    if (GetTokenInformation(token, TokenElevation, &el, sizeof(el), &ret)) {
        elevated = el.TokenIsElevated != 0;
    }

    wchar_t user[256] = L"?";
    DWORD need = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &need);
    if (need != 0) {
        TOKEN_USER* tu = (TOKEN_USER*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)need);
        if (tu != NULL) {
            if (GetTokenInformation(token, TokenUser, tu, need, &need)) {
                wchar_t* sid = NULL;
                if (ConvertSidToStringSidW(tu->User.Sid, &sid)) {
                    wcsncpy_s(user, _countof(user), sid, _TRUNCATE);
                    LocalFree(sid);
                }
            }
            HeapFree(GetProcessHeap(), 0, tu);
        }
    }

    TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault;
    const BOOL haveEt = GetTokenInformation(token, TokenElevationType, &et, sizeof(et), &ret);

    /* ★ 行首的 [TOKEN] 与 elevated=yes/no、type=N 都是 **ASCII 锚点** ——
     *   给 GBK 控制台下的诊断脚本（tools/diag_autostart.bat）用的。
     *   它读不了日志里的中文（日志是 UTF-8），只能 findstr ASCII。 */
    Log(L"[TOKEN] elevated=%s type=%d user=%s （%s）",
        elevated ? L"yes" : L"no", haveEt ? (int)et : -1, user, what);
    /* ★ ElevationType 必须一起打。
     *   elevated=no 有两种完全不同的含义（铁律 98：动作失败必须分型）：
     *     Limited  -> UAC 过滤令牌，**有**关联的提权令牌，可以升级；
     *     Default  -> 本来就没有 UAC 分裂（标准用户 / UAC 关），没得升。
     *   只打一个 elevated=no，看日志的人分不出该修哪条路。 */
    {
        const wchar_t* name =
            (et == TokenElevationTypeFull)    ? L"Full（已提权）" :
            (et == TokenElevationTypeLimited) ? L"Limited（被 UAC 过滤，有可升级的关联令牌）" :
                                                L"Default（无 UAC 分裂）";
        Log(L"        type 含义：%d = %s", (int)et, name);
    }

    if (!elevated) {
        Log(L"  [警告] 这个令牌**没有**提权 —— 引擎是 requireAdministrator，"
            L"拿它去 CreateProcessAsUser 会直接 **err=740**，进程根本建不出来。");
    }
}

/* ------------------------------------------------------------------ */
/* 特权：令牌里"有" != "能用"                                          */
/* ------------------------------------------------------------------ */

/* ★★★ 为什么必须有这一段（这是"开机不自启"的第一个断点）★★★
 *
 *   令牌里**存在**一个特权，和**能用**这个特权，是两回事：
 *   令牌创建时所有特权默认都是 **关闭（SE_PRIVILEGE_DISABLED）** 的，
 *   做特权检查的操作必须先 AdjustTokenPrivileges 显式打开。
 *
 *   LocalSystem 令牌里 SeTcbPrivilege / SeAssignPrimaryTokenPrivilege /
 *   SeIncreaseQuotaPrivilege / SeImpersonatePrivilege / SeDebugPrivilege
 *   全都在，但**全是关的**。本服务原来一个都没开，于是：
 *     · WTSQueryUserToken         要 SeTcbPrivilege        -> 直接失败；
 *     · CreateProcessAsUserW      要 SeAssignPrimaryToken
 *                                    + SeIncreaseQuota     -> 失败（err=1314）；
 *     · CreateProcessWithTokenW   要 SeImpersonatePrivilege -> 失败（err=1314）；
 *     · SetTokenInformation(TokenSessionId) 要 SeTcbPrivilege -> 失败。
 *
 *   ★ 对照：R3ShieldCore/r3shieldcore_superdesk.cpp 里同一套调用之前，
 *     逐个 EnablePrivilege 了这五个 —— 那段是**验证过能用**的，
 *     本服务当初漏抄了这一步（铁律 93："文档里写了" != "代码会读"）。
 *
 *   ★ 注意原注释里那句"LocalSystem 天然具备"是对的，但**具备 != 启用** ——
 *     正是这句话让这个断点藏了很久。 */
static BOOL EnablePrivilege(HANDLE token, const wchar_t* name)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(0);
    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        return FALSE;
    }

    /* ★ AdjustTokenPrivileges 在"只成功了一部分"时**也返回 TRUE** ——
     *   必须再看 GetLastError() == ERROR_NOT_ALL_ASSIGNED。
     *   只判返回值就会把"这个特权根本不在令牌里"当成"开好了"
     *   （铁律 110 的形态：只判一个布尔值，全零时也成立）。 */
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

/* 逐个打开本服务干活要用的五个特权，并把**每一个的结果**写进日志。
 * ★ 一个都不许静默：后面任何一步失败，都要能在这里对上原因（铁律 97）。 */
static void EnableServicePrivileges(void)
{
    static const wchar_t* kPriv[] = {
        SE_TCB_NAME,                 /* WTSQueryUserToken / 改令牌会话号 */
        SE_ASSIGNPRIMARYTOKEN_NAME,  /* CreateProcessAsUser */
        SE_INCREASE_QUOTA_NAME,      /* CreateProcessAsUser */
        SE_IMPERSONATE_NAME,         /* CreateProcessWithTokenW */
        SE_DEBUG_NAME                /* OpenProcess 到 SYSTEM 进程取令牌 */
    };
    static const wchar_t* kWhy[] = {
        L"WTSQueryUserToken / SetTokenInformation(TokenSessionId)",
        L"CreateProcessAsUserW",
        L"CreateProcessAsUserW",
        L"CreateProcessWithTokenW（兜底路）",
        L"打开别的进程取令牌"
    };

    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        Log(L"[特权] OpenProcessToken 失败 err=%lu —— 后面每一步都可能因缺特权失败",
            GetLastError());
        return;
    }

    for (int i = 0; i < (int)(sizeof(kPriv) / sizeof(kPriv[0])); ++i) {
        const BOOL ok = EnablePrivilege(token, kPriv[i]);
        /* ★ [PRIV] / OK / FAIL 是**ASCII 锚点**，故意放在行首：
         *   诊断脚本（tools/diag_autostart.bat）在 GBK 控制台下**读不了**
         *   日志里的中文（日志是 UTF-8），只能 findstr 匹配 ASCII。
         *   没有这个锚点，"哪条特权没开"这件事在 .bat 里就是不可见的
         *   （铁律 99：诊断口径必须 >= 触发口径）。 */
        Log(L"[PRIV] %-30s %s   （%s）", kPriv[i],
            ok ? L"OK" : L"FAIL", kWhy[i]);
    }

    CloseHandle(token);
}

/* ------------------------------------------------------------------ */
/* 令牌：过滤令牌 -> 已提权令牌                                        */
/* ------------------------------------------------------------------ */

/* 令牌是不是"提权态"。取不到按**否**处理（宁可多走一次保底路，
 * 也不要因为"查不到"就当成"已经提权"从而建不出进程 —— 铁律 110）。 */
static BOOL TokenIsElevated(HANDLE token)
{
    TOKEN_ELEVATION el;
    DWORD cb = 0;
    ZeroMemory(&el, sizeof(el));
    if (GetTokenInformation(token, TokenElevation, &el, sizeof(el), &cb)) {
        return el.TokenIsElevated != 0;
    }
    return FALSE;
}

/* ★★★ 这是"开机不自启"的**根因所在**，改之前先看懂这段 ★★★
 *
 *   症状：双击快捷方式能开引擎，开机自启就是不开。
 *
 *   链条：
 *     1) 引擎清单是 requireAdministrator（已核对 dist 里的 exe）。
 *     2) 服务用 WTSQueryUserToken 取会话令牌 —— 它返回的是 **UAC 过滤后**
 *        的未提权令牌（ElevationType = Limited）。管理员账户也是这个。
 *     3) 用**未提权**令牌 CreateProcessAsUser 一个 requireAdministrator 的程序，
 *        内核直接拒：**err=740 (ERROR_ELEVATION_REQUIRED)**。
 *        本机实测（tools/probe_elev_launch.cpp + build_elev_launch_probe.sh）：
 *          CreateProcessAsUserW(过滤令牌)   -> err=740
 *          CreateProcessWithTokenW(过滤令牌) -> err=1314
 *        而 Explorer 双击走 ShellExecuteEx(runas)，由 AppInfo 服务弹 UAC
 *        拿到**已提权**令牌再建进程 -> 所以双击能开。
 *     4) 原代码的兜底只认 err=1314，740 不在其中 -> 直接放弃。
 *
 *   修法：取关联令牌（TokenLinkedToken），复制成**已提权**的主令牌。
 *
 *   ★ 但这条路**不是万能的**（本机实测）：在没有 SeTcbPrivilege 的普通进程里，
 *     TokenLinkedToken 返回的是一个 **Identification 级冒充令牌**，
 *     拿它 DuplicateTokenEx 成主令牌会报 err=1346 (ERROR_BAD_IMPERSONATION_LEVEL)。
 *     （见 tools/probe_linked_token.cpp 的实测输出。）
 *     所以调用方**必须**处理"升级失败"，退回 BuildFallbackSessionToken。
 *
 * 返回：成功 = 新的已提权主令牌（调用方负责 CloseHandle）；
 *       失败 = NULL（**不动**传入的 filtered，调用方自己决定怎么退）。 */
static HANDLE TryDuplicateElevatedToken(HANDLE filtered)
{
    DWORD cb = 0;
    TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault;

    if (GetTokenInformation(filtered, TokenElevationType, &et, sizeof(et), &cb)) {
        if (et == TokenElevationTypeFull) {
            Log(L"  令牌已是提权态（ElevationType=Full），无需升级");
            return NULL;
        }
        if (et == TokenElevationTypeDefault) {
            Log(L"  令牌 ElevationType=Default（无 UAC 分裂）—— 没有可升级的关联令牌");
            return NULL;
        }
    }

    HANDLE linked = NULL;
    if (!GetTokenInformation(filtered, TokenLinkedToken, &linked, sizeof(linked), &cb)) {
        Log(L"  取关联令牌失败 err=%lu", GetLastError());
        return NULL;
    }

    HANDLE elevated = NULL;
    if (!DuplicateTokenEx(linked, TOKEN_ALL_ACCESS, NULL,
                          SecurityImpersonation, TokenPrimary, &elevated)) {
        const DWORD e = GetLastError();
        Log(L"[TOKEN] upgrade=FAIL err=%lu", e);
        Log(L"  复制关联令牌为主令牌失败 err=%lu%s", e,
            (e == ERROR_BAD_IMPERSONATION_LEVEL)
                ? L"（ERROR_BAD_IMPERSONATION_LEVEL：关联句柄是 Identification 级冒充令牌，"
                  L"升成主令牌需要 SeTcbPrivilege）"
                : L"");
        CloseHandle(linked);
        return NULL;
    }

    CloseHandle(linked);
    Log(L"[TOKEN] upgrade=OK");
    Log(L"  令牌升级：成功换成**已提权**的关联令牌");
    return elevated;
}

/* 保底路：用**本进程令牌**造一个"目标会话的提权主令牌"。
 *
 * ★ 服务里本进程 = LocalSystem。SYSTEM 令牌本身就是**提权**的（高完整性），
 *   所以 requireAdministrator 的清单检查会通过 —— 这条路一定能建出进程。
 *   （引擎以 SYSTEM 跑是**受支持**的配置：functions.cpp 的
 *     BuildSharedSecurityDescriptor / TryGetSessionUserSid 就是为它写的，
 *     见 docs/HANDOVER.md 附录 C.1 的 v55 修复。）
 *
 * ★ 为什么要改会话号：SYSTEM 令牌的 TokenSessionId 是 0（会话 0），
 *   直接建进程会落在会话 0 的桌面上 —— 用户根本看不见、也 hook 不到。
 *   SetTokenInformation(TokenSessionId) 需要 SeTcbPrivilege，
 *   服务是 SYSTEM，已在 EnableServicePrivileges 里打开。
 *   （同一套做法见 r3shieldcore_superdesk.cpp:806-820，那段验证过。） */
static HANDLE BuildFallbackSessionToken(DWORD session)
{
    HANDLE self = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &self)) {
        Log(L"[TOKEN] fallback=FAIL err=%lu", GetLastError());
        Log(L"  [保底] OpenProcessToken(自己) 失败 err=%lu", GetLastError());
        return NULL;
    }

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);

    HANDLE primary = NULL;
    if (!DuplicateTokenEx(self, MAXIMUM_ALLOWED, &sa,
                          SecurityImpersonation, TokenPrimary, &primary)) {
        Log(L"[TOKEN] fallback=FAIL err=%lu", GetLastError());
        Log(L"  [保底] 复制本进程令牌失败 err=%lu", GetLastError());
        CloseHandle(self);
        return NULL;
    }
    CloseHandle(self);

    DWORD cur = 0xFFFFFFFFu;
    DWORD cb = 0;
    if (GetTokenInformation(primary, TokenSessionId, &cur, sizeof(cur), &cb)) {
        if (cur != session) {
            if (!SetTokenInformation(primary, TokenSessionId, &session, sizeof(session))) {
                Log(L"[TOKEN] fallback=FAIL err=%lu (setsession)", GetLastError());
                Log(L"  [保底] 改令牌会话号 %lu -> %lu 失败 err=%lu（缺 SeTcbPrivilege？）",
                    (unsigned long)cur, (unsigned long)session, GetLastError());
                CloseHandle(primary);
                return NULL;
            }
            Log(L"  [保底] 令牌会话号已改：%lu -> %lu",
                (unsigned long)cur, (unsigned long)session);
        }
    }

    Log(L"[TOKEN] fallback=OK session=%lu", (unsigned long)session);
    Log(L"  [保底] 已造出本进程令牌的主令牌副本（服务里 = SYSTEM，会话 %lu）",
        (unsigned long)session);
    return primary;
}

/* 一次拉起尝试的结论。让诊断脚本**一条 findstr 就能定位根因** ——
 * 否则它得自己在日志里拼好几条锚点，拼错就是"报了个假原因"。
 * ★ 取值必须是**单个英文字母**（findstr /c:"LAST] E" 才好匹配）：
 *     E = elevation（令牌没提权，err=740）
 *     P = privilege（某条特权没打开，err=1314）
 *     S = token upgrade / fallback 失败（拿不到可用令牌）
 *     C = CreateProcess 失败（别的原因，看同一行的 err=）
 *     X = 引擎拉起来后**秒退**（建进程成功但目标没活下来）
 *     O = OK（已确认存活） */
static wchar_t g_lastOutcome = L'-';
static DWORD   g_lastErr = 0;
static DWORD   g_outcomeSession = 0;

static void SetOutcome(wchar_t code, DWORD err, DWORD session)
{
    g_lastOutcome = code;
    g_lastErr = err;
    g_outcomeSession = session;
}

static void LogOutcome(void)
{
    /* ★ 这一行是给 tools/diag_autostart.bat 用的**唯一**根因入口。
     *   形状固定：[LAST] <字母> err=<数字> session=<数字>
     *   字母含义见 SetOutcome 上方的注释。 */
    Log(L"[LAST] %c err=%lu session=%lu", g_lastOutcome, (unsigned long)g_lastErr,
        (unsigned long)g_outcomeSession);
}

/* ------------------------------------------------------------------ */
/* 拉起引擎                                                            */
/* ------------------------------------------------------------------ */

/* useCurrentToken=TRUE 时用**本进程**令牌（仅 --selftest --launch 用），
 * 否则按会话取交互用户令牌（服务正常路径）。 */
static BOOL LaunchInSession(DWORD session, BOOL useCurrentToken)
{
    wchar_t engine[MAX_PATH];
    if (!EnginePath(engine, _countof(engine))) {
        const DWORD e = GetLastError();
        Log(L"  [失败] 解析引擎路径失败 err=%lu", e);
        SetOutcome(L'C', e, session);
        LogOutcome();
        return FALSE;
    }

    DWORD attrs = GetFileAttributesW(engine);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        Log(L"  [失败] 引擎不在：%s", engine);
        SetOutcome(L'C', ERROR_FILE_NOT_FOUND, session);
        LogOutcome();
        return FALSE;
    }

    HANDLE token = NULL;
    if (useCurrentToken) {
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                              &token)) {
            const DWORD e = GetLastError();
            Log(L"  [失败] OpenProcessToken err=%lu", e);
            SetOutcome(L'S', e, session);
            LogOutcome();
            return FALSE;
        }
    }
    else {
        /* WTSQueryUserToken 需要 **已启用** 的 SeTcbPrivilege
         * （见 EnableServicePrivileges —— "令牌里有" != "已经打开"）。
         * 会话里还没有交互用户时它必然失败，这是**预期**的，不是故障。 */
        if (!WTSQueryUserToken(session, &token)) {
            const DWORD e = GetLastError();
            Log(L"[TOKEN] wts=FAIL err=%lu session=%lu", e, (unsigned long)session);
            Log(L"  会话 %lu 取不到交互用户令牌 err=%lu%s",
                (unsigned long)session, e,
                (e == ERROR_PRIVILEGE_NOT_HELD)
                    ? L"（缺 SeTcbPrivilege —— 回看上面 [特权] 那几行的结果）"
                    : L"（可能还没人登录）");
            /* ★ 不再直接 return FALSE：取不到令牌要退到保底路。
             *   原来这里 `return FALSE`，于是"还没人登录"和"我缺特权"
             *   两种完全不同的问题都变成同一句"没拉起"（铁律 100）。 */
            token = BuildFallbackSessionToken(session);
            if (token == NULL) {
                Log(L"  [失败] 连保底令牌都造不出来 —— 见上面的 err");
                SetOutcome(L'S', e, session);
                LogOutcome();
                return FALSE;
            }
            Log(L"  [保底] 改用本进程令牌拉起引擎（会话 %lu）", (unsigned long)session);
        }
    }

    LogTokenFacts(token, useCurrentToken ? L"本进程" : L"会话交互用户");

    /* ★★ 关键一步：过滤令牌 -> 已提权令牌。
     *    引擎清单是 requireAdministrator；拿**未提权**令牌去 CreateProcessAsUser
     *    必 **err=740**（本机已实测，见 TryDuplicateElevatedToken 的注释）。
     *    原代码漏了这一步，这就是"开机不自启、双击却能开"的直接原因。 */
    if (!TokenIsElevated(token)) {
        HANDLE elevated = TryDuplicateElevatedToken(token);
        if (elevated != NULL) {
            CloseHandle(token);
            token = elevated;
            LogTokenFacts(token, L"升级后");
        }
        else {
            Log(L"  [保底] 该令牌无法提权 -> 换成本进程令牌"
                L"（否则建 requireAdministrator 进程必 err=740）");
            HANDLE fb = BuildFallbackSessionToken(session);
            if (fb != NULL) {
                CloseHandle(token);
                token = fb;
                LogTokenFacts(token, L"保底");
            }
            /* fb == NULL：保留原令牌，让下面真的失败并把 err 原样记下来 ——
             * 宁可留一条真错误，也不要在这里编一个假成功。 */
        }
    }
    else {
        Log(L"  令牌已是提权态，直接用它");
    }

    LPVOID env = NULL;
    if (!CreateEnvironmentBlock(&env, token, FALSE)) {
        env = NULL; /* 拿不到就用空环境，不致命 */
    }

    wchar_t dir[MAX_PATH];
    wcsncpy_s(dir, _countof(dir), engine, _TRUNCATE);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash != NULL) {
        *slash = L'\0';
    }

    /* ★ 引擎名带空格 —— 命令行必须**整条加引号**，否则 CreateProcess 会把
     *   路径拆成两截（铁律 115）。 */
    wchar_t cmd[MAX_PATH + 8];
    if (swprintf_s(cmd, _countof(cmd), L"\"%s\"", engine) < 0) {
        if (env != NULL) {
            DestroyEnvironmentBlock(env);
        }
        CloseHandle(token);
        Log(L"  [失败] 命令行拼装失败");
        SetOutcome(L'C', (DWORD)GetLastError(), session);
        LogOutcome();
        return FALSE;
    }

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = L"winsta0\\default"; /* 必须指定，否则落在服务自己的桌面（看不见） */

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    SetLastError(0);
    BOOL ok = CreateProcessAsUserW(token, engine, cmd, NULL, NULL, FALSE,
                                   CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
                                   env, dir, &si, &pi);
    DWORD err = ok ? 0 : GetLastError();

    if (!ok) {
        /* ★ 兜底条件**故意放宽**到"任何失败"，不再只认 1314。
         *   原来只认 1314，而实测"未提权令牌 + requireAdministrator"走的是
         *   **740** —— 恰好是最该兜底的那种被漏掉了（铁律 110 的形态：
         *   把一个错误码当成了全部失败）。 */
        Log(L"[LAUNCH] asuser=FAIL err=%lu", err);
        Log(L"  CreateProcessAsUserW 失败 err=%lu%s —— 改走 CreateProcessWithTokenW",
            err,
            (err == ERROR_PRIVILEGE_NOT_HELD)
                ? L"（1314 缺 SeAssignPrimaryToken / SeIncreaseQuota）"
                : (err == ERROR_ELEVATION_REQUIRED
                       ? L"（740 令牌没提权，建不了 requireAdministrator 进程）"
                       : L""));
        SetLastError(0);
        ok = CreateProcessWithTokenW(token, LOGON_WITH_PROFILE, engine, cmd,
                                     CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
                                     env, dir, &si, &pi);
        err = ok ? 0 : GetLastError();
        if (!ok) {
            Log(L"  CreateProcessWithTokenW 也失败 err=%lu%s", err,
                (err == ERROR_PRIVILEGE_NOT_HELD)
                    ? L"（1314 缺 SeImpersonatePrivilege）"
                    : L"");
        }
    }

    if (env != NULL) {
        DestroyEnvironmentBlock(env);
    }
    CloseHandle(token);

    if (!ok) {
        /* ★ err 分型（铁律 98：动作失败必须分型）——
         *   740 = 令牌没提权（这台机器的真根因）
         *   1314 = 缺特权/缺 SeImpersonatePrivilege（令牌没打开特权）
         *   5 = 拒绝访问（引擎清单/ACL 问题） */
        const wchar_t code = (err == ERROR_ELEVATION_REQUIRED) ? L'E'
                           : (err == ERROR_PRIVILEGE_NOT_HELD) ? L'P'
                           : L'C';
        /* [LAUNCH] FAIL / err= 是给 .bat 诊断脚本用的 ASCII 锚点 */
        Log(L"[LAUNCH] FAIL err=%lu session=%lu", err, (unsigned long)session);
        Log(L"  [失败] 拉起引擎失败 err=%lu（会话 %lu）%s",
            err, (unsigned long)session,
            (err == ERROR_ELEVATION_REQUIRED)
                ? L" —— err=740：令牌没提权。回看上面 [PRIV] 与 [TOKEN] 那几行。"
                : (err == ERROR_PRIVILEGE_NOT_HELD)
                      ? L" —— err=1314：缺特权。回看上面 [PRIV] 那几行有没有 FAIL。"
                      : L"");
        SetOutcome(code, err, session);
        LogOutcome();
        return FALSE;
    }

    /* ================= 存活确认 =================
     * ★★ CreateProcessAsUser 返回 TRUE **只说明进程被创建**，不说明引擎活着。
     *    桌面没就绪 / 引擎自己初始化失败时会**秒退**。如果这时就记账，
     *    AlreadyLaunched() 会让这个会话**永远不再重试** —— 结果是
     *    "开机自启静默失效，而日志写着已拉起 pid=xxxx"（铁律 124 的空真形态：
     *    把"调用成功"当成了"目标达成"）。
     *
     * ★ 判据是"等它**退出**"：WAIT_TIMEOUT = 没退出 = 活着 = **成功**。
     *   所以宽限期短**不会**把"还在启动中"误判成"秒退"——
     *   LAUNCH_GRACE_MS 只决定"多晚的崩溃还算启动失败"。
     */
    DWORD wait = WaitForSingleObject(pi.hProcess, LAUNCH_GRACE_MS);
    if (wait == WAIT_OBJECT_0) {
        DWORD code = 0;
        if (!GetExitCodeProcess(pi.hProcess, &code)) {
            code = 0xFFFFFFFFu;
        }
        Log(L"  [失败] 引擎拉起后 %lu ms 内就退出了（退出码 0x%08lX，会话 %lu）"
            L" —— 本次**不记账**，%lu ms 后重试",
            (unsigned long)LAUNCH_GRACE_MS, (unsigned long)code,
            (unsigned long)session, (unsigned long)RETRY_MS);
        SetOutcome(L'X', code, session);
        LogOutcome();
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    /* ★ 再用一个**独立**的正向证据交叉确认 —— 不依赖上面那次等待的结果。
     *   （铁律 59：探针不能自己当自己的法官。） */
    if (!ProcessRunningInSession(ENGINE_EXE, session, FALSE)) {
        Log(L"  [失败] 等待未超时，但快照里找不到 pid=%lu 的引擎（会话 %lu）"
            L" —— 不记账，%lu ms 后重试",
            (unsigned long)pi.dwProcessId, (unsigned long)session,
            (unsigned long)RETRY_MS);
        SetOutcome(L'X', ERROR_NOT_FOUND, session);
        LogOutcome();
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    Log(L"[LAUNCH] OK pid=%lu session=%lu", (unsigned long)pi.dwProcessId,
        (unsigned long)session);
    Log(L"  已拉起引擎 pid=%lu（会话 %lu）并确认存活",
        (unsigned long)pi.dwProcessId, (unsigned long)session);
    SetOutcome(L'O', 0, session);
    LogOutcome();
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* 安全模式                                                            */
/* ------------------------------------------------------------------ */

/* 仅 --selftest --fake-safemode 用：让"安全模式"这条分支在正常启动的机器上
 * 也能被测到。没有它的话，这条闸门只能靠"真的进一次安全模式"来验证，
 * 而那是没法自动化的（铁律 108：被测不到的分支等于没写）。 */
static BOOL g_forceSafeMode = FALSE;
static BOOL g_safeModeLogged = FALSE;

/* 安全模式判定。
 *
 * ★ 用户态唯一**有文档**的判据就是 GetSystemMetrics(SM_CLEANBOOT)：
 *     0 = 正常启动，1 = 安全模式，2 = 带网络的安全模式。
 *   刻意**不**用注册表 (HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot)：
 *   那个键是人可写的（很多工具靠它改行为），而 SM_CLEANBOOT 是引导加载器
 *   写进内核、由 user32 直接读出来的 —— 判定要选"骗不了"的那个来源。
 */
static BOOL IsSafeMode(void)
{
    if (g_forceSafeMode) {
        return TRUE;
    }
    return GetSystemMetrics(SM_CLEANBOOT) != 0;
}

/* ------------------------------------------------------------------ */
/* 「同一会话只拉一次」的记账                                           */
/* ------------------------------------------------------------------ */

static DWORD g_launched[MAX_SESSIONS];
static int   g_launchedCount = 0;
static CRITICAL_SECTION g_launchLock;

static BOOL AlreadyLaunched(DWORD session)
{
    for (int i = 0; i < g_launchedCount; ++i) {
        if (g_launched[i] == session) {
            return TRUE;
        }
    }
    return FALSE;
}

static void MarkLaunched(DWORD session)
{
    if (g_launchedCount < MAX_SESSIONS && !AlreadyLaunched(session)) {
        g_launched[g_launchedCount++] = session;
    }
}

/* 会话变更回调和主循环都会走到这里，所以要加锁 */
static void TryLaunchForSession(DWORD session, BOOL useCurrentToken)
{
    if (session == 0xFFFFFFFF) {
        return;
    }

    /* ★ 安全模式闸门放在**所有拉起路径的唯一入口**上。
     *
     *   为什么必须在这里而不是在各个调用点：拉起引擎有三条路
     *   （服务启动时首试 / 会话变更回调 / 兜底 tick），任何一个调用点漏判
     *   都会在安全模式下把引擎拉起来。判据只写一份，就不会漏（铁律 6 的形态）。
     *
     *   背景：驱动被设成 SERVICE_BOOT_START 后，**安全模式也会加载它**。
     *   内核侧本身不启动任何进程，所以"安全模式下不激活"这件事只能由这里保证。 */
    if (IsSafeMode()) {
        if (!g_safeModeLogged) {
            g_safeModeLogged = TRUE;
            Log(L"检测到**安全模式** —— 按要求不拉起引擎进程。");
            Log(L"  （驱动在 BOOT_START 下仍会被加载，但它自己不启动任何进程；"
                L"本服务也不会拉起用户态引擎）");
        }
        return;
    }

    EnterCriticalSection(&g_launchLock);

    if (AlreadyLaunched(session)) {
        LeaveCriticalSection(&g_launchLock);
        return; /* 这个会话已经拉过了 —— 静默返回，不刷日志 */
    }

    /* 已经有引擎在跑（比如遗留的计划任务先拉起来了）=> 记账但不再拉，
     * 免得变成"两份引擎"。 */
    if (EngineRunningInSession(session)) {
        MarkLaunched(session);
        Log(L"会话 %lu 里已经有引擎，本次不再拉起", (unsigned long)session);
        LeaveCriticalSection(&g_launchLock);
        return;
    }

    /* ★ 会话"真的可用"才拉（四条判据，见 SessionUsable）。
     *   不过就**不记账** —— 登录瞬间失败属于"还没到点"，不是"坏了"，
     *   30s 后的兜底 tick 会再试（铁律 98：动作失败必须分型）。 */
    wchar_t why[256];
    if (!SessionUsable(session, why, _countof(why))) {
        LogNotUsable(session, why);
        LeaveCriticalSection(&g_launchLock);
        return;
    }

    if (LaunchInSession(session, useCurrentToken)) {
        MarkLaunched(session);
    }
    /* 失败**不**记账 —— 兜底 tick 会再试（登录瞬间 winsta 可能还没就绪；
     * 以及"拉起来了但秒退"，见 LaunchInSession 的存活确认） */

    LeaveCriticalSection(&g_launchLock);
}

/* ------------------------------------------------------------------ */
/* 服务主体                                                            */
/* ------------------------------------------------------------------ */

static SERVICE_STATUS_HANDLE g_statusHandle = NULL;
static SERVICE_STATUS        g_status;
static HANDLE                g_stopEvent = NULL;

static void ReportStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkpoint = 1;

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted =
        (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
            ? 0
            : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE);
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    g_status.dwWaitHint = waitHint;

    if (g_statusHandle != NULL) {
        SetServiceStatus(g_statusHandle, &g_status);
    }
}

static DWORD WINAPI HandlerEx(DWORD control, DWORD eventType,
                              LPVOID eventData, LPVOID context)
{
    (void)context;

    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        ReportStatus(SERVICE_STOP_PENDING, 0, 3000);
        if (g_stopEvent != NULL) {
            SetEvent(g_stopEvent);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        ReportStatus(g_status.dwCurrentState, 0, 0);
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE: {
        /* ★ 结构体大小必须校验：eventData 可能是别的结构，
         *   不校验就直接 cast 会读到垃圾会话号（铁律 57：判定须验前提）。 */
        WTSSESSION_NOTIFICATION* n = (WTSSESSION_NOTIFICATION*)eventData;
        if (n != NULL && n->cbSize == sizeof(WTSSESSION_NOTIFICATION)) {
            switch (eventType) {
            case WTS_SESSION_LOGON:
            case WTS_SESSION_UNLOCK:
            case WTS_CONSOLE_CONNECT:
                /* ★ 常量名是 WTS_CONSOLE_CONNECT（不是 WTS_SESSION_CONSOLE_CONNECT
                 *   —— 后者不存在，写了会 C2065 编译失败）。
                 *   这三个事件覆盖：登录、解锁、切到本机控制台。 */
                Log(L"[会话变更] 事件=0x%lx 会话=%lu",
                    (unsigned long)eventType, (unsigned long)n->dwSessionId);
                TryLaunchForSession(n->dwSessionId, FALSE);
                break;
            default:
                break; /* 登出/锁屏等，不需要动作 */
            }
        }
        return NO_ERROR;
    }

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

/* 主循环：启动时先试一次，之后每 RETRY_MS 兜底一次。
 * ★ 兜底 tick 只在"该会话还没成功拉过"时有实际动作 —— 所以引擎被关掉后
 *   它**不会**把引擎拉回来（这是刻意的，见文件头"同一会话只拉一次"）。 */
static void RunLoop(void)
{
    for (;;) {
        DWORD session = WTSGetActiveConsoleSessionId();
        if (session == 0xFFFFFFFF) {
            /* 没有活动控制台会话（还没人登录）—— 正常状态，不刷日志 */
        }
        else {
            TryLaunchForSession(session, FALSE);
        }

        if (WaitForSingleObject(g_stopEvent, RETRY_MS) == WAIT_OBJECT_0) {
            break;
        }
    }
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    (void)argc;
    (void)argv;

    g_statusHandle = RegisterServiceCtrlHandlerExW(SVC_NAME, HandlerEx, NULL);
    if (g_statusHandle == NULL) {
        return;
    }

    ReportStatus(SERVICE_START_PENDING, 0, 5000);

    g_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_stopEvent == NULL) {
        ReportStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    InitializeCriticalSection(&g_launchLock);

    LogInit();
    Log(L"=== %s 启动 pid=%lu ===", SVC_NAME, (unsigned long)GetCurrentProcessId());

    /* ★ 第一件事就是打开特权。
     *   令牌里的特权默认是**关**的，"有"不等于"能用" —— 不打开这几行，
     *   下面 WTSQueryUserToken / CreateProcessAsUser 全部会以
     *   err=1314 失败（见 EnableServicePrivileges 的注释）。 */
    EnableServicePrivileges();

    ReportStatus(SERVICE_RUNNING, 0, 0);

    RunLoop();

    Log(L"=== %s 停止 ===", SVC_NAME);
    LogClose();
    DeleteCriticalSection(&g_launchLock);

    ReportStatus(SERVICE_STOPPED, 0, 0);
}

/* ------------------------------------------------------------------ */
/* 前台测试入口                                                        */
/* ------------------------------------------------------------------ */

static int RunSelfTest(BOOL doLaunch)
{
    LogInit();

    wprintf(L"=== r3shieldcore_svc --selftest ===\n");

    /* ★ 先把"能不能拉起引擎"的**前提**摆出来：特权 + 令牌身份。
     *   只报一个"引擎在跑=否"是不可诊断的（铁律 97）—— 必须能看到**为什么**。
     *   ★ 但 --selftest 通常是以管理员身份在控制台跑的，**不是 SYSTEM**，
     *     所以这里的 [特权] 结果**不能**代表服务里的结果；服务里的结果
     *     要读 r3shieldcore-svc.log 里那几行。 */
    wprintf(L"\n--- 前提 A：特权（本进程；注意这不是服务里的 SYSTEM 上下文）---\n");
    EnableServicePrivileges();

    wprintf(L"\n--- 前提 B：令牌（本进程）---\n");
    HANDLE selfTok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &selfTok)) {
        LogTokenFacts(selfTok, L"本进程");
        CloseHandle(selfTok);
    }
    else {
        wprintf(L"  OpenProcessToken 失败 err=%lu\n", GetLastError());
    }
    wprintf(L"\n");

    wchar_t engine[MAX_PATH];
    if (!EnginePath(engine, _countof(engine))) {
        wprintf(L"引擎路径   : [败] 解析失败 err=%lu\n", GetLastError());
        return 1;
    }
    wprintf(L"引擎路径   : %s\n", engine);

    DWORD attrs = GetFileAttributesW(engine);
    BOOL exists = (attrs != INVALID_FILE_ATTRIBUTES) &&
                  ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0);
    wprintf(L"引擎存在   : %s\n", exists ? L"是" : L"否");

    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    wprintf(L"当前会话   : %lu\n", (unsigned long)session);

    BOOL safe = IsSafeMode();
    wprintf(L"安全模式   : %s\n", safe ? L"是（不会拉起引擎）" : L"否");

    /* ★ 把"会话可用性"四条判据的**结果**打出来。
     *   这是"为什么没自启"的第一诊断口径 —— 只给一个"没拉起"的布尔值
     *   是不可诊断的（铁律 97）。 */
    DWORD console_ = WTSGetActiveConsoleSessionId();
    if (console_ == 0xFFFFFFFFu) {
        wprintf(L"控制台会话 : (无)\n");
        wprintf(L"会话可用   : 否 —— 还没有控制台会话\n");
    }
    else {
        wprintf(L"控制台会话 : %lu\n", (unsigned long)console_);
        wchar_t why[256];
        if (SessionUsable(console_, why, _countof(why))) {
            wprintf(L"会话可用   : 是（有人登录 / 活动态 / 有令牌 / 桌面已起）\n");
        }
        else {
            wprintf(L"会话可用   : 否 —— %s\n", why);
        }
    }

    BOOL running = EngineRunningInSession(session);
    wprintf(L"引擎在跑   : %s\n", running ? L"是" : L"否");

    if (!exists) {
        wprintf(L"[败] 引擎不存在 —— 这个 exe 必须和引擎放在同一目录\n");
        LogClose();
        return 1;
    }

    if (!doLaunch) {
        wprintf(L"（未加 --launch，只诊断，不真的拉引擎）\n");
        LogClose();
        return 0;
    }

    /* ★ 安全模式下的**负对照**：加了 --launch 也必须**不**拉。
     *   这正是"安全模式不拉起进程"这条要求的可自动化验证方式。 */
    if (safe) {
        wprintf(L"\n--launch：检测到安全模式 -> **拒绝拉起**（预期行为，不是失败）\n");
        wprintf(L"拉起结果   : 已按要求跳过\n");
        LogClose();
        return 0;
    }

    if (running) {
        wprintf(L"（本会话已有引擎在跑，跳过 --launch）\n");
        LogClose();
        return 0;
    }

    /* ★ --launch 是**手工强制**路径：刻意**不**过 SessionUsable 那四条判据
     *   （你是坐在机器前面敲的，会话当然可用；这里要的就是"强行拉一次看看"）。
     *   但**存活确认照做** —— 所以"成功"的含义是"拉起来了并且还活着"。 */
    wprintf(L"\n--launch：用**本进程令牌**拉一次引擎（前台可见，跳过会话判据）\n");
    BOOL ok = LaunchInSession(session, TRUE);
    wprintf(L"拉起结果   : %s\n",
            ok ? L"成功（已确认存活）" : L"失败（见上面的原因）");

    LogClose();
    return ok ? 0 : 1;
}

static int RunConsole(void)
{
    LogInit();
    Log(L"=== --console 前台模式 pid=%lu ===", (unsigned long)GetCurrentProcessId());
    EnableServicePrivileges();

    InitializeCriticalSection(&g_launchLock);
    g_stopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    wprintf(L"前台模式：Ctrl+C 退出\n");
    RunLoop();

    DeleteCriticalSection(&g_launchLock);
    Log(L"=== --console 退出 ===");
    LogClose();
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    setlocale(LC_ALL, "");

    if (argc >= 2) {
        if (wcscmp(argv[1], L"--version") == 0) {
            wprintf(L"r3shieldcore_svc %s\n", VERSION_STR);
            return 0;
        }

        if (wcscmp(argv[1], L"--selftest") == 0) {
            BOOL doLaunch = FALSE;
            for (int i = 2; i < argc; ++i) {
                if (wcscmp(argv[i], L"--launch") == 0) {
                    doLaunch = TRUE;
                }
                else if (wcscmp(argv[i], L"--fake-safemode") == 0) {
                    /* 把"安全模式"这条分支强制打开，用来验证闸门真的会拦。
                     * ★ 只影响 --selftest，不进入服务主循环。 */
                    g_forceSafeMode = TRUE;
                }
            }
            return RunSelfTest(doLaunch);
        }

        if (wcscmp(argv[1], L"--console") == 0) {
            return RunConsole();
        }

        wprintf(L"未知参数：%s\n", argv[1]);
        wprintf(L"用法：r3shieldcore_svc.exe [--selftest [--launch] [--fake-safemode]] "
                L"[--console] [--version]\n");
        return 2;
    }

    /* 正常路径：交给 SCM */
    SERVICE_TABLE_ENTRYW table[2];
    table[0].lpServiceName = (LPWSTR)SVC_NAME;
    table[0].lpServiceProc = ServiceMain;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;

    if (!StartServiceCtrlDispatcherW(table)) {
        DWORD err = GetLastError();
        LogInit();
        Log(L"StartServiceCtrlDispatcherW 失败 err=%lu —— "
            L"这个程序必须由服务控制管理器（SCM）启动。", err);
        Log(L"手工调试请用 --console；只做诊断请用 --selftest。");
        LogClose();
        wprintf(L"[失败] 必须由 SCM 启动（err=%lu）。手工调试用 --console。\n", err);
        return 1;
    }

    return 0;
}
