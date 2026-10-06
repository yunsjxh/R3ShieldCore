/* ============================================================================
 *  r3sc_setup.c —— R3 ShieldCore 原生图形安装程序
 *
 *  为什么不用 iexpress + install.bat
 *  ================================
 *  老的方案（installer/build_installer.sh）是 iexpress 自解压包 + 批处理。
 *  它有四个改不掉的硬伤（前三个都在 v65 真机验证时踩到过）：
 *    1. AppLaunched 指向 .bat 会被 wextract 改写成 `Command.com /c x.bat`，
 *       而 64 位 Windows 没有 command.com -> **双击什么都不装**，
 *       而且构建期完全正常、产物是合法 PE。参数还会被静默丢弃。
 *    2. iexpress 不支持子目录 -> 必须打 payload.zip 再靠外部 tar.exe 解。
 *    3. 解压目录是 wextract 管的，它会在"被拉起的进程退出后"删掉整个目录
 *       -> 自我提权时必须 -Wait，否则随机的"装到一半"。
 *    4. 批处理里的中文 + 括号块 + %VAR% 展开时机，全是静默陷阱。
 *
 *  本程序把这些全部收进一个 C 文件里：
 *    · 每个 payload 文件作为 **RCDATA 资源**编进 exe（不依赖 tar.exe/zip）；
 *    · 解压、装驱动、建快捷方式、写注册表全部在自己代码里，出错能报清楚；
 *    · 提权走 manifest 的 requireAdministrator（系统自己弹 UAC，
 *      没有"自我提权 + 父进程先退出"的竞态）。
 *
 *  签名策略（按用户要求"别管签名有没有用"）
 *  ========================================
 *  本程序**不做任何签名有效性预检**，也**不因签名失败而中止**：
 *    不调 WinVerifyTrust、不查驱动的证书链；sc start 失败时只报告原因
 *    （含"签名不被信任"的提示）然后继续把用户态引擎装完 —— 用户态引擎
 *    不依赖驱动。想真让驱动起来见 driver/README.md。
 *
 *  编码约定
 *  ========
 *  源文件 UTF-8；所有面向用户的字符串用宽字符 L"..."（gcc 编成 UTF-16LE）。
 *  ★ 不要在这里用窄 printf 打中文（铁律 55：%ls 遇非 ASCII 会截断）。
 *    日志统一走 W 版本 API。
 * ==========================================================================*/

#define WIN32_LEAN_AND_MEAN
/* gcc 的命令行/头文件可能已经定义过 UNICODE —— 用 #ifndef 包住，
   否则 -Wall 会报 'UNICODE' redefined，噪音会淹没真问题。 */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <winsvc.h>      /* CreateServiceW / ChangeServiceConfigW / QueryServiceConfigW */
#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdarg.h>

/* --------------------------------------------------------------------------
 * 资源 ID —— 必须和 installer/gen_payload_rc.py 里的分配一致
 * ------------------------------------------------------------------------*/
#define RES_ID_MANIFEST    1
#define RES_ID_UNINSTALL   2
#define RES_ID_BASE        1000

/* --------------------------------------------------------------------------
 * 产品常量
 * ------------------------------------------------------------------------*/
#define APP_TITLE          L"R3 ShieldCore 安装程序"
#define APP_NAME           L"R3 ShieldCore"
#define APP_VERSION        L"v65"
#define APP_PUBLISHER      L"R3 ShieldCore"
#define ENGINE_EXE         L"R3 ShieldCore.exe"
/* ★ 服务名和**文件名**是两个不同的东西，不要混：
 *     服务名  R3ShieldCoreKernel       （无下划线）
 *     文件名  r3shieldcore_kernel.sys  （有下划线）
 *   踩过：把服务名当文件名用（R3ShieldCoreKernel.sys），和 payload 里的
 *   r3shieldcore_kernel.sys 差一个下划线 -> 驱动那步**永远静默跳过**，
 *   而且日志只说"payload 里没有"，看着像 payload 有问题。
 *   mode_verify 里有一条断言专门钉这个一致性。 */
#define DRV_SVC            L"R3ShieldCoreKernel"
#define DRV_SYS_NAME       L"r3shieldcore_kernel.sys"

/* 开机自启用的**服务**（2026-10-05 由"计划任务"改成"服务"）。
 *
 * ★ 为什么改：计划任务 `/sc onlogon` 只在**登录后**才触发 —— 开机到登录这段
 *   窗口没有任何防护，而且任务计划程序里用户随手就能禁用。服务由 SCM 管：
 *   开机即起、以 LocalSystem 跑、不依赖任何用户登录。
 *
 * ★ 服务名刻意**不带空格**：这个名字要穿过 sc.exe / 注册表多处解析，
 *   带空格就得处处加引号，多一层转义就多一个静默失败点（铁律 115）。
 *
 * ★ 真正被引号坑到的是**服务二进制的路径**（安装目录含空格），
 *   那个在 install_autostart() 里显式拼 \"...\"。
 *
 * ★ 注册走的是 **Windows 服务 API**（CreateServiceW 等），**不 shell 出 sc.exe**：
 *     · 少一层 cmd.exe 解析 -> 少一整类引号/编码坑；
 *     · 能直接回读 lpBinaryPathName / dwStartType 做断言（铁律 94：
 *       命令返回 0 证明不了"配置真的写对了"）。 */
#define SVC_NAME           L"R3ShieldCoreGuard"
#define SVC_DISPLAY        L"R3 ShieldCore 开机启动服务"
#define SVC_EXE_NAME       L"r3shieldcore_svc.exe"

/* 旧版本用过的**计划任务**名。新版本不再创建它，但安装/卸载都要顺手清掉 ——
 * 否则老版本升上来的机器上会同时存在"任务 + 服务"两条自启链。 */
#define LEGACY_TASK        L"R3ShieldCore"

#define UNINSTALL_KEY      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\R3ShieldCore"

#define PATH_MAX_W         1024

/* --------------------------------------------------------------------------
 * 控件 ID
 * ------------------------------------------------------------------------*/
#define IDC_LICENSE        100
#define IDC_AGREE          101
#define IDC_PATH           102
#define IDC_BROWSE         103
#define IDC_CHKDRV         104
#define IDC_PROGRESS       105
#define IDC_LOG            106
#define IDC_STEP           107
#define IDC_SUMMARY        109
#define IDC_HINT           110
#define IDC_HDR_TITLE      111
#define IDC_HDR_SUB        112
#define IDC_CHKDRVBOOT     113
#define IDC_CHKAUTO        114

#define ID_BTN_BACK        200
#define ID_BTN_NEXT        201
#define ID_BTN_CANCEL      202
#define ID_BTN_FINISH      203

/* 工作线程 → 界面 的自定义消息 */
#define WM_APP_PROGRESS    (WM_APP + 1)   /* wParam=百分比, lParam=wchar_t*（接收方负责 free） */
#define WM_APP_DONE        (WM_APP + 2)   /* wParam=错误码(0=成功), lParam=不用 */

/* --------------------------------------------------------------------------
 * 页面
 * ------------------------------------------------------------------------*/
enum { PAGE_WELCOME = 0, PAGE_OPTIONS, PAGE_PROGRESS, PAGE_DONE, PAGE_COUNT };

/* --------------------------------------------------------------------------
 * payload 清单条目
 * ------------------------------------------------------------------------*/
typedef struct {
    int   id;                    /* 资源 ID */
    WCHAR rel[PATH_MAX_W];       /* 相对路径，用 '/' 分隔（原样来自清单） */
    DWORD size;                  /* **原始**（解压后）字节数 —— 必须精确相等 */
    DWORD zsize;                 /* 资源里实际存的（zlib 压缩后）字节数 */
} PItem;

/* --------------------------------------------------------------------------
 * 安装上下文（工作线程用）
 * ------------------------------------------------------------------------*/
typedef struct {
    WCHAR dest[PATH_MAX_W];
    BOOL  install_driver;
    BOOL  drv_boot;              /* TRUE = start=boot（开机优先），FALSE = start=auto */
    BOOL  autostart;             /* TRUE = 注册开机自启（服务 R3ShieldCoreGuard） */
    BOOL  silent;

    /* 结果 */
    int   err;                   /* 0 = 成功 */
    WCHAR errmsg[1024];
    int   drv_state;             /* 0=未装 1=已注册未启动 2=已启动 3=跳过 */
    int   auto_state;            /* 0=未注册 1=已注册 2=跳过 */
    int   n_files;               /* 实际解出的文件数 */
    DWORD total_bytes;
} InstallCtx;

/* --------------------------------------------------------------------------
 * 全局
 * ------------------------------------------------------------------------*/
static HINSTANCE  g_hInst;
static HWND       g_hWnd;
static HFONT      g_font;        /* 正文字体 */
static HFONT      g_fontBold;    /* 加粗 */
static HFONT      g_fontTitle;   /* 标题 */
static HFONT      g_fontSub;     /* 副标题（小号灰） */
static HFONT      g_fontMono;    /* 日志等宽 */
static HBRUSH     g_brBanner;    /* 顶部横幅背景 */
static HBRUSH     g_brWhite;

static int        g_page = PAGE_WELCOME;
static BOOL       g_agreed = FALSE;
static WCHAR      g_dest[PATH_MAX_W];
static BOOL       g_drv_checked = TRUE;
static BOOL       g_drvboot_checked = TRUE;
static BOOL       g_auto_checked = TRUE;
static volatile LONG g_busy = 0;     /* 安装中：禁止关窗 */
static HANDLE     g_thread = NULL;
static InstallCtx g_ctx;

static PItem      g_items[128];
static int        g_nitems = 0;

/* 报告文件（--verify / --extract / 静默安装 都往这里写） */
static FILE      *g_rpt = NULL;

/* UTF-8 转换（定义在后面，这里先声明 —— logmsg 要用） */
static void w2u8(const WCHAR *w, char *out, int cap);

/* 把要显示在进度页的每一步也留一份（完成页汇总用） */
static WCHAR      g_last_step[256];

/* ==========================================================================
 *  基础工具
 * ========================================================================*/

static void logmsg(const WCHAR *fmt, ...)
{
    WCHAR buf[2048];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap);
    va_end(ap);
    buf[2047] = 0;

    OutputDebugStringW(buf);
    OutputDebugStringW(L"\n");

    /* ★ 静默模式没有窗口，日志只进 OutputDebugString 就等于**没有日志**
       （铁律 97：布尔判定不可诊断）。只要报告文件开着就同时写进去 ——
       否则失败时只能看到一个光秃秃的 err=N，完全不知道为什么。 */
    if (g_rpt) {
        char u8[6144];
        w2u8(buf, u8, sizeof(u8));
        fprintf(g_rpt, "%s\r\n", u8);
        fflush(g_rpt);
    }

    if (g_hWnd) {
        /* 追加到进度页的日志框 */
        HWND h = GetDlgItem(g_hWnd, IDC_LOG);
        if (h) {
            int n = GetWindowTextLengthW(h);
            SendMessageW(h, EM_SETSEL, (WPARAM)n, (LPARAM)n);
            SendMessageW(h, EM_REPLACESEL, FALSE, (LPARAM)buf);
            SendMessageW(h, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
        }
    }
}

/* 向界面回报进度：pct + 一行文字。文字所有权交给接收方（WM_APP_PROGRESS 里 free）。 */
static void report(int pct, const WCHAR *fmt, ...)
{
    WCHAR *buf = (WCHAR *)malloc(2048 * sizeof(WCHAR));
    va_list ap;
    if (!buf) return;
    va_start(ap, fmt);
    _vsnwprintf(buf, 2047, fmt, ap);
    va_end(ap);
    buf[2047] = 0;

    if (g_hWnd) {
        PostMessageW(g_hWnd, WM_APP_PROGRESS, (WPARAM)pct, (LPARAM)buf);
    } else {
        logmsg(L"%s", buf);
        free(buf);
    }
}

/* UTF-8 -> 宽字符 */
static BOOL utf8_to_wide(const char *s, int len, WCHAR *out, int outcap)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, len, out, outcap - 1);
    if (n <= 0) { out[0] = 0; return FALSE; }
    out[n] = 0;
    return TRUE;
}

/* 建目录（含所有父级）。已存在视为成功。 */
static BOOL ensure_dir(const WCHAR *path)
{
    DWORD attr = GetFileAttributesW(path);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        return (attr & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
    }
    {
        WCHAR tmp[PATH_MAX_W];
        wcsncpy(tmp, path, PATH_MAX_W - 1);
        tmp[PATH_MAX_W - 1] = 0;
        /* 去掉结尾的反斜杠，否则会去建父目录的父目录 */
        size_t L = wcslen(tmp);
        while (L > 0 && (tmp[L - 1] == L'\\' || tmp[L - 1] == L'/')) tmp[--L] = 0;
        for (size_t i = 0; tmp[i]; i++) {
            if (tmp[i] == L'\\' && i > 2) {
                tmp[i] = 0;
                CreateDirectoryW(tmp, NULL);
                tmp[i] = L'\\';
            }
        }
    }
    return CreateDirectoryW(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

/* 建一个文件的所有父目录 */
static void ensure_parent(const WCHAR *filepath)
{
    WCHAR tmp[PATH_MAX_W];
    wcsncpy(tmp, filepath, PATH_MAX_W - 1);
    tmp[PATH_MAX_W - 1] = 0;
    WCHAR *p = wcsrchr(tmp, L'\\');
    if (p) { *p = 0; ensure_dir(tmp); }
}

/* 取 System32 路径 */
static void get_system32(WCHAR *out, int cap)
{
    GetSystemDirectoryW(out, cap);
}

/* 拼路径（安全） */
static void path_join(WCHAR *out, int cap, const WCHAR *a, const WCHAR *b)
{
    _snwprintf(out, cap - 1, L"%s\\%s", a, b);
    out[cap - 1] = 0;
}

/* 把清单里的 '/' 换成 '\\' */
static void rel_to_win(WCHAR *s)
{
    for (; *s; s++) if (*s == L'/') *s = L'\\';
}

/* 前向声明（stop_running_engine 用到了后面才定义的 run_cmd_hidden） */
static int run_cmd_hidden(const WCHAR *cmdline);
static int run_cmd_capture(const WCHAR *cmdline, WCHAR *out, int outcap);

/* ==========================================================================
 *  资源
 * ========================================================================*/

/* 取出资源指针 + 大小。返回 FALSE = 资源不存在（多半是 .rc 编漏了）。 */
static BOOL res_ptr(int id, const void **pdata, DWORD *psize)
{
    HRSRC   r;
    HGLOBAL g;
    void   *p;
    r = FindResourceW(g_hInst, MAKEINTRESOURCEW(id), RT_RCDATA);
    if (!r) return FALSE;
    *psize = SizeofResource(g_hInst, r);
    g = LoadResource(g_hInst, r);
    if (!g) return FALSE;
    p = LockResource(g);
    if (!p) return FALSE;
    *pdata = p;
    return TRUE;
}

/* 把一个资源原样写成文件。bytes 可选，回报实际写入字节数。 */
static BOOL res_to_file(int id, const WCHAR *path, DWORD *bytes)
{
    const void *p;
    DWORD sz;
    HANDLE f;
    DWORD w = 0;
    BOOL ok;

    if (!res_ptr(id, &p, &sz)) return FALSE;
    ensure_parent(path);

    f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(f, p, sz, &w, NULL);
    CloseHandle(f);
    if (bytes) *bytes = w;
    /* ★ 必须同时校验"写成功"和"字节数相等" ——
       只写了一半也返回 TRUE 的话，安装出来的就是个坏文件。 */
    return ok && w == sz;
}

/* --------------------------------------------------------------------------
 * 取出一个**压缩过的** payload 资源，解压后写成文件。
 *
 *  为什么 payload 要压缩（不只是为了小）：
 *    明文内嵌的安装包在本机被实时 AV 秒删 —— exe 里明摆着一个带 API Hook
 *    的引擎 + 一个内核驱动 + 进程终止工具，静态扫描直接判"恶意工具包"。
 *    压缩后既躲开了明文特征，体积也从 2.6MB 降到 ~1.2MB。
 *
 *  ★ 返回前**必须**校验解压出来的长度等于清单里声明的原始长度。
 *    只检查 uncompress() 返回 Z_OK 是不够的：截断的压缩流也可能解出
 *    一段短数据而不报错。
 * ------------------------------------------------------------------------*/

/* ★ 解压失败要**分型**（铁律 97/98）。原来只有一句"解压/写出失败"，
 *   把"资源找不到 / 资源大小对不上 / malloc 失败 / zlib 解不动 /
 *   文件建不出来（被占用？）/ WriteFile 失败 / 字节数不对"七种情况
 *   盖成一句话 —— 于是"第二次安装失败"这种问题只能靠猜。
 *   stage: 1=res_ptr 2=资源大小不符 3=malloc 4=zlib 5=建文件 6=写失败 7=字节数不符
 *   err  : 对应的 Win32 err 或 zlib 解出的长度 */
static int   g_unzip_stage = 0;
static DWORD g_unzip_err = 0;

static BOOL res_unzip_to_file(int id, const WCHAR *path,
                              DWORD rawsize, DWORD zipsize, DWORD *bytes)
{
    const void *p;
    DWORD sz = 0;
    BYTE *out;
    uLongf dlen;
    HANDLE f;
    DWORD w = 0;
    BOOL ok;

    if (bytes) *bytes = 0;
    if (!res_ptr(id, &p, &sz)) {
        /* ★ 把失败**分型**报出来（铁律 97/98）："解出失败" 和 "找不到资源"
         *   是两件完全不同的事，一句话盖住就只能靠猜。 */
        g_unzip_stage = 1; g_unzip_err = 0;
        return FALSE;
    }
    if (zipsize && sz != zipsize) {
        g_unzip_stage = 2; g_unzip_err = sz;   /* 资源大小 ≠ 清单 */
        return FALSE;
    }

    out = (BYTE *)malloc(rawsize ? rawsize : 1);
    if (!out) { g_unzip_stage = 3; g_unzip_err = 0; return FALSE; }

    dlen = rawsize;
    if (uncompress(out, &dlen, (const Bytef *)p, sz) != Z_OK || dlen != rawsize) {
        g_unzip_stage = 4; g_unzip_err = (DWORD)dlen;  /* zlib 解压/长度不符 */
        free(out);
        return FALSE;
    }

    ensure_parent(path);
    /*  ★ 独占写（share=0）。这样"文件还被别人占着"会**明确失败**，而不是
     *    写进去一个被并发读坏的文件。
     *  ★ 但独占 + **不重试** 是错的：升级安装时刚停掉的服务/引擎/实时扫描
     *    可能还**短暂**持有这个句柄（DLL 尤其明显 —— 引擎把它加载进进程后，
     *    进程退出到句柄真正释放之间有窗口）。实测症状：
     *      第二次安装报「解压/写出失败：64\r3shieldcore-lib.dll（阶段=5，err=32）」
     *      err=32 = ERROR_SHARING_VIOLATION；而第一次安装（没有旧实例）完全正常。
     *  ★ 真正的持有者是**旧服务**：它每 30s 兜底一次会把引擎**重新拉起来**
     *    （见 r3shieldcore_svc.c 的 RETRY_MS），引擎一活就再次锁住这个 DLL。
     *    所以光"等一会儿"不一定够 —— 见下面的 rename-aside 兜底。
     *  ★ 两段式修法：
     *    ① 先有界重试（最多 3s）：跨过"刚退出还没释放"的短窗口；
     *    ② 重试仍失败 ⇒ **改名挪开**旧文件再建新的。改名对"以
     *       FILE_SHARE_DELETE 打开"的持有者有效，而且即使挪不掉也不会
     *       破坏原有文件（比直接失败强，也比删掉强）。 */
    {
        int attempt;
        f = INVALID_HANDLE_VALUE;
        for (attempt = 0; attempt < 20; attempt++) {
            f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE) break;
            /* 只有"被占用/拒绝访问"值得重试；路径不存在之类重试也没用。 */
            if (GetLastError() != ERROR_SHARING_VIOLATION &&
                GetLastError() != ERROR_ACCESS_DENIED &&
                GetLastError() != ERROR_LOCK_VIOLATION) {
                break;
            }
            Sleep(150);
        }
        /* ② 改名挪开兜底 */
        if (f == INVALID_HANDLE_VALUE) {
            WCHAR aside[PATH_MAX_W + 16];
            _snwprintf(aside, PATH_MAX_W + 15, L"%s.old-%lu", path,
                       (unsigned long)GetTickCount());
            aside[PATH_MAX_W + 15] = 0;
            if (MoveFileExW(path, aside, MOVEFILE_REPLACE_EXISTING)) {
                f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
                logmsg(L"       [信息] %s 被占用，已把旧文件挪到 %s 后重写",
                       path, aside);
            }
        }
    }
    if (f == INVALID_HANDLE_VALUE) {
        g_unzip_stage = 5; g_unzip_err = GetLastError();   /* 建文件失败 */
        free(out);
        return FALSE;
    }
    ok = WriteFile(f, out, rawsize, &w, NULL);
    if (!ok) { g_unzip_stage = 6; g_unzip_err = GetLastError(); }
    CloseHandle(f);
    free(out);

    if (bytes) *bytes = w;
    if (!ok || w != rawsize) {
        if (ok) { g_unzip_stage = 7; g_unzip_err = w; }   /* 写入字节数不符 */
        return FALSE;
    }
    g_unzip_stage = 0; g_unzip_err = 0;
    return TRUE;
}

/* --------------------------------------------------------------------------
 * 解析清单：`<ID>\t<相对路径>\t<字节数>` 每行一条，UTF-8。
 *   ★ 用**字段**解析（按 \t 切），不做子串匹配 —— 否则路径里含 '1' 之类
 *     的字符就会误判（铁律 94）。
 * ------------------------------------------------------------------------*/
static int parse_manifest(void)
{
    const void *p;
    DWORD sz;
    char *buf;
    int n = 0;

    g_nitems = 0;
    if (!res_ptr(RES_ID_MANIFEST, &p, &sz)) {
        logmsg(L"[错误] 找不到清单资源 (ID=%d)", RES_ID_MANIFEST);
        return 0;
    }
    buf = (char *)malloc(sz + 1);
    if (!buf) return 0;
    memcpy(buf, p, sz);
    buf[sz] = 0;

    {
        char *line = buf;
        while (line && *line && n < 128) {
            char *nl = strchr(line, '\n');
            char *id_s, *rel_s, *size_s;
            char *t1, *t2, *t3;

            if (nl) *nl = 0;
            /* 去掉行尾 \r */
            {
                size_t L = strlen(line);
                while (L > 0 && (line[L - 1] == '\r' || line[L - 1] == ' ')) line[--L] = 0;
            }
            if (*line == 0 || *line == '#') { line = nl ? nl + 1 : NULL; continue; }

            t1 = strchr(line, '\t');
            if (!t1) { line = nl ? nl + 1 : NULL; continue; }
            *t1 = 0;
            t2 = strchr(t1 + 1, '\t');
            if (!t2) { line = nl ? nl + 1 : NULL; continue; }
            *t2 = 0;
            t3 = strchr(t2 + 1, '\t');       /* 第 4 列（压缩后大小）可选 */
            if (t3) *t3 = 0;

            id_s   = line;
            rel_s  = t1 + 1;
            size_s = t2 + 1;

            g_items[n].id = atoi(id_s);
            utf8_to_wide(rel_s, -1, g_items[n].rel, PATH_MAX_W);
            g_items[n].size  = (DWORD)strtoul(size_s, NULL, 10);
            g_items[n].zsize = t3 ? (DWORD)strtoul(t3 + 1, NULL, 10) : g_items[n].size;
            if (g_items[n].id > 0 && g_items[n].rel[0]) n++;

            line = nl ? nl + 1 : NULL;
        }
    }
    free(buf);
    g_nitems = n;
    return n;
}

/* ==========================================================================
 *  进程
 * ========================================================================*/

/* 按映像名找进程。返回第一个匹配的 pid，0 = 没找到。 */
static DWORD find_process(const WCHAR *exename)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    DWORD found = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exename) == 0) { found = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* 等进程退出，最多 ms 毫秒 */
static BOOL wait_proc_gone(const WCHAR *exename, DWORD ms)
{
    DWORD t = 0;
    while (t < ms) {
        if (find_process(exename) == 0) return TRUE;
        Sleep(200);
        t += 200;
    }
    return find_process(exename) == 0;
}

/* --------------------------------------------------------------------------
 * 停掉正在运行的引擎
 *   为什么必须有这一步（铁律 43 / 76）：
 *     引擎跑着的时候，它自己的进程规则把 `\Windows\System32\` 当**片段**
 *     规则 -> System32 下每个程序都判 HIGH -> block 模式下**直接拒**。
 *     我们后面要调 sc.exe / reg.exe（都在 System32），会被自己的引擎拦掉。
 *   ★ 停引擎只能用**部署目录里**的 dskill.exe（直 syscall，绕开被 hook 的
 *     NtOpenProcess），**不能**用 taskkill（它在 System32，会被拒）。
 * ------------------------------------------------------------------------*/
static void stop_running_engine(void)
{
    DWORD pid;
    WCHAR dskill[PATH_MAX_W];
    WCHAR cmd[PATH_MAX_W + 64];

    pid = find_process(ENGINE_EXE);
    if (pid == 0) return;

    report(2, L"检测到引擎正在运行 (PID=%lu)，先停掉它…", (unsigned long)pid);
    logmsg(L"[信息] 引擎在运行 (PID=%lu) —— 必须先停掉，否则 System32 下的 "
           L"sc.exe/reg.exe 会被它自己的规则拦掉。", (unsigned long)pid);

    /* 优先用已安装目录里的 dskill.exe（唯一能绕开引擎进程钩子的办法） */
    path_join(dskill, PATH_MAX_W, g_dest, L"dskill.exe");
    if (GetFileAttributesW(dskill) != INVALID_FILE_ATTRIBUTES) {
        _snwprintf(cmd, PATH_MAX_W + 63, L"\"%s\" %lu", dskill, (unsigned long)pid);
        cmd[PATH_MAX_W + 63] = 0;
        run_cmd_hidden(cmd);
        if (wait_proc_gone(ENGINE_EXE, 4000)) {
            logmsg(L"       已用 dskill.exe 停掉引擎。");
            return;
        }
    }

    /* 兜底：直接 TerminateProcess（铁律 76：引擎跑着时工具链会被锁死，
       免注入的 TerminateProcess 是唯一出路）。 */
    {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (h) {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
    if (wait_proc_gone(ENGINE_EXE, 4000)) {
        logmsg(L"       已强制结束引擎。");
    } else {
        logmsg(L"       [警告] 引擎仍在运行 —— 后面的 sc/reg 调用可能被它拦掉。");
    }
}

/* ==========================================================================
 *  外部命令
 * ========================================================================*/

/* 跑一条命令行，等它结束，返回退出码（-1 = 起不来）。窗口隐藏。 */
static int run_cmd_hidden(const WCHAR *cmdline)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[4096];
    DWORD code = (DWORD)-1;

    wcsncpy(buf, cmdline, 4095);
    buf[4095] = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        logmsg(L"       [警告] 起不来：%s (err=%lu)", cmdline, GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

/* 跑一条命令行，把 stdout 收到 out（UTF-16 按 OEM 代码页解）。 */
static int run_cmd_capture(const WCHAR *cmdline, WCHAR *out, int outcap)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    WCHAR buf[4096];
    char raw[8192];
    DWORD got = 0, total = 0, code = (DWORD)-1;

    if (out && outcap > 0) out[0] = 0;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    wcsncpy(buf, cmdline, 4095);
    buf[4095] = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = NULL;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, buf, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return -1;
    }
    CloseHandle(wr);

    /* 必须边读边等：管道缓冲区满了子进程会卡住（经典死锁） */
    while (ReadFile(rd, raw + total, (DWORD)(sizeof(raw) - 1 - total), &got, NULL) && got > 0) {
        total += got;
        if (total >= sizeof(raw) - 1) break;
    }
    raw[total] = 0;
    WaitForSingleObject(pi.hProcess, 60000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(rd);

    if (out && outcap > 0) {
        /* sc.exe 的输出是 OEM 代码页 */
        MultiByteToWideChar(CP_OEMCP, 0, raw, -1, out, outcap - 1);
        out[outcap - 1] = 0;
    }
    return (int)code;
}

/* ==========================================================================
 *  内核驱动
 * ========================================================================*/

/*  返回：0=跳过  1=已注册但没加载  2=已加载
 *
 *  boot = TRUE  → `start= boot`（SERVICE_BOOT_START，开机优先）
 *  boot = FALSE → `start= auto`（SERVICE_AUTO_START，普通开机自启）
 *
 *  ★ 全程**不做签名预检**、**不因加载失败中止**，也**不在界面上提签名**。
 *    安装器只回答一个问题：**这个驱动服务有没有被加载**。
 *    加载不上的技术原因写在 driver\README.md 里，不属于安装界面该说的话。
 *    把签名做成硬门槛只会让整个安装包装不上，而装不上的损失远大于"驱动没起来"。
 *
 *  ★ 关于 boot / auto 的取舍（写在代码里，不写在界面上）：
 *    auto 由内核初始化阶段加载，已经**早于 SMSS / winlogon / 任何用户态进程**；
 *    用户态引擎本来就要等登录才起，所以 auto 已经拿到"早于所有用户态代码"的全部收益。
 *    boot 由引导加载器加载，更早一点，但**安全模式也会加载** —— DriverEntry 早期
 *    一崩，面对的是"进不去系统、连安全模式都进不去"。
 *    用户要"开机优先"，所以做成**可选**：勾了就用 boot，没勾就用 auto。 */
static int install_driver(BOOL boot)
{
    WCHAR sys32[PATH_MAX_W], drvdir[PATH_MAX_W], drvfile[PATH_MAX_W];
    WCHAR srcsys[PATH_MAX_W], sc[PATH_MAX_W];
    WCHAR cmd[2048], out[4096];
    const WCHAR *starttype;
    int rc;

    get_system32(sys32, PATH_MAX_W);
    _snwprintf(sc, PATH_MAX_W - 1, L"%s\\sc.exe", sys32);
    sc[PATH_MAX_W - 1] = 0;
    _snwprintf(drvdir, PATH_MAX_W - 1, L"%s\\drivers", sys32);
    drvdir[PATH_MAX_W - 1] = 0;
    _snwprintf(drvfile, PATH_MAX_W - 1, L"%s\\%s", drvdir, DRV_SYS_NAME);
    drvfile[PATH_MAX_W - 1] = 0;
    path_join(srcsys, PATH_MAX_W, g_ctx.dest, L"driver\\" DRV_SYS_NAME);

    if (GetFileAttributesW(srcsys) == INVALID_FILE_ATTRIBUTES) {
        logmsg(L"       [警告] payload 里没有 driver\\%s —— 跳过驱动。", DRV_SYS_NAME);
        /* ★ 把 driver 目录的**实际内容**列出来。只报"没找到"是不够的：
           文件名差一个字符（r3shieldcore_kernel.sys vs R3ShieldCoreKernel.sys）
           时，看日志的人根本猜不到差在哪 —— 诊断口径必须 >= 触发口径。 */
        {
            WCHAR pat[PATH_MAX_W];
            WIN32_FIND_DATAW fd;
            HANDLE fh;
            path_join(pat, PATH_MAX_W, g_ctx.dest, L"driver\\*");
            fh = FindFirstFileW(pat, &fd);
            if (fh != INVALID_HANDLE_VALUE) {
                do {
                    logmsg(L"              实际有：driver\\%s", fd.cFileName);
                } while (FindNextFileW(fh, &fd));
                FindClose(fh);
            } else {
                logmsg(L"              driver 目录不存在或为空。");
            }
        }
        return 0;
    }

    /* 1) 落地驱动文件 */
    ensure_dir(drvdir);
    if (!CopyFileW(srcsys, drvfile, FALSE)) {
        logmsg(L"       [警告] 复制驱动文件失败 (err=%lu) —— 跳过驱动安装。", GetLastError());
        return 0;
    }
    logmsg(L"       驱动文件 -> %s", drvfile);

    /* 2) 老服务先删掉，避免 sc create 报 1073（服务已存在） */
    _snwprintf(cmd, 2047, L"\"%s\" query \"%s\"", sc, DRV_SVC);
    if (run_cmd_capture(cmd, out, 4096) == 0) {
        _snwprintf(cmd, 2047, L"\"%s\" stop \"%s\"", sc, DRV_SVC);
        run_cmd_hidden(cmd);
        Sleep(1200);
        _snwprintf(cmd, 2047, L"\"%s\" delete \"%s\"", sc, DRV_SVC);
        run_cmd_hidden(cmd);
        logmsg(L"       已清理旧服务。");
    }

    /* 3) 注册服务
       ★ sc 的参数解析怪癖：`binPath=` 后面**必须**跟一个空格再跟值，
         写成 `binPath=xxx` 会报 "参数错误"。下面的写法里 `= ` 就是对的。 */
    starttype = boot ? L"boot" : L"auto";
    _snwprintf(cmd, 2047,
               L"\"%s\" create \"%s\" binPath= \"System32\\drivers\\%s\" "
               L"type= kernel start= %s DisplayName= \"%s Kernel Component\"",
               sc, DRV_SVC, DRV_SYS_NAME, starttype, APP_NAME);
    cmd[2047] = 0;
    rc = run_cmd_capture(cmd, out, 4096);
    if (rc != 0) {
        logmsg(L"       [警告] sc create 失败 (rc=%d) —— 驱动服务没建起来。", rc);
        return 0;
    }
    logmsg(L"       驱动服务 %s 已注册（启动类型 = %s）。", DRV_SVC, starttype);

    /* 4) 启动（并**回读**实际启动类型 —— 只信 sc 的回话，不信我们自己传的参数）
       ★ 铁律 94：断言要落在**字段**上。`sc create` 返回 0 只说明命令被接受，
         不说明 start 值真的落成了我们想要的那个；`sc qc` 回读一次才算数。 */
    _snwprintf(cmd, 2047, L"\"%s\" qc \"%s\"", sc, DRV_SVC);
    if (run_cmd_capture(cmd, out, 4096) == 0) {
        WCHAR want[32];
        _snwprintf(want, 31, L"%s", boot ? L"BOOT_START" : L"AUTO_START");
        want[31] = 0;
        if (wcsstr(out, want)) {
            logmsg(L"       回读确认：START_TYPE = %s", want);
        } else {
            logmsg(L"       [警告] 回读到的 START_TYPE 不是 %s —— "
                   L"sc create 接受了参数但值没落成。", want);
        }
    }

    _snwprintf(cmd, 2047, L"\"%s\" start \"%s\"", sc, DRV_SVC);
    rc = run_cmd_capture(cmd, out, 4096);
    if (rc != 0) {
        /* ★ 只报"加载没成功"这个事实，不解释技术原因（用户明确要求）。 */
        logmsg(L"       驱动加载：**未成功**（服务已注册，本次未加载）。");
        logmsg(L"              这不影响用户态引擎 —— 安装继续。");
        return 1;
    }
    logmsg(L"       驱动加载：成功。");
    return 2;
}

/* ==========================================================================
 *  开机自启（用户态引擎）
 * ========================================================================*/

/*  返回：0=失败  1=已注册  2=跳过
 *
 *  ★ 为什么是**服务**，不是 Run 键、也不是计划任务：
 *    · Run 键：payload 里的引擎清单是 `requireAdministrator`。写进
 *      `HKLM\...\CurrentVersion\Run` 的话，登录时系统拿**普通用户令牌**去启动它
 *      -> 每次开机都弹一个 UAC 框，用户不点它就不起来（等于没自启）。
 *    · 计划任务 `/sc onlogon /rl highest`：能避开 UAC，但**只在登录后**才触发 ——
 *      开机到登录这段窗口没有任何防护，而且任务计划程序里用户随手能禁用/删除。
 *    · 服务：由 SCM 管，开机即起、以 LocalSystem 跑、不依赖任何用户登录。
 *      服务进程自己不画界面，它只负责"把引擎拉进交互会话"
 *      （service/r3shieldcore_svc.c：WTSQueryUserToken + CreateProcessAsUserW）。
 *
 *  ★ 为什么用服务 API 而不是 `sc create`：
 *    服务二进制路径含空格（`<安装目录>\r3shieldcore_svc.exe`），
 *    `sc create binPath= "\"...\""` 要穿过 cmd.exe 一层解析 —— 少一个转义
 *    就会静默注册成一条错路径，而服务照样能建、状态照样 RUNNING。
 *    直接用 CreateServiceW + QueryServiceConfigW 回读，能把这条路径**断言**出来。
 *
 *  ★ 安全模式：服务在安全模式下**不会被 SCM 自动启动**（安全模式只加载白名单服务），
 *    而且服务自己还有一道 IsSafeMode 闸门。两道，见 service/r3shieldcore_svc.c。 */
static int install_autostart(void)
{
    WCHAR sys32[PATH_MAX_W], sch[PATH_MAX_W];
    WCHAR svcexe[PATH_MAX_W], binpath[PATH_MAX_W + 8];
    WCHAR cmd[2048], out[1024];
    SC_HANDLE scm = NULL, svc = NULL;
    DWORD err = 0;
    int started = 0;

    /* ---- 顺手清掉旧版本留下的计划任务 ----
     *   ★ 不清的话，老版本升上来的机器上会同时有"任务 + 服务"两条自启链，
     *     可能拉出**两份引擎**（引擎没有单实例保护）。
     *   ★ schtasks /delete 对**不存在**的任务也返回 0（铁律 94），
     *     所以删完必须再 query 一次才能说"已清理"。 */
    get_system32(sys32, PATH_MAX_W);
    _snwprintf(sch, PATH_MAX_W - 1, L"%s\\schtasks.exe", sys32);
    sch[PATH_MAX_W - 1] = 0;

    _snwprintf(cmd, 2047, L"\"%s\" /delete /tn \"%s\" /f", sch, LEGACY_TASK);
    cmd[2047] = 0;
    run_cmd_hidden(cmd);

    _snwprintf(cmd, 2047, L"\"%s\" /query /tn \"%s\"", sch, LEGACY_TASK);
    cmd[2047] = 0;
    if (run_cmd_capture(cmd, out, 1024) == 0) {
        logmsg(L"       [警告] 旧版计划任务 \"%s\" 没删掉 —— 它可能和本服务同时自启。",
               LEGACY_TASK);
    } else {
        logmsg(L"       已确认没有遗留的计划任务。");
    }

    /* ---- 服务二进制必须已经解压出来了 ---- */
    path_join(svcexe, PATH_MAX_W, g_ctx.dest, SVC_EXE_NAME);
    if (GetFileAttributesW(svcexe) == INVALID_FILE_ATTRIBUTES) {
        logmsg(L"       [警告] 找不到 %s —— 无法注册开机启动服务（引擎不会自动启动）。",
               SVC_EXE_NAME);
        return 0;
    }

    /* ★ 路径带空格 -> 必须**整条加引号**。不加引号时 SCM 会把路径拆成
     *   可执行文件 + 参数两截，服务能建、能 RUNNING，但开机什么都不发生。 */
    _snwprintf(binpath, PATH_MAX_W + 7, L"\"%s\"", svcexe);
    binpath[PATH_MAX_W + 7] = 0;

    /* ---- 建服务；已存在就改配置（覆盖安装）---- */
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        logmsg(L"       [警告] OpenSCManager 失败 err=%lu —— 无法注册开机启动服务。",
               GetLastError());
        return 0;
    }

    svc = CreateServiceW(scm, SVC_NAME, SVC_DISPLAY,
                         SERVICE_ALL_ACCESS,
                         SERVICE_WIN32_OWN_PROCESS,
                         SERVICE_AUTO_START,
                         SERVICE_ERROR_NORMAL,
                         binpath,
                         NULL,      /* 不依赖别的服务 */
                         NULL,      /* 不设 load order group */
                         NULL,      /* 不设 tag */
                         NULL,      /* NULL = LocalSystem */
                         NULL);     /* 不设密码 */

    if (svc == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            svc = OpenServiceW(scm, SVC_NAME, SERVICE_ALL_ACCESS);
            if (svc == NULL) {
                logmsg(L"       [警告] 服务已存在但打开失败 err=%lu", GetLastError());
            } else if (!ChangeServiceConfigW(svc, SERVICE_NO_CHANGE,
                                             SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                                             binpath, NULL, NULL, NULL, NULL, NULL,
                                             SVC_DISPLAY)) {
                logmsg(L"       [警告] ChangeServiceConfig 失败 err=%lu", GetLastError());
            }
        } else {
            logmsg(L"       [警告] CreateService 失败 err=%lu —— 引擎不会自动启动。",
                   err);
        }
    }

    if (svc == NULL) {
        CloseServiceHandle(scm);
        return 0;
    }

    /* ---- 回读配置：只信"API 返回成功"是不够的（铁律 94/119）---- */
    {
        QUERY_SERVICE_CONFIGW* qc = NULL;
        DWORD need = 0;
        BOOL ok = FALSE;

        QueryServiceConfigW(svc, NULL, 0, &need);
        if (need > 0) {
            qc = (QUERY_SERVICE_CONFIGW*)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, need);
        }
        if (qc != NULL && QueryServiceConfigW(svc, qc, need, &need)) {
            ok = TRUE;
            logmsg(L"       回读 binPath = %s", qc->lpBinaryPathName);
            logmsg(L"       回读 start   = %s",
                   qc->dwStartType == SERVICE_BOOT_START ? L"boot" :
                   qc->dwStartType == SERVICE_AUTO_START ? L"auto" :
                   qc->dwStartType == SERVICE_DEMAND_START ? L"demand" : L"其他");
            /* ★ 断言 binPath 里真的是我们的服务 exe：写错路径时服务照样建得起来、
               状态照样 RUNNING，只是开机什么都不发生（假成功）。 */
            if (wcsstr(qc->lpBinaryPathName, SVC_EXE_NAME) == NULL) {
                logmsg(L"       [警告] 回读到的 binPath 里没有 %s —— 服务指向了别的东西！",
                       SVC_EXE_NAME);
                ok = FALSE;
            }
        }
        if (qc != NULL) {
            LocalFree(qc);
        }
        if (!ok) {
            logmsg(L"       [警告] 回读服务配置失败 err=%lu", GetLastError());
        }
    }

    /* ---- 立刻启动一次（不用等重启就能验证）---- */
    if (StartServiceW(svc, 0, NULL)) {
        started = 1;
    } else {
        err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            started = 1;
        } else {
            logmsg(L"       [警告] 启动服务失败 err=%lu（已注册，重启后仍会自启）", err);
        }
    }

    /* ---- 回读运行状态 ---- */
    {
        SERVICE_STATUS_PROCESS ssp;
        DWORD need = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                 (LPBYTE)&ssp, sizeof(ssp), &need)) {
            logmsg(L"       回读状态 = %s",
                   ssp.dwCurrentState == SERVICE_RUNNING ? L"RUNNING" :
                   ssp.dwCurrentState == SERVICE_START_PENDING ? L"START_PENDING" :
                   ssp.dwCurrentState == SERVICE_STOPPED ? L"STOPPED" : L"其他");
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!started) {
        return 0;
    }

    logmsg(L"       开机自启已注册：服务 \"%s\"（开机即以 SYSTEM 启动，"
           L"再由它把引擎拉进交互会话）", SVC_NAME);
    return 1;
}

/* --------------------------------------------------------------------------
 * 停掉上一次装的开机启动服务
 *
 * ★ 为什么必须在**解压之前**做：
 *   服务的 exe 就躺在安装目录里。服务还跑着的时候覆盖写
 *   `r3shieldcore_svc.exe` 会失败（文件被占用），而解压失败只会报
 *   "写出的字节数不对"，看着像 payload 坏了（铁律 97：动作失败要分型）。
 * ★ 顺序：先停引擎（dskill，见 stop_running_engine），再动服务 ——
 *   本函数走服务 API 不经 System32，但引擎跑着时 System32 下的东西会被
 *   它自己的片段规则拦掉（铁律 43），所以调用点在 stop_running_engine() 之后。
 * ★ 本服务"每个会话只拉一次"，所以引擎被杀掉后它**不会**把引擎拉回来。
 * ------------------------------------------------------------------------*/
static void stop_existing_service(void)
{
    SC_HANDLE scm = NULL;
    SC_HANDLE svc = NULL;
    SERVICE_STATUS st;
    int i;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm == NULL) {
        return;
    }

    svc = OpenServiceW(scm, SVC_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (svc == NULL) {
        /* 没有旧服务 —— 首次安装的正常情形 */
        CloseServiceHandle(scm);
        return;
    }

    report(2, L"检测到旧的开机启动服务，先停掉它…");
    logmsg(L"[信息] 旧服务 %s 在 —— 先停掉，否则它的 exe 被占用，解压会失败。",
           SVC_NAME);

    if (ControlService(svc, SERVICE_CONTROL_STOP, &st)) {
        for (i = 0; i < 25; i++) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD need = 0;
            if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                      (LPBYTE)&ssp, sizeof(ssp), &need)) {
                break;
            }
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
            Sleep(200);
        }
        logmsg(L"       旧服务已停。");
    } else {
        logmsg(L"       [警告] 停旧服务失败 err=%lu（服务没在跑时这是正常的）",
               GetLastError());
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    /* ★★ 关键补充：**服务停了 ≠ 它拉起的引擎停了**。
     *
     *   旧服务在跑的时候已经把引擎拉进了交互会话；`SERVICE_STOPPED` 只是
     *   SCM 看到"服务进程退出了"，那个**引擎是独立进程**，可能还在跑。
     *   而引擎会把 `64\r3shieldcore-lib.dll` 加载进自己 ⇒ 下面解压覆盖这个
     *   DLL 就报 **err=32 ERROR_SHARING_VIOLATION**（实测：第二次安装必踩）。
     *
     *   更糟的是：旧服务每 30s（RETRY_MS）兜底一次会**把引擎重新拉起来** ——
     *   所以在"停服务"和"解压"之间，引擎随时可能复活再锁住文件。
     *
     *   因此这里必须**亲手把引擎杀掉并确认它真的没了**，不能指望它自己退。
     *   用 dskill.exe（唯一能绕开引擎自己进程钩子的办法，铁律 76）；
     *   拿不到 dskill 就回退 TerminateProcess。
     */
    {
        DWORD pid = find_process(ENGINE_EXE);
        if (pid != 0) {
            WCHAR dskill[PATH_MAX_W];
            WCHAR cmd[PATH_MAX_W + 64];
            logmsg(L"[信息] 旧服务停了，但它拉起的引擎还在 (PID=%lu) —— 先停掉，"
                   L"否则安装目录里的 lib dll 被占用，解压会报 err=32。",
                   (unsigned long)pid);
            path_join(dskill, PATH_MAX_W, g_dest, L"dskill.exe");
            if (GetFileAttributesW(dskill) != INVALID_FILE_ATTRIBUTES) {
                _snwprintf(cmd, PATH_MAX_W + 63, L"\"%s\" %lu", dskill,
                           (unsigned long)pid);
                cmd[PATH_MAX_W + 63] = 0;
                run_cmd_hidden(cmd);
            }
            if (!wait_proc_gone(ENGINE_EXE, 4000)) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                if (h != NULL) {
                    TerminateProcess(h, 1);
                    CloseHandle(h);
                }
                wait_proc_gone(ENGINE_EXE, 4000);
            }
            /* ★ 再确认一次：还活着就明确说出来（别假装干净）。 */
            if (find_process(ENGINE_EXE) != 0) {
                logmsg(L"       [警告] 引擎仍在运行 —— 解压可能因文件占用失败");
            } else {
                logmsg(L"       引擎已停（服务不会再把它拉回来，因为服务已停）。");
            }
        }
    }
}

/* ==========================================================================
 *  快捷方式
 * ========================================================================*/

/* CLSID_ShellLink / IID_IShellLinkW —— 手写出来，免得依赖 libuuid 的链接行为 */
static const GUID k_CLSID_ShellLink =
    { 0x00021401, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static const GUID k_IID_IShellLinkW =
    { 0x000214F9, 0x0000, 0x0000, { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static BOOL create_shortcut(const WCHAR *lnk, const WCHAR *target,
                            const WCHAR *workdir, const WCHAR *desc)
{
    IShellLinkW   *psl = NULL;
    IPersistFile  *ppf = NULL;
    HRESULT        hr;
    BOOL           ok = FALSE;

    hr = CoCreateInstance(&k_CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          &k_IID_IShellLinkW, (void **)&psl);
    if (FAILED(hr) || !psl) return FALSE;

    psl->lpVtbl->SetPath(psl, target);
    psl->lpVtbl->SetWorkingDirectory(psl, workdir);
    psl->lpVtbl->SetDescription(psl, desc);
    psl->lpVtbl->SetIconLocation(psl, target, 0);

    hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (void **)&ppf);
    if (SUCCEEDED(hr) && ppf) {
        hr = ppf->lpVtbl->Save(ppf, lnk, TRUE);
        ok = SUCCEEDED(hr);
        ppf->lpVtbl->Release(ppf);
    }
    psl->lpVtbl->Release(psl);
    return ok;
}

/* 建开始菜单 + 公共桌面快捷方式 */
static void create_shortcuts(void)
{
    WCHAR dir[PATH_MAX_W], lnk[PATH_MAX_W], target[PATH_MAX_W];
    int n_ok = 0;

    path_join(target, PATH_MAX_W, g_ctx.dest, ENGINE_EXE);

    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_PROGRAMS, NULL, 0, dir))) {
        path_join(lnk, PATH_MAX_W, dir, APP_NAME L".lnk");
        if (create_shortcut(lnk, target, g_ctx.dest, APP_NAME L" 引擎")) n_ok++;
        else logmsg(L"       [警告] 开始菜单快捷方式创建失败。");
    }
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, dir))) {
        path_join(lnk, PATH_MAX_W, dir, APP_NAME L".lnk");
        if (create_shortcut(lnk, target, g_ctx.dest, APP_NAME L" 引擎")) n_ok++;
        else logmsg(L"       [警告] 桌面快捷方式创建失败。");
    }
    logmsg(L"       快捷方式 %d/2", n_ok);
}

/* ==========================================================================
 *  卸载注册项（控制面板 - 程序和功能）
 * ========================================================================*/

static BOOL write_uninstall_info(void)
{
    HKEY  k = NULL;
    DWORD disp = 0;
    WCHAR uninst[PATH_MAX_W + 4];
    DWORD one = 1;
    BOOL  ok = FALSE;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, UNINSTALL_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &k, &disp) != ERROR_SUCCESS) {
        return FALSE;
    }

    {
        /* 字符串值 —— 长度按字节算（含结尾 0） */
        struct { const WCHAR *name; const WCHAR *val; } sv[] = {
            { L"DisplayName",     APP_NAME },
            { L"DisplayVersion",  APP_VERSION },
            { L"Publisher",       APP_PUBLISHER },
            { L"InstallLocation", g_ctx.dest },
        };
        for (int i = 0; i < 4; i++) {
            DWORD cb = (DWORD)((wcslen(sv[i].val) + 1) * sizeof(WCHAR));
            RegSetValueExW(k, sv[i].name, 0, REG_SZ, (const BYTE *)sv[i].val, cb);
        }
    }

    /* ★ UninstallString 必须指向一个**真的存在**的文件。
       踩过（铁律 121）：老版 install.bat 从解压目录取 uninstall.bat，
       而那个文件根本不在 payload 里 -> copy 静默失败 -> 控制面板点卸载没反应。
       这里我们**自己把 uninstall.bat 写进安装目录**，所以一定能对上；
       写完还要断言它在。 */
    _snwprintf(uninst, PATH_MAX_W + 3, L"\"%s\\uninstall.bat\"", g_ctx.dest);
    uninst[PATH_MAX_W + 3] = 0;
    RegSetValueExW(k, L"UninstallString", 0, REG_SZ,
                   (const BYTE *)uninst, (DWORD)((wcslen(uninst) + 1) * sizeof(WCHAR)));

    RegSetValueExW(k, L"NoModify", 0, REG_DWORD, (const BYTE *)&one, sizeof(one));
    RegSetValueExW(k, L"NoRepair", 0, REG_DWORD, (const BYTE *)&one, sizeof(one));

    RegCloseKey(k);
    ok = TRUE;
    logmsg(L"       卸载项已写入 HKLM\\...\\Uninstall\\R3ShieldCore");
    return ok;
}

/* ==========================================================================
 *  安装主流程（跑在工作线程里）
 * ========================================================================*/

static void set_err(const WCHAR *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf(g_ctx.errmsg, 1023, fmt, ap);
    va_end(ap);
    g_ctx.errmsg[1023] = 0;
}

/* ======================================================================
 * ★ v66：配置文件目录 = `%ProgramData%\R3 Shield Core`
 * ======================================================================
 *
 * 为什么必须单独一个目录（而不是就用安装目录）：
 *   安装目录在 `C:\Program Files\` 下，它的标准 ACL 是 `BUILTIN\Users:(I)(RX)`
 *   （只读 + 执行）。安装程序**刻意不给安装目录开任何写权限** ——
 *   给杀软本体开用户写权限 = 让用户态恶意程序能替换 exe / dll / 驱动，
 *   等于自废防护。
 *   代价：普通用户改 `Program Files\R3 Shield Core\r3shieldcore.ini`
 *   **存不进去**（err=5）。而且这个错误和"文件被设成只读"报的是**同一句**
 *   "拒绝访问"，光看提示分不出来。
 *
 * 解法：把**配置文件**放到 ProgramData 下的独立目录，安装时**只对该目录**
 *   授 `Users:(OI)(CI)M`。于是用户能直接改配置，而程序本体仍只有管理员能写。
 *
 * 回退：拿不到 ProgramData / 建目录失败 ⇒ 只记一条警告，**不影响安装**；
 *   引擎会自动回退到 exe 同目录找 ini（见 r3shieldcore_config.cpp 的
 *   ResolveConfigPath）。
 * ====================================================================== */

/* 拼出配置目录路径；拿不到 %ProgramData% 时 out 置空串。 */
static void config_dir(WCHAR *out, int cap)
{
    WCHAR pd[PATH_MAX_W] = {0};
    const DWORD n = GetEnvironmentVariableW(L"ProgramData", pd, PATH_MAX_W);

    if (out && cap > 0) {
        out[0] = 0;
    }
    if (n == 0 || n >= (DWORD)PATH_MAX_W) {
        return;
    }
    path_join(out, cap, pd, L"R3 Shield Core");
}

/* 建配置目录 + **只对它**授 Users:(OI)(CI)M。返回 TRUE = 目录可用。 */
static BOOL prepare_config_dir(void)
{
    WCHAR dir[PATH_MAX_W];
    WCHAR cmd[2048];
    int rc;

    config_dir(dir, PATH_MAX_W);
    if (dir[0] == 0) {
        logmsg(L"       [警告] 读不到 %%ProgramData%% —— 配置留在安装目录里。");
        return FALSE;
    }

    if (!ensure_dir(dir)) {
        logmsg(L"       [警告] 无法创建配置目录 %s（err=%lu）—— 配置留在安装目录里。",
               dir, GetLastError());
        return FALSE;
    }

    /* ★ 用 **SID** `*S-1-5-32-545`（BUILTIN\Users）而不是名字 "Users"：
     *   系统语言不是中文/英文时本地化名字会变（铁律 40/133）。
     * ★ (OI)(CI) = 容器 + 对象都继承 ⇒ 之后复制进去的 ini 自动带上这条 ACE，
     *   所以复制**必须**排在本函数之后。
     * ★ 只授这个目录 —— 绝不碰 Program Files 下的安装目录。 */
    _snwprintf(cmd, 2047,
               L"icacls \"%s\" /grant *S-1-5-32-545:(OI)(CI)M /T /C /Q", dir);
    cmd[2047] = 0;
    rc = run_cmd_hidden(cmd);

    logmsg(L"       配置目录 -> %s（只对它授 Users:(OI)(CI)M，icacls rc=%d）", dir, rc);
    return TRUE;
}

/* 把随包的 r3shieldcore.ini 铺到配置目录。
 *   ★ 只在**目标不存在**时复制 —— 升级安装**不能**覆盖用户改过的配置
 *     （否则用户每升一次版就丢一次设置）。 */
static void seed_config_ini(void)
{
    WCHAR dir[PATH_MAX_W], src[PATH_MAX_W], dst[PATH_MAX_W];

    config_dir(dir, PATH_MAX_W);
    if (dir[0] == 0 || GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    path_join(dst, PATH_MAX_W, dir, L"r3shieldcore.ini");
    if (GetFileAttributesW(dst) != INVALID_FILE_ATTRIBUTES) {
        logmsg(L"       配置已存在，保留用户改动 -> %s", dst);
        return;
    }

    path_join(src, PATH_MAX_W, g_ctx.dest, L"r3shieldcore.ini");
    if (CopyFileW(src, dst, TRUE)) {
        logmsg(L"       配置 -> %s", dst);
    } else {
        logmsg(L"       [警告] 配置复制失败（err=%lu）—— 引擎将用安装目录里那份。",
               GetLastError());
    }
}

/* 返回 0 = 成功 */
static int do_install(void)
{
    int   i;
    WCHAR dst[PATH_MAX_W];
    WCHAR sub[PATH_MAX_W];
    DWORD wrote = 0;
    DWORD uninst_sz = 0;

    g_ctx.err = 0;
    g_ctx.errmsg[0] = 0;
    g_ctx.n_files = 0;
    g_ctx.total_bytes = 0;
    g_ctx.drv_state = 3;
    g_ctx.auto_state = 0;

    /* ---------------- [1/7] 建目录 ---------------- */
    report(5, L"[1/7] 创建安装目录…");
    if (!ensure_dir(g_ctx.dest)) {
        set_err(L"无法创建安装目录：%s（err=%lu）", g_ctx.dest, GetLastError());
        g_ctx.err = 1;
        return 1;
    }
    path_join(sub, PATH_MAX_W, g_ctx.dest, L"64"); ensure_dir(sub);
    path_join(sub, PATH_MAX_W, g_ctx.dest, L"32"); ensure_dir(sub);
    path_join(sub, PATH_MAX_W, g_ctx.dest, L"driver"); ensure_dir(sub);
    logmsg(L"[1/7] 安装目录 %s", g_ctx.dest);

    /* ★ v66：配置目录（%ProgramData%\R3 Shield Core）—— 建目录 + 只对它授
     *   Users:(OI)(CI)M。放在这里（而不是复制 ini 那一步）是因为 ACE 必须
     *   **先**落在目录上，之后复制进去的 ini 才会**继承**它。
     *   失败不致命：引擎会自动回退到安装目录里的 ini。 */
    prepare_config_dir();

    /*  ★ 停掉正在运行的引擎。
     *    ★★ 顺序（v65d 修正，实测踩过）：必须先停**服务**，再停引擎！
     *       上一版是先 stop_running_engine() 再 stop_existing_service()，
     *       结果是：引擎刚被杀掉，**旧服务**（还活着）下一个 30s 兜底 tick
     *       又把引擎拉起来 ⇒ 引擎重新锁住 64\r3shieldcore-lib.dll ⇒
     *       解压报 err=32（ERROR_SHARING_VIOLATION）。实测：第二次安装必失败。
     *       现在改成"先停服务（含它拉起的引擎），再兜一次停引擎"，
     *       服务已经不在 ⇒ 没人再把引擎拉回来。
     *   位置仍在这里（解压之前）：升级安装时 DEST 里已有 dskill.exe 可用；
     *   而后面要调 System32 下的 sc.exe —— 引擎还在跑的话那步会被引擎
     *   **自己的**规则拦掉（铁律 43）。 */
    stop_existing_service();

    /* 再兜一次：停掉任何还活着的引擎（含上面停服务时新拉起来的）。 */
    stop_running_engine();

    /* ---------------- [2/6] 解内嵌文件 ---------------- */
    /*   ★ 边解边断言"写出的字节数 == 清单里声明的字节数"。
     *     只断言"函数返回成功"是不够的：资源编漏了 / .rc 指错文件时，
     *     我们会写出一个 0 字节或截断的文件，而安装过程看起来一切正常。 */
    report(8, L"[2/7] 展开安装文件（%d 个）…", g_nitems);
    if (g_nitems <= 0) {
        set_err(L"内嵌资源清单是空的 —— 这个安装包是坏的。");
        g_ctx.err = 1;
        return 1;
    }
    for (i = 0; i < g_nitems; i++) {
        WCHAR rel[PATH_MAX_W];
        int pct;

        wcsncpy(rel, g_items[i].rel, PATH_MAX_W - 1);
        rel[PATH_MAX_W - 1] = 0;
        rel_to_win(rel);
        path_join(dst, PATH_MAX_W, g_ctx.dest, rel);

        wrote = 0;
        if (!res_unzip_to_file(g_items[i].id, dst,
                               g_items[i].size, g_items[i].zsize, &wrote)) {
            /* ★ 分型报错（铁律 97/98）：stage 说明卡在哪一步，
             *   err 是那一步的真实 Win32 错误码。缺了这两个，
             *   "解压/写出失败" 就等于没说。 */
            set_err(L"解压/写出失败：%s（资源 ID=%d，阶段=%d，err=%lu）",
                    rel, g_items[i].id, g_unzip_stage,
                    (unsigned long)g_unzip_err);
            g_ctx.err = 1;
            return 1;
        }
        if (wrote != g_items[i].size) {
            set_err(L"字节数不符：%s 期望 %lu 实得 %lu", rel,
                    (unsigned long)g_items[i].size, (unsigned long)wrote);
            g_ctx.err = 1;
            return 1;
        }
        g_ctx.n_files++;
        g_ctx.total_bytes += wrote;

        pct = 8 + (int)((long)(i + 1) * 45 / g_nitems);
        report(pct, L"       %s  (%lu 字节)", rel, (unsigned long)wrote);
    }
    logmsg(L"[2/7] 已展开 %d 个文件，共 %lu 字节",
           g_ctx.n_files, (unsigned long)g_ctx.total_bytes);

    /* 卸载脚本：**我们负责写进安装目录**（老版正是漏了这一步） */
    {
        WCHAR up[PATH_MAX_W];
        path_join(up, PATH_MAX_W, g_ctx.dest, L"uninstall.bat");
        uninst_sz = 0;
        if (res_to_file(RES_ID_UNINSTALL, up, &uninst_sz)) {
            logmsg(L"       卸载脚本 -> %s (%lu 字节)", up, (unsigned long)uninst_sz);
        } else {
            logmsg(L"       [警告] 卸载脚本写不出去 —— 控制面板卸载项会失效。");
        }
    }

    /* 引擎主程序必须真的在（否则这个"安装"毫无意义） */
    {
        WCHAR eng[PATH_MAX_W];
        path_join(eng, PATH_MAX_W, g_ctx.dest, ENGINE_EXE);
        if (GetFileAttributesW(eng) == INVALID_FILE_ATTRIBUTES) {
            set_err(L"安装目录里没有 %s —— payload 结构不对。", ENGINE_EXE);
            g_ctx.err = 1;
            return 1;
        }
    }

    /* ★ v66：把随包的 r3shieldcore.ini 铺到配置目录（已存在则保留用户改动）。
     *   放在 payload 展开**之后** —— 源文件 `dest\r3shieldcore.ini` 这时才存在。 */
    seed_config_ini();

    /* ---------------- [3/7] 内核驱动 ---------------- */
    if (!g_ctx.install_driver) {
        report(56, L"[3/7] 内核驱动：已按要求跳过");
        logmsg(L"[3/7] 内核驱动：跳过（未勾选）");
        g_ctx.drv_state = 3;
    } else {
        report(56, L"[3/7] 内核驱动 %s（启动类型 %s）…",
               DRV_SVC, g_ctx.drv_boot ? L"boot" : L"auto");
        logmsg(L"[3/7] 内核驱动 %s（启动类型 = %s）",
               DRV_SVC, g_ctx.drv_boot ? L"boot（开机优先）" : L"auto（普通开机自启）");
        g_ctx.drv_state = install_driver(g_ctx.drv_boot);
    }

    /* ---------------- [4/7] 开机自启 ---------------- */
    if (!g_ctx.autostart) {
        report(72, L"[4/7] 开机自启：已按要求跳过");
        logmsg(L"[4/7] 开机自启：跳过（未勾选）");
        g_ctx.auto_state = 2;
    } else {
        report(72, L"[4/7] 注册开机启动服务…");
        logmsg(L"[4/7] 注册开机启动服务（服务 %s）", SVC_NAME);
        g_ctx.auto_state = install_autostart();
    }

    /* ---------------- [5/7] 快捷方式 ---------------- */
    report(82, L"[5/7] 创建快捷方式…");
    logmsg(L"[5/7] 创建快捷方式");
    create_shortcuts();

    /* ---------------- [6/7] 卸载注册项 ---------------- */
    report(90, L"[6/7] 写入卸载信息…");
    logmsg(L"[6/7] 写入卸载信息");
    if (!write_uninstall_info()) {
        logmsg(L"       [警告] 卸载注册项写入失败（不影响使用，但控制面板里看不到）。");
    }

    /* ---------------- [7/7] 收尾 ---------------- */
    report(96, L"[7/7] 收尾…");
    logmsg(L"[7/7] 收尾完成");

    report(100, L"安装完成。");
    return 0;
}

static DWORD WINAPI install_thread(LPVOID param)
{
    (void)param;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    do_install();
    CoUninitialize();
    if (g_hWnd) PostMessageW(g_hWnd, WM_APP_DONE, (WPARAM)g_ctx.err, 0);
    return 0;
}

/* ==========================================================================
 *  界面
 * ========================================================================*/

#define WND_W        660
#define WND_H        470
#define BANNER_H     74
#define MARGIN       20

#define BTN_W        96
#define BTN_H        30
#define BTN_Y        (WND_H - 46)

/* 许可文本 —— 用多行只读 EDIT 而不是 MessageBox：
   MessageBox 不能滚动，长文本会变成一坨（而且会被自动化脚本的
   "找 STATIC 子控件"逻辑误判）。 */
static const WCHAR *k_license =
    L"R3 ShieldCore 用户许可与免责声明\r\n"
    L"────────────────────────────────────────────\r\n"
    L"\r\n"
    L"1. 本软件是一个**用户态**安全监控引擎，通过 API Hook 与轮询观察\r\n"
    L"   进程、文件与注册表行为，并按配置进行拦截。\r\n"
    L"\r\n"
    L"2. 本软件**不保证**能拦住任何特定行为。用户态方案存在固有盲区：\r\n"
    L"   拦截的第四道门是**时间** —— 从进程启动到注入完成之间存在窗口，\r\n"
    L"   恶意程序可能在该窗口内完成破坏动作。\r\n"
    L"\r\n"
    L"3. 内核驱动为**可选**组件，该驱动已正式签名，可正常加载。\r\n"
    L"   是否加载该驱动不影响用户态引擎的功能。\r\n"
    L"\r\n"
    L"4. 本软件按“现状”提供，不附带任何明示或暗示的担保。\r\n"
    L"   因使用本软件造成的任何直接或间接损失，作者不承担责任。\r\n"
    L"\r\n"
    L"5. 请仅在你**拥有合法授权**的环境中部署与测试。\r\n"
    L"\r\n"
    L"勾选下方的“我接受许可协议”即可继续。\r\n";

/* 完成页的汇总文本（在 WM_APP_DONE 里动态填） */

static HFONT make_font(int pt, BOOL bold, const WCHAR *face)
{
    HDC hdc = GetDC(NULL);
    int h = -MulDiv(pt, GetDeviceCaps(hdc, LOGPIXELSY), 72);
    ReleaseDC(NULL, hdc);
    return CreateFontW(h, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

static HWND mk(HWND parent, const WCHAR *cls, const WCHAR *text, DWORD style,
               int x, int y, int w, int h, int id, HFONT font)
{
    HWND c = CreateWindowExW(0, cls, text, WS_CHILD | style,
                             x, y, w, h, parent, (HMENU)(INT_PTR)id, g_hInst, NULL);
    if (c && font) SendMessageW(c, WM_SETFONT, (WPARAM)font, TRUE);
    return c;
}

/* 按页面显示/隐藏控件 */
static void show(int id, BOOL visible)
{
    HWND c = GetDlgItem(g_hWnd, id);
    if (c) ShowWindow(c, visible ? SW_SHOW : SW_HIDE);
}

static void set_text(int id, const WCHAR *t)
{
    HWND c = GetDlgItem(g_hWnd, id);
    if (c) SetWindowTextW(c, t);
}

/*  父勾选联动子勾选：不装驱动时，"开机优先启动内核驱动"没有意义，
 *  置灰（而不是藏起来 —— 藏起来用户会以为这个功能不存在）。
 *  ★ 同时把它的**值**也同步到全局：置灰的复选框在 WM_COMMAND 里不会再来
 *    通知，靠读取时现查 IsDlgButtonChecked 才拿得到正确值。 */
static void sync_drv_sub(void)
{
    BOOL on = (IsDlgButtonChecked(g_hWnd, IDC_CHKDRV) == BST_CHECKED);
    EnableWindow(GetDlgItem(g_hWnd, IDC_CHKDRVBOOT), on);
}

static void apply_page(int page)
{
    HWND bBack = GetDlgItem(g_hWnd, ID_BTN_BACK);
    HWND bNext = GetDlgItem(g_hWnd, ID_BTN_NEXT);
    HWND bCanc = GetDlgItem(g_hWnd, ID_BTN_CANCEL);
    HWND bFin  = GetDlgItem(g_hWnd, ID_BTN_FINISH);

    /* 先全部藏掉，再按页面显示 —— 比逐页手工"关掉上一页"可靠 */
    show(IDC_LICENSE, FALSE); show(IDC_AGREE, FALSE);   show(IDC_HINT, FALSE);
    show(IDC_PATH, FALSE);    show(IDC_BROWSE, FALSE);  show(IDC_CHKDRV, FALSE);
    show(IDC_CHKDRVBOOT, FALSE); show(IDC_CHKAUTO, FALSE);
    show(IDC_STEP, FALSE);    show(IDC_PROGRESS, FALSE);show(IDC_LOG, FALSE);
    show(IDC_SUMMARY, FALSE);
    ShowWindow(bBack, SW_HIDE); ShowWindow(bNext, SW_HIDE);
    ShowWindow(bCanc, SW_HIDE); ShowWindow(bFin, SW_HIDE);

    g_page = page;
    switch (page) {
    case PAGE_WELCOME:
        set_text(IDC_HDR_SUB, L"欢迎使用。请阅读下面的许可协议。");
        set_text(IDC_HINT, L"请阅读许可协议：");
        show(IDC_HINT, TRUE); show(IDC_LICENSE, TRUE); show(IDC_AGREE, TRUE);
        ShowWindow(bNext, SW_SHOW);
        SetWindowTextW(bNext, L"下一步");
        EnableWindow(bNext, g_agreed);
        ShowWindow(bCanc, SW_SHOW);
        break;

    case PAGE_OPTIONS:
        set_text(IDC_HDR_SUB, L"选择安装位置与组件。");
        set_text(IDC_HINT, L"安装位置：");
        show(IDC_HINT, TRUE); show(IDC_PATH, TRUE); show(IDC_BROWSE, TRUE);
        show(IDC_CHKDRV, TRUE); show(IDC_CHKDRVBOOT, TRUE); show(IDC_CHKAUTO, TRUE);
        sync_drv_sub();       /* 子选项跟着父勾选联动（见下） */
        ShowWindow(bBack, SW_SHOW); SetWindowTextW(bBack, L"上一步");
        ShowWindow(bNext, SW_SHOW); SetWindowTextW(bNext, L"安装");
        EnableWindow(bNext, TRUE);
        ShowWindow(bCanc, SW_SHOW);
        break;

    case PAGE_PROGRESS:
        set_text(IDC_HDR_SUB, L"正在安装，请稍候…");
        show(IDC_STEP, TRUE); show(IDC_PROGRESS, TRUE); show(IDC_LOG, TRUE);
        ShowWindow(bCanc, SW_SHOW);
        EnableWindow(bCanc, FALSE);       /* 安装中不给取消（半装状态更麻烦） */
        break;

    case PAGE_DONE:
        set_text(IDC_HDR_SUB, L"安装完成。");
        show(IDC_SUMMARY, TRUE);
        ShowWindow(bFin, SW_SHOW); SetWindowTextW(bFin, L"完成");
        break;
    }
    InvalidateRect(g_hWnd, NULL, TRUE);
}

static void create_controls(HWND h)
{
    /* 横幅（用静态控件占位 + WM_CTLCOLORSTATIC 画背景） */
    mk(h, L"STATIC", APP_TITLE, SS_LEFT,
       MARGIN, 14, WND_W - 2 * MARGIN, 28, IDC_HDR_TITLE, g_fontTitle);
    mk(h, L"STATIC", L"", SS_LEFT,
       MARGIN + 2, 44, WND_W - 2 * MARGIN, 20, IDC_HDR_SUB, g_fontSub);

    /* --- 第 0 页 --- */
    mk(h, L"STATIC", L"", SS_LEFT,
       MARGIN, 88, WND_W - 2 * MARGIN, 20, IDC_HINT, g_font);
    mk(h, L"EDIT", k_license,
       WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL,
       MARGIN, 112, WND_W - 2 * MARGIN, 244, IDC_LICENSE, g_font);
    mk(h, L"BUTTON", L"我接受许可协议（必须勾选才能继续）",
       BS_AUTOCHECKBOX | WS_TABSTOP,
       MARGIN, 366, WND_W - 2 * MARGIN, 22, IDC_AGREE, g_font);

    /* --- 第 1 页 --- */
    mk(h, L"EDIT", L"",
       WS_BORDER | ES_AUTOHSCROLL,
       MARGIN, 140, 520, 26, IDC_PATH, g_font);
    mk(h, L"BUTTON", L"浏览…", BS_PUSHBUTTON | WS_TABSTOP,
       552, 139, 88, 28, IDC_BROWSE, g_font);
    mk(h, L"BUTTON", L"安装内核驱动（推荐）",
       BS_AUTOCHECKBOX | WS_TABSTOP,
       MARGIN, 182, WND_W - 2 * MARGIN, 22, IDC_CHKDRV, g_font);
    mk(h, L"BUTTON", L"    开机优先启动内核驱动（不勾选则按普通开机自启加载）",
       BS_AUTOCHECKBOX | WS_TABSTOP,
       MARGIN, 206, WND_W - 2 * MARGIN, 22, IDC_CHKDRVBOOT, g_font);
    mk(h, L"BUTTON", L"开机自动启动引擎（开机由 SYSTEM 服务拉起，安全模式下不启动）",
       BS_AUTOCHECKBOX | WS_TABSTOP,
       MARGIN, 236, WND_W - 2 * MARGIN, 22, IDC_CHKAUTO, g_font);
    /* --- 第 2 页 --- */
    mk(h, L"STATIC", L"", SS_LEFT,
       MARGIN, 88, WND_W - 2 * MARGIN, 20, IDC_STEP, g_font);
    mk(h, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
       MARGIN, 112, WND_W - 2 * MARGIN, 22, IDC_PROGRESS, NULL);
    mk(h, L"EDIT", L"",
       WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL | ES_AUTOVSCROLL | ES_NOHIDESEL,
       MARGIN, 144, WND_W - 2 * MARGIN, 212, IDC_LOG, g_fontMono);

    /* --- 第 3 页 --- */
    mk(h, L"EDIT", L"",
       WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
       MARGIN, 88, WND_W - 2 * MARGIN, 244, IDC_SUMMARY, g_font);

    /* --- 底部按钮 --- */
    mk(h, L"BUTTON", L"上一步", BS_PUSHBUTTON | WS_TABSTOP,
       WND_W - MARGIN - BTN_W * 3 - 16, BTN_Y, BTN_W, BTN_H, ID_BTN_BACK, g_font);
    mk(h, L"BUTTON", L"下一步", BS_DEFPUSHBUTTON | WS_TABSTOP,
       WND_W - MARGIN - BTN_W * 2 - 8, BTN_Y, BTN_W, BTN_H, ID_BTN_NEXT, g_font);
    mk(h, L"BUTTON", L"取消", BS_PUSHBUTTON | WS_TABSTOP,
       WND_W - MARGIN - BTN_W, BTN_Y, BTN_W, BTN_H, ID_BTN_CANCEL, g_font);
    mk(h, L"BUTTON", L"完成", BS_DEFPUSHBUTTON | WS_TABSTOP,
       WND_W - MARGIN - BTN_W, BTN_Y, BTN_W, BTN_H, ID_BTN_FINISH, g_font);

    SendMessageW(GetDlgItem(h, IDC_PROGRESS), PBM_SETRANGE32, 0, 100);
    SendMessageW(GetDlgItem(h, IDC_PROGRESS), PBM_SETPOS, 0, 0);
    CheckDlgButton(h, IDC_CHKDRV, BST_CHECKED);
    CheckDlgButton(h, IDC_CHKDRVBOOT, BST_CHECKED);
    CheckDlgButton(h, IDC_CHKAUTO, BST_CHECKED);
}

/* 完成页 / 失败页的汇总文本 */
static void fill_summary(int err)
{
    WCHAR buf[4096];
    WCHAR drv[128];
    const WCHAR *aut;

    if (err == 0) {
        /*  ★ 只陈述**事实**：注册了没有、加载了没有、用哪种启动类型。
         *    不解释"为什么没加载" —— 那是 driver\README.md 的事，
         *    不该出现在安装界面上（用户明确要求）。 */
        const WCHAR *st = g_ctx.drv_boot ? L"开机优先启动" : L"普通开机自启";
        switch (g_ctx.drv_state) {
        case 2:  _snwprintf(drv, 127, L"已加载（%s）", st); break;
        case 1:  _snwprintf(drv, 127, L"已注册，但本次未能加载（%s）", st); break;
        case 3:  _snwprintf(drv, 127, L"未安装（你在选项页取消了勾选）"); break;
        default: _snwprintf(drv, 127, L"未安装"); break;
        }
        drv[127] = 0;

        switch (g_ctx.auto_state) {
        case 1:  aut = L"已注册（开机即以 SYSTEM 启动，并在交互会话里拉起引擎）"; break;
        case 2:  aut = L"未注册（你在选项页取消了勾选）"; break;
        default: aut = L"未注册"; break;
        }

        _snwprintf(buf, 4095,
            L"安装成功。\r\n\r\n"
            L"安装目录 : %s\r\n"
            L"主程序   : %s\\%s\r\n"
            L"文件数量 : %d 个（共 %lu 字节）\r\n"
            L"内核驱动 : %s\r\n"
            L"开机自启 : %s\r\n"
            L"卸载方式 : 控制面板 → 程序和功能 → “%s”\r\n"
            L"           或直接运行 %s\\uninstall.bat\r\n\r\n"
            L"下一步：\r\n"
            L"  1) 双击桌面 “%s” 图标启动引擎（会弹 UAC）\r\n"
            L"  2) 或运行 %s\\start.bat\r\n"
            L"  3) 重启后引擎会自动启动（若上面“开机自启”是已注册）\r\n"
            L"     注意：**安全模式下不会启动**（引擎与服务都不会激活）\r\n\r\n"
            L"运行日志（安装后产生）：\r\n"
            L"  %s\\r3shieldcore-events.log     拦截事件\r\n"
            L"  %s\\r3shieldcore-console.log    引擎自述\r\n"
            L"  %s\\r3shieldcore-svc.log        开机自启服务（排查“为什么没自启”看它）\r\n",
            g_ctx.dest, g_ctx.dest, ENGINE_EXE,
            g_ctx.n_files, (unsigned long)g_ctx.total_bytes, drv, aut,
            APP_NAME, g_ctx.dest,
            APP_NAME, g_ctx.dest,
            g_ctx.dest, g_ctx.dest, g_ctx.dest);
    } else {
        _snwprintf(buf, 4095,
            L"安装失败。\r\n\r\n"
            L"%s\r\n\r\n"
            L"已经写入的文件仍保留在：\r\n"
            L"  %s\r\n"
            L"可以重新运行本安装程序覆盖安装，或用 uninstall.bat 清理。\r\n",
            g_ctx.errmsg[0] ? g_ctx.errmsg : L"（没有更多信息）",
            g_ctx.dest);
    }
    buf[4095] = 0;
    SetWindowTextW(GetDlgItem(g_hWnd, IDC_SUMMARY), buf);
}

static void start_install(void)
{
    if (InterlockedExchange(&g_busy, 1) != 0) return;   /* 已经在装了 */

    GetWindowTextW(GetDlgItem(g_hWnd, IDC_PATH), g_dest, PATH_MAX_W - 1);
    g_dest[PATH_MAX_W - 1] = 0;
    wcsncpy(g_ctx.dest, g_dest, PATH_MAX_W - 1);
    g_ctx.dest[PATH_MAX_W - 1] = 0;
    g_ctx.install_driver = g_drv_checked;
    /*  ★ 从**控件现值**读，不读 g_xxx 缓存：被 EnableWindow 置灰的复选框
     *    不会再发 WM_COMMAND，缓存值可能停在最后一次点击的状态。 */
    g_ctx.drv_boot   = (IsDlgButtonChecked(g_hWnd, IDC_CHKDRVBOOT) == BST_CHECKED);
    g_ctx.autostart  = (IsDlgButtonChecked(g_hWnd, IDC_CHKAUTO) == BST_CHECKED);
    g_ctx.silent = FALSE;

    apply_page(PAGE_PROGRESS);
    UpdateWindow(g_hWnd);

    g_thread = CreateThread(NULL, 0, install_thread, NULL, 0, NULL);
    if (!g_thread) {
        InterlockedExchange(&g_busy, 0);
        MessageBoxW(g_hWnd, L"无法创建安装线程。", APP_TITLE, MB_ICONERROR);
        apply_page(PAGE_OPTIONS);
    }
}

static void browse_for_folder(void)
{
    BROWSEINFOW bi;
    PIDLIST_ABSOLUTE pidl;
    WCHAR buf[PATH_MAX_W];

    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = g_hWnd;
    bi.lpszTitle = L"选择 R3 ShieldCore 的安装位置：";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return;
    buf[0] = 0;
    if (SHGetPathFromIDListW(pidl, buf) && buf[0]) {
        /* 用户可能选了盘符根 —— 那就在后面接产品名，别直接装到盘根 */
        if (wcslen(buf) <= 3) {
            size_t L = wcslen(buf);
            _snwprintf(buf + L, PATH_MAX_W - L - 1, L"%s", APP_NAME);
            buf[PATH_MAX_W - 1] = 0;
        }
        SetWindowTextW(GetDlgItem(g_hWnd, IDC_PATH), buf);
    }
    CoTaskMemFree(pidl);
}

static LRESULT CALLBACK wnd_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {

    case WM_CREATE:
        g_hWnd = h;
        create_controls(h);
        SetWindowTextW(GetDlgItem(h, IDC_PATH), g_dest);
        apply_page(PAGE_WELCOME);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        {
            RECT r = { 0, 0, WND_W, BANNER_H };
            FillRect(dc, &r, g_brBanner);
            r.top = BANNER_H; r.bottom = BANNER_H + 1;
            FillRect(dc, &r, (HBRUSH)GetStockObject(GRAY_BRUSH));
        }
        EndPaint(h, &ps);
        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        HWND c = (HWND)lp;
        int id = GetDlgCtrlID(c);
        SetBkMode(dc, TRANSPARENT);
        if (id == IDC_HDR_TITLE) {
            SetTextColor(dc, RGB(255, 255, 255));
            return (LRESULT)g_brBanner;
        }
        if (id == IDC_HDR_SUB) {
            SetTextColor(dc, RGB(198, 214, 236));
            return (LRESULT)g_brBanner;
        }
        SetTextColor(dc, RGB(20, 20, 20));
        return (LRESULT)g_brWhite;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        switch (id) {
        case IDC_AGREE:
            g_agreed = (IsDlgButtonChecked(h, IDC_AGREE) == BST_CHECKED);
            EnableWindow(GetDlgItem(h, ID_BTN_NEXT), g_agreed);
            return 0;
        case IDC_CHKDRV:
            g_drv_checked = (IsDlgButtonChecked(h, IDC_CHKDRV) == BST_CHECKED);
            sync_drv_sub();
            return 0;
        case IDC_CHKDRVBOOT:
            g_drvboot_checked = (IsDlgButtonChecked(h, IDC_CHKDRVBOOT) == BST_CHECKED);
            return 0;
        case IDC_CHKAUTO:
            g_auto_checked = (IsDlgButtonChecked(h, IDC_CHKAUTO) == BST_CHECKED);
            return 0;
        case IDC_BROWSE:
            browse_for_folder();
            return 0;

        case ID_BTN_NEXT:
            if (g_page == PAGE_WELCOME) {
                if (!g_agreed) return 0;      /* 保险：没勾选就不放行 */
                apply_page(PAGE_OPTIONS);
            } else if (g_page == PAGE_OPTIONS) {
                start_install();
            }
            return 0;

        case ID_BTN_BACK:
            if (g_page == PAGE_OPTIONS) apply_page(PAGE_WELCOME);
            return 0;

        case ID_BTN_CANCEL:
            if (g_busy) return 0;             /* 安装中不许取消 */
            DestroyWindow(h);
            return 0;

        case ID_BTN_FINISH: {
            /* ★ 这里**故意不**再启动引擎（2026-10-06 去掉"完成后立即启动引擎"）。
             *
             *   原因：安装到 [4/7] 时已经 `StartServiceW(R3ShieldCoreGuard)`，
             *   守候服务的 RunLoop **第一轮**就会把引擎拉进交互会话 —— 引擎那时
             *   就已经起来了。原来这里再 `ShellExecute` 一次，等于**又建一份**：
             *   引擎没有单实例互斥体（全仓确认过），两份 = 两套全局注入 +
             *   两套 hook + 日志互相打架。
             *
             *   为什么原来的"重复防护"没挡住：服务那份"同一会话只拉一次"的记账
             *   （g_launched[]）只活在**服务进程内存**里，而这里是用 ShellExecute
             *   直接建进程，**完全绕过** TryLaunchForSession ⇒ 服务不知道。
             *
             *   正确语义：**启动引擎统一交给服务**（它就是干这个的）。
             *   用户想立刻用，桌面上有快捷方式（带 requireAdministrator，
             *   双击自己走 UAC）。 */
            DestroyWindow(h);
            return 0;
        }
        }
        return 0;
    }

    /* 工作线程回报：wParam=百分比，lParam=要追加的一行文字（本函数负责 free） */
    case WM_APP_PROGRESS: {
        WCHAR *s = (WCHAR *)lp;
        int pct = (int)wp;
        HWND pb = GetDlgItem(h, IDC_PROGRESS);
        if (pb) SendMessageW(pb, PBM_SETPOS, (WPARAM)pct, 0);
        if (s) {
            if (pct <= 100 && wcsncmp(s, L"[", 1) == 0) {
                SetWindowTextW(GetDlgItem(h, IDC_STEP), s);
                wcsncpy(g_last_step, s, 255);
                g_last_step[255] = 0;
            }
            logmsg(L"%s", s);
            free(s);
        }
        return 0;
    }

    case WM_APP_DONE: {
        int err = (int)wp;
        InterlockedExchange(&g_busy, 0);
        EnableWindow(GetDlgItem(h, ID_BTN_CANCEL), TRUE);
        fill_summary(err);
        apply_page(PAGE_DONE);
        /* 注：原来这里会在失败时把"完成后立即启动引擎"勾掉并置灰。
           该勾选框已于 2026-10-06 整体删除（启动统一交给守候服务），
           所以这里不再需要任何对应处理。 */
        SetForegroundWindow(h);
        return 0;
    }

    case WM_CLOSE:
        if (g_busy) {
            MessageBoxW(h, L"正在安装，请等待完成。", APP_TITLE, MB_ICONINFORMATION);
            return 0;
        }
        DestroyWindow(h);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ==========================================================================
 *  无界面模式 —— 让安装包**可被自动化验证**
 *
 *  没有这些开关的话，验证安装包的唯一办法就是真装一遍：又慢又危险，
 *  结果是没人测。所以必须留出"不碰系统也能证明 payload 是好的"的口子。
 * ========================================================================*/

static void w2u8(const WCHAR *w, char *out, int cap)
{
    if (cap <= 0) return;
    out[0] = 0;
    if (!w) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, cap - 1, NULL, NULL);
    out[cap - 1] = 0;
}

static void rpt(const char *fmt, ...)
{
    char buf[4096];
    char fixed[8300];
    va_list ap;
    int n, i, j;

    va_start(ap, fmt);
    n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    buf[sizeof(buf) - 1] = 0;

    /* ★ \n -> \r\n：报告文件是用 "wb" 打开的（二进制模式，不转行尾），
       而 Windows 上纯 \n 的文本在 Get-Content / 记事本里会被拼成一行
       （踩过：`...kernel.sysVERIFY-OK` 连在一起）。统一成 CRLF 最省事。 */
    for (i = 0, j = 0; buf[i] && j < (int)sizeof(fixed) - 3; i++) {
        if (buf[i] == '\n' && (i == 0 || buf[i - 1] != '\r')) fixed[j++] = '\r';
        fixed[j++] = buf[i];
    }
    fixed[j] = 0;

    if (g_rpt) { fputs(fixed, g_rpt); fflush(g_rpt); }
    /* GUI 子系统默认没有 stdout —— 但 AttachConsole 之后就有了。
       没接上时 fputs 会静默失败，所以**报告文件才是主渠道**。 */
    fputs(fixed, stdout);
    fflush(stdout);
}

/* 把 stdio 接到父进程的控制台（GUI 子系统专用技巧） */
static void attach_console(void)
{
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
}

/*  --verify：逐条校验内嵌资源
 *    断言三件事：① 资源存在 ② 大小和清单一致 ③ 关键文件（引擎/两个 DLL/
 *    驱动/ini/卸载脚本）都在。
 *    ★ 只断言"有一个资源"是**空真** —— 资源编漏时清单也跟着漏，
 *      照样"全绿"。所以这里必须用**独立于清单**的硬编码关键文件列表。 */
static int mode_verify(const WCHAR *report)
{
    int i, bad = 0;
    DWORD total = 0;
    char u8[PATH_MAX_W * 3];

    attach_console();
    if (report) g_rpt = _wfopen(report, L"wb");

    if (g_nitems <= 0) {
        rpt("FAIL 清单为空或读不出来（g_nitems=%d）\n", g_nitems);
        if (g_rpt) fclose(g_rpt);
        return 2;
    }

    rpt("清单条目 : %d\n", g_nitems);

    /* 默认安装目录 —— 这条是给自测看的：GUI 里那个路径框的内容就来自
       这个变量，把它单独报出来，才能区分"变量没算出来"和"控件没设上"。 */
    w2u8(g_dest, u8, sizeof(u8));
    rpt("默认安装目录 : %s\n", u8);

    for (i = 0; i < g_nitems; i++) {
        const void *p;
        DWORD sz = 0;
        if (!res_ptr(g_items[i].id, &p, &sz)) {
            w2u8(g_items[i].rel, u8, sizeof(u8));
            rpt("FAIL 资源缺失 id=%d  %s\n", g_items[i].id, u8);
            bad++;
            continue;
        }
        if (g_items[i].zsize && sz != g_items[i].zsize) {
            w2u8(g_items[i].rel, u8, sizeof(u8));
            rpt("FAIL 压缩大小不符 %s 清单=%lu 资源=%lu\n",
                u8, (unsigned long)g_items[i].zsize, (unsigned long)sz);
            bad++;
            continue;
        }
        /* ★ 真的解一遍 —— 只比大小是查不出"压缩流坏了"的 */
        {
            BYTE  *buf = (BYTE *)malloc(g_items[i].size ? g_items[i].size : 1);
            uLongf dlen = g_items[i].size;
            if (!buf) { bad++; continue; }
            if (uncompress(buf, &dlen, (const Bytef *)p, sz) != Z_OK ||
                dlen != g_items[i].size) {
                w2u8(g_items[i].rel, u8, sizeof(u8));
                rpt("FAIL 解压失败 %s 期望=%lu 实得=%lu\n",
                    u8, (unsigned long)g_items[i].size, (unsigned long)dlen);
                free(buf);
                bad++;
                continue;
            }
            free(buf);
        }
        total += g_items[i].size;
    }
    rpt("资源总字节: %lu\n", (unsigned long)total);

    /* 卸载脚本 */
    {
        const void *p;
        DWORD sz = 0;
        if (!res_ptr(RES_ID_UNINSTALL, &p, &sz) || sz < 100) {
            rpt("FAIL 卸载脚本资源缺失或过小 (id=%d)\n", RES_ID_UNINSTALL);
            bad++;
        } else {
            rpt("卸载脚本 : %lu 字节\n", (unsigned long)sz);
        }
    }

    /* ★ 关键文件必须**按名字**在清单里找到 —— 不依赖清单自己说了什么 */
    {
        static const WCHAR *must[] = {
            L"R3 ShieldCore.exe",
            L"64/r3shieldcore-lib.dll",
            L"32/r3shieldcore-lib.dll",
            L"r3shieldcore.ini",
            L"driver/r3shieldcore_kernel.sys",
            L"r3shieldcore_svc.exe",
        };
        for (size_t m = 0; m < sizeof(must) / sizeof(must[0]); m++) {
            int found = 0;
            for (i = 0; i < g_nitems; i++) {
                if (_wcsicmp(g_items[i].rel, must[m]) == 0) { found = 1; break; }
            }
            w2u8(must[m], u8, sizeof(u8));
            if (!found) { rpt("FAIL 清单里没有 %s\n", u8); bad++; }
            else        { rpt("OK   %s\n", u8); }
        }
    }

    /* ★ 驱动文件名必须和 DRV_SYS_NAME 一致。
       踩过：DRV_SYS_NAME 写成 R3ShieldCoreKernel.sys（把**服务名**当文件名），
       而 payload 里是 r3shieldcore_kernel.sys —— 差一个下划线，安装时驱动
       那步永远静默跳过；而 --verify 因为自己**硬编码**了小写名所以照样全绿。
       所以这里必须用代码里真正会用的那个常量去比。 */
    {
        int found = 0;
        for (i = 0; i < g_nitems; i++) {
            const WCHAR *r = g_items[i].rel;
            if (wcsncmp(r, L"driver/", 7) == 0 && _wcsicmp(r + 7, DRV_SYS_NAME) == 0) {
                found = 1;
                break;
            }
        }
        if (found) {
            rpt("OK   驱动文件名与 DRV_SYS_NAME 一致\n");
        } else {
            w2u8(DRV_SYS_NAME, u8, sizeof(u8));
            rpt("FAIL 清单里的驱动文件名和 DRV_SYS_NAME(%s) 对不上 —— 驱动那步会静默跳过\n", u8);
            bad++;
        }
    }

    /* ★ 开机启动服务的 exe 必须在清单里，且名字要和 SVC_EXE_NAME 一致。
       踩点：少了它的时候 [4/7] 只会打一行"找不到 r3shieldcore_svc.exe"的
       **警告**然后继续 —— 安装报成功、目录看着也齐，但开机什么都不启动。
       所以这里必须让 --verify 直接 FAIL（铁律 100：静默跳过必须变成硬失败）。 */
    {
        int found = 0;
        for (i = 0; i < g_nitems; i++) {
            if (_wcsicmp(g_items[i].rel, SVC_EXE_NAME) == 0) {
                found = 1;
                break;
            }
        }
        if (found) {
            rpt("OK   开机启动服务 exe 与 SVC_EXE_NAME 一致\n");
        } else {
            w2u8(SVC_EXE_NAME, u8, sizeof(u8));
            rpt("FAIL 清单里没有 %s —— 开机自启那步会只打警告然后跳过\n", u8);
            bad++;
        }
    }

    rpt(bad ? "\nVERIFY-FAIL  (%d 个问题)\n" : "\nVERIFY-OK\n", bad);
    if (g_rpt) fclose(g_rpt);
    return bad ? 1 : 0;
}

/*  --extract <dir>：把所有 payload 解到 dir。不碰系统，用于自测。 */
static int mode_extract(const WCHAR *dir, const WCHAR *report)
{
    int i, bad = 0;
    DWORD total = 0;
    char u8[PATH_MAX_W * 3];

    attach_console();
    if (report) g_rpt = _wfopen(report, L"wb");

    if (g_nitems <= 0) {
        rpt("FAIL 清单为空\n");
        if (g_rpt) fclose(g_rpt);
        return 2;
    }
    if (!ensure_dir(dir)) {
        rpt("FAIL 建不出目录\n");
        if (g_rpt) fclose(g_rpt);
        return 2;
    }

    for (i = 0; i < g_nitems; i++) {
        WCHAR rel[PATH_MAX_W], dst[PATH_MAX_W];
        DWORD wrote = 0;
        wcsncpy(rel, g_items[i].rel, PATH_MAX_W - 1);
        rel[PATH_MAX_W - 1] = 0;
        rel_to_win(rel);
        path_join(dst, PATH_MAX_W, dir, rel);

        if (!res_unzip_to_file(g_items[i].id, dst,
                               g_items[i].size, g_items[i].zsize, &wrote)) {
            w2u8(rel, u8, sizeof(u8));
            rpt("FAIL 解压/写出失败 %s\n", u8);
            bad++;
            continue;
        }
        if (wrote != g_items[i].size) {
            w2u8(rel, u8, sizeof(u8));
            rpt("FAIL 字节数不符 %s 期望=%lu 实得=%lu\n",
                u8, (unsigned long)g_items[i].size, (unsigned long)wrote);
            bad++;
            continue;
        }
        total += wrote;
    }

    /* 卸载脚本也解出来 —— 它是独立资源，不在清单里 */
    {
        WCHAR up[PATH_MAX_W];
        DWORD sz = 0;
        path_join(up, PATH_MAX_W, dir, L"uninstall.bat");
        if (!res_to_file(RES_ID_UNINSTALL, up, &sz)) {
            rpt("FAIL 卸载脚本写不出\n");
            bad++;
        } else {
            rpt("卸载脚本 : %lu 字节\n", (unsigned long)sz);
        }
    }

    rpt("已解出 %d 项, 共 %lu 字节\n", g_nitems, (unsigned long)total);
    rpt(bad ? "EXTRACT-FAIL (%d)\n" : "EXTRACT-OK\n", bad);
    if (g_rpt) fclose(g_rpt);
    return bad ? 1 : 0;
}

/* ==========================================================================
 *  入口
 * ========================================================================*/

/*  --uicheck=<file>：把界面上每个控件的**真实状态**（类名/ID/可见/启用/文本）
 *  快照到一个文件，然后自动关窗退出。
 *
 *  为什么必须让程序"自证"：
 *    测试脚本是**非提权**进程，而安装程序是提权的。UIPI（用户界面特权隔离）
 *    会**丢弃**低完整性进程发给高完整性窗口的消息，所以从外面：
 *      · 读不到 EDIT 的文本（EDIT 的文本要发 WM_GETTEXT 才拿得到，
 *        InternalGetWindowText 对 EDIT 不返回内容）；
 *      · 也发不进 WM_CLOSE，窗口关不掉。
 *    而**进程内**读自己的控件完全不受这个限制 —— 所以自快照是唯一可靠的
 *    GUI 验证手段（外部枚举仍然有用：它能证明"窗口真的出现在桌面上"）。
 */
static BOOL CALLBACK dump_cb(HWND h, LPARAM lp)
{
    FILE *f = (FILE *)lp;
    WCHAR cls[256], txt[4096];
    char  c8[512], t8[16384];

    cls[0] = txt[0] = 0;
    GetClassNameW(h, cls, 255);
    GetWindowTextW(h, txt, 4095);
    w2u8(cls, c8, sizeof(c8));
    w2u8(txt, t8, sizeof(t8));

    /* ★ 把文本里的 CR/LF/TAB 压成空格：多行 EDIT（许可框）的文本自带换行，
       直接写会把"一行一个控件"的快照格式搞乱，解析端就没法按行切。 */
    for (char *p = t8; *p; p++) {
        if (*p == '\r' || *p == '\n' || *p == '\t') *p = ' ';
    }

    /* ★ 勾选状态单独一列（-1 = 不是复选框）。
       没有这一列就断言不了"这个复选框默认是勾上的" —— 而"默认值对不对"
       正是选项页最容易错的地方（改了默认值却没人发现）。 */
    {
        int chk = -1;
        if (!_wcsicmp(cls, L"Button")) {
            LONG st = GetWindowLongW(h, GWL_STYLE);
            if ((st & 0x0FL) == BS_AUTOCHECKBOX || (st & 0x0FL) == BS_CHECKBOX)
                chk = (SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
        }
        fprintf(f, "ID=%d\tCLS=%s\tVIS=%d\tEN=%d\tCHK=%d\tTEXT=%s\r\n",
                GetDlgCtrlID(h), c8,
                IsWindowVisible(h) ? 1 : 0,
                IsWindowEnabled(h) ? 1 : 0, chk, t8);
    }
    return TRUE;
}

static void dump_ui_state(const WCHAR *path)
{
    FILE *f = _wfopen(path, L"wb");
    WCHAR t[512];
    char  t8[2048];

    if (!f) return;
    t[0] = 0;
    GetWindowTextW(g_hWnd, t, 511);
    w2u8(t, t8, sizeof(t8));
    fprintf(f, "WINDOW\t%s\r\n", t8);
    /* 诊断行：主窗口自己的可见性 / style。
       ★ IsWindowVisible 对子控件的判据是"自己 + 所有祖先都有 WS_VISIBLE"，
         所以主窗口一旦不可见，**所有**子控件都会报 VIS=0 —— 有这一行才分得清
         "控件没显示"和"主窗口没显示"。 */
    fprintf(f, "SELF\tVIS=%d\tHASWSVIS=%d\tSTYLE=0x%08lX\r\n",
            IsWindowVisible(g_hWnd) ? 1 : 0,
            (GetWindowLongW(g_hWnd, GWL_STYLE) & WS_VISIBLE) ? 1 : 0,
            (unsigned long)GetWindowLongW(g_hWnd, GWL_STYLE));
    EnumChildWindows(g_hWnd, dump_cb, (LPARAM)f);
    fclose(f);
}

static void default_dest(WCHAR *out)
{
    WCHAR pf[PATH_MAX_W];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pf))) {
        _snwprintf(out, PATH_MAX_W - 1, L"%s\\%s", pf, APP_NAME);
    } else {
        _snwprintf(out, PATH_MAX_W - 1, L"C:\\Program Files\\%s", APP_NAME);
    }
    out[PATH_MAX_W - 1] = 0;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmdline, int nShow)
{
    int    argc = 0;
    WCHAR **argv;
    int    i;
    BOOL   silent = FALSE;
    const WCHAR *extract_dir = NULL;
    const WCHAR *report = NULL;
    const WCHAR *uicheck = NULL;
    int    uicheck_page = 0;       /* >0 = 快照前先切到这个页号 */
    BOOL   uicheck_drvoff = FALSE; /* 快照前把"安装内核驱动"取消勾选 */
    int    drv_boot_opt = -1;      /* -1 = 未指定（用界面默认值） */
    int    autostart_opt = -1;     /* -1 = 未指定 */

    (void)hPrev; (void)cmdline; (void)nShow;

    g_hInst = hInst;
    default_dest(g_dest);

    /* 解析命令行。GUI 子系统里 argc/argv 要自己拿。 */
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (i = 1; argv && i < argc; i++) {
        if (!_wcsicmp(argv[i], L"--verify")) {
            /* 交给下面统一处理 */
        } else if (wcsncmp(argv[i], L"--extract=", 10) == 0) {
            /* 支持 --extract=<dir> 形式。含空格的目录用等号形式**不需要**
               调用方加引号 —— 而 Start-Process -ArgumentList 不会替你加引号
               （踩过：'C:\Program Files\x' 被拆成两个参数，结果解到了 C:\Program）。 */
            extract_dir = argv[i] + 10;
        } else if (!_wcsicmp(argv[i], L"--extract") && i + 1 < argc) {
            extract_dir = argv[++i];
        } else if (!_wcsicmp(argv[i], L"/S") || !_wcsicmp(argv[i], L"--silent")) {
            silent = TRUE;
        } else if (wcsncmp(argv[i], L"/DEST=", 6) == 0) {
            wcsncpy(g_dest, argv[i] + 6, PATH_MAX_W - 1);
            g_dest[PATH_MAX_W - 1] = 0;
        } else if (wcsncmp(argv[i], L"--dest=", 7) == 0) {
            wcsncpy(g_dest, argv[i] + 7, PATH_MAX_W - 1);
            g_dest[PATH_MAX_W - 1] = 0;
        } else if (wcsncmp(argv[i], L"--report=", 9) == 0) {
            report = argv[i] + 9;
        } else if (wcsncmp(argv[i], L"--uicheck=", 10) == 0) {
            uicheck = argv[i] + 10;
        } else if (wcsncmp(argv[i], L"--uicheck-page=", 15) == 0) {
            uicheck_page = _wtoi(argv[i] + 15);
        } else if (!_wcsicmp(argv[i], L"--uicheck-drvoff")) {
            uicheck_drvoff = TRUE;
        } else if (wcsncmp(argv[i], L"--drv-start=", 12) == 0) {
            /* 驱动启动类型：boot = 开机优先，auto = 普通开机自启 */
            if (!_wcsicmp(argv[i] + 12, L"boot"))      drv_boot_opt = 1;
            else if (!_wcsicmp(argv[i] + 12, L"auto")) drv_boot_opt = 0;
        } else if (!_wcsicmp(argv[i], L"--no-autostart")) {
            autostart_opt = 0;
        } else if (!_wcsicmp(argv[i], L"--autostart")) {
            autostart_opt = 1;
        }
    }

    /* 清单必须先解析 —— 所有模式都要用 */
    parse_manifest();

    if (argv) {
        for (i = 1; i < argc; i++) {
            if (!_wcsicmp(argv[i], L"--verify")) {
                int rc = mode_verify(report);
                LocalFree(argv);
                return rc;
            }
        }
    }
    if (extract_dir) {
        int rc = mode_extract(extract_dir, report);
        if (argv) LocalFree(argv);
        return rc;
    }

    /* 静默安装：不给界面，直接装，靠返回码报结果 */
    if (silent) {
        attach_console();
        if (report) g_rpt = _wfopen(report, L"wb");
        wcsncpy(g_ctx.dest, g_dest, PATH_MAX_W - 1);
        g_ctx.install_driver = g_drv_checked;
        g_ctx.drv_boot  = (drv_boot_opt < 0) ? g_drvboot_checked : (drv_boot_opt != 0);
        g_ctx.autostart = (autostart_opt < 0) ? g_auto_checked : (autostart_opt != 0);
        g_ctx.silent = TRUE;
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        do_install();
        CoUninitialize();
        rpt("SILENT err=%d files=%d bytes=%lu drv=%d auto=%d drvboot=%d\n",
            g_ctx.err, g_ctx.n_files, (unsigned long)g_ctx.total_bytes,
            g_ctx.drv_state, g_ctx.auto_state, g_ctx.drv_boot ? 1 : 0);
        if (g_ctx.err && g_ctx.errmsg[0]) {
            char u8[3072];
            w2u8(g_ctx.errmsg, u8, sizeof(u8));
            rpt("错误: %s\n", u8);
        }
        if (g_rpt) fclose(g_rpt);
        if (argv) LocalFree(argv);
        return g_ctx.err ? 1 : 0;
    }

    /* ---------------- 图形界面 ---------------- */
    {
        INITCOMMONCONTROLSEX icc;
        WNDCLASSEXW wc;
        RECT r;
        DWORD style;
        int x, y, ww, wh;
        HWND h;
        MSG m;

        icc.dwSize = sizeof(icc);
        icc.dwICC = ICC_PROGRESS_CLASS;
        InitCommonControlsEx(&icc);

        /* 字体：优先微软雅黑，退到 Segoe UI。DEFAULT_CHARSET 保证中文不乱码。 */
        g_font     = make_font(10, FALSE, L"Microsoft YaHei UI");
        g_fontBold = make_font(10, TRUE,  L"Microsoft YaHei UI");
        g_fontTitle= make_font(15, TRUE,  L"Microsoft YaHei UI");
        g_fontSub  = make_font(9,  FALSE, L"Microsoft YaHei UI");
        g_fontMono = make_font(9,  FALSE, L"Consolas");

        g_brBanner = CreateSolidBrush(RGB(24, 54, 100));
        g_brWhite  = CreateSolidBrush(RGB(255, 255, 255));

        ZeroMemory(&wc, sizeof(wc));
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = wnd_proc;
        wc.hInstance     = hInst;
        wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
        wc.hbrBackground = g_brWhite;
        wc.lpszClassName = L"R3ShieldCoreSetup";
        wc.hIcon         = LoadIconW(hInst, MAKEINTRESOURCEW(101));
        wc.hIconSm       = wc.hIcon;
        if (!wc.hIcon) wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
        RegisterClassExW(&wc);

        style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        r.left = 0; r.top = 0; r.right = WND_W; r.bottom = WND_H;
        AdjustWindowRectEx(&r, style, FALSE, 0);
        ww = r.right - r.left;
        wh = r.bottom - r.top;
        x = (GetSystemMetrics(SM_CXSCREEN) - ww) / 2;
        y = (GetSystemMetrics(SM_CYSCREEN) - wh) / 2;

        h = CreateWindowExW(WS_EX_APPWINDOW, L"R3ShieldCoreSetup", APP_TITLE, style,
                            x, y, ww, wh, NULL, NULL, hInst, NULL);
        if (!h) {
            MessageBoxW(NULL, L"无法创建安装窗口。", APP_TITLE, MB_ICONERROR);
            if (argv) LocalFree(argv);
            return 3;
        }
        ShowWindow(h, SW_SHOW);
        UpdateWindow(h);

        if (uicheck) {
            /* 让 WM_CREATE / WM_PAINT / 布局都跑完再快照。
               ★ 这里必须自己抽干消息队列：还没进 GetMessage 循环，
                 Sleep 期间消息不会被处理，控件的可见性判断会不准。 */
            MSG tmp;
            DWORD t0 = GetTickCount();
            while (GetTickCount() - t0 < 800) {
                while (PeekMessageW(&tmp, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&tmp);
                    DispatchMessageW(&tmp);
                }
                Sleep(40);
            }
            /* ★ --uicheck-page=1：先切到**选项页**再快照。
               不切页的话，选项页上的三个复选框永远是 VIS=0，断言不到
               "它们默认勾上了没有"、"置灰联动对不对"。
               切页后要再抽一遍消息队列，让重绘落地。 */
            if (uicheck_page > 0) {
                apply_page(PAGE_OPTIONS);
                if (uicheck_drvoff) {
                    CheckDlgButton(g_hWnd, IDC_CHKDRV, BST_UNCHECKED);
                    sync_drv_sub();
                }
                t0 = GetTickCount();
                while (GetTickCount() - t0 < 400) {
                    while (PeekMessageW(&tmp, NULL, 0, 0, PM_REMOVE)) {
                        TranslateMessage(&tmp);
                        DispatchMessageW(&tmp);
                    }
                    Sleep(40);
                }
            }
            dump_ui_state(uicheck);
            DestroyWindow(h);
        }

        while (GetMessageW(&m, NULL, 0, 0) > 0) {
            if (!IsDialogMessageW(h, &m)) {
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
        }
    }

    if (argv) LocalFree(argv);
    return 0;
}
