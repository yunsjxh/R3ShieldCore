// diag_autostart.cpp -- R3 ShieldCore 开机自启诊断器（**原生 C++ / 零 shell-out**）
//
// 为什么要有这个 C++ 版本
// =======================
// 同功能的 `tools/diag_autostart.bat` 依赖 cmd 的 `for /f` 去 shell out 调
// reg.exe / tasklist.exe / findstr.exe / find.exe。这条路在真机上踩过一次大坑：
// 子命令**第一个字符是双引号**时，cmd 把引号剥掉后拿到一条非法命令，
// 每个 `for /f` 都静默产出 0 行，于是所有计数恒为 0，脚本却照常打印结论 ——
// 最后**错误地**报告"服务键不存在 / 开机自启没注册"。
//
// 已用原生探针（tools/forfprobe.cpp）独立复验：那与 `2^>nul` 无关，
// 判据是**首字符是否双引号**。无论怎么修，只要脚本还 shell out，
// 就还要继续跟 cmd 的引号/转义/代码页规则搏斗。
//
// 所以：**这一版一次都不 shell out**。
//   · 注册表   -> RegOpenKeyExW / RegQueryValueExW
//   · 服务状态 -> OpenServiceW / QueryServiceStatusEx
//   · 进程枚举 -> CreateToolhelp32Snapshot / Process32NextW
//   · 开机时间 -> GetTickCount64()（自报，比 net statistics 可靠）
//   · 日志解析 -> 直接 ReadFile + 自己按 CRLF 切行
// 结果：不存在"读不出"，不存在"(查不出)"，不存在编码/引号陷阱。
//
// 输出对用户可见，所以**必须 UTF-8 → 控制台**。
// 中文标签用 UTF-8 源（编译加 -source-charset:utf-8），输出时转成本机码页。
//
// 用法
// ====
//   tools\diag_autostart.exe              正常诊断（双击/命令行都行）
//   tools\diag_autostart.exe "D:\path"    指定安装目录
//   tools\diag_autostart.exe --json       机器可读输出（给自动化用）
//   tools\diag_autostart.exe --no-pause   跑完**立刻退出**（自动化/管道用）
//
// ★ 关于"窗口一闪就过"
// ====================
// 这是控制台程序的通病：双击 .exe 时，cmd 会为它开一个控制台窗口，
// **进程一退出，窗口就跟着关掉** —— 用户根本来不及看输出。
// Facebook 的解决办法是让用户"开个 cmd 再跑"，但那对用户太不友好。
//
// 本程序的策略：
//   1) 若检测到**被双击启动**（父进程是 explorer.exe / 本进程没有现成控制台），
//      跑完自动"按任意键继续"，窗口停住；
//   2) 若在**已有的 cmd 窗口**里跑（父进程是 cmd.exe），不暂停（不打扰）；
//   3) `--no-pause` 显式要求不暂停（给自动化/重定向用）；
//   4) `--pause` 强制暂停。
// 这样"双击看结果"和"脚本里抓输出"两种用法都自然。
//
// 退出码：0 = 三层都 OK；10 = 有断点（结果里带 FAIL_* 标签）

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <set>

#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// 控制台输出：内部一律 std::wstring（宽字符，天然能放中文），
// 打印时转成本机 ANSI 码页 —— 这样在 cmd.exe（936）和 Windows Terminal 都对。
// ---------------------------------------------------------------------------
static void Out(const std::wstring& s) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    bool console = GetConsoleMode(h, &mode) != 0;
    DWORD cp = console ? GetConsoleOutputCP() : GetACP();
    if (cp == 0) cp = GetACP();
    int n = WideCharToMultiByte(cp, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) { // 码页放不下（例如 UTF-8 控制台下不该走这里）
        cp = CP_UTF8;
        n = WideCharToMultiByte(cp, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    }
    std::string o(n, '\0');
    WideCharToMultiByte(cp, 0, s.c_str(), (int)s.size(), &o[0], n, nullptr, nullptr);
    fwrite(o.data(), 1, o.size(), stdout);
}

static void OutLine(const std::wstring& s = L"") { Out(s + L"\r\n"); }

// 把**日志片段的原始字节**变成可打印的宽串。
// ★ 服务日志是 UTF-8（带 BOM）—— 直接按字节 1:1 转 wchar 会把中文变成一串 '?'
//   （本程序第一版就是那样，实测 [PRIV] 行里的说明全成了 ???）。
//   这里按 UTF-8 解码；解不出来时退回"按 936 解"，再不行就逐字节转义。
static std::wstring RawToWide(const std::string& b) {
    // 先去掉 UTF-8 BOM —— 否则输入侧会渲染出一个 "?"（第一版实测第一行开头有个 ?）
    std::string body = b;
    if (body.size() >= 3 && (unsigned char)body[0] == 0xEF &&
        (unsigned char)body[1] == 0xBB && (unsigned char)body[2] == 0xBF)
        body.erase(0, 3);
    auto dec = [&](UINT cp) -> std::wstring {
        int n = MultiByteToWideChar(cp, 0, body.c_str(), (int)body.size(), nullptr, 0);
        if (n <= 0) return std::wstring();
        std::wstring w(n, L'\0');
        MultiByteToWideChar(cp, 0, body.c_str(), (int)body.size(), &w[0], n);
        return w;
    };
    std::wstring w = dec(CP_UTF8);
    if (!w.empty()) return w;
    w = dec(936);
    if (!w.empty()) return w;
    std::wstring o;
    for (unsigned char c : body) o += (c < 128) ? (wchar_t)c : L'?';
    return o;
}

static std::wstring Fmt(const wchar_t* fmt, ...) {
    wchar_t buf[4096];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    return std::wstring(buf);
}

// ---------------------------------------------------------------------------
// 结果汇总：每条"断点"都记下来，最后统一判
// ---------------------------------------------------------------------------
struct Report {
    std::vector<std::wstring> breaks;   // 断点描述
    std::vector<std::wstring> notes;    // 提示
    void Brk(const std::wstring& s) { breaks.push_back(s); }
    void Note(const std::wstring& s) { notes.push_back(s); }
};
static Report g_rep;

// ---------------------------------------------------------------------------
// 注册表读取（全部原生）
// ---------------------------------------------------------------------------
struct RegVal {
    bool exists = false;
    bool isString = false;
    std::wstring s;
    DWORD dw = 0;
};

static RegVal RegGet(HKEY root, const std::wstring& subkey, const wchar_t* name) {
    RegVal v;
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return v;
    DWORD type = 0, cb = 0;
    if (RegQueryValueExW(h, name, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS) {
        RegCloseKey(h);
        return v;
    }
    v.exists = true;
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        v.isString = true;
        std::vector<wchar_t> buf(cb / sizeof(wchar_t) + 2, 0);
        if (RegQueryValueExW(h, name, nullptr, &type, (LPBYTE)buf.data(), &cb) == ERROR_SUCCESS) {
            v.s = buf.data();
            // REG_EXPAND_SZ 要展开（ImagePath 常用 %SystemRoot%）
            if (type == REG_EXPAND_SZ) {
                wchar_t exp[4096]{};
                if (ExpandEnvironmentStringsW(v.s.c_str(), exp, 4096)) v.s = exp;
            }
        }
    } else if (type == REG_DWORD) {
        DWORD d = 0; cb = sizeof(d);
        if (RegQueryValueExW(h, name, nullptr, &type, (LPBYTE)&d, &cb) == ERROR_SUCCESS) v.dw = d;
    }
    RegCloseKey(h);
    return v;
}

static bool RegKeyExists(HKEY root, const std::wstring& subkey) {
    HKEY h = nullptr;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    RegCloseKey(h);
    return true;
}

// ---------------------------------------------------------------------------
// "窗口一闪就过" 的解决：判断要不要在结束时停住
// ---------------------------------------------------------------------------
// 双击 .exe 时，Windows 给它新建一个控制台；进程一退，窗口就没了。
// 判据（按可靠性排序）：
//   1) 父进程名 == explorer.exe   -> 基本可断定是双击（资源管理器启动的）
//   2) 本进程是**新建**的控制台（没有继承来的控制台）-> 也停住
// 反过来，父进程是 cmd.exe / powershell.exe / bash 等 -> 说明用户已经
// 有个窗口在那儿，再 pause 就是打扰。
static std::wstring ParentProcessName() {
    DWORD pid = 0;
    // 用 Toolhelp 拿父进程 id（PROCESSENTRY32 里带 th32ParentProcessID）
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"";
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD me = GetCurrentProcessId();
    DWORD ppid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == me) { ppid = pe.th32ParentProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (ppid == 0) return L"";
    // 再扫一遍拿父进程名
    std::wstring name;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"";
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == ppid) { name = pe.szExeFile; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    for (auto& c : name) c = towlower(c);
    return name;
}

// 本进程的控制台，是"本来就有的"还是"双击新开的"？
// ★ 关键：GetConsoleProcessList 返回**共享这个控制台的进程数**。
//   双击新建的控制台里，通常只有自己（外加可能的 conhost，但那个不算进程表里的成员）。
//   在一个已有 cmd 里跑，会有 cmd.exe + 自己 = 2 个。
//   实测口径：<=1 -> 认为是"新开的窗口"。
static bool ConsoleIsFreshlyMade() {
    DWORD pids[8]{};
    DWORD n = GetConsoleProcessList(pids, 8);
    return n <= 1;
}

// 结束时按需停住。force=false 时按上面的判据自动决定。
static void MaybePause(bool forcePause, bool forceNoPause) {
    if (forceNoPause) return;
    bool shouldPause = forcePause;
    if (!forcePause && !forceNoPause) {
        std::wstring parent = ParentProcessName();
        bool fromExplorer = (parent == L"explorer.exe");
        bool freshConsole = ConsoleIsFreshlyMade();
        shouldPause = fromExplorer || freshConsole;
    }
    if (!shouldPause) return;

    OutLine(L"");
    OutLine(L"----------------------------------------------------------------------");
    OutLine(L" 诊断完毕。按「回车」或「任意键」关闭本窗口 ...");
    OutLine(L" （下次想不让它停：加参数 --no-pause；想强制停：--pause）");
    OutLine(L"----------------------------------------------------------------------");
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (hIn && hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &mode)) {
        // 有控制台：清掉可能残留的输入事件，然后等一个键
        FlushConsoleInputBuffer(hIn);
        INPUT_RECORD ir{};
        DWORD got = 0;
        while (ReadConsoleInputW(hIn, &ir, 1, &got) && got > 0) {
            if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) break;
        }
    } else {
        // 没有控制台（被重定向/无 tty）：退化成读一个字符
        fgetc(stdin);
    }
}

// ---------------------------------------------------------------------------
// 路径展开 + 存在性
// ---------------------------------------------------------------------------
static std::wstring Expand(const std::wstring& s) {
    wchar_t buf[4096]{};
    if (ExpandEnvironmentStringsW(s.c_str(), buf, 4096)) return buf;
    return s;
}

static bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
static bool DirExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

// ---------------------------------------------------------------------------
// 服务状态（原生 SCM）
// ---------------------------------------------------------------------------
struct SvcInfo {
    bool keyExists = false;
    bool scmOpen = false;
    DWORD start = 0xFFFFFFFF;
    std::wstring imagePath;
    DWORD state = 0;
    DWORD win32Exit = 0;
    DWORD pid = 0;
};

static SvcInfo QuerySvc(const std::wstring& name, const std::wstring& regKey) {
    SvcInfo si;
    si.keyExists = RegKeyExists(HKEY_LOCAL_MACHINE, regKey);
    if (si.keyExists) {
        RegVal st = RegGet(HKEY_LOCAL_MACHINE, regKey, L"Start");
        if (st.exists) si.start = st.dw;
        RegVal ip = RegGet(HKEY_LOCAL_MACHINE, regKey, L"ImagePath");
        if (ip.exists) si.imagePath = ip.s;   // 注意：可能带引号
    }
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, name.c_str(), SERVICE_QUERY_STATUS);
        if (svc) {
            si.scmOpen = true;
            SERVICE_STATUS_PROCESS ssp{};
            DWORD need = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &need)) {
                si.state = ssp.dwCurrentState;
                si.win32Exit = ssp.dwWin32ExitCode;
                si.pid = ssp.dwProcessId;
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    return si;
}

static const wchar_t* SvcStateName(DWORD st) {
    switch (st) {
    case SERVICE_STOPPED:          return L"STOPPED";
    case SERVICE_START_PENDING:    return L"START_PENDING";
    case SERVICE_STOP_PENDING:     return L"STOP_PENDING";
    case SERVICE_RUNNING:          return L"RUNNING";
    case SERVICE_CONTINUE_PENDING: return L"CONTINUE_PENDING";
    case SERVICE_PAUSE_PENDING:    return L"PAUSE_PENDING";
    case SERVICE_PAUSED:           return L"PAUSED";
    default:                       return L"(未知)";
    }
}

// ---------------------------------------------------------------------------
// 进程枚举（原生）
// ---------------------------------------------------------------------------
// 注意：铁律 41 —— tasklist 的表格输出会把映像名截断到 25 字符，长名会静默漏掉。
// 这里用 Toolhelp 拿**完整**文件名，没有截断问题。
static int ListProcesses(const std::wstring& exeLower, std::vector<DWORD>* pids) {
    int n = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring nm = pe.szExeFile;
            for (auto& c : nm) c = towlower(c);
            if (nm == exeLower) {
                if (pids) pids->push_back(pe.th32ProcessID);
                n++;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

// ---------------------------------------------------------------------------
// 日志读取：整个文件读进来，按 CRLF 切行。
// ★ 关键：**不做** ANSI/UTF-8 解码后再找锚点 —— 锚点都是纯 ASCII，
//   直接按**字节**找即可，这样 UTF-8 BOM 和中文内容都不会干扰，
//   也不会因为"解码失败"而丢行（.bat 版在这里吃过 findstr 的亏）。
// ---------------------------------------------------------------------------
struct LogLine {
    size_t offset;
    std::string bytes;   // 原始字节（不含 CRLF）
};

static bool ReadLogRaw(const std::wstring& path, std::string* raw) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    raw->clear();
    if (sz.QuadPart > 0 && sz.QuadPart < (64 << 20)) {
        raw->resize((size_t)sz.QuadPart);
        DWORD got = 0, total = 0;
        while (total < raw->size() &&
               ReadFile(h, &(*raw)[total], (DWORD)(raw->size() - total), &got, nullptr) && got > 0)
            total += got;
        raw->resize(total);
    }
    CloseHandle(h);
    return true;
}

static void SplitLines(const std::string& raw, std::vector<LogLine>* out) {
    out->clear();
    size_t i = 0, start = 0;
    while (i < raw.size()) {
        if (raw[i] == '\n') {
            size_t end = i;
            if (end > start && raw[end - 1] == '\r') end--;   // 去 CR
            LogLine L; L.offset = start; L.bytes = raw.substr(start, end - start);
            out->push_back(L);
            start = i + 1;
        }
        i++;
    }
    if (start < raw.size()) {
        LogLine L; L.offset = start; L.bytes = raw.substr(start);
        out->push_back(L);
    }
}

// ★★ 关键（本程序第一版就在这栽了）：真实日志每行形如
//      "2026-10-05 23:14:28.573  [PRIV] SeTcbPrivilege   FAIL   （...）"
//    锚点**不在行首**，在时间戳之后。所以：
//      · 不能 `compare(0, n, anchor)`（那是 .bat 版注释里写的"行首锚点"，
//        指的是**服务端 Log() 的消息体**从 [PRIV] 开始，不是整行）；
//      · 也不能用裸 `find(anchor)` —— 那会把文档/说明里提到的 "[PRIV]" 也数进来。
//    正确做法：**跳过行首的时间戳**，再从那里比锚点。
//    时间戳形状固定 23 字节："YYYY-MM-DD HH:MM:SS.mmm"（含 BOM 时前面多 3 字节）。
static size_t SkipTimestamp(const std::string& b) {
    size_t i = 0;
    // BOM
    if (b.size() >= 3 && (unsigned char)b[0] == 0xEF &&
        (unsigned char)b[1] == 0xBB && (unsigned char)b[2] == 0xBF) i = 3;
    // 日期 YYYY-MM-DD
    if (b.size() >= i + 10 && b[i + 4] == '-' && b[i + 7] == '-') {
        i += 10;
        if (i < b.size() && b[i] == ' ') i++;
        // 时间 HH:MM:SS.mmm
        if (b.size() >= i + 8 && b[i + 2] == ':' && b[i + 5] == ':') {
            i += 8;
            if (i < b.size() && b[i] == '.') { i++; while (i < b.size() && isdigit((unsigned char)b[i])) i++; }
        }
    }
    while (i < b.size() && b[i] == ' ') i++;   // 吃掉分隔空格
    return i;
}

// 锚点是否出现在"时间戳之后"（= 消息体开头）。这是本程序所有锚点统计的统一口径。
static bool AnchorAt(const std::string& line, const char* anchor) {
    size_t p = SkipTimestamp(line);
    return line.compare(p, strlen(anchor), anchor) == 0;
}

static int CountAnchors(const std::vector<LogLine>& lines, const char* anchor) {
    int n = 0;
    for (auto& L : lines) if (AnchorAt(L.bytes, anchor)) n++;
    return n;
}

// "消息体里包含"（用于 elevated=no / LAUNCH] OK 这类**行内**判据）
static bool BodyContains(const std::string& line, const char* sub) {
    size_t p = SkipTimestamp(line);
    return line.find(sub, p) != std::string::npos;
}
static int CountContains(const std::vector<LogLine>& lines, const char* sub) {
    int n = 0;
    for (auto& L : lines) if (BodyContains(L.bytes, sub)) n++;
    return n;
}

// ---------------------------------------------------------------------------
// [LAST] 行解析：形状固定 "[LAST] <字母> err=<n> session=<n>"
// 逐词扫描，绝不按字段序号取（时间戳自己就带空格，序号会对不上）。
// ---------------------------------------------------------------------------
struct LastRec {
    bool found = false;
    wchar_t code = L'?';
    DWORD err = 0;
    DWORD session = 0;
    std::string rawLine;
};

static LastRec ParseLast(const std::vector<LogLine>& lines) {
    LastRec r;
    const char* A = "[LAST] ";
    for (auto& L : lines) {
        if (!AnchorAt(L.bytes, A)) continue;
        r.found = true;
        r.rawLine = L.bytes;   // 取**最后一条**（最新的一次启动尝试）
        std::string s = L.bytes;
        size_t i = SkipTimestamp(s) + strlen(A);
        // 第一个词 = 单字母 code
        while (i < s.size() && s[i] == ' ') i++;
        if (i < s.size()) r.code = (wchar_t)(unsigned char)s[i];
        // 扫 err= / session=
        size_t p = 0;
        while ((p = s.find("err=", p)) != std::string::npos) {
            r.err = (DWORD)strtoul(s.c_str() + p + 4, nullptr, 10);
            p += 4;
        }
        p = 0;
        while ((p = s.find("session=", p)) != std::string::npos) {
            r.session = (DWORD)strtoul(s.c_str() + p + 8, nullptr, 10);
            p += 8;
        }
    }
    return r;
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------
static const wchar_t* kSvcName  = L"R3ShieldCoreGuard";
static const wchar_t* kSvcExe   = L"r3shieldcore_svc.exe";
static const wchar_t* kDrvName  = L"R3ShieldCoreKernel";
static const wchar_t* kDrvSys   = L"r3shieldcore_kernel.sys";
static const wchar_t* kEngine   = L"R3 ShieldCore.exe";
static const wchar_t* kSvcLog   = L"r3shieldcore-svc.log";

int wmain(int argc, wchar_t** argv) {
    bool json = false;
    bool forcePause = false;
    bool forceNoPause = false;
    std::wstring argDir;
    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        if (a == L"--json") json = true;
        else if (a == L"--pause") forcePause = true;
        else if (a == L"--no-pause" || a == L"--nopause") forceNoPause = true;
        else if (a == L"-h" || a == L"--help" || a == L"/?") {
            OutLine(L"用法：diag_autostart.exe [安装目录] [--json] [--pause|--no-pause]");
            OutLine(L"  不带参数       正常诊断（双击时会自动停住窗口）");
            OutLine(L"  \"D:\\path\"      指定安装目录（默认读注册表 InstallLocation）");
            OutLine(L"  --json         额外输出一段机器可读 JSON");
            OutLine(L"  --pause        结束时强制停住");
            OutLine(L"  --no-pause     结束时不暂停（自动化/重定向用）");
            return 0;
        }
        else if (!a.empty() && a[0] != L'-') argDir = a;
    }
    SetConsoleOutputCP(GetConsoleOutputCP()); // 保持现状

    // ★ 只在"看起来会被一闪就过"的场景才打那条启动提示：
    //   父进程是 cmd.exe（从入口脚本调起）时不需要，避免噪音。
    {
        std::wstring par = ParentProcessName();
        if (par != L"cmd.exe") {
            OutLine(L"");
            OutLine(L"  [启动] R3 ShieldCore 诊断器已启动。若本窗口一闪就过，");
            OutLine(L"         请在 cmd 里跑：  tools\\diag_autostart.exe --pause");
        }
    }

    std::wstring SVCKEY = Fmt(L"SYSTEM\\CurrentControlSet\\Services\\%s", kSvcName);
    std::wstring DRVKEY = Fmt(L"SYSTEM\\CurrentControlSet\\Services\\%s", kDrvName);
    std::wstring UNKEY  = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\R3ShieldCore";

    OutLine(L"======================================================================");
    OutLine(L" R3 ShieldCore 开机自启诊断（原生 C++ 版：不装不删不改不启动）");
    OutLine(L"======================================================================");
    OutLine(L" 说明：本程序**不调用任何外部命令**，全部走 Win32 API。");
    OutLine(L"       所以它不可能出现 bat 版那种「计数恒 0 / (查不出)」的假阴性。");

    // ---------------- 0. 环境 ----------------
    OutLine();
    OutLine(L"=== 0. 环境 ===");

    RegVal man  = RegGet(HKEY_LOCAL_MACHINE,
                         L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer");
    RegVal prod = RegGet(HKEY_LOCAL_MACHINE,
                         L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    std::wstring model = Fmt(L"%s / %s",
        man.s.empty()  ? L"(读不出)" : man.s.c_str(),
        prod.s.empty() ? L"(读不出)" : prod.s.c_str());
    OutLine(Fmt(L"  [信息] 机型          : %s", model.c_str()));
    bool isVM = false;
    for (const wchar_t* kw : { L"vmware", L"virtualbox", L"qemu", L"hyper-v", L"kvm",
                               L"parallels", L"xen", L"bochs", L"virtual machine" }) {
        std::wstring low = model;
        for (auto& c : low) c = towlower(c);
        if (low.find(kw) != std::wstring::npos) { isVM = true; break; }
    }
    OutLine(Fmt(L"  [信息] 是否虚拟机    : %s", isVM ? L"**是**（下面重启相关项要特别看）" : L"否（或未识别）"));

    ULONGLONG tick = GetTickCount64();
    ULONGLONG sec = tick / 1000ULL;
    SYSTEMTIME st{}, local{};
    GetLocalTime(&st);
    // 直接用 tick 反推开机时刻，避免依赖 wmic/net statistics（Win11 起 wmic 已移除）
    ULONGLONG bootUnix = 0;
    {
        FILETIME ft; GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
        bootUnix = (u.QuadPart / 10000000ULL) - sec;   // 秒
    }
    OutLine(Fmt(L"  [信息] 本次开机已运行 : %llu 分 %llu 秒（自报，GetTickCount64）",
                sec / 60, sec % 60));
    {
        // 转成可读本地时间
        ULONGLONG unixSec = bootUnix - 11644473600ULL;   // FILETIME 纪元 -> Unix 纪元
        time_t t = (time_t)unixSec;
        struct tm tmv{};
        localtime_s(&tmv, &t);
        wchar_t b[64]{};
        wcsftime(b, 64, L"%Y-%m-%d %H:%M:%S", &tmv);
        OutLine(Fmt(L"  [信息] 本次开机于    : %s", b));
        if (sec < 300) {
            OutLine(L"  [注意] 刚刚开机不到 5 分钟 —— 若下面的服务/进程还没起来，");
            OutLine(L"         请等 1~2 分钟再跑一次，别急着下结论。");
        }
    }

    RegVal safe = RegGet(HKEY_LOCAL_MACHINE,
                         L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option", L"OptionValue");
    bool safeChecking = false;
    {
        // SafeBoot\Option 存在 + OptionValue 有值 才判"正在跑安全模式"
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option",
                          0, KEY_READ, &h) == ERROR_SUCCESS) {
            safeChecking = safe.exists;
            RegCloseKey(h);
        }
        // 更可靠：查 SafeBoot 下有没有 Network/Minimal 子键且当前是安全模式
        // ★ 权威口径：GetSystemMetrics(SM_CLEANBOOT) —— 服务端也是用它做闸门（铁律 138）
    }
    int cleanboot = GetSystemMetrics(SM_CLEANBOOT);
    if (cleanboot != 0) {
        OutLine(Fmt(L"  [注意] 安全模式      : **是**（SM_CLEANBOOT=%d）", cleanboot));
        OutLine(L"          ★ 安全模式下按设计**不启动**引擎（驱动仍会加载）。这不是故障。");
    } else {
        OutLine(L"  [信息] 安全模式      : 否（正常启动，SM_CLEANBOOT=0）");
    }

    // ---------------- 1. 安装目录与文件 ----------------
    OutLine();
    OutLine(L"=== 1. 安装目录与文件 ===");
    std::wstring DEST, destSrc;
    if (!argDir.empty()) { DEST = argDir; destSrc = L"命令行参数"; }
    else {
        RegVal il = RegGet(HKEY_LOCAL_MACHINE, UNKEY, L"InstallLocation");
        if (il.exists && !il.s.empty()) { DEST = il.s; destSrc = L"注册表 InstallLocation"; }
        else { DEST = L"C:\\Program Files\\R3 ShieldCore"; destSrc = L"默认路径"; }
    }
    OutLine(Fmt(L"  [信息] 安装目录      : %s   （来源：%s）", DEST.c_str(), destSrc.c_str()));

    bool dirOK = false;
    if (DirExists(DEST)) {
        dirOK = true;
        OutLine(L"  [ OK ] 目录存在");
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(DEST.c_str(), GetFileExInfoStandard, &fad)) {
            SYSTEMTIME t2{};
            FileTimeToSystemTime(&fad.ftLastWriteTime, &t2);
            OutLine(Fmt(L"  [信息] 目录时间戳    : %04d-%02d-%02d %02d:%02d:%02d",
                        t2.wYear, t2.wMonth, t2.wDay, t2.wHour, t2.wMinute, t2.wSecond));
            // 安装后有没有真正重启过：拿目录时间 vs 开机时刻
            ULONGLONG instUnix = ((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime << 32 |
                                  fad.ftLastWriteTime.dwLowDateTime) / 10000000ULL
                                 - 11644473600ULL;
            ULONGLONG bootUnix2 = bootUnix - 11644473600ULL;
            if (instUnix > bootUnix2 + 60) {
                OutLine(L"");
                OutLine(L"  [ 断 ] ★ 安装之后**还没有真正重启过**");
                OutLine(Fmt(L"         目录时间比本次开机时刻晚 %llu 秒。", instUnix - bootUnix2));
                OutLine(L"         开机自启**只能靠「重启后」证明**。");
                if (isVM) {
                    OutLine(L"         ★★ VM 专项：虚拟机上的重启必须是**真正的关机再开机**。");
                    OutLine(L"            「挂起 / 保存状态后恢复」**不算重启** —— 内核状态原样恢复，");
                    OutLine(L"            服务的 AUTO_START 不会再触发、驱动的 BOOT_START 也不会重跑；");
                    OutLine(L"            「快照回滚」更糟 —— 它把服务注册和文件一起回滚掉。");
                }
                g_rep.Brk(L"安装后未真正重启");
            }
        }
    } else {
        OutLine(L"  [ 断 ] 目录**不存在**");
        g_rep.Brk(L"安装目录不存在");
    }

    if (dirOK) {
        struct { const wchar_t* label; std::wstring path; bool critical; } files[] = {
            { L"引擎", DEST + L"\\" + kEngine,  true  },
            { L"服务", DEST + L"\\" + kSvcExe,  true  },
            { L"驱动", DEST + L"\\driver\\" + kDrvSys, true },
            { L"日志", DEST + L"\\" + kSvcLog,  false },
        };
        for (auto& f : files) {
            if (FileExists(f.path))
                OutLine(Fmt(L"  [ OK ] %s文件       : %s", f.label, f.path.c_str()));
            else
                OutLine(Fmt(L"  [ %s ] %s文件       : **不存在**  %s",
                            f.critical ? L"断" : L"注意", f.label, f.path.c_str()));
        }
    }

    // ---------------- 2. 驱动层 ----------------
    OutLine();
    OutLine(L"=== 2. 驱动层（BOOT_START，只负责被加载）===");
    SvcInfo drv = QuerySvc(kDrvName, DRVKEY);
    if (!drv.keyExists) {
        OutLine(Fmt(L"  [注意] 服务键 %s **不存在**（驱动没注册）", kDrvName));
        OutLine(L"         -> 只是「没有内核组件」。三层是独立的，**不影响用户态引擎的自启**。");
    } else {
        OutLine(L"  [ OK ] 服务键存在");
        OutLine(Fmt(L"  [信息] Start          : %lu   （期望 0 = Boot）", drv.start));
        OutLine(Fmt(L"  [信息] ImagePath      : %s", drv.imagePath.empty() ? L"(读不出)" : drv.imagePath.c_str()));
        std::wstring drvOnDisk = Fmt(L"%s\\System32\\drivers\\%s",
            [] { wchar_t w[MAX_PATH]{}; GetWindowsDirectoryW(w, MAX_PATH); return std::wstring(w); }().c_str(),
            kDrvSys);
        if (FileExists(Expand(drvOnDisk)))
            OutLine(Fmt(L"  [ OK ] 驱动文件       : 存在  %s", drvOnDisk.c_str()));
        else
            OutLine(Fmt(L"  [ 断 ] 驱动文件       : **不存在**  %s", drvOnDisk.c_str()));
        RegVal lsb = RegGet(HKEY_LOCAL_MACHINE, DRVKEY, L"LoadSinceBootMs");
        if (lsb.exists)
            OutLine(Fmt(L"  [信息] LoadSinceBootMs: %lu  （0 对 BOOT_START 是最正常的结果）", lsb.dw));
        else
            OutLine(L"  [注意] LoadSinceBootMs: 没有这个值（驱动可能还没被加载过）");
    }

    // ---------------- 3. 服务层 ----------------
    OutLine();
    OutLine(L"=== 3. 服务层（AUTO_START，负责把引擎拉进交互会话）===");
    SvcInfo svc = QuerySvc(kSvcName, SVCKEY);
    bool svcOK = false;
    if (!svc.keyExists) {
        OutLine(Fmt(L"  [ 断 ] 服务键 %s **不存在** —— 开机自启根本没注册", kSvcName));
        OutLine(L"         可能原因：装的时候「开机自动启动引擎」那格没勾 / 注册那步失败 /");
        OutLine(L"                   服务被 sc delete 了 / **VM 上回滚了快照**。");
        g_rep.Brk(L"服务键不存在");
    } else {
        svcOK = true;
        OutLine(L"  [ OK ] 服务键存在");
        OutLine(Fmt(L"  [信息] Start          : %lu   （期望 2 = Auto）", svc.start));
        if (svc.start != 2)
            OutLine(L"         ★ Start 不是 2 -> 开机不会自动拉起，即使服务注册正确。");
        OutLine(Fmt(L"  [信息] ImagePath      : %s", svc.imagePath.empty() ? L"(读不出)" : svc.imagePath.c_str()));

        // ★ 铁律 135：「注册项存在」!=「指对了程序」—— 回读目标字段并**校验它指向的文件存在**。
        std::wstring imgTarget = svc.imagePath;
        // ImagePath 可能形如  "C:\path\svc.exe" -args  或  C:\path\svc.exe
        if (!imgTarget.empty() && imgTarget[0] == L'"') {
            size_t e = imgTarget.find(L'"', 1);
            if (e != std::wstring::npos) imgTarget = imgTarget.substr(1, e - 1);
        } else {
            size_t sp = imgTarget.find(L' ');
            if (sp != std::wstring::npos) imgTarget = imgTarget.substr(0, sp);
        }
        imgTarget = Expand(imgTarget);
        if (!svc.imagePath.empty()) {
            if (FileExists(imgTarget))
                OutLine(Fmt(L"  [ OK ] 指向的服务 exe : 存在  %s", imgTarget.c_str()));
            else {
                OutLine(Fmt(L"  [ 断 ] 指向的服务 exe : **不存在** —— %s", imgTarget.c_str()));
                g_rep.Brk(L"服务 ImagePath 指向的文件不存在");
            }
        } else {
            OutLine(L"  [ 断 ] 指向的服务 exe : **读不出 ImagePath**");
            g_rep.Brk(L"服务键缺 ImagePath");
        }

        // SCM 实时状态
        if (svc.scmOpen) {
            OutLine(Fmt(L"  [信息] SCM 实时状态   : %s  pid=%lu  win32Exit=%lu",
                        SvcStateName(svc.state), svc.pid, svc.win32Exit));
            if (svc.state == SERVICE_STOPPED && RegGet(HKEY_LOCAL_MACHINE, SVCKEY, L"Start").dw == 2) {
                OutLine(L"         ★ 服务是 AUTO_START 但当前 STOPPED ——");
                OutLine(L"           如果本次开机已超过 2 分钟，说明**它启动失败了**（去看日志）。");
            }
        } else {
            OutLine(L"  [注意] SCM 里打不开这个服务（可能没权限 / 服务已从 SCM 注销但键还在）");
        }
    }

    // ---------------- 4. 服务日志（第一诊断口径）----------------
    OutLine();
    OutLine(L"=== 4. 服务日志（第一诊断口径）===");
    std::wstring logPath = DEST + L"\\" + kSvcLog;
    if (!FileExists(logPath)) {
        if (svcOK)
            OutLine(Fmt(L"  [ 断 ] 服务日志**不存在**：%s", logPath.c_str()));
        else
            OutLine(Fmt(L"  [提示] 服务日志**不存在**：%s", logPath.c_str()));
        OutLine(L"         -> 服务**从来没被启动过**（服务一起来第一件事就是写日志）。");
        if (svcOK) g_rep.Brk(L"服务日志不存在");
    } else {
        std::string raw;
        if (!ReadLogRaw(logPath, &raw)) {
            OutLine(Fmt(L"  [ 断 ] 日志**打不开**：%s（err=%lu）", logPath.c_str(), GetLastError()));
            OutLine(L"         ★ 这通常是**权限**问题：日志在 Program Files 下，");
            OutLine(L"           而你现在不是管理员。请右键「以管理员身份运行」。");
            g_rep.Brk(L"日志打不开（权限）");
        } else if (raw.empty()) {
            OutLine(Fmt(L"  [注意] 日志存在但**是空的**（0 字节）：%s", logPath.c_str()));
            OutLine(L"         -> 服务起来过但什么都没写（可能刚创建就崩了）。");
        } else {
            std::vector<LogLine> lines;
            SplitLines(raw, &lines);

            // ★ 编码/换行体检：BOM 与裸 LF
            bool hasBOM = raw.size() >= 3 && (unsigned char)raw[0] == 0xEF &&
                          (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF;
            size_t crlf = 0, lf = 0;
            for (size_t i = 0; i < raw.size(); i++) {
                if (raw[i] == '\n') { lf++; if (i > 0 && raw[i-1] == '\r') crlf++; }
            }
            if (lf > 0 && crlf != lf) {
                OutLine(Fmt(L"  [注意] 换行符异常：%zu 个 LF 里只有 %zu 个是 CRLF。", lf, crlf));
                OutLine(L"         真服务写的是 CRLF。裸 LF 会让**按行解析**的工具少算行数 ——");
                OutLine(L"         如果这份日志被编辑器/工具重写过，下面的统计可能偏小。");
            }

            OutLine(Fmt(L"  [信息] 日志物理 %zu 行（本程序按 CRLF/LF 切行，不会少算）",
                        lines.size()));
            OutLine(Fmt(L"  [信息] 编码         : %s", hasBOM ? L"UTF-8 with BOM（正常）" : L"无 BOM"));

            int nPriv   = CountAnchors(lines, "[PRIV] ");
            int nFail   = 0;
            for (auto& L : lines)
                if (AnchorAt(L.bytes, "[PRIV] ") &&
                    (BodyContains(L.bytes, "FAIL   ") || BodyContains(L.bytes, "FAIL  "))) nFail++;
            int nTok    = CountAnchors(lines, "[TOKEN] ");
            int nNoelev = CountContains(lines, "elevated=no");
            int nYesel  = CountContains(lines, "elevated=yes");
            int nUpFail = CountContains(lines, "upgrade=FAIL");
            int nFbOK   = CountContains(lines, "fallback=OK");
            int nLOK    = CountContains(lines, "LAUNCH] OK");
            int nLFAIL  = CountContains(lines, "LAUNCH] FAIL");
            int nAsFail = CountContains(lines, "asuser=FAIL");
            int nLast   = CountAnchors(lines, "[LAST] ");
            LastRec last = ParseLast(lines);

            OutLine(L"  [信息] 服务日志锚点统计（下面「关键行」是逐字原文）：");
            OutLine(Fmt(L"         · 拉起成功    [LAUNCH] OK    : %d", nLOK));
            OutLine(Fmt(L"         · 拉起失败    [LAUNCH] FAIL  : %d", nLFAIL));
            OutLine(Fmt(L"         · 令牌事实行  [TOKEN]        : %d", nTok));
            OutLine(Fmt(L"         · 令牌没提权  elevated=no    : %d", nNoelev));
            OutLine(Fmt(L"         · 令牌已提权  elevated=yes   : %d", nYesel));
            OutLine(Fmt(L"         · 升级失败    upgrade=FAIL   : %d", nUpFail));
            OutLine(Fmt(L"         · 退保底路    fallback=OK    : %d", nFbOK));
            OutLine(Fmt(L"         · 特权失败行  [PRIV] FAIL    : %d / %d 条 [PRIV]", nFail, nPriv));
            OutLine(Fmt(L"         · 拉起尝试    [LAST]         : %d", nLast));

            // 交叉约束（铁律 110：先问"全零时是否也成立"）
            if (nLOK + nLFAIL != nLast && nLast > 0)
                OutLine(Fmt(L"  [警告] 计数不自洽：OK+FAIL=%d 但 [LAST]=%d —— 解析可能有问题。",
                            nLOK + nLFAIL, nLast));

            // ★ 读到了吗？前提检查
            if (nPriv == 0 && nTok == 0 && nLOK == 0 && nLFAIL == 0 && nLast == 0) {
                OutLine(Fmt(L"  [ 断 ] **日志读不出内容**（%zu 字节，但没有一个已知锚点）。", raw.size()));
                OutLine(L"         -> 下面的根因判定**已停用**，因为盘点都是 0，「没看见」和「没发生」分不开。");
                OutLine(L"         请把这份日志原文贴出来。");
                g_rep.Brk(L"日志读不出内容（锚点全 0）");
            } else {
                // 关键行原文
                OutLine(L"");
                OutLine(L"  ---- 关键行（逐字原文）----");
                for (auto& L : lines) {
                    if (AnchorAt(L.bytes, "[PRIV] ") && BodyContains(L.bytes, "FAIL")) {
                        OutLine(L"    " + RawToWide(L.bytes));
                    }
                }
                for (auto& L : lines)
                    if (AnchorAt(L.bytes, "[TOKEN] ")) {
                        OutLine(L"    " + RawToWide(L.bytes)); break;
                    }
                if (last.found)
                    OutLine(L"    " + RawToWide(last.rawLine));

                // ---------------- 5. 根因判定 ----------------
                OutLine(L"");
                OutLine(L"=== 5. 根因判定 ===");
                if (last.found) {
                    const wchar_t* meaning = L"";
                    const wchar_t* fix = L"";
                    switch (last.code) {
                    case L'O': meaning = L"成功"; break;
                    case L'P':
                        meaning = L"缺特权（err=1314）";
                        fix = L"令牌里「有」特权 != 「能用」。看上面 [PRIV] 的 FAIL 行是哪几条。";
                        break;
                    case L'E':
                        meaning = L"令牌没提权（err=740）";
                        fix = L"引擎清单要求管理员，但拿到的是未提权令牌。看 [TOKEN] 行。";
                        break;
                    case L'S':
                        meaning = L"拿不到可用令牌 / 令牌升级也失败";
                        fix = L"看 [TOKEN] upgrade=FAIL / fallback=FAIL 的 err=。";
                        break;
                    case L'C':
                        meaning = L"CreateProcess 失败（其它原因）";
                        fix = L"看 [LAUNCH] FAIL 那行的 err= 具体值。";
                        break;
                    case L'X':
                        meaning = L"进程建出来了但**秒退**（引擎自己挂了）";
                        fix = L"去看引擎自己的启动日志（不是服务日志）。";
                        break;
                    default:
                        meaning = L"(未知代码)";
                        fix = L"请把 [LAST] 原文贴出来。";
                        break;
                    }
                    OutLine(Fmt(L"  [LAST] 代码=%c  err=%lu  session=%lu", last.code, last.err, last.session));
                    OutLine(Fmt(L"         含义：%s", meaning));
                    if (fix[0]) OutLine(Fmt(L"         下一步：%s", fix));
                    if (last.code == L'O') {
                        OutLine(L"");
                        OutLine(L"  [ OK ] 服务**成功拉起过引擎**。");
                        OutLine(Fmt(L"         （最近一次 session=%lu。若引擎现在不在，可能是之后被用户关掉了。）",
                                    last.session));
                    } else {
                        g_rep.Brk(Fmt(L"最近一次拉起结果=%c err=%lu", last.code, last.err));
                    }
                } else {
                    OutLine(L"  [注意] 日志里没有 [LAST] 行 —— 服务还没走到「拉起引擎」那一步。");
                    if (nTok == 0)
                        OutLine(L"         · 连 [TOKEN] 都没有 -> 服务可能在拿令牌之前就退出了。");
                }

                // 特权失败清单（不依赖 [LAST]）
                if (nFail > 0 && (!last.found || last.code != L'O')) {
                    OutLine(L"");
                    OutLine(Fmt(L"  ★ 有 %d 条 [PRIV] FAIL —— 这些特权没打开，是拉起失败的直接原因：", nFail));
                    for (auto& L : lines) {
                        if (AnchorAt(L.bytes, "[PRIV] ") && BodyContains(L.bytes, "FAIL"))
                            OutLine(L"    " + RawToWide(L.bytes));
                    }
                }

                // ★ 假根因守卫（铁律：曾经 elevated=no 是正常中间态，不能因此定罪）
                if (nNoelev > 0 && nYesel == 0 && nLOK == 0) {
                    OutLine(L"");
                    OutLine(L"  [注意] 日志里出现过 elevated=no 且**从没** elevated=yes、也没成功拉起过：");
                    OutLine(L"         令牌始终没提权 -> 这条路**必失败**。看 [TOKEN] 相关行。");
                }
            }
        }
    }

    // ---------------- 6. 引擎进程 ----------------
    OutLine();
    OutLine(L"=== 6. 引擎进程 ===");
    std::wstring engLow = kEngine;
    for (auto& c : engLow) c = towlower(c);
    std::vector<DWORD> pids;
    int engN = ListProcesses(engLow, &pids);
    if (engN < 0) {
        OutLine(L"  [注意] 进程枚举失败（CreateToolhelp32Snapshot 出错）");
    } else if (engN == 0) {
        OutLine(Fmt(L"  [注意] 引擎**没在跑**（%s）", kEngine));
        OutLine(L"         （开机自启成功的话，这里应该有；但如果你等下只是看结论，");
        OutLine(L"           注意「服务拉起过」和「现在还在跑」是两件事。）");
        // ★ 不当即判"自启失败"：用户可能手动关了它。
        if (svcOK) {
            RegVal st = RegGet(HKEY_LOCAL_MACHINE, SVCKEY, L"Start");
            if (st.dw == 2 && tick < 120000ULL) {
                OutLine(L"         ★ 本次开机还不到 2 分钟，别急 —— 再等等看。");
            }
        }
    } else {
        std::wstring list;
        for (DWORD p : pids) list += Fmt(L"%lu ", p);
        OutLine(Fmt(L"  [ OK ] 引擎在跑      : %d 个进程，pid = %s", engN, list.c_str()));
    }

    // SCM 自己的 pid 也报一下（服务进程）
    {
        std::wstring sl = kSvcExe; for (auto& c : sl) c = towlower(c);
        std::vector<DWORD> sp;
        int sn = ListProcesses(sl, &sp);
        if (sn > 0) {
            std::wstring l; for (DWORD p : sp) l += Fmt(L"%lu ", p);
            OutLine(Fmt(L"  [信息] 服务进程      : %d 个，pid = %s", sn, l.c_str()));
        } else {
            OutLine(L"  [信息] 服务进程      : 没在跑（服务是按需起来拉引擎的，拉完可能就退）");
        }
    }

    // ---------------- 7. 汇总裁决 ----------------
    OutLine();
    OutLine(L"======================================================================");
    OutLine(L" 7. 汇总裁决");
    OutLine(L"======================================================================");
    if (g_rep.breaks.empty()) {
        OutLine(L"  [ PASS ] 没发现断点。");
        if (engN > 0) OutLine(L"           引擎正在运行 —— 开机自启**看起来是好的**。");
        else          OutLine(L"           但引擎当前不在跑；如果你刚重启过并且没手动关它，请复查日志。");
    } else {
        OutLine(Fmt(L"  [ FAIL ] 发现 %zu 处断点（按发现顺序）：", g_rep.breaks.size()));
        for (size_t i = 0; i < g_rep.breaks.size(); i++)
            OutLine(Fmt(L"           %zu) %s", i + 1, g_rep.breaks[i].c_str()));
        OutLine(L"");
        OutLine(L"  ★ 上面这些是**这台机器上的事实**，不是猜的 —— 本程序不 shell out，");
        OutLine(L"    所以不会出现「计数恒 0 导致假结论」那种情况。");
    }
    OutLine(L"======================================================================");
    OutLine(L"（只读诊断：本程序不装、不删、不改、不启动任何东西）");
    OutLine(L"用法：tools\\diag_autostart.exe [安装目录] [--json] [--no-pause]");

    if (json) {
        // 机器可读（简单起见，追加一段 JSON）
        OutLine(L"{");
        OutLine(Fmt(L"  \"dir\": \"%s\",", DEST.c_str()));
        OutLine(Fmt(L"  \"service_key_exists\": %s,", svc.keyExists ? L"true" : L"false"));
        OutLine(Fmt(L"  \"service_start\": %lu,", svc.start));
        OutLine(Fmt(L"  \"driver_key_exists\": %s,", drv.keyExists ? L"true" : L"false"));
        OutLine(Fmt(L"  \"engine_processes\": %d,", engN < 0 ? 0 : engN));
        OutLine(Fmt(L"  \"breaks\": %zu,", g_rep.breaks.size()));
        OutLine(L"  \"breaks_list\": [");
        for (size_t i = 0; i < g_rep.breaks.size(); i++)
            OutLine(Fmt(L"    \"%s\"%s", g_rep.breaks[i].c_str(),
                        i + 1 < g_rep.breaks.size() ? L"," : L""));
        OutLine(L"  ]");
        OutLine(L"}");
    }

    // ★ 最后一步：按需停住窗口（双击场景）—— 必须在**所有输出之后**，
    //   且必须在 return 之前（否则窗口会在用户看到结果前关掉）。
    MaybePause(forcePause, forceNoPause);

    return g_rep.breaks.empty() ? 0 : 10;
}
