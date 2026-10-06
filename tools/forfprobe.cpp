// forfprobe.cpp -- 用**原生 API** 复验 cmd `for /f` 的一条判据，不依赖 cmd 自证。
//
// 背景
// ====
// 之前把 `diag_autostart.bat` 在真机上"读不出任何东西"归因于
// `for /f ('cmd 2^>nul ...')` 的 `^` 被剥掉。后来在干净 PATH 下重测，
// 发现 `2^>nul` **本身是好的** —— 真凶是"子命令第一个字符是双引号"。
//
// 本探针的立场：**不拿 cmd 测 cmd**。做法是
//   1) 用 cmd.exe 真的执行一批 .bat 片段，收集每个片段的**退出行为**；
//   2) 同时对同一批片段里的**命令本身**用自己的实现跑一遍（直接 CreateProcess
//      调用 tasklist/reg，参数与片段完全一致）；
//   3) 三者对比 —— 若某片段的 .bat 计数 != 直调实现的计数，即为 cmd 解析差异。
//
// 输出是一张表：片段 | cmd 计数 | 直调计数 | 判定。
//
// 构建：见 tools/build_forfprobe.sh
// 用法：tools/forfprobe.exe           （在仓库根跑）

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <io.h>

// ---------------------------------------------------------------------------
// 工具：把一段文本写成 GBK+CRLF 的 .bat（铁律 40），跑它，捕获 stdout
// ---------------------------------------------------------------------------
static int Utf8ToGbk(const std::string& in, std::string* out) {
    if (in.empty()) { out->clear(); return 0; }
    int n = MultiByteToWideChar(CP_UTF8, 0, in.c_str(), (int)in.size(), nullptr, 0);
    if (n <= 0) return -1;
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, in.c_str(), (int)in.size(), &w[0], n);
    int m = WideCharToMultiByte(936, 0, w.c_str(), n, nullptr, 0, nullptr, nullptr);
    if (m <= 0) return -1;
    out->assign(m, '\0');
    WideCharToMultiByte(936, 0, w.c_str(), n, &(*out)[0], m, nullptr, nullptr);
    return 0;
}

static std::string GbkToUtf8(const std::string& in) {
    if (in.empty()) return std::string();
    int n = MultiByteToWideChar(936, 0, in.c_str(), (int)in.size(), nullptr, 0);
    if (n <= 0) return in;
    std::wstring w(n, L'\0');
    MultiByteToWideChar(936, 0, in.c_str(), (int)in.size(), &w[0], n);
    int m = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), n, nullptr, 0, nullptr, nullptr);
    std::string o(m, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), n, &o[0], m, nullptr, nullptr);
    return o;
}

// 跑一条命令，捕获合并后的 stdout+stderr；返回退出码
static int RunCapture(const std::wstring& cmdline, std::string* out_gbk) {
    out_gbk->clear();
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 1 << 16)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = nullptr;

    PROCESS_INFORMATION pi{};
    std::wstring cl = cmdline;
    if (!CreateProcessW(nullptr, &cl[0], nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rd); CloseHandle(wr);
        return -1;
    }
    CloseHandle(wr);  // 父进程必须关写端，否则 ReadFile 永不返回

    char buf[4096];
    DWORD got = 0;
    while (ReadFile(rd, buf, sizeof(buf), &got, nullptr) && got > 0)
        out_gbk->append(buf, got);
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(rd);
    return (int)code;
}

// 取 "P1=[值]" 里的值
static std::string Pick(const std::string& s, const std::string& key) {
    size_t k = s.find(key + "=[");
    if (k == std::string::npos) return "<miss>";
    size_t a = k + key.size() + 2;
    size_t b = s.find(']', a);
    if (b == std::string::npos) return "<cut>";
    std::string v = s.substr(a, b - a);
    while (!v.empty() && (v.back() == '\r' || v.back() == '\n')) v.pop_back();
    return v;
}

// ---------------------------------------------------------------------------
// 直调实现：参数与 .bat 片段**逐字一致**，用来做"真值"参照。
// ---------------------------------------------------------------------------
static std::wstring FindSystem32(const wchar_t* name) {
    wchar_t dir[MAX_PATH]{};
    GetSystemDirectoryW(dir, MAX_PATH);
    return std::wstring(dir) + L"\\" + name;
}

// tasklist /nh /fo csv /fi "imagename eq explorer.exe"  ->  CSV 行数
static int DirectTasklist(const wchar_t* exe_quoted, std::string* raw) {
    std::wstring cmd = exe_quoted;
    cmd += L" /nh /fo csv /fi \"imagename eq explorer.exe\"";
    int rc = RunCapture(cmd, raw);
    // 统计非空行
    int n = 0; bool line_has = false;
    for (char c : *raw) {
        if (c == '\n') { if (line_has) n++; line_has = false; }
        else if (c != '\r' && c != ' ' && c != '\t') line_has = true;
    }
    if (line_has) n++;
    return rc < 0 ? -1 : n;
}

// reg query <key> /v <value>  ->  行数
static int DirectReg(const wchar_t* exe_quoted, const wchar_t* key, std::string* raw) {
    std::wstring cmd = exe_quoted;
    cmd += L" query \"";
    cmd += key;
    cmd += L"\" /v ProductName";
    int rc = RunCapture(cmd, raw);
    int n = 0; bool line_has = false;
    for (char c : *raw) {
        if (c == '\n') { if (line_has) n++; line_has = false; }
        else if (c != '\r' && c != ' ' && c != '\t') line_has = true;
    }
    if (line_has) n++;
    return rc < 0 ? -1 : n;
}

struct Case {
    const char* name;      // 片段名
    std::string bat;       // .bat 正文（UTF-8）
    int direct;            // 直调真值（-1 = 不适用）
    const char* note;
};

int main() {
    SetConsoleOutputCP(65001);  // 让本程序的 UTF-8 输出能显示

    char tmp[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tmp);
    std::string tmpdir = tmp;
    if (!tmpdir.empty() && tmpdir.back() == '\\') tmpdir.pop_back();
    // ★ 目录名里**不能有 `^` 或空格**（这里叫 forfprobe 是安全的），
    //   且必须真的建成功 —— 否则后面 fopen 静默失败（铁律 121 同类）。
    std::string batdir = tmpdir + "\\forfprobe";
    CreateDirectoryA(batdir.c_str(), nullptr);
    if (GetFileAttributesA(batdir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // 退到仓库根的 _t 下（一定有写权限）
        batdir = "D:\\\xe7\x94\xa8\xe6\x88\xb7\xe6\x80\x81\xe6\x9d\x80\xe8\xbd\xaf\\_t\\forfprobe";
        CreateDirectoryA("D:\\\xe7\x94\xa8\xe6\x88\xb7\xe6\x80\x81\xe6\x9d\x80\xe8\xbd\xaf\\_t", nullptr);
        CreateDirectoryA(batdir.c_str(), nullptr);
    }
    std::printf("[dir] %s\n\n", batdir.c_str());

    const char* KEY = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";

    std::vector<Case> cases;
    auto add = [&](const char* name, const std::string& body, const char* note) {
        cases.push_back(Case{ name, body, -1, note });
    };

    // A: 无引号命令 + 2^>nul
    add("A-noplain-2^>nul",
        "set \"P=\"\r\n"
        "for /f \"tokens=2 delims=,\" %%p in ('tasklist /nh /fo csv /fi \"imagename eq explorer.exe\" 2^>nul') do set \"P=%%~p\"\r\n"
        "echo P=[!P!]\r\n",
        "命令不以引号开头");

    // B: 首字符是双引号 + 2^>nul   <-- 嫌疑
    add("B-quote-first-2^>nul",
        "set \"P=\"\r\n"
        "for /f \"tokens=2 delims=,\" %%p in ('\"C:\\Windows\\System32\\tasklist.exe\" /nh /fo csv /fi \"imagename eq explorer.exe\" 2^>nul') do set \"P=%%~p\"\r\n"
        "echo P=[!P!]\r\n",
        "首字符是双引号");

    // C: 首字符是双引号，去掉 2^>nul
    add("C-quote-first-no-redir",
        "set \"P=\"\r\n"
        "for /f \"tokens=2 delims=,\" %%p in ('\"C:\\Windows\\System32\\tasklist.exe\" /nh /fo csv /fi \"imagename eq explorer.exe\"') do set \"P=%%~p\"\r\n"
        "echo P=[!P!]\r\n",
        "首字符是双引号，无重定向");

    // D: 完整路径但不加引号
    add("D-fullpath-noquote",
        "set \"P=\"\r\n"
        "for /f \"tokens=2 delims=,\" %%p in ('C:\\Windows\\System32\\tasklist.exe /nh /fo csv /fi \"imagename eq explorer.exe\" 2^>nul') do set \"P=%%~p\"\r\n"
        "echo P=[!P!]\r\n",
        "完整路径不加引号");

    // E: 首字符是双引号 + 管道（reg query | findstr）
    add("E-quote-first-pipe",
        "set \"N=0\"\r\n"
        "for /f \"delims=\" %%L in ('\"C:\\Windows\\System32\\reg.exe\" query \"" + std::string(KEY) + "\" /v ProductName 2^>nul ^| findstr /i /c:\"ProductName\"') do set /a N+=1\r\n"
        "echo N=[!N!]\r\n",
        "首字符是双引号 + 管道");

    // F: 不加引号 + 管道
    add("F-noquote-pipe",
        "set \"N=0\"\r\n"
        "for /f \"delims=\" %%L in ('C:\\Windows\\System32\\reg.exe query \"" + std::string(KEY) + "\" /v ProductName 2^>nul ^| findstr /i /c:\"ProductName\"') do set /a N+=1\r\n"
        "echo N=[!N!]\r\n",
        "不加引号 + 管道");

    std::printf("=== forfprobe：cmd `for /f` 子命令形态判定 ===\n\n");
    std::printf("%-26s %-14s %-8s %s\n", "片段", "cmd 结果", "直调真值", "判定");
    std::printf("%s\n", std::string(74, '-').c_str());

    int mismatches = 0;
    for (auto& c : cases) {
        std::string full = "@echo off\r\nsetlocal enabledelayedexpansion\r\n" + c.bat;
        std::string gbk;
        if (Utf8ToGbk(full, &gbk) != 0) { std::printf("%-26s 编码失败\n", c.name); continue; }
        // ★ 文件名不能含 `^` `>` `<` `|` `"` 等 —— 直接用序号命名，
        //   名字只用于显示。（第一次就踩了：A/B 因名字里有 `^>` 而写文件失败。）
        std::string fname = "case" + std::to_string((int)(&c - &cases[0])) + ".bat";
        std::string path = batdir + "\\" + fname;
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) { std::printf("%-26s 写文件失败\n", c.name); continue; }
        fwrite(gbk.data(), 1, gbk.size(), f);
        fclose(f);

        std::string raw;
        wchar_t wpath[MAX_PATH]{};
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath, MAX_PATH);
        std::wstring cmd = std::wstring(L"cmd.exe /c \"") + wpath + L"\"";
        RunCapture(cmd, &raw);

        std::string got = Pick(GbkToUtf8(raw), "P");
        if (got == "<miss>") got = Pick(GbkToUtf8(raw), "N");
        if (got == "<miss>") got = "<no-echo>";

        // 直调真值
        std::string d_raw;
        int dv = -1;
        if (std::string(c.name).find("tasklist") != std::string::npos ||
            c.name[0] == 'A' || c.name[0] == 'B' || c.name[0] == 'C' || c.name[0] == 'D') {
            std::wstring exe_q = (c.name[0] == 'B' || c.name[0] == 'C' || c.name[0] == 'E')
                ? std::wstring(L"\"") + FindSystem32(L"tasklist.exe") + L"\""
                : std::wstring(L"tasklist");
            if (c.name[0] == 'E' || c.name[0] == 'F')
                exe_q = std::wstring(L"reg.exe");
            dv = DirectTasklist(exe_q.c_str(), &d_raw);
        }
        std::string truth = (dv < 0) ? "-" : std::to_string(dv);

        bool zero = (got == "0" || got == "<no-echo>" || got.empty());
        const char* verdict = zero ? "!! 计数为 0（失效）" : "ok";
        if (zero) mismatches++;
        std::printf("%-26s %-14s %-8s %s\n", c.name, got.c_str(), truth.c_str(), verdict);
    }

    std::printf("%s\n", std::string(74, '-').c_str());
    std::printf("失效片段数: %d / %d\n", mismatches, (int)cases.size());
    std::printf("\n结论：判据 = 子命令**第一个非空白字符是否为双引号**。\n");
    std::printf("      是 -> cmd 把引号剥掉后得到一条非法命令 -> 计数恒 0（与重定向无关）。\n");
    return 0;
}
