// redirect_probe.cpp -- 证明 GUI 子系统进程「无标准句柄」时 stdout 重定向的可行路径。
//
// 背景（v33）：R3ShieldCore 是 -SUBSYSTEM:WINDOWS。自检实测
//   [diag] redirect ... stdoutFd=-2 dup2Out=-1
// 即 _fileno(stdout) == -2 -> _dup2 必然失败 -> printf 全丢。
//
// 注意：从 bash/mintty 直接启动 GUI exe 时，子进程**继承了有效 std 句柄**，
//   _fileno(stdout) == 1，_dup2 反而成功 —— 这样测不出问题。
//   必须复现「无标准句柄」条件：本探针默认作为**启动器**，
//   用 DETACHED_PROCESS + STARTF_USESTDHANDLES(NULL) + 不继承句柄
//   重新拉起自己（--child），子进程才会得到 _fileno(stdout) == -2。
//
// 编译：-SUBSYSTEM:WINDOWS（与产品一致），运行无需管理员。

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <string>
#include <fstream>

#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include <windows.h>

namespace {

std::wstring ModuleDir()
{
    wchar_t path[MAX_PATH * 4] = {};
    const DWORD n = GetModuleFileNameW(nullptr, path, _countof(path));
    if (n == 0) return std::wstring();
    std::wstring full(path, n);
    const size_t slash = full.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : full.substr(0, slash);
}

std::wstring ModulePath()
{
    wchar_t path[MAX_PATH * 4] = {};
    const DWORD n = GetModuleFileNameW(nullptr, path, _countof(path));
    return n == 0 ? std::wstring() : std::wstring(path, n);
}

void Note(const std::wstring& dir, const std::string& line)
{
    std::ofstream out(std::wstring(dir) + L"\\redirect-probe-result.log",
                      std::ios::out | std::ios::app);
    if (out) out << line << std::endl;
}

std::string Num(long long v) { return std::to_string(v); }

// --child 分支：真正的重定向测试。
int RunChildTest(const std::wstring& dir)
{
    const int fdOut = _fileno(stdout);
    const int fdErr = _fileno(stderr);
    Note(dir, "[probe-child] _fileno(stdout)=" + Num(fdOut) +
                  "  _fileno(stderr)=" + Num(fdErr));

    // ---- A) 旧做法：_wsopen_s + _dup2 --------------------------------------
    const std::wstring targetA = dir + L"\\redirect-probe-target.log";
    int handle = -1;
    const errno_t openRc = _wsopen_s(&handle, targetA.c_str(),
        _O_CREAT | _O_WRONLY | _O_APPEND | _O_TEXT, _SH_DENYNO,
        _S_IREAD | _S_IWRITE);
    errno = 0;
    const int dup2Rc = (handle >= 0) ? _dup2(handle, fdOut) : -999;
    Note(dir, "[probe-child] A _wsopen_s rc=" + Num(openRc) + " fd=" + Num(handle) +
                  " ; _dup2(fd," + Num(fdOut) + ") rc=" + Num(dup2Rc) +
                  " errno=" + Num(errno) + "  => " +
                  (dup2Rc == 0 ? "OK" : "FAILED(旧做法证实不可用)"));

    // ---- B) 新做法：_wfreopen_s 重建流 -------------------------------------
    const std::wstring targetB = dir + L"\\redirect-probe-freopen.log";
    FILE* reopened = nullptr;
    errno = 0;
    const errno_t freRc = _wfreopen_s(&reopened, targetB.c_str(), L"a", stdout);
    Note(dir, "[probe-child] B _wfreopen_s rc=" + Num(freRc) + " errno=" + Num(errno) +
                  " stream=" + (reopened ? "non-null" : "null") +
                  "  => " + (freRc == 0 ? "OK(新做法可用)" : "FAILED"));

    if (freRc == 0) {
        setvbuf(stdout, nullptr, _IONBF, 0);
        printf("[probe-child] printf-sentinel pid=%lu (this line proves freopen worked)\n",
               static_cast<unsigned long>(GetCurrentProcessId()));
        fflush(stdout);
        Note(dir, "[probe-child] printf sentinel emitted -> see redirect-probe-freopen.log");
    }
    return 0;
}

// 默认分支：以「无标准句柄」方式拉起 --child。
int SpawnChild(const std::wstring& dir, const std::wstring& self)
{
    std::wstring cmd = L"\"" + self + L"\" --child";
    std::wstring mutableCmd(cmd);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;
    si.hStdOutput = nullptr;   // ★ 关键：不给任何标准句柄
    si.hStdError = nullptr;

    PROCESS_INFORMATION pi = {};
    const BOOL ok = CreateProcessW(
        self.c_str(), mutableCmd.data(),
        nullptr, nullptr, FALSE,                       // bInheritHandles = FALSE
        DETACHED_PROCESS | CREATE_NO_WINDOW,           // 无控制台
        nullptr, dir.c_str(), &si, &pi);

    Note(dir, std::string("[probe-launcher] CreateProcessW DETACHED+NULL-handles ok=") +
                  (ok ? "1" : "0") + " err=" + Num(ok ? 0 : GetLastError()));

    if (!ok) return 1;

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    Note(dir, "[probe-launcher] child exit=" + Num(exitCode));
    return 0;
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR cmdLine, int)
{
    const std::wstring dir = ModuleDir();
    const std::wstring self = ModulePath();
    if (dir.empty() || self.empty()) return 1;

    const bool isChild = cmdLine && wcsstr(cmdLine, L"--child") != nullptr;
    if (isChild) return RunChildTest(dir);

    // 启动前清空旧结果。
    DeleteFileW((dir + L"\\redirect-probe-result.log").c_str());
    DeleteFileW((dir + L"\\redirect-probe-target.log").c_str());
    DeleteFileW((dir + L"\\redirect-probe-freopen.log").c_str());
    return SpawnChild(dir, self);
}
