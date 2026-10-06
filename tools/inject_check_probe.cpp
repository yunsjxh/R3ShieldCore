// inject_check_probe.cpp -- 判断"某个 exe 会不会被引擎注入"，并跑 v53 豁免的整套验证。
//
// 三种身份（同一个二进制，省得编一堆）：
//   ① 不带参数            -> 当**靶子**：睡 15 秒，等引擎来注入（或不来）。
//   ② <targetExePath>     -> 当**检查器**：启动目标，等一会儿，用模块枚举看它
//                             到底有没有加载 `r3shieldcore-lib.dll`。
//   ③ --suite <engine> <exemptTarget> <controlTarget>
//                         -> 当**套件运行器**：起引擎 -> 测两个靶子 -> 关引擎。
//
// ★★ 为什么要有 ③（而不是让 bash 脚本去起引擎）：
//   引擎跑着的时候会拦"跨进程内存写入"（`hook_memory_op`）。而 **MSYS2 的
//   `fork()` 正是靠写子进程栈来实现的** —— 于是引擎一跑起来，bash 里所有
//   `$(...)` / 管道 / 后台任务全部失败：
//     `bash: fork: Resource temporarily unavailable`
//     `child_copy: stack write copy failed ... Win32 error 5`
//   把"起引擎 + 测试 + 关引擎"整个塞进一个 exe，bash 在引擎存活期间
//   一次 fork 都不做，这个坑就绕过去了。
//
// ★ 为什么用**模块枚举**当判据，而不是只看引擎日志：
//   "日志里没有跳过行" 是**缺席证据** —— 引擎没跑、日志被轮转、
//   LOG 走了别的文件，都会造成同样的现象。而"目标进程里有没有那颗 DLL"
//   是**在场证据**，直接回答"注入了没有"（铁律 59）。
//
// 用法：
//   inject_check_probe.exe                       # 当靶子（睡 15s）
//   inject_check_probe.exe <targetExePath>       # 检查 targetExePath
//   inject_check_probe.exe --suite <engine> <exemptTarget> <controlTarget>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>
#include <tlhelp32.h>

namespace {

constexpr PCWSTR kEngineDll = L"r3shieldcore-lib.dll";
// 引擎日志里那条"点名豁免"的行（v53）。
constexpr char kSkipMarkerUtf8[] = "跳过内置豁免进程注入(VMware Tools)";

int g_pass = 0;
int g_fail = 0;

void Check(const char* what, bool ok)
{
	printf("[suite] %-58s %s\n", what, ok ? "OK" : "**FAIL**");
	if (ok) {
		++g_pass;
	}
	else {
		++g_fail;
	}
}

bool HasEngineDll(DWORD pid)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("[check] WARN: CreateToolhelp32Snapshot(pid=%lu) err=%lu\n",
			pid, GetLastError());
		return false;
	}

	bool found = false;
	MODULEENTRY32W entry = {};
	entry.dwSize = sizeof(entry);
	if (Module32FirstW(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szModule, kEngineDll) == 0) {
				found = true;
				break;
			}
		} while (Module32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return found;
}

// 启动 target，轮询等引擎 DLL 出现。返回 true = 被注入。
bool ProbeTarget(const char* target)
{
	std::string commandLine = std::string("\"") + target + "\"";
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessA(target, commandLine.data(), nullptr, nullptr, FALSE,
			0, nullptr, nullptr, &si, &pi)) {
		printf("[check] FAIL: CreateProcess(%s) err=%lu\n", target, GetLastError());
		return false;
	}

	printf("[check] target=%s pid=%lu\n", target, pi.dwProcessId);

	bool injected = false;
	for (int i = 0; i < 30; ++i) {   // 最多 3 秒
		if (HasEngineDll(pi.dwProcessId)) {
			injected = true;
			break;
		}
		if (WaitForSingleObject(pi.hProcess, 0) != WAIT_TIMEOUT) {
			printf("[check] target exited early\n");
			break;
		}
		Sleep(100);
	}

	printf("[check] ENGINE_DLL_LOADED=%d -> %s\n",
		injected ? 1 : 0, injected ? "INJECTED" : "NOT-INJECTED");

	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return injected;
}

// 文件里是否含某串（UTF-8 与 UTF-16LE 两种编码都试 —— 引擎日志是混合编码）。
bool FileContains(const std::wstring& path, const char* needle)
{
	FILE* f = nullptr;
	if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) {
		return false;
	}
	fseek(f, 0, SEEK_END);
	const long size = ftell(f);
	fseek(f, 0, SEEK_SET);
	std::vector<char> data(static_cast<size_t>(size > 0 ? size : 0));
	if (size > 0) {
		fread(data.data(), 1, static_cast<size_t>(size), f);
	}
	fclose(f);

	if (data.empty()) {
		return false;
	}

	const std::string utf8(needle);
	if (std::search(data.begin(), data.end(), utf8.begin(), utf8.end()) != data.end()) {
		return true;
	}

	// UTF-16LE：把 needle 转成宽字符再按字节找。
	const int wideLen = MultiByteToWideChar(CP_UTF8, 0, needle, -1, nullptr, 0);
	if (wideLen > 1) {
		std::wstring wide(static_cast<size_t>(wideLen - 1), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, needle, -1, wide.data(), wideLen);
		const char* raw = reinterpret_cast<const char*>(wide.data());
		const size_t rawBytes = wide.size() * sizeof(WCHAR);
		if (std::search(data.begin(), data.end(), raw, raw + rawBytes) != data.end()) {
			return true;
		}
	}
	return false;
}

std::wstring DirOf(const std::wstring& filePath)
{
	const size_t slash = filePath.find_last_of(L"\\/");
	return (slash == std::wstring::npos) ? std::wstring() : filePath.substr(0, slash + 1);
}

std::wstring Widen(const char* utf8)
{
	const int need = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
	if (need <= 1) {
		return {};
	}
	std::wstring out(static_cast<size_t>(need - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out.data(), need);
	return out;
}

int RunSuite(const char* engine, const char* exemptTarget, const char* controlTarget)
{
	const std::wstring engineWide = Widen(engine);
	const std::wstring engineDir = DirOf(engineWide);
	const std::wstring consoleLog = engineDir + L"r3shieldcore-console.log";

	DeleteFileW(consoleLog.c_str());

	std::string commandLine = std::string("\"") + engine + "\"";
	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	std::wstring engineCmdLine = Widen(commandLine.c_str());
	if (!CreateProcessW(engineWide.c_str(), engineCmdLine.data(), nullptr, nullptr, FALSE,
			0, nullptr, engineDir.empty() ? nullptr : engineDir.c_str(), &si, &pi)) {
		printf("[suite] FAIL: cannot start engine (%s) err=%lu\n", engine, GetLastError());
		return 1;
	}
	printf("[suite] engine pid=%lu\n", pi.dwProcessId);

	Sleep(4000);
	if (WaitForSingleObject(pi.hProcess, 0) != WAIT_TIMEOUT) {
		DWORD code = 0;
		GetExitCodeProcess(pi.hProcess, &code);
		printf("[suite] FAIL: engine died during startup (exit=%lu) -- 查 ACL\n",
			(unsigned long)code);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return 1;
	}
	Sleep(2000);   // 让注入器把全表扫一遍

	printf("\n--- 1) 豁免目录：期望 NOT-INJECTED ---\n");
	const bool exemptInjected = ProbeTarget(exemptTarget);

	printf("\n--- 2) 反向对照：同名但放错目录，期望 INJECTED ---\n");
	const bool controlInjected = ProbeTarget(controlTarget);

	printf("\n--- 3) 引擎日志交叉验证 ---\n");
	const bool logHasSkip = FileContains(consoleLog, kSkipMarkerUtf8);
	printf("[suite] r3shieldcore-console.log 含「跳过内置豁免进程注入(VMware Tools)」: %s\n",
		logHasSkip ? "YES" : "NO");

	TerminateProcess(pi.hProcess, 0);
	WaitForSingleObject(pi.hProcess, 5000);
	const bool engineGone = WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0;
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	printf("[suite] 引擎已退出: %s\n", engineGone ? "YES" : "NO（后面 bash 可能 fork 不了）");

	printf("\n");
	Check("豁免目录下的 vmtoolsd.exe 未被注入", !exemptInjected);
	Check("放错目录的同名 vmtoolsd.exe 照常被注入（证明豁免按路径、不按文件名）",
		controlInjected);
	Check("r3shieldcore-console.log 记录了点名的内置豁免", logHasSkip);
	Check("引擎已退出（bash 后续可正常 fork）", engineGone);

	printf("\n[suite] RESULT: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 6;
}

} // namespace

int main(int argc, char** argv)
{
	if (argc >= 5 && strcmp(argv[1], "--suite") == 0) {
		return RunSuite(argv[2], argv[3], argv[4]);
	}

	if (argc < 2) {
		// 靶子模式：活够久，让引擎的轮询注入器（10ms 一轮）能看见我们。
		Sleep(15000);
		return 0;
	}

	const char* target = argv[1];
	const bool injected = ProbeTarget(target);
	return injected ? 0 : 2;
}
