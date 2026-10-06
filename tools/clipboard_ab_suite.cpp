// clipboard_ab_suite.cpp -- 一键跑「hook_clipboard 开关真能关掉」的 A/B 实测。
//
// ============================================================================
// 为什么是一个 exe，而不是 bash 脚本
// ============================================================================
//
// 本套件要在引擎**存活期间**继续干活（起引擎 → 跑探针 → 关引擎），
// 而引擎跑着的时候：
//   · MSYS2 bash 的 `fork()` 全废（`hook_memory_op` 拦跨进程栈拷贝）
//   · PowerShell 也起不来（`hook_dll_load` 拒 runtimeconfig 映射）
//   · 脚本里 spawn System32 下的程序会被判 HIGH 直接拒（kProcessPathRules 片段规则）
//
// ⇒ 用 bash 驱动必然锁死（铁律 76）。把「改 ini + 起引擎 + 跑探针 + 关引擎」
//   整个流程塞进**一个原生 exe**，bash 在引擎存活期间一次 fork 都不做。
//
// ============================================================================
// 判定逻辑（★ 铁律 54：没有反向对照的测试等于没测）
// ============================================================================
//
// 同一个探针（clipboard_hook_probe.exe）跑两轮：
//
//   Round A: r3shieldcore.ini 里 hook_clipboard=1  -> 期望 GetClipboardData == HOOKED
//   Round B: r3shieldcore.ini 里 hook_clipboard=0  -> 期望 GetClipboardData == NOT-HOOKED
//
// 同时每轮都观察 gdi32!BitBlt（受 hook_screen 控制，两轮都保持 =1）：
//   它必须**两轮都 HOOKED** —— 这就是"引擎确实注入了这个靶子、MinHook 确实在工作"
//   的在场证据。没有它，Round B 的 NOT-HOOKED 无法与"根本没被注入"区分开
//   （假绿）。这是本套件最重要的一条设计。
//
// 四项断言：
//   1. Round A: GetClipboardData == HOOKED
//   2. Round B: GetClipboardData == NOT-HOOKED
//   3. 两轮 BitBlt 都 == HOOKED（证明注入确实发生，排除"没注入"这种假绿）
//   4. 两轮结果**不同**（否则 A/B 没有分辨力）
//
// 用法：
//   clipboard_ab_suite.exe <engineDir> <probeExe> <targetExe>
//      engineDir = 含 R3 ShieldCore.exe + r3shieldcore.ini 的目录（沙盒）
//      probeExe  = clipboard_hook_probe.exe
//      targetExe = 靶子（一个真的会加载 user32/gdi32 的 GUI/控制台程序；
//                  这里用 probeExe 自己也行 —— 它一启动就 GetModuleHandle
//                  了 user32/gdi32）
//
// 退出码：0 = 全 PASS，1 = 有 FAIL，6 = 环境问题（引擎起不来等）

#include <clocale>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <string>
#include <vector>

#include <windows.h>
#include <shellapi.h>

namespace {

int g_pass = 0;
int g_fail = 0;

// ★ 提权后的实例有**自己的控制台**，stdout 回不到调用方的管道里
//   （`ShellExecuteEx(runas)` 起的新进程不继承父进程的 stdout）。
//   所以所有输出必须**同时**写一份到文件，否则跑完什么都看不到。
FILE* g_logFile = nullptr;

void Emit(const char* fmt, ...)
{
	char buffer[4096];
	va_list args;
	va_start(args, fmt);
	_vsnprintf_s(buffer, _TRUNCATE, fmt, args);
	va_end(args);

	fputs(buffer, stdout);
	fflush(stdout);
	if (g_logFile) {
		fputs(buffer, g_logFile);
		fflush(g_logFile);
	}
}

// 把 Emit 重定向到 printf 之外的所有地方（下面原有的 printf 全部改成 Emit）
#define printf Emit

void Check(const char* what, bool ok)
{
	Emit("[suite] %-62s %s\n", what, ok ? "OK" : "**FAIL**");
	if (ok) { ++g_pass; } else { ++g_fail; }
}

std::string DirOf(const std::string& path)
{
	const size_t pos = path.find_last_of("\\/");
	return (pos == std::string::npos) ? std::string(".") : path.substr(0, pos);
}

// ------------------------------------------------------------ 跑一个子进程并捕获输出

struct RunResult
{
	DWORD exitCode = (DWORD)-1;
	std::string output;
	bool  wroteOutputFile = false;
};

// 用管道捕获子进程 stdout。★ 必须**同时**读，否则管道满了子进程会卡死。
RunResult RunAndCapture(const std::string& exePath, const std::string& args)
{
	RunResult result;

	std::string cmdLine = "\"" + exePath + "\"";
	if (!args.empty()) {
		cmdLine += " " + args;
	}

	SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
	HANDLE readEnd = nullptr, writeEnd = nullptr;
	if (!CreatePipe(&readEnd, &writeEnd, &sa, 0)) {
		printf("[suite] CreatePipe failed err=%lu\n", GetLastError());
		return result;
	}
	SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);

	STARTUPINFOA si = { sizeof(si) };
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = writeEnd;
	si.hStdError = writeEnd;
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

	PROCESS_INFORMATION pi = {};
	if (!CreateProcessA(exePath.c_str(), cmdLine.data(), nullptr, nullptr, TRUE,
			0, nullptr, DirOf(exePath).c_str(), &si, &pi)) {
		printf("[suite] CreateProcess(%s) failed err=%lu\n", exePath.c_str(), GetLastError());
		CloseHandle(readEnd);
		CloseHandle(writeEnd);
		return result;
	}
	CloseHandle(writeEnd);   // 父进程不留写端，否则 ReadFile 等不到 EOF

	char buffer[4096];
	DWORD got = 0;
	for (;;) {
		if (!ReadFile(readEnd, buffer, sizeof(buffer) - 1, &got, nullptr) || got == 0) {
			break;
		}
		buffer[got] = '\0';
		result.output += buffer;
	}
	CloseHandle(readEnd);

	WaitForSingleObject(pi.hProcess, 30000);
	GetExitCodeProcess(pi.hProcess, &result.exitCode);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return result;
}

// ------------------------------------------------------------ ini 开关改写

// 把 `key=...` 那一行的值改成 value。返回是否找到并改写。
// ★ 只匹配**行首**（允许前导空白）的 key，不碰注释行 ——
//   否则 `# hook_clipboard=0` 这种注释会被误改（铁律 33 同族）。
bool SetIniValue(const std::string& iniPath, const char* key, const char* value)
{
	FILE* f = nullptr;
	if (fopen_s(&f, iniPath.c_str(), "rb") != 0 || !f) {
		printf("[suite] 打不开 ini: %s\n", iniPath.c_str());
		return false;
	}
	std::string content;
	{
		char buf[8192];
		size_t n = 0;
		while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
			content.append(buf, n);
		}
	}
	fclose(f);

	const std::string keyEq = std::string(key) + "=";
	std::string out;
	out.reserve(content.size() + 64);

	size_t pos = 0;
	bool replaced = false;
	while (pos <= content.size())
	{
		size_t lineEnd = content.find('\n', pos);
		const bool last = (lineEnd == std::string::npos);
		std::string line = last ? content.substr(pos) : content.substr(pos, lineEnd - pos);

		// 去掉 CR
		std::string bare = line;
		if (!bare.empty() && bare.back() == '\r') { bare.pop_back(); }

		const size_t firstNonSpace = bare.find_first_not_of(" \t");
		if (!replaced && firstNonSpace != std::string::npos &&
			bare.compare(firstNonSpace, keyEq.size(), keyEq) == 0) {
			out += std::string(key) + "=" + value;
			replaced = true;
		}
		else {
			out += line;
		}
		if (!last) { out += "\n"; }

		if (last) { break; }
		pos = lineEnd + 1;
	}

	if (!replaced) {
		// 没找到就追加到末尾（保证开关一定被写进去）
		if (!out.empty() && out.back() != '\n') { out += "\n"; }
		out += std::string(key) + "=" + value + "\n";
	}

	if (fopen_s(&f, iniPath.c_str(), "wb") != 0 || !f) {
		printf("[suite] 写不回 ini: %s\n", iniPath.c_str());
		return false;
	}
	fwrite(out.data(), 1, out.size(), f);
	fclose(f);
	return true;
}

// ------------------------------------------------------------ 解析探针输出

// 在探针输出里找含 `module` 与 `function` 的那一行，取出 verdict。
// 返回 "HOOKED" / "NOT-HOOKED" / "" (没找到)
//
// ★ 逐行扫，不要拼 `"gdi32.dll BitBlt"` 这种固定空格的 needle ——
//   探针用 `%-10s %-22s` 对齐输出，模块名不足 10 字符时会**补空格**
//   （`gdi32.dll` = 9 字符 ⇒ 输出是 `gdi32.dll  BitBlt`，两个空格）。
//   固定单空格只对"正好 10 字符"的 `user32.dll` 碰巧有效，
//   对 `gdi32.dll` 永远匹配不上 —— 本套件首跑就踩了这个。
//
// ★ 还必须**先判 "NOT-HOOKED"**：它是 "HOOKED" 的**超串**
//   （"NOT-HOOKED".find("HOOKED") == 4），顺序反了会把 NOT-HOOKED 误判成 HOOKED。
std::string ExtractVerdict(const std::string& output, const char* module, const char* function)
{
	size_t pos = 0;
	while (pos < output.size())
	{
		size_t lineEnd = output.find('\n', pos);
		if (lineEnd == std::string::npos) { lineEnd = output.size(); }
		const std::string line = output.substr(pos, lineEnd - pos);
		pos = lineEnd + 1;

		if (line.find(module) != std::string::npos &&
			line.find(function) != std::string::npos)
		{
			if (line.find("NOT-HOOKED") != std::string::npos) {
				return "NOT-HOOKED";
			}
			if (line.find("HOOKED") != std::string::npos) {
				return "HOOKED";
			}
		}
	}
	return "";
}

// ------------------------------------------------------------ 起/停引擎

struct EngineProc
{
	PROCESS_INFORMATION pi = {};
	bool running = false;
};

bool StartEngine(const std::string& engineExe, const std::string& engineDir, EngineProc& out)
{
	std::string cmdLine = "\"" + engineExe + "\"";
	STARTUPINFOA si = { sizeof(si) };
	if (!CreateProcessA(engineExe.c_str(), cmdLine.data(), nullptr, nullptr, FALSE,
			0, nullptr, engineDir.c_str(), &si, &out.pi)) {
		printf("[suite] 起引擎失败 err=%lu\n", GetLastError());
		return false;
	}
	out.running = true;

	// 等它活过启动期（ACL 不对会秒退）
	Sleep(5000);
	if (WaitForSingleObject(out.pi.hProcess, 0) != WAIT_TIMEOUT) {
		DWORD code = 0;
		GetExitCodeProcess(out.pi.hProcess, &code);
		printf("[suite] 引擎启动期就退出了 exit=%lu —— 查路径/清单/依赖（v57 起已无 ACL 门禁）\n",
			(unsigned long)code);
		out.running = false;
		CloseHandle(out.pi.hThread);
		CloseHandle(out.pi.hProcess);
		return false;
	}
	Sleep(2000);   // 让注入器扫一遍
	return true;
}

// 停引擎：优先用 dskill（直 syscall，绕过自我保护 hook）；没有就 TerminateProcess。
void StopEngine(EngineProc& engine, const std::string& engineDir)
{
	if (!engine.running) {
		return;
	}

	const std::string dskill = engineDir + "\\dskill.exe";
	const std::string pidArg = std::to_string(engine.pi.dwProcessId);

	bool killed = false;
	if (GetFileAttributesA(dskill.c_str()) != INVALID_FILE_ATTRIBUTES) {
		printf("[suite] 用 dskill.exe（直 syscall）停引擎 pid=%lu\n",
			(unsigned long)engine.pi.dwProcessId);
		RunResult r = RunAndCapture(dskill, pidArg);
		WaitForSingleObject(engine.pi.hProcess, 5000);
		killed = (WaitForSingleObject(engine.pi.hProcess, 0) == WAIT_OBJECT_0);
		if (!killed) {
			printf("[suite] WARN: dskill 没杀掉（exit=%lu），回退 TerminateProcess\n",
				(unsigned long)r.exitCode);
		}
	}

	if (!killed) {
		TerminateProcess(engine.pi.hProcess, 0);
		WaitForSingleObject(engine.pi.hProcess, 5000);
	}

	const bool gone = (WaitForSingleObject(engine.pi.hProcess, 0) == WAIT_OBJECT_0);
	printf("[suite] 引擎已退出: %s\n", gone ? "YES" : "NO（后面 bash 可能 fork 不了）");

	CloseHandle(engine.pi.hThread);
	CloseHandle(engine.pi.hProcess);
	engine.running = false;
}

// ------------------------------------------------------------ 跑一轮

struct RoundResult
{
	std::string clipboardVerdict;   // user32!GetClipboardData
	std::string bitBltVerdict;      // gdi32!BitBlt（独立对照）
	bool        probeExited = false;
	std::string rawOutput;
};

RoundResult RunRound(const std::string& engineDir,
					 const std::string& probeExe,
					 const std::string& iniValue,
					 const char* roundTag)
{
	printf("\n=================== Round %s（hook_clipboard=%s）===================\n",
		roundTag, iniValue.c_str());

	RoundResult rr;

	const std::string iniPath = engineDir + "\\r3shieldcore.ini";
	if (!SetIniValue(iniPath, "hook_clipboard", iniValue.c_str())) {
		printf("[suite] FAIL: 改 ini 失败，本轮作废\n");
		return rr;
	}
	if (!SetIniValue(iniPath, "hook_screen", "1")) {
		printf("[suite] WARN: 没把 hook_screen 设回 1（BitBlt 对照可能失效）\n");
	}

	const std::string engineExe = engineDir + "\\R3 ShieldCore.exe";
	if (GetFileAttributesA(engineExe.c_str()) == INVALID_FILE_ATTRIBUTES) {
		printf("[suite] FAIL: 找不到引擎 %s\n", engineExe.c_str());
		return rr;
	}

	EngineProc engine;
	if (!StartEngine(engineExe, engineDir, engine)) {
		return rr;
	}
	printf("[suite] 引擎 pid=%lu 已就绪\n", (unsigned long)engine.pi.dwProcessId);

	// 跑探针（靶子 = 探针自己，它一启动就会加载 user32/gdi32）
	RunResult r = RunAndCapture(probeExe, "");
	rr.rawOutput = r.output;
	rr.probeExited = (r.exitCode != (DWORD)-1);
	printf("--- 探针原始输出 ---\n%s--- 结束 ---\n", r.output.c_str());

	rr.clipboardVerdict = ExtractVerdict(r.output, "user32.dll", "GetClipboardData");
	rr.bitBltVerdict = ExtractVerdict(r.output, "gdi32.dll", "BitBlt");

	StopEngine(engine, engineDir);
	return rr;
}

} // namespace

// ---------------------------------------------------------------- 自提权

// ★ 引擎的清单是 `requireAdministrator` ⇒ 标准用户 `CreateProcess` 直接
//   返回 `ERROR_ELEVATION_REQUIRED(740)`（实测）。
//   所以套件自己走 `ShellExecuteEx(runas)` 提权，只需点一次 UAC。
//
//   为什么不在套件里 `CreateProcess` 引擎时用 `runas`：
//   `CreateProcess` 不支持 runas；而 `ShellExecuteEx(runas)` 起出来的进程
//   不再由我们持有句柄，**拿不到 pid 也就停不掉引擎**。
//   ⇒ 正确做法是「让**套件自己**提权」：提权后套件持有引擎句柄，能干净收尾。
static bool RelaunchElevated(int argc, char** argv)
{
	std::string args;
	for (int i = 1; i < argc; ++i) {
		if (i > 1) { args += " "; }
		args += "\"" + std::string(argv[i]) + "\"";
	}

	char exePath[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, exePath, MAX_PATH);

	SHELLEXECUTEINFOA sei = { sizeof(sei) };
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.lpVerb = "runas";
	sei.lpFile = exePath;
	sei.lpParameters = args.c_str();
	sei.nShow = SW_SHOWNORMAL;

	if (!ShellExecuteExA(&sei)) {
		const DWORD err = GetLastError();
		if (err == ERROR_CANCELLED) {
			printf("[suite] 用户取消了 UAC 提权 —— 无法起引擎（它的清单要求管理员）\n");
		}
		else {
			printf("[suite] 提权失败 err=%lu\n", err);
		}
		return false;
	}

	// 等提权后的实例跑完，把它的退出码带回来。
	WaitForSingleObject(sei.hProcess, INFINITE);
	DWORD code = 0;
	GetExitCodeProcess(sei.hProcess, &code);
	CloseHandle(sei.hProcess);
	printf("[suite] （提权实例退出码 %lu）\n", (unsigned long)code);
	return true;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	// 提权后的实例带 `--elevated`，避免无限自我重启。
	bool alreadyElevated = false;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--elevated") == 0) {
			alreadyElevated = true;
		}
	}

	if (!alreadyElevated)
	{
		BOOL isAdmin = FALSE;
		PSID adminGroup = nullptr;
		SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
		if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
			CheckTokenMembership(nullptr, adminGroup, &isAdmin);
			FreeSid(adminGroup);
		}

		if (!isAdmin) {
			printf("[suite] 当前不是管理员 —— 引擎清单要求管理员，先自动提权...\n");

			// 把 `--elevated` 拼进参数
			std::vector<std::string> newArgv;
			newArgv.push_back(argv[0]);
			newArgv.push_back("--elevated");
			for (int i = 1; i < argc; ++i) {
				newArgv.push_back(argv[i]);
			}
			std::vector<char*> raw;
			for (auto& s : newArgv) { raw.push_back(s.data()); }
			raw.push_back(nullptr);

			if (!RelaunchElevated(static_cast<int>(raw.size()) - 1, raw.data())) {
				return 6;
			}
			return 0;
		}
	}

	if (argc < 4) {
		printf("用法: clipboard_ab_suite.exe [--elevated] <engineDir> <probeExe> <targetExe>\n");
		return 2;
	}

	// 跳过可能的 `--elevated`（它不参与位置参数）
	std::vector<std::string> positional;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--elevated") != 0) {
			positional.push_back(argv[i]);
		}
	}
	if (positional.size() < 3) {
		printf("用法: clipboard_ab_suite.exe [--elevated] <engineDir> <probeExe> <targetExe>\n");
		return 2;
	}
	const std::string engineDir = positional[0];
	const std::string probeExe = positional[1];

	// 结果文件：写在引擎目录**外面**（引擎目录已加固，提权实例才写得进；
	// 但我们希望无论提权与否都能读）。放在当前工作目录。
	const std::string resultPath = "clipboard_ab_result.txt";
	if (fopen_s(&g_logFile, resultPath.c_str(), "wb") != 0 || !g_logFile) {
		g_logFile = nullptr;
	}
	else {
		Emit("[suite] 结果同时写入: %s\n", resultPath.c_str());
	}

	// 备份 ini，跑完还原（免得把沙盒配置改花）
	const std::string iniPath = engineDir + "\\r3shieldcore.ini";
	std::string iniBackup;
	{
		FILE* f = nullptr;
		if (fopen_s(&f, iniPath.c_str(), "rb") == 0 && f) {
			char buf[8192];
			size_t n = 0;
			while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
				iniBackup.append(buf, n);
			}
			fclose(f);
		}
	}

	printf("=== hook_clipboard 开关 A/B 实测 ===\n");
	printf("引擎目录 : %s\n", engineDir.c_str());
	printf("探针     : %s\n", probeExe.c_str());

	// ---------------- Round A：hook_clipboard=1 ----------------
	RoundResult a = RunRound(engineDir, probeExe, "1", "A");

	// ---------------- Round B：hook_clipboard=0 ----------------
	RoundResult b = RunRound(engineDir, probeExe, "0", "B");

	// 还原 ini
	if (!iniBackup.empty()) {
		FILE* f = nullptr;
		if (fopen_s(&f, iniPath.c_str(), "wb") == 0 && f) {
			fwrite(iniBackup.data(), 1, iniBackup.size(), f);
			fclose(f);
		}
	}

	// ---------------- 汇总 ----------------
	printf("\n=================== 汇总 ===================\n");
	printf("Round A (hook_clipboard=1): GetClipboardData=%s  BitBlt=%s\n",
		a.clipboardVerdict.empty() ? "(未读到)" : a.clipboardVerdict.c_str(),
		a.bitBltVerdict.empty() ? "(未读到)" : a.bitBltVerdict.c_str());
	printf("Round B (hook_clipboard=0): GetClipboardData=%s  BitBlt=%s\n",
		b.clipboardVerdict.empty() ? "(未读到)" : b.clipboardVerdict.c_str(),
		b.bitBltVerdict.empty() ? "(未读到)" : b.bitBltVerdict.c_str());
	printf("\n");

	Check("Round A: hook_clipboard=1 -> GetClipboardData 被 hook",
		a.clipboardVerdict == "HOOKED");
	Check("Round B: hook_clipboard=0 -> GetClipboardData 未 hook",
		b.clipboardVerdict == "NOT-HOOKED");
	Check("Round A: BitBlt 被 hook（证明注入确实发生）",
		a.bitBltVerdict == "HOOKED");
	Check("Round B: BitBlt 仍被 hook（证明 Round B 不是「没注入」造成的假绿）",
		b.bitBltVerdict == "HOOKED");
	Check("两轮 GetClipboardData 结果不同（A/B 有分辨力）",
		!a.clipboardVerdict.empty() && !b.clipboardVerdict.empty() &&
		a.clipboardVerdict != b.clipboardVerdict);

	printf("\n[suite] RESULT: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");

	if (g_logFile) {
		fclose(g_logFile);
		g_logFile = nullptr;
	}
	return g_fail == 0 ? 0 : 1;
}
