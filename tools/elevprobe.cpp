//
// elevprobe.cpp —— 「引擎能不能拦管理员程序？」专用探针
// ============================================================================
//
// 为什么要单独做这个探针
// ----------------------------------------------------------------------------
// 用户的问题：R3ShieldCore 是不是拦不住以管理员身份运行的程序？
//
// 直接拿 HKLM 之类**需要管理员才能写**的键去测，是**测不出答案的**：
//   · 非提权变体拿到 5(拒绝) —— 那是 **Windows 的 ACL** 拒的，不是引擎；
//   · 提权变体拿到 5(拒绝) —— 才可能是引擎。
// 两个变体返回同一个 5，**没有分辨力**，等于白测。
//
// 所以本探针刻意选 **HKCU\Software\Microsoft\Windows\CurrentVersion\Run**：
//   · 它是规则表里的高危项（`自启动项(Run)`，见 r3shieldcore_rules.cpp），
//   · 而**普通用户本来就有权写它**（这是 Windows 的设计，也是
//     "用户态自启动"这种真实攻击手法的立足点）。
// ⇒ 于是：
//     - 引擎没跑  -> 一定返回 0（写成功）；
//     - 引擎在跑  -> 应当返回 5，且**这个 5 只可能来自引擎**。
//   提权 / 非提权两个变体应当**都是 5** —— 那才是"能拦管理员程序"。
//
// 探针还额外自报三件"前提"，缺了它们结论就不成立（铁律 57：判定须验前提）：
//   ① 本进程的**完整性级别**（Medium 还是 High）—— 证明变体真的是提权/非提权；
//   ② 引擎 DLL（`r3shieldcore-lib.dll`）**有没有被加载进本进程** ——
//      没加载 = 根本没被注入 = 后面"没拦住"是废话，不是引擎的错；
//   ③ 每步的**耗时** —— 弹窗模式(ask)下被拦会阻塞到 prompt_timeout 秒。
//
// 输出同时打印到控制台并落盘 `<exe 同目录>\elevprobe-<pid>.out`（UTF-8）。
// 双击运行时控制台一闪就没，必须落盘。
//
// ★ 落盘刻意**不用** CRT 的 `_wfopen_s(ccs=UTF-8)` + `vfprintf`：
//   实测那条路在本机 **`vfprintf` 直接 0xC0000409 崩掉**（文件只留下 3 字节 BOM），
//   现象酷似"程序没启动"，极难查。改成 CreateFileW + 自己 GBK→UTF-8 转换，
//   与 `sync_inject_probe.cpp` 的做法一致（那边也是从 `fopen_s` 迁到 `CreateFileA`）。
//
// 用法：
//   elevprobe-admin.exe           双击（会弹 UAC）或从提权 cmd 里敲
//   elevprobe-user.exe            双击（不弹 UAC）
//   elevprobe-user.exe --no-pause 不等待回车（给脚本用）
//   elevprobe-user.exe --trace    崩溃时在 stderr 留下阶段标记（诊断用）
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

static HANDLE g_logHandle = INVALID_HANDLE_VALUE;
static bool g_trace = false;

// 诊断用：直接写 stderr（不经 CRT 缓冲），进程 fastfail 时也能留下足迹。
static void Trace(const char* tag)
{
	if (!g_trace) {
		return;
	}

	const HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
	DWORD written = 0;
	if (handle && handle != INVALID_HANDLE_VALUE) {
		WriteFile(handle, tag, static_cast<DWORD>(strlen(tag)), &written, nullptr);
	}
}

// GBK(当前代码页) -> UTF-8 写进日志句柄。
static void WriteLogUtf8(const char* ansi, int length)
{
	if (g_logHandle == INVALID_HANDLE_VALUE || length <= 0) {
		return;
	}

	const int wideLength = MultiByteToWideChar(CP_ACP, 0, ansi, length, nullptr, 0);
	if (wideLength <= 0) {
		return;
	}

	WCHAR* wide = static_cast<WCHAR*>(malloc((wideLength + 1) * sizeof(WCHAR)));
	if (!wide) {
		return;
	}
	MultiByteToWideChar(CP_ACP, 0, ansi, length, wide, wideLength);

	const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wide, wideLength,
		nullptr, 0, nullptr, nullptr);
	if (utf8Length > 0) {
		char* utf8 = static_cast<char*>(malloc(utf8Length));
		if (utf8) {
			WideCharToMultiByte(CP_UTF8, 0, wide, wideLength, utf8, utf8Length,
				nullptr, nullptr);

			DWORD written = 0;
			WriteFile(g_logHandle, utf8, static_cast<DWORD>(utf8Length), &written, nullptr);
			free(utf8);
		}
	}

	free(wide);
}

//
// ★ 阶段标记 + 看门狗（诊断"卡死但啥也不输出"专用）
// ----------------------------------------------------------------------------
// 现象：提权运行本探针时控制台**一个字都没有**、`.out` 只有 3 字节 BOM，
//       进程永不退出。3 字节 BOM 说明 `main` 跑到了、日志文件也建出来了，
//       所以卡点在 `main` 之内 —— 但普通 `printf` 全被 CRT 缓冲吃掉了，
//       卡死时一个字都留不下，无从定位。
//
// 对策三条：
//   ① `Stage()` —— **绕开 CRT**，直接用 `WriteFile` 往日志句柄写 ASCII 阶段标记。
//      主线程卡在某个 API 里时，之前写下的标记已经落盘。
//   ② `Print()` **先写文件、后写 stdout** —— 万一是 stdout 那一侧卡住，
//      日志里照样有完整内容。
//   ③ **看门狗线程** —— 25 秒还没跑完就把"最后停在哪个阶段"写进日志并自杀
//      （退出码 3）。宁可明确失败，也不要无限期挂在那里让人以为死机。
//      ★ 主线程跑到 `g_done = 1` 之后看门狗自动收工，
//        所以最后那句"按回车退出"的正常等待不会被误杀。
//
static volatile LONG g_done = 0;
static volatile const char* g_stage = "before-main";

// 绕开 CRT 的阶段标记：只用 WriteFile，主线程被 API 卡住时也已落盘。
static void Stage(const char* tag)
{
	g_stage = tag;

	if (g_logHandle == INVALID_HANDLE_VALUE) {
		return;
	}

	char line[192] = {};
	size_t i = 0;
	const char* prefix = "[stage] ";
	for (const char* p = prefix; *p && i < sizeof(line) - 3; ++p) {
		line[i++] = *p;
	}
	for (const char* p = tag; *p && i < sizeof(line) - 3; ++p) {
		line[i++] = *p;
	}
	line[i++] = '\r';
	line[i++] = '\n';

	DWORD written = 0;
	WriteFile(g_logHandle, line, static_cast<DWORD>(i), &written, nullptr);
}

static DWORD WINAPI WatchdogProc(LPVOID)
{
	const int kSeconds = 25;

	for (int i = 0; i < kSeconds; ++i) {
		Sleep(1000);
		if (InterlockedCompareExchange(&g_done, 1, 1) == 1) {
			return 0;   // 主线程正常跑完了
		}
	}

	if (InterlockedCompareExchange(&g_done, 1, 1) == 1) {
		return 0;
	}

	// 主线程卡住了：把最后阶段写进日志（同样是绕开 CRT 的裸 WriteFile）。
	//
	// ⚠️ `g_stage` 是 `volatile const char*`（指针指向 volatile const char），
	//   不能直接赋给 `const char*`（C2440 丢限定符）⇒ 先逐字符拷进本地缓冲。
	char stageName[96] = {};
	{
		const volatile char* src = g_stage;
		for (size_t k = 0; k < sizeof(stageName) - 1 && src && src[k]; ++k) {
			stageName[k] = src[k];
		}
	}

	char line[256] = {};
	size_t i = 0;
	const char* prefix = "[watchdog] MAIN THREAD BLOCKED after 25s, last stage = ";
	for (const char* p = prefix; *p && i < sizeof(line) - 3; ++p) {
		line[i++] = *p;
	}
	for (const char* p = stageName; *p && i < sizeof(line) - 3; ++p) {
		line[i++] = *p;
	}
	line[i++] = '\r';
	line[i++] = '\n';

	if (g_logHandle != INVALID_HANDLE_VALUE) {
		DWORD written = 0;
		WriteFile(g_logHandle, line, static_cast<DWORD>(i), &written, nullptr);
		FlushFileBuffers(g_logHandle);
	}

	const HANDLE err = GetStdHandle(STD_ERROR_HANDLE);
	if (err && err != INVALID_HANDLE_VALUE) {
		DWORD written = 0;
		WriteFile(err, line, static_cast<DWORD>(i), &written, nullptr);
	}

	// 宁可明确失败，也不要无限期挂着。
	TerminateProcess(GetCurrentProcess(), 3);
	return 0;
}

static void Print(const char* fmt, ...)
{
	char buffer[4096] = {};

	va_list args;
	va_start(args, fmt);
	const int length = vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	if (length <= 0) {
		return;
	}
	const int safeLength = (length < static_cast<int>(sizeof(buffer)))
		? length : static_cast<int>(sizeof(buffer)) - 1;

	// ★ 先写日志文件（裸 WriteFile），再写 stdout。
	//   反过来的话，一旦卡在 stdout 那一侧，日志里就什么都没有 —— 正是本次的现场。
	WriteLogUtf8(buffer, safeLength);
	fwrite(buffer, 1, static_cast<size_t>(safeLength), stdout);
	fflush(stdout);
}

static ULONGLONG NowMs()
{
	return GetTickCount64();
}

static const char* Verdict(LSTATUS status)
{
	if (status == ERROR_SUCCESS) {
		return "  [成功]";
	}
	if (status == ERROR_ACCESS_DENIED) {
		return "  [被拒绝 5]";
	}
	return "";
}

static void Report(const char* operation, LSTATUS status, ULONGLONG elapsedMs)
{
	Print("%-38s -> %-5ld %7llu ms%s\n", operation, status, elapsedMs, Verdict(status));
}

static bool IsProcessElevatedSelf()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return false;
	}

	TOKEN_ELEVATION elevation = {};
	DWORD returned = 0;
	const bool elevated = GetTokenInformation(token, TokenElevation,
		&elevation, sizeof(elevation), &returned) && elevation.TokenIsElevated;

	CloseHandle(token);
	return elevated;
}

// 完整性级别（Medium / High / System）。提权与否看这个，不看用户名。
static const char* IntegrityLevelName()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return "?";
	}

	DWORD size = 0;
	GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
	if (size == 0) {
		CloseHandle(token);
		return "?";
	}

	BYTE* buffer = static_cast<BYTE*>(malloc(size));
	const char* name = "?";
	if (buffer && GetTokenInformation(token, TokenIntegrityLevel, buffer, size, &size)) {
		TOKEN_MANDATORY_LABEL* label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer);
		const DWORD rid = *GetSidSubAuthority(label->Label.Sid,
			static_cast<DWORD>(*GetSidSubAuthorityCount(label->Label.Sid) - 1));

		if (rid >= SECURITY_MANDATORY_SYSTEM_RID) {
			name = "System";
		}
		else if (rid >= SECURITY_MANDATORY_HIGH_RID) {
			name = "High(提权)";
		}
		else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) {
			name = "Medium(普通)";
		}
		else if (rid >= SECURITY_MANDATORY_LOW_RID) {
			name = "Low";
		}
		else {
			name = "Untrusted";
		}
	}

	free(buffer);
	CloseHandle(token);
	return name;
}

// ★ 前提②：引擎的 DLL 到底有没有被注入进本进程。
//   没注入 -> 后面的"没拦住"与引擎无关，是"没覆盖到"而不是"拦不住"。
static void ReportInjectionState()
{
	const WCHAR* names[] = { L"r3shieldcore-lib.dll", L"R3ShieldCoreLib-x86.dll" };

	bool anyLoaded = false;
	for (const WCHAR* name : names) {
		HMODULE module = GetModuleHandleW(name);
		if (module) {
			WCHAR path[MAX_PATH * 2] = {};
			GetModuleFileNameW(module, path, _countof(path));
			Print("  引擎 DLL: 已加载  %ls\n        %ls\n", name, path);
			anyLoaded = true;
		}
	}

	if (!anyLoaded) {
		Print("  引擎 DLL: **未加载** —— 本进程没有被注入，"
			"下面的'没拦住'与引擎判定无关\n");
	}
}

static void StepRegistryRunKey()
{
	Print("\n[1] 写自启动项  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	Print("    (规则表高危项；且普通用户本来就有写权限 -> 拒绝只可能来自引擎)\n");

	HKEY key = nullptr;
	ULONGLONG before = NowMs();
	LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
	Report("RegCreateKeyEx(Run, KEY_SET_VALUE)", status, NowMs() - before);

	if (status != ERROR_SUCCESS) {
		Print("    打开被拒 -> 后续写值跳过。\n");
		return;
	}

	const WCHAR* data = L"D:\\__r3shieldcore_elevprobe_noop__.exe";
	before = NowMs();
	status = RegSetValueExW(key, L"R3ShieldCoreElevProbe", 0, REG_SZ,
		reinterpret_cast<const BYTE*>(data),
		static_cast<DWORD>((wcslen(data) + 1) * sizeof(WCHAR)));
	Report("RegSetValueEx(R3ShieldCoreElevProbe)", status, NowMs() - before);

	if (status == ERROR_SUCCESS) {
		const LSTATUS cleanup = RegDeleteValueW(key, L"R3ShieldCoreElevProbe");
		Report("RegDeleteValue(清理)", cleanup, 0);
		if (cleanup != ERROR_SUCCESS) {
			Print("    ★ 注意：自启动项没清掉，请手动删 HKCU Run 里的 "
				"R3ShieldCoreElevProbe\n");
		}
	}

	RegCloseKey(key);
}

static void StepCreateProcess()
{
	Print("\n[2] 创建子进程  cmd.exe /c exit\n");
	Print("    (block 模式放行；block_all 拒；block_all_safe 因 System32+签名放行)\n");

	STARTUPINFOW startupInfo = {};
	startupInfo.cb = sizeof(startupInfo);
	PROCESS_INFORMATION processInfo = {};

	WCHAR commandLine[] = L"cmd.exe /c exit";

	ULONGLONG before = NowMs();
	const BOOL created = CreateProcessW(nullptr, commandLine, nullptr, nullptr,
		FALSE, 0, nullptr, nullptr, &startupInfo, &processInfo);
	const ULONGLONG elapsed = NowMs() - before;

	if (created) {
		Report("CreateProcessW", ERROR_SUCCESS, elapsed);
		CloseHandle(processInfo.hThread);
		CloseHandle(processInfo.hProcess);
	}
	else {
		Report("CreateProcessW", GetLastError(), elapsed);
	}
}

// ★ 这一项同时是 TokenTheftGuard 的探针：
//   非提权令牌里根本没有 SeDebugPrivilege -> err=1300，属正常，不能当结论。
static void StepEnableDebugPrivilege()
{
	Print("\n[3] 启用 SeDebugPrivilege  (TokenTheftGuard 的判据之一)\n");
	Print("    (非提权令牌里没有这个特权 -> err=1300 是正常的，不算被拦)\n");

	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		Print("    OpenProcessToken 失败 err=%lu\n", GetLastError());
		return;
	}

	LUID luid = {};
	if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
		Print("    LookupPrivilegeValue 失败 err=%lu\n", GetLastError());
		CloseHandle(token);
		return;
	}

	TOKEN_PRIVILEGES privileges = {};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	ULONGLONG before = NowMs();
	const BOOL ok = AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr);
	const DWORD error = GetLastError();
	const ULONGLONG elapsed = NowMs() - before;

	Print("%-38s -> ok=%d err=%-5lu %7llu ms%s\n", "AdjustTokenPrivileges(SeDebug)",
		ok, error, elapsed,
		(error == ERROR_NOT_ALL_ASSIGNED) ? "  [令牌里没这个特权，正常]" :
		(ok && error == ERROR_SUCCESS) ? "  [成功]" : "  [被拒绝]");

	CloseHandle(token);
}

static void OpenLogFile()
{
	WCHAR modulePath[MAX_PATH * 2] = {};
	GetModuleFileNameW(nullptr, modulePath, _countof(modulePath));

	WCHAR* slash = wcsrchr(modulePath, L'\\');
	if (slash) {
		*(slash + 1) = L'\0';
	}

	WCHAR outPath[MAX_PATH * 2] = {};
	// ★ size 参数不能省：`swprintf_s(buf, fmt, ...)` 少了它，CRT 会把**格式串指针**
	//   当 size 用 -> 缓冲区检查失败 -> __fastfail -> 0xC0000409。
	swprintf_s(outPath, _countof(outPath), L"%selevprobe-%lu.out",
		modulePath, GetCurrentProcessId());

	g_logHandle = CreateFileW(outPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (g_logHandle == INVALID_HANDLE_VALUE) {
		// 目录不可写（例如加固过的发布目录）就退到 %TEMP%
		WCHAR tempPath[MAX_PATH * 2] = {};
		GetTempPathW(_countof(tempPath), tempPath);
		swprintf_s(outPath, _countof(outPath), L"%selevprobe-%lu.out",
			tempPath, GetCurrentProcessId());
		g_logHandle = CreateFileW(outPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	if (g_logHandle != INVALID_HANDLE_VALUE) {
		const char bom[] = "\xEF\xBB\xBF";
		DWORD written = 0;
		WriteFile(g_logHandle, bom, 3, &written, nullptr);
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	bool noPause = false;
	for (int i = 1; i < argc; ++i) {
		if (_stricmp(argv[i], "--no-pause") == 0) {
			noPause = true;
		}
		else if (_stricmp(argv[i], "--trace") == 0) {
			g_trace = true;
		}
	}

	Trace("[T1:main]");
	Stage("main-entered");
	OpenLogFile();
	Trace("[T2:log-open-done]");
	Stage("log-opened");

	// ★ 看门狗要在"日志已打开"之后立刻起：它自己也往这个句柄写。
	//   若主线程此后卡在任意 API 里，25 秒后日志里会多出一行
	//   `[watchdog] MAIN THREAD BLOCKED ... last stage = X`，进程退出码 3。
	{
		HANDLE watchdog = CreateThread(nullptr, 0, WatchdogProc, nullptr, 0, nullptr);
		if (watchdog) {
			CloseHandle(watchdog);
		}
	}

	Stage("before-first-print");
	Print("================ R3ShieldCore 提权拦截探针 ================\n");
	Stage("after-first-print");

	WCHAR imagePath[MAX_PATH * 2] = {};
	DWORD length = _countof(imagePath);
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, imagePath, &length);

	Print("pid            : %lu   (引擎日志按这个 pid 交叉核对)\n", GetCurrentProcessId());
	Print("镜像路径       : %ls\n", imagePath);
	Print("完整性级别     : %s\n", IntegrityLevelName());
	Print("令牌已提权     : %s\n", IsProcessElevatedSelf() ? "是 (High)" : "否 (Medium)");
	{
		WCHAR user[256] = {};
		DWORD userLength = _countof(user);
		GetUserNameW(user, &userLength);
		Print("用户名         : %ls\n", user);
	}

	Trace("[T3:header-done]");
	Stage("header-done");
	ReportInjectionState();
	Trace("[T4:inject-state-done]");
	Stage("inject-state-done");

	Stage("step1-registry-enter");
	StepRegistryRunKey();
	Trace("[T5:reg-done]");
	Stage("step1-registry-done");

	Stage("step2-createprocess-enter");
	StepCreateProcess();
	Trace("[T6:proc-done]");
	Stage("step2-createprocess-done");

	Stage("step3-token-enter");
	StepEnableDebugPrivilege();
	Trace("[T7:token-done]");
	Stage("step3-token-done");

	Print("\n================ 判读 ================\n");
	Print("· 步骤[1] 返回 0  = 没拦住（或被引擎放行）\n");
	Print("· 步骤[1] 返回 5  = 被拦。因为 HKCU Run 普通用户本来可写，\n");
	Print("                    这个 5 只可能来自引擎（前提是'引擎 DLL 已加载'）。\n");
	Print("· 引擎 DLL 未加载 = 本进程压根没被注入，本次结论**无效**，\n");
	Print("                    要先查 r3shieldcore-console.log 里'注入新进程: N 个'。\n");
	Print("· 提权变体与普通变体**结论应当一致**；不一致才是真问题。\n");
	Print("\n本次输出已存到 exe 同目录的 elevprobe-%lu.out\n", GetCurrentProcessId());

	// ★ 全部步骤走完 —— 通知看门狗收工，后面"按回车退出"的正常等待不会被误杀。
	Stage("DONE");
	InterlockedExchange(&g_done, 1);

	if (!noPause) {
		Print("\n按回车退出...");
		(void)getchar();
	}

	// 句柄放到最后关：看门狗可能刚好在收尾时还要写一行。
	if (g_logHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(g_logHandle);
		g_logHandle = INVALID_HANDLE_VALUE;
	}

	return 0;
}
