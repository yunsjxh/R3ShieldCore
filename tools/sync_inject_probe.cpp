//
// sync_inject_probe.cpp —— v46 端到端验证：「全量注入的父进程」拉子进程时，
// 引擎自己的注入写入**不再被自己的规则拦掉**。
//
// ==================================================================
// 它验证的 bug（用户真机实测，v45 日志）
// ==================================================================
//
//   同步注入路 `CreateProcessInternalW_Hook` **跑在调用方进程里**，`DllInject`
//   用 `VirtualAllocEx` / `WriteProcessMemory` / `VirtualProtectEx` /
//   `CreateRemoteThread` **在父进程上下文**完成注入。父进程若被**全量注入**，
//   它自己就装着这些钩子 -> 注入器自己的跨进程写被判成 HIGH -> Block 模式直接拒：
//
//       PROC ALLOW      CreateProcess        image=...\tasklist.exe  (pid=1912)
//       PROC ALLOW      AllocateVirtualMemory                          (pid=1912)
//       PROC BLOCK HIGH WriteVirtualMemory                            (pid=1912)  <- 自己拦自己
//
//   后果：同步路**静默退化成 10 ms 轮询路**（盲区回来），而不是"子进程被杀"。
//
// ==================================================================
// 怎么用
// ==================================================================
//
//   1. 先启动引擎（`dist/R3ShieldCore-x64/start.bat`，要管理员）。
//   2. **双击**本 exe（不要从 cmd 里敲 —— 从 cmd 启动时本进程的父进程是 cmd，
//      同样是被注入的，能测；但双击更贴近"用户真实场景"，且父进程是
//      explorer.exe -> 本进程由**瘦宿主**的同步路注入，本进程自己一定是被注入的）。
//   3. 本进程（已被全量注入）连续创建 3 个子进程。每个子进程在**第一行代码**
//      就去试一个已知会被拦的操作（写 HKCU 的 Run 键）：
//        · blockedAtMs = 0  -> hook 在子进程跑第一行代码前就装好了 = 同步路正常 [OK]
//        · blockedAtMs > 0  -> 同步路失效、掉回轮询路 [BAD]
//   4. 本进程还会自己去 `r3shieldcore-events.log` 里核对：对每个子进程 pid，
//      **不应**出现 `PROC BLOCK ... WriteVirtualMemory ... (pid=<子>)`。
//      找不到日志文件时只打印"该查什么"，不阻塞。
//
// ★ v49：修两个"真机上静默吞掉判定"的缺陷（用户 v48 真机实测暴露）：
//   ① 读日志用 `fopen_s(..., "rb")` —— 共享模式不含 `FILE_SHARE_WRITE`，
//      而引擎写日志时持的是 `GENERIC_WRITE + FILE_SHARE_READ` ⇒ 必然
//      `ERROR_SHARING_VIOLATION(32)`。症状：`起始偏移: 0` + 每个子进程
//      「日志读不到，跳过」+ **照样判 PASS**（假绿）。
//      ⇒ 改用 `CreateFileA(GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, ...)`。
//   ② 判定只有 PASS/FAIL 两态，"读不到日志"被静默跳过。
//      ⇒ 改成**三态**：PASS(0) / FAIL(1) / **无法判定(2)**。
//   ③ 痕迹文件建不出来：发布目录**加固过**（Users 只有 RX），探针以标准用户
//      运行时建不了 `probe-trace.log` ⇒ 回退 `%TEMP%\R3ShieldCoreProbeTrace.log`，
//      并在横幅里把**实际路径**打出来。
//
// 安全：只写 `HKCU\...\CurrentVersion\Run` 下的一个值 `R3ShieldCoreSyncInjectProbe`，
//       普通用户可写、命中高危规则「自启动项(Run)」，**写入成功后立刻删除**。
//
// ★ v50：修两个"判定看似 PASS、实际什么都没验"的缺陷（用户 v49 真机实测暴露）：
//   ① `TryResolveLogPath` 的候选 2 **硬编码** `..\dist\R3ShieldCore-x64\`（无版本后缀）。
//      项目现在有 `R3ShieldCore-x64-v49` 这类带版本的部署目录 ⇒ 从 `tools/` 跑时
//      落到**老目录**上；引擎却往新目录写 ⇒ 探针扫的永远是老文件 ⇒
//      `起始偏移 == 文件大小`（扫 0 字节）⇒ 三条 `[OK]` 是**空扫**、判定必然 PASS。
//      ⇒ 改成枚举 `..\dist\R3ShieldCore-x64*`，取 **r3shieldcore-events.log 的 mtime 最新**那个。
//   ② 判定**完全不看前提**。子进程自报 `blocked=no` = HKCU Run 写成功 =
//      它**根本没装 hook**（没被注入 / 模式不是 block）。这时"引擎没拦自己的
//      注入写入"是废话，不能算 PASS。原判定只看 `bad` / `unreadable` ⇒
//      **引擎没跑也照样 PASS**。
//      ⇒ 从 `probe-trace.log` 取每个子进程的 `blockedEver`；**一个都没被拦**
//        时判定 = **无法判定(2)**。
//   ③ 顺带把日志的**最后写入时间**打出来 —— 引擎没在写这个文件时，下面的
//      "日志核对"必然空扫，提前把这点摆在屏幕上。
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <string>

namespace
{
	// ==================================================================
	// ★★★ v51：入口时刻必须用 **QPC** 记，不能用 `GetTickCount64`。
	//
	//   本机实测（`_t/tick/tick.cpp`）：`GetTickCount64` 的粒度是 **15–16 ms**
	//   —— 500 ms 内最小非零增量 = 15 ms，`Sleep(10)` 它报 16 ms。
	//   引擎虽然会调 `NtSetTimerResolution(10000, TRUE)`，但**并没有**让
	//   `GetTickCount64` 变细：引擎在跑的那一轮，整份 `probe-trace.log` 里的
	//   `t=` 仍然只有 {0, 15, 16, 31, 47, ...}，**没有一个中间值**。
	//
	//   ⇒ 用 `GetTickCount64` 算出来的 `blockedAtMs` **取不到中间值**：
	//     一个 `15` 既可能是"真的晚了 15 ms"，也可能只是"跨了一个时钟滴答"。
	//     **它无法区分同步注入路和 10 ms 轮询路** —— 而"0 = 正常 / >0 = 失效"
	//     这个图例正是这么写的，于是每一轮都会随机误报一次"同步路失效"。
	// ==================================================================
	struct EntryClock
	{
		ULONGLONG qpc = 0;
		LONGLONG freq = 0;
		EntryClock()
		{
			LARGE_INTEGER f = {}, c = {};
			QueryPerformanceFrequency(&f);
			QueryPerformanceCounter(&c);
			freq = f.QuadPart;
			qpc = static_cast<ULONGLONG>(c.QuadPart);
		}
	};
	const EntryClock g_entryClock;

	// 从**全局初始化**到现在的微秒数。QPC 是唯一可用于子毫秒判据的时钟。
	ULONGLONG ElapsedUs()
	{
		if (g_entryClock.freq == 0) { return 0; }
		LARGE_INTEGER now = {};
		QueryPerformanceCounter(&now);
		return static_cast<ULONGLONG>(
			(now.QuadPart - static_cast<LONGLONG>(g_entryClock.qpc)) * 1000000LL /
			g_entryClock.freq);
	}

	// ★ 只给痕迹里的 `t=` 用（人看的时间轴，**不参与判定**）。
	//   ⚠️ 粒度 15–16 ms，别拿它做判据。
	const ULONGLONG g_entryTick = GetTickCount64();

	constexpr ULONG kPollIntervalMs = 10;
	constexpr ULONG kMaxWaitMs = 3000;
	constexpr int   kChildCount = 3;

	// ==================================================================
	// ★★★ v48：**文件级早期痕迹**（probe-trace.log）
	//
	// 为什么必须有：本探针是控制台程序，`printf` 的输出只有"进程真的跑起来了、
	// 控制台也真的接上了"才看得见。一旦**主线程被卡住**（例如被第二次注入的
	// APC 吊死在会话信号量上），窗口就是**一片空白**，而且——
	//   · 进程活着（看着像卡死，不像崩溃）；
	//   · 日志里那个 pid 只有一条 `DLL ALLOW LoadLibrary`，没有 main 的任何痕迹；
	//   · 从 cmd / bash 里跑**看不出来**（stdout 是管道，空白和"没输出"分不清）。
	//
	// 所以：**main 的第一行**就往 exe 同目录的 `probe-trace.log` 追加一条记录。
	// 事后只要看这个文件：
	//   · 有 "enter main"  -> 进程跑到了 main，问题在 main 之后（往下看最后一条）；
	//   · 一条都没有       -> 进程**根本没进 main**（卡在注入 / APC / 加载器里）。
	//
	// ⚠️ 用 Win32 `CreateFileA(FILE_APPEND_DATA, FILE_SHARE_READ|WRITE)` +
	//    `WriteFile`，**不用 `fopen_s`**：实测父进程把文件打开着的时候，
	//    子进程的 `fopen_s(..., "ab")` 会**静默失败**（`g_trace` 变 NULL，
	//    于是子进程一条痕迹都没有 —— 而子进程恰恰是最需要看痕迹的那个）。
	//    `FILE_APPEND_DATA` 让每次 `WriteFile` 都落在文件末尾，多进程并发追加
	//    也不会互相覆盖。打开失败就静默降级（只影响诊断，不能影响判定）。
	// ==================================================================
	HANDLE g_traceFile = INVALID_HANDLE_VALUE;
	CRITICAL_SECTION g_traceLock;
	bool g_traceLockReady = false;

	// 实际落盘的痕迹路径（空串 = 痕迹不可用）。横幅要把它打出来 ——
	// 否则"痕迹文件在哪"要靠猜，而回退到 %TEMP% 时更是猜不到。
	char g_tracePath[MAX_PATH * 2] = {};

	void TraceInit()
	{
		InitializeCriticalSection(&g_traceLock);
		g_traceLockReady = true;

		char exePath[MAX_PATH] = {};
		GetModuleFileNameA(nullptr, exePath, MAX_PATH);
		char* slash = strrchr(exePath, '\\');
		if (!slash) {
			return;
		}
		*(slash + 1) = '\0';

		char primary[MAX_PATH + 32] = {};
		sprintf_s(primary, "%sprobe-trace.log", exePath);

		g_traceFile = CreateFileA(primary, FILE_APPEND_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, nullptr);

		// ★★★ 回退：发布目录是**加固过的**（`Users:(OI)(CI)(RX)`，见
		//   `harden_dist_acl.sh` / 铁律 39）—— 探针以**标准用户**运行时，
		//   在 exe 同目录 `CreateFileA(FILE_APPEND_DATA)` 会 `ACCESS_DENIED(5)`，
		//   痕迹文件**根本不存在**。而这恰恰是"最需要看痕迹"的部署场景：
		//   引擎（管理员）能在那目录写 `r3shieldcore-events.log`，探针（标准用户）不能。
		//
		//   ⇒ 退到 `%TEMP%`（标准用户一定可写）。**用固定名**（不带 pid）：
		//   父进程与 3 个子进程跑的是同一个 exe，必须写进**同一份**痕迹才连得起来
		//   （每行自带 pid + 时间戳，混写也不会串）。
		if (g_traceFile == INVALID_HANDLE_VALUE) {
			char tmp[MAX_PATH] = {};
			const DWORD n = GetTempPathA(MAX_PATH, tmp);
			if (n > 0 && n < MAX_PATH) {
				char fallback[MAX_PATH * 2] = {};
				sprintf_s(fallback, "%sR3ShieldCoreProbeTrace.log", tmp);
				g_traceFile = CreateFileA(fallback, FILE_APPEND_DATA,
					FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
					FILE_ATTRIBUTE_NORMAL, nullptr);
				if (g_traceFile != INVALID_HANDLE_VALUE) {
					strncpy_s(g_tracePath, fallback, _TRUNCATE);
				}
			}
		}
		else {
			strncpy_s(g_tracePath, primary, _TRUNCATE);
		}
	}

	void Trace(const char* fmt, ...)
	{
		if (g_traceFile == INVALID_HANDLE_VALUE || !g_traceLockReady) {
			return;
		}
		EnterCriticalSection(&g_traceLock);

		SYSTEMTIME st = {};
		GetLocalTime(&st);

		char line[768] = {};
		// ★ v51：`t=` 也改用 QPC（原来是 `GetTickCount64`，粒度 15–16 ms，
		//   时间轴上所有事件都被吸到滴答边界上，看不出先后）。
		int n = sprintf_s(line,
			"%04u-%02u-%02u %02u:%02u:%02u.%03u pid=%lu t=%llums  ",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
			st.wMilliseconds, GetCurrentProcessId(),
			static_cast<unsigned long long>(ElapsedUs() / 1000));
		if (n < 0) {
			LeaveCriticalSection(&g_traceLock);
			return;
		}

		va_list ap;
		va_start(ap, fmt);
		const int m = vsprintf_s(line + n, sizeof(line) - static_cast<size_t>(n), fmt, ap);
		va_end(ap);

		if (m >= 0) {
			strcat_s(line, "\r\n");
			DWORD wrote = 0;
			WriteFile(g_traceFile, line, static_cast<DWORD>(strlen(line)), &wrote, nullptr);
		}

		LeaveCriticalSection(&g_traceLock);
	}

	enum class Attempt { Blocked, Succeeded, Other };

	// ---- 子进程侧：量"第一次被拦"发生在进程启动后多少毫秒 ----
	struct ChildResult
	{
		// ★ v51：**微秒**（QPC）。原来是 `blockedAtMs`（`GetTickCount64`，
		//   粒度 15–16 ms）—— 取不到中间值，"同步路"与"10 ms 轮询路"分不开。
		ULONGLONG blockedAtUs = 0;
		bool blockedEver = false;
		// 第一次尝试（还没 Sleep 过）就被拦 ⇒ hook 在**第一次尝试之前**就装好了。
		// ★ 这才是"同步路 vs 轮询路"的**判据**，`blockedAtUs` 只是旁证。
		bool blockedBeforeFirstTry = false;
		// ★ v51：**第一次尝试**发生在进程启动后多少微秒。这是"测量窗口有多干净"
		//   的自证：`--child` 分派 + 测量都排在 TraceInit/printf 之前，所以它应该
		//   是**零点几毫秒**；若还是 5~7 ms，说明前导代码又爬回来了。
		ULONGLONG firstTryUs = 0;
	};

	ChildResult MeasureRunKeyBlock()
	{
		constexpr PCWSTR kRunKey =
			L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
		constexpr PCWSTR kValueName = L"R3ShieldCoreSyncInjectProbe";

		ChildResult r = {};

		for (ULONG waited = 0; waited <= kMaxWaitMs; waited += kPollIntervalMs) {
			Attempt attempt = Attempt::Other;
			if (waited == 0) {
				r.firstTryUs = ElapsedUs();   // ★ v51：测量窗口的起点
			}

			HKEY key = nullptr;
			LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr,
				REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
			if (status != ERROR_SUCCESS) {
				attempt = (status == ERROR_ACCESS_DENIED) ? Attempt::Blocked : Attempt::Other;
			}
			else {
				const WCHAR data[] = L"probe";
				status = RegSetValueExW(key, kValueName, 0, REG_SZ,
					reinterpret_cast<const BYTE*>(data), sizeof(data));
				if (status == ERROR_SUCCESS) {
					// ★ 成功 = 还没被监控 -> 立刻清掉，不留持久化痕迹。
					RegDeleteValueW(key, kValueName);
					attempt = Attempt::Succeeded;
				}
				else {
					attempt = (status == ERROR_ACCESS_DENIED) ? Attempt::Blocked : Attempt::Other;
				}
				RegCloseKey(key);
			}

			if (attempt == Attempt::Blocked) {
				r.blockedEver = true;
				r.blockedAtUs = ElapsedUs();   // ★ v51：QPC，微秒
				r.blockedBeforeFirstTry = (waited == 0);
				return r;
			}

			Sleep(kPollIntervalMs);
		}

		return r;
	}

	// ---- 子进程入口 ----
	int RunChild()
	{
		// ★★★ v51：测量必须是**本进程的第一件事**。
		//
		//   原来这里先 `Trace("RunChild: enter")`，而 `main` 里还排着
		//   `TraceInit()`（CreateFile）、`setlocale`、两条 `printf` + `fflush`
		//   —— 实测这段前导代码要 **5–7 ms**。而 10 ms 轮询路正好能在这段
		//   空隙里把 hook 装上 ⇒ 第一次尝试也会被拦 ⇒ 两种路**分不开**，
		//   而且「第一行代码前就已装好 hook」这句话本身是**假的**。
		//
		//   ⇒ 先量，再 TraceInit / printf。`--child` 的分派也上移到 main 第一行。
		const ChildResult r = MeasureRunKeyBlock();

		TraceInit();
		Trace("RunChild: enter (--child)");
		Trace("RunChild: measured blockedEver=%d blockedAtUs=%llu beforeFirstTry=%d firstTryUs=%llu",
			r.blockedEver ? 1 : 0, r.blockedAtUs, r.blockedBeforeFirstTry ? 1 : 0,
			r.firstTryUs);

		char firstTry[32] = {};
		sprintf_s(firstTry, "%llu", r.firstTryUs);   // 原始微秒

		char atMs[32] = {};
		if (r.blockedEver) {
			sprintf_s(atMs, "%llu.%03llu", r.blockedAtUs / 1000, r.blockedAtUs % 1000);
		}
		else {
			// 没被拦过 ⇒ 时间无意义，别打 0（会看起来像"第一次尝试前就被拦"）。
			strcpy_s(atMs, "--");
		}

		// ★ 先拼成一整行再一次性输出：三个子进程共用同一个控制台，逐个
		//   printf 会被交叉插字符（看起来像乱码）。
		// ★ v51：只有**被拦过**才谈得上"同步路 vs 轮询路"。
		//   没被拦（引擎没跑）时打「掉回轮询路」是**误导** —— 那是"什么都没
		//   发生"，不是"掉了"。（旧版就是无条件打这两句，和 blocked=no 打架。）
		const char* route = "--（没被拦过，无意义）";
		if (r.blockedEver) {
			route = r.blockedBeforeFirstTry ? "YES (= 同步路)" : "no (= 掉回轮询路)";
		}

		char out[224] = {};
		sprintf_s(out,
			"child pid=%-6u firstTryUs=%-8s blockedAtMs=%-9s blocked=%s  beforeFirstTry=%s\n",
			GetCurrentProcessId(), firstTry,
			atMs,
			r.blockedEver ? "yes" : "no",
			route);
		fputs(out, stdout);
		fflush(stdout);

		// 多活一会儿，让日志线程有时间落盘（父进程还要去日志里核对）。
		Sleep(400);
		return 0;
	}

	// ---- 父进程侧小工具 ----
	void QueryParentImage(WCHAR* out, size_t cch)
	{
		out[0] = L'\0';
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return;
		}

		PROCESSENTRY32W entry = { sizeof(entry) };
		const DWORD self = GetCurrentProcessId();
		DWORD parent = 0;
		if (Process32FirstW(snapshot, &entry)) {
			do {
				if (entry.th32ProcessID == self) { parent = entry.th32ParentProcessID; break; }
			} while (Process32NextW(snapshot, &entry));
		}
		if (parent != 0) {
			entry = PROCESSENTRY32W{ sizeof(entry) };
			if (Process32FirstW(snapshot, &entry)) {
				do {
					if (entry.th32ProcessID == parent) {
						wcsncpy_s(out, cch, entry.szExeFile, _TRUNCATE);
						break;
					}
				} while (Process32NextW(snapshot, &entry));
			}
		}
		CloseHandle(snapshot);
	}

	// ---- 在日志里核对：某个 pid 有没有被 WriteVirtualMemory 拦过 ----
	// 日志是 UTF-8；我们只搜 ASCII 片段，所以按字节搜即可（不依赖编码）。
	//
	// ★ `startOffset` = 本进程启动时日志文件的长度。**必须从那里开始扫** ——
	//   日志是**追加**的，一份文件里混着好几次运行，而 pid 会回收；不限定区间
	//   就会把上一轮同 pid 的拦截算到本轮头上（假 FAIL）。这是铁律 45 第 3 条的
	//   直接应用。
	//
	// ★★★ 为什么**必须**用 `CreateFileA` 而不是 `fopen_s(..., "rb")`：
	//   引擎写日志用的是
	//     CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, ...)   （r3shieldcore_log.cpp）
	//   —— 共享模式**只有 `FILE_SHARE_READ`**。CRT 的 `"rb"` 共享模式**不含
	//   `FILE_SHARE_WRITE`**，于是我们这次 open 与引擎那个写句柄冲突 ⇒
	//   `ERROR_SHARING_VIOLATION(32)`，`fopen_s` 直接失败。
	//
	//   ⇒ 症状就是真机看到的：`起始偏移: 0`（`LogCurrentSize` 失败）+ 每个子进程
	//     「日志读不到，跳过」（`CountWriteVirtualMemoryBlocks` 失败）—— 而且
	//     **照样判 PASS**（最坏的一种：静默假绿）。
	//
	//   实测矩阵见 `_t/lock/lock.cpp`：
	//     fopen_s("rb")                              -> 失败 _doserrno=32
	//     CreateFileA(READ, SHARE_READ)              -> 失败 err=32
	//     CreateFileA(READ, SHARE_READ|SHARE_WRITE)  -> 成功   ← 本探针采用
	//     CreateFileA(READ, SHARE_NONE)              -> 失败 err=32
	//
	//   一句话：**Windows 上不声明 `FILE_SHARE_WRITE`，就永远读不到一个"正在被
	//   写的文件"。**

	// 打开"正在被引擎写"的日志，把 `startOffset` 之后的全部字节读进堆缓冲。
	// 返回 nullptr = 打不开（调用方**必须**把"读不到"当**可见异常**处理，
	// 不能静默跳过 —— 否则又是假绿）。非 nullptr 时由调用方 `free()`。
	char* ReadLogFromOffset(const char* path, __int64 startOffset, size_t* outSize)
	{
		*outSize = 0;

		HANDLE h = CreateFileA(path, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			return nullptr;
		}

		if (startOffset > 0) {
			LARGE_INTEGER li = {};
			li.QuadPart = startOffset;
			SetFilePointerEx(h, li, nullptr, FILE_BEGIN);
		}

		size_t cap = 64 * 1024;
		size_t len = 0;
		char* buf = static_cast<char*>(malloc(cap + 1));
		if (!buf) {
			CloseHandle(h);
			return nullptr;
		}

		for (;;) {
			if (len + 4096 > cap) {
				const size_t ncap = cap * 2;
				char* nb = static_cast<char*>(realloc(buf, ncap + 1));
				if (!nb) {
					free(buf);
					CloseHandle(h);
					return nullptr;
				}
				buf = nb;
				cap = ncap;
			}
			DWORD got = 0;
			if (!ReadFile(h, buf + len, 4096, &got, nullptr) || got == 0) {
				break;
			}
			len += got;
		}

		CloseHandle(h);
		buf[len] = '\0';
		*outSize = len;
		return buf;
	}

	int CountWriteVirtualMemoryBlocks(const char* logPath, __int64 startOffset, DWORD childPid)
	{
		size_t len = 0;
		char* buf = ReadLogFromOffset(logPath, startOffset, &len);
		if (!buf) {
			return -1;   // 打不开
		}

		char needlePid[32] = {};
		sprintf_s(needlePid, "(pid=%lu)", childPid);

		int hits = 0;
		char* p = buf;
		char* const end = buf + len;
		while (p < end) {
			char* nl = static_cast<char*>(memchr(p, '\n', static_cast<size_t>(end - p)));
			if (nl) {
				*nl = '\0';   // 就地断行（缓冲区用完即 free，不还原）
			}
			if (strstr(p, "WriteVirtualMemory") && strstr(p, "BLOCK") && strstr(p, needlePid)) {
				hits++;
			}
			if (!nl) {
				break;
			}
			p = nl + 1;
		}

		free(buf);
		return hits;
	}

	// 取日志当前长度（= 本次运行的起点）。
	__int64 LogCurrentSize(const char* logPath)
	{
		HANDLE h = CreateFileA(logPath, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			return -1;
		}
		LARGE_INTEGER size = {};
		const bool ok = GetFileSizeEx(h, &size) != 0;
		CloseHandle(h);
		return ok ? size.QuadPart : -1;
	}

	bool TryResolveLogPath(const char* argPath, char* out, size_t cch)
	{
		if (argPath && argPath[0]) {
			if (GetFileAttributesA(argPath) != INVALID_FILE_ATTRIBUTES) {
				strncpy_s(out, cch, argPath, _TRUNCATE);
				return true;
			}
			return false;
		}

		char exePath[MAX_PATH] = {};
		GetModuleFileNameA(nullptr, exePath, MAX_PATH);
		char* slash = strrchr(exePath, '\\');
		if (!slash) {
			return false;
		}
		*slash = '\0';

		// 候选 1：exe 同目录（在**发布目录**里跑时就是它 —— 正确）
		// 候选 2：`..\dist\R3ShieldCore-x64*\r3shieldcore-events.log`，取 **mtime 最新**的那个。
		//
		// ★ v50 修：原来候选 2 硬编码 `R3ShieldCore-x64`（**无版本后缀**）。
		//   项目现在有 `R3ShieldCore-x64-v49` 这类带版本的部署目录，从 `tools/`
		//   跑时会命中**老目录**；而引擎往新目录写 ⇒ 探针扫的永远是老文件
		//   ⇒ `起始偏移 == 文件大小`（扫 0 字节）⇒ 三条 `[OK]` 是**空扫**、
		//   判定必然 PASS。**这是最危险的一种假绿：引擎在跑也照样 PASS。**
		{
			char candidate[MAX_PATH * 2] = {};
			sprintf_s(candidate, "%s\\r3shieldcore-events.log", exePath);
			if (GetFileAttributesA(candidate) != INVALID_FILE_ATTRIBUTES) {
				strncpy_s(out, cch, candidate, _TRUNCATE);
				return true;
			}
		}

		char best[MAX_PATH * 2] = {};
		FILETIME bestTime = {};
		{
			char pattern[MAX_PATH * 2] = {};
			sprintf_s(pattern, "%s\\..\\dist\\*", exePath);
			WIN32_FIND_DATAA fd = {};
			HANDLE find = FindFirstFileA(pattern, &fd);
			if (find != INVALID_HANDLE_VALUE) {
				do {
					if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) { continue; }
					if (_strnicmp(fd.cFileName, "R3ShieldCore-x64", 12) != 0) { continue; }
					char candidate[MAX_PATH * 2] = {};
					sprintf_s(candidate, "%s\\..\\dist\\%s\\r3shieldcore-events.log",
						exePath, fd.cFileName);
					WIN32_FILE_ATTRIBUTE_DATA attr = {};
					if (!GetFileAttributesExA(candidate, GetFileExInfoStandard, &attr)) {
						continue;
					}
					if (best[0] == '\0' ||
						CompareFileTime(&attr.ftLastWriteTime, &bestTime) > 0) {
						strncpy_s(best, candidate, _TRUNCATE);
						bestTime = attr.ftLastWriteTime;
					}
				} while (FindNextFileA(find, &fd));
				FindClose(find);
			}
		}
		if (best[0] != '\0') {
			strncpy_s(out, cch, best, _TRUNCATE);
			return true;
		}
		return false;
	}

	// 日志的**最后写入时间**（分钟）。取不到返回 -1。
	// 用途：引擎没在往这个文件写时，"日志核对"必然空扫 —— 提前讲出来。
	long long LogAgeMinutes(const char* path)
	{
		WIN32_FILE_ATTRIBUTE_DATA attr = {};
		if (!path || !path[0] || !GetFileAttributesExA(path, GetFileExInfoStandard, &attr)) {
			return -1;
		}
		FILETIME now = {};
		GetSystemTimeAsFileTime(&now);
		ULARGE_INTEGER wrote = {};
		wrote.LowPart = attr.ftLastWriteTime.dwLowDateTime;
		wrote.HighPart = attr.ftLastWriteTime.dwHighDateTime;
		ULARGE_INTEGER cur = {};
		cur.LowPart = now.dwLowDateTime;
		cur.HighPart = now.dwHighDateTime;
		if (cur.QuadPart <= wrote.QuadPart) {
			return 0;
		}
		return static_cast<long long>((cur.QuadPart - wrote.QuadPart) / 600000000ULL);
	}

	// 三个子进程里有几个**真的被拦过**（`blockedEver=1`）。
	//
	// ★ v50：这是判定的**前提**。子进程自报 `blocked=no` 说明 HKCU Run 写成功了
	//   = 它压根没装 hook（没被注入，或模式不是 block）。此时"引擎没拦自己的
	//   注入写入"是废话 —— 原判定不看这个，导致**引擎没跑也照样 PASS**。
	//
	//   数据来源：子进程已经在 `probe-trace.log` 里写了
	//   `RunChild: measured blockedEver=<0|1> blockedAtMs=<n>`，按 pid 取即可。
	//
	// ★ 返回值 = **读到的子进程结果行数**（不是"被拦数"！）。
	//   这样"读不到痕迹/解析坏了"（返回 -1 或 0）和"读到了但都没被拦"
	//   （返回 count、*outBlocked = 0）能分开 —— 否则解析器坏了会伪装成
	//   "前提不成立"，而**前提不成立**本身又会被伪装成 PASS。
	//   被拦条数通过 `outBlocked` 带出。
	//   ★ 只扫 `startOffset` **之后**的字节：痕迹文件是**追加**的，pid 会回收
	//     （铁律 45），扫全文件会把上一轮同 pid 的行算到本轮头上。
	int CountChildrenEverBlocked(const char* tracePath, __int64 startOffset,
		const DWORD* pids, int count, int* outBlocked)
	{
		if (outBlocked) { *outBlocked = 0; }
		if (!tracePath || !tracePath[0]) {
			return -1;
		}
		// 同 v49 读日志：写方持 FILE_APPEND_DATA + SHARE_READ|WRITE，
		// 读方必须声明 SHARE_WRITE，否则必然 ERROR_SHARING_VIOLATION(32)。
		HANDLE h = CreateFileA(tracePath, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			return -1;
		}

		LARGE_INTEGER offset = {};
		offset.QuadPart = (startOffset > 0) ? startOffset : 0;
		if (!SetFilePointerEx(h, offset, nullptr, FILE_BEGIN)) {
			CloseHandle(h);
			return -1;
		}

		std::string data;
		char buf[4096] = {};
		DWORD got = 0;
		while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) {
			data.append(buf, got);
		}
		CloseHandle(h);

		int linesSeen = 0;
		int blockedCount = 0;
		for (int i = 0; i < count; ++i) {
			if (!pids[i]) { continue; }
			char needle[64] = {};
			sprintf_s(needle, "pid=%lu ", static_cast<unsigned long>(pids[i]));
			size_t pos = 0;
			while ((pos = data.find(needle, pos)) != std::string::npos) {
				const size_t eol = data.find('\n', pos);
				const size_t end = (eol == std::string::npos) ? data.size() : eol;
				const std::string line = data.substr(pos, end - pos);
				const size_t mark = line.find("RunChild: measured blockedEver=");
				if (mark != std::string::npos) {
					++linesSeen;
					if (line.find("blockedEver=1", mark) != std::string::npos) {
						++blockedCount;
					}
					break;  // 这个 pid 的行已找到（blockedEver 是 0 或 1）
				}
				pos = end + 1;
			}
		}
		if (outBlocked) { *outBlocked = blockedCount; }
		return linesSeen;
	}
}

int main(int argc, char** argv)
{
	// ★★★ v51：`--child` 必须在**这里**分派 —— 任何 `TraceInit` / `printf`
	//   都不能排在测量之前（那段前导实测 5~7 ms，会把「同步路 vs 轮询路」
	//   的时间判据糊掉；见 RunChild 顶部注释）。
	for (int i = 1; i < argc; ++i) {
		if (_stricmp(argv[i], "--child") == 0) {
			return RunChild();
		}
	}

	// ==================================================================
	// ★★★ v48：**这里必须是本进程的第一条语句**。
	//
	// 顺序变了（原来是先解析参数 / 找日志 / 查父进程，最后才 printf）：
	//   · 原来"窗口空白"时完全没法区分是"没进 main"还是"printf 被吞了"，
	//     因为第一个 printf 排在 `CreateToolhelp32Snapshot` 等调用之后 ——
	//     任何一步卡住都会让窗口看起来是空的。
	//   · 现在：文件痕迹 + 横幅**先打**，之后才是别的工作。
	// ==================================================================
	TraceInit();
	Trace("main: enter, argc=%d", argc);
	for (int i = 1; i < argc; ++i) {
		Trace("main: argv[%d]=%s", i, argv[i]);
	}

	setlocale(LC_ALL, "");

	// ★ 关掉 stdout 缓冲：父进程和子进程共用同一个控制台，若各自缓冲，
	//   子进程的输出会整块插到父进程输出前面，看起来像"顺序乱了"。
	setvbuf(stdout, nullptr, _IONBF, 0);

	printf("=== sync_inject_probe (v51) ===\n");
	printf("本进程 pid=%lu\n", GetCurrentProcessId());
	// ★ 把**实际**痕迹路径打出来：加固目录下会回退到 %TEMP%，不打出来就找不到。
	if (g_tracePath[0]) {
		printf("执行轨迹: %s\n", g_tracePath);
	}
	else {
		printf("执行轨迹: **不可用**（exe 同目录与 %%TEMP%% 都建不了 probe-trace.log）\n");
	}
	fflush(stdout);
	Trace("main: banner printed");

	// ★ v51：`--child` 已在本函数**开头**分派掉了，这里不再重复检查。

	const bool noPause = [&]() {
		for (int i = 1; i < argc; ++i) {
			if (_stricmp(argv[i], "--no-pause") == 0) { return true; }
		}
		return false;
	}();

	const char* logArg = nullptr;
	for (int i = 1; i < argc; ++i) {
		if (_stricmp(argv[i], "--log") == 0 && i + 1 < argc) {
			logArg = argv[i + 1];
		}
	}

	// ★ 先定位日志并记下**当前长度**：日志是追加的，必须只扫本次运行之后的字节
	//   （否则 pid 回收会把上一轮的拦截算进来 = 假 FAIL）。
	char logPath[MAX_PATH * 2] = {};
	const bool haveLog = TryResolveLogPath(logArg, logPath, _countof(logPath));
	__int64 logStart = 0;
	// `TryResolveLogPath` 已经确认文件**存在**（GetFileAttributes 通过），
	// 所以这里返回 -1 只可能是"打不开"（权限 / 共享冲突），**不是**"文件不存在"。
	// 必须记下来并让判定看得见 —— 这正是 v48 真机上被静默吞掉的那个失败。
	bool logStartUnreadable = false;
	if (haveLog) {
		logStart = LogCurrentSize(logPath);
		if (logStart < 0) {
			logStartUnreadable = true;
			logStart = 0;
		}
	}
	Trace("main: log resolved=%d path=%s start=%lld unreadable=%d", haveLog ? 1 : 0,
		haveLog ? logPath : "(none)", static_cast<long long>(logStart),
		logStartUnreadable ? 1 : 0);

	WCHAR parentImage[MAX_PATH] = {};
	QueryParentImage(parentImage, _countof(parentImage));
	Trace("main: parent queried");

	// 这里**不用** `printf("...%ls...", parentImage)`，改成显式转窄串：
	//   窄 printf 的 `%ls` 走 "C" locale，遇第一个非 ASCII 字符（父进程路径里若有中文，
	//   或下面这个 `(取不到)` 兜底串**本身就带中文**）就转换失败 ⇒ **整个 printf
	//   提前返回**、连结尾 `\n` 都不写 ⇒ 输出被截断并和下一行粘连。
	//
	//   ⚠️ 本文件第 361 行**已经**调了 `setlocale(LC_ALL, "")`（早于这里），
	//      所以**这处本来并不会坏** —— 实测见 `_t/ls/ls.cpp`（setlocale 确实能修）。
	//      改成显式转换是**加固**：不依赖 locale 是否设置、何时设置，后人调整
	//      `setlocale` 的位置或加一个更早的 `%ls` 都不会把它改坏。
	//      （真实踩坑的是 `_t/sess/sess.cpp` —— 那里没调 setlocale。）
	{
		char parentA[MAX_PATH * 2] = {};
		if (parentImage[0]) {
			WideCharToMultiByte(CP_ACP, 0, parentImage, -1, parentA,
				sizeof(parentA), nullptr, nullptr);
		}
		else {
			strcpy_s(parentA, "(取不到)");
		}
		printf("\n父进程 映像=%s\n", parentA);
	}
	printf("  · 父进程若是 explorer.exe / svchost.exe -> 本进程由**瘦宿主**的同步路注入\n");
	printf("  · 本进程一定是被**全量注入**的（有 hook），所以它拉子进程时才会暴露注入自锁\n\n");

	// ---- 创建子进程（这一步就是被测行为）----
	char selfPath[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, selfPath, MAX_PATH);

	printf("创建 %d 个子进程（全量注入的父进程 -> 本应走「同步注入路」）：\n", kChildCount);
	Trace("main: creating %d children", kChildCount);

	// ★ v50：记下痕迹文件的**当前长度** —— 子进程的结果行只会出现在它之后。
	//   痕迹是追加的、pid 会回收；不切这一刀会把上一轮同 pid 的行算到本轮头上。
	const __int64 traceStart = g_tracePath[0] ? LogCurrentSize(g_tracePath) : -1;

	DWORD childPids[kChildCount] = {};
	HANDLE children[kChildCount] = {};
	for (int i = 0; i < kChildCount; ++i) {
		char cmdLine[MAX_PATH + 32] = {};
		sprintf_s(cmdLine, "\"%s\" --child", selfPath);

		STARTUPINFOA si = { sizeof(si) };
		PROCESS_INFORMATION pi = {};
		if (CreateProcessA(nullptr, cmdLine, nullptr, nullptr, FALSE, 0,
			nullptr, nullptr, &si, &pi)) {
			childPids[i] = pi.dwProcessId;
			children[i] = pi.hProcess;
			CloseHandle(pi.hThread);
			printf("  子 %d: pid=%lu\n", i + 1, pi.dwProcessId);
			Trace("main: child %d created pid=%lu", i + 1, pi.dwProcessId);
		}
		else {
			printf("  子 %d: 创建失败 err=%lu\n", i + 1, GetLastError());
			Trace("main: child %d FAILED err=%lu", i + 1, GetLastError());
		}
	}

	printf("\n--- 子进程自报（每个子进程在**第一行代码**就试写 Run 键）---\n");
	for (int i = 0; i < kChildCount; ++i) {
		if (children[i]) {
			WaitForSingleObject(children[i], 8000);
			CloseHandle(children[i]);
		}
	}
	Trace("main: children waited");

	// ★ v50：先取**前提** —— 子进程自报里"有几个真的被拦过"。
	//   一个都没被拦 ⇒ 它们没装 hook ⇒ 下面的日志核对和"判定"都是空谈。
	int everBlockedCount = 0;
	const int childLines = CountChildrenEverBlocked(g_tracePath, traceStart,
		childPids, kChildCount, &everBlockedCount);
	Trace("main: childLines=%d everBlocked=%d", childLines, everBlockedCount);

	printf("\n--- 前提核对（子进程自报，来自 %s）---\n",
		g_tracePath[0] ? g_tracePath : "**无痕迹文件**");
	printf("读到子进程结果: %d/%d 条，其中被拦: %d 条\n",
		childLines < 0 ? 0 : childLines, kChildCount, everBlockedCount);

	printf("\n--- 日志核对（只扫本次运行之后的字节，避开 pid 回收）---\n");
	// 判定三态：0=PASS，1=FAIL，2=**无法判定**（日志读不到）。
	// ★ "读不到日志"绝不能再算 PASS —— 那是本项目最忌讳的**假绿**：
	//   修复前 `fopen_s` 打不开日志（共享冲突），三个子进程全"跳过"，
	//   程序照样打印 PASS，把"根本没核对"伪装成"核对通过"。
	int verdict = 0;
	if (haveLog) {
		printf("日志: %s\n起始偏移: %lld%s\n", logPath, static_cast<long long>(logStart),
			logStartUnreadable ? "  **（打不开，无法定位起点）**" : "");
		// ★ v50：把日志的**最后写入时间**摆出来。引擎没在往这个文件写时，
		//   上面的"起始偏移"会等于文件总大小（扫 0 字节），三条 [OK] 就是空扫。
		{
			const long long age = LogAgeMinutes(logPath);
			if (age >= 0) {
				printf("日志最后写入: %lld 分钟前%s\n", age,
					age >= 60 ? "  **← 引擎很可能没在写这个文件，本次核对是空扫**" : "");
			}
		}
		// ★ v50：本轮**日志有没有增长**。引擎在跑就一定会往它自己那个日志里写；
		//   本轮 0 增长 ⇒ 探针读的**不是引擎正在写的那个文件**（典型原因：
		//   部署目录有多个版本、路径解析落到了别的目录）⇒ 核对是空扫。
		{
			const __int64 logEnd = LogCurrentSize(logPath);
			const long long grew = (!logStartUnreadable && logStart >= 0 && logEnd >= 0)
				? static_cast<long long>(logEnd - logStart) : -1;
			printf("本轮日志增长: %lld 字节%s\n", grew,
				(grew == 0) ? "  **← 0 增长 = 引擎没在写这个文件，本次核对是空扫**" : "");
		}
		int bad = 0;
		int unreadable = 0;
		for (int i = 0; i < kChildCount; ++i) {
			if (!childPids[i]) { continue; }
			const int hits = CountWriteVirtualMemoryBlocks(logPath, logStart, childPids[i]);
			if (hits < 0) {
				unreadable++;
				printf("  子 %d (pid=%lu): **日志读不到**（打不开 / 共享冲突）—— 无法核对\n",
					i + 1, childPids[i]);
				continue;
			}
			if (hits == 0) {
				printf("  子 %d (pid=%lu): 无 WriteVirtualMemory 拦截 [OK]\n", i + 1, childPids[i]);
			}
			else {
				bad++;
				printf("  子 %d (pid=%lu): **%d 条** PROC BLOCK ... WriteVirtualMemory [BAD]（注入自锁还在）\n",
					i + 1, childPids[i], hits);
			}
		}

		if (bad > 0) {
			verdict = 1;
			printf("\n判定：FAIL —— 引擎仍在拦自己的注入写入\n");
		}
		else if (childLines <= 0) {
			// ★ v50：**前提未知**。痕迹文件读不到（或解析不到子进程结果行）
			//   ⇒ 无法知道子进程有没有被注入 ⇒ 不能 PASS。
			verdict = 2;
			printf("\n判定：**无法判定** —— 读不到子进程自报（%d/%d 条）\n",
				childLines < 0 ? 0 : childLines, kChildCount);
			printf("      痕迹文件: %s\n",
				g_tracePath[0] ? g_tracePath : "(建不出来)");
			printf("      没有它就无法确认「子进程到底装没装 hook」，**不算 PASS**。\n");
		}
		else if (everBlockedCount == 0) {
			// ★ v50：前提不成立。子进程都写成功了 Run 键 ⇒ 它们**没装 hook**
			//   ⇒ "引擎没拦自己的注入写入"是废话（没注入当然没拦）。
			verdict = 2;
			printf("\n判定：**无法判定** —— %d 个子进程一个都没被拦（blocked=no）\n",
				childLines);
			printf("      说明它们**没装 hook**：引擎没在跑 / 没注入本进程 / 模式不是 block。\n");
			printf("      这种前提下「没拦自己的注入写入」是废话，**不算 PASS**。\n");
			printf("      请先确认引擎在跑（BLOCK 模式）再跑本探针。\n");
		}
		else if (unreadable > 0 || logStartUnreadable) {
			verdict = 2;
			printf("\n判定：**无法判定** —— 日志读不到（%d 个子进程未核对）\n", unreadable);
			printf("      （不是 PASS！请确认引擎在跑、日志可读，或改用 --log <路径>）\n");
		}
		else {
			verdict = 0;
			printf("\n判定：PASS —— 引擎没有拦自己的注入写入\n");
		}
		Trace("main: verdict=%d bad=%d unreadable=%d", verdict, bad, unreadable);
	}
	else {
		verdict = 2;
		printf("没找到 r3shieldcore-events.log（可用 --log <路径> 指定）—— 无法判定。请手工核对：\n");
		for (int i = 0; i < kChildCount; ++i) {
			if (childPids[i]) {
				printf("  pid=%lu -> 不应出现 `PROC BLOCK ... WriteVirtualMemory ... (pid=%lu)`\n",
					childPids[i], childPids[i]);
			}
		}
	}

	printf("\n提示：判定要看子进程自报的 **beforeFirstTry** ——\n");
	printf("  beforeFirstTry=YES -> 第一次尝试就被拦 = hook 在第一次尝试前就在了 = **同步路**\n");
	printf("  beforeFirstTry=no  -> 第一次尝试漏了、之后才被拦 = 掉回 10 ms **轮询路**\n");
	printf("  blockedAtMs 只是旁证（v51 起改用 QPC，微秒精度）。\n");
	printf("  ★ **别再用 blockedAtMs 跟 0 比**：`GetTickCount64` 粒度 15.6 ms，\n");
	printf("    旧图例「0=正常 / >0=失效」会**每轮随机误报一次「同步路失效」**。\n");
	printf("  三个子进程都 blocked=no -> 引擎没在跑（或没注入本进程）\n");
	printf("\n（本次运行的执行轨迹: %s）\n",
		g_tracePath[0] ? g_tracePath : "不可用（exe 同目录与 %TEMP% 都建不了）");

	if (!noPause) {
		printf("\n按回车退出...");
		(void)getchar();
	}
	Trace("main: exit verdict=%d", verdict);
	return verdict;
}
