//
// inject_race_probe.cpp —— 实测「新进程被注入之前」的**盲区有多长**。
//
// ==================================================================
// 为什么需要这个探针（真实绕过，v41）
// ==================================================================
//
// 样本 `Windows XP Horror` 在 `FormCreate` 里 —— 也就是**进程启动后
// 几十~几百毫秒**——就执行：
//
//   h = CreateFileA("\\\\.\\PhysicalDrive0", 0x10000000, 3, 0, 3, 0, 0);
//   WriteFile(h, buf, 0x2800, &written, 0);
//
// 而 R3ShieldCore 是**用户态注入**：新进程必须先被注入 DLL、hook 装好，
// 才谈得上拦截。所以在"进程启动"到"hook 生效"之间有一段**盲区**，
// 落在这段里的写操作**一律拦不住**。
//
// 本探针就是量这段盲区的长度。
//
// ==================================================================
// ★ 必须用「双击」或「右键→以管理员身份运行」启动
// ==================================================================
//
// 盲区只存在于**父进程没有被注入**的时候。而引擎有两条注入路：
//
//   ① 同步路 —— 在**父进程**里 hook `CreateProcessInternalW`，
//      强制 `CREATE_SUSPENDED` → 注入 → 再 `ResumeThread`。
//      子进程**跑第一行代码之前** hook 就装好了 -> 盲区 ≈ 0。
//   ② 轮询路 —— 引擎定期枚举新进程再注入 -> 盲区 = 轮询间隔 + 注入耗时。
//
//   ★ 而 `cmd.exe` / `powershell.exe` / 绝大多数程序**都是被注入的**，
//     从它们里面启动本探针会走①，盲区恒为 0 —— **测不出问题**。
//
//   只有**没被注入的父进程**（`explorer.exe` 双击 / 提权时的
//   `svchost.exe`）才走②，那才是"用户双击运行病毒"的真实场景。
//
//   所以：**双击本 exe**，或**右键 → 以管理员身份运行**。不要从 cmd 里敲。
//
// ==================================================================
// 安全说明
// ==================================================================
//
//   · 第 1 组：往 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//     写一个值 `R3ShieldCoreRaceProbe`，**成功就立刻删掉**。
//     这条命中高危规则表里的「自启动项(Run)」，而且是 **HKCU** ——
//     **普通用户就能写** -> 不需要提权，任何情况下都能测。
//
//     ★ 为什么不用"启动目录建文件"：`\Startup\` 虽然也是高危规则，
//       但它属于**普通文件操作**，而发布默认是 `hook_file=0` ——
//       `Evaluate` 会在 `FlagHookFile` 没开时**直接 Pass**（见
//       file_guard.cpp 的 v39 注释）。于是探针会**假 FAIL**：
//       hook 明明装好了，却因为"文件监控关着"而放行。
//       注册表写入**不受 `hook_file` 影响**，是干净的代理信号。
//
//   · 第 2 组：**只打开、绝不写**裸盘（真写会当场毁引导区，不可逆）。
//     "打开"就是拦截点 —— 被拒就拿不到句柄，`WriteFile` 根本到不了。
//     需要提权才有意义；未提权时标 SKIP。
//
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

namespace
{
	// ★ 在**全局初始化**阶段就取时间戳 —— 比 main 更早，
	//   尽量贴近"进程开始运行"那一刻。
	const ULONGLONG g_entryTick = GetTickCount64();

	constexpr ULONG kSampleAccess = 0x10000000;   // GENERIC_ALL（样本用的值）
	constexpr DWORD kSampleShare = FILE_SHARE_READ | FILE_SHARE_WRITE;
	constexpr ULONG kPollIntervalMs = 10;
	constexpr ULONG kMaxWaitMs = 5000;

	bool g_elevated = false;

	bool IsElevated() noexcept
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}
		TOKEN_ELEVATION elevation = {};
		DWORD returned = 0;
		const BOOL ok = GetTokenInformation(token, TokenElevation,
			&elevation, sizeof(elevation), &returned);
		CloseHandle(token);
		return ok && elevation.TokenIsElevated != 0;
	}

	// 父进程名（explorer / svchost / cmd ...）—— 用来判断这次测的是哪条路。
	void ParentNameOf(WCHAR* out, size_t cch) noexcept
	{
		out[0] = L'\0';

		// 用 NtQueryInformationProcess 拿 InheritedFromUniqueProcessId 太重，
		// 这里用 Toolhelp 快照反查（进程不多，开销可忽略）。
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE) {
			return;
		}

		PROCESSENTRY32W entry = { sizeof(entry) };
		const DWORD self = GetCurrentProcessId();
		DWORD parent = 0;
		if (Process32FirstW(snapshot, &entry)) {
			do {
				if (entry.th32ProcessID == self) {
					parent = entry.th32ParentProcessID;
					break;
				}
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

	// 一次尝试的结果。
	enum class Attempt
	{
		Blocked,     // 被拒（ACCESS_DENIED）-> 已被监控
		Succeeded,   // 成功 -> 还没被监控
		Other,       // 别的错误（不是"拦住了"）
	};

	struct ProbeResult
	{
		ULONG firstAttemptMs = 0;      // 第一次尝试发生在进程启动后多少 ms
		Attempt firstAttempt = Attempt::Other;
		bool blockedEver = false;
		ULONG blockedAtMs = 0;         // 第一次被拦住时，距进程启动多少 ms
		bool protectedBeforeFirstLine = false;  // 第一次尝试就已经被拦
	};

	// 通用循环：立刻试一次，然后每 kPollIntervalMs 试一次，直到被拦或超时。
	template <typename Fn>
	ProbeResult Measure(Fn&& attemptOnce) noexcept
	{
		ProbeResult r = {};
		r.firstAttemptMs = static_cast<ULONG>(GetTickCount64() - g_entryTick);

		for (ULONG waited = 0; waited <= kMaxWaitMs; waited += kPollIntervalMs) {
			const Attempt result = attemptOnce();

			if (r.firstAttempt == Attempt::Other && waited == 0) {
				r.firstAttempt = result;
			}

			if (result == Attempt::Blocked) {
				r.blockedEver = true;
				r.blockedAtMs = static_cast<ULONG>(GetTickCount64() - g_entryTick);
				r.protectedBeforeFirstLine = (waited == 0);
				return r;
			}

			if (result == Attempt::Other) {
				// 别的错误（比如未提权）—— 继续等没有意义，但再等一轮看看。
				// 这里只把第一次的结果记下来，循环仍继续（可能只是权限问题）。
			}

			Sleep(kPollIntervalMs);
		}

		return r;
	}

	// ---- 第 1 组：写 HKCU 的 Run 键（普通用户可写，命中高危规则「自启动项(Run)」）----
	//
	// ★ 这一组是"注入是否已完成"的**代理信号**：注册表 hook 与文件 hook
	//   由同一个 DLL 在同一次 DllMain 里装上，所以"Run 键被拦"⇒"裸盘 hook 也装好了"。
	// ★ 值名固定，成功写入后**立刻删除**（不留持久化痕迹）。
	ProbeResult MeasureRegistryRun(bool& pathOk)
	{
		pathOk = true;

		constexpr PCWSTR kRunKey =
			L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
		constexpr PCWSTR kValueName = L"R3ShieldCoreRaceProbe";

		return Measure([&]() -> Attempt {
			HKEY key = nullptr;
			LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr,
				REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);

			if (status != ERROR_SUCCESS) {
				// 打不开（写意图）也可能是引擎拦的。
				return (status == ERROR_ACCESS_DENIED) ? Attempt::Blocked : Attempt::Other;
			}

			const WCHAR data[] = L"probe";
			status = RegSetValueExW(key, kValueName, 0, REG_SZ,
				reinterpret_cast<const BYTE*>(data), sizeof(data));

			if (status != ERROR_SUCCESS) {
				RegCloseKey(key);
				return (status == ERROR_ACCESS_DENIED) ? Attempt::Blocked : Attempt::Other;
			}

			// 写进去了 —— 立刻清掉，**不留任何自启动项**。
			RegDeleteValueW(key, kValueName);
			RegCloseKey(key);
			return Attempt::Succeeded;
		});
	}

	// ---- 第 2 组：裸盘（只打开，不写）----
	ProbeResult MeasureRawDisk()
	{
		return Measure([]() -> Attempt {
			HANDLE handle = CreateFileA("\\\\.\\PhysicalDrive0", kSampleAccess,
				kSampleShare, nullptr, OPEN_EXISTING, 0, nullptr);

			if (handle == INVALID_HANDLE_VALUE) {
				const DWORD err = GetLastError();
				return (err == ERROR_ACCESS_DENIED) ? Attempt::Blocked : Attempt::Other;
			}

			CloseHandle(handle);   // ★ 只打开、绝不写
			return Attempt::Succeeded;
		});
	}

	const char* AttemptText(Attempt a) noexcept
	{
		switch (a) {
		case Attempt::Blocked:   return "被拒(ACCESS_DENIED)";
		case Attempt::Succeeded: return "成功(没被拦)";
		default:                 return "其它错误";
		}
	}

	// 打印一组结果 + 结论。
	// sensitiveToElevation: true = 未提权时结果不可信（裸盘那组）。
	void Report(const char* title, const ProbeResult& r, bool skipped)
	{
		printf("-- %s --\n", title);

		if (skipped) {
			printf("  SKIP：未提权 —— 打开失败可能只是设备 ACL，不能证明 R3ShieldCore。\n");
			printf("        请用「右键 → 以管理员身份运行」重跑。\n\n");
			return;
		}

		printf("  第一次尝试 : 进程启动后 %lu ms  →  %s\n",
			static_cast<unsigned long>(r.firstAttemptMs), AttemptText(r.firstAttempt));

		if (r.protectedBeforeFirstLine) {
			printf("  ★ 第一行代码之前就已经被监控 —— 盲区 ≈ 0（同步注入路生效）\n");
			printf("     [!] 这说明本次是**从已注入的父进程**启动的（走了同步路），\n");
			printf("        测不出轮询盲区。请**双击**本 exe 重跑。\n\n");
			return;
		}

		if (!r.blockedEver) {
			printf("  ★★ %lu ms 内**始终没被拦** —— 三种可能：\n",
				static_cast<unsigned long>(kMaxWaitMs));
			printf("       ① 引擎没在运行；② 这个进程没被注入；③ 模式不是 block。\n");
			printf("       查 r3shieldcore-console.log 的「注入新进程」与「注入扫描间隔」。\n\n");
			return;
		}

		printf("  首次被拦   : 进程启动后 %lu ms\n",
			static_cast<unsigned long>(r.blockedAtMs));
		printf("  -> 本次**盲区 ≈ %lu ms**（进程启动 → hook 生效）\n",
			static_cast<unsigned long>(r.blockedAtMs));

		if (r.blockedAtMs <= 60) {
			printf("  [PASS] 盲区够短：样本那点启动开销（几十~几百 ms）跑不完。\n");
		}
		else if (r.blockedAtMs <= 300) {
			printf("  [WARN] 盲区偏大：启动很快的样本仍可能抢跑。\n");
			printf("         把 ini 的 inject_interval_ms 调小（如 5 或 1）再测。\n");
		}
		else {
			printf("  [FAIL] 盲区太大：启动快的样本几乎必然抢跑。\n");
			printf("         确认 ini 里 inject_interval_ms 生效（重启引擎后才生效）。\n");
		}
		printf("\n");
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	bool noPause = false;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--no-pause") == 0) {
			noPause = true;
		}
	}

	g_elevated = IsElevated();

	WCHAR parent[64] = {};
	ParentNameOf(parent, _countof(parent));

	printf("=== R3ShieldCore 注入盲区实测探针 ===\n");
	printf("进程启动   : %llu (tick)\n", static_cast<unsigned long long>(g_entryTick));
	printf("父进程     : %ls\n", parent[0] ? parent : L"(未知)");
	printf("提权状态   : %s\n", g_elevated ? "已提权" : "未提权");
	printf("轮询间隔   : %lu ms（探针自身的重试间隔，不是引擎的）\n\n",
		static_cast<unsigned long>(kPollIntervalMs));

	//
	// [!] 父进程提醒：从 cmd / powershell 里启动**测不出轮询盲区**。
	//
	if (parent[0] != L'\0'
		&& _wcsicmp(parent, L"explorer.exe") != 0
		&& _wcsicmp(parent, L"svchost.exe") != 0) {
		printf("[!] 父进程是 %ls —— 它**很可能已被引擎注入**，\n", parent);
		printf("    于是本探针走的是同步注入路，盲区会显示为 0，**测不出问题**。\n");
		printf("    ★ 请关掉本窗口，直接**双击**本 exe 重跑（父进程 = explorer.exe）。\n\n");
	}

	bool runKeyOk = false;
	const ProbeResult registry = MeasureRegistryRun(runKeyOk);
	Report("第 1 组：写 HKCU Run 键（普通用户可写，命中高危规则「自启动项(Run)」）",
		registry, !runKeyOk);

	const ProbeResult rawdisk = MeasureRawDisk();
	Report("第 2 组：写意图打开 \\\\.\\PhysicalDrive0（样本同款；只打开不写盘）",
		rawdisk, !g_elevated);

	printf("=== 结论 ===\n");
	printf("  「盲区」= 进程启动 → R3ShieldCore hook 生效 之间的时间。\n");
	printf("  样本在 FormCreate 里（几十~几百 ms）就写 MBR -> 盲区必须远小于它。\n");
	printf("  引擎侧可调项：r3shieldcore.ini 的 inject_interval_ms（默认 10，改完重启引擎）。\n");
	printf("  最终确认看 r3shieldcore-events.log：reason=裸盘/物理盘写入(引导区)。\n");

	if (!noPause) {
		printf("\n按回车键退出...");
		(void)getchar();
	}
	return 0;
}
