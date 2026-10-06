//
// ark_actions_ut.cpp —— `ark_actions.{h,cpp}` 的单元测试（v62）
//
// ==================================================================
// 为什么这套动作必须"真起一个进程"来测
// ==================================================================
//
// 这四种处置（挂起 / 恢复 / 内部退出 / 强制结束）**全是副作用型功能**：
// 函数返回 `Ok` 和"目标真的被挂起了"是两件完全不同的事。
// 只看返回码的测试，对下面每一条都会给出假绿：
//
//   · `NtSuspendProcess` 返回 >= 0，但目标某个线程正在内核里跑、
//     根本没停下来 —— 返回码照样是成功。
//   · `TerminateProcess` 返回 TRUE，但目标还有线程没退干净。
//   · "内部退出"里远程线程**起来了**（`CreateRemoteThread` 成功），
//     可入口点算错了，目标压根没走退出路径 —— 也只能从外部看出来。
//
// ⇒ 所以本测试**自己起受害进程**，并且用**目标自己产生的可观测副作用**
//   来判定，而不是用被测函数的返回值：
//
//     受害进程 = `cmd.exe` 跑一个批处理死循环，每圈往 `tick.txt` 追加一行。
//     判定依据 = `tick.txt` 的**文件大小**（cmd 每圈 open/write/close，
//                不跨圈缓冲，所以大小是即时的）。
//
//   A/B 对照（铁律 54：修前修后都 PASS = 没测）：
//     · 挂起前 —— 大小必须**在长**（这是"测量方法本身有效"的正向对照，
//                 没有它，后面"大小不变"可能是文件根本没写进去）；
//     · 挂起后 —— 大小必须**冻住**；
//     · 恢复后 —— 大小必须**重新在长**。
//
// ==================================================================
// 安全边界的负向对照
// ==================================================================
// `Perform` 会拒绝"关键系统进程"。这个拒绝如果只是"提前 return"，
// 从返回码看是对的，但万一 return 后面还有代码被误执行，就是一按蓝屏。
// ⇒ 所以除了断言 `RefusedCritical`，还要断言目标**还活着、还在 tick**
//   （= 真的什么都没做），这才是完整的负向对照。
//
// ★ 为了让"按名字拒绝"这条路径能测，测试会**把 cmd.exe 复制一份改名成
//   `csrss.exe`** 放到临时目录里跑。名字是唯一的判定输入，跑的是无害二进制，
//   所以既证明了"名字命中就拒"，又不会真的碰到系统关键进程。
//
// 链法（见 build_ut.sh 的 run_ark_actions_ut）：只链 `ark_actions.cpp` +
// kernel32 + psapi —— 它**故意零依赖**（不 include stdafx、不碰 Policy/共享内存）。
//
#include "ark_actions.h"

#include <psapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <wchar.h>

namespace
{
	int g_pass = 0;
	int g_fail = 0;

	void Check(bool ok, const char* what, const char* detail = "")
	{
		if (ok) {
			++g_pass;
			printf("PASS %s%s%s\n", what, detail[0] ? " -- " : "", detail);
		}
		else {
			++g_fail;
			printf("FAIL %s%s%s\n", what, detail[0] ? " -- " : "", detail);
		}
	}

	void CheckW(bool ok, const char* what, const WCHAR* detail)
	{
		char narrow[512] = {};
		if (detail) {
			WideCharToMultiByte(CP_ACP, 0, detail, -1, narrow, sizeof(narrow), nullptr, nullptr);
		}
		Check(ok, what, narrow);
	}

	// ==============================================================
	// 受害进程脚手架
	// ==============================================================

	// 每个小节一个**独立**临时目录：`%TEMP%\ark_ut_<pid>_<tag>`。
	//
	// ★ 为什么必须按小节分开，而不是整轮共用一个：
	//   判定依据是 `tick.txt` 的**大小**，而"载荷前提"断言写成 `size > 0`。
	//   共用一个目录时，上一节留下的 tick.txt 让 `size > 0` **恒真** ——
	//   前提断言退化成"永远通过"，于是受害进程**还没初始化完**就被拿去
	//   `EnumProcessModulesEx`，拿到 ERROR_PARTIAL_COPY(299)，
	//   而症状看起来像"产品代码读模块表读不到"（铁律 103 的同族坑）。
	//   独立目录让 `size > 0` 重新变成"这一节的受害进程真的跑起来了"。
	bool MakeTempDir(WCHAR* out, size_t cch, const WCHAR* tag) noexcept
	{
		WCHAR temp[MAX_PATH] = {};
		if (GetTempPathW(_countof(temp), temp) == 0) {
			return false;
		}
		swprintf_s(out, cch, L"%sark_ut_%lu_%s", temp, GetCurrentProcessId(), tag);
		if (!CreateDirectoryW(out, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
			return false;
		}
		// 目录可能是上一次运行残留的（同 pid 复用），先清掉 tick.txt，
		// 否则 `size > 0` 的前提断言又会被上一轮的残留喂成恒真。
		WCHAR tick[MAX_PATH] = {};
		swprintf_s(tick, L"%s\\tick.txt", out);
		DeleteFileW(tick);
		return true;
	}

	// 写一个纯 ASCII 文件。
	//
	// ★ 批处理必须 **CRLF + ASCII**：铁律 40 —— .bat 里出现 LF-only 或非 ASCII
	//   会让 cmd 的解析器失同步，症状是"一闪而过、什么都不做"。
	bool WriteAsciiFile(const WCHAR* path, const char* text) noexcept
	{
		HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return false;
		}
		const DWORD length = static_cast<DWORD>(strlen(text));
		DWORD written = 0;
		const BOOL ok = WriteFile(file, text, length, &written, nullptr);
		CloseHandle(file);
		return ok && written == length;
	}

	// tick.txt 的当前大小。
	//
	// ★ 必须声明 `FILE_SHARE_WRITE`（铁律 57）：受害进程正拿着这个文件在写，
	//   不声明共享写就会拿到 ERROR_SHARING_VIOLATION（err=32），
	//   于是"读不出大小"会被误当成"文件没长" ⇒ 假绿。
	unsigned long long TickSize(const WCHAR* tickPath) noexcept
	{
		HANDLE file = CreateFileW(tickPath, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return 0;
		}
		LARGE_INTEGER size = {};
		GetFileSizeEx(file, &size);
		CloseHandle(file);
		return static_cast<unsigned long long>(size.QuadPart);
	}

	// 进程还在不在（能被等 = 活着）。
	bool ProcessAlive(DWORD pid) noexcept
	{
		HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
			FALSE, pid);
		if (!process) {
			return false;
		}
		const DWORD wait = WaitForSingleObject(process, 0);
		CloseHandle(process);
		return wait == WAIT_TIMEOUT;
	}

	struct Victim
	{
		DWORD Pid = 0;
		HANDLE Process = nullptr;
		WCHAR Dir[MAX_PATH] = {};
		WCHAR TickPath[MAX_PATH] = {};
		WCHAR ExePath[MAX_PATH] = {};
	};

	// 起一个受害进程：
	//   dir\victim.bat  = `:loop / echo tick>>tick.txt / goto loop`
	//   dir\<exeName>   = 解释器（系统 cmd.exe，或复制改名后的副本）
	//
	// exeName 存在的唯一目的：让"按映像名拒绝"这条判据可以被真实触发。
	bool LaunchVictim(const WCHAR* dir, const WCHAR* exeName, Victim* victim) noexcept
	{
		*victim = Victim();
		wcsncpy_s(victim->Dir, dir, _TRUNCATE);

		WCHAR batPath[MAX_PATH] = {};
		swprintf_s(batPath, L"%s\\victim.bat", dir);
		wcsncpy_s(victim->TickPath, L"", _TRUNCATE);
		swprintf_s(victim->TickPath, L"%s\\tick.txt", dir);

		// `cd /d` 到自己的目录，循环里就能用相对路径，省掉一层引号地狱。
		char bat[1024] = {};
		sprintf_s(bat,
			"@echo off\r\n"
			"cd /d \"%ls\"\r\n"
			":loop\r\n"
			"echo tick>>tick.txt\r\n"
			"goto loop\r\n", dir);
		if (!WriteAsciiFile(batPath, bat)) {
			return false;
		}

		// 解释器路径：System32\<exeName> 或 dir\<exeName>。
		WCHAR exePath[MAX_PATH] = {};
		if (exeName[0] && _wcsicmp(exeName, L"cmd.exe") != 0) {
			swprintf_s(exePath, L"%s\\%s", dir, exeName);
		}
		else {
			WCHAR sysDir[MAX_PATH] = {};
			GetSystemDirectoryW(sysDir, _countof(sysDir));
			swprintf_s(exePath, L"%s\\cmd.exe", sysDir);
		}
		wcsncpy_s(victim->ExePath, exePath, _TRUNCATE);

		WCHAR cmdLine[MAX_PATH * 3] = {};
		swprintf_s(cmdLine, L"\"%s\" /c \"%s\"", exePath, batPath);

		STARTUPINFOW si = {};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(exePath, cmdLine, nullptr, nullptr, FALSE,
			CREATE_NO_WINDOW, nullptr, dir, &si, &pi)) {
			return false;
		}
		CloseHandle(pi.hThread);
		victim->Process = pi.hProcess;
		victim->Pid = pi.dwProcessId;
		return true;
	}

	// 等 tick.txt 长过 `from`，返回是否等到。
	//
	// ★ 这是**载荷前提断言**（铁律 103）：受害进程没跑起来 / 批处理没生效时，
	//   后面所有"大小不变"的断言都会因为"文件根本没写过"而假绿。
	bool WaitTickGrow(const WCHAR* tickPath, unsigned long long from,
		DWORD timeoutMs, unsigned long long* nowOut) noexcept
	{
		const ULONGLONG deadline = GetTickCount64() + timeoutMs;
		while (GetTickCount64() < deadline) {
			const unsigned long long size = TickSize(tickPath);
			if (size > from) {
				if (nowOut) {
					*nowOut = size;
				}
				return true;
			}
			Sleep(20);
		}
		if (nowOut) {
			*nowOut = TickSize(tickPath);
		}
		return false;
	}

	void StopVictim(Victim* victim) noexcept
	{
		if (victim->Process) {
			TerminateProcess(victim->Process, 1);
			WaitForSingleObject(victim->Process, 2000);
			CloseHandle(victim->Process);
			victim->Process = nullptr;
		}
	}

	// ==============================================================
	// A. 纯判据
	// ==============================================================

	void SectionA_PureCriteria() noexcept
	{
		printf("\n--- A. 纯判据 ---\n");

		// A1 关键名单里的每一条都要命中（带路径、带大小写混合）。
		struct { const WCHAR* path; bool expect; } cases[] = {
			{ L"csrss.exe", true },
			{ L"smss.exe", true },
			{ L"wininit.exe", true },
			{ L"winlogon.exe", true },
			{ L"services.exe", true },
			{ L"lsass.exe", true },
			{ L"lsaiso.exe", true },
			{ L"fontdrvhost.exe", true },
			{ L"dwm.exe", true },
			{ L"System", true },
			{ L"Idle", true },
			{ L"Registry", true },
			{ L"Memory Compression", true },
			{ L"Secure System", true },
			// 带路径 + 大小写混合（FileNamePart + 不区分大小写）
			{ L"C:\\Windows\\System32\\CSRSS.EXE", true },
			{ L"\\\\?\\C:\\Windows\\System32\\lsass.exe", true },

			// ★ 普通系统进程**必须不命中**：它们被杀不蓝屏、被挂起不卡死，
			//   ARK 的价值就在于能动它们。把它们一起拒掉 = 功能废掉。
			{ L"svchost.exe", false },
			{ L"explorer.exe", false },
			{ L"SearchHost.exe", false },
			{ L"StartMenuExperienceHost.exe", false },
			{ L"taskhostw.exe", false },
			{ L"sihost.exe", false },
			{ L"RuntimeBroker.exe", false },
			{ L"audiodg.exe", false },
			{ L"conhost.exe", false },
			{ L"notepad.exe", false },
			{ L"chrome.exe", false },
		};

		int mismatched = 0;
		for (const auto& c : cases) {
			if (ArkActions::IsCriticalProcessName(c.path) != c.expect) {
				++mismatched;
				printf("  mismatch: %ls expect=%d\n", c.path, c.expect ? 1 : 0);
			}
		}
		char detail[64] = {};
		sprintf_s(detail, "%d cases", static_cast<int>(_countof(cases)));
		Check(mismatched == 0, "A1 IsCriticalProcessName 逐条命中", detail);

		// A2 空/nullptr 不能崩，且一律 false。
		Check(!ArkActions::IsCriticalProcessName(nullptr), "A2a nullptr 安全且为 false");
		Check(!ArkActions::IsCriticalProcessName(L""), "A2b 空串为 false");

		// A3 IsSystemImagePath：%SystemRoot% 之下才算系统进程。
		WCHAR root[MAX_PATH] = {};
		GetWindowsDirectoryW(root, _countof(root));   // 形如 C:\Windows，不带尾反斜杠

		WCHAR inSystem[MAX_PATH] = {};
		swprintf_s(inSystem, L"%s\\System32\\svchost.exe", root);
		Check(ArkActions::IsSystemImagePath(inSystem, root),
			"A3a %SystemRoot%\\System32 之下 = 系统进程");

		WCHAR inRoot[MAX_PATH] = {};
		swprintf_s(inRoot, L"%s\\explorer.exe", root);
		Check(ArkActions::IsSystemImagePath(inRoot, root),
			"A3b %SystemRoot% 根目录之下 = 系统进程（explorer 就在这）");

		// ★ 前缀边界：`C:\WindowsApps` 与 `C:\Windows` 共享前缀，
		//   不加那个反斜杠就会被误判成系统进程。
		WCHAR sibling[MAX_PATH] = {};
		swprintf_s(sibling, L"%sApps\\fake.exe", root);
		Check(!ArkActions::IsSystemImagePath(sibling, root),
			"A3c C:\\WindowsApps 不是系统进程（前缀边界）");

		Check(!ArkActions::IsSystemImagePath(L"C:\\Tools\\evil.exe", root),
			"A3d 非系统目录 = false");
		Check(!ArkActions::IsSystemImagePath(nullptr, root), "A3e nullptr 安全");
		Check(!ArkActions::IsSystemImagePath(inSystem, nullptr), "A3f systemRoot 为 nullptr 安全");
		Check(!ArkActions::IsSystemImagePath(inSystem, L""), "A3g systemRoot 为空安全");

		// A4 文本函数：都不返回 nullptr，且 ActionText 四个动作互不相同。
		Check(ArkActions::ResultText(ArkActions::Result::Ok) != nullptr, "A4a ResultText 非空");
		Check(ArkActions::ResultCode(ArkActions::Result::Ok) != nullptr, "A4b ResultCode 非空");
		Check(ArkActions::ActionText(ArkActions::Action::Suspend) != nullptr, "A4c ActionText 非空");

		const char* codes[] = {
			ArkActions::ResultCode(ArkActions::Result::Ok),
			ArkActions::ResultCode(ArkActions::Result::RefusedSelf),
			ArkActions::ResultCode(ArkActions::Result::RefusedCritical),
			ArkActions::ResultCode(ArkActions::Result::ProcessGone),
			ArkActions::ResultCode(ArkActions::Result::AccessDenied),
			ArkActions::ResultCode(ArkActions::Result::UnsupportedWow64),
			ArkActions::ResultCode(ArkActions::Result::DllNotLoaded),
			ArkActions::ResultCode(ArkActions::Result::DllMismatch),
			ArkActions::ResultCode(ArkActions::Result::ExportMissing),
			ArkActions::ResultCode(ArkActions::Result::RemoteThreadFailed),
			ArkActions::ResultCode(ArkActions::Result::TimedOut),
		};
		bool distinct = true;
		for (size_t i = 0; i < _countof(codes) && distinct; i++) {
			for (size_t j = i + 1; j < _countof(codes); j++) {
				if (strcmp(codes[i], codes[j]) == 0) {
					distinct = false;
					break;
				}
			}
		}
		Check(distinct, "A4d 每个失败码互不相同（日志能区分）");
	}

	// ==============================================================
	// B. 拒绝路径（真实进程 + 负向对照）
	// ==============================================================

	void SectionB_Refusals() noexcept
	{
		printf("\n--- B. 拒绝路径 ---\n");

		const DWORD self = GetCurrentProcessId();

		// B1 动自己 —— 必须拒，而且引擎必须还活着（废话，但这是对照）。
		ArkActions::Outcome selfKill =
			ArkActions::Perform(self, ArkActions::Action::ForceKill, self, 0);
		Check(selfKill.Code == ArkActions::Result::RefusedSelf,
			"B1a 对自己 ForceKill = RefusedSelf",
			ArkActions::ResultCode(selfKill.Code));
		Check(ProcessAlive(self), "B1b 负向对照：本进程还活着");

		ArkActions::Outcome selfSuspend =
			ArkActions::Perform(self, ArkActions::Action::Suspend, self, 0);
		Check(selfSuspend.Code == ArkActions::Result::RefusedSelf,
			"B1c 对自己 Suspend = RefusedSelf");

		// B2 pid 4 = System 伪进程，永远存在，且**在 OpenProcess 之前**就被拒。
		ArkActions::Outcome sys =
			ArkActions::Perform(4, ArkActions::Action::ForceKill, self, 0);
		Check(sys.Code == ArkActions::Result::RefusedCritical,
			"B2a pid 4 (System) = RefusedCritical",
			ArkActions::ResultCode(sys.Code));

		// B3 按**映像名**拒绝：把 cmd.exe 复制一份改名成 csrss.exe。
		//
		//    这是唯一能真实触发"名字命中就拒"这条判据的办法 ——
		//    光断言 IsCriticalProcessName("csrss.exe") 只证明了纯判据，
		//    证明不了 Perform 真的接了它。
		WCHAR dir[MAX_PATH] = {};
		if (!MakeTempDir(dir, _countof(dir), L"refuse")) {
			Check(false, "B3 临时目录创建失败（后续用例跳过）");
			return;
		}

		WCHAR sysDir[MAX_PATH] = {};
		GetSystemDirectoryW(sysDir, _countof(sysDir));
		WCHAR realCmd[MAX_PATH] = {};
		swprintf_s(realCmd, L"%s\\cmd.exe", sysDir);
		WCHAR fakeExe[MAX_PATH] = {};
		swprintf_s(fakeExe, L"%s\\csrss.exe", dir);
		if (!CopyFileW(realCmd, fakeExe, FALSE)) {
			Check(false, "B3 复制 cmd.exe -> csrss.exe 失败（后续用例跳过）");
			return;
		}

		Victim fake = {};
		if (!LaunchVictim(dir, L"csrss.exe", &fake)) {
			Check(false, "B3 启动 csrss.exe 副本失败");
			return;
		}

		unsigned long long ticks = 0;
		const bool ticking = WaitTickGrow(fake.TickPath, 0, 4000, &ticks);
		Check(ticking, "B3a 载荷前提：csrss.exe 副本真的在 tick（否则后续假绿）");

		ArkActions::Outcome fakeSuspend =
			ArkActions::Perform(fake.Pid, ArkActions::Action::Suspend, self, 0);
		Check(fakeSuspend.Code == ArkActions::Result::RefusedCritical,
			"B3b 名字命中关键名单 = RefusedCritical",
			ArkActions::ResultCode(fakeSuspend.Code));

		ArkActions::Outcome fakeKill =
			ArkActions::Perform(fake.Pid, ArkActions::Action::ForceKill, self, 0);
		Check(fakeKill.Code == ArkActions::Result::RefusedCritical,
			"B3c 强制结束同样被拒");

		// ★ 负向对照：拒绝了就必须**真的什么都没做** —— 还活着、还在 tick。
		Check(ProcessAlive(fake.Pid), "B3d 负向对照：被拒的目标还活着");
		unsigned long long afterRefusal = 0;
		const bool stillTicking = WaitTickGrow(fake.TickPath, ticks, 2000, &afterRefusal);
		Check(stillTicking, "B3e 负向对照：被拒的目标没有被挂起（还在 tick）");

		StopVictim(&fake);
	}

	// ==============================================================
	// C. 挂起 / 恢复 A/B
	// ==============================================================

	void SectionC_SuspendResume() noexcept
	{
		printf("\n--- C. 挂起 / 恢复 ---\n");

		const DWORD self = GetCurrentProcessId();

		WCHAR dir[MAX_PATH] = {};
		if (!MakeTempDir(dir, _countof(dir), L"suspend")) {
			Check(false, "C 临时目录创建失败");
			return;
		}

		Victim victim = {};
		if (!LaunchVictim(dir, L"cmd.exe", &victim)) {
			Check(false, "C 启动受害进程失败");
			return;
		}

		// C1 正向对照：**先证明"tick 大小在长"这个测量方法本身有效**。
		//    没有这一步，"挂起后大小不变"完全可能是"文件压根没在写"。
		unsigned long long t0 = 0;
		const bool grew1 = WaitTickGrow(victim.TickPath, 0, 5000, &t0);
		Check(grew1, "C1 正向对照：挂起前 tick.txt 在增长（测量方法有效）");

		unsigned long long t1 = t0;
		const bool grew2 = WaitTickGrow(victim.TickPath, t0, 3000, &t1);
		Check(grew2, "C1b 正向对照：再等一段仍在增长");

		// C2 挂起。
		ArkActions::Outcome suspend =
			ArkActions::Perform(victim.Pid, ArkActions::Action::Suspend, self, 0);
		Check(suspend.Code == ArkActions::Result::Ok, "C2a Suspend = Ok",
			ArkActions::ResultCode(suspend.Code));

		// 让在途的写落盘（挂起返回后可能还有一次刚提交的写）。
		Sleep(250);
		const unsigned long long frozen0 = TickSize(victim.TickPath);
		Sleep(900);
		const unsigned long long frozen1 = TickSize(victim.TickPath);
		char detail[128] = {};
		sprintf_s(detail, "frozen %llu -> %llu", frozen0, frozen1);
		Check(frozen1 == frozen0, "C2b 挂起后 tick.txt 冻住（目标真的停了）", detail);
		Check(frozen0 > 0, "C2c 前提：文件非空（否则'冻住'无意义）");

		// C3 恢复。
		ArkActions::Outcome resume =
			ArkActions::Perform(victim.Pid, ArkActions::Action::Resume, self, 0);
		Check(resume.Code == ArkActions::Result::Ok, "C3a Resume = Ok",
			ArkActions::ResultCode(resume.Code));

		unsigned long long resumed = 0;
		const bool grew3 = WaitTickGrow(victim.TickPath, frozen1, 3000, &resumed);
		Check(grew3, "C3b 恢复后 tick.txt 重新增长（目标真的醒了）");

		// C4 挂起 → 恢复 之间目标必须**始终存活**（挂起不是结束）。
		Check(ProcessAlive(victim.Pid), "C4 挂起/恢复全程目标存活");

		StopVictim(&victim);
	}

	// ==============================================================
	// D. 内部退出 —— 失败必须分型
	// ==============================================================

	void SectionD_InternalExit() noexcept
	{
		printf("\n--- D. 内部退出（分型）---\n");

		const DWORD self = GetCurrentProcessId();

		WCHAR dir[MAX_PATH] = {};
		if (!MakeTempDir(dir, _countof(dir), L"exit")) {
			Check(false, "D 临时目录创建失败");
			return;
		}

		Victim victim = {};
		if (!LaunchVictim(dir, L"cmd.exe", &victim)) {
			Check(false, "D 启动受害进程失败");
			return;
		}

		unsigned long long t0 = 0;
		const bool alive = WaitTickGrow(victim.TickPath, 0, 5000, &t0);
		Check(alive, "D0 载荷前提：受害进程在跑");

		// D1 目标**没被注入**（单测环境里没有引擎）⇒ 必须是 DllNotLoaded，
		//    而不是笼统的 Failed。这是"下一步该干什么"的依据：
		//    DllNotLoaded ⇒ 换"强制结束"；DllMismatch ⇒ 重新部署发布包。
		ArkActions::Outcome exitNotInjected =
			ArkActions::Perform(victim.Pid, ArkActions::Action::InternalExit, self, 0);
		Check(exitNotInjected.Code == ArkActions::Result::DllNotLoaded,
			"D1 未注入的目标 = DllNotLoaded",
			ArkActions::ResultCode(exitNotInjected.Code));
		Check(!exitNotInjected.DllPresent, "D1b DllPresent = false");
		Check(exitNotInjected.Win32Error == ERROR_MOD_NOT_FOUND,
			"D1c Win32Error = ERROR_MOD_NOT_FOUND");

		// D2 负向对照：分型失败之后目标必须**毫发无伤**。
		Check(ProcessAlive(victim.Pid), "D2 负向对照：内部退出失败后目标还活着");
		unsigned long long t1 = 0;
		Check(WaitTickGrow(victim.TickPath, t0, 2000, &t1),
			"D2b 负向对照：目标仍在 tick（没被误伤）");

		StopVictim(&victim);
	}

	// ==============================================================
	// E. 强制结束
	// ==============================================================

	void SectionE_ForceKill() noexcept
	{
		printf("\n--- E. 强制结束 ---\n");

		const DWORD self = GetCurrentProcessId();

		WCHAR dir[MAX_PATH] = {};
		if (!MakeTempDir(dir, _countof(dir), L"kill")) {
			Check(false, "E 临时目录创建失败");
			return;
		}

		Victim victim = {};
		if (!LaunchVictim(dir, L"cmd.exe", &victim)) {
			Check(false, "E 启动受害进程失败");
			return;
		}

		unsigned long long t0 = 0;
		Check(WaitTickGrow(victim.TickPath, 0, 5000, &t0), "E0 载荷前提：受害进程在跑");
		Check(ProcessAlive(victim.Pid), "E0b 前提：目标当前存活");

		const DWORD pid = victim.Pid;

		ArkActions::Outcome kill =
			ArkActions::Perform(pid, ArkActions::Action::ForceKill, self, 0);
		Check(kill.Code == ArkActions::Result::Ok, "E1 ForceKill = Ok",
			ArkActions::ResultCode(kill.Code));
		Check(!ProcessAlive(pid), "E2 目标真的没了（不是只看返回码）");

		// E3 对已经不存在的 pid 再下一次 ⇒ ProcessGone（分型，不是 Failed）。
		ArkActions::Outcome again =
			ArkActions::Perform(pid, ArkActions::Action::ForceKill, self, 0);
		Check(again.Code == ArkActions::Result::ProcessGone,
			"E3 对已消失的 pid = ProcessGone",
			ArkActions::ResultCode(again.Code));

		// E4 挂起一个不存在的 pid 也必须分型。
		ArkActions::Outcome suspendGone =
			ArkActions::Perform(pid, ArkActions::Action::Suspend, self, 0);
		Check(suspendGone.Code == ArkActions::Result::ProcessGone,
			"E4 挂起已消失的 pid = ProcessGone");

		StopVictim(&victim);
	}

	// ==============================================================
	// F. QueryRemoteDllBase 的负向对照
	// ==============================================================

	void SectionF_RemoteDllQuery() noexcept
	{
		printf("\n--- F. QueryRemoteDllBase ---\n");

		// F1 nullptr 进程句柄。
		ULONG_PTR base = 0;
		bool same = false;
		DWORD err = 0;
		Check(!ArkActions::QueryRemoteDllBase(nullptr, 0, &base, &same, &err),
			"F1 nullptr 进程 = false");
		Check(base == 0 && !same, "F1b 输出被清零");

		WCHAR dir[MAX_PATH] = {};
		if (!MakeTempDir(dir, _countof(dir), L"remote")) {
			Check(false, "F 临时目录创建失败");
			return;
		}

		Victim victim = {};
		if (!LaunchVictim(dir, L"cmd.exe", &victim)) {
			Check(false, "F 启动受害进程失败");
			return;
		}

		unsigned long long t0 = 0;
		Check(WaitTickGrow(victim.TickPath, 0, 5000, &t0), "F0 载荷前提：受害进程在跑");

		// F2 没被注入的进程里找不到我们的 DLL。
		//
		//    ★ 这里**只有负向对照**是诚实的：正向（目标里真的有我们的 DLL，
		//      且校验通过）必须在**真机跑着引擎**的场景里验，单测里造不出来 ——
		//      直接 LoadLibrary 我们那份 DLL 会把它自己的钩子装进测试进程，
		//      测出来的东西就不是被测对象了。
		HANDLE process = OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, victim.Pid);
		Check(process != nullptr, "F2 前提：能打开受害进程");
		if (process) {
			base = 0xdeadbeef;
			same = true;
			err = 0;
			const bool found = ArkActions::QueryRemoteDllBase(process, 0, &base, &same, &err);
			Check(!found, "F2a 未注入进程里找不到 DLL = false");
			Check(base == 0, "F2b remoteBase 被清零");
			Check(!same, "F2c sameBuild = false（fail-closed）");
			Check(err == ERROR_MOD_NOT_FOUND, "F2d err = ERROR_MOD_NOT_FOUND",
				[&] { static char b[64]; sprintf_s(b, "err=%lu", err); return b; }());
			CloseHandle(process);
		}

		StopVictim(&victim);
	}

	// ==============================================================
	// G. ElapsedMs 只做展示，不参与判据（铁律 58）
	// ==============================================================

	void SectionG_Elapsed() noexcept
	{
		printf("\n--- G. 耗时字段 ---\n");

		const DWORD self = GetCurrentProcessId();
		ArkActions::Outcome refused =
			ArkActions::Perform(self, ArkActions::Action::ForceKill, self, 0);
		// 只断言"字段存在且合理"，**不断言具体数值** ——
		// 时间判据一旦进断言就会变成 flaky（铁律 58）。
		Check(refused.ElapsedMs < 5000, "G1 ElapsedMs 被填且量级合理");
	}
}

int main()
{
	// 窄 printf 里的 `%ls` 需要 locale 才会正确转换宽字符（铁律 55）：
	// 不设的话遇到非 ASCII 会**静默截断**（还可能吞掉后面的换行），
	// 于是"路径打出来是空的"会被误读成"路径本来就是空的"。
	setlocale(LC_ALL, "");

	printf("=== ark_actions_ut (v62) ===\n");

	SectionA_PureCriteria();
	SectionB_Refusals();
	SectionC_SuspendResume();
	SectionD_InternalExit();
	SectionE_ForceKill();
	SectionF_RemoteDllQuery();
	SectionG_Elapsed();

	printf("\n=== ark_actions_ut: %d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
