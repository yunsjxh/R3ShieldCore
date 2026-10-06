//
// 探针：KSword 的「真·超级置顶」配方能不能在这台机器上复现？
//
// 背景 —— 上一个探针（tools/uiaccess_probe.cpp）实测的结论是：
//   把 UIAccess 标在**自己（管理员）的令牌**上、再 CreateProcessAsUser 拉起子进程，
//   子进程出生 TokenUIAccess=1，但 user32!SetWindowBand 依旧 FALSE err=5/87。
//
// KSword（D:\KSword-main\KswordUacDesk\UacDesk.cpp:672 duplicateSystemTokenForSession）
// 的配方有两处**不同**，上一次没测到：
//   (1) 主令牌不是复制自己的，而是复制 **winlogon.exe 的 LocalSystem 令牌**；
//   (2) 用 CreateProcessWithTokenW + startup.lpDesktop = "winsta0\\Winlogon"
//       —— 子进程直接生在 **UAC 安全桌面** 上。
//
// 本探针就为了把这两个变量分开测：
//   P0  SYSTEM 令牌 + UIAccess=0 + default 桌面   （对照：光有 SYSTEM 够不够？）
//   P1  SYSTEM 令牌 + UIAccess=1 + default 桌面   （令牌来源是关键变量？）
//   P2  SYSTEM 令牌 + UIAccess=1 + Winlogon 桌面  （KSword 原配方）
// 每个阶段的子进程都自报：SYSTEM? UIAccess? 窗口站/桌面名? 然后跑 SetWindowBand 判定。
//
// 判定方式与上个探针一致：故意最后抬 B —— B 仍在 A 之上 = band 没生效。
//
// 用法（非提权直接跑，它会自己弹 UAC）：
//     tools\uiaaccess_system_probe.exe
// 结果：tools\uiaaccess_system_probe.out.{parent,p0,p1,p2}
//

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <string>
#include <vector>

static FILE* g_log = nullptr;
static const wchar_t* kWndClass = L"UiAccessSysProbeWnd";

static void L(const char* fmt, ...)
{
	char buffer[2048];
	va_list ap;
	va_start(ap, fmt);
	_vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, ap);
	va_end(ap);

	fputs(buffer, stdout);
	fflush(stdout);

	if (g_log) {
		// 别把 CP936 窄串塞进 "ccs=UTF-8" 流 —— CRT 转换失败会触发 invalid
		// parameter handler 直接杀进程。自己走 CP_ACP -> UTF-16 -> UTF-8。
		wchar_t wide[2048] = {};
		int wn = MultiByteToWideChar(CP_ACP, 0, buffer, -1, wide, _countof(wide));
		if (wn > 0) {
			char utf8[4096] = {};
			int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, sizeof(utf8), nullptr, nullptr);
			if (n > 1) fwrite(utf8, 1, static_cast<size_t>(n - 1), g_log);
		}
		fflush(g_log);
	}
}

static bool IsElevated()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
	TOKEN_ELEVATION e = {};
	DWORD ret = 0;
	BOOL ok = GetTokenInformation(token, TokenElevation, &e, sizeof(e), &ret);
	CloseHandle(token);
	return ok && e.TokenIsElevated != 0;
}

static DWORD TokenUIAccessFlag(HANDLE token)
{
	DWORD v = 0, ret = 0;
	if (!token) return 0;
	GetTokenInformation(token, TokenUIAccess, &v, sizeof(v), &ret);
	return v;
}

static DWORD SelfUIAccessFlag()
{
	HANDLE t = nullptr;
	DWORD v = 0;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) { v = TokenUIAccessFlag(t); CloseHandle(t); }
	return v;
}

static bool EnablePrivilege(HANDLE token, LPCWSTR name, DWORD* err)
{
	if (err) *err = ERROR_SUCCESS;
	LUID luid = {};
	if (!LookupPrivilegeValueW(nullptr, name, &luid)) { if (err) *err = GetLastError(); return false; }
	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	SetLastError(ERROR_SUCCESS);
	BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
	DWORD e = GetLastError();
	if (err) *err = e;
	return ok && e == ERROR_SUCCESS;
}

static bool TokenIsLocalSystem(HANDLE token)
{
	DWORD need = 0;
	GetTokenInformation(token, TokenUser, nullptr, 0, &need);
	if (need == 0) return false;
	std::vector<BYTE> buf(need);
	if (!GetTokenInformation(token, TokenUser, buf.data(), need, &need)) return false;
	BYTE sysSid[SECURITY_MAX_SID_SIZE] = {};
	DWORD sidSize = sizeof(sysSid);
	if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sysSid, &sidSize)) return false;
	const TOKEN_USER* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
	return EqualSid(tu->User.Sid, sysSid) != FALSE;
}

static DWORD FindSystemProcess(DWORD sessionId, wchar_t* nameOut, size_t nameChars)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) return 0;
	DWORD best = 0;
	int bestRank = 0;
	PROCESSENTRY32W pe = { sizeof(pe) };
	if (Process32FirstW(snap, &pe)) {
		do {
			DWORD sid = 0;
			ProcessIdToSessionId(pe.th32ProcessID, &sid);
			int rank = 0;
			if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) rank = (sid == sessionId) ? 40 : 30;
			else if (_wcsicmp(pe.szExeFile, L"services.exe") == 0) rank = (sid == sessionId) ? 20 : 10;
			if (rank > bestRank) {
				bestRank = rank;
				best = pe.th32ProcessID;
				if (nameOut) _snwprintf_s(nameOut, nameChars, _TRUNCATE, L"%s", pe.szExeFile);
			}
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
	return best;
}

static const wchar_t* CurrentDesktopName()
{
	static wchar_t name[128] = {};
	HDESK desk = GetThreadDesktop(GetCurrentThreadId());
	if (!desk) return L"(GetThreadDesktop 失败)";
	DWORD len = 0;
	GetUserObjectInformationW(desk, UOI_NAME, nullptr, 0, &len);
	if (len == 0 || len > sizeof(name)) return L"(UOI_NAME 查询失败)";
	if (!GetUserObjectInformationW(desk, UOI_NAME, name, sizeof(name), &len)) return L"(UOI_NAME 读取失败)";
	return name;
}

static const wchar_t* CurrentWindowStationName()
{
	static wchar_t name[128] = {};
	HWINSTA ws = GetProcessWindowStation();
	if (!ws) return L"(GetProcessWindowStation 失败)";
	DWORD len = 0;
	GetUserObjectInformationW(ws, UOI_NAME, nullptr, 0, &len);
	if (len == 0 || len > sizeof(name)) return L"(UOI_NAME 查询失败)";
	if (!GetUserObjectInformationW(ws, UOI_NAME, name, sizeof(name), &len)) return L"(UOI_NAME 读取失败)";
	return name;
}

// 沿 z 序从 hwnd 往上走，先遇到 target => target 在 hwnd 之上。
static bool TargetIsAbove(HWND hwnd, HWND target)
{
	for (HWND w = GetWindow(hwnd, GW_HWNDPREV); w; w = GetWindow(w, GW_HWNDPREV)) {
		if (w == target) return true;
		if (w == GetDesktopWindow()) break;
	}
	return false;
}

static void Pump()
{
	for (int i = 0; i < 3; ++i) {
		MSG msg;
		while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
		Sleep(40);
	}
}

using SetWindowBandFn = BOOL(WINAPI*)(HWND, HWND, DWORD);
static SetWindowBandFn g_setWindowBand = nullptr;

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) { return DefWindowProcW(h, m, w, l); }

static void RunWindowBandTest(const char* phase)
{
	L("\n---- %s ----\n", phase);

	WNDCLASSEXW wc = { sizeof(wc) };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = GetModuleHandleW(nullptr);
	wc.lpszClassName = kWndClass;
	if (!RegisterClassExW(&wc)) {
		L("  [失败] RegisterClassExW err=%lu\n", (unsigned long)GetLastError());
		return;
	}
	HWND a = CreateWindowExW(WS_EX_TOOLWINDOW, kWndClass, L"A", WS_POPUP, 0, 0, 120, 30,
		nullptr, nullptr, wc.hInstance, nullptr);
	HWND b = CreateWindowExW(WS_EX_TOOLWINDOW, kWndClass, L"B", WS_POPUP, 140, 0, 120, 30,
		nullptr, nullptr, wc.hInstance, nullptr);
	if (!a || !b) {
		L("  [失败] CreateWindowExW err=%lu (a=%p b=%p)\n",
			(unsigned long)GetLastError(), (void*)a, (void*)b);
		if (a) DestroyWindow(a);
		if (b) DestroyWindow(b);
		return;
	}
	ShowWindow(a, SW_SHOWNOACTIVATE);
	ShowWindow(b, SW_SHOWNOACTIVATE);
	Pump();

	SetWindowPos(a, HWND_TOPMOST, 0, 0, 120, 30, SWP_NOACTIVATE);
	SetWindowPos(b, HWND_TOPMOST, 140, 0, 120, 30, SWP_NOACTIVATE);
	Pump();
	L("基线（不调 SetWindowBand）：抬B后B仍在A之上=%s\n", TargetIsAbove(a, b) ? "是" : "否");

	auto measure = [&](const char* tag, HWND insertAfter, DWORD band) {
		SetLastError(0);
		BOOL ret = g_setWindowBand ? g_setWindowBand(a, insertAfter, band) : FALSE;
		DWORD e = GetLastError();
		Pump();
		SetWindowPos(b, HWND_TOPMOST, 140, 0, 120, 30, SWP_NOACTIVATE);
		Pump();
		bool bAbove = TargetIsAbove(a, b);
		L("%-34s ret=%-5s err=%-4lu  抬B后B仍在A之上=%s  -> %s\n",
			tag, ret ? "TRUE" : "FALSE", (unsigned long)e, bAbove ? "是" : "否",
			bAbove ? "band 未生效" : "**band 生效**");
	};

	measure("band=2 (HWND_TOP)", HWND_TOP, 2);
	measure("band=2 (HWND_TOPMOST)", HWND_TOPMOST, 2);
	measure("band=1 (HWND_TOP)", HWND_TOP, 1);

	DestroyWindow(a);
	DestroyWindow(b);
	UnregisterClassW(kWndClass, wc.hInstance);
}

// ---------------------------------------------------------------------------

// KSword 配方：复制 winlogon 的 LocalSystem 令牌 -> 设 TokenUIAccess -> 交给
// CreateProcessWithTokenW。成功时返回 primary token（调用方负责 CloseHandle）。
static HANDLE BuildSystemPrimaryToken(bool setUiAccess, DWORD* outSourcePid, DWORD* outErr)
{
	HANDLE currentToken = nullptr, sourceProcess = nullptr, sourceToken = nullptr;
	HANDLE impToken = nullptr, primaryToken = nullptr;
	bool impersonating = false;
	DWORD err = ERROR_SUCCESS;

	auto fail = [&](const char* what, DWORD e) {
		L("  [失败] %s err=%lu\n", what, (unsigned long)e);
		if (outErr) *outErr = e;
	};

	do {
		if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ASSIGN_PRIMARY,
			&currentToken)) { fail("OpenProcessToken(self)", GetLastError()); break; }

		// 与 KSword 一致：SeImpersonate 是 CreateProcessWithTokenW 的前置条件。
		const LPCWSTR privs[] = { SE_DEBUG_NAME, SE_ASSIGNPRIMARYTOKEN_NAME,
			SE_INCREASE_QUOTA_NAME, SE_TCB_NAME, SE_IMPERSONATE_NAME };
		for (LPCWSTR p : privs) {
			DWORD pe = 0;
			bool ok = EnablePrivilege(currentToken, p, &pe);
			L("         %-28ls -> %s%s\n", p, ok ? "已启用" : "失败",
				ok ? "" : " (err 见后)");
			if (!ok) L("            err=%lu\n", (unsigned long)pe);
		}

		DWORD sessionId = 0;
		ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
		wchar_t srcName[64] = {};
		DWORD sourcePid = FindSystemProcess(sessionId, srcName, _countof(srcName));
		if (sourcePid == 0) { fail("找不到 SYSTEM 令牌源", ERROR_NOT_FOUND); break; }
		if (outSourcePid) *outSourcePid = sourcePid;
		L("         令牌源：%ls pid=%lu (session=%lu)\n", srcName, (unsigned long)sourcePid, (unsigned long)sessionId);

		sourceProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
		if (!sourceProcess || !OpenProcessToken(sourceProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &sourceToken)) {
			fail("OpenProcessToken(SYSTEM 源)", GetLastError()); break;
		}
		if (!TokenIsLocalSystem(sourceToken)) { fail("该令牌不是 LocalSystem", ERROR_INVALID_OWNER); break; }

		SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
		if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &sa, SecurityImpersonation,
			TokenImpersonation, &impToken)) { fail("DuplicateTokenEx(impersonation)", GetLastError()); break; }
		if (!ImpersonateLoggedOnUser(impToken)) { fail("ImpersonateLoggedOnUser(SYSTEM)", GetLastError()); break; }
		impersonating = true;
		EnablePrivilege(impToken, SE_ASSIGNPRIMARYTOKEN_NAME, nullptr);
		EnablePrivilege(impToken, SE_INCREASE_QUOTA_NAME, nullptr);
		EnablePrivilege(impToken, SE_TCB_NAME, nullptr);

		// ★ 关键：primary token 来自 **SYSTEM 源**，不是自己的令牌。
		if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &sa, SecurityImpersonation,
			TokenPrimary, &primaryToken)) { fail("DuplicateTokenEx(primary)", GetLastError()); break; }
		EnablePrivilege(primaryToken, SE_ASSIGNPRIMARYTOKEN_NAME, nullptr);
		EnablePrivilege(primaryToken, SE_INCREASE_QUOTA_NAME, nullptr);
		EnablePrivilege(primaryToken, SE_TCB_NAME, nullptr);

		DWORD uiAccess = setUiAccess ? 1u : 0u;
		SetLastError(ERROR_SUCCESS);
		BOOL setOk = SetTokenInformation(primaryToken, TokenUIAccess, &uiAccess, sizeof(uiAccess));
		DWORD setErr = GetLastError();
		L("         SetTokenInformation(primary, TokenUIAccess, %lu) -> %s err=%lu\n",
			(unsigned long)uiAccess, setOk ? "TRUE" : "FALSE", (unsigned long)setErr);
		if (!setOk) { fail("SetTokenInformation(TokenUIAccess)", setErr); break; }
		L("         复查 primary 的 TokenUIAccess=%lu\n", (unsigned long)TokenUIAccessFlag(primaryToken));

		err = ERROR_SUCCESS;
	} while (false);

	if (impersonating) RevertToSelf();
	if (impToken) CloseHandle(impToken);
	if (sourceToken) CloseHandle(sourceToken);
	if (sourceProcess) CloseHandle(sourceProcess);
	if (currentToken) CloseHandle(currentToken);

	if (err != ERROR_SUCCESS && primaryToken) { CloseHandle(primaryToken); primaryToken = nullptr; }
	return primaryToken;
}

static bool SpawnChildWithToken(HANDLE primaryToken, const wchar_t* desktop,
	const wchar_t* outPath, const char* label)
{
	wchar_t self[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, self, MAX_PATH);
	wchar_t cmd[MAX_PATH * 3] = {};
	_snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
		L"\"%s\" --child --out \"%s\"", self, outPath);

	STARTUPINFOW si = { sizeof(si) };
	std::wstring desk = desktop;
	si.lpDesktop = desk.data();

	PROCESS_INFORMATION pi = {};
	SetLastError(ERROR_SUCCESS);
	BOOL ok = CreateProcessWithTokenW(primaryToken, LOGON_NETCREDENTIALS_ONLY, self, cmd,
		CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi);
	DWORD e = GetLastError();
	if (!ok) {
		L("  [失败] %s CreateProcessWithTokenW(desktop=%ls) err=%lu\n",
			label, desktop, (unsigned long)e);
		return false;
	}

	HANDLE childToken = nullptr;
	DWORD childFlag = 0;
	if (OpenProcessToken(pi.hProcess, TOKEN_QUERY, &childToken)) {
		childFlag = TokenUIAccessFlag(childToken);
		CloseHandle(childToken);
	}
	L("  [ok]   %s 子进程已拉起 pid=%lu  desktop=%ls  其 TokenUIAccess=%lu\n",
		label, (unsigned long)pi.dwProcessId, desktop, (unsigned long)childFlag);

	DWORD wait = WaitForSingleObject(pi.hProcess, 60000);
	DWORD code = 0;
	GetExitCodeProcess(pi.hProcess, &code);
	L("         子进程结束 wait=%lu exit=0x%08lX\n", (unsigned long)wait, (unsigned long)code);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return true;
}

int wmain(int argc, wchar_t** argv)
{
	bool elevatedRun = false;
	bool childMode = false;
	wchar_t outBase[MAX_PATH] = {};
	{
		wchar_t self[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, self, MAX_PATH);
		wchar_t* slash = wcsrchr(self, L'\\');
		if (slash) *(slash + 1) = 0;
		_snwprintf_s(outBase, MAX_PATH, _TRUNCATE, L"%suiaaccess_system_probe.out", self);
	}
	for (int i = 1; i < argc; ++i) {
		if (_wcsicmp(argv[i], L"--elevated") == 0) elevatedRun = true;
		else if (_wcsicmp(argv[i], L"--child") == 0) childMode = true;
		else if (_wcsicmp(argv[i], L"--out") == 0 && i + 1 < argc) {
			wcsncpy_s(outBase, MAX_PATH, argv[++i], _TRUNCATE);
		}
	}

	if (!elevatedRun && !childMode && !IsElevated()) {
		wprintf(L"当前非提权 —— 自动以管理员身份重启（会弹 UAC）...\n");
		wchar_t self[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, self, MAX_PATH);
		wchar_t params[MAX_PATH * 2] = {};
		_snwprintf_s(params, _countof(params), _TRUNCATE, L"--elevated --out \"%s\"", outBase);
		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.fMask = SEE_MASK_NOCLOSEPROCESS;
		sei.lpVerb = L"runas";
		sei.lpFile = self;
		sei.lpParameters = params;
		sei.nShow = SW_SHOWNORMAL;
		if (!ShellExecuteExW(&sei)) {
			wprintf(L"提权被拒绝/失败 err=%lu\n", GetLastError());
			return 1;
		}
		WaitForSingleObject(sei.hProcess, 180000);
		CloseHandle(sei.hProcess);
		wprintf(L"已结束，结果见：%s.parent / .p0 / .p1 / .p2\n", outBase);
		return 0;
	}

	_wfopen_s(&g_log, outBase, L"wb");
	HMODULE user32 = GetModuleHandleW(L"user32.dll");
	g_setWindowBand = user32 ? reinterpret_cast<SetWindowBandFn>(GetProcAddress(user32, "SetWindowBand")) : nullptr;

	// ---------------- 子进程 ----------------
	if (childMode) {
		L("=== [子进程] KSword 配方验证 ===\n");
		L("pid=%lu\n", (unsigned long)GetCurrentProcessId());
		L("提权=%s  TokenUIAccess=%lu\n",
			IsElevated() ? "是" : "否",
			(unsigned long)SelfUIAccessFlag());
		{
			HANDLE t = nullptr;
			bool sys = false;
			if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) { sys = TokenIsLocalSystem(t); CloseHandle(t); }
			L("令牌主体是否 LocalSystem=%s\n", sys ? "是" : "否");
		}
		L("窗口站=%ls  桌面=%ls\n", CurrentWindowStationName(), CurrentDesktopName());
		L("user32!SetWindowBand 解析=%s\n", g_setWindowBand ? "成功" : "失败");
		RunWindowBandTest("子进程 band 测试");
		L("\n[子进程结束]\n");
		if (g_log) fclose(g_log);
		return 0;
	}

	// ---------------- 父进程（提权） ----------------
	L("=== KSword 配方探针（SYSTEM 令牌 + CreateProcessWithTokenW + Winlogon 桌面）===\n");
	L("pid=%lu  提权=%s  TokenUIAccess=%lu\n",
		(unsigned long)GetCurrentProcessId(), IsElevated() ? "是" : "否",
		(unsigned long)SelfUIAccessFlag());
	L("窗口站=%ls  桌面=%ls\n", CurrentWindowStationName(), CurrentDesktopName());
	L("user32!SetWindowBand 解析=%s\n", g_setWindowBand ? "成功" : "失败");

	RunWindowBandTest("阶段 P-基线：父进程（管理员，无 UIAccess）");

	struct Phase { const char* tag; const wchar_t* desktop; bool uiAccess; const wchar_t* outSuffix; };
	const Phase phases[] = {
		{ "P0  SYSTEM + UIAccess=0 + default ", L"winsta0\\default",  false, L".p0" },
		{ "P1  SYSTEM + UIAccess=1 + default ", L"winsta0\\default",  true,  L".p1" },
		{ "P2  SYSTEM + UIAccess=1 + Winlogon", L"winsta0\\Winlogon", true,  L".p2" },
	};

	for (const Phase& ph : phases) {
		L("\n---- 阶段 %s ----\n", ph.tag);
		DWORD sourcePid = 0, err = ERROR_SUCCESS;
		HANDLE token = BuildSystemPrimaryToken(ph.uiAccess, &sourcePid, &err);
		if (!token) {
			L("  令牌准备失败，跳过本阶段（err=%lu）\n", (unsigned long)err);
			continue;
		}
		wchar_t childOut[MAX_PATH] = {};
		_snwprintf_s(childOut, MAX_PATH, _TRUNCATE, L"%s%s", outBase, ph.outSuffix);
		SpawnChildWithToken(token, ph.desktop, childOut, ph.tag);
		CloseHandle(token);
	}

	L("\n---- 结论怎么看 ----\n");
	L("看每个 .pX 文件里 band=2 那两行的 ret/err 与「band 生效」。\n");
	L("  P1 生效            => 关键变量是「主令牌来自 SYSTEM」，不需要驱动也不需要注入 DWM。\n");
	L("  P1 不生效 / P2 生效 => 关键是「生在 Winlogon 安全桌面」，即 KSword UacDesk 的做法。\n");
	L("  P0/P1/P2 全不生效  => 与上一轮结论一致：win32k 不认事后设的 TokenUIAccess。\n");

	if (g_log) fclose(g_log);
	return 0;
}
