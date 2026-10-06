//
// 探针：怎么才能真正拿到 UIAccess（= 真·超级置顶 / SetWindowBand band 2）。
//
// 要回答两个问题，分两个阶段：
//
//   阶段 B（就地开）：模拟 SYSTEM 拿 SeTcb → 对**自己进程的 primary 令牌**调
//     SetTokenInformation(TokenUIAccess, 1)。标记能设上，但 win32k 认不认？
//     【已实测结论：不认】—— 令牌复查 TokenUIAccess=1，但 SetWindowBand 依旧失败，
//     窗口也压不住别的置顶窗口。UIAccess 是**进程创建时**被 win32k 读进内部状态的，
//     运行中改令牌不生效。
//
//   阶段 E（重启开）：jiyu 那条路 —— 复制当前令牌为 primary、设 TokenUIAccess，
//     再 CreateProcessAsUser 拉起**同一个 exe**（带 --child）。子进程从一出生
//     就带 UIAccess，这时 SetWindowBand 能不能用？
//     这是判断"超级置顶能不能做"的**决定性实验**。
//
// 为什么需要管理员：模拟 SYSTEM 要 SeDebugPrivilege，设 TokenUIAccess 要 SeTcbPrivilege。
//   本探针会**自己弹 UAC**，结果写进 .out 文件（UTF-8）。
//
// 用法（非提权直接跑，它会自己提权）：
//     tools\uiaccess_probe.exe
//   结果：tools\uiaccess_probe.out   +   tools\uiaccess_probe.out.child
//

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <vector>

static FILE* g_log = nullptr;
static const wchar_t* kWndClass = L"UiAccessProbeWnd";

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
		// ⚠️ 别把 CP936 窄串直接塞进 "ccs=UTF-8" 打开的流：CRT 会做 CP936→UTF-8
		//    转换，默认 "C" locale 不认非 ASCII 字节 => 转换失败 => invalid parameter
		//    handler => **进程被直接干掉**（现象：文件只剩一个 BOM、stdout 只剩第一行）。
		//    所以自己走 CP_ACP -> UTF-16 -> UTF-8，再按字节写。
		wchar_t wide[2048] = {};
		int wn = MultiByteToWideChar(CP_ACP, 0, buffer, -1, wide, _countof(wide));
		if (wn > 0) {
			char utf8[4096] = {};
			int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, sizeof(utf8), nullptr, nullptr);
			if (n > 1) {
				fwrite(utf8, 1, static_cast<size_t>(n - 1), g_log);
			}
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

static DWORD SelfUiAccessFlag()
{
	HANDLE token = nullptr;
	DWORD v = 0;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		DWORD ret = 0;
		GetTokenInformation(token, TokenUIAccess, &v, sizeof(v), &ret);
		CloseHandle(token);
	}
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

static DWORD FindSystemProcess(DWORD sessionId)
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
			if (rank > bestRank) { bestRank = rank; best = pe.th32ProcessID; }
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
	return best;
}

// 「模拟 SYSTEM + 开 SeTcb」这一段阶段 B / E 共用，单独抽出来。
struct SystemImpersonation
{
	HANDLE currentToken = nullptr;
	HANDLE impToken = nullptr;
	HANDLE sourceToken = nullptr;
	HANDLE sourceProcess = nullptr;
	bool active = false;

	bool Begin()
	{
		if (!OpenProcessToken(GetCurrentProcess(),
			TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
			&currentToken)) {
			L("  [失败] OpenProcessToken(self) err=%lu\n", GetLastError());
			return false;
		}
		DWORD err = 0;
		if (!EnablePrivilege(currentToken, SE_DEBUG_NAME, &err)) {
			L("  [失败] 启用 SeDebugPrivilege err=%lu\n", err);
			return false;
		}
		DWORD sessionId = 0;
		ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
		DWORD sourcePid = FindSystemProcess(sessionId);
		if (sourcePid == 0) { L("  [失败] 找不到 SYSTEM 进程\n"); return false; }

		sourceProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
		if (!sourceProcess || !OpenProcessToken(sourceProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &sourceToken)) {
			L("  [失败] 打开 SYSTEM 进程/令牌 err=%lu\n", GetLastError());
			return false;
		}
		if (!TokenIsLocalSystem(sourceToken)) { L("  [失败] 该令牌不是 LocalSystem\n"); return false; }

		SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
		if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &sa, SecurityImpersonation,
			TokenImpersonation, &impToken)) {
			L("  [失败] DuplicateTokenEx(SYSTEM impersonation) err=%lu\n", GetLastError());
			return false;
		}
		if (!ImpersonateLoggedOnUser(impToken)) {
			L("  [失败] ImpersonateLoggedOnUser(SYSTEM) err=%lu\n", GetLastError());
			return false;
		}
		active = true;
		L("  [ok]   已模拟 SYSTEM (来源 pid=%lu)\n", (unsigned long)sourcePid);
		L("         SeAssignPrimaryToken=%d  SeIncreaseQuota=%d  SeTcb=%d\n",
			EnablePrivilege(impToken, SE_ASSIGNPRIMARYTOKEN_NAME, nullptr) ? 1 : 0,
			EnablePrivilege(impToken, SE_INCREASE_QUOTA_NAME, nullptr) ? 1 : 0,
			EnablePrivilege(impToken, SE_TCB_NAME, nullptr) ? 1 : 0);
		return true;
	}

	void End()
	{
		if (active) {
			RevertToSelf();
			L("         RevertToSelf() 已调用\n");
			active = false;
		}
		if (impToken) { CloseHandle(impToken); impToken = nullptr; }
		if (sourceToken) { CloseHandle(sourceToken); sourceToken = nullptr; }
		if (sourceProcess) { CloseHandle(sourceProcess); sourceProcess = nullptr; }
		if (currentToken) { CloseHandle(currentToken); currentToken = nullptr; }
	}
};

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

// 判据：每次都「故意最后抬 B」。B 仍在 A 之上 => 没抬起来；B 落到 A 之下 => band 生效。
static void RunWindowBandTest(const char* phase)
{
	L("\n---- %s ----\n", phase);

	WNDCLASSEXW wc = { sizeof(wc) };
	wc.lpfnWndProc = WndProc;
	wc.hInstance = GetModuleHandleW(nullptr);
	wc.lpszClassName = kWndClass;
	RegisterClassExW(&wc);
	HWND a = CreateWindowExW(WS_EX_TOOLWINDOW, kWndClass, L"A", WS_POPUP, 0, 0, 120, 30,
		nullptr, nullptr, wc.hInstance, nullptr);
	HWND b = CreateWindowExW(WS_EX_TOOLWINDOW, kWndClass, L"B", WS_POPUP, 140, 0, 120, 30,
		nullptr, nullptr, wc.hInstance, nullptr);
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

int wmain(int argc, wchar_t** argv)
{
	bool elevatedRun = false;
	bool childMode = false;
	wchar_t outPath[MAX_PATH] = {};
	{
		wchar_t self[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, self, MAX_PATH);
		wchar_t* slash = wcsrchr(self, L'\\');
		if (slash) *(slash + 1) = 0;
		_snwprintf_s(outPath, MAX_PATH, _TRUNCATE, L"%suiaccess_probe.out", self);
	}
	for (int i = 1; i < argc; ++i) {
		if (_wcsicmp(argv[i], L"--elevated") == 0) elevatedRun = true;
		else if (_wcsicmp(argv[i], L"--child") == 0) childMode = true;
		else if (_wcsicmp(argv[i], L"--out") == 0 && i + 1 < argc) {
			wcsncpy_s(outPath, MAX_PATH, argv[++i], _TRUNCATE);
		}
	}

	// 非提权且不是子进程 => 自己提权重启。
	if (!elevatedRun && !childMode && !IsElevated()) {
		wprintf(L"当前非提权 —— 自动以管理员身份重启（会弹 UAC）...\n");
		wchar_t self[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, self, MAX_PATH);
		wchar_t params[MAX_PATH * 2] = {};
		_snwprintf_s(params, _countof(params), _TRUNCATE, L"--elevated --out \"%s\"", outPath);
		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.fMask = SEE_MASK_NOCLOSEPROCESS;
		sei.lpVerb = L"runas";
		sei.lpFile = self;
		sei.lpParameters = params;
		sei.nShow = SW_SHOWNORMAL;
		if (!ShellExecuteExW(&sei)) {
			wprintf(L"提权被拒绝/失败 err=%lu —— 请右键「以管理员身份运行」后重试。\n", GetLastError());
			return 1;
		}
		WaitForSingleObject(sei.hProcess, 120000);
		CloseHandle(sei.hProcess);
		wprintf(L"已结束，结果见：%s\n", outPath);
		return 0;
	}

	_wfopen_s(&g_log, outPath, L"wb");

	HMODULE user32 = GetModuleHandleW(L"user32.dll");
	g_setWindowBand = user32 ? reinterpret_cast<SetWindowBandFn>(GetProcAddress(user32, "SetWindowBand")) : nullptr;

	if (childMode) {
		L("=== [子进程] 出生即带 UIAccess 的窗口波段测试 ===\n");
		L("pid=%lu  提权=%s  TokenUIAccess=%lu\n",
			(unsigned long)GetCurrentProcessId(), IsElevated() ? "是" : "否",
			(unsigned long)SelfUiAccessFlag());
		L("user32!SetWindowBand 解析=%s\n", g_setWindowBand ? "成功" : "失败");
		RunWindowBandTest("子进程 band 测试（CreateProcessAsUser 拉起）");
		L("\n[子进程结束]\n");
		if (g_log) fclose(g_log);
		return 0;
	}

	L("=== UIAccess 获取途径探针 ===\n");
	L("pid=%lu  提权=%s  起始 TokenUIAccess=%lu\n",
		(unsigned long)GetCurrentProcessId(), IsElevated() ? "是" : "否",
		(unsigned long)SelfUiAccessFlag());
	L("user32!SetWindowBand 解析=%s\n", g_setWindowBand ? "成功" : "失败");

	RunWindowBandTest("阶段 A：对照基线（未开 UIAccess）");

	L("\n---- 阶段 B：就地开 UIAccess（对运行中的自己改令牌）----\n");
	{
		SystemImpersonation imp;
		if (imp.Begin()) {
			HANDLE selfToken = nullptr;
			if (OpenProcessToken(GetCurrentProcess(),
				TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &selfToken)) {
				DWORD uiAccess = 1;
				SetLastError(0);
				BOOL ok = SetTokenInformation(selfToken, TokenUIAccess, &uiAccess, sizeof(uiAccess));
				L("  ★ SetTokenInformation(self, TokenUIAccess, 1) -> %s  err=%lu\n",
					ok ? "TRUE" : "FALSE", (unsigned long)GetLastError());
				CloseHandle(selfToken);
			}
			imp.End();
		}
		L("  复查：本进程 TokenUIAccess=%lu\n", (unsigned long)SelfUiAccessFlag());
	}

	RunWindowBandTest("阶段 C：就地改完令牌之后（同一进程，未重启）");

	L("\n---- 阶段 E：用 UIAccess 令牌重启一个自己（jiyu 那条路）----\n");
	{
		SystemImpersonation imp;
		if (imp.Begin()) {
			SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
			HANDLE uiToken = nullptr;
			if (DuplicateTokenEx(imp.currentToken, MAXIMUM_ALLOWED, &sa, SecurityImpersonation,
				TokenPrimary, &uiToken)) {
				DWORD uiAccess = 1;
				BOOL setOk = SetTokenInformation(uiToken, TokenUIAccess, &uiAccess, sizeof(uiAccess));
				L("  SetTokenInformation(duplicated primary, TokenUIAccess, 1) -> %s err=%lu\n",
					setOk ? "TRUE" : "FALSE", (unsigned long)GetLastError());

				wchar_t self[MAX_PATH] = {};
				GetModuleFileNameW(nullptr, self, MAX_PATH);
				wchar_t childOut[MAX_PATH] = {};
				_snwprintf_s(childOut, MAX_PATH, _TRUNCATE, L"%s.child", outPath);
				wchar_t cmd[MAX_PATH * 3] = {};
				_snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
					L"\"%s\" --child --out \"%s\"", self, childOut);

				STARTUPINFOW si = { sizeof(si) };
				wchar_t desktop[] = L"winsta0\\default";
				si.lpDesktop = desktop;
				PROCESS_INFORMATION pi = {};
				if (CreateProcessAsUserW(uiToken, self, cmd, nullptr, nullptr, FALSE,
					CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
					HANDLE childToken = nullptr;
					DWORD childFlag = 0;
					if (OpenProcessToken(pi.hProcess, TOKEN_QUERY, &childToken)) {
						DWORD ret = 0;
						GetTokenInformation(childToken, TokenUIAccess, &childFlag, sizeof(childFlag), &ret);
						CloseHandle(childToken);
					}
					L("  [ok]   子进程已拉起 pid=%lu  其 TokenUIAccess=%lu\n",
						(unsigned long)pi.dwProcessId, (unsigned long)childFlag);
					WaitForSingleObject(pi.hProcess, 60000);
					CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);
				}
				else {
					L("  [失败] CreateProcessAsUserW err=%lu\n", GetLastError());
				}
				CloseHandle(uiToken);
			}
			else {
				L("  [失败] DuplicateTokenEx(current primary) err=%lu\n", GetLastError());
			}
			imp.End();
		}
	}

	L("\n---- 结论 ----\n");
	L("阶段 C 全灭 + 阶段 E 子进程 band 生效 => 必须**重启进程**，jiyu 那条路可行。\n");
	L("阶段 E 也全灭 => UIAccess 还要求 exe 有签名/清单 uiAccess='true'，本项目做不到。\n");

	if (g_log) fclose(g_log);
	return 0;
}
