#include "ark_actions.h"

#include <psapi.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

namespace ArkActions
{
	namespace
	{
		// 两份 PE 头是不是同一次构建。
		//
		// 判据刻意只取 `TimeDateStamp` + `SizeOfImage` 这一对 —— 与
		// `check_dist_sync.sh` 的"重建后哈希变了 != 行为变了"同源（铁律 61）：
		// 重编一次会让文件哈希变、时间戳变，但**规则/代码没变的构建**不该被拒。
		// 反过来，只要这两项不同，就说明不是同一份产物，偏移不可信。
		bool HeadersMatch(const BYTE* a, size_t aSize, const BYTE* b, size_t bSize) noexcept
		{
			if (!a || !b || aSize < sizeof(IMAGE_DOS_HEADER) || bSize < sizeof(IMAGE_DOS_HEADER)) {
				return false;
			}

			const IMAGE_DOS_HEADER* da = reinterpret_cast<const IMAGE_DOS_HEADER*>(a);
			const IMAGE_DOS_HEADER* db = reinterpret_cast<const IMAGE_DOS_HEADER*>(b);
			if (da->e_magic != IMAGE_DOS_SIGNATURE || db->e_magic != IMAGE_DOS_SIGNATURE) {
				return false;
			}

			const size_t offsetA = static_cast<size_t>(da->e_lfanew);
			const size_t offsetB = static_cast<size_t>(db->e_lfanew);
			if (offsetA < sizeof(IMAGE_DOS_HEADER) || offsetB < sizeof(IMAGE_DOS_HEADER)
				|| offsetA + sizeof(IMAGE_NT_HEADERS) > aSize
				|| offsetB + sizeof(IMAGE_NT_HEADERS) > bSize) {
				return false;
			}

			const IMAGE_NT_HEADERS* na = reinterpret_cast<const IMAGE_NT_HEADERS*>(a + offsetA);
			const IMAGE_NT_HEADERS* nb = reinterpret_cast<const IMAGE_NT_HEADERS*>(b + offsetB);
			if (na->Signature != IMAGE_NT_SIGNATURE || nb->Signature != IMAGE_NT_SIGNATURE) {
				return false;
			}

			return na->FileHeader.TimeDateStamp == nb->FileHeader.TimeDateStamp
				&& na->OptionalHeader.SizeOfImage == nb->OptionalHeader.SizeOfImage;
		}

		// ------------------------------------------------------------------
		// 关键系统进程名单（全小写、带扩展名）
		// ------------------------------------------------------------------
		//
		// 入列标准（**两条满足任一条就入**，因为本名单对"结束"和"挂起"同时生效）：
		//   ① 结束它 ⇒ 立即 `CRITICAL_PROCESS_DIED` 蓝屏
		//      （这些进程带 CriticalProcess 标志，内核会直接 bugcheck）；
		//   ② 挂起它 ⇒ 整机卡死到只能断电
		//      （csrss 管窗口管理、dwm 管桌面合成、fontdrvhost 管字体）。
		//
		// ⚠️ 刻意**不**包含普通系统进程（svchost.exe / explorer.exe /
		//    SearchHost.exe / taskhostw.exe …）：它们是 %SystemRoot% 下的 Windows
		//    二进制，但既不带 CriticalProcess 标志、被杀也不会蓝屏。
		//    把它们一起拒掉会让 ARK 在"清理异常系统组件"时毫无用处。
		//    界面把"系统进程"与"关键进程"分成两列，就是这条边界的体现。
		constexpr PCWSTR kCriticalProcesses[] = {
			L"system",                  // pid 4 的内核伪进程
			L"[system process]",        // pid 0（Idle）在 Toolhelp 里的名字
			L"idle",
			L"registry",
			L"memory compression",
			L"secure system",
			L"smss.exe",
			L"csrss.exe",
			L"wininit.exe",
			L"winlogon.exe",
			L"services.exe",
			L"lsass.exe",
			L"lsaiso.exe",
			L"fontdrvhost.exe",         // Win10 1903+ 带 CriticalProcess
			L"dwm.exe",                 // 结束=Win7 蓝屏；挂起=桌面立刻冻住
		};

		bool EqualsNoCase(PCWSTR a, PCWSTR b) noexcept
		{
			return a && b && _wcsicmp(a, b) == 0;
		}

		bool StartsWithNoCase(PCWSTR text, PCWSTR prefix) noexcept
		{
			if (!text || !prefix) {
				return false;
			}
			const size_t n = wcslen(prefix);
			return _wcsnicmp(text, prefix, n) == 0;
		}

		PCWSTR FileNamePart(PCWSTR path) noexcept
		{
			if (!path) {
				return nullptr;
			}
			PCWSTR last = path;
			for (PCWSTR p = path; *p; p++) {
				if (*p == L'\\' || *p == L'/') {
					last = p + 1;
				}
			}
			return last;
		}

		// pid → 映像名（Toolhelp 快照）。
		//
		// ★ 为什么不用 OpenProcess + QueryFullProcessImageNameW：
		//   `lsass.exe` 在开了 LSA 保护的机器上是 **PPL**，OpenProcess 会被拒，
		//   于是"拒绝原因"会退化成 AccessDenied —— 用户看到"权限不足"，
		//   而真相是"这是关键进程，本来就不该动"（铁律 97：原因要准）。
		//   Toolhelp 快照对 PPL 一样有效。
		bool QueryProcessNameByPid(DWORD pid, WCHAR* out, size_t cch) noexcept
		{
			if (!out || cch == 0) {
				return false;
			}
			out[0] = L'\0';

			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snapshot == INVALID_HANDLE_VALUE) {
				return false;
			}

			bool found = false;
			PROCESSENTRY32W entry = {};
			entry.dwSize = sizeof(entry);
			if (Process32FirstW(snapshot, &entry)) {
				do {
					if (entry.th32ProcessID == pid) {
						wcsncpy_s(out, cch, entry.szExeFile, _TRUNCATE);
						found = true;
						break;
					}
				} while (Process32NextW(snapshot, &entry));
			}

			CloseHandle(snapshot);
			return found;
		}

		// pid 现在还在不在。
		//
		// ★ 为什么不用 `OpenProcess(SYNCHRONIZE)` + 看 ERROR_INVALID_PARAMETER：
		//   受保护进程（PPL）连 `SYNCHRONIZE` 都不给，于是"权限不足"会被
		//   误读成"进程还在"，两条完全不同的成因混成一个分支（铁律 97）。
		//   Toolhelp 快照对 PPL 一样能列出，判"在不在"是准的。
		bool GetProcessIdPresent(DWORD pid) noexcept
		{
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snapshot == INVALID_HANDLE_VALUE) {
				// 快照都建不出来时**当作"在"**：宁可走到 OpenProcess 拿真实
				// 错误码，也不要凭一次快照失败就报"进程已不存在"。
				return true;
			}

			bool present = false;
			PROCESSENTRY32W entry = {};
			entry.dwSize = sizeof(entry);
			if (Process32FirstW(snapshot, &entry)) {
				do {
					if (entry.th32ProcessID == pid) {
						present = true;
						break;
					}
				} while (Process32NextW(snapshot, &entry));
			}

			CloseHandle(snapshot);
			return present;
		}

		// 目标是不是 32 位进程（跑在 64 位 Windows 上）。
		bool IsTargetWow64(HANDLE process) noexcept
		{
			BOOL wow64 = FALSE;
			if (!IsWow64Process(process, &wow64)) {
				return false;
			}
			return wow64 != FALSE;
		}

		// ntdll!NtSuspendProcess / NtResumeProcess。
		//
		// 用它们而不是"遍历线程 SuspendThread"：后者要么漏线程（新起的），
		// 要么把线程卡在系统调用里导致死锁，而且 N 个线程要 N 次挂起、还可能中途失败
		// 留下一半挂起的进程 —— 这个状态用户根本没法收拾。
		using NtProcessControlFn = LONG(NTAPI*)(HANDLE);

		// 名字用 **ANSI**：`GetProcAddress` 只吃 `LPCSTR`（导出名本来就是 ASCII），
		// 传宽串得先转一次，纯属多余。
		NtProcessControlFn ResolveNtProcessControl(LPCSTR name) noexcept
		{
			HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
			if (!ntdll) {
				return nullptr;
			}
			return reinterpret_cast<NtProcessControlFn>(
				reinterpret_cast<void*>(GetProcAddress(ntdll, name)));
		}

		Outcome PerformSuspendOrResume(DWORD pid, Action action) noexcept
		{
			Outcome out = {};

			HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
				FALSE, pid);
			if (!process) {
				out.Win32Error = GetLastError();
				out.Code = (out.Win32Error == ERROR_INVALID_PARAMETER)
					? Result::ProcessGone : Result::AccessDenied;
				return out;
			}

			NtProcessControlFn fn = ResolveNtProcessControl(
				action == Action::Suspend ? "NtSuspendProcess" : "NtResumeProcess");
			if (!fn) {
				CloseHandle(process);
				out.Code = Result::Failed;
				return out;
			}

			const LONG status = fn(process);
			CloseHandle(process);

			// NTSTATUS：>= 0 成功。STATUS_PROCESS_IS_TERMINATING 之类会带负值。
			if (status >= 0) {
				out.Code = Result::Ok;
			}
			else {
				out.Code = Result::Failed;
				out.Win32Error = static_cast<DWORD>(status);
			}
			return out;
		}

		// 内部退出：在目标进程里跑我们那份 DLL 的导出。
		Outcome PerformInternalExit(DWORD pid, ULONG_PTR localDllBase) noexcept
		{
			Outcome out = {};

			const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
				PROCESS_VM_OPERATION | PROCESS_VM_READ | SYNCHRONIZE;
			HANDLE process = OpenProcess(access, FALSE, pid);
			if (!process) {
				out.Win32Error = GetLastError();
				out.Code = (out.Win32Error == ERROR_INVALID_PARAMETER)
					? Result::ProcessGone : Result::AccessDenied;
				return out;
			}

			// ---- 跨位数先判：64 位引擎**不可能**在 32 位目标里建远程线程 ----
			// 先判出来是为了给出准确的失败原因，而不是让 CreateRemoteThread
			// 报一个 ERROR_PARTIAL_COPY 让用户去猜。
			BOOL selfWow64 = FALSE;
			IsWow64Process(GetCurrentProcess(), &selfWow64);
			if (IsTargetWow64(process) != (selfWow64 != FALSE)) {
				CloseHandle(process);
				out.Code = Result::UnsupportedWow64;
				return out;
			}

			// ---- 目标里的 DLL 基址 + 同一份构建校验 ----
			ULONG_PTR remoteBase = 0;
			bool sameBuild = false;
			DWORD queryError = 0;
			if (!QueryRemoteDllBase(process, localDllBase, &remoteBase, &sameBuild,
				&queryError)) {
				CloseHandle(process);
				out.DllPresent = false;
				out.Win32Error = queryError;
				out.Code = Result::DllNotLoaded;
				return out;
			}

			out.DllPresent = true;
			out.DllSameBuild = sameBuild;
			if (!sameBuild) {
				CloseHandle(process);
				out.Code = Result::DllMismatch;
				return out;
			}

			if (localDllBase == 0) {
				CloseHandle(process);
				out.Code = Result::ExportMissing;
				return out;
			}
			const ULONG_PTR localExport = reinterpret_cast<ULONG_PTR>(
				GetProcAddress(reinterpret_cast<HMODULE>(localDllBase),
					"GlobalHookSessionSelfExit"));
			if (localExport == 0) {
				CloseHandle(process);
				out.Code = Result::ExportMissing;
				return out;
			}
			const ULONG_PTR offset = localExport - localDllBase;

			HANDLE thread = CreateRemoteThread(process, nullptr, 0,
				reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteBase + offset),
				nullptr, 0, nullptr);
			if (!thread) {
				out.Win32Error = GetLastError();
				CloseHandle(process);
				out.Code = Result::RemoteThreadFailed;
				return out;
			}
			CloseHandle(thread);

			// 给目标时间跑完它自己的退出路径（DllMain DETACH / atexit / flush）。
			const DWORD wait = WaitForSingleObject(process, 1500);
			CloseHandle(process);

			out.Code = (wait == WAIT_OBJECT_0) ? Result::Ok : Result::TimedOut;
			return out;
		}

		Outcome PerformForceKill(DWORD pid) noexcept
		{
			Outcome out = {};

			HANDLE process = OpenProcess(
				PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
				FALSE, pid);
			if (!process) {
				out.Win32Error = GetLastError();
				out.Code = (out.Win32Error == ERROR_INVALID_PARAMETER)
					? Result::ProcessGone : Result::AccessDenied;
				return out;
			}

			if (!TerminateProcess(process, 1)) {
				out.Win32Error = GetLastError();
				CloseHandle(process);
				out.Code = Result::Failed;
				return out;
			}

			const DWORD wait = WaitForSingleObject(process, 1500);
			CloseHandle(process);

			out.Code = (wait == WAIT_OBJECT_0) ? Result::Ok : Result::TimedOut;
			return out;
		}
	}

	bool IsCriticalProcessName(PCWSTR fileName) noexcept
	{
		if (!fileName || fileName[0] == L'\0') {
			return false;
		}
		PCWSTR base = FileNamePart(fileName);
		for (PCWSTR name : kCriticalProcesses) {
			if (EqualsNoCase(base, name)) {
				return true;
			}
		}
		return false;
	}

	bool IsSystemImagePath(PCWSTR imagePath, PCWSTR systemRoot) noexcept
	{
		if (!imagePath || imagePath[0] == L'\0' || !systemRoot || systemRoot[0] == L'\0') {
			return false;
		}

		// `%SystemRoot%` + `\` —— 必须带上那个反斜杠，否则
		// `C:\WindowsApps\...`（同前缀但不是系统目录）会被误判成系统进程。
		WCHAR prefix[MAX_PATH + 8] = {};
		if (swprintf_s(prefix, L"%s\\", systemRoot) <= 0) {
			return false;
		}
		return StartsWithNoCase(imagePath, prefix);
	}

	bool QueryRemoteDllBase(HANDLE process, ULONG_PTR localDllBase,
		ULONG_PTR* remoteBase, bool* sameBuild, DWORD* win32Error) noexcept
	{
		if (remoteBase) {
			*remoteBase = 0;
		}
		if (sameBuild) {
			*sameBuild = false;
		}
		if (win32Error) {
			*win32Error = 0;
		}
		if (!process || !remoteBase) {
			return false;
		}

		// ---- 1. 在目标模块表里按**基名**找我们的 DLL ----
		HMODULE modules[1024] = {};
		DWORD needed = 0;
		if (!EnumProcessModulesEx(process, modules, sizeof(modules), &needed,
			LIST_MODULES_ALL)) {
			if (win32Error) {
				*win32Error = GetLastError();
			}
			return false;
		}

		ULONG_PTR found = 0;
		const DWORD count = needed / sizeof(HMODULE);
		for (DWORD i = 0; i < count && i < _countof(modules); i++) {
			WCHAR name[MAX_PATH] = {};
			if (GetModuleBaseNameW(process, modules[i], name, _countof(name)) == 0) {
				continue;
			}
			if (_wcsicmp(name, L"r3shieldcore-lib.dll") == 0) {
				found = reinterpret_cast<ULONG_PTR>(modules[i]);
				break;
			}
		}

		if (found == 0) {
			if (win32Error) {
				*win32Error = ERROR_MOD_NOT_FOUND;
			}
			return false;
		}
		*remoteBase = found;

		// ---- 2. 同一份构建校验（fail-closed）----
		if (!sameBuild) {
			return true;
		}
		if (localDllBase == 0) {
			return true;
		}

		BYTE localHeader[4096] = {};
		BYTE remoteHeader[4096] = {};
		memcpy(localHeader, reinterpret_cast<const void*>(localDllBase), sizeof(localHeader));

		SIZE_T read = 0;
		if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(found), remoteHeader,
			sizeof(remoteHeader), &read) || read < 256) {
			// 读不出远端 PE 头 ⇒ 无法证明偏移一致 ⇒ **拒绝**（调用方会看到
			// DllMismatch）。把远程线程入口设到没验证过的地址 = 在目标里
			// 执行任意代码，这是绝对不能猜的一步。
			if (win32Error) {
				*win32Error = GetLastError();
			}
			return true;
		}

		*sameBuild = HeadersMatch(localHeader, sizeof(localHeader),
			remoteHeader, sizeof(remoteHeader));
		return true;
	}

	Outcome Perform(DWORD pid, Action action, DWORD selfPid, ULONG_PTR localDllBase) noexcept
	{
		Outcome out = {};
		const ULONGLONG start = GetTickCount64();

		// ---- 拒绝清单（在 OpenProcess 之前判，原因才准）----
		if (pid == 0 || pid == 4) {
			out.Code = Result::RefusedCritical;
			return out;
		}
		if (pid == selfPid) {
			out.Code = Result::RefusedSelf;
			return out;
		}

		WCHAR name[64] = {};
		if (QueryProcessNameByPid(pid, name, _countof(name))) {
			if (IsCriticalProcessName(name)) {
				out.Code = Result::RefusedCritical;
				return out;
			}
		}
		else if (!GetProcessIdPresent(pid)) {
			out.Code = Result::ProcessGone;
			return out;
		}

		switch (action) {
		case Action::Suspend:
		case Action::Resume:
			out = PerformSuspendOrResume(pid, action);
			break;
		case Action::InternalExit:
			out = PerformInternalExit(pid, localDllBase);
			break;
		case Action::ForceKill:
			out = PerformForceKill(pid);
			break;
		default:
			out.Code = Result::Failed;
			break;
		}

		out.ElapsedMs = static_cast<DWORD>(GetTickCount64() - start);
		return out;
	}

	PCWSTR ResultText(Result result) noexcept
	{
		switch (result) {
		case Result::Ok: return L"成功";
		case Result::RefusedSelf: return L"拒绝：目标是引擎自己";
		case Result::RefusedCritical: return L"拒绝：关键系统进程（结束会蓝屏 / 挂起会卡死）";
		case Result::ProcessGone: return L"目标进程已经不存在";
		case Result::AccessDenied: return L"权限不足（目标可能是受保护进程 PPL）";
		case Result::UnsupportedWow64: return L"跨位数：64 位引擎无法在 32 位目标里执行内部退出，请用强制结束";
		case Result::DllNotLoaded: return L"目标未被注入（模块表里没有 r3shieldcore-lib.dll）";
		case Result::DllMismatch: return L"目标里的 DLL 与本引擎不是同一份构建，拒绝在未校验的地址上执行";
		case Result::ExportMissing: return L"本地 DLL 没有该导出（旧版 DLL？）";
		case Result::RemoteThreadFailed: return L"在目标里创建远程线程失败";
		case Result::TimedOut: return L"已下发但目标在 1.5 秒内没有退出";
		default: return L"失败";
		}
	}

	const char* ResultCode(Result result) noexcept
	{
		switch (result) {
		case Result::Ok: return "OK";
		case Result::RefusedSelf: return "REFUSED_SELF";
		case Result::RefusedCritical: return "REFUSED_CRITICAL";
		case Result::ProcessGone: return "PROCESS_GONE";
		case Result::AccessDenied: return "ACCESS_DENIED";
		case Result::UnsupportedWow64: return "WOW64_UNSUPPORTED";
		case Result::DllNotLoaded: return "DLL_NOT_LOADED";
		case Result::DllMismatch: return "DLL_MISMATCH";
		case Result::ExportMissing: return "EXPORT_MISSING";
		case Result::RemoteThreadFailed: return "REMOTE_THREAD_FAILED";
		case Result::TimedOut: return "TIMED_OUT";
		default: return "FAILED";
		}
	}

	PCWSTR ActionText(Action action) noexcept
	{
		switch (action) {
		case Action::Suspend: return L"挂起";
		case Action::Resume: return L"恢复";
		case Action::InternalExit: return L"内部退出";
		case Action::ForceKill: return L"强制结束";
		default: return L"未知动作";
		}
	}
}
