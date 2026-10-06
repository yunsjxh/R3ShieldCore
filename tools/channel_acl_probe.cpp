//
// channel_acl_probe —— 复现并验证「共享通道 ACL 把交互用户挤掉」这个根因。
//
// 背景（v55 修的 bug）：
//   UIAccess 子引擎是用 winlogon.exe 的 LocalSystem 令牌拉起来的，所以那个进程的
//   token 用户 = SYSTEM (S-1-5-18)。共享对象的 ACL 历来只写「本进程 token 用户」
//   一条 ACE ⇒ SYSTEM 引擎建出来的对象**没有交互用户的 ACE** ⇒ 普通（中等完整性）
//   进程 OpenFileMapping 被 DACL 直接拒 ⇒ "共享通道不可用" ⇒ 全局零事件。
//
// 用法：
//   channel_acl_probe.exe        # 只跑 A/B（纯 ACL 对照，最干净）
//   channel_acl_probe.exe c      # 再跑 C：加载真实 DLL，走产品代码建真通道
//
//   A. 旧式 SDDL 建映射再自己打开 —— 期望**被拒**（复现 bug）。
//      旧式 = D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-18)
//   B. 新式 SDDL（再追加一条"交互用户" ACE）建映射再打开 —— 期望**成功**。
//   C. LoadLibrary(R3ShieldCore/Release/64/r3shieldcore-lib.dll) →
//      GlobalHookSessionStart() 按**产品代码**建真通道 → 自己打开 —— 期望成功。
//
// 必须在**非提权**（中等完整性）进程里跑，否则 token 里有已启用的
// Administrators 组，旧式 SDDL 的 (A;;GA;;;BA) 会放行，A 步就复现不出来。
//
#include <windows.h>
#include <sddl.h>
#include <wtsapi32.h>

#include <r3shieldcore/r3shieldcore_shared.h>

#include <clocale>
#include <cstdio>
#include <cstring>
#include <string>

namespace
{
	int g_pass = 0;
	int g_fail = 0;

	void Report(bool ok, const char* what, DWORD err = 0)
	{
		if (ok) {
			++g_pass;
			std::printf("  [PASS] %s\n", what);
		}
		else {
			++g_fail;
			std::printf("  [FAIL] %s (err=%lu)\n", what, static_cast<unsigned long>(err));
		}
	}

	std::wstring SidToString(PSID sid)
	{
		WCHAR* text = nullptr;
		if (!ConvertSidToStringSidW(sid, &text)) {
			return std::wstring();
		}
		std::wstring result(text);
		LocalFree(text);
		return result;
	}

	// TOKEN_USER 里带内联 SID，缓冲区必须按指针对齐 —— 用 LocalAlloc，
	// 不能用 std::string（未对齐时会读出垃圾 SID）。
	std::wstring TokenUserSid(HANDLE token)
	{
		DWORD bytes = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
		if (bytes == 0) {
			return std::wstring();
		}

		HLOCAL buffer = LocalAlloc(LMEM_FIXED, bytes);
		if (!buffer) {
			return std::wstring();
		}

		std::wstring result;
		if (GetTokenInformation(token, TokenUser, buffer, bytes, &bytes)) {
			result = SidToString(static_cast<const TOKEN_USER*>(buffer)->User.Sid);
		}
		LocalFree(buffer);
		return result;
	}

	std::wstring CurrentUserSid()
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return std::wstring();
		}
		std::wstring result = TokenUserSid(token);
		CloseHandle(token);
		return result;
	}

	// 与 functions.cpp 的 TryGetSessionUserSid 完全同一套调用。
	// 非提权进程缺 SeTcbPrivilege，这里**预期失败** —— 生产路径上只有 SYSTEM
	// 引擎才会走到这段（它有特权），那时解析一定成功。
	std::wstring SessionUserSid(bool& privilegedEnough)
	{
		privilegedEnough = false;

		DWORD sessionId = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			return std::wstring();
		}

		HANDLE userToken = nullptr;
		if (!WTSQueryUserToken(sessionId, &userToken)) {
			return std::wstring();
		}
		privilegedEnough = true;

		std::wstring result = TokenUserSid(userToken);
		CloseHandle(userToken);
		return result;
	}

	bool IsElevated()
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}
		TOKEN_ELEVATION elevation = {};
		DWORD bytes = 0;
		const bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes);
		CloseHandle(token);
		return ok && elevation.TokenIsElevated != 0;
	}

	bool CreateThenOpen(const std::wstring& sddl, const std::wstring& name,
		bool& created, DWORD& createErr, bool& opened, DWORD& openErr)
	{
		created = false;
		opened = false;
		createErr = 0;
		openErr = 0;

		PSECURITY_DESCRIPTOR descriptor = nullptr;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
				sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
			createErr = GetLastError();
			return false;
		}

		SECURITY_ATTRIBUTES attributes = { sizeof(SECURITY_ATTRIBUTES) };
		attributes.lpSecurityDescriptor = descriptor;
		attributes.bInheritHandle = FALSE;

		SetLastError(ERROR_SUCCESS);
		HANDLE creator = CreateFileMappingW(INVALID_HANDLE_VALUE, &attributes,
			PAGE_READWRITE, 0, 4096, name.c_str());
		createErr = GetLastError();
		LocalFree(descriptor);

		if (!creator) {
			return false;
		}
		created = true;

		// 关掉"创建者"句柄，逼这次打开走一次完整的 DACL 判定。
		HANDLE handle = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name.c_str());
		openErr = GetLastError();
		if (handle) {
			opened = true;
			CloseHandle(handle);
		}

		CloseHandle(creator);
		return true;
	}

	void RunRealDllTest()
	{
		const wchar_t* dllPath = L"R3ShieldCore\\Release\\64\\r3shieldcore-lib.dll";
		std::printf("\n--- C: 真实构建产物 %ls ---\n", dllPath);

		HMODULE dll = LoadLibraryW(dllPath);
		if (!dll) {
			++g_fail;
			std::printf("  [FAIL] LoadLibrary 失败 err=%lu\n",
				static_cast<unsigned long>(GetLastError()));
			return;
		}

		using StartFn = HANDLE(__cdecl*)(const R3ShieldCore::Policy*);
		using EndFn = BOOL(__cdecl*)(HANDLE);
		auto start = reinterpret_cast<StartFn>(GetProcAddress(dll, "GlobalHookSessionStart"));
		auto end = reinterpret_cast<EndFn>(GetProcAddress(dll, "GlobalHookSessionEnd"));

		if (!start || !end) {
			++g_fail;
			std::printf("  [FAIL] 找不到导出 GlobalHookSessionStart/End\n");
			FreeLibrary(dll);
			return;
		}

		std::printf("        sizeof(R3ShieldCore::Policy)=%zu\n", sizeof(R3ShieldCore::Policy));

		R3ShieldCore::Policy policy = {};
		policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Log);

		HANDLE session = start(&policy);
		if (!session) {
			++g_fail;
			std::printf("  [FAIL] GlobalHookSessionStart 返回 null（通道没建起来）\n");
			FreeLibrary(dll);
			return;
		}

		const std::wstring base = L"R3ShieldCore-Events-pid=" + std::to_wstring(GetCurrentProcessId());
		HANDLE opened = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, base.c_str());
		DWORD err = GetLastError();
		if (opened) {
			CloseHandle(opened);
			std::printf("        (会话内命名)\n");
		}
		else {
			const std::wstring globalName = L"Global\\" + base;
			opened = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, globalName.c_str());
			err = GetLastError();
			if (opened) {
				CloseHandle(opened);
				std::printf("        (Global 命名)\n");
			}
		}

		Report(opened != nullptr, "产品代码建的 R3ShieldCore-Events 通道应能被本用户打开", err);

		end(session);
		FreeLibrary(dll);
	}
}

int main(int argc, char** argv)
{
	setvbuf(stdout, nullptr, _IONBF, 0);   // 崩溃时也要能看到已打印的内容
	setlocale(LC_ALL, "");

	const bool runRealDll = (argc > 1 && (argv[1][0] == 'c' || argv[1][0] == 'C'));

	std::printf("=== channel_acl_probe ===\n");
	std::printf("pid=%lu elevated=%d\n",
		static_cast<unsigned long>(GetCurrentProcessId()), IsElevated() ? 1 : 0);

	const std::wstring userSid = CurrentUserSid();
	bool sessionPrivileged = false;
	const std::wstring sessionSid = SessionUserSid(sessionPrivileged);

	std::printf("token   user sid = %ls\n", userSid.c_str());
	std::printf("session user sid = %ls (WTS 可用=%d)\n",
		sessionSid.empty() ? L"(未取到)" : sessionSid.c_str(), sessionPrivileged ? 1 : 0);

	if (IsElevated()) {
		std::printf("\n[!] 当前进程已提权 —— A 步的 (A;;GA;;;BA) 会放行，复现不出。"
			"请用非提权 cmd 跑。\n");
	}

	// 扮演"交互用户"的 SID：优先用 WTS 解析出的会话用户（若可得），
	// 否则用本进程 token 用户（单用户机器上同一个账户）。
	const std::wstring interactiveSid = sessionSid.empty() ? userSid : sessionSid;

	std::printf("\n--- A: 旧式 SDDL（= SYSTEM 引擎建出来的 ACL）---\n");
	{
		const std::wstring name = L"R3ShieldCoreAclProbe-Old-" + std::to_wstring(GetCurrentProcessId());
		const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-18)";

		bool created = false, opened = false;
		DWORD createErr = 0, openErr = 0;
		if (!CreateThenOpen(sddl, name, created, createErr, opened, openErr)) {
			std::printf("  [SKIP] 建对象失败 err=%lu\n", static_cast<unsigned long>(createErr));
		}
		else if (IsElevated()) {
			std::printf("  [SKIP] 已提权，复现不出\n");
		}
		else {
			Report(!opened, "旧式 ACL 应**拒绝**中等完整性的交互用户（这就是零事件）", openErr);
		}
	}

	std::printf("\n--- B: 新式 SDDL（旧式 + 一条交互用户 ACE）---\n");
	{
		const std::wstring name = L"R3ShieldCoreAclProbe-New-" + std::to_wstring(GetCurrentProcessId());
		const std::wstring sddl =
			L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-18)(A;;GA;;;" + interactiveSid + L")";

		bool created = false, opened = false;
		DWORD createErr = 0, openErr = 0;
		if (!CreateThenOpen(sddl, name, created, createErr, opened, openErr)) {
			++g_fail;
			std::printf("  [FAIL] 建对象失败 err=%lu（SDDL 语法？）\n",
				static_cast<unsigned long>(createErr));
		}
		else {
			Report(opened, "新式 ACL 应**放行**交互用户", openErr);
		}
	}

	if (runRealDll) {
		RunRealDllTest();
	}
	else {
		std::printf("\n(C 步未跑；加参数 c 可加载真实 DLL 端到端验证)\n");
	}

	std::printf("\n=== 结果: pass=%d fail=%d ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
