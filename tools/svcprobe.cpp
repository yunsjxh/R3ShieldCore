//
// R3ShieldCore 服务 API 探针（ABI v9 的 SCM 盲区补丁验证）。
//
// 背景：驱动加载走 services.exe（SCM），而 services.exe 在 R3ShieldCore 的
// 白名单里（%SystemRoot%\ → ComputeBypass）→ 只挂 ntdll!NtLoadDriver
// 根本抓不到调用方。ABI v9 在**调用方一侧**补挂了：
//     advapi32!CreateServiceW
//     advapi32!ChangeServiceConfigW
//     advapi32!StartServiceW
// 这个探针就是用来验证那三个 hook 到底有没有生效。
//
// 用法：
//   svcprobe driver     装内核驱动服务，二进制指向用户可写目录（= 高危）
//   svcprobe win32      装 Win32 服务，二进制 C:\Windows\System32\svchost.exe（正常，应放行）
//   svcprobe win32bad   装 Win32 服务，二进制在 %TEMP%（用户可写 = 高危）
//   svcprobe change     改已有服务的 ImagePath 指向用户可写目录的 .sys
//   svcprobe start [名] 启动一个已存在的服务（默认探测服务名），验证 StartServiceW hook
//   svcprobe clean      删掉探测服务
//   svcprobe all        依次跑 driver / win32 / win32bad / change，最后清理
//
// ⚠️ 装服务需要管理员权限。但**即使不提权**这个探针也有用：
//    hook 挂在 API 入口，OpenSCManager 失败（句柄为 NULL）不影响
//    CreateServiceW 被调用 → 我们的 hook 照样触发、照样上报事件。
//    只是没提权时 SCM 本来也会拒绝，"光看错误码"分不清是谁拒的 ——
//    所以判据要配合 R3ShieldCore 日志（有没有 DRV CreateService 事件）。
//
// ⚠️ 本探针**不会真的启动任何内核驱动**（.sys 是假的，SCM 会拒绝），
//    只做"注册/改配置/尝试启动"，不往内核里塞东西。
//
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <locale.h>
#include <vector>

namespace
{
	constexpr PCWSTR ProbeServiceName = L"R3ShieldCoreSvcProbe";
	constexpr PCWSTR ProbeDisplayName = L"R3ShieldCore Service Probe";

	// 用户可写目录 —— 命中 ABI v9 新增的"从用户可写目录安装服务"规则。
	constexpr PCWSTR UserWritableDriverPath = L"C:\\Users\\Public\\R3ShieldCoreSvcProbe.sys";

	// 正常的系统二进制 —— 用来验证"合法的 Win32 服务安装不被误拦"。
	constexpr PCWSTR SystemBinaryPath = L"C:\\Windows\\System32\\svchost.exe";

	void Report(PCWSTR what, BOOL ok, DWORD error)
	{
		wprintf(L"%-42s -> %s  err=%lu%s\n",
			what,
			ok ? L"OK" : L"失败",
			error,
			(!ok && error == ERROR_ACCESS_DENIED) ? L"   [被拦截?]" : L"");
	}

	void ReportHandle(PCWSTR what, HANDLE handle)
	{
		DWORD error = handle ? 0 : GetLastError();
		wprintf(L"%-42s -> %s  err=%lu%s\n",
			what,
			handle ? L"OK" : L"失败",
			error,
			(!handle && error == ERROR_ACCESS_DENIED) ? L"   [被拦截?]" : L"");
	}

	bool IsElevated()
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		TOKEN_ELEVATION elevation = {};
		DWORD size = 0;
		bool elevated = false;
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
			elevated = elevation.TokenIsElevated != 0;
		}

		CloseHandle(token);
		return elevated;
	}

	// 拿 SCM 句柄。没权限时返回 NULL —— 但**调用方照样继续调服务 API**，
	// 因为我们要验证的是 hook 有没有在 API 入口跑起来，而不是 SCM 让不让。
	SC_HANDLE OpenManager()
	{
		SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (!manager) {
			manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
		}

		return manager;
	}

	void CreateProbeService(DWORD serviceType, PCWSTR binaryPath, PCWSTR label)
	{
		SC_HANDLE manager = OpenManager();

		wprintf(L"\n--- %s ---\n", label);
		wprintf(L"  serviceType=0x%08lX  binary=%s\n", serviceType, binaryPath);
		wprintf(L"  OpenSCManager -> %s\n", manager ? L"OK" : L"失败（下面照样调 CreateServiceW）");

		SetLastError(0);
		SC_HANDLE service = CreateServiceW(
			manager,
			ProbeServiceName,
			ProbeDisplayName,
			SERVICE_ALL_ACCESS,
			serviceType,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			binaryPath,
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr);

		ReportHandle(L"CreateServiceW", service);

		if (service) {
			wprintf(L"  → 服务真的建起来了，立刻删掉（不留垃圾）\n");
			BOOL deleted = DeleteService(service);
			Report(L"DeleteService", deleted, GetLastError());
			CloseServiceHandle(service);
		}

		if (manager) {
			CloseServiceHandle(manager);
		}
	}

	void ChangeProbeService()
	{
		SC_HANDLE manager = OpenManager();

		wprintf(L"\n--- 改服务 ImagePath（指向用户可写目录）---\n");

		SC_HANDLE service = nullptr;
		if (manager) {
			service = OpenServiceW(manager, ProbeServiceName, SERVICE_CHANGE_CONFIG);
		}

		wprintf(L"  OpenService -> %s\n", service ? L"OK" : L"失败（下面照样调 ChangeServiceConfigW）");
		wprintf(L"  新 binary=%s\n", UserWritableDriverPath);

		SetLastError(0);
		BOOL changed = ChangeServiceConfigW(
			service,
			SERVICE_NO_CHANGE,          // 不改类型
			SERVICE_NO_CHANGE,          // 不改启动类型
			SERVICE_NO_CHANGE,          // 不改错误控制
			UserWritableDriverPath,     // 只改二进制路径
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr,
			nullptr);

		Report(L"ChangeServiceConfigW", changed, GetLastError());

		if (service) {
			CloseServiceHandle(service);
		}

		if (manager) {
			CloseServiceHandle(manager);
		}
	}

	// 启动一个**已存在**的服务，用来验证 StartServiceW hook。
	//
	// ⚠️ 关键在 OpenService 能不能拿到句柄：拿不到（NULL）时我们 hook 里的
	//    QueryServiceConfigW 也会失败 → 类型未知 → 判不出是不是内核驱动。
	//    所以这个模式的意义是"找一个普通权限也打得开的驱动服务"。
	//    用法：svcprobe start <服务名>
	void StartProbeService(PCWSTR serviceName)
	{
		SC_HANDLE manager = OpenManager();

		wprintf(L"\n--- 启动已存在的服务：%s ---\n", serviceName);

		SC_HANDLE service = nullptr;
		if (manager) {
			service = OpenServiceW(manager, serviceName, SERVICE_START | SERVICE_QUERY_CONFIG);
		}

		DWORD openError = service ? 0 : GetLastError();
		wprintf(L"  OpenService -> %s  err=%lu\n",
			service ? L"OK" : L"失败（下面照样调 StartServiceW）", openError);

		// 顺手把 SCM 眼里的类型和二进制路径打出来 —— 和 hook 侧
		// QueryServiceInfo 读到的应该是同一份数据，可以互相印证。
		if (service) {
			DWORD needed = 0;
			QueryServiceConfigW(service, nullptr, 0, &needed);
			if (needed > 0) {
				std::vector<BYTE> buffer(needed + 64);
				if (QueryServiceConfigW(service, reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data()),
						static_cast<DWORD>(buffer.size()), &needed)) {
					auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
					wprintf(L"  QueryServiceConfigW -> type=0x%08lX  binary=%s\n",
						config->dwServiceType, config->lpBinaryPathName);
				}
			}
		}

		SetLastError(0);
		BOOL started = StartServiceW(service, 0, nullptr);
		Report(L"StartServiceW", started, GetLastError());

		if (service) {
			CloseServiceHandle(service);
		}

		if (manager) {
			CloseServiceHandle(manager);
		}
	}

	void CleanProbeService()
	{
		SC_HANDLE manager = OpenManager();

		wprintf(L"\n--- 清理探测服务 ---\n");

		SC_HANDLE service = nullptr;
		if (manager) {
			service = OpenServiceW(manager, ProbeServiceName, DELETE | SERVICE_STOP);
		}

		if (!service) {
			wprintf(L"  服务不存在（或打不开），无需清理\n");
		}
		else {
			// 先停（驱动可能被 SCM 挂上），再删。
			SERVICE_STATUS status = {};
			ControlService(service, SERVICE_CONTROL_STOP, &status);
			BOOL deleted = DeleteService(service);
			Report(L"DeleteService", deleted, GetLastError());
			CloseServiceHandle(service);
		}

		if (manager) {
			CloseServiceHandle(manager);
		}
	}
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	const PCWSTR mode = (argc > 1) ? argv[1] : L"all";

	wprintf(L"R3ShieldCore 服务 API 探针 (pid=%lu)  [%s权限]\n",
		GetCurrentProcessId(), IsElevated() ? L"管理员" : L"普通");
	wprintf(L"镜像路径: 见 R3ShieldCore 日志的 pid\n");
	wprintf(L"========================================\n");

	if (_wcsicmp(mode, L"driver") == 0) {
		CreateProbeService(SERVICE_KERNEL_DRIVER, UserWritableDriverPath,
			L"内核驱动服务 · 用户可写目录（高危）");
	}
	else if (_wcsicmp(mode, L"win32") == 0) {
		CreateProbeService(SERVICE_WIN32_OWN_PROCESS, SystemBinaryPath,
			L"Win32 服务 · System32 二进制（正常）");
	}
	else if (_wcsicmp(mode, L"win32bad") == 0) {
		WCHAR tempPath[MAX_PATH] = {};
		GetTempPathW(_countof(tempPath), tempPath);
		wcscat_s(tempPath, L"R3ShieldCoreSvcProbe.exe");
		CreateProbeService(SERVICE_WIN32_OWN_PROCESS, tempPath,
			L"Win32 服务 · %TEMP% 二进制（高危）");
	}
	else if (_wcsicmp(mode, L"change") == 0) {
		ChangeProbeService();
	}
	else if (_wcsicmp(mode, L"start") == 0) {
		StartProbeService((argc > 2) ? argv[2] : ProbeServiceName);
	}
	else if (_wcsicmp(mode, L"clean") == 0) {
		CleanProbeService();
	}
	else if (_wcsicmp(mode, L"all") == 0) {
		CreateProbeService(SERVICE_KERNEL_DRIVER, UserWritableDriverPath,
			L"内核驱动服务 · 用户可写目录（高危）");
		CreateProbeService(SERVICE_WIN32_OWN_PROCESS, SystemBinaryPath,
			L"Win32 服务 · System32 二进制（正常）");
		ChangeProbeService();
		CleanProbeService();
	}
	else {
		wprintf(L"未知模式: %s\n", mode);
		wprintf(L"用法: svcprobe [driver|win32|win32bad|change|start <服务名>|clean|all]\n");
		return 2;
	}

	wprintf(L"\n完成。\n");
	return 0;
}
