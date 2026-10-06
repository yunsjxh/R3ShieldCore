// v12probe.cpp —— 触发 v12 新增的两条持久化路径，供 R3ShieldCore 引擎观测。
//
// 用法：
//   v12probe.exe com      → CoCreateInstance 一个"CLSID 指向用户可写目录"的 COM 服务器
//                           （应被 ComHijackGuard 捕获）
//   v12probe.exe comreg   → 往 HKCU\Software\Classes\CLSID 写一个假 CLSID 再激活
//                           （自建劫持，完整复现攻击链）
//   v12probe.exe task     → 注册一个计划任务（应被 ScheduledTaskGuard 捕获）
//   v12probe.exe taskrun  → 注册后立即运行（Run 判据）
//   v12probe.exe svcacl   → 按名称改服务 ACL（SetNamedSecurityInfoW 旁路，v12 补强）
//   v12probe.exe dbg      → 只打印，不触发（对照）
//
// 为什么单独做成工具：验证必须"从被监控进程内部"动作。
// 把本 exe 放到**非 System32** 目录下运行（会被注入），再看引擎日志。
//
// ⚠️ 本工具只做"无害演示"：CLSID 是随机生成的、指向一个不存在的 DLL，
//    计划任务用当前用户权限、动作是无害的 cmd /c echo。它只用来证明
//    "这条路径被引擎看到了"，不真的落地任何东西。
//
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <taskschd.h>
#include <oleauto.h>
#include <accctrl.h>   // SE_SERVICE / SE_OBJECT_TYPE
#include <aclapi.h>    // SetNamedSecurityInfoW

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "advapi32.lib")

static int DoCom()
{
	printf("[v12probe] 路径 A：CoCreateInstance（CLSID 指向上不存在的用户目录 DLL）...\n");

	// 先造一个假 CLSID 注册项，把 InprocServer32 指向**临时目录**里的
	// 一个不存在 DLL —— 这正是典型的 COM 劫持形态（用户可写目录）。
	// ComHijackGuard 的判据是"服务器路径落在用户可写目录"，与 DLL 是否存在无关。
	GUID guid;
	HRESULT hr = CoCreateGuid(&guid);
	if (FAILED(hr)) {
		printf("  CoCreateGuid 失败 hr=0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	WCHAR clsid[64] = {};
	swprintf_s(clsid, L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	WCHAR tempPath[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, tempPath);
	WCHAR dllPath[MAX_PATH] = {};
	swprintf_s(dllPath, L"%sv12probe_hijack.dll", tempPath);

	WCHAR subKey[256] = {};
	swprintf_s(subKey, L"Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);

	HKEY key = nullptr;
	if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
		RegSetValueExW(key, nullptr, 0, REG_SZ,
			reinterpret_cast<const BYTE*>(dllPath),
			static_cast<DWORD>((wcslen(dllPath) + 1) * sizeof(WCHAR)));
		RegCloseKey(key);
		printf("  已写劫持注册项：HKCU\\%ls -> %ls\n", subKey, dllPath);
	} else {
		printf("  写注册项失败 err=%lu（不影响后续激活尝试）\n", GetLastError());
	}

	// 激活它 —— 这一步应被 ComHijackGuard 捕获（判据落在路径）。
	CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
	IUnknown* unknown = nullptr;
	CLSID target = guid;
	SetLastError(0);
	hr = CoCreateInstance(target, nullptr, CLSCTX_INPROC_SERVER, IID_IUnknown,
		reinterpret_cast<void**>(&unknown));
	printf("  CoCreateInstance = 0x%08lX（DLL 不存在，失败是预期的）\n", (unsigned long)hr);
	if (unknown) { unknown->Release(); }
	CoUninitialize();

	// 收拾：把演示用的劫持注册项删掉，别留在机器上。
	HKEY classesRoot = nullptr;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_ALL_ACCESS, &classesRoot) == ERROR_SUCCESS) {
		RegDeleteTreeW(classesRoot, clsid);
		RegCloseKey(classesRoot);
		printf("  已清理演示注册项\n");
	}

	return 0;
}

static int DoTask()
{
	printf("[v12probe] 路径 B：RegisterTaskDefinition（注册无害计划任务）...\n");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
		printf("  CoInitializeEx 失败 hr=0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	ITaskService* service = nullptr;
	hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
		IID_ITaskService, reinterpret_cast<void**>(&service));
	if (FAILED(hr)) {
		printf("  CoCreateInstance(TaskScheduler) 失败 hr=0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	VARIANT empty;
	VariantInit(&empty);
	hr = service->Connect(empty, empty, empty, empty);
	if (FAILED(hr)) {
		printf("  ITaskService::Connect 失败 hr=0x%08lX\n", (unsigned long)hr);
		service->Release();
		return 1;
	}

	ITaskFolder* root = nullptr;
	BSTR rootPath = SysAllocString(L"\\");
	hr = service->GetFolder(rootPath, &root);
	SysFreeString(rootPath);
	if (FAILED(hr) || !root) {
		printf("  GetFolder 失败 hr=0x%08lX\n", (unsigned long)hr);
		service->Release();
		return 1;
	}
	printf("  拿到根任务目录\n");

	// 建一个"无害"任务：动作 = cmd /c echo r3shieldcore-v12。
	ITaskDefinition* def = nullptr;
	hr = service->NewTask(0, &def);
	if (FAILED(hr)) {
		printf("  NewTask 失败 hr=0x%08lX\n", (unsigned long)hr);
		root->Release(); service->Release();
		return 1;
	}

	// 注册 —— 这一步应被 ScheduledTaskGuard 捕获（slot 17）。
	BSTR taskName = SysAllocString(L"R3ShieldCoreV12ProbeTask");
	VARIANT empty2;
	VariantInit(&empty2);
	ITaskFolder* dummyFolder = nullptr;

	// 先填一个动作（否则注册会因"无动作"失败）。
	IActionCollection* actions = nullptr;
	if (SUCCEEDED(def->get_Actions(&actions)) && actions) {
		IAction* action = nullptr;
		if (SUCCEEDED(actions->Create(TASK_ACTION_EXEC, &action)) && action) {
			IExecAction* exec = nullptr;
			if (SUCCEEDED(action->QueryInterface(IID_IExecAction, reinterpret_cast<void**>(&exec))) && exec) {
				BSTR exe = SysAllocString(L"C:\\Windows\\System32\\cmd.exe");
				BSTR args = SysAllocString(L"/c echo r3shieldcore-v12-probe");
				exec->put_Path(exe);
				exec->put_Arguments(args);
				SysFreeString(exe);
				SysFreeString(args);
				printf("  已设动作：cmd.exe /c echo r3shieldcore-v12-probe\n");
				exec->Release();
			}
			action->Release();
		}
		actions->Release();
	}

	IRegisteredTask* registered = nullptr;
	SetLastError(0);
	hr = root->RegisterTaskDefinition(taskName, def, TASK_CREATE_OR_UPDATE,
		empty2, empty2, TASK_LOGON_INTERACTIVE_TOKEN, empty2, &registered);
	printf("  RegisterTaskDefinition = 0x%08lX\n", (unsigned long)hr);

	if (SUCCEEDED(hr) && registered) {
		// 顺手跑一次 —— 触发 Run 判据。
		VARIANT empty3;
		VariantInit(&empty3);
		IRunningTask* running = nullptr;
		HRESULT runHr = registered->Run(empty3, &running);
		printf("  IRunningTask::Run = 0x%08lX（Run 判据）\n", (unsigned long)runHr);
		if (running) { running->Release(); }
		registered->Release();

		// 清理：删掉演示任务。
		root->DeleteTask(taskName, 0);
		printf("  已清理演示任务\n");
	} else {
		printf("  （注册未成功 —— 若引擎处于 BLOCK/ASK 模式，这就是被拦了）\n");
	}

	SysFreeString(taskName);

	if (dummyFolder) { dummyFolder->Release(); }
	def->Release();
	root->Release();
	service->Release();
	CoUninitialize();
	return 0;
}

static int DoServiceAcl()
{
	printf("[v12probe] 路径 C：SetNamedSecurityInfoW（按名称改服务 ACL，v12 补强）...\n");

	// 目标用一个**当前用户有权限改**的服务名（这里用 DHCP 做只读探测，
	// 真要改会因权限不足失败 —— 但 hook 在**调用前**就判定并上报了，
	// 所以哪怕最终失败，引擎日志里也该出现一条）。
	WCHAR serviceName[256] = {};
	// 先枚举一个系统服务名，避免硬编码。
	SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!scm) {
		printf("  OpenSCManager 失败 err=%lu（未提权是正常的）\n", GetLastError());
		return 1;
	}

	ENUM_SERVICE_STATUS_PROCESSW* status = nullptr;
	DWORD bytesNeeded = 0, count = 0, resume = 0;
	if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
		nullptr, 0, &bytesNeeded, &count, &resume, nullptr) == FALSE
		&& GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0) {
		status = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(LocalAlloc(LPTR, bytesNeeded));
		if (status && EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
			reinterpret_cast<LPBYTE>(status), bytesNeeded, &bytesNeeded, &count, &resume, nullptr)) {
			wcsncpy_s(serviceName, status[0].lpServiceName, _TRUNCATE);
		}
		if (status) { LocalFree(status); }
	}
	CloseServiceHandle(scm);

	if (!serviceName[0]) {
		printf("  没枚举到服务名，跳过\n");
		return 1;
	}
	printf("  目标服务：%ls\n", serviceName);

	// 构造一个空 DACL（= 完全放开）的安全描述符。
	// ⚠️ 关键：直接调 SetNamedSecurityInfoW（sc sdset 走的路径），
	//    而不是 SetServiceObjectSecurity —— 后者才是我们 v11 唯一挂着的那个。
	SECURITY_DESCRIPTOR sd = {};
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	ACL acl = {};
	InitializeAcl(&acl, sizeof(acl), ACL_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, &acl, FALSE);

	SetLastError(0);
	DWORD result = SetNamedSecurityInfoW(serviceName, SE_SERVICE,
		DACL_SECURITY_INFORMATION, nullptr, nullptr, &acl, nullptr);
	printf("  SetNamedSecurityInfoW(SE_SERVICE) = %lu  err=%lu\n", result, GetLastError());
	printf("  （err=5 说明 SCM 拒绝 —— 但 hook 在调用前就上报了；\n");
	printf("    err=87/123 说明参数/名称问题；只要能走到这里就证明 API 被调用）\n");

	return 0;
}

static int DoDump(const char* argv0)
{
	(void)argv0;
	printf("[v12probe] 自检：ITaskFolder vtable 的关键槽位指向哪个模块？\n");
	printf("          （patch 成功 → 槽位指向 r3shieldcore-lib.dll；未 patch → taskschd.dll）\n\n");

	HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	(void)hr;

	ITaskService* service = nullptr;
	hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
		IID_ITaskService, reinterpret_cast<void**>(&service));
	if (FAILED(hr)) {
		printf("  CoCreateInstance 失败 hr=0x%08lX\n", (unsigned long)hr);
		return 1;
	}

	VARIANT empty;
	VariantInit(&empty);
	if (FAILED(service->Connect(empty, empty, empty, empty))) {
		printf("  Connect 失败\n");
		service->Release();
		return 1;
	}

	BSTR rootPath = SysAllocString(L"\\");
	ITaskFolder* root = nullptr;
	hr = service->GetFolder(rootPath, &root);
	SysFreeString(rootPath);
	if (FAILED(hr) || !root) {
		printf("  GetFolder 失败 hr=0x%08lX\n", (unsigned long)hr);
		service->Release();
		return 1;
	}

	void** folderVt = *reinterpret_cast<void***>(root);
	printf("  ITaskFolder vtable = %p\n", folderVt);

	const int slots[] = { 9, 11, 17 };
	const char* names[] = { "GetFolder(9)", "CreateFolder(11)", "RegisterTaskDefinition(17)" };
	for (int i = 0; i < 3; i++) {
		void* target = folderVt[slots[i]];
		HMODULE owner = nullptr;
		char ownerName[MAX_PATH] = "(未知)";
		if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
			| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(target), &owner) && owner) {
			GetModuleFileNameA(owner, ownerName, MAX_PATH);
			const char* slash = strrchr(ownerName, '\\');
			if (slash) { memmove(ownerName, slash + 1, strlen(slash) + 1); }
		}
		printf("  slot %2d %-28s -> %p  归属=%s\n", slots[i], names[i], target, ownerName);
	}

	root->Release();
	service->Release();
	CoUninitialize();
	return 0;
}

int main(int argc, char** argv)
{
	const char* mode = (argc > 1) ? argv[1] : "dbg";

	// ⚠️ 必须等注入完成。
	//
	//    引擎是"发现新进程 → 远程线程注入 DLL"的模型，有两个延迟：
	//      ① 轮询发现新进程（~百毫秒级）
	//      ② 注入 + DLL 初始化 + 各 guard Install
	//    如果探针在 main 里立刻调目标 API，**注入还没落地**，
	//    guard 的 hook/vtable patch 都没装 → 引擎什么也看不到
	//    （这是实测踩到的坑：第一次跑 task 路径时任务注册成功、
	//      引擎日志里一条 TASK 事件都没有）。
	//
	//    等 3 秒是给足余量；用 dbg 模式可以对照"不等"的行为。
	if (_stricmp(mode, "dbg") != 0 && _stricmp(mode, "nouwait") != 0) {
		printf("[v12probe] 等待 3s 让引擎完成注入与 guard 安装...\n");
		Sleep(3000);
	}

	if (_stricmp(mode, "com") == 0 || _stricmp(mode, "comreg") == 0) {
		return DoCom();
	}
	if (_stricmp(mode, "task") == 0 || _stricmp(mode, "taskrun") == 0) {
		return DoTask();
	}
	if (_stricmp(mode, "svcacl") == 0) {
		return DoServiceAcl();
	}
	if (_stricmp(mode, "dump") == 0) {
		return DoDump(argv[0]);
	}

	printf("v12probe —— 触发 v12 新增的持久化路径\n\n");
	printf("  com      CoCreateInstance（自建 HKCU CLSID 劫持 → 激活）\n");
	printf("  task     注册 + 运行计划任务\n");
	printf("  svcacl   SetNamedSecurityInfoW 按名称改服务 ACL（v12 补强）\n");
	printf("  dump     自检 ITaskFolder vtable 关键槽位归属（诊断 vtable patch）\n");
	printf("  dbg      只打印（对照）\n\n");
	printf("用法：把本 exe 放到非 System32 目录下运行，然后看引擎日志。\n");
	return 0;
}
