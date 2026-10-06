#include "stdafx.h"
#include "new_process_injector.h"
#include "session_private_namespace.h"
#include "dll_inject.h"
#include "functions.h"
#include "inject_activity.h"
#include "logger.h"

// This static pointer is used in the hook procedure.
// As a result, only one instance of the class can be used at any given time.
NewProcessInjector* volatile NewProcessInjector::pThis;

namespace
{
	bool IsSuperDeskPanelCommandLine(LPCWSTR commandLine) noexcept
	{
		if (!commandLine) {
			return false;
		}

		// The panel is a same-binary child launched on winsta0\Winlogon.
		// Injecting the engine DLL into it can break its secure-desktop
		// message loop and file logging, especially in BLOCK mode.
		constexpr LPCWSTR marker = L"--super-panel";
		constexpr size_t markerLength = _countof(L"--super-panel") - 1;
		for (LPCWSTR cursor = commandLine; *cursor; ++cursor) {
			if (_wcsnicmp(cursor, marker, markerLength) == 0) {
				return true;
			}
		}
		return false;
	}
}

NewProcessInjector::NewProcessInjector(HANDLE hSessionManagerProcess) :
	hSessionManagerProcess(hSessionManagerProcess)
{
	if (_InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(&pThis), this, nullptr)) {
		throw std::logic_error("NewProcessInjector - only one instance is supported at any given time");
	}

	bool createProcessInternalWHooked = false;

	// Try kernelbase.dll first.
	HMODULE hKernelBase = GetModuleHandle(L"kernelbase.dll");
	if (hKernelBase) {
		CreateProcessInternalW_t pCreateProcessInternalW =
			reinterpret_cast<CreateProcessInternalW_t>(GetProcAddress(hKernelBase, "CreateProcessInternalW"));
		if (pCreateProcessInternalW) {
			if (MH_CreateHook(pCreateProcessInternalW, CreateProcessInternalW_Hook,
				reinterpret_cast<void**>(&originalCreateProcessInternalW)) == MH_OK) {
				MH_QueueEnableHook(pCreateProcessInternalW);
				createProcessInternalWHooked = true;
			}
		}
	}

	if (!createProcessInternalWHooked) {
		// Try kernel32.dll next.
		HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
		if (hKernel32) {
			CreateProcessInternalW_t pCreateProcessInternalW =
				reinterpret_cast<CreateProcessInternalW_t>(GetProcAddress(hKernel32, "CreateProcessInternalW"));
			if (pCreateProcessInternalW) {
				if (MH_CreateHook(pCreateProcessInternalW, CreateProcessInternalW_Hook,
					reinterpret_cast<void**>(&originalCreateProcessInternalW)) == MH_OK) {
					MH_QueueEnableHook(pCreateProcessInternalW);
					createProcessInternalWHooked = true;
				}
			}
		}
	}

	if (!createProcessInternalWHooked) {
		LOG(L"Failed to hook CreateProcessInternalW");
	}
}

NewProcessInjector::~NewProcessInjector()
{
	while (nHookProcCallCounter > 0) {
		Sleep(10);
	}

	_InterlockedCompareExchangePointer(reinterpret_cast<void* volatile*>(&pThis), nullptr, this);
}

BOOL WINAPI NewProcessInjector::CreateProcessInternalW_Hook(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	DWORD_PTR unknown)
{
	InterlockedIncrement(&pThis->nHookProcCallCounter);

	// ★★★ v46（第二次定位后的真修法）：打开「CreateProcess 窗口」。
	//
	//   下面这次 `originalCreateProcessInternalW` **自己**就要往刚建出来的子进程
	//   里写进程参数（`RTL_USER_PROCESS_PARAMETERS`：环境块 / 命令行 / 当前目录），
	//   走的是 `NtWriteVirtualMemory`。如果本进程被全量注入，那次写会被我们自己的
	//   钩子判成"跨进程写 = HIGH" ⇒ Block 模式下直接拒 ⇒ 原函数回滚、返回 FALSE、
	//   `GetLastError()=5` —— 于是**根本走不到 `DllInject`**。
	//
	//   实测调用栈（本地复现器）：
	//     #4 KERNELBASE!CreateProcessInternalW   <- 原函数自己
	//     #5 KERNEL32!CreateProcessA
	//     #0 KERNELBASE!NtWriteVirtualMemory     <- 被我们拦下来的那一次
	//
	//   所以放行窗口必须从 `DllInject` **上移**到这里：窗口内由本线程建出来的
	//   子进程（由 process_guard 的进程创建钩子回报 pid）对"跨进程写内存 / 改页
	//   保护 / 建远程线程"一律透传。窗口一关立即失效。详见 inject_activity.h。
	//
	//   ⚠️ 手工 Enter/Leave 配对（不能用 RAII）：本函数体里有 `__try/__finally`，
	//      带析构函数的对象会触发 C2712。CreateWindowState 是 POD，安全。
	R3ShieldCoreInjectActivity::CreateWindowState windowState =
		R3ShieldCoreInjectActivity::EnterCreateProcessWindow();

	BOOL bRet = FALSE;
	DWORD dwError = ERROR_SUCCESS;

	__try {
		DWORD dwNewCreationFlags = dwCreationFlags | CREATE_SUSPENDED;

		bRet = pThis->originalCreateProcessInternalW(			hToken,
			lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwNewCreationFlags,
			lpEnvironment,
			lpCurrentDirectory,
			lpStartupInfo,
			lpProcessInformation,
			unknown
		);

		dwError = GetLastError();

		if (bRet) {
			bool injectionAttempted = false;
			bool injectionSucceeded = false;

			if (IsSuperDeskPanelCommandLine(lpCommandLine)) {
				LOG(L"跳过超级置顶面板注入 pid=%u", lpProcessInformation->dwProcessId);
			}
			else if (ShouldSkipProcessInjection(lpProcessInformation->hProcess)) {
				LOG(L"跳过新建安全进程注入 pid=%u", lpProcessInformation->dwProcessId);
			}
			else {
				injectionAttempted = true;
				injectionSucceeded = HandleCreatedProcess(lpProcessInformation);
			}

			if (injectionAttempted && !injectionSucceeded) {
				// ★ v46：注入失败 ⇒ **不能让一个没被监控的进程跑起来**（那就是盲区）。
				//   子进程此刻是 `CREATE_SUSPENDED`，一条指令都没执行过，
				//   终结它等价于"从未启动"；这也和 `NtCreateUserProcess_Hook`
				//   里"高危 → 趁挂起 TerminateProcess"的策略一致。
				//   不这么做的话，原来的代码会照样 `ResumeThread` ⇒ 进程跑起来
				//   但一个钩子都没装，日志里还看不见 —— 最坏的一种失败。
				TerminateProcess(lpProcessInformation->hProcess, ERROR_DLL_INIT_FAILED);
				CloseHandle(lpProcessInformation->hThread);
				CloseHandle(lpProcessInformation->hProcess);
				*lpProcessInformation = {};
				bRet = FALSE;
				dwError = ERROR_DLL_INIT_FAILED;
				LOG(L"注入失败，已终止新建进程（避免未监控进程运行）");
			}
			else {
				if (!(dwCreationFlags & CREATE_SUSPENDED)) {
					ResumeThread(lpProcessInformation->hThread);
				}

				VERBOSE(L"New process %u from CreateProcessInternalW(\"%s\", \"%s\")",
					lpProcessInformation->dwProcessId,
					lpApplicationName ? lpApplicationName : L"(NULL)",
					lpCommandLine ? lpCommandLine : L"(NULL)");
			}
		}

		SetLastError(dwError);
	}
	__finally {
		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(windowState);
		InterlockedDecrement(&pThis->nHookProcCallCounter);
	}

	return bRet;
}

// 返回值：是否**可以放行**这个子进程。
//   true  —— 注入成功；或另一个线程/进程已经在处理它（互斥体已存在，
//            说明它的注入由那次调用负责），我们不该再动手也不该终结它。
//   false —— 真的注入失败了。调用方必须终结子进程（见 CreateProcessInternalW_Hook）。
bool NewProcessInjector::HandleCreatedProcess(LPPROCESS_INFORMATION lpProcessInformation)
{
	try {
		wil::unique_mutex_nothrow mutex(CreateProcessInitAPCMutex(pThis->hSessionManagerProcess, lpProcessInformation->dwProcessId, FALSE));
		if (GetLastError() == ERROR_ALREADY_EXISTS) {			// Make sure the main thread doesn't begin execution before the
			// APC is queued.
			THROW_LAST_ERROR_IF(WaitForSingleObject(mutex.get(), INFINITE) == WAIT_FAILED);
			ReleaseMutex(mutex.get());
			return true;
		}

		DllInject::DllInject(lpProcessInformation->hProcess, lpProcessInformation->hThread, pThis->hSessionManagerProcess, mutex.get());
		VERBOSE(L"DllInject succeeded for new process %u", lpProcessInformation->dwProcessId);
		return true;
	}
	catch (const std::exception& e) {
		LOG(L"Error for new process %u: %S", lpProcessInformation->dwProcessId, e.what());
		return false;
	}
}

HANDLE NewProcessInjector::CreateProcessInitAPCMutex(HANDLE sessionManagerProcess, DWORD processId, BOOL initialOwner)
{
	DWORD dwSessionManagerProcessId = GetProcessId(sessionManagerProcess);
	THROW_LAST_ERROR_IF(dwSessionManagerProcessId == 0);

	if (dwSessionManagerProcessId != GetCurrentProcessId()) {
		if (!SessionPrivateNamespace::Open(dwSessionManagerProcessId)) {
			THROW_WIN32(ERROR_INVALID_DATA);
		}
	}

	// ★★★ v46：名字必须用 `MakeProcessInitAPCMutexName` 拼 —— 分隔符是 `-`（连字符），
	//   不是 `\`（反斜杠）。
	//
	//   原来这里写的是 `L"\\ProcessInitAPCMutex-pid=%u"`，拼出来是个**对象路径**，
	//   而 `SessionPrivateNamespace::Create()` 从来没有真的创建过私有命名空间
	//   （`BuildBoundaryDescriptor` 是死代码）⇒ `CreateMutex` 每次都返回
	//   `ERROR_PATH_NOT_FOUND(3)` ⇒ `HandleCreatedProcess` 每次都抛异常 ⇒
	//   **同步注入路从来没成功过一次**，子进程被原样 Resume，全靠 10 ms 轮询兜底。
	//
	//   轮询路（`all_processes_injector.cpp`）历史上已经踩过并改成了 `-`，
	//   同步路漏了。详见 session_private_namespace.h。
	WCHAR szMutexName[SessionPrivateNamespace::PrivateNamespaceMaxLen +
		SessionPrivateNamespace::ProcessInitAPCMutexNameExtra] = {};
	if (SessionPrivateNamespace::MakeProcessInitAPCMutexName(szMutexName,
			ARRAYSIZE(szMutexName), dwSessionManagerProcessId, processId) <= 0) {
		THROW_WIN32(ERROR_INVALID_DATA);
	}

	wil::unique_hlocal secDesc = GetSharedObjectSecurityDescriptor();
	THROW_IF_NULL_ALLOC(secDesc.get());

	SECURITY_ATTRIBUTES secAttr = { sizeof(SECURITY_ATTRIBUTES) };
	secAttr.lpSecurityDescriptor = secDesc.get();
	secAttr.bInheritHandle = FALSE;

	wil::unique_mutex_nothrow mutex(CreateMutex(&secAttr, initialOwner, szMutexName));
	THROW_LAST_ERROR_IF_NULL(mutex);

	return mutex.release();
}
