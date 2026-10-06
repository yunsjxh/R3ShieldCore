#include "stdafx.h"
#include "customization_session.h"
#include "session_private_namespace.h"
#include "inject_policy.h"
#include "functions.h"
#include "r3shieldcore_channel.h"
#include "registry_guard.h"
#include "file_guard.h"
#include "process_guard.h"
#include "driver_guard.h"
#include "network_guard.h"
#include "camera_guard.h"
#include "input_hook_guard.h"
#include "screen_guard.h"
#include "dll_load_guard.h"
#include "clipboard_guard.h"
#include "spawn_guard.h"
#include "service_config_guard.h"
#include "com_hijack_guard.h"
#include "scheduled_task_guard.h"
#include "token_theft_guard.h"
#include "wmi_subscription_guard.h"
#include "host_hijack_guard.h"
#include "r3shieldcore_prompt.h"
#include "logger.h"

extern HINSTANCE g_hDllInst;

namespace
{
	//
	// 模板原本在这里挂 MessageBoxW 做演示。现在换成注册表 + 文件 +
	// 进程/线程 + 驱动 + 网络 + 摄像头/音频 + 输入钩子 + 截屏 + DLL加载 +
	// 剪贴板 + 进程创建旁路 + 服务权限 + COM劫持 + 计划任务 +
	// 令牌窃取 + WMI订阅 + 宿主劫持 共十七类行为拦截：
	// 由 RegistryGuard 自行判断本进程是否属于"系统程序"，是则一个 hook 都不挂。
	//
	// 顺序不能换：其余 guard 都直接读 RegistryGuard::IsBypassed() 的结果
	// 来决定自己要不要挂 —— 两边判的是同一件事，分开算会引入不一致。
	//
	MH_STATUS InitCustomizationHooks(HANDLE sessionManagerProcess)
	{
		// RegistryGuard opens the policy/event channel and establishes the
		// bypass decision used by the remaining guards. If that IPC setup fails,
		// continuing with the other hooks would turn a diagnostics failure into
		// unexplained access-denied results in the host process.
		if (!RegistryGuard::Install(sessionManagerProcess)) {
			LOG(L"R3ShieldCore: 共享通道不可用，本进程跳过全部 Hook");
			return MH_ERROR_MEMORY_ALLOC;
		}

		bool allInstalled = true;
#define INSTALL_GUARD(name) \
		do { \
			if (!name::Install(sessionManagerProcess)) { \
				LOG(L"%S: Hook 安装失败，本进程不启用不完整的防护会话", #name); \
				allInstalled = false; \
			} \
		} while (false)
		INSTALL_GUARD(FileGuard);
		INSTALL_GUARD(ProcessGuard);
		INSTALL_GUARD(DriverGuard);
		INSTALL_GUARD(NetworkGuard);
		INSTALL_GUARD(CameraGuard);
		INSTALL_GUARD(InputHookGuard);
		INSTALL_GUARD(ScreenGuard);
		INSTALL_GUARD(DllLoadGuard);
		INSTALL_GUARD(ClipboardGuard);
		INSTALL_GUARD(SpawnGuard);
		INSTALL_GUARD(ServiceConfigGuard);
		INSTALL_GUARD(ComHijackGuard);
		INSTALL_GUARD(ScheduledTaskGuard);
		INSTALL_GUARD(TokenTheftGuard);
		INSTALL_GUARD(WmiSubscriptionGuard);
		// ⚠️ HostHijackGuard 必须排在 RegistryGuard 之后 —— 它自己虽不挂
		//    NtSetValueKey，但依赖 RegistryGuard 已挂并会回调它。
		INSTALL_GUARD(HostHijackGuard);
#undef INSTALL_GUARD
		return allInstalled ? MH_OK : MH_ERROR_MEMORY_ALLOC;
	}
}

bool CustomizationSession::Start(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	auto instance = new (std::nothrow) CustomizationSession();
	if (!instance) {
		LOG(L"Allocation of CustomizationSession failed");
		return false;
	}

	if (!instance->StartAllocated(runningFromAPC, sessionManagerProcess, sessionMutex)) {
		delete instance;
		return false;
	}

	// Instance will free itself.
	return true;
}

bool CustomizationSession::StartAllocated(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	// Create the session semaphore. This will block the library if another instance
	// (from another session manager process) is already injected and its customization session is active.
	WCHAR szSemaphoreName[sizeof("CustomizationSessionSemaphore-pid=1234567890")];
	swprintf_s(szSemaphoreName, L"CustomizationSessionSemaphore-pid=%u", GetCurrentProcessId());

	//
	// ★★★ v48：**先探测"本进程是否已有活动会话"，有就立刻退出，绝不阻塞。**
	//
	//   原来的写法是 `create(1, 1, name)` + `acquire()`。名字按 **pid** 命名
	//   ⇒ 同一个进程被**注入两次**时，第二次的 `create` 拿到的是**同一个**
	//   信号量对象（计数已被第一次拿走 ⇒ 0），`acquire()` **永久阻塞**。
	//
	//   为什么这是灾难而不是"排队等一下"：
	//     · 第二次注入如果走的是 **APC 路**（`DllInject` 在 `hThreadForAPC !=
	//       nullptr` 时把 shellcode 投到**目标主线程**），那这次 `InjectInit`
	//       就**跑在主线程上** ⇒ 主线程卡在 `acquire()` ⇒ **`main` 永远进不去**。
	//     · 现象 = **窗口一片空白、进程常驻、日志里该 pid 只有一条
	//       「DLL ALLOW LoadLibrary」**（第二次注入的 LoadLibrary —— 第一次
	//       装钩子时那次不会被自己记录）。
	//     · 真机实测：`sync_inject_probe.exe` 双击后正是这个样子。
	//
	//   而"等另一个引擎的会话结束"这个原始意图在本项目里**根本不成立**：
	//     · 会话是按 pid 命名的，同 pid 只可能是**同一个引擎**（或同一引擎的
	//       两条注入路）重复注入 —— 没有"另一个引擎"要等；
	//     · 就算真有第二个引擎，等它退出也等于把自己吊死（它会活到系统关机）。
	//   所以正确语义是 **fail-fast**：先来的会话继续跑，后来的这次注入放弃。
	//   调用方（shellcode → `InjectInit`）拿到 FALSE 就正常返回，
	//   APC 随即结束、主线程继续往下跑 —— 不会再出现空白窗口。
	//
	//   ⚠️ 用 `OpenSemaphoreW` 显式探测，**不能**用 `create()` 之后的
	//      `GetLastError()`：`wil::unique_semaphore_nothrow::create` 内部还会
	//      调别的 API，last-error 不保证是 `ERROR_ALREADY_EXISTS`。
	//
	{
		wil::unique_handle existing(OpenSemaphoreW(SYNCHRONIZE, FALSE, szSemaphoreName));
		if (existing) {
			LOG(L"R3ShieldCore: 本进程已有活动注入会话（信号量 %ls 已存在），"
				L"本次重复注入直接放弃 —— 不阻塞调用线程", szSemaphoreName);
			return false;
		}
	}

	HRESULT hr = m_sessionSemaphore.create(1, 1, szSemaphoreName);
	if (FAILED(hr)) {
		LOG(L"Semaphore creation failed with error %08X", hr);
		return false;
	}

	m_sessionSemaphoreLock = m_sessionSemaphore.acquire();

	if (WaitForSingleObject(sessionManagerProcess, 0) != WAIT_TIMEOUT) {
		VERBOSE(L"Session manager process is no longer running");
		return false;
	}

	if (!InitSession(runningFromAPC, sessionManagerProcess)) {
		return false;
	}

	if (runningFromAPC) {
		// Create a new thread for us to allow the program's main thread to run.
		try {
			// Note: Before creating the thread, the CRT/STL bumps the
			// reference count of the module, something a plain CreateThread
			// doesn't do.
			std::thread thread(&CustomizationSession::RunAndDeleteThis, this,
				sessionManagerProcess, sessionMutex);
			thread.detach();
		}
		catch (const std::exception& e) {
			LOG(L"%S", e.what());
			UninitSession();
			return false;
		}
	}
	else {
		// No need to create a new thread, a dedicated thread was created for us
		// before injection.
		RunAndDeleteThis(sessionManagerProcess, sessionMutex);
	}

	return true;
}

bool CustomizationSession::InitSession(bool runningFromAPC, HANDLE sessionManagerProcess) noexcept
{
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK) {
		LOG(L"MH_Initialize failed with %d", status);
		return false;
	}

	if (runningFromAPC) {
		// No other threads should be running, skip thread freeze.
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_NONE_UNSAFE);
	}
	else {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	//
	// ★★ v42：本进程该走"瘦会话"还是"完整会话"？
	//
	// 判据是**本进程自己的镜像名**（`inject_policy.cpp` 的 `kThinInject[]`）：
	//   `explorer.exe` / `svchost.exe` / `runtimebroker.exe` ⇒ 瘦会话。
	//
	// 为什么用"自己的镜像名"而不是让引擎传一个参数进来：
	//   ① 不用改注入管道的 ABI（`InjectInit` 的签名、shellcode、导出表都不动）；
	//   ② 引擎侧 `ShouldSkipProcessInjection` 与这里读的是**同一张表**，
	//      天然一致 —— 引擎认为该注入的，DLL 必然知道该以什么强度跑。
	//
	// ⚠️ `IsThinInjectAllowed()` 在 Policy 不可用时返回 true（见 functions.cpp）。
	//    瘦会话**本来就不开通道**，所以这里恒为 true —— 是**故意的**：
	//    引擎侧的 Policy 位决定"注不注入"，一旦注进来，就按名单走瘦会话。
	//
	const InjectPolicy::Mode injectionMode =
		InjectPolicy::ClassifyCurrentProcess(IsThinInjectAllowed());

	try {
		m_newProcessInjector.emplace(sessionManagerProcess);
	}
	catch (const std::exception& e) {
		LOG(L"InitSession failed: %S", e.what());
		m_newProcessInjector.reset();
		MH_Uninitialize();
		return false;
	}

	if (injectionMode == InjectPolicy::Mode::Thin) {
		//
		// ★★ 瘦会话：**一个 guard 都不装**，只留 `CreateProcessInternalW`。
		//
		// 这样做的收益与代价：
		//   · 收益：本进程拉起的**子进程**能走同步注入路（强制
		//     `CREATE_SUSPENDED` → 注入 → `ResumeThread`），子进程在
		//     **跑第一行代码之前** hook 就装好了 ⇒ 盲区 ≈ 0。
		//     这是"双击运行一个启动即写 MBR 的样本"唯一能赢的办法。
		//   · 代价：**本进程自己不受监控** —— 不拦文件、不拦注册表、
		//     不拦网络。这是**故意的**：`explorer.exe` 的文件 I/O 极高频
		//     （每开一个目录、每张缩略图、每次拖放），全量 hook 在
		//     `block_all` 下必炸；DLL 里任何 bug 都会让**桌面**死掉。
		//     瘦会话在行为上等价于"没被注入"。
		//
		// ⚠️ 正因为不装 guard，这里**不能**调 `InitCustomizationHooks` ——
		//    它第一步就是 `RegistryGuard::Install`（开共享通道 + 定 bypass），
		//    后面 16 个 guard 全依赖它的结论。瘦会话跳过它是完整一致的。
		//
		// ★★★ v49：但**必须只读挂载 Policy**（不挂 Events 通道）。
		//
		//   本进程装的 `CreateProcessInternalW`（`new_process_injector.cpp`）在
		//   注入前会调 `ShouldSkipProcessInjection`，而 `IsUserNeverInject`
		//   要读 Policy 才知道用户的 `never_inject=` 名单。
		//
		//   不挂 Policy 的后果：用户**双击**启动的程序，父进程是 `explorer.exe`
		//   = 瘦会话 ⇒ `R3ShieldCoreChannel::Policy()` 为 nullptr ⇒ 免注入名单
		//   **恒不生效** ⇒ 名单形同虚设。而"双击"恰恰是最典型的启动方式。
		//   （v42 起瘦会话从不碰通道，这个洞一直存在，v49 才补上。）
		//
		// ⚠️ `OpenPolicyOnly` **不会**让 `IsOpen()` 变 true —— 瘦会话不是
		//    "受监控进程"，只是**读**一下策略决定要不要注入别人。
		{
			const DWORD policyEnginePid =
				sessionManagerProcess ? GetProcessId(sessionManagerProcess) : 0;
			if (!R3ShieldCoreChannel::OpenPolicyOnly(policyEnginePid)) {
				// 读不到策略不算致命：瘦会话的核心职责（让子进程走同步注入路）
				// 不依赖它，只是 `never_inject=` 名单会失效 ⇒ 记一条日志。
				LOG(L"R3ShieldCore: 瘦会话无法只读挂载 Policy（err=%u）—— "
					L"never_inject= 名单在本进程拉起的子进程上不生效",
					GetLastError());
			}
		}

		WCHAR hostImage[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, hostImage, _countof(hostImage));

		LOG(L"R3ShieldCore: **瘦会话**（只装 CreateProcessInternalW，不装任何 guard）host=%ls "
			L"—— 目的：让本进程拉起的子进程走同步注入路（盲区≈0）",
			hostImage);
	}
	else if (injectionMode == InjectPolicy::Mode::Skip) {
		//
		// ★★★ v53：本进程按策略属于「绝不注入」（例如 VMware Tools）。
		//
		// 正常路径下引擎**根本不会**注入它 —— `ShouldSkipProcessInjection`
		// 在两条注入路（轮询 / 同步）上都会拦住。走到这里只有一种可能：
		// **竞态** —— 轮询注入器碰上"进程刚起、镜像路径还查不到"的瞬间，
		// `QueryFullProcessImageNameW` 失败，而 `ShouldSkipProcessInjection`
		// 在那种情况下是 **fail-open**（见 functions.cpp：查不到路径 ⇒ 照常注入）。
		// 此刻 DLL 已经进了进程，唯一正确的做法是**什么都不装**、让调用方
		// 卸载它 —— 行为上等价于"从没被注入过"。
		//
		// ⚠️ 绝不能落进下面的 `else`（完整会话）：那会装上剪贴板 hook，
		//    把 VMware Tools 的共享剪贴板掐死 —— 而共享剪贴板正是
		//    "病毒毁了系统后把日志带出去"的**唯一通道**（本次要修的就是这个）。
		//
		WCHAR skipHostImage[MAX_PATH] = {};
		GetModuleFileNameW(nullptr, skipHostImage, _countof(skipHostImage));
		LOG(L"R3ShieldCore: 本进程按策略属于「绝不注入」(Skip)，不装任何 hook host=%ls "
			L"—— 竞态注入，已放弃本会话", skipHostImage);

		m_newProcessInjector.reset();
		MH_Uninitialize();
		return false;
	}
	else {
		status = InitCustomizationHooks(sessionManagerProcess);
		if (status != MH_OK) {
			LOG(L"InitCustomizationHooks failed with %d", status);
			m_newProcessInjector.reset();
			MH_Uninitialize();
			return false;
		}
	}

	status = MH_ApplyQueued();
	if (status != MH_OK) {
		LOG(L"MH_ApplyQueued failed with %d", status);
		// Do not report a live session while the queue is only partially active.
		// The caller will unload the DLL after this rollback completes.
		MH_DisableHook(MH_ALL_HOOKS);
		m_newProcessInjector.reset();
		MH_Uninitialize();
		return false;
	}

	if (runningFromAPC) {
		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);
	}

	return true;
}

void CustomizationSession::RunAndDeleteThis(HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept
{
	m_sessionManagerProcess.reset(sessionManagerProcess);

	if (sessionMutex) {
		m_sessionMutex.reset(sessionMutex);
	}

	// Prevent the system from displaying the critical-error-handler message box.
	// A message box like this was appearing while trying to load a dll in a
	// process with the ProcessSignaturePolicy mitigation, and it looked like this:
	// https://stackoverflow.com/q/38367847
	DWORD dwOldMode;
	SetThreadErrorMode(SEM_FAILCRITICALERRORS, &dwOldMode);

	Run();

	SetThreadErrorMode(dwOldMode, nullptr);

	delete this;
}

void CustomizationSession::Run() noexcept
{
	DWORD waitResult = WaitForSingleObject(m_sessionManagerProcess.get(), INFINITE);
	if (waitResult != WAIT_OBJECT_0) {
		LOG(L"WaitForSingleObject returned %u, last error %u", waitResult, GetLastError());
	}

	VERBOSE(L"Uninitializing and freeing library");

	UninitSession();
}

void CustomizationSession::UninitSession() noexcept
{
	// 顺序很关键，一步都不能换。
	//
	// 之前的写法是直接 MH_Uninitialize()，结果把宿主进程打崩了：
	// 那一步会释放 trampoline，而此刻进程里可能还有线程正卡在 hook 里
	// （ask 模式下甚至停在等用户点按钮上，最长几十秒）。释放后那个线程
	// 返回时就是野指针 —— WER 报 "r3shieldcore-lib.dll_unloaded"，
	// 异常码 c0000005。实测打崩过 MyApp.exe 和 OfficeClickToRun.exe。

	// 1) 让还在等用户答复的 Ask() 立刻收手，别让宿主线程白等满超时。
	R3ShieldCorePrompt::NotifyShutdown();

	// 2) 停用所有 hook：新调用立刻走回原函数，不再进我们的代码。
	MH_STATUS status = MH_DisableHook(MH_ALL_HOOKS);
	if (status != MH_OK && status != MH_ERROR_NOT_INITIALIZED) {
		LOG(L"MH_DisableHook failed with status %d", status);
	}

	// 3) 等在飞的 hook 跑完。
	//    先让一小会：停用之后还可能有一瞬间，某线程正好跨过被改写的前几个
	//    字节跳进 detour，但还没执行到计数递增。
	Sleep(100);
	RegistryGuard::WaitForHooksToDrain(10000);
	FileGuard::WaitForHooksToDrain(10000);
	ProcessGuard::WaitForHooksToDrain(10000);
	DriverGuard::WaitForHooksToDrain(10000);
	NetworkGuard::WaitForHooksToDrain(10000);
	CameraGuard::WaitForHooksToDrain(10000);
	InputHookGuard::WaitForHooksToDrain(10000);
	ScreenGuard::WaitForHooksToDrain(10000);
	DllLoadGuard::WaitForHooksToDrain(10000);
	ClipboardGuard::WaitForHooksToDrain(10000);
	SpawnGuard::WaitForHooksToDrain(10000);
	ServiceConfigGuard::WaitForHooksToDrain(10000);
	ComHijackGuard::WaitForHooksToDrain(10000);
	ScheduledTaskGuard::WaitForHooksToDrain(10000);
	TokenTheftGuard::WaitForHooksToDrain(10000);
	WmiSubscriptionGuard::WaitForHooksToDrain(10000);
	HostHijackGuard::WaitForHooksToDrain(10000);

	// 4) 模板自带的反计数保护，等 CreateProcessInternalW 的在飞调用归零。
	m_newProcessInjector.reset();

	// 5) 现在确认没有任何线程还在本 DLL 的代码里，才能安全释放 trampoline。
	status = MH_Uninitialize();
	if (status != MH_OK) {
		LOG(L"MH_Uninitialize failed with status %d", status);
	}
}
