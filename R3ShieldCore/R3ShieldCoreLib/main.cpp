#include "stdafx.h"
#include "all_processes_injector.h"
#include "customization_session.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_log.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_prompt_ui.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

HINSTANCE g_hDllInst;

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason) {
	case DLL_PROCESS_ATTACH:
		g_hDllInst = hinstDLL;

		//
		// 这里【不】用 GET_MODULE_HANDLE_EX_FLAG_PIN 把模块钉住。
		//
		// 钉住确实能避免"模块被卸载时还有线程在 hook 里"的崩溃，但代价是
		// 每个被注入的进程都永久持有这个 DLL —— 文件一直被映射，link.exe
		// 再也没法覆盖它（LNK1104），开发时每改一次代码就得先重启宿主应用。
		//
		// 正确的做法是在 UninitSession 里"停用 hook → 等在飞的跑完 → 才反初始化"，
		// 见 customization_session.cpp。那样可以安全卸载，也不会占住文件。
		//

#ifndef _WIN64
		Wow64ExtInitialize();
#endif // _WIN64
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

// Exported
//
// 全部导出必须是 extern "C"：_exports.def 里写的是未修饰名，
// 而 inject-shellcode 也是用 GetProcAddress(hModule, "InjectInit")
// 按未修饰名找的。C++ 名称修饰会让两边都找不到。
extern "C" BOOL InjectInit(BOOL bRunningFromAPC, HANDLE hSessionManagerProcess, HANDLE hSessionMutex)
{
	VERBOSE(L"Running InjectInit");

	if (!CustomizationSession::Start(bRunningFromAPC, hSessionManagerProcess, hSessionMutex)) {
		return FALSE;
	}

	return TRUE;
}

// Exported
extern "C" HANDLE GlobalHookSessionStart(const R3ShieldCore::Policy* policy)
{
	VERBOSE(L"Running GlobalHookSessionStart");

	// 只有引擎进程把内部日志同时写到 stderr，方便排查启动问题。
	Logger::EnableStderrOutput(true);

	// 共享内存必须在任何注入发生之前建好，否则被注入的进程打不开通道。
	R3ShieldCore::Policy effectivePolicy = {};
	if (policy) {
		effectivePolicy = *policy;
	}
	else {
		effectivePolicy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Log);
	}

	if (!R3ShieldCoreChannel::Create(effectivePolicy)) {
		LOG(L"R3ShieldCore: 共享通道建立失败，停止启动注入会话");
		return nullptr;
	}

	if (effectivePolicy.LogPath[0]) {
		if (!R3ShieldCoreLog::Open(effectivePolicy.LogPath)) {
			LOG(L"R3ShieldCore: 日志文件打开失败，事件只进环形缓冲不会落盘");
		}
	}

	//
	// 询问通道 + 询问 UI 线程：**无条件**建立，不再只在 ASK 模式建。
	//
	// 原来这里有个 `if (Mode == Ask)`，代价是"运行期切到 ASK 却没有 UI 线程" ——
	// 而 `R3ShieldCorePrompt::Ask` 在 UI 线程不存在时会**立刻**返回 fallback(deny)，
	// 表现为"模式写着 ask 却全部拒绝"。同一个坑已经以 canAsk 补丁的形式
	// 在 process / thread / driver 三个 guard 上各踩过一次
	// （见 HANDOVER §10 第 8/11/16 条）—— 根因就在这里。
	//
	// 无条件建的成本只是引擎进程里一个隐藏窗口 + 一小块共享内存，
	// 换掉一整类 bug。模式判定仍然由 Policy->Mode 决定，UI 闲着不会弹任何东西。
	//
	if (R3ShieldCorePrompt::Create() && R3ShieldCorePromptUi::Start()) {
		// Ready for injected processes.
	}
	else {
		LOG(L"R3ShieldCore: 询问通道建立失败，停止启动注入会话");
		R3ShieldCorePromptUi::Stop();
		R3ShieldCorePrompt::Close();
		R3ShieldCoreLog::Close();
		R3ShieldCoreChannel::Close();
		return nullptr;
	}

	try {
		return static_cast<HANDLE>(new AllProcessesInjector());
	}
	catch (const std::exception& e) {
		LOG(L"%S", e.what());
	}

	R3ShieldCorePromptUi::Stop();
	R3ShieldCorePrompt::Close();
	R3ShieldCoreLog::Close();
	R3ShieldCoreChannel::Close();
	return nullptr;
}

// Exported
extern "C" int GlobalHookSessionHandleNewProcesses(HANDLE hSession)
{
	VERBOSE(L"Running GlobalHookSessionHandleNewProcesses");

	auto allProcessInjector = static_cast<AllProcessesInjector*>(hSession);
	return allProcessInjector->InjectIntoNewProcesses();
}

// Exported
extern "C" int GlobalHookSessionDrainEvents(HANDLE /*hSession*/)
{
	return R3ShieldCoreLog::DrainAndWrite();
}

// Exported
extern "C" ULONG GlobalHookSessionDroppedEventCount(HANDLE /*hSession*/)
{
	return R3ShieldCoreChannel::DroppedCount();
}

// Exported
extern "C" void GlobalHookSessionSetObserver(void (*observer)(const R3ShieldCore::Event&, void*), void* context)
{
	R3ShieldCoreChannel::SetObserver(observer, context);
}

// Exported
extern "C" void GlobalHookSessionReadPromptStats(ULONG* shown, ULONG* allowed, ULONG* denied, ULONG* timedOut)
{
	ULONG s = 0, a = 0, d = 0, t = 0;
	R3ShieldCorePromptUi::ReadPromptStats(s, a, d, t);
	if (shown) { *shown = s; }
	if (allowed) { *allowed = a; }
	if (denied) { *denied = d; }
	if (timedOut) { *timedOut = t; }
}

// Exported
//
// 高危规则的运行期计数。单独一个导出而不是扩展 ReadPromptStats ——
// 后者已经在跑了，改签名会把老调用方的栈搅乱。
//
extern "C" void GlobalHookSessionReadHighRiskStats(ULONG* asked, ULONG* blocked)
{
	ULONG a = 0, b = 0;

	// 这两个计数由被注入进程的 hook 侧递增，写在 Events 通道头里
	// （Policy 是只读映射，不能写）。
	R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel();
	if (channel) {
		a = static_cast<ULONG>(InterlockedCompareExchange(&channel->HighRiskAsked, 0, 0));
		b = static_cast<ULONG>(InterlockedCompareExchange(&channel->HighRiskBlocked, 0, 0));
	}

	if (asked) { *asked = a; }
	if (blocked) { *blocked = b; }
}

// Exported
//
// 运行期切换模式（界面上的「切换模式」按钮走这里）。
//
// 只改共享内存 Policy 块里的 `Mode` —— 被注入进程的 hook **每次判定都重新读**
// `policy->Mode`，所以立刻全局生效：不需要重启引擎，也不需要重新注入任何进程。
//
// ⚠️ 为什么在这里写 Policy 不会崩：Policy 是引擎侧 `Create()` 出来的
//    READ|WRITE 映射，**只有引擎进程是合法写入方**。DLL 侧 `Open()` 挂的是
//    FILE_MAP_READ，hook 里写它会 0xC0000005（被 __except 吞成"什么都没发生"，
//    见 HANDOVER §3.1）。这个函数跑在引擎进程里，所以是允许的。
extern "C" BOOL GlobalHookSessionSetMode(ULONG mode)
{
	// 上限必须跟上 Mode 枚举 —— 原来只到 BlockAll，运行期切
	// block_all_safe 会被这里直接拒掉（静默失败，界面点了没反应）。
	if (mode > static_cast<ULONG>(R3ShieldCore::Mode::BlockAllSafe)) {
		return FALSE;
	}

	R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
	if (!policy) {
		return FALSE;
	}

	policy->Mode = mode;

	// 兜底：切到 ASK / 全拦（block_all / block_all_safe）时确保询问通道
	// 和 UI 线程真的在。
	//
	// ⚠️ 为什么全拦模式也要这里兜底：从 v21 起，全拦模式下**进程创建 /
	//    远程线程 / 跨进程内存**不再是"直接拒"，而是"弹窗询问"。
	//    弹窗需要 UI 线程；若此刻 UI 线程不在，R3ShieldCorePrompt::Ask 会
	//    立刻返回 fallback（deny），表现为"全拦模式该问的不问、直接拒"。
	//
	// 正常启动流程里它们已经建好了（上面改成无条件建），这里只覆盖
	// "通道创建失败过 / 旧的启动路径" 这类边角。
	// ⚠️ Create() 内部会先 Close()，所以**只在没打开时才建**，
	//    否则会把正在等待答复的槽一起拆掉。
	const bool needsPrompt =
		mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask) ||
		R3ShieldCore::IsAnyBlockAllMode(mode);

	if (needsPrompt && !R3ShieldCorePrompt::IsOpen()) {
		if (R3ShieldCorePrompt::Create()) {
			R3ShieldCorePromptUi::Start();
		}
	}

	return TRUE;
}

// Exported
//
// ★ v61：高危进程「存在」判定的跨模块入口。
//
// 为什么要有这个导出（**不是**多此一举）：
//   判据表必须只有一份（`r3shieldcore_rules.cpp` 的 `kSystemCriticalImages` /
//   `kMasqueradeExempt` / `kAttackToolNames`），而**引擎 exe 不链接 lib 的源码**
//   （见 build.sh 的 build_demo：只编 R3ShieldCore/*.cpp）。
//   引擎要定期快照全机进程判高危，只能通过 DLL 导出拿到同一份判据 ——
//   否则就得在引擎侧抄一份表，那才是真正的隐患（两份真相必然漂移）。
//
// ⚠️ 返回值指向 DLL 里的**静态字符串**。引擎进程把 DLL LoadLibrary 进来了，
//    所以那个指针在引擎地址空间里有效；调用方**不得**释放或写入它。
//    没命中返回 nullptr。
//
// ⚠️ systemRoot 由**调用方**传（`C:\Windows`，不带尾反斜杠）而不是这里自己取：
//    引擎可以在启动时解析一次并打日志，取不到就整体停用这个功能
//    —— 比"每个进程各取一次、失败时静默不报"可诊断得多（铁律 97）。
extern "C" const char* GlobalHookSessionCheckHighRiskProcess(
	const wchar_t* imagePath, const wchar_t* systemRoot)
{
	return R3ShieldCoreRules::HighRiskProcessReasonForRoot(imagePath, systemRoot);
}

// Exported
//
// v62: ARK "internal exit" remote entry point.
//
// WHY the entry point must live INSIDE our own DLL instead of calling
// kernel32!ExitProcess remotely (which is what the sentinel's rung 4 does):
//
//   A remote thread's start address is `remote module base + export RVA`.
//   For that RVA to be trustworthy we must first LOCATE our DLL inside the
//   target and PROVE it is the same build the engine loaded (PE header
//   TimeDateStamp + SizeOfImage). Anchoring the entry point in our own DLL
//   makes both pieces of evidence fall out naturally; calling kernel32
//   directly gives us nothing to verify against.
//
//   When the DLL is absent or is a different build, `ark_actions` REFUSES
//   (DllNotLoaded / DllMismatch) rather than pointing a thread at a guessed
//   address -- i.e. it never executes unverified code in the target.
//
// SEMANTICS: "run the process's own exit path".
//   ExitProcess terminates the other threads, then runs every DLL's
//   DllMain(DLL_PROCESS_DETACH), then atexit callbacks, then flushes CRT
//   buffers. That is exactly what separates this from ForceKill
//   (TerminateProcess, where the kernel tears the address space down and
//   none of the above runs).
//
// NOTE: declared noreturn via ExitProcess; the void return type is
// deliberate -- the remote thread never comes back.
extern "C" void GlobalHookSessionSelfExit()
{
	ExitProcess(0);
}

// Exported
extern "C" BOOL GlobalHookSessionEnd(HANDLE hSession)
{
	VERBOSE(L"Running GlobalHookSessionEnd");

	// 先把缓冲里剩下的写完，再拆通道。
	R3ShieldCoreLog::DrainAndWrite();
	R3ShieldCoreLog::Close();

	// UI 线程要先停，否则它可能还在往槽里写答复。
	R3ShieldCorePromptUi::Stop();
	R3ShieldCorePrompt::Close();

	R3ShieldCoreChannel::Close();

	auto allProcessInjector = static_cast<AllProcessesInjector*>(hSession);
	delete allProcessInjector;

	return TRUE;
}
