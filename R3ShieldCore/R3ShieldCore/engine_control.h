#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

class EngineControl {
public:
	explicit EngineControl(const R3ShieldCore::Policy& policy);
	~EngineControl();

	EngineControl(const EngineControl&) = delete;
	EngineControl(EngineControl&&) = delete;
	EngineControl& operator=(const EngineControl&) = delete;
	EngineControl& operator=(EngineControl&&) = delete;

	int HandleNewProcesses();

	// 把各进程投递到环形缓冲的注册表事件落盘，返回写入条数。
	int DrainEvents();

	// 因为缓冲区满而丢弃的事件总数。
	ULONG DroppedEventCount();

	// 注册"旁观者"回调：Drain 时每条事件额外投递一次，用来喂统计聚合。
	void SetEventObserver(void (*observer)(const R3ShieldCore::Event&, void*), void* context);

	// 读询问统计（弹窗发生在 DLL 侧，计数写在共享内存 Policy 块里）。
	void ReadPromptStats(ULONG& shown, ULONG& allowed, ULONG& denied, ULONG& timedOut) const;

	// 读高危规则统计。单独一个接口，不动上面那个已经在用的签名。
	void ReadHighRiskStats(ULONG& asked, ULONG& blocked) const;

	// 运行期切换模式（界面按钮）。只改共享内存 Policy 块的 Mode，
	// 被注入进程下一次判定就生效，不用重启也不用重新注入。
	// 返回 false = DLL 不支持（版本不匹配）或通道没建起来。
	bool SetMode(R3ShieldCore::Mode mode) const;

	//
	// ★ v61：判"**这个进程本身**是不是高危"（伪装系统进程名 / 形近伪装 /
	//   已知攻击工具）。与 `SetMode` 一样走 DLL 导出 —— 引擎 exe **不链接**
	//   lib 的源码，而判据表必须只有一份，所以只能这么拿。
	//
	// 返回值指向 **DLL 里的静态字符串**（引擎进程已把 DLL LoadLibrary 进来，
	// 所以指针有效）。调用方**不得**释放或写入它。没命中返回 nullptr。
	//
	// systemRoot 由调用方传（形如 `C:\Windows`，**不带**尾反斜杠）——
	// 引擎启动时解析一次，取不到就整体停用这个功能并打日志，
	// 比"每个进程各取一次、失败时静默不报"可诊断得多。
	//
	// ⚠️ 加载到旧 DLL（没有这个导出）时恒返回 nullptr，且
	//    `SupportsHighRiskProcessCheck()` 为 false —— 调用方必须先查它，
	//    否则"功能没生效"和"没发现高危进程"会分不清（铁律 97）。
	//
	const char* CheckHighRiskProcess(const wchar_t* imagePath, const wchar_t* systemRoot) const;

	bool SupportsHighRiskProcessCheck() const noexcept
	{
		return pGlobalHookSessionCheckHighRiskProcess != nullptr;
	}

	//
	// ★ v62：ARK「内部退出」需要的两样东西。
	//
	// 为什么不是多此一举（铁律 97：布尔判定不可诊断）：
	//   `LocalEngineDllBase()` 给的是**本引擎加载的那份** DLL 的基址。
	//   远程入口地址 = 目标里的 DLL 基址 + (本地导出地址 - 本地基址)，
	//   所以这个基址就是"偏移"的参照原点 —— 拿错了，偏移就是错的，
	//   而症状会是"远程线程起来了但目标没退"（TimedOut），很难反查。
	//
	//   `SupportsSelfExit()` 单独存在，是因为"加载到旧 DLL"这件事
	//   必须能和"内部退出执行失败"分开报 —— 否则界面上的
	//   "内部退出不可用"会被当成"目标有防护"，而真相是部署包太旧。
	//
	ULONG_PTR LocalEngineDllBase() const noexcept
	{
		return reinterpret_cast<ULONG_PTR>(engineModule.get());
	}

	bool SupportsSelfExit() const noexcept
	{
		return pGlobalHookSessionSelfExit != nullptr;
	}

private:
	using GLOBAL_HOOK_SESSION_START = HANDLE(*)(const R3ShieldCore::Policy* policy);
	using GLOBAL_HOOK_SESSION_HANDLE_NEW_PROCESSES = int(*)(HANDLE hSession);
	using GLOBAL_HOOK_SESSION_DRAIN_EVENTS = int(*)(HANDLE hSession);
	using GLOBAL_HOOK_SESSION_DROPPED_EVENT_COUNT = ULONG(*)(HANDLE hSession);
	using GLOBAL_HOOK_SESSION_SET_OBSERVER = void(*)(void (*)(const R3ShieldCore::Event&, void*), void*);
	using GLOBAL_HOOK_SESSION_READ_PROMPT_STATS = void(*)(ULONG*, ULONG*, ULONG*, ULONG*);
	using GLOBAL_HOOK_SESSION_READ_HIGH_RISK_STATS = void(*)(ULONG*, ULONG*);
	using GLOBAL_HOOK_SESSION_END = BOOL(*)(HANDLE hSession);
	using GLOBAL_HOOK_SESSION_SET_MODE = BOOL(*)(ULONG mode);
	using GLOBAL_HOOK_SESSION_CHECK_HIGH_RISK_PROCESS =
		const char*(*)(const wchar_t* imagePath, const wchar_t* systemRoot);
	// ★ v62：ARK 内部退出的远程入口（`void()` —— ExitProcess 不返回）。
	using GLOBAL_HOOK_SESSION_SELF_EXIT = void(*)();

	wil::unique_hmodule engineModule;
	GLOBAL_HOOK_SESSION_START pGlobalHookSessionStart;
	GLOBAL_HOOK_SESSION_HANDLE_NEW_PROCESSES pGlobalHookSessionHandleNewProcesses;
	GLOBAL_HOOK_SESSION_DRAIN_EVENTS pGlobalHookSessionDrainEvents;
	GLOBAL_HOOK_SESSION_DROPPED_EVENT_COUNT pGlobalHookSessionDroppedEventCount;
	GLOBAL_HOOK_SESSION_SET_OBSERVER pGlobalHookSessionSetObserver;
	GLOBAL_HOOK_SESSION_READ_PROMPT_STATS pGlobalHookSessionReadPromptStats;
	GLOBAL_HOOK_SESSION_READ_HIGH_RISK_STATS pGlobalHookSessionReadHighRiskStats;
	GLOBAL_HOOK_SESSION_END pGlobalHookSessionEnd;
	GLOBAL_HOOK_SESSION_SET_MODE pGlobalHookSessionSetMode;
	GLOBAL_HOOK_SESSION_CHECK_HIGH_RISK_PROCESS pGlobalHookSessionCheckHighRiskProcess = nullptr;
	GLOBAL_HOOK_SESSION_SELF_EXIT pGlobalHookSessionSelfExit = nullptr;
	HANDLE hGlobalHookSession;
};
