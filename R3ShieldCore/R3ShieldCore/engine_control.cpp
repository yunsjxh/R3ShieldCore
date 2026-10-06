#include "stdafx.h"
#include "engine_control.h"

namespace
{
	//
	// ★ v57：**已删除**「部署目录必须不可写」这道门。
	//
	//   原来这里有一条硬门槛（判据在 `engine_deploy_acl.h`）：
	//
	//       if (!IsProtectedEngineDeployment(engineLibraryPath)) {
	//           throw std::runtime_error(
	//               "Refusing to load an engine DLL from a user-writable deployment directory");
	//       }
	//
	//   它挡的是"低权限进程替换 DLL / exe，借管理员启动提权"。但代价太大：
	//   加固要用 `icacls` 把整个目录（含 `r3shieldcore.ini`）锁成 `Users:(RX)`，
	//   于是**用户改不了自己的配置** —— 而 ini 头部明明写着"改完保存"。
	//
	//   实测对比：Windows Defender 的 `C:\ProgramData\Microsoft\Windows Defender`
	//   也是 `BUILTIN\Users:(RX)`，形状和我们的加固一样。区别在**锁是谁给的** ——
	//   它是安装位置/OS 免费给的，不需要用户手动跑脚本。
	//   ⇒ 结论：锁没错，"用脚本锁 + 锁到配置文件"才是错的。
	//
	//   取舍（2026-10-05 产品决策）：本工具是**用户态可见性工具**，
	//   部署在可控环境；配置可写带来的便利 > 目录可写带来的风险。
	//   引擎自己的 `self_protect`（NtOpenProcess 剥权限）仍在，
	//   但它护不了"加载之前"那一步 —— 这是**明确接受的**边界。
	//
	//   ★ `engine_deploy_acl.h` 与 `tools/deploy_acl_probe.exe` 保留：
	//     它们现在只是**独立的自查工具**（想知道目录是否对外开放写权限时跑一下），
	//     不再参与启动决策。

	bool EngineDllExists(const std::filesystem::path& directory)
	{
		const auto libraryPath = directory / L"r3shieldcore-lib.dll";
		return GetFileAttributesW(libraryPath.c_str()) != INVALID_FILE_ATTRIBUTES;
	}

	std::filesystem::path GetEnginePath()
	{
		// Use current architecture.
#ifdef _WIN64
		USHORT machine = IMAGE_FILE_MACHINE_AMD64;
#else // !_WIN64
		USHORT machine = IMAGE_FILE_MACHINE_I386;
#endif // _WIN64

		PCWSTR folderName;
		switch (machine) {
		case IMAGE_FILE_MACHINE_I386:
			folderName = L"32";
			break;

		case IMAGE_FILE_MACHINE_AMD64:
			folderName = L"64";
			break;

		default:
			throw std::logic_error("Unknown architecture");
	}

		const std::filesystem::path modulePath = wil::GetModuleFileName<std::wstring>();
		const std::filesystem::path moduleDirectory = modulePath.parent_path();

		// Packaged layout: <package>\\Release\\<arch>\\r3shieldcore-lib.dll.
		// This is the preferred location because its ACL is protected by the
		// release packaging step.
		const std::filesystem::path adjacent = moduleDirectory / folderName;
		if (EngineDllExists(adjacent)) {
			return adjacent;
		}

		// Visual Studio puts the demo executable under a project-specific output
		// directory, while the protected DLL is copied to the sibling package
		// Release directory. Walk a few ancestors so both build output layouts
		// can use the same protected engine without weakening the ACL check.
		std::filesystem::path ancestor = moduleDirectory;
		for (int depth = 0; depth < 5; ++depth) {
			const std::filesystem::path packaged = ancestor / L"Release" / folderName;
			if (EngineDllExists(packaged)) {
				return packaged;
			}

			const std::filesystem::path parent = ancestor.parent_path();
			if (parent == ancestor || parent.empty()) {
				break;
			}
			ancestor = parent;
		}

		// Preserve the primary path in the error message when neither layout
		// contains the engine DLL.
		return adjacent;
	}
}

EngineControl::EngineControl(const R3ShieldCore::Policy& policy)
	{
		auto engineLibraryPath = GetEnginePath() / L"r3shieldcore-lib.dll";
		const DWORD engineAttributes = GetFileAttributesW(engineLibraryPath.c_str());
		if (engineAttributes == INVALID_FILE_ATTRIBUTES) {
			throw std::runtime_error("Engine DLL not found beside the executable or in the packaged Release directory");
		}
		// ★ v57：这里原来还有一道 `IsProtectedEngineDeployment` 门禁（见文件头注释）。
		//   已删除 —— 部署目录可写不再拒绝启动。

		engineModule.reset(LoadLibrary(engineLibraryPath.c_str()));
	THROW_LAST_ERROR_IF_NULL(engineModule);

	pGlobalHookSessionStart = reinterpret_cast<GLOBAL_HOOK_SESSION_START>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionStart"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionStart);

	pGlobalHookSessionHandleNewProcesses = reinterpret_cast<GLOBAL_HOOK_SESSION_HANDLE_NEW_PROCESSES>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionHandleNewProcesses"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionHandleNewProcesses);

	pGlobalHookSessionDrainEvents = reinterpret_cast<GLOBAL_HOOK_SESSION_DRAIN_EVENTS>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionDrainEvents"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionDrainEvents);

	pGlobalHookSessionDroppedEventCount = reinterpret_cast<GLOBAL_HOOK_SESSION_DROPPED_EVENT_COUNT>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionDroppedEventCount"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionDroppedEventCount);

	pGlobalHookSessionSetObserver = reinterpret_cast<GLOBAL_HOOK_SESSION_SET_OBSERVER>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionSetObserver"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionSetObserver);

	pGlobalHookSessionReadPromptStats = reinterpret_cast<GLOBAL_HOOK_SESSION_READ_PROMPT_STATS>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionReadPromptStats"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionReadPromptStats);

	pGlobalHookSessionReadHighRiskStats = reinterpret_cast<GLOBAL_HOOK_SESSION_READ_HIGH_RISK_STATS>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionReadHighRiskStats"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionReadHighRiskStats);

	pGlobalHookSessionEnd = reinterpret_cast<GLOBAL_HOOK_SESSION_END>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionEnd"));
	THROW_LAST_ERROR_IF_NULL(pGlobalHookSessionEnd);

	// 运行期切模式。**故意不 THROW** —— 这个导出是后加的（ABI v9 之后），
	// 万一加载到的是旧 DLL，缺的只是"点按钮切模式"这一个功能，
	// 不该让整个引擎起不来。SetMode() 返回 false，界面照旧显示但切不动。
	pGlobalHookSessionSetMode = reinterpret_cast<GLOBAL_HOOK_SESSION_SET_MODE>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionSetMode"));

	// ★ v61：高危进程判定导出。同样**故意不 THROW**（同上理由）。
	// 调用方**必须**先查 `SupportsHighRiskProcessCheck()` —— 否则
	// "旧 DLL ⇒ 功能没生效"与"新 DLL 但没发现高危进程"会分不清，
	// 表现为"界面上那个数字一直是 0，看不出是坏了还是真干净"（铁律 97）。
	pGlobalHookSessionCheckHighRiskProcess =
		reinterpret_cast<GLOBAL_HOOK_SESSION_CHECK_HIGH_RISK_PROCESS>(
			GetProcAddress(engineModule.get(), "GlobalHookSessionCheckHighRiskProcess"));

	// ★ v62：ARK 内部退出的远程入口。同样**故意不 THROW**（同上理由）——
	// 缺的只是"内部退出"这一个动作，界面会退化成"只能强制结束"，
	// 不该让整个引擎起不来。`SupportsSelfExit()` 负责把这件事报出来。
	pGlobalHookSessionSelfExit = reinterpret_cast<GLOBAL_HOOK_SESSION_SELF_EXIT>(
		GetProcAddress(engineModule.get(), "GlobalHookSessionSelfExit"));

	// 共享内存必须在第一次注入之前建好，被注入的进程才打得开通道。
	hGlobalHookSession = pGlobalHookSessionStart(&policy);
	if (!hGlobalHookSession) {
		throw std::runtime_error("Failed to start the global hooking session");
	}
}

EngineControl::~EngineControl()
{
	pGlobalHookSessionEnd(hGlobalHookSession);
}

int EngineControl::HandleNewProcesses()
{
	return pGlobalHookSessionHandleNewProcesses(hGlobalHookSession);
}

int EngineControl::DrainEvents()
{
	return pGlobalHookSessionDrainEvents(hGlobalHookSession);
}

ULONG EngineControl::DroppedEventCount()
{
	return pGlobalHookSessionDroppedEventCount(hGlobalHookSession);
}

void EngineControl::SetEventObserver(void (*observer)(const R3ShieldCore::Event&, void*), void* context)
{
	pGlobalHookSessionSetObserver(observer, context);
}

void EngineControl::ReadPromptStats(ULONG& shown, ULONG& allowed, ULONG& denied, ULONG& timedOut) const
{
	shown = allowed = denied = timedOut = 0;
	pGlobalHookSessionReadPromptStats(&shown, &allowed, &denied, &timedOut);
}

void EngineControl::ReadHighRiskStats(ULONG& asked, ULONG& blocked) const
{
	asked = blocked = 0;
	pGlobalHookSessionReadHighRiskStats(&asked, &blocked);
}

bool EngineControl::SetMode(R3ShieldCore::Mode mode) const
{
	if (!pGlobalHookSessionSetMode) {
		return false;
	}

	return pGlobalHookSessionSetMode(static_cast<ULONG>(mode)) != FALSE;
}

const char* EngineControl::CheckHighRiskProcess(
	const wchar_t* imagePath, const wchar_t* systemRoot) const
{
	if (!pGlobalHookSessionCheckHighRiskProcess) {
		return nullptr;
	}

	return pGlobalHookSessionCheckHighRiskProcess(imagePath, systemRoot);
}
