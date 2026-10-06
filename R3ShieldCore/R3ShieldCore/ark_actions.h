#pragma once

#include <windows.h>

//
// ★ v62 ARK 动作层 —— 对**任意进程**执行四种处置。
//
// 为什么单独成文件、而且**零依赖**（不 include stdafx、不碰 Policy / 共享内存 /
// wil）：这套动作要能被 `tools/ark_actions_ut.cpp` 独立单测 —— 真的起一个
// 受害进程、真的挂起它、真的让它走内部退出、真的强杀它。
// 判据与动作"能测"是它值得单独成文件的唯一理由（同 inject_policy.cpp 的套路）。
//
// ------------------------------------------------------------------
// 四种动作，按"温和程度"排序
// ------------------------------------------------------------------
//   ① Suspend      挂起：NtSuspendProcess。可恢复，进程状态完整保留。
//   ② Resume       恢复：NtResumeProcess。
//   ③ InternalExit 内部退出：**在目标进程里执行它自己的退出路径** ——
//                  远程线程调用我们注入的那份 DLL 的导出
//                  `GlobalHookSessionSelfExit`，由它去调 `ExitProcess`。
//                  ⇒ 目标会跑完 DllMain(DETACH) / atexit / 缓冲刷新，
//                    而不是被内核直接拆掉地址空间。
//                  为什么不是直接远程调 kernel32!ExitProcess（sentinel 第 ④ 级
//                  用的那招）：那样"跳过去就完事"，**证明不了目标里有没有我们的
//                  DLL**，也证明不了那份 DLL 和本引擎是不是同一份。走自己的导出
//                  天然带上这两条证据（见 QueryRemoteDllBase）。
//   ④ ForceKill    强制结束：TerminateProcess。内核直接拆，目标**跑不到任何清理**。
//                  所以它在界面上要二次确认。
//
// ------------------------------------------------------------------
// 安全边界（**必须**守住，理由都是"一按就蓝屏"）
// ------------------------------------------------------------------
//   · 拒绝动**自己**（引擎进程）—— 自杀式操作没有意义，只会让防护凭空消失。
//   · 拒绝动**关键系统进程**（smss / csrss / wininit / winlogon / services /
//     lsass / lsaiso / fontdrvhost / dwm …）：
//       - 结束它们 = 立即 `CRITICAL_PROCESS_DIED` 蓝屏（它们带 CriticalProcess 标志）；
//       - 挂起它们 = 整机卡死（csrss 管窗口管理、dwm 管合成）。
//     ⇒ 这三个动作一律**拒**，并把原因**原样回报**给界面（不是静默失败）。
//   · 但**普通系统进程**（svchost.exe / explorer.exe / SearchHost.exe …）**允许**处置
//     —— 它们是 %SystemRoot% 下的 Windows 二进制，却既不带 CriticalProcess 标志
//     也不会因被杀而蓝屏。界面把"系统进程"与"关键进程"分成两个字段显示，
//     就是这条边界在 UI 上的体现。
//
// ------------------------------------------------------------------
// 失败必须分型（铁律 97/98）
// ------------------------------------------------------------------
//   "内部退出没成功"有六七种完全不同的成因，全都返回 bool 的话，
//   用户看到的永远只有"失败"两个字，下一步该干什么无从判断：
//     · 目标没被注入（DllNotLoaded）      ⇒ 换"强制结束"
//     · 目标里的 DLL 是旧版（DllMismatch）⇒ 重新部署发布包
//     · 跨位数（UnsupportedWow64）        ⇒ 只能"强制结束"
//     · 权限不足（AccessDenied）          ⇒ 目标可能是 PPL
//     · 线程起了但没退（TimedOut）        ⇒ 目标在退出路径上卡住了
//   ⇒ `Result` 是**枚举**，界面按它给不同提示，日志按它打不同 ASCII 码。
//
namespace ArkActions
{
	enum class Action
	{
		Suspend,
		Resume,
		InternalExit,
		ForceKill,
	};

	enum class Result
	{
		Ok,
		RefusedSelf,          // 目标是本进程（引擎自己）
		RefusedCritical,      // 关键系统进程（结束会蓝屏 / 挂起会卡死）
		ProcessGone,          // 目标已经不在了
		AccessDenied,         // OpenProcess 被拒（PPL / 权限不足）
		UnsupportedWow64,     // 跨位数：64 位引擎无法在 32 位目标里建远程线程
		DllNotLoaded,         // 目标里没有 r3shieldcore-lib.dll（未被注入）
		DllMismatch,          // 目标里的 DLL 与本引擎不是同一份（或读不出 PE 头）
		ExportMissing,        // 本地 DLL 里没有那个导出（旧版 DLL）
		RemoteThreadFailed,   // CreateRemoteThread 失败
		TimedOut,             // 线程起来了，但目标在等待期内没退出
		Failed,               // 其它失败
	};

	struct Outcome
	{
		Result Code = Result::Failed;
		DWORD Win32Error = 0;      // 最后一次相关 Win32 错误（0 = 不适用）
		DWORD ElapsedMs = 0;       // 动作耗时（**只用于展示**，不参与任何判据 —— 铁律 58）
		bool DllPresent = false;   // 目标模块表里有 r3shieldcore-lib.dll
		bool DllSameBuild = false; // 且它与本引擎加载的是同一份构建
	};

	// ------------------------------------------------------------------
	// 纯判据（可单测，不碰系统状态）
	// ------------------------------------------------------------------

	// 文件名是不是"结束就会蓝屏 / 挂起就会卡死"的关键系统进程。
	// 只列**带 CriticalProcess 标志**的那批 + 两个伪进程（System / Idle）。
	bool IsCriticalProcessName(PCWSTR fileName) noexcept;

	// 映像路径是否在 %SystemRoot% 之下（= 界面上说的"系统进程"）。
	// systemRoot 形如 `C:\Windows`（**不带**尾反斜杠）。
	bool IsSystemImagePath(PCWSTR imagePath, PCWSTR systemRoot) noexcept;

	// ------------------------------------------------------------------
	// 远程 DLL 校验
	// ------------------------------------------------------------------

	// 在目标进程的模块表里找 `r3shieldcore-lib.dll`。
	//   localDllBase —— 本进程里**同一份** DLL 的基址（引擎 LoadLibrary 的那份）。
	// 命中后回填 remoteBase，并比对两边的 PE 头（TimeDateStamp + SizeOfImage）
	// 判断是不是同一份构建。
	//
	// ★ 读不出远端 PE 头时 `sameBuild` 一律为 **false**（fail-closed）：
	//   把远程线程的入口设到"没验证过的偏移"上等于在目标里执行任意代码，
	//   宁可拒绝也不能猜。
	bool QueryRemoteDllBase(HANDLE process, ULONG_PTR localDllBase,
		ULONG_PTR* remoteBase, bool* sameBuild, DWORD* win32Error) noexcept;

	// ------------------------------------------------------------------
	// 执行
	// ------------------------------------------------------------------

	// 执行一个动作。selfPid 用来拒绝"动自己"；localDllBase 供内部退出用
	// （传 0 时内部退出必然返回 ExportMissing）。
	Outcome Perform(DWORD pid, Action action, DWORD selfPid, ULONG_PTR localDllBase) noexcept;

	// 文本。ResultText = 界面用的中文说明；ResultCode = 日志用的 ASCII 码
	// （r3shieldcore-console.log 是 GBK，ASCII 码能直接 grep）；ActionText = 中文动作名。
	PCWSTR ResultText(Result result) noexcept;
	const char* ResultCode(Result result) noexcept;
	PCWSTR ActionText(Action action) noexcept;
}
