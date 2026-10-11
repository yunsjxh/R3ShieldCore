#pragma once
//
// rules_script_runtime.h —— 引擎侧：把「规则脚本文件」装进规则表。
//
// ★ 什么时候加载、加载几次
//   **每个被注入进程各加载一次**（懒加载，首次用到规则时）。理由：
//     ① `DllMain` 里**不能**做文件 I/O（loader lock ⇒ 死锁风险，微软明令），
//        所以不能在 `DLL_PROCESS_ATTACH` 里读；
//     ② 规则是"读进程自己"的事，进程间不共享 —— 不做跨进程广播，
//        用户改完规则**重启引擎**即生效（界面上必须写清这一点）。
//
// ★ 与 `Policy`（共享内存）**无关** ⇒ **`AbiVersion` 不用升**
//   规则文件走的是文件系统，不进 `Policy` 结构体。这一点是刻意的：
//   进共享内存就要动 ABI，而动 ABI 会让"新旧 DLL 混装"变成崩溃而不是降级。
//
// ★ 幂等：`EnsureLoadedOnce()` 内部用 CAS 抢占，**并发下也只加载一次**。
//   重复加载的后果不是"慢"，而是**规则表里出现重复条目**（`LoadFile`
//   是追加语义），`first-match wins` 下看不出来，但 `RemoveAt` 的序号全错。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <r3shieldcore/rules_file.h>
#include <r3shieldcore/rules_codec.h>

namespace R3ShieldCoreRuleScriptRuntime
{
	// 0 = 还没试过；1 = 正在加载（别人抢到了）；2 = 加载完毕（不论成功与否）
	inline volatile LONG g_state = 0;

	inline WCHAR g_path[MAX_PATH] = L"";
	inline volatile LONG g_fileOk = 0;    // 文件打开成功
	inline volatile LONG g_okCount = 0;   // 解析成功的条数
	inline volatile LONG g_badCount = 0;  // 解析失败的条数
	inline volatile LONG g_loads = 0;     // 真跑过几次加载（诊断 / 闸门）

	// 从**指定路径**读。单测与端到端夹具用它把规则指向临时文件 ——
	// 否则单测只能去动真实安装路径（`%ProgramData%\R3 Shield Core\`），
	// 那会污染本机真装的那一份，属于"测试改了用户数据"。
	// ⚠️ 定义必须排在 `LoadNow` **之前**（头文件里没有前向声明）。
	inline bool LoadFrom(const WCHAR* path) noexcept
	{
		if (!path || !*path) { g_fileOk = 0; return false; }
		wcscpy_s(g_path, path);

		// ★ 先清空：本函数可能被反复调用；不清就会**重复追加**
		//   （同一条规则在表里出现两次，first-match wins 下"看不出来"，
		//    但 RemoveAt 的序号全错）。
		R3ShieldCoreRuleScript::Clear();

		int ok = 0;
		int bad = 0;
		std::wstring firstErr;
		const bool read = R3ShieldCoreRuleScript::LoadFile(path, &ok, &bad, firstErr);
		InterlockedExchange(&g_fileOk, read ? 1 : 0);
		InterlockedExchange(&g_okCount, ok);
		InterlockedExchange(&g_badCount, bad);
		InterlockedIncrement(&g_loads);
		return read;
	}

	// 真的去读一次（用**解析出来的**路径）。
	inline bool LoadNow() noexcept
	{
		WCHAR path[MAX_PATH] = {};
		if (!R3ShieldCoreRulesFile::ResolveRulesPath(nullptr, path, _countof(path))) {
			g_fileOk = 0;
			return false;
		}
		return LoadFrom(path);
	}

	// ★ 返回 true ⇒ **本次调用真的执行了加载**（调用方据此打**一次**日志）。
	//   返回 false ⇒ 已经加载过（或别的线程正在加载）—— 不要重复打日志。
	inline bool EnsureLoadedOnce() noexcept
	{
		if (g_state != 0) return false;
		if (InterlockedCompareExchange(&g_state, 1, 0) != 0) return false;
		LoadNow();
		InterlockedExchange(&g_state, 2);
		return true;
	}

	// 同上，但**包住异常**。
	//
	// ★ 为什么必须包：调用方（`registry_guard.cpp` / `clipboard_guard.cpp` 的
	//   `Evaluate` / `RejectOrSpoof`）都是 `noexcept` 的 **hook 热路径**，
	//   而读文件 + 解析规则会分配内存（`std::wstring` / `std::vector` /
	//   `std::wregex`）。真抛出来 = `std::terminate` ⇒ 把**被注入的宿主进程**
	//   整个带走。规则读不进来最多是"没有规则"，绝不能是"宿主崩了"。
	//   （状态机在抛异常后会停在 1 ⇒ 之后永远不再尝试 —— 这是**刻意的**：
	//    失败一次就别在热路径上反复撞同一堵墙。）
	inline bool EnsureLoadedSafe() noexcept
	{
		try {
			return EnsureLoadedOnce();
		}
		catch (...) {
			return false;
		}
	}

	// 强制重读（供"规则改完想立刻生效"的场景；引擎里目前没有调用点，
	// 留着是为了单测能反复换文件 —— 不这么做，单测只能测第一份）。
	inline bool ForceReload() noexcept
	{
		InterlockedExchange(&g_state, 1);
		const bool ok = LoadNow();
		InterlockedExchange(&g_state, 2);
		return ok;
	}

	// 从**指定路径**强制加载，并把状态置成"已加载"。
	// 单测 / 端到端夹具用 —— 否则它们只能去动真实安装路径。
	inline bool ForceLoadFrom(const WCHAR* path) noexcept
	{
		InterlockedExchange(&g_state, 1);
		const bool ok = LoadFrom(path);
		InterlockedExchange(&g_state, 2);
		return ok;
	}

	inline LONG OkCount() noexcept { return g_okCount; }
	inline LONG BadCount() noexcept { return g_badCount; }
	inline LONG Loads() noexcept { return g_loads; }
	inline const WCHAR* Path() noexcept { return g_path; }

	// 单测用：把状态清回"没试过"（**不改规则表本身**）。
	inline void ResetForTest() noexcept
	{
		InterlockedExchange(&g_state, 0);
		InterlockedExchange(&g_loads, 0);
	}
}
