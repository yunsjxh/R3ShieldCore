#pragma once

// =====================================================================
// 「当前线程正在把引擎 DLL 注入到 targetPid 这个进程里」—— 线程级标记。
//
// 为什么需要它（v46，真机实测）：
//
//   同步注入路（`NewProcessInjector::CreateProcessInternalW_Hook`）**跑在调用方
//   进程里**：它 `CREATE_SUSPENDED` 建子进程，再调 `DllInject`，由
//   `VirtualAllocEx` / `WriteProcessMemory` / `VirtualProtectEx` /
//   `CreateRemoteThread` **在父进程的上下文里**完成注入。
//
//   如果父进程本身是**全量注入**的（`cmd.exe` / 浏览器 / IDE / 办公软件 …），
//   它自己就装着 `NtAllocateVirtualMemory` / `NtWriteVirtualMemory` /
//   `NtProtectVirtualMemory` / `NtCreateThreadEx` 的钩子 ⇒ 注入器**自己的**这次
//   跨进程写会被自己的规则判成 HIGH（"跨进程写内存 = 注入"）⇒ 在 Block 模式下
//   **直接拒**（`EvaluateMemoryOp` 里 `!allowAsk` 那条）。
//
//   真机铁证（`r3shieldcore-events.log`，相隔 3 ms）：
//     PROC ALLOW      CreateProcess        image=...\tasklist.exe  (pid=1912)
//     PROC ALLOW      AllocateVirtualMemory                          (pid=1912)
//     PROC BLOCK HIGH WriteVirtualMemory                            (pid=1912)   <- 自己拦自己
//
//   后果**不是**"子进程被杀"（钩子失败后调用方照样 `ResumeThread`），而是这条
//   同步路**静默退化成 10 ms 轮询路** —— 盲区回来了，而横幅还在宣称"盲区≈0"。
//
// ---------------------------------------------------------------------
// ★★★ v46 第二次定位：真正先被打中的**不是** DllInject，是 kernelbase 自己
//
//   第一次修法（把放行标记加在 `DllInject` 入口）在真机上**没生效**。用本地
//   复现器抓调用栈才看清：被拦的那次 `NtWriteVirtualMemory` 根本还没轮到
//   `DllInject` ——
//
//     #0 KERNELBASE!NtWriteVirtualMemory
//     #1 KERNELBASE
//     #2 r3shieldcore-lib.dll   <- 我们的钩子
//     #3 KERNELBASE
//     #4 KERNELBASE!CreateProcessInternalW   <- 原函数自己
//     #5 KERNEL32!CreateProcessA
//     #6 repro.exe
//
//   `CreateProcessInternalW` 建完进程/线程后，**自己**就要往子进程里写
//   `RTL_USER_PROCESS_PARAMETERS`（环境块、命令行、当前目录）—— 走的正是
//   `NtWriteVirtualMemory`。这一次被拦 ⇒ 它回滚（Terminate 子进程）⇒ 返回
//   **FALSE、`GetLastError()=5`**，`bRet=0 childPid=0`。整条 `CreateProcess`
//   在**到达 DllInject 之前**就失败了 ⇒ 标记加在 DllInject 里当然救不了。
//
//   所以放行窗口必须**上移**：从"DllInject 那一段"扩到"整个
//   `CreateProcessInternalW` 调用期间"，并且判据不能只看"我正在注入谁"，
//   还要看"**本线程在这个窗口里刚建出来的是谁**"—— 因为那一刻
//   `DllInject` 还没被调用、`g_injectTargetPid` 还是 0。
//
// ---------------------------------------------------------------------
// 设计要点（为什么这样写才是安全的，而不是开了个后门）：
//
//   1. **线程级**，不是进程级。注入跑在"调用 `CreateProcess` 的那个线程"上；
//      同一进程里**别的线程**的跨进程写必须继续被判定。
//   2. **按目标 pid 精确匹配**，不是"一刀切放行"。只放行"写进我此刻正在注入的
//      那个子进程"（`g_injectTargetPid`）**或**"写进本线程在这个 CreateProcess
//      窗口里刚建出来的那个子进程"（`g_createdChildPid`）的操作；同一线程去写
//      **别的**进程照样判。最小授权。
//   3. **窗口极窄**：`g_createWindowDepth > 0` 只覆盖 `CreateProcessInternalW`
//      那一次调用（含它内部全部工作），函数一返回窗口即关、子进程 pid 即清。
//      不是"进程启动后一段时间内都放行"。
//   4. **不进导出表**（`_exports.def` 没加这几项）⇒ 外部进程无法打开这个开关。
//      进程内的攻击者本来就能直接 patch MinHook 跳板，这里不降低门槛。
//   5. **POD + `__declspec(thread)`**，不注册 TLS 析构回调 —— 钩子可能在进程
//      收尾（DLL 卸载 / TLS 销毁）阶段执行，依赖 TLS 析构会崩。
//   6. **可嵌套**：`ScopedTarget` / `EnterCreateProcessWindow` 都保存旧值、退出
//      时恢复，注入链里套注入也正确。
//
// 用法：
//   · 同步路：`new_process_injector.cpp` 的 `CreateProcessInternalW_Hook` 在调
//     原函数**前后**夹一对 `Enter/LeaveCreateProcessWindow()`。
//   · 子进程回报：`process_guard.cpp` 的 `NtCreateUserProcess_Hook` /
//     `NtCreateProcessEx_Hook` 拿到新进程句柄后调 `NoteCreatedChild(pid)`。
//   · 轮询路：`DllInject` 入口放一个 `ScopedTarget`，覆盖分配/写/改保护/建线程。
// =====================================================================

namespace R3ShieldCoreInjectActivity {

namespace detail {
	// 当前线程正在注入的目标进程 pid；0 = 不在注入区间内。
	// inline 变量 ⇒ 所有翻译单元共享同一个 TLS 槽（C++17 起）。
	inline __declspec(thread) unsigned long g_injectTargetPid = 0;

	// 本线程在**当前 CreateProcess 窗口内**建出来的子进程 pid；0 = 还没建。
	// 由进程创建钩子（NtCreateUserProcess / NtCreateProcessEx）回报。
	inline __declspec(thread) unsigned long g_createdChildPid = 0;

	// CreateProcess 窗口深度；>0 = 本线程此刻正跑在 CreateProcessInternalW 里。
	// 用深度而非 bool，支持"注入器自己在注入过程里又起一个进程"的嵌套。
	inline __declspec(thread) int g_createWindowDepth = 0;
}

// 当前线程是否正在注入 targetPid。
//
// 两个来源，取并集：
//   A. `g_injectTargetPid` —— `DllInject` 已进入，明确知道在注入谁。
//   B. `g_createdChildPid` —— 还在 `CreateProcessInternalW` 内部，原函数自己
//      正往刚建出来的子进程写进程参数；此刻 A 尚未设立，只能靠 B。
//
// targetPid == 0 永远返回 false —— 0 是"取不到目标"的哨兵，不能当成匹配。
inline bool IsInjectingInto(unsigned long targetPid) noexcept
{
	if (targetPid == 0) {
		return false;
	}
	if (detail::g_injectTargetPid == targetPid) {
		return true;
	}
	return detail::g_createWindowDepth > 0 && detail::g_createdChildPid == targetPid;
}

// 当前线程是否在注入区间内（不关心目标）。仅用于日志/诊断。
inline bool IsActive() noexcept
{
	return detail::g_injectTargetPid != 0;
}

// 当前线程是否处于 CreateProcess 窗口内。仅用于日志/诊断。
inline bool IsInCreateProcessWindow() noexcept
{
	return detail::g_createWindowDepth > 0;
}

// 由进程创建钩子回报"本线程刚建出来的子进程 pid"。
//
// 只在 CreateProcess 窗口内、且本窗口内还没记过时才生效：
//   · 不在窗口内 ⇒ 这不是"注入器起子进程"，是普通进程创建，不记（保持最小授权）。
//   · 已记过 ⇒ 一个窗口内建多个进程时以**第一个**为准（保守：宁可少放行）。
//   · childPid == 0 ⇒ 取不到 pid，不记（0 是哨兵）。
inline void NoteCreatedChild(unsigned long childPid) noexcept
{
	if (detail::g_createWindowDepth <= 0 || childPid == 0) {
		return;
	}
	if (detail::g_createdChildPid == 0) {
		detail::g_createdChildPid = childPid;
	}
}

// CreateProcess 窗口的进入/退出。
//
// ⚠️ 手工 Enter/Leave 配对，**不是** RAII —— 调用点（钩子函数）里有
//    `__try/__finally`，在那个函数里放带析构函数的对象会触发 C2712
//    （"无法在要求对象展开的函数中使用 __try"）。所以状态由调用方持有。
struct CreateWindowState
{
	unsigned long previousChildPid;
	int previousDepth;
};

inline CreateWindowState EnterCreateProcessWindow() noexcept
{
	CreateWindowState state = { detail::g_createdChildPid, detail::g_createWindowDepth };
	// 新窗口从"还没建子进程"开始；嵌套时也重置，避免把外层窗口的
	// 子进程 pid 误用到内层（内层窗口内的写只应放行内层建的那个）。
	detail::g_createdChildPid = 0;
	detail::g_createWindowDepth = state.previousDepth + 1;
	return state;
}

inline void LeaveCreateProcessWindow(const CreateWindowState& state) noexcept
{
	detail::g_createWindowDepth = state.previousDepth;
	detail::g_createdChildPid = state.previousChildPid;
}

// RAII：进入注入区间；析构时恢复上一个值（可嵌套）。
class ScopedTarget
{
public:
	explicit ScopedTarget(unsigned long targetPid) noexcept
		: previous_(detail::g_injectTargetPid)
	{
		detail::g_injectTargetPid = targetPid;
	}

	~ScopedTarget() noexcept
	{
		detail::g_injectTargetPid = previous_;
	}

	ScopedTarget(const ScopedTarget&) = delete;
	ScopedTarget& operator=(const ScopedTarget&) = delete;

private:
	unsigned long previous_;
};

} // namespace R3ShieldCoreInjectActivity
