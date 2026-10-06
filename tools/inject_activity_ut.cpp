//
// inject_activity_ut.cpp - v46「引擎自己在注入」标记的单元测试。
//
// 背景（用户真机实测）：
//   同步注入路 `CreateProcessInternalW_Hook` **跑在调用方进程里**，它 `DllInject`
//   用的 `VirtualAllocEx` / `WriteProcessMemory` / `VirtualProtectEx` /
//   `CreateRemoteThread` 全部**在父进程上下文**执行。父进程若是**全量注入**，
//   它自己就装着这些内存/线程钩子 ⇒ 注入器**自己的**这次跨进程写被自己的规则判成
//   HIGH ⇒ Block 模式下直接拒：
//       PROC BLOCK HIGH WriteVirtualMemory  (pid=1912)   <- 目标就是刚建出来的子进程
//   后果是同步路**静默退化成 10 ms 轮询路**（盲区回来），而不是"子进程被杀"。
//
// 修法 = `inject_activity.h`：线程级 + **按目标 pid 精确匹配**的"注入中"标记，
// 让内存/线程钩子对"正在注入的那个目标"透传。本文件钉住它的语义边界 ——
// 这些边界正是"它会不会变成后门"的关键，改坏任何一条都在这里红：
//
//   ① 默认不生效（没进区间 ⇒ 什么都不放行）；
//   ② 只放行**目标 pid**，别的 pid 一律不放行（最小授权）；
//   ③ `pid == 0` 永远不放行（0 是"取不到目标"的哨兵，不能当匹配）；
//   ④ **线程级** —— A 线程进区间，B 线程必须完全不受影响（这是"别的线程的
//      跨进程写照判"的保证）；
//   ⑤ 可嵌套，退出内层恢复外层；异常展开时也必须恢复；
//   ⑥ 出区间后彻底复原。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#include "inject_activity.h"

static int g_failed = 0;
static int g_total = 0;

static void Check(const char* note, bool got, bool want)
{
	g_total++;
	if (got != want) {
		g_failed++;
		printf("  [FAIL] %-52s got=%s want=%s\n", note, got ? "true" : "false", want ? "true" : "false");
	}
	else {
		printf("  [ ok ] %-52s %s\n", note, got ? "true" : "false");
	}
}

// ------------------------------------------------------------------
// ⑦⑧⑨⑩⑪ v46 **第二次定位**：CreateProcess 窗口
//
//   第一次修法（把放行标记加在 `DllInject` 入口）在真机上**没生效**。抓调用栈
//   才看清：被拦的那次 `NtWriteVirtualMemory` 根本还没轮到 `DllInject` ——
//
//     #0 KERNELBASE!NtWriteVirtualMemory
//     #2 r3shieldcore-lib.dll          <- 我们的钩子
//     #4 KERNELBASE!CreateProcessInternalW   <- 原函数自己
//     #5 KERNEL32!CreateProcessA
//     #6 repro.exe
//
//   `CreateProcessInternalW` 建完进程/线程后**自己**就要往子进程写
//   `RTL_USER_PROCESS_PARAMETERS`（环境块 / 命令行 / 当前目录）—— 走的正是
//   `NtWriteVirtualMemory`。这一次被拦 ⇒ 它回滚（Terminate 子进程）⇒ 返回
//   FALSE、`GetLastError()=5` ⇒ 整条 `CreateProcess` 在**到达 DllInject 之前**
//   就失败了。真机日志同样是这个形状（`r3shieldcore-events.log`）：
//
//     00:33:25.168 PROC ALLOW      CreateProcess        image=...\tasklist.exe (pid=1912)
//     00:33:25.170 PROC ALLOW      AllocateVirtualMemory                        (pid=1912)
//     00:33:25.170 PROC BLOCK HIGH WriteVirtualMemory                            (pid=1912)
//     00:33:25.170 PROC ALLOW      TerminateProcess                            (pid=1912)  <- 回滚
//
//   于是放行窗口上移：`g_createWindowDepth > 0` 表示"本线程此刻正跑在
//   `CreateProcessInternalW` 里"，`g_createdChildPid` 是"本线程在这个窗口里刚建
//   出来的子进程"。下面钉住它的语义边界 —— 这些边界正是"它会不会变成后门"的
//   关键：
//
//   ⑦ 默认关；进入后开；退出后关且子进程 pid 被清；
//   ⑧ `NoteCreatedChild` 的边界：窗口外调用无效（不能从外面开后门）、
//      `pid == 0` 无效、一个窗口内以**第一个**子进程为准（保守）；
//   ⑨ 窗口可嵌套：内层窗口**不继承**外层的子进程 pid，退出内层恢复外层；
//   ⑩ 窗口是**线程局部**的（别的线程看不到）；
//   ⑪ 窗口与 `ScopedTarget` 并存、互不干扰（DllInject 同时用两者）。
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// ④ 线程局部：另起一个线程，断言它看不到主线程的区间；
//    并且它自己设的区间也不能泄漏回主线程。
// ------------------------------------------------------------------
struct ThreadProbe {
	bool	activeInThread;
	bool	seesMainThreadPid;
	unsigned long	threadOwnPid;
	bool	seesThreadOwnPid;
};

// ⑩ 窗口的线程局部性探针。
struct WindowThreadProbe {
	bool	seesMainWindow;
	bool	seesMainChild;
	bool	ownWindow;
	bool	ownChild;
};

static DWORD WINAPI WindowThreadProc(LPVOID param)
{
	WindowThreadProbe* p = static_cast<WindowThreadProbe*>(param);

	// 主线程已进窗口并回报了 8001；本线程必须"既没窗口、也没子进程"。
	p->seesMainWindow = R3ShieldCoreInjectActivity::IsInCreateProcessWindow();
	p->seesMainChild = R3ShieldCoreInjectActivity::IsInjectingInto(8001);

	// 本线程自己开窗口：不得影响主线程。
	{
		R3ShieldCoreInjectActivity::CreateWindowState st =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		p->ownWindow = R3ShieldCoreInjectActivity::IsInCreateProcessWindow();
		R3ShieldCoreInjectActivity::NoteCreatedChild(8002);
		p->ownChild = R3ShieldCoreInjectActivity::IsInjectingInto(8002);
		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(st);
	}

	return 0;
}

static DWORD WINAPI ThreadProc(LPVOID param)
{
	ThreadProbe* p = static_cast<ThreadProbe*>(param);

	// 主线程已进入 scope(3333)；本线程必须是"干净"的。
	p->activeInThread = R3ShieldCoreInjectActivity::IsActive();
	p->seesMainThreadPid = R3ShieldCoreInjectActivity::IsInjectingInto(3333);

	// 本线程自己设一个区间：不得影响主线程。
	{
		R3ShieldCoreInjectActivity::ScopedTarget scoped(4444);
		p->threadOwnPid = 4444;
		p->seesThreadOwnPid = R3ShieldCoreInjectActivity::IsInjectingInto(4444);
	}

	return 0;
}

int main()
{
	setlocale(LC_ALL, "");
	printf("=== inject_activity_ut ===\n\n");

	// ---- ① 默认不生效 ----
	printf("[1] 默认（未进区间）\n");
	Check("IsActive() == false", R3ShieldCoreInjectActivity::IsActive(), false);
	Check("IsInjectingInto(1234) == false", R3ShieldCoreInjectActivity::IsInjectingInto(1234), false);

	// ---- ② / ③ 精确匹配 + pid 0 哨兵 ----
	printf("\n[2] 进入 scope(1234)：只认 1234\n");
	{
		R3ShieldCoreInjectActivity::ScopedTarget scoped(1234);
		Check("IsActive() == true", R3ShieldCoreInjectActivity::IsActive(), true);
		Check("IsInjectingInto(1234) == true", R3ShieldCoreInjectActivity::IsInjectingInto(1234), true);
		Check("IsInjectingInto(1235) == false（别的目标照判）", R3ShieldCoreInjectActivity::IsInjectingInto(1235), false);
		Check("IsInjectingInto(0) == false（哨兵不当匹配）", R3ShieldCoreInjectActivity::IsInjectingInto(0), false);
		Check("IsInjectingInto(1) == false", R3ShieldCoreInjectActivity::IsInjectingInto(1), false);
	}
	printf("\n[3] 出区间后复原\n");
	Check("IsActive() == false", R3ShieldCoreInjectActivity::IsActive(), false);
	Check("IsInjectingInto(1234) == false", R3ShieldCoreInjectActivity::IsInjectingInto(1234), false);

	// ---- ⑤ 可嵌套 ----
	printf("\n[4] 嵌套：内层生效时外层被遮蔽，退出内层后恢复\n");
	{
		R3ShieldCoreInjectActivity::ScopedTarget outer(1111);
		Check("外层: IsInjectingInto(1111) == true", R3ShieldCoreInjectActivity::IsInjectingInto(1111), true);
		{
			R3ShieldCoreInjectActivity::ScopedTarget inner(2222);
			Check("内层: IsInjectingInto(2222) == true", R3ShieldCoreInjectActivity::IsInjectingInto(2222), true);
			Check("内层: IsInjectingInto(1111) == false（被遮蔽）", R3ShieldCoreInjectActivity::IsInjectingInto(1111), false);
		}
		Check("退内层: IsInjectingInto(1111) == true（已恢复）", R3ShieldCoreInjectActivity::IsInjectingInto(1111), true);
		Check("退内层: IsInjectingInto(2222) == false", R3ShieldCoreInjectActivity::IsInjectingInto(2222), false);
	}
	Check("退外层: IsActive() == false", R3ShieldCoreInjectActivity::IsActive(), false);

	// ---- ⑤b 异常展开也必须恢复 ----
	printf("\n[5] 异常展开时恢复（DllInject 里 THROW_* 很常见）\n");
	try {
		R3ShieldCoreInjectActivity::ScopedTarget scoped(5555);
		Check("区间内: IsInjectingInto(5555) == true", R3ShieldCoreInjectActivity::IsInjectingInto(5555), true);
		throw 42;
	}
	catch (...) {
	}
	Check("异常后: IsActive() == false", R3ShieldCoreInjectActivity::IsActive(), false);
	Check("异常后: IsInjectingInto(5555) == false", R3ShieldCoreInjectActivity::IsInjectingInto(5555), false);

	// ---- ④ 线程局部（最关键的一条）----
	printf("\n[6] 线程局部：主线程进 scope(3333)，另一线程必须完全干净\n");
	{
		R3ShieldCoreInjectActivity::ScopedTarget scoped(3333);
		ThreadProbe probe = {};
		HANDLE h = CreateThread(nullptr, 0, ThreadProc, &probe, 0, nullptr);
		if (h) {
			WaitForSingleObject(h, 5000);
			CloseHandle(h);
		}
		Check("另线程: IsActive() == false（看不到主线程的区间）", probe.activeInThread, false);
		Check("另线程: IsInjectingInto(3333) == false", probe.seesMainThreadPid, false);
		Check("另线程: 自己设的 4444 生效", probe.seesThreadOwnPid, true);
		Check("主线程: 未被另线程的 4444 污染", R3ShieldCoreInjectActivity::IsInjectingInto(4444), false);
		Check("主线程: 自己的 3333 仍在", R3ShieldCoreInjectActivity::IsInjectingInto(3333), true);
	}

	// ---- ⑦ 窗口基本语义 ----
	printf("\n[7] CreateProcess 窗口：默认关 / 进入后开 / 退出后关\n");
	Check("默认 IsInCreateProcessWindow() == false", R3ShieldCoreInjectActivity::IsInCreateProcessWindow(), false);
	{
		R3ShieldCoreInjectActivity::CreateWindowState st =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		Check("进入后 IsInCreateProcessWindow() == true", R3ShieldCoreInjectActivity::IsInCreateProcessWindow(), true);
		Check("窗口内未回报子进程: IsInjectingInto(7777) == false",
			R3ShieldCoreInjectActivity::IsInjectingInto(7777), false);

		R3ShieldCoreInjectActivity::NoteCreatedChild(7777);
		Check("回报后 IsInjectingInto(7777) == true", R3ShieldCoreInjectActivity::IsInjectingInto(7777), true);
		Check("回报后 IsInjectingInto(7778) == false（别的 pid 照判）",
			R3ShieldCoreInjectActivity::IsInjectingInto(7778), false);
		Check("回报后 IsInjectingInto(0) == false（哨兵）",
			R3ShieldCoreInjectActivity::IsInjectingInto(0), false);

		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(st);
	}
	Check("退出后 IsInCreateProcessWindow() == false", R3ShieldCoreInjectActivity::IsInCreateProcessWindow(), false);
	Check("退出后 IsInjectingInto(7777) == false（子进程 pid 已清）",
		R3ShieldCoreInjectActivity::IsInjectingInto(7777), false);

	// ---- ⑧ NoteCreatedChild 的边界 ----
	printf("\n[8] NoteCreatedChild 的边界（不能从窗口外开后门）\n");
	R3ShieldCoreInjectActivity::NoteCreatedChild(6666);
	Check("窗口外 NoteCreatedChild(6666) 无效", R3ShieldCoreInjectActivity::IsInjectingInto(6666), false);
	{
		R3ShieldCoreInjectActivity::CreateWindowState st =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		R3ShieldCoreInjectActivity::NoteCreatedChild(0);
		Check("窗口内 NoteCreatedChild(0) 无效（哨兵）",
			R3ShieldCoreInjectActivity::IsInjectingInto(0), false);

		R3ShieldCoreInjectActivity::NoteCreatedChild(6001);
		R3ShieldCoreInjectActivity::NoteCreatedChild(6002);
		Check("一窗多子进程: 以第一个为准 6001", R3ShieldCoreInjectActivity::IsInjectingInto(6001), true);
		Check("一窗多子进程: 第二个 6002 不放行（保守）",
			R3ShieldCoreInjectActivity::IsInjectingInto(6002), false);

		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(st);
	}
	Check("退出后 6001 不放行", R3ShieldCoreInjectActivity::IsInjectingInto(6001), false);

	// ---- ⑨ 窗口嵌套 ----
	printf("\n[9] 窗口嵌套：内层不继承外层的子进程 pid\n");
	{
		R3ShieldCoreInjectActivity::CreateWindowState outer =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		R3ShieldCoreInjectActivity::NoteCreatedChild(5001);
		Check("外层窗口: IsInjectingInto(5001) == true",
			R3ShieldCoreInjectActivity::IsInjectingInto(5001), true);

		R3ShieldCoreInjectActivity::CreateWindowState inner =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		Check("内层窗口: IsInjectingInto(5001) == false（不继承）",
			R3ShieldCoreInjectActivity::IsInjectingInto(5001), false);
		R3ShieldCoreInjectActivity::NoteCreatedChild(5002);
		Check("内层窗口: IsInjectingInto(5002) == true",
			R3ShieldCoreInjectActivity::IsInjectingInto(5002), true);
		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(inner);

		Check("退内层: 外层 5001 恢复", R3ShieldCoreInjectActivity::IsInjectingInto(5001), true);
		Check("退内层: 内层 5002 失效", R3ShieldCoreInjectActivity::IsInjectingInto(5002), false);
		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(outer);
	}
	Check("退外层: IsInCreateProcessWindow() == false",
		R3ShieldCoreInjectActivity::IsInCreateProcessWindow(), false);
	Check("退外层: 5001 失效", R3ShieldCoreInjectActivity::IsInjectingInto(5001), false);

	// ---- ⑩ 窗口的线程局部性 ----
	printf("\n[10] 窗口是线程局部的\n");
	{
		R3ShieldCoreInjectActivity::CreateWindowState st =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		R3ShieldCoreInjectActivity::NoteCreatedChild(8001);
		WindowThreadProbe wp = {};
		HANDLE h = CreateThread(nullptr, 0, WindowThreadProc, &wp, 0, nullptr);
		if (h) {
			WaitForSingleObject(h, 5000);
			CloseHandle(h);
		}
		Check("另线程: 看不到主线程的窗口", wp.seesMainWindow, false);
		Check("另线程: IsInjectingInto(8001) == false", wp.seesMainChild, false);
		Check("另线程: 自己开窗口生效", wp.ownWindow, true);
		Check("另线程: 自己的 8002 生效", wp.ownChild, true);
		Check("主线程: 未被另线程的 8002 污染",
			R3ShieldCoreInjectActivity::IsInjectingInto(8002), false);
		Check("主线程: 自己的 8001 仍在", R3ShieldCoreInjectActivity::IsInjectingInto(8001), true);
		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(st);
	}

	// ---- ⑪ 与 ScopedTarget 并存 ----
	printf("\n[11] 窗口与 ScopedTarget 并存（DllInject 同时用两者）\n");
	{
		R3ShieldCoreInjectActivity::ScopedTarget scoped(9001);
		R3ShieldCoreInjectActivity::CreateWindowState st =
			R3ShieldCoreInjectActivity::EnterCreateProcessWindow();
		R3ShieldCoreInjectActivity::NoteCreatedChild(9002);
		Check("ScopedTarget 的 9001 仍生效", R3ShieldCoreInjectActivity::IsInjectingInto(9001), true);
		Check("窗口的 9002 也生效", R3ShieldCoreInjectActivity::IsInjectingInto(9002), true);
		Check("别的 pid 9003 不放行", R3ShieldCoreInjectActivity::IsInjectingInto(9003), false);
		R3ShieldCoreInjectActivity::LeaveCreateProcessWindow(st);
		Check("关窗后 9002 失效、9001 仍在",
			!R3ShieldCoreInjectActivity::IsInjectingInto(9002) &&
			R3ShieldCoreInjectActivity::IsInjectingInto(9001), true);
	}
	Check("全部退出: IsActive()==false 且窗口关",
		!R3ShieldCoreInjectActivity::IsActive() &&
		!R3ShieldCoreInjectActivity::IsInCreateProcessWindow(), true);

	printf("\n=== %d/%d 通过 ===\n", g_total - g_failed, g_total);
	return g_failed == 0 ? 0 : 1;
}
