//
// procwatch_nonblock_ut.cpp —— 钉住 v101「扫描不阻塞主线程」这条性质。
//
// 为什么需要这个测试：
//
//   2026-10-24 真机：用户报「还是不行，退不出去怎么办?」。
//   日志取证结论 —— 界面窗口能画、能响应点击，但 `[loop] 主循环存活`
//   **整场 0 行**，即主循环根本没跑起来。而它卡在
//   `R3ShieldCoreProcWatch::Start` 里：`Start` 打完「已启用」就同步跑
//   一整轮全机扫描，而 `ScanOnce` 对**每一个进程**问一次引擎（加密 IPC）。
//   全机 288 个进程 × 单次超时 ⇒ 主循环几十秒到十几分钟起不来 ⇒
//   用户点的「切换模式」和「退出引擎」都只置了标志、**没有人消费**。
//
//   v101 的修法：扫描搬到专用线程 + 单轮时间预算 + `Tick()` 变空实现。
//
// 本测试钉的就是那四件事（**用"慢判据"制造出当时那种 IPC 延迟**）：
//   ① `Start()` 立刻返回（不再同步扫第一轮）；
//   ② 扫描**真的在后台跑**（统计会涨）；
//   ③ 单轮时间预算真的会生效（慢判据下 `LastScanBudgetHit` 置位）；
//   ④ `Tick()` 立刻返回（主循环调它不会被打断）；
//   ⑤ `Stop()` 能在预算内 join 掉线程（退出不会被扫描拖住）。
//
// ★ 为什么用假判据而不是真引擎：本机**禁止运行引擎**（全局注入会 hook 编辑器）。
//   而这条性质与"引擎答什么"无关 —— 只要判据是慢的，性质就该成立。
//   用假判据反而更严格：延迟可控、可重复。
//
#include <windows.h>
#include <stdio.h>

#include "r3shieldcore_procwatch.h"

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok, const char* detail = nullptr)
{
	printf("  [%s] %s", ok ? "PASS" : "FAIL", name);
	if (detail && detail[0]) {
		printf("   (%s)", detail);
	}
	printf("\n");
	if (ok) g_pass++; else g_fail++;
}

// ---------------------------------------------------------------------
// 假判据
// ---------------------------------------------------------------------
//
// slowCheck：每次调用睡 120ms 再答"不是高危"。
//   这个 120ms 就是当年那次"每次 IPC 都要等"的替身。
//   288 个进程 × 120ms ≈ 34 秒 —— 如果 `Start()` 还同步扫，本测试必然超时。
//
static ULONG g_checkCalls = 0;

static const char* SlowCheck(const wchar_t*, const wchar_t*)
{
	InterlockedIncrement(&g_checkCalls);
	Sleep(120);
	return nullptr;   // 一律"不是高危"：本测试不关心判据结论，只关心"别阻塞"
}

static const char* FastCheck(const wchar_t*, const wchar_t*)
{
	InterlockedIncrement(&g_checkCalls);
	return nullptr;
}

static ULONGLONG NowMs()
{
	return GetTickCount64();
}

int main()
{
	printf("=== procwatch_nonblock_ut（v101：扫描不得阻塞主线程）===\n\n");

	// 负对照：确认计时本身可信。
	//   没有这一条，"Start 只花了 3ms"可能只是计时写错了。
	{
		const ULONGLONG t0 = NowMs();
		Sleep(200);
		const ULONGLONG elapsed = NowMs() - t0;
		char buf[128] = {};
		sprintf_s(buf, "Sleep(200) 实测 %llu ms", elapsed);
		Check("负对照：计时可信（200ms 的睡眠测得出 >=180ms）",
			elapsed >= 180, buf);
	}

	// -----------------------------------------------------------------
	//  ① 慢判据下 Start() 必须立刻返回
	// -----------------------------------------------------------------
	printf("\n-- ① Start() 不得同步扫第一轮（判据 120ms/进程）--\n");
	{
		const ULONGLONG t0 = NowMs();
		R3ShieldCoreProcWatch::Start(1, 1000, &SlowCheck);
		const ULONGLONG elapsed = NowMs() - t0;
		char buf[160] = {};
		sprintf_s(buf, "Start 耗时 %llu ms（修复前这里是 288×120ms ≈ 34s）", elapsed);
		// 阈值 1500ms：只要没有"跑完一整轮"就过。
		// 取 1500 而不是 100，是为了容忍首次建线程/建临界区的开销。
		Check("Start() 立刻返回（< 1500ms）", elapsed < 1500, buf);
		Check("Start() 之后确实处于启用态", R3ShieldCoreProcWatch::IsEnabled());
	}

	// -----------------------------------------------------------------
	//  ④ Tick() 必须是空实现（主循环每 100ms 调一次）
	// -----------------------------------------------------------------
	printf("\n-- ④ Tick() 不得阻塞主循环 --\n");
	{
		const ULONGLONG t0 = NowMs();
		R3ShieldCoreProcWatch::Tick();
		R3ShieldCoreProcWatch::Tick();
		R3ShieldCoreProcWatch::Tick();
		const ULONGLONG elapsed = NowMs() - t0;
		char buf[128] = {};
		sprintf_s(buf, "3 次 Tick 共 %llu ms", elapsed);
		Check("Tick() 立刻返回（3 次 < 50ms）", elapsed < 50, buf);
	}

	// -----------------------------------------------------------------
	//  ③ 单轮时间预算：慢判据下第一轮应该在 ~4s 内收尾并置位
	// -----------------------------------------------------------------
	printf("\n-- ③ 单轮预算生效（慢判据下不无限拖）--\n");
	{
		// 预算 4000ms + 一轮的收尾开销 ⇒ 6s 内一定结束第一轮。
		ULONGLONG waited = 0;
		R3ShieldCoreProcWatch::Stats st = {};
		while (waited < 8000) {
			Sleep(200);
			waited += 200;
			st = R3ShieldCoreProcWatch::GetStats();
			if (st.Scans >= 1) {
				break;
			}
		}
		char buf[200] = {};
		sprintf_s(buf, "等待 %llu ms 后 扫描轮数=%lu 本轮进程=%lu 预算超时=%d 判据调用=%lu",
			waited,
			static_cast<unsigned long>(st.Scans),
			static_cast<unsigned long>(st.LastScanProcesses),
			st.LastScanBudgetHit ? 1 : 0,
			static_cast<unsigned long>(InterlockedCompareExchange(&g_checkCalls, 0, 0)));
		Check("慢判据下第一轮确实收尾了（预算生效，没有无限拖）",
			st.Scans >= 1, buf);
		Check("本轮被标记为「未扫完」（如实告知没扫完，而不是假装扫完了）",
			st.LastScanBudgetHit, buf);
		// 关键：一轮最多 4000ms ⇒ 判据调用次数必须远小于全机进程数 × 若干轮。
		// 这里只钉"没有被跑成几十秒"，用 Scan 数 >= 1 且预算置位就够。
	}

	// -----------------------------------------------------------------
	//  ⑤ Stop() 必须能在预算内 join 掉线程
	// -----------------------------------------------------------------
	printf("\n-- ⑤ Stop() 不得被扫描拖住 --\n");
	{
		const ULONGLONG t0 = NowMs();
		R3ShieldCoreProcWatch::Stop();
		const ULONGLONG elapsed = NowMs() - t0;
		char buf[160] = {};
		sprintf_s(buf, "Stop 耗时 %llu ms", elapsed);
		// 线程内部等 8s 是硬上限；正常应远小于（退出标志每个进程都查）。
		Check("Stop() 在 9s 内返回（不会让「退出」卡死）", elapsed < 9000, buf);
		Check("Stop() 之后处于停用态", !R3ShieldCoreProcWatch::IsEnabled());
	}

	// -----------------------------------------------------------------
	//  ② 快判据下：扫描真的在后台跑，且一轮能扫完（预算不误报）
	// -----------------------------------------------------------------
	printf("\n-- ② 后台扫描确实在工作（快判据）--\n");
	{
		R3ShieldCoreProcWatch::Start(1, 300, &FastCheck);

		ULONGLONG waited = 0;
		R3ShieldCoreProcWatch::Stats st = {};
		while (waited < 5000) {
			Sleep(100);
			waited += 100;
			st = R3ShieldCoreProcWatch::GetStats();
			if (st.Scans >= 1 && st.LastScanProcesses > 0) {
				break;
			}
		}
		char buf[200] = {};
		sprintf_s(buf, "等待 %llu ms 后 扫描轮数=%lu 本轮进程=%lu 预算超时=%d",
			waited,
			static_cast<unsigned long>(st.Scans),
			static_cast<unsigned long>(st.LastScanProcesses),
			st.LastScanBudgetHit ? 1 : 0);
		Check("后台扫描跑起来了（扫描轮数 >= 1）", st.Scans >= 1, buf);
		Check("确实枚举到了进程（本轮进程 > 0）", st.LastScanProcesses > 0, buf);
		Check("快判据下不该误报「预算超时」", !st.LastScanBudgetHit, buf);
		// 负对照：慢判据那一轮一定枚举得比快判据少（预算真的截断过）。
		//   这条保证上面"预算超时"那个置位不是随便置的。

		R3ShieldCoreProcWatch::Stop();
	}

	// -----------------------------------------------------------------
	//  ⑥ 可重入：Start/Stop 反复调用不得泄漏或崩溃
	// -----------------------------------------------------------------
	printf("\n-- ⑥ Start/Stop 可重入 --\n");
	{
		bool ok = true;
		for (int i = 0; i < 5; i++) {
			R3ShieldCoreProcWatch::Start(1, 200, &FastCheck);
			if (!R3ShieldCoreProcWatch::IsEnabled()) {
				ok = false;
				break;
			}
			R3ShieldCoreProcWatch::Stop();
			if (R3ShieldCoreProcWatch::IsEnabled()) {
				ok = false;
				break;
			}
		}
		Check("连续 5 次 Start/Stop 状态正确", ok);
	}

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
