//
// wmcloseprobe.cpp — 窗口消息攻击探针。
//
// 目的：验证"任务管理器「进程 / 应用」页的结束任务"这条路径能不能把引擎窗口弄没。
//       那条路径走的是**友好关闭**：给主窗口发 WM_CLOSE（不是 TerminateProcess），
//       而 WM_CLOSE 是窗口消息，不需要进程句柄 → NtOpenProcess 的保护 hook 不在链路上。
//       同理还有 PostThreadMessage(WM_QUIT) —— 能让消息循环退出、窗口消失（进程仍在）。
//
// 用法: wmcloseprobe.exe [className] [outFile]
//   默认 className = R3ShieldCoreMainWindow
//
// 判读：
//   WM_CLOSE 后  visible=1 且 iconic=1  → 窗口过程把它**最小化**了，没被关掉  ✅
//   WM_CLOSE 后  visible=0             → 被隐藏了（旧行为，用户会误以为引擎已关）
//   WM_QUIT  后  窗口仍存在            → 消息循环吞掉了 WM_QUIT              ✅
//   任何一步后  进程不存在             → 窗口消息真能杀掉进程（不该发生）
//
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

static FILE* g_out = nullptr;

static void Emit(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	if (g_out) {
		va_start(ap, fmt);
		vfprintf(g_out, fmt, ap);
		fflush(g_out);
	}
}

static bool ProcessAlive(DWORD pid)
{
	HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!h) return false;
	DWORD code = 0;
	bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
	CloseHandle(h);
	return alive;
}

static void Report(const char* stage, HWND hwnd, DWORD pid)
{
	if (!hwnd || !IsWindow(hwnd)) {
		Emit("  [%s] 窗口已不存在  |  进程 %s\n", stage,
			ProcessAlive(pid) ? "仍在运行" : "已退出");
		return;
	}
	Emit("  [%s] hwnd=%p  visible=%d  iconic=%d  |  进程 %s\n",
		stage, reinterpret_cast<void*>(hwnd),
		IsWindowVisible(hwnd) ? 1 : 0,
		IsIconic(hwnd) ? 1 : 0,
		ProcessAlive(pid) ? "仍在运行" : "已退出");
}

int main(int argc, char** argv)
{
	const char* className = (argc > 1 && argv[1][0]) ? argv[1] : "R3ShieldCoreMainWindow";
	if (argc > 2 && argv[2][0]) {
		g_out = fopen(argv[2], "w");
	}

	Emit("wmcloseprobe pid=%u\n", GetCurrentProcessId());
	Emit("目标窗口类: %s\n\n", className);

	HWND hwnd = FindWindowA(className, nullptr);
	if (!hwnd) {
		Emit("找不到窗口（类名 %s）。引擎没在跑？\n", className);
		if (g_out) fclose(g_out);
		return 1;
	}

	DWORD pid = 0;
	DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
	Emit("找到窗口 hwnd=%p  pid=%u  tid=%u\n\n", reinterpret_cast<void*>(hwnd), pid, tid);
	Report("初始", hwnd, pid);

	// ---- 1. 模拟任务管理器「进程/应用」页的结束任务：发 WM_CLOSE ----
	Emit("\n[1] PostMessage(WM_CLOSE) —— 任务管理器进程页的友好关闭\n");
	PostMessageA(hwnd, WM_CLOSE, 0, 0);
	Sleep(800);
	Report("WM_CLOSE 后", hwnd, pid);

	// ---- 2. 同步版 SendMessage(WM_CLOSE) ----
	Emit("\n[2] SendMessage(WM_CLOSE) —— 同步版\n");
	SendMessageA(hwnd, WM_CLOSE, 0, 0);
	Sleep(300);
	Report("SendMessage 后", hwnd, pid);

	// ---- 3. PostThreadMessage(WM_QUIT)：让消息循环退出 ----
	Emit("\n[3] PostThreadMessage(WM_QUIT) —— 让 GUI 线程的消息循环退出\n");
	if (!PostThreadMessageA(tid, WM_QUIT, 0, 0)) {
		Emit("  PostThreadMessage 失败 err=%u\n", GetLastError());
	}
	Sleep(800);
	Report("WM_QUIT 后", hwnd, pid);

	// ---- 4. 最后再用 WM_CLOSE 确认窗口还能响应 ----
	Emit("\n[4] 再发一次 WM_CLOSE（确认窗口过程还活着）\n");
	PostMessageA(hwnd, WM_CLOSE, 0, 0);
	Sleep(500);
	Report("二次 WM_CLOSE 后", hwnd, pid);

	Emit("\n完成。\n");
	if (g_out) fclose(g_out);
	return 0;
}
