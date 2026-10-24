// cfg_launch.h —— 「配置与日志工具」（r3shieldcore-cfg.exe）的**启动与激活契约**。
//
//   为什么要有这个头（铁律 127）：
//     主程序（`R3 ShieldCore.exe`）要"跳到"配置工具的「高级」页；
//     配置工具自己也要知道"被点名的是哪一页、消息叫什么名字"。
//     两边各写一份常量 ⇒ 哪天改了一个字（窗口类名 / 消息名 / 页号 / exe 名）
//     就**静默对不上**：主程序照样"启动成功"，但窗口永远停在第 0 页，
//     而两边都不会报错（这正是最难查的一类故障）。
//     ⇒ 类名 / 消息名 / 页号 / exe 名**只在这一处定义**。
//
//   跨进程怎么"对上暗号"：
//     `RegisterWindowMessageW` 是**幂等**的 —— 同一个字符串，在任何进程、
//     任何时候调用，都返回同一个 `0xC000..0xFFFF` 区间的消息 id。
//     所以两个 exe **不需要共享内存、不需要约定的数字**，
//     各自用同一个字符串注册，就能拿到同一个 id。
//
//   用法：
//     · 主程序：`R3ShieldCoreCfg::LaunchOrActivate(opts, &err)`；
//     · 配置工具：WndProc 开头比对 `msg == R3ShieldCoreCfg::ActivateMessageId()`。
//
//   本头只依赖 Win32 + <string>（两个 exe 都能直接 #include）。
#pragma once
#ifndef R3SHIELDCORE_CFG_LAUNCH_H
#define R3SHIELDCORE_CFG_LAUNCH_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

namespace R3ShieldCoreCfg {

// ---- 页号（与 r3shieldcore_cfg.cpp 的 g_page 一致）----
constexpr int kPageConfig   = 0;
constexpr int kPageLog      = 1;
constexpr int kPageAdvanced = 2;   // ★ v80：从主程序搬过来的「高级」页

// ---- 窗口类名（必须与 r3shieldcore_cfg.cpp 的 RegisterClassExW 一致）----
constexpr wchar_t kWindowClass[] = L"R3ShieldCoreCfgWnd";

// ---- exe 文件名（与主程序同目录）----
constexpr wchar_t kExeName[] = L"r3shieldcore-cfg.exe";

// ---- 激活消息名（两个 exe 用同一个字符串注册 ⇒ 拿到同一个 id）----
constexpr wchar_t kActivateMsgName[] = L"R3ShieldCoreCfg.Activate";

inline UINT ActivateMessageId() {
	// static：注册一次就够（幂等，重复调用只是多一次哈希查找）。
	static const UINT id = ::RegisterWindowMessageW(kActivateMsgName);
	return id;
}

// ---- 命令行开关：主程序"顺手拉起"时带上的安静标记 ----
//
//   为什么要这个开关（而不是让 cfg 自己猜）：
//     主程序启动时会顺手拉起 cfg（quiet）。如果**同时**有第二个主程序实例
//     也在拉起（UIAccess 接管时父 / 子两个实例会并发走到这一段），
//     第二个 cfg 进程会撞上单实例互斥体 —— 它必须**安静地退出**，
//     而不能去"激活已有窗口"：那会把 cfg 抢到前台，而用户此刻
//     可能正在别的窗口里打字。
constexpr wchar_t kQuietSwitch[] = L"--quiet";

// ---- 单实例互斥体名 ----
//
//   cfg 用它拦住第二个实例（`Local\` 前缀 = 每个登录会话一个，多用户/RDP 不串台）。
//
//   ★★ 为什么**探针**也要这个名字（铁律 254 的直接后果）：
//     探针清掉上一轮的 cfg 走的是 `TerminateProcess` —— **异步**的。
//     窗口消失了，进程的互斥体可能**还没释放**；这时立刻 `CreateProcess`，
//     新实例会撞上 `ERROR_ALREADY_EXISTS` ⇒ **安静退出**。
//     症状极具误导性：`窗口没出现（15s 超时）`，看着像崩溃/挂死，
//     其实是**race**；而且**连日志都不建** —— 因为单实例早退发生在
//     stdout 重定向**之前**，探针连"它为什么退出"都看不到。
//     ⇒ 探针必须**等互斥体真的没了**再启动，不能只看窗口消没消失。
constexpr wchar_t kSingleInstanceMutex[] = L"Local\\R3ShieldCoreCfg.SingleInstance";

// 单实例互斥体现在是否已被占用（存在即占用）。
//
//   只做**存在性查询**，不创建、不修改 ⇒ 对生产路径零影响。
//   `OpenMutexW` 拿到的句柄会让我们**参与持有**这个对象，所以必须立刻关掉，
//   否则"等它释放"会永远等不到（自己把自己挡住了）。
inline bool SingleInstanceTaken() {
	HANDLE h = ::OpenMutexW(SYNCHRONIZE, FALSE, kSingleInstanceMutex);
	if (h) {
		::CloseHandle(h);
		return true;
	}
	return false;
}

// 等到单实例互斥体释放为止（最多 waitMs 毫秒）。返回 true = 已经空了。
//
//   ★ 返回 false 时**不要**当没事发生继续 —— 那正是上面那种"看着像崩溃"的
//     误导性症状的来源。调用方应当把这件事**明说**出来（探针会打一行诊断）。
inline bool WaitSingleInstanceFree(DWORD waitMs, DWORD stepMs = 50) {
	for (DWORD t = 0; t < waitMs; t += stepMs) {
		if (!SingleInstanceTaken()) { return true; }
		::Sleep(stepMs);
	}
	return !SingleInstanceTaken();
}

struct LaunchOptions {
	int  page = kPageConfig;

	// quiet = 主程序启动时"顺手拉起"，不是用户主动点的：
	//   · 已经在跑 ⇒ **什么都不做**（连切页都不做，更不抢焦点）；
	//   · 没在跑   ⇒ **完全不显示窗口**（SW_HIDE），并带上 `--quiet`。
	//
	// ★ v90 改动（用户要求原话）：「cfg 被主程序拉起时**不打开窗口**，
	//   但是如果是用户双击、或者主程序点「高级」按钮时都要打开窗口」。
	//   以前 quiet 用的是 `SW_SHOWMINNOACTIVE` —— 窗口会以**最小化**出现在
	//   任务栏里，用户看到多出来一个条目，观感像"自己弹了个东西"。
	//   现在改成 `SW_HIDE`：进程在跑、窗口不存在于屏幕上，任务栏也没有条目。
	//
	//   点「高级」时怎么又出来：`LaunchOrActivate` 的②分支只负责"已经在跑"，
	//   它发 `ActivateMessageId()` 给 cfg；cfg 收到后自己
	//   `ShowWindow(SW_SHOW)` + `SetForegroundWindow`（tools/r3shieldcore_cfg.cpp
	//   的激活分支）。所以"隐藏"与"能被叫出来"是两条独立的路径，互不影响。
	bool quiet = false;
};

// cfg exe 的完整路径 = 本进程 exe 所在目录 + kExeName。
inline std::wstring CfgExePath() {
	WCHAR buf[MAX_PATH] = {};
	const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
	if (n == 0 || n >= MAX_PATH) { return std::wstring(); }
	std::wstring p(buf, n);
	const size_t slash = p.find_last_of(L"\\/");
	if (slash == std::wstring::npos) { return std::wstring(); }
	p.resize(slash + 1);
	p += kExeName;
	return p;
}

// 允许"被点名的那个窗口所属进程"把窗口带到前台。
//
// 不这么做的话，被叫醒的 cfg 窗口只会闪一下任务栏、不真的到前台
// （Windows 的前台锁定：非前台进程不能抢焦点）。调用方此刻通常正是前台
// （用户刚点了「高级」），所以这一次放行是有效的。
//
// ★ 只放行**那一个进程**，不用 `ASFW_ANY`：后者等于"接下来谁都可以抢前台"，
//   而窗口已经找到了，没必要把范围放大。
inline void AllowProcessForeground(HWND target) {
	DWORD pid = 0;
	::GetWindowThreadProcessId(target, &pid);
	if (pid != 0) {
		::AllowSetForegroundWindow(pid);
	}
}

// 启动 cfg；若已经在跑则**只发激活消息**（不重复开）。
// 返回 false 时 errOut（若给了）填的是**给人看**的原因，不是错误码。
inline bool LaunchOrActivate(const LaunchOptions& opts, std::wstring* errOut) {
	// ① 已经在跑？
	if (HWND existing = ::FindWindowW(kWindowClass, nullptr)) {
		if (opts.quiet) {
			// 顺手拉起：已经在跑 ⇒ 什么都不做。
			// ★ 尤其**不要**发激活消息 —— 那会把 cfg 抢到前台，
			//   而用户此刻可能正在别的窗口里打字（这是"启动时自动拉起"
			//   和"用户点了跳转"的唯一区别，也是最容易写错的一处）。
			return true;
		}
		AllowProcessForeground(existing);
		if (!::PostMessageW(existing, ActivateMessageId(),
			static_cast<WPARAM>(opts.page), 0)) {
			if (errOut) { *errOut = L"无法通知已在运行的配置工具（PostMessage 失败）。"; }
			return false;
		}
		return true;
	}

	// ② 没在跑：启动它。
	const std::wstring exe = CfgExePath();
	if (exe.empty()) {
		if (errOut) { *errOut = L"无法定位 r3shieldcore-cfg.exe（取本程序目录失败）。"; }
		return false;
	}
	if (::GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
		if (errOut) { *errOut = L"找不到 r3shieldcore-cfg.exe：\n" + exe; }
		return false;
	}

	// ★ 命令行里 exe 路径要**再带一次引号**（CreateProcess 的 lpCommandLine
	//   规定 argv[0] 是程序名；路径含空格时漏引号 ⇒ 启动的是另一个东西）。
	std::wstring cmd = L"\"" + exe + L"\" --page " + std::to_wstring(opts.page);
	if (opts.quiet) {
		cmd += L" ";
		cmd += kQuietSwitch;
	}
	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	// ★ v90：quiet ⇒ `SW_HIDE`（完全不显示），不是 `SW_SHOWMINNOACTIVE`。
	//   cfg 侧第一次 `ShowWindow(g_main, SW_SHOWDEFAULT)` 会尊重这个值
	//   （Windows 的"第一次 ShowWindow 用 STARTUPINFO"约定）。
	si.wShowWindow = opts.quiet ? SW_HIDE : SW_SHOWNORMAL;
	PROCESS_INFORMATION pi = {};
	if (!::CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE,
		0, nullptr, nullptr, &si, &pi)) {
		const DWORD e = ::GetLastError();
		if (errOut) {
			*errOut = L"启动 r3shieldcore-cfg.exe 失败（错误 " + std::to_wstring(e) + L"）。";
		}
		return false;
	}
	::CloseHandle(pi.hThread);
	::CloseHandle(pi.hProcess);
	return true;
}

}  // namespace R3ShieldCoreCfg

#endif  // R3SHIELDCORE_CFG_LAUNCH_H
