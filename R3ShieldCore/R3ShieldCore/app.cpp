#include "stdafx.h"
#include "functions.h"
#include "engine_control.h"
#include "r3shieldcore_config.h"
#include "r3shieldcore_gui.h"
#include "r3shieldcore_log_replay.h"
#include "r3shieldcore_stats.h"
#include "r3shieldcore_superdesk.h"
#include "r3shieldcore_sentinel.h"
#include "r3shieldcore_procwatch.h"
#include "r3shieldcore_ark.h"
#include <atomic>
#include <clocale>
#include <fcntl.h>
#include <fstream>
#include <io.h>
#include <share.h>
#include <sys/stat.h>
#include <thread>

namespace
{
	// exe 所在目录（直接调 Win32，不走会抛异常的 wil 包装）。
	std::wstring ModuleDirectory() noexcept
	{
		wchar_t path[MAX_PATH * 4] = {};
		const DWORD length = GetModuleFileNameW(nullptr, path, _countof(path));
		if (length == 0 || length >= _countof(path)) {
			return std::wstring();
		}
		const std::wstring full(path, length);
		const size_t slash = full.find_last_of(L"\\/");
		return slash == std::wstring::npos ? std::wstring() : full.substr(0, slash);
	}

	// 用 **ofstream** 追加一行诊断到 r3shieldcore-console.log。
	//
	// ★ 这条通道必须独立于 stdout 重定向：本程序是 **GUI 子系统**，没有控制台，
	//   重定向一旦失败 printf 就静默消失。而 ofstream 直接开文件，不受影响
	//   （同目录的 superdesk-panel.log 一直这么写，从没丢过）。
	//   v33 实测：提权自检时 superdesk-panel.log 有内容，r3shieldcore-console.log 却
	//   **一行不加、连兜底文件都没生成** ⇒ 必须把"重定向到底成没成"本身也记下来，
	//   否则永远分不清是"重定向失败"还是"根本没跑到那一步"。
	void AppendDiagnosticLine(const std::wstring& directory, const std::string& text) noexcept
	{
		try {
			std::ofstream output(std::filesystem::path(directory) / L"r3shieldcore-console.log",
				std::ios::out | std::ios::app);
			if (output) {
				output << text << std::endl;
			}
		}
		catch (...) {
		}
	}

	void RedirectDiagnosticsToFile() noexcept
	{
		const std::wstring directory = ModuleDirectory();
		if (directory.empty()) {
			return;
		}

		// ★ 必须用 `freopen_s`，**不能用 `_dup2`**。
		//
		// 本 exe 是 **GUI 子系统**（-SUBSYSTEM:WINDOWS）。进程**没有控制台**时，
		// MSVC 的 stdout 是一个"没有 fd 的流"—— v33 实测 `_fileno(stdout) == -2`，
		// 于是 `_dup2(fd, -2)` 必然失败（实测 `dup2Out=-1`），printf 全部进黑洞。
		// `freopen_s` 会**重建**流、不依赖原来的 fd，所以能救回来。
		//
		// ⚠️ 连带教训：把 demo 从 `-SUBSYSTEM:CONSOLE` 改成 `WINDOWS` 修好了
		//    LNK2019，却**悄悄弄丢了引擎横幅**（printf 从此写不出去），
		//    直到加上 `[diag]` 这一行才暴露。
		auto rebind = [](const std::wstring& path, FILE* stream) {
			FILE* reopened = nullptr;
			if (_wfreopen_s(&reopened, path.c_str(), L"a", stream) != 0) {
				return 1;
			}
			setvbuf(stream, nullptr, _IONBF, 0);
			return 0;
		};

		const std::wstring primary = directory + L"\\r3shieldcore-console.log";
		const std::wstring fallback =
			directory + L"\\engine-console-" + std::to_wstring(GetCurrentProcessId()) + L".log";

		// ① 短暂重试 —— 上一份引擎可能还持有该文件，给它一点时间退出。
		int stdoutResult = 1;
		for (int attempt = 0; attempt < 4 && stdoutResult != 0; ++attempt) {
			if (attempt != 0) {
				::Sleep(50);
			}
			stdoutResult = rebind(primary, stdout);
		}
		// ② 仍失败就退到按 PID 命名的兜底日志。
		bool usedFallback = false;
		if (stdoutResult != 0) {
			usedFallback = true;
			stdoutResult = rebind(fallback, stdout);
		}

		int stderrResult = -1;
		if (stdoutResult == 0) {
			stderrResult = rebind(usedFallback ? fallback : primary, stderr);
		}

		char status[512] = {};
		_snprintf_s(status, sizeof(status), _TRUNCATE,
			"[diag] redirect pid=%lu stdout=%d stderr=%d fallback=%d",
			static_cast<unsigned long>(GetCurrentProcessId()),
			stdoutResult, stderrResult, usedFallback ? 1 : 0);

		// 重定向成功 ⇒ 直接用 printf 落盘（此时 stdout 已指向日志、且 unbuffered）；
		// 失败 ⇒ 只能走 ofstream 兜底，否则这行诊断自己也丢了。
		if (stdoutResult == 0) {
			printf("%s\n", status);
		}
		else {
			AppendDiagnosticLine(directory, status);
		}
	}

	void WriteStartupFailure(const char* message) noexcept
	{
		try {
			const std::filesystem::path modulePath = wil::GetModuleFileName<std::wstring>();
			std::ofstream output(modulePath.parent_path() / L"r3shieldcore-startup-error.log",
				std::ios::out | std::ios::app);
			if (output) {
				output << "pid=" << GetCurrentProcessId() << " error="
					<< (message ? message : "unknown exception") << std::endl;
			}
		}
		catch (...) {
			// Startup diagnostics must never change the failure path.
		}
	}

	// 把异常消息（窄字符串，内容是 ASCII/ANSI）转成宽字符给弹窗用。
	std::wstring WidenStartupMessage(const char* message)
	{
		if (!message || !*message) {
			return L"(异常消息为空)";
		}
		const int needed = MultiByteToWideChar(CP_ACP, 0, message, -1, nullptr, 0);
		if (needed <= 1) {
			return L"(异常消息无法转换)";
		}
		std::wstring wide(static_cast<size_t>(needed - 1), L'\0');
		MultiByteToWideChar(CP_ACP, 0, message, -1, wide.data(), needed);
		return wide;
	}

	//
	// ★★ 启动失败必须**显眼**，不能只写日志。
	//
	// 引擎是控制台子系统程序：双击运行时用户只看到一个"一闪而过"的黑窗口。
	// 而**启动失败 = 零防护** —— 用户会以为自己在受保护，然后拿它去做拦截
	// 测试，得到一整套假结论（"没拦住"其实是因为根本没有引擎在跑）。
	//
	// ★ v57：原来这里对"部署目录可写"这条错误给了专门的操作步骤（去跑
	//   harden-acl.bat）。那道门禁已删除（见 `engine_control.cpp` 文件头），
	//   所以这个特判分支也随之删除 —— 现在目录可写**不会**导致启动失败。
	//
	void ShowStartupFailureDialog(const char* message) noexcept
	{
		try {
			const std::wstring reason = WidenStartupMessage(message);

			std::wstring text =
				L"R3ShieldCore 引擎启动失败 —— 本机当前**没有任何防护**。\n\n"
				L"原因：\n" + reason + L"\n\n";

			text += L"详细信息见同目录的 r3shieldcore-startup-error.log。";

			MessageBoxW(nullptr, text.c_str(), L"R3ShieldCore 引擎启动失败",
				MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
		}
		catch (...) {
			// 弹窗本身失败绝不能改变失败路径。
		}
	}

	// 统计聚合回调。挂在事件通道的"旁观者"钩子上，
	// 每条事件被 drain 出来时额外调一次（落盘仍走原来的回调）。
	void OnEventForStats(const R3ShieldCore::Event& event, void* /*context*/)
	{
		R3ShieldCoreStats::OnEvent(event);
	}

	// 启动横幅与运行期切换共用同一份文案，免得两处说法不一致。
	PCWSTR ModeDisplayText(ULONG mode)
	{
		switch (static_cast<R3ShieldCore::Mode>(mode)) {
		case R3ShieldCore::Mode::Block: return L"BLOCK（主动防御：仅拦截高置信度高危行为）";
		case R3ShieldCore::Mode::Ask: return L"ASK（拦截并弹窗询问）";
		case R3ShieldCore::Mode::BlockAll:
			return L"BLOCK_ALL（完全拦截：其余一律拒绝；进程创建/远程线程/跨进程内存改为弹窗）";
		case R3ShieldCore::Mode::BlockAllSafe:
			return L"BLOCK_ALL_SAFE（完全拦截·安全：可信来源的进程创建直接放行；其余一律拒绝，远程线程/跨进程内存改为弹窗）";
		default: return L"LOG（只记录，全部放行）";
		}
	}

	// 界面点了「切换模式」按钮之后真正落地。
	//
	// 三件事，顺序无所谓但一件都不能少：
	//   ① 改 DLL 侧共享内存的 Mode —— 全局立刻生效（被注入进程每次判定都重读）
	//   ② 把新值写回 r3shieldcore.ini —— 让切换活过下次重启
	//   ③ 通知界面刷新徽章 —— 只有走到这里才变，切失败就保持原样
	void ApplyMode(EngineControl& engineControl, R3ShieldCore::Mode mode,
		const std::filesystem::path& exeDirectory)
	{
		if (!engineControl.SetMode(mode)) {
			printf("模式切换失败：DLL 不支持运行期切换（版本不匹配？），或共享通道未建立\n");
			return;
		}

		R3ShieldCoreGui::SetMode(mode);

		const ULONG raw = static_cast<ULONG>(mode);
		const char* iniText = R3ShieldCoreConfig::ModeIniText(raw);
		printf("模式已切换为 %ls\n", ModeDisplayText(raw));

		if (R3ShieldCoreConfig::SaveMode(raw, exeDirectory)) {
			printf("            （已写回 r3shieldcore.ini: mode=%s，重启后保持）\n", iniText);
		}
		else {
			// ⚠ 不要在这里写 U+26A0：窄字符串 printf 走 936 代码页，MSVC 会报
			// C4566 且实际打出 '?'。日志里用 [!!] 更稳。
			printf("            [!!] 写回 r3shieldcore.ini 失败，本次生效但重启后会回到旧模式\n");
		}

		if (mode == R3ShieldCore::Mode::BlockAll) {
			printf("            [!!] 完全拦截模式：其余一律拒绝；进程创建 / 远程线程 /\n");
			printf("                 跨进程内存改为弹窗询问（默认结论按 ini 兜底）。\n");
			printf("              点「切换」退回 LOG，或改 ini / 结束引擎进程。\n");
		}
		else if (mode == R3ShieldCore::Mode::BlockAllSafe) {
			printf("            [!!] 完全拦截·安全模式：可信来源的进程创建**直接放行**\n");
			printf("                 （系统目录 + 微软签名），连问都不问；其余一律拒绝，\n");
			printf("                 远程线程 / 跨进程内存改为弹窗询问。\n");
			printf("              点「切换」退回 LOG，或改 ini / 结束引擎进程。\n");
		}
	}

	// ----------------------------------------------------------------------
	// ★ v61：高危进程判据的跨函数桥。
	//
	// `R3ShieldCoreProcWatch::Start` 要的是一个普通函数指针（CheckFn），而判据
	// 实现在 `EngineControl::CheckHighRiskProcess`（成员函数）里。引擎进程里
	// 只有一份 EngineControl、且它在主循环开始前构造、循环结束后才析构，
	// 所以用一个文件静态指针 + 自由函数 thunk 把它接过去是安全的（成员函数
	// 指针不能直接转成普通函数指针）。
	//
	// 判据本身跑在 DLL 里、只读静态表 + 参数、无可变状态 ⇒ 可被主循环线程
	// 与注入线程安全地并发调用。
	EngineControl* g_engineControlForProcWatch = nullptr;

	const char* ProcWatchCheckThunk(const wchar_t* imagePath, const wchar_t* systemRoot)
	{
		return g_engineControlForProcWatch
			? g_engineControlForProcWatch->CheckHighRiskProcess(imagePath, systemRoot)
			: nullptr;
	}

	// ----------------------------------------------------------------------
	// ★ v62：自动化用的「优雅退出」入口 —— `R3SHIELDCORE_EXIT_AFTER_MS=<毫秒>`。
	//
	// 为什么必须有它（**不是**开发时的临时补丁）：
	//
	//   ARK 允许挂起任意进程。由此产生一条**唯一的安全兜底**：引擎退出时
	//   必须把它挂起过的进程全部恢复回来 —— 否则用户关掉引擎之后，那些
	//   进程会**永久冻结**，而屏幕上再也没有界面可以解冻它们。
	//
	//   但这条兜底只在**优雅退出**时执行（break 出主循环 → R3ShieldCoreArk::Stop()
	//   → ArkActions::Perform(Resume)）。用 TerminateProcess 强杀
	//   （dskill / 任务管理器「结束任务」）根本不给代码执行的机会 —— 于是
	//   自动化验证就只剩"强杀"一条路，"自动恢复"**永远测不到**；更糟的是
	//   探针里那句"退出后已恢复"会因为"压根没挂起过"而**假通过**
	//   （铁律 54：没有反向对照的 PASS 等于没测）。
	//
	//   它走的是和「退出引擎」按钮**完全同一条**收尾路径（g_quitRequest
	//   的语义），不是另开一条捷径 —— 见主循环里的调用点。
	bool ShouldAutoExit()
	{
		static bool initialized = false;
		static bool enabled = false;
		static ULONGLONG startMs = 0;
		static ULONGLONG deadlineMs = 0;

		if (!initialized) {
			initialized = true;
			startMs = GetTickCount64();

			wchar_t text[32] = {};
			const DWORD length = GetEnvironmentVariableW(L"R3SHIELDCORE_EXIT_AFTER_MS",
				text, _countof(text));
			if (length > 0 && length < _countof(text)) {
				const unsigned long value = wcstoul(text, nullptr, 10);
				if (value > 0) {
					deadlineMs = value;
					enabled = true;
					printf("[diag] R3SHIELDCORE_EXIT_AFTER_MS=%lu —— 到点后走"
						"「退出引擎」同一条收尾路径\n", value);
					fflush(stdout);
				}
			}
		}

		return enabled && (GetTickCount64() - startMs) >= deadlineMs;
	}
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
	// ★ 必须放在**任何引擎初始化之前**。
	//
	// 「超级置顶面板」是同一个 exe 的另一个实例，被主引擎用
	// CreateProcessWithTokenW 拉到 winsta0\Winlogon（UAC 安全桌面）上。
	// 它只画一块状态面板，绝不能启动第二份引擎 —— 两份引擎 = 两套全局注入
	// + 两套自我保护，日志也会互相打架。
	if (R3ShieldCoreSuperDesk::IsPanelInvocation()) {
		return R3ShieldCoreSuperDesk::RunPanel();
	}

	RedirectDiagnosticsToFile();

	setlocale(LC_ALL, "");

	// 发布包自检：只验证 GUI 置顶，不初始化注入引擎。
	if (std::wstring(GetCommandLineW()).find(L"--topmost-selftest") != std::wstring::npos) {
		return R3ShieldCoreGui::RunTopMostSelfTest();
	}

	// 全链路自检（--superdesk-selftest）：自己扮演引擎，走完整条 A 配方
	//（SYSTEM 令牌 → 改会话号 → TokenUIAccess → CreateProcessWithTokenW
	//  到 winsta0\Winlogon），等面板按 6 秒寿命自己退掉后收尾。
	//
	// 它**只**验证"配方能不能跑通"，不启动引擎 —— 所以同样必须在
	// 引擎初始化之前分流，否则会顺带注入一整套 hook。
	// 放在 setlocale 之后：它要往日志里写中文。
	if (R3ShieldCoreSuperDesk::IsSelfTestInvocation()) {
		return R3ShieldCoreSuperDesk::RunSelfTest();
	}

	// UIAccess 重启链路自检（--uiaccess-selftest）：跑的是**用户点「超级置顶」
	// 按钮**时真正走的那条路（LaunchUiAccessInstance），补上 A 配方自检
	// 覆盖不到的洞 —— 铁律 22：自检入口必须和用户路径共用同一个函数，
	// 否则"自检绿"和"用户能用"是两件事（本项目已经踩过一次）。
	if (R3ShieldCoreSuperDesk::IsUiAccessSelfTestInvocation()) {
		return R3ShieldCoreSuperDesk::RunUiAccessSelfTest();
	}

	// 输出不缓冲：这个工具可能被 taskkill 结束，
	// 缓冲的话最后几行日志永远看不到。
	setvbuf(stdout, nullptr, _IONBF, 0);

	printf("R3ShieldCore - 用户态注册表 / 文件 / 进程 / 线程 / 驱动 / 网络行为监控\n");
	printf("================================\n\n");

	printf("设置调试权限... ");
	if (SetDebugPrivilege(TRUE)) {
		printf("OK\n");
	}
	else {
		printf("失败，可能不是以管理员身份运行\n");
	}

	//
	// ⚠️ 提权自检。
	//
	// exe 的清单里写了 requireAdministrator，正常双击时 UAC 已经提过权。
	// 但**直接跑"以管理员身份运行"以外的方式**（比如从已提权的父进程
	// CreateProcess、或清单被剥离/被工具改了）都可能进来一个非提权实例，
	// 而那种实例是残的（注入失败、服务 API 全 err=5）。
	// 与其让它默默半残，不如在这里明说。
	//
	// 判断方式用 token 的 TokenElevation 而不是"名字里有没有 Admin" ——
	// 后者在 UAC 虚拟化 / 组策略改名下会误判。
	//
	// ★ 历史：v30（2026-10-01）曾把清单改成 highestAvailable（不强制管理员），
	//   同日**已回退** —— 不提权时引擎大面积失效，实用价值不足。
	{
		HANDLE token = nullptr;
		TOKEN_ELEVATION elevation = {};
		DWORD returned = 0;
		BOOL elevated = FALSE;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) &&
			GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned)) {
			elevated = elevation.TokenIsElevated;
		}

		if (token) {
			CloseHandle(token);
		}

		if (elevated) {
			printf("运行身份    : 管理员（已提权）\n");
		}
		else {
			printf("\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("!! 当前**没有**管理员权限 —— 引擎会大面积失效               !!\n");
			printf("!!                                                        !!\n");
			printf("!! 正常双击时清单里的 requireAdministrator 会弹 UAC 提权，  !!\n");
			printf("!! 走到这里说明是被别的方式拉起来的（或清单被剥离）。       !!\n");
			printf("!!                                                        !!\n");
			printf("!! 后果：全局注入会被拒（err=5）、服务 API 全失败、         !!\n");
			printf("!!       自我保护无效、部分 hook 挂不上。                   !!\n");
			printf("!! 做法：关掉本窗口，右键 exe →「以管理员身份运行」。       !!\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("\n");
		}
	}

	try {
		std::filesystem::path exeDirectory = wil::GetModuleFileName<std::wstring>();
		exeDirectory = exeDirectory.parent_path();

		R3ShieldCore::Policy policy;
		R3ShieldCoreConfig::Load(policy, exeDirectory);

		// 引擎侧主动反制的开关（不进 Policy 共享内存，只影响引擎自身行为）。
		R3ShieldCoreConfig::EngineSettings engineSettings = R3ShieldCoreConfig::LoadEngineSettings(exeDirectory);

		// ★ v66：**把配置文件的实际路径印出来**。
		//
		// 为什么必须印：现在配置有**两个可能的位置**（ProgramData 优先，exe 同目录
		//   兜底），用户改错文件时症状是"改了不生效"—— 而**什么都不提示**。
		//   这正是铁律 97/99 说的那类"布尔判定 = 不可诊断"。
		//   印出来之后，"我该改哪个文件"变成一个可以直接看的事实。
		{
			const std::filesystem::path configPath =
				R3ShieldCoreConfig::ResolveConfigPath(exeDirectory);
			printf("配置文件    : %ls\n", configPath.c_str());
			printf("              （改完保存 -> 重启引擎生效；v66 起安装版优先用 ProgramData 那份）\n");
		}

		printf("模式        : %ls\n", ModeDisplayText(policy.Mode));
		printf("  切换方式  : 界面页签栏右侧的「切换: xxx」按钮（运行期生效，会写回 ini）\n");

		if (policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::BlockAll)) {
			// 这个模式的后果很重，横幅必须写足，免得用户过两天忘了是自己开的。
			printf("\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("!! 完全拦截模式已启用                                     !!\n");
			printf("!!                                                        !!\n");
			printf("!! 注册表写 / 文件写 / 网络 / 摄像头 / 输入钩子 / 截屏       !!\n");
			printf("!! 一律被拒绝，不看豁免也不看高危。第三方程序会大面积失灵。 !!\n");
			printf("!!                                                        !!\n");
			printf("!! 【进程创建 / 远程线程 / 跨进程内存】★ v66 起：直接拒，   !!\n");
			printf("!!   不弹窗、不问用户、不看 prompt_default。               !!\n");
			printf("!!   （v21~v65 曾改成「先问再拦」，v66 撤销：全拦就是全拦）  !!\n");
			printf("!!   唯一例外：UAC 同意框本体（System32\\consent.exe 等），  !!\n");
			printf("!!   放行它们只为保证「提权」这条路不断，不是放行被提权目标。 !!\n");
			printf("!!                                                        !!\n");
			printf("!! 不受影响：系统进程、exclude 白名单进程、本引擎自身       !!\n");
			printf("!!           （它们不在注入范围内，所以探测不到）。          !!\n");
			printf("!! 进程 / 线程的「退出」也**不会**被拦（拦了进程就退不出，   !!\n");
			printf("!! 系统会直接死锁）。                                      !!\n");
			printf("!!                                                        !!\n");
			printf("!! 恢复方式：点界面上的「切换」按钮（一步退回 LOG），      !!\n");
			printf("!!           或改 r3shieldcore.ini 的 mode=log|block|ask，      !!\n");
			printf("!!           或在任务管理器结束引擎进程。                   !!\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("\n");
		}

		if (policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::BlockAllSafe)) {
			// 与 BlockAll 同属"全拦"家族，但有一处放行 —— 横幅要把这一处说清楚，
			// 避免用户以为防护变弱了（其实只是把断点从"创建"后移到"写内存"）。
			printf("\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("!! 完全拦截·安全模式已启用（block_all_safe）              !!\n");
			printf("!!                                                        !!\n");
			printf("!! 与 block_all 的唯一区别：                              !!\n");
			printf("!!   * 放行「可信来源」的**进程创建**                     !!\n");
			printf("!!     可信来源 = SystemRoot / Program Files 下,           !!\n");
			printf("!!                 且不在可写子目录、且微软签名有效。      !!\n");
			printf("!!   -> 系统目录里的程序（记事本/计算器/任务管理器）能启动 !!\n");
			printf("!!   -> 用户目录 / 桌面 / 下载目录里的程序仍然被拦         !!\n");
			printf("!!   -> 拿不到镜像路径的创建（NtCreateProcess，镂空特征）  !!\n");
			printf("!!     仍然被拦。                                          !!\n");
			printf("!!                                                        !!\n");
			printf("!! 其余全部照旧全拦：                                      !!\n");
			printf("!!   注册表写 / 文件写 / 网络 / 驱动 / 隐私采集            !!\n");
			printf("!! => 注入链仍然断在「写内存」那一步，安全性不降。         !!\n");
			printf("!!                                                        !!\n");
			printf("!! 【注】远程线程 / 跨进程内存 ★ v66 起：直接拒，不弹窗。  !!\n");
			printf("!!   （v21~v65 曾改成弹窗询问，v66 撤销。）                !!\n");
			printf("!!   UAC 同意框本体（System32\\consent.exe 等）仍放行。      !!\n");
			printf("!!                                                        !!\n");
			printf("!! 恢复方式：点界面上的「切换」按钮（一步退回 LOG），      !!\n");
			printf("!!           或改 r3shieldcore.ini 的 mode=... ，              !!\n");
			printf("!!           或在任务管理器结束引擎进程。                   !!\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("\n");
		}


		// ★ v66：全拦模式**不再弹窗** ⇒ 超时设置只对 Ask 模式有意义。
		//   全拦模式下无论 prompt_default 写什么都不放行，把它印出来反而误导
		//   （用户会以为"设成 allow 就能过"）。
		if (policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask)) {
			printf("询问超时    : %u 秒，超时后%s\n",
				policy.PromptTimeoutMs / 1000,
				policy.PromptDefaultVerdict == static_cast<ULONG>(R3ShieldCore::Verdict::Allow) ? "允许" : "拒绝");
		}
		else if (R3ShieldCore::IsAnyBlockAllMode(policy.Mode)) {
			printf("询问超时    : 不适用（全拦模式直接拒：不弹窗、不看 prompt_default）\n");
		}

		printf("挂读操作    : %s\n", (policy.Flags & R3ShieldCore::FlagHookReads) ? "是" : "否");
		printf("挂 Hive 操作: %s\n", (policy.Flags & R3ShieldCore::FlagHookHive) ? "是" : "否");
		printf("挂键信息操作: %s\n", (policy.Flags & R3ShieldCore::FlagHookSetInfo) ? "是" : "否");
		printf("挂文件操作  : %s\n", (policy.Flags & R3ShieldCore::FlagHookFile)
			? "是（建/写/删/改名/改时间戳/改 ACL）" : "否（文件系统太热，默认关）");
		printf("挂进程操作  : %s\n", (policy.Flags & R3ShieldCore::FlagHookProcess)
			? "是（创建/终止，高危才拦）" : "否");
		printf("挂线程操作  : %s\n", (policy.Flags & R3ShieldCore::FlagHookThread)
			? ((policy.Flags & R3ShieldCore::FlagHookSelfThread)
				? "是（远程 + 本进程，本进程线程噪音很大）"
				: "是（仅远程线程 = 注入检测）")
			: "否");
		printf("挂驱动操作  : %s\n", (policy.Flags & R3ShieldCore::FlagHookDriver)
			? "是（NtLoadDriver + advapi32 服务 API：装/改/启驱动服务）" : "否");
		printf("挂网络操作  : %s\n", (policy.Flags & R3ShieldCore::FlagHookNetwork)
			? ((policy.Flags & R3ShieldCore::FlagHookNetAll)
				? "是（出站 + DNS + 监听/绑定/接受）"
				: "是（出站 + DNS；监听/绑定/接受默认关）")
			: "否");
		printf("自我保护    : %s\n", (policy.Flags & R3ShieldCore::FlagSelfProtect)
			? "是（NtOpenProcess 对引擎剥掉终止/写入/建线程权限；不受 mode 影响）"
			: "否（引擎可被任意进程终止或注入）");
		printf("挂摄像头    : %s\n", (policy.Flags & R3ShieldCore::FlagHookCamera)
			? "是（VFW + Media Foundation；打开设备即高危）" : "否");
		printf("挂输入钩子  : %s\n", (policy.Flags & R3ShieldCore::FlagHookInputHook)
			? "是（SetWindowsHookEx + 原始输入；低级/全局钩子即高危）" : "否");
		printf("挂截屏      : %s\n", (policy.Flags & R3ShieldCore::FlagHookScreen)
			? "是（BitBlt/StretchBlt/GetDIBits 源为屏幕 DC + PrintWindow）" : "否");
		printf("挂 DLL 加载 : %s\n", (policy.Flags & R3ShieldCore::FlagHookDllLoad)
			? "是（LdrLoadDll + NtMapViewOfSection；仅非系统目录上报）" : "否");
		printf("挂剪贴板    : %s\n", (policy.Flags & R3ShieldCore::FlagHookClipboard)
			? "是（GetClipboardData 高危；OpenClipboard 只记录）" : "否");
		printf("挂进程旁路  : %s\n", (policy.Flags & R3ShieldCore::FlagHookSpawn)
			? "是（ShellExecuteEx/WinExec/WithToken/WithLogon/AsUser，一律高危）" : "否");
		printf("挂服务权限  : %s\n", (policy.Flags & R3ShieldCore::FlagHookServiceConfig)
			? "是（SetServiceObjectSecurity + NtSetSecurityObject；改 DACL 即高危）" : "否");
		printf("挂 COM 激活 : %s\n", (policy.Flags & R3ShieldCore::FlagHookComHijack)
			? "是（CoCreateInstance/Ex + CoGetClassObject；CLSID 指向用户可写目录即高危）" : "否");
		printf("挂计划任务  : %s\n", (policy.Flags & R3ShieldCore::FlagHookScheduledTask)
			? "是（ITaskFolder::RegisterTaskDefinition vtable patch；注册/覆盖任务即高危）" : "否");
		printf("挂音频采集  : %s\n", (policy.Flags & R3ShieldCore::FlagHookAudio)
			? "是（waveIn/MCI + WASAPI IAudioClient::Initialize；麦克风与环回均高危）" : "否");
		printf("挂令牌窃取  : %s\n", (policy.Flags & R3ShieldCore::FlagHookTokenTheft)
			? "是（OpenProcessToken→DuplicateTokenEx→冒充；开 SeDebug/SeImpersonate 高危）" : "否");
		printf("挂 WMI 订阅 : %s\n", (policy.Flags & R3ShieldCore::FlagHookWmiSubscription)
			? "是（IWbemServices::PutInstance vtable patch；root\\subscription 三件套即高危）" : "否");
		printf("挂宿主劫持  : %s\n", (policy.Flags2 & R3ShieldCore::FlagHookHostHijack)
			? "是（AppInit/IFEO/LSA/Winlogon 注入键 + LoadLibraryEx + 跨进程映射/APC；指向用户可写目录或跨进程即高危）" : "否");
		if (policy.Flags & R3ShieldCore::FlagHookNetwork) {
			printf("  说明      : 用户态 ws2_32 出口，可被静态链接/直连 AFD 绕过，定位为可见性工具\n");
		}
		if (policy.Flags & (R3ShieldCore::FlagHookCamera | R3ShieldCore::FlagHookInputHook | R3ShieldCore::FlagHookScreen
			| R3ShieldCore::FlagHookAudio)) {
			printf("  说明      : 摄像头/音频/输入钩子/截屏均为用户态可见性，绕过路径见 docs/HANDOVER.md\n");
		}
		if (policy.Flags & (R3ShieldCore::FlagHookDllLoad | R3ShieldCore::FlagHookClipboard | R3ShieldCore::FlagHookSpawn
			| R3ShieldCore::FlagHookTokenTheft | R3ShieldCore::FlagHookWmiSubscription)) {
			printf("  说明      : DLL加载/剪贴板/进程旁路/令牌/WMI订阅均为用户态出口，直 syscall/手工映射可绕过\n");
		}
		printf("排除路径    : %u 条\n", policy.ExcludePathCount);
		// ★ v49：把"绝不注入"名单条数打出来 —— 这是**用户最容易配错又最难自查**
		//   的一项：ini 里写错一个字符（少个结尾 `\` 写成别的目录、用了文件名而不是
		//   完整路径）就**静默不生效**，而"没生效"的表现是"某个程序偶尔卡一下"，
		//   几乎不可能联想到 ini。所以启动横幅必须让它可见。
		printf("绝不注入    : %u 条（ini: never_inject=；命中者一个 hook 都不装）\n",
			policy.NeverInjectCount);
		for (ULONG i = 0; i < policy.NeverInjectCount && i < R3ShieldCore::MaxNeverInjectPaths; ++i) {
			printf("  [%u] %ls\n", i, policy.NeverInjectPaths[i]);
		}
		{
			static const PCWSTR kNeutralizeText[] = {
				L"否（ini: neutralize_overlay=0）",
				L"是·不问（最小化/关闭/销毁窗口/调用退出函数/杀进程）",
				// ★ v60：旧文案写"超时=跳过"，与 v59 之后的真实语义相反 ——
				//   超时**只代表"这次没结论"**，稍后会重试；只有连续 kMaxAskTimeouts(3)
				//   次无应答才停止询问。写成"跳过"会让用户以为超时=放弃（真机日志里
				//   就是靠这句误导排查方向）。
				L"是·弹窗询问（每级执行前弹居中置顶小窗；超时=本次不做、稍后重试，连续 3 次无应答才停止询问）",
			};
			const ULONG level = engineSettings.NeutralizeOverlayLevel;
			printf("反制覆盖层  : %ls\n", kNeutralizeText[level <= 2 ? level : 2]);
		}
		printf("注入扫描间隔: %lu ms（ini: inject_interval_ms；越小盲区越短）\n",
			static_cast<unsigned long>(engineSettings.InjectionIntervalMs));
		printf("瘦注入宿主  : %s（ini: inject_shell_thin）\n",
			(policy.Flags2 & R3ShieldCore::FlagInjectShellThin)
			? "是（explorer.exe / svchost.exe / runtimebroker.exe 只装 CreateProcessInternalW "
			  "-> 双击启动与 UAC 提权启动的子进程走同步路，盲区≈0）"
			: "否（这些宿主不注入，只能靠轮询）");
		if (policy.Flags2 & R3ShieldCore::FlagInjectShellThin) {
			printf("  说明      : 瘦会话**不装任何 guard** -> 这些宿主自己不受监控，"
				"但它们拉起的子进程受完整监控\n");
		}
		// ★ v58：**双架构注入 DLL 的存在性自检**。
		//
		//   为什么必须在启动横幅里吵出来：
		//   注入器是按**目录名**选架构的 —— `dll_inject.cpp` 的
		//   `GetEnginePath(machine)` 返回 `<部署根>\32` 或 `<部署根>\64`，
		//   再拼上固定的 `r3shieldcore-lib.dll`。
		//   发布包曾经把 32 位 DLL 命名成 `64\R3ShieldCoreLib-x86.dll`
		//   （代码里零引用、路径也对不上），于是**32 位进程永远注入失败**，
		//   而症状只是"某些程序没有事件"—— 完全联想不到是缺了一个目录。
		//   这类"零防护且无提示"的失败必须消灭（同铁律 39 家族）。
		{
			wchar_t exePath[MAX_PATH] = {};
			if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) != 0) {
				std::filesystem::path dir = std::filesystem::path(exePath).parent_path();
				const std::filesystem::path dll32 = dir / L"32" / L"r3shieldcore-lib.dll";
				const std::filesystem::path dll64 = dir / L"64" / L"r3shieldcore-lib.dll";
				const bool has32 = GetFileAttributesW(dll32.c_str()) != INVALID_FILE_ATTRIBUTES;
				const bool has64 = GetFileAttributesW(dll64.c_str()) != INVALID_FILE_ATTRIBUTES;

				if (has32 && has64) {
					printf("注入 DLL    : 32\\ 与 64\\ 都在（双架构覆盖完整）\n");
				}
				if (!has64) {
					printf("!! 缺少 64 位注入 DLL: %ls\n", dll64.c_str());
					printf("!!   => **所有 64 位进程都不会被注入、不会有任何事件**\n");
				}
				if (!has32) {
					printf("!! 缺少 32 位注入 DLL: %ls\n", dll32.c_str());
					printf("!!   => **所有 32 位进程都不会被注入、不会有任何事件**\n");
					printf("!!   => 修复：把 32 位版 r3shieldcore-lib.dll 放进上面的 32\\ 目录\n");
					printf("!!   （注意：命名为 R3ShieldCoreLib-x86.dll 放在 64\\ 里是**无效**的，\n");
					printf("!!     注入器只认 <部署根>\\32\\r3shieldcore-lib.dll 这个固定路径）\n");
				}
			}
			// 铁律 80：诊断 printf 必须紧跟 fflush，否则被强杀时整段丢失。
			fflush(stdout);
		}
		printf("日志文件    : %ls\n", policy.LogPath);
		printf("\n");

		// 先打开界面。UIAccess 接管实例先完成窗口创建和自身置顶，
		// 父实例随后退出旧引擎；因此接管实例在此之前不能创建第二套 EngineControl。
		R3ShieldCoreGui::Options guiOptions = {};
		guiOptions.Mode = static_cast<R3ShieldCore::Mode>(policy.Mode);
		guiOptions.HookReads = (policy.Flags & R3ShieldCore::FlagHookReads) != 0;
		guiOptions.HookHive = (policy.Flags & R3ShieldCore::FlagHookHive) != 0;
		guiOptions.HookSetInfo = (policy.Flags & R3ShieldCore::FlagHookSetInfo) != 0;
		guiOptions.HookFile = (policy.Flags & R3ShieldCore::FlagHookFile) != 0;
		guiOptions.HookProcess = (policy.Flags & R3ShieldCore::FlagHookProcess) != 0;
		guiOptions.HookThread = (policy.Flags & R3ShieldCore::FlagHookThread) != 0;
		guiOptions.HookSelfThread = (policy.Flags & R3ShieldCore::FlagHookSelfThread) != 0;
		guiOptions.HookDriver = (policy.Flags & R3ShieldCore::FlagHookDriver) != 0;
		guiOptions.HighRisk = (policy.Flags & R3ShieldCore::FlagHighRiskGuard) != 0;
		guiOptions.LogPath = policy.LogPath;
		guiOptions.ExcludePathCount = policy.ExcludePathCount;
		guiOptions.NeverInjectPathCount = policy.NeverInjectCount;   // ★ v51
		guiOptions.PromptTimeoutMs = policy.PromptTimeoutMs;
		// ★ v61：高危进程提示级别 —— 界面用它决定底部栏要不要多画一行。
		guiOptions.HighRiskProcessAlert = engineSettings.HighRiskProcessAlert;
		// ★ v62：ARK 页开关与间隔 —— 配置页只做展示，改它要改 ini 并重启。
		guiOptions.ArkEnabled = engineSettings.ArkEnabled;
		guiOptions.ArkScanMs = engineSettings.ArkScanMs;
		// ★ v63：界面刷新间隔（与扫描间隔是两件事，见 r3shieldcore_config.h）。
		guiOptions.ArkRefreshMs = engineSettings.ArkRefreshMs;

		if (R3ShieldCoreGui::Start(guiOptions)) {
			printf("界面窗口    : 已打开（关掉窗口不退出引擎，会继续在后台记录）\n");
		}
		else {
			printf("界面窗口    : 打开失败，详情写入 r3shieldcore-console.log\n");
		}

		if (std::wstring(GetCommandLineW()).find(L"--uiaccess-parent-pid=") != std::wstring::npos) {
			DWORD waitError = ERROR_SUCCESS;
			if (!R3ShieldCoreSuperDesk::WaitForUiAccessParentExit(15000, &waitError)) {
				printf("UIAccess 父引擎未退出，取消接管 err=%lu\n",
					static_cast<unsigned long>(waitError));
				R3ShieldCoreGui::Stop();
				return 1;
			}
		}

		printf("加载引擎... ");
		EngineControl engineControl(policy);
		printf("完成\n");

		// 统计聚合挂在事件通道上，必须在开始注入之前就位，
		// 否则第一批事件会漏统计。
		engineControl.SetEventObserver(&OnEventForStats, nullptr);

		//
		// ==================================================================
		// ★ v54：跨重启保留界面信息（在**第一批事件到达之前**做完）
		// ==================================================================
		//
		// 为什么必须在这个位置：
		//   · 回放要占用日志序号 1..N，实时事件必须从 N+1 开始 ——
		//     注入线程一起来就会灌事件，晚了序号就撞了。
		//   · 统计基线要在 OnEvent 累加**之前**灌进去，否则本轮的前几条
		//     会把基线冲掉（SeedHistory 里 g_totalEvents 取 max，能兜住，
		//     但语义上还是尽早灌更干净）。
		//
		// 两件事都不影响判定，纯粹是给界面看的历史。
		//
		if (engineSettings.PersistStats) {
			R3ShieldCoreStats::EnablePersistence(exeDirectory / L"r3shieldcore-stats.json");
		}

		if (engineSettings.ReplayHistoryLog && policy.LogPath[0]) {
			const size_t limit = engineSettings.ReplayHistoryLimit
				? engineSettings.ReplayHistoryLimit : 200;
			const R3ShieldCoreLogReplay::Result replay =
				R3ShieldCoreLogReplay::ReadTail(policy.LogPath, limit);

			if (!replay.Entries.empty()) {
				// 基线 = 上一轮落盘的总事件数（没有就退回"历史条数"）。
				const ULONGLONG baseline = R3ShieldCoreStats::PersistedTotalEvents();
				R3ShieldCoreStats::SeedHistory(replay.Entries,
					baseline > 0 ? baseline : replay.Entries.size());

				printf("回放历史    : %u 条（读 %u 行，实时事件从序号 %u 继续）\n",
					static_cast<unsigned>(replay.Entries.size()),
					static_cast<unsigned>(replay.LinesRead),
					static_cast<unsigned>(R3ShieldCoreStats::GetLatestLogSerial() + 1));
			}
			else {
				// ⚠️ "读不到"和"没有历史"是两件事，这里必须能分开：
				//    文件大小 > 0 却解析出 0 条 ⇒ 格式变了或编码坏了（要排查）。
				printf("回放历史    : 无（文件 %llu 字节，读 %u 行，解析 %u 条）\n",
					static_cast<unsigned long long>(replay.FileBytes),
					static_cast<unsigned>(replay.LinesRead),
					static_cast<unsigned>(replay.LinesParsed));
			}
		}

		printf("开始全局注入，正在接管非系统程序的注册表行为。详情写入 r3shieldcore-console.log。\n\n");

		// 覆盖层反制（引擎侧主动行为）。放在注入之后、主循环之前：
		// 它只在引擎进程里跑一份，靠 EnumWindows 直接看桌面，不依赖被注入进程。
		R3ShieldCoreSentinel::Start(engineSettings.NeutralizeOverlayLevel, policy.PromptTimeoutMs);
		if (R3ShieldCoreSentinel::IsEnabled()) {
			printf("覆盖层反制  : 已启用（级别 %lu：%s）\n\n",
				static_cast<unsigned long>(engineSettings.NeutralizeOverlayLevel),
				engineSettings.NeutralizeOverlayLevel >= 2 ? "每级弹窗询问" : "不问直接执行");
		}

		// ★ v61：高危进程提示（引擎侧主动行为，不依赖注入覆盖）。
		// 放在 sentinel 之后、主循环之前，同理：只在引擎进程里跑一份。
		// 支持/不支持用 SupportsHighRiskProcessCheck() 显式区分（铁律 97）：
		// 旧 DLL ⇒ 传 nullptr ⇒ procwatch 自己打「未启用：DLL 没有这个导出」；
		// 新 DLL ⇒ 传 thunk ⇒ 正常扫描。
		g_engineControlForProcWatch = &engineControl;
		const R3ShieldCoreProcWatch::CheckFn procWatchCheck =
			engineControl.SupportsHighRiskProcessCheck() ? &ProcWatchCheckThunk : nullptr;
		R3ShieldCoreProcWatch::Start(engineSettings.HighRiskProcessAlert,
			engineSettings.HighRiskProcessScanMs, procWatchCheck);

		// ★ v62：ARK（全机进程列表 + 四种处置）。
		//
		// 放在 procwatch 之后、主循环之前：它同样只在引擎进程里跑一份。
		//
		// 它需要三样东西，都由 `EngineControl` 提供：
		//   · `LocalEngineDllBase()` —— "内部退出"算导出偏移的参照原点；
		//   · `SupportsSelfExit()`   —— DLL 有没有那个导出（旧 DLL 就没有，
		//     必须能报成"功能不可用"而不是"执行失败"，铁律 97）；
		//   · 本进程 pid —— 拒绝"动自己"。
		//
		// ⚠️ 顺序：必须在 `EngineControl` 构造（= 已经 LoadLibrary 了 DLL）
		//    之后。放前面拿到的 `LocalEngineDllBase()` 会是 0，
		//    而 0 会被 `PerformInternalExit` 判成 ExportMissing ——
		//    症状是"内部退出永远不可用"，但看上去像 DLL 版本问题。
		{
			R3ShieldCoreArk::Config arkConfig = {};
			arkConfig.Level = engineSettings.ArkEnabled ? 1 : 0;
			arkConfig.ScanIntervalMs = engineSettings.ArkScanMs;
			arkConfig.SelfPid = GetCurrentProcessId();
			arkConfig.LocalDllBase = engineControl.LocalEngineDllBase();
			arkConfig.SelfExitSupported = engineControl.SupportsSelfExit();
			R3ShieldCoreArk::Start(arkConfig);
		}

		ULONG lastReportedDropped = 0;
		ULONG drainElapsedMs = 0;

		//
		// ==================================================================
		// ★★★ v41：新进程注入搬到**专用线程**，间隔收到毫秒级
		// ==================================================================
		//
		// 为什么（**真实绕过**）：样本 `Windows XP Horror` 在 `FormCreate` 里
		// （进程启动后几十~几百 ms）就 `CreateFileA("\\.\PhysicalDrive0")` +
		// `WriteFile` 把 MBR 写掉。而原来注入挂在主循环上、**1000ms 才扫一轮**
		// ⇒ 写入整个落在盲区里 ⇒ `mode=block` 没拦住。
		//
		// 为什么不能靠"同步注入"那条路：同步路要在**父进程**里 hook
		// `CreateProcessInternalW`，而双击的父进程是 `explorer.exe`
		// （提权后是 `svchost.exe`），两者都在 `ShouldSkipProcessInjection`
		// 的 `kNeverInject[]` 里（注入 shell / 服务宿主会破坏系统）
		// ⇒ 这条路对"用户手动运行的程序"**用不上**，只剩轮询路。
		//
		// 所以只能把轮询做快。空转时一轮只是一次 `NtGetNextProcess` 系统调用
		// （立刻返回 `STATUS_NO_MORE_ENTRIES`），10ms 间隔的 CPU 开销可忽略。
		//
		// ⚠️ 首轮**立刻**跑（循环体在 Sleep 之前）：把"引擎启动前就在运行"的
		//    进程一次注完，不用等一个间隔。
		//
		std::atomic<bool> stopInjection{ false };
		// ★ v54：起点取持久化基值 —— 让"已注入进程"这个数字跨重启连续。
		// （基值由前面的 EnablePersistence 从 r3shieldcore-stats.json 载入；
		//   未启用持久化时是 0，行为与旧版一致。）
		std::atomic<ULONG> injectedTotal{ R3ShieldCoreStats::GetInjectedBase() };
		const ULONG injectionIntervalMs = engineSettings.InjectionIntervalMs;

		// RAII 收尾：先置停止位、再 join。
		// ⚠️ 必须**早于** `EngineControl` 析构 —— 析构会反注入并销毁会话，
		//    线程若还在跑就会去调用一个正在拆的会话。
		struct InjectionThreadGuard
		{
			std::thread thread;
			std::atomic<bool>* stopFlag = nullptr;
			~InjectionThreadGuard() noexcept
			{
				if (stopFlag) {
					stopFlag->store(true, std::memory_order_relaxed);
				}
				if (thread.joinable()) {
					thread.join();
				}
			}
		};
		InjectionThreadGuard injectionGuard;
		injectionGuard.stopFlag = &stopInjection;
		injectionGuard.thread = std::thread([&engineControl, &stopInjection, &injectedTotal, injectionIntervalMs] {
			// 稍微提一点优先级：这场竞争的对象是"样本启动后到它写 MBR 之间"，
			// 让扫描线程比普通线程更容易抢到 CPU（不至于饿死别的线程）。
			SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

			//
			// ★★★ 让 `Sleep(5)` 真的是 5ms，而不是 15.6ms。
			//
			// Windows 的默认时钟粒度是 **15.6ms** —— 不提高分辨率的话，
			// `Sleep(任意小于 15.6 的值)` 都会睡到**下一个时钟中断**，
			// 也就是实际 ~15.6ms。那样 `inject_interval_ms` 调到 10 以下
			// **完全没有意义**（旋钮是假的）。
			//
			// `NtSetTimerResolution(10000, TRUE, ...)`（10000 × 100ns = 1ms）
			// 把粒度降到 1ms。⚠️ 这是**全系统**设置，会提高时钟中断频率
			// （功耗/笔记本续航的代价）—— 所以只在间隔 < 16ms 时才动它：
			// ≥16ms 时默认粒度已经够用，没必要白白增加中断。
			//
			if (injectionIntervalMs < 16) {
				using NtSetTimerResolution_t = LONG(NTAPI*)(ULONG, BOOLEAN, PULONG);
				if (HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll")) {
					if (auto setResolution = reinterpret_cast<NtSetTimerResolution_t>(
						GetProcAddress(hNtdll, "NtSetTimerResolution"))) {
						ULONG current = 0;
						setResolution(10000, TRUE, &current);
					}
				}
			}

			while (!stopInjection.load(std::memory_order_relaxed)) {
				int injected = 0;
				try {
					injected = engineControl.HandleNewProcesses();
				}
				catch (...) {
					injected = 0;   // 注入失败不该把扫描线程带走
				}
				if (injected > 0) {
					injectedTotal.fetch_add(static_cast<ULONG>(injected), std::memory_order_relaxed);
				}
				Sleep(injectionIntervalMs);
			}
		});

		ULONG lastReportedInjected = 0;
		ULONG saveTickCount = 0;   // ★ v54：统计落盘节流（100ms 切片计数）

		while (true) {
			// 主循环按 100ms 切片跑：模式切换按钮要立刻有反馈，
			// 事件排空与模式处理高频运行；注入扫描保持 1 秒一次。
			Sleep(100);
			if (R3ShieldCoreGui::TakeUiAccessRestartRequest()) {
				printf("UIAccess 新实例已接管，正在结束当前引擎会话。\n");
				break;
			}			// 用户点了界面上的「退出引擎」。和 UIAccess 接管走同一条收尾路径：
			// 跳出循环 → EngineControl 析构（反注入）→ R3ShieldCoreGui::Stop() → 进程退出。
			if (R3ShieldCoreGui::TakeQuitRequest()) {
				printf("用户点击「退出引擎」，正在结束当前引擎会话。\n");
				break;
			}

			// ★ v62：自动化用的优雅退出（R3SHIELDCORE_EXIT_AFTER_MS）。
			//   **刻意放在 TakeQuitRequest 旁边、走同一个 break** ——
			//   这样它证明的就是"用户点退出"那条路，而不是一条测试专用捷径。
			if (ShouldAutoExit()) {
				printf("R3SHIELDCORE_EXIT_AFTER_MS 到点，按「退出引擎」收尾"
					"（会先恢复本引擎挂起过的进程）。\n");
				break;
			}

		// 覆盖层反制：内部按 500ms 节流，未启用时立即返回。
		R3ShieldCoreSentinel::Tick();

		// v61 高危进程提示：内部按 scanIntervalMs 节流，未启用时立即返回。
		R3ShieldCoreProcWatch::Tick();

		// ★ v62 ARK：内部按 ark_scan_ms 节流；**动作队列每轮都排空**
		// （用户点了按钮就该尽快生效，不该等下一轮扫描）。
		R3ShieldCoreArk::Tick();

			drainElapsedMs += 100;

			R3ShieldCore::Mode requestedMode = R3ShieldCore::Mode::Log;
			if (R3ShieldCoreGui::TakePendingMode(requestedMode)) {
				ApplyMode(engineControl, requestedMode, exeDirectory);
			}

			// 高频排空，避免全开模式下后台进程的正常噪音在 1 秒内
			// 把环形缓冲区套圈。
			if (drainElapsedMs >= 100) {
				drainElapsedMs = 0;
				int drained = engineControl.DrainEvents();
				if (drained > 0) {
					printf("记录注册表行为: %d 条\n", drained);
				}
			}

			// 注入计数由**专用线程**累加（v41），这里只按增量打印一次日志。
			{
				const ULONG total = injectedTotal.load(std::memory_order_relaxed);
				if (total > lastReportedInjected) {
					printf("注入新进程: %lu 个\n",
						static_cast<unsigned long>(total - lastReportedInjected));
					lastReportedInjected = total;
				}
			}

			ULONG dropped = engineControl.DroppedEventCount();
			if (dropped > 0) {
				R3ShieldCoreStats::SetDroppedCount(dropped);
			}

			if (dropped > lastReportedDropped) {
				printf("警告: 事件缓冲区已满，累计丢弃 %u 条（可调大 R3ShieldCore::EventCapacity）\n", dropped);
				lastReportedDropped = dropped;
			}

			// 把询问统计从 DLL 读回来推给界面。
			R3ShieldCoreStats::PromptStat promptStat = {};
			engineControl.ReadPromptStats(promptStat.Shown, promptStat.Allowed,
				promptStat.Denied, promptStat.TimedOut);
			engineControl.ReadHighRiskStats(promptStat.HighRiskAsked,
				promptStat.HighRiskBlocked);
		R3ShieldCoreStats::SetPromptStat(promptStat);

		// ★ v61：把高危进程扫描统计从 procwatch 读回来推给界面（GUI 底部栏）。
		// procwatch 的 Stats 用定长 WCHAR[]，stats 用 wstring —— 直接赋值即可。
		{
			const R3ShieldCoreProcWatch::Stats pw = R3ShieldCoreProcWatch::GetStats();
			R3ShieldCoreStats::ProcWatchStat stat = {};
			stat.Scans = pw.Scans;
			stat.LastScanProcesses = pw.LastScanProcesses;
			stat.HighRiskFound = pw.HighRiskFound;
			stat.Alerts = pw.Alerts;
			stat.DedupEntries = pw.DedupEntries;
			stat.DedupCapacity = pw.DedupCapacity;
			stat.LatestPid = pw.LatestPid;
			stat.LatestName = pw.LatestName;
			stat.LatestPath = pw.LatestPath;
			stat.LatestReason = pw.LatestReason;
			R3ShieldCoreStats::SetProcWatchStat(stat);
		}

		// 把累计注入数喂给界面。
		R3ShieldCoreGui::Update(injectedTotal.load(std::memory_order_relaxed));

			//
			// ★ v54：统计落盘兜底。
			//
			// 正常退出时下面还会再存一次（那次是准的）。这里存在的意义是
			// **防 kill** —— 用户直接点任务管理器结束进程、或者机器断电，
			// 没有这个兜底就丢掉整轮的统计。
			//
			// 30s 一次：落盘是几 KB 的小文件，频率再高一点也无所谓，
			// 但没必要 —— 丢 30s 的计数比丢一整轮强得多。
			//
			++saveTickCount;
			if (engineSettings.PersistStats && saveTickCount >= 300) {
				saveTickCount = 0;
				R3ShieldCoreStats::SetInjectedBase(injectedTotal.load(std::memory_order_relaxed));
				R3ShieldCoreStats::SaveNow();
			}
		}

		// ★ v61：高危进程提示的收尾（打一行总结，重置去重表）。
		// 放在注入线程 join 之前不依赖任何顺序 —— 它只读写自己的静态状态。
		R3ShieldCoreProcWatch::Stop();
		g_engineControlForProcWatch = nullptr;

		// ★ v62：ARK 的收尾。**必须在 GUI 停掉之后、EngineControl 析构之前**：
		//   · 它会调用 `ArkActions::Perform` 去**恢复**本引擎挂起过的进程
		//     （见 r3shieldcore_ark.cpp 的 Stop）—— 这些动作不依赖会话；
		//   · 但界面还在跑的时候停它没有意义（界面会显示一个空列表）。
		R3ShieldCoreArk::Stop();

		//
		// ★ v54：正常退出前存最后一次（准的那次）。
		//
		// 位置很讲究：必须在 `injectionGuard` 析构**之前** ——
		// 它之后再读 `injectedTotal` 就可能被正在 join 的线程写，
		// 而且更重要的，落盘要走文件 I/O，不该和"反注入拆会话"抢时间。
		//
		// 另外：这里也包括 UIAccess 接管的退出路径（老引擎让位），
		// 所以即便用户只点了下「超级置顶」，这一轮的统计也不会丢。
		//
		if (engineSettings.PersistStats) {
			R3ShieldCoreStats::SetInjectedBase(injectedTotal.load(std::memory_order_relaxed));
			R3ShieldCoreStats::SaveNow();
			printf("统计已保存    : 累计事件 %llu 条，注入进程 %lu 个\n",
				static_cast<unsigned long long>(R3ShieldCoreStats::GetSnapshot().TotalEvents),
				static_cast<unsigned long>(injectedTotal.load(std::memory_order_relaxed)));
		}
	}
	catch (const std::exception& e) {
		WriteStartupFailure(e.what());
		printf("%s\n", e.what());
		R3ShieldCoreGui::Stop();
		// ★ 关掉界面之后再弹：此时框是屏幕上唯一的 UI，用户不可能错过。
		ShowStartupFailureDialog(e.what());
		return 1;
	}
	catch (...) {
		WriteStartupFailure("unknown non-standard exception");
		printf("unknown non-standard exception\n");
		R3ShieldCoreGui::Stop();
		ShowStartupFailureDialog("unknown non-standard exception");
		return 1;
	}

	R3ShieldCoreGui::Stop();
	return 0;
}
