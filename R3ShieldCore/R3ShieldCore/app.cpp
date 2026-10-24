#include "stdafx.h"
#include "functions.h"
// ★ v89：`engine_control.h`（同进程 LoadLibrary）已被 `engine_client.h` 取代。
//   引擎现在是独立进程，界面这一侧只跟**加密管道**打交道。
#include "engine_client.h"
#include "r3shieldcore_config.h"
#include "r3shieldcore_gui.h"
#include "r3shieldcore_log_replay.h"
#include "r3shieldcore_stats.h"
#include "r3shieldcore_superdesk.h"
#include "r3shieldcore_sentinel.h"
#include "r3shieldcore_procwatch.h"
#include "r3shieldcore_ark.h"
// ★ v81：配置工具 ⇄ 引擎 的管道**服务端**。
//   配置工具的日志页 / 配置页不再自己去 tail 日志文件，改成向引擎要数据；
//   引擎这边由它回答（协议在共享头 shared/r3shieldcore/cfg_ipc.h，铁律 127）。
#include "r3shieldcore_cfgipc.h"
// ★ v80：配置工具（r3shieldcore-cfg.exe）的启动 / 激活契约。
//   「高级」规则编辑台搬去了 cfg，主程序启动时要顺手把它拉起来。
//   窗口类名 / 激活消息 / 页号 / exe 名只在那个头里定义一份（铁律 127）。
#include <r3shieldcore/cfg_launch.h>
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
	// ★★★ v100：**机器级引擎熔断**（自动化脚本不得运行引擎的强制执行点）
	//
	// 背景（2026-10-23 事故，必须记住）：
	//   项目早就有铁律"自动化脚本不得运行引擎"—— 因为引擎会**全局注入**（白名单之外
	//   的一切，含 `cl.exe` 这类构建工具），并且在 `mode=ask` /
	//   `neutralize_overlay>=2` 下会**弹出置顶且抢前台焦点的询问窗**
	//   （`WS_EX_TOPMOST` + `SetForegroundWindow`，见 `r3shieldcore_sentinel.cpp`）。
	//
	//   ★ 注意：**白名单 `never_inject=` 挡不住这件事**。它只决定"往哪个进程
	//     注入 DLL"，而弹窗是**引擎进程自己创建的窗口**，与注入无关。
	//     所以"编辑器已经在白名单里" ≠ "误跑引擎不会影响编辑器"。
	//
	//   但那条铁律只写在文档里，**代码里没有任何强制**。于是只要有人
	//   （包括自动化探针）双击一次界面，界面就按默认行为拉起引擎，
	//   于是：编辑器无法输入（焦点被弹窗反复抢走）、`cl.exe` 每次操作
	//   等 30 秒询问超时 ⇒ 构建挂 19 分钟停不下来，最后只能重启机器。
	//
	//   ⇒ 把"不许跑"从**约定**变成**机制**：
	//     标记文件存在 ⇒ 界面**不连也不拉起**引擎，引擎自己也拒绝启动。
	//
	// 为什么用标记文件而不是编译宏：
	//   · 编译宏只保护"用某个开关编出来的那份"，而事故恰恰是随手用了
	//     `BuildCheck` 那份（免提权、专为探针编的）；
	//   · 标记文件是**机器级**的：不管谁编的、从哪个目录启动、双击还是探针，
	//     在这台机器上一律起不来。换机器不受影响。
	//
	// 关掉它（仅限确实要在这台机器上做注入验证时）：
	//   删掉 %ProgramData%\R3 Shield Core\NO_ENGINE 这一个文件即可。
	//   也可以在单次运行里用环境变量临时放行（见 EngineAllowedByEnv）。
	bool IsEngineKilledByMachineFlag(std::wstring* reasonOut) noexcept
	{
		// ① 环境变量：给"我明确知道自己在做什么"的一次性放行留口子。
		wchar_t allow[8] = {};
		if (GetEnvironmentVariableW(L"R3SHIELDCORE_ALLOW_ENGINE", allow,
			_countof(allow)) > 0 && allow[0] == L'1') {
			return false;
		}

		// ② 标记文件：%ProgramData%\R3 Shield Core\NO_ENGINE
		wchar_t programData[MAX_PATH * 2] = {};
		const DWORD n = GetEnvironmentVariableW(L"ProgramData", programData,
			_countof(programData));
		if (n == 0 || n >= _countof(programData)) {
			return false;   // 拿不到 ProgramData 就不拦（别把正常启动搞挂）
		}

		std::wstring flag = programData;
		if (!flag.empty() && flag.back() != L'\\') {
			flag += L'\\';
		}
		flag += L"R3 Shield Core\\NO_ENGINE";

		const DWORD attr = GetFileAttributesW(flag.c_str());
		if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
			return false;
		}

		if (reasonOut) {
			*reasonOut = flag;
		}
		return true;
	}

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
			// ★★★ v100 教训（**别再试 `_wfsopen` + `_dup2`**）：
			//
			//   我一度把它换成 `_wfsopen(..., _SH_DENYNO)` + `_dup2(_fileno(fresh),
			//   _fileno(stream))`，想让界面日志"运行期也能被读"。结果**日志整个
			//   写不出来**：GUI 子系统下 `_fileno(stdout) == -2`（没有 fd），
			//   `_dup2` 的目标 fd 是 -2 ⇒ 必然失败 ⇒ 打印
			//   `[diag] redirect pid=... stdout=1 stderr=-1 fallback=1`。
			//
			//   根因：`printf` 写的是 `stdout` 这个 **FILE\***，它内部记着自己的 fd。
			//   `_dup2` 只改**进程 fd 表**，不改那个 FILE* 的 fd 字段 ⇒ 流依旧无效。
			//   能把流**重新绑定**到新文件的只有 `freopen` 家族 —— 而它不接受
			//   共享模式参数。
			//
			//   ⇒ 结论：界面侧**只能用 `_wfreopen_s`**。想要"运行期可读"，
			//     正确做法是别碰 stdout：引擎侧已经用 `_wfsopen(_SH_DENYNO)` +
			//     自己的 `g_logFile` 写日志（不经过 stdout），那份是可读的。
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

	// ★★★ v103：把「引擎真值」铺进界面的 `Options`。
	//
	// 抽成函数是为了让**两处**共用同一份口径（铁律 127）：
	//   · 启动时喂一次（`R3ShieldCoreGui::Start` 之前）；
	//   · 「配置」页应用完、引擎重启之后再喂一次（`RefreshOptionsFromPolicy`）。
	// 抄两份的话迟早漂移，而漂移的后果是"拨了开关、重启完又弹回去"，
	// 用户会当成"开关还是点不动"。
	void FillGuiOptions(R3ShieldCoreGui::Options& guiOptions,
		const R3ShieldCore::Policy& policy,
		const R3ShieldCoreConfig::EngineSettings& engineSettings)
	{
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
		// ★ v62：ARK 页开关与间隔 —— 配置页改它要写 ini 并重启（v103 已可直接改）。
		guiOptions.ArkEnabled = engineSettings.ArkEnabled;
		guiOptions.ArkScanMs = engineSettings.ArkScanMs;
		// ★ v63：界面刷新间隔（与扫描间隔是两件事，见 r3shieldcore_config.h）。
		guiOptions.ArkRefreshMs = engineSettings.ArkRefreshMs;
		// ★ v78：「高级」页显示规则的三个总闸 —— 取自**引擎真正读到的那份
		//   Policy**（不是界面自己再解析一遍 ini）。默认全关。
		guiOptions.SpoofReg = (policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) != 0;
		guiOptions.SpoofClipboard = (policy.Flags2 & R3ShieldCore::FlagSpoofClipboard) != 0;
		guiOptions.SpoofRegEnum = (policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) != 0;
	}

	// ★★★ v103：配置应用完（引擎已重启）之后，让界面**重新读一遍真值**。
	//
	// ★ 为什么在 app.cpp 重读 ini 而不是问引擎要 Policy：
	//   引擎连上之后共享内存里的 Policy 才是权威，但读它要走
	//   `R3ShieldCoreEngine` 的会话 —— 这里只是"界面显示"，
	//   重读 ini 得到的值与引擎从同一份文件读到的**必然一致**
	//   （引擎重启时就是读的这一份）。少一次 IPC 往返，也不会因为
	//   引擎刚起来还没填好 Policy 而读到全零。
	//
	// `arkOverride`：`ark_enabled` 是**界面侧**设置（不属于 Policy），
	// 刚写完 ini 时 `LoadEngineSettings` 也会读到新值，所以一般不必传；
	// 传它是为了显式钉住"这次用户改的就是它"。
	void RefreshOptionsFromPolicy(const std::filesystem::path& exeDirectory,
		const bool* arkOverride)
	{
		R3ShieldCore::Policy policy = {};
		// ★ 用 `LoadFromFile` 钉住**具体文件**，不用 `Load()`
		//   （铁律 290：`Load()` 优先 ProgramData，闸门/调试时会假绿假红）。
		R3ShieldCoreConfig::LoadFromFile(policy,
			R3ShieldCoreConfig::ResolveConfigPath(exeDirectory), exeDirectory);

		R3ShieldCoreConfig::EngineSettings settings =
			R3ShieldCoreConfig::LoadEngineSettings(exeDirectory);
		if (arkOverride != nullptr) {
			settings.ArkEnabled = *arkOverride;
		}

		R3ShieldCoreGui::Options updated = {};
		FillGuiOptions(updated, policy, settings);
		// ★ `LogPath` 是 `const WCHAR*` 指向 `policy.LogPath` 内部缓冲 ——
		//   而 `policy` 是**栈上局部量**。交给 GUI 之前必须指到一块活着的内存。
		//   ⇒ 用 GUI 自己的存储：`SetOptions` 会把 `LogPath` 拷进静态缓冲。
		R3ShieldCoreGui::SetOptions(updated);

		printf("[config] 界面选项已刷新（hook_file=%d hook_reads=%d ark=%d）\n",
			updated.HookFile ? 1 : 0, updated.HookReads ? 1 : 0,
			updated.ArkEnabled ? 1 : 0);
		fflush(stdout);
	}

	// 界面点了「切换模式」按钮之后真正落地。
	//
	// 三件事，顺序无所谓但一件都不能少：
	//   ① 改 DLL 侧共享内存的 Mode —— 全局立刻生效（被注入进程每次判定都重读）
	//   ② 把新值写回 r3shieldcore.ini —— 让切换活过下次重启
	//   ③ 通知界面刷新徽章 —— 只有走到这里才变，切失败就保持原样
	//
	// ★ v69 注意：切换**不会**动 `test_inject_only=`（`SaveMode` 只改 `mode=`
	//   一行）。这是**安全的**：注入白名单与 `mode=` 解耦（只要名单非空就生效），
	//   所以"测试模式里点了切换 ⇒ 重启后退化成全局注入"这件事**不会发生**。
	// ★ v89：模式切换现在是一次**加密 IPC 请求**（引擎去改共享内存里的 Mode）。
	//   签名里多一个 `dllSupports` 出参：拆进程之后，"引擎连不上"和
	//   "DLL 不支持运行期切换"必须能分开报（铁律 97）——
	//   前者是部署问题，后者是版本问题，用户的下一步动作完全不同。
	void ApplyMode(R3ShieldCoreEngine::Client& engineClient, R3ShieldCore::Mode mode,
		const std::filesystem::path& exeDirectory)
	{
		// ★ v100 诊断：主循环确实消费到了切换请求。
		printf("[mode] ApplyMode 开始 mode=%lu 连接=%d\n",
			static_cast<unsigned long>(mode), engineClient.Connected() ? 1 : 0);
		fflush(stdout);

		bool engineReplied = false;
		const bool ok = engineClient.SetMode(mode, &engineReplied);
		// ★ 用 WideCharToMultiByte 转窄串，不用 `%ls` ——
		//   窄 printf 的 `%ls` 依赖 locale，中文日志会整行静默截断（铁律 252）。
		{
			const std::wstring& werr = engineClient.LastError();
			char errBuf[512] = {};
			if (!werr.empty()) {
				WideCharToMultiByte(CP_ACP, 0, werr.c_str(), -1, errBuf,
					sizeof(errBuf) - 1, nullptr, nullptr);
			}
			printf("[mode] SetMode 返回 ok=%d engineReplied=%d 错误=%s\n", ok ? 1 : 0,
				engineReplied ? 1 : 0, errBuf);
			fflush(stdout);
		}
		if (!ok) {
			// ★ v91：失败原因**必须同时进窗口**，不能只 `printf`。
			//   界面是 WINDOWS 子系统（没有控制台），printf 全进日志文件；
			//   而日志在运行期是独占打开的 ⇒ 用户永远看不到这行字，
			//   现象就是"点了切换完全没反应、徽章不变"（2026-10-23 实测）。
			std::wstring notice;
			if (engineReplied) {
				notice = L"模式切换失败：DLL 不支持运行期切换（版本不匹配？）";
			}
			else if (!engineClient.Connected()) {
				notice = L"模式切换失败：引擎未连接（" + engineClient.LastError() + L"）";
			}
			else {
				notice = L"模式切换失败：引擎没有应答（" + engineClient.LastError() + L"）";
			}
			// ★ 不用 `printf("%ls")` —— 窄 printf 的 `%ls` 依赖 locale，
			//   中文会整行静默截断（铁律 252）。手动转窄串。
			{
				char narrow[512] = {};
				WideCharToMultiByte(CP_ACP, 0, notice.c_str(), -1, narrow,
					sizeof(narrow) - 1, nullptr, nullptr);
				printf("%s\n", narrow);
				fflush(stdout);
			}
			R3ShieldCoreGui::ShowNotice(notice, 10000);
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
	// ★ v89：高危进程判据的跨函数桥（改走 IPC）。
	//
	// `R3ShieldCoreProcWatch::Start` 要的是一个普通函数指针（CheckFn），而判据
	// 现在在**引擎进程**里（`GlobalHookSessionCheckHighRiskProcess` 导出）。
	// 这里用一个文件静态指针 + 自由函数 thunk 把它接过去。
	//
	// ★ 和拆进程之前的区别：这条路现在是**同步 IPC 请求**（一次往返，
	//   本机管道通常 < 0.2ms），而 procwatch 默认 1000ms 才扫一轮、
	//   每轮最多几十个候选进程 —— 开销可以忽略。
	//   ⚠️ 但它**不是零成本**：引擎没连上时每次调用会立刻返回 nullptr
	//      （而不是等超时），所以断线状态下扫描不会卡。
	R3ShieldCoreEngine::Client* g_engineClientForProcWatch = nullptr;

	const char* ProcWatchCheckThunk(const wchar_t* imagePath, const wchar_t* systemRoot)
	{
		if (!g_engineClientForProcWatch || !imagePath) {
			return nullptr;
		}

		// ★★ v101：引擎没答 ⇒ **熔断 5 秒**，别把剩下几百个进程挨个再问一遍。
		//
		//   为什么必须熔断：这是**每个进程一次**的调用。引擎一旦不答，
		//   "一次超时 × 全机进程数"就是几十秒到十几分钟。2026-10-24 现场
		//   就是这么把主循环整场冻住的（当时这条链路还在主线程上），
		//   用户看到的是「切换模式 / 退出引擎 点了完全没反应」。
		//   扫描现在已搬到专用线程（procwatch.cpp 的 `ScanThreadProc`），
		//   熔断是为了别让那个线程白烧几百个超时 —— 也让退出时的 join 立刻返回。
		static thread_local ULONGLONG s_suspendUntilMs = 0;
		const ULONGLONG nowMs = GetTickCount64();
		if (nowMs < s_suspendUntilMs) {
			return nullptr;   // 熔断窗口内：直接判"不是高危"，**不发**请求
		}

		// ★ 返回的指针必须**活到下次调用**：procwatch 会把它当 C 字符串用。
		//   所以存进一个 thread_local 缓冲，而不是返回临时 std::wstring 的 data()。
		static thread_local std::string s_reason;
		std::wstring reason;
		bool reachable = false;
		const bool hit = g_engineClientForProcWatch->CheckHighRiskProcess(imagePath,
			systemRoot ? systemRoot : L"", reason, &reachable);
		if (!reachable) {
			// 引擎没答（断开 / 超时）⇒ 熔断 5 秒后重试。
			// 注意这里**不能**返回"命中"：宁可这一小段时间不判，也不能
			// 让一次断线变成几百次连续超时。
			s_suspendUntilMs = nowMs + 5000;
			return nullptr;
		}
		if (!hit) {
			return nullptr;
		}
		// 引擎回的是宽串；这里转成 UTF-8 存在线程局部缓冲里。
		s_reason.clear();
		if (!reason.empty()) {
			const int need = WideCharToMultiByte(CP_UTF8, 0, reason.c_str(), -1,
				nullptr, 0, nullptr, nullptr);
			if (need > 1) {
				s_reason.resize(static_cast<size_t>(need - 1));
				WideCharToMultiByte(CP_UTF8, 0, reason.c_str(), -1, s_reason.data(), need,
					nullptr, nullptr);
			}
		}
		return s_reason.c_str();
	}

	// ★ v89：ARK「内部退出」的 IPC 桥。
	//
	//   界面进程不再加载引擎 DLL ⇒ `ArkActions::Perform(InternalExit)` 在
	//   本地必然报 `ExportMissing`。这里把它转给引擎进程，由引擎用
	//   自己的 DLL 基址执行（语义与拆进程前一致）。
	bool ArkSelfExitThunk(DWORD pid, void* context, R3ShieldCoreArk::SelfExitResult* out)
	{
		auto* client = static_cast<R3ShieldCoreEngine::Client*>(context);
		if (!client || !out) {
			return false;
		}
		R3ShieldCoreEngine::Client::SelfExitResult r = {};
		if (!client->SelfExit(pid, r)) {
			return false;
		}
		out->Code = r.code;
		out->Win32Error = r.win32Error;
		out->ElapsedMs = r.elapsedMs;
		out->DllPresent = r.dllPresent;
		out->DllSameBuild = r.dllSameBuild;
		return true;
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

	// ★ v77 界面预览（--gui-preview）：建窗 + 一直跑着，**不初始化注入引擎**。
	//   用途 = 在开发机上安全地看 / 截图核对界面（铁律 175：本机禁跑引擎，
	//   因为全局注入会 hook 编辑器）。和 --topmost-selftest 一样必须在
	//   引擎初始化**之前**分流，否则会顺带注入一整套 hook。
	//   配合 R3SHIELDCORE_START_TAB=log|process|config|ark|advanced 指定页签。
	if (std::wstring(GetCommandLineW()).find(L"--gui-preview") != std::wstring::npos) {
		return R3ShieldCoreGui::RunPreview();
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

		//
		// ★ v68/v69：**限定注入范围**（ini: `test_inject_only=`；`mode=test` 是便捷写法）。
		//
		// 动机：本机做端到端验证时，全局注入会 hook 编辑器 ⇒ 崩（铁律 175）。
		//   把注入范围缩到一个**白名单**，引擎就能在开发机上安全地跑。
		//
		// ★ 为什么单独印一段、而不是并进上面那行：
		//   注入范围与 `mode=` 是**两件事**（只要名单非空就生效，见
		//   `functions.cpp` 里那段"解耦"的理由）。所以「模式」那行可能是
		//   BLOCK 也可能是 LOG，**看不出**引擎其实只在注入白名单 ——
		//   铁律 97：这件事必须可诊断，不能靠"我记得我配过"。
		//
		// ★ fail-closed：写了 `mode=test` 却没给名单 ⇒ 用户的本意是"只碰这几个
		//   进程"，实际会变成"一个都不注入"（引擎看着在跑、实际全盲）。宁可起不来，
		//   也不要一个"正常"的假实例（铁律 110：别让"全零"也算成立）。
		//   走 throw ⇒ 复用既有启动失败路径（startup-failure 日志 + 弹框 + 退出码 1）。
		//
		if ((policy.Flags2 & R3ShieldCore::FlagTestMode) && policy.TestInjectCount == 0) {
			throw std::runtime_error(
				"mode=test 已开启，但 test_inject_only= 一条都没有（或全是空白）。"
				"那样注入范围会缩成零个进程，引擎看着在跑却什么都不监控。"
				"请补上白名单，或把 mode= 改回 log。");
		}

		if (policy.TestInjectCount > 0) {
			// ⚠️ 本段是**窄**字符串 printf，走 936 代码页 ⇒ 不能出现 CP936 之外
			//   的符号（`⇒` U+21D2 会被 MSVC 报 C4566 并实际打出 `?`）。
			printf("\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			printf("!! 注入范围已被限定（test_inject_only=）                   !!\n");
			printf("!! 只注入下列白名单条目匹配的进程，其余**一律跳过**。       !!\n");
			printf("!! 名单之外的进程**完全不受监控**（一个 hook 都没有）。     !!\n");
			printf("!! 这是给开发机做验证用的；日常使用请把 test_inject_only=   !!\n");
			printf("!! 整行删掉（或注释掉），再重启引擎。                       !!\n");
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			if (policy.Flags2 & R3ShieldCore::FlagTestMode) {
				printf("（mode=test 的拦截行为 = LOG：只记录、全部放行）\n");
			}
			printf("测试白名单  : %u 条（ini: test_inject_only=，可重复/可逗号分隔）\n",
				static_cast<unsigned>(policy.TestInjectCount));
			for (ULONG i = 0; i < policy.TestInjectCount && i < R3ShieldCore::MaxTestInjectPaths; ++i) {
				printf("  [%u] %ls\n", static_cast<unsigned>(i), policy.TestInjectPaths[i]);
			}
			// ⚠️ 本行是**窄**字符串 printf，走 936 代码页 ⇒ 不能出现 CP936 之外
			//   的符号（`⇒` U+21D2 会被 MSVC 报 C4566 并实际打出 `?`）。
			printf("  匹配规则  : 含 \\ 或 / = 完整路径前缀（带路径边界）；否则 = 镜像基名（不区分大小写）\n");
			printf("\n");
		}

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
		// ★ v71：注册表值替换状态。触发面与截屏/剪贴板**不同** ——
		//   它只在 `protect_reg=` 命中的键上生效，所以**必须同时把名单打出来**，
		//   否则"名单为空 ⇒ 一个字节都没动"和"功能没写"在界面上一模一样
		//   （铁律 97：布尔判定必须可诊断）。
		if (policy.Flags2 & R3ShieldCore::FlagSpoofRegistry) {
			if (policy.ProtectRegCount > 0) {
				printf("  注册表值替换: 开（受保护位置的读返回全 0，长度/类型不变；名单 %u 条）\n",
					static_cast<unsigned>(policy.ProtectRegCount));
			}
			else {
				// ⚠️ 这是**窄**字符串 printf，走 936 代码页 ⇒ 不能出现 CP936
				//   之外的符号（`⇒` U+21D2 会被 MSVC 报 C4566 并实际打出 `?`）。
				//   同 473/491 行的规矩。
				printf("  注册表值替换: 开，但 protect_reg 名单为空，实际不生效（没有任何键受保护）\n");
			}
		}
		// ★ v72：注册表**枚举隐藏**状态。与值替换**共用触发面**
		//   （都只看 `protect_reg=`），所以同样必须把名单条数打出来 ——
		//   否则"名单为空 ⇒ 一项都没藏"与"功能没写"在界面上一模一样
		//   （铁律 97：布尔判定必须可诊断）。
		//   ⚠️ 与值替换是**两个独立的位**（风险画像不同：值替换长度不变、
		//   枚举隐藏长度会变），所以这里单独一行、单独判。
		if (policy.Flags2 & R3ShieldCore::FlagSpoofRegistryEnum) {
			if (policy.ProtectRegCount > 0) {
				printf("  注册表枚举隐藏: 开（受保护项从枚举结果里去掉，列表变短；名单 %u 条）\n",
					static_cast<unsigned>(policy.ProtectRegCount));
			}
			else {
				printf("  注册表枚举隐藏: 开，但 protect_reg 名单为空，实际不生效（没有任何键受保护）\n");
			}
		}
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
		// ★ v73：摄像头帧替换状态。只在 hook_camera 开着时才有意义
		//   （hook_camera=0 ⇒ CameraGuard 根本不装 hook，spoof 无处生效）。
		//   ⚠️ 三态而不是布尔（铁律 97）：只有"建读取器"这一条入口能替换，
		//   其余入口（VFW / 设备源 / 音频）**仍然直接拒绝** —— 必须说清楚，
		//   否则用户会以为"开了它就全放行了"。
		if (policy.Flags & R3ShieldCore::FlagHookCamera) {
			printf("  摄像头帧替换: %s\n", (policy.Flags2 & R3ShieldCore::FlagSpoofCamera)
				? "开（建读取器的那条路改为返回中性帧：RGB→全 0、YUV→Y16/UV128；"
				  "VFW/设备源/音频仍直接拒绝；压缩子类型如 MJPG 仍拒绝）"
				: "关（本应拒绝的摄像头数据流直接失败）");
		}
		// ★ v100 措辞更正：这里开的是**监控**，不是引擎自己装钩子。
		//   实际实现在 `R3ShieldCoreLib/input_hook_guard.cpp`：hook 的是
		//   **别人对 `SetWindowsHookEx` / `RegisterRawInputDevices` 的调用**，
		//   用来发现"有进程在装键盘/鼠标钩子或注册后台原始输入"。
		//   旧文案写"挂输入钩子"，会让人以为引擎自己挂钩子 ——
		//   2026-10-23 排查时我自己就被它误导过，以为是钩子吞了键盘输入。
		printf("监控输入钩子: %s\n", (policy.Flags & R3ShieldCore::FlagHookInputHook)
			? "是（hook 别人对 SetWindowsHookEx/RawInput 的调用；**引擎自己不装钩子**）"
			: "否");
		printf("挂截屏      : %s\n", (policy.Flags & R3ShieldCore::FlagHookScreen)
			? "是（BitBlt/StretchBlt/GetDIBits 源为屏幕 DC + PrintWindow）" : "否");
		// ★ v67：截屏替换状态。只在 hook_screen 开着时才有意义
		//   （hook_screen=0 ⇒ ScreenGuard 根本不装 hook，spoof 无处生效）。
		if (policy.Flags & R3ShieldCore::FlagHookScreen) {
			printf("  截屏替换  : %s\n", (policy.Flags2 & R3ShieldCore::FlagSpoofScreen)
				? "开（本应拒绝的截屏改为返回黑帧 —— 调用方以为成功）"
				: "关（本应拒绝的截屏直接失败）");
		}
		printf("挂 DLL 加载 : %s\n", (policy.Flags & R3ShieldCore::FlagHookDllLoad)
			? "是（LdrLoadDll + NtMapViewOfSection；仅非系统目录上报）" : "否");
		printf("挂剪贴板    : %s\n", (policy.Flags & R3ShieldCore::FlagHookClipboard)
			? "是（GetClipboardData 高危；OpenClipboard 只记录）" : "否");
		// ★ v70：剪贴板替换状态。同样只在 hook_clipboard 开着时才有意义
		//   （hook_clipboard=0 ⇒ ClipboardGuard 根本不装 hook）。
		if (policy.Flags & R3ShieldCore::FlagHookClipboard) {
			printf("  剪贴板替换: %s\n", (policy.Flags2 & R3ShieldCore::FlagSpoofClipboard)
				? "开（本应拒绝的剪贴板读取改为返回中性内容 —— 调用方以为成功）"
				: "关（本应拒绝的剪贴板读取直接失败）");
		}
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
		FillGuiOptions(guiOptions, policy, engineSettings);

		if (R3ShieldCoreGui::Start(guiOptions)) {
			printf("界面窗口    : 已打开（关掉窗口不退出引擎，会继续在后台记录）\n");

			// ★ v80：顺手把配置工具（r3shieldcore-cfg.exe）也拉起来。
			//
			//   为什么：v80 把「高级」规则编辑台从主程序**整块搬去**了 cfg
			//   （主程序那一页现在只剩一个跳转按钮）。既然用户几乎总要用它，
			//   就在启动时一起拉起来 —— 点「高级」时它是"已经在跑"的状态，
			//   直接被激活，不会多等一次冷启动。
			//
			//   ★ `quiet = true` 是这里的**关键**：这是自动行为，不是用户点的。
			//     · cfg 已经在跑 ⇒ 什么都不做（连切页都不做，更不抢焦点）；
			//     · 没在跑       ⇒ 最小化启动（SW_SHOWMINNOACTIVE），
			//                       且带上 `--quiet` —— 万一并发撞上
			//                       单实例互斥体，第二个进程会安静退出，
			//                       不会去"激活已有窗口"抢前台。
			//     （UIAccess 接管时父 / 子两个实例会并发走到这一段，
			//       这个 race 是真实存在的，见 cfg_launch.h 的 kQuietSwitch。）
			//
			//   ★ 失败**只记日志、不弹窗**：自动拉起失败不该在启动时拦一个框；
			//     用户真要用的时候点「高级」，那条路径会把原因画在页内。
			{
				R3ShieldCoreCfg::LaunchOptions cfgOptions;
				cfgOptions.page = R3ShieldCoreCfg::kPageAdvanced;
				cfgOptions.quiet = true;
				std::wstring cfgError;
				if (R3ShieldCoreCfg::LaunchOrActivate(cfgOptions, &cfgError)) {
					printf("配置工具    : 已拉起（r3shieldcore-cfg.exe）\n");
				}
				else {
					printf("配置工具    : 拉起失败 —— %ls\n", cfgError.c_str());
				}
				fflush(stdout);   // 铁律 80：诊断 printf 必须紧跟 fflush
			}
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

		// -----------------------------------------------------------------
		// ★★★ v89：连引擎（独立进程 + 加密管道）
		// -----------------------------------------------------------------
		//
		// 拆进程之前这里是 `EngineControl engineControl(policy);` —— 同进程
		// LoadLibrary 引擎 DLL。现在改成"连一个已经在跑（或现在拉起）的进程"。
		//
		// ⚠️ 连不上**不拦启动**：界面本身还有价值（看历史日志、改配置、排查），
		//    拦掉只会让用户"什么都看不到"。但必须**明说**（铁律 97）——
		//    底部状态栏会显示"引擎未连接"，日志里也有原因。
		printf("连接引擎... ");
		R3ShieldCoreEngine::Client engineClient;
		//
		// ★★★ v100：先过**机器级熔断**。命中就**既不连也不拉起**引擎。
		//
		//   这一条是为了让"自动化脚本不得运行引擎"从文档约定变成硬机制：
		//   引擎会全局注入（含 cl.exe），ask/覆盖层反制下还会弹**置顶抢焦点**
		//   的询问窗 ⇒ 编辑器无法输入 + 构建每次等 30 秒超时
		//   （2026-10-23 实测：无法输入 + 构建挂 19 分钟）。
		//   ★ 白名单 `never_inject=` 挡不住弹窗，别指望它。
		//   标记文件见 `IsEngineKilledByMachineFlag` 的注释。
		std::wstring engineKillFlag;
		const bool engineKilled = IsEngineKilledByMachineFlag(&engineKillFlag);
		bool engineConnected = false;
		if (engineKilled) {
			printf("已跳过（本机引擎熔断：%ls 存在）\n", engineKillFlag.c_str());
			printf("            界面照常可用（看日志/改配置/排查），但**不会拉起引擎、不做任何注入**。\n");
			printf("            确需在本机验证注入：删掉上面那个文件，或设 R3SHIELDCORE_ALLOW_ENGINE=1。\n");
		}
		else {
			engineConnected = engineClient.Start(exeDirectory, &OnEventForStats, nullptr);
			if (engineConnected) {
				printf("完成（pid=%lu，加密通道 AES-256-GCM）\n",
					static_cast<unsigned long>(engineClient.EnginePid()));
			}
			else {
				printf("失败 —— %ls\n", engineClient.LastError().c_str());
				printf("            界面继续运行，但**没有防护**；请检查 %s 是否在包里。\n",
					"r3shieldcore-engine.exe");
			}
		}
		fflush(stdout);   // 铁律 80：诊断 printf 必须紧跟 fflush

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

		//
		// ==================================================================
		// ★ v81：配置工具接口（管道服务端）
		// ==================================================================
		//
		// 为什么放在这里（引擎已连上、历史已回放完，主循环之前）：
		//   · CONFIG 回答的是**引擎真正读到的那份 Policy / EngineSettings**
		//     —— 两者在上面都已就位；
		//   · LOG 读的是 `R3ShieldCoreStats` 的环形缓冲 —— 放在回放之后，
		//     配置工具一连上就能看到"本次启动前的历史"（占序号 1..N），
		//     不必自己去读文件（这正是用户要的效果）；
		//   · 主循环一跑起来，`PollSync` 就能处理配置工具发来的"保存后同步"。
		//
		// ⚠️ 启动失败**不拦启动**：这只是"配置工具能不能向引擎要数据"，
		//    失败了配置工具会回落去读日志文件，引擎照常工作。
		//
		bool cfgIpcStarted = false;
		{
			R3ShieldCoreCfgIpcServer::Options ipcOptions;
			ipcOptions.Policy = &policy;
			ipcOptions.EngineSettings = &engineSettings;
			// ★ 与 `R3ShieldCoreConfig::Load` 内部用的是同一个解析函数
			//   （铁律 127：路径规则只写一份）—— 配置工具拿它和
			//   "自己算出来的配置文件路径"对，不一致时明说。
			ipcOptions.IniPath = R3ShieldCoreConfig::ResolveConfigPath(exeDirectory);
			ipcOptions.ExeDirectory = exeDirectory;

			cfgIpcStarted = R3ShieldCoreCfgIpcServer::Start(ipcOptions);
			if (cfgIpcStarted) {
				printf("配置工具接口: 已启动（%ls）\n",
					R3ShieldCoreCfgIpc::PipeName().c_str());
			}
			else {
				printf("配置工具接口: 启动失败（配置工具将回落为读日志文件）\n");
			}
			fflush(stdout);   // 铁律 80：诊断 printf 必须紧跟 fflush
		}

		// RAII 收尾：异常 / 提前返回也要把服务线程停掉。
		// ⚠️ 必须**早于**引擎连接断开 —— 服务线程持有
		//    `Options.Policy` 指针，那个对象就在本函数的同一个
		//    作用域里（声明顺序保证本 guard 先析构，见下面的 InjectionThreadGuard）。
		struct CfgIpcGuard
		{
			bool active = false;
			~CfgIpcGuard() noexcept
			{
				if (active) {
					R3ShieldCoreCfgIpcServer::Stop();
				}
			}
		};
		CfgIpcGuard cfgIpcGuard;
		cfgIpcGuard.active = cfgIpcStarted;

		printf("开始全局注入，正在接管非系统程序的注册表行为。详情写入 r3shieldcore-console.log。\n\n");

		// 覆盖层反制（引擎侧主动行为）。放在注入之后、主循环之前：
		// 它只在引擎进程里跑一份，靠 EnumWindows 直接看桌面，不依赖被注入进程。
		R3ShieldCoreSentinel::Start(engineSettings.NeutralizeOverlayLevel, policy.PromptTimeoutMs);
		if (R3ShieldCoreSentinel::IsEnabled()) {
			printf("覆盖层反制  : 已启用（级别 %lu：%s）\n\n",
				static_cast<unsigned long>(engineSettings.NeutralizeOverlayLevel),
				engineSettings.NeutralizeOverlayLevel >= 2 ? "每级弹窗询问" : "不问直接执行");
		}

		// ★ v61：高危进程提示（界面侧主动行为）。
		//
		// ★ v89：判据改走 IPC —— 它现在在引擎进程里（DLL 导出）。
		//   `g_engineClientForProcWatch` 在 `engineClient` 还活着的时候有效，
		//   收尾时先置空再让 client 析构（见下面的 Stop）。
		g_engineClientForProcWatch = engineConnected ? &engineClient : nullptr;
		const R3ShieldCoreProcWatch::CheckFn procWatchCheck =
			engineConnected ? &ProcWatchCheckThunk : nullptr;
		R3ShieldCoreProcWatch::Start(engineSettings.HighRiskProcessAlert,
			engineSettings.HighRiskProcessScanMs, procWatchCheck);

		// ★ v62：ARK（全机进程列表 + 四种处置）。
		//
		// ★★ v89 的关键变化：「内部退出」不再由界面执行。
		//   那个动作要用"本地引擎 DLL 基址"算导出偏移，而界面进程**已经不再
		//   LoadLibrary 那份 DLL 了**（分进程的必然结果）⇒ `LocalDllBase` 恒为 0，
		//   内部退出会永远报 `ExportMissing`（看上去像"包太旧"，极具误导性）。
		//   ⇒ 现在它走 `SelfExitViaIpc` 回调，由引擎进程用**它自己的**基址执行。
		//   挂起/恢复/强杀仍然是界面进程本地做（它们不需要 DLL）。
		{
			R3ShieldCoreArk::Config arkConfig = {};
			arkConfig.Level = engineSettings.ArkEnabled ? 1 : 0;
			arkConfig.ScanIntervalMs = engineSettings.ArkScanMs;
			arkConfig.SelfPid = GetCurrentProcessId();
			// 0 = 本进程没有引擎 DLL（v89 起恒为 0）；内部退出必须走 IPC。
			arkConfig.LocalDllBase = 0;
			// 同包部署 ⇒ 引擎必然带那个导出；真没有的话 IPC 会回 ExportMissing，
			// 界面照样能给出准确提示（比"猜"可靠）。
			arkConfig.SelfExitSupported = engineConnected;
			if (engineConnected) {
				arkConfig.SelfExitViaIpc = &ArkSelfExitThunk;
				arkConfig.SelfExitContext = &engineClient;
			}
			R3ShieldCoreArk::Start(arkConfig);
		}

		ULONG lastReportedDropped = 0;
		ULONG lastReportedInjected = 0;
		ULONG saveTickCount = 0;   // ★ v54：统计落盘节流（100ms 切片计数）

		//
		// ==================================================================
		// ★★★ v89：注入扫描已经搬去**引擎进程**
		// ==================================================================
		//
		// 拆进程之前这里有一个 10ms 间隔的专用线程调 `HandleNewProcesses()`
		// （理由见 HANDOVER：样本启动后几十~几百 ms 就写 MBR，1000ms 轮询是盲区）。
		// 现在那个线程在 `r3shieldcore-engine.exe` 里，**节奏与优先级一模一样**
		// （它自己 SetThreadPriority + NtSetTimerResolution，见 engine_main.cpp）。
		//
		// 界面这边只做一件事：每 100ms 从引擎推来的统计快照里读 `injectedTotal`。
		// ⇒ 这个数字**跨界面重启连续**（引擎不停，计数不停），比原来更准。
		//
		ULONG injectedTotal = R3ShieldCoreStats::GetInjectedBase();

		// ★ v89：退出时要不要**真的把引擎停掉**。
		//   ★★★ v102 修正：只有「用户点退出引擎」和「自动化退出」置 true；
		//   **UIAccess 接管必须置 false**（引擎是独立进程，界面重启跟它无关，
		//   停了会让新界面连不上、还撞引擎互斥体 —— 详见下方收尾处的说明）。
		//   而"关窗口收托盘"根本不走这里 —— 界面进程继续活着，引擎更不用说。
		bool stopEngineOnExit = false;

		while (true) {
			// 主循环按 100ms 切片跑：模式切换按钮要立刻有反馈。
			Sleep(100);

			// ★★★ v101：心跳搬到**循环最前面**（以前写在 TakeQuitRequest 之后）。
			//
			//   为什么必须搬：2026-10-24 那次主循环整场都没跑起来，而用户早就
			//   点过退出 —— 主循环一醒就 `break` 了，于是 `[loop]` **一行都没打出来**，
			//   结果"主循环卡死了"和"主循环起来了但第一轮就退出"在日志里
			//   长得一模一样（铁律 97 的翻版）。
			//   放在这里：只要循环进过一次，日志里就一定有这一行。
			{
				static ULONGLONG lastBeat = 0;
				const ULONGLONG now = GetTickCount64();
				if (lastBeat == 0 || (now - lastBeat) >= 60000) {
					lastBeat = now;
					printf("[loop] 主循环存活（运行 %llu 秒）\n", now / 1000);
					fflush(stdout);
				}
			}

			// ★★★ v102：UIAccess 接管**不停引擎** —— 这是 v89 拆进程的遗留错误。
			//
			//   2026-10-24 真机：用户点「超级置顶」⇒ 界面按 KSword 配方重启成
			//   UIAccess 实例 ⇒ 新实例显示**「引擎未连接」**，而且旧引擎退出后
			//   **一个引擎都不剩**（防护断档）。日志证据链（全部来自 dist 日志）：
			//     · 旧实例 `UIAccess handoff complete child=14104; requesting engine shutdown`
			//     · 旧实例 `引擎收尾: 已请求退出，引擎仍在收尾（反注入要恢复被挂起的进程）`
			//       ⇒ 引擎 3 秒内没退掉，**仍占着单实例互斥体**
			//     · 新实例 `连接引擎... 失败 —— 引擎已拉起但管道一直没出现（pid=25332）`
			//     · 新引擎 `已经有一个引擎在跑（互斥体 Local\R3ShieldCoreEngine.1 已存在），本实例退出`
			//
			//   为什么原来写 `true`：拆进程**之前**引擎是界面进程里 LoadLibrary
			//   出来的，UIAccess 重启 = 换进程 ⇒ 旧进程必须把引擎收掉、新进程重建。
			//   v89 之后引擎是**独立进程**、界面只是客户端 ⇒ 那条前提不成立了：
			//   旧界面关掉管道，引擎的管道服务端会立刻重新监听，新实例直接连上
			//   **同一个引擎** —— 既没有防护断档，也不用等引擎反注入收尾。
			//
			//   ⇒ 改成 false（只断开连接，引擎继续防护），与「关窗口收托盘」同语义。
			//   ⚠️ 判据：改完之后旧实例日志应出现「引擎收尾: 保持运行（pid=…），
			//      界面只是断开连接」；新实例日志应出现「完成（pid=<同一个 pid>）」。
			if (R3ShieldCoreGui::TakeUiAccessRestartRequest()) {
				printf("UIAccess 新实例已接管，旧界面只断开连接"
					"（引擎继续防护，由新实例接管同一个引擎）。\n");
				fflush(stdout);
				stopEngineOnExit = false;
				break;
			}
			// 用户点了界面上的「退出引擎」：跳出循环 → 通知引擎收尾（反注入）
			// → R3ShieldCoreGui::Stop() → 进程退出。
			//
			// ★ v102：**注意它和上面的 UIAccess 接管已经不是同一条路了** ——
			//   接管只断连接（引擎留着），这里才真的停引擎。两者都用 `break`
			//   跳出同一个循环，但 `stopEngineOnExit` 的取值相反。
			if (R3ShieldCoreGui::TakeQuitRequest()) {
				printf("[quit] 主循环收到退出请求\n");
				fflush(stdout);
				printf("用户点击「退出引擎」，正在结束当前引擎会话。\n");
				stopEngineOnExit = true;
				break;
			}

			// ★ v62：自动化用的优雅退出（R3SHIELDCORE_EXIT_AFTER_MS）。
			//   **刻意放在 TakeQuitRequest 旁边、走同一个 break** ——
			//   这样它证明的就是"用户点退出"那条路，而不是一条测试专用捷径。
			if (ShouldAutoExit()) {
				printf("R3SHIELDCORE_EXIT_AFTER_MS 到点，按「退出引擎」收尾"
					"（会先恢复本引擎挂起过的进程）。\n");
				stopEngineOnExit = true;
				break;
			}

		// 覆盖层反制：内部按 500ms 节流，未启用时立即返回。
		R3ShieldCoreSentinel::Tick();

		// v61 高危进程提示：内部按 scanIntervalMs 节流，未启用时立即返回。
		R3ShieldCoreProcWatch::Tick();

		// ★ v62 ARK：内部按 ark_scan_ms 节流；**动作队列每轮都排空**
		// （用户点了按钮就该尽快生效，不该等下一轮扫描）。
		R3ShieldCoreArk::Tick();

			// ★ v91：把引擎连接状态喂给界面 —— 连不上时徽章显示「未连接」，
			//   而不是继续显示一个"点了也切不动的模式"。
			R3ShieldCoreGui::SetEngineConnected(engineClient.Connected());

			// （v101：健康心跳已搬到循环最前面，见上面那段说明。）

			R3ShieldCore::Mode requestedMode = R3ShieldCore::Mode::Log;
			if (R3ShieldCoreGui::TakePendingMode(requestedMode)) {
				printf("[loop] 进入 ApplyMode\n");
				fflush(stdout);
				ApplyMode(engineClient, requestedMode, exeDirectory);
				printf("[loop] ApplyMode 返回\n");
				fflush(stdout);
			}

			// ★★★ v103：「配置」页的开关按下「应用并重启引擎」。
			//
			//   ★ 为什么必须在**主循环**做，不能界面自己去写：
			//     · 写 ini 要 `ResolveConfigPath`（ProgramData 优先），
			//       和 `SaveMode` 是同一套逻辑；
			//     · 改完之后必须**重启引擎**才生效 —— 这些开关决定的是
			//       注入 DLL 的 hook 面，落在共享内存的 `Policy` 块里，
			//       引擎只在 LoadLibrary 那一刻读它。
			//     · 重启引擎会反注入 + 恢复挂起进程，耗时以秒计 ——
			//       放在 UI 线程就是整屏卡死（v101 的教训）。
			{
				std::vector<std::wstring> configLines;
				bool arkPresent = false;
				bool arkEnabled = false;
				if (R3ShieldCoreGui::TakeConfigApplyRequest(configLines,
					arkPresent, arkEnabled)) {
					printf("[config] 收到配置应用请求：%zu 条 ini 改动 ark=%d/%d\n",
						configLines.size(), arkPresent ? 1 : 0, arkEnabled ? 1 : 0);
					fflush(stdout);

					// wstring 的 ini 行是 ASCII 键名（`hook_file=1`），
					// 直接窄化即可 —— 不做 locale 转换，避免 CP_ACP 把
					// 不认识的字符变成 `?` 写进文件。
					std::vector<std::string> entries;
					entries.reserve(configLines.size());
					for (const std::wstring& line : configLines) {
						std::string narrow;
						narrow.reserve(line.size());
						for (const wchar_t c : line) {
							narrow.push_back(static_cast<char>(c & 0x7F));
						}
						entries.push_back(narrow);
					}

					const bool saved = entries.empty()
						? true
						: R3ShieldCoreConfig::SaveEntries(entries, exeDirectory);
					if (!saved) {
						printf("[config] 写 ini 失败 —— **不重启引擎**（改了也没生效）\n");
						fflush(stdout);
						R3ShieldCoreGui::ShowNotice(
							L"配置写入失败（ini 打不开或没权限），引擎未重启", 10000);
					}
					else {
						printf("[config] ini 已写回，开始重启引擎\n");
						fflush(stdout);
						R3ShieldCoreGui::ShowNotice(
							L"配置已写入，正在重启引擎以生效…", 8000);

						// ★ 复用和「用户点退出引擎」**同一条**收尾路径之外的
						//   最轻做法：先 Stop(true) 停掉，再由客户端重新 Start。
						//   不 `break` 出主循环 —— 界面要留着（用户还得看结果）。
						if (engineConnected) {
							engineClient.Stop(true);
							printf("[config] 旧引擎已停：%ls\n",
								engineClient.StopReport().c_str());
							fflush(stdout);
						}
						engineConnected = engineClient.Start(exeDirectory,
							&OnEventForStats, nullptr);
						R3ShieldCoreGui::SetEngineConnected(engineConnected);
						if (engineConnected) {
							printf("[config] 引擎已重启（pid=%lu）\n",
								static_cast<unsigned long>(engineClient.EnginePid()));
							fflush(stdout);
							R3ShieldCoreGui::ShowNotice(
								L"配置已生效，引擎已重启", 8000);
						}
						else {
							printf("[config] 引擎重启失败：%ls\n",
								engineClient.LastError().c_str());
							fflush(stdout);
							R3ShieldCoreGui::ShowNotice(
								L"引擎重启失败：" + engineClient.LastError(), 15000);
						}

						// ★ 让界面**重新读一遍真值**：`g_pendingConfig` 的
						//   `dirty` 由 `SetOptions` 清 —— 那是唯一正确时机
						//   （新值已经到位的这一刻），早了会让开关先弹回旧值。
						RefreshOptionsFromPolicy(
							exeDirectory, arkPresent ? &arkEnabled : nullptr);
					}
				}
			}

			// ★ v81 → v89：处理配置工具发来的「保存后立即同步」（重读 ini + 热应用）。
			//
			//   拆进程之前这里直接拿 `EngineControl` 去 `SetMode`。现在引擎在
			//   另一个进程里 ⇒ 同步请求变成一次**加密 IPC 往返**，由引擎去改
			//   共享内存里的 Mode。语义不变，只是多了一跳。
			//
			//   没有请求时它只是一次原子读，开销可忽略。
			R3ShieldCoreCfgIpcServer::PollSync(engineClient);

			// ★★★ v89：引擎推来的统计快照。
			//
			//   引擎每 200ms 推一次（`engine_main.cpp` 的 pusher 线程），界面这里
			//   读的是**本地缓存**，不阻塞、不发请求。断线时缓存保持不变
			//   （数字停住，而不是归零 —— 归零会被误读成"事件清零了"）。
			const R3ShieldCoreEngineIpc::StatsPayload es = engineClient.LatestStats();

			injectedTotal = es.injectedTotal;
			if (injectedTotal > lastReportedInjected) {
				printf("注入新进程: %lu 个\n",
					static_cast<unsigned long>(injectedTotal - lastReportedInjected));
				lastReportedInjected = injectedTotal;
			}

			if (es.droppedEvents > 0) {
				R3ShieldCoreStats::SetDroppedCount(es.droppedEvents);
			}
			if (es.droppedEvents > lastReportedDropped) {
				printf("警告: 事件缓冲区已满，累计丢弃 %lu 条（可调大 R3ShieldCore::EventCapacity）\n",
					static_cast<unsigned long>(es.droppedEvents));
				lastReportedDropped = es.droppedEvents;
			}

			// 询问统计（弹窗发生在被注入的进程里，计数写在共享内存 Policy 块，
			// 由引擎读出来推给我们）。
			{
				R3ShieldCoreStats::PromptStat promptStat = {};
				promptStat.Shown = es.promptShown;
				promptStat.Allowed = es.promptAllowed;
				promptStat.Denied = es.promptDenied;
				promptStat.TimedOut = es.promptTimedOut;
				promptStat.HighRiskAsked = es.highRiskAsked;
				promptStat.HighRiskBlocked = es.highRiskBlocked;
				R3ShieldCoreStats::SetPromptStat(promptStat);
			}

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
			R3ShieldCoreGui::Update(injectedTotal);

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
				R3ShieldCoreStats::SetInjectedBase(injectedTotal);
				R3ShieldCoreStats::SaveNow();
			}
		}

		// ★ v61：高危进程提示的收尾（打一行总结，重置去重表）。
		//
		// ★★★ v101：**顺序在这里变成了硬约束**。
		//   v101 起扫描跑在 procwatch 自己的线程上，而它每一步都要通过
		//   `g_engineClientForProcWatch` 问引擎（加密 IPC）。所以：
		//     · `Stop()` 必须**真的把那个线程 join 掉**（它内部等 8 秒）；
		//     · 之后才能把 `g_engineClientForProcWatch` 置空、再让
		//       `engineClient` 析构 —— 否则扫描线程会拿着野指针发请求。
		//   下面这两行的先后顺序**不能调换**。
		R3ShieldCoreProcWatch::Stop();
		g_engineClientForProcWatch = nullptr;

		// ★ v62：ARK 的收尾。**必须在 GUI 停掉之后、引擎连接断开之前**：
		//   · 它会调用 `ArkActions::Perform` 去**恢复**本引擎挂起过的进程
		//     （见 r3shieldcore_ark.cpp 的 Stop）—— 这些动作不依赖会话；
		//   · 但界面还在跑的时候停它没有意义（界面会显示一个空列表）。
		R3ShieldCoreArk::Stop();

		//
		// ★★★ v89：断开引擎连接（最后一步"业务"收尾）。
		//
		//   ★ `stopEngineOnExit` 的语义是**"这次界面退出，要不要连引擎一起带走"**：
		//       true  ⇒ 发 StopEngine，引擎反注入 + 销毁会话后自己退出；
		//       false ⇒ 只断开管道，引擎**继续防护**。
		//
		//   它的取值只有 3 个来源（全在 `main()` 里）：
		//     ① 默认 false（声明处的初值）；
		//     ② **UIAccess 新实例接管**（`TakeUiAccessRestartRequest()` 分支）
		//        ⇒ 必须 false，见下面的 v102 说明；
		//     ③ 用户点了界面上的「退出引擎」（`TakeQuitRequest()` 分支）
		//        ⇒ 必须 true，这是唯一该真停引擎的地方。
		//
		//   为什么 false 是一个有意义的分支（而不是"顺手写的"）：
		//     分进程的全部意义就在这里 —— 界面只是一个显示器。
		//     用户关窗口（收托盘）走的是另一条路，根本不进这个函数；
		//     真正走到这里且 stopEngineOnExit=false 的，是上面 ① 和 ②。
		//     此时引擎留着是对的：重新打开界面会直接连上它，防护中间没有断档。
		//
		//   ★★★ v102：② 曾经被写成 true，这就是「开启置顶之后显示引擎未连接」
		//     的根因。v89 拆进程**之前**引擎活在界面进程里，界面为了变成
		//     UIAccess 必须重启自己 ⇒ 只能把引擎一起停掉再重建；拆进程
		//     **之后**引擎是独立进程、有自己的 pid 和互斥体，界面重启跟它
		//     一点关系都没有。写成 true 的后果（实测日志）：
		//       · 旧实例发 StopEngine，引擎要恢复被挂起的进程，3 秒内退不掉；
		//       · 新实例这时启动，`ConnectOnly` 连不上（管道已关）；
		//       · `LaunchEngine` 拉新引擎 ⇒ 撞上 `Local\R3ShieldCoreEngine.1`
		//         互斥体 ⇒ 新引擎打印"已经有一个引擎在跑"后自己退出；
		//       · 新界面报"引擎已拉起但管道一直没出现" ⇒ 界面显示**未连接**；
		//       · 旧引擎最终退完 ⇒ 一个引擎都不剩，防护**断档**。
		//     ⇒ 改成 false 之后，新旧实例接管的是**同一个**引擎进程，
		//       防护零断档，界面也不会再报未连接。
		//
		//   顺序：必须**在 ARK 恢复挂起进程之后**（那步是本地动作，不依赖引擎），
		//   也必须**在配置工具接口停止之前**（它可能还有一次 SYNC 在途）。
		//
		if (engineConnected) {
			if (stopEngineOnExit) {
				// ★ v90：先 Stop（它会真的等引擎退出并把结论写进 StopReport），
				//   再按**实际结果**打印 —— 不再无条件说"已请求退出"。
				engineClient.Stop(true);
				printf("引擎收尾    : %ls\n", engineClient.StopReport().c_str());
			}
			else {
				printf("引擎收尾    : 保持运行（pid=%lu），界面只是断开连接\n",
					static_cast<unsigned long>(engineClient.EnginePid()));
				fflush(stdout);
				engineClient.Stop(false);
			}
			fflush(stdout);
		}

		//
		// ★ v81：配置工具接口的收尾。
		//
		// 位置：在 GUI / ARK 停掉之后、引擎连接断开之前。
		//   · 服务线程持有 `Options.Policy` 指针（就是本作用域的 `policy`），
		//     所以必须早于它析构 —— `CfgIpcGuard` 也会兜一次（Stop 可重复调）。
		//   · 这里先停：正在等 SYNC 结论的配置工具会立刻拿到 ERR，
		//     而不是干等 5 秒（引擎要退出了，它等不到结果）。
		//
		// 计数打出来是**为了核对**：探针可以据此判断"配置工具到底有没有连上、
		// 有没有真的走过管道"，而不是只看界面上有没有字。
		//
		{
			const R3ShieldCoreCfgIpcServer::Stats ipc = R3ShieldCoreCfgIpcServer::GetStats();
			printf("配置工具接口: 关闭（连接 %lu 次，日志 %lu 次，配置 %lu 次，同步 %lu 次，"
				"错误 %lu，无法识别 %lu）\n",
				static_cast<unsigned long>(ipc.Accepted),
				static_cast<unsigned long>(ipc.LogRequests),
				static_cast<unsigned long>(ipc.ConfigRequests),
				static_cast<unsigned long>(ipc.SyncRequests),
				static_cast<unsigned long>(ipc.Errors),
				static_cast<unsigned long>(ipc.Malformed));
			fflush(stdout);
			R3ShieldCoreCfgIpcServer::Stop();
		}

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
			R3ShieldCoreStats::SetInjectedBase(injectedTotal);
			R3ShieldCoreStats::SaveNow();
			printf("统计已保存    : 累计事件 %llu 条，注入进程 %lu 个\n",
				static_cast<unsigned long long>(R3ShieldCoreStats::GetSnapshot().TotalEvents),
				static_cast<unsigned long>(injectedTotal));
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
