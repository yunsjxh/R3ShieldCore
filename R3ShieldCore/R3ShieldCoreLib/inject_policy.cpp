#include "inject_policy.h"

#include <string.h>
#include <wctype.h>

//
// ⚠️ 本文件**故意只依赖 <windows.h> / <string.h>**：
//    不要 include "stdafx.h"、不要碰共享内存或 Policy。
//    理由：它要被 `build_ut.sh` 单独链成单元测试（只链 kernel32），
//    这是本项目"判据表单独成文件 + 纯函数分类"的既有套路
//    （对照 `r3shieldcore_rules.cpp`）。铁律 9：判"漏没漏"看探针不看 grep。
//

namespace
{
	//
	// 完全不注入。
	//
	// 这些进程跑在 **UAC / 安全桌面**路径上，或是**会话核心**。
	// 注进去可能在 `consent.exe` 显示 UI 之前就把它弄坏（v29 那条实测：
	// UAC 提权链任一环静默拒 = UAC 框根本不出现）。
	//
	// ⚠️ 与"瘦注入名单"的区别：这里**连 CreateProcessInternalW 都不挂**。
	//    判断标准 = 「注进去会不会把**系统本身**弄坏」，而不是"有没有用"。
	//
	constexpr PCWSTR kNeverInject[] = {
		L"consent.exe", L"CredentialUIBroker.exe", L"LogonUI.exe",
		L"winlogon.exe", L"csrss.exe", L"smss.exe", L"wininit.exe",
		L"services.exe", L"lsass.exe", L"lsaiso.exe",
		L"dwm.exe", L"fontdrvhost.exe", L"sihost.exe", L"taskhostw.exe",
		L"ctfmon.exe", L"audiodg.exe", L"conhost.exe",
		L"WUDFHost.exe", L"dllhost.exe", L"SearchIndexer.exe",
		L"SecurityHealthSystray.exe", L"SecurityHealthService.exe",

		//
		// Windows 11 文本输入 / Shell 代理进程（SystemApps 下，v34 补）。
		//
		// ★ 为什么必须列：`ctfmon.exe` 是**旧**的文本服务宿主，已经在上面；
		//   Win10/11 换成了 `TextInputHost.exe`（"Windows 输入体验"），
		//   路径 = `C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe`。
		//   它**不在**具体文件白名单（35 个核心进程）、**也不在** `%ProgramFiles%\WindowsApps\`，
		//   而且原先没列它 ⇒ 引擎**会注入它**。
		//
		//   后果（用户实测症状）：TextInputHost 是**全系统文本框**的 TSF/IME 代理 ——
		//   所有程序的「点击输入框后敲键盘没反应」「光标恒为 I 型」都指向它；
		//   而按钮/菜单/拖窗口不走它 ⇒ 表现为「只有输入框打不了字，但所有程序都这样」。
		//   它还是**按需启动**的：你点输入框那一刻它才被 CreateProcess 拉起来，
		//   正好落在注入器「进程启动期映射几十个映像」的时间窗里（见 v23 那条实测）。
		//
		//   ⚠️ 与 `registry_guard.cpp` 的 v24 修正是**两件事**：
		//     v24 加 `%SystemRoot%\SystemApps\` 是为了让它们的**注册表写入**不被拦；
		//     这里是要让它们**根本不被挂 hook**（bypass 与"不注入"是两条独立判据，
		//     `ShouldSkipProcessInjection` 才是真正决定"注不注入"的那个 —— 铁律 29）。
		//
		//   ★★ v42 复核：这几个（TextInputHost / ShellExperienceHost /
		//      StartMenuExperienceHost / SearchHost）**故意不进瘦名单**。
		//      理由是它们是**叶子 UI 进程**——不负责拉起用户程序，
		//      瘦注入对它们**零收益**、却仍有"映射 DLL 拖慢启动"的风险
		//      （v34 的故障就是这么来的）。收益为零就别冒风险。
		//
		L"TextInputHost.exe",
		L"ShellExperienceHost.exe",
		L"StartMenuExperienceHost.exe",
		L"SearchHost.exe",
	};

	//
	// ★★ v42 瘦注入名单：**会被注入**，但只装 `CreateProcessInternalW`
	//    这一个 hook（拿到"子进程跑第一行代码前就挂好"的**同步路**），
	//    **不装任何 guard**。
	//
	// 准入标准（三条都要满足）：
	//   ① 它**会当用户程序的父进程**（否则瘦注入毫无意义）；
	//   ② 它**不是**安全桌面 / 会话核心（注进去不会把系统弄坏）；
	//   ③ 它**不是叶子 UI 进程**（那种情况收益为零、风险非零）。
	//
	// 逐个说明：
	//   · `explorer.exe` —— ★ 最大收益。**双击桌面/资源管理器里的 exe**、
	//     `Win+R`、开始菜单启动，父进程都是它。它也是**文件 I/O 最热**的进程
	//     （每开一个目录、每张缩略图、每次拖放），所以**绝不能**给它装
	//     file/registry 等 guard —— 只装进程创建这一个。
	//   · `svchost.exe` —— UAC 提权链：用户双击一个 `requireAdministrator`
	//     的程序 → `consent.exe` 弹框 → 用户同意后由 **AppInfo 服务**
	//     （`svchost.exe -k netsvcs -s AppInfo`）`CreateProcessAsUser` 拉起提权进程。
	//     所以提权进程的父进程是 svchost，不注入它就拿不到同步路。
	//     ⚠️ 注意：本模块只按**镜像名**分类，分不出"哪个 svchost 是 AppInfo"
	//     ⇒ 所有 svchost 都会被瘦注入。代价是若干个实例各映射一次 DLL，
	//     可接受（瘦会话不装 guard，开销远小于完整会话）。
	//   · `runtimebroker.exe` —— UWP / Shell 代理，部分启动走它。
	//   · `ShellExperienceHost.exe` 等已在"绝不注入"名单，见上面理由。
	//
	// ⚠️ 排除 `consent.exe` / `LogonUI.exe` / `winlogon.exe` 等：
	//    它们跑在安全桌面上，弄坏的代价是"UAC / 登录界面直接不可用"，
	//    而它们**并不负责拉起被监控的用户程序**（提权进程由 AppInfo 拉起，
	//    不是 consent 自己）⇒ 收益小、风险大，留在"绝不注入"。
	//
	// ⚠️ 排除 `dllhost.exe`：它是 COM 代理宿主，会拉起东西，但同时也是
	//    系统大量 COM 组件的宿主，历史上（v34 同类故障）注入它引起过
	//    组件失灵。**保守起见先不加**；真需要时加进来即可（只改这张表）。
	//
	constexpr PCWSTR kThinInject[] = {
		L"explorer.exe",
		L"svchost.exe",
		L"runtimebroker.exe",
	};

	bool BaseNameInList(PCWSTR baseName, const PCWSTR* list, size_t count) noexcept
	{
		if (!baseName || baseName[0] == L'\0') {
			return false;
		}

		for (size_t i = 0; i < count; ++i) {
			if (_wcsicmp(baseName, list[i]) == 0) {
				return true;
			}
		}
		return false;
	}

	// 从完整路径里取基础名。没有分隔符时返回原串。
	PCWSTR BaseNameOf(PCWSTR path) noexcept
	{
		if (!path) {
			return L"";
		}

		PCWSTR back = wcsrchr(path, L'\\');
		PCWSTR forward = wcsrchr(path, L'/');
		PCWSTR sep = back;
		if (!sep || (forward && forward > sep)) {
			sep = forward;
		}
		return sep ? sep + 1 : path;
	}

	// 路径是否落在 %SystemRoot%\ 下（不区分大小写）。
	bool IsUnderWindowsDirectory(PCWSTR imagePath) noexcept
	{
		WCHAR windowsDirectory[MAX_PATH] = {};
		const UINT windowsLength = GetWindowsDirectoryW(windowsDirectory, _countof(windowsDirectory));
		if (windowsLength == 0 || windowsLength >= _countof(windowsDirectory)) {
			return false;
		}

		if (_wcsnicmp(imagePath, windowsDirectory, windowsLength) != 0) {
			return false;
		}

		return imagePath[windowsLength] == L'\\' || imagePath[windowsLength] == L'/';
	}

	// ------------------------------------------------------------------
	// ★ v53：VMware Tools —— 内置「绝不注入」。
	//
	// 为什么**内置**、而不是让用户写进 ini：
	//   VMware Tools 是**每个虚拟机 guest 都有的通用组件**（对照
	//   `never_inject=D:\Program Files\WorkBuddyAI\` 那种本机特有路径），
	//   而且本包有 **5 个预设 ini** —— 写 ini 就得 5 处同步维护，
	//   漏一个预设就变成"换个模式就失效"。
	//
	// 为什么必须**绝不注入**（真实后果，不是理论）：
	//   · ★ 共享剪贴板是**取证通道**。VMware Tools 的会话代理
	//     （`vmtoolsd.exe -n vmusr` / `vmware-user-svc.exe`）靠
	//     `GetClipboardData` 把 guest 剪贴板推给宿主机；而引擎在 block
	//     模式下**正是拦 `GetClipboardData`**（`clipboard_guard.cpp:128`）
	//     ⇒ 注进去 = guest→host 剪贴板直接死 ⇒ GUI「复制全部日志」的产出
	//     传不到宿主机（用户报的正是"日志拿不出来"）。
	//   · 已有两次先例：`dll_load_guard.cpp` 记录 vmtoolsd 的映像映射被
	//     误判成手工映射而拒（v23）；`process_guard.cpp` 记录 VMware Tools
	//     的进程创建被"一刀切拒掉"（v21 之前）。
	//   · 它**不负责拉起被监控的用户程序**（不是 explorer / svchost 那种
	//     父进程角色）⇒ 瘦注入对它是**零收益**，只留"映射 DLL"的风险。
	//
	// ⚠️ 身份 = **路径**，不是文件名：按文件名等于白送一张"改名叫
	//    `vmtoolsd.exe` 就免注入"的免死金牌（本文件上面已写明这个坑）。
	//    要求路径形如 `<盘符>:\Program Files[\ (x86)]\VMware\VMware Tools\…`
	//    —— 想伪造就得先拿到"写 Program Files 根"的管理员权限。
	//
	// ⚠️ 刻意**不用** `%ProgramFiles%` 环境变量：那个值可被调用方改写，
	//    而这里要的是"不可伪造"。用字面量 `Program Files` + 盘符任意，
	//    既覆盖"Windows 装在别的盘"，也不给环境变量留后门。
	//
	bool ProgramFilesRootRest(PCWSTR path, PCWSTR* rest) noexcept
	{
		// 形如 `X:\` / `X:/`
		if (!path || !iswalpha(static_cast<wint_t>(path[0])) || path[1] != L':' ||
			(path[2] != L'\\' && path[2] != L'/')) {
			return false;
		}

		PCWSTR cursor = path + 3;

		if (_wcsnicmp(cursor, L"Program Files", 13) != 0) {
			return false;
		}
		cursor += 13;

		// `Program Files (x86)` 也认。
		if (_wcsnicmp(cursor, L" (x86)", 6) == 0) {
			cursor += 6;
		}

		// ★ 必须是**目录边界** —— 否则 `X:\Program FilesXYZ\...` 会被误认。
		if (*cursor != L'\\' && *cursor != L'/') {
			return false;
		}

		*rest = cursor + 1;
		return true;
	}

	bool IsVmwareToolsImage(PCWSTR imagePath) noexcept
	{
		PCWSTR rest = nullptr;
		if (!ProgramFilesRootRest(imagePath, &rest)) {
			return false;
		}

		// `VMware\VMware Tools\` 之后任意 —— 覆盖 `vmtoolsd.exe`、
		// `vmware-user-svc.exe`、`vmware-tray.exe`、`vmware-resolutionSet.exe` 等。
		// 长度 20 = "VMware"(6) + "\"(1) + "VMware Tools"(12) + "\"(1)。
		return _wcsnicmp(rest, L"VMware\\VMware Tools\\", 20) == 0;
	}
}

namespace InjectPolicy
{
	Mode ClassifyImagePath(PCWSTR imagePath, bool thinAllowed) noexcept
	{
		if (!imagePath || imagePath[0] == L'\0') {
			return Mode::Full;
		}

		//
		// ★★ 去掉 Win32 长路径 / NT 前缀。
		//
		// 为什么必须做：`QueryFullProcessImageNameW` 与 `GetModuleFileNameW`
		// 在**路径超过 MAX_PATH** 时会返回 `\\?\C:\...` 形式，NT 形式是
		// `\??\C:\...`。不剥掉的话：
		//   · 引擎侧 `ShouldSkipProcessInjection` 判不出来 ⇒ 该 Skip/Thin 的
		//     变成 Full（**方向安全**，只是多监控）；
		//   · 但 DLL 侧 `ClassifyCurrentProcess` 同样判不出来 ⇒ 一个长路径的
		//     `explorer.exe` 会以**完整会话**启动，把 file/registry/net 全量
		//     hook 装进桌面 —— 那是最危险的误判方向。
		// 所以这里统一剥前缀，两个方向都保住。
		//
		if (wcsncmp(imagePath, L"\\\\?\\", 4) == 0) {
			imagePath += 4;
			// `\\?\UNC\server\share\...` 映射不回 %SystemRoot%，只能判 Full。
			if (_wcsnicmp(imagePath, L"UNC\\", 4) == 0) {
				return Mode::Full;
			}
		}
		else if (wcsncmp(imagePath, L"\\??\\", 4) == 0) {
			imagePath += 4;
		}

		//
		// ★ v53：内置「绝不注入」**路径**判据（VMware Tools）。
		//
		// ⚠️ 必须放在 `IsUnderWindowsDirectory` 这道门**之前** ——
		//    VMware Tools 装在 `Program Files` 下、**不在** Windows 目录，
		//    放到后面就永远到不了 ⇒ 变成"规则写了但命中不了"的**假豁免**
		//    （和铁律 34「挂了 API ≠ 行为被覆盖」同一类陷阱）。
		//
		if (IsBuiltinNeverInjectPath(imagePath)) {
			return Mode::Skip;
		}

		//
		// ★ 只有 Windows 目录下的同名进程才认。
		//
		// 不校验目录的话，攻击者只要把自己的样本改名成 `explorer.exe`
		// 就能拿到"免注入"待遇 —— 这是"用文件名当身份"的经典漏洞。
		// 反过来，`D:\tools\explorer.exe` 这种山寨货会走 Full（被完整监控），
		// 正是我们想要的。
		//
		if (!IsUnderWindowsDirectory(imagePath)) {
			return Mode::Full;
		}

		const PCWSTR baseName = BaseNameOf(imagePath);

		if (BaseNameInList(baseName, kNeverInject, _countof(kNeverInject))) {
			return Mode::Skip;
		}

		if (BaseNameInList(baseName, kThinInject, _countof(kThinInject))) {
			// `thinAllowed=false`（ini: inject_shell_thin=0）⇒ 退回 v41 行为。
			return thinAllowed ? Mode::Thin : Mode::Skip;
		}

		return Mode::Full;
	}

	Mode ClassifyCurrentProcess(bool thinAllowed) noexcept
	{
		WCHAR imagePath[MAX_PATH * 2] = {};
		const DWORD length = GetModuleFileNameW(nullptr, imagePath, _countof(imagePath));
		if (length == 0 || length >= _countof(imagePath)) {
			return Mode::Full;
		}

		return ClassifyImagePath(imagePath, thinAllowed);
	}

	bool IsThinInjectBaseName(PCWSTR baseName) noexcept
	{
		return BaseNameInList(baseName, kThinInject, _countof(kThinInject));
	}

	bool IsNeverInjectBaseName(PCWSTR baseName) noexcept
	{
		return BaseNameInList(baseName, kNeverInject, _countof(kNeverInject));
	}

	//
	// ★ v53：内置「绝不注入」的**路径**判据（与 `kNeverInject[]` 的
	//   **文件名**判据并列 —— 后者只在 Windows 目录下生效）。
	//
	// 目前只有一条：VMware Tools。导出**只为**让 `build_ut.sh` 能直接打
	// 这张表（铁律 9：判"漏没漏"看探针不看 grep）。
	//
	bool IsBuiltinNeverInjectPath(PCWSTR imagePath) noexcept
	{
		return IsVmwareToolsImage(imagePath);
	}

	//
	// ★ v49：用户自定义「绝不注入」路径匹配（ini: `never_inject=`）。
	//
	// 语义 = **前缀匹配 + 路径边界**，不区分大小写。
	//
	// 为什么不用现成的 `StartsWithNoCase`（registry_guard.cpp 里那个）：
	//   那个是**裸前缀** —— `D:\App` 会命中 `D:\App2\x.exe`。对"排除目录"
	//   够用（多排一个目录只影响日志噪音），但这里是**免注入**：
	//   命中 = 该进程及其子进程统统不受监控。裸前缀等于给攻击者留一个
	//   "把目录改名成 `WorkBuddyAI2` 就免注入"的后门（铁律 42 同族）。
	//
	bool MatchesNeverInjectPath(PCWSTR imagePath, PCWSTR prefix) noexcept
	{
		if (!imagePath || !prefix || imagePath[0] == L'\0' || prefix[0] == L'\0') {
			return false;
		}

		const size_t prefixLength = wcslen(prefix);

		// 前缀必须含**至少一个非分隔符字符**：否则 `\` / `\\` 这种写法会
		// 匹配一大片（`\\` 还会匹配所有 UNC）—— 等于把整个名单机制废掉。
		bool hasNameChar = false;
		for (size_t i = 0; i < prefixLength; ++i) {
			if (prefix[i] != L'\\' && prefix[i] != L'/') {
				hasNameChar = true;
				break;
			}
		}
		if (!hasNameChar) {
			return false;
		}

		// ★ 逐字符比较，并且**把 `/` 与 `\` 视为等价**。
		//
		// 为什么要归一化分隔符：前缀是**用户手写**在 ini 里的，写成
		// `D:/Program Files/WorkBuddyAI` 太常见了；而 `imagePath` 来自
		// `QueryFullProcessImageNameW`，**只会**返回 `\`。不归一化的话
		// 用户配置会**静默失效**（名单看起来写了、其实一条都不命中）——
		// 这正是铁律 33 那类"配置写对了但引擎不认"的坑。
		for (size_t i = 0; i < prefixLength; ++i) {
			const WCHAR imageChar = imagePath[i];
			if (imageChar == L'\0') {
				return false;   // imagePath 比前缀还短
			}

			const WCHAR a = (imageChar == L'/') ? L'\\' : imageChar;
			const WCHAR b = (prefix[i] == L'/') ? L'\\' : prefix[i];
			if (towupper(a) != towupper(b)) {
				return false;
			}
		}

		// 前缀自己以分隔符结尾 ⇒ 边界天然满足（`D:\App\`、`C:\`）。
		if (prefix[prefixLength - 1] == L'\\' || prefix[prefixLength - 1] == L'/') {
			return true;
		}

		// 否则要求 imagePath 里紧接着是**分隔符或字符串结束**：
		//   `D:\App` 命中 `D:\App\x.exe`，但**不**命中 `D:\App2\x.exe`
		//   —— 后者就是"改个目录名就免注入"的后门。
		const WCHAR next = imagePath[prefixLength];
		return next == L'\0' || next == L'\\' || next == L'/';
	}

	const char* ModeName(Mode mode) noexcept
	{
		switch (mode) {
		case Mode::Thin: return "Thin";
		case Mode::Skip: return "Skip";
		default:         return "Full";
		}
	}
}
