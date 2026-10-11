#include "stdafx.h"
#include "r3shieldcore_config.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>

namespace
{
	std::string Trim(const std::string& text)
	{
		size_t begin = 0;
		while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) {
			begin++;
		}

		size_t end = text.size();
		while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
			end--;
		}

		return text.substr(begin, end - begin);
	}

	//
	// 剥掉**行内注释**：`mode=block   # 主动防御…` → `block   `。
	//
	// 为什么要有这个（v38）：配置文件里每个键后面跟一句短说明可读性最好，
	//   但原来的解析器只在**行首**认 `#` / `;`，行内的会连同说明一起当成值 ——
	//   `mode=block # 说明` 解析出来是 `block # 说明`，匹配不上 → **静默退回默认值**。
	//   （实测：发布闸门 tools/verify_dist_ini.cpp 报 mode 解析成 log。）
	//
	// ⚠️ 只在 `#` / `;` **前面是空白**（或它在行首）时才当注释切 ——
	//   否则会把值里合法的 `#` 切掉，例如 `exclude=C:\a#b`。
	//
	std::string StripInlineComment(const std::string& text)
	{
		for (size_t i = 0; i < text.size(); ++i) {
			const char c = text[i];
			if (c != '#' && c != ';') {
				continue;
			}
			if (i == 0 || text[i - 1] == ' ' || text[i - 1] == '\t') {
				return text.substr(0, i);
			}
		}
		return text;
	}

	std::string ToLower(std::string text)
	{
		std::transform(text.begin(), text.end(), text.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return text;
	}

	std::wstring Utf8ToWide(const std::string& text)
	{
		if (text.empty()) {
			return std::wstring();
		}

		int chars = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
		if (chars <= 0) {
			return std::wstring();
		}

		std::wstring result(static_cast<size_t>(chars), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), result.data(), chars);
		return result;
	}

	bool IsTrue(const std::string& value)
	{
		std::string lower = ToLower(value);
		return lower == "1" || lower == "true" || lower == "yes" || lower == "on";
	}

}   // ← 匿名 namespace 到此为止

// ★ v66：本函数**必须**对外可见（app.cpp 的启动横幅要把它印出来，让用户一眼
//   看到"引擎到底在读哪一份配置"）—— 所以它不再放在匿名 namespace 里。
namespace R3ShieldCoreConfig
{
	//
	// ★ v66：配置文件**优先**从 `%ProgramData%\R3 Shield Core\` 读。
	//
	// 为什么必须这么做：安装目录在 `C:\Program Files\` 下，它的标准 ACL 是
	//   `BUILTIN\Users:(I)(RX)`（只读 + 执行），而安装程序**刻意不给安装目录
	//   开任何写权限** —— 给杀软本体开用户写权限 = 让用户态恶意程序能替换
	//   exe / dll / 驱动，等于自废防护（铁律 47/63/88 的方向）。
	//   ⇒ 普通用户改 `Program Files\R3 Shield Core\r3shieldcore.ini` 时
	//     **存不进去**（err=5，且错误信息与"文件被设只读"完全一样，铁律 161）。
	//
	// 解法：把**配置文件**单独放到 `%ProgramData%\R3 Shield Core\`，
	//   安装时**只对该目录**授 `Users:(OI)(CI)M`。于是：
	//     · 用户能直接编辑配置（记事本原地保存、VS Code 原子保存都行）；
	//     · 程序本体（exe / dll / 驱动）仍在 Program Files，**仅管理员可写**，
	//       恶意程序改不动本体。
	//
	// 回退：ProgramData 下的 ini **不存在**时，回退到 exe 同目录 —— 兼容
	//   ①旧安装（v65 及以前，ini 就在安装目录里）；
	//   ②绿色包（解压即用，不往 ProgramData 里丢东西）。
	//   判据是"**那个文件**在不在"，不是"目录在不在" —— 只看目录会让
	//   一个空目录把配置整个顶掉（静默退回全默认值）。
	//
	// ⚠️ 两处**同时存在**时以 ProgramData 为准（先返回它）。
	//    引擎写回 mode（SaveMode）用的也是本函数 ⇒ 读写永远是同一个文件，
	//    不会出现"读 A 写 B"那种改了不生效的怪象。
	//
	std::filesystem::path ResolveConfigPath(const std::filesystem::path& exeDirectory)
	{
		WCHAR programData[MAX_PATH] = {};
		const DWORD length = GetEnvironmentVariableW(L"ProgramData", programData,
			_countof(programData));
		if (length > 0 && length < _countof(programData)) {
			const std::filesystem::path candidate =
				std::filesystem::path(programData) / L"R3 Shield Core" / L"r3shieldcore.ini";

			std::error_code ec;
			if (std::filesystem::exists(candidate, ec) && !ec) {
				return candidate;
			}
		}

		return exeDirectory / L"r3shieldcore.ini";
	}

	void Load(R3ShieldCore::Policy& policy, const std::filesystem::path& exeDirectory)
	{
		ZeroMemory(&policy, sizeof(policy));
		policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Log);
		// hive 级和 NtSetInformationKey 默认挂上：这两类是原版覆盖不到的真实缺口，
		// 而且调用频率极低（不像 NtCreateFile 那么热），挂着几乎零成本。
		//
		// 文件 hook 默认**关**：文件系统比注册表热一个数量级
		// （浏览器/编译器每秒开几百个文件），默认挂上会把事件缓冲区刷爆。
		policy.Flags = R3ShieldCore::FlagHookHive | R3ShieldCore::FlagHookSetInfo
			| R3ShieldCore::FlagHighRiskGuard
			| R3ShieldCore::FlagHookProcess | R3ShieldCore::FlagHookThread
			| R3ShieldCore::FlagHookDriver
			| R3ShieldCore::FlagHookNetwork | R3ShieldCore::FlagHookDns
			| R3ShieldCore::FlagSelfProtect
			| R3ShieldCore::FlagHookCamera | R3ShieldCore::FlagHookInputHook
			| R3ShieldCore::FlagHookScreen
			| R3ShieldCore::FlagHookDllLoad | R3ShieldCore::FlagHookClipboard
			| R3ShieldCore::FlagHookSpawn
			| R3ShieldCore::FlagHookServiceConfig
			| R3ShieldCore::FlagHookComHijack
			| R3ShieldCore::FlagHookScheduledTask
			| R3ShieldCore::FlagHookAudio
			| R3ShieldCore::FlagHookTokenTheft
			| R3ShieldCore::FlagHookWmiSubscription;

		// v14：Flags 32 位已满，新开关走 Flags2（尾部追加字段）。
		// 两项都默认开 —— 代码注入链和锁屏勒索都是"不该发生"的动作，
		// 频率极低（正常程序几小时都不一定调一次跨进程写内存），挂着几无成本。
		// v15：宿主劫持面（注册表注入键 + 加载器变体 + 远程映射/APC）同样默认开。
		// v36：终止进程收敛（只允许终止自己/后代/同镜像）同样默认开。
		// 默认 mode=log ⇒ 它只**记录**（标 WouldBlock），不会真的拦；
		// 切到 block / ask 才生效 —— 所以默认开是安全的。
		// v39：裸盘/物理盘写入（写 MBR/引导区 = bootkit）同样默认开。
		// 它**独立于 hook_file**（后者默认关）—— 见 FileGuard::Install 的注释。
		// 频率极低（正常机器几周不一定有一次），挂上几无成本。
		// v42：**瘦注入**（shell/服务宿主只装 CreateProcessInternalW）同样默认开。
		// 它决定"explorer.exe / svchost.exe / runtimebroker.exe 要不要被注入"。
		// 不注入它们 ⇒ 双击启动与 UAC 提权启动都只能走轮询路（盲区 = 间隔 + 注入耗时）；
		// 注入它们（瘦会话）⇒ 这两条链上的子进程能走**同步路**（盲区 ≈ 0）。
		// ⚠️ 这是 v42 为"启动即写 MBR"的样本（Windows XP Horror）加的关键一项。
		policy.Flags2 = R3ShieldCore::FlagHookMemoryOp | R3ShieldCore::FlagHookInputInject
			| R3ShieldCore::FlagHookHostHijack | R3ShieldCore::FlagHookTerminateContain
			| R3ShieldCore::FlagHookRawDisk | R3ShieldCore::FlagInjectShellThin;
		policy.PromptTimeoutMs = 30000;
		policy.PromptDefaultVerdict = static_cast<ULONG>(R3ShieldCore::Verdict::Deny);

		std::filesystem::path defaultLogPath = exeDirectory / L"r3shieldcore-events.log";
		wcsncpy_s(policy.LogPath, defaultLogPath.c_str(), _TRUNCATE);

		// ★ v66：优先 `%ProgramData%\R3 Shield Core\r3shieldcore.ini`，
		//    没有才回退 exe 同目录（见 ResolveConfigPath 的完整理由）。
		const std::filesystem::path configPath = ResolveConfigPath(exeDirectory);
		std::ifstream file(configPath, std::ios::binary);
		if (!file) {
			return;
		}

		std::string line;
		while (std::getline(file, line)) {
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}

			std::string trimmed = Trim(line);
			if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
				continue;
			}

			size_t separator = trimmed.find('=');
			if (separator == std::string::npos) {
				continue;
			}

			std::string key = ToLower(Trim(trimmed.substr(0, separator)));
			std::string value = Trim(StripInlineComment(trimmed.substr(separator + 1)));

			if (key == "mode") {
				std::string lower = ToLower(value);

				// ★ v68：`mode=` 是**权威**的 —— 先清掉 `FlagTestMode` 位，再按值设。
				//   否则 ini 里同时出现 `mode=test` 和 `mode=block` 时会留下
				//   `FlagTestMode`（"最后一行是 block，但引擎却按 mode=test 要求
				//   白名单非空"这种半开状态），而且**不可见**（铁律 97）。
				policy.Flags2 &= ~R3ShieldCore::FlagTestMode;

				if (lower == "test" || lower == "test_mode" || lower == "testmode"
					|| lower == "test-mode") {
					// ★ v68：`mode=test` —— 便捷写法 = `log` 的行为 +
					//   **强制要求** `test_inject_only=` 非空（引擎启动时 fail-closed）。
					//
					// ⚠️ 注意这里**只设 Mode 与标志位**，**不碰** `TestInjectPaths[]`：
					//    「注入范围」与「拦截行为」是解耦的（只要名单非空就限定注入
					//    范围，与 `mode=` 无关），见 shared 头 `FlagTestMode` 上面
					//    那段"解耦"的理由 —— spoof 只在"本应拒绝"时生效，若白名单
					//    只认 `mode=test` 就永远验证不到替换路径。
					//
					// ⚠️ 这里**故意**复用 `Mode::Log` 而不是新增一个 `Mode` 枚举值：
					//    `Mode` 在 22 个文件里有 ~130 处 `mode == Mode::Xxx` 分支，
					//    加新值会让每一处都落进 else 分支 —— 那是静默错行为。
					policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Log);
					policy.Flags2 |= R3ShieldCore::FlagTestMode;
				}
				else if (lower == "block") {
					// Daily-use active defense: block only high-confidence risky
					// operations; ordinary writes and network traffic remain usable.
					policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Block);
				}
				else if (lower == "ask") {
					policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				}
				else if (lower == "block_all" || lower == "blockall" || lower == "block-all") {
					// 完全拦截：探测范围内一律拒绝。风险见 ini 里的说明块。
					policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::BlockAll);
				}
				else if (lower == "block_all_safe" || lower == "blockallsafe"
					|| lower == "block-all-safe" || lower == "block_safe"
					|| lower == "blocksafe") {
					// 完全拦截（安全版）：唯一区别是**放行可信来源的进程创建**。
					// 注册表 / 文件 / 网络 / 内存 / 线程 / APC 语义与 block_all 完全一致。
					policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::BlockAllSafe);
				}
				else {
					policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Log);
				}
			}
			else if (key == "prompt_timeout") {
				int seconds = atoi(value.c_str());
				if (seconds > 0 && seconds <= 600) {
					policy.PromptTimeoutMs = static_cast<ULONG>(seconds) * 1000;
				}
			}
			else if (key == "prompt_default") {
				policy.PromptDefaultVerdict = (ToLower(value) == "allow")
					? static_cast<ULONG>(R3ShieldCore::Verdict::Allow)
					: static_cast<ULONG>(R3ShieldCore::Verdict::Deny);
			}
			else if (key == "hook_reads") {
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookReads;
				}
			}
			else if (key == "log_all_open") {
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagLogAllOpen;
				}
			}
			else if (key == "hook_hive") {
				// hive 级操作（Load/Save/Restore/Replace）。默认开。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookHive;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookHive;
				}
			}
			else if (key == "hook_set_info") {
				// NtSetInformationKey（时间戳伪造 / WOW64 重定向）。默认开。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookSetInfo;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookSetInfo;
				}
			}
			else if (key == "hook_file") {
				// 文件写类操作（建/写/删/改名/改时间戳/改 ACL）。默认**关**。
				// 打开后才能监控文件写操作；关闭时文件高危规则也不会生效（hook 都没挂）。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookFile;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookFile;
				}
			}
			else if (key == "high_risk") {
				// 高危规则总开关。默认开。
				// 关掉后退化成"纯按 mode 一刀切"的老行为。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHighRiskGuard;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHighRiskGuard;
				}
			}
			else if (key == "hook_process") {
				// 进程创建/终止监控。默认开（频率低、信息价值高）。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookProcess;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookProcess;
				}
			}
			else if (key == "self_protect") {
				// 自我保护：NtOpenProcess 对"受保护目标"（引擎自身 + protect_process=）
				// 剥掉 PROCESS_TERMINATE / VM_WRITE / CREATE_THREAD 等危险权限位。
				// 默认**开**，且**不受 mode 影响** —— 它在 LOG 模式下也会生效，
				// 因为这是"能不能被杀"的问题，不是"记录还是拦截"的问题。
				// 关掉它 = 引擎可被任意进程终止/注入。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagSelfProtect;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagSelfProtect;
				}
			}
			else if (key == "hook_thread") {
				// 线程创建监控。默认开，但默认只上报远程线程（见 hook_self_thread）。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookThread;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookThread;
				}
			}
			else if (key == "hook_self_thread") {
				// 连本进程内的线程创建也记录。默认**关** ——
				// 线程创建极高频（一个 Chrome 每秒几十上百个），
				// 打开会淹掉日志、拖慢系统。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookSelfThread;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookSelfThread;
				}
			}
			else if (key == "hook_driver") {
				// 驱动加载/卸载监控（NtLoadDriver）。默认开（频率极低）。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookDriver;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookDriver;
				}
			}
			else if (key == "hook_net") {
				// 网络出站监控（connect/WSAConnect/sendto/WSASendTo）。
				// 默认开 —— 外连是数据外泄的口子，情报价值最高。
				// 关掉等于网络监控整个停用。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookNetwork;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookNetwork;
				}
			}
			else if (key == "hook_dns") {
				// 域名解析监控（gethostbyname/getaddrinfo）。默认开 ——
				// C2 域名只在这里现形（解析之后就只剩 IP 了）。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookDns;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookDns;
				}
			}
			else if (key == "hook_net_all") {
				// 连 bind/listen/accept 也挂。默认**关** ——
				// 服务端程序（开发服务器、本地 Web、P2P）这里极高频。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookNetAll;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookNetAll;
				}
			}
			else if (key == "hook_camera") {
				// 摄像头 / 麦克风访问监控（VFW + Media Foundation）。
				// 默认开 —— "打开设备"一律高危，走询问路径。
				//
				// ⚠️ 代价：会在每个被注入进程里主动 LoadLibrary
				//    avicap32 / mfplat / mfreadwrite（多数进程本来不加载
				//    这三个）。不想付这个代价就关掉。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookCamera;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookCamera;
				}
			}
			else if (key == "hook_input") {
				// 鼠标 / 键盘钩子监控（SetWindowsHookEx + RegisterRawInputDevices）。
				// 默认开 —— 键盘记录器在用户态只看得到这一处。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookInputHook;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookInputHook;
				}
			}
			else if (key == "hook_screen") {
				// 屏幕捕获监控（BitBlt/StretchBlt 源为屏幕 DC + PrintWindow）。
				// 默认开。只上报"把屏幕内容拷走"，普通窗口重绘在 hook 里
				// 就被过滤掉了，不会产生噪音。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookScreen;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookScreen;
				}
			}
			else if (key == "spoof_screen") {
				// ★ v67：截屏**替换**（默认**关**）。
				//
				// 语义：本应**拒绝**截屏时，改为"**调用成功 + 返回黑帧**"
				//   （`Decision::Spoofed`）—— 攻击者以为截到了，其实拿到一张黑图。
				//
				// 覆盖范围（只有"本应拒绝"的地方）：
				//   · `mode=block` 下的高危截屏（本来直接拒）；
				//   · `mode=ask` 下用户点了"拒绝"（本来返回失败）。
				// **不覆盖**：
				//   · `mode=log` —— 它本来就不拒（替换会破坏"只记录、全放行"）；
				//   · `mode=block_all` —— 铁律 165：全拦下**一律拒绝**，不做替换。
				//
				// ⚠️ 前置条件：必须同时开着 `hook_screen=1`（否则 ScreenGuard
				//    根本不装 hook，本开关无处生效）。
				// ⚠️ 默认**关**：这是"主动欺骗"能力，与产品既有的「可见性 + 拒绝」
				//    定位不同族。默认配置下行为与旧版**完全一致**。
				// ⚠️ 已知盲区（非本开关引入）：`GetPixel` 逐像素读屏、
				//    Desktop Duplication、WinRT Capture 都没挂 ⇒ 换这些路径
				//    仍能拿到真画面。定位是"提高成本"，不是硬边界。
				//    见 docs/回传数据替换-多路径盘点.md。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagSpoofScreen;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagSpoofScreen;
				}
			}
			else if (key == "spoof_clipboard") {
				// ★ v70：剪贴板**替换**（默认**关**）。
				//
				// 语义：本应**拒绝**读取剪贴板时，改为"**调用成功 + 返回
				//   中性化内容**"（`Decision::Spoofed`）—— 文本变空串，
				//   位图/DIB 变同尺寸全 0（BGR 下即全黑）。
				//
				// 覆盖范围（只有"本应拒绝"的地方，与 `spoof_screen` 同构）：
				//   · `mode=block` 下的高危剪贴板读取（本来直接拒）；
				//   · `mode=ask` 下用户点了"拒绝"（本来返回失败）。
				// **不覆盖**：
				//   · `mode=log` —— 它本来就不拒；
				//   · `mode=block_all` —— 铁律 165：全拦下**一律拒绝**。
				//
				// ⚠️ 前置条件：必须同时开着 `hook_clipboard=1`（否则
				//    ClipboardGuard 根本不装 hook，本开关无处生效）。
				// ⚠️ **只对能伪造的格式生效**：CF_TEXT(1) / CF_BITMAP(2) /
				//    CF_OEMTEXT(7) / CF_DIB(8) / CF_UNICODETEXT(13) /
				//    CF_DIBV5(17)。其余格式（如注册格式、CF_HDROP）
				//    **回落到拒绝** —— 造不出未知格式的合法布局，
				//    硬造一个长度不对的块会让调用方读越界。
				//    见 `clipboard_spoof_codec.h`。
				// ⚠️ 默认**关**：这是"主动欺骗"能力，与产品既有的
				//    「可见性 + 拒绝」定位不同族。默认配置下行为与旧版
				//    **完全一致**。
				// ⚠️ 已知盲区（非本开关引入）：OLE 拖放
				//    `IDataObject::GetData`、`win32u!NtUserGetClipboardData`、
				//    延迟渲染都没挂 ⇒ 换这些路径仍能拿到真内容。
				//    见 docs/回传数据替换-多路径盘点.md §2.2。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagSpoofClipboard;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagSpoofClipboard;
				}
			}
			else if (key == "spoof_reg") {
				// ★ v71：注册表值**替换**（默认**关**）。
				//
				// 语义：读取**受保护位置**（`protect_reg=` 命中的键）的值时，
				//   返回"**调用成功 + 数据区清零**"（`Decision::Spoofed`）——
				//   值类型、长度字段**全部不变**，只有数据字节变 0：
				//     · `REG_SZ`/`REG_EXPAND_SZ` ⇒ 空串；
				//     · `REG_DWORD`/`REG_QWORD`   ⇒ 0；
				//     · `REG_BINARY`              ⇒ 全 0 字节；
				//     · `REG_MULTI_SZ`            ⇒ 空列表。
				//   配合既有的"写不进"（`protect_reg` 拒写），合起来即
				//   **「保护 = 写不进 + 读不到」**。
				//
				// ⚠️ 与 `spoof_screen`/`spoof_clipboard` 的**触发面不同**：
				//   那两个只在"**本应拒绝**"时替换；注册表读**本来不拒**
				//   （`!blockable`），所以这里是"**命中 `protect_reg` 就替换**"。
				//   换句话说：**必须配 `protect_reg=` 才有效**，空名单下本开关
				//   一个字节都不会动（判据见 `IsProtectedRegistryPathForSpoof`）。
				//
				// ⚠️ **不能拿 `IsHighRiskRegistry` 当触发面**：那张表里有
				//   `...\CurrentVersion\Run`，任务管理器 / 启动项管理 / 各类
				//   安装程序**天天在读**它 —— 一旦替换，正常软件会看到空值，
				//   属于"把正常功能打坏"。所以触发面**只认用户显式声明的**
				//   `protect_reg=`。
				//
				// ⚠️ 前置条件：`NtQueryValueKey` 必须被挂上。挂载条件已放宽成
				//   `hook_reads || spoof_reg`（见 `registry_guard.cpp` 的 Install）——
				//   否则用户打开 `spoof_reg` 什么也不会发生。**注意**：只挂
				//   `NtQueryValueKey` 一个，不偷偷打开 `NtEnumerateKey`/
				//   `NtEnumerateValueKey` 的读记录（那条路由 `hook_reads` 单独管）。
				//
				// ⚠️ 默认**关**：这是"主动欺骗"能力，与产品既有的
				//   「可见性 + 拒绝」定位不同族。默认配置下行为与旧版
				//   **完全一致**。
				// ⚠️ 已知盲区（非本开关引入）：
				//   · **枚举不隐藏** —— 枚举仍能看见值的**名字与类型**
				//     （只是拿到 0 值）。要连名字一起藏，开 `spoof_reg_enum=`
				//     （v72，**另一个位** —— 两者风险画像不同，见那里）；
				//   · `KeyValueBasicInformation`(class 0) **没有数据区** ⇒ 不动；
				//   · `NtQueryMultipleValueKey` **没挂**；
				//   · 直接读 hive 文件、事务注册表（KTM）**没覆盖**。
				//   见 docs/回传数据替换-多路径盘点.md §2.4 / §8。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagSpoofRegistry;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagSpoofRegistry;
				}
			}
			else if (key == "spoof_reg_enum") {
				// ★ v72：注册表**枚举隐藏**（默认**关**）。
				//
				// 语义：枚举**受保护位置**（`protect_reg=` 命中的键）的子键 / 值时，
				//   把命中保护前缀的项**从列表里去掉**（`Decision::Spoofed`）——
				//   攻击者"看不见"受保护的值与子键，配合 `spoof_reg=` 的
				//   "读不到"和既有的"写不进"，合起来即
				//   **「保护 = 写不进 + 读不到 + 看不见」**。
				//
				// ★ 实现 = **索引重映射**（不是伪造项）：调用方要第 N 个可见项，
				//   我们跳过被隐藏的、真调原函数取到对应的那一个 ⇒ 返回的每一项
				//   都是**真实、合法、结构完整**的项（铁律 194）。
				//   ⚠️ 代价：列表**长度变了**。按"枚举到 NO_MORE_ENTRIES 为止"
				//   写代码的程序看到的是短列表（这正是我们要的）；但**缓存过
				//   列表长度**的程序可能行为改变 —— 所以本开关默认关。
				//
				// ⚠️ **与 `spoof_reg=` 是两个独立的位**，理由（铁律 199 同族）：
				//   值替换只改"某个值的内容"（长度不变），枚举隐藏改的是
				//   **列表长度与顺序**。并进同一个开关 ⇒ "只想让值读不到"的用户
				//   会**顺带**发现枚举结果也变了，而且没法单独关掉。
				//
				// ⚠️ 必须配 `protect_reg=` 才有效（同 `spoof_reg`）：名单为空时
				//   没有任何键是"受保护位置"，本开关空转（横幅会明说）。
				//
				// ⚠️ 前置条件：`NtEnumerateKey` / `NtEnumerateValueKey` 必须被挂上。
				//   挂载条件已放宽成 `hook_reads || spoof_reg || spoof_reg_enum`
				//   （见 `registry_guard.cpp` 的 Install）—— 否则用户打开本开关
				//   什么也不会发生，而横幅还会印"开"（铁律 93）。
				//   **注意**：只额外挂这两个枚举 hook，不偷偷打开读记录
				//   （那是 `hook_reads` 的语义，见 `HookReadsEnabled`）。
				//
				// ⚠️ 默认**关**：这是"主动欺骗"能力，与产品既有的
				//   「可见性 + 拒绝」定位不同族。默认配置下行为与旧版
				//   **完全一致**。
				// ⚠️ 已知盲区（非本开关引入）：
				//   · 隐藏是**列表级**的，不是**访问级**的 —— 被隐藏的键/值
				//     仍可被 `NtOpenKey` / `NtQueryValueKey` **直接按名字**访问
				//     （值还会被 `spoof_reg` 清零）；
				//   · `NtQueryKey` 的 `SubKeys` / `Values` **计数不变**
				//     （键元数据，改它要同步改一堆字段，风险大于收益）；
				//   · 事务注册表 / hive 文件直读 / WOW64 重定向路径未覆盖。
				//   见 docs/回传数据替换-多路径盘点.md §2.4 / §8。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagSpoofRegistryEnum;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagSpoofRegistryEnum;
				}
			}
			else if (key == "spoof_camera") {
				// ★ v73：摄像头**帧替换**（默认**关**）。
				//
				// 语义：判定"本应拒绝**读取摄像头数据流**"时，**改为替换** ——
				//   建读取器（`MFCreateSourceReaderFromMediaSource`）照常成功，
				//   但我们顺手 patch 那个 `IMFSourceReader` 的 `ReadSample` 槽，
				//   之后每一帧都被**原地改成中性帧**（`Decision::Spoofed`）。
				//   ⇒ 攻击者拿到"合法的黑画面"，而不是"打开失败"。
				//
				// ★★ 与前三个面（屏幕 / 剪贴板 / 注册表值）的**根本不同**：
				//   那三个是**单次调用**（一进一出、无状态）；摄像头是**流式**
				//   （一帧一帧来）。所以判定在"建读取器"时做一次，替换在
				//   "每一帧"做，并且要记住"哪些 reader 要替换"。
				//
				// ★★ 中性值**与子类型有关**：全 0 在 **YUV** 里**不是黑**
				//   （是饱和色）⇒ 必须按子类型填（RGB → 全 0；YUV → Y16/UV128）。
				//   决策表在 `camera_spoof_codec.h`，**生产与探针共用一份**。
				//   ⚠️ 对外口径**不能**说"黑帧"（铁律 97）。
				//
				// ⚠️ **只有"能造出合法中性帧"的路径才替换，其余一律回落 `Block`**
				//   （铁律 194）。能替换的**只有** `MFCreateSourceReaderFromMediaSource`
				//   一个入口 —— VFW（`WM_CAP_*` 回调）、设备源创建、以及音频三路
				//   （`waveInOpen` / MCI / `IAudioClient::Initialize`）都**回落拒绝**。
				//   ⇒ 打开本开关**不会**让麦克风/环回被放行（铁律 199）。
				//   建读取器时若**没有视频流**，同样回落 `Block`。
				//
				// ⚠️ 子类型不支持（MJPG / H264 等压缩格式）⇒ `ReadSample`
				//   **直接返回失败**（= 拒绝语义）并记日志。压缩帧里填 16/128
				//   得到的是"一帧解不出来的垃圾"，宁可拒绝不可硬造（铁律 194/196）。
				//
				// ⚠️ **不覆盖** `block_all`（铁律 165：全拦模式一律拒绝，不替换）；
				//   默认 `mode=log` 下也不触发（log 本来就不拒）。
				//
				// ⚠️ 默认**关**：这是"主动欺骗"能力，与产品既有的
				//   「可见性 + 拒绝」定位不同族。默认配置下行为与旧版**完全一致**。
				// ⚠️ 已知盲区（非本开关引入）：DirectShow / WinRT `MediaCapture` /
				//   内核态驱动路径未覆盖；异步回调路径已单独 patch。
				//   见 docs/回传数据替换Hook-技术预研.md §8 Phase 2。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagSpoofCamera;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagSpoofCamera;
				}
			}
			else if (key == "hook_dll_load") {
				// DLL 加载/劫持监控（LdrLoadDll + NtMapViewOfSection）。
				// 默认开 —— 白加黑（DLL 侧加载）是当前主流的绕过手法。
				// hook 层已过滤系统目录（System32/SysWOW64/Program Files），
				// 只有非系统目录的加载会上报，噪音可控。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookDllLoad;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookDllLoad;
				}
			}
			else if (key == "hook_clipboard") {
				// 剪贴板读取监控（OpenClipboard 只记录 + GetClipboardData 高危）。
				// 默认开。密码管理器 / 钱包 / 验证码的常见窃取面。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookClipboard;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookClipboard;
				}
			}
			else if (key == "hook_spawn") {
				// 进程创建旁路监控（ShellExecuteEx/WinExec/WithToken/WithLogon）。
				// 默认开。这一层挂的全是低频、上下文特殊的 API，一律高危。
				// 普通 CreateProcessW 走 NtCreateUserProcess，由进程监控覆盖，
				// 不在这里重复报。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookSpawn;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookSpawn;
				}
			}
			else if (key == "hook_service_config") {
				// 服务/安全对象权限变更监控（SetServiceObjectSecurity +
				// NtSetSecurityObject）。默认开。
				// 补的是 DriverGuard 覆盖不到的提权链：sc sdset 把 SYSTEM
				// 服务的控制权开放给普通用户 → 普通用户改 binPath/重启服务
				// → 任意 SYSTEM 代码执行。这条链不改二进制路径，DriverGuard
				// 的判据一个都不命中。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookServiceConfig;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookServiceConfig;
				}
			}
			else if (key == "hook_com_hijack") {
				// COM / OLE 激活劫持监控（CoCreateInstance / CoCreateInstanceEx
				// / CoGetClassObject）。默认开。
				// 判据：CLSID 解析出来的服务器 DLL/EXE 落在**用户可写目录**。
				// 系统 CLSID（程序每秒都在建的）根本不产生事件 —— 见
				// com_hijack_guard.cpp 里"非高危直接 Pass"那段。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookComHijack;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookComHijack;
				}
			}
			else if (key == "hook_scheduled_task") {
				// 计划任务持久化监控（ITaskFolder::RegisterTaskDefinition
				// vtable patch）。默认开。
				// ⚠️ 这是用户态唯一能抓到"注册计划任务"的地方 ——
				//    schtasks.exe 在 System32（bypass 白名单），真正的
				//    执行者 Task Scheduler 服务在 svchost（也是白名单），
				//    只有调用方进程里的 COM 接口可以拦。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookScheduledTask;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookScheduledTask;
				}
			}
			else if (key == "hook_audio") {
				// 音频采集 / 环回监控（v13）。默认开。
				// 覆盖 waveInOpen / mciSendCommandW（winmm 导出）+
				// WASAPI IAudioClient::Initialize（vtable patch）。
				// 判据：麦克风高危；环回（AUDCLNT_STREAMFLAGS_LOOPBACK）
				// 尤其高危 —— 录系统输出等于能录通话/会议。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookAudio;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookAudio;
				}
			}
			else if (key == "hook_token_theft") {
				// 令牌窃取 / 冒充监控（v13）。默认开。
				// 一档（OpenProcessToken）只做关联不上报；二档（复制/冒充）
				// 与三档（开 SeDebug/SeImpersonate/SeTcb）高危。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookTokenTheft;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookTokenTheft;
				}
			}
			else if (key == "hook_wmi_subscription") {
				// WMI 事件订阅持久化监控（v13）。默认开。
				// 纯 vtable patch（IWbemLocator::ConnectServer +
				// IWbemServices::PutInstance 等）。
				// 两道闸：root\subscription 命名空间 + 三件套类名。
				if (IsTrue(value)) {
					policy.Flags |= R3ShieldCore::FlagHookWmiSubscription;
				}
				else {
					policy.Flags &= ~R3ShieldCore::FlagHookWmiSubscription;
				}
			}
			else if (key == "hook_memory_op") {
				// 跨进程内存操作 / 代码注入链监控（v14）。默认开。
				// 补 NtAllocateVirtualMemory / NtWriteVirtualMemory /
				// NtProtectVirtualMemory 三步，配合已有的 NtCreateThreadEx
				// 把整条注入链补齐。
				// ⚠️ 判据的存活关键：**本进程一律放行**（JIT/堆/GC 高频）。
				//    只有跨进程 + 权限位齐全才算高危。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagHookMemoryOp;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagHookMemoryOp;
				}
			}
			else if (key == "hook_input_inject") {
				// 合成输入 / 锁屏勒索监控（v14）。默认开。
				// 覆盖 SendInput / keybd_event / mouse_event（合成键鼠）
				// + BlockInput（冻结输入）+ ClipCursor（锁鼠标）。
				// 判据：SendInput 按密度；BlockInput/ClipCursor 看前台窗口归属。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagHookInputInject;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagHookInputInject;
				}
			}
			else if (key == "hook_host_hijack") {
				// 宿主劫持 / 加载器监控（v15）。默认开。
				// 覆盖注册表全局注入键（AppInit_DLLs / IFEO / LSA / Winlogon）
				// + LoadLibraryExW / LdrRegisterDllNotification
				// + 跨进程映射与 APC 注入。判据：配置/载荷指向用户可写目录，
				// 或目标是别的进程。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagHookHostHijack;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagHookHostHijack;
				}
			}
			else if (key == "hook_terminate_contain") {
				// 终止进程收敛（v36）。默认开。
				//
				// 语义：NtTerminateProcess 从"只记录"升级为按判据处置 ——
				//   放行：终止**自己**（ExitProcess 也走这条路）/ **自己的后代**
				//         （整棵子树）/ **同镜像路径**的进程（单实例程序杀旧实例）；
				//   高危：终止以上之外的任何进程（"不许杀别人"）。
				//
				// ⚠️ 默认 mode=log ⇒ 只记录（标 WouldBlock），不真拦；
				//    切到 block / ask / block_all 才生效。
				// ⚠️ hook 只在非 bypass 进程里装 ⇒ System32 的任务管理器 /
				//    taskkill 不受约束，系统工具仍能正常管理进程。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagHookTerminateContain;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagHookTerminateContain;
				}
			}
			else if (key == "hook_raw_disk") {
				// 裸盘 / 物理盘写入监控（v39）。默认开。
				//
				// 语义：带写意图打开 `\\.\PhysicalDrive0` /
				// `\Device\Harddisk0\DR0` / `\Device\Harddisk0\Partition0`
				// ⇒ 高危（写 MBR / 引导扇区 = bootkit 第一步）。
				//
				// ⚠️ **独立于 `hook_file`**：`hook_file=0`（发布默认）时它照样
				//    生效 —— 真实绕过就发生在这个配置下。关掉它需要显式写
				//    `hook_raw_disk=0`。
				// ⚠️ 默认 mode=log ⇒ 只记录（标 WouldBlock），不真拦；
				//    切到 block / ask / block_all 才真拦。
				// ⚠️ 合法磁盘工具（分区/整盘备份还原/引导修复）会被拦 ——
				//    这类工具运行时临时切 `log` 即可。
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagHookRawDisk;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagHookRawDisk;
				}
			}
			else if (key == "inject_shell_thin") {			// ★ 瘦注入：shell/服务宿主只装 CreateProcessInternalW（v42，默认开）
				//
				// 语义：把"会当**用户程序父进程**"的宿主从"绝不注入"名单
				//   挪到"**瘦注入**"名单 —— 注入它们，但**只装
				//   `CreateProcessInternalW` 一个 hook**，不装任何 guard。
				//
				// ★ 为什么必须这么做：引擎的**同步注入路**（hook 父进程的
				//   `CreateProcessInternalW` → 强制 `CREATE_SUSPENDED` →
				//   注入 → `ResumeThread`）能让子进程**跑第一行代码之前**就
				//   挂好 hook ⇒ **盲区 ≈ 0**。但它的前提是**父进程已被注入**。
				//   而"双击启动"的父进程是 `explorer.exe`、"UAC 提权启动"的
				//   父进程是 `svchost.exe`（AppInfo 服务）—— 这两个原来都在
				//   "绝不注入"名单里 ⇒ 那条链上**永远拿不到同步路**，只能靠
				//   轮询（盲区 = `inject_interval_ms` + 注入耗时）。
				//   样本 `Windows XP Horror` 恰好在 `FormCreate`
				//   （启动后几十~几百 ms）里写 MBR，抢的就是这个窗口。
				//
				// ★ 为什么**只装一个 hook**：`explorer.exe` 的文件 I/O 极高频
				//   （每开一个目录、每张缩略图、每次拖放），全量 hook 在
				//   `block_all` 下必炸；DLL 里任何 bug 都会让**桌面**死掉。
				//   瘦会话在行为上等价于"没被注入"，只是多一个进程创建拦截点。
				//   ⇒ 本进程**自己不受监控**，但它的**子进程受完整监控**。
				//
				// ⚠️ 逃生门：`inject_shell_thin=0` 即退回 v41 及以前的行为
				//    （不注入这些宿主），不必回滚版本。
				//
				// ⚠️ 名单本身（哪些进程算"宿主"）在
				//    `R3ShieldCoreLib/inject_policy.cpp` 的 `kThinInject[]`，
				//    要加/减进程改那张表（本 ini 只控制开关）。
				//
				if (IsTrue(value)) {
					policy.Flags2 |= R3ShieldCore::FlagInjectShellThin;
				}
				else {
					policy.Flags2 &= ~R3ShieldCore::FlagInjectShellThin;
				}
			}
			else if (key == "protect_net") {				// 自定义网络保护目标（"1.2.3.4:445" 或域名）。
				// 命中即视为高危，弹窗询问。
				if (policy.ProtectNetCount >= R3ShieldCore::MaxProtectPaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.ProtectNetTargets[policy.ProtectNetCount], wide.c_str(), _TRUNCATE);
				policy.ProtectNetCount++;
			}
			else if (key == "protect_process") {
				// 自定义进程保护前缀（按镜像路径）。命中即视为高危。
				if (policy.ProtectProcessCount >= R3ShieldCore::MaxProtectPaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.ProtectProcessPaths[policy.ProtectProcessCount], wide.c_str(), _TRUNCATE);
				policy.ProtectProcessCount++;
			}
			else if (key == "protect_driver") {
				// 自定义驱动保护前缀（按 .sys 路径）。命中即视为高危。
				if (policy.ProtectDriverCount >= R3ShieldCore::MaxProtectPaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.ProtectDriverPaths[policy.ProtectDriverCount], wide.c_str(), _TRUNCATE);
				policy.ProtectDriverCount++;
			}
			else if (key == "protect_reg") {
				// 自定义注册表保护前缀。命中即视为高危，弹窗询问。
				if (policy.ProtectRegCount >= R3ShieldCore::MaxProtectPaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.ProtectRegPaths[policy.ProtectRegCount], wide.c_str(), _TRUNCATE);
				policy.ProtectRegCount++;
			}
			else if (key == "protect_file") {
				// 自定义文件保护前缀。命中即视为高危，弹窗询问。
				if (policy.ProtectFileCount >= R3ShieldCore::MaxProtectPaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.ProtectFilePaths[policy.ProtectFileCount], wide.c_str(), _TRUNCATE);
				policy.ProtectFileCount++;
			}
			else if (key == "log") {
				std::wstring wide = Utf8ToWide(value);
				if (!wide.empty()) {
					std::filesystem::path logPath(wide);
					if (logPath.is_relative()) {
						logPath = exeDirectory / logPath;
					}

					wcsncpy_s(policy.LogPath, logPath.c_str(), _TRUNCATE);
				}
			}
			else if (key == "exclude") {
				if (policy.ExcludePathCount >= R3ShieldCore::MaxExcludePaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.ExcludePaths[policy.ExcludePathCount], wide.c_str(), _TRUNCATE);
				policy.ExcludePathCount++;
			}
			//
			// ★ v49：`never_inject=` —— 用户自定义的「绝不注入」名单（可重复）。
			//
			// 与 `exclude=`（文件操作前缀白名单）**不是一回事**：
			//   · exclude= 只管"这些目录下的**文件操作**别拦"；
			//   · never_inject= 管"这个**进程**别注入"。
			// 后者会让该进程及其子进程失去同步注入路（盲区变大），
			// 所以 ini 注释里必须写明代价。
			//
			else if (key == "never_inject") {
				if (policy.NeverInjectCount >= R3ShieldCore::MaxNeverInjectPaths) {
					continue;
				}

				std::wstring wide = Utf8ToWide(value);
				if (wide.empty()) {
					continue;
				}

				wcsncpy_s(policy.NeverInjectPaths[policy.NeverInjectCount], wide.c_str(), _TRUNCATE);
				policy.NeverInjectCount++;
			}

			// ★ v68：**限定注入范围**的白名单（ini: `test_inject_only=`）。
			//
			// 与 `never_inject=` 的区别：
			//   · `never_inject=` 是**黑名单**（列在这里的**不**注入）；
			//   · `test_inject_only=` 是**白名单**（**只有**列在这里的才注入）。
			//
			// ★ 生效判据 = **名单非空**（`TestInjectCount > 0`），**与 `mode=` 无关**。
			//   为什么不绑 `mode=test`：spoof（截屏替换）只在"本应拒绝"时才生效，
			//   而 `mode=test` 的行为 = `log`（全部放行）⇒ 绑在一起就永远验证不到
			//   替换路径。解耦后 `mode=block` + 本名单既能限定注入范围、又保留拦截
			//   行为（见 shared 头 `FlagTestMode` 上面那段"解耦"）。
			//   ⚠️ 代价：本键**一旦写了就生效**，所以启动横幅必须把"生效条数 + 内容"
			//   打出来（app.cpp），否则"随手加了一行，防护范围就悄悄变了"不可见
			//   （铁律 97）。
			//
			// 匹配规则（见 shared 头里 `MaxTestInjectPaths` 的说明）：
			//   含路径分隔符 ⇒ 完整镜像路径前缀匹配；否则 ⇒ 镜像基名匹配。
			//
			// ⚠️ 支持**一行逗号分隔**（`a.exe,b.exe`）。这不是花哨 —— 不切分的
			//    话 `a.exe,b.exe` 会被当成**一个字面路径**，永远匹配不上，而且
			//    **完全静默**（铁律 97：失败必须可见）。
			else if (key == "test_inject_only") {
				std::wstring wide = Utf8ToWide(value);

				size_t start = 0;
				for (;;) {
					const size_t comma = wide.find(L',', start);
					std::wstring item = (comma == std::wstring::npos)
						? wide.substr(start)
						: wide.substr(start, comma - start);

					// 去首尾空白（用户写成 `a.exe, b.exe` 也要能匹配）。
					const size_t first = item.find_first_not_of(L" \t\r\n");
					if (first == std::wstring::npos) {
						item.clear();
					}
					else {
						const size_t last = item.find_last_not_of(L" \t\r\n");
						item = item.substr(first, last - first + 1);
					}

					if (!item.empty()) {
						if (policy.TestInjectCount < R3ShieldCore::MaxTestInjectPaths) {
							wcsncpy_s(policy.TestInjectPaths[policy.TestInjectCount],
								item.c_str(), _TRUNCATE);
							policy.TestInjectCount++;
						}
						// 超过上限：**静默丢弃**是错的 —— 用户会以为配上了。
						// 但这里没有日志设施（纯解析函数），所以由引擎启动时
						// 把"实际生效条数"打进横幅（见 app.cpp）。
					}

					if (comma == std::wstring::npos) {
						break;
					}
					start = comma + 1;
				}
			}
		}
	}

	const char* ModeIniText(ULONG mode) noexcept
	{
		switch (static_cast<R3ShieldCore::Mode>(mode)) {
		case R3ShieldCore::Mode::Log: return "log";
		case R3ShieldCore::Mode::Block: return "block";
		case R3ShieldCore::Mode::Ask: return "ask";
		case R3ShieldCore::Mode::BlockAll: return "block_all";
		case R3ShieldCore::Mode::BlockAllSafe: return "block_all_safe";
		default: return nullptr;
		}
	}

	bool SaveMode(ULONG mode, const std::filesystem::path& exeDirectory)
	{
		const char* text = ModeIniText(mode);
		if (!text) {
			return false;
		}

		// ★ v66：优先 `%ProgramData%\R3 Shield Core\r3shieldcore.ini`，
		//    没有才回退 exe 同目录（见 ResolveConfigPath 的完整理由）。
		const std::filesystem::path configPath = ResolveConfigPath(exeDirectory);

		// 整文件读成字节，只改 mode 那一行，其余原样写回。
		// 用 binary 是为了不动编码、不动换行风格（这个 ini 里有大段中文说明）。
		std::ifstream input(configPath, std::ios::binary);
		if (!input) {
			return false;
		}

		std::string content((std::istreambuf_iterator<char>(input)),
			std::istreambuf_iterator<char>());
		input.close();

		const std::string replacement = std::string("mode=") + text;

		std::string output;
		output.reserve(content.size() + 16);

		bool replaced = false;
		size_t position = 0;

		while (position < content.size()) {
			size_t lineEnd = content.find('\n', position);
			if (lineEnd == std::string::npos) {
				lineEnd = content.size();
			}

			std::string line = content.substr(position, lineEnd - position);

			// 分析时去掉行尾 CR，但**原样保留** —— 只有真替换了才重写这一行。
			std::string body = line;
			bool hadCarriageReturn = false;
			if (!body.empty() && body.back() == '\r') {
				body.pop_back();
				hadCarriageReturn = true;
			}

			if (!replaced) {
				std::string trimmed = Trim(body);
				if (!trimmed.empty() && trimmed[0] != '#' && trimmed[0] != ';') {
					size_t separator = trimmed.find('=');
					if (separator != std::string::npos &&
						ToLower(Trim(trimmed.substr(0, separator))) == "mode") {
						line = replacement + (hadCarriageReturn ? "\r" : "");
						replaced = true;
					}
				}
			}

			output += line;
			if (lineEnd < content.size()) {
				output += '\n';
			}

			position = lineEnd + 1;
		}

		if (!replaced) {
			// 文件里没有生效的 mode 行（全被注释掉了 / 压根没写）→ 追加一行。
			if (!output.empty() && output.back() != '\n') {
				output += '\n';
			}
			output += replacement + "\n";
		}

		std::ofstream result(configPath, std::ios::binary | std::ios::trunc);
		if (!result) {
			return false;
		}

		result.write(output.data(), static_cast<std::streamsize>(output.size()));
		result.flush();
		return result.good();
	}

	EngineSettings LoadEngineSettings(const std::filesystem::path& exeDirectory)
	{
		EngineSettings settings;

		// ★ v66：优先 `%ProgramData%\R3 Shield Core\r3shieldcore.ini`，
		//    没有才回退 exe 同目录（见 ResolveConfigPath 的完整理由）。
		const std::filesystem::path configPath = ResolveConfigPath(exeDirectory);
		std::ifstream file(configPath, std::ios::binary);
		if (!file) {
			return settings;
		}

		std::string line;
		while (std::getline(file, line)) {
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}

			std::string trimmed = Trim(line);
			if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
				continue;
			}

			size_t separator = trimmed.find('=');
			if (separator == std::string::npos) {
				continue;
			}

			std::string key = ToLower(Trim(trimmed.substr(0, separator)));
			std::string value = Trim(StripInlineComment(trimmed.substr(separator + 1)));

			if (key == "inject_interval_ms") {
				// 新进程注入的轮询间隔（毫秒）。见 r3shieldcore_config.h 的说明。
				// 解析失败 / 认不出 → 保持默认（10）。
				try {
					const long parsed = std::stol(value);
					if (parsed >= 1 && parsed <= 1000) {
						settings.InjectionIntervalMs = static_cast<ULONG>(parsed);
					}
				}
				catch (...) {
					// 保持默认
				}
			}
			else if (key == "neutralize_overlay") {
				// 反制覆盖层的**级别**（v39 起由 bool 升级为 0/1/2）：
				//   0 / false / no / off  → 关闭
				//   1                     → 开启，反制时**不问**
				//   2                     → 开启，每级执行前**弹窗询问**
				//
				// ⚠️ 向后兼容：旧配置里的 `1` 仍是"开且不问"。
				// ⚠️ 认不出的值（含没写）→ 保持默认（2，询问）—— 宁可多问，
				//    也不要因为一个拼错的值把"结束进程"变成静默行为。
				const std::string lower = ToLower(value);
				if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
					settings.NeutralizeOverlayLevel = 0;
				}
				else if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
					settings.NeutralizeOverlayLevel = 1;
				}
				else if (lower == "2") {
					settings.NeutralizeOverlayLevel = 2;
				}
			}
			else if (key == "replay_history_log") {
				// ★ v54：启动时回放 r3shieldcore-events.log 尾部若干条到界面事件列表。
				// ⚠️ 语义与所有 hook_* 一致：只有 1/true/yes/on 算开，
				//    其它（含 0）一律为关。
				settings.ReplayHistoryLog = IsTrue(value);
			}
			else if (key == "persist_stats") {
				// ★ v54：累计统计落盘（r3shieldcore-stats.json），跨重启连续。
				settings.PersistStats = IsTrue(value);
			}
			else if (key == "replay_history_limit") {
				// 回放条数上限。0 / 认不出 → 保持默认（200）。
				try {
					const long parsed = std::stol(value);
					if (parsed > 0 && parsed <= 5000) {
						settings.ReplayHistoryLimit = static_cast<ULONG>(parsed);
					}
				}
				catch (...) {
					// 保持默认
				}
			}
			else if (key == "high_risk_process_alert") {
				// ★ v61：高危进程提示的**级别**（0/1/2，语义见 r3shieldcore_config.h）。
				//
				// ⚠️ 与 `neutralize_overlay` 一样**不用 IsTrue** ——
				//    `1` 在这里是"开，但只记录"，而 IsTrue 只认 1/true/yes/on
				//    并把它当"开"，读不出 0/1/2 的区别。
				//
				// ⚠️ 认不出的值 → 保持默认（2）。理由同 neutralize_overlay：
				//    宁可多说一句，也不要因为一个拼错的值把功能**静默关掉**。
				const std::string lower = ToLower(value);
				if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
					settings.HighRiskProcessAlert = 0;
				}
				else if (lower == "1") {
					settings.HighRiskProcessAlert = 1;
				}
				else if (lower == "2" || lower == "true" || lower == "yes" || lower == "on") {
					settings.HighRiskProcessAlert = 2;
				}
			}
			else if (key == "high_risk_process_scan_ms") {
				// 扫描间隔（毫秒）。超出 200..60000 → 保持默认（1000）。
				try {
					const long parsed = std::stol(value);
					if (parsed >= 200 && parsed <= 60000) {
						settings.HighRiskProcessScanMs = static_cast<ULONG>(parsed);
					}
				}
				catch (...) {
					// 保持默认
				}
			}
			else if (key == "ark_enabled") {
				// ★ v62：ARK 页开关。**是 bool**（没有"仅记录"这一档，
				//   理由见 r3shieldcore_config.h）。
				//
				// ⚠️ 不能直接 `settings.ArkEnabled = IsTrue(value)` ——
				//    IsTrue 对**认不出**的值返回 false，那会把一个拼错的值
				//    （`ark_enabled=enable`）当成"用户要关掉"，把功能**静默关掉**。
				//    这里把"认得出是假"和"认不出"分开：认不出就保持默认。
				const std::string lower = ToLower(value);
				if (lower == "0" || lower == "false" || lower == "no" || lower == "off") {
					settings.ArkEnabled = false;
				}
				else if (lower == "1" || lower == "true" || lower == "yes" || lower == "on") {
					settings.ArkEnabled = true;
				}
				// 其余：保持默认（true）
			}
			else if (key == "ark_scan_ms") {
				// 扫描间隔（毫秒）。超出 500..60000 → 保持默认（2000）。
				try {
					const long parsed = std::stol(value);
					if (parsed >= 500 && parsed <= 60000) {
						settings.ArkScanMs = static_cast<ULONG>(parsed);
					}
				}
				catch (...) {
					// 保持默认
				}
			}
			else if (key == "ark_refresh_ms") {
				// ★ v63：界面刷新间隔（毫秒）。超出 200..60000 → 保持默认（1000）。
				//
				// ⚠️ 与 `ark_scan_ms` 分开是刻意的（详见 r3shieldcore_config.h）：
				//    scan 管"数据多久变一次"，refresh 管"界面多久看一次"。
				//    这里**不**做"refresh 不能小于 scan"之类的自动纠正 ——
				//    那样会把用户明确写的值悄悄改掉（铁律 33 家族：
				//    静默改配置 = 用户永远查不出为什么没生效）。
				//    两者关系只写在文档和配置页提示里。
				try {
					const long parsed = std::stol(value);
					if (parsed >= 200 && parsed <= 60000) {
						settings.ArkRefreshMs = static_cast<ULONG>(parsed);
					}
				}
				catch (...) {
					// 保持默认
				}
			}
		}

		return settings;
	}
}
