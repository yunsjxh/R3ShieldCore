//
// r3shieldcore_rules.cpp - 高危操作规则表。
//
// 规则选取原则：
//   1. 只挑"一旦被改就是持久化 / 提权 / 凭据泄露"的位置，不追求覆盖面广。
//   2. 不挑高频写入路径 —— 否则会变成弹窗机关枪（试过加
//      \Software\Microsoft\Windows\CurrentVersion\Explorer，
//      结果资源管理器自己每秒写十几次）。
//   3. 系统自身组件会写的路径必须排除（IsSystemInfrastructure 已挡掉一部分，
//      这里再挡一次），否则开机就弹窗。
//
#include "stdafx.h"
#include "r3shieldcore_rules.h"
#include "r3shieldcore_channel.h"

namespace
{
	// ------------------------------------------------------------------
	// 通用工具
	// ------------------------------------------------------------------

	// 不区分大小写的前缀比较。为了对齐注册表路径里大小写不统一的现实
	// （HKLM 下常见全大写，HKCU 下常见首字母大写）。
	bool StartsWithNoCase(PCWSTR text, PCWSTR prefix) noexcept
	{
		return _wcsnicmp(text, prefix, wcslen(prefix)) == 0;
	}

	// ------------------------------------------------------------------
	// 路径段等价（★ 处理 \CurrentControlSet 与 \ControlSetNNN 的等价）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么必须有这个：NtQueryKey(KeyNameInformation) 返回的是**内核**路径，
	//    它把符号链接 `CurrentControlSet` 解析成真实的 `ControlSet001`：
	//
	//      输入  \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services
	//      返回  \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services
	//
	//    （tools/regnorm.cpp 实测确认。）
	//
	//    而 **NtSetValueKey / NtSaveKey 这类"拿句柄"的判定路径**用的是
	//    ResolveKeyPath（即 NtQueryKey）→ 于是规则表里所有
	//    `SYSTEM\CurrentControlSet\...` 前缀（服务、防火墙、LSA、终端服务）
	//    对这两条最高频的路径**全部静默失效**。
	//
	//    修法：比对时把 `CurrentControlSet` 与 `ControlSetNNN` 视为同一段。
	//    只改匹配语义，不改写路径字符串 —— 日志/弹窗仍然展示内核真实路径，
	//    不影响可读性，也不引入分配。

	// 判断 `[text, text+len)` 这一段是不是 `ControlSet` + 若干数字。
	bool IsControlSetSegment(PCWSTR text, size_t len) noexcept
	{
		constexpr PCWSTR kMarker = L"ControlSet";
		constexpr size_t kMarkerLen = 10;

		if (len <= kMarkerLen) {
			return false;
		}
		if (_wcsnicmp(text, kMarker, kMarkerLen) != 0) {
			return false;
		}
		// 后面必须全是数字（ControlSet001）。
		for (size_t i = kMarkerLen; i < len; ++i) {
			if (text[i] < L'0' || text[i] > L'9') {
				return false;
			}
		}
		return true;
	}

	// 某一段是不是 `CurrentControlSet`（恰好整段）。
	bool IsCurrentControlSetSegment(PCWSTR text, size_t len) noexcept
	{
		constexpr PCWSTR kLiteral = L"CurrentControlSet";
		constexpr size_t kLiteralLen = 17;
		return len == kLiteralLen && _wcsnicmp(text, kLiteral, kLiteralLen) == 0;
	}

	// 取出 next 段（下一个 `\` 之前的部分），推进 cursor，并回填段起始指针。
	// 末尾返回空段（len=0），调用方据此终止。
	//
	// ⚠️ 必须把**段起始指针**回填出去：cursor 会被推进到分隔符处，
	//    直接拿 cursor 当段内容会带上前导 `\`（踩过：段长度多 1，
	//    比对结果整体错位，导致规则全部漏判）。
	void NextSegment(PCWSTR& cursor, PCWSTR& start, size_t& len) noexcept
	{
		start = nullptr;
		len = 0;

		if (!cursor || *cursor == L'\0') {
			return;
		}

		// 跳过开头可能的分隔符。
		while (*cursor == L'\\' || *cursor == L'/') {
			++cursor;
		}
		if (*cursor == L'\0') {
			return;
		}

		start = cursor;
		while (*cursor && *cursor != L'\\' && *cursor != L'/') {
			++cursor;
		}
		len = static_cast<size_t>(cursor - start);
	}

	// `text` 是否以 `prefix` 开头，按"路径段"逐段比对，
	// 且把 CurrentControlSet ≡ ControlSetNNN 视作同一段。
	//
	// 逐段而不是逐字符，是为了避免 `ControlSetX` 这种前缀被误判
	// （段等价必须整段成立）。
	bool KeyPrefixMatchesNoCase(PCWSTR text, PCWSTR prefix) noexcept
	{
		if (!text || !prefix) {
			return false;
		}
		if (prefix[0] == L'\0') {
			return true;
		}

		PCWSTR t = text;
		PCWSTR p = prefix;

		for (;;) {
			PCWSTR tSeg = nullptr;
			PCWSTR pSeg = nullptr;
			size_t tLen = 0;
			size_t pLen = 0;
			NextSegment(t, tSeg, tLen);
			NextSegment(p, pSeg, pLen);

			// 规则前缀走完了 → 命中。
			if (pLen == 0) {
				return true;
			}
			// 路径走完了但规则还没完 → 不命中。
			if (tLen == 0) {
				return false;
			}

			if (tLen == pLen && _wcsnicmp(tSeg, pSeg, tLen) == 0) {
				continue;
			}

			// 段不等长/不等值：只允许 CurrentControlSet ↔ ControlSetNNN 这一种等价。
			const bool equivalent =
				(IsCurrentControlSetSegment(pSeg, pLen) && IsControlSetSegment(tSeg, tLen)) ||
				(IsCurrentControlSetSegment(tSeg, tLen) && IsControlSetSegment(pSeg, pLen));

			if (!equivalent) {
				return false;
			}
		}
	}

	// 数一个路径有几段（忽略前导/重复分隔符）。
	size_t CountSegments(PCWSTR path) noexcept
	{
		size_t count = 0;
		PCWSTR cursor = path;
		for (;;) {
			PCWSTR seg = nullptr;
			size_t len = 0;
			NextSegment(cursor, seg, len);
			if (len == 0) {
				break;
			}
			++count;
		}
		return count;
	}

	// `prefix` 是否以 `text` 为**祖先**（text 是 prefix 的前若干段，
	// 且 text 比 prefix 短至少一段）。
	//
	// ⚠️ 用途：hive 级操作（NtSaveKey / NtSaveKeyEx / NtRestoreKey /
	//    NtReplaceKey）拿到的键路径可能是规则的**中间层级**。
	//
	//    实测（tools/regnorm.cpp）：`NtSaveKey` 拖走 SAM 时，句柄指向
	//      \REGISTRY\MACHINE\SAM  → relative = "SAM"
	//    而规则表里写的是叶子层：
	//      "SAM\SAM"（SAM 数据库本体）
	//    → StartsWith 不成立 → **拖 SAM 不判高危**（静默漏判）。
	//
	//    hive 操作的作用面是**整棵子树**，所以在 hive 场景下，
	//    "规则前缀是当前路径的后代" 同样构成危害：导出/覆盖 HKLM\SAM
	//    必然包含 HKLM\SAM\SAM。
	//
	//    只在 hive 场景启用（调用方按 op 判定），否则普通键操作
	//    写 HKLM\SAM 这个**父键**会被误判成"动 SAM 数据库"。
	bool KeyPrefixIsDescendantNoCase(PCWSTR text, PCWSTR prefix) noexcept
	{
		if (!text || !prefix || text[0] == L'\0' || prefix[0] == L'\0') {
			return false;
		}
		if (!KeyPrefixMatchesNoCase(prefix, text)) {
			return false;
		}
		// 同段数是"相等"，不算祖先（相等由 KeyPrefixMatchesNoCase 负责）。
		return CountSegments(prefix) > CountSegments(text);
	}

	// 不区分大小写的**子串**查找。
	//
	// ⚠️ 所有"路径片段"匹配都必须用它，不能用 `wcsstr`。Windows 的路径和
	//    注册表键名都不区分大小写，而实际大小写五花八门：
	//      · `GetWindowsDirectoryW()` 返回 `C:\WINDOWS`（全大写）
	//      · 服务配置里的二进制路径常写 `\SystemRoot\system32\...`（小写）
	//      · 驱动 INF 里的 `\SystemRoot\System32\drivers\`（首字母大写）
	//    三者指的是同一个目录。用 `wcsstr` 比 `\Windows\System32\drivers\`
	//    就会全部落空 —— 结果是**系统驱动被误判成高危**，
	//    同时攻击者只要把路径换个大小写就能**绕过**规则。
	//    （实测踩过：StartServiceW 启动 Defender 的 WdFilter 被判 HIGH。）
	bool ContainsNoCase(PCWSTR text, PCWSTR fragment) noexcept
	{
		if (!text || !fragment || fragment[0] == L'\0') {
			return false;
		}

		const size_t fragmentLength = wcslen(fragment);

		for (PCWSTR cursor = text; *cursor; ++cursor) {
			if (_wcsnicmp(cursor, fragment, fragmentLength) == 0) {
				return true;
			}
		}

		return false;
	}

	// 去掉 \REGISTRY\MACHINE\ 之类的前缀，让规则表只写有意义的部分。
	//
	// 输入形如：
	//   \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	//   \REGISTRY\USER\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run
	// 输出（hive 已剥离）：
	//   SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	//   Software\Microsoft\Windows\CurrentVersion\Run
	//
	// 注意必须区分"机器级"和"用户级" —— 有些规则只对其中一个生效。
	struct NormalizedKey
	{
		PCWSTR relative; // 剥离 hive 后的相对路径（hive 名不含在内）
		bool machine;    // true = HKLM / HKU 的 .DEFAULT 等机器范围
		bool user;       // true = 当前用户 hive（HKCU）
	};

	NormalizedKey NormalizeKey(PCWSTR keyPath) noexcept
	{
		NormalizedKey result = { keyPath, false, false };

		if (!keyPath || keyPath[0] == L'\0') {
			return result;
		}

		// \REGISTRY\MACHINE\... 或 \REGISTRY\USER\.DEFAULT\...
		if (StartsWithNoCase(keyPath, L"\\REGISTRY\\MACHINE\\")) {
			result.relative = keyPath + 18;
			result.machine = true;
			return result;
		}
		if (StartsWithNoCase(keyPath, L"\\REGISTRY\\USER\\")) {
			PCWSTR rest = keyPath + 15;
			// HKCU 的实际形态是 \REGISTRY\USER\S-1-5-21-...\Software\...
			// 把 SID 这一段跳过。跳过之后剩下的就是 Software\...。
			// 但要区分 ".DEFAULT" 这类非当前用户的 hive。
			if (StartsWithNoCase(rest, L".DEFAULT")) {
				result.machine = true;
				result.relative = rest;
			}
			else {
				PCWSTR slash = wcschr(rest, L'\\');
				if (slash) {
					result.relative = slash + 1;
					result.user = true;
				}
			}
			return result;
		}

		// 已经是相对路径（例如 hive 级操作给的 ObjectName）。
		return result;
	}

	// 用户自定义 protect_reg / protect_file 前缀匹配。
	bool MatchesProtectList(
		PCWSTR path,
		PCWSTR (*getAt)(ULONG index),
		ULONG count) noexcept
	{
		if (!path || path[0] == L'\0') {
			return false;
		}

		for (ULONG i = 0; i < count; i++) {
			PCWSTR prefix = getAt(i);
			if (prefix && prefix[0] != L'\0' && StartsWithNoCase(path, prefix)) {
				return true;
			}
		}

		return false;
	}

	PCWSTR ProtectRegAt(ULONG index) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectRegPaths[index] : nullptr;
	}

	PCWSTR ProtectFileAt(ULONG index) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectFilePaths[index] : nullptr;
	}

	ULONG ProtectRegCount() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectRegCount : 0;
	}

	ULONG ProtectFileCount() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectFileCount : 0;
	}

	PCWSTR ProtectProcessAt(ULONG index) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectProcessPaths[index] : nullptr;
	}

	ULONG ProtectProcessCount() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectProcessCount : 0;
	}

	PCWSTR ProtectDriverAt(ULONG index) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectDriverPaths[index] : nullptr;
	}

	ULONG ProtectDriverCount() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectDriverCount : 0;
	}

	PCWSTR ProtectNetAt(ULONG index) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectNetTargets[index] : nullptr;
	}

	ULONG ProtectNetCount() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy ? policy->ProtectNetCount : 0;
	}

	// ------------------------------------------------------------------
	// 网络地址解析工具（纯文本，不调 inet_pton —— 那些 API 自己就在 ws2_32 里，
	// 从 hook 里调会递归回我们自己的 hook）
	// ------------------------------------------------------------------

	// 判断一个字符串是不是纯 IPv4 点分十进制。返回点数，不是 IPv4 返回 -1。
	// 顺带把四段数值填进 out[4]（不校验 0..255，调用方自己判）。
	int ParseIpv4(PCWSTR text, ULONG out[4]) noexcept
	{
		if (!text) {
			return -1;
		}

		ULONG parts[4] = {};
		int index = 0;
		ULONG current = 0;
		bool anyDigit = false;

		for (PCWSTR p = text; ; p++) {
			const WCHAR c = *p;

			if (c >= L'0' && c <= L'9') {
				current = current * 10 + static_cast<ULONG>(c - L'0');
				if (current > 999) {
					return -1; // 明显不是一个合法八位组
				}
				anyDigit = true;
				continue;
			}

			if (c == L'.' || c == L'\0') {
				if (!anyDigit || index >= 4) {
					return -1;
				}
				parts[index++] = current;
				current = 0;
				anyDigit = false;

				if (c == L'\0') {
					break;
				}
				continue;
			}

			return -1; // 出现非数字非点字符 —— 不是 IPv4 字面量
		}

		if (index != 4) {
			return -1;
		}

		for (int i = 0; i < 4; i++) {
			out[i] = parts[i];
		}
		return 4;
	}

	// 地址是域名（非字面量 IP）吗？判断依据是"含字母且不是 IPv6 字面量风格"。
	bool LooksLikeHostname(PCWSTR address) noexcept
	{
		if (!address || !address[0]) {
			return false;
		}

		// 含冒号 → 大概率 IPv6 字面量或 "host:port" 形式，不当作域名。
		if (wcschr(address, L':') != nullptr) {
			return false;
		}

		// 纯 IPv4 → 不是域名。
		ULONG parts[4] = {};
		if (ParseIpv4(address, parts) == 4) {
			return false;
		}

		return true;
	}
}

namespace R3ShieldCoreRules
{
	// ------------------------------------------------------------------
	// 注册表高危规则
	// ------------------------------------------------------------------

	// 每条规则：相对路径前缀 + 适用范围 + 说明。
	struct RegistryRule
	{
		PCWSTR prefix;
		bool machine; // 是否适用于 HKLM
		bool user;    // 是否适用于 HKCU
		const char* reason;
	};

	// 规则表。搜索顺序即优先级，命中第一条就返回。
	//
	// ⚠️ 新增规则前先确认：这条路径会不会被正常软件高频写入？
	//    会的话就不该进这张表（参考 Explorer 的例子）。
	//
	// ⚠⚠️ 大小写：路径**不分大小写**比对（KeyPrefixMatchesNoCase），
	//    表里 `SOFTWARE\\` 与 `Software\\` 两种写法等价 —— 保留两种只是
	//    历史习惯（v19 起新增条目统一写两种，便于 grep 与对照真实路径）。
	constexpr RegistryRule kRegistryRules[] = {
		// ---- 自启动 ----
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true, true, "自启动项(Run)" },
		{ L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", true, true, "自启动项(Run)" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", true, true, "自启动项(RunOnce)" },
		{ L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", true, true, "自启动项(RunOnce)" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", true, true, "自启动项(策略Run)" },
		{ L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", true, true, "自启动项(策略Run)" },
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", true, false, "Winlogon(登录劫持)" },
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true, false, "AppInit_DLLs(全局注入)" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", true, true, "启动目录重定向" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", true, true, "启动目录重定向" },

		// ---- 服务 / 驱动 ----
		//
		// ⚠️ **具体条目必须在宽泛条目之前**（命中第一条即返回，见上方注释）。
		//    `SYSTEM\CurrentControlSet\Services` 覆盖**整棵子树** ——
		//    它后面的任何 `Services\Xxx\...` 条目都**永远不会命中**
		//    （不是漏报，是"判据能命中但返回的是通用 reason"）。
		//    所以下面几个来自 Services 子树的具体点必须排在它前面。
		//    自检工具：`tools/_ruleshadow.py`（列出被前序规则完全遮蔽的条目）。
		{ L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess", true, false, "防火墙配置" },
		{ L"System\\CurrentControlSet\\Services\\SharedAccess", true, false, "防火墙配置" },
		{ L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders", true, false, "时间服务提供程序(LSASS 注入)" },
		{ L"System\\CurrentControlSet\\Services\\W32Time\\TimeProviders", true, false, "时间服务提供程序(LSASS 注入)" },
		{ L"SYSTEM\\CurrentControlSet\\Services", true, false, "系统服务/驱动" },
		{ L"System\\CurrentControlSet\\Services", true, false, "系统服务/驱动" },

		// ---- 映像劫持（IFEO）----
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true, false, "映像劫持(IFEO)" },
		{ L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true, false, "映像劫持(IFEO)" },

		// ---- 凭据 / 安全 ----
		{ L"SAM\\SAM", true, false, "SAM(账户数据库)" },
		{ L"SECURITY\\Policy\\Secrets", true, false, "LSA Secrets(凭据)" },
		{ L"SECURITY\\Policy\\Accounts", true, false, "LSA 账户策略" },

		// ---- 浏览器劫持 ----
		{ L"SOFTWARE\\Microsoft\\Internet Explorer\\Main", true, true, "IE 主页劫持" },
		{ L"Software\\Microsoft\\Internet Explorer\\Main", true, true, "IE 主页劫持" },
		{ L"SOFTWARE\\Policies\\Microsoft\\Edge", true, false, "Edge 策略劫持" },
		{ L"SOFTWARE\\Policies\\Google\\Chrome", true, false, "Chrome 策略劫持" },

		// ---- 文件关联 / 命令处理器劫持 ----
		{ L"SOFTWARE\\Classes\\exefile\\shell\\open\\command", true, true, "exe 关联劫持" },
		{ L"SOFTWARE\\Classes\\batfile\\shell\\open\\command", true, true, "bat 关联劫持" },
		{ L"SOFTWARE\\Classes\\cmdfile\\shell\\open\\command", true, true, "cmd 关联劫持" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts", true, true, "文件关联劫持" },

		// ---- 安全中心 / 防火墙 ----
		{ L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", true, false, "Defender 策略" },
		{ L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions", true, false, "Defender 排除项" },
		// ⚠️ SharedAccess 的条目已上移到「服务 / 驱动」段（必须在宽泛的
		//    `Services` 前缀之前，否则永不命中）。此处不再重复。

		// ---- 远程访问 / 网络 ----
		{ L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server", true, false, "远程桌面配置" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Lsa", true, false, "LSA 配置" },

		//
		// ================================================================
		// v19 新增：三条被忽略的持久化 / 提权面
		// ================================================================
		//
		// ⚠️ 这三类都满足"实际危害"判据（铁律⑤）：不是"路径敏感"，
		//    而是**它们本身就是持久化 / 代码执行的落点**。
		//    与 kHostInjectionKeys 的分工：那张表判"值指向哪"（需要 value），
		//    这张表是 RegistryGuard 的粗筛（只看键路径），粒度粗但覆盖全
		//    （有些点没有值可比，如建键、改 DACL）。
		//

		// ---- ① 打印机驱动 / 端口监视器（v19）----
		//
		// Print Spooler 以 SYSTEM 身份加载"打印处理器 / 端口监视器 / 打印监视器"
		// 三组 DLL。注册点落在用户可写目录 = 打印机服务按攻击者路径起 DLL
		// → SYSTEM 权限代码执行（PrintNightmare 家族的核心落点）。
		//
		//   Monitors      —— 端口监视器（LOCAL_PORT / 网络端口），Spooler 直接 LoadLibrary
		//   Providers     —— 打印提供程序（本地/网络打印路由）
		//   Print Processors —— 打印处理器（datatype 转换），LoadLibraryEx 加载
		//   Ports         —— 端口定义（指向 Monitor DLL）
		//   Environments\Windows NT x86|x64\Print Processors —— 按架构的处理器
		//
		// ⚠️ 判据不看"值指向哪"（RegistryGuard 拿不到值语义），
		//    只看"写没写" —— 因为正常安装打印机驱动**不会**改 HKLM 这几处，
		//    改这几处的只有驱动安装包和攻击者。误报面窄，值得粗筛。
		{ L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", true, false, "打印机端口监视器(Spooler 加载 DLL)" },
		{ L"System\\CurrentControlSet\\Control\\Print\\Monitors", true, false, "打印机端口监视器(Spooler 加载 DLL)" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Print\\Providers", true, false, "打印提供程序(Spooler 加载 DLL)" },
		{ L"System\\CurrentControlSet\\Control\\Print\\Providers", true, false, "打印提供程序(Spooler 加载 DLL)" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments", true, false, "打印环境(处理器/驱动 DLL 路径)" },
		{ L"System\\CurrentControlSet\\Control\\Print\\Environments", true, false, "打印环境(处理器/驱动 DLL 路径)" },

		// ---- ② WinRT / Appx 应用注册与激活（v19）----
		//
		// ⚠️ 为什么单列：`AppModel` 这一族控制**谁来激活这个包**、**包的
		//    身份是什么**、**包下面挂哪些扩展点**。写它 = 可以
		//      · 伪造包身份（给非商店程序一个受信任的 Publisher，绕过
		//        AppLocker / 智能屏的签名检查）—— 铁律⑤说的"实际危害"典型
		//      · 注册一个后台任务 / 协议处理器（AppExtension），
		//        让系统在特定事件时启动我们的代码
		//      · 篡改 PackageRepository 让某个已装包的 "InstallLocation"
		//        指向用户可写目录
		//    RegistryGuard 只判键，够用 —— 这几处**正常安装流程由 AppX
		//    部署服务（提权）写**，用户态程序直接写 = 可疑。
		//
		//    Classes\ActivatableClasses —— 包注册的 COM 激活入口，
		//    指向包内实现类；劫持它等于让"某 CLSID 的激活"落到别处。
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel", true, true, "WinRT/Appx 包注册(身份/激活)" },
		{ L"Software\\Microsoft\\Windows\\CurrentVersion\\AppModel", true, true, "WinRT/Appx 包注册(身份/激活)" },
		{ L"SOFTWARE\\Classes\\ActivatableClasses", true, false, "WinRT 可激活类注册(COM 激活劫持)" },
		{ L"Software\\Classes\\ActivatableClasses", true, false, "WinRT 可激活类注册(COM 激活劫持)" },
		{ L"SOFTWARE\\Classes\\AppID", true, false, "COM AppID 注册(激活/权限绑定)" },
		{ L"Software\\Classes\\AppID", true, false, "COM AppID 注册(激活/权限绑定)" },
		{ L"SOFTWARE\\Classes\\Extensions", true, false, "WinRT 扩展点注册(后台任务/协议)" },
		{ L"Software\\Classes\\Extensions", true, false, "WinRT 扩展点注册(后台任务/协议)" },

		// ---- ③ COM+ 目录（v19）----
		//
		// COM+ 目录（COM3\Catalog）落库为 `%SystemRoot%\Registration`
		// 下的 RDBMS 文件，但**所有写入都经注册表这套 API 提交**。
		// 里面存的是"哪个 CLSID 由哪个 DLL 实现、跑在哪个账号身份下"。
		//
		// ⚠️ 危害：COM+ 应用可以指定**以哪个身份运行**（`RunAs` / 角色），
		//    写 Catalog 可以让系统按攻击者的 DLL 以高权限身份激活组件 ——
		//    这条路径**不经过 HKCR\CLSID**，所以既有的 COM 劫持规则看不到它。
		{ L"SOFTWARE\\Classes\\CLSID\\{00000112-0000-0000-C000-000000000046}", true, false, "COM+ 目录(注册/删除组件)" },
		{ L"SOFTWARE\\Classes\\CLSID\\{00000113-0000-0000-C000-000000000046}", true, false, "COM+ 目录(应用/角色管理)" },
		{ L"SOFTWARE\\Microsoft\\COM3\\Catalog", true, false, "COM+ 目录数据库(身份/路径注册)" },
		{ L"Software\\Microsoft\\COM3\\Catalog", true, false, "COM+ 目录数据库(身份/路径注册)" },

		// ---- ④ 其余已知自启 / 宿主劫持点（v19 补盲）----
		//
		// 这几个 e 家老自启点在实战里仍在使用，而 v15 的宿主注入表
		// 需要"值指向用户可写目录"才判 —— 建键 / 改 DACL / 写非路径值
		// 会漏。放进粗筛表补上（与 kHostInjectionKeys 故意重叠）。
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", true, true, "外壳延迟加载劫持" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", true, false, "ShellExecute 钩子劫持" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", true, true, "Explorer 策略劫持" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", true, true, "浏览器帮助对象(BHO)注入" },
		{ L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components", true, false, "Active Setup 登录自启" },
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", true, true, "AppInit_DLLs(全局注入)" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", true, false, "AppCertDlls(进程/文件创建回调注入)" },
		// ⚠️ W32Time\TimeProviders 的条目已上移到「服务 / 驱动」段（必须在宽泛的
		//    `Services` 前缀之前，否则永不命中）。此处不再重复。
		{ L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders", true, false, "安全提供程序注册(SSP 劫持)" },
	};

	// 哪些操作算"高危动作"。读操作不算 —— 读 SAM 是可疑但不破坏，
	// 且读操作太频繁，全问会打扰用户。
	bool IsHighRiskOp(ULONG op) noexcept
	{
		switch (static_cast<R3ShieldCore::Op>(op)) {
		// 键级写
		case R3ShieldCore::Op::CreateKey:
		case R3ShieldCore::Op::SetValueKey:
		case R3ShieldCore::Op::DeleteKey:
		case R3ShieldCore::Op::DeleteValueKey:
		case R3ShieldCore::Op::RenameKey:
		case R3ShieldCore::Op::SetInformationKey:
		// hive 级（这几种影响面最大）
		//
		// ⚠️ LoadKey/LoadKeyEx 挂载任意 hive、SaveKey/SaveKeyEx 拖走 SAM、
		//    RestoreKey/ReplaceKey 静默覆盖子树、UnloadKey/UnloadKeyEx 卸载
		//    子树（可用来把防护组件依赖的 hive 摘掉）—— 全部都是提权/持久化
		//    关键动作，必须升格为高危。
		case R3ShieldCore::Op::LoadKey:
		case R3ShieldCore::Op::LoadKeyEx:
		case R3ShieldCore::Op::ReplaceKey:
		case R3ShieldCore::Op::RestoreKey:
		case R3ShieldCore::Op::SaveKey:
		case R3ShieldCore::Op::SaveKeyEx:
		case R3ShieldCore::Op::UnloadKey:
		case R3ShieldCore::Op::UnloadKeyEx:
			return true;
		default:
			return false;
		}
	}

	const char* RegistryRiskReason(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept
	{
		(void)valueName;

		if (!IsHighRiskOp(op)) {
			return nullptr;
		}

		// ★ 自定义保护路径（ini `protect_reg=`）：**两种写法都要认**（2026-10-05 修）。
		//
		//   历史行为：只拿**原始** keyPath 做前缀比。而注册表 hook 交上来的
		//   keyPath 是**完整形式** ——
		//     · `\REGISTRY\MACHINE\SOFTWARE\...`
		//     · `\REGISTRY\USER\S-1-5-21-...\Software\...`
		//   （证据：真机日志的 `key=` 字段；以及 `tools/reg_rules_ut.cpp` 里
		//     所有既有用例都写完整形式。）
		//
		//   而文档 `配置详解.md` 给用户的例子是**相对形式**：
		//     `# protect_reg=SOFTWARE\MyCompany\Critical`
		//
		//   ⇒ 照文档配的 `protect_reg=` **一条都命中不了，而且完全静默**
		//     （没有报错、没有日志）—— 典型的"文档里写了但代码不会命中"（铁律 93）。
		//     实测：`tools/protect_reg_ut.cpp` 在修之前 5 条用例全 FAIL。
		//
		//   现在：原始形式先试（向后兼容已经在用完整形式的老配置），
		//        归一化后的**相对**形式再试（文档写法 / 用户 hive 自动跳过 SID 段）。
		if (MatchesUserProtectRegistry(keyPath)) {
			return "自定义保护路径";
		}

		NormalizedKey key = NormalizeKey(keyPath);
		if (key.relative && key.relative[0] != L'\0'
			&& MatchesUserProtectRegistry(key.relative)) {
			return "自定义保护路径";
		}

		if (!key.relative || key.relative[0] == L'\0') {
			return nullptr;
		}

		for (const RegistryRule& rule : kRegistryRules) {
			if (!rule.machine && !rule.user) {
				continue;
			}
			// 适用范围不匹配就跳过（例如 SAM 只在机器范围有意义）。
			if (key.machine && !rule.machine) {
				continue;
			}
			if (key.user && !rule.user) {
				continue;
			}
			// 既不是机器也不是用户（相对路径）时，两边都试。
			if (!key.machine && !key.user && !rule.machine && !rule.user) {
				continue;
			}

			// 逐段前缀比对，CurrentControlSet ≡ ControlSetNNN（见函数注释）。
			if (KeyPrefixMatchesNoCase(key.relative, rule.prefix)) {
				return rule.reason;
			}

			// hive 级操作拿到的是**子树根**（可能是规则的中间层级），
			// 作用面覆盖整棵子树 —— 规则前缀落在其下同样算命中。
			// 例如 NtSaveKey(HKLM\SAM) 导出整个 SAM，规则是 "SAM\SAM"。
			//
			// ⚠️ 只在 hive op 上放开，否则普通键操作写父键会误报。
			if (R3ShieldCore::IsHiveOp(op) && KeyPrefixIsDescendantNoCase(key.relative, rule.prefix)) {
				return rule.reason;
			}
		}

		return nullptr;
	}

	bool IsHighRiskRegistry(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept
	{
		return RegistryRiskReason(keyPath, valueName, op) != nullptr;
	}

	// ------------------------------------------------------------------
	// 文件高危规则
	// ------------------------------------------------------------------

	// 文件规则：路径片段 + 说明 + 是否对"改时间戳"敏感。
	//
	// 用"包含"而不是"前缀"匹配，因为系统目录可能带不同前缀
	// （C:\Windows、D:\Windows，或者 \Device\HarddiskVolumeN 归一化后）。
	//
	// ⚠️ timeStampSensitive 用于过滤 SetBasicInfo（SetFileTime）。
	//    hosts 必须为 false：Windows DNS 客户端 + Chromium 系
	//    （Chrome / Edge / WebView2 / Electron）每次域名解析都会更新
	//    hosts 的访问时间戳，每秒十几次 —— 判高危会变弹窗机关枪，
	//    并让解析线程卡满 30 秒超时。实测噪音占比 99.5%（13111/13183）。
	//    而"抹时间戳"对 hosts 没有实际意义（劫持要靠写内容，那个仍被拦）。
	struct FileRule
	{
		PCWSTR fragment;
		const char* reason;
		bool timeStampSensitive;
	};

	constexpr FileRule kFileRules[] = {
		// ---- 系统可执行 / 库 ----
		{ L"\\Windows\\System32\\", "系统目录(System32)", true },
		{ L"\\Windows\\SysWOW64\\", "系统目录(SysWOW64)", true },
		{ L"\\Windows\\System32\\drivers\\", "驱动目录", true },
		{ L"\\Windows\\WinSxS\\", "组件存储(WinSxS)", true },

		// ---- 自启动 ----
		{ L"\\Start Menu\\Programs\\Startup\\", "启动目录", true },
		{ L"\\Startup\\", "启动目录", true },

		// ---- 网络 / 名称解析 ----
		// hosts：写内容也算高危，但改时间戳是系统正常行为 → 排除。
		{ L"\\Windows\\System32\\drivers\\etc\\hosts", "hosts 文件", false },
		{ L"\\etc\\hosts", "hosts 文件", false },

		// ---- 计划任务 ----
		{ L"\\Windows\\System32\\Tasks\\", "计划任务", true },
		{ L"\\Windows\\Tasks\\", "计划任务", true },

		// ---- 引导 / 登陆界面 ----
		{ L"\\Windows\\Boot\\", "引导配置", true },
		{ L"\\EFI\\Microsoft\\Boot\\", "EFI 引导", true },
		{ L"\\Windows\\System32\\WinLogon.exe", "Winlogon 程序", true },
		{ L"\\Windows\\explorer.exe", "Explorer 程序", true },

		// ---- 系统还原 / 卷影 ----
		{ L"\\System Volume Information\\", "系统还原点", true },
	};

	// ------------------------------------------------------------------
	// v39：裸盘 / 物理盘设备判定（写 MBR / 引导扇区 = bootkit）
	// ------------------------------------------------------------------
	//
	// 为什么需要（**真实绕过**）：样本只用
	//   h = CreateFileA("\\\\.\\PhysicalDrive0", 0x10000000, 3, 0, 3, 0, 0);
	//   WriteFile(h, buf, 0x2800, &written, 0);
	// 就改掉了引导区，block 模式**没拦住**。这条链根本不进文件监控：
	//   · `\\.\PhysicalDrive0` 经 Win32→NT 转换后是 `\??\PhysicalDrive0`，
	//     `NormalizeDosPrefix` 把 `\??\` 剥掉 ⇒ 事件里的路径变成 `PhysicalDrive0`；
	//   · `IsDiskFile` 只认 `X:` 和 `\Device\HarddiskVolumeN`
	//     ⇒ 判成"非文件对象"（和管道/套接字一类）
	//     ⇒ `Evaluate` 第一步就 `Pass`，**连记录都没有**。
	//
	// ⚠️ 所以本判定必须在 `IsNonFileObject` **之前**做
	//    （见 file_guard.cpp 的 `Evaluate`）。
	//
	// 认得的形态（大小写不敏感，`\??\` / `\DosDevices\` 前缀先跳过）：
	//   PhysicalDriveN                       ← `\\.\PhysicalDriveN` 归一化后的样子
	//   \Device\HarddiskN\DRN                ← 对象管理器解析后的真名
	//   \Device\HarddiskN\PartitionN         ← 分区设备（N=0 即整盘）
	//
	// ⚠️ **绝不能误伤** `\Device\HarddiskVolumeN` —— 正常卷，所有文件都挂在它
	//    下面。区分点：`Harddisk` 之后要求跟**数字**，而 `Volume` 以 `V` 开头。
	//    `tools/file_rules_ut.cpp` 有专门的反例盯着这一点。
	//
	// ⚠️ 本函数**不看 op**。调用方 `FileRiskReason` 把它放在 `IsHighRiskFileOp`
	//    门槛之前 —— 否则 `NtOpenFile`（op=Open，不在高危 op 表里）会漏。
	PCWSTR SkipAsciiDigits(PCWSTR cursor) noexcept
	{
		if (!cursor || *cursor < L'0' || *cursor > L'9') {
			return nullptr;
		}
		while (*cursor >= L'0' && *cursor <= L'9') {
			++cursor;
		}
		return cursor;
	}

	bool IsRawDiskDevicePath(PCWSTR path) noexcept
	{
		if (!path || path[0] == L'\0') {
			return false;
		}

		// 归一化前后的两种写法都要认。
		if (StartsWithNoCase(path, L"\\??\\")) {
			path += 4;
		}
		else if (StartsWithNoCase(path, L"\\DosDevices\\")) {
			path += 12;
		}

		// 形态①：PhysicalDriveN
		constexpr PCWSTR kPhysicalDrive = L"PhysicalDrive";
		if (StartsWithNoCase(path, kPhysicalDrive) &&
			SkipAsciiDigits(path + wcslen(kPhysicalDrive)) != nullptr) {
			return true;
		}

		// 形态②③：\Device\HarddiskN\DRN / \Device\HarddiskN\PartitionN
		constexpr PCWSTR kHardDisk = L"\\Device\\Harddisk";
		if (!StartsWithNoCase(path, kHardDisk)) {
			return false;
		}

		PCWSTR afterDiskNumber = SkipAsciiDigits(path + wcslen(kHardDisk));
		if (!afterDiskNumber || *afterDiskNumber != L'\\') {
			// `\Device\HarddiskVolumeN` 走到这里：`V` 不是数字 ⇒ 不是裸盘。
			return false;
		}

		PCWSTR tail = afterDiskNumber + 1;

		if (StartsWithNoCase(tail, L"DR")) {
			return SkipAsciiDigits(tail + 2) != nullptr;
		}

		if (StartsWithNoCase(tail, L"Partition")) {
			return SkipAsciiDigits(tail + wcslen(L"Partition")) != nullptr;
		}

		return false;
	}

	// 哪些文件操作算高危。写 / 删 / 改名 / 改权限都算；
	// 普通 Open 不算（否则系统启动就弹窗）。
	// ⚠️ SetBasicInfo（改时间戳）也在此列，但命中后还要看规则条目的
	//    timeStampSensitive 标记（见 FileRiskReason）。
	bool IsHighRiskFileOp(ULONG fileOp) noexcept
	{
		switch (static_cast<R3ShieldCore::FileOp>(fileOp)) {
		case R3ShieldCore::FileOp::Create:
		case R3ShieldCore::FileOp::Write:
		case R3ShieldCore::FileOp::Delete:
		case R3ShieldCore::FileOp::Rename:
		case R3ShieldCore::FileOp::SetBasicInfo:
		case R3ShieldCore::FileOp::SetSecurity:
		case R3ShieldCore::FileOp::SetEa:
		case R3ShieldCore::FileOp::Truncate:
			return true;
		default:
			return false;
		}
	}

	const char* FileRiskReason(PCWSTR path, ULONG fileOp) noexcept
	{
		if (!path || path[0] == L'\0') {
			return nullptr;
		}

		//
		// ★ v39：裸盘 / 物理盘 —— 放在 `IsHighRiskFileOp` 门槛**之前**。
		//
		// 为什么提前：高危 op 表里**没有 `Open`**（普通打开不该算高危，
		// 否则系统启动就弹窗）。但"用写权限打开裸盘"本身就等于引导区写入
		// 的第一步 —— 样本既有 `CreateFileA`（op=Create）也有
		// `OpenFile` 变体（op=Open）。放在门槛后面就会漏掉后者。
		//
		// 只判路径不判 op 是安全的：`Evaluate` 只在"带写意图"时才调用
		// 到这里（`IsWriteIntent` 过滤过），所以能走到这里的裸盘打开
		// 一定是写意图。
		//
		if (IsRawDiskDevicePath(path)) {
			return "裸盘/物理盘写入(引导区)";
		}

		if (!IsHighRiskFileOp(fileOp)) {
			return nullptr;
		}

		if (MatchesUserProtectFile(path)) {
			return "自定义保护路径";
		}

		// 改时间戳（SetBasicInfo / SetFileTime）的额外过滤。
		//
		// 难点：hosts 路径同时命中 `\Windows\System32\`（timeStampSensitive=true）
		// 和它自己的 hosts 规则（false）。如果只是"命中就 continue"，会先撞上
		// System32 那条直接返回高危 —— 过滤形同虚设。
		//
		// 所以：改时间戳时，**先看有没有 timestamp-insensitive 的匹配**，
		// 有就一律不算高危（这类路径的时间戳是系统高频维护的）。
		// 只有"所有匹配规则都 timestamp-sensitive"才算高危。
		//
		// 见 kFileRules 上方说明（hosts 是系统/浏览器每秒刷十几次的正常行为）。
		const bool isTimestampOp =
			(static_cast<R3ShieldCore::FileOp>(fileOp) == R3ShieldCore::FileOp::SetBasicInfo);

		if (isTimestampOp) {
			const char* matchedReason = nullptr;
			bool matched = false;
			bool anySensitive = false;

			for (const FileRule& rule : kFileRules) {
				if (ContainsNoCase(path, rule.fragment)) {
					matched = true;
					if (!rule.timeStampSensitive) {
						// 命中任何"时间戳不敏感"的规则 → 整体不算高危。
						return nullptr;
					}
					anySensitive = true;
					if (!matchedReason) {
						matchedReason = rule.reason;
					}
				}
			}

			return (matched && anySensitive) ? matchedReason : nullptr;
		}

		for (const FileRule& rule : kFileRules) {
			if (ContainsNoCase(path, rule.fragment)) {
				return rule.reason;
			}
		}

		return nullptr;
	}

	bool IsHighRiskFile(PCWSTR path, ULONG fileOp) noexcept
	{
		return FileRiskReason(path, fileOp) != nullptr;
	}

	// ------------------------------------------------------------------
	// 进程高危规则
	// ------------------------------------------------------------------
	//
	// 判"这两个问题"，命中任一条即高危：
	//   1. 可执行文件本身来自敏感位置（System32、临时目录、根目录…）
	//      —— 从这些地方起进程几乎总是可疑的（正常程序装在自己目录里）。
	//   2. 父子关系可疑（Office/浏览器 → cmd/powershell/mshta…）
	//      —— 这是宏病毒、钓鱼文档、浏览器漏洞利用的经典链条。
	//
	// 注意：只判"创建"。终止进程没有询问的余地（调用即生效）。

	struct ProcessPathRule
	{
		PCWSTR fragment;
		const char* reason;
	};

	// 可疑的可执行来源。用片段匹配（盘符可能不同）。
	constexpr ProcessPathRule kProcessPathRules[] = {
		{ L"\\Windows\\System32\\", "System32 下的程序" },
		{ L"\\Windows\\SysWOW64\\", "SysWOW64 下的程序" },
		{ L"\\Windows\\Temp\\", "Windows 临时目录下的程序" },
		{ L"\\AppData\\Local\\Temp\\", "临时目录下的程序" },
		{ L"\\Downloads\\", "下载目录下的程序" },
		{ L"\\Start Menu\\Programs\\Startup\\", "启动目录下的程序" },
		{ L"\\ProgramData\\", "ProgramData 下的程序" },
		{ L"\\$Recycle.Bin\\", "回收站里的程序" },
	};

	// ------------------------------------------------------------------
	// System32 / SysWOW64 下的「日常可信程序」豁免表（★ block_all_safe 配套）
	// ------------------------------------------------------------------
	//
	// 用途：`ProcessRiskReason` 在跑 `kProcessPathRules` 之前先过这张表，
	//   命中则**不判高危**。解决 `\Windows\System32\` 片段规则把
	//   `notepad.exe` 这类日常程序全标 HIGH 的噪音问题（详见调用处注释）。
	//
	// ⚠️ 只列**普通用户会主动运行的、且攻击者利用价值低的**程序。
	//
	//   ❌ 绝对不要加进来的（它们必须继续报 HIGH）：
	//      cmd / powershell / pwsh / wscript / cscript / mshta
	//      rundll32 / regsvr32 / msiexec / installutil / regasm
	//      bitsadmin / certutil / wmic / forfiles / pcalua
	//      —— 这些是 LOLBin，攻击链的关键一环。
	//      父子关系规则（kProcessPairRules）与高危规则表另有判据盯着它们。
	//
	//   ⚠️ 也不要把 `schtasks` / `sc` / `net` / `net1` / `reg` 加进来 ——
	//      持久化与配置变更的常用工具。
	//
	// 匹配方式：**全路径片段**（`\System32\notepad.exe` 这样），
	//   而不是纯文件名 —— 避免 `D:\evil\notepad.exe` 蹭到豁免。
	constexpr PCWSTR kCommonTrustedSystemExes[] = {
		// 系统目录下的两个根（System32 / SysWOW64 都要覆盖）
		L"\\System32\\notepad.exe",
		L"\\SysWOW64\\notepad.exe",
		L"\\System32\\calc.exe",
		L"\\SysWOW64\\calc.exe",
		L"\\System32\\mspaint.exe",
		L"\\SysWOW64\\mspaint.exe",
		L"\\System32\\charmap.exe",
		L"\\System32\\magnify.exe",
		L"\\System32\\osk.exe",
		L"\\System32\\narrator.exe",
		L"\\System32\\utilman.exe",
		L"\\System32\\snippingtool.exe",
		L"\\System32\\mstsc.exe",
		L"\\System32\\cleanmgr.exe",
		L"\\System32\\dfrgui.exe",
		L"\\System32\\taskmgr.exe",
		L"\\System32\\control.exe",
		L"\\System32\\explorer.exe",
		L"\\System32\\write.exe",
		L"\\System32\\wordpad.exe",
		// ⚠️ 注意这里**没有** `wscript.exe` / `cscript.exe` / `mshta.exe` /
		//    `rundll32.exe` / `regsvr32.exe` / `cmd.exe` / `powershell.exe`
		//    —— 它们属 LOLBin，是本表头部 ❌ 列表里的东西，
		//    必须继续被 `\Windows\System32\` 规则判 HIGH。
		L"\\System32\\dxdiag.exe",
		L"\\System32\\msinfo32.exe",
		L"\\System32\\resmon.exe",
		L"\\System32\\perfmon.exe",
		L"\\System32\\eventvwr.exe",
		L"\\System32\\services.msc",
		L"\\System32\\compmgmt.msc",
		L"\\System32\\diskmgmt.msc",
		L"\\System32\\devmgmt.msc",
		L"\\System32\\certmgr.msc",
	};

	// ------------------------------------------------------------------
	// System32 / SysWOW64 下的「控制台 / 诊断工具」豁免表（★ v45 新增）
	// ------------------------------------------------------------------
	//
	// 【为什么必须单独一张表 —— 这条是实测踩出来的】
	//
	//   `\Windows\System32\` 是**片段**规则 ⇒ System32 下**每一个**程序都判 HIGH。
	//   而 `EvaluateProcess`（process_guard.cpp:558）在 **block 模式下对
	//   highRisk 的进程创建是「直接拒」**（不是"只记录"）。
	//   ⇒ 结论：**block 模式下，System32 下任何没进豁免表的程序都起不来**。
	//
	//   实测（`tools/procpath_probe.exe`，直调 `ProcessRiskReason`）：
	//     tasklist / findstr / find / timeout / icacls / net / ping / ipconfig
	//     netstat / whoami / hostname / systeminfo / where / robocopy / attrib
	//     全部 HIGH。用户机上真机日志也印证了：
	//       PROC BLOCK HIGH CreateProcess image=C:\WINDOWS\system32\tasklist.exe
	//
	//   后果不只是"不方便"：**引擎自己的部署脚本就是 cmd.exe 写的**，
	//   于是 `start.bat` 启动引擎后调 `tasklist` 做存活检查 → 被自己拦掉
	//   → 脚本误报"引擎未成功启动"（v44 实测），`stop.bat` 同理。
	//
	// 【收录标准】**只收"没有执行能力"的只读 / 诊断 / 文本 / 时间工具**。
	//   判据是"它能不能拿来跑别人的代码"——不能，就收。
	//
	//   ❌ 仍然**不收**（必须继续 HIGH）：
	//      执行类   cmd / powershell / pwsh / wscript / cscript / mshta /
	//               rundll32 / regsvr32 / msiexec / installutil / forfiles
	//      下载类   certutil / bitsadmin / curl / ftp
	//      持久化   schtasks / sc / reg / net / net1 / at
	//      查杀相关 taskkill（终止动作另有 terminate 判据盯着）
	//              wmic（WMI 可执行方法）
	//
	//   ⚠️ `icacls.exe` 是**有争议的一条**，收录理由：
	//      ① 改 ACL 需要调用方本来就持有 WRITE_DAC（非提权拿不到）；
	//      ② 它改 DACL 这个**动作**由安全描述符那套 hook 单独判
	//         （见 `挂服务权限: 改 DACL 即高危`）——豁免的只是"把它创建出来"；
	//      ③ 随包的 `unlock-acl.bat` 靠它还原旧版本加固过的目录权限
	//         （v57 起引擎不再要求目录不可写，但老部署仍需要这一步来解锁 ini）。
	//
	// 匹配方式：**先确认在 `\Windows\System32\` / `\Windows\SysWOW64\` 下，
	//   再按文件名匹配** —— 只写文件名的话 `D:\evil\tasklist.exe` 会蹭到豁免。
	constexpr PCWSTR kCommonTrustedSystemConsoleTools[] = {
		// —— 进程 / 系统信息（只读）——
		L"\\tasklist.exe",
		L"\\systeminfo.exe",
		L"\\whoami.exe",
		L"\\hostname.exe",
		L"\\where.exe",
		// —— 文本 / 文件属性（不执行）——
		L"\\find.exe",
		L"\\findstr.exe",
		L"\\sort.exe",
		L"\\more.exe",
		L"\\fc.exe",
		L"\\comp.exe",
		L"\\tree.exe",
		L"\\attrib.exe",
		// —— 延时 / 交互 ——
		L"\\timeout.exe",
		L"\\choice.exe",
		// —— 网络诊断（只读）——
		L"\\ping.exe",
		L"\\ipconfig.exe",
		L"\\netstat.exe",
		L"\\nslookup.exe",
		L"\\tracert.exe",
		L"\\pathping.exe",
		L"\\arp.exe",
		L"\\getmac.exe",
		// —— ACL（见上面的争议说明）——
		L"\\icacls.exe",
	};

	// 控制台工具豁免只认这两个系统目录。
	constexpr PCWSTR kConsoleToolSystemDirs[] = {
		L"\\Windows\\System32\\",
		L"\\Windows\\SysWOW64\\",
	};

	// ------------------------------------------------------------------
	// 路径里有没有 `..` 段？（★ v45）
	//
	// 为什么必须判：下面两张豁免表都是**子串**匹配，而 `NormalizeFilePath`
	//   （process_guard.cpp:255）只处理 `\??\` 与设备路径前缀，**不折叠 `..`**。
	//   于是
	//       C:\Windows\System32\..\Temp\tasklist.exe
	//   同时命中「含 \Windows\System32\」和「含 \tasklist.exe」两个子串 ——
	//   而文件实际躺在 `C:\Windows\Temp\`（Users 可写，规则表里本来就是 HIGH）。
	//   ⇒ 攻击者只要**把样本改名成 tasklist.exe**、再用带 `..` 的路径启动，
	//     就能白嫖这张豁免表 —— 豁免被伪造，等于规则没写。
	//
	//   判据 fail-closed：出现 `..` 段就**不给豁免**。内核给出的正常路径
	//   不会有 `..`，被拒的只可能是手工构造的；拒了之后流程继续落到
	//   `kProcessPathRules`，那条 `\Windows\System32\` 片段规则照样判 HIGH。
	// ------------------------------------------------------------------
	bool HasParentDirectorySegment(PCWSTR path) noexcept
	{
		if (!path) {
			return false;
		}

		for (PCWSTR cursor = path; *cursor; ++cursor) {
			if (cursor[0] != L'.' || cursor[1] != L'.') {
				continue;
			}

			const bool atSegmentStart = (cursor == path) || (cursor[-1] == L'\\');
			const bool atSegmentEnd = (cursor[2] == L'\0') || (cursor[2] == L'\\');
			if (atSegmentStart && atSegmentEnd) {
				return true;
			}
		}

		return false;
	}

	bool IsCommonTrustedSystemExecutable(PCWSTR imagePath) noexcept
	{
		if (!imagePath || imagePath[0] == L'\0') {
			return false;
		}

		// ★ 豁免不可伪造：带 `..` 段的路径一律不给豁免（理由见上）。
		if (HasParentDirectorySegment(imagePath)) {
			return false;
		}

		for (PCWSTR fragment : kCommonTrustedSystemExes) {
			if (ContainsNoCase(imagePath, fragment)) {
				return true;
			}
		}

		// ★ v45：控制台 / 诊断工具。两道都要过：
		//   ① 路径里出现 `\Windows\System32\` / `\Windows\SysWOW64\`；
		//   ② 文件名**紧跟在**该目录后面，而且就是路径的最后一段。
		//   ② 不能写成"路径里含 \tasklist.exe" —— 那样
		//   `C:\Windows\System32\sub\tasklist.exe` 也会被放行。
		//   用「紧跟 + 结尾」才是精确的"这个目录下的这个文件"。
		for (PCWSTR systemDir : kConsoleToolSystemDirs) {
			const size_t dirLength = wcslen(systemDir);

			for (PCWSTR cursor = imagePath; *cursor; ++cursor) {
				if (_wcsnicmp(cursor, systemDir, dirLength) != 0) {
					continue;
				}

				const PCWSTR after = cursor + dirLength;
				for (PCWSTR name : kCommonTrustedSystemConsoleTools) {
					// 表里写的是 L"\\tasklist.exe"，跳过前导反斜杠再比。
					const size_t nameLength = wcslen(name) - 1;
					if (StartsWithNoCase(after, name + 1) && after[nameLength] == L'\0') {
						return true;
					}
				}
			}
		}

		return false;
	}

	// ------------------------------------------------------------------
	// 「人手动启动」判定（v22）
	//
	// 用途：全拦模式（block_all / block_all_safe）下，判断一个**进程创建**
	//   是不是"有人在跟前点的"：
	//     是  → 弹窗询问（用户有机会放行）
	//     否  → 直接拦（服务/脚本/恶意程序自己拉起的子进程，旁边没人看着）
	//
	// 判据：**父进程是不是"人操作的中介"**。
	//
	// 为什么不只看 explorer.exe：双击桌面图标确实是 explorer 当父进程，
	//   但下面这些常见启动方式**父进程不是 explorer**，只认 explorer 会误伤：
	//     · 右键「以管理员身份运行」→ 父进程是 **svchost.exe**（UAC 提权中介）
	//     · 从压缩包里双击       → 父进程是 WinRAR / 7zFM / Bandizip
	//     · 从浏览器下载后点「打开」→ 父进程是 chrome / msedge
	//     · 用 Everything / Listary 等启动器 → 父进程是那个启动器
	//
	// ⚠️ **明确不含**（这是本表的安全边界）：
	//   cmd.exe / powershell.exe / wscript.exe / cscript.exe / mshta.exe /
	//   rundll32.exe / regsvr32.exe / conhost.exe / wsl.exe
	//   它们是"恶意程序拉起子进程"最常用的媒介，也最容易由脚本自动触发。
	//   把这些算成"人启动"等于给自动化攻击开后门。
	//
	// ⚠️ 匹配方式：**纯文件名**（`\explorer.exe` 这样带前导反斜杠）。
	//   不能只写 `explorer.exe` —— 那会命中 `D:\evil\myexplorer.exe`。
	//   前导 `\` 保证匹配的是"路径里某个完整文件名"，不是后缀。
	//
	// ⚠️ 父进程拿不到路径（已退出 / 受限）→ 返回 false → 直接拦（fail-closed）。
	//   恶意程序完全可以先退出父进程再造子进程；这种情况下"没人能确认有
	//   人在跟前"，按不可信处理是对的。
	// ------------------------------------------------------------------
	constexpr PCWSTR kUserLaunchParentExes[] = {
		// —— 桌面外壳 ——
		L"\\explorer.exe",
		// —— UAC 提权中介（右键"以管理员身份运行"）——
		L"\\svchost.exe",
		// —— 压缩 / 归档软件（双击压缩包里的程序）——
		L"\\WinRAR.exe",
		L"\\7zFM.exe",
		L"\\7zG.exe",
		L"\\Bandizip.exe",
		L"\\WinZip32.exe",
		L"\\HaoZip.exe",
		L"\\PeaZip.exe",
		// —— 浏览器（"下载后打开"）——
		L"\\chrome.exe",
		L"\\msedge.exe",
		L"\\firefox.exe",
		L"\\iexplore.exe",
		L"\\brave.exe",
		// —— 文件启动器 / 快速搜索 ——
		L"\\Everything.exe",
		L"\\Listary.exe",
		L"\\Wox.exe",
		L"\\Flow.Launcher.exe",
		L"\\PowerToys.PowerLauncher.exe",
		// —— 资源管理器替代（常见第三方）——
		L"\\TotalCMD64.exe",
		L"\\TotalCMD.exe",
		L"\\DirectoryOpus.exe",
		//
		// ⚠️ 到此为止。下面这些**故意不加**：
		//     cmd.exe / powershell.exe / pwsh.exe / wscript.exe / cscript.exe
		//     mshta.exe / rundll32.exe / regsvr32.exe / conhost.exe
		//     services.exe / wininit.exe / taskeng.exe / schtasks.exe
	};

	bool IsUserInitiatedLaunch(PCWSTR parentImagePath) noexcept
	{
		// 父进程路径拿不到 → 不可信（fail-closed）。
		if (!parentImagePath || parentImagePath[0] == L'\0') {
			return false;
		}

		for (PCWSTR fragment : kUserLaunchParentExes) {
			if (ContainsNoCase(parentImagePath, fragment)) {
				return true;
			}
		}

		return false;
	}

	// 可疑的父子关系：父进程名（小写、不含扩展名）+ 子进程名。
	// 中间随便生成 shell 是宏病毒/钓鱼/漏洞利用的典型链条。
	struct ProcessPairRule
	{
		PCWSTR parent; // 不含扩展名，小写
		PCWSTR child;  // 不含扩展名，小写
		const char* reason;
	};

	constexpr ProcessPairRule kProcessPairRules[] = {
		{ L"winword", L"cmd", "Office 启动了命令行" },
		{ L"winword", L"powershell", "Office 启动了 PowerShell" },
		{ L"winword", L"wscript", "Office 启动了脚本宿主" },
		{ L"winword", L"cscript", "Office 启动了脚本宿主" },
		{ L"winword", L"mshta", "Office 启动了 mshta" },
		{ L"winword", L"rundll32", "Office 启动了 rundll32" },
		{ L"winword", L"regsvr32", "Office 启动了 regsvr32" },
		{ L"excel", L"cmd", "Office 启动了命令行" },
		{ L"excel", L"powershell", "Office 启动了 PowerShell" },
		{ L"excel", L"wscript", "Office 启动了脚本宿主" },
		{ L"excel", L"mshta", "Office 启动了 mshta" },
		{ L"excel", L"rundll32", "Office 启动了 rundll32" },
		{ L"powerpnt", L"cmd", "Office 启动了命令行" },
		{ L"powerpnt", L"powershell", "Office 启动了 PowerShell" },
		{ L"powerpnt", L"mshta", "Office 启动了 mshta" },
		{ L"outlook", L"cmd", "Outlook 启动了命令行" },
		{ L"outlook", L"powershell", "Outlook 启动了 PowerShell" },
		{ L"outlook", L"wscript", "Outlook 启动了脚本宿主" },
		{ L"wscript", L"powershell", "脚本宿主启动了 PowerShell" },
		{ L"cscript", L"powershell", "脚本宿主启动了 PowerShell" },
		{ L"mshta", L"powershell", "mshta 启动了 PowerShell" },
		{ L"wscript", L"cmd", "脚本宿主启动了命令行" },
		{ L"cscript", L"cmd", "脚本宿主启动了命令行" },
		{ L"mshta", L"cmd", "mshta 启动了命令行" },
		// 浏览器 → 解释器：漏洞利用链（正常情况浏览器只起浏览器/更新器）
		{ L"chrome", L"powershell", "浏览器启动了 PowerShell" },
		{ L"chrome", L"cmd", "浏览器启动了命令行" },
		{ L"msedge", L"powershell", "浏览器启动了 PowerShell" },
		{ L"msedge", L"cmd", "浏览器启动了命令行" },
		{ L"firefox", L"powershell", "浏览器启动了 PowerShell" },
		{ L"firefox", L"cmd", "浏览器启动了命令行" },
		// 服务宿主起了命令行 —— 正常服务不这么干
		{ L"svchost", L"powershell", "svchost 启动了 PowerShell" },
		{ L"svchost", L"cmd", "svchost 启动了命令行" },
		{ L"svchost", L"mshta", "svchost 启动了 mshta" },
		{ L"lsass", L"cmd", "lsass 启动了命令行" },
		{ L"lsass", L"powershell", "lsass 启动了 PowerShell" },
		// 系统目录里的"解释器"起解释器 —— 常用于无文件攻击
		{ L"rundll32", L"powershell", "rundll32 启动了 PowerShell" },
		{ L"regsvr32", L"powershell", "regsvr32 启动了 PowerShell" },
	};

	// 取路径最后一段（文件名），不含目录。
	PCWSTR FileNamePart(PCWSTR path) noexcept
	{
		if (!path) {
			return L"";
		}

		PCWSTR last = path;
		for (PCWSTR p = path; *p; p++) {
			if (*p == L'\\' || *p == L'/') {
				last = p + 1;
			}
		}
		return last;
	}

	// 把文件名去掉扩展名，并小写化，方便和规则表比。
	// 输出缓冲由调用方提供。
	void StemLower(PCWSTR fileName, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch == 0) {
			return;
		}
		out[0] = L'\0';
		if (!fileName) {
			return;
		}

		size_t n = 0;
		while (fileName[n] && n + 1 < cch) {
			WCHAR c = fileName[n];
			if (c == L'.') {
				break; // 到第一个点为止（去掉所有扩展名）
			}
			out[n] = static_cast<WCHAR>(towlower(c));
			n++;
		}
		out[n] = L'\0';
	}

	const char* ProcessRiskReason(PCWSTR imagePath, ULONG processOp, ULONG parentPid) noexcept
	{
		(void)parentPid;

		const R3ShieldCore::ProcessOp op = static_cast<R3ShieldCore::ProcessOp>(processOp);

		// ------------------------------------------------------------------
		// v18：NtCreateProcess（老 API）—— 判据与 Create 完全不同。
		// ------------------------------------------------------------------
		//
		// ⚠️ 为什么不能复用下面的路径匹配：NtCreateProcess**不收
		//    RTL_USER_PROCESS_PARAMETERS**，所以 hook 侧拿不到镜像路径
		//    （imagePath 恒为 NULL / 空）—— 走下面的 `if (!imagePath) return nullptr;`
		//    就是**永远非高危**，整个 hook 等于白挂（典型 §10-33 静默降级）。
		//
		//    所以这里改用**特征判据**。判据保守到什么程度？
		//    Windows 自身的 CreateProcessW 走的是 NtCreateUserProcess，
		//    **NtCreateProcess 在正常系统上几乎不出现** —— 出现本身就是信号。
		//    因此这里宁宽勿漏：只要调了就记高危，理由写清楚。
		//
		//    真做细的话可以用 SectionHandle / DebugPort 区分（hook 侧带过来
		//    放在 imagePath 的位置不合适，留给 Event::Flags2），当前先按
		//    "老 API + 无参数块"这条最稳的特征判。
		//
		if (op == R3ShieldCore::ProcessOp::CreateLegacy) {
			if (imagePath && imagePath[0] != L'\0') {
				// 罕见情形：调用方自己拼了路径文本（少见但可能）。
				// 有路径就顺带把路径规则也跑一遍，命中自定义保护更要报。
				if (MatchesUserProtectProcess(imagePath)) {
					return "自定义保护程序（老 API 创建）";
				}
				for (const ProcessPathRule& rule : kProcessPathRules) {
					if (ContainsNoCase(imagePath, rule.fragment)) {
						return rule.reason;
					}
				}
			}
			return "NtCreateProcess 创建进程（无参数块，疑似镂空/反射加载）";
		}

		// 只有创建才判高危；终止只记录。
		if (op != R3ShieldCore::ProcessOp::Create) {
			return nullptr;
		}

		if (!imagePath || imagePath[0] == L'\0') {
			return nullptr;
		}

		if (MatchesUserProtectProcess(imagePath)) {
			return "自定义保护程序";
		}

		// ------------------------------------------------------------------
		// ★ 收窄 System32 / SysWOW64 片段规则的误报。
		// ------------------------------------------------------------------
		//
		// 问题：`kProcessPathRules` 里 `\Windows\System32\` 是**片段匹配**，
		//   于是 `notepad.exe` / `calc.exe` / `mspaint.exe` 这些**日常可信
		//   程序**全部被判 HIGH-RISK。
		//
		// ⚠️★ v45 更正（原来这里写着"在 log / block 模式下问题不大"——**是错的**）：
		//   这句话的推理是"block 的普通创建本来就不拦"，但**这些程序不是
		//   "普通创建"，它们被本函数判成了 HIGH**，而 `EvaluateProcess`
		//   （process_guard.cpp:558）在 block 模式下对 highRisk 的创建是
		//   **直接拒**。所以误报在这里不是"噪音"，是**实打实的拒绝**：
		//   block 模式下 System32 下任何没进豁免表的程序都起不来。
		//   实测见 `tools/procpath_probe.exe` 与 kCommonTrustedSystemConsoleTools
		//   上面的说明（用户机上 `tasklist.exe` 真被拒了，连带把引擎自己的
		//   `start.bat` 打瘫）。
		//
		//   ⇒ 所以这里做的是"先过豁免表"：GUI 日常程序在 kCommonTrustedSystemExes，
		//     控制台/诊断工具在 kCommonTrustedSystemConsoleTools。两张表都过不了
		//     才落到 kProcessPathRules。**block_all_safe 下这个误报同样会变成噪音源**
		//     —— 每一次记事本启动都在日志里标 HIGH，真信号被淹掉。
		//
		// 修法：先过一张"系统目录下的日常程序"白名单，命中则**不判高危**。
		//
		// ⚠️ 为什么是"放行"而不是"删规则"：
		//   `\Windows\System32\` 这条规则本身是有价值的（攻击者把 exe 丢到
		//   System32 是经典手法，见 `IsInWritableWindowsSubdir` 的反面）。
		//   删掉等于放弃这个判据；只在**明确的日常程序**上开豁免，
		//   其余 System32 程序（含攻击者投放的）照样报。
		//
		// ⚠️ 豁免表的选取原则：**只列普通用户会主动双击的、且攻击者
		//   利用价值低的**。不要往里塞 `cmd`/`powershell`/`rundll32`/
		//   `regsvr32`/`mshta` 这类 LOLBin —— 它们恰恰是攻击链的关键，
		//   必须继续报 HIGH（父子关系规则里已经单独盯着它们）。
		if (IsCommonTrustedSystemExecutable(imagePath)) {
			return nullptr;
		}

		for (const ProcessPathRule& rule : kProcessPathRules) {
			if (ContainsNoCase(imagePath, rule.fragment)) {
				return rule.reason;
			}
		}

		return nullptr;
	}

	bool IsHighRiskProcessImage(PCWSTR imagePath, ULONG processOp, ULONG parentPid) noexcept
	{
		return ProcessRiskReason(imagePath, processOp, parentPid) != nullptr;
	}

	// ==================================================================
	// ★ v61 高危进程「存在」判定
	// ==================================================================
	//
	// 与上面 `ProcessRiskReason` 的分工（**别把两者混起来**）：
	//
	//   `ProcessRiskReason` —— 判"**这一次创建**该不该拦"。数据来源是被注入
	//     进程里的 hook ⇒ **只看得见被监控进程发起、且落在引擎观测窗内**的创建。
	//     v60b 复盘（`Windows XP Horror` 的症状键全日志 0 命中）暴露的正是
	//     这个盲区：破坏发生在观测窗之前 ⇒ 注入路根本看不见。
	//
	//   本组判据          —— 判"**这个进程本身是不是高危**"。引擎定期快照
	//     **全机**进程逐个过这里 ⇒ **不依赖注入覆盖、也不依赖观测窗**
	//     （引擎启动前就在跑的进程一样能看见）。
	//
	// ------------------------------------------------------------------
	// ★ 判据的"度"（刻意收窄 —— 铁律 4：高危判据必须带**实际危害**）
	// ------------------------------------------------------------------
	//
	//   ① 系统进程名伪装
	//        文件名 == 受保护系统组件名，但**不在**该组件的规范目录
	//        （`%SystemRoot%\System32\` / `SysWOW64\` / `Sysnative\` / `WinSxS\`）。
	//        危害：冒充可信进程骗过用户与其它软件（MITRE T1036.005）。
	//        正常软件不会把自己命名成 `lsass.exe` 放到别处 ⇒ 信号极强、误报极低。
	//
	//   ② 形近伪装
	//        剥离空白 + 视觉字符归一化（`0→o` `1→l` `3→e` `5→s` …）后等于系统
	//        组件名，**或**与系统组件名只差一对**相邻字符交换**；且原文件名
	//        不等于系统组件名、且不在系统目录。
	//        危害：同上，但更隐蔽（`lsass .exe` / `svch0st.exe` / `scvhost.exe`）。
	//        ⚠️ 相邻交换会撞上 `Ssms.exe`（SQL Server Management Studio 正是
	//           `smss.exe` 的交换变体）⇒ 有显式豁免表 `kMasqueradeExempt`。
	//           `tools/high_risk_process_ut.cpp` **穷举**全部交换变体并断言
	//           "每一个要么被检出、要么在豁免表里" —— 以后往系统名表里加名字
	//           时，测试会逼着人先想清楚碰撞。
	//
	//   ③ 已知攻击工具
	//        文件名（去扩展名）在攻击工具名单里。这些工具**存在本身**就意味着
	//        凭据窃取 / 横向移动。本项只提示不拦截，所以名单可以比"高危拦截表"宽。
	//
	// ------------------------------------------------------------------
	// ⚠️ **刻意不做**的判据（做了就是噪音，会把这个提示功能整个淹掉）
	// ------------------------------------------------------------------
	//
	//   · "从用户可写目录运行的进程" —— 安装包 / 便携软件 / 自解压全都是这样。
	//     而且"判断一个目录可不可写"本身极容易做错：铁律 91 那场误报灾难
	//     （`\ProgramData\` 整片判可写）就是栽在这里。
	//   · "非系统目录的进程" —— 等于把用户装的软件全报一遍。
	//   · "无数字签名" —— 要 `WinVerifyTrust` + 证书链缓存；离线环境会大面积
	//     误报，而且把签名验证做对本身就是一个子项目。留作后续增强。
	//   · "名字是 LOLBin（cmd / powershell / wscript / rundll32 / regsvr32…）"
	//     —— 复制、转发这些程序是常见做法（便携工具、安装包、CI 环境），
	//     而且它们的危害在"**谁**调用它们"，不在"它叫什么名字"。
	//     放进伪装表只会制造误报（`ProcessPairRiskReason` 已经在盯父子关系了）。

	// 受保护的系统组件名（全小写，带扩展名）。
	// 只列"冒充了就能骗过人"的那批关键进程，**不是** System32 全表。
	constexpr PCWSTR kSystemCriticalImages[] = {
		L"smss.exe",
		L"csrss.exe",
		L"wininit.exe",
		L"winlogon.exe",
		L"services.exe",
		L"lsass.exe",
		L"lsaiso.exe",
		L"svchost.exe",
		L"explorer.exe",
		L"taskhostw.exe",
		L"dwm.exe",
		L"spoolsv.exe",
		L"conhost.exe",
		L"runtimebroker.exe",
		L"dllhost.exe",
		L"fontdrvhost.exe",
		L"sihost.exe",
		L"audiodg.exe",
		L"securityhealthservice.exe",
		L"msmpeng.exe",
		L"nissrv.exe",
		L"wmiprvse.exe",
		L"wudfhost.exe",
		L"searchindexer.exe",
		L"searchhost.exe",
		L"startmenuexperiencehost.exe",
		L"shellexperiencehost.exe",
		L"textinputhost.exe",
		L"applicationframehost.exe",
		L"useroobebroker.exe",
		L"ctfmon.exe",
		L"taskmgr.exe",
	};

	// 系统组件的规范目录（相对 `%SystemRoot%`，含前后反斜杠）。
	constexpr PCWSTR kSystemImageDirs[] = {
		L"\\System32\\",
		L"\\SysWOW64\\",
		L"\\Sysnative\\",   // 32 位进程看 System32 的重定向别名
		L"\\WinSxS\\",      // 组件存储里的硬链接副本（正常运行极少，但不误伤）
	};

	// ★ 少数组件名的**额外**规范目录（相对 `%SystemRoot%`，含前后反斜杠）。
	//
	// 为什么需要它 —— v61 真机首跑的误报（必须记住这一课）：
	//   `kSystemImageDirs` 只覆盖 System32 家族，但有两个名字**本来就不住那儿**：
	//     · `explorer.exe` —— 住在 `%SystemRoot%\`（**根目录**，不是 System32）
	//     · `searchhost.exe` / `startmenuexperiencehost.exe` /
	//       `shellexperiencehost.exe` / `textinputhost.exe` —— 住在
	//       `%SystemRoot%\SystemApps\<包名>\`（UWP 宿主）
	//   于是这 5 个**完全正常**的系统进程被判成"伪装系统进程名"。
	//   实测（一台普通 Win10 桌面 / 270 个进程）：**5 个候选全是误报**。
	//   ⇒ 单元测试当时全绿，因为用例只写了 `SysPath(L"System32", ...)` ——
	//     **测试的"正常路径"覆盖不到真机上真实存在的正常路径**（铁律 54：
	//     必须有反向对照，且对照要来自真机，不是自己想象的）。
	//
	// 为什么不干脆把 `\` 和 `\SystemApps\` 整个加进 `kSystemImageDirs`：
	//   那等于把整个 Windows 根目录 + 整个 SystemApps 洗白 ⇒
	//   `C:\Windows\lsass.exe`、`C:\Windows\Temp\explorer.exe`、
	//   `C:\Windows\SystemApps\x\svchost.exe` 这些**典型落盘伪装**也会一起放走。
	//   所以只对"确实住在那儿"的**名字**开口子，而且**深度精确匹配** ——
	//   精确到 (名字, 目录, 深度) 这个三元组，多一层、少一层都不算数。
	struct SystemImageExtraDir
	{
		PCWSTR Name;    // 全小写、带扩展名
		PCWSTR Dir;     // 相对 `%SystemRoot%`，含前后反斜杠
		ULONG  Depth;   // 前缀之后、文件名之前还有**几层**目录（精确匹配）
	};

	constexpr SystemImageExtraDir kSystemImageExtraDirs[] = {
		// `explorer.exe` 就住在 `%SystemRoot%\` 下，**直接**在那儿，不深一层。
		{ L"explorer.exe", L"\\", 0 },
		// UWP 宿主住在 `%SystemRoot%\SystemApps\<包名>\` —— 中间正好一层。
		{ L"searchhost.exe", L"\\SystemApps\\", 1 },
		{ L"startmenuexperiencehost.exe", L"\\SystemApps\\", 1 },
		{ L"shellexperiencehost.exe", L"\\SystemApps\\", 1 },
		{ L"textinputhost.exe", L"\\SystemApps\\", 1 },
	};

	// 形近伪装会撞上的**正常软件名**（全小写、带扩展名）。
	// 目前穷举出的唯一一个是 SQL Server Management Studio —— `Ssms.exe`
	// 正是 `smss.exe` 的相邻交换变体。见 `high_risk_process_ut.cpp` 的穷举断言。
	constexpr PCWSTR kMasqueradeExempt[] = {
		L"ssms.exe",
	};

	// 已知攻击工具（全小写，**不带**扩展名）。
	//
	// ⚠️ 本项**只提示、不拦截**，所以可以比"高危拦截表"宽；但仍刻意剔除两类：
	//      · 太通用的词（`beacon` / `empire` / `spray` / `responder` / `cme` /
	//        `john`）—— 会和正常软件撞名
	//      · 普通用户机器上常见的开发/运维工具（`ngrok` / `plink`）
	constexpr PCWSTR kAttackToolNames[] = {
		// 凭据窃取
		L"mimikatz", L"mimilib", L"mimidrv", L"pypykatz",
		L"wce", L"fgdump", L"pwdump", L"pwdump7", L"pwdump8",
		L"gsecdump", L"cachedump", L"lazagne", L"secretsdump",
		// 进程/内存转储（常被用来抓 lsass）
		L"procdump", L"dumpert", L"nanodump", L"sharpdump",
		// Kerberos / AD 攻击
		L"rubeus", L"kekeo", L"kerbrute", L"sharphound", L"bloodhound",
		L"adfind", L"sharpup", L"powerup", L"seatbelt", L"winpeas", L"linenum",
		// 横向移动 / 远程执行
		L"psexec", L"paexec", L"smbexec", L"wmiexec", L"atexec",
		L"dcomexec", L"crackmapexec",
		// 隧道 / 端口转发
		L"chisel", L"frpc", L"frps",
		// 口令破解
		L"hydra", L"medusa", L"hashcat",
		// 经典网络工具（攻击载荷里高频出现）
		L"nc", L"ncat", L"netcat", L"socat",
	};

	// 路径是否落在系统组件的规范目录里。
	bool IsInSystemImageDir(PCWSTR path, PCWSTR systemRoot) noexcept
	{
		if (!path || !systemRoot || systemRoot[0] == L'\0') {
			return false;
		}

		WCHAR prefix[MAX_PATH + 32] = {};
		for (PCWSTR dir : kSystemImageDirs) {
			if (swprintf_s(prefix, L"%s%s", systemRoot, dir) <= 0) {
				continue;
			}
			if (StartsWithNoCase(path, prefix)) {
				return true;
			}
		}

		return false;
	}

	// 名字 == name（全小写）时，path 是否位于该名字的**规范目录** ——
	// System32 家族（`kSystemImageDirs`）**或**它自己的额外目录
	// （`kSystemImageExtraDirs`）。
	//
	// 判据 ① 必须用这个、而不是笼统的 `IsInSystemImageDir` —— 否则
	// `C:\Windows\explorer.exe` 这类**本来就不在 System32 里**的正常进程
	// 会被判成伪装（v61 真机首跑的 5 个误报就是这么来的）。
	bool IsInSystemImageDirFor(PCWSTR path, PCWSTR systemRoot, PCWSTR name) noexcept
	{
		if (IsInSystemImageDir(path, systemRoot)) {
			return true;
		}
		if (!path || !systemRoot || systemRoot[0] == L'\0' || !name) {
			return false;
		}

		WCHAR prefix[MAX_PATH + 32] = {};
		for (const SystemImageExtraDir& extra : kSystemImageExtraDirs) {
			if (wcscmp(name, extra.Name) != 0) {
				continue;   // 这个额外目录只对这一个名字开放
			}
			if (swprintf_s(prefix, L"%s%s", systemRoot, extra.Dir) <= 0) {
				continue;
			}
			if (!StartsWithNoCase(path, prefix)) {
				continue;
			}

			// ★ 深度必须**精确**相等 —— 这是本表与 `kSystemImageDirs`
			//   的关键差别，也是"不把整片区域洗白"的保证：
			//     `C:\Windows\explorer.exe`                → 前缀后 0 个 `\` ⇒ 规范
			//     `C:\Windows\Temp\explorer.exe`           → 1 个 `\` ⇒ **报**（经典落盘目录！）
			//     `C:\Windows\SystemApps\Pkg\SearchHost.exe` → 1 个 `\` ⇒ 规范
			//     `C:\Windows\SystemApps\evil\SearchHost.exe`→ 2 个 `\` ⇒ **报**
			//   （文件名本身已由调用方确认等于 name，这里只需数层数。）
			ULONG slashes = 0;
			for (PCWSTR p = path + wcslen(prefix); *p; p++) {
				if (*p == L'\\') {
					slashes++;
				}
			}
			if (slashes == extra.Depth) {
				return true;
			}
		}

		return false;
	}

	// 形近比对用的归一化：小写 + 去掉所有空白 + 折叠常见视觉替换字符。
	//
	// ⚠️ 只做"替换"，**不做**任意编辑距离 —— 编辑距离会把
	//    `service.exe`（第三方服务极常见）和 `services.exe` 判成一对。
	void NormalizeImageNameForCompare(PCWSTR fileName, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch == 0) {
			return;
		}
		out[0] = L'\0';
		if (!fileName) {
			return;
		}

		size_t n = 0;
		for (PCWSTR p = fileName; *p && n + 1 < cch; p++) {
			WCHAR c = static_cast<WCHAR>(towlower(*p));
			if (c == L' ' || c == L'\t') {
				continue;
			}
			switch (c) {
			case L'0': c = L'o'; break;
			case L'1': c = L'l'; break;
			case L'2': c = L'z'; break;
			case L'3': c = L'e'; break;
			case L'5': c = L's'; break;
			case L'6': c = L'g'; break;
			case L'8': c = L'b'; break;
			case L'9': c = L'g'; break;
			case L'$': c = L's'; break;
			case L'@': c = L'a'; break;
			default: break;
			}
			out[n++] = c;
		}
		out[n] = L'\0';
	}

	// candidate 与 target 长度相同、且恰好只差**一对相邻字符交换**
	// （`scvhost` ↔ `svchost`）。完全相同返回 false —— "完全相同"由判据 ① 负责。
	bool IsAdjacentTranspositionOf(PCWSTR candidate, PCWSTR target) noexcept
	{
		const size_t length = wcslen(candidate);
		if (length != wcslen(target)) {
			return false;
		}

		constexpr size_t NoIndex = static_cast<size_t>(-1);
		size_t first = NoIndex;
		size_t second = NoIndex;

		for (size_t i = 0; i < length; i++) {
			if (candidate[i] == target[i]) {
				continue;
			}
			if (first == NoIndex) {
				first = i;
			}
			else if (second == NoIndex) {
				second = i;
			}
			else {
				return false;   // 三处以上不同 ⇒ 不是单次交换
			}
		}

		if (first == NoIndex || second == NoIndex) {
			return false;   // 完全相同
		}

		return second == first + 1
			&& candidate[first] == target[second]
			&& candidate[second] == target[first];
	}

	const char* HighRiskProcessReasonForRoot(PCWSTR imagePath, PCWSTR systemRoot) noexcept
	{
		if (!imagePath || imagePath[0] == L'\0') {
			return nullptr;
		}

		// 判不出"在不在系统目录"就不猜 —— 否则会把真正的
		// `C:\Windows\System32\svchost.exe` 报成伪装。
		if (!systemRoot || systemRoot[0] == L'\0') {
			return nullptr;
		}

		// 用户 `protect_process=` 点名要盯的程序优先 —— 不管名字像不像
		// 系统组件，用户说了要保护就报。
		if (MatchesUserProtectProcess(imagePath)) {
			return "自定义保护程序";
		}

		const PCWSTR fileName = FileNamePart(imagePath);
		if (!fileName || fileName[0] == L'\0') {
			return nullptr;
		}

		const size_t nameLength = wcslen(fileName);
		if (nameLength >= MAX_PATH) {
			return nullptr;   // 畸形超长文件名，不猜
		}

		WCHAR name[MAX_PATH] = {};
		for (size_t i = 0; i < nameLength; i++) {
			name[i] = static_cast<WCHAR>(towlower(fileName[i]));
		}
		name[nameLength] = L'\0';

		// ---- ③ 已知攻击工具 ----
		// 与"在不在系统目录"无关：工具放到 System32 里照样是工具。
		WCHAR stem[MAX_PATH] = {};
		StemLower(fileName, stem, ARRAYSIZE(stem));
		for (PCWSTR tool : kAttackToolNames) {
			if (wcscmp(stem, tool) == 0) {
				return "已知攻击工具";
			}
		}

		const bool inSystemDir = IsInSystemImageDir(imagePath, systemRoot);

		// ---- ① 系统进程名伪装 ----
		for (PCWSTR systemImage : kSystemCriticalImages) {
			if (wcscmp(name, systemImage) != 0) {
				continue;
			}
			// 名字对、位置也对 ⇒ 正常的系统进程，收工。
			//
			// ⚠️ 这里必须用**按名字**的规范目录判定，不能笼统用 inSystemDir：
			//    `explorer.exe` 住在 `%SystemRoot%\`、4 个 UWP 宿主住在
			//    `%SystemRoot%\SystemApps\` —— 都不在 System32 家族里。
			//    （v61 真机首跑正是拿笼统判定把 5 个正常进程报成了伪装。）
			return IsInSystemImageDirFor(imagePath, systemRoot, name)
				? nullptr
				: "伪装系统进程名（不在系统目录）";
		}

		// 名字不在系统组件表里、又确实在系统目录 ⇒ 那只是 System32 下
		// 众多正常程序之一（`notepad.exe`、`cmd.exe`…），后面的"形近"
		// 判据一律不再判，避免把系统目录里的正常名字制造出噪音。
		if (inSystemDir) {
			return nullptr;
		}

		// ---- ② 形近伪装 ----
		for (PCWSTR exempt : kMasqueradeExempt) {
			if (wcscmp(name, exempt) == 0) {
				return nullptr;
			}
		}

		WCHAR normalized[MAX_PATH] = {};
		NormalizeImageNameForCompare(fileName, normalized, ARRAYSIZE(normalized));

		for (PCWSTR systemImage : kSystemCriticalImages) {
			if (wcscmp(normalized, systemImage) == 0
				|| IsAdjacentTranspositionOf(normalized, systemImage)) {
				return "形近伪装系统进程名（不在系统目录）";
			}
		}

		return nullptr;
	}

	const char* HighRiskProcessReason(PCWSTR imagePath) noexcept
	{
		WCHAR systemRoot[MAX_PATH] = {};
		const UINT length = GetWindowsDirectoryW(systemRoot, ARRAYSIZE(systemRoot));
		if (length == 0 || length >= ARRAYSIZE(systemRoot)) {
			return nullptr;
		}

		return HighRiskProcessReasonForRoot(imagePath, systemRoot);
	}

	bool IsHighRiskProcess(PCWSTR imagePath) noexcept
	{
		return HighRiskProcessReason(imagePath) != nullptr;
	}

	// 表的只读访问器 —— 只为测试穷举验证而暴露（见 .h 的说明）。
	PCWSTR SystemCriticalImageAt(ULONG index) noexcept
	{
		return index < ARRAYSIZE(kSystemCriticalImages) ? kSystemCriticalImages[index] : nullptr;
	}

	ULONG SystemCriticalImageCount() noexcept
	{
		return static_cast<ULONG>(ARRAYSIZE(kSystemCriticalImages));
	}

	PCWSTR MasqueradeExemptAt(ULONG index) noexcept
	{
		return index < ARRAYSIZE(kMasqueradeExempt) ? kMasqueradeExempt[index] : nullptr;
	}

	ULONG MasqueradeExemptCount() noexcept
	{
		return static_cast<ULONG>(ARRAYSIZE(kMasqueradeExempt));
	}

	PCWSTR AttackToolNameAt(ULONG index) noexcept
	{
		return index < ARRAYSIZE(kAttackToolNames) ? kAttackToolNames[index] : nullptr;
	}

	ULONG AttackToolNameCount() noexcept
	{
		return static_cast<ULONG>(ARRAYSIZE(kAttackToolNames));
	}

	// ★ v61 修：额外规范目录表的访问器。
	// 测试用它**穷举**：每一条 `(名字, 目录, 深度)` 都必须让
	// `<systemRoot><目录><深度层>\<名字>` 判成**正常**（不报），
	// 而"再深一层"必须判成高危。
	// 这样以后往表里加条目时，忘配名字 / 目录写错 / 深度填错会立刻 FAIL。
	ULONG SystemImageExtraDirCount() noexcept
	{
		return static_cast<ULONG>(ARRAYSIZE(kSystemImageExtraDirs));
	}

	bool SystemImageExtraDirAt(ULONG index, PCWSTR* name, PCWSTR* dir, ULONG* depth) noexcept
	{
		if (index >= ARRAYSIZE(kSystemImageExtraDirs)) {
			return false;
		}
		if (name) {
			*name = kSystemImageExtraDirs[index].Name;
		}
		if (dir) {
			*dir = kSystemImageExtraDirs[index].Dir;
		}
		if (depth) {
			*depth = kSystemImageExtraDirs[index].Depth;
		}
		return true;
	}

	// 父子关系判定需要父进程名，单独一个入口 —— 因为要查父进程，
	// 比纯路径匹配贵，只在需要时才调。
	const char* ProcessPairRiskReason(PCWSTR parentPath, PCWSTR childPath) noexcept
	{
		if ((!parentPath || !parentPath[0]) || (!childPath || !childPath[0])) {
			return nullptr;
		}

		WCHAR parentStem[64] = {};
		WCHAR childStem[64] = {};
		StemLower(FileNamePart(parentPath), parentStem, _countof(parentStem));
		StemLower(FileNamePart(childPath), childStem, _countof(childStem));

		for (const ProcessPairRule& rule : kProcessPairRules) {
			if (wcscmp(parentStem, rule.parent) == 0 && wcscmp(childStem, rule.child) == 0) {
				return rule.reason;
			}
		}

		return nullptr;
	}

	// ------------------------------------------------------------------
	// 线程高危规则
	// ------------------------------------------------------------------
	//
	// 用户态能观察到的最有价值的信号：一个进程在**别的进程**里创建线程。
	// 这就是注入。正常程序极少这么做（除了调试器和少数合法工具）。
	//
	// 本进程内的线程创建完全正常，不判高危（但可以由 hook 开关决定记不记）。

	const char* ThreadRiskReason(ULONG targetPid, ULONG selfPid, ULONG threadOp) noexcept
	{
		const R3ShieldCore::ThreadOp op = static_cast<R3ShieldCore::ThreadOp>(threadOp);

		// v18：NtCreateThread（老 API）走**同一条**远程线程判据。
		//
		// 好消息：NtCreateThread 同样显式收 ProcessHandle，所以
		// "目标进程 ≠ 当前进程"这条判据可以原样复用 —— 两者的差别
		// 只在参数表（NtCreateThread 多一个 ClientId），不影响本判据。
		// 这里显式列出 CreateLegacy，而不是写 `!= Create`，就是为了
		// 避免它掉进 default（§10-33：新 Op 掉进 default = 静默永远非高危）。
		if (op != R3ShieldCore::ThreadOp::Create &&
			op != R3ShieldCore::ThreadOp::CreateLegacy) {
			return nullptr;
		}

		if (targetPid != 0 && selfPid != 0 && targetPid != selfPid) {
			return (op == R3ShieldCore::ThreadOp::CreateLegacy)
				? "远程线程注入（老 API）"
				: "远程线程注入";
		}

		return nullptr;
	}

	bool IsHighRiskThread(ULONG targetPid, ULONG selfPid, ULONG threadOp) noexcept
	{
		return ThreadRiskReason(targetPid, selfPid, threadOp) != nullptr;
	}

	// ------------------------------------------------------------------
	// 终止进程收敛（v36）
	// ------------------------------------------------------------------
	//
	// 一句话语义：**允许退出自己、自己的后代、同程序的其它实例；
	//              不许杀别的进程。**
	//
	// 为什么"自己"必须放行（不是可选优化，是存活前提）：
	//   ExitProcess → RtlExitUserProcess → NtTerminateProcess(NtCurrentProcess()).
	//   实测（tools/terminate_block_probe.cpp）：
	//     · detour 里对 `NtCurrentProcess()` 也返回 STATUS_ACCESS_DENIED 时，
	//       detour **确实被触发**（直接调导出返回 0xC0000022）；
	//     · 但进程**照样退出**，只是退出码被破坏成 0xC0000005（异常码），可复现。
	//   ⇒ 无差别拦 = 拦不住退出、还把每个进程的干净退出弄成崩溃退出。
	//
	// 为什么"后代"放行：shell / 构建工具 / 安装器杀整棵进程树是常规行为，
	//   拦了就是误伤（且它们持有子进程句柄，本来就该能管自己的树）。
	//
	// 为什么"同镜像"放行：单实例程序杀"上一个实例"是常见模式，但上一个实例
	//   与当前进程没有父子关系（是兄弟），只按父子判会误伤。
	//
	// ⚠️ 本层是**唯一会查进程**的规则 —— 刻意的：父链上溯与镜像比对是这套
	//    新逻辑里最容易错的地方，放这里才能被 tools/terminate_contain_ut.cpp
	//    用**真实进程树**直接驱动验证（铁律 9：判"漏没漏"看探针不看 grep）。

	namespace
	{
		// 与 guard 层同名结构体保持一致的布局（只取用得到的字段）。
		struct RgProcessBasicInformation
		{
			NTSTATUS ExitStatus;
			PVOID PebBaseAddress;
			ULONG_PTR AffinityMask;
			LONG BasePriority;              // KPRIORITY
			ULONG_PTR UniqueProcessId;
			ULONG_PTR InheritedFromUniqueProcessId;
		};

		typedef NTSTATUS(NTAPI* RgNtQueryInformationProcessPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);

		constexpr ULONG kRgProcessBasicInformation = 0;

		// 惰性解析一次（ntdll 必然已加载）。用 magic static —— 只初始化一次，
		// 之后是纯指针读取，hook 里调用不会反复进 loader lock。
		RgNtQueryInformationProcessPtr NtQueryInfoProcess() noexcept
		{
			static RgNtQueryInformationProcessPtr fn = []() -> RgNtQueryInformationProcessPtr {
				HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
				if (!ntdll) {
					return nullptr;
				}
				return reinterpret_cast<RgNtQueryInformationProcessPtr>(
					GetProcAddress(ntdll, "NtQueryInformationProcess"));
			}();
			return fn;
		}
	}

	// 由 pid 拿父进程 pid（ProcessBasicInformation.InheritedFromUniqueProcessId）。
	// 失败返回 0 —— 判不出父子关系时**不当作自己人**（偏保守：宁可少放行一次）。
	ULONG ParentPidOf(ULONG pid) noexcept
	{
		if (pid == 0) {
			return 0;
		}

		RgNtQueryInformationProcessPtr query = NtQueryInfoProcess();
		if (!query) {
			return 0;
		}

		HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
		if (!process) {
			return 0;
		}

		RgProcessBasicInformation info = {};
		ULONG length = 0;
		const NTSTATUS status = query(process, kRgProcessBasicInformation,
			&info, sizeof(info), &length);
		CloseHandle(process);

		if (status < 0) {
			return 0;
		}

		return static_cast<ULONG>(info.InheritedFromUniqueProcessId);
	}

	// targetPid 是不是 selfPid 的后代（整棵子树，含孙进程）—— 沿父链上溯。
	//
	// 为什么上溯而不是下溯：下溯要枚举全系统进程建树（CreateToolhelp32Snapshot
	// 在 hook 里既慢又会重入）；上溯只要 1~N 次 OpenProcess + 一次查询，
	// 典型深度 1~3 层就命中，且不依赖任何全局快照。
	//
	// 深度封顶防止畸形父链（环 / 超长链）把 hook 卡住。
	bool IsOwnDescendant(ULONG targetPid, ULONG selfPid) noexcept
	{
		if (targetPid == 0 || selfPid == 0 || targetPid == selfPid) {
			return false;
		}

		constexpr int kMaxAncestorDepth = 16;
		ULONG current = targetPid;
		for (int depth = 0; depth < kMaxAncestorDepth; depth++) {
			const ULONG parent = ParentPidOf(current);
			if (parent == 0 || parent == current) {
				return false;   // 到顶 / 自环 —— 不是自己的后代
			}
			if (parent == selfPid) {
				return true;
			}
			current = parent;
		}
		return false;
	}

	// 目标进程的镜像路径是不是与**当前进程**相同（同程序多实例）。
	bool SameImageAsSelf(ULONG targetPid) noexcept
	{
		if (targetPid == 0) {
			return false;
		}

		WCHAR selfPath[R3ShieldCore::MaxImagePathChars] = {};
		if (GetModuleFileNameW(nullptr, selfPath, _countof(selfPath)) == 0) {
			return false;
		}

		HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
		if (!target) {
			return false;
		}

		WCHAR targetPath[R3ShieldCore::MaxImagePathChars] = {};
		DWORD size = _countof(targetPath);
		const BOOL ok = QueryFullProcessImageNameW(target, 0, targetPath, &size);
		CloseHandle(target);

		if (!ok || targetPath[0] == L'\0') {
			return false;
		}

		return _wcsicmp(selfPath, targetPath) == 0;
	}

	const char* TerminateRiskReason(ULONG targetPid, ULONG selfPid) noexcept
	{
		// 取不到 pid：多半是拿不到句柄信息（含"结束自己"的伪句柄场景）——
		// 判不出来就不算高危（与 ThreadRiskReason 的宽松处理一致）。
		if (targetPid == 0 || selfPid == 0) {
			return nullptr;
		}

		// 退出自己 —— 无条件放行（见上面 ExitProcess 的实证）。
		if (targetPid == selfPid) {
			return nullptr;
		}

		// 自己的后代（整棵子树）。
		if (IsOwnDescendant(targetPid, selfPid)) {
			return nullptr;
		}

		// 同程序多实例。
		if (SameImageAsSelf(targetPid)) {
			return nullptr;
		}

		return "终止其他进程";
	}

	bool IsHighRiskTerminate(ULONG targetPid, ULONG selfPid) noexcept
	{
		return TerminateRiskReason(targetPid, selfPid) != nullptr;
	}

	// ------------------------------------------------------------------
	// 跨进程内存操作 / 代码注入链（v14）
	// ------------------------------------------------------------------
	//
	// ⚠️ 存活前提（最重要的一条）：**对当前进程自己的内存操作一律放行**。
	//
	//    NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory
	//    是每个进程的**日常刚需** ——
	//      · CRT 启动、堆管理、任何 new/malloc 都在 Allocate + Protect；
	//      · .NET / Java / V8 的 JIT 每编译一个方法就
	//        Allocate(RW) → Write(机器码) → Protect(RX)；
	//      · 加壳程序、反调试器自己也在 Protect 自己的页。
	//    如果对本进程也判高危，系统会在几秒内瘫掉 —— 这不是"误报多"，
	//    是**直接不可用**。所以 targetPid == selfPid（或取不到 pid）时
	//    一律 nullptr。
	//
	//    跨进程才是攻击特征：一个进程去改**别人**的内存页，只有少数
	//    正当场景（调试器、注入器、部分 AppInit/EDR），而这正是要盯的。
	//
	// 判据按 Op 分三档（严格程度递增）：
	//   WriteMemory    —— 跨进程写内存 = 注入链第二步。**跨进程即高危**
	//                     （写什么内容看不到，但"往别的进程写内存"本身
	//                      就是铁证；调试器读内存不写，不受影响）。
	//   ProtectMemory  —— 跨进程改页权限。只有改成**可执行**才是注入
	//                     （PAGE_EXECUTE / EXECUTE_READ / EXECUTE_READWRITE /
	//                      EXECUTE_WRITECOPY）。改成只读/可读写很常见
	//                     （调试器、部分 API hook 库）→ 只记录。
	//   AllocateMemory —— 跨进程申请内存。只有 **COMMIT 且可执行**才是注入。
	//                     MEM_RESERVE 只是划地址空间（不占物理页，无害），
	//                     RW 不可执行的申请也常见（共享数据）→ 只记录。
	//
	// ⚠️ 注意这三个 Op 与 Op=1 一样是"各 ObjectType 独立从 1 起"，
	//    这里靠 static_cast<ProcessOp> 取值，不能拿数字硬写。

	// 页权限里是否含"可执行"。
	bool IsExecutableProtect(ULONG protect) noexcept
	{
		const ULONG base = protect & 0xFFu; // 低字节是页保护类型
		switch (base) {
		case PAGE_EXECUTE:
		case PAGE_EXECUTE_READ:
		case PAGE_EXECUTE_READWRITE:
		case PAGE_EXECUTE_WRITECOPY:
			return true;
		default:
			return false;
		}
	}

	const char* MemoryOpRiskReason(ULONG targetPid, ULONG selfPid, ULONG processOp,
		ULONG protect, ULONG allocationType) noexcept
	{
		// ---- 存活前提：本进程一律放行 ----
		if (targetPid == 0 || selfPid == 0 || targetPid == selfPid) {
			return nullptr;
		}

		switch (static_cast<R3ShieldCore::ProcessOp>(processOp)) {
		case R3ShieldCore::ProcessOp::WriteMemory:
			// 跨进程写内存 —— 注入链第二步，最直接的铁证。
			return "跨进程写内存（代码注入 / 打补丁）";

		case R3ShieldCore::ProcessOp::ProtectMemory:
			// 跨进程改页权限：只有改成可执行才算。
			if (IsExecutableProtect(protect)) {
				return "把别的进程的内存页改成可执行（注入链：为 shellcode 开 RWX）";
			}
			return nullptr;

		case R3ShieldCore::ProcessOp::AllocateMemory:
			// 跨进程申请内存：只有"提交且可执行"才算。
			if ((allocationType & MEM_COMMIT) != 0 && IsExecutableProtect(protect)) {
				return "在别的进程里申请可执行内存（注入链起点）";
			}
			return nullptr;

		default:
			return nullptr;
		}
	}

	bool IsHighRiskMemoryOp(ULONG targetPid, ULONG selfPid, ULONG processOp,
		ULONG protect, ULONG allocationType) noexcept
	{
		return MemoryOpRiskReason(targetPid, selfPid, processOp, protect, allocationType) != nullptr;
	}

	// ------------------------------------------------------------------
	// 驱动加载高危规则
	// ------------------------------------------------------------------
	//
	// 用户态能观察到的驱动加载有两条路：
	//   ① NtLoadDriver（服务方式）—— 但调用方几乎总是 services.exe，
	//      而它在白名单里，所以这条路基本抓不到（见 DriverOp 的注释）；
	//   ② advapi32 的服务 API（CreateService / ChangeServiceConfig / StartService）
	//      —— 调用方就是那个不受信任的应用，能抓到。这是 ABI v9 补的。
	//
	// 判据分两档：
	//   · 内核驱动服务：和 NtLoadDriver 同一套 —— 不是从系统驱动目录
	//     （System32\drivers / SysWOW64\drivers）来的就高危。
	//     为什么这么严：正常驱动都装在自己目录然后由 SCM 加载，
	//     一个用户态程序自备 .sys 装成服务 —— 这就是大多数"驱动级"
	//     恶意软件、外挂、反杀软工具的加载方式。
	//   · Win32 服务：**不按"是否服务"一刀切** —— 装服务是安装器天天干的
	//     合法运维动作。只在二进制落在**用户可写目录**时算高危，
	//     那才是持久化的特征（而且那些目录普通用户能改）。

	// 服务二进制路径是否落在"用户可写目录"里。
	// 正常服务装在 Program Files / Windows 下。
	bool IsUserWritableServicePath(PCWSTR path) noexcept
	{
		static const PCWSTR kFragments[] = {
			L"\\Temp\\",
			L"\\Users\\",
			L"\\ProgramData\\",
			L"\\$Recycle.Bin\\",
			L"\\Windows\\Tasks\\",
			L"\\Windows\\Temp\\",
		};

		for (PCWSTR fragment : kFragments) {
			if (ContainsNoCase(path, fragment)) {
				return true;
			}
		}

		return false;
	}

	const char* DriverRiskReason(PCWSTR driverPath, ULONG driverOp, bool kernelDriverService) noexcept
	{
		if (!driverPath || driverPath[0] == L'\0') {
			return nullptr;
		}

		if (MatchesUserProtectDriver(driverPath)) {
			return "自定义保护驱动";
		}

		const R3ShieldCore::DriverOp op = static_cast<R3ShieldCore::DriverOp>(driverOp);

		// ---- 服务类操作（advapi32，ABI v9）----
		if (op == R3ShieldCore::DriverOp::CreateService ||
			op == R3ShieldCore::DriverOp::ChangeServiceConfig ||
			op == R3ShieldCore::DriverOp::StartService) {

			const bool inSystemDrivers =
				ContainsNoCase(driverPath, L"\\Windows\\System32\\drivers\\") ||
				ContainsNoCase(driverPath, L"\\Windows\\SysWOW64\\drivers\\");

			if (kernelDriverService) {
				if (inSystemDrivers) {
					return nullptr;
				}

				switch (op) {
				case R3ShieldCore::DriverOp::CreateService: return "非系统目录安装驱动服务";
				case R3ShieldCore::DriverOp::ChangeServiceConfig: return "把服务改成非系统驱动";
				default: return "启动非系统驱动服务";
				}
			}

			if (IsUserWritableServicePath(driverPath)) {
				return "从用户可写目录安装服务";
			}

			return nullptr;
		}

	// 从系统驱动目录加载 —— 放行（这是正常驱动的常态）。
	// 注意路径已经归一化成 DOS 形式（C:\Windows\System32\drivers\x.sys），
	// 且**实际大小写不固定**（`GetWindowsDirectoryW` 给的是 `C:\WINDOWS`）——
	// 所以必须用 ContainsNoCase，不能用 wcsstr。
	if (ContainsNoCase(driverPath, L"\\Windows\\System32\\drivers\\") ||
		ContainsNoCase(driverPath, L"\\Windows\\SysWOW64\\drivers\\")) {
			return nullptr;
		}

		// 卸载系统目录外的驱动本身也是反取证动作，同样高危。
		if (op == R3ShieldCore::DriverOp::Load) {
			return "非系统驱动加载";
		}

		return "非系统驱动卸载";
	}

	bool IsHighRiskDriverLoad(PCWSTR driverPath, ULONG driverOp, bool kernelDriverService) noexcept
	{
		return DriverRiskReason(driverPath, driverOp, kernelDriverService) != nullptr;
	}

	// ------------------------------------------------------------------
	// 网络高危规则
	// ------------------------------------------------------------------
	//
	// ⚠️ 先明确能力边界，免得误以为这是防火墙：这里拦的是 ws2_32 用户态出口。
	//    直连 \Device\Afd、静态链接 socket、WinHTTP 内部路径、起子进程转发
	//    —— 都能绕过。所以网络层的定位是"看得见大多数正常程序在连谁"，
	//    不是"挡得住铁了心要绕的东西"。真正的执法在内核（WFP）。
	//
	// 用户选定的两条判据：**敏感端口** + **内网地址**。
	//   敏感端口 = 横向移动 / 数据库 / 远控常用口（445、139、3389、1433…）
	//   内网地址 = 10./172.16-31./192.168./169.254. + 回环 —— 内网横向的特征
	//
	// 额外的第三条：**listen 无差别高危**。正常客户端程序不该开监听；
	// 一个"只是上网"的程序突然 listen(4444) 是后门的教科书特征。

	// 敏感服务端口表。每条：端口 + 服务名 + 是不是"横向移动"类。
	//
	// 选点原则：出现在这里就意味着"一个普通用户程序连过去"是异常行为。
	// 所以浏览器连 443 不会被拦，但一个文档程序连 3389 就得问一句。
	struct SensitivePort
	{
		ULONG port;
		const char* service;
	};

	constexpr SensitivePort kSensitivePorts[] = {
		// ---- 横向移动 / 远程管理 ----
		{ 3389, "远程桌面 RDP" },
		{ 5900, "VNC 远程桌面" },
		{ 5901, "VNC 远程桌面" },
		{ 5985, "WinRM 远程管理" },
		{ 5986, "WinRM 远程管理(加密)" },
		{ 22, "SSH 远程登录" },
		{ 23, "Telnet 明文远程登录" },
		{ 512, "rsh 远程执行" },
		{ 513, "rlogin 远程登录" },
		{ 514, "rsh 远程 shell" },

		// ---- Windows 文件共享 / 域 ----
		{ 445, "SMB 文件共享" },
		{ 139, "NetBIOS 会话服务" },
		{ 135, "RPC 端点映射" },
		{ 137, "NetBIOS 名称服务" },
		{ 138, "NetBIOS 数据报" },
		{ 88, "Kerberos 认证" },
		{ 389, "LDAP 目录服务" },
		{ 636, "LDAPS 目录服务" },
		{ 3268, "全局编录 LDAP" },

		// ---- 数据库（数据外泄的靶子） ----
		{ 1433, "MSSQL 数据库" },
		{ 1434, "MSSQL 浏览器服务" },
		{ 3306, "MySQL 数据库" },
		{ 5432, "PostgreSQL 数据库" },
		{ 1521, "Oracle 数据库" },
		{ 27017, "MongoDB 数据库" },
		{ 6379, "Redis 数据库" },
		{ 9042, "Cassandra 数据库" },
		{ 9200, "Elasticsearch" },

		// ---- 明文 / 无认证的传统协议 ----
		{ 21, "FTP 明文文件传输" },
		{ 69, "TFTP 明文传输" },
		{ 110, "POP3 明文邮件" },
		{ 143, "IMAP 明文邮件" },
		{ 25, "SMTP 明文邮件" },
		{ 161, "SNMP 设备管理" },
		{ 162, "SNMP Trap" },
		{ 2049, "NFS 网络文件系统" },
		{ 111, "RPCbind 端口映射" },

		// ---- 内网服务 / 常见后门 ----
		{ 2375, "Docker 未加密 API" },
		{ 2376, "Docker API" },
		{ 8500, "Consul 服务" },
		{ 4444, "Metasploit 默认监听口" },
		{ 5555, "常见远控监听口" },
		{ 6666, "常见后门端口" },
		{ 31337, "经典后门端口" },

		// ---- 邮件提交 / 目录 ----
		{ 587, "SMTP 邮件提交" },
		{ 993, "IMAPS 加密邮件" },
		{ 995, "POP3S 加密邮件" },
	};

	const SensitivePort* FindSensitivePort(ULONG port) noexcept
	{
		for (const SensitivePort& entry : kSensitivePorts) {
			if (entry.port == port) {
				return &entry;
			}
		}
		return nullptr;
	}

	const char* SensitivePortServiceName(ULONG port) noexcept
	{
		const SensitivePort* entry = FindSensitivePort(port);
		return entry ? entry->service : nullptr;
	}

	bool IsSensitivePort(ULONG port) noexcept
	{
		return FindSensitivePort(port) != nullptr;
	}

	// 回环地址判定。IPv4 是 127.0.0.0/8，IPv6 是 ::1。
	//
	// 单列一个函数：回环判定在 NetworkRiskReason 里**必须先于所有其它规则**，
	// 理由见那里的注释。
	bool IsLoopbackAddress(PCWSTR address) noexcept
	{
		if (!address || !address[0]) {
			return false;
		}

		ULONG o[4] = {};
		if (ParseIpv4(address, o) == 4) {
			return o[0] == 127;
		}

		return _wcsicmp(address, L"::1") == 0;
	}

	// 内网 / 保留网段判定。address 是纯地址文本（不含端口）。
	//
	// 覆盖：
	//   IPv4：0.0.0.0/8、10.0.0.0/8、100.64.0.0/10（运营商级 NAT）、
	//         127.0.0.0/8（回环）、169.254.0.0/16（链路本地）、
	//         172.16.0.0/12、192.0.0.0/24、192.168.0.0/16、
	//         198.18.0.0/15（基准测试）、224.0.0.0/4（组播）、240.0.0.0/4（保留）
	//   IPv6：::1（回环）、fc00::/7（ULA）、fe80::/10（链路本地）
	bool IsPrivateOrReservedAddress(PCWSTR address) noexcept
	{
		if (!address || !address[0]) {
			return false;
		}

		ULONG o[4] = {};

		if (ParseIpv4(address, o) == 4) {
			// 0.0.0.0/8 —— "本机"通配
			if (o[0] == 0) {
				return true;
			}
			// 10.0.0.0/8
			if (o[0] == 10) {
				return true;
			}
			// 100.64.0.0/10 —— 运营商级 NAT（RFC 6598）
			if (o[0] == 100 && o[1] >= 64 && o[1] <= 127) {
				return true;
			}
			// 127.0.0.0/8 —— 回环
			if (o[0] == 127) {
				return true;
			}
			// 169.254.0.0/16 —— 链路本地（APIPA）
			if (o[0] == 169 && o[1] == 254) {
				return true;
			}
			// 172.16.0.0/12
			if (o[0] == 172 && o[1] >= 16 && o[1] <= 31) {
				return true;
			}
			// 192.0.0.0/24 —— IETF 协议分配
			if (o[0] == 192 && o[1] == 0 && o[2] == 0) {
				return true;
			}
			// 192.168.0.0/16
			if (o[0] == 192 && o[1] == 168) {
				return true;
			}
			// 198.18.0.0/15 —— 基准测试
			if (o[0] == 198 && (o[1] == 18 || o[1] == 19)) {
				return true;
			}
			// 224.0.0.0/4 —— 组播
			if (o[0] >= 224 && o[0] <= 239) {
				return true;
			}
			// 240.0.0.0/4 —— 保留（含 255.255.255.255 广播）
			if (o[0] >= 240) {
				return true;
			}
			return false;
		}

		// ---- IPv6 ----
		// 回环 ::1
		if (_wcsicmp(address, L"::1") == 0) {
			return true;
		}
		// 未指定 ::
		if (_wcsicmp(address, L"::") == 0) {
			return true;
		}
		// 链路本地 fe80::/10 —— 第二段十六进制在 80 到 bf 之间。
		// 文本形态一定是 "fe80:" / "fe90:" / "fea0:" / "febf:" 开头，
		// 所以看第 3 位落在 8/9/a/b 即可。
		if ((address[0] == L'f' || address[0] == L'F') &&
			(address[1] == L'e' || address[1] == L'E')) {
			const WCHAR third = address[2];
			if (third == L'8' || third == L'9' ||
				third == L'a' || third == L'A' ||
				third == L'b' || third == L'B') {
				return true;
			}
		}
		// 唯一本地地址 fc00::/7 —— fc/fd
		if ((address[0] == L'f' || address[0] == L'F') &&
			(address[1] == L'c' || address[1] == L'C' ||
			 address[1] == L'd' || address[1] == L'D')) {
			return true;
		}

		return false;
	}

	// 基础设施端口 —— 全网程序都要打的"公共设施"，一律不判高危（只记录）。
	//
	// ⚠️ 这是实机踩出来的坑：DNS 是**最高频**的网络行为。如果按"内网地址"
	//    或"敏感端口"去判 DNS，开一次浏览器就是弹窗机关枪（Edge 每次解析
	//    域名都往路由器 192.168.2.1:53 发 UDP）。
	//
	// 判据来源：用户要"全都加（含 DNS）"—— 这里的"含 DNS"是指**要看得见**
	//   程序在解析什么（情报价值），不是"要拦 DNS"。而且 DNS 服务器通常就是
	//   网关本身（192.168.x.1），必然命中"内网地址"规则 —— 所以必须在
	//   内网/敏感端口判定**之前**先放行。
	//
	// 注意：明文的 DNS(53/UDP) 确实可被投毒/劫持，但把它判成"高危待拦"
	//   会 100% 阻断所有上网 —— 那是把杀软做成了断网器。这里只做可见性。
	//
	// 覆盖：
	//   53   —— DNS（UDP/TCP 都算）
	//   5353 —— mDNS（组播 DNS，局域网设备发现）
	//   853  —— DoT（DNS over TLS）
	//   443  —— 因为 DoH 也走 443，但 443 是海量正常流量，绝不能整段放行，
	//           所以**只有 53/5353/853 单列**，DoH 靠"不是内网+不是敏感口"
	//           自然放行，不影响。
	//   123  —— NTP 时间同步（也是全网高频）
	bool IsInfrastructurePort(ULONG port) noexcept
	{
		switch (port) {
		case 53:    // DNS
		case 5353:  // mDNS
		case 853:   // DNS over TLS
		case 123:   // NTP
			return true;
		default:
			return false;
		}
	}

	// 已知的明文 / 无认证协议端口 —— 独立于"敏感端口"，
	// 因为像 FTP(21) 这类既敏感又明文的，原因文案要单独说。
	bool IsPlaintextProtocolPort(ULONG port) noexcept
	{
		switch (port) {
		case 21:   // FTP
		case 23:   // Telnet
		case 25:   // SMTP
		case 69:   // TFTP
		case 80:   // HTTP
		case 110:  // POP3
		case 143:  // IMAP
		case 161:  // SNMP
		case 512:  // rsh
		case 513:  // rlogin
		case 514:  // rsh
			return true;
		default:
			return false;
		}
	}

	const char* NetworkRiskReason(PCWSTR remoteAddress, ULONG targetPort, ULONG protocol,
		ULONG netOp) noexcept
	{
		(void)protocol;

		const R3ShieldCore::NetOp op = static_cast<R3ShieldCore::NetOp>(netOp);

		// ---- 域名解析：本身不算高危（所有上网程序都要解析域名）----
		// 它的价值是"情报"：能看见程序在解析哪个域名（C2 域名在这里现形）。
		// 所以只记录，不判高危 —— 否则开浏览器就弹窗机关枪。
		if (op == R3ShieldCore::NetOp::DnsQuery) {
			return nullptr;
		}

		// ---- 回环：一律放行 ----
		//
		// ⚠️ 顺序坑（和文件侧 hosts 那个一模一样）：回环地址**同时命中**
		//    "内网地址"和"敏感端口"两类规则 —— 127.0.0.1:445 会先撞上
		//    敏感端口判定，被判"内网横向移动"。但连本机 445 是 SMB 本机共享、
		//    连本机 3389 是本机远程桌面，全是正常行为。
		//
		//    正解：**回环判定必须在所有规则之前**。本机进程互访不是安全问题。
		//
		if (IsLoopbackAddress(remoteAddress)) {
			return nullptr;
		}

		// ---- 基础设施端口（DNS/NTP/mDNS）：一律放行 ----
		//
		// ⚠️ 必须放在"内网地址"和"敏感端口"判定**之前**。
		//    DNS 服务器一般就是网关（192.168.x.1:53），会先命中"内网地址"
		//    规则；按内网判就会把每次域名解析都标成高危 —— 开浏览器即弹窗
		//    机关枪（实机已验证）。
		//
		//    用户要"含 DNS"= 要看得见解析了什么，不是要拦 DNS。
		//    所以这里只放行高危判定，事件照记（DnsQuery 已经在更前面
		//    返回 nullptr，这里兜的是"程序自己走 UDP 53 直发"的场景）。
		if (targetPort != 0 && IsInfrastructurePort(targetPort)) {
			return nullptr;
		}

		// ---- 用户自定义 protect_net= ----
		if (MatchesUserProtectNetwork(remoteAddress, targetPort)) {
			return "自定义保护网络目标";
		}

		// ---- 监听：无差别高危 ----
		// 客户端程序不该开监听。一个本来只会上网的程序开了 listen，
		// 要么是被当成后门了，要么是在搭 P2P 服务 —— 都值得问一句。
		if (op == R3ShieldCore::NetOp::Listen) {
			return "程序开启了网络监听";
		}

		// ---- bind：绑到非回环地址才可疑 ----
		// 绑 127.0.0.1 是本地服务（正常，回环已前置放行）。
		// 绑 0.0.0.0 / :: 是"对所有网卡开放"，绑具体公网/内网地址是"对特定
		// 网卡开放" —— 两者都是对外暴露，才是"监听前准备"。
		if (op == R3ShieldCore::NetOp::Bind) {
			if (remoteAddress && (wcscmp(remoteAddress, L"0.0.0.0") == 0 ||
					wcscmp(remoteAddress, L"::") == 0)) {
				return "程序绑定了全部网络接口";
			}
			return "程序绑定了对外网络地址";
		}

		// ---- 下面都是出站（connect / sendto / accept）----
		// accept 是"收到连接"，对普通客户端程序也少见（它没 listen 过就不会 accept）。
		if (op == R3ShieldCore::NetOp::Accept) {
			return "程序接受了外部网络连接";
		}

		// ---- 敏感端口 ----
		if (targetPort != 0 && IsSensitivePort(targetPort)) {
			const char* service = SensitivePortServiceName(targetPort);
			// 内网 + 敏感端口 = 横向移动的最典型组合，用专门文案。
			if (IsPrivateOrReservedAddress(remoteAddress)) {
				return (targetPort == 445 || targetPort == 139 || targetPort == 3389)
					? "尝试连接内网远程服务（横向移动特征）"
					: "尝试连接内网敏感服务";
			}
			(void)service;
			return "尝试连接敏感服务端口";
		}

		// ---- 内网地址 ----
		// 回环已在上面前置放行了，走到这里的都是真内网。
		if (IsPrivateOrReservedAddress(remoteAddress)) {
			return "尝试连接内网地址";
		}

		// ---- 明文协议端口（含普通 HTTP 80）----
		if (targetPort != 0 && IsPlaintextProtocolPort(targetPort)) {
			return "尝试使用明文网络协议";
		}

		// ---- v18：\Device\Afd 直发（DeviceIo）----
		//
		// 走到这里意味着：不是回环、不是基础设施端口、不是自定义保护目标、
		// 不是 listen/bind/accept、不是敏感端口、不是内网地址、不是明文协议端口。
		//
		// 此时如果是**绕开 ws2_32 直接打 \Device\Afd 送数据**，就是本层
		// 唯一还能识别出的异常特征 —— 正常程序不会自己
		//    CreateFile("\\.\Afd") + DeviceIoControl(IOCTL_AFD_SEND...)
		// 去发数据。所以这里兜底报高危。
		//
		// ⚠️ 净效果说明（避免误读）：
		//    · 回环 / :53 等基础设施端口 → 已在前面放行，走不到这里；
		//    · 内网地址 / 敏感端口 / 明文端口（80 等）走 AFD → **仍按
		//      原有规则判**（"尝试连接内网地址" 等），文案会不带 AFD 字样 ——
		//      这是刻意的：那些目标本来就已经高危，不需要区分是不是走 AFD；
		//    · 本分支实际兜住的是「公网 + 非敏感 + 非明文端口」的裸外发
		//      （例如 203.0.113.9:4444 这种 C2 常见形态）。
		//
		// ⚠️ 前提：**必须解析出远端地址**。AFD 直发时拿不到地址（缓冲形态
		//    没解析出来）就不再判 —— 否则任何一次没解析成功的 IOCTL 都变
		//    高危，那就是灾难级误报。
		if (op == R3ShieldCore::NetOp::DeviceIo) {
			if (remoteAddress && remoteAddress[0] != L'\0') {
				return "绕过 ws2_32 直接经 \\Device\\Afd 外发数据";
			}
			return nullptr;
		}

		return nullptr;
	}

	bool IsHighRiskNetwork(PCWSTR remoteAddress, ULONG targetPort, ULONG protocol,
		ULONG netOp) noexcept
	{
		return NetworkRiskReason(remoteAddress, targetPort, protocol, netOp) != nullptr;
	}

	// ------------------------------------------------------------------
	// 用户自定义保护路径
	// ------------------------------------------------------------------

	bool MatchesUserProtectRegistry(PCWSTR keyPath) noexcept
	{
		return MatchesProtectList(keyPath, ProtectRegAt, ProtectRegCount());
	}

	bool MatchesUserProtectFile(PCWSTR path) noexcept
	{
		return MatchesProtectList(path, ProtectFileAt, ProtectFileCount());
	}

	bool MatchesUserProtectProcess(PCWSTR imagePath) noexcept
	{
		return MatchesProtectList(imagePath, ProtectProcessAt, ProtectProcessCount());
	}

	bool MatchesUserProtectDriver(PCWSTR driverPath) noexcept
	{
		return MatchesProtectList(driverPath, ProtectDriverAt, ProtectDriverCount());
	}

	// 网络目标的 protect_net= 匹配。
	//
	// 比其它 protect_ 多一层：网络目标有两种写法 —— 光地址（"1.2.3.4"）
	// 或 地址+端口（"1.2.3.4:445"）。所以先直接前缀匹配整串，
	// 再单独比"地址不比端口"的情况（条目里没带端口则按整地址匹配）。
	bool MatchesUserProtectNetwork(PCWSTR address, ULONG port) noexcept
	{
		if (!address || !address[0]) {
			return false;
		}

		const ULONG count = ProtectNetCount();

		// 先拼一份 "address:port" 用于带端口条目的精确前缀匹配。
		WCHAR withPort[R3ShieldCore::MaxProtectPathChars] = {};
		if (port != 0) {
			swprintf_s(withPort, L"%s:%u", address, port);
		}

		for (ULONG i = 0; i < count; i++) {
			PCWSTR entry = ProtectNetAt(i);
			if (!entry || !entry[0]) {
				continue;
			}

			// 条目带端口（含 ':'）→ 比 "address:port"
			if (wcschr(entry, L':') != nullptr) {
				if (withPort[0] && StartsWithNoCase(withPort, entry)) {
					return true;
				}
				// 也允许条目直接是 "1.2.3.4:445"，而调用方传的是完整串
				if (StartsWithNoCase(address, entry)) {
					return true;
				}
			}
			else {
				// 条目不带端口 → 只比地址
				if (StartsWithNoCase(address, entry)) {
					return true;
				}
			}
		}

		return false;
	}

	// ------------------------------------------------------------------
	// 摄像头 / 麦克风
	// ------------------------------------------------------------------
	//
	// 判据只有一条：**是不是"打开"**。
	//
	// 这里刻意不做白名单（"zoom.exe 开摄像头就放行"）—— 摄像头是隐私设备，
	// 正常软件开它的时候用户应该在场，所以宁可多问一次。用户如果信任某个
	// 程序，在弹窗上点「始终允许」即可（决策缓存按 Op 隔离，见 Ask 机制）。
	//
	bool IsHighRiskCamera(ULONG cameraOp) noexcept
	{
		switch (static_cast<R3ShieldCore::CameraOp>(cameraOp)) {
		case R3ShieldCore::CameraOp::OpenDevice:
		case R3ShieldCore::CameraOp::CreateDeviceSource:
		case R3ShieldCore::CameraOp::CreateSourceReader:
			return true;
		default:
			// EnumDevice：枚举设备列表。相机应用/会议软件启动时都会做，
			// 只记录，不打断。
			return false;
		}
	}

	const char* CameraRiskReason(ULONG cameraOp) noexcept
	{
		switch (static_cast<R3ShieldCore::CameraOp>(cameraOp)) {
		case R3ShieldCore::CameraOp::OpenDevice: return "打开摄像头（VFW）";
		case R3ShieldCore::CameraOp::CreateDeviceSource: return "打开摄像头/麦克风（Media Foundation 设备源）";
		case R3ShieldCore::CameraOp::CreateSourceReader: return "读取摄像头/麦克风数据流";
		default: return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 输入钩子
	// ------------------------------------------------------------------
	//
	// 分层判据（见 r3shieldcore_shared.h 里 HookOp 的说明）：
	//
	//   低级钩子（LL）      → 全系统监听，无需注入          → 高危
	//   全局钩子（tid==0）  → 需要注入所有 GUI 进程          → 高危
	//   线程内钩子（tid!=0）→ 只作用于自己进程的某个线程     → 只记录
	//   输入日志录制/回放   → 直接录制或伪造全系统输入       → 高危
	//
	// 判断"是不是全局"只看 dwThreadId 是否为 0 —— 这是 Win32 的定义：
	// dwThreadId==0 且 lpfn 在本模块外时，系统会把 DLL 注入到所有
	// 同类 GUI 线程里。哪怕 lpfn 在本进程（不注入），只要 tid==0
	// 也是"监听所有线程的消息"，同样值得问一句。
	//
	bool IsHighRiskInputHook(ULONG idHook, ULONG threadId, ULONG hookOp, bool rawInputSink) noexcept
	{
		const bool global = (threadId == 0);

		switch (static_cast<R3ShieldCore::HookOp>(hookOp)) {
		case R3ShieldCore::HookOp::SetMouseHook:
			// WH_MOUSE_LL 恒为全局；WH_MOUSE 看 tid。
			return (idHook == 14 /*WH_MOUSE_LL*/) || global;

		case R3ShieldCore::HookOp::SetKeyboardHook:
			return (idHook == 13 /*WH_KEYBOARD_LL*/) || global;

		case R3ShieldCore::HookOp::SetInputJournal:
			// WH_JOURNALRECORD(0) / WH_JOURNALPLAYBACK(1)：录制/回放输入。
			return true;

		case R3ShieldCore::HookOp::SetOtherHook:
			// 其它 wh（WH_CBT / WH_GETMESSAGE / WH_CALLWNDPROC …）：
			// 全局时等于往所有 GUI 进程注入 DLL，这本身就是注入行为。
			return global;

		case R3ShieldCore::HookOp::RegisterRawInput:
			// RIDEV_INPUTSINK：窗口不在前台也收输入 → 后台偷输入。
			// 不带这个标志的普通原始输入（游戏读鼠标）只记录。
			return rawInputSink;

		//
		// v11：轮询式输入读取。**注意这里的语义** —— 命中这个 case 说明
		// 调用方（InputHookGuard）已经用密度检测把这次调用判定为键盘记录了，
		// 所以一律高危。规则层不做二次过滤。
		//
		case R3ShieldCore::HookOp::PollAsyncKeyState:
		case R3ShieldCore::HookOp::PollKeyState:
			return true;

		case R3ShieldCore::HookOp::SetEventHook:
			// 前台窗口跟踪：不算高危（无障碍工具/窗口管理器都在用），只记录。
			return false;

		default:
			// Unhook：拆钩子不是攻击行为。
			return false;
		}
	}

	const char* InputHookRiskReason(ULONG idHook, ULONG threadId, ULONG hookOp, bool rawInputSink) noexcept
	{
		const bool global = (threadId == 0);

		switch (static_cast<R3ShieldCore::HookOp>(hookOp)) {
		case R3ShieldCore::HookOp::SetMouseHook:
			if (idHook == 14) { return "低级鼠标钩子（全系统监听）"; }
			return global ? "全局鼠标钩子（需注入所有 GUI 进程）" : nullptr;

		case R3ShieldCore::HookOp::SetKeyboardHook:
			if (idHook == 13) { return "低级键盘钩子（键盘记录器特征）"; }
			return global ? "全局键盘钩子（需注入所有 GUI 进程）" : nullptr;

		case R3ShieldCore::HookOp::SetInputJournal:
			return (idHook == 0) ? "录制全系统输入（WH_JOURNALRECORD）"
				: "回放/伪造输入（WH_JOURNALPLAYBACK）";

		case R3ShieldCore::HookOp::SetOtherHook:
			return global ? "全局钩子（往所有 GUI 进程注入 DLL）" : nullptr;

		case R3ShieldCore::HookOp::RegisterRawInput:
			return rawInputSink ? "注册后台原始输入（RIDEV_INPUTSINK，窗口不在前台也收）" : nullptr;

		//
		// v11：不装钩子的键盘记录路径。
		//
		// ⚠️ 这三条**由调用方（InputHookGuard 的轮询检测器）判密度之后再调**。
		//    规则层这里无法判断"这次调用是不是键盘记录"，因为它只看得到
		//    单次调用的参数 —— 而 GetAsyncKeyState 的参数就是虚拟键码，
		//    没有任何可判别特征。所以规则层只负责回答"这种 Op 一旦被认定，
		//    算不算高危"：算。是否认定由密度检测器决定。
		//
		case R3ShieldCore::HookOp::PollAsyncKeyState:
			return "轮询式读取按键状态（未安装钩子的键盘记录手法）";

		case R3ShieldCore::HookOp::PollKeyState:
			return "轮询式读取键盘状态（未安装钩子的键盘记录手法）";

		case R3ShieldCore::HookOp::SetEventHook:
			// SetWinEventHook 单独看不算攻击（无障碍工具、窗口管理器都在用），
			// 但它是"前台窗口跟踪 / 行为画像"的常用骨架。这里只给"需知情"，
			// 不算高危 —— 返回 nullptr 让 Mode 决定。
			return nullptr;

		default:
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 反向输入 —— 合成键鼠 / 锁屏勒索（v14）
	// ------------------------------------------------------------------
	//
	// ⚠️ 与 1~9 的方向相反：那批是"读用户在按什么"（窃听），
	//    这批是"代替用户去按"（操控）。这是远控木马（RAT）的核心动作，
	//    也是 **UAC 绕过** 的经典链：
	//        SetForegroundWindow(consent.exe) + SendInput 自动点"是"
	//    —— 用户只看到窗口一闪而过，提权就完成了。
	//
	// 三类各自的判据不同：
	//
	//   SendInputEvents（SendInput / keybd_event / mouse_event）
	//     ⚠️ **不能"调了就报"**：自动化外挂、宏、脚本、无障碍工具、
	//        远程桌面客户端、KVM 软件全在用，合法高频。
	//        所以和轮询式键盘记录一样，用**调用密度**过滤 ——
	//        hook 层（InputHookGuard 的合成输入检测器）判定"这次是不是
	//        在批量伪造输入"，规则层只回答"一旦被认定算不算高危"：算。
	//        是否认定由检测器决定（见 InputHookGuard）。
	//
	//   BlockUserInput（BlockInput）
	//     ⚠️ 这个 API 的作用是**冻结整个用户的键鼠输入** —— 除了
	//        Ctrl+Alt+Del（SAS）什么都按不动。勒索软件锁屏的标配，
	//        也用来"锁死用户不让其反应"。合法用途只有少数
	//        （部分安装器、演示工具），且正常做法是**自己前台时**才冻结。
	//        判据 = 调用方不是当前前台窗口的属主 → 后台冻结输入 = 高危。
	//
	//   ClipCursorLock（ClipCursor）
	//     ⚠️ 把鼠标锁在一个矩形里。游戏锁鼠标（自己前台且用了全屏/独占）
	//        是合法的；**后台进程**把鼠标锁到某个小矩形 = 典型的
	//        "伪造登录框骗密码"手法（锁住鼠标不让你点别处）。
	//        判据同 BlockInput：非前台属主 → 高危。
	//
	// foregroundOwnedByCaller：hook 层查 GetForegroundWindow() 的
	//   进程是否就是调用方自己 —— 是则说明它在"自己的界面上"操作，
	//   认定为合法；否则是干预别人的界面 → 高危。

	const char* InputInjectionRiskReason(ULONG hookOp, bool foregroundOwnedByCaller) noexcept
	{
		switch (static_cast<R3ShieldCore::HookOp>(hookOp)) {
		case R3ShieldCore::HookOp::SendInputEvents:
			// 走到这里说明 hook 层的密度检测器已认定为"批量伪造输入"。
			return "合成键鼠输入（SendInput / keybd_event —— 远控代操作 / UAC 绕过的点击）";

		case R3ShieldCore::HookOp::BlockUserInput:
			// 前台属主自己冻结自己（演示/安装器）→ 不算。
			if (foregroundOwnedByCaller) {
				return nullptr;
			}
			return "冻结用户输入（BlockInput —— 勒索软件锁屏 / 阻断用户操作）";

		case R3ShieldCore::HookOp::ClipCursorLock:
			if (foregroundOwnedByCaller) {
				return nullptr;
			}
			return "把鼠标锁在固定区域（ClipCursor —— 伪造登录框 / 困住用户）";

		default:
			return nullptr;
		}
	}

	bool IsHighRiskInputInjection(ULONG hookOp, bool foregroundOwnedByCaller) noexcept
	{
		return InputInjectionRiskReason(hookOp, foregroundOwnedByCaller) != nullptr;
	}

	// ------------------------------------------------------------------
	// 屏幕捕获
	// ------------------------------------------------------------------
	//
	// 能走到这里的只有两种：
	//   ① BitBlt / StretchBlt 且**源 DC 是屏幕/桌面 DC**（hook 层用
	//      WindowFromDC 过滤过，普通窗口重绘根本不会产生事件）
	//   ② PrintWindow —— 抓指定窗口，含被遮挡的内容
	//
	// 两条都是"把屏幕内容拿走"，一律高危。频率上也不构成问题：
	// 真截屏是低频动作（一次几百毫秒），不像重绘那样每秒几十次。
	//
	bool IsHighRiskScreen(ULONG screenOp) noexcept
	{
		switch (static_cast<R3ShieldCore::ScreenOp>(screenOp)) {
		case R3ShieldCore::ScreenOp::BitBlt:
		case R3ShieldCore::ScreenOp::StretchBlt:
		case R3ShieldCore::ScreenOp::PrintWindow:
		case R3ShieldCore::ScreenOp::GetDIBits:
			return true;
		default:
			return false;
		}
	}

	const char* ScreenRiskReason(ULONG screenOp) noexcept
	{
		switch (static_cast<R3ShieldCore::ScreenOp>(screenOp)) {
		case R3ShieldCore::ScreenOp::BitBlt: return "截取屏幕（BitBlt 源为屏幕 DC）";
		case R3ShieldCore::ScreenOp::StretchBlt: return "截取屏幕（StretchBlt 源为屏幕 DC）";
		case R3ShieldCore::ScreenOp::PrintWindow: return "抓取窗口内容（PrintWindow）";
		case R3ShieldCore::ScreenOp::GetDIBits: return "截取屏幕（GetDIBits 直读屏幕 DC，绕过 BitBlt）";
		default: return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// DLL 加载 / 劫持
	// ------------------------------------------------------------------
	//
	// ⚠️ 能力边界（必读）：挂的是 ntdll!LdrLoadDll / NtMapViewOfSection。
	//    手工映射 PE（自己解析重定位、自己建节）**不走这两个出口**，
	//    能绕过。所以这里的定位是"看得见常规侧加载"，不是"挡得住手工映射"。
	//
	// 关键设计：**过滤发生在 hook 层，不在规则层**。
	//   每个进程启动会加载几十上百个 System32 DLL —— 如果不过滤，
	//   事件日志会被淹没（和 hosts 时间戳那次同类失效）。
	//   所以 hook 里先判"是不是系统目录"，是就直接透传、不产生事件。
	//   走到这里的路径**一定已经是非系统目录的**了。
	//
	// 于是规则层只剩两档：
	//   ① 用户可写目录（Temp / AppData\Roaming / AppData\LocalLow /
	//      Downloads / ProgramData / 公共目录 / AppData\Local 下**非安装目录**）
	//      → 高危 —— 这是"白加黑"（合法 EXE 侧加载恶意 DLL）的典型落地点
	//      ⚠️ `AppData\Local\` 不是整体高危：`AppData\Local\Programs\`
	//         是标准的用户级安装目录（Python/VS Code…），必须排除。
	//   ② 其余非系统目录（如 Program Files、自建目录）→ **不算高危**（返回 nullptr）
	//      ⚠️ 这一点是实测修正的：曾经写成"非系统目录一律高危"，结果
	//         PowerShell 7（装在 D:\Program Files）一启动刷 235 条全 HIGH，
	//         99% 是正常 .NET 依赖 —— 噪音淹没真信号。兜底必须 nullptr。

	// 用户可写目录片段表。命中即"这个位置任何人都能写"。
	struct DllWritableDir
	{
		PCWSTR fragment;
		const char* label;
	};

	constexpr DllWritableDir kDllWritableDirs[] = {
		{ L"\\AppData\\Local\\Temp\\", "临时目录" },
		{ L"\\AppData\\LocalLow\\",    "用户本地低权限目录" },
		{ L"\\AppData\\Roaming\\",     "用户漫游目录" },
		{ L"\\Windows\\Temp\\",        "Windows 临时目录" },
		{ L"\\Downloads\\",            "下载目录" },
		{ L"\\ProgramData\\",          "ProgramData" },
		{ L"\\Users\\Public\\",        "公共用户目录" },
		{ L"\\Temp\\",                 "临时目录" },
		{ L"$Recycle.Bin\\",           "回收站" },
		{ L"\\PerfLogs\\",             "系统日志目录" },
	};

	// ⚠️ `AppData\Local\` **整体**不能判高危 —— 它是 Windows 上最大的
	//    "用户级安装目录"：`AppData\Local\Programs\`（Python、VS Code、
	//    GitHub Desktop…所有用 Squirrel/NSIS 装的用户级程序都在这）、
	//    `AppData\Local\Microsoft\`（OneDrive、Edge 组件）全在里面。
	//
	//    实测翻车记录：只写 `\\AppData\\Local\\` 一条片段时，
	//    `AppData\Local\Programs\Python\Python312\DLLs\_socket.pyd`
	//    被整片判成 HIGH —— 一次 Python 启动刷上百条假 HIGH，
	//    又是"噪音淹没真信号"。
	//
	//    所以这里**反过来列白名单**：`AppData\Local\` 下只有下面这些
	//    子目录才继续按"可写"处理，其余（Programs / Microsoft / Packages…）
	//    一律不算高危。
	constexpr PCWSTR kAppDataLocalExceptions[] = {
		L"\\AppData\\Local\\Programs\\",
		L"\\AppData\\Local\\Microsoft\\",
		L"\\AppData\\Local\\Packages\\",
		L"\\AppData\\Local\\Temp\\",     // 已在可写表里，列在这只是为了对称
		L"\\AppData\\Local\\CrashDumps\\",
	};

	const char* MatchWritableDir(PCWSTR path) noexcept
	{
		for (const DllWritableDir& entry : kDllWritableDirs) {
			if (ContainsNoCase(path, entry.fragment)) {
				return entry.label;
			}
		}

		// 兜底：`AppData\Local\` 之下但不在白名单子目录里的位置仍算可写
		// （比如 `AppData\Local\SomeApp\`、`AppData\Local\<随机名>\`）。
		if (ContainsNoCase(path, L"\\AppData\\Local\\")) {
			for (PCWSTR exception : kAppDataLocalExceptions) {
				if (ContainsNoCase(path, exception)) {
					return nullptr;
				}
			}
			return "用户本地目录";
		}

		return nullptr;
	}

	bool IsHighRiskDllLoad(PCWSTR dllPath, ULONG dllOp, bool manualMap) noexcept
	{
		return DllLoadRiskReason(dllPath, dllOp, manualMap) != nullptr;
	}

	const char* DllLoadRiskReason(PCWSTR dllPath, ULONG dllOp, bool manualMap) noexcept
	{
		// 手工映射 —— 最高档，和路径无关。
		// 一个映像被映射进进程，却**没有**经过 LdrLoadDll（模块表里没有它），
		// 这就是经典的"反射式注入"/手工映射特征。
		if (manualMap ||
			static_cast<R3ShieldCore::DllLoadOp>(dllOp) == R3ShieldCore::DllLoadOp::ManualMap) {
			return "手工映射 DLL 映像（无模块登记，反射式注入特征）";
		}

		if (!dllPath || !dllPath[0]) {
			return nullptr;
		}

		// 用户 protect_file= 也覆盖 DLL 路径 —— 复用同一套前缀匹配。
		if (MatchesUserProtectFile(dllPath)) {
			return "自定义保护路径下的 DLL";
		}

		if (MatchWritableDir(dllPath)) {
			// ⚠️ 只把**用户可写目录**判高危。
			//
			// 曾经的写法是"非系统目录一律高危"，实测立刻翻车：
			// PowerShell 7 装在 D:\Program Files\PowerShell\7\（不是系统 Program Files），
			// 一次启动就刷出 235 条 DLL 事件、**全部** HIGH —— 99% 是 .NET 依赖。
			// 这就是 hosts 时间戳那次的同类失效：噪音淹没真信号 = 功能性失效。
			//
			// 所以兜底必须返回 nullptr。非系统目录的加载仍会在 hook 层产生事件
			// （用户能看到"谁加载了哪来的 DLL"），但**不算高危、不弹窗、不拦**。
			return "从用户可写目录加载 DLL（白加黑侧加载特征）";
		}

		// 非系统目录、但也不是常见的可写目录（Program Files、自建安装目录…）
		// —— 只记录，不判高危。
		return nullptr;
	}

	// ------------------------------------------------------------------
	// 剪贴板
	// ------------------------------------------------------------------
	//
	// 为什么只把 Read 判高危：
	//   OpenClipboard 是"我要用剪贴板"的通用声明 —— 复制粘贴、截图工具、
	//   输入法、Office 全都在调。拦它 = 按 Ctrl+C 就弹窗。
	//   GetClipboardData 才是真的把内容取走。
	//
	// 但有价值的信息是：**谁在 Open 之后去 Get 了文本/密码类格式**。
	//   格式判定在 hook 层做不了（要 CF_TEXT/CF_UNICODETEXT 才知道是文本），
	//   所以这里不细分格式 —— 只要 Get 了就报，让用户看是谁。
	//
	// 隐私面定位：密码管理器、加密钱包、验证码 —— 它们的内容经常
	// 就躺在剪贴板里。这是"需要用户知情"，不是"一定恶意"。

	bool IsHighRiskClipboard(ULONG clipboardOp) noexcept
	{
		return ClipboardRiskReason(clipboardOp) != nullptr;
	}

	const char* ClipboardRiskReason(ULONG clipboardOp) noexcept
	{
		switch (static_cast<R3ShieldCore::ClipboardOp>(clipboardOp)) {
		case R3ShieldCore::ClipboardOp::Read:
			return "读取剪贴板内容";
		default:
			// Open 只记录，不判高危。
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 进程创建旁路
	// ------------------------------------------------------------------
	//
	// 和 ProcessGuard::NtCreateUserProcess 的关系：
	//   NtCreateUserProcess 是**最终出口**，所有创建最终都经过它 ——
	//   所以 ProcessGuard 已经在看"谁起了谁"了。
	//   这一层看的是**上下文差异**，只有这几种 API 才能提供的信号：
	//     CreateProcessWithTokenW  → token 被换过（提权 / 窃取 token 后横向）
	//     CreateProcessWithLogonW  → 带着别人的凭据起进程
	//     ShellExecuteEx           → 走 shell 解析，可能被关联劫持（.lnk/bat）
	//     WinExec / system         → shellcode 与老载荷最常用的一层
	//
	// ⚠️ 这几个 API 的调用频率极低（比 NtCreateUserProcess 低几个数量级），
	//    所以**可以全部判高危**，不用担心噪音。真正高频的 CreateProcessW
	//    走 NtCreateUserProcess，不在这里重复报。

	bool IsHighRiskSpawn(ULONG spawnOp) noexcept
	{
		return SpawnRiskReason(spawnOp) != nullptr;
	}

	bool IsHighRiskInputPolling(ULONG hookOp) noexcept
	{
		return InputHookRiskReason(0, 0, hookOp, false) != nullptr;
	}

	const char* SpawnRiskReason(ULONG spawnOp) noexcept
	{
		switch (static_cast<R3ShieldCore::SpawnOp>(spawnOp)) {
		case R3ShieldCore::SpawnOp::WithToken:
			return "携带令牌创建进程（提权 / 令牌窃取后的横向移动特征）";
		case R3ShieldCore::SpawnOp::WithLogon:
			return "使用指定凭据创建进程（凭据滥用）";
		case R3ShieldCore::SpawnOp::WinExec:
			return "通过 WinExec 启动程序（shellcode 常用的一层）";
		case R3ShieldCore::SpawnOp::System:
			return "通过 system / _wsystem 拉起命令解释器";
		case R3ShieldCore::SpawnOp::ShellExecute:
			return "通过 ShellExecute 启动程序（可能触发关联劫持）";
		case R3ShieldCore::SpawnOp::AsUser:
			return "用指定令牌创建进程（CreateProcessAsUser —— 换取用户身份，落地/提权常用）";
		default:
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 服务 / 安全对象权限变更（v11）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么这类单独判：Driver 那类看的是"装/改/启服务（看二进制路径）"。
	//    改 DACL 不改二进制 —— 例：sc sdset MySvc "D:(A;;RPWPCR;;;WD)"
	//    给 Everyone 加上服务控制权，此后普通用户能改这个 SYSTEM 服务的
	//    binPath 或直接重启它 → 任意 SYSTEM 代码执行。
	//    这类操作本身"什么都没改"，所以不看路径、只看"改了安全描述符"。
	//
	// 为什么不看具体 SDDL 内容：解析 SDDL 要看"是否给低权限主体授予了
	// 服务控制权"，是个真活；而且给普通用户加服务控制权在某些运维场景
	//   是有意为之。所以这里统一按"改服务安全描述符 = 高危"处理，
	//   让用户过目 —— 与"驱动高危无视模式一律拦"的取向一致。
	//
	bool IsHighRiskServiceConfig(ULONG serviceOp) noexcept
	{
		return ServiceConfigRiskReason(serviceOp) != nullptr;
	}

	const char* ServiceConfigRiskReason(ULONG serviceOp) noexcept
	{
		switch (static_cast<R3ShieldCore::ServiceConfigOp>(serviceOp)) {
		case R3ShieldCore::ServiceConfigOp::SetServiceSecurity:
			return "修改服务安全描述符（sc sdset —— 常被用来给普通用户授予服务控制权 → 提权）";
		case R3ShieldCore::ServiceConfigOp::SetKernelObjectSecurity:
			return "修改内核对象安全描述符（NtSetSecurityObject —— 常被用来放宽对象 ACL）";
		default:
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// COM / OLE 激活劫持（v12）
	// ------------------------------------------------------------------
	//
	// ⚠️ 判据的核心：**服务器路径落在用户可写目录**。
	//
	//    为什么不能"凡是 CoCreateInstance 就报"：COM 是 Windows 的地基，
	//    一个浏览器进程每秒都在 CoCreateInstance（图标、拖放、外壳扩展、
	//    媒体解码…）。一刀切 = 弹窗机关枪 + 日志刷爆，等于功能失效。
	//
	//    而"劫持"的特征很明确 —— 一个 CLSID 的服务器 DLL 被放到了
	//    用户可写目录（Temp / Downloads / AppData\Local\<随机名> /
	//    ProgramData）。合法软件的 COM 服务器装在 Program Files 或
	//    Windows 下，不会在这类目录里。
	//
	//    和 DllLoad 那条 `MatchWritableDir` 复用同一套片段表 ——
	//    原因和结论都一样（见上面 MatchWritableDir 的实测翻车记录）。
	//
	// ⚠️ 残余盲区（写清楚别让人误以为全覆盖）：
	//   · 直接写 HKCU\Software\Classes\CLSID\{guid}\InprocServer32 做
	//     **用户级**劫持 —— 不激活就看不见，激活时我们也只看路径。
	//     注册表 hook 能看到那次写（HKCR 合并视图下会落到 HKCU\Software\Classes）。
	//   · COM 服务器已经在注册表里被改过、现在才激活 —— 我们看得到激活
	//     （这一次能拦），但"谁改的"要翻注册表日志。
	//   · 注册表里已经在跑的代理（AppID / DllSurrogate）间接加载，路径可能
	//     解析不到 —— 拿不到路径时**不判高危**（宁可不报，也不刷假 HIGH）。
	//
	bool IsHighRiskComHijack(PCWSTR comServerPath, bool inproc) noexcept
	{
		return ComHijackRiskReason(comServerPath, inproc) != nullptr;
	}

	const char* ComHijackRiskReason(PCWSTR comServerPath, bool inproc) noexcept
	{
		if (!comServerPath || !comServerPath[0]) {
			// 拿不到服务器路径（CLSID 只在内存里映射、或走了代理）→ 不判高危。
			return nullptr;
		}

		// 用户 protect_file= 也覆盖 COM 服务器路径 —— 复用同一套前缀匹配。
		if (MatchesUserProtectFile(comServerPath)) {
			return inproc
				? "自定义保护路径下的进程内 COM 服务器（InprocServer32）"
				: "自定义保护路径下的本地 COM 服务器（LocalServer32）";
		}

		if (const char* where = MatchWritableDir(comServerPath)) {
			// where 是中文目录名（"临时目录"/"下载目录"…），拼进返回串里。
			static thread_local char buffer[256];
			sprintf_s(buffer,
				inproc
					? "CLSID 映射到用户可写目录的进程内服务器（%s｜InprocServer32 劫持）"
					: "CLSID 映射到用户可写目录的本地服务器（%s｜LocalServer32 劫持）",
				where);
			return buffer;
		}

		return nullptr;
	}

	// ------------------------------------------------------------------
	// 计划任务持久化（v12）
	// ------------------------------------------------------------------
	//
	// 判据按操作分档，理由：
	//
	//   RegisterTaskDefinition → 高危。这是"建立持久化"本身 ——
	//     任务注册后，攻击者重启一次机器就回来。哪怕动作是合法的
	//     （安装器建更新任务），也应该让用户过目一次。
	//
	//   TaskCacheWrite → 高危。绕过 COM 直写 TaskCache 注册表树，
	//     这是"任务计划程序看不见"的持久化方式（不产生 4698 事件）。
	//
	//   Run → 高危。立即执行某个已存在的任务 —— 横向移动（PsExec 那类
	//     工具就是起一个 SYSTEM 任务）与"提权后立即落地"的常见一步。
	//
	//   CreateFolder → 不算高危。建任务目录本身无害，很多安装器先建目录。
	//
	bool IsHighRiskScheduledTask(ULONG taskOp) noexcept
	{
		return ScheduledTaskRiskReason(taskOp) != nullptr;
	}

	const char* ScheduledTaskRiskReason(ULONG taskOp) noexcept
	{
		switch (static_cast<R3ShieldCore::ScheduledTaskOp>(taskOp)) {
		case R3ShieldCore::ScheduledTaskOp::RegisterTaskDefinition:
			return "注册 / 覆盖计划任务（持久化最常用的一招 —— 重启后自动执行）";
		case R3ShieldCore::ScheduledTaskOp::TaskCacheWrite:
			return "直接写任务计划缓存（HKLM\\...\\Schedule\\TaskCache —— 绕过 COM，不产生任务计划事件）";
		case R3ShieldCore::ScheduledTaskOp::Run:
			return "立即运行计划任务（横向移动 / 提权后立刻落地常用）";
		case R3ShieldCore::ScheduledTaskOp::CreateFolder:
			// 只建目录，不判高危。
			return nullptr;
		default:
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 音频采集 / 环回（v13）
	// ------------------------------------------------------------------
	//
	// ⚠️ 与摄像头判据的关系：
	//    摄像头那套（IsHighRiskCamera）**已经覆盖了 MF 设备源**，而 MF
	//    接口里摄像头和麦克风是同一套 API。所以音频这边**不重复判**
	//    CreateDeviceSource / CreateSourceReader（那两个照样走摄像头规则）。
	//    这里只处理**音频独有**的三个入口。
	//
	// 分档理由：
	//
	//   WasapiLoopback → 高危。AUDCLNT_STREAMFLAGS_LOOPBACK 表示"录
	//     系统正在播的声音"。正常软件用它只有录音/直播/字幕几种场景，
	//     而恶意场景是**录 VoIP 通话、录会议、录系统提示音里的口令**。
	//     这个标志本身就把意图暴露得很清楚。
	//
	//   WasapiCapture → 高危。普通麦克风采集。与摄像头同口径：不是
	//     "识别恶意"，是"让用户知情"。会议软件会开，那就问一次，
	//     用户点「始终允许」即可。
	//
	//   MicOpen → 高危。老式 waveInOpen / MCI 录音，同麦克风口径。
	//     现在用的人少，但正因如此**出现就相对可疑**。
	//
	bool IsHighRiskAudio(ULONG cameraOp) noexcept
	{
		return AudioRiskReason(cameraOp) != nullptr;
	}

	const char* AudioRiskReason(ULONG cameraOp) noexcept
	{
		switch (static_cast<R3ShieldCore::CameraOp>(cameraOp)) {
		case R3ShieldCore::CameraOp::WasapiLoopback:
			return "采集系统输出音频（WASAPI 环回 —— 可录制通话/会议/正在播放的声音）";
		case R3ShieldCore::CameraOp::WasapiCapture:
			return "采集麦克风（WASAPI 采集流）";
		case R3ShieldCore::CameraOp::MicOpen:
			return "打开录音设备（waveIn / MCI —— 老式录音接口）";
		default:
			// 摄像头侧那几个 op（以及 EnumDevice）不由这个判据负责。
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 令牌窃取 / 冒充（v13）
	// ------------------------------------------------------------------
	//
	// 判据分三档（用户选定的"完整链：拿句柄即可疑 + 复制/使用"）。
	//
	// ⚠️ 一档（OpenProcessToken / OpenThreadToken）**在规则层不判高危**
	//    —— 它只返回"拿到一个可被复制/被冒充的句柄"。为什么不能一刀切：
	//    进程管理器、调试器、备份软件、我们的**自我保护 hook 自己**都在
	//    调 OpenProcessToken。判高危 = 满屏假 HIGH = 真信号被淹没
	//    （v10/v12 已经栽过两次）。所以这一档交给 guard 侧的**关联判据**：
	//    同一进程在拿到句柄后又走到二档时，把那一次的 tier 标成"准备→使用"。
	//
	// 二档（DuplicateTokenEx / ImpersonateLoggedOnUser / CreateProcessWithToken /
	//    SetThreadToken）→ 高危。到这一步身份真的变了。
	//
	// 三档（AdjustTokenPrivileges）→ 在规则层判高危，但**真正上报与否
	//    由 guard 侧看参数**（只有启用 SeDebug/SeImpersonate/SeTcb 才算，
	//    DisableAllPrivileges 或无关特权不算）。规则层这里只表达"这一档
	//    的语义是铺路"。
	//
	bool IsHighRiskTokenTheft(ULONG tokenOp) noexcept
	{
		ULONG tier = 0;
		return TokenTheftRiskReason(tokenOp, &tier) != nullptr;
	}

	const char* TokenTheftRiskReason(ULONG tokenOp, ULONG* tierOut) noexcept
	{
		// tier：1 = 准备（可疑，非高危）；2 = 使用（高危）；3 = 铺路（高危）
		ULONG tier = 0;
		const char* reason = nullptr;

		switch (static_cast<R3ShieldCore::TokenTheftOp>(tokenOp)) {
		case R3ShieldCore::TokenTheftOp::OpenProcessToken:
			tier = 1;
			reason = "获取进程令牌句柄（令牌窃取链的起点）";
			break;
		case R3ShieldCore::TokenTheftOp::OpenThreadToken:
			tier = 1;
			reason = "获取线程令牌句柄（令牌窃取链的起点）";
			break;
		case R3ShieldCore::TokenTheftOp::DuplicateTokenEx:
			tier = 2;
			reason = "复制令牌（DuplicateTokenEx —— 造出可冒充的令牌副本）";
			break;
		case R3ShieldCore::TokenTheftOp::ImpersonateLoggedOnUser:
			tier = 2;
			reason = "冒充登录用户（ImpersonateLoggedOnUser —— 本线程身份被换掉）";
			break;
		case R3ShieldCore::TokenTheftOp::CreateProcessWithToken:
			tier = 2;
			reason = "用他人令牌启动进程（CreateProcessWithToken —— 以被窃身份执行代码）";
			break;
		case R3ShieldCore::TokenTheftOp::SetThreadToken:
			tier = 2;
			reason = "替换线程令牌（SetThreadToken —— 身份切换）";
			break;
		case R3ShieldCore::TokenTheftOp::AdjustTokenPrivileges:
			tier = 3;
			reason = "调整令牌特权（AdjustTokenPrivileges —— 为令牌窃取铺路）";
			break;
		default:
			break;
		}

		if (tierOut) *tierOut = tier;

		// 一档只表达"可疑"，不作为高危原因返回。
		if (tier == 1) {
			return nullptr;
		}
		return reason;
	}

	// ------------------------------------------------------------------
	// WMI 事件订阅持久化（v13）
	// ------------------------------------------------------------------
	//
	// ⚠️ 判据的两层过滤（**少了任何一层都会刷屏**）：
	//
	//   第一层：命名空间必须是 root\subscription。
	//     WMI 是 Windows 的管理总线，正常软件大量使用 —— 系统中心、
	//     杀软、设备管理、Office 都在 root\cimv2 / root\wmi 里查东西。
	//     只有 root\subscription 才是"事件订阅持久化"的地盘。
	//
	//   第二层：目标类必须是那三个之一。
	//     __EventFilter（触发条件）/ __EventConsumer（执行体）/
	//     __FilterToConsumerBinding（绑起来）。缺一不生效 —— 所以
	//     三件套里任何一件被写都是"有人在装持久化"。
	//
	// 分档：
	//   __EventConsumer  → 高危（最危险：它就是要执行的代码载体，
	//                       尤其是 CommandLineEventConsumer = 无文件执行）
	//   __FilterToConsumerBinding → 高危（绑定 = 整条链激活）
	//   __EventFilter    → 高危（触发条件）
	//   Subscribe（ExecNotificationQuery 在 root\subscription）→ 高危
	//   ExecMethod（在 root\subscription）→ 高危（可能直接触发消费者）
	//   ConnectServer / ExecQuery → 不算高危（连接与查询是审计行为）
	//
	bool IsHighRiskWmiSubscription(ULONG wmiOp, bool inSubscriptionNs, PCWSTR wmiClass) noexcept
	{
		return WmiSubscriptionRiskReason(wmiOp, inSubscriptionNs, wmiClass) != nullptr;
	}

	const char* WmiSubscriptionRiskReason(ULONG wmiOp, bool inSubscriptionNs, PCWSTR wmiClass) noexcept
	{
		if (!inSubscriptionNs) {
			// 不在 root\subscription —— 正常 WMI 使用，直接不算高危。
			return nullptr;
		}

		const bool isFilter = wmiClass && ContainsNoCase(wmiClass, L"__EventFilter");
		// ⚠️ 消费者类有两种形态（实测踩坑）：抽象基类是 `__EventConsumer`，
		//    而具体实现类（CommandLineEventConsumer / ActiveScriptEventConsumer）
		//    **不带前导双下划线** —— 只判 `__EventConsumer` 会漏掉真正的执行体。
		const bool isConsumer = wmiClass &&
			(ContainsNoCase(wmiClass, L"__EventConsumer") ||
			 ContainsNoCase(wmiClass, L"EventConsumer"));
		const bool isBinding = wmiClass && ContainsNoCase(wmiClass, L"__FilterToConsumerBinding");

		switch (static_cast<R3ShieldCore::WmiSubscriptionOp>(wmiOp)) {
		case R3ShieldCore::WmiSubscriptionOp::PutInstance:
			if (isConsumer) {
				// CommandLineEventConsumer 是默认的无文件执行体；
				// ActiveScriptEventConsumer 等价于脚本落地。都按同一档报。
				if (wmiClass && ContainsNoCase(wmiClass, L"CommandLine")) {
					return "写入 WMI 事件消费者 —— 命令行执行体（无文件持久化，重启后仍在）";
				}
				return "写入 WMI 事件消费者（__EventConsumer —— 事件触发时执行的代码载体）";
			}
			if (isBinding) {
				return "写入 WMI 订阅绑定（__FilterToConsumerBinding —— 把触发条件与执行体绑定，整条链激活）";
			}
			if (isFilter) {
				return "写入 WMI 事件过滤器（__EventFilter —— 定义什么事件触发后续动作）";
			}
			// 在 root\subscription 里写别的类 —— 少见但不报（避免误伤）。
			return nullptr;

		case R3ShieldCore::WmiSubscriptionOp::Subscribe:
			return "订阅 WMI 事件（ExecNotificationQuery on root\\subscription —— 可能是事件订阅攻击的一环）";

		case R3ShieldCore::WmiSubscriptionOp::ExecMethod:
			return "调用 WMI 对象方法（ExecMethod on root\\subscription —— 可能直接触发事件消费者）";

		case R3ShieldCore::WmiSubscriptionOp::ConnectServer:
		case R3ShieldCore::WmiSubscriptionOp::ExecQuery:
			// 连接与查询是审计/管理行为，只记录。
			return nullptr;

		default:
			return nullptr;
		}
	}

	// ------------------------------------------------------------------
	// 宿主劫持 / 加载器高危规则（v15）
	// ------------------------------------------------------------------
	//
	// 四个子面共用一个核心口径（同 v12 COM / v14 内存）：
	//   **配置点本身可能合法，只有当它指向"用户可写目录 / 非系统路径 /
	//   别的进程"时才高危。**
	//
	// 为什么必须这样收窄：这一类里每一个注册点、每一个加载 API
	// 都是系统正常运转的一部分 —— AppInit_DLLs 键系统自己在读，
	// LoadLibraryEx 每个进程都在调，NtMapViewOfSection 加载 DLL 时
	// 自己就在用。不设"实际危害"门槛 = 全系统假 HIGH 雪崩（铁律③）。

	// 路径是否落在"用户可写目录"。与 IsUserWritableServicePath 同一张表，
	// 但补上 AppData / Downloads —— 注入载荷最常落这两处。
	bool IsUserWritableHostPath(PCWSTR path) noexcept
	{
		if (!path || path[0] == L'\0') {
			return false;
		}

		static const PCWSTR kFragments[] = {
			L"\\Temp\\",
			L"\\AppData\\",       // 含 AppData\Local / Roaming / LocalLow
			L"\\Users\\",         // 含 Downloads / Desktop / Documents
			L"\\ProgramData\\",
			L"\\$Recycle.Bin\\",
			L"\\Windows\\Temp\\",
			L"\\Windows\\Tasks\\",
			L"\\Public\\",
			L"\\PerfLogs\\",
		};

		for (PCWSTR fragment : kFragments) {
			if (ContainsNoCase(path, fragment)) {
				return true;
			}
		}

		return false;
	}

	// 宿主注入键的"键路径"判据（子面①）。
	//
	// ⚠️ 关键：**是"值名"决定危害，不是"键"**。这些键本身都是正常的
	//    系统键（AppInit_DLLs 默认存在且为空、Winlogon 天天被读写）。
	//    所以本函数只看 keyPath（值名由 HostHijackOp 侧配合），
	//    路径命中即认为"这是一次全局注入键写"——真正的高危判定在
	//    调用处叠加"值名 + 值内容是否指向用户可写目录"。
	struct HostInjectionKeyRule
	{
		PCWSTR prefix;
		bool machine;
		bool user;
		const char* reason;
	};

	constexpr HostInjectionKeyRule kHostInjectionKeys[] = {
		// ---- AppInit_DLLs：每个加载 user32.dll 的进程都注入 ----
		// 32/64 位各一个键，且 WOW6432Node 重定向也是同一个位置。
		//
		// ⚠️ machine + user 两个都列：HKLM 版需要管理员，HKCU 版**不需要** ——
		//    正因为不需要提权，HKCU\...\Windows\AppInit_DLLs 才是更常见的
		//    用户态注入点（Windows 会同时读两处）。漏掉 user 就漏掉一半。
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true, true, "AppInit_DLLs（每个 GUI 进程注入）" },
		{ L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows", true, false, "AppInit_DLLs（32 位 WOW 注入）" },

		// ---- AppCertDlls：每次 CreateProcess / CreateFile 都注入 ----
		{ L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls", true, false, "AppCertDlls（进程/文件创建回调注入）" },

		// ---- IFEO Debugger / VerifierDlls：映像劫持 ----
		// IFEO 的 HKCU 版本对当前用户启动的进程同样生效。
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true, true, "IFEO 映像劫持" },
		{ L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", true, false, "IFEO 映像劫持（32 位）" },

		// ---- LSA 认证/通知包：LSASS 加载我们的 DLL ----
		{ L"SYSTEM\\CurrentControlSet\\Control\\Lsa", true, false, "LSA 认证/通知包（LSASS 注入）" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", true, false, "LSA OSConfig（凭据宿主）" },

		// ---- Winlogon 通知/Shell/Userinit：登录宿主劫持 ----
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", true, true, "Winlogon 宿主劫持（Notify/Shell/Userinit）" },
		{ L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", true, true, "Winlogon Notify 通知包" },

		// ---- 外壳扩展延迟加载 / 已知 DLL 劫持点 ----
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", true, true, "外壳延迟加载劫持" },
		{ L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler", true, true, "共享任务调度器劫持" },

		// ---- 会话管理器启动/引导执行 ----
		{ L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", true, false, "BootExecute（引导期执行）" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SetupExecute", true, false, "SetupExecute（安装期执行）" },
		{ L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd", true, false, "RDP 启动程序劫持" },
	};

	// 键路径是否命中"宿主注入键"表。返回规则说明或 nullptr。
	//
	// ⚠️ 与 kRegistryRules 的区别：那张表给 RegistryGuard 做**粗筛**，
	//    只写前缀就够（那里只判"写没写"，不看值名）。这里要更精确 ——
	//    因为宿主劫持的判据落在**值名 + 值内容**上，键命中只是第一步。
	//    两张表有重叠是**故意的**（AppInit 在两边都有）：RegistryGuard
	//    报"有人写了那个键"，HostHijackGuard 报"写入的 DLL 落在用户可写目录"。
	const char* HostInjectionKeyReason(PCWSTR keyPath) noexcept
	{
		if (!keyPath || keyPath[0] == L'\0') {
			return nullptr;
		}

		NormalizedKey key = NormalizeKey(keyPath);
		if (!key.relative || key.relative[0] == L'\0') {
			return nullptr;
		}

		for (const HostInjectionKeyRule& rule : kHostInjectionKeys) {
			if (key.machine && !rule.machine) {
				continue;
			}
			if (key.user && !rule.user) {
				continue;
			}

			// 逐段前缀比对：CurrentControlSet ≡ ControlSetNNN。
			//
			// ⚠️ 这里**必须**用段比对版本：本函数的输入来自
			//    NtSetValueKey 的 ResolveKeyPath（NtQueryKey），返回的是内核
			//    真实路径 `SYSTEM\ControlSet001\...`，而表里写的是
			//    `SYSTEM\CurrentControlSet\...`。用 StartsWithNoCase 会让
			//    AppCertDlls / LSA / BootExecute / SetupExecute / rdpwd
			//    这几条**全部静默失效**（实测 tools/regnorm.cpp 确认）。
			if (KeyPrefixMatchesNoCase(key.relative, rule.prefix)) {
				return rule.reason;
			}
		}

		// 用户自定义 protect_reg= 也算。
		//
		// ★ 两种写法都认（2026-10-05，同 RegistryRiskReason 的修法）：
		//   原始完整形式（向后兼容）+ 归一化相对形式（文档写法）。
		if (MatchesUserProtectRegistry(keyPath)
			|| MatchesUserProtectRegistry(key.relative)) {
			return "自定义保护路径（宿主注入）";
		}

		return nullptr;
	}

	// 宿主注入键写是否高危。pathValue 是准备写进该键的值
	// （AppInit_DLLs 的值 = DLL 路径；IFEO Debugger 的值 = 调试器路径；
	//  Shell/Userinit 的值 = 程序路径）。可能为空（如建键、改 LoadAppInit）。
	//
	// 判据：
	//   键命中注入表 **且** 值指向用户可写目录 → 高危
	//   键命中注入表 但 值为空 / 指向系统目录 → 不算（可能是系统自己在配）
	bool IsHighRiskHostInjectionKey(PCWSTR keyPath, PCWSTR pathValue) noexcept
	{
		return HostInjectionKeyRiskReason(keyPath, pathValue) != nullptr;
	}

	const char* HostInjectionKeyRiskReason(PCWSTR keyPath, PCWSTR pathValue) noexcept
	{
		const char* keyReason = HostInjectionKeyReason(keyPath);
		if (!keyReason) {
			return nullptr;
		}

		// ⚠️ 值指向用户可写目录 = 真劫持特征。
		//
		//    IFEO 的 Debugger 指向 System32 下的调试器（windbg/cdb）是正常
		//    开发行为；AppInit_DLLs 留空或指向系统 DLL 也不是攻击。只有当
		//    "系统以后会加载的那个东西"落在用户能改的地方 —— 才是攻击者
		//    能持续利用的劫持点。
		if (IsUserWritableHostPath(pathValue)) {
			return keyReason;
		}

		// 值不是路径（IFEO 的 GlobalFlag / 数字、AppInit 的 0/1 开关）时不做判断
		// —— 交给 RegistryGuard 的粗筛记录即可，避免误报。
		return nullptr;
	}

	// 加载器侧加载变体（子面②）/ 远程映射注入（子面③）/
	// 凭据宿主（子面④）共用：由路径 + 是否跨进程 + 是否手工映射 判定。
	//
	// ⚠️ 与 IsHighRiskDllLoad 的关系：那个函数判的是"加载的 DLL 路径本身"
	//    （白加黑看路径），这里判的是**"这次加载动作的机制"**：
	//      - 跨进程映射（MapSectionRemote）→ 无论载荷路径，机制即注入
	//      - 跨进程 APC（QueueApcRemote）→ 同上
	//      - 凭据宿主注册（CredentialHost）→ 涉及 LSASS/登录宿主
	//      - 本地 LoadLibraryEx / 通知注册 → 回到"路径是否用户可写"
	//
	// crossProcess 只有远程映射/APC 两个 op 才为 true。
	const char* HostHijackRiskReason(ULONG hostOp, PCWSTR dllPath, bool crossProcess, bool manualMap) noexcept
	{
		const R3ShieldCore::HostHijackOp op = static_cast<R3ShieldCore::HostHijackOp>(hostOp);

		switch (op) {
		case R3ShieldCore::HostHijackOp::InjectionRegistryKey:
			// 走 HostInjectionKeyRiskReason（需要 keyPath + value），
			// 这里 dllPath 传的是 valueName，语义不同 —— 不在本函数判。
			return nullptr;

		case R3ShieldCore::HostHijackOp::MapSectionRemote:
			// ⚠️ 跨进程映射 = 反射式 / 手工映射注入的核心动作。
			//
			//    这是子面③的**主要判据**：把 SEC_IMAGE 段映射进**别的进程**，
			//    载荷直接落在目标地址空间里，不经过 LdrLoadDll、不写内存、
			//    不起线程 —— v14 注入链的四步它一步都不走。
			//
			//    本进程映射段（自己的 DLL 加载）永远走这条 API —— 所以
			//    **crossProcess 是硬门槛**：不等就不是高危。
			if (crossProcess) {
				return "跨进程映射内存段（反射式/手工映射注入 —— 绕过 LdrLoadDll 把载荷落进别的进程）";
			}
			return nullptr;

		case R3ShieldCore::HostHijackOp::QueueApcRemote:
			// ⚠️ 跨进程 APC = 把载荷地址塞进目标进程的 APC 队列，
			//    等目标线程进 alertable 状态时执行。第二条注入路径
			//    （同样绕过 v14 的四步）。crossProcess 是硬门槛。
			if (crossProcess) {
				return "跨进程投递 APC（APC 注入 —— 借目标进程已有线程执行载荷）";
			}
			return nullptr;

		case R3ShieldCore::HostHijackOp::CredentialHost:
			// ⚠️ 凭据宿主注册（Security Packages / Credential Provider）。
			//
			//    LSASS 会在启动时加载 Authentication Packages / Security
			//    Packages 里列出的 DLL；登录界面会加载 Credential Provider。
			//    把我们的 DLL 注册进去 = 系统以后主动把凭据交给我们。
			//
			//    判据同注入键：**路径落在用户可写目录**才是劫持，
			//    指向系统 DLL（kerberos.dll / msv1_0.dll）是正常配置。
			if (IsUserWritableHostPath(dllPath)) {
				return "凭据宿主注册指向用户可写目录（LSASS/登录宿主劫持 —— 系统以后会把凭据交给它）";
			}
			return nullptr;

		case R3ShieldCore::HostHijackOp::LoadLibraryEx:
		case R3ShieldCore::HostHijackOp::RegisterDllNotification:
			// 本地加载变体：回到"路径是否用户可写"（与白加黑同一口径）。
			//
			// ⚠️ manualMap 时即便路径在系统目录也报 —— 手工映射一个
			//    系统 DLL 到非映像边界是反常的（正常加载器不这么做）。
			if (manualMap) {
				return "手工映射加载（绕过加载器，映射行为异常）";
			}
			if (IsUserWritableHostPath(dllPath)) {
				return (op == R3ShieldCore::HostHijackOp::RegisterDllNotification)
					? "注册加载通知回调并加载用户可写目录 DLL（劫持加载决策）"
					: "以扩展参数从用户可写目录加载 DLL（白加黑宿主加载）";
			}
			return nullptr;

		default:
			return nullptr;
		}
	}

	bool IsHighRiskHostHijack(ULONG hostOp, PCWSTR dllPath, bool crossProcess, bool manualMap) noexcept
	{
		return HostHijackRiskReason(hostOp, dllPath, crossProcess, manualMap) != nullptr;
	}

	// ------------------------------------------------------------------
	// bypass 判据的纯函数部分（v16）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么需要：ComputeBypass 原判据只看目录前缀（`%SystemRoot%\` 全放行），
	//    导致 `C:\Windows\Temp\evil.exe` 这种**用户可写子目录**里的程序
	//    被当系统进程 bypass（一个 hook 都不挂）。v16 起改成"签名 + 目录"双条件，
	//    这里提供其中**不需要系统 API** 的两块（可单测）。

	// `%SystemRoot%\` 下**用户可写（或半可写）**的子目录名。
	//
	// ⚠️ 全部小写，但**不用预先转小写** —— 下面用 ContainsNoCase 逐条比。
	//    片段两端带 `\`，避免 `\temp` 撞上 `\template`。
	//
	//   为什么这些目录算"不可信"：它们默认 ACL 允许 Users/普通用户写入，
	//   攻击者往里丢 EXE 就能借 `C:\Windows\...` 的路径前缀冒充系统程序。
	static const PCWSTR kWindowsWritableSubdirFragments[] = {
		L"\\Temp\\",
		L"\\Tasks\\",
		L"\\Prefetch\\",
		L"\\tracing\\",
		L"\\LiveKernelReports\\",
		L"\\Logs\\",
		L"\\Debug\\",
		L"\\Fonts\\",                  // 字体目录历史上可写
		L"\\Web\\Wallpaper\\",
		L"\\AddIns\\",
		L"\\AppCompat\\Programs\\",
		L"\\System32\\spool\\drivers\\",       // 打印驱动目录常被滥用
		L"\\System32\\config\\systemprofile\\",
		L"\\SysWOW64\\spool\\drivers\\",
		L"\\ServiceProfiles\\",
	};

	bool IsInWritableWindowsSubdir(PCWSTR imagePath) noexcept
	{
		if (!imagePath || imagePath[0] == L'\0') {
			return false;
		}

		for (PCWSTR fragment : kWindowsWritableSubdirFragments) {
			if (ContainsNoCase(imagePath, fragment)) {
				return true;
			}
		}

		return false;
	}

	bool IsMicrosoftSigner(PCWSTR signerName) noexcept
	{
		if (!signerName || signerName[0] == L'\0') {
			return false;
		}

		// ⚠️ 别写全等：微软签名主题名有多种写法
		//    （"Microsoft Windows" / "Microsoft Corporation" /
		//      "Microsoft Windows Publisher" / "Microsoft Component Publisher"）
		//    统一判"以 Microsoft 开头"。
		if (_wcsnicmp(signerName, L"Microsoft", 9) != 0) {
			return false;
		}

		// ⚠️ 但**必须跟词边界**：只判前 9 个字符会让 "Microsoftish Evil Corp."
		//    这类伪造名蒙混过关（v16 单测抓到的前缀撞车）。真正的微软签名者
		//    在 "Microsoft" 后面一定是空格（"Microsoft Windows"），或者整个
		//    名字就是 "Microsoft" 本身（\0 结束）。任何字母/数字紧跟其后
		//    （"Microsoftish" / "MicrosoftXxx"）都不认。
		const WCHAR next = signerName[9];
		if (next == L'\0') {
			return true;  // 主题名就是 "Microsoft"
		}

		if (next == L' ' || next == L'\t') {
			return true;  // "Microsoft Windows" 之类
		}

	// 其余情况（连着的字母/数字/标点）视为撞车，不认。
	return false;
	}

	// ------------------------------------------------------------------
	// bypass 判据 v20：**具体文件路径白名单**（取代「整个 %SystemRoot%\ 目录」）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么不再信任"System32 目录前缀 + 微软签名"：
	//
	//   v16 的判据是「目录在 %SystemRoot%\ 下 + 微软签名 → bypass」。它挡住了
	//   `C:\Windows\Temp\evil.exe`（可写子目录），但没有挡住：
	//
	//     · 任何**持有效微软签名的、放在 System32 里的**非系统模块
	//       （被利用的微软签名组件、DLL 侧加载落点、合法文件的滥用）；
	//     · 攻击者若能让某个微软签名程序从异常路径运行，仍可能借目录前缀蒙混。
	//
	//   v20 收紧为**白名单制**：只有**逐个列出的具体文件**才可能 bypass，
	//   其余一律挂 hook（哪怕它是微软签名、哪怕在 System32 里）。
	//
	// 判据（三条同时成立才 bypass）：
	//   ① 镜像路径**逐字符命中**白名单里的某一条（归一化后全路径全等，不分大小写）
	//   ② 不在可写子目录里（`IsInWritableWindowsSubdir`，双保险）
	//   ③ 微软签名（沿用 `IsMicrosoftSigner`，调用方在 registry_guard.cpp 里做）
	//
	// ⚠️ **路径归一化**：白名单条目用**规范形态**写（`C:\Windows\System32\xxx.exe`），
	//    比较前把传入路径的 `\SystemRoot\` / `\??\` 前缀补全成 `%SystemRoot%`，
	//    并把 `/` 统一成 `\`。这样内核返回的 `\SystemRoot\System32\...` 形态
	//    也能正确命中。
	//
	// ⚠️ **SysWOW64 vs System32**：32 位进程在 64 位系统上，System32 会被 WOW64
	//    重定向到 SysWOW64。白名单**两条都要列**（或调用方按需补 SysWOW64 条目），
	//    否则 32 位系统进程会被漏掉 → 全挂 hook → 噪音。

	// 系统程序白名单（**具体文件**，非目录）。
	//
	// 设计原则：只列"必须零开销放行、且绝不可能被替换"的**核心系统进程**。
	// 越少越安全 —— 每多一条就多一个被伪造面（虽然还有签名兜底）。
	//
	// 路径统一用 `%SystemRoot%` 占位符（比较时展开），避免硬编码 `C:\Windows`。
	static const PCWSTR kSystemImageWhitelist[] = {
		// ---- 会话/内核基础进程（这些挂 hook 会导致系统行为异常）----
		L"%SystemRoot%\\System32\\smss.exe",
		L"%SystemRoot%\\System32\\csrss.exe",
		L"%SystemRoot%\\System32\\wininit.exe",
		L"%SystemRoot%\\System32\\winlogon.exe",
		L"%SystemRoot%\\System32\\services.exe",
		L"%SystemRoot%\\System32\\lsass.exe",
		L"%SystemRoot%\\System32\\lsaiso.exe",
		L"%SystemRoot%\\System32\\svchost.exe",
		L"%SystemRoot%\\System32\\dwm.exe",
		L"%SystemRoot%\\System32\\fontdrvhost.exe",
		L"%SystemRoot%\\System32\\spoolsv.exe",
		L"%SystemRoot%\\System32\\sihost.exe",
		L"%SystemRoot%\\System32\\taskhostw.exe",
		L"%SystemRoot%\\System32\\runtimebroker.exe",
		L"%SystemRoot%\\System32\\ctfmon.exe",
		L"%SystemRoot%\\System32\\audiodg.exe",
		L"%SystemRoot%\\System32\\conhost.exe",
		L"%SystemRoot%\\System32\\WUDFHost.exe",
		L"%SystemRoot%\\System32\\Registry\\",
		// ---- 系统 shell / 桌面（高频、被注入后噪音大）----
		L"%SystemRoot%\\explorer.exe",
		L"%SystemRoot%\\System32\\dllhost.exe",
		L"%SystemRoot%\\System32\\SearchIndexer.exe",
		L"%SystemRoot%\\System32\\SecurityHealthSystray.exe",
		L"%SystemRoot%\\System32\\SecurityHealthService.exe",
		// ---- SysWOW64 对应项（32 位系统进程）----
		L"%SystemRoot%\\SysWOW64\\smss.exe",
		L"%SystemRoot%\\SysWOW64\\csrss.exe",
		L"%SystemRoot%\\SysWOW64\\winlogon.exe",
		L"%SystemRoot%\\SysWOW64\\services.exe",
		L"%SystemRoot%\\SysWOW64\\lsass.exe",
		L"%SystemRoot%\\SysWOW64\\svchost.exe",
		L"%SystemRoot%\\SysWOW64\\dwm.exe",
		L"%SystemRoot%\\SysWOW64\\spoolsv.exe",
		L"%SystemRoot%\\SysWOW64\\conhost.exe",
		L"%SystemRoot%\\SysWOW64\\explorer.exe",
		L"%SystemRoot%\\SysWOW64\\dllhost.exe",
	};

	// 把镜像路径归一化成**统一形态**，便于与白名单逐字符比较：
	//   · `/` → `\`
	//   · `\SystemRoot\...` 前缀 → `%SystemRoot%\...`
	//   · `X:\Windows\...` 前缀 → `%SystemRoot%\...`（盘符无关；WOW64/重定向无关）
	//
	// 归一化后，白名单条目也统一用 `%SystemRoot%` 开头，直接 `_wcsicmp` 即可。
	//
	// 返回写进 out 的字符数（不含结尾 NUL）；容量不足 / 非法输入返回 0。
	static size_t NormalizeImagePath(PCWSTR imagePath, WCHAR* out, size_t outChars) noexcept
	{
		if (!imagePath || !out || outChars == 0) {
			return 0;
		}

		// 先整体拷贝 + `/`→`\`
		size_t n = 0;
		for (const WCHAR* p = imagePath; *p; ++p) {
			if (n + 1 >= outChars) {
				return 0;
			}
			out[n++] = (*p == L'/') ? L'\\' : *p;
		}
		out[n] = L'\0';

		// 尾部形态为 `%SystemRoot%\<rest>`，统一往这里归。
		WCHAR tail[MAX_PATH * 2] = {};  // 存 `\rest`（以反斜杠开头）
		bool haveTail = false;

		// 形态 A：`\SystemRoot\...`（内核 / 服务配置常见）
		const WCHAR* kSystemRootPrefix = L"\\SystemRoot\\";
		constexpr size_t kSystemRootPrefixLen = 12;  // \SystemRoot\ = 12 字符
		if (_wcsnicmp(out, kSystemRootPrefix, kSystemRootPrefixLen) == 0) {
			// 从 `\SystemRoot` 后的那个 `\` 开始（`out + 11`）
			wcscpy_s(tail, out + kSystemRootPrefixLen - 1);
			haveTail = true;
		}

		// 形态 B：`X:\Windows\...`（盘符 + \Windows）
		if (!haveTail && out[0] != L'\0' && out[1] == L':' && out[2] == L'\\' &&
			_wcsnicmp(out + 2, L"\\Windows", 8) == 0) {
			// out + 10 是 `\Windows` 之后的位置（`\rest`）
			if (out[10] == L'\\') {
				wcscpy_s(tail, out + 10);
				haveTail = true;
			}
		}

		if (haveTail) {
			WCHAR rebuilt[MAX_PATH * 2] = {};
			if (swprintf_s(rebuilt, L"%%SystemRoot%%%s", tail) < 0) {
				return 0;
			}
			n = wcslen(rebuilt);
			if (n + 1 > outChars) {
				return 0;
			}
			wcscpy_s(out, outChars, rebuilt);
			return n;
		}

		return n;
	}

	// 白名单条目与**已归一化**路径的比较。
	//
	// ⚠️ 规则层是**纯函数层**，不在这里调 `GetWindowsDirectory`（那会引入
	//    系统依赖，破坏可单测性）。`NormalizeImagePath` 已把传入路径统一成
	//    `%SystemRoot%\...` 形态，白名单条目本身就是这个形态 →
	//    **直接 `_wcsicmp` 全等**即可（大小写不敏感）。
	//
	//    这样规则层不依赖任何 API，单测可以直接喂 `C:\Windows\System32\smss.exe`
	//    或 `\SystemRoot\System32\smss.exe`。
	static bool MatchWhitelistEntry(PCWSTR entry, PCWSTR normalizedImage) noexcept
	{
		if (!entry || !normalizedImage) {
			return false;
		}

		return _wcsicmp(entry, normalizedImage) == 0;
	}

	// bypass 判据 v20：镜像路径是否命中**具体文件白名单**。
	//
	// ⚠️ 这是"是否值得信任"的**第一条**（路径白名单）；调用方还要再叠加
	//    「不在可写子目录」+「微软签名」两条。三条全过才 bypass。
	bool IsWhitelistedSystemImage(PCWSTR imagePath) noexcept
	{
		if (!imagePath || imagePath[0] == L'\0') {
			return false;
		}

		WCHAR normalized[MAX_PATH * 2] = {};
		if (NormalizeImagePath(imagePath, normalized, _countof(normalized)) == 0) {
			return false;
		}

		for (PCWSTR entry : kSystemImageWhitelist) {
			if (MatchWhitelistEntry(entry, normalized)) {
				return true;
			}
		}

		return false;
	}

	// ------------------------------------------------------------------
	// block_all / block_all_safe 用（v25）：注册表写要不要"先问再拦"？
	// ------------------------------------------------------------------
	//
	// 背景：`registry_guard.cpp` 的 block-all 分支原来是"一律直接拒、不弹窗"，
	// 后果是**正常软件写自己的配置也静默失败**，用户看到系统弹
	// 「Windows 无法访问指定设备、路径或文件」（`0xC0000022`），而**没有任何
	// 提示**。实测：桌面软件全打不开；系统 UWP 组件（`TextInputHost` 等）
	// 写 `LocalState` 被拒 24 次。
	//
	// v25 把这三类操作从"直接拒"改成"弹窗询问"（与 v21 对进程类做的一样）。
	//
	// ★ 但注册表比进程类**危险得多**，所以判据必须区分"正常软件写自己配置"
	//   与"持久化植入"。命中的位置直接拦、**连问都不问**：
	//
	//   ① 高危规则表命中（`IsHighRiskRegistry`）—— Run / IFEO / 服务 /
	//      Winlogon / COM 劫持 / WMI 订阅 / 打印机驱动 … 全部已在册，
	//      恶意样本的持久化落点都在这张表里。
	//   ② Windows 自身运行时基础设施键（`IsSystemInfrastructureKey` 的等价集合）
	//      —— `SOFTWARE\Microsoft\Windows` / `Cryptography` / `COM3` /
	//      `SystemCertificates` / `Classes` / `SYSTEM\ControlSet` 等。
	//      这些**原本就有豁免**（`registry_guard.cpp` 的
	//      `IsSystemInfrastructureKey`），历史结论是"问了没意义 + 弹窗机关枪"。
	//      这里必须显式再判一次：block-all 分支**抢在豁免之前**执行，
	//      不判的话它们会被弹窗淹没。
	//   ③ hive 级操作（`IsHiveOp`）—— 加载 / 卸载 / 导出 / 还原配置单元，
	//      整棵子树的原子替换，不是"写一个值"，没有询问的意义。
	//   ④ COM+ 目录（`SOFTWARE\Microsoft\COM3\Catalog`）—— 可指定激活身份，
	//      写它 = 以高权限激活攻击者组件。
	//
	// 其余（第三方软件写自己的 `SOFTWARE\<厂商>\<产品>`、
	// 用户 hive 里的应用配置）→ 返回 true，交给调用方弹窗。
	//
	// ⚠️ 默认结论仍是**拒绝**：`prompt_default` 默认就是 deny，
	//   超时 / UI 不在 → 直接拒。放开的只是"让人有机会放行正常软件"。
	//
	// ⚠️ 本函数**只允许**在 block-all 分支调用，不要拿它去放过 LOG/BLOCK。
	bool ShouldAskInsteadOfBlockAll(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept
	{
		// ③ hive 级操作：不问。
		if (R3ShieldCore::IsHiveOp(op)) {
			return false;
		}

		// ① 高危规则表命中：不问（这些正是要拦的持久化落点）。
		if (IsHighRiskRegistry(keyPath, valueName, op)) {
			return false;
		}

		if (!keyPath || keyPath[0] == L'\0') {
			// 拿不到路径 = 判不出这写的是什么 → 不问（fail-closed）。
			return false;
		}

		// 去掉 `\REGISTRY\MACHINE\` / `\REGISTRY\USER\S-1-5-21-...\` 前缀，
		// 与 `IsSystemInfrastructureKey` 用同一套归一化，避免两处判据漂移。
		PCWSTR path = keyPath;
		if (_wcsnicmp(path, L"\\REGISTRY\\MACHINE\\", 18) == 0) {
			path += 18;
		}
		else if (_wcsnicmp(path, L"\\REGISTRY\\USER\\", 15) == 0) {
			PCWSTR slash = wcschr(path + 15, L'\\');
			if (slash) {
				path = slash + 1;
			}
		}

		// ② Windows 自身运行时基础设施键：不问。
		//
		// ⚠️ 这里列的是**字面前缀**，而 `SYSTEM\ControlSet001\...` 是
		//    从键句柄解析出来的**内核真实形态**（`CurrentControlSet` 只是
		//    符号链接，见 §十-40）。两者**都要列** ——
		//    `KeyPrefixMatchesNoCase` 的段等价只在"段不等长"时才触发，
		//    这里用的是 `_wcsnicmp` 字面比对，不做等价（v25 踩过：
		//    只列 `CurrentControlSet` 时，`SetValueKey` 的句柄路径
		//    `SYSTEM\ControlSet001\...` 全部落到"问"的分支）。
		//
		//    `ControlSet001` 是绝大多数机器上 `CurrentControlSet` 指向的
		//    那一个（正常安装 → 001）。`ControlSet002`+ 是 LastKnownGood
		//    等备份，写它们也算系统基础设施，一并列出。
		//
		// ⚠️ ⚠️ **v27 剔除两条（`SOFTWARE\Classes` / `SOFTWARE\Microsoft\MMDevices`）**：
		//
		//   这两条曾从 `IsSystemInfrastructureKey`（LOG/BLOCK 模式的**豁免**表）
		//   照搬进来 —— 但**"豁免不拦"和"不问直接拒"是相反的两件事**！
		//   在 LOG/BLOCK 下它们是"放过"（合理），搬到 block-all 的"不问表"里
		//   就变成**"直接杀"**（灾难）。
		//
		//   `HKLM\SOFTWARE\Classes`（= `HKCR` 的机器侧主存储）是**全系统最热的
		//   键之一**：每个程序启动、每次 COM 激活、每个安装器都摸它；里面
		//   绝大多数内容是良性的（已装程序的 ProgID、文件扩展名关联、
		//   已注册 COM 组件的 CLSID）。
		//   `MMDevices` 同理（音频/蓝牙设备枚举，正常软件常态读写）。
		//
		//   ⇒ 它们回到**"可问"档（弹窗）**，不再是"直接拒"。
		//
		//   ★ 安全边界**没漏**：`Classes` 下真正的劫持点
		//   （`exefile\shell\open\command` / `ActivatableClasses` / `AppID` /
		//   `Extensions` / COM+ 两个 CLSID）**都在 `kRegistryRules` 高危表里**，
		//   由上面的判据 ① 直接拒，压根走不到这张表。
		//
		//   ⚠️ 教训（沉淀为铁律）：**往 block-all 的"不问表"加条目时，
		//   禁止直接复用"豁免表"的前缀**。两者语义相反：
		//   豁免表错了顶多"少拦一次"，不问表错了是"整机报废"。
		static const PCWSTR infrastructurePrefixes[] = {
			L"SOFTWARE\\Microsoft\\Windows",
			L"Software\\Microsoft\\Windows",
			L"SOFTWARE\\Microsoft\\Cryptography",
			L"Software\\Microsoft\\Cryptography",
			L"SOFTWARE\\Microsoft\\COM3",
			L"Software\\Microsoft\\COM3",
			L"SOFTWARE\\Microsoft\\SystemCertificates",
			L"Software\\Microsoft\\SystemCertificates",
			L"SOFTWARE\\Microsoft\\OLE",
			L"Software\\Microsoft\\OLE",
			L"SOFTWARE\\Policies\\Microsoft\\Cryptography",
			L"Software\\Policies\\Microsoft\\Cryptography",
			L"SOFTWARE\\Microsoft\\AppModel",
			L"Software\\Microsoft\\AppModel",
		};

		for (PCWSTR prefix : infrastructurePrefixes) {
			size_t length = wcslen(prefix);
			if (_wcsnicmp(path, prefix, length) != 0) {
				continue;
			}

			// 边界必须落在 '\' 或结尾，避免 `SOFTWARE\Microsoft\WindowsApps`
			// 这类近邻段误命中。
			const WCHAR next = path[length];
			if (next == L'\0' || next == L'\\') {
				return false;
			}
		}

		// ④ COM+ 目录：不问（自成一段，不在上面的前缀树里）。
		if (_wcsnicmp(path, L"SOFTWARE\\Microsoft\\COM3\\Catalog", 33) == 0 ||
			_wcsnicmp(path, L"Software\\Microsoft\\COM3\\Catalog", 33) == 0) {
			return false;
		}

		// ⑤ 字面前缀判不出、但规则表已覆盖的"段名不同形"规则：不问。
		//
		// ⚠️ 为什么不能用字面 `_wcsnicmp` 判这几条：
		//    规则里写的是 `SYSTEM\CurrentControlSet\...`，而键句柄路径
		//    解析出来是 `SYSTEM\ControlSet001\...`（§十-40）。上面的
		//    基础设施表把两种形态都列了，但**逐条列前缀**的办法对
		//    "规则里带更长后缀"的条目会漏（v25 自测发现 BootExecute 漏判）。
		//    所以这里改走规则库自己的**逐段比对**（它能处理
		//    `CurrentControlSet ≡ ControlSetNNN`），把前缀当规则来试。
		//
		//    这几条都是"引导/登录期执行"的要害键，必须直接拦、不能给询问机会。
		//
		// ⚠️ SYSTEM hive 走**逐段比对**（`KeyPrefixMatchesNoCase`）而不是字面
		//    前缀，因为 `ControlSetNNN` 的段等价只有逐段比对才认。
		//    字面写法 `L"SYSTEM\\ControlSet"`（17 字符）是**不行的**：
		//    `ControlSet001` 的第 18 个字符是 `'0'`，边界判据要求 `\` 或结尾
		//    → 永远不命中（v25 自测踩到）。`CurrentControlSet` 与
		//    `ControlSet001` 两种形态逐段比对都能覆盖。
		//
		//    注意：整个 SYSTEM hive 基础设施面（`SYSTEM\ControlSet001\*`）
		//    并不全部进这个列表 —— 只有下面这几条"要害"，其余（比如
		//    `SYSTEM\ControlSet001\Services\...`）应该**直接拦**而不是问，
		//    由上面的 `IsHighRiskRegistry` 覆盖（服务子树在高危表里）。
		static const PCWSTR segmentRules[] = {
			L"SYSTEM\\CurrentControlSet\\Control",
			L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
			L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\SetupExecute",
			L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls",
			L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
			L"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Wds\\rdpwd",
			L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders",
		};

		for (PCWSTR rule : segmentRules) {
			if (KeyPrefixMatchesNoCase(path, rule)) {
				return false;
			}
		}

		// ⑥ WMI 仓库（`SOFTWARE\Microsoft\Wbem`）：不问。
		//
		// ⚠️ 为什么必须显式加这一条：WMI **事件订阅**的监控（v13）走的是
		//    `wmi_subscription_guard`（`IWbemServices` vtable patch），
		//    覆盖 `__EventFilter` / `CommandLineEventConsumer` /
		//    `__FilterToConsumerBinding`。但**直接写 WMI 仓库键**
		//    （`SOFTWARE\Microsoft\Wbem\...`）是**另一条路** ——
		//    不经过 root\subscription 的 COM 接口，能绕过那个 guard
		//    （§十一 明确列为已知空白）。方向是"拦"不是"问"，所以这里
		//    整棵树直接拒绝，不给询问机会。
		if (_wcsnicmp(path, L"SOFTWARE\\Microsoft\\Wbem", 23) == 0 ||
			_wcsnicmp(path, L"Software\\Microsoft\\Wbem", 23) == 0) {
			const WCHAR next = path[23];
			// 边界：`Wbem` 之后必须是 `\` 或结尾（避免 `WbemX` 误命中）。
			if (next == L'\0' || next == L'\\') {
				return false;
			}
		}

		// 其余 → 值得给用户一个放行的机会。
		return true;
	}
}
