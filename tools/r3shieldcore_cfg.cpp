//
// r3shieldcore_cfg.cpp —— R3 ShieldCore 独立「配置编辑 + 日志观察」工具。
//
// ============================================================================
//  为什么要有这个程序
// ============================================================================
//  引擎自己的 GUI 里虽然有「配置」页和「事件日志」页，但两件事都做不到：
//    ① 配置页是**只读展示**（只把日志路径/几个开关印出来看一眼），
//       想改任何一项都得手动去编辑 r3shieldcore.ini 文本文件 ——
//       50 多个键、大段中文说明、还要小心别把编码搞坏；
//    ② 事件日志页长在**引擎进程里**，必须先启动引擎（全局注入）才能看。
//
//  本工具是**独立进程**，不注入、不挂钩、不依赖引擎在跑：
//    · 配置页：把 ini 里的键做成表单（勾选 / 下拉 / 数值 / 多行列表），
//      带类型与范围校验，保存时**逐行改值、其余字节原样保留**
//      （中文注释、空行、示例注释都不动）。
//    · 日志页：实时 tail 事件日志 / 控制台日志 / 服务日志，支持暂停、
//      关键字过滤、只看高危、只看被拦。
//
//  ★ 配置文件路径与引擎一致（见 r3shieldcore_config.cpp 的 ResolveConfigPath）：
//      %ProgramData%\R3 Shield Core\r3shieldcore.ini  （优先，安装版）
//      回退 <本工具 exe 同目录>\r3shieldcore.ini      （绿色包 / 旧安装）
//    ⇒ 本工具改的就是**引擎真正在读的那一份**，不会出现"改了不生效"。
//
//  ★ 不要求管理员：v66 起 ProgramData 下那份配置对 Users 可写（铁律 163）。
//    绿色包时配置就在 exe 同目录，也通常可写。写不进去会**明确报错**，不静默。
//
// ============================================================================
//  构建
// ============================================================================
//  见仓库根 build_cfgtool.sh（复用 scripts_env.sh 的工具链探测）。
//  单文件 + 一个 .rc（图标）+ 一个 .manifest（asInvoker / comctl32 / DPI）。
//
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <algorithm>
#include <cwctype>
#include <cwchar>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// ===========================================================================
//  小工具：编码 / 字符串
// ===========================================================================
namespace {

std::string ToLowerA(std::string s) {
	for (char& c : s) { c = static_cast<char>(tolower(static_cast<unsigned char>(c))); }
	return s;
}

bool IsSpaceA(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'; }

std::string TrimA(const std::string& s) {
	size_t a = 0, b = s.size();
	while (a < b && IsSpaceA(s[a])) { ++a; }
	while (b > a && IsSpaceA(s[b - 1])) { --b; }
	return s.substr(a, b - a);
}

std::wstring TrimW(const std::wstring& s) {
	size_t a = 0, b = s.size();
	auto sp = [](wchar_t c) { return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n'; };
	while (a < b && sp(s[a])) { ++a; }
	while (b > a && sp(s[b - 1])) { --b; }
	return s.substr(a, b - a);
}

std::wstring U82W(const std::string& s) {
	if (s.empty()) { return std::wstring(); }
	int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
	if (n <= 0) { return std::wstring(); }
	std::wstring w(static_cast<size_t>(n), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
	return w;
}

std::string W2U8(const std::wstring& w) {
	if (w.empty()) { return std::string(); }
	int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
	if (n <= 0) { return std::string(); }
	std::string s(static_cast<size_t>(n), '\0');
	WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
	return s;
}

bool IContainsW(const std::wstring& hay, const std::wstring& needle) {
	if (needle.empty()) { return true; }
	auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
		[](wchar_t a, wchar_t b) { return towlower(a) == towlower(b); });
	return it != hay.end();
}

bool IsTrueA(const std::string& value) {
	const std::string v = ToLowerA(TrimA(value));
	return v == "1" || v == "true" || v == "yes" || v == "on";
}

std::wstring ExeDir() {
	WCHAR buf[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, buf, _countof(buf));
	std::wstring p(buf);
	const size_t slash = p.find_last_of(L"\\/");
	return (slash == std::wstring::npos) ? std::wstring() : p.substr(0, slash);
}

std::wstring DirOf(const std::wstring& filePath) {
	const size_t slash = filePath.find_last_of(L"\\/");
	return (slash == std::wstring::npos) ? std::wstring() : filePath.substr(0, slash);
}

std::wstring FileNameOf(const std::wstring& filePath) {
	const size_t slash = filePath.find_last_of(L"\\/");
	return (slash == std::wstring::npos) ? filePath : filePath.substr(slash + 1);
}

bool FileExistsW(const std::wstring& p) {
	const DWORD a = GetFileAttributesW(p.c_str());
	return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// 配置文件路径：与引擎 ResolveConfigPath 同一套判据（"那个文件在不在"，不是目录）。
std::wstring ResolveConfigPath() {
	WCHAR pd[MAX_PATH] = {};
	const DWORD len = GetEnvironmentVariableW(L"ProgramData", pd, _countof(pd));
	if (len > 0 && len < _countof(pd)) {
		std::wstring cand = std::wstring(pd) + L"\\R3 Shield Core\\r3shieldcore.ini";
		if (FileExistsW(cand)) { return cand; }
	}
	return ExeDir() + L"\\r3shieldcore.ini";
}

}  // namespace

// ===========================================================================
//  配置模型：键表
// ===========================================================================
namespace {

enum class Kind { Bool, Enum, Number, Text, List };

struct KeyDef {
	const wchar_t* key;
	const wchar_t* label;
	Kind kind;
	const wchar_t* def;              // 默认值（ini 里没有该键时显示它）
	const wchar_t* const* opts;      // Enum：取值（以 nullptr 结尾）
	const wchar_t* const* optLabels; // Enum：显示名（可与 opts 不同；nullptr = 用 opts）
	int lo;                          // Number：下限
	int hi;                          // Number：上限
	const wchar_t* hint;             // 灰色说明
};

struct Section {
	const wchar_t* title;
	const KeyDef* keys;
	int count;
};

// ---- 枚举取值 ----
const wchar_t* kOptMode[] = { L"log", L"block", L"ask", L"block_all", L"block_all_safe", nullptr };
const wchar_t* kLblMode[] = {
	L"log —— 只记录",
	L"block —— 主动防御（只拦高危）",
	L"ask —— 拦截 + 弹窗询问",
	L"block_all —— 全拦·不弹窗",
	L"block_all_safe —— 全拦·放行可信进程",
	nullptr
};
const wchar_t* kOptVerdict[] = { L"deny", L"allow", nullptr };
const wchar_t* kLblVerdict[] = { L"deny —— 超时/不理会时拒绝", L"allow —— 超时/不理会时放行", nullptr };
const wchar_t* kOptLevel[] = { L"0", L"1", L"2", nullptr };
const wchar_t* kLblOverlay[] = { L"0 —— 关闭", L"1 —— 开·不问直接执行", L"2 —— 开·每级弹窗询问", nullptr };
const wchar_t* kLblAlert[] = { L"0 —— 关闭", L"1 —— 仅记录", L"2 —— 记录 + 界面提示", nullptr };

// ---- 各分组 ----
const KeyDef kSecMode[] = {
	{ L"mode", L"运行模式", Kind::Enum, L"log", kOptMode, kLblMode, 0, 0,
	  L"决定「记」还是「拦」。改完保存后需重启引擎生效。" },
	{ L"prompt_timeout", L"弹窗超时(秒)", Kind::Number, L"30", nullptr, nullptr, 1, 600,
	  L"只对 ask 模式有效：弹窗等多少秒算超时。" },
	{ L"prompt_default", L"超时兜底", Kind::Enum, L"deny", kOptVerdict, kLblVerdict, 0, 0,
	  L"只对 ask 模式有效：超时 / 不理会时怎么办（block_all 恒拒，不看它）。" },
};

const KeyDef kSecMaster[] = {
	{ L"high_risk", L"内置高危规则表", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"建议保持开启。" },
	{ L"self_protect", L"引擎自我保护", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"挡别人杀引擎 / 挂引擎。建议保持开启。" },
};

const KeyDef kSecPersist[] = {
	{ L"persist_stats", L"统计跨重启保留", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"退出时把累计计数落到 r3shieldcore-stats.json，下次启动读回。只统计数字，不含事件内容。" },
	{ L"replay_history_log", L"启动回放历史日志", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"启动时读事件日志尾部，预填进界面列表（带 [史] 前缀）。只影响显示，不影响判定。" },
	{ L"replay_history_limit", L"回放条数上限", Kind::Number, L"200", nullptr, nullptr, 1, 5000,
	  L"范围 1..5000（ini 注释写的是 2000，解析器实际接受到 5000）。" },
};

const KeyDef kSecInject[] = {
	{ L"inject_shell_thin", L"瘦注入 shell/服务宿主", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"把 explorer.exe / svchost.exe 也注进去，但只装 CreateProcessInternalW 一个 hook。"
	  L"让「双击启动 / UAC 提权启动」的子进程能走同步路（盲区≈0）。关掉 = 逃生门。" },
	{ L"inject_interval_ms", L"注入扫描间隔(ms)", Kind::Number, L"10", nullptr, nullptr, 1, 1000,
	  L"= 未受保护的时间窗（盲区）。范围 1..1000。调大省 CPU 但盲区变大。" },
};

const KeyDef kSecReg[] = {
	{ L"hook_reads", L"记录注册表读", Kind::Bool, L"0", nullptr, nullptr, 0, 0, L"噪音极大，默认关。" },
	{ L"log_all_open", L"NtOpenKey 全记录", Kind::Bool, L"0", nullptr, nullptr, 0, 0, L"不管读写意图都记录。" },
	{ L"hook_hive", L"hive 级操作", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"加载 / 保存 / 替换整棵子树。" },
	{ L"hook_set_info", L"NtSetInformationKey", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"改键属性（时间戳伪造 / WOW64 重定向）。" },
};

const KeyDef kSecFile[] = {
	{ L"hook_file", L"文件操作", Kind::Bool, L"0", nullptr, nullptr, 0, 0,
	  L"建/写/删/改名/截断/改ACL。比注册表热得多，默认关（噪音大）。" },
	{ L"hook_raw_disk", L"裸盘 / 引导区写入", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"写 \\\\.\\PhysicalDrive0 等 = 改引导区（bootkit）。独立于「文件操作」，默认拦。" },
};

const KeyDef kSecProc[] = {
	{ L"hook_process", L"进程创建 / 终止", Kind::Bool, L"1", nullptr, nullptr, 0, 0, nullptr },
	{ L"hook_thread", L"跨进程远程线程", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"只报跨进程的（= 注入）。" },
	{ L"hook_self_thread", L"本进程内建线程", Kind::Bool, L"0", nullptr, nullptr, 0, 0, L"极高频，默认关。" },
	{ L"hook_terminate_contain", L"终止收敛", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"只许退自己/后代/同镜像；杀别人 = 高危。" },
	{ L"hook_memory_op", L"跨进程内存操作", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"Alloc / Write / Protect（代码注入链）。" },
};

const KeyDef kSecDriver[] = {
	{ L"hook_driver", L"驱动加载 / 卸载", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"NtLoadDriver + SCM 服务 API。" },
	{ L"hook_service_config", L"服务/安全对象权限变更", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"sc sdset 提权。" },
};

const KeyDef kSecNet[] = {
	{ L"hook_net", L"网络连接 / 发送", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"ws2_32 连接 / 发送 / 绑定 / 监听 / 接受。" },
	{ L"hook_dns", L"DNS 查询", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"只记录，永不判高危。" },
	{ L"hook_net_all", L"含 bind/listen/accept", Kind::Bool, L"0", nullptr, nullptr, 0, 0, L"服务端程序极高频，默认关。" },
};

const KeyDef kSecPrivacy[] = {
	{ L"hook_camera", L"摄像头 / 麦克风", Kind::Bool, L"1", nullptr, nullptr, 0, 0, nullptr },
	{ L"hook_input", L"输入钩子", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"SetWindowsHookEx / RawInput。" },
	{ L"hook_screen", L"截屏", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"BitBlt / PrintWindow。" },
	{ L"hook_audio", L"音频采集", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"环回 / 麦克风。" },
	{ L"hook_clipboard", L"剪贴板读取", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"Open 只记录，取走数据才高危。" },
	{ L"hook_input_inject", L"合成输入 / 锁屏勒索", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"SendInput / BlockInput / ClipCursor。" },
};

const KeyDef kSecPersist2[] = {
	{ L"hook_dll_load", L"DLL 加载劫持", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"LdrLoadDll / 手工映射 / 侧加载。" },
	{ L"hook_spawn", L"进程创建旁路", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"WinExec / ShellExecute / 令牌。" },
	{ L"hook_com_hijack", L"COM/OLE 激活劫持", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"CLSID -> 用户可写 DLL。" },
	{ L"hook_scheduled_task", L"计划任务持久化", Kind::Bool, L"1", nullptr, nullptr, 0, 0, nullptr },
	{ L"hook_token_theft", L"令牌窃取 / 冒充", Kind::Bool, L"1", nullptr, nullptr, 0, 0, nullptr },
	{ L"hook_wmi_subscription", L"WMI 事件订阅持久化", Kind::Bool, L"1", nullptr, nullptr, 0, 0, nullptr },
	{ L"hook_host_hijack", L"宿主劫持 / 加载器", Kind::Bool, L"1", nullptr, nullptr, 0, 0, L"注入键 + 远程映射 + APC。" },
};

const KeyDef kSecOverlay[] = {
	{ L"neutralize_overlay", L"反制覆盖层级别", Kind::Enum, L"2", kOptLevel, kLblOverlay, 0, 0,
	  L"反制全屏+置顶覆盖层（锁屏勒索 / 假 UAC）。级别 1 会直接结束目标进程，默认取 2（询问）。" },
};

const KeyDef kSecHighRisk[] = {
	{ L"high_risk_process_alert", L"高危进程提示级别", Kind::Enum, L"2", kOptLevel, kLblAlert, 0, 0,
	  L"定期快照全机进程判高危，只「告知」不「拦截」。" },
	{ L"high_risk_process_scan_ms", L"扫描间隔(ms)", Kind::Number, L"1000", nullptr, nullptr, 200, 60000,
	  L"范围 200..60000。比注入轮询慢两个数量级是刻意的（本功能是告知，不是拦）。" },
};

const KeyDef kSecArk[] = {
	{ L"ark_enabled", L"启用 ARK 页", Kind::Bool, L"1", nullptr, nullptr, 0, 0,
	  L"只定期枚举进程列表，不做任何主动行为。动作只由用户点击触发。" },
	{ L"ark_scan_ms", L"枚举间隔(ms)", Kind::Number, L"2000", nullptr, nullptr, 500, 60000,
	  L"引擎多久重新枚举一次全机进程（数据新鲜度）。范围 500..60000。" },
	{ L"ark_refresh_ms", L"界面刷新间隔(ms)", Kind::Number, L"1000", nullptr, nullptr, 200, 60000,
	  L"界面多久重取 + 重绘一次（显示新鲜度）。与枚举间隔是两件事。范围 200..60000。" },
};

const KeyDef kSecWhite[] = {
	{ L"exclude", L"排除目录（注册表判据白名单）", Kind::List, L"", nullptr, nullptr, 0, 0,
	  L"每行一条，前缀匹配、大小写不敏感。只作用于注册表判据；不会让进程不被注入。" },
	{ L"never_inject", L"绝不注入名单", Kind::List, L"", nullptr, nullptr, 0, 0,
	  L"每行一条完整路径（目录要带结尾 \\）。列进来的进程一个 hook 都不装 —— 它自己不受监控，"
	  L"且其子进程失去同步注入路。" },
};

const KeyDef kSecProtectA[] = {
	{ L"protect_reg", L"自定义保护：注册表", Kind::List, L"", nullptr, nullptr, 0, 0,
	  L"每行一条。相对写法（SOFTWARE\\X）与完整写法等价；命中即视为高危。" },
	{ L"protect_file", L"自定义保护：文件", Kind::List, L"", nullptr, nullptr, 0, 0, L"每行一条前缀。" },
};

const KeyDef kSecProtectB[] = {
	{ L"protect_net", L"自定义保护：网络", Kind::List, L"", nullptr, nullptr, 0, 0, L"每行一条。" },
	{ L"protect_process", L"自定义保护：进程", Kind::List, L"", nullptr, nullptr, 0, 0, L"每行一条。" },
	{ L"protect_driver", L"自定义保护：驱动", Kind::List, L"", nullptr, nullptr, 0, 0, L"每行一条。" },
};

const KeyDef kSecLog[] = {
	{ L"log", L"事件日志路径", Kind::Text, L"r3shieldcore-events.log", nullptr, nullptr, 0, 0,
	  L"相对路径按**引擎 exe 同目录**解析；也可写绝对路径。" },
};

const Section kSections[] = {
	{ L"模式与询问", kSecMode, _countof(kSecMode) },
	{ L"总开关", kSecMaster, _countof(kSecMaster) },
	{ L"跨重启保留", kSecPersist, _countof(kSecPersist) },
	{ L"注入与盲区", kSecInject, _countof(kSecInject) },
	{ L"注册表", kSecReg, _countof(kSecReg) },
	{ L"文件", kSecFile, _countof(kSecFile) },
	{ L"进程 / 线程 / 内存", kSecProc, _countof(kSecProc) },
	{ L"驱动 / 服务", kSecDriver, _countof(kSecDriver) },
	{ L"网络", kSecNet, _countof(kSecNet) },
	{ L"隐私采集", kSecPrivacy, _countof(kSecPrivacy) },
	{ L"持久化 / 劫持", kSecPersist2, _countof(kSecPersist2) },
	{ L"窗口反制", kSecOverlay, _countof(kSecOverlay) },
	{ L"高危进程提示", kSecHighRisk, _countof(kSecHighRisk) },
	{ L"ARK 进程视图", kSecArk, _countof(kSecArk) },
	{ L"排除与白名单", kSecWhite, _countof(kSecWhite) },
	{ L"自定义保护 · 注册表/文件", kSecProtectA, _countof(kSecProtectA) },
	{ L"自定义保护 · 网络/进程/驱动", kSecProtectB, _countof(kSecProtectB) },
	{ L"日志", kSecLog, _countof(kSecLog) },
};
const int kSectionCount = _countof(kSections);

// 全部键的集合（保存时只认这些键，避免误改 ini 里的其它内容）。
const KeyDef* FindKey(const std::string& key) {
	for (int s = 0; s < kSectionCount; ++s) {
		for (int i = 0; i < kSections[s].count; ++i) {
			if (key == W2U8(kSections[s].keys[i].key)) { return &kSections[s].keys[i]; }
		}
	}
	return nullptr;
}

int EnumOptionCount(const KeyDef& k) {
	int n = 0;
	while (k.opts && k.opts[n]) { ++n; }
	return n;
}

const wchar_t* EnumOptionLabel(const KeyDef& k, int i) {
	if (k.optLabels && k.optLabels[i]) { return k.optLabels[i]; }
	return k.opts[i];
}

// 把 ini 里的值（可能是别名）映射到下拉框序号。
int EnumIndexFromValue(const KeyDef& k, const std::string& raw) {
	const std::string v = ToLowerA(TrimA(raw));
	const std::wstring key(k.key);

	if (key == L"mode") {
		if (v == "log") { return 0; }
		if (v == "block") { return 1; }
		if (v == "ask") { return 2; }
		if (v == "block_all" || v == "blockall" || v == "block-all") { return 3; }
		if (v == "block_all_safe" || v == "blockallsafe" || v == "block-all-safe"
			|| v == "block_safe" || v == "blocksafe") { return 4; }
		return 0;
	}
	if (key == L"prompt_default") {
		return (v == "allow") ? 1 : 0;
	}
	if (key == L"neutralize_overlay" || key == L"high_risk_process_alert") {
		if (v == "0" || v == "false" || v == "no" || v == "off") { return 0; }
		if (v == "1" || v == "true" || v == "yes" || v == "on") { return 1; }
		if (v == "2") { return 2; }
		return (key == L"neutralize_overlay") ? 2 : 2;  // 认不出 -> 默认档（询问 / 提示）
	}
	for (int i = 0; i < EnumOptionCount(k); ++i) {
		if (v == ToLowerA(W2U8(k.opts[i]))) { return i; }
	}
	return 0;
}

std::string EnumValueFromIndex(const KeyDef& k, int i) {
	const int n = EnumOptionCount(k);
	if (i < 0 || i >= n) { i = 0; }
	return W2U8(k.opts[i]);
}

}  // namespace

// ===========================================================================
//  配置文件读写
// ===========================================================================
namespace {

struct ParsedLine {
	bool isAssign = false;
	std::string key;     // 小写
	std::string value;   // 已去空白
	std::string prefix;  // 行首到 '=' 之后（含 '=' 与 '=' 后的空白）
	std::string tail;    // 值后面的空白 + 行内注释
};

// 解析一行（不含 '\n'；可能有结尾 '\r'，调用方先剥掉）。
ParsedLine ParseLine(const std::string& core) {
	ParsedLine out;
	size_t p = 0;
	while (p < core.size() && (core[p] == ' ' || core[p] == '\t')) { ++p; }
	if (p < core.size() && (core[p] == '#' || core[p] == ';')) { return out; }  // 整行注释
	const size_t eq = core.find('=', p);
	if (eq == std::string::npos) { return out; }

	std::string k = ToLowerA(TrimA(core.substr(p, eq - p)));
	if (k.empty()) { return out; }
	for (char c : k) {
		if (!(isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.')) { return out; }
	}

	const std::string rest = core.substr(eq + 1);
	size_t c = rest.find_first_of("#;");
	const std::string valPart = (c == std::string::npos) ? rest : rest.substr(0, c);
	const std::string tailPart = (c == std::string::npos) ? std::string() : rest.substr(c);

	size_t a = 0, b = valPart.size();
	while (a < b && IsSpaceA(valPart[a])) { ++a; }
	while (b > a && IsSpaceA(valPart[b - 1])) { --b; }

	out.isAssign = true;
	out.key = k;
	out.value = valPart.substr(a, b - a);
	out.prefix = core.substr(0, eq + 1) + valPart.substr(0, a);
	out.tail = valPart.substr(b) + tailPart;
	return out;
}

struct ConfigFile {
	std::wstring path;
	bool exists = false;
	bool hasBom = false;
	std::string eol = "\r\n";
	std::vector<std::string> lines;              // 不含 '\n'，可能以 '\r' 结尾
	std::map<std::string, int> firstActive;      // key -> 第一条生效行

	bool Load(const std::wstring& p) {
		path = p;
		exists = false;
		hasBom = false;
		lines.clear();
		firstActive.clear();

		HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) { return false; }

		std::string raw;
		char buf[65536];
		DWORD got = 0;
		while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) {
			raw.append(buf, got);
		}
		CloseHandle(h);

		if (raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF
			&& static_cast<unsigned char>(raw[1]) == 0xBB
			&& static_cast<unsigned char>(raw[2]) == 0xBF) {
			hasBom = true;
			raw.erase(0, 3);
		}

		eol = (raw.find("\r\n") != std::string::npos) ? "\r\n" : "\n";

		size_t start = 0;
		for (size_t i = 0; i < raw.size(); ++i) {
			if (raw[i] == '\n') {
				lines.push_back(raw.substr(start, i - start));
				start = i + 1;
			}
		}
		lines.push_back(raw.substr(start));

		RebuildIndex();
		exists = true;
		return true;
	}

	void RebuildIndex() {
		firstActive.clear();
		for (size_t i = 0; i < lines.size(); ++i) {
			const std::string core = StripCr(lines[i]);
			const ParsedLine pl = ParseLine(core);
			if (!pl.isAssign) { continue; }
			if (!FindKey(pl.key)) { continue; }
			if (firstActive.find(pl.key) == firstActive.end()) {
				firstActive[pl.key] = static_cast<int>(i);
			}
		}
	}

	static std::string StripCr(const std::string& s) {
		if (!s.empty() && s.back() == '\r') { return s.substr(0, s.size() - 1); }
		return s;
	}

	std::string GetScalar(const std::string& key, const std::string& def) const {
		auto it = firstActive.find(key);
		if (it == firstActive.end()) { return def; }
		const ParsedLine pl = ParseLine(StripCr(lines[it->second]));
		return pl.isAssign ? pl.value : def;
	}

	std::vector<std::string> GetList(const std::string& key) const {
		std::vector<std::string> out;
		for (const std::string& line : lines) {
			const ParsedLine pl = ParseLine(StripCr(line));
			if (pl.isAssign && pl.key == key && !pl.value.empty()) { out.push_back(pl.value); }
		}
		return out;
	}

	// 逐行改值：标量键改第一条生效行；列表键重排为连续若干行。
	// 其余字节（中文注释、空行、示例注释）原样保留。
	std::string BuildNewContent(const std::map<std::string, std::string>& scalars,
		const std::map<std::string, std::vector<std::string>>& lists) const {
		std::vector<std::string> out;
		std::set<std::string> scalarDone, listDone;

		for (size_t i = 0; i < lines.size(); ++i) {
			const std::string rawLine = lines[i];
			const bool hadCr = (!rawLine.empty() && rawLine.back() == '\r');
			const std::string core = StripCr(rawLine);
			const std::string cr = hadCr ? "\r" : "";
			const ParsedLine pl = ParseLine(core);

			if (!pl.isAssign) { out.push_back(rawLine); continue; }

			auto ls = lists.find(pl.key);
			if (ls != lists.end()) {
				if (listDone.count(pl.key)) { continue; }  // 已写过块，多余的行删掉
				listDone.insert(pl.key);
				for (const std::string& v : ls->second) {
					out.push_back(pl.key + "=" + v + cr);
				}
				continue;
			}

			auto sc = scalars.find(pl.key);
			if (sc != scalars.end()) {
				if (scalarDone.count(pl.key)) { out.push_back(rawLine); continue; }
				scalarDone.insert(pl.key);
				out.push_back(pl.prefix + sc->second + pl.tail + cr);
				continue;
			}

			out.push_back(rawLine);
		}

		// 文件里原本没有的标量键：追加到末尾。
		for (const auto& kv : scalars) {
			if (scalarDone.count(kv.first)) { continue; }
			if (!out.empty() && !out.back().empty() && out.back().back() != '\r') {
				// 末行没有换行 -> 先补一个换行，避免拼接粘连
				out.push_back(std::string());
			}
			out.push_back(kv.first + "=" + kv.second);
		}

		std::string joined;
		for (size_t i = 0; i < out.size(); ++i) {
			if (i) { joined += "\n"; }
			joined += out[i];
		}
		if (hasBom) { joined.insert(0, "\xEF\xBB\xBF"); }
		return joined;
	}

	// 原子写：先写 .tmp，再替换原文件（尽量保留原文件 ACL）。
	bool SaveContent(const std::string& content, std::wstring& err) const {
		const std::wstring tmp = path + L".r3cfg.tmp";
		HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h == INVALID_HANDLE_VALUE) {
			WCHAR m[256] = {};
			swprintf_s(m, L"无法创建临时文件（错误 %u）：\n%s", GetLastError(), tmp.c_str());
			err = m;
			return false;
		}
		const char* p = content.data();
		size_t left = content.size();
		while (left > 0) {
			DWORD wrote = 0;
			const DWORD chunk = static_cast<DWORD>(left > 0x40000000 ? 0x40000000 : left);
			if (!WriteFile(h, p, chunk, &wrote, nullptr) || wrote == 0) {
				WCHAR m[256] = {};
				swprintf_s(m, L"写入临时文件失败（错误 %u）", GetLastError());
				err = m;
				CloseHandle(h);
				DeleteFileW(tmp.c_str());
				return false;
			}
			p += wrote;
			left -= wrote;
		}
		CloseHandle(h);

		if (FileExistsW(path)) {
			if (ReplaceFileW(path.c_str(), tmp.c_str(), nullptr, REPLACEFILE_WRITE_THROUGH,
				nullptr, nullptr)) {
				return true;
			}
		}
		if (MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
			return true;
		}
		const DWORD e = GetLastError();
		WCHAR m[320] = {};
		swprintf_s(m, L"替换配置文件失败（错误 %u）。\n"
			L"若配置在 Program Files 下，普通用户改不了 —— 安装版请改 ProgramData 那份。", e);
		err = m;
		DeleteFileW(tmp.c_str());
		return false;
	}
};

}  // namespace

// ===========================================================================
//  UI
// ===========================================================================
namespace {

HINSTANCE g_inst = nullptr;
HWND g_main = nullptr;

const int IDC_TABAREA = 1;
enum {
	IDC_SECLIST = 1000,
	IDC_CFGPATH,
	IDC_RELOAD,
	IDC_SAVE,
	IDC_OPENCFGDIR,
	IDC_CFGNOTE,
	IDC_LOGCOMBO,
	IDC_LOGBROWSE,
	IDC_OPENLOGDIR,
	IDC_PAUSE,
	IDC_CLEAR,
	IDC_AUTOSCROLL,
	IDC_ONLYHIGH,
	IDC_ONLYBLOCK,
	IDC_FILTERLABEL,
	IDC_FILTER,
	IDC_LOGLIST,
	IDC_LOGSTATUS,
	IDC_FIELD_BASE = 3000,
};

// ---------------------------------------------------------------------------
// 视觉样式 —— 与引擎主窗口逐字一致
//
// ★★ 下面这组配色/字体/布局常量是**从**
//      R3ShieldCore/R3ShieldCore/r3shieldcore_gui.cpp
//    抄过来的（ColorBackground / ColorHeaderBackground / ColorBorder /
//    ColorTextPrimary / ColorTextSecondary / ColorAccent / ColorTab* /
//    Padding / TabBarTop / TabBarHeight / TabWidth / CreateFont 参数）。
//    两边的常量必须**一起改** —— 分叉一次就再也对不上了（铁律 127：
//    同一份「名字清单」拷贝多份 ⇒ 必漂）。
// ---------------------------------------------------------------------------
const COLORREF kBg              = RGB(250, 250, 250);  // ColorBackground
const COLORREF kHeaderBg        = RGB(255, 255, 255);  // ColorHeaderBackground
const COLORREF kBorder          = RGB(226, 226, 226);  // ColorBorder
const COLORREF kTextPrimary     = RGB(24, 24, 24);     // ColorTextPrimary
const COLORREF kTextSecondary   = RGB(110, 110, 110);  // ColorTextSecondary
const COLORREF kAccent          = RGB(0, 120, 215);    // ColorAccent
const COLORREF kBlocked         = RGB(209, 52, 56);    // ColorBlocked
const COLORREF kWouldBlock      = RGB(230, 126, 34);   // ColorWouldBlock
const COLORREF kTrack           = RGB(232, 232, 232);  // ColorTrack
const COLORREF kTabActiveBg     = RGB(0, 120, 215);    // ColorTabActiveBg
const COLORREF kTabActiveText   = RGB(255, 255, 255);  // ColorTabActiveText
const COLORREF kTabInactiveText = RGB(90, 90, 90);     // ColorTabInactiveText
const COLORREF kTabHoverBg      = RGB(233, 242, 252);  // ColorTabHoverBg
const COLORREF kTabHoverBorder  = RGB(178, 210, 240);  // ColorTabHoverBorder
const COLORREF kLogRowAlt       = RGB(246, 246, 246);  // ColorLogRowAlt
const COLORREF kHighRisk        = RGB(190, 30, 120);   // ColorHighRisk
const COLORREF kWarn            = RGB(230, 126, 34);
// 主窗口 DrawConfigRow 里那个"已启用"绿点用的就是这一对。
const COLORREF kOkDot           = RGB(34, 160, 96);
const COLORREF kOkText          = RGB(34, 140, 86);

// 布局（与主窗口一致）
const int kPadding    = 20;   // Padding
const int kHeaderH    = 62;   // 标题区高度（分隔线画在 y=61）
const int kTabBarTop  = 62;   // TabBarTop
const int kTabBarH    = 38;   // TabBarHeight
const int kTabWidth   = 84;   // TabWidth
const int kTabGap     = 8;
const int kTabCount   = 2;    // 配置 / 日志
const int kContentTop = kTabBarTop + kTabBarH + 1;   // 101：内容区起点
const int kRowH       = 30;   // 按钮 / 复选框行高（主窗口动作按钮同档）

HFONT g_fontTitle = nullptr;  // -17 FW_SEMIBOLD  标题
HFONT g_fontUI    = nullptr;  // -13 FW_NORMAL    正文
HFONT g_fontBold  = nullptr;  // -13 FW_SEMIBOLD  面板小标题/加粗
HFONT g_fontMono  = nullptr;  // -12 Consolas     日志行
HFONT g_fontHint  = nullptr;  // = g_fontUI       说明文字（颜色变灰）
HFONT g_fontTab   = nullptr;  // -14 FW_SEMIBOLD  页签

ConfigFile g_cfg;
int g_page = 0;  // 0 = 配置，1 = 日志
int g_section = 0;
int g_startPage = 0;     // --page 启动参数
int g_startSection = 0;  // --section 启动参数

struct FieldSlot {
	HWND label = nullptr;
	HWND ctl = nullptr;
	HWND hint = nullptr;
	int keyIdx = -1;
	int rowY = 0;
	Kind kind = Kind::Bool;
};
std::vector<FieldSlot> g_fields;

// 跨分组累计的"待保存改动"（只记录与文件里不同的键）。
std::map<std::string, std::string> g_pendingScalars;
std::map<std::string, std::vector<std::string>> g_pendingLists;

// 配置页控件
HWND g_hSecList = nullptr, g_hCfgPath = nullptr, g_hReload = nullptr;
HWND g_hSave = nullptr, g_hOpenCfgDir = nullptr, g_hCfgNote = nullptr;
HWND g_hCfgLabel = nullptr;   // "配置文件:" —— ★ 必须是全局并纳入 LayoutAll

// 日志页控件
HWND g_hLogCombo = nullptr, g_hLogBrowse = nullptr, g_hOpenLogDir = nullptr;
HWND g_hLogLabel = nullptr;   // "日志文件:" —— 同上
HWND g_hPause = nullptr, g_hClear = nullptr, g_hAutoScroll = nullptr;
HWND g_hOnlyHigh = nullptr, g_hOnlyBlock = nullptr, g_hFilterLabel = nullptr, g_hFilter = nullptr;
HWND g_hLogList = nullptr, g_hLogStatus = nullptr;

// 日志 tail 状态
struct LogState {
	std::wstring path;
	HANDLE h = INVALID_HANDLE_VALUE;
	ULONGLONG offset = 0;
	std::string pending;
	bool bomChecked = false;
	bool paused = false;
	bool autoScroll = true;
	std::deque<std::wstring> all;
	int maxWidth = 0;
	std::wstring status;
	bool followRequested = false;
} g_log;

// ---------------------------------------------------------------------------
// 自绘控件的交互状态
//
// 主窗口是**全自绘**（一个子控件都没有），所以它有全局的 hover/pressed。
// 本工具还要用原生 EDIT / COMBOBOX（自绘文本输入框成本太高、风险也大），
// 于是按钮/复选框走 BS_OWNERDRAW + 一张按 HWND 索引的小表来存三态。
// ---------------------------------------------------------------------------
void SetFontAll(HWND h, HFONT f);   // 定义在后面（字体创建之后）

// 按钮三态（画法见 ButtonColors / DrawActionButton）。
enum class BtnState { Normal, Hover, Pressed };

std::map<HWND, bool> g_btnHover;    // 鼠标悬停中
std::map<HWND, bool> g_btnPressed;  // 左键按住（BS_OWNERDRAW 同时会给 ODS_SELECTED，双保险）
std::map<HWND, bool> g_checkState;  // 复选框勾选值（BS_OWNERDRAW 不会自动切换，必须自管）
std::map<HWND, bool> g_ctlFocused;  // 有焦点（画焦点描边）
// 位于**白色面板**上的控件（字段标签 / 提示 / 字段复选框）。
// WM_CTLCOLORSTATIC / WM_CTLCOLORBTN / 自绘复选框都要按它选底色 ——
// 面板是白的、工具条是灰的，选错就会在面板上留一块灰（铁律 99）。
std::set<HWND> g_panelText;
std::set<HWND> g_hintText;   // 字段的灰色说明文字（次级色，与主窗口一致）

BtnState StateOf(HWND h) {
	if (g_btnPressed.count(h) && g_btnPressed[h]) { return BtnState::Pressed; }
	if (g_btnHover.count(h) && g_btnHover[h]) { return BtnState::Hover; }
	return BtnState::Normal;
}

bool CheckOf(HWND h) {
	auto it = g_checkState.find(h);
	return it != g_checkState.end() && it->second;
}

// 子类化：只为按钮/复选框补上"悬停 + 按下 + 焦点"这三件原生控件不告诉父窗口的事。
LRESULT CALLBACK CtlSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp,
	UINT_PTR /*id*/, DWORD_PTR /*ref*/) {
	switch (msg) {
	case WM_MOUSEMOVE:
		if (!(g_btnHover.count(h) && g_btnHover[h])) {
			g_btnHover[h] = true;
			TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, h, 0 };
			TrackMouseEvent(&tme);
			InvalidateRect(h, nullptr, FALSE);
		}
		break;
	case WM_MOUSELEAVE:
		g_btnHover[h] = false;
		g_btnPressed[h] = false;
		InvalidateRect(h, nullptr, FALSE);
		break;
	case WM_LBUTTONDOWN:
		g_btnPressed[h] = true;
		InvalidateRect(h, nullptr, FALSE);
		break;
	case WM_LBUTTONUP:
		g_btnPressed[h] = false;
		InvalidateRect(h, nullptr, FALSE);
		break;
	case WM_SETFOCUS:
	case WM_KILLFOCUS:
		g_ctlFocused[h] = (msg == WM_SETFOCUS);
		InvalidateRect(h, nullptr, FALSE);
		break;
	case WM_NCDESTROY:
		g_btnHover.erase(h);
		g_btnPressed.erase(h);
		g_checkState.erase(h);
		g_ctlFocused.erase(h);
		g_panelText.erase(h);
		RemoveWindowSubclass(h, CtlSubclass, 0);
		break;
	default:
		break;
	}
	return DefSubclassProc(h, msg, wp, lp);
}

// 建一个自绘按钮。
HWND MakeButton(HWND parent, int id, PCWSTR text, int x, int y, int w, int h) {
	HWND b = CreateWindowExW(0, L"BUTTON", text,
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
		x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_inst, nullptr);
	if (b) {
		SetFontAll(b, g_fontUI);
		SetWindowSubclass(b, CtlSubclass, 0, 0);
	}
	return b;
}

// 建一个自绘复选框（勾选值由 g_checkState 自管）。
HWND MakeCheckBox(HWND parent, int id, PCWSTR text, int x, int y, int w, int h) {
	HWND c = CreateWindowExW(0, L"BUTTON", text,
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
		x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_inst, nullptr);
	if (c) {
		SetFontAll(c, g_fontUI);
		SetWindowSubclass(c, CtlSubclass, 0, 0);
		g_checkState[c] = false;
	}
	return c;
}

void SetFontAll(HWND h, HFONT f) {
	SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(f), TRUE);
}

// 与主窗口一样的建字体方式：高度直接用**负像素**（不走 pt 换算），
// 这样两边的字号严格一致（主窗口用的是 CreateFont(-17, ...) 这类写法）。
HFONT MakeFontPx(int px, int weight, const wchar_t* face, BYTE pitchAndFamily) {
	LOGFONTW lf = {};
	lf.lfHeight = px;
	lf.lfWeight = weight;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = CLEARTYPE_QUALITY;
	lf.lfPitchAndFamily = pitchAndFamily;
	wcsncpy_s(lf.lfFaceName, face, _TRUNCATE);
	return CreateFontIndirectW(&lf);
}

void CreateUiFonts() {
	g_fontTitle = MakeFontPx(-17, FW_SEMIBOLD, L"Microsoft YaHei UI", DEFAULT_PITCH | FF_DONTCARE);
	g_fontUI    = MakeFontPx(-13, FW_NORMAL,   L"Microsoft YaHei UI", DEFAULT_PITCH | FF_DONTCARE);
	g_fontBold  = MakeFontPx(-13, FW_SEMIBOLD, L"Microsoft YaHei UI", DEFAULT_PITCH | FF_DONTCARE);
	g_fontHint  = g_fontUI;
	g_fontTab   = MakeFontPx(-14, FW_SEMIBOLD, L"Microsoft YaHei UI", DEFAULT_PITCH | FF_DONTCARE);
	g_fontMono  = MakeFontPx(-12, FW_NORMAL,   L"Consolas", FIXED_PITCH | FF_MODERN);
	if (!g_fontMono) { g_fontMono = MakeFontPx(-12, FW_NORMAL, L"Courier New", FIXED_PITCH | FF_MODERN); }
}

// ---------------------------------------------------------------------------
// 绘制原语 —— 名字与主窗口里的同名函数一致，画法也一致。
// ---------------------------------------------------------------------------

void DrawTextSimple(HDC dc, PCWSTR text, RECT rect, HFONT font, COLORREF color, UINT format) {
	HGDIOBJ oldFont = SelectObject(dc, font);
	SetBkMode(dc, TRANSPARENT);
	SetTextColor(dc, color);
	DrawTextW(dc, text, -1, &rect, format | DT_NOPREFIX);
	SelectObject(dc, oldFont);
}

void FillSolid(HDC dc, const RECT& r, COLORREF c) {
	HBRUSH b = CreateSolidBrush(c);
	FillRect(dc, &r, b);
	DeleteObject(b);
}

// 圆角面板：白底 + 1px 描边 + 左上角标题（与主窗口 DrawPanel 逐字一致）。
void DrawPanel(HDC dc, RECT rect, PCWSTR title, HFONT titleFont, COLORREF titleColor) {
	HBRUSH brush = CreateSolidBrush(kHeaderBg);
	HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
	HGDIOBJ oldBrush = SelectObject(dc, brush);
	HGDIOBJ oldPen = SelectObject(dc, pen);
	RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
	SelectObject(dc, oldBrush);
	SelectObject(dc, oldPen);
	DeleteObject(brush);
	DeleteObject(pen);

	if (title) {
		RECT titleRect = { rect.left + 16, rect.top + 12, rect.right - 16, rect.top + 34 };
		DrawTextSimple(dc, title, titleRect, titleFont, titleColor, DT_LEFT | DT_SINGLELINE);
	}
}

// 按钮三态。
// （枚举定义已上移到交互状态区，这里不再重复声明。）

// 由（是否主按钮 / 是否危险 / 三态）算出背景、描边、文字三色。
// 与主窗口 ButtonColors 同一套层次：Normal 白底中性描边，Hover/Pressed 逐档加深，
// 主按钮恒用强调色描边+文字（浅蓝底），危险按钮恒红。
void ButtonColors(bool primary, bool danger, BtnState state,
	COLORREF* background, COLORREF* border, COLORREF* text) {
	const COLORREF accent = danger ? kBlocked : kAccent;
	switch (state) {
	case BtnState::Pressed:
		*background = primary ? RGB(198, 222, 245)
			: (danger ? RGB(246, 216, 216) : RGB(213, 230, 248));
		break;
	case BtnState::Hover:
		*background = primary ? RGB(222, 236, 250)
			: (danger ? RGB(252, 235, 235) : RGB(233, 242, 252));
		break;
	default:
		*background = primary ? RGB(235, 244, 252) : kHeaderBg;
		break;
	}

	if (primary || danger) {
		*border = accent;
		*text = accent;
	} else if (state == BtnState::Normal) {
		*border = kBorder;
		*text = kTextSecondary;
	} else {
		*border = accent;
		*text = accent;
	}
}

void DrawActionButton(HDC dc, const RECT& rect, PCWSTR text, bool primary,
	bool danger, BtnState state) {
	COLORREF background = kHeaderBg;
	COLORREF border = kBorder;
	COLORREF textColor = kTextSecondary;
	ButtonColors(primary, danger, state, &background, &border, &textColor);

	HBRUSH brush = CreateSolidBrush(background);
	HPEN pen = CreatePen(PS_SOLID, 1, border);
	HGDIOBJ oldBrush = SelectObject(dc, brush);
	HGDIOBJ oldPen = SelectObject(dc, pen);
	RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
	SelectObject(dc, oldBrush);
	SelectObject(dc, oldPen);
	DeleteObject(brush);
	DeleteObject(pen);

	RECT textRect = rect;
	if (state == BtnState::Pressed) { OffsetRect(&textRect, 0, 1); }
	DrawTextSimple(dc, text, textRect, g_fontUI, textColor,
		DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

// 自绘复选框：圆角方块 + 白勾 + 右侧文字（主窗口没有复选框，
// 这里按它的配色与圆角风格新画一个，保证"看起来是一套的"）。
//
// ★ `bg` 必须由调用方给，并且要把整个 rcItem 填满 ——
//   BS_OWNERDRAW 按钮会先用 WM_CTLCOLORBTN 返回的刷子擦一遍背景，
//   而"只画方块和文字"会让剩下那一圈露出按钮默认灰（实测踩到）。
void DrawCheckBox(HDC dc, const RECT& rect, PCWSTR text, bool checked,
	bool hover, bool focused, COLORREF bg) {
	FillSolid(dc, rect, bg);

	const int box = 18;
	const int by = rect.top + (rect.bottom - rect.top - box) / 2;
	RECT b = { rect.left, by, rect.left + box, by + box };

	COLORREF fill = checked ? kAccent : (hover ? kTabHoverBg : kHeaderBg);
	COLORREF bd = checked ? kAccent : (hover ? kTabHoverBorder : kBorder);
	if (focused && !checked) { bd = kAccent; }

	HBRUSH br = CreateSolidBrush(fill);
	HPEN pn = CreatePen(PS_SOLID, 1, bd);
	HGDIOBJ ob = SelectObject(dc, br);
	HGDIOBJ op = SelectObject(dc, pn);
	RoundRect(dc, b.left, b.top, b.right, b.bottom, 5, 5);
	SelectObject(dc, ob);
	SelectObject(dc, op);
	DeleteObject(br);
	DeleteObject(pn);

	if (checked) {
		HPEN cp = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
		HGDIOBJ op2 = SelectObject(dc, cp);
		MoveToEx(dc, b.left + 4, b.top + 9, nullptr);
		LineTo(dc, b.left + 7, b.top + 12);
		LineTo(dc, b.right - 4, b.top + 5);
		SelectObject(dc, op2);
		DeleteObject(cp);
	}

	RECT tr = { b.right + 8, rect.top, rect.right, rect.bottom };
	DrawTextSimple(dc, text, tr, g_fontUI,
		checked ? kTextPrimary : kTextSecondary,
		DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

// ---------- 配置页 ----------

std::wstring CfgPathDisplay() {
	if (g_cfg.path.empty()) { return L"(未找到配置文件)"; }
	std::wstring s = g_cfg.path;
	if (!g_cfg.exists) { s += L"   （文件不存在，保存时会新建）"; }
	return s;
}

void DestroyFields() {
	for (FieldSlot& f : g_fields) {
		if (f.label) { g_panelText.erase(f.label); DestroyWindow(f.label); }
		if (f.ctl) { DestroyWindow(f.ctl); }
		if (f.hint) { g_panelText.erase(f.hint); g_hintText.erase(f.hint); DestroyWindow(f.hint); }
	}
	g_fields.clear();
}

void SetFieldFromConfig(FieldSlot& f, const KeyDef& k) {
	const std::string keyU8 = W2U8(k.key);
	if (k.kind == Kind::List) {
		const std::vector<std::string> vals = g_cfg.GetList(keyU8);
		std::wstring text;
		for (size_t i = 0; i < vals.size(); ++i) {
			if (i) { text += L"\r\n"; }
			text += U82W(vals[i]);
		}
		SetWindowTextW(f.ctl, text.c_str());
		return;
	}
	const std::string raw = g_cfg.GetScalar(keyU8, W2U8(k.def));
	switch (k.kind) {
	case Kind::Bool: {
		const bool on = IsTrueA(raw);
		g_checkState[f.ctl] = on;
		InvalidateRect(f.ctl, nullptr, FALSE);
		break;
	}
	case Kind::Enum: {
		const int idx = EnumIndexFromValue(k, raw);
		SendMessageW(f.ctl, CB_SETCURSEL, idx, 0);
		break;
	}
	default:  // Number / Text
		SetWindowTextW(f.ctl, U82W(raw).c_str());
		break;
	}
}

// ---------------------------------------------------------------------------
// 布局
//
// ★ 所有矩形只在一处算（ComputeLayout），画面板和摆控件都用它 ——
//   分开算必然漂（铁律 127）。
// ---------------------------------------------------------------------------
struct LayoutRects {
	RECT cfgToolbar;    // 配置页工具条（配置文件路径 + 三个按钮）
	RECT secPanel;      // 左：分组面板
	RECT formPanel;     // 右：表单面板
	RECT noteRow;       // 底部单行说明
	RECT logToolbar1;   // 日志页第一行（文件选择）
	RECT logToolbar2;   // 日志页第二行（暂停/过滤）
	RECT logPanel;      // 日志面板
};

LayoutRects ComputeLayout(HWND hwnd) {
	RECT rc = {};
	GetClientRect(hwnd, &rc);
	const int cx = rc.right;
	const int cy = rc.bottom;

	LayoutRects L = {};
	const int row1 = kContentTop + 14;
	L.cfgToolbar = { kPadding, row1, cx - kPadding, row1 + kRowH };
	L.logToolbar1 = L.cfgToolbar;
	const int row2 = row1 + kRowH + 10;
	L.logToolbar2 = { kPadding, row2, cx - kPadding, row2 + kRowH };

	const int noteH = 20;
	const int panelsTop = row1 + kRowH + 14;
	const int panelsBottom = cy - kPadding - noteH - 6;
	L.noteRow = { kPadding, cy - kPadding - noteH, cx - kPadding, cy - kPadding };

	const int secW = 200;
	L.secPanel = { kPadding, panelsTop, kPadding + secW, panelsBottom };
	L.formPanel = { kPadding + secW + 14, panelsTop, cx - kPadding, panelsBottom };
	L.logPanel = { kPadding, row2 + kRowH + 14, cx - kPadding, panelsBottom };
	return L;
}

// 表单区内字段的坐标（标签列 / 控件列 / 起始行）。
int FormPaneX(const LayoutRects& L) { return L.formPanel.left + 24; }
int FormCtlX(const LayoutRects& L) { return FormPaneX(L) + 248; }
int FormTopY(const LayoutRects& L) { return L.formPanel.top + 52; }

// 画两个面板底 + 标题。子控件是**不透明**的且内缩，所以圆角不会被挡住。
void DrawContentPanels(HDC dc, HWND hwnd) {
	const LayoutRects L = ComputeLayout(hwnd);
	if (g_page == 0) {
		DrawPanel(dc, L.secPanel, L"配置分组", g_fontBold, kTextPrimary);
		DrawPanel(dc, L.formPanel, kSections[g_section].title, g_fontBold, kTextPrimary);
	} else {
		DrawPanel(dc, L.logPanel, L"事件日志", g_fontBold, kTextPrimary);
	}
}

// 给输入框补 1px 边框。
//
// 为什么要自己画：EDIT 控件去掉 WS_EX_CLIENTEDGE 之后是**完全无边框**的，
// 白底控件落在白面板上就"看不见边界"了。主窗口的输入区都是 1px 描边风格，
// 这里就按同一套画：把控件矩形**外扩 1px** 再 FrameRect，正好落在控件外沿，
// 不会被 WS_CLIPCHILDREN 裁掉。
void FrameControl(HDC dc, HWND hwnd, HWND ctl) {
	if (!ctl || !IsWindowVisible(ctl)) { return; }
	RECT r = {};
	GetWindowRect(ctl, &r);
	MapWindowPoints(HWND_DESKTOP, hwnd, reinterpret_cast<POINT*>(&r), 2);
	InflateRect(&r, 1, 1);
	HBRUSH b = CreateSolidBrush(kBorder);
	FrameRect(dc, &r, b);
	DeleteObject(b);
}

void PaintFieldFrames(HDC dc, HWND hwnd) {
	for (const FieldSlot& f : g_fields) {
		if (!f.ctl) { continue; }
		// 下拉框自带边框、复选框不需要边框 —— 只有输入框要补 1px 描边。
		if (f.kind == Kind::Enum || f.kind == Kind::Bool) { continue; }
		FrameControl(dc, hwnd, f.ctl);
	}
	FrameControl(dc, hwnd, g_hFilter);
}

void HarvestSection();
bool HasUnsaved();
void UpdateTitle();

void LayoutFields() {
	if (g_fields.empty()) { return; }
	const LayoutRects L = ComputeLayout(g_main);
	const int paneX = FormPaneX(L);
	const int paneW = (L.formPanel.right - 24) - paneX;
	const int ctlX = FormCtlX(L);
	for (const FieldSlot& f : g_fields) {
		const int y = f.rowY;
		if (f.kind == Kind::List) {
			if (f.label) { MoveWindow(f.label, paneX, y + 4, 240, 20, TRUE); }
			if (f.ctl) { MoveWindow(f.ctl, paneX, y + 24, paneW > 120 ? paneW : 120, 76, TRUE); }
			if (f.hint) { MoveWindow(f.hint, paneX, y + 104, paneW > 120 ? paneW : 120, 30, TRUE); }
			continue;
		}
		if (f.label) { MoveWindow(f.label, paneX, y + 4, 240, 20, TRUE); }
		if (f.ctl) {
			if (f.kind == Kind::Bool) {
				MoveWindow(f.ctl, ctlX, y, 150, 24, TRUE);
			} else if (f.kind == Kind::Enum) {
				MoveWindow(f.ctl, ctlX, y + 1, 340, 200, TRUE);
			} else {
				MoveWindow(f.ctl, ctlX, y + 1, 250, 24, TRUE);
			}
		}
		if (f.hint) {
			const int hw = (L.formPanel.right - 24 - ctlX) > 60 ? (L.formPanel.right - 24 - ctlX) : 60;
			MoveWindow(f.hint, ctlX, y + 26, hw, 30, TRUE);
		}
	}
}

void LayoutAll() {
	if (!g_main) { return; }
	const LayoutRects L = ComputeLayout(g_main);
	const int cx = L.cfgToolbar.right;

	// ---- 配置页 ----
	{
		const int btnW1 = 96, btnW2 = 76, btnW3 = 120, gap = 8;
		const int x3 = cx - btnW3;
		const int x2 = x3 - gap - btnW2;
		const int x1 = x2 - gap - btnW1;
		const int ty = L.cfgToolbar.top;

		if (g_hCfgLabel) { MoveWindow(g_hCfgLabel, kPadding, ty + 5, 70, 20, TRUE); }
		if (g_hCfgPath) { MoveWindow(g_hCfgPath, kPadding + 74, ty + 5, (x1 - 14) - (kPadding + 74), 20, TRUE); }
		if (g_hReload) { MoveWindow(g_hReload, x1, ty, btnW1, kRowH, TRUE); }
		if (g_hSave) { MoveWindow(g_hSave, x2, ty, btnW2, kRowH, TRUE); }
		if (g_hOpenCfgDir) { MoveWindow(g_hOpenCfgDir, x3, ty, btnW3, kRowH, TRUE); }

		if (g_hSecList) {
			MoveWindow(g_hSecList, L.secPanel.left + 10, L.secPanel.top + 42,
				(L.secPanel.right - 10) - (L.secPanel.left + 10),
				(L.secPanel.bottom - 10) - (L.secPanel.top + 42), TRUE);
		}
		if (g_hCfgNote) {
			MoveWindow(g_hCfgNote, L.noteRow.left, L.noteRow.top, L.noteRow.right - L.noteRow.left, 20, TRUE);
		}
	}

	// ---- 日志页 ----
	{
		const int ty1 = L.logToolbar1.top;
		if (g_hLogLabel) { MoveWindow(g_hLogLabel, kPadding, ty1 + 5, 70, 20, TRUE); }
		if (g_hLogCombo) {
			MoveWindow(g_hLogCombo, kPadding + 74, ty1, 380, 200, TRUE);
			MoveWindow(g_hLogBrowse, kPadding + 74 + 388, ty1, 70, kRowH, TRUE);
			MoveWindow(g_hOpenLogDir, kPadding + 74 + 388 + 78, ty1, 110, kRowH, TRUE);
		}

		const int ty2 = L.logToolbar2.top;
		int bx = kPadding;
		const int gap = 8;
		if (g_hPause) { MoveWindow(g_hPause, bx, ty2, 96, kRowH, TRUE); bx += 96 + gap; }
		if (g_hClear) { MoveWindow(g_hClear, bx, ty2, 96, kRowH, TRUE); bx += 96 + gap; }
		if (g_hAutoScroll) { MoveWindow(g_hAutoScroll, bx, ty2, 100, kRowH, TRUE); bx += 100 + gap; }
		if (g_hOnlyHigh) { MoveWindow(g_hOnlyHigh, bx, ty2, 92, kRowH, TRUE); bx += 92 + gap; }
		if (g_hOnlyBlock) { MoveWindow(g_hOnlyBlock, bx, ty2, 92, kRowH, TRUE); bx += 92 + gap; }
		if (g_hFilterLabel) { MoveWindow(g_hFilterLabel, bx, ty2 + 5, 42, 20, TRUE); bx += 46; }
		if (g_hFilter) { MoveWindow(g_hFilter, bx, ty2 + 3, (cx - bx) > 100 ? (cx - bx) : 100, 24, TRUE); }

		if (g_hLogList) {
			MoveWindow(g_hLogList, L.logPanel.left + 10, L.logPanel.top + 42,
				(L.logPanel.right - 10) - (L.logPanel.left + 10),
				(L.logPanel.bottom - 10) - (L.logPanel.top + 42), TRUE);
		}
		if (g_hLogStatus) {
			MoveWindow(g_hLogStatus, L.noteRow.left, L.noteRow.top, L.noteRow.right - L.noteRow.left, 20, TRUE);
		}
	}

	LayoutFields();
}

void BuildSection(int section) {
	HarvestSection();  // 先把当前分组的改动收进待写表，再重建控件
	DestroyFields();
	g_section = section;
	const Section& sec = kSections[section];

	const LayoutRects L = ComputeLayout(g_main);
	const int paneX = FormPaneX(L);
	const int paneW = (L.formPanel.right - 24) - paneX;
	int y = FormTopY(L);

	for (int i = 0; i < sec.count; ++i) {
		const KeyDef& k = sec.keys[i];
		FieldSlot f;
		f.keyIdx = i;
		f.rowY = y;
		f.kind = k.kind;

		f.label = CreateWindowExW(0, L"STATIC", k.label, WS_CHILD | WS_VISIBLE | SS_LEFT,
			paneX, y + 4, 240, 20, g_main, nullptr, g_inst, nullptr);
		SetFontAll(f.label, g_fontUI);
		g_panelText.insert(f.label);

		const int ctlX = FormCtlX(L);

		if (k.kind == Kind::List) {
			f.ctl = CreateWindowExW(0, L"EDIT", L"",
				WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN,
				paneX, y + 24, paneW, 76, g_main,
				reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIELD_BASE + i)), g_inst, nullptr);
			SetFontAll(f.ctl, g_fontMono);
		} else if (k.kind == Kind::Bool) {
			f.ctl = MakeCheckBox(g_main, IDC_FIELD_BASE + i, L"启用", ctlX, y, 150, 24);
			if (f.ctl) { g_panelText.insert(f.ctl); }   // 在白色面板上
		} else if (k.kind == Kind::Enum) {
			f.ctl = CreateWindowExW(0, L"COMBOBOX", L"",
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
				ctlX, y + 1, 340, 200, g_main,
				reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIELD_BASE + i)), g_inst, nullptr);
			SetFontAll(f.ctl, g_fontUI);
			const int n = EnumOptionCount(k);
			for (int o = 0; o < n; ++o) {
				SendMessageW(f.ctl, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(EnumOptionLabel(k, o)));
			}
		} else {
			f.ctl = CreateWindowExW(0, L"EDIT", L"",
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL
					| ((k.kind == Kind::Number) ? ES_NUMBER : 0),
				ctlX, y + 1, 250, 24, g_main,
				reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_FIELD_BASE + i)), g_inst, nullptr);
			SetFontAll(f.ctl, g_fontUI);
		}

		// 说明文字**独占一行**（放在控件下方）。原来与控件同行时，
		// 下拉框较宽会把它盖住，长句还会被窗口右边裁掉。
		if (k.hint && k.hint[0]) {
			const int hintX = (k.kind == Kind::List) ? paneX : ctlX;
			const int hintY = (k.kind == Kind::List) ? (y + 104) : (y + 26);
			const int hintW = (L.formPanel.right - 24 - hintX) > 60 ? (L.formPanel.right - 24 - hintX) : 60;
			f.hint = CreateWindowExW(0, L"STATIC", k.hint,
				WS_CHILD | WS_VISIBLE | SS_LEFT, hintX, hintY, hintW, 30,
				g_main, nullptr, g_inst, nullptr);
			SetFontAll(f.hint, g_fontHint);
			g_panelText.insert(f.hint);
			g_hintText.insert(f.hint);
		}

		SetFieldFromConfig(f, k);
		g_fields.push_back(f);

		y += (k.kind == Kind::List) ? 144 : 50;
	}
	UpdateTitle();
	// 面板标题/输入框描边都是父窗口画的，重建控件后必须让父窗口重画一次。
	if (g_main) { InvalidateRect(g_main, nullptr, TRUE); }
}

// 把当前分组控件里的值"收"进待写表。只记录**与文件里不同的**键 ——
// 这样未改动的键不会被重写（也不会把默认值补进文件里）。
void HarvestSection() {
	if (g_fields.empty()) { return; }
	const Section& sec = kSections[g_section];
	for (const FieldSlot& f : g_fields) {
		if (f.keyIdx < 0 || f.keyIdx >= sec.count) { continue; }
		const KeyDef& k = sec.keys[f.keyIdx];
		const std::string keyU8 = W2U8(k.key);

		if (k.kind == Kind::List) {
			const int len = GetWindowTextLengthW(f.ctl);
			std::wstring text(static_cast<size_t>(len) + 1, L'\0');
			GetWindowTextW(f.ctl, text.data(), len + 1);
			text.resize(static_cast<size_t>(len));
			std::vector<std::string> vals;
			size_t start = 0;
			for (size_t i = 0; i <= text.size(); ++i) {
				if (i == text.size() || text[i] == L'\n') {
					const std::wstring one = TrimW(text.substr(start, i - start));
					start = i + 1;
					if (!one.empty()) { vals.push_back(W2U8(one)); }
				}
			}
			if (vals == g_cfg.GetList(keyU8)) { g_pendingLists.erase(keyU8); }
			else { g_pendingLists[keyU8] = vals; }
			continue;
		}

		std::string newVal;
		if (k.kind == Kind::Bool) {
			newVal = CheckOf(f.ctl) ? "1" : "0";
		} else if (k.kind == Kind::Enum) {
			const int idx = static_cast<int>(SendMessageW(f.ctl, CB_GETCURSEL, 0, 0));
			newVal = EnumValueFromIndex(k, idx);
		} else {
			const int len = GetWindowTextLengthW(f.ctl);
			std::wstring text(static_cast<size_t>(len) + 1, L'\0');
			GetWindowTextW(f.ctl, text.data(), len + 1);
			text.resize(static_cast<size_t>(len));
			newVal = W2U8(TrimW(text));
			if (newVal.empty() && k.kind == Kind::Number) { newVal = W2U8(k.def); }
		}

		if (newVal == g_cfg.GetScalar(keyU8, W2U8(k.def))) { g_pendingScalars.erase(keyU8); }
		else { g_pendingScalars[keyU8] = newVal; }
	}
}

bool HasUnsaved() { return !g_pendingScalars.empty() || !g_pendingLists.empty(); }

// 字段控件一有变化就立刻收进待写表并刷新标题的「*」。
//
// ★ 为什么必须即时收：`WM_CLOSE` 的"有未保存的修改"闸门问的是
//   `HasUnsaved()`，而它只看 `g_pending*`；而 `g_pending*` 原本只在
//   **切分组 / 保存**时才由 `HarvestSection()` 填。于是"改完当前分组的
//   字段、不切分组直接关窗"会**静默丢掉改动**（铁律 93：查出来 ≠ 修掉）。
void TouchPending() {
	HarvestSection();
	UpdateTitle();
}

void UpdateTitle() {
	if (g_main) {
		SetWindowTextW(g_main, HasUnsaved() ? L"R3 ShieldCore 配置与日志 *" : L"R3 ShieldCore 配置与日志");
	}
	if (g_hCfgNote) {
		SetWindowTextW(g_hCfgNote, HasUnsaved()
			? L"有未保存的修改（标题带 *）—— 点『保存』写入生效的配置文件；引擎需重启才生效。"
			: L"改完点『保存』写入生效的配置文件；引擎需重启才生效。");
	}
}

bool SaveAll() {
	HarvestSection();

	// 校验**所有**待写值（含之前分组改过的）。
	std::wstring problems;
	for (const auto& kv : g_pendingScalars) {
		const KeyDef* k = FindKey(kv.first);
		if (!k || k->kind != Kind::Number) { continue; }
		const std::wstring w = U82W(kv.second);
		wchar_t* endp = nullptr;
		const long v = wcstol(w.c_str(), &endp, 10);
		if (endp == w.c_str() || (endp && *endp != L'\0')) {
			problems += std::wstring(L"· ") + k->label + L"：不是合法整数\n";
			continue;
		}
		if (v < k->lo || v > k->hi) {
			WCHAR m[256] = {};
			swprintf_s(m, L"· %s：超出范围 %d..%d（当前 %ld）\n", k->label, k->lo, k->hi, v);
			problems += m;
		}
	}
	if (!problems.empty()) {
		MessageBoxW(g_main, (L"以下项不合法，未保存：\n\n" + problems).c_str(),
			L"配置校验失败", MB_ICONWARNING | MB_OK);
		return false;
	}

	if (!HasUnsaved()) {
		MessageBoxW(g_main, L"没有需要保存的修改。", L"保存", MB_ICONINFORMATION | MB_OK);
		return true;
	}
	if (g_cfg.path.empty()) {
		MessageBoxW(g_main, L"没有可写入的配置文件路径。", L"保存失败", MB_ICONERROR | MB_OK);
		return false;
	}

	const std::string content = g_cfg.BuildNewContent(g_pendingScalars, g_pendingLists);
	std::wstring err;
	if (!g_cfg.SaveContent(content, err)) {
		MessageBoxW(g_main, err.c_str(), L"保存失败", MB_ICONERROR | MB_OK);
		return false;
	}

	// 重新加载，让界面与实际文件一致（也刷新 firstActive）。
	const std::wstring p = g_cfg.path;
	g_cfg.Load(p);
	g_pendingScalars.clear();
	g_pendingLists.clear();
	BuildSection(g_section);
	LayoutAll();
	SetWindowTextW(g_hCfgPath, CfgPathDisplay().c_str());
	UpdateTitle();

	MessageBoxW(g_main, (L"已保存：\n" + p + L"\n\n引擎需重启才生效。").c_str(),
		L"保存成功", MB_ICONINFORMATION | MB_OK);
	return true;
}

// ---------- 日志页 ----------

void UpdateLogStatus() {
	if (!g_hLogStatus) { return; }
	WCHAR buf[512] = {};
	swprintf_s(buf, L"%s    共 %llu 行  |  显示 %d 行  |  已读 %llu 字节",
		g_log.status.c_str(),
		static_cast<unsigned long long>(g_log.all.size()),
		g_hLogList ? static_cast<int>(SendMessageW(g_hLogList, LB_GETCOUNT, 0, 0)) : 0,
		static_cast<unsigned long long>(g_log.offset));
	SetWindowTextW(g_hLogStatus, buf);
}

bool PassesFilter(const std::wstring& line) {
	if (CheckOf(g_hOnlyHigh)
		&& !IContainsW(line, L"[HIGH-RISK]")) {
		return false;
	}
	if (CheckOf(g_hOnlyBlock)
		&& !IContainsW(line, L"[by R3ShieldCore]")) {
		return false;
	}
	const int len = GetWindowTextLengthW(g_hFilter);
	if (len > 0) {
		std::wstring f(static_cast<size_t>(len) + 1, L'\0');
		GetWindowTextW(g_hFilter, f.data(), len + 1);
		f.resize(static_cast<size_t>(len));
		if (!IContainsW(line, f)) { return false; }
	}
	return true;
}

void AddLineToView(const std::wstring& line) {
	SendMessageW(g_hLogList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str()));
}

void AppendLogLine(const std::wstring& line) {
	g_log.all.push_back(line);
	if (PassesFilter(line)) { AddLineToView(line); }

	if (g_log.all.size() > 100000) {
		const size_t drop = g_log.all.size() - 50000;
		for (size_t i = 0; i < drop; ++i) { g_log.all.pop_front(); }
		// 重建视图（前面被丢掉了）
		SendMessageW(g_hLogList, LB_RESETCONTENT, 0, 0);
		for (const std::wstring& l : g_log.all) {
			if (PassesFilter(l)) { AddLineToView(l); }
		}
	}

	if (g_log.autoScroll && !g_log.paused) {
		const int n = static_cast<int>(SendMessageW(g_hLogList, LB_GETCOUNT, 0, 0));
		if (n > 0) { SendMessageW(g_hLogList, LB_SETTOPINDEX, n - 1, 0); }
	}
}

void CloseLogFile() {
	if (g_log.h != INVALID_HANDLE_VALUE) { CloseHandle(g_log.h); g_log.h = INVALID_HANDLE_VALUE; }
}

void ResetLogView() {
	SendMessageW(g_hLogList, LB_RESETCONTENT, 0, 0);
	g_log.all.clear();
	g_log.offset = 0;
	g_log.pending.clear();
	g_log.bomChecked = false;
	g_log.maxWidth = 0;
	SendMessageW(g_hLogList, LB_SETHORIZONTALEXTENT, 100, 0);
}

// 打开并读入尾部若干字节，然后进入 follow 模式。
bool OpenLogFile(const std::wstring& path, bool keepView) {
	CloseLogFile();
	g_log.path = path;
	if (!keepView) { ResetLogView(); }

	g_log.h = CreateFileW(path.c_str(), GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (g_log.h == INVALID_HANDLE_VALUE) {
		g_log.status = L"无法打开（文件不存在或不可读）";
		UpdateLogStatus();
		return false;
	}

	LARGE_INTEGER size = {};
	GetFileSizeEx(g_log.h, &size);
	const ULONGLONG total = static_cast<ULONGLONG>(size.QuadPart);
	const ULONGLONG tailBytes = 262144;  // 启动时最多回看 256KB
	ULONGLONG start = (total > tailBytes) ? (total - tailBytes) : 0;

	LARGE_INTEGER li = {};
	li.QuadPart = static_cast<LONGLONG>(start);
	SetFilePointerEx(g_log.h, li, nullptr, FILE_BEGIN);

	std::string data;
	char buf[65536];
	DWORD got = 0;
	while (ReadFile(g_log.h, buf, sizeof(buf), &got, nullptr) && got > 0) {
		data.append(buf, got);
	}

	// 非从头开始 -> 丢掉可能被截断的第一行。
	if (start > 0) {
		const size_t nl = data.find('\n');
		if (nl == std::string::npos) { data.clear(); }
		else { data.erase(0, nl + 1); }
	}

	g_log.pending = data;
	g_log.bomChecked = false;
	// 处理 pending 里的完整行
	for (;;) {
		const size_t nl = g_log.pending.find('\n');
		if (nl == std::string::npos) { break; }
		std::string one = g_log.pending.substr(0, nl);
		g_log.pending.erase(0, nl + 1);
		if (!g_log.bomChecked) {
			g_log.bomChecked = true;
			if (one.size() >= 3 && static_cast<unsigned char>(one[0]) == 0xEF
				&& static_cast<unsigned char>(one[1]) == 0xBB
				&& static_cast<unsigned char>(one[2]) == 0xBF) {
				one.erase(0, 3);
			}
		}
		if (!one.empty() && one.back() == '\r') { one.pop_back(); }
		AppendLogLine(U82W(one));
	}

	g_log.offset = total;
	g_log.status = L"跟随中（实时）";
	UpdateLogStatus();
	return true;
}

void ReadMore() {
	if (g_log.path.empty()) { return; }

	if (g_log.h == INVALID_HANDLE_VALUE) {
		// 文件可能后来才出现 —— 定期重试
		if (FileExistsW(g_log.path)) { OpenLogFile(g_log.path, true); }
		return;
	}
	if (g_log.paused) { return; }

	LARGE_INTEGER size = {};
	if (!GetFileSizeEx(g_log.h, &size)) { return; }
	const ULONGLONG total = static_cast<ULONGLONG>(size.QuadPart);

	if (total < g_log.offset) {
		// 被截断 / 轮转 -> 从头再来
		g_log.status = L"检测到日志被截断，已从头重读";
		OpenLogFile(g_log.path, false);
		return;
	}
	if (total == g_log.offset) { return; }

	LARGE_INTEGER li = {};
	li.QuadPart = static_cast<LONGLONG>(g_log.offset);
	SetFilePointerEx(g_log.h, li, nullptr, FILE_BEGIN);

	std::string data;
	char buf[65536];
	DWORD got = 0;
	while (ReadFile(g_log.h, buf, sizeof(buf), &got, nullptr) && got > 0) {
		data.append(buf, got);
	}
	g_log.offset = total;
	g_log.pending += data;

	int added = 0;
	for (;;) {
		const size_t nl = g_log.pending.find('\n');
		if (nl == std::string::npos) { break; }
		std::string one = g_log.pending.substr(0, nl);
		g_log.pending.erase(0, nl + 1);
		if (!g_log.bomChecked) {
			g_log.bomChecked = true;
			if (one.size() >= 3 && static_cast<unsigned char>(one[0]) == 0xEF
				&& static_cast<unsigned char>(one[1]) == 0xBB
				&& static_cast<unsigned char>(one[2]) == 0xBF) {
				one.erase(0, 3);
			}
		}
		if (!one.empty() && one.back() == '\r') { one.pop_back(); }
		AppendLogLine(U82W(one));
		++added;
	}
	if (added > 0) { g_log.status = L"跟随中（实时）"; }
	UpdateLogStatus();
}

void RebuildLogView() {
	SendMessageW(g_hLogList, LB_RESETCONTENT, 0, 0);
	for (const std::wstring& l : g_log.all) {
		if (PassesFilter(l)) { AddLineToView(l); }
	}
	UpdateLogStatus();
}

void ChooseLogTarget(int comboIdx, bool initial) {
	const std::wstring exeDir = ExeDir();
	const std::wstring cfgDir = g_cfg.path.empty() ? exeDir : DirOf(g_cfg.path);
	std::wstring target;

	if (comboIdx == 0) {
		// 事件日志：优先用配置里的 log=，相对路径按引擎 exe 同目录解析
		std::string raw = g_cfg.GetScalar("log", "r3shieldcore-events.log");
		std::wstring w = U82W(raw);
		if (w.empty()) { w = L"r3shieldcore-events.log"; }
		const bool abs = (w.size() > 2 && w[1] == L':') || (w.size() > 1 && (w[0] == L'\\' || w[0] == L'/'));
		if (abs) {
			target = w;
		} else {
			target = exeDir + L"\\" + w;
			if (!FileExistsW(target) && FileExistsW(cfgDir + L"\\" + w)) {
				target = cfgDir + L"\\" + w;
			}
		}
	} else if (comboIdx == 1) {
		target = exeDir + L"\\r3shieldcore-console.log";
	} else if (comboIdx == 2) {
		target = exeDir + L"\\r3shieldcore-svc.log";
	} else {
		return;  // 自定义：等用户浏览
	}

	OpenLogFile(target, false);
	(void)initial;
}

// ---------- 布局（LayoutFields / LayoutAll 已上移到 BuildSection 之前，
//            与 ComputeLayout 放在一起，避免两处几何漂移）----------

void ShowPage(int page) {
	g_page = page;
	const int cfgShow = (page == 0) ? SW_SHOW : SW_HIDE;
	const int logShow = (page == 1) ? SW_SHOW : SW_HIDE;

	ShowWindow(g_hSecList, cfgShow);
	ShowWindow(g_hCfgLabel, cfgShow);
	ShowWindow(g_hCfgPath, cfgShow);
	ShowWindow(g_hReload, cfgShow);
	ShowWindow(g_hSave, cfgShow);
	ShowWindow(g_hOpenCfgDir, cfgShow);
	ShowWindow(g_hCfgNote, cfgShow);
	for (FieldSlot& f : g_fields) {
		if (f.label) { ShowWindow(f.label, cfgShow); }
		if (f.ctl) { ShowWindow(f.ctl, cfgShow); }
		if (f.hint) { ShowWindow(f.hint, cfgShow); }
	}

	ShowWindow(g_hLogCombo, logShow);
	ShowWindow(g_hLogLabel, logShow);
	ShowWindow(g_hLogBrowse, logShow);
	ShowWindow(g_hOpenLogDir, logShow);
	ShowWindow(g_hPause, logShow);
	ShowWindow(g_hClear, logShow);
	ShowWindow(g_hAutoScroll, logShow);
	ShowWindow(g_hOnlyHigh, logShow);
	ShowWindow(g_hOnlyBlock, logShow);
	ShowWindow(g_hFilterLabel, logShow);
	ShowWindow(g_hFilter, logShow);
	ShowWindow(g_hLogList, logShow);
	ShowWindow(g_hLogStatus, logShow);

	InvalidateRect(g_main, nullptr, TRUE);
}

// ---------------------------------------------------------------------------
// 标题区 + 页签栏
//
// 几何与画法**逐字对齐**主窗口：标题区 62px（白底，标题 14..38、副标题 38..56，
// 分隔线在 y=61），页签栏 62..100（白底，页签 84×30、间距 8、圆角 8px，
// 选中蓝底白字、悬停浅蓝底淡蓝描边），栏下 1px 分隔线。
// ---------------------------------------------------------------------------
int g_hoverTab = -1;
bool g_trackingLeave = false;

PCWSTR TabTitle(int index) {
	return (index == 1) ? L"日志" : L"配置";
}

RECT TabRect(int index) {
	const int left = kPadding + index * (kTabWidth + kTabGap);
	RECT rect = { left, kTabBarTop + 4, left + kTabWidth, kTabBarTop + kTabBarH - 4 };
	return rect;
}

int HitTestTab(POINT point) {
	for (int i = 0; i < kTabCount; ++i) {
		RECT rect = TabRect(i);
		if (PtInRect(&rect, point)) { return i; }
	}
	return -1;
}

void DrawHeader(HDC dc, const RECT& client) {
	RECT header = { 0, 0, client.right, kHeaderH };
	FillSolid(dc, header, kHeaderBg);

	RECT title = { kPadding, 14, client.right - kPadding, 38 };
	DrawTextSimple(dc, L"R3 ShieldCore 配置与日志", title, g_fontTitle, kTextPrimary,
		DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

	RECT subtitle = { kPadding, 38, client.right - kPadding, 56 };
	DrawTextSimple(dc, L"配置表单  ·  逐行保真写入  ·  日志实时跟踪  ·  无需引擎运行",
		subtitle, g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

	RECT line = { 0, kHeaderH - 1, client.right, kHeaderH };
	FillSolid(dc, line, kBorder);
}

void DrawTabBar(HDC dc, const RECT& client) {
	RECT strip = { 0, kTabBarTop, client.right, kTabBarTop + kTabBarH };
	FillSolid(dc, strip, kHeaderBg);

	for (int i = 0; i < kTabCount; ++i) {
		RECT rect = TabRect(i);
		const bool active = (i == g_page);
		COLORREF fill = 0;
		COLORREF stroke = 0;
		if (active) {
			fill = kTabActiveBg;
			stroke = kTabActiveBg;
		} else if (i == g_hoverTab) {
			fill = kTabHoverBg;
			stroke = kTabHoverBorder;
		}
		if (active || i == g_hoverTab) {
			HBRUSH brush = CreateSolidBrush(fill);
			HGDIOBJ oldBrush = SelectObject(dc, brush);
			HPEN pen = CreatePen(PS_SOLID, 1, stroke);
			HGDIOBJ oldPen = SelectObject(dc, pen);
			RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
			SelectObject(dc, oldBrush);
			SelectObject(dc, oldPen);
			DeleteObject(brush);
			DeleteObject(pen);
		}
		DrawTextSimple(dc, TabTitle(i), rect, g_fontTab,
			active ? kTabActiveText : (i == g_hoverTab ? kAccent : kTabInactiveText),
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	RECT line = { 0, kTabBarTop + kTabBarH, client.right, kTabBarTop + kTabBarH + 1 };
	FillSolid(dc, line, kBorder);
}

std::wstring PickFolderFile(HWND owner, const std::wstring& initialDir) {
	// 用系统"打开文件"对话框（GETOPENFILENAME）。
	WCHAR buf[MAX_PATH * 2] = {};
	if (!initialDir.empty()) { wcsncpy_s(buf, initialDir.c_str(), _TRUNCATE); }

	OPENFILENAMEW ofn = {};
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = owner;
	ofn.lpstrFilter = L"日志文件 (*.log)\0*.log\0所有文件 (*.*)\0*.*\0\0";
	ofn.lpstrFile = buf;
	ofn.nMaxFile = _countof(buf);
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
	if (!GetOpenFileNameW(&ofn)) { return std::wstring(); }
	return buf;
}

void OpenInExplorer(const std::wstring& path, bool select) {
	if (path.empty()) { return; }
	if (select) {
		const std::wstring params = L"/select,\"" + path + L"\"";
		ShellExecuteW(nullptr, L"open", L"explorer.exe", params.c_str(), nullptr, SW_SHOWNORMAL);
	} else {
		ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
	}
}

// ---------------------------------------------------------------------------
// 列表自绘
//
// 两个列表都套用主窗口事件日志页的画法：交替行底 + 左侧 3px 决策色条，
// 行高 22、等宽 Consolas -12。分组列表用主窗口页签的"选中蓝条"风格。
// ---------------------------------------------------------------------------

// 从一行原始日志文本里推出"决策色"（用于左侧色条 + 文字色）。
// 与主窗口 DecisionColor 的语义对应：被拦=红、高危=品红、降级放行=橙。
COLORREF LogLineColor(const std::wstring& text) {
	if (IContainsW(text, L"[HIGH-RISK]")) { return kHighRisk; }
	if (IContainsW(text, L"[by R3ShieldCore]")) { return kBlocked; }
	if (IContainsW(text, L"ASK-UNAVAIL")) { return kWarn; }
	if (text.find(L"[史]") != std::wstring::npos) { return kTextSecondary; }
	return kAccent;
}

void DrawLogItem(DRAWITEMSTRUCT* dis) {
	if (dis->itemID == static_cast<UINT>(-1)) { return; }
	const int len = static_cast<int>(SendMessageW(dis->hwndItem, LB_GETTEXTLEN, dis->itemID, 0));
	if (len < 0) { return; }
	std::wstring text(static_cast<size_t>(len) + 1, L'\0');
	SendMessageW(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(text.data()));
	text.resize(static_cast<size_t>(len));

	const bool selected = (dis->itemState & ODS_SELECTED) != 0;
	const COLORREF decision = LogLineColor(text);

	// 交替底色（主窗口 ColorLogRowAlt）
	FillSolid(dis->hDC, dis->rcItem,
		(dis->itemID % 2) ? kLogRowAlt : kHeaderBg);

	// 左侧 3px 决策色条 —— 比整行染色克制得多
	RECT stripe = { dis->rcItem.left, dis->rcItem.top + 2, dis->rcItem.left + 3, dis->rcItem.bottom - 2 };
	FillSolid(dis->hDC, stripe, decision);

	if (selected) {
		RECT hl = { dis->rcItem.left + 3, dis->rcItem.top, dis->rcItem.right, dis->rcItem.bottom };
		FillSolid(dis->hDC, hl, kTabHoverBg);
	}

	COLORREF fg = selected ? kAccent : decision;
	if (!selected && decision == kAccent) { fg = kTextPrimary; }

	RECT r = dis->rcItem;
	r.left += 10;
	DrawTextSimple(dis->hDC, text.c_str(), r, g_fontMono, fg,
		DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

void DrawSectionItem(DRAWITEMSTRUCT* dis) {
	if (dis->itemID == static_cast<UINT>(-1)) { return; }
	const int len = static_cast<int>(SendMessageW(dis->hwndItem, LB_GETTEXTLEN, dis->itemID, 0));
	if (len < 0) { return; }
	std::wstring text(static_cast<size_t>(len) + 1, L'\0');
	SendMessageW(dis->hwndItem, LB_GETTEXT, dis->itemID, reinterpret_cast<LPARAM>(text.data()));
	text.resize(static_cast<size_t>(len));

	const bool selected = (dis->itemState & ODS_SELECTED) != 0;
	FillSolid(dis->hDC, dis->rcItem, selected ? kTabHoverBg : kHeaderBg);
	if (selected) {
		RECT stripe = { dis->rcItem.left, dis->rcItem.top, dis->rcItem.left + 3, dis->rcItem.bottom };
		FillSolid(dis->hDC, stripe, kAccent);
	}

	RECT r = dis->rcItem;
	r.left += 14;
	r.right -= 8;
	DrawTextSimple(dis->hDC, text.c_str(), r, g_fontUI,
		selected ? kAccent : kTextPrimary,
		DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

// ---------- 窗口过程 ----------

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
	switch (msg) {
	case WM_CREATE: {
		// ★★ 必须**先**把 g_main 指到 hwnd。
		//    原因：WM_CREATE 是在 CreateWindowExW **内部**同步发出的，
		//    那一刻外层赋值 `g_main = CreateWindowExW(...)` 还没执行完，
		//    g_main 仍是 nullptr ⇒ 这里用 g_main 当父窗口会把所有控件
		//    创建成**顶层窗口**（父子关系丢失、布局全乱、切页也隐藏不掉）。
		g_main = hwnd;

		// ---- 配置页 ----
		g_hCfgPath = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_ENDELLIPSIS,
			84, 60, 400, 20, hwnd, reinterpret_cast<HMENU>(IDC_CFGPATH), g_inst, nullptr);
		SetFontAll(g_hCfgPath, g_fontUI);

		HWND lbl = CreateWindowExW(0, L"STATIC", L"配置文件:", WS_CHILD | WS_VISIBLE | SS_LEFT,
			14, 60, 66, 20, hwnd, nullptr, g_inst, nullptr);
		SetFontAll(lbl, g_fontUI);
		g_hCfgLabel = lbl;

		g_hReload = MakeButton(hwnd, IDC_RELOAD, L"重新加载", 0, 0, 96, kRowH);
		g_hSave = MakeButton(hwnd, IDC_SAVE, L"保存", 0, 0, 76, kRowH);
		g_hOpenCfgDir = MakeButton(hwnd, IDC_OPENCFGDIR, L"打开所在目录", 0, 0, 120, kRowH);

		// 分组列表：自绘固定行高，套主窗口的"选中蓝条"风格。
		g_hSecList = CreateWindowExW(0, L"LISTBOX", L"",
			WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP
				| LBS_NOTIFY | LBS_OWNERDRAWFIXED | LBS_HASSTRINGS | LBS_NOINTEGRALHEIGHT,
			14, 96, 180, 400, hwnd, reinterpret_cast<HMENU>(IDC_SECLIST), g_inst, nullptr);
		SetFontAll(g_hSecList, g_fontUI);
		SendMessageW(g_hSecList, LB_SETITEMHEIGHT, 0, 30);
		for (int i = 0; i < kSectionCount; ++i) {
			SendMessageW(g_hSecList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(kSections[i].title));
		}
		SendMessageW(g_hSecList, LB_SETCURSEL, 0, 0);

		g_hCfgNote = CreateWindowExW(0, L"STATIC",
			L"改完点『保存』写入生效的配置文件；引擎需重启才生效。",
			WS_CHILD | WS_VISIBLE | SS_LEFT, 196, 600, 600, 20, hwnd,
			reinterpret_cast<HMENU>(IDC_CFGNOTE), g_inst, nullptr);
		SetFontAll(g_hCfgNote, g_fontHint);

		// ---- 日志页 ----
		HWND llog = CreateWindowExW(0, L"STATIC", L"日志文件:", WS_CHILD | SS_LEFT,
			14, 58, 66, 20, hwnd, nullptr, g_inst, nullptr);
		SetFontAll(llog, g_fontUI);
		g_hLogLabel = llog;

		g_hLogCombo = CreateWindowExW(0, L"COMBOBOX", L"",
			WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
			84, 58, 380, 200, hwnd, reinterpret_cast<HMENU>(IDC_LOGCOMBO), g_inst, nullptr);
		SetFontAll(g_hLogCombo, g_fontUI);
		SendMessageW(g_hLogCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"事件日志  r3shieldcore-events.log"));
		SendMessageW(g_hLogCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"控制台日志  r3shieldcore-console.log"));
		SendMessageW(g_hLogCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"服务日志  r3shieldcore-svc.log"));
		SendMessageW(g_hLogCombo, CB_SETCURSEL, 0, 0);

		g_hLogBrowse = MakeButton(hwnd, IDC_LOGBROWSE, L"浏览…", 0, 0, 70, kRowH);
		g_hOpenLogDir = MakeButton(hwnd, IDC_OPENLOGDIR, L"打开所在目录", 0, 0, 110, kRowH);

		g_hPause = MakeButton(hwnd, IDC_PAUSE, L"暂停", 0, 0, 96, kRowH);
		g_hClear = MakeButton(hwnd, IDC_CLEAR, L"清空显示", 0, 0, 96, kRowH);
		g_hAutoScroll = MakeCheckBox(hwnd, IDC_AUTOSCROLL, L"自动滚动", 0, 0, 100, kRowH);
		g_hOnlyHigh = MakeCheckBox(hwnd, IDC_ONLYHIGH, L"只看高危", 0, 0, 92, kRowH);
		g_hOnlyBlock = MakeCheckBox(hwnd, IDC_ONLYBLOCK, L"只看被拦", 0, 0, 92, kRowH);
		g_hFilterLabel = CreateWindowExW(0, L"STATIC", L"过滤:", WS_CHILD | SS_LEFT,
			0, 0, 42, 20, hwnd, reinterpret_cast<HMENU>(IDC_FILTERLABEL), g_inst, nullptr);
		SetFontAll(g_hFilterLabel, g_fontUI);
		g_hFilter = CreateWindowExW(0, L"EDIT", L"",
			WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 200, 24, hwnd,
			reinterpret_cast<HMENU>(IDC_FILTER), g_inst, nullptr);
		SetFontAll(g_hFilter, g_fontUI);
		g_checkState[g_hAutoScroll] = true;   // 默认开启自动滚动

		// 日志列表：自绘固定行高（主窗口事件日志页是 22px 一行）。
		g_hLogList = CreateWindowExW(0, L"LISTBOX", L"",
			WS_CHILD | WS_VSCROLL | WS_HSCROLL | LBS_OWNERDRAWFIXED | LBS_NOSEL | LBS_NOINTEGRALHEIGHT
				| LBS_DISABLENOSCROLL
				// ★ LBS_HASSTRINGS 必须有：ownerdraw 列表框**默认不保存字符串**
				//   （只存 LPARAM 作 item data），少了它 LB_GETTEXT 取到的是垃圾 ⇒
				//   自绘时画出乱码（实测踩到）。
				| LBS_HASSTRINGS,
			14, 128, 900, 460, hwnd, reinterpret_cast<HMENU>(IDC_LOGLIST), g_inst, nullptr);
		SetFontAll(g_hLogList, g_fontMono);
		SendMessageW(g_hLogList, LB_SETITEMHEIGHT, 0, 22);
		SendMessageW(g_hLogList, LB_SETHORIZONTALEXTENT, 1200, 0);

		g_hLogStatus = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | SS_LEFT,
			14, 600, 900, 20, hwnd, reinterpret_cast<HMENU>(IDC_LOGSTATUS), g_inst, nullptr);
		SetFontAll(g_hLogStatus, g_fontHint);

		// 载入配置
		g_cfg.Load(ResolveConfigPath());
		SetWindowTextW(g_hCfgPath, CfgPathDisplay().c_str());
		BuildSection(g_section);

		// --section / --page 启动参数（截图、排障用）
		if (g_startSection > 0 && g_startSection < kSectionCount) {
			SendMessageW(g_hSecList, LB_SETCURSEL, g_startSection, 0);
			BuildSection(g_startSection);
		}

		LayoutAll();
		ShowPage(g_startPage == 1 ? 1 : 0);

		// 预选日志（不显示，切过去再读也行；这里先打开以便计时器跟进）
		ChooseLogTarget(0, true);

		SetTimer(hwnd, 1, 500, nullptr);
		return 0;
	}

	case WM_SIZE:
		LayoutAll();
		InvalidateRect(hwnd, nullptr, TRUE);
		return 0;

	case WM_GETMINMAXINFO: {
		MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lp);
		// 最小宽度要放得下：页签条右缘（20 + 2×92 - 8 = 196）
		// 与配置页工具条那一簇按钮（右对齐约 440px）。
		mmi->ptMinTrackSize.x = 800;
		mmi->ptMinTrackSize.y = 560;
		return 0;
	}

	case WM_ERASEBKGND: {
		HDC dc = reinterpret_cast<HDC>(wp);
		RECT rc = {};
		GetClientRect(hwnd, &rc);
		// 标题区/页签栏那一段直接擦成白底（与标题区同色）—— 否则会先闪一下
		// 灰底再被白底覆盖。
		RECT strip = { 0, 0, rc.right, kContentTop };
		FillSolid(dc, strip, kHeaderBg);
		RECT body = { 0, kContentTop, rc.right, rc.bottom };
		FillSolid(dc, body, kBg);
		return 1;
	}

	case WM_PAINT: {
		PAINTSTRUCT ps = {};
		HDC dc = BeginPaint(hwnd, &ps);
		RECT rc = {};
		GetClientRect(hwnd, &rc);

		// 标题区 + 页签栏这一段**没有子控件** ⇒ 可以双缓冲（与主窗口同款做法），
		// 消掉拖动/缩放时的重绘闪烁。
		const int stripH = kContentTop;
		HDC mem = CreateCompatibleDC(dc);
		HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right > 0 ? rc.right : 1, stripH);
		HGDIOBJ oldBmp = SelectObject(mem, bmp);
		RECT strip = { 0, 0, rc.right, stripH };
		FillSolid(mem, strip, kHeaderBg);
		DrawHeader(mem, rc);
		DrawTabBar(mem, rc);
		BitBlt(dc, 0, 0, rc.right, stripH, mem, 0, 0, SRCCOPY);
		SelectObject(mem, oldBmp);
		DeleteObject(bmp);
		DeleteDC(mem);

		// 内容区：面板底 + 输入框描边。这一片有子控件，**不能**整体双缓冲
		// （BitBlt 会把子控件一起盖掉）。绘制区已被 WS_CLIPCHILDREN 裁掉
		// 子控件覆盖的部分，所以直接画是安全的。
		DrawContentPanels(dc, hwnd);
		PaintFieldFrames(dc, hwnd);
		EndPaint(hwnd, &ps);
		return 0;
	}

	case WM_CTLCOLORSTATIC: {
		HDC dc = reinterpret_cast<HDC>(wp);
		HWND ctl = reinterpret_cast<HWND>(lp);
		// ★ 必须 OPAQUE + 明确的底色，不能只设 TRANSPARENT：
		//   父窗口的绘制区被 WS_CLIPCHILDREN 裁掉了子控件那块，面板的白底
		//   根本没画到 STATIC 底下；TRANSPARENT 下 STATIC 又不擦背景 ⇒
		//   会直接露出父窗口 WM_ERASEBKGND 的灰底（实测踩到）。
		const bool onPanel = g_panelText.count(ctl) > 0;
		const COLORREF bg = onPanel ? kHeaderBg : kBg;
		SetBkMode(dc, OPAQUE);
		SetBkColor(dc, bg);
		// 底部说明 / 字段提示用次级灰，其余用主文字色（与主窗口层次一致）。
		if (ctl == g_hCfgNote || ctl == g_hLogStatus || g_hintText.count(ctl)) {
			SetTextColor(dc, kTextSecondary);
		} else {
			SetTextColor(dc, kTextPrimary);
		}

		static HBRUSH bgBrush = nullptr;
		static HBRUSH panelBrush = nullptr;
		if (!bgBrush) { bgBrush = CreateSolidBrush(kBg); }
		if (!panelBrush) { panelBrush = CreateSolidBrush(kHeaderBg); }
		return reinterpret_cast<LRESULT>(onPanel ? panelBrush : bgBrush);
	}

	// 自绘按钮 / 复选框的底色也走这里 —— 不处理的话按钮会先用系统
	// COLOR_BTNFACE 擦一遍，在面板/工具条上留下色差方块。
	case WM_CTLCOLORBTN: {
		HDC dc = reinterpret_cast<HDC>(wp);
		HWND ctl = reinterpret_cast<HWND>(lp);
		const bool onPanel = g_panelText.count(ctl) > 0;
		const COLORREF bg = onPanel ? kHeaderBg : kBg;
		SetBkMode(dc, OPAQUE);
		SetBkColor(dc, bg);
		static HBRUSH bgBrush = nullptr;
		static HBRUSH panelBrush = nullptr;
		if (!bgBrush) { bgBrush = CreateSolidBrush(kBg); }
		if (!panelBrush) { panelBrush = CreateSolidBrush(kHeaderBg); }
		return reinterpret_cast<LRESULT>(onPanel ? panelBrush : bgBrush);
	}

	case WM_CTLCOLOREDIT:
	case WM_CTLCOLORLISTBOX: {
		HDC dc = reinterpret_cast<HDC>(wp);
		SetTextColor(dc, kTextPrimary);
		SetBkColor(dc, kHeaderBg);
		static HBRUSH whiteBrush = nullptr;
		if (!whiteBrush) { whiteBrush = CreateSolidBrush(kHeaderBg); }
		return reinterpret_cast<LRESULT>(whiteBrush);
	}

	case WM_DRAWITEM: {
		DRAWITEMSTRUCT* dis = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
		if (dis->CtlType == ODT_LISTBOX) {
			if (dis->CtlID == IDC_LOGLIST) { DrawLogItem(dis); return TRUE; }
			if (dis->CtlID == IDC_SECLIST) { DrawSectionItem(dis); return TRUE; }
			return FALSE;
		}
		if (dis->CtlType == ODT_BUTTON) {
			// 自绘按钮 / 复选框：按 BS_OWNERDRAW 的惯例，我们从控件文字取标题。
			const int len = GetWindowTextLengthW(dis->hwndItem);
			std::wstring text(static_cast<size_t>(len) + 1, L'\0');
			GetWindowTextW(dis->hwndItem, text.data(), len + 1);
			text.resize(static_cast<size_t>(len));

			// 复选框：控件自己不带 BS_AUTOCHECKBOX（BS_OWNERDRAW 不能和它组合），
			// 所以勾选值存在 g_checkState 里，由 BN_CLICKED 切换。
			const bool isCheck = (dis->CtlID == IDC_AUTOSCROLL
				|| dis->CtlID == IDC_ONLYHIGH
				|| dis->CtlID == IDC_ONLYBLOCK
				|| (dis->CtlID >= IDC_FIELD_BASE
					&& g_checkState.count(dis->hwndItem) > 0));
			BtnState state = StateOf(dis->hwndItem);
			if (dis->itemState & ODS_SELECTED) { state = BtnState::Pressed; }
			if (isCheck) {
				// 底色：字段复选框在白色面板上，日志页那三个在灰色工具条上。
				const COLORREF bg = g_panelText.count(dis->hwndItem) ? kHeaderBg : kBg;
				DrawCheckBox(dis->hDC, dis->rcItem, text.c_str(),
					CheckOf(dis->hwndItem),
					state != BtnState::Normal,
					g_ctlFocused.count(dis->hwndItem) && g_ctlFocused[dis->hwndItem],
					bg);
			} else {
				// 「保存」是主按钮（强调色描边）；其余中性。
				const bool primary = (dis->CtlID == IDC_SAVE);
				DrawActionButton(dis->hDC, dis->rcItem, text.c_str(), primary, false, state);
			}
			return TRUE;
		}
		break;
	}

	case WM_MOUSEMOVE: {
		const POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
		const int tab = HitTestTab(pt);
		if (tab != g_hoverTab) {
			g_hoverTab = tab;
			RECT strip = { 0, kTabBarTop, 4096, kTabBarTop + kTabBarH };
			InvalidateRect(hwnd, &strip, FALSE);
		}
		if (!g_trackingLeave) {
			g_trackingLeave = true;
			TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
			TrackMouseEvent(&tme);
		}
		return 0;
	}

	case WM_MOUSELEAVE: {
		g_trackingLeave = false;
		if (g_hoverTab != -1) {
			g_hoverTab = -1;
			RECT strip = { 0, kTabBarTop, 4096, kTabBarTop + kTabBarH };
			InvalidateRect(hwnd, &strip, FALSE);
		}
		return 0;
	}

	case WM_TIMER:
		if (wp == 1) { ReadMore(); }
		return 0;

	case WM_COMMAND: {
		const int id = LOWORD(wp);
		const int code = HIWORD(wp);

		if (id == IDC_TABAREA) { return 0; }

		// ---- 自绘复选框：BS_OWNERDRAW 不会自动切换勾选值，必须自己翻 ----
		// （BS_OWNERDRAW 与 BS_AUTOCHECKBOX 互斥，所以状态由 g_checkState 自管。）
		if (code == BN_CLICKED) {
			HWND ctl = reinterpret_cast<HWND>(lp);
			if (ctl && g_checkState.count(ctl)) {
				g_checkState[ctl] = !g_checkState[ctl];
				InvalidateRect(ctl, nullptr, FALSE);
				if (ctl == g_hAutoScroll) {
					g_log.autoScroll = g_checkState[ctl];
				} else if (ctl == g_hOnlyHigh || ctl == g_hOnlyBlock) {
					RebuildLogView();
				} else {
					TouchPending();   // 字段复选框：立刻标记「未保存」
				}
				return 0;
			}
		}

		if (id == IDC_SECLIST && code == LBN_SELCHANGE) {
			const int sel = static_cast<int>(SendMessageW(g_hSecList, LB_GETCURSEL, 0, 0));
			if (sel >= 0 && sel < kSectionCount) {
				BuildSection(sel);
				LayoutAll();
				ShowPage(0);
				InvalidateRect(hwnd, nullptr, TRUE);   // 表单面板标题要跟着换
			}
			return 0;
		}
		if (id == IDC_RELOAD) {
			if (HasUnsaved()) {
				if (MessageBoxW(g_main, L"有未保存的修改，重新加载会丢弃它们。继续？",
					L"重新加载", MB_ICONQUESTION | MB_YESNO) != IDYES) {
					return 0;
				}
			}
			g_pendingScalars.clear();
			g_pendingLists.clear();
			g_cfg.Load(ResolveConfigPath());
			SetWindowTextW(g_hCfgPath, CfgPathDisplay().c_str());
			BuildSection(g_section);
			LayoutAll();
			ShowPage(0);
			return 0;
		}
		if (id == IDC_SAVE) {
			SaveAll();
			return 0;
		}
		if (id == IDC_OPENCFGDIR) {
			OpenInExplorer(g_cfg.path, true);
			return 0;
		}
		if (id == IDC_LOGCOMBO && code == CBN_SELCHANGE) {
			const int sel = static_cast<int>(SendMessageW(g_hLogCombo, CB_GETCURSEL, 0, 0));
			ChooseLogTarget(sel, false);
			return 0;
		}
		if (id == IDC_LOGBROWSE) {
			const std::wstring start = g_log.path.empty() ? DirOf(g_cfg.path) : DirOf(g_log.path);
			const std::wstring picked = PickFolderFile(hwnd, start);
			if (!picked.empty()) { OpenLogFile(picked, false); }
			return 0;
		}
		if (id == IDC_OPENLOGDIR) {
			if (!g_log.path.empty() && FileExistsW(g_log.path)) { OpenInExplorer(g_log.path, true); }
			else if (!g_log.path.empty()) { OpenInExplorer(DirOf(g_log.path), false); }
			return 0;
		}
		if (id == IDC_PAUSE) {
			g_log.paused = !g_log.paused;
			SetWindowTextW(g_hPause, g_log.paused ? L"继续" : L"暂停");
			g_log.status = g_log.paused ? L"已暂停" : L"跟随中（实时）";
			if (!g_log.paused) { ReadMore(); }
			UpdateLogStatus();
			return 0;
		}
		if (id == IDC_CLEAR) {
			SendMessageW(g_hLogList, LB_RESETCONTENT, 0, 0);
			g_log.all.clear();
			UpdateLogStatus();
			return 0;
		}
		if (id == IDC_FILTER && code == EN_CHANGE) {
			RebuildLogView();
			return 0;
		}
		// 字段输入框 / 下拉框一改就标记「未保存」（理由见 TouchPending）。
		// 注意 IDC_FILTER(1015) 远小于 IDC_FIELD_BASE(3000)，不会误伤。
		if (id >= IDC_FIELD_BASE && (code == EN_CHANGE || code == CBN_SELCHANGE)) {
			TouchPending();
			return 0;
		}
		break;
	}

	case WM_LBUTTONDOWN: {
		const POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
		if (pt.y >= kTabBarTop && pt.y < kTabBarTop + kTabBarH) {
			const int page = HitTestTab(pt);
			if (page >= 0 && page != g_page) { ShowPage(page); }
		}
		return 0;
	}

	case WM_SETCURSOR: {
		// 悬停在页签上给个手型，暗示"这里可以点"（主窗口同款行为）。
		const POINT pt = { GET_X_LPARAM(GetMessagePos()), GET_Y_LPARAM(GetMessagePos()) };
		POINT client = pt;
		ScreenToClient(hwnd, &client);
		if (client.y >= kTabBarTop && client.y < kTabBarTop + kTabBarH
			&& HitTestTab(client) >= 0) {
			SetCursor(LoadCursor(nullptr, IDC_HAND));
			return TRUE;
		}
		break;
	}

	case WM_CLOSE:
		if (HasUnsaved()) {
			if (MessageBoxW(hwnd, L"有未保存的修改，确定退出吗？", L"退出",
				MB_ICONQUESTION | MB_YESNO) != IDYES) {
				return 0;
			}
		}
		DestroyWindow(hwnd);
		return 0;

	case WM_DESTROY:
		KillTimer(hwnd, 1);
		CloseLogFile();
		DestroyFields();
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

// ===========================================================================
//  自检模式（无界面）—— 用于构建后验收，不依赖 GUI 自动化。
//    r3shieldcore-cfg.exe --selftest [工作目录]
//  写报告到 <工作目录>\r3shieldcore_cfg_selftest.txt（UTF-8 + BOM），
//  返回 0 = 全过，1 = 有失败。
// ===========================================================================
namespace {

int RunSelfTest(const std::wstring& workDirIn) {
	std::wstring workDir = workDirIn;
	if (workDir.empty()) { workDir = ExeDir(); }
	CreateDirectoryW(workDir.c_str(), nullptr);

	// 控制台输出（若父进程有控制台）。中文只进报告文件，控制台保持 ASCII。
	if (AttachConsole(ATTACH_PARENT_PROCESS)) {
		FILE* f = nullptr;
		freopen_s(&f, "CONOUT$", "w", stdout);
	}

	std::string report;
	int pass = 0, fail = 0;
	auto Check = [&](bool ok, const char* name) {
		if (ok) { ++pass; } else { ++fail; }
		report += ok ? "[PASS] " : "[FAIL] ";
		report += name;
		report += "\r\n";
		if (GetStdHandle(STD_OUTPUT_HANDLE)) {
			printf("%s %s\n", ok ? "[PASS]" : "[FAIL]", name);
		}
	};

	// ---- 夹具：带 BOM、CRLF、中文注释、行内注释、列表键、示例注释 ----
	const std::string fixture =
		std::string("\xEF\xBB\xBF") +
		W2U8(L"# 测试用配置（自检生成，可删）\r\n") +
		W2U8(L"mode=log                  # 运行模式\r\n") +
		W2U8(L"hook_file=0               # 文件监控\r\n") +
		W2U8(L"ark_enabled=1\r\n") +
		W2U8(L"exclude=C:\\Old\r\n") +
		W2U8(L"exclude=D:\\Old2\r\n") +
		W2U8(L"# exclude=C:\\Example（示例注释，不该被动）\r\n") +
		W2U8(L"log=r3shieldcore-events.log\r\n");

	const std::wstring fixturePath = workDir + L"\\r3shieldcore_cfg_selftest.ini";
	{
		HANDLE h = CreateFileW(fixturePath.c_str(), GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		DWORD wrote = 0;
		const bool ok = (h != INVALID_HANDLE_VALUE)
			&& WriteFile(h, fixture.data(), static_cast<DWORD>(fixture.size()), &wrote, nullptr)
			&& wrote == fixture.size();
		if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); }
		Check(ok, "write fixture ini");
	}

	ConfigFile cfg;
	Check(cfg.Load(fixturePath), "load fixture");
	Check(cfg.hasBom, "BOM detected");
	Check(cfg.eol == "\r\n", "CRLF detected");
	Check(cfg.GetScalar("mode", "") == "log", "parse mode=log");
	Check(cfg.GetScalar("hook_file", "") == "0", "parse hook_file=0");
	Check(cfg.GetScalar("log", "") == "r3shieldcore-events.log", "parse log=...");

	{
		const std::vector<std::string> ex = cfg.GetList("exclude");
		Check(ex.size() == 2, "parse exclude count == 2");
		Check(ex.size() >= 1 && ex[0] == "C:\\Old", "exclude[0] == C:\\Old");
		Check(ex.size() >= 2 && ex[1] == "D:\\Old2", "exclude[1] == D:\\Old2");
	}

	// ---- 应用改动 ----
	std::map<std::string, std::string> scalars;
	std::map<std::string, std::vector<std::string>> lists;
	scalars["mode"] = "block";
	scalars["hook_file"] = "1";
	scalars["ark_scan_ms"] = "3000";            // 文件里原本没有 -> 应追加
	lists["exclude"] = { "E:\\New" };            // 两行并成一行

	const std::string content = cfg.BuildNewContent(scalars, lists);

	Check(content.compare(0, 3, "\xEF\xBB\xBF") == 0, "output keeps BOM");
	Check(content.find("mode=block") != std::string::npos, "value replaced: mode=block");
	Check(content.find(W2U8(L"# 运行模式")) != std::string::npos, "inline Chinese comment preserved");
	Check(content.find("hook_file=1") != std::string::npos, "value replaced: hook_file=1");
	Check(content.find("ark_enabled=1") != std::string::npos, "untouched key preserved");
	Check(content.find("log=r3shieldcore-events.log") != std::string::npos, "untouched log= preserved");
	Check(content.find("exclude=E:\\New") != std::string::npos, "list rewritten");
	Check(content.find("exclude=C:\\Old") == std::string::npos, "old list entry removed");
	Check(content.find("exclude=D:\\Old2") == std::string::npos, "second old list entry removed");
	Check(content.find(W2U8(L"# exclude=C:\\Example")) != std::string::npos, "commented example untouched");
	Check(content.find("ark_scan_ms=3000") != std::string::npos, "absent key appended");

	// 行数守恒：删掉 1 行 exclude、加 1 行 ark_scan_ms -> 行数不变。
	{
		size_t nl = 0;
		for (char c : content) { if (c == '\n') { ++nl; } }
		size_t nl0 = 0;
		for (char c : fixture) { if (c == '\n') { ++nl0; } }
		Check(nl == nl0, "line count preserved (2 exclude -> 1, +1 appended)");
	}

	// ---- 落盘往返 ----
	{
		std::wstring err;
		Check(cfg.SaveContent(content, err), "SaveContent succeeds");
		std::string back;
		HANDLE h = CreateFileW(fixturePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			char buf[8192]; DWORD got = 0;
			while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) { back.append(buf, got); }
			CloseHandle(h);
		}
		Check(back == content, "round-trip: file content == built content");
	}

	// ---- 负对照：写到不存在的目录必须**失败**（不能静默成功）----
	{
		ConfigFile bad;
		bad.path = workDir + L"\\no_such_dir_zzz\\r3shieldcore.ini";
		std::wstring err;
		const bool ok = bad.SaveContent("x=1\r\n", err);
		Check(!ok, "negative control: save to missing dir fails");
	}

	// ---- 报告 ----
	{
		std::string body = std::string("\xEF\xBB\xBF") + W2U8(L"R3 ShieldCore 配置与日志 —— 自检报告\r\n")
			+ W2U8(L"夹具: ") + W2U8(fixturePath) + "\r\n\r\n" + report;
		WCHAR tail[128] = {};
		swprintf_s(tail, L"\r\n通过 %d / 失败 %d\r\n", pass, fail);
		body += W2U8(tail);

		const std::wstring reportPath = workDir + L"\\r3shieldcore_cfg_selftest.txt";
		HANDLE h = CreateFileW(reportPath.c_str(), GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (h != INVALID_HANDLE_VALUE) {
			DWORD wrote = 0;
			WriteFile(h, body.data(), static_cast<DWORD>(body.size()), &wrote, nullptr);
			CloseHandle(h);
		}
		if (GetStdHandle(STD_OUTPUT_HANDLE)) {
			printf("selftest: %d passed, %d failed\n", pass, fail);
		}
	}

	return fail == 0 ? 0 : 1;
}

}  // namespace

// ===========================================================================
//  入口
// ===========================================================================
int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int) {
	// 命令行：--selftest [工作目录] / --section N / --page N
	{
		int argc = 0;
		LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		if (argv) {
			bool selfTest = false;
			std::wstring workDir;
			for (int i = 1; i < argc; ++i) {
				if (wcscmp(argv[i], L"--selftest") == 0) {
					selfTest = true;
				} else if (selfTest && workDir.empty()) {
					workDir = argv[i];
				} else if (wcscmp(argv[i], L"--section") == 0 && i + 1 < argc) {
					g_startSection = _wtoi(argv[++i]);
				} else if (wcscmp(argv[i], L"--page") == 0 && i + 1 < argc) {
					g_startPage = _wtoi(argv[++i]);
				}
			}
			LocalFree(argv);
			if (selfTest) { return RunSelfTest(workDir); }
		}
	}

	g_inst = inst;

	INITCOMMONCONTROLSEX icc = {};
	icc.dwSize = sizeof(icc);
	icc.dwICC = ICC_STANDARD_CLASSES;
	InitCommonControlsEx(&icc);

	CreateUiFonts();

	WNDCLASSEXW wc = {};
	wc.cbSize = sizeof(wc);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = WndProc;
	wc.hInstance = inst;
	wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wc.hbrBackground = nullptr;   // 背景全自绘（WM_ERASEBKGND + WM_PAINT）
	wc.lpszClassName = L"R3ShieldCoreCfgWnd";
	wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
	wc.hIconSm = LoadIconW(inst, MAKEINTRESOURCEW(1));
	if (!RegisterClassExW(&wc)) {
		MessageBoxW(nullptr, L"窗口类注册失败。", L"R3 ShieldCore 配置与日志", MB_ICONERROR);
		return 1;
	}

	// 初始尺寸与主窗口一致（1024×740），窗口样式也对齐：
	// WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME
	// ★ 加上 WS_CLIPCHILDREN：父窗口重绘时不覆盖子控件（否则页签栏/面板
	//   一刷就把列表和输入框擦掉一片）。
	const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU
		| WS_MINIMIZEBOX | WS_THICKFRAME | WS_CLIPCHILDREN;

	g_main = CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"R3 ShieldCore 配置与日志",
		style, CW_USEDEFAULT, CW_USEDEFAULT, 1024, 740,
		nullptr, nullptr, inst, nullptr);
	if (!g_main) {
		MessageBoxW(nullptr, L"窗口创建失败。", L"R3 ShieldCore 配置与日志", MB_ICONERROR);
		return 1;
	}

	ShowWindow(g_main, SW_SHOW);
	UpdateWindow(g_main);

	MSG msg = {};
	while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	return static_cast<int>(msg.wParam);
}
