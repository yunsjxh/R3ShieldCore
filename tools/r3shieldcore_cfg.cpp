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
//    · 日志页：看**事件日志**（v81 起优先向引擎要**实时**流，引擎没跑回落读文件）
//      与**服务日志**（服务写的文件）；支持暂停、关键字过滤、只看高危、只看被拦。
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
#include <clocale>

// ---------------------------------------------------------------------------
//  共享头（与主程序 / 引擎**同一份**，铁律 195 / 127）
// ---------------------------------------------------------------------------
//  「高级」页（v80 从主程序整块搬来）要用的四个共享头，外加两个"生产同源"的
//  伪造 codec —— 「改前/改后」对照算的就是引擎真正会写出来的那些字节。
//  ★ 这些头全部 `inline`/纯头，**不需要链引擎的 lib**：
//    配置工具仍然是"不注入、不挂钩、不依赖引擎在跑"的独立进程。
#include <r3shieldcore/rules_codec.h>
#include <r3shieldcore/spoof_apply_codec.h>
#include <r3shieldcore/rules_file.h>
#include <r3shieldcore/advanced_quiz.h>
#include <r3shieldcore/md_inline.h>
#include <r3shieldcore/cfg_launch.h>
// ★ v81：向引擎要数据的**管道协议客户端**。
//   日志页的「事件日志」这一项不再自己去 tail 文件，而是向引擎要它**进程内**
//   那份事件流（`R3ShieldCoreStats` 的环形缓冲 —— 它不进共享内存，只能跨进程问）。
//   协议 / 转义 / 连接语义全在共享头里，两侧同一份（铁律 127）。
//   ⚠️ 只在**引擎确实在跑**时走这条路；引擎没在跑 ⇒ **回落**成"读日志文件"，
//      本工具仍然"不依赖引擎"（这是它一直以来的定位）。
#include <r3shieldcore/cfg_ipc.h>
// ★ 托盘图标（关闭窗口 = 收进托盘）。与主程序**同一份**实现 —— 铁律 127。
//   ⚠️ 回调消息名必须用 `kCallbackMessageCfg`（与主程序**不同**）：两个 exe
//      各注册各的，免得同一台机器上互相看着像"同一个程序的图标"（见头文件）。
#include <r3shieldcore/tray_icon.h>
// ★ v83：液态玻璃材质（背景模糊 + 圆角 SDF + 折射/色散/rim/噪点/投影）。
//   与主程序**同一份**实现 —— 铁律 127（各写一份 ⇒ 材质参数慢慢分叉且不报错）。
#include <r3shieldcore/ui_material.h>
#include "registry_spoof_codec.h"
#include "clipboard_spoof_codec.h"

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

// ★ 托盘（关闭窗口 = 收进通知区；用户 2026-10-17 要求）。
//
//   ⚠️ 这里有个**本工具特有**的坑：`--quiet` 自动拉起（主程序点「高级」时
//      顺手拉起我们）用的是 `SW_SHOWMINNOACTIVE` —— 那种情况下窗口
//      本来就该安静地待在任务栏，**不该**被当成"收进托盘"（会白弹一次气泡）。
//      所以下面用 `g_tray.autoLaunched` 把它区分开。
struct {
	R3ShieldCoreTray::TrayIcon icon;
	bool windowHidden = false;
	bool reallyExiting = false;   // 用户从托盘菜单选了「退出」⇒ 真退
	bool autoLaunched = false;    // `--quiet` 自动拉起（不是用户主动打开的）
} g_tray;

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
	// ★ v81：「立即同步」按钮（保存后请引擎热应用）。
	//   ⚠️ 日志页**没有**"数据来源"复选框了 —— 「事件日志」这一项**本身**就是
	//      服务端实时流（引擎没跑时自动回落读文件），见 `ChooseLogTarget`。
	IDC_SYNCNOW,
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
const COLORREF kSpoofed         = RGB(123, 31, 162);  // ColorSpoofed：替换/伪造语义色（紫）
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
const int kTabCount   = 3;    // 配置 / 日志 / 高级（★ v80：高级页从主程序搬来）
const int kContentTop = kTabBarTop + kTabBarH + 1;   // 101：内容区起点

// ---------------------------------------------------------------------------
// v83 液态玻璃：背景缓存 + 面板层缓存（与主程序同一套）
//
// ★ 与主程序的差别（刻意保留）：cfg 的**正文区有原生子控件**（EDIT / 下拉框 /
//   列表），所以玻璃层只负责"背景 + 面板"，子控件照旧由系统绘制、下面垫浅色底
//   （见 WM_CTLCOLORSTATIC 那段注释）。玻璃在控件底下"绕开"，不去硬啃透明控件。
// ---------------------------------------------------------------------------
R3ShieldCoreUi::GlassSurface g_glass;
bool g_glassWantBackdrop = true;
ULONGLONG g_glassMovedAt = 0;

float CfgDpiScale(HWND hwnd) {
	using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
	static GetDpiForWindowFn fn = nullptr;
	static bool resolved = false;
	if (!resolved) {
		HMODULE user = GetModuleHandleW(L"user32.dll");
		fn = user ? reinterpret_cast<GetDpiForWindowFn>(
			GetProcAddress(user, "GetDpiForWindow")) : nullptr;
		resolved = true;
	}
	UINT dpi = 96;
	if (fn && hwnd) {
		const UINT got = fn(hwnd);
		if (got > 0) {
			dpi = got;
		}
	}
	return static_cast<float>(dpi) / 96.0f;
}
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
// ★ v81：「立即同步」按钮（保存后请引擎热应用）。
HWND g_hSyncNow = nullptr;
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
	// ★ v83：外观交给玻璃层（背景模糊 + 圆角 + 折射 + rim + 投影）。
	//   这里只**登记矩形** + 画标题；玻璃层在下一帧按这张表合成
	//   （两帧收敛，见 ui_material.h 的 GlassSurface::CommitPanels）。
	//   玻璃不可用 ⇒ 退回原来的白底圆角，一像素不变。
	if (g_glass.active) {
		g_glass.AddPanel(rect.left, rect.top, rect.right, rect.bottom,
			R3ShieldCoreUi::DefaultTheme().panelRadius * CfgDpiScale(g_main),
			R3ShieldCoreUi::DefaultTheme().tintIdle);
	} else {
		HBRUSH brush = CreateSolidBrush(kHeaderBg);
		HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);
	}

	if (title) {
		RECT titleRect = { rect.left + 16, rect.top + 12, rect.right - 16, rect.top + 34 };
		DrawTextSimple(dc, title, titleRect, titleFont, titleColor, DT_LEFT | DT_SINGLELINE);
	}
}

// 3 参版本：标题字体/颜色写死。
//
// ★ 存在的唯一理由：主程序里那版 `DrawPanel` 就是 3 参（`g_labelFont` +
//   `ColorTextPrimary`），「高级」页整块搬过来时用的就是这个签名。
//   与其改 4 个调用点，不如在这里补一个**行为完全一致**的重载（铁律 127：
//   语义只有一处；这里只是把"省略参数时用什么"钉死）。
void DrawPanel(HDC dc, RECT rect, PCWSTR title) {
	DrawPanel(dc, rect, title, g_fontUI, kTextPrimary);
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
		// ★ 面板标题保持**中性** —— 内容跟着上面的下拉框走
		//   （事件日志 / 服务日志 / 浏览选的文件），写死"事件日志"会与内容不符。
		DrawPanel(dc, L.logPanel, L"日志内容", g_fontBold, kTextPrimary);
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
		const int btnW1 = 96, btnW2 = 76, btnW3 = 120, btnW4 = 96, gap = 8;
		const int x4 = cx - btnW4;
		const int x3 = x4 - gap - btnW3;
		const int x2 = x3 - gap - btnW2;
		const int x1 = x2 - gap - btnW1;
		const int ty = L.cfgToolbar.top;

		if (g_hCfgLabel) { MoveWindow(g_hCfgLabel, kPadding, ty + 5, 70, 20, TRUE); }
		if (g_hCfgPath) { MoveWindow(g_hCfgPath, kPadding + 74, ty + 5, (x1 - 14) - (kPadding + 74), 20, TRUE); }
		if (g_hReload) { MoveWindow(g_hReload, x1, ty, btnW1, kRowH, TRUE); }
		if (g_hSave) { MoveWindow(g_hSave, x2, ty, btnW2, kRowH, TRUE); }
		// ★ v81：「立即同步」—— 让**正在跑的引擎**重读 ini 并热应用 `mode`。
		//   没有它的话，"改了 mode 保存"只在下次重启引擎时生效，而界面上
		//   完全看不出来（配置文件变了、引擎还在用旧的）——本项目最忌讳的
		//   "看着像生效了"。
		if (g_hSyncNow) { MoveWindow(g_hSyncNow, x3, ty, btnW3, kRowH, TRUE); }
		if (g_hOpenCfgDir) { MoveWindow(g_hOpenCfgDir, x4, ty, btnW4, kRowH, TRUE); }

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

// 前置声明：`AppendLogLine` 定义在下面（文件读取那一段），
// 但引擎数据源那一段（v81）先用到它 —— 两条路要往**同一个**列表里塞，
// 这正是"引擎流"和"读文件"行为一致的前提。
void AppendLogLine(const std::wstring& line);

// ===========================================================================
//  ★ v81：向**引擎**要事件流（管道客户端）
// ===========================================================================
//
//  为什么要有这一段：
//    「事件日志」页原来自己去 tail `r3shieldcore-events.log`。文件是**注入 DLL**
//    写的，所以它有两个天生缺陷：
//      ① **慢一拍** —— DLL 落盘到界面看到之间隔着文件缓冲；
//      ② **看不到"没落盘的东西"** —— 比如引擎刚启动的那几条，或者日志文件
//         被轮转 / 权限拦住的时候，界面就"静默地什么都没有"。
//
//    v81 起改为**问引擎要**：引擎手里那份事件流是**进程内**的环形缓冲
//    （`R3ShieldCoreStats`），拿到的就是它**当前**知道的一切，不必经过文件。
//
//  ★ 但它**不能变成硬依赖**：本工具一直的定位是"不注入、不挂钩、不依赖引擎在跑"
//    （见文件头）。所以：
//      · 引擎在跑  ⇒ 默认走引擎（"数据来源：引擎（实时）"）；
//      · 引擎没在跑 ⇒ **自动回落**读日志文件，状态栏明说"引擎未运行，已回落读文件"。
//    两条路都用同一个 `AppendLogLine`，界面的过滤 / 暂停 / 自动滚动行为完全一致。
//
//  ★ 增量游标：`LatestSerial`。服务端按**序号**给，而不是"行号"或"字节偏移" ——
//    序号是环形缓冲自己的记账，不受文件轮转 / 截断影响，也不会因为
//    "同一行被写了两次"而错位。

struct EngineLogCursor
{
	bool everConnected = false;   // 历史上连上过（用来区分"从没在跑"和"刚退出"）
	bool connectedLast = false;   // 上一拍是否连上
	ULONG sinceSerial = 0;        // 下一次要的起点（服务端回传的 latest）
	ULONG lastTotal = 0;          // 服务端累计写过多少条（诊断用）
	std::wstring lastError;       // 最近一次失败原因（给状态栏）
};

EngineLogCursor g_engineLog;

// 「当前选中的日志项是不是**事件日志**」—— 它决定数据从哪儿来：
//   · true  ⇒ **优先向服务端（引擎）要**进程内事件流；引擎不可用则**回落**读事件日志文件；
//   · false ⇒ 读**文件**（服务日志，或用户「浏览…」选的自定义文件）。
//
// ★★ 这里**没有**"数据来源"复选框 —— 「事件日志」这一项**本身**就是这个语义。
//    加一个复选框等于把同一件事表达两遍，而且两遍会打架（勾着复选框再选别的文件，
//    选择会被静默忽略）。见铁律 **265**。
bool g_useEngineSource = true;

// ★ v81 核对开关：`R3SHIELDCORE_PREVIEW_LOGSRC=event|svc` —— 预览模式下**钉死**
//   日志页选哪一项（探针不会去点下拉框）。只在设了变量时生效 ⇒ 生产路径行为不变。
//   ⚠️ 这个变量名是**代次标记**（`check_dist_sync.sh` 的 v81 节按它查 exe），别改名。
bool g_previewLogSrcSvc = false;

// 从引擎取一批增量。返回 true = 这一拍真的拿到了**引擎的**数据。
bool ReadMoreFromEngine() {
	if (!g_useEngineSource) { return false; }

	const auto r = R3ShieldCoreCfgIpc::Call(
		R3ShieldCoreCfgIpc::BuildLogRequest(g_engineLog.sinceSerial,
			R3ShieldCoreCfgIpc::kMaxLogBatch));

	if (!r.Ok) {
		// ★ 失败**不改游标** —— 引擎重启会从 1 重新计数，
		//   这时候 `sinceSerial` 比引擎的 `latest` 大，会把**新的一批全吞掉**
		//   （"引擎重启后界面再也没有新日志"的经典原因）。下面按 latest 判一次。
		g_engineLog.connectedLast = false;
		g_engineLog.lastError = U82W(r.Error);
		return false;
	}

	const ULONG latest = R3ShieldCoreCfgIpc::ToULong(
		R3ShieldCoreCfgIpc::FindKeyed(r.Reply, "latest", "0"), 0);
	const ULONG total = R3ShieldCoreCfgIpc::ToULong(
		R3ShieldCoreCfgIpc::FindKeyed(r.Reply, "total", "0"), 0);

	// ★ 引擎重启检测：序号是**从 1 开始**的，一旦回传的 latest 比我们要的起点小，
	//   说明对面是一个**新的**引擎进程 ⇒ 游标归零、把缓冲从头取一遍。
	if (latest < g_engineLog.sinceSerial) {
		g_engineLog.sinceSerial = 0;
	}
	if (total < g_engineLog.lastTotal) {
		// 同上：total 只会单调增，变小 ⇒ 换了个引擎。
		g_engineLog.lastTotal = 0;
	}

	int added = 0;
	for (const std::string& line : r.Reply.Payload) {
		ULONG serial = 0;
		std::string text;
		if (!R3ShieldCoreCfgIpc::ParseLogPayloadLine(line, serial, text)) { continue; }
		AppendLogLine(U82W(text));
		++added;
	}
	if (latest > g_engineLog.sinceSerial) {
		g_engineLog.sinceSerial = latest;
	}
	g_engineLog.lastTotal = total;
	g_engineLog.everConnected = true;
	g_engineLog.connectedLast = true;
	g_engineLog.lastError.clear();
	(void)added;
	return true;
}

void UpdateLogStatus() {
	if (!g_hLogStatus) { return; }
	WCHAR buf[512] = {};
	// 三态措辞：引擎实时 / 事件日志（引擎没跑，回落文件）/ 服务日志（就是文件）。
	const WCHAR* src = g_useEngineSource
		? (g_engineLog.connectedLast ? L"引擎（实时）" : L"日志文件（引擎未运行）")
		: L"日志文件";
	swprintf_s(buf, L"数据来源：%s    %s    共 %llu 行  |  显示 %d 行  |  已读 %llu 字节",
		src,
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
	// ★ v81：选了「事件日志」就**优先问引擎**（实时、不经文件缓冲）；
	//   引擎不可用则**回落读文件**。
	//
	//   为什么要"两条都留"而不是二选一：
	//     · 引擎在跑 ⇒ 引擎的数据**更全更及时**（连"还没落盘的"都有）；
	//     · 引擎没跑 ⇒ 文件里通常仍有**上一次运行**的日志（`r3shieldcore-log-replay`
	//       的机制同理：历史不该因为引擎退出就看不见）。
	//   两条路的输出都进同一个 `AppendLogLine`，界面行为（过滤/暂停/滚动）一致。
	//
	// ★★ 回落是**临时**的，不是"降级"：`g_useEngineSource` **不**被清掉，
	//    所以引擎后来起来了，下一拍就自动切回实时流（不需要用户再点一下）。
	//    旧版把标志位清掉 ⇒ 引擎后启动也永远读文件，那才是真缺陷。
	if (g_useEngineSource) {
		if (ReadMoreFromEngine()) {
			if (!g_log.paused) { UpdateLogStatus(); }
			return;
		}
		// 这一拍没连上（引擎没跑 / 刚退出 / 接口不可用）——
		// 只改**状态栏措辞**，然后继续往下走去读文件。
		g_log.status = g_engineLog.lastError.empty()
			? L"引擎未运行，显示事件日志文件"
			: (L"引擎接口不可用（" + g_engineLog.lastError + L"），显示事件日志文件");
	}
	if (g_log.path.empty()) { UpdateLogStatus(); return; }

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

	g_log.status.clear();

	bool wantEngine = false;
	if (comboIdx == 0) {
		// 「事件日志」—— 数据**优先向服务端（引擎）要**；下面这个文件路径是
		// 引擎没在跑时的**回落**，同时也是"历史不该因为引擎退出就看不见"的保证。
		wantEngine = true;
		// ★ 切换来源会把列表清空（`OpenLogFile(..., false)` ⇒ `ResetLogView`）
		//   ⇒ 引擎游标也要归零，否则切回来时只会取到"切换之后"的增量、
		//     前面的内容永远补不回来（界面看着像"日志丢了一段"）。
		g_engineLog.sinceSerial = 0;
		g_engineLog.lastTotal = 0;

		// 优先用配置里的 log=，相对路径按引擎 exe 同目录解析
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
		// 「服务日志」—— 开机自启服务写的文件，和引擎不是一回事 ⇒ 纯文件读取。
		wantEngine = false;
		target = exeDir + L"\\r3shieldcore-svc.log";
	} else {
		return;  // 自定义：等用户浏览
	}

	g_useEngineSource = wantEngine;
	OpenLogFile(target, false);
	// ★ 状态栏在 `OpenLogFile` **之后**写：它失败时会填"无法打开（文件不存在或不可读）"，
	//   而"事件日志"这条路的**主状态**是"跟随引擎事件流"（文件只是回落）。
	//   反过来的话，引擎在跑、文件没落盘时，底部会同时显示
	//   "数据来源：引擎（实时）" 和 "无法打开…"，自相矛盾。
	if (wantEngine) { g_log.status = L"跟随引擎事件流"; }

	// ★ 给**探针**看的判据行（预览模式才有日志文件可读；生产路径 stdout 没重定向，
	//   这行只是走个空）。两件事一起报：
	//     · `来源=event|svc`  —— 当前选中的是哪一项；
	//     · `项数=N`          —— 下拉框有几项。**这一条是"控制台日志已删除"的判据**
	//       （应当恒为 2；哪天又被加回来，这条立刻红）。
	//   ⚠️ 用窄 `%s` 传 ASCII（不碰 locale）—— `%ls` 依赖 setlocale，搬过家会整行截断（铁律 252）。
	{
		const int items = g_hLogCombo
			? static_cast<int>(SendMessageW(g_hLogCombo, CB_GETCOUNT, 0, 0)) : 0;
		printf("[log] 日志页已就绪 来源=%s 项数=%d\n", wantEngine ? "event" : "svc", items);
	}
	(void)initial;
}

// ---------- 布局（LayoutFields / LayoutAll 已上移到 BuildSection 之前，
//            与 ComputeLayout 放在一起，避免两处几何漂移）----------

	// =================================================================
	// ★ v77/v78/v80：「高级」页 —— 规则脚本的**编辑台 + 预览台**
	//   （v80 从主程序 `r3shieldcore_gui.cpp` **整块搬到这里**，成为配置工具的
	//     第 3 个页签；主程序那侧只剩一个"跳过来"的入口。搬的时候逐字保留，
	//     只换了字体/颜色/布局常量的名字 —— 见本文件顶部的别名区。）
	// =================================================================
	//
	// 这一页回答两个问题：
	//   ① **我写的规则，会把 API 的返回值改成什么？**（v77 起的改前/改后对照）
	//   ② **怎么把规则写出来、存下去，让引擎真的用上？**（v78 起的编辑 + 落盘）
	//
	// ★ 三个界面状态（同一页，互斥）
	//   ① 闸门未过  —— 整块内容区换成**三道 Win32 题**（编辑区锁住）。
	//   ② 刚全对    —— 展示三道题的解析 + 「开始编辑」。
	//   ③ 已解锁    —— 左：规则表 + 编辑区；右：改前/改后字节对照。
	//
	// ★★ 三道题与命令行控制台是**同一套题**（`shared/r3shieldcore/advanced_quiz.h`）
	//   抄两份必然漂（铁律 127）：漂了之后"控制台过了、界面过不了"，
	//   而两边都不会报错。
	//
	// ★★ 规则文件在哪、谁读它（**这一页最容易让人误解的地方**）
	//   · 路径：`%ProgramData%\R3 Shield Core\r3shieldcore-rules.txt`
	//     （目录不存在则回退到本程序所在目录）—— 与 `r3shieldcore.ini` 同目录。
	//   · 引擎侧（`r3shieldcore-lib.dll`，跑在**每个被注入进程**里）**启动时
	//     各读一次**。⇒ **存完规则要重启引擎才生效**，页面上必须写清。
	//   · 路径解析是**同一份**代码（`shared/r3shieldcore/rules_file.h`）——
	//     界面存到 A、引擎读 B 是最难查的一类"存了没用"。
	//
	// ★★ 规则的**总闸**仍是 ini 的三个开关（`spoof_reg` / `spoof_clipboard` /
	//   `spoof_reg_enum`，默认**关**）。开关关着 ⇒ 规则一律不生效。
	//   页面必须把这件事**显示出来**（读的是引擎真正读到的那份配置）——
	//   否则用户写完规则没反应，界面上看不出任何原因（铁律 97）。
	//
	// ★ 它**不注入、不跑引擎、不碰真实 API**（铁律 175 因此不适用）：
	//   注册表样例是**本进程栈上的合成缓冲区**，剪贴板样例是**本进程自己
	//   GlobalAlloc 出来的** HGLOBAL。所以开发机上可以放心跑，配合
	//   `--gui-preview` 就能建窗截图核对。
	//
	// ★ 「改后」是怎么算出来的（每一步都走**生产路径**，不是"照着生产写的"）
	//   注册表值  ：`RSpoof::LocateDataRegion` 定位 -> `RApply::ApplyRegValue` 落值
	//   剪贴板    ：`RClip::FormatLabel` 出格式名 -> 命中规则走
	//               `RApply::BuildClipText`；没命中回落**生产** `RClip::BuildFake`
	//   注册表枚举：`RRule::Eval` 逐个子键问规则，命中「隐藏」的从列表去掉
	//               ⚠️ 未命中**一律保留** —— 这一页**不**模拟 `protect_reg` 判据
	//                  （那是引擎侧配置，界面拿不到；硬编一个假判据才是骗人）。
	//   ⚠️ 这一页只证明"规则 -> 字节"这一步；**引擎真的照做**由
	//      `tools/v78_guard_ut.cpp` 直接驱动生产的 `Evaluate` 证明。

	namespace RRule = R3ShieldCoreRuleScript;
	namespace RApply = R3ShieldCoreSpoofApply;
	namespace RClip = R3ShieldCoreClipboardSpoof;
	namespace RSpoof = R3ShieldCoreRegistrySpoof;

	// ================================================================
	// 闸门状态（v78）
	// ================================================================
	bool g_advQuizPassed = false;      // 三道题全对
	bool g_advWhyDismissed = false;    // 解析看完、开始编辑
	int  g_advPick[3] = { -1, -1, -1 }; // 每题选了什么（0..3 = A..D，-1 = 没选）
	int  g_advWrongMask = 0;           // 上次提交时哪几题错（bit i 置 1）
	bool g_advSubmitted = false;       // 提交过至少一次
	int  g_advAttempts = 0;            // 提交次数（诊断用）

	// ================================================================
	// 编辑状态（v78）
	// ================================================================
	HWND g_advEdit = nullptr;          // 原生 EDIT 子控件（中文输入必须靠它）
	int  g_advSelected = -1;           // 规则表里选中的序号（-1 = 没选）
	int  g_advHoverChip = -1;          // 悬停的模板按钮
	int  g_advPressedChip = -1;        // 按下的模板按钮
	// ★ 底部按钮的悬停 / 按下态。
	//   主程序里这两个变量和"页头按钮"那套放在一起（那边页头按钮是按客户区
	//   宽度算位置的另一套体系）；配置工具里没有页头按钮 ⇒ 就近放在这儿。
	int  g_advHoverAction = -1;
	int  g_advPressedAction = -1;
	std::wstring g_advStatus;          // 编辑区下方那行状态（保存/载入结果）
	WCHAR g_advPath[MAX_PATH] = L"";   // 规则文件路径（解析一次后缓存）

	// ★ v78：**仅预览模式**用的规则文件路径重定向（空 = 不重定向）。
	//
	//   只有 `RunPreview`（`--gui-preview`）会填它，生产路径永远是空的 ——
	//   所以引擎读的、界面写的仍然是 `rules_file.h` 解析出来的那**同一个**
	//   真实路径（铁律 195 没有被破坏）。
	//
	//   为什么需要它：自动核对要的是**确定性**。不重定向的话，探针读到的
	//   规则条数取决于这台机器上 `%ProgramData%\R3 Shield Core\` 里
	//   有没有那个文件、里面有几条 —— 于是"规则=3"这条判据在别人机器上
	//   会随机红，而真正要验证的（页面画出来没有）反而被淹没。
	//   顺带一个好处：自动核对**完全不碰**用户的真实规则文件。
	WCHAR g_previewRulesPath[MAX_PATH] = L"";

	// ★ v79：预览模式下**预置编辑框内容**（只为把"输入中"的实时提示截下来）。
	//
	//   为什么需要：实时提示是"输入时才有"的 —— 探针不会打字（UIPI 拦、
	//   自绘界面也没有控件可点），没有这个开关就永远只能截到"空输入框"，
	//   而"提示到底会不会跟着输入变"就只能靠人眼（铁律 24/28）。
	//   ⚠️ 只有 `RunPreview` 会填它 ⇒ 生产路径恒为空，用户看到的编辑框
	//      仍然是空的（不是"带着一条别人的规则启动"）。
	std::wstring g_previewEditText;

	// ★ v82：`R3SHIELDCORE_PREVIEW_ADV=cycle` —— 让界面**真的走一遍**
	//   闸门 -> 解析 -> 编辑台 的状态切换（-1 = 关）。
	//
	//   为什么需要这么一个"演练"模式（实测踩过）：
	//     直接置状态建窗（`=editor`）时，窗口**第一次**画出来就是编辑台 ——
	//     中间没有那两次重绘。而"重绘不擦背景"这类缺陷**只在切换时**现形：
	//     旧状态的摘要/说明行留在原地，新状态的字叠上去 ⇒ 糊成一团。
	//     ⇒ 光靠"直接置状态"的截图**永远抓不到它**（铁律 24/28 那一类：
	//       自动化看不见 = 等于没有判据）。
	//     这个模式用**定时器**驱动，走的正是真实点击那条路
	//     （`InvalidateRect(hwnd, nullptr, FALSE)`，与按钮点击同款），
	//     所以它复现的就是用户看到的那一屏。
	int g_previewCycleStep = -1;

	// 演练用的定时器 id（现有的 1 号是日志刷新，别撞）。
	constexpr UINT kCycleTimerId = 2;

	// ---------------- 按钮 ----------------
	//
	// ★ 一次把**所有**按钮列出来，再按界面状态决定"这一屏显示哪几个" ——
	//   不这么做的话，"按钮位置"会在三个状态里各写一份布局（铁律 127）。
	enum AdvButton
	{
		AdvButtonNone = -1,
		AdvButtonQuizSubmit = 0,   // ① 提交答案
		AdvButtonQuizReset = 1,    // ① 清空作答
		AdvButtonWhyDone = 2,      // ② 开始编辑
		AdvButtonApply = 3,        // ③ 把编辑框内容加为新规则 / 更新选中那条
		AdvButtonDelete = 4,       // ③ 删除选中
		AdvButtonSave = 5,         // ③ 保存到规则文件
		AdvButtonLoad = 6,         // ③ 从规则文件载入
		AdvButtonSeed = 7,         // ③ 重置为示例规则
		AdvButtonClear = 8,        // ③ 清空规则表
		AdvButtonAll = 9,
	};

	// 当前状态该显示哪些按钮。
	bool AdvButtonVisible(int index)
	{
		if (!g_advQuizPassed) {
			return index == AdvButtonQuizSubmit || index == AdvButtonQuizReset;
		}
		if (!g_advWhyDismissed) {
			return index == AdvButtonWhyDone;
		}
		return index == AdvButtonApply || index == AdvButtonDelete
			|| index == AdvButtonSave || index == AdvButtonLoad
			|| index == AdvButtonSeed || index == AdvButtonClear;
	}

	PCWSTR AdvButtonLabel(int index)
	{
		switch (index) {
		case AdvButtonQuizSubmit: return L"提交答案";
		case AdvButtonQuizReset:  return L"清空作答";
		case AdvButtonWhyDone:    return L"开始编辑规则";
		case AdvButtonApply:      return L"加入 / 更新规则";
		case AdvButtonDelete:     return L"删除选中";
		case AdvButtonSave:       return L"保存到规则文件";
		case AdvButtonLoad:       return L"从规则文件载入";
		case AdvButtonSeed:       return L"重置为示例规则";
		case AdvButtonClear:      return L"清空规则表";
		default: return L"";
		}
	}

	// ---------------- 模板（结构化点选搭骨架） ----------------
	//
	// ★ 点「面」＝插入一整条骨架；点「算子」「动作」＝在光标处插入该词。
	//   骨架用**中文 DSL 原文**（不是直接拼 Rule 结构体）—— 必须走用户手敲
	//   那条**同一条解析路径**（铁律 22）。
	PCWSTR kAdvFaceChips[3] = {
		L"当 注册表值 的 值名 含 \"\" 时 替换为 \"\"",
		L"当 注册表枚举 的 子键名 含 \"\" 时 隐藏",
		L"当 剪贴板 的 格式 等于 文本 时 替换为 \"\"",
	};
	PCWSTR kAdvFaceChipLabel[3] = { L"注册表值", L"注册表枚举", L"剪贴板" };

	PCWSTR kAdvOpChips[5] = { L"等于", L"含", L"匹配 /正则/", L"开头", L"结尾" };
	PCWSTR kAdvOpChipText[5] = { L"等于", L"含", L"匹配 //", L"开头", L"结尾" };

	PCWSTR kAdvActChips[6] = { L"替换为 \"\"", L"替换为 空", L"替换为 全零",
		L"隐藏", L"拒绝", L"放行" };

	constexpr int kAdvChipRowA = 3;    // 面
	constexpr int kAdvChipRowB = 5;    // 算子
	constexpr int kAdvChipRowC = 6;    // 动作
	constexpr int kAdvChipCount = kAdvChipRowA + kAdvChipRowB + kAdvChipRowC;

	PCWSTR AdvChipLabel(int index)
	{
		if (index < kAdvChipRowA) {
			return kAdvFaceChipLabel[index];
		}
		index -= kAdvChipRowA;
		if (index < kAdvChipRowB) {
			return kAdvOpChips[index];
		}
		return kAdvActChips[index - kAdvChipRowB];
	}

	// 芯片宽度：首次调用测一次，之后查表。
	//
	// ★ 为什么不在布局函数里测：布局函数会被**命中测试**调用（没有 DC），
	//   在那里量文字要么传 DC 要么再建一个 —— 两条路都会让"画"和"点"
	//   用上不同的宽度。缓存一次，两边读同一张表。
	int AdvChipWidth(int index)
	{
		static int widths[kAdvChipCount] = {};
		static bool ready = false;
		if (!ready) {
			HDC dc = GetDC(nullptr);
			HGDIOBJ old = SelectObject(dc, g_fontUI);
			for (int i = 0; i < kAdvChipCount; i++) {
				RECT r = { 0, 0, 0, 0 };
				DrawTextW(dc, AdvChipLabel(i), -1, &r, DT_CALCRECT | DT_SINGLELINE);
				widths[i] = (r.right - r.left) + 20;   // 左右各 10px 内边距
				if (widths[i] < 52) {
					widths[i] = 52;
				}
			}
			SelectObject(dc, old);
			ReleaseDC(nullptr, dc);
			ready = true;
		}
		return widths[index];
	}

	// ---------------- 布局（绘制与命中共用一份，避免"画在这儿点在那儿"） ----------------
	constexpr int AdvButtonHeight = 28;
	constexpr int AdvButtonWidth = 140;
	constexpr int AdvLineHeight = 21;
	constexpr int AdvMaxHexBytes = 16;   // 每行最多显示多少字节（超了打 "..."）
	constexpr int AdvTableRowHeight = 19;
	constexpr int AdvChipHeight = 22;
	constexpr int AdvChipGap = 4;
	constexpr int AdvEditHeight = 26;
	// ★ v79：输入框下面那两行「实时提示」（第一行 = 解析结果，第二行 = 下一步）。
	constexpr int AdvHintLineHeight = 20;

	struct AdvLayout
	{
		int Left = 0, Right = 0;
		int SummaryTop = 0;
		// ★ 摘要行下面那一行说明（"编辑区已锁定…" / "全对 —— 闸门打开…"）。
		//   单独一个字段而不是"PanelTop - 22"：那样写的话，一旦有人调
		//   PanelTop 的偏移，说明行会**无声地叠到摘要行上** ——
		//   自绘界面里两张文字叠在一起没有任何报错，只有截图看得出来
		//   （实测过一次：两行字糊成一团）。
		int NoteTop = 0;
		int PanelTop = 0, PanelBottom = 0;
		int RulesLeft = 0, RulesRight = 0;
		int DiffLeft = 0, DiffRight = 0;
		int ButtonTop = 0;
		RECT Buttons[AdvButtonAll] = {};

		// 编辑区（只在"已解锁"状态用得上）
		//
		// ★ v79 顺序（自上而下）：规则表 -> **输入框** -> 模板按钮 -> 实时提示
		//   -> 动作状态。用户要的是"像 IDE 一样，可以点**下方**的按钮、
		//   也可以直接输入" —— 所以按钮必须在输入框下面（原来在上面）。
		int TableTop = 0, TableBottom = 0;
		int EditTop = 0, EditBottom = 0;
		int ChipTop = 0;
		RECT ChipRow[3][6] = {};
		int HintTop = 0, HintBottom = 0;
		int StatusTop = 0;
		// 贴底那一行「总闸（ini）」（它是"规则为什么没生效"的答案，最该常在）。
		int GatesTop = 0;

		// 闸门（只在"未过 / 刚全对"状态用得上）
		int QuizColTop = 0, QuizColWidth = 0;
		int QuizOptTop = 0;
	};

	// 规则表最多画几行 —— **绘制与命中读同一个数**。
	//
	// ★ 为什么按高度算、不写死 6：窗口最小高度是 640（见 WM_GETMINMAXINFO）。
	//   那一档下 6 行表格 + 输入框 + 按钮 + 提示 + 状态会**超出**面板底部，
	//   把输入框挤到看不见 —— 而"能编辑"正是这一页存在的全部理由。
	//   写死的话这个故障**没有任何报错**，只有把窗口拉到最矮才看得到。
	//
	// ★ 为什么不能用"画 6 行、命中判 6 行"之外的第三个常量：那正是
	//   "看得见却点不中 / 点得中却看不见"的来源（铁律 127）。
	int AdvTableMaxRows(const AdvLayout& layout)
	{
		const int avail = layout.PanelBottom - layout.PanelTop;
		// 除表格外的固定开销 —— 与 `AdvLayoutFor` 里那串间距**同一批常量**：
		//   面板标题 46
		// + 表格下间距 10 + 输入框 AdvEditHeight + 8
		// + 芯片 3×(AdvChipHeight+AdvChipGap) + 8
		// + 提示 2×AdvHintLineHeight + 4
		// + 状态 18 + 贴底总闸 20 + 兜底 8
		const int fixed = 46 + 10 + AdvEditHeight + 8
			+ 3 * (AdvChipHeight + AdvChipGap) + 8
			+ 2 * AdvHintLineHeight + 4
			+ 18 + 20 + 8;
		int rows = (avail - fixed) / AdvTableRowHeight;
		if (rows < 2) {
			rows = 2;
		}
		if (rows > 6) {
			rows = 6;
		}
		return rows;
	}

	AdvLayout AdvLayoutFor(const RECT& client)
	{
		AdvLayout layout = {};
		layout.Left = kPadding;
		layout.Right = client.right - kPadding;
		layout.SummaryTop = kTabBarTop + kTabBarH + 12;
		// 摘要行 22px + 说明行 18px + 间距 ⇒ 面板从摘要行下方 46px 起。
		// 之前是 26px，导致说明行（画在 PanelTop-22）正好压在摘要行上。
		layout.NoteTop = layout.SummaryTop + 24;
		layout.PanelTop = layout.NoteTop + 22;

		// 底部按钮条固定贴底（在询问统计栏之上）—— 与其它页同一套算法，
		// 窗口被拉矮时按钮不会跑到可视区外。
		// ★ 主程序那版这里要减掉底部"询问统计栏"的高度（PromptSummaryHeight()）——
		//   配置工具没有那一栏 ⇒ 直接留一个 kPadding 的底边距（搬运时唯一改了
		//   一处"数值来源"的地方，其余几何逐字保留）。
		layout.ButtonTop = client.bottom - kPadding - AdvButtonHeight;
		layout.PanelBottom = layout.ButtonTop - 34;   // 再往上留一行状态文字

		const int gap = 14;
		const int contentWidth = layout.Right - layout.Left - gap;
		const int rulesWidth = contentWidth * 52 / 100;
		layout.RulesLeft = layout.Left;
		layout.RulesRight = layout.Left + rulesWidth;
		layout.DiffLeft = layout.RulesRight + gap;
		layout.DiffRight = layout.Right;

		// 按钮：只给**当前状态该显示**的那些分配位置，从左往右排。
		int x = layout.Left;
		for (int i = 0; i < AdvButtonAll; i++) {
			if (!AdvButtonVisible(i)) {
				continue;
			}
			layout.Buttons[i] = { x, layout.ButtonTop, x + AdvButtonWidth,
				layout.ButtonTop + AdvButtonHeight };
			x += AdvButtonWidth + 8;
		}

		// ---- 编辑区（左栏内）：输入框 -> 按钮 -> 实时提示 -> 状态 ----
		//
		// ★ v79：顺序与 v78 **相反**。用户的原话是"编辑器做成类似于 IDE 的
		//   情况：可以点击**下方**的按钮，也可以直接输入，输入的时候要有提示"。
		//   所以自上而下必须是：**输入框** → 模板按钮（在下方）→ 提示。
		const int tableRows = AdvTableMaxRows(layout);
		layout.TableTop = layout.PanelTop + 46;
		layout.TableBottom = layout.TableTop + tableRows * AdvTableRowHeight + 4;

		layout.EditTop = layout.TableBottom + 10;
		layout.EditBottom = layout.EditTop + AdvEditHeight;

		layout.ChipTop = layout.EditBottom + 8;
		for (int row = 0; row < 3; row++) {
			const int count = (row == 0) ? kAdvChipRowA : (row == 1 ? kAdvChipRowB : kAdvChipRowC);
			int cx = layout.RulesLeft + 16;
			const int cy = layout.ChipTop + row * (AdvChipHeight + AdvChipGap);
			for (int i = 0; i < count; i++) {
				const int global = (row == 0) ? i
					: (row == 1 ? kAdvChipRowA + i : kAdvChipRowA + kAdvChipRowB + i);
				const int w = AdvChipWidth(global);
				layout.ChipRow[row][i] = { cx, cy, cx + w, cy + AdvChipHeight };
				cx += w + AdvChipGap;
			}
		}

		layout.HintTop = layout.ChipTop + 3 * (AdvChipHeight + AdvChipGap) + 8;
		layout.HintBottom = layout.HintTop + 2 * AdvHintLineHeight;
		layout.StatusTop = layout.HintBottom + 4;

		// 贴底：总闸那一行。★ 用 max 兜一下：窗口被拉到极矮时，
		// 宁可它压在状态行下面，也不要它盖住输入框/提示（内容区优先）。
		layout.GatesTop = layout.PanelBottom - 20;
		if (layout.GatesTop < layout.StatusTop + 18) {
			layout.GatesTop = layout.StatusTop + 18;
		}

		// ---- 闸门（整块内容区，三列）----
		layout.QuizColTop = layout.PanelTop + 40;
		const int quizGap = 12;
		layout.QuizColWidth = (layout.Right - layout.Left - quizGap * 2) / 3;
		layout.QuizOptTop = layout.QuizColTop + 26 + 96;   // 标题 + 题干框

		return layout;
	}

	// 闸门第 col 列第 opt 个选项的矩形（0..3 = A..D）。
	//
	// ★ 高度给 **48**（三行文字）而不是 22：选项原文里带着**对齐用的连续空格**
	//   （与控制台共用同一份文本，不能改），而这一页每列只有 ~300px 宽 ——
	//   一行放不下。22px + 单行 + `DT_END_ELLIPSIS` 会把括号里的关键部分
	//   截掉（实测截成 `A. STATUS_OBJECT_NAME_NOT_FOUND (0...`），
	//   而**被截掉的那半截往往正是区分对错的地方**。
	//   ⚠️ 高度是**定值**不是"按内容算"：命中测试要用同一个矩形，
	//      变高的行会让"画在这儿、点在那儿"。
	constexpr int AdvQuizOptHeight = 48;
	constexpr int AdvQuizOptStep = AdvQuizOptHeight + 4;

	RECT AdvQuizOptionRect(const AdvLayout& layout, int col, int opt)
	{
		const int left = layout.Left + col * (layout.QuizColWidth + 12);
		const int top = layout.QuizOptTop + opt * AdvQuizOptStep;
		return { left + 8, top, left + layout.QuizColWidth - 8, top + AdvQuizOptHeight };
	}

	int HitTestAdvButton(POINT point, const RECT& client)
	{
		if (g_page != R3ShieldCoreCfg::kPageAdvanced) {
			return AdvButtonNone;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		for (int i = 0; i < AdvButtonAll; i++) {
			if (!AdvButtonVisible(i)) {
				continue;
			}
			if (PtInRect(&layout.Buttons[i], point)) {
				return i;
			}
		}
		return AdvButtonNone;
	}

	int HitTestAdvChip(POINT point, const RECT& client)
	{
		if (g_page != R3ShieldCoreCfg::kPageAdvanced || !g_advQuizPassed || !g_advWhyDismissed) {
			return -1;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		for (int row = 0; row < 3; row++) {
			const int count = (row == 0) ? kAdvChipRowA : (row == 1 ? kAdvChipRowB : kAdvChipRowC);
			for (int i = 0; i < count; i++) {
				if (PtInRect(&layout.ChipRow[row][i], point)) {
					return (row == 0) ? i
						: (row == 1 ? kAdvChipRowA + i : kAdvChipRowA + kAdvChipRowB + i);
				}
			}
		}
		return -1;
	}

	// 闸门选项的命中（未过闸门时才有效）。
	// 返回 列号（0..2）；`optOut` 收选项号（0..3）。没命中返回 -1。
	int HitTestAdvQuizOption(POINT point, const RECT& client, int* optOut)
	{
		if (g_page != R3ShieldCoreCfg::kPageAdvanced || g_advQuizPassed) {
			return -1;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		for (int col = 0; col < R3ShieldCoreQuiz::Count(); col++) {
			for (int opt = 0; opt < 4; opt++) {
				RECT r = AdvQuizOptionRect(layout, col, opt);
				if (PtInRect(&r, point)) {
					if (optOut) {
						*optOut = opt;
					}
					return col;
				}
			}
		}
		return -1;
	}

	// 规则表某一行的命中（已解锁状态才有效）。
	//
	// ★ 行数上限必须与 `AdvDrawEditor` 里画的那 6 行**同一个数** ——
	//   画 6 行、这里判 8 行的话，点"第 7 行"（画面上是空白）会选中一条
	//   看不见的规则；反过来则是"看得见却点不中"。所以两边都读
	//   `AdvTableRowHeight` 与同一个 maxRows。
	int HitTestAdvTableRow(POINT point, const RECT& client)
	{
		if (g_page != R3ShieldCoreCfg::kPageAdvanced || !g_advQuizPassed || !g_advWhyDismissed) {
			return -1;
		}
		const int total = RRule::Count();
		if (total <= 0) {
			return -1;
		}
		const AdvLayout layout = AdvLayoutFor(client);
		// ★ v79：行数上限改读 `AdvTableMaxRows`（与绘制**同一个函数**）——
		//   写死 6 的话，窗口拉到最矮（表格只剩 2 行）时，第 3~6 行明明
		//   没画出来却仍然"点得中"：点在空白处会选中一条看不见的规则。
		const int maxRows = AdvTableMaxRows(layout);
		const int rows = (total < maxRows) ? total : maxRows;
		const int bottom = layout.TableTop + rows * AdvTableRowHeight;
		if (point.x < layout.RulesLeft + 8 || point.x > layout.RulesRight - 8) {
			return -1;
		}
		if (point.y < layout.TableTop || point.y >= bottom) {
			return -1;
		}
		return (point.y - layout.TableTop) / AdvTableRowHeight;
	}

	// ---------------- EDIT 子控件（v78） ----------------
	//
	// ★ 为什么非要用**原生** EDIT：这一页是纯自绘窗口（一个子控件都没有），
	//   而中文规则必须能敲中文 ⇒ 需要 **IME**。自绘 + 自己处理
	//   `WM_IME_*` 等于重写一个输入框，代价和风险都不划算。
	//
	// ★ 与双缓冲的冲突（铁律 181）：主窗口整块 `BitBlt` 会**盖掉**子控件。
	//   解法是给主窗口加 `WS_CLIPCHILDREN` —— 父窗口的绘制区里"子控件占的
	//   那块"被裁掉，`BitBlt` 就不会画到 EDIT 上。这是必须的前提，不是优化。
	//   ⚠️ 加了之后**父窗口不能再指望自己画子控件底下的像素** ⇒ EDIT 自己
	//      带 `WS_BORDER` 且用 `WM_CTLCOLOREDIT` 给它白底（见 WndProc）。
	//
	// ★ 位置只在 `AdvLayoutFor` 里算一次（铁律 182：坐标只在创建点出现一次
	//   的控件 = 定时炸弹）。本函数只负责"把算出来的位置应用上去"。
	// 编辑框的**控件 ID**。
	//
	// ★ 为什么必须给 ID（v79）：输入时要能收到 `EN_CHANGE` 才能实时刷新提示，
	//   而 `EN_CHANGE` 是**通过 WM_COMMAND 通知父窗口**的 —— 父窗口靠
	//   `LOWORD(wParam)`（= 控件 ID）认出是哪个控件。给 `nullptr` 就没有 ID，
	//   通知收不到，提示只能"点了「加入」才更新"。
	constexpr int AdvEditId = 4001;

	void AdvCreateEdit(HWND parent)
	{
		if (g_advEdit) {
			return;
		}
		g_advEdit = CreateWindowExW(
			0, L"EDIT", L"",
			WS_CHILD | ES_AUTOHSCROLL | WS_BORDER | WS_TABSTOP,
			0, 0, 10, 10, parent,
			reinterpret_cast<HMENU>(static_cast<INT_PTR>(AdvEditId)),
			g_inst, nullptr);
		if (g_advEdit && g_fontMono) {
			SendMessageW(g_advEdit, WM_SETFONT,
				reinterpret_cast<WPARAM>(g_fontMono), TRUE);
		}
	}

	// 「编辑框这一刻该不该显示」—— **唯一一处**判据。
	//
	// ★ 为什么要抽出来：这个条件有两个读者 —— `AdvSyncEdit`（真的去
	//   ShowWindow/SW_HIDE）和 `DrawAdvancedPage` 的核对日志（报给探针看）。
	//   写两遍必然漂（铁律 127）：漂了之后日志说"编辑框=1"、屏幕上却没有，
	//   于是探针判据变成**恒真**，而它本来是"编辑台画出来了"的唯一证据。
	bool AdvEditShouldShow()
	{
		return g_advEdit != nullptr
			&& g_page == R3ShieldCoreCfg::kPageAdvanced
			&& g_advQuizPassed
			&& g_advWhyDismissed;
	}

	// 编辑框左边留给「规则行」标签的宽度。
	//
	// ★ 为什么要有这一段：原生 EDIT 会**盖住**它底下的像素（父窗口加了
	//   `WS_CLIPCHILDREN`，父窗口画的东西进不到控件区域里）。所以标签不能
	//   和编辑框重叠 —— 重叠的表现是"标签根本没画"，而代码里明明有那一句
	//   `DrawTextSimple`，读代码永远查不出来（实测：截图里找不到"规则行"）。
	constexpr int AdvEditLabelWidth = 56;

	void AdvSyncEdit(HWND hwnd, const RECT& client)
	{
		if (!g_advEdit) {
			return;
		}
		if (!AdvEditShouldShow()) {
			if (IsWindowVisible(g_advEdit)) {
				ShowWindow(g_advEdit, SW_HIDE);
			}
			return;
		}

		const AdvLayout layout = AdvLayoutFor(client);
		const int editLeft = layout.RulesLeft + 16 + AdvEditLabelWidth;
		const int w = layout.RulesRight - 16 - editLeft;
		const int h = layout.EditBottom - layout.EditTop;
		if (w <= 0 || h <= 0) {
			return;
		}

		RECT want = { editLeft, layout.EditTop, editLeft + w, layout.EditTop + h };
		RECT have = {};
		GetWindowRect(g_advEdit, &have);
		MapWindowPoints(nullptr, hwnd, reinterpret_cast<POINT*>(&have), 2);

		if (!IsWindowVisible(g_advEdit)
			|| have.left != want.left || have.top != want.top
			|| (have.right - have.left) != w || (have.bottom - have.top) != h) {
			SetWindowPos(g_advEdit, nullptr, want.left, want.top, w, h,
				SWP_NOZORDER | SWP_NOACTIVATE);
			ShowWindow(g_advEdit, SW_SHOWNA);
		}
	}

	// 取编辑框内容（没控件时返回空串）。
	std::wstring AdvEditText()
	{
		if (!g_advEdit) {
			return L"";
		}
		const int len = GetWindowTextLengthW(g_advEdit);
		if (len <= 0) {
			return L"";
		}
		std::wstring s(static_cast<size_t>(len) + 1, L'\0');
		GetWindowTextW(g_advEdit, &s[0], len + 1);
		s.resize(static_cast<size_t>(len));
		return s;
	}

	void AdvSetEditText(const std::wstring& text)
	{
		if (g_advEdit) {
			SetWindowTextW(g_advEdit, text.c_str());
		}
	}

	// 在光标处插入一段文本（模板按钮用）。
	void AdvInsertEditText(const std::wstring& insert)
	{
		if (!g_advEdit) {
			return;
		}
		SendMessageW(g_advEdit, EM_REPLACESEL, TRUE,
			reinterpret_cast<LPARAM>(insert.c_str()));
		SetFocus(g_advEdit);
	}

	// ---------------- 示例规则 ----------------
	//
	// ★ 三条覆盖三个面 × 三种动作：
	//   #0 注册表值  ：正则匹配 -> 替换为文本（真会写进数据区）
	//   #1 剪贴板    ：等于    -> 替换为文本
	//   #2 注册表枚举：含      -> 隐藏（从列表里去掉）
	PCWSTR kAdvDemoRules[] = {
		L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"",
		L"当 剪贴板 的 格式 等于 文本 时 替换为 \"[已替换]\"",
		L"当 注册表枚举 的 子键名 含 \"Secret\" 时 隐藏",
	};

	void AdvLoadDemoRules()
	{
		RRule::Clear();
		for (PCWSTR line : kAdvDemoRules) {
			std::wstring err;
			RRule::Add(line, err, nullptr);
		}
		g_advSelected = -1;
	}

	// 规则文件的路径（解析一次后缓存）。
	const WCHAR* AdvRulesPath()
	{
		if (g_advPath[0] == L'\0') {
			// 预览模式的重定向优先（生产路径下 `g_previewRulesPath` 恒为空，
			// 见它的声明处 —— 这不是"另一条路径解析"，只是一个测试替身）。
			if (g_previewRulesPath[0] != L'\0') {
				wcsncpy_s(g_advPath, g_previewRulesPath, _TRUNCATE);
				return g_advPath;
			}
			if (!R3ShieldCoreRulesFile::ResolveRulesPath(nullptr, g_advPath, _countof(g_advPath))) {
				wcsncpy_s(g_advPath, L"(解析规则文件路径失败)", _TRUNCATE);
			}
		}
		return g_advPath;
	}

	// 首次进这一页：先试着从规则文件读；读不到再铺示例规则。
	//
	// ★ 顺序很重要：直接铺示例会把用户存过的规则**顶掉**（他下次一看
	//   "我写的规则没了"）。先读文件才是对的。
	// ★ 读不到也要**说清楚**（不能静默铺示例 —— 那与"用户存过但读失败"
	//   长得一模一样，铁律 97）。
	void AdvInitialLoad()
	{
		int ok = 0;
		int bad = 0;
		std::wstring firstErr;
		const WCHAR* path = AdvRulesPath();
		// ★ 来源要**显式打出来**：`来源=文件` / `来源=示例`。
		//   只打条数的话，"从文件读到 3 条"和"文件没有、铺了 3 条示例"
		//   在日志里长得一模一样 —— 而这两件事的后续行为完全不同
		//   （前者用户点「保存」会覆盖他自己的规则，后者是新建）。
		const WCHAR* source = L"示例";
		if (RRule::LoadFile(path, &ok, &bad, firstErr)) {
			source = L"文件";
			WCHAR buf[512] = {};
			swprintf_s(buf, L"已从规则文件载入 %d 条（无效 %d 条）：%s", ok, bad, path);
			g_advStatus = buf;
		}
		else {
			AdvLoadDemoRules();
			WCHAR buf[512] = {};
			swprintf_s(buf, L"还没有规则文件，已铺 3 条示例（保存后写入 %s）", path);
			g_advStatus = buf;
		}
		printf("[adv] 初始规则=%d 来源=%ls 路径=%ls\n", RRule::Count(), source, path);
		fflush(stdout);
	}

	// ---------------- 动作 ----------------
	void AdvQuizSubmit()
	{
		g_advSubmitted = true;
		g_advAttempts++;
		int wrongMask = 0;
		int wrong = 0;
		const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();
		for (int i = 0; i < R3ShieldCoreQuiz::Count(); i++) {
			const bool ok = (g_advPick[i] >= 0)
				&& (static_cast<WCHAR>(L'A' + g_advPick[i]) == q[i].answer);
			if (!ok) {
				wrongMask |= (1 << i);
				wrong++;
			}
		}
		g_advWrongMask = wrongMask;

		if (wrong == 0) {
			g_advQuizPassed = true;
			g_advWhyDismissed = false;
		}
		// ★ 只报"哪几题错"，**不报答案** —— 报了答案这道闸门就白设了。
		printf("[adv] 闸门提交 第%d次 错%d题 通过=%d\n", g_advAttempts, wrong,
			g_advQuizPassed ? 1 : 0);
		fflush(stdout);
	}

	void AdvQuizReset()
	{
		g_advPick[0] = g_advPick[1] = g_advPick[2] = -1;
		g_advWrongMask = 0;
		g_advSubmitted = false;
	}

	// 把编辑框里那行加入规则表（选中了就是**更新**）。
	void AdvApplyRule()
	{
		const std::wstring line = AdvEditText();
		if (line.empty()) {
			g_advStatus = L"编辑框是空的 —— 先点上面的模板按钮搭一条骨架。";
			return;
		}
		if (g_advSelected >= 0 && g_advSelected < RRule::Count()) {
			if (!RRule::RemoveAt(g_advSelected)) {
				g_advStatus = L"更新失败：选中的规则已经不在表里了。";
				return;
			}
		}
		std::wstring err;
		int index = -1;
		if (!RRule::Add(line.c_str(), err, &index)) {
			g_advStatus = L"这一行解析不了：" + err;
			return;
		}
		g_advSelected = index;
		WCHAR buf[256] = {};
		swprintf_s(buf, L"已写入第 %d 条规则（共 %d 条）。记得点「保存到规则文件」。",
			index, RRule::Count());
		g_advStatus = buf;
	}

	void AdvDeleteSelected()
	{
		if (g_advSelected < 0 || g_advSelected >= RRule::Count()) {
			g_advStatus = L"先在左边规则表里点一行。";
			return;
		}
		const int removed = g_advSelected;
		RRule::RemoveAt(removed);
		g_advSelected = -1;
		AdvSetEditText(L"");
		WCHAR buf[160] = {};
		swprintf_s(buf, L"已删除第 %d 条（还剩 %d 条）。", removed, RRule::Count());
		g_advStatus = buf;
	}

	void AdvSaveRules()
	{
		const WCHAR* path = AdvRulesPath();
		R3ShieldCoreRulesFile::EnsureParentDirectory(path);
		int count = 0;
		if (!RRule::SaveFile(path, &count)) {
			g_advStatus = std::wstring(L"保存失败（写不进去）：") + path;
			return;
		}
		WCHAR buf[600] = {};
		swprintf_s(buf, L"已保存 %d 条到 %s —— 引擎在**下次启动**时读取（每个被注入进程各读一次）。",
			count, path);
		g_advStatus = buf;
		printf("[adv] 已保存规则 %d 条 路径=%ls\n", count, path);
		fflush(stdout);
	}

	void AdvLoadRules()
	{
		const WCHAR* path = AdvRulesPath();
		int ok = 0;
		int bad = 0;
		std::wstring firstErr;
		if (!RRule::LoadFile(path, &ok, &bad, firstErr)) {
			g_advStatus = std::wstring(L"载入失败（文件打不开）：") + path;
			return;
		}
		g_advSelected = -1;
		AdvSetEditText(L"");
		WCHAR buf[600] = {};
		if (bad > 0) {
			swprintf_s(buf, L"已载入 %d 条（**%d 条解析失败**，第一条：%s）", ok, bad, firstErr.c_str());
		}
		else {
			swprintf_s(buf, L"已载入 %d 条（全部解析成功）：%s", ok, path);
		}
		g_advStatus = buf;
	}

	void PerformAdvAction(int index)
	{
		switch (index) {
		case AdvButtonQuizSubmit: AdvQuizSubmit(); break;
		case AdvButtonQuizReset:  AdvQuizReset(); break;
		case AdvButtonWhyDone:    g_advWhyDismissed = true; break;
		case AdvButtonApply:      AdvApplyRule(); break;
		case AdvButtonDelete:     AdvDeleteSelected(); break;
		case AdvButtonSave:       AdvSaveRules(); break;
		case AdvButtonLoad:       AdvLoadRules(); break;
		case AdvButtonSeed:
			AdvLoadDemoRules();
			g_advStatus = L"已重置为 3 条示例规则。";
			break;
		case AdvButtonClear:
			RRule::Clear();
			g_advSelected = -1;
			AdvSetEditText(L"");
			g_advStatus = L"规则表已清空（文件里的没动 —— 要清文件得点「保存到规则文件」）。";
			break;
		default: break;
		}
		printf("[adv] 动作 #%d 规则=%d\n", index, RRule::Count());
		fflush(stdout);
	}

	// 点规则表某一行：载入编辑框。
	void AdvSelectRule(int index)
	{
		if (index < 0 || index >= RRule::Count()) {
			return;
		}
		g_advSelected = index;
		std::wstring desc;
		if (RRule::DescribeAt(index, desc)) {
			AdvSetEditText(desc);
		}
		if (g_advEdit) {
			SetFocus(g_advEdit);
		}
	}

	// 点模板按钮。
	void AdvClickChip(int index)
	{
		if (index < 0 || index >= kAdvChipCount) {
			return;
		}
		if (index < kAdvChipRowA) {
			// 「面」= 整条骨架（替换掉编辑框内容 —— 骨架是"起手式"，
			// 追加会越积越长，反而更难改）。
			AdvSetEditText(kAdvFaceChips[index]);
		}
		else if (index < kAdvChipRowA + kAdvChipRowB) {
			AdvInsertEditText(kAdvOpChipText[index - kAdvChipRowA]);
		}
		else {
			AdvInsertEditText(kAdvActChips[index - kAdvChipRowA - kAdvChipRowB]);
		}
		if (g_advEdit) {
			SetFocus(g_advEdit);
		}
	}

	// ---------------- 显示辅助 ----------------
	std::wstring AdvHex(const BYTE* data, size_t length)
	{
		if (!data || length == 0) {
			return L"(空)";
		}
		std::wstring out;
		WCHAR cell[8] = {};
		const size_t n = (length < AdvMaxHexBytes) ? length : AdvMaxHexBytes;
		for (size_t i = 0; i < n; i++) {
			swprintf_s(cell, L"%02X ", data[i]);
			out += cell;
		}
		if (n < length) {
			out += L"...";
		}
		return out;
	}

	// 判定 -> 一句话。复用规则引擎自己的 Describe，别在这里再拼一遍语法
	// （拼两遍必然与解析器漂移 —— 那正是 v74 收敛 Action 枚举要防的事）。
	std::wstring AdvVerdictText(const RRule::Verdict& v)
	{
		if (!v.hit) {
			return L"未命中规则 · 回落内置默认行为";
		}
		std::wstring desc;
		if (!RRule::DescribeAt(v.index, desc)) {
			return L"命中规则";
		}
		WCHAR head[32] = {};
		swprintf_s(head, L"命中 #%d · ", v.index);
		return std::wstring(head) + desc;
	}

	// 造一个"真实剪贴板文本"（UTF-16 带结尾 NUL）—— 只为喂给**生产**
	// `RClip::BuildFake`，让"回落"那一格走的是真生产路径而不是模仿。
	HGLOBAL AdvBuildRealUnicodeText(const WCHAR* text)
	{
		const size_t chars = text ? wcslen(text) : 0;
		HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,
			(chars + 1) * sizeof(WCHAR));
		if (!h) {
			return nullptr;
		}
		void* p = GlobalLock(h);
		if (!p) {
			GlobalFree(h);
			return nullptr;
		}
		if (chars) {
			memcpy(p, text, chars * sizeof(WCHAR));
		}
		GlobalUnlock(h);
		return h;
	}

	void AdvDrawButton(HDC dc, const RECT& rect, PCWSTR label, bool hovered, bool pressed)
	{
		COLORREF fill = kHeaderBg;
		COLORREF border = kBorder;
		COLORREF text = kTextPrimary;
		if (pressed) {
			fill = RGB(200, 222, 244);
			border = kAccent;
			text = kAccent;
		}
		else if (hovered) {
			fill = kTabHoverBg;
			border = kTabHoverBorder;
			text = kAccent;
		}

		HBRUSH brush = CreateSolidBrush(fill);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 6, 6);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);

		DrawTextSimple(dc, label, rect, g_fontUI, text,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE);
	}

	// 模板按钮（比普通按钮矮、圆角小）。
	void AdvDrawChip(HDC dc, const RECT& rect, PCWSTR label, bool hovered)
	{
		COLORREF fill = kTabHoverBg;
		COLORREF border = kTabHoverBorder;
		if (hovered) {
			fill = RGB(214, 232, 250);
			border = kAccent;
		}
		HBRUSH brush = CreateSolidBrush(fill);
		HPEN pen = CreatePen(PS_SOLID, 1, border);
		HGDIOBJ oldBrush = SelectObject(dc, brush);
		HGDIOBJ oldPen = SelectObject(dc, pen);
		RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 5, 5);
		SelectObject(dc, oldBrush);
		SelectObject(dc, oldPen);
		DeleteObject(brush);
		DeleteObject(pen);
		DrawTextSimple(dc, label, rect, g_fontUI, kAccent,
			DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// 一行「标签 : 值」
	void AdvRow(HDC dc, int left, int right, int y, PCWSTR label,
		const std::wstring& value, COLORREF color)
	{
		DrawTextSimple(dc, label, { left, y, left + 48, y + 18 },
			g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE);
		DrawTextSimple(dc, value.c_str(), { left + 48, y, right, y + 18 },
			g_fontMono, color, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// 读一个 bool 开关的**当前生效值**。
	//
	// ★ 配置工具里没有引擎解析好的 `g_options` ⇒ 直接从**配置文件**读
	//   （`g_cfg` 就是配置页正在编辑的那一份）。判据用 `IsTrueA`，与配置页
	//   勾选框**同一个函数**（铁律 127）—— 否则会出现"配置页显示开、
	//   高级页显示关"这种自相矛盾，而两边都不报错。
	bool AdvSwitchOn(const char* key)
	{
		return IsTrueA(g_cfg.GetScalar(key, "0"));
	}

	// 把开关状态画成一行（"总闸"）—— 用户"写了规则没生效"时第一个要看的东西。
	void AdvDrawGates(HDC dc, int left, int right, int y)
	{
		const bool gateReg  = AdvSwitchOn("spoof_reg");
		const bool gateClip = AdvSwitchOn("spoof_clipboard");
		const bool gateEnum = AdvSwitchOn("spoof_reg_enum");
		WCHAR buf[256] = {};
		swprintf_s(buf, L"总闸（ini）：spoof_reg=%s  spoof_clipboard=%s  spoof_reg_enum=%s",
			gateReg ? L"开" : L"关",
			gateClip ? L"开" : L"关",
			gateEnum ? L"开" : L"关");
		const bool anyOn = gateReg || gateClip || gateEnum;
		DrawTextSimple(dc, buf, { left, y, right, y + 18 },
			g_fontUI, anyOn ? kTextPrimary : kBlocked,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// 把连续空格折成一个、并去掉首尾空格。
	//
	// ★ 只用于**显示**：闸门题的选项原文为了在控制台里对齐括号，塞了一串
	//   空格；在这一页 ~300px 宽的列里那串空格会把文字挤出可视高度。
	//   折叠是"换一种排法"，不改共享文本（`advanced_quiz.h` 一字不动）。
	//   折叠之后 `A. STATUS_INVALID_HANDLE (0xC0000008)` 这种刚好两行。
	std::wstring AdvCollapseSpaces(const WCHAR* s)
	{
		std::wstring out;
		if (!s) {
			return out;
		}
		bool prevSpace = false;
		for (const WCHAR* p = s; *p; ++p) {
			const bool isSpace = (*p == L' ' || *p == L'\t');
			if (isSpace) {
				if (!prevSpace && !out.empty()) {
					out.push_back(L' ');
				}
				prevSpace = true;
			}
			else {
				out.push_back(*p);
				prevSpace = false;
			}
		}
		while (!out.empty() && out.back() == L' ') {
			out.pop_back();
		}
		return out;
	}

	// ---------------- 极简 Markdown 渲染（题干 / 解析） ----------------
	//
	// ★ 为什么需要：`advanced_quiz.h` 的题干与解析里**本来就写着 Markdown**
	//   （`**加粗**`、`` `行内代码` ``）—— 那是给**控制台**看的记号，
	//   终端里只能这么表达强调。但这一页是**渲染**给眼睛看的：原文直接画出来，
	//   用户看到的是四个星号，而不是强调。
	//   ⇒ 必须在这一侧**解释**这些记号，而不是去改共享文本（改了两边就不一致，
	//     铁律 195）。
	//
	// ★ 解析在 `md_inline.h`（纯文本、可单测），这里只负责"画在哪个像素"。
	HFONT MdFont(R3ShieldCoreMd::Style style)
	{
		switch (style) {
		case R3ShieldCoreMd::Style::Bold: return g_fontBold ? g_fontBold : g_fontUI;
		case R3ShieldCoreMd::Style::Code: return g_fontMono;
		default:                          return g_fontUI;
		}
	}

	COLORREF MdColor(R3ShieldCoreMd::Style style, COLORREF base)
	{
		switch (style) {
		// ★ 行内代码用 Spoof 紫：这一页里紫色已经是"替换/伪造"的语义色，
		//   再借它标"这段是代码"很自然，也不引入第四种颜色。
		case R3ShieldCoreMd::Style::Code: return kSpoofed;
		default:                          return base;
		}
	}

	int MdMeasure(HDC dc, const std::wstring& s, R3ShieldCoreMd::Style style)
	{
		if (s.empty()) {
			return 0;
		}
		HGDIOBJ old = SelectObject(dc, MdFont(style));
		SIZE sz = {};
		GetTextExtentPoint32W(dc, s.c_str(), static_cast<int>(s.size()), &sz);
		SelectObject(dc, old);
		return sz.cx;
	}

	// 画一个词。代码片段带一层浅底 —— 像 IDE 里的行内代码。
	void MdDrawWord(HDC dc, int x, int y, const std::wstring& s,
		R3ShieldCoreMd::Style style, COLORREF base, int lineHeight)
	{
		if (s.empty()) {
			return;
		}
		const int w = MdMeasure(dc, s, style);
		if (style == R3ShieldCoreMd::Style::Code) {
			RECT bg = { x - 2, y + 1, x + w + 2, y + lineHeight - 1 };
			HBRUSH brush = CreateSolidBrush(RGB(238, 238, 244));
			FillRect(dc, &bg, brush);
			DeleteObject(brush);
		}
		HGDIOBJ oldFont = SelectObject(dc, MdFont(style));
		SetBkMode(dc, TRANSPARENT);
		SetTextColor(dc, MdColor(style, base));
		TextOutW(dc, x, y, s.c_str(), static_cast<int>(s.size()));
		SelectObject(dc, oldFont);
	}

	// 画一段（可含 '\n'）Markdown 文本，自动折行；返回**实际用到的高度**。
	//
	// ★ 画不下就**停在整行边界**（不画半行）—— 半行文字比"少一行"更像故障。
	int MdDraw(HDC dc, const WCHAR* text, const RECT& box, int lineHeight, COLORREF base)
	{
		if (!text) {
			return 0;
		}

		// 1) 先整段解析（逐行 -> piece），再逐行折行绘制。
		std::vector<std::vector<R3ShieldCoreMd::Piece>> lines;
		std::vector<bool> codeLines;
		R3ShieldCoreMd::ParseText(std::wstring(text), lines, codeLines);

		int x = box.left;
		int y = box.top;
		for (size_t li = 0; li < lines.size(); ++li) {
			if (li > 0) {
				y += lineHeight;
			}
			if (y + lineHeight > box.bottom) {
				break;
			}
			x = codeLines[li] ? box.left + 6 : box.left;   // 代码行整体缩一点

			// 2) piece -> 词（按空白切；空白本身也留成词，折行时才知道能断在哪）
			struct Word {
				std::wstring text;
				R3ShieldCoreMd::Style style;
				bool space;
			};
			std::vector<Word> words;
			for (const R3ShieldCoreMd::Piece& pc : lines[li]) {
				size_t s = 0;
				while (s < pc.text.size()) {
					const bool isSpace = (pc.text[s] == L' ' || pc.text[s] == L'\t');
					size_t e = s;
					while (e < pc.text.size()
						&& ((pc.text[e] == L' ' || pc.text[e] == L'\t') == isSpace)) {
						++e;
					}
					words.push_back({ pc.text.substr(s, e - s), pc.style, isSpace });
					s = e;
				}
			}

			// 3) 逐词摆放：放不下就换行（行首不摆空白）。
			for (const Word& wd : words) {
				const int w = MdMeasure(dc, wd.text, wd.style);
				if (wd.space) {
					if (x == box.left || x == box.left + 6) {
						continue;   // 行首空白丢掉
					}
					x += w;
					continue;
				}
				if (x > box.left && x + w > box.right) {
					y += lineHeight;
					x = box.left;
					if (y + lineHeight > box.bottom) {
						break;
					}
				}
				MdDrawWord(dc, x, y, wd.text, wd.style, base, lineHeight);
				x += w;
			}
		}
		return y + lineHeight - box.top;
	}

	// ---------------- 实时提示（IDE 式） ----------------
	//
	// ★ 用户要的是"输入的时候要有提示"。所以这里在**每一次输入**（EN_CHANGE）
	//   之后重算两行：
	//     第一行 = 这一行**能不能用**（√ 归一化后的一句话 / × 具体错在哪）
	//     第二行 = **下一步该写什么**（或"已经写完了，点加入"）
	//
	// ★ 为什么**不缓存**提示文本、而是在绘制时现算：
	//   提示完全由编辑框内容决定 ⇒ 现算不可能与编辑框不同步。
	//   缓存就多一份状态，而"状态与输入不一致"正是这类界面最常见的 bug
	//   （界面上显示"√ 可以解析"，点加入却报错）。
	struct AdvHint
	{
		std::wstring line1;
		std::wstring line2;
		bool ok = false;
		bool empty = true;
	};

	AdvHint AdvComputeHint()
	{
		AdvHint h = {};
		const std::wstring line = AdvEditText();

		bool blank = true;
		for (WCHAR c : line) {
			if (c != L' ' && c != L'\t') {
				blank = false;
				break;
			}
		}
		if (blank) {
			// 空的时候，提示**就是**语法速查 —— 省掉面板里那三行常驻说明。
			h.empty = true;
			h.line1 = L"提示：当 <面> [的 <字段>] <算子> <模式> 时 <动作>";
			h.line2 = L"点下面的按钮搭骨架，或直接在这里输入中文规则。";
			return h;
		}

		h.empty = false;
		RRule::Rule rule;
		std::wstring err;
		bool parsed = false;
		// ★ 包一层：`Parse` 内部虽然已经把 `std::regex_error` 兜住了，
		//   但这里是**绘制路径** —— 真抛出来就是整个界面崩掉，代价太大。
		try {
			parsed = RRule::Parse(line.c_str(), rule, err);
		}
		catch (...) {
			err = L"解析时发生异常";
		}

		if (parsed) {
			h.ok = true;
			h.line1 = L"√ 可以解析 —— " + RRule::Describe(rule);
			h.line2 = (g_advSelected >= 0)
				? L"点「加入 / 更新规则」写回选中的那一条。"
				: L"点「加入 / 更新规则」把它加到规则表。";
			return h;
		}

		h.ok = false;
		h.line1 = L"× " + err;
		const std::wstring step = RRule::NextStepHint(line.c_str());
		// ★ "已经写完却还报错"要说清楚：这时候再报"下一步该写什么"是**误导**
		//   （用户按提示补完还是错，会以为软件坏了）。
		h.line2 = step.empty()
			? L"按 × 后面的提示改；点「重置为示例规则」能看到一条标准写法。"
			: (L"下一步：" + step);
		return h;
	}

	// 给日志用的一句话（探针据此判"提示真的跟着输入变了"）。
	PCWSTR AdvHintKind()
	{
		const AdvHint h = AdvComputeHint();
		if (h.empty) {
			return L"空";
		}
		return h.ok ? L"可解析" : L"错误";
	}

	// ---------------- 闸门：未通过 ----------------
	void AdvDrawQuiz(HDC dc, const AdvLayout& layout)
	{
		const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();

		// 顶部一句说明（"为什么锁着"）。
		DrawTextSimple(dc,
			L"编辑区已锁定 —— 答对下面三道 Win32 题解锁（题目都是这个项目真踩过的坑，全对才开门）。",
			{ layout.Left, layout.NoteTop, layout.Right, layout.NoteTop + 18 },
			g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		for (int col = 0; col < R3ShieldCoreQuiz::Count(); col++) {
			const int left = layout.Left + col * (layout.QuizColWidth + 12);
			const int right = left + layout.QuizColWidth;
			RECT panel = { left, layout.PanelTop, right, layout.PanelBottom };
			DrawPanel(dc, panel, L"");

			WCHAR title[32] = {};
			swprintf_s(title, L"第 %d 题", col + 1);
			DrawTextSimple(dc, title, { left + 10, layout.QuizColTop, right - 10, layout.QuizColTop + 20 },
				g_fontUI, kAccent, DT_LEFT | DT_SINGLELINE);

			// 题干：**渲染** Markdown（`**加粗**` / `` `代码` `` / 8 空格代码行），
			// 不是原样画出来 —— 文本与控制台**同一份**（`advanced_quiz.h`），
			// 记号由这一侧解释（见 MdDraw 的注释）。
			MdDraw(dc, q[col].text,
				{ left + 10, layout.QuizColTop + 22, right - 10, layout.QuizColTop + 22 + 92 },
				18, kTextPrimary);

			for (int opt = 0; opt < 4; opt++) {
				const RECT r = AdvQuizOptionRect(layout, col, opt);
				const bool picked = (g_advPick[col] == opt);
				const bool wrong = g_advSubmitted && (g_advWrongMask & (1 << col))
					&& (g_advPick[col] == opt);

				COLORREF fill = picked ? kTabHoverBg : kHeaderBg;
				COLORREF border = picked ? kAccent : kBorder;
				if (wrong) {
					fill = RGB(253, 233, 233);
					border = kBlocked;
				}
				HBRUSH brush = CreateSolidBrush(fill);
				HPEN pen = CreatePen(PS_SOLID, 1, border);
				HGDIOBJ ob = SelectObject(dc, brush);
				HGDIOBJ op = SelectObject(dc, pen);
				RoundRect(dc, r.left, r.top, r.right, r.bottom, 4, 4);
				SelectObject(dc, ob);
				SelectObject(dc, op);
				DeleteObject(brush);
				DeleteObject(pen);

				WCHAR line[512] = {};
				swprintf_s(line, L"%lc. %ls", static_cast<WCHAR>(L'A' + opt), q[col].opt[opt]);
				// ★ 三行 + 自动换行 + **折叠连续空格**，不要 `DT_END_ELLIPSIS`：
				//   选项原文里带对齐用的连续空格（为了在**控制台**里把括号对齐），
				//   在这一页 ~300px 宽的列里那串空格会把文字挤到第三行之外，
				//   省略号再把括号里的状态码截掉 —— 而那半截往往正是区分对错的地方。
				//   折叠只影响**显示**，不动共享的题目文本（铁律 195）。
				DrawTextSimple(dc, AdvCollapseSpaces(line).c_str(),
					{ r.left + 8, r.top + 3, r.right - 6, r.bottom - 3 },
					g_fontUI, wrong ? kBlocked : kTextPrimary,
					DT_LEFT | DT_TOP | DT_WORDBREAK);
			}

			// 这一列的结果（只报对错，不报答案）。
			if (g_advSubmitted) {
				const bool ok = (g_advWrongMask & (1 << col)) == 0;
				const int resultTop = layout.QuizOptTop + 4 * AdvQuizOptStep + 2;
				DrawTextSimple(dc, ok ? L"这一题：对" : L"这一题：错（可重选）",
					{ left + 10, resultTop, right - 10, resultTop + 18 },
					g_fontUI, ok ? kAccent : kBlocked,
					DT_LEFT | DT_SINGLELINE);
			}
		}

		// 底部状态行（"错了几题"）。
		std::wstring status;
		if (!g_advSubmitted) {
			status = L"三道题都选好之后点「提交答案」。";
		}
		else if (g_advQuizPassed) {
			status = L"全对 —— 闸门打开。";
		}
		else {
			int wrong = 0;
			for (int i = 0; i < 3; i++) {
				if (g_advWrongMask & (1 << i)) {
					wrong++;
				}
			}
			WCHAR buf[160] = {};
			swprintf_s(buf, L"错 %d 题（红色那几题），改完再提交。", wrong);
			status = buf;
		}
		DrawTextSimple(dc, status.c_str(),
			{ layout.Left, layout.ButtonTop - 26, layout.Right, layout.ButtonTop - 6 },
			g_fontUI, g_advQuizPassed ? kAccent : kTextSecondary,
			DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// ---------------- 闸门：刚全对，展示解析 ----------------
	void AdvDrawWhy(HDC dc, const AdvLayout& layout)
	{
		const R3ShieldCoreQuiz::Question* q = R3ShieldCoreQuiz::Questions();

		DrawTextSimple(dc, L"全对 —— 闸门打开。下面把三道题的答案讲清楚（看懂了再点「开始编辑规则」）。",
			{ layout.Left, layout.NoteTop, layout.Right, layout.NoteTop + 18 },
			g_fontUI, kAccent, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);

		for (int col = 0; col < R3ShieldCoreQuiz::Count(); col++) {
			const int left = layout.Left + col * (layout.QuizColWidth + 12);
			const int right = left + layout.QuizColWidth;
			DrawPanel(dc, { left, layout.PanelTop, right, layout.PanelBottom }, L"");

			WCHAR title[64] = {};
			swprintf_s(title, L"第 %d 题 · 正确答案 %lc", col + 1, q[col].answer);
			DrawTextSimple(dc, title,
				{ left + 10, layout.QuizColTop, right - 10, layout.QuizColTop + 20 },
				g_fontUI, kAccent, DT_LEFT | DT_SINGLELINE);

			// 解析：同样**渲染** Markdown（原文里 `Nt*`、`KEY_WOW64_64KEY`
			// 这些是行内代码，`**不吃**` 是加粗）。
			MdDraw(dc, q[col].why,
				{ left + 10, layout.QuizColTop + 26, right - 10, layout.PanelBottom - 10 },
				18, kTextPrimary);
		}
	}

	// ---------------- 已解锁：规则表 + 编辑区（左） ----------------
	void AdvDrawEditor(HDC dc, const AdvLayout& layout)
	{
		RECT rulesPanel = { layout.RulesLeft, layout.PanelTop, layout.RulesRight, layout.PanelBottom };
		DrawPanel(dc, rulesPanel, L"规则表（点一行载入编辑框）");

		std::vector<std::wstring> all;
		RRule::ListAll(all);

		int y = layout.TableTop;
		if (all.empty()) {
			DrawTextSimple(dc, L"（还没有规则 —— 点下面的模板按钮搭一条，或「重置为示例规则」）",
				{ rulesPanel.left + 16, y, rulesPanel.right - 16, y + 20 },
				g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
		else {
			// ★ v79：行数上限与命中测试读**同一个函数**（见 AdvTableMaxRows）。
			const int maxRows = AdvTableMaxRows(layout);
			for (size_t i = 0; i < all.size() && static_cast<int>(i) < maxRows; i++) {
				const bool selected = (static_cast<int>(i) == g_advSelected);
				if (selected) {
					RECT hl = { rulesPanel.left + 8, y - 1, rulesPanel.right - 8, y + AdvTableRowHeight - 1 };
					HBRUSH b = CreateSolidBrush(kTabHoverBg);
					FillRect(dc, &hl, b);
					DeleteObject(b);
				}
				WCHAR index[16] = {};
				swprintf_s(index, L"#%u", static_cast<unsigned>(i));
				DrawTextSimple(dc, index, { rulesPanel.left + 16, y, rulesPanel.left + 46, y + 17 },
					g_fontMono, kAccent, DT_LEFT | DT_SINGLELINE);
				DrawTextSimple(dc, all[i].c_str(),
					{ rulesPanel.left + 50, y, rulesPanel.right - 16, y + 17 },
					g_fontMono, kTextPrimary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
				y += AdvTableRowHeight;
			}
			if (static_cast<int>(all.size()) > maxRows) {
				WCHAR more[64] = {};
				swprintf_s(more, L"… 还有 %d 条（编辑区仍然能改它们）",
					static_cast<int>(all.size()) - maxRows);
				DrawTextSimple(dc, more, { rulesPanel.left + 16, y, rulesPanel.right - 16, y + 17 },
					g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE);
			}
		}

		// 模板按钮（三行）。
		for (int row = 0; row < 3; row++) {
			const int count = (row == 0) ? kAdvChipRowA : (row == 1 ? kAdvChipRowB : kAdvChipRowC);
			for (int i = 0; i < count; i++) {
				const int global = (row == 0) ? i
					: (row == 1 ? kAdvChipRowA + i : kAdvChipRowA + kAdvChipRowB + i);
				AdvDrawChip(dc, layout.ChipRow[row][i], AdvChipLabel(global),
					g_advHoverChip == global || g_advPressedChip == global);
			}
		}
		// 编辑框的框线由原生 EDIT 自己画（`WS_BORDER`）；这里只画个标签。
		// ⚠️ 宽度必须 ≤ `AdvEditLabelWidth` —— 超了就会被 EDIT 盖掉一截
		//   （EDIT 的左缘 = RulesLeft + 16 + AdvEditLabelWidth，见 AdvSyncEdit）。
		DrawTextSimple(dc, L"规则行",
			{ rulesPanel.left + 16, layout.EditTop,
			  rulesPanel.left + 16 + AdvEditLabelWidth - 8, layout.EditBottom },
			g_fontUI, kTextSecondary, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
		// ⚠️ 原生 EDIT 会盖住 [RulesLeft+16, RulesRight-16] 这一段 ——
		//   主窗口有 `WS_CLIPCHILDREN`，所以这里画的任何东西都不会渗进 EDIT 里。

		// ---- 实时提示（输入时就在看的两行）----
		//
		// ★ 位置在**输入框下面**：用户敲字时视线在输入框上，提示紧跟着才看得到
		//   （掉到面板底部就等于没有）。
		{
			const AdvHint hint = AdvComputeHint();
			const COLORREF c1 = hint.empty ? kTextSecondary
				: (hint.ok ? kAccent : kBlocked);
			DrawTextSimple(dc, hint.line1.c_str(),
				{ rulesPanel.left + 16, layout.HintTop,
				  rulesPanel.right - 16, layout.HintTop + AdvHintLineHeight },
				g_fontUI, c1, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			DrawTextSimple(dc, hint.line2.c_str(),
				{ rulesPanel.left + 16, layout.HintTop + AdvHintLineHeight,
				  rulesPanel.right - 16, layout.HintBottom },
				g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		if (!g_advStatus.empty()) {
			DrawTextSimple(dc, g_advStatus.c_str(),
				{ rulesPanel.left + 16, layout.StatusTop, rulesPanel.right - 16, layout.StatusTop + 18 },
				g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		// 贴底：总闸（ini 的三个开关）。
		//
		// ★ v79 把原来那三行"语法速查"**删了** —— 输入框空着的时候，
		//   实时提示的第一行**就是**语法骨架；不空的时候它给的是
		//   "这一行对不对 / 下一步写什么"，比一张静态速查表有用得多。
		//   面 / 算子 / 动作三个词表本来就印在上面的模板按钮上。
		AdvDrawGates(dc, rulesPanel.left + 16, rulesPanel.right - 16, layout.GatesTop);
	}

	// ---------------- 已解锁：改前 / 改后 字节对照（右） ----------------
	void AdvDrawPreview(HDC dc, const AdvLayout& layout)
	{
		RECT diffPanel = { layout.DiffLeft, layout.PanelTop, layout.DiffRight, layout.PanelBottom };
		DrawPanel(dc, diffPanel, L"改前 / 改后 字节对照（生产同源 codec）");

		int dy = layout.PanelTop + 46;
		const int dleft = diffPanel.left + 16;
		const int dright = diffPanel.right - 16;

		// ---- 样例 1：注册表值（REG_SZ）----
		{
			const WCHAR* keyPath = L"HKEY_CURRENT_USER\\Software\\R3ShieldCoreDemo\\Vault";
			const WCHAR* valueName = L"Password";
			const WCHAR* secret = L"hunter2";

			// 合成一个 class 2 的 KEY_VALUE_PARTIAL_INFORMATION：
			//   +0 TitleIndex   +4 Type   +8 DataLength   +12 Data[]
			const size_t secretBytes = (wcslen(secret) + 1) * sizeof(WCHAR);
			BYTE buffer[12 + 64] = {};
			ULONG type = 1 /*REG_SZ*/;
			ULONG dataLength = static_cast<ULONG>(secretBytes);
			memcpy(buffer + 4, &type, sizeof(type));
			memcpy(buffer + 8, &dataLength, sizeof(dataLength));
			memcpy(buffer + 12, secret, secretBytes);
			const ULONG total = static_cast<ULONG>(12 + secretBytes);

			RSpoof::DataRegion region = {};
			const bool located = RSpoof::LocateDataRegion(2, buffer, sizeof(buffer), total, region);
			const size_t regionOffset = located ? region.offset : 12;
			const size_t regionLength = located ? region.length : secretBytes;

			BYTE before[64] = {};
			memcpy(before, buffer + regionOffset, regionLength);

			const RRule::Verdict v = RRule::Eval(RRule::Face::RegValue, keyPath, valueName, nullptr);
			const RApply::Effect effect = RApply::ApplyRegValue(v, v.hit, buffer,
				sizeof(buffer), regionOffset, regionLength, 0);

			DrawTextSimple(dc, L"① 注册表值 · Password（REG_SZ）",
				{ dleft, dy, dright, dy + 18 }, g_fontUI, kTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"判定", AdvVerdictText(v),
				v.hit ? kSpoofed : kTextSecondary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改前", AdvHex(before, regionLength), kTextPrimary);
			dy += AdvLineHeight;

			std::wstring afterText;
			COLORREF afterColor = kSpoofed;
			if (effect == RApply::Effect::Rejected) {
				afterText = L"（拒绝 —— 调用方拿到 STATUS_ACCESS_DENIED）";
				afterColor = kBlocked;
			}
			else if (effect == RApply::Effect::PassThrough) {
				afterText = AdvHex(before, regionLength) + L"   （规则要求放行，原样返回）";
				afterColor = kTextSecondary;
			}
			else {
				afterText = AdvHex(buffer + regionOffset, regionLength);
				afterText += L"   （";
				afterText += RApply::EffectName(effect);
				afterText += L"）";
			}
			AdvRow(dc, dleft, dright, dy, L"改后", afterText, afterColor);
			dy += AdvLineHeight + 10;
		}

		// ---- 样例 2：剪贴板（CF_UNICODETEXT）----
		{
			const UINT format = 13 /*CF_UNICODETEXT*/;
			const WCHAR* realText = L"账号=admin 口令=hunter2";
			const size_t realLength = (wcslen(realText) + 1) * sizeof(WCHAR);

			HGLOBAL real = AdvBuildRealUnicodeText(realText);
			const BYTE* realBytes = real
				? static_cast<const BYTE*>(GlobalLock(real)) : nullptr;

			// ★ 必须**先**把「改前」的字节抓成字符串，再解锁 / 释放。
			//   否则后面显示用的是已经还回去的内存（use-after-free）。
			//   实测症状很隐蔽：程序**不崩**，只是"改前"那一行变成两个指针值
			//   （`70 2D 61 E5 5B 02 00 00 ...`），而不是真实的 UTF-16 文本 ——
			//   自绘界面里没有任何东西会报错，只有截图能看出来。
			const std::wstring beforeHex = AdvHex(realBytes, realLength);

			WCHAR fmtBuffer[32] = {};
			const WCHAR* fmtLabel = RClip::FormatLabel(format, fmtBuffer, _countof(fmtBuffer));
			const RRule::Verdict v = RRule::Eval(RRule::Face::Clip, nullptr, nullptr, fmtLabel);

			HGLOBAL fake = nullptr;
			std::wstring afterText;
			COLORREF afterColor = kSpoofed;
			const WCHAR* afterWhat = L"";

			if (v.hit && v.act == RRule::Act::Block) {
				afterText = L"（拒绝 —— 调用方拿到 NULL + err=5）";
				afterColor = kBlocked;
			}
			else if (v.hit && v.act == RRule::Act::Pass) {
				afterText = beforeHex + L"   （规则要求放行，原样返回）";
				afterColor = kTextSecondary;
			}
			else if (v.hit) {
				const WCHAR* text = (v.act == RRule::Act::ReplaceText) ? v.text.c_str() : L"";
				fake = RApply::BuildClipText(format, text);
				afterWhat = (v.act == RRule::Act::ReplaceText)
					? L"写入了规则指定的文本" : L"内容变空串";
			}
			else {
				// ★ 回落 = **生产**路径：文本类 -> 空串（BuildEmptyText）
				fake = RClip::BuildFake(format, real);
				afterWhat = L"生产回落：文本内容变空串";
				afterColor = kTextSecondary;
			}

			if (fake) {
				const BYTE* fakeBytes = static_cast<const BYTE*>(GlobalLock(fake));
				const size_t fakeLength = static_cast<size_t>(GlobalSize(fake));
				afterText = AdvHex(fakeBytes, fakeLength);
				afterText += L"   （";
				afterText += afterWhat;
				afterText += L"）";
				GlobalUnlock(fake);
				RClip::FreeFake(format, fake);
			}

			if (realBytes) {
				GlobalUnlock(real);
			}
			if (real) {
				GlobalFree(real);
			}

			DrawTextSimple(dc, L"② 剪贴板 · CF_UNICODETEXT（文本）",
				{ dleft, dy, dright, dy + 18 }, g_fontUI, kTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"判定", AdvVerdictText(v),
				v.hit ? kSpoofed : kTextSecondary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改前", beforeHex, kTextPrimary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改后", afterText, afterColor);
			dy += AdvLineHeight + 10;
		}

		// ---- 样例 3：注册表枚举（隐藏）----
		{
			const WCHAR* keyPath = L"HKEY_CURRENT_USER\\Software\\R3ShieldCoreDemo\\Vault";
			PCWSTR children[] = { L"SecretKey", L"PublicKey", L"SecretToken", L"Password" };
			const int childCount = static_cast<int>(_countof(children));

			std::wstring beforeList;
			std::wstring afterList;
			std::wstring hitText;
			int hidden = 0;
			for (int i = 0; i < childCount; i++) {
				if (!beforeList.empty()) {
					beforeList += L" · ";
				}
				beforeList += children[i];

				const RRule::Verdict v = RRule::Eval(RRule::Face::RegEnum, keyPath, children[i], nullptr);
				if (v.hit && v.act == RRule::Act::Hide) {
					hidden++;
					if (hitText.empty()) {
						hitText = AdvVerdictText(v);
					}
					continue;
				}
				if (!afterList.empty()) {
					afterList += L" · ";
				}
				afterList += children[i];
			}
			if (afterList.empty()) {
				afterList = L"（全被隐藏）";
			}

			DrawTextSimple(dc, L"③ 注册表枚举 · 子键列表（隐藏）",
				{ dleft, dy, dright, dy + 18 }, g_fontUI, kTextPrimary,
				DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"判定",
				hidden ? hitText : std::wstring(L"未命中规则 · 一项都不隐藏"),
				hidden ? kSpoofed : kTextSecondary);
			dy += AdvLineHeight;
			// ★ 不带"共 N 项"后缀：这一行本来就长（4 个名字），加了会被
			//   DT_END_ELLIPSIS 截掉尾巴，反而看不出藏的是谁。条数由「改后」那行说。
			AdvRow(dc, dleft, dright, dy, L"改前", beforeList, kTextPrimary);
			dy += AdvLineHeight;
			AdvRow(dc, dleft, dright, dy, L"改后",
				afterList + L"   （隐藏 " + std::to_wstring(hidden) + L" 项）",
				hidden ? kSpoofed : kTextSecondary);
			dy += AdvLineHeight + 10;
		}

		// 一句诚实标注：这一页**不**模拟引擎侧的 protect_reg 判据。
		DrawTextSimple(dc, L"注：枚举面未命中即「保留」（不模拟 protect_reg 判据）。",
			{ dleft, layout.PanelBottom - 24, dright, layout.PanelBottom - 6 },
			g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
	}

	// ---------------- 页面主入口 ----------------
	void DrawAdvancedPage(HDC dc, const RECT& client)
	{
		// ★ 首次进这一页：先从规则文件读，读不到再铺示例 —— 只做一次。
		{
			static bool seeded = false;
			if (!seeded) {
				seeded = true;
				AdvInitialLoad();
			}
		}

		const AdvLayout layout = AdvLayoutFor(client);

		// ★ 证明"这一页真的被画到了"（与 ARK 页同一套路，铁律 97）。
		//   为什么值得单开一行日志：`--gui-preview` 的核对完全建立在
		//   "窗口画出来了"这件事上，而"页面没被画到"与"画了但内容不对"
		//   在一张截图上长得一模一样 —— 截到空窗口时分不清是哪种。
		{
			static bool paintedOnce = false;
			if (!paintedOnce) {
				paintedOnce = true;
				// ★ v78：`闸门=` 与 `编辑框=` 是**两个**开关，必须分开报 ——
				//   只报一个的话，"闸门过了但解析屏还没点掉"这种中间态
				//   在日志里看不出来，而它正好是三个界面状态里的第二个。
				//   `编辑框=` 报的是 `AdvEditShouldShow()`（与真正去
				//   ShowWindow 的是**同一个函数**），不是"句柄存不存在" ——
				//   后者在闸门屏也是 1（控件早建好了，只是隐藏着），
				//   报它等于给探针一条**恒真**的判据。
				// ★ v79：再加一个 `提示=` —— 它是**实时提示**（输入框下面那两行）
				//   当前算出来的种类：空 / 可解析 / 错误。
				//   为什么值得单开一个字段：提示是"输入时才有"的东西，
				//   截图上只能看出"有两行字"，看不出那两行**跟没跟着输入变**。
				//   探针用"预置一段合法规则 -> 提示=可解析""预置一段非法规则
				//   -> 提示=错误"这一对，就能证明它真的在读编辑框，而不是
				//   画了一句写死的说明。
				printf("[adv] 页面已绘制 规则=%d 页签=%d 闸门=%d 编辑框=%d 提示=%ls 客户区=%dx%d\n",
					RRule::Count(), g_page, g_advQuizPassed ? 1 : 0,
					AdvEditShouldShow() ? 1 : 0, AdvHintKind(),
					static_cast<int>(client.right), static_cast<int>(client.bottom));
				fflush(stdout);
			}
		}

		// ---------------- 摘要行 ----------------
		{
			WCHAR buffer[320] = {};
			if (!g_advQuizPassed) {
				swprintf_s(buffer, _countof(buffer),
					L"替换 API 结果 · 规则引擎编辑台 —— 编辑区**已锁定**（先过三道题闸门）· 规则 %d 条",
					RRule::Count());
			}
			else if (!g_advWhyDismissed) {
				swprintf_s(buffer, _countof(buffer),
					L"替换 API 结果 · 规则引擎编辑台 —— 闸门已通过，看完解析点「开始编辑规则」");
			}
			else {
				swprintf_s(buffer, _countof(buffer),
					L"替换 API 结果 · 规则引擎编辑台 —— 规则 %d 条 · first-match wins，未命中回落内置默认行为",
					RRule::Count());
			}
			DrawTextSimple(dc, buffer,
				{ layout.Left, layout.SummaryTop, layout.Right, layout.SummaryTop + 22 },
				g_fontUI, kTextSecondary, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
		}

		// ---------------- 三个状态 ----------------
		if (!g_advQuizPassed) {
			AdvDrawQuiz(dc, layout);
		}
		else if (!g_advWhyDismissed) {
			AdvDrawWhy(dc, layout);
		}
		else {
			AdvDrawEditor(dc, layout);
			AdvDrawPreview(dc, layout);
		}

		// ---------------- 底部按钮 + 说明 ----------------
		int lastButtonRight = layout.Left;
		for (int i = 0; i < AdvButtonAll; i++) {
			if (!AdvButtonVisible(i)) {
				continue;
			}
			AdvDrawButton(dc, layout.Buttons[i], AdvButtonLabel(i),
				g_advHoverAction == i, g_advPressedAction == i);
			lastButtonRight = layout.Buttons[i].right;
		}
		{
			PCWSTR hint = L"";
			if (g_advQuizPassed && g_advWhyDismissed) {
				// ★ 编辑态有 6 个按钮，右边只剩百来像素 —— 这句必须短。
				//   写长了会被 DT_END_ELLIPSIS 截成"规则文件路径…"，
				//   等于什么都没说（路径本来就印在左栏底部）。
				hint = L"重启引擎后生效";
			}
			else if (!g_advQuizPassed) {
				hint = L"闸门与命令行控制台共用同一套题（advanced_quiz.h）。";
			}
			// ★ 说明行接在**最后一个可见按钮**右边 —— 不能写死
			//   "Left + AdvButtonWidth*3 + 32"：三个状态各显示 2 / 1 / 6 个按钮，
			//   写死的话编辑态那 6 个按钮会被这行说明**压在底下**
			//   （实测：截图里「重置为示例规则」「清空规则表」两个按钮上叠着字，
			//    而日志和像素判据都完全看不出来）。
			DrawTextSimple(dc, hint,
				{ lastButtonRight + 16, layout.ButtonTop,
				  layout.Right, layout.ButtonTop + AdvButtonHeight },
				g_fontUI, kTextSecondary,
				DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
		}
	}

void ShowPage(int page) {
	g_page = page;
	const int cfgShow = (page == 0) ? SW_SHOW : SW_HIDE;
	const int logShow = (page == 1) ? SW_SHOW : SW_HIDE;

	ShowWindow(g_hSecList, cfgShow);
	ShowWindow(g_hCfgLabel, cfgShow);
	ShowWindow(g_hCfgPath, cfgShow);
	ShowWindow(g_hReload, cfgShow);
	ShowWindow(g_hSave, cfgShow);
	ShowWindow(g_hSyncNow, cfgShow);
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

	// ★ 高级页：唯一的子控件是那个原生 EDIT（中文靠 IME）。
	//   它必须**跟着页走** —— 否则切到配置页时它会浮在配置表单上面
	//   （自绘界面里"画了但看不见"和"看得见但不该有"是同一类坑，铁律 237）。
	//   判据用 AdvEditShouldShow()（与真正去 ShowWindow 的是同一个函数），
	//   不在这里另写一份"什么状态该显示"的逻辑（铁律 127/241）。
	RECT advClient = {};
	GetClientRect(g_main, &advClient);
	AdvSyncEdit(g_main, advClient);

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
	switch (index) {
	case 1:  return L"日志";
	case 2:  return L"高级";
	default: return L"配置";
	}
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
	// ★ v81：引擎在跑时日志页走引擎的**实时**流（不经文件缓冲），
	//   所以副标题里既要说"要引擎"，也要说"不必依赖引擎"—— 两句都对：
	//   有引擎更好，没有也能读文件。说成一边会误导（铁律 99：诊断口径 ≥ 触发口径）。
	DrawTextSimple(dc, L"配置表单  ·  逐行保真写入  ·  事件日志：引擎实时 / 服务日志：文件  ·  不注入",
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

// ===========================================================================
//  托盘（关闭窗口 = 收进通知区）
//
//   用户 2026-10-17 要求。与主程序共用 `shared/r3shieldcore/tray_icon.h`（铁律 127）。
//
//   ★★ 本工具与主程序**唯一**的实质区别：这里的「退出」是**安全**的
//      （配置工具不注入、不挂钩 —— 它退掉不影响任何防护），所以二次确认
//      问的是"未保存的修改会不会丢"，而不是"防护会不会停"。
// ===========================================================================

HICON CfgTrayIcon() {
	// 用 exe 资源里的图标；取不到退回系统图标（不出现空白方框）。
	HICON icon = reinterpret_cast<HICON>(
		LoadImageW(g_inst, MAKEINTRESOURCEW(1), IMAGE_ICON,
			GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
	return icon ? icon : ::LoadIconW(nullptr, IDI_APPLICATION);
}

std::wstring CfgTrayTipText() {
	std::wstring tip = L"R3 ShieldCore 配置与日志";
	if (HasUnsaved()) {
		// ★ 提示必须**如实**反映"有未保存的修改" —— 图标收起来之后，
		//   托盘提示就是用户唯一的信息来源（铁律 97：诊断不能自己变假信息）。
		tip += L" — 有未保存的修改";
	}
	tip += L"\n双击显示窗口，右键更多操作。";
	return tip;
}

void CfgHideToTray(HWND hwnd) {
	if (!g_tray.icon.added()) {
		// ★ 图标没加上就**不隐藏**：窗口从任务栏和托盘同时消失 =
		//   用户彻底找不到它（比"没做托盘"更糟）。退回最小化。
		printf("[tray] 图标未就绪，退回最小化到任务栏\n");
		ShowWindow(hwnd, SW_MINIMIZE);
		return;
	}
	const bool firstTime = !g_tray.windowHidden;
	ShowWindow(hwnd, SW_HIDE);
	g_tray.windowHidden = true;
	g_tray.icon.SetTip(CfgTrayTipText());
	printf("[tray] 配置工具窗口已收进托盘\n");

	// ★ 自动拉起（`--quiet`）时不弹气泡：那种情况下用户根本没在操作我们，
	//   弹一个"已收进托盘"纯属噪音（而噪音会让人关掉通知，
	//   连带把真正要紧的提示一起关掉）。
	if (firstTime && !g_tray.autoLaunched) {
		g_tray.icon.Balloon(L"配置工具仍在后台",
			L"窗口已收进托盘。双击托盘图标可重新打开；右键可退出。");
	}
}

void CfgRestoreFromTray(HWND hwnd) {
	ShowWindow(hwnd, SW_SHOW);
	if (IsIconic(hwnd)) {
		ShowWindow(hwnd, SW_RESTORE);
	}
	// ★ 不用 `SetForegroundWindow` 了事：前台锁会拒绝后台进程（铁律 256）。
	//   TOPMOST→NOTOPMOST 抬 z 序不需要前台权。
	SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
	SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
		SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
	SetForegroundWindow(hwnd);
	SetFocus(hwnd);
	g_tray.windowHidden = false;
	g_tray.icon.SetTip(CfgTrayTipText());
	printf("[tray] 配置工具窗口已从托盘恢复\n");
}

void CfgExitRequested(HWND hwnd) {
	// ★ 本工具退出**不影响防护**（不注入、不挂钩）⇒ 这里问的是
	//   "未保存的修改怎么办"，不是"确定要停掉防护吗"。
	int r = IDYES;
	if (HasUnsaved()) {
		r = MessageBoxW(hwnd,
			L"有未保存的修改，退出后会丢失。\n\n确定要退出吗？",
			L"退出配置工具", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
		if (r != IDYES) {
			printf("[tray] 用户取消了退出（有未保存修改）\n");
			return;
		}
	} else {
		r = MessageBoxW(hwnd,
			L"确定要关闭配置工具吗？\n\n"
			L"（它只负责改配置与看日志，关掉它**不影响**引擎的监控与拦截。）",
			L"退出配置工具", MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
		if (r != IDYES) {
			printf("[tray] 用户取消了退出\n");
			return;
		}
	}
	printf("[tray] 用户确认退出配置工具\n");
	g_tray.reallyExiting = true;
	// ★ 这里可以**直接** `DestroyWindow`（与主程序**不同** —— 主程序只置 `g_quitRequest`
	//   让 app.cpp 走"反注入 → 关窗口"的有序收尾，见 r3shieldcore_gui.cpp 的说明）。
	//   本工具不注入、不挂钩、没有引擎要收尾 ⇒ 没有需要保序的动作。
	DestroyWindow(hwnd);
}

void HandleCfgTrayMessage(HWND hwnd, LPARAM lp) {
	switch (LOWORD(lp)) {
	case WM_LBUTTONUP:
	case WM_LBUTTONDBLCLK:
		CfgRestoreFromTray(hwnd);
		return;

	case WM_RBUTTONUP:
	case WM_CONTEXTMENU: {
		// 本工具**不需要**「退出引擎」那一项（它管不到引擎），所以传 false。
		const R3ShieldCoreTray::TrayMenuAction act =
			R3ShieldCoreTray::ShowTrayMenu(hwnd, L"显示窗口", false, L"");
		switch (act) {
		case R3ShieldCoreTray::TrayMenuAction::ShowWindow:
			CfgRestoreFromTray(hwnd);
			return;
		case R3ShieldCoreTray::TrayMenuAction::Exit:
			CfgExitRequested(hwnd);
			return;
		default:
			return;
		}
	}
	default:
		return;
	}
}

// ★ v82：预览"演练"模式的一步（`R3SHIELDCORE_PREVIEW_ADV=cycle`）。
//
//   为什么要有它：闸门 -> 解析 -> 编辑台 是**三个互斥状态**，每次切换都会
//   重绘。而"重绘前没擦背景"这种缺陷**只在切换时**留下残留 —— 直接置状态
//   建窗（`=editor`）截出来是干净的，**永远抓不到**（铁律 24/28）。
//   这个函数用**与按钮点击完全同款**的 `InvalidateRect(..., FALSE)` 推进，
//   所以它复现的就是用户连点三次时看到的那一屏。
void AdvancePreviewCycle(HWND hwnd) {
	switch (g_previewCycleStep) {
	case 0:
		// 闸门屏 -> 解析屏（等价于"三道题全对"）。
		g_advQuizPassed = true;
		g_advWhyDismissed = false;
		printf("[adv] 演练：闸门屏 -> 解析屏\n");
		break;
	case 1:
		// 解析屏 -> 编辑台。
		g_advWhyDismissed = true;
		printf("[adv] 演练：解析屏 -> 编辑台\n");
		break;
	default:
		// 到编辑台为止；停掉定时器，让画面稳定下来好截图。
		KillTimer(hwnd, kCycleTimerId);
		g_previewCycleStep = -1;
		printf("[adv] 演练：结束（停在编辑台，共切 2 次）\n");
		fflush(stdout);
		return;
	}
	++g_previewCycleStep;
	// ★ 与按钮点击**同款**（`bErase=FALSE`）—— 这正是"旧字没被擦掉"的
	//   触发条件，演练必须原样复现它，不能偷偷传 TRUE 把它绕过去。
	InvalidateRect(hwnd, nullptr, FALSE);
	UpdateWindow(hwnd);
	fflush(stdout);
}

// ---------- 窗口过程 ----------

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
	// ★★ 被主程序"点名"（v80）：主程序点「高级」时，若本工具已在跑，
	//    就 PostMessage 这条**注册消息**过来（不是 WM_COMMAND，也不是自定义
	//    的 WM_APP+N —— 那两个都要两边各写一份数字，改了不报错，铁律 127）。
	//    RegisterWindowMessageW 保证两个 exe 用同一个字符串拿到同一个 id。
	//
	//    ★ 这条判断必须放在 switch **之前**：注册消息的数值是运行时才知道的
	//      （0xC000..0xFFFF），没法写成 case 标签。
	if (msg != 0 && msg == R3ShieldCoreCfg::ActivateMessageId()) {
		const int page = static_cast<int>(wp);
		if (page >= 0 && page < kTabCount && page != g_page) {
			ShowPage(page);
		}
		// 从最小化/隐藏里恢复并提到前台（主程序侧已 AllowSetForegroundWindow）。
		if (IsIconic(hwnd)) { ShowWindow(hwnd, SW_RESTORE); }
		else { ShowWindow(hwnd, SW_SHOW); }
		SetForegroundWindow(hwnd);
		BringWindowToTop(hwnd);
		InvalidateRect(hwnd, nullptr, TRUE);
		// ★ 被激活 = 窗口又可见了 ⇒ 托盘那份"收起来了"的状态要跟着清掉，
		//   否则之后双击托盘图标会以为"已经显示着"而什么都不做。
		g_tray.windowHidden = false;
		g_tray.icon.SetTip(CfgTrayTipText());
		return 0;
	}

	// ★ 托盘回调 + explorer 重启重加图标 —— 同样**必须**在 switch 之前
	//   （两个消息的 id 都是运行时才知道的，当不了 case，铁律 250）。
	if (msg != 0 && msg == g_tray.icon.callbackMessage()) {
		HandleCfgTrayMessage(hwnd, lp);
		return 0;
	}
	{
		static const UINT taskbarCreated = ::RegisterWindowMessageW(L"TaskbarCreated");
		if (msg == taskbarCreated) {
			// explorer 重启后通知区被清空 ⇒ 图标得加回去。不加的话，
			// 窗口收进托盘的用户就**再也找不到这个程序了**（没有窗口也没有图标）。
			if (g_tray.icon.Add(hwnd, CfgTrayIcon(), CfgTrayTipText(),
					R3ShieldCoreTray::kCallbackMessageCfg)) {
				printf("[tray] explorer 重启，配置工具托盘图标已重新加入\n");
			}
			return 0;
		}
	}

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
		// ★ v81：让正在跑的引擎重读 ini 并热应用 —— 见 LayoutAll 里的说明。
		g_hSyncNow = MakeButton(hwnd, IDC_SYNCNOW, L"立即同步", 0, 0, 96, kRowH);
		g_hOpenCfgDir = MakeButton(hwnd, IDC_OPENCFGDIR, L"打开所在目录", 0, 0, 96, kRowH);

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
		// ★ v81：只剩两项 ——
		//   「事件日志」= 向**服务端（引擎）**要进程内事件流（引擎没跑回落读文件）；
		//   「服务日志」= 服务写的文件。
		//   ⚠️ 「控制台日志」（主程序自己的 stdout）已删除：它是内部诊断输出，
		//      对使用者没有意义（铁律 **265**）。
		SendMessageW(g_hLogCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"事件日志  r3shieldcore-events.log（引擎实时）"));
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
		// ★ v80 修缺陷：这里原来是 `ShowPage(g_startPage == 1 ? 1 : 0)` ——
		//   只有 0 / 1 两页时的写法。加了第 3 个页签（高级）之后，
		//   `--page 2` 会被**静默压回第 0 页**：命令行说"去高级页"，
		//   窗口却停在配置页，而且不报任何错 —— 主程序点「高级」跳转
		//   就会"跳了个寂寞"（激活成功、页不对）。
		//   ⇒ 改成**按 kTabCount 夹取**，页号唯一判据是共享头里的 kPage*。
		ShowPage(g_startPage >= 0 && g_startPage < kTabCount ? g_startPage : 0);

		// 预选日志（不显示，切过去再读也行；这里先打开以便计时器跟进）
		// ★ v81：默认选第 0 项「事件日志」⇒ 数据优先来自服务端（引擎）。
		//   核对开关 `R3SHIELDCORE_PREVIEW_LOGSRC=svc` 可以把默认钉到「服务日志」
		//   （探针不会去点下拉框 ⇒ 不钉的话那一项永远核对不到，铁律 142/175）。
		if (g_previewLogSrcSvc) {
			SendMessageW(g_hLogCombo, CB_SETCURSEL, 1, 0);
			ChooseLogTarget(1, true);
		} else {
			SendMessageW(g_hLogCombo, CB_SETCURSEL, 0, 0);
			ChooseLogTarget(0, true);
		}

		SetTimer(hwnd, 1, 500, nullptr);
		return 0;
	}

	case WM_SIZE:
	case WM_MOVE:
		// ★ v83：背景是"窗口后方那块屏幕"的快照，位置一变就对不上 ⇒ 必须重抓。
		if (g_glass.active) {
			g_glassWantBackdrop = true;
			g_glassMovedAt = GetTickCount64();
		}
		if (msg == WM_SIZE) {
			LayoutAll();
			InvalidateRect(hwnd, nullptr, TRUE);
		}
		return 0;

	case WM_GETMINMAXINFO: {
		MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lp);
		// 最小宽度要放得下：页签条右缘（20 + 3×92 - 8 = 288，v80 起三个页签）
		// 与配置页工具条那一簇按钮（右对齐约 440px）。
		mmi->ptMinTrackSize.x = 800;
		// ★ 最小高度 640：高级页在编辑态要同时放下「规则表 + 输入框 + 模板按钮
		//   + 两行实时提示 + 状态行 + 贴底总闸」。矮于这个高度时
		//   `AdvTableMaxRows` 会按可用高度把规则表压到 2 行 —— 但再矮就会
		//   把**输入框**挤出面板（而那正是这一页存在的意义）。
		//   （主程序里定的也是 640，搬过来保持同一个数。）
		mmi->ptMinTrackSize.y = 640;
		return 0;
	}

	case WM_ERASEBKGND: {
		HDC dc = reinterpret_cast<HDC>(wp);
		RECT rc = {};
		GetClientRect(hwnd, &rc);
		// ★ v83：玻璃可用时直接抹玻璃层 —— 不铺不透明底色。
		//   （先铺实色再被玻璃盖掉 = 每次擦背景都闪一下，缩放时尤其明显。）
		if (g_glass.active && g_glass.layer.dc) {
			BitBlt(dc, 0, 0, rc.right, rc.bottom, g_glass.layer.dc, 0, 0, SRCCOPY);
			return 1;
		}
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

		// ★ v83：先准备玻璃层（背景 + 面板）。
		g_glass.headerBand = kContentTop;
		g_glass.headerVeil = 0.30f;
		const bool glassOn = g_glass.Begin(hwnd, rc.right, rc.bottom,
			CfgDpiScale(hwnd),
			g_glassWantBackdrop || (GetTickCount64() - g_glassMovedAt) < 1200);
		g_glassWantBackdrop = false;
		if (glassOn) {
			// ★ 这行不只是日志：它把宽串代次标记 `kGenerationMarker` **引用**一遍，
			//   否则链接器看不到有人用它，会把那个常量丢掉 ⇒ 发布闸门
			//   `check_dist_sync.sh` 的 v83 节查不到标记、报"包里不是 v83 产物"。
			//   （实测踩过：主程序有这行、cfg 没有 ⇒ 闸门精准 FAIL 在 cfg 那一侧。）
			static bool s_glassLogged = false;
			if (!s_glassLogged) {
				s_glassLogged = true;
				printf("[glass] 液态玻璃已就绪 背景=%ls 尺寸=%dx%d 标记=%ls\n",
					R3ShieldCoreUi::BackdropSourceName(g_glass.backdrop.source),
					rc.right, rc.bottom, R3ShieldCoreUi::kGenerationMarker);
			}
		}

		// 标题区 + 页签栏这一段**没有子控件** ⇒ 可以双缓冲（与主窗口同款做法），
		// 消掉拖动/缩放时的重绘闪烁。
		const int stripH = kContentTop;
		HDC mem = CreateCompatibleDC(dc);
		HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right > 0 ? rc.right : 1, stripH);
		HGDIOBJ oldBmp = SelectObject(mem, bmp);
		RECT strip = { 0, 0, rc.right, stripH };
		if (glassOn) {
			BitBlt(mem, 0, 0, rc.right, stripH, g_glass.layer.dc, 0, 0, SRCCOPY);
		} else {
			FillSolid(mem, strip, kHeaderBg);
		}
		DrawHeader(mem, rc);
		DrawTabBar(mem, rc);
		BitBlt(dc, 0, 0, rc.right, stripH, mem, 0, 0, SRCCOPY);
		SelectObject(mem, oldBmp);
		DeleteObject(bmp);
		DeleteDC(mem);

		// ★★ 先把**正文区底色**填掉，再画内容。
		//
		//   为什么必须在这里填、而不是靠 `WM_ERASEBKGND`（实测踩过）：
		//   正文区里**有直接画在底色上的文字**（高级页的摘要行 / 说明行 ——
		//   它们底下没有面板，不像规则表那样每次都被 `DrawPanel` 重新填白）。
		//   而状态切换走的是 `InvalidateRect(hwnd, nullptr, FALSE)` ——
		//   `bErase=FALSE` **不会**发 `WM_ERASEBKGND` ⇒ 旧文字留在原地，
		//   新状态的字直接叠上去。症状：quiz → why → editor 三层摘要糊成一片，
		//   而这个 bug **只在真按顺序点过去时**才现形（探针是直接置状态建窗，
		//   中间没有那两次重绘 ⇒ 截出来是干净的，铁律 24/28 那一类）。
		//
		//   ⇒ 在绘制入口**无条件**填一次，等价于"保证擦除一定发生"，
		//     这样就不依赖每个 `InvalidateRect` 调用点都记得传 `TRUE`
		//     （`FALSE` 是有意用的：它少一次擦除、悬停时更不容易闪）。
		//   ⚠️ 子控件由 `WS_CLIPCHILDREN` 裁掉 ⇒ 这次填充不会盖住它们。
		{
			RECT body = { 0, kContentTop, rc.right, rc.bottom };
			if (glassOn) {
				// 玻璃层已经算好「背景 + 面板」，正文区直接抹上去；
				// 子控件由 WS_CLIPCHILDREN 裁掉 ⇒ 不会盖住它们。
				BitBlt(dc, 0, kContentTop, rc.right, rc.bottom - kContentTop,
					g_glass.layer.dc, 0, kContentTop, SRCCOPY);
			} else {
				FillSolid(dc, body, kBg);
			}
		}

		// 内容区：面板底 + 输入框描边。这一片有子控件，**不能**整体双缓冲
		// （BitBlt 会把子控件一起盖掉）。绘制区已被 WS_CLIPCHILDREN 裁掉
		// 子控件覆盖的部分，所以直接画是安全的。
		if (g_page == R3ShieldCoreCfg::kPageAdvanced) {
			// 高级页**整页自绘**（没有面板），所以走它自己的绘制入口。
			// ★ 那个原生 EDIT 由 WS_CLIPCHILDREN 裁掉 ⇒ 直接画不会盖住它
			//   （主程序里踩过：漏了这个标志，BitBlt 把编辑框抹掉，铁律 181/237）。
			DrawAdvancedPage(dc, rc);
		} else {
			DrawContentPanels(dc, hwnd);
			PaintFieldFrames(dc, hwnd);
		}
		// ★ 本帧记下的面板表若与"已合成的那张"不一致 ⇒ 再刷一帧
		//   （切页签 / 缩放 / 悬停态变化时会触发；稳定后零额外成本）。
		if (g_glass.active && g_glass.CommitPanels()) {
			InvalidateRect(hwnd, nullptr, FALSE);
		}
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

		// ★ 高级页：按钮 / 模板芯片的悬停（与主程序同款 —— 它们不在
		//   页签栏那套里，位置随客户区大小变，且只在这一页存在）。
		if (g_page == R3ShieldCoreCfg::kPageAdvanced) {
			RECT client = {};
			GetClientRect(hwnd, &client);
			const int hoveredAdv = HitTestAdvButton(pt, client);
			const int hoveredChip = HitTestAdvChip(pt, client);
			if (hoveredAdv != g_advHoverAction || hoveredChip != g_advHoverChip) {
				g_advHoverAction = hoveredAdv;
				g_advHoverChip = hoveredChip;
				InvalidateRect(hwnd, nullptr, FALSE);
			}
		} else if (g_advHoverAction != -1 || g_advHoverChip != -1) {
			g_advHoverAction = -1;
			g_advHoverChip = -1;
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
		if (g_advHoverAction != -1 || g_advHoverChip != -1) {
			g_advHoverAction = -1;
			g_advHoverChip = -1;
			InvalidateRect(hwnd, nullptr, FALSE);
		}
		return 0;
	}

	case WM_CAPTURECHANGED:
		// 捕获被抢走（弹了别的窗口 / 别的进程抢了鼠标）⇒ 清掉按下态，
		// 否则按钮会永远停在"按下"的样子（主程序同款处理）。
		if (g_advPressedAction != -1 || g_advPressedChip != -1) {
			g_advPressedAction = -1;
			g_advPressedChip = -1;
			InvalidateRect(hwnd, nullptr, FALSE);
		}
		return 0;

	case WM_TIMER:
		if (wp == 1) { ReadMore(); }
		// ★ v82：演练模式的状态推进（见 AdvancePreviewCycle）。
		if (wp == kCycleTimerId && g_previewCycleStep >= 0) { AdvancePreviewCycle(hwnd); }
		return 0;

	case WM_COMMAND: {
		const int id = LOWORD(wp);
		const int code = HIWORD(wp);

		if (id == IDC_TABAREA) { return 0; }

		// ★ 高级页：编辑框内容一变就重绘 —— 实时提示是"现算"的
		//   （不缓存），所以必须**有人告诉窗口"内容变了"**。
		//   这条通知能到达这里的前提：创建 EDIT 时把**控件 ID** 传给了
		//   `hMenu`（`AdvEditId = 4001`）—— 否则 `LOWORD(wParam)` 恒为 0，
		//   通知发到了父窗口也没人认领（敲字时提示不动的经典原因）。
		if (id == AdvEditId && code == EN_CHANGE) {
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;
		}

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
		if (id == IDC_SYNCNOW) {
			// ★ v81：让**正在跑的引擎**重读 ini 并热应用（真实可热应用的只有 `mode`）。
			//
			//   为什么要有这个按钮：改完 ini 保存之后，引擎手里仍是启动时那份
			//   （只有 `mode` 例外、可以热切）。没有这个按钮，"改了没生效"
			//   就只能靠用户自己猜 + 重启引擎。有了它，引擎会把
			//   **哪些立即生效、哪些要重启** 明确回过来，这里原样转达。
			//
			//   ★ 先保存再同步：如果用户改了界面上的值却没点「保存」，
			//     同步过去的是**旧文件**—— 那比不同步更糟（用户以为生效了）。
			if (HasUnsaved()) {
				const int answer = MessageBoxW(g_main,
					L"有未保存的修改。\n\n"
					L"『是』= 先保存再同步（推荐）\n"
					L"『否』= 不保存，只同步文件里已有的内容\n"
					L"『取消』= 什么都不做",
					L"立即同步", MB_ICONQUESTION | MB_YESNOCANCEL);
				if (answer == IDCANCEL) { return 0; }
				if (answer == IDYES) {
					if (!SaveAll()) { return 0; }   // 保存失败就不同步
				}
			}

			const auto r = R3ShieldCoreCfgIpc::Call(R3ShieldCoreCfgIpc::BuildSyncRequest());
			if (!r.Ok) {
				MessageBoxW(g_main,
					(L"同步失败：\n" + U82W(r.Error)
						+ L"\n\n引擎可能没在运行 —— 它会在下次启动时读到这份配置。").c_str(),
					L"立即同步", MB_ICONWARNING | MB_OK);
				return 0;
			}
			const std::wstring applied = U82W(
				R3ShieldCoreCfgIpc::FindKeyed(r.Reply, R3ShieldCoreCfgIpc::kSyncFieldApplied));
			const std::wstring restart = U82W(
				R3ShieldCoreCfgIpc::FindKeyed(r.Reply, R3ShieldCoreCfgIpc::kSyncFieldRestart));
			const std::wstring detail = U82W(
				R3ShieldCoreCfgIpc::FindKeyed(r.Reply, R3ShieldCoreCfgIpc::kSyncFieldDetail));

			std::wstring msg = L"引擎已重读配置文件。\n\n";
			msg += L"立即生效：" + (applied.empty() ? std::wstring(L"（无）") : applied) + L"\n";
			msg += L"需重启引擎：" + (restart.empty() ? std::wstring(L"（无）") : restart) + L"\n";
			if (!detail.empty()) { msg += L"\n" + detail; }
			MessageBoxW(g_main, msg.c_str(), L"同步完成", MB_ICONINFORMATION | MB_OK);
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
			if (!picked.empty()) {
				// ★ 自定义文件 = 纯文件读取（不是「事件日志」项 ⇒ 不走服务端）。
				//   否则"浏览到一个文件"会被引擎流**静默盖掉**（铁律 265）。
				g_useEngineSource = false;
				g_log.status.clear();
				OpenLogFile(picked, false);
			}
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
			return 0;
		}

		// ★ 高级页：三种可点区域，按**界面状态**分派。
		//
		//   闸门未过 ⇒ 只有「三道题的选项」可点（编辑区锁着，底部按钮也只剩
		//   两个，见 AdvButtonVisible）；闸门过了 ⇒ 模板芯片 / 规则表行 / 底部按钮。
		//
		//   ⚠️ 三个命中函数**各自自带状态判断**（不在对应状态时直接返回"没命中"）
		//      ⇒ 这里不需要再写一遍 if 分支。少一处分支就少一处"状态与分支对不上"
		//      的机会（主程序里就是这么写的，搬过来一字未改）。
		if (g_page == R3ShieldCoreCfg::kPageAdvanced) {
			RECT client = {};
			GetClientRect(hwnd, &client);

			// ① 闸门选项（只在未通过时命中）。
			int quizOpt = -1;
			const int quizCol = HitTestAdvQuizOption(pt, client, &quizOpt);
			if (quizCol >= 0) {
				g_advPick[quizCol] = quizOpt;
				// ★ 重选就**撤掉这一题的"错"标记** —— 否则用户改对了，
				//   界面上那题还是红的，他会以为没点上（判据滞后于输入）。
				g_advWrongMask &= ~(1 << quizCol);
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ② 模板芯片（只在已解锁时命中）。
			const int chip = HitTestAdvChip(pt, client);
			if (chip >= 0) {
				g_advPressedChip = chip;
				SetCapture(hwnd);
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ③ 规则表某一行（只在已解锁时命中）。
			const int row = HitTestAdvTableRow(pt, client);
			if (row >= 0) {
				AdvSelectRule(row);
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}

			// ④ 底部按钮。
			const int button = HitTestAdvButton(pt, client);
			if (button != AdvButtonNone) {
				g_advPressedAction = button;
				SetCapture(hwnd);
				InvalidateRect(hwnd, nullptr, FALSE);
				return 0;
			}
			// 这一页没有别的可点区域 ⇒ 命中与否都吃掉这次点击。
			return 0;
		}
		return 0;
	}

	case WM_LBUTTONUP: {
		const POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };

		// ★ 模板芯片（比按钮先判 —— 芯片与按钮的按下态是两个独立变量，
		//   同时为真不会出现，但先判谁决定了"万一同时为真"时的行为）。
		if (g_advPressedChip != -1) {
			const int pressed = g_advPressedChip;
			g_advPressedChip = -1;
			if (GetCapture() == hwnd) { ReleaseCapture(); }
			RECT client = {};
			GetClientRect(hwnd, &client);
			// 标准按钮语义：松手时仍停在**同一个**芯片上才触发。
			if (HitTestAdvChip(pt, client) == pressed) { AdvClickChip(pressed); }
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;
		}

		// ★ 底部按钮。
		if (g_advPressedAction != AdvButtonNone) {
			const int pressed = g_advPressedAction;
			g_advPressedAction = AdvButtonNone;
			if (GetCapture() == hwnd) { ReleaseCapture(); }
			RECT client = {};
			GetClientRect(hwnd, &client);
			if (HitTestAdvButton(pt, client) == pressed) { PerformAdvAction(pressed); }
			InvalidateRect(hwnd, nullptr, FALSE);
			return 0;
		}
		break;
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
		// 高级页的按钮 / 芯片同样给手型（不这么做的话，自绘按钮看上去
		// 像装饰 —— 用户不会去点）。
		if (g_page == R3ShieldCoreCfg::kPageAdvanced) {
			RECT advRc = {};
			GetClientRect(hwnd, &advRc);
			if (HitTestAdvButton(client, advRc) != AdvButtonNone
				|| HitTestAdvChip(client, advRc) >= 0) {
				SetCursor(LoadCursor(nullptr, IDC_HAND));
				return TRUE;
			}
		}
		break;
	}

	case WM_CLOSE:
		// ★ 用户 2026-10-17 要求：关窗口不再退出，改成**收进托盘**。
		//
		//   与旧行为的两个区别，都要说清楚：
		//     ① 旧版这里 `DestroyWindow` **真退出**；现在收起来、进程还在。
		//        ⇒ 但**未保存的修改**那道理还必须在，而且必须**在收起来之前**问:
		//        收起来之后用户可能再也不打开，那些改动就悄悄丢了。
		//     ② 真正退出的入口在托盘右键菜单「退出」（那里也问同一道题）。
		if (HasUnsaved()) {
			// ★ 用 ✓/✗ 而不是光靠文字：这里的后果是"改动丢失"（铁律 239 家族）。
			const int r = MessageBoxW(hwnd,
				L"有未保存的修改。\n\n"
				L"「是」= 收进托盘，稍后回来保存\n"
				L"「否」= 直接收进托盘，改动会丢失\n"
				L"（想保存请选「否」再用托盘图标打开窗口）",
				L"未保存的修改", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON1);
			// 两个分支其实都往下走（都收进托盘）—— 这里问只是**提醒**，
			// 不是阻止：用户明确点关闭时，强行拦住他去做别的会更烦人。
			printf("[tray] 关闭时有未保存修改，用户选择=%s\n", (r == IDYES) ? "稍后保存" : "丢弃");
		}
		CfgHideToTray(hwnd);
		return 0;

	case WM_DESTROY:
		KillTimer(hwnd, 1);
		// ★ v83：玻璃缓存（背景 + 面板层，两块整幅 DIB）必须显式放掉。
		g_glass.Shutdown();
		// ★ 摘图标要在关文件**之前或之后都行**，但必须做：图标消息投给这个 hwnd，
		//   窗口没了还留着图标 = 通知区里一个"点了没反应"的僵尸（铁律 103）。
		g_tray.icon.Remove();
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
	// ★★ v80：**必须**在第一条 printf 之前设 locale（与主程序 app.cpp:337 同款）。
	//
	//   为什么（这是个只看得见症状、看不见原因的坑）：
	//   本工具的核对日志里有 `printf("[adv] ... 提示=%ls ...")` —— 窄格式串里
	//   带 `%ls`（宽字符串）。MSVC 的 `printf` 按**当前 locale** 把宽串转成
	//   窄串；默认的 "C" locale 转不了任何非 ASCII 字符，于是它**从 `%ls`
	//   处直接停住**：那一行剩下的部分（包括后面的 `%d`、换行）全部丢失，
	//   而且**不报任何错**。
	//
	//   实测症状（v80 踩到）：日志里两条诊断都**只到第一个 `%ls` 就断了** ——
	//     `[adv] 初始规则=3 来源=`            ← 后面「示例 路径=…」没了
	//     `[adv] 页面已绘制 规则=3 … 提示=`   ← 后面「空 客户区=…」没了
	//   界面完全正常、截图完全正常、退出码 0 —— 只有**判据**在悄悄失效。
	//   主程序那边一直没这问题，只是因为 app.cpp 早就调过 `setlocale`。
	//
	//   ⇒ 代码搬了家，**这条前置条件也得跟着搬**（铁律 195 的另一面：
	//     搬走的不只是函数体，还有它依赖的进程级初始化）。
	setlocale(LC_ALL, "");

	// 命令行：--selftest [工作目录] / --section N / --page N / --quiet
	bool quietLaunch = false;
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
				} else if (wcscmp(argv[i], R3ShieldCoreCfg::kQuietSwitch) == 0) {
					quietLaunch = true;
				}
			}
			LocalFree(argv);
			if (selfTest) { return RunSelfTest(workDir); }
		}
	}
	// ★ 托盘要知道"这次是不是自动拉起的"：自动拉起（`--quiet`）时窗口
	//   本来就该安静待着，**不该**在关闭时弹"已收进托盘"的气泡（见 g_tray 注释）。
	g_tray.autoLaunched = quietLaunch;

	// ★★ 单实例（v80）：主程序启动时会自动把我们拉起来，用户再点「高级」
	//    又会点一次 —— 不拦的话会出现两个配置窗口，而用户看到的那个
	//    未必是他刚点出来的那个（改了半天发现改的是另一个）。
	//
	//    拦法：命名互斥体。已经有一个在跑 ⇒ 把**激活消息**转交给它
	//    （带着本次想要的页号），然后自己直接退出。
	//    `Local\` 前缀 = 每个登录会话一个实例（多用户/RDP 下互不干扰）。
	//
	//    ★ `--quiet`（主程序"顺手拉起"带的标记）例外：那种情况下
	//      **只退出、不激活**。理由：拉起 cfg 是自动行为，如果这时
	//      去激活已有窗口，就会把 cfg 抢到前台 —— 而用户此刻可能正在
	//      别的窗口里打字。UIAccess 接管时父 / 子两个实例会**并发**
	//      走到这里，这个 race 是真实存在的（见 cfg_launch.h 的
	//      kQuietSwitch）。
	//   ★ 名字在 `cfg_launch.h`（铁律 127）—— 探针要靠它等"上一个真的走了"
	//     （`TerminateProcess` 异步 ⇒ 只看窗口消没消失会撞 race，见铁律 254）。
	HANDLE singleInstance = CreateMutexW(nullptr, FALSE, R3ShieldCoreCfg::kSingleInstanceMutex);
	if (singleInstance && GetLastError() == ERROR_ALREADY_EXISTS) {
		if (!quietLaunch) {
			if (HWND existing = FindWindowW(R3ShieldCoreCfg::kWindowClass, nullptr)) {
				R3ShieldCoreCfg::AllowProcessForeground(existing);
				PostMessageW(existing, R3ShieldCoreCfg::ActivateMessageId(),
					static_cast<WPARAM>(g_startPage), 0);
			}
		}
		CloseHandle(singleInstance);
		return 0;
	}

	// ★ 预览开关（只为自动核对）：与主程序 `--gui-preview` 用的是**同一组**
	//   环境变量名，理由见 `MEMORY-3`。
	//
	//   配置工具本身不注入、不挂钩 ⇒ 本来就安全；这一组变量解决的是
	//   **确定性**：探针不会打字、也不会点鼠标，没有它们就只能截到
	//   "空输入框 + 闸门屏"，而"实时提示会不会跟着输入变"就只能靠人眼
	//   （铁律 24/28/240/249）。
	{
		// ★ v80：`R3SHIELDCORE_PREVIEW_LOG=<路径>` —— 把 stdout 重定向到文件。
		//
		//   为什么需要：主程序是 GUI 子系统、由 app.cpp 统一把 stdout 重定向
		//   到 `r3shieldcore-console.log`，所以它那些 `[adv] ...` 核对日志
		//   一直能被探针读到。cfg 没有这个重定向 —— 「高级」编辑台搬过来
		//   之后，它的核对日志就**没人看得到**了（探针读不到日志，
		//   判据只能退回"看像素"，那是本项目吃过亏的做法，铁律 24/28）。
		//
		//   ⚠️ 只在设了变量时才重定向 ⇒ 生产路径**不产生**任何新文件，
		//      行为与之前完全一致。
		{
			WCHAR logPath[MAX_PATH * 4] = {};
			if (GetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_LOG", logPath,
					_countof(logPath)) > 0 && logPath[0] != L'\0') {
				FILE* logFile = nullptr;
				if (_wfreopen_s(&logFile, logPath, L"w", stdout) == 0 && logFile) {
					// ★ 必须 `_IONBF`（**不**缓冲），与主程序 app.cpp 的做法一致。
					//
					//   两个理由，都是实测出来的：
					//   ① 探针是 `TerminateProcess` 之后才读日志的 ——
					//      缓冲里的内容**不会**落盘，读到的就是半截
					//      （实测：整行被截断成 `[adv] 初始规则=3 来源=`，
					//       后面接的是另一行，两条都不完整）。
					//   ② 试过 `setvbuf(stdout, nullptr, _IOLBF, 0)` ——
					//      **加了它窗口就建不出来**：进程活着、日志 0 字节、
					//      没有任何窗口，也不报错。这是个只看得见症状、
					//      看不见原因的坑，别再踩。
					setvbuf(stdout, nullptr, _IONBF, 0);
				}
			}
		}

		WCHAR buf[MAX_PATH * 4] = {};
		if (GetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_RULES", buf, _countof(buf)) > 0) {
			wcsncpy_s(g_previewRulesPath, buf, _TRUNCATE);
		}
		if (GetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_EDIT", buf, _countof(buf)) > 0) {
			g_previewEditText = buf;
		}
		// ★ v81：`R3SHIELDCORE_PREVIEW_LOGSRC=event|svc` —— 预览模式下**钉死**
		//   日志页默认选哪一项（探针不会去点下拉框）。
		//
		//   为什么需要：核对环境里引擎**不允许运行**（铁律 175）⇒「事件日志」
		//   这一项会走"引擎未跑 ⇒ 回落文件"那条分支。而「服务日志」那一项
		//   默认根本选不到 ⇒ 不钉的话它的界面**永远核对不到**
		//   （覆盖静默丢失，铁律 142 同款）。
		//
		//   ⚠️ 只在设了变量时才生效 ⇒ 生产路径行为完全不变。
		//   ⚠️ 这个变量名是**代次标记**（`check_dist_sync.sh` 的 v81 节按它查
		//      exe 里的宽串），别改名。
		{
			WCHAR logSrc[16] = {};
			if (GetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_LOGSRC", logSrc,
					_countof(logSrc)) > 0 && logSrc[0] != L'\0') {
				if (_wcsicmp(logSrc, L"svc") == 0) {
					g_previewLogSrcSvc = true;
				} else if (_wcsicmp(logSrc, L"event") == 0) {
					g_previewLogSrcSvc = false;
				}
			}
		}

		WCHAR adv[32] = {};
		if (GetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_ADV", adv, _countof(adv)) > 0) {
			if (_wcsicmp(adv, L"why") == 0) {
				g_advQuizPassed = true;
				g_advWhyDismissed = false;
			} else if (_wcsicmp(adv, L"editor") == 0) {
				g_advQuizPassed = true;
				g_advWhyDismissed = true;
			} else if (_wcsicmp(adv, L"cycle") == 0) {
				// ★ v82：不直接置到编辑台 —— 停在**闸门屏**起步，之后由
				//   定时器一步步切过去（见 g_previewCycleStep 的注释）。
				g_advQuizPassed = false;
				g_advWhyDismissed = false;
				g_previewCycleStep = 0;
			}
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

	// ★ v83：外框圆角（"背景透明圆角"）。优先 DWM 抗锯齿圆角，
	//   不成就退回 region 硬裁剪。判据是 API 返回值，不是版本号。
	{
		const int cornerMode = R3ShieldCoreUi::ApplyRoundedWindow(
			g_main, static_cast<int>(8.0f * CfgDpiScale(g_main) + 0.5f));
		if (cornerMode == 0) {
			printf("[glass] 警告：外框圆角不可用（DWM 与 region 都没成）\n");
		}
	}

	// ★ 高级页的那个原生 EDIT 必须**在首次绘制之前**建好并摆位
	//   （布局函数按客户区算位置，晚一步就会先按 0×0 画一帧）。
	AdvCreateEdit(g_main);
	if (!g_previewEditText.empty()) {
		AdvSetEditText(g_previewEditText);
	}

	// ★ SW_SHOWDEFAULT（不是 SW_SHOW）：主程序自动拉起我们时用的是
	//   `STARTUPINFO.wShowWindow = SW_SHOWMINNOACTIVE`（别抢用户焦点）；
	//   只有用 SW_SHOWDEFAULT 才会**尊重**那个值（第一次 ShowWindow 的约定）。
	//   写成 SW_SHOW 的话，被自动拉起时也会"跳"到前台打断用户。
	ShowWindow(g_main, SW_SHOWDEFAULT);
	UpdateWindow(g_main);

	// ★ v82：演练模式 —— 首帧（闸门屏）画完之后，用定时器一步步切到编辑台。
	//
	//   必须在 `UpdateWindow` **之后**起步：我们要的是"闸门屏先真的画出来，
	//   再切过去"，这样才复现"旧字留在原地"的条件。
	//   150ms 一步 ⇒ 300ms 走完两次切换；探针那边是窗口出现后等 1200ms 才截图
	//   ⇒ 截图时已经稳定停在编辑台。
	if (g_previewCycleStep >= 0) {
		SetTimer(g_main, kCycleTimerId, 150, nullptr);
	}

	// ★ 托盘图标：窗口出来了就注册（"关闭窗口 = 收进托盘"的前提）。
	//
	//   ⚠️ 加不上不能当没事发生 —— `CfgHideToTray` 会检查 `added()` 并退回
	//      "最小化到任务栏"（否则窗口从任务栏和托盘同时消失，用户找不到它）。
	//   ⚠️ 用 `kCallbackMessageCfg`（与主程序**不同**的字符串）。
	if (!g_tray.icon.Add(g_main, CfgTrayIcon(), CfgTrayTipText(),
			R3ShieldCoreTray::kCallbackMessageCfg)) {
		printf("[tray] 警告：配置工具托盘图标添加失败（Shell_NotifyIcon(NIM_ADD) 失败），"
			"关闭窗口将退回最小化到任务栏\n");
	} else {
		// ★ 带上宽串代次标记：它在共享头里（铁律 127），闸门用 `strings -el`
		//   查它来确认"托盘这套代码真的编进了这个 exe"。用 `%ls` 传宽串
		//   —— 传窄串的话编进去的是 GBK 字节，`strings -el` 查不到。
		printf("[tray] 配置工具托盘图标已就绪（关闭窗口 = 收进托盘）标记=%ls\n",
			R3ShieldCoreTray::kGenerationMarker);
	}

	MSG msg = {};
	while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}
	return static_cast<int>(msg.wParam);
}
