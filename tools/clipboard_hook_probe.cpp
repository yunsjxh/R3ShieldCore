// clipboard_hook_probe.cpp -- 验证 `hook_clipboard` 这个 ini 开关**真的能关掉剪贴板 hook**。
//
// ============================================================================
// 为什么不能用日志当判据（★ 这是本探针存在的理由）
// ============================================================================
//
// `hook_clipboard=0` 生效的表现是「**什么都没发生**」—— 引擎不挂 hook，
// 于是运行时日志里也**不会有任何** CLIP 行。这时候：
//
//   · 「日志里没有 CLIP BLOCK」 ≠ 「hook 没挂」——
//     引擎没跑 / 目标没被注入 / 用户根本没碰剪贴板，都会造成同样的现象。
//   · 而且 `clipboard_guard.cpp:325` 那条
//     `LOG(L"ClipboardGuard: hook_clipboard 未开启，本进程不挂剪贴板 hook")`
//     走的是 `Logger::LogLine` ⇒ **只 OutputDebugString（+ 可选 stderr），不落文件**
//     ⇒ 用 grep 翻日志**永远翻不到它**（要看它得挂 DebugView）。
//
// ⇒ 唯一可靠的判据是**在场证据**：**直接看被注入进程里那个函数的首字节**。
//   MinHook 的 detour 会把函数序言改写成 `jmp`：
//     E9 rel32            （相对跳）
//     FF 25 <abs>         （绝对跳）
//     或 hot-patch 形态：开头若干 `90`(nop) + `EB`/`E9`
//   函数没被 hook 时，首字节是原序言（`48 89 5C 24 ...` 这类）。
//
// ============================================================================
// 为什么要 detour 在自己进程内读（而不是父进程 ReadProcessMemory）
// ============================================================================
//
// 引擎的 `hook_memory_op` 会拦"跨进程读另一个进程的内存"。父进程
// `ReadProcessMemory(靶子, user32!GetClipboardData, ...)` 很可能**被引擎自己拒掉**
// ⇒ 拿不到字节，看起来像"读失败"，实际上是被 SUT 拦了（铁律 74 同族）。
//
// 所以本探针走 hookcheck 的路子：**靶子进程自己读自己的内存**。
// 此时 `ReadProcessMemory(GetCurrentProcess(), ...)` 是**同进程**读，
// 不触发跨进程判据。而且它本来就是被注入的那个进程，读到的就是真实状态。
//
// ============================================================================
// A/B 反向对照（★ 铁律 54：修前修后都 PASS = 没测）
// ============================================================================
//
// 同一个 exe 要在两种配置下各跑一次，并且**必须输出不同结果**：
//
//   hook_clipboard=1  ->  user32!GetClipboardData 首字节 == E9  => HOOKED
//   hook_clipboard=0  ->  user32!GetClipboardData 首字节 == 原序言 => NOT-HOOKED
//
// 如果两次都 HOOKED，说明 ini 开关没生效（或写错了 ini）；
// 如果两次都 NOT-HOOKED，说明靶子根本没被注入（或 `hook_clipboard` 判据读不到）。
// 两种"两边一样"都算**假绿**，必须查。
//
// 同时观察第二条独立钩子做**自身有效性对照**：
//   `gdi32!BitBlt`（受 `hook_screen` 控制，与 hook_clipboard **无关**）——
//   它的存在证明"引擎确实注入了这个进程、MinHook 确实在工作"，
//   从而把「开关真的关了」与「注入根本没发生」区分开。★ 这条是本探针的
//   核心分辨力来源：没有它，`hook_clipboard=0` 下的 NOT-HOOKED 无法解释。
//
// 用法：
//   clipboard_hook_probe.exe                  # 当靶子：睡 15s，期间自己读自己
//   clipboard_hook_probe.exe --report         # 立刻读一次并打印（不等注入）
//   clipboard_hook_probe.exe --file <路径>    # 额外把结果同时写进该文件
//
// 典型跑法（★ 必须在**免注入**的终端里驱动，见 MEMORY 铁律 76）：
//   1) 写 hook_clipboard=1 的 ini -> 起引擎 -> 双击本 exe -> 记下结果
//   2) 关引擎；写 hook_clipboard=0 的 ini -> 起引擎 -> 双击本 exe -> 记下结果
//   3) 断言两次结果**不同**，且 =0 那次 BitBlt 仍 HOOKED（证明注入确实发生）

#include <clocale>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

#include <windows.h>

namespace {

// ---------------------------------------------------------------- 字节判读

// MinHook 的 detour 形态。与 hookcheck.cpp 保持同一套判据，便于交叉对照。
enum class Verdict { Unknown, Hooked, NotHooked };

Verdict Classify(const unsigned char* b, SIZE_T n)
{
	if (n < 2) {
		return Verdict::Unknown;
	}
	// E9 rel32 / EB rel8     —— 相对跳
	if (b[0] == 0xE9 || b[0] == 0xEB) {
		return Verdict::Hooked;
	}
	// FF 25 <abs32/64>       —— 绝对跳（x64 下是 `FF 25 rel32`）
	if (b[0] == 0xFF && b[1] == 0x25) {
		return Verdict::Hooked;
	}
	// hot-patch：nop sled 之后跟跳转
	if (b[0] == 0x90 && b[1] == 0x90 && n >= 8 && (b[2] == 0xEB || b[2] == 0xE9)) {
		return Verdict::Hooked;
	}
	if (b[0] == 0x90 && b[1] == 0xE9) {
		return Verdict::Hooked;
	}
	return Verdict::NotHooked;
}

const char* VerdictName(Verdict v)
{
	switch (v) {
	case Verdict::Hooked:    return "HOOKED";
	case Verdict::NotHooked: return "NOT-HOOKED";
	default:                 return "UNKNOWN";
	}
}

// ---------------------------------------------------------------- 读一个导出

struct ProbeResult
{
	const char* module;
	const char* function;
	bool        loaded;      // 模块/导出是否找得到
	unsigned char bytes[8];
	SIZE_T      readCount;
	Verdict     verdict;
};

ProbeResult ProbeExport(const char* moduleName, const char* functionName)
{
	ProbeResult r = {};
	r.module = moduleName;
	r.function = functionName;
	r.verdict = Verdict::Unknown;

	// ★ 刻意**不**主动 LoadLibrary：要测的是"这个进程本来会被引擎怎么处理"。
	//   但 GetClipboardData / BitBlt 这类要用的模块，靶子自己要用，
	//   所以这里显式加载反而更接近"一个真的会碰剪贴板的进程"。
	//   两种做法都会命中同一份已加载映像（user32/gdi32 在 GUI 进程里)。
	HMODULE mod = GetModuleHandleA(moduleName);
	if (!mod) {
		mod = LoadLibraryA(moduleName);
	}
	if (!mod) {
		return r;
	}

	void* p = reinterpret_cast<void*>(GetProcAddress(mod, functionName));
	if (!p) {
		return r;
	}
	r.loaded = true;

	// ★ 同进程读：不触发引擎的跨进程内存判据。
	SIZE_T got = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), p, r.bytes, sizeof(r.bytes), &got) || got == 0) {
		return r;   // verdict 仍是 Unknown
	}
	r.readCount = got;
	r.verdict = Classify(r.bytes, got);
	return r;
}

// ---------------------------------------------------------------- 输出

FILE* g_extraFile = nullptr;

void Emit(const char* fmt, ...)
{
	char buffer[1024];
	va_list args;
	va_start(args, fmt);
	_vsnprintf_s(buffer, _TRUNCATE, fmt, args);
	va_end(args);

	fputs(buffer, stdout);
	fflush(stdout);

	if (g_extraFile) {
		fputs(buffer, g_extraFile);
		fflush(g_extraFile);
	}
}

const char* g_tag = "";   // 由命令行给出，写进每行，方便 A/B 两份输出并排比

void ReportAll()
{
	// ① 受 `hook_clipboard` 控制的：剪贴板读取两个挂载点
	// ② 独立对照：`hook_screen` 控制的 gdi32!BitBlt
	//    —— 它**与 hook_clipboard 无关**，用来证明"注入确实发生了"。
	struct { const char* mod; const char* fn; const char* label; } kTargets[] = {
		{ "user32.dll", "GetClipboardData", "clip" },   // hook_clipboard
		{ "user32.dll", "OpenClipboard",    "clip" },   // hook_clipboard
		{ "gdi32.dll",  "BitBlt",           "screen" }, // hook_screen（独立对照）
	};

	Emit("%s[probe] pid=%lu\n", g_tag, (unsigned long)GetCurrentProcessId());

	for (const auto& t : kTargets)
	{
		ProbeResult r = ProbeExport(t.mod, t.fn);
		if (!r.loaded) {
			Emit("%s[probe] %-10s %-22s %-10s (导出不存在)\n",
				g_tag, t.mod, t.fn, "N/A");
			continue;
		}
		if (r.verdict == Verdict::Unknown) {
			Emit("%s[probe] %-10s %-22s %-10s (读内存失败 err=%lu)\n",
				g_tag, t.mod, t.fn, "UNKNOWN", GetLastError());
			continue;
		}
		Emit("%s[probe] %-10s %-22s %-10s %02X %02X %02X %02X  (%s)\n",
			g_tag, t.mod, t.fn, VerdictName(r.verdict),
			r.bytes[0], r.bytes[1], r.bytes[2], r.bytes[3], t.label);
	}

	Emit("%s[probe] done\n", g_tag);
}

} // namespace

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	std::string extraFile;
	bool immediate = false;

	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "--report") == 0) {
			immediate = true;
		}
		else if (strcmp(argv[i], "--tag") == 0 && i + 1 < argc) {
			g_tag = argv[++i];
		}
		else if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
			extraFile = argv[++i];
		}
	}

	if (!extraFile.empty())
	{
		// ★ 发布目录是加固的（标准用户写不进去），所以这里失败要**明说**，
		//   不能让"没写进去"看起来像"没结果"。
		if (fopen_s(&g_extraFile, extraFile.c_str(), "wb") != 0 || !g_extraFile) {
			fprintf(stderr, "[probe] WARN: 打不开输出文件 %s —— 结果只在 stdout\n",
				extraFile.c_str());
			g_extraFile = nullptr;
		}
	}

	if (immediate)
	{
		// 不等注入，立刻读一次（用于确认探针自身工作正常 / 做"未注入"基线）
		ReportAll();
		return 0;
	}

	// 靶子模式：给引擎的注入器（同步路 + 轮询路）足够时间。
	//   3 秒足够轮询路（默认 10ms 一轮）扫到；报告放在末尾。
	Emit("%s[probe] 等待 4s 让引擎完成注入...\n", g_tag);
	Sleep(4000);
	ReportAll();

	// 再活一会儿，方便父进程观察 / 手动核对。
	Sleep(1000);
	return 0;
}
