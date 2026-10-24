// engine_main.cpp —— 「引擎」独立进程（r3shieldcore-engine.exe）。
//
//   ────────────────────────────────────────────────────────────────
//   它是什么（v89）
//   ────────────────────────────────────────────────────────────────
//   拆进程之前，引擎是 `r3shieldcore-lib.dll`，被界面进程 `LoadLibrary`，
//   12 个导出直接当函数指针调。界面里任何一个绘制 bug 崩掉，防护跟着一起没。
//
//   现在它是**自己的进程**：
//     · 仍然 `LoadLibrary` 同一个 DLL（注入链路零改动，见 engine_ipc.h 的头注释）；
//     · 自己跑注入扫描 / 事件排空；
//     · 通过**加密命名管道**把事件与统计推给界面（协议见 engine_ipc.h）。
//   ⇒ 界面关掉、甚至崩掉，引擎继续防护。只有收到 `StopEngine` 才收尾退出。
//
//   ────────────────────────────────────────────────────────────────
//   这个进程里**没有**的东西（刻意）
//   ────────────────────────────────────────────────────────────────
//   · 没有窗口、没有 GL、没有场景渲染 —— 界面那套（ui_scene.h 等）一行都不编进来。
//   · 没有 `R3ShieldCoreStats` —— 那是界面的日志/统计聚合，属于客户端。
//   · 没有 ARK 的扫描与表格 —— 但**内部退出**在引擎侧（它需要本地 DLL 基址算
//     导出偏移，界面进程已经不再加载那个 DLL 了）。
//
//   ────────────────────────────────────────────────────────────────
//   命令行
//   ────────────────────────────────────────────────────────────────
//     --config-dir <dir>     ini 所在目录（默认 = 本 exe 目录）
//     --parent-pid <pid>     界面进程 pid（**只记日志**；引擎不跟着它退出）
//     --log-file <path>      控制台日志落盘路径（默认 = 本 exe 目录下）
//     --version              打印代次标记后退出（闸门用）
//     --dry-run              **不 LoadLibrary、不建会话、不注入**，只跑加密 IPC
//     --fake-events          配合 --dry-run：每秒造 4 条假事件验编解码往返
//
//   `--dry-run` 为什么必须有：本机有一条铁律「禁止运行引擎」—— 全局注入会
//   hook 编辑器，一跑就崩。可"加密管道通不通、事件编解码对不对"不能靠推理
//   （协议 bug 恰恰是最容易骗过自己的一类）。dry-run 把**传输层**和**注入层**
//   切开：管道、握手、AES-GCM、帧编解码、请求-应答全都能真跑真验，一个 hook
//   都不装。它不是"简化版引擎"，是**故意只剩管道**的引擎。
//
#include "stdafx.h"
#include "../ark_actions.h"
#include "../engine_control.h"
#include "../r3shieldcore_config.h"

#include <r3shieldcore/engine_ipc.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ipc = R3ShieldCoreEngineIpc;
using R3ShieldCore::Event;

namespace
{
	// ---------------------------------------------------------------------
	// 全局状态
	// ---------------------------------------------------------------------
	std::atomic<bool> g_stop{ false };
	std::atomic<HANDLE> g_currentPipe{ nullptr };
	std::atomic<uint32_t> g_injectedTotal{ 0 };
	std::atomic<uint32_t> g_currentMode{ 0 };

	// ★ v90：本进程**有没有可用的控制台**（决定要不要注册 Ctrl 处理器）。
	//   WINDOWS 子系统默认没有；只有在"从 cmd 里手动跑"或显式 `--console`
	//   时才附加/新建一个。
	bool g_consoleAttached = false;
	// ★ 另一个独立的问题：**stdout 能不能写**。
	//   它和控制台是两件事 —— 被 `> out.txt` 重定向时没有控制台但 stdout 可写，
	//   而 AttachConsole 成功后 stdout 仍然绑在继承来的管道上（不是控制台）。
	//   混成一个标志会出两种怪事：手动跑看不到输出、重定向时输出跑到别处。
	bool g_stdoutOk = false;

	// 事件双缓冲：drain 线程往里写，IPC 线程 swap 出来发。
	// ★ 用 vector<Event> 而不是"直接发给管道"：drain 线程**必须**尽快返回
	//   （它是在引擎主循环的节奏里被调的），写管道可能阻塞几十毫秒。
	std::mutex g_eventMutex;
	std::vector<Event> g_pendingEvents;

	// 离线时最多留多少条。界面不在时没人 swap，涨到上限就丢最旧的。
	// ★ 3000 × sizeof(Event) ≈ 12MB。留这么多是为了"界面重启后能补一小段"，
	//   不是为了当存储用 —— 真正的历史在 `R3ShieldCoreLog` 的日志文件里。
	constexpr size_t kMaxPendingEvents = 3000;
	std::atomic<uint32_t> g_pendingDropped{ 0 };

	FILE* g_logFile = nullptr;

	// ★ 日志会被三个线程同时调（主线程/IPC 读线程/推送线程 + 假事件线程）。
	//   `fputws` + `fputwc` + `fflush` 是**三次**独立调用，不加锁会互相插进
	//   对方中间，日志变成一行半截中文接半截英文（很难看出是插行，像乱码）。
	std::mutex g_logMutex;

	// ---------------------------------------------------------------------
	// 日志
	// ---------------------------------------------------------------------
	// ★ 不用 `printf("%ls")`：它依赖 setlocale，中文系统上没设 locale 时
	//   整行会**静默截断**（铁律 252，界面侧踩过一次）。这里统一走
	//   `vswprintf` + `WideCharToMultiByte(CP_ACP)`，控制台和文件都正常。
	//
	// ★★ 控制台用**窄写**（CP_ACP），文件用**宽写** —— 这不是风格问题：
	//   日志文件是按 `ccs=UTF-8` 打开的，此时对同一个流做 `fputs`（窄写）
	//   会触发 CRT 的**无效参数处理** ⇒ `__fastfail` ⇒ 进程直接以
	//   `0xC0000409`(STATUS_STACK_BUFFER_OVERRUN) 退出。
	//   症状极具误导性：**第一行只写进了 stdout 就死了**，日志文件里只剩
	//   一个 BOM，控制台/事件查看器都没有任何提示，看起来像"引擎启动即崩"。
	//   （2026-10-23 实测踩到，花了一轮才定位到 fputs。）
	//   ⇒ 别把下面这段改回 `fputs(abuf, g_logFile)`。
	void LogLine(const wchar_t* fmt, ...)
	{
		wchar_t wbuf[2048];
		va_list args;
		va_start(args, fmt);
		_vsnwprintf_s(wbuf, _countof(wbuf), _TRUNCATE, fmt, args);
		va_end(args);

		std::lock_guard<std::mutex> lock(g_logMutex);

		// 控制台：CP_ACP 窄字节（中文控制台就是 CP936）
		// ★ v90：引擎改成 WINDOWS 子系统后**默认没有控制台**，这里必须先判
		//   `g_stdoutOk` —— 否则对无效的 stdout 调 `fputs` 会走进 CRT 的
		//   无效参数处理器（`__fastfail`，见上面那段血泪注释的同一个坑）。
		if (g_stdoutOk) {
			char abuf[6144];
			const int n = WideCharToMultiByte(CP_ACP, 0, wbuf, -1, abuf, sizeof(abuf) - 1,
				nullptr, nullptr);
			if (n > 1) {
				abuf[n - 1] = '\n';
				abuf[n] = 0;
				fputs(abuf, stdout);
				fflush(stdout);
			}
		}

		// 文件：宽写（走 ccs=UTF-8 的编码器）
		if (g_logFile) {
			fputws(wbuf, g_logFile);
			fputwc(L'\n', g_logFile);
			fflush(g_logFile);
		}
	}

	// ---------------------------------------------------------------------
	// 事件旁观者：把 DLL 抽出来的事件攒进本地队列
	// ---------------------------------------------------------------------
	void OnEngineEvent(const Event& event, void* /*context*/)
	{
		std::lock_guard<std::mutex> lock(g_eventMutex);
		if (g_pendingEvents.size() >= kMaxPendingEvents) {
			// 丢最旧的一条，而不是拒绝新的 —— 日志里最新的更重要。
			g_pendingEvents.erase(g_pendingEvents.begin());
			g_pendingDropped.fetch_add(1, std::memory_order_relaxed);
		}
		g_pendingEvents.push_back(event);
	}

	std::vector<Event> TakePendingEvents()
	{
		std::vector<Event> out;
		std::lock_guard<std::mutex> lock(g_eventMutex);
		out.swap(g_pendingEvents);
		return out;
	}

	// ---------------------------------------------------------------------
	// 命令行
	// ---------------------------------------------------------------------
	struct Options
	{
		std::filesystem::path configDir;
		std::filesystem::path logPath;
		uint32_t parentPid = 0;
		bool printVersion = false;
		// ★ `--dry-run`：**不 LoadLibrary、不建会话、不注入**，只跑 IPC 服务。
		//
		//   为什么必须有它：本机有一条铁律「禁止运行引擎」——全局注入会 hook
		//   编辑器，一跑就崩。但没有它，"加密管道能不能通、事件编解码对不对"
		//   就永远只能靠推理（而协议类 bug 恰恰是推理最容易骗过自己的地方）。
		//   ⇒ dry-run 把**传输层**和**注入层**切开：管道、握手、AES-GCM、
		//     帧编解码、请求-应答全都能真跑真验，一个 hook 都不装。
		bool dryRun = false;
		// 配合 dry-run：每秒造几条假事件，专门验 `EncodeEvents/DecodeEvents`
		// 的往返一致性（含中文路径、空字段、超长命令行）。
		bool fakeEvents = false;
		// ★ v90：强制开一个控制台。
		//   WINDOWS 子系统默认**没有**控制台（用户要求「引擎默认不显示控制台」）。
		//   从 cmd/PowerShell 里手动跑时，`AttachConsole(父进程)` 已经能让你看到
		//   输出；这个开关是给"没有父控制台（比如从任务计划/快捷方式起）但又想
		//   看日志"的场景用的。
		bool console = false;
	};

	std::filesystem::path ExeDirectory()
	{
		wchar_t buf[MAX_PATH * 2] = {};
		const DWORD n = GetModuleFileNameW(nullptr, buf, _countof(buf));
		std::filesystem::path p(std::wstring(buf, n));
		return p.parent_path();
	}

	Options ParseOptions(int argc, wchar_t** argv)
	{
		Options opt;
		opt.configDir = ExeDirectory();

		for (int i = 1; i < argc; ++i) {
			const std::wstring arg = argv[i];
			auto next = [&](const wchar_t* name) -> const wchar_t* {
				if (i + 1 < argc) {
					return argv[++i];
				}
				LogLine(L"参数 %s 后面缺少值，忽略", name);
				return nullptr;
			};
			if (arg == L"--config-dir") {
				if (const wchar_t* v = next(L"--config-dir")) {
					opt.configDir = v;
				}
			}
			else if (arg == L"--log-file") {
				if (const wchar_t* v = next(L"--log-file")) {
					opt.logPath = v;
				}
			}
			else if (arg == L"--parent-pid") {
				if (const wchar_t* v = next(L"--parent-pid")) {
					opt.parentPid = static_cast<uint32_t>(wcstoul(v, nullptr, 10));
				}
			}
			else if (arg == L"--version") {
				opt.printVersion = true;
			}
			else if (arg == L"--dry-run") {
				opt.dryRun = true;
			}
			else if (arg == L"--fake-events") {
				opt.fakeEvents = true;
			}
			else if (arg == L"--console") {
				opt.console = true;
			}
			else {
				LogLine(L"未知参数：%s（忽略）", arg.c_str());
			}
		}

		if (opt.logPath.empty()) {
			opt.logPath = ExeDirectory() / L"r3shieldcore-engine-console.log";
		}
		return opt;
	}

	// ---------------------------------------------------------------------
	// 控制台退出信号
	// ---------------------------------------------------------------------
	BOOL WINAPI ConsoleCtrlHandler(DWORD type)
	{
		switch (type) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			LogLine(L"收到控制台退出信号(%lu)，准备收尾", static_cast<unsigned long>(type));
			g_stop.store(true, std::memory_order_relaxed);
			// 主线程可能正阻塞在 ReadFile / ConnectNamedPipe 上 —— 必须打断它，
			// 否则"收到信号"和"真的退出"之间会卡住（铁律 254 的近亲）。
			if (HANDLE h = g_currentPipe.load(std::memory_order_relaxed)) {
				CancelIoEx(h, nullptr);
			}
			return TRUE;
		default:
			return FALSE;
		}
	}

	// ---------------------------------------------------------------------
	// 管道服务端
	// ---------------------------------------------------------------------
	HANDLE CreateServerPipe(const std::wstring& name, PSECURITY_DESCRIPTOR sd)
	{
		SECURITY_ATTRIBUTES sa = {};
		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = sd;
		sa.bInheritHandle = FALSE;

		// ★ PIPE_ACCESS_DUPLEX：请求-应答和事件推送共用一条连接。
		//   `FILE_FLAG_OVERLAPPED`：ConnectNamedPipe 要能被打断（见下面 Accept）。
		//   `nMaxInstances = 1`：一个引擎只服务一个界面 —— 两个界面同时改模式
		//   会互相覆盖，且日志顺序会乱，没有意义。
		return CreateNamedPipeW(name.c_str(),
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			1, 1u << 20, 1u << 20, 0, &sa);
	}

	// 握手。成功返回 true，并把会话密钥装进 aead。
	bool Handshake(HANDLE pipe, ipc::Aead& aead, std::wstring& err)
	{
		std::string hello;
		if (!ipc::ReadLine(pipe, hello, ipc::kMaxHandshakeBytes)) {
			err = L"读 HELLO 失败（对端不是我们的客户端，或握手超时）";
			return false;
		}

		ipc::HelloInfo hi;
		if (!ipc::ParseHello(hello, hi)) {
			err = L"HELLO 文法不对";
			ipc::WriteLine(pipe, "ERR|bad hello");
			return false;
		}
		err = ipc::CheckPeerCompatible(hi.protocolVersion, hi.abiVersion, hi.eventBytes);
		if (!err.empty()) {
			// 把原因也回给对端 —— 界面上要能直接看到"为什么连不上"。
			char utf8[512] = {};
			WideCharToMultiByte(CP_UTF8, 0, err.c_str(), -1, utf8, sizeof(utf8) - 1,
				nullptr, nullptr);
			ipc::WriteLine(pipe, std::string("ERR|") + utf8);
			return false;
		}

		BYTE master[ipc::kKeyBytes] = {};
		if (!ipc::EnsureMasterKey(master, true, &err)) {
			ipc::WriteLine(pipe, "ERR|master key unavailable");
			return false;
		}

		BYTE serverNonce[32] = {};
		if (!NT_SUCCESS(BCryptGenRandom(nullptr, serverNonce, sizeof(serverNonce),
			BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			SecureZeroMemory(master, sizeof(master));
			err = L"BCryptGenRandom 失败";
			ipc::WriteLine(pipe, "ERR|rng failed");
			return false;
		}

		const std::string welcome = ipc::MakeWelcome(serverNonce, GetCurrentProcessId());
		if (!ipc::WriteLine(pipe, welcome)) {
			SecureZeroMemory(master, sizeof(master));
			err = L"回 WELCOME 失败";
			return false;
		}

		BYTE sessionKey[ipc::kKeyBytes] = {};
		const bool derived = ipc::DeriveSessionKey(master, hi.nonce, serverNonce, sessionKey);
		SecureZeroMemory(master, sizeof(master));
		if (!derived) {
			err = L"派生会话密钥失败";
			return false;
		}
		const bool ready = aead.Init(sessionKey);
		if (ready) {
			// 指纹（单向，可安全写日志）：两端比对就知道"是不是同一把密钥"。
			const std::string fp = ipc::KeyFingerprint(sessionKey);
			LogLine(L"会话密钥已派生（指纹 %hs）—— 对端应打印同一个指纹", fp.c_str());
		}
		SecureZeroMemory(sessionKey, sizeof(sessionKey));
		if (!ready) {
			err = L"AES-256-GCM 初始化失败";
			return false;
		}
		return true;
	}

	struct ConnState
	{
		HANDLE pipe = nullptr;
		ipc::Aead* aead = nullptr;
		ipc::FrameWriter* writer = nullptr;
		std::mutex* writeMutex = nullptr;
		std::atomic<bool>* alive = nullptr;
		// ★ `--dry-run` 下这里是 **nullptr**（不 LoadLibrary ⇒ 根本没有 EngineControl）。
		//   下游每一处都必须**显式判空**并给出一个诚实的回答，而不是"假装它有值"。
		//   理由：dry-run 存在的意义就是让"管道通不通"和"注入对不对"变成两个
		//   可以分别证伪的问题；如果 dry-run 里偷偷编个假的 EngineControl，
		//   它验出来的就是假货（铁律 97：不可诊断的判定 = 没有判定）。
		EngineControl* engine = nullptr;
		std::atomic<uint32_t>* injected = nullptr;
		std::atomic<uint32_t>* mode = nullptr;
	};

	// 写应答（所有写都必须过 writeMutex —— writer.seq 是共享的）。
	void SendFrame(ConnState& st, ipc::Msg type, const void* data, size_t len)
	{
		std::lock_guard<std::mutex> lock(*st.writeMutex);
		if (!st.writer->Write(st.pipe, *st.aead, type, data, len)) {
			// ★ 必须记一行：写失败会让整条连接静默死掉（读线程下一轮就退），
			//   界面上表现为"连着连着就不动了"，而引擎日志里如果什么都没有，
			//   那就只能靠猜（铁律 97）。
			LogLine(L"写帧失败 type=%u len=%zu err=%lu —— 标记连接断开",
				static_cast<unsigned>(type), len,
				static_cast<unsigned long>(GetLastError()));
			st.alive->store(false, std::memory_order_relaxed);
		}
	}

	void SendOk(ConnState& st, uint8_t code)
	{
		SendFrame(st, ipc::Msg::Ok, &code, 1);
	}

	void SendErr(ConnState& st, const wchar_t* text)
	{
		char utf8[1024] = {};
		WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, sizeof(utf8) - 1, nullptr, nullptr);
		const size_t len = strlen(utf8);
		std::vector<BYTE> payload(4 + len);
		const uint32_t n = static_cast<uint32_t>(len);
		memcpy(payload.data(), &n, 4);
		memcpy(payload.data() + 4, utf8, len);
		SendFrame(st, ipc::Msg::Err, payload.data(), payload.size());
	}

	void BuildStats(EngineControl* engine, ipc::StatsPayload& s)
	{
		s = {};
		if (engine) {
			s.droppedEvents = engine->DroppedEventCount();
			ULONG shown = 0, allowed = 0, denied = 0, timedOut = 0;
			engine->ReadPromptStats(shown, allowed, denied, timedOut);
			s.promptShown = shown;
			s.promptAllowed = allowed;
			s.promptDenied = denied;
			s.promptTimedOut = timedOut;
			ULONG asked = 0, blocked = 0;
			engine->ReadHighRiskStats(asked, blocked);
			s.highRiskAsked = asked;
			s.highRiskBlocked = blocked;
		}
		else {
			// dry-run：DLL 没加载 ⇒ 所有 DLL 侧计数天然为 0。唯一有意义的数字是
			// **本地队列丢了几个**（界面不在时队列涨到上限会丢最旧的）。
			s.droppedEvents = g_pendingDropped.load(std::memory_order_relaxed);
		}
		s.injectedTotal = g_injectedTotal.load(std::memory_order_relaxed);
		s.mode = g_currentMode.load(std::memory_order_relaxed);
		s.enginePid = GetCurrentProcessId();
	}

	// 处理一条请求。返回 false = 该断开连接。
	bool HandleRequest(ConnState& st, ipc::Msg type, const std::vector<BYTE>& payload)
	{
		switch (type) {
		case ipc::Msg::Ping:
			// ★ 记一行：Ping 是"通道是否活着"的唯一探针。它有没有到、
			//   到了之后回没回得去，是排查"连上就不动"的分水岭。
			LogLine(L"收到 Ping → 回 Pong");
			SendFrame(st, ipc::Msg::Pong, nullptr, 0);
			return true;

		case ipc::Msg::SetMode: {
			if (payload.size() < 4) {
				SendErr(st, L"SetMode 载荷太短");
				return true;
			}
			uint32_t mode = 0;
			memcpy(&mode, payload.data(), 4);
			if (!st.engine) {
				// dry-run：**没有 DLL 可切**。这里回 ok 只代表"这条请求在加密通道上
				// 走通了"，不代表模式真的变了 —— 日志必须说清楚，否则又是一次假绿。
				LogLine(L"SetMode(%lu) → dry-run：仅验证通道，未切换（DLL 未加载）",
					static_cast<unsigned long>(mode));
				SendOk(st, 1);
				return true;
			}
			const bool ok = st.engine->SetMode(static_cast<R3ShieldCore::Mode>(mode));
			if (ok) {
				st.mode->store(mode, std::memory_order_relaxed);
			}
			LogLine(L"SetMode(%lu) → %s", static_cast<unsigned long>(mode),
				ok ? L"成功" : L"失败（DLL 不支持运行期切换或通道未建立）");
			SendOk(st, ok ? 1 : 0);
			return true;
		}

		case ipc::Msg::ReadStats: {
			ipc::StatsPayload s;
			BuildStats(st.engine, s);
			SendFrame(st, ipc::Msg::Stats, &s, sizeof(s));
			return true;
		}

		case ipc::Msg::RiskCheck: {
			// 载荷：u32 pathChars + WCHAR[] + u32 rootChars + WCHAR[]
			if (payload.size() < 8) {
				SendErr(st, L"RiskCheck 载荷太短");
				return true;
			}
			const BYTE* p = payload.data();
			uint32_t pathChars = 0, rootChars = 0;
			memcpy(&pathChars, p, 4);
			p += 4;
			if (payload.size() < 4 + pathChars * sizeof(WCHAR) + 4) {
				SendErr(st, L"RiskCheck 路径长度越界");
				return true;
			}
			std::wstring imagePath(reinterpret_cast<const wchar_t*>(p), pathChars);
			p += pathChars * sizeof(WCHAR);
			memcpy(&rootChars, p, 4);
			p += 4;
			if (payload.size() < static_cast<size_t>(p - payload.data()) + rootChars * sizeof(WCHAR)) {
				SendErr(st, L"RiskCheck systemRoot 长度越界");
				return true;
			}
			std::wstring systemRoot(reinterpret_cast<const wchar_t*>(p), rootChars);

			const char* reason = st.engine
				? st.engine->CheckHighRiskProcess(imagePath.c_str(), systemRoot.c_str())
				: nullptr;
			// ★ 注意这里**不是**"dry-run 一律放行"的偷懒分支：CheckHighRiskProcess
			//   是纯判据（看进程名/路径），它不依赖 DLL。但 dry-run 下我们刻意
			//   不调它 —— 让 dry-run 的结果只反映传输层，不掺入策略层。
			//   真要验策略层请用 `tools/spoof_console` 那一套。
			std::vector<BYTE> out;
			if (reason && *reason) {
				const size_t len = strlen(reason);
				out.resize(1 + 4 + len);
				out[0] = 1;
				const uint32_t n = static_cast<uint32_t>(len);
				memcpy(out.data() + 1, &n, 4);
				memcpy(out.data() + 5, reason, len);
			}
			else {
				out.push_back(0);
			}
			SendFrame(st, ipc::Msg::Ok, out.data(), out.size());
			return true;
		}

		case ipc::Msg::SelfExit: {
			if (payload.size() < 4) {
				SendErr(st, L"SelfExit 载荷太短");
				return true;
			}
			uint32_t pid = 0;
			memcpy(&pid, payload.data(), 4);
			// ★ 内部退出必须在**引擎进程**里做：它要用"本地 DLL 基址"算导出偏移，
			//   而界面进程已经不再加载那份 DLL 了（分进程的必然结果）。
			ArkActions::Outcome outcome = {};
			if (st.engine) {
				outcome = ArkActions::Perform(pid, ArkActions::Action::InternalExit,
					GetCurrentProcessId(), st.engine->LocalEngineDllBase());
			}
			else {
				// dry-run：没有本地 DLL ⇒ 算不出导出偏移 ⇒ 老实回 `ExportMissing`，
				// 而不是编一个"成功"。界面上它会显示成"部署包太旧"，那是**对的**
				// ——在 dry-run 这个语境里确实没有可用的 DLL。
				outcome.Code = ArkActions::Result::ExportMissing;
			}
			uint8_t buf[12] = {};
			buf[0] = static_cast<uint8_t>(outcome.Code);
			buf[1] = outcome.DllPresent ? 1 : 0;
			buf[2] = outcome.DllSameBuild ? 1 : 0;
			memcpy(buf + 4, &outcome.Win32Error, 4);
			memcpy(buf + 8, &outcome.ElapsedMs, 4);
			LogLine(L"SelfExit(pid=%lu) → %s", static_cast<unsigned long>(pid),
				ArkActions::ResultText(outcome.Code));
			SendFrame(st, ipc::Msg::Ok, buf, sizeof(buf));
			return true;
		}

		case ipc::Msg::StopEngine:
			LogLine(L"收到界面发来的「退出引擎」请求，开始收尾");
			SendOk(st, 1);
			g_stop.store(true, std::memory_order_relaxed);
			return false;   // 断开 → 主线程收尾

		default:
			LogLine(L"收到未知消息类型 %u（忽略）", static_cast<unsigned>(type));
			return true;
		}
	}

	// 服务一条已建立的连接，直到对端断开或引擎要停。
	// `engine` 在 `--dry-run` 下为 nullptr（见 ConnState::engine 的注释）。
	void ServeConnection(HANDLE pipe, EngineControl* engine)
	{
		ipc::Aead aead;
		std::wstring err;
		if (!Handshake(pipe, aead, err)) {
			LogLine(L"握手失败：%s", err.c_str());
			return;
		}
		LogLine(L"界面已连上（加密通道就绪，AES-256-GCM）");

		std::atomic<bool> alive{ true };
		std::mutex writeMutex;
		ipc::FrameWriter writer;

		ConnState st;
		st.pipe = pipe;
		st.aead = &aead;
		st.writer = &writer;
		st.writeMutex = &writeMutex;
		st.alive = &alive;
		st.engine = engine;
		st.injected = &g_injectedTotal;
		st.mode = &g_currentMode;

		// 推送线程：事件 + 统计。和读线程分开 —— 单线程同时"阻塞读请求"
		// 和"定时推事件"做不到，除非改成非阻塞轮询（cfg_ipc 在铁律 259 里
		// 踩过 PeekNamedPipe 的坑，这里不重蹈）。
		std::thread pusher([&]() {
			uint32_t statsTick = 0;
			while (alive.load(std::memory_order_relaxed)
				&& !g_stop.load(std::memory_order_relaxed)) {
				Sleep(50);

				std::vector<Event> batch = TakePendingEvents();
				if (!batch.empty()) {
					std::vector<BYTE> payload;
					ipc::EncodeEvents(batch.data(), static_cast<int>(batch.size()), payload);
					SendFrame(st, ipc::Msg::Events, payload.data(), payload.size());
				}

				// 统计 200ms 一次就够（界面按它刷新徽章/计数）。
				if (++statsTick >= 4) {
					statsTick = 0;
					ipc::StatsPayload s;
					BuildStats(engine, s);
					SendFrame(st, ipc::Msg::Stats, &s, sizeof(s));
				}
			}
		});

		// 读线程（本线程）：处理请求。
		ipc::FrameReader reader;
		ipc::Msg type = ipc::Msg::Ping;
		std::vector<BYTE> payload;
		while (alive.load(std::memory_order_relaxed)
			&& !g_stop.load(std::memory_order_relaxed)) {
			std::wstring why;
			if (!reader.Read(pipe, aead, type, payload, &why)) {
				LogLine(L"读帧失败：%s", why.c_str());
				break;
			}
			if (!HandleRequest(st, type, payload)) {
				break;
			}
		}

		alive.store(false, std::memory_order_relaxed);
		// 打断 pusher 的 Sleep/写（它可能正卡在 WriteFile 上）
		CancelIoEx(pipe, nullptr);
		pusher.join();
		LogLine(L"界面已断开");
	}

	// Accept 循环。每次连上一个客户端就 ServeConnection，回来再等下一个。
	// 前置声明：定义在下面（「引擎起来也要带界面」那一节），
	// 而 `AcceptLoop` 要用它 —— 放在这里避免"用了才定义"。
	void LaunchUiIfNeeded(bool launchedByGui, const std::filesystem::path& dir);

	void AcceptLoop(EngineControl* engine, PSECURITY_DESCRIPTOR sd,
		bool launchedByGui, const std::filesystem::path& configDir)
	{
		const std::wstring name = ipc::PipeName();
		LogLine(L"等待界面连接：%s", name.c_str());

		// ★ 「引擎起来也要带界面」：**管道建好之后**再拉起界面。
		//   顺序很重要 —— 界面一启动就会 `ConnectOnly(300)` 试连，
		//   如果这时管道还没建，它会白等一轮、还会顺手多拉一个引擎
		//   （被单实例互斥体挡掉，但日志里会多一段莫名其妙的"本实例退出"）。
		bool uiLaunched = false;

		while (!g_stop.load(std::memory_order_relaxed)) {
			HANDLE pipe = CreateServerPipe(name, sd);
			if (pipe == INVALID_HANDLE_VALUE) {
				LogLine(L"CreateNamedPipe 失败 err=%lu",
					static_cast<unsigned long>(GetLastError()));
				Sleep(500);
				continue;
			}
			g_currentPipe.store(pipe, std::memory_order_relaxed);

			if (!uiLaunched) {
				uiLaunched = true;
				LaunchUiIfNeeded(launchedByGui, configDir);
			}

			// 连接（overlapped，好让 g_stop 能打断）
			bool connected = false;
			OVERLAPPED ov = {};
			ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			if (!ConnectNamedPipe(pipe, &ov)) {
				const DWORD e = GetLastError();
				if (e == ERROR_PIPE_CONNECTED) {
					connected = true;
				}
				else if (e == ERROR_IO_PENDING) {
					while (!g_stop.load(std::memory_order_relaxed)) {
						const DWORD w = WaitForSingleObject(ov.hEvent, 200);
						if (w == WAIT_OBJECT_0) {
							connected = true;
							break;
						}
					}
					if (!connected) {
						CancelIoEx(pipe, nullptr);
					}
				}
				else {
					LogLine(L"ConnectNamedPipe 失败 err=%lu",
						static_cast<unsigned long>(e));
				}
			}
			else {
				connected = true;
			}
			if (ov.hEvent) {
				CloseHandle(ov.hEvent);
			}

			if (connected && !g_stop.load(std::memory_order_relaxed)) {
				ServeConnection(pipe, engine);
			}

			g_currentPipe.store(nullptr, std::memory_order_relaxed);
			DisconnectNamedPipe(pipe);
			CloseHandle(pipe);
		}
	}

	// ---------------------------------------------------------------------
	// 假事件发生器（**只给 `--dry-run --fake-events` 用**）
	// ---------------------------------------------------------------------
	// 它存在的唯一理由：把 `EncodeEvents/DecodeEvents` 的**往返**跑成可判定的
	// 证据。协议类 bug 是最会骗过推理的一类 —— "我觉得我写对了"和"它真的对"
	// 之间只差一次真跑。
	//
	// 所以每条假事件都刻意踩一个**编解码最容易错**的点：
	//   ① 中文键路径 / 中文值名 —— UTF-16 汉字，ASCII 糊不过去；
	//   ② 空字段 —— KeyPath/ValueName 长度 0，不能"顺手"多写一个 NUL；
	//   ③ 超长命令行 —— 贴到 `CommandLine[512]` 边界，验定长截断；
	//   ④ 网络字段 —— `TargetPort/NetProtocol/LocalPort` 夹在 KeyPath 与
	//      DllPath **之间**，不在"固定区"里；漏掉一个就整段错位，
	//      症状是"端口"显示成一串乱码路径（极难反查）；
	//   ⑤ 尾部字段 —— `LocalAddress` + `Flags2`，最容易在"只发固定区"
	//      的实现里被静默丢掉（丢了自己还不知道，因为没人比对）。
	LONG64 NowFileTime()
	{
		FILETIME ft = {};
		GetSystemTimeAsFileTime(&ft);
		ULARGE_INTEGER u;
		u.LowPart = ft.dwLowDateTime;
		u.HighPart = ft.dwHighDateTime;
		return static_cast<LONG64>(u.QuadPart);
	}

	void PushFakeEvents(uint32_t round)
	{
		std::vector<Event> batch;

		// ① 注册表 SetValueKey —— 中文路径 + 中文值名
		{
			Event e = {};
			e.Sequence = static_cast<LONG>(round * 10 + 1);
			e.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Registry);
			e.Op = static_cast<ULONG>(R3ShieldCore::Op::SetValueKey);
			e.Decision = 1;
			e.RiskLevel = 1;
			e.ProcessId = GetCurrentProcessId();
			e.ThreadId = GetCurrentThreadId();
			e.DesiredAccess = 0x00020006;
			const wchar_t* kp = L"\\REGISTRY\\MACHINE\\SOFTWARE\\测试项\\子键\\Run";
			const wchar_t* vn = L"默认启动项（中文值名）";
			e.KeyPathLength = static_cast<ULONG>(wcslen(kp));
			e.ValueNameLength = static_cast<ULONG>(wcslen(vn));
			wcsncpy_s(e.KeyPath, kp, _TRUNCATE);
			wcsncpy_s(e.ValueName, vn, _TRUNCATE);
			e.TimeStamp = NowFileTime();
			batch.push_back(e);
		}

		// ② 进程创建 —— 空 ValueName / 空 DllPath（长度 0），超长命令行
		{
			Event e = {};
			e.Sequence = static_cast<LONG>(round * 10 + 2);
			e.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Process);
			e.Op = static_cast<ULONG>(R3ShieldCore::ProcessOp::Create);
			e.Decision = 0;
			e.RiskLevel = 0;
			e.ProcessId = GetCurrentProcessId();
			e.ThreadId = GetCurrentThreadId();
			const wchar_t* kp = L"C:\\Windows\\System32\\notepad.exe";
			e.KeyPathLength = static_cast<ULONG>(wcslen(kp));
			wcsncpy_s(e.KeyPath, kp, _TRUNCATE);
			// 命令行故意写成"贴边"长度：513 个字符 → 必须被截到 511 + NUL
			std::wstring cmd = L"notepad.exe /A ";
			while (cmd.size() < 513) {
				cmd.push_back(L'长');
			}
			wcsncpy_s(e.CommandLine, cmd.c_str(), _TRUNCATE);
			e.TargetProcessId = GetCurrentProcessId() + 1;
			e.CreatorProcessId = GetCurrentProcessId();
			e.TimeStamp = NowFileTime();
			batch.push_back(e);
		}

		// ③ 网络 connect —— TargetPort/NetProtocol/LocalPort + LocalAddress
		{
			Event e = {};
			e.Sequence = static_cast<LONG>(round * 10 + 3);
			e.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Network);
			e.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Connect);
			e.Decision = 1;
			e.RiskLevel = 2;
			e.ProcessId = GetCurrentProcessId();
			e.ThreadId = GetCurrentThreadId();
			const wchar_t* kp = L"例子.测试";
			e.KeyPathLength = static_cast<ULONG>(wcslen(kp));
			wcsncpy_s(e.KeyPath, kp, _TRUNCATE);
			e.TargetPort = 4444;
			e.NetProtocol = 6;      // IPPROTO_TCP
			e.LocalPort = 51234;
			wcsncpy_s(e.LocalAddress, L"192.168.1.20", _TRUNCATE);
			e.Flags2 = 0x00000001;
			e.TimeStamp = NowFileTime();
			batch.push_back(e);
		}

		// ④ 全空字段 —— KeyPath / ValueName / DllPath / CommandLine 全为 0 长度
		{
			Event e = {};
			e.Sequence = static_cast<LONG>(round * 10 + 4);
			e.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Thread);
			e.Op = static_cast<ULONG>(R3ShieldCore::ThreadOp::Create);
			e.Decision = 1;
			e.RiskLevel = 3;
			e.ProcessId = GetCurrentProcessId();
			e.ThreadId = GetCurrentThreadId();
			e.TargetProcessId = GetCurrentProcessId();
			e.TimeStamp = NowFileTime();
			batch.push_back(e);
		}

		for (const Event& e : batch) {
			OnEngineEvent(e, nullptr);
		}
	}

	// ---------------------------------------------------------------------
	// 「引擎起来也要带界面」（用户要求）
	// ---------------------------------------------------------------------
	// 语义：**引擎先起来**的场景（用户双击引擎、任务计划、将来由服务拉起）
	//       要顺手把界面叫出来，否则用户看不出防护在跑。
	//
	// ★★ 防环（这是最容易写错的一处）：
	//   界面启动时一定会带 `--parent-pid` 拉起引擎 ⇒ 那种情况下**绝不**
	//   反向拉起界面，否则就是 界面→引擎→界面→… 无限套娃。
	//   所以判据是"本引擎是不是被界面拉起的"，而不是"界面在不在跑"。
	//
	// ★ 会话 0（服务/系统会话）里拉界面没有意义 —— 那里没有可见桌面，
	//   进程会起来但谁也看不到，只会白占内存。所以先看会话号。
	void LaunchUiIfNeeded(bool launchedByGui, const std::filesystem::path& dir)
	{
		if (launchedByGui) {
			return;
		}

		const std::filesystem::path ui = dir / L"R3 ShieldCore.exe";
		if (GetFileAttributesW(ui.c_str()) == INVALID_FILE_ATTRIBUTES) {
			LogLine(L"同目录没有界面程序（%s），跳过自动拉起界面", ui.c_str());
			return;
		}

		DWORD session = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &session) || session == 0) {
			LogLine(L"当前在会话 0（服务/系统会话）—— 那里没有可见桌面，不拉起界面");
			return;
		}

		std::wstring cmd = L"\"" + ui.wstring() + L"\"";
		STARTUPINFOW si = {};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(ui.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0,
				nullptr, dir.c_str(), &si, &pi)) {
			LogLine(L"自动拉起界面失败 err=%lu（引擎继续防护，不影响监控）",
				static_cast<unsigned long>(GetLastError()));
			return;
		}
		LogLine(L"已自动拉起界面（pid=%lu）—— 引擎先起来时要带出界面",
			static_cast<unsigned long>(pi.dwProcessId));
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	void FakeEventLoop()
	{
		uint32_t round = 0;
		while (!g_stop.load(std::memory_order_relaxed)) {
			++round;
			PushFakeEvents(round);
			LogLine(L"[fake] 第 %lu 轮：造了 4 条事件（中文/空字段/超长/网络）",
				static_cast<unsigned long>(round));
			for (int i = 0; i < 20 && !g_stop.load(std::memory_order_relaxed); ++i) {
				Sleep(50);
			}
		}
	}
}

int wmain(int argc, wchar_t** argv)
{
	// ---------------------------------------------------------------------
	// 控制台：**默认没有**（WINDOWS 子系统）
	// ---------------------------------------------------------------------
	// 用户要求原话：「引擎默认不显示控制台」。
	//
	// 为什么不能靠 `CREATE_NO_WINDOW`（v89 的做法，已废弃）：
	//   `CREATE_NO_WINDOW` 只是"不新建控制台窗口"，**不会脱离父控制台** ——
	//   子进程仍然挂在界面那个控制台上。于是界面一退出（或用户关掉那个黑窗），
	//   引擎就收到 `CTRL_CLOSE_EVENT(2)` 被一起带走，
	//   "界面关了引擎继续防护"这条保证当场失效。
	//   （2026-10-23 实测：引擎日志里最后一行就是
	//     `收到控制台退出信号(2)，准备收尾`，而界面日志里根本没有 StopEngine。）
	//
	// 现在的语义：
	//   · 被界面拉起 / 双击     ⇒ 没有控制台，也没有窗口；
	//   · 从 cmd/PowerShell 跑  ⇒ `AttachConsole(父进程)` 成功，能看输出；
	//   · 显式 `--console`      ⇒ 没有父控制台时自己开一个。
	bool wantConsole = false;
	bool launchedByGui = false;
	for (int i = 1; i < argc; ++i) {
		if (wcscmp(argv[i], L"--console") == 0) {
			wantConsole = true;
		}
		else if (wcscmp(argv[i], L"--parent-pid") == 0) {
			launchedByGui = true;
		}
	}
	// ★★ `launchedByGui` 这个判断是**必须**的，别删：
	//   `AttachConsole(ATTACH_PARENT_PROCESS)` 只看"父进程有没有控制台"，
	//   而界面本身是 CONSOLE 子系统 —— 用户双击界面时它有一个黑窗口。
	//   若引擎也去附着，就又把命交给了那个窗口：界面一退出/窗口一关，
	//   引擎照样收到 `CTRL_CLOSE_EVENT(2)` ⇒ 白改。
	//   ⇒ 界面拉起时（一定带 `--parent-pid`）**绝不附着**；
	//     只有"手动从 cmd 里跑"或显式 `--console` 才有控制台。
	//
	// ★ 先看 stdout 本来能不能写（管道/文件/重定向）。
	//   能写就**不要动它** —— 抢过来重绑 CONOUT$ 会让 `engine --version > x.txt`
	//   这种用法输出跑到控制台、文件里空着。
	{
		const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		if (hOut != nullptr && hOut != INVALID_HANDLE_VALUE
			&& GetFileType(hOut) != FILE_TYPE_UNKNOWN) {
			g_stdoutOk = true;
		}
	}

	if (!launchedByGui) {
		if (AttachConsole(ATTACH_PARENT_PROCESS)) {
			g_consoleAttached = true;
		}
		else if (wantConsole && AllocConsole()) {
			g_consoleAttached = true;
		}
	}

	if (!g_stdoutOk && g_consoleAttached) {
		// AttachConsole/AllocConsole 之后 stdout/stderr 还是无效的
		// （CRT 启动时就已经绑好了），必须重新绑到 CONOUT$，否则写不出去。
		FILE* dummy = nullptr;
		freopen_s(&dummy, "CONOUT$", "w", stdout);
		freopen_s(&dummy, "CONOUT$", "w", stderr);
		SetConsoleOutputCP(CP_ACP);
		g_stdoutOk = true;
	}

	const Options opt = ParseOptions(argc, argv);

	if (opt.printVersion) {
		LogLine(L"%s", ipc::kMarker);
		LogLine(L"protocol=%d abi=%lu eventBytes=%zu", ipc::kProtocolVersion,
			static_cast<unsigned long>(R3ShieldCore::AbiVersion),
			sizeof(R3ShieldCore::Event));
		return 0;
	}

	// 日志落盘（同时保留控制台输出）
	//
	// ★ v91：必须用 `_wfsopen(..., _SH_DENYNO)`，**不能用 `_wfopen_s`**。
	//   实测：引擎卡在收尾时（进程还活着、日志句柄没关），`_wfopen_s` 打开的那份
	//   **读不到**（"The process cannot access the file ... used by another
	//   process"）—— 而那正是最需要看日志的时刻：卡住的引擎永远不放句柄，
	//   于是"引擎为什么退不掉"这个问题**永远无法取证**，只能靠猜。
	//   `_SH_DENYNO` = 允许别的进程同时读；代价只是别人也能写这份日志（日志而已）。
	//   ★ 顺手把 `ccs=UTF-8` 保留：文件是宽写（见 `LogLine` 里的 `fputws`），
	//     窄写会 `__fastfail`（铁律 280）。
	if (!opt.logPath.empty()) {
		FILE* f = _wfsopen(opt.logPath.c_str(), L"w, ccs=UTF-8", _SH_DENYNO);
		if (f) {
			g_logFile = f;
		}
	}

	LogLine(L"=== r3shieldcore-engine 启动（pid=%lu）===",
		static_cast<unsigned long>(GetCurrentProcessId()));
	LogLine(L"代次标记：%s", ipc::kMarker);
	LogLine(L"程序目录：%s", opt.configDir.c_str());
	//
	// ★ v91：这里**必须**印 `ResolveConfigPath` 的结果，不能只印 `opt.configDir`。
	//
	//   为什么：`Load` 内部走 `ResolveConfigPath`，它**优先**
	//   `%ProgramData%\R3 Shield Core\r3shieldcore.ini`。只印程序目录的话，
	//   用户看到 `D:\...\dist\R3ShieldCore-x64` 就以为"我该改 dist 那份"，
	//   改完重启发现毫无变化 —— 这正是铁律 290 的另一面：
	//   打印的路径 ≠ 真正读的文件 ⇒ 诊断口径本身就是错的。
	//
	//   注意用 `%ls` 会踩铁律 252（locale 下非 ASCII 整行静默截断），
	//   这里走 `LogLine`（宽格式 + 宽写），所以 `%s` 拿宽串是安全的。
	try {
		const std::filesystem::path actual =
			R3ShieldCoreConfig::ResolveConfigPath(opt.configDir);
		LogLine(L"配置文件：%s", actual.c_str());
	}
	catch (const std::exception& e) {
		LogLine(L"配置文件：解析失败（%hs）", e.what());
	}
	if (opt.parentPid) {
		LogLine(L"由界面拉起（parent pid=%lu）—— 引擎**不跟随**它退出",
			static_cast<unsigned long>(opt.parentPid));
	}

	// ---------------------------------------------------------------------
	// ★★★ v100：机器级引擎熔断（**必须排在所有副作用之前**）
	// ---------------------------------------------------------------------
	//
	// 为什么引擎自己也要拦一次：
	//   界面侧已经拦了，但引擎是**独立 exe** —— 可以直接双击、可以被别的
	//   脚本/服务/自启动项拉起。只拦界面等于只堵了一个入口。
	//
	// 事故背景（2026-10-23）：引擎会全局注入，并**弹置顶询问窗**，
	//   误跑一次就会让编辑器无法输入（焦点被抢）、编译器卡死。
	//
	// 放行：删 `%ProgramData%\R3 Shield Core\NO_ENGINE`，或设
	//   `R3SHIELDCORE_ALLOW_ENGINE=1`（仅限确实要做注入验证时）。
	{
		wchar_t allow[8] = {};
		const bool envAllowed =
			GetEnvironmentVariableW(L"R3SHIELDCORE_ALLOW_ENGINE", allow,
				_countof(allow)) > 0 && allow[0] == L'1';

		if (!envAllowed) {
			wchar_t programData[MAX_PATH * 2] = {};
			const DWORD n = GetEnvironmentVariableW(L"ProgramData", programData,
				_countof(programData));
			if (n > 0 && n < _countof(programData)) {
				std::wstring flag = programData;
				if (!flag.empty() && flag.back() != L'\\') {
					flag += L'\\';
				}
				flag += L"R3 Shield Core\\NO_ENGINE";

				const DWORD attr = GetFileAttributesW(flag.c_str());
				if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
					// ★ 用 [guard] 前缀而不是 [!!]：这不是"出错"，是**按要求拒绝**。
					LogLine(L"[guard] 本机引擎熔断已生效 —— 拒绝启动：%s 存在", flag.c_str());
					LogLine(L"[guard] 为什么：引擎会全局注入（白名单外的一切，含 cl.exe 等构建工具），"
						L"且 ask 模式下会弹**置顶询问窗**抢前台焦点"
						L" ⇒ 编辑器无法输入、编译器每次等 30 秒超时。");
					LogLine(L"[guard] 确需在本机做注入验证：删掉上面那个文件，"
						L"或设 R3SHIELDCORE_ALLOW_ENGINE=1 后重试。");
					return 9;
				}
			}
		}
	}

	// ---------------------------------------------------------------------
	// 单实例
	// ---------------------------------------------------------------------
	// ★ 为什么必须有：界面可能被点两次，第二次拉起的引擎会**再建一套会话**，
	//   两个引擎同时注入同一批进程 ⇒ 目标里有两份 DLL、两份 hook，
	//   症状是"每条事件都出现两次"且两边统计各算一半。
	//   所以第二个实例直接退出，让界面去连第一个。
	const std::wstring mutexName = ipc::EngineMutexName();
	HANDLE instanceMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
	if (!instanceMutex) {
		LogLine(L"CreateMutex 失败 err=%lu", static_cast<unsigned long>(GetLastError()));
		return 2;
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		LogLine(L"已经有一个引擎在跑（互斥体 %s 已存在），本实例退出。",
			mutexName.c_str());
		CloseHandle(instanceMutex);
		return 0;
	}

	// ★ v90：没有控制台时注册 Ctrl 处理器没有意义（也不会有 CTRL_CLOSE 打进来）。
	//   有控制台（手动从 cmd 跑）时才有意义：用户 Ctrl+C / 关窗口 ⇒ 有序收尾。
	if (g_consoleAttached) {
		SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
		LogLine(L"控制台已附加（手动运行模式）—— 关掉这个窗口会停掉引擎");
	}
	else {
		LogLine(L"无控制台（正常：被界面拉起或双击）—— 关掉界面**不会**停掉本引擎");
	}

	// ---------------------------------------------------------------------
	// 主密钥：**引擎侧生成**，客户端只读
	// ---------------------------------------------------------------------
	// ★★ 必须在这里就把密钥文件建出来，**不能**等到 `Handshake` 里：
	//    客户端要在发 HELLO **之前**读这把密钥（它没法等一个还不存在的
	//    文件），而握手要等 HELLO 才发生 —— 顺序上死锁。
	//    首次部署的症状很有迷惑性：引擎正常起来了、管道也建好了，界面却
	//    永远连不上，日志里只有一句「主密钥不存在（err=2）」。
	//    （2026-10-23 实测踩到。）
	// ★ 两侧的 createIfMissing 必须**一真一假**：引擎 true（唯一生成者）、
	//   客户端 false。两边都 true 会互相覆盖（后起的赢），症状是"偶尔能连、
	//   偶尔不能"，几乎无法复现。
	{
		BYTE master[ipc::kKeyBytes] = {};
		std::wstring keyErr;
		if (!ipc::EnsureMasterKey(master, true, &keyErr)) {
			LogLine(L"主密钥准备失败：%s —— 拒绝以「无密钥通道」启动", keyErr.c_str());
			ReleaseMutex(instanceMutex);
			CloseHandle(instanceMutex);
			return 5;
		}
		SecureZeroMemory(master, sizeof(master));
		LogLine(L"主密钥就绪（DPAPI·LOCAL_MACHINE）：%s", ipc::MasterKeyPath().c_str());
	}

	// ---------------------------------------------------------------------
	// 读配置 + 起会话
	// ---------------------------------------------------------------------
	R3ShieldCore::Policy policy;
	try {
		R3ShieldCoreConfig::Load(policy, opt.configDir);
	}
	catch (const std::exception& e) {
		LogLine(L"读配置失败：%hs", e.what());
		return 3;
	}
	g_currentMode.store(policy.Mode, std::memory_order_relaxed);
	LogLine(L"配置已加载：mode=%lu 日志=%s", static_cast<unsigned long>(policy.Mode),
		policy.LogPath);

	// ★ 这里构造 EngineControl 就是"起引擎"：LoadLibrary + GlobalHookSessionStart。
	//   建出来的共享内存/会话互斥体**与进程身份无关**，被注入的进程照旧找得到。
	//
	//   `--dry-run` 下**不构造** —— 它只跑传输层（管道/握手/AES-GCM/编解码），
	//   一个 hook 都不装。这不是"简化版引擎"，是**故意只剩管道**的引擎：
	//   本机禁止真跑引擎（全局注入会 hook 编辑器），但协议必须能真验。
	std::unique_ptr<EngineControl> engine;
	if (opt.dryRun) {
		LogLine(L"=== dry-run：不 LoadLibrary、不建会话、不注入，只跑加密 IPC ===");
	}
	else {
		try {
			engine = std::make_unique<EngineControl>(policy);
		}
		catch (const std::exception& e) {
			LogLine(L"引擎会话启动失败：%hs", e.what());
			LogLine(L"常见原因：32|64\\r3shieldcore-lib.dll 缺失，或共享通道建不起来。");
			return 4;
		}
		engine->SetEventObserver(&OnEngineEvent, nullptr);
		LogLine(L"引擎会话已建立（DLL 基址=%p，内部退出=%s）",
			reinterpret_cast<void*>(engine->LocalEngineDllBase()),
			engine->SupportsSelfExit() ? L"可用" : L"不可用（DLL 缺导出）");
	}

	// ---------------------------------------------------------------------
	// 注入扫描线程
	// ---------------------------------------------------------------------
	// 间隔来自 ini（`inject_interval_ms`，默认 10ms）。和原来 app.cpp 里
	// 那个线程完全一致 —— 只是现在跑在引擎进程里。
	std::thread injector;
	std::thread drainer;
	std::thread faker;

	if (engine) {
		ULONG injectionIntervalMs = 10;
		try {
			injectionIntervalMs = R3ShieldCoreConfig::LoadEngineSettings(opt.configDir)
				.InjectionIntervalMs;
		}
		catch (...) {
			// 读不到就用默认值 —— 注入间隔不该是"起不来"的理由
		}
		if (injectionIntervalMs == 0) {
			injectionIntervalMs = 10;
		}
		LogLine(L"注入扫描间隔：%lu ms", static_cast<unsigned long>(injectionIntervalMs));
		injector = std::thread([&]() {
			SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
			while (!g_stop.load(std::memory_order_relaxed)) {
				int injected = 0;
				try {
					injected = engine->HandleNewProcesses();
				}
				catch (...) {
					injected = 0;
				}
				if (injected > 0) {
					g_injectedTotal.fetch_add(static_cast<uint32_t>(injected),
						std::memory_order_relaxed);
				}
				Sleep(injectionIntervalMs);
			}
		});

		// -----------------------------------------------------------------
		// 事件排空线程
		// -----------------------------------------------------------------
		// ★ 必须高频（100ms）：全开模式下后台进程的正常噪音会在 1 秒内把
		//   环形缓冲套圈。原来在主循环里做，现在单独一个线程，节奏不变。
		drainer = std::thread([&]() {
			while (!g_stop.load(std::memory_order_relaxed)) {
				try {
					engine->DrainEvents();
				}
				catch (...) {
					// 排空失败不该把线程带走
				}
				Sleep(100);
			}
		});
	}

	// 假事件：只和 `--dry-run` 搭配。真引擎跑起来时用真事件，掺假的只会
	// 让日志变成一堆查不到的路径。
	if (opt.fakeEvents) {
		if (!opt.dryRun) {
			LogLine(L"--fake-events 只在 --dry-run 下生效，已忽略（真引擎不掺假事件）");
		}
		else {
			LogLine(L"--fake-events：每秒造 4 条假事件，验事件编解码往返");
			faker = std::thread(FakeEventLoop);
		}
	}

	// ---------------------------------------------------------------------
	// IPC 服务（主线程）
	// ---------------------------------------------------------------------
	// ★ 先做"引擎起来要带出界面"这件事 —— 但它挪到 AcceptLoop 里了
	//   （必须在管道建好之后，见那里的注释）。这里只留一句说明，别把调用加回来。

	SECURITY_ATTRIBUTES sa = {};
	PSECURITY_DESCRIPTOR sd = nullptr;
	if (!ipc::BuildPipeSecurity(sa, sd)) {
		LogLine(L"构造管道安全属性失败 —— 拒绝以「无保护管道」启动");
		g_stop.store(true);
	}
	else {
		AcceptLoop(engine.get(), sd, launchedByGui, opt.configDir);
	}

	// ---------------------------------------------------------------------
	// 收尾
	// ---------------------------------------------------------------------
	//
	// ★★ v91：收尾**每一步都要留日志**，而且必须有**硬上限**。
	//
	//   事故（2026-10-23 21:07）：用户点「退出引擎」→ 界面 3 秒后放弃并退出，
	//   引擎却**一直活着**（pid 1808 在 5 分钟后仍在，CPU 只涨 0.08s/3s = 死等）。
	//   后果不是"引擎没关"这么简单：
	//     · 单实例互斥体 + 唯一管道都被这个僵尸占着 ⇒ 下次开界面**连不上**；
	//     · 连不上 ⇒ 点「切换模式」只往日志里写一行（界面是 WINDOWS 子系统，
	//       没有控制台），用户看到的就是**"点了完全没反应、徽章不变"**；
	//     · ARK 同理（"ark 用不了"）。
	//   ⇒ 一个"退不掉的引擎"会把下一次启动的所有功能一起拖垮。
	//
	//   所以这里做两件事：
	//     ① 每步 `LogLine` 一个阶段号 —— 下次卡住，日志最后一行直接指出卡在哪；
	//     ② 起一个看门狗：收尾开始 N 秒还没退完就**强制退出**，宁可留一个已反注入
	//        的残留也不留一个占着管道的僵尸。
	LogLine(L"正在收尾……");
	g_stop.store(true);

	// ★ 看门狗：独立线程，不参与任何 join。
	//   用 `TerminateProcess(自己)` 而不是 `exit()`：此时可能有别的线程正卡在
	//   内核里（反注入/等待目标进程），`exit()` 会去跑它们的析构，反而可能再卡住。
	//   `kShutdownDeadlineMs` 给 20 秒 —— 反注入要恢复被挂起的进程，正常几秒内完成。
	constexpr DWORD kShutdownDeadlineMs = 20000;
	std::thread watchdog([&]() {
		const ULONGLONG start = GetTickCount64();
		while (GetTickCount64() - start < kShutdownDeadlineMs) {
			Sleep(100);
		}
		// 走到这里说明主线程 20 秒还没退完 —— 记一行再自我了断。
		LogLine(L"[!!] 收尾超过 %lu ms 仍未完成（卡在最后打印的那个阶段）—— 强制退出，"
			L"以免占用单实例互斥体与管道把下一次启动拖死",
			static_cast<unsigned long>(kShutdownDeadlineMs));
		if (g_logFile) {
			fflush(g_logFile);
		}
		TerminateProcess(GetCurrentProcess(), 3);
	});
	watchdog.detach();

	LogLine(L"收尾 1/6：停假事件线程");
	// ★★★ v91：**有界 join** —— 这是本次事故的正面修法。
	//
	//   实测（2026-10-23 21:07，pid 1808）：日志停在「正在收尾……」之后再无输出，
	//   进程活着 12 分钟、CPU 只涨 0.08s/3s（= 死等）。位置就是这三个 `join()`
	//   之一 —— 注入线程卡在 `GlobalHookSessionHandleNewProcesses` 里（它要挂起目标
	//   进程、写内存、恢复线程），一旦某个目标进程状态不对，它就再也回不来，
	//   而 `std::thread::join()` **没有超时**。
	//
	//   为什么不能只靠下面的看门狗：看门狗是 `TerminateProcess`，会把「反注入」
	//   一起掐掉（被注入进程里留悬空 hook，正是铁律 175 那类事故）。
	//   所以先**放弃等待**那个卡住的线程（detach），让主线程继续往下走完
	//   反注入 → 释放互斥体；卡住的线程随进程退出一起消失。
	//   看门狗只作为最后兜底（万一反注入本身也卡）。
	auto joinWithTimeout = [](std::thread& t, DWORD timeoutMs, PCWSTR stage) {
		if (!t.joinable()) {
			return;
		}
		const HANDLE h = static_cast<HANDLE>(t.native_handle());
		if (WaitForSingleObject(h, timeoutMs) == WAIT_OBJECT_0) {
			t.join();
			return;
		}
		LogLine(L"[!!] 收尾：%s 线程 %lu ms 内没停下来 —— 放弃等待（detach）继续收尾，"
			L"否则引擎会永远占着单实例互斥体与管道",
			stage, static_cast<unsigned long>(timeoutMs));
		t.detach();
	};

	joinWithTimeout(faker, 3000, L"假事件");
	LogLine(L"收尾 2/6：停注入线程");
	joinWithTimeout(injector, 5000, L"注入");
	LogLine(L"收尾 3/6：停事件排空线程");
	joinWithTimeout(drainer, 5000, L"事件排空");

	// ★ 顺序：先停会话（= 反注入、销毁共享内存），再释放互斥体。
	//   反注入必须在被注入的进程还在的时候做 —— 晚了目标就找不到了。
	LogLine(L"收尾 4/6：反注入 + 销毁共享会话（可能较慢：要恢复被挂起的进程）");
	engine.reset();
	LogLine(L"收尾 5/6：反注入完成");

	if (sd) {
		LocalFree(sd);
	}
	if (instanceMutex) {
		ReleaseMutex(instanceMutex);
		CloseHandle(instanceMutex);
	}

	LogLine(L"收尾 6/6：释放互斥体完成");
	LogLine(L"=== r3shieldcore-engine 已退出 ===");
	if (g_logFile) {
		fclose(g_logFile);
		g_logFile = nullptr;
	}
	return 0;
}
