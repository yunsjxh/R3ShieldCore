#include "stdafx.h"
#include "engine_client.h"

#include <r3shieldcore/engine_ipc.h>

#include <cstdio>

namespace ipc = R3ShieldCoreEngineIpc;
using R3ShieldCore::Event;

namespace
{
	// 中文原因 → 日志/界面都能用。
	void SetErr(std::wstring& slot, const wchar_t* fmt, ...)
	{
		wchar_t buf[512];
		va_list args;
		va_start(args, fmt);
		_vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
		va_end(args);
		slot = buf;
	}

	// ★ 引擎 exe 的名字。**必须**和 build.sh 里 `-OUT:` 的那一行一致 ——
	//   写错了不会有编译错，只会是"界面起来后一直连不上引擎"，
	//   而日志里只有一句"CreateProcess 失败 err=2（找不到文件）"。
	constexpr wchar_t kEngineExeName[] = L"r3shieldcore-engine.exe";
}

namespace R3ShieldCoreEngine
{
	Client::~Client()
	{
		Stop(false);
	}

	void Client::Stop(bool stopEngine)
	{
		if (!running_.load(std::memory_order_relaxed)) {
			// 即使没起读线程，也要把句柄收掉
			if (pipe_ != INVALID_HANDLE_VALUE) {
				CloseHandle(pipe_);
				pipe_ = INVALID_HANDLE_VALUE;
			}
			connected_.store(false);
			return;
		}

		if (stopEngine) {
			// 「退出引擎」：发一条请求，引擎回 Ok 之后自己收尾。
			//
			// ★ v90：发完要**核对它到底退没退**，并把结论写进 `stopReport_`。
			//   v89 只打"已请求退出"，于是"点了没反应"和"点了但引擎还在"
			//   在日志里长得一模一样（铁律 97）。
			const uint32_t pid = enginePid_.load(std::memory_order_relaxed);
			std::vector<BYTE> reply;
			bool sent = false;
			if (connected_.load(std::memory_order_relaxed)) {
				sent = Request(ipc::Msg::StopEngine, nullptr, 0, reply, 2000);
			}
			if (!sent) {
				stopReport_ = L"请求没发出去（引擎已断开或管道异常）";
				if (!lastError_.empty()) {
					stopReport_ += L"：";
					stopReport_ += lastError_;
				}
			}
			else {
				// 等它真的退出。反注入要逐个恢复被挂起的进程，给它 3 秒；
				// 超时也不算失败 —— 但要**说清楚**是"还在收尾"，不是"没反应"。
				bool exited = false;
				if (pid != 0) {
					HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
						FALSE, pid);
					if (h) {
						exited = WaitForSingleObject(h, 3000) == WAIT_OBJECT_0;
						CloseHandle(h);
					}
					else {
						// 打不开进程 ⇒ 它已经不在了（也可能是权限，但我们同级提权）
						exited = true;
					}
				}
				if (exited) {
					wchar_t buf[128];
					_snwprintf_s(buf, _countof(buf), _TRUNCATE, L"引擎已退出（pid=%lu）",
						static_cast<unsigned long>(pid));
					stopReport_ = buf;
				}
				else {
					stopReport_ = L"已请求退出，引擎仍在收尾（反注入要恢复被挂起的进程）";
				}
			}
		}

		running_.store(false, std::memory_order_relaxed);
		connected_.store(false, std::memory_order_relaxed);

		// 打断阻塞中的 ReadFile
		if (pipe_ != INVALID_HANDLE_VALUE) {
			CancelIoEx(pipe_, nullptr);
		}
		{
			// 让可能还在等的请求立刻返回
			std::lock_guard<std::mutex> lock(replyMutex_);
			replyReady_ = false;
			replyCv_.notify_all();
		}

		if (readerThread_.joinable()) {
			readerThread_.join();
		}
		if (pipe_ != INVALID_HANDLE_VALUE) {
			DisconnectNamedPipe(pipe_);
			CloseHandle(pipe_);
			pipe_ = INVALID_HANDLE_VALUE;
		}
	}

	R3ShieldCoreEngineIpc::StatsPayload Client::LatestStats() const
	{
		std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(statsMutex_));
		return stats_;
	}

	bool Client::ConnectOnly(int timeoutMs)
	{
		const std::wstring name = ipc::PipeName();
		const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);

		while (GetTickCount64() < deadline) {
			// WaitNamedPipeW 在"管道存在但没有空闲实例"时也会等 —— 正是我们要的。
			if (WaitNamedPipeW(name.c_str(), 200)) {
				HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE,
					0, nullptr, OPEN_EXISTING, 0, nullptr);
				if (h != INVALID_HANDLE_VALUE) {
					pipe_ = h;
					return true;
				}
				// 常见：ERROR_PIPE_BUSY（实例被占）/ ERROR_ACCESS_DENIED（ACL）。
				// 后者**不该**被当成"引擎没跑"，否则会去重复拉起引擎。
				if (GetLastError() == ERROR_ACCESS_DENIED) {
					SetErr(lastError_,
						L"连上了管道但被拒绝访问（ERROR_ACCESS_DENIED）—— "
						L"界面和引擎的权限级别不一致？");
					return false;
				}
			}
			Sleep(100);
		}
		return false;
	}

	bool Client::LaunchEngine(const std::filesystem::path& exeDirectory)
	{
		const std::filesystem::path exePath = exeDirectory / kEngineExeName;
		if (GetFileAttributesW(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
			SetErr(lastError_, L"找不到引擎程序：%s", exePath.c_str());
			return false;
		}

		wchar_t cmd[2048];
		_snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
			L"\"%s\" --config-dir \"%s\" --parent-pid %lu",
			exePath.c_str(), exeDirectory.c_str(),
			static_cast<unsigned long>(GetCurrentProcessId()));

		STARTUPINFOW si = {};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi = {};

		// ★★ v90：`DETACHED_PROCESS`（**不是** `CREATE_NO_WINDOW`）。
		//
		//   `CREATE_NO_WINDOW` 只保证"不新建控制台窗口"，**不会脱离父控制台**：
		//   引擎仍然挂在界面进程的控制台上，界面一退出（控制台关闭），
		//   引擎就收到 `CTRL_CLOSE_EVENT(2)` 被一起带走 ⇒
		//   "界面关了引擎继续防护"这条核心保证是假的。
		//   （2026-10-23 实测：引擎日志最后一行 `收到控制台退出信号(2)`，
		//     而界面日志里压根没有 StopEngine —— 说明它不是被"退出引擎"停的。）
		//
		//   `DETACHED_PROCESS` 让子进程**完全不附着任何控制台**：
		//   父控制台关掉与它无关，也不会弹出黑窗口。
		//   （引擎本身也已经是 WINDOWS 子系统，这里再加一道，防止将来有人
		//     把引擎改回 CONSOLE 子系统时这个洞又回来。）
		const BOOL ok = CreateProcessW(exePath.c_str(), cmd, nullptr, nullptr, FALSE,
			DETACHED_PROCESS, nullptr, exeDirectory.c_str(), &si, &pi);
		if (!ok) {
			SetErr(lastError_, L"拉起引擎失败 err=%lu（%s）",
				static_cast<unsigned long>(GetLastError()), exePath.c_str());
			return false;
		}

		enginePid_.store(pi.dwProcessId, std::memory_order_relaxed);
		CloseHandle(pi.hThread);
		// 不等待、不持有进程句柄：引擎的生命周期**不绑定**界面
		// （界面关掉它还活着 —— 这是分进程的核心收益）。
		CloseHandle(pi.hProcess);
		return true;
	}

	bool Client::DoHandshake()
	{
		BYTE clientNonce[32] = {};
		if (!NT_SUCCESS(BCryptGenRandom(nullptr, clientNonce, sizeof(clientNonce),
			BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
			lastError_ = L"生成随机数失败";
			return false;
		}

		if (!ipc::WriteLine(pipe_, ipc::MakeHello(clientNonce))) {
			lastError_ = L"发送 HELLO 失败";
			return false;
		}

		std::string line;
		if (!ipc::ReadLine(pipe_, line, ipc::kMaxHandshakeBytes)) {
			lastError_ = L"等不到引擎的 WELCOME";
			return false;
		}
		if (line.rfind("ERR|", 0) == 0) {
			// 引擎把原因写在后面（UTF-8）
			const std::string utf8 = line.substr(4);
			wchar_t wbuf[512] = {};
			MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wbuf, _countof(wbuf) - 1);
			SetErr(lastError_, L"引擎拒绝连接：%s", wbuf);
			return false;
		}

		ipc::WelcomeInfo wi;
		if (!ipc::ParseWelcome(line, wi)) {
			lastError_ = L"WELCOME 文法不对";
			return false;
		}
		std::wstring bad = ipc::CheckPeerCompatible(wi.protocolVersion, wi.abiVersion,
			wi.eventBytes);
		if (!bad.empty()) {
			lastError_ = bad;
			return false;
		}

		BYTE master[ipc::kKeyBytes] = {};
		std::wstring keyErr;
		// ★ createIfMissing = **false**：密钥只能由引擎生成。
		//   界面也允许生成的话，两边在"文件还不存在"的瞬间会各生成一份，
		//   后写的覆盖先写的 ⇒ 先连上的那个再也解不开（表现为"随机连不上"）。
		if (!ipc::EnsureMasterKey(master, false, &keyErr)) {
			SetErr(lastError_, L"读不到引擎主密钥：%s（引擎是否已启动过？）", keyErr.c_str());
			return false;
		}

		BYTE sessionKey[ipc::kKeyBytes] = {};
		const bool derived = ipc::DeriveSessionKey(master, clientNonce, wi.nonce, sessionKey);
		SecureZeroMemory(master, sizeof(master));
		if (!derived) {
			lastError_ = L"派生会话密钥失败";
			return false;
		}
		const bool ready = aead_.Init(sessionKey);
		SecureZeroMemory(sessionKey, sizeof(sessionKey));
		if (!ready) {
			lastError_ = L"AES-256-GCM 初始化失败";
			return false;
		}

		enginePid_.store(wi.enginePid, std::memory_order_relaxed);
		return true;
	}

	bool Client::Start(const std::filesystem::path& exeDirectory, EventSink sink, void* context)
	{
		sink_ = sink;
		sinkContext_ = context;
		lastError_.clear();

		// 1) 先试着连已有引擎（界面重启时引擎通常还在跑）
		if (!ConnectOnly(300) || !DoHandshake()) {
			if (pipe_ != INVALID_HANDLE_VALUE) {
				CloseHandle(pipe_);
				pipe_ = INVALID_HANDLE_VALUE;
			}
			aead_.Reset();

			// 2) 连不上 ⇒ 拉起一个，再等它把管道建好
			if (!LaunchEngine(exeDirectory)) {
				return false;
			}
			// 引擎要读 ini、LoadLibrary、建共享内存 —— 给 12 秒
			if (!ConnectOnly(12000)) {
				// ★ v90：**别覆盖**已经拿到的具体原因。
				//   `ConnectOnly` 在 `ERROR_ACCESS_DENIED` 时会写一句
				//   "界面和引擎的权限级别不一致？" —— 那是最常见的真因
				//   （管道 DACL 只授 SYSTEM+Administrators）。
				//   以前这里无条件改写 lastError_，于是"权限不一致"被糊成
				//   "管道一直没出现"，排查方向直接跑偏（铁律 97）。
				if (lastError_.empty()) {
					SetErr(lastError_, L"引擎已拉起但 %s 一直没出现（pid=%lu）",
						ipc::PipeName().c_str(),
						static_cast<unsigned long>(enginePid_.load()));
				}
				return false;
			}
			if (!DoHandshake()) {
				CloseHandle(pipe_);
				pipe_ = INVALID_HANDLE_VALUE;
				aead_.Reset();
				return false;
			}
		}

		running_.store(true, std::memory_order_relaxed);
		connected_.store(true, std::memory_order_relaxed);
		readerThread_ = std::thread(&Client::ReaderLoop, this);
		return true;
	}

	void Client::ReaderLoop()
	{
		ipc::Msg type = ipc::Msg::Ping;
		std::vector<BYTE> payload;

		while (running_.load(std::memory_order_relaxed)) {
			if (!reader_.Read(pipe_, aead_, type, payload)) {
				break;
			}

			switch (type) {
			case ipc::Msg::Events: {
				std::vector<Event> events;
				if (ipc::DecodeEvents(payload.data(), payload.size(), events) && sink_) {
					for (const Event& e : events) {
						sink_(e, sinkContext_);
					}
				}
				break;
			}

			case ipc::Msg::Stats: {
				if (payload.size() >= sizeof(ipc::StatsPayload)) {
					ipc::StatsPayload s;
					memcpy(&s, payload.data(), sizeof(s));
					std::lock_guard<std::mutex> lock(statsMutex_);
					stats_ = s;
				}
				break;
			}

			case ipc::Msg::Pong:
			case ipc::Msg::Ok:
			case ipc::Msg::Err: {
				std::lock_guard<std::mutex> lock(replyMutex_);
				replyBuf_ = payload;
				replyReady_ = true;
				replyCv_.notify_all();
				break;
			}

			default:
				// 未知类型：忽略但不静默 —— 打一次就够（刷屏没意义）
				{
					static int s_unknown = 0;
					if (s_unknown < 5) {
						++s_unknown;
						printf("[engine] 收到未知消息类型 %u（已忽略）\n",
							static_cast<unsigned>(type));
					}
				}
				break;
			}
		}

		connected_.store(false, std::memory_order_relaxed);
		// 读线程退出时把等待中的请求唤醒（否则它会一直等到超时）
		std::lock_guard<std::mutex> lock(replyMutex_);
		replyReady_ = false;
		replyCv_.notify_all();
	}

	bool Client::Request(ipc::Msg type, const void* payload, size_t len,
		std::vector<BYTE>& reply, int timeoutMs)
	{
		std::lock_guard<std::mutex> serialize(requestMutex_);
		reply.clear();

		if (!connected_.load(std::memory_order_relaxed) || pipe_ == INVALID_HANDLE_VALUE) {
			lastError_ = L"引擎未连接";
			return false;
		}

		{
			std::lock_guard<std::mutex> lock(replyMutex_);
			replyReady_ = false;
		}

		{
			std::lock_guard<std::mutex> lock(writeMutex_);
			if (!writer_.Write(pipe_, aead_, type, payload, len)) {
				lastError_ = L"写引擎管道失败";
				return false;
			}
		}

		std::unique_lock<std::mutex> lock(replyMutex_);
		if (!replyCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
			[this] { return replyReady_; })) {
			SetErr(lastError_, L"引擎 %d ms 内没有应答", timeoutMs);
			return false;
		}
		reply = replyBuf_;
		replyReady_ = false;
		return true;
	}

	bool Client::SetMode(R3ShieldCore::Mode mode, bool* engineReplied)
	{
		if (engineReplied) {
			*engineReplied = false;
		}
		const uint32_t raw = static_cast<uint32_t>(mode);
		std::vector<BYTE> reply;
		if (!Request(ipc::Msg::SetMode, &raw, sizeof(raw), reply, 3000)) {
			return false;
		}
		if (reply.empty()) {
			return false;
		}
		// 引擎确实回了一条 Ok ⇒ 之后不管内容是 0 还是 1，都属于"引擎的答复"。
		if (engineReplied) {
			*engineReplied = true;
		}
		return reply[0] != 0;
	}

	bool Client::CheckHighRiskProcess(const std::wstring& imagePath,
		const std::wstring& systemRoot, std::wstring& reason, bool* reachable)
	{
		reason.clear();
		if (reachable) {
			*reachable = false;
		}

		// 载荷：u32 pathChars + WCHAR[] + u32 rootChars + WCHAR[]
		const uint32_t pathChars = static_cast<uint32_t>(imagePath.size());
		const uint32_t rootChars = static_cast<uint32_t>(systemRoot.size());
		std::vector<BYTE> payload;
		payload.resize(4 + pathChars * sizeof(WCHAR) + 4 + rootChars * sizeof(WCHAR));
		BYTE* p = payload.data();
		memcpy(p, &pathChars, 4);
		p += 4;
		memcpy(p, imagePath.data(), pathChars * sizeof(WCHAR));
		p += pathChars * sizeof(WCHAR);
		memcpy(p, &rootChars, 4);
		p += 4;
		memcpy(p, systemRoot.data(), rootChars * sizeof(WCHAR));

		// ★★ v101：超时 3000ms → **400ms**。
		//
		//   这是一次"问一句这个映像可不可疑"的查询，引擎侧是纯内存判据，
		//   正常是**亚毫秒**级。原来的 3000ms 意味着：引擎一旦不答，
		//   全机 288 个进程 × 3s = 14 分钟，而调用点当时在主线程上。
		//   400ms 已经比正常往返宽了两个数量级，超了就是真出问题了 ——
		//   此时由调用方熔断（见 `ProcWatchCheckThunk`），不是硬等。
		std::vector<BYTE> reply;
		if (!Request(ipc::Msg::RiskCheck, payload.data(), payload.size(), reply, 400)) {
			return false;
		}
		if (reachable) {
			*reachable = true;   // 引擎确实答了 —— 之后无论命中与否都是"有答复"
		}
		if (reply.empty() || reply[0] == 0) {
			return false;   // 没命中（或引擎侧没有这个导出）
		}
		if (reply.size() >= 5) {
			uint32_t n = 0;
			memcpy(&n, reply.data() + 1, 4);
			if (n > 0 && reply.size() >= 5u + n) {
				wchar_t wbuf[512] = {};
				MultiByteToWideChar(CP_UTF8, 0,
					reinterpret_cast<const char*>(reply.data() + 5),
					static_cast<int>(n), wbuf, _countof(wbuf) - 1);
				reason = wbuf;
			}
		}
		return true;
	}

	bool Client::SelfExit(uint32_t pid, SelfExitResult& out)
	{
		out = {};
		std::vector<BYTE> reply;
		if (!Request(ipc::Msg::SelfExit, &pid, sizeof(pid), reply, 6000)) {
			return false;
		}
		if (reply.size() < 12) {
			return false;
		}
		out.code = reply[0];
		out.dllPresent = reply[1] != 0;
		out.dllSameBuild = reply[2] != 0;
		memcpy(&out.win32Error, reply.data() + 4, 4);
		memcpy(&out.elapsedMs, reply.data() + 8, 4);
		return true;
	}
}
