#include "stdafx.h"
#include "r3shieldcore_cfgipc.h"

// ★ v81：配置工具 ⇄ 引擎 的管道服务端。协议 / 转义 / 管道名全在共享头里
//   （铁律 127）—— 本文件只做"把请求翻成动作、把结果写回管道"。
#include <r3shieldcore/cfg_ipc.h>
#include <r3shieldcore/text_conv.h>

#include "engine_control.h"
#include "r3shieldcore_gui.h"
#include "r3shieldcore_stats.h"

#include <atomic>
#include <cstdio>
#include <vector>

namespace
{
	namespace Ipc = R3ShieldCoreCfgIpc;
	namespace Text = R3ShieldCoreText;

	HANDLE g_thread = nullptr;                  // 服务线程
	HANDLE g_pipe = INVALID_HANDLE_VALUE;       // 当前管道实例
	std::atomic<bool> g_stop{false};

	R3ShieldCoreCfgIpcServer::Options g_options;

	// 诊断计数（服务线程写、主循环读；用 Interlocked，不加锁）。
	volatile LONG g_accepted = 0;
	volatile LONG g_logRequests = 0;
	volatile LONG g_configRequests = 0;
	volatile LONG g_syncRequests = 0;
	volatile LONG g_errors = 0;
	volatile LONG g_malformed = 0;
	volatile LONG g_clientConnected = 0;

	// ------------------------------------------------------------------
	// SYNC：服务线程挂请求 -> 主循环处理 -> 服务线程取结论
	// ------------------------------------------------------------------
	//
	//   为什么不能由服务线程直接做（`SetMode` 是"改共享内存 + 必要时建询问通道"）：
	//     那是主循环线程的活。服务线程越界去做，就会和主循环里正在跑的
	//     `TakePendingMode` / `ApplyMode` 抢同一块共享内存。
	//
	//   两边用一把临界区 + 一个手动重置事件交接：
	//     · 服务线程：清结果 -> 置 pending -> 等事件（上限 5 秒）
	//     · 主循环：`PollSync` 看到 pending -> 干活 -> 填结果 -> 置事件
	//
	//   ⚠️ 超时（主循环正在收尾 / 卡在别处）时服务线程回 `ERR`，**不挂死** ——
	//      配置工具那边会把它显示成"引擎忙"，而不是"没反应"。
	std::atomic<bool> g_syncPending{false};
	HANDLE g_syncDone = nullptr;                // 手动重置
	CRITICAL_SECTION g_syncLock;
	bool g_syncLockReady = false;
	bool g_syncHasResult = false;
	std::string g_syncApplied;                  // UTF-8
	std::string g_syncRestart;                  // UTF-8
	std::string g_syncDetail;                   // UTF-8
	std::string g_syncModeText;                 // UTF-8

	// 引擎**启动时读到的那份** ini 的内容摘要。用来回答
	// "用户现在改的这份，引擎用上了吗"。
	ULONGLONG g_iniDigestAtStart = 0;

	void PublishSyncResult(const char* applied, const char* restart,
		const char* detail, const char* modeText)
	{
		EnterCriticalSection(&g_syncLock);
		g_syncApplied = applied ? applied : "";
		g_syncRestart = restart ? restart : "";
		g_syncDetail = detail ? detail : "";
		g_syncModeText = modeText ? modeText : "";
		g_syncHasResult = true;
		LeaveCriticalSection(&g_syncLock);
		SetEvent(g_syncDone);
	}

	// ------------------------------------------------------------------
	// 管道安全描述符：调用方用户 + Administrators
	// ------------------------------------------------------------------
	//
	// ★★ 这一段的缺失的症状是**误导性的**：引擎是 `requireAdministrator`，
	//    配置工具是普通用户 ⇒ 跨完整性级别访问命名管道，如果 DACL 里没有
	//    调用方用户 SID，`CreateFileW` 恒定返回 `ERROR_ACCESS_DENIED(5)`。
	//    而配置工具把它翻译成"引擎没在跑" —— 于是一个权限问题被当成
	//    "进程不在"，怎么查都查不到（这正是本函数存在的原因）。
	//
	//   Administrators 也要放：管理员手动从高完整性 shell 里跑配置工具时
	//   一样要连得上。
	bool BuildSecurityAttributes(SECURITY_ATTRIBUTES& sa, SECURITY_DESCRIPTOR& sd,
		std::vector<BYTE>& userSidStorage, std::vector<BYTE>& aclStorage)
	{
		// ---- 调用方用户 SID ----
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		DWORD size = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &size);
		if (size == 0) {
			CloseHandle(token);
			return false;
		}
		userSidStorage.assign(size, 0);
		const BOOL gotUser = GetTokenInformation(token, TokenUser,
			userSidStorage.data(), size, &size);
		CloseHandle(token);
		if (!gotUser) {
			return false;
		}
		const PSID userSid = reinterpret_cast<TOKEN_USER*>(userSidStorage.data())->User.Sid;

		// ---- Administrators 的良构 SID ----
		BYTE adminSid[SECURITY_MAX_SID_SIZE] = {};
		DWORD adminSidSize = sizeof(adminSid);
		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid, &adminSidSize)) {
			return false;
		}

		EXPLICIT_ACCESSW entries[2] = {};
		entries[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
		entries[0].grfAccessMode = SET_ACCESS;
		entries[0].grfInheritance = NO_INHERITANCE;
		entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
		entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
		entries[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(const_cast<PSID>(userSid));

		entries[1] = entries[0];
		entries[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(adminSid);

		PACL acl = nullptr;
		if (SetEntriesInAclW(2, entries, nullptr, &acl) != ERROR_SUCCESS || !acl) {
			return false;
		}

		if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)
			|| !SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE)) {
			LocalFree(acl);
			return false;
		}

		// ACL 由 SECURITY_DESCRIPTOR 引用 ⇒ 必须活到 CreateNamedPipeW 之后。
		// 存进调用方的 vector（它活得更久）而不是局部变量。
		aclStorage.assign(reinterpret_cast<const BYTE*>(acl),
			reinterpret_cast<const BYTE*>(acl) + acl->AclSize);
		LocalFree(acl);

		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = &sd;
		sa.bInheritHandle = FALSE;
		// 让 sd 指向我们搬走的那份 ACL。
		if (!SetSecurityDescriptorDacl(&sd, TRUE,
			reinterpret_cast<PACL>(aclStorage.data()), FALSE)) {
			return false;
		}
		return true;
	}

	// ------------------------------------------------------------------
	// 处理一条请求 -> 一条应答（含载荷行）
	// ------------------------------------------------------------------
	void HandleRequest(const std::string& request, std::string& response)
	{
		const std::vector<std::string> fields = Ipc::SplitFields(request);
		if (fields.empty() || fields[0].empty()) {
			InterlockedIncrement(&g_malformed);
			response = Ipc::BuildErrorResponse("空请求");
			return;
		}

		const std::string& verb = fields[0];

		// ---- PING：只探活（配置工具用它判断"引擎在不在"，
		//      比 FindWindow 可靠 —— 窗口可能被别的实例占着）----
		if (verb == Ipc::kVerbPing) {
			response = Ipc::BuildResponse({ "OK", "pong=1" });
			return;
		}

		// ---- HELLO：握手 ----
		if (verb == Ipc::kVerbHello) {
			std::vector<std::string> status = {
				"OK",
				std::string("proto=") + std::to_string(Ipc::kProtocolVersion),
				std::string("abi=") + std::to_string(R3ShieldCore::AbiVersion),
				std::string("pid=") + std::to_string(GetCurrentProcessId()),
			};
			response = Ipc::BuildResponse(status);
			return;
		}

		// ---- LOG：事件流（按序号增量取）----
		if (verb == Ipc::kVerbLog) {
			InterlockedIncrement(&g_logRequests);
			const ULONG since = Ipc::ToULong(fields.size() > 1 ? fields[1] : std::string());
			ULONG maxCount = Ipc::ToULong(fields.size() > 2 ? fields[2] : std::string(), 256);
			if (maxCount == 0 || maxCount > Ipc::kMaxLogBatch) {
				maxCount = Ipc::kMaxLogBatch;
			}

			// ★ 直接调 `R3ShieldCoreStats` —— 它自带 `CRITICAL_SECTION`，
			//   服务线程与主循环并发访问是安全的，不需要另做快照通道。
			const R3ShieldCoreStats::LogChunk chunk =
				R3ShieldCoreStats::GetLogsSince(since, maxCount);

			std::vector<std::string> payload;
			payload.reserve(chunk.Entries.size());
			for (const R3ShieldCoreStats::LogEntry& entry : chunk.Entries) {
				payload.push_back(Ipc::BuildLogPayloadLine(entry.Serial, entry.Line));
			}

			const std::vector<std::string> status = {
				"OK",
				std::string("latest=") + std::to_string(chunk.LatestSerial),
				std::string("total=") + std::to_string(chunk.TotalWritten),
				std::string("count=") + std::to_string(payload.size()),
			};
			response = Ipc::BuildResponse(status, payload);
			return;
		}

		// ---- CONFIG：引擎**当前生效**的配置 ----
		if (verb == Ipc::kVerbConfig) {
			InterlockedIncrement(&g_configRequests);

			std::vector<std::string> payload;
			auto add = [&payload](const char* key, const std::string& value) {
				payload.push_back(Ipc::BuildConfigPayloadLine(key, value));
			};
			auto addNum = [&add](const char* key, ULONGLONG value) {
				add(key, std::to_string(value));
			};

			// 身份与来源
			add("ini", Text::WideToUtf8(g_options.IniPath.wstring()));
			add("exe", Text::WideToUtf8(g_options.ExeDirectory.wstring()));
			addNum("abi", R3ShieldCore::AbiVersion);
			addNum("pid", GetCurrentProcessId());
			addNum("ini_hash", g_iniDigestAtStart);

			if (g_options.Policy) {
				const R3ShieldCore::Policy& p = *g_options.Policy;
				const char* modeText = R3ShieldCoreConfig::ModeIniText(p.Mode);
				add("mode", modeText ? modeText : "?");
				addNum("prompt_timeout", p.PromptTimeoutMs);
				add("prompt_default",
					p.PromptDefaultVerdict == static_cast<ULONG>(R3ShieldCore::Verdict::Allow)
						? "allow" : "deny");
				add("log", Text::WideToUtf8(p.LogPath));
				addNum("exclude_count", p.ExcludePathCount);
				addNum("never_inject_count", p.NeverInjectCount);
				addNum("test_inject_count", p.TestInjectCount);
				addNum("protect_reg_count", p.ProtectRegCount);
				addNum("protect_file_count", p.ProtectFileCount);
				addNum("protect_process_count", p.ProtectProcessCount);
				addNum("protect_driver_count", p.ProtectDriverCount);
				addNum("protect_net_count", p.ProtectNetCount);
			}

			if (g_options.EngineSettings) {
				const R3ShieldCoreConfig::EngineSettings& s = *g_options.EngineSettings;
				addNum("inject_interval_ms", s.InjectionIntervalMs);
				addNum("persist_stats", s.PersistStats ? 1 : 0);
				addNum("replay_history_log", s.ReplayHistoryLog ? 1 : 0);
				addNum("replay_history_limit", s.ReplayHistoryLimit);
				addNum("neutralize_overlay", s.NeutralizeOverlayLevel);
				addNum("high_risk_process_alert", s.HighRiskProcessAlert);
				addNum("high_risk_process_scan_ms", s.HighRiskProcessScanMs);
				addNum("ark_enabled", s.ArkEnabled ? 1 : 0);
				addNum("ark_scan_ms", s.ArkScanMs);
				addNum("ark_refresh_ms", s.ArkRefreshMs);
			}

			const std::vector<std::string> status = {
				"OK", std::string("count=") + std::to_string(payload.size()),
			};
			response = Ipc::BuildResponse(status, payload);
			return;
		}

		// ---- SYNC：请引擎重读 ini 并热应用 ----
		if (verb == Ipc::kVerbSync) {
			InterlockedIncrement(&g_syncRequests);

			if (!g_syncLockReady) {
				InterlockedIncrement(&g_errors);
				response = Ipc::BuildErrorResponse("同步通道未就绪");
				return;
			}

			ResetEvent(g_syncDone);
			EnterCriticalSection(&g_syncLock);
			g_syncHasResult = false;
			g_syncApplied.clear();
			g_syncRestart.clear();
			g_syncDetail.clear();
			g_syncModeText.clear();
			LeaveCriticalSection(&g_syncLock);

			g_syncPending.store(true);

			if (WaitForSingleObject(g_syncDone, 5000) != WAIT_OBJECT_0) {
				InterlockedIncrement(&g_errors);
				response = Ipc::BuildErrorResponse(
					"引擎主循环未在 5 秒内响应同步请求（引擎可能正在退出）");
				return;
			}

			std::string applied, restart, detail, modeText;
			bool has = false;
			EnterCriticalSection(&g_syncLock);
			has = g_syncHasResult;
			applied = g_syncApplied;
			restart = g_syncRestart;
			detail = g_syncDetail;
			modeText = g_syncModeText;
			LeaveCriticalSection(&g_syncLock);

			if (!has) {
				InterlockedIncrement(&g_errors);
				response = Ipc::BuildErrorResponse("同步请求未产生结论");
				return;
			}

			const std::vector<std::string> status = {
				"OK",
				std::string("applied=") + Ipc::Escape(applied),
				std::string("restart=") + Ipc::Escape(restart),
				std::string("mode=") + Ipc::Escape(modeText),
				std::string("detail=") + Ipc::Escape(detail),
			};
			response = Ipc::BuildResponse(status);
			return;
		}

		InterlockedIncrement(&g_malformed);
		response = Ipc::BuildErrorResponse("认不出的请求：" + verb);
	}

	// 服务一个已连接的客户端。返回 false = 该断开重来。
	bool ServeOneClient()
	{
		std::string buffer;
		for (;;) {
			if (g_stop.load()) {
				return false;
			}

			char chunk[1024] = {};
			DWORD got = 0;
			if (!ReadFile(g_pipe, chunk, sizeof(chunk), &got, nullptr) || got == 0) {
				return false;   // 客户端断开 / 管道出错
			}
			buffer.append(chunk, got);

			// 逐行处理。一条请求一定以 '\n' 结尾（协议规定）。
			for (;;) {
				const size_t newline = buffer.find('\n');
				if (newline == std::string::npos) {
					break;
				}
				std::string line = buffer.substr(0, newline);
				buffer.erase(0, newline + 1);
				if (!line.empty() && line.back() == '\r') {
					line.pop_back();
				}
				if (line.empty()) {
					continue;
				}

				std::string response;
				HandleRequest(line, response);

				DWORD wrote = 0;
				if (!WriteFile(g_pipe, response.data(),
					static_cast<DWORD>(response.size()), &wrote, nullptr)) {
					return false;
				}
			}

			// 防御：对面一直发不带换行的垃圾 ⇒ 直接断开，别把内存吃光。
			if (buffer.size() > Ipc::kMaxRequestBytes) {
				InterlockedIncrement(&g_malformed);
				printf("[ipc] 收到超长无换行数据（%zu 字节），断开该连接\n", buffer.size());
				fflush(stdout);
				return false;
			}
		}
	}

	// 建一个管道实例（含安全描述符）。
	bool CreatePipeInstance()
	{
		SECURITY_ATTRIBUTES sa = {};
		SECURITY_DESCRIPTOR sd = {};
		std::vector<BYTE> userSidStorage;
		std::vector<BYTE> aclStorage;
		if (!BuildSecurityAttributes(sa, sd, userSidStorage, aclStorage)) {
			printf("[ipc] 构造管道安全描述符失败（err=%lu）—— 配置工具将连不上引擎\n",
				static_cast<unsigned long>(GetLastError()));
			fflush(stdout);
			return false;
		}

		const std::wstring name = Ipc::PipeName();
		g_pipe = CreateNamedPipeW(name.c_str(),
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			1,                 // 只允许一个实例：配置工具本身是单实例
			256 * 1024,        // 出缓冲：一次 LOG 可能几百 KB，给足免得来回阻塞
			16 * 1024,         // 入缓冲：请求都很短
			0, &sa);
		if (g_pipe == INVALID_HANDLE_VALUE) {
			printf("[ipc] 建管道失败（err=%lu）\n", static_cast<unsigned long>(GetLastError()));
			fflush(stdout);
			return false;
		}
		return true;
	}

	DWORD WINAPI ServerThread(LPVOID)
	{
		printf("[ipc] 管道服务已启动：%ls\n", Ipc::PipeName().c_str());
		fflush(stdout);

		while (!g_stop.load()) {
			if (!CreatePipeInstance()) {
				// 建不出来（内存/句柄耗尽）—— 退避重试，别把 CPU 烧了。
				Sleep(500);
				continue;
			}

			const BOOL connected = ConnectNamedPipe(g_pipe, nullptr)
				? TRUE
				: (GetLastError() == ERROR_PIPE_CONNECTED);

			if (g_stop.load()) {
				DisconnectNamedPipe(g_pipe);
				CloseHandle(g_pipe);
				g_pipe = INVALID_HANDLE_VALUE;
				break;
			}

			if (!connected) {
				CloseHandle(g_pipe);
				g_pipe = INVALID_HANDLE_VALUE;
				continue;
			}

			InterlockedIncrement(&g_accepted);
			InterlockedExchange(&g_clientConnected, 1);
			printf("[ipc] 配置工具已连接\n");
			fflush(stdout);

			ServeOneClient();

			InterlockedExchange(&g_clientConnected, 0);
			DisconnectNamedPipe(g_pipe);
			CloseHandle(g_pipe);
			g_pipe = INVALID_HANDLE_VALUE;
			printf("[ipc] 配置工具已断开\n");
			fflush(stdout);
		}

		printf("[ipc] 管道服务已停止\n");
		fflush(stdout);
		return 0;
	}
}   // namespace

namespace R3ShieldCoreCfgIpcServer
{
	bool Start(const Options& options) noexcept
	{
		if (g_thread) {
			return true;   // 已经起了
		}

		g_options = options;
		g_stop.store(false);

		InitializeCriticalSection(&g_syncLock);
		g_syncLockReady = true;
		g_syncDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!g_syncDone) {
			printf("[ipc] 建同步事件失败（err=%lu），管道服务不启动\n",
				static_cast<unsigned long>(GetLastError()));
			fflush(stdout);
			return false;
		}

		// 记下"引擎启动时读到的那份 ini"的内容摘要 —— 配置工具靠它回答
		// "我改的这份引擎用上了吗"。
		ULONGLONG iniSize = 0;
		g_iniDigestAtStart = Ipc::FileDigest(options.IniPath.wstring(), &iniSize);
		printf("[ipc] 引擎启动时读到的 ini：%ls（%llu 字节，摘要 %016llX）\n",
			options.IniPath.c_str(),
			static_cast<unsigned long long>(iniSize),
			static_cast<unsigned long long>(g_iniDigestAtStart));
		fflush(stdout);

		g_thread = CreateThread(nullptr, 0, ServerThread, nullptr, 0, nullptr);
		if (!g_thread) {
			printf("[ipc] 服务线程创建失败（err=%lu）\n",
				static_cast<unsigned long>(GetLastError()));
			fflush(stdout);
			CloseHandle(g_syncDone);
			g_syncDone = nullptr;
			return false;
		}
		return true;
	}

	void Stop() noexcept
	{
		if (!g_thread) {
			return;
		}

		g_stop.store(true);

		// 唤醒可能正阻塞在 `ConnectNamedPipe` 的线程：自己连一次再关掉。
		// （不这么做的话，没有客户端时线程会一直等在那里，join 必然超时。）
		HANDLE wake = CreateFileW(Ipc::PipeName().c_str(),
			GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (wake != INVALID_HANDLE_VALUE) {
			CloseHandle(wake);
		}

		// 若线程正阻塞在 `ReadFile`（客户端还连着），同步 I/O 需要显式取消。
		CancelSynchronousIo(g_thread);

		const DWORD waited = WaitForSingleObject(g_thread, 3000);
		if (waited == WAIT_OBJECT_0) {
			CloseHandle(g_thread);
			g_thread = nullptr;
			if (g_pipe != INVALID_HANDLE_VALUE) {
				CloseHandle(g_pipe);
				g_pipe = INVALID_HANDLE_VALUE;
			}
		}
		else {
			// ★ 不 join 到底：引擎正在收尾，宁可让进程退出时回收这个线程，
			//   也不能把退出流程卡住（用户在等窗口关掉）。
			printf("[ipc] 服务线程未在 3 秒内退出，留给进程退出回收\n");
			fflush(stdout);
			g_thread = nullptr;
		}

		if (g_syncDone) {
			CloseHandle(g_syncDone);
			g_syncDone = nullptr;
		}
	}

	void PollSync(EngineControl& engineControl) noexcept
	{
		if (!g_syncLockReady) {
			return;
		}
		if (!g_syncPending.exchange(false)) {
			return;
		}
		if (!g_options.Policy) {
			PublishSyncResult("", "", "引擎策略未初始化", "");
			return;
		}

		//
		// ① 重读 ini —— **读到临时对象里**，不动正在跑的引擎。
		//
		//    为什么用临时对象：`Load` 会整份重填 Policy（含各 WCHAR 数组），
		//    而共享内存里那份是 DLL 判定用的。半途重填正在被读的缓冲
		//    会让 hook 读到"半个路径" —— 那可能让一条本该拦的操作被放行。
		//    ⇒ 只有**确认要热应用**的那一项（mode）才写回引擎。
		//
		R3ShieldCore::Policy fresh = {};
		R3ShieldCoreConfig::Load(fresh, g_options.ExeDirectory);

		const R3ShieldCore::Policy& running = *g_options.Policy;
		const bool modeChanged = (fresh.Mode != running.Mode);

		//
		// ② 热应用：**只有 `mode` 是热的**。
		//
		//    引擎里真正"改完立刻全局生效"的只有它 ——
		//    `GlobalHookSessionSetMode` 只改共享内存 Policy 块里的 `Mode`，
		//    而被注入进程**每次判定都重读**它。
		//    其余开关（hook_* / protect_* / exclude / 注入间隔 / 回放 / ARK）
		//    都是启动期定死的 `EngineSettings` 或注入时确定下来的 hook 集合。
		//    ⇒ 界面必须把这件事说出来，否则用户以为保存完就生效了。
		//
		std::string applied;
		std::string detail;
		const char* modeText = R3ShieldCoreConfig::ModeIniText(fresh.Mode);

		if (modeChanged) {
			if (engineControl.SetMode(static_cast<R3ShieldCore::Mode>(fresh.Mode))) {
				g_options.Policy->Mode = fresh.Mode;          // 让后续 CONFIG 报新值
				R3ShieldCoreGui::SetMode(static_cast<R3ShieldCore::Mode>(fresh.Mode));
				applied = "mode";
				detail = "已重读配置文件：运行模式已立即切换";
				printf("[ipc] SYNC：运行模式已热切换为 %s\n", modeText ? modeText : "?");
			}
			else {
				detail = "已重读配置文件：运行模式切换失败（DLL 不支持运行期切换）";
				printf("[ipc] SYNC：运行模式热切换失败（DLL 不支持）\n");
			}
		}
		else {
			applied = "mode";
			detail = "已重读配置文件：运行模式无变化";
		}

		//
		// ③ 其余项：拿"引擎启动时读到的那份 ini"和现在的文件比内容摘要。
		//    不一样 ⇒ 明说"要重启引擎"。不逐键列举是**刻意**的 ——
		//    那需要一份"Flags 位 → ini 键名"的反查表，而它只能是
		//    `r3shieldcore_config.cpp` 里正向映射的第二份副本（铁律 127：
		//    两份必然漂）。用文件摘要回答"是不是同一份配置"既不重复映射，
		//    也比 mtime 可靠（复制/还原会改 mtime 却不改内容）。
		//
		std::string restart;
		{
			ULONGLONG nowSize = 0;
			const ULONGLONG nowDigest = Ipc::FileDigest(g_options.IniPath.wstring(), &nowSize);
			if (nowDigest != 0 && g_iniDigestAtStart != 0 && nowDigest != g_iniDigestAtStart) {
				restart = "hook_* / protect_* / exclude / never_inject / 注入间隔 / 回放 / ARK 等"
					"（除运行模式外的全部项）";
			}
		}

		fflush(stdout);
		PublishSyncResult(applied.c_str(), restart.c_str(), detail.c_str(),
			modeText ? modeText : "");
	}

	Stats GetStats() noexcept
	{
		Stats stats = {};
		stats.Accepted = static_cast<ULONG>(InterlockedCompareExchange(&g_accepted, 0, 0));
		stats.LogRequests = static_cast<ULONG>(InterlockedCompareExchange(&g_logRequests, 0, 0));
		stats.ConfigRequests = static_cast<ULONG>(InterlockedCompareExchange(&g_configRequests, 0, 0));
		stats.SyncRequests = static_cast<ULONG>(InterlockedCompareExchange(&g_syncRequests, 0, 0));
		stats.Errors = static_cast<ULONG>(InterlockedCompareExchange(&g_errors, 0, 0));
		stats.Malformed = static_cast<ULONG>(InterlockedCompareExchange(&g_malformed, 0, 0));
		stats.ClientConnected =
			InterlockedCompareExchange(&g_clientConnected, 0, 0) != 0;
		return stats;
	}

	bool LastSyncSummary(std::wstring& appliedOut, std::wstring& restartOut) noexcept
	{
		if (!g_syncLockReady) {
			return false;
		}
		bool has = false;
		EnterCriticalSection(&g_syncLock);
		has = g_syncHasResult;
		if (has) {
			appliedOut = Text::Utf8ToWide(g_syncApplied);
			restartOut = Text::Utf8ToWide(g_syncRestart);
		}
		LeaveCriticalSection(&g_syncLock);
		return has;
	}
}
