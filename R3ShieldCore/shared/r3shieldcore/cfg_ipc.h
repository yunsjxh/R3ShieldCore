// cfg_ipc.h —— 「配置工具（r3shieldcore-cfg.exe）」⇄「引擎（R3 ShieldCore.exe）」
//             之间的**管道协议**契约。
//
//   为什么要有这个头（铁律 127）：
//     请求文法、应答文法、字段分隔符、**转义规则**、管道名 —— 这些东西
//     服务端与客户端各写一份，改了不报错：一边发 `LOG|12|256`，另一边
//     期待 `LOG|12|256|`，症状是"连上了但一条都读不出来"，
//     而两边都认为自己是对的。
//     ⇒ 全部常量与编解码**只在这一处**，两侧 `#include` 同一个头。
//
//   ────────────────────────────────────────────────────────────────
//   为什么用管道（而不是共享内存）
//   ────────────────────────────────────────────────────────────────
//   引擎里那份"事件流"是**进程内**的环形缓冲（`R3ShieldCoreStats`），
//   它**不进共享内存**（共享内存里只有 `Policy`）。所以配置工具想拿到它，
//   只能**问引擎要** —— 这正是本协议存在的理由。
//
//   ⚠️ 顺带一个好处：`R3ShieldCoreStats` 自己带 `CRITICAL_SECTION`，
//      服务端线程可以直接调 `GetLogsSince` 增量取，**不需要**额外做快照通道。
//
//   ────────────────────────────────────────────────────────────────
//   线格式（UTF-8 文本，一行一条记录）
//   ────────────────────────────────────────────────────────────────
//   请求：  <VERB>[|<字段>]...  \n
//   应答：  OK|<字段>...       \n      ← 状态行
//           [<载荷行> \n]...            ← 由状态行里的 count= 决定条数
//   失败：  ERR|<说明>          \n
//
//   ★ 字段里**可能含任意文本**（日志行里有 `|`、路径里有 `\`、错误说明里
//     有换行）⇒ 所有"自由文本"字段必须过 `Escape()`：
//        `\` → `\\`      `|` → `\p`      CR → `\r`      LF → `\n`
//     数字字段（序号 / 计数 / pid）**不转义**（它们不含分隔符）。
//     不转义的话，日志行里的一个 `|` 就会让**字段数漂**，
//     下游按位置取字段全部错位 —— 而那是"能连上、能读到行、只是内容不对"，
//     最难发现的一类。
//
//   本头只依赖 Win32 + STL，两个 exe 都能直接 #include（不需要链任何库）。
#pragma once
#ifndef R3SHIELDCORE_CFG_IPC_H
#define R3SHIELDCORE_CFG_IPC_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdlib>
#include <string>
#include <vector>

namespace R3ShieldCoreCfgIpc
{
	// 协议版本。两侧对不上就**明说**（ERR 里带上双方的版本号），
	// 不做"尽力兼容"—— 字段悄悄少一个比直接拒绝更难查。
	constexpr int kProtocolVersion = 1;

	// 管道名前缀。**完整名 = 前缀 + 会话号**（见 PipeName()）。
	//
	// ⚠️ 为什么必须带会话号：`Local\` 只保证"同一会话内唯一"，多登录会话
	//    （RDP / 快速用户切换）下两个会话会**撞同一个名字** ——
	//    后到的那个连上的可能是**另一个会话的引擎**，然后显示别人的日志。
	//    会话号取自 `ProcessIdToSessionId(GetCurrentProcessId())`，
	//    两侧算出来必然一样（同一个会话里的进程）。
	constexpr wchar_t kPipeNamePrefix[] = L"\\\\.\\pipe\\R3ShieldCoreCfgIpc";

	// 单条请求的最大字节数（防御性上限：请求都很短，超了直接断）。
	constexpr size_t kMaxRequestBytes = 4096;

	// 单次 LOG 请求最多要多少条（服务端会夹到这个值）。
	// 512 与主程序界面自己的 `GetLogsSince(..., 512)` 一致。
	constexpr size_t kMaxLogBatch = 512;

	// 单条应答行的上限。日志行本身最长 ~2KB（见 log_line.h 的 line[2048]），
	// 留足余量；超了说明对面在发垃圾，直接断。
	constexpr size_t kMaxResponseLineBytes = 16 * 1024;

	// ---- 命令字（VERB）----
	constexpr char kVerbHello[] = "HELLO";   // 握手：拿协议版本 / ABI / pid / 引擎 exe 路径
	constexpr char kVerbLog[] = "LOG";       // 取事件流：LOG|<sinceSerial>|<maxCount>
	constexpr char kVerbConfig[] = "CONFIG"; // 取引擎**生效**配置：CONFIG
	constexpr char kVerbSync[] = "SYNC";     // 请引擎重读 ini 并热应用：SYNC
	constexpr char kVerbPing[] = "PING";     // 只探活

	// ------------------------------------------------------------------
	// 管道名
	// ------------------------------------------------------------------
	inline std::wstring PipeName() noexcept
	{
		DWORD session = 0;
		if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &session)) {
			session = 0;
		}
		return std::wstring(kPipeNamePrefix) + std::to_wstring(session);
	}

	// ------------------------------------------------------------------
	// 转义 / 反转义
	// ------------------------------------------------------------------
	inline std::string Escape(const std::string& raw) noexcept
	{
		std::string out;
		out.reserve(raw.size() + 8);
		for (const char c : raw) {
			switch (c) {
			case '\\': out += "\\\\"; break;
			case '|':  out += "\\p";  break;
			case '\r': out += "\\r";  break;
			case '\n': out += "\\n";  break;
			default:   out += c;      break;
			}
		}
		return out;
	}

	// 反转义。**单趟左到右**扫描，所以不会出现"先解 `\\` 再解 `\p`"那种
	// 二次解码错误（那样 `\\p` 会被解成 `|`，而它本该是一个反斜杠 + p）。
	inline std::string Unescape(const std::string& escaped) noexcept
	{
		std::string out;
		out.reserve(escaped.size());
		for (size_t i = 0; i < escaped.size(); ++i) {
			const char c = escaped[i];
			if (c != '\\' || i + 1 >= escaped.size()) {
				out += c;
				continue;
			}
			const char n = escaped[++i];
			switch (n) {
			case '\\': out += '\\'; break;
			case 'p':  out += '|';  break;
			case 'r':  out += '\r'; break;
			case 'n':  out += '\n'; break;
			default:
				// 不认识的转义：原样保留（宽容解析 —— 对面加了个新转义符
				// 不该让整条记录报废，只是那一段文本原样显示）。
				out += '\\';
				out += n;
				break;
			}
		}
		return out;
	}

	// ------------------------------------------------------------------
	// 拆字段 / 拼字段
	// ------------------------------------------------------------------
	// 按 `|` 拆成字段。**不做反转义** —— 调用方按字段语义决定要不要 Unescape
	// （数字字段不用）。这样"转义"与"字段切分"两件事不会互相污染。
	inline std::vector<std::string> SplitFields(const std::string& line) noexcept
	{
		std::vector<std::string> out;
		size_t start = 0;
		for (;;) {
			const size_t bar = line.find('|', start);
			if (bar == std::string::npos) {
				out.push_back(line.substr(start));
				return out;
			}
			out.push_back(line.substr(start, bar - start));
			start = bar + 1;
		}
	}

	inline std::string JoinFields(const std::vector<std::string>& fields) noexcept
	{
		std::string out;
		for (size_t i = 0; i < fields.size(); ++i) {
			if (i) { out += '|'; }
			out += fields[i];
		}
		return out;
	}

	// 数字字段解析：认不出来返回 fallback（不抛异常、不改调用方流程）。
	inline ULONG ToULong(const std::string& text, ULONG fallback = 0) noexcept
	{
		if (text.empty()) {
			return fallback;
		}
		char* stop = nullptr;
		const unsigned long v = strtoul(text.c_str(), &stop, 10);
		if (stop == text.c_str()) {
			return fallback;
		}
		return static_cast<ULONG>(v);
	}

	// ------------------------------------------------------------------
	// 文件内容摘要（FNV-1a 64）
	// ------------------------------------------------------------------
	//
	//   ★ 用途：回答"我改的那份配置，引擎到底在用哪一份？"
	//
	//     引擎启动时读一次 ini，之后就不再读了（除了 `mode` 是热的）。
	//     用户在配置工具里改了 ini、保存了，**引擎手里仍然是启动时那份**。
	//     界面必须把这件事说清楚，否则用户会以为"保存完就生效了"。
	//
	//     比 mtime 可靠：复制 / 还原 / 同步盘都会改 mtime 却不改内容；
	//     而内容变了 mtime 一定变。所以比内容。
	//
	//   返回 0 = 打不开 / 读失败（**不要**当成"内容为空"）。
	//   `sizeOut` 回传文件字节数（可空）。
	inline ULONGLONG FileDigest(const std::wstring& path, ULONGLONG* sizeOut = nullptr) noexcept
	{
		if (sizeOut) { *sizeOut = 0; }

		HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return 0;
		}

		ULONGLONG hash = 1469598103934665603ull;   // FNV-1a 64 offset basis
		ULONGLONG total = 0;
		BYTE buffer[65536];
		DWORD got = 0;
		while (::ReadFile(file, buffer, sizeof(buffer), &got, nullptr) && got > 0) {
			total += got;
			for (DWORD i = 0; i < got; ++i) {
				hash ^= buffer[i];
				hash *= 1099511628211ull;          // FNV-1a 64 prime
			}
		}
		::CloseHandle(file);

		if (sizeOut) { *sizeOut = total; }
		return hash;
	}

	// ------------------------------------------------------------------
	// 请求构造
	// ------------------------------------------------------------------
	inline std::string BuildHelloRequest() noexcept
	{
		return std::string(kVerbHello);
	}

	inline std::string BuildPingRequest() noexcept
	{
		return std::string(kVerbPing);
	}

	inline std::string BuildLogRequest(ULONG sinceSerial, size_t maxCount) noexcept
	{
		if (maxCount == 0 || maxCount > kMaxLogBatch) {
			maxCount = kMaxLogBatch;
		}
		return std::string(kVerbLog) + "|" + std::to_string(sinceSerial)
			+ "|" + std::to_string(maxCount);
	}

	inline std::string BuildConfigRequest() noexcept
	{
		return std::string(kVerbConfig);
	}

	inline std::string BuildSyncRequest() noexcept
	{
		return std::string(kVerbSync);
	}

	// ------------------------------------------------------------------
	// 应答构造
	// ------------------------------------------------------------------
	inline std::string BuildErrorResponse(const std::string& message) noexcept
	{
		return std::string("ERR|") + Escape(message);
	}

	// 状态行 + 若干载荷行 ⇒ 一整块待发送的字节（每行自带 '\n'）。
	inline std::string BuildResponse(const std::vector<std::string>& statusFields,
		const std::vector<std::string>& payloadLines = {}) noexcept
	{
		std::string out = JoinFields(statusFields);
		out += '\n';
		for (const std::string& line : payloadLines) {
			out += line;
			out += '\n';
		}
		return out;
	}

	// ------------------------------------------------------------------
	// 应答解析
	// ------------------------------------------------------------------
	struct Response
	{
		bool IsError = false;               // ERR|
		bool Ok = false;                    // 解析成功（且不是 ERR）
		std::vector<std::string> Fields;    // 状态行的字段（已 Split，**未** Unescape）
		std::vector<std::string> Payload;   // 载荷行原文
		std::string Raw;                    // 状态行原文（诊断用）
	};

	// 把"一整块应答字节"切成状态行 + 载荷行。
	// 返回 false = 空应答 / 状态行都不是 OK| 或 ERR|（协议不同步）。
	inline bool ParseResponse(const std::string& blob, Response& out) noexcept
	{
		out = Response{};

		size_t start = 0;
		bool first = true;
		while (start <= blob.size()) {
			size_t nl = blob.find('\n', start);
			if (nl == std::string::npos) {
				nl = blob.size();
			}
			std::string line = blob.substr(start, nl - start);
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}

			if (first) {
				first = false;
				if (line.empty()) {
					return false;
				}
				out.Raw = line;
				out.Fields = SplitFields(line);
				if (out.Fields.empty()) {
					return false;
				}
				if (out.Fields[0] == "ERR") {
					out.IsError = true;
					out.Ok = false;
					return true;
				}
				if (out.Fields[0] != "OK") {
					return false;
				}
				out.Ok = true;
			}
			else if (!line.empty()) {
				out.Payload.push_back(line);
			}

			if (nl >= blob.size()) {
				break;
			}
			start = nl + 1;
		}
		return true;
	}

	// 在状态行的字段里按 `key=value` 取值（value 会被反转义）。
	// 找不到返回 fallback。
	inline std::string FindKeyed(const Response& response, const char* key,
		const std::string& fallback = std::string()) noexcept
	{
		const std::string prefix = std::string(key) + "=";
		for (size_t i = 1; i < response.Fields.size(); ++i) {
			const std::string& field = response.Fields[i];
			if (field.size() >= prefix.size()
				&& field.compare(0, prefix.size(), prefix) == 0) {
				return Unescape(field.substr(prefix.size()));
			}
		}
		return fallback;
	}

	// ------------------------------------------------------------------
	// 日志载荷行：`L|<serial>|<转义后的整行文本>`
	// ------------------------------------------------------------------
	inline std::string BuildLogPayloadLine(ULONG serial, const std::string& lineUtf8) noexcept
	{
		return std::string("L|") + std::to_string(serial) + "|" + Escape(lineUtf8);
	}

	// 解析一条载荷行。返回 false = 不是日志行（调用方跳过）。
	inline bool ParseLogPayloadLine(const std::string& payload,
		ULONG& serialOut, std::string& lineOut) noexcept
	{
		if (payload.size() < 2 || payload[0] != 'L' || payload[1] != '|') {
			return false;
		}
		const size_t bar = payload.find('|', 2);
		if (bar == std::string::npos) {
			return false;
		}
		serialOut = ToULong(payload.substr(2, bar - 2));
		lineOut = Unescape(payload.substr(bar + 1));
		return true;
	}

	// ------------------------------------------------------------------
	// 配置载荷行：`C|<转义后的键>|<转义后的值>`
	// ------------------------------------------------------------------
	inline std::string BuildConfigPayloadLine(const std::string& key,
		const std::string& value) noexcept
	{
		return std::string("C|") + Escape(key) + "|" + Escape(value);
	}

	inline bool ParseConfigPayloadLine(const std::string& payload,
		std::string& keyOut, std::string& valueOut) noexcept
	{
		if (payload.size() < 2 || payload[0] != 'C' || payload[1] != '|') {
			return false;
		}
		const size_t bar = payload.find('|', 2);
		if (bar == std::string::npos) {
			return false;
		}
		keyOut = Unescape(payload.substr(2, bar - 2));
		valueOut = Unescape(payload.substr(bar + 1));
		return true;
	}

	// ------------------------------------------------------------------
	// SYNC 的结论：哪些项"热应用"了、哪些"要重启引擎"
	// ------------------------------------------------------------------
	//
	//   ★ 这个字段是**给用户看的**，不是诊断日志。所以它必须**诚实**：
	//     引擎里真正"热"的只有 `mode`（`GlobalHookSessionSetMode` 只改共享
	//     内存 Policy 块里的 `Mode`，被注入进程每次判定都重读）。
	//     其余开关都是**启动期定死**的 `EngineSettings` / hook 集合 ——
	//     界面必须把"要重启"说出来，否则用户会以为保存完就生效了。
	constexpr char kSyncFieldApplied[] = "applied";  // 已立即生效的键（逗号分隔）
	constexpr char kSyncFieldRestart[] = "restart";  // 需要重启引擎的键（逗号分隔）
	constexpr char kSyncFieldDetail[] = "detail";    // 给人看的一句话

	// ------------------------------------------------------------------
	// 客户端传输：连管道 → 发一条请求 → 收完整块应答
	// ------------------------------------------------------------------
	//
	//   ★ 为什么放在**共享头**里（铁律 127）：
	//     这一句"怎么连、超时怎么设、读到哪里算一条应答读完"如果客户端
	//     自己写一份，服务端改了分帧规则（比如应答里加了新的载荷行种类）
	//     客户端不会报错，只会**静默少读几条**。
	//
	//   ★ 语义（两侧都用同一份）：
	//     · 每次调用**新建一个连接**（管道实例是服务端一轮一个）——
	//       请求都很短，省掉的"长连接状态机"远比省下的握手值钱；
	//       而且"连接断了"天然等价于"引擎重启了"，不需要额外探测。
	//     · 管道是**字节模式**（两侧都在共享头里写死这个假设）：
	//       写请求 → `FlushFileBuffers` → 读应答，分帧靠**内容**
	//       （请求以 `\n` 结尾；应答靠状态行的 `count=N` 记账）。
	//     · 读用 `PeekNamedPipe` 先看有没有数据：**没有就立刻返回**
	//       （而不是阻塞在 `ReadFile` 上等满一个超时）——
	//       调用方是界面定时器（500ms 一拍），卡住界面比"这一拍没数据"严重。
	//     · 超时 / 断开 ⇒ 返回 `Ok=false` + 可读的 `Error`，
	//       调用方**回落**（读日志文件 / 报"引擎没在跑"），不抛异常。
	//
	//   ★ `WaitNamedPipeW` 只等 **50ms**：同上，界面不能被它拖住。
	struct CallResult
	{
		bool Connected = false;    // 连上了（哪怕应答是 ERR）
		bool Ok = false;           // 连上且应答是 OK|
		std::string Error;         // 没能连上 / 应答是 ERR 时的说明（UTF-8）
		Response Reply;            // 解析后的应答（Ok / IsError 时有意义）
	};

	inline CallResult Call(const std::string& request, DWORD timeoutMs = 800) noexcept
	{
		CallResult result;

		// ① 连（带等一等的短超时）。引擎不在跑 ⇒ 这里就是唯一的分支点。
		if (!::WaitNamedPipeW(PipeName().c_str(), 50)) {
			result.Error = "引擎没在运行（管道未就绪）";
			return result;
		}

		HANDLE pipe = ::CreateFileW(PipeName().c_str(), GENERIC_READ | GENERIC_WRITE,
			0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (pipe == INVALID_HANDLE_VALUE) {
			// ★ 这里最常见的是 `ERROR_ACCESS_DENIED(5)` —— 服务端 DACL 没放行。
			//   对用户来说它和"引擎没在跑"是**同一件事**（都表现为没有数据），
			//   但诊断上必须分开，否则永远查不出 DACL 的问题。
			const DWORD err = ::GetLastError();
			if (err == ERROR_ACCESS_DENIED) {
				result.Error = "连接被拒绝（权限不足 —— 管道 DACL 未放行当前用户）";
			}
			else {
				result.Error = "连不上引擎的配置接口";
			}
			return result;
		}
		result.Connected = true;

		// ② 写请求。超时设成参数值，免得服务端卡住时界面跟着卡。
		//
		//   ★★ 管道是**字节模式**（服务端 `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE`），
		//      客户端**不能**去 `SetNamedPipeHandleState(..., PIPE_READMODE_MESSAGE)`——
		//      对字节型管道设消息读模式会**直接失败**，而后面的 `ReadFile` 仍按
		//      字节流工作：不会报错，只会让"一次读拿到一条消息"这个假设悄悄失效。
		//      ⇒ 两侧都按**字节流 + 内容分帧**：请求以 `\n` 结尾、应答以
		//      `count=` 记账（见下面的读循环）。这是**契约的一部分**，
		//      改一侧必须改另一侧（铁律 127）。
		{
			DWORD mode = PIPE_READMODE_BYTE;
			::SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
		}

		std::string payload = request;
		payload += '\n';

		DWORD wrote = 0;
		if (!::WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()),
			&wrote, nullptr) || wrote != payload.size()) {
			result.Error = "写请求失败（引擎可能刚退出）";
			::CloseHandle(pipe);
			return result;
		}
		// ★ 必须 flush：消息模式管道上这是"请求到此为止"的界，不 flush
		//   服务端的 ReadFile 会继续等下一个包（直到超时）。
		::FlushFileBuffers(pipe);

		// ③ 读应答（可能要多轮）。
		//
		//   ★ 什么时候算"读完了"：管道是**字节流**，服务端每轮的应答可能被
		//     拆成任意片段交给我们。判据不能用"一次读全"，用**内容**：
		//     状态行里的 `count=N` 说了后面还有几条载荷行 —— 数够了就停。
		//     `ERR|` / `HELLO` / `PING` / `SYNC` 这类应答**没有** `count=`，
		//     只有状态行一行 ⇒ 拿到状态行就算读完。
		//
		//   ⚠️ 唯一的坑：如果状态行本身被拆开（只读到 `OK|latest=12` 还没到 `\n`），
		//      必须**继续读**而不是当成"只有状态行"。所以先等到第一个 `\n` 再判。
		(void)timeoutMs;   // 超时由 WaitNamedPipeW(50ms) 与"内容记账"共同保证
		std::string blob;
		blob.reserve(4096);
		char buffer[4096];
		const size_t hardLimit = kMaxResponseLineBytes * 64;  // 512 行 × 2KB 有余量

		// 已收到的完整行数（含状态行）。
		auto completeLines = [](const std::string& s) -> size_t {
			size_t n = 0;
			for (const char c : s) { if (c == '\n') { ++n; } }
			return n;
		};

		// ★★ "有没有数据"这件事**不能只问一次**：
		//    发完请求的那一瞬间服务端**必然还没写完**（它也要读、要处理、要写）。
		//    只 Peek 一次就判"没数据" ⇒ 每一次调用都白跑（实测就踩到这个：
		//    连上了、写成功了，却每次都报"引擎没有应答"）。
		//    ⇒ 给一个**短的总等待窗口**：在这段时间里轮询 Peek，
		//      拿到第一块就进入下面的记账循环。窗口取 150ms ——
		//      远小于界面定时器周期（500ms），服务端本地应答通常是微秒级。
		const DWORD waitBudgetMs = 150;
		DWORD waitedMs = 0;
		for (;;) {
			DWORD avail0 = 0;
			if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail0, nullptr)) {
				break;   // 管道断了
			}
			if (avail0 > 0) {
				break;   // 有数据了，交给下面的循环读
			}
			if (waitedMs >= waitBudgetMs) {
				break;   // 等够了：对面没答（引擎正忙），本轮放弃，由下一拍重试
			}
			::Sleep(5);
			waitedMs += 5;
		}

		for (;;) {
			// ★ 用 Peek 的"可用字节数"决定读多少：有数据才 ReadFile，
			//   避免在一次 ReadFile 上阻塞（调用方在界面线程）。
			DWORD avail = 0;
			if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr)) {
				break;   // 管道断了
			}
			if (avail == 0) {
				// 数据读完了。但**只有**"该收的都收到了"才算正常结束；
				// 中途断流（对面还欠载荷行）也必须退出，否则死等。
				break;
			}

			DWORD got = 0;
			const BOOL okRead = ::ReadFile(pipe, buffer, sizeof(buffer), &got, nullptr);
			if (got > 0) {
				blob.append(buffer, got);
			}

			if (blob.size() >= hardLimit) {
				break;
			}

			// 状态行还没读完 ⇒ 继续（不拿"半行"去判 count）。
			const size_t firstNl = blob.find('\n');
			if (firstNl == std::string::npos) {
				if (!okRead && got == 0) { break; }   // 断了
				continue;
			}

			const std::string statusLine = blob.substr(0, firstNl);
			const std::vector<std::string> statusFields = SplitFields(statusLine);
			if (!statusFields.empty() && statusFields[0] == "ERR") {
				break;   // ERR 没有载荷行
			}

			size_t want = 0;
			for (size_t i = 1; i < statusFields.size(); ++i) {
				const std::string prefix = "count=";
				if (statusFields[i].compare(0, prefix.size(), prefix) == 0) {
					want = static_cast<size_t>(ToULong(statusFields[i].substr(prefix.size()), 0));
					break;
				}
			}
			// 状态行 + want 条载荷行 = want + 1 行。
			if (completeLines(blob) >= want + 1) {
				break;
			}
			if (!okRead && got == 0) {
				break;   // 对面提前关了：按已拿到的解析（解析器会判不足）
			}
		}
		::CloseHandle(pipe);

		if (blob.empty()) {
			result.Error = "引擎没有应答（可能正在退出）";
			return result;
		}

		if (!ParseResponse(blob, result.Reply)) {
			result.Error = "应答格式不对（协议不同步）";
			return result;
		}
		if (result.Reply.IsError) {
			result.Error = FindKeyed(result.Reply, "msg", std::string("引擎拒绝了该请求"));
			// ERR| 后面直接是说明文本（不是 key=value）时，取原始字段。
			if (result.Reply.Fields.size() > 1 && result.Error == "引擎拒绝了该请求") {
				result.Error = Unescape(result.Reply.Fields[1]);
			}
			return result;
		}

		result.Ok = true;
		return result;
	}

}  // namespace R3ShieldCoreCfgIpc

#endif  // R3SHIELDCORE_CFG_IPC_H
