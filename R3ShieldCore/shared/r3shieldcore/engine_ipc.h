// engine_ipc.h —— 「引擎进程（r3shieldcore-engine.exe）」⇄「界面进程（R3 ShieldCore.exe）」
//                之间的**加密管道协议**契约。
//
//   ────────────────────────────────────────────────────────────────
//   为什么要拆成两个进程（v89）
//   ────────────────────────────────────────────────────────────────
//   拆之前：引擎是 `r3shieldcore-lib.dll`，被主程序 `LoadLibrary` 进**同一个进程**，
//   12 个导出直接当函数指针调。好处是快，坏处是：
//     · 界面里任何一个绘制/布局 bug 崩掉，**防护跟着一起没了**；
//     · 引擎必须活在"有窗口、有 D3D/GL 上下文"的进程里，
//       而它真正需要的只是"管理员 + 一个会话管理器"。
//   ⇒ 现在：引擎是独立 exe（仍然 `LoadLibrary` 同一个 DLL，注入链路**零改动**），
//     界面只是它的客户端。界面关掉、甚至崩掉，引擎继续防护。
//
//   ⚠️ 一个关键事实（别被"分进程"吓到）：注入到目标进程里的 DLL
//      找会话管理器靠的是**共享内存 + 会话互斥体**（`R3ShieldCoreChannel`），
//      跟"谁 LoadLibrary 了 DLL"无关。所以把 `GlobalHookSessionStart`
//      搬到引擎 exe 里，被注入的进程照旧能找到它 —— **注入这一层不用改一行**。
//
//   ────────────────────────────────────────────────────────────────
//   为什么要加密（用户明确要求「加密沟通」）
//   ────────────────────────────────────────────────────────────────
//   同机低权限进程可以做的事比想象中多：
//     · 抢占/劫持管道实例（先建同名管道，等引擎来连）；
//     · 用 `DuplicateHandle` 从父进程继承句柄；
//     · 直接读管道里的明文 —— 事件里有完整路径、命令行、注册表键值。
//   所以这里做**两层**：
//     ① 管道 DACL 只给 `SYSTEM` + `Administrators`（连接层面就挡住）；
//     ② 每条消息 AES-256-GCM 加密 + 单调序号防重放（就算 ACL 被绕开也读不懂）。
//   ⇒ 只有"能读到主密钥"的进程才解得开，而主密钥是 DPAPI(LocalMachine) 封的，
//     只有 SYSTEM/Administrators 能解。两层是**独立的**，任一层失效都还有另一层。
//
//   ────────────────────────────────────────────────────────────────
//   线格式
//   ────────────────────────────────────────────────────────────────
//   握手（明文，但只有 32 字节随机数，不含任何敏感内容）：
//       客户端 → `HELLO|<protoVer>|<abiVer>|<sizeof(Event)>|<clientNonceHex 64 字符>`
//       服务端 → `WELCOME|<protoVer>|<abiVer>|<sizeof(Event)>|<enginePid>|<serverNonceHex>`
//       失败   → `ERR|<说明>`
//   ★ 为什么要把 abi 和 sizeof(Event) 也带上：32 位界面连 64 位引擎、
//     或者装了两份不同代的产物时，事件结构体会**错位**。那种错位不会崩，
//     只会让日志内容全变成乱码路径 —— 最难查的一类。所以**握手期就拒绝**。
//   会话密钥 = HKDF-SHA256(masterKey, salt=clientNonce||serverNonce, info="r3sc-engine-v1")
//   ★ 每连接一把新密钥 ⇒ 昨天的抓包今天解不开；重放旧帧会因 seq 回退被拒。
//
//   之后每条消息是一个**二进制帧**（全加密）：
//       [u32 totalLen]                 ← 明文的只有这 4 字节（分帧用），它进 AAD
//       [u8  type][u32 seq]            ← 也进 AAD（防篡改类型/序号）
//       [12B iv][ciphertext][16B tag]
//   ★ AAD = totalLen || type || seq ⇒ 攻击者改任何一个字节，GCM 校验必失败。
//
//   本头只依赖 Win32 + BCrypt + STL，两个 exe 都能直接 `#include`（不需要链项目库）。
#pragma once
#ifndef R3SHIELDCORE_ENGINE_IPC_H
#define R3SHIELDCORE_ENGINE_IPC_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
// DATA_BLOB / CryptProtectData（主密钥封存）
#include <wincrypt.h>
// SetEntriesInAclW（管道 DACL）
#include <aclapi.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <r3shieldcore/r3shieldcore_shared.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace R3ShieldCoreEngineIpc
{
	// ---------------------------------------------------------------------
	// 代次标记
	// ---------------------------------------------------------------------
	// ★ 这个宽串**必须被两侧各引用一次**（引擎打印、界面打印），否则
	//   `inline constexpr` 会被链接器当死代码丢掉，发布闸门查不到它。
	//   v83/v85 都踩过同一个坑（闸门 FAIL 或恒 PASS）。
	inline constexpr wchar_t kMarker[] = L"R3ShieldCoreEngineIpc.v89";

	// 协议版本。两侧对不上就**明说**（ERR 里带双方版本），不做"尽力兼容"。
	// v1：首版（HELLO/WELCOME + 加密帧 + EVENTS 推送）。
	constexpr int kProtocolVersion = 1;

	// 管道名前缀。**完整名 = 前缀 + 会话号**（同 cfg_ipc 的理由：
	// 多登录会话下 `Local\` 会撞名，后连的可能连到别人的引擎）。
	constexpr wchar_t kPipeNamePrefix[] = L"\\\\.\\pipe\\R3ShieldCoreEngineIpc";

	// 引擎单实例互斥体（带会话号）。
	constexpr wchar_t kEngineMutexPrefix[] = L"Local\\R3ShieldCoreEngine.";

	// 单帧上限。事件批量帧会大一些，给 8MB（正常 100ms 一批远小于它）。
	// 超限一律断开 —— 而不是"截断继续"，截断会让后续帧边界全错。
	constexpr uint32_t kMaxFrameBytes = 8u * 1024u * 1024u;

	// 握手行的上限。
	constexpr size_t kMaxHandshakeBytes = 256;

	// GCM 参数（NIST 推荐：AES-256 + 96-bit IV + 128-bit tag）。
	constexpr size_t kKeyBytes = 32;
	constexpr size_t kIvBytes = 12;
	constexpr size_t kTagBytes = 16;

	// ---------------------------------------------------------------------
	// 消息类型
	// ---------------------------------------------------------------------
	enum class Msg : uint8_t
	{
		// —— 界面 → 引擎（请求）——
		Ping = 1,        // 空载荷 → Pong
		SetMode = 2,     // u32 mode → Ok(u8 ok)
		ReadStats = 3,   // 空 → Stats 结构
		RiskCheck = 4,   // u32 pathChars, WCHAR[] imagePath, u32 rootChars, WCHAR[] systemRoot
		                 //   → Ok(u8 hasReason) [+ u32 len + UTF-8 原因]
		SelfExit = 5,    // u32 pid → Ok(u8 started)
		StopEngine = 6,  // 空 → Ok（引擎收尾并退出）
		ShutdownAck = 7, // 引擎 → 界面：我要走了（先推这一帧，再断管道）

		// —— 引擎 → 界面（推送/应答）——
		Pong = 64,
		Ok = 65,         // u8 code（0=成功）
		Err = 66,        // u32 len + UTF-8 说明
		Events = 67,     // 事件批量帧（见 EncodeEvents）
		Stats = 68,      // 计数器快照
	};

	// 引擎推送的计数器快照。字段顺序即线上顺序（**只追加，不改前面**）。
	struct StatsPayload
	{
		uint32_t droppedEvents = 0;  // 累计丢弃
		uint32_t promptShown = 0;
		uint32_t promptAllowed = 0;
		uint32_t promptDenied = 0;
		uint32_t promptTimedOut = 0;
		uint32_t highRiskAsked = 0;
		uint32_t highRiskBlocked = 0;
		uint32_t injectedTotal = 0;  // 累计注入进程数（引擎自己数）
		uint32_t mode = 0;           // 引擎当前生效的 mode（界面用来纠偏）
		uint32_t enginePid = 0;
	};
	constexpr size_t kStatsPayloadBytes = 10 * 4;

	inline void HexEncode(const BYTE* data, size_t len, std::string& out)
	{
		static const char* kHex = "0123456789abcdef";
		out.clear();
		out.reserve(len * 2);
		for (size_t i = 0; i < len; ++i) {
			out.push_back(kHex[data[i] >> 4]);
			out.push_back(kHex[data[i] & 0x0F]);
		}
	}

	inline bool HexDecode(const std::string& hex, BYTE* out, size_t outLen)
	{
		if (hex.size() != outLen * 2) {
			return false;
		}
		auto nib = [](char c) -> int {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			return -1;
		};
		for (size_t i = 0; i < outLen; ++i) {
			const int hi = nib(hex[i * 2]);
			const int lo = nib(hex[i * 2 + 1]);
			if (hi < 0 || lo < 0) {
				return false;
			}
			out[i] = static_cast<BYTE>((hi << 4) | lo);
		}
		return true;
	}

	// ---------------------------------------------------------------------
	// 握手文法的唯一实现（两侧都调这里，别各写一份 —— 铁律 127）
	// ---------------------------------------------------------------------
	inline std::string MakeHello(const BYTE clientNonce[32])
	{
		std::string hex;
		HexEncode(clientNonce, 32, hex);
		char head[128];
		_snprintf_s(head, _countof(head), _TRUNCATE, "HELLO|%d|%lu|%zu|",
			kProtocolVersion, static_cast<unsigned long>(R3ShieldCore::AbiVersion),
			sizeof(R3ShieldCore::Event));
		return std::string(head) + hex;
	}

	struct HelloInfo
	{
		int protocolVersion = 0;
		uint32_t abiVersion = 0;
		uint32_t eventBytes = 0;
		BYTE nonce[32] = {};
	};

	// 按 `|` 切分（握手行里没有自由文本，不需要转义）。
	inline void SplitFields(const std::string& line, std::vector<std::string>& out)
	{
		out.clear();
		size_t start = 0;
		while (true) {
			const size_t bar = line.find('|', start);
			if (bar == std::string::npos) {
				out.push_back(line.substr(start));
				break;
			}
			out.push_back(line.substr(start, bar - start));
			start = bar + 1;
		}
	}

	inline bool ParseHello(const std::string& line, HelloInfo& out)
	{
		std::vector<std::string> f;
		SplitFields(line, f);
		if (f.size() != 5 || f[0] != "HELLO") {
			return false;
		}
		out.protocolVersion = atoi(f[1].c_str());
		out.abiVersion = static_cast<uint32_t>(strtoul(f[2].c_str(), nullptr, 10));
		out.eventBytes = static_cast<uint32_t>(strtoul(f[3].c_str(), nullptr, 10));
		return HexDecode(f[4], out.nonce, 32);
	}

	inline std::string MakeWelcome(const BYTE serverNonce[32], uint32_t enginePid)
	{
		std::string hex;
		HexEncode(serverNonce, 32, hex);
		char head[128];
		_snprintf_s(head, _countof(head), _TRUNCATE, "WELCOME|%d|%lu|%zu|%lu|",
			kProtocolVersion, static_cast<unsigned long>(R3ShieldCore::AbiVersion),
			sizeof(R3ShieldCore::Event), static_cast<unsigned long>(enginePid));
		return std::string(head) + hex;
	}

	struct WelcomeInfo
	{
		int protocolVersion = 0;
		uint32_t abiVersion = 0;
		uint32_t eventBytes = 0;
		uint32_t enginePid = 0;
		BYTE nonce[32] = {};
	};

	inline bool ParseWelcome(const std::string& line, WelcomeInfo& out)
	{
		std::vector<std::string> f;
		SplitFields(line, f);
		if (f.size() != 6 || f[0] != "WELCOME") {
			return false;
		}
		out.protocolVersion = atoi(f[1].c_str());
		out.abiVersion = static_cast<uint32_t>(strtoul(f[2].c_str(), nullptr, 10));
		out.eventBytes = static_cast<uint32_t>(strtoul(f[3].c_str(), nullptr, 10));
		out.enginePid = static_cast<uint32_t>(strtoul(f[4].c_str(), nullptr, 10));
		return HexDecode(f[5], out.nonce, 32);
	}

	// 两侧共用的"能不能谈"判定。返回空串 = 可以；否则是给人看的原因。
	inline std::wstring CheckPeerCompatible(int proto, uint32_t abi, uint32_t eventBytes)
	{
		wchar_t b[256];
		if (proto != kProtocolVersion) {
			_snwprintf_s(b, _countof(b), _TRUNCATE,
				L"协议版本不一致（本端 %d / 对端 %d）", kProtocolVersion, proto);
			return b;
		}
		if (abi != static_cast<uint32_t>(R3ShieldCore::AbiVersion)) {
			_snwprintf_s(b, _countof(b), _TRUNCATE,
				L"引擎 ABI 版本不一致（本端 %lu / 对端 %lu）—— 两边的 exe/dll 不是同一代产物",
				static_cast<unsigned long>(R3ShieldCore::AbiVersion),
				static_cast<unsigned long>(abi));
			return b;
		}
		if (eventBytes != sizeof(R3ShieldCore::Event)) {
			_snwprintf_s(b, _countof(b), _TRUNCATE,
				L"事件结构体大小不一致（本端 %zu / 对端 %lu）—— 大概率 32/64 位混用",
				sizeof(R3ShieldCore::Event), static_cast<unsigned long>(eventBytes));
			return b;
		}
		return L"";
	}

	// ---------------------------------------------------------------------
	// 小工具
	// ---------------------------------------------------------------------
	// 会话号 → 管道名。两侧算出来必然一样（同一会话里的进程）。
	inline std::wstring PipeName()
	{
		DWORD sessionId = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			sessionId = 0;
		}
		wchar_t buf[128];
		_snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%s%lu", kPipeNamePrefix,
			static_cast<unsigned long>(sessionId));
		return buf;
	}

	inline std::wstring EngineMutexName()
	{
		DWORD sessionId = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			sessionId = 0;
		}
		wchar_t buf[128];
		_snwprintf_s(buf, _countof(buf), _TRUNCATE, L"%s%lu", kEngineMutexPrefix,
			static_cast<unsigned long>(sessionId));
		return buf;
	}

	// 主密钥文件路径：`%ProgramData%\R3 Shield Core\r3shieldcore-engine.key`
	// ★ 放在 ProgramData 而不是 exe 旁边：exe 目录是**用户可写**的
	//   （v57 明确接受了这一点，见 engine_control.cpp 的头注释），
	//   把密钥放在可写目录里等于把钥匙挂在门上。
	inline std::wstring MasterKeyPath()
	{
		wchar_t programData[MAX_PATH] = {};
		DWORD n = GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
		if (n == 0 || n >= MAX_PATH) {
			return L"";
		}
		std::wstring dir = programData;
		dir += L"\\R3 Shield Core";
		CreateDirectoryW(dir.c_str(), nullptr);   // 已存在时返回 FALSE，正常
		dir += L"\\r3shieldcore-engine.key";
		return dir;
	}

	// ---------------------------------------------------------------------
	// 主密钥：DPAPI(LocalMachine) 封存的 32 字节随机数
	// ---------------------------------------------------------------------
	// ★ 为什么用 LocalMachine 而不是 CurrentUser：引擎是**提权**跑的，
	//   而界面也是提权的，两者用户上下文可能不同（UIAccess/服务接管场景）。
	//   CurrentUser 封的密钥换个上下文就解不开 —— 表现为"握手一直 ERR"。
	inline bool EnsureMasterKey(BYTE outKey[kKeyBytes], bool createIfMissing,
		std::wstring* errOut = nullptr)
	{
		const std::wstring path = MasterKeyPath();
		if (path.empty()) {
			if (errOut) *errOut = L"取不到 %ProgramData% 路径";
			return false;
		}

		HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			const DWORD openErr = GetLastError();
			if (!createIfMissing) {
				if (errOut) {
					wchar_t b[160];
					_snwprintf_s(b, _countof(b), _TRUNCATE,
						L"主密钥不存在（err=%lu）", static_cast<unsigned long>(openErr));
					*errOut = b;
				}
				return false;
			}

			// —— 生成 ——
			BYTE raw[kKeyBytes] = {};
			if (!NT_SUCCESS(BCryptGenRandom(nullptr, raw, kKeyBytes,
				BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
				if (errOut) *errOut = L"BCryptGenRandom 失败";
				return false;
			}

			DATA_BLOB plain = { kKeyBytes, raw };
			DATA_BLOB sealed = {};
			if (!CryptProtectData(&plain, L"R3ShieldCore engine master key", nullptr, nullptr,
				nullptr, CRYPTPROTECT_LOCAL_MACHINE, &sealed)) {
				if (errOut) {
					wchar_t b[160];
					_snwprintf_s(b, _countof(b), _TRUNCATE,
						L"CryptProtectData 失败（err=%lu）",
						static_cast<unsigned long>(GetLastError()));
					*errOut = b;
				}
				SecureZeroMemory(raw, sizeof(raw));
				return false;
			}

			file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
				CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
			DWORD written = 0;
			const bool ok = file != INVALID_HANDLE_VALUE
				&& WriteFile(file, sealed.pbData, sealed.cbData, &written, nullptr)
				&& written == sealed.cbData;
			if (file != INVALID_HANDLE_VALUE) {
				CloseHandle(file);
			}
			LocalFree(sealed.pbData);
			SecureZeroMemory(raw, sizeof(raw));
			if (!ok) {
				if (errOut) *errOut = L"写主密钥文件失败";
				return false;
			}

			// 生成完立刻按"只读回"走一遍，确保能解开（写坏了要马上知道）。
			file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (file == INVALID_HANDLE_VALUE) {
				if (errOut) *errOut = L"主密钥写入后读不回来";
				return false;
			}
		}

		BYTE buf[512] = {};
		DWORD read = 0;
		const bool readOk = ReadFile(file, buf, sizeof(buf), &read, nullptr) && read > 0;
		CloseHandle(file);
		if (!readOk) {
			if (errOut) *errOut = L"读主密钥文件失败";
			return false;
		}

		DATA_BLOB sealed = { read, buf };
		DATA_BLOB plain = {};
		const BOOL unsealed = CryptUnprotectData(&sealed, nullptr, nullptr, nullptr, nullptr,
			CRYPTPROTECT_LOCAL_MACHINE, &plain);
		SecureZeroMemory(buf, sizeof(buf));
		if (!unsealed || plain.cbData != kKeyBytes) {
			if (plain.pbData) LocalFree(plain.pbData);
			if (errOut) {
				wchar_t b[160];
				_snwprintf_s(b, _countof(b), _TRUNCATE,
					L"CryptUnprotectData 失败或长度不是 32（实际 %lu）",
					static_cast<unsigned long>(plain.cbData));
				*errOut = b;
			}
			return false;
		}
		memcpy(outKey, plain.pbData, kKeyBytes);
		SecureZeroMemory(plain.pbData, plain.cbData);
		LocalFree(plain.pbData);
		return true;
	}

	// ---------------------------------------------------------------------
	// HMAC-SHA256 + HKDF（自己实现，不赌 `BCRYPT_HKDF_ALGORITHM` 的可用性）
	// ---------------------------------------------------------------------
	// ★ 为什么不直接用 `BCryptKeyDerivation` 的 HKDF：它在 Win10 才全量可用，
	//   而本项目的 32 位构建要在更老的机器上跑。HMAC-SHA256 是 XP 就有原语。
	inline bool HmacSha256(const BYTE* key, size_t keyLen,
		const BYTE* data1, size_t len1,
		const BYTE* data2, size_t len2,
		BYTE out[32])
	{
		BCRYPT_ALG_HANDLE alg = nullptr;
		if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
			nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
			return false;
		}
		BCRYPT_HASH_HANDLE hash = nullptr;
		bool ok = false;
		if (NT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0,
			const_cast<PUCHAR>(key), static_cast<ULONG>(keyLen), 0))) {
			ok = true;
			if (len1 && !NT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(data1),
				static_cast<ULONG>(len1), 0))) {
				ok = false;
			}
			if (ok && len2 && !NT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(data2),
				static_cast<ULONG>(len2), 0))) {
				ok = false;
			}
			if (ok && !NT_SUCCESS(BCryptFinishHash(hash, out, 32, 0))) {
				ok = false;
			}
			BCryptDestroyHash(hash);
		}
		BCryptCloseAlgorithmProvider(alg, 0);
		return ok;
	}

	// HKDF-SHA256（RFC 5869）。输出固定 32 字节 —— 本协议只需要一把 AES-256 密钥。
	inline bool HkdfSha256(const BYTE prkInput[kKeyBytes],
		const BYTE* salt, size_t saltLen,
		const char* info, size_t infoLen,
		BYTE out[32])
	{
		BYTE prk[32] = {};
		if (!HmacSha256(salt, saltLen, prkInput, kKeyBytes, nullptr, 0, prk)) {
			return false;
		}
		// T(1) = HMAC(prk, info || 0x01)，32 字节正好够用
		BYTE tail = 0x01;
		BYTE tmp[64] = {};
		const size_t infoCopy = infoLen < 32 ? infoLen : 32;
		memcpy(tmp, info, infoCopy);
		tmp[infoCopy] = tail;
		const bool ok = HmacSha256(prk, sizeof(prk), tmp, infoCopy + 1, nullptr, 0, out);
		SecureZeroMemory(prk, sizeof(prk));
		SecureZeroMemory(tmp, sizeof(tmp));
		return ok;
	}

	// 会话密钥 = HKDF(master, salt = clientNonce||serverNonce, info = "r3sc-engine-v1")
	inline bool DeriveSessionKey(const BYTE master[kKeyBytes],
		const BYTE clientNonce[32], const BYTE serverNonce[32],
		BYTE out[kKeyBytes])
	{
		BYTE salt[64] = {};
		memcpy(salt, clientNonce, 32);
		memcpy(salt + 32, serverNonce, 32);
		static const char kInfo[] = "r3sc-engine-v1";
		const bool ok = HkdfSha256(master, salt, sizeof(salt), kInfo, sizeof(kInfo) - 1, out);
		SecureZeroMemory(salt, sizeof(salt));
		return ok;
	}

	// ---------------------------------------------------------------------
	// 密钥指纹（**单向**，可安全写日志）
	// ---------------------------------------------------------------------
	// 用来回答一个具体问题：「两端派生的到底是不是同一把会话密钥？」
	//
	// 为什么需要它：密钥不一致的症状只有一句"解密/验签失败"，而可能的
	// 成因有四五种（主密钥文件没读到 / DPAPI 解不开 / nonce 传错 /
	// HKDF 参数不一致 / 一边拿了默认零值）。没有指纹就只能逐个试。
	// 指纹是 `SHA-256(key)` 的前 8 字节 —— 泄不出密钥，但两端一比对
	// 立刻能区分"密钥不同"和"密钥相同但帧坏了"。
	inline std::string KeyFingerprint(const BYTE key[kKeyBytes])
	{
		BYTE digest[32] = {};
		BCRYPT_ALG_HANDLE alg = nullptr;
		if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
			nullptr, 0))) {
			return std::string("????????");
		}
		BCRYPT_HASH_HANDLE hash = nullptr;
		std::string out = "????????";
		if (NT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
			if (NT_SUCCESS(BCryptHashData(hash, const_cast<PUCHAR>(key),
				static_cast<ULONG>(kKeyBytes), 0))
				&& NT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0))) {
				HexEncode(digest, 8, out);
			}
			BCryptDestroyHash(hash);
		}
		BCryptCloseAlgorithmProvider(alg, 0);
		SecureZeroMemory(digest, sizeof(digest));
		return out;
	}

	// ---------------------------------------------------------------------
	// AES-256-GCM
	// ---------------------------------------------------------------------
	// ★★ 明文**永远不为空**：`Seal` 会在明文前面加 1 个填充字节，`Open` 再剥掉。
	//
	//   为什么非加不可（这是本项目最重要的一条密码学教训）：
	//   CNG 的 AES-GCM 在**零长度明文**上**根本不校验 tag** ——
	//   `BCryptDecrypt(cbInput = 0)` 直接返回 `STATUS_SUCCESS`，
	//   密钥是错的也照样"解密成功"。
	//   而本协议里 `Ping` / `ReadStats` / `StopEngine` **全都是零长度载荷**
	//   ⇒ 任何人拿一把乱密钥（甚至随手 32 个字节）都能：
	//       · 让引擎回 Pong（看起来"加密通道正常"）
	//       · **发 StopEngine 把防护叫停**
	//   而同一把错密钥发 4 字节的 `SetMode` 就会被拒 —— 两种结果并存，
	//   极难联想到"载荷长度"这个变量上。
	//   （2026-10-23 由 `--neg` 反向对照抓到：空载荷被接受、有载荷被拒。）
	//
	//   ⇒ 加 1 字节填充后，GCM 每次都有输入，tag 必然被校验。
	//     填充值本身也检查一次（双保险：万一哪天 CNG 行为再变，这里会先炸）。
	constexpr size_t kPadBytes = 1;
	constexpr BYTE kPadByte = 0x52;   // 'R'

	class Aead
	{
	public:
		Aead() = default;
		~Aead() { Reset(); }
		Aead(const Aead&) = delete;
		Aead& operator=(const Aead&) = delete;

		bool Init(const BYTE key[kKeyBytes])
		{
			Reset();
			if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_, BCRYPT_AES_ALGORITHM,
				nullptr, 0))) {
				return false;
			}
			// 必须显式设成 GCM —— 默认是 CBC，设失败会**静默**按 CBC 跑
			// （然后 tag 校验永远失败，看起来像"密钥不对"）。
			if (!NT_SUCCESS(BCryptSetProperty(alg_, BCRYPT_CHAINING_MODE,
				reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
				sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
				Reset();
				return false;
			}
			keyObjectLen_ = 0;
			ULONG got = 0;
			if (!NT_SUCCESS(BCryptGetProperty(alg_, BCRYPT_OBJECT_LENGTH,
				reinterpret_cast<PUCHAR>(&keyObjectLen_), sizeof(keyObjectLen_), &got, 0))) {
				Reset();
				return false;
			}
			keyObject_.assign(keyObjectLen_, 0);
			if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg_, &key_, keyObject_.data(),
				keyObjectLen_, const_cast<PUCHAR>(key), static_cast<ULONG>(kKeyBytes), 0))) {
				Reset();
				return false;
			}
			ready_ = true;
			return true;
		}

		bool Ready() const { return ready_; }

		// 加密：out = ciphertext || tag
		//   长度 = (plainLen + kPadBytes) + kTagBytes
		bool Seal(const BYTE iv[kIvBytes], const void* aad, size_t aadLen,
			const void* plain, size_t plainLen, std::vector<BYTE>& out) const
		{
			if (!ready_) {
				return false;
			}
			const size_t ctLen = plainLen + kPadBytes;
			out.assign(ctLen + kTagBytes, 0);

			// 填充 + 明文（填充在最前面，Open 按同一规则剥掉）
			std::vector<BYTE> padded(ctLen, 0);
			padded[0] = kPadByte;
			if (plainLen) {
				memcpy(padded.data() + kPadBytes, plain, plainLen);
			}

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = const_cast<PUCHAR>(iv);
			info.cbNonce = static_cast<ULONG>(kIvBytes);
			info.pbAuthData = const_cast<PUCHAR>(static_cast<const BYTE*>(aad));
			info.cbAuthData = static_cast<ULONG>(aadLen);
			info.pbTag = out.data() + ctLen;
			info.cbTag = static_cast<ULONG>(kTagBytes);

			ULONG written = 0;
			const NTSTATUS st = BCryptEncrypt(key_, padded.data(),
				static_cast<ULONG>(ctLen), &info, nullptr, 0,
				out.data(), static_cast<ULONG>(ctLen), &written, 0);
			SecureZeroMemory(padded.data(), padded.size());
			return NT_SUCCESS(st) && written == ctLen;
		}

		// 解密：in = ciphertext || tag（ciphertext 长度 = 明文 + kPadBytes）
		//
		// ★★ 这里有一个**与 OpenSSL 相反**的坑，踩过一次：
		//   CNG 的 GCM 解密要求 `cbInput` **只算密文**，tag 通过 `pbTag`
		//   单独指（tag 仍可以物理地紧跟在密文后面，但**不能**计入 cbInput）。
		//   按 OpenSSL 的习惯传 `cbInput = 密文+tag` 会得到
		//     · 输出缓冲正好给 plainLen ⇒ `0xC0000023`(BUFFER_TOO_SMALL)
		//     · 输出缓冲给大一点     ⇒ `0xC000A002`(AUTH_TAG_MISMATCH)
		//   —— 明明加解密用的是同一把密钥、同一个 IV，tag 就是验不过。
		//   症状是"能连上、发一帧就被断开"，极易误判成密钥派生错了。
		//   （2026-10-23 用 NIST 向量定位：加密侧完全正确，只有解密侧错。）
		bool Open(const BYTE iv[kIvBytes], const void* aad, size_t aadLen,
			const void* in, size_t inLen, std::vector<BYTE>& out) const
		{
			if (!ready_ || inLen < kPadBytes + kTagBytes) {
				return false;
			}
			const size_t ctLen = inLen - kTagBytes;
			std::vector<BYTE> padded(ctLen, 0);

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = const_cast<PUCHAR>(iv);
			info.cbNonce = static_cast<ULONG>(kIvBytes);
			info.pbAuthData = const_cast<PUCHAR>(static_cast<const BYTE*>(aad));
			info.cbAuthData = static_cast<ULONG>(aadLen);
			info.pbTag = const_cast<PUCHAR>(static_cast<const BYTE*>(in)) + ctLen;
			info.cbTag = static_cast<ULONG>(kTagBytes);

			ULONG written = 0;
			const NTSTATUS st = BCryptDecrypt(key_,
				const_cast<PUCHAR>(static_cast<const BYTE*>(in)),
				static_cast<ULONG>(ctLen),   // ← 只算密文，**不含 tag**
				&info, nullptr, 0,
				padded.data(), static_cast<ULONG>(ctLen), &written, 0);
			if (!NT_SUCCESS(st) || written != ctLen) {
				SecureZeroMemory(padded.data(), padded.size());
				out.clear();
				return false;
			}
			if (padded[0] != kPadByte) {
				// 到这一步说明 tag 过了但填充不对 —— 只可能是两端协议不一致。
				SecureZeroMemory(padded.data(), padded.size());
				out.clear();
				return false;
			}
			out.assign(padded.begin() + static_cast<long>(kPadBytes), padded.end());
			SecureZeroMemory(padded.data(), padded.size());
			return true;
		}

		void Reset()
		{
			if (key_) {
				BCryptDestroyKey(key_);
				key_ = nullptr;
			}
			if (alg_) {
				BCryptCloseAlgorithmProvider(alg_, 0);
				alg_ = nullptr;
			}
			keyObject_.clear();
			ready_ = false;
		}

	private:
		BCRYPT_ALG_HANDLE alg_ = nullptr;
		BCRYPT_KEY_HANDLE key_ = nullptr;
		std::vector<BYTE> keyObject_;
		ULONG keyObjectLen_ = 0;
		bool ready_ = false;
	};

	// ---------------------------------------------------------------------
	// 帧读写
	// ---------------------------------------------------------------------
	// ★★ 这两个函数是本协议最容易踩坑的地方：
	//   ① `ReadFile` **可以少读**（管道消息模式下更常见）⇒ 必须循环读满，
	//      否则把半帧当整帧，后续所有帧边界全错（症状：连上了、能收几条、
	//      然后突然全是乱码，看起来像"密钥漂了"）。
	//   ② `WriteFile` 同理可能只写一半。
	// ---------------------------------------------------------------------
	// 同步读写（读满/写满）
	// ---------------------------------------------------------------------
	// ★★ 必须走 OVERLAPPED + GetOverlappedResult，**不能**传
	//   `lpOverlapped = NULL`：
	//   管道服务端是用 `FILE_FLAG_OVERLAPPED` 创建的（accept 循环要靠它
	//   每 200ms 轮询 g_stop）。对这种句柄传 NULL，MSDN 的原话是
	//   "the function can incorrectly report that the read operation is
	//   complete" —— 即 `ReadFile` 可能返回 TRUE 而 `got == 0`，
	//   或者返回 FALSE 且 GetLastError 是 `ERROR_IO_PENDING`。
	//   症状是**随机**的：握手能过、Ping/Pong 能过，然后某一帧开始
	//   "读帧头失败"，两端互相说"对端已断开"，日志里没有任何有用信息。
	//   （2026-10-23 实测踩到，靠给 `FrameReader` 加失败原因才定位到。）
	//
	//   ★ 传一个栈上的 OVERLAPPED 给**同步**句柄是安全的（管道忽略 Offset），
	//     所以这段代码对"客户端忘了加 FILE_FLAG_OVERLAPPED"也成立。
	inline bool ReadExact(HANDLE h, void* buf, size_t len)
	{
		BYTE* p = static_cast<BYTE*>(buf);
		size_t done = 0;
		while (done < len) {
			OVERLAPPED ov = {};
			ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			if (!ov.hEvent) {
				return false;
			}
			DWORD got = 0;
			const BOOL ok = ReadFile(h, p + done, static_cast<DWORD>(len - done), &got, &ov);
			if (!ok) {
				const DWORD e = GetLastError();
				if (e != ERROR_IO_PENDING
					|| !GetOverlappedResult(h, &ov, &got, TRUE)) {
					CloseHandle(ov.hEvent);
					return false;
				}
			}
			CloseHandle(ov.hEvent);
			if (got == 0) {
				return false;
			}
			done += got;
		}
		return true;
	}

	inline bool WriteExact(HANDLE h, const void* buf, size_t len)
	{
		const BYTE* p = static_cast<const BYTE*>(buf);
		size_t done = 0;
		while (done < len) {
			OVERLAPPED ov = {};
			ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			if (!ov.hEvent) {
				return false;
			}
			DWORD wrote = 0;
			const BOOL ok = WriteFile(h, p + done, static_cast<DWORD>(len - done), &wrote, &ov);
			if (!ok) {
				const DWORD e = GetLastError();
				if (e != ERROR_IO_PENDING
					|| !GetOverlappedResult(h, &ov, &wrote, TRUE)) {
					CloseHandle(ov.hEvent);
					return false;
				}
			}
			CloseHandle(ov.hEvent);
			if (wrote == 0) {
				return false;
			}
			done += wrote;
		}
		return true;
	}

	inline bool WriteLine(HANDLE h, const std::string& line)
	{
		if (!WriteExact(h, line.data(), line.size())) {
			return false;
		}
		const char nl = '\n';
		return WriteExact(h, &nl, 1);
	}

	// 读一行（到 '\n' 为止，不含 '\n'）。超过上限返回 false。
	inline bool ReadLine(HANDLE h, std::string& out, size_t maxBytes)
	{
		out.clear();
		char c = 0;
		while (out.size() < maxBytes) {
			if (!ReadExact(h, &c, 1)) {
				return false;
			}
			if (c == '\n') {
				return true;
			}
			if (c != '\r') {
				out.push_back(c);
			}
		}
		return false;
	}

	// 帧头：totalLen(4) | type(1) | seq(4)
	// totalLen = 4 + 1 + 4 + 12 + plainLen + 16（含自己）
	constexpr size_t kFrameHeaderBytes = 9;

	struct FrameWriter
	{
		// 单调递增的 seq（每条消息 +1）。防重放靠它。
		uint32_t seq = 1;

		bool Write(HANDLE h, const Aead& aead, Msg type,
			const void* payload, size_t payloadLen)
		{
			if (!aead.Ready()) {
				return false;
			}
			const uint32_t mySeq = seq++;
			// ★ +kPadBytes：`Aead::Seal` 会在明文前加 1 字节填充（见那里的长注释），
			//   密文因此比 payload 长 1。这里算 total 时必须算上，否则对端
			//   按 total 切帧会少读一个字节 ⇒ 帧边界错位。
			const uint32_t total = static_cast<uint32_t>(
				kFrameHeaderBytes + kIvBytes + kPadBytes + payloadLen + kTagBytes);
			if (total > kMaxFrameBytes) {
				return false;
			}

			BYTE header[kFrameHeaderBytes];
			memcpy(header, &total, 4);
			header[4] = static_cast<BYTE>(type);
			memcpy(header + 5, &mySeq, 4);

			BYTE iv[kIvBytes] = {};
			if (!NT_SUCCESS(BCryptGenRandom(nullptr, iv, kIvBytes,
				BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
				return false;
			}

			std::vector<BYTE> sealed;
			// AAD = header（含 totalLen / type / seq）⇒ 改任何一个字节都验不过
			if (!aead.Seal(iv, header, sizeof(header), payload, payloadLen, sealed)) {
				return false;
			}

			if (!WriteExact(h, header, sizeof(header))) {
				return false;
			}
			if (!WriteExact(h, iv, sizeof(iv))) {
				return false;
			}
			return WriteExact(h, sealed.data(), sealed.size());
		}
	};

	struct FrameReader
	{
		// 已接受的最大 seq。新帧的 seq 必须**严格大于**它，否则视为重放。
		uint32_t lastSeq = 0;

		// `why`（可选）：失败原因。★ 一定要有 —— "连接断了"这四个字在排查时
		// 等于没说：是读不到头、还是解密验签失败、还是 seq 被判成重放，
		// 三者下一步动作完全不同（查网络 / 查密钥 / 查两端是不是同一份协议）。
		// ★ 用 `std::wstring` 而不是 `std::string`：窄字面量会按**执行字符集**
		//   （默认 CP936）编成 GBK 字节，再经 `%hs` 打印时 CRT 按 C locale
		//   当 ASCII 转宽 ⇒ 中文全成乱码（"¶ÁÖ¡Í·"）。宽串没有这一步转换。
		bool Read(HANDLE h, const Aead& aead, Msg& type, std::vector<BYTE>& payload,
			std::wstring* why = nullptr)
		{
			auto bad = [&](const wchar_t* reason) {
				if (why) {
					*why = reason;
				}
				return false;
			};

			payload.clear();
			if (!aead.Ready()) {
				return bad(L"AEAD 未就绪");
			}

			BYTE header[kFrameHeaderBytes];
			if (!ReadExact(h, header, sizeof(header))) {
				return bad(L"读帧头失败（对端已断开？）");
			}
			uint32_t total = 0;
			memcpy(&total, header, 4);
			if (total < kFrameHeaderBytes + kIvBytes + kPadBytes + kTagBytes
				|| total > kMaxFrameBytes) {
				return bad(L"帧长越界（帧边界已错位）");
			}
			uint32_t seq = 0;
			memcpy(&seq, header + 5, 4);
			if (seq <= lastSeq) {
				return bad(L"seq 未单调递增（重放/乱序）");
			}

			BYTE iv[kIvBytes] = {};
			if (!ReadExact(h, iv, sizeof(iv))) {
				return bad(L"读 IV 失败");
			}
			const size_t sealedLen = total - kFrameHeaderBytes - kIvBytes;
			std::vector<BYTE> sealed(sealedLen);
			if (!ReadExact(h, sealed.data(), sealedLen)) {
				return bad(L"读密文失败");
			}
			if (!aead.Open(iv, header, sizeof(header), sealed.data(), sealed.size(), payload)) {
				return bad(L"解密/验签失败（两端会话密钥不一致？）");
			}

			lastSeq = seq;
			type = static_cast<Msg>(header[4]);
			return true;
		}
	};

	// ---------------------------------------------------------------------
	// 事件批量编解码
	// ---------------------------------------------------------------------
	// ★ 为什么不直接 `memcpy(sizeof(Event))`：Event 里嵌了
	//   `KeyPath[MaxKeyPathChars]` / `DllPath[MaxImagePathChars]` / `CommandLine[512]`
	//   这些定长宽字符数组，sizeof 在 3~4KB 量级。而一条普通注册表事件的
	//   实际内容只有一两百字节 —— 全量发等于把带宽放大 20 倍
	//   （BLOCK_ALL 模式下 100ms 上千条 = 每秒几十 MB，加密和管道都吃不住）。
	//   ⇒ 只发**实际用到的长度**，接收端清零后按长度回填。
	//
	//   线格式（一条事件）：
	//       u32 固定区字节数（= sizeof(Event) 的头部部分，见下）
	//       固定区（不含四个宽字符数组）
	//       u32 keyPathChars + WCHAR[]
	//       u32 valueNameChars + WCHAR[]
	//       u32 localAddressChars + WCHAR[]
	//       u32 dllPathChars + WCHAR[]
	//       u32 commandLineChars + WCHAR[]
	constexpr size_t kEventFixedBytes =
		offsetof(R3ShieldCore::Event, KeyPath);

	inline void AppendU32(std::vector<BYTE>& out, uint32_t v)
	{
		const BYTE* p = reinterpret_cast<const BYTE*>(&v);
		out.insert(out.end(), p, p + 4);
	}

	inline void AppendWChars(std::vector<BYTE>& out, const WCHAR* s, size_t maxChars)
	{
		size_t n = 0;
		while (n < maxChars && s[n]) {
			++n;
		}
		AppendU32(out, static_cast<uint32_t>(n));
		if (n) {
			const BYTE* p = reinterpret_cast<const BYTE*>(s);
			out.insert(out.end(), p, p + n * sizeof(WCHAR));
		}
	}

	inline bool ReadU32(const BYTE*& p, const BYTE* end, uint32_t& v)
	{
		if (p + 4 > end) return false;
		memcpy(&v, p, 4);
		p += 4;
		return true;
	}

	inline bool ReadWChars(const BYTE*& p, const BYTE* end, WCHAR* dst, size_t maxChars)
	{
		uint32_t n = 0;
		if (!ReadU32(p, end, n)) return false;
		if (n > maxChars) return false;
		if (n) {
			if (p + n * sizeof(WCHAR) > end) return false;
			memcpy(dst, p, n * sizeof(WCHAR));
			p += n * sizeof(WCHAR);
		}
		dst[n < maxChars ? n : maxChars - 1] = 0;
		return true;
	}

	inline void EncodeEvents(const R3ShieldCore::Event* events, int count,
		std::vector<BYTE>& out)
	{
		out.clear();
		if (count <= 0) {
			AppendU32(out, 0);
			return;
		}
		AppendU32(out, static_cast<uint32_t>(count));
		for (int i = 0; i < count; ++i) {
			const R3ShieldCore::Event& e = events[i];
			// 固定区：从结构体开头到 KeyPath 之前的全部字段
			// （Sequence/ObjectType/.../CreatorProcessId），一次性拷过去。
			// ★ 这段里全是定长整数，没有指针 ⇒ 跨进程 memcpy 是安全的。
			const BYTE* fixedSrc = reinterpret_cast<const BYTE*>(&e);
			out.insert(out.end(), fixedSrc, fixedSrc + kEventFixedBytes);

			AppendWChars(out, e.KeyPath, R3ShieldCore::MaxKeyPathChars);
			AppendWChars(out, e.ValueName, R3ShieldCore::MaxValueNameChars);

			// 网络段：TargetPort / NetProtocol / LocalPort 三个整数 + LocalAddress
			// ★ 它们在结构体里**夹在** KeyPath 和 DllPath 之间，不能跟着固定区走。
			AppendU32(out, e.TargetPort);
			AppendU32(out, e.NetProtocol);
			AppendU32(out, e.LocalPort);
			AppendWChars(out, e.LocalAddress, 64);

			AppendWChars(out, e.DllPath, R3ShieldCore::MaxImagePathChars);
			AppendWChars(out, e.CommandLine, 512);
			AppendU32(out, e.Flags2);
		}
	}

	inline bool DecodeEvents(const BYTE* data, size_t len,
		std::vector<R3ShieldCore::Event>& out)
	{
		out.clear();
		const BYTE* p = data;
		const BYTE* end = data + len;
		uint32_t count = 0;
		if (!ReadU32(p, end, count)) {
			return false;
		}
		if (count > 100000) {
			return false;   // 防御：坏帧不要试图分配
		}
		out.resize(count);
		for (uint32_t i = 0; i < count; ++i) {
			R3ShieldCore::Event& e = out[i];
			ZeroMemory(&e, sizeof(e));
			if (p + kEventFixedBytes > end) {
				return false;
			}
			memcpy(&e, p, kEventFixedBytes);
			p += kEventFixedBytes;

			if (!ReadWChars(p, end, e.KeyPath, R3ShieldCore::MaxKeyPathChars)) return false;
			if (!ReadWChars(p, end, e.ValueName, R3ShieldCore::MaxValueNameChars)) return false;

			// ★ 这几个是 `ULONG`（unsigned long），而 ReadU32 收 `uint32_t&`
			//   （unsigned int）—— 同宽但**不同类型**，引用不能直接绑。
			//   过一手临时量，别为了省事改 Event 的字段类型（那是 ABI）。
			uint32_t u32 = 0;
			if (!ReadU32(p, end, u32)) return false; e.TargetPort = u32;
			if (!ReadU32(p, end, u32)) return false; e.NetProtocol = u32;
			if (!ReadU32(p, end, u32)) return false; e.LocalPort = u32;
			if (!ReadWChars(p, end, e.LocalAddress, 64)) return false;

			if (!ReadWChars(p, end, e.DllPath, R3ShieldCore::MaxImagePathChars)) return false;
			if (!ReadWChars(p, end, e.CommandLine, 512)) return false;
			if (!ReadU32(p, end, u32)) return false; e.Flags2 = u32;
		}
		return true;
	}

	// ---------------------------------------------------------------------
	// 管道安全属性：只给 SYSTEM + Administrators
	// ---------------------------------------------------------------------
	// ★ 必须**显式**授 DACL：命名管道的默认 DACL 只给"创建者 + 当前用户"，
	//   而引擎是提权进程、界面也是提权进程但可能在不同令牌上下文里 ——
	//   不显式授就会恒定 `ERROR_ACCESS_DENIED(5)`，且伪装成"引擎没跑"（v81 踩过）。
	inline bool BuildPipeSecurity(SECURITY_ATTRIBUTES& sa, PSECURITY_DESCRIPTOR& sd)
	{
		sd = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH));
		if (!sd) {
			return false;
		}
		if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)) {
			LocalFree(sd);
			sd = nullptr;
			return false;
		}

		// D:(A;;GA;;;SY)(A;;GA;;;BA)
		//   SY = LocalSystem，BA = Builtin Administrators，GA = GENERIC_ALL
		// ★ 不加 `WD`（Everyone）也不加 `AU`（Authenticated Users）——
		//   普通用户连不上是**特性**，不是 bug。
		PSID systemSid = nullptr;
		PSID adminSid = nullptr;
		SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
		if (!AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0,
			&systemSid)) {
			LocalFree(sd);
			sd = nullptr;
			return false;
		}
		if (!AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid)) {
			FreeSid(systemSid);
			LocalFree(sd);
			sd = nullptr;
			return false;
		}

		EXPLICIT_ACCESSW ea[2] = {};
		for (int i = 0; i < 2; ++i) {
			ea[i].grfAccessPermissions = GENERIC_ALL;
			ea[i].grfAccessMode = SET_ACCESS;
			ea[i].grfInheritance = NO_INHERITANCE;
			ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[i].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		}
		ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(systemSid);
		ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(adminSid);

		PACL acl = nullptr;
		const DWORD setOk = SetEntriesInAclW(2, ea, nullptr, &acl);
		FreeSid(systemSid);
		FreeSid(adminSid);
		if (setOk != ERROR_SUCCESS || !acl) {
			LocalFree(sd);
			sd = nullptr;
			return false;
		}

		// ★★★ 这里**必须**做成自相对（self-relative）安全描述符，不能
		//    `SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE)` 之后把 acl 释放掉：
		//   绝对格式的 SD 只是**指向** ACL，释放了 acl 就等于给 SD 留了个
		//   悬空指针。而 `CreateNamedPipe` 会去解引用它 —— 第一次调用往往
		//   侥幸成功（那块堆内存还没被复用），之后恒定失败
		//   `err=1336`(ERROR_INVALID_ACL)。
		//   症状极具欺骗性：**第一个客户端能连上，断开后引擎再也连不上**，
		//   日志里只有一行"CreateNamedPipe 失败 err=1336"，看着像管道名字撞了。
		//   （2026-10-23 实测踩到。）
		//   自相对格式把 SD + ACL + SID 全部装进**一块**缓冲，随 sd 一起释放。
		const BOOL daclOk = SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE);
		if (!daclOk) {
			LocalFree(acl);
			LocalFree(sd);
			sd = nullptr;
			return false;
		}

		DWORD selfRelBytes = 0;
		if (MakeSelfRelativeSD(sd, nullptr, &selfRelBytes) != FALSE
			|| GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			// 第一次调用按约定必然失败并报 INSUFFICIENT_BUFFER；
			// 若它"成功"了（或报别的错），说明我们对 API 的假设不成立。
			LocalFree(acl);
			LocalFree(sd);
			sd = nullptr;
			return false;
		}
		auto* selfRel = static_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR, selfRelBytes));
		if (!selfRel) {
			LocalFree(acl);
			LocalFree(sd);
			sd = nullptr;
			return false;
		}
		if (!MakeSelfRelativeSD(sd, selfRel, &selfRelBytes)) {
			LocalFree(selfRel);
			LocalFree(acl);
			LocalFree(sd);
			sd = nullptr;
			return false;
		}
		LocalFree(acl);
		LocalFree(sd);

		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = selfRel;
		sa.bInheritHandle = FALSE;
		sd = selfRel;
		return true;
	}
}

#endif // R3SHIELDCORE_ENGINE_IPC_H
