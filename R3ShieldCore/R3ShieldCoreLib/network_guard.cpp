#include "stdafx.h"
#include "network_guard.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "logger.h"

//
// 网络行为监控层（ws2_32 用户态出口）。
//
// 骨架与其它 guard 一致：判定 → 上报 / 拒绝 → 等排空。
// 这里的难点全在 **地址解析** 上：
//
//   Winsock 的地址都是 sockaddr 系列结构（sockaddr_in / sockaddr_in6），
//   里头的 IP 是二进制、端口是网络字节序。要展示给用户必须转成文本。
//
//   ⚠️ 不能用 inet_ntop / ntohs —— 那些函数本身就在 ws2_32 里，
//      从我们的 hook 里调会递归回自己（而且我们可能正持有它的 hook 锁）。
//      所以全部手写：手写大端转换、手写 IPv4/IPv6 文本化。
//
// 另一个要点：**默认只挂出站**。
//   connect / WSAConnect / sendto / WSASendTo —— 数据外泄的口子
//   gethostbyname / getaddrinfo —— 域名情报（C2 域名在这里现形）
//   bind / listen / accept —— 服务端程序极高频，默认不挂（FlagHookNetAll 才开）
//
namespace
{
	// ------------------------------------------------------------------
	// Winsock 类型（不 include winsock2.h —— 它会和 stdafx.h 里的
	// windows.h 打架（winsock.h vs winsock2.h 重复定义），且我们要避免
	// 拉进 ws2_32.lib 的链接依赖）
	// ------------------------------------------------------------------

	// winsock2.h 里 NG_SOCKET 是 UINT_PTR。
	typedef UINT_PTR NG_SOCKET;

	constexpr NG_SOCKET NG_INVALID_SOCKET = static_cast<NG_SOCKET>(~0ull);
	constexpr int NG_SOCKET_ERROR = -1;

	// WSA 错误码（winsock2.h 的值）。
	constexpr int NG_WSAECONNREFUSED = 10061;
	constexpr int NG_WSAEACCES = 10013;
	constexpr int NG_WSANO_DATA = 11004;
	constexpr int NG_EAI_FAIL = 11003;

	// WSAAPI = __stdcall。x64 上 __stdcall 被忽略，但 keep 着一并。
#define NG_WSAAPI __stdcall

	struct NG_SOCKADDR
	{
		USHORT sa_family;
		CHAR sa_data[14];
	};

	struct NG_SOCKADDR_IN
	{
		USHORT sin_family;
		USHORT sin_port;       // 网络字节序
		ULONG sin_addr;        // 网络字节序
		CHAR sin_zero[8];
	};

	struct NG_IN6_ADDR
	{
		UCHAR bytes[16];
	};

	struct NG_SOCKADDR_IN6
	{
		USHORT sin6_family;
		USHORT sin6_port;      // 网络字节序
		ULONG sin6_flowinfo;
		NG_IN6_ADDR sin6_addr;
		ULONG sin6_scope_id;
	};

	struct NG_WSABUF
	{
		ULONG len;
		CHAR* buf;
	};

	struct NG_HOSTENT
	{
		CHAR* h_name;
		CHAR** h_aliases;
		SHORT h_addrtype;
		SHORT h_length;
		CHAR** h_addr_list;
	};

	// addrinfo（getaddrinfo 的返回项）。字段布局对齐 winsock2.h。
	struct NG_ADDRINFO
	{
		int ai_flags;
		int ai_family;
		int ai_socktype;
		int ai_protocol;
		size_t ai_addrlen;
		CHAR* ai_canonname;
		NG_SOCKADDR* ai_addr;
		NG_ADDRINFO* ai_next;
	};

	constexpr int AF_INET_ = 2;
	constexpr int AF_INET6_ = 23;

	// ------------------------------------------------------------------
	// 原型
	// ------------------------------------------------------------------
	typedef int (NG_WSAAPI *connectPtr)(NG_SOCKET, const NG_SOCKADDR*, int);
	typedef int (NG_WSAAPI *WSAConnectPtr)(NG_SOCKET, const NG_SOCKADDR*, int,
		PVOID, PVOID, PVOID, PVOID);
	typedef int (NG_WSAAPI *sendtoPtr)(NG_SOCKET, const CHAR*, int, int,
		const NG_SOCKADDR*, int);
	typedef int (NG_WSAAPI *WSASendToPtr)(NG_SOCKET, const NG_WSABUF*, DWORD, LPDWORD,
		DWORD, const NG_SOCKADDR*, int, PVOID, PVOID);
	typedef int (NG_WSAAPI *bindPtr)(NG_SOCKET, const NG_SOCKADDR*, int);
	typedef int (NG_WSAAPI *listenPtr)(NG_SOCKET, int);
	typedef NG_SOCKET (NG_WSAAPI *acceptPtr)(NG_SOCKET, NG_SOCKADDR*, int*);
	typedef NG_SOCKET (NG_WSAAPI *WSAAcceptPtr)(NG_SOCKET, NG_SOCKADDR*, int*,
		PVOID, DWORD_PTR);
	typedef NG_HOSTENT* (NG_WSAAPI *gethostbynamePtr)(const CHAR*);
	typedef int (NG_WSAAPI *getaddrinfoPtr)(const CHAR*, const CHAR*,
		const NG_ADDRINFO*, NG_ADDRINFO**);

	// ------------------------------------------------------------------
	// v18：\Device\Afd 直发路径（ntdll!NtDeviceIoControlFile）
	// ------------------------------------------------------------------
	//
	// 上面挂的全是 ws2_32 用户态出口。谁都可以绕开它们：
	//     HANDLE h = CreateFileA("\\\\.\\Afd", ...);   // 或 NtCreateFile
	//     DeviceIoControl(h, IOCTL_AFD_SEND, ...);
	// 这条路上一个 ws2_32 函数都不经过 → 之前的 hook 全部看不见。
	//
	// 挂点选 **ntdll!NtDeviceIoControlFile**（而非 kernel32!DeviceIoControl）：
	// 后者内部就是调前者，挂 ntdll 层能同时覆盖直接调 Nt* 的代码。
	//
	// ⚠️⚠️ 性能红线（本 hook 是全库最高频的 syscall 之一）：
	//    每一次文件 IO / socket 收发 / 驱动交互都走 NtDeviceIoControlFile。
	//    所以 hook 的**第一步必须只比对 IoControlCode**，
	//    不在下面三个 AFD 码里就立刻原样透传 —— 绝不做任何解析、
	//    取 pid、查句柄。这是本 hook 唯一的存活前提。
	//
	// AFD IOCTL 码（来自 afd.h / 公开文档）：
	constexpr ULONG IOCTL_AFD_SEND          = 0x0001201F;
	constexpr ULONG IOCTL_AFD_RECV          = 0x0001203F;
	constexpr ULONG IOCTL_AFD_SEND_DATAGRAM = 0x0001207F;

	// NtDeviceIoControlFile 原型（10 参）。
	typedef NTSTATUS(NTAPI* NtDeviceIoControlFilePtr)(HANDLE, HANDLE, PVOID, PVOID,
		PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);

	NtDeviceIoControlFilePtr pOriginalNtDeviceIoControlFile = nullptr;

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

	// 下面的地址文本化辅助函数定义在文件更下方（字节序/地址段落），
	// 这里前置声明，供 AFD 缓冲解析使用。
	ULONG Ntohs16(USHORT value) noexcept;
	void Ipv4ToText(ULONG netOrder, WCHAR* out, size_t cch) noexcept;
	void Ipv6ToText(const UCHAR bytes[16], WCHAR* out, size_t cch) noexcept;

	// ------------------------------------------------------------------
	// AFD 发送缓冲解析
	// ------------------------------------------------------------------
	//
	// NtDeviceIoControlFile(AFD_SEND) 的 InputBuffer 布局（afd.h）：
	//
	//   struct AFD_SEND_INFO {
	//       char*        Buffer;   // ← 数据（不关心）
	//       ULONG        Length;
	//       ULONG        Reserved;
	//       ULONG        HeadLength;
	//       ...
	//   }
	//
	//   而 AFD_SEND_DATAGRAM 的 InputBuffer 是：
	//   struct AFD_WSABUF_SEND_INFO {
	//       ...
	//       SOCKADDR*    DestinationAddress;  // ← 目的地址（要的）
	//       ...
	//   }
	//
	//   ⚠️ 这些结构**随 Windows 版本变**，没有稳定 ABI。所以解析策略是
	//   "尽力而为 + 严格校验"：在缓冲里按可能的偏移试探 **SOCKADDR_IN/IN6**，
	//   用 sa_family 必须是 AF_INET(2)/AF_INET6(23) 来过滤垃圾。
	//   解析不出地址就只记事件不判高危（规则层对空地址返回 nullptr）。
	//
	bool TryParseAfdDestination(const VOID* inputBuffer, ULONG inputLength,
		WCHAR* out, size_t cch, ULONG* outPort) noexcept
	{
		if (out == nullptr || cch == 0 || outPort == nullptr) {
			return false;
		}
		out[0] = L'\0';
		*outPort = 0;

		if (inputBuffer == nullptr || inputLength < 4) {
			return false;
		}

		// 在输入缓冲里寻找一个"像 sockaddr_in / sockaddr_in6"的位置。
		// 候选偏移：0 / 4 / 8 / 12 / 16（指针与长度字段的常见排布）。
		// 每个位置检查 sa_family 是否合法，并用总长度限制读取范围。
		const ULONG kOffsets[] = { 0, 8, 16, 4, 12, 24 };
		const BYTE* base = static_cast<const BYTE*>(inputBuffer);

		for (ULONG off : kOffsets) {
			if (off + 2 > inputLength) {
				continue;
			}

			__try {
				const USHORT family = *reinterpret_cast<const USHORT*>(base + off);

				if (family == AF_INET_ && off + sizeof(NG_SOCKADDR_IN) <= inputLength) {
					const NG_SOCKADDR_IN* sin =
						reinterpret_cast<const NG_SOCKADDR_IN*>(base + off);
					Ipv4ToText(sin->sin_addr, out, cch);
					*outPort = Ntohs16(sin->sin_port);
					return (*out != L'\0');
				}
				if (family == AF_INET6_ && off + sizeof(NG_SOCKADDR_IN6) <= inputLength) {
					const NG_SOCKADDR_IN6* sin6 =
						reinterpret_cast<const NG_SOCKADDR_IN6*>(base + off);
					// 跳过全零地址（未指定）。
					bool allZero = true;
					for (int i = 0; i < 16; i++) {
						if (sin6->sin6_addr.bytes[i] != 0) { allZero = false; break; }
					}
					if (allZero) {
						continue;
					}
					Ipv6ToText(sin6->sin6_addr.bytes, out, cch);
					*outPort = Ntohs16(sin6->sin6_port);
					return (*out != L'\0');
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				continue;
			}
		}

		return false;
	}

	connectPtr pOriginalConnect = nullptr;
	WSAConnectPtr pOriginalWSAConnect = nullptr;
	sendtoPtr pOriginalSendto = nullptr;
	WSASendToPtr pOriginalWSASendTo = nullptr;
	bindPtr pOriginalBind = nullptr;
	listenPtr pOriginalListen = nullptr;
	acceptPtr pOriginalAccept = nullptr;
	WSAAcceptPtr pOriginalWSAAccept = nullptr;
	gethostbynamePtr pOriginalGethostbyname = nullptr;
	getaddrinfoPtr pOriginalGetaddrinfo = nullptr;

	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;
	volatile LONG g_activeHooks = 0;

	enum class Action
	{
		Pass,
		Record,
		Block,
	};

	bool BlockAllOnException() noexcept
	{
		const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		return policy && R3ShieldCore::IsAnyBlockAllMode(policy->Mode);
	}

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// ⚠️ 不直接调 WSAGetLastError() / WSASetLastError() —— 它们是 ws2_32 的导出，
	//    虽然我们没挂它们，但为了保险（万一将来挂了）统一从 GetProcAddress 拿。
	//    这里缓存函数指针。
	typedef int (NG_WSAAPI *WSAGetLastErrorPtr)(void);
	typedef void (NG_WSAAPI *WSASetLastErrorPtr)(int);

	WSAGetLastErrorPtr ResolveGetLastError() noexcept
	{
		static WSAGetLastErrorPtr cached = nullptr;
		if (!cached) {
			HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
			if (ws2) {
				cached = reinterpret_cast<WSAGetLastErrorPtr>(
					GetProcAddress(ws2, "WSAGetLastError"));
			}
		}
		return cached;
	}

	// 取当前线程的 Winsock 错误码。拿不到返回 0。
	int NgGetLastError() noexcept
	{
		WSAGetLastErrorPtr fn = ResolveGetLastError();
		return fn ? fn() : 0;
	}

	// 设置当前线程的 Winsock 错误码（用于我们主动拒绝后让调用方看到原因）。
	void NgSetLastError(int error) noexcept
	{
		static WSASetLastErrorPtr cached = nullptr;
		if (!cached) {
			HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
			if (ws2) {
				cached = reinterpret_cast<WSASetLastErrorPtr>(
					GetProcAddress(ws2, "WSASetLastError"));
			}
		}
		if (cached) {
			cached(error);
		}
	}

	// ------------------------------------------------------------------
	// 字节序与地址文本化（手写，不碰 ws2_32）
	// ------------------------------------------------------------------

	// 网络字节序（大端）→ 主机序。手写，与 ntohs 等价。
	ULONG Ntohs16(USHORT value) noexcept
	{
		return (static_cast<ULONG>(value & 0x00FF) << 8) |
			(static_cast<ULONG>(value & 0xFF00) >> 8);
	}

	// sink 结构里的 sin_addr 是大端的 32 位整数。取出四个八位组。
	void Ipv4Octets(ULONG netOrder, UCHAR out[4]) noexcept
	{
		out[0] = static_cast<UCHAR>(netOrder & 0xFF);
		out[1] = static_cast<UCHAR>((netOrder >> 8) & 0xFF);
		out[2] = static_cast<UCHAR>((netOrder >> 16) & 0xFF);
		out[3] = static_cast<UCHAR>((netOrder >> 24) & 0xFF);
	}

	// IPv4 → 点分十进制文本。
	void Ipv4ToText(ULONG netOrder, WCHAR* out, size_t cch) noexcept
	{
		UCHAR o[4] = {};
		Ipv4Octets(netOrder, o);
		swprintf_s(out, cch, L"%u.%u.%u.%u", o[0], o[1], o[2], o[3]);
	}

	// IPv6 → 文本。压缩最长的连续零段（RFC 5952 的 "::" 写法）。
	void Ipv6ToText(const UCHAR bytes[16], WCHAR* out, size_t cch) noexcept
	{
		// 16 字节 → 8 个 16 位组（大端）。
		USHORT groups[8] = {};
		for (int i = 0; i < 8; i++) {
			groups[i] = static_cast<USHORT>((bytes[i * 2] << 8) | bytes[i * 2 + 1]);
		}

		// 找最长连续零段（长度 >= 2 才值得压缩）。
		int bestStart = -1;
		int bestLen = 0;
		int runStart = -1;
		int runLen = 0;

		for (int i = 0; i < 8; i++) {
			if (groups[i] == 0) {
				if (runStart < 0) {
					runStart = i;
					runLen = 0;
				}
				runLen++;
				if (runLen > bestLen) {
					bestLen = runLen;
					bestStart = runStart;
				}
			}
			else {
				runStart = -1;
				runLen = 0;
			}
		}

		if (bestLen < 2) {
			bestStart = -1; // 不压缩
		}

		WCHAR buffer[64] = {};
		size_t pos = 0;
		for (int i = 0; i < 8; i++) {
			if (bestStart >= 0 && i == bestStart) {
				// 压缩段：写 "::"。
				buffer[pos++] = L':';
				buffer[pos++] = L':';
				i += bestLen - 1;
				continue;
			}

			// 非首组（且上一个字符不是 ':'）时补分隔冒号。
			if (pos > 0 && buffer[pos - 1] != L':') {
				buffer[pos++] = L':';
			}

			WCHAR group[8] = {};
			swprintf_s(group, L"%x", groups[i]);
			for (size_t k = 0; group[k] && pos + 1 < _countof(buffer); k++) {
				buffer[pos++] = group[k];
			}
		}

		buffer[pos] = L'\0';
		wcsncpy_s(out, cch, buffer, _TRUNCATE);
	}

	// 从 sockaddr 里取地址文本和端口。
	// 返回 true 表示解析成功（family 认得）。
	bool ParseSockaddr(const NG_SOCKADDR* addr, int addrLen, WCHAR* text, size_t cch,
		ULONG& port) noexcept
	{
		port = 0;
		if (text && cch) {
			text[0] = L'\0';
		}

		if (!addr || addrLen < static_cast<int>(sizeof(USHORT))) {
			return false;
		}

		if (addr->sa_family == AF_INET_ && addrLen >= static_cast<int>(sizeof(NG_SOCKADDR_IN))) {
			const NG_SOCKADDR_IN* in4 = reinterpret_cast<const NG_SOCKADDR_IN*>(addr);
			if (text) {
				Ipv4ToText(in4->sin_addr, text, cch);
			}
			port = Ntohs16(in4->sin_port);
			return true;
		}

		if (addr->sa_family == AF_INET6_ && addrLen >= static_cast<int>(sizeof(NG_SOCKADDR_IN6))) {
			const NG_SOCKADDR_IN6* in6 = reinterpret_cast<const NG_SOCKADDR_IN6*>(addr);
			if (text) {
				Ipv6ToText(in6->sin6_addr.bytes, text, cch);
			}
			port = Ntohs16(in6->sin6_port);
			return true;
		}

		return false;
	}

	// 从 socket 句柄反查本端地址（用于填 LocalAddress/LocalPort）。
	// 失败就留空 —— 不是关键路径。
	void QueryLocalEndpoint(NG_SOCKET s, WCHAR* text, size_t cch, ULONG& port) noexcept
	{
		port = 0;
		if (text && cch) {
			text[0] = L'\0';
		}

		if (s == NG_INVALID_SOCKET) {
			return;
		}

		// ⚠️ getsockname 在 ws2_32 里，但**我们没挂它** —— 所以调它是安全的。
		//    只挂需要拦的那些，查询类 API 保持原生。
		typedef int (NG_WSAAPI *getsocknamePtr)(NG_SOCKET, NG_SOCKADDR*, int*);
		static getsocknamePtr pGetsockname = nullptr;
		if (!pGetsockname) {
			HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
			if (ws2) {
				pGetsockname = reinterpret_cast<getsocknamePtr>(
					GetProcAddress(ws2, "getsockname"));
			}
		}
		if (!pGetsockname) {
			return;
		}

		// sockaddr_storage 大小足够装下任一 family。
		BYTE storage[128] = {};
		int len = sizeof(storage);
		if (pGetsockname(s, reinterpret_cast<NG_SOCKADDR*>(storage), &len) != 0) {
			return;
		}

		ParseSockaddr(reinterpret_cast<NG_SOCKADDR*>(storage), len, text, cch, port);
	}

	// ------------------------------------------------------------------
	// 上报与判定
	// ------------------------------------------------------------------
	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Network);
		if (event.TimeStamp == 0) {
			event.TimeStamp = NowFileTime();
		}
		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();

		R3ShieldCoreChannel::Publish(event);
	}

	R3ShieldCore::Verdict PromptFallbackVerdict() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
			return static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
		}

		return R3ShieldCore::Verdict::Deny;
	}

	// 结果判定。allowAsk 决定高危时能不能真的弹窗 ——
	// LOG/BLOCK 模式下 UI 线程根本没起，Ask 会白等满超时。
	Action Evaluate(R3ShieldCore::NetOp op, R3ShieldCore::Event& event, bool allowAsk) noexcept
	{
		event.ObjectType = static_cast<ULONG>(R3ShieldCore::ObjectType::Network);

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all）----
		//
		// 探测范围内一律拒绝：不判豁免、不判高危、不弹窗。
		// 能走到这里的操作都已经被更早的"探测边界"判定为"被探测到的"
		// （非文件对象、没开 hook 的只读打开、不被注入的进程都在前面返回了），
		// 所以这里不再做任何区分。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskNetwork(event.KeyPath, event.TargetPort,
					event.NetProtocol, static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;

				// 打上细分标记，UI 好上色。
				if (event.TargetPort != 0 && R3ShieldCoreRules::IsSensitivePort(event.TargetPort)) {
					event.Flags |= R3ShieldCore::FlagEventSensitivePort;
				}
				if (R3ShieldCoreRules::IsPrivateOrReservedAddress(event.KeyPath)) {
					event.Flags |= R3ShieldCore::FlagEventPrivateNet;
				}
			}
		}

		// 非高危：按 mode 处理。
		//
		// ⚠️ 网络在 BLOCK 模式下**不做**"一刀切拦截"。注册表 / 文件的 BLOCK
		//    语义是"拒绝非系统程序的写操作"，而网络连接不是写操作；把非高危
		//    连接全拒会把回环和 DNS 一起掐掉 —— 实测表现是整机断网
		//    （连 8.8.8.8:443、127.0.0.1:445 都被拒，DNS 随之解析失败）。
		//    所以 BLOCK 下非高危放行，只记录。
		if (!highRisk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				return Action::Record;
			}
			// BLOCK / ASK：放行。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// ---- 高危 ----
		// ASK 模式弹窗询问；BLOCK 模式直接拒绝；LOG 模式只记录。
		if (!allowAsk) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
				return Action::Block;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();
		event.TimeStamp = NowFileTime();

		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskAsked);
		}

		// ★ v29：走“通道可用性”包装 —— 管理员启动引擎时通道打不开，
		//   LOG 模式下降级放行（否则高危操作被静默拒，不可识别）。
		//   见 r3shieldcore_prompt.h 的 AskWithChannelGuard 说明。
		R3ShieldCore::Verdict verdict = R3ShieldCore::Verdict::Deny;
		if (!R3ShieldCorePrompt::AskWithChannelGuard(event, PromptFallbackVerdict(), mode, verdict)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
			return Action::Record;
		}
		if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
			InterlockedIncrement(&channel->HighRiskBlocked);
		}
		return Action::Block;
	}

	// 组装事件：KeyPath 放远端地址，LocalAddress 放本端地址。
	void BuildEvent(R3ShieldCore::Event& event, const WCHAR* remoteText, ULONG remotePort,
		const WCHAR* localText, ULONG localPort, ULONG protocol) noexcept
	{
		if (remoteText) {
			wcsncpy_s(event.KeyPath, remoteText, _TRUNCATE);
		}
		event.KeyPathLength = static_cast<ULONG>(wcslen(event.KeyPath));

		event.TargetPort = remotePort;
		event.NetProtocol = protocol;

		if (localText) {
			wcsncpy_s(event.LocalAddress, localText, _TRUNCATE);
		}
		event.LocalPort = localPort;
	}

	// 协议号：从 socket 类型推（SOCK_STREAM=1 → TCP，SOCK_DGRAM=2 → UDP）。
	// 我们拿不到 socket 的 type（SO_TYPE 要 getsockopt，但那是 ws2_32 的活），
	// 所以由调用方按"是哪个 API"来定：connect/sendto 各自知道。
	ULONG ProtocolFromSoType(int soType) noexcept
	{
		switch (soType) {
		case 1: return 6;  // SOCK_STREAM → IPPROTO_TCP
		case 2: return 17; // SOCK_DGRAM → IPPROTO_UDP
		default: return 0;
		}
	}

	// 查 socket 类型（SOCK_STREAM / SOCK_DGRAM），拿不到返回 0。
	// getsockopt 不在我们的 hook 列表里，调用安全。
	int QuerySocketType(NG_SOCKET s) noexcept
	{
		typedef int (NG_WSAAPI *getsockoptPtr)(NG_SOCKET, int, int, CHAR*, int*);
		static getsockoptPtr pGetsockopt = nullptr;
		if (!pGetsockopt) {
			HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
			if (ws2) {
				pGetsockopt = reinterpret_cast<getsockoptPtr>(
					GetProcAddress(ws2, "getsockopt"));
			}
		}
		if (!pGetsockopt || s == NG_INVALID_SOCKET) {
			return 0;
		}

		constexpr int SOL_SOCKET_ = 0xFFFF;
		constexpr int SO_TYPE_ = 0x1008;

		int soType = 0;
		int len = sizeof(soType);
		if (pGetsockopt(s, SOL_SOCKET_, SO_TYPE_, reinterpret_cast<CHAR*>(&soType), &len) != 0) {
			return 0;
		}
		return soType;
	}

	// ==================================================================
	// hook
	// ==================================================================

	int NG_WSAAPI connect_Hook(NG_SOCKET s, const NG_SOCKADDR* name, int namelen)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Connect);

			WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
			WCHAR localText[64] = {};
			ULONG remotePort = 0;
			ULONG localPort = 0;

			const bool parsed = ParseSockaddr(name, namelen, remoteText,
				_countof(remoteText), remotePort);

			if (parsed) {
				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				QueryLocalEndpoint(s, localText, _countof(localText), localPort);
				BuildEvent(event, remoteText, remotePort, localText, localPort, protocol);

				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::Connect, event, allowAsk);

				if (action == Action::Block) {
					event.Status = static_cast<ULONG>(NG_WSAECONNREFUSED);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event);

					// 设置 WSA 错误码，让调用方看到"拒绝连接"。
					NgSetLastError(NG_WSAECONNREFUSED);

					InterlockedDecrement(&g_activeHooks);
					return NG_SOCKET_ERROR;
				}

				result = pOriginalConnect(s, name, namelen);

				if (action == Action::Record) {
					event.Status = static_cast<ULONG>(result == 0 ? 0 : NgGetLastError());
					Publish(event);
				}
			}
			else {
				result = pOriginalConnect(s, name, namelen);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_SOCKET_ERROR;
			}
			else {
				result = pOriginalConnect(s, name, namelen);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	int NG_WSAAPI sendto_Hook(NG_SOCKET s, const CHAR* buf, int len, int flags,
		const NG_SOCKADDR* to, int tolen)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::SendTo);

			WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
			WCHAR localText[64] = {};
			ULONG remotePort = 0;
			ULONG localPort = 0;

			const bool parsed = ParseSockaddr(to, tolen, remoteText,
				_countof(remoteText), remotePort);

			if (parsed) {
				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				QueryLocalEndpoint(s, localText, _countof(localText), localPort);
				BuildEvent(event, remoteText, remotePort, localText, localPort, protocol);

				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::SendTo, event, allowAsk);

				if (action == Action::Block) {
					event.Status = static_cast<ULONG>(NG_WSAECONNREFUSED);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event);
					InterlockedDecrement(&g_activeHooks);
					return NG_SOCKET_ERROR;
				}

				result = pOriginalSendto(s, buf, len, flags, to, tolen);

				if (action == Action::Record) {
					event.Status = static_cast<ULONG>(result == NG_SOCKET_ERROR ? NgGetLastError() : 0);
					Publish(event);
				}
			}
			else {
				result = pOriginalSendto(s, buf, len, flags, to, tolen);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_SOCKET_ERROR;
			}
			else {
				result = pOriginalSendto(s, buf, len, flags, to, tolen);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	int NG_WSAAPI WSAConnect_Hook(NG_SOCKET s, const NG_SOCKADDR* name, int namelen,
		PVOID callerData, PVOID calleeData, PVOID sqos, PVOID gqos)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Connect);

			WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
			WCHAR localText[64] = {};
			ULONG remotePort = 0;
			ULONG localPort = 0;

			const bool parsed = ParseSockaddr(name, namelen, remoteText,
				_countof(remoteText), remotePort);

			if (parsed) {
				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				QueryLocalEndpoint(s, localText, _countof(localText), localPort);
				BuildEvent(event, remoteText, remotePort, localText, localPort, protocol);

				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::Connect, event, allowAsk);

				if (action == Action::Block) {
					event.Status = static_cast<ULONG>(NG_WSAECONNREFUSED);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event);
					InterlockedDecrement(&g_activeHooks);
					return NG_SOCKET_ERROR;
				}

				result = pOriginalWSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);

				if (action == Action::Record) {
					event.Status = static_cast<ULONG>(result == NG_SOCKET_ERROR ? NgGetLastError() : 0);
					Publish(event);
				}
			}
			else {
				result = pOriginalWSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_SOCKET_ERROR;
			}
			else {
				result = pOriginalWSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	int NG_WSAAPI WSASendTo_Hook(NG_SOCKET s, const NG_WSABUF* bufs, DWORD bufCount,
		LPDWORD bytesSent, DWORD flags, const NG_SOCKADDR* to, int tolen,
		PVOID overlapped, PVOID completionRoutine)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::SendTo);

			WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
			WCHAR localText[64] = {};
			ULONG remotePort = 0;
			ULONG localPort = 0;

			const bool parsed = ParseSockaddr(to, tolen, remoteText,
				_countof(remoteText), remotePort);

			if (parsed) {
				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				QueryLocalEndpoint(s, localText, _countof(localText), localPort);
				BuildEvent(event, remoteText, remotePort, localText, localPort, protocol);

				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::SendTo, event, allowAsk);

				if (action == Action::Block) {
					event.Status = static_cast<ULONG>(NG_WSAECONNREFUSED);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event);
					InterlockedDecrement(&g_activeHooks);
					return NG_SOCKET_ERROR;
				}

				result = pOriginalWSASendTo(s, bufs, bufCount, bytesSent, flags, to, tolen,
					overlapped, completionRoutine);

				if (action == Action::Record) {
					event.Status = static_cast<ULONG>(result == NG_SOCKET_ERROR ? NgGetLastError() : 0);
					Publish(event);
				}
			}
			else {
				result = pOriginalWSASendTo(s, bufs, bufCount, bytesSent, flags, to, tolen,
					overlapped, completionRoutine);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_SOCKET_ERROR;
			}
			else {
				result = pOriginalWSASendTo(s, bufs, bufCount, bytesSent, flags, to, tolen,
					overlapped, completionRoutine);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	int NG_WSAAPI bind_Hook(NG_SOCKET s, const NG_SOCKADDR* name, int namelen)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Bind);
			event.Flags |= R3ShieldCore::FlagEventInbound;

			WCHAR addrText[R3ShieldCore::MaxKeyPathChars] = {};
			ULONG port = 0;

			if (ParseSockaddr(name, namelen, addrText, _countof(addrText), port)) {
				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				BuildEvent(event, addrText, port, addrText, port, protocol);

				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::Bind, event, allowAsk);

				if (action == Action::Block) {
					event.Status = static_cast<ULONG>(NG_WSAEACCES);
					event.Flags |= R3ShieldCore::FlagEventBlocked;
					Publish(event);
					InterlockedDecrement(&g_activeHooks);
					return NG_SOCKET_ERROR;
				}

				result = pOriginalBind(s, name, namelen);

				if (action == Action::Record) {
					event.Status = static_cast<ULONG>(result == NG_SOCKET_ERROR ? NgGetLastError() : 0);
					Publish(event);
				}
			}
			else {
				result = pOriginalBind(s, name, namelen);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_SOCKET_ERROR;
			}
			else {
				result = pOriginalBind(s, name, namelen);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	int NG_WSAAPI listen_Hook(NG_SOCKET s, int backlog)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Listen);
			event.Flags |= R3ShieldCore::FlagEventInbound | R3ShieldCore::FlagEventListen;

			WCHAR localText[R3ShieldCore::MaxKeyPathChars] = {};
			ULONG localPort = 0;
			QueryLocalEndpoint(s, localText, _countof(localText), localPort);

			const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
			BuildEvent(event, localText, localPort, localText, localPort, protocol);

			const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
			const bool allowAsk = policy &&
				policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
			const Action action = Evaluate(R3ShieldCore::NetOp::Listen, event, allowAsk);

			if (action == Action::Block) {
				event.Status = static_cast<ULONG>(NG_WSAEACCES);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				Publish(event);
				InterlockedDecrement(&g_activeHooks);
				return NG_SOCKET_ERROR;
			}

			result = pOriginalListen(s, backlog);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(result == NG_SOCKET_ERROR ? NgGetLastError() : 0);
				Publish(event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_SOCKET_ERROR;
			}
			else {
				result = pOriginalListen(s, backlog);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	NG_SOCKET NG_WSAAPI accept_Hook(NG_SOCKET s, NG_SOCKADDR* addr, int* addrlen)
	{
		InterlockedIncrement(&g_activeHooks);

		NG_SOCKET result = NG_INVALID_SOCKET;
		__try {
			result = pOriginalAccept(s, addr, addrlen);

			if (result != NG_INVALID_SOCKET) {
				R3ShieldCore::Event event = {};
				event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Accept);
				event.Flags |= R3ShieldCore::FlagEventInbound;

				WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
				WCHAR localText[64] = {};
				ULONG remotePort = 0;
				ULONG localPort = 0;

				const int len = addrlen ? *addrlen : 0;
				ParseSockaddr(addr, len, remoteText, _countof(remoteText), remotePort);
				QueryLocalEndpoint(s, localText, _countof(localText), localPort);

				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				BuildEvent(event, remoteText, remotePort, localText, localPort, protocol);

				// accept 只是"记录"（连接已经建立，拒绝它等于不接收 ——
				// 但那是服务端自己的选择，不该由我们代劳）。
				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::Accept, event, allowAsk);

				if (action == Action::Record) {
					event.Status = 0;
					Publish(event);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_INVALID_SOCKET;
			}
			else {
				result = pOriginalAccept(s, addr, addrlen);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	NG_SOCKET NG_WSAAPI WSAAccept_Hook(NG_SOCKET s, NG_SOCKADDR* addr, int* addrlen,
		PVOID condition, DWORD_PTR context)
	{
		InterlockedIncrement(&g_activeHooks);

		NG_SOCKET result = NG_INVALID_SOCKET;
		__try {
			result = pOriginalWSAAccept(s, addr, addrlen, condition, context);

			if (result != NG_INVALID_SOCKET) {
				R3ShieldCore::Event event = {};
				event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::Accept);
				event.Flags |= R3ShieldCore::FlagEventInbound;

				WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
				WCHAR localText[64] = {};
				ULONG remotePort = 0;
				ULONG localPort = 0;

				const int len = addrlen ? *addrlen : 0;
				ParseSockaddr(addr, len, remoteText, _countof(remoteText), remotePort);
				QueryLocalEndpoint(s, localText, _countof(localText), localPort);

				const ULONG protocol = ProtocolFromSoType(QuerySocketType(s));
				BuildEvent(event, remoteText, remotePort, localText, localPort, protocol);

				const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
				const bool allowAsk = policy &&
					policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
				const Action action = Evaluate(R3ShieldCore::NetOp::Accept, event, allowAsk);

				if (action == Action::Record) {
					event.Status = 0;
					Publish(event);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSAECONNREFUSED);
				result = NG_INVALID_SOCKET;
			}
			else {
				result = pOriginalWSAAccept(s, addr, addrlen, condition, context);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	NG_HOSTENT* NG_WSAAPI gethostbyname_Hook(const CHAR* name)
	{
		InterlockedIncrement(&g_activeHooks);

		NG_HOSTENT* result = nullptr;
		__try {
			result = pOriginalGethostbyname(name);

			if (name && name[0]) {
				R3ShieldCore::Event event = {};
				event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::DnsQuery);
				event.Flags |= R3ShieldCore::FlagEventDns | R3ShieldCore::FlagEventUnresolved;

				WCHAR wide[R3ShieldCore::MaxKeyPathChars] = {};
				if (MultiByteToWideChar(CP_ACP, 0, name, -1, wide, _countof(wide)) > 0) {
					BuildEvent(event, wide, 0, nullptr, 0, 0);

					const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
					const bool allowAsk = policy &&
						policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
					const Action action = Evaluate(R3ShieldCore::NetOp::DnsQuery, event, allowAsk);

					if (action == Action::Record) {
						event.Status = result ? 0 : 1;
						Publish(event);
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				NgSetLastError(NG_WSANO_DATA);
				result = nullptr;
			}
			else {
				result = pOriginalGethostbyname(name);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	int NG_WSAAPI getaddrinfo_Hook(const CHAR* node, const CHAR* service,
		const NG_ADDRINFO* hints, NG_ADDRINFO** res)
	{
		InterlockedIncrement(&g_activeHooks);

		int result = -1;
		__try {
			result = pOriginalGetaddrinfo(node, service, hints, res);

			if (node && node[0]) {
				R3ShieldCore::Event event = {};
				event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::DnsQuery);
				event.Flags |= R3ShieldCore::FlagEventDns;

				WCHAR wide[R3ShieldCore::MaxKeyPathChars] = {};
				if (MultiByteToWideChar(CP_ACP, 0, node, -1, wide, _countof(wide)) > 0) {
					// 服务名可能是端口数字串。
					ULONG port = 0;
					if (service && service[0]) {
						port = static_cast<ULONG>(strtoul(service, nullptr, 10));
					}

					BuildEvent(event, wide, port, nullptr, 0, 0);
					if (port == 0) {
						event.Flags |= R3ShieldCore::FlagEventUnresolved;
					}

					const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
					const bool allowAsk = policy &&
						policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
					const Action action = Evaluate(R3ShieldCore::NetOp::DnsQuery, event, allowAsk);

					if (action == Action::Record) {
						event.Status = static_cast<ULONG>(result);
						Publish(event);
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				result = NG_EAI_FAIL;
			}
			else {
				result = pOriginalGetaddrinfo(node, service, hints, res);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return result;
	}

	// ==================================================================
	// v18：\Device\Afd 直发 hook
	// ==================================================================
	//
	// ⚠️⚠️ 性能铁律（再看一遍）：
	//   本函数是全系统最高频的 syscall 入口之一。**第一步必须只比对
	//   IoControlCode**，否则（取 pid / 查句柄 / 解析路径）会把整机 IO
	//   拖慢一个数量级。非 AFD 码 = 一行比较 + 一次原函数调用，无副作用。
	//
	NTSTATUS NTAPI NtDeviceIoControlFile_Hook(HANDLE FileHandle, HANDLE Event,
		PVOID ApcRoutine, PVOID ApcContext, PVOID IoStatusBlock, ULONG IoControlCode,
		PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
		ULONG OutputBufferLength)
	{
		// ---- 第一步：精确过滤。非 AFD 发送/接收码 → 立刻透传 ----
		//
		// 注意：AFD_RECV(0x1203F) 是**接收**，拿不到远端地址（数据是收进来的），
		// 我们只挂它做"可见性"用途 —— 判定时因 remote 为空会走 nullptr 分支，
		// 不会误报。这里不做区分，统一交给下面判。
		if (IoControlCode != IOCTL_AFD_SEND &&
			IoControlCode != IOCTL_AFD_RECV &&
			IoControlCode != IOCTL_AFD_SEND_DATAGRAM) {
			return pOriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine,
				ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
				OutputBuffer, OutputBufferLength);
		}

		InterlockedIncrement(&g_activeHooks);

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			R3ShieldCore::Event event = {};
			event.Op = static_cast<ULONG>(R3ShieldCore::NetOp::DeviceIo);

			WCHAR remoteText[R3ShieldCore::MaxKeyPathChars] = {};
			ULONG remotePort = 0;

			// AFD_RECV 是入向数据，没有目的地址 → 解析必然失败 → 只记不判。
			const bool parsed = (IoControlCode == IOCTL_AFD_RECV)
				? false
				: TryParseAfdDestination(InputBuffer, InputBufferLength,
					remoteText, _countof(remoteText), &remotePort);

			// 无论解析成功与否都组装事件（可见性）：拿不到地址就留空。
			BuildEvent(event, parsed ? remoteText : L"", remotePort, nullptr, 0, 0);

			const R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
			const bool allowAsk = policy &&
				policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask);
			const Action action = Evaluate(R3ShieldCore::NetOp::DeviceIo, event, allowAsk);

			if (action == Action::Block) {
				event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
				event.Flags |= R3ShieldCore::FlagEventBlocked;
				Publish(event);
				InterlockedDecrement(&g_activeHooks);
				// ⚠️ 拒绝方式：返回 ACCESS_DENIED 且**不调原函数** ——
				//    数据送不出去。这与 sendto 侧一致。
				return STATUS_ACCESS_DENIED;
			}

			status = pOriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine,
				ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
				OutputBuffer, OutputBufferLength);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (BlockAllOnException()) {
				status = STATUS_ACCESS_DENIED;
			}
			else {
				status = pOriginalNtDeviceIoControlFile(FileHandle, Event, ApcRoutine,
					ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
					OutputBuffer, OutputBufferLength);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// 挂载
	// ==================================================================
	bool QueueHook(LPCSTR moduleName, LPCSTR functionName, LPVOID detour,
		LPVOID* original, bool required) noexcept
	{
		HMODULE module = GetModuleHandleA(moduleName);
		if (!module) {
			if (required) {
				LOG(L"NetworkGuard: 模块 %S 未加载", moduleName);
			}
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(module, functionName));
		if (!target) {
			if (required) {
				LOG(L"NetworkGuard: %S!%S 找不到", moduleName, functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"NetworkGuard: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"NetworkGuard: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}
}

namespace NetworkGuard
{
	int HookCount() noexcept
	{
		return g_hookCount;
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"NetworkGuard: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	bool Install(HANDLE /*engineProcess*/) noexcept
	{
		if (g_installed) {
			return true;
		}

		if (RegistryGuard::IsBypassed()) {
			g_bypass = true;
			g_installed = true;
			return true;
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy || (policy->Flags & R3ShieldCore::FlagHookNetwork) == 0) {
			g_bypass = true;
			g_installed = true;
			LOG(L"NetworkGuard: hook_net 未开启，本进程不挂网络 hook");
			return true;
		}

		g_bypass = false;

		// ⚠️ 必须先确保 ws2_32 已加载。很多进程启动时还没 import winsock，
		//    此时 GetModuleHandle 返回 0，hook 就挂不上 —— 之后它调
		//    WSAStartup 才加载 ws2_32，那时我们又没机会了（除非挂 WSAStartup）。
		//
		//    做法：主动 LoadLibraryW("ws2_32.dll")。它是系统 DLL，加载是幂等
		//    且廉价的；副作用只是让本进程提前映射了网络栈（本来也要用）。
		HMODULE ws2 = LoadLibraryW(L"ws2_32.dll");
		(void)ws2;

		// ---- 出站：默认挂（数据外泄的口子）----
		QueueHook("ws2_32.dll", "connect", reinterpret_cast<LPVOID>(connect_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalConnect), true);
		QueueHook("ws2_32.dll", "WSAConnect", reinterpret_cast<LPVOID>(WSAConnect_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalWSAConnect), false);
		QueueHook("ws2_32.dll", "sendto", reinterpret_cast<LPVOID>(sendto_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalSendto), false);
		QueueHook("ws2_32.dll", "WSASendTo", reinterpret_cast<LPVOID>(WSASendTo_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalWSASendTo), false);

		// ---- v18：\Device\Afd 直发（绕开 ws2_32 的路径）----
		//
		// 挂 ntdll!NtDeviceIoControlFile。⚠️ 这是全库最高频的 hook，
		// 内部第一步只比对 IoControlCode（见 NtDeviceIoControlFile_Hook）。
		// required=false：个别环境可能取不到该导出，缺了不该拖垮整层。
		QueueHook("ntdll.dll", "NtDeviceIoControlFile",
			reinterpret_cast<LPVOID>(NtDeviceIoControlFile_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtDeviceIoControlFile), false);

		// ---- 域名解析：默认挂（C2 域名情报）----
		if ((policy->Flags & R3ShieldCore::FlagHookDns) != 0) {
			QueueHook("ws2_32.dll", "gethostbyname", reinterpret_cast<LPVOID>(gethostbyname_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalGethostbyname), false);
			QueueHook("ws2_32.dll", "getaddrinfo", reinterpret_cast<LPVOID>(getaddrinfo_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalGetaddrinfo), false);
		}

		// ---- 服务端（bind/listen/accept）：默认不挂，高频 ----
		if ((policy->Flags & R3ShieldCore::FlagHookNetAll) != 0) {
			QueueHook("ws2_32.dll", "bind", reinterpret_cast<LPVOID>(bind_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalBind), false);
			QueueHook("ws2_32.dll", "listen", reinterpret_cast<LPVOID>(listen_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalListen), false);
			QueueHook("ws2_32.dll", "accept", reinterpret_cast<LPVOID>(accept_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalAccept), false);
			QueueHook("ws2_32.dll", "WSAAccept", reinterpret_cast<LPVOID>(WSAAccept_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalWSAAccept), false);
		}

		g_installed = true;

		LOG(L"NetworkGuard: 已挂载 %d 个网络 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}
