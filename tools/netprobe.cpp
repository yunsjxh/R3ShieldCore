//
// netprobe.cpp - 网络监控探针。
//
// 触发各种网络行为，验证 NetworkGuard 的 hook 是否生效。
// 用法：netprobe <子命令>
//
//   connect-rdp      连接 192.168.1.1:3389   （内网 + 敏感端口 → 高危）
//   connect-smb      连接 10.0.0.5:445       （内网 + 敏感端口 → 高危）
//   connect-pub      连接 93.184.216.34:80   （公网明文 → 高危）
//   connect-safe     连接 8.8.8.8:443        （公网 HTTPS → 放行）
//   connect-loop     连接 127.0.0.1:445      （回环 → 放行）
//   sendto-udp       向 1.2.3.4:445 发 UDP   （敏感端口 → 高危）
//   dns              解析 example.com        （域名情报 → 只记录）
//   listen           在 4444 监听            （需要 hook_net_all=1）
//
// 全部用阻塞 socket（连接失败也算触发，因为我们只测 hook 命中）。
// 超时设成 1 秒，免得卡住。
//
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#pragma comment(lib, "ws2_32.lib")

static ULONG ParsePort(const char* text, ULONG fallback)
{
	if (!text || !text[0]) {
		return fallback;
	}
	return static_cast<ULONG>(strtoul(text, nullptr, 10));
}

static int ConnectTo(const char* ip, unsigned short port, const char* label, ULONG timeoutMs)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		printf("  [%s] socket() 失败 err=%d\n", label, WSAGetLastError());
		return 2;
	}

	// 非阻塞 + select 超时，避免 connect 卡住。
	u_long nonBlocking = 1;
	ioctlsocket(s, FIONBIO, &nonBlocking);

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
	int lastError = WSAGetLastError();

	if (rc == SOCKET_ERROR && lastError == WSAEWOULDBLOCK) {
		fd_set writeSet;
		FD_ZERO(&writeSet);
		FD_SET(s, &writeSet);

		timeval tv = {};
		tv.tv_sec = timeoutMs / 1000;
		tv.tv_usec = (timeoutMs % 1000) * 1000;

		rc = select(0, nullptr, &writeSet, nullptr, &tv);
		if (rc == 0) {
			printf("  [%s] connect 超时（%ums）—— 已触发 hook\n", label, timeoutMs);
			closesocket(s);
			return 3;
		}
		rc = 0;
	}

	closesocket(s);

	if (rc == 0) {
		printf("  [%s] connect 成功\n", label);
		return 0;
	}

	lastError = WSAGetLastError();
	printf("  [%s] connect 失败 err=%d\n", label, lastError);
	return 1;
}

static int SendUdp(const char* ip, unsigned short port, const char* label)
{
	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		printf("  [%s] socket() 失败 err=%d\n", label, WSAGetLastError());
		return 2;
	}

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	const char payload[] = "netprobe";
	int rc = sendto(s, payload, sizeof(payload), 0,
		reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

	if (rc == SOCKET_ERROR) {
		printf("  [%s] sendto 失败 err=%d\n", label, WSAGetLastError());
		closesocket(s);
		return 1;
	}

	printf("  [%s] sendto 成功（%d 字节）\n", label, rc);
	closesocket(s);
	return 0;
}

static int DoDns(const char* host)
{
	addrinfo hints = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	addrinfo* result = nullptr;
	int rc = getaddrinfo(host, "80", &hints, &result);
	if (rc != 0) {
		printf("  [dns] getaddrinfo(%s) 失败 rc=%d\n", host, rc);
		return 1;
	}

	char ip[64] = {};
	if (result->ai_addr) {
		sockaddr_in* in = reinterpret_cast<sockaddr_in*>(result->ai_addr);
		inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
	}
	printf("  [dns] getaddrinfo(%s) -> %s\n", host, ip[0] ? ip : "?");

	freeaddrinfo(result);

	// 也走一遍老 API，验证两个 hook 都挂了。
	HOSTENT* he = gethostbyname(host);
	printf("  [dns] gethostbyname(%s) -> %s\n", host,
		he ? "解析成功" : "失败");
	return 0;
}

static int DoListen(unsigned short port)
{
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		printf("  [listen] socket() 失败 err=%d\n", WSAGetLastError());
		return 2;
	}

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
		printf("  [listen] bind 失败 err=%d\n", WSAGetLastError());
		closesocket(s);
		return 1;
	}

	if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
		printf("  [listen] listen 失败 err=%d\n", WSAGetLastError());
		closesocket(s);
		return 1;
	}

	printf("  [listen] 正在 %u 监听\n", port);
	closesocket(s);
	return 0;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	const char* cmd = (argc > 1) ? argv[1] : "all";

	WSADATA wsaData = {};
	int wsa = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsa != 0) {
		printf("WSAStartup 失败 %d\n", wsa);
		return 2;
	}

	printf("netprobe: %s\n", cmd);

	// --hold N 解析放在最前面，**必须在网络操作之前**先等引擎注入。
	//
	// ⚠️ 顺序坑：引擎每 1 秒轮询一次新进程表来注入。如果先做 connect
	//    再 hold，connect 在注入之前就发完了 —— hook 根本没挂上，
	//    事件当然是 0。所以必须"先等注入，再做操作"。
	int holdSeconds = 0;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--hold") == 0 && i + 1 < argc) {
			holdSeconds = atoi(argv[i + 1]);
		}
	}
	if (holdSeconds > 0) {
		printf("先等 %d 秒，让引擎轮询到本进程并完成注入...\n", holdSeconds);
		Sleep(static_cast<DWORD>(holdSeconds) * 1000);
	}

	if (strcmp(cmd, "connect-rdp") == 0) {
		ConnectTo("192.168.1.1", 3389, "connect-rdp", 1000);
	}
	else if (strcmp(cmd, "connect-smb") == 0) {
		ConnectTo("10.0.0.5", 445, "connect-smb", 1000);
	}
	else if (strcmp(cmd, "connect-pub") == 0) {
		ConnectTo("93.184.216.34", 80, "connect-pub", 1500);
	}
	else if (strcmp(cmd, "connect-safe") == 0) {
		ConnectTo("8.8.8.8", 443, "connect-safe", 1500);
	}
	else if (strcmp(cmd, "connect-loop") == 0) {
		ConnectTo("127.0.0.1", 445, "connect-loop", 500);
	}
	else if (strcmp(cmd, "sendto-udp") == 0) {
		SendUdp("1.2.3.4", 445, "sendto-udp");
	}
	else if (strcmp(cmd, "dns") == 0) {
		DoDns("example.com");
	}
	else if (strcmp(cmd, "listen") == 0) {
		DoListen(4444);
	}
	else if (strcmp(cmd, "all") == 0) {
		ConnectTo("127.0.0.1", 445, "connect-loop", 500);
		SendUdp("1.2.3.4", 445, "sendto-udp");
		ConnectTo("192.168.1.1", 3389, "connect-rdp", 1000);
		DoDns("example.com");
	}
	else {
		printf("未知子命令: %s\n", cmd);
		WSACleanup();
		return 2;
	}

	// --hold 的等待已经挪到网络操作**之前**（见上面），这里不再重复。
	// 保留一点尾巴，确保事件有时间被引擎 drain 出来。
	if (holdSeconds > 0) {
		Sleep(1500);
	}

	WSACleanup();
	printf("netprobe 完成\n");
	return 0;
}
