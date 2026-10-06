//
// net_rules_ut.cpp - R3ShieldCoreRules 网络高危规则单元测试。
//
// 直接链 r3shieldcore_rules.cpp 的目标文件 + channel_stub.cpp（提供 Policy 桩）。
// 覆盖点：
//   - 敏感端口（445 / 3389 / 1433 / 6379 …）
//   - 内网地址（10./172.16-31./192.168./169.254.）
//   - 回环放行（127.0.0.1 / ::1）
//   - 公网普通端口放行
//   - listen 无差别高危
//   - bind 仅对外地址高危
//   - DNS 永不判高危（纯情报）
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskNetwork(const wchar_t* addr, unsigned long port,
		unsigned long protocol, unsigned long netOp) noexcept;
	const char* NetworkRiskReason(const wchar_t* addr, unsigned long port,
		unsigned long protocol, unsigned long netOp) noexcept;
	bool IsPrivateOrReservedAddress(const wchar_t* addr) noexcept;
	bool IsSensitivePort(unsigned long port) noexcept;
	bool IsInfrastructurePort(unsigned long port) noexcept;
}

// NetOp 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	N_Connect = 1,
	N_SendTo = 2,
	N_Bind = 3,
	N_Listen = 4,
	N_Accept = 5,
	N_DnsQuery = 6,
};

constexpr unsigned long TCP = 6;
constexpr unsigned long UDP = 17;

struct Case
{
	const wchar_t* addr;
	unsigned long port;
	unsigned long proto;
	unsigned long op;
	bool expectHigh;
	const char* note;
};

int wmain()
{
	setlocale(LC_ALL, "");

	const Case cases[] = {
		// ---- 敏感端口 + 公网（横向移动/数据库）----
		{ L"1.2.3.4",   445,   TCP, N_Connect, true,  "公网 SMB 445（高危）" },
		{ L"1.2.3.4",   3389,  TCP, N_Connect, true,  "公网 RDP 3389（高危）" },
		{ L"1.2.3.4",   1433,  TCP, N_Connect, true,  "公网 MSSQL 1433（高危）" },
		{ L"1.2.3.4",   6379,  TCP, N_Connect, true,  "公网 Redis 6379（高危）" },
		{ L"1.2.3.4",   23,    TCP, N_Connect, true,  "公网 Telnet 23（高危）" },

		// ---- 敏感端口 + 内网（横向移动特征）----
		{ L"10.0.0.5",  445,   TCP, N_Connect, true,  "内网 SMB 445（高危）" },
		{ L"192.168.1.1", 3389, TCP, N_Connect, true, "内网 RDP 3389（高危）" },
		{ L"172.16.5.5", 445,  TCP, N_Connect, true,  "内网 172.16 SMB（高危）" },

		// ---- 内网地址（非敏感端口）----
		{ L"10.0.0.5",  8080,  TCP, N_Connect, true,  "内网任意端口（高危）" },
		{ L"192.168.1.1", 80,  TCP, N_Connect, true,  "内网 HTTP（高危）" },
		{ L"169.254.1.1", 1234, TCP, N_Connect, true, "链路本地（高危）" },

		// ---- 回环：放行 ----
		{ L"127.0.0.1", 445,   TCP, N_Connect, false, "回环 445（放行）" },
		{ L"127.0.0.1", 8080,  TCP, N_Connect, false, "回环 8080（放行）" },
		{ L"::1",       445,   TCP, N_Connect, false, "IPv6 回环（放行）" },

		// ---- 公网普通端口：放行 ----
		{ L"8.8.8.8",   443,   TCP, N_Connect, false, "公网 HTTPS 443（放行）" },
		{ L"1.1.1.1",   53,    TCP, N_Connect, false, "公网 DNS 53（放行）" },
		{ L"93.184.216.34", 80, TCP, N_Connect, true, "公网 HTTP 80（明文，高危）" },

		// ---- listen：无差别高危 ----
		{ L"0.0.0.0",   4444,  TCP, N_Listen,  true,  "监听 4444（高危）" },
		{ L"0.0.0.0",   8080,  TCP, N_Listen,  true,  "监听任意端口（高危）" },

		// ---- bind：仅对外地址高危 ----
		{ L"127.0.0.1", 5000,  TCP, N_Bind,    false, "绑定回环（放行）" },
		{ L"0.0.0.0",   5000,  TCP, N_Bind,    true,  "绑定全部接口（高危）" },
		{ L"1.2.3.4",   5000,  TCP, N_Bind,    true,  "绑定公网地址（高危）" },

		// ---- accept：少见，判高危 ----
		{ L"1.2.3.4",   5000,  TCP, N_Accept,  true,  "接受外部连接（高危）" },

		// ---- DNS：永不判高危（纯情报）----
		{ L"evil.example.com", 0, 0, N_DnsQuery, false, "域名解析（只记录）" },
		{ L"www.baidu.com",    0, 0, N_DnsQuery, false, "正常域名解析（只记录）" },

		// ---- 基础设施端口（DNS/NTP/mDNS/DoT）：内网也不判高危 ----
		// ⚠️ 实机血泪：Edge 每次都往路由器 192.168.2.1:53 发 UDP；
		//    若按"内网地址"判 → 开浏览器即弹窗机关枪。
		{ L"192.168.2.1", 53,  UDP, N_SendTo,  false, "内网 DNS 53（放行）" },
		{ L"192.168.2.1", 53,  TCP, N_Connect, false, "内网 DNS TCP 53（放行）" },
		{ L"10.0.0.1",    53,  UDP, N_SendTo,  false, "内网 10. DNS（放行）" },
		{ L"8.8.8.8",     53,  UDP, N_SendTo,  false, "公网 DNS 53（放行）" },
		{ L"192.168.1.1", 5353, UDP, N_SendTo, false, "内网 mDNS 5353（放行）" },
		{ L"1.1.1.1",     853, TCP, N_Connect, false, "DoT 853（放行）" },
		{ L"192.168.1.1", 123, UDP, N_SendTo,  false, "内网 NTP 123（放行）" },

		// ---- 域名 + 敏感端口（域名本身不解析，纯文本匹配）----
		{ L"evil.example.com", 445, TCP, N_Connect, true, "域名 + 敏感端口（高危）" },
	};

	int failed = 0;
	for (const Case& c : cases) {
		const char* reason = R3ShieldCoreRules::NetworkRiskReason(c.addr, c.port, c.proto, c.op);
		bool got = (reason != nullptr);
		const char* mark = (got == c.expectHigh) ? "OK  " : "FAIL";
		if (got != c.expectHigh) failed++;
		printf("%s  op=%-2lu port=%-5lu %-18ls expect=%-5s got=%-5s  %-30s reason=%s\n",
			mark, c.op, c.port, c.addr, c.expectHigh ? "HIGH" : "norm",
			got ? "HIGH" : "norm", c.note, reason ? reason : "(null)");
	}

	// ---- 内网判定单独验 ----
	printf("\n[IsPrivateOrReservedAddress]\n");
	const struct { const wchar_t* a; bool e; } priv[] = {
		{ L"10.1.2.3", true }, { L"172.16.0.1", true }, { L"172.31.255.255", true },
		{ L"172.32.0.1", false }, { L"192.168.0.1", true }, { L"169.254.0.1", true },
		{ L"127.0.0.1", true }, { L"100.64.0.1", true }, { L"104.18.0.1", false },
		{ L"8.8.8.8", false }, { L"::1", true }, { L"fc00::1", true }, { L"fe80::1", true },
		{ L"2606:4700::1111", false },
	};
	for (const auto& p : priv) {
		bool got = R3ShieldCoreRules::IsPrivateOrReservedAddress(p.a);
		const char* mark = (got == p.e) ? "OK  " : "FAIL";
		if (got != p.e) failed++;
		printf("%s  %-20ls expect=%-5s got=%-5s\n", mark, p.a, p.e ? "priv" : "pub", got ? "priv" : "pub");
	}

	printf("\n[IsSensitivePort]\n");
	const struct { unsigned long p; bool e; } spt[] = {
		{ 445, true }, { 3389, true }, { 443, false }, { 8080, false }, { 22, true },
	};
	for (const auto& s : spt) {
		bool got = R3ShieldCoreRules::IsSensitivePort(s.p);
		const char* mark = (got == s.e) ? "OK  " : "FAIL";
		if (got != s.e) failed++;
		printf("%s  port=%-5lu expect=%-5s got=%-5s\n", mark, s.p, s.e ? "sens" : "norm", got ? "sens" : "norm");
	}

	printf("\n[IsInfrastructurePort]\n");
	const struct { unsigned long p; bool e; } inf[] = {
		{ 53, true }, { 853, true }, { 5353, true }, { 123, true },
		{ 443, false }, { 80, false }, { 445, false },
	};
	for (const auto& s : inf) {
		bool got = R3ShieldCoreRules::IsInfrastructurePort(s.p);
		const char* mark = (got == s.e) ? "OK  " : "FAIL";
		if (got != s.e) failed++;
		printf("%s  port=%-5lu expect=%-5s got=%-5s\n", mark, s.p, s.e ? "infra" : "norm", got ? "infra" : "norm");
	}

	printf("\n%s  失败 %d\n", failed == 0 ? "全部通过" : "存在失败", failed);
	return failed;
}
