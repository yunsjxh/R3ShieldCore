//
// v18_rules_ut.cpp - R3ShieldCoreRules v18「老 API 补盲 + AFD 直发」单元测试。
//
// 本轮补的是**两个此前完全裸奔的绕过面**：
//
//   ① 老 API 建进程 / 建线程
//        · NtCreateProcess（不是 Ex 变体）—— 不收 RTL_USER_PROCESS_PARAMETERS，
//          **拿不到镜像路径**。钩子侧 imagePath 恒为 NULL，如果判据照抄
//          NtCreateProcessEx 的「路径匹配」，就会走 `if (!imagePath) return nullptr;`
//          → 永远非高危 → 整个 hook 白挂（§10-33 静默降级）。
//          正解：改用**特征判据**（老 API + 无参数块 = 镂空/反射加载特征）。
//        · NtCreateThread（不是 Ex 变体）—— 同样显式收 ProcessHandle，
//          所以「目标进程 ≠ 当前进程」这条远程线程判据可以原样复用。
//
//   ② \Device\Afd 直发
//        · ws2_32 底下走 \Device\Afd，谁都能 CreateFile("\\.\Afd") +
//          DeviceIoControl(IOCTL_AFD_SEND / AFD_RECV / AFD_SEND_DATAGRAM)
//          把数据送出去，一个 ws2_32 reload 都不需要。
//          新增 NetOp::DeviceIo，复用出站判据，但**必须放在回环/基础设施
//          端口放行之后**，否则本机 socket 往返全部误报。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

#include <r3shieldcore/r3shieldcore_shared.h>
#include "r3shieldcore_rules.h"

static int g_failed = 0;

static void Check(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-62s expect=%-6s got=%-6s\n", mark, group, note,
		expect ? "YES" : "no", got ? "YES" : "no");
}

int main()
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	typedef R3ShieldCore::ProcessOp POp;
	typedef R3ShieldCore::ThreadOp TOp;
	typedef R3ShieldCore::NetOp NOp;

	// ==================================================================
	// 0. Op 值本身（防 §10-33：新 Op 必须真的存在且 Name() 认它）
	// ==================================================================
	printf("=== 0. 新 Op 值与前缀无冲突 ===\n");

	Check("abi", "ProcessOp::CreateLegacy == 7",
		((ULONG)POp::CreateLegacy == 7), true);
	Check("abi", "ThreadOp::CreateLegacy == 3",
		((ULONG)TOp::CreateLegacy == 3), true);
	Check("abi", "NetOp::DeviceIo == 7",
		((ULONG)NOp::DeviceIo == 7), true);

	// Name() 必须显式认识新 Op（掉进 default = 日志显示 "Unknown"）。
	Check("abi", "ProcessOpName(CreateLegacy) 不是 Unknown",
		(strcmp(R3ShieldCore::ProcessOpName((ULONG)POp::CreateLegacy), "Unknown") != 0), true);
	Check("abi", "ThreadOpName(CreateLegacy) 不是 Unknown",
		(strcmp(R3ShieldCore::ThreadOpName((ULONG)TOp::CreateLegacy), "Unknown") != 0), true);
	Check("abi", "NetOpName(DeviceIo) 不是 Unknown",
		(strcmp(R3ShieldCore::NetOpName((ULONG)NOp::DeviceIo), "Unknown") != 0), true);

	// ==================================================================
	// 1. ★ NtCreateProcess（老 API）—— 无路径也必须判高危
	// ==================================================================
	//
	// 这是本轮最核心的一条：老 API 拿不到路径，判据必须靠"特征"。
	// 对照组是 Create（有路径才判）。
	printf("\n=== 1. ★ NtCreateProcess 无路径特征（本轮修复）===\n");

	// ★ 关键：imagePath = NULL（NtCreateProcess 的真实情形）→ 仍判高危
	Check("legacy-proc", "★ CreateLegacy + 无路径 → 高危（本轮修复）",
		R3ShieldCoreRules::IsHighRiskProcessImage(nullptr, (ULONG)POp::CreateLegacy, 0), true);
	Check("legacy-proc", "★ CreateLegacy + 空路径 → 高危（本轮修复）",
		R3ShieldCoreRules::IsHighRiskProcessImage(L"", (ULONG)POp::CreateLegacy, 0), true);

	// 反向保护：普通 Create 无路径仍是"拿不到信息不判"（不能一刀切高危，
	// 否则所有 Create 事件全部变高危）。
	Check("legacy-proc", "普通 Create + 无路径 → 不判（对照组）",
		R3ShieldCoreRules::IsHighRiskProcessImage(nullptr, (ULONG)POp::Create, 0), false);

	// 老 API 若带路径（罕见），路径规则仍须命中。
	Check("legacy-proc", "CreateLegacy + 敏感路径 → 命中路径规则",
		R3ShieldCoreRules::IsHighRiskProcessImage(
			L"C:\\Windows\\Temp\\evil.exe", (ULONG)POp::CreateLegacy, 0), true);

	// 终止不该被新 Op 带入（Terminate 仍只记录）。
	Check("legacy-proc", "Terminate 仍不判高危（对照）",
		R3ShieldCoreRules::IsHighRiskProcessImage(nullptr, (ULONG)POp::Terminate, 0), false);

	// ==================================================================
	// 2. ★ NtCreateThread（老 API）—— 远程线程判据原样复用
	// ==================================================================
	printf("\n=== 2. ★ NtCreateThread 远程线程（本轮修复）===\n");

	// 跨进程 → 高危（与 Create 同判据）。
	Check("legacy-thr", "★ CreateLegacy 跨进程（target=1234, self=555）→ 高危",
		R3ShieldCoreRules::IsHighRiskThread(1234, 555, (ULONG)TOp::CreateLegacy), true);
	// 本进程 → 放行（存活前提）。
	Check("legacy-thr", "CreateLegacy 本进程（target=self）→ 不判",
		R3ShieldCoreRules::IsHighRiskThread(555, 555, (ULONG)TOp::CreateLegacy), false);
	// 与已有 Create 判据一致（防两条路径分叉）。
	Check("legacy-thr", "Create 跨进程 → 高危（对照，应与 Legacy 一致）",
		R3ShieldCoreRules::IsHighRiskThread(1234, 555, (ULONG)TOp::Create), true);
	Check("legacy-thr", "Terminate 不判（对照）",
		R3ShieldCoreRules::IsHighRiskThread(1234, 555, (ULONG)TOp::Terminate), false);

	// ==================================================================
	// 3. ★ \Device\Afd 直发（DeviceIo）—— 复用出站判据 + 不误报本机
	// ==================================================================
	//
	// ⚠️ 顺序铁律：回环 / 基础设施端口必须在 DeviceIo 判据**之前**放行。
	printf("\n=== 3. ★ \\Device\\Afd 直发（本轮修复）===\n");

	// ★ 本案唯一净收益：公网 + 非敏感 + 非明文端口 → 只有 DeviceIo 能判出来。
	//   443 是中性端口（既不在敏感表里，也不在明文表里）。
	Check("afd", "★ DeviceIo → 公网 443（非敏感非明文）→ 高危（本轮新增能力）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"203.0.113.9", 443, 6, (ULONG)NOp::DeviceIo), true);
	Check("afd", "★ DeviceIo → 公网 443 无端口信息 → 也判（行为即特征）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"203.0.113.9", 0, 6, (ULONG)NOp::DeviceIo), true);

	// ★ 反向保护（最关键）：本机回环走 AFD 是对内通信，绝不能报。
	Check("afd", "★ DeviceIo → 回环 127.0.0.1 → 放行（防空误报）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"127.0.0.1", 0, 6, (ULONG)NOp::DeviceIo), false);
	Check("afd", "★ DeviceIo → 回环 + 敏感端口 445 → 放行（顺序铁律）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"127.0.0.1", 445, 6, (ULONG)NOp::DeviceIo), false);
	Check("afd", "DeviceIo → 基础设施端口 53 → 放行",
		R3ShieldCoreRules::IsHighRiskNetwork(L"8.8.8.8", 53, 17, (ULONG)NOp::DeviceIo), false);

	// 内网地址走 AFD → 仍命中**原有内网规则**（刻意不区分是否走 AFD）。
	Check("afd", "设备地址走 AFD → 内网 192.168.1.10 仍判（与旧语义一致）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"192.168.1.10", 0, 6, (ULONG)NOp::DeviceIo), true);
	Check("afd", "设备地址走 AFD → 公网敏感端口 445 仍判（与旧语义一致）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"1.2.3.4", 445, 6, (ULONG)NOp::DeviceIo), true);
	// 拿不到远端地址 → 不判（可见性）。
	Check("afd", "DeviceIo → 无地址 → 不判",
		R3ShieldCoreRules::IsHighRiskNetwork(nullptr, 0, 6, (ULONG)NOp::DeviceIo), false);
	Check("afd", "DeviceIo → 空地址 → 不判",
		R3ShieldCoreRules::IsHighRiskNetwork(L"", 0, 6, (ULONG)NOp::DeviceIo), false);

	// 对照：同样输入换成 Connect 就是**放行** —— 证明"走 AFD"本身是新增信号。
	Check("afd", "Connect → 公网 443 无端口 → 放行（旧行为，对照组）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"203.0.113.9", 443, 6, (ULONG)NOp::Connect), false);
	Check("afd", "Connect → 公网 443 → 放行（旧行为，对照组）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"203.0.113.9", 443, 6, (ULONG)NOp::Connect), false);
	Check("afd", "Connect → 公网 445 → 高危（旧行为不变）",
		R3ShieldCoreRules::IsHighRiskNetwork(L"1.2.3.4", 445, 6, (ULONG)NOp::Connect), true);

	// ==================================================================
	// 4. 防回归：旧 Op 语义一字不动
	// ==================================================================
	printf("\n=== 4. 防回归（旧 Op 行为不变）===\n");

	Check("regress", "CreateLegacy 未被误当 Create 处理（无路径判据分叉）",
		R3ShieldCoreRules::IsHighRiskProcessImage(nullptr, (ULONG)POp::CreateLegacy, 0) !=
			R3ShieldCoreRules::IsHighRiskProcessImage(nullptr, (ULONG)POp::Create, 0), true);
	Check("regress", "DnsQuery 仍不判高危",
		R3ShieldCoreRules::IsHighRiskNetwork(L"8.8.8.8", 53, 17, (ULONG)NOp::DnsQuery), false);
	Check("regress", "Listen 仍无差别高危",
		R3ShieldCoreRules::IsHighRiskNetwork(nullptr, 0, 6, (ULONG)NOp::Listen), true);

	printf("\n%s  失败 %d\n", g_failed ? "=== 存在失败用例 ===" : "=== 全部通过 ===", g_failed);
	return g_failed;
}
