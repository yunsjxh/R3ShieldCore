//
// probe_ask.cpp —— 用 VM 日志里的**真实键路径**直接问规则层：
//                 「这条在 block_all 下应该弹窗、还是直接拒？」
//
// 目的：VM 日志（2026-09-30 20:38~20:39）里 `OneDrive.exe` 写
//       `key=Software` / `key=Software\Microsoft\OneDrive` 等，
//       全部是 `REG BLOCK`。按代码 `ShouldAskInsteadOfBlockAll` 应该返回 true
//       （→ 弹窗）才对。这里把每条 key 都喂进去，看实际返回什么。
//
// 同时也打 IsHighRiskRegistry 的结果，定位是"高危表命中"还是"前缀表命中"。

#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool ShouldAskInsteadOfBlockAll(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
	bool IsHighRiskRegistry(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
}

// 照 R3ShieldCore::Op 声明顺序（r3shieldcore_shared.h）
enum ProbeOp
{
	OpCreateKey = 1,
	OpOpenKey = 2,
	OpSetValueKey = 3,
	OpDeleteKey = 4,
	OpDeleteValueKey = 5,
	OpRenameKey = 6,
	OpFlushKey = 7,
	OpQueryValueKey = 8,
	OpEnumerateKey = 9,
	OpEnumerateValueKey = 10,
	OpQueryKey = 11,
	OpSetInformationKey = 12,
};

static void One(PCWSTR key, ULONG op, const char* opName)
{
	const bool ask = R3ShieldCoreRules::ShouldAskInsteadOfBlockAll(key, L"SomeValue", op);
	const bool risk = R3ShieldCoreRules::IsHighRiskRegistry(key, L"SomeValue", op);

	printf("  %-62S  %-16s  risk=%-3s  ask=%-5s => %s\n",
		key, opName,
		risk ? "YES" : "no",
		ask ? "ASK" : "BLOCK",
		ask ? "问（应弹窗）" : "不问（直接拒）");
}

int main()
{
	setlocale(LC_ALL, ".UTF8");

	printf("=== VM 日志里的真实键（OneDrive.exe，20:38~20:39）===\n");

	// 日志里出现的形态：`key=Software` / `key=Software\Microsoft\OneDrive`
	// —— 这些是**相对路径**（NtCreateKey 拿不到 hive 时的形态）。
	One(L"Software", OpCreateKey, "CreateKey");
	One(L"Software", OpSetValueKey, "SetValueKey");
	One(L"Software\\Microsoft\\OneDrive", OpCreateKey, "CreateKey");
	One(L"Software\\Microsoft\\OneDrive", OpSetValueKey, "SetValueKey");
	One(L"UpdateBinary", OpOpenKey, "OpenKey");

	printf("\n=== 同一批键，带完整 hive 前缀（对照）===\n");
	One(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\OneDrive", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\OneDrive", OpCreateKey, "CreateKey");

	printf("\n=== 应当『不问』的对照（必须 BLOCK）===\n");
	One(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Cryptography", OpSetInformationKey, "SetInfoKey");
	One(L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\CIMOM", OpCreateKey, "CreateKey");

	printf("\n=== 应当『问』的对照（第三方自用配置）===\n");
	One(L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\MyApp\\Settings", OpCreateKey, "CreateKey");

	// ---------------------------------------------------------------------
	// 2026-09-30 21:02 日志（vmtoolsd.exe）—— 三个反常形态
	// ---------------------------------------------------------------------
	printf("\n=== 21:02 日志：vmtoolsd.exe 的三个键（原文形态）===\n");
	One(L"System", OpCreateKey, "CreateKey");
	One(L"System\\CurrentControlSet\\Services\\Tcpip\\Parameters", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", OpCreateKey, "CreateKey");

	printf("\n=== 同三个键，补全 hive 前缀（对照：正常内核路径形态）===\n");
	One(L"\\REGISTRY\\MACHINE\\SYSTEM", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", OpCreateKey, "CreateKey");
	One(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters", OpCreateKey, "CreateKey");

	return 0;
}
