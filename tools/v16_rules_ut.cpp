//
// v16_rules_ut.cpp - R3ShieldCoreRules v16「bypass 签名 + 目录双条件」单元测试。
//
// v16 把 ComputeBypass 从"只看 %SystemRoot%\ 目录前缀就放行"改成
// "**目录可信 + 微软签名** 才是系统程序（才 bypass）"。判据拆成三部分：
//
//   ① 目录是否落在 `%SystemRoot%\` 下的**用户可写子目录**
//      → IsInWritableWindowsSubdir（纯函数，本单测覆盖）
//   ② 文件有没有**有效签名**（WinVerifyTrust）
//      → registry_guard.cpp 里，碰系统 API，不进单测
//   ③ 签名者是不是**微软**
//      → IsMicrosoftSigner（纯函数，本单测覆盖）
//
// ⚠️ 为什么 ① 必须测：
//   绕过判据的经典方式就是把恶意程序丢进 `C:\Windows\Temp\` —— 路径前缀
//    以 `C:\Windows\` 开头，旧判据直接整进程放行（一个 hook 都不挂）。
//    名单写漏一个目录 = 留一个可利用的洞。这里把已知可写子目录逐条钉死。
//
// ⚠️ 为什么 ③ 要判"微软签名"：
//    需求原文：「System32 下未签名的、或**签名者非 Microsoft 的**、或来自
//    %SystemRoot%\Temp／可写子目录的，必须挂 hook。」
//    所以 System32 下**非微软签名**的组件（AMD/NVIDIA/Realtek 的 DLL）
//    也会挂 hook —— 这是有意为之的取舍：宁可多监控，也不放过"可信目录里
//    被换成非微软签名载荷"的情况。
//
//    判"以 Microsoft 开头"而不是全等，是因为微软签名主题名有多种写法
//    （"Microsoft Windows" / "Microsoft Corporation" / ...）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsInWritableWindowsSubdir(PCWSTR imagePath) noexcept;
	bool IsMicrosoftSigner(PCWSTR signerName) noexcept;
}

static int g_failed = 0;

static void Check(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-58s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm");
}

int main()
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	// ==================================================================
	// 1. 可写子目录判据 —— 命中 = 目录不可信 = 必须挂 hook
	// ==================================================================
	printf("=== 1. %s ===\n", "可写子目录判据（命中即不 bypass）");

	// ① 用户可写子目录 —— 必须命中（挂 hook），大小写都要认。
	Check("dir", "C:\\Windows\\Temp\\evil.exe（经典洞，必须挂）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\Temp\\evil.exe"), true);
	Check("dir", "c:\\windows\\temp\\evil.exe（小写也认）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"c:\\windows\\temp\\evil.exe"), true);
	Check("dir", "C:\\Windows\\TEMP\\EVIL.EXE（全大写也认）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\TEMP\\EVIL.EXE"), true);
	Check("dir", "C:\\Windows\\Tasks\\updater.exe（任务目录）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\Tasks\\updater.exe"), true);
	Check("dir", "C:\\Windows\\Prefetch\\x.exe（预取目录）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\Prefetch\\x.exe"), true);
	Check("dir", "C:\\Windows\\tracing\\x.exe",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\tracing\\x.exe"), true);
	Check("dir", "C:\\Windows\\LiveKernelReports\\x.exe",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\LiveKernelReports\\x.exe"), true);
	Check("dir", "C:\\Windows\\Logs\\x.exe",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\Logs\\x.exe"), true);
	Check("dir", "C:\\Windows\\Fonts\\sneaky.exe（字体目录历史可写）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\Fonts\\sneaky.exe"), true);
	Check("dir", "C:\\Windows\\Web\\Wallpaper\\x.exe",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\Web\\Wallpaper\\x.exe"), true);
	Check("dir", "C:\\Windows\\System32\\spool\\drivers\\color\\x.exe",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\System32\\spool\\drivers\\color\\x.exe"), true);
	Check("dir", "C:\\Windows\\ServiceProfiles\\x.exe",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\ServiceProfiles\\x.exe"), true);

	// ② 可信系统目录 —— 不得命中（否则正常系统程序被误伤挂 hook）。
	Check("dir", "C:\\Windows\\System32\\kernel32.dll（可信）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\System32\\kernel32.dll"), false);
	Check("dir", "C:\\Windows\\explorer.exe（可信）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\explorer.exe"), false);
	Check("dir", "C:\\Windows\\SysWOW64\\ntdll.dll（可信）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\SysWOW64\\ntdll.dll"), false);
	Check("dir", "C:\\Windows\\WinSxS\\x.dll（可信）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\WinSxS\\x.dll"), false);
	Check("dir", "C:\\Windows\\System32\\drivers\\x.sys（可信）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\System32\\drivers\\x.sys"), false);

	// ③ 片段匹配不能"撞车"：`\Temp\` 不能命中 `\Template\`。
	Check("dir", "C:\\Windows\\System32\\Template\\x.exe（不含 \\Temp\\ 段）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\System32\\Template\\x.exe"), false);
	Check("dir", "C:\\Windows\\System32\\LogsBackup\\x.exe（不含 \\Logs\\ 段）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L"C:\\Windows\\System32\\LogsBackup\\x.exe"), false);

	// ④ 空 / 空指针 —— 不得崩，返回 false。
	Check("dir", "空字符串（不得崩）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(L""), false);
	Check("dir", "nullptr（不得崩）",
		R3ShieldCoreRules::IsInWritableWindowsSubdir(nullptr), false);

	// ==================================================================
	// 2. 微软签名者判据
	// ==================================================================
	printf("\n=== 2. %s ===\n", "微软签名者判据");

	Check("signer", "Microsoft Windows（典型）",
		R3ShieldCoreRules::IsMicrosoftSigner(L"Microsoft Windows"), true);
	Check("signer", "Microsoft Corporation",
		R3ShieldCoreRules::IsMicrosoftSigner(L"Microsoft Corporation"), true);
	Check("signer", "Microsoft Windows Publisher",
		R3ShieldCoreRules::IsMicrosoftSigner(L"Microsoft Windows Publisher"), true);
	Check("signer", "Microsoft Component Publisher",
		R3ShieldCoreRules::IsMicrosoftSigner(L"Microsoft Component Publisher"), true);
	Check("signer", "microsoft windows（小写也认）",
		R3ShieldCoreRules::IsMicrosoftSigner(L"microsoft windows"), true);

	// ⚠️ 非微软签名者 —— 不得命中（这些进程仍 bypass，不挂 hook）。
	Check("signer", "NVIDIA Corporation（可信目录，放行）",
		R3ShieldCoreRules::IsMicrosoftSigner(L"NVIDIA Corporation"), false);
	Check("signer", "Realtek Semiconductor Corp.",
		R3ShieldCoreRules::IsMicrosoftSigner(L"Realtek Semiconductor Corp."), false);
	Check("signer", "Microsoftish Evil Corp.（不能前缀撞车）",
		R3ShieldCoreRules::IsMicrosoftSigner(L"Microsoftish Evil Corp."), false);
	Check("signer", "空字符串",
		R3ShieldCoreRules::IsMicrosoftSigner(L""), false);
	Check("signer", "nullptr（不得崩）",
		R3ShieldCoreRules::IsMicrosoftSigner(nullptr), false);

	printf("\n=== 全部通过  失败 %d ===\n", g_failed);
	return g_failed == 0 ? 0 : 1;
}
