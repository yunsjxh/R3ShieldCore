//
// v20_rules_ut.cpp - R3ShieldCoreRules v20「bypass 改为具体文件路径白名单」单元测试。
//
// v20 把 ComputeBypass 从「目录（%SystemRoot%\）+ 微软签名」改成
// 「**具体文件路径白名单** + 微软签名」—— System32 下**未列出的**文件
// （哪怕微软签名）也挂 hook。
//
// 本单测覆盖规则层的纯函数：
//   · IsWhitelistedSystemImage —— 路径是否命中具体文件白名单
//（签名部分 IsTrustedSystemImage 碰系统 API，在 registry_guard.cpp，不进单测。）
//
// ⚠️ 为什么必须测：
//    bypass = 零开销，也 = 一个 hook 都不挂。白名单**多一条**就多一个被
//    伪造/滥用面（虽然还有签名兜底），**少一条**则系统进程被挂 hook →
//    行为异常或日志雪崩。这里把边界逐条钉死。
//
// ⚠️ 关键回归点：
//   1. 白名单**必须是精确全路径**，不能是目录前缀 —— `System32\` 下任意
//      未列出的 .exe/.dll 都必须不命中（这正是 v20 的核心收紧）。
//   2. `\SystemRoot\` / `/` / 大小写 形态都要正确归一化后命中。
//   3. 路径**尾部多一段**（`smss.exe.bak`）、**前缀不同**（`C:\Other\`）
//      不得误命中。
//   4. `System32` 与 `SysWOW64` 是两个不同条目（WOW64 重定向），各自独立。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsWhitelistedSystemImage(PCWSTR imagePath) noexcept;
	bool IsInWritableWindowsSubdir(PCWSTR imagePath) noexcept;
}

static int g_failed = 0;

static void Check(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-58s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "WHITE" : "hook", got ? "WHITE" : "hook");
}

static bool Wl(PCWSTR path) { return R3ShieldCoreRules::IsWhitelistedSystemImage(path); }
static bool Ww(PCWSTR path) { return R3ShieldCoreRules::IsInWritableWindowsSubdir(path); }

int main()
{
	setlocale(LC_ALL, ".UTF8");

	printf("=== 1. 白名单核心系统进程（应命中）===\n");
	Check("core", "services.exe", Wl(L"C:\\Windows\\System32\\services.exe"), true);
	Check("core", "lsass.exe", Wl(L"C:\\Windows\\System32\\lsass.exe"), true);
	Check("core", "svchost.exe", Wl(L"C:\\Windows\\System32\\svchost.exe"), true);
	Check("core", "winlogon.exe", Wl(L"C:\\Windows\\System32\\winlogon.exe"), true);
	Check("core", "wininit.exe", Wl(L"C:\\Windows\\System32\\wininit.exe"), true);
	Check("core", "csrss.exe", Wl(L"C:\\Windows\\System32\\csrss.exe"), true);
	Check("core", "smss.exe", Wl(L"C:\\Windows\\System32\\smss.exe"), true);
	Check("core", "dwm.exe", Wl(L"C:\\Windows\\System32\\dwm.exe"), true);
	Check("core", "runtimebroker.exe", Wl(L"C:\\Windows\\System32\\runtimebroker.exe"), true);
	Check("core", "explorer.exe", Wl(L"C:\\Windows\\explorer.exe"), true);

	printf("\n=== 2. ★ v20 核心收紧：System32 下未列出的文件不命中 ===\n");
	Check("tight", "notepad.exe（未列入）", Wl(L"C:\\Windows\\System32\\notepad.exe"), false);
	Check("tight", "cmd.exe（未列入）", Wl(L"C:\\Windows\\System32\\cmd.exe"), false);
	Check("tight", "kernel32.dll（未列入，即使微软签名）", Wl(L"C:\\Windows\\System32\\kernel32.dll"), false);
	Check("tight", "任意未列出 dll", Wl(L"C:\\Windows\\System32\\evil_or_benign.dll"), false);
	Check("tight", "System32 子目录任意 exe", Wl(L"C:\\Windows\\System32\\drivers\\foo.sys"), false);

	printf("\n=== 3. ★ 形态归一化（\\SystemRoot\\ / 正斜杠 / 大小写）===\n");
	Check("norm", "\\SystemRoot\\System32\\services.exe", Wl(L"\\SystemRoot\\System32\\services.exe"), true);
	Check("norm", "正斜杠 C:/Windows/System32/lsass.exe", Wl(L"C:/Windows/System32/lsass.exe"), true);
	Check("norm", "全大写盘符 C:\\WINDOWS\\SYSTEM32\\SVCHOST.EXE", Wl(L"C:\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"), true);
	Check("norm", "小写盘符 c:\\windows\\system32\\winlogon.exe", Wl(L"c:\\windows\\system32\\winlogon.exe"), true);
	Check("norm", "混合 D 盘（非 C）也应展开匹配", Wl(L"D:\\Windows\\System32\\services.exe"), true);

	printf("\n=== 4. ★ 段边界 / 后缀不得误命中 ===\n");
	Check("bound", "smss.exe.bak（尾部多段）", Wl(L"C:\\Windows\\System32\\smss.exe.bak"), false);
	Check("bound", "notservices.exe（前缀不同）", Wl(L"C:\\Windows\\System32\\notservices.exe"), false);
	Check("bound", "services.exe 在别的目录", Wl(L"C:\\Other\\services.exe"), false);
	Check("bound", "services.exe 在 Temp 下", Wl(L"C:\\Windows\\Temp\\services.exe"), false);
	Check("bound", "services 无扩展名", Wl(L"C:\\Windows\\System32\\services"), false);

	printf("\n=== 5. ★ System32 vs SysWOW64 独立 ===\n");
	Check("wow", "SysWOW64\\services.exe", Wl(L"C:\\Windows\\SysWOW64\\services.exe"), true);
	Check("wow", "SysWOW64\\lsass.exe", Wl(L"C:\\Windows\\SysWOW64\\lsass.exe"), true);
	Check("wow", "SysWOW64\\notepad.exe（未列）", Wl(L"C:\\Windows\\SysWOW64\\notepad.exe"), false);

	printf("\n=== 6. 商店应用 / 第三方进程不在白名单 ===\n");
	Check("other", "Program Files 下第三方 exe", Wl(L"C:\\Program Files\\App\\app.exe"), false);
	Check("other", "用户目录 exe", Wl(L"C:\\Users\\a\\evil.exe"), false);
	Check("other", "WindowsApps 商店应用", Wl(L"C:\\Program Files\\WindowsApps\\Pkg\\app.exe"), false);

	printf("\n=== 7. 与可写子目录判据的配合（② 双保险）===\n");
	Check("combo", "Temp 下命中可写子目录", Ww(L"C:\\Windows\\Temp\\x.exe"), true);
	Check("combo", "System32 根不在可写子目录", Ww(L"C:\\Windows\\System32\\services.exe"), false);
	Check("combo", "spool\\drivers 是可写子目录", Ww(L"C:\\Windows\\System32\\spool\\drivers\\x.dll"), true);

	printf("\n=== 8. 边界 / 空输入 ===\n");
	Check("edge", "空串", Wl(L""), false);
	Check("edge", "nullptr", Wl(nullptr), false);
	Check("edge", "只有盘符", Wl(L"C:"), false);
	Check("edge", "只有 Windows", Wl(L"C:\\Windows"), false);

	printf("\n=== 全部通过 ===  失败 %d\n", g_failed);
	return g_failed == 0 ? 0 : 1;
}
