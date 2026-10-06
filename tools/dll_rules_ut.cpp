//
// dll_rules_ut.cpp - R3ShieldCoreRules DLL 加载/劫持高危规则单元测试。
//
// 直接链 r3shieldcore_rules.cpp 的目标文件 + channel_stub.cpp（提供 Policy 桩）。
//
// 覆盖点（对齐 v10 的三条实测教训）：
//   - 手工映射（manualMap=true 或 op=ManualMap）→ 高危，且**与路径无关**
//   - 用户可写目录（Temp/AppData/Downloads/ProgramData…）→ 高危
//   - AppData\Local\ 兜底 + 白名单例外（Programs/Microsoft/Packages/CrashDumps）→ 不算高危
//   - 非系统目录但非可写（System32/Program Files/D:\Program Files…）→ 不算高危
//   - 空路径 → 不算高危
//
// ⚠️ 这个 UT 就是为了拦住 §10-20 那个坑（"非系统目录一律高危"噪音淹没真信号）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskDllLoad(const wchar_t* dllPath, unsigned long dllOp, bool manualMap) noexcept;
	const char* DllLoadRiskReason(const wchar_t* dllPath, unsigned long dllOp, bool manualMap) noexcept;
}

// DllLoadOp 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	D_LoadLibrary = 1,
	D_MapSection = 2,
	D_ManualMap = 3,
};

struct Case
{
	const wchar_t* path;
	unsigned long op;
	bool manualMap;
	bool expectHigh;
	const char* note;
};

int wmain()
{
	setlocale(LC_ALL, "");

	const Case cases[] = {
		// ---- 手工映射：与路径无关，一律高危 ----
		{ L"",                     D_MapSection, true,  true,  "手工映射（空路径也高危）" },
		{ L"C:\\Windows\\System32\\kernel32.dll", D_MapSection, true, true, "手工映射（系统路径也高危）" },
		{ L"C:\\Windows\\System32\\kernel32.dll", D_ManualMap,  false, true, "op=ManualMap 即高危" },

		// ---- 用户可写目录：高危 ----
		{ L"C:\\Users\\v\\AppData\\Local\\Temp\\evil.dll",   D_LoadLibrary, false, true, "Temp（白加黑）" },
		{ L"C:\\Windows\\Temp\\payload.dll",                 D_LoadLibrary, false, true, "Windows\\Temp" },
		{ L"C:\\Users\\v\\Downloads\\dropper.dll",           D_LoadLibrary, false, true, "下载目录" },
		{ L"C:\\ProgramData\\Malware\\x.dll",                D_LoadLibrary, false, true, "ProgramData" },
		{ L"C:\\Users\\Public\\share\\x.dll",                D_LoadLibrary, false, true, "公共用户目录" },
		{ L"C:\\Users\\v\\AppData\\Roaming\\x.dll",          D_LoadLibrary, false, true, "Roaming" },
		{ L"C:\\Users\\v\\AppData\\LocalLow\\x.dll",         D_LoadLibrary, false, true, "LocalLow" },
		{ L"C:\\Users\\v\\AppData\\Local\\SomeApp\\x.dll",   D_LoadLibrary, false, true, "AppData\\Local 兜底" },
		{ L"C:\\$Recycle.Bin\\S-1-5\\x.dll",                 D_LoadLibrary, false, true, "回收站" },

		// ---- AppData\Local 白名单例外：不算高危 ----
		{ L"C:\\Users\\v\\AppData\\Local\\Programs\\Python\\python310.dll", D_LoadLibrary, false, false, "Local\\Programs（用户级安装）" },
		{ L"C:\\Users\\v\\AppData\\Local\\Microsoft\\Edge\\x.dll",          D_LoadLibrary, false, false, "Local\\Microsoft" },
		{ L"C:\\Users\\v\\AppData\\Local\\Packages\\App\\x.dll",            D_LoadLibrary, false, false, "Local\\Packages" },
		{ L"C:\\Users\\v\\AppData\\Local\\CrashDumps\\x.dll",               D_LoadLibrary, false, false, "Local\\CrashDumps" },

		// ---- 系统目录 / 自装目录：不算高危 ----
		{ L"C:\\Windows\\System32\\ntdll.dll",       D_LoadLibrary, false, false, "System32" },
		{ L"C:\\Windows\\SysWOW64\\user32.dll",      D_LoadLibrary, false, false, "SysWOW64" },
		{ L"C:\\Program Files\\App\\x.dll",          D_LoadLibrary, false, false, "系统 Program Files" },
		{ L"D:\\Program Files\\PowerShell\\7\\x.dll", D_LoadLibrary, false, false, "非系统盘 Program Files（实测噪音源）" },
		{ L"D:\\Program Files\\WorkBuddy\\x.dll",    D_LoadLibrary, false, false, "自装软件目录" },
		{ L"",                                       D_LoadLibrary, false, false, "空路径不判高危" },
	};

	int failed = 0;
	for (const Case& c : cases) {
		const char* reason = R3ShieldCoreRules::DllLoadRiskReason(c.path, c.op, c.manualMap);
		bool got = (reason != nullptr);
		const char* mark = (got == c.expectHigh) ? "OK  " : "FAIL";
		if (got != c.expectHigh) failed++;
		printf("%s  op=%lu manual=%d expect=%-5s got=%-5s  %-42s reason=%s\n",
			mark, c.op, c.manualMap ? 1 : 0, c.expectHigh ? "HIGH" : "norm",
			got ? "HIGH" : "norm", c.note, reason ? reason : "(null)");
	}

	// ---- 大小写不敏感（§10-17 铁律）----
	printf("\n[大小写不敏感]\n");
	const struct { const wchar_t* p; bool e; const char* n; } ci[] = {
		{ L"C:\\USERS\\V\\APPDATA\\LOCAL\\TEMP\\X.DLL", true,  "全大写 Temp" },
		{ L"c:\\windows\\temp\\x.dll",                  true,  "全小写 windows\\temp" },
		{ L"C:\\Users\\V\\AppData\\Local\\PROGRAMS\\x.dll", false, "大写白名单例外" },
	};
	for (const auto& t : ci) {
		bool got = R3ShieldCoreRules::IsHighRiskDllLoad(t.p, D_LoadLibrary, false);
		const char* mark = (got == t.e) ? "OK  " : "FAIL";
		if (got != t.e) failed++;
		printf("%s  expect=%-5s got=%-5s  %-26s %ls\n", mark, t.e ? "HIGH" : "norm",
			got ? "HIGH" : "norm", t.n, t.p);
	}

	printf("\n%s  失败 %d\n", failed == 0 ? "全部通过" : "存在失败", failed);
	return failed;
}
