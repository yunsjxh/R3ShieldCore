//
// v19probe.cpp - 验证 v19 新增注册表规则（打印机 / WinRT / COM+ / 自启补盲）
// 在**真实引擎**里能否判出高危。
//
// 原理：写几个**无害的临时子键**到新规则覆盖的路径下（用 R3ShieldCoreProbe
// 作为子键名，跑完即删），然后去引擎日志里找对应的 HIGH 行。
//
// ⚠️ 为什么不用"看返回码"来验证：本轮 `mode=log`（全放行）下返回码
//    不会变 —— 规则层只影响**高危标记**（日志里的 [危] / HIGH），
//    不影响放行与否。所以验证要看日志，不看返回码。
//
// 用法：
//   v19probe.exe        —— 写全部探针键（不删）
//   v19probe.exe clean  —— 删除全部探针键
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace
{
	// 每个探针：根键 + 子路径（都会再拼上 \R3ShieldCoreProbe）。
	struct Target
	{
		HKEY root;
		PCWSTR path;
		const char* label;
	};

	// ⚠️ 只写**我们自己的** R3ShieldCoreProbe 子键，绝不碰既有内容；
	//    探针键本身无害（空键 + 一个字符串值），跑完可一键清掉。
	const Target kTargets[] = {
		// ① 打印机驱动面
		{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors\\R3ShieldCoreProbe", "打印机端口监视器" },
		{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\R3ShieldCoreProbe", "打印提供程序" },
		{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors\\R3ShieldCoreProbe", "打印处理器" },

		// ② WinRT / Appx
		{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\R3ShieldCoreProbe", "Appx 包注册" },
		{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\ActivatableClasses\\R3ShieldCoreProbe", "WinRT 可激活类" },

		// ③ COM+ 目录
		{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\COM3\\Catalog\\R3ShieldCoreProbe", "COM+ 目录" },

		// ④ 自启补盲
		{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks\\R3ShieldCoreProbe", "ShellExecute 钩子" },
		{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\{R3ShieldCore-Probe-0000-0000-000000000000}", "BHO 注入" },
		{ HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\R3ShieldCoreProbe", "Active Setup" },
		{ HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\R3ShieldCoreProbe", "安全提供程序" },
	};

	constexpr PCWSTR kValueName = L"Probe";
	constexpr WCHAR kValueData[] = L"v19probe";

	int CreateOne(const Target& t)
	{
		HKEY key = nullptr;
		const LSTATUS st = RegCreateKeyExW(t.root, t.path, 0, nullptr,
			REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &key, nullptr);
		if (st != ERROR_SUCCESS) {
			printf("  [CREATE-FAIL] %-22s status=%ld\n", t.label, (long)st);
			return 0;
		}

		const LSTATUS st2 = RegSetValueExW(key, kValueName, 0, REG_SZ,
			reinterpret_cast<const BYTE*>(kValueData),
			static_cast<DWORD>((wcslen(kValueData) + 1) * sizeof(WCHAR)));
		RegCloseKey(key);

		printf("  [%s] %-22s create=OK set=%ld\n",
			st2 == ERROR_SUCCESS ? "WRITE-OK" : "SET-FAIL", t.label, (long)st2);
		return 1;
	}

	int DeleteOne(const Target& t)
	{
		// 先删值再删键（其实 RegDeleteTree 一把梭也可以）。
		const LSTATUS st = RegDeleteTreeW(t.root, t.path);
		printf("  [DEL] %-22s status=%ld\n", t.label, (long)st);
		return 1;
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	const bool clean = (argc > 1 && _stricmp(argv[1], "clean") == 0);

	printf("=== v19probe: %s ===\n", clean ? "清理" : "写入探针键");
	printf("(mode=log 下不会拦，验证方式是看引擎日志里的高危标记)\n\n");

	for (const Target& t : kTargets) {
		if (clean) {
			DeleteOne(t);
		} else {
			CreateOne(t);
		}
	}

	printf("\n");
	return 0;
}
