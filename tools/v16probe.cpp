//
// v16probe.cpp - 验证 bypass 判据（签名 + 目录）是否生效。
//
// 用途：在 `%SystemRoot%\Temp\`（用户可写子目录）里跑，确认本进程
// **没有**被 bypass（即挂上了 hook），从而证明 v16 的收紧生效。
//
// 怎么"证明挂上了 hook"：**看自己进程里有没有加载 R3ShieldCore 注入 DLL**。
//   全局注入 DLL 只对"未被 bypass"的进程注入 —— 只要它在，就说明
//   ComputeBypass 返回了 false（挂 hook）；反之说明被 bypass。
//   这比"做一次注册表写、去日志里翻"更直接，也不依赖日志刷盘时序。
//
// 模式：
//   check —— 枚举自己的模块，报有没有 r3shieldcore-lib.dll
//   write —— 做一次无害注册表写（观察日志用）
//   sleep —— 只挂起，供外部观察
//
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "psapi.lib")

// 自己的进程里有没有加载 R3ShieldCore 注入 DLL。
static bool HasR3ShieldCoreInjected()
{
	HMODULE mods[1024] = {};
	DWORD needed = 0;
	if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
		return false;
	}

	const DWORD count = needed / sizeof(HMODULE);
	for (DWORD i = 0; i < count; ++i) {
		wchar_t name[MAX_PATH] = {};
		if (GetModuleBaseNameW(GetCurrentProcess(), mods[i], name, _countof(name)) > 0) {
			if (_wcsicmp(name, L"r3shieldcore-lib.dll") == 0) {
				return true;
			}
		}
	}

	return false;
}

int wmain(int argc, wchar_t** argv)
{
	const wchar_t* mode = (argc > 1) ? argv[1] : L"check";

	wchar_t path[MAX_PATH * 2] = {};
	if (GetModuleFileNameW(nullptr, path, _countof(path)) == 0) {
		wcscpy_s(path, L"(unknown)");
	}

	printf("[v16probe] pid=%lu mode=%ls\n", GetCurrentProcessId(), mode);
	printf("[v16probe] image=%ls\n", path);

	const bool hooked = HasR3ShieldCoreInjected();
	printf("[v16probe] injected=%s  -> %s\n",
		hooked ? "YES" : "NO",
		hooked ? "未 bypass（挂了 hook）" : "被 bypass（没挂 hook）");

	if (wcscmp(mode, L"sleep") == 0) {
		printf("[v16probe] sleeping 30s...\n");
		fflush(stdout);
		Sleep(30000);
		return hooked ? 0 : 2;
	}

	if (wcscmp(mode, L"write") == 0) {
		HKEY key = nullptr;
		LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER,
			L"Software\\R3ShieldCoreV16Probe", 0, nullptr,
			REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
		if (st == ERROR_SUCCESS) {
			const wchar_t* val = L"v16-probe";
			st = RegSetValueExW(key, L"Probe", 0, REG_SZ,
				reinterpret_cast<const BYTE*>(val),
				static_cast<DWORD>((wcslen(val) + 1) * sizeof(wchar_t)));
			RegCloseKey(key);
			printf("[v16probe] RegSetValueEx status=%ld (0=OK)\n", st);
		} else {
			printf("[v16probe] RegCreateKeyEx failed status=%ld\n", st);
		}
	}

	fflush(stdout);
	Sleep(500);
	return hooked ? 0 : 2;
}
