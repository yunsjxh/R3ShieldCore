//
// R3ShieldCore 验证用的小工具。
//
// 关键：这个 exe 必须放在 C:\Windows 之外，才会被 R3ShieldCore 判定为
// "非系统程序"。reg.exe / powershell.exe 都在 System32 下，属于系统程序，
// 拿它们测什么都测不到。
//
// 用法：
//   regtest              建键 → 写值 → 删值 → 删键（完整链路）
//   regtest nocreate     跳过建键，直接以 KEY_WRITE 打开已存在的键
//   regtest hold <秒>    先在引擎注入前拿到可写句柄，等 <秒> 秒让引擎注入，
//                        再写值 —— 单独验证 NtSetValueKey 的拦截
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

static void Report(const char* operation, LSTATUS status)
{
	printf("%-24s -> %ld%s\n", operation, status,
		status == ERROR_ACCESS_DENIED ? "   [被拦截]" : "");
}

static ULONGLONG NowMs()
{
	return GetTickCount64();
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	const char* mode = (argc > 1) ? argv[1] : "";
	bool skipCreate = (_stricmp(mode, "nocreate") == 0);
	bool hold = (_stricmp(mode, "hold") == 0);
	bool once = (_stricmp(mode, "once") == 0);
	int holdSeconds = (hold && argc > 2) ? atoi(argv[2]) : 15;

	printf("R3ShieldCore 注册表行为探针 (pid=%lu)%s\n", GetCurrentProcessId(),
		skipCreate ? "  [nocreate]" : (hold ? "  [hold]" : (once ? "  [once]" : "")));
	{
		WCHAR path[MAX_PATH] = {};
		DWORD size = _countof(path);
		if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &size)) {
			printf("镜像路径: %ls\n", path);
		}
	}
	printf("----------------------------------------\n");

	HKEY key = nullptr;
	LSTATUS status;

	if (hold) {
		DWORD disposition = 0;
		status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest", 0, nullptr,
			REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
		Report("RegCreateKeyEx (注入前)", status);
		if (status != ERROR_SUCCESS) {
			return 0;
		}

		printf("\n已持有可写句柄。等 %d 秒让引擎注入本进程...\n", holdSeconds);
		for (int i = 0; i < holdSeconds; i++) {
			Sleep(1000);
			printf("  %d/%d\n", i + 1, holdSeconds);
		}
		printf("\n注入应已生效，现在用【注入前就拿到的句柄】写值：\n");

		status = RegSetValueExW(key, L"ProbeAfterInjection", 0, REG_SZ,
			reinterpret_cast<const BYTE*>(L"x"), sizeof(L"x"));
		Report("RegSetValueEx (注入后)", status);

		status = RegDeleteValueW(key, L"Seed");
		Report("RegDeleteValue (注入后)", status);

		RegCloseKey(key);
		printf("----------------------------------------\n");
		return 0;
	}

	if (skipCreate) {
		status = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest", 0,
			KEY_READ | KEY_WRITE, &key);
		Report("RegOpenKeyEx", status);
	}
	else {
		DWORD disposition = 0;
		ULONGLONG before = NowMs();
		status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest", 0, nullptr,
			REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
		printf("(RegCreateKeyEx 阻塞 %llu ms)\n", NowMs() - before);
		Report("RegCreateKeyEx", status);
	}

	if (status != ERROR_SUCCESS) {
		printf("\n打开/创建被拒绝，后续步骤跳过。\n");
		return 0;
	}

	if (once) {
		// 只做建键一步，用来验证"一次询问"的行为，不打扰用户。
		RegCloseKey(key);
		printf("----------------------------------------\n");
		printf("完成（once）。\n");
		return 0;
	}

	status = RegSetValueExW(key, L"Probe", 0, REG_SZ,
		reinterpret_cast<const BYTE*>(L"r3shieldcore"), sizeof(L"r3shieldcore"));
	Report("RegSetValueEx", status);

	status = RegDeleteValueW(key, L"Probe");
	Report("RegDeleteValue", status);

	RegCloseKey(key);

	status = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest");
	Report("RegDeleteKey", status);

	printf("----------------------------------------\n");
	printf("完成。\n");
	return 0;
}
