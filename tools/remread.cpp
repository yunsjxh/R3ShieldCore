//
// remread.cpp - 跨进程读取目标进程里某模块导出的首字节，判断 hook 是否挂上。
//
// 用途：验证 v16 bypass 收紧后，**可信目录 + 微软签名**的进程仍被 bypass
// （不挂 hook），而 Temp 下未签名的进程被挂 hook。hookcheck 只能读自身。
//
// 判据同 hookcheck：首字节 E9/EB/FF25 = 已 hook（MinHook detour）。
//
// 用法： remread.exe <pid>
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <tlhelp32.h>

struct Target { const wchar_t* mod; const char* fn; };

static const Target kTargets[] = {
	{ L"combase.dll",  "CoCreateInstance" },
	{ L"advapi32.dll", "OpenProcessToken" },
	{ L"ntdll.dll",    "NtLoadDriver" },
	{ L"advapi32.dll", "CreateServiceW" },
	{ L"kernel32.dll", "LoadLibraryExW" },
};

// 枚举目标进程模块，找指定模块基址（返回 0 = 未找到）。
static ULONGLONG FindRemoteModuleBase(DWORD pid, const wchar_t* moduleName)
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (snap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	MODULEENTRY32W me = {};
	me.dwSize = sizeof(me);
	ULONGLONG base = 0;

	if (Module32FirstW(snap, &me)) {
		do {
			if (_wcsicmp(me.szModule, moduleName) == 0) {
				base = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
				break;
			}
		} while (Module32NextW(snap, &me));
	}

	CloseHandle(snap);
	return base;
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2) {
		wprintf(L"用法: remread.exe <pid>\n");
		return 1;
	}

	DWORD pid = static_cast<DWORD>(_wtoi(argv[1]));
	HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!proc) {
		wprintf(L"OpenProcess 失败 err=%lu\n", GetLastError());
		return 1;
	}

	wchar_t imagePath[MAX_PATH * 2] = {};
	DWORD np = _countof(imagePath);
	if (QueryFullProcessImageNameW(proc, 0, imagePath, &np)) {
		wprintf(L"目标 pid=%lu\n    镜像=%ls\n", pid, imagePath);
	}

	wprintf(L"    r3shieldcore-lib.dll = %s\n",
		FindRemoteModuleBase(pid, L"r3shieldcore-lib.dll") ? L"已加载" : L"未加载");

	for (const Target& t : kTargets) {
		wchar_t modPath[MAX_PATH] = {};
		const ULONGLONG base = FindRemoteModuleBase(pid, t.mod);
		if (!base) {
			wprintf(L"  %-16ls -> 模块未加载\n", t.mod);
			continue;
		}

		// 本地加载同模块，用「本地导出地址 - 本地基址」得偏移，再加到远程基址。
		HMODULE localMod = LoadLibraryW(t.mod);
		if (!localMod) {
			wprintf(L"  %-16ls -> 本地加载失败\n", t.mod);
			continue;
		}

		void* localFn = reinterpret_cast<void*>(GetProcAddress(localMod, t.fn));
		if (!localFn) {
			wprintf(L"  %-16ls!%-24S -> 导出不存在\n", t.mod, t.fn);
			FreeLibrary(localMod);
			continue;
		}

		const ULONGLONG offset =
			reinterpret_cast<ULONGLONG>(localFn) - reinterpret_cast<ULONGLONG>(localMod);
		const ULONGLONG remoteFn = base + offset;

		unsigned char b[8] = {};
		SIZE_T read = 0;
		if (!ReadProcessMemory(proc, reinterpret_cast<void*>(remoteFn), b, sizeof(b), &read) || read < 1) {
			wprintf(L"  %-16ls!%-24S -> 读内存失败 err=%lu\n", t.mod, t.fn, GetLastError());
			FreeLibrary(localMod);
			continue;
		}

		const bool hooked = (b[0] == 0xE9) || (b[0] == 0xEB) || (b[0] == 0xFF && b[1] == 0x25);

		wprintf(L"  %-16ls!%-24S %02X %02X %02X %02X  %s\n",
			t.mod, t.fn, b[0], b[1], b[2], b[3],
			hooked ? L"已拦(hook已挂)" : L"未拦(bypass)");

		FreeLibrary(localMod);
	}

	CloseHandle(proc);
	return 0;
}
