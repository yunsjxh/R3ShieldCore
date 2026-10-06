// hookcheck —— 直接检查某个进程里指定模块导出的首字节，判断 MinHook 是否装上。
//
// 背景：guard 的 LOG() 输出在被注入进程里，控制台看不到；HookCount() 也只能
//       进程内读。想从"外面"确认 hook 是否真的写进去了，最直接的办法就是
//       看函数入口的第一个字节是不是跳转指令。
//
// MinHook 的 detour 会把目标函数开头改写成 `jmp`（E9 rel32 / 或 FF 25 绝对跳），
// 有的还会先放一个 hot-patch 前导。所以判定规则：
//   - 首字节 E9 / FF / EB        → 已 hook（相对/绝对跳转）
//   - 首字节 8B / 48 / 4C / 40 ... → 大概率是原函数序言（未 hook）
//
// 用法： hookcheck.exe <模块名> <导出名> [更多 模块 导出 对...]
//        例：hookcheck.exe combase.dll CoCreateInstance ole32.dll CoCreateInstance
//
// 注意：本工具只读内存；对其它进程要用 ReadProcessMemory —— 这里先只支持
//       自身进程（探针自己就是被注入的进程，看自己最准）。

#include <windows.h>
#include <stdio.h>
#include <locale.h>

static void CheckOne(HMODULE mod, const char* modName, const char* fn)
{
	void* p = reinterpret_cast<void*>(GetProcAddress(mod, fn));
	if (!p) {
		printf("  %-16s!%-28s -> 导出不存在\n", modName, fn);
		return;
	}

	unsigned char b[8] = {};
	SIZE_T read = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), p, b, sizeof(b), &read) || read < 1) {
		printf("  %-16s!%-28s -> 读内存失败\n", modName, fn);
		return;
	}

	const bool jmpRel = (b[0] == 0xE9);
	const bool jmpShort = (b[0] == 0xEB);
	const bool jmpAbs = (b[0] == 0xFF && b[1] == 0x25);
	const bool hotpatch = (b[0] == 0x90 && b[1] == 0x90); // nop sled（部分 hook 引擎）

	const char* verdict = "未拦";
	if (jmpRel || jmpShort || jmpAbs) {
		verdict = "已拦";
	}
	else if (hotpatch) {
		verdict = "已拦(?)";
	}

	printf("  %-16s!%-28s %02X %02X %02X %02X  %s\n",
		modName, fn, b[0], b[1], b[2], b[3], verdict);
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	printf("R3ShieldCore hookcheck  (pid=%u)\n", GetCurrentProcessId());
	printf("等待 3s 让引擎完成注入...\n");
	Sleep(3000);

	if (argc >= 3) {
		// 显式指定模块/导出
		for (int i = 1; i + 1 < argc; i += 2) {
			HMODULE mod = LoadLibraryA(argv[i]);
			if (!mod) {
				printf("  %-16s -> 模块加载失败 err=%u\n", argv[i], GetLastError());
				continue;
			}
			CheckOne(mod, argv[i], argv[i + 1]);
		}
		return 0;
	}

	// 默认：查 v13 关心的全部挂载点
	printf("\n=== 导出型 hook（MinHook）===\n");
	struct { const char* mod; const char* fn; } kTargets[] = {
		{ "combase.dll",     "CoCreateInstance" },
		{ "combase.dll",     "CoCreateInstanceEx" },
		{ "combase.dll",     "CoGetClassObject" },
		{ "advapi32.dll",    "OpenProcessToken" },
		{ "advapi32.dll",    "DuplicateTokenEx" },
		{ "advapi32.dll",    "ImpersonateLoggedOnUser" },
		{ "advapi32.dll",    "SetThreadToken" },
		{ "advapi32.dll",    "AdjustTokenPrivileges" },
		{ "winmm.dll",       "waveInOpen" },
		{ "winmm.dll",       "mciSendCommandW" },
		{ "ntdll.dll",       "NtLoadDriver" },
		{ "advapi32.dll",    "CreateServiceW" },
		{ "advapi32.dll",    "StartServiceW" },
		{ "kernel32.dll",    "CreateProcessW" },
		{ "user32.dll",      "SetWindowsHookExW" },
		{ "gdi32.dll",       "BitBlt" },
		{ "kernel32.dll",    "LoadLibraryExW" },
	};
	for (const auto& t : kTargets) {
		HMODULE mod = LoadLibraryA(t.mod);
		if (!mod) {
			printf("  %-16s -> 模块加载失败\n", t.mod);
			continue;
		}
		CheckOne(mod, t.mod, t.fn);
	}

	printf("\ndone\n");
	return 0;
}
