//
// regnorm.cpp —— 实测 R3ShieldCore 注册表路径归一化的实际输入形态。
//
// 背景（v16 之后的 bypass 收紧发现的新洞）：
//   r3shieldcore_rules.cpp 的 NormalizeKey 只剥掉 `\REGISTRY\MACHINE\` 前缀，
//   剩下的相对路径直接拿去和 kRegistryRules 的前缀比。
//
//   但 Win32 API 路径和原生句柄路径归一化后**不是同一个字符串**：
//     HKLM\SAM\SAM              (Win32)
//       → \REGISTRY\MACHINE\SAM\SAM
//       → relative = "SAM\SAM"           ← 规则表里写的就是这个 ✓
//
//     NtSaveKey(句柄 = HKLM\SAM) (原生)
//       → NtQueryKey(KeyNameInformation) → \REGISTRY\MACHINE\SAM
//       → relative = "SAM"               ← 规则表里没有这条 ✗ 静默漏判
//
//   这个探针把 NtQueryKey(KeyNameInformation) 的真实返回逐个打出来，
//   用来确认"hive 级操作拿到的键路径到底长什么样"。
//
// 用法：
//   regnorm              打印一组有代表性的键的 NtQueryKey 结果
//   regnorm <完整KLM子路径>  只打印指定键（如 "SAM" / "SOFTWARE\Microsoft"）
//
// 独立编译（同 sigcheck / remread，按需手工编，不进 build.sh）：
//   bash -c 'cd "<仓库根>" && ... cl.exe -O2 -MT -EHsc -std:c++20 \
//     -source-charset:utf-8 -Fe"tools/regnorm.exe" "tools/regnorm.cpp" kernel32.lib'
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

typedef LONG NTSTATUS;

struct Q_KEY_NAME_INFORMATION
{
	ULONG NameLength;
	WCHAR Name[1];
};

typedef NTSTATUS(NTAPI* NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static NtQueryKey_t pNtQueryKey;

// 用原生方式打开一个 \REGISTRY\... 全路径，然后问内核它叫什么。
static void QueryAndPrint(PCWSTR fullPath)
{
	// 用 RegOpenKeyExW 打开不了 \REGISTRY\... 全路径（那要先开 \REGISTRY 根），
	// 所以改用 NtOpenKey。这里用最省事的方式：把全路径里的
	// \REGISTRY\MACHINE\ 换成 HKLM 前缀，交给 RegOpenKeyExW。
	// 但那样拿到的就是 Win32 路径 —— 不是我们要测的。
	//
	// 正确做法：自己 NtOpenKey 全路径。

	typedef NTSTATUS(NTAPI* NtOpenKey_t)(PHANDLE, ACCESS_MASK, PVOID);
	NtOpenKey_t pNtOpenKey = reinterpret_cast<NtOpenKey_t>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenKey"));

	struct USTR { USHORT Length, MaximumLength; PWSTR Buffer; };
	struct OATTRS { ULONG Length; HANDLE RootDirectory; USTR* ObjectName; ULONG Attributes; PVOID Sec; PVOID Sqos; };

	USTR name = {};
	name.Length = (USHORT)(wcslen(fullPath) * sizeof(WCHAR));
	name.MaximumLength = name.Length + sizeof(WCHAR);
	name.Buffer = const_cast<PWSTR>(fullPath);

	OATTRS oa = {};
	oa.Length = sizeof(oa);
	oa.ObjectName = &name;
	oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

	HANDLE key = nullptr;
	NTSTATUS st = pNtOpenKey(&key, KEY_READ, &oa);
	if (st < 0) {
		printf("  [打开失败 0x%08lX] %ls\n", (unsigned long)st, fullPath);
		return;
	}

	BYTE raw[4096] = {};
	ULONG got = 0;
	st = pNtQueryKey(key, 3 /* KeyNameInformation */, raw, sizeof(raw), &got);
	if (st < 0) {
		printf("  [查询失败 0x%08lX] %ls\n", (unsigned long)st, fullPath);
		CloseHandle(key);
		return;
	}

	auto* info = reinterpret_cast<Q_KEY_NAME_INFORMATION*>(raw);
	ULONG chars = info->NameLength / sizeof(WCHAR);
	// 手工 NUL 结尾方便打印
	WCHAR buf[2048] = {};
	if (chars >= _countof(buf)) chars = _countof(buf) - 1;
	memcpy(buf, info->Name, chars * sizeof(WCHAR));

	printf("  输入: %-52ls\n", fullPath);
	printf("  NtQueryKey 返回: %ls\n", buf);
	printf("  → 剥掉 \\REGISTRY\\MACHINE\\ 后的 relative: ");
	if (_wcsnicmp(buf, L"\\REGISTRY\\MACHINE\\", 18) == 0) {
		printf("%ls\n", buf + 18);
	}
	else {
		printf("(不是 MACHINE 前缀) %ls\n", buf);
	}
	printf("\n");

	CloseHandle(key);
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);
	pNtQueryKey = reinterpret_cast<NtQueryKey_t>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryKey"));

	printf("R3ShieldCore 注册表路径归一化实测 (pid=%lu)\n", GetCurrentProcessId());
	printf("========================================================\n\n");

	if (argc > 1) {
		// 把用户给的相对子路径拼成全路径
		WCHAR full[1024];
		swprintf_s(full, L"\\REGISTRY\\MACHINE\\%S", argv[1]);
		QueryAndPrint(full);
		return 0;
	}

	printf("---- 有键句柄的 hive 级操作会看到什么 ----\n");
	printf("(NtSaveKey / NtSaveKeyEx / NtRestoreKey / NtReplaceKey / NtSetInformationKey)\n\n");

	// 这几个是 hive 级操作的典型目标：拖 SAM、改服务、动 LSA。
	// 注意 "SAM" 和 "SAM\\SAM" 的差别 —— 规则表里写的是后者。
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SAM");
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SAM\\SAM");
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SECURITY");
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SECURITY\\Policy\\Secrets");
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services");
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
	QueryAndPrint(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options");

	printf("---- 对照：没有键句柄的 hive 操作看到的 ObjectName ----\n");
	printf("(NtLoadKey / NtLoadKeyEx / NtUnloadKey / NtUnloadKeyEx)\n\n");
	printf("  这几个的 KeyPath 直接来自调用方的 OBJECT_ATTRIBUTES->ObjectName，\n");
	printf("  典型写法是 `\\Registry\\Machine\\...`（与上面同形态）。\n\n");

	printf("结论：hive 级操作拿到的键路径可能是 **中间层级**（如 `SAM`），\n");
	printf("      而规则表里写的是**叶子层级**（如 `SAM\\SAM`）→ StartsWithNoMatch → 静默漏判。\n");
	return 0;
}
