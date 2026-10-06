//
// R3ShieldCore hive 级操作探针。
//
// regtest.exe 验证的是"键级"API（NtCreateKey / NtSetValueKey ...），
// 这个工具验证新补的"hive 级"API：NtSaveKey / NtRestoreKey / NtLoadKey /
// NtUnloadKey / NtReplaceKey / NtSetInformationKey / NtFlushKey。
//
// 这些调用都直接吃 ntdll 导出，不经过 advapi32 —— 因为 advapi32 里
// 没有对应的高层封装（RegSaveKeyEx 是最接近的，但为了直击目标就用原生调用）。
//
// 关键：本 exe 必须放在 C:\Windows 之外，才会被判为"非系统程序"。
//
// 用法：
//   hiveprobe            全部跑一遍
//   hiveprobe save       只跑 NtSaveKeyEx（导出 HKCU\Software\R3ShieldCoreTest）
//   hiveprobe flush      只跑 NtFlushKey
//   hiveprobe setinfo    只跑 NtSetInformationKey（改最后写入时间）
//   hiveprobe load       只跑 NtLoadKey（需要 SeRestorePrivilege，通常失败）
//   hiveprobe restore    只跑 NtRestoreKey
//   hiveprobe prepare    只准备一个可导出的键（不调用敏感 API）
//   hiveprobe open       只读打开已存在的键，然后跑全部新 API。
//                        BLOCK 模式下建键会被拦，用它验证"新 API 被拦"
//                        而不是"开键被拦"。
//   hiveprobe hold <秒>  在引擎注入前先拿到键句柄，等 <秒> 秒后再调用新 API。
//                        注意：引擎会在几秒内注入所有存量进程，
//                        所以这个模式的窗口很窄，一般用 open 更方便。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>

typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_PRIVILEGE_NOT_HELD
#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#endif

// OBJECT_ATTRIBUTES，自己定义一份避免牵进 winternl.h
struct P_UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

struct P_OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	P_UNICODE_STRING* ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
};

// KeySetInformationClass 实测结论（见 setinfoprobe.cpp）：
//   class 1 (KeyWriteTimeInformation) 要求缓冲区【正好 4 字节】，
//   传 8 字节会得到 STATUS_INFO_LENGTH_MISMATCH(0xC0000004)。
//   所以这里的结构体是一个 ULONG，不是 LARGE_INTEGER —— 文档里没写清楚，
//   是靠实测确认的。
struct P_KEY_WRITE_TIME
{
	ULONG LastWriteTime; // 秒（相对 1601-01-01 的时间，单位由内核解释）
};

typedef NTSTATUS(NTAPI* NtSaveKeyEx_t)(HANDLE, HANDLE, ULONG);
typedef NTSTATUS(NTAPI* NtFlushKey_t)(HANDLE);
typedef NTSTATUS(NTAPI* NtSetInformationKey_t)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtLoadKey_t)(P_OBJECT_ATTRIBUTES*, P_OBJECT_ATTRIBUTES*);
typedef NTSTATUS(NTAPI* NtUnloadKey_t)(P_OBJECT_ATTRIBUTES*);
typedef NTSTATUS(NTAPI* NtRestoreKey_t)(HANDLE, HANDLE, ULONG);
typedef NTSTATUS(NTAPI* NtReplaceKey_t)(P_OBJECT_ATTRIBUTES*, HANDLE, P_OBJECT_ATTRIBUTES*);

static NtSaveKeyEx_t pNtSaveKeyEx;
static NtFlushKey_t pNtFlushKey;
static NtSetInformationKey_t pNtSetInformationKey;
static NtLoadKey_t pNtLoadKey;
static NtUnloadKey_t pNtUnloadKey;
static NtRestoreKey_t pNtRestoreKey;
static NtReplaceKey_t pNtReplaceKey;

static void InitUnicodeString(P_UNICODE_STRING* s, PCWSTR text)
{
	s->Length = (USHORT)(wcslen(text) * sizeof(WCHAR));
	s->MaximumLength = s->Length + sizeof(WCHAR);
	s->Buffer = const_cast<PWSTR>(text);
}

static void InitObjectAttributes(P_OBJECT_ATTRIBUTES* oa, P_UNICODE_STRING* name)
{
	memset(oa, 0, sizeof(*oa));
	oa->Length = sizeof(*oa);
	oa->ObjectName = name;
	oa->Attributes = 0x00000040; // OBJ_CASE_INSENSITIVE
}

static void Report(const char* operation, NTSTATUS status)
{
	const char* note = "";
	if (status == STATUS_ACCESS_DENIED) {
		note = "   [被 R3ShieldCore 拦截]";
	}
	else if (status == STATUS_PRIVILEGE_NOT_HELD) {
		note = "   [缺少特权 —— 本机未提权或未启用备份/还原特权]";
	}
	else if (status >= 0) {
		note = "   [系统放行]";
	}

	printf("%-28s -> 0x%08lX%s\n", operation, (unsigned long)status, note);
}

static bool PrepareKey(HKEY* outKey)
{
	HKEY key = nullptr;
	DWORD disposition = 0;
	LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest", 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
	if (status != ERROR_SUCCESS) {
		printf("准备测试键失败: %ld\n", status);
		return false;
	}

	RegSetValueExW(key, L"Seed", 0, REG_SZ,
		reinterpret_cast<const BYTE*>(L"seed"), sizeof(L"seed"));

	*outKey = key;
	return true;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	const char* mode = (argc > 1) ? argv[1] : "";
	// 无参数 / open / hold 三个模式都会把全部 API 跑一遍，
	// 区别只在于"句柄是怎么拿到的"。
	const bool runAll = (mode[0] == '\0') ||
		(_stricmp(mode, "open") == 0) ||
		(_stricmp(mode, "hold") == 0);

	printf("R3ShieldCore Hive 级操作探针 (pid=%lu)\n", GetCurrentProcessId());
	{
		WCHAR path[MAX_PATH] = {};
		DWORD size = _countof(path);
		if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &size)) {
			printf("镜像路径: %ls\n", path);
		}
	}
	printf("----------------------------------------\n");

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	pNtSaveKeyEx = reinterpret_cast<NtSaveKeyEx_t>(GetProcAddress(ntdll, "NtSaveKeyEx"));
	pNtFlushKey = reinterpret_cast<NtFlushKey_t>(GetProcAddress(ntdll, "NtFlushKey"));
	pNtSetInformationKey = reinterpret_cast<NtSetInformationKey_t>(GetProcAddress(ntdll, "NtSetInformationKey"));
	pNtLoadKey = reinterpret_cast<NtLoadKey_t>(GetProcAddress(ntdll, "NtLoadKey"));
	pNtUnloadKey = reinterpret_cast<NtUnloadKey_t>(GetProcAddress(ntdll, "NtUnloadKey"));
	pNtRestoreKey = reinterpret_cast<NtRestoreKey_t>(GetProcAddress(ntdll, "NtRestoreKey"));
	pNtReplaceKey = reinterpret_cast<NtReplaceKey_t>(GetProcAddress(ntdll, "NtReplaceKey"));

	printf("ntdll 导出: SaveKeyEx=%s FlushKey=%s SetInformationKey=%s\n",
		pNtSaveKeyEx ? "有" : "无",
		pNtFlushKey ? "有" : "无",
		pNtSetInformationKey ? "有" : "无");
	printf("ntdll 导出: LoadKey=%s UnloadKey=%s RestoreKey=%s ReplaceKey=%s\n",
		pNtLoadKey ? "有" : "无",
		pNtUnloadKey ? "有" : "无",
		pNtRestoreKey ? "有" : "无",
		pNtReplaceKey ? "有" : "无");
	printf("----------------------------------------\n");

	HKEY key = nullptr;

	// hold 模式：引擎注入前先拿句柄。BLOCK 模式下建键会被拒，
	// 只有这样才能测到"新 API 本身被拦"。
	if (_stricmp(mode, "hold") == 0) {
		int holdSeconds = (argc > 2) ? atoi(argv[2]) : 12;

		DWORD disposition = 0;
		LSTATUS createStatus = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest", 0, nullptr,
			REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE | KEY_SET_VALUE, nullptr, &key, &disposition);
		printf("注入前建键: %ld%s\n", createStatus,
			createStatus == ERROR_SUCCESS ? "" : "   (失败就不用继续了)");

		if (createStatus != ERROR_SUCCESS) {
			return 1;
		}

		printf("已持有句柄，等 %d 秒让引擎注入...\n", holdSeconds);
		for (int i = 0; i < holdSeconds; i++) {
			Sleep(1000);
			printf("  %d/%d\n", i + 1, holdSeconds);
		}

		printf("\n注入应已生效，现在用【注入前拿到的句柄】调用新 API：\n");
		// 落到下面的通用测试流程
	}
	else if (_stricmp(mode, "open") == 0) {
		// BLOCK 模式下最实用的验证路径：
		// 键已经由 prepare 建好，这里只做【只读打开】——
		// 只读打开不会被拦（R3ShieldCore 只拦截带写意图的打开），
		// 于是能拿到句柄去调用需要写权限之外的新 API。
		//
		// 注意 NtSaveKeyEx 导出 hive 只需要 KEY_READ，所以这条路走得通；
		// NtSetInformationKey 需要 KEY_SET_VALUE，会被拦 —— 这也是有效结论。
		LSTATUS openStatus = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreTest", 0,
			KEY_READ, &key);
		printf("只读打开已有键: %ld%s\n", openStatus,
			openStatus == ERROR_SUCCESS ? "" : "   (先跑 hiveprobe prepare 建键)");

		if (openStatus != ERROR_SUCCESS) {
			return 1;
		}
	}
	else {
		if (!PrepareKey(&key)) {
			return 1;
		}

		if (_stricmp(mode, "prepare") == 0) {
			RegCloseKey(key);
			printf("已准备好 HKCU\\Software\\R3ShieldCoreTest。\n");
			return 0;
		}
	}

	// --- NtFlushKey：不改变内容，只强制刷盘。只应被记录，不应被拦。---
	if (runAll || _stricmp(mode, "flush") == 0) {
		NTSTATUS status = pNtFlushKey(key);
		Report("NtFlushKey", status);
	}

	// --- NtSetInformationKey：改"最后写入时间"（class 1，正好 4 字节）。---
	if (runAll || _stricmp(mode, "setinfo") == 0) {
		P_KEY_WRITE_TIME info = {};
		info.LastWriteTime = 0; // 0 是合法值（会被规范到某个下限），过长/超范围会报 INVALID_PARAMETER

		NTSTATUS status = pNtSetInformationKey(key, 1, &info, sizeof(info));
		Report("NtSetInformationKey(时间)", status);
	}

	// --- NtSaveKeyEx：把键导成 hive 文件。---
	if (runAll || _stricmp(mode, "save") == 0) {
		WCHAR tempPath[MAX_PATH];
		GetTempPathW(_countof(tempPath), tempPath);
		wcscat_s(tempPath, L"r3shieldcore-hiveprobe.hiv");

		HANDLE file = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			printf("创建导出文件失败: %lu\n", GetLastError());
		}
		else {
			NTSTATUS status = pNtSaveKeyEx(key, file, 2); // 2 = REG_STANDARD_FORMAT
			Report("NtSaveKeyEx(导出 hive)", status);
			CloseHandle(file);
			DeleteFileW(tempPath);
		}
	}

	// --- NtLoadKey：把 hive 挂到注册表树上。需要 SeRestorePrivilege。---
	if (runAll || _stricmp(mode, "load") == 0) {
		P_UNICODE_STRING targetName;
		P_UNICODE_STRING sourceName;
		InitUnicodeString(&targetName, L"\\Registry\\Machine\\Software\\R3ShieldCoreHiveProbe");
		InitUnicodeString(&sourceName, L"\\??\\C:\\nonexistent-r3shieldcore-probe.hiv");

		P_OBJECT_ATTRIBUTES targetKey = {};
		P_OBJECT_ATTRIBUTES sourceFile = {};
		InitObjectAttributes(&targetKey, &targetName);
		InitObjectAttributes(&sourceFile, &sourceName);

		NTSTATUS status = pNtLoadKey(&targetKey, &sourceFile);
		Report("NtLoadKey(挂载 hive)", status);

		// 顺手试一下卸载
		NTSTATUS unloadStatus = pNtUnloadKey(&targetKey);
		Report("NtUnloadKey(卸载 hive)", unloadStatus);
	}

	// --- NtRestoreKey：用文件内容覆盖现有键。---
	if (runAll || _stricmp(mode, "restore") == 0) {
		WCHAR tempPath[MAX_PATH];
		GetTempPathW(_countof(tempPath), tempPath);
		wcscat_s(tempPath, L"r3shieldcore-hiveprobe-restore.hiv");

		HANDLE file = CreateFileW(tempPath, GENERIC_READ, 0, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			// 没有现成 hive 文件就造一个：先导出自己再恢复，路径最短。
			HANDLE out = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (out == INVALID_HANDLE_VALUE) {
				printf("创建临时 hive 失败: %lu\n", GetLastError());
			}
			else {
				pNtSaveKeyEx(key, out, 2);
				CloseHandle(out);

				file = CreateFileW(tempPath, GENERIC_READ, 0, nullptr,
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			}
		}

		if (file != INVALID_HANDLE_VALUE) {
			NTSTATUS status = pNtRestoreKey(key, file, 0);
			Report("NtRestoreKey(覆盖键)", status);
			CloseHandle(file);
		}

		DeleteFileW(tempPath);
	}

	// --- NtReplaceKey：原子替换，是 RestoreKey 的底层实现。---
	if (runAll || _stricmp(mode, "replace") == 0) {
		P_UNICODE_STRING newFileName;
		P_UNICODE_STRING backupName;
		InitUnicodeString(&newFileName, L"\\??\\C:\\nonexistent-r3shieldcore-probe.hiv");
		InitUnicodeString(&backupName, L"\\??\\C:\\nonexistent-r3shieldcore-backup.hiv");

		P_OBJECT_ATTRIBUTES newFile = {};
		P_OBJECT_ATTRIBUTES backupFile = {};
		InitObjectAttributes(&newFile, &newFileName);
		InitObjectAttributes(&backupFile, &backupName);

		NTSTATUS status = pNtReplaceKey(&newFile, key, &backupFile);
		Report("NtReplaceKey(原子替换)", status);
	}

	RegCloseKey(key);
	printf("----------------------------------------\n");
	printf("完成。\n");
	return 0;
}
