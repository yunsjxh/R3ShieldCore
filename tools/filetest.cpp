//
// R3ShieldCore 文件行为验证探针。
//
// 和 regtest.cpp 同理：必须放在 C:\Windows 之外才会被判为"非系统程序"。
//
// 覆盖五类动作，全部落在目标目录下的临时文件上：
//   1. CreateFile 建新文件（真正新建，带 CREATE_NEW）
//   2. WriteFile   写内容
//   3. SetFileTime 改最后写入时间（时间戳伪造的典型动作）
//   4. MoveFile    改名 / 移动
//   5. DeleteFile  删除
//
// 用法：
//   filetest <目标目录>          完整链路（上面五步）
//   filetest <目标目录> hold <秒> 先拿句柄、等注入、再写（验证单点拦截）
//   filetest <目标目录> once      只建文件
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

static void Report(const char* operation, BOOL ok)
{
	DWORD error = ok ? 0 : GetLastError();
	printf("%-28s -> %s%s\n", operation, ok ? "OK" : "FAILED",
		ok ? "" : (error == ERROR_ACCESS_DENIED ? "   [被拦截]" : ""));
	if (!ok && error != ERROR_ACCESS_DENIED) {
		printf("%-28s    GetLastError=%lu\n", "", error);
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	WCHAR wideDirectory[MAX_PATH] = {};
	const WCHAR* directory = wideDirectory;
	if (argc > 1) {
		MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wideDirectory, _countof(wideDirectory));
	}
	else {
		// 默认落到当前用户的桌面下的一个子目录，肯定不是系统路径。
		DWORD length = GetEnvironmentVariable(L"USERPROFILE", wideDirectory, _countof(wideDirectory));
		if (length == 0 || length >= _countof(wideDirectory) - 32) {
			wcscpy_s(wideDirectory, L"C:\\R3ShieldCoreFileTest");
		}
		else {
			wcscat_s(wideDirectory, L"\\Desktop\\R3ShieldCoreFileTest");
		}
	}

	const char* mode = (argc > 2) ? argv[2] : "";
	bool hold = (_stricmp(mode, "hold") == 0);
	bool once = (_stricmp(mode, "once") == 0);
	int holdSeconds = (hold && argc > 3) ? atoi(argv[3]) : 12;

	printf("R3ShieldCore 文件行为探针 (pid=%lu)\n", GetCurrentProcessId());
	printf("目标目录: %ls\n", directory);
	printf("----------------------------------------\n");

	// 目标目录用 CreateDirectoryW 准备，它走的也是 NtCreateFile，
	// 但只在 Log 模式/未拦截时才会成功 —— 失败不算探针失败。
	if (!CreateDirectoryW(directory, nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
		printf("(目标目录创建失败，GetLastError=%lu，继续尝试直接建文件)\n", GetLastError());
	}

	WCHAR path[MAX_PATH] = {};
	WCHAR renamedPath[MAX_PATH] = {};
	swprintf_s(path, L"%s\\r3shieldcore_probe.txt", directory);
	swprintf_s(renamedPath, L"%s\\r3shieldcore_probe_renamed.txt", directory);

	HANDLE file = INVALID_HANDLE_VALUE;

	if (hold) {
		file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		Report("CreateFile (注入前)", file != INVALID_HANDLE_VALUE);
		if (file == INVALID_HANDLE_VALUE) {
			return 0;
		}

		printf("\n已持有可写句柄。等 %d 秒让引擎注入本进程...\n", holdSeconds);
		for (int i = 0; i < holdSeconds; i++) {
			Sleep(1000);
			printf("  %d/%d\n", i + 1, holdSeconds);
		}
		printf("\n注入应已生效，现在用【注入前就拿到的句柄】写：\n");

		DWORD written = 0;
		Report("WriteFile (注入后)", WriteFile(file, "probe", 5, &written, nullptr));
		CloseHandle(file);
		printf("----------------------------------------\n");
		return 0;
	}

	// ---- 1) 建文件 ----
	file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	Report("CreateFile (CREATE_ALWAYS)", file != INVALID_HANDLE_VALUE);

	if (file == INVALID_HANDLE_VALUE) {
		printf("\n创建被拒绝，后续步骤跳过。\n");
		return 0;
	}

	if (once) {
		CloseHandle(file);
		printf("----------------------------------------\n");
		printf("完成（once）。\n");
		return 0;
	}

	// ---- 2) 写内容 ----
	{
		const char payload[] = "r3shieldcore file probe";
		DWORD written = 0;
		Report("WriteFile", WriteFile(file, payload, sizeof(payload) - 1, &written, nullptr));
	}

	// ---- 3) 改时间戳（反取证的典型动作）----
	{
		FILETIME stamp = {};
		// 2000-01-01 附近的一个时间，明显不是"现在"。
		SYSTEMTIME fake = {};
		fake.wYear = 2000; fake.wMonth = 1; fake.wDay = 1;
		SystemTimeToFileTime(&fake, &stamp);
		Report("SetFileTime (伪造时间戳)",
			SetFileTime(file, nullptr, nullptr, &stamp));
	}

	CloseHandle(file);

	// ---- 4) 改名 / 移动 ----
	Report("MoveFile (改名)", MoveFileW(path, renamedPath));

	// ---- 5) 删除 ----
	Report("DeleteFile", DeleteFileW(renamedPath));

	printf("----------------------------------------\n");
	printf("完成。\n");
	return 0;
}
