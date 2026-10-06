//
// R3ShieldCore 高危规则验证探针。
//
// 目的：验证 high_risk=1 时，命中高危规则的操作**无论 mode 是什么**都会
// 弹窗询问（log 模式下也一样），而未命中高危规则的普通操作仍然按 mode 走。
//
// 关键：本 exe 必须放在 C:\Windows 之外，否则被判为系统程序，一个 hook 都不挂。
//
// 用例：
//   1. [高危] HKCU\...\CurrentVersion\Run 写一个自启动项
//   2. [普通] HKCU\Software\R3ShieldCoreTest 写一个普通值（对照）
//   3. [高危] 往 C:\Windows\System32 下建一个文件（需提权）
//   4. [高危] 往 hosts 追加内容（需提权）
//   5. [普通] 往 %TEMP% 同级用户目录写一个普通文件（对照）
//
// 用法：
//   hightest            全部用例（缺权限的会被跳过并提示）
//   hightest reg        只跑注册表用例
//   hightest file       只跑文件用例
//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>

static void Report(const char* what, DWORD err)
{
	const char* tag = "";
	if (err == ERROR_ACCESS_DENIED) {
		tag = "   [被拦截]";
	} else if (err == ERROR_SUCCESS) {
		tag = "";
	}
	printf("%-46s -> %lu%s\n", what, err, tag);
}

static bool IsElevated()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
	TOKEN_ELEVATION elev = {};
	DWORD size = sizeof(elev);
	bool ok = GetTokenInformation(token, TokenElevation, &elev, size, &size) && elev.TokenIsElevated;
	CloseHandle(token);
	return ok;
}

// ------------------------------------------------------------------
// 注册表用例
// ------------------------------------------------------------------

static void CaseRunKey()
{
	printf("\n--- [高危] 自启动项 Run 键 ---\n");
	HKEY key = nullptr;
	DWORD disposition = 0;
	LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER,
		L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, &disposition);
	Report("RegCreateKeyEx ...\\CurrentVersion\\Run", (DWORD)status);
	if (status != ERROR_SUCCESS) return;

	status = RegSetValueExW(key, L"R3ShieldCoreHighTest", 0, REG_SZ,
		(const BYTE*)L"calc.exe", (DWORD)((wcslen(L"calc.exe") + 1) * sizeof(WCHAR)));
	Report("RegSetValueEx R3ShieldCoreHighTest", (DWORD)status);

	// 收尾：删掉，别真的留一个自启动项
	status = RegDeleteValueW(key, L"R3ShieldCoreHighTest");
	Report("RegDeleteValue R3ShieldCoreHighTest", (DWORD)status);
	RegCloseKey(key);
}

static void CaseNormalKey()
{
	printf("\n--- [普通] 普通用户键（对照） ---\n");
	HKEY key = nullptr;
	DWORD disposition = 0;
	LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER,
		L"Software\\R3ShieldCoreNormalTest",
		0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, &disposition);
	Report("RegCreateKeyEx ...\\R3ShieldCoreNormalTest", (DWORD)status);
	if (status != ERROR_SUCCESS) return;

	status = RegSetValueExW(key, L"PlainValue", 0, REG_SZ,
		(const BYTE*)L"hello", (DWORD)((wcslen(L"hello") + 1) * sizeof(WCHAR)));
	Report("RegSetValueEx PlainValue", (DWORD)status);

	status = RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreNormalTest");
	Report("RegDeleteKey ...\\R3ShieldCoreNormalTest", (DWORD)status);
	RegCloseKey(key);
}

// ------------------------------------------------------------------
// 文件用例
// ------------------------------------------------------------------

static void CaseSystem32()
{
	printf("\n--- [高危] System32 下建文件 ---\n");
	WCHAR path[MAX_PATH];
	swprintf_s(path, L"C:\\Windows\\System32\\R3ShieldCoreHighTest.txt");

	HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		Report("CreateFile C:\\Windows\\System32\\...", GetLastError());
		return;
	}
	Report("CreateFile C:\\Windows\\System32\\...", ERROR_SUCCESS);
	DWORD written = 0;
	WriteFile(h, "test", 4, &written, nullptr);
	Report("WriteFile", GetLastError());
	CloseHandle(h);

	DeleteFileW(path);
}

static void CaseHosts()
{
	printf("\n--- [高危] hosts 文件 ---\n");
	HANDLE h = CreateFileW(L"C:\\Windows\\System32\\drivers\\etc\\hosts",
		FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		Report("CreateFile hosts (append)", GetLastError());
		return;
	}
	Report("CreateFile hosts (append)", ERROR_SUCCESS);
	DWORD written = 0;
	WriteFile(h, "\r\n", 2, &written, nullptr);
	Report("WriteFile hosts", GetLastError());
	CloseHandle(h);
}

static void CaseNormalFile()
{
	printf("\n--- [普通] 用户数据目录（对照） ---\n");
	WCHAR path[MAX_PATH];
	swprintf_s(path, L"D:\\R3ShieldCoreNormalTest.txt");

	HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		Report("CreateFile D:\\R3ShieldCoreNormalTest.txt", GetLastError());
		return;
	}
	Report("CreateFile D:\\R3ShieldCoreNormalTest.txt", ERROR_SUCCESS);
	DWORD written = 0;
	WriteFile(h, "plain", 5, &written, nullptr);
	Report("WriteFile D:\\R3ShieldCoreNormalTest.txt", GetLastError());
	CloseHandle(h);
	DeleteFileW(path);
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	// 输出不缓冲：探针可能被 BLOCK 卡住或被强杀，缓冲会丢最后几行。
	setvbuf(stdout, nullptr, _IONBF, 0);

	// argv[3] 给路径时把 stdout 重定向到该文件。
	// 提权运行时没法用 shell 重定向（安全策略拦 cmd /c ... > file），
	// 所以探针自己写文件，这样提权场景也能留证据。
	if (argc > 3 && argv[3][0]) {
		WCHAR widePath[MAX_PATH] = {};
		MultiByteToWideChar(CP_ACP, 0, argv[3], -1, widePath, _countof(widePath));
		FILE* out = nullptr;
		_wfreopen_s(&out, widePath, L"w", stdout);
	}

	const char* mode = (argc > 1) ? argv[1] : "all";
	// 第二参数：开跑前先睡 N 秒，给引擎留出注入时间。
	// 引擎启动后约 6 秒才注完存量进程，紧接着启动的探针容易被漏掉。
	int delaySeconds = (argc > 2) ? atoi(argv[2]) : 0;
	bool doReg = (strcmp(mode, "reg") == 0) || (strcmp(mode, "all") == 0);
	bool doFile = (strcmp(mode, "file") == 0) || (strcmp(mode, "all") == 0);

	printf("R3ShieldCore 高危规则探针 (pid=%lu)%s\n", GetCurrentProcessId(),
		IsElevated() ? "  [已提权]" : "  [普通权限]");
	{
		WCHAR path[MAX_PATH] = {};
		DWORD size = _countof(path);
		if (QueryFullProcessImageNameW(GetCurrentProcess(), 0, path, &size)) {
			printf("镜像路径: %ls\n", path);
		}
	}
	if (delaySeconds > 0) {
		printf("等待 %d 秒，让引擎完成注入...\n", delaySeconds);
		Sleep(delaySeconds * 1000);
	}
	printf("========================================\n");

	if (doReg) {
		CaseRunKey();
		CaseNormalKey();
	}
	if (doFile) {
		CaseSystem32();
		CaseHosts();
		CaseNormalFile();
	}

	printf("\n完成。\n");
	return 0;
}
