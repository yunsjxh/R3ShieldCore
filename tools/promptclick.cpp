//
// 验证用：找到引擎弹出的 R3ShieldCore 询问窗口，按控件 ID 点按钮。
//
// 用法: promptclick <引擎PID> <按钮ID|dump> [持续秒数]
//   1001 = 允许这一次
//   1002 = 拒绝这一次
//   1003 = 始终允许此程序
//   1004 = 始终拒绝此程序
//   dump = 只打印该进程的窗口树，不点击（用来排查找不到按钮的问题）
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>

namespace
{
	struct FindContext
	{
		DWORD enginePid;
		int buttonId;             // 按控件 ID 匹配；TaskDialog 里用不上（都是 0）
		const WCHAR* keywordText; // 按按钮文字匹配，实际走这条
		HWND dialog;
		HWND button;
	};

	struct DumpContext
	{
		DWORD enginePid;
		int count;
	};

	BOOL CALLBACK DumpChildProc(HWND hwnd, LPARAM lParam)
	{
		auto* context = reinterpret_cast<DumpContext*>(lParam);
		if (context->count > 120) {
			return TRUE;
		}

		WCHAR className[128] = {};
		WCHAR text[256] = {};
		GetClassNameW(hwnd, className, _countof(className));
		GetWindowTextW(hwnd, text, _countof(text));

		printf("      child class=%-22ls id=%-6d visible=%d text=%ls\n",
			className, GetDlgCtrlID(hwnd), IsWindowVisible(hwnd) ? 1 : 0, text);

		context->count++;
		return TRUE;
	}

	BOOL CALLBACK DumpTopProc(HWND hwnd, LPARAM lParam)
	{
		auto* context = reinterpret_cast<DumpContext*>(lParam);

		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid != context->enginePid) {
			return TRUE;
		}

		WCHAR className[128] = {};
		WCHAR text[256] = {};
		GetClassNameW(hwnd, className, _countof(className));
		GetWindowTextW(hwnd, text, _countof(text));

		printf("top   [%p] class=%-22ls visible=%d text=%ls\n",
			hwnd, className, IsWindowVisible(hwnd) ? 1 : 0, text);

		EnumChildWindows(hwnd, DumpChildProc, lParam);
		return TRUE;
	}

	BOOL CALLBACK EnumChildProc(HWND hwnd, LPARAM lParam)
	{
		auto* context = reinterpret_cast<FindContext*>(lParam);

		if (context->buttonId != 0 && GetDlgCtrlID(hwnd) == context->buttonId) {
			context->button = hwnd;
			return FALSE;
		}

		// TaskDialog 建出来的按钮控件 ID 全是 0，TASKDIALOG_BUTTON.nButtonID
		// 不会变成 Win32 控件 ID。所以只能按按钮文字找。
		if (context->keywordText) {
			WCHAR text[256] = {};
			GetWindowTextW(hwnd, text, _countof(text));
			if (text[0] != L'\0' && wcsstr(text, context->keywordText)) {
				context->button = hwnd;
				return FALSE;
			}
		}

		return TRUE;
	}

	BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
	{
		auto* context = reinterpret_cast<FindContext*>(lParam);

		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid != context->enginePid) {
			return TRUE;
		}

		if (!IsWindowVisible(hwnd)) {
			return TRUE;
		}

		// 不能用 GetDlgItem：它只找直接子窗口，而 TaskDialog 的按钮可能嵌在
		// 中间容器里。EnumChildWindows 会递归枚举所有后代。
		EnumChildWindows(hwnd, EnumChildProc, lParam);
		if (context->button) {
			context->dialog = hwnd;
			return FALSE;
		}

		return TRUE;
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	// 会被 taskkill 掉，输出不能缓冲。
	setvbuf(stdout, nullptr, _IONBF, 0);

	if (argc < 3) {
		printf("usage: promptclick <enginePid> <choice|dump> [seconds]\n");
		printf("  choice: allow | deny | allowalways | denyalways  (也可传数字控件 ID)\n");
		return 1;
	}

	DWORD enginePid = static_cast<DWORD>(strtoul(argv[1], nullptr, 10));

	if (_stricmp(argv[2], "dump") == 0) {
		DumpContext context = { enginePid, 0 };
		printf("=== window tree of pid %lu ===\n", enginePid);
		EnumWindows(DumpTopProc, reinterpret_cast<LPARAM>(&context));
		printf("=== %d child controls total ===\n", context.count);
		return 0;
	}

	struct Choice
	{
		const char* keyword;
		const WCHAR* buttonText;
	};

	const Choice choices[] = {
		{ "allow",       L"允许这一次" },
		{ "deny",        L"拒绝这一次" },
		{ "allowalways", L"始终允许" },
		{ "denyalways",  L"始终拒绝" },
	};

	int buttonId = 0;
	const WCHAR* buttonText = nullptr;

	for (const Choice& choice : choices) {
		if (_stricmp(argv[2], choice.keyword) == 0) {
			buttonText = choice.buttonText;
			break;
		}
	}

	if (!buttonText) {
		buttonId = atoi(argv[2]);
	}

	if (!buttonText && buttonId == 0) {
		printf("unknown choice: %s\n", argv[2]);
		return 1;
	}

	int seconds = (argc > 3) ? atoi(argv[3]) : 20;

	ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000;
	int clicked = 0;

	while (GetTickCount64() < deadline) {
		FindContext context = { enginePid, buttonId, buttonText, nullptr, nullptr };
		EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&context));

		if (context.button) {
			printf("found button [%ls], clicking\n", buttonText ? buttonText : L"(by id)");
			SendMessage(context.button, BM_CLICK, 0, 0);
			clicked++;
			Sleep(300);
		}
		else {
			Sleep(150);
		}
	}

	printf("total clicks = %d\n", clicked);
	return 0;
}
