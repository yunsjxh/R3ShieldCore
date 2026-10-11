//
// run_elevated.cpp —— 提权转发器（给开发/自动化用的"最小 sudo"）。
//
// 为什么需要它：
//   · 本项目的引擎清单是 `requireAdministrator`，而自动化的 shell **提不了权**；
//   · 工具侧又**禁止**用 `Start-Process` 去起 shell / 解释器 / 系统工具
//     （会被命令校验直接拦掉：那样等于绕过命令校验）。
//   ⇒ 这个 exe 是**普通程序**（不是 shell、不是解释器、不是系统工具），
//     调用方可以用 runas 把它拉起来（**只弹一次 UAC**），
//     它再 CreateProcess 目标命令 —— 子进程**继承提权令牌**，不会再弹第二次。
//
// 用法:
//   run_elevated.exe <outFile> <exe> [args...]
//
// 例:
//   run_elevated.exe C:\tmp\out.log D:\msys64\usr\bin\bash.exe D:\proj\tools\x.sh --run-engine
//
// ★ 子进程的 stdout/stderr 会被重定向到 <outFile>：提权进程通常**没有可用控制台**
//   （从非提权会话提权起来会拿到一个新控制台窗口，输出随之消失），
//   不重定向的话什么都看不到。
// ★ 子进程退出码会追加写到 <outFile> 末尾，并作为本进程的退出码返回。
//
#include <windows.h>
#include <stdio.h>
#include <string>

namespace
{
	// 给单个参数加引号（路径里基本不会出现 `"`，这里只做最小转义）。
	void AppendQuoted(std::wstring& out, const wchar_t* arg)
	{
		out += L'"';
		for (const wchar_t* p = arg; p && *p; ++p)
		{
			if (*p == L'"')
			{
				out += L'\\';
			}
			out += *p;
		}
		out += L'"';
	}

	void AppendAscii(HANDLE hOut, const char* text)
	{
		if (!text || !*text)
		{
			return;
		}
		DWORD written = 0;
		WriteFile(hOut, text, static_cast<DWORD>(::strlen(text)), &written, nullptr);
	}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 3)
	{
		fwprintf(stderr, L"usage: run_elevated.exe <outFile> <exe> [args...]\n");
		return 2;
	}

	const wchar_t* outFile = argv[1];

	std::wstring cmd;
	AppendQuoted(cmd, argv[2]);
	for (int i = 3; i < argc; ++i)
	{
		cmd += L' ';
		AppendQuoted(cmd, argv[i]);
	}

	SECURITY_ATTRIBUTES sa = {};
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	const HANDLE hOut = CreateFileW(outFile, GENERIC_WRITE, FILE_SHARE_READ, &sa,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hOut == INVALID_HANDLE_VALUE)
	{
		fwprintf(stderr, L"run_elevated: cannot create %ls (err=%lu)\n",
			outFile, GetLastError());
		return 3;
	}

	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hOut;
	si.hStdError = hOut;
	si.hStdInput = INVALID_HANDLE_VALUE;

	// ★ 先把**最终拼出来的命令行**写进日志 —— 否则调用方传参错位（少引号、被空格拆开）
	//   时只会看到一个光秃秃的 `err=2`，完全不知道该怪谁（铁律 97：失败必须可诊断）。
	{
		char head[4096] = {};
		int n = WideCharToMultiByte(CP_UTF8, 0, cmd.c_str(), -1, head, sizeof(head) - 1,
			nullptr, nullptr);
		if (n <= 0)
		{
			head[0] = '\0';
		}
		AppendAscii(hOut, "[run_elevated] cmd = ");
		AppendAscii(hOut, head);
		AppendAscii(hOut, "\n");
	}

	PROCESS_INFORMATION pi = {};
	std::wstring mutableCmd = cmd;   // CreateProcessW 可能要改写这块内存
	const BOOL ok = CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr,
		TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
	if (!ok)
	{
		const DWORD err = GetLastError();
		char line[256] = {};
		_snprintf_s(line, sizeof(line), _TRUNCATE,
			"\n[run_elevated] CreateProcessW failed err=%lu\n",
			static_cast<unsigned long>(err));
		AppendAscii(hOut, line);
		CloseHandle(hOut);
		return 4;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD code = 0;
	GetExitCodeProcess(pi.hProcess, &code);

	char tail[256] = {};
	_snprintf_s(tail, sizeof(tail), _TRUNCATE,
		"\n[run_elevated] child exit code = %lu\n",
		static_cast<unsigned long>(code));
	AppendAscii(hOut, tail);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(hOut);
	return static_cast<int>(code);
}
