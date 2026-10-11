// gui_preview_probe.cpp -- 给主程序的 `--gui-preview` 建一条**可复现**的核对通道。
//
// 为什么需要它
//   主程序一启动就全局注入，而开发机上禁止跑引擎（铁律 175）。于是
//   `--gui-preview`（v77）把"建窗但不初始化引擎"这条路开了出来 ——
//   可它自己**没有任何核对手段**：跑完只能靠人眼看。
//   本项目已经吃过"靠人眼 = 假绿"的亏（铁律 24/28），所以补这个探针。
//
// 做法（遵循 win32-selfdrawn-ui-verify 的三条硬约束）
//   1. 拉起**免提权**的 exe（同完整性级别，否则 UIPI 会静默丢输入/截不到）。
//   2. **从屏幕 DC** 取图，不用 PrintWindow —— 后者拿的是 DWM 合成缓存帧，
//      动态内容永远是"没变"，而且不少窗口直接给一张全黑。
//   3. 断言优先用**应用自己的日志**（确定性），像素只作辅助证据。
//      这里断言 `[adv] 页面已绘制 规则=3 ...` —— 它证明"这一页真被画到了"，
//      而"截到一张空窗口"与"页面没画"在图上分不开，只有日志能分开。
//
// 用法:
//   gui_preview_probe.exe <exePath> <tab> <outBmpPath> [advMode]
//     tab     = overview | log | process | config | ark | advanced
//     advMode = quiz(默认) | why | editor —— 只在 tab=advanced 时有意义
//               「高级」页有**三个互斥的界面状态**（闸门未过 / 刚全对 /
//               已解锁的编辑台），一个页签名看不全，靠它把三屏都截出来。
//
// 退出码: 0 = 全部判据通过；1 = 有判据失败；2 = 窗口没起来。

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>

namespace
{
	constexpr PCWSTR kClassName = L"R3ShieldCoreMainWindow";

	int g_pass = 0;
	int g_fail = 0;

	void Check(bool ok, const char* what)
	{
		printf("  [%s] %s\n", ok ? " OK " : "FAIL", what);
		if (ok) {
			++g_pass;
		}
		else {
			++g_fail;
		}
	}

	// 32 位 BMP（top-down，BGRA）。用 BMP 而不是 PNG：本探针**零依赖**，
	// 不引第三方编码器；转换交给脚本里的 Python（只用标准库 zlib）。
	bool SaveBmp32(const wchar_t* path, const BYTE* pixels, int width, int height)
	{
		const DWORD imageBytes = static_cast<DWORD>(width) * static_cast<DWORD>(height) * 4u;
		BITMAPFILEHEADER fileHeader = {};
		BITMAPINFOHEADER infoHeader = {};
		fileHeader.bfType = 0x4D42;   // "BM"
		fileHeader.bfOffBits = sizeof(fileHeader) + sizeof(infoHeader);
		fileHeader.bfSize = fileHeader.bfOffBits + imageBytes;
		infoHeader.biSize = sizeof(infoHeader);
		infoHeader.biWidth = width;
		infoHeader.biHeight = -height;   // 负 = top-down，与 DIB 内存布局一致
		infoHeader.biPlanes = 1;
		infoHeader.biBitCount = 32;
		infoHeader.biCompression = BI_RGB;
		infoHeader.biSizeImage = imageBytes;

		FILE* f = nullptr;
		if (_wfopen_s(&f, path, L"wb") != 0 || !f) {
			return false;
		}
		fwrite(&fileHeader, sizeof(fileHeader), 1, f);
		fwrite(&infoHeader, sizeof(infoHeader), 1, f);
		fwrite(pixels, 1, imageBytes, f);
		fclose(f);
		return true;
	}

	HWND g_found = nullptr;
	HWND FindWindowByClass()
	{
		g_found = nullptr;
		EnumWindows([](HWND hwnd, LPARAM) -> BOOL {
			WCHAR cls[128] = {};
			if (GetClassNameW(hwnd, cls, _countof(cls)) > 0
				&& wcscmp(cls, kClassName) == 0
				&& IsWindowVisible(hwnd)) {
				g_found = hwnd;
				return FALSE;
			}
			return TRUE;
		}, 0);
		return g_found;
	}

	std::wstring ExeDirectory(const std::wstring& exePath)
	{
		const size_t slash = exePath.find_last_of(L"\\/");
		return (slash == std::wstring::npos) ? L"." : exePath.substr(0, slash);
	}

	// 读日志（GBK）并转宽 —— 关键字是中文，必须转码后再找。
	bool LogContains(const std::wstring& path, const WCHAR* needle)
	{
		FILE* f = nullptr;
		const errno_t openErr = _wfopen_s(&f, path.c_str(), L"rb");
		if (openErr != 0 || !f) {
			printf("        [诊断] 日志打不开 err=%d 路径=%ls\n", static_cast<int>(openErr), path.c_str());
			return false;
		}
		std::string raw;
		char buf[4096];
		size_t n = 0;
		while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
			raw.append(buf, n);
		}
		fclose(f);
		if (raw.empty()) {
			printf("        [诊断] 日志是空的（exe 还没写？）\n");
			return false;
		}
		const int wideChars = MultiByteToWideChar(CP_ACP, 0, raw.c_str(),
			static_cast<int>(raw.size()), nullptr, 0);
		if (wideChars <= 0) {
			return false;
		}
		std::wstring wide(static_cast<size_t>(wideChars), L'\0');
		MultiByteToWideChar(CP_ACP, 0, raw.c_str(), static_cast<int>(raw.size()),
			&wide[0], wideChars);
		return wide.find(needle) != std::wstring::npos;
	}

	int Run(const std::wstring& exePath, const std::wstring& tab,
		const std::wstring& outBmp, const std::wstring& advMode)
	{
		// ---- 环境变量：让 exe 起来就停在指定页签 ----
		SetEnvironmentVariableW(L"R3SHIELDCORE_START_TAB", tab.c_str());

		// ★ v78：「高级」页有**三个互斥的界面状态**（闸门未过 / 刚全对 / 已解锁），
		//   光靠"停在 advanced 页签"只能截到第一屏。第 4 个参数把另外两屏
		//   也变成可截的 —— 否则"新加的编辑台长什么样"仍然只能靠人眼
		//   （铁律 24/28）。
		//     空串 / "quiz" -> 默认（闸门屏）
		//     "why"         -> 解析屏
		//     "editor"      -> 编辑台
		if (!advMode.empty() && advMode != L"quiz") {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_ADV", advMode.c_str());
		}
		else {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_ADV", nullptr);
		}

		// ---- 规则文件重定向到一个**临时文件**（先删掉，保证"来源=示例"）----
		//
		// ★ 为什么不直接用真实路径：那样这条判据会取决于这台机器的
		//   `%ProgramData%\R3 Shield Core\` 里有没有规则文件、有几条 ——
		//   换台机器就随机红。而且自动核对不该去读（更不该写）用户的真规则。
		const std::wstring previewRules = ExeDirectory(exePath) + L"\\r3shieldcore-rules-preview.txt";
		DeleteFileW(previewRules.c_str());
		SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_RULES", previewRules.c_str());

		// ---- 先删掉上一次的日志：否则断言可能被**上一轮**的行满足（假绿） ----
		const std::wstring logPath = ExeDirectory(exePath) + L"\\r3shieldcore-console.log";
		DeleteFileW(logPath.c_str());

		std::wstring cmdline = L"\"" + exePath + L"\" --gui-preview";
		std::vector<WCHAR> mutableCmd(cmdline.begin(), cmdline.end());
		mutableCmd.push_back(L'\0');

		STARTUPINFOW si = {};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(exePath.c_str(), mutableCmd.data(), nullptr, nullptr,
			FALSE, 0, nullptr, ExeDirectory(exePath).c_str(), &si, &pi)) {
			printf("[gui-preview-probe] CreateProcess 失败 err=%lu\n", GetLastError());
			return 2;
		}

		// ---- 等窗口出现（最多 15s）----
		HWND hwnd = nullptr;
		for (int i = 0; i < 150 && !hwnd; i++) {
			Sleep(100);
			hwnd = FindWindowByClass();
		}
		if (!hwnd) {
			printf("[gui-preview-probe] 窗口没出现（15s 超时）\n");
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return 2;
		}

		SetForegroundWindow(hwnd);
		Sleep(1500);   // 等首帧 + 页签切换生效

		// ---- 取窗口矩形（含边框，截图更像"真窗口"）----
		RECT wr = {};
		GetWindowRect(hwnd, &wr);
		const int width = wr.right - wr.left;
		const int height = wr.bottom - wr.top;

		RECT cr = {};
		GetClientRect(hwnd, &cr);
		printf("[gui-preview-probe] 窗口 %dx%d，客户区 %dx%d，页签=%ls\n",
			width, height, static_cast<int>(cr.right), static_cast<int>(cr.bottom), tab.c_str());

		// ---- 从**屏幕 DC** 抓图（不是 PrintWindow）----
		HDC screen = GetDC(nullptr);
		HDC mem = CreateCompatibleDC(screen);
		BITMAPINFO bi = {};
		bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bi.bmiHeader.biWidth = width;
		bi.bmiHeader.biHeight = -height;
		bi.bmiHeader.biPlanes = 1;
		bi.bmiHeader.biBitCount = 32;
		bi.bmiHeader.biCompression = BI_RGB;
		void* bits = nullptr;
		HBITMAP dib = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
		HGDIOBJ oldBmp = SelectObject(mem, dib);
		const BOOL blt = BitBlt(mem, 0, 0, width, height, screen,
			wr.left, wr.top, SRCCOPY);
		const DWORD bltErr = blt ? 0 : GetLastError();
		SelectObject(mem, oldBmp);
		DeleteDC(mem);
		ReleaseDC(nullptr, screen);

		Check(blt != FALSE, "从屏幕 DC 取图成功（BitBlt）");
		if (!blt) {
			printf("        BitBlt err=%lu —— 若为 5，先查是不是被某个安全软件拦了\n", bltErr);
		}

		// ---- 指纹：非白像素 + 紫色（Spoof 色）像素 ----
		int nonWhite = 0;
		int purple = 0;
		ULONGLONG checksum = 1469598103934665603ull;
		const BYTE* px = static_cast<const BYTE*>(bits);
		for (int y = 0; y < height; y++) {
			for (int x = 0; x < width; x++) {
				const BYTE* p = px + (static_cast<size_t>(y) * width + x) * 4;
				const BYTE b = p[0], g = p[1], r = p[2];
				if (r < 250 || g < 250 || b < 250) {
					++nonWhite;
				}
				// ColorSpoofed = RGB(123,31,162)：紫。给足容差（文字有抗锯齿）。
				if (r > 60 && r < 190 && g < 90 && b > 110 && b < 220 && b > r) {
					++purple;
				}
				checksum = (checksum ^ r) * 1099511628211ull;
				checksum = (checksum ^ g) * 1099511628211ull;
				checksum = (checksum ^ b) * 1099511628211ull;
			}
		}
		const double ratio = (width && height)
			? static_cast<double>(nonWhite) * 100.0 / (static_cast<double>(width) * height) : 0.0;
		printf("[gui-preview-probe] 指纹：非白=%d(%.1f%%) 紫=%d 校验和=%016llX\n",
			nonWhite, ratio, purple, checksum);

		if (bits) {
			SaveBmp32(outBmp.c_str(), px, width, height);
			printf("[gui-preview-probe] 截图 -> %ls\n", outBmp.c_str());
		}

		// ---- 判据 ----
		Check(width >= 1000 && height >= 600, "窗口尺寸合理（>=1000x600）");
		Check(ratio > 3.0, "画面上有内容（非白像素 > 3%）");
		if (tab == L"advanced") {
			// 紫色是 Spoof 的语义色：判定/改后两列都用它，出现即说明对照区画出来了。
			// ⚠️ 这一条只在**编辑台**那一屏成立 —— 闸门屏/解析屏根本没有对照区，
			//    所以它必须跟着状态走，否则"闸门屏没有紫色"会被当成失败。
			if (advMode == L"editor") {
				Check(purple > 0, "画面上有 Spoof 紫像素（改前/改后对照区渲染出来了）");
			}
		}

		// ★ 先把被测进程结束掉，**再**读它的日志。
		//
		//   为什么不能边跑边读：exe 把 stdout 重定向到了 r3shieldcore-console.log
		//   并**一直持有**那个句柄，第二个进程再打开会拿到 err=13（EACCES）——
		//   实测过，表现为"日志里明明有那一行、探针却读不到"的假失败。
		//   TerminateProcess 之后句柄释放，日志（无缓冲）已经落盘。
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		Sleep(200);

		if (tab == L"advanced") {
			// ★ 关键判据：应用自己的日志。它证明"高级页真被画到了"。
			const bool painted = LogContains(logPath, L"[adv] 页面已绘制");
			Check(painted, "日志里有「[adv] 页面已绘制」（这一页真的画到了）");

			// ★ v78：日志里那一行同时报了**闸门**和**编辑框**两个状态 ——
			//   用它把"三屏画的是哪一屏"钉死。
			//   ⚠️ 为什么要分开断言"闸门"和"编辑框"：它们是**两个**开关
			//      （`g_advQuizPassed` / `g_advWhyDismissed`），只报一个的话
			//      "闸门过了但解析屏没点掉"这种中间态就看不出来。
			if (advMode == L"editor") {
				Check(LogContains(logPath, L"闸门=1 编辑框=1"),
					"日志报「闸门=1 编辑框=1」（截到的是**已解锁的编辑台**）");
				Check(LogContains(logPath, L"[adv] 初始规则=3 来源=示例"),
					"日志报「初始规则=3 来源=示例」（首次进入走了铺示例那条分支）");
			}
			else if (advMode == L"why") {
				Check(LogContains(logPath, L"闸门=1 编辑框=0"),
					"日志报「闸门=1 编辑框=0」（截到的是**刚全对的解析屏**）");
			}
			else {
				Check(LogContains(logPath, L"闸门=0 编辑框=0"),
					"日志报「闸门=0 编辑框=0」（截到的是**未过闸门的三道题**）");
				Check(LogContains(logPath, L"[adv] 初始规则=3 来源=示例"),
					"日志报「初始规则=3 来源=示例」（首次进入走了铺示例那条分支）");
			}
		}
		else {
			// ★ 负对照（铁律 128/110）：**不是** advanced 页签时，这一页不该被画到。
			//   没有这条，"画到了"那句判据就可能是恒真的 —— 那样它证明不了任何事。
			Check(!LogContains(logPath, L"[adv] 页面已绘制"),
				"负对照：非 advanced 页签时日志里**没有**「[adv] 页面已绘制」");
		}

		return g_fail == 0 ? 0 : 1;
	}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 4) {
		printf("用法: gui_preview_probe.exe <exePath> <tab> <outBmpPath> [advMode]\n");
		printf("      tab     = overview | log | process | config | ark | advanced\n");
		printf("      advMode = quiz(默认) | why | editor   —— 只在 tab=advanced 时有意义\n");
		return 2;
	}
	const std::wstring advMode = (argc >= 5) ? argv[4] : L"";
	const int rc = Run(argv[1], argv[2], argv[3], advMode);
	printf("\n[gui-preview-probe] 通过 %d / 失败 %d\n", g_pass, g_fail);
	return rc;
}
