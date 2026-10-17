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
//      这里断言 `[adv] ...` —— 它证明"这一页真被画到了"，
//      而"截到一张空窗口"与"页面没画"在图上分不开，只有日志能分开。
//
// ★ v80：同一份探针现在也核对 **cfg 工具**（`r3shieldcore-cfg.exe`）——
//   「高级」编辑台从主程序整块搬到了那里。两者都是**自绘窗口**、都靠
//   自己的日志自证，取图/断言的做法完全一样，所以不抄第二份
//   （铁律 195：同一份逻辑不抄第二遍）；差别只有三个参数：
//     · 窗口类名  主程序 R3ShieldCoreMainWindow / cfg R3ShieldCoreCfgWnd
//     · 启动参数  主程序 `--gui-preview` / cfg `--page <N>`
//     · 日志文件  主程序固定 r3shieldcore-console.log（app.cpp 重定向的）
//                 cfg 默认不落盘 ⇒ 预览时用 R3SHIELDCORE_PREVIEW_LOG 指定
//   ⇒ 第 5 个参数 `app` 选 `main`（默认）或 `cfg`。
//
// 用法:
//   gui_preview_probe.exe <exePath> <tab> <outBmpPath> [mode] [app]
//     tab     = overview | log | process | config | ark | advanced
//     mode    = 见下方 Run() 里的分支；摘要：
//       main + advanced : jump(默认) | click  —— click 会模拟点一下跳转按钮，
//                         并检查 cfg 的窗口有没有起来、停在第几页
//       cfg  + advanced : quiz(默认) | why | editor | typing | error
//       cfg  + log      : (默认=事件日志) | svc  —— 用 R3SHIELDCORE_PREVIEW_LOGSRC
//                         把"停哪一项"传给 cfg（探针不点下拉框）
//     app     = main(默认) | cfg
//
// 退出码: 0 = 全部判据通过；1 = 有判据失败；2 = 窗口没起来。

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <windows.h>

// ★ v80：窗口类名 / 页号**从共享头取**，不在这里再写一份（铁律 127）。
//
//   为什么这条对**探针**也成立：探针要断言"cfg 的窗口出现了"、"跳过去停在
//   高级页"。如果这里自己写一份 `L"R3ShieldCoreCfgWnd"` / 硬编码 `页签=2`，
//   那么哪天 cfg 改了类名或页号，**探针会跟着一起错**（它自己也被改了才会绿），
//   或者更糟：探针红得莫名其妙，而真正的问题在别处。
//   共用同一份常量，"探针认为的契约"与"两个 exe 实现的契约"就永远一致。
#include <r3shieldcore/cfg_launch.h>

namespace
{
	// 目标窗口类名 —— 由第 5 个参数（app）决定，见 wmain。
	std::wstring g_className = L"R3ShieldCoreMainWindow";

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
				&& g_className == cls
				&& IsWindowVisible(hwnd)) {
				g_found = hwnd;
				return FALSE;
			}
			return TRUE;
		}, 0);
		return g_found;
	}

	// 按类名找窗口（不依赖 g_className）—— 用来找"另一个 exe"的窗口，
	// 例如主程序点了跳转之后应该出现的 cfg 窗口。
	HWND FindWindowOfClass(PCWSTR className)
	{
		g_found = nullptr;
		EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
			WCHAR cls[128] = {};
			if (GetClassNameW(hwnd, cls, _countof(cls)) > 0
				&& wcscmp(cls, static_cast<PCWSTR>(reinterpret_cast<void*>(lp))) == 0
				&& IsWindowVisible(hwnd)) {
				g_found = hwnd;
				return FALSE;
			}
			return TRUE;
		}, reinterpret_cast<LPARAM>(className));
		return g_found;
	}

	// 结束某个窗口所属的进程（用于清掉被跳转拉起来的 cfg）。
	void KillProcessOfWindow(HWND hwnd)
	{
		if (!hwnd) { return; }
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid == 0) { return; }
		HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		if (h) {
			TerminateProcess(h, 0);
			CloseHandle(h);
		}
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

	int Run(const std::wstring& exePathIn, const std::wstring& tab,
		const std::wstring& outBmp, const std::wstring& advMode, bool cfgApp)
	{
		// ★★ 先把 exe 路径规范成**绝对路径**，再用它派生一切。
		//
		//   为什么必须（实测踩过，症状极具误导性）：
		//     调用方给了**相对**路径时，`exeDir` 也是相对的，于是
		//       · 传给子进程的 `R3SHIELDCORE_PREVIEW_LOG` = `dist\...\x.log`（相对）；
		//       · 而子进程的工作目录（下面 `CreateProcess` 的 lpCurrentDirectory）
		//         **已经被设成同一个 `exeDir`** ⇒ 相对路径是**相对它自己**解析的
		//         ⇒ 变成 `dist\...\dist\...\x.log` —— **目录不存在**。
		//     ⇒ `_wfreopen_s` 失败 ⇒ stdout 被关掉 ⇒ 后面第一句 `printf`
		//       撞上 CRT 的无效参数处理器 ⇒ `__fastfail` ⇒ 进程**秒退**，
		//       退出码 **`0xC0000409`**（`STATUS_STACK_BUFFER_OVERRUN`）。
		//     探针这边只看到"窗口没出现（15s 超时）"，**看着像崩溃**
		//     （与铁律 266 同一种误读）。
		//
		//   ⇒ 规范成绝对路径后，exeDir / 日志路径 / 规则文件路径全部是绝对的，
		//     不管探针自己被怎么调用（`test_gui_preview.sh` 传的本来就是绝对路径，
		//     所以这条只是让**手动调用**不再踩坑）。
		std::wstring exePath = exePathIn;
		{
			WCHAR full[MAX_PATH * 4] = {};
			const DWORD n = ::GetFullPathNameW(exePathIn.c_str(), _countof(full), full, nullptr);
			if (n > 0 && n < _countof(full)) {
				exePath.assign(full, n);
			} else {
				printf("[gui-preview-probe] 警告：无法把 exe 路径规范成绝对路径（err=%lu），"
					"按原样用\n", ::GetLastError());
			}
		}
		const std::wstring exeDir = ExeDirectory(exePath);

		// 日志文件：主程序固定写 r3shieldcore-console.log（app.cpp 重定向的）；
		// cfg 生产路径**不落盘**，所以预览时用 R3SHIELDCORE_PREVIEW_LOG
		// 指一个专门的文件（名字不同，免得和主程序那一份互相覆盖）。
		const std::wstring logPath = cfgApp
			? exeDir + L"\\r3shieldcore-cfg-console.log"
			: exeDir + L"\\r3shieldcore-console.log";

		// cfg 的日志路径（两种 app 都要设）：
		//   · app=cfg  —— 就是它自己的日志；
		//   · app=main —— 主程序点跳转会**拉起 cfg**，而那个 cfg 是主程序的
		//     子进程，继承环境变量 ⇒ 也会写到这里。探针靠它验证
		//     "跳过去的 cfg 停在第几页"（`--page 2` / 激活消息有没有生效）。
		const std::wstring cfgLogPath = exeDir + L"\\r3shieldcore-cfg-console.log";
		SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_LOG", cfgLogPath.c_str());

		// ★ v81：cfg 日志页有两项（事件日志 / 服务日志），默认停在第 0 项。
		//   探针不会去点下拉框 ⇒ 必须用这个环境变量把**规格**翻译成"停哪一项"，
		//   否则 `cfg/log:svc` 那一屏截到的还是第 0 项，而判据会以为切过去了
		//   （覆盖静默丢失，铁律 142/249）。
		if (cfgApp && tab == L"log") {
			const WCHAR* src = (advMode == L"svc") ? L"svc" : L"event";
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_LOGSRC", src);
		} else {
			// 别的规格别把上一轮的值带过去（探针进程内环境变量是**累积**的）。
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_LOGSRC", nullptr);
		}

		// ---- 先清掉**上一次**遗留的窗口 ----
		//
		// ★ 为什么要清（**两种** app 都要清）：
		//   · 主程序那几屏里有一屏是"点跳转 -> cfg 起来"。如果上一轮留下的
		//     cfg 还在跑，这一轮的"跳转成功"就会被那个**旧窗口**满足 ——
		//     判据恒真，等于白设（铁律 128/110）。
		//   · cfg 自己那几屏同理，而且更隐蔽：`TerminateProcess` 是**异步**的，
		//     上一个 cfg 的窗口可能还没消失，紧接着的 `FindWindowByClass`
		//     就会找到**它** ⇒ 截图截到的是一个正在销毁的窗口。
		//     实测症状：`cfg/advanced:error` 偶发报"没有紫像素"，
		//     单独重跑又全绿 —— 典型的"判据被上一轮的残骸满足"。
		//   ⇒ 清完之后**等它真的消失**再继续，不能只发一个 TerminateProcess。
		{
			HWND stale = FindWindowOfClass(g_className.c_str());
			if (stale) {
				printf("[gui-preview-probe] 清掉上一轮遗留的窗口（class=%ls）\n",
					g_className.c_str());
				KillProcessOfWindow(stale);
			}
			if (!cfgApp) {
				HWND staleCfg = FindWindowOfClass(R3ShieldCoreCfg::kWindowClass);
				if (staleCfg) {
					printf("[gui-preview-probe] 清掉上一轮遗留的 cfg 窗口\n");
					KillProcessOfWindow(staleCfg);
				}
			}
			for (int i = 0; i < 40 && FindWindowOfClass(g_className.c_str()); ++i) {
				Sleep(100);
			}
		}

		// ★★ v81：还要等**单实例互斥体**释放 —— 窗口消失 ≠ 进程走了。
		//
		//   为什么（这条踩过一次，症状极具误导性）：
		//     上面清上一轮用的是 `TerminateProcess`，它是**异步**的（铁律 254）。
		//     窗口（作为最后一个可见窗口）先消失，而进程的互斥体可能**还在**。
		//     此时立刻 `CreateProcess` ⇒ 新 cfg 撞上 `ERROR_ALREADY_EXISTS`
		//     ⇒ 走单实例早退，**安静退出**：
		//       · 没有窗口       ⇒ 探针报 `窗口没出现（15s 超时）`，看着像崩溃；
		//       · **连日志都不建** ⇒ 因为早退发生在 stdout 重定向**之前**，
		//                            探针连"它为什么退出"都看不到（最坑的一点）。
		//     实测：一次反向对照就因为这个 race 假红，而单独重跑又全绿。
		//
		//   ⇒ 判据必须是"互斥体真的没了"，而不是"窗口消没消失"。
		//   ⚠️ 只在 app=cfg 时适用：主程序没有单实例互斥体（只有 cfg 有）。
		if (cfgApp && !R3ShieldCoreCfg::WaitSingleInstanceFree(10000)) {
			printf("[gui-preview-probe] 诊断：上一个 cfg 的单实例互斥体 10s 内没释放"
				"（进程还在？）—— 接下来必然报'窗口没出现'，不是崩溃\n");
		}

		std::wstring cmdline;
		if (cfgApp) {
			// cfg：页号走命令行（它没有 R3SHIELDCORE_START_TAB）。
			int page = 0;
			if (tab == L"log") { page = 1; }
			else if (tab == L"advanced") { page = 2; }
			cmdline = L"\"" + exePath + L"\" --page " + std::to_wstring(page);

			DeleteFileW(logPath.c_str());
		}
		else {
			// 主程序：`--gui-preview` 停在指定页签。
			cmdline = L"\"" + exePath + L"\" --gui-preview";
			SetEnvironmentVariableW(L"R3SHIELDCORE_START_TAB", tab.c_str());

			// ★ v80：`click` = 让 exe **自己**模拟点一下「高级」页的跳转按钮。
			//   见 r3shieldcore_gui.cpp 的 RunPreview / GuiThreadProc。
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_JUMP",
				advMode == L"click" ? L"click" : nullptr);
		}

		// ★ v78：「高级」页有**三个互斥的界面状态**（闸门未过 / 刚全对 / 已解锁），
		//   光靠"停在 advanced 页签"只能截到第一屏。第 4 个参数把另外几屏
		//   也变成可截的 —— 否则"新加的编辑台长什么样"仍然只能靠人眼
		//   （铁律 24/28）。
		//     空串 / "quiz" -> 默认（闸门屏）
		//     "why"         -> 解析屏
		//     "editor"      -> 编辑台（输入框是空的）
		//   ★ v79 再加两屏 —— 实时提示是**输入时才有**的，空输入框截不到它：
		//     "typing"      -> 编辑台 + 预置一条**合法**规则（提示=可解析）
		//     "error"       -> 编辑台 + 预置一条**非法**规则（提示=错误）
		std::wstring advEnvValue = advMode;
		if (advMode == L"typing" || advMode == L"error") {
			advEnvValue = L"editor";
		}
		if (!advEnvValue.empty() && advEnvValue != L"quiz" && advEnvValue != L"click") {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_ADV", advEnvValue.c_str());
		}
		else {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_ADV", nullptr);
		}

		// ★ v79：预置编辑框内容 —— 把"输入中"的实时提示变成**可截屏的确定状态**。
		//
		//   为什么把两段文本**写死在探针里**（而不是从命令行收）：
		//   规则是中文 DSL，走命令行就要过一次 shell 的编码转换，
		//   而这台机器上 bash 传进来的字节是 UTF-8 还是 GBK 并不确定 ——
		//   探针是宽字符程序，硬编码的宽字面量**不经过任何编码转换**，
		//   是这里唯一能保证逐字正确的做法。
		//   两段只差一个词：合法那条用「匹配」（真算子），
		//   非法那条用「模糊」（不是算子）—— 正好验证提示读的是真解析结果。
		if (advMode == L"typing") {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_EDIT",
				L"当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"");
		}
		else if (advMode == L"error") {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_EDIT",
				L"当 注册表值 的 值名 模糊 /Pass.*/ 时 替换为 \"***\"");
		}
		else {
			SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_EDIT", nullptr);
		}

		// ---- 规则文件重定向到一个**临时文件**（先删掉，保证"来源=示例"）----
		//
		// ★ 为什么不直接用真实路径：那样这条判据会取决于这台机器的
		//   `%ProgramData%\R3 Shield Core\` 里有没有规则文件、有几条 ——
		//   换台机器就随机红。而且自动核对不该去读（更不该写）用户的真规则。
		const std::wstring previewRules = exeDir + L"\\r3shieldcore-rules-preview.txt";
		DeleteFileW(previewRules.c_str());
		SetEnvironmentVariableW(L"R3SHIELDCORE_PREVIEW_RULES", previewRules.c_str());

		// ---- 先删掉上一次的日志：否则断言可能被**上一轮**的行满足（假绿） ----
		DeleteFileW(logPath.c_str());

		std::vector<WCHAR> mutableCmd(cmdline.begin(), cmdline.end());
		mutableCmd.push_back(L'\0');

		STARTUPINFOW si = {};
		si.cb = sizeof(si);
		PROCESS_INFORMATION pi = {};
		if (!CreateProcessW(exePath.c_str(), mutableCmd.data(), nullptr, nullptr,
			FALSE, 0, nullptr, exeDir.c_str(), &si, &pi)) {
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
			// ★ 超时了要说清"子进程是死了还是活着没建窗" —— 这两个原因
			//   的排查方向完全不同，只报"窗口没出现"等于什么都没说
			//   （本项目已经在这上面栽过：单实例早退 ⇒ exit 0 + 无日志，
			//    症状"看着像崩溃"，铁律 266）。
			DWORD ec = 0;
			const BOOL gotEc = GetExitCodeProcess(pi.hProcess, &ec);
			if (gotEc && ec == STILL_ACTIVE) {
				printf("[gui-preview-probe] 窗口没出现（15s 超时）—— 子进程**还活着**，"
					"只是没建出窗口（挂住了？）\n");
			} else if (gotEc) {
				printf("[gui-preview-probe] 窗口没出现（15s 超时）—— 子进程**已退出**，"
					"退出码=%lu（0 = 正常退出，多半是撞了单实例互斥体；"
					"其它值 = 崩了）\n", ec);
			} else {
				printf("[gui-preview-probe] 窗口没出现（15s 超时）—— 取不到退出码 err=%lu\n",
					GetLastError());
			}
			printf("        命令行=[%ls] 工作目录=[%ls]\n", cmdline.c_str(), exeDir.c_str());
			printf("        ★ 提示：exe 路径给**绝对路径**试试 —— 相对路径下"
				"子进程的工作目录/重定向路径会一起变成相对，容易出怪事\n");
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return 2;
		}

		// 等到窗口**真的在屏幕上最前面**再截图。
		//
		// ★ 为什么不能只 `SetForegroundWindow` + 一个固定 sleep：探针是从
		//   **屏幕 DC** 取图的（不用 PrintWindow，理由见文件头）。窗口没到
		//   前台的话，截到的是压在它上面的别的窗口。
		//
		// ★★ v80 二次踩坑（第一版修法不够）：`SetForegroundWindow` 会被
		//   **前台锁**拒绝 —— 探针是从 bash 起的后台进程，没有抢前台的资格。
		//   而主程序窗口**自己置顶**（安全控制台），所以主程序那几屏一直是对的；
		//   cfg 的窗口不置顶 ⇒ **全部**截到了压在它上面的编辑器窗口。
		//   更糟的是像素判据在一个**无关窗口**上求值**照样能过**
		//   （编辑器 UI 里本来就有紫色图标 ⇒ "紫>0" 假绿、`非白>3%` 也必然过），
		//   只有"紫=0"那种时刻才会偶发红 —— 症状被误读成"偶发失败"。
		//   ⇒ 改用「TOPMOST → NOTOPMOST」把它抬到 z 序最前（**不需要**前台权），
		//     并且**必须验证**"这个屏幕位置上真的是它"（下面那段）。
		if (IsIconic(hwnd)) {
			ShowWindow(hwnd, SW_RESTORE);   // 最小化状态下 SetWindowPos 也抬不上来
		}
		SetForegroundWindow(hwnd);
		SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
		SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
			SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW | SWP_NOACTIVATE);
		Sleep(1200);   // 等首帧 + 页签切换生效

		// ---- 取窗口矩形（含边框，截图更像"真窗口"）----
		RECT wr = {};
		GetWindowRect(hwnd, &wr);
		const int width = wr.right - wr.left;
		const int height = wr.bottom - wr.top;

		// ★★ 硬闸门：这个屏幕位置上**真的**是我们要截的那个窗口吗？
		//
		//   不查这一步，下面所有像素判据都可能在一个**无关窗口**上求值 ——
		//   而且**照样能过**（假绿），或莫名其妙红（假红）。这是"截图核对"
		//   这类判据最容易塌掉的地方：判据本身写得很对，只是**看的不是那个东西**。
		{
			const POINT mid = { (wr.left + wr.right) / 2, (wr.top + wr.bottom) / 2 };
			HWND atPoint = WindowFromPoint(mid);
			HWND atRoot = atPoint ? GetAncestor(atPoint, GA_ROOT) : nullptr;
			Check(atRoot == hwnd,
				"屏幕该位置上的顶层窗口就是被截的那个（没被别的窗口压住）");
			if (atRoot != hwnd) {
				WCHAR cls[128] = {};
				GetClassNameW(atRoot ? atRoot : GetDesktopWindow(), cls, _countof(cls));
				printf("        实际在那个位置的是窗口类「%ls」hwnd=%p（期望 %p）"
					" —— 下面的像素判据全部不可信\n",
					cls, static_cast<void*>(atRoot), static_cast<void*>(hwnd));
			}
		}

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

		// 编辑台（含 v79 的两屏"输入中"）才有右侧的改前/改后对照区。
		const bool editorLike = (advMode == L"editor" || advMode == L"typing"
			|| advMode == L"error");
		if (tab == L"advanced") {
			// 紫色是 Spoof 的语义色：判定/改后两列都用它，出现即说明对照区画出来了。
			// ⚠️ 这一条只在**编辑台**那几屏成立 —— 闸门屏/解析屏根本没有对照区，
			//    所以它必须跟着状态走，否则"闸门屏没有紫色"会被当成失败。
			if (editorLike) {
				Check(purple > 0, "画面上有 Spoof 紫像素（改前/改后对照区渲染出来了）");
			}
		}

		// ★ 先把被测进程结束掉，**再**读它的日志。
		//
		//   为什么不能边跑边读：exe 把 stdout 重定向到了日志文件
		//   并**一直持有**那个句柄，第二个进程再打开会拿到 err=13（EACCES）——
		//   实测过，表现为"日志里明明有那一行、探针却读不到"的假失败。
		//   TerminateProcess 之后句柄释放，日志（无缓冲）已经落盘。
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		Sleep(200);

		if (cfgApp && tab == L"advanced") {
			// ================= cfg 工具：搬过来的「高级」编辑台 =================
			//
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
				Check(LogContains(logPath, L"提示=空"),
					"日志报「提示=空」（编辑框空着，提示给的是语法骨架）");
				Check(LogContains(logPath, L"[adv] 初始规则=3 来源=示例"),
					"日志报「初始规则=3 来源=示例」（首次进入走了铺示例那条分支）");
			}
			else if (advMode == L"typing") {
				// ★ v79：预置了一条**合法**规则 ⇒ 实时提示必须说"可解析"。
				//   这一条证明的是"提示真的读了编辑框"，而不是画了句写死的话。
				Check(LogContains(logPath, L"闸门=1 编辑框=1"),
					"日志报「闸门=1 编辑框=1」（截到的是编辑台）");
				Check(LogContains(logPath, L"提示=可解析"),
					"日志报「提示=可解析」（合法规则 -> 实时提示认出来了）");
			}
			else if (advMode == L"error") {
				// ★ v79：预置了一条**非法**规则（「模糊」不是算子）⇒ 提示必须报错。
				//   与上一条成对：一个"合法->可解析"、一个"非法->错误"，
				//   合起来才能排除"提示恒等于某个值"的假绿。
				Check(LogContains(logPath, L"闸门=1 编辑框=1"),
					"日志报「闸门=1 编辑框=1」（截到的是编辑台）");
				Check(LogContains(logPath, L"提示=错误"),
					"日志报「提示=错误」（非法规则 -> 实时提示报错）");
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
		else if (cfgApp && tab == L"log") {
			// ============ cfg 工具：日志页（v81 起） ============
			//
			// ★ 判据一：这一页真的画到了（应用自己的日志）。
			Check(LogContains(logPath, L"[log] 日志页已就绪"),
				"日志里有「[log] 日志页已就绪」（这一页真的画到了）");

			// ★★ 判据二：下拉框**项数**。v81 把「控制台日志」删掉了 ⇒ 必须恒为 2。
			//   这是"控制台日志没被加回来"的**唯一**机器判据 ——
			//   光看截图只能证明"当前这一项显示的是什么"，证明不了"一共几项"
			//   （下拉列表是收起的，第三项看不见）。
			Check(LogContains(logPath, L"项数=2"),
				"日志报「项数=2」（下拉框只有 事件日志 / 服务日志 —— 控制台日志已删除）");

			// ★ 判据三：当前来源与**规格**一致（成对断言，防"恒等于某个值"）。
			if (advMode == L"svc") {
				Check(LogContains(logPath, L"来源=svc"),
					"日志报「来源=svc」（规格要求停在**服务日志**）");
			} else {
				Check(LogContains(logPath, L"来源=event"),
					"日志报「来源=event」（默认停在**事件日志**）");
			}
		}
		else if (tab == L"advanced") {
			// ============ 主程序：「高级」页只剩跳转入口（v80） ============
			Check(LogContains(logPath, L"[adv] 跳转页已绘制"),
				"日志里有「[adv] 跳转页已绘制」（这一页真的画到了）");

			// ★ 负判据：**不许**出现"启动失败"。
			//
			//   为什么要写成"不许出现失败"而不是"必须出现成功"：
			//   这一页每帧都打一行，成功那条在点击之前就已经出现过了 ——
			//   只查成功的话，点击失败（页内画了红字原因）也照样绿。
			Check(!LogContains(logPath, L"失败=1"),
				"日志里**没有**「失败=1」（LaunchOrActivate 没报错）");

			if (advMode == L"click") {
				// ★ v80 核心判据：模拟点一下 -> cfg 真被拉起来 / 被激活，
				//   而且停在**高级页**。这条链路上任何一环写错
				//   （窗口类名 / 激活消息名 / 页号 / exe 名）都会在这里红。
				Check(LogContains(logPath, L"[adv] 预览：模拟点击跳转按钮"),
					"日志里有「模拟点击跳转按钮」（点击真的走完了消息路径）");

				// 等 cfg 的窗口出现。用**共享头里的类名**（cfg_launch.h 的
				// kWindowClass）—— 探针不重新发明一个名字。
				HWND cfgWindow = nullptr;
				for (int i = 0; i < 100 && !cfgWindow; ++i) {
					Sleep(100);
					cfgWindow = FindWindowOfClass(R3ShieldCoreCfg::kWindowClass);
				}
				Check(cfgWindow != nullptr,
					"点了跳转之后 cfg 的窗口出现了（exe 名 / 窗口类名对得上）");

				if (cfgWindow) {
					// 结束 cfg，才能读它独占的日志（见上面那段 err=13 的说明）。
					KillProcessOfWindow(cfgWindow);
					Sleep(400);
					// 「页签=<kPageAdvanced>」= 共享头里的页号常量。它证明
					// **页号**也传对了（--page N 或激活消息的 wParam）——
					// 页号写错是最隐蔽的一种：窗口照样出现、照样激活，
					// 只是停在第 0 页，用户以为"没跳过去"。
					WCHAR pageNeedle[64] = {};
					swprintf_s(pageNeedle, L"页签=%d", R3ShieldCoreCfg::kPageAdvanced);
					Check(LogContains(cfgLogPath, pageNeedle),
						"cfg 的日志报「页签=kPageAdvanced」（跳转落到了高级页，不是停在配置页）");
					Check(LogContains(cfgLogPath, L"[adv] 页面已绘制"),
						"cfg 的日志里有「[adv] 页面已绘制」（那边真把编辑台画出来了）");
				}
			}
		}
		else {
			// ★ 负对照（铁律 128/110）：**不是** advanced 页签时，这一页不该被画到。
			//   没有这条，"画到了"那句判据就可能是恒真的 —— 那样它证明不了任何事。
			//
			//   ⚠️ v80 起主程序那一页改叫「跳转页已绘制」，cfg 那边仍是
			//      「页面已绘制」—— 两个都查，负对照才覆盖得住。
			Check(!LogContains(logPath, L"[adv] 跳转页已绘制")
					&& !LogContains(logPath, L"[adv] 页面已绘制"),
				"负对照：非 advanced 页签时日志里**没有**「[adv] ...已绘制」");
		}

		return g_fail == 0 ? 0 : 1;
	}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 4) {
		printf("用法: gui_preview_probe.exe <exePath> <tab> <outBmpPath> [mode] [app]\n");
		printf("      tab  = overview | log | process | config | ark | advanced\n");
		printf("      app  = main(默认，主程序) | cfg(配置工具 r3shieldcore-cfg.exe)\n");
		printf("      mode —— 只在 tab=advanced 时有意义：\n");
		printf("        app=main: jump(默认，只看跳转页) | click(模拟点按钮，验 cfg 被拉起并停在第 2 页)\n");
		printf("        app=cfg : quiz(默认，闸门屏) | why | editor | typing | error\n");
		printf("                  typing = 预置一条**合法**规则（验实时提示说「可解析」）\n");
		printf("                  error  = 预置一条**非法**规则（验实时提示报「错误」）\n");
		return 2;
	}
	const std::wstring mode = (argc >= 5) ? argv[4] : L"";
	const bool cfgApp = (argc >= 6) && (_wcsicmp(argv[5], L"cfg") == 0);
	g_className = cfgApp ? R3ShieldCoreCfg::kWindowClass : L"R3ShieldCoreMainWindow";
	const int rc = Run(argv[1], argv[2], argv[3], mode, cfgApp);
	printf("\n[gui-preview-probe] 通过 %d / 失败 %d\n", g_pass, g_fail);
	return rc;
}
