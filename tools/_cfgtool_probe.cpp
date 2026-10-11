//
// _cfgtool_probe.cpp —— 「配置与日志」工具的子控件探针（仅用于自动化验收）。
//
// 为什么需要它：clickat 只能给**顶层窗口**发消息，选不中列表框 / 勾选框这类
// 子控件；而本工具的过滤、分组切换都在子控件上。本探针按**控件文字**找到子
// 窗口，直接给它发消息（BM_CLICK / LB_SETCURSEL），不依赖真实鼠标。
//
// 用法：
//   _cfgtool_probe.exe dump
//   _cfgtool_probe.exe click-text "<按钮/勾选框文字>"
//   _cfgtool_probe.exe setedit-text "<标签>" "<值>"      (按前一个 static 定位不了，简化：不用)
//   _cfgtool_probe.exe section <索引>
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static HWND g_root = nullptr;

BOOL CALLBACK FindRoot(HWND hwnd, LPARAM lp) {
	wchar_t cls[256] = {};
	GetClassNameW(hwnd, cls, _countof(cls));
	if (_wcsicmp(cls, L"R3ShieldCoreCfgWnd") == 0) {
		*reinterpret_cast<HWND*>(lp) = hwnd;
		return FALSE;
	}
	return TRUE;
}

struct ChildCtx {
	const wchar_t* text;
	HWND found;
};
BOOL CALLBACK FindChildByText(HWND hwnd, LPARAM lp) {
	auto* ctx = reinterpret_cast<ChildCtx*>(lp);
	wchar_t txt[512] = {};
	GetWindowTextW(hwnd, txt, _countof(txt));
	if (_wcsicmp(txt, ctx->text) == 0) {
		ctx->found = hwnd;
		return FALSE;
	}
	return TRUE;
}

struct DumpCtx { int depth; };
BOOL CALLBACK DumpChild(HWND hwnd, LPARAM lp) {
	wchar_t cls[128] = {};
	wchar_t txt[256] = {};
	GetClassNameW(hwnd, cls, _countof(cls));
	GetWindowTextW(hwnd, txt, _countof(txt));
	RECT r = {};
	GetWindowRect(hwnd, &r);
	printf("  hwnd=%p class=%-16ls rect=(%ld,%ld,%ld,%ld) text=%ls\n",
		hwnd, cls, r.left, r.top, r.right, r.bottom, txt);
	return TRUE;
}

struct ByIdCtx { int id; HWND found; };
BOOL CALLBACK FindChildById(HWND hwnd, LPARAM lp) {
	auto* ctx = reinterpret_cast<ByIdCtx*>(lp);
	if (GetDlgCtrlID(hwnd) == ctx->id) { ctx->found = hwnd; return FALSE; }
	return TRUE;
}

BOOL CALLBACK FindDialog(HWND hwnd, LPARAM lp) {
	wchar_t cls[64] = {};
	GetClassNameW(hwnd, cls, _countof(cls));
	if (_wcsicmp(cls, L"#32770") == 0) {
		*reinterpret_cast<HWND*>(lp) = hwnd;
		return FALSE;
	}
	return TRUE;
}

int wmain(int argc, wchar_t** argv) {
	// 关掉当前弹出的模态对话框（保存成功 / 校验失败 …）
	if (argc >= 2 && wcscmp(argv[1], L"dismiss-dialog") == 0) {
		HWND dlg = nullptr;
		for (int i = 0; i < 20 && !dlg; ++i) {
			EnumWindows(FindDialog, reinterpret_cast<LPARAM>(&dlg));
			if (!dlg) { Sleep(100); }
		}
		if (!dlg) { printf("no dialog\n"); return 1; }
		SendMessageW(dlg, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED),
			reinterpret_cast<LPARAM>(GetDlgItem(dlg, IDOK)));
		Sleep(150);
		PostMessageW(dlg, WM_CLOSE, 0, 0);
		printf("dismissed dialog\n");
		return 0;
	}

	EnumWindows(FindRoot, reinterpret_cast<LPARAM>(&g_root));
	if (!g_root) { printf("main window not found\n"); return 1; }

	if (argc >= 2 && wcscmp(argv[1], L"dump") == 0) {
		printf("main=%p\n", g_root);
		EnumChildWindows(g_root, DumpChild, 0);
		return 0;
	}

	// 按控件 ID 发 BM_CLICK（最稳：不依赖中文、不依赖坐标）
	if (argc >= 3 && wcscmp(argv[1], L"click-id") == 0) {
		ByIdCtx ctx = { _wtoi(argv[2]), nullptr };
		EnumChildWindows(g_root, FindChildById, reinterpret_cast<LPARAM>(&ctx));
		if (!ctx.found) { printf("child id not found: %ls\n", argv[2]); return 1; }
		SendMessageW(ctx.found, BM_CLICK, 0, 0);
		printf("clicked id=%d\n", ctx.id);
		return 0;
	}

	// 往指定 ID 的 EDIT 里写文字并触发 EN_CHANGE
	if (argc >= 4 && wcscmp(argv[1], L"setedit-id") == 0) {
		ByIdCtx ctx = { _wtoi(argv[2]), nullptr };
		EnumChildWindows(g_root, FindChildById, reinterpret_cast<LPARAM>(&ctx));
		if (!ctx.found) { printf("child id not found: %ls\n", argv[2]); return 1; }
		SetWindowTextW(ctx.found, argv[3]);
		SendMessageW(g_root, WM_COMMAND,
			MAKEWPARAM(ctx.id, EN_CHANGE), reinterpret_cast<LPARAM>(ctx.found));
		printf("set edit id=%d\n", ctx.id);
		return 0;
	}

	if (argc >= 3 && wcscmp(argv[1], L"click-text") == 0) {
		ChildCtx ctx = { argv[2], nullptr };
		EnumChildWindows(g_root, FindChildByText, reinterpret_cast<LPARAM>(&ctx));
		if (!ctx.found) { printf("child not found: %ls\n", argv[2]); return 1; }
		SendMessageW(ctx.found, BM_CLICK, 0, 0);
		printf("clicked %ls\n", argv[2]);
		return 0;
	}

	if (argc >= 3 && wcscmp(argv[1], L"section") == 0) {
		// 第一个 LISTBOX 子窗口即分组列表
		struct { HWND lb; } c = { nullptr };
		EnumChildWindows(g_root, [](HWND h, LPARAM lp) -> BOOL {
			wchar_t cls[64] = {};
			GetClassNameW(h, cls, _countof(cls));
			if (_wcsicmp(cls, L"ListBox") == 0) {
				*reinterpret_cast<HWND*>(lp) = h;
				return FALSE;
			}
			return TRUE;
		}, reinterpret_cast<LPARAM>(&c.lb));
		if (!c.lb) { printf("listbox not found\n"); return 1; }
		const int idx = _wtoi(argv[2]);
		SendMessageW(c.lb, LB_SETCURSEL, idx, 0);
		// 触发 LBN_SELCHANGE：给父窗口发 WM_COMMAND
		SendMessageW(g_root, WM_COMMAND,
			MAKEWPARAM(GetDlgCtrlID(c.lb), LBN_SELCHANGE),
			reinterpret_cast<LPARAM>(c.lb));
		printf("section %d\n", idx);
		return 0;
	}

	printf("usage: _cfgtool_probe.exe dump | click-text <text> | section <idx>\n");
	return 2;
}
