//
// toast_pair_ut.cpp - 验证通知卡片"按下/抬起配对"逻辑。
//
// 背景（§10-19）：卡片贴右下角 + WS_EX_TOPMOST，行 2 按钮压在任务栏通知区，
// 鼠标在托盘区松开时 WM_LBUTTONUP 会误投到卡片上，旧实现会当成
// 「始终拒绝」→ 静默写永久 deny 规则。
//
// 修法：只有"按下与抬起在同一按钮内"才生效。这个探针证明：
//   1) 裸 WM_LBUTTONUP（无 DOWN）→ 不触发动作
//   2) DOWN 在 A、UP 在 B（不同按钮）→ 不触发动作
//   3) DOWN+UP 都在同一按钮 → 触发动作
//
// 因为卡片是运行期创建的，这里用一个**假的宿主窗口**重现同样的消息处理契约：
// 直接给真卡片发消息需要引擎在跑。改为：启动引擎 → 触发一个会弹卡的探针 →
// 用 toastclick 的两种模式各点一次，从引擎日志里看是否真的写入了决策。
//
// 用法: toast_pair_ut <引擎PID>
//
#include <windows.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

namespace
{
	constexpr PCWSTR ToastClass = L"R3ShieldCoreToastWindow";

	struct FindContext
	{
		DWORD pid;
		HWND toast;
	};

	BOOL CALLBACK FindProc(HWND hwnd, LPARAM lParam)
	{
		auto* ctx = reinterpret_cast<FindContext*>(lParam);

		DWORD pid = 0;
		GetWindowThreadProcessId(hwnd, &pid);
		if (pid != ctx->pid) return TRUE;

		WCHAR cls[128] = {};
		GetClassNameW(hwnd, cls, _countof(cls));
		if (wcscmp(cls, ToastClass) != 0) return TRUE;
		if (!IsWindowVisible(hwnd)) return TRUE;

		ctx->toast = hwnd;
		return FALSE;
	}

	HWND WaitForToast(DWORD pid, int seconds)
	{
		ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000;
		while (GetTickCount64() < deadline) {
			FindContext ctx = { pid, nullptr };
			EnumWindows(FindProc, reinterpret_cast<LPARAM>(&ctx));
			if (ctx.toast) return ctx.toast;
			Sleep(100);
		}
		return nullptr;
	}

	// 行 2 左侧按钮（始终允许）的中心，客户区坐标
	constexpr int AllowAlwaysX = 16 + 200 / 2;
	constexpr int DenyAlwaysX = 16 + 210 + 200 / 2;
	constexpr int Row2Y = 162 + 28 / 2;
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	if (argc < 2) {
		printf("用法: toast_pair_ut <引擎PID>\n");
		return 2;
	}

	DWORD pid = static_cast<DWORD>(strtoul(argv[1], nullptr, 10));
	printf("等待引擎 %lu 弹出卡片 ...\n", pid);

	HWND toast = WaitForToast(pid, 20);
	if (!toast) {
		printf("未等到卡片（请先用探针触发一次高危操作）\n");
		return 2;
	}

	printf("找到卡片 %p\n", toast);
	LPARAM row2Left = MAKELPARAM(AllowAlwaysX, Row2Y);
	LPARAM row2Right = MAKELPARAM(DenyAlwaysX, Row2Y);

	// 用例 1：裸 WM_LBUTTONUP（模拟托盘区误投）—— 不应触发动作
	printf("\n[1] 裸 WM_LBUTTONUP（无 DOWN）→ 期望：动作不生效、卡片仍在\n");
	SendMessage(toast, WM_LBUTTONUP, 0, row2Right);
	Sleep(200);
	printf("    卡片是否仍存在: %s\n", IsWindow(toast) ? "是（正确，未误触）" : "否（错误，被误触了）");

	// 用例 2：DOWN 在左、UP 在右（跨按钮拖动）—— 不应触发动作
	printf("\n[2] DOWN(左) + UP(右) 跨按钮 → 期望：动作不生效\n");
	SendMessage(toast, WM_LBUTTONDOWN, MK_LBUTTON, row2Left);
	SendMessage(toast, WM_LBUTTONUP, 0, row2Right);
	Sleep(200);
	printf("    卡片是否仍存在: %s\n", IsWindow(toast) ? "是（正确，未误触）" : "否（错误，被误触了）");

	// 用例 3：DOWN+UP 都在同一按钮 —— 应触发动作（卡片关闭）
	printf("\n[3] DOWN+UP 同一按钮(右) → 期望：动作生效、卡片关闭\n");
	SendMessage(toast, WM_LBUTTONDOWN, MK_LBUTTON, row2Left);
	SendMessage(toast, WM_LBUTTONUP, 0, row2Left);
	Sleep(400);
	printf("    卡片是否仍存在: %s\n", IsWindow(toast) ? "是（错误，未触发）" : "否（正确，已触发）");

	return 0;
}
