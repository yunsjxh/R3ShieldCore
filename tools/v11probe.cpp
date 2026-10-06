// v11probe.cpp —— 触发 v11 新增的三条 API 变体路径，供 R3ShieldCore 引擎观测。
//
// 用法：
//   v11probe.exe screen   → GetDC(NULL) + GetDIBits 直读屏幕（应被 ScreenGuard 捕获）
//   v11probe.exe poll     → 256 键全扫的轮询式键盘记录（应被 InputHookGuard 捕获）
//   v11probe.exe dbg      → 只打印，不触发（对照）
//
// 为什么单独做成工具：验证必须"从被监控进程内部"动作，而在本会话的
// 控制台进程里直接调会影响判定（探针进程自身不在注入范围内）。
// 让用户手动启动这个 exe（它会被注入），再看引擎日志。
//
#include <windows.h>
#include <stdio.h>
#include <string.h>

static int DoScreen()
{
	printf("[v11probe] 触发 GetDIBits 直读屏幕路径...\n");

	HDC screen = GetDC(NULL);
	if (!screen) {
		printf("  GetDC(NULL) 失败 err=%lu\n", GetLastError());
		return 1;
	}

	// 关键：拿屏幕 DC 后**不经过 BitBlt**，直接 GetDIBits 读像素。
	// 这正是 v11 新补的那条路。
	HBITMAP bmp = CreateCompatibleBitmap(screen, 64, 64);
	if (!bmp) {
		printf("  CreateCompatibleBitmap 失败 err=%lu\n", GetLastError());
		ReleaseDC(NULL, screen);
		return 1;
	}

	BITMAPINFO bmi = {};
	bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bmi.bmiHeader.biWidth = 64;
	bmi.bmiHeader.biHeight = -64;
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32;
	bmi.bmiHeader.biCompression = BI_RGB;

	DWORD pixels[64 * 64] = {};
	SetLastError(0);
	int lines = GetDIBits(screen, bmp, 0, 64, pixels, &bmi, DIB_RGB_COLORS);
	printf("  GetDIBits(screenDc, ...) = %d  err=%lu\n", lines, GetLastError());

	DeleteObject(bmp);
	ReleaseDC(NULL, screen);
	printf("[v11probe] 完成\n");
	return 0;
}

static int DoPoll()
{
	printf("[v11probe] 触发轮询式键盘记录（256 键全扫，重复 50 轮）...\n");

	// 这就是键盘记录器的标准骨架：循环扫全部虚拟键。
	// 单线程 100ms 内会远超 InputHookGuard 的阈值（60 次）。
	for (int round = 0; round < 50; round++) {
		for (int vk = 0; vk < 256; vk++) {
			SHORT state = GetAsyncKeyState(vk);
			(void)state;
		}
		Sleep(2);
	}

	printf("[v11probe] 完成\n");
	return 0;
}

int main(int argc, char** argv)
{
	if (argc > 1 && strcmp(argv[1], "screen") == 0) {
		return DoScreen();
	}
	if (argc > 1 && strcmp(argv[1], "poll") == 0) {
		return DoPoll();
	}

	printf("用法: v11probe.exe <screen|poll>\n");
	return 2;
}
