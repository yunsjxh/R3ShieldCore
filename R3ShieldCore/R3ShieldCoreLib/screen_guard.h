#pragma once

//
// 屏幕捕获监控层（GDI 截屏路径）。
//
// ⚠️ 先读这段：
//
//   截屏在 GDI 里是一条固定流水线：
//     ① GetDC(NULL) / GetDC(GetDesktopWindow())  拿屏幕 DC
//     ② CreateCompatibleDC + CreateCompatibleBitmap  建内存 DC
//     ③ BitBlt / StretchBlt  把屏幕 DC 拷进内存 DC
//     ④ GetDIBits  把像素取出来
//
//   我们拦 ③ 和 **④ 的一条变体**。
//
//   ⚠️ v11 补充：③ ④ 并不总是连在一起。存在**跳过 ③ 的直读路径**：
//      GetDC(NULL) 拿屏幕 DC 后直接 GetDIBits(screenDc, hbm, ...) 读像素。
//      这条路径现在也挂了（ScreenOp::GetDIBits），判据复用同一个
//      WindowFromDC（已用 tools/dibprobe.cpp 实测验证）。
//
//   ③ 的判据是**源 DC 是不是屏幕/桌面 DC**，用
//   `WindowFromDC(hdcSrc) == GetDesktopWindow()` 判断。
//   这个判据是实测出来的（tools/dctest.cpp）：
//       屏幕 DC（GetDC(NULL)）        → WindowFromDC = 桌面窗口句柄
//       内存 DC（CreateCompatibleDC） → WindowFromDC = NULL
//       窗口 DC（GetDC(hwnd)）        → WindowFromDC = 该窗口句柄
//   注意 GetDeviceCaps(TECHNOLOGY) 在三种 DC 上都是 DT_RASDISPLAY(1)，
//   完全区分不了 —— 只有 WindowFromDC 能用。
//
//   这层过滤是必须的：BitBlt 本身极高频（窗口重绘、滚动、图标合成
//   都走它），不过滤的话日志会被重绘刷爆。过滤后只剩"把屏幕内容
//   拷进内存 DC"这一种情况 —— 那才是截屏。
//
//   另一条路是 PrintWindow：直接抓指定窗口的内容（包括被遮挡的部分），
//   频率低、意图明确，无差别上报。
//
// ⚠️ 看不到的截屏方式（现代工具越来越多走这些）：
//   - Desktop Duplication API（dxgi!IDXGIOutputDuplication::AcquireNextFrame）
//     —— COM 虚函数，没有可 hook 的导出
//   - Windows.Graphics.Capture（WinRT）
//   - DirectX 全屏抓帧 / 显卡驱动自带的捕获（如 OBS 的 game capture）
//   - 通过 GetPixel 逐点读取（太热，挂不了）
//
//   所以定位是 **可见性**：让用户知道"有程序在拿我的屏幕"，
//   而不是"保证屏幕偷不走"。真边界要在内核（显卡/显示过滤驱动）。
//
namespace ScreenGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	//
	// 收尾：等所有"在飞"的 hook 跑完。
	//
	// 与其它 guard 同理，必须先把 hook 停用再调这个，
	// 然后才能 MH_Uninitialize()。见 registry_guard.h 的详细说明。
	//
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
