#pragma once

//
// 剪贴板读取监控层。
//
// ⚠️ 只盯"读"，不盯"写"。理由：
//
//   OpenClipboard 是"我要用剪贴板"的通用声明 —— 复制（写）、粘贴（读）、
//   截图工具、输入法、Office、浏览器全都在调。拦它等于按 Ctrl+C 就弹窗。
//   GetClipboardData 才是真的**把内容取走**。
//
//   所以：
//     OpenClipboard    → 只记录（ClipboardOp::Open）
//     GetClipboardData → 高危（ClipboardOp::Read）
//
//   想进一步降低噪音的话，可以只看 CF_UNICODETEXT / CF_TEXT 格式 ——
//   但格式判定要在 GetClipboardData 之后才知道（每次 Get 的是**一种**格式，
//   参数就是格式号），所以这里**不细分格式**：只要 Get 了就报，让用户看是谁。
//   密码管理器 / 加密钱包 / 验证码，这些内容经常就躺在剪贴板里 ——
//   这是"需要用户知情"，不是"一定恶意"。
//
// ⚠️ 能力边界：绕开这条太容易了。
//   - 直接 DeviceIoControl 打 \Device\NtControlPipe* / 走 win32k 系统调用
//   - 通过 COM（IDataObject / Clipboard API，如 Windows.ApplicationModel
//     .DataTransfer）—— 底层仍是 win32k，但不经过 user32 的这两个导出
//   - 读剪贴板"历史"（WIN+V 的记录），走的是另一套 UWP API
//   所以定位是 **可见性**：回答"谁在读我的剪贴板"，不是"剪贴板偷不走"。
//
namespace ClipboardGuard
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
