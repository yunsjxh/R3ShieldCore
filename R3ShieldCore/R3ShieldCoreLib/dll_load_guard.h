#pragma once

//
// DLL 加载 / 劫持监控层。
//
// ⚠️ 先读这段 —— 这里最容易把"能看见"当成"能挡住"。
//
//   挂的是两条**常规加载出口**：
//     ① ntdll!LdrLoadDll          ← LoadLibrary* / LoadLibraryEx 的底层出口
//     ② ntdll!NtMapViewOfSection  ← 映射 DLL 映像（SEC_IMAGE）的出口
//
//   绕过它太容易了：
//     - **手工映射（manual map / reflective load）**：自己读 PE、自己在目标
//       进程里分配内存、写节、修重定位、跳入口 —— 全程不碰 LdrLoadDll，
//       模块表里也没有它。这是当前主流注入框架的默认做法，我们看不见。
//     - 内核态驱动直接把映像塞进地址空间（MiMapViewOfImageSection 的
//       内核调用方）—— 用户态没有任何出口。
//     - 直接把 DLL 内容当 shellcode 执行（不映射，只当作代码缓冲区）。
//
//   所以定位是 **可见性**：让用户知道"有程序在从一个不该有 DLL 的地方
//   （临时目录、下载目录、AppData）加载模块"。这正是**白加黑（DLL 侧加载）**
//   的特征 —— 合法 EXE（含 System32 里被豁免的）被诱导加载同目录下的
//   恶意 DLL，或者从 %TEMP% 里 LoadLibrary 一个刚落地的模块。
//   真边界在内核（PsSetLoadImageNotifyRoutine + 驱动签名强制）。
//
// 关键设计：**过滤发生在 hook 层，不在规则层**。
//
//   每个进程启动都要加载几十上百个 System32 DLL（ntdll、kernel32、
//   msvcrt、各种 api-ms-win-* 转发 DLL…），如果每条都产生事件，
//   事件日志会被瞬间淹没 —— 和"hosts 时间戳刷出 1.3 万条 HIGH"那次
//   是同一种失效模式（噪音淹没真信号 = 功能性失效）。
//
//   所以 hook 里第一件事就是判"这个路径是不是系统目录"，**是就立刻
//   透传、不计数、不上报、不判定**。规则层永远看不到系统 DLL。
//
//   系统目录 = %SystemRoot% 下全部（System32 / SysWOW64 / WinSxS /
//   servicing / Microsoft.NET…）+ Program Files / Program Files (x86)。
//   这两个前缀之外的加载，才上报。
//
//   ⚠️ 上报表 ≠ 判高危。规则层只有"用户可写目录（Temp/AppData/Downloads…）
//      加载"和"手工映射"才算高危；Program Files 下的自装软件加载自己
//      的 DLL 只记录（Allowed），不弹窗不拦 —— 否则噪音会淹没真信号。
//
namespace DllLoadGuard
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
