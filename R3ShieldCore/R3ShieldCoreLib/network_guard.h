#pragma once

//
// 网络行为拦截层（ws2_32 用户态出口）。
//
// ⚠️ 先读这段，免得误以为这是防火墙：
//
//   这里挂的是 **ws2_32.dll 导出的 Winsock API**。能拦住的是"规规矩矩
//   调 socket/connect/sendto 的程序"—— 也就是绝大多数正常软件的绝大多数行为。
//
//   绕过它太容易了：
//     - 静态链接 / 自带 socket 实现，不走 ws2_32 的导出
//     - 直接 DeviceIoControl 打到 \Device\Afd（Winsock 底层就是它）
//       ★ v18 已补：挂了 ntdll!NtDeviceIoControlFile，只认 AFD_SEND / AFD_RECV /
//         AFD_SEND_DATAGRAM 三个 IOCTL 码，其余透传（该 syscall 高频，
//         必须先精确过滤）。能看见这条路上的出站，但仍拦不住"静态链接 +
//         直发原始 socket"。
//     - WinHTTP / WinINet 在内部有自己的一份 ws2_32 副本，且会重写参数
//     - 起个子进程，让子进程去连（父进程这边看不见）
//     - 直接发原始 socket（SOCK_RAW）绕过 TCP 栈
//
//   所以本模块的定位是 **可见性工具**，不是安全边界：
//   它回答"这台机器上的进程正在连谁"，而不是"保证它连不上"。
//   真正的网络执法在内核：WFP (Windows Filtering Platform) / NDIS / TDI。
//
// 与其它 guard 共享同一套骨架：判定 → 上报 / 拒绝 → 等排空。
// 特殊之处：
//   1. 所有地址都是 sockaddr 结构，要自己解析成文本（不能用 inet_ntop ——
//      它在 ws2_32 里，从 hook 里调会递归回自己）。
//   2. 端口是网络字节序（大端），要用 ntohs 语义手动换。
//   3. "可拦"不等于"该拦"：listen/accept/bind 在服务端程序里极高频，
//      默认不挂（由 FlagHookNetAll 开）；真正默认拦的是出站（connect/sendto）。
//
namespace NetworkGuard
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
