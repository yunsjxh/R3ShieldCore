#pragma once

//
// COM / OLE 激活劫持监控层（v12）。
//
// ⚠️ 补的是哪一类缺口：
//
//   COM 劫持是**持久化 + 提权**的经典手法，而且几乎完全绕开前面所有 guard：
//
//     ① 写注册表：
//          HKCU\Software\Classes\CLSID\{guid}\InprocServer32 = C:\evil.dll
//        （用户级劫持，**不需要管理员**；HKCR 是 HKLM+HKCU 的合并视图，
//          HKCU 一侧优先）
//     ② 等某个高权限进程（资源管理器、任务栏、提权后的安装器）
//        按这个 CLSID 做 CoCreateInstance →
//        **它就把我们的 DLL 加载进了自己的进程**（进程内服务器）
//        或者**按我们的 EXE 起了个新进程**（本地服务器）
//
//   ① 那一步 RegistryGuard 能看到（写 CLSID 键），但**看不到"现在真的被
//   激活了"** —— 而被激活才是实际执行。② 这一步没有任何一个既有 guard
//   覆盖：DllLoadGuard 只看 LdrLoadDll / NtMapViewOfSection，COM 走的
//   是 NtCreateSection + LdrLoadDll 的组合，模块路径**可以**被看到，
//   但"这是由一个 CLSID 解析出来的"这层语义丢了。
//
//   所以本 guard 挂在**激活入口**上，把"CLSID → 服务器路径"解析出来，
//   路径落在用户可写目录就判高危。理由与判据见 r3shieldcore_rules.cpp
//   的 ComHijackRiskReason。
//
// ⚠️ 三条激活路径都要挂（"挂了一个 API ≠ 挂了这件事" 铁律 12）：
//     CoCreateInstance     —— 高层入口，最常用
//     CoCreateInstanceEx   —— 远程/多接口变体
//     CoGetClassObject     —— 底层入口，拿 IClassFactory 自己 CreateInstance
//
// ⚠️ 能力边界：
//   · 走 IClassFactory 缓存（CoGetClassObject 之后重复 CreateInstance）
//     不会重复报 —— 但第一次拿 IClassFactory 时报过了。
//   · 已注册的**运行中对象**（ROT / GetActiveObject）不经过这三条 —— 不覆盖。
//   · 直接读 HKCU\Software\Classes\CLSID 拿到服务器路径自己 LoadLibrary ——
//     那就是 DllLoadGuard 的活（非系统目录会报）。
//   · 真正的执法点是内核对象回调 + CLSID 解析，用户态 hook 只能到这一层。
//
namespace ComHijackGuard
{
	bool Install(HANDLE engineProcess) noexcept;

	// 已挂载的 hook 数量，供日志使用。
	int HookCount() noexcept;

	// 收尾：等所有"在飞"的 hook 跑完（顺序约束同其它 guard）。
	void WaitForHooksToDrain(DWORD timeoutMs) noexcept;
}
