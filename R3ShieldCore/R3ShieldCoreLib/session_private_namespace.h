#pragma once

namespace SessionPrivateNamespace
{
	// PID alone can be reused after an unclean engine exit. Include the
	// engine creation timestamp so a stale namespace cannot block startup.
	constexpr size_t PrivateNamespaceMaxLen = sizeof("CustomizationSession1234567890-FFFFFFFFFFFFFFFF") - 1;

	int MakeName(WCHAR szPrivateNamespaceName[PrivateNamespaceMaxLen + 1], DWORD dwSessionManagerProcessId) noexcept;

	//
	// 「进程初始化 APC 互斥体」的对象名。
	//
	// 形状：`<名空间名>-ProcessInitAPCMutex-pid=<子进程pid>`
	//
	// ★★★ v46 铁律：名空间名与互斥体名之间**必须用 `-`（连字符），不能用 `\`**。
	//
	//   用 `\` 的话这个名字在对象管理器里被当成**对象路径**：它会先去根目录
	//   找 `<名空间名>` 这个"目录"。而 `Create()` **从来没有真的调用过
	//   `CreatePrivateNamespace`**（`BuildBoundaryDescriptor` 是死代码）⇒
	//   那个"目录"不存在 ⇒ `CreateMutex` 返回 `ERROR_PATH_NOT_FOUND(3)`。
	//
	//   实测（`_t/mtx/probe.cpp`）：
	//     `CustomizationSession12345-...\ProcessInitAPCMutex-pid=5678` -> err=3
	//     `CustomizationSession12345-...-ProcessInitAPCMutex-pid=5678` -> err=0
	//     （真的 `CreatePrivateNamespaceW` 之后再试第一种形状 -> err=0）
	//
	//   轮询路（`all_processes_injector.cpp`）历史上踩过这个坑、已改成 `-`；
	//   同步路（`new_process_injector.cpp`）漏了 ⇒ **同步注入路从来没成功过**，
	//   每次都抛异常被 `HandleCreatedProcess` 吞掉、子进程照常 Resume，
	//   最后全靠 10 ms 轮询兜底（盲区回来了，日志里却看不见）。
	//
	//   抽成函数是为了让两条路**不可能再分叉**。
	//
	// 缓冲区至少 `PrivateNamespaceMaxLen + ProcessInitAPCMutexNameExtra`。
	//
	constexpr size_t ProcessInitAPCMutexNameExtra =
		sizeof("-ProcessInitAPCMutex-pid=1234567890");

	int MakeProcessInitAPCMutexName(WCHAR* szBuffer, size_t cchBuffer,
		DWORD dwSessionManagerProcessId, DWORD processId) noexcept;

	bool Create(DWORD dwSessionManagerProcessId) noexcept;
	bool Open(DWORD dwSessionManagerProcessId) noexcept;
}
