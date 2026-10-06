#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>

//
// 注册表事件的共享内存通道。
//
// 引擎进程调用 Create() 建立 Policy + Events 两块共享内存；
// 每个被注入的进程调用 Open() 只读挂载 Policy、读写挂载 Events。
//
// Publish() 运行在任意进程的任意线程上，必须做到：
//   - 不加锁、不分配、不阻塞、不抛异常
//   - 缓冲区满时丢弃并计数，绝不等待消费者
//
namespace R3ShieldCoreChannel
{
	// ---- 引擎侧 ----
	bool Create(const R3ShieldCore::Policy& policy) noexcept;

	// 把环形缓冲里已就绪的事件交给 callback；返回处理条数。
	int Drain(void (*callback)(const R3ShieldCore::Event&, void*), void* context) noexcept;

	// 额外的"旁观者"回调：Drain 时对每条事件额外调用一次。
	// 引擎侧用来喂统计聚合（统计在 exe 里，事件在 dll 里 drain）。
	// 只允许注册一个，重复注册覆盖旧的。
	void SetObserver(void (*observer)(const R3ShieldCore::Event&, void*), void* context) noexcept;

	// ---- 注入侧 ----
	bool Open(DWORD enginePid) noexcept;

	// ★ v49：只读挂载 **Policy**（不挂 Events 通道），供**瘦会话**使用。
	//
	// 瘦会话（explorer.exe / svchost.exe / runtimebroker.exe）不装任何 guard，
	// 但它装的 `CreateProcessInternalW` 在注入前要调 `ShouldSkipProcessInjection`
	// —— 那里的 `IsUserNeverInject` 需要读 Policy 才知道用户的 `never_inject=` 名单。
	//
	// ⚠️ 调用它**不会**让 `IsOpen()` 变 true（那是"本进程受监控"的语义）。
	bool OpenPolicyOnly(DWORD enginePid) noexcept;

	// ---- 两侧共用 ----
	void Close() noexcept;
	bool IsOpen() noexcept;

	// 本进程是不是共享对象的创建者（即引擎进程自己）。
	bool IsOwner() noexcept;

	// 事件/询问映射使用同一用户可读写的 ACL；策略映射由调用方请求只读 ACL。
	wil::unique_hlocal BuildSharedSecurityDescriptor(bool allowWrite = true);

	R3ShieldCore::Policy* Policy() noexcept;

	// Events 通道头。这块映射是 READ|WRITE，hook 侧可以往里递增计数
	// （Policy 是只读映射，写它会访问违规）。没打开时返回 nullptr。
	R3ShieldCore::ChannelHeader* Channel() noexcept;

	void Publish(const R3ShieldCore::Event& event) noexcept;
	ULONG DroppedCount() noexcept;
}
