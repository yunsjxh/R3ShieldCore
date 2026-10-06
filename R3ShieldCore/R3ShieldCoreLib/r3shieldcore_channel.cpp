#include "stdafx.h"
#include "r3shieldcore_channel.h"
#include "functions.h"
#include "logger.h"

namespace
{
	wil::unique_handle g_policyMapping;
	wil::unique_handle g_channelMapping;
	R3ShieldCore::Policy* g_policy = nullptr;
	R3ShieldCore::ChannelHeader* g_channel = nullptr;
	bool g_ownsObjects = false;

	// 旁观者回调：每条事件额外投递一次，用来喂引擎侧统计。
	void (*g_observer)(const R3ShieldCore::Event&, void*) = nullptr;
	void* g_observerContext = nullptr;

	//
	// 用指定前缀建通道。返回 false 表示这个前缀建不起来（比如没有
	// SeCreateGlobalPrivilege 时建不了 Global\ 对象），调用方换一个前缀再试。
	//
	bool CreateWithPrefix(const R3ShieldCore::Policy& policy, PCWSTR prefix) noexcept
	{
		auto policySecurityDescriptor = GetSharedObjectSecurityDescriptor(false);
		auto channelSecurityDescriptor = GetSharedObjectSecurityDescriptor(true);
		if (!policySecurityDescriptor || !channelSecurityDescriptor) {
			return false;
		}

		SECURITY_ATTRIBUTES policySecurityAttributes = { sizeof(SECURITY_ATTRIBUTES) };
		policySecurityAttributes.lpSecurityDescriptor = policySecurityDescriptor.get();
		policySecurityAttributes.bInheritHandle = FALSE;
		SECURITY_ATTRIBUTES channelSecurityAttributes = { sizeof(SECURITY_ATTRIBUTES) };
		channelSecurityAttributes.lpSecurityDescriptor = channelSecurityDescriptor.get();
		channelSecurityAttributes.bInheritHandle = FALSE;

		DWORD enginePid = GetCurrentProcessId();
		WCHAR name[R3ShieldCore::ObjectNameCapacity];

		R3ShieldCore::MakePolicyName(name, _countof(name), prefix, enginePid);
		SetLastError(ERROR_SUCCESS);
		wil::unique_handle policyMapping(CreateFileMapping(INVALID_HANDLE_VALUE, &policySecurityAttributes,
			PAGE_READWRITE, 0, sizeof(R3ShieldCore::Policy), name));
		if (!policyMapping || GetLastError() == ERROR_ALREADY_EXISTS) {
			LOG(L"R3ShieldCore: CreateFileMapping(policy) failed prefix=%ls err=%u",
				prefix, GetLastError());
			return false;
		}

		auto* policyView = static_cast<R3ShieldCore::Policy*>(
			MapViewOfFile(policyMapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(R3ShieldCore::Policy)));
		if (!policyView) {
			LOG(L"R3ShieldCore: MapViewOfFile(policy) failed prefix=%ls err=%u",
				prefix, GetLastError());
			return false;
		}

		*policyView = policy;
		policyView->Magic = R3ShieldCore::PolicyMagic;
		policyView->Version = R3ShieldCore::AbiVersion;
		policyView->EngineProcessId = enginePid;

		R3ShieldCore::MakeChannelName(name, _countof(name), prefix, enginePid);
		SetLastError(ERROR_SUCCESS);
		wil::unique_handle channelMapping(CreateFileMapping(INVALID_HANDLE_VALUE, &channelSecurityAttributes,
			PAGE_READWRITE, 0, static_cast<DWORD>(R3ShieldCore::ChannelBytes()), name));
		if (!channelMapping || GetLastError() == ERROR_ALREADY_EXISTS) {
			LOG(L"R3ShieldCore: CreateFileMapping(channel) failed prefix=%ls err=%u",
				prefix, GetLastError());
			UnmapViewOfFile(policyView);
			return false;
		}

		auto* channelView = static_cast<R3ShieldCore::ChannelHeader*>(
			MapViewOfFile(channelMapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, R3ShieldCore::ChannelBytes()));
		if (!channelView) {
			LOG(L"R3ShieldCore: MapViewOfFile(channel) failed prefix=%ls err=%u",
				prefix, GetLastError());
			UnmapViewOfFile(policyView);
			return false;
		}

		ZeroMemory(channelView, R3ShieldCore::ChannelBytes());
		channelView->Magic = R3ShieldCore::ChannelMagic;
		channelView->Version = R3ShieldCore::AbiVersion;
		channelView->Capacity = R3ShieldCore::EventCapacity;

		g_policyMapping = std::move(policyMapping);
		g_channelMapping = std::move(channelMapping);
		g_policy = policyView;
		g_channel = channelView;
		g_ownsObjects = true;

		return true;
	}

	bool OpenWithPrefix(DWORD enginePid, PCWSTR prefix) noexcept
	{
		WCHAR name[R3ShieldCore::ObjectNameCapacity];

		R3ShieldCore::MakePolicyName(name, _countof(name), prefix, enginePid);
		wil::unique_handle policyMapping(OpenFileMapping(FILE_MAP_READ, FALSE, name));
		if (!policyMapping) {
			LOG(L"R3ShieldCore: OpenFileMapping(policy) failed pid=%u prefix=%ls err=%u",
				enginePid, prefix, GetLastError());
			return false;
		}

		auto* policyView = static_cast<R3ShieldCore::Policy*>(
			MapViewOfFile(policyMapping.get(), FILE_MAP_READ, 0, 0, sizeof(R3ShieldCore::Policy)));
		if (!policyView) {
			LOG(L"R3ShieldCore: MapViewOfFile(policy) failed pid=%u prefix=%ls err=%u",
				enginePid, prefix, GetLastError());
			return false;
		}

		if (policyView->Magic != R3ShieldCore::PolicyMagic ||
			policyView->Version != R3ShieldCore::AbiVersion ||
			policyView->EngineProcessId != enginePid) {
			UnmapViewOfFile(policyView);
			return false;
		}

		R3ShieldCore::MakeChannelName(name, _countof(name), prefix, enginePid);
		wil::unique_handle channelMapping(OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name));
		if (!channelMapping) {
			LOG(L"R3ShieldCore: OpenFileMapping(channel) failed pid=%u prefix=%ls err=%u",
				enginePid, prefix, GetLastError());
			UnmapViewOfFile(policyView);
			return false;
		}

		auto* channelView = static_cast<R3ShieldCore::ChannelHeader*>(
			MapViewOfFile(channelMapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, R3ShieldCore::ChannelBytes()));
		if (!channelView) {
			LOG(L"R3ShieldCore: MapViewOfFile(channel) failed pid=%u prefix=%ls err=%u",
				enginePid, prefix, GetLastError());
			UnmapViewOfFile(policyView);
			return false;
		}

		if (channelView->Magic != R3ShieldCore::ChannelMagic) {
			UnmapViewOfFile(channelView);
			UnmapViewOfFile(policyView);
			return false;
		}

		g_policyMapping = std::move(policyMapping);
		g_channelMapping = std::move(channelMapping);
		g_policy = policyView;
		g_channel = channelView;
		g_ownsObjects = false;

		return true;
	}

	//
	// ★★★ v49：**只**挂载 Policy 视图，**不**挂载 Events 通道。
	//
	// 为什么需要它（一个真会漏注入的洞）：
	//   **瘦会话**（`explorer.exe` / `svchost.exe` / `runtimebroker.exe`）**一个
	//   guard 都不装**，所以历史上从不碰通道 —— 但瘦会话装的那个
	//   `CreateProcessInternalW`（`new_process_injector.cpp`）在注入前会调
	//   `ShouldSkipProcessInjection`，而 `IsUserNeverInject` 要读 `Policy` 才能
	//   拿到用户的 `never_inject=` 名单。
	//
	//   没有 Policy ⇒ `R3ShieldCoreChannel::Policy()` 是 nullptr ⇒ `IsUserNeverInject`
	//   恒返 false ⇒ **用户"双击"启动的程序（父进程 = explorer = 瘦会话）仍然
	//   会被同步注入路注进去** —— 恰好绕过了免注入名单。
	//
	//   （"双击"正是最典型的启动方式，所以这个洞必须补。）
	//
	// ⚠️ 故意**不**设置 `g_channel`：`IsOpen()` 必须保持 false。
	//    `IsOpen()` 的语义是"本进程是个**受监控**的进程"（有 Events 通道能上报）。
	//    瘦会话不是 —— 它只是**读**一下策略去决定要不要注入别人。
	//    若这里把 g_channel 填上，瘦会话在别处就会被当成"已受监控"。
	bool PolicyOnlyWithPrefix(DWORD enginePid, PCWSTR prefix) noexcept
	{
		WCHAR name[R3ShieldCore::ObjectNameCapacity];

		R3ShieldCore::MakePolicyName(name, _countof(name), prefix, enginePid);
		wil::unique_handle policyMapping(OpenFileMapping(FILE_MAP_READ, FALSE, name));
		if (!policyMapping) {
			return false;
		}

		auto* policyView = static_cast<R3ShieldCore::Policy*>(
			MapViewOfFile(policyMapping.get(), FILE_MAP_READ, 0, 0, sizeof(R3ShieldCore::Policy)));
		if (!policyView) {
			return false;
		}

		if (policyView->Magic != R3ShieldCore::PolicyMagic ||
			policyView->Version != R3ShieldCore::AbiVersion ||
			policyView->EngineProcessId != enginePid) {
			UnmapViewOfFile(policyView);
			return false;
		}

		g_policyMapping = std::move(policyMapping);
		g_policy = policyView;
		// g_channel 保持 nullptr；g_ownsObjects 保持 false。
		return true;
	}
}

namespace R3ShieldCoreChannel
{
	wil::unique_hlocal BuildSharedSecurityDescriptor(bool allowWrite)
	{
		return GetSharedObjectSecurityDescriptor(allowWrite);
	}

	bool IsOpen() noexcept
	{
		return g_channel != nullptr && g_policy != nullptr;
	}

	bool IsOwner() noexcept
	{
		return g_ownsObjects;
	}

	R3ShieldCore::Policy* Policy() noexcept
	{
		return g_policy;
	}

	R3ShieldCore::ChannelHeader* Channel() noexcept
	{
		return g_channel;
	}

	ULONG DroppedCount() noexcept
	{
		return g_channel ? static_cast<ULONG>(g_channel->DroppedCount) : 0;
	}

	void Close() noexcept
	{
		if (g_channel) {
			UnmapViewOfFile(g_channel);
			g_channel = nullptr;
		}

		if (g_policy) {
			UnmapViewOfFile(g_policy);
			g_policy = nullptr;
		}

		g_channelMapping.reset();
		g_policyMapping.reset();
		g_ownsObjects = false;
	}

	bool Create(const R3ShieldCore::Policy& policy) noexcept
	{
		Close();

		if (CreateWithPrefix(policy, R3ShieldCore::GlobalNamePrefix)) {
			LOG(L"R3ShieldCore: 事件通道已建立（Global 命名空间），容量 %u", R3ShieldCore::EventCapacity);
			return true;
		}

		// 没有 SeCreateGlobalPrivilege 就建不了 Global\ 对象（CreateFileMapping
		// 直接返回 ERROR_ACCESS_DENIED）。退化成会话内命名 —— 没那个特权说明
		// 进程也没提权，本来就注入不到别的会话，会话内命名够用。
		if (CreateWithPrefix(policy, R3ShieldCore::SessionNamePrefix)) {
			LOG(L"R3ShieldCore: 事件通道已建立（会话内命名，引擎未提权）");
			return true;
		}

		LOG(L"R3ShieldCore: 事件通道建立失败（Global 和会话内命名都建不起来）");
		return false;
	}

	bool Open(DWORD enginePid) noexcept
	{
		if (IsOpen()) {
			// 引擎进程自己也会被注入，这时通道是本进程建好的，直接复用。
			return true;
		}

		// 两个前缀都试，引擎建起来的是哪个就打开哪个。
		return OpenWithPrefix(enginePid, R3ShieldCore::GlobalNamePrefix) ||
			OpenWithPrefix(enginePid, R3ShieldCore::SessionNamePrefix);
	}

	//
	// ★★★ v49：瘦会话专用 —— 只读挂载 Policy（不挂 Events 通道）。
	//
	// 见 `PolicyOnlyWithPrefix` 的注释：瘦会话要读 `never_inject=` 名单，
	// 但它**不能**变成"受监控进程"（`IsOpen()` 必须保持 false）。
	//
	// 引擎进程自己（`IsOwner()`）已经有映射，直接复用。
	bool OpenPolicyOnly(DWORD enginePid) noexcept
	{
		if (g_policy != nullptr) {
			return true;
		}

		return PolicyOnlyWithPrefix(enginePid, R3ShieldCore::GlobalNamePrefix) ||
			PolicyOnlyWithPrefix(enginePid, R3ShieldCore::SessionNamePrefix);
	}

	void Publish(const R3ShieldCore::Event& event) noexcept
	{		auto* channel = g_channel;
		if (!channel) {
			return;
		}

		LONG index = InterlockedIncrement(&channel->WriteIndex) - 1;

		// 消费者还没追上就丢弃，绝不阻塞调用方。
		bool dropped = static_cast<ULONG>(index - channel->ReadIndex) >= channel->Capacity;
		if (dropped) {
			InterlockedIncrement(&channel->DroppedCount);
		}

		R3ShieldCore::Event* slot = R3ShieldCore::ChannelEventAt(channel, static_cast<ULONG>(index));

		if (dropped) {
			// 丢弃也要占位，否则消费者会永远卡在这个序号上。
			R3ShieldCore::Event placeholder = {};
			memcpy(slot, &placeholder, sizeof(placeholder));
		}
		else {
			memcpy(slot, &event, sizeof(R3ShieldCore::Event));
		}

		slot->Sequence = 0;
		MemoryBarrier();
		InterlockedExchange(&slot->Sequence, index + 1);
	}

	int Drain(void (*callback)(const R3ShieldCore::Event&, void*), void* context) noexcept
	{		auto* channel = g_channel;
		if (!channel) {
			return 0;
		}

		int count = 0;

		while (true) {
			LONG writeIndex = channel->WriteIndex;
			LONG readIndex = channel->ReadIndex;
			if (readIndex >= writeIndex) {
				break;
			}

			// 生产者已经套圈：readIndex 指向的槽位被后续记录覆盖过，
			// Sequence 再也不可能等于 readIndex + 1。若这里直接 break 等下一轮，
			// 消费者会永久卡死在这个序号上，此后一条事件都读不出来。
			// 只能把消费者推进到最新一圈的起点，跳过这段已丢失的事件
			// （它们早已被生产者的丢弃分支计入 DroppedCount）。
			if (static_cast<ULONG>(writeIndex - readIndex) > channel->Capacity) {
				readIndex = writeIndex - static_cast<LONG>(channel->Capacity);
				InterlockedExchange(&channel->ReadIndex, readIndex);
			}

			R3ShieldCore::Event* slot = R3ShieldCore::ChannelEventAt(channel, static_cast<ULONG>(readIndex));
			if (slot->Sequence != readIndex + 1) {
				// 生产者已经递增了序号但还没写完，下一轮再来。
				break;
			}

			// Op == 0 是缓冲区满时的占位记录。
			if (slot->Op != 0) {
				if (callback) {
					callback(*slot, context);
				}

				if (g_observer) {
					g_observer(*slot, g_observerContext);
				}
			}

			InterlockedExchange(&slot->Sequence, 0);
			InterlockedIncrement(&channel->ReadIndex);
			count++;
		}

		return count;
	}

	void SetObserver(void (*observer)(const R3ShieldCore::Event&, void*), void* context) noexcept
	{
		g_observerContext = context;
		g_observer = observer;
	}
}
