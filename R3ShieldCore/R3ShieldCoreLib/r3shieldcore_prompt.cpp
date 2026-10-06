#include "stdafx.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_channel.h"
#include "logger.h"

namespace
{
	wil::unique_handle g_promptMapping;
	R3ShieldCore::PromptHeader* g_promptHeader = nullptr;
	wil::unique_handle g_requestEvent;
	wil::unique_handle g_slotEvents[R3ShieldCore::PromptSlotCount];

	WCHAR g_processPath[R3ShieldCore::MaxProcessPathChars] = {};
	volatile LONG g_processPathReady = 0;
	volatile LONG g_shutdown = 0;

	// 运行期切 ASK 的按需补开只做一次（成功或失败都算做过）。
	// 不加这个标志的话，每次 Ask 都会走一串 OpenFileMapping / OpenEvent，
	// 而 Ask 在 hook 热路径上。
	volatile LONG g_openAttempted = 0;

	// 当前进程的镜像路径，只算一次。多个线程同时算也无所谓，写的是同一个值。
	PCWSTR CurrentProcessPath() noexcept
	{
		if (g_processPathReady == 0) {
			WCHAR path[R3ShieldCore::MaxProcessPathChars] = {};
			DWORD size = _countof(path);
			if (QueryFullProcessImageName(GetCurrentProcess(), 0, path, &size)) {
				memcpy(g_processPath, path, sizeof(g_processPath));
			}

			InterlockedExchange(&g_processPathReady, 1);
		}

		return g_processPath;
	}

	void CopyString(WCHAR* destination, size_t destinationChars, PCWSTR source, size_t sourceChars, ULONG& lengthOut) noexcept
	{
		size_t chars = sourceChars;
		if (chars >= destinationChars) {
			chars = destinationChars - 1;
		}

		if (source && chars > 0) {
			memcpy(destination, source, chars * sizeof(WCHAR));
		}

		destination[chars] = L'\0';
		lengthOut = static_cast<ULONG>(chars);
	}

	ULONG PromptTimeoutMs() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptTimeoutMs > 0) {
			return policy->PromptTimeoutMs;
		}

		return 30000;
	}

	R3ShieldCore::Verdict PromptDefaultVerdict() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
			return static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
		}

		return R3ShieldCore::Verdict::Deny;
	}

	//
	// 一次 Win32 调用可能触发多次底层 Nt 调用。
	//
	// 实测：RegCreateKeyExW 建键失败后会退回去建父路径 ——
	// 先 NtCreateKey("Software\R3ShieldCoreTest")，被拒后再 NtCreateKey("Software")。
	// ask 模式下这会弹两次窗，超时也翻倍（实测 16s = 2×8s）。
	//
	// 这里按线程记住上一次的结论：同线程、且新键路径是上次键路径的
	// 祖先或后代（带边界）时直接复用，不再弹窗。
	//
	// ⚠ 但"同操作"的限制太严了：实测 NtOpenKey 与 NtCreateKey 交替出现
	// （先试探打开、失败后创建），两者是**同一次高层调用的两个阶段**。
	// 只按 op 相等去比会漏掉这种情况，于是同一个键被问两遍。
	// 所以把 Op 分成"打开"和"建/写"两组，组内可互相复用：
	// 同一组里的相邻操作基本都来自同一次 Win32 调用。
	//
	struct LastVerdict
	{
		bool valid;
		ULONG op;
		ULONG tick;
		WCHAR keyPath[R3ShieldCore::MaxKeyPathChars];
		R3ShieldCore::Verdict verdict;
	};

	__declspec(thread) LastVerdict t_lastVerdict = {};

	// 把 Op 归并成"行为组"。同组内的操作可以复用一次询问结论。
	ULONG OpGroup(ULONG op) noexcept
	{
		switch (static_cast<R3ShieldCore::Op>(op)) {
		// 打开类：只是拿句柄，失败会诱发创建
		case R3ShieldCore::Op::OpenKey:
			return 1;

		// 建/写类：真正改变注册表内容
		case R3ShieldCore::Op::CreateKey:
		case R3ShieldCore::Op::SetValueKey:
		case R3ShieldCore::Op::DeleteKey:
		case R3ShieldCore::Op::DeleteValueKey:
		case R3ShieldCore::Op::RenameKey:
		case R3ShieldCore::Op::SetInformationKey:
			return 2;

		// hive 类：各自独立，不与其他操作混用结论
		default:
			return op;
		}
	}

	bool IsAncestorOrSame(PCWSTR a, PCWSTR b) noexcept
	{
		size_t lengthA = wcslen(a);
		if (lengthA == 0) {
			return false;
		}

		if (_wcsnicmp(a, b, lengthA) != 0) {
			return false;
		}

		WCHAR next = b[lengthA];
		return next == L'\0' || next == L'\\';
	}

	// 两个键路径是否"同源"：一个是另一个的祖先或后代。
	// 父路径回退（长 → 短）和先开后建（短 → 长）两个方向都要认。
	bool IsSameKeyFamily(PCWSTR a, PCWSTR b) noexcept
	{
		return IsAncestorOrSame(a, b) || IsAncestorOrSame(b, a);
	}

	bool TryReuseLastVerdict(const R3ShieldCore::Event& event, R3ShieldCore::Verdict& verdict) noexcept
	{
		if (!t_lastVerdict.valid) {
			return false;
		}

		// 同组才复用（打开组 / 建写组 / 各自的 hive op）。
		if (OpGroup(t_lastVerdict.op) != OpGroup(event.Op)) {
			return false;
		}

		// 超过两倍超时就当新的一次操作，不再复用。
		ULONG window = PromptTimeoutMs() * 2 + 2000;
		if (GetTickCount() - t_lastVerdict.tick > window) {
			return false;
		}

		if (!IsSameKeyFamily(event.KeyPath, t_lastVerdict.keyPath)) {
			return false;
		}

		verdict = t_lastVerdict.verdict;
		return true;
	}

	void RememberVerdict(const R3ShieldCore::Event& event, R3ShieldCore::Verdict verdict) noexcept
	{
		t_lastVerdict.op = event.Op;
		t_lastVerdict.tick = GetTickCount();
		wcsncpy_s(t_lastVerdict.keyPath, event.KeyPath, _TRUNCATE);
		t_lastVerdict.verdict = verdict;
		t_lastVerdict.valid = true;
	}
}

namespace R3ShieldCorePrompt
{
	bool IsOpen() noexcept
	{
		return g_promptHeader != nullptr && g_requestEvent != nullptr;
	}

	R3ShieldCore::PromptHeader* Header() noexcept
	{
		return g_promptHeader;
	}

	HANDLE RequestEvent() noexcept
	{
		return g_requestEvent.get();
	}

	HANDLE SlotEvent(ULONG index) noexcept
	{
		if (index >= R3ShieldCore::PromptSlotCount) {
			return nullptr;
		}

		return g_slotEvents[index].get();
	}

	ULONG SlotCount() noexcept
	{
		return g_promptHeader ? g_promptHeader->SlotCount : 0;
	}

	void Close() noexcept
	{
		InterlockedExchange(&g_shutdown, 0);
		InterlockedExchange(&g_openAttempted, 0);
		InterlockedExchange(&g_processPathReady, 0);
		ZeroMemory(g_processPath, sizeof(g_processPath));

		for (ULONG i = 0; i < R3ShieldCore::PromptSlotCount; i++) {
			g_slotEvents[i].reset();
		}

		g_requestEvent.reset();

		if (g_promptHeader) {
			UnmapViewOfFile(g_promptHeader);
			g_promptHeader = nullptr;
		}

		g_promptMapping.reset();
	}

	static bool CreateWithPrefix(PCWSTR prefix) noexcept
	{
		try {
			Close();

			auto securityDescriptor = R3ShieldCoreChannel::BuildSharedSecurityDescriptor(true);
			if (!securityDescriptor) {
				return false;
			}

			SECURITY_ATTRIBUTES securityAttributes = { sizeof(SECURITY_ATTRIBUTES) };
			securityAttributes.lpSecurityDescriptor = securityDescriptor.get();
			securityAttributes.bInheritHandle = FALSE;

			DWORD enginePid = GetCurrentProcessId();

			WCHAR name[R3ShieldCore::ObjectNameCapacity];

			R3ShieldCore::MakePromptName(name, _countof(name), prefix, enginePid);
			SetLastError(ERROR_SUCCESS);
			wil::unique_handle mapping(CreateFileMapping(INVALID_HANDLE_VALUE, &securityAttributes,
				PAGE_READWRITE, 0, static_cast<DWORD>(R3ShieldCore::PromptBytes()), name));
			if (!mapping || GetLastError() == ERROR_ALREADY_EXISTS) {
				LOG(L"R3ShieldCore: CreateFileMapping(prompt) failed prefix=%ls err=%u",
					prefix, GetLastError());
				return false;
			}

			auto* header = static_cast<R3ShieldCore::PromptHeader*>(
				MapViewOfFile(mapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, R3ShieldCore::PromptBytes()));
			if (!header) {
				LOG(L"R3ShieldCore: MapViewOfFile(prompt) failed prefix=%ls err=%u",
					prefix, GetLastError());
				return false;
			}

			ZeroMemory(header, R3ShieldCore::PromptBytes());
			header->Magic = R3ShieldCore::PromptMagic;
			header->Version = R3ShieldCore::AbiVersion;
			header->SlotCount = R3ShieldCore::PromptSlotCount;

			R3ShieldCore::MakePromptRequestEventName(name, _countof(name), prefix, enginePid);
			SetLastError(ERROR_SUCCESS);
			wil::unique_handle requestEvent(CreateEvent(&securityAttributes, FALSE, FALSE, name));
			if (!requestEvent || GetLastError() == ERROR_ALREADY_EXISTS) {
				LOG(L"R3ShieldCore: CreateEvent(prompt request) failed prefix=%ls err=%u",
					prefix, GetLastError());
				UnmapViewOfFile(header);
				return false;
			}

			wil::unique_handle slotEvents[R3ShieldCore::PromptSlotCount];
			for (ULONG i = 0; i < R3ShieldCore::PromptSlotCount; i++) {
				R3ShieldCore::MakePromptSlotEventName(name, _countof(name), prefix, enginePid, i);
				SetLastError(ERROR_SUCCESS);
				slotEvents[i].reset(CreateEvent(&securityAttributes, FALSE, FALSE, name));
				if (!slotEvents[i] || GetLastError() == ERROR_ALREADY_EXISTS) {
					LOG(L"R3ShieldCore: CreateEvent(prompt slot=%u) failed prefix=%ls err=%u",
						i, prefix, GetLastError());
					UnmapViewOfFile(header);
					return false;
				}
			}

			g_promptMapping = std::move(mapping);
			g_promptHeader = header;
			g_requestEvent = std::move(requestEvent);
			for (ULONG i = 0; i < R3ShieldCore::PromptSlotCount; i++) {
				g_slotEvents[i] = std::move(slotEvents[i]);
			}

			return true;
		}
		catch (const std::exception&) {
			Close();
			return false;
		}
	}

	bool Create() noexcept
	{
		Close();

		if (CreateWithPrefix(R3ShieldCore::GlobalNamePrefix)) {
			LOG(L"R3ShieldCore: 询问通道已建立（Global 命名空间），%u 个槽", R3ShieldCore::PromptSlotCount);
			return true;
		}

		// 没有 SeCreateGlobalPrivilege 就建不了 Global\ 对象，退化成会话内命名。
		if (CreateWithPrefix(R3ShieldCore::SessionNamePrefix)) {
			LOG(L"R3ShieldCore: 询问通道已建立（会话内命名，引擎未提权），%u 个槽", R3ShieldCore::PromptSlotCount);
			return true;
		}

		LOG(L"R3ShieldCore: 询问通道建立失败");
		return false;
	}

	static bool OpenWithPrefix(DWORD enginePid, PCWSTR prefix) noexcept
	{
		try {
			WCHAR name[R3ShieldCore::ObjectNameCapacity];

			R3ShieldCore::MakePromptName(name, _countof(name), prefix, enginePid);
			wil::unique_handle mapping(OpenFileMapping(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name));
			if (!mapping) {
				LOG(L"R3ShieldCore: OpenFileMapping(prompt) failed pid=%u prefix=%ls err=%u",
					enginePid, prefix, GetLastError());
				return false;
			}

			auto* header = static_cast<R3ShieldCore::PromptHeader*>(
				MapViewOfFile(mapping.get(), FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, R3ShieldCore::PromptBytes()));
			if (!header) {
				LOG(L"R3ShieldCore: MapViewOfFile(prompt) failed pid=%u prefix=%ls err=%u",
					enginePid, prefix, GetLastError());
				return false;
			}

			if (header->Magic != R3ShieldCore::PromptMagic || header->Version != R3ShieldCore::AbiVersion) {
				UnmapViewOfFile(header);
				return false;
			}

			R3ShieldCore::MakePromptRequestEventName(name, _countof(name), prefix, enginePid);
			// The injected side only signals this event.  Requesting SYNCHRONIZE
			// here unnecessarily fails against older event DACL mappings.
			wil::unique_handle requestEvent(OpenEvent(EVENT_MODIFY_STATE, FALSE, name));
			if (!requestEvent) {
				LOG(L"R3ShieldCore: OpenEvent(prompt request) failed pid=%u prefix=%ls err=%u",
					enginePid, prefix, GetLastError());
				UnmapViewOfFile(header);
				return false;
			}

			wil::unique_handle slotEvents[R3ShieldCore::PromptSlotCount];
			for (ULONG i = 0; i < R3ShieldCore::PromptSlotCount; i++) {
				R3ShieldCore::MakePromptSlotEventName(name, _countof(name), prefix, enginePid, i);
				slotEvents[i].reset(OpenEvent(SYNCHRONIZE, FALSE, name));
				if (!slotEvents[i]) {
					LOG(L"R3ShieldCore: OpenEvent(prompt slot=%u) failed pid=%u prefix=%ls err=%u",
						i, enginePid, prefix, GetLastError());
					UnmapViewOfFile(header);
					return false;
				}
			}

			g_promptMapping = std::move(mapping);
			g_promptHeader = header;
			g_requestEvent = std::move(requestEvent);
			for (ULONG i = 0; i < R3ShieldCore::PromptSlotCount; i++) {
				g_slotEvents[i] = std::move(slotEvents[i]);
			}

			return true;
		}
		catch (const std::exception&) {
			Close();
			return false;
		}
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

	// 运行期切到 ASK 时的兜底补开。
	//
	// 正常路径是 registry_guard 的 Install 无条件开好通道（引擎在注入之前
	// 就建好了通道）。这里防的是边角：
	//   · 本进程的 Install 早于询问通道建立（理论上不会，但便宜）
	//   · Install 那次 Open 因为权限/时序失败过
	//   · 未来某个 guard 不走 registry_guard 的 Install
	//
	// ⚠️ 只试一次。失败就记住，绝不能在热路径上反复做系统调用。
	bool EnsureOpenForAsk() noexcept
	{
		if (g_promptHeader && g_requestEvent) {
			return true;
		}

		if (InterlockedCompareExchange(&g_openAttempted, 1, 0) != 0) {
			return false; // 已经试过了
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		const DWORD enginePid = policy ? policy->EngineProcessId : 0;
		if (!enginePid) {
			return false;
		}

		if (!Open(enginePid)) {
			LOG(L"R3ShieldCore: 询问通道按需打开失败（运行期切 ASK），本进程按兜底结论处理");
			return false;
		}

		LOG(L"R3ShieldCore: 询问通道已按需打开（运行期切 ASK）");
		return true;
	}

	R3ShieldCore::Verdict Ask(const R3ShieldCore::Event& event, R3ShieldCore::Verdict fallback) noexcept
	{
		// Log is observational by definition. Do not enter the prompt channel
		// or allow a missing channel to turn an audit event into a denial.
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (!policy || policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
			return R3ShieldCore::Verdict::Allow;
		}

		auto* header = g_promptHeader;
		if (!header || !g_requestEvent) {
			if (!EnsureOpenForAsk()) {
				return fallback;
			}

			header = g_promptHeader;
			if (!header || !g_requestEvent) {
				return fallback;
			}
		}

		// 同一次 Win32 调用引发的后续 Nt 调用，直接复用上一次的结论。
		R3ShieldCore::Verdict reusedVerdict;
		if (TryReuseLastVerdict(event, reusedVerdict)) {
			return reusedVerdict;
		}

		R3ShieldCore::PromptSlot* slots = R3ShieldCore::PromptSlotBase(header);
		ULONG count = header->SlotCount;
		if (count > R3ShieldCore::PromptSlotCount) {
			count = R3ShieldCore::PromptSlotCount;
		}

		// 同一进程已经有请求在等用户，就不再弹第二个窗。
		// 这既是防刷屏，也避免了"用户还没点完，进程已经被问十次"。
		for (ULONG i = 0; i < count; i++) {
			if (slots[i].State == R3ShieldCore::PromptSlotPending && slots[i].ProcessId == event.ProcessId) {
				return fallback;
			}
		}

		ULONG index = 0;
		R3ShieldCore::PromptSlot* slot = nullptr;
		for (; index < count; index++) {
			if (InterlockedCompareExchange(&slots[index].State,
					R3ShieldCore::PromptSlotClaimed, R3ShieldCore::PromptSlotFree) == R3ShieldCore::PromptSlotFree) {
				slot = &slots[index];
				break;
			}
		}

		if (!slot) {
			return fallback;
		}

		// 世代号必须在发布之前递增，否则引擎可能读到上一次的值。
		LONG generation = InterlockedIncrement(&slot->Generation);

		slot->Op = event.Op;
		slot->ObjectType = event.ObjectType;
		slot->ProcessId = event.ProcessId;
		slot->ThreadId = event.ThreadId;
		slot->TimeStamp = event.TimeStamp;
		slot->TargetKind = event.TargetKind;
		slot->Flags = event.Flags;
		slot->AnsweredGeneration = 0;
		slot->Verdict = static_cast<ULONG>(fallback);

		CopyString(slot->KeyPath, _countof(slot->KeyPath), event.KeyPath, event.KeyPathLength, slot->KeyPathLength);
		CopyString(slot->ValueName, _countof(slot->ValueName), event.ValueName, event.ValueNameLength, slot->ValueNameLength);
		CopyString(slot->ProcessPath, _countof(slot->ProcessPath), CurrentProcessPath(),
			wcslen(CurrentProcessPath()), slot->ProcessPathLength);

		// v10：DLL 加载路径 / 进程旁路命令行。按对象类型只拷对应那一个，
		// 另一个留空。两者都是尾部追加字段，不影响既有偏移。
		// 这里不需要各自的长度字段（PromptSlot 里没加），用临时变量接一下。
		ULONG ignoredLength = 0;
		if (event.ObjectType == static_cast<ULONG>(R3ShieldCore::ObjectType::ProcessSpawn)) {
			CopyString(slot->CommandLine, _countof(slot->CommandLine), event.CommandLine,
				wcslen(event.CommandLine), ignoredLength);
		}
		else if (event.ObjectType == static_cast<ULONG>(R3ShieldCore::ObjectType::DllLoad)) {
			CopyString(slot->DllPath, _countof(slot->DllPath), event.DllPath,
				wcslen(event.DllPath), ignoredLength);
		}

		MemoryBarrier();
		InterlockedExchange(&slot->State, R3ShieldCore::PromptSlotPending);
		SetEvent(g_requestEvent.get());

		HANDLE slotEvent = g_slotEvents[index].get();
		DWORD timeoutMs = PromptTimeoutMs();
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		R3ShieldCore::Verdict verdict = fallback;

		while (true) {
			// 引擎没了 / 要收尾了，立刻收手。否则宿主进程的线程会白等满超时。
			if (InterlockedCompareExchange(&g_shutdown, 0, 0) != 0) {
				break;
			}

			LONGLONG remaining = static_cast<LONGLONG>(deadline) - static_cast<LONGLONG>(GetTickCount64());
			if (remaining <= 0) {
				break;
			}

			// 切成小片等待，才能及时看到 shutdown 标志。
			DWORD slice = (remaining > 250) ? 250 : static_cast<DWORD>(remaining);
			DWORD waitResult = WaitForSingleObject(slotEvent, slice);
			if (waitResult == WAIT_OBJECT_0 &&
				slot->State == R3ShieldCore::PromptSlotAnswered &&
				slot->AnsweredGeneration == generation) {
				verdict = static_cast<R3ShieldCore::Verdict>(slot->Verdict);
				break;
			}

			// 其余情况（超时切片 / 上一次请求的迟到答复）继续等自己的。
		}

		InterlockedExchange(&slot->State, R3ShieldCore::PromptSlotFree);

		RememberVerdict(event, verdict);
		return verdict;
	}

	// ------------------------------------------------------------------
	// ★★ v29：带「通道可用性」降级判定的询问包装（所有 guard 共用）
	// ------------------------------------------------------------------
	//
	// 详见头文件说明。一句话：`Ask()` 的 fallback=`deny` 分不清
	// "用户拒绝"和"问不出去"，导致管理员启动引擎时**静默全拒**。
	// 这里把 v26/v28 在 registry/file 侧做的降级**收拢成公共实现**。
	//
	// ★ 为什么必须在**调用 Ask 之前**探测：`IsOpen()` 是纯读（两个全局指针
	//   非空），廉价、不阻塞、不弹窗；`Ask()` 则会立刻返 fallback，事后无法
	//   区分"通道不在"与"用户点了拒绝"。所以先探再问。
	//
	// ★ 为什么**只降 Log 模式**：Log 的语义就是"只记录、全部放行"
	//   （r3shieldcore.ini 明文）。Block/Ask/block_all 是用户明确表达的
	//   "要拦 / 要问"，通道坏了也不该悄悄放行 —— 那是**安全边界的塌陷**。
	bool AskWithChannelGuard(const R3ShieldCore::Event& event, R3ShieldCore::Verdict fallback,
		ULONG mode, R3ShieldCore::Verdict& verdictOut) noexcept
	{
		const bool available = IsOpen();

		if (!available) {
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
				// LOG 模式 + 通道不可用 → 告诉调用方"降级放行"。
				verdictOut = fallback;
				return false;
			}

			// 非 LOG：保持原语义（按 fallback 处置，通常是拒）。
			verdictOut = fallback;
			return true;
		}

		verdictOut = Ask(event, fallback);

		// ★ 通道可能在"调用过程中"失效（引擎退出 / NotifyShutdown）。
		//   再补探一次：LOG 模式下同样降级放行，与 v26/v28 的第二次补探同构。
		const R3ShieldCore::Verdict effectiveFallback = fallback;
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) &&
			!IsOpen() &&
			verdictOut == effectiveFallback) {
			// 只有"结论恰好等于 fallback"时才可能是通道失效造成的；
			// 用户真的点了拒绝时 IsOpen() 仍为 true，不会误判。
			verdictOut = fallback;
			return false;
		}

		return true;
	}

	void NotifyShutdown() noexcept
	{
		InterlockedExchange(&g_shutdown, 1);
	}

	bool Answer(ULONG index, LONG generation, R3ShieldCore::Verdict verdict) noexcept
	{
		auto* header = g_promptHeader;
		if (!header || index >= header->SlotCount || index >= R3ShieldCore::PromptSlotCount) {
			return false;
		}

		R3ShieldCore::PromptSlot* slot = &R3ShieldCore::PromptSlotBase(header)[index];

		slot->Verdict = static_cast<ULONG>(verdict);
		slot->AnsweredGeneration = generation;
		MemoryBarrier();

		// 只在槽仍是"待处理"时置为"已答复"。
		// 如果 DLL 已经超时释放了槽，CAS 失败，答复直接丢弃。
		if (InterlockedCompareExchange(&slot->State,
				R3ShieldCore::PromptSlotAnswered, R3ShieldCore::PromptSlotPending) != R3ShieldCore::PromptSlotPending) {
			return false;
		}

		SetEvent(g_slotEvents[index].get());
		return true;
	}
}
