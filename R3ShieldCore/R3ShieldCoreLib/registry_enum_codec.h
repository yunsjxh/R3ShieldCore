#pragma once
//
// registry_enum_codec.h —— 注册表「枚举隐藏」的**项名解析**与**子路径拼接**。
//
// 职责单一：给定 `NtEnumerateKey` / `NtEnumerateValueKey` 回传的结构，
// 把**项名**取出来、拼成完整路径交给判据；以及判断"这次能不能隐藏"。
//
// ★★ 为什么单独成一个**头文件**（与 `clipboard_spoof_codec.h` /
//   `registry_spoof_codec.h` 同一理由，铁律 195）：这份逻辑要**同时**被
//     ① 生产：`registry_guard.cpp` 的 `NtEnumerateKey_Hook` /
//        `NtEnumerateValueKey_Hook`（索引重映射）；
//     ② 验证：`tools/spoof_reg_enum_probe.cpp`（自挂自测探针）
//   使用。抄两份 ⇒ 必漂（铁律 127：同一份清单拷贝多份必然漂移，且漂了之后
//   探针照样全绿、生产照样出错）。全部 `inline` ⇒ 探针直接 `#include`。
//
// ★★ 核心设计：**索引重映射**，不是"伪造一个项"。
//
//   调用方要"第 N 个可见项"，我们**从 0 开始扫**、跳过被隐藏的，
//   数到第 N 个可见项对应的**原始索引 M**，再用**调用方给的 class / 缓冲区**
//   真调一次原函数取第 M 项。于是：
//     · 返回的每一项都是**真实、合法、结构完整**的项
//       （铁律 194：能造出合法替代物才替换 —— 这里的"替代物"就是
//        列表里的下一项，不需要凭空构造任何字节）；
//     · **一个长度字段都不用改**：`ResultLength` 由原函数按真实项回填。
//
//   ⚠️ 代价：调用方看到的列表**变短了**。这正是"隐藏"的语义，但也意味着
//     按"第几个"索引的程序会看到整体前移 —— 所以它是**独立开关**、默认关。
//
// ⚠️ **不能用调用方给的 InformationClass 去探测名字**：
//   `NtEnumerateValueKey` 的 `KeyValuePartialInformation`（class 2）**没有名字**
//   （只有 TitleIndex / Type / DataLength / Data），而它恰恰是 `RegEnumValue`
//   内部用的那一个 ⇒ 用调用方的 class 探测，会让**最常见的那条路**
//   永远"取不到名字"、永远不隐藏（而且完全不报错）。
//   ⇒ 一律用 **class 0**（`KeyBasicInformation` / `KeyValueBasicInformation`）
//     探测：两个 class 都带 `NameLength + Name`，且头部最短、缓冲区需求最小。
//
// ⚠️ 这里**不做**任何判定（不读 Policy、不打日志）—— 那是 guard 的事。
//   本文件是纯函数：进什么、出什么，没有全局状态。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <string.h>

namespace R3ShieldCoreRegistryEnum
{
	// ------------------------------------------------------------------
	// 探测用的 InformationClass（**固定 0**，与调用方给的那个无关）
	// ------------------------------------------------------------------
	//   NtEnumerateKey       class 0 = KeyBasicInformation
	//   NtEnumerateValueKey  class 0 = KeyValueBasicInformation
	constexpr ULONG kKeyProbeClass = 0;
	constexpr ULONG kValueProbeClass = 0;

	// ------------------------------------------------------------------
	// 结构布局（**实测**，不靠记忆 —— 勘察输出见 spoof_reg_enum_probe 的
	// 「0. 布局勘察」一节 / 本仓库 docs/注册表枚举隐藏-机制探针-*.txt）
	// ------------------------------------------------------------------
	//
	//   KEY_BASIC_INFORMATION            头 **16** 字节
	//     +0  LARGE_INTEGER LastWriteTime   （8 字节，占 +0..+7）
	//     +8  ULONG TitleIndex
	//     +12 ULONG NameLength              ← 名字**字节数**（不含结尾 NUL）
	//     +16 WCHAR Name[]
	//
	//   KEY_VALUE_BASIC_INFORMATION      头 **12** 字节
	//     +0  ULONG TitleIndex
	//     +4  ULONG Type
	//     +8  ULONG NameLength              ← 名字**字节数**
	//     +12 WCHAR Name[]
	//
	//   ⚠️ 两个都是"头 + 名字"，但**头长度不同**（16 vs 12）—— 与
	//      `KEY_VALUE_*_INFORMATION` 的 class 2 / class 4 是同一类坑
	//      （铁律 196：布局只能实测，别假设"值枚举和键枚举一样"）。
	constexpr ULONG kKeyBasicNameLengthOffset = 12;
	constexpr ULONG kKeyBasicNameOffset = 16;
	constexpr ULONG kValueBasicNameLengthOffset = 8;
	constexpr ULONG kValueBasicNameOffset = 12;

	// 探测缓冲区大小。
	//   子键名上限 255 WCHAR ⇒ 16 + 510 = 526 字节，绰绰有余；
	//   值名理论上是长字符串，放不下的那部分由 `LocateBasicName` 判失败
	//   ⇒ 调用方**放弃隐藏**（宁可漏，不可用截断的名字去判）。
	constexpr ULONG kProbeBufferBytes = 4096;

	// 探测缓冲区能装下的最大名字字符数（按**较长**的那个头 16 字节算）。
	constexpr ULONG kMaxProbeNameChars = (kProbeBufferBytes - kKeyBasicNameOffset) / sizeof(WCHAR);

	// 键路径上限。★ **必须与 `R3ShieldCore::MaxKeyPathChars` 一致** ——
	//   本文件刻意不 include 共享头（保持探针零依赖），所以改用
	//   `registry_guard.cpp` 里的 `static_assert` 做**编译期**闸门
	//   （铁律 127：同一份常量别抄两份而不管；抄了就要有闸门盯着）。
	constexpr ULONG kMaxKeyPathChars = 320;

	// 扫描上限：防御性的"两侧设界"（铁律 186）。
	// 正常键不可能有这么多子项；真撞上就回落原样调用（宁可漏藏，不可卡住）。
	constexpr ULONG kMaxEnumScan = 65536;

	// 从结构头里读字段（用 memcpy 而不是解引用 —— 缓冲区不保证 ULONG 对齐；
	// 本机 x86/x64 不会挂，但别赌）。
	inline ULONG ReadU32(const void* base, ULONG offset) noexcept
	{
		ULONG value = 0;
		memcpy(&value, static_cast<const BYTE*>(base) + offset, sizeof(value));
		return value;
	}

	// ------------------------------------------------------------------
	// 项名定位
	// ------------------------------------------------------------------
	struct NameRegion
	{
		ULONG offset;   // 从缓冲区起点算起（字节）
		ULONG length;   // **字节数**（不含结尾 NUL；WCHAR 数 = length / 2）
	};

	// 定位结果 —— **三态**，不是布尔。
	//
	// ★★ 为什么必须是三态（本轮最重要的设计修正）：
	//   值的**"(默认)"项名字为空**（`NameLength == 0`），而 `RegEnumValue`
	//   枚举时它**通常排在索引 0**。若把"取不到名字"一律当成"判不出 ⇒ 放弃隐藏"，
	//   那么**任何有默认值的键**都会让枚举隐藏整体失效 —— 而且完全不报错，
	//   表现为"功能写了但从来不生效"（铁律 93 / 97 那一类）。
	//
	//   正确的分法：
	//     · `Unnamed`       —— 名字长度**就是 0**。它没有名字可藏，
	//                          拿 `键路径\` 去比前缀还会命中"整棵子树"⇒
	//                          **按"可见"处理，继续扫**（不能中止）。
	//     · `Indeterminate` —— 结构自相矛盾 / 名字放不进探测缓冲区 /
	//                          长度不是偶数。**判不出** ⇒ 必须中止（宁可漏）。
	enum class NameProbe
	{
		Parsed,
		Unnamed,
		Indeterminate,
	};

	// 五道校验（缺一不可 —— 铁律 186：判据必须**两侧都设界**）：
	//   ① `info` 非空；② 名字头（`nameOffset` 之前的字段）完整落在可用长度内；
	//   ③ `nameLength` 是**偶数**（WCHAR 对齐）；④ `nameOffset + nameLength` ≤ 可用长度；
	//   ⑤ `nameLength > 0`（否则 `Unnamed`）。
	//
	// "可用长度"取 `min(bufferLength, resultLength)`：两者都可能单独失真
	// （Length 被调用方虚报 / ResultLength 是上一次的残留），取小的才安全。
	inline NameProbe ProbeBasicName(bool valueEnum, const void* info,
		ULONG bufferLength, ULONG resultLength, NameRegion& out) noexcept
	{
		out.offset = 0;
		out.length = 0;

		if (!info) {
			return NameProbe::Indeterminate;
		}

		const ULONG nameLengthOffset = valueEnum ? kValueBasicNameLengthOffset : kKeyBasicNameLengthOffset;
		const ULONG nameOffset = valueEnum ? kValueBasicNameOffset : kKeyBasicNameOffset;

		const ULONG available = bufferLength < resultLength ? bufferLength : resultLength;
		// 名字头必须完整：至少要能读到 NameLength 那个字段的**末尾**。
		if (available < nameLengthOffset + sizeof(ULONG) || available < nameOffset) {
			return NameProbe::Indeterminate;
		}

		const ULONG nameBytes = ReadU32(info, nameLengthOffset);
		if (nameBytes == 0) {
			// 空名：没有名字可藏 ⇒ 按"可见"处理（**不是**判不出）。
			return NameProbe::Unnamed;
		}
		if ((nameBytes & 1u) != 0) {
			return NameProbe::Indeterminate;
		}

		// ⚠️ 用 64 位算加法再比 —— 在 ULONG 里 `nameOffset + nameBytes` 可能回绕，
		//    回绕之后会**通过** `<= available` 的检查（经典整数溢出漏判）。
		const ULONGLONG end = static_cast<ULONGLONG>(nameOffset) + static_cast<ULONGLONG>(nameBytes);
		if (end > static_cast<ULONGLONG>(available)) {
			return NameProbe::Indeterminate;
		}

		out.offset = nameOffset;
		out.length = nameBytes;
		return NameProbe::Parsed;
	}

	// 兼容旧口径的薄包装：只有"确实解析出名字"才算成功。
	// ⚠️ 隐藏逻辑**不要**用这个 —— 用 `ProbeBasicName` 拿三态，
	//    否则会踩上面说的"默认值让整条路失效"的坑。
	inline bool LocateBasicName(bool valueEnum, const void* info,
		ULONG bufferLength, ULONG resultLength, NameRegion& out) noexcept
	{
		return ProbeBasicName(valueEnum, info, bufferLength, resultLength, out) == NameProbe::Parsed;
	}

	// ------------------------------------------------------------------
	// 子路径拼接
	// ------------------------------------------------------------------
	//
	// `parent` 是**已经还原好的键路径**（来自 `ResolveKeyPath`，
	// 形如 `\REGISTRY\MACHINE\SOFTWARE\...`），`name` 是刚解析出来的项名。
	// 结果形如 `<parent>\<name>`。
	//
	// ⚠️ 父路径**可能已带结尾反斜杠**（根键 `\REGISTRY\MACHINE\`）⇒ 不能再补一个
	//   （`\\` 会让前缀比较失真）。
	// ⚠️ 放不下时返回 false，**不截断** —— 截断出来的路径可能"碰巧"命中前缀，
	//   那会隐藏一个本不该隐藏的项（假阳性比漏报更贵，铁律 184 同族）。
	inline bool BuildChildPath(const WCHAR* parent, ULONG parentChars,
		const WCHAR* name, ULONG nameChars, WCHAR* out, ULONG capacity) noexcept
	{
		if (!parent || !name || !out || capacity == 0) {
			return false;
		}

		const bool parentEndsWithSlash = parentChars > 0 && parent[parentChars - 1] == L'\\';
		const ULONGLONG separator = parentEndsWithSlash ? 0 : 1;

		// 总字符数含结尾 NUL。
		const ULONGLONG total = static_cast<ULONGLONG>(parentChars) + separator
			+ static_cast<ULONGLONG>(nameChars) + 1;
		if (total > static_cast<ULONGLONG>(capacity)) {
			return false;
		}

		ULONG at = 0;
		for (ULONG i = 0; i < parentChars; ++i) {
			out[at++] = parent[i];
		}
		if (!parentEndsWithSlash) {
			out[at++] = L'\\';
		}
		for (ULONG i = 0; i < nameChars; ++i) {
			out[at++] = name[i];
		}
		out[at] = L'\0';
		return true;
	}

	// ------------------------------------------------------------------
	// 状态码（自己定义，不引 winternl.h —— 那套随 SDK 漂，铁律 196 同源）
	// ------------------------------------------------------------------
	constexpr LONG kStatusNoMoreEntries = static_cast<LONG>(0x8000001AL);  // 索引越界
	constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005L); // 缓冲区不够，*ResultLength 给出所需
	constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023L);

	inline bool IsSuccess(LONG status) noexcept
	{
		return status >= 0;
	}

	inline bool IsNoMoreEntries(LONG status) noexcept
	{
		return status == kStatusNoMoreEntries;
	}

	// 这个状态码是不是"这次调用什么都没写进缓冲区"。
	// ⚠️ 两个都是**负数**（NT_SUCCESS 为假）：`0x80000005` 是 warning，
	//   但它的最高位是 1 ⇒ 按 NTSTATUS 口径算**失败**。所以判据要显式列出来，
	//   不能靠 `status >= 0`。
	inline bool IsNothingWritten(LONG status) noexcept
	{
		return IsNoMoreEntries(status)
			|| status == kStatusBufferOverflow
			|| status == kStatusBufferTooSmall;
	}

	// ------------------------------------------------------------------
	// ★★ 索引重映射算法（**生产与探针共用同一份**，铁律 195 / 127）
	// ------------------------------------------------------------------
	//
	// 为什么把**算法**也放进 codec，而不只是"解析函数"：
	//   v67 的屏幕探针是**抄**了一份 detour 逻辑（当时没别的办法）；
	//   v70/v71 只抽了"纯函数"那一层。而这里最容易漂的恰恰是**控制流**
	//   （"命中就往后挪一格" vs "从 0 数可见项" —— 后者才对，见下）。
	//   把循环也抽出来 ⇒ 探针验的就是生产跑的那条路。
	//
	// 算法：调用方要"第 `callerIndex` 个**可见**项"。**从 0 开始扫**，
	//   跳过命中隐藏判据的项，数到第 `callerIndex` 个可见项时记下它的
	//   **原始索引**。
	//
	// ⚠️ **为什么不能"命中就往后挪一格"**：
	//   列表 [A(可见) B(隐藏) C(可见)]。若"命中就 +1"：
	//     索引 0 → A；索引 1 → 原 1=B 隐藏 ⇒ 挪到 C；索引 2 → 原 2=C **可见**
	//     ⇒ 又返回 C。调用方看到 [A, C, C] —— **重复项**。
	//   从 0 数可见项才不会重复（代价：每次调用 O(n)）。
	//
	// ⚠️ 探测**必须**用独立的缓冲区与 class 0，不能借调用方的：
	//   `KeyValuePartialInformation`(class 2) 没有名字，而它正是
	//   `RegEnumValue` 用的那个 ⇒ 借调用方的 class 会让最常见的那条路
	//   永远取不到名字（而且完全不报错）。
	template <typename CallFn, typename IsHiddenFn>
	inline bool RemapEnumerationIndexImpl(bool valueEnum,
		CallFn&& call, IsHiddenFn&& isHidden, ULONG callerIndex,
		const WCHAR* keyPath, ULONG keyPathChars,
		ULONG& outOriginalIndex, ULONG& outHiddenCount, LONG& outProbeStatus) noexcept
	{
		outOriginalIndex = 0;
		outHiddenCount = 0;
		outProbeStatus = 0;

		if (!keyPath || keyPathChars == 0) {
			return false;
		}
		// ⚠️ 路径被 `ResolveKeyPath` 截断过（超长）⇒ 拼出来的子路径可能"碰巧"
		//    命中前缀 ⇒ 藏掉一个本不该藏的项。宁可漏（返回 false ⇒ 原样调用）。
		if (keyPathChars + 1 >= kMaxKeyPathChars) {
			return false;
		}

		BYTE probe[kProbeBufferBytes] = {};
		WCHAR childPath[kMaxKeyPathChars + kMaxProbeNameChars + 2] = {};

		ULONG visibleSeen = 0;

		for (ULONG original = 0; original < kMaxEnumScan; ++original) {
			ULONG resultLength = 0;
			const LONG status = call(original,
				valueEnum ? kValueProbeClass : kKeyProbeClass,
				probe, static_cast<ULONG>(sizeof(probe)), &resultLength);

			if (IsNoMoreEntries(status)) {
				// 真的扫到底了：没有第 callerIndex 个可见项。
				// `outHiddenCount` 保留已数到的值（调用方据此判断"是越界还是判不出"）。
				outProbeStatus = status;
				return true;
			}
			if (!IsSuccess(status)) {
				// 探测本身失败（缓冲区不够 / 别的错）⇒ **判不出** ⇒ 放弃隐藏。
				outProbeStatus = status;
				return false;
			}

			NameRegion name = {};
			const NameProbe probed = ProbeBasicName(valueEnum, probe,
				static_cast<ULONG>(sizeof(probe)), resultLength, name);

			if (probed == NameProbe::Indeterminate) {
				// 结构自相矛盾 / 名字放不进探测缓冲区 ⇒ **判不出** ⇒ 放弃隐藏。
				// 这条是"宁可漏，不可崩"的落点：绝不拿猜的名字去判。
				outProbeStatus = status;
				return false;
			}

			if (probed == NameProbe::Unnamed) {
				// 名字长度就是 0（值的"(默认)"项）⇒ 没有名字可藏 ⇒
				// **按"可见"处理、继续扫**（不能中止，否则有默认值的键
				// 会让整条路静默失效）。
				if (visibleSeen == callerIndex) {
					outOriginalIndex = original;
					return true;
				}
				visibleSeen++;
				continue;
			}

			const ULONG nameChars = name.length / sizeof(WCHAR);
			if (!BuildChildPath(keyPath, keyPathChars,
					reinterpret_cast<const WCHAR*>(probe + name.offset), nameChars,
					childPath, static_cast<ULONG>(_countof(childPath)))) {
				return false;
			}

			if (isHidden(childPath)) {
				outHiddenCount++;
				continue;
			}

			if (visibleSeen == callerIndex) {
				outOriginalIndex = original;
				return true;
			}
			visibleSeen++;
		}

		// 扫描上限到了 ⇒ 判不出 ⇒ 原样调用（防御性的"两侧设界"，铁律 186）。
		return false;
	}

	// 判定结果（语义与 `registry_guard.cpp` 的 `Remap` 一一对应）。
	enum class RemapResult
	{
		Passthrough,   // 判不出 / 不适合 ⇒ **原样调用**（与开关之前完全一致）
		Mapped,        // 找到目标 ⇒ 用 outOriginalIndex 真调
		Exhausted,     // 可见项不够（调用方索引越界）
	};

	// 把 `RemapEnumerationIndexImpl` 的布尔结果翻译成三态。
	//   ok=false                      ⇒ Passthrough（判不出）
	//   ok=true 且 hidden==0 且没扫到底 ⇒ 其实等价于 Passthrough（什么都没藏）
	//   ok=true 且扫到底              ⇒ Exhausted
	//   ok=true 且找到目标            ⇒ Mapped
	//
	// ★ "什么都没藏" 归到 `Passthrough` 而不是 `Mapped`：那样调用方会走
	//   "原样调用"那条路，**行为与开关关闭时逐字节相同**（可证伪的等价性）。
	inline RemapResult ClassifyRemap(bool ok, ULONG hiddenCount, ULONG originalIndex,
		ULONG callerIndex, bool exhausted) noexcept
	{
		if (!ok) {
			return RemapResult::Passthrough;
		}
		if (hiddenCount == 0) {
			return RemapResult::Passthrough;
		}
		if (exhausted) {
			return RemapResult::Exhausted;
		}
		(void)originalIndex;
		(void)callerIndex;
		return RemapResult::Mapped;
	}
}
