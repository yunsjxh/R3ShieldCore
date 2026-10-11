#pragma once
//
// registry_spoof_codec.h —— 注册表「值替换」的**数据区定位与清零**。
//
// 职责单一：给定 `NtQueryValueKey` 的 `KeyValueInformationClass` 与 out 缓冲区，
// 算出**数据区在哪、有多长**，然后把它清零；以及判断"这次能不能替换"。
//
// ★★ 为什么单独成一个**头文件**（与 `clipboard_spoof_codec.h` 同一理由，
//   铁律 195）：这份逻辑要**同时**被
//     ① 生产：`registry_guard.cpp` 的 `NtQueryValueKey_Hook`；
//     ② 验证：`tools/spoof_reg_probe.cpp`（自挂自测探针）
//   使用。抄两份 ⇒ 必漂（铁律 127：同一份清单拷贝多份必然漂移，且漂了之后
//   探针照样全绿、生产照样出错）。全部 `inline` ⇒ 探针直接 `#include`。
//
// ★★ 核心设计：**长度字段一个都不改，只把数据字节清零**。
//
//   `NtQueryValueKey` 的 out 缓冲区是 `KEY_VALUE_*_INFORMATION` 的**变长结构**，
//   数据区的位置由调用方给的 `KeyValueInformationClass` 决定：
//
//     class 0  KeyValueBasicInformation        —— **没有数据区**（只有 Type + Name）
//     class 1  KeyValueFullInformation         —— 头 20 字节，数据在 `DataOffset` 处
//     class 2  KeyValuePartialInformation      —— 头 12 字节，数据紧跟其后
//     class 3  KeyValueFullInformationAlign64  —— **与 class 1 逐字节相同**（实测）
//     class 4  KeyValuePartialInformationAlign64 —— ⚠️ 头 **8** 字节，**没有 TitleIndex**！
//                 （不是"同 class 2" —— 这个假设实测证伪，见下）
//
//   只要**改长度**，就有多个长度字段要同步改（Partial 的 `DataLength`、
//   Full 的 `DataLength` + `DataOffset`、外加 `*ResultLength`），改错一个
//   ⇒ 调用方**读越界或按错偏移解析** ⇒ 宿主崩溃。
//   "长度不动、只清零"⇒ **一个字段都不用改**，长度与数据区天然自洽，
//   结构上不可能出现"声明长度 ≠ 实际长度"。
//   ★ 这与 v70 剪贴板的"同格式、同尺寸、内容清零"是**同一条规则**。
//
// ★ 清零后的值对每种类型都合法：
//     REG_SZ / REG_EXPAND_SZ → 空串（首个 WCHAR 为 0）
//     REG_DWORD / REG_QWORD  → 0
//     REG_BINARY             → 全 0 字节
//     REG_MULTI_SZ           → 空列表（全 0 = 无字符串）
//
// ⚠️ 这里**不做**任何判定（不读 Policy、不打日志）—— 那是 guard 的事。
//   本文件是纯函数：进什么、出什么，没有全局状态。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <string.h>

namespace R3ShieldCoreRegistrySpoof
{
	// ------------------------------------------------------------------
	// 结构布局（**实测**，不靠记忆 —— 勘察输出见 spoof_reg_probe 的
	// 「class 0~4 原始字节」一节 / 本仓库 docs/注册表值替换-机制探针-*.txt）
	// ------------------------------------------------------------------
	//
	//   class 2  KEY_VALUE_PARTIAL_INFORMATION             头 **12** 字节
	//     +0  ULONG TitleIndex
	//     +4  ULONG Type
	//     +8  ULONG DataLength        ← 数据长度
	//     +12 UCHAR Data[]            ← 数据（紧跟头）
	//
	//   class 4  KEY_VALUE_PARTIAL_INFORMATION_ALIGN64     头 **8** 字节
	//     +0  ULONG Type              ← ⚠️ **没有 TitleIndex**（Align64 变体去掉了它）
	//     +4  ULONG DataLength        ← 数据长度（在 +4，不是 +8）
	//     +8  UCHAR Data[]
	//     ★ 实测：REG_SZ "Secret123"（数据 20 字节）⇒ ResultLength=28 = **8**+20；
	//       同值用 class 2 是 32 = 12+20 —— 差的 4 字节正是被去掉的 TitleIndex。
	//     ★ 踩过的坑：把 class 4 当 12 字节头 ⇒ 数据偏移算成 12、长度从 +8 读
	//       （读到的是**数据本身的前 4 字节**）⇒ 长度离谱 ⇒ 定位失败。
	//       靠"长度字段自洽"校验挡下来了，**否则会零掉错误的位置**。
	//
	//   class 1 / class 3  KEY_VALUE_FULL_INFORMATION(_ALIGN64)  头 **20** 字节
	//     +0  ULONG TitleIndex
	//     +4  ULONG Type
	//     +8  ULONG DataOffset        ← 数据相对结构起点的偏移
	//     +12 ULONG DataLength        ← 数据长度
	//     +16 ULONG NameLength
	//     +20 WCHAR Name[]
	//     ★ 实测：class 3 的字节与 class 1 **逐字节相同**（含 TitleIndex），
	//       `DataOffset` 都按 8 字节对齐（"Text" ⇒ 0x20）。
	//       ⇒ 两者可以共用同一套偏移。
	constexpr ULONG kPartialHeaderBytes = 12;          // class 2
	constexpr ULONG kPartialAlign64HeaderBytes = 8;    // class 4（无 TitleIndex）
	constexpr ULONG kFullHeaderBytes = 20;             // class 1 / 3

	// 从结构头里读字段（用 memcpy 而不是解引用 —— 缓冲区可能没有 ULONG 对齐，
	// 直接 `*(ULONG*)p` 在严格对齐的平台上会挂；本机 x86/x64 不会，但别赌）。
	inline ULONG ReadU32(const void* base, ULONG offset) noexcept
	{
		ULONG value = 0;
		memcpy(&value, static_cast<const BYTE*>(base) + offset, sizeof(value));
		return value;
	}

	// ------------------------------------------------------------------
	// 判据：这个 InformationClass 有没有"数据区"
	// ------------------------------------------------------------------
	//
	// class 0（Basic）只有 TitleIndex / Type / NameLength / Name —— **没有数据区**，
	// 也就是说它**不携带值的秘密**（名字是调用方自己传进来的，类型是元数据）。
	// ⇒ 对它做替换毫无意义，必须回落"放行"。
	//
	// ⚠️ class 5（KeyValueLayerInformation）是 Win8.1+ 的分层键信息，
	//    布局不是上面两种，**一律不认识 ⇒ 不替换**（宁可漏，不可崩）。
	inline bool HasDataRegion(ULONG infoClass) noexcept
	{
		switch (infoClass) {
		case 1:  // KeyValueFullInformation
		case 2:  // KeyValuePartialInformation
		case 3:  // KeyValueFullInformationAlign64
		case 4:  // KeyValuePartialInformationAlign64
			return true;
		default:
			return false;
		}
	}

	inline bool IsFullClass(ULONG infoClass) noexcept
	{
		return infoClass == 1 || infoClass == 3;
	}

	// class 4（PartialAlign64）的头是 8 字节、且**没有 TitleIndex** ——
	// 与 class 2 的 12 字节头**不是**同一套偏移。别合并（实测见上）。
	inline bool IsPartialAlign64Class(ULONG infoClass) noexcept
	{
		return infoClass == 4;
	}

	// ------------------------------------------------------------------
	// 数据区定位
	// ------------------------------------------------------------------
	struct DataRegion
	{
		ULONG offset;   // 从缓冲区起点算起
		ULONG length;   // 字节数
	};

	// 定位数据区。返回 false ⇒ 调用方**必须**放弃替换（回落原样返回）。
	//
	// ⚠️ 四道校验（缺一不可 —— 铁律 186：判据必须**两侧都设界**）：
	//   ① `infoClass` 是已知的 1/2/3/4；
	//   ② `info` 非空；
	//   ③ 结构头完整落在**可用长度**内（Full 要 20 字节、Partial 要 12 字节）；
	//   ④ `dataOffset + dataLength` ≤ 可用长度，且 `dataLength > 0`。
	//
	//   "可用长度"取 `min(bufferLength, resultLength)`：
	//     · `bufferLength` = 调用方给 `NtQueryValueKey` 的 `Length`（缓冲区真实大小）；
	//     · `resultLength` = `*ResultLength`（真实调用**回填**的"写进去了多少"）。
	//   两者都可能单独失真（Length 被调用方虚报 / ResultLength 是上一次的残留），
	//   取小的那个才安全。
	//
	// ⚠️ `dataLength == 0`（例如 REG_NONE、空 REG_BINARY）⇒ **返回 false**：
	//   本来就没有内容可泄露，清零 0 字节是空操作。此时应回落"放行 + 记录"，
	//   而不是谎报"替换发生了"（铁律 97）。
	inline bool LocateDataRegion(ULONG infoClass, const void* info,
		ULONG bufferLength, ULONG resultLength, DataRegion& out) noexcept
	{
		if (!info || !HasDataRegion(infoClass)) {
			return false;
		}

		ULONG available = bufferLength < resultLength ? bufferLength : resultLength;
		if (available == 0) {
			return false;
		}

		const ULONG headerBytes = IsFullClass(infoClass) ? kFullHeaderBytes
			: (IsPartialAlign64Class(infoClass) ? kPartialAlign64HeaderBytes : kPartialHeaderBytes);
		if (available < headerBytes) {
			return false;
		}

		ULONG dataOffset = 0;
		ULONG dataLength = 0;
		if (IsFullClass(infoClass)) {
			// class 1 / 3：TitleIndex(0) Type(4) DataOffset(8) DataLength(12) NameLength(16)
			dataOffset = ReadU32(info, 8);    // DataOffset
			dataLength = ReadU32(info, 12);   // DataLength
		}
		else if (IsPartialAlign64Class(infoClass)) {
			// class 4：**没有 TitleIndex** ⇒ Type(0) DataLength(4)，数据紧跟 8 字节头
			dataOffset = kPartialAlign64HeaderBytes;
			dataLength = ReadU32(info, 4);    // DataLength（注意是 +4）
		}
		else {
			// class 2：TitleIndex(0) Type(4) DataLength(8)，数据紧跟 12 字节头
			dataOffset = kPartialHeaderBytes;
			dataLength = ReadU32(info, 8);    // DataLength
		}

		if (dataLength == 0) {
			return false;
		}
		// ⚠️ 用 64 位算加法再比 —— `dataOffset + dataLength` 在 ULONG 里可能回绕，
		//    回绕之后会**通过** `<= available` 的检查（经典整数溢出漏判）。
		const ULONGLONG end = static_cast<ULONGLONG>(dataOffset) + static_cast<ULONGLONG>(dataLength);
		if (end > static_cast<ULONGLONG>(available)) {
			return false;
		}

		out.offset = dataOffset;
		out.length = dataLength;
		return true;
	}

	// 把数据区清零。返回 true 表示**替换真的发生了**。
	//
	// ⚠️ 用 `__try` 护住：目标页可能只读 / 缓冲区其实比声明的短
	//    （调用方虚报 `Length`）—— 失败返回 false，让调用方回落"原样返回"，
	//    绝不让宿主崩（铁律 97：失败必须可见，不能只有"没生效"）。
	// ⚠️ `__try` 放在**这里**而不是调用点：两个调用方（guard / 探针）
	//    都自动受保护，不会出现"某一个忘了加"。
	inline bool ZeroDataRegion(void* info, ULONG bufferLength, const DataRegion& region) noexcept
	{
		if (!info || region.length == 0) {
			return false;
		}
		if (region.offset > bufferLength
			|| region.length > bufferLength - region.offset) {
			return false;   // 再核一次（防调用方传进来的 region 不是本函数算的）
		}

		__try {
			memset(static_cast<BYTE*>(info) + region.offset, 0, region.length);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
		return true;
	}

	// ------------------------------------------------------------------
	// 类型名（给日志 / 探针输出用，纯诊断）
	// ------------------------------------------------------------------
	inline const char* RegTypeName(ULONG type) noexcept
	{
		switch (type) {
		case 0:  return "REG_NONE";
		case 1:  return "REG_SZ";
		case 2:  return "REG_EXPAND_SZ";
		case 3:  return "REG_BINARY";
		case 4:  return "REG_DWORD";
		case 5:  return "REG_DWORD_BIG_ENDIAN";
		case 6:  return "REG_LINK";
		case 7:  return "REG_MULTI_SZ";
		case 8:  return "REG_RESOURCE_LIST";
		case 9:  return "REG_FULL_RESOURCE_DESCRIPTOR";
		case 10: return "REG_RESOURCE_REQUIREMENTS_LIST";
		case 11: return "REG_QWORD";
		default: return "REG_?";
		}
	}
}
