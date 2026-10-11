//
// spoof_console.cpp —— R3 ShieldCore「替换 API 结果」交互式控制台
//
// ★★ 这是什么
//    一个**自包含**的交互式控制台：把项目里的「回传数据替换（Spoof）」能力
//    装进自己这个进程，然后**你自己当攻击者**，一条一条命令地试，
//    看每一个 API 的真实返回值 / 真实数据被替换成了什么。
//
// ★★ 进「高级模式」要先过闸门
//    启动后先出**三道 Win32 编程题**（多选题）。**全对**才进高级模式；
//    答错会告诉你哪几题错（不告诉答案），可以重做。
//    题目都是本项目真踩过的坑 —— 答对了说明你确实懂这几层。
//
// ★★ 不注入、不跑引擎（铁律 175 不适用）
//    hook 只装在本进程；只在 HKCU 下建一个临时键，退出时删掉。
//    判据与替换逻辑**与生产同源**：直接 #include 三个 codec 头（铁律 195）。
//
// 用法:
//    ./tools/spoof_console.exe          # 交互
//    ./tools/spoof_console.exe < 脚本   # 也可以喂脚本（自测用）
//
// 编译: bash build_spoof_console.sh
//
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <ktmw32.h>

// ★ 规则引擎（v76）：中文规则语法 + 正则。见下方 `namespace RRule`。
#include <string>
#include <vector>
#include <regex>
#include <mutex>

#include <MinHook.h>

#include "registry_spoof_codec.h"     // v71：注册表值替换（生产同款，不抄）
#include "registry_enum_codec.h"      // v72：注册表枚举隐藏（生产同款，不抄）
#include "clipboard_spoof_codec.h"    // v70：剪贴板替换（生产同款，不抄）
#include <r3shieldcore/rules_codec.h>   // v76：规则引擎（与主程序「高级」页签同源）
#include <r3shieldcore/spoof_apply_codec.h>   // v77：判定 -> 字节怎么落地（两处同源）
#include <r3shieldcore/advanced_quiz.h>       // v78：闸门三题（与「高级」页同源）

#pragma comment(lib, "ktmw32.lib")

namespace RSpoof = R3ShieldCoreRegistrySpoof;
namespace REnum = R3ShieldCoreRegistryEnum;
namespace RClip = R3ShieldCoreClipboardSpoof;
namespace RApply = R3ShieldCoreSpoofApply;

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((LONG)0xC0000022L)
#endif

// ================================================================== 输出
//
// ★ 全部用户可见文本走**宽字面量**（L"..."），再用 WideCharToMultiByte(CP_ACP)
//   落到控制台。理由：MSVC 的执行字符集是 CP936，**窄字面量**里放不下的字符
//   会被 C4566 静默丢掉（铁律 46/133）；而**宽字面量不受 C4566 影响**。
//   这样彻底免疫，还能安全用 ★ 这类符号。
//
static void PutW(const WCHAR* s)
{
	if (!s) return;
	char buf[8192];
	const int n = WideCharToMultiByte(CP_ACP, 0, s, -1, buf, (int)sizeof(buf) - 1, nullptr, nullptr);
	if (n > 0) {
		buf[n - 1] = '\0';
		fputs(buf, stdout);
	}
}

static void Say(const WCHAR* fmt, ...)
{
	WCHAR buf[4096];
	va_list ap;
	va_start(ap, fmt);
	_vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
	va_end(ap);
	PutW(buf);
}

static void Hr() { Say(L"  ------------------------------------------------------------\n"); }
static void Act(const WCHAR* s) { Say(L"   攻击者: %ls\n", s); }
static void Res(const WCHAR* s) { Say(L"   ->     %ls\n", s); }

// 从 stdin 读一行（**按字节读**再按 CP_ACP 转宽 —— 与 PutW 对称，
// 不依赖 setlocale，中英文都稳）。
static bool ReadLineW(WCHAR* out, int cap)
{
	char raw[1024];
	if (!fgets(raw, (int)sizeof(raw), stdin)) return false;

	size_t len = strlen(raw);
	while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r')) raw[--len] = '\0';

	const int n = MultiByteToWideChar(CP_ACP, 0, raw, (int)len, out, cap - 1);
	if (n <= 0) { out[0] = L'\0'; return true; }
	out[n] = L'\0';
	return true;
}

// ================================================================== 原生结构
struct ProbeUnicodeString {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
};

struct ProbeObjectAttributes {
	ULONG               Length;
	HANDLE              RootDirectory;
	ProbeUnicodeString* ObjectName;
	ULONG               Attributes;
	PVOID               SecurityDescriptor;
	PVOID               SecurityQualityOfService;
};

// ================================================================== 原型
typedef LONG(NTAPI* NtOpenKey_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*);
typedef LONG(NTAPI* NtOpenKeyTransacted_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*, HANDLE);
typedef LONG(NTAPI* NtOpenKeyTransactedEx_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*, ULONG, HANDLE);
typedef LONG(NTAPI* NtCreateKeyTransacted_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*, ULONG,
	ProbeUnicodeString*, ULONG, HANDLE, PULONG);
typedef LONG(NTAPI* NtQueryValueKey_t)(HANDLE, const ProbeUnicodeString*, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtEnumerateKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtSetValueKey_t)(HANDLE, const ProbeUnicodeString*, ULONG, ULONG, PVOID, ULONG);
typedef LONG(NTAPI* NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef HANDLE(WINAPI* GetClipboardData_t)(UINT);
typedef BOOL(WINAPI* CloseClipboard_t)();

static NtOpenKey_t             g_tOpenKey = nullptr;
static NtOpenKeyTransacted_t   g_tOpenKeyKtm = nullptr;
static NtOpenKeyTransactedEx_t g_tOpenKeyKtmEx = nullptr;
static NtCreateKeyTransacted_t g_tCreateKeyKtm = nullptr;
static NtQueryValueKey_t       g_tQueryValue = nullptr;
static NtEnumerateKey_t        g_tEnumKey = nullptr;
static NtSetValueKey_t         g_tSetValue = nullptr;
static NtQueryKey_t            g_tQueryKey = nullptr;
static GetClipboardData_t      g_tGetClipboard = nullptr;
static CloseClipboard_t        g_tCloseClipboard = nullptr;

static NtOpenKey_t             g_oOpenKey = nullptr;
static NtOpenKeyTransacted_t   g_oOpenKeyKtm = nullptr;
static NtOpenKeyTransactedEx_t g_oOpenKeyKtmEx = nullptr;
static NtCreateKeyTransacted_t g_oCreateKeyKtm = nullptr;
static NtQueryValueKey_t       g_oQueryValue = nullptr;
static NtEnumerateKey_t        g_oEnumKey = nullptr;
static NtSetValueKey_t         g_oSetValue = nullptr;
static NtQueryKey_t            g_oQueryKey = nullptr;
static GetClipboardData_t      g_oGetClipboard = nullptr;
static CloseClipboard_t        g_oCloseClipboard = nullptr;

// ================================================================== 状态（控制台可改）
static volatile LONG g_protectOn = 0;   // 保护总开关（0 = 引擎没装 / 开关全关）
static volatile LONG g_modeBlock = 1;   // 1 = block（本应拒绝）；0 = log（全部放行）
static volatile LONG g_spoofReg = 1;    // 注册表值替换
static volatile LONG g_spoofRegEnum = 1;// 注册表枚举隐藏
static volatile LONG g_spoofClip = 1;   // 剪贴板替换

static BYTE  g_fillByte = 0;            // 值替换的填充字节（生产固定 0；演示可改）
static WCHAR g_fakeClipText[256] = L""; // 剪贴板替换文本（生产固定空串；演示可改）
static WCHAR g_protectPrefix[128] = L"R3ShieldCoreDemo";  // 保护名单（= 生产 protect_reg=）
static WCHAR g_hideNeedle[128] = L"Secret";               // 枚举隐藏判据

static int g_blocked = 0;
static int g_allowed = 0;
static int g_spoofed = 0;

// 剪贴板替换块的登记表（回收点 = CloseClipboard，铁律 192）
struct TrackedFake { UINT format; HANDLE handle; };
static TrackedFake g_fakes[32];
static volatile LONG g_fakeCount = 0;

static bool ProtectEnabled() { return InterlockedCompareExchange(&g_protectOn, 0, 0) != 0; }
static bool ModeBlock()      { return InterlockedCompareExchange(&g_modeBlock, 0, 0) != 0; }

// ================================================================== 工具
static void MakeUs(ProbeUnicodeString* us, const WCHAR* s)
{
	const size_t n = wcslen(s);
	us->Buffer = const_cast<PWSTR>(s);
	us->Length = static_cast<USHORT>(n * sizeof(WCHAR));
	us->MaximumLength = static_cast<USHORT>(us->Length + sizeof(WCHAR));
}

static void InitObjAttr(ProbeObjectAttributes* oa, HANDLE root, ProbeUnicodeString* name)
{
	ZeroMemory(oa, sizeof(*oa));
	oa->Length = sizeof(*oa);
	oa->RootDirectory = root;
	oa->ObjectName = name;
	oa->Attributes = 0x00000040UL;   // OBJ_CASE_INSENSITIVE
}

static bool ContainsW(const WCHAR* hay, ULONG hayChars, const WCHAR* needle)
{
	if (!hay || !needle) return false;
	const ULONG nlen = static_cast<ULONG>(wcslen(needle));
	if (nlen == 0 || hayChars < nlen) return false;
	for (ULONG i = 0; i + nlen <= hayChars; ++i) {
		ULONG j = 0;
		for (; j < nlen; ++j) {
			WCHAR a = hay[i + j], b = needle[j];
			if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a - L'A' + L'a');
			if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b - L'A' + L'a');
			if (a != b) break;
		}
		if (j == nlen) return true;
	}
	return false;
}

static bool IsWriteAccess(ACCESS_MASK a)
{
	const ACCESS_MASK bits = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK
		| DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE;
	return (a & bits) != 0;
}

static bool PathIsProtected(const ProbeUnicodeString* name)
{
	if (!name || !name->Buffer || name->Length == 0) return false;
	return ContainsW(name->Buffer, name->Length / sizeof(WCHAR), g_protectPrefix);
}

static ULONG QueryKeyPathImpl(HANDLE key, WCHAR* out, ULONG capacity)
{
	if (!g_oQueryKey) return 0;
	BYTE buf[2048] = {};
	ULONG rl = 0;
	if (g_oQueryKey(key, 3 /*KeyNameInformation*/, buf, sizeof(buf), &rl) < 0) return 0;
	const ULONG bytes = REnum::ReadU32(buf, 0);
	const ULONG chars = bytes / sizeof(WCHAR);
	if (chars == 0 || chars >= capacity) return 0;
	memcpy(out, buf + sizeof(ULONG), bytes);
	out[chars] = L'\0';
	return chars;
}

// ================================================================== 规则引擎（v76）
//
// ★★ 这是什么
//    进高级模式之后，你可以**用中文写规则**来编辑 API 的返回值 ——
//    语法刻意做得像易语言（`当 … 时 …`）；匹配模式既可以是字面量，
//    也可以是**正则**（用 /.../ 包起来）。
//
//      当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 "***"
//      当 注册表值 的 键路径 含 "Vault" 时 替换为 全FF
//      当 注册表枚举 的 子键名 含 "Secret" 时 隐藏
//      当 剪贴板 的 格式 等于 文本 时 替换为 "假的"
//      当 注册表值 的 值名 等于 "Password" 时 放行
//
// ★ 求值：**按加入顺序，第一条命中的生效**（first-match wins）。
//   一条都没命中 ⇒ 回落控制台的内置默认行为（fill / hide / fakeclip）——
//   所以「加规则」是**叠加**，不会把你之前调好的默认行为弄丢。
//
// ★ 线程：控制台单线程改规则、detour 在读 ⇒ 一把 mutex 护住。
//
	// ★ v76 之后：规则引擎住在**共享头**
	//   `R3ShieldCore/shared/r3shieldcore/rules_codec.h`
	//   （铁律 195：控制台 / 主程序「高级」页签 / 引擎侧 三处共用同一份，不许抄）。
	//   这里只留一个别名，让下面所有 `RRule::xxx` 的调用一字不改。
	namespace RRule = R3ShieldCoreRuleScript;

// ================================================================== detour：准入
static LONG NTAPI NtOpenKey_Detour(PHANDLE KeyHandle, ACCESS_MASK Access, const ProbeObjectAttributes* Oa)
{
	if (ProtectEnabled() && ModeBlock() && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
		return STATUS_ACCESS_DENIED;
	}
	return g_oOpenKey(KeyHandle, Access, Oa);
}

static LONG NTAPI NtOpenKeyTransacted_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
	const ProbeObjectAttributes* Oa, HANDLE Txn)
{
	if (ProtectEnabled() && ModeBlock() && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
		return STATUS_ACCESS_DENIED;
	}
	return g_oOpenKeyKtm(KeyHandle, Access, Oa, Txn);
}

static LONG NTAPI NtOpenKeyTransactedEx_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
	const ProbeObjectAttributes* Oa, ULONG Opts, HANDLE Txn)
{
	if (ProtectEnabled() && ModeBlock() && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
		return STATUS_ACCESS_DENIED;
	}
	return g_oOpenKeyKtmEx(KeyHandle, Access, Oa, Opts, Txn);
}

static LONG NTAPI NtCreateKeyTransacted_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
	const ProbeObjectAttributes* Oa, ULONG Title, ProbeUnicodeString* Class,
	ULONG CreateOptions, HANDLE Txn, PULONG Disposition)
{
	if (ProtectEnabled() && ModeBlock() && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
		return STATUS_ACCESS_DENIED;
	}
	return g_oCreateKeyKtm(KeyHandle, Access, Oa, Title, Class, CreateOptions, Txn, Disposition);
}

// ================================================================== detour：注册表值替换
static LONG NTAPI NtQueryValueKey_Detour(HANDLE Key, const ProbeUnicodeString* Name, ULONG Cls,
	PVOID Info, ULONG Len, PULONG ResultLen)
{
	const LONG st = g_oQueryValue(Key, Name, Cls, Info, Len, ResultLen);
	if (!ProtectEnabled() || !InterlockedCompareExchange(&g_spoofReg, 0, 0) || st < 0 || !Info || !ResultLen) {
		return st;
	}

	WCHAR path[REnum::kMaxKeyPathChars] = {};
	if (QueryKeyPathImpl(Key, path, static_cast<ULONG>(_countof(path))) == 0) return st;
	if (!ContainsW(path, static_cast<ULONG>(wcslen(path)), g_protectPrefix)) return st;

	// ★ v76：先问规则引擎（按 值名 / 键路径 匹配）。没命中才回落内置的 fill 行为。
	WCHAR valueName[256] = L"";
	if (Name && Name->Buffer && Name->Length > 0) {
		const ULONG chars = Name->Length / sizeof(WCHAR);
		const ULONG n = (chars < (ULONG)_countof(valueName) - 1) ? chars : (ULONG)_countof(valueName) - 1;
		memcpy(valueName, Name->Buffer, n * sizeof(WCHAR));
		valueName[n] = L'\0';
	}

	const RRule::Verdict v = RRule::Eval(RRule::Face::RegValue, path, valueName, nullptr);
	if (v.hit) {
		RRule::NoteHit(v.index, valueName);
		if (v.act == RRule::Act::Block) return STATUS_ACCESS_DENIED;
		if (v.act == RRule::Act::Pass)  return st;   // 规则明确要求放行 ⇒ 一个字节都不动

		RSpoof::DataRegion region = {};
		if (RSpoof::LocateDataRegion(Cls, Info, Len, *ResultLen, region)) {
			// ★ v77：落地逻辑搬到 `spoof_apply_codec.h` —— 与主程序「高级」页签
			//   用**同一份**（铁律 195）。这里只负责"定位"（生产 codec）与计数。
			RApply::ApplyRegValue(v, /*ruleHit=*/true, static_cast<BYTE*>(Info),
				Len, region.offset, region.length, g_fillByte);
			++g_spoofed;
		}
		return st;
	}

	RSpoof::DataRegion region = {};
	if (RSpoof::LocateDataRegion(Cls, Info, Len, *ResultLen, region)) {
		// ★ 生产行为是 `ZeroDataRegion`（填 0）。这里的 `g_fillByte` 是**演示扩展**：
		//   先把定位交给**生产同源**的 codec，再按控制台的填充字节落值 ——
		//   目的是让你**亲眼看到**"长度一个字节都没改、只有数据区被动过"。
		//   （v77 起落地逻辑与主程序「高级」页签共用一份，铁律 195。）
		RApply::ApplyRegValue(RRule::Verdict{}, /*ruleHit=*/false, static_cast<BYTE*>(Info),
			Len, region.offset, region.length, g_fillByte);
		++g_spoofed;
	}
	return st;
}

// ================================================================== detour：注册表枚举隐藏
static LONG NTAPI NtEnumerateKey_Detour(HANDLE Key, ULONG Index, ULONG Cls,
	PVOID Info, ULONG Len, PULONG ResultLen)
{
	if (!ProtectEnabled() || !InterlockedCompareExchange(&g_spoofRegEnum, 0, 0)) {
		return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);
	}

	WCHAR path[REnum::kMaxKeyPathChars] = {};
	if (QueryKeyPathImpl(Key, path, static_cast<ULONG>(_countof(path))) == 0) {
		return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);
	}
	if (!ContainsW(path, static_cast<ULONG>(wcslen(path)), g_protectPrefix)) {
		return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);
	}

	ULONG orig = 0, hidden = 0;
	LONG probe = 0;
	const bool ok = REnum::RemapEnumerationIndexImpl(false,
		[Key](ULONG i, ULONG c, PVOID b, ULONG bl, PULONG rl) {
			return g_oEnumKey(Key, i, c, b, bl, rl);
		},
		[&path](const WCHAR* child) {
			// ★ v76：先问规则引擎（按 子键名 / 键路径 匹配）。
			//   命中「隐藏」= 藏；命中「放行」= 不藏；没命中才回落内置判据。
			const RRule::Verdict v = RRule::Eval(RRule::Face::RegEnum, path, child, nullptr);
			if (v.hit) {
				RRule::NoteHit(v.index, child);
				return v.act == RRule::Act::Hide;
			}
			return ContainsW(child, static_cast<ULONG>(wcslen(child)), g_hideNeedle);
		},
		Index, path, static_cast<ULONG>(wcslen(path)), orig, hidden, probe);

	const REnum::RemapResult r = REnum::ClassifyRemap(ok, hidden, orig, Index,
		ok && REnum::IsNoMoreEntries(probe));

	if (r == REnum::RemapResult::Mapped && hidden > 0) {
		++g_spoofed;
		return g_oEnumKey(Key, orig, Cls, Info, Len, ResultLen);
	}
	if (r == REnum::RemapResult::Exhausted && hidden > 0) {
		++g_spoofed;
		if (ResultLen) *ResultLen = 0;
		return REnum::kStatusNoMoreEntries;
	}
	return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);
}

// ================================================================== detour：写判据
static LONG NTAPI NtSetValueKey_Detour(HANDLE Key, const ProbeUnicodeString* Name, ULONG Title,
	ULONG Type, PVOID Data, ULONG DataSize)
{
	if (ProtectEnabled() && ModeBlock()) {
		WCHAR path[REnum::kMaxKeyPathChars] = {};
		if (QueryKeyPathImpl(Key, path, static_cast<ULONG>(_countof(path))) > 0
			&& ContainsW(path, static_cast<ULONG>(wcslen(path)), g_protectPrefix)) {
			return STATUS_ACCESS_DENIED;
		}
	}
	return g_oSetValue(Key, Name, Title, Type, Data, DataSize);
}

// ================================================================== detour：剪贴板
static void TrackFake(UINT format, HANDLE fake)
{
	const LONG i = InterlockedIncrement(&g_fakeCount) - 1;
	if (i >= 0 && i < (LONG)_countof(g_fakes)) {
		g_fakes[i].format = format;
		g_fakes[i].handle = fake;
	}
}

static void ReleaseAllFakes()
{
	LONG n = InterlockedExchange(&g_fakeCount, 0);
	if (n > (LONG)_countof(g_fakes)) n = (LONG)_countof(g_fakes);
	for (LONG i = 0; i < n; ++i) {
		RClip::FreeFake(g_fakes[i].format, g_fakes[i].handle);
		g_fakes[i].handle = nullptr;
	}
}

// 造替代物。
// ★ 生产路径 = `RClip::BuildFake`（文本变空串 / 位图变全 0）。
// ★ 控制台 `fakeclip <文本>` 与**规则引擎**的 `替换为 "文本"` 是**演示扩展**：
//   只在文本类格式上把内容换成你给的串，其余格式仍走生产 codec ——
//   让你直观看到"API 说成功了，拿到的却是别的东西"。
static HANDLE BuildClipFake(UINT format, HANDLE real, const WCHAR* textOverride = nullptr)
{
	const WCHAR* txt = textOverride ? textOverride : g_fakeClipText;
	if (txt && txt[0] != L'\0'
		&& RClip::ClassifyFormat(format) == RClip::FakeKind::Text) {
		// ★ v77：构造搬到 `spoof_apply_codec.h`（与主程序「高级」页签同一份，
		//   铁律 195）—— 这里不再自己拼 HGLOBAL。
		return RApply::BuildClipText(format, txt);
	}
	return RClip::BuildFake(format, real);
}

static HANDLE WINAPI GetClipboardData_Detour(UINT format)
{
	const HANDLE real = g_oGetClipboard(format);
	if (!ProtectEnabled() || real == nullptr) return real;

	// ★ 剪贴板的语义与注册表**不同**：替换只在"本应拒绝"时生效
	//   （生产里是 RejectOrSpoof）。mode=log 下根本不拒 ⇒ 也不替换。
	if (!ModeBlock()) {
		++g_allowed;
		return real;
	}

	// ★ v76：先问规则引擎（按格式名：文本 / 位图 / 数字）。
	// ★ v77：格式名由**生产 codec** 给（`RClip::FormatLabel`）——
	//   "哪些格式算文本"只有一个真源（ClassifyFormat），别在这里再 switch 一遍。
	WCHAR fmtName[32] = L"";
	const WCHAR* fmtLabel = RClip::FormatLabel(format, fmtName, _countof(fmtName));
	const RRule::Verdict v = RRule::Eval(RRule::Face::Clip, nullptr, nullptr, fmtLabel);
	if (v.hit) {
		RRule::NoteHit(v.index, fmtLabel);
		if (v.act == RRule::Act::Pass) return real;             // 规则要求放行 ⇒ 给真值
		if (v.act == RRule::Act::Block) {                        // 规则要求拒绝
			SetLastError(ERROR_ACCESS_DENIED);
			++g_blocked;
			return nullptr;
		}
		const WCHAR* txt = (v.act == RRule::Act::ReplaceText) ? v.text.c_str() : nullptr;
		const HANDLE fake = BuildClipFake(format, real, txt);
		if (!fake) {                                             // 造不出 ⇒ 回落拒绝（铁律 194）
			SetLastError(ERROR_ACCESS_DENIED);
			++g_blocked;
			return nullptr;
		}
		TrackFake(format, fake);
		++g_spoofed;
		return fake;
	}

	if (!InterlockedCompareExchange(&g_spoofClip, 0, 0)) {
		// 替换关 + 本应拒绝 ⇒ 如实拒绝（调用方拿到 NULL + err=5）
		SetLastError(ERROR_ACCESS_DENIED);
		++g_blocked;
		return nullptr;
	}

	const HANDLE fake = BuildClipFake(format, real);
	if (!fake) {
		// 造不出合法替代物 ⇒ 回落"拒绝"（铁律 194），不能假装成功
		SetLastError(ERROR_ACCESS_DENIED);
		++g_blocked;
		return nullptr;
	}
	TrackFake(format, fake);
	++g_spoofed;
	return fake;
}

static BOOL WINAPI CloseClipboard_Detour()
{
	const BOOL result = g_oCloseClipboard();
	if (result) ReleaseAllFakes();   // 只在原函数成功时回收（铁律 192）
	return result;
}

// ================================================================== 夹具
static const WCHAR* kRel = L"Software\\R3ShieldCoreDemo\\Vault";
static const WCHAR* kRealPassword = L"hunter2";
static const WCHAR* kRealClip = L"R3SC-CONSOLE-CLIP-SECRET";
static WCHAR g_abs[512] = {};
static WCHAR g_softAbs[512] = {};

static bool QueryAbsPathOf(const WCHAR* rel, WCHAR* out, ULONG cap)
{
	HKEY h = nullptr;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, &h) != ERROR_SUCCESS) return false;
	BYTE buf[2048] = {};
	ULONG rl = 0;
	const LONG st = g_oQueryKey(h, 3, buf, sizeof(buf), &rl);
	CloseHandle(h);
	if (st < 0) return false;
	const ULONG bytes = *reinterpret_cast<const ULONG*>(buf);
	const ULONG chars = bytes / sizeof(WCHAR);
	if (chars == 0 || chars >= cap) return false;
	memcpy(out, buf + sizeof(ULONG), bytes);
	out[chars] = L'\0';
	return true;
}

static bool CreateFixture()
{
	RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreDemo");
	HKEY h = nullptr;
	if (RegCreateKeyExW(HKEY_CURRENT_USER, kRel, 0, nullptr, REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS, nullptr, &h, nullptr) != ERROR_SUCCESS) {
		return false;
	}
	RegSetValueExW(h, L"Password", 0, REG_SZ,
		reinterpret_cast<const BYTE*>(kRealPassword),
		static_cast<DWORD>((wcslen(kRealPassword) + 1) * sizeof(WCHAR)));
	static const wchar_t* subs[3] = { L"Public1", L"SecretKey", L"Public2" };
	for (int i = 0; i < 3; ++i) {
		HKEY s = nullptr;
		if (RegCreateKeyExW(h, subs[i], 0, nullptr, REG_OPTION_NON_VOLATILE,
			KEY_ALL_ACCESS, nullptr, &s, nullptr) == ERROR_SUCCESS) {
			RegCloseKey(s);
		}
	}
	RegCloseKey(h);
	return true;
}

// ================================================================== 攻击动作
//
// 每个攻击两种输出：
//   verbose=true  -> 逐条打印（给人看）
//   verbose=false -> 只回填一句 brief（给 `compare` 的紧凑对照用）
struct Outcome
{
	WCHAR brief[192];
	bool  rejected;    // 本应拒绝处被拒
	bool  spoofed;     // 替换生效
	bool  realValue;   // 拿到真值
};

// 前 8 字节的十六进制预览 —— 用来证明"长度一个字节没改，只有数据被动过"。
static void HexPreview(const BYTE* p, DWORD bytes, WCHAR* out, int cap)
{
	int n = 0;
	out[0] = L'\0';
	const DWORD shown = bytes < 8 ? bytes : 8;
	for (DWORD i = 0; i < shown && n < cap - 4; ++i) {
		n += swprintf_s(out + n, static_cast<size_t>(cap - n), L"%02X ", p[i]);
	}
}

// 一段 UTF-16 数据能不能当"可打印字符串"显示。
static bool LooksLikeText(const WCHAR* s, DWORD cb)
{
	if (cb < sizeof(WCHAR)) return false;
	const DWORD chars = cb / sizeof(WCHAR);
	for (DWORD i = 0; i + 1 < chars; ++i) {
		const WCHAR c = s[i];
		if (c < 0x20 || c > 0x7E) return false;
	}
	return s[chars - 1] == L'\0';
}

// ---- 面 1：注册表值（**数据类**替换 —— 成功但数据被换掉）
static Outcome DoAttackReg(bool verbose)
{
	Outcome o = {};
	wcscpy_s(o.brief, L"(未执行)");
	if (verbose) Act(L"RegQueryValueExW(Password)");

	HKEY h = nullptr;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, kRel, 0, KEY_READ, &h) != ERROR_SUCCESS) {
		wcscpy_s(o.brief, L"打开键失败");
		o.rejected = true; ++g_blocked;
		if (verbose) Res(L"打开键就失败了 —— 打不开");
		return o;
	}

	BYTE raw[256] = {};
	DWORD cb = sizeof(raw);
	DWORD type = 0;
	const LSTATUS st = RegQueryValueExW(h, L"Password", nullptr, &type,
		reinterpret_cast<LPBYTE>(raw), &cb);
	RegCloseKey(h);

	if (st != ERROR_SUCCESS) {
		swprintf_s(o.brief, L"读失败 err=%lu", static_cast<unsigned long>(st));
		o.rejected = true; ++g_blocked;
		if (verbose) Say(L"   ->     读失败 err=%lu\n", static_cast<unsigned long>(st));
		return o;
	}

	const WCHAR* asText = reinterpret_cast<const WCHAR*>(raw);
	WCHAR hex[64] = {};
	HexPreview(raw, cb, hex, static_cast<int>(_countof(hex)));

	if (!LooksLikeText(asText, cb)) {
		swprintf_s(o.brief, L"成功 + 数据被换（长度 %lu 不变，前 8 字节 %ls）",
			static_cast<unsigned long>(cb), hex);
		o.spoofed = true; ++g_spoofed;
		if (verbose) {
			Say(L"   ->     返回值 ERROR_SUCCESS，回填长度 = %lu 字节（**一个字节都没改**）\n",
				static_cast<unsigned long>(cb));
			Say(L"   ->     前 8 字节 = %ls\n", hex);
			Res(L"**替换生效** —— API 说成功了，数据却是假的");
		}
		return o;
	}

	swprintf_s(o.brief, L"成功 + 真值 \"%ls\"", asText);
	o.realValue = true; ++g_allowed;
	if (verbose) {
		Say(L"   ->     返回值 ERROR_SUCCESS，回填长度 = %lu 字节\n",
			static_cast<unsigned long>(cb));
		Say(L"   ->     内容 = \"%ls\"\n", asText);
		Res(L"**拿到真值**  ==>  没被替换");
	}
	return o;
}

// ---- 面 2：注册表枚举（**索引重映射** —— 命中判据的项"不存在"）
static Outcome DoAttackRegEnum(bool verbose)
{
	Outcome o = {};
	WCHAR names[6][64] = {};
	int count = 0;
	bool sawHidden = false;

	HKEY h = nullptr;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, kRel, 0, KEY_READ, &h) != ERROR_SUCCESS) {
		wcscpy_s(o.brief, L"打开键失败");
		o.rejected = true; ++g_blocked;
		if (verbose) { Act(L"RegEnumKeyExW"); Res(L"打开键就失败了"); }
		return o;
	}

	if (verbose) Act(L"RegEnumKeyExW 枚举子键");
	for (DWORD i = 0; i < 6; ++i) {
		WCHAR name[256] = {};
		DWORD cch = 256;
		const LSTATUS st = RegEnumKeyExW(h, i, name, &cch, nullptr, nullptr, nullptr, nullptr);
		if (st != ERROR_SUCCESS) {
			if (verbose) Say(L"             第 %lu 项 = 越界（err=%lu）\n",
				static_cast<unsigned long>(i), static_cast<unsigned long>(st));
			break;
		}
		if (count < 6) wcsncpy_s(names[count], name, _TRUNCATE);
		++count;
		if (ContainsW(name, static_cast<ULONG>(wcslen(name)), g_hideNeedle)) sawHidden = true;
		if (verbose) Say(L"             第 %lu 项 = %ls\n", static_cast<unsigned long>(i), name);
	}
	RegCloseKey(h);

	WCHAR joined[320] = {};
	for (int i = 0; i < count && i < 6; ++i) {
		if (i) wcscat_s(joined, L", ");
		wcscat_s(joined, names[i]);
	}

	if (!sawHidden) {
		swprintf_s(o.brief, L"枚举到 [%ls] —— 命中判据的项消失了", joined);
		o.spoofed = true; ++g_spoofed;
	}
	else {
		swprintf_s(o.brief, L"枚举到 [%ls] —— 一个都没少", joined);
		o.realValue = true; ++g_allowed;
	}
	return o;
}

// ---- 面 3：剪贴板（**句柄类**替换 —— 返回的句柄指向我们造的东西）
static Outcome DoAttackClip(bool verbose)
{
	Outcome o = {};
	if (verbose) Act(L"GetClipboardData(CF_UNICODETEXT)");

	// 1) 先放一段**已知真值**（真内容由"别人"放，我们只负责读）
	if (!OpenClipboard(nullptr)) {
		wcscpy_s(o.brief, L"打不开剪贴板");
		if (verbose) Res(L"打不开剪贴板（被别的进程占着？）");
		return o;
	}
	EmptyClipboard();
	const size_t bytes = (wcslen(kRealClip) + 1) * sizeof(WCHAR);
	HGLOBAL real = GlobalAlloc(GMEM_MOVEABLE, bytes);
	if (real) {
		void* p = GlobalLock(real);
		if (p) { memcpy(p, kRealClip, bytes); GlobalUnlock(real); }
		if (!SetClipboardData(CF_UNICODETEXT, real)) GlobalFree(real);
	}
	CloseClipboard();

	// 2) 再读回来（这一步会经过我们的 GetClipboardData detour）
	if (!OpenClipboard(nullptr)) {
		wcscpy_s(o.brief, L"打不开剪贴板");
		if (verbose) Res(L"打不开剪贴板");
		return o;
	}
	const HANDLE got = GetClipboardData(CF_UNICODETEXT);
	if (!got) {
		const DWORD err = GetLastError();
		CloseClipboard();
		swprintf_s(o.brief, L"返回 NULL err=%lu —— 被拒绝", static_cast<unsigned long>(err));
		o.rejected = true; ++g_blocked;
		if (verbose) {
			Say(L"   ->     返回 NULL，err=%lu  ==>  **被拒绝**\n", static_cast<unsigned long>(err));
		}
		return o;
	}
	WCHAR text[512] = {};
	const WCHAR* src = static_cast<const WCHAR*>(GlobalLock(got));
	if (src) {
		wcsncpy_s(text, src, _TRUNCATE);
		GlobalUnlock(got);
	}
	CloseClipboard();

	if (wcscmp(text, kRealClip) == 0) {
		swprintf_s(o.brief, L"成功 + 真值 \"%ls\"", text);
		o.realValue = true; ++g_allowed;
		if (verbose) {
			Say(L"   ->     内容 = \"%ls\"\n", text);
			Res(L"**拿到真值**  ==>  没被替换");
		}
		return o;
	}

	swprintf_s(o.brief, L"成功 + 假内容 \"%ls\"（真值本来是 \"%ls\"）", text, kRealClip);
	o.spoofed = true; ++g_spoofed;
	if (verbose) {
		Say(L"   ->     内容 = \"%ls\"\n", text);
		Res(L"**替换生效** —— 成功了，但拿到的不是你放进去的东西");
	}
	return o;
}

// 打印"这次攻击命中了哪条规则"（规则没命中就什么都不打 —— 说明走的是内置默认行为）
static void ReportRuleHit()
{
	const LONG h = InterlockedCompareExchange(&RRule::g_lastHit, 0, 0);
	if (h < 0) return;
	std::wstring d;
	if (RRule::DescribeAt((int)h, d))
		Say(L"   [规则] 命中 #%d：%ls\n", (int)h, d.c_str());
}

static bool AttackByName(const WCHAR* key, bool verbose)
{
	RRule::NoteHit(-1, nullptr);
	if (_wcsicmp(key, L"reg") == 0)          DoAttackReg(verbose);
	else if (_wcsicmp(key, L"regenum") == 0) DoAttackRegEnum(verbose);
	else if (_wcsicmp(key, L"clip") == 0)    DoAttackClip(verbose);
	else return false;
	ReportRuleHit();
	return true;
}

static void AttackAll()
{
	Say(L"\n===== attack all =====\n");
	Say(L"\n[1/3] 注册表值（数据类）\n");
	RRule::NoteHit(-1, nullptr); DoAttackReg(true);     ReportRuleHit();
	Say(L"\n[2/3] 注册表枚举（索引重映射）\n");
	RRule::NoteHit(-1, nullptr); DoAttackRegEnum(true); ReportRuleHit();
	Say(L"\n[3/3] 剪贴板（句柄类）\n");
	RRule::NoteHit(-1, nullptr); DoAttackClip(true);    ReportRuleHit();
	Say(L"\n===== 完 =====\n");
}

// ---- compare：把同一个面在**三种状态**下的结果并排打出来
//
// 这是整个控制台最有信息量的一条命令 —— 它把
//   保护关 / 保护开+替换关 / 保护开+替换开
// 三态的差别钉在一起，一眼看出"替换"到底改了什么、以及为什么
// 剪贴板（本应拒绝才替换）和注册表（读路径上就替换）**语义不同**。
static void Compare(const WCHAR* which)
{
	struct State { const WCHAR* label; bool protect; bool spoof; };
	const State states[3] = {
		{ L"保护关（= 引擎没装）        ", false, false },
		{ L"保护开 + 替换关（只拦不换）  ", true,  false },
		{ L"保护开 + 替换开（本版默认）  ", true,  true  },
	};
	const WCHAR* surf[3] = { L"reg", L"regenum", L"clip" };
	const bool all = (_wcsicmp(which, L"all") == 0);

	// 快照（对照跑完要还原，否则把用户的状态搅了）
	const LONG sp = g_protectOn, sm = g_modeBlock;
	const LONG s1 = g_spoofReg, s2 = g_spoofRegEnum, s3 = g_spoofClip;
	const int c1 = g_blocked, c2 = g_allowed, c3 = g_spoofed;

	Say(L"\n");
	Hr();
	Say(L" 对照：同一个面，三种状态（mode=block）\n");
	Hr();

	for (int s = 0; s < 3; ++s) {
		if (!all && _wcsicmp(which, surf[s]) != 0) continue;
		Say(L"\n [面 = %ls]\n", surf[s]);
		for (int k = 0; k < 3; ++k) {
			InterlockedExchange(&g_protectOn, states[k].protect ? 1 : 0);
			InterlockedExchange(&g_modeBlock, 1);
			const LONG v = states[k].spoof ? 1 : 0;
			InterlockedExchange(&g_spoofReg, v);
			InterlockedExchange(&g_spoofRegEnum, v);
			InterlockedExchange(&g_spoofClip, v);

			Outcome o = {};
			if (s == 0)      o = DoAttackReg(false);
			else if (s == 1) o = DoAttackRegEnum(false);
			else             o = DoAttackClip(false);

			Say(L"   %ls -> %ls\n", states[k].label, o.brief);
		}
	}

	InterlockedExchange(&g_protectOn, sp);
	InterlockedExchange(&g_modeBlock, sm);
	InterlockedExchange(&g_spoofReg, s1);
	InterlockedExchange(&g_spoofRegEnum, s2);
	InterlockedExchange(&g_spoofClip, s3);
	g_blocked = c1; g_allowed = c2; g_spoofed = c3;
	Hr();
	Say(L" 注：注册表的替换发生在**读路径**上（与 mode 无关，只认替换开关）；\n");
	Say(L"     剪贴板的替换发生在**本应拒绝处**（RejectOrSpoof）=> 不拒就不换。\n");
}

// ================================================================== 闸门：三道 Win32 题
//
// ★ v78：题目与解析**不再写在这里** —— 提到 `shared/r3shieldcore/advanced_quiz.h`，
//   因为主程序「高级」页用的是**同一套题**（页内问答）。抄两份必然漂
//   （铁律 127）：漂了之后"控制台过了、界面过不了"，而两边都不会报错。
using QuizQ = R3ShieldCoreQuiz::Question;
static const QuizQ* kQuiz = R3ShieldCoreQuiz::Questions();
static constexpr int kQuizCount = 3;

// 读一个 A/B/C/D。返回 0 表示这一轮不合法 / 用户要退出（*quit = true）。
static WCHAR AskOne(const QuizQ& q, int index, bool* quit)
{
	*quit = false;
	Say(L"\n");
	Hr();
	Say(L" 第 %d 题\n", index + 1);
	Say(L" %ls\n", q.text);
	Say(L"\n");
	const WCHAR* tags[4] = { L" A. ", L" B. ", L" C. ", L" D. " };
	for (int i = 0; i < 4; ++i) {
		Say(L"%ls%ls\n", tags[i], q.opt[i]);
	}
	Say(L"\n 你的答案 (A/B/C/D，q 退出): ");

	WCHAR line[64] = {};
	if (!ReadLineW(line, (int)_countof(line))) { *quit = true; return 0; }

	const WCHAR* p = line;
	while (*p == L' ' || *p == L'\t') ++p;
	if (*p == L'q' || *p == L'Q') { *quit = true; return 0; }
	WCHAR c = *p;
	if (c >= L'a' && c <= L'z') c = static_cast<WCHAR>(c - L'a' + L'A');
	if (c < L'A' || c > L'D') return 0;
	return c;
}

// 全对返回 true。答错可以重做。
static bool RunQuiz()
{
	Say(L"\n");
	Say(L"================================================================\n");
	Say(L" 高级模式闸门 —— 三道 Win32 编程题\n");
	Say(L"================================================================\n");
	Say(L" 全对才开门。答错会告诉你哪几题错（不告诉答案），可以重做。\n");
	Say(L" 题目都是这个项目**真踩过**的坑。\n");

	int round = 0;
	for (;;) {
		++round;
		if (round > 1) {
			Say(L"\n");
			Hr();
			Say(L" 第 %d 轮 —— 重新作答\n", round);
		}

		WCHAR given[3] = {};
		bool quit = false;
		for (int i = 0; i < kQuizCount; ++i) {
			WCHAR c = 0;
			while (c == 0) {
				c = AskOne(kQuiz[i], i, &quit);
				if (quit) { Say(L"\n [退出] 未通过闸门。\n"); return false; }
				if (c == 0) Say(L"   （请输入 A / B / C / D）\n");
			}
			given[i] = c;
		}

		int wrong = 0;
		Say(L"\n");
		Hr();
		for (int i = 0; i < 3; ++i) {
			const bool ok = (given[i] == kQuiz[i].answer);
			Say(L" 第 %d 题: %ls\n", i + 1, ok ? L"对" : L"错");
			if (!ok) ++wrong;
		}

		if (wrong == 0) {
			Say(L"\n");
			Say(L"================================================================\n");
			Say(L" 全对 —— 闸门打开。\n");
			Say(L"================================================================\n");
			Say(L" 顺带把三道题的答案讲清楚：\n");
			for (int i = 0; i < 3; ++i) {
				Say(L"\n [第 %d 题] 正确答案 %lc\n", i + 1, kQuiz[i].answer);
				Say(L"    %ls\n", kQuiz[i].why);
			}
			return true;
		}

		Say(L"\n 错 %d 题 —— 闸门未开，重做一遍。\n", wrong);
	}
}

// ================================================================== 控制台
struct Surface { const WCHAR* key; const WCHAR* desc; };

static void PrintStatus()
{
	Say(L"\n");
	Hr();
	Say(L" 保护总开关 : %ls\n", ProtectEnabled() ? L"开" : L"关");
	Say(L" 拦截行为   : mode=%ls  （%ls）\n",
		ModeBlock() ? L"block" : L"log",
		ModeBlock() ? L"本应拒绝 -> 才替换 / 才拦" : L"全部放行 -> 不拦也不替换（注册表读路径除外）");
	Say(L" 替换开关   : reg=%ls  regenum=%ls  clip=%ls\n",
		InterlockedCompareExchange(&g_spoofReg, 0, 0) ? L"on" : L"off",
		InterlockedCompareExchange(&g_spoofRegEnum, 0, 0) ? L"on" : L"off",
		InterlockedCompareExchange(&g_spoofClip, 0, 0) ? L"on" : L"off");
	Say(L" 保护名单   : \"%ls\"   （值替换 / 准入判据 / 枚举隐藏都用它）\n", g_protectPrefix);
	Say(L" 隐藏判据   : 子键路径含 \"%ls\" 的项被藏起来\n", g_hideNeedle);
	Say(L" 填充字节   : 0x%02X   （生产固定 0x00；这里是演示扩展）\n", g_fillByte);
	if (g_fakeClipText[0]) Say(L" 剪贴板假值 : \"%ls\"   （生产固定空串；这里是演示扩展）\n", g_fakeClipText);
	else                   Say(L" 剪贴板假值 : 空串（= 生产行为）\n");
	Say(L" 规则条数   : %d   （`rule list` 看全部；以「当」开头的一行 = 直接加一条）\n", RRule::Count());
	Say(L" 计数       : 被挡 %d / 替换 %d / 放行 %d\n", g_blocked, g_spoofed, g_allowed);
	Hr();
}

static void PrintHelp()
{
	Say(L"\n");
	Hr();
	Say(L" 命令                         说明\n");
	Hr();
	Say(L" help / ?                     显示本帮助\n");
	Say(L" status                       当前状态（开关 / 名单 / 计数）\n");
	Say(L" list                         列出可替换的「面」\n");
	Say(L" guard on | off               保护**总开关**（off = 引擎没装，全部放行）\n");
	Say(L" on  <面> / off <面>           开 / 关某面的「替换」（面见 list，all = 全部）\n");
	Say(L" mode block | log             切「拦截行为」（替换只在\"本应拒绝\"时才生效）\n");
	Say(L" protect <前缀>               改保护名单（默认 R3ShieldCoreDemo）\n");
	Say(L" hide <子串>                  改枚举隐藏判据（默认 Secret）\n");
	Say(L" fill <0..255>                值替换后的填充字节（默认 0 = 生产行为）\n");
	Say(L" fakeclip <文本>              剪贴板替换后的文本（默认空串 = 生产行为）\n");
	Say(L" rule ...                     **规则引擎**：help / list / add / del / clear / load / save / test\n");
	Say(L"   ★ 也可以**直接输入以「当」开头的一行** = 加一条中文规则（见 rule help）\n");
	Say(L" attack <面> | all            跑一次攻击，打印真实返回值与真实数据\n");
	Say(L" compare <面> | all           **三态并排对照**（保护关 / 只拦不换 / 拦+换）\n");
	Say(L" demo                         跑一遍「保护关 / 保护开 / 事务绕过」三幕\n");
	Say(L" reset                        复位到初始状态\n");
	Say(L" quiz                         重做闸门三道题（不计分）\n");
	Say(L" quit / exit                  退出\n");
	Hr();
	Say(L" 默认状态 = 保护开 + 三个替换全开 + mode=block（一进来 `attack all`\n");
	Say(L" 就是\"替换生效\"的样子）。`guard off` 看真值；`compare all` 看三态差别。\n");
}

static void PrintList()
{
	Say(L"\n");
	Hr();
	Say(L" 面        替换  说明\n");
	Hr();
	Say(L" reg       %-4ls  NtQueryValueKey -> 值读成功，但数据区被换掉（长度一个字节不改）\n",
		InterlockedCompareExchange(&g_spoofReg, 0, 0) ? L"on" : L"off");
	Say(L" regenum   %-4ls  NtEnumerateKey -> 索引重映射，命中隐藏判据的项\"不存在\"\n",
		InterlockedCompareExchange(&g_spoofRegEnum, 0, 0) ? L"on" : L"off");
	Say(L" clip      %-4ls  GetClipboardData -> 句柄换成我们造的替代物（句柄类替换）\n",
		InterlockedCompareExchange(&g_spoofClip, 0, 0) ? L"on" : L"off");
	Hr();
	Say(L" 注：屏幕 / 摄像头两面的中性化函数还没抽成 codec（在生产 screen_guard.cpp 里\n");
	Say(L"     是文件内静态函数），按\"同一份逻辑别抄两份\"的规矩**没往这里搬**。\n");
}

// ---- 规则引擎（v76）
static bool StrIn(const WCHAR* s, std::initializer_list<const WCHAR*> names)
{
	for (const WCHAR* w : names) if (_wcsicmp(s, w) == 0) return true;
	return false;
}

static bool FaceFromName(const WCHAR* s, RRule::Face& out)
{
	if (StrIn(s, { L"注册表值", L"值", L"reg", L"regvalue", L"value" }))   { out = RRule::Face::RegValue; return true; }
	if (StrIn(s, { L"注册表枚举", L"枚举", L"regenum", L"enum", L"key" })) { out = RRule::Face::RegEnum;  return true; }
	if (StrIn(s, { L"剪贴板", L"clip", L"clipboard" }))                    { out = RRule::Face::Clip;     return true; }
	return false;
}

static void PrintRules()
{
	std::vector<std::wstring> all;
	RRule::ListAll(all);
	Say(L"\n");
	Hr();
	if (all.empty()) {
		Say(L" 还没有规则。加一条试试（下面这行**直接敲进去**就行）：\n");
		Say(L"   当 注册表值 的 值名 含 \"Password\" 时 替换为 \"***\"\n");
		Say(L" 或者：rule add 当 剪贴板 的 格式 等于 文本 时 替换为 \"假的\"\n");
	} else {
		Say(L" 共 %d 条（**按顺序，第一条命中的生效**）\n", (int)all.size());
		Hr();
		for (size_t i = 0; i < all.size(); ++i) Say(L"  #%-2d  %ls\n", (int)i, all[i].c_str());
	}
	Hr();
}

static void PrintRuleHelp()
{
	Say(L"\n");
	Hr();
	Say(L" 规则语法（中文，形如易语言）\n");
	Hr();
	Say(L"   当 <面> [的 <字段>] <算子> <模式> 时 <动作>\n");
	Say(L"\n");
	Say(L"   面   : 注册表值 | 注册表枚举 | 剪贴板\n");
	Say(L"   字段 : 值名 | 键路径 | 子键名 | 格式    （可省，用该面的默认字段）\n");
	Say(L"   算子 : 等于 | 含 | 匹配 | 开头 | 结尾   （匹配 = 正则）\n");
	Say(L"   模式 : \"文本\"  或  /正则/             （正则用斜杠包起来）\n");
	Say(L"   动作 : 替换为 \"文本\" | 替换为 全零 | 替换为 全FF | 替换为 空\n");
	Say(L"          | 隐藏（只对枚举面） | 拒绝 | 放行\n");
	Say(L"\n");
	Say(L"   例：\n");
	Say(L"     当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 \"***\"\n");
	Say(L"     当 注册表值 的 键路径 含 \"Vault\" 时 替换为 全FF\n");
	Say(L"     当 注册表枚举 的 子键名 含 \"Secret\" 时 隐藏\n");
	Say(L"     当 剪贴板 的 格式 等于 文本 时 替换为 \"假的\"\n");
	Say(L"     当 注册表值 的 值名 等于 \"Password\" 时 放行\n");
	Say(L"\n");
	Say(L"   命令： rule add <规则> | rule list | rule del <序号> | rule clear\n");
	Say(L"          rule load <文件> | rule save <文件> | rule test <面> <值> | rule help\n");
	Say(L"   ★ 也可以**直接输入以「当」开头的一行**，等价于 rule add。\n");
	Hr();
}

// ---- 三幕演示（复用上面的攻击动作 + KTM 部分）
static void RunDemo()
{
	const LONG savedProtect = g_protectOn;
	const LONG savedMode = g_modeBlock;
	const LONG savedReg = g_spoofReg, savedEnum = g_spoofRegEnum, savedClip = g_spoofClip;

	Say(L"\n");
	Say(L"################################################################\n");
	Say(L"# 第 1 幕  保护**关闭**（= 引擎没装 / 开关全关）\n");
	Say(L"################################################################\n");
	InterlockedExchange(&g_protectOn, 0);
	DoAttackReg(true); DoAttackRegEnum(true); DoAttackClip(true);

	Say(L"\n");
	Say(L"################################################################\n");
	Say(L"# 第 2 幕  保护**打开**（= 引擎装上后：写不进 / 读不到 / 看不见）\n");
	Say(L"################################################################\n");
	InterlockedExchange(&g_protectOn, 1);
	InterlockedExchange(&g_modeBlock, 1);
	InterlockedExchange(&g_spoofReg, 1);
	InterlockedExchange(&g_spoofRegEnum, 1);
	InterlockedExchange(&g_spoofClip, 1);
	DoAttackReg(true); DoAttackRegEnum(true); DoAttackClip(true);

	// 第 2 幕补一条**写**：读不到 / 看不见之外，"写不进"也要看得见。
	Say(L"\n");
	Act(L"RegSetValueExW(Password, \"pwned-by-console\")");
	{
		HKEY h = nullptr;
		if (RegOpenKeyExW(HKEY_CURRENT_USER, kRel, 0, KEY_SET_VALUE, &h) != ERROR_SUCCESS) {
			Res(L"打开键就被拒（准入这一层就挡住了）");
			++g_blocked;
		}
		else {
			const WCHAR* evil = L"pwned-by-console";
			const LSTATUS st = RegSetValueExW(h, L"Password", 0, REG_SZ,
				reinterpret_cast<const BYTE*>(evil),
				static_cast<DWORD>((wcslen(evil) + 1) * sizeof(WCHAR)));
			RegCloseKey(h);
			if (st == ERROR_SUCCESS) { Res(L"写进去了  ==>  篡改成功（不该发生）"); ++g_allowed; }
			else {
				Say(L"   ->     拒绝 err=%lu  ==>  **写不进**\n", static_cast<unsigned long>(st));
				++g_blocked;
			}
		}
	}

	Say(L"\n");
	Say(L"################################################################\n");
	Say(L"# 第 3 幕  攻击者改用「事务注册表（KTM）」绕过\n");
	Say(L"################################################################\n");
	Say(L" 攻击思路：普通路径被挡住了，那就用 NtOpenKeyTransacted /\n");
	Say(L"           NtCreateKeyTransacted —— 事务版**不是**同一个函数，\n");
	Say(L"           普通路径的准入判据**不经过**它。\n\n");

	Say(L"--------------------------------------------------------------\n");
	Say(L" (A) v75 **之前**：没有挂事务 hook（= 修复前的状态）\n");
	Say(L"--------------------------------------------------------------\n");
	MH_DisableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtm));
	MH_DisableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtmEx));
	MH_DisableHook(reinterpret_cast<LPVOID>(g_tCreateKeyKtm));
	{
		HANDLE txn = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
		if (!txn || txn == INVALID_HANDLE_VALUE) {
			Say(L" [skip] 本机 KTM 不可用\n");
		}
		else {
			ProbeUnicodeString us = {}; MakeUs(&us, g_abs);
			ProbeObjectAttributes oa = {}; InitObjAttr(&oa, nullptr, &us);
			HANDLE hKey = nullptr;
			LONG st = g_tOpenKeyKtm(&hKey, KEY_SET_VALUE, &oa, txn);
			Act(L"NtOpenKeyTransacted(KEY_SET_VALUE) 打开受保护键");
			Say(L"   ->     st=0x%08lX\n", static_cast<unsigned long>(st));
			if (st >= 0) { Res(L"**拿到句柄**  ==>  第一道门（准入）被绕过"); ++g_allowed; }
			else { Res(L"被拒"); ++g_blocked; }
			if (hKey) CloseHandle(hKey);

			WCHAR evil[640] = {};
			wcscpy_s(evil, g_abs);
			wcscat_s(evil, L"\\Evil");
			ULONG disp = 0;
			HANDLE hEvil = nullptr;
			ProbeUnicodeString us2 = {}; MakeUs(&us2, evil);
			ProbeObjectAttributes oa2 = {}; InitObjAttr(&oa2, nullptr, &us2);
			const LONG stC = g_tCreateKeyKtm(&hEvil, KEY_ALL_ACCESS, &oa2, 0, nullptr, 0, txn, &disp);
			Act(L"NtCreateKeyTransacted 在受保护键下**凭空建子键** Evil");
			Say(L"   ->     st=0x%08lX\n", static_cast<unsigned long>(stC));
			if (stC >= 0) { Res(L"建成功了，没有任何阻拦  ==>  受保护键下多了攻击者的键"); ++g_allowed; }
			else { Res(L"被拒"); ++g_blocked; }
			if (hEvil) CloseHandle(hEvil);
			CommitTransaction(txn);
			CloseHandle(txn);
		}
	}

	Say(L"\n--------------------------------------------------------------\n");
	Say(L" (B) v75 **之后**：事务 hook 挂上（= 本版的实际状态）\n");
	Say(L"--------------------------------------------------------------\n");
	MH_EnableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtm));
	MH_EnableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtmEx));
	MH_EnableHook(reinterpret_cast<LPVOID>(g_tCreateKeyKtm));
	{
		HANDLE txn = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
		if (!txn || txn == INVALID_HANDLE_VALUE) {
			Say(L" [skip] 本机 KTM 不可用\n");
		}
		else {
			ProbeUnicodeString us = {}; MakeUs(&us, g_abs);
			ProbeObjectAttributes oa = {}; InitObjAttr(&oa, nullptr, &us);
			HANDLE hKey = nullptr;
			LONG st = g_tOpenKeyKtm(&hKey, KEY_SET_VALUE, &oa, txn);
			Act(L"NtOpenKeyTransacted(KEY_SET_VALUE) 打开受保护键");
			Say(L"   ->     st=0x%08lX (%ls)\n", static_cast<unsigned long>(st),
				st == STATUS_ACCESS_DENIED ? L"STATUS_ACCESS_DENIED" : L"见上");
			if (st == STATUS_ACCESS_DENIED) { Res(L"被拒  ==>  堵住了"); ++g_blocked; }
			else { Res(L"没挡住！"); ++g_allowed; }
			if (hKey) CloseHandle(hKey);

			WCHAR evil[640] = {};
			wcscpy_s(evil, g_abs);
			wcscat_s(evil, L"\\Evil");
			ULONG disp = 0;
			HANDLE hEvil = nullptr;
			ProbeUnicodeString us2 = {}; MakeUs(&us2, evil);
			ProbeObjectAttributes oa2 = {}; InitObjAttr(&oa2, nullptr, &us2);
			const LONG stC = g_tCreateKeyKtm(&hEvil, KEY_ALL_ACCESS, &oa2, 0, nullptr, 0, txn, &disp);
			Act(L"NtCreateKeyTransacted 在受保护键下建子键 Evil");
			Say(L"   ->     st=0x%08lX\n", static_cast<unsigned long>(stC));
			if (stC == STATUS_ACCESS_DENIED) { Res(L"被拒  ==>  凭空建键这条路也堵住了"); ++g_blocked; }
			else { Res(L"没挡住！"); ++g_allowed; }
			if (hEvil) CloseHandle(hEvil);

			ProbeUnicodeString us3 = {}; MakeUs(&us3, g_softAbs);
			ProbeObjectAttributes oa3 = {}; InitObjAttr(&oa3, nullptr, &us3);
			HANDLE hSoft = nullptr;
			const LONG stN = g_tOpenKeyKtm(&hSoft, KEY_READ, &oa3, txn);
			Act(L"负对照：打开**不受保护**的键");
			Say(L"   ->     st=0x%08lX\n", static_cast<unsigned long>(stN));
			if (stN >= 0) Res(L"照常放行  ==>  没有误伤");
			else          Res(L"被误伤了！");
			if (hSoft) CloseHandle(hSoft);

			RollbackTransaction(txn);
			CloseHandle(txn);
		}
	}

	InterlockedExchange(&g_protectOn, savedProtect);
	InterlockedExchange(&g_modeBlock, savedMode);
	InterlockedExchange(&g_spoofReg, savedReg);
	InterlockedExchange(&g_spoofRegEnum, savedEnum);
	InterlockedExchange(&g_spoofClip, savedClip);
}

// ================================================================== 命令分发
static void ResetAll()
{
	// ★ 默认**保护开 + 三个替换全开 + mode=block** —— 这样一进来 `attack all`
	//   看到的就是"替换生效"（最直观）。想看真值用 `guard off`，
	//   想看"只拦不换"用 `on/off` 或 `compare`。
	InterlockedExchange(&g_protectOn, 1);
	InterlockedExchange(&g_modeBlock, 1);
	InterlockedExchange(&g_spoofReg, 1);
	InterlockedExchange(&g_spoofRegEnum, 1);
	InterlockedExchange(&g_spoofClip, 1);
	g_fillByte = 0;
	g_fakeClipText[0] = L'\0';
	wcscpy_s(g_protectPrefix, L"R3ShieldCoreDemo");
	wcscpy_s(g_hideNeedle, L"Secret");
	g_blocked = g_allowed = g_spoofed = 0;
	RRule::Clear();                 // ★ 规则也一起清（初始状态本来就没有规则）
	RRule::NoteHit(-1, nullptr);
}

// 取下一个空白分隔的词；返回 nullptr 表示没有了。
static WCHAR* NextToken(WCHAR** p)
{
	WCHAR* s = *p;
	while (*s == L' ' || *s == L'\t') ++s;
	if (*s == L'\0') { *p = s; return nullptr; }
	WCHAR* start = s;
	while (*s && *s != L' ' && *s != L'\t') ++s;
	if (*s) { *s = L'\0'; ++s; }
	*p = s;
	return start;
}

// 取"剩下的全部"（保留内部空格，去掉首尾空白）。
static WCHAR* RestOfLine(WCHAR** p)
{
	WCHAR* s = *p;
	while (*s == L' ' || *s == L'\t') ++s;
	if (*s == L'\0') return nullptr;
	WCHAR* end = s + wcslen(s);
	while (end > s && (end[-1] == L' ' || end[-1] == L'\t')) *--end = L'\0';
	*p = end;
	return s;
}

static bool HandleCommand(WCHAR* line)
{
	// ★ 以「当」开头的行 = 直接加一条规则（"中文编辑"的入口）
	{
		WCHAR* q = line;
		while (*q == L' ' || *q == L'\t') ++q;
		if (*q == L'当') {
			std::wstring err; int idx = -1;
			if (!RRule::Add(q, err, &idx)) {
				Say(L" [规则错] %ls\n", err.c_str());
			} else {
				std::wstring d; RRule::DescribeAt(idx, d);
				Say(L" [加规则 #%d] %ls\n", idx, d.c_str());
			}
			return true;
		}
	}

	WCHAR* p = line;
	WCHAR* cmd = NextToken(&p);
	if (!cmd) return true;

	if (_wcsicmp(cmd, L"help") == 0 || wcscmp(cmd, L"?") == 0) { PrintHelp(); return true; }
	if (_wcsicmp(cmd, L"status") == 0) { PrintStatus(); return true; }
	if (_wcsicmp(cmd, L"list") == 0)   { PrintList(); return true; }

	if (_wcsicmp(cmd, L"quit") == 0 || _wcsicmp(cmd, L"exit") == 0) return false;

	// ---- 规则引擎 ----
	if (_wcsicmp(cmd, L"rule") == 0 || _wcsicmp(cmd, L"rules") == 0 || wcscmp(cmd, L"规则") == 0) {
		WCHAR* sub = NextToken(&p);
		if (!sub || _wcsicmp(sub, L"list") == 0) { PrintRules(); return true; }
		if (_wcsicmp(sub, L"help") == 0) { PrintRuleHelp(); return true; }

		if (_wcsicmp(sub, L"add") == 0) {
			WCHAR* rest = RestOfLine(&p);
			if (!rest) { Say(L" 用法: rule add 当 注册表值 的 值名 含 \"Password\" 时 替换为 \"***\"\n"); return true; }
			std::wstring err; int idx = -1;
			if (!RRule::Add(rest, err, &idx)) { Say(L" [规则错] %ls\n", err.c_str()); return true; }
			std::wstring d; RRule::DescribeAt(idx, d);
			Say(L" [加规则 #%d] %ls\n", idx, d.c_str());
			return true;
		}

		if (_wcsicmp(sub, L"del") == 0 || _wcsicmp(sub, L"remove") == 0 || _wcsicmp(sub, L"rm") == 0) {
			WCHAR* n = NextToken(&p);
			if (!n) { Say(L" 用法: rule del <序号>\n"); return true; }
			const int idx = _wtoi(n);
			if (!RRule::RemoveAt(idx)) { Say(L" 没有第 %d 条（rule list 看序号）\n", idx); return true; }
			Say(L" [删规则 #%d] 它后面的序号都往前挪了一位\n", idx);
			return true;
		}

		if (_wcsicmp(sub, L"clear") == 0) {
			const int n = RRule::Count();
			RRule::Clear();
			Say(L" [清空] 删掉了 %d 条规则\n", n);
			return true;
		}

		if (_wcsicmp(sub, L"load") == 0) {
			WCHAR* path = RestOfLine(&p);
			if (!path) { Say(L" 用法: rule load <文件路径>\n"); return true; }
			int ok = 0, bad = 0; std::wstring firstErr;
			if (!RRule::LoadFile(path, &ok, &bad, firstErr)) { Say(L" [错] 打不开文件: %ls\n", path); return true; }
			Say(L" [加载] 成功 %d 条，失败 %d 条\n", ok, bad);
			if (bad > 0 && !firstErr.empty()) Say(L"         第一条错在：%ls\n", firstErr.c_str());
			return true;
		}

		if (_wcsicmp(sub, L"save") == 0) {
			WCHAR* path = RestOfLine(&p);
			if (!path) { Say(L" 用法: rule save <文件路径>\n"); return true; }
			int n = 0;
			if (!RRule::SaveFile(path, &n)) { Say(L" [错] 写不了文件: %ls\n", path); return true; }
			Say(L" [存盘] %d 条规则已写入 %ls（UTF-8，可直接 rule load 回来）\n", n, path);
			return true;
		}

		if (_wcsicmp(sub, L"test") == 0) {
			WCHAR* face = NextToken(&p);
			WCHAR* val  = RestOfLine(&p);
			if (!face || !val) { Say(L" 用法: rule test <注册表值|注册表枚举|剪贴板> <值>\n"); return true; }
			RRule::Face f;
			if (!FaceFromName(face, f)) { Say(L" 不认识的面: %ls\n", face); return true; }
			// 值同时填进三个字段槽 —— 只是"试匹配"，快速看这条值会被哪条规则吃掉
			const RRule::Verdict v = RRule::Eval(f, val, val, val);
			if (!v.hit) { Say(L" [试] \"%ls\" 没被任何规则命中 => 会走内置默认行为\n", val); return true; }
			std::wstring d; RRule::DescribeAt(v.index, d);
			Say(L" [试] \"%ls\" 命中 #%d：%ls\n", val, v.index, d.c_str());
			return true;
		}

		Say(L" 未知子命令: %ls（试 rule help）\n", sub);
		return true;
	}

	if (_wcsicmp(cmd, L"on") == 0 || _wcsicmp(cmd, L"off") == 0) {
		const LONG v = (_wcsicmp(cmd, L"on") == 0) ? 1 : 0;
		WCHAR* which = NextToken(&p);
		if (!which) { Say(L" 用法: %ls <reg|regenum|clip|all>\n", cmd); return true; }
		if (_wcsicmp(which, L"all") == 0) {
			InterlockedExchange(&g_spoofReg, v);
			InterlockedExchange(&g_spoofRegEnum, v);
			InterlockedExchange(&g_spoofClip, v);
			Say(L" 已把三个面的替换都设为 %ls\n", v ? L"on" : L"off");
		}
		else if (_wcsicmp(which, L"reg") == 0)     { InterlockedExchange(&g_spoofReg, v);     Say(L" reg 替换 = %ls\n", v ? L"on" : L"off"); }
		else if (_wcsicmp(which, L"regenum") == 0) { InterlockedExchange(&g_spoofRegEnum, v); Say(L" regenum 替换 = %ls\n", v ? L"on" : L"off"); }
		else if (_wcsicmp(which, L"clip") == 0)    { InterlockedExchange(&g_spoofClip, v);    Say(L" clip 替换 = %ls\n", v ? L"on" : L"off"); }
		else Say(L" 未知的面: %ls（试 list）\n", which);
		return true;
	}

	if (_wcsicmp(cmd, L"mode") == 0) {
		WCHAR* v = NextToken(&p);
		if (!v) { Say(L" 用法: mode block | log\n"); return true; }
		if (_wcsicmp(v, L"block") == 0)      { InterlockedExchange(&g_modeBlock, 1); Say(L" 拦截行为 = block（本应拒绝 -> 才拦 / 才替换）\n"); }
		else if (_wcsicmp(v, L"log") == 0)   { InterlockedExchange(&g_modeBlock, 0); Say(L" 拦截行为 = log（全部放行 -> 不拦；注册表读路径**仍**替换）\n"); }
		else Say(L" 未知模式: %ls\n", v);
		return true;
	}

	if (_wcsicmp(cmd, L"protect") == 0) {
		WCHAR* v = RestOfLine(&p);
		if (!v) { Say(L" 用法: protect <路径前缀>\n"); return true; }
		wcsncpy_s(g_protectPrefix, v, _TRUNCATE);
		Say(L" 保护名单 = \"%ls\"\n", g_protectPrefix);
		return true;
	}

	if (_wcsicmp(cmd, L"hide") == 0) {
		WCHAR* v = RestOfLine(&p);
		if (!v) { Say(L" 用法: hide <子串>\n"); return true; }
		wcsncpy_s(g_hideNeedle, v, _TRUNCATE);
		Say(L" 隐藏判据 = \"%ls\"\n", g_hideNeedle);
		return true;
	}

	if (_wcsicmp(cmd, L"fill") == 0) {
		WCHAR* v = NextToken(&p);
		if (!v) { Say(L" 用法: fill <0..255>\n"); return true; }
		const int n = _wtoi(v);
		if (n < 0 || n > 255) { Say(L" 超出范围（0..255）\n"); return true; }
		g_fillByte = static_cast<BYTE>(n);
		Say(L" 填充字节 = 0x%02X\n", g_fillByte);
		return true;
	}

	if (_wcsicmp(cmd, L"fakeclip") == 0) {
		WCHAR* v = RestOfLine(&p);
		if (!v) { g_fakeClipText[0] = L'\0'; Say(L" 剪贴板假值 = 空串（= 生产行为）\n"); return true; }
		wcsncpy_s(g_fakeClipText, v, _TRUNCATE);
		Say(L" 剪贴板假值 = \"%ls\"\n", g_fakeClipText);
		return true;
	}

	if (_wcsicmp(cmd, L"guard") == 0) {
		WCHAR* v = NextToken(&p);
		if (!v) { Say(L" 用法: guard on | off\n"); return true; }
		if (_wcsicmp(v, L"on") == 0)       { InterlockedExchange(&g_protectOn, 1); Say(L" 保护总开关 = 开（= 引擎装上）\n"); }
		else if (_wcsicmp(v, L"off") == 0) { InterlockedExchange(&g_protectOn, 0); Say(L" 保护总开关 = 关（= 引擎没装，全部放行）\n"); }
		else Say(L" 用法: guard on | off\n");
		return true;
	}

	if (_wcsicmp(cmd, L"attack") == 0) {
		WCHAR* v = NextToken(&p);
		if (!v) { Say(L" 用法: attack <reg|regenum|clip|all>\n"); return true; }
		if (_wcsicmp(v, L"all") == 0) { AttackAll(); return true; }
		if (!AttackByName(v, true)) Say(L" 未知的面: %ls（试 list）\n", v);
		return true;
	}

	if (_wcsicmp(cmd, L"compare") == 0) {
		WCHAR* v = NextToken(&p);
		if (!v) { Say(L" 用法: compare <reg|regenum|clip|all>\n"); return true; }
		Compare(v);
		return true;
	}

	if (_wcsicmp(cmd, L"demo") == 0)  { RunDemo(); return true; }
	if (_wcsicmp(cmd, L"reset") == 0) { ResetAll(); Say(L" 已复位（开关 + 规则都回到初始状态）。\n"); return true; }
	if (_wcsicmp(cmd, L"quiz") == 0)  { RunQuiz(); return true; }

	Say(L" 未知命令: %ls（试 help）\n", cmd);
	return true;
}

// ================================================================== main
int main()
{
	// ★ 无缓冲：崩溃时也能看到崩在哪一步（铁律 80：printf 不 fflush = 没写；
	//   重定向到文件时 stdio 是**全缓冲**的，一崩就全丢）。
	setvbuf(stdout, nullptr, _IONBF, 0);

	Say(L"\n");
	Say(L"================================================================\n");
	Say(L" R3 ShieldCore —— 「替换 API 结果」交互式控制台\n");
	Say(L"================================================================\n");
	Say(L" 本控制台**不启动引擎、不注入任何进程**。它把替换逻辑装进自己进程，\n");
	Say(L" 然后你自己当攻击者，逐条命令看每个 API 的真实返回值被换成了什么。\n");
	Say(L" 判据与替换逻辑与生产**同源**（直接 include 三个 codec 头）。\n");

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	HMODULE user32 = GetModuleHandleW(L"user32.dll");
	g_tOpenKey = reinterpret_cast<NtOpenKey_t>(GetProcAddress(ntdll, "NtOpenKey"));
	g_tOpenKeyKtm = reinterpret_cast<NtOpenKeyTransacted_t>(GetProcAddress(ntdll, "NtOpenKeyTransacted"));
	g_tOpenKeyKtmEx = reinterpret_cast<NtOpenKeyTransactedEx_t>(GetProcAddress(ntdll, "NtOpenKeyTransactedEx"));
	g_tCreateKeyKtm = reinterpret_cast<NtCreateKeyTransacted_t>(GetProcAddress(ntdll, "NtCreateKeyTransacted"));
	g_tQueryValue = reinterpret_cast<NtQueryValueKey_t>(GetProcAddress(ntdll, "NtQueryValueKey"));
	g_tEnumKey = reinterpret_cast<NtEnumerateKey_t>(GetProcAddress(ntdll, "NtEnumerateKey"));
	g_tSetValue = reinterpret_cast<NtSetValueKey_t>(GetProcAddress(ntdll, "NtSetValueKey"));
	g_tQueryKey = reinterpret_cast<NtQueryKey_t>(GetProcAddress(ntdll, "NtQueryKey"));
	// ★ `NtQueryKey` **不挂钩**（我们只用它反查键路径），所以没有 MH_CreateHook
	//   去回填 `g_oQueryKey` —— 必须**手动**接上，否则它是 nullptr，一调就崩。
	g_oQueryKey = g_tQueryKey;
	g_tGetClipboard = reinterpret_cast<GetClipboardData_t>(GetProcAddress(user32, "GetClipboardData"));
	g_tCloseClipboard = reinterpret_cast<CloseClipboard_t>(GetProcAddress(user32, "CloseClipboard"));

	if (!g_tOpenKey || !g_tOpenKeyKtm || !g_tOpenKeyKtmEx || !g_tCreateKeyKtm
		|| !g_tQueryValue || !g_tEnumKey || !g_tSetValue || !g_tQueryKey
		|| !g_tGetClipboard || !g_tCloseClipboard) {
		Say(L"\n[FATAL] 缺少必要导出（ntdll / user32）\n");
		return 2;
	}

	// ---- 闸门：三道题，全对才继续
	if (!RunQuiz()) return 1;

	// ---- 进高级模式
	Say(L"\n");
	Say(L"================================================================\n");
	Say(L" 已进入**高级模式** —— 替换 API 结果控制台\n");
	Say(L"================================================================\n");

	if (MH_Initialize() != MH_OK) { Say(L"[FATAL] MH_Initialize 失败\n"); return 2; }

	struct HookSpec { LPVOID target; LPVOID detour; LPVOID* orig; const WCHAR* name; };
	const HookSpec specs[] = {
		{ reinterpret_cast<LPVOID>(g_tOpenKey), reinterpret_cast<LPVOID>(NtOpenKey_Detour),
		  reinterpret_cast<LPVOID*>(&g_oOpenKey), L"NtOpenKey" },
		{ reinterpret_cast<LPVOID>(g_tOpenKeyKtm), reinterpret_cast<LPVOID>(NtOpenKeyTransacted_Detour),
		  reinterpret_cast<LPVOID*>(&g_oOpenKeyKtm), L"NtOpenKeyTransacted" },
		{ reinterpret_cast<LPVOID>(g_tOpenKeyKtmEx), reinterpret_cast<LPVOID>(NtOpenKeyTransactedEx_Detour),
		  reinterpret_cast<LPVOID*>(&g_oOpenKeyKtmEx), L"NtOpenKeyTransactedEx" },
		{ reinterpret_cast<LPVOID>(g_tCreateKeyKtm), reinterpret_cast<LPVOID>(NtCreateKeyTransacted_Detour),
		  reinterpret_cast<LPVOID*>(&g_oCreateKeyKtm), L"NtCreateKeyTransacted" },
		{ reinterpret_cast<LPVOID>(g_tQueryValue), reinterpret_cast<LPVOID>(NtQueryValueKey_Detour),
		  reinterpret_cast<LPVOID*>(&g_oQueryValue), L"NtQueryValueKey" },
		{ reinterpret_cast<LPVOID>(g_tEnumKey), reinterpret_cast<LPVOID>(NtEnumerateKey_Detour),
		  reinterpret_cast<LPVOID*>(&g_oEnumKey), L"NtEnumerateKey" },
		{ reinterpret_cast<LPVOID>(g_tSetValue), reinterpret_cast<LPVOID>(NtSetValueKey_Detour),
		  reinterpret_cast<LPVOID*>(&g_oSetValue), L"NtSetValueKey" },
		{ reinterpret_cast<LPVOID>(g_tGetClipboard), reinterpret_cast<LPVOID>(GetClipboardData_Detour),
		  reinterpret_cast<LPVOID*>(&g_oGetClipboard), L"GetClipboardData" },
		{ reinterpret_cast<LPVOID>(g_tCloseClipboard), reinterpret_cast<LPVOID>(CloseClipboard_Detour),
		  reinterpret_cast<LPVOID*>(&g_oCloseClipboard), L"CloseClipboard" },
	};
	const int specCount = static_cast<int>(sizeof(specs) / sizeof(specs[0]));

	int installed = 0;
	for (int i = 0; i < specCount; ++i) {
		if (MH_CreateHook(specs[i].target, specs[i].detour, specs[i].orig) == MH_OK
			&& MH_EnableHook(specs[i].target) == MH_OK) {
			++installed;
		}
		else {
			Say(L" [warn] 挂钩失败: %ls\n", specs[i].name);
		}
	}
	Say(L" [就绪] %d/%d 个 hook 装好\n", installed, specCount);

	if (!CreateFixture()) { Say(L"[FATAL] 建夹具失败\n"); return 2; }
	if (!QueryAbsPathOf(kRel, g_abs, 512) || !QueryAbsPathOf(L"Software", g_softAbs, 512)) {
		Say(L"[FATAL] 取绝对路径失败\n");
		return 2;
	}
	Say(L" [就绪] 受保护键 = HKCU\\%ls\n", kRel);
	Say(L"        绝对路径 = %ls\n", g_abs);
	Say(L" [就绪] 真值: Password=\"%ls\" ；子键 Public1 / SecretKey / Public2\n", kRealPassword);
	Say(L"        剪贴板真值: \"%ls\"\n", kRealClip);

	ResetAll();
	Say(L"\n 输入 help 看命令。一进来就是「保护开 + 替换全开」—— 直接 `attack all`\n");
	Say(L" 看替换生效的样子；`guard off` 看真值；`compare all` 看三态并排对照；\n");
	Say(L" `demo` 跑完整三幕（含事务 KTM 绕过）。\n");

	for (;;) {
		Say(L"\nR3SC> ");
		fflush(stdout);
		WCHAR line[1024] = {};
		if (!ReadLineW(line, (int)_countof(line))) { Say(L"\n[EOF] 退出。\n"); break; }
		if (!HandleCommand(line)) break;
	}

	for (int i = 0; i < specCount; ++i) MH_DisableHook(specs[i].target);
	MH_Uninitialize();
	InterlockedExchange(&g_protectOn, 0);
	ReleaseAllFakes();
	RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreDemo");
	Say(L" [清理] 临时键已删除。\n\n");
	return 0;
}
