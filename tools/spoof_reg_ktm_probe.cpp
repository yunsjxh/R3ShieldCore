//
// spoof_reg_ktm_probe.cpp —— 实证：事务注册表（KTM）这一面到底"缺什么"。
//
// 背景（v75 生产改动 `registry_guard.cpp` 的立项依据）：
//   `NtXxxTransacted` 与对应的非事务版**签名只差一个 `TransactionHandle`**
//   （Create 版还差位置：`TransactionHandle` 在 `Disposition` **之前**）。
//   值读 / 枚举 / 写三类操作在事务句柄上**复用同一个** `NtQueryValueKey` /
//   `NtEnumerateKey` / `NtSetValueKey`（这些 API 只看句柄，不区分句柄是不是
//   事务的）⇒ v71 的值替换、v72 的枚举隐藏**本来就在事务句柄上生效**。
//   真正缺的只有**"打开 / 创建"这一步的准入判据** —— 原来 `NtOpenKey` 的
//   detour **不经过**事务变体 ⇒ 用 `NtOpenKeyTransacted` 打开受保护键，
//   能绕过"写不进 / 读不到 / 看不见"里的**第一道门**。
//
// 本探针要回答五个问题：
//
//   0. 三个事务导出在本机 ntdll 里**存在吗**？能**挂上**吗？它们与对应的
//      非事务导出是**不同的函数**吗（否则"补挂"会重复计数 / 根本挂不上）？
//      —— 顺带把 syscall 号打出来（x64 下 `mov eax, <ssn>`），这是"是不是
//      同一个内核入口"的直接证据。
//      还顺手钉死一个**踩过的坑**：`NtOpenKey` **不接受预定义伪句柄**
//      （`HKEY_CURRENT_USER` / `HKEY_LOCAL_MACHINE`）作为 `RootDirectory`
//      ⇒ 返回 `STATUS_INVALID_HANDLE`（advapi32 自己消化了伪句柄，
//      所以 `RegOpenKeyExW(HKEY_CURRENT_USER, ...)` 照样能用，**掩盖了这个坑**）。
//
//   A. 基线（负对照）：判据关着时，事务路径能正常打开。
//
//   B. ★★ **缺口成立吗**：把事务 detour **关掉**（＝修复前的状态），
//      `NtOpenKeyTransacted` 打开受保护键**能不能拿到句柄**？
//      并且要证明"非事务那条 detour **没有**被顺带触发"
//      —— 不然缺口就不存在，v75 那三个 hook 就是多余的。
//
//   C. ★★ **修复生效吗**：把事务 detour **打开**（＝v75 之后的状态），
//      同样的调用**是不是被拒**？三个导出都要覆盖。
//      再配**负对照**：打开一个**不受保护**的键，仍然必须放行
//      （否则就是"一律拒绝"，那是 Block 全开而不是准入判据）。
//
//   D. ★★ **事务句柄上复用同一 API 吗**：在事务键句柄上真调
//      `NtQueryValueKey` / `NtEnumerateKey` / `NtSetValueKey`，
//      **是不是走到同一个 detour**？并验证 v71（值清零）与 v72
//      （枚举隐藏）在这条路上真的生效。这是"缺的只是准入"这句话的证据。
//      ★ 顺带实测 `NtQueryKey` 吃不吃**事务键句柄** —— 生产 v72 的
//        `ResolveKeyPath` 依赖它，这里不成立的话 v72 在事务句柄上会**静默降级**。
//
//   E. 事务语义：**读己之写**（事务内写的东西事务内读得到）+
//      **回滚**（Rollback 之后写的东西不见了）。生产注释里那句
//      "读己之写"必须有实测撑着，不能靠记忆。
//
// ★★ 探针**自包含**：自己挂自己的 hook，不注入任何进程、不经过引擎、
//    不读屏幕。只在 HKCU 下建一个临时键、结束时删掉。
//    因此**不受**「自动化脚本不得运行引擎」那条约束（铁律 175）。
//
// ★★ 探针**不抄** v71 / v72 的算法 —— 直接 `#include` 两个 codec 头，
//    与生产 `registry_guard.cpp` 用**同一份**代码（铁律 195 / 127）。
//
// 编译：bash build_spoof_reg_ktm_probe.sh
// 运行：./tools/spoof_reg_ktm_probe.exe
//
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <ktmw32.h>

#include <MinHook.h>

#include "registry_spoof_codec.h"   // v71：值替换（生产同款，不抄）
#include "registry_enum_codec.h"    // v72：枚举隐藏（生产同款，不抄）

#pragma comment(lib, "ktmw32.lib")

namespace RSpoof = R3ShieldCoreRegistrySpoof;
namespace REnum = R3ShieldCoreRegistryEnum;

// ⚠️ `ntstatus.h` 不能 include（与 winnt.h 大量重定义冲突）⇒ 用到的状态码
//    自己定义，与生产 `registry_guard.cpp` 同一个处理（铁律 196 同源）。
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((LONG)0xC0000022L)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((LONG)0xC0000008L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((LONG)0xC0000034L)
#endif

// ------------------------------------------------------------------ 计数 / 输出
static int g_pass = 0, g_fail = 0, g_skip = 0;
static void Ok(const char* s)   { ++g_pass; printf("  [ OK ] %s\n", s); }
static void Bad(const char* s)  { ++g_fail; printf("  [FAIL] %s\n", s); }
static void Skip(const char* s) { ++g_skip; printf("  [skip] %s\n", s); }
static void Obs(const char* s)  { printf("  [obs ] %s\n", s); }
static void Check(const char* s, bool ok) { if (ok) Ok(s); else Bad(s); }

// ------------------------------------------------------------------ 原生结构
//
// ⚠️ **不 include winternl.h**：那套定义随 SDK 漂（本机 SDK 10.0.28000 里
//    连 `NtOpenKey` 都没声明），而且与本项目生产代码（`RG_UNICODE_STRING` /
//    `RG_OBJECT_ATTRIBUTES`）的口径不一致。这里只用到几个字段。
struct ProbeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct ProbeObjectAttributes {
    ULONG                  Length;
    HANDLE                 RootDirectory;
    ProbeUnicodeString*    ObjectName;
    ULONG                  Attributes;
    PVOID                  SecurityDescriptor;
    PVOID                  SecurityQualityOfService;
};

// 编译期闸门：本探针的结构布局必须与生产 `RG_OBJECT_ATTRIBUTES` 一致
// （铁律 127：同一份布局抄了两份，就得有东西盯着它别漂）。
static_assert(sizeof(ProbeObjectAttributes) == (sizeof(void*) == 8 ? 48u : 24u),
    "ProbeObjectAttributes 布局与原生 OBJECT_ATTRIBUTES 不符");
static_assert(sizeof(ProbeUnicodeString) == (sizeof(void*) == 8 ? 16u : 8u),
    "ProbeUnicodeString 布局与原生 UNICODE_STRING 不符");

// ------------------------------------------------------------------ 原型
typedef LONG(NTAPI* NtOpenKey_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*);
typedef LONG(NTAPI* NtOpenKeyTransacted_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*, HANDLE);
typedef LONG(NTAPI* NtOpenKeyTransactedEx_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*, ULONG, HANDLE);
typedef LONG(NTAPI* NtCreateKeyTransacted_t)(PHANDLE, ACCESS_MASK, const ProbeObjectAttributes*, ULONG,
    ProbeUnicodeString*, ULONG, HANDLE, PULONG);
typedef LONG(NTAPI* NtQueryValueKey_t)(HANDLE, const ProbeUnicodeString*, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtEnumerateKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtSetValueKey_t)(HANDLE, const ProbeUnicodeString*, ULONG, ULONG, PVOID, ULONG);
typedef LONG(NTAPI* NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// 被 patch 的入口（调用它 ⇒ 走 detour）与 trampoline（调用它 ⇒ 真值）
static NtOpenKey_t               g_targetNtOpenKey = nullptr;
static NtOpenKeyTransacted_t     g_targetNtOpenKeyTransacted = nullptr;
static NtOpenKeyTransactedEx_t   g_targetNtOpenKeyTransactedEx = nullptr;
static NtCreateKeyTransacted_t   g_targetNtCreateKeyTransacted = nullptr;
static NtQueryValueKey_t         g_targetNtQueryValueKey = nullptr;
static NtEnumerateKey_t          g_targetNtEnumerateKey = nullptr;
static NtSetValueKey_t           g_targetNtSetValueKey = nullptr;

static NtOpenKey_t               g_origNtOpenKey = nullptr;
static NtOpenKeyTransacted_t     g_origNtOpenKeyTransacted = nullptr;
static NtOpenKeyTransactedEx_t   g_origNtOpenKeyTransactedEx = nullptr;
static NtCreateKeyTransacted_t   g_origNtCreateKeyTransacted = nullptr;
static NtQueryValueKey_t         g_origNtQueryValueKey = nullptr;
static NtEnumerateKey_t          g_origNtEnumerateKey = nullptr;
static NtSetValueKey_t           g_origNtSetValueKey = nullptr;
static NtQueryKey_t              g_origNtQueryKey = nullptr;

// ------------------------------------------------------------------ 开关 / 计数
static volatile LONG g_blockOn = 0;     // 1 = 打开"准入判据"（受保护键的写打开被拒）
static volatile LONG g_spoofOn = 0;     // 1 = v71 值替换
static volatile LONG g_enumHideOn = 0;  // 1 = v72 枚举隐藏

static volatile LONG g_openHits = 0;        // 非事务 NtOpenKey detour 进入次数
static volatile LONG g_openKtmHits = 0;     // NtOpenKeyTransacted detour 进入次数
static volatile LONG g_openKtmExHits = 0;   // NtOpenKeyTransactedEx detour 进入次数
static volatile LONG g_createKtmHits = 0;   // NtCreateKeyTransacted detour 进入次数
static volatile LONG g_queryHits = 0;       // NtQueryValueKey detour 进入次数
static volatile LONG g_querySpoofed = 0;    // 值真的被清零的次数
static volatile LONG g_enumHits = 0;        // NtEnumerateKey detour 进入次数
static volatile LONG g_enumHidden = 0;      // 真的藏掉了一项的次数
static volatile LONG g_enumPathFail = 0;    // 枚举 detour 里"取不到父路径"的次数
static volatile LONG g_setHits = 0;         // NtSetValueKey detour 进入次数

// ------------------------------------------------------------------ 绝对路径
//
// ★★ 踩过的坑（本探针第一版就栽在这上面）：
//   `NtOpenKey` / `NtOpenKeyTransacted` **不接受预定义伪句柄**
//   （`HKEY_CURRENT_USER` / `HKEY_LOCAL_MACHINE` / `HKEY_USERS`）作为
//   `RootDirectory` ⇒ 一律返回 `STATUS_INVALID_HANDLE`。
//   advapi32 的 `RegOpenKeyExW(HKEY_CURRENT_USER, ...)` 能跑，是因为
//   **它自己把伪句柄换成了真句柄** —— 这掩盖了上面的坑。
//   ⇒ Nt* 这条路只能用两种形态之一：
//       ① `RootDirectory = 真键句柄` + 相对名；② `RootDirectory = NULL` + 绝对 NT 路径。
//   本探针统一用 ②，因为绝对路径能直接喂给"受保护"判据（不需要先开句柄）。
static WCHAR g_probeAbs[512] = {};   // \REGISTRY\USER\<SID>\Software\R3ShieldCoreProbe\Ktm
static WCHAR g_softAbs[512] = {};    // \REGISTRY\USER\<SID>\Software

// ------------------------------------------------------------------ 小工具
static void MakeUs(ProbeUnicodeString* us, const WCHAR* s)
{
    const size_t n = wcslen(s);
    us->Buffer = const_cast<PWSTR>(s);
    us->Length = static_cast<USHORT>(n * sizeof(WCHAR));
    us->MaximumLength = static_cast<USHORT>(us->Length + sizeof(WCHAR));
}

static void InitObjAttr(ProbeObjectAttributes* oa, HANDLE root, ProbeUnicodeString* name, ULONG attrs)
{
    ZeroMemory(oa, sizeof(*oa));
    oa->Length = sizeof(*oa);
    oa->RootDirectory = root;
    oa->ObjectName = name;
    oa->Attributes = attrs;
}

// 大小写不敏感的宽字符子串查找。
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

// 写意图（与生产 `IsWriteAccess` 同一口径：只看"要不要动它"）。
static bool IsWriteAccess(ACCESS_MASK a)
{
    const ACCESS_MASK bits = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK
        | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE;
    return (a & bits) != 0;
}

// 探针自己的"受保护"判据：绝对路径里含 `R3ShieldCoreProbe`。
// （生产的判据是 `IsProtectedRegistryPathForSpoof`；本探针只关心**机制**，
//  所以用一个自造且可证伪的判据，避免把生产规则表也拖进来。）
static bool PathIsProtected(const ProbeUnicodeString* name)
{
    if (!name || !name->Buffer || name->Length == 0) return false;
    return ContainsW(name->Buffer, name->Length / sizeof(WCHAR), L"R3ShieldCoreProbe");
}

// ------------------------------------------------------------------ 路径查询
// ★ 前置声明：`NtEnumerateKey_Detour` 里要用到（定义在 detour 之后）。
static ULONG QueryKeyPathImpl(HANDLE key, WCHAR* out, ULONG capacity);

// ------------------------------------------------------------------ detour
//
// 与生产 `registry_guard.cpp` 的对应 detour **同构**：
// 先判准入（命中受保护 + 带写意图 ⇒ 拒），否则真调原函数。
// 唯一差别：生产的"要不要拒"由 Policy 决定，这里由一个开关控制
// （为了做"同一条调用路径、只翻一个开关"的对照）。

static LONG NTAPI NtOpenKey_Detour(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    const ProbeObjectAttributes* ObjectAttributes)
{
    InterlockedIncrement(&g_openHits);
    if (g_blockOn && ObjectAttributes && PathIsProtected(ObjectAttributes->ObjectName)
        && IsWriteAccess(DesiredAccess)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_origNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
}

static LONG NTAPI NtOpenKeyTransacted_Detour(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    const ProbeObjectAttributes* ObjectAttributes, HANDLE TransactionHandle)
{
    InterlockedIncrement(&g_openKtmHits);
    if (g_blockOn && ObjectAttributes && PathIsProtected(ObjectAttributes->ObjectName)
        && IsWriteAccess(DesiredAccess)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_origNtOpenKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TransactionHandle);
}

static LONG NTAPI NtOpenKeyTransactedEx_Detour(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    const ProbeObjectAttributes* ObjectAttributes, ULONG OpenOptions, HANDLE TransactionHandle)
{
    InterlockedIncrement(&g_openKtmExHits);
    if (g_blockOn && ObjectAttributes && PathIsProtected(ObjectAttributes->ObjectName)
        && IsWriteAccess(DesiredAccess)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_origNtOpenKeyTransactedEx(KeyHandle, DesiredAccess, ObjectAttributes,
        OpenOptions, TransactionHandle);
}

static LONG NTAPI NtCreateKeyTransacted_Detour(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    const ProbeObjectAttributes* ObjectAttributes, ULONG TitleIndex, ProbeUnicodeString* Class,
    ULONG CreateOptions, HANDLE TransactionHandle, PULONG Disposition)
{
    InterlockedIncrement(&g_createKtmHits);
    if (g_blockOn && ObjectAttributes && PathIsProtected(ObjectAttributes->ObjectName)
        && IsWriteAccess(DesiredAccess)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_origNtCreateKeyTransacted(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex,
        Class, CreateOptions, TransactionHandle, Disposition);
}

// v71：值替换。**与生产同构** —— 先真调（真值、真副作用），成功时再清零数据区。
static LONG NTAPI NtQueryValueKey_Detour(HANDLE KeyHandle, const ProbeUnicodeString* ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    InterlockedIncrement(&g_queryHits);

    const LONG status = g_origNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
        KeyValueInformation, Length, ResultLength);

    if (g_spoofOn == 0 || status < 0 || !KeyValueInformation || !ResultLength) {
        return status;
    }

    RSpoof::DataRegion region = {};
    if (RSpoof::LocateDataRegion(KeyValueInformationClass, KeyValueInformation, Length,
        *ResultLength, region)
        && RSpoof::ZeroDataRegion(KeyValueInformation, Length, region)) {
        InterlockedIncrement(&g_querySpoofed);
    }
    return status;
}

// v72：枚举隐藏。**算法用 codec 里的同一份**（不是抄的控制流，铁律 195）。
static LONG NTAPI NtEnumerateKey_Detour(HANDLE KeyHandle, ULONG Index,
    ULONG KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    InterlockedIncrement(&g_enumHits);

    if (g_enumHideOn == 0) {
        return g_origNtEnumerateKey(KeyHandle, Index, KeyInformationClass,
            KeyInformation, Length, ResultLength);
    }

    // 取父路径：★ 这里刻意用**同一个** `NtQueryKey`（生产 `ResolveKeyPath` 也用它）
    //   —— 它吃不吃**事务键句柄**，正是 D 节要单独实测的东西。
    WCHAR keyPath[REnum::kMaxKeyPathChars] = {};
    const ULONG keyPathChars = QueryKeyPathImpl(KeyHandle, keyPath,
        static_cast<ULONG>(_countof(keyPath)));
    if (keyPathChars == 0) {
        // ★ 如实留痕：生产这条路上会**静默降级成"原样返回"**（铁律 97）。
        InterlockedIncrement(&g_enumPathFail);
        return g_origNtEnumerateKey(KeyHandle, Index, KeyInformationClass,
            KeyInformation, Length, ResultLength);
    }

    ULONG originalIndex = 0;
    ULONG hiddenCount = 0;
    LONG probeStatus = 0;

    const bool ok = REnum::RemapEnumerationIndexImpl(false,
        [KeyHandle](ULONG i, ULONG c, PVOID b, ULONG bl, PULONG rl) {
            return g_origNtEnumerateKey(KeyHandle, i, c, b, bl, rl);
        },
        [](const WCHAR* childPath) {
            return ContainsW(childPath, static_cast<ULONG>(wcslen(childPath)), L"HiddenChild");
        },
        Index, keyPath, keyPathChars, originalIndex, hiddenCount, probeStatus);

    const bool exhausted = ok && REnum::IsNoMoreEntries(probeStatus);
    const REnum::RemapResult remap =
        REnum::ClassifyRemap(ok, hiddenCount, originalIndex, Index, exhausted);

    if (remap == REnum::RemapResult::Mapped && hiddenCount > 0) {
        InterlockedIncrement(&g_enumHidden);
        return g_origNtEnumerateKey(KeyHandle, originalIndex, KeyInformationClass,
            KeyInformation, Length, ResultLength);
    }
    if (remap == REnum::RemapResult::Exhausted && hiddenCount > 0) {
        if (ResultLength) *ResultLength = 0;
        InterlockedIncrement(&g_enumHidden);
        return REnum::kStatusNoMoreEntries;
    }
    return g_origNtEnumerateKey(KeyHandle, Index, KeyInformationClass,
        KeyInformation, Length, ResultLength);
}

static LONG NTAPI NtSetValueKey_Detour(HANDLE KeyHandle, const ProbeUnicodeString* ValueName,
    ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
    InterlockedIncrement(&g_setHits);
    return g_origNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

// ------------------------------------------------------------------ 路径查询实现
static ULONG QueryKeyPathImpl(HANDLE key, WCHAR* out, ULONG capacity)
{
    if (!g_origNtQueryKey) return 0;

    BYTE buf[2048] = {};
    ULONG rl = 0;
    // class 3 = KeyNameInformation（`{ ULONG NameLength; WCHAR Name[1]; }`）
    const LONG st = g_origNtQueryKey(key, 3, buf, sizeof(buf), &rl);
    if (st < 0) return 0;

    const ULONG nameBytes = REnum::ReadU32(buf, 0);
    const ULONG chars = nameBytes / sizeof(WCHAR);
    if (chars == 0 || chars >= capacity) return 0;

    memcpy(out, buf + sizeof(ULONG), nameBytes);
    out[chars] = L'\0';
    return chars;
}

// 用 advapi32 打开一个**真句柄**，再拿它反查绝对 NT 路径。
// （伪句柄 `HKEY_CURRENT_USER` 喂给 `NtQueryKey` 也是 `STATUS_INVALID_HANDLE`，
//   必须让 advapi32 先换成真句柄。）
static bool QueryAbsPathOf(const WCHAR* rel, WCHAR* out, ULONG cap)
{
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, rel, 0, KEY_READ, &h) != ERROR_SUCCESS) return false;

    BYTE buf[2048] = {};
    ULONG rl = 0;
    const LONG st = g_origNtQueryKey(h, 3, buf, sizeof(buf), &rl);
    CloseHandle(h);
    if (st < 0) return false;

    const ULONG nameBytes = *reinterpret_cast<const ULONG*>(buf);
    const ULONG chars = nameBytes / sizeof(WCHAR);
    if (chars == 0 || chars >= cap) return false;
    memcpy(out, buf + sizeof(ULONG), nameBytes);
    out[chars] = L'\0';
    return true;
}

// ------------------------------------------------------------------ 调用包装
// ★ 统一 `RootDirectory = NULL` + **绝对 NT 路径**（见上面"绝对路径"那段的坑）。
static LONG OpenKeyVia(const WCHAR* absPath, ACCESS_MASK access, PHANDLE out)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, absPath);
    ProbeObjectAttributes oa = {};
    InitObjAttr(&oa, nullptr, &us, 0x00000040UL /* OBJ_CASE_INSENSITIVE */);
    return g_targetNtOpenKey(out, access, &oa);
}

static LONG OpenKeyKtmVia(const WCHAR* absPath, ACCESS_MASK access, HANDLE txn, PHANDLE out)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, absPath);
    ProbeObjectAttributes oa = {};
    InitObjAttr(&oa, nullptr, &us, 0x00000040UL);
    return g_targetNtOpenKeyTransacted(out, access, &oa, txn);
}

static LONG OpenKeyKtmExVia(const WCHAR* absPath, ACCESS_MASK access, ULONG opts,
    HANDLE txn, PHANDLE out)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, absPath);
    ProbeObjectAttributes oa = {};
    InitObjAttr(&oa, nullptr, &us, 0x00000040UL);
    return g_targetNtOpenKeyTransactedEx(out, access, &oa, opts, txn);
}

static LONG CreateKeyKtmVia(const WCHAR* absPath, ACCESS_MASK access, HANDLE txn,
    PHANDLE out, PULONG disposition)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, absPath);
    ProbeObjectAttributes oa = {};
    InitObjAttr(&oa, nullptr, &us, 0x00000040UL);
    // CreateOptions 0 = REG_OPTION_NON_VOLATILE
    return g_targetNtCreateKeyTransacted(out, access, &oa, 0, nullptr, 0, txn, disposition);
}

static LONG QueryValueVia(HANDLE key, const WCHAR* valueName, ULONG cls,
    BYTE* buf, ULONG bufLen, ULONG* outLen)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, valueName);
    ULONG rl = 0;
    const LONG st = g_targetNtQueryValueKey(key, &us, cls, buf, bufLen, &rl);
    if (outLen) *outLen = rl;
    return st;
}

static LONG SetValueVia(HANDLE key, const WCHAR* valueName, ULONG type, PVOID data, ULONG dataSize)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, valueName);
    return g_targetNtSetValueKey(key, &us, 0, type, data, dataSize);
}

// 用 class 0（KeyBasicInformation）枚举子键名 —— 也就是"调用方视角"。
static bool EnumChildName(HANDLE key, ULONG index, WCHAR* out, ULONG cap, LONG* outStatus)
{
    BYTE buf[1024] = {};
    ULONG rl = 0;
    const LONG st = g_targetNtEnumerateKey(key, index, 0, buf, sizeof(buf), &rl);
    if (outStatus) *outStatus = st;
    if (st < 0) return false;

    const ULONG nameBytes = REnum::ReadU32(buf, REnum::kKeyBasicNameLengthOffset);
    const ULONG chars = nameBytes / sizeof(WCHAR);
    if (chars == 0 || chars >= cap) return false;
    memcpy(out, buf + REnum::kKeyBasicNameOffset, nameBytes);
    out[chars] = L'\0';
    return true;
}

// ------------------------------------------------------------------ stub 勘察
// 从 ntdll 的 syscall stub 里把 syscall 号抠出来（**只做观测**，不做判据）。
//   x64: 4C 8B D1        mov  r10, rcx
//        B8 XX XX XX XX  mov  eax, <ssn>
//   x86: B8 XX XX XX XX  mov  eax, <ssn>
// 抠不出来返回 -1。
static long ReadSyscallNumber(LPCVOID fn)
{
    const BYTE* b = reinterpret_cast<const BYTE*>(fn);
    if (!b) return -1;
    if (sizeof(void*) == 8) {
        if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8) {
            ULONG v = 0; memcpy(&v, b + 4, 4); return static_cast<long>(v);
        }
        return -1;
    }
    if (b[0] == 0xB8) {
        ULONG v = 0; memcpy(&v, b + 1, 4); return static_cast<long>(v);
    }
    return -1;
}

// ------------------------------------------------------------------ 临时键
static const WCHAR* kProbeRel = L"Software\\R3ShieldCoreProbe\\Ktm";
static const WCHAR* kProbeCreatedRel = L"Software\\R3ShieldCoreProbe\\Ktm\\TxnCreated";

static bool CreateProbeKey()
{
    HKEY h = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kProbeRel, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        return false;
    }

    const wchar_t* text = L"Secret123";
    RegSetValueExW(h, L"Text", 0, REG_SZ, reinterpret_cast<const BYTE*>(text),
        static_cast<DWORD>((wcslen(text) + 1) * sizeof(WCHAR)));

    DWORD dw = 0x11223344;
    RegSetValueExW(h, L"Dword", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dw), sizeof(dw));

    // 三个子键：用来验枚举隐藏（HiddenChild 应被藏掉）。
    static const wchar_t* subs[3] = { L"Vis1", L"HiddenChild", L"Vis2" };
    for (int i = 0; i < 3; ++i) {
        HKEY sub = nullptr;
        if (RegCreateKeyExW(h, subs[i], 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS, nullptr, &sub, nullptr) == ERROR_SUCCESS) {
            RegCloseKey(sub);
        }
    }

    RegCloseKey(h);
    return true;
}

static void DeleteProbeKey()
{
    RegDeleteTreeW(HKEY_CURRENT_USER, kProbeRel);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreProbe");
}

// ================================================================== main
int main()
{
    printf("=== 事务注册表（KTM）机制探针（自挂自测，不经过引擎）===\n");
    printf("（本探针只碰 HKCU 下自己建的临时键，不注入、不跑引擎）\n\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { printf("[FATAL] 取不到 ntdll.dll\n"); return 2; }

    // ---------------------------------------------------------- Part 0
    printf("--- 0. 导出存在性 / 地址 / syscall 号 / 可挂性 ---\n");

    g_targetNtOpenKey = reinterpret_cast<NtOpenKey_t>(GetProcAddress(ntdll, "NtOpenKey"));
    g_targetNtOpenKeyTransacted =
        reinterpret_cast<NtOpenKeyTransacted_t>(GetProcAddress(ntdll, "NtOpenKeyTransacted"));
    g_targetNtOpenKeyTransactedEx =
        reinterpret_cast<NtOpenKeyTransactedEx_t>(GetProcAddress(ntdll, "NtOpenKeyTransactedEx"));
    g_targetNtCreateKeyTransacted =
        reinterpret_cast<NtCreateKeyTransacted_t>(GetProcAddress(ntdll, "NtCreateKeyTransacted"));
    g_targetNtQueryValueKey =
        reinterpret_cast<NtQueryValueKey_t>(GetProcAddress(ntdll, "NtQueryValueKey"));
    g_targetNtEnumerateKey =
        reinterpret_cast<NtEnumerateKey_t>(GetProcAddress(ntdll, "NtEnumerateKey"));
    g_targetNtSetValueKey =
        reinterpret_cast<NtSetValueKey_t>(GetProcAddress(ntdll, "NtSetValueKey"));
    g_origNtQueryKey = reinterpret_cast<NtQueryKey_t>(GetProcAddress(ntdll, "NtQueryKey"));

    Check("ntdll!NtOpenKey 存在", g_targetNtOpenKey != nullptr);
    Check("ntdll!NtOpenKeyTransacted 存在", g_targetNtOpenKeyTransacted != nullptr);
    Check("ntdll!NtOpenKeyTransactedEx 存在", g_targetNtOpenKeyTransactedEx != nullptr);
    Check("ntdll!NtCreateKeyTransacted 存在", g_targetNtCreateKeyTransacted != nullptr);
    Check("ntdll!NtQueryKey 存在（取路径用）", g_origNtQueryKey != nullptr);

    if (!g_targetNtOpenKey || !g_targetNtOpenKeyTransacted || !g_targetNtOpenKeyTransactedEx
        || !g_targetNtCreateKeyTransacted || !g_origNtQueryKey) {
        printf("[FATAL] 缺少必要导出，无法继续。\n");
        return 2;
    }

    {
        const LPCVOID openKeyEx = GetProcAddress(ntdll, "NtOpenKeyEx");
        const LPCVOID createKey = GetProcAddress(ntdll, "NtCreateKey");
        char line[256];

        snprintf(line, sizeof(line), "NtOpenKey              addr=%p ssn=%ld",
            reinterpret_cast<const void*>(g_targetNtOpenKey), ReadSyscallNumber(g_targetNtOpenKey));
        Obs(line);
        snprintf(line, sizeof(line), "NtOpenKeyTransacted    addr=%p ssn=%ld",
            reinterpret_cast<const void*>(g_targetNtOpenKeyTransacted),
            ReadSyscallNumber(g_targetNtOpenKeyTransacted));
        Obs(line);
        snprintf(line, sizeof(line), "NtOpenKeyTransactedEx  addr=%p ssn=%ld",
            reinterpret_cast<const void*>(g_targetNtOpenKeyTransactedEx),
            ReadSyscallNumber(g_targetNtOpenKeyTransactedEx));
        Obs(line);
        snprintf(line, sizeof(line), "NtOpenKeyEx            addr=%p ssn=%ld",
            reinterpret_cast<const void*>(openKeyEx), ReadSyscallNumber(openKeyEx));
        Obs(line);
        snprintf(line, sizeof(line), "NtCreateKey            addr=%p ssn=%ld",
            reinterpret_cast<const void*>(createKey), ReadSyscallNumber(createKey));
        Obs(line);
        snprintf(line, sizeof(line), "NtCreateKeyTransacted  addr=%p ssn=%ld",
            reinterpret_cast<const void*>(g_targetNtCreateKeyTransacted),
            ReadSyscallNumber(g_targetNtCreateKeyTransacted));
        Obs(line);

        // ★ 判据一：事务导出必须是**不同的函数** —— 否则"补挂"没有意义
        //   （挂同一个入口会重复计数，甚至 MinHook 直接挂不上）。
        Check("NtOpenKeyTransacted 与 NtOpenKey 是**不同的函数**",
            reinterpret_cast<const void*>(g_targetNtOpenKeyTransacted)
            != reinterpret_cast<const void*>(g_targetNtOpenKey));
        Check("NtOpenKeyTransactedEx 与 NtOpenKeyEx 是**不同的函数**",
            openKeyEx != nullptr
            && reinterpret_cast<const void*>(g_targetNtOpenKeyTransactedEx) != openKeyEx);
        Check("NtCreateKeyTransacted 与 NtCreateKey 是**不同的函数**",
            createKey != nullptr
            && reinterpret_cast<const void*>(g_targetNtCreateKeyTransacted) != createKey);

        // ★ 判据二：syscall 号必须不同 —— 这是"内核入口不同"的直接证据。
        const long ssnOpen = ReadSyscallNumber(g_targetNtOpenKey);
        const long ssnOpenKtm = ReadSyscallNumber(g_targetNtOpenKeyTransacted);
        if (ssnOpen >= 0 && ssnOpenKtm >= 0) {
            Check("NtOpenKey 与 NtOpenKeyTransacted 的 syscall 号**不同**（内核入口不同）",
                ssnOpen != ssnOpenKtm);
        }
        else {
            Skip("本机 stub 形态不是标准 `mov eax,<ssn>`，syscall 号判据跳过");
        }
    }

    // ---------------------------------------------------------- Part 0.5
    printf("\n--- 0.5 坑位勘察：`RootDirectory` 吃不吃**预定义伪句柄** ---\n");
    {
        // P1：伪句柄作为 RootDirectory
        {
            ProbeUnicodeString us = {};
            MakeUs(&us, L"Software");
            ProbeObjectAttributes oa = {};
            InitObjAttr(&oa, HKEY_CURRENT_USER, &us, 0x00000040UL);
            HANDLE h = nullptr;
            const LONG st = g_targetNtOpenKey(&h, KEY_READ, &oa);
            char line[200];
            snprintf(line, sizeof(line),
                "root=HKEY_CURRENT_USER（伪句柄）-> st=0x%08lX（**不接受**，advapi32 才消化它）",
                static_cast<unsigned long>(st));
            Check(line, st == STATUS_INVALID_HANDLE);
            if (h) CloseHandle(h);
        }
        // P2：NULL + 绝对路径（本探针统一用的形态）
        {
            HKEY hReal = nullptr;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &hReal) != ERROR_SUCCESS) {
                Skip("打不开 HKCU\\Software，绝对路径形态无法验证");
            }
            else {
                BYTE buf[2048] = {};
                ULONG rl = 0;
                const LONG stq = g_origNtQueryKey(hReal, 3, buf, sizeof(buf), &rl);
                const ULONG bytes = *reinterpret_cast<const ULONG*>(buf);
                WCHAR abs[512] = {};
                if (stq >= 0 && bytes / 2 < 500) {
                    memcpy(abs, buf + sizeof(ULONG), bytes);
                    abs[bytes / 2] = L'\0';
                }
                CloseHandle(hReal);

                ProbeUnicodeString us = {};
                MakeUs(&us, abs);
                ProbeObjectAttributes oa = {};
                InitObjAttr(&oa, nullptr, &us, 0x00000040UL);
                HANDLE h = nullptr;
                const LONG st = g_targetNtOpenKey(&h, KEY_READ, &oa);
                char line[256];
                snprintf(line, sizeof(line), "root=NULL + abs=%ls -> st=0x%08lX（**接受**）",
                    abs, static_cast<unsigned long>(st));
                Check(line, st >= 0 && h != nullptr);
                if (h) CloseHandle(h);

                // 顺便把两个绝对路径备好，后面各节都要用
                wcscpy_s(g_softAbs, abs);
                wcscpy_s(g_probeAbs, abs);
                wcscat_s(g_probeAbs, L"\\R3ShieldCoreProbe\\Ktm");
            }
        }
    }

    // ---- 挂 hook ----
    if (MH_Initialize() != MH_OK) { printf("[FATAL] MH_Initialize 失败\n"); return 2; }

    struct HookSpec { LPVOID target; LPVOID detour; LPVOID* orig; const char* name; };
    const HookSpec specs[] = {
        { reinterpret_cast<LPVOID>(g_targetNtOpenKey),
          reinterpret_cast<LPVOID>(NtOpenKey_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtOpenKey), "NtOpenKey" },
        { reinterpret_cast<LPVOID>(g_targetNtOpenKeyTransacted),
          reinterpret_cast<LPVOID>(NtOpenKeyTransacted_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtOpenKeyTransacted), "NtOpenKeyTransacted" },
        { reinterpret_cast<LPVOID>(g_targetNtOpenKeyTransactedEx),
          reinterpret_cast<LPVOID>(NtOpenKeyTransactedEx_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtOpenKeyTransactedEx), "NtOpenKeyTransactedEx" },
        { reinterpret_cast<LPVOID>(g_targetNtCreateKeyTransacted),
          reinterpret_cast<LPVOID>(NtCreateKeyTransacted_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtCreateKeyTransacted), "NtCreateKeyTransacted" },
        { reinterpret_cast<LPVOID>(g_targetNtQueryValueKey),
          reinterpret_cast<LPVOID>(NtQueryValueKey_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtQueryValueKey), "NtQueryValueKey" },
        { reinterpret_cast<LPVOID>(g_targetNtEnumerateKey),
          reinterpret_cast<LPVOID>(NtEnumerateKey_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtEnumerateKey), "NtEnumerateKey" },
        { reinterpret_cast<LPVOID>(g_targetNtSetValueKey),
          reinterpret_cast<LPVOID>(NtSetValueKey_Detour),
          reinterpret_cast<LPVOID*>(&g_origNtSetValueKey), "NtSetValueKey" },
    };
    const int specCount = static_cast<int>(sizeof(specs) / sizeof(specs[0]));

    int installed = 0;
    for (int i = 0; i < specCount; ++i) {
        if (MH_CreateHook(specs[i].target, specs[i].detour, specs[i].orig) != MH_OK) {
            char nm[160];
            snprintf(nm, sizeof(nm), "MH_CreateHook(%s) 成功", specs[i].name);
            Bad(nm);
            continue;
        }
        if (MH_EnableHook(specs[i].target) != MH_OK) {
            char nm[160];
            snprintf(nm, sizeof(nm), "MH_EnableHook(%s) 成功", specs[i].name);
            Bad(nm);
            continue;
        }
        ++installed;
    }
    {
        char nm[128];
        snprintf(nm, sizeof(nm), "%d/%d 个 hook 安装成功", installed, specCount);
        Check(nm, installed == specCount);
    }

    // ---- 造夹具 ----
    if (!CreateProbeKey()) {
        printf("[FATAL] 创建临时测试键失败（HKCU\\%ls）\n", kProbeRel);
        return 2;
    }
    // 清掉可能残留的 TxnCreated（上一次跑出来的），保证"建子键"这条测试非空真。
    RegDeleteTreeW(HKEY_CURRENT_USER, kProbeCreatedRel);
    printf("\n夹具：HKCU\\%ls（值 Text/Dword，子键 Vis1/HiddenChild/Vis2）\n", kProbeRel);
    printf("      绝对路径 = %ls\n", g_probeAbs);

    // ---- 开事务 ----
    HANDLE txn = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
    if (!txn || txn == INVALID_HANDLE_VALUE) {
        char line[160];
        snprintf(line, sizeof(line), "CreateTransaction 失败（err=%lu）",
            static_cast<unsigned long>(GetLastError()));
        Skip(line);
        Skip("KTM 不可用 —— A~E 各节跳过（这是环境事实，不是代码缺陷）");
        goto cleanup;
    }
    Obs("CreateTransaction 成功（KTM 可用）");

    // ---------------------------------------------------------- Part A
    printf("\n--- A. 基线（负对照）：判据关着时，事务路径能正常打开 ---\n");
    {
        HANDLE h = nullptr;
        LONG st = OpenKeyKtmVia(g_probeAbs, KEY_READ, txn, &h);
        char line[220];
        snprintf(line, sizeof(line), "判据关时 NtOpenKeyTransacted 打开探针键成功（st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st >= 0 && h != nullptr);
        if (h) CloseHandle(h);

        h = nullptr;
        st = OpenKeyKtmExVia(g_probeAbs, KEY_READ, 0, txn, &h);
        snprintf(line, sizeof(line), "判据关时 NtOpenKeyTransactedEx 打开探针键成功（st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st >= 0 && h != nullptr);
        if (h) CloseHandle(h);
    }

    // ---------------------------------------------------------- Part B/C
    printf("\n--- B/C. 缺口演示（关事务 detour）与修复生效（开事务 detour）---\n");
    InterlockedExchange(&g_blockOn, 1);

    // B0：非事务判据本身有效
    {
        HANDLE h = nullptr;
        const LONG st = OpenKeyVia(g_probeAbs, KEY_SET_VALUE, &h);
        char line[220];
        snprintf(line, sizeof(line),
            "非事务 NtOpenKey(KEY_SET_VALUE) 被拒（st=0x%08lX == ACCESS_DENIED）",
            static_cast<unsigned long>(st));
        Check(line, st == STATUS_ACCESS_DENIED);
        if (h) CloseHandle(h);
    }

    // B：关掉三个事务 detour ＝ 修复前的状态
    MH_DisableHook(reinterpret_cast<LPVOID>(g_targetNtOpenKeyTransacted));
    MH_DisableHook(reinterpret_cast<LPVOID>(g_targetNtOpenKeyTransactedEx));
    MH_DisableHook(reinterpret_cast<LPVOID>(g_targetNtCreateKeyTransacted));
    {
        const LONG openHitsBefore = InterlockedCompareExchange(&g_openHits, 0, 0);

        HANDLE h = nullptr;
        const LONG st = OpenKeyKtmVia(g_probeAbs, KEY_SET_VALUE, txn, &h);

        char line[240];
        snprintf(line, sizeof(line),
            "★ 事务 detour 关闭时 NtOpenKeyTransacted(KEY_SET_VALUE) **拿到句柄**（绕过成立，st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st >= 0 && h != nullptr);
        if (h) CloseHandle(h);

        const LONG openHitsAfter = InterlockedCompareExchange(&g_openHits, 0, 0);
        snprintf(line, sizeof(line),
            "★ 非事务 NtOpenKey detour **没有**被顺带触发（%ld -> %ld）—— 缺口确实存在",
            static_cast<long>(openHitsBefore), static_cast<long>(openHitsAfter));
        Check(line, openHitsBefore == openHitsAfter);

        // 非事务判据仍然有效（证明"关的只是事务那三个"，不是整个判据塌了）
        HANDLE h2 = nullptr;
        const LONG st2 = OpenKeyVia(g_probeAbs, KEY_SET_VALUE, &h2);
        snprintf(line, sizeof(line), "同一时刻非事务路径**仍被拒**（st=0x%08lX）",
            static_cast<unsigned long>(st2));
        Check(line, st2 == STATUS_ACCESS_DENIED);
        if (h2) CloseHandle(h2);
    }

    // C：打开三个事务 detour ＝ v75 之后的状态
    MH_EnableHook(reinterpret_cast<LPVOID>(g_targetNtOpenKeyTransacted));
    MH_EnableHook(reinterpret_cast<LPVOID>(g_targetNtOpenKeyTransactedEx));
    MH_EnableHook(reinterpret_cast<LPVOID>(g_targetNtCreateKeyTransacted));
    {
        char line[240];

        HANDLE h = nullptr;
        LONG st = OpenKeyKtmVia(g_probeAbs, KEY_SET_VALUE, txn, &h);
        snprintf(line, sizeof(line),
            "★ 修复后 NtOpenKeyTransacted(KEY_SET_VALUE) 被拒（st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st == STATUS_ACCESS_DENIED);
        if (h) CloseHandle(h);

        h = nullptr;
        st = OpenKeyKtmExVia(g_probeAbs, KEY_SET_VALUE, 0, txn, &h);
        snprintf(line, sizeof(line),
            "★ 修复后 NtOpenKeyTransactedEx(KEY_SET_VALUE) 被拒（st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st == STATUS_ACCESS_DENIED);
        if (h) CloseHandle(h);

        WCHAR created[640] = {};
        wcscpy_s(created, g_probeAbs);
        wcscat_s(created, L"\\TxnCreated");
        ULONG disp = 0;
        h = nullptr;
        st = CreateKeyKtmVia(created, KEY_ALL_ACCESS, txn, &h, &disp);
        snprintf(line, sizeof(line),
            "★ 修复后 NtCreateKeyTransacted(建子键) 被拒（st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st == STATUS_ACCESS_DENIED);
        if (h) CloseHandle(h);

        // 负对照：不受保护的键必须**仍然放行**（否则就是"一律拒绝"）
        h = nullptr;
        st = OpenKeyKtmVia(g_softAbs, KEY_READ, txn, &h);
        snprintf(line, sizeof(line),
            "负对照：事务打开**不受保护**的键仍放行（st=0x%08lX）",
            static_cast<unsigned long>(st));
        Check(line, st >= 0 && h != nullptr);
        if (h) CloseHandle(h);

        // detour 真的被调到（不是"因为别的原因失败"）
        const LONG hK = InterlockedCompareExchange(&g_openKtmHits, 0, 0);
        const LONG hE = InterlockedCompareExchange(&g_openKtmExHits, 0, 0);
        const LONG hC = InterlockedCompareExchange(&g_createKtmHits, 0, 0);
        snprintf(line, sizeof(line), "三个事务 detour 都被调到过（open=%ld ex=%ld create=%ld）",
            static_cast<long>(hK), static_cast<long>(hE), static_cast<long>(hC));
        Check(line, hK > 0 && hE > 0 && hC > 0);
    }

    InterlockedExchange(&g_blockOn, 0);   // 后面几节放行

    // ---------------------------------------------------------- Part D
    printf("\n--- D. 事务键句柄上**复用同一 API**（v71 值替换 / v72 枚举隐藏）---\n");
    {
        HANDLE hTxnKey = nullptr;
        LONG st = OpenKeyKtmVia(g_probeAbs, KEY_ALL_ACCESS, txn, &hTxnKey);
        char line[240];
        snprintf(line, sizeof(line), "拿到事务键句柄（st=0x%08lX）", static_cast<unsigned long>(st));
        Check(line, st >= 0 && hTxnKey != nullptr);

        HANDLE hPlainKey = nullptr;
        const LONG stP = OpenKeyVia(g_probeAbs, KEY_ALL_ACCESS, &hPlainKey);
        snprintf(line, sizeof(line), "拿到非事务键句柄（对照，st=0x%08lX）",
            static_cast<unsigned long>(stP));
        Check(line, stP >= 0 && hPlainKey != nullptr);

        if (hTxnKey && hPlainKey) {
            // ---- D0. NtQueryKey 吃不吃事务键句柄（生产 ResolveKeyPath 依赖它）----
            {
                WCHAR p1[REnum::kMaxKeyPathChars] = {};
                const ULONG c1 = QueryKeyPathImpl(hTxnKey, p1, static_cast<ULONG>(_countof(p1)));
                WCHAR p2[REnum::kMaxKeyPathChars] = {};
                const ULONG c2 = QueryKeyPathImpl(hPlainKey, p2, static_cast<ULONG>(_countof(p2)));
                snprintf(line, sizeof(line),
                    "★ NtQueryKey 吃**事务键句柄**（事务 %u 字符 / 非事务 %u 字符）", c1, c2);
                Check(line, c1 > 0 && c2 > 0 && _wcsicmp(p1, p2) == 0);
                if (c1 > 0) {
                    snprintf(line, sizeof(line), "   事务键句柄的路径 = %ls", p1);
                    Obs(line);
                }
            }

            // ---- D1. 值读：走同一个 NtQueryValueKey ----
            InterlockedExchange(&g_spoofOn, 1);
            {
                const LONG qBefore = InterlockedCompareExchange(&g_queryHits, 0, 0);

                static BYTE bufT[2048];
                static BYTE bufP[2048];
                ZeroMemory(bufT, sizeof(bufT));
                ZeroMemory(bufP, sizeof(bufP));
                ULONG rlT = 0, rlP = 0;

                const LONG stT = QueryValueVia(hTxnKey, L"Text", 2, bufT, sizeof(bufT), &rlT);
                const LONG stP2 = QueryValueVia(hPlainKey, L"Text", 2, bufP, sizeof(bufP), &rlP);

                const LONG qAfter = InterlockedCompareExchange(&g_queryHits, 0, 0);
                snprintf(line, sizeof(line),
                    "事务句柄上的 NtQueryValueKey **走同一个 detour**（hits %ld -> %ld，本次 +2）",
                    static_cast<long>(qBefore), static_cast<long>(qAfter));
                Check(line, qAfter - qBefore >= 2);

                RSpoof::DataRegion region = {};
                const bool located = RSpoof::LocateDataRegion(2, bufT, sizeof(bufT), rlT, region);
                snprintf(line, sizeof(line),
                    "★ 事务句柄上 v71 值替换生效（成功 st=0x%08lX，数据区全 0）",
                    static_cast<unsigned long>(stT));
                Check(line, stT >= 0 && located && region.length > 0
                    && bufT[region.offset] == 0 && bufT[region.offset + 1] == 0);

                snprintf(line, sizeof(line),
                    "非事务句柄上结果**逐字节相同**（st=0x%08lX，两路同一份代码）",
                    static_cast<unsigned long>(stP2));
                Check(line, stP2 >= 0 && rlT == rlP && memcmp(bufT, bufP, rlT) == 0);
            }
            InterlockedExchange(&g_spoofOn, 0);

            // ---- D2. 枚举：走同一个 NtEnumerateKey，且 v72 隐藏生效 ----
            InterlockedExchange(&g_enumHideOn, 1);
            {
                const LONG eBefore = InterlockedCompareExchange(&g_enumHits, 0, 0);

                WCHAR n0[256] = {}, n1[256] = {}, n2[256] = {};
                LONG s0 = 0, s1 = 0, s2 = 0;
                const bool ok0 = EnumChildName(hTxnKey, 0, n0, 256, &s0);
                const bool ok1 = EnumChildName(hTxnKey, 1, n1, 256, &s1);
                const bool ok2 = EnumChildName(hTxnKey, 2, n2, 256, &s2);

                const LONG eAfter = InterlockedCompareExchange(&g_enumHits, 0, 0);
                snprintf(line, sizeof(line),
                    "事务句柄上的 NtEnumerateKey **走同一个 detour**（hits %ld -> %ld）",
                    static_cast<long>(eBefore), static_cast<long>(eAfter));
                Check(line, eAfter - eBefore >= 3);

                snprintf(line, sizeof(line),
                    "★ 事务句柄上 v72 枚举隐藏生效：0 -> %ls，1 -> %ls（HiddenChild 被跳过）",
                    ok0 ? n0 : L"(失败)", ok1 ? n1 : L"(失败)");
                Check(line, ok0 && ok1 && _wcsicmp(n0, L"Vis1") == 0 && _wcsicmp(n1, L"Vis2") == 0);

                snprintf(line, sizeof(line),
                    "★ 索引 2 越界（st=0x%08lX == NO_MORE_ENTRIES，可见项只有 2 个）",
                    static_cast<unsigned long>(s2));
                Check(line, !ok2 && s2 == static_cast<LONG>(REnum::kStatusNoMoreEntries));

                snprintf(line, sizeof(line), "真的藏掉了项（hidden=%ld）",
                    static_cast<long>(InterlockedCompareExchange(&g_enumHidden, 0, 0)));
                Check(line, InterlockedCompareExchange(&g_enumHidden, 0, 0) > 0);

                // 对照：非事务句柄上行为**完全一致**
                WCHAR m0[256] = {}, m1[256] = {};
                LONG t0 = 0, t1 = 0;
                const bool okm0 = EnumChildName(hPlainKey, 0, m0, 256, &t0);
                const bool okm1 = EnumChildName(hPlainKey, 1, m1, 256, &t1);
                snprintf(line, sizeof(line), "非事务句柄上枚举结果**逐项相同**（%ls / %ls）",
                    okm0 ? m0 : L"(失败)", okm1 ? m1 : L"(失败)");
                Check(line, okm0 && okm1 && _wcsicmp(m0, n0) == 0 && _wcsicmp(m1, n1) == 0);
            }
            InterlockedExchange(&g_enumHideOn, 0);

            // ---- D3. 值写：走同一个 NtSetValueKey ----
            {
                const LONG sBefore = InterlockedCompareExchange(&g_setHits, 0, 0);
                DWORD v = 0xAABBCCDD;
                const LONG stS = SetValueVia(hTxnKey, L"TxnWrite", REG_DWORD, &v, sizeof(v));
                const LONG sAfter = InterlockedCompareExchange(&g_setHits, 0, 0);
                snprintf(line, sizeof(line),
                    "事务句柄上的 NtSetValueKey **走同一个 detour**（hits %ld -> %ld，st=0x%08lX）",
                    static_cast<long>(sBefore), static_cast<long>(sAfter),
                    static_cast<unsigned long>(stS));
                Check(line, sAfter > sBefore && stS >= 0);
            }
        }

        if (hTxnKey) CloseHandle(hTxnKey);
        if (hPlainKey) CloseHandle(hPlainKey);
    }

    // ---------------------------------------------------------- Part E
    printf("\n--- E. 事务语义：读己之写 + 回滚 ---\n");
    {
        char line[240];

        // E1：事务内写，事务内读得到（读己之写）。
        // ⚠️ 必须用**事务内打开的键句柄**来写 —— 事务句柄（`txn`）不是键句柄，
        //    拿它去调 `NtSetValueKey` 是错的（会返回 INVALID_HANDLE）。
        HANDLE hTxnKey = nullptr;
        LONG st = OpenKeyKtmVia(g_probeAbs, KEY_ALL_ACCESS, txn, &hTxnKey);
        snprintf(line, sizeof(line), "事务内打开键句柄（st=0x%08lX）", static_cast<unsigned long>(st));
        Check(line, st >= 0 && hTxnKey != nullptr);

        if (hTxnKey) {
            DWORD v = 0x55667788;
            const LONG stW = SetValueVia(hTxnKey, L"TxnVal", REG_DWORD, &v, sizeof(v));
            snprintf(line, sizeof(line), "事务内写入 TxnVal 成功（st=0x%08lX）",
                static_cast<unsigned long>(stW));
            Check(line, stW >= 0);

            static BYTE buf[2048];
            ZeroMemory(buf, sizeof(buf));
            ULONG rl = 0;
            const LONG stR = QueryValueVia(hTxnKey, L"TxnVal", 2, buf, sizeof(buf), &rl);
            DWORD got = 0;
            RSpoof::DataRegion region = {};
            if (stR >= 0 && RSpoof::LocateDataRegion(2, buf, sizeof(buf), rl, region)
                && region.length >= sizeof(DWORD)) {
                memcpy(&got, buf + region.offset, sizeof(got));
            }
            snprintf(line, sizeof(line),
                "★ 读己之写：事务内读回 TxnVal == 0x%08lX（st=0x%08lX）",
                static_cast<unsigned long>(got), static_cast<unsigned long>(stR));
            Check(line, stR >= 0 && got == 0x55667788);

            // 收尾：这个键句柄属于事务，Rollback 后就失效；先关掉。
            CloseHandle(hTxnKey);
            hTxnKey = nullptr;
        }

        // E2：回滚 -> 写的东西不见了
        const BOOL rb = RollbackTransaction(txn);
        snprintf(line, sizeof(line), "RollbackTransaction 成功（%d）", rb ? 1 : 0);
        Check(line, rb != FALSE);
        CloseHandle(txn);
        txn = nullptr;

        {
            HANDLE h = nullptr;
            const LONG st2 = OpenKeyVia(g_probeAbs, KEY_READ, &h);
            static BYTE buf[2048];
            ZeroMemory(buf, sizeof(buf));
            ULONG rl = 0;
            const LONG stR = (st2 >= 0 && h) ? QueryValueVia(h, L"TxnVal", 2, buf, sizeof(buf), &rl) : -1;
            snprintf(line, sizeof(line),
                "★ 回滚后 TxnVal 读不到（st=0x%08lX == OBJECT_NAME_NOT_FOUND）",
                static_cast<unsigned long>(stR));
            Check(line, stR == STATUS_OBJECT_NAME_NOT_FOUND);
            if (h) CloseHandle(h);
        }

        // E3：对照 —— 提交后写的东西**在**
        {
            HANDLE txn2 = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
            if (!txn2 || txn2 == INVALID_HANDLE_VALUE) {
                Skip("第二个事务创建失败，提交对照跳过");
            }
            else {
                HANDLE hTxnKey2 = nullptr;
                const LONG st3 = OpenKeyKtmVia(g_probeAbs, KEY_ALL_ACCESS, txn2, &hTxnKey2);
                if (st3 >= 0 && hTxnKey2) {
                    DWORD v = 0x0BADF00D;
                    SetValueVia(hTxnKey2, L"CommittedVal", REG_DWORD, &v, sizeof(v));
                    CloseHandle(hTxnKey2);
                }
                const BOOL cm = CommitTransaction(txn2);
                snprintf(line, sizeof(line), "CommitTransaction 成功（%d）", cm ? 1 : 0);
                Check(line, cm != FALSE);
                CloseHandle(txn2);

                HANDLE h = nullptr;
                if (OpenKeyVia(g_probeAbs, KEY_READ, &h) >= 0 && h) {
                    static BYTE buf[2048];
                    ZeroMemory(buf, sizeof(buf));
                    ULONG rl = 0;
                    const LONG stR = QueryValueVia(h, L"CommittedVal", 2, buf, sizeof(buf), &rl);
                    DWORD got = 0;
                    RSpoof::DataRegion region = {};
                    if (stR >= 0 && RSpoof::LocateDataRegion(2, buf, sizeof(buf), rl, region)
                        && region.length >= sizeof(DWORD)) {
                        memcpy(&got, buf + region.offset, sizeof(got));
                    }
                    snprintf(line, sizeof(line),
                        "对照：提交后 CommittedVal == 0x%08lX（写确实落地了）",
                        static_cast<unsigned long>(got));
                    Check(line, stR >= 0 && got == 0x0BADF00D);
                    CloseHandle(h);
                }
                else {
                    Check("对照：提交后能读到 CommittedVal", false);
                }
            }
        }
    }

cleanup:
    // ---------------------------------------------------------- 收尾
    {
        char line[200];
        snprintf(line, sizeof(line), "detour 计数自检：query=%ld enum=%ld set=%ld open=%ld",
            static_cast<long>(InterlockedCompareExchange(&g_queryHits, 0, 0)),
            static_cast<long>(InterlockedCompareExchange(&g_enumHits, 0, 0)),
            static_cast<long>(InterlockedCompareExchange(&g_setHits, 0, 0)),
            static_cast<long>(InterlockedCompareExchange(&g_openHits, 0, 0)));
        Obs(line);

        const LONG pf = InterlockedCompareExchange(&g_enumPathFail, 0, 0);
        snprintf(line, sizeof(line), "枚举 detour 取不到父路径的次数 = %ld（>0 -> v72 会静默降级）",
            static_cast<long>(pf));
        Obs(line);
    }

    for (int i = 0; i < specCount; ++i) {
        MH_DisableHook(specs[i].target);
    }
    MH_Uninitialize();
    DeleteProbeKey();

    printf("\n=== 结果：通过 %d / 失败 %d / 跳过 %d ===\n", g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}
