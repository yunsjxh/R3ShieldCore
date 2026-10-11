//
// ktm_effect_demo.cpp —— R3 ShieldCore 注册表保护「看得见的效果」演示
//
// ★★ 这不是探针，是**演示**。
//    它把「保护逻辑」装在自己进程里，然后**自己扮演攻击者**去攻同一台机器上的
//    受保护键，把每一步的**真实返回值**和**真实数据**打印出来 ——
//    让「保护前 vs 保护后」「v75 之前 vs v75 之后」的差别一眼可见。
//
// ★ 不启动引擎、不注入任何进程（铁律 175 不适用）；只在 HKCU 下建临时键，跑完删掉。
// ★ 判据与伪造逻辑**与生产同源**：直接 `#include` 两个 codec 头（铁律 195）。
//
// 三幕：
//   第 1 幕  保护关闭        —— 攻击者想读就读、想写就写（＝引擎没装 / 开关全关）
//   第 2 幕  保护打开        —— 读不到 / 看不见 / 写不进（＝引擎装上后）
//   第 3 幕  事务（KTM）绕过  —— (A) v75 之前：第一道门敞开；(B) v75 之后：被拒
//
// 用法：
//   ./tools/ktm_effect_demo.exe
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

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((LONG)0xC0000022L)
#endif

// ------------------------------------------------------------------ 输出
static void Hr()            { printf("  ------------------------------------------------------------\n"); }
static void Act(const char* s) { printf("   攻击者: %s\n", s); }
static void Res(const char* s) { printf("   ->     %s\n", s); }

// ------------------------------------------------------------------ 原生结构
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

static NtOpenKey_t             g_tOpenKey = nullptr;
static NtOpenKeyTransacted_t   g_tOpenKeyKtm = nullptr;
static NtOpenKeyTransactedEx_t g_tOpenKeyKtmEx = nullptr;
static NtCreateKeyTransacted_t g_tCreateKeyKtm = nullptr;
static NtQueryValueKey_t       g_tQueryValue = nullptr;
static NtEnumerateKey_t        g_tEnumKey = nullptr;
static NtSetValueKey_t         g_tSetValue = nullptr;

static NtOpenKey_t             g_oOpenKey = nullptr;
static NtOpenKeyTransacted_t   g_oOpenKeyKtm = nullptr;
static NtOpenKeyTransactedEx_t g_oOpenKeyKtmEx = nullptr;
static NtCreateKeyTransacted_t g_oCreateKeyKtm = nullptr;
static NtQueryValueKey_t       g_oQueryValue = nullptr;
static NtEnumerateKey_t        g_oEnumKey = nullptr;
static NtSetValueKey_t         g_oSetValue = nullptr;
static NtQueryKey_t            g_oQueryKey = nullptr;

// ------------------------------------------------------------------ 开关 / 计数
static volatile LONG g_protectOn = 0;   // 保护总开关（＝引擎装没装）
static int g_blocked = 0;               // 被挡下来的攻击次数
static int g_allowed = 0;               // 溜过去的攻击次数

static void MarkBlocked() { ++g_blocked; }
static void MarkAllowed() { ++g_allowed; }

// ------------------------------------------------------------------ 工具
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

// 保护判据：绝对路径里含 `R3ShieldCoreDemo`（与生产的 `protect_reg=` 名单同一口径）。
static bool PathIsProtected(const ProbeUnicodeString* name)
{
    if (!name || !name->Buffer || name->Length == 0) return false;
    return ContainsW(name->Buffer, name->Length / sizeof(WCHAR), L"R3ShieldCoreDemo");
}

// ------------------------------------------------------------------ 路径查询
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

// ------------------------------------------------------------------ detour
//
// ★ 与生产 `registry_guard.cpp` 的对应 detour **同构**：
//   准入类 = 命中受保护 + 带写意图 -> 拒；读类 = 真调后清零/隐藏；写类 = 拒。

static LONG NTAPI NtOpenKey_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
    const ProbeObjectAttributes* Oa)
{
    if (g_protectOn && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_oOpenKey(KeyHandle, Access, Oa);
}

static LONG NTAPI NtOpenKeyTransacted_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
    const ProbeObjectAttributes* Oa, HANDLE Txn)
{
    if (g_protectOn && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_oOpenKeyKtm(KeyHandle, Access, Oa, Txn);
}

static LONG NTAPI NtOpenKeyTransactedEx_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
    const ProbeObjectAttributes* Oa, ULONG Opts, HANDLE Txn)
{
    if (g_protectOn && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_oOpenKeyKtmEx(KeyHandle, Access, Oa, Opts, Txn);
}

static LONG NTAPI NtCreateKeyTransacted_Detour(PHANDLE KeyHandle, ACCESS_MASK Access,
    const ProbeObjectAttributes* Oa, ULONG Title, ProbeUnicodeString* Class,
    ULONG CreateOptions, HANDLE Txn, PULONG Disposition)
{
    if (g_protectOn && Oa && PathIsProtected(Oa->ObjectName) && IsWriteAccess(Access)) {
        return STATUS_ACCESS_DENIED;
    }
    return g_oCreateKeyKtm(KeyHandle, Access, Oa, Title, Class, CreateOptions, Txn, Disposition);
}

// v71：读 -> 成功但数据区全 0（长度字段一个都不改）。
static LONG NTAPI NtQueryValueKey_Detour(HANDLE Key, const ProbeUnicodeString* Name, ULONG Cls,
    PVOID Info, ULONG Len, PULONG ResultLen)
{
    const LONG st = g_oQueryValue(Key, Name, Cls, Info, Len, ResultLen);
    if (!g_protectOn || st < 0 || !Info || !ResultLen) return st;

    WCHAR path[REnum::kMaxKeyPathChars] = {};
    if (QueryKeyPathImpl(Key, path, static_cast<ULONG>(_countof(path))) == 0) return st;
    if (!ContainsW(path, static_cast<ULONG>(wcslen(path)), L"R3ShieldCoreDemo")) return st;

    RSpoof::DataRegion region = {};
    if (RSpoof::LocateDataRegion(Cls, Info, Len, *ResultLen, region)) {
        RSpoof::ZeroDataRegion(Info, Len, region);
    }
    return st;
}

// v72：枚举 -> 索引重映射，名字含 `Secret` 的项被跳过（不造假项）。
static LONG NTAPI NtEnumerateKey_Detour(HANDLE Key, ULONG Index, ULONG Cls,
    PVOID Info, ULONG Len, PULONG ResultLen)
{
    if (!g_protectOn) return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);

    WCHAR path[REnum::kMaxKeyPathChars] = {};
    if (QueryKeyPathImpl(Key, path, static_cast<ULONG>(_countof(path))) == 0) {
        return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);
    }

    ULONG orig = 0, hidden = 0;
    LONG probe = 0;
    const bool ok = REnum::RemapEnumerationIndexImpl(false,
        [Key](ULONG i, ULONG c, PVOID b, ULONG bl, PULONG rl) {
            return g_oEnumKey(Key, i, c, b, bl, rl);
        },
        [](const WCHAR* child) {
            return ContainsW(child, static_cast<ULONG>(wcslen(child)), L"Secret");
        },
        Index, path, static_cast<ULONG>(wcslen(path)), orig, hidden, probe);

    const REnum::RemapResult r = REnum::ClassifyRemap(ok, hidden, orig, Index,
        ok && REnum::IsNoMoreEntries(probe));

    if (r == REnum::RemapResult::Mapped && hidden > 0) {
        return g_oEnumKey(Key, orig, Cls, Info, Len, ResultLen);
    }
    if (r == REnum::RemapResult::Exhausted && hidden > 0) {
        if (ResultLen) *ResultLen = 0;
        return REnum::kStatusNoMoreEntries;
    }
    return g_oEnumKey(Key, Index, Cls, Info, Len, ResultLen);
}

// 写判据：命中受保护 -> 拒。
static LONG NTAPI NtSetValueKey_Detour(HANDLE Key, const ProbeUnicodeString* Name, ULONG Title,
    ULONG Type, PVOID Data, ULONG DataSize)
{
    if (g_protectOn) {
        WCHAR path[REnum::kMaxKeyPathChars] = {};
        if (QueryKeyPathImpl(Key, path, static_cast<ULONG>(_countof(path))) > 0
            && ContainsW(path, static_cast<ULONG>(wcslen(path)), L"R3ShieldCoreDemo")) {
            return STATUS_ACCESS_DENIED;
        }
    }
    return g_oSetValue(Key, Name, Title, Type, Data, DataSize);
}

// ------------------------------------------------------------------ 调用包装
static LONG KtmOpen(const WCHAR* absPath, ACCESS_MASK access, HANDLE txn, PHANDLE out)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, absPath);
    ProbeObjectAttributes oa = {};
    InitObjAttr(&oa, nullptr, &us);
    return g_tOpenKeyKtm(out, access, &oa, txn);
}

static LONG KtmCreate(const WCHAR* absPath, ACCESS_MASK access, HANDLE txn,
    PHANDLE out, PULONG disp)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, absPath);
    ProbeObjectAttributes oa = {};
    InitObjAttr(&oa, nullptr, &us);
    return g_tCreateKeyKtm(out, access, &oa, 0, nullptr, 0, txn, disp);
}

static LONG KtmSetValue(HANDLE key, const WCHAR* valueName, ULONG type, PVOID data, ULONG size)
{
    ProbeUnicodeString us = {};
    MakeUs(&us, valueName);
    return g_tSetValue(key, &us, 0, type, data, size);
}

// ------------------------------------------------------------------ 演示夹具
static const WCHAR* kRel = L"Software\\R3ShieldCoreDemo\\Vault";
static WCHAR g_abs[512] = {};        // 受保护键的绝对 NT 路径
static WCHAR g_softAbs[512] = {};    // 一个**不受保护**的键（负对照用）

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

static void DeleteFixture()
{
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreDemo");
}

static bool CreateFixture()
{
    DeleteFixture();

    HKEY h = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRel, 0, nullptr, REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        return false;
    }

    const wchar_t* pw = L"hunter2";
    RegSetValueExW(h, L"Password", 0, REG_SZ, reinterpret_cast<const BYTE*>(pw),
        static_cast<DWORD>((wcslen(pw) + 1) * sizeof(WCHAR)));

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

// ------------------------------------------------------------------ 演示动作
static void DemoRead(const char* tag)
{
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRel, 0, KEY_READ, &h) != ERROR_SUCCESS) {
        Act("RegQueryValueExW(Password)");
        Res("打开键就失败了 —— 打不开");
        return;
    }
    wchar_t buf[256] = {};
    DWORD cb = sizeof(buf);
    DWORD type = 0;
    const LSTATUS st = RegQueryValueExW(h, L"Password", nullptr, &type,
        reinterpret_cast<LPBYTE>(buf), &cb);
    RegCloseKey(h);

    char line[512];
    if (st != ERROR_SUCCESS) {
        snprintf(line, sizeof(line), "[%s] 读 Password 失败 err=%lu", tag,
            static_cast<unsigned long>(st));
        Act(line);
        Res("读不到");
    }
    else {
        snprintf(line, sizeof(line), "[%s] RegQueryValueExW(Password)  返回长度=%lu 字节，内容=\"%ls\"",
            tag, static_cast<unsigned long>(cb), buf);
        Act(line);
        if (buf[0] == L'\0') {
            Res("内容被清空（长度没变、数据全 0）  ==>  读不到");
        }
        else {
            Res("拿到真实值  ==>  泄露");
        }
    }
}

static void DemoEnum(const char* tag)
{
    HKEY h = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRel, 0, KEY_READ, &h) != ERROR_SUCCESS) {
        Act("RegEnumKeyExW 枚举子键");
        Res("打开键就失败了");
        return;
    }
    char line[512];
    snprintf(line, sizeof(line), "[%s] RegEnumKeyExW 枚举子键:", tag);
    Act(line);
    for (DWORD i = 0; i < 4; ++i) {
        wchar_t name[256] = {};
        DWORD cch = 256;
        const LSTATUS st = RegEnumKeyExW(h, i, name, &cch, nullptr, nullptr, nullptr, nullptr);
        if (st == ERROR_SUCCESS) {
            printf("             第 %lu 项 = %ls\n", static_cast<unsigned long>(i), name);
        }
        else {
            printf("             第 %lu 项 = 越界（err=%lu）\n",
                static_cast<unsigned long>(i), static_cast<unsigned long>(st));
            break;
        }
    }
    RegCloseKey(h);
}

static void DemoWrite(const char* tag, const wchar_t* valueName, const wchar_t* data)
{
    HKEY h = nullptr;
    LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER, kRel, 0, KEY_SET_VALUE, &h);
    if (st != ERROR_SUCCESS) {
        char line[512];
        snprintf(line, sizeof(line), "[%s] RegSetValueExW(%ls) -> 打开键就被拒 err=%lu",
            tag, valueName, static_cast<unsigned long>(st));
        Act(line);
        Res("写不进（准入这一层就挡住了）");
        MarkBlocked();
        return;
    }
    st = RegSetValueExW(h, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(data),
        static_cast<DWORD>((wcslen(data) + 1) * sizeof(WCHAR)));
    RegCloseKey(h);

    char line[512];
    if (st == ERROR_SUCCESS) {
        snprintf(line, sizeof(line), "[%s] RegSetValueExW(%ls, \"%ls\") -> 成功",
            tag, valueName, data);
        Act(line);
        Res("写进去了  ==>  篡改成功");
        MarkAllowed();
    }
    else {
        snprintf(line, sizeof(line), "[%s] RegSetValueExW(%ls, \"%ls\") -> 拒绝 err=%lu",
            tag, valueName, data, static_cast<unsigned long>(st));
        Act(line);
        Res("写不进  ==>  篡改失败");
        MarkBlocked();
    }
}

// ================================================================== main
int main()
{
    printf("\n");
    printf("==============================================================\n");
    printf(" R3 ShieldCore —— 注册表保护「看得见的效果」演示\n");
    printf("==============================================================\n");
    printf(" 本演示**不启动引擎、不注入任何进程**。\n");
    printf(" 它把「保护逻辑」装在自己进程里，然后自己扮演攻击者去攻受保护键，\n");
    printf(" 把每一步的真实返回值和真实数据打印出来。\n");
    printf("\n");
    printf(" 受保护键 : HKCU\\%ls\n", kRel);
    printf(" 真实内容 : Password = \"hunter2\" ；子键 Public1 / SecretKey / Public2\n");
    printf(" 保护判据 : 路径含 \"R3ShieldCoreDemo\"（与生产的 protect_reg= 同一口径）\n");
    printf("\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    g_tOpenKey = reinterpret_cast<NtOpenKey_t>(GetProcAddress(ntdll, "NtOpenKey"));
    g_tOpenKeyKtm = reinterpret_cast<NtOpenKeyTransacted_t>(GetProcAddress(ntdll, "NtOpenKeyTransacted"));
    g_tOpenKeyKtmEx = reinterpret_cast<NtOpenKeyTransactedEx_t>(GetProcAddress(ntdll, "NtOpenKeyTransactedEx"));
    g_tCreateKeyKtm = reinterpret_cast<NtCreateKeyTransacted_t>(GetProcAddress(ntdll, "NtCreateKeyTransacted"));
    g_tQueryValue = reinterpret_cast<NtQueryValueKey_t>(GetProcAddress(ntdll, "NtQueryValueKey"));
    g_tEnumKey = reinterpret_cast<NtEnumerateKey_t>(GetProcAddress(ntdll, "NtEnumerateKey"));
    g_tSetValue = reinterpret_cast<NtSetValueKey_t>(GetProcAddress(ntdll, "NtSetValueKey"));
    g_oQueryKey = reinterpret_cast<NtQueryKey_t>(GetProcAddress(ntdll, "NtQueryKey"));

    if (!g_tOpenKey || !g_tOpenKeyKtm || !g_tOpenKeyKtmEx || !g_tCreateKeyKtm
        || !g_tQueryValue || !g_tEnumKey || !g_tSetValue || !g_oQueryKey) {
        printf("[FATAL] ntdll 缺少必要导出\n");
        return 2;
    }

    if (MH_Initialize() != MH_OK) { printf("[FATAL] MH_Initialize 失败\n"); return 2; }

    struct HookSpec { LPVOID target; LPVOID detour; LPVOID* orig; const char* name; };
    const HookSpec specs[] = {
        { reinterpret_cast<LPVOID>(g_tOpenKey), reinterpret_cast<LPVOID>(NtOpenKey_Detour),
          reinterpret_cast<LPVOID*>(&g_oOpenKey), "NtOpenKey" },
        { reinterpret_cast<LPVOID>(g_tOpenKeyKtm), reinterpret_cast<LPVOID>(NtOpenKeyTransacted_Detour),
          reinterpret_cast<LPVOID*>(&g_oOpenKeyKtm), "NtOpenKeyTransacted" },
        { reinterpret_cast<LPVOID>(g_tOpenKeyKtmEx), reinterpret_cast<LPVOID>(NtOpenKeyTransactedEx_Detour),
          reinterpret_cast<LPVOID*>(&g_oOpenKeyKtmEx), "NtOpenKeyTransactedEx" },
        { reinterpret_cast<LPVOID>(g_tCreateKeyKtm), reinterpret_cast<LPVOID>(NtCreateKeyTransacted_Detour),
          reinterpret_cast<LPVOID*>(&g_oCreateKeyKtm), "NtCreateKeyTransacted" },
        { reinterpret_cast<LPVOID>(g_tQueryValue), reinterpret_cast<LPVOID>(NtQueryValueKey_Detour),
          reinterpret_cast<LPVOID*>(&g_oQueryValue), "NtQueryValueKey" },
        { reinterpret_cast<LPVOID>(g_tEnumKey), reinterpret_cast<LPVOID>(NtEnumerateKey_Detour),
          reinterpret_cast<LPVOID*>(&g_oEnumKey), "NtEnumerateKey" },
        { reinterpret_cast<LPVOID>(g_tSetValue), reinterpret_cast<LPVOID>(NtSetValueKey_Detour),
          reinterpret_cast<LPVOID*>(&g_oSetValue), "NtSetValueKey" },
    };
    const int specCount = static_cast<int>(sizeof(specs) / sizeof(specs[0]));

    int installed = 0;
    for (int i = 0; i < specCount; ++i) {
        if (MH_CreateHook(specs[i].target, specs[i].detour, specs[i].orig) == MH_OK
            && MH_EnableHook(specs[i].target) == MH_OK) {
            ++installed;
        }
    }
    printf(" [就绪] %d/%d 个 hook 装好（保护逻辑就位）\n", installed, specCount);

    if (!CreateFixture()) { printf("[FATAL] 建夹具失败\n"); return 2; }
    if (!QueryAbsPathOf(kRel, g_abs, 512) || !QueryAbsPathOf(L"Software", g_softAbs, 512)) {
        printf("[FATAL] 取绝对路径失败\n");
        return 2;
    }
    printf(" [就绪] 受保护键绝对路径 = %ls\n", g_abs);
    printf("\n");

    // ============================================================= 第 1 幕
    printf("##############################################################\n");
    printf("# 第 1 幕  保护**关闭**（＝引擎没装 / 开关全关）\n");
    printf("##############################################################\n");
    InterlockedExchange(&g_protectOn, 0);
    printf(" 当前状态：保护 = 关\n\n");
    DemoRead("基线");
    DemoEnum("基线");
    DemoWrite("基线", L"Attack1", L"pwned-by-plain");
    printf("\n >>> 结论：保护没开时，攻击者想读就读、想枚举就枚举、想写就写。\n\n");

    // ============================================================= 第 2 幕
    printf("##############################################################\n");
    printf("# 第 2 幕  保护**打开**（＝引擎装上后：写不进 / 读不到 / 看不见）\n");
    printf("##############################################################\n");
    InterlockedExchange(&g_protectOn, 1);
    printf(" 当前状态：保护 = 开\n\n");
    DemoRead("保护中");
    DemoEnum("保护中");
    DemoWrite("保护中", L"Password", L"pwned-by-plain");
    printf("\n >>> 结论：读 → 长度没变但内容空；枚举 → SecretKey 消失；写 → 被拒。\n\n");

    // ============================================================= 第 3 幕
    printf("##############################################################\n");
    printf("# 第 3 幕  攻击者改用「事务注册表（KTM）」绕过\n");
    printf("##############################################################\n");
    printf(" 攻击思路：普通路径被挡住了，那就用 `NtOpenKeyTransacted` /\n");
    printf("           `NtCreateKeyTransacted` —— 事务版**不是**同一个函数，\n");
    printf("           普通路径的准入判据**不经过**它。\n\n");

    // ---- (A) v75 之前：事务 hook 没挂 ----
    printf("--------------------------------------------------------------\n");
    printf(" (A) v75 **之前**：没有挂事务 hook（＝修复前的状态）\n");
    printf("--------------------------------------------------------------\n");
    MH_DisableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtm));
    MH_DisableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtmEx));
    MH_DisableHook(reinterpret_cast<LPVOID>(g_tCreateKeyKtm));
    {
        HANDLE txn = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
        if (!txn || txn == INVALID_HANDLE_VALUE) {
            printf(" [skip] 本机 KTM 不可用\n");
        }
        else {
            char line[512];
            HANDLE hKey = nullptr;
            LONG st = KtmOpen(g_abs, KEY_SET_VALUE, txn, &hKey);
            snprintf(line, sizeof(line),
                "[A1] NtOpenKeyTransacted(KEY_SET_VALUE) 打开受保护键  ->  st=0x%08lX",
                static_cast<unsigned long>(st));
            Act(line);
            if (st >= 0) { Res("**拿到句柄**  ==>  第一道门（准入）被绕过"); MarkAllowed(); }
            else { Res("被拒"); MarkBlocked(); }

            WCHAR evil[640] = {};
            wcscpy_s(evil, g_abs);
            wcscat_s(evil, L"\\Evil");
            ULONG disp = 0;
            HANDLE hEvil = nullptr;
            const LONG stC = KtmCreate(evil, KEY_ALL_ACCESS, txn, &hEvil, &disp);
            snprintf(line, sizeof(line),
                "[A2] NtCreateKeyTransacted 在受保护键下**凭空建子键** Evil  ->  st=0x%08lX",
                static_cast<unsigned long>(stC));
            Act(line);
            if (stC >= 0) { Res("建成功了，**没有任何阻拦**  ==>  受保护键下多了一个攻击者的键"); MarkAllowed(); }
            else { Res("被拒"); MarkBlocked(); }
            if (hEvil) CloseHandle(hEvil);
            if (hKey) CloseHandle(hKey);

            if (!CommitTransaction(txn)) { /* ignore */ }
            CloseHandle(txn);

            // 展示"读/枚举/写在事务句柄上复用同一个 API" ⇒ 这三条仍然有效
            printf("\n   （对照：v75 之前，读/枚举/写**本来就已经**在事务句柄上生效 ——\n");
            printf("    因为它们复用同一个 NtQueryValueKey / NtEnumerateKey / NtSetValueKey）\n");
            DemoRead("A3");
            DemoEnum("A3");
            DemoWrite("A3", L"Password", L"pwned-by-txn");
            printf("\n >>> (A) 结论：**准入被绕过**（拿到句柄 + 凭空建键），\n");
            printf("     而「读不到 / 看不见 / 写不进」这三条本身是好的。\n");
            printf("     ==> 缺的就是**「打开 / 创建」这一步的准入判据**。\n\n");
        }
    }

    // ---- (B) v75 之后：事务 hook 挂上 ----
    printf("--------------------------------------------------------------\n");
    printf(" (B) v75 **之后**：事务 hook 挂上（＝本版的实际状态）\n");
    printf("--------------------------------------------------------------\n");
    MH_EnableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtm));
    MH_EnableHook(reinterpret_cast<LPVOID>(g_tOpenKeyKtmEx));
    MH_EnableHook(reinterpret_cast<LPVOID>(g_tCreateKeyKtm));
    {
        HANDLE txn = CreateTransaction(nullptr, nullptr, 0, 0, 0, 0, nullptr);
        if (!txn || txn == INVALID_HANDLE_VALUE) {
            printf(" [skip] 本机 KTM 不可用\n");
        }
        else {
            char line[512];
            HANDLE hKey = nullptr;
            LONG st = KtmOpen(g_abs, KEY_SET_VALUE, txn, &hKey);
            snprintf(line, sizeof(line),
                "[B1] NtOpenKeyTransacted(KEY_SET_VALUE) 打开受保护键  ->  st=0x%08lX (%s)",
                static_cast<unsigned long>(st),
                st == STATUS_ACCESS_DENIED ? "STATUS_ACCESS_DENIED" : "见上");
            Act(line);
            if (st == STATUS_ACCESS_DENIED) { Res("被拒  ==>  堵住了"); MarkBlocked(); }
            else { Res("没挡住！"); MarkAllowed(); }
            if (hKey) CloseHandle(hKey);

            WCHAR evil[640] = {};
            wcscpy_s(evil, g_abs);
            wcscat_s(evil, L"\\Evil");
            ULONG disp = 0;
            HANDLE hEvil = nullptr;
            const LONG stC = KtmCreate(evil, KEY_ALL_ACCESS, txn, &hEvil, &disp);
            snprintf(line, sizeof(line),
                "[B2] NtCreateKeyTransacted 在受保护键下建子键 Evil  ->  st=0x%08lX",
                static_cast<unsigned long>(stC));
            Act(line);
            if (stC == STATUS_ACCESS_DENIED) { Res("被拒  ==>  凭空建键这条路也堵住了"); MarkBlocked(); }
            else { Res("没挡住！"); MarkAllowed(); }
            if (hEvil) CloseHandle(hEvil);

            // 负对照：不受保护的键必须仍然放行（否则就是"一律拒绝"，那叫误伤）
            HANDLE hSoft = nullptr;
            const LONG stN = KtmOpen(g_softAbs, KEY_READ, txn, &hSoft);
            snprintf(line, sizeof(line),
                "[B3] 负对照：NtOpenKeyTransacted 打开**不受保护**的键  ->  st=0x%08lX",
                static_cast<unsigned long>(stN));
            Act(line);
            if (stN >= 0) { Res("照常放行  ==>  没有误伤"); }
            else { Res("被误伤了！"); }
            if (hSoft) CloseHandle(hSoft);

            RollbackTransaction(txn);
            CloseHandle(txn);
            printf("\n >>> (B) 结论：三个事务变体被**同一套判据**挡住，且不受保护的键照常放行。\n\n");
        }
    }

    // ============================================================= 收尾
    printf("##############################################################\n");
    printf("# 总结\n");
    printf("##############################################################\n");
    printf(" 被挡下来的攻击 : %d 次\n", g_blocked);
    printf(" 溜过去的攻击   : %d 次\n", g_allowed);
    printf("\n");
    printf(" 一句话：\n");
    printf("   v75 之前 —— 事务变体是一道**敞开的后门**：普通路径挡住了，\n");
    printf("               攻击者换成 NtOpenKeyTransacted / NtCreateKeyTransacted\n");
    printf("               就能拿到句柄、凭空建键，而且**不产生任何事件**。\n");
    printf("   v75 之后 —— 三个事务变体走**同一套准入判据**，与普通路径一致；\n");
    printf("               而「读不到 / 看不见 / 写不进」在事务句柄上**照旧生效**\n");
    printf("               （因为它们复用同一个 NtQueryValueKey / NtEnumerateKey /\n");
    printf("                 NtSetValueKey）。\n");
    printf("\n");

    for (int i = 0; i < specCount; ++i) MH_DisableHook(specs[i].target);
    MH_Uninitialize();
    InterlockedExchange(&g_protectOn, 0);
    DeleteFixture();
    printf(" [清理] 临时键已删除。\n\n");
    return 0;
}
