//
// spoof_reg_enum_probe.cpp —— 实证：注册表「枚举隐藏」到底行不行（**真 API**）。
//
// 这是《回传数据替换Hook-技术预研》§8 Phase 3「注册表读替换」第二个子项
// （**枚举隐藏**，`NtEnumerateKey` / `NtEnumerateValueKey`）的机制探针。
// 它**不经过引擎**、**不需要注入器**，在一个进程里自己挂自己的 hook，
// 在 HKCU 下建一棵真键树，回答这些问题：
//
//   A. 基线（负对照）：隐藏关着时，枚举拿到的是**完整**列表吗？
//      —— 没有这一条，后面"少了两个"无法归因（铁律 110：空真）。
//   B. 隐藏真的发生了吗？—— 列表变短、且剩下的每一项都是**真实项**
//      （名字 / 顺序 / 内容与"直接按原始索引真调"逐字节相同）。
//   C. ★★ **索引重映射**：调用方要第 N 个可见项，拿到的是第 N 个可见项，
//      而且**没有重复**（"命中就往后挪一格"那种写法会产生重复项）。
//   D. ★ 越界语义：可见项数不够时返回 `STATUS_NO_MORE_ENTRIES` 且
//      `*ResultLength == 0`（与真实调用的越界完全一致）。
//   E. ★★ **默认值（空名项）不能让整条路失效**：值的"(默认)"项名字为空、
//      通常排在索引 0。若把"取不到名字"当成"判不出 ⇒ 放弃隐藏"，
//      **任何有默认值的键**都会让枚举隐藏整体失效（而且完全不报错）。
//      本探针专门造一个默认值来钉这条。
//   F. 缓冲区太小：仍返回 `STATUS_BUFFER_OVERFLOW` + 所需长度（行为不变）。
//   G. 对**真实调用方**生效：`RegEnumKeyExW` / `RegEnumValueW` 看到短列表。
//   H. ★ **诚实边界**：隐藏是**列表级**的，不是**访问级**的 ——
//      知道名字仍可直接打开 / 查询（本探针把这条也钉住，免得把定位吹大）。
//
// ★★ 关键：重映射算法**不是抄的** —— 直接 `#include "registry_enum_codec.h"`，
//    与生产 `registry_guard.cpp` 用的是**同一份控制流 + 同一份解析函数**
//    （铁律 195 / 127：同一份逻辑拷贝多份必然漂移，且漂了之后探针照样全绿、
//     生产照样出错）。
//
// ⚠️ 本探针只碰**自己进程内自己创建的**注册表键（HKCU 下一个临时键），
//    不注入任何进程、不读屏幕、不写系统位置。因此**不受**
//    「自动化脚本不得运行引擎」那条约束（铁律 175）。结束时会把临时键删掉。
//
// 编译：bash build_spoof_reg_enum_probe.sh
// 运行：./tools/spoof_reg_enum_probe.exe
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <MinHook.h>

#include "registry_enum_codec.h"   // ← 生产同款（不抄）

using namespace R3ShieldCoreRegistryEnum;

// ------------------------------------------------------------------ 状态
static int g_pass = 0;
static int g_fail = 0;

static volatile LONG g_hideOn = 0;        // 1 = detour 允许隐藏
static volatile LONG g_hits = 0;          // detour 进入次数
static volatile LONG g_hiddenCalls = 0;   // "真的藏掉了东西"的次数

// 受保护前缀（原始完整形式，运行时由 NtQueryKey 还原后拼出来）
static wchar_t g_hiddenPrefix[512] = {};
static ULONG g_hiddenPrefixChars = 0;

typedef LONG(NTAPI* NtEnumerateKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtEnumerateValueKey_t)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
typedef LONG(NTAPI* NtQueryKey_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static NtEnumerateKey_t g_targetNtEnumerateKey = nullptr;
static NtEnumerateKey_t g_origNtEnumerateKey = nullptr;
static NtEnumerateValueKey_t g_targetNtEnumerateValueKey = nullptr;
static NtEnumerateValueKey_t g_origNtEnumerateValueKey = nullptr;
static NtQueryKey_t g_origNtQueryKey = nullptr;   // 不挂钩，只用来还原路径

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ 工具
static LPVOID ProcOf(LPCWSTR module, LPCSTR name)
{
    HMODULE m = GetModuleHandleW(module);
    if (!m) return nullptr;
    return reinterpret_cast<LPVOID>(GetProcAddress(m, name));
}

// 用 NtQueryKey(KeyNameInformation) 还原键的完整路径（走 trampoline，不递归）。
static ULONG ResolveKeyPath(HANDLE key, wchar_t* buffer, ULONG capacity)
{
    if (!key || !g_origNtQueryKey || capacity == 0) return 0;

    constexpr ULONG KeyNameInformation = 3;
    struct LocalNameInfo { ULONG NameLength; wchar_t Name[1]; };

    static BYTE raw[sizeof(ULONG) + 1024 * sizeof(wchar_t)];
    ZeroMemory(raw, sizeof(raw));
    ULONG resultLength = 0;
    if (g_origNtQueryKey(key, KeyNameInformation, raw, sizeof(raw), &resultLength) < 0) {
        return 0;
    }

    auto* info = reinterpret_cast<LocalNameInfo*>(raw);
    ULONG chars = info->NameLength / sizeof(wchar_t);
    if (chars >= capacity) chars = capacity - 1;
    if (chars > 0) memcpy(buffer, info->Name, chars * sizeof(wchar_t));
    buffer[chars] = L'\0';
    return chars;
}

static bool StartsWithNoCase(const wchar_t* text, const wchar_t* prefix)
{
    return _wcsnicmp(text, prefix, wcslen(prefix)) == 0;
}

// "这个子路径算不算受保护" —— 探针里就是"以前缀开头"。
// ★ 生产用的是 `IsProtectedRegistryPathForSpoof`（两种写法都认）；
//   探针只用**原始完整形式**一种，因为 g_hiddenPrefix 是运行时还原出来的
//   同一种形式。这条差别不影响被测的**重映射算法**。
static bool IsHiddenChild(const wchar_t* childPath)
{
    return g_hiddenPrefixChars > 0 && StartsWithNoCase(childPath, g_hiddenPrefix);
}

// ------------------------------------------------------------------ detour
//
// ★ 与生产 `registry_guard.cpp` 的 `NtEnumerateKey_Hook` **同构**：
//   ① 先取被枚举键的路径；
//   ② 调 codec 的 `RemapEnumerationIndexImpl`（**同一份算法**）拿到
//      三态判定；
//   ③ Mapped ⇒ 用**调用方给的 class / 缓冲区**真调原始索引；
//      Exhausted ⇒ NO_MORE_ENTRIES + ResultLength=0；
//      其余 ⇒ 原样调用。
//   唯一差别：生产里"要不要隐藏"由 Policy 判定，这里由一个开关控制
//   （为了做"同一调用路径、只翻一个开关"的负对照）。
static LONG DetourCommon(bool valueEnum, HANDLE key, ULONG index, ULONG infoClass,
    PVOID info, ULONG length, PULONG resultLength)
{
    InterlockedIncrement(&g_hits);

    if (g_hideOn == 0) {
        return valueEnum
            ? g_origNtEnumerateValueKey(key, index, infoClass, info, length, resultLength)
            : g_origNtEnumerateKey(key, index, infoClass, info, length, resultLength);
    }

    wchar_t keyPath[512] = {};
    const ULONG keyPathChars = ResolveKeyPath(key, keyPath, 512);
    if (keyPathChars == 0) {
        return valueEnum
            ? g_origNtEnumerateValueKey(key, index, infoClass, info, length, resultLength)
            : g_origNtEnumerateKey(key, index, infoClass, info, length, resultLength);
    }

    struct Call {
        bool valueEnum;
        HANDLE key;
        LONG operator()(ULONG i, ULONG cls, PVOID buf, ULONG len, PULONG rl) const
        {
            return valueEnum
                ? g_origNtEnumerateValueKey(key, i, cls, buf, len, rl)
                : g_origNtEnumerateKey(key, i, cls, buf, len, rl);
        }
    } call{ valueEnum, key };

    struct Hidden {
        bool operator()(const wchar_t* childPath) const { return IsHiddenChild(childPath); }
    } hidden;

    ULONG originalIndex = 0;
    ULONG hiddenCount = 0;
    LONG probeStatus = 0;
    const bool ok = RemapEnumerationIndexImpl(valueEnum, call, hidden, index,
        keyPath, keyPathChars, originalIndex, hiddenCount, probeStatus);

    const bool exhausted = ok && IsNoMoreEntries(probeStatus);
    const RemapResult verdict = ClassifyRemap(ok, hiddenCount, originalIndex, index, exhausted);

    if (verdict == RemapResult::Mapped) {
        InterlockedIncrement(&g_hiddenCalls);
        return valueEnum
            ? g_origNtEnumerateValueKey(key, originalIndex, infoClass, info, length, resultLength)
            : g_origNtEnumerateKey(key, originalIndex, infoClass, info, length, resultLength);
    }
    if (verdict == RemapResult::Exhausted) {
        InterlockedIncrement(&g_hiddenCalls);
        if (resultLength) *resultLength = 0;
        return kStatusNoMoreEntries;
    }

    // 判不出 / 一项都没藏 ⇒ 原样调用（与开关关闭时完全一致）。
    return valueEnum
        ? g_origNtEnumerateValueKey(key, index, infoClass, info, length, resultLength)
        : g_origNtEnumerateKey(key, index, infoClass, info, length, resultLength);
}

static LONG NTAPI NtEnumerateKey_Detour(HANDLE key, ULONG index, ULONG infoClass,
    PVOID info, ULONG length, PULONG resultLength)
{
    return DetourCommon(false, key, index, infoClass, info, length, resultLength);
}

static LONG NTAPI NtEnumerateValueKey_Detour(HANDLE key, ULONG index, ULONG infoClass,
    PVOID info, ULONG length, PULONG resultLength)
{
    return DetourCommon(true, key, index, infoClass, info, length, resultLength);
}

// ------------------------------------------------------------------ 调用助手
static LONG CallKeyEnum(bool viaDetour, HANDLE key, ULONG index, ULONG cls,
    BYTE* buf, ULONG len, ULONG* outLen)
{
    ULONG rl = 0;
    const LONG st = viaDetour
        ? g_targetNtEnumerateKey(key, index, cls, buf, len, &rl)
        : g_origNtEnumerateKey(key, index, cls, buf, len, &rl);
    if (outLen) *outLen = rl;
    return st;
}

static LONG CallValueEnum(bool viaDetour, HANDLE key, ULONG index, ULONG cls,
    BYTE* buf, ULONG len, ULONG* outLen)
{
    ULONG rl = 0;
    const LONG st = viaDetour
        ? g_targetNtEnumerateValueKey(key, index, cls, buf, len, &rl)
        : g_origNtEnumerateValueKey(key, index, cls, buf, len, &rl);
    if (outLen) *outLen = rl;
    return st;
}

// 把一次枚举结果的**项名**取出来（class 0）。
//   返回 false 表示"没有名字"（值的默认项）—— 那是**合法**情况。
static bool EntryName(bool valueEnum, const BYTE* buf, ULONG bufferLength, ULONG rl,
    wchar_t* out, ULONG cap)
{
    NameRegion region = {};
    if (ProbeBasicName(valueEnum, buf, bufferLength, rl, region) != NameProbe::Parsed) {
        out[0] = L'\0';
        return false;
    }
    ULONG chars = region.length / sizeof(wchar_t);
    if (chars >= cap) chars = cap - 1;
    memcpy(out, buf + region.offset, chars * sizeof(wchar_t));
    out[chars] = L'\0';
    return true;
}

// 枚举一整个列表，把每项名字收集到 out（out[0] 用 "(默认)" 表示空名）。
static ULONG CollectNames(bool valueEnum, bool viaDetour, HANDLE key,
    wchar_t out[][64], ULONG maxCount)
{
    ULONG count = 0;
    for (ULONG i = 0; count < maxCount; ++i) {
        static BYTE buf[4096];
        ZeroMemory(buf, sizeof(buf));
        ULONG rl = 0;
        const LONG st = valueEnum
            ? CallValueEnum(viaDetour, key, i, 0, buf, sizeof(buf), &rl)
            : CallKeyEnum(viaDetour, key, i, 0, buf, sizeof(buf), &rl);
        if (IsNoMoreEntries(st)) break;
        if (st < 0) break;

        wchar_t name[64] = {};
        if (!EntryName(valueEnum, buf, sizeof(buf), rl, name, 64)) {
            wcscpy_s(name, L"(默认)");
        }
        wcsncpy_s(out[count], 64, name, _TRUNCATE);
        count++;
    }
    return count;
}

static bool NameAt(const wchar_t names[][64], ULONG count, ULONG index, const wchar_t* expect)
{
    return index < count && _wcsicmp(names[index], expect) == 0;
}

// ------------------------------------------------------------------ 临时键树
static const wchar_t* kRootRel = L"Software\\R3ShieldCoreProbe";
static const wchar_t* kEnumRel = L"Software\\R3ShieldCoreProbe\\RegEnum";

static HKEY g_rootKey = nullptr;
static HKEY g_enumKey = nullptr;

static bool CreateProbeTree()
{
    LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, kRootRel, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &g_rootKey, nullptr);
    if (st != ERROR_SUCCESS) return false;

    st = RegCreateKeyExW(HKEY_CURRENT_USER, kEnumRel, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &g_enumKey, nullptr);
    if (st != ERROR_SUCCESS) return false;

    // 子键：Alpha / Beta / SecretA* / SecretB* / Zulu
    //   ★ 排序后是 [Alpha, Beta, SecretA, SecretB, Zulu] ⇒ 隐藏的两个
    //     **夹在中间**，这样才测得到"索引整体前移"，而不只是"尾巴被砍"。
    const wchar_t* subkeys[] = { L"Alpha", L"Beta", L"SecretA", L"SecretB", L"Zulu" };
    for (const wchar_t* name : subkeys) {
        HKEY sub = nullptr;
        if (RegCreateKeyExW(g_enumKey, name, 0, nullptr, REG_OPTION_NON_VOLATILE,
                KEY_ALL_ACCESS, nullptr, &sub, nullptr) != ERROR_SUCCESS) {
            return false;
        }
        RegCloseKey(sub);
    }

    // 值：默认值（**空名**）+ AlphaV / BetaV / SecretV1* / SecretV2* / ZuluV
    //   ★ 默认值那一项是必须的：它名字为空，是"空名不能中止扫描"这条的载体。
    struct Value { const wchar_t* name; const wchar_t* data; };
    const Value values[] = {
        { L"",         L"DefaultData" },
        { L"AlphaV",   L"alpha-data" },
        { L"BetaV",    L"beta-data" },
        { L"SecretV1", L"secret-one" },
        { L"SecretV2", L"secret-two" },
        { L"ZuluV",    L"zulu-data" },
    };
    for (const Value& v : values) {
        const DWORD bytes = static_cast<DWORD>((wcslen(v.data) + 1) * sizeof(wchar_t));
        if (RegSetValueExW(g_enumKey, v.name, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(v.data), bytes) != ERROR_SUCCESS) {
            return false;
        }
    }
    return true;
}

static void DeleteProbeTree()
{
    if (g_enumKey) { RegCloseKey(g_enumKey); g_enumKey = nullptr; }
    if (g_rootKey) { RegCloseKey(g_rootKey); g_rootKey = nullptr; }
    RegDeleteTreeW(HKEY_CURRENT_USER, kRootRel);
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreProbe");
}

// ------------------------------------------------------------------ 主流程
int main()
{
    // ★ 必须设 locale，否则 `printf("%ls", ...)` 在 "C" locale 下**转不出中文**：
    //   宽字符到多字节的转换会失败 ⇒ 输出只剩半截（实测："(默认)" 只打出 "("）。
    //   判据本身不受影响（走 `_wcsicmp`），但**人看的输出**会缺字。
    setlocale(LC_ALL, ".936");

    printf("=== 注册表枚举隐藏 机制探针（自挂自测，不经过引擎）===\n\n");

    g_targetNtEnumerateKey = reinterpret_cast<NtEnumerateKey_t>(ProcOf(L"ntdll.dll", "NtEnumerateKey"));
    g_targetNtEnumerateValueKey = reinterpret_cast<NtEnumerateValueKey_t>(ProcOf(L"ntdll.dll", "NtEnumerateValueKey"));
    g_origNtQueryKey = reinterpret_cast<NtQueryKey_t>(ProcOf(L"ntdll.dll", "NtQueryKey"));

    if (!g_targetNtEnumerateKey || !g_targetNtEnumerateValueKey || !g_origNtQueryKey) {
        printf("[FATAL] 找不到 ntdll 的 NtEnumerateKey / NtEnumerateValueKey / NtQueryKey\n");
        return 2;
    }

    if (MH_Initialize() != MH_OK) {
        printf("[FATAL] MH_Initialize 失败\n");
        return 2;
    }
    if (MH_CreateHook(reinterpret_cast<LPVOID>(g_targetNtEnumerateKey),
            reinterpret_cast<LPVOID>(NtEnumerateKey_Detour),
            reinterpret_cast<LPVOID*>(&g_origNtEnumerateKey)) != MH_OK
        || MH_EnableHook(reinterpret_cast<LPVOID>(g_targetNtEnumerateKey)) != MH_OK) {
        printf("[FATAL] 挂钩 ntdll!NtEnumerateKey 失败\n");
        return 2;
    }
    if (MH_CreateHook(reinterpret_cast<LPVOID>(g_targetNtEnumerateValueKey),
            reinterpret_cast<LPVOID>(NtEnumerateValueKey_Detour),
            reinterpret_cast<LPVOID*>(&g_origNtEnumerateValueKey)) != MH_OK
        || MH_EnableHook(reinterpret_cast<LPVOID>(g_targetNtEnumerateValueKey)) != MH_OK) {
        printf("[FATAL] 挂钩 ntdll!NtEnumerateValueKey 失败\n");
        return 2;
    }
    printf("已挂钩 ntdll!NtEnumerateKey / NtEnumerateValueKey（本进程内）。\n\n");

    if (!CreateProbeTree()) {
        printf("[FATAL] 创建临时测试键树失败（HKCU\\%ls）\n", kEnumRel);
        return 2;
    }

    // 受保护前缀 = 被枚举键的原始路径 + "\Secret"
    {
        wchar_t enumPath[512] = {};
        const ULONG chars = ResolveKeyPath(g_enumKey, enumPath, 512);
        if (chars == 0 || chars + 8 >= 512) {
            printf("[FATAL] 还原被枚举键路径失败\n");
            return 2;
        }
        memcpy(g_hiddenPrefix, enumPath, chars * sizeof(wchar_t));
        memcpy(g_hiddenPrefix + chars, L"\\Secret", 8 * sizeof(wchar_t));
        g_hiddenPrefixChars = chars + 7;
        printf("受保护前缀（原始形式）= %ls\n\n", g_hiddenPrefix);
    }

    // ---------- 0. 布局勘察 ----------
    printf("--- 0. 布局勘察：class 0 的原始头（★ 实测，不靠记忆）---\n");
    {
        static BYTE kbuf[256];
        ULONG krl = 0;
        ZeroMemory(kbuf, sizeof(kbuf));
        const LONG kst = CallKeyEnum(false, g_enumKey, 0, 0, kbuf, sizeof(kbuf), &krl);
        printf("  NtEnumerateKey      : status=0x%08lX ResultLength=%u dwords:",
            static_cast<unsigned long>(kst), krl);
        for (int i = 0; i < 6; ++i) {
            ULONG v = 0; memcpy(&v, kbuf + i * 4, 4);
            printf(" [+%d]=0x%08lX", i * 4, static_cast<unsigned long>(v));
        }
        printf("\n");

        static BYTE vbuf[256];
        ULONG vrl = 0;
        ZeroMemory(vbuf, sizeof(vbuf));
        const LONG vst = CallValueEnum(false, g_enumKey, 0, 0, vbuf, sizeof(vbuf), &vrl);
        printf("  NtEnumerateValueKey : status=0x%08lX ResultLength=%u dwords:",
            static_cast<unsigned long>(vst), vrl);
        for (int i = 0; i < 6; ++i) {
            ULONG v = 0; memcpy(&v, vbuf + i * 4, 4);
            printf(" [+%d]=0x%08lX", i * 4, static_cast<unsigned long>(v));
        }
        printf("\n");

        // KEY_BASIC_INFORMATION：头 16 字节（LastWriteTime 8 + TitleIndex 4 + NameLength 4）
        // 第一项是 "Alpha"（10 字节）⇒ ResultLength == 16 + 10 == 26
        Check("布局：KEY_BASIC_INFORMATION 头 == 16 字节（ResultLength - NameLength）",
            kst >= 0 && krl == 16 + ReadU32(kbuf, kKeyBasicNameLengthOffset));
        Check("布局：KEY_BASIC_INFORMATION 的 NameLength 在 +12",
            ReadU32(kbuf, kKeyBasicNameLengthOffset) == 5 * sizeof(wchar_t));
        Check("布局：KEY_BASIC_INFORMATION 的 Name 在 +16（内容是 \"Alpha\"）",
            memcmp(kbuf + kKeyBasicNameOffset, L"Alpha", 5 * sizeof(wchar_t)) == 0);

        // ★ 值的**索引 0 是"(默认)"项**（名字长度 0）—— 这是实测事实，钉成判据。
        Check("★ 实测：值枚举的索引 0 是名字为空的默认项（NameLength == 0）",
            vst >= 0 && ReadU32(vbuf, kValueBasicNameLengthOffset) == 0);

        // KEY_VALUE_BASIC_INFORMATION：头 12 字节（TitleIndex 4 + Type 4 + NameLength 4）
        static BYTE vbuf1[256];
        ULONG vrl1 = 0;
        ZeroMemory(vbuf1, sizeof(vbuf1));
        const LONG vst1 = CallValueEnum(false, g_enumKey, 1, 0, vbuf1, sizeof(vbuf1), &vrl1);
        Check("布局：KEY_VALUE_BASIC_INFORMATION 头 == 12 字节",
            vst1 >= 0 && vrl1 == 12 + ReadU32(vbuf1, kValueBasicNameLengthOffset));
        Check("布局：KEY_VALUE_BASIC_INFORMATION 的 NameLength 在 +8",
            ReadU32(vbuf1, kValueBasicNameLengthOffset) == 6 * sizeof(wchar_t));
        Check("布局：KEY_VALUE_BASIC_INFORMATION 的 Name 在 +12（内容是 \"AlphaV\"）",
            memcmp(vbuf1 + kValueBasicNameOffset, L"AlphaV", 6 * sizeof(wchar_t)) == 0);
    }

    // ---------- A. 基线（负对照：隐藏关）----------
    printf("\n--- A. 基线（负对照）：隐藏**关** ---\n");
    wchar_t baseKeys[16][64] = {};
    wchar_t baseValues[16][64] = {};
    ULONG baseKeyCount = 0;
    ULONG baseValueCount = 0;
    {
        baseKeyCount = CollectNames(false, true, g_enumKey, baseKeys, 16);
        baseValueCount = CollectNames(true, true, g_enumKey, baseValues, 16);

        printf("  子键：");
        for (ULONG i = 0; i < baseKeyCount; ++i) printf("%ls ", baseKeys[i]);
        printf("\n  值  ：");
        for (ULONG i = 0; i < baseValueCount; ++i) printf("%ls ", baseValues[i]);
        printf("\n");

        Check("隐藏关：枚举到 5 个子键", baseKeyCount == 5);
        Check("隐藏关：子键顺序为 Alpha/Beta/SecretA/SecretB/Zulu",
            NameAt(baseKeys, baseKeyCount, 0, L"Alpha")
            && NameAt(baseKeys, baseKeyCount, 1, L"Beta")
            && NameAt(baseKeys, baseKeyCount, 2, L"SecretA")
            && NameAt(baseKeys, baseKeyCount, 3, L"SecretB")
            && NameAt(baseKeys, baseKeyCount, 4, L"Zulu"));

        Check("隐藏关：枚举到 6 个值（含空名默认项）", baseValueCount == 6);
        Check("隐藏关：值索引 0 是空名默认项",
            NameAt(baseValues, baseValueCount, 0, L"(默认)"));

        Check("隐藏关：一次都没发生隐藏（计数为 0）",
            InterlockedCompareExchange(&g_hiddenCalls, 0, 0) == 0);
    }

    // ---------- B/C/D. 打开隐藏 ----------
    printf("\n--- B/C/D. 打开隐藏：子键列表变短、无重复、越界语义正确 ---\n");
    InterlockedExchange(&g_hideOn, 1);
    {
        wchar_t names[16][64] = {};
        const ULONG count = CollectNames(false, true, g_enumKey, names, 16);

        printf("  子键：");
        for (ULONG i = 0; i < count; ++i) printf("%ls ", names[i]);
        printf("\n");

        Check("★ 隐藏开：子键只剩 3 个（SecretA / SecretB 被藏）", count == 3);
        Check("★ 隐藏开：剩下的是 Alpha / Beta / Zulu（顺序不变）",
            NameAt(names, count, 0, L"Alpha")
            && NameAt(names, count, 1, L"Beta")
            && NameAt(names, count, 2, L"Zulu"));

        // ★ 无重复：三个名字两两不同
        bool distinct = true;
        for (ULONG i = 0; i < count && distinct; ++i) {
            for (ULONG j = i + 1; j < count; ++j) {
                if (_wcsicmp(names[i], names[j]) == 0) { distinct = false; break; }
            }
        }
        Check("★ 无重复（「命中就往后挪一格」的错法会在这里变红）", distinct);
    }

    // 越界：索引 3 在隐藏关时是 SecretB，隐藏开时必须 NO_MORE_ENTRIES。
    {
        static BYTE buf[4096];
        ULONG rl = 12345;
        ZeroMemory(buf, sizeof(buf));
        const LONG st = CallKeyEnum(true, g_enumKey, 3, 0, buf, sizeof(buf), &rl);
        Check("★ 越界：索引 3 返回 STATUS_NO_MORE_ENTRIES",
            st == kStatusNoMoreEntries);
        Check("★ 越界：*ResultLength 被置 0", rl == 0);

        // 负对照：同一个索引在隐藏关时是**真实的第 4 项**
        ULONG rl2 = 0;
        ZeroMemory(buf, sizeof(buf));
        const LONG st2 = CallKeyEnum(false, g_enumKey, 3, 0, buf, sizeof(buf), &rl2);
        wchar_t name[64] = {};
        Check("★ 负对照：隐藏关时同一索引确实是 SecretB（证明少了两项不是错觉）",
            st2 >= 0 && EntryName(false, buf, sizeof(buf), rl2, name, 64) && wcscmp(name, L"SecretB") == 0);
    }

    // ---------- C2. 长度字段与内容都没被我们自己改 ----------
    printf("\n--- C2. 隐藏开时拿到的项 == 直接按原始索引真调的项（逐字节）---\n");
    {
        // 可见索引 -> 原始索引：0->0, 1->1, 2->4
        const ULONG map[3][2] = { {0, 0}, {1, 1}, {2, 4} };
        bool allSame = true;
        for (const auto& m : map) {
            static BYTE hiddenBuf[4096];
            static BYTE realBuf[4096];
            ULONG hiddenLen = 0, realLen = 0;
            ZeroMemory(hiddenBuf, sizeof(hiddenBuf));
            ZeroMemory(realBuf, sizeof(realBuf));

            const LONG sh = CallKeyEnum(true, g_enumKey, m[0], 0, hiddenBuf, sizeof(hiddenBuf), &hiddenLen);
            const LONG sr = CallKeyEnum(false, g_enumKey, m[1], 0, realBuf, sizeof(realBuf), &realLen);

            if (sh < 0 || sr < 0 || hiddenLen != realLen
                || memcmp(hiddenBuf, realBuf, hiddenLen) != 0) {
                allSame = false;
                printf("         索引 %u -> 原始 %u：len %u vs %u\n", m[0], m[1], hiddenLen, realLen);
            }
        }
        Check("★ 可见索引拿到的项与直接真调原始索引逐字节相同（长度字段没被改）", allSame);
    }

    // ---------- E. 值枚举（默认值不能让整条路失效）----------
    printf("\n--- E. 值枚举：空名默认项**不能**让隐藏失效 ---\n");
    {
        wchar_t names[16][64] = {};
        const ULONG count = CollectNames(true, true, g_enumKey, names, 16);

        printf("  值  ：");
        for (ULONG i = 0; i < count; ++i) printf("%ls ", names[i]);
        printf("\n");

        Check("★ 隐藏开：值只剩 4 个（SecretV1 / SecretV2 被藏）", count == 4);
        Check("★ 空名默认项仍在索引 0（空名按可见处理，不中止扫描）",
            NameAt(names, count, 0, L"(默认)"));
        Check("★ 默认项之后的可见值映射正确：AlphaV / BetaV / ZuluV",
            NameAt(names, count, 1, L"AlphaV")
            && NameAt(names, count, 2, L"BetaV")
            && NameAt(names, count, 3, L"ZuluV"));

        // 值越界
        static BYTE buf[4096];
        ULONG rl = 12345;
        const LONG st = CallValueEnum(true, g_enumKey, 4, 0, buf, sizeof(buf), &rl);
        Check("★ 值越界：索引 4 -> NO_MORE_ENTRIES + ResultLength=0",
            st == kStatusNoMoreEntries && rl == 0);
    }

    // ---------- F. 缓冲区太小 ----------
    printf("\n--- F. 缓冲区太小：行为不变（BUFFER_OVERFLOW + 所需长度）---\n");
    {
        static BYTE tiny[8];
        ULONG rl = 0;
        ZeroMemory(tiny, sizeof(tiny));
        // 索引 2 在隐藏开时映射到原始索引 4（"Zulu"，10 字节 ⇒ 需要 26）
        const LONG st = CallKeyEnum(true, g_enumKey, 2, 0, tiny, sizeof(tiny), &rl);
        printf("  （status=0x%08lX ResultLength=%u）\n", static_cast<unsigned long>(st), rl);
        // ★ 实测：`NtEnumerateKey` 在缓冲区不够时返回的是
        //   `0xC0000023 STATUS_BUFFER_TOO_SMALL`，**不是** `0x80000005`
        //   `STATUS_BUFFER_OVERFLOW`（后者是别的 API 的口径）。
        //   两者都是**负**的 NTSTATUS（`NT_SUCCESS` 为假）—— 所以
        //   codec 的 `IsNothingWritten` 两个都认（别只写 `status >= 0`）。
        Check("缓冲区太小 -> STATUS_BUFFER_TOO_SMALL（0xC0000023，实测）",
            st == kStatusBufferTooSmall);
        Check("缓冲区太小 -> 该状态被 IsNothingWritten 认作「什么都没写」",
            IsNothingWritten(st));
        Check("缓冲区太小 -> *ResultLength 给出所需长度（16 + 名字字节）",
            rl == 16 + 4 * sizeof(wchar_t));
    }

    // ---------- G. 无关键的负对照 ----------
    printf("\n--- G. 负对照：与保护前缀无关的键 -> 一项都不藏 ---\n");
    {
        wchar_t names[16][64] = {};
        const ULONG count = CollectNames(false, true, g_rootKey, names, 16);
        Check("无关键：隐藏开时列表与隐藏关时完全一致（只看到 RegEnum）",
            count == 1 && NameAt(names, count, 0, L"RegEnum"));

        wchar_t namesOff[16][64] = {};
        const ULONG countOff = CollectNames(false, false, g_rootKey, namesOff, 16);
        Check("无关键：走 detour 与不走 detour 的列表一致",
            count == countOff && NameAt(namesOff, countOff, 0, L"RegEnum"));
    }

    // ---------- H. 真实调用方（advapi32）----------
    printf("\n--- H. 真实调用方：RegEnumKeyExW / RegEnumValueW 也看到短列表 ---\n");
    {
        // RegEnumKeyExW
        ULONG found = 0;
        bool sawSecret = false;
        for (DWORD i = 0; ; ++i) {
            wchar_t name[256] = {};
            DWORD cch = 256;
            const LSTATUS st = RegEnumKeyExW(g_enumKey, i, name, &cch,
                nullptr, nullptr, nullptr, nullptr);
            if (st != ERROR_SUCCESS) break;
            found++;
            if (_wcsicmp(name, L"SecretA") == 0 || _wcsicmp(name, L"SecretB") == 0) {
                sawSecret = true;
            }
        }
        Check("RegEnumKeyExW 只看到 3 个子键", found == 3);
        Check("RegEnumKeyExW 看不到 SecretA / SecretB", !sawSecret);

        // RegEnumValueW
        ULONG values = 0;
        bool sawSecretValue = false;
        for (DWORD i = 0; ; ++i) {
            wchar_t name[256] = {};
            DWORD cch = 256;
            const LSTATUS st = RegEnumValueW(g_enumKey, i, name, &cch,
                nullptr, nullptr, nullptr, nullptr);
            if (st != ERROR_SUCCESS) break;
            values++;
            if (_wcsicmp(name, L"SecretV1") == 0 || _wcsicmp(name, L"SecretV2") == 0) {
                sawSecretValue = true;
            }
        }
        Check("RegEnumValueW 只看到 4 个值（含空名默认项）", values == 4);
        Check("RegEnumValueW 看不到 SecretV1 / SecretV2", !sawSecretValue);
    }

    // ---------- I. 诚实边界：隐藏是"列表级"，不是"访问级" ----------
    printf("\n--- I. 诚实边界：被隐藏的项仍可按名字直接访问（列表级隐藏，不是访问级）---\n");
    {
        HKEY sub = nullptr;
        const LSTATUS st = RegOpenKeyExW(g_enumKey, L"SecretA", 0, KEY_READ, &sub);
        Check("★ 被隐藏的子键仍能被 RegOpenKeyExW 直接打开（如实标注，别吹成硬隐藏）",
            st == ERROR_SUCCESS);
        if (sub) RegCloseKey(sub);

        wchar_t data[64] = {};
        DWORD cb = sizeof(data);
        DWORD type = 0;
        const LSTATUS stv = RegQueryValueExW(g_enumKey, L"SecretV1", nullptr, &type,
            reinterpret_cast<LPBYTE>(data), &cb);
        Check("★ 被隐藏的值仍能被 RegQueryValueExW 直接读到真内容（隐藏只管枚举）",
            stv == ERROR_SUCCESS && wcscmp(data, L"secret-one") == 0);
    }

    // ---------- 计数自检 ----------
    printf("\n--- 计数自检 ---\n");
    {
        const LONG hiddenCalls = InterlockedCompareExchange(&g_hiddenCalls, 0, 0);
        const LONG hits = InterlockedCompareExchange(&g_hits, 0, 0);
        char line[128];
        snprintf(line, sizeof(line), "发生过隐藏（hiddenCalls=%ld）", static_cast<long>(hiddenCalls));
        Check(line, hiddenCalls > 0);
        snprintf(line, sizeof(line), "detour 命中次数 >= 隐藏次数（hits=%ld >= %ld）",
            static_cast<long>(hits), static_cast<long>(hiddenCalls));
        Check(line, hits >= hiddenCalls);
    }

    // ---------- 收尾 ----------
    MH_DisableHook(reinterpret_cast<LPVOID>(g_targetNtEnumerateKey));
    MH_DisableHook(reinterpret_cast<LPVOID>(g_targetNtEnumerateValueKey));
    MH_Uninitialize();
    DeleteProbeTree();

    printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
