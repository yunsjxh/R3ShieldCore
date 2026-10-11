//
// spoof_reg_probe.cpp —— 实证：注册表「值替换」（拦截并替换回传数据）到底行不行。
//
// 这是《回传数据替换Hook-技术预研》§8 Phase 3「注册表读替换」第一个子项
// （**值替换**，`NtQueryValueKey`）的机制探针。它**不经过引擎**、
// **不需要注入器**，在一个进程里自己挂自己的 hook，回答六个问题：
//
//   A. 基线（负对照）：不替换时，`NtQueryValueKey` 拿到的是真值吗？
//      —— 没有这一条，后面"变成了全 0"无法归因（铁律 110：空真）。
//   B. 替换真的发生了吗？—— 数据区全 0，且**调用返回成功**（status>=0）。
//      这正是 Spoof 与 Block 的分水岭：Block 返回失败，Spoof 返回**成功 + 假数据**。
//   C. ★★ **长度字段一个都没变**（本面特有的坑）：`DataLength`、`DataOffset`、
//      `NameLength`、`*ResultLength`、`Type` 全部与真实调用**逐字节相同**。
//      这是整个设计的命门 —— 只要改了长度，调用方就会读越界或按错偏移解析
//      ⇒ 宿主崩溃。判据做成"**数据区之外的每一个字节都必须相等**"。
//   D. 清零后的值对每种类型都**合法**：REG_SZ → 空串、REG_DWORD → 0、
//      REG_MULTI_SZ → 空列表、REG_BINARY → 全 0。
//   E. 不认识的东西**一律不动**：class 0（Basic，无数据区）不替换；
//      缓冲区短 / 长度回绕 / dataLength==0 ⇒ 定位失败 ⇒ 回落原样返回。
//   F. 对**真实调用方**生效：`RegQueryValueExW`（内部走 `NtQueryValueKey`）
//      也读到空串 —— 证明不是"只有直接调 ntdll 才有效"。
//
// ★★ 关键：清零逻辑**不是抄的** —— 直接 `#include "registry_spoof_codec.h"`，
//    与生产 `registry_guard.cpp` 用的是**同一份**代码（铁律 195 / 127：
//    同一份逻辑拷贝多份必然漂移，且漂了之后探针照样全绿、生产照样出错）。
//
// ⚠️ 本探针只碰**自己进程内自己创建的**注册表键（HKCU 下一个临时键），
//    不注入任何进程、不读屏幕、不写系统位置。因此**不受**
//    「本机禁止运行引擎」那条约束（铁律 175）。
//    结束时会把临时键删掉。
//
// 编译：bash build_spoof_reg_probe.sh
// 运行：./tools/spoof_reg_probe.exe
//
#include <windows.h>
#include <stdio.h>
#include <MinHook.h>

#include "registry_spoof_codec.h"   // ← 生产同款（不抄）

using namespace R3ShieldCoreRegistrySpoof;

// ------------------------------------------------------------------ 状态
static int g_pass = 0;
static int g_fail = 0;

// ⚠️ 自己定义 UNICODE_STRING，**不 include winternl.h**：那套定义随 SDK 版本漂，
//    而且与本项目生产代码（`RG_UNICODE_STRING`）的口径不一致。这里只用到三个字段。
struct ProbeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

typedef LONG(NTAPI* NtQueryValueKey_t)(HANDLE, ProbeUnicodeString*, ULONG, PVOID, ULONG, PULONG);

static NtQueryValueKey_t g_targetNtQueryValueKey = nullptr; // 被 patch 的入口（调用它 ⇒ 走 detour）
static NtQueryValueKey_t g_origNtQueryValueKey = nullptr;   // trampoline（调用它 ⇒ 真值）

static volatile LONG g_spoofOn = 0;      // 1 = detour 允许替换
static volatile LONG g_hits = 0;         // detour 进入次数
static volatile LONG g_spoofedCount = 0; // 真的清零成功的次数

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ detour
//
// 与生产 registry_guard.cpp 的 NtQueryValueKey_Hook **同构**：
// 先真调原函数（真值、真副作用），再在成功时定位数据区并清零。
// 唯一差别：生产里"要不要替换"由 Policy 判定，这里由一个开关控制
// （为了做"同一调用路径、只翻一个开关"的负对照）。
static LONG NTAPI NtQueryValueKey_Detour(HANDLE key, ProbeUnicodeString* name, ULONG cls,
    PVOID info, ULONG len, PULONG resultLen)
{
    InterlockedIncrement(&g_hits);

    const LONG status = g_origNtQueryValueKey(key, name, cls, info, len, resultLen);

    if (g_spoofOn == 0 || status < 0 || !info || !resultLen) {
        return status;
    }

    const ULONG resultLength = *resultLen;
    DataRegion region = {};
    if (LocateDataRegion(cls, info, len, resultLength, region)
        && ZeroDataRegion(info, len, region)) {
        InterlockedIncrement(&g_spoofedCount);
    }
    return status;
}

// ------------------------------------------------------------------ 工具
static LPVOID ProcOf(LPCWSTR module, LPCSTR name)
{
    HMODULE m = GetModuleHandleW(module);
    if (!m) return nullptr;
    return reinterpret_cast<LPVOID>(GetProcAddress(m, name));
}

// 调一次 NtQueryValueKey（走 detour 那条路 —— 也就是真实调用方的路）。
static LONG QueryVia(HKEY h, const wchar_t* valueName, ULONG cls,
    BYTE* buf, ULONG bufLen, ULONG* outLen)
{
    ProbeUnicodeString us = {};
    const size_t chars = wcslen(valueName);
    us.Buffer = const_cast<PWSTR>(valueName);
    us.Length = static_cast<USHORT>(chars * sizeof(WCHAR));
    us.MaximumLength = static_cast<USHORT>(us.Length + sizeof(WCHAR));

    ULONG rl = 0;
    const LONG st = g_targetNtQueryValueKey(h, &us, cls, buf, bufLen, &rl);
    if (outLen) *outLen = rl;
    return st;
}

// 调一次**真值**（绕过 detour，用 trampoline）—— 用来拿"替换前"的对照。
static LONG QueryReal(HKEY h, const wchar_t* valueName, ULONG cls,
    BYTE* buf, ULONG bufLen, ULONG* outLen)
{
    ProbeUnicodeString us = {};
    const size_t chars = wcslen(valueName);
    us.Buffer = const_cast<PWSTR>(valueName);
    us.Length = static_cast<USHORT>(chars * sizeof(WCHAR));
    us.MaximumLength = static_cast<USHORT>(us.Length + sizeof(WCHAR));

    ULONG rl = 0;
    const LONG st = g_origNtQueryValueKey(h, &us, cls, buf, bufLen, &rl);
    if (outLen) *outLen = rl;
    return st;
}

// 数据区**之外**的每个字节都必须相等（＝长度字段/偏移/名字全没动）。
static bool BytesEqualOutsideRegion(const BYTE* a, const BYTE* b, ULONG len, const DataRegion& r)
{
    for (ULONG i = 0; i < len; ++i) {
        if (i >= r.offset && i < r.offset + r.length) continue;
        if (a[i] != b[i]) return false;
    }
    return true;
}

static bool RegionAllZero(const BYTE* buf, const DataRegion& r)
{
    for (ULONG i = 0; i < r.length; ++i) {
        if (buf[r.offset + i] != 0) return false;
    }
    return true;
}

static bool RegionHasNonZero(const BYTE* buf, const DataRegion& r)
{
    for (ULONG i = 0; i < r.length; ++i) {
        if (buf[r.offset + i] != 0) return true;
    }
    return false;
}

// ------------------------------------------------------------------ 临时键
static const wchar_t* kProbeKeyRel = L"Software\\R3ShieldCoreProbe\\RegSpoof";

static HKEY CreateProbeKey()
{
    HKEY h = nullptr;
    LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, kProbeKeyRel, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &h, nullptr);
    if (st != ERROR_SUCCESS) return nullptr;

    const wchar_t* text = L"Secret123";
    RegSetValueExW(h, L"Text", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(text),
        static_cast<DWORD>((wcslen(text) + 1) * sizeof(WCHAR)));

    DWORD dw = 0x11223344;
    RegSetValueExW(h, L"Dword", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&dw), sizeof(dw));

    const wchar_t multi[] = L"alpha\0beta\0";
    RegSetValueExW(h, L"Multi", 0, REG_MULTI_SZ,
        reinterpret_cast<const BYTE*>(multi),
        static_cast<DWORD>(sizeof(multi)));

    const BYTE bin[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    RegSetValueExW(h, L"Bin", 0, REG_BINARY, bin, sizeof(bin));

    ULONGLONG qw = 0x1122334455667788ULL;
    RegSetValueExW(h, L"Qword", 0, REG_QWORD,
        reinterpret_cast<const BYTE*>(&qw), sizeof(qw));

    return h;
}

static void DeleteProbeKey()
{
    RegDeleteTreeW(HKEY_CURRENT_USER, kProbeKeyRel);
    // 连父键一起清掉（尽力而为）。
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreProbe");
}

// ------------------------------------------------------------------ 逐类型验证
//
// 对某个值：先取"真值"快照，再取"替换后"快照，然后断言
//   ① 真值数据区里**确实有非 0 内容**（否则这条测试是空真）
//   ② 替换后数据区**全 0**
//   ③ 数据区**之外逐字节相同**（长度字段一个都没变）
//   ④ 两次的 *ResultLength 相同
static void TestValueType(HKEY h, const wchar_t* valueName, const char* label)
{
    static BYTE realBuf[2048];
    static BYTE spoofBuf[2048];
    ZeroMemory(realBuf, sizeof(realBuf));
    ZeroMemory(spoofBuf, sizeof(spoofBuf));

    const ULONG cls = 2;   // KeyValuePartialInformation

    ULONG realLen = 0, spoofLen = 0;
    const LONG stReal = QueryReal(h, valueName, cls, realBuf, sizeof(realBuf), &realLen);
    const LONG stSpoof = QueryVia(h, valueName, cls, spoofBuf, sizeof(spoofBuf), &spoofLen);

    DataRegion region = {};
    const bool located = LocateDataRegion(cls, realBuf, sizeof(realBuf), realLen, region);

    char name[160];

    snprintf(name, sizeof(name), "%s：真实调用成功且定位到数据区", label);
    Check(name, stReal >= 0 && located);

    if (!located) return;

    snprintf(name, sizeof(name), "%s：真实数据区里确实有非 0 内容（非空真）", label);
    Check(name, RegionHasNonZero(realBuf, region));

    snprintf(name, sizeof(name), "%s：替换后数据区**全 0**", label);
    Check(name, stSpoof >= 0 && RegionAllZero(spoofBuf, region));

    snprintf(name, sizeof(name), "%s：数据区**之外逐字节相同**（长度/偏移/名字全没动）", label);
    Check(name, BytesEqualOutsideRegion(realBuf, spoofBuf, realLen, region));

    snprintf(name, sizeof(name), "%s：*ResultLength 不变", label);
    Check(name, realLen == spoofLen);

    printf("         （类型=%s 数据长度=%u 数据偏移=%u）\n",
        RegTypeName(ReadU32(realBuf, 4)), region.length, region.offset);
}

// ------------------------------------------------------------------ 主流程
int main()
{
    printf("=== 注册表值替换 机制探针（自挂自测，不经过引擎）===\n\n");

    g_targetNtQueryValueKey = reinterpret_cast<NtQueryValueKey_t>(
        ProcOf(L"ntdll.dll", "NtQueryValueKey"));
    if (!g_targetNtQueryValueKey) {
        printf("[FATAL] 找不到 ntdll!NtQueryValueKey\n");
        return 2;
    }

    if (MH_Initialize() != MH_OK) {
        printf("[FATAL] MH_Initialize 失败\n");
        return 2;
    }
    if (MH_CreateHook(reinterpret_cast<LPVOID>(g_targetNtQueryValueKey),
        reinterpret_cast<LPVOID>(NtQueryValueKey_Detour),
        reinterpret_cast<LPVOID*>(&g_origNtQueryValueKey)) != MH_OK
        || MH_EnableHook(reinterpret_cast<LPVOID>(g_targetNtQueryValueKey)) != MH_OK) {
        printf("[FATAL] 挂钩 ntdll!NtQueryValueKey 失败\n");
        return 2;
    }
    printf("已挂钩 ntdll!NtQueryValueKey（本进程内）。\n\n");

    HKEY h = CreateProbeKey();
    if (!h) {
        printf("[FATAL] 创建临时测试键失败（HKCU\\%ls）\n", kProbeKeyRel);
        return 2;
    }

    // ---------- 0. 布局勘察（★ 把"实测布局"变成判据）----------
    //
    // 为什么必须有这一节：`KEY_VALUE_*_INFORMATION` 的**头长度与字段偏移**
    // 只能实测，不能靠记忆。曾经把 class 4（PartialAlign64）当成"同 class 2
    // 的 12 字节头"，实际它是 **8 字节头、且没有 TitleIndex** ⇒ 偏移全错。
    // 那次是靠"长度字段自洽"校验兜住的（定位失败 ⇒ 不替换），否则会
    // **零掉错误的位置**（Type/DataLength 被清零 ⇒ 调用方解析出乱码）。
    //
    // 把实测事实钉成断言后，将来 Windows 改了布局，这里是**红**，
    // 而不是"悄悄改坏"（铁律 137：验收矩阵要覆盖到会变的东西）。
    printf("--- 0. 布局勘察：class 0~4 的原始头（值 Text=\"Secret123\"，数据 20 字节）---\n");
    {
        static BYTE b0[256], b1[256], b2[256], b3[256], b4[256];
        BYTE* bufs[5] = { b0, b1, b2, b3, b4 };
        ULONG rls[5] = { 0, 0, 0, 0, 0 };
        LONG sts[5] = { 0, 0, 0, 0, 0 };

        for (ULONG cls = 0; cls <= 4; ++cls) {
            ZeroMemory(bufs[cls], 256);
            sts[cls] = QueryReal(h, L"Text", cls, bufs[cls], 256, &rls[cls]);
            printf("  class=%u status=0x%08lX ResultLength=%u  dwords:",
                cls, static_cast<unsigned long>(sts[cls]), rls[cls]);
            for (int i = 0; i < 5; ++i) {
                ULONG v = 0; memcpy(&v, bufs[cls] + i * 4, 4);
                printf(" [+%d]=0x%08lX", i * 4, static_cast<unsigned long>(v));
            }
            printf("\n");
        }

        // —— 由实测反推的判据 ——
        // class 0：无数据区，ResultLength == 12 + 名字字节数（名字 "Text" = 8）
        Check("布局：class 0 无数据区（ResultLength == 12 + 名字字节）",
            sts[0] >= 0 && rls[0] == 12 + 8);

        // class 2：头 12；Type 在 +4
        {
            const ULONG dataLen = ReadU32(b2, 8);
            Check("布局：class 2 头 == 12 字节（ResultLength - DataLength）",
                sts[2] >= 0 && rls[2] == 12 + dataLen);
            Check("布局：class 2 的 Type 在 +4", ReadU32(b2, 4) == REG_SZ);
        }

        // class 4：头 **8**；Type 在 +0（**没有 TitleIndex**）
        {
            const ULONG dataLen = ReadU32(b4, 4);
            Check("布局：class 4 头 == **8** 字节（不是 12！）",
                sts[4] >= 0 && rls[4] == 8 + dataLen);
            // ⚠️ 这里用 ASCII `->` 而**不是** `⇒`：这是**窄字面量**，CP936 编不出
            //   U+21D2 ⇒ MSVC 报 C4566 并**静默丢掉那个字符**（注释里的 `⇒` 不受
            //   影响，闸门只查窄字面量）。见 tools/check_source_gbk.py。
            Check("布局：class 4 的 Type 在 +0（-> **没有 TitleIndex**）",
                ReadU32(b4, 0) == REG_SZ);
        }

        // class 1 / 3：头 20；DataOffset@8、DataLength@12、NameLength@16
        {
            const ULONG off1 = ReadU32(b1, 8);
            const ULONG len1 = ReadU32(b1, 12);
            Check("布局：class 1 的 DataOffset 在 +8、DataLength 在 +12，且 DataOffset+DataLength == ResultLength",
                sts[1] >= 0 && off1 >= 20 && off1 + len1 == rls[1]);
            Check("布局：class 3 与 class 1 **逐字节相同**（含 TitleIndex）",
                sts[3] >= 0 && rls[3] == rls[1] && memcmp(b3, b1, rls[1]) == 0);
        }
    }

    // ---------- A. 基线负对照：替换关着时拿到真值 ----------
    printf("--- A. 基线（负对照）：替换**关** ---\n");
    {
        static BYTE buf[2048];
        ZeroMemory(buf, sizeof(buf));
        ULONG rl = 0;
        const LONG st = QueryVia(h, L"Text", 2, buf, sizeof(buf), &rl);
        DataRegion region = {};
        const bool located = LocateDataRegion(2, buf, sizeof(buf), rl, region);
        Check("替换关时调用成功", st >= 0);
        Check("替换关时拿到真值（数据区非 0）", located && RegionHasNonZero(buf, region));
        Check("替换关时计数为 0（没发生替换）", InterlockedCompareExchange(&g_spoofedCount, 0, 0) == 0);
    }

    // ---------- B/C/D. 打开替换，逐类型验证 ----------
    printf("\n--- B/C/D. 打开替换，逐类型验证（Partial class=2）---\n");
    InterlockedExchange(&g_spoofOn, 1);
    TestValueType(h, L"Text",  "REG_SZ");
    TestValueType(h, L"Dword", "REG_DWORD");
    TestValueType(h, L"Multi", "REG_MULTI_SZ");
    TestValueType(h, L"Bin",   "REG_BINARY");
    TestValueType(h, L"Qword", "REG_QWORD");

    // ---------- 归零后的值确实"合法且空" ----------
    printf("\n--- D2. 归零后的值语义（真实调用方视角）---\n");
    {
        static BYTE buf[2048];
        ZeroMemory(buf, sizeof(buf));
        ULONG rl = 0;
        QueryVia(h, L"Text", 2, buf, sizeof(buf), &rl);
        DataRegion region = {};
        if (LocateDataRegion(2, buf, sizeof(buf), rl, region)) {
            // REG_SZ 归零 ⇒ 首个 WCHAR 为 0 ⇒ 空串。
            const wchar_t* s = reinterpret_cast<const wchar_t*>(buf + region.offset);
            Check("REG_SZ 归零后是空串（首 WCHAR == 0）", s[0] == L'\0');
        }
        else {
            Check("REG_SZ 归零后是空串（首 WCHAR == 0）", false);
        }

        ZeroMemory(buf, sizeof(buf));
        QueryVia(h, L"Dword", 2, buf, sizeof(buf), &rl);
        if (LocateDataRegion(2, buf, sizeof(buf), rl, region)) {
            DWORD v = 0;
            memcpy(&v, buf + region.offset, sizeof(v));
            Check("REG_DWORD 归零后是 0", v == 0);
        }
        else {
            Check("REG_DWORD 归零后是 0", false);
        }

        ZeroMemory(buf, sizeof(buf));
        QueryVia(h, L"Multi", 2, buf, sizeof(buf), &rl);
        if (LocateDataRegion(2, buf, sizeof(buf), rl, region)) {
            const wchar_t* s = reinterpret_cast<const wchar_t*>(buf + region.offset);
            Check("REG_MULTI_SZ 归零后是空列表（首 WCHAR == 0）", s[0] == L'\0');
        }
        else {
            Check("REG_MULTI_SZ 归零后是空列表（首 WCHAR == 0）", false);
        }
    }

    // ---------- C2. Full 类（class 1 / 3）同样只动数据区 ----------
    printf("\n--- C2. Full 类（class=1）与 Align64（class=3/4）---\n");
    {
        const ULONG classes[3] = { 1, 3, 4 };
        const char* names[3] = { "class=1 Full", "class=3 FullAlign64", "class=4 PartialAlign64" };
        for (int i = 0; i < 3; ++i) {
            static BYTE realBuf[2048];
            static BYTE spoofBuf[2048];
            ZeroMemory(realBuf, sizeof(realBuf));
            ZeroMemory(spoofBuf, sizeof(spoofBuf));

            ULONG realLen = 0, spoofLen = 0;
            const LONG stReal = QueryReal(h, L"Text", classes[i], realBuf, sizeof(realBuf), &realLen);
            const LONG stSpoof = QueryVia(h, L"Text", classes[i], spoofBuf, sizeof(spoofBuf), &spoofLen);

            DataRegion region = {};
            const bool located = LocateDataRegion(classes[i], realBuf, sizeof(realBuf), realLen, region);

            // 诊断：把状态码与长度打出来 —— 失败时才知道是"内核不认这个 class"
            // 还是"布局读错了"（铁律 97：别让失败只剩一个 FAIL）。
            printf("         （%s: stReal=0x%08lX realLen=%u located=%d stSpoof=0x%08lX spoofLen=%u）\n",
                names[i], static_cast<unsigned long>(stReal), realLen, located ? 1 : 0,
                static_cast<unsigned long>(stSpoof), spoofLen);

            char nm[160];
            snprintf(nm, sizeof(nm), "%s：定位到数据区且替换后全 0", names[i]);
            Check(nm, stReal >= 0 && located && stSpoof >= 0 && RegionAllZero(spoofBuf, region));

            snprintf(nm, sizeof(nm), "%s：数据区之外逐字节相同（含 DataOffset/NameLength）", names[i]);
            Check(nm, located && BytesEqualOutsideRegion(realBuf, spoofBuf, realLen, region));

            snprintf(nm, sizeof(nm), "%s：*ResultLength 不变", names[i]);
            Check(nm, realLen == spoofLen);
        }
    }

    // ---------- E. 不认识的东西一律不动 ----------
    printf("\n--- E. 边界：不认识 / 不合法的一律不替换 ---\n");
    {
        // E1. class 0（Basic）没有数据区 ⇒ HasDataRegion=false
        Check("class=0 Basic 被判定为无数据区", !HasDataRegion(0));
        Check("class=5 Layer 被判定为无数据区（宁可漏不可崩）", !HasDataRegion(5));

        const LONG before = InterlockedCompareExchange(&g_spoofedCount, 0, 0);
        {
            static BYTE buf[2048];
            ZeroMemory(buf, sizeof(buf));
            ULONG rl = 0;
            const LONG st = QueryVia(h, L"Text", 0, buf, sizeof(buf), &rl);
            Check("class=0 调用成功", st >= 0);
            Check("class=0 没有发生替换（计数未增）",
                InterlockedCompareExchange(&g_spoofedCount, 0, 0) == before);
        }

        // E2. 直接喂 codec：短缓冲区
        {
            BYTE tiny[8] = { 0 };
            DataRegion r = {};
            Check("缓冲区短于结构头 -> 定位失败", !LocateDataRegion(2, tiny, sizeof(tiny), sizeof(tiny), r));
        }
        // E3. 直接喂 codec：dataLength == 0
        {
            BYTE hdr[16] = { 0 };
            // Partial：+8 = DataLength = 0
            DataRegion r = {};
            Check("dataLength==0 -> 定位失败（清零 0 字节是空操作）",
                !LocateDataRegion(2, hdr, sizeof(hdr), sizeof(hdr), r));
        }
        // E4. 直接喂 codec：dataOffset+dataLength 回绕（ULONG 溢出）
        {
            BYTE hdr[32] = { 0 };
            const ULONG off = 0xFFFFFFF0u;
            const ULONG len = 0x00000020u;   // 相加回绕成 0x10 < available
            memcpy(hdr + 8, &off, sizeof(off));
            memcpy(hdr + 12, &len, sizeof(len));
            DataRegion r = {};
            Check("dataOffset+dataLength 回绕 -> 定位失败（64 位算加法）",
                !LocateDataRegion(1, hdr, sizeof(hdr), sizeof(hdr), r));
        }
        // E5. 直接喂 codec：null 缓冲
        {
            DataRegion r = {};
            Check("info==nullptr -> 定位失败", !LocateDataRegion(2, nullptr, 64, 64, r));
        }
    }

    // ---------- F. 对真实调用方生效（RegQueryValueExW）----------
    printf("\n--- F. 真实调用方视角：RegQueryValueExW 也读到空串 ---\n");
    {
        wchar_t buf[256] = {};
        DWORD cb = sizeof(buf);
        DWORD type = 0;
        const LSTATUS st = RegQueryValueExW(h, L"Text", nullptr, &type,
            reinterpret_cast<LPBYTE>(buf), &cb);
        Check("RegQueryValueExW 调用成功", st == ERROR_SUCCESS);
        Check("RegQueryValueExW 拿到的类型仍是 REG_SZ", type == REG_SZ);
        Check("RegQueryValueExW 拿到的是空串（替换对真实调用方生效）",
            st == ERROR_SUCCESS && buf[0] == L'\0');
    }

    // ---------- 计数自检 ----------
    printf("\n--- 计数自检 ---\n");
    {
        const LONG spoofed = InterlockedCompareExchange(&g_spoofedCount, 0, 0);
        const LONG hits = InterlockedCompareExchange(&g_hits, 0, 0);
        char nm[128];
        snprintf(nm, sizeof(nm), "发生过替换（spoofed=%ld）", static_cast<long>(spoofed));
        Check(nm, spoofed > 0);
        snprintf(nm, sizeof(nm), "detour 命中次数 >= 替换次数（hits=%ld >= %ld）",
            static_cast<long>(hits), static_cast<long>(spoofed));
        Check(nm, hits >= spoofed);
    }

    // ---------- 收尾 ----------
    MH_DisableHook(reinterpret_cast<LPVOID>(g_targetNtQueryValueKey));
    MH_Uninitialize();
    RegCloseKey(h);
    DeleteProbeKey();

    printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
