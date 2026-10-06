// deploy_acl_probe.cpp —— 「引擎会不会加载这个部署目录里的 DLL」实测探针
// ============================================================================
//
// 【要回答的问题】
//   引擎的 `EngineControl` 构造函数里有一道硬门槛：
//
//       if (!IsProtectedEngineDeployment(engineLibraryPath)) {
//           throw std::runtime_error(
//               "Refusing to load an engine DLL from a user-writable deployment directory");
//       }
//
//   过不去 ⇒ 引擎**抛异常直接退出**（不是降级、不是警告）。
//   用户看到的现象是「双击引擎 → 窗口一闪 → 什么都没发生」，然后所有拦截
//   测试都变成假的 —— 因为**根本没有引擎在跑**。
//
//   2026-10-03 实测踩到：`dist\R3ShieldCore-x64\` 从 `D:\` 继承了
//   `Authenticated Users:(M)`，三次启动全部被拒（见 r3shieldcore-startup-error.log）。
//
// 【为什么不能靠"看 icacls 输出"判断】
//   判据的边界条件不止"有没有 Authenticated Users"这一条（还看 mask、
//   看 ACE 类型、看文件**和**目录、看 Everyone/BUILTIN\Users）。用眼睛看
//   或者用 grep 都会漂移。
//
//   ★ 本探针与引擎包含的是**同一个** `engine_deploy_acl.h`（不是复制一份），
//     所以"探针说能加载"和"引擎真的能加载"不可能分歧。
//     —— 这是 `verify_dist_ini` 那套做法的延续（铁律 9/17：看真实现，不看 grep）。
//
// 用法:
//   tools\deploy_acl_probe.exe                 # 查 <本exe目录>\64\r3shieldcore-lib.dll
//   tools\deploy_acl_probe.exe <目录>          # 查 <目录>\r3shieldcore-lib.dll
//   tools\deploy_acl_probe.exe <某个.dll>      # 直接查这个文件
//   tools\deploy_acl_probe.exe --no-pause      # 不暂停（脚本用）
//
// 退出码: 0 = 引擎会加载 ｜ 1 = 引擎会拒绝 ｜ 2 = 找不到 DLL
// ============================================================================

#include <windows.h>
#include <aclapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <locale.h>

#include <filesystem>
#include <string>
#include <system_error>

#include "engine_deploy_acl.h"

static bool g_noPause = false;

static void PauseBeforeExit()
{
    if (g_noPause) { return; }
    printf("\n按回车键退出...");
    (void)getchar();
}

// 把访问掩码里"写"相关的位翻译成人能读的名字。
static void DescribeWriteRights(ACCESS_MASK mask, char* out, size_t outSize)
{
    out[0] = '\0';
#define APPEND_RIGHT(bit, name) \
    do { \
        if ((mask & (bit)) != 0) { \
            if (out[0] != '\0') { strcat_s(out, outSize, "|"); } \
            strcat_s(out, outSize, name); \
        } \
    } while (false)

    APPEND_RIGHT(GENERIC_ALL, "GENERIC_ALL");
    APPEND_RIGHT(GENERIC_WRITE, "GENERIC_WRITE");
    APPEND_RIGHT(FILE_WRITE_DATA, "WRITE_DATA");
    APPEND_RIGHT(FILE_APPEND_DATA, "APPEND_DATA");
    APPEND_RIGHT(FILE_WRITE_EA, "WRITE_EA");
    APPEND_RIGHT(FILE_WRITE_ATTRIBUTES, "WRITE_ATTR");
    APPEND_RIGHT(DELETE, "DELETE");
    APPEND_RIGHT(WRITE_DAC, "WRITE_DAC");
    APPEND_RIGHT(WRITE_OWNER, "WRITE_OWNER");
#undef APPEND_RIGHT
}

static bool SidToName(PSID sid, wchar_t* out, size_t outCount)
{
    wchar_t domain[128] = {};
    DWORD domainSize = _countof(domain);
    DWORD nameSize = static_cast<DWORD>(outCount);
    SID_NAME_USE use = SidTypeUnknown;
    if (!LookupAccountSidW(nullptr, sid, out, &nameSize, domain, &domainSize, &use)) {
        return false;
    }
    return true;
}

// 只负责**报告**：把 DACL 里对 Everyone / Authenticated Users / BUILTIN\Users
// 开放的写权限 ACE 逐条列出来，并给出它是不是那三个 SID。
// 注意：**判定不在这里** —— 判定来自共用 header 的 EngineDeploy::HasBroadWriteAccess。
static void ListBroadWriteAces(const std::filesystem::path& path, int* listedCount)
{
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS || !sd) {
        printf("   (无法读取安全描述符)\n");
        return;
    }

    if (!dacl) {
        printf("   (DACL 为空 = 谁都访问不了；这本身就是坏状态)\n");
        LocalFree(sd);
        return;
    }

    BYTE world[SECURITY_MAX_SID_SIZE] = {};
    BYTE auth[SECURITY_MAX_SID_SIZE] = {};
    BYTE users[SECURITY_MAX_SID_SIZE] = {};
    DWORD worldSize = sizeof(world), authSize = sizeof(auth), usersSize = sizeof(users);
    if (!CreateWellKnownSid(WinWorldSid, nullptr, world, &worldSize) ||
        !CreateWellKnownSid(WinAuthenticatedUserSid, nullptr, auth, &authSize) ||
        !CreateWellKnownSid(WinBuiltinUsersSid, nullptr, users, &usersSize)) {
        LocalFree(sd);
        return;
    }

    constexpr ACCESS_MASK kWriteMask = FILE_WRITE_DATA | FILE_APPEND_DATA |
        FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
        GENERIC_WRITE | GENERIC_ALL;

    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        LPVOID raw = nullptr;
        if (!GetAce(dacl, i, &raw)) { continue; }
        auto* header = static_cast<PACE_HEADER>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { continue; }

        auto* allowed = static_cast<PACCESS_ALLOWED_ACE>(raw);
        PSID sid = &allowed->SidStart;

        const char* kind = nullptr;
        if (EqualSid(sid, world)) { kind = "Everyone"; }
        else if (EqualSid(sid, auth)) { kind = "Authenticated Users"; }
        else if (EqualSid(sid, users)) { kind = "BUILTIN\\Users"; }

        if (!kind) { continue; }
        if ((allowed->Mask & kWriteMask) == 0) { continue; }

        wchar_t sidName[128] = {};
        SidToName(sid, sidName, _countof(sidName));

        char rights[256] = {};
        DescribeWriteRights(allowed->Mask, rights, sizeof(rights));

        printf("   [!!] %-22s (%ls) mask=%08lX -> %s\n",
            kind, sidName[0] ? sidName : L"?",
            static_cast<unsigned long>(allowed->Mask), rights);
        ++(*listedCount);
    }

    if (*listedCount == 0) {
        printf("   [OK] 没有向 Everyone / Authenticated Users / BUILTIN\\Users 开放的写 ACE\n");
    }
    LocalFree(sd);
}

// 返回 true = 这个对象被"广泛可写"（引擎会因此拒绝加载）。
static bool ReportOne(const wchar_t* label, const std::filesystem::path& path, int* listedCount)
{
    printf("\n[%ls] %ls\n", label, path.c_str());
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("   [!!] 对象不存在\n");
        return false;
    }

    ListBroadWriteAces(path, listedCount);

    const bool broad = EngineDeploy::HasBroadWriteAccess(path);
    const bool agree = broad == (*listedCount > 0);
    if (!agree) {
        // 列出与判定不一致 = 报告逻辑或判据漂移了，必须说出来而不是掩盖。
        printf("   [!] 注意: 列表与判据不一致（判据=%s，列表命中=%d 条）"
               "—— 说明有边界条件没被列表覆盖，以**判据**为准。\n",
            broad ? "广泛可写" : "受保护", *listedCount);
    }
    return broad;
}

int main(int argc, char** argv)
{
    // ★ 必须先 setlocale，否则 printf 的 `%ls` 在 "C" locale 下遇到中文
    //   会**静默截断**（wcstombs 转不过去就停在那里）—— 路径里含中文时
    //   会打印出半个路径，看起来像"路径解析错了"，其实是编码问题。
    setlocale(LC_ALL, "");
    SetConsoleOutputCP(936);

    std::filesystem::path target;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--no-pause") == 0) { g_noPause = true; continue; }
        if (strcmp(argv[i], "--help") == 0) {
            printf("deploy_acl_probe.exe [<目录 或 .dll 路径>] [--no-pause]\n");
            printf("  回答\"引擎会不会加载这个部署目录里的 DLL\"。\n");
            printf("  不带参数 = 查 <本exe目录>\\64\\r3shieldcore-lib.dll\n");
            printf("  退出码: 0=会加载 1=会拒绝 2=找不到 DLL\n");
            PauseBeforeExit();
            return 0;
        }
        target = argv[i];
    }

    if (target.empty()) {
        wchar_t self[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, self, _countof(self));
        target = std::filesystem::path(self).parent_path() / L"64";
    }

    std::error_code fsError;
    if (std::filesystem::is_directory(target, fsError)) {
        target /= L"r3shieldcore-lib.dll";
    }

    printf("============================================================\n");
    printf(" R3ShieldCore 部署 ACL 判据探针\n");
    printf(" （与引擎共用 engine_deploy_acl.h，判定不会分歧）\n");
    printf("============================================================\n");
    printf(" 目标 DLL : %ls\n", target.c_str());
    printf(" 所在目录 : %ls\n", target.parent_path().c_str());

    if (GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[SKIP] 找不到这个 DLL，无法判断。\n");
        printf("       请确认路径，或把本 exe 放到部署目录里再跑（默认查 .\\64\\）。\n");
        PauseBeforeExit();
        return 2;
    }

    int listed = 0;
    const bool dllBroad = ReportOne(L"DLL 文件", target, &listed);

    listed = 0;
    const bool dirBroad = ReportOne(L"所在目录", target.parent_path(), &listed);

    printf("\n============================================================\n");
    const bool protectedOk = !dllBroad && !dirBroad;
    if (protectedOk) {
        printf(" 结论: [PASS] 引擎**会**加载这个 DLL。\n");
        printf("       注意: 只证明「加载得过」，不证明 hook 装上了 ——\n");
        printf("       装没装看 r3shieldcore-console.log 的「注入新进程」。\n");
        PauseBeforeExit();
        return 0;
    }

    printf(" 结论: [FAIL] 引擎会**拒绝加载**并直接退出。\n");
    printf("       现象: 双击引擎 -> 窗口一闪 -> 屏幕上没有任何防护。\n");
    printf("       日志: 同目录 r3shieldcore-startup-error.log 里的\n");
    printf("             \"Refusing to load an engine DLL from a user-writable\n");
    printf("              deployment directory\"\n");
    printf("\n 修复（管理员 cmd，**只加固根目录、不要加 /T**）:\n");
    printf("   icacls \"<部署根目录>\" /inheritance:r ^\n");
    printf("      /grant:r \"*S-1-5-32-544:(OI)(CI)F\" ^\n");
    printf("               \"*S-1-5-18:(OI)(CI)F\" ^\n");
    printf("               \"*S-1-5-32-545:(OI)(CI)RX\"\n");
    printf("   或直接运行随包的 harden-acl.bat（右键 -> 以管理员身份运行）。\n");
    printf("\n   ★ v57 起引擎**已删除这道门禁** —— 目录可写不再拒绝启动，\n");
    printf("     上面的修复步骤只对 <= v56 的旧引擎有意义。\n");
    printf("     本探针保留是为了复现/讲解旧行为，以及给旧版本排障。\n");
    printf("\n   [!] 不要加 /T: /inheritance:r 会把每个文件的继承 ACE 也剥掉，\n");
    printf("       而 (OI)(CI) 对文件无效 => 文件留下**空 DACL**（谁都读不了）。\n");
    PauseBeforeExit();
    return 1;
}
