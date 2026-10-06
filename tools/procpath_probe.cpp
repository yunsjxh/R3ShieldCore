//
// procpath_probe.cpp —— 直接问规则层：这些常见程序算不算「高危进程创建」。
//
// 为什么要它（而不是读源码）：
//   `kProcessPathRules` 里 `\Windows\System32\` 是**片段匹配**，
//   豁免靠 `kCommonTrustedSystemExes`。两张表谁赢、有没有漏项，
//   光看代码容易看漏 —— 这里直接调**引擎真正跑的那个函数**
//   `R3ShieldCoreRules::ProcessRiskReason()`，和单测同一套底座。
//
//   block 模式下 highRisk 的进程创建是**直接拒**（process_guard.cpp），
//   所以这里返回非 nullptr 就等于"这个程序在 block 模式下起不来"。
//
// 用法: procpath_probe.exe [--no-pause]
//
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "r3shieldcore_rules.h"

namespace
{
bool g_noPause = false;

struct Case
{
    PCWSTR path;
    PCWSTR note;
};

// 覆盖三类：① 日常 GUI（作者已豁免）② 控制台/脚本常用工具 ③ 真正的 LOLBin
const Case kCases[] = {
    { L"C:\\Windows\\System32\\notepad.exe",      L"日常 GUI（应在豁免表里）" },
    { L"C:\\Windows\\System32\\taskmgr.exe",      L"日常 GUI（应在豁免表里）" },
    { L"C:\\Windows\\System32\\tasklist.exe",     L"控制台：列进程 ★ start.bat 用它" },
    { L"C:\\Windows\\System32\\findstr.exe",      L"控制台：文本过滤 ★ verify-v26.bat 用它" },
    { L"C:\\Windows\\System32\\find.exe",         L"控制台：文本过滤" },
    { L"C:\\Windows\\System32\\timeout.exe",      L"控制台：延时 ★ start.bat 用它" },
    { L"C:\\Windows\\System32\\icacls.exe",       L"控制台：改 ACL ★ unlock-acl.bat 用它" },
    { L"C:\\Windows\\System32\\net.exe",          L"控制台：★ start.bat 的提权检查用它" },
    { L"C:\\Windows\\System32\\ping.exe",         L"控制台：网络诊断" },
    { L"C:\\Windows\\System32\\ipconfig.exe",     L"控制台：网络诊断" },
    { L"C:\\Windows\\System32\\netstat.exe",      L"控制台：网络诊断" },
    { L"C:\\Windows\\System32\\whoami.exe",       L"控制台：身份查询" },
    { L"C:\\Windows\\System32\\hostname.exe",     L"控制台：身份查询" },
    { L"C:\\Windows\\System32\\systeminfo.exe",   L"控制台：系统信息" },
    { L"C:\\Windows\\System32\\where.exe",        L"控制台：查路径" },
    { L"C:\\Windows\\System32\\robocopy.exe",     L"控制台：复制" },
    { L"C:\\Windows\\System32\\attrib.exe",       L"控制台：属性" },
    { L"C:\\Windows\\System32\\cmd.exe",          L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\powershell.exe",   L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\wscript.exe",      L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\mshta.exe",        L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\rundll32.exe",     L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\regsvr32.exe",     L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\certutil.exe",     L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\schtasks.exe",     L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\sc.exe",           L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\reg.exe",          L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\wmic.exe",         L"LOLBin（应保持 HIGH）" },
    { L"C:\\Windows\\System32\\bitsadmin.exe",    L"LOLBin（应保持 HIGH）" },
    // 攻击者投放：System32 下的**非白名单**程序 → 必须仍然是 HIGH
    { L"C:\\Windows\\System32\\evil_dropped.exe", L"★ 投放样本（必须仍是 HIGH）" },
    { L"C:\\Windows\\Temp\\evil.exe",             L"★ 可写目录投放（必须仍是 HIGH）" },
    { L"dist\\R3ShieldCore-x64\\dskill.exe", L"部署目录（应放行）" },
};

} // namespace

int wmain(int argc, wchar_t** argv)
{
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--no-pause") == 0) {
            g_noPause = true;
        }
    }

    SetConsoleOutputCP(936);

    printf("============================================================\n");
    printf(" 进程创建高危判据探针（直调 R3ShieldCoreRules::ProcessRiskReason）\n");
    printf(" block 模式下：非 nullptr == 会被直接拒 == 这个程序起不来\n");
    printf("============================================================\n\n");

    int highCount = 0;
    int lowCount = 0;

    for (const Case& c : kCases) {
        const char* reason = R3ShieldCoreRules::ProcessRiskReason(
            c.path, static_cast<ULONG>(R3ShieldCore::ProcessOp::Create), 0);

        if (reason) {
            ++highCount;
            printf("  [HIGH] %-52ls  <- %s\n", c.path, reason);
        }
        else {
            ++lowCount;
            printf("  [ OK ] %-52ls  （不判高危）\n", c.path);
        }
        printf("         %ls\n", c.note);
    }

    printf("\n------------------------------------------------------------\n");
    printf(" HIGH=%d  OK=%d\n", highCount, lowCount);

    // ★ 结论行：只看脚本工具那几条 —— 它们 HIGH 就意味着部署脚本自己会瘫
    const PCWSTR kScriptTools[] = {
        L"C:\\Windows\\System32\\tasklist.exe",
        L"C:\\Windows\\System32\\findstr.exe",
        L"C:\\Windows\\System32\\timeout.exe",
        L"C:\\Windows\\System32\\icacls.exe",
        L"C:\\Windows\\System32\\net.exe",
    };
    printf("\n=== 部署脚本依赖的 5 个 System32 工具 ===\n");
    int blocked = 0;
    for (PCWSTR t : kScriptTools) {
        const char* r = R3ShieldCoreRules::ProcessRiskReason(
            t, static_cast<ULONG>(R3ShieldCore::ProcessOp::Create), 0);
        printf("  %-52ls %s\n", t, r ? "★ 会被 block 模式拒掉" : "可放行");
        if (r) {
            ++blocked;
        }
    }
    printf("\n  结论: %d / 5 个会被拒 %s\n", blocked,
           blocked ? "=> start.bat / stop.bat / unlock-acl.bat 在引擎跑起来之后会自己瘫"
                   : "=> 部署脚本可用");

    if (!g_noPause) {
        printf("\n按回车键退出...");
        (void)getchar();
    }
    return blocked ? 1 : 0;
}
