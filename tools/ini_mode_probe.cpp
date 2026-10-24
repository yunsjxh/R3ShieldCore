// ini_mode_probe.cpp —— 用**引擎侧同一个解析器**确认生效配置读出来是什么模式。
//
// 为什么不能只用 grep：
//   `mode=` 那一行可能被注释符号吃掉、被大小写搞混、被 CRLF 弄坏，
//   或者 `ResolveConfigPath` 压根读的是另一份文件。grep 只看字节，
//   这里看的是**引擎真正会拿到的 Policy.Mode**（铁律 17：验行为不验字面）。
//
// 用法: ini_mode_probe.exe [iniPath]
//   不传参数 = 走 ResolveConfigPath（ProgramData 优先），即引擎运行期的真实选择。
#include "stdafx.h"

#include "r3shieldcore_config.h"
#include <r3shieldcore/r3shieldcore_shared.h>

#include <cstdio>
#include <filesystem>

int wmain(int argc, wchar_t** argv)
{
    setlocale(LC_ALL, "");

    const std::filesystem::path exeDir = std::filesystem::current_path();

    // 引擎运行期真正会读的那一份
    const std::filesystem::path resolved = R3ShieldCoreConfig::ResolveConfigPath(exeDir);
    wprintf(L"[ResolveConfigPath] %s\n", resolved.c_str());
    wprintf(L"[存在] %s\n\n", std::filesystem::exists(resolved) ? L"是" : L"否");

    std::filesystem::path target = resolved;
    if (argc >= 2) {
        target = argv[1];
        wprintf(L"[显式指定] %s\n\n", target.c_str());
    }

    R3ShieldCore::Policy policy = {};
    R3ShieldCoreConfig::LoadFromFile(policy, target, exeDir);

    const char* text = R3ShieldCoreConfig::ModeIniText(policy.Mode);
    wprintf(L"Policy.Mode = %lu  ->  \"%hs\"\n",
        static_cast<unsigned long>(policy.Mode), text ? text : "(无法识别)");

    wprintf(L"\n判读：\n");
    if (policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
        wprintf(L"  log = 只记录、全部放行 —— 不会拦 SetWindowsHookEx / RawInput，输入框正常\n");
    }
    else if (R3ShieldCore::IsAnyBlockAllMode(policy.Mode)) {
        wprintf(L"  ⚠️ block_all = 一律拒绝 —— 会拒掉输入钩子，所有程序输入框打不进字\n");
    }
    else if (policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Block)) {
        wprintf(L"  block = 只拦高危 —— 输入钩子按高危规则判，正常输入法放行\n");
    }
    else if (policy.Mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask)) {
        wprintf(L"  ask = 弹窗询问\n");
    }
    return 0;
}
