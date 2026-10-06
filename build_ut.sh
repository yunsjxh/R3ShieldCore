#!/usr/bin/env bash
#
# build_ut.sh - 构建并运行 R3ShieldCoreRules 高危规则单元测试。
#
# 为什么要这个脚本：
#   规则单测（tools/*_rules_ut.cpp）直接链 r3shieldcore_rules.cpp 的目标文件 +
#   channel_stub.cpp（提供 Policy 桩），不依赖引擎、不需要注入，秒级跑完。
#   它们是"改规则表后第一时间发现问题"的护栏 —— 比如 v10 那个
#   "非系统目录一律高危 → 噪音淹没真信号"的坑，有 UT 就能在编译期拦住。
#
# 用法: bash build_ut.sh [x64|x86]
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
#   本脚本可能位于仓库根或子目录（driver/ installer/ tools/），
#   所以向上找到含 scripts_env.sh 的目录（= 仓库根）。
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"
LIB_SRC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib"
SHARED="$PROJECT_ROOT/R3ShieldCore/shared"
TOOLS="$PROJECT_ROOT/tools"


ARCH="${1:-x64}"

if [ "$ARCH" = "x64" ]; then
    HOST="Hostx64/x64"
else
    HOST="Hostx64/x86"
fi

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**调 cl/link：项目根含中文，
#    绝对路径经 MSYS 转换后会把仓库根和 git 安装路径拼在一起，
#    变成 `D:\<仓库根>\C:\Users\...\PortableGit\...` → C1083。
#    MSYS_NO_PATHCONV=1 也有效，但统一用相对路径更省心（同 build.sh）。
cd "$PROJECT_ROOT" || exit 1

OBJDIR_REL="tools/ut-obj-$ARCH"
mkdir -p "$OBJDIR_REL"

CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

# r3shieldcore_rules.cpp 经 stdafx.h 间接拉进 MinHook/MinHook.h 与 wil/stl.h，
# 所以必须带 libraries 这两个 include 目录（同 build.sh）。
INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

LIB_SRC_REL="R3ShieldCore/R3ShieldCoreLib"

# r3shieldcore_rules.cpp 与 channel_stub.cpp 是共用的底座，编一次。
echo "=== 编译底座 r3shieldcore_rules.cpp + channel_stub.cpp [$ARCH] ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_rules.obj" "$LIB_SRC_REL/r3shieldcore_rules.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/channel_stub.obj" "tools/channel_stub.cpp" || exit 1

FAILED=0
run_one() {
    local name="$1"
    echo ""
    echo "=== $name [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/$name.obj" "tools/$name.cpp" || { FAILED=1; return; }

    "$LINK" -nologo -SUBSYSTEM:CONSOLE \
        -OUT:"tools/$name.exe" \
        "$OBJDIR_REL/$name.obj" "$OBJDIR_REL/r3shieldcore_rules.obj" "$OBJDIR_REL/channel_stub.obj" \
        kernel32.lib user32.lib || { FAILED=1; return; }

    "./tools/$name.exe" || FAILED=1
}

run_config_ut() {
    echo ""
    echo "=== config_ut [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_config.obj" \
        "R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp" || { FAILED=1; return; }
    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/config_ut.obj" "tools/config_ut.cpp" || { FAILED=1; return; }
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/config_ut.exe" \
        "$OBJDIR_REL/config_ut.obj" "$OBJDIR_REL/r3shieldcore_config.obj" kernel32.lib || { FAILED=1; return; }
    "./tools/config_ut.exe" || FAILED=1
}
for t in reg_rules_ut file_rules_ut net_rules_ut procguard_ut \
         dll_rules_ut clipboard_rules_ut spawn_rules_ut v11_rules_ut \
         v12_rules_ut v13_rules_ut v14_rules_ut v15_rules_ut v16_rules_ut \
         v17_rules_ut v18_rules_ut v19_rules_ut v20_rules_ut v25_rules_ut \
         v26_rules_ut terminate_contain_ut v45_rules_ut protect_reg_ut \
         high_risk_process_ut; do
    [ -f "$TOOLS/$t.cpp" ] && run_one "$t"
done

run_config_ut

# ★ v42：inject_policy.cpp **故意零依赖**（不 include stdafx、不碰 Policy/共享内存），
#    所以它的单测**只链自己 + kernel32**，不走 run_one 那套
#    r3shieldcore_rules + channel_stub 底座。
#    这条也是"判据表单独成文件"这个套路的回报：能独立测、测的就是引擎真正跑的那份代码。
run_inject_policy_ut() {
    echo ""
    echo "=== inject_policy_ut [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/inject_policy.obj" \
        "$LIB_SRC_REL/inject_policy.cpp" || { FAILED=1; return; }
    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/inject_policy_ut.obj" "tools/inject_policy_ut.cpp" || { FAILED=1; return; }
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/inject_policy_ut.exe" \
        "$OBJDIR_REL/inject_policy_ut.obj" "$OBJDIR_REL/inject_policy.obj" \
        kernel32.lib || { FAILED=1; return; }
    "./tools/inject_policy_ut.exe" || FAILED=1
}

run_inject_policy_ut

# ★ v46：inject_activity.h 是**纯头文件**（inline 变量 + inline 函数，不链任何东西），
#    所以它的单测**只编自己 + kernel32**。钉的是"引擎自己在注入"这个标记的语义边界：
#    精确匹配目标 pid、pid 0 是哨兵不放行、**线程局部**、可嵌套、异常展开恢复。
run_inject_activity_ut() {
    echo ""
    echo "=== inject_activity_ut [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/inject_activity_ut.obj" "tools/inject_activity_ut.cpp" || { FAILED=1; return; }
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/inject_activity_ut.exe" \
        "$OBJDIR_REL/inject_activity_ut.obj" kernel32.lib || { FAILED=1; return; }
    "./tools/inject_activity_ut.exe" || FAILED=1
}

run_inject_activity_ut

# ★ v62：ark_actions.cpp 同样**故意零依赖**（不 include stdafx、不碰 Policy/共享内存），
#    所以它的单测**只链自己 + kernel32 + psapi**。
#    这个套件和上面那些"判据表"套件最大的不同：它会**真的起受害进程**
#    （cmd.exe 跑死循环批处理），然后真的挂起它 / 恢复它 / 杀掉它，
#    并用受害进程自己产生的 tick.txt 大小做 A/B 判定 —— 不是看返回码。
#    需要 psapi：QueryRemoteDllBase 用 EnumProcessModulesEx / GetModuleBaseNameW。
run_ark_actions_ut() {
    echo ""
    echo "=== ark_actions_ut [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/ark_actions.obj" \
        "R3ShieldCore/R3ShieldCore/ark_actions.cpp" || { FAILED=1; return; }
    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/ark_actions_ut.obj" "tools/ark_actions_ut.cpp" || { FAILED=1; return; }
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/ark_actions_ut.exe" \
        "$OBJDIR_REL/ark_actions_ut.obj" "$OBJDIR_REL/ark_actions.obj" \
        kernel32.lib psapi.lib || { FAILED=1; return; }
    "./tools/ark_actions_ut.exe" || FAILED=1
}

run_ark_actions_ut

# ★ v63：ARK 列表的「分组 + 排序」判据。`GroupRankOf` / `ArkRowLess` 是
#    **纯函数**，刻意以 `inline` 形式放在 `r3shieldcore_ark.h` 里 ⇒
#    本套件**只编译自己**，不链 r3shieldcore_ark.cpp（那要 wil + R3ShieldCoreStats
#    一整套）。好处是引擎和单测跑的是**同一份判据**，而不是"测试里照抄一遍"
#    —— 照抄的话判据改了测试不会红，等于没测。
run_ark_order_ut() {
    echo ""
    echo "=== ark_order_ut [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/ark_order_ut.obj" "tools/ark_order_ut.cpp" || { FAILED=1; return; }
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/ark_order_ut.exe" \
        "$OBJDIR_REL/ark_order_ut.obj" kernel32.lib || { FAILED=1; return; }
    "./tools/ark_order_ut.exe" || FAILED=1
}

run_ark_order_ut

echo ""
if [ "$FAILED" = "0" ]; then
    echo "=== 全部单元测试通过 ==="
else
    echo "=== 存在失败用例 ==="
fi
exit $FAILED
