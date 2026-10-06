#!/usr/bin/env bash
#
# build_procpath_probe.sh —— 编译「进程创建高危判据」探针。
#
# 探针回答一个问题：**这些常见程序在 block 模式下起不起得来**。
#
# ★ 它直调 `R3ShieldCoreRules::IsHighRiskProcessImage()` —— 引擎真正跑的那个
#   函数，底座与 `build_ut.sh` 完全一致（r3shieldcore_rules.obj + channel_stub.obj）。
#   所以它的结论就是引擎的结论，不是"读源码猜的"。
#
# 背景：`kProcessPathRules` 里 `\Windows\System32\` 是**片段匹配** ⇒ System32
#   下**所有**程序都判 HIGH；豁免只靠 `kCommonTrustedSystemExes` 那张小表。
#   而 block 模式下 highRisk 的进程创建是**直接拒**（process_guard.cpp:558）。
#   ⇒ 表里没列到的 System32 工具（tasklist / findstr / timeout / net ...）
#     在引擎跑起来之后**全部起不来**，包括引擎自己的 start.bat / stop.bat。
#
# 用法:
#   bash build_procpath_probe.sh            # 编译 + 跑
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


r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

# 与 build_ut.sh 同一套 include：r3shieldcore_rules.cpp 经 stdafx.h 拉 MinHook/wil
INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

LIB_SRC_REL="R3ShieldCore/R3ShieldCoreLib"
OBJDIR_REL="tools/ut-obj-x64"
mkdir -p "$OBJDIR_REL"

echo "=== 编译底座 r3shieldcore_rules.cpp + channel_stub.cpp ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_rules.obj" "$LIB_SRC_REL/r3shieldcore_rules.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/channel_stub.obj" "tools/channel_stub.cpp" || exit 1

echo "=== 编译 procpath_probe.cpp ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/procpath_probe.obj" "tools/procpath_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/procpath_probe.exe" \
    "$OBJDIR_REL/procpath_probe.obj" "$OBJDIR_REL/r3shieldcore_rules.obj" \
    "$OBJDIR_REL/channel_stub.obj" kernel32.lib user32.lib || exit 1

echo ""
echo "=== 运行 ==="
"./tools/procpath_probe.exe" --no-pause
exit $?
