#!/usr/bin/env bash
#
# build_terminate_probes.sh - 构建并运行「终止进程收敛」的**端到端**探针（v36/v37）。
#
# 与其它脚本的分工：
#   · build_ut.sh         —— 规则层单测（链 r3shieldcore_rules.cpp），秒级。
#   · build_guard_ut.sh   —— guard 层单测（链 registry_guard.cpp + guard_stub）。
#   · 本脚本              —— 把**真实的 process_guard.cpp** 链进来，
#                            在本进程里**真的装 hook**（ProcessGuard::Install +
#                            MH_ApplyQueued），然后**真的去杀进程**。
#                           这是"产品代码本身"的端到端，不需要提权、不需要全系统注入。
#
# 目标文件：
#   · tools/terminate_contain_e2e.cpp  —— 端到端（11+ 项断言）
#   · tools/handle_query_probe.cpp     —— 根因探针（各 access mask 反查 pid 能力）
#
# 用法: bash build_terminate_probes.sh [x64|x86]
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
TOOLS="$PROJECT_ROOT/tools"


ARCH="${1:-x64}"

if [ "$ARCH" = "x64" ]; then
    HOST="Hostx64/x64"
    MH_LIB="libMinHook.x64.lib"
else
    HOST="Hostx64/x86"
    MH_LIB="libMinHook.x86.lib"
fi

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

OBJDIR_REL="tools/terminate-obj-$ARCH"
mkdir -p "$OBJDIR_REL"

CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib/libraries/MinHook \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

LIB_SRC_REL="R3ShieldCore/R3ShieldCoreLib"
MH_LIB_REL="$LIB_SRC_REL/libraries/MinHook/$MH_LIB"

echo "=== 编译底座（process_guard + registry_guard + rules + guard_stub）[$ARCH] ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/process_guard.obj"   "$LIB_SRC_REL/process_guard.cpp"   || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/registry_guard.obj"  "$LIB_SRC_REL/registry_guard.cpp"  || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_rules.obj" "$LIB_SRC_REL/r3shieldcore_rules.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/guard_stub.obj"      "tools/guard_stub.cpp"             || exit 1

FAILED=0
run_one() {
    local name="$1"
    echo ""
    echo "=== $name [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/$name.obj" "tools/$name.cpp" || { FAILED=1; return; }

    "$LINK" -nologo -SUBSYSTEM:CONSOLE \
        -OUT:"tools/$name.exe" \
        "$OBJDIR_REL/$name.obj" \
        "$OBJDIR_REL/process_guard.obj" \
        "$OBJDIR_REL/registry_guard.obj" \
        "$OBJDIR_REL/r3shieldcore_rules.obj" \
        "$OBJDIR_REL/guard_stub.obj" \
        "$MH_LIB_REL" \
        kernel32.lib user32.lib advapi32.lib || { FAILED=1; return; }

    "./tools/$name.exe" || FAILED=1
}

run_one terminate_contain_e2e

# handle_query_probe 是自包含的（不链 guard），单独编。
echo ""
echo "=== handle_query_probe [$ARCH] ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/handle_query_probe.obj" "tools/handle_query_probe.cpp" || FAILED=1
if [ "$FAILED" = "0" ]; then
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/handle_query_probe.exe" \
        "$OBJDIR_REL/handle_query_probe.obj" kernel32.lib || FAILED=1
fi
if [ "$FAILED" = "0" ]; then
    "./tools/handle_query_probe.exe" || FAILED=1
fi

echo ""
if [ "$FAILED" = "0" ]; then
    echo "=== 终止收敛探针全部通过 ==="
else
    echo "=== 终止收敛探针存在失败用例 ==="
fi
exit $FAILED
