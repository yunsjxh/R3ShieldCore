#!/usr/bin/env bash
#
# build_channel_policy_ut.sh —— 编译并运行 `R3ShieldCoreChannel::OpenPolicyOnly` 单测（v49）。
#
# 为什么需要它：瘦会话（explorer.exe）要读 `never_inject=` 名单才能不注入名单里的程序，
# 但它**不能**变成"受监控进程"（`IsOpen()` 必须保持 false）。这个不变量靠单测钉住。
#
# 用法: bash build_channel_policy_ut.sh [x64|x86]
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


ARCH="${1:-x64}"
if [ "$ARCH" = "x64" ]; then HOST="Hostx64/x64"; else HOST="Hostx64/x86"; fi

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

cd "$PROJECT_ROOT" || exit 1

OBJDIR_REL="obj/channel-ut-$ARCH"
mkdir -p "$OBJDIR_REL"

CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

LIB_SRC_REL="R3ShieldCore/R3ShieldCoreLib"

echo "=== 编译 channel 单测底座（$ARCH）==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_channel.obj" "$LIB_SRC_REL/r3shieldcore_channel.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/logger.obj" "$LIB_SRC_REL/logger.cpp" || exit 1
# functions.cpp 提供 GetSharedObjectSecurityDescriptor（Create 要用）；
# 它只 include stdafx/functions/inject_policy/r3shieldcore_channel/logger，**不碰任何 guard**，所以可单链。
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/functions.obj" "$LIB_SRC_REL/functions.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/inject_policy.obj" "$LIB_SRC_REL/inject_policy.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/channel_policy_ut.obj" "tools/channel_policy_ut.cpp" || exit 1

echo "=== 链接 ==="
MSYS_NO_PATHCONV=1 "$LINK" -nologo -SUBSYSTEM:CONSOLE \
    -OUT:"tools/channel_policy_ut.exe" \
    "$OBJDIR_REL/channel_policy_ut.obj" \
    "$OBJDIR_REL/r3shieldcore_channel.obj" \
    "$OBJDIR_REL/functions.obj" \
    "$OBJDIR_REL/inject_policy.obj" \
    "$OBJDIR_REL/logger.obj" \
    kernel32.lib advapi32.lib || exit 1

echo ""
"./tools/channel_policy_ut.exe"
exit $?
