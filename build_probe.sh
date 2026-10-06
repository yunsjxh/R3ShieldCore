#!/usr/bin/env bash
# 单独编译并运行 probe_ask.cpp（链规则层 + channel 桩）。
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


r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"
INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

mkdir -p obj/probe

echo "=== 编译 r3shieldcore_rules.cpp ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/r3shieldcore_rules.obj" "R3ShieldCore/R3ShieldCoreLib/r3shieldcore_rules.cpp" || exit 1

echo "=== 编译 channel_stub.cpp ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/channel_stub.obj" "tools/channel_stub.cpp" || exit 1

echo "=== 编译 probe_ask.cpp ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/probe_ask.obj" "tools/probe_ask.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/probe_ask.exe" \
    "obj/probe/probe_ask.obj" "obj/probe/r3shieldcore_rules.obj" "obj/probe/channel_stub.obj" \
    kernel32.lib || exit 1

echo "=== 运行 ==="
"./tools/probe_ask.exe"
