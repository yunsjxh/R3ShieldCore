#!/usr/bin/env bash
# 构建「全屏置顶覆盖层反制」相关的两个实证探针：
#   overlay_ladder_probe  —— 纯 Win32 三级升级链可行性（不链引擎代码）
#   sentinel_probe        —— 端到端验证真实 R3ShieldCoreSentinel 模块（链 r3shieldcore_sentinel.cpp）
#
# 与 build_probe.sh 同款工具链；所有路径相对（项目根目录含中文）。
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
DEMO="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore"


r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -execution-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"
INCS="-I$DEMO -IR3ShieldCore/shared -IR3ShieldCore/shared/libraries"

mkdir -p obj/probe

echo "=== overlay_ladder_probe ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/overlay_ladder_probe.obj" "tools/overlay_ladder_probe.cpp" || exit 1
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/overlay_ladder_probe.exe" \
    "obj/probe/overlay_ladder_probe.obj" user32.lib kernel32.lib || exit 1

echo "=== sentinel_probe ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/sentinel_probe.obj" "tools/sentinel_probe.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"obj/probe/r3shieldcore_sentinel.obj" "$DEMO/r3shieldcore_sentinel.cpp" || exit 1
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/sentinel_probe.exe" \
    "obj/probe/sentinel_probe.obj" "obj/probe/r3shieldcore_sentinel.obj" \
    user32.lib kernel32.lib advapi32.lib psapi.lib gdi32.lib || exit 1

echo "BUILD OK"
