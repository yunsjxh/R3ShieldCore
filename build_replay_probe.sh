#!/usr/bin/env bash
#
# 编译 tools/replay_probe.cpp —— 事件日志回放解析器的独立探针。
#
# 链接的是**真代码**（r3shieldcore_log_replay.cpp + r3shieldcore_stats.cpp），
# 不是复制一份逻辑 —— 否则"探针绿了但引擎不绿"（铁律 22 家族）。
#
# 用法：bash build_replay_probe.sh
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

ARCH="x64"

cd "$PROJECT_ROOT" || { echo "找不到项目目录"; exit 1; }

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -W3 -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p _t/replay_probe

echo "编译 tools/replay_probe.cpp"
"$CL" $CFLAGS -I R3ShieldCore/shared -I R3ShieldCore/shared/libraries -I R3ShieldCore/R3ShieldCore \
    -Fo_t/replay_probe/replay_probe.obj tools/replay_probe.cpp || exit 1

echo "编译 R3ShieldCore/R3ShieldCore/r3shieldcore_log_replay.cpp（真代码）"
"$CL" $CFLAGS -I R3ShieldCore/shared -I R3ShieldCore/shared/libraries -I R3ShieldCore/R3ShieldCore \
    -Fo_t/replay_probe/r3shieldcore_log_replay.obj \
    R3ShieldCore/R3ShieldCore/r3shieldcore_log_replay.cpp || exit 1

echo "编译 R3ShieldCore/R3ShieldCore/r3shieldcore_stats.cpp（真代码）"
"$CL" $CFLAGS -I R3ShieldCore/shared -I R3ShieldCore/shared/libraries -I R3ShieldCore/R3ShieldCore \
    -Fo_t/replay_probe/r3shieldcore_stats.obj \
    R3ShieldCore/R3ShieldCore/r3shieldcore_stats.cpp || exit 1

echo "链接"
MSYS_NO_PATHCONV=1 "$LINK" -nologo \
    -SUBSYSTEM:CONSOLE \
    -MACHINE:X64 \
    -OUT:_t/replay_probe/replay_probe.exe \
    _t/replay_probe/replay_probe.obj \
    _t/replay_probe/r3shieldcore_log_replay.obj \
    _t/replay_probe/r3shieldcore_stats.obj \
    kernel32.lib user32.lib advapi32.lib shell32.lib psapi.lib \
    || exit 1

echo "--> _t/replay_probe/replay_probe.exe"
