#!/usr/bin/env bash
#
# build_v54_config_probe.sh —— 编译 v54 配置/回放联合探针（链真代码）。
#
# 链进来的真代码：r3shieldcore_config.cpp（LoadEngineSettings）+ r3shieldcore_log_replay.cpp
# 这样测的就是引擎真正会跑的路径，不是复制品。
#
# 编译选项风格「单横线 + 冒号」（-nologo / -Fo:...）与本仓其它构建脚本一致 ——
# Git Bash 会把 `/nologo` 之类的**正斜线开头参数**当路径改写（MSYS 路径转换），
# 症状是 `warning D9024: 无法识别的源文件类型 "C:/…/nologo"`。
#
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

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
CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

# 用 INCLUDE/LIB 环境变量传搜索路径（与 build.sh 一致），避免 /I 被路径转换
r3sc_export_msvc_env "${ARCH:-x64}"
export PATH="$MSVC_ROOT/bin/Hostx64/x64:$PATH"

OUT="_t/v54_config_probe"
mkdir -p "$OUT"

CFLAGS=(
    -nologo -c -std:c++20 -MT -EHsc -O2 -W3
    -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX
    -source-charset:utf-8 -execution-charset:utf-8
    -I R3ShieldCore/shared
    -I R3ShieldCore/shared/libraries
    -I R3ShieldCore/R3ShieldCore
)

echo "编译 tools/v54_config_probe.cpp"
MSYS_NO_PATHCONV=1 "$CL" "${CFLAGS[@]}" -Fo:"$OUT/v54_config_probe.obj" tools/v54_config_probe.cpp
echo "编译 R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp（真代码）"
MSYS_NO_PATHCONV=1 "$CL" "${CFLAGS[@]}" -Fo:"$OUT/r3shieldcore_config.obj" R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp
echo "编译 R3ShieldCore/R3ShieldCore/r3shieldcore_log_replay.cpp（真代码）"
MSYS_NO_PATHCONV=1 "$CL" "${CFLAGS[@]}" -Fo:"$OUT/r3shieldcore_log_replay.obj" R3ShieldCore/R3ShieldCore/r3shieldcore_log_replay.cpp

echo "链接"
MSYS_NO_PATHCONV=1 "$LINK" -nologo \
    "$OUT/v54_config_probe.obj" \
    "$OUT/r3shieldcore_config.obj" \
    "$OUT/r3shieldcore_log_replay.obj" \
    -OUT:"$OUT/v54_config_probe.exe" \
    -SUBSYSTEM:CONSOLE -MACHINE:X64 \
    kernel32.lib user32.lib advapi32.lib shell32.lib psapi.lib

echo "--> $OUT/v54_config_probe.exe"
