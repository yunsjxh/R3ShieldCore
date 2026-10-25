#!/usr/bin/env bash
#
# build_spoof_file_probe.sh —— 编译「文件读替换」验证探针（v133）。
#
# ★★ 探针**不抄**替换逻辑 —— 直接 `#include "file_spoof_codec.h"`，
#    与生产 `file_guard.cpp` 用同一份代码（铁律 127）。
#    所以本脚本必须把 `R3ShieldCore/R3ShieldCoreLib` 加进包含路径。
#
# 探针是**自包含**的（自己挂自己的 NtReadFile detour），不注入任何进程、
# 不经过引擎、只碰自己在 %TEMP% 下建的两个小文件 ⇒ 不受
# 「自动化脚本不得运行引擎」那条约束（铁律 175）。
#
# 用法:
#   bash build_spoof_file_probe.sh          # 只编译
#   bash build_spoof_file_probe.sh --run    # 编译后跑一次
#
set -u

R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"

ARCH="${ARCH:-x64}"
if [ "$ARCH" = "x64" ]; then
    HOST="Hostx64/x64"
    MH_LIB="libMinHook.x64.lib"
else
    HOST="Hostx64/x86"
    MH_LIB="libMinHook.x86.lib"
fi

r3sc_export_msvc_env "$ARCH"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

MH_LIB_REL="R3ShieldCore/R3ShieldCoreLib/libraries/MinHook/$MH_LIB"
MH_INC_REL="R3ShieldCore/R3ShieldCoreLib/libraries/MinHook"
CODEC_INC_REL="R3ShieldCore/R3ShieldCoreLib"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，
#   不指定的话 UTF-8 字节会被按 CP936 解码，**吞掉后面的行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 spoof_file_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -I"$CODEC_INC_REL" \
    -Fo"obj/probe/spoof_file_probe.obj" \
    "tools/spoof_file_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_file_probe.exe" \
    "obj/probe/spoof_file_probe.obj" \
    "$MH_LIB_REL" \
    kernel32.lib || exit 1

echo "BUILD OK -> tools/spoof_file_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_file_probe.exe
fi
