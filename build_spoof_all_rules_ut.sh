#!/usr/bin/env bash
#
# build_spoof_all_rules_ut.sh —— 编译「全都换一遍」夹具（spoof_all_rules_ut）。
#
# 这个夹具**不挂 hook、不注入、不经过引擎** —— 它只调生产 codec
# （`rules_codec.h` / `spoof_apply_codec.h` / `clipboard_spoof_codec.h`），
# 所以不需要 MinHook，也不需要管理员。
#
# 用法:
#   bash build_spoof_all_rules_ut.sh              # 编译
#   bash build_spoof_all_rules_ut.sh --run        # 编译后用默认规则文件跑
#   bash build_spoof_all_rules_ut.sh --run <规则文件>
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
if [ "$ARCH" = "x64" ]; then HOST="Hostx64/x64"; else HOST="Hostx64/x86"; fi
r3sc_export_msvc_env "$ARCH"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 必须有：源码里有中文，不指定会按 CP936 解码并吞行。
# ★★ `-MT -DNDEBUG -std:c++20` 与 `build_cfgtool.sh` **逐项对齐**，不是抄格式：
#    实测 `-O2 -MT` **不带** `-DNDEBUG` 时，只 include 这两个 codec 头的最小 TU
#    就会 `fatal error C1060: 编译器的堆空间不足`（在 regex / algorithm / xlocale
#    之间随机报，看着像"内存不够"，其实是这组开关下的实例化把 cl 的堆吃穿）。
#    加 `-DNDEBUG` 或降到 `-O1` 都能编过；cfg 用的正是 `-O2 -MT -DNDEBUG`。
CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -DNDEBUG -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 spoof_all_rules_ut.cpp [$ARCH] ==="
"$CL" $CFLAGS \
    -I R3ShieldCore/shared \
    -I R3ShieldCore/shared/libraries \
    -I R3ShieldCore/R3ShieldCoreLib \
    -Fo"obj/probe/spoof_all_rules_ut.obj" \
    "tools/spoof_all_rules_ut.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_all_rules_ut.exe" \
    "obj/probe/spoof_all_rules_ut.obj" \
    kernel32.lib user32.lib advapi32.lib || exit 1

echo "BUILD OK -> tools/spoof_all_rules_ut.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    if [ -n "${2:-}" ]; then
        ./tools/spoof_all_rules_ut.exe "$2"
    else
        ./tools/spoof_all_rules_ut.exe
    fi
fi
