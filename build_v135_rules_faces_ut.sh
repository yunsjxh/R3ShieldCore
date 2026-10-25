#!/usr/bin/env bash
#
# build_v135_rules_faces_ut.sh —— 编译并运行「规则表文件/截屏两个面」单测（v135）。
#
# 它**不挂 hook、不注入、不经过引擎**：只调共享 codec（rules_codec.h），纯逻辑。
# 所以不需要 MinHook，也不需要管理员。
#
# 用法:
#   bash build_v135_rules_faces_ut.sh          # 只编译
#   bash build_v135_rules_faces_ut.sh --run    # 编译并运行
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

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释与中文规则字面量。
CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -DNDEBUG -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 v135_rules_faces_ut.cpp [$ARCH] ==="
"$CL" $CFLAGS \
    -I R3ShieldCore/shared \
    -I R3ShieldCore/shared/libraries \
    -Fo"obj/probe/v135_rules_faces_ut.$ARCH.obj" \
    "tools/v135_rules_faces_ut.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/v135_rules_faces_ut.exe" \
    "obj/probe/v135_rules_faces_ut.$ARCH.obj" \
    kernel32.lib || exit 1

echo "BUILD OK -> tools/v135_rules_faces_ut.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    ./tools/v135_rules_faces_ut.exe
fi
