#!/usr/bin/env bash
#
# build_screen_image_ut.sh —— 编译并运行「截屏替换外部图片源」单测（v134）。
#
# 它**不挂 hook、不注入、不经过引擎**：只调生产头 `screen_spoof_image.h`
# 里的函数，用真 GDI + 真 BMP 文件验"图片真的被画上去了"。
# 所以不需要 MinHook，也不需要管理员。
#
# 用法:
#   bash build_screen_image_ut.sh          # 只编译
#   bash build_screen_image_ut.sh --run    # 编译并运行
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

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释。
# ★ `-MT -DNDEBUG` 与 build_cfgtool.sh 对齐（理由见 build_spoof_all_rules_ut.sh）。
CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -DNDEBUG -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 v134_screen_image_ut.cpp [$ARCH] ==="
"$CL" $CFLAGS \
    -I R3ShieldCore/shared \
    -I R3ShieldCore/shared/libraries \
    -I R3ShieldCore/R3ShieldCoreLib \
    -Fo"obj/probe/v134_screen_image_ut.$ARCH.obj" \
    "tools/v134_screen_image_ut.cpp" || exit 1

echo "=== 链接 ==="
# ★ gdi32.lib 必须有（StretchBlt / GetDIBits / CreateCompatibleBitmap）。
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/v134_screen_image_ut.exe" \
    "obj/probe/v134_screen_image_ut.$ARCH.obj" \
    kernel32.lib user32.lib gdi32.lib || exit 1

echo "BUILD OK -> tools/v134_screen_image_ut.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    ./tools/v134_screen_image_ut.exe
fi
