#!/usr/bin/env bash
#
# build_verify_dist.sh —— 发布闸门：验证**随包 r3shieldcore.ini** 真的解析成预期模式。
#
# 用途：每次出包前跑一次。它把 `tools/verify_dist_ini.cpp` 与**真实的**
#       `r3shieldcore_config.cpp`（引擎侧同一个解析器）链起来，对 `dist/R3ShieldCore-x64`
#       里的 ini 跑一次 `R3ShieldCoreConfig::Load`，断言 mode 解析为 block。
#
#   ★ 光"看一遍 ini"证明不了引擎认不认（铁律 17：看真实现，不看 grep）。
#
# 用法: bash build_verify_dist.sh [x64|x86] [ini目录]
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
INI_DIR="${2:-dist/R3ShieldCore-x64}"

if [ "$ARCH" = "x64" ]; then HOST="Hostx64/x64"; else HOST="Hostx64/x86"; fi

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

OBJDIR_REL="obj/verify-dist-$ARCH"
mkdir -p "$OBJDIR_REL"

CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

echo "=== 编译 verify_dist_ini + r3shieldcore_config [$ARCH] ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/verify_dist_ini.obj" "tools/verify_dist_ini.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_config.obj" \
    "R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp" || exit 1

"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/verify_dist_ini.exe" \
    "$OBJDIR_REL/verify_dist_ini.obj" "$OBJDIR_REL/r3shieldcore_config.obj" \
    kernel32.lib || exit 1

echo ""
"./tools/verify_dist_ini.exe" "$INI_DIR"
exit $?
