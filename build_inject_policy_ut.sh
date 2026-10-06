#!/usr/bin/env bash
#
# build_inject_policy_ut.sh —— 只编/跑 `inject_policy` 的分类表单测（v42）。
#
# 为什么单独一个脚本：`build_ut.sh` 要跑二十多个套件（40+ 秒），
# 改 `inject_policy.cpp` 时想秒级看到结果就得有个单件入口。
# 正式回归仍然走 `build_ut.sh`（它已把本套件包含在内）。
#
# ★ `inject_policy.cpp` **故意零依赖**（不 include stdafx、不碰 Policy/共享内存），
#   所以这里只链它自己 + kernel32。
#
# 用法:
#   bash build_inject_policy_ut.sh
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
r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

OBJDIR="tools/ut-obj-$ARCH"
mkdir -p "$OBJDIR"

echo "=== 编译 inject_policy.cpp + inject_policy_ut.cpp [$ARCH] ==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR/inject_policy.obj" \
    "R3ShieldCore/R3ShieldCoreLib/inject_policy.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR/inject_policy_ut.obj" "tools/inject_policy_ut.cpp" || exit 1

echo "=== 链接（只链 kernel32）==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/inject_policy_ut.exe" \
    "$OBJDIR/inject_policy_ut.obj" "$OBJDIR/inject_policy.obj" kernel32.lib || exit 1

echo ""
"./tools/inject_policy_ut.exe"
