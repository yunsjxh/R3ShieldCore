#!/usr/bin/env bash
#
# build_hive_read_probe.sh —— 编译「hive 文件直读可行性」探针（v75 预研）。
#
# 这个探针回答**一个**问题：活 hive（已被系统加载的那个文件）能不能被用户态
# 程序当**文件**打开 / 读 / 内存映射？答案决定了"hive 直读"这条绕过路要不要做：
#   · 打不开 ⇒ 活系统上走不通 ⇒ 该面不必做（与"文件内容"同族的淘汰结论）；
#   · 打得开、甚至能映射 ⇒ 真实绕过路，且映射后无 API 可拦 ⇒ 用户态拦不住。
#
# ★ 探针**不挂 hook**（所以不链 MinHook）、不注入、不跑引擎 ⇒ 不受铁律 175 约束。
#   它只读，只在自己 %TEMP% 下建普通文件做基线。
#
# 用法:
#   bash build_hive_read_probe.sh          # 只编译
#   bash build_hive_read_probe.sh --run    # 编译后跑一次
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"

# ★ 多架构脚本必须两架构都真编。
ARCH="${ARCH:-x64}"
if [ "$ARCH" = "x64" ]; then
    HOST="Hostx64/x64"
else
    HOST="Hostx64/x86"
fi

r3sc_export_msvc_env "$ARCH"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

# ★ 编之前先过 GBK 闸门：窄字面量里的 `⇒` 之类字符在 CP936 下**静默丢字符**
#   （铁律 133）。本文件第一版就踩过 —— 20 处 `⇒` 全被吞。
if [ -f tools/check_source_gbk.py ]; then
    if ! python tools/check_source_gbk.py tools/hive_read_probe.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
fi

echo "=== 编译 hive_read_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS \
    -Fo"obj/probe/hive_read_probe.$ARCH.obj" \
    "tools/hive_read_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/hive_read_probe.exe" \
    "obj/probe/hive_read_probe.$ARCH.obj" \
    kernel32.lib advapi32.lib user32.lib || exit 1

echo "BUILD OK -> tools/hive_read_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（只读，不挂 hook、不跑引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/hive_read_probe.exe
fi
