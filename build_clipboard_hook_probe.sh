#!/usr/bin/env bash
#
# build_clipboard_hook_probe.sh —— 编译「hook_clipboard 开关是否真生效」探针。
#
# 背景：`hook_clipboard=0` 生效的表现是「**什么都没发生**」——
#       既没有运行时事件，那条 `LOG()` 又只走 OutputDebugString **不落文件**。
#       所以必须直接读被注入进程里 `user32!GetClipboardData` 的**首字节**
#       看 MinHook 到底挂了没有（在场证据，铁律 59）。
#
# 用法:
#   bash build_clipboard_hook_probe.sh          # 只编译
#   bash build_clipboard_hook_probe.sh --run    # 编译后跑一次 --report（基线）
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


r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

# 项目根含中文，必须 cd 进去用相对路径（铁律 46 同族：直接传中文绝对路径会踩坑）。
cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，
#   不指定的话 UTF-8 字节会被按 CP936 解码，**吞掉后面的 `#include` 行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 clipboard_hook_probe.cpp ==="
"$CL" $CFLAGS -Fo"obj/probe/clipboard_hook_probe.obj" "tools/clipboard_hook_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/clipboard_hook_probe.exe" \
    "obj/probe/clipboard_hook_probe.obj" \
    kernel32.lib || exit 1

echo "BUILD OK -> tools/clipboard_hook_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 基线（无引擎，应当全部 NOT-HOOKED）==="
    MSYS_NO_PATHCONV=1 ./tools/clipboard_hook_probe.exe --report --tag "[base] "
fi
