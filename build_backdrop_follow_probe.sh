#!/usr/bin/env bash
#
# build_backdrop_follow_probe.sh —— 编译「玻璃跟不跟背景」的探针。
#
# 它是什么：
#   在窗口背后放一块纯色窗口，换色 / 移动窗口，各抓一次屏幕，
#   量出**面板、字段到底有没有跟着背景变**。回答的是
#   「文字的背景为什么拖了也不变」这类问题 —— 靠截图看不出来。
#
# ★ 不注入、不跑引擎（cfg 用 `--page 0` 起，只建窗）。
#
# 用法:
#   bash build_backdrop_follow_probe.sh
#   tools/backdrop_follow_probe.exe
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
else
    HOST="Hostx64/x86"
fi

r3sc_export_msvc_env "$ARCH"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★ GBK 闸门（铁律 46/226）：源码里有中文注释和中文输出。
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门 ==="
    if ! python tools/check_source_gbk.py tools/backdrop_follow_probe.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
fi

# `-source-charset:utf-8` 必须有：不指定的话 UTF-8 字节按 CP936 解码，
# **吞掉后面的行**（症状是莫名其妙的"标识符找不到"）。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"
INC="-I R3ShieldCore/shared"

mkdir -p obj/probe

echo "=== 编译 backdrop_follow_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS $INC -Fo"obj/probe/backdrop_follow_probe.obj" \
    "tools/backdrop_follow_probe.cpp" || exit 1

echo "=== 链接 ==="
# user32 = EnumWindows / SetWindowPos / CreateWindowExW
# gdi32  = CreateDIBSection / BitBlt / CreateCompatibleDC
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/backdrop_follow_probe.exe" \
    "obj/probe/backdrop_follow_probe.obj" \
    kernel32.lib user32.lib gdi32.lib || exit 1

echo "BUILD OK -> tools/backdrop_follow_probe.exe"
