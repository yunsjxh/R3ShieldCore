#!/usr/bin/env bash
#
# build_gui_preview_probe.sh —— 编译 `--gui-preview` 的界面核对探针。
#
# 它是什么：
#   拉起**免提权**的主程序（`--gui-preview`，不初始化引擎），从**屏幕 DC**
#   截图，并断言应用自己日志里的「[adv] 页面已绘制」——
#   把"界面画得对不对"从"靠人眼"变成"可复现的判据"（铁律 24/28）。
#
# ★ 不注入、不跑引擎（铁律 175 不适用）。
#
# 用法:
#   bash build_gui_preview_probe.sh          # 只编译
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

# ★ GBK 前置闸门（铁律 46）：窄字面量里 CP936 放不下的字符会被 C4566 静默丢掉。
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门：窄字面量（C4566 编译期丢字）==="
    if ! python tools/check_source_gbk.py tools/gui_preview_probe.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
fi

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，不指定的话 UTF-8 字节
#   会被按 CP936 解码，**吞掉后面的行**（症状是莫名其妙的"标识符找不到"）。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 gui_preview_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -Fo"obj/probe/gui_preview_probe.obj" \
    "tools/gui_preview_probe.cpp" || exit 1

echo "=== 链接 ==="
# user32.lib = EnumWindows / GetWindowRect / BitBlt(与 gdi32)
# gdi32.lib  = CreateDIBSection / BitBlt / CreateCompatibleDC
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/gui_preview_probe.exe" \
    "obj/probe/gui_preview_probe.obj" \
    kernel32.lib user32.lib gdi32.lib || exit 1

echo "BUILD OK -> tools/gui_preview_probe.exe"
