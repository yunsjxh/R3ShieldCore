#!/usr/bin/env bash
#
# build_r3shot.sh —— 编译通用截图器 `tools/r3shot.exe`。
#
# 它是什么：把屏幕上的任意矩形（窗口 / 客户区 / 全屏 / 鼠标拖框）存成图片。
# 与 `build_gui_preview_probe.sh` 的分工见 `tools/r3shot.cpp` 开头：
#   那个是**闸门**（自己拉起 exe、自己断言），这个是**量尺**（抓你眼前那一下）。
#
# ★ 不注入、不启动任何被测进程、不跑引擎（铁律 175 不适用）。
#
# 用法:
#   bash build_r3shot.sh              # 默认 x64
#   ARCH=x86 bash build_r3shot.sh     # 32 位
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
#   本工具的窄字面量全是 ASCII（输出走 UTF-8 直出），所以两道闸门都应当直接过；
#   留着是因为**将来**有人往 Usage() 里加中文就会踩到。
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门 ==="
    if ! python tools/check_source_gbk.py tools/r3shot.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
    if ! python tools/check_source_gbk.py --wide tools/r3shot.cpp; then
        echo "GBK 宽闸门未过，停止编译"; exit 1
    fi
fi

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，不指定的话 UTF-8 字节
#   会被按 CP936 解码，**吞掉后面的行**（症状是莫名其妙的"标识符找不到"）。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 r3shot.cpp [$ARCH] ==="
"$CL" $CFLAGS -Fo"obj/probe/r3shot.obj" "tools/r3shot.cpp" || exit 1

echo "=== 链接 ==="
# user32    = EnumWindows / GetWindowRect / SetWindowDisplayAffinity 相关
# gdi32     = CreateDIBSection / BitBlt / CreatePatternBrush
# gdiplus   = 写 PNG（与 tools/bmp2png.cpp 同一条路）
# msimg32   = AlphaBlend（交互模式把选区外压暗）
# ole32     = GDI+ 内部用 COM
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/r3shot.exe" \
    "obj/probe/r3shot.obj" \
    kernel32.lib user32.lib gdi32.lib gdiplus.lib msimg32.lib ole32.lib || exit 1

echo "BUILD OK -> tools/r3shot.exe"
