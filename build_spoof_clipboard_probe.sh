#!/usr/bin/env bash
#
# build_spoof_clipboard_probe.sh —— 编译「剪贴板回传数据替换」验证探针。
#
# 背景：v67 落地了**屏幕**面的替换（黑帧），v70 落地**剪贴板**面。
#       剪贴板与屏幕最大的不同是**句柄所有权**：`GetClipboardData` 返回的
#       是剪贴板拥有的 HANDLE，调用方不得释放 ⇒ 替代物必须由我们在
#       `CloseClipboard` 时回收。这个探针要实证这条契约能闭合。
#
# ★★ 探针**不抄**伪造逻辑 —— 直接 `#include "clipboard_spoof_codec.h"`，
#    与生产 clipboard_guard.cpp 用同一份代码（铁律 127）。
#    所以本脚本必须把 `R3ShieldCore/R3ShieldCoreLib` 加进包含路径。
#
# 探针是**自包含**的（自己挂自己的 hook），不注入任何进程、不经过引擎、
# 不读屏幕、不写盘 —— 只碰自己进程内自己放到剪贴板上的内容。
# 因此**不受**「自动化脚本不得运行引擎」那条约束（铁律 175）。
#
# 用法:
#   bash build_spoof_clipboard_probe.sh          # 只编译
#   bash build_spoof_clipboard_probe.sh --run    # 编译后跑一次
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
    MH_LIB="libMinHook.x64.lib"
else
    HOST="Hostx64/x86"
    MH_LIB="libMinHook.x86.lib"
fi

r3sc_export_msvc_env "$ARCH"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

MH_LIB_REL="R3ShieldCore/R3ShieldCoreLib/libraries/MinHook/$MH_LIB"
MH_INC_REL="R3ShieldCore/R3ShieldCoreLib/libraries/MinHook"
CODEC_INC_REL="R3ShieldCore/R3ShieldCoreLib"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，
#   不指定的话 UTF-8 字节会被按 CP936 解码，**吞掉后面的行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 spoof_clipboard_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -I"$CODEC_INC_REL" \
    -Fo"obj/probe/spoof_clipboard_probe.obj" \
    "tools/spoof_clipboard_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_clipboard_probe.exe" \
    "obj/probe/spoof_clipboard_probe.obj" \
    "$MH_LIB_REL" \
    kernel32.lib user32.lib gdi32.lib || exit 1

echo "BUILD OK -> tools/spoof_clipboard_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_clipboard_probe.exe
fi
