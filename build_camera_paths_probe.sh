#!/usr/bin/env bash
#
# build_camera_paths_probe.sh —— 编译「摄像头其余取帧路径」可行性探针（v75 预研）。
#
# 回答 DirectShow / VFW / WinRT MediaCapture 三条盲区"能不能替换"。
# 探针自包含（自己挂自己的 vtable patch），不注入、不跑引擎 ⇒ 不受铁律 175 约束。
#
# 用法:
#   bash build_camera_paths_probe.sh               # 只编译
#   bash build_camera_paths_probe.sh --run         # 编译后跑（不开硬件）
#   bash build_camera_paths_probe.sh --run-camera  # 编译后跑（--use-camera，真开摄像头）
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

cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

# ★ 编之前先过 GBK 闸门（窄字面量里的 ⇒ 之类会静默丢字符，铁律 133）。
if [ -f tools/check_source_gbk.py ]; then
    if ! python tools/check_source_gbk.py tools/camera_paths_probe.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
fi

echo "=== 编译 camera_paths_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" \
    -Fo"obj/probe/camera_paths_probe.$ARCH.obj" \
    "tools/camera_paths_probe.cpp" || exit 1

echo "=== 链接 ==="
# strmiids.lib = DirectShow 的 CLSID/IID 静态库；vfw32.lib = avicap32 的导入库；
# ole32 = CoCreateInstance；oleaut32 = VARIANT。
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/camera_paths_probe.exe" \
    "obj/probe/camera_paths_probe.$ARCH.obj" \
    "$MH_LIB_REL" \
    strmiids.lib vfw32.lib ole32.lib oleaut32.lib user32.lib advapi32.lib gdi32.lib || exit 1

echo "BUILD OK -> tools/camera_paths_probe.exe"

case "${1:-}" in
    --run)
        echo ""
        echo "=== 运行（不开硬件）==="
        MSYS_NO_PATHCONV=1 ./tools/camera_paths_probe.exe
        ;;
    --run-camera)
        echo ""
        echo "=== 运行（--use-camera，会真开摄像头）==="
        MSYS_NO_PATHCONV=1 ./tools/camera_paths_probe.exe --use-camera
        ;;
esac
