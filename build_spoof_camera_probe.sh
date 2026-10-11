#!/usr/bin/env bash
#
# build_spoof_camera_probe.sh —— 编译「摄像头帧替换」**可行性**探针。
#
# 背景：v67 屏幕 / v70 剪贴板 / v71 注册表值 都落地了，**摄像头面（§8 Phase 2）
#       还没动**。它与前三个面的根本差别是：
#         · **流式**（一帧一帧地来），不是单次调用；
#         · 帧数据在 `IMFSample` 里，而 `IMFSourceReader::ReadSample` **不是导出函数**
#           ⇒ 只能走 **vtable patch**；
#         · "中性值"**与子类型有关**：RGB 全 0 是黑，但 **YUV 全 0 不是黑**（是饱和色）。
#
# ★★ 本机**不一定有摄像头**，所以探针用**合成媒体源**（自己写一个最小 WAV）
#    来验证**机制链**（vtable patch → detour 被调用 → `IMFSample` 缓冲区原地改写
#    → 调用方看得见）。采样器换成视频帧源时，前两层**完全相同**。
#    探针同时会**勘察并如实报告**本机有没有视频采集设备。
#
# ⚠️ 探针只读自己进程内自己创建的媒体源，不打开摄像头、不注入任何进程、
#    不经过引擎 ⇒ **不受**「本机禁止运行引擎」那条约束（铁律 175）。
#
# 用法:
#   bash build_spoof_camera_probe.sh          # 只编译
#   bash build_spoof_camera_probe.sh --run    # 编译后跑一次
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

# ★ 多架构脚本必须两架构都真编（库路径用当前 $arch，不能写 ${ARCH:-x64}）。
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
# ★ `-IR3ShieldCore/R3ShieldCoreLib`：探针要 `#include "camera_spoof_codec.h"`
#   —— **生产与探针共用同一份**中性帧决策表（铁律 195：同一份逻辑别抄两份）。
#   这条 -I 就是"共用"的载体：改一处，两边同时变。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS -IR3ShieldCore/R3ShieldCoreLib"

mkdir -p obj/probe

echo "=== 编译 spoof_camera_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -Fo"obj/probe/spoof_camera_probe.obj" \
    "tools/spoof_camera_probe.cpp" || exit 1

echo "=== 链接 ==="
# Media Foundation: mfplat(启动/属性) + mfreadwrite(源读取器) + mfuuid(媒体类型 GUID)
#   ★ MFEnumDeviceSources 在 **mf.lib**（由 mf.dll 导出、转发到 mfcore.dll），
#     不在 mfplat.lib —— 漏了它会 LNK2019。
# psapi: GetModuleInformation（vtable 前提检查）
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_camera_probe.exe" \
    "obj/probe/spoof_camera_probe.obj" \
    kernel32.lib ole32.lib mfplat.lib mfreadwrite.lib mfuuid.lib mf.lib psapi.lib || exit 1

echo "BUILD OK -> tools/spoof_camera_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_camera_probe.exe
fi
