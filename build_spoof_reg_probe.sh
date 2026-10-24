#!/usr/bin/env bash
#
# build_spoof_reg_probe.sh —— 编译「注册表值替换」验证探针。
#
# 背景：v67 落地**屏幕**面（黑帧），v70 落地**剪贴板**面（中性内容），
#       v71 落地**注册表值**面。注册表与那两个最大的不同是：
#         · 触发面**不是"本应拒绝处"** —— 注册表读本来就不拒（`!blockable`），
#           所以是"**命中 protect_reg 就替换**"；
#         · out 缓冲区是**变长结构**，有**多个**长度字段（DataLength /
#           DataOffset / *ResultLength）—— 改错一个 ⇒ 调用方读越界 ⇒ 宿主崩溃。
#       设计对策 = **长度字段一个都不改，只把数据字节清零**。
#       这个探针要实证"长度不变、数据全 0"这条性质。
#
# ★★ 探针**不抄**清零逻辑 —— 直接 `#include "registry_spoof_codec.h"`，
#    与生产 registry_guard.cpp 用同一份代码（铁律 195 / 127）。
#    所以本脚本必须把 `R3ShieldCore/R3ShieldCoreLib` 加进包含路径。
#
# 探针是**自包含**的（自己挂自己的 hook），不注入任何进程、不经过引擎、
# 不读屏幕；只在 HKCU 下建一个临时键、结束时删掉。
# 因此**不受**「自动化脚本不得运行引擎」那条约束（铁律 175）。
#
# 用法:
#   bash build_spoof_reg_probe.sh          # 只编译
#   bash build_spoof_reg_probe.sh --run    # 编译后跑一次
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

# ★ 多架构脚本必须两架构都真编（见记忆铁律：写死 ${ARCH:-x64} 会让 x86 链 x64 库）。
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

echo "=== 编译 spoof_reg_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -I"$CODEC_INC_REL" \
    -Fo"obj/probe/spoof_reg_probe.obj" \
    "tools/spoof_reg_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_reg_probe.exe" \
    "obj/probe/spoof_reg_probe.obj" \
    "$MH_LIB_REL" \
    kernel32.lib advapi32.lib || exit 1

echo "BUILD OK -> tools/spoof_reg_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_reg_probe.exe
fi
