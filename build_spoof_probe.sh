#!/usr/bin/env bash
#
# build_spoof_probe.sh —— 编译「拦截并替换回传数据」验证探针。
#
# 背景：产品里 17 个 guard 的 detour 只有两条返回路径（Block = 伪造失败 /
#       Pass·Record = 原样返回真实结果），**没有任何一处改写回传数据**。
#       这个探针要实证：detour 内「真调原函数 → 改写 out 缓冲区 → 返回成功」
#       在本机到底行不行，以及「只替换一条获取路径会不会被另一条戳穿」。
#
# 探针是**自包含**的（自己挂自己的 hook），不注入任何进程、不经过引擎、
# 不读屏幕、不写盘 —— 只碰自己进程内自己创建的位图。
# 因此**不受**「本机禁止运行引擎」那条约束（铁律 175）。
#
# 用法:
#   bash build_spoof_probe.sh          # 只编译
#   bash build_spoof_probe.sh --run    # 编译后跑一次
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

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，
#   不指定的话 UTF-8 字节会被按 CP936 解码，**吞掉后面的行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 spoof_retdata_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -Fo"obj/probe/spoof_retdata_probe.obj" \
    "tools/spoof_retdata_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_retdata_probe.exe" \
    "obj/probe/spoof_retdata_probe.obj" \
    "$MH_LIB_REL" \
    kernel32.lib user32.lib gdi32.lib || exit 1

echo "BUILD OK -> tools/spoof_retdata_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_retdata_probe.exe
fi
