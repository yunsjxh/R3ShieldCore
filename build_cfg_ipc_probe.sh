#!/usr/bin/env bash
#
# 编译 tools/cfg_ipc_probe.cpp —— v81「配置工具 ⇄ 引擎」管道协议**端到端**夹具。
#
# 它**不跑引擎**（铁律 175）：夹具自己起一个"假引擎"服务端，
# 用共享头里与生产**同一份**的编解码；再用生产客户端代码去连它。
#
# 用法：
#   bash build_cfg_ipc_probe.sh [x64|x86]
#   _t/cfg_ipc_probe/cfg_ipc_probe.exe          # 正常跑（应全过）
#   _t/cfg_ipc_probe/cfg_ipc_probe.exe --neg    # 反向对照（应报失败 ⇒ 判据有分辨力）
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

ARCH="${1:-x64}"
case "$ARCH" in
    x64|x86) ;;
    *) echo "架构只支持 x64 / x86（收到：$ARCH）"; exit 1 ;;
esac

cd "$PROJECT_ROOT" || { echo "找不到项目目录"; exit 1; }

# ★ 宽字面量闸门：协议头里的中文/符号会经 CP_ACP 输出（控制台夹具直接 printf）。
#   不接进构建 ⇒ 下次改动又会悄悄引入 CP936 编不出的字符（铁律 226/244）。
if ! "$PYTHON" tools/check_source_gbk.py --wide R3ShieldCore/shared/r3shieldcore/cfg_ipc.h; then
    echo "GBK 宽闸门未过，停止编译"; exit 1
fi

r3sc_export_msvc_env "$ARCH"

HOST_BIN="Hostx64/x64"; MACHINE="X64"
if [ "$ARCH" = "x86" ]; then HOST_BIN="Hostx64/x86"; MACHINE="X86"; fi
CL="$MSVC_ROOT/bin/$HOST_BIN/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST_BIN/link.exe"

CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -W3 -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"
INC="-I R3ShieldCore/shared"

OUT="_t/cfg_ipc_probe"
mkdir -p "$OUT"

echo "编译 tools/cfg_ipc_probe.cpp ($ARCH)"
"$CL" $CFLAGS $INC -Fo"$OUT/cfg_ipc_probe.obj" tools/cfg_ipc_probe.cpp || exit 1

echo "链接"
MSYS_NO_PATHCONV=1 "$LINK" -nologo \
    -SUBSYSTEM:CONSOLE \
    -MACHINE:"$MACHINE" \
    -OUT:"$OUT/cfg_ipc_probe.exe" \
    "$OUT/cfg_ipc_probe.obj" \
    kernel32.lib advapi32.lib \
    || exit 1

echo "--> $OUT/cfg_ipc_probe.exe"
