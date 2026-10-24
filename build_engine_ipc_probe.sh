#!/usr/bin/env bash
#
# 编译 tools/engine_ipc_probe.cpp —— v89「引擎 ⇄ 界面」加密命名管道端到端探针。
#
# 用法：
#   bash build_engine_ipc_probe.sh [x64|x86]
#   _t/engine_ipc_probe/engine_ipc_probe.exe --launch "R3ShieldCore/Release/r3shieldcore-engine.exe"
#   _t/engine_ipc_probe/engine_ipc_probe.exe --neg ...     # 反向对照（必须报失败）
#
# ★ 探针必须**提权**跑：管道 DACL 只授 SYSTEM + Administrators（那是判据之一）。
#   提权转发用 tools/run_elevated.exe：
#     tools/run_elevated.exe _t/engine_ipc_probe/out.log \
#         _t/engine_ipc_probe/engine_ipc_probe.exe --launch ...
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

# ★ 宽字面量闸门：探针的输出走 UTF-8 显式转换，但源码里仍有中文注释/宽串，
#   编不进 CP936 的字符会在 MSVC 那边悄悄变成 `?`（铁律 226/244）。
if ! "$PYTHON" tools/check_source_gbk.py --wide R3ShieldCore/shared/r3shieldcore/engine_ipc.h; then
    echo "GBK 宽闸门未过，停止编译"; exit 1
fi

r3sc_export_msvc_env "$ARCH"

HOST_BIN="Hostx64/x64"; MACHINE="X64"
if [ "$ARCH" = "x86" ]; then HOST_BIN="Hostx64/x86"; MACHINE="X86"; fi
CL="$MSVC_ROOT/bin/$HOST_BIN/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST_BIN/link.exe"

# ★ `-execution-charset:utf-8` 是**必须**的（本项目其它脚本都没加）：
#   探针把控制台切到 CP_UTF8，并且用 `U8()` 把宽串转成 UTF-8 打印。
#   如果窄字面量还按默认执行字符集（CP936）编，中英文会混着两种编码输出 ⇒
#   一半乱码。两个字符集都定成 UTF-8，整份输出才是同一种字节流。
CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -W3 -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE -source-charset:utf-8 -execution-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"
INC="-I R3ShieldCore/shared"

OUT="_t/engine_ipc_probe"
mkdir -p "$OUT"

echo "编译 tools/engine_ipc_probe.cpp ($ARCH)"
"$CL" $CFLAGS $INC -Fo"$OUT/engine_ipc_probe.obj" tools/engine_ipc_probe.cpp || exit 1

echo "链接"
MSYS_NO_PATHCONV=1 "$LINK" -nologo \
    -SUBSYSTEM:CONSOLE \
    -MACHINE:"$MACHINE" \
    -OUT:"$OUT/engine_ipc_probe.exe" \
    "$OUT/engine_ipc_probe.obj" \
    kernel32.lib advapi32.lib bcrypt.lib crypt32.lib \
    || exit 1

echo "--> $OUT/engine_ipc_probe.exe"
