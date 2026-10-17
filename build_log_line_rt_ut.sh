#!/usr/bin/env bash
#
# 编译 tools/log_line_rt_ut.cpp —— v81「事件日志行唯一实现 + 管道协议编解码」单测。
#
# 链接的是**真代码**（r3shieldcore_stats.cpp + r3shieldcore_log_replay.cpp），
# 不是复制一份逻辑 —— 否则"单测绿了但引擎不绿"（铁律 22 家族）。
#
# 用法：
#   bash build_log_line_rt_ut.sh [x64|x86]            # 编译
#   _t/log_line_rt_ut/log_line_rt_ut.exe [events.log] # 运行（可选：真实日志语料）
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

ARCH="${1:-x64}"
case "$ARCH" in
    x64|x86) ;;
    *) echo "架构只支持 x64 / x86（收到：$ARCH）"; exit 1 ;;
esac

cd "$PROJECT_ROOT" || { echo "找不到项目目录"; exit 1; }

r3sc_export_msvc_env "$ARCH"

# ★ 多架构脚本必须两架构都真编（铁律：只编一个架构等于没验证另一个）
HOST_BIN="Hostx64/x64"
MACHINE="X64"
if [ "$ARCH" = "x86" ]; then
    HOST_BIN="Hostx64/x86"
    MACHINE="X86"
fi
CL="$MSVC_ROOT/bin/$HOST_BIN/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST_BIN/link.exe"

# ★ -source-charset:utf-8：源码里全是中文注释，不加会被按当前代码页读
#   （踩过：注释被拆成两行 ⇒ C2018/C3872 一堆语法错，而报错行号指向别处）。
CFLAGS="-nologo -c -std:c++20 -EHsc -O2 -MT -W3 -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"
INC="-I R3ShieldCore/shared -I R3ShieldCore/shared/libraries -I R3ShieldCore/R3ShieldCore"

OUT="_t/log_line_rt_ut"
mkdir -p "$OUT"

echo "编译 tools/log_line_rt_ut.cpp ($ARCH)"
"$CL" $CFLAGS $INC -Fo"$OUT/log_line_rt_ut.obj" tools/log_line_rt_ut.cpp || exit 1

echo "编译 R3ShieldCore/R3ShieldCore/r3shieldcore_log_replay.cpp（真代码）"
"$CL" $CFLAGS $INC -Fo"$OUT/r3shieldcore_log_replay.obj" \
    R3ShieldCore/R3ShieldCore/r3shieldcore_log_replay.cpp || exit 1

echo "编译 R3ShieldCore/R3ShieldCore/r3shieldcore_stats.cpp（真代码）"
"$CL" $CFLAGS $INC -Fo"$OUT/r3shieldcore_stats.obj" \
    R3ShieldCore/R3ShieldCore/r3shieldcore_stats.cpp || exit 1

echo "链接"
MSYS_NO_PATHCONV=1 "$LINK" -nologo \
    -SUBSYSTEM:CONSOLE \
    -MACHINE:"$MACHINE" \
    -OUT:"$OUT/log_line_rt_ut.exe" \
    "$OUT/log_line_rt_ut.obj" \
    "$OUT/r3shieldcore_log_replay.obj" \
    "$OUT/r3shieldcore_stats.obj" \
    kernel32.lib user32.lib advapi32.lib shell32.lib psapi.lib \
    || exit 1

echo "--> $OUT/log_line_rt_ut.exe"
