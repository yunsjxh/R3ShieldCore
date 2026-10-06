#!/usr/bin/env bash
#
# build_rg_arch_probes.sh —— 编译一对架构探针：rg32probe.exe / rg64probe.exe。
#
# ★ 为什么要成对：
#   "32 位进程没有事件"这个症状有两种完全不同的解释 ——
#     (a) 32 位注入坏了（DLL 路径 / WOW64 处理）
#     (b) 引擎压根没在注入任何进程
#   只有配上**同源码、同目录、只差架构**的 64 位对照，
#   才能在日志里把两者分开（铁律 54：不做 A/B = 没测）。
#
# ★ 历史事故（2026-10-05 定位）：
#   发布包把 x86 DLL 放在 `64\R3ShieldCoreLib-x86.dll`，而
#   `dll_inject.cpp:409` 要的是 `<部署根>\32\r3shieldcore-lib.dll`
#   （`GetEnginePath()` 只返回 `32`/`64` **目录**名）。
#   ⇒ 32 位注入**一直静默失败**，且**零提示**。
#
# 用法: bash build_rg_arch_probes.sh
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
#   本脚本可能位于仓库根或子目录（driver/ installer/ tools/），
#   所以向上找到含 scripts_env.sh 的目录（= 仓库根）。
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"


cd "$PROJECT_ROOT" || exit 1
mkdir -p obj/rgprobe

build_one() {
    local arch="$1" host="$2" expect="$3"
    # ★ 用本函数的 $arch（x86/x64），不能写 ${ARCH:-x64}：
    #   本脚本没有 ARCH 变量，写死 x64 会让 x86 探针链到 x64 库（LNK4272）。
    r3sc_export_msvc_env "$arch"

    local CL="$MSVC_ROOT/bin/Hostx64/$host/cl.exe"
    local LINK="$MSVC_ROOT/bin/Hostx64/$host/link.exe"
    local DUMPBIN="$MSVC_ROOT/bin/Hostx64/$host/dumpbin.exe"

    local out="_t/x86probe/rg32probe.exe"
    [ "$arch" = "x64" ] && out="_t/x86probe/rg64probe.exe"

    echo "=== 编译 rgprobe ($arch) ==="
    "$CL" -nologo -c -O2 -MT -source-charset:utf-8 \
        -Fo"obj/rgprobe/rgprobe-$arch.obj" "_t/x86probe/rg32probe.c" || return 1
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"$out" \
        "obj/rgprobe/rgprobe-$arch.obj" kernel32.lib advapi32.lib user32.lib || return 1

    local machine
    machine="$("$DUMPBIN" -nologo -headers "$out" | grep -i "machine" | head -1)"
    echo "  $machine"
    case "$machine" in
        *"$expect"*) echo "  => 架构正确 ✅" ;;
        *) echo "  => 架构不符（期望含 $expect）❌"; return 1 ;;
    esac
    ls -la "$out"
}

build_one x86  x86  14C   || exit 1
build_one x64  x64  8664  || exit 1
