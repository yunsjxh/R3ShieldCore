#!/usr/bin/env bash
#
# build_spoof_e2e.sh —— 编译端到端验证的「被注入目标」进程。
#
# 与 build_spoof_probe.sh 的区别：
#   · 探针是**自挂自测**（自己 hook 自己），不经过引擎 —— 验的是"机制行不行"；
#   · 本目标是**真的等着被引擎注入**，走真的截屏路径 —— 验的是"产品链路行不行"。
#
# ⚠️ 它本身**不 hook 任何东西**（不需要 MinHook），所以编译很简单。
# ⚠️ 两个架构都编：引擎是 x64 的（`R3 Shield Core.exe`），但保留 x86 产物
#    是为了将来验 32 位链路；runner 默认只用 x64。
#
# 用法:
#   bash build_spoof_e2e.sh          # 编译 x64 + x86
#   ARCH=x64 bash build_spoof_e2e.sh # 只编 x64
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

cd "$PROJECT_ROOT" || exit 1

# 两个架构都编（除非 ARCH 指定了单个）。
ARCHES="${ARCH:-x64 x86}"
[ "$ARCHES" = "x64" ] && ARCHES="x64"
[ "$ARCHES" = "x86" ] && ARCHES="x86"

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

fail=0
for arch in $ARCHES; do
    if [ "$arch" = "x64" ]; then
        HOST="Hostx64/x64"
        OUT="tools/spoof_e2e_target.exe"
    else
        HOST="Hostx64/x86"
        OUT="tools/spoof_e2e_target-x86.exe"
    fi

    r3sc_export_msvc_env "$arch"
    CL="$MSVC_ROOT/bin/$HOST/cl.exe"
    LINK="$MSVC_ROOT/bin/$HOST/link.exe"

    echo "=== 编译 spoof_e2e_target.cpp [$arch] ==="
    "$CL" $CFLAGS -Fo"obj/probe/spoof_e2e_target.$arch.obj" \
        "tools/spoof_e2e_target.cpp" || { fail=1; continue; }

    echo "=== 链接 [$arch] ==="
    # ★ v74：多了注册表面（`RegOpenKeyExW` / `RegQueryValueExW` / `RegCloseKeyW`）
    #   ⇒ 必须加 `advapi32.lib`。剪贴板面用的 `GlobalAlloc` 在 kernel32 里。
    "$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"$OUT" \
        "obj/probe/spoof_e2e_target.$arch.obj" \
        kernel32.lib user32.lib gdi32.lib advapi32.lib || { fail=1; continue; }

    echo "  -> $OUT"
done

if [ "$fail" -ne 0 ]; then
    echo "BUILD FAILED"
    exit 1
fi

echo "BUILD OK -> tools/spoof_e2e_target.exe"
