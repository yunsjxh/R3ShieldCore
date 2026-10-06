#!/usr/bin/env bash
# 编译 drvload_probe.cpp —— 内核驱动加载实证探针（直调 cl.exe/link.exe，不用 MSBuild）
#
# 为什么用 requireAdministrator：
#   建内核服务 / 复制到 System32\drivers 都需要管理员。
#   没有它就只能靠外层提权，容易踩"提权后工作目录变了"的坑。
#   注意：requireAdministrator 的程序**不能从 bash 直接起**（会 err=740），
#   测试时必须用 explorer 双击、或 PowerShell Start-Process -Verb RunAs（铁律 130）。
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

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

cd "$PROJECT_ROOT" || exit 1

# ---- 预检：源码里不能有 CP936 编不出的字符（铁律 46，否则静默丢字）----
if [ -f tools/check_source_gbk.py ]; then
    if ! python tools/check_source_gbk.py tools/drvload_probe.cpp; then
        echo "BUILD FAILED (预检：源码字符集)"
        exit 1
    fi
fi

mkdir -p obj/drvload

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

echo "=== 编译 drvload_probe.cpp ==="
"$CL" $CFLAGS -Fo"obj/drvload/drvload_probe.obj" "tools/drvload_probe.cpp" || exit 1

echo "=== 链接（嵌入 requireAdministrator manifest）==="
# ★ -MANIFESTUAC:NO 必须加：否则 link 会**自动生成**一份 asInvoker 的 UAC 片段，
#   和我们的 requireAdministrator 片段冲突，mt.exe 报 c1010001（level 不一致）。
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/drvload_probe.exe" \
    -MANIFEST:EMBED -MANIFESTUAC:NO -MANIFESTINPUT:tools/drvload_probe.manifest \
    "obj/drvload/drvload_probe.obj" advapi32.lib wevtapi.lib kernel32.lib user32.lib || exit 1

echo "=== 完成 ==="
ls -la tools/drvload_probe.exe
