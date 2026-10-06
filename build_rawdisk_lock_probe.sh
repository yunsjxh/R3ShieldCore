#!/usr/bin/env bash
#
# build_rawdisk_lock_probe.sh —— 编译「裸盘独占锁」可行性探针。
#
# 探针**只打开、绝不写盘**（真写 = 当场毁引导区）。
# ★ 必须以管理员身份运行才有结论（非管理员会 SKIP 并返回 2）。
#
# 用法:
#   bash build_rawdisk_lock_probe.sh           # 编译 + 试着运行
#   bash build_rawdisk_lock_probe.sh --quick   # 只试只读独占 + 0 号盘
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


r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"

cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 rawdisk_lock_probe.cpp ==="
"$CL" $CFLAGS -Fo"obj/probe/rawdisk_lock_probe.obj" "tools/rawdisk_lock_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/rawdisk_lock_probe.exe" \
    "obj/probe/rawdisk_lock_probe.obj" kernel32.lib advapi32.lib || exit 1

echo "=== 运行（当前 shell 是否管理员取决于启动方式）==="
"./tools/rawdisk_lock_probe.exe" "$@"
rc=$?

echo
echo "★ 如果上面显示 SKIP/非管理员：请在资源管理器里右键 tools\\rawdisk_lock_probe.exe"
echo "  -> 以管理员身份运行，才能得到结论。"
exit $rc
