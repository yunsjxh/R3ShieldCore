#!/usr/bin/env bash
#
# build_rawdisk_probe.sh —— 编译并运行裸盘写入拦截探针。
#
# 探针本身**只做打开、不写盘**（安全），不需要链规则层。
# 详见 tools/rawdisk_probe.cpp 顶部的安全说明。
#
# 用法:
#   bash build_rawdisk_probe.sh          # 编译 + 运行
#   bash build_rawdisk_probe.sh --help   # 看探针的判据说明
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

# 同 build.sh：项目根含中文，必须 cd 进去用相对路径。
cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 rawdisk_probe.cpp ==="
"$CL" $CFLAGS -Fo"obj/probe/rawdisk_probe.obj" "tools/rawdisk_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/rawdisk_probe.exe" \
    "obj/probe/rawdisk_probe.obj" kernel32.lib advapi32.lib || exit 1

echo "=== 运行 ==="
"./tools/rawdisk_probe.exe" "$@"
