#!/usr/bin/env bash
#
# build_elev_probe.sh —— 编译「引擎能不能拦管理员程序」探针的两个变体。
#
#   tools/elevprobe-user.exe   清单 asInvoker           -> 双击不弹 UAC（普通用户）
#   tools/elevprobe-admin.exe  清单 requireAdministrator -> 双击必弹 UAC（管理员）
#
# 两个变体**同一份源码**，只有链接时的 /MANIFESTUAC 不同 —— 这是刻意的：
# 变量只有"提权与否"一个，否则测出来的差异说不清是谁造成的。
#
# 用法:
#   bash build_elev_probe.sh           # 编译 + 核验清单
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

echo "=== 编译 elevprobe.cpp ==="
"$CL" $CFLAGS -Fo"obj/probe/elevprobe.obj" "tools/elevprobe.cpp" || exit 1

echo "=== 链接 user 变体（asInvoker）==="
# ★ `-MANIFEST:EMBED` 不能省：直接调 link.exe 时**默认不嵌清单**，
#   只写 `-MANIFESTUAC:` 会被静默忽略 —— 两个变体产出**字节数完全相同**、
#   都不含 `<assembly>`，提权变体双击也不弹 UAC（= 测了个寂寞）。
#   本仓主引擎的清单是走 rsrc/*.manifest + rc.exe 那条路，这里是纯 link 路。
"$LINK" -nologo -SUBSYSTEM:CONSOLE -MANIFEST:EMBED \
    -MANIFESTUAC:"level='asInvoker'" \
    -OUT:"tools/elevprobe-user.exe" \
    "obj/probe/elevprobe.obj" kernel32.lib advapi32.lib || exit 1

echo "=== 链接 admin 变体（requireAdministrator）==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -MANIFEST:EMBED \
    -MANIFESTUAC:"level='requireAdministrator'" \
    -OUT:"tools/elevprobe-admin.exe" \
    "obj/probe/elevprobe.obj" kernel32.lib advapi32.lib || exit 1

echo ""
echo "=== 核验清单（必须一 user 一 admin，且两个文件不同）==="
LEVEL_USER=""
LEVEL_ADMIN=""
for variant in user admin; do
    exe="tools/elevprobe-$variant.exe"
    level=$(python - "$exe" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
found = []
for tag in (b'requireAdministrator', b'asInvoker', b'highestAvailable'):
    if tag in data:
        found.append(tag.decode())
print(','.join(found) if found else '(none)')
PY
)
    echo "  elevprobe-$variant.exe  ->  $level"
    if [ "$variant" = "user" ]; then LEVEL_USER="$level"; else LEVEL_ADMIN="$level"; fi
done

if [ "$LEVEL_USER" != "asInvoker" ] || [ "$LEVEL_ADMIN" != "requireAdministrator" ]; then
    echo ""
    echo "!!! 清单核验失败：user=$LEVEL_USER  admin=$LEVEL_ADMIN"
    echo "    （两个变体必须一个是 asInvoker、一个是 requireAdministrator；"
    echo "      否则'提权'这个变量根本没生效，测出来的差异不可信）"
    exit 1
fi
echo "  [OK] 两个变体的清单确实是 asInvoker / requireAdministrator"

echo ""
echo "BUILD OK"
echo ""
echo "★ 下一步（照这个顺序，一步都不能省）："
echo "  0) 引擎**先停掉**，双击 tools/elevprobe-user.exe  -> 步骤[1] 必须返回 0"
echo "     （这一步是反向对照：证明这个键普通用户本来就能写，"
echo "      后面的 5 才有意义）"
echo "  1) 启动引擎（dist/R3ShieldCore-x64/start.bat，要管理员），确认 mode=block"
echo "  2) 双击 tools/elevprobe-user.exe   -> 步骤[1] 期望 5"
echo "  3) 双击 tools/elevprobe-admin.exe  -> 步骤[1] 期望 5  ★ 这就是答案"
echo "  4) 每步都看输出头部的「引擎 DLL: 已加载/未加载」"
echo "     未加载 = 本次结论无效，先查 r3shieldcore-console.log"
