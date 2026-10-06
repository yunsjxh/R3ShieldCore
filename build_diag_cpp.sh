#!/usr/bin/env bash
# 编译 diag_autostart.cpp —— 原生 C++ 诊断器。
# ★ 铁律 65：直调 link.exe 必须自己管 manifest。
#   这里是**控制台程序**，默认不需要 requireAdministrator；
#   但诊断 Program Files 下的日志要读权限 —— 所以让它**不**强制提权，
#   未提权时日志打不开会给出明确的"请用管理员运行"提示（见源码）。
#   若想要点击即提权，把下面 -MANIFEST:EMBED 那段换成 requireAdministrator 的 rc。
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
mkdir -p obj/diag

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

echo "=== 编译 diag_autostart.cpp ==="
"$CL" $CFLAGS -Fo"obj/diag/diag_autostart.obj" "tools/diag_autostart.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/diag_autostart.exe" \
    -MANIFEST:EMBED -MANIFESTINPUT:tools/diag_autostart.manifest \
    "obj/diag/diag_autostart.obj" advapi32.lib kernel32.lib user32.lib || exit 1

echo "=== 完成 ==="
ls -la tools/diag_autostart.exe
