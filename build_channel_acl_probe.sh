#!/usr/bin/env bash
# 编译 tools/channel_acl_probe.cpp —— 复现并验证「共享通道 ACL 把交互用户挤掉」。
#
# 用法：
#   bash build_channel_acl_probe.sh          # 只跑 A/B（纯 ACL 对照）
#   bash build_channel_acl_probe.sh c        # 再跑 C：加载真实 DLL 端到端验证
#
# 必须在**非提权**进程里跑，否则旧式 ACL 的 (A;;GA;;;BA) 会放行，A 步复现不出。
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
INCS="-IR3ShieldCore/shared -IR3ShieldCore/shared/libraries"

mkdir -p obj/probe

echo "=== 编译 channel_acl_probe.cpp ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/channel_acl_probe.obj" "tools/channel_acl_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"_t/channel_acl_probe.exe" \
    "obj/probe/channel_acl_probe.obj" \
    kernel32.lib advapi32.lib wtsapi32.lib || exit 1

echo "=== 运行 ==="
"./_t/channel_acl_probe.exe" "${1:-}"
