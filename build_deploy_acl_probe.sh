#!/usr/bin/env bash
#
# build_deploy_acl_probe.sh —— 编译「部署 ACL 判据」探针。
#
# 探针回答一个问题：**引擎会不会加载这个部署目录里的 DLL**。
# 过不去的话引擎会抛异常直接退出，屏幕上只留一行 Refusing to load...，
# 用户看到的是"双击 → 一闪 → 零防护"。
#
# ★ 探针与引擎共用 `R3ShieldCore/R3ShieldCore/engine_deploy_acl.h`
#   —— 同一份实现，不是复制。所以探针的结论就是引擎的结论。
#
# 用法:
#   bash build_deploy_acl_probe.sh                    # 编译 + 查默认路径
#   bash build_deploy_acl_probe.sh <目录 或 .dll>     # 编译 + 查指定路径
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

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

# 共用判据头在 R3ShieldCore/R3ShieldCore/ 下。
INCS="-IR3ShieldCore/R3ShieldCore"

mkdir -p obj/probe

echo "=== 编译 deploy_acl_probe.cpp ==="
"$CL" $CFLAGS $INCS -Fo"obj/probe/deploy_acl_probe.obj" "tools/deploy_acl_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/deploy_acl_probe.exe" \
    "obj/probe/deploy_acl_probe.obj" kernel32.lib advapi32.lib || exit 1

echo ""
echo "=== 运行 ==="
if [ "$#" -gt 0 ]; then
    "./tools/deploy_acl_probe.exe" "$1" --no-pause
else
    "./tools/deploy_acl_probe.exe" --no-pause
fi
exit $?
