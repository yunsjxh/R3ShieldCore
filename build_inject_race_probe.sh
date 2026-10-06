#!/usr/bin/env bash
#
# build_inject_race_probe.sh —— 编译「注入盲区」实测探针。
#
# 探针量的是：**进程启动 → R3ShieldCore hook 生效** 之间的时间窗
# （样本 Windows XP Horror 就在这个窗口里写 MBR）。
#
# ★ 探针必须**双击**运行（或右键→以管理员身份运行），
#   不要从 cmd / powershell 里敲 —— 那些父进程已被注入，会走同步路，
#   盲区恒为 0，测不出问题。详见 tools/inject_race_probe.cpp 顶部。
#
# 用法:
#   bash build_inject_race_probe.sh          # 只编译
#   bash build_inject_race_probe.sh --run    # 编译后在本 shell 里跑一次
#                                            #（⚠️ 这次跑出来的是"同步路"结果，仅验证能跑）
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

echo "=== 编译 inject_race_probe.cpp ==="
"$CL" $CFLAGS -Fo"obj/probe/inject_race_probe.obj" "tools/inject_race_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/inject_race_probe.exe" \
    "obj/probe/inject_race_probe.obj" \
    kernel32.lib advapi32.lib shell32.lib || exit 1

echo "BUILD OK -> tools/inject_race_probe.exe"
echo ""
echo "★ 下一步：在资源管理器里**双击** tools/inject_race_probe.exe"
echo "  （或右键 → 以管理员身份运行，才能测第 2 组裸盘）"
echo "  ⚠️ 不要从 cmd / powershell 启动 —— 父进程已被注入，会走同步路、盲区恒为 0。"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 在当前 shell 里跑一次（仅验证能运行；结果不是真实盲区）==="
    MSYS_NO_PATHCONV=1 ./tools/inject_race_probe.exe --no-pause
fi
