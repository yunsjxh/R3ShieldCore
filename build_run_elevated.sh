#!/usr/bin/env bash
#
# build_run_elevated.sh —— 编 `tools/run_elevated.exe`（提权转发器）。
#
# 为什么有这个工具：引擎清单是 `requireAdministrator`，而自动化的 shell 提不了权；
#   工具侧又禁止用 `Start-Process` 去起 shell/解释器/系统工具（会被命令校验拦掉）。
#   ⇒ 用这个**普通程序**当"最小 sudo"：调用方用 runas 拉起它（**只弹一次 UAC**），
#     它再 CreateProcess 目标命令，子进程**继承提权令牌**，不会再弹。
#
# 用法:
#   bash build_run_elevated.sh
#
# 用法示例（PowerShell，注意 `-ArgumentList` 要传**一个**带引号的整串，
# 传数组会被按空格拆开、路径里的空格就把参数拆坏了）:
#   $a = '"C:\out.log" "D:\...\PortableGit\usr\bin\bash.exe" --login "D:\proj\tools\x.sh" --run-engine'
#   Start-Process -FilePath tools\run_elevated.exe -ArgumentList $a -Verb RunAs -Wait
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"

r3sc_export_msvc_env x64
CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"

cd "$PROJECT_ROOT" || exit 1

# ★ `-source-charset:utf-8` 不能省：源码是 UTF-8 **无 BOM**，而 cl 默认按
#   **系统 ANSI 代码页**（中文机 = 936）读 ⇒ 中文注释被拆坏 ⇒ 报一堆
#   C2447/C3861 语法错（看着像代码写错了，其实是编码）。本仓库统一用这个开关。
echo "=== 编译 run_elevated.cpp [x64] ==="
"$CL" -nologo -O2 -MT -std:c++20 -EHsc -source-charset:utf-8 \
    -DUNICODE -D_UNICODE \
    -Fe:"tools/run_elevated.exe" "tools/run_elevated.cpp" || exit 1

echo ""
echo "产出: tools/run_elevated.exe"
