#!/usr/bin/env bash
#
# build_sync_inject_probe.sh —— 编译「同步注入自锁」端到端探针（v46 起，v49 起判定改三态）。
#
# 探针验证的是：**全量注入的父进程**拉子进程时，引擎自己的注入写入
# （VirtualAllocEx / WriteProcessMemory / VirtualProtectEx / CreateRemoteThread
#   **以及 v48 补上的 NtQueueApcThread**）会不会被自己的内存/线程/宿主劫持钩子拦掉
#   —— 拦掉的话同步注入路就静默退化成轮询路，甚至（v47 的 fail-closed）把子进程终结掉。
#
# ★ v48 起：探针同时把执行轨迹写进 exe 同目录的 `probe-trace.log`
#   —— 窗口空白/输出被吞时靠它区分"没进 main"还是"只是没打印"。
#
# ★ v49 起：
#   ① 读日志改用 `CreateFileA(READ, FILE_SHARE_READ|FILE_SHARE_WRITE)`。
#      原来用 `fopen_s(..., "rb")`（共享模式不含 `FILE_SHARE_WRITE`），
#      在"引擎正持写句柄"时必然 `ERROR_SHARING_VIOLATION(32)` ⇒ 真机上表现为
#      `起始偏移: 0` + 「日志读不到，跳过」—— **却照样判 PASS**。
#   ② 判定从两态改**三态**：PASS(exit 0) / FAIL(exit 1) / **无法判定(exit 2)**。
#      "读不到日志"绝不再算 PASS（那是假绿）。
#   ③ `probe-trace.log` 建不出来时回退 `%TEMP%\R3ShieldCoreProbeTrace.log`
#      （发布目录是加固的，标准用户写不进去），横幅打印**实际**路径。
#
# ★ v50 起（用户 v49 真机实测暴露：引擎没跑却照样打印 PASS）：
#   ① 日志路径的候选 2 原来**硬编码** `..\dist\R3ShieldCore-x64\`（无版本后缀）。
#      项目现在有 `R3ShieldCore-x64-v49` 这类带版本的部署目录 ⇒ 从 tools/ 跑时
#      落到**老目录** ⇒ `起始偏移 == 文件大小`（扫 0 字节）⇒ 三条 [OK] 是空扫。
#      ⇒ 改成枚举 `..\dist\R3ShieldCore-x64*`，取 `r3shieldcore-events.log` **mtime 最新**的。
#   ② 判定**完全不看前提**：子进程 `blocked=no` = HKCU Run 写成功 = 它没装 hook
#      ⇒ "引擎没拦自己的注入写入"是废话。原判定只看 `bad`/`unreadable` ⇒
#      **引擎没跑也照样 PASS**。
#      ⇒ 从 `probe-trace.log`（只扫本轮新增字节，防 pid 回收）取每个子进程的
#        `blockedEver`；**一个都没被拦** ⇒ 判定 = **无法判定(2)**。
#      ⇒ 返回值是**读到的行数**（不是被拦数），"解析坏了"和"真没被拦"要能分开。
#   ③ 打印 `日志最后写入: N 分钟前` + `本轮日志增长: N 字节`
#      —— 0 增长 = 引擎没在写这个文件 = 本次核对是空扫（直接暴露"读错目录"）。
#
# ★ 用法：先启动引擎（dist/R3ShieldCore-x64-v49/start.bat，要管理员），
#   然后**双击** tools/sync_inject_probe.exe。
#   从 cmd 里敲也能测（cmd 同样是被注入的），但双击更贴近真实场景。
#
# 用法:
#   bash build_sync_inject_probe.sh          # 只编译
#   bash build_sync_inject_probe.sh --run    # 编译后在本 shell 里跑一次（--no-pause）
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

echo "=== 编译 sync_inject_probe.cpp ==="
"$CL" $CFLAGS -Fo"obj/probe/sync_inject_probe.obj" "tools/sync_inject_probe.cpp" || exit 1

echo "=== 链接 ==="
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/sync_inject_probe.exe" \
    "obj/probe/sync_inject_probe.obj" \
    kernel32.lib advapi32.lib || exit 1

echo "BUILD OK -> tools/sync_inject_probe.exe"
echo ""
echo "★ 下一步：先启动引擎，再**双击** tools/sync_inject_probe.exe"
echo "  期望：3 个子进程都 blockedAtMs=0，且日志核对 PASS"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 在当前 shell 里跑一次（--no-pause）==="
    MSYS_NO_PATHCONV=1 ./tools/sync_inject_probe.exe --no-pause
fi
