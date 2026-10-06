#!/usr/bin/env bash
#
# 文件操作监控三模式验收（干净版）。
#
# 依次切 LOG / BLOCK / ASK，各跑一次 filetest 探针，记录事件日志。
#
# 关键：**不排除探针程序** —— 它的写入正是被验证对象。
# 探针的 stdout 是控制台（不是管道），所以不会被 NtWriteFile 的
# 非文件对象过滤误伤；即使被拦也只是打印失败，不影响判定。
#
# 需要临时打开 hook_file，跑完自动恢复 r3shieldcore.ini。
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
#   本脚本位于 tools/ 子目录，向上找到含 scripts_env.sh 的仓库根。
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"
ROOT="$PROJECT_ROOT"
REL="$ROOT/R3ShieldCore/Release"
INI="$REL/r3shieldcore.ini"
EXE="$REL/R3 ShieldCore.exe"
PROBE="$ROOT/tools/filetest.exe"
TARGET_DIR="$ROOT/facc"
TARGET_WIN="$PROJECT_ROOT/facc"

cp "$INI" "$INI.accbak"

set_mode() {
    local mode="$1"
    sed -i "s/^mode=.*/mode=$mode/" "$INI"
    sed -i "s/^hook_file=.*/hook_file=1/" "$INI"
}

run_case() {
    local mode="$1"
    echo ""
    echo "############ [$mode] 模式 ############"
    set_mode "$mode"
    rm -rf "$TARGET_DIR"; mkdir -p "$TARGET_DIR"

    "$EXE" > "$REL/engine_acc_$mode.log" 2>&1 &
    sleep 6

    echo "--- 探针输出 ---"
    timeout 40 "$PROBE" "$TARGET_WIN" 2>&1 | head -12

    sleep 2
    taskkill //F //IM "R3 ShieldCore.exe" >/dev/null 2>&1
    sleep 1

    echo "--- facc 事件 ---"
    grep "facc" "$REL/r3shieldcore-events.log" 2>/dev/null | tail -14
}

run_case log
: > "$REL/r3shieldcore-events.log" 2>/dev/null
run_case block
: > "$REL/r3shieldcore-events.log" 2>/dev/null
run_case ask

echo ""
echo "############ 恢复配置 ############"
taskkill //F //IM "R3 ShieldCore.exe" >/dev/null 2>&1
cp "$INI.accbak" "$INI"
rm -f "$INI.accbak"
rm -rf "$TARGET_DIR"
grep -v "^#" "$INI" | grep -v "^$"
echo "验收完成。"
