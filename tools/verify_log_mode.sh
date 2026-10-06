#!/usr/bin/env bash
#
# verify_log_mode.sh —— LOG 模式六类监控全覆盖验收。
#
# 依次跑六类探针，确认每类都产生正确的事件记录。
# 用完自动恢复 r3shieldcore.ini。
#
# 注意：探针的 stdout 重定向到文件会产生额外文件事件（噪音），
#       分析时按进程名过滤即可。
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
ENGINE="R3 ShieldCore.exe"
T="$ROOT/tools"
OUT="$T/logrun"
EV="$REL/r3shieldcore-events.log"
DIR="$ROOT/verdir"
STARTUP="$APPDATA/Microsoft/Windows/Start Menu/Programs/Startup"

mkdir -p "$OUT"

kill_engine() {
    taskkill //F //IM "$ENGINE" >/dev/null 2>&1
    sleep 3
}

cp "$INI" "$INI.logbak"
restore() {
    kill_engine
    cp "$INI.logbak" "$INI"
}
trap restore EXIT

kill_engine

cat > "$INI" <<'INIEOF'
mode=log
prompt_timeout=5
prompt_default=deny
high_risk=1
hook_reads=0
log_all_open=0
hook_hive=1
hook_set_info=1
hook_file=1
hook_process=1
hook_thread=1
hook_self_thread=0
hook_driver=1
hook_net=1
hook_dns=1
hook_net_all=1
exclude=D:\Program Files\WorkBuddy
exclude=$USERPROFILE\.workbuddy-ai
exclude=$USERPROFILE\.workbuddy
INIEOF

> "$EV"
mkdir -p "$DIR"

echo "=== 启动引擎 (LOG 模式，六类全开) ==="
( cd "$REL" && ./"$ENGINE" > engine_logrun.log 2>&1 & )
sleep 8
echo "引擎启动完成，日志: $EV"
echo ""

run() {
    local name="$1"; shift
    echo "### $name"
    "$@" > "$OUT/$name.txt" 2>&1
    echo "    exit=$?"
}

run reg_normal    "$T/regtest.exe" hold 3
run reg_highrisk  "$T/hightest.exe" reg 3
run file_normal   "$T/filetest.exe" "$ROOT/verdir" hold 3
run file_highrisk "$T/filetest.exe" "$STARTUP" hold 3
run proc          "$T/proctest.exe" proc 3
run thread        "$T/proctest.exe" thread 3
run driver        "$T/proctest.exe" driver 3
run network       "$T/netprobe.exe" all --hold 3
run hosts_time    "$T/hoststime.exe"
run hive          "$T/hiveprobe.exe"

sleep 3
kill_engine

echo ""
echo "=== 事件日志分类统计（$EV）==="
for k in REG FILE PROC THRD DRV NET; do
    printf "  %-5s %4s 条\n" "$k" "$(grep -cE "\b$k\b" "$EV" 2>/dev/null || echo 0)"
done

echo ""
echo "=== 总记录数 ==="
grep -c "pid=" "$EV" 2>/dev/null || echo 0
echo ""
echo "验收完成（配置已恢复）。"
