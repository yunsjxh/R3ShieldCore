#!/usr/bin/env bash
#
# R3ShieldCore acceptance test.
#
# Runs all three modes and prints raw evidence:
#   A. LOG   - are non-system programs' registry writes recorded?
#   B. BLOCK - system programs unaffected / non-system programs denied?
#   C. ASK   - does the prompt appear, and does clicking "always allow" work?
#
# Note: this script's own output is ASCII on purpose. The console code page is
# CP936 while bash emits UTF-8, so Chinese echoed from bash would be mojibake.
# Output from the Windows test binaries is fine either way.
#
# Usage: bash acceptance_test.sh
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
REG="$PROJECT_ROOT/R3ShieldCore/Release"
TOOLS="$PROJECT_ROOT/tools"
ENGINE="$REG/R3 ShieldCore-x86.exe"
PROBE="$TOOLS/regtest.exe"
CLICKER="$TOOLS/promptclick.exe"
LOG="$REG/r3shieldcore-events.log"

PASS=0
FAIL=0

check() {
    if [ "$2" = "$3" ]; then
        printf '  [PASS] %-44s = %s\n' "$1" "$3"
        PASS=$((PASS + 1))
    else
        printf '  [FAIL] %-44s expected %s, got %s\n' "$1" "$2" "$3"
        FAIL=$((FAIL + 1))
    fi
}

write_ini() {
    : > "$REG/r3shieldcore.ini"
    for line in "$@"; do
        printf '%s\n' "$line" >> "$REG/r3shieldcore.ini"
    done
}

start_engine() {
    rm -f "$LOG"
    "$ENGINE" > "$REG/engine.log" 2>&1 &
    sleep 12
    ENGINE_PID=$(tasklist //FI "IMAGENAME eq R3 ShieldCore-x86.exe" //FO CSV //NH 2>/dev/null \
        | head -1 | cut -d, -f2 | tr -d '"')
}

stop_engine() {
    taskkill //F //IM promptclick.exe //T >/dev/null 2>&1
    taskkill //F //IM "R3 ShieldCore-x86.exe" //T >/dev/null 2>&1
    sleep 2
}

reset_test_key() {
    reg delete "HKCU\Software\R3ShieldCoreTest" //f >/dev/null 2>&1
}

echo "==============================================="
echo " R3ShieldCore acceptance test   $(date '+%Y-%m-%d %H:%M:%S')"
echo "==============================================="

# ---------------------------------------------------------------------
echo ""
echo "### A. LOG mode - are non-system registry writes recorded?"
# ---------------------------------------------------------------------
# Whitelist is off for this case so long-running apps also fall in scope.
write_ini "mode=log" "hook_reads=0"
reset_test_key
start_engine

"$PROBE" once > "$TOOLS/probe.log" 2>&1
sleep 6

TOTAL=$(wc -l < "$LOG" 2>/dev/null || echo 0)
PROBE_PID=$(grep -o "pid=[0-9]*" "$TOOLS/probe.log" | head -1 | cut -d= -f2)
PROBE_HITS=$(grep -cE "pid=$PROBE_PID " "$LOG" 2>/dev/null || true)
PROCS=$(grep -o "pid=[0-9]*" "$LOG" 2>/dev/null | sort -u | wc -l)

stop_engine

echo "  engine pid          : $ENGINE_PID"
echo "  probe pid           : $PROBE_PID"
echo "  total events        : $TOTAL"
echo "  distinct processes  : $PROCS"
echo "  events from probe   : $PROBE_HITS"
echo "  probe's record      :"
grep -E "pid=$PROBE_PID " "$LOG" 2>/dev/null | head -2 | sed 's/^/    /'
check "non-system writes are recorded" "1" "$([ "$PROBE_HITS" -ge 1 ] && echo 1 || echo 0)"
check "multiple processes are monitored" "1" "$([ "$PROCS" -ge 2 ] && echo 1 || echo 0)"

# ---------------------------------------------------------------------
echo ""
echo "### B. BLOCK mode - system program vs non-system program"
# ---------------------------------------------------------------------
write_ini "mode=block" "hook_reads=0"
reset_test_key
start_engine

# system program: reg.exe lives in System32
reg add "HKCU\Software\R3ShieldCoreTest" //v FromSystem //t REG_SZ //d ok //f >/dev/null 2>&1
SYS_RC=$?

# non-system program: the probe lives outside C:\Windows
"$PROBE" once > "$TOOLS/probe.log" 2>&1
PROBE_RC=$(grep -oE 'RegCreateKeyEx +-> [0-9]+' "$TOOLS/probe.log" | head -1 | grep -oE '[0-9]+$')
PROBE_RC=${PROBE_RC:-0}

stop_engine

echo "  system program reg.exe exit code : $SYS_RC   (0 = unaffected)"
echo "  non-system probe return code     : $PROBE_RC   (5 = ERROR_ACCESS_DENIED)"
echo "  probe output:"
sed 's/^/    /' "$TOOLS/probe.log"
check "system program unaffected" "0" "$SYS_RC"
check "non-system program denied" "5" "$PROBE_RC"

# ---------------------------------------------------------------------
echo ""
echo "### C. ASK mode - prompt appears, click always-allow"
# ---------------------------------------------------------------------
write_ini "mode=ask" "prompt_timeout=25" "prompt_default=deny" "hook_reads=0"
reset_test_key
rm -f "$TOOLS/click.log"
start_engine

"$CLICKER" "$ENGINE_PID" allowalways 30 > "$TOOLS/click.log" 2>&1 &

T0=$(date +%s)
"$PROBE" > "$TOOLS/probe.log" 2>&1
T1=$(date +%s)
ELAPSED=$((T1 - T0))

stop_engine

# Count from the per-click lines: the clicker is killed before it can print
# its final summary, so "total clicks" is never emitted.
CLICKS=$(grep -c 'clicking' "$TOOLS/click.log" 2>/dev/null || true)
OP_OK=$(grep -cE '\-> 0$' "$TOOLS/probe.log" || true)
ALLOW_LINES=$(grep -c 'ALLOW' "$LOG" 2>/dev/null || true)

echo "  probe elapsed       : ${ELAPSED}s"
echo "  clicks              : $CLICKS"
echo "  operations allowed  : $OP_OK / 4"
echo "  probe output:"
sed 's/^/    /' "$TOOLS/probe.log"
echo "  click log:"
sed 's/^/    /' "$TOOLS/click.log"
check "prompt was clicked" "1" "$([ "$CLICKS" -ge 1 ] && echo 1 || echo 0)"
check "all 4 ops allowed after clicking" "4" "$OP_OK"

# ---------------------------------------------------------------------
echo ""
echo "==============================================="
echo " RESULT: PASS=$PASS  FAIL=$FAIL"
echo "==============================================="

# restore the default config
cat > "$REG/r3shieldcore.ini" <<'INI'
# R3ShieldCore 配置
#
# mode: log = 只记录、全部放行；block = 拒绝写操作；ask = 弹窗询问
mode=log
#
# ask 模式的询问超时（秒）与超时后的兜底结论：deny / allow
prompt_timeout=30
prompt_default=deny
#
# 连读操作一起记录（噪音极大，默认关）
hook_reads=0
#
# NtOpenKey 无论读写意图都记录（默认只记带写意图的打开）
log_all_open=0
#
# 排除路径，前缀匹配，可重复。命中则一个 hook 都不挂（零开销）。
exclude=D:\Program Files\WorkBuddyAI
exclude=$USERPROFILE\.workbuddy-ai
INI

reset_test_key
echo ""
echo "Default config restored (mode=log + WorkBuddy whitelist). Test key removed."
exit "$FAIL"
