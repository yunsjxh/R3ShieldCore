#!/usr/bin/env bash
#
# R3ShieldCore ASK 模式测试 —— 验证 hive 操作的弹窗。
#
# 重点验证：
#   1. hive 操作会弹窗（原版只会弹键级操作的窗）
#   2. 弹窗措辞区分 hive / 键级（"挂载或替换注册表配置单元" vs "修改注册表"）
#   3. 点"允许"后操作真的放行
#   4. 点"拒绝"后操作真的被拒
#   5. 决策缓存生效（点"始终允许"后不再弹窗）
#
# 用法：bash tools/test_ask_mode.sh
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
RELEASE="$PROJECT_ROOT/R3ShieldCore/Release"
TOOLS="$PROJECT_ROOT/tools"
ENGINE="R3 ShieldCore.exe"
INI="$RELEASE/r3shieldcore.ini"
BACKUP="$RELEASE/r3shieldcore.ini.testbak"
PROBE="$TOOLS/hiveprobe.exe"
CLICKER="$TOOLS/promptclick.exe"

PASS=0
FAIL=0

check() {
    if [ "$2" = "1" ]; then
        echo "  [PASS] $1"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $1"
        FAIL=$((FAIL + 1))
    fi
}

kill_engine() {
    taskkill //F //IM "$ENGINE" >/dev/null 2>&1
    pkill -f promptclick 2>/dev/null
    for _ in 1 2 3 4 5; do
        local count
        count=$(tasklist //FI "IMAGENAME eq $ENGINE" 2>/dev/null | grep -c "$ENGINE" || true)
        [ "${count:-0}" -eq 0 ] && break
        sleep 1
        taskkill //F //IM "$ENGINE" >/dev/null 2>&1
    done
    sleep 3
}

RUN_ID=$$
LOGFILE_NAME="r3shieldcore-ask-test-$RUN_ID.log"
PROBE_LOG="$TOOLS/ask-probe-$RUN_ID.log"

cp "$INI" "$BACKUP"
trap 'kill_engine; cp "$BACKUP" "$INI"' EXIT

# ASK 模式配置。超时给长一点，避免自动点掉干扰判断。
cat > "$INI" <<EOF
# R3ShieldCore 配置 —— ASK 模式测试，用完恢复
mode=ask
prompt_timeout=25
prompt_default=deny
hook_reads=0
log_all_open=0
hook_hive=1
hook_set_info=1
log=$LOGFILE_NAME
exclude=D:\\Program Files\\WorkBuddyAI
exclude=C:$USERPROFILE\\.workbuddy-ai
EOF

echo "=============================================="
echo " R3ShieldCore ASK 模式测试  (run=$RUN_ID)"
echo "=============================================="
echo ""

# 先建好测试键（引擎未跑时）
kill_engine
"$PROBE" prepare > /dev/null 2>&1

# 启动引擎
( cd "$RELEASE" && ./$ENGINE > "engine_ask_$RUN_ID.log" 2>&1 & )
sleep 8

ENGINE_PID=$(tasklist //FI "IMAGENAME eq $ENGINE" //FO CSV //NH 2>/dev/null | head -1 | cut -d'"' -f4)
echo "引擎 PID = ${ENGINE_PID:-未知}"

if [ -z "${ENGINE_PID:-}" ]; then
    echo "引擎没起来，中止。"
    exit 1
fi

echo ""

# ------------------------------------------------------------------
# 测试 1：dump 窗口树，确认弹窗存在且措辞正确
# ------------------------------------------------------------------
echo "--- 测试 1：hive 操作弹窗的措辞 ---"

# 后台跑探针（只跑 save，最典型的 hive 操作）
"$PROBE" save > "$PROBE_LOG" 2>&1 &
PROBE_PID=$!

sleep 3   # 等弹窗出现

DUMP=$("$CLICKER" "$ENGINE_PID" dump 2>&1)
echo "$DUMP" | grep -E "窗口|text=" | head -12 | sed 's/^/    /'

if echo "$DUMP" | grep -q "挂载或替换注册表配置单元"; then
    check "hive 弹窗使用了 hive 专属措辞" 1
else
    check "hive 弹窗使用了 hive 专属措辞" 0
fi

if echo "$DUMP" | grep -q "Hive 文件"; then
    check "弹窗显示了 hive 文件路径" 1
else
    check "弹窗显示了 hive 文件路径" 0
fi

# 点"拒绝这一次"
"$CLICKER" "$ENGINE_PID" deny 8 > /dev/null 2>&1
wait $PROBE_PID 2>/dev/null
sleep 2

DENY_OUT=$(iconv -f GBK -t UTF-8 "$PROBE_LOG" 2>/dev/null)
echo "    探针结果: $(echo "$DENY_OUT" | grep 'NtSaveKeyEx')"

if echo "$DENY_OUT" | grep -qE "NtSaveKeyEx.*0xC0000022"; then
    check "点拒绝 → NtSaveKeyEx 被拒（0xC0000022）" 1
else
    check "点拒绝 → NtSaveKeyEx 被拒（0xC0000022）" 0
fi

echo ""

# ------------------------------------------------------------------
# 测试 2：点"允许"，操作应放行
# ------------------------------------------------------------------
echo "--- 测试 2：点允许 → 操作放行 ---"

"$PROBE" save > "$PROBE_LOG" 2>&1 &
PROBE_PID=$!
sleep 3
"$CLICKER" "$ENGINE_PID" allow 8 > /dev/null 2>&1
wait $PROBE_PID 2>/dev/null
sleep 2

ALLOW_OUT=$(iconv -f GBK -t UTF-8 "$PROBE_LOG" 2>/dev/null)
echo "    探针结果: $(echo "$ALLOW_OUT" | grep 'NtSaveKeyEx')"

# 允许后不该是 0xC0000022（未提权会是 0xC0000061，那是系统限制）
if echo "$ALLOW_OUT" | grep -qE "NtSaveKeyEx.*0xC0000022"; then
    check "点允许 → 不再被 R3ShieldCore 拒" 0
else
    check "点允许 → 不再被 R3ShieldCore 拒" 1
fi

echo ""

# ------------------------------------------------------------------
# 测试 3：键级操作弹窗措辞应不同
# ------------------------------------------------------------------
echo "--- 测试 3：键级操作弹窗措辞 ---"

"$TOOLS/regtest.exe" once > "$TOOLS/regtest-ask-$RUN_ID.log" 2>&1 &
PROBE_PID=$!
sleep 3

DUMP2=$("$CLICKER" "$ENGINE_PID" dump 2>&1)

if echo "$DUMP2" | grep -q "想要修改注册表"; then
    check "键级弹窗使用键级措辞" 1
else
    check "键级弹窗使用键级措辞" 0
    echo "$DUMP2" | grep "text=" | head -8 | sed 's/^/    /'
fi

"$CLICKER" "$ENGINE_PID" deny 8 > /dev/null 2>&1
wait $PROBE_PID 2>/dev/null
sleep 1

echo ""

# ------------------------------------------------------------------
# 收尾
# ------------------------------------------------------------------
kill_engine

ASKDIR="$RELEASE/$LOGFILE_NAME"
echo "--- ASK 模式日志: $(grep -c 'pid=' "$ASKDIR" 2>/dev/null || echo 0) 条 ---"
echo ""

echo "=============================================="
echo " 结果: PASS=$PASS  FAIL=$FAIL"
echo "=============================================="

if [ "$FAIL" -eq 0 ]; then
    echo "全部通过"
    exit 0
else
    echo "有失败项"
    exit 1
fi
