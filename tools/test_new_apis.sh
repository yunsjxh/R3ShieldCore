#!/usr/bin/env bash
#
# R3ShieldCore 新功能测试脚本。
#
# 自动跑三组场景：
#   1. LOG 模式   —— 新 API 是否被记录
#   2. BLOCK 模式 —— 新 API 是否被拦（码值从 0xC0000061 变 0xC0000022）
#   3. 开关关闭   —— hook_hive=0 时新 API 是否真的完全不挂
#
# 用完自动恢复原来的 r3shieldcore.ini。
#
# 用法：bash tools/test_new_apis.sh
#
# 注意：不要用 rm 清理日志文件 —— 本机的 safe-delete 会拦，
# 导致脚本静默中断。改用"每次生成带序号的新文件名"。
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

PASS=0
FAIL=0

check() {
    local name="$1"
    local result="$2"
    if [ "$result" = "1" ]; then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name"
        FAIL=$((FAIL + 1))
    fi
}

# 杀引擎并确认真的退干净（否则残留引擎会污染下一场景的结论）。
kill_engine() {
    taskkill //F //IM "$ENGINE" >/dev/null 2>&1
    for _ in 1 2 3 4 5; do
        local count
        count=$(tasklist //FI "IMAGENAME eq $ENGINE" 2>/dev/null | grep -c "$ENGINE" || true)
        [ "${count:-0}" -eq 0 ] && break
        sleep 1
        taskkill //F //IM "$ENGINE" >/dev/null 2>&1
    done
    # 引擎卸载需要时间，等 hooks 从各进程里撤干净
    sleep 3
    return 0
}

start_engine() {
    local tag="$1"
    # 用子 shell 切目录，不污染调用方的 cwd ——
    # 否则后面的 ./hiveprobe.exe 会在 Release 目录下找不到文件。
    ( cd "$RELEASE" && ./$ENGINE > "engine_test_$tag.log" 2>&1 & )
    # 等引擎注入存量进程。引擎主循环是 1 秒一轮，
    # 注入所有存量进程大致需要 3-6 秒，给足余量。
    sleep 8
}

write_ini() {
    local mode="$1"
    local logfile="$2"
    local hook_hive="$3"
    local hook_setinfo="$4"

    cat > "$INI" <<EOF
# R3ShieldCore 配置 —— 自动测试脚本生成，用完会恢复
mode=$mode
prompt_timeout=5
prompt_default=deny
hook_reads=0
log_all_open=0
hook_hive=$hook_hive
hook_set_info=$hook_setinfo
log=$logfile
exclude=D:\\Program Files\\MyApp
exclude=C:$USERPROFILE\\.mytool
EOF
}

# 准备：备份原配置
cp "$INI" "$BACKUP"
trap 'kill_engine; cp "$BACKUP" "$INI"' EXIT

# 每次运行生成唯一的日志后缀，避免依赖删除
RUN_ID=$$
LOG1="r3shieldcore-test-log-$RUN_ID.log"
LOG2="r3shieldcore-test-block-$RUN_ID.log"
LOG3="r3shieldcore-test-off-$RUN_ID.log"

# 探针输出统一落到 tools 目录，路径写死避免 cwd 影响
PROBE_LOG="$TOOLS/probe-output-$RUN_ID.log"

echo "=============================================="
echo " R3ShieldCore 新 API 测试  (run=$RUN_ID)"
echo "=============================================="
echo ""

# ------------------------------------------------------------------
# 场景 1：LOG 模式
# ------------------------------------------------------------------
echo "--- 场景 1：LOG 模式（新 API 应被记录）---"
kill_engine
write_ini log "$LOG1" 1 1
start_engine "log"


"$PROBE" > "$PROBE_LOG" 2>&1
sleep 3

LOGFILE="$RELEASE/$LOG1"

for api in FlushKey SetInformationKey SaveKeyEx LoadKey UnloadKey RestoreKey ReplaceKey; do
    if grep -q "$api" "$LOGFILE" 2>/dev/null; then
        check "LOG 记录 $api" 1
    else
        check "LOG 记录 $api" 0
    fi
done

if grep -qE "file=[A-Z]:" "$LOGFILE" 2>/dev/null; then
    check "hive 文件路径转成 DOS 路径" 1
else
    check "hive 文件路径转成 DOS 路径" 0
fi

if grep -qE "target=" "$LOGFILE" 2>/dev/null; then
    check "hive 操作使用 target= 标签" 1
else
    check "hive 操作使用 target= 标签" 0
fi

echo "  --- LOG 模式记录数: $(grep -c 'pid=' "$LOGFILE" 2>/dev/null || echo 0) 条 ---"
echo ""

# ------------------------------------------------------------------
# 场景 2：BLOCK 模式
# ------------------------------------------------------------------
echo "--- 场景 2：BLOCK 模式（新 API 应被拒绝）---"
kill_engine

# 关键顺序：先在【引擎未运行】时建好键。
# BLOCK 模式下连 RegCreateKeyExW 都会被拒，所以准备阶段不能有引擎。

"$PROBE" prepare > "$PROBE_LOG" 2>&1
if ! iconv -f GBK -t UTF-8 "$PROBE_LOG" 2>/dev/null | grep -q "已准备好"; then
    echo "  （警告：准备键失败，场景 2 结果不可信）"
    iconv -f GBK -t UTF-8 "$PROBE_LOG" 2>/dev/null | tail -3
fi

write_ini block "$LOG2" 1 1
start_engine "block"
"$PROBE" open > "$PROBE_LOG" 2>&1
sleep 3

BLOCKLOG="$RELEASE/$LOG2"
BLOCKPROBE_OUT=$(iconv -f GBK -t UTF-8 "$PROBE_LOG" 2>/dev/null)

if echo "$BLOCKPROBE_OUT" | grep -q "0xC0000022"; then
    check "BLOCK 模式返回 0xC0000022（我们的拒绝）" 1
else
    check "BLOCK 模式返回 0xC0000022（我们的拒绝）" 0
    echo "  （探针实际输出：）"
    echo "$BLOCKPROBE_OUT" | grep -E "Nt[A-Z]|只读打开" | sed 's/^/    /'
fi

if echo "$BLOCKPROBE_OUT" | grep -qE "NtFlushKey +-> 0x00000000"; then
    check "NtFlushKey 未被拦截（只记录）" 1
else
    check "NtFlushKey 未被拦截（只记录）" 0
fi

SYS_OK=0
if (cd /c/Windows/System32 && ./reg.exe query "HKCU\Software\Microsoft\Windows\CurrentVersion" >/dev/null 2>&1); then
    SYS_OK=1
fi
check "系统程序 reg.exe 不受影响" "$SYS_OK"

# 系统程序不应该出现在日志里
if grep -q "System32" "$BLOCKLOG" 2>/dev/null; then
    check "日志中无 System32 进程记录" 0
else
    check "日志中无 System32 进程记录" 1
fi

echo "  --- BLOCK 模式日志: $(grep -c 'pid=' "$BLOCKLOG" 2>/dev/null || echo 0) 条 ---"
echo ""

# ------------------------------------------------------------------
# 场景 3：开关关闭
# ------------------------------------------------------------------
echo "--- 场景 3：hook_hive=0（新 API 应完全不挂）---"
kill_engine
write_ini log "$LOG3" 0 0
start_engine "off"


"$PROBE" open > "$PROBE_LOG" 2>&1
sleep 3

OFFLOG="$RELEASE/$LOG3"

HIVE_ABSENT=1
for api in SaveKey LoadKey UnloadKey RestoreKey ReplaceKey SetInformationKey; do
    if grep -q "$api" "$OFFLOG" 2>/dev/null; then
        HIVE_ABSENT=0
        echo "  （不该出现却出现了: $api）"
    fi
done
check "关闭开关后 hive/SetInfo API 完全不记录" "$HIVE_ABSENT"

if grep -q "FlushKey" "$OFFLOG" 2>/dev/null; then
    check "NtFlushKey 仍被记录（不受 hive 开关影响）" 1
else
    check "NtFlushKey 仍被记录（不受 hive 开关影响）" 0
fi

echo "  --- 开关关闭后日志: $(grep -c 'pid=' "$OFFLOG" 2>/dev/null || echo 0) 条 ---"
echo ""

# ------------------------------------------------------------------
# 收尾
# ------------------------------------------------------------------
kill_engine

echo "=============================================="
echo " 结果: PASS=$PASS  FAIL=$FAIL"
echo "=============================================="

if [ "$FAIL" -eq 0 ]; then
    echo "全部通过"
    exit 0
else
    echo "有失败项，见上方 [FAIL]"
    exit 1
fi
