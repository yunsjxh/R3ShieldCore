#!/usr/bin/env bash
#
# test_selfprotect.sh — R3ShieldCore 引擎自我保护实测脚本
#
# 覆盖 5 条攻击路径 + 1 条对照 + 1 条残余绕过，逐条给期望值。
#
# 前置条件：
#   1) 以【管理员】身份启动引擎：R3ShieldCore/Release/R3 ShieldCore.exe
#      （GUI 会弹出来，不用管它；不要用 taskkill 停，见文末逃生门）
#   2) r3shieldcore.ini 里 self_protect=1（默认就是 1）
#   3) 引擎不要加进 ini 的 exclude（引擎自己天然排除）
#
# 用法：
#   bash tools/test_selfprotect.sh              # 自动从 Release/engine.pid 读引擎 pid
#   bash tools/test_selfprotect.sh <pid>        # 手动指定
#   bash tools/test_selfprotect.sh <pid> --with-escape   # 末尾追加 dskill（会杀掉引擎）
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
TOOLS="$ROOT/tools"
REL="$ROOT/R3ShieldCore/Release"
BYPASS_DIR="$USERPROFILE/.workbuddy-ai"   # 在 ini 的 exclude 里 → 该目录下的程序不会被注入
STAMP="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$TOOLS/selfprotect-$STAMP"
WITH_ESCAPE=0
for a in "$@"; do [ "$a" = "--with-escape" ] && WITH_ESCAPE=1; done

mkdir -p "$OUTDIR"

pass=0; fail=0
ok()   { echo "  [PASS] $1"; pass=$((pass+1)); }
bad()  { echo "  [FAIL] $1"; fail=$((fail+1)); }
info() { echo "  ---- $1"; }

# ⚠️ tasklist.exe 在 System32 —— 引擎跑 BLOCK 模式时它会被 R3ShieldCore 拦掉，
#    于是"探不到 pid"和"判不了存活"会同时发生。所以两条路都留着：
#    优先用 tasklist，不可用时退化为解析探针自己写的"复查"行。
TASKLIST_OK=1
if ! MSYS_NO_PATHCONV=1 tasklist /NH >/dev/null 2>&1; then
  TASKLIST_OK=0
fi

alive() {  # 返回 0=活着 1=已退出 2=无法判定
  [ "$TASKLIST_OK" = "0" ] && return 2
  MSYS_NO_PATHCONV=1 tasklist /FI "PID eq $1" 2>/dev/null | grep -q "r3shieldcore" && return 0
  return 1
}

# 从探针输出里读复查结论（不依赖 tasklist，探针内部自己 OpenProcess 查过）
alive_from_probe() {  # $1=输出文件 → 0=活着 1=已退出 2=读不到
  [ -f "$1" ] || return 2
  grep -q "复查: 目标仍在运行" "$1" && return 0
  grep -q "复查: 目标已退出\|复查: 目标已不存在" "$1" && return 1
  return 2
}

# 综合判定：优先探针自述，其次 tasklist
check_alive() {  # $1=探针输出文件（可为空）
  local r=2
  if [ -n "${1:-}" ]; then
    alive_from_probe "$1"; r=$?
  fi
  if [ "$r" = "2" ]; then
    alive "$PID"; r=$?
  fi
  case "$r" in
    0) ok "引擎仍存活" ;;
    1) bad "引擎已死" ;;
    *) info "无法判定引擎存活（tasklist 不可用；看引擎 GUI / 任务管理器）" ;;
  esac
}

# 按镜像名探测引擎 pid（引擎自己不写 pid 文件，只能查 tasklist）
find_engine_pid() {
  [ "$TASKLIST_OK" = "0" ] && return 1
  local name csv
  for name in "R3 ShieldCore.exe" "R3 ShieldCore-x86.exe"; do
    csv="$(MSYS_NO_PATHCONV=1 tasklist /FI "IMAGENAME eq $name" /NH /FO CSV 2>/dev/null \
           | tr -d '"' | awk -F, 'NR==1 && $1 ~ /r3shieldcore/ {print $2; exit}')"
    if [ -n "$csv" ]; then echo "$csv"; return 0; fi
  done
  return 1
}

# ---------------------------------------------------------------- 前置检查
echo "=== 0. 前置检查 ==="

PID="${1:-}"
case "$PID" in ''|--*) PID="";; esac
if [ -z "$PID" ]; then
  PID="$(find_engine_pid || true)"
fi
if [ -z "$PID" ]; then
  echo "没找到正在运行的引擎。请先以【管理员】身份启动："
  echo "  $REL/R3 ShieldCore.exe"
  if [ "$TASKLIST_OK" = "0" ]; then
    echo
    echo "⚠️ tasklist 不可用（多半是引擎跑在 BLOCK 模式，System32 程序被拦）→ 必须手动传 pid。"
  fi
  echo
  echo "手动取 pid 的两种方式："
  echo "  PowerShell : (Get-Process R3 ShieldCore).Id"
  echo "  任务管理器 : 详细信息 → 找 R3 ShieldCore.exe → PID 列"
  echo "然后：bash tools/test_selfprotect.sh <pid>"
  exit 1
fi
if [ "$TASKLIST_OK" = "1" ] && ! alive "$PID"; then
  echo "pid=$PID 不是正在运行的引擎进程。请确认引擎已启动。"
  exit 1
fi
echo "引擎 pid = $PID"
echo "输出目录 = $OUTDIR"
[ "$TASKLIST_OK" = "0" ] && echo "⚠️ tasklist 不可用（BLOCK 模式），存活判定改看探针自述的『复查』行"

for t in killprobe injecttest sysinject dskill; do
  [ -x "$TOOLS/$t.exe" ] || { echo "缺少 $TOOLS/$t.exe，先编译 tools/"; exit 1; }
done
echo "self_protect 配置：$(grep -m1 '^self_protect=' "$REL/r3shieldcore.ini" 2>/dev/null || echo '(未显式写，默认 1=开)')"
echo "当前模式：$(grep -m1 '^mode=' "$REL/r3shieldcore.ini" 2>/dev/null)"

# ---------------------------------------------------- 1. 被注入进程发起终止
echo
echo "=== 1. 终止：从 tools/ 发起（该进程会被引擎注入 → 保护 hook 生效）==="
echo "    期望：OpenProcess(PROCESS_TERMINATE) 失败 err=5，引擎存活"
"$TOOLS/killprobe.exe" "$PID" 0 "$OUTDIR/1-kill-injected.txt" >/dev/null 2>&1
grep -E "OpenProcess|TerminateProcess|复查" "$OUTDIR/1-kill-injected.txt"
if grep -q "OpenProcess(PROCESS_TERMINATE) 失败" "$OUTDIR/1-kill-injected.txt"; then
  ok "OpenProcess 被拒"
else
  bad "OpenProcess 竟然成功了"
fi
check_alive "$OUTDIR/1-kill-injected.txt"

# ------------------------------------------- 2. bypass 进程发起终止（关键）
echo
echo "=== 2. 终止：从 exclude 目录发起（该进程不被注入 → 验证保护 hook 跨过 bypass）==="
echo "    期望：同样失败 err=5。若这里成功 → 保护 hook 没挂到 bypass 进程上（已知坑）"
mkdir -p "$BYPASS_DIR"
cp -f "$TOOLS/killprobe.exe" "$BYPASS_DIR/killprobe.exe"
"$BYPASS_DIR/killprobe.exe" "$PID" 0 "$OUTDIR/2-kill-bypass.txt" >/dev/null 2>&1
grep -E "OpenProcess|TerminateProcess|复查" "$OUTDIR/2-kill-bypass.txt"
if grep -q "OpenProcess(PROCESS_TERMINATE) 失败" "$OUTDIR/2-kill-bypass.txt"; then
  ok "bypass 进程同样被拒"
else
  bad "bypass 进程杀掉了引擎 → 保护 hook 未跨过 bypass"
fi
check_alive "$OUTDIR/2-kill-bypass.txt"
rm -f "$BYPASS_DIR/killprobe.exe"

# ------------------------------------------------------- 3. 标准注入（走 ntdll）
echo
echo "=== 3. 注入：标准 CreateRemoteThread（走 ntdll!NtCreateThreadEx）==="
echo "    期望：第 2 步 VirtualAllocEx 就被拒 err=5（句柄权限已被剥），引擎存活"
"$TOOLS/injecttest.exe" "$PID" 0 "$OUTDIR/3-inject-std.txt" >/dev/null 2>&1
grep -E "OpenProcess|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|结论|复查" "$OUTDIR/3-inject-std.txt"
if grep -qE "(VirtualAllocEx|CreateRemoteThread).*失败" "$OUTDIR/3-inject-std.txt"; then
  ok "注入链被切断"
else
  bad "注入链竟然走完了"
fi
check_alive "$OUTDIR/3-inject-std.txt"

# --------------------------------------------------- 4. 直 syscall 注入（绕过）
echo
echo "=== 4. 注入：直 syscall NtCreateThreadEx（绕过 MinHook 补丁）==="
echo "    期望：仍然卡在 VirtualAllocEx —— syscall 能绕 hook，但绕不过被剥权限的句柄"
"$TOOLS/sysinject.exe" "$PID" 0 "$OUTDIR/4-inject-syscall.txt" >/dev/null 2>&1
grep -E "OpenProcess|VirtualAllocEx|WriteProcessMemory|NtCreateThreadEx|结论|复查" "$OUTDIR/4-inject-syscall.txt"
if grep -qE "(VirtualAllocEx|NtCreateThreadEx).*失败" "$OUTDIR/4-inject-syscall.txt"; then
  ok "直 syscall 注入同样被挡"
else
  bad "直 syscall 注入成功 → 保护失效"
fi
check_alive "$OUTDIR/4-inject-syscall.txt"

# ------------------------------------------------------------ 5. 对照组
echo
echo "=== 5. 对照：普通进程应该照样能杀（证明不是「全都杀不掉」）==="
echo "    期望：killprobe 对 sleep.exe 返回成功"
sleep 60 &
VICTIM=$!
"$TOOLS/killprobe.exe" "$VICTIM" 0 "$OUTDIR/5-kill-normal.txt" >/dev/null 2>&1
grep -E "OpenProcess|TerminateProcess|复查" "$OUTDIR/5-kill-normal.txt"
if grep -q "TerminateProcess -> 成功" "$OUTDIR/5-kill-normal.txt"; then
  ok "普通进程正常可杀（保护是定向的）"
else
  bad "普通进程也杀不掉 → 保护范围过宽"
fi
kill "$VICTIM" 2>/dev/null

# ------------------------------------------------- 6. 残余绕过 / 逃生门
echo
echo "=== 6. 残余绕过：dskill 直 syscall NtOpenProcess ==="
echo "    这是用户态 hook 的固有上限，同时也是开发者逃生门"
if [ "$WITH_ESCAPE" = "1" ]; then
  "$TOOLS/dskill.exe" "$PID" "$OUTDIR/6-escape.txt" >/dev/null 2>&1
  grep -E "NtOpenProcess|TerminateProcess|目标状态" "$OUTDIR/6-escape.txt"
  info "dskill 已执行（引擎应已退出）—— 这就是逃生门"
  if [ "$TASKLIST_OK" = "1" ]; then
    alive "$PID" && info "引擎居然还活着" || info "引擎已退出"
  else
    info "tasklist 不可用，请自行确认引擎是否退出"
  fi
else
  info "已跳过（加了 --with-escape 才会执行，它会杀掉引擎）"
fi

# ---------------------------------------------------------------- 汇总
echo
echo "=== 汇总：$pass 项符合预期，$fail 项不符 ==="
echo "原始输出：$OUTDIR/"
echo
echo "停引擎的逃生门（任选）："
echo "  1) 引擎控制台按 Ctrl+C"
echo "  2) 直接关掉引擎的控制台窗口（系统终止，不经 hook）"
echo "  3) tools/dskill.exe <pid>"
echo "  4) 启动前在 r3shieldcore.ini 写 self_protect=0"

[ "$fail" -eq 0 ] || exit 1
