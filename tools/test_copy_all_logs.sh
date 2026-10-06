#!/usr/bin/env bash
#
# test_copy_all_logs.sh —— 一键端到端验证 GUI 的「复制全部日志」按钮。
#
# 为什么要有这个脚本：这套流程有 4 个**必须按顺序做对**的步骤，任何一步漏了
# 都会得到"假失败"，而且失败现象极具误导性（详见各步骤注释）：
#   1. 出**免提权**引擎（带 requireAdministrator 的 exe 在非提权会话里根本创建不出来）
#   2. 把 DLL 目录 ACL 加固（否则引擎拒绝从可写目录加载 DLL → exe 1 秒就退）
#   3. **关掉探针自己要用到的两个 hook**（hook_clipboard / hook_screen）——
#      否则引擎会把探针的"测量仪器"拦掉，看起来像按钮坏了
#   4. 同完整性级别运行（否则 UIPI 静默丢输入）
#
# 用法：
#   bash test_copy_all_logs.sh          # 全套：构建 + 加固 + 跑 + 清理
#   bash test_copy_all_logs.sh --keep   # 跑完不清理（保留 BuildCheck 现场）
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
DEMO="$ROOT/R3ShieldCore"
BUILD_DIR="$DEMO/BuildCheck"
PROBE="$ROOT/tools/gui_copy_all_logs_probe.exe"
KEEP="${1:-}"

export MSYS_NO_PATHCONV=1   # ★ 不加这个，icacls 的 /xxx 开关会被 Git Bash 当路径改写

cleanup() {
    if [ "$KEEP" = "--keep" ]; then
        echo "[cleanup] --keep：保留 $BUILD_DIR"
        return
    fi
    if [ -d "$BUILD_DIR" ]; then
        echo "[cleanup] 重置 ACL 并删除 $BUILD_DIR"
        icacls "$BUILD_DIR" /reset /T >/dev/null 2>&1
        powershell.exe -NoProfile -Command \
            "Remove-Item -LiteralPath '$BUILD_DIR' -Recurse -Force -ErrorAction SilentlyContinue" \
            >/dev/null 2>&1
    fi
}
trap cleanup EXIT

echo "=== [1/5] 构建免提权引擎 -> $BUILD_DIR ==="
cd "$ROOT" || exit 1
R3SHIELDCORE_NO_UAC=1 bash build.sh BuildCheck x64 2>&1 | tail -3 || exit 1

echo ""
echo "=== [2/5] 放配置 + 关掉探针自己要用的两个 hook ==="
# ⚠️ 只关 hook_clipboard / hook_screen —— 这两条 hook 会让引擎把**探针自己**的
#    GetClipboardData / BitBlt 判高危并在 block 下拦掉（实测：日志里是
#    `CLIP BLOCK HIGH GetClipboardData` / `SCRN BLOCK HIGH ScreenBitBlt [by R3ShieldCore]`）。
#    其余配置保持发布默认（mode=block）。按钮行为与这两条 hook 无关。
cp "$ROOT/dist/R3ShieldCore-x64/r3shieldcore.ini" "$BUILD_DIR/r3shieldcore.ini" || exit 1
python - "$BUILD_DIR/r3shieldcore.ini" <<'PYEOF'
import io, sys
p = sys.argv[1]
s = io.open(p, encoding='utf-8').read()
s = s.replace('hook_clipboard=1', 'hook_clipboard=0', 1)
s = s.replace('hook_screen=1', 'hook_screen=0', 1)
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('  hook_clipboard=0 / hook_screen=0')
PYEOF

echo ""
echo "=== [3/5] 加固 DLL 目录 ACL（两步必须分开执行）==="
# ★ /inheritance:d 和 /remove:g 写在一条命令里时，remove 是对"改动前的继承 ACE"
#   生效 —— 会静默不生效，引擎照样拒绝加载。
icacls "$BUILD_DIR/64" /inheritance:d >/dev/null
icacls "$BUILD_DIR/64" /remove:g "NT AUTHORITY\\Authenticated Users" >/dev/null
icacls "$BUILD_DIR/64/r3shieldcore-lib.dll" /inheritance:d >/dev/null
icacls "$BUILD_DIR/64/r3shieldcore-lib.dll" /remove:g "NT AUTHORITY\\Authenticated Users" >/dev/null
echo "  ACL 已加固"

echo ""
echo "=== [4/5] 跑探针（同完整性级别）==="
cd "$DEMO" || exit 1
"$PROBE" "BuildCheck\\R3 ShieldCore.exe"
RC=$?

echo ""
echo "=== [5/5] 结果 ==="
if [ "$RC" -eq 0 ]; then
    echo "PASS：复制全部日志按钮端到端可用"
else
    echo "FAIL（exit=$RC）"
    echo "  exit=2 窗口没出现 / exit=3 引擎启动即死（先查 ACL）"
fi
exit "$RC"
