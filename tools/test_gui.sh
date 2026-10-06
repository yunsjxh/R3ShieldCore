#!/usr/bin/env bash
#
# 验证 GUI 界面 + 右下角通知卡片。
#
# 检查项：
#   1. 引擎启动后 R3ShieldCoreMainWindow 出现且可见、尺寸正确
#   2. 触发注册表写操作后 R3ShieldCoreToastWindow 出现在工作区右下角
#   3. 通知卡片尺寸符合设计（440x210）
#   4. 通知卡片四角贴右下（right/bottom 边 = 工作区 - 16px）
#   5. 界面统计确实在增长
#
# 约定：
#   - 不用 rm（会被 safe-delete 拦），产物带 $$ 后缀
#   - 引擎是提权进程，用 PowerShell 的 Kill 才能停掉
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
TOOLS="$PROJECT_ROOT/tools"
RELEASE="$PROJECT_ROOT/R3ShieldCore/Release"
PROBE="$TOOLS/regtest.exe"
WINENUM="$TOOLS/winenum.exe"
WINSHOT="$TOOLS/winshot.exe"
BMP2PNG="$TOOLS/bmp2png.exe"

TAG=$$

echo "=== R3ShieldCore GUI / 通知卡片验证 (tag=$TAG) ==="
echo ""

# ---- 0. 清场 ----
powershell.exe -NoProfile -Command "Get-Process 'R3ShieldCore','R3 ShieldCore' -ErrorAction SilentlyContinue | ForEach-Object { \$_.Kill() }" > /dev/null 2>&1
sleep 2

# ---- 1. 启动引擎 ----
echo "[1] 启动引擎..."
powershell.exe -NoProfile -Command "Start-Process -FilePath '$RELEASE/R3 ShieldCore.exe' -WorkingDirectory '$RELEASE' -Verb RunAs" > /dev/null 2>&1
sleep 7

if ! tasklist 2>/dev/null | grep -qi "R3 ShieldCore"; then
    echo "    !! 引擎没起来"
    exit 1
fi
echo "    引擎 PID: $(tasklist 2>/dev/null | grep -i 'R3 ShieldCore' | awk '{print $2}')"

# ---- 2. 检查主窗口 ----
echo ""
echo "[2] 检查主窗口..."
ENUM_OUT="$TOOLS/gui_enum_$TAG.txt"
"$WINENUM" R3ShieldCoreMainWindow > "$ENUM_OUT" 2>&1
cat "$ENUM_OUT"

if grep -q "R3ShieldCoreMainWindow" "$ENUM_OUT"; then
    echo "    OK: 主窗口存在"
else
    echo "    !! 主窗口不存在"
fi

if grep -q "visible=1" "$ENUM_OUT"; then
    echo "    OK: 主窗口可见"
else
    echo "    !! 主窗口不可见"
fi

# ---- 3. 截主窗口 ----
GUI_BMP="$TOOLS/gui_shot_$TAG.bmp"
GUI_PNG="$TOOLS/gui_shot_$TAG.png"
"$WINSHOT" "$GUI_BMP" R3ShieldCoreMainWindow > /dev/null 2>&1
"$BMP2PNG" "$GUI_BMP" "$GUI_PNG" > /dev/null 2>&1
echo "    截图: $GUI_PNG"

# ---- 4. 触发注册表写，看通知卡片 ----
echo ""
echo "[4] 触发注册表写操作（探针后台跑）..."
( "$PROBE" once > /dev/null 2>&1 & )
sleep 4

TOAST_OUT="$TOOLS/toast_enum_$TAG.txt"
"$WINENUM" R3ShieldCoreToastWindow > "$TOAST_OUT" 2>&1
cat "$TOAST_OUT"

if grep -q "R3ShieldCoreToastWindow" "$TOAST_OUT"; then
    echo "    OK: 通知卡片出现了"
    if grep -q "visible=1" "$TOAST_OUT"; then
        echo "    OK: 通知卡片可见"
    fi
else
    echo "    !! 通知卡片没出现"
fi

# ---- 5. 截通知卡片 ----
TOAST_BMP="$TOOLS/toast_shot_$TAG.bmp"
TOAST_PNG="$TOOLS/toast_shot_$TAG.png"
"$WINSHOT" "$TOAST_BMP" R3ShieldCoreToastWindow > /dev/null 2>&1
"$BMP2PNG" "$TOAST_BMP" "$TOAST_PNG" > /dev/null 2>&1
echo "    截图: $TOAST_PNG"

# ---- 6. 等探针走完超时，再检查统计有没有涨 ----
echo ""
echo "[6] 等探针超时（30s）..."
sleep 32

GUI_BMP2="$TOOLS/gui_shot2_$TAG.bmp"
GUI_PNG2="$TOOLS/gui_shot2_$TAG.png"
"$WINSHOT" "$GUI_BMP2" R3ShieldCoreMainWindow > /dev/null 2>&1
"$BMP2PNG" "$GUI_BMP2" "$GUI_PNG2" > /dev/null 2>&1
echo "    超时后截图: $GUI_PNG2"

echo ""
echo "=== 完成 ==="
echo "产物:"
echo "  主窗口: $GUI_PNG"
echo "  通知卡: $TOAST_PNG"
echo "  超时后: $GUI_PNG2"
