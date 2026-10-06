#!/usr/bin/env bash
#
# test_neverinject_vmware.sh —— 端到端验证 v53 的「VMware Tools 内置豁免注入」。
#
# 判据（两层，互为交叉验证）：
#   ① **在场证据**：用模块枚举直接看目标进程里有没有 `r3shieldcore-lib.dll`。
#      · `D:\Program Files\VMware\VMware Tools\vmtoolsd.exe`  -> 必须 **NOT-INJECTED**
#      · `D:\tools\vmtoolsd.exe`（同名、放错目录）             -> 必须 **INJECTED**
#      第二条是**反向对照**：没有它，"没被注入"可能只是引擎没跑（铁律 54）。
#   ② **引擎自己的日志**：r3shieldcore-console.log 里有
#      `跳过内置豁免进程注入(VMware Tools) image=...`，且 image 正是那个路径。
#
# 用法: bash tools/test_neverinject_vmware.sh [--keep]
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
ENGINE="$BUILD_DIR/R3 ShieldCore.exe"
PROBE="$ROOT/tools/inject_check_probe.exe"

# 靶子目录：D: 盘上**字面**复刻 Program Files 结构 —— 内置判据不依赖
# %ProgramFiles% 环境变量，只认 `<盘符>:\Program Files\VMware\VMware Tools\`，
# 所以在 D: 上造一个就能真实验证（不必去写 C:\Program Files）。
#
# ⚠️ `D:\Program Files` 是**真实目录**（装着 bilibili/Git/Java 等），
#    所以只创建/删除它下面的 `VMware` 子目录，而且**先确认它原本不存在**
#    （见 cleanup 里的 SAFE_EXEMPT_* 守卫）。
EXEMPT_PARENT="D:\\Program Files\\VMware"
EXEMPT_DIR="D:\\Program Files\\VMware\\VMware Tools"
CONTROL_DIR="D:\\R3ShieldCoreNeverInjectTest"

export MSYS_NO_PATHCONV=1
KEEP="${1:-}"
PASS=0
FAIL=0

# 只有"我们确实新建了它"时才允许删除。
SAFE_EXEMPT_PARENT=0
SAFE_CONTROL_DIR=0
[ -e "/d/Program Files/VMware" ] || SAFE_EXEMPT_PARENT=1
[ -e "/d/R3ShieldCoreNeverInjectTest" ] || SAFE_CONTROL_DIR=1

ok()   { echo "  [OK]   $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup() {
    powershell.exe -NoProfile -Command \
        "Get-Process -Name 'R3 ShieldCore','vmtoolsd' -ErrorAction SilentlyContinue | ForEach-Object { \$_.Kill() }" \
        >/dev/null 2>&1
    if [ "$KEEP" != "--keep" ]; then
        if [ "$SAFE_EXEMPT_PARENT" -eq 1 ]; then
            powershell.exe -NoProfile -Command \
                "Remove-Item -LiteralPath 'D:\Program Files\VMware' -Recurse -Force -ErrorAction SilentlyContinue" \
                >/dev/null 2>&1
        else
            echo "  [cleanup] 跳过删除 $EXEMPT_PARENT（运行前就存在，不是我们建的）"
        fi
        if [ "$SAFE_CONTROL_DIR" -eq 1 ]; then
            powershell.exe -NoProfile -Command \
                "Remove-Item -LiteralPath 'D:\R3ShieldCoreNeverInjectTest' -Recurse -Force -ErrorAction SilentlyContinue" \
                >/dev/null 2>&1
        fi
        if [ -d "$BUILD_DIR" ]; then
            icacls "$BUILD_DIR" /reset /T >/dev/null 2>&1
            powershell.exe -NoProfile -Command \
                "Remove-Item -LiteralPath '$root\R3ShieldCore\BuildCheck' -Recurse -Force -ErrorAction SilentlyContinue" \
                >/dev/null 2>&1
        fi
    fi
}
trap cleanup EXIT

echo "=== [1/6] 构建免提权引擎 -> $BUILD_DIR ==="
cd "$ROOT" || exit 1
R3SHIELDCORE_NO_UAC=1 bash build.sh BuildCheck x64 2>&1 | tail -2 || exit 1

echo ""
echo "=== [2/6] 放配置 + 加固 ACL ==="
cp "$ROOT/dist/R3ShieldCore-x64/r3shieldcore.ini" "$BUILD_DIR/r3shieldcore.ini" || exit 1
icacls "$BUILD_DIR/64" /inheritance:d >/dev/null
icacls "$BUILD_DIR/64" /remove:g "NT AUTHORITY\\Authenticated Users" >/dev/null
icacls "$BUILD_DIR/64/r3shieldcore-lib.dll" /inheritance:d >/dev/null
icacls "$BUILD_DIR/64/r3shieldcore-lib.dll" /remove:g "NT AUTHORITY\\Authenticated Users" >/dev/null
rm -f "$BUILD_DIR/r3shieldcore-console.log"
echo "  ok"

echo ""
echo "=== [3/6] 造靶子（同一个二进制，两处放）==="
if [ "$SAFE_EXEMPT_PARENT" -ne 1 ]; then
    echo "  !! $EXEMPT_PARENT 已存在，为避免误删真实数据，本次不跑。"
    exit 1
fi
mkdir -p "/d/Program Files/VMware/VMware Tools" "/d/R3ShieldCoreNeverInjectTest" || exit 1
cp "$PROBE" "/d/Program Files/VMware/VMware Tools/vmtoolsd.exe" || exit 1
cp "$PROBE" "/d/R3ShieldCoreNeverInjectTest/vmtoolsd.exe" || exit 1
echo "  $EXEMPT_DIR\\vmtoolsd.exe"
echo "  $CONTROL_DIR\\vmtoolsd.exe"

echo ""
echo "=== [4/6] 启动引擎 ==="
"$ENGINE" &
sleep 4
if tasklist /nh /fo csv 2>/dev/null | grep -qi "R3 ShieldCore"; then
    echo "  引擎已启动"
else
    echo "  !! 引擎没起来（先查 ACL）"
    exit 1
fi
sleep 2   # 让注入器把全表扫一遍

echo ""
echo "=== [5/6] 检查两个靶子 ==="
echo "--- ① 豁免目录（期望 NOT-INJECTED）---"
"$PROBE" "$EXEMPT_DIR\\vmtoolsd.exe"
if [ $? -eq 2 ]; then ok "VMware Tools 目录下的 vmtoolsd.exe 未被注入"; else bad "VMware Tools 目录下的 vmtoolsd.exe **被注入了**"; fi

echo "--- ② 反向对照：同名但放错目录（期望 INJECTED）---"
"$PROBE" "$CONTROL_DIR\\vmtoolsd.exe"
if [ $? -eq 0 ]; then ok "D:\\R3ShieldCoreNeverInjectTest 下的同名 vmtoolsd.exe 照常被注入（说明豁免是**按路径**、不是按文件名）"; else bad "对照组也没被注入 —— 引擎没工作，①的结论不成立"; fi

echo ""
echo "=== [6/6] 引擎日志交叉验证 ==="
if [ -f "$BUILD_DIR/r3shieldcore-console.log" ]; then
    if grep -a -q "跳过内置豁免进程注入(VMware Tools)" "$BUILD_DIR/r3shieldcore-console.log"; then
        ok "r3shieldcore-console.log 里有「跳过内置豁免进程注入(VMware Tools)」"
        grep -a "跳过内置豁免进程注入(VMware Tools)" "$BUILD_DIR/r3shieldcore-console.log" | head -3
    else
        bad "r3shieldcore-console.log 里没有内置豁免记录"
        echo "    （看看有没有别的跳过行：）"
        grep -a "跳过.*注入" "$BUILD_DIR/r3shieldcore-console.log" | head -5
    fi
else
    bad "r3shieldcore-console.log 不存在"
fi

echo ""
echo "=== 结果：$PASS 通过 / $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] && echo "PASS" || echo "FAIL"
exit "$FAIL"
