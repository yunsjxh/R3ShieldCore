#!/usr/bin/env bash
#
# build_ark_probe.sh —— 准备 ARK 端到端探针用的**免提权**引擎目录。
#
# ★ 为什么必须另建一份免提权引擎，而不是直接用 dist/R3ShieldCore-x64：
#
#   正式发布包的 exe 带 `requireAdministrator` 清单。要从自动化里起它，
#   只能 `Start-Process -Verb RunAs`，而那条路**过不了环境变量** ——
#   本探针要靠 `R3SHIELDCORE_START_TAB` / `R3SHIELDCORE_ARK_ACTION` 两个环境变量
#   把"停在 ARK 页"和"发一次动作请求"喂进去（ARK 的动作按钮是自绘的、
#   且提权窗口不接收非提权进程的鼠标输入，点击路走不通）。
#
#   ⇒ 用 `R3SHIELDCORE_NO_UAC=1` 编一份**同样代码、同样 hook、只少提权要求**的
#     exe（这是 build.sh 里早就有的开关，见那里的注释）。它跟正式包的唯一
#     差别就是清单里的 level，所以"动作链走不走得通"这件事测得是准的。
#
#   正式发布包的启动仍然由 `tools/v57_smoke.ps1` 覆盖（它用 RunAs 起真包）。
#
# 用法: bash build_ark_probe.sh
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
cd "$PROJECT_ROOT" || exit 1

PROBE_DIR="_t/ark-probe"
NOUAC_CONFIG="ArkTest"

echo "=== 1/3 免提权构建（R3SHIELDCORE_NO_UAC=1, x64）==="
R3SHIELDCORE_NO_UAC=1 ONLY_ARCH=x64 bash build.sh "$NOUAC_CONFIG" 2>&1 | tail -5
if [ ! -f "R3ShieldCore/$NOUAC_CONFIG/R3 ShieldCore.exe" ]; then
    echo "[FAIL] 免提权 exe 没编出来"
    exit 1
fi

echo ""
echo "=== 2/3 准备探针目录 $PROBE_DIR ==="
rm -rf "$PROBE_DIR"
mkdir -p "$PROBE_DIR"
# 从发布目录整份拷过来（配置 / 预设 / 文档都跟正式包一致），
# 只把三个二进制换成免提权那份。
cp -r dist/R3ShieldCore-x64/. "$PROBE_DIR/"
cp -f "R3ShieldCore/$NOUAC_CONFIG/R3 ShieldCore.exe" "$PROBE_DIR/"
cp -f "R3ShieldCore/$NOUAC_CONFIG/64/r3shieldcore-lib.dll" "$PROBE_DIR/64/"
cp -f "R3ShieldCore/$NOUAC_CONFIG/32/r3shieldcore-lib.dll" "$PROBE_DIR/32/"

echo ""
echo "=== 3/3 校验 ==="
for f in "R3 ShieldCore.exe" "64/r3shieldcore-lib.dll" "32/r3shieldcore-lib.dll" "r3shieldcore.ini"; do
    if [ ! -f "$PROBE_DIR/$f" ]; then
        echo "[FAIL] 探针目录缺 $f"
        exit 1
    fi
done

# ★ 确认这份 exe 真的**没有** requireAdministrator —— 否则探针会静默地
#   退化成"起不来"，而症状看起来像"ARK 功能坏了"。
#
# ⚠️ 必须匹配**属性**（`level="requireAdministrator"`），不能只 grep
#   `requireAdministrator` 这个词 —— app.cpp 里有一句面向用户的诊断文案
#   `printf("!! 正常双击时清单里的 requireAdministrator 会弹 UAC 提权 ...")`，
#   那句话**会原样出现在二进制里**，于是裸词匹配对**任何**构建都恒真。
#   这是"子串断言"的典型假阳性（铁律 94）。
if strings -a "$PROBE_DIR/R3 ShieldCore.exe" | grep -q 'level="requireAdministrator"'; then
    echo "[FAIL] 探针 exe 的清单里仍是 level=requireAdministrator —— 环境变量传不进去"
    exit 1
fi
if ! strings -a "$PROBE_DIR/R3 ShieldCore.exe" | grep -q 'level="asInvoker"'; then
    echo "[FAIL] 探针 exe 的清单里找不到 level=asInvoker —— 清单可能整个丢了"
    exit 1
fi
echo "[ OK ] 探针 exe 清单是 level=asInvoker（环境变量可以传进去）"

# 确认新导出在位（内部退出那条路要用）
if ! strings -a "$PROBE_DIR/64/r3shieldcore-lib.dll" | grep -q "GlobalHookSessionSelfExit"; then
    echo "[FAIL] 探针 DLL 缺 GlobalHookSessionSelfExit 导出"
    exit 1
fi
echo "[ OK ] 探针 DLL 带 GlobalHookSessionSelfExit 导出"

echo ""
echo "探针目录就绪: $PROBE_DIR"
echo "下一步: powershell -File tools/v62_ark_probe.ps1"
