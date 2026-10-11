#!/usr/bin/env bash
#
# test_gui_preview.sh —— 一键：出免提权 exe -> 起 `--gui-preview` -> 截图 + 断言 -> 转 PNG。
#
# 为什么走"免提权 exe"：
#   发布清单是 requireAdministrator，在**非提权会话**里根本创建不出来
#   （bash/cmd 直接 Permission denied —— 这正是 UAC 的正确行为）。
#   而 `--gui-preview` 本来就不初始化引擎，所以用 R3SHIELDCORE_NO_UAC=1
#   出的**验证专用** exe 完全够用，而且与探针**同完整性级别**
#   （不同级别的话 UIPI 会静默拦掉一切输入/交互）。
#
# ★ 不需要 ACL 加固、不需要改 ini —— 预览模式**不加载 DLL、不跑引擎**，
#   所以 test_copy_all_logs.sh 里那两步（加固 ACL / 关掉 hook_clipboard+hook_screen）
#   在这里都不需要。
#
# 用法:
#   bash tools/test_gui_preview.sh                 # 只看 advanced（默认）
#   bash tools/test_gui_preview.sh advanced ark    # 指定若干页签
#
set -u

R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
ROOT="$R3SC_PROJECT_ROOT"
DEMO="$ROOT/R3ShieldCore"
EXE="$DEMO/BuildCheck/R3 ShieldCore.exe"
PROBE="$ROOT/tools/gui_preview_probe.exe"
SHOTS="$ROOT/docs/shots"

TABS=("$@")
if [ "${#TABS[@]}" -eq 0 ]; then
    TABS=(advanced)
fi

cd "$ROOT" || exit 1

echo "=== [1/4] 出免提权 exe -> $DEMO/BuildCheck ==="
R3SHIELDCORE_NO_UAC=1 bash build.sh BuildCheck x64 2>&1 | tail -2 || exit 1
if [ ! -f "$EXE" ]; then
    echo "[败] 没出 $EXE"
    exit 1
fi

echo ""
echo "=== [2/4] 编探针 ==="
if ! bash build_gui_preview_probe.sh >/dev/null 2>&1; then
    bash build_gui_preview_probe.sh
    exit 1
fi
if [ ! -f "$PROBE" ]; then
    echo "[败] 没出 $PROBE"
    exit 1
fi

mkdir -p "$SHOTS"

echo ""
echo "=== [3/4] 逐页签：起预览 -> 截图 -> 断言 ==="
rc_all=0
for tab in "${TABS[@]}"; do
    echo ""
    echo "---- 页签: $tab ----"
    bmp="$SHOTS/gui-preview-$tab.bmp"
    png="$SHOTS/gui-preview-$tab.png"
    "$PROBE" "$EXE" "$tab" "$bmp"
    rc=$?
    [ "$rc" -eq 0 ] || rc_all=1
    if [ -f "$bmp" ]; then
        python tools/bmp_to_png.py "$bmp" "$png" && rm -f "$bmp"
    fi
done

echo ""
echo "=== [4/4] 结果 ==="
if [ "$rc_all" -eq 0 ]; then
    echo "PASS：预览截图与判据全部通过（图在 docs/shots/）"
else
    echo "FAIL：有判据没过（exit=2 窗口没起来；exit=1 见上面 [FAIL] 行）"
fi
exit "$rc_all"
