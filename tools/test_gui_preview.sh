#!/usr/bin/env bash
#
# test_gui_preview.sh —— 一键：出免提权 exe -> 起预览 -> 截图 + 断言 -> 转 PNG。
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
# ★ v80：被核对的东西变成了**两个 exe** ——
#   · main（R3 ShieldCore.exe）：「高级」页现在只剩**跳转入口**；
#   · cfg （r3shieldcore-cfg.exe）：编辑台搬到了这里（第 3 个页签）。
#   两者都是自绘窗口、都靠自己的日志自证，所以**共用同一个探针**
#   （见 gui_preview_probe.cpp 开头；铁律 195：同一份逻辑不抄第二遍）。
#
# 用法:
#   bash tools/test_gui_preview.sh                       # 默认跑主程序 + cfg 的每一屏
#   bash tools/test_gui_preview.sh main/advanced:click   # 只跑"点跳转"
#   bash tools/test_gui_preview.sh cfg/advanced:editor   # 只跑 cfg 的编辑台
#
# 规格写法: [main|cfg]/<tab>[:<mode>]     —— 不带 `app/` 前缀就是 main
#   main + advanced : jump(默认) | click
#       click 会让 exe **自己**模拟点一下跳转按钮，然后检查 cfg 的窗口
#       有没有起来、停在第 2 页（高级页）。这条链路上任何一环写错
#       （exe 名 / 窗口类名 / 激活消息 / 页号）都会红。
#   cfg  + advanced : quiz(默认) | why | editor | typing | error
#       「高级」编辑台有**互斥的界面状态**（闸门未过 / 刚全对 / 已解锁 /
#       编辑台里"输入中"），一个页签名看不全，靠它把每一屏都截出来
#       （铁律 240）。
#   ark -> **负对照**：非「高级」页时这一页不该被画到
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
MAIN_EXE="$DEMO/BuildCheck/R3 ShieldCore.exe"
CFG_EXE="$ROOT/dist/R3ShieldCore-x64/r3shieldcore-cfg.exe"
PROBE="$ROOT/tools/gui_preview_probe.exe"
SHOTS="$ROOT/docs/shots"

SPECS=("$@")
if [ "${#SPECS[@]}" -eq 0 ]; then
    # ★ v80：默认把**两个 exe** 的每一屏都跑一遍，末尾带一个**负对照**。
    #   负对照必须在默认跑法里 —— 否则"非 advanced 页签不会画这一页"
    #   这条判据（铁律 128）平时根本不执行，等于白设。
    SPECS=(
        main/advanced:jump
        main/advanced:click
        cfg/advanced:quiz
        cfg/advanced:why
        cfg/advanced:editor
        cfg/advanced:typing
        cfg/advanced:error
        # ★ v81：日志页两屏 —— 默认（事件日志）/ 服务日志。
        #   两屏**成对**（铁律 249）：只截一屏的话，"来源=event" 这条判据
        #   可能恒真（比如下拉框根本没接上），看不出"切换到底生效没有"。
        #   判据里还有一条 `项数=2` —— 那是"控制台日志已删除"的机器判据。
        cfg/log
        cfg/log:svc
        main/ark
    )
fi

cd "$ROOT" || exit 1

echo "=== [1/4] 出免提权主程序 -> $DEMO/BuildCheck ==="
R3SHIELDCORE_NO_UAC=1 bash build.sh BuildCheck x64 2>&1 | tail -2 || exit 1
if [ ! -f "$MAIN_EXE" ]; then
    echo "[败] 没出 $MAIN_EXE"
    exit 1
fi

echo ""
echo "=== [2/4] 出配置工具 -> $CFG_EXE ==="
bash build_cfgtool.sh x64 2>&1 | tail -2 || exit 1
if [ ! -f "$CFG_EXE" ]; then
    echo "[败] 没出 $CFG_EXE"
    exit 1
fi

# ★ v80：把 cfg **放到主程序旁边**。
#
#   为什么必须这一步：主程序点「高级」时按 `GetModuleFileName(本进程)` 的目录
#   去找 `r3shieldcore-cfg.exe`（见 cfg_launch.h 的 CfgExePath）——
#   这正是**发布布局**（两个 exe 同目录）。而 BuildCheck 是验证专用的
#   另一个目录，里面只有主程序。
#
#   ⚠️ 漏了这一步的后果**不是崩溃，而是"点了没反应"** —— 主程序会在页内
#      画出"找不到 r3shieldcore-cfg.exe：<路径>"，探针的
#      「不许出现 失败=1」那条判据会红。也就是说：这条判据**抓到过真问题**
#      （第一次跑就是这个原因红的），不是摆设。
cp -f "$CFG_EXE" "$DEMO/BuildCheck/r3shieldcore-cfg.exe" || exit 1

echo ""
echo "=== [3/4] 编探针 ==="
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
echo "=== [4/4] 逐规格：起预览 -> 截图 -> 断言 ==="
rc_all=0
for spec in "${SPECS[@]}"; do
    app="main"
    rest="$spec"
    case "$spec" in
        */*) app="${spec%%/*}"; rest="${spec#*/}" ;;
    esac
    tab="${rest%%:*}"
    mode=""
    case "$rest" in
        *:*) mode="${rest#*:}" ;;
    esac

    if [ "$app" = "cfg" ]; then
        exe="$CFG_EXE"
    else
        exe="$MAIN_EXE"
    fi

    # 截图文件名带上 app + 状态，否则各屏会互相覆盖（只剩最后一张）。
    label="$app-$tab"
    [ -n "$mode" ] && label="$label-$mode"
    echo ""
    echo "---- 规格: $spec（app=$app 页签=$tab 状态=${mode:-默认}）----"
    bmp="$SHOTS/gui-preview-$label.bmp"
    png="$SHOTS/gui-preview-$label.png"
    "$PROBE" "$exe" "$tab" "$bmp" "$mode" "$app"
    rc=$?
    [ "$rc" -eq 0 ] || rc_all=1
    if [ -f "$bmp" ]; then
        python tools/bmp_to_png.py "$bmp" "$png" && rm -f "$bmp"
    fi
done

echo ""
echo "=== 结果 ==="
if [ "$rc_all" -eq 0 ]; then
    echo "PASS：预览截图与判据全部通过（图在 docs/shots/）"
else
    echo "FAIL：有判据没过（exit=2 窗口没起来；exit=1 见上面 [FAIL] 行）"
fi
exit "$rc_all"
