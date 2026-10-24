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
#   cfg  + advanced : quiz(默认) | why | editor | typing | error | cycle | scroll
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
# ★ v92：预览模式默认**实时**抓背景（人眼看效果必须是跟手的）。
#   闸门要的是"可重复的截图"，所以这里显式冻住 —— 冻住后背景不再重抓，
#   截图就不会撞上"抓屏那几毫秒窗口被 WDA 排除"的瞬间（截到一张洞）。
#   反过来说：这一条也让"背景是实时还是冻结"这件事在闸门里是确定的，
#   不依赖谁记不记得设环境变量。
export R3SHIELDCORE_PREVIEW_FREEZEBG=1
# ★ v128 备注（别再往这里加）：规则文件的"来源=示例"由**探针**保证 ——
#   它把 `R3SHIELDCORE_PREVIEW_RULES` 指到 `<exe 目录>\r3shieldcore-rules-preview.txt`
#   并先 `DeleteFile`（见 gui_preview_probe.cpp）。探针会**覆盖**这里设的值，
#   所以在这里再设一遍是无效配置（两处配置一处生效 = 以后一定有人改错地方）。
#   直接手工跑 `--gui-preview` 时不设 ⇒ 读本机真实规则文件（那正是想要的）。
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
        # ★ v88：主程序的四个常规页也进默认跑法。
        #   以前默认只跑 advanced/ark/cfg —— 而 v86~v88 改的恰恰是
        #   **所有页共用的内容层**（场景渲染器），不跑就等于没验。
        main/overview
        main/log
        main/process
        main/config
        main/advanced:jump
        main/advanced:click
        cfg/advanced:quiz
        cfg/advanced:why
        cfg/advanced:editor
        # ★ v82：`cycle` = 让界面**真的走一遍**闸门 -> 解析 -> 编辑台 的切换。
        #   为什么必须有这一屏（这是一个真缺陷的判据）：
        #   摘要行/说明行是**直接画在底色上**的，而状态切换走
        #   `InvalidateRect(..., FALSE)`（不发 WM_ERASEBKGND）⇒ 旧字留在
        #   原地、新字叠上去。`editor` 那一屏是**直接置状态建窗**，
        #   中间没有那次重绘 ⇒ **永远截不到**这个缺陷（铁律 24/28）。
        #   它必须和 `editor` **成对**：末态相同 ⇒ 像素应当一致；
        #   比对由下面的 compare_band.py 做（判据在脚本末尾）。
        cfg/advanced:cycle
        cfg/advanced:typing
        cfg/advanced:error
        # ★★★ v127：规则表滚动 —— 规则超过一屏上限（6 条）时必须能翻。
        #   为什么必须进默认跑法：这一屏的判据不靠像素（滚没滚只差三行字），
        #   靠的是 cfg 自驱一发真 `WM_MOUSEWHEEL` 后打的 `滚动自检=PASS`。
        #   不进默认跑法 ⇒ 那条分支平时根本不执行（铁律 128）。
        cfg/advanced:scroll
        # ★ v81：日志页两屏 —— 默认（事件日志）/ 服务日志。
        #   两屏**成对**（铁律 249）：只截一屏的话，"来源=event" 这条判据
        #   可能恒真（比如下拉框根本没接上），看不出"切换到底生效没有"。
        #   判据里还有一条 `项数=2` —— 那是"控制台日志已删除"的机器判据。
        cfg/log
        cfg/log:svc
        # ★ v114：配置页 —— 这一屏是**自绘按钮/开关**的主场。
        #   以前默认跑法里根本没有它，而 v114 修的两个缺陷（按钮没有药丸、
        #   「保存」白底白字）恰恰只在这一页现形 ⇒ 不跑就等于没验。
        #   像素判据见下面的 `tools/check_cfg_pills.py`。
        cfg/config
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

    # -----------------------------------------------------------------
    # ★ v114：配置页的**像素**判据 —— 必须趁 BMP 还在时跑。
    #
    #   为什么不能只靠探针的"有内容 / 非白 > 3%"：
    #   按钮没有药丸、白底白字，这两件事都**不影响**那两条判据
    #   （画面上确实有东西、确实不是白的）。它们只在"这块矩形里
    #   到底是什么颜色"上体现 —— 所以判据必须下到像素。
    # -----------------------------------------------------------------
    if [ "$label" = "cfg-config" ] && [ -f "$bmp" ]; then
        echo "  ---- 像素判据: cfg 配置页的自绘按钮 / 滚动条 ----"
        if python "$ROOT/tools/check_cfg_pills.py" "$bmp"; then
            echo "  [ OK ] cfg 配置页像素判据通过"
        else
            echo "  [败] cfg 配置页像素判据未通过（见上）"
            rc_all=1
        fi

        # =================================================================
        # ★★★ v122：**不激活**再抓一遍 —— 专查「首帧子控件没跟着重画」。
        #
        #   为什么必须单独一遍（用户原话：「他的按钮有问题，但是窗口重绘
        #   一下之后就好了，比如把鼠标移上去」）：
        #
        #   探针默认会 `SetForegroundWindow` ⇒ 发 WM_ACTIVATE ⇒ 整窗连子控件
        #   一起重画 ⇒ **正好把这类缺陷抹平**。于是 v114~v121 闸门一直全绿，
        #   用户装上去却一眼看见按钮只剩一行白字。
        #   （铁律 24/28：探针把自己要查的现象改掉了，比没有探针更危险。）
        #
        #   ⇒ 用 `R3SHIELDCORE_PREVIEW_NOACTIVATE=1` 再跑一遍：只抬 z 序、
        #     不激活，窗口停在"刚建出来、没人碰过"的状态，判据才是真的。
        #   ⚠️ 这一遍的**探针断言**可能因为"没抢到前台"而红（那是环境噪声），
        #     所以只认 `check_cfg_pills.py` 的结果；探针那一路只打印不判负。
        # =================================================================
        echo "  ---- 像素判据（不激活 / 没人碰过的首帧）----"
        bmp_na="$SHOTS/gui-preview-$label-noactivate.bmp"
        R3SHIELDCORE_PREVIEW_NOACTIVATE=1 \
            "$PROBE" "$exe" "$tab" "$bmp_na" "$mode" "$app" || true
        if [ -f "$bmp_na" ]; then
            if python "$ROOT/tools/check_cfg_pills.py" "$bmp_na"; then
                echo "  [ OK ] 不激活时按钮/字段同样正常（没有「等重绘才恢复」的缺陷）"
            else
                echo "  [败] 不激活时按钮/字段不对 —— 这就是「重绘一下才好」的缺陷"
                rc_all=1
            fi
            python tools/bmp_to_png.py "$bmp_na" "${bmp_na%.bmp}.png" && rm -f "$bmp_na"
        else
            echo "  [败] 不激活模式没产出截图（探针没起来？）"
            rc_all=1
        fi
    fi

    if [ -f "$bmp" ]; then
        python tools/bmp_to_png.py "$bmp" "$png" && rm -f "$bmp"
    fi
done

# ---------------------------------------------------------------------------
# ★ v82：`cycle` 与 `editor` 的**像素**比对 —— "重绘不擦背景"的唯一机器判据。
# ---------------------------------------------------------------------------
#
# 为什么单独放在循环外：
#   探针是**一个规格一个进程**，它看不到"另一屏"的截图；而这条判据天生
#   需要**两张图**（末态相同 ⇒ 应当像素一致）。所以由脚本在两屏都跑完之后比。
#
# 判据带 y=[138,188)：窗口坐标（截图含边框）里，摘要行 ~147..158、
#   说明行 ~171..182 那一片（下方 159+ 是面板，不参与）。
#   ⚠️ 这个坐标绑定**标准预览几何**（窗口 1024x740、客户区 1008x701）——
#      探针建窗的尺寸是写死的，所以它稳定；哪天窗口尺寸变了，这里要跟着改。
#
# ⚠️ 只在两屏都真的产出了 PNG 时才比 —— 只跑了单屏（`bash ... cfg/advanced:cycle`）
#    时跳过并**明说跳过**（否则"没比"会被读成"比过且通过"）。
CYCLE_PNG="$SHOTS/gui-preview-cfg-advanced-cycle.png"
EDITOR_PNG="$SHOTS/gui-preview-cfg-advanced-editor.png"
if [ -f "$CYCLE_PNG" ] && [ -f "$EDITOR_PNG" ]; then
    echo ""
    echo "---- 像素判据: cycle 末态 vs editor（摘要行/说明行那一带）----"
    python tools/compare_band.py "$CYCLE_PNG" "$EDITOR_PNG" 138 188 0 1010
    rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "  [ OK ] 走完状态切换后，摘要行/说明行与直接进编辑台**像素一致**（没有残留叠字）"
    else
        echo "  [FAIL] 走完状态切换后那一带**多出内容** —— 重绘没擦背景，旧状态的字留在原地"
        echo "         （这就是 v82 修掉的那个真缺陷；判据带见 tools/compare_band.py 的注释）"
        rc_all=1
    fi
else
    echo ""
    echo "---- 像素判据: 跳过（需要同时跑 cfg/advanced:editor 与 cfg/advanced:cycle）----"
fi

echo ""
echo "=== 结果 ==="
if [ "$rc_all" -eq 0 ]; then
    echo "PASS：预览截图与判据全部通过（图在 docs/shots/）"
else
    echo "FAIL：有判据没过（exit=2 窗口没起来；exit=1 见上面 [FAIL] 行）"
fi
exit "$rc_all"
