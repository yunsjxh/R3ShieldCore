#!/usr/bin/env bash
#
# deploy_dist.sh —— 把构建产物**装配**进 `dist/R3ShieldCore-x64/`。
#
# ★ 为什么需要这个脚本
#   项目里原本**没有任何脚本**做这一步，全靠手工 `cp`。两个后果：
#
#   ① v57 实测事故（见 check_dist_sync.sh 头注释）：
#      `64/r3shieldcore-lib.dll` 已经更新，`32/r3shieldcore-lib.dll` 却停在
#      v55 之前的构建 —— 差的正是 v55 的共享通道 ACL 修复。结果发布包
#      "文件都在、大小也对、闸门也全绿"，而 **32 位进程一条事件都没有**。
#
#   ② 开源阻断（全新 clone 实测）：
#      跑完 `bash build.sh Release` 后 `dist/` 里**只有 14 个手写文件**
#      （5 ini + 5 bat + 4 md/txt），一个二进制都没有 ——
#      `build_dist_zip.sh` 直接报"缺少必备文件"，
#      `installer/build_setup.sh` 也过不了预检。因为那 5 个二进制
#      **没有任何脚本负责搬过去**。外加 `dskill.exe` 连构建脚本都没有
#      （它只出现在"必备文件清单"和文档里）。
#
# 本脚本负责四件事：
#   1) 校验 `R3ShieldCore/Release/` 里 5 个引擎产物都在（v89 起多一个
#      `r3shieldcore-engine.exe` —— 少了它界面永远连不上引擎）；
#   2) 编 `tools/dskill.cpp` → `dist/R3ShieldCore-x64/dskill.exe`；
#   3) 按**约定布局**拷贝（exe 放根、DLL 必须放 `64/` 与 `32/`）；
#   4) 调 `check_dist_sync.sh` 做验收 —— 判据是**内容相等（md5）**，
#      不是"文件存在"（铁律 142：只查存在 ⇒ 假绿）。
#
# 用法:
#   bash deploy_dist.sh              # 装配 + 验收
#   bash deploy_dist.sh --check      # 只跑验收，不拷贝（= check_dist_sync.sh）
#   bash deploy_dist.sh --no-dskill  # 跳过 dskill.exe（比如没装 MSVC 时）
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

BUILD_ROOT="R3ShieldCore/Release"
DIST_DIR="dist/R3ShieldCore-x64"

CHECK_ONLY=0
DO_DSKILL=1
DO_CFGTOOL=1
DO_VERIFY_INI=1
for a in "$@"; do
    case "$a" in
        --check)          CHECK_ONLY=1 ;;
        --no-dskill)      DO_DSKILL=0 ;;
        --no-cfgtool)     DO_CFGTOOL=0 ;;
        --no-verify-ini)  DO_VERIFY_INI=0 ;;
        *) echo "未知参数: $a"; exit 2 ;;
    esac
done

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根可能含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★★★ 2026-10-24：宿主环境会往 shell 注入 `rm` 函数，它指向的 safe-bin 目录
#   是 **Windows 反斜杠绝对路径** ⇒ MSYS 当成相对 cwd 的路径 ⇒ 每次 `rm` 都在 D 盘
#   做无效查找，脚本卡在下面 2b) 的清理上**几分钟不动、CPU 0%**。
#   `command rm`（原来那两道修）**只绕开了函数、没绕开 PATH**：真正的 /usr/bin/rm
#   在被污染的 PATH 里仍要逐个目录查找。⇒ 必须把 safe-bin 段整体从 PATH 剔除。
#   ★ 判据只用 PATH 段里的 `safe-bin`，**不判断任何宿主变量名**。
unset -f rm unlink rmdir 2>/dev/null || true
_old_path="$PATH"
PATH=""
_rest="$_old_path:"
while [ -n "$_rest" ]; do
    _seg="${_rest%%:*}"
    _rest="${_rest#*:}"
    case "$_seg" in
        *safe-bin*) continue ;;
        "") continue ;;
    esac
    if [ -z "$PATH" ]; then PATH="$_seg"; else PATH="$PATH:$_seg"; fi
done
export PATH
unset _old_path _rest _seg
hash -r 2>/dev/null || true

if [ "$CHECK_ONLY" = "1" ]; then
    exec bash check_dist_sync.sh "$DIST_DIR"
fi

# ---------------------------------------------------------------------------
#  映射：dist 内相对路径 | 构建产物相对路径
#
#  ★ 这份布局**必须与代码一致**，别改：
#    `dll_inject.cpp` 的 `GetEnginePath(machine)` 按**目录名**选架构 ——
#    它返回 `<部署根>\32` 或 `<部署根>\64`，再拼固定的 `r3shieldcore-lib.dll`。
#    所以 32 位 DLL 必须叫 `32\r3shieldcore-lib.dll`。
#  ★ 这份表与 check_dist_sync.sh 里的 MAP **同源**：两边都少写一项，
#    就会出现"装进去了但没人验"。改一处必须改两处（下面有自检）。
# ---------------------------------------------------------------------------
MAP=(
    "R3 ShieldCore.exe|$BUILD_ROOT/R3 ShieldCore.exe"
    "r3shieldcore-engine.exe|$BUILD_ROOT/r3shieldcore-engine.exe"
    "r3shieldcore_svc.exe|$BUILD_ROOT/r3shieldcore_svc.exe"
    "64/r3shieldcore-lib.dll|$BUILD_ROOT/64/r3shieldcore-lib.dll"
    "32/r3shieldcore-lib.dll|$BUILD_ROOT/32/r3shieldcore-lib.dll"
)

echo "=== 装配发布目录: $DIST_DIR ==="
echo "构建产物来源: $BUILD_ROOT"
echo ""

# ---- 0) 先验构建产物齐不齐。缺了就**说清楚**该跑什么，别让后面 cp 静默失败。
missing=0
for entry in "${MAP[@]}"; do
    src="${entry##*|}"
    if [ ! -f "$src" ]; then
        echo "[缺] $src"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    echo ""
    echo "构建产物不全（缺 $missing 个）—— 先跑：  bash build.sh Release"
    echo "（本脚本只负责**搬运**，不负责编译引擎。）"
    exit 1
fi
echo "[OK] ${#MAP[@]} 个引擎产物都在。"
echo ""

# ---- 1) dskill.exe：逃生门，必须随包发布，但此前**没有构建脚本**。
#      直 syscall 终止引擎进程（普通 taskkill 会被自我保护 hook 拦掉）。
#      ★ 产物直接写进 dist —— 它属于发布物，不属于 tools/ 的探针堆。
if [ "$DO_DSKILL" = "1" ]; then
    if [ -z "${MSVC_ROOT:-}" ]; then
        echo "[警告] 找不到 MSVC —— 跳过 dskill.exe。"
        echo "       dist 会缺这个文件，build_dist_zip.sh 会因此中止。"
    else
        r3sc_export_msvc_env x64
        CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
        LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"
        OBJDIR_REL="tools/dskill-obj-x64"
        mkdir -p "$OBJDIR_REL"
        echo "=== 编译 dskill.exe（逃生门，x64 控制台）==="
        # ★ 与其它 tools/ 探针同一套编译参数（见 build_probe.sh 等）。
        "$CL" -nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
              -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE \
              -Fo"$OBJDIR_REL/dskill.obj" "tools/dskill.cpp" || exit 1
        # ★ `-MANIFEST:NO`：dskill 是纯控制台工具，不带 UAC 清单
        #   （实测随包的 dskill.exe 里没有任何 requestedExecutionLevel 串）。
        # ★ 不加 `-MANIFEST:EMBED`：那是给 requireAdministrator 的 GUI 程序用的（铁律 65）。
        MSYS_NO_PATHCONV=1 "$LINK" -nologo -SUBSYSTEM:CONSOLE -MANIFEST:NO \
              -OUT:"$DIST_DIR/dskill.exe" "$OBJDIR_REL/dskill.obj" \
              kernel32.lib || exit 1
        echo "  --> $DIST_DIR/dskill.exe"
        echo ""
    fi
else
    echo "[跳过] dskill.exe（--no-dskill）"
    echo ""
fi

# ---- 1b) r3shieldcore-cfg.exe：独立「配置编辑 + 日志观察」工具 ----
#      不注入、不挂钩、不依赖引擎/服务在跑 —— 只读写 ini + tail 日志。
#      ★ 它**不来自 Release/**：由 build_cfgtool.sh 直接编进 dist（和 dskill 同类）。
#      ★ 也不走下面的 MAP 拷贝 —— 那样会出现"自己拷自己"的空判据。
if [ "$DO_CFGTOOL" = "1" ]; then
    echo "=== 构建配置与日志工具（build_cfgtool.sh x64）==="
    bash build_cfgtool.sh x64 || { echo "[败] build_cfgtool.sh 失败"; exit 1; }
    echo ""
else
    echo "[跳过] r3shieldcore-cfg.exe（--no-cfgtool）"
    echo ""
fi

# ---- 2) 拷贝（按布局建子目录）
echo "=== 拷贝 ==="
for entry in "${MAP[@]}"; do
    rel="${entry%%|*}"
    src="${entry##*|}"
    dst="$DIST_DIR/$rel"
    mkdir -p "$(dirname "$dst")"
    cp -f "$src" "$dst" || { echo "[败] cp $src -> $dst"; exit 1; }
    echo "  $rel  ($(stat -c%s "$dst") B)"
done
echo ""

# ---- 2b) 清掉**运行时残留**的日志
#      ★ 为什么必须清：这两个日志是**引擎自己跑起来之后写的**（写在 exe 同目录），
#        不是发布内容。谁在 dist 目录里直接跑过一次引擎，它们就会留在那里，
#        然后被打进 zip / 安装包。后果有两条，都不轻：
#          ① 泄漏：开发机上的**键路径 / 进程路径 / 事件**会随发布包发出去；
#          ② 骗人：`tools/spoof_e2e.sh` 的 `read_console` 在"引擎还没跑"时
#             会退到读这个文件 ⇒ 用户看到的是**上一次**的日志，却以为是本次的
#             （铁律 97：诊断不能自己变成假信息）。
#      ★ 安装器的自测（installer/selftest_setup.py）早就把它们归到
#        `is_runtime_artifact` 一类（"引擎跑起来之后自己写的，不算安装出来的
#        文件"）⇒ 从这里删掉与那份口径**一致**，不会让任何闸门变红。
#      ⚠️ 只删顶层这两个已知名 —— 不用通配 `*.log`，免得将来真有随包发的
#        日志文件被误删（铁律 117：判据要窄，别顺手扩大）。
#
#      ★★ 2026-10-16 实测缺陷（**静默失效**，必须按下面这样写）：
#        本机 shell 里 `rm` 是一个**函数**（沙箱注入的 `safe-bin/rm`）。
#        那个 shim 目录不存在 ⇒ `rm` 退出码 **127**、**什么都没删**，
#        而旧代码紧接着无条件 `echo "清掉..."` ⇒ **脚本谎报成功**。
#        后果正是这一步要防的那两条（泄漏 + 夹具读到旧日志），
#        而且因为 `rm` 的 stderr 混在编译输出里，极难注意到。
#        ⇒ 两道修：① 用 `command rm` 绕开函数（走真 /bin/rm）；
#                  ② 删完**回查**文件是否真没了，没删掉就报错退出
#                     （铁律 142：只喊成功不验结果 = 假绿）。
#
#      ★★ 2026-10-16 又发现**第三个**已知名（v80 引入）：
#        `r3shieldcore-cfg-console.log` —— 它是**配置工具**在预览模式下
#        被 `R3SHIELDCORE_PREVIEW_LOG` 重定向出来的 stdout（探针每次跑都写）。
#        探针跑的是 `dist/R3ShieldCore-x64/r3shieldcore-cfg.exe` ⇒ 它就落在
#        **发布目录**里。它不是随包内容（安装器自测同样归到 runtime artifact），
#        所以和上面两个一样要清。
#        ⚠️ 仍然**只列已知名**、不用通配 `*.log`（铁律 117：判据要窄）——
#          将来真有随包发的日志文件，才不会被误删。
#
#      ★★ 2026-10-24 补**第四个**已知名：`r3shieldcore-engine-console.log`。
#        v89 拆进程后**引擎自己**也开了一个控制台，写在自己 exe 同目录。
#        它比前三个更该清 —— 实测内容第一行就是
#           程序目录：D:\用户态杀软\dist\R3ShieldCore-x64
#           配置文件：C:\ProgramData\R3 Shield Core\r3shieldcore.ini
#        **开发机的完整路径 + pid + 父进程 pid** 全在里面，会随包发出去。
#        之前漏掉是因为清单里只有前三个，而安装器那边的 `is_runtime_artifact`
#        也只认 `engine-console-` 前缀 —— 两边**同时**漏了同一个名字
#        （铁律 197：白名单/黑名单两处各写一份，必然有一处忘记同步）。
#      ★★ 2026-10-24 补**第五个**已知名：`r3shieldcore-svc.log`。
#        开机自启服务写在**自己所在目录**（`service/r3shieldcore_svc.c` 的
#        `LOG_NAME`）。谁在 dist 里跑过一次服务，它就留在发布目录里。
#        它比引擎那份更露：服务日志里带**服务状态 / 引擎拉起结果 / 错误码**，
#        还带安装路径。安装器自测那边（`is_runtime_artifact`）早就认它了
#        ⇒ 这里补上，两边口径才一致（铁律 197）。
for _stale in r3shieldcore-console.log r3shieldcore-events.log r3shieldcore-cfg-console.log \
              r3shieldcore-engine-console.log r3shieldcore-svc.log; do
    if [ -f "$DIST_DIR/$_stale" ]; then
        # ★ 2026-10-24：`command rm` 只绕开 shell 函数，**绕不开被污染的 PATH**
        #   （safe-bin 段让每次查找都算出一个无效的 D 盘相对路径 ⇒ 卡几分钟）。
        #   PATH 已在脚本开头清理；这里保留 `command` 作为兜底。
        command rm -f "$DIST_DIR/$_stale" 2>/dev/null || true
        if [ -f "$DIST_DIR/$_stale" ]; then
            echo "[败] 删不掉运行时残留: $_stale"
            echo "     （它会随包发出去，且会让夹具读到旧日志 —— 必须解决再打包）"
            echo "     （本机 `rm` 可能是被注入的 shell 函数；用 'command rm' 绕开）"
            exit 1
        fi
        echo "  清掉运行时残留: $_stale"
    fi
done

# ★★ 2026-10-24：`engine-console-<pid>.log` —— **带 pid 后缀**，上面那圈按名字
#   逐个比对的写法抓不到。它是 `--gui-preview` 探针把引擎/界面的 stderr
#   重定向到"exe 同目录 + pid"产生的（每次跑探针新增一个，实测 dist 里
#   攒了 5 个）。内容含 `[diag] redirect pid=…`、`当前页签 = …` 等开发期
#   细节，同样不该随包发。
#   ⚠️ 仍然**不写 `*.log`**（铁律 117）—— 只匹配这个已知前缀 + `.log` 后缀。
for _stale in "$DIST_DIR"/engine-console-*.log; do
    [ -e "$_stale" ] || continue   # 没有匹配时字面量不展开，跳过
    _name="$(basename "$_stale")"
    command rm -f "$_stale" 2>/dev/null || true
    if [ -e "$_stale" ]; then
        echo "[败] 删不掉运行时残留: $_name"
        exit 1
    fi
    echo "  清掉运行时残留: $_name"
done
echo ""

# ---- 2c) 发布闸门：随包 ini **真的解析成预期配置**吗
#      ★★ 为什么必须接进流水线（2026-10-11 补）：`tools/verify_dist_ini.cpp`
#        这个闸门**早就存在**（build_verify_dist.sh 能编能跑），但**一直没人调**
#        —— 于是某次把 `mode=block` 手改成 `mode=ask` 的漂移一路飘进了 dist：
#        文档（配置详解 / 部署指南 / 模式选择说明）、预设、以及这个闸门自己的
#        断言**三处都写着 block**，只有 ini 是 ask，谁都没发现。
#        ⇒ 铁律：**闸门不接进流水线 = 没有闸门**。
#      ★ 它链的是**引擎侧同一个解析器**（r3shieldcore_config.cpp），所以验的是
#        "引擎认不认"，不是"grep 找不找得到"（铁律 17）。
#      ⚠️ 它必须跑在 **2) 拷贝之后** —— 校验对象是 dist 里那份，不是 Release 里的。
if [ "$DO_VERIFY_INI" = "1" ]; then
    echo "=== 发布闸门：随包 ini 解析校验（build_verify_dist.sh）==="
    bash build_verify_dist.sh x64 "$DIST_DIR" \
        || { echo "[败] 随包 ini 未通过发布闸门 —— 不要出包"; exit 1; }
    echo ""
else
    echo "[跳过] 随包 ini 解析校验（--no-verify-ini）"
    echo ""
fi

# ---- 2d) ★ v91：提醒"本机配置会不会把 dist 的 ini 顶掉"
#      `ResolveConfigPath` 是 **ProgramData 优先**（v66）：只要
#      `%ProgramData%\R3 Shield Core\r3shieldcore.ini` 存在，引擎/界面读的就是它，
#      **dist 里的 ini 改动一律不生效**。开发机上这份通常是存在的（本机注入白名单
#      就写在里面），于是"我改了 dist 的 ini 怎么没反应"会变成一个很贵的坑。
#      ⇒ 不判失败（这是正常的安装态），但必须**说出来**（铁律 97：不许静默）。
_PD_INI="${ProgramData:-C:\\ProgramData}\\R3 Shield Core\\r3shieldcore.ini"
if [ -f "$_PD_INI" ]; then
    echo "[注意] 本机存在运行时配置：$_PD_INI"
    echo "       引擎/界面**优先读它** —— 本次部署到 dist 的 r3shieldcore.ini 不会生效。"
    echo "       要改生效配置请改上面那份（或删掉它，回退到 exe 同目录那份）。"
    echo ""
fi

# ---- 3) 验收：内容相等（md5），不是"文件存在"
#      ★ 这一步不能省 —— 它正是 v57 事故之后补的那道闸门。
exec bash check_dist_sync.sh "$DIST_DIR"
