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
#   1) 校验 `R3ShieldCore/Release/` 里 4 个引擎产物都在；
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
echo "[OK] 4 个引擎产物都在。"
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
for _stale in r3shieldcore-console.log r3shieldcore-events.log; do
    if [ -f "$DIST_DIR/$_stale" ]; then
        rm -f "$DIST_DIR/$_stale"
        echo "  清掉运行时残留: $_stale"
    fi
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

# ---- 3) 验收：内容相等（md5），不是"文件存在"
#      ★ 这一步不能省 —— 它正是 v57 事故之后补的那道闸门。
exec bash check_dist_sync.sh "$DIST_DIR"
