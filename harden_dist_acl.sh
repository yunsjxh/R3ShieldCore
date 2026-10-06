#!/usr/bin/env bash
#
# harden_dist_acl.sh —— ★ 已废弃（v57）。默认行为已改为「还原权限」。
#
# 【v57 的产品决策：不再加固部署目录】
#   v56 及更早有一道硬门槛：DLL 所在目录必须对
#   Everyone / Authenticated Users / BUILTIN\Users 都不可写，
#   否则引擎抛异常退出（`engine_control.cpp` 里的 IsProtectedEngineDeployment）。
#
#   它挡的是"低权限进程替换 DLL/exe，借管理员启动提权"。但代价太大：
#   加固用 `icacls <目录> /inheritance:r ... Users:(OI)(CI)RX`，而 `(OI)(CI)`
#   会**继承到所有子文件** —— 于是 `r3shieldcore.ini` 也被锁成只读，
#   用户改完保存不了（实测 `Permission denied` / `[Errno 13]`）。
#
#   对比：Windows Defender 的 `C:\ProgramData\Microsoft\Windows Defender`
#   也是 `BUILTIN\Users:(RX)`，形状一模一样。差别在**锁是谁给的** ——
#   它是安装位置/OS 免费给的，不需要用户手动跑脚本。
#   ⇒ 结论：锁没错，"用脚本锁 + 锁到配置文件"才是错的。
#
#   2026-10-05 决定：删除那道门禁，本脚本**不再用于出包**。
#   保留下来只为了**修旧目录** —— 老部署被加固过，ini 改不了。
#
# 用法（默认就是还原）:
#   bash harden_dist_acl.sh <目录>              # 还原成继承 ACL（ini 可写）
#   bash harden_dist_acl.sh --unharden <目录>   # 同上
#   bash harden_dist_acl.sh --verify <目录>     # 只看现状，不改
#   bash harden_dist_acl.sh --harden <目录>     # ★ 只在明确需要时才用：
#                                               #   重新加固（会再次锁住 ini）
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

# ★ 参数解析必须与顺序无关（2026-10-05 踩到）：
#   原来只认"模式参数必须在第一位"，于是
#       bash harden_dist_acl.sh <目录> --unharden
#   里的 `--unharden` 被当成**目录**（或直接被忽略），MODE 保持 harden
#   ⇒ **静默执行了加固**，而屏幕上照样打"已加固" —— 用户以为放开了写权限，
#     实际越跑越紧（这是最坏的一类错：方向反了还不报错）。
#   现在扫描**所有**参数：以 `--` 开头的当模式，第一个非 `--` 的当目录。
MODE="unharden"
TARGET=""
for arg in "$@"; do
    case "$arg" in
        --verify)   MODE="verify" ;;
        --unharden) MODE="unharden" ;;
        --harden)   MODE="harden" ;;
        --*)        echo "!! 未知参数: $arg"; exit 2 ;;
        *)          if [ -z "$TARGET" ]; then TARGET="$arg"; fi ;;
    esac
done
TARGET="${TARGET:-dist/R3ShieldCore-x64}"

cd "$PROJECT_ROOT" || exit 1

if [ ! -d "$TARGET" ]; then
    echo "!! 目录不存在: $TARGET"
    exit 1
fi

# ★ MSYS_NO_PATHCONV=1 必须加：否则 Git Bash 会把 icacls 的 /T /C 当成路径转换。
#   （本项目踩过多次，见铁律「MSYS 路径转换」。）
run_icacls() {
    MSYS_NO_PATHCONV=1 icacls "$@"
}

if [ "$MODE" = "unharden" ]; then
    echo "=== 还原权限（去掉加固留下的显式 ACE）：$TARGET ==="
    echo "    用途：让 r3shieldcore.ini 等配置文件重新可写。"
    echo "    ★ v57 起引擎不再要求目录不可写，所以还原后引擎照常启动。"
    #
    # ★ 用 `/reset /T /C` 而不是 `/grant:r ... /T`：
    #   `/reset` 把每个对象还原成「从父目录继承」，会**抹掉加固留下的显式 ACE**，
    #   这正是"回到出厂状态"该做的事。`/grant:r` 只是再加一条显式 ACE，
    #   结果是"继承 ACE + 显式 ACE"叠加，看着能写但语义脏。
    #
    #   `/C` = 遇到改不动的对象继续（例如引擎以管理员身份建的日志文件，
    #   属主是 Administrators，非提权进程改不了它的 DACL；它们本来也不影响使用）。
    #
    #   ⚠️ `/reset /T` 安全：这里**没有** `/inheritance:r` + `/grant:r` 那个组合，
    #      不会出现"文件留下空 DACL"的事故（那个坑只属于 harden 那一支）。
    run_icacls "$TARGET" /reset /T /C >/dev/null 2>&1 || true
    echo ""
    echo "=== 还原后 ==="
    run_icacls "$TARGET" | head -8
    echo ""
    echo "[OK] 已还原为继承 ACL —— 配置文件现在可以直接编辑保存。"
    exit 0
fi

if [ "$MODE" = "harden" ]; then
    echo "=== 加固前 ==="
    run_icacls "$TARGET" | head -12

    echo ""
    echo "=== 加固 $TARGET（只加固根目录，不加 /T）==="

    # ★★ 2026-10-04 实测踩到：**先清子对象上的残留「显式」ACE，再加固根目录。**
    #
    #   坑的形状：`--unharden` 用了 `/T` 之后，根目录、子目录、exe 上都会留下
    #   **显式**的 `Users:(M)` ACE。而加固那一支只在**根目录**做
    #   `/inheritance:r` —— 它**改不掉子对象上的显式 ACE**（`/inheritance:r`
    #   只影响被作用的那一个对象）。
    #
    #   ⇒ 结果最阴险：根目录看起来是 `Users:(OI)(CI)(RX)`（正确），
    #     但 `64\` 目录和 DLL 上还挂着显式 `Users:(M)`
    #     ⇒ **引擎仍然拒绝加载、仍然零防护**，而屏幕上只有一句"加固完成"。
    #     这正是铁律 39 那一类"静默失效"。
    #
    #   `/reset /T` 把每个对象的 ACL 还原成"从父目录继承"，
    #   从而**抹掉所有显式 ACE**；它同时也会重置根目录（暂时变可写），
    #   所以**必须紧跟着**下面那条加固命令 —— 顺序不能反。
    #   `/C` = 遇到改不动的对象继续（例如引擎以管理员身份建的日志文件，
    #   属主是 Administrators，非提权进程连它的 DACL 都改不了）；
    #   那些对象本来就已经是 `(I)(RX)`，跳过它们没有风险。
    run_icacls "$TARGET" /reset /T /C >/dev/null 2>&1 || true

    if ! run_icacls "$TARGET" /inheritance:r \
        /grant:r "*S-1-5-32-544:(OI)(CI)F" \
                 "*S-1-5-18:(OI)(CI)F" \
                 "*S-1-5-32-545:(OI)(CI)RX"; then
        echo "!! 加固失败（可能需要管理员权限，或目录被占用）"
        exit 1
    fi

    echo ""
    echo "=== 加固后 ==="
    run_icacls "$TARGET" | head -8
fi

# ── 验证：用**与引擎同一份**判据来看现状 ────────────────────────────
# ★ v57：引擎已删除这道门禁，所以探针的结论**不再决定引擎能不能启动**。
#   现在它只是"这个目录对不对外开放写权限"的自查。
PROBE="tools/deploy_acl_probe.exe"
if [ ! -f "$PROBE" ]; then
    echo ""
    echo "=== 探针不存在，先编译 ==="
    bash build_deploy_acl_probe.sh "$TARGET/64" >/dev/null 2>&1
fi

if [ ! -f "$PROBE" ]; then
    echo "!! 无法编译 deploy_acl_probe.exe，跳过验证"
    exit 1
fi

echo ""
echo "=== 现状（deploy_acl_probe，仅供参考）==="
"./$PROBE" "$TARGET/64" --no-pause
rc=$?

echo ""
if [ "$rc" -eq 0 ]; then
    echo "[信息] $TARGET 目录对普通用户不可写（旧的加固态）。"
    echo "       v57 起引擎照常启动，但 r3shieldcore.ini 会改不了 ——"
    echo "       要能编辑配置请跑： bash harden_dist_acl.sh $TARGET   （默认就是还原）"
else
    echo "[信息] $TARGET 对普通用户可写 —— v57 起这是**预期状态**，不是错误。"
    echo "       引擎会正常启动，配置文件可以直接编辑保存。"
fi
# ★ 不再把探针结论当失败：v57 起"可写"才是对的。
exit 0
