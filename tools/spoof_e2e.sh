#!/usr/bin/env bash
#
# spoof_e2e.sh —— 回传数据「替换」的**端到端**验证 runner（v74：三面统一）。
#
# 它回答的问题：把**真引擎**跑起来、让它注入一个**真进程**之后，
#   屏幕 / 剪贴板 / 注册表 三个面的 spoof_*=1 到底有没有让那个进程
#   "取数据成功但拿到假内容"？
#
# ======================================================================
# ★ 三面的语义**不是**同一个 —— 这决定了矩阵怎么设计（v74 新增）
# ======================================================================
#   · 屏幕 / 剪贴板：替换**只在"本应拒绝"时**生效（RejectOrSpoof）。
#       ⇒ mode=log 下根本不拒 ⇒ 也**不替换**，调用方拿到真数据。
#   · 注册表（值替换）：替换发生在**读路径**上（!blockable 分支），
#       与 mode **无关** —— log 下照样清零。
#       ⇒ 矩阵里专门用 C 格把这条差异**证出来**（否则会被当成 bug）。
#
# 所以本 runner 的三格不是"三个开关的组合"，而是三个**语义位置**：
#       A  本应拒绝 + 不替换   ⇒ 看到"失败 / 真值"（负对照）
#       B  本应拒绝 + 替换     ⇒ 看到"成功 + 假内容"
#       C  不拒绝  + 替换      ⇒ 屏幕/剪贴板真、注册表**仍假**（模式无关）
#
# ======================================================================
# ★★★ 为什么默认**不跑**（铁律 175）
# ======================================================================
# 引擎的正常工作是**全局注入**所有非系统进程 —— 包括你正在用的编辑器 /
#   IDE。本机跑它会把编辑器 hook 崩（用户明令 2026-10-06）。
#
# ★ v69 起用 ini 的 test_inject_only= 把注入范围缩到**一个镜像名**
#   （旧版是命令行 --test-inject-only=，v69 已删除，理由见 shared 头
#   FlagTestMode 那段）。**理论上**这样就安全了；但"白名单真的生效了吗"
#   只能靠跑起来才知道，所以仍然**必须显式加 --run-engine** 才执行
#   （沿用仓库既有约定，见 installer/selftest_setup.py 第 4 层）。
#
# 不加 --run-engine：打印说明 + [skip]，**并把跳过数写进结论行**
#   （铁律 178：跳过必须可见并计数，否则"故意没跑"和"全绿"输出一样）。
#
# ======================================================================
# ★ 为什么是「两步式」（--prepare 然后 --run-engine）
# ======================================================================
# 引擎的清单是 requireAdministrator ⇒ 启动它的那个 shell **必须已提权**。
#   非提权的 shell 提不了权（沙箱里 net session 直接失败，UAC 也起不来），
#   所以本脚本**不替你提权**，而是把准备工作全做完，让你只需要在**管理员终端**
#   里跑一条命令。
#
#   bash tools/spoof_e2e.sh --prepare      # 不需要管理员：查产物 / 验基线 / 搭配置
#   bash tools/spoof_e2e.sh --run-engine   # 需要管理员：冒烟闸门 + 真跑三格 + 出结论
#   bash tools/spoof_e2e.sh --collect      # 只重新解析上一次 --run-engine 的落盘结果
#
# ⚠️ 不会碰你真实的 %ProgramData%\R3 Shield Core\ —— 整个测试跑在一份
#    临时工作区里，并把**子进程的** ProgramData 重定向到那里。
#
# ⚠️ 会在 HKCU\Software\R3ShieldCoreE2E 建一个**测试用**注册表值
#    （三面里的注册表面要读它）。--clean 会删掉。除此之外不动你的注册表。
#
# 用法:
#   bash tools/spoof_e2e.sh                 # 打印说明 + SKIP（默认）
#   bash tools/spoof_e2e.sh --prepare       # 搭工作区 + 建注册表值 + 写三格配置 + 基线校验
#   bash tools/spoof_e2e.sh --run-engine    # 真跑（管理员终端；先冒烟闸门、再三格矩阵）
#   bash tools/spoof_e2e.sh --collect       # 只出结论（读工作区里的落盘结果）
#   bash tools/spoof_e2e.sh --clean         # 删掉工作区 + 删注册表值
#   可选: --work-dir=DIR
#
# ⚠️ 上面写的 bash … 只在**已经有一个 bash 的环境**里成立（非提权的 shell、
#    Git Bash、MSYS2 终端）。在**本机 cmd** 里 bash 不在 PATH 上，直接敲会得到
#    'bash' 不是内部或外部命令。cmd 下请用脚本自己打印的那条**绝对路径**命令
#    （--prepare / 不带参数时都会打印，形如
#    "D:\…\bash.exe" "D:\…\tools\spoof_e2e.sh" --run-engine）。
#    为什么不在注释里写死那条路径：bash 的安装位置随机器而变，写死必漂（铁律 127）。
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
PROJECT_ROOT="$R3SC_PROJECT_ROOT"
cd "$PROJECT_ROOT" || exit 1

DIST_DIR="dist/R3ShieldCore-x64"
# ★ 引擎名**从目录里派生**，不硬编码 —— 真名是 R3 ShieldCore.exe
#   （R3 和 ShieldCore 之间**只有一个空格**）。铁律 127：名字手抄第二遍必漂，
#   本项目已经踩过"多写一个空格 ⇒ 自测报假 FAIL"的坑。这里直接 glob 出来。
ENGINE="$(ls "$DIST_DIR"/R3*.exe 2>/dev/null | head -1)"
ENGINE_BASE="$(basename "${ENGINE:-R3 ShieldCore.exe}")"
TARGET="tools/spoof_e2e_target.exe"
TARGET_BASE="$(basename "$TARGET")"

# ======================================================================
# 注册表面要用的键 / 值 / 内容 —— **单一来源**（铁律 127）
# ======================================================================
# ⚠️ 这三个常量与 tools/spoof_e2e_target.cpp 里那份**必须一致**：
#    建值在 bash 侧、读值在目标进程里，是**跨进程契约**。
#    目标用 reg_match 判"读到的等不等于 kRegSecret"，所以真漂了会**判 FAIL**
#    而不是静默（铁律 97）。
REG_SUBKEY='Software\R3ShieldCoreE2E'
REG_VALUE='Secret'
REG_SECRET='R3SC-E2E-REG-SECRET'
# protect_reg= 用**相对写法**（文档用法）。用户 hive 会自动跳过
#   \REGISTRY\USER\S-1-5-21-...\ 那段 SID ⇒ 相对写法命中 HKCU
#   （见 r3shieldcore_rules.cpp 的 NormalizeKey + protect_reg_ut 用例）。
REG_PROTECT_PATH="$REG_SUBKEY"

#
# ★ 工作区路径是**固定名**（不带 PID）—— 这是对铁律 177 的**有意例外**：
#   两步式流程要求工作区**跨两次调用存活**，而"同一时刻只能有一份引擎在跑"
#   是硬约束（脚本自己会拒绝第二份）⇒ 天然串行，不存在并行互踩。
#   反过来，带 PID 会让 --prepare 写的东西 --run-engine 找不到。
#
WORK="${TMPDIR:-/tmp}/spoof_e2e_work"

# ======================================================================
# 「管理员终端」提示用的路径
# ======================================================================
# ★★★ 为什么要把这些算出来：本机 cmd 里 **bash 不在 PATH 上**（实测：
#   在管理员 cmd 里敲 bash tools/spoof_e2e.sh --run-engine 得到
#   'bash' 不是内部或外部命令）—— 因为 bash 来自 MSYS2 / PortableGit，
#   它们默认**不往系统 PATH 里写**。用户于是卡在"我该用哪个 bash"。
#   ⇒ 这里把**当前正在跑的 bash** 与**本脚本**都转成 Windows 形式，
#     让用户直接复制粘贴。用 $BASH 而不是硬编码路径：那是**已知能跑**
#     的那一个（本脚本此刻就跑在它上面），比猜一个可能不存在的路径可靠。
#   ⚠️ 必须先转成**绝对**路径：$0 可能是 tools/spoof_e2e.sh 这种相对写法，
#     直接 cygpath -w 出来还是相对的 ⇒ 用户在别的目录下粘贴就找不到。
SELF_ABS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/$(basename "${BASH_SOURCE[0]}")"
SELF_WIN="$(cygpath -w "$SELF_ABS" 2>/dev/null || printf '%s' "$SELF_ABS")"
BASH_WIN="$(cygpath -w "${BASH:-bash}" 2>/dev/null || printf 'bash')"
MSYS2_BASH_WIN="D:\\msys64\\usr\\bin\\bash.exe"

# 打印「用当前这个 bash 跑本脚本」的一行 —— 单点维护（铁律 127）。
# 为什么不写 bash tools/spoof_e2e.sh …：本机 cmd 里没有 bash（见上）。
bash_line() {
    if [ "$BASH_WIN" = "bash" ]; then
        # 兜底：算不出完整路径时打印占位符，**不打印** "bash" ...（见 admin_hint）。
        printf '        <bash.exe 的完整路径> "%s" %s\n' "$SELF_WIN" "$*"
    else
        printf '        "%s" "%s" %s\n' "$BASH_WIN" "$SELF_WIN" "$*"
    fi
}

# 打印"怎么在管理员终端里跑"——三处都调它，避免各写一份（铁律 127）。
admin_hint() {
    echo "  ★ 本机 cmd 里 \`bash\` 不在 PATH 上（bash 来自 MSYS2 / PortableGit）。"
    echo "    以管理员身份打开 cmd（右键「开始」→「终端(管理员)」），粘贴："
    echo ""
    if [ "$BASH_WIN" = "bash" ]; then
        # 兜底：cygpath 没算出完整路径时，**绝不**打印 "bash" ... ——
        # 那看起来是条命令，粘进去却还是 'bash' 不是内部或外部命令，
        # 正是用户报的那个坑（铁律 97：诊断不能自己变成假信息）。
        echo "        <bash.exe 的完整路径> \"$SELF_WIN\" --run-engine"
        echo "    ⚠️ 没能自动算出 bash 的完整路径。常见位置："
        echo "        D:\\msys64\\usr\\bin\\bash.exe"
    else
        bash_line --run-engine
        echo ""
        # 备选：仓库构建链用的那套 MSYS2（存在才提，不给不存在的路径）
        if [ -f "D:/msys64/usr/bin/bash.exe" ]; then
            echo "    备选（本机 MSYS2 自带的 bash —— 构建链用的就是它那套工具链）："
            printf '        "%s" "%s" %s\n' "$MSYS2_BASH_WIN" "$SELF_WIN" "--run-engine"
            echo ""
        fi
    fi
    echo "    ⚠️ 必须**管理员**会话：引擎清单是 requireAdministrator。"
    echo "    ⚠️ 上面 bash 路径里带空格 ⇒ **引号不能省**。"
}

ACTION=""
for a in "$@"; do
    case "$a" in
        --prepare)     ACTION="prepare" ;;
        --run-engine)  ACTION="run" ;;
        --collect)     ACTION="collect" ;;
        --clean)       ACTION="clean" ;;
        --work-dir=*)  WORK="${a#--work-dir=}" ;;
        *) echo "未知参数: $a"; exit 2 ;;
    esac
done

pass=0
fail=0
skip=0

ok()   { echo "  [ OK ] $1"; pass=$((pass+1)); }
bad()  { echo "  [FAIL] $1"; fail=$((fail+1)); }
note() { echo "  [skip] $1"; skip=$((skip+1)); }

# 从目标的 RESULT ... 行里取一个字段。
# ⚠️ 必须**按空格切词**再前缀匹配，不能用 s/.*key=// —— 那是贪婪匹配，
#    而 nonblack= 是 getpixel_nonblack= 的**子串**，会取到最后一个（错的）。
#    同理 clip_read= / reg_read= 也都靠"整词"才分得开。
field() { printf '%s' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }

# 三格矩阵的 (mode, spoof_*) 定义 —— 单一来源，别在两处各写一遍（铁律 127）。
#
# ★ 为什么 A/B 两格是 mode=block 而不是 mode=test：
#   spoof（替换）在屏幕/剪贴板两面**只在"本应拒绝"时才生效**。mode=test
#   的决策行为 = log（全部放行）⇒ 用 test 跑 A/B 永远看不到替换。v69 把
#   「注入范围」与「拦截行为」**解耦**正是为了这个（见 shared 头 FlagTestMode）。
#   test_inject_only= 与 mode= 无关 ⇒ A/B 既能保留 block 行为，又只注入目标。
#
# ★ 三面的 spoof 开关在 A/B/C 里**同进同出**（都是 A=0、B/C=1）—— 所以只用一个
#   函数。写成三个只会漂（铁律 127）。要单独验某一面时再拆。
cell_mode()  { case "$1" in A|B) echo block ;; C) echo log ;; *) echo "" ;; esac; }
cell_spoof() { case "$1" in A) echo 0 ;; B|C) echo 1 ;; *) echo "" ;; esac; }
CELLS="A B C"

cell_desc() {
    case "$1" in
        A) echo "mode=block, spoof_*=0  -> 期望 屏幕被拒 / 剪贴板被拒 / 注册表**读到真值**" ;;
        B) echo "mode=block, spoof_*=1  -> 期望 屏幕成功+黑 / 剪贴板成功+空 / 注册表成功+空" ;;
        C) echo "mode=log,   spoof_*=1  -> 期望 屏幕/剪贴板**真**（不拒就不换）/ 注册表**仍空**" ;;
    esac
}

result_file()  { echo "$WORK/result-$1.txt"; }
console_file() { echo "$WORK/console-$1.log"; }
# 引擎自己重定向出来的控制台日志（RedirectDiagnosticsToFile，主名）。
# ⚠️ 它在 $WORK/app/ 下、**每格都会被覆盖** ⇒ run_cell 跑完必须**拷走**
#    到 console-<格>.log，否则 assert_cells 拿三格都读到最后一格（铁律 127 同族：
#    "一份东西被复用"最容易变成"三格看着一样"）。
engine_console() { echo "$WORK/app/r3shieldcore-console.log"; }
pd_dir()       { echo "$WORK/pd-$1"; }
ini_path()     { echo "$(pd_dir "$1")/R3 Shield Core/r3shieldcore.ini"; }
# 兜底配置（exe 同目录）：ProgramData 重定向失效时引擎会读它。
# ★ 内容刻意与格无关且**最保守**（log + 白名单）—— 见 write_fallback_ini 的注释。
ini_fallback() { echo "$WORK/app/r3shieldcore.ini"; }

read_result() {
    local f; f="$(result_file "$1")"
    [ -f "$f" ] || return 0
    grep -m1 '^RESULT ' "$f" 2>/dev/null
}

read_console() {
    local c; c="$(console_file "$1")"
    # 已拷走的 console-<格>.log 是**已经转好码**的 UTF-8（见 run_cell 的拷贝那一步）。
    if [ -f "$c" ]; then cat "$c"; return 0; fi
    # 还没拷走（或这一格没跑成）⇒ 现场读引擎的日志（**要转码**，见 decode_engine_log）。
    local t; t="$(engine_log_text)"
    if [ -n "$t" ]; then printf '%s\n' "$t"; return 0; fi
    # 最后退到我们自己的 stdout 重定向（引擎若没来得及 freopen，东西还在这）。
    [ -f "$c.raw" ] && cat "$c.raw"
    return 0
}

# ======================================================================
# 引擎控制台日志的**读取**（含编码转换）
# ======================================================================
# ★★★ 引擎的 r3shieldcore-console.log 是 **GBK**，不是 UTF-8 —— 实测（2026-10-10）。
#   根因：build.sh 给 cl 的是 /source-charset:utf-8，但**没给**
#   /execution-charset:utf-8 ⇒ 窄字面量按**系统 ANSI 代码页**（中文机 = CP936/GBK）
#   落盘 ⇒ 引擎 printf 出来的中文字节是 GBK。
#   而本脚本是 UTF-8 ⇒ **不转码的话，所有中文 grep 永远 0 命中**。
#
#   ★ 实测后果（第一次真跑引擎才发现）：注入范围已被限定 / 配置文件 / 模式
#     / 注入新进程 **四个模式全部未命中** ⇒ 夹具每一格都会 FAIL，而且失败信息
#     看起来像"引擎没进限定模式"，跟真实根因（编码）差了十万八千里
#     （铁律 185 同族：判据的载体不对 ⇒ 恒红）。
#   ⇒ 所以**所有**读引擎日志的地方统一走下面三个函数，**出口保证是 UTF-8**。
engine_log_path() {
    if [ -f "$(engine_console)" ]; then printf '%s\n' "$(engine_console)"; return 0; fi
    ls "$WORK/app/"engine-console-*.log 2>/dev/null | head -1
}

# 把（GBK 的）引擎日志转成 UTF-8 写到 stdout。
decode_engine_log() {
    local raw conv
    raw="$(cat)"
    if command -v iconv >/dev/null 2>&1; then
        conv="$(printf '%s' "$raw" | iconv -f GBK -t UTF-8 2>/dev/null)"
        # ★ 判据用"转出来非空"而**不是** iconv 的返回码：日志里若有个别非法字节，
        #   iconv 会返非 0 但**已经转好了绝大部分** —— 那时退回原文才是真的丢信息。
        if [ -n "$conv" ]; then printf '%s\n' "$conv"; return 0; fi
    fi
    printf '%s\n' "$raw"     # 兜底：转不了就原样输出（纯 ASCII 行照样能 grep）
}

engine_log_text() {
    local f; f="$(engine_log_path)"
    [ -n "$f" ] && [ -f "$f" ] || return 0
    decode_engine_log < "$f"
}

# ======================================================================
# 注册表测试值：建 / 查 / 删
# ======================================================================
# ★ 为什么由 runner 建、而不是目标进程建：protect_reg= 命中的路径被算作
#   **高危写**（r3shieldcore_rules.cpp:678）⇒ mode=block 下会被拒
#   ⇒ 目标建不出来。那不是 bug，正是"保护 = 写不进"这条设计。
#   ⇒ 建值必须在**引擎启动之前**、由引擎外的一方做。
#
# ★ 用 reg.exe（系统自带）而不是自己写个小工具：少一个要编的产物，
#   而且 reg.exe 的写法本身就是"标准用户建 HKCU 值"的最短路径。
reg_exe() { MSYS_NO_PATHCONV=1 reg "$@"; }

ensure_reg_value() {
    reg_exe add "HKCU\\$REG_SUBKEY" /v "$REG_VALUE" /t REG_SZ /d "$REG_SECRET" /f \
        >/dev/null 2>&1 || return 1
    return 0
}

reg_value_ok() {
    local out
    out="$(reg_exe query "HKCU\\$REG_SUBKEY" /v "$REG_VALUE" 2>/dev/null)"
    printf '%s' "$out" | grep -qF "$REG_SECRET"
}

delete_reg_value() {
    reg_exe delete "HKCU\\$REG_SUBKEY" /f >/dev/null 2>&1 || true
}

# ======================================================================
# 闸门：没显式给动作就到此为止（--prepare / --collect / --clean 不启动引擎）
# ======================================================================
if [ -z "$ACTION" ]; then
    cat <<EOF
=== 回传数据「替换」端到端验证（三面：屏幕 / 剪贴板 / 注册表）===

本步骤会**真启动引擎**（$ENGINE_BASE），并用 v69 的配置项
（test_inject_only=$TARGET_BASE）把注入范围缩到一个进程。

  · 引擎的常规行为是全局注入所有非系统进程 —— 包括你正在用的编辑器。
    本机跑它会把编辑器 hook 崩（铁律 175，用户明令）。
  · 限定注入范围就是为了让这件事变安全而加的，但「白名单真的生效」只能
    跑起来才知道 ⇒ **必须显式**加 --run-engine。
  · --run-engine 会**分两级**跑，第二级要过第一级才启动：
      级 1 冒烟闸门（约 9s）：只证「白名单真的限住了注入范围」。
            判据 = 引擎自报的「注入新进程: N 个」合计 1 ≤ N ≤ 5。
            N=0 ⇒ 目标注不进去；N≥100 ⇒ 没限住、在全局注入（本项目实测
            全局时 N 是 100~200）。**这一级不过就不跑级 2。**
      级 2 三格矩阵（约 60s）：A/B/C 三格，同时验三面的替换成没成。
  · 引擎清单是 requireAdministrator ⇒ 启动它的 shell 必须已提权；本脚本
    **不替你提权**，所以拆成两步：

第 1 步（不需要管理员）—— 查产物、建注册表测试值、验基线、把三格配置搭好：
EOF
    bash_line --prepare
    echo ""
    echo "第 2 步（**管理员终端**）—— 真跑三格并出结论："
    admin_hint
    echo ""
    echo "（跑完想只看结论 / 复查："
    bash_line --collect
    echo "  想清掉工作区与注册表测试值："
    bash_line --clean
    echo "）"
    echo ""
    note "端到端（真引擎）未运行：缺 --run-engine"
    echo ""
    echo "结果: SKIP —— 通过 $pass / 失败 $fail / **跳过 $skip**"
    echo "      （跳过的是会真启动引擎的端到端矩阵，不等于「全绿」）"
    exit 0
fi

if [ "$ACTION" = "clean" ]; then
    rm -rf "$WORK" 2>/dev/null
    delete_reg_value
    echo "已删除工作区: $WORK"
    echo "已删除注册表测试值: HKCU\\$REG_SUBKEY\\$REG_VALUE"
    exit 0
fi

# ======================================================================
# 记录一份 transcript
# ======================================================================
# ★ 为什么需要：--run-engine 要在**管理员终端**里跑，那个窗口的输出未必方便
#   回看/贴 issue。写一份固定名的 transcript，事后就能翻。
# ⚠️ 固定名：同一时刻只应跑一份（脚本自己也会拒绝"已有引擎在跑"）。
TRANSCRIPT="${TMPDIR:-/tmp}/spoof_e2e-last.log"
: > "$TRANSCRIPT" 2>/dev/null || true
exec > >(tee -a "$TRANSCRIPT") 2>&1
echo "transcript  : $TRANSCRIPT"
echo "工作区      : $WORK"

# ======================================================================
# 前置检查（fail-closed：任何一条不满足都**不启动引擎**）
# ======================================================================
echo ""
echo "=== 前置检查 ==="

# ★ 前提（铁律 117）：cygpath 必须存在。
#   它不只是"为了打印好看的提示"—— --run-engine 要靠它把工作区的
#   ProgramData 转成 **Windows** 形式（见下面 pd_win）。缺了它，ProgramData
#   会退化成 MSYS 路径（/tmp/...），**原生引擎根本不认**，于是回退去读你
#   **真实的** %ProgramData%\R3 Shield Core\ —— 也就是拿你的真配置去全局注入。
#   ⇒ 缺 cygpath 不是"提示难看"，是**安全前提**不成立，必须硬 FAIL。
if ! command -v cygpath >/dev/null 2>&1; then
    bad "找不到 cygpath —— 本脚本必须在 MSYS2 / Git Bash / PortableGit 的 bash 里跑"
    echo "       （cmd 里没有 bash，也就没有 cygpath；见脚本头部「用法」说明）"
    echo "结果: FAIL"; exit 1
fi
ok "cygpath 可用（ProgramData 重定向 / 路径转换的前提）"

# ★ 前提（铁律 117）：iconv 必须存在 —— 引擎日志是 **GBK**，本脚本是 UTF-8，
#   所有中文判据都要靠它转码；缺了它，每个中文 grep 都会 0 命中（恒红）。
if ! command -v iconv >/dev/null 2>&1; then
    bad "找不到 iconv —— 引擎日志是 GBK，没有它所有中文判据都会 0 命中"
    echo "       ★ 实测：**MSYS2 的 bash 没有 iconv**，PortableGit / Git Bash 的**有**。"
    echo "         （本仓库的构建链用 MSYS2，但本夹具必须跑在有 iconv 的那个 bash 里）"
    echo "结果: FAIL"; exit 1
fi
ok "iconv 可用（引擎日志 GBK -> UTF-8 转码的前提）"

# ★ 前提（铁律 117）：reg.exe 必须存在 —— 注册表面要读一个预先建好的值。
if ! command -v reg >/dev/null 2>&1; then
    bad "找不到 reg.exe —— 注册表面要由 runner 预建一个 HKCU 测试值"
    echo "结果: FAIL"; exit 1
fi
ok "reg.exe 可用（注册表测试值的建/查/删前提）"

if [ ! -f "$ENGINE" ]; then
    bad "找不到引擎 $ENGINE（先跑 bash build.sh Release + bash deploy_dist.sh）"
    echo "结果: FAIL"; exit 1
fi
if [ ! -f "$TARGET" ]; then
    bad "找不到目标 $TARGET（先跑 bash build_spoof_e2e.sh）"
    echo "结果: FAIL"; exit 1
fi
ok "引擎与目标产物都在（$ENGINE_BASE / $TARGET_BASE）"

# ★ v69 判据：DLL 里必须有**宽**串 test_inject_only（functions.cpp 的
#   LOG 字面量）—— 证明"注入决策真的按白名单走"这段代码在这个架构里。
#   旧版查的是导出 GlobalHookSessionSetTestInjectOnly；v69 那条导出已删除。
#   ⚠️ 必须 strings -el：中文是宽串，-a 只看 8 位可打印序列（另一个世界）。
#
# ★ v74：再加两条**三面**判据 —— spoof_clipboard / spoof_reg 都是 DLL 里的
#   宽串字面量（clipboard_guard.cpp / registry_guard.cpp 的 LOG）。
#   屏幕面没有这样的宽串标记（spoof_screen 只出现在 EXE 的配置解析里），
#   但屏幕面的功能由 A/B 两格的**行为**直接证（BitBlt 被拒 / 变黑）⇒ 不需要串标记。
#   ⚠️ 用 -el 且 grep -qwF：整词匹配，防 spoof_reg 被 spoof_reg_enum 满足
#      （铁律 142 同族：子串匹配 ⇒ 假绿）。
for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        bad "缺 $dll —— 该架构的进程不会被注入，端到端结果不可信"
        echo "结果: FAIL"; exit 1
    fi
    for marker in test_inject_only spoof_clipboard spoof_reg; do
        if strings -el "$dll" | grep -qwF "$marker"; then
            ok "$arch 位 DLL 带标记 '$marker'（该面逻辑已编入）"
        else
            bad "$arch 位 DLL 没有标记 '$marker'（用 strings -el 查）"
            echo "       ⇒ 该架构的 DLL 没重编；不要继续"
            echo "结果: FAIL"; exit 1
        fi
    done
done

# ======================================================================
# 注册表测试值（基线也要读它 ⇒ 必须在跑基线之前就绪）
# ======================================================================
echo ""
echo "=== 注册表测试值（三面里的注册表面要读它）==="
if ensure_reg_value && reg_value_ok; then
    ok "已就绪 HKCU\\$REG_SUBKEY\\$REG_VALUE = $REG_SECRET"
else
    bad "建注册表测试值失败（HKCU\\$REG_SUBKEY）"
    echo "       reg.exe 可能被策略挡住；注册表面将无法验证。"
    echo "结果: FAIL"; exit 1
fi

# ======================================================================
# 基线：目标单独跑（无引擎）—— 三面都必须拿到**真**数据，否则后面的
# 「变假」无法归因（铁律 110：全零时判据也成立就是空真）。
# ★ 它**不启动引擎**，所以放在管理员检查之前 —— 非提权也能先确认判别力。
# ======================================================================
echo ""
echo "=== 基线：目标单独跑（无引擎，无 hook）—— 三面都要读到**真**数据 ==="
BASE_OUT="$(MSYS_NO_PATHCONV=1 "$TARGET" --wait-ms=0 --tag=baseline 2>&1)"
BASE_RESULT="$(printf '%s\n' "$BASE_OUT" | grep -m1 '^RESULT ')"
echo "  $BASE_RESULT"
if [ -z "$BASE_RESULT" ]; then
    bad "基线没拿到 RESULT 行（目标起不来？）"
    echo "结果: FAIL"; exit 1
fi

# ---- 屏幕：必须非黑 ----
BASE_NONBLACK="$(field "$BASE_RESULT" nonblack)"; BASE_NONBLACK="${BASE_NONBLACK%%/*}"
if [ -z "$BASE_NONBLACK" ] || [ "$BASE_NONBLACK" -le 0 ]; then
    bad "基线屏幕**全黑**（nonblack=${BASE_NONBLACK:-?}）⇒ 无法区分「替换生效」和「屏幕本来就黑」"
    echo "      换一张非黑壁纸，或换台机器再跑。"
    echo "结果: FAIL"; exit 1
fi
ok "基线屏幕非黑（nonblack=$BASE_NONBLACK）⇒ 后续「变黑」可归因"

# ---- 剪贴板：必须读回我们放进去的**已知常量** ----
BASE_CLIP_MATCH="$(field "$BASE_RESULT" clip_match)"
BASE_CLIP_LEN="$(field "$BASE_RESULT" clip_strlen)"
if [ "$BASE_CLIP_MATCH" = "1" ]; then
    ok "基线剪贴板读到真值（clip_match=1，strlen=$BASE_CLIP_LEN）⇒ 后续「变空」可归因"
else
    bad "基线剪贴板**没**读到我们放进去的常量（clip_match=${BASE_CLIP_MATCH:-?} strlen=${BASE_CLIP_LEN:-?}）"
    echo "       ⇒ 判据没有判别力：可能是别的进程占着剪贴板改了内容。"
    echo "结果: FAIL"; exit 1
fi

# ---- 注册表：必须读到预先建好的**已知常量** ----
BASE_REG_MATCH="$(field "$BASE_RESULT" reg_match)"
BASE_REG_ERR="$(field "$BASE_RESULT" reg_err)"
if [ "$BASE_REG_MATCH" = "1" ]; then
    ok "基线注册表读到真值（reg_match=1）⇒ 后续「变空」可归因"
else
    bad "基线注册表**没**读到 $REG_SECRET（reg_match=${BASE_REG_MATCH:-?} reg_err=${BASE_REG_ERR:-?}）"
    echo "       ⇒ 键/值可能没建上，或目标读的键与 runner 建的不是同一个。"
    echo "结果: FAIL"; exit 1
fi

# ======================================================================
# 工作区（--run-engine 需要它；缺了就自己搭一份）
# ======================================================================
build_workspace() {
    rm -rf "$WORK" 2>/dev/null
    mkdir -p "$WORK/app" || { bad "临时目录创建失败: $WORK"; return 1; }
    for c in $CELLS; do
        mkdir -p "$(pd_dir "$c")/R3 Shield Core" || return 1
    done
    cp -r "$DIST_DIR/." "$WORK/app/" || { bad "拷贝 dist 失败"; return 1; }
    purge_stale_engine_logs
    return 0
}

# 清掉发布包**残留**的两个已知运行时日志名（console / events）。
#
# ★ 为什么必要：`read_console` 在"本格还没跑出日志"时会退到读
#   `$WORK/app/r3shieldcore-console.log`（见那里的注释）。若那份是**旧的**
#   （老 dist 里可能留着，见 deploy_dist.sh 的 2b 步），用户就会看到上一次的
#   日志却以为是本格的 —— 正是铁律 97 说的"诊断自己变成假信息"。
#   ⇒ 每次进 `assert_cells` 之前先把这两份清掉，"没有日志"就真的是"没有日志"。
#   ⚠️ **不**碰 `engine-console-*.log`：那是引擎按 PID 自己起的日志，是**本次**
#      运行的真实产物，清掉会丢诊断（只在"全新工作区"那一步才一并清）。
#   ⚠️ 不用宽通配 `*.log`（铁律 117：判据要窄，别顺手扩大）。
purge_dist_residue_logs() {
    rm -f "$WORK/app/r3shieldcore-console.log" \
          "$WORK/app/r3shieldcore-events.log" 2>/dev/null
    return 0
}

# 全新工作区：连引擎按 PID 起的日志也一并清（此刻不可能有"本次运行"的产物）。
purge_stale_engine_logs() {
    purge_dist_residue_logs
    rm -f "$WORK/app/"engine-console-*.log 2>/dev/null
    return 0
}

# 写一格配置（ProgramData 形式：每格一份）。
#
# ⚠️ **不写 log=** —— 那是个文件路径，写 MSYS 形式（/tmp/...）原生引擎不认，
#    会让它"日志文件打开失败"（非致命但脏）。不写就落到默认的 exe 同目录，
#    本来就在工作区里。
#
# ★ heredoc 是**不带引号**的（要展开 $mode / $spoof / $TARGET_BASE 等）
#   ⇒ 正文里**不能出现反引号**（会被当命令替换执行）。注释一律用纯文本。
write_ini() {
    local cell="$1" mode="$2" spoof="$3"
    printf '%s\n' "$(cat <<EOF
# spoof_e2e.sh 自动生成 —— 仅用于端到端验证，跑完即删。
mode=$mode
test_inject_only=$TARGET_BASE

# ---- 三个面：都要挂上（hook），是否替换由格决定 ----
hook_screen=1
spoof_screen=$spoof
hook_clipboard=1
spoof_clipboard=$spoof

# ---- 注册表面 ----
#   hook_reads=0：**故意**保持生产推荐值 —— 这样 spoof 格同时验了
#     "只靠 spoof_reg 就能把 NtQueryValueKey 挂上，且不偷偷打开读记录"
#     （v71 的设计约束，铁律 199）。A 格里 spoof_reg=0 ⇒ 读 hook 不挂
#     ⇒ 读到真值，正是负对照。
#   protect_reg= 是**触发面**：注册表替换只认它，不认内置高危表。
hook_reads=0
protect_reg=$REG_PROTECT_PATH
spoof_reg=$spoof

# ---- 静音化：只留「注入 + 三面判定」，其余主动行为全关 ----
self_protect=0
neutralize_overlay=0
high_risk_process_alert=0
ark_enabled=0
persist_stats=0
replay_history_log=0
inject_shell_thin=0
inject_interval_ms=50
prompt_timeout=5
prompt_default=deny
EOF
)" > "$(ini_path "$cell")"
}

# 写 exe 同目录的**兜底**配置。
#
# ★★★ 它存在的唯一理由：万一 ProgramData 重定向没生效（环境变量没传进子进程、
#   或被引擎的启动路径忽略），引擎会回退读 exe 同目录 —— 而 cp -r dist 已经
#   把**发布包自带的** r3shieldcore.ini（mode=block、**没有白名单**）拷了进来。
#   那份一旦被读到就是**全局注入 block**，正是这个脚本要防的事。
#
# ⇒ 所以兜底内容刻意写**最保守**的组合（log + 白名单）：只记录、只注入目标。
#   而且它**必须与格无关**（固定内容），否则"上一格的兜底"会静默影响下一格。
#
# ⚠️ 兜底被读到**本身就是异常**：assert_cells 会断言引擎自报的配置路径里含
#    pd-<格>（ProgramData 那份），兜底路径不含 ⇒ 该格直接判 FAIL（不是静默通过）。
write_fallback_ini() {
    printf '%s\n' "$(cat <<EOF
# spoof_e2e.sh 自动生成（兜底）—— 内容与格无关，刻意取最保守组合。
# ★ 如果引擎读的是**这一份**，说明 ProgramData 重定向没生效，该格会判 FAIL。
mode=log
test_inject_only=$TARGET_BASE
hook_screen=1
spoof_screen=1
hook_clipboard=1
spoof_clipboard=1
hook_reads=0
protect_reg=$REG_PROTECT_PATH
spoof_reg=1

self_protect=0
neutralize_overlay=0
high_risk_process_alert=0
ark_enabled=0
persist_stats=0
replay_history_log=0
inject_shell_thin=0
inject_interval_ms=50
prompt_timeout=5
prompt_default=deny
EOF
)" > "$(ini_fallback)"
}

write_all_inis() {
    for c in $CELLS; do
        write_ini "$c" "$(cell_mode "$c")" "$(cell_spoof "$c")" || {
            bad "写配置失败: $(ini_path "$c")"; return 1; }
    done
    write_fallback_ini || { bad "写兜底配置失败: $(ini_fallback)"; return 1; }
    return 0
}

# 工作区存在性：--run-engine / --collect 都要求它已经搭好（否则判据失去前提）。
ensure_workspace() {
    if [ ! -d "$WORK/app" ]; then
        echo "  工作区不存在，现场搭一份（等价于 --prepare 的搭台部分）"
        build_workspace || { echo "结果: FAIL"; exit 1; }
    fi
    # ★ 进断言之前先把**发布包残留**的日志清掉 —— 否则 `--collect` 在
    #   "还没跑过任何一格"时会读到那份旧的，把上一次的输出当成本次诊断。
    purge_dist_residue_logs
    write_all_inis || { echo "结果: FAIL"; exit 1; }
}

# ======================================================================
# --prepare：只搭工作区 + 建注册表值 + 写三格配置，**不启动引擎**
# ======================================================================
if [ "$ACTION" = "prepare" ]; then
    echo ""
    echo "=== --prepare：搭工作区 + 写三格配置（不启动引擎）==="
    build_workspace || { echo "结果: FAIL"; exit 1; }
    write_all_inis || { echo "结果: FAIL"; exit 1; }

    for c in $CELLS; do
        echo ""
        echo "--- 格 $c：$(cell_desc "$c") ---"
        sed 's/^/  /' "$(ini_path "$c")"
    done

    echo ""
    echo "工作区: $WORK"
    echo "  引擎会从 ProgramData 形式的那份读（ResolveConfigPath 优先）:"
    echo "    \$ProgramData\\R3 Shield Core\\r3shieldcore.ini"
    echo "  兜底（同目录）: $WORK/app/r3shieldcore.ini"
    echo ""
    echo "注册表测试值: HKCU\\$REG_SUBKEY\\$REG_VALUE （已建；--clean 会删）"
    echo ""
    echo "下一步（**管理员终端**里跑）:"
    admin_hint
    echo ""
    echo "结果: SETUP OK —— 未启动引擎。"
    exit 0
fi

# ======================================================================
# --collect：只解析工作区里已有的落盘结果
# ======================================================================
# ★ 断言集中在这一个函数里，--run-engine 跑完也调它 —— 两条路走**同一份**
#   判据，避免"跑的时候用一套、复查时用另一套"（铁律 127 同族）。
assert_cells() {
    for c in $CELLS; do
        echo ""
        echo "--- 格 $c：$(cell_desc "$c") ---"
        local r; r="$(read_result "$c")"
        echo "  $r"
        if [ -z "$r" ]; then
            bad "$c: 没有 RESULT 行 —— 引擎没起来 / 目标没被注入 / 配置没读到（见 console-$c.log）"
            local ctail; ctail="$(read_console "$c" | tail -12)"
            if [ -n "$ctail" ]; then
                echo "    ---- 引擎控制台日志尾部 ----"
                printf '%s\n' "$ctail" | sed 's/^/    /'
            fi
            continue
        fi

        # ---- 先证「引擎读的是**本格**的配置」：诊断口径必须 ≥ 触发口径（铁律 99）----
        #   否则"期望黑帧却拿到真实画面"会被误判成功能坏了，而其实是
        #   引擎回退去读了你真实的 %ProgramData% 那份、或读了工作区的兜底那份。
        #
        # ★ 判据必须是 pd-<格>（每格一份的那条路径），**不能只查 spoof_e2e_work**
        #   —— 兜底配置（$WORK/app/r3shieldcore.ini）也在工作区里，只查工作区
        #   前缀会把"读了兜底"当成通过（铁律 142：只查存在 ⇒ 假绿）。
        local console cfg_line mode_line wl_line
        console="$(read_console "$c")"
        cfg_line="$(printf '%s\n' "$console" | grep -m1 '配置文件' || true)"
        mode_line="$(printf '%s\n' "$console" | grep -m1 '模式 ' || true)"
        wl_line="$(printf '%s\n' "$console" | grep -m1 '注入范围已被限定' || true)"
        [ -n "$cfg_line" ]  && echo "    引擎自报: $cfg_line"
        [ -n "$mode_line" ] && echo "    引擎自报: $mode_line"
        if printf '%s' "$cfg_line" | grep -qF "pd-$c"; then
            ok "$c: 引擎读的是**本格**的配置（pd-$c；未误读你真实的 ProgramData）"
        else
            bad "$c: 引擎读的**不是**本格配置（没看到 pd-$c）—— 本格结论不可信"
            echo "       （若读到 $WORK/app/... ⇒ ProgramData 重定向没生效）"
            continue
        fi
        if [ -n "$wl_line" ]; then
            ok "$c: 引擎自报「注入范围已被限定」⇒ 白名单真的被读到了"
        else
            bad "$c: 引擎**没有**报「注入范围已被限定」⇒ test_inject_only= 没生效"
            echo "       （那意味着本格是全局注入，必须立刻停掉引擎）"
            continue
        fi

        # ---- 再证 mode 对得上（A/B=block，C=log）----
        local want; want="$(cell_mode "$c")"
        case "$want" in
            block) printf '%s' "$mode_line" | grep -q "BLOCK" \
                       && ok "$c: 引擎自报模式 = BLOCK" \
                       || bad "$c: 引擎自报模式不是 BLOCK（$mode_line）" ;;
            log)   printf '%s' "$mode_line" | grep -q "LOG" \
                       && ok "$c: 引擎自报模式 = LOG" \
                       || bad "$c: 引擎自报模式不是 LOG（$mode_line）" ;;
        esac

        local blt err first nb gpnb gpnbf
        local cput cread cerr clen cmatch
        local rread rerr rlen rmatch
        blt="$(field "$r" bitblt)"
        err="$(field "$r" err)"
        first="$(field "$r" first)"
        nb="$(field "$r" nonblack)"; nb="${nb%%/*}"
        gpnb="$(field "$r" getpixel_nonblack)"
        gpnbf="$(field "$r" getpixel_full_nonblack)"; gpnbf="${gpnbf%%/*}"
        cput="$(field "$r" clip_put)"
        cread="$(field "$r" clip_read)"
        cerr="$(field "$r" clip_err)"
        clen="$(field "$r" clip_strlen)"
        cmatch="$(field "$r" clip_match)"
        rread="$(field "$r" reg_read)"
        rerr="$(field "$r" reg_err)"
        rlen="$(field "$r" reg_strlen)"
        rmatch="$(field "$r" reg_match)"

        # ---- 前提：剪贴板面的**判别力**先证一下 ----
        #   clip_put=0 ⇒ 目标压根没把测试文本放上去 ⇒ 后面"读到空"分不清
        #   是"被替换"还是"本来就没内容"（铁律 110 空真）。
        if [ "$cput" != "1" ]; then
            bad "$c: clip_put=$cput —— 目标没能把测试文本放进剪贴板，剪贴板面无判别力"
            echo "       （多半是别的进程占着剪贴板；重跑一次通常就好）"
        fi

        case "$c" in
            A)
                # ---- 屏幕：本应拒绝 ⇒ 失败 ----
                if [ "$blt" = "0" ] && [ "$err" = "5" ]; then
                    ok "A[屏幕]: BitBlt 被拒（bitblt=0 err=5）—— 同时证明**目标确实被注入了**"
                else
                    bad "A[屏幕]: 期望 bitblt=0 err=5，实得 bitblt=$blt err=$err"
                    echo "       （若 bitblt=1 且像素非黑 ⇒ 目标**根本没被注入**，后面都不算数）"
                fi
                # ---- 剪贴板：本应拒绝 ⇒ 失败 ----
                if [ "$cread" = "0" ] && [ "$cerr" = "5" ]; then
                    ok "A[剪贴板]: GetClipboardData 被拒（clip_read=0 err=5）"
                else
                    bad "A[剪贴板]: 期望 clip_read=0 err=5，实得 clip_read=$cread err=$cerr"
                fi
                # ---- 注册表：spoof 关 ⇒ 读到**真值**（负对照）----
                if [ "$rread" = "1" ] && [ "$rmatch" = "1" ]; then
                    ok "A[注册表]: 读到**真值**（reg_match=1）⇒ spoof_reg=0 时确实不替换"
                else
                    bad "A[注册表]: 期望读到真值，实得 reg_read=$rread reg_match=$rmatch reg_err=$rerr"
                fi
                ;;
            B)
                # ---- 屏幕：成功 + 全黑 ----
                if [ "$blt" = "1" ] && [ "$nb" = "0" ]; then
                    ok "B[屏幕]: BitBlt 成功（bitblt=1）但像素**全黑**（first=$first nonblack=0）⇒ 替换生效"
                else
                    bad "B[屏幕]: 期望 bitblt=1 且 nonblack=0，实得 bitblt=$blt nonblack=$nb first=$first"
                fi
                # 多路径戳穿：GetPixel 没被挂 ⇒ 仍读真实画面。这正是「已知盲区」的实证。
                # ⚠️ 用**两个**采样：左上角那块（可能被引擎自己的 GUI 窗口盖住）和**全屏**粗采样。
                #    任一非空即成立 —— 否则"那块被窗口盖住"会被误读成"GetPixel 也被替换了"。
                if { [ -n "$gpnb" ] && [ "$gpnb" -gt 0 ] 2>/dev/null; } \
                   || { [ -n "$gpnbf" ] && [ "$gpnbf" -gt 0 ] 2>/dev/null; }; then
                    ok "B[屏幕]: 多路径戳穿实证 —— GetPixel 路仍读真实画面（块内=$gpnb，全屏=$gpnbf 个非黑点）"
                else
                    bad "B[屏幕]: GetPixel 路也变黑了（块内=$gpnb，全屏=$gpnbf）—— 与「只挂 4 条路」的预期不符"
                fi
                # ---- 剪贴板：成功 + 空 ----
                if [ "$cread" = "1" ] && [ "$clen" = "0" ] && [ "$cmatch" = "0" ]; then
                    ok "B[剪贴板]: 读**成功**（clip_read=1）但内容**为空**（strlen=0 match=0）⇒ 替换生效"
                else
                    bad "B[剪贴板]: 期望 clip_read=1 且 strlen=0，实得 clip_read=$cread strlen=$clen match=$cmatch"
                fi
                # ---- 注册表：成功 + 空 ----
                if [ "$rread" = "1" ] && [ "$rlen" = "0" ] && [ "$rmatch" = "0" ]; then
                    ok "B[注册表]: 读**成功**（reg_read=1）但数据区**全 0**（strlen=0 match=0）⇒ 替换生效"
                else
                    bad "B[注册表]: 期望 reg_read=1 且 strlen=0，实得 reg_read=$rread strlen=$rlen match=$rmatch"
                fi
                ;;
            C)
                # ---- 屏幕：log 下不拒 ⇒ **不替换** ⇒ 真画面 ----
                if [ "$blt" = "1" ] && [ -n "$nb" ] && [ "$nb" -gt 0 ] 2>/dev/null; then
                    ok "C[屏幕]: mode=log 下 BitBlt 成功且像素**非黑**（nonblack=$nb）⇒ 替换只在「本应拒绝」时生效"
                else
                    bad "C[屏幕]: 期望 bitblt=1 且 nonblack>0，实得 bitblt=$blt nonblack=$nb"
                    echo "       （若 nonblack=0 ⇒ 替换越界到了 log 模式，是个真 bug）"
                fi
                # ---- 剪贴板：log 下不拒 ⇒ 真内容 ----
                if [ "$cread" = "1" ] && [ "$cmatch" = "1" ]; then
                    ok "C[剪贴板]: mode=log 下读到**真值**（clip_match=1）⇒ 替换只在「本应拒绝」时生效"
                else
                    bad "C[剪贴板]: 期望 clip_match=1，实得 clip_read=$cread strlen=$clen match=$cmatch"
                fi
                # ---- 注册表：与 mode **无关** ⇒ log 下**仍**被清零 ----
                #   ★ 这是三面里注册表面**特有的语义**（替换在读路径上，不在拒绝路径上）。
                #     若这里读到真值，说明"注册表替换被 mode 门控了" —— 与设计不符。
                if [ "$rread" = "1" ] && [ "$rlen" = "0" ] && [ "$rmatch" = "0" ]; then
                    ok "C[注册表]: mode=log 下**仍**被清零（strlen=0）⇒ 注册表替换与 mode 无关（符合设计）"
                else
                    bad "C[注册表]: 期望 log 下仍被清零（strlen=0 match=0），实得 reg_read=$rread strlen=$rlen match=$rmatch"
                    echo "       （读到真值 ⇒ 注册表替换被 mode 门控了，与 !blockable 读路径的设计不符）"
                fi
                ;;
        esac
    done
}

if [ "$ACTION" = "collect" ]; then
    echo ""
    echo "=== --collect：解析工作区里已有的落盘结果 ==="
    ensure_workspace
    assert_cells
    echo ""
    echo "=== 结果：通过 $pass / 失败 $fail / 跳过 $skip ==="
    if [ "$fail" -eq 0 ]; then
        echo "结论：回传数据「替换」端到端成立（三面）—— 真引擎注入真进程后，"
        echo "      block+spoof 下屏幕 BitBlt 返回成功但拿到黑帧、剪贴板读回空、注册表读回空；"
        echo "      且 log 模式下屏幕/剪贴板恢复真实、注册表**仍**被清零（模式无关）。"
        exit 0
    fi
    echo "结果: FAIL —— 见上面每格的诊断。"
    exit 1
fi

# ======================================================================
# --run-engine：真跑
# ======================================================================
if [ "$ACTION" != "run" ]; then
    echo "未知动作: $ACTION"; exit 2
fi

echo ""
echo "=== 管理员检查 ==="
if ! net session >/dev/null 2>&1; then
    bad "当前 shell **不是管理员** —— 引擎清单要求提权，请在管理员终端里跑"
    admin_hint
    echo "结果: FAIL"; exit 1
fi
ok "当前是管理员会话"

# 安全闸门：已经有别的引擎在跑就**不启动第二份**（两份引擎 = 两套全局注入）。
if tasklist 2>/dev/null | grep -qiF "$ENGINE_BASE"; then
    bad "已有引擎在运行（$ENGINE_BASE）—— 先退出它（两份引擎会互相打架）"
    echo "结果: FAIL"; exit 1
fi
ok "没有别的引擎实例在跑"

# ★ 注册表值可能在 --prepare 之后被别的进程（或上一步的 --clean）清掉
#   ⇒ --run-engine 自己再确保一次（幂等）。
if ensure_reg_value && reg_value_ok; then
    ok "注册表测试值就绪（HKCU\\$REG_SUBKEY\\$REG_VALUE）"
else
    bad "注册表测试值不在位 —— 注册表面无法验证"
    echo "结果: FAIL"; exit 1
fi

ensure_workspace
ENGINE_W="$WORK/app/$ENGINE_BASE"
[ -f "$ENGINE_W" ] || { bad "工作区里没有引擎: $ENGINE_W"; echo "结果: FAIL"; exit 1; }
ok "工作区就绪（引擎: $ENGINE_W）"

# ======================================================================
# 冒烟闸门：跑矩阵**之前**先证「注入范围真的被限定了」
# ======================================================================
# ★ 为什么非要有这一步：矩阵一跑就是 3 格 × 20s ≈ 60s。如果
#   test_inject_only= 根本没生效，这 60s 里引擎在**全局注入** —— 编辑器、
#   宿主工具自己的 Electron 子进程都可能被 hook 崩（铁律 175）。
#   ⇒ 先用**最短的暴露时间**（默认 9s，够目标被注入一轮）把"白名单真的生效"
#     单独证掉，拿到明确结论再决定要不要跑矩阵。失败就**不跑**矩阵。
#
# ★ 判据必须**正向**且**可量化**，不能只查"没出事"（铁律 110：全零时也成立
#   就是空真）。三条都要有：
#     ① 引擎**自报**「注入范围已被限定」        —— 配置被读到了
#     ② 引擎**自报**的「注入新进程: N 个」合计 ≥1 —— 目标真的被注入了
#     ③ 同一个 N 必须**小**                     —— 范围真的被限住了
#   ②③ 是同一条数字的两面：只查②会被"全局注入"骗过（那时 N 也 ≥1），
#   只查③会被"一个都没注入"骗过（那时 N=0 也"小"）。
#
# ★★ 为什么用「注入新进程: N 个」而不是 grep 跳过非白名单进程：
#   那条是 LOG(...) ⇒ Logger::LogLine ⇒ **只 OutputDebugString**
#   （logger.cpp:52），**不落盘**（铁律 45② / 77 实测）。DLL 与 exe 各用
#   静态 CRT（-MT）⇒ exe 的 freopen(stderr) 改不到 DLL 的 stderr，
#   所以 EnableStderrOutput(true) 也救不了它。grep 它**永远 0 命中**
#   ⇒ 闸门会假 FAIL（铁律 184：假 FAIL 比漏报贵）。
#   而 注入新进程: N 个 是 app.cpp:1001 的 **printf** ⇒ 进 stdout ⇒
#   进控制台日志（且 _IONBF 无缓冲）⇒ 文件里**一定看得到**。
#
# ★ 阈值：白名单生效时只会有**目标自己**被注入（N=1，留点余量到 5）。
#   全局注入时 N 是**全机进程数**量级（本项目实测 100~200，见铁律 39/45）。
#   所以 5 与 100 之间有一道**两个数量级**的空档，判据不会两边都擦边。
SMOKE_MS="${R3SC_SMOKE_MS:-9000}"
SMOKE_MAX_INJECT="${R3SC_SMOKE_MAX_INJECT:-5}"

smoke_gate() {
    echo ""
    echo "=== 冒烟闸门：先证「注入范围真的被限定了」，再跑矩阵 ==="
    echo "    （引擎只跑 ${SMOKE_MS}ms；这一步失败就**不**跑矩阵）"

    write_ini A "$(cell_mode A)" "$(cell_spoof A)" || { bad "冒烟：写配置失败"; return 1; }
    rm -f "$(engine_console)" "$WORK/app/"engine-console-*.log 2>/dev/null

    local pd_win
    pd_win="$(cygpath -w "$(pd_dir A)" 2>/dev/null || printf '%s' "$(pd_dir A)")"

    (
        export ProgramData="$pd_win"
        export R3SHIELDCORE_EXIT_AFTER_MS="$SMOKE_MS"
        MSYS_NO_PATHCONV=1 "$ENGINE_W" >/dev/null 2>&1
    ) &
    local job=$!

    # ---- ① 等引擎起来 ----
    # ★★ 这里**不能**轮询日志（引擎运行期间日志是**独占**的，读不到 ——
    #    见 run_cell 里那段说明）。改成**定时等待**，然后：
    #      先跑目标（②），再等引擎按 EXIT_AFTER_MS 自己退出，**最后才读日志**。
    sleep "${R3SC_CELL_SETTLE_S:-2}"

    # ---- ② 造一个**必现**的被注入样本：白名单里的目标 ----
    #   为什么必须自己造：没有新进程就 N=0，② 就没有前提（铁律 117）。
    MSYS_NO_PATHCONV=1 "$TARGET" --wait-ms=2500 --tag=smoke >/dev/null 2>&1

    wait "$job" 2>/dev/null

    local log; log="$(engine_log_text)"
    if [ -z "$log" ]; then
        bad "冒烟：引擎没有产出任何控制台日志 —— 它可能压根没起来"
        return 1
    fi

    local cfg_line; cfg_line="$(printf '%s\n' "$log" | grep -m1 '配置文件' || true)"
    [ -n "$cfg_line" ] && echo "    引擎自报: $cfg_line"

    # ---- ① 白名单被读到（否则它就是在全局注入）----
    if ! printf '%s\n' "$log" | grep -q "注入范围已被限定"; then
        bad "冒烟①：引擎**没有**报「注入范围已被限定」⇒ test_inject_only= 没生效"
        echo "       ⇒ 它很可能在**全局注入**。**不要**继续跑矩阵。"
        echo "       排查线索（按可能性排序）："
        echo "         · ini 应在: $(ini_path A)"
        echo "         · 引擎自报的「配置文件 :」是不是这一份？"
        echo "         · 日志编码：本脚本已按 **GBK** 解码；若引擎在非中文代码页上"
        echo "           编译，中文字节会不同 ⇒ 这里会认不出（见 decode_engine_log）。"
        printf '%s\n' "$log" | tail -15 | sed 's/^/         /'
        return 1
    fi
    ok "冒烟①：引擎自报「注入范围已被限定」⇒ 白名单被读到了"

    # ---- ①b 配置路径也要对（否则"生效"的是**别人那份**配置）----
    if printf '%s' "$cfg_line" | grep -qF "pd-A"; then
        ok "冒烟①b：引擎读的是本工作区的配置（pd-A）"
    else
        bad "冒烟①b：引擎读的**不是** pd-A 那份 —— 后面结论都不算数"
        echo "       （若读到你真实的 %ProgramData%\\R3 Shield Core\\ ⇒ 重定向没生效）"
        return 1
    fi

    # ---- ②③ 注入计数：合计 N ----
    local total
    total="$(printf '%s\n' "$log" \
        | sed -n 's/^注入新进程: \([0-9][0-9]*\) 个.*/\1/p' \
        | awk '{s+=$1} END {print s+0}')"
    : "${total:=0}"
    echo "    引擎自报注入计数合计: N=$total  （阈值: 1 ≤ N ≤ $SMOKE_MAX_INJECT）"

    if [ "$total" -lt 1 ]; then
        bad "冒烟②：引擎一共只注入了 0 个进程 ⇒ 目标**没被注入**"
        echo "       ⇒ 矩阵会三格全「没被注入」，那是最难诊断的一种失败。"
        echo "         检查 test_inject_only=$TARGET_BASE 与目标镜像基名是否真的相等"
        echo "         （基名匹配，大小写不敏感）。"
        return 1
    fi
    ok "冒烟②：引擎注入了 $total 个进程 ⇒ 目标确实被注入了（注入路径通了）"

    if [ "$total" -le "$SMOKE_MAX_INJECT" ]; then
        ok "冒烟③：N=$total ≤ $SMOKE_MAX_INJECT ⇒ 注入范围**真的被限住**了"
    else
        bad "冒烟③：N=$total > $SMOKE_MAX_INJECT ⇒ 范围**没限住**，疑似全局注入！"
        echo "       （全局注入时 N 是全机进程数量级：本项目实测 100~200）"
        echo "       ⇒ **立刻**结束引擎，不要跑矩阵。"
        return 1
    fi

    ok "冒烟闸门通过 —— 白名单**行为上**生效了，可以安全跑矩阵"
    return 0
}

# ======================================================================
# 跑一格：启动引擎 -> 等白名单生效 -> 跑目标 -> 收结果 -> 落盘
# ======================================================================
run_cell() {
    local cell="$1"
    local mode spoof pd_win console
    mode="$(cell_mode "$cell")"
    spoof="$(cell_spoof "$cell")"
    console="$(console_file "$cell")"
    write_ini "$cell" "$mode" "$spoof" || { echo "写配置失败" >&2; return 1; }

    rm -f "$console" "$console.raw" "$(result_file "$cell")" 2>/dev/null
    rm -f "$(engine_console)" 2>/dev/null
    rm -f "$WORK/app/"engine-console-*.log 2>/dev/null

    # ★★★ 关键：引擎是**原生 Windows 进程**，它读的是
    #   GetEnvironmentVariableW("ProgramData")。如果把 MSYS 形式（/tmp/...）
    #   塞进去，它拼出来的路径在 Windows 上**不存在** ⇒ 静默回退去读 exe 同目录
    #   或**真实的** %ProgramData%\R3 Shield Core\（你机器上的那份配置！）。
    #   所以必须转成 Windows 形式（C:\Users\...\Temp\...）。
    pd_win="$(cygpath -w "$(pd_dir "$cell")" 2>/dev/null || printf '%s' "$(pd_dir "$cell")")"

    # 子进程继承这两个环境变量：
    #   ProgramData                -> 配置解析重定向到工作区（ResolveConfigPath）
    #                                 ★ 必须是 **Windows** 形式（见上面）
    #   R3SHIELDCORE_EXIT_AFTER_MS -> 引擎自己按点优雅退出，不用 taskkill
    (
        export ProgramData="$pd_win"
        export R3SHIELDCORE_EXIT_AFTER_MS=20000
        MSYS_NO_PATHCONV=1 "$ENGINE_W" >"$console.raw" 2>&1
    ) &
    local engine_job=$!

    # ---- 等引擎起来并把横幅打出去 ----
    # ★★ 为什么**不能**边跑边轮询日志：引擎把 r3shieldcore-console.log 以
    #    **独占**方式持有 —— 实测（2026-10-10，第一次真跑引擎）：运行期间
    #    cat 报 Device or resource busy、PowerShell 的 FileShare.Read
    #    和 FileShare.ReadWrite **都**报 SharingViolation；只有引擎**退出后**
    #    才读得到。所以"轮询日志等横幅"这条路根本不存在。
    #    ⇒ 这里改成**定时等待**，日志一律等引擎退出后再读（见下面拷贝那一步）。
    #      "白名单是否真的生效"由**冒烟闸门**在矩阵之前用
    #      "短跑 + **退出后**读日志"单独证掉。
    sleep "${R3SC_CELL_SETTLE_S:-2}"

    # ---- 跑目标（等 2.5s 让轮询注入落进来）----
    MSYS_NO_PATHCONV=1 "$TARGET" --wait-ms=2500 --tag="$cell" \
        >"$(result_file "$cell")" 2>&1

    # ---- 等引擎自己退出（EXIT_AFTER_MS=20000）----
    wait "$engine_job" 2>/dev/null

    # ---- ★ 把这一格的引擎控制台日志**拷走**（下一格会覆盖 $WORK/app 里那份）----
    #   ★ 这里**顺便转码**：拷出来的是 UTF-8 ⇒ 后面 assert_cells 直接 grep 即可，
    #     不会再有"GBK 文件 vs UTF-8 模式"的恒红（铁律 185 同族）。
    engine_log_text > "$console" 2>/dev/null
    [ -f "$console.raw" ] && cp "$console.raw" "$console.stdout" 2>/dev/null
    return 0
}

echo ""
echo "=== 三格矩阵（同一份引擎、同一个目标，只改 mode / spoof_*）==="
echo "    每格都会重启一次引擎 —— 只有它退出后才跑下一格（避免两份引擎互相打架）。"

# ★ 先过冒烟闸门。不过就**不跑矩阵** —— 理由见 smoke_gate 上面的注释：
#   白名单没生效时，矩阵每跑一格都是一次全局注入（铁律 175）。
if ! smoke_gate; then
    echo ""
    bad "冒烟闸门未通过 —— **已跳过三格矩阵**（避免全局注入）"
    echo "结果: FAIL —— 通过 $pass / 失败 $fail / **跳过 1**（三格矩阵）"
    exit 1
fi

for c in $CELLS; do
    echo ""
    echo "--- 跑格 $c：$(cell_desc "$c") ---"
    if run_cell "$c"; then
        echo "    完成（结果已落盘: $(result_file "$c")）"
    else
        bad "$c: 这一格没跑成（见上面的 !! 诊断）"
    fi
done

assert_cells

# ======================================================================
# 汇总
# ======================================================================
echo ""
echo "=== 结果：通过 $pass / 失败 $fail / 跳过 $skip ==="
if [ "$fail" -eq 0 ]; then
    echo "结论：回传数据「替换」端到端成立（三面）—— 真引擎注入真进程后，"
    echo "      block+spoof 下屏幕 BitBlt 返回成功但拿到黑帧、剪贴板读回空、注册表读回空；"
    echo "      且 log 模式下屏幕/剪贴板恢复真实、注册表**仍**被清零（模式无关）。"
    echo ""
    echo "工作区保留在 $WORK（复查：bash tools/spoof_e2e.sh --collect；"
    echo "清掉工作区与注册表测试值：bash tools/spoof_e2e.sh --clean）"
    exit 0
fi
echo "结果: FAIL —— 见上面每格的诊断。"
echo "工作区保留在 $WORK（排查用；清掉：bash tools/spoof_e2e.sh --clean）"
exit 1
