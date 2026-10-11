#!/usr/bin/env bash
#
# spoof_e2e_selftest.sh —— 端到端夹具**判据逻辑**的自测（合成数据，**不启动引擎**）。
#
# ======================================================================
# 为什么需要它（铁律 137 / 110 / 148）
# ======================================================================
# `tools/spoof_e2e.sh --run-engine` 会**真启动引擎**（全局注入）⇒ 本机禁止
#   （铁律 175）。于是"三格矩阵的判据到底会不会红"这件事，在能跑引擎的机器
#   之外**无法验证** —— 而"判据恒绿"和"功能正确"在输出上一模一样。
#
# 本脚本把 `spoof_e2e.sh --collect` 的**输入**（result-*.txt / console-*.log）
#   用**合成的**数据写出来，然后跑 `--collect` 看它怎么判：
#     · 先写一份"**符合预期**"的合成结果 ⇒ 必须 **0 个 [FAIL]**（否则判据恒红）；
#     · 再对每个面各做若干**定向篡改**（把某个字段改成一个"错的"值）
#       ⇒ 必须**恰好**在对应的那条断言上报 [FAIL]（否则判据恒绿 / 判错地方）。
#
# ⇒ 它证明的是**判据有判别力**，**不**证明"引擎真的会替换"。
#    后者只能在允许跑引擎的机器上用 `--run-engine` 验（见脚本头部）。
#
# 用法: bash tools/spoof_e2e_selftest.sh
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

RUNNER="tools/spoof_e2e.sh"
# ★ 工作区**独立于**真夹具的默认工作区（`/tmp/spoof_e2e_work`）—— 免得自测把
#   用户手上那份真夹具的落盘结果覆盖掉（铁律 177 同族：别踩别人的现场）。
WORK="${TMPDIR:-/tmp}/spoof_e2e_selftest_work"

pass=0
fail=0

ok()  { echo "  [ OK ] $1"; pass=$((pass+1)); }
bad() { echo "  [FAIL] $1"; fail=$((fail+1)); }

# ======================================================================
# 合成数据：三格"符合预期"的 RESULT 行
# ======================================================================
# ⚠️ 这些字段的含义与取值必须与 `tools/spoof_e2e_target.cpp` 的输出**同构**
#    （同样的 key、同样的量纲）—— 否则自测验的是"另一个程序"。
#
#   A（block, spoof=0）：屏幕被拒 / 剪贴板被拒 / 注册表**真值**
#   B（block, spoof=1）：屏幕成功+全黑 / 剪贴板成功+空 / 注册表成功+空
#   C（log,   spoof=1）：屏幕真 / 剪贴板真 / 注册表**仍空**（模式无关）
BASE_A='RESULT bitblt=0 err=5 lines=0 first=0x123456 nonblack=0/12288 getpixel0=0x00F2F2F2 getpixelmid=0x00F2F2F2 getpixel_nonblack=192 getpixel_full_nonblack=508/510 clip_put=1 clip_read=0 clip_err=5 clip_strlen=0 clip_match=0 reg_read=1 reg_err=0 reg_strlen=19 reg_match=1'
BASE_B='RESULT bitblt=1 err=0 lines=96 first=0x00000000 nonblack=0/12288 getpixel0=0x00F2F2F2 getpixelmid=0x00F2F2F2 getpixel_nonblack=192 getpixel_full_nonblack=508/510 clip_put=1 clip_read=1 clip_err=0 clip_strlen=0 clip_match=0 reg_read=1 reg_err=0 reg_strlen=0 reg_match=0'
BASE_C='RESULT bitblt=1 err=0 lines=96 first=0xFFF2F2F2 nonblack=12288/12288 getpixel0=0x00F2F2F2 getpixelmid=0x00F2F2F2 getpixel_nonblack=192 getpixel_full_nonblack=508/510 clip_put=1 clip_read=1 clip_err=0 clip_strlen=31 clip_match=1 reg_read=1 reg_err=0 reg_strlen=0 reg_match=0'

base_result() { case "$1" in A) printf '%s' "$BASE_A" ;; B) printf '%s' "$BASE_B" ;; C) printf '%s' "$BASE_C" ;; esac; }
base_mode()   { case "$1" in A|B) printf 'BLOCK' ;; C) printf 'LOG' ;; esac; }

# 写一格的落盘文件。$3 = result 行（缺省用 base_result），$4 = console 的
# 「配置文件」行是否带上 pd-<格>（缺省带；用于测"读错配置"那条判据）。
write_cell() {
    local cell="$1" result="$2" cfg_pd="${3:-yes}"
    local cfg
    if [ "$cfg_pd" = "yes" ]; then
        cfg="$WORK/pd-$cell/R3 Shield Core/r3shieldcore.ini"
    else
        cfg="$WORK/app/r3shieldcore.ini"      # 兜底那份（不含 pd-<格>）
    fi
    # ★★★ 必须先建 `$WORK/app` —— 否则 runner 的 `ensure_workspace` 看到
    #   "工作区不存在" 会调 `build_workspace`，而那一步会 **`rm -rf $WORK`**，
    #   把我们刚写进去的合成 result-*.txt 全删掉 ⇒ 三格全报"没有 RESULT 行"。
    #   （自测第一次跑就踩了这个：场景 1 三格全红，场景 2 却基本正常 ——
    #    因为场景 1 跑完 app/ 已经存在了。这正是"自测自己也要有前提"的例子。）
    mkdir -p "$WORK/app"
    mkdir -p "$WORK/pd-$cell/R3 Shield Core"
    printf '%s\n' "$result" > "$WORK/result-$cell.txt"
    cat > "$WORK/console-$cell.log" <<EOF
配置文件   : $cfg
模式       : $(base_mode "$cell")
注入范围已被限定: spoof_e2e_target.exe
EOF
}

# 写三格：把 $1 指定的那一格（A/B/C，或 ALL）的 result 行换成 $2，其余用基线。
write_all_cells() {
    local target="$1" result="$2" cfg_pd="${3:-yes}"
    local c
    for c in A B C; do
        if [ "$target" = "ALL" ] || [ "$target" = "$c" ]; then
            write_cell "$c" "$result" "$cfg_pd"
        else
            write_cell "$c" "$(base_result "$c")" yes
        fi
    done
}

# 跑一次 --collect，只回**断言段**（`=== --collect` 之后）的文本。
# ★ 为什么要切：`--collect` 也会跑前置检查 + 基线，那两段的 [FAIL] 与
#   "三格判据"无关；不切的话基线一红（比如换了台黑屏的机器）会把自测带红，
#   让"判据本身对不对"这件事被无关因素掩盖。
collect_cells_output() {
    bash "$RUNNER" --collect --work-dir="$WORK" 2>&1 \
        | sed -n '/=== --collect/,$p'
}

# 数"断言段里有多少个 [FAIL]"。
count_fails() { printf '%s\n' "$1" | grep -c '^  \[FAIL\]' || true; }

# ======================================================================
# 场景 1：**符合预期**的合成数据 ⇒ 断言段必须 0 个 [FAIL]
# ======================================================================
echo "=== 场景 1：符合预期的合成数据（三格全对）==="
write_all_cells ALL ""
for c in A B C; do write_cell "$c" "$(base_result "$c")" yes; done
OUT="$(collect_cells_output)"
NF="$(count_fails "$OUT")"
if [ "$NF" -eq 0 ]; then
    ok "三格全对 ⇒ 断言段 0 个 [FAIL]（判据不是恒红）"
else
    bad "三格全对却报了 $NF 个 [FAIL] ⇒ 判据恒红（自测里就能看出来）"
    printf '%s\n' "$OUT" | grep '^  \[FAIL\]' | sed 's/^/       /'
fi

# ======================================================================
# 场景 2：**定向篡改** ⇒ 必须恰好在那条断言上红
# ======================================================================
# 每一条 = (格, 篡改后的 result 行, 期望在输出里出现的关键字)
#   关键字取自各条 ok()/bad() 消息里的**面标签**（如 `A[注册表]`），
#   这样"红在别的面"也能被抓出来（只数 [FAIL] 个数会把"红错地方"放过）。
echo ""
echo "=== 场景 2：定向篡改 ⇒ 必须恰好红在对应的那条断言上 ==="

# 把 base 行里的某个 `key=旧` 换成 `key=新`（整词替换，防 `err=` 撞 `clip_err=`）。
# ★ 分隔符用 `@` 而**不是** `/`：新值里有 `0/12288` 这种带 `/` 的（nonblack
#   的 `分子/分母` 写法）⇒ 用 `/` 当分隔符会让 sed 报 "unknown option to `s'"。
#   自测第一次跑就踩了这个（B/C 两格各一条），而且症状是"红错地方" —— 值得记一笔。
mutate() {
    local line="$1" key="$2" val="$3"
    printf '%s' "$line" | sed -E "s@(^| )$key=[^ ]*@\1$key=$val@"
}

check_case() {
    local desc="$1" cell="$2" mutated="$3" expect_tag="$4"
    write_all_cells "$cell" "$mutated" yes
    local out nf
    out="$(collect_cells_output)"
    nf="$(count_fails "$out")"
    if [ "$nf" -eq 0 ]; then
        bad "$desc ⇒ 篡改后**一个都没红**（判据恒绿 / 空真）"
        return
    fi
    if printf '%s\n' "$out" | grep '^  \[FAIL\]' | grep -qF "$expect_tag"; then
        ok "$desc ⇒ 红在「$expect_tag」（$nf 个 FAIL）"
    else
        bad "$desc ⇒ 红了，但**不是**在「$expect_tag」上（红错地方）"
        printf '%s\n' "$out" | grep '^  \[FAIL\]' | sed 's/^/       /'
    fi
}

# ---- A 格：本应拒绝却没拒 / 注册表被误替换 ----
check_case "A: 屏幕没被拒（bitblt 0->1）"          A "$(mutate "$BASE_A" bitblt 1)"              "A[屏幕]"
check_case "A: 剪贴板没被拒（clip_read 0->1）"     A "$(mutate "$BASE_A" clip_read 1)"           "A[剪贴板]"
check_case "A: 注册表被误替换（reg_match 1->0）"   A "$(mutate "$BASE_A" reg_match 0)"           "A[注册表]"

# ---- B 格：替换没生效 / 判别力前提不成立 ----
check_case "B: 屏幕没变黑（nonblack 0->100）"      B "$(mutate "$BASE_B" nonblack '100/12288')"  "B[屏幕]"
check_case "B: 剪贴板没变空（clip_strlen 0->5）"   B "$(mutate "$BASE_B" clip_strlen 5)"         "B[剪贴板]"
check_case "B: 注册表没变空（reg_strlen 0->19）"   B "$(mutate "$BASE_B" reg_strlen 19)"         "B[注册表]"
check_case "B: 剪贴板判别力前提不成立（clip_put 1->0）" B "$(mutate "$BASE_B" clip_put 0)"       "clip_put=0"

# ---- C 格：替换越界到 log / 注册表被 mode 门控 ----
check_case "C: 屏幕被越界替换（nonblack 12288->0）" C "$(mutate "$BASE_C" nonblack '0/12288')"   "C[屏幕]"
check_case "C: 剪贴板被越界替换（clip_match 1->0）" C "$(mutate "$BASE_C" clip_match 0)"         "C[剪贴板]"
check_case "C: 注册表替换被 mode 门控（reg_strlen 0->19）" C "$(mutate "$BASE_C" reg_strlen 19)"  "C[注册表]"

# ---- 配置口径：引擎读了**别人那份**配置 ⇒ 该格结论不可信 ----
echo ""
echo "--- 配置口径（引擎读了兜底那份，而非本格那份）---"
for c in A B C; do
    write_all_cells ALL ""
    for x in A B C; do
        if [ "$x" = "$c" ]; then write_cell "$x" "$(base_result "$x")" no
        else write_cell "$x" "$(base_result "$x")" yes; fi
    done
    out="$(collect_cells_output)"
    if printf '%s\n' "$out" | grep '^  \[FAIL\]' | grep -qF "$c: 引擎读的**不是**本格配置"; then
        ok "$c: 读了兜底配置 ⇒ 该格判 FAIL（不是静默通过）"
    else
        bad "$c: 读了兜底配置却**没**判 FAIL（铁律 142：只查存在 ⇒ 假绿）"
    fi
done

# ======================================================================
# 清理
# ======================================================================
# ★ 自测**不**该留下注册表测试值：`--collect` 的前置段会建它（为了让基线能跑）。
#   用 runner 自己的 `--clean` 收尾（它会删工作区 + 删注册表值）—— 复用同一份
#   清理逻辑，别在自测里另写一份（铁律 127）。
bash "$RUNNER" --clean --work-dir="$WORK" >/dev/null 2>&1
rm -rf "$WORK" 2>/dev/null

echo ""
echo "=== 结果：通过 $pass / 失败 $fail ==="
if [ "$fail" -eq 0 ]; then
    echo "结论：端到端夹具的**判据逻辑**有判别力 —— 符合预期时 0 红，"
    echo "      每个面的定向篡改都能恰好红在对应断言上。"
    echo "      ⚠️ 这**不**证明「引擎真的会替换」；那一步要 --run-engine（铁律 175）。"
    exit 0
fi
echo "结果: FAIL —— 见上面每条。"
exit 1
