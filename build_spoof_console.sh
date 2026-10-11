#!/usr/bin/env bash
#
# build_spoof_console.sh —— 编译「替换 API 结果」交互式控制台。
#
# 它是什么：
#   一个**自包含**的交互式控制台，把项目里的「回传数据替换（Spoof）」能力
#   装进自己进程，让你逐条命令地试、看每个 API 的真实返回值被换成了什么。
#   进「高级模式」要先过**三道 Win32 编程题**（全对才开门）。
#
# ★ 不注入、不跑引擎（铁律 175 不适用）；只在 HKCU 下建临时键，退出时删掉。
# ★ 判据与替换逻辑**与生产同源**：直接 #include 三个 codec 头（铁律 195）。
#
# 用法:
#   bash build_spoof_console.sh              # 只编译
#   bash build_spoof_console.sh --run        # 编译后**交互**运行
#   bash build_spoof_console.sh --selftest   # 编译后喂一段脚本（自测闸门+命令通路）
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"

# ★ 多架构脚本必须两架构都真编（写死 ${ARCH:-x64} 会让 x86 链 x64 库）。
ARCH="${ARCH:-x64}"
if [ "$ARCH" = "x64" ]; then
    HOST="Hostx64/x64"
    MH_LIB="libMinHook.x64.lib"
else
    HOST="Hostx64/x86"
    MH_LIB="libMinHook.x86.lib"
fi

r3sc_export_msvc_env "$ARCH"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

MH_LIB_REL="R3ShieldCore/R3ShieldCoreLib/libraries/MinHook/$MH_LIB"
MH_INC_REL="R3ShieldCore/R3ShieldCoreLib/libraries/MinHook"
CODEC_INC_REL="R3ShieldCore/R3ShieldCoreLib"
# ★ 共享头（`<r3shieldcore/rules_codec.h>` 等）在 R3ShieldCore/shared 下 ——
#   和主程序/引擎用的是**同一份**（铁律 195），不是复制过来的第二份。
SHARED_INC_REL="R3ShieldCore/shared"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★★ GBK 前置闸门（铁律 46/133 + 226）：
#    ① 窄字面量：CP936 放不下的字符会被 C4566 **静默丢掉**（编译期）。
#    ② 宽字面量：本控制台**所有用户可见文本都在 L"..." 里**，而输出走
#       WideCharToMultiByte(CP_ACP) ⇒ CP936 编不出的字符会被**静默换成 `?`**
#       （运行时）。★ 这个坑 v75 真踩过：一句提示里的 `⇒` 变成了 `?`。
#    两个方向都查 —— 检测器同一个，只是选中的字面量类别相反。
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门①：窄字面量（C4566 编译期丢字）==="
    if ! python tools/check_source_gbk.py tools/spoof_console.cpp; then
        echo "GBK 闸门①未过，停止编译"; exit 1
    fi
    echo "=== GBK 闸门②：宽字面量（CP_ACP 运行期变 '?'）==="
    if ! python tools/check_source_gbk.py --wide tools/spoof_console.cpp; then
        echo "GBK 闸门②未过，停止编译"; exit 1
    fi
fi

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，不指定的话 UTF-8 字节
#   会被按 CP936 解码，**吞掉后面的行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 spoof_console.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -I"$CODEC_INC_REL" -I"$SHARED_INC_REL" \
    -Fo"obj/probe/spoof_console.obj" \
    "tools/spoof_console.cpp" || exit 1

echo "=== 链接 ==="
# ktmw32.lib   = CreateTransaction / CommitTransaction / RollbackTransaction
# advapi32.lib = RegCreateKeyExW / RegSetValueExW / RegEnumKeyExW / RegDeleteTreeW
# user32.lib   = GetClipboardData / CloseClipboard / OpenClipboard / EmptyClipboard
# gdi32.lib    = 剪贴板 codec 里的位图分支（CreateBitmap / DeleteObject / GetObjectW）
#                —— 即使本程序不跑那条路，inline 函数编进 TU 就会产生引用。
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_console.exe" \
    "obj/probe/spoof_console.obj" \
    "$MH_LIB_REL" \
    kernel32.lib advapi32.lib user32.lib gdi32.lib ktmw32.lib || exit 1

echo "BUILD OK -> tools/spoof_console.exe"

case "${1:-}" in
--run)
    echo ""
    echo "=== 交互运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_console.exe
    ;;
--selftest)
    echo ""
    echo "=== 自测 1/3：正路 —— 三道题全对 -> 进高级模式 -> 跑命令 + 规则引擎 ==="
    # 前三行 = 闸门答案（C / B / A，全对）；其余 = 控制台命令。
    # ★ 中文规则必须按 **CP936** 喂进去（程序用 CP_ACP 读 stdin）⇒ 单独 iconv 一段。
    {
        cat <<'R3SC_SCRIPT'
C
B
A
status
list
rule list
attack all
on clip
off clip
attack clip
mode log
attack clip
mode block
fill 65
attack reg
fakeclip HELLO-FAKE
attack clip
demo
R3SC_SCRIPT
        iconv -f UTF-8 -t CP936 <<'R3SC_RULES'
当 注册表值 的 值名 匹配 /Pass.*/ 时 替换为 "RULE-FAKE"
当 剪贴板 的 格式 等于 文本 时 替换为 "CLIP-FAKE"
当 注册表枚举 的 子键名 含 "Secret" 时 隐藏
rule list
attack all
rule test 注册表值 Password
rule test 注册表值 Public1
rule del 0
rule clear
rule list
attack reg
R3SC_RULES
        printf 'quit\n'
    } | MSYS_NO_PATHCONV=1 ./tools/spoof_console.exe > /tmp/sc_pos.txt 2>&1
    rc_pos=$?
    echo ""
    echo "  [判据] 正路退出码 = $rc_pos （期望 0）"

    echo ""
    echo "=== 自测 2/3：负对照 —— 故意答错一题，闸门**必须不开门** ==="
    # A 是错的（正确是 C）⇒ 应当判"错 1 题 -> 重做"；再答 q 退出。
    # ★ 判据是**退出码非 0** + 输出里没有"已进入**高级模式**"。
    MSYS_NO_PATHCONV=1 ./tools/spoof_console.exe <<'R3SC_NEG' > /tmp/spoof_console_neg.txt 2>&1
A
B
A
q
R3SC_NEG
    rc_neg=$?

    neg_entered=0
    if iconv -f CP936 -t UTF-8 /tmp/spoof_console_neg.txt 2>/dev/null | grep -q "已进入\*\*高级模式\*\*"; then
        neg_entered=1
    fi

    pass=0; fail=0
    if [ "$rc_pos" -eq 0 ]; then echo "  [ OK ] 正路退出码 = 0"; pass=$((pass+1));
    else echo "  [FAIL] 正路退出码 = $rc_pos（期望 0）"; fail=$((fail+1)); fi

    if [ "$rc_neg" -ne 0 ]; then echo "  [ OK ] 负对照退出码 = $rc_neg（非 0 = 闸门拒绝了）"; pass=$((pass+1));
    else echo "  [FAIL] 负对照退出码 = 0 —— 答错也放行了，闸门是坏的"; fail=$((fail+1)); fi

    if [ "$neg_entered" -eq 0 ]; then echo "  [ OK ] 负对照输出里**没有**「已进入高级模式」"; pass=$((pass+1));
    else echo "  [FAIL] 负对照居然进了高级模式"; fail=$((fail+1)); fi

    # ---- 正路的**内容**判据：规则真生效了、且数据真被换成了指定的串 ----
    iconv -f CP936 -t UTF-8 /tmp/sc_pos.txt > /tmp/sc_pos_u.txt 2>/dev/null || cp /tmp/sc_pos.txt /tmp/sc_pos_u.txt
    if grep -q '\[规则\] 命中 #0' /tmp/sc_pos_u.txt; then
        echo "  [ OK ] 规则生效：attack 输出里报了「[规则] 命中 #0」"; pass=$((pass+1))
    else echo "  [FAIL] 规则没生效（attack 输出里没有「[规则] 命中」）"; fail=$((fail+1)); fi

    if grep -q '52 00 55 00 4C 00 45 00' /tmp/sc_pos_u.txt; then
        echo "  [ OK ] 值替换：数据区被写成 \"RULE-FAKE\" 的 UTF-16（52 00 55 00 4C 00 45 00）"; pass=$((pass+1))
    else echo "  [FAIL] 值替换没落到数据区"; fail=$((fail+1)); fi

    if grep -q '内容 = "CLIP-FAKE"' /tmp/sc_pos_u.txt; then
        echo "  [ OK ] 剪贴板替换：拿到的是规则指定的 \"CLIP-FAKE\""; pass=$((pass+1))
    else echo "  [FAIL] 剪贴板规则没生效"; fail=$((fail+1)); fi

    if grep -q '命中 #2' /tmp/sc_pos_u.txt; then
        echo "  [ OK ] 枚举规则生效（命中 #2 = 隐藏 Secret 那条）"; pass=$((pass+1))
    else echo "  [FAIL] 枚举隐藏规则没生效"; fail=$((fail+1)); fi

    # ---- 自测 3/3：规则语法错误**必须被挡住**，不能静默收下 ----
    echo ""
    echo "=== 自测 3/3：规则语法错误必须被挡住（4 条错的都不能静默收下）==="
    {
        printf 'C\nB\nA\n'
        iconv -f UTF-8 -t CP936 <<'R3SC_BAD'
当 注册表值 的 值名 匹配 Pass.* 时 替换为 "X"
当 注册表值 的 值名 含 "P" 时 隐藏
当 剪贴板 的 格式 等于 文本 时 替换为 全FF
当 注册表值 的 值名 含 "P" 时 替换为
rule list
quit
R3SC_BAD
    } | MSYS_NO_PATHCONV=1 ./tools/spoof_console.exe > /tmp/sc_bad.txt 2>&1
    rc_bad=$?
    iconv -f CP936 -t UTF-8 /tmp/sc_bad.txt > /tmp/sc_bad_u.txt 2>/dev/null || cp /tmp/sc_bad.txt /tmp/sc_bad_u.txt
    bad_errs=$(grep -c '\[规则错\]' /tmp/sc_bad_u.txt || true)

    if [ "$bad_errs" -eq 4 ]; then echo "  [ OK ] 4 条错规则全被挡下（都报了「[规则错]」）"; pass=$((pass+1));
    else echo "  [FAIL] 只挡住了 $bad_errs 条（期望 4）"; fail=$((fail+1)); fi

    if grep -q '还没有规则' /tmp/sc_bad_u.txt; then
        echo "  [ OK ] 错规则一条都没进表（rule list 仍是空的）"; pass=$((pass+1))
    else echo "  [FAIL] 错规则被收进表里了"; fail=$((fail+1)); fi

    if [ "$rc_bad" -eq 0 ]; then echo "  [ OK ] 写错规则不崩（退出码 0）"; pass=$((pass+1));
    else echo "  [FAIL] 写错规则把程序弄崩了（退出码 $rc_bad）"; fail=$((fail+1)); fi

    echo ""
    echo "结果: 通过 $pass / 失败 $fail"
    [ "$fail" -eq 0 ] || exit 1
    ;;
esac
