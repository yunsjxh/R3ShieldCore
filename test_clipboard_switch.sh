#!/usr/bin/env bash
#
# test_clipboard_switch.sh —— 一键实测「hook_clipboard 开关能不能真的关掉剪贴板 hook」。
#
# ============================================================================
# 为什么要有这个测试
# ============================================================================
#
# `hook_clipboard=0` 生效的表现是「**什么都没发生**」：
#   · 运行时日志里不会有任何 CLIP 行（没挂 hook 自然没有事件）
#   · `clipboard_guard.cpp:325` 那条「hook_clipboard 未开启…」走 `LOG()`
#     ⇒ 只 OutputDebugString（+ 可选 stderr），**不落文件** ⇒ grep 永远翻不到
#
# ⇒ 必须直接看**被注入进程里函数首字节**（在场证据），并且做 **A/B 反向对照**
#   （铁律 54：没有对照的测试等于没测）。
#
# ============================================================================
# 前置条件（脚本会自己检查）
# ============================================================================
#
#   1. 一个**已加固 ACL** 的引擎沙盒目录（否则引擎拒载 DLL，铁律 39/48）：
#        cp -r dist/R3ShieldCore-x64-v53 _t/clip_ab
#        bash harden_dist_acl.sh _t/clip_ab
#   2. 引擎沙盒里要有 dskill.exe（直 syscall 停引擎，绕过自我保护）
#
# ============================================================================
# ★★ 为什么整套塞进一个 exe，而不是 bash 直接驱动
# ============================================================================
#
# 引擎存活期间 bash `fork()` 全废、PowerShell 起不来、spawn System32 程序被拒
# ⇒ 用 bash 驱动必然把执行环境锁死（铁律 76）。
# 所以这里只负责「**准备工作 + 启动套件 + 展示结果**」，
# 引擎的起/停全在 `clipboard_ab_suite.exe` 内部完成。
#
# 用法:
#   bash test_clipboard_switch.sh                    # 用默认沙盒 _t/clip_ab
#   bash test_clipboard_switch.sh <引擎沙盒目录>
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
SANDBOX="${1:-_t/clip_ab}"

cd "$PROJECT_ROOT" || exit 1

PROBE="tools/clipboard_hook_probe.exe"
SUITE="tools/clipboard_ab_suite.exe"
RESULT="clipboard_ab_result.txt"

echo "============================================================"
echo " hook_clipboard 开关 A/B 实测"
echo "============================================================"
echo " 沙盒     : $SANDBOX"
echo " 探针     : $PROBE"
echo " 套件     : $SUITE"
echo ""

# ---------- 前置检查 ----------
fail=0

if [ ! -x "$PROBE" ]; then
    echo "[!] 缺少 $PROBE —— 先跑： bash build_clipboard_hook_probe.sh"
    fail=1
fi
if [ ! -x "$SUITE" ]; then
    echo "[!] 缺少 $SUITE —— 先跑： bash build_clipboard_ab_suite.sh"
    fail=1
fi
if [ ! -f "$SANDBOX/R3 ShieldCore.exe" ]; then
    echo "[!] 沙盒里没有引擎： $SANDBOX/R3 ShieldCore.exe"
    echo "    建沙盒： cp -r dist/R3ShieldCore-x64-v53 $SANDBOX"
    fail=1
fi
if [ ! -f "$SANDBOX/dskill.exe" ]; then
    echo "[!] 沙盒里没有 dskill.exe（停引擎用）"
    fail=1
fi
if [ "$fail" != "0" ]; then
    exit 1
fi

# ---------- ACL 预检（★ 不通过就会得到"假绿"：引擎起得来但拒载 DLL）----------
echo "--- ACL 预检（引擎愿意加载 DLL 的前提）---"
if ! bash harden_dist_acl.sh --verify "$SANDBOX" 2>&1 | grep -q "\[PASS\]"; then
    echo ""
    echo "[!] ACL 未通过 —— 引擎会拒载 DLL，测试结果会是假绿（全 NOT-HOOKED）。"
    echo "    修复： bash harden_dist_acl.sh $SANDBOX"
    exit 1
fi
echo "[OK] ACL 通过"
echo ""

# ---------- 跑套件 ----------
echo "--- 启动套件（会弹一次 UAC，请点「是」）---"
echo ""

rm -f "$RESULT"
MSYS_NO_PATHCONV=1 "./$SUITE" "$(cd "$PROJECT_ROOT" && pwd -W 2>/dev/null || echo "$PROJECT_ROOT")/$SANDBOX" \
    "$(cd "$PROJECT_ROOT" && pwd -W 2>/dev/null || echo "$PROJECT_ROOT")/$PROBE" \
    "$(cd "$PROJECT_ROOT" && pwd -W 2>/dev/null || echo "$PROJECT_ROOT")/$PROBE"
suiteExit=$?

echo ""
echo "--- 套件退出码: $suiteExit ---"
echo ""

# ---------- 展示结果 ----------
if [ -f "$RESULT" ]; then
    echo "============================================================"
    echo " 结果（$RESULT）"
    echo "============================================================"
    cat "$RESULT"
    echo ""
else
    echo "[!] 没有拿到 $RESULT —— 可能 UAC 被取消，或套件没跑起来"
    exit 1
fi

# ---------- 判读 ----------
echo "============================================================"
if grep -q "RESULT: .* -> PASS" "$RESULT"; then
    echo " 结论: PASS —— hook_clipboard 开关**确实**能关掉剪贴板 hook"
    echo "   · =1 时 GetClipboardData / OpenClipboard 均为 HOOKED（E9 ...）"
    echo "   · =0 时两者恢复原始序言（NOT-HOOKED）"
    echo "   · 两轮 BitBlt 均 HOOKED ⇒ 注入确实发生（排除「没注入」的假绿）"
else
    echo " 结论: FAIL —— 见上方逐条断言"
fi
echo "============================================================"

exit $suiteExit
