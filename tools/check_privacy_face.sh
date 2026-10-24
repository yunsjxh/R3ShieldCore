#!/usr/bin/env bash
#
# check_privacy_face.sh —— v129「block 模式下隐私面不拦」的**静态形态判据**。
#
# ★ 为什么还需要它（行为单测已经覆盖了 3 个面）：
#   摄像头面 `camera_guard.cpp` 依赖 Media Foundation（17 处 MF 符号），
#   而本机 `mfplat.lib` 加进链接会出问题（MEMORY-4 铁律 215）⇒
#   `build_guard_ut.sh` **测不到**它。它的改动与另外三个面**完全同构**，
#   所以用形态判据兜住：四处必须都有同一段"先判 IsPrivacyFace、再 WouldBlock"。
#
# ★ 判据查**调用形态**，不查裸名字（MEMORY 里那条坑）：
#   只 grep `IsPrivacyFace` 会被"定义 + 注释 + 说明文字"喂饱 ⇒
#   把调用点删掉仍然通过（变异测试实测）。所以查 `IsPrivacyFace(` 且
#   后面 N 行内必须出现 `WouldBlock`。
#
# 用法: bash tools/check_privacy_face.sh
# 退出码: 0 = 全过 / 1 = 有缺失
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
LIB="$ROOT/R3ShieldCore/R3ShieldCoreLib"
SHARED="$ROOT/R3ShieldCore/shared/r3shieldcore/r3shieldcore_shared.h"

FAILED=0

say_ok()   { echo "[ OK ] $1"; }
say_fail() { echo "[FAIL] $1"; FAILED=1; }

echo "=== v129 隐私面分流：形态判据 ==="

# ---- 判据 1：helper 本体存在（不是注释）----
if grep -q "inline bool IsPrivacyFace(ObjectType type) noexcept" "$SHARED"; then
    say_ok "IsPrivacyFace() 定义存在（inline bool + ObjectType 形参）"
else
    say_fail "shared.h 里没有 IsPrivacyFace() 的**定义**（只有注释不算）"
fi

# ---- 判据 2：四个面都要包含 Camera / InputHook / Screen / Clipboard ----
for face in Camera InputHook Screen Clipboard; do
    if grep -A12 "inline bool IsPrivacyFace" "$SHARED" | grep -q "ObjectType::$face"; then
        say_ok "IsPrivacyFace 认 $face"
    else
        say_fail "IsPrivacyFace 没认 $face —— 漏一个面就等于那个面在 block 下照拦"
    fi
done

# ---- 判据 3：四处 guard 都**调用**了它，且紧跟着标 WouldBlock ----
#   `grep -A6` 取调用点之后 6 行：中间隔着两行注释 + 一行 if 收尾。
check_guard() {
    local file="$1" label="$2"
    if [ ! -f "$LIB/$file" ]; then
        say_fail "$file 不存在"
        return
    fi
    # 调用形态（带左括号），排除注释行 `// ... IsPrivacyFace(...)`
    local hits
    hits=$(grep -c "^[^/]*R3ShieldCore::IsPrivacyFace(" "$LIB/$file" 2>/dev/null || true)
    if [ "${hits:-0}" -lt 1 ]; then
        say_fail "$label：$file 里没有 IsPrivacyFace() 的**调用**（注释/定义不算）"
        return
    fi
    if grep -A6 "^[^/]*R3ShieldCore::IsPrivacyFace(" "$LIB/$file" | grep -q "WouldBlock"; then
        say_ok "$label：$file 调用了 IsPrivacyFace 且标 WouldBlock"
    else
        say_fail "$label：$file 调了 IsPrivacyFace，但后面没有 WouldBlock（可能被改成了直接放行）"
    fi
}

check_guard "camera_guard.cpp"     "摄像头/麦克风"
check_guard "clipboard_guard.cpp"  "剪贴板"
check_guard "screen_guard.cpp"     "截屏"
check_guard "input_hook_guard.cpp" "输入钩子"

# ---- 判据 4：负对照 —— 不存在的标记必须搜不到 ----
#   证明上面的检索本身是活的（不是"grep 永远返回真"）。
if grep -q "IsPrivacyFace_THIS_MARKER_MUST_NOT_EXIST" "$LIB"/*.cpp 2>/dev/null; then
    say_fail "负对照失败：不存在的标记居然搜到了 ⇒ 检索不可信"
else
    say_ok "负对照：不存在的标记搜不到（检索有效）"
fi

# ---- 判据 5：破坏类**不能**被顺手加进隐私名单 ----
#   这是最关键的一条：如果哪天有人图省事把 Registry/File/Driver 也塞进
#   IsPrivacyFace，block 就等于什么都不拦了 —— 而上面 4 条判据**全绿**。
for bad in Registry File Driver Process Thread; do
    if grep -A14 "inline bool IsPrivacyFace" "$SHARED" | grep -q "ObjectType::$bad"; then
        say_fail "IsPrivacyFace 里出现了破坏类 $bad —— block 会因此放水"
    else
        say_ok "破坏类 $bad 不在隐私名单里"
    fi
done

echo ""
if [ "$FAILED" = "0" ]; then
    echo "结果: PASS —— 四个隐私面都在 block 下分流，破坏类没有被误放"
else
    echo "结果: FAIL"
fi
exit "$FAILED"
