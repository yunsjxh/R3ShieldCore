#!/usr/bin/env bash
#
# check_privacy_face.sh —— 隐私面「按配置处置」（v129 分流 + v132 可配）的**静态形态判据**。
#
# ★ 为什么还需要它（行为单测已经覆盖了 3 个面）：
#   摄像头面 `camera_guard.cpp` 依赖 Media Foundation（17 处 MF 符号），
#   而本机 `mplat.lib` 加进链接会出问题（MEMORY-4 铁律 215）⇒
#   `build_guard_ut.sh` **测不到**它。它的改动与另外三个面**完全同构**，
#   所以用形态判据兜住。
#
# ★ 判据查**调用形态**，不查裸名字（MEMORY 里那条坑）：
#   只 grep `IsPrivacyFace` 会被"定义 + 注释 + 说明文字"喂饱 ⇒
#   把调用点删掉仍然通过（变异测试实测）。
#
# ★ v132 起判据变了（旧判据会假红）：
#   原来要求"IsPrivacyFace 之后 N 行内必须有 WouldBlock"。现在这一面
#   可能被配成 **block**（那时正确行为是**没有** WouldBlock），所以
#   改成查三件事：① 调了 `PrivacyActionOf`（读配置）② 调了
#   `IsPrivacyFace`（这面可配）③ 有 `privacy != ...::Block` 的分支
#   （= 真的分了两档，不是把配置读出来就扔）。
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

echo "=== 隐私面处置（v129 分流 / v132 可配）：形态判据 ==="

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
        say_fail "IsPrivacyFace 没认 $face —— 漏一个面就等于那个面不可配"
    fi
done

# ---- 判据 3：位布局钉死 ----
#
# ★ 为什么静态也要查一遍（单测里已经断言过）：单测只跑 guard 层，
#   而**引擎侧解析**（r3shieldcore_config.cpp）用的是同一个位移函数。
#   这条防的是"有人把位移改大/改小，单测和解析一起变、行为用例全绿"。
if grep -A14 "inline ULONG PrivacyActionShift" "$SHARED" | grep -q "return 12;"; then
    say_ok "PrivacyActionShift 里 Camera = bit12（钉死）"
else
    say_fail "PrivacyActionShift 的 Camera 位移不是 12 —— 位布局变了，旧 DLL 会错位"
fi
if grep -A14 "inline ULONG PrivacyActionShift" "$SHARED" | grep -q "return 18;"; then
    say_ok "PrivacyActionShift 里 Clipboard = bit18（钉死）"
else
    say_fail "PrivacyActionShift 的 Clipboard 位移不是 18"
fi

# ---- 判据 4：四处 guard 都按配置分流 ----
#
# 三个条件缺一不可：
#   a) 调了 PrivacyActionOf（否则根本没读配置）
#   b) 调了 IsPrivacyFace（否则非隐私面也会走进这套判断）
#   c) 出现 `privacy != ...PrivacyAction::Block`（否则"读出来就扔"也能满足 a/b）
check_guard() {
    local file="$1" label="$2"
    if [ ! -f "$LIB/$file" ]; then
        say_fail "$file 不存在"
        return
    fi

    # a) 读配置（调用形态：带左括号、非注释行）
    local hits
    hits=$(grep -c "^[^/]*R3ShieldCore::PrivacyActionOf(" "$LIB/$file" 2>/dev/null || true)
    if [ "${hits:-0}" -lt 1 ]; then
        say_fail "$label：$file 没调 PrivacyActionOf（配置没被读）"
        return
    fi

    # b) 这面属于可配范围
    hits=$(grep -c "^[^/]*R3ShieldCore::IsPrivacyFace(" "$LIB/$file" 2>/dev/null || true)
    if [ "${hits:-0}" -lt 1 ]; then
        say_fail "$label：$file 没调 IsPrivacyFace（非隐私面也会进这套判断）"
        return
    fi

    # c) 真的分了档（Block 与其它两档走不同分支）
    if grep -q "privacy != R3ShieldCore::PrivacyAction::Block" "$LIB/$file"; then
        say_ok "$label：$file 读了配置、认面、且按 Block / 非 Block 分了两条路"
    else
        say_fail "$label：$file 读了 PrivacyActionOf 但没有 'privacy != Block' 分支 —— 配置读了没用"
    fi
}

check_guard "camera_guard.cpp"     "摄像头/麦克风"
check_guard "clipboard_guard.cpp"  "剪贴板"
check_guard "screen_guard.cpp"     "截屏"
check_guard "input_hook_guard.cpp" "输入钩子"

# ---- 判据 5：Ask 档在 block 下真的能问 ----
#
# ★ 这是 v132 最容易做错的一处：`canAsk` 原来写死 `mode == Ask`，
#   不改就变成"选了 ask 却永远不弹窗"（静默回落 record）。
#   四处必须都有 `|| privacyAsk` 这样的形态。
for f in camera_guard.cpp clipboard_guard.cpp screen_guard.cpp input_hook_guard.cpp; do
    if grep -q "|| privacyAsk" "$LIB/$f"; then
        say_ok "$f：canAsk 放开了 privacyAsk（block 下 Ask 档能弹窗）"
    else
        say_fail "$f：canAsk 没接 privacyAsk —— 选了 ask 也不会弹窗（静默失效）"
    fi
done

# ---- 判据 6：负对照 —— 不存在的标记必须搜不到 ----
#   证明上面的检索本身是活的（不是"grep 永远返回真"）。
if grep -q "IsPrivacyFace_THIS_MARKER_MUST_NOT_EXIST" "$LIB"/*.cpp 2>/dev/null; then
    say_fail "负对照失败：不存在的标记居然搜到了 ⇒ 检索不可信"
else
    say_ok "负对照：不存在的标记搜不到（检索有效）"
fi

# ---- 判据 7：破坏类**不能**被顺手加进隐私名单 ----
#   这是最关键的一条：如果哪天有人图省事把 Registry/File/Driver 也塞进
#   IsPrivacyFace，block 就等于什么都不拦了 —— 而上面几条**全绿**。
for bad in Registry File Driver Process Thread; do
    if grep -A14 "inline bool IsPrivacyFace" "$SHARED" | grep -q "ObjectType::$bad"; then
        say_fail "IsPrivacyFace 里出现了破坏类 $bad —— block 会因此放水"
    else
        say_ok "破坏类 $bad 不在隐私名单里"
    fi
done

# ---- 判据 8：ini 里真的带上了四个键 ----
#
# ★ 只查源码不查配置 = 漏掉"代码支持、随包配置没写"这种情况。
#   默认值不写也能跑（引擎默认 record），但用户翻 ini 时看不到这个功能，
#   等于没做 —— 而判据全绿。
INI="$ROOT/dist/R3ShieldCore-x64/r3shieldcore.ini"
if [ -f "$INI" ]; then
    for k in privacy_camera privacy_input_hook privacy_screen privacy_clipboard; do
        if grep -q "^$k=" "$INI"; then
            say_ok "随包 ini 里有 $k"
        else
            say_fail "随包 ini 里没有 $k —— 功能做了但用户看不见（等于没做）"
        fi
    done
else
    say_fail "找不到 $INI"
fi

# ---- 判据 9：界面与引擎认的**字面量**必须一致 ----
#
# ★★★ 这是本轮最容易漏、且**所有行为单测都测不到**的一处：
#   行为单测直接调 `PrivacyActionOf()`（枚举），根本不经过 ini 字符串；
#   而用户是通过 cfg 界面写 ini 的，写的是 `kOptPrivacy` 里的字面量，
#   引擎读的是 `ParsePrivacyAction()` 认的字面量。
#   两处只要差一个字母，症状是"界面显示 ask、实际跑 record" ——
#   而单测、形态判据、发布闸门**全绿**（铁律：配置类 bug 的经典形态）。
CFGTOOL="$ROOT/tools/r3shieldcore_cfg.cpp"
ENGCFG="$ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp"
for lit in record ask block; do
    if grep -q "L\"$lit\"" "$CFGTOOL"; then
        :
    else
        say_fail "cfg 界面的 kOptPrivacy 里没有 \"$lit\"（用户选不到这一档）"
    fi
    if grep -q "\"$lit\"" "$ENGCFG"; then
        :
    else
        say_fail "引擎 ParsePrivacyAction 不认 \"$lit\" —— 界面写进去的值会被当成非法"
    fi
done
if grep -q "kOptPrivacy\[\] = { L\"record\", L\"ask\", L\"block\", nullptr }" "$CFGTOOL"; then
    say_ok "界面取值与引擎字面量一致（record / ask / block）"
else
    say_fail "kOptPrivacy 的取值不是 {record, ask, block} —— 与引擎 ParsePrivacyAction 对齐了吗？"
fi

echo ""
if [ "$FAILED" = "0" ]; then
    echo "结果: PASS —— 四个隐私面都按配置分流，Ask 档能弹窗，破坏类没被误放"
else
    echo "结果: FAIL"
fi
exit "$FAILED"
