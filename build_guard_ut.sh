#!/usr/bin/env bash
#
# build_guard_ut.sh - 构建并运行 **guard 层** 单测（v28 起）。
#
# 为什么需要独立的脚本（与 build_ut.sh 的分工）：
#   `build_ut.sh` 只链 `r3shieldcore_rules.cpp` —— 那是**规则层**，
#   秒级、无依赖，适合改规则表后第一时间跑。
#
#   但 v28 的修复点在 **guard 层**（`registry_guard.cpp` 的 `Evaluate`），
#   规则层单测**测不到**。本脚本直接编译 `registry_guard.cpp` 本体
#   （带 `-DREGUARD_GUARD_UT` 打开文件尾部的单测入口）+ `tools/guard_stub.cpp`，
#   把 guard 层真正跑起来。
#
# 代价：要链 MinHook（`registry_guard.cpp` 的 `Install` 用到），
#       所以比规则层单测慢一些，但仍是秒级。
#
# 用法: bash build_guard_ut.sh [x64|x86]
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
TOOLS="$PROJECT_ROOT/tools"


ARCH="${1:-x64}"

if [ "$ARCH" = "x64" ]; then
    HOST="Hostx64/x64"
    MH_LIB="libMinHook.x64.lib"
else
    HOST="Hostx64/x86"
    MH_LIB="libMinHook.x86.lib"
fi

r3sc_export_msvc_env "${ARCH:-x64}"

CL="$MSVC_ROOT/bin/$HOST/cl.exe"
LINK="$MSVC_ROOT/bin/$HOST/link.exe"

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

OBJDIR_REL="tools/guard-ut-obj-$ARCH"
mkdir -p "$OBJDIR_REL"

# ★ `-DREGUARD_GUARD_UT` 打开 registry_guard.cpp 尾部的单测入口。
CFLAGS="-nologo -c -O2 -MT -std:c++20 -EHsc -W3 -source-charset:utf-8 \
-DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE -DREGUARD_GUARD_UT"

INCS="-IR3ShieldCore/shared -IR3ShieldCore/R3ShieldCoreLib/libraries \
-IR3ShieldCore/R3ShieldCoreLib -IR3ShieldCore/shared/libraries \
-IR3ShieldCore/R3ShieldCore"

LIB_SRC_REL="R3ShieldCore/R3ShieldCoreLib"
MH_LIB_REL="$LIB_SRC_REL/libraries/MinHook/$MH_LIB"

echo "=== 编译 guard 层底座（$ARCH）==="
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/r3shieldcore_rules.obj" "$LIB_SRC_REL/r3shieldcore_rules.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/registry_guard.obj" "$LIB_SRC_REL/registry_guard.cpp" || exit 1
# ★ v29：token_theft_guard.cpp 也要编（它的单测入口在文件尾，靠 REGUARD_GUARD_UT 打开）。
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/token_theft_guard.obj" "$LIB_SRC_REL/token_theft_guard.cpp" || exit 1
"$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/guard_stub.obj" "tools/guard_stub.cpp" || exit 1

FAILED=0
RAN=0

run_one() {
    local name="$1"
    local extra="${2:-}"
    echo ""
    echo "=== $name [$ARCH] ==="

    "$CL" $CFLAGS $INCS -Fo"$OBJDIR_REL/$name.obj" "tools/$name.cpp" || { FAILED=1; return; }

    "$LINK" -nologo -SUBSYSTEM:CONSOLE \
        -OUT:"tools/$name.exe" \
        "$OBJDIR_REL/$name.obj" \
        $extra \
        "$OBJDIR_REL/registry_guard.obj" \
        "$OBJDIR_REL/r3shieldcore_rules.obj" \
        "$OBJDIR_REL/guard_stub.obj" \
        "$MH_LIB_REL" \
        kernel32.lib advapi32.lib || { FAILED=1; return; }

    "./tools/$name.exe" || FAILED=1
    # ★ 无论断言是否通过都计数 —— 这个计数要回答的是
    #   "有没有**根本没跑起来**的单测"（编译/链接阶段就断了）。
    RAN=$((RAN + 1))
}

# ---------------------------------------------------------------------------
# 单测名字清单（**只此一份**，铁律 127：同一份清单拷贝多份⇒必漂）
# ---------------------------------------------------------------------------
# 格式： "测试名|额外要链的 obj（可空）"
#
# ★ 为什么写成数组 + 显式"文件不存在就 FAIL"（而不是 `[ -f ] && run_one`）：
#   `[ -f ] && run_one` 在文件被删/改名时**静默跳过** —— 闸门照旧全绿，
#   覆盖却已经丢了（铁律 142「只查存在⇒假绿」的同款）。
#   声明了就必须在，不在就红。
TESTS=(
    "v28_guard_ut|"
    "v29_guard_ut|$OBJDIR_REL/token_theft_guard.obj"
    "uacwhitelist_ut|"
)

DECLARED=${#TESTS[@]}
for entry in "${TESTS[@]}"; do
    t="${entry%%|*}"
    extra="${entry##*|}"
    if [ ! -f "$TOOLS/$t.cpp" ]; then
        echo ""
        echo "[FAIL] 清单里声明了 $t，但 tools/$t.cpp 不存在"
        echo "       ⇒ 单测被删掉/改名却没同步清单 = **静默丢覆盖**，必须红"
        FAILED=1
        continue
    fi
    run_one "$t" "$extra"
done

# ---- 覆盖恒等式自检（铁律 148）---------------------------------------------
# 声明的个数必须等于"编译+链接+执行"跑完的个数。
# 不等 ⇒ 有单测在编译/链接阶段中断（`|| return` 静默退出了）。
echo ""
echo "=== 覆盖恒等式自检 [$ARCH] ==="
if [ "$RAN" = "$DECLARED" ]; then
    echo "[ OK ] 声明的 $DECLARED 个单测全部跑完（RAN=$RAN）"
else
    echo "[FAIL] 声明 $DECLARED 个，跑完 $RAN 个 ⇒ 有单测在编译/链接阶段中断"
    echo "       （逐个看上面的 \"=== <名字> [$ARCH] ===\" 段落，缺哪个就是哪个）"
    FAILED=1
fi

echo ""
if [ "$FAILED" = "0" ]; then
    echo "=== guard 层单测全部通过 ==="
else
    echo "=== guard 层单测存在失败用例 ==="
fi
exit $FAILED
