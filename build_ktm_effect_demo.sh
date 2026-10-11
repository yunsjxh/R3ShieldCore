#!/usr/bin/env bash
#
# build_ktm_effect_demo.sh —— 编译「注册表保护：看得见的效果」演示。
#
# 背景：用户要的不是文档、不是探针结论，而是**能跑、能看见**的东西。
#       这个演示把「保护逻辑」装在自己进程里，然后**自己扮演攻击者**去攻
#       同一台机器上的受保护键，把每一步的真实返回值和真实数据打印出来。
#
#       三幕：
#         第 1 幕  保护关闭  —— 想读就读 / 想枚举就枚举 / 想写就写
#         第 2 幕  保护打开  —— 读不到 / 看不见 / 写不进
#         第 3 幕  事务（KTM）绕过 —— (A) v75 之前：准入敞开
#                                   (B) v75 之后：同一套判据挡住 + 负对照放行
#
# ★★ 演示**不启动引擎、不注入任何进程**（铁律 175 不适用）；
#    只在 HKCU 下建临时键，跑完删掉。
# ★★ 判据与伪造逻辑**与生产同源**：直接 `#include` 两个 codec 头（铁律 195）。
#
# 用法:
#   bash build_ktm_effect_demo.sh          # 只编译
#   bash build_ktm_effect_demo.sh --run    # 编译后跑一次
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

# ⚠️ 必须 cd 进项目根并用**相对路径**（项目根含中文，绝对路径会 C1083）。
cd "$PROJECT_ROOT" || exit 1

# ★★ GBK 前置闸门（铁律 133）：**窄字面量**里的非 GBK 字符（如 `⇒`）在 CP936
#    下编不出 ⇒ MSVC 报 C4566 并**静默丢掉那个字符**。编之前先过这道闸门。
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门：tools/ktm_effect_demo.cpp ==="
    if ! python tools/check_source_gbk.py tools/ktm_effect_demo.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
fi

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，不指定的话 UTF-8 字节
#   会被按 CP936 解码，**吞掉后面的行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 ktm_effect_demo.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -I"$CODEC_INC_REL" \
    -Fo"obj/probe/ktm_effect_demo.obj" \
    "tools/ktm_effect_demo.cpp" || exit 1

echo "=== 链接 ==="
# ktmw32.lib   = CreateTransaction / CommitTransaction / RollbackTransaction
# advapi32.lib = RegCreateKeyExW / RegSetValueExW / RegEnumKeyExW / RegDeleteTreeW
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/ktm_effect_demo.exe" \
    "obj/probe/ktm_effect_demo.obj" \
    "$MH_LIB_REL" \
    kernel32.lib advapi32.lib ktmw32.lib || exit 1

echo "BUILD OK -> tools/ktm_effect_demo.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/ktm_effect_demo.exe
fi
