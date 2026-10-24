#!/usr/bin/env bash
#
# build_spoof_reg_ktm_probe.sh —— 编译「事务注册表（KTM）」机制探针。
#
# 背景：v75 往 `registry_guard.cpp` 里补了三个**事务注册表**导出
#       （`NtCreateKeyTransacted` / `NtOpenKeyTransacted` /
#        `NtOpenKeyTransactedEx`）。立项依据是：
#          · 事务句柄上**复用同一个** `NtQueryValueKey` / `NtEnumerateKey` /
#            `NtSetValueKey` ⇒ v71 值替换 / v72 枚举隐藏**本来就在生效**；
#          · 缺的只有**"打开 / 创建"这一步的准入判据** —— 原来 `NtOpenKey`
#            的 detour **不经过**事务变体 ⇒ 能绕过"第一道门"。
#       这个探针要**实证**上面两句话，而不是靠推理。
#
# ★★ 探针**不抄** v71 / v72 的算法 —— 直接 `#include` 两个 codec 头，
#    与生产 `registry_guard.cpp` 用**同一份**代码（铁律 195 / 127）。
#    所以本脚本必须把 `R3ShieldCore/R3ShieldCoreLib` 加进包含路径。
#
# 探针是**自包含**的（自己挂自己的 hook），不注入任何进程、不经过引擎、
# 不读屏幕；只在 HKCU 下建一个临时键、结束时删掉。
# 因此**不受**「自动化脚本不得运行引擎」那条约束（铁律 175）。
#
# 用法:
#   bash build_spoof_reg_ktm_probe.sh          # 只编译
#   bash build_spoof_reg_ktm_probe.sh --run    # 编译后跑一次
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

# ★ 多架构脚本必须两架构都真编（见记忆铁律：写死 ${ARCH:-x64} 会让 x86 链 x64 库）。
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

# ★★ GBK 前置闸门（铁律 133）：**窄字面量**里的 `⇒`(U+21D2) 在 CP936 下
#    编不出 ⇒ MSVC 报 C4566 并**静默丢掉那个字符**（注释里的 `⇒` 不受影响）。
#    凡是新增/改动过带中文的源文件，编之前先过这道闸门。
#    （`build_drvload_probe.sh` 是这条惯例的范例。）
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门：tools/spoof_reg_ktm_probe.cpp ==="
    if ! python tools/check_source_gbk.py tools/spoof_reg_ktm_probe.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
fi

# ★ `-source-charset:utf-8` 必须有：源码里有中文注释，
#   不指定的话 UTF-8 字节会被按 CP936 解码，**吞掉后面的行**。
CFLAGS="-nologo -c -std:c++17 -EHsc -O2 -W3 -DUNICODE -D_UNICODE -source-charset:utf-8 -D_CRT_SECURE_NO_WARNINGS"

mkdir -p obj/probe

echo "=== 编译 spoof_reg_ktm_probe.cpp [$ARCH] ==="
"$CL" $CFLAGS -I"$MH_INC_REL" -I"$CODEC_INC_REL" \
    -Fo"obj/probe/spoof_reg_ktm_probe.obj" \
    "tools/spoof_reg_ktm_probe.cpp" || exit 1

echo "=== 链接 ==="
# ktmw32.lib = CreateTransaction / CommitTransaction / RollbackTransaction
# advapi32.lib = RegCreateKeyExW / RegDeleteTreeW
"$LINK" -nologo -SUBSYSTEM:CONSOLE -OUT:"tools/spoof_reg_ktm_probe.exe" \
    "obj/probe/spoof_reg_ktm_probe.obj" \
    "$MH_LIB_REL" \
    kernel32.lib advapi32.lib ktmw32.lib || exit 1

echo "BUILD OK -> tools/spoof_reg_ktm_probe.exe"

if [ "${1:-}" = "--run" ]; then
    echo ""
    echo "=== 运行（自挂自测，不经过引擎）==="
    MSYS_NO_PATHCONV=1 ./tools/spoof_reg_ktm_probe.exe
fi
