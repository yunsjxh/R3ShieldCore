#!/usr/bin/env bash
#
# 直接驱动 cl.exe / link.exe 构建 R3ShieldCore 内核组件（r3shieldcore_kernel.sys）。
#
# 为什么不用 MSBuild / devenv：与 build.sh 同样的原因（见 build.sh 顶部注释）
# —— 本机 devenv.com 不执行命令行构建，MSBuild.exe 被安全策略按名字拦截。
#
# ===========================================================================
# ★ 为什么内核构建要**单独一套 SDK 路径**（这是本脚本最容易踩的坑）
# ===========================================================================
# 项目根 build.sh 用的是 SDK 10.0.26100.0，但那个版本**只装了用户态部分**：
#   Include/10.0.26100.0/  → 只有 cppwinrt shared ucrt um winrt（**没有 km**）
#   Lib/10.0.26100.0/      → 没有 km
# 内核头/库装在**另一个版本** 10.0.28000.0 下：
#   Include/10.0.28000.0/km/      ← wdm.h / ntddk.h 在这里
#   Lib/10.0.28000.0/km/x64/      ← ntoskrnl.lib / BufferOverflowK.lib 在这里
# 所以内核构建必须用 WDK_SDK_VERSION=10.0.28000.0，**不能**跟着 build.sh 走。
# 症状：如果跟着 build.sh 用 26100，会报 "cannot open include file: 'ntddk.h'"
#       —— 而且看起来像"没装 WDK"，实际是版本指错了。
#
# ★ include 顺序也和用户态完全不同：
#     内核:  km ; km/crt ; shared ; ucrt      ← 绝不能把 um 放进来
#     用户态: ucrt ; shared ; um
#   把 um 混进内核构建会引入用户态原型（同一函数名两套签名），报一堆
#   "conflicting types" 或静默按错误原型链接。
#
# 用法：
#   bash driver/build_driver.sh              # Release x64（默认）
#   bash driver/build_driver.sh Debug        # 带 /Zi（不生成 pdb 之外的调试器配置）
#
set -u

DRIVER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
# ★ WDK 内核头/库：SDK_ROOT 由 scripts_env.sh 探测。
#   内核头/库只装在**某个具体版本**下（本机是 10.0.28000.0），且该版本必须含 km/。
#   所以这里不直接复用 $SDK_VERSION（那可能是只装了用户态部分的版本），
#   而是从 SDK_ROOT/Include/ 里**挑第一个含 km/ 的版本**；可用 WDK_SDK_VERSION 覆盖。
WDK_ROOT="${WDK_ROOT:-$SDK_ROOT}"
if [ -z "${WDK_SDK_VERSION:-}" ]; then
    WDK_SDK_VERSION=""
    for d in "$WDK_ROOT"/Include/*/ ; do
        [ -d "$d/km" ] || continue
        v="$(basename "$d")"
        if [ -z "$WDK_SDK_VERSION" ] || [ "$(printf '%s\n%s\n' "$WDK_SDK_VERSION" "$v" | sort -V | tail -1)" = "$v" ]; then
            WDK_SDK_VERSION="$v"
        fi
    done
fi
if [ -z "$WDK_SDK_VERSION" ]; then
    echo "找不到含 km/ 的 WDK/SDK 版本（内核头文件）。"
    echo "→ 请安装 WDK（Windows Driver Kit），或用 WDK_SDK_VERSION 指定。"
    echo "→ 已安装版本：$(ls "$WDK_ROOT/Include/" 2>/dev/null | tr '\n' ' ')"
    exit 1
fi

CONFIG="${1:-Release}"

cd "$DRIVER_ROOT" || { echo "找不到驱动目录: $DRIVER_ROOT"; exit 1; }

# ---- 预检 0：源文件里不能有 CP936 编不出的字符 ----
# 为什么要有这一步：MSVC 只会给一条 warning C4566，然后**把那个字符丢掉**，
# 窄字符串字面量被静默改写（"⚠ 失败" → " 失败"）。没有 error、没有乱码。
# 详见 tools/check_source_gbk.py 顶部说明（铁律 46）。
if [ -f "../tools/check_source_gbk.py" ]; then
    if ! python ../tools/check_source_gbk.py r3shieldcore_kernel.c driver_probe.c; then
        echo ""
        echo "BUILD FAILED (预检：源码字符集)"
        exit 1
    fi
    echo ""
fi

# ---- 预检 0b：.bat 里不许出现 `dir` 中间段带通配符 ----
# 为什么：`dir "X:\a\*\b.exe"` 不报错、不提示，就是 exit=1 + 零输出；
# 而 `for /f` 对"命令失败"和"命令成功但没输出"一视同仁，于是**静默 0 次迭代**，
# 最后落到"找不到 X，跳过这一步"——看起来像"这台机器没装那个东西"。
# ★ 真踩过：install_driver.bat 的签名预检就是这么坏的（从来没执行过）。
# 详见 tools/check_bat_dir_wildcard.py 顶部说明（铁律 100/124）。
if [ -f "../tools/check_bat_dir_wildcard.py" ]; then
    if ! python ../tools/check_bat_dir_wildcard.py; then
        echo ""
        echo "BUILD FAILED (预检：.bat 的 dir 通配符位置)"
        exit 1
    fi
    echo ""
fi

# ---- 内核头/库存在性预检：缺了就直说，别让编译器报一句含糊的 ntddk.h 找不到 ----
KM_INC="$WDK_ROOT/Include/$WDK_SDK_VERSION/km"
KM_LIB="$WDK_ROOT/Lib/$WDK_SDK_VERSION/km/x64"
for p in "$KM_INC/wdm.h" "$KM_INC/ntddk.h" "$KM_LIB/ntoskrnl.lib" "$KM_LIB/BufferOverflowK.lib"; do
    if [ ! -f "$p" ]; then
        echo "缺少内核构建所需文件: $p"
        echo "→ 需要安装 WDK（Windows Driver Kit），或确认版本号是否为 $WDK_SDK_VERSION"
        echo "→ 本机已安装的 SDK 版本：$(ls "$WDK_ROOT/Include/" 2>/dev/null | tr '\n' ' ')"
        exit 1
    fi
done

# ---- 工具链（x64 宿主 → x64 目标）----
CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"
DUMPBIN="$MSVC_ROOT/bin/Hostx64/x64/dumpbin.exe"

for t in "$CL" "$LINK"; do
    [ -f "$t" ] || { echo "找不到编译器: $t"; exit 1; }
done

# ★ include 顺序：km 在最前，**不含 um**
r3sc_export_km_env "${ARCH:-x64}" "$WDK_SDK_VERSION"

OUTDIR="build"
mkdir -p "$OUTDIR"

# ---- 参数一律用 `-` 前缀，不用 `/` ----
# ★ 这是本仓库踩过的坑：Git-Bash/MSYS 会把**以 `/` 开头的参数当成路径**做
#   POSIX→Windows 转换，于是 `/nologo` 变成 `C:/.../PortableGit/.../nologo`，
#   cl 收到一堆"无法识别的源文件类型 D9024"警告，而 `/D_AMD64_` 被吃掉后
#   内核头会直接 `#error "No Target Architecture"`。
#   cl.exe / link.exe 两种前缀都认，所以统一写 `-`。
#
# -kernel  —— 内核模式：关掉用户态 CRT/异常/RTTI 假设，设 _KERNEL_MODE
# -GS-     —— 关栈保护。开着 /GS 就要链 BufferOverflowK 的 __security_cookie，
#             并且入口点得用 GsDriverEntry（CRT 提供的包装）而不是 DriverEntry。
#             这里用 -GS- + -ENTRY:DriverEntry，行为确定、少一层依赖。
# -source-charset:utf-8 —— **必须有**：源文件是 UTF-8，而中文系统上 cl 默认按
#             CP936 解码，注释里的全角标点会吃掉换行、把下一行代码吞进注释
#             （本仓库已有同类事故记录）。
# -D_AMD64_ —— cl.exe 只自动定义 _M_AMD64/_M_X64；wdm.h 判的是 _AMD64_（带尾下划线），
#             不手动定义会在内核头里走错分支。
CFLAGS="-nologo -c -kernel -GS- -W4 -O2 -source-charset:utf-8 -we4566 -D_AMD64_ -DAMD64"

if [ "$CONFIG" = "Debug" ]; then
    CFLAGS="$CFLAGS -Zi -Od"
fi

echo "=== 编译 r3shieldcore_kernel.c ($CONFIG, x64, WDK $WDK_SDK_VERSION) ==="
# shellcheck disable=SC2086
"$CL" $CFLAGS -Fo"$OUTDIR/r3shieldcore_kernel.obj" r3shieldcore_kernel.c
if [ $? -ne 0 ]; then
    echo ""
    echo "BUILD FAILED (编译阶段)"
    exit 1
fi

echo ""
echo "=== 链接 r3shieldcore_kernel.sys ==="
# -DRIVER        —— 内核驱动
# -SUBSYSTEM:NATIVE —— 内核映像必须走 native 子系统（不是 CONSOLE/GUI）
# -ENTRY:DriverEntry —— 显式指定入口（配 -GS- 使用）
# -NODEFAULTLIB  —— 否则会链进用户态 CRT，内核里一跑就崩
"$LINK" -nologo -DRIVER -SUBSYSTEM:NATIVE -ENTRY:DriverEntry \
    -NODEFAULTLIB -MACHINE:X64 -INCREMENTAL:NO -OPT:REF -OPT:ICF \
    -VERSION:1.0 \
    -MAP:"$OUTDIR/r3shieldcore_kernel.map" \
    -OUT:"$OUTDIR/r3shieldcore_kernel.sys" \
    "$OUTDIR/r3shieldcore_kernel.obj" \
    "$KM_LIB/ntoskrnl.lib" "$KM_LIB/BufferOverflowK.lib" "$KM_LIB/wdm.lib"
if [ $? -ne 0 ]; then
    echo ""
    echo "BUILD FAILED (链接阶段)"
    exit 1
fi

echo ""
echo "=== 校验产物是合法内核映像 ==="
"$DUMPBIN" -headers "$OUTDIR/r3shieldcore_kernel.sys" 2>/dev/null | grep -iE \
    "subsystem|machine|entry point|image version" | head -8

SIZE=$(stat -c %s "$OUTDIR/r3shieldcore_kernel.sys" 2>/dev/null)
echo ""
echo "BUILD OK  ->  $OUTDIR/r3shieldcore_kernel.sys  ($SIZE 字节)"

# ===========================================================================
# 用户态取证探针
#
# ★ 这里必须把 INCLUDE/LIB **整套换回用户态**。内核那套里没有 windows.h /
#   stdio.h；而且 um 与 km 是两套原型（同名函数签名不同），混用会报一堆
#   conflicting types，或者更糟——静默按错误原型链接。
# ===========================================================================
echo ""
echo "=== 编译用户态取证探针 ==="

r3sc_export_msvc_env "${ARCH:-x64}"

UCFLAGS="-nologo -c -O2 -MT -W3 -source-charset:utf-8 -we4566 -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE"

# shellcheck disable=SC2086
"$CL" $UCFLAGS -Fo"$OUTDIR/driver_probe.obj" driver_probe.c
if [ $? -ne 0 ]; then
    echo ""
    echo "BUILD FAILED (探针编译)"
    exit 1
fi

# advapi32 是 RegOpenKeyExW 需要的
"$LINK" -nologo -SUBSYSTEM:CONSOLE -MACHINE:X64 -INCREMENTAL:NO \
    -OUT:"$OUTDIR/driver_probe.exe" \
    "$OUTDIR/driver_probe.obj" \
    kernel32.lib advapi32.lib
if [ $? -ne 0 ]; then
    echo ""
    echo "BUILD FAILED (探针链接)"
    exit 1
fi
echo "  -> $OUTDIR/driver_probe.exe"
echo ""
echo "BUILD OK  ->  $OUTDIR/driver_probe.exe"
echo ""
echo "下一步（都需要管理员，且会改启动配置）："
echo "  1) 签名   powershell -File driver/sign_driver.ps1"
echo "  2) 安装   driver/install_driver.bat      （sc create start=boot）"
echo "  3) 重启后验证   powershell -File driver/verify_autostart.ps1"
echo "★ 本机 BitLocker 已启用：改启动配置前先备好恢复密钥，详见 driver/README.md"
