#!/usr/bin/env bash
# ============================================================================
#  scripts_env.sh —— 工具链自动探测（所有 build_*.sh / *.sh 共用）
#
#  用法（在脚本开头）：
#      SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#      . "$SCRIPT_DIR/scripts_env.sh"
#
#  之后可直接用：
#      $PROJECT_ROOT   仓库根（= 本文件所在目录）
#      $R3SC_SRC_DIR   源码工程目录（$PROJECT_ROOT/R3ShieldCore）
#      $MSVC_ROOT      MSVC 工具链根（.../VC/Tools/MSVC/<ver>）
#      $SDK_ROOT       Windows Kits 根
#      $SDK_VERSION    SDK 版本号
#      $RC             rc.exe（资源编译器）
#      $PYTHON         Python 解释器
#      $GCC            MSYS2 gcc（找不到则为空）
#      r3sc_to_windir <path>   把 /d/foo 转成 D:/foo（给 cl/link 的 INCLUDE/LIB 用）
#      r3sc_export_msvc_env <arch>  导出 INCLUDE/LIB（arch = x86|x64）
#
#  全部可用环境变量覆盖：
#      R3SC_PROJECT_ROOT  MSVC_ROOT  SDK_ROOT  SDK_VERSION  PYTHON  GCC
# ============================================================================

# ---- 仓库根 = 本文件所在目录 ----
: "${R3SC_PROJECT_ROOT:=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"
R3SC_SRC_DIR="$PROJECT_ROOT/R3ShieldCore"

# ---- MSYS 风格路径 -> Windows 风格（给 cl.exe / link.exe 的 INCLUDE、LIB 用）----
#   ★ cl/link 认 Windows 路径；MSYS 挂载点形式 /d/Windows Kits/... 它们找不到，
#     会报 `fatal error C1083: 无法打开包括文件: "windows.h"`。
r3sc_to_windir() {
    case "$1" in
        /[a-zA-Z]/*)
            local drive rest
            drive="$(echo "$1" | cut -c2 | tr 'a-z' 'A-Z')"
            rest="$(echo "$1" | cut -c4-)"
            printf '%s:/%s\n' "$drive" "$rest"
            ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# ---- MSVC 根：优先 $MSVC_ROOT，否则 vswhere，否则扫常见安装位置 ----
r3sc_find_msvc() {
    if [ -n "${MSVC_ROOT:-}" ] && [ -d "$MSVC_ROOT" ]; then
        echo "$MSVC_ROOT"; return 0
    fi
    local vswhere=""
    local c
    for c in \
        "/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe" \
        "/d/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe" \
        "/c/Program Files/Microsoft Visual Studio/Installer/vswhere.exe" \
        "/d/Program Files/Microsoft Visual Studio/Installer/vswhere.exe" ; do
        [ -x "$c" ] && { vswhere="$c"; break; }
    done
    [ -z "$vswhere" ] && command -v vswhere >/dev/null 2>&1 && vswhere="$(command -v vswhere)"
    if [ -n "$vswhere" ]; then
        local vsroot
        vsroot="$("$vswhere" -latest -products '*' \
                 -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 \
                 -property installationPath 2>/dev/null | tr -d '\r')"
        if [ -n "$vsroot" ]; then
            vsroot="$(echo "$vsroot" | sed -e 's#\\#/#g' -e 's#^\([A-Za-z]\):#/\L\1#')"
            local best
            best="$(ls -1d "$vsroot"/VC/Tools/MSVC/*/ 2>/dev/null | sort -V | tail -1)"
            [ -n "$best" ] && { echo "${best%/}"; return 0; }
        fi
    fi
    local p
    for p in "/c/Program Files/Microsoft Visual Studio"/*/*/VC/Tools/MSVC \
             "/d/Program Files/Microsoft Visual Studio"/*/*/VC/Tools/MSVC ; do
        [ -d "$p" ] || continue
        local b; b="$(ls -1d "$p"/*/ 2>/dev/null | sort -V | tail -1)"
        [ -n "$b" ] && { echo "${b%/}"; return 0; }
    done
    return 1
}

# ---- Windows SDK 根 ----
r3sc_find_sdk() {
    if [ -n "${SDK_ROOT:-}" ] && [ -d "$SDK_ROOT" ]; then
        echo "$SDK_ROOT"; return 0
    fi
    local p
    for p in "/c/Program Files (x86)/Windows Kits/10" \
             "/d/Program Files (x86)/Windows Kits/10" \
             "/c/Program Files/Windows Kits/10" \
             "/d/Program Files/Windows Kits/10" \
             "/c/Windows Kits/10" "/d/Windows Kits/10" ; do
        [ -d "$p" ] && { echo "$p"; return 0; }
    done
    return 1
}

# ---- SDK 版本：挑 Include/ 下含 ucrt 的最大版本 ----
r3sc_find_sdk_version() {
    local root="$1" v="" cur
    for d in "$root"/Include/*/ ; do
        [ -d "$d/ucrt" ] || continue
        cur="$(basename "$d")"
        if [ -z "$v" ] || [ "$(printf '%s\n%s\n' "$v" "$cur" | sort -V | tail -1)" = "$cur" ]; then
            v="$cur"
        fi
    done
    echo "$v"
}

# ---- Python ----
r3sc_find_python() {
    if [ -n "${PYTHON:-}" ] && [ -x "$PYTHON" ]; then echo "$PYTHON"; return 0; fi
    local n
    for n in python3 python py; do
        command -v "$n" >/dev/null 2>&1 && { echo "$(command -v "$n")"; return 0; }
    done
    return 1
}

# ---- MSYS2 gcc（部分探针用它；找不到不报错）----
r3sc_find_gcc() {
    if [ -n "${GCC:-}" ] && [ -x "$GCC" ]; then echo "$GCC"; return 0; fi
    local p
    for p in "/d/msys64/ucrt64/bin/gcc.exe" "/c/msys64/ucrt64/bin/gcc.exe" \
             "/d/msys64/mingw64/bin/gcc.exe" "/c/msys64/mingw64/bin/gcc.exe" ; do
        [ -x "$p" ] && { echo "$p"; return 0; }
    done
    command -v gcc >/dev/null 2>&1 && { echo "$(command -v gcc)"; return 0; }
    return 1
}

# ---- 探测并落变量（失败只警告，不直接 exit：探针脚本可能不需要 MSVC）----
MSVC_ROOT="$(r3sc_find_msvc || true)"
SDK_ROOT="$(r3sc_find_sdk || true)"
if [ -n "$SDK_ROOT" ]; then
    [ -z "${SDK_VERSION:-}" ] && SDK_VERSION="$(r3sc_find_sdk_version "$SDK_ROOT")"
fi
PYTHON="$(r3sc_find_python || true)"
GCC="$(r3sc_find_gcc || true)"

# rc.exe
RC=""
if [ -n "$SDK_ROOT" ] && [ -n "${SDK_VERSION:-}" ] && [ -x "$SDK_ROOT/bin/$SDK_VERSION/x64/rc.exe" ]; then
    RC="$SDK_ROOT/bin/$SDK_VERSION/x64/rc.exe"
fi
if [ -z "$RC" ] && [ -n "$SDK_ROOT" ]; then
    for _p in "$SDK_ROOT"/bin/*/x64/rc.exe; do [ -x "$_p" ] && { RC="$_p"; break; }; done
fi

MSVC_WIN="$(r3sc_to_windir "${MSVC_ROOT:-}")"
SDK_WIN="$(r3sc_to_windir "${SDK_ROOT:-}")"

# ---- 导出 cl/link 需要的 INCLUDE / LIB ----
#   用法：r3sc_export_msvc_env x64
r3sc_export_msvc_env() {
    local arch="$1"
    [ -n "$MSVC_WIN" ] || { echo "r3sc: MSVC_ROOT 未探测到，无法导出 INCLUDE/LIB" >&2; return 1; }
    [ -n "$SDK_WIN" ]  || { echo "r3sc: SDK_ROOT 未探测到，无法导出 INCLUDE/LIB"  >&2; return 1; }
    export INCLUDE="$MSVC_WIN/include;$SDK_WIN/Include/$SDK_VERSION/ucrt;$SDK_WIN/Include/$SDK_VERSION/shared;$SDK_WIN/Include/$SDK_VERSION/um;$SDK_WIN/Include/$SDK_VERSION/winrt"
    export LIB="$MSVC_WIN/lib/$arch;$SDK_WIN/Lib/$SDK_VERSION/ucrt/$arch;$SDK_WIN/Lib/$SDK_VERSION/um/$arch"
}

# ---- 内核模式：导出 km 头/库（**不含 um**）----
#   ★ 内核 include 顺序：km ; km/crt ; shared ; ucrt —— 绝不能含 um，
#     否则用户态原型（同名不同签名）会与之冲突（铁律 112）。
#   用法：r3sc_export_km_env x64 <WDK_SDK_VERSION>
r3sc_export_km_env() {
    local arch="$1" wdkver="$2" kern="km"
    [ -d "$SDK_ROOT/Include/$wdkver/km/crt" ] && kern="km/crt"
    export INCLUDE="$SDK_WIN/Include/$wdkver/km;$SDK_WIN/Include/$wdkver/$kern;$SDK_WIN/Include/$wdkver/shared;$SDK_WIN/Include/$wdkver/ucrt;$MSVC_WIN/include"
    export LIB="$SDK_WIN/Lib/$wdkver/km/$arch;$MSVC_WIN/lib/$arch"
}

# 可选：打印一次工具链摘要（设 R3SC_QUIET=1 可关）
if [ -z "${R3SC_QUIET:-}" ]; then
    echo "[env] MSVC=${MSVC_ROOT:-未找到}"
    echo "[env] SDK =${SDK_ROOT:-未找到} (${SDK_VERSION:-?})"
    echo "[env] PY  =${PYTHON:-未找到}   GCC=${GCC:-未找到}"
fi
