#!/usr/bin/env bash
#
# 直接驱动 cl.exe / link.exe 构建 R3ShieldCore + R3ShieldCoreLib。
#
# 为什么不用 devenv.com：本机 devenv.com 只会把 IDE 拉起来，不执行命令行构建
# （返回 0、不产出、不写 /Out 日志）。MSBuild.exe 又被安全策略按名字拦截。
# 这里用的还是同一套编译器和同样的参数，产物与 IDE 构建等价。
#
# 关键约束：所有传给编译器的路径必须是相对路径。
# 项目根目录可能带中文，绝对路径传进去有编码风险，
# 所以先 cd 进项目目录，参数里只用相对路径。
#
# 用法：
#   bash build.sh              # Release，x86 + x64
#   bash build.sh Debug        # Debug，x86 + x64
#   bash build.sh Release x64  # 只构建 x64
#
set -u

# ---------------------------------------------------------------------------
#  工具链自动探测 —— 见仓库根的 scripts_env.sh（所有构建脚本共用同一份）
#
#  ★ 本项目原本把 MSVC / Windows SDK / Python 的绝对路径写死在各脚本里，
#    换一台机器就必然编不过。现在统一走 scripts_env.sh 自动探测，可用环境变量覆盖：
#      R3SC_PROJECT_ROOT  MSVC_ROOT  SDK_ROOT  SDK_VERSION  PYTHON  GCC
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts_env.sh
. "$SCRIPT_DIR/scripts_env.sh"

# 本构建脚本的工程目录（源码 + 相对路径基准）
PROJECT_ROOT="$SCRIPT_DIR/R3ShieldCore"
R3SC_SRC_DIR="$PROJECT_ROOT"

[ -n "$MSVC_ROOT" ] || { echo "找不到 MSVC 工具链。请设置 MSVC_ROOT，或用 VS Installer 安装『使用 C++ 的桌面开发』。"; exit 1; }
[ -n "$SDK_ROOT" ]  || { echo "找不到 Windows SDK。请设置 SDK_ROOT 指向 Windows Kits/10。"; exit 1; }
[ -n "${SDK_VERSION:-}" ] || { echo "在 $SDK_ROOT/Include/ 下找不到任何 SDK 版本。"; exit 1; }
[ -n "$RC" ]        || { echo "找不到 rc.exe（资源编译器）。检查 SDK_ROOT: $SDK_ROOT"; exit 1; }
PYICON="$PYTHON"
[ -n "$PYICON" ]    || { echo "找不到 Python —— 无法生成图标。请安装 Python 3 或设置 PYTHON。"; exit 1; }

echo "工具链: MSVC=$MSVC_ROOT"
echo "        SDK =$SDK_ROOT ($SDK_VERSION)"
echo "        RC  =$RC"
echo "        PY  =$PYICON"

# 产品版本 —— 同时用于资源版本信息（link 的 /VERSION）。
# ★ 只写在这里一处，避免"装的是 v65、关于对话框写 v64"这类漂移。
#
# ★★ 格式陷阱（实测踩到两次，两种写法都错）：
#    ① "/VERSION:65.0.0.0"  → LNK1117 语法错误（不认点分）
#    ② "/VERSION:65,0,0,0"  → LNK4056 "已忽略选项的额外参数"
#       原因：逗号在 link 命令行里是**参数分隔符**，被 shell 传进去后
#       link 把 "0,0,0" 当成**后续参数**丢掉了 —— 所以版本号只会是 65.0。
#    正解：版本号的每段用**点**连、但整体当作**一个**参数时，link 要的是
#        "/VERSION:major.minor" 形式（只接受两段）——
#    本项目其实只需要给一个"有版本信息"的 exe，最稳的写法是
#    直接用 **/VERSION:65.0**（两段，无逗号，不会被拆参）。
#    ★ 而 .rc 里的 FILEVERSION 才是四段点分写法（那是另一种语法）。
PRODUCT_VERSION="65.0"

CONFIG="${1:-Release}"
ONLY_ARCH="${2:-}"

cd "$PROJECT_ROOT" || { echo "找不到项目目录: $PROJECT_ROOT"; exit 1; }

FAILED=0

setup_toolchain() {
    local arch="$1"

    # ★★ INCLUDE 必须**显式**导出：不只是 cl.exe 用，
    #    rc.exe 也要靠它找 winresrc.h / windows.h。
    #    踩过：rc.exe 单独跑时报 `RC1015: cannot open include file 'winresrc.h'`
    #    —— 因为 rc.exe 不认 cl 的 -I 之外的"默认搜索路径"，
    #    它只看 INCLUDE 环境变量。少这一条 ⇒ 资源编不出来 ⇒
    #    .res 文件根本不存在 ⇒ link 拿不到 RES_OBJ（而 link **不报错**，
    #    只是图标没了）。这正是"构建报绿但图标是空白"的根源。
    r3sc_export_msvc_env "${ARCH:-x64}"
    if [ "$arch" = "x64" ]; then
        CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
        LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"
        DUMPBIN="$MSVC_ROOT/bin/Hostx64/x64/dumpbin.exe"
        MACHINE="X64"
    else
        CL="$MSVC_ROOT/bin/Hostx64/x86/cl.exe"
        LINK="$MSVC_ROOT/bin/Hostx64/x86/link.exe"
        DUMPBIN="$MSVC_ROOT/bin/Hostx64/x86/dumpbin.exe"
        MACHINE="X86"
    fi
}

compile_all() {
    local objdir="$1"
    shift

    mkdir -p "$objdir"
    local objects=()

    for source in "$@"; do
        local name
        name="$(basename "$source" .cpp)"
        local object="$objdir/$name.obj"

        # -source-charset:utf-8 必须有：源文件是 UTF-8，而中文系统上 cl 默认按
        # CP936 解码，注释里的全角标点会吃掉换行符、把下一行代码吞进注释。
        # 只改 source charset，不动 execution charset —— 这样窄字符串里的中文
        # 仍按系统 ANSI 编码生成，控制台能正常显示。
        "$CL" -nologo -c -O2 -MT -std:c++20 -EHsc -W3 \
            -source-charset:utf-8 \
            -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE \
            "${EXTRA_INCLUDES[@]}" \
            -Fo"$object" \
            "$source" || return 1

        objects+=("$object")
    done

    COMPILED_OBJECTS=("${objects[@]}")
    return 0
}

build_lib() {
    local arch="$1"
    local archdir
    [ "$arch" = "x64" ] && archdir="64" || archdir="32"

    echo ""
    echo "=== R3ShieldCoreLib [$CONFIG|$arch] ==="

    setup_toolchain "$arch"

    if [ "$CONFIG" = "Debug" ]; then
        MINHOOK="R3ShieldCoreLib/libraries/MinHook/libMinHook.d.$arch.lib"
    else
        MINHOOK="R3ShieldCoreLib/libraries/MinHook/libMinHook.$arch.lib"
    fi

    EXTRA_INCLUDES=(
        -I R3ShieldCoreLib/libraries
        -I shared
        -I shared/libraries
    )

    local sources=(
        R3ShieldCoreLib/all_processes_injector.cpp
        R3ShieldCoreLib/camera_guard.cpp
        R3ShieldCoreLib/clipboard_guard.cpp
        R3ShieldCoreLib/com_hijack_guard.cpp
        R3ShieldCoreLib/customization_session.cpp
        R3ShieldCoreLib/dll_inject.cpp
        R3ShieldCoreLib/dll_load_guard.cpp
        R3ShieldCoreLib/driver_guard.cpp
        R3ShieldCoreLib/file_guard.cpp
        R3ShieldCoreLib/functions.cpp
        R3ShieldCoreLib/host_hijack_guard.cpp
        R3ShieldCoreLib/inject_policy.cpp
        R3ShieldCoreLib/input_hook_guard.cpp
        R3ShieldCoreLib/logger.cpp
        R3ShieldCoreLib/main.cpp
        R3ShieldCoreLib/network_guard.cpp
        R3ShieldCoreLib/new_process_injector.cpp
        R3ShieldCoreLib/process_guard.cpp
        R3ShieldCoreLib/r3shieldcore_channel.cpp
        R3ShieldCoreLib/r3shieldcore_log.cpp
        R3ShieldCoreLib/r3shieldcore_prompt.cpp
        R3ShieldCoreLib/r3shieldcore_prompt_ui.cpp
        R3ShieldCoreLib/r3shieldcore_rules.cpp
        R3ShieldCoreLib/r3shieldcore_toast.cpp
        R3ShieldCoreLib/registry_guard.cpp
        R3ShieldCoreLib/scheduled_task_guard.cpp
        R3ShieldCoreLib/screen_guard.cpp
        R3ShieldCoreLib/service_config_guard.cpp
        R3ShieldCoreLib/session_private_namespace.cpp
        R3ShieldCoreLib/spawn_guard.cpp
        R3ShieldCoreLib/token_theft_guard.cpp
        R3ShieldCoreLib/wmi_subscription_guard.cpp
    )

    # wow64ext 只在 32 位构建里编（与 vcxproj 的 ExcludedFromBuild 一致）
    if [ "$arch" = "x86" ]; then
        sources+=(R3ShieldCoreLib/libraries/wow64ext/wow64ext.cpp)
    fi

    compile_all "obj/$arch" "${sources[@]}" || { FAILED=1; return 1; }

    mkdir -p "$CONFIG/$archdir"

    # comctl32 v6 才有 TaskDialogIndirect（询问弹窗的四按钮）。
    # 没有这个 manifest 依赖，加载到的是 v5，只能退回 MessageBox。
    #
    # 注意：这两个选项必须用正斜杠。用 "-MANIFEST" 时 link 不报错，
    # 但产物里根本没有资源区，manifest 静默丢失（实测确认）。
    # 所以这里临时关掉 MSYS 的路径转换。
    MSYS_NO_PATHCONV=1 "$LINK" -nologo -DLL \
        -DEF:R3ShieldCoreLib/_exports.def \
        -SUBSYSTEM:WINDOWS \
        -MACHINE:"$MACHINE" \
        -OUT:"$CONFIG/$archdir/r3shieldcore-lib.dll" \
        /MANIFEST:EMBED \
        "/MANIFESTDEPENDENCY:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'" \
        "${COMPILED_OBJECTS[@]}" \
        "$MINHOOK" \
        kernel32.lib user32.lib gdi32.lib advapi32.lib wtsapi32.lib ntdll.lib shell32.lib ole32.lib oleaut32.lib comctl32.lib uuid.lib taskschd.lib wintrust.lib crypt32.lib \
        || { FAILED=1; return 1; }

    echo "--> $CONFIG/$archdir/r3shieldcore-lib.dll"
    return 0
}

make_icon_on_demand() {
    # ★ 图标是按需生成的：rsrc/r3shieldcore.ico 不进版本库，
    #   每次构建都用 installer/make_icon.py 重画一遍（纯 Python，无依赖，< 1 秒）。
    #   为什么不在生成器旁边直接放一份 .ico：那样会分叉 ——
    #   生成器改了、.ico 没重跑，产物用的是旧图标而没人发现。
    #   按需生成 = 永远只有一个真源（make_icon.py）。
    #
    # ★ 陈本判定：只有 .ico 比 make_icon.py 旧才重画 —— 但**必须**先确认
    #   .ico 存在：`[ A -ot B ]` 在 A 不存在时静默为假（铁律 142/117），
    #   少了这个前提检查，"图标没生成"会变成"构建报绿但产物没图标"。
    local ico="R3ShieldCore/rsrc/r3shieldcore.ico"
    local gen="../installer/make_icon.py"
    if [ ! -f "$ico" ] || [ "$ico" -ot "$gen" ]; then
        echo "  生成图标: $ico"
        "$PYICON" "$gen" "$ico" || { FAILED=1; return 1; }
    else
        echo "  图标已是最新: $ico"
    fi
    return 0
}

build_demo() {
    local arch="$1"
    local outName="$2"

    echo ""
    echo "=== R3ShieldCore [$CONFIG|$arch] -> $outName ==="

    setup_toolchain "$arch"

    EXTRA_INCLUDES=(
        -I shared
        -I shared/libraries
    )

    local sources=(
        R3ShieldCore/app.cpp
        R3ShieldCore/ark_actions.cpp
        R3ShieldCore/engine_control.cpp
        R3ShieldCore/functions.cpp
        R3ShieldCore/r3shieldcore_ark.cpp
        R3ShieldCore/r3shieldcore_config.cpp
        R3ShieldCore/r3shieldcore_gui.cpp
        R3ShieldCore/r3shieldcore_log_replay.cpp
        R3ShieldCore/r3shieldcore_procwatch.cpp
        R3ShieldCore/r3shieldcore_sentinel.cpp
        R3ShieldCore/r3shieldcore_stats.cpp
        R3ShieldCore/r3shieldcore_superdesk.cpp
    )

    compile_all "obj/demo-$arch" "${sources[@]}" || { FAILED=1; return 1; }

    mkdir -p "$CONFIG"

    # ---------------------------------------------------------------------
    # 资源：图标（rsrc/r3shieldcore.rc → .res）
    #   ★ 没有这一步时引擎 exe 里**一个资源区都没有** —— 资源管理器、
    #     窗口标题栏、任务栏、Alt+Tab 四处全是系统的空白默认图标。
    #   ★ 用 SDK 的 rc.exe（不是 windres）：rc.exe 是 Unicode 程序，
    #     能直接处理带中文的项目根路径，不需要纯 ASCII 暂存目录这一步。
    #   ★ 开关必须用**正斜杠** + MSYS_NO_PATHCONV=1 —— 反斜杠形式的 /fo
    #     会被 MSYS 当路径改写，rc.exe 拿到的输出路径就变了（本项目在
    #     link 的 /MANIFEST 上已实测过这个坑）。
    # ---------------------------------------------------------------------
    local RES_OBJ="obj/demo-$arch/r3shieldcore.res"
    mkdir -p "obj/demo-$arch"
    rm -f "$RES_OBJ"
    # ★ 先确认图标真的在（make_icon_on_demand 已保证，这里做交付级断言）
    if [ ! -f "R3ShieldCore/rsrc/r3shieldcore.ico" ]; then
        echo "  [败] 图标 R3ShieldCore/rsrc/r3shieldcore.ico 不存在"
        FAILED=1; return 1
    fi
    MSYS_NO_PATHCONV=1 "$RC" -nologo \
        -I "R3ShieldCore/rsrc" \
        -fo "$RES_OBJ" \
        "R3ShieldCore/rsrc/r3shieldcore.rc" \
        || { FAILED=1; return 1; }
    # ★ 体积下限：只有图标的 .res 也有 ~100KB（7 张位图）。
    #   几十字节 = 资源根本没编进去而 rc 返回 0（空资源也"成功"）。
    local res_sz
    res_sz=$(stat -c %s "$RES_OBJ" 2>/dev/null || echo 0)
    if [ "$res_sz" -lt 5000 ]; then
        echo "  [败] 资源目标文件只有 $res_sz 字节 —— 图标明显没编进去"
        FAILED=1; return 1
    fi
    echo "  资源: $RES_OBJ ($res_sz 字节)"

    # ⚠️ 引擎 exe 用**自己的清单**（rsrc/r3shieldcore-uac.manifest），不是 link 默认的。
    #
    #    提权（requireAdministrator）用 /MANIFESTUAC 生成 ——
    #    **不能**写进清单文件里：link 自己也会生成一段 trustInfo，
    #    两边都有 mt.exe 就报
    #      "manifest authoring error c1010001:
    #       Values of attribute \"level\" not equal in different manifest snippets"
    #    （LNK1327）。这是实测踩到的坑。
    #
    #    ⚠️ 一个 exe 只能有一个 application manifest，所以这边**不再**用
    #       /MANIFESTDEPENDENCY 追加 comctl32 —— 那条已经在 r3shieldcore-uac.manifest
    #       里以 <dependency> 形式写了。
    #
    #    ⚠️ /MANIFESTINPUT 必须用正斜杠 —— 写 "-MANIFESTINPUT:" 时 link 不报错
    #       但清单静默丢失（本项目在 /MANIFEST 上已实测过这个坑）。
    #
    #    ⚠️ R3SHIELDCORE_NO_UAC=1（**仅供本地自动化验证**）：
    #       带 requireAdministrator 的 exe 在**非提权会话**里根本创建不出来
    #       （bash/cmd 直接 Permission denied —— 这是 UAC 的正确行为，
    #        但也让"跑探针 → 看引擎日志"的自动化链路断了）。
    #       置这个变量时**不带 /MANIFESTUAC**，编出的是同样代码、同样 hook、
    #       只少了提权要求的验证专用 exe。**正式发布绝不要带它。**
    #
    #    ★ v30 曾把这里改成 highestAvailable（不强制管理员），
    #      **2026-10-01 已回退** —— 不提权时引擎大面积失效，实用价值不足。
    #      详见 docs/HANDOVER.md §3.10l。
    local manifestArgs=(
        /MANIFEST:EMBED
        /MANIFESTINPUT:R3ShieldCore/rsrc/r3shieldcore-uac.manifest
    )
    if [ -z "${R3SHIELDCORE_NO_UAC:-}" ]; then
        manifestArgs+=( "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" )
    else
        echo "  [R3SHIELDCORE_NO_UAC=1] 本 exe 不带提权清单（仅用于本地验证）"
    fi

    # ⚠️ 必须是 WINDOWS，**不能**是 CONSOLE —— app.cpp 的入口是 `wWinMain`。
    #    写 CONSOLE 时 CRT 会去找 `main`，链接直接失败：
    #      LNK2019: 无法解析的外部符号 main
    #      (LIBCMT.lib(exe_main.obj) 引用)
    #    而且 link 失败会**把上一次的 exe 删掉** —— 本项目实测：编译一次
    #    Release/R3 ShieldCore.exe 就凭空消失了，很容易误判成"代码坏了"。
    #
    #    printf 诊断不依赖控制台：app.cpp 开头就 RedirectDiagnosticsToFile()
    #    把 stdout/stderr 重定向到 r3shieldcore-console.log 了（父引擎和 UIAccess
    #    子实例共享同一份，用 _SH_DENYNO 打开）。
    #
    # ★ 资源 .res 要跟在对象文件一起喂给 link。**顺序无所谓**，但不能漏 ——
    #   漏了不会有任何报错，只是图标又变回空白（静默失败）。
    MSYS_NO_PATHCONV=1 "$LINK" -nologo \
        -SUBSYSTEM:WINDOWS \
        -MACHINE:"$MACHINE" \
        -OUT:"$CONFIG/$outName" \
        "/VERSION:$PRODUCT_VERSION" \
        "${manifestArgs[@]}" \
        "${COMPILED_OBJECTS[@]}" \
        "$RES_OBJ" \
        kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib comctl32.lib psapi.lib \
        || { FAILED=1; return 1; }

    echo "--> $CONFIG/$outName"
    return 0
}

# 开机启动服务（service/r3shieldcore_svc.c）。
#
# ★ 它**只**把引擎拉进交互会话，不做自保护、不做看门狗 —— 是"启动器"不是防护组件。
# ★ 单独一个 build 函数而不是塞进 build_demo：它是独立进程、独立子系统
#   （CONSOLE）、独立 lib 集合，混在一起以后加开关会互相污染。
# ★ 只编 x64：服务是给 64 位 Windows 用的。引擎的 32 位产物是给"注入 32 位
#   目标进程"用的，跟服务无关。
build_svc() {
    local arch="$1"

    echo ""
    echo "=== R3ShieldCore boot-autostart service [$CONFIG|$arch] ==="

    setup_toolchain "$arch"

    mkdir -p "obj/svc-$arch"

    # 纯 C，不复用 compile_all：那个函数带 -std:c++20 / -EHsc，
    # 对 .c 文件只会刷一堆 D9002"忽略未知选项"，把真警告埋掉。
    # ★ 路径基准是 R3ShieldCore/（本脚本开头就 cd 到这里），服务源码在**仓库根**
    #   的 service/ 下，所以要 ../service/...。
    #   踩过：写成 service/r3shieldcore_svc.c 时 cl 报
    #     c1: fatal error C1083: 无法打开源文件
    #   而构建脚本自己的收尾断言才把它抓住（否则就是"构建 OK 但没产物"）。
    "$CL" -nologo -c -O2 -MT -W3 \
        -source-charset:utf-8 \
        -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE \
        -Fo"obj/svc-$arch/r3shieldcore_svc.obj" \
        "../service/r3shieldcore_svc.c" || { FAILED=1; return 1; }

    mkdir -p "$CONFIG"

    # ★ CONSOLE 子系统（**不是** WINDOWS）：
    #   --selftest / --console 要能往终端打印。被 SCM 拉起时本来就没有控制台，
    #   printf 静默失败无害，真正的诊断走 r3shieldcore-svc.log。
    MSYS_NO_PATHCONV=1 "$LINK" -nologo \
        -SUBSYSTEM:CONSOLE \
        -MACHINE:"$MACHINE" \
        -OUT:"$CONFIG/r3shieldcore_svc.exe" \
        "obj/svc-$arch/r3shieldcore_svc.obj" \
        advapi32.lib wtsapi32.lib userenv.lib kernel32.lib user32.lib \
        || { FAILED=1; return 1; }

    echo "--> $CONFIG/r3shieldcore_svc.exe"
    return 0
}

echo "Config: $CONFIG   Arch: ${ONLY_ARCH:-x86+x64}"

# ★ 图标：编任何东西之前先生成，两个架构共用同一份 .ico。
#   放在最前面是因为它同时被 x86/x64 两个 build_demo 用 —— 放在 build_demo
#   里会被调两次（第二次虽然会被"已是最新"挡掉，但日志会重复一遍）。
echo ""
echo "=== 0/3 图标 ==="
make_icon_on_demand

if [ -z "$ONLY_ARCH" ] || [ "$ONLY_ARCH" = "x86" ]; then
    build_lib x86
fi

if [ -z "$ONLY_ARCH" ] || [ "$ONLY_ARCH" = "x64" ]; then
    build_lib x64
fi

# 引擎 exe 两个架构都编：
#   32 位版（README 的默认）—— 但注入 64 位进程时 VirtualAllocEx 只能拿到
#                              目标 4GB 以下的地址，Chromium 系应用会失败
#   64 位版                  —— 没有这个限制，推荐用它
#
# ★★★【坑】产物名里**有空格**（"R3 ShieldCore.exe"）。
#     这里必须**加引号**：不加时 shell 会把参数拆成两个，
#     build_demo 收到 $2="R3"、$3="ShieldCore.exe"，
#     产物名静默变成 `R3`（实测：BUILD OK 但 Release/ 下只有个叫 R3 的文件）。
if [ -z "$ONLY_ARCH" ] || [ "$ONLY_ARCH" = "x86" ]; then
    build_demo x86 "R3 ShieldCore-x86.exe"
fi

if [ -z "$ONLY_ARCH" ] || [ "$ONLY_ARCH" = "x64" ]; then
    build_demo x64 "R3 ShieldCore.exe"
fi

# 开机启动服务：只编 x64（ONLY_ARCH=x86 时明确跳过，并说明原因，
# 免得看构建日志的人以为"漏编了"）。
if [ -z "$ONLY_ARCH" ] || [ "$ONLY_ARCH" = "x64" ]; then
    build_svc x64
else
    echo ""
    echo "  [跳过] 开机启动服务（x64 专用；本次 ONLY_ARCH=$ONLY_ARCH）"
fi

# ★ 收尾断言：产物名必须**一字不差**。名字里带空格时，
#   任何一处漏引号都会静默产出错误名字的文件，所以这里硬校验一次。
EXPECT_EXE="$PROJECT_ROOT/Release/R3 ShieldCore.exe"
if [ ! -f "$EXPECT_EXE" ]; then
    echo ""
    echo "!!! 断言失败：没有产出 '$EXPECT_EXE'"
    echo "    最常见原因 = 某个脚本里 exe 名漏了引号（名字带空格）。"
    ls -1 "$PROJECT_ROOT/Release/" 2>/dev/null | sed 's/^/      Release\//'
    FAILED=1
fi

# ★ 服务产物同样断言：安装包会把它和引擎一起装进同一个目录，
#   少了它 => 开机自启那步会**静默失败**（服务注册指向不存在的文件）。
#
# ★★ 但"存在"**不够** —— 必须同时是**新的**（铁律 119）。
#    踩过（v65c）：链接步骤失败（缺 user32.lib）时，Release/ 下**上一次**构建
#    留下的旧 exe 还在 ⇒ 只查"存在"的断言照样通过、照样打 BUILD OK；
#    而那个旧 exe 是**加安全模式闸门之前**编的 —— 于是 dist 里发布的服务
#    二进制**根本不含安全模式逻辑**，而所有闸门全绿（check_dist_sync 只比
#    dist 与 Release，两个都是旧的，正好相等）。
#    ⇒ 判据要跟源码比时间：产物比源码旧 = 产物不是本次构建出来的。
EXPECT_SVC="$PROJECT_ROOT/Release/r3shieldcore_svc.exe"
# ★ 服务源码在**仓库根**的 service/ 下，而 PROJECT_ROOT 是 R3ShieldCore/
#   —— 所以是 ../service/...（和 build_svc 里 cl 用的相对路径一致）。
SVC_SRC="$PROJECT_ROOT/../service/r3shieldcore_svc.c"
if [ -z "$ONLY_ARCH" ] || [ "$ONLY_ARCH" = "x64" ]; then
    # ★★ 判据**自己也要有前提**：`[ A -ot B ]` 在 B 不存在时**静默为假**
    #    ⇒ 源码路径写错 = 断言永远绿（铁律 117：声明的根必须存在，否则 FAIL）。
    #    踩过：第一版写成 "$PROJECT_ROOT/service/..."（少了个 ../），
    #    负对照（故意把产物改成 1 天前）居然还是 BUILD OK —— 才发现判据没生效。
    if [ ! -f "$SVC_SRC" ]; then
        echo ""
        echo "!!! 断言失败：服务源码 '$SVC_SRC' 不存在 ——"
        echo "    新鲜度判据失去前提（比较一个不存在的文件会静默为假）。"
        FAILED=1
    elif [ ! -f "$EXPECT_SVC" ]; then
        echo ""
        echo "!!! 断言失败：没有产出 '$EXPECT_SVC'"
        ls -1 "$PROJECT_ROOT/Release/" 2>/dev/null | sed 's/^/      Release\//'
        FAILED=1
    elif [ "$EXPECT_SVC" -ot "$SVC_SRC" ]; then
        echo ""
        echo "!!! 断言失败：'$EXPECT_SVC' 比源码 '$SVC_SRC' 还旧 ——"
        echo "    说明链接没成功，这个产物是**上一次**构建留下的（旧产物会假绿）。"
        FAILED=1
    fi
fi

# 图标：用 **PE 资源目录**直接验证（见 tools/pe_has_icon.py 的说明）。
# ★★ 为什么不能用"产物里有 .rsrc 段"当判据：
#    link 带 /MANIFEST:EMBED 时**总会**建一个 .rsrc 来装 manifest，
#    所以"有 .rsrc"恒为真 —— 典型的空真判据（铁律 110）。
#    也不能 grep "RT_ICON"：资源表里存的是**数字 ID**（3 / 14），
#    根本没有这个字符串。
# ★ 真判据 = 资源类型层里同时有 3(RT_ICON) 和 14(RT_GROUP_ICON)。
PE_ICON_CHK="$PROJECT_ROOT/../tools/pe_has_icon.py"
if [ ! -f "$PE_ICON_CHK" ]; then
    echo ""
    echo "!!! 断言失败：图标检查器 '$PE_ICON_CHK' 不存在（判据失去前提）"
    FAILED=1
else
    for pair in "Release/R3 ShieldCore.exe|引擎 x64" "Release/R3 ShieldCore-x86.exe|引擎 x86"; do
        f="${pair%%|*}"; label="${pair##*|}"
        full="$PROJECT_ROOT/$f"
        if [ ! -f "$full" ]; then
            echo "  [跳过] $label：本次未编（$f 不存在）"
            continue
        fi
        if "$PYICON" "$PE_ICON_CHK" "$full"; then
            echo "  OK  $label：图标资源已编入"
        else
            rc=$?
            if [ "$rc" = "2" ]; then
                echo "  [败] $label：资源目录里没有 ICON —— 图标没编进去"
            else
                echo "  [败] $label：图标检查执行失败（rc=$rc）"
            fi
            FAILED=1
        fi
    done
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "BUILD OK"
else
    echo "BUILD FAILED (see errors above)"
fi

exit "$FAILED"
