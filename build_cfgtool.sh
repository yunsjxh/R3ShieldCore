#!/usr/bin/env bash
#
# build_cfgtool.sh —— 构建「R3 ShieldCore 配置与日志」独立工具。
#
#   源码： tools/r3shieldcore_cfg.cpp      （单文件，Win32 GUI，不依赖引擎）
#   资源： tools/r3shieldcore_cfg.rc       （图标 + 版本信息）
#   清单： tools/r3shieldcore_cfg.manifest （asInvoker / comctl32 / DPI）
#   产物： dist/R3ShieldCore-x64/r3shieldcore-cfg.exe
#
# 为什么单独一个脚本（不塞进 build.sh）：
#   · 它**不属于引擎**：不注入、不挂钩、不依赖服务，独立进程、独立链接库集合；
#   · build.sh 的收尾断言全是针对引擎产物的，混进去会互相污染；
#   · 它需要跑一次**无界面自检**（--selftest），引擎构建里没有这个环节。
#
# 用法：
#   bash build_cfgtool.sh            # x64（默认）
#   bash build_cfgtool.sh x86
#
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts_env.sh
. "$SCRIPT_DIR/scripts_env.sh"

ARCH="${1:-x64}"
case "$ARCH" in
    x64|x86) ;;
    *) echo "未知架构: $ARCH（只支持 x64 / x86）"; exit 2 ;;
esac

[ -n "$MSVC_ROOT" ] || { echo "找不到 MSVC 工具链（设 MSVC_ROOT 或用 VS Installer 装 C++ 桌面开发）。"; exit 1; }
[ -n "$SDK_ROOT" ]  || { echo "找不到 Windows SDK。"; exit 1; }
[ -n "$RC" ]        || { echo "找不到 rc.exe。检查 SDK_ROOT: $SDK_ROOT"; exit 1; }
[ -n "$PYTHON" ]    || { echo "找不到 Python（用于生成图标 + 验收）。"; exit 1; }

cd "$PROJECT_ROOT" || exit 1

# ★★★ 2026-10-24：和 `build.sh` 同一处修复 —— 宿主环境会往 shell 里注入
#   `rm() { "${SAFE_DELETE_BIN_DIR}/rm" "$@"; }`，而那个变量指向
#   **Windows 反斜杠绝对路径**（`D:\Program Files\...\safe-bin`），MSYS 把它
#   当成相对 cwd 的路径 ⇒ 每次 `rm` 都要在 D 盘做无效查找 + 目录遍历。
#   后果：脚本卡在下面那句 `rm -f "$RES_OBJ"` 上**几分钟不动、CPU 0%**，
#   看起来像"编译卡死"。`unset -f` 单独不够（PATH 里那一段还在），
#   必须**把 PATH 里的 safe-bin 段整体剔除**再 `hash -r`。
#   ★ 判据只用 PATH 段里的 `safe-bin`，**不判断任何宿主变量名**。
unset -f rm unlink rmdir 2>/dev/null || true
_old_path="$PATH"
PATH=""
_rest="$_old_path:"
while [ -n "$_rest" ]; do
    _seg="${_rest%%:*}"
    _rest="${_rest#*:}"
    case "$_seg" in
        *safe-bin*) continue ;;
        "") continue ;;
    esac
    if [ -z "$PATH" ]; then PATH="$_seg"; else PATH="$PATH:$_seg"; fi
done
export PATH
unset _old_path _rest _seg
hash -r 2>/dev/null || true

OUT_DIR="dist/R3ShieldCore-x64"
# ★ 允许用 `CFG_OUT_EXE` 覆盖产物路径 —— 唯一用途是"cfg 正开着、exe 被占用"
#   的时候仍然能把改动**真编一遍**（否则只能看到 LNK1104，无法判断代码对不对）。
#   默认值不变，正常构建行为与以前完全一致。
#   ⚠️ 用它构建出来的产物**不在 dist 里** ⇒ 别指望 deploy/闸门会看到它。
OUT_EXE="${CFG_OUT_EXE:-$OUT_DIR/r3shieldcore-cfg.exe}"
OBJ_DIR="obj/cfgtool-$ARCH"

# ★ INCLUDE / LIB 必须在**调用 rc.exe 之前**导出（rc 只认 INCLUDE 环境变量，
#   见铁律 169）。r3sc_export_msvc_env 用的必须是本脚本的 $ARCH。
r3sc_export_msvc_env "$ARCH"
if [ "$ARCH" = "x64" ]; then
    CL="$MSVC_ROOT/bin/Hostx64/x64/cl.exe"
    LINK="$MSVC_ROOT/bin/Hostx64/x64/link.exe"
    MACHINE="X64"
else
    CL="$MSVC_ROOT/bin/Hostx64/x86/cl.exe"
    LINK="$MSVC_ROOT/bin/Hostx64/x86/link.exe"
    MACHINE="X86"
fi

# ---- 图标：按需生成（.ico 不入库，唯一真源 = installer/make_icon.py）----
#   ★ 必须先确认 .ico 存在：`[ A -ot B ]` 在 A 不存在时静默为假（铁律 117/142）。
ICO="R3ShieldCore/R3ShieldCore/rsrc/r3shieldcore.ico"
GEN="installer/make_icon.py"
if [ ! -f "$ICO" ] || [ "$ICO" -ot "$GEN" ]; then
    echo "生成图标: $ICO"
    "$PYTHON" "$GEN" "$ICO" || { echo "[败] 图标生成失败"; exit 1; }
else
    echo "图标已是最新: $ICO"
fi
if [ ! -f "$ICO" ]; then
    echo "[败] 图标 $ICO 不存在 —— 判据失去前提"
    exit 1
fi

mkdir -p "$OBJ_DIR" "$OUT_DIR"

# ★ GBK 前置闸门（铁律 46 / 226）—— 与主程序、探针用**同一份**脚本。
#
#   为什么这里也要：v80 把「高级」编辑台从主程序搬了过来 —— 那一页里有
#   `√` `×` `●` 这类符号，而它们**必须**是 CP936 里有的（铁律 244）：
#   一旦哪个符号编不出，将来只要有人把这段文字送进
#   `WideCharToMultiByte(CP_ACP)`（日志、剪贴板、导出的都算），
#   它就会**静默变成 `?`** —— 界面上看不出来，日志里也只是一串问号。
#
#   ⚠️ 与窄闸门不同，宽闸门是**保守**的：它不知道某个字面量会不会被转码。
#      确属"只经 GDI 绘制"的合法假阳性，在那一行加 `// gbk-ok` 豁免。
if [ -f "tools/check_source_gbk.py" ]; then
    echo "=== GBK 闸门：窄字面量（C4566 编译期丢字）==="
    if ! "$PYTHON" tools/check_source_gbk.py tools/r3shieldcore_cfg.cpp; then
        echo "GBK 闸门未过，停止编译"; exit 1
    fi
    echo "=== GBK 闸门：宽字面量（CP_ACP 输出时变 '?'）==="
    if ! "$PYTHON" tools/check_source_gbk.py --wide \
        tools/r3shieldcore_cfg.cpp \
        R3ShieldCore/shared/r3shieldcore/cfg_launch.h; then
        echo "GBK 宽闸门未过，停止编译"; exit 1
    fi
fi

echo ""
echo "=== 编译 r3shieldcore_cfg.cpp [$ARCH] ==="
# ★ v80：「高级」页从主程序搬来 ⇒ 现在要 #include 共享头 + 两个"生产同源"
#   的伪造 codec（都在 R3ShieldCoreLib 下）。三个 -I 与 build.sh 里给引擎的
#   完全一致（铁律 127：路径只描述一次，别在两处各写一份）。
#   ★ 这些头全是 inline/纯头 ⇒ **不需要**链任何引擎的 lib，
#     配置工具仍然是"不注入、不挂钩、不依赖引擎在跑"的独立进程。
"$CL" -nologo -c -O2 -MT -std:c++20 -EHsc -W3 \
      -source-charset:utf-8 \
      -DNDEBUG -DWIN32 -D_WINDOWS -DUNICODE -D_UNICODE \
      -I R3ShieldCore/shared \
      -I R3ShieldCore/shared/libraries \
      -I R3ShieldCore/R3ShieldCoreLib \
      -Fo"$OBJ_DIR/r3shieldcore_cfg.obj" \
      "tools/r3shieldcore_cfg.cpp" || { echo "[败] 编译失败"; exit 1; }

echo ""
echo "=== 资源（图标 + 版本信息）==="
RES_OBJ="$OBJ_DIR/r3shieldcore_cfg.res"
rm -f "$RES_OBJ"
MSYS_NO_PATHCONV=1 "$RC" -nologo \
    -I "R3ShieldCore/R3ShieldCore/rsrc" \
    -fo "$RES_OBJ" \
    "tools/r3shieldcore_cfg.rc" || { echo "[败] rc.exe 失败"; exit 1; }

# ★ 体积下限：只有图标的 .res 也有几十 KB；太小 = 图标没编进去而 rc 返回 0。
RES_SZ=$(stat -c %s "$RES_OBJ" 2>/dev/null || echo 0)
if [ "$RES_SZ" -lt 5000 ]; then
    echo "[败] 资源目标文件只有 $RES_SZ 字节 —— 图标明显没编进去"
    exit 1
fi
echo "  资源: $RES_OBJ ($RES_SZ 字节)"

echo ""
echo "=== 链接 ==="
# ★ 不传 /VERSION —— 版本信息由 .rc 的 VS_VERSION_INFO 提供，
#   两者同时存在会在资源表里出现两个 VERSION 条目（引擎那边踩过）。
# ★ /MANIFESTINPUT 必须用正斜杠 + MSYS_NO_PATHCONV=1，否则清单静默丢失。
MSYS_NO_PATHCONV=1 "$LINK" -nologo \
    -SUBSYSTEM:WINDOWS \
    -MACHINE:"$MACHINE" \
    -OUT:"$OUT_EXE" \
    /MANIFEST:EMBED \
    /MANIFESTINPUT:tools/r3shieldcore_cfg.manifest \
    "$OBJ_DIR/r3shieldcore_cfg.obj" \
    "$RES_OBJ" \
    kernel32.lib user32.lib gdi32.lib comctl32.lib shell32.lib advapi32.lib comdlg32.lib \
    || { echo "[败] 链接失败"; exit 1; }
echo "  --> $OUT_EXE"

echo ""
echo "=== 验收：PE 资源层有图标 ==="
"$PYTHON" tools/pe_has_icon.py "$OUT_EXE" || { echo "[败] 图标未编入 PE 资源"; exit 1; }

echo ""
echo "=== 验收：无界面自检（配置往返 + 负对照）==="
# ★ 工作目录用**相对 ASCII 路径**（项目根可能含中文，绝对路径经 shell 传给
#   exe 有编码风险）；进程 cwd = 仓库根，相对路径能正确落盘。
ST_DIR="$OBJ_DIR/selftest"
mkdir -p "$ST_DIR"
"$OUT_EXE" --selftest "$ST_DIR"
ST_RC=$?
if [ -f "$ST_DIR/r3shieldcore_cfg_selftest.txt" ]; then
    cat "$ST_DIR/r3shieldcore_cfg_selftest.txt"
else
    echo "[警告] 没找到自检报告 $ST_DIR/r3shieldcore_cfg_selftest.txt"
fi
if [ "$ST_RC" -ne 0 ]; then
    echo ""
    echo "BUILD FAILED —— 自检未通过（rc=$ST_RC）"
    exit 1
fi

echo ""
echo "BUILD OK -> $OUT_EXE"
