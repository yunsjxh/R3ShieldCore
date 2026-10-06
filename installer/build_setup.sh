#!/usr/bin/env bash
#
# build_setup.sh —— 用 MSYS2 的 gcc + windres 构建**原生图形安装程序**
#                   `dist/R3ShieldCore-Setup.exe`。
#
# 为什么不再用 iexpress
# ====================
# 老的 build_installer.sh 是 iexpress 自解压 + 批处理。它能用，但有四个
# 改不掉的硬伤（前三个都在 v65 真机验证时踩到过，详见 docs/HANDOVER 附录 K）：
#   1. AppLaunched 指向 .bat 会被 wextract 改写成 `Command.com /c x.bat`，
#      而 64 位 Windows 没有 command.com ⇒ **双击什么都不装**；
#      而且参数会被静默丢弃、构建期完全正常。
#   2. iexpress 不支持子目录 ⇒ 必须打 payload.zip 再靠外部 tar.exe 解。
#   3. 解压目录归 wextract 管，它会在被拉起的进程退出后删掉整个目录 ⇒
#      自我提权必须 -Wait，否则随机"装到一半"。
#   4. 批处理的中文 + CRLF + 括号块 + %VAR% 展开时机，全是静默陷阱。
#
# 本脚本产出的是**一个自包含的原生 PE**：payload 全部作为 RCDATA 编进去，
# 提权走 manifest 的 requireAdministrator，解压/装驱动/建快捷方式/写注册表
# 全在自己代码里 —— 没有外部依赖，没有批处理解析，没有 wextract 竞态。
#
# 用法
# ====
#   bash installer/build_setup.sh              # 构建
#   bash installer/build_setup.sh --no-copy    # 只构建，不拷回 dist/
#   bash installer/build_setup.sh --res-only   # 只生成 payload 资源（调试用）
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
cd "$PROJECT_ROOT" || exit 1

INST_DIR="installer"
DIST_DIR="dist"
OUT_NAME="R3ShieldCore-Setup.exe"
OUT_EXE="$PROJECT_ROOT/$DIST_DIR/$OUT_NAME"

PY="$PYTHON"   # 由 scripts_env.sh 自动探测（见文件头）
# ★ 工具链：MSYS2 ucrt64。windres/objdump 与 gcc 同目录，所以从 $GCC 推导，
#   不写死 /d/msys64/...（换机器/换安装位置就编不了）。可用 WINDRES/OBJDUMP 覆盖。
if [ -n "${GCC:-}" ]; then
    _gccdir="$(dirname "$GCC")"
    WINDRES="${WINDRES:-$_gccdir/windres.exe}"
    OBJDUMP="${OBJDUMP:-$_gccdir/objdump.exe}"
else
    WINDRES="${WINDRES:-}"
    OBJDUMP="${OBJDUMP:-}"
fi

MODE="${1:-build}"

# ---------------------------------------------------------------------------
# 1/6 预检
# ---------------------------------------------------------------------------
echo "=== 1/6 预检 ==="
FAILED=0
for t in "$GCC" "$WINDRES"; do
    if [ ! -x "$t" ]; then
        echo "  [缺] $t"
        echo "       需要 MSYS2 的 ucrt64 工具链。装法：pacman -S mingw-w64-ucrt-x86_64-gcc"
        FAILED=1
    fi
done
for f in "$INST_DIR/r3sc_setup.c" "$INST_DIR/r3sc_setup.rc" \
         "$INST_DIR/setup.manifest" "$INST_DIR/gen_payload_rc.py" \
         "$INST_DIR/make_icon.py" "$INST_DIR/uninstall.bat"; do
    if [ ! -f "$f" ]; then
        echo "  [缺] $f"
        FAILED=1
    fi
done
if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "预检失败 —— 先把上面缺的东西补齐。"
    exit 1
fi
echo "  OK（gcc + windres + 源码 + manifest + 卸载脚本）"

# ---------------------------------------------------------------------------
# 2/6 准备纯 ASCII 暂存目录
#   ★★★ 这一步不能省 ★★★
#   windres 是 ANSI 程序，读 .rc 里的路径走**窄字符 fopen**。
#   本项目根目录可能带中文，直接把 .rc 放在这儿编，
#   windres 拿 UTF-8 的路径去调 CP936 的 fopen ⇒ 找不到文件，
#   或者更糟：编出一个**空资源**而构建报成功。
#   所以所有编译输入都复制到 %TEMP% 下的纯 ASCII 目录里再编。
# ---------------------------------------------------------------------------
echo ""
echo "=== 2/6 准备暂存目录（纯 ASCII）==="
TMP="$("$PY" -c "import os,tempfile;print(os.path.join(tempfile.gettempdir(),'r3sc-setup-build'))")"
# 转成 MSYS 风格给 bash 用
TMP_SH="$("$PY" -c "import os;print(os.path.abspath(r'$TMP').replace(chr(92),'/'))")"
# 转成 Windows 风格给 gcc/windres 用（它们自己认，但显式给更稳）
TMP_WIN="$("$PY" -c "import os;print(os.path.abspath(r'$TMP').replace('/', chr(92)))")"

case "$TMP" in
    *[!\ -~]*) echo "  [败] 暂存目录含非 ASCII 字符：$TMP"; exit 1 ;;
esac

mkdir -p "$TMP_SH"
echo "  暂存目录 : $TMP"

# ---------------------------------------------------------------------------
# 3/6 生成 payload 资源
# ---------------------------------------------------------------------------
echo ""
echo "=== 3/6 生成 payload 资源 ==="
if ! "$PY" "$INST_DIR/gen_payload_rc.py" "$TMP" ; then
    echo "  [败] gen_payload_rc.py 失败"
    exit 1
fi

# 图标
if ! "$PY" "$INST_DIR/make_icon.py" "$TMP_WIN\\app.ico" ; then
    echo "  [败] make_icon.py 失败"
    exit 1
fi

if [ "$MODE" = "--res-only" ]; then
    echo ""
    echo "资源已生成在 $TMP（--res-only，未编译）"
    exit 0
fi

# ---------------------------------------------------------------------------
# 4/6 复制源码到暂存目录
#   ★ 用绝对路径的 Windows 形式传给 gcc/windres，避免 MSYS 的路径转换
#     把开关吃掉（铁律 113：`/` 开头的参数会被当路径改写）。
# ---------------------------------------------------------------------------
echo ""
echo "=== 4/6 复制源码到暂存目录 ==="
cp -f "$INST_DIR/r3sc_setup.c"    "$TMP_SH/r3sc_setup.c"
cp -f "$INST_DIR/r3sc_setup.rc"   "$TMP_SH/r3sc_setup.rc"
cp -f "$INST_DIR/setup.manifest"  "$TMP_SH/setup.manifest"
echo "  OK"

# ---------------------------------------------------------------------------
# 5/6 编译
# ---------------------------------------------------------------------------
echo ""
echo "=== 5/6 编译 ==="
RES_OBJ="$TMP_WIN\\app.res.o"
SRC_C="$TMP_WIN\\r3sc_setup.c"
RC_FILE="$TMP_WIN\\r3sc_setup.rc"
TMP_EXE="$TMP_WIN\\$OUT_NAME"

echo "  [1/2] windres 编译资源（-c 65001：必须！见文件头）..."
rm -f "$TMP_SH/app.res.o"
if ! ( cd "$TMP_SH" && MSYS_NO_PATHCONV=1 "$WINDRES" -c 65001 -O coff \
        -o "$RES_OBJ" "$RC_FILE" ) ; then
    echo "  [败] windres 失败"
    echo "       排查：① 是不是漏了 -c 65001？② payload.rc 里的路径存在吗？"
    exit 1
fi
RES_SIZE=$(stat -c %s "$TMP_SH/app.res.o")
echo "        资源目标文件 $RES_SIZE 字节"
# ★ 资源目标文件太小 = 根本没编进 payload（空资源也会"成功"）
if [ "$RES_SIZE" -lt 800000 ]; then
    echo "  [败] 资源目标文件只有 $RES_SIZE 字节 —— payload 明显没编进去。"
    echo "       检查 $TMP_SH/payload.rc 里引用的 _res/*.bin 是否真的存在。"
    exit 1
fi

echo "  [2/2] gcc 链接..."
rm -f "$TMP_SH/$OUT_NAME"
MSYS_NO_PATHCONV=1 "$GCC" \
    -O2 -municode -mwindows -static -s \
    -finput-charset=UTF-8 -fexec-charset=UTF-8 -fwide-exec-charset=UTF-16LE \
    -Wall \
    -o "$TMP_EXE" \
    "$SRC_C" "$RES_OBJ" \
    -lcomctl32 -lshell32 -lole32 -luuid -lshlwapi -ladvapi32 \
    -luser32 -lgdi32 -lkernel32 -lz
if [ ! -f "$TMP_SH/$OUT_NAME" ]; then
    echo "  [败] gcc 没产出 exe"
    exit 1
fi
SIZE=$(stat -c %s "$TMP_SH/$OUT_NAME")
echo "        产物 $SIZE 字节"

# ---------------------------------------------------------------------------
# 6/6 产物自检 + 拷回 dist/
#   ★ 只看"编译成功"是不够的：资源编漏了照样能链接成功。
#     必须用 objdump 看**资源表里到底有没有** RT_RCDATA 和 RT_MANIFEST。
# ---------------------------------------------------------------------------
echo ""
echo "=== 6/6 产物自检 ==="

if ! head -c 2 "$TMP_SH/$OUT_NAME" | grep -q "MZ"; then
    echo "  [败] 产物不是合法 PE"
    exit 1
fi
echo "  OK  PE 头"

# ★ 不要用 `grep RT_RCDATA` 去查资源表 —— MinGW 的 objdump 在资源表里打的是
#   **数字 ID**（3=ICON 10=RCDATA 14=GROUP_ICON 16=VERSION 24=MANIFEST），
#   根本不会出现 "RT_RCDATA" 这个字符串。
#   踩过：检查写错 ⇒ 明明资源编进去了，却报"资源表为空"，白排查一轮。
#   正确判据是 Type Table 那一行的 `IDs: N`（= 资源类型个数）。
if [ -x "$OBJDUMP" ]; then
    RSRC="$("$OBJDUMP" -x "$TMP_SH/$OUT_NAME" 2>/dev/null)"
    TYPE_LINE="$(echo "$RSRC" | grep -m1 "Type Table")"
    if [ -z "$TYPE_LINE" ]; then
        echo "  [败] 产物里没有 .rsrc 资源目录"
        FAILED=1
    else
        echo "  OK  资源表：$TYPE_LINE"
        N_TYPES="$(echo "$TYPE_LINE" | sed -n 's/.*IDs: \([0-9]*\).*/\1/p')"
        if [ -z "$N_TYPES" ] || [ "$N_TYPES" -lt 4 ]; then
            echo "  [败] 资源类型只有 ${N_TYPES:-0} 种（应 >= 4：ICON/RCDATA/MANIFEST/VERSION）"
            FAILED=1
        else
            echo "  OK  资源类型 $N_TYPES 种"
        fi
    fi
else
    echo "  [跳过] 没找到 objdump，无法检查资源表"
fi

# ★ 体积下限：payload 原始 2.4MB，zlib 压缩后约 1.2MB。
#   产物不可能比"压缩后的 payload"还小 —— 那说明资源根本没进去。
if [ "$SIZE" -lt 800000 ]; then
    echo "  [败] 产物只有 $SIZE 字节 —— 比压缩后的 payload 还小，资源肯定没进去"
    exit 1
fi
echo "  OK  体积 $SIZE 字节（payload 2.4MB → zlib 后约 1.2MB）"

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "[败] 产物自检没过 —— 不拷到 dist/"
    exit 1
fi

if [ "$MODE" = "--no-copy" ]; then
    echo ""
    echo "产物在 $TMP_SH/$OUT_NAME（--no-copy，未拷回 dist/）"
    exit 0
fi

cp -f "$TMP_SH/$OUT_NAME" "$OUT_EXE"
SHA=$(sha256sum "$OUT_EXE" | cut -d' ' -f1)
echo ""
echo "=== 完成 ==="
echo "  安装包 : dist/$OUT_NAME  ($SIZE 字节)"
echo "  sha256 : $SHA"
echo ""
echo "  自测（不碰系统）："
echo "     python installer/selftest_setup.py"
echo "  手动干跑："
echo "     \"dist/$OUT_NAME\" --verify"
echo "     \"dist/$OUT_NAME\" --extract %TEMP%\\r3sc-check"
