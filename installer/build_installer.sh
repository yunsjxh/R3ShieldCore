#!/usr/bin/env bash
#
# build_installer.sh —— 把 dist 发布目录 + 内核驱动 + 安装脚本 打成一个
#                      单文件安装包（iexpress 自解压）。
#
# ★★★ 这是**老路**。正式发布路径已经换成原生 GUI 安装器 ★★★
#   正式路径：`bash installer/build_setup.sh` → `r3sc_setup.c`（C + Win32 GUI，
#   payload 以 zlib 压缩 RCDATA 内嵌）→ `dist/R3ShieldCore-Setup.exe`
#   本脚本是**兼容保留**，产物固定带 `-iexpress` 后缀，不会覆盖正式产物
#   （原因见下面 OUT_NAME 处的注释）。
#
# 为什么用 iexpress 而不是 Inno Setup / NSIS
# ==========================================
# 本机**没有**装 Inno Setup，也**没有** NSIS（`makensis` / `iscc` 都不存在）。
# 而 `iexpress.exe` 是 **Windows 自带**的（System32 下就有），所以零额外依赖。
#
# iexpress 的一个硬限制（本脚本绕开它的办法）
# ==========================================
# iexpress 的自解压包**不支持子目录** —— 它只会把 [SourceFiles] 里列的文件
# 平铺到解压目录。可是引擎要求**固定子目录**：
#     <部署根>\64\r3shieldcore-lib.dll
#     <部署根>\32\r3shieldcore-lib.dll
# 所以这里把整个发布树打成 `payload.zip` 再交给 iexpress，
# 由 install.bat 用 Windows 自带的 tar.exe（bsdtar）解出来。
#
# 产物
# ====
#   dist/R3ShieldCore-Setup-iexpress.exe   老路安装包（双击就装）
#   dist/R3ShieldCore-x64.zip              绿色版（解压即用，由 build_dist_zip.sh 出）
#
# 用法
# ====
#   bash build_installer.sh              # 组装 + 打包装
#   bash build_installer.sh --verify     # 只校验（不打包）
#   bash build_installer.sh --payload-only   # 只生成 payload.zip（调试用）
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

DIST_DIR="dist/R3ShieldCore-x64"
DRIVER_SYS="driver/build/r3shieldcore_kernel.sys"
INST_DIR="installer"

PY="$PYTHON"   # 由 scripts_env.sh 自动探测（见文件头）
MODE="${1:-build}"
FAILED=0

# ★★★ 预检：清掉上一次构建可能留下的"挂死 worker" ★★★
# 实测（本机踩过两次）：iexpress.exe 会**再起一个自己的 worker 实例**去跑 makecab，
# 主进程退出后 worker 可能**一直挂着**，攥着 ~<目标名>.DDF 的句柄不放。
# 它的危害不是"这一次失败"，而是**下一次构建彻底坏掉**：
#   DDF 建不出来 ⇒ iexpress 返回 1、不产出任何文件、也不打印任何错误。
#   （表现和"SED 不是 GBK"一模一样，排查起来极费时间。）
# 本脚本就是打包这一步的 owner，所以先清掉 —— 僵尸进程的代价远大于误杀。
TASKKILL="/c/Windows/System32/taskkill.exe"
"$TASKKILL" //F //IM iexpress.exe //IM makecab.exe >/dev/null 2>&1

# ★ 自测变体：把 AppLaunched 换成 `install.bat /dryrun /nodriver /quiet`，
#   产物叫 ...-DRYRUN.exe 且**不覆盖**正式安装包。
#   这样"iexpress 解压 -> install.bat 解析 -> payload 结构"这条链能被**真正跑一遍**，
#   而完全不碰系统（不复制文件、不建服务、不写注册表）。
#   （没有这一步的话，验证安装包的唯一办法就是真装一遍 —— 结果是没人测。）
# ★★★ AppLaunched 的第一个 token 必须是 .exe，不能是 .bat/.cmd ★★★
# wextract 检测到 AppLaunched 是批处理时，会自作主张把它改写成
#     Command.com /c <解压目录>\install.bat
# 而 **64 位 Windows 根本没有 command.com**（32 位时代的东西，早删了），
# 于是 CreateProcess 直接失败：
#     "创建进程 <Command.com /c ...> 时出错。原因: 系统找不到指定的文件。"
# 更坑的是：① 它会把 AppLaunched 后面的参数**全部丢掉**；
#           ② 这个失败**只在运行期弹一个错误框**，构建期一切正常、产物也是合法 PE。
# 也就是说——不真跑一遍就发现不了。
# 修法（ss64 的 iexpress SED 文档明确给的 workaround）：包一层 cmd.exe。
#     AppLaunched=cmd.exe /c install.bat <args>
APP_LAUNCHED="cmd.exe /c install.bat"

# ★★★ 产物名带 `-iexpress` 后缀 —— 这条不是命名洁癖，是**防静默覆盖** ★★★
# 现在的正式发布路径是**原生 GUI 安装器**（`build_setup.sh` → `r3sc_setup.c`），
# 它产出的也是 `dist/R3ShieldCore-Setup.exe`。两条路同名的话，谁后构建谁覆盖谁，
# 而且**覆盖是静默的**：跑一次老路构建，就会把已经验证过的原生安装器换成
# 一个"没有开机自启"的老版本 —— 正是用户报的那个问题。
# 所以老路产物固定叫 `R3ShieldCore-Setup-iexpress.exe`，与原生路彻底分开。
OUT_NAME="R3ShieldCore-Setup-iexpress.exe"
if [ "$MODE" = "--dryrun-build" ]; then
    APP_LAUNCHED="cmd.exe /c install.bat /dryrun /nodriver /quiet"
    OUT_NAME="R3ShieldCore-Setup-iexpress-DRYRUN.exe"
fi

# ★★★【暂存目录必须是纯 ASCII 路径】★★★
# 项目根目录可能带中文。而 iexpress.exe 是 **ANSI** 程序：
# 它读 SED 时按系统 ANSI(CP936) 解码，路径里有中文时行为不可靠（实测直接
# 返回 1、不产出任何文件、也不报错）。所以：
#   · 暂存目录 -> 用户 TEMP 下的纯 ASCII 路径
#   · TargetName -> 同一个 ASCII 目录
#   · 打完再把 Setup.exe **拷回** dist/
STAGE_BASE="$("$PY" -c "import os,tempfile;print(os.path.join(tempfile.gettempdir(),'r3sc-installer-stage').replace(chr(92),'/'))")"
STAGE="$STAGE_BASE"
PAYLOAD_ZIP="$STAGE/payload.zip"
SED="$STAGE/installer.sed"
OUT_EXE="$PROJECT_ROOT/dist/R3ShieldCore-Setup-iexpress.exe"
if [ "$MODE" = "--dryrun-build" ]; then
    # 自测变体单独放，**绝不覆盖**正式安装包
    OUT_EXE="$PROJECT_ROOT/dist/R3ShieldCore-Setup-iexpress-DRYRUN.exe"
fi
TMP_EXE="$STAGE/$OUT_NAME"

# ★ 不能写 `$SystemRoot` —— bash 里它不是变量名（是 Windows 的环境变量，
#   Git-Bash 只在某些配置下导出它），配合 `set -u` 会直接 "unbound variable"。
IEXPRESS="/c/Windows/System32/iexpress.exe"
[ -x "$IEXPRESS" ] || IEXPRESS="${SYSTEMROOT:-/c/Windows}/System32/iexpress.exe"

# ---------------------------------------------------------------------------
# 必备文件清单（少一个就报错 —— 和 build_dist_zip.sh 一个思路：
# 清单本身就是交付物的一部分，不能靠"目录里碰巧有什么"）
# ---------------------------------------------------------------------------
DIST_FILES=(
    "R3 ShieldCore.exe"
    "r3shieldcore_svc.exe"
    "64/r3shieldcore-lib.dll"
    "32/r3shieldcore-lib.dll"
    "r3shieldcore.ini"
    "r3shieldcore-block.ini"
    "r3shieldcore-blockall.ini"
    "r3shieldcore-blockallsafe.ini"
    "r3shieldcore-safe-first.ini"
    "start.bat"
    "stop.bat"
    "unlock-acl.bat"
    "verify-v26.bat"
    "netcheck-diag.bat"
    "dskill.exe"
    "配置详解.md"
    "模式选择说明.md"
    "部署指南.md"
    "预设说明.txt"
)

echo "=== 1/5 预检 ==="
for f in "${DIST_FILES[@]}"; do
    if [ ! -f "$DIST_DIR/$f" ]; then
        echo "  [缺] $DIST_DIR/$f"
        FAILED=1
    fi
done
if [ ! -f "$DRIVER_SYS" ]; then
    echo "  [缺] $DRIVER_SYS  —— 先跑 bash driver/build_driver.sh"
    # ★ 本脚本（老路 iexpress）**要求**驱动；正式路 build_setup.sh 不要求
    #   （没驱动就出「仅用户态包」）。两条路的差异是有意的，不是漏改。
    echo "       （正式路 bash installer/build_setup.sh 允许缺驱动，产物是「仅用户态包」）"
    FAILED=1
fi
for f in install.bat uninstall.bat; do
    if [ ! -f "$INST_DIR/$f" ]; then
        echo "  [缺] $INST_DIR/$f"
        FAILED=1
    fi
done
if [ ! -x "$IEXPRESS" ]; then
    echo "  [缺] iexpress.exe（应该在 $IEXPRESS）"
    FAILED=1
fi
if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "预检失败 —— 先把上面缺的东西补齐。"
    exit 1
fi
echo "  OK（dist 20 项 + 驱动 + 2 个安装脚本 + iexpress）"

# ---------------------------------------------------------------------------
# .bat 编码闸门：必须 CRLF + GBK + 无 BOM
#   ★ 这一步不能省：install.bat 里有大量中文注释，而 cmd.exe 按字节读批处理。
#     LF-only + 非 ASCII ⇒ 解析器失同步 ⇒ 双击一闪而过。
# ---------------------------------------------------------------------------
echo ""
echo "=== 2/5 安装脚本编码闸门（CRLF + GBK + 无 BOM）==="
if ! "$PY" tools/bat_gbk_crlf.py "$INST_DIR/install.bat" "$INST_DIR/uninstall.bat" >/dev/null 2>&1; then
    echo "  [败] bat_gbk_crlf.py 报错"
    exit 1
fi
if ! "$PY" tools/bat_gbk_crlf.py --all --check 2>&1 | tail -1 | grep -q "PASS"; then
    echo "  [败] 有 .bat 不符合 CRLF + GBK"
    "$PY" tools/bat_gbk_crlf.py --all --check 2>&1 | grep -v "OK" | head -20
    exit 1
fi
echo "  OK"

# ---------------------------------------------------------------------------
# 产品名里有空格 ⇒ 每一处引用都要加引号
# ---------------------------------------------------------------------------
if ! "$PY" tools/check_spaced_name_quoted.py 2>&1 | tail -1 | grep -q "都在引号内"; then
    echo "  [败] 有引号外的空格名引用（会被 shell 拆参）"
    "$PY" tools/check_spaced_name_quoted.py 2>&1 | sed -n '/✗/,$p' | head -20
    exit 1
fi
echo "  OK（空格名引用全部带引号）"

# ---------------------------------------------------------------------------
# 组 payload
# ---------------------------------------------------------------------------
echo ""
echo "=== 3/5 组 payload ==="
# ★ 暂存目录清不掉 = 有残留 worker 攥着句柄（见文件头的预检注释）。
#   这时**不能**继续用同一个路径：换个新的，否则这次构建必挂。
if ! rm -rf "$STAGE" 2>/dev/null; then
    STAGE="$STAGE_BASE-$(date +%H%M%S)-$$"
    # ★ 派生变量必须跟着重算 —— 否则后面还在往旧路径写（静默错位）。
    PAYLOAD_ZIP="$STAGE/payload.zip"
    SED="$STAGE/installer.sed"
    TMP_EXE="$STAGE/$OUT_NAME"
    echo "  [警告] 旧暂存目录清不掉（残留 iexpress worker 锁着）—— 改用 $STAGE"
fi
mkdir -p "$STAGE"
mkdir -p "$STAGE/_payload"

# 只拷清单里的文件（不把 dist 里的运行期日志一起带进去）
for f in "${DIST_FILES[@]}"; do
    mkdir -p "$STAGE/_payload/$(dirname "$f")"
    cp -f "$DIST_DIR/$f" "$STAGE/_payload/$f"
done
# 内核驱动放在 payload 的 driver\ 子目录（install.bat 从那里取）
mkdir -p "$STAGE/_payload/driver"
cp -f "$DRIVER_SYS" "$STAGE/_payload/driver/r3shieldcore_kernel.sys"

# 打成 zip。用 Python 的 zipfile 而不是 `zip`/`tar`：
# ① 条目顺序和路径分隔符可控（必须是正斜杠，tar.exe 才认）；
# ② 不依赖 PATH 里有没有 zip。
"$PY" - "$STAGE/_payload" "$PAYLOAD_ZIP" <<'PYEOF'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
n = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src).replace(os.sep, "/")
            z.write(full, rel)
            n += 1
print(f"  payload.zip: {n} 个条目")
PYEOF

cp -f "$INST_DIR/install.bat"   "$STAGE/install.bat"
cp -f "$INST_DIR/uninstall.bat" "$STAGE/uninstall.bat"

echo "  payload 条目："
"$PY" -c "
import zipfile,sys
z=zipfile.ZipFile(r'$PAYLOAD_ZIP')
for i in z.infolist(): print('   ', i.file_size, i.filename)
"

if [ "$MODE" = "--payload-only" ]; then
    echo ""
    echo "payload 已生成：$PAYLOAD_ZIP（--payload-only，未打包）"
    exit 0
fi

# ---------------------------------------------------------------------------
# 生成 iexpress 的 SED 指令文件
#   ★★★ 必须写 **GBK（= 本机 ANSI）**，不能写 UTF-8 ★★★
#   iexpress.exe 是 ANSI 程序，按系统 ANSI 解码 SED。
#   用 UTF-8 写时：FriendlyName 里的中文变乱码，而且**整个打包会静默失败**
#   （实测：返回码 1、不产出任何文件、不打印任何错误）。
# ---------------------------------------------------------------------------
echo ""
echo "=== 4/5 生成 iexpress SED ==="
WIN_STAGE="$("$PY" -c "import os;print(os.path.abspath(r'$STAGE').replace('/', chr(92)))")"
WIN_TMP_EXE="$("$PY" -c "import os;print(os.path.abspath(r'$TMP_EXE').replace('/', chr(92)))")"
WIN_SED="$("$PY" -c "import os;print(os.path.abspath(r'$SED').replace('/', chr(92)))")"

"$PY" - "$SED" "$WIN_STAGE" "$WIN_TMP_EXE" "$APP_LAUNCHED" <<'PYEOF'
import sys
sed, stage, target, app = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = (
    "[Version]\r\n"
    "Class=IEXPRESS\r\n"
    "SEDVersion=3\r\n"
    "[Options]\r\n"
    "PackagePurpose=InstallApp\r\n"
    # ★ ShowInstallProgramWindow 的取值（ss64 的 SED 文档）：
    #     0=默认  1=**隐藏**  2=最小化  3=最大化
    #   注意是"1 = 隐藏"，不是"1 = 显示"（这里踩过）。
    #   选隐藏的理由：真正干活的 cmd.exe 会自己开一个控制台窗口，
    #   把 [1/7]~[7/7] 全过程打出来；再叠一个解压进度窗是噪音。
    "ShowInstallProgramWindow=1\r\n"
    "HideExtractAnimation=0\r\n"
    "UseLongFileName=1\r\n"
    "InsideCompressed=0\r\n"
    "CAB_FixedSize=0\r\n"
    "CAB_ResvCodeSigning=0\r\n"
    "RebootMode=N\r\n"
    "InstallPrompt=\r\n"
    "DisplayLicense=\r\n"
    "FinishMessage=\r\n"
    f"TargetName={target}\r\n"
    "FriendlyName=R3 ShieldCore 安装程序\r\n"
    f"AppLaunched={app}\r\n"
    "PostInstallCmd=<None>\r\n"
    "AdminQuietInstCmd=\r\n"
    "UserQuietInstCmd=\r\n"
    "SourceFiles=SourceFiles\r\n"
    "[Strings]\r\n"
    'FILE0="install.bat"\r\n'
    'FILE1="payload.zip"\r\n'
    'FILE2="uninstall.bat"\r\n'
    "[SourceFiles]\r\n"
    f"SourceFiles0={stage}\\\r\n"
    "[SourceFiles0]\r\n"
    "%FILE0%=\r\n"
    "%FILE1%=\r\n"
    "%FILE2%=\r\n"
)
with open(sed, "w", encoding="gbk", errors="replace", newline="") as f:
    f.write(text)
print(f"  SED -> {sed}  (GBK/CRLF)")
PYEOF

echo "  TargetName -> $WIN_TMP_EXE"
echo "  （暂存目录是纯 ASCII，打完再拷回 dist/）"

if [ "$MODE" = "--verify" ]; then
    echo ""
    echo "--verify 模式：SED 已生成，未调用 iexpress。"
    exit 0
fi

# ---------------------------------------------------------------------------
# 调 iexpress 打包
#   ★ 必须用 /N（非交互）。不带 /N 时它会弹图形向导，自动化里会挂住。
#   ★ 加 MSYS_NO_PATHCONV=1：否则 Git-Bash 会把 `/N` 当路径转换掉。
# ---------------------------------------------------------------------------
echo ""
echo "=== 5/5 调用 iexpress ==="
rm -f "$TMP_EXE"

# ★★★ iexpress 会"打包完了也不退出"，所以这里不裸等 ★★★
# 后台起 iexpress，**盯产物文件**：大小连续 2 秒不变就当打包完成。
# 这样即使 worker 吊死，本脚本也一定能往下走，不会卡住。
MSYS_NO_PATHCONV=1 "$IEXPRESS" /N "$WIN_SED" >/dev/null 2>&1 &
IEPID=$!

PREV=-1
STABLE=0
for _ in $(seq 1 240); do          # 上限 240 × 0.5s = 120s
    sleep 0.5
    [ -f "$TMP_EXE" ] || continue
    CUR=$(stat -c %s "$TMP_EXE" 2>/dev/null || echo 0)
    if [ "$CUR" = "$PREV" ] && [ "$CUR" -gt 0 ]; then
        STABLE=$((STABLE + 1))
        [ "$STABLE" -ge 4 ] && break
    else
        STABLE=0
    fi
    PREV=$CUR
done

if kill -0 "$IEPID" 2>/dev/null; then
    echo "  [注意] iexpress 主进程打包完没自己退出 —— 收尾清掉（见文件头预检注释）"
    kill -9 "$IEPID" 2>/dev/null
fi
# worker 是 iexpress 的孙进程，MSYS 的 kill 够不着，只能按映像名收。
# ★ 这会连带杀掉**别的** iexpress/makecab —— 刻意的，理由同上。
"$TASKKILL" //F //IM iexpress.exe //IM makecab.exe >/dev/null 2>&1
sleep 0.5

if [ ! -f "$TMP_EXE" ]; then
    echo "  [败] iexpress 没产出安装包"
    echo "       排查顺序："
    echo "        1) 暂存目录里是不是有被锁的 ~*.DDF？（残留 worker 没清干净）"
    echo "        2) SED 是不是 GBK？（UTF-8 会静默失败，返回 1 且不报错）"
    echo "        3) TargetName / SourceFiles0 所在目录是不是纯 ASCII？"
    echo "       SED 内容在：$SED"
    exit 1
fi

cp -f "$TMP_EXE" "$OUT_EXE"
SIZE=$(stat -c %s "$OUT_EXE")
echo "  OK  ->  dist/$OUT_NAME  ($SIZE 字节)"
SHA=$(sha256sum "$OUT_EXE" | cut -d' ' -f1)
echo "  sha256: $SHA"

# 收尾自检：产物必须真的是 PE
if ! head -c 2 "$OUT_EXE" | grep -q "MZ"; then
    echo "  [败] 产物不是合法的 PE 文件"
    exit 1
fi
echo ""
echo "=== 完成 ==="
echo "  安装包 : dist/$OUT_NAME"
if [ "$MODE" != "--dryrun-build" ]; then
    echo "  绿色版 : dist/R3ShieldCore-x64.zip"
fi
echo ""
echo "  自测（不会真的安装）："
echo "     双击 Setup.exe  ->  解压到 %TEMP%  ->  跑 install.bat"
echo "     想先干跑一遍：install.bat /dryrun /nodriver"
echo "     dryrun 会把证据写到 %TEMP%\\R3ShieldCore-dryrun-report.txt"
