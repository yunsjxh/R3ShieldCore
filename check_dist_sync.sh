#!/usr/bin/env bash
#
# check_dist_sync.sh —— 发布闸门：断言 dist 里的二进制 == 刚构建出来的二进制。
#
# ★ 为什么需要这道闸门（v57 实测事故）：
#   项目里**没有任何脚本**把构建产物拷进 `dist/`，全靠手工 cp。
#   结果是 `dist/R3ShieldCore-x64/64/R3ShieldCoreLib-x86.dll` 停留在
#   **v55 之前**的构建（472064 B），而 x64 DLL 已经是 v55 之后（570368 B）。
#   两者差一个 `WTSQueryUserToken` —— 也就是 v55 的共享通道 ACL 修复。
#   后果：32 位目标进程在「超级置顶」子引擎下拿不到共享通道，
#   直接 `共享通道不可用，本进程跳过全部 Hook` ⇒ **一条事件都没有**。
#   而发布包看上去完全正常（文件都在、大小也对、闸门也全绿）。
#
#   ⇒ 判据必须是**内容相等**（md5），不是"文件存在"。
#
# 用法:
#   bash check_dist_sync.sh                    # 检查 dist/R3ShieldCore-x64
#   bash check_dist_sync.sh dist/R3ShieldCore-x64-v57
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
BUILD_ROOT="$PROJECT_ROOT/R3ShieldCore/Release"

DIST_DIR="${1:-dist/R3ShieldCore-x64}"

cd "$PROJECT_ROOT" || exit 1

# 映射：dist 内路径 | 构建产物路径
#
# ★ 布局约定（必须与代码一致，别改）：
#   `dll_inject.cpp` 的 `GetEnginePath(machine)` 按**目录名**选架构 ——
#   它返回 `<部署根>\32` 或 `<部署根>\64`，再拼固定的 `r3shieldcore-lib.dll`。
#   所以 32 位 DLL 必须在 `32\r3shieldcore-lib.dll`，
#   **不能**叫 `64\R3ShieldCoreLib-x86.dll`（那是无效命名，代码零引用）。
MAP=(
    "R3 ShieldCore.exe|$BUILD_ROOT/R3 ShieldCore.exe"
    "r3shieldcore_svc.exe|$BUILD_ROOT/r3shieldcore_svc.exe"
    "64/r3shieldcore-lib.dll|$BUILD_ROOT/64/r3shieldcore-lib.dll"
    "32/r3shieldcore-lib.dll|$BUILD_ROOT/32/r3shieldcore-lib.dll"
)

echo "=== 发布同步闸门: $DIST_DIR ==="
echo "对照构建目录: $BUILD_ROOT"
echo ""

fail=0

md5_of() {
    if [ -f "$1" ]; then md5sum "$1" | cut -d' ' -f1; else echo ""; fi
}

for entry in "${MAP[@]}"; do
    rel="${entry%%|*}"
    src="${entry##*|}"
    dst="$DIST_DIR/$rel"

    if [ ! -f "$dst" ]; then
        echo "[FAIL] 缺失: $dst"
        fail=1
        continue
    fi
    if [ ! -f "$src" ]; then
        echo "[FAIL] 构建产物缺失: $src（先跑 bash build.sh）"
        fail=1
        continue
    fi

    a="$(md5_of "$dst")"
    b="$(md5_of "$src")"
    sa=$(stat -c%s "$dst")
    sb=$(stat -c%s "$src")

    if [ "$a" = "$b" ]; then
        echo "[ OK ] $rel  ($sa B, md5=${a:0:12})"
    else
        echo "[FAIL] $rel 与构建产物不一致 —— dist 里的是**旧二进制**"
        echo "       dist : $sa B  md5=${a:0:12}"
        echo "       build: $sb B  md5=${b:0:12}"
        echo "       修复 : cp -f \"$src\" \"$dst\""
        fail=1
    fi
done

# ---- 布局判据：32 位 DLL 必须在 `32\` 下 --------------------------------------
# 这是"32 位进程到底有没有防护"的唯一开关。缺了它，32 位注入**静默失败**：
# 引擎照常启动、照常注入 64 位、照常写日志 —— 只有 32 位进程一条事件都没有。
echo ""
echo "=== 32 位注入 DLL 布局判据 ==="
if [ -f "$DIST_DIR/32/r3shieldcore-lib.dll" ]; then
    echo "[ OK ] 32/r3shieldcore-lib.dll 存在（32 位进程可被注入）"
else
    echo "[FAIL] 32/r3shieldcore-lib.dll 缺失"
    echo "       => **所有 32 位进程都不会被注入、不会有任何事件**"
    echo "       注入器只认 <部署根>\\32\\r3shieldcore-lib.dll"
    echo "       （dll_inject.cpp 的 GetEnginePath 按**目录名**选架构）"
    fail=1
fi
if [ -f "$DIST_DIR/64/R3ShieldCoreLib-x86.dll" ]; then
    echo "[WARN] 发现无效命名 64/R3ShieldCoreLib-x86.dll"
    echo "       代码里零引用 —— 放在这里**不起任何作用**，只会误导。建议删除。"
fi

# ---- 附加判据：两个架构的 DLL 必须带同一套特性标记 ---------------------------
# 光比大小/时间戳不够（v57 事故里 x86 只是"小一点"，肉眼看不出来）。
# 这里用**源码里能 grep 到的符号**当版本探针：缺了就说明构建代次落后。
echo ""
echo "=== 双架构特性标记一致性 ==="

MARKERS=(
    "WTSQueryUserToken|v55 共享通道 ACL 修复（会话用户 SID）"
    "GlobalHookSessionSelfExit|v62 ARK 内部退出导出（远程入口必须落在自己 DLL 里）"
)

for m in "${MARKERS[@]}"; do
    sym="${m%%|*}"
    desc="${m##*|}"
    has64=0
    has32=0
    [ -f "$DIST_DIR/64/r3shieldcore-lib.dll" ] && strings -a "$DIST_DIR/64/r3shieldcore-lib.dll" | grep -q "$sym" && has64=1
    [ -f "$DIST_DIR/32/r3shieldcore-lib.dll" ] && strings -a "$DIST_DIR/32/r3shieldcore-lib.dll" | grep -q "$sym" && has32=1

    if [ "$has64" = "1" ] && [ "$has32" = "1" ]; then
        echo "[ OK ] $sym  x64=有  x86=有   ($desc)"
    else
        echo "[FAIL] $sym  x64=$has64  x86=$has32   ($desc)"
        echo "       ⇒ 有一侧的 DLL 是旧代次构建，必须重新 bash build.sh"
        fail=1
    fi
done

# ---- 附加判据：v66 代次标记（见下）--------------------------------------------
#
# ★ 为什么还要这一节 —— 铁律 142「只查存在⇒假绿」的补救：
#   上面 4 条 md5 只能证明「dist == Release/」。如果 **Release/ 自己就是旧的**
#   （比如改了源码只重建了 x64 引擎、没重建 DLL），两边都旧 ⇒ 正好相等 ⇒ 报绿。
#   所以要有一两个「**只有新代次才有**」的字符串当探针。
#
# ★ 为什么用**宽字符串**（`strings -el`）而不是 ASCII：
#   中文横幅是窄字面量，在 PE 里是 CP936 字节，bash 里要写 `\xc8\xab` 这种转义，
#   脆且不可读。而下面这两个标记恰好都是**宽字面量**，`strings -el` 直接可读。
#
# ★ 为什么它们确实是「v66 才有」：
#   · `R3 Shield Core`（带空格）—— v66 把配置迁到 `%ProgramData%\R3 Shield Core\`，
#     `ResolveConfigPath()` 里的 `L"R3 Shield Core"` 是新加的宽字面量；
#     v65 及以前配置只在 exe 同目录，全仓没有这个串。
#     （注意：主程序文件名是 `R3 ShieldCore.exe`，**没空格**，不会误命中。）
#   · `System32\consent.exe` 等三条 —— v66 的 `IsUacConsentImage` 用
#     **不带 `%SystemRoot%\` 前缀**的相对尾巴比对；v65 的写法是
#     `%SystemRoot%\System32\consent.exe`，`strings -el` 打出来是**另一行**。
#     ⇒ 用 `grep -x`（整行相等）才能把新旧两种写法分开。
echo ""
echo "=== v66 代次标记（防 Release/ 自己也旧）==="

V66_EXE_MARK="R3 Shield Core"
if [ -f "$DIST_DIR/R3 ShieldCore.exe" ]; then
    if strings -el "$DIST_DIR/R3 ShieldCore.exe" | grep -qxF "$V66_EXE_MARK"; then
        echo "[ OK ] EXE 含 v66 标记 '$V66_EXE_MARK'（配置已迁 ProgramData）"
    else
        echo "[FAIL] EXE 里没有 v66 标记 '$V66_EXE_MARK'"
        echo "       ⇒ dist 里的 EXE 是 v66 之前的构建（配置路径迁移那版没进去）"
        fail=1
    fi
else
    echo "[FAIL] 缺失: $DIST_DIR/R3 ShieldCore.exe"
    fail=1
fi

for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    miss=0
    for rel in "System32\\consent.exe" "System32\\CredentialUIBroker.exe" "System32\\LogonUI.exe"; do
        strings -el "$dll" | grep -qxF "$rel" || miss=$((miss + 1))
    done
    if [ "$miss" -eq 0 ]; then
        echo "[ OK ] $arch 位 DLL 含 v66 UAC 白名单三条相对路径（整行相等）"
    else
        echo "[FAIL] $arch 位 DLL 缺 $miss 条 v66 UAC 白名单标记"
        echo "       ⇒ 该架构的 DLL 是 v65 代次（那时用的是 '%SystemRoot%\\System32\\...' 前缀写法）"
        fail=1
    fi
done

echo ""
if [ "$fail" -eq 0 ]; then
    echo "结果: PASS —— dist 与构建产物一致，双架构同代次，且带 v66 标记。"
    exit 0
fi
echo "结果: FAIL —— 发布目录与构建产物不同步，**不要打包**。"
exit 1