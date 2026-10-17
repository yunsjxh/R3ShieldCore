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

# ---- 附加判据：v67 代次标记（截屏替换）--------------------------------------
#
# ★ 为什么需要：上面 v66 的两条标记只能证明"至少是 v66 代次"，证明不了
#   v67 的**截屏替换**改动真的进了产物 —— 改了源码没重编照样全绿（铁律 142）。
# ★ 标记选 `SPOOF`：它是 v67 才有的决策档名（`DecisionName` 的返回值 / GUI 的
#   决策分布标签），v66 及以前全仓没有这个字面量。
# ★ 为什么 EXE 查**宽**串、DLL 查**窄**串：
#   · EXE 侧是 GUI 的 `L"SPOOF"` 标签（宽字面量）⇒ `strings -el`；
#   · DLL 侧是 `DecisionName()` 返回的 `"SPOOF"`（窄字面量，走日志）⇒ `strings -a`。
#   两边各查各的，避免"查了 A 却以为 B 也在"。
echo ""
echo "=== v67 代次标记（截屏替换）==="

if [ -f "$DIST_DIR/R3 ShieldCore.exe" ]; then
    if strings -el "$DIST_DIR/R3 ShieldCore.exe" | grep -qxF "SPOOF"; then
        echo "[ OK ] EXE 含 v67 标记 'SPOOF'（GUI 决策分布新档）"
    else
        echo "[FAIL] EXE 里没有 v67 标记 'SPOOF'"
        echo "       ⇒ dist 里的 EXE 是 v67 之前的构建（GUI 没加 SPOOF 档）"
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
    if strings -a "$dll" | grep -qxF "SPOOF"; then
        echo "[ OK ] $arch 位 DLL 含 v67 标记 'SPOOF'（DecisionName 新档）"
    else
        echo "[FAIL] $arch 位 DLL 缺 v67 标记 'SPOOF'"
        echo "       ⇒ 该架构的 DLL 是 v66 代次（截屏替换没编进去）"
        fail=1
    fi
done

# ---- 附加判据：v69 代次标记（测试模式改为**配置驱动**）------------------------
#
# ★ 背景：v68 的测试模式是**命令行**（`--test-inject-only=<镜像名>` + 导出
#   `GlobalHookSessionSetTestInjectOnly`）。v69 把它改成**配置驱动**
#   （ini: `mode=test` + `test_inject_only=`），因为引擎自带
#   `requireAdministrator` manifest、**自己会提权**，双击即可 —— 而命令行
#   传参要求调用方先有提权 shell。于是那条导出被**删掉**了。
#
# ★ 为什么需要这节：v67 的 `SPOOF` 标记只证明"至少是 v67 代次"，证明不了
#   v69 的配置驱动测试模式真的进了产物 —— 改了源码没重编照样全绿（铁律 142）。
#
# ★ 判据（三条，缺一不可）：
#   ① EXE 含**窄**串 `test_inject_only=` —— 启动横幅 / fail-closed 报错里的
#      那个字面量（`app.cpp`），证明"引擎读了配置里这个键"。
#   ② 两个架构的 DLL 都含**宽**串 `test_inject_only` —— `functions.cpp` 的
#      `LOG(L"测试模式(test_inject_only)：…")`，证明"注入决策真的按白名单走"。
#      ⚠️ 必须用 `strings -el`（16 位）而不是 `-a`：中文是宽串，`-a` 只看
#         8 位可打印序列，查的是另一个世界（v67 那节踩过同一个坑）。
#   ③ ★ **负对照**：`GlobalHookSessionSetTestInjectOnly` 必须**不在**任何产物里
#      —— v69 删掉了这条导出。若它还在，说明"删了源码但没重编"（铁律 148：
#         闸门要有负对照，否则"查到了"和"该不该查到"分不清）。
# ★ 前提检查（铁律 117）：源码里必须有这两个字面量，否则判据失去前提直接 FAIL
#   —— 否则"键被改名"会表现成"标记查不到"，被误当成"没重编"。
echo ""
echo "=== v69 代次标记（限定注入范围：ini 的 test_inject_only=，与 mode= 解耦）==="

V69_EXE_MARK="test_inject_only="
V69_DLL_MARK="test_inject_only"
V69_REMOVED="GlobalHookSessionSetTestInjectOnly"
V69_SRC_CFG="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp"
V69_SRC_APP="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/app.cpp"
V69_SRC_DLL="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/functions.cpp"

if ! grep -qF "$V69_EXE_MARK" "$V69_SRC_CFG" 2>/dev/null; then
    echo "[FAIL] 源码 $V69_SRC_CFG 里没有 '$V69_EXE_MARK' —— 判据失去前提"
    fail=1
fi
if ! grep -qF "$V69_DLL_MARK" "$V69_SRC_DLL" 2>/dev/null; then
    echo "[FAIL] 源码 $V69_SRC_DLL 里没有 '$V69_DLL_MARK' —— 判据失去前提"
    fail=1
fi
# ★ 铁律 127：同一个「键名」在**三个**源文件里各写一遍（解析器 / 横幅 / 日志）。
#   任何一处被改名，另外两处都会**静默漂移**（配置改了不生效 / 日志里查不到）。
#   跨语言收敛不了，就建闸门 —— 三处必须都含这个字面量。
if ! grep -qF "$V69_DLL_MARK" "$V69_SRC_APP" 2>/dev/null; then
    echo "[FAIL] 源码 $V69_SRC_APP 里没有 '$V69_DLL_MARK' —— 键名在三处之一漂了（铁律 127）"
    fail=1
fi

V69_EXE="$DIST_DIR/R3 ShieldCore.exe"
if [ ! -f "$V69_EXE" ]; then
    echo "[FAIL] 缺失: $V69_EXE"
    fail=1
else
    if strings -a "$V69_EXE" | grep -qF "$V69_EXE_MARK"; then
        echo "[ OK ] EXE 含 v69 标记 '$V69_EXE_MARK'（配置驱动：读 ini 的测试白名单）"
    else
        echo "[FAIL] EXE 里没有 v69 标记 '$V69_EXE_MARK'"
        echo "       ⇒ dist 里的 EXE 是 v69 之前的构建（测试模式还是命令行版）"
        fail=1
    fi
    if strings -a "$V69_EXE" | grep -qxF "$V69_REMOVED"; then
        echo "[FAIL] EXE 里**仍含**已删除的 $V69_REMOVED —— 负对照失败"
        echo "       ⇒ 源码删了那条导出，但 dist 里的 EXE 没重编"
        fail=1
    else
        echo "[ OK ] EXE 不含已删除的 $V69_REMOVED（负对照：命令行版确实拆掉了）"
    fi
fi

for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    if strings -el "$dll" | grep -qF "$V69_DLL_MARK"; then
        echo "[ OK ] $arch 位 DLL 含 v69 宽串标记 '$V69_DLL_MARK'（注入决策走白名单）"
    else
        echo "[FAIL] $arch 位 DLL 缺 v69 宽串标记 '$V69_DLL_MARK'（用 strings -el 查）"
        echo "       ⇒ 该架构的 DLL 没重编，或标记被改名"
        fail=1
    fi
    if strings -a "$dll" | grep -qxF "$V69_REMOVED"; then
        echo "[FAIL] $arch 位 DLL 里**仍含**已删除的 $V69_REMOVED —— 负对照失败"
        fail=1
    else
        echo "[ OK ] $arch 位 DLL 不含已删除的 $V69_REMOVED（负对照）"
    fi
done

# ---- 附加判据：v70 代次标记（剪贴板替换）------------------------------------
#
# ★ 背景：v67 落地**屏幕**面的回传数据替换（黑帧），v70 落地**剪贴板**面
#   （文本→空串 / 位图·DIB→同尺寸全 0）。剪贴板这个面特有的坑是**句柄所有权**
#   —— `GetClipboardData` 返回的句柄归剪贴板所有，替代物必须由我们在
#   `CloseClipboard` 时回收。
#
# ★ 为什么需要这节：v67 的 `SPOOF` 标记只证明"至少是 v67 代次"，证明不了
#   v70 的剪贴板替换真的进了产物 —— 改了源码没重编照样全绿（铁律 142）。
#
# ★ 判据（四条，缺一不可）：
#   ① EXE 含**窄**串 `spoof_clipboard` —— 配置解析器里的键名
#      （`r3shieldcore_config.cpp`），证明"引擎认识这个 ini 键"。
#   ② 两个架构的 DLL 都含**宽**串 `spoof_clipboard` —— 替换失败日志里的
#      ASCII 子串，证明"替换逻辑真的编进了 DLL"。
#      ⚠️ 必须用 `strings -el`（16 位）而不是 `-a`：中文是宽串，`-a` 只看
#         8 位可打印序列，查的是另一个世界（v67 / v69 两节都踩过这个坑）。
#      ⚠️ 标记必须选 **ASCII 子串**：GNU `strings -el` 只输出 ASCII 可打印
#         字符，**纯中文标记永远查不到**（那会变成一个恒 FAIL 的判据）。
#   ③ ★ **前提检查**（铁律 117）：源码里必须有这两个字面量，否则"键被改名"
#      会表现成"标记查不到"，被误当成"没重编"。
#   ④ ★ **负对照 / 出厂安全性质**（铁律 148 + 110）：随包 ini 里
#      `spoof_clipboard` 必须**存在**且是**关**。这是个"主动欺骗"能力，
#      出厂默认必须是关（与 `spoof_screen` 同规矩）。
#      ⚠️ 顺序很重要：**先**确认键存在，**再**判它不是 1 —— 键不存在时
#         "没有 =1 的行"是**空真**（铁律 110）。
echo ""
echo "=== v70 代次标记（剪贴板替换：返回中性内容 + 句柄所有权）==="

V70_MARK="spoof_clipboard"
V70_SRC_CFG="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp"
V70_SRC_DLL="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/clipboard_guard.cpp"
V70_INI="$DIST_DIR/r3shieldcore.ini"

if ! grep -qF "$V70_MARK" "$V70_SRC_CFG" 2>/dev/null; then
    echo "[FAIL] 源码 $V70_SRC_CFG 里没有 '$V70_MARK' —— 判据失去前提（键被改名了？）"
    fail=1
fi
if ! grep -qF "$V70_MARK" "$V70_SRC_DLL" 2>/dev/null; then
    echo "[FAIL] 源码 $V70_SRC_DLL 里没有 '$V70_MARK' —— 判据失去前提（标记被删了？）"
    fail=1
fi

V70_EXE="$DIST_DIR/R3 ShieldCore.exe"
if [ ! -f "$V70_EXE" ]; then
    echo "[FAIL] 缺失: $V70_EXE"
    fail=1
elif strings -a "$V70_EXE" | grep -qF "$V70_MARK"; then
    echo "[ OK ] EXE 含 v70 标记 '$V70_MARK'（配置解析器认识这个 ini 键）"
else
    echo "[FAIL] EXE 里没有 v70 标记 '$V70_MARK'"
    echo "       ⇒ dist 里的 EXE 是 v70 之前的构建（不认识 spoof_clipboard）"
    fail=1
fi

for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    if strings -el "$dll" | grep -qF "$V70_MARK"; then
        echo "[ OK ] $arch 位 DLL 含 v70 宽串标记 '$V70_MARK'（替换逻辑已编入）"
    else
        echo "[FAIL] $arch 位 DLL 缺 v70 宽串标记 '$V70_MARK'（用 strings -el 查）"
        echo "       ⇒ 该架构的 DLL 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
done

# ④ 出厂默认必须是关（负对照）
if [ ! -f "$V70_INI" ]; then
    echo "[FAIL] 缺失: $V70_INI（出厂默认值判据失去前提）"
    fail=1
elif ! grep -qE "^[[:space:]]*${V70_MARK}[[:space:]]*=" "$V70_INI"; then
    echo "[FAIL] $V70_INI 里**没有** ${V70_MARK}= 这一项 —— 判据失去前提"
    echo "       （缺键时\"没有 =1\"是空真，铁律 110）"
    fail=1
elif grep -qE "^[[:space:]]*${V70_MARK}[[:space:]]*=[[:space:]]*(1|on|yes|true)" "$V70_INI"; then
    echo "[FAIL] 随包 ini 把 ${V70_MARK} 打开了 —— 出厂默认必须**关**"
    echo "       （这是\"主动欺骗\"能力，默认配置行为必须与旧版一致）"
    fail=1
else
    echo "[ OK ] 随包 ini 里 ${V70_MARK} 存在且为**关**（出厂默认安全）"
fi

# ---------------------------------------------------------------------------
# v71 代次标记（注册表值替换：数据区清零 + 长度字段一个都不改）
# ---------------------------------------------------------------------------
#
# ★ 为什么需要这节：v70 的标记只证明"至少是 v70 代次"，证明不了
#   v71 的注册表值替换真的进了产物 —— 改了源码没重编照样全绿（铁律 142）。
#
# ★ 判据（四条，与 v70 同构）：
#   ① EXE 含**窄**串 `spoof_reg` —— 配置解析器里的键名
#      （`r3shieldcore_config.cpp`），证明"引擎认识这个 ini 键"。
#   ② 两个架构的 DLL 都含**宽**串 `spoof_reg` —— 替换失败日志里的
#      ASCII 子串（`LOG(L"...（spoof_reg，class=%u ...）")`），
#      证明"清零逻辑真的编进了 DLL"。
#      ⚠️ 必须用 `strings -el`（16 位）：中文是宽串，`-a` 只看 8 位
#         可打印序列，查的是另一个世界（铁律 193）。
#      ⚠️ 标记必须是 **ASCII 子串**：GNU `strings -el` 只输出 ASCII
#         可打印字符，**纯中文标记永远查不到**（会变成恒 FAIL 的判据）。
#   ③ ★ **前提检查**（铁律 117）：源码里必须有这三个字面量，否则
#      "键被改名"会表现成"标记查不到"，被误当成"没重编"。
#   ④ ★ **负对照 / 出厂安全性质**（铁律 148 + 110）：随包 ini 里
#      `spoof_reg` 必须**存在**且是**关**。
#      ⚠️ 顺序很重要：**先**确认键存在，**再**判它不是 1 —— 键不存在时
#         "没有 =1 的行"是**空真**（铁律 110）。
echo ""
echo "=== v71 代次标记（注册表值替换：数据区清零、长度字段不变）==="

V71_MARK="spoof_reg"
V71_SRC_CFG="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp"
V71_SRC_DLL="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/registry_guard.cpp"
V71_SRC_CODEC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/registry_spoof_codec.h"
V71_INI="$DIST_DIR/r3shieldcore.ini"

# ⚠️ 必须用 **词边界** 匹配（`-w`）而不是裸子串（`-F`）：
#    v72 的标记 `spoof_reg_enum` **包含** v71 的标记 `spoof_reg`
#    ⇒ 裸 `grep -F spoof_reg` 会被 `spoof_reg_enum` 那一行满足，
#      于是"v71 被删、v72 还在"时这条判据**假绿**（铁律 142/110 的精神）。
#    `-w` 把 `_` 算作词字符 ⇒ `spoof_reg_enum` 里那个 `spoof_reg`
#    后面跟着 `_`，**不算**词边界，匹配不上。★ 两条标记互相独立了。
if ! grep -qwF "$V71_MARK" "$V71_SRC_CFG" 2>/dev/null; then
    echo "[FAIL] 源码 $V71_SRC_CFG 里没有独立的 '$V71_MARK' —— 判据失去前提（键被改名了？）"
    fail=1
fi
if ! grep -qwF "$V71_MARK" "$V71_SRC_DLL" 2>/dev/null; then
    echo "[FAIL] 源码 $V71_SRC_DLL 里没有独立的 '$V71_MARK' —— 判据失去前提（标记被删了？）"
    fail=1
fi
# ★ 额外前提：清零逻辑必须**仍在**那个共享头里（铁律 195：生产与探针共用一份）。
#   如果哪天有人把 codec 抄回 guard、把这个头删了，探针就会与生产漂移 —— 这里钉住。
if [ ! -f "$V71_SRC_CODEC" ]; then
    echo "[FAIL] 缺失 $V71_SRC_CODEC —— 清零逻辑的共享头（生产与探针共用一份）不见了"
    fail=1
fi

V71_EXE="$DIST_DIR/R3 ShieldCore.exe"
if [ ! -f "$V71_EXE" ]; then
    echo "[FAIL] 缺失: $V71_EXE"
    fail=1
elif strings -a "$V71_EXE" | grep -qwF "$V71_MARK"; then
    echo "[ OK ] EXE 含 v71 标记 '$V71_MARK'（配置解析器认识这个 ini 键）"
else
    echo "[FAIL] EXE 里没有独立的 v71 标记 '$V71_MARK'（注意：不能用裸子串，会被 v72 的 spoof_reg_enum 假绿）"
    echo "       ⇒ dist 里的 EXE 是 v71 之前的构建（不认识 spoof_reg）"
    fail=1
fi

for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    if strings -el "$dll" | grep -qwF "$V71_MARK"; then
        echo "[ OK ] $arch 位 DLL 含 v71 宽串标记 '$V71_MARK'（清零逻辑已编入）"
    else
        echo "[FAIL] $arch 位 DLL 缺独立的 v71 宽串标记 '$V71_MARK'（用 strings -el 查）"
        echo "       ⇒ 该架构的 DLL 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
done

# ④ 出厂默认必须是关（负对照）
if [ ! -f "$V71_INI" ]; then
    echo "[FAIL] 缺失: $V71_INI（出厂默认值判据失去前提）"
    fail=1
elif ! grep -qE "^[[:space:]]*${V71_MARK}[[:space:]]*=" "$V71_INI"; then
    echo "[FAIL] $V71_INI 里**没有** ${V71_MARK}= 这一项 —— 判据失去前提"
    echo "       （缺键时\"没有 =1\"是空真，铁律 110）"
    fail=1
elif grep -qE "^[[:space:]]*${V71_MARK}[[:space:]]*=[[:space:]]*(1|on|yes|true)" "$V71_INI"; then
    echo "[FAIL] 随包 ini 把 ${V71_MARK} 打开了 —— 出厂默认必须**关**"
    echo "       （这是\"主动欺骗\"能力，默认配置行为必须与旧版一致）"
    fail=1
else
    echo "[ OK ] 随包 ini 里 ${V71_MARK} 存在且为**关**（出厂默认安全）"
fi

# ---------------------------------------------------------------------------
# v72 代次标记（注册表枚举隐藏：索引重映射 + 跳过受保护项）
# ---------------------------------------------------------------------------
#
# ★ 为什么需要这节：v71 的标记只证明"至少是 v71 代次"，证明不了
#   v72 的**枚举隐藏**真的进了产物 —— 改了源码没重编照样全绿（铁律 142）。
#
# ★ 判据（与 v70/v71 同构）：
#   ① EXE 含**窄**串 `spoof_reg_enum` —— 配置解析器里的键名
#      （`r3shieldcore_config.cpp`），证明"引擎认识这个 ini 键"。
#   ② 两个架构的 DLL 都含**宽**串 `spoof_reg_enum` —— 枚举隐藏日志里的
#      ASCII 子串（`LOG(L"...（spoof_reg_enum，...）")`），
#      证明"索引重映射逻辑真的编进了 DLL"。
#      ⚠️ 必须用 `strings -el`（16 位）：中文是宽串，`-a` 只看 8 位
#         可打印序列，查的是另一个世界（铁律 193）。
#      ⚠️ 标记必须是 **ASCII 子串**：GNU `strings -el` 只输出 ASCII
#         可打印字符，**纯中文标记永远查不到**（会变成恒 FAIL 的判据）。
#   ③ ★ **前提检查**（铁律 117）：源码里必须有这三条，否则"键被改名"会
#      表现成"标记查不到"，被误当成"没重编"：
#        a) 配置键名      —— `r3shieldcore_config.cpp`
#        b) 标记日志      —— `registry_guard.cpp`
#        c) 重映射共享头  —— `registry_enum_codec.h`
#           （生产与探针共用一份，铁律 195：逻辑不许抄两份）
#   ④ ★ **负对照 / 出厂安全性质**（铁律 148 + 110）：随包 ini 里
#      `spoof_reg_enum` 必须**存在**且是**关**。
#      ⚠️ 顺序很重要：**先**确认键存在，**再**判它不是 1 —— 键不存在时
#         "没有 =1 的行"是**空真**（铁律 110）。
#   ★ 额外：v71 的 `spoof_reg` 与 v72 的 `spoof_reg_enum` 是**两个独立的
#      位** —— 上面两条判据一律用 `grep -w`（词边界），谁也不能满足对方
#      （否则"v71 被删、v72 还在"会假绿，铁律 199 同族）。
echo ""
echo "=== v72 代次标记（注册表枚举隐藏：索引重映射、跳过受保护项）==="

V72_MARK="spoof_reg_enum"
V72_SRC_CFG="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp"
V72_SRC_DLL="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/registry_guard.cpp"
V72_SRC_CODEC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/registry_enum_codec.h"
V72_INI="$DIST_DIR/r3shieldcore.ini"

if ! grep -qwF "$V72_MARK" "$V72_SRC_CFG" 2>/dev/null; then
    echo "[FAIL] 源码 $V72_SRC_CFG 里没有独立的 '$V72_MARK' —— 判据失去前提（键被改名了？）"
    fail=1
fi
if ! grep -qwF "$V72_MARK" "$V72_SRC_DLL" 2>/dev/null; then
    echo "[FAIL] 源码 $V72_SRC_DLL 里没有独立的 '$V72_MARK' —— 判据失去前提（标记被删了？）"
    fail=1
fi
# ★ 额外前提：重映射逻辑必须**仍在**那个共享头里（铁律 195：生产与探针共用一份）。
#   如果哪天有人把 codec 抄回 guard、把这个头删了，探针就会与生产漂移 —— 这里钉住。
if [ ! -f "$V72_SRC_CODEC" ]; then
    echo "[FAIL] 缺失 $V72_SRC_CODEC —— 重映射逻辑的共享头（生产与探针共用一份）不见了"
    fail=1
fi

V72_EXE="$DIST_DIR/R3 ShieldCore.exe"
if [ ! -f "$V72_EXE" ]; then
    echo "[FAIL] 缺失: $V72_EXE"
    fail=1
elif strings -a "$V72_EXE" | grep -qwF "$V72_MARK"; then
    echo "[ OK ] EXE 含 v72 标记 '$V72_MARK'（配置解析器认识这个 ini 键）"
else
    echo "[FAIL] EXE 里没有独立的 v72 标记 '$V72_MARK'"
    echo "       ⇒ dist 里的 EXE 是 v72 之前的构建（不认识 spoof_reg_enum）"
    fail=1
fi

for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    if strings -el "$dll" | grep -qwF "$V72_MARK"; then
        echo "[ OK ] $arch 位 DLL 含 v72 宽串标记 '$V72_MARK'（重映射逻辑已编入）"
    else
        echo "[FAIL] $arch 位 DLL 缺独立的 v72 宽串标记 '$V72_MARK'（用 strings -el 查）"
        echo "       ⇒ 该架构的 DLL 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
done

# ④ 出厂默认必须是关（负对照）
if [ ! -f "$V72_INI" ]; then
    echo "[FAIL] 缺失: $V72_INI（出厂默认值判据失去前提）"
    fail=1
elif ! grep -qE "^[[:space:]]*${V72_MARK}[[:space:]]*=" "$V72_INI"; then
    echo "[FAIL] $V72_INI 里**没有** ${V72_MARK}= 这一项 —— 判据失去前提"
    echo "       （缺键时\"没有 =1\"是空真，铁律 110）"
    fail=1
elif grep -qE "^[[:space:]]*${V72_MARK}[[:space:]]*=[[:space:]]*(1|on|yes|true)" "$V72_INI"; then
    echo "[FAIL] 随包 ini 把 ${V72_MARK} 打开了 —— 出厂默认必须**关**"
    echo "       （枚举隐藏会改变列表长度与顺序，默认配置行为必须与旧版一致）"
    fail=1
else
    echo "[ OK ] 随包 ini 里 ${V72_MARK} 存在且为**关**（出厂默认安全）"
fi

# ---------------------------------------------------------------------------
# v73 代次标记（摄像头帧替换：patch ReadSample vtable + 逐帧中性化）
# ---------------------------------------------------------------------------
#
# ★ 为什么需要这节：v72 的标记只证明"至少是 v72 代次"，证明不了
#   v73 的**摄像头帧替换**真的进了产物 —— 改了源码没重编照样全绿（铁律 142）。
#
# ★ 判据（与 v70/v71/v72 同构）：
#   ① EXE 含**窄**串 `spoof_camera` —— 配置解析器里的键名
#      （`r3shieldcore_config.cpp`），证明"引擎认识这个 ini 键"。
#   ② 两个架构的 DLL 都含**宽**串 `spoof_camera` —— 挂载成功日志里的
#      ASCII 子串（`LOG(L"CameraGuard: 摄像头帧替换已挂载（spoof_camera）...")`），
#      证明"vtable patch + 逐帧中性化逻辑真的编进了 DLL"。
#      ⚠️ 必须用 `strings -el`（16 位）：中文是宽串，`-a` 只看 8 位
#         可打印序列，查的是另一个世界（铁律 193）。
#      ⚠️ 标记必须是 **ASCII 子串**：GNU `strings -el` 只输出 ASCII
#         可打印字符，**纯中文标记永远查不到**（会变成恒 FAIL 的判据）。
#   ③ ★ **前提检查**（铁律 117）：源码里必须有这三条，否则"键被改名"会
#      表现成"标记查不到"，被误当成"没重编"：
#        a) 配置键名      —— `r3shieldcore_config.cpp`
#        b) 标记日志      —— `camera_guard.cpp`
#        c) 中性帧共享头  —— `camera_spoof_codec.h`
#           （生产与探针共用一份，铁律 195：逻辑不许抄两份）
#   ④ ★ **负对照 / 出厂安全性质**（铁律 148 + 110）：随包 ini 里
#      `spoof_camera` 必须**存在**且是**关**。
#      ⚠️ 顺序很重要：**先**确认键存在，**再**判它不是 1 —— 键不存在时
#         "没有 =1 的行"是**空真**（铁律 110）。
#   ★ 额外：`spoof_camera` 与 `spoof_screen` / `spoof_clipboard` /
#      `spoof_reg` / `spoof_reg_enum` 是**五个独立的位** —— 一律用
#      `grep -w`（词边界）。虽然本标记与那四个**互不为子串**，但统一口径
#      可以防止将来新增一个 `spoof_camera_xxx` 时踩同一个坑（铁律 209）。
echo ""
echo "=== v73 代次标记（摄像头帧替换：patch ReadSample vtable、逐帧中性化）==="

V73_MARK="spoof_camera"
V73_SRC_CFG="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_config.cpp"
V73_SRC_DLL="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/camera_guard.cpp"
V73_SRC_CODEC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/camera_spoof_codec.h"
V73_INI="$DIST_DIR/r3shieldcore.ini"

if ! grep -qwF "$V73_MARK" "$V73_SRC_CFG" 2>/dev/null; then
    echo "[FAIL] 源码 $V73_SRC_CFG 里没有独立的 '$V73_MARK' —— 判据失去前提（键被改名了？）"
    fail=1
fi
if ! grep -qwF "$V73_MARK" "$V73_SRC_DLL" 2>/dev/null; then
    echo "[FAIL] 源码 $V73_SRC_DLL 里没有独立的 '$V73_MARK' —— 判据失去前提（标记被删了？）"
    fail=1
fi
# ★ 额外前提：中性帧决策表必须**仍在**那个共享头里（铁律 195：生产与探针共用一份）。
#   如果哪天有人把 codec 抄回 guard、把这个头删了，探针就会与生产漂移 —— 这里钉住。
if [ ! -f "$V73_SRC_CODEC" ]; then
    echo "[FAIL] 缺失 $V73_SRC_CODEC —— 中性帧决策表的共享头（生产与探针共用一份）不见了"
    fail=1
fi

V73_EXE="$DIST_DIR/R3 ShieldCore.exe"
if [ ! -f "$V73_EXE" ]; then
    echo "[FAIL] 缺失: $V73_EXE"
    fail=1
elif strings -a "$V73_EXE" | grep -qwF "$V73_MARK"; then
    echo "[ OK ] EXE 含 v73 标记 '$V73_MARK'（配置解析器认识这个 ini 键）"
else
    echo "[FAIL] EXE 里没有独立的 v73 标记 '$V73_MARK'"
    echo "       ⇒ dist 里的 EXE 是 v73 之前的构建（不认识 spoof_camera）"
    fail=1
fi

for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    if strings -el "$dll" | grep -qwF "$V73_MARK"; then
        echo "[ OK ] $arch 位 DLL 含 v73 宽串标记 '$V73_MARK'（帧替换逻辑已编入）"
    else
        echo "[FAIL] $arch 位 DLL 缺独立的 v73 宽串标记 '$V73_MARK'（用 strings -el 查）"
        echo "       ⇒ 该架构的 DLL 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
done

# ④ 出厂默认必须是关（负对照）
if [ ! -f "$V73_INI" ]; then
    echo "[FAIL] 缺失: $V73_INI（出厂默认值判据失去前提）"
    fail=1
elif ! grep -qE "^[[:space:]]*${V73_MARK}[[:space:]]*=" "$V73_INI"; then
    echo "[FAIL] $V73_INI 里**没有** ${V73_MARK}= 这一项 —— 判据失去前提"
    echo "       （缺键时\"没有 =1\"是空真，铁律 110）"
    fail=1
elif grep -qE "^[[:space:]]*${V73_MARK}[[:space:]]*=[[:space:]]*(1|on|yes|true)" "$V73_INI"; then
    echo "[FAIL] 随包 ini 把 ${V73_MARK} 打开了 —— 出厂默认必须**关**"
    echo "       （帧替换会把\"打开失败\"变成\"打开成功但内容是假的\"，"
    echo "        默认配置行为必须与旧版一致）"
    fail=1
else
    echo "[ OK ] 随包 ini 里 ${V73_MARK} 存在且为**关**（出厂默认安全）"
fi

# ---- 附加判据：配置与日志工具（独立进程，不来自 Release/）--------------------
#   ★ 它由 build_cfgtool.sh **直接编进 dist**，没有 Release/ 那一侧的对照物，
#     所以不能像上面那样用 md5 比（那会变成"自己跟自己比"的空判据）。
#     判据改成两条：
#       ① 文件存在且体积合理（太小 = 根本没编进去）；
#       ② **比源码新** —— 防止"改了源码没重编"（铁律 119：只查存在 ⇒ 假绿）。
#     并且判据**自己要有前提**：源码不存在时直接 FAIL（铁律 117）。
echo ""
echo "=== 配置与日志工具（r3shieldcore-cfg.exe）==="
CFG_TOOL="$DIST_DIR/r3shieldcore-cfg.exe"
CFG_SRC="$PROJECT_ROOT/tools/r3shieldcore_cfg.cpp"
if [ ! -f "$CFG_SRC" ]; then
    echo "[FAIL] 源码不存在: $CFG_SRC（新鲜度判据失去前提）"
    fail=1
elif [ ! -f "$CFG_TOOL" ]; then
    echo "[FAIL] 缺失: $CFG_TOOL（先跑 bash build_cfgtool.sh）"
    fail=1
elif [ "$CFG_TOOL" -ot "$CFG_SRC" ]; then
    echo "[FAIL] $CFG_TOOL 比源码 $CFG_SRC 还旧 —— 改了源码没重编"
    fail=1
else
    cfg_sz=$(stat -c%s "$CFG_TOOL")
    if [ "$cfg_sz" -lt 50000 ]; then
        echo "[FAIL] $CFG_TOOL 只有 $cfg_sz 字节 —— 太小，明显不是正常产物"
        fail=1
    else
        echo "[ OK ] r3shieldcore-cfg.exe 存在且比源码新（$cfg_sz B）"
    fi
fi

echo ""
# ======================================================================
# v74：发布目录里**不得**有运行时残留的日志
# ======================================================================
# ★ 为什么这是一条闸门而不是洁癖：
#   这两个日志是**引擎自己跑起来之后写在 exe 同目录**的，不是发布内容。
#   谁在 dist 目录里直接跑过一次引擎，它们就会留下，然后被打进 zip / 安装包。
#   后果两条：
#     ① 泄漏：开发机上的键路径 / 进程路径 / 事件会随发布包发出去；
#     ② 骗人：`tools/spoof_e2e.sh` 的 `read_console` 在"引擎还没跑"时会退到读
#        这个文件 ⇒ 用户看到的是**上一次**的日志却以为是本次的（铁律 97）。
#   `deploy_dist.sh` 已经会清（2b 步），这里再加一道**验收** —— 光有清理
#   动作没有验收，等于"改了源码没闸门"（本项目吃过这个亏：铁律 119）。
# ★ 判据是"这两个**已知名**不存在"，不是通配 `*.log`：将来若真有随包发的
#   日志文件，通配会误杀（铁律 117：判据要窄）。
echo "=== v74 发布目录里没有运行时残留日志 ==="
# ★ 2026-10-16 加了第三个已知名 `r3shieldcore-cfg-console.log`（v80 引入）：
#   配置工具在预览模式下被 `R3SHIELDCORE_PREVIEW_LOG` 重定向出来的 stdout，
#   探针跑的是 dist 里的 cfg exe ⇒ 它就落在**发布目录**里（不是随包内容）。
#   ⚠️ 仍然只列已知名、不用通配 `*.log`（铁律 117）。
_stale_found=0
for _stale in r3shieldcore-console.log r3shieldcore-events.log r3shieldcore-cfg-console.log; do
    if [ -f "$DIST_DIR/$_stale" ]; then
        echo "[FAIL] dist 里有运行时残留: $_stale —— 它会随包发出去，且会让夹具读到旧日志"
        echo "       修法：跑 bash deploy_dist.sh（2b 步会清），或手动删掉它"
        _stale_found=1
    fi
done
if [ "$_stale_found" -eq 0 ]; then
    echo "[ OK ] 没有 r3shieldcore-console.log / r3shieldcore-events.log / r3shieldcore-cfg-console.log"
else
    fail=1
fi

# ======================================================================
# v75 代次标记（事务注册表 KTM：补 3 个 Transacted 的**准入判据**）
# ======================================================================
#
# ★ 为什么需要这节：v74 的判据只管"发布目录里没有运行时残留日志"，与代码代次无关。
#   而 v75 补的三个事务导出在别的地方**完全同构**于已有的 `NtOpenKey` ——
#   **没有新 ini 键、没有新 ABI 位** ⇒ 光看 v70~v73 那些标记，
#   区分不出"这一版到底补没补"（改了源码没重编照样全绿，铁律 142）。
#
# ★ 判据（与 v70~v73 同构，但**没有"ini 键存在且为关"那一条**，理由见 ④）：
#   ① ★ **前提检查**（铁律 117）：源码里必须有
#        a) 三个 Transacted 导出名 —— `QueueHook("NtOpenKeyTransacted", ...)`
#        b) 标记日志的 ASCII 子串 `spoof_reg_ktm` —— 挂载日志里那句
#      否则"标记查不到"会被误当成"没重编"，而真因是"标记被改名/删了"。
#   ② 两个架构的 DLL 都含**宽**串 `spoof_reg_ktm` —— 挂载成功日志里的
#      ASCII 子串，证明"KTM 挂载逻辑真的编进了 DLL"。
#      ⚠️ 必须用 `strings -el`（16 位）：中文是宽串，`-a` 只看 8 位可打印序列，
#         查的是另一个世界（铁律 193）。
#      ⚠️ 标记必须是 **ASCII 子串**：GNU `strings -el` 只输出 ASCII 可打印字符，
#         **纯中文标记永远查不到**（会变成恒 FAIL 的判据）。
#   ③ 两个架构的 DLL 都含**窄**串 `NtOpenKeyTransacted` /
#      `NtOpenKeyTransactedEx` / `NtCreateKeyTransacted` —— `QueueHook` 的
#      导出名窄字面量，证明"这三个导出名真的写进了代码"（光有日志不算，
#      日志可以空写、`QueueHook` 也可以挂到别的函数上）。
#      ⚠️ `NtOpenKeyTransacted` 是 `NtOpenKeyTransactedEx` 的**子串**
#         ⇒ 一律 `grep -w`（词边界）。虽然 `-w` 在这里恰好能靠"后面紧跟 `E`"
#         区分开，但统一口径可以防止将来新增 `NtOpenKeyTransacted2` 时踩坑
#         （铁律 209 同族）。
#   ④ ★★ **方向与 v70~v73 相反**：随包 ini 里**不得**出现 `spoof_reg_ktm` 这个键。
#      为什么反过来写：事务准入**故意不设独立开关** ——
#      事务打开与普通打开是**同一个决策**（都是"要不要放行这次准入"），
#      给它一个开关等于**人为开一个洞**（关掉它就能绕过 v71 读不到 / v72 看不见）。
#      所以正确的出厂性质是"**没有这个键**"。
#      ⚠️ 将来若有人真加了这个键，这条会红 —— 那是**提醒**，不是误报：
#         要么有人把它做成了可关闭的（这个决定要重新评估并写进 CHANGELOG），
#         要么只是命名撞车（那就改名）。
#      ⚠️ 这里刻意**不写**"键存在且为关" —— 对 v75 来说那是**空真**
#         （键本来就不该存在，"不存在时没有 =1 的行"永远成立，铁律 110）。
echo ""
echo "=== v75 代次标记（事务注册表 KTM：补 3 个 Transacted 的准入判据）==="

V75_MARK="spoof_reg_ktm"
V75_SYMS="NtOpenKeyTransacted NtOpenKeyTransactedEx NtCreateKeyTransacted"
V75_SRC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCoreLib/registry_guard.cpp"
V75_INI="$DIST_DIR/r3shieldcore.ini"

# ① 前提检查
if [ ! -f "$V75_SRC" ]; then
    echo "[FAIL] 源码不存在: $V75_SRC（v75 判据失去前提）"
    fail=1
else
    if ! grep -qwF "$V75_MARK" "$V75_SRC" 2>/dev/null; then
        echo "[FAIL] $V75_SRC 里没有独立的 '$V75_MARK' —— 标记日志被删了（判据失去前提）"
        fail=1
    fi
    for _sym in $V75_SYMS; do
        if ! grep -qwF "$_sym" "$V75_SRC" 2>/dev/null; then
            echo "[FAIL] $V75_SRC 里没有独立的 '$_sym' —— 那个 Transacted hook 不见了"
            fail=1
        fi
    done
fi

# ②③ 两个架构的 DLL
for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ ! -f "$dll" ]; then
        echo "[FAIL] 缺失: $dll"
        fail=1
        continue
    fi
    if strings -el "$dll" | grep -qwF "$V75_MARK"; then
        echo "[ OK ] $arch 位 DLL 含 v75 宽串标记 '$V75_MARK'（KTM 挂载日志已编入）"
    else
        echo "[FAIL] $arch 位 DLL 缺独立的 v75 宽串标记 '$V75_MARK'（用 strings -el 查）"
        echo "       ⇒ 该架构的 DLL 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
    _v75_miss=0
    for _sym in $V75_SYMS; do
        if ! strings -a "$dll" | grep -qwF "$_sym"; then
            echo "[FAIL] $arch 位 DLL 缺**窄**串 '$_sym'（QueueHook 的导出名）"
            _v75_miss=1
        fi
    done
    if [ "$_v75_miss" -eq 0 ]; then
        echo "[ OK ] $arch 位 DLL 含三个 Transacted 导出名的窄串（3/3）"
    else
        fail=1
    fi
done

# ④ 出厂性质：**不得**有独立开关（方向与 v70~v73 相反，见上面注释）
if [ ! -f "$V75_INI" ]; then
    echo "[FAIL] 缺失: $V75_INI（v75 出厂性质判据失去前提）"
    fail=1
elif grep -qE "^[[:space:]]*${V75_MARK}[[:space:]]*=" "$V75_INI"; then
    echo "[FAIL] 随包 ini 里出现了 ${V75_MARK}= —— 事务准入**不该有独立开关**"
    echo "       事务打开与普通打开是同一个决策；给它一个开关等于人为开一个洞"
    echo "       （关掉就能绕过 v71 读不到 / v72 看不见）。"
    echo "       要么删掉这个键，要么重新评估这个决定并写进 CHANGELOG。"
    fail=1
else
    echo "[ OK ] 随包 ini 里**没有** ${V75_MARK} 键（事务准入跟随主判据，无独立开关）"
fi

# ======================================================================
# v77 代次标记（主程序第 6 页签「高级」+ `--gui-preview` 界面预览）
# ======================================================================
#
# ★ 为什么需要这节：v76（规则引擎）只改 `tools/spoof_console.cpp` —— 那是**开发工具**，
#   **不进 dist、不进安装包**，所以 v76 刻意**没有**代次标记（判据 = "改了源码"≠"要进发布物"）。
#   而 v77 **改的是主程序 exe**（`R3 Shield Core.exe` 里多了一个页签 + 一个启动分流）
#   ⇒ **必须有标记**，否则"改了源码没重编"照样全绿（铁律 142）。
#
# ★ 判据：
#   ① ★ **前提检查**（铁律 117）：源码 `r3shieldcore_gui.cpp` 里必须有
#        a) `R3SHIELDCORE_START_TAB` —— 指定启动页签的环境变量名
#        b) `advanced` —— 新页签的键名
#      否则"标记查不到"会被误当成"没重编"，而真因是"标记被改名 / 删了"。
#   ② dist 的 `R3 Shield Core.exe` 含**宽**串 `R3SHIELDCORE_START_TAB`
#      —— 证明"启动页签分流逻辑真的编进了 exe"。
#      ⚠️ 必须用 `strings -el`（16 位）：GUI 里是 `L"..."` 宽字面量，
#         `-a` 看的是 8 位世界，查不到（铁律 193）。
#      ⚠️ 标记必须是 **ASCII 子串**：GNU `strings -el` 只输出 ASCII 可打印字符，
#         纯中文标记（比如页签名「高级」）**永远查不到** ⇒ 会变成恒 FAIL 的判据。
#   ③ dist 的 `R3 Shield Core.exe` 含**窄**串 `advanced`（页签键名）。
#      ⚠️ 用 `grep -w`：`advanced` 若将来成为更长键名（如 `advanced2`）的前缀，
#         裸 `grep -F` 会假绿（铁律 209 同族）。
echo ""
echo "=== v77 代次标记（主程序第 6 页签「高级」+ --gui-preview）==="

V77_MARK="R3SHIELDCORE_START_TAB"
V77_TAB="advanced"
V77_SRC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_gui.cpp"
V77_EXE="$DIST_DIR/R3 ShieldCore.exe"

# ① 前提检查
if [ ! -f "$V77_SRC" ]; then
    echo "[FAIL] 源码不存在: $V77_SRC（v77 判据失去前提）"
    fail=1
else
    if ! grep -qwF "$V77_MARK" "$V77_SRC" 2>/dev/null; then
        echo "[FAIL] $V77_SRC 里没有 '$V77_MARK' —— 启动页签分流被删了（判据失去前提）"
        fail=1
    fi
    if ! grep -qwF "$V77_TAB" "$V77_SRC" 2>/dev/null; then
        echo "[FAIL] $V77_SRC 里没有 '$V77_TAB' —— 第 6 页签的键名不见了"
        fail=1
    fi
fi

# ②③ dist 的主程序 exe
if [ ! -f "$V77_EXE" ]; then
    echo "[FAIL] 缺失: $V77_EXE"
    fail=1
else
    if strings -el "$V77_EXE" | grep -qwF "$V77_MARK"; then
        echo "[ OK ] EXE 含 v77 宽串标记 '$V77_MARK'（启动页签分流已编入）"
    else
        echo "[FAIL] EXE 缺 v77 宽串标记 '$V77_MARK'（用 strings -el 查）"
        echo "       ⇒ exe 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
    if strings -a "$V77_EXE" | grep -qwF "$V77_TAB"; then
        echo "[ OK ] EXE 含 v77 窄串 '$V77_TAB'（第 6 页签键名）"
    else
        echo "[FAIL] EXE 缺 v77 窄串 '$V77_TAB'"
        fail=1
    fi
fi

# ======================================================================
# v78 代次标记（「高级」页可编辑 + 规则文件路径两侧同源）
# ======================================================================
#
# ★ 为什么需要这节：v78 改的是**两个发布物** ——
#   · 主程序 `R3 Shield Core.exe` 里多了一个原生 EDIT 子控件、三道题的闸门、
#     以及"保存到规则文件"的动作；
#   · 引擎 `r3shieldcore-lib.dll` 里多了**启动时读规则文件**的逻辑。
#   ⇒ 两样都必须有标记，否则"改了源码没重编"照样全绿（铁律 142）。
#
# ★★ v80：编辑台（连同这些标记）**整块搬去了 cfg 工具** ——
#   所以本节里的"界面侧"从 `R3 Shield Core.exe` 换成了
#   `r3shieldcore-cfg.exe` + `tools/r3shieldcore_cfg.cpp`。
#   ⚠️ 标记没跟着搬家的话，这一节会**恒 FAIL**（源码里 grep 不到），
#      或者更糟：恒 PASS（查的还是旧位置，而旧位置已经被删空了）。
#
# ★ 判据：
#   ① ★ **前提检查**（铁律 117）：标记必须先在源码里存在，否则"查不到"
#      会被误当成"没重编"，而真因是"标记被改名 / 删了"。
#        a) `tools/r3shieldcore_cfg.cpp` 含 `R3SHIELDCORE_PREVIEW_ADV`
#           —— 预览模式给「高级」页预置界面状态的环境变量（v78 新增）。
#        b) `shared/r3shieldcore/rules_file.h` 存在且含 `r3shieldcore-rules.txt`
#           —— 规则文件名的**唯一一份**定义。
#   ② cfg 的 exe 含**宽**串 `R3SHIELDCORE_PREVIEW_ADV`
#      —— 证明「高级」页的新代码真的编进了那个 exe。
#   ③ ★★ **两侧同源**：cfg exe 与引擎 dll **都**含宽串
#      `r3shieldcore-rules.txt`。
#      这一条是本节的重点：界面**写**这个文件、引擎**读**它，两边必须指向
#      同一个名字。只查一侧的话，"界面存到 A、引擎读 B"这种
#      **界面显示已保存、引擎一条都不生效**的故障查不出来（铁律 195/127）。
#      ⚠️ `kFileName` 是 `L"..."` 宽字面量 ⇒ 必须用 `strings -el`（16 位），
#         `-a` 看的是 8 位世界，查不到（铁律 193）。
echo ""
echo "=== v78 代次标记（「高级」页可编辑 + 规则文件路径两侧同源）==="

V78_MARK="R3SHIELDCORE_PREVIEW_ADV"
V78_RULES="r3shieldcore-rules.txt"
V78_SRC="$PROJECT_ROOT/tools/r3shieldcore_cfg.cpp"
V78_RULES_HDR="$PROJECT_ROOT/R3ShieldCore/shared/r3shieldcore/rules_file.h"
V78_EXE="$DIST_DIR/r3shieldcore-cfg.exe"

# ① 前提检查
if [ ! -f "$V78_SRC" ]; then
    echo "[FAIL] 源码不存在: $V78_SRC（v78 判据失去前提）"
    fail=1
elif ! grep -qwF "$V78_MARK" "$V78_SRC" 2>/dev/null; then
    echo "[FAIL] $V78_SRC 里没有 '$V78_MARK' —— 「高级」页的预览状态开关被删了"
    fail=1
fi
if [ ! -f "$V78_RULES_HDR" ]; then
    echo "[FAIL] 缺失: $V78_RULES_HDR（规则文件名的唯一一份定义 —— 两侧同源的前提）"
    fail=1
elif ! grep -qF "$V78_RULES" "$V78_RULES_HDR" 2>/dev/null; then
    echo "[FAIL] $V78_RULES_HDR 里没有 '$V78_RULES' —— 文件名标记不见了"
    fail=1
fi

# ②③ dist 的两个发布物
if [ ! -f "$V78_EXE" ]; then
    echo "[FAIL] 缺失: $V78_EXE"
    fail=1
else
    if strings -el "$V78_EXE" | grep -qwF "$V78_MARK"; then
        echo "[ OK ] cfg EXE 含 v78 宽串标记 '$V78_MARK'（「高级」页可编辑已编入）"
    else
        echo "[FAIL] cfg EXE 缺 v78 宽串标记 '$V78_MARK'（用 strings -el 查）"
        echo "       ⇒ cfg exe 没重编，或标记被改名 / 改成了窄串"
        fail=1
    fi
fi

# ★ 两侧同源：cfg exe（写）与 dll（读）都要带规则文件名。
v78_src_exe=0
v78_src_dll=0
if [ -f "$V78_EXE" ] && strings -el "$V78_EXE" | grep -qF "$V78_RULES"; then
    v78_src_exe=1
fi
for arch in 64 32; do
    dll="$DIST_DIR/$arch/r3shieldcore-lib.dll"
    if [ -f "$dll" ] && strings -el "$dll" | grep -qF "$V78_RULES"; then
        v78_src_dll=1
    fi
done
if [ "$v78_src_exe" -eq 1 ]; then
    echo "[ OK ] cfg EXE 含宽串 '$V78_RULES'（界面**写**的那个文件名）"
else
    echo "[FAIL] cfg EXE 缺宽串 '$V78_RULES' ⇒ 界面侧没有把 rules_file.h 编进去"
    echo "       （用 strings -el 查；写成 -a 永远查不到，铁律 193）"
    fail=1
fi
if [ "$v78_src_dll" -eq 1 ]; then
    echo "[ OK ] 引擎 DLL 含宽串 '$V78_RULES'（引擎**读**的那个文件名 —— 两侧同源）"
else
    echo "[FAIL] 64/32 的 r3shieldcore-lib.dll 都缺宽串 '$V78_RULES'"
    echo "       ⇒ 引擎侧没有接入规则文件读取（v78 的引擎那一半没编进去）"
    fail=1
fi

echo ""
# ---------------------------------------------------------------------------
# v79 代次标记（题干/解析渲染 Markdown + 规则输入实时提示）
# ---------------------------------------------------------------------------
# ★ 为什么需要这节：v79 加的东西**全部只影响界面那一侧**（引擎 DLL 一行没动），
#   所以它最容易出现"源码改了、包里的 exe 还是旧的"这种**看不见的不同步** ——
#   而症状只是"题目里的星号没渲染 / 输入时没有提示"，不会报任何错。
#
# ★★ v80：这一整套（题干渲染 + 实时提示 + 编辑台）搬去了 cfg 工具 ⇒
#   "界面那一侧"从 `R3 Shield Core.exe` 换成了 `r3shieldcore-cfg.exe`。
#
# 三组判据：
#   ① 共享头真的在（`md_inline.h`）+ 解析器命名空间在；
#   ② 两个接入点真的在（cfg 源码里 `MdDraw` / `AdvComputeHint`）；
#   ③ **exe 里能查到 v79 独有的宽串** `R3SHIELDCORE_PREVIEW_EDIT`
#      —— 那是 v79 新增的预览环境变量，只在界面 exe 里出现。
#      ⚠️ 为什么不用中文当标记：`strings -el` 只吐 ASCII 区间的宽字符，
#         中文标记根本查不到（查不到就会被当成"没编进去"，假 FAIL）。
echo "=== v79 代次标记（题干 Markdown 渲染 + 规则输入实时提示）==="
V79_MD_HDR="$PROJECT_ROOT/R3ShieldCore/shared/r3shieldcore/md_inline.h"
V79_MD_NS="R3ShieldCoreMd"
V79_CODEC="$PROJECT_ROOT/R3ShieldCore/shared/r3shieldcore/rules_codec.h"
V79_HINT_FN="NextStepHint"
V79_GUI="$PROJECT_ROOT/tools/r3shieldcore_cfg.cpp"
V79_MARK="R3SHIELDCORE_PREVIEW_EDIT"
V79_EXE="$DIST_DIR/r3shieldcore-cfg.exe"

if [ ! -f "$V79_MD_HDR" ]; then
    echo "[FAIL] 缺失: $V79_MD_HDR（Markdown 行内解析器 —— 渲染的前提）"
    fail=1
elif ! grep -qF "$V79_MD_NS" "$V79_MD_HDR" 2>/dev/null; then
    echo "[FAIL] $V79_MD_HDR 里没有 '$V79_MD_NS' —— 解析器命名空间不见了"
    fail=1
else
    echo "[ OK ] 共享头 md_inline.h 在（含 '$V79_MD_NS'）"
fi

if [ ! -f "$V79_CODEC" ]; then
    echo "[FAIL] 缺失: $V79_CODEC（输入提示所在）"
    fail=1
elif ! grep -qF "$V79_HINT_FN" "$V79_CODEC" 2>/dev/null; then
    echo "[FAIL] $V79_CODEC 里没有 '$V79_HINT_FN' —— 输入提示被删了"
    fail=1
else
    echo "[ OK ] rules_codec.h 含 '$V79_HINT_FN'（输入提示）"
fi

if [ ! -f "$V79_GUI" ]; then
    echo "[FAIL] 缺失: $V79_GUI"
    fail=1
else
    v79_md=0
    v79_hint=0
    grep -qF "MdDraw" "$V79_GUI" 2>/dev/null && v79_md=1
    grep -qF "AdvComputeHint" "$V79_GUI" 2>/dev/null && v79_hint=1
    if [ "$v79_md" -eq 1 ] && [ "$v79_hint" -eq 1 ]; then
        echo "[ OK ] cfg 源码里两个接入点都在（MdDraw / AdvComputeHint）"
    else
        echo "[FAIL] cfg 源码缺接入点：MdDraw=$v79_md AdvComputeHint=$v79_hint"
        fail=1
    fi
fi

if [ ! -f "$V79_EXE" ]; then
    echo "[FAIL] 缺失: $V79_EXE"
    fail=1
else
    if strings -el "$V79_EXE" | grep -qwF "$V79_MARK"; then
        echo "[ OK ] cfg EXE 含 v79 宽串标记 '$V79_MARK'（实时提示/预览支持已编入）"
    else
        echo "[FAIL] cfg EXE 缺 v79 宽串标记 '$V79_MARK'（用 strings -el 查）"
        echo "       ⇒ 包里的 cfg exe 不是 v79 产物（重新 build_cfgtool.sh + deploy_dist.sh）"
        fail=1
    fi
fi

# ---------------------------------------------------------------------------
# v80 代次标记（「高级」编辑台搬去 cfg + 主程序只留跳转入口）
# ---------------------------------------------------------------------------
# ★ 为什么需要这节：v80 改的是**两个发布物**，而且它们之间有一份**契约** ——
#   · 主程序 `R3 Shield Core.exe`：启动时顺手拉起 cfg，页内留一个跳转按钮；
#   · cfg `r3shieldcore-cfg.exe`：多了第 3 个页签「高级」+ 单实例/被激活。
#
#   契约（窗口类名 / 激活消息名 / 页号 / exe 名）**只定义一处** ——
#   共享头 `shared/r3shieldcore/cfg_launch.h`（铁律 127）。
#   两边各写一份的后果是**静默对不上**：主程序照样"启动成功"，窗口却
#   永远停在第 0 页，而两边都不报错 —— 这正是最难查的一类故障。
#   ⇒ 所以本节**两侧都要查，而且查的是同一个字符串**。
#
# ★ 判据：
#   ① ★ **前提检查**（铁律 117）：
#        a) `cfg_launch.h` 存在，且含窗口类名 / 激活消息名 / exe 名；
#        b) 主程序源码含 `cfg_launch.h` + 跳转动作 `AdvLaunchCfg`；
#        c) cfg 源码含 `kQuietSwitch`（"顺手拉起"的安静标记）。
#   ② ★★ **两侧同源**：主程序 exe 与 cfg exe **都**含宽串
#      `R3ShieldCoreCfg.Activate`（激活消息名）与 `r3shieldcore-cfg.exe`（exe 名）。
#      ⚠️ 只查一侧的话，"主程序点名 A、cfg 注册的是 B"这种
#         **点了没反应**的故障查不出来（铁律 195/127）。
#   ③ 主程序 exe 含宽串 `R3SHIELDCORE_PREVIEW_JUMP`（v80 新增的预览开关）
#      —— 证明"跳转页"的新代码真的编进了主程序。
#   ④ cfg exe 含宽串 `R3SHIELDCORE_PREVIEW_LOG`（v80 新增）
#      —— 证明日志重定向那段真的编进了 cfg。
#      ⚠️ 宽串必须用 `strings -el`（16 位），`-a` 看的是 8 位世界（铁律 193）。
echo "=== v80 代次标记（「高级」编辑台搬去 cfg + 主程序跳转入口）==="

V80_HDR="$PROJECT_ROOT/R3ShieldCore/shared/r3shieldcore/cfg_launch.h"
V80_CLASS="R3ShieldCoreCfgWnd"
V80_MSG="R3ShieldCoreCfg.Activate"
V80_EXENAME="r3shieldcore-cfg.exe"
V80_QUIET="kQuietSwitch"
V80_MAIN_SRC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_gui.cpp"
V80_CFG_SRC="$PROJECT_ROOT/tools/r3shieldcore_cfg.cpp"
V80_MAIN_EXE="$DIST_DIR/R3 ShieldCore.exe"
V80_CFG_EXE="$DIST_DIR/r3shieldcore-cfg.exe"

# ① 前提检查
if [ ! -f "$V80_HDR" ]; then
    echo "[FAIL] 缺失: $V80_HDR（启动/激活契约的唯一一份定义 —— 两侧同源的前提）"
    fail=1
else
    v80_hdr_ok=1
    for mark in "$V80_CLASS" "$V80_MSG" "$V80_EXENAME"; do
        if ! grep -qF "$mark" "$V80_HDR" 2>/dev/null; then
            echo "[FAIL] $V80_HDR 里没有 '$mark' —— 契约被改了名，两侧会静默对不上"
            v80_hdr_ok=0
            fail=1
        fi
    done
    if [ "$v80_hdr_ok" -eq 1 ]; then
        echo "[ OK ] cfg_launch.h 含契约三件套（类名 / 激活消息 / exe 名）"
    fi
fi

if [ ! -f "$V80_MAIN_SRC" ]; then
    echo "[FAIL] 缺失: $V80_MAIN_SRC"
    fail=1
else
    v80_hdr_inc=0
    v80_action=0
    grep -qF "cfg_launch.h" "$V80_MAIN_SRC" 2>/dev/null && v80_hdr_inc=1
    grep -qF "AdvLaunchCfg" "$V80_MAIN_SRC" 2>/dev/null && v80_action=1
    if [ "$v80_hdr_inc" -eq 1 ] && [ "$v80_action" -eq 1 ]; then
        echo "[ OK ] 主程序源码含 cfg_launch.h + 跳转动作 AdvLaunchCfg"
    else
        echo "[FAIL] 主程序源码缺：cfg_launch.h=$v80_hdr_inc AdvLaunchCfg=$v80_action"
        fail=1
    fi
fi

if [ ! -f "$V80_CFG_SRC" ]; then
    echo "[FAIL] 缺失: $V80_CFG_SRC"
    fail=1
elif ! grep -qF "$V80_QUIET" "$V80_CFG_SRC" 2>/dev/null; then
    echo "[FAIL] $V80_CFG_SRC 里没有 '$V80_QUIET' —— 单实例的「安静退出」分支被删了"
    echo "       （删掉它的后果：UIAccess 父子实例并发拉起时，第二个 cfg 会"
    echo "         去激活已有窗口、把 cfg 抢到前台打断用户）"
    fail=1
else
    echo "[ OK ] cfg 源码含 '$V80_QUIET'（顺手拉起时安静退出）"
fi

# ①b ★★ 单实例互斥体名也必须在契约头里（铁律 127/266）
#
#   为什么它也算"契约"：这个名字有**两个消费者** ——
#     ① cfg 自己（拦第二个实例）；② **探针**（判断"上一个 cfg 真的走了"）。
#   探针不能只看"窗口消没消失"：它清上一轮走的是 `TerminateProcess`（**异步**），
#   窗口没了而互斥体还在 ⇒ 立刻 `CreateProcess` ⇒ 新实例撞上
#   `ERROR_ALREADY_EXISTS` ⇒ **静默早退**（连日志都不建，因为早退发生在
#   stdout 重定向**之前**）⇒ 症状是"窗口没出现"，**看着像崩溃**（铁律 266）。
#   ⇒ 名字退回成 cfg 里的字面量 = 探针再也拿不到它 = 那个 race 又回来。
V80_MUTEX="kSingleInstanceMutex"
V80_MUTEX_STR='Local\R3ShieldCoreCfg.SingleInstance'
if [ -f "$V80_HDR" ]; then
    # ⚠️ 必须 `-w`（词边界）—— 裸 `-F` 会让 `kSingleInstanceMutex_TMP` **满足**
    #    `kSingleInstanceMutex`（子串包含）⇒ 改名后闸门**照样 PASS** = 假绿。
    #    实测：第一版就是裸 `-qF`，负对照（改名 + `_TMP`）**没变红**（铁律 209）。
    if grep -qwF "$V80_MUTEX" "$V80_HDR" 2>/dev/null; then
        echo "[ OK ] cfg_launch.h 含 '$V80_MUTEX'（单实例互斥体名 —— 探针靠它等上一轮真的走了）"
    else
        echo "[FAIL] $V80_HDR 里没有 '$V80_MUTEX' —— 互斥体名退回成 cfg 里的字面量了"
        echo "       （后果：探针只能靠'窗口消失'判断 ⇒ 撞 TerminateProcess 的异步 race，"
        echo "         表现为「窗口没出现」这种看着像崩溃的假红，铁律 266）"
        fail=1
    fi
fi

# ②③④ dist 的两个发布物
v80_main_ok=1
if [ ! -f "$V80_MAIN_EXE" ]; then
    echo "[FAIL] 缺失: $V80_MAIN_EXE"
    fail=1
    v80_main_ok=0
else
    if strings -el "$V80_MAIN_EXE" | grep -qF "$V80_MSG"; then
        echo "[ OK ] 主程序 EXE 含宽串 '$V80_MSG'（它**点名**用的那个消息名）"
    else
        echo "[FAIL] 主程序 EXE 缺宽串 '$V80_MSG' ⇒ 跳转那半边没编进去"
        fail=1
        v80_main_ok=0
    fi
    if strings -el "$V80_MAIN_EXE" | grep -qF "$V80_EXENAME"; then
        echo "[ OK ] 主程序 EXE 含宽串 '$V80_EXENAME'（它要拉起的那个 exe 名）"
    else
        echo "[FAIL] 主程序 EXE 缺宽串 '$V80_EXENAME'"
        fail=1
        v80_main_ok=0
    fi
    if strings -el "$V80_MAIN_EXE" | grep -qwF "R3SHIELDCORE_PREVIEW_JUMP"; then
        echo "[ OK ] 主程序 EXE 含 v80 宽串标记 'R3SHIELDCORE_PREVIEW_JUMP'"
    else
        echo "[FAIL] 主程序 EXE 缺 v80 宽串标记 'R3SHIELDCORE_PREVIEW_JUMP'"
        fail=1
        v80_main_ok=0
    fi
fi

if [ ! -f "$V80_CFG_EXE" ]; then
    echo "[FAIL] 缺失: $V80_CFG_EXE"
    fail=1
else
    if strings -el "$V80_CFG_EXE" | grep -qF "$V80_MSG"; then
        echo "[ OK ] cfg EXE 含宽串 '$V80_MSG'（它**应答**用的那个消息名 —— 两侧同源）"
    else
        echo "[FAIL] cfg EXE 缺宽串 '$V80_MSG' ⇒ 被激活那半边没编进去"
        echo "       （主程序点名了、cfg 不认，症状就是「点了没反应」）"
        fail=1
    fi
    if strings -el "$V80_CFG_EXE" | grep -qF "$V80_CLASS"; then
        echo "[ OK ] cfg EXE 含宽串 '$V80_CLASS'（窗口类名 —— 主程序靠它找窗口）"
    else
        echo "[FAIL] cfg EXE 缺宽串 '$V80_CLASS'"
        fail=1
    fi
    if strings -el "$V80_CFG_EXE" | grep -qwF "R3SHIELDCORE_PREVIEW_LOG"; then
        echo "[ OK ] cfg EXE 含 v80 宽串标记 'R3SHIELDCORE_PREVIEW_LOG'"
    else
        echo "[FAIL] cfg EXE 缺 v80 宽串标记 'R3SHIELDCORE_PREVIEW_LOG'"
        fail=1
    fi
    # ★ 互斥体名真的编进去了（而不是"常量改了名、字面量还在别处"）
    #   ⚠️ 同样要 `-w`（见上面 ①b 的说明，铁律 209）。
    if strings -el "$V80_CFG_EXE" | grep -qwF "$V80_MUTEX_STR"; then
        echo "[ OK ] cfg EXE 含宽串 '$V80_MUTEX_STR'（单实例互斥体名已编入）"
    else
        echo "[FAIL] cfg EXE 缺宽串 '$V80_MUTEX_STR' ⇒ 单实例保护没编进去"
        fail=1
    fi
fi
if [ "$v80_main_ok" -eq 1 ]; then
    echo "[ OK ] 主程序 EXE 三件套齐全（消息名 / exe 名 / v80 预览开关）"
fi

# ---------------------------------------------------------------------------
# v81 代次标记（配置工具 ⇄ 引擎的命名管道 IPC）
# ---------------------------------------------------------------------------
# ★ 为什么需要这节：v81 让 cfg 工具**不再自己 tail 日志文件**，改为向引擎
#   **索取**「进程内事件流」（`R3ShieldCoreStats` 环形缓冲只活在引擎进程里，
#   不进共享内存 ⇒ 跨进程只能问）。两侧之间新增一份**线协议契约** ——
#   管道名 / VERB / 转义规则 / 字段名，全部只定义一处：
#   共享头 `shared/r3shieldcore/cfg_ipc.h`（铁律 127）。
#
# ★★ 谁在服务、谁在请求（这里最容易搞错，写错就会去查错文件）：
#   · **服务端 = 主程序 `R3 Shield Core.exe`** —— 它才是持有引擎控制块、
#     能碰 `GlobalHookSession` 共享内存的那个进程（`PollSync(engineControl)`
#     在主循环里跑）。代码：`R3ShieldCore/r3shieldcore_cfgipc.cpp`，
#     由 `build.sh` 的 `build_demo` 编进主程序。
#   · **客户端 = cfg `r3shieldcore-cfg.exe`** —— 它用共享头里的 `Ipc::Call`
#     发请求。
#   ⚠️ 我曾一度以为服务端在引擎 DLL 里 —— 错。DLL 里**没有**管道名宽串，
#      拿"引擎 DLL 缺宽串"当判据会得到**假 FAIL**。判据必须盯**主程序 exe**。
#
# ★ 判据：
#   ① ★ **前提检查**（铁律 117）：
#        a) `cfg_ipc.h` 存在，且含管道名前缀 / 至少一个 VERB / 转义函数；
#        b) 服务端源码 `r3shieldcore_cfgipc.cpp` 存在且含 `PipeName`；
#        c) 客户端源码 `tools/r3shieldcore_cfg.cpp` 含 `cfg_ipc.h` + `Ipc::Call`；
#        d) `build.sh` 的 sources 里真的列了 `r3shieldcore_cfgipc.cpp`
#           —— 漏这一行的症状是**链接期十几条 LNK2001**，极易被当"环境问题"；
#   ② ★★ **两侧同源**：主程序 exe（服务端）与 cfg exe（客户端）
#      **都**含宽串 `\\.\pipe\R3ShieldCoreCfgIpc`（管道名）。
#      这是整条链唯一的"接头" —— 任一侧改名 ⇒ 症状是"引擎没在运行"
#      （伪装成**引擎没跑**，实际是名字对不上），极难查（铁律 195/127）。
#   ③ 两侧都含窄串 VERB `HELLO`（握手）—— 证明协议常量真的编进去。
#      ⚠️ 只查一侧的话，"客户端发 HELLO、服务端不认"查不出来。
#   ④ cfg exe 含 v81 宽串标记 `R3SHIELDCORE_PREVIEW_LOGSRC`
#      —— 证明"日志页「事件日志 / 服务日志」两项 + 事件日志走服务端"那段界面
#         真的编进了 cfg。（★ 该标记是**预览环境变量名**，只在预览模式生效。）
#      ⚠️ 宽串必须用 `strings -el`（16 位），`-a` 看的是 8 位世界（铁律 193）。
#
# ★★ 代次标记搬家提醒（铁律 255）：v80 已把「高级」编辑台整块搬去过 cfg，
#   那次教训是**标记跟着代码走、闸门路径没跟** ⇒ 闸门查了个空文件却**恒 PASS**。
#   本节的两个宽串都在**当前**所在文件里核实过，不在旧位置。
echo "=== v81 代次标记（配置工具 ⇄ 引擎 管道 IPC）==="

V81_HDR="$PROJECT_ROOT/R3ShieldCore/shared/r3shieldcore/cfg_ipc.h"
V81_PIPE_PREFIX='\\.\pipe\R3ShieldCoreCfgIpc'
V81_VERB="HELLO"
V81_SRV_SRC="$PROJECT_ROOT/R3ShieldCore/R3ShieldCore/r3shieldcore_cfgipc.cpp"
V81_CLI_SRC="$PROJECT_ROOT/tools/r3shieldcore_cfg.cpp"
V81_BUILD="$PROJECT_ROOT/build.sh"
V81_MAIN_EXE="$DIST_DIR/R3 ShieldCore.exe"
V81_CFG_EXE="$DIST_DIR/r3shieldcore-cfg.exe"

# ① 前提检查
v81_pre_ok=1
if [ ! -f "$V81_HDR" ]; then
    echo "[FAIL] 缺失: $V81_HDR（线协议契约的唯一一份定义 —— 两侧同源的前提）"
    fail=1
    v81_pre_ok=0
else
    v81_hdr_pipe=0
    v81_hdr_verb=0
    v81_hdr_esc=0
    grep -qF "R3ShieldCoreCfgIpc" "$V81_HDR" 2>/dev/null && v81_hdr_pipe=1
    grep -qF "HELLO" "$V81_HDR" 2>/dev/null && v81_hdr_verb=1
    grep -qE "Escape|Unescape" "$V81_HDR" 2>/dev/null && v81_hdr_esc=1
    if [ "$v81_hdr_pipe" -eq 1 ] && [ "$v81_hdr_verb" -eq 1 ] && [ "$v81_hdr_esc" -eq 1 ]; then
        echo "[ OK ] cfg_ipc.h 含契约三件套（管道名 / VERB / 转义规则）"
    else
        echo "[FAIL] $V81_HDR 契约不全：管道名=$v81_hdr_pipe VERB=$v81_hdr_verb 转义=$v81_hdr_esc"
        fail=1
        v81_pre_ok=0
    fi
fi

if [ ! -f "$V81_SRV_SRC" ]; then
    echo "[FAIL] 缺失: $V81_SRV_SRC（管道服务端实现）"
    fail=1
    v81_pre_ok=0
elif ! grep -qF "PipeName" "$V81_SRV_SRC" 2>/dev/null; then
    echo "[FAIL] $V81_SRV_SRC 里没有 'PipeName' —— 服务端没接共享头的管道名"
    fail=1
    v81_pre_ok=0
fi

if [ ! -f "$V81_CLI_SRC" ]; then
    echo "[FAIL] 缺失: $V81_CLI_SRC"
    fail=1
    v81_pre_ok=0
else
    v81_cli_inc=0
    v81_cli_call=0
    grep -qF "cfg_ipc.h" "$V81_CLI_SRC" 2>/dev/null && v81_cli_inc=1
    grep -qF "Ipc::Call" "$V81_CLI_SRC" 2>/dev/null && v81_cli_call=1
    if [ "$v81_cli_inc" -eq 1 ] && [ "$v81_cli_call" -eq 1 ]; then
        echo "[ OK ] cfg 源码含 cfg_ipc.h + 客户端调用 Ipc::Call（走共享头，不自己编协议）"
    else
        echo "[FAIL] cfg 源码缺：cfg_ipc.h=$v81_cli_inc Ipc::Call=$v81_cli_call"
        echo "       （自己另写一份协议 ⇒ 与引擎静默对不上，铁律 127）"
        fail=1
        v81_pre_ok=0
    fi
fi

if [ ! -f "$V81_BUILD" ]; then
    echo "[FAIL] 缺失: $V81_BUILD"
    fail=1
    v81_pre_ok=0
elif ! grep -qF "r3shieldcore_cfgipc.cpp" "$V81_BUILD" 2>/dev/null; then
    echo "[FAIL] build.sh 的 sources 里没有 'r3shieldcore_cfgipc.cpp'"
    echo "       ⇒ 服务端实现没编进主程序（症状是链接期十几条 LNK2001，"
    echo "         极易被误当成环境问题）"
    fail=1
    v81_pre_ok=0
fi
if [ "$v81_pre_ok" -eq 1 ]; then
    echo "[ OK ] v81 前提齐全（共享头 / 服务端源码 / 客户端接入 / build.sh 源清单）"
fi

# ② 两侧同源：管道名宽串（这一条是整条链的"接头"）
if [ ! -f "$V81_MAIN_EXE" ]; then
    echo "[FAIL] 缺失: $V81_MAIN_EXE（服务端所在进程）"
    fail=1
else
    if strings -el "$V81_MAIN_EXE" | grep -qF "$V81_PIPE_PREFIX"; then
        echo "[ OK ] 主程序 EXE 含宽串管道名 '$V81_PIPE_PREFIX'（服务端已编入）"
    else
        echo "[FAIL] 主程序 EXE 缺宽串管道名 ⇒ 服务端那半边没编进去"
        echo "       （cfg 会一直显示「引擎未运行」，而引擎其实在跑）"
        fail=1
    fi
fi

if [ ! -f "$V81_CFG_EXE" ]; then
    echo "[FAIL] 缺失: $V81_CFG_EXE"
    fail=1
else
    if strings -el "$V81_CFG_EXE" | grep -qF "$V81_PIPE_PREFIX"; then
        echo "[ OK ] cfg EXE 含宽串管道名 '$V81_PIPE_PREFIX'（客户端已编入 —— 两侧同源）"
    else
        echo "[FAIL] cfg EXE 缺宽串管道名 ⇒ 客户端那半边没编进去"
        fail=1
    fi
    if strings -el "$V81_CFG_EXE" | grep -qwF "R3SHIELDCORE_PREVIEW_LOGSRC"; then
        echo "[ OK ] cfg EXE 含 v81 宽串标记 'R3SHIELDCORE_PREVIEW_LOGSRC'（日志页事件日志/服务日志切换已编入）"
    else
        echo "[FAIL] cfg EXE 缺 v81 宽串标记 'R3SHIELDCORE_PREVIEW_LOGSRC'"
        echo "       ⇒ 包里的 cfg exe 不是 v81 产物（重新 build_cfgtool.sh + deploy_dist.sh）"
        fail=1
    fi
fi

# ③ 两侧都含 VERB（协议常量真的编进去）
if [ -f "$V81_MAIN_EXE" ] && [ -f "$V81_CFG_EXE" ]; then
    v81_srv_verb=0
    v81_cli_verb=0
    strings -a "$V81_MAIN_EXE" | grep -qE "^$V81_VERB$" && v81_srv_verb=1
    strings -a "$V81_CFG_EXE"  | grep -qE "^$V81_VERB$" && v81_cli_verb=1
    if [ "$v81_srv_verb" -eq 1 ] && [ "$v81_cli_verb" -eq 1 ]; then
        echo "[ OK ] 两侧 EXE 都含 VERB '$V81_VERB'（协议常量同源）"
    else
        echo "[FAIL] VERB '$V81_VERB' 缺失：主程序=$v81_srv_verb cfg=$v81_cli_verb"
        echo "       （只查一侧 ⇒ 「客户端发、服务端不认」查不出来）"
        fail=1
    fi
fi

echo ""
if [ "$fail" -eq 0 ]; then
    echo "结果: PASS —— dist 与构建产物一致，双架构同代次，且带 v66/v67/v69/v70/v71/v72/v73/v74/v75/v77/v78/v79/v80/v81 标记。"
    exit 0
fi
echo "结果: FAIL —— 发布目录与构建产物不同步，**不要打包**。"
exit 1