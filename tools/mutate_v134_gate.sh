#!/usr/bin/env bash
# v134 发布闸门的变异测试：逐条破坏被测事实，确认闸门真的报红。
#
# ★ 为什么必须做：v134 段 17 条判据全是 grep。grep 判据最容易出的问题是
#   "正则写错 ⇒ 恒绿"，比没有判据更糟（铁律 142：只查存在 ⇒ 假绿）。
#
# ★★ 上一版脚本被中途 kill 时留下了 `return true; // MUTANT`（安全底线被破坏
#    的状态）—— 那是最危险的一种残留：闸门会红，但人以为"只是在测变异"。
#    ⇒ 这一版三处改进：
#      ① **只在开头取一次** pristine 备份（原来每次变异前覆盖备份，
#         一旦 kill 在"变异后/恢复前"，备份本身可能是脏的）；
#      ② `trap ... EXIT INT TERM` —— 任何退出路径都先还原；
#      ③ 每条变异独立可跑（`--only=M1`），不必一次跑完全部。
#
# ★ 隔离手段：变异后把源文件 mtime 恢复成原值（touch -r pristine），
#   否则 ⑦「DLL 比源码新」也会一起红，就分不清是谁在报。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

SGRD="$ROOT/R3ShieldCore/R3ShieldCoreLib/screen_guard.cpp"
IMG="$ROOT/R3ShieldCore/R3ShieldCoreLib/screen_spoof_image.h"
SHARED="$ROOT/R3ShieldCore/shared/r3shieldcore/r3shieldcore_shared.h"
INI="$ROOT/dist/R3ShieldCore-x64/r3shieldcore.ini"
BAK="$ROOT/_t/mutbak"
mkdir -p "$BAK"

ONLY=""
for a in "$@"; do
    case "$a" in
        --only=*) ONLY="${a#--only=}" ;;
    esac
done

# ---- pristine 备份（只在开头取一次；已存在且干净则复用，避免把脏文件当基线）----
take_pristine() {  # $1=源  $2=备份名
    local src="$1" dst="$BAK/$2"
    if [ -f "$dst" ] && ! grep -q "MUTANT" "$dst" 2>/dev/null; then
        cp -p "$dst" "$src"          # 复用干净备份，先把源拉回基线
    else
        cp -p "$src" "$dst"
    fi
    if grep -q "MUTANT" "$dst" 2>/dev/null; then
        echo "[FATAL] 备份 $2 本身含 MUTANT —— 先手工还原源码再跑" >&2
        exit 2
    fi
}
take_pristine "$SGRD"   screen_guard.cpp
take_pristine "$IMG"    screen_spoof_image.h
take_pristine "$SHARED" shared.h
take_pristine "$INI"    r3shieldcore.ini

# ---- 任何退出路径都还原 ----
cleanup() {
    cp -p "$BAK/screen_guard.cpp"       "$SGRD"   2>/dev/null
    cp -p "$BAK/screen_spoof_image.h"   "$IMG"    2>/dev/null
    cp -p "$BAK/shared.h"               "$SHARED" 2>/dev/null
    cp -p "$BAK/r3shieldcore.ini"       "$INI"    2>/dev/null
}
trap cleanup EXIT INT TERM

pass=0; fail=0; skipped=0

want() {  # $1=用例号 → 该不该跑
    [ -z "$ONLY" ] && return 0
    [ "$ONLY" = "$1" ] && return 0
    return 1
}

# 跑闸门，检查是否出现期望的 FAIL 行
check_red() {  # $1=用例名  $2=期望出现的 FAIL 关键字
    local name="$1" needle="$2" out rc
    out="$(bash "$ROOT/check_dist_sync.sh" 2>&1)"; rc=$?
    if printf '%s\n' "$out" | grep -qF "$needle" && [ "$rc" -ne 0 ]; then
        echo "[ OK ] $name —— 闸门报红且 exit=$rc"
        pass=$((pass+1))
    else
        echo "[FAIL] $name —— 闸门没报红（exit=$rc），这条判据是假绿"
        printf '%s\n' "$out" | grep -E '^\[FAIL\]' | head -5 | sed 's/^/        /'
        fail=$((fail+1))
    fi
}

mutate() {  # $1=python 片段（读 s 写 s）
    python -c "
import io,sys
p=sys.argv[1]
s=io.open(p,'r',encoding='utf-8',errors='surrogateescape').read()
$1
io.open(p,'w',encoding='utf-8',errors='surrogateescape').write(s)
" "$2"
}

# ================= M0 基线 =================
if want M0; then
    echo "--- M0 基线（未变异必须 PASS）---"
    out="$(bash "$ROOT/check_dist_sync.sh" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "[ OK ] M0 基线 —— 未变异时闸门 PASS（否则后面全是假红）"
        pass=$((pass+1))
    else
        echo "[FAIL] M0 基线 —— 未变异就红了，先修基线"
        printf '%s\n' "$out" | grep -E '^\[FAIL\]' | head -10 | sed 's/^/        /'
        fail=$((fail+1))
    fi
fi

# ================= M1 SpoofRect 不回落黑帧 =================
if want M1; then
    echo "--- M1 SpoofRect 失败时直接 return true（安全底线）---"
    mutate "old='return BlackenRect(dc, x, y, width, height);'
assert s.count(old)>=1, 'anchor missing'
s=s.replace(old,'return true;  // MUTANT',1)" "$SGRD"
    touch -r "$BAK/screen_guard.cpp" "$SGRD"
    check_red "M1" "SpoofRect 没有回落黑帧"
    cp -p "$BAK/screen_guard.cpp" "$SGRD"
fi

# ================= M2 SpoofDibBits 不回落 memset(0) =================
if want M2; then
    echo "--- M2 SpoofDibBits 失败时直接 return true（安全底线）---"
    mutate "old='return BlackenDibBits(bits, info, rowsWritten);'
assert s.count(old)>=1, 'anchor missing'
s=s.replace(old,'return true;  // MUTANT',1)" "$SGRD"
    touch -r "$BAK/screen_guard.cpp" "$SGRD"
    check_red "M2" "SpoofDibBits 没有回落"
    cp -p "$BAK/screen_guard.cpp" "$SGRD"
fi

# ================= M3 漏掉一路调用点 =================
if want M3; then
    echo "--- M3 把 PrintWindow 那一路的 SpoofRect 调用删掉 ---"
    mutate "lines=s.split('\n')
idx=None
for i,ln in enumerate(lines):
    if 'SpoofRect(hdcBlt,' in ln: idx=i; break
assert idx is not None, 'anchor missing'
lines[idx]='\t\t\tif (false) {  // MUTANT: 这一路不再替换'
s='\n'.join(lines)" "$SGRD"
    touch -r "$BAK/screen_guard.cpp" "$SGRD"
    check_red "M3" "SpoofRect 的调用点只有"
    cp -p "$BAK/screen_guard.cpp" "$SGRD"
fi

# ================= M4 加字段却不升 ABI =================
if want M4; then
    echo "--- M4 AbiVersion 27 退回 26 ---"
    mutate "assert 'AbiVersion = 27' in s, 'anchor missing'
s=s.replace('AbiVersion = 27','AbiVersion = 26',1)" "$SHARED"
    touch -r "$BAK/shared.h" "$SHARED"
    check_red "M4" "AbiVersion 不是 27"
    cp -p "$BAK/shared.h" "$SHARED"
fi

# ================= M5 出厂 ini 把路径填上 =================
if want M5; then
    echo "--- M5 出厂 ini 的 spoof_screen_image 填上值 ---"
    mutate "import re
s2=re.sub(r'(?m)^spoof_screen_image=[^\r\n]*','spoof_screen_image=C:/fake/desktop.bmp',s)
assert s2!=s, 'anchor missing'
s=s2" "$INI"
    touch -r "$BAK/r3shieldcore.ini" "$INI"
    check_red "M5" "应为空"
    cp -p "$BAK/r3shieldcore.ini" "$INI"
fi

# ================= M7 缓存键退回"只比 mtime" =================
if want M7; then
    echo "--- M7 去掉 Load 缓存键里的路径比较（只比 mtime）---"
    mutate "old='&& wcscmp(g_cache.path, path) == 0'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'&& true  // MUTANT',1)" "$IMG"
    touch -r "$BAK/screen_spoof_image.h" "$IMG"
    check_red "M7" "Load 只比 mtime 不比路径"
    cp -p "$BAK/screen_spoof_image.h" "$IMG"
fi

# ================= M6 还原后复核 =================
if want M6; then
    echo "--- M6 还原后复核 ---"
    if grep -q "MUTANT" "$SGRD" "$IMG" "$SHARED" "$INI" 2>/dev/null; then
        echo "[FAIL] M6 源码里还有 MUTANT 残留"
        fail=$((fail+1))
    else
        out="$(bash "$ROOT/check_dist_sync.sh" 2>&1)"; rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "[ OK ] M6 还原后闸门回到 PASS（变异没留下污染）"
            pass=$((pass+1))
        else
            echo "[FAIL] M6 还原后仍然红 —— 变异残留了！"
            printf '%s\n' "$out" | grep -E '^\[FAIL\]' | head -10 | sed 's/^/        /'
            fail=$((fail+1))
        fi
    fi
fi

echo ""
echo "变异测试结果: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
