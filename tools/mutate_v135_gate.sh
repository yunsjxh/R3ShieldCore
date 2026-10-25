#!/usr/bin/env bash
# v135 发布闸门的变异测试：逐条破坏被测事实，确认闸门真的报红。
#
# ★ 为什么必须做：v135 段 12 条判据全是 grep。grep 判据最容易出的问题是
#   "正则写错 ⇒ 恒绿"，比没有判据更糟（铁律 142：只查存在 ⇒ 假绿）。
#   v135 尤其危险 —— 它防的是"规则**解析通过、永远不命中、也不报错**"，
#   这种失效**没有任何运行时症状**，只能靠静态判据 + 变异测试证明判据有牙。
#
# ★ 沿用 v134 脚本的三件套（上一版被 kill 留下 `// MUTANT` 的教训）：
#   ① pristine 备份**只在开头取一次**；
#   ② `trap ... EXIT INT TERM` —— 任何退出路径都先还原；
#   ③ 每条变异独立可跑（`--only=M1`），不必一次跑完全部。
#
# ★ 隔离手段：变异后把源文件 mtime 恢复成原值（`touch -r`），
#   否则 ⑨「cfg 比源码新」/ ⑪「DLL 比源码新」也会一起红，就分不清是谁在报。
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

CODEC="$ROOT/R3ShieldCore/shared/r3shieldcore/rules_codec.h"
FGUARD="$ROOT/R3ShieldCore/R3ShieldCoreLib/file_guard.cpp"
SGRD="$ROOT/R3ShieldCore/R3ShieldCoreLib/screen_guard.cpp"
CFGSRC="$ROOT/tools/r3shieldcore_cfg.cpp"
GATEALL="$ROOT/tools/spoof_verify_all.sh"
BAK="$ROOT/_t/mutbak135"
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
take_pristine "$CODEC"  rules_codec.h
take_pristine "$FGUARD" file_guard.cpp
take_pristine "$SGRD"   screen_guard.cpp
take_pristine "$CFGSRC" r3shieldcore_cfg.cpp
take_pristine "$GATEALL" spoof_verify_all.sh

cleanup() {
    cp -p "$BAK/rules_codec.h"        "$CODEC"   2>/dev/null
    cp -p "$BAK/file_guard.cpp"       "$FGUARD"  2>/dev/null
    cp -p "$BAK/screen_guard.cpp"     "$SGRD"    2>/dev/null
    cp -p "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"  2>/dev/null
    cp -p "$BAK/spoof_verify_all.sh"  "$GATEALL" 2>/dev/null
}
trap cleanup EXIT INT TERM

pass=0; fail=0

want() {
    [ -z "$ONLY" ] && return 0
    [ "$ONLY" = "$1" ] && return 0
    return 1
}

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

mutate() {  # $1=python 片段（读 s 写 s）  $2=文件
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

# ================= M1 面×字段 相容性校验被拆 =================
#   拆了它 ⇒ `当 文件 的 格式 含 "x" 时 …` 解析通过、永不命中、不报错。
if want M1; then
    echo "--- M1 把「文件面只认路径」的校验放行 ---"
    mutate "old='case Face::File:   fieldOk = (r.field == Field::Path);'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'case Face::File:   fieldOk = true;  // MUTANT',1)" "$CODEC"
    touch -r "$BAK/rules_codec.h" "$CODEC"
    check_red "M1" "面×字段 相容性校验被删/改了"
    cp -p "$BAK/rules_codec.h" "$CODEC"
fi

# ================= M2 面×动作 相容性校验被拆 =================
#   拆了它 ⇒ 文件面写「替换为图」会静默变成全零（因为 fill 默认 0）。
if want M2; then
    echo "--- M2 把「替换为图只对截屏面」的校验放行 ---"
    mutate "old='r.act == Act::ReplaceImage && r.face != Face::Screen'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'false && r.act == Act::ReplaceImage  // MUTANT',1)" "$CODEC"
    touch -r "$BAK/rules_codec.h" "$CODEC"
    check_red "M2" "缺「替换为图只对截屏面」的校验"
    cp -p "$BAK/rules_codec.h" "$CODEC"
fi

# ================= M3 Eval 不接 Process 槽 =================
#   截屏规则的匹配值恒为空 ⇒ 任何模式都匹配不上，同样"静默不生效"。
if want M3; then
    echo "--- M3 把 Eval 的 Process 字段拆掉 ---"
    mutate "old='case Field::Process: v = name; break;'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'case Field::Process: break;  // MUTANT',1)" "$CODEC"
    touch -r "$BAK/rules_codec.h" "$CODEC"
    check_red "M3" "Eval 没接 Process 字段"
    cp -p "$BAK/rules_codec.h" "$CODEC"
fi

# ================= M4 file_guard 求值不传真实路径 =================
if want M4; then
    echo "--- M4 file_guard 求值时把 rulePath 换成常量 ---"
    mutate "old='RScript::Face::File, rulePath'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'RScript::Face::File, L\"C:\\\\\\\\x\"  // MUTANT',1)" "$FGUARD"
    touch -r "$BAK/file_guard.cpp" "$FGUARD"
    check_red "M4" "求值时没传 rulePath"
    cp -p "$BAK/file_guard.cpp" "$FGUARD"
fi

# ================= M5 screen_guard 求值不传进程名 =================
if want M5; then
    echo "--- M5 screen_guard 求值时把进程名换成 nullptr ---"
    mutate "old='RScript::Face::Screen, nullptr, CurrentProcessExeName()'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'RScript::Face::Screen, nullptr, nullptr  // MUTANT',1)" "$SGRD"
    touch -r "$BAK/screen_guard.cpp" "$SGRD"
    check_red "M5" "求值时没传进程名"
    cp -p "$BAK/screen_guard.cpp" "$SGRD"
fi

# ================= M6 漏掉一路 ScreenMode 调用点 =================
if want M6; then
    echo "--- M6 把 GetDIBits 那一路的 ScreenMode 调用拆掉 ---"
    mutate "lines=s.split('\n')
idx=None
for i,ln in enumerate(lines):
    if 'const ScreenSpoofMode mode = ScreenMode(spoofImage, _countof(spoofImage));' in ln:
        idx=i; break
assert idx is not None, 'anchor missing'
lines[idx]='\t\t\tconst ScreenSpoofMode mode = ScreenSpoofMode::Black;  // MUTANT'
s='\n'.join(lines)" "$SGRD"
    touch -r "$BAK/screen_guard.cpp" "$SGRD"
    check_red "M6" "ScreenMode 调用点 = 3"
    cp -p "$BAK/screen_guard.cpp" "$SGRD"
fi

# ================= M7 放行时仍报 Spoofed（铁律 97）=================
#   ★ 这是最难发现的一类：代码确实没替换，但日志说"我替换了"。
if want M7; then
    echo "--- M7 把一处「放行」的上报口径改回 Spoofed ---"
    mutate "lines=s.split('\n')
hits=[i for i,ln in enumerate(lines) if 'ScreenMode(spoofImage, _countof(spoofImage))' in ln]
assert len(hits)==4, 'anchor missing: %d' % len(hits)
tgt=None
for i in range(hits[2], min(hits[2]+8, len(lines))):
    if 'Decision::Allowed' in lines[i]:
        tgt=i; break
assert tgt is not None, 'no Allowed near 3rd call'
lines[tgt]=lines[tgt].replace('Decision::Allowed','Decision::Spoofed  // MUTANT')
s='\n'.join(lines)" "$SGRD"
    touch -r "$BAK/screen_guard.cpp" "$SGRD"
    check_red "M7" "放行分支只有"
    cp -p "$BAK/screen_guard.cpp" "$SGRD"
fi

# ================= M8 cfg 面芯片退回 3 个 =================
if want M8; then
    echo "--- M8 cfg 面芯片退回 3 个（新面点不出来）---"
    mutate "old='constexpr int kAdvChipRowA = 5;'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'constexpr int kAdvChipRowA = 3;  // MUTANT',1)" "$CFGSRC"
    touch -r "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"
    check_red "M8" "cfg 面芯片不是 5 个"
    cp -p "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"
fi

# ================= M9 cfg 动作芯片退回 6 个 =================
if want M9; then
    echo "--- M9 cfg 动作芯片退回 6 个（全FF / 替换为图 点不出来）---"
    mutate "old='constexpr int kAdvChipRowC = 8;'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'constexpr int kAdvChipRowC = 6;  // MUTANT',1)" "$CFGSRC"
    touch -r "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"
    check_red "M9" "cfg 动作芯片不是 8 个"
    cp -p "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"
fi

# ================= M10 骨架字段与 codec 默认不一致 =================
#   点一下「文件」芯片就得到一条永不命中的规则。
if want M10; then
    echo "--- M10 文件面骨架的字段写成「格式」---"
    mutate "old='当 文件 的 路径 含'
assert s.count(old)>=1, 'anchor missing'
s=s.replace(old,'当 文件 的 格式 含',1)" "$CFGSRC"
    touch -r "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"
    check_red "M10" "骨架里的字段与 codec 默认不一致"
    cp -p "$BAK/r3shieldcore_cfg.cpp" "$CFGSRC"
fi

# ================= M11 v135 codec 单测没进任何闸门 =================
if want M11; then
    echo "--- M11 把 v135_rules_faces_ut 从 spoof_verify_all.sh 摘掉 ---"
    mutate "old='run_one \"DSL 面\" ./tools/v135_rules_faces_ut.exe'
assert s.count(old)==1, 'anchor missing'
s=s.replace(old,'# MUTANT: 这一行被删了',1)" "$GATEALL"
    touch -r "$BAK/spoof_verify_all.sh" "$GATEALL"
    check_red "M11" "没进 spoof_verify_all.sh"
    cp -p "$BAK/spoof_verify_all.sh" "$GATEALL"
fi

# ================= M12 还原后复核 =================
if want M12; then
    echo "--- M12 还原后复核 ---"
    if grep -q "MUTANT" "$CODEC" "$FGUARD" "$SGRD" "$CFGSRC" "$GATEALL" 2>/dev/null; then
        echo "[FAIL] M12 源码里还有 MUTANT 残留"
        fail=$((fail+1))
    else
        out="$(bash "$ROOT/check_dist_sync.sh" 2>&1)"; rc=$?
        if [ "$rc" -eq 0 ]; then
            echo "[ OK ] M12 还原后闸门回到 PASS（变异没留下污染）"
            pass=$((pass+1))
        else
            echo "[FAIL] M12 还原后仍然红 —— 变异残留了！"
            printf '%s\n' "$out" | grep -E '^\[FAIL\]' | head -10 | sed 's/^/        /'
            fail=$((fail+1))
        fi
    fi
fi

echo ""
echo "变异测试结果: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
