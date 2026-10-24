#!/usr/bin/env bash
#
# spoof_verify_all.sh —— 「全都换一遍」：把**替换**这件事从两个方向一次验完。
#
# ======================================================================
# 两个方向（缺一不可）
# ======================================================================
#   ① **面**（API 层）：六个自挂 hook 的探针，各回答"真调原函数 -> 换成假数据 ->
#      返回成功"在**真 Windows API** 上到底行不行：
#        注册表值 / 注册表枚举 / 剪贴板 / 屏幕(GetDIBits) / 事务注册表(KTM) / 摄像头
#   ② **规则**（codec 层）：`spoof_all_rules_ut` 把规则文件里**每一条**都用
#      生产同源 codec 真跑一遍，打印"改前 -> 改后"的真实字节。
#      还会报出**被遮蔽**的规则（first-match wins，前面有条同面规则顶掉它）。
#
# ★ 为什么不需要引擎：这六个探针**自己挂自己**的 hook（铁律 175 的豁免），
#   `spoof_all_rules_ut` 只调生产 codec。所以本脚本**不注入任何进程**，
#   不会 hook 你的编辑器。
# ★ 真正的端到端（引擎注入真进程）只有 `tools/spoof_e2e.sh --run-engine` 能验，
#   那条路要管理员 + 会全局注入，**本机禁止**（用户明令 2026-10-06）。
#
# 用法:
#   bash tools/spoof_verify_all.sh                  # 跑全部（含摄像头硬件）
#   bash tools/spoof_verify_all.sh --no-camera      # 跳过摄像头硬件
#   bash tools/spoof_verify_all.sh --rules <文件>   # 指定规则文件（默认 ProgramData 那份）
#
set -u

R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
cd "$R3SC_PROJECT_ROOT" || exit 1

CAMERA=1
RULES=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-camera) CAMERA=0 ;;
        --rules) shift; RULES="${1:-}" ;;
        *) echo "不认识的参数：$1"; exit 2 ;;
    esac
    shift
done

# ★ 判定只看**退出码**：探针的输出是 CP936，脚本是 UTF-8，
#   拿中文串去 grep 会因编码不同而恒不匹配（"判据恒绿"的老坑）。
#   退出码是 `g_fail == 0 ? 0 : 1`，与语言无关。
TOTAL=0
FAILED=0

run_one() {
    local name="$1"; shift
    printf '%-14s ' "$name"
    local out; out="$("$@" 2>&1)"; local rc=$?
    # 把结论行打出来（转码失败也不影响退出码判定）
    # ★ 不要用 `tail -3`：夹具的结论行后面还有两行"结论/注意"，会被截掉 ⇒ 打印空白
    #   （第一次跑就是这样，看着像"没结论"，其实退出码是对的）。
    local tail_line; tail_line="$(printf '%s\n' "$out" | iconv -f CP936 -t UTF-8 -c 2>/dev/null | grep -E '结果|判据' | tail -1)"
    if [ "$rc" -eq 0 ]; then
        echo "OK    ${tail_line}"
    else
        echo "FAIL  ${tail_line}"
        FAILED=$((FAILED + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

echo "=== ① 六个面（自挂 hook，真 Windows API，不经过引擎）==="
run_one "注册表值"   ./tools/spoof_reg_probe.exe
run_one "注册表枚举" ./tools/spoof_reg_enum_probe.exe
run_one "剪贴板"     ./tools/spoof_clipboard_probe.exe
run_one "屏幕DIB"    ./tools/spoof_retdata_probe.exe
run_one "事务注册表" ./tools/spoof_reg_ktm_probe.exe
if [ "$CAMERA" -eq 1 ]; then
    run_one "摄像头"   ./tools/spoof_camera_probe.exe --use-camera
else
    echo "摄像头         跳过（--no-camera）—— 跳过数不进结论，别当它通过了"
fi

echo ""
echo "=== ② 规则全量落地（生产同源 codec，逐条真跑）==="
if [ -n "$RULES" ]; then
    run_one "规则文件" ./tools/spoof_all_rules_ut.exe "$RULES"
else
    run_one "规则文件" ./tools/spoof_all_rules_ut.exe
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "结果: PASS —— $TOTAL 项全过（替换在 API 层与 codec 层都真的发生了）"
    exit 0
fi
echo "结果: FAIL —— $TOTAL 项里有 $FAILED 项没过，**别当成能替换**"
exit 1
