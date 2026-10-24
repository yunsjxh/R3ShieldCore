#!/usr/bin/env bash
# local_engine_switch.sh -- 本机引擎熔断的"安全放行 / 恢复保护"开关。
#
# 背景（2026-10-23 事故）：
#   引擎会**全局注入**（白名单之外的一切，含 cl.exe/link.exe），并且在
#   `mode=ask` / `neutralize_overlay>=2` 下会弹 **置顶且抢前台焦点** 的询问窗
#   （`r3shieldcore_sentinel.cpp`: WS_EX_TOPMOST + SetForegroundWindow，超时重试 3 次）。
#   ⇒ 误跑一次就会出现：编辑器无法输入、构建每次等 30 秒超时、只能重启机器。
#
#   ★ 关键：`never_inject=` 白名单**挡不住弹窗** —— 它只决定"往哪个进程注入 DLL"，
#     而弹窗是引擎进程自己创建的窗口。所以"放行熔断"时**必须同时关掉弹窗**，
#     否则等于把那次事故再演一遍。
#
# 用法：
#   bash tools/local_engine_switch.sh on      # 放行（自动改成不弹窗的安全配置）
#   bash tools/local_engine_switch.sh off     # 恢复保护（建 NO_ENGINE + 恢复弹窗配置）
#   bash tools/local_engine_switch.sh status  # 只看当前状态
#
set -u

INI_DIR="${ProgramData:-C:\\ProgramData}\\R3 Shield Core"
INI="$INI_DIR\\r3shieldcore.ini"
FLAG="$INI_DIR\\NO_ENGINE"

# MSYS 下把 C:\x\y 转成 /c/x/y 才能用 test/sed 操作
to_msys() {
    local p="$1"
    p="${p//\\//}"
    if [[ "$p" =~ ^([A-Za-z]):(.*)$ ]]; then
        echo "/${BASH_REMATCH[1],,}${BASH_REMATCH[2]}"
    else
        echo "$p"
    fi
}

INI_M="$(to_msys "$INI")"
FLAG_M="$(to_msys "$FLAG")"

read_key() {
    # 只取有效行（行首 key=），忽略注释里的示例
    grep -m1 -E "^$1=" "$INI_M" 2>/dev/null | sed "s/^$1=//" | sed 's/[[:space:]]*$//'
}

set_key() {
    local key="$1" value="$2"
    if grep -qE "^${key}=" "$INI_M" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$INI_M"
    else
        printf '\n%s=%s\n' "$key" "$value" >> "$INI_M"
    fi
}

status() {
    echo "配置文件 : $INI_M"
    if [ -f "$INI_M" ]; then
        echo "  mode              = $(read_key mode)"
        echo "  neutralize_overlay= $(read_key neutralize_overlay)"
        echo "  never_inject      = $(grep -cE '^never_inject=' "$INI_M" 2>/dev/null) 条"
    else
        echo "  （文件不存在）"
    fi
    if [ -f "$FLAG_M" ]; then
        echo "熔断     : **已启用**（引擎拒绝启动）"
    else
        echo "熔断     : 已放行（引擎可以启动）"
    fi
}

case "${1:-status}" in
on)
    [ -f "$INI_M" ] || { echo "[FAIL] 找不到 $INI_M"; exit 1; }

    # 留一份一次性备份（已存在就不覆盖，避免把好备份冲掉）
    BACKUP="$INI_M.bak-before-engine-on"
    if [ ! -f "$BACKUP" ]; then
        cp "$INI_M" "$BACKUP" && echo "[备份] $BACKUP"
    else
        echo "[备份] 已存在，保留不动：$BACKUP"
    fi

    # ★ 必须的两项：不弹窗、不拦截
    #   mode=log          → 只记录不拦截、不询问
    #   neutralize_overlay=0 → 关闭覆盖层反制（它的询问窗会抢焦点）
    set_key mode log
    set_key neutralize_overlay 0

    rm -f "$FLAG_M"
    echo
    echo "[放行] 已删除熔断标记，并改为不弹窗配置："
    status
    echo
    echo "★ 编辑器仍在 never_inject 白名单里（不被注入），但**其他进程会被注入**，"
    echo "  包括 cl.exe/link.exe。mode=log 下它们不会被弹窗卡住，但注入本身仍有开销。"
    echo "  若构建变慢或不稳，再往 ini 里加：test_inject_only=<某个无害进程.exe>"
    echo
    echo "恢复保护：bash tools/local_engine_switch.sh off"
    ;;
off)
    [ -f "$INI_M" ] || { echo "[FAIL] 找不到 $INI_M"; exit 1; }

    # 恢复成"会弹窗询问"的保守档（与随包默认一致）
    set_key mode ask
    set_key neutralize_overlay 2

    printf 'R3 ShieldCore - 本机引擎熔断标记\r\n\r\n这个文件存在时，界面不会拉起引擎、引擎自己也拒绝启动。\r\n\r\n原因：引擎做全局注入并会弹置顶询问窗（抢前台焦点）。\r\n2026-10-23 事故：误跑一次 -> 编辑器无法输入、cl.exe 卡死、\r\n构建挂 19 分钟停不下来，只能重启机器。\r\n\r\n确需在本机做注入验证时，删掉这个文件（或设 R3SHIELDCORE_ALLOW_ENGINE=1）。\r\n验证完请把它放回来。\r\n' > "$FLAG_M"

    echo "[恢复] 已重建熔断标记，并恢复弹窗配置："
    status
    ;;
status)
    status
    ;;
*)
    echo "用法: bash tools/local_engine_switch.sh {on|off|status}"
    exit 2
    ;;
esac
