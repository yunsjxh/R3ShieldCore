#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_spaced_name_quoted.py -- 主程序名里**带空格**，所有引用必须加引号。

为什么需要这个闸门
==================
主程序叫 `R3 ShieldCore.exe` —— 名字里有**一个空格**。

这带来一类**静默失效**（不会报错，只是行为不对）：

  · bash:   build_demo x64 R3 ShieldCore.exe
            → shell 拆成两个参数，产物名变成 `R3`。构建照样 "BUILD OK"。
  · bash:   taskkill //F //IM R3 ShieldCore.exe
            → 收到 4 个参数，杀不掉，而且不报错。
  · bash:   for name in R3 ShieldCore.exe R3 ShieldCore-x86.exe
            → 变成 4 个循环项，循环体跑到一堆垃圾名字上。
  · PowerShell -Command "Get-Process R3ShieldCore,R3 ShieldCore"
            → PS 在命令模式按空格拆参，解析成 `R3ShieldCore,R3` + `ShieldCore`。

本脚本扫描 .sh / .ps1 / .bat，把"出现在引号外的空格名"报出来并 FAIL。

判定方式（保守）
================
逐行扫描，维护一个"当前是否在引号内"的状态机（同时处理 ' " ` 和 \\ 转义）。
如果某个 `R3 ShieldCore` 的**起始字符**落在引号外 => 报错。

已知不能覆盖的情况（必须人工看）
================================
PowerShell 的 `-Command "…"` 里再出现空格名 —— 外层双引号让它"看起来"是引号内，
但 PS 收到字符串后还会**再解析一次**。这类地方要求内层用**单引号**，
本脚本会在检测到 `-Command` / `-c ` 行里出现空格名时**额外提示**（不 FAIL，
因为其中一部分是正确的单引号写法）。

用法
====
    python tools/check_spaced_name_quoted.py          # 扫全仓
    python tools/check_spaced_name_quoted.py --list   # 额外列出所有提示行

退出码：发现未加引号的引用 => 1。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# 带空格的名字（要检查的）
#
# ★ 只放**裸名** `R3 ShieldCore`：它是 `R3 ShieldCore.exe` /
#   `R3 ShieldCore-x86.exe` 的子串，所以一次就把三种写法全覆盖了。
#   反过来把三个都放进去，同一处会被报 3 遍（噪音）。
#
# ★ 必须覆盖裸名的理由（实测漏过一次）：
#     powershell -Command "Get-Process R3ShieldCore,R3 ShieldCore …"
#   这里没有 `.exe`，但 PS 照样按空格拆成 `R3ShieldCore,R3` + `ShieldCore`。
#   只查带 .exe 的写法时，这一行会被**整行跳过**（第一个过滤器就不通过）。
SPACED_NAMES = ("R3 ShieldCore",)

# 扫描的脚本类型
EXTS = {".sh", ".ps1", ".bat", ".cmd"}

# 跳过的目录
EXCLUDE_DIRS = {
    "obj", "_t", "verdir", ".git", ".vs",
    "Debug", "Release", "RelV53", "RelV53x64", "x64", "Win32",
    "libraries", "build", "backup", "verification",
    "BuildCheck", "ArkTest", "_probe_results", "__pycache__",
}
EXCLUDE_PATH_PREFIXES = (
    "dist/R3ShieldCore-x64-v", "dist/R3ShieldCore-x64-v", "dist/build",
    ".workbuddy-ai/backup", ".backup-",
)

# ---------------------------------------------------------------------------
# --fix 用的替换表
# ---------------------------------------------------------------------------
# 全部是 **纯 ASCII 的 old -> new**，所以可以安全地做**字节级**替换 ——
# .bat 是 GBK、.sh 是 UTF-8，但 ASCII 字节在两种编码里完全一致，
# 不会像"解码再编码"那样把非 ASCII 内容搞坏。
#
# 顺序有讲究：先长后短（`R3 ShieldCore-x86.exe` 必须先于 `R3 ShieldCore.exe`）。
FIXES: list[tuple[str, str]] = [
    # taskkill / tasklist 的 /IM 参数
    (b"//IM R3 ShieldCore-x86.exe", b'//IM "R3 ShieldCore-x86.exe"'),
    (b"//IM R3 ShieldCore.exe",     b'//IM "R3 ShieldCore.exe"'),
    # cmd 的 if exist（不带引号时会把空格当参数分隔，且和后面的 ( 块混淆）
    (b'if not exist R3 ShieldCore.exe ', b'if not exist "R3 ShieldCore.exe" '),
    # cmd 的 set：推荐写法是 set "VAR=value"
    (b"set ENGINE=R3 ShieldCore.exe", b'set "ENGINE=R3 ShieldCore.exe"'),
    # start 的第二个参数才是程序名（第一个是标题），必须带引号
    (b'start "" /wait R3 ShieldCore.exe', b'start "" /wait "R3 ShieldCore.exe"'),
    # 直接当命令跑
    (b"\nR3 ShieldCore.exe --superdesk-selftest", b'\n"R3 ShieldCore.exe" --superdesk-selftest'),
    # bash 的 for 列表：每个词都要单独引号，否则拆成 4 项
    (b"for name in R3 ShieldCore.exe R3 ShieldCore-x86.exe;",
     b'for name in "R3 ShieldCore.exe" "R3 ShieldCore-x86.exe";'),
    # PowerShell -Command 的**内层**：必须用单引号，否则 PS 二次解析按空格拆参
    (b"Get-Process R3ShieldCore,R3 ShieldCore",
     b"Get-Process 'R3ShieldCore','R3 ShieldCore'"),
]


def quote_state(line: str) -> list[bool]:
    """返回一个列表：每个字符位置上"是否处于引号内"。"""
    state = [False] * len(line)
    in_s = in_d = in_b = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and not in_s:
            # 转义：下一个字符不算引号
            if i + 1 < len(line):
                state[i] = in_s or in_d or in_b
                i += 1
                state[i] = in_s or in_d or in_b
            i += 1
            continue
        if ch == "'" and not in_d and not in_b:
            in_s = not in_s
        elif ch == '"' and not in_s and not in_b:
            in_d = not in_d
        elif ch == "`" and not in_s:
            # PowerShell 的转义字符（这里只做保守处理，不切换状态）
            pass
        state[i] = in_s or in_d or in_b
        i += 1
    return state


def iter_scripts() -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        d = Path(dirpath)
        dirnames[:] = [
            n for n in dirnames
            if n not in EXCLUDE_DIRS
            and not n.startswith(".backup")
            and not (d / n).relative_to(REPO).as_posix().startswith(EXCLUDE_PATH_PREFIXES)
        ]
        for name in filenames:
            if Path(name).suffix.lower() in EXTS:
                out.append(d / name)
    return sorted(out)


def read(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def segment_start(line: str, idx: int) -> int:
    """找 idx 所在"命令片段"的起点。

    cmd / bash 里 `&` `|` `(` `)` 会开启新的命令片段，
    片段的首个词决定这条命令是什么（echo? taskkill? if?）。
    """
    start = 0
    for i in range(idx):
        if line[i] in "&|()":
            start = i + 1
    return start


def single_quote_state(line: str) -> list[bool]:
    """返回：每个字符位置"是否处于单引号内"（独立于双引号统计）。

    用途：PowerShell 的 `-Command "…"` 里，外层双引号只是把字符串**交给** PS，
    PS 拿到之后还会**再解析一次**。所以"在双引号里"并不等于安全 ——
    名字必须落在**单引号**里（`'R3 ShieldCore.exe'`）才不会被 PS 按空格拆参。
    """
    state = [False] * len(line)
    in_s = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'":
            state[i] = in_s
            in_s = not in_s
            i += 1
            continue
        state[i] = in_s
        i += 1
    return state


def is_ps_command(line: str) -> bool:
    low = line.lower()
    return "-command" in low or "powershell" in low and " -c " in low


def is_raw_arg_occurrence(line: str, idx: int) -> bool:
    """这个出现位置是不是"整行吃参数"的命令的参数？

    这类命令把**字节原样**交给后面的东西，不按空格分词，所以空格不构成问题，
    属于**假阳性**，要放过。目前三类：

      · `echo [错误] 未找到 R3 ShieldCore.exe` —— echo 原样打印
      · `rem` 行（已在 is_comment 里挡掉，这里兜一手行内的 rem）
      · `title R3 ShieldCore 开机自启诊断` —— cmd 的 `title` 取**整行余下部分**
        作为窗口标题，同样不分词。

    ★ 为什么 title 要特判：`title "R3 ShieldCore 诊断"` 会把**引号本身**显示在
      标题栏里，所以这里**不能**用"加引号"来消警报 —— 只能从判据上放过。
      （实测：diag.cmd:18、diag_autostart.bat:4 两处命中，均为本类假阳性。）
    """
    seg = line[segment_start(line, idx):idx].strip().lstrip("@").strip()
    head = seg.split(None, 1)[0].lower() if seg.split() else ""
    return head in ("echo", "rem", "title")


def is_comment(line: str, ext: str) -> bool:
    s = line.lstrip()
    if ext in (".sh", ".ps1"):
        return s.startswith("#")
    if ext in (".bat", ".cmd"):
        return s[:4].upper().startswith("REM") or s.startswith("::")
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="检查带空格的 exe 名是否都加了引号")
    ap.add_argument("--list", action="store_true", help="列出所有提示行")
    ap.add_argument("--fix", action="store_true",
                    help="按 FIXES 表做字节级修复（ASCII，对 GBK/UTF-8 都安全）")
    args = ap.parse_args()

    if args.fix:
        n = 0
        for path in iter_scripts():
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            new = raw
            for old, rep in FIXES:
                if old in new:
                    n += new.count(old)
                    new = new.replace(old, rep)
            if new != raw:
                path.write_bytes(new)
                print(f"  [修] {path.relative_to(REPO).as_posix()}")
        print(f"[fix] 共 {n} 处加上了引号。再跑一次不带 --fix 的检查确认。")
        return 0

    bad: list[str] = []
    hints: list[str] = []

    for path in iter_scripts():
        text = read(path)
        if text is None:
            continue
        ext = path.suffix.lower()
        rel = path.relative_to(REPO).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            if not any(n in line for n in SPACED_NAMES):
                continue
            if is_comment(line, ext):
                continue
            st = quote_state(line)
            st1 = single_quote_state(line)
            ps_cmd = is_ps_command(line)
            for name in SPACED_NAMES:
                start = 0
                while True:
                    idx = line.find(name, start)
                    if idx < 0:
                        break
                    start = idx + 1
                    if not st[idx]:
                        # 第一层：连引号都没有 —— shell / cmd 直接按空格拆参
                        if is_raw_arg_occurrence(line, idx):
                            continue
                        bad.append(f"{rel}:{lineno}: 引号外 -> {line.strip()}")
                    elif ps_cmd and not st1[idx]:
                        # 第二层：在双引号里，但这是 PowerShell -Command，
                        #         PS 还会再解析一次 -> 必须落在单引号里
                        bad.append(
                            f"{rel}:{lineno}: PS -Command 内层未加单引号 -> {line.strip()}")
            # PowerShell 二次解析提示
            if ps_cmd:
                hints.append(f"{rel}:{lineno}: [PS 二次解析] {line.strip()}")

    print("=== check_spaced_name_quoted ===")
    print(f"  检查的名字: {', '.join(SPACED_NAMES)}")
    print(f"  扫描脚本数: {len(iter_scripts())}")

    if hints and args.list:
        print()
        print("  --- PowerShell -Command 提示（内层必须用单引号） ---")
        for h in hints:
            print(f"    {h}")

    if bad:
        print()
        print(f"  ✗ {len(bad)} 处**引号外**的引用 —— 会被 shell 拆参，静默失效：")
        for b in bad:
            print(f"    {b}")
        print()
        print("  修法：给名字加引号，例如")
        print('      taskkill //F //IM "R3 ShieldCore.exe"')
        print('      build_demo x64 "R3 ShieldCore.exe"')
        return 1

    print()
    print("  ✓ 所有引用都在引号内。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
