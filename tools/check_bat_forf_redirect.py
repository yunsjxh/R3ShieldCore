#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_bat_forf_redirect.py -- 禁止 `for /f ('子命令')` 里"子命令以双引号开头"。

（文件名叫 forf_redirect 是历史原因；本闸门现在查的是**正确的那条判据**，
  重定向只作为附带提示 —— 见下面"判据的修正过程"。）

判据的修正过程（这一段很重要，别再改回去）
================================================
一开始我以为真机事故的根因是 `for /f ('cmd 2^>nul ...')` 里的 `2^>nul`
（`^` 被剥掉后 `2>nul` 变成 findstr 的字面参数 -> 计数恒 0）。据此写了本闸门，
规则是"子命令里禁止任何重定向"。

后来用**原生探针** tools/forfprobe.cpp（不拿 cmd 测 cmd）实测六种形态：

    片段                                    cmd 结果      判定
    --------------------------------------  ------------  --------
    A  tasklist ... 2^>nul                 8996          ok
    B  "C:\\...\\tasklist.exe" ... 2^>nul     (空)          **失效**
    C  "C:\\...\\tasklist.exe" ...           (空)          **失效**   <- 没有重定向也失效!
    D  C:\\...\\tasklist.exe ... 2^>nul      8996          ok
    E  "C:\\...\\reg.exe" query ... ^| find  0             **失效**
    F  C:\\...\\reg.exe query ... ^| find     1             ok

B 与 C 的对照是铁证：**去掉 `2^>nul` 完全没用**。
真判据 = 子命令的**第一个非空白字符是不是双引号**：
  cmd 在解析 `'...'` 时会先把最外层引号剥掉/重排，若首字符是 `"`，
  它拿到的就成了一条非法命令（报 `系统找不到指定的路径`），
  于是 for /f **静默产出 0 行** -> 计数恒 0 -> 脚本"看着跑完了"。
  `2^>nul` 本身在 for /f 里是**完全正常**的写法（A/D 证明）。

所以本闸门现在的规则：
  FAIL 条件： `for /f ... in ('` 之后第一个非空白字符是 `"`
  修法：      把命令加引号整体去掉 -> 用变量或完整路径
              for /f ... in ('%SystemRoot%\\System32\\tasklist.exe /nh ...')  <- 注意开头没有 "
              或者把带引号的路径塞进变量再 !VAR! 展开

附带的"重定向"检查降级为 **提示**（WARN），不再 FAIL ——
因为 A/D 证明它无害，把它当 FAIL 会产生大量假阳性（实测 14 处全是假的）。

用法
====
    python tools/check_bat_forf_redirect.py            # 扫全仓
    python tools/check_bat_forf_redirect.py --list     # 列出每个 for /f 子命令
    python tools/check_bat_forf_redirect.py a.bat      # 只查指定文件

退出码：0 = 干净；1 = 有"首字符是引号"的 for /f 子命令。
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

EXTS = {".bat", ".cmd"}

EXCLUDE_DIRS = {
    "obj", "_t", "verdir", ".git", ".vs",
    "Debug", "Release", "RelV53", "RelV53x64", "x64", "Win32",
    "libraries", "build", "backup", "verification",
    "BuildCheck", "ArkTest", "_probe_results", "__pycache__",
}

FORF_IN = re.compile(r"for\s+/f\b", re.IGNORECASE)


def iter_bats() -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [
            n for n in dirnames
            if n not in EXCLUDE_DIRS and not n.startswith(".backup")
        ]
        for name in filenames:
            if Path(name).suffix.lower() in EXTS and ".bak" not in name:
                out.append(Path(dirpath) / name)
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


def is_comment_line(line: str) -> bool:
    s = line.lstrip()
    if not s:
        return False
    if s.startswith("::"):
        return True
    low = s.lower()
    return low == "rem" or low.startswith("rem ") or low.startswith("rem\t")


def extract_forf_subs(line: str) -> list[tuple[str, int]]:
    """返回 [(子命令文本, 起始列)]，只认 `in ('...')` 的单引号形式。"""
    out: list[tuple[str, int]] = []
    for m in FORF_IN.finditer(line):
        n = len(line)
        j = m.end()
        in_kw = None
        # 跳过 for /f 的开关（可能含引号，如 "delims=" / tokens=1,2）
        while j < n - 1:
            if line[j] in "'\"":
                q = line[j]; j += 1
                while j < n and line[j] != q:
                    j += 1
                j += 1
                continue
            if line[j:j + 2].lower() == "in":
                in_kw = j
                break
            j += 1
        if in_kw is None:
            continue
        k = line.find("'", in_kw + 2)
        if k < 0:
            continue
        e = line.find("'", k + 1)
        if e < 0:
            continue
        out.append((line[k + 1:e], k + 1))
    return out


# 附带提示（不再 FAIL）：子命令里的重定向。A/D 实测证明 2^>nul 是好的，
# 所以这里只提醒"别把 stderr 静音写在子命令里导致看不懂"，不拦截。
REDIR_HINT = re.compile(r"\^\^>|\^>|(?<![|&^])>>?\s*\S")


def check_line(line: str) -> tuple[list[str], list[str]]:
    """返回 (致命错误, 提示)。"""
    errs: list[str] = []
    hints: list[str] = []
    if is_comment_line(line):
        return errs, hints

    for sub, _ in extract_forf_subs(line):
        stripped = sub.lstrip()
        if stripped.startswith('"'):
            errs.append(
                "for /f 子命令**以双引号开头** -> cmd 会剥掉它再执行，"
                "拿到一条非法命令，for /f **静默产出 0 行**（计数恒 0）。\n"
                "          子命令: %s\n"
                "          修法：把命令最外层的引号去掉，改成\n"
                "                for /f ... in ('%%SystemRoot%%\\System32\\tasklist.exe /nh ...')\n"
                "                （首字符必须是命令本身，不能是 \"）\n"
                "                或用 %%VAR%% / !VAR! 承载带引号的路径。"
                % sub.strip()[:160])
        if REDIR_HINT.search(sub):
            hints.append("for /f 子命令里有重定向（无害，但建议把静音放调用点 "
                         "`call :x 2>nul`，子命令里更干净）：%s" % sub.strip()[:120])
    return errs, hints


def main() -> int:
    ap = argparse.ArgumentParser(description="禁止 for /f 子命令以双引号开头")
    ap.add_argument("--list", action="store_true", help="列出所有 for /f 子命令")
    ap.add_argument("--hints", action="store_true", help="也打印重定向提示")
    ap.add_argument("files", nargs="*", help="只检查指定文件")
    args = ap.parse_args()

    targets = [Path(f) for f in args.files] if args.files else iter_bats()

    bad: list[str] = []
    hints: list[str] = []
    sub_total = 0
    printed: list[str] = []

    for path in targets:
        text = read(path)
        if text is None:
            continue
        try:
            rel = path.relative_to(REPO).as_posix()
        except ValueError:
            rel = path.as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            if is_comment_line(line):
                continue
            subs = extract_forf_subs(line)
            sub_total += len(subs)
            for sub, _ in subs:
                printed.append("%s:%d: %s" % (rel, lineno, sub.strip()[:160]))
            e, h = check_line(line)
            bad += ["%s:%d: %s" % (rel, lineno, x) for x in e]
            hints += ["%s:%d: %s" % (rel, lineno, x) for x in h]

    print("=== check_bat_forf_redirect ===")
    print("  判据: for /f 子命令**首字符是双引号** -> FAIL（实测会让计数恒 0）")
    print("  扫描文件数: %d" % len(targets))
    print("  发现 for /f 子命令: %d 处" % sub_total)

    if args.list:
        print()
        print("  --- for /f 子命令清单 ---")
        for s in printed:
            print("    %s" % s)

    if hints and args.hints:
        print()
        print("  --- 提示（无害，不拦截）---")
        for h in hints:
            print("    %s" % h)

    if bad:
        print()
        print("  X %d 处**首字符是双引号**的 for /f 子命令：" % len(bad))
        for b in bad:
            print("    %s" % b)
        print()
        print("  实证：tools/forfprobe.cpp 六组对照 -> 只有『首字符是引号』的三种失效，")
        print("        与是否写 2^>nul **无关**；去掉重定向并不能救它。")
        return 1

    print()
    print("  OK 没有 for /f 子命令以双引号开头。")
    if hints and not args.hints:
        print("     （另有 %d 处重定向提示，加 --hints 查看；它们无害。）" % len(hints))
    return 0


if __name__ == "__main__":
    sys.exit(main())
