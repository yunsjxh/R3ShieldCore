#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_bat_dir_wildcard.py —— 闸门：禁止 `dir` 把通配符写在路径**中间**。

为什么要有这条闸门
==================
实测（本机 cmd，2026-10-06）：

    dir /b /s /o-n "D:\\Windows Kits\\10\\bin\\*\\x64\\signtool.exe"
        -> exit=1，**零输出**（不带 /s 也一样）
    dir /b /s /o-n "D:\\Windows Kits\\10\\bin\\*.exe"          -> 正常
    dir /b    /ad  "D:\\Windows Kits\\10\\bin\\*"              -> 正常

`dir` **只支持最后一段**带通配符。中间段带 `*` / `?` 时它不报错、不提示，
就是 exit=1 + 零输出 —— 于是

    for /f "delims=" %%i in ('dir ... 2^>nul') do ...

会**静默 0 次迭代**（`for /f` 对"命令失败"和"命令成功但没输出"一视同仁），
最后落到"找不到 X，跳过这一步"。看起来像"这台机器没装那个东西"。

★ 这个坑真踩过：`driver/install_driver.bat` 的签名预检就是这么坏的 ——
  它从来没找到过 signtool，所以**签名预检从来没执行过**，
  而输出永远是那句无辜的"找不到 signtool.exe，跳过签名预检"。
  （判据和它的反面同形：铁律 100 / 124。）

判据（只报**确认会静默失败**的那一种，不扩大化 —— 铁律 127 假 FAIL 更贵）
======================================================================
在 `dir` 的参数里，如果某个**不是最后一段**的路径段含 `*` 或 `?`，就判 FAIL。

扫描范围
========
`git ls-files --cached --others --exclude-standard` —— 已跟踪 + 未跟踪但没被忽略的
所有 `.bat` / `.cmd`。★ 不写死目录列表：写死的话新加的目录永远扫不到，
闸门会一直是绿的（铁律 111 / 117）。

用法
====
    python tools/check_bat_dir_wildcard.py            # 扫全仓
    python tools/check_bat_dir_wildcard.py a.bat b.bat # 只扫指定文件
    python tools/check_bat_dir_wildcard.py --selftest  # 负对照自测
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 通配符（cmd 的 dir 认 * 和 ?）
WILD = set('*?')

# 一条命令里出现 dir 的位置（避免匹配到 "directory" 之类）
RE_DIR = re.compile(r'(?<![A-Za-z0-9_])dir(?![A-Za-z0-9_])', re.IGNORECASE)
# 双引号串
RE_QUOTED = re.compile(r'"([^"]*)"')


def bad_component(path):
    """返回第一个"位置不对"的通配符段；没有就返回 None。"""
    # 只处理看起来像路径的（含分隔符）。纯文件名不算"中间段"问题。
    if '\\' not in path and '/' not in path:
        return None
    parts = re.split(r'[\\/]', path)
    # 去掉末尾空段（路径以 \ 结尾时）
    while len(parts) > 1 and parts[-1] == '':
        parts.pop()
    if len(parts) < 2:
        return None
    for seg in parts[:-1]:          # ★ 最后一段允许有通配符
        if any(c in WILD for c in seg):
            return seg
    return None


def scan_line(line):
    """返回该行里所有违规的 (段, 原始参数)。"""
    hits = []
    for m in RE_DIR.finditer(line):
        rest = line[m.end():]
        # 在 dir 之后的这一段里找参数（用引号串 + 裸 token 两种）
        args = RE_QUOTED.findall(rest)
        # 裸 token（没有引号的路径）
        head = rest.split('"')[0]
        for tok in head.split():
            if '\\' in tok or '/' in tok:
                args.append(tok)
        for a in args:
            seg = bad_component(a)
            if seg:
                hits.append((seg, a))
        # 只处理第一个 dir 就够（一行通常只有一条 dir）
        break
    return hits


def scan_file(path):
    """返回 [(行号, 段, 原始参数)]。"""
    out = []
    try:
        raw = open(path, 'rb').read()
    except OSError:
        return out
    for enc in ('utf-8-sig', 'gbk', 'latin-1'):
        try:
            txt = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        return out
    for i, line in enumerate(txt.splitlines(), 1):
        s = line.strip()
        if s.lower().startswith('rem ') or s.startswith('::'):
            continue
        for seg, arg in scan_line(line):
            out.append((i, seg, arg))
    return out


def list_targets():
    try:
        r = subprocess.run(['git', 'ls-files', '--cached', '--others',
                            '--exclude-standard'],
                           capture_output=True, text=True, cwd=ROOT)
        files = [f for f in r.stdout.splitlines() if f.strip()]
    except OSError:
        files = []
    return [f for f in files if f.lower().endswith(('.bat', '.cmd'))]


def run_selftest():
    """负对照：坏夹具必须被抓到，好夹具必须放过（铁律 128）。"""
    cases = [
        ('bad  中间通配符', 'for /f "delims=" %%i in (\'dir /b /s "D:\\x\\*\\y\\z.exe" 2^>nul\') do echo %%i', True),
        ('bad  中间通配符(无 /s)', 'dir /b "D:\\x\\*\\z.exe"', True),
        ('bad  裸参数中间通配符', 'dir /b D:\\a\\*\\b.txt', True),
        ('good 通配符在最后', 'dir /b /s "D:\\x\\*.exe"', False),
        ('good 目录通配符在最后', 'dir /b /s /ad "D:\\x\\*"', False),
        ('good 无通配符', 'dir /b "D:\\x\\y\\z.exe"', False),
        ('good rem 行里的坏模式', 'rem dir /b "D:\\x\\*\\z.exe"', False),
    ]
    bad = 0
    for name, line, want_hit in cases:
        got = bool(scan_line(line)) if not line.strip().lower().startswith('rem') else False
        mark = 'OK  ' if got == want_hit else 'FAIL'
        if got != want_hit:
            bad += 1
        print('  %s %-26s 期望命中=%-5s 实际命中=%s' % (mark, name, want_hit, got))
    print()
    if bad:
        print('负对照自测: FAIL（%d 条不符）' % bad)
    else:
        print('负对照自测: PASS（坏夹具都被抓到，好夹具都没误报）')
    return 0 if bad == 0 else 1


def main():
    if '--selftest' in sys.argv:
        print('=== check_bat_dir_wildcard 负对照自测 ===')
        return run_selftest()

    targets = sys.argv[1:] or list_targets()
    if not targets:
        print('没找到任何 .bat / .cmd 目标')
        return 0

    total = 0
    for rel in targets:
        p = rel if os.path.isabs(rel) else os.path.join(ROOT, rel)
        hits = scan_file(p)
        for ln, seg, arg in hits:
            print('  [违] %s:%d  中间段 "%s" 带通配符' % (rel, ln, seg))
            print('        %s' % arg)
            total += 1

    print()
    print('扫描 %d 个文件，违规 %d 处' % (len(targets), total))
    if total:
        print('FAIL：dir 只支持**最后一段**带通配符；中间段带 * / ? 会 exit=1 + 零输出，')
        print('      放进 for /f 就是静默 0 次迭代。改用 for /d + if exist，')
        print('      或把通配符挪到最后一段并让 /s 去递归。')
        return 1
    print('PASS：没有 dir 中间段带通配符的写法。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
