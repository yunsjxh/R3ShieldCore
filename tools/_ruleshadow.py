#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
_ruleshadow.py — R3ShieldCore 注册表规则表「死条目」审计（v19）。

背景
----
`RegistryRiskReason()` 遍历 `kRegistryRules`，**命中第一条就 return**。
所以一条宽泛前缀会把**它后面**的所有具体条目变成**死条目**：

    { L"SYSTEM\\CurrentControlSet\\Services", ..., "系统服务/驱动" },   ← 宽泛，覆盖整棵子树
    ...
    { L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess", ..., "防火墙配置" },  ← 永不命中！

症状很隐蔽：不是漏报（宽泛那条仍判高危），而是**返回了泛化 reason**，
丢失"这是防火墙配置 / 时间服务提供程序"这个要害信息。
只判 `IsHighRiskRegistry() == true` 的单测抓不到（见 §10-46）。

用法
----
    python tools/_ruleshadow.py

输出
----
    1. 规则总数
    2. 被**前序规则完全遮蔽**的条目（真死条目，必须修：上移到宽泛条目之前）
    3. 完全相同的前缀重复（多为 `Software`/`SOFTWARE` 大小写变体，**可忽略**）

匹配语义与 C++ 侧一致：逐段比对、不分大小写、
`CurrentControlSet` ≡ `ControlSetNNN`（N 为纯数字）。
"""

import os
import re
import sys

# 默认指向仓库内的规则源文件；可用命令行参数覆盖。
_HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(_HERE, '..', 'R3ShieldCore', 'R3ShieldCoreLib', 'r3shieldcore_rules.cpp')
if len(sys.argv) > 1:
    PATH = sys.argv[1]
BS = chr(92)  # backslash


def load_rules(path):
    src = open(path, encoding='utf-8').read()
    m = re.search(r'constexpr RegistryRule kRegistryRules\[\] = \{(.*?)\n\t\};', src, re.S)
    if not m:
        print('ERROR: 找不到 kRegistryRules 定义（路径对否？）', file=sys.stderr)
        sys.exit(2)
    body = m.group(1)
    rules = []
    for idx, line in enumerate(body.split('\n')):
        mm = re.match(r'\s*\{ L"((?:[^"\\]|\\.)*)", (true|false), (true|false),', line)
        if mm:
            prefix = mm.group(1).replace(BS + BS, BS)
            rules.append((prefix, mm.group(2) == 'true', mm.group(3) == 'true'))
    return rules


def segs(p):
    return [s for s in p.split(BS) if s]


def eq_seg(s, t):
    sl, tl = s.lower(), t.lower()
    if sl == tl:
        return True
    # CurrentControlSet ≡ ControlSetNNN（纯数字）
    if sl == 'currentcontrolset' and tl.startswith('controlset') and tl[10:].isdigit():
        return True
    if tl == 'currentcontrolset' and sl.startswith('controlset') and sl[10:].isdigit():
        return True
    return False


def covers(a, b):
    """规则 a（前缀）是否覆盖规则 b（即 b 永远轮不到）？"""
    sa, sb = segs(a), segs(b)
    if len(sa) > len(sb):
        return False
    return all(eq_seg(sa[i], sb[i]) for i in range(len(sa)))


def main():
    rules = load_rules(PATH)
    print('kRegistryRules 条目数: %d' % len(rules))

    dead = []
    for i, (p, m_, u) in enumerate(rules):
        for j in range(i):
            pj, mj, uj = rules[j]
            if m_ and not mj:
                continue
            if u and not uj:
                continue
            if covers(pj, p):
                dead.append((i + 1, p, j + 1, pj))
                break

    print()
    print('=== 被前序规则完全遮蔽的死条目（必须修）===')
    if not dead:
        print('  （无 —— 全部具体条目都在宽泛条目之前）')
    else:
        for no, p, jno, pj in dead:
            print('  #%-3d %s' % (no, p))
            print('        <= 被 #%d 遮蔽: %s' % (jno, pj))

    print()
    print('=== 相同前缀重复（多为大小写变体，可忽略）===')
    seen = {}
    dups = 0
    for i, (p, m_, u) in enumerate(rules):
        key = (p.lower(), m_, u)
        if key in seen:
            print('  dup: %s  (#%d, #%d)' % (p, seen[key], i + 1))
            dups += 1
        else:
            seen[key] = i + 1
    if not dups:
        print('  （无）')

    print()
    # 大小写变体不计入"必须修"。
    real_dead = [d for d in dead
                 if d[1].lower() != d[3].lower()]
    if real_dead:
        print('结论: 有 %d 条**语义死条目**（非大小写变体），请上移到宽泛条目之前。' % len(real_dead))
        return 1
    print('结论: 无语义死条目。')
    return 0


if __name__ == '__main__':
    sys.exit(main())
