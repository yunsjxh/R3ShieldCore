#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""R3ShieldCore 真机日志核对器（每次发布验证都用得上）。

用法：
    python tools/logscan.py [部署目录]            # 默认 dist/R3ShieldCore-x64
    python tools/logscan.py dist/R3ShieldCore-x64 --grep tasklist
    python tools/logscan.py --runs               # 只按时间片列每次运行

为什么需要它（都是踩过的坑，铁律 45）：
  * r3shieldcore-console.log 用 GBK（printf），r3shieldcore-events.log 用 UTF-8（ConsoleLog）
    —— 同一个目录里两种编码，必须先探测再解码，否则 grep 中文永远不命中。
  * 两份日志都是**追加**的，一份文件里可能混着好几次运行 ⇒ 必须按时间戳切片。
  * `pid=<N> [?]` 不是"解析不出来"，而是"该进程在日志线程落盘前已退出"（短命进程）。
  * 注入细节（DllInject 成败）走 OutputDebugString，**不在日志文件里**，
    所以本工具只报"看得见的证据"，不会替你断言注入成功。
"""
import argparse
import collections
import os
import re
import sys

CONSOLE_KEYS = (
    '====', '运行身份', '模式 ', '注入扫描间隔', '瘦注入宿主', '注入新进程',
    '日志文件', '界面窗口', '加载引擎', '覆盖层反制', '排除路径', '[diag]',
    'engine-startup-error',
)
BANNER_KEYS = ('====', '运行身份', '模式 ', '注入扫描间隔', '瘦注入宿主', '日志文件', '排除路径')


def decode(path):
    """先试 UTF-8，再退 GBK（引擎 printf 是 GBK，ConsoleLog 是 UTF-8）。"""
    raw = open(path, 'rb').read()
    for enc in ('utf-8', 'gbk'):
        try:
            return raw.decode(enc), enc, len(raw)
        except UnicodeDecodeError:
            continue
    return raw.decode('utf-8', errors='replace'), 'utf-8/replace', len(raw)


def read_lines(path):
    text, enc, size = decode(path)
    # universal newlines 会把 \r\n 折叠掉，这里保留原始行划分
    return text.splitlines(), enc, size


def split_runs(lines, gap_seconds=120):
    """按时间戳切片：时间戳回退，**或**与前一条间隔超过 gap_seconds，都算新一次运行。

    ⚠️ 只判"回退"是不够的 —— 两次运行之间通常是**时间前跳**（引擎退出、
    过一会儿再启动），时间戳只增不减，那样两次会被并成一片（实测踩过）。
    """
    def to_sec(ts):
        return sum(int(x) * m for x, m in
                   zip(re.split(r'[-: ]', ts), (31536000, 2592000, 86400, 3600, 60, 1)))

    runs, cur = [], []
    prev = None
    for i, line in enumerate(lines):
        m = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        if not m:
            continue
        ts = m.group(1)
        if prev is not None and (ts < prev or to_sec(ts) - to_sec(prev) > gap_seconds):
            runs.append(cur)
            cur = []
        cur.append(i)
        prev = ts
    if cur:
        runs.append(cur)
    return runs


def op_of(line):
    m = re.search(r'\s([A-Z]{2,5})\s+(BLOCK|ALLOW|WOULD-BLOCK)\s+(?:HIGH\s+)?(\S+)', line)
    return ('%s %s %s' % m.groups()) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dist', nargs='?', default=os.path.join('dist', 'R3ShieldCore-x64'))
    ap.add_argument('--grep', action='append', default=[],
                    help='只打印匹配这些正则的行（可多次）')
    ap.add_argument('--runs', action='store_true', help='只按时间片列每次运行')
    args = ap.parse_args()

    console = os.path.join(args.dist, 'r3shieldcore-console.log')
    events = os.path.join(args.dist, 'r3shieldcore-events.log')

    print('=' * 74)
    print('部署目录: %s' % os.path.abspath(args.dist))
    print('=' * 74)

    # ---------- 1) 启动错误日志（存在即"引擎抛异常退出 ⇒ 零防护"） ----------
    errlog = os.path.join(args.dist, 'r3shieldcore-startup-error.log')
    if os.path.exists(errlog):
        print('!! 存在 r3shieldcore-startup-error.log —— 引擎启动就抛异常，等于零防护：')
        for line in read_lines(errlog)[0][:20]:
            print('   | %s' % line)
    else:
        print('[OK] 没有 r3shieldcore-startup-error.log（部署目录 ACL 那一关过了）')

    # ---------- 2) 控制台日志：横幅 + Gate 0 正信号 ----------
    if os.path.exists(console):
        lines, enc, size = read_lines(console)
        print('\n--- r3shieldcore-console.log (%d 字节, %d 行, 编码 %s) ---' % (size, len(lines), enc))
        banners = [i for i, l in enumerate(lines) if l.strip().startswith('====')]
        print('启动横幅数量 = %d %s' % (len(banners),
              '（>1 ⇒ 日志是追加的，一份文件里混着多次运行）' if len(banners) > 1 else ''))
        for i, l in enumerate(lines):
            if any(k in l for k in BANNER_KEYS):
                print('%5d| %s' % (i + 1, l[:190]))
        injected = [(i + 1, l) for i, l in enumerate(lines) if '注入新进程' in l]
        total = 0
        for _, l in injected:
            m = re.search(r'注入新进程:\s*(\d+)', l)
            if m:
                total += int(m.group(1))
        if injected:
            print('\n[Gate 0] 注入新进程 共 %d 条，累计 %d 个 —— 有 >0 的正信号才算"引擎真的在注入"'
                  % (len(injected), total))
        else:
            print('\n[Gate 0] 没有任何「注入新进程: N 个」⇒ 引擎可能压根没在注入（只有横幅不算证据）')
        for i, l in enumerate(lines):
            if 'engine-startup-error' in l or 'Refusing to load an engine DLL' in l:
                print('!! %5d| %s' % (i + 1, l[:190]))
        tail = [l for l in lines[-3:]]
        if any('退出引擎' in l for l in tail):
            print('[退出] 日志末尾是「用户点击「退出引擎」」⇒ 正常退出')

    # ---------- 3) 事件日志：按运行切片 ----------
    if not os.path.exists(events):
        return 0
    lines, enc, size = read_lines(events)
    runs = split_runs(lines)
    print('\n--- r3shieldcore-events.log (%d 字节, %d 行, 编码 %s) ---' % (size, len(lines), enc))
    print('时间片（=运行）数量 = %d' % len(runs))
    for n, idx in enumerate(runs, 1):
        blk = [i for i in idx if ' BLOCK ' in lines[i]]
        print('\n[运行 %d] 行 %d..%d  事件 %d 条  BLOCK %d 条  %s .. %s'
              % (n, idx[0] + 1, idx[-1] + 1, len(idx), len(blk),
                 lines[idx[0]][:19], lines[idx[-1]][:19]))
        if args.runs:
            continue
        kinds = collections.Counter(filter(None, (op_of(lines[i]) for i in blk)))
        if kinds:
            print('  BLOCK 归类：')
            for k, v in kinds.most_common(12):
                print('    %-28s %d' % (k, v))
        asked = [i for i in idx if 'ASK-UNAVAIL' in lines[i]]
        would = [i for i in idx if 'WOULD-BLOCK' in lines[i]]
        print('  ASK-UNAVAIL %d 条 / WOULD-BLOCK %d 条（都应为 0）' % (len(asked), len(would)))
        unknown = collections.Counter()
        for i in idx:
            m = re.search(r'pid=(\d+)\s+\[\?\]', lines[i])
            if m:
                unknown[m.group(1)] += 1
        if unknown:
            print('  映像名未解析（[?] = 落盘前已退出的短命进程）: %s'
                  % ', '.join('pid=%s×%d' % (p, c) for p, c in unknown.most_common()))

    # ---------- 4) 定向 grep ----------
    for pat in args.grep:
        rx = re.compile(pat, re.I)
        hits = [(i + 1, l) for i, l in enumerate(lines) if rx.search(l)]
        print('\n--- grep %r : %d 命中 ---' % (pat, len(hits)))
        for i, l in hits[:40]:
            print('%5d| %s' % (i, l[:190]))
        if len(hits) > 40:
            print('   ...（还有 %d 条）' % (len(hits) - 40))
    return 0


if __name__ == '__main__':
    sys.exit(main())
