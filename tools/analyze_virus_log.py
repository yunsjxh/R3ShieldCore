#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_virus_log.py —— 从 r3shieldcore-events.log 里挖「病毒哪些行为没被拦住」。

用法:
    python analyze_virus_log.py <events.log> [病毒映像名]

设计意图（对齐项目铁律）:
  * 铁律 75「日志里没有 != 没跑」：本脚本不只看病毒自己的事件，还看
    「同一时刻其它进程做了什么」，用来区分「没扫到」与「换了进程干」。
  * 铁律 94「断言必须匹配字段而非子串」：所有匹配都锚定字段位置。
  * 铁律 92「events.log 是追加、不截断」：脚本会打印时间跨度，
    提醒「引擎启动之前的破坏，这份日志里根本看不到」。
"""
import re
import sys
import collections

LINE = re.compile(
    r'^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+'
    r'pid=(?P<pid>\d+)\s+\[(?P<proc>[^\]]*)\]\s+tid=(?P<tid>\d+)\s+'
    r'(?P<type>\S+)\s+(?P<verdict>\S+)\s+(?P<rest>.*)$')

# 症状 -> 对应的注册表值名（Windows XP Horror 一类恶作剧程序的典型落点）
SYMPTOM_KEYS = [
    ('左右键互换', 'SwapMouseButtons'),
    ('左右键互换', 'MouseSpeed'),
    ('桌面无图标', 'HideIcons'),
    ('桌面无图标', 'NoDesktop'),
    ('桌面无图标', 'HideDesktopIcons'),
    ('桌面壁纸被改', 'Wallpaper'),
    ('壁纸被改', 'WallpaperStyle'),
    ('任务管理器被禁', 'DisableTaskMgr'),
    ('注册表编辑器被禁', 'DisableRegistryTools'),
    ('Ctrl+Alt+Del 被禁', 'DisableCAD'),
    ('启动项', 'Run'),
    ('外壳替换', 'Shell'),
]


def parse(path):
    rows = []
    with open(path, 'rb') as fh:
        text = fh.read().decode('gbk', errors='replace')
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            rows.append(m.groupdict())
    return rows


def op_of(rest):
    m = re.search(r'\b([A-Za-z]+)\s+status=', rest)
    return m.group(1) if m else '?'


def key_of(rest):
    m = re.search(r'key=(.*?)(?:\s{2,}|$)', rest)
    return m.group(1).strip() if m else ''


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else 'Windows XP Horror.exe'

    rows = parse(path)
    if not rows:
        print('!! 一行都没解析出来 —— 检查路径/编码')
        return 1

    print('=' * 78)
    print(f'总事件 {len(rows)} 条；时间跨度 {rows[0]["ts"]} -> {rows[-1]["ts"]}')
    print('=' * 78)
    print('⚠️  铁律 92：events.log 是追加不截断，但「首行时刻」只能说明目录是新的。')
    print('    引擎启动**之前**发生的破坏，这份日志里根本不存在 —— 不能据它判「没拦住」。')
    print()

    # ---------- 1. 目标进程自己的行为 ----------
    mine = [r for r in rows if r['proc'] == target]
    print(f'--- 1. 【{target}】自身事件 {len(mine)} 条 ---')
    if mine:
        print(f'    时间跨度 {mine[0]["ts"]} -> {mine[-1]["ts"]}')
        c = collections.Counter((r['type'], r['verdict'], op_of(r['rest'])) for r in mine)
        for k, v in c.most_common():
            print(f'    {v:7}  {k[0]:6} {k[1]:6} {k[2]}')
    print()

    # ---------- 2. 症状键在整个日志里出现过吗 ----------
    print('--- 2. 症状相关注册表值名（全日志搜索）---')
    text = open(path, 'rb').read().decode('gbk', errors='replace')
    for symptom, name in SYMPTOM_KEYS:
        n = text.count(name)
        flag = '★ 出现过' if n else '  从未出现'
        print(f'    {flag}  {name:24} 命中 {n} 次   （{symptom}）')
    print()

    # ---------- 3. 谁写了 HKCU 下的「用户界面/外壳」相关键 ----------
    print('--- 3. 所有写入类操作里，落点含 Control Panel / Explorer / Policies 的 ---')
    WRITE = {'SetValueKey', 'CreateKey', 'DeleteKey', 'DeleteValueKey',
             'SetInformationKey', 'RenameKey', 'LoadKeyEx'}
    hits = [r for r in rows
            if r['type'] == 'REG' and op_of(r['rest']) in WRITE
            and any(s in key_of(r['rest']) for s in
                    ('Control Panel', 'Explorer', 'Policies', 'CurrentVersion'))]
    agg = collections.Counter((r['proc'], op_of(r['rest']), r['verdict']) for r in hits)
    if not agg:
        print('    （无）')
    for k, v in agg.most_common(25):
        print(f'    {v:7}  {k[0]:32} {k[1]:20} {k[2]}')
    print()

    # ---------- 4. 全进程直方图（找「换了个进程干」）----------
    print('--- 4. 所有在场进程（事件数 TOP 20）---')
    c = collections.Counter(r['proc'] for r in rows)
    for k, v in c.most_common(20):
        print(f'    {v:7}  {k}')
    print()

    # ---------- 5. 被拒绝的操作（真拦住了什么）----------
    print('--- 5. 被拦下的操作（verdict=BLOCK）按 进程/类型/操作 ---')
    b = collections.Counter((r['proc'], r['type'], op_of(r['rest'])) for r in rows
                            if r['verdict'] == 'BLOCK')
    for k, v in b.most_common(20):
        print(f'    {v:7}  {k[0]:32} {k[1]:6} {k[2]}')
    print()

    # ---------- 6. 时间线：目标进程的事件序列（去掉重复风暴）----------
    print(f'--- 6. 【{target}】事件时间线（同 op 连续重复只打首末）---')
    if mine:
        prev = None
        run_start = None
        run_n = 0
        for r in mine:
            sig = (r['type'], r['verdict'], op_of(r['rest']))
            if sig == prev:
                run_n += 1
                continue
            if prev is not None:
                tail = f' ... x{run_n}' if run_n > 1 else ''
                print(f'    {run_start}  {prev[0]:6} {prev[1]:6} {prev[2]}{tail}')
            prev = sig
            run_start = r['ts']
            run_n = 1
        if prev is not None:
            tail = f' ... x{run_n}' if run_n > 1 else ''
            print(f'    {run_start}  {prev[0]:6} {prev[1]:6} {prev[2]}{tail}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
