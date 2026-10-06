import re, collections

import sys, os
p = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'R3ShieldCore', 'Release', 'r3shieldcore-events.log')
pat = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+pid=(\d+)\s+\[([^\]]+)\]\s+tid=(\d+)\s+(.*)$')
rows = []
with open(p, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = pat.match(line.rstrip('\n'))
        if m:
            rows.append((m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5)))

print('===== 全部 TOKEN 事件 =====')
for r in rows:
    if r[4].split()[0] == 'TOKEN':
        print(f'  {r[0]}  pid={r[1]:5d} [{r[2]}]  {r[4]}')
print()
print('===== 全部 HOST 事件 =====')
for r in rows:
    if r[4].split()[0] == 'HOST':
        print(f'  {r[0]}  pid={r[1]:5d} [{r[2]}]  {r[4]}')
print()
print('===== 全部 PROC 事件 =====')
for r in rows:
    if r[4].split()[0] == 'PROC':
        print(f'  {r[0]}  pid={r[1]:5d} [{r[2]}]  {r[4]}')
print()
print('===== 目标进程 NET 事件 =====')
tgt = [r for r in rows if r[2].lower() == 'chat-deepseek.all.exe']
anynet = [r for r in tgt if r[4].split()[0] == 'NET']
print(f'  count={len(anynet)}')
for r in anynet[:40]:
    print(f'  {r[0]}  {r[4]}')
print()
print('===== 全日志 NET 事件按 (进程,动作,op) 统计 =====')
c = collections.Counter()
for r in rows:
    if r[4].split()[0] == 'NET':
        parts = r[4].split(None, 3)
        c[(r[2], parts[1], parts[2])] += 1
for k, v in c.most_common(30):
    print(f'  {v:6d}  {k[0]:22s} {k[1]:8s} {k[2]}')
