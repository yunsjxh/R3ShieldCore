import re, collections

import sys, os
p = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'R3ShieldCore', 'Release', 'r3shieldcore-events.log')
pat = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+pid=(\d+)\s+\[([^\]]+)\]\s+tid=(\d+)\s+(.*)$')

rows = []
head = []
tail = []
with open(p, 'r', encoding='utf-8', errors='replace') as f:
    for i, line in enumerate(f):
        if i < 25:
            head.append(line.rstrip('\n'))
        m = pat.match(line.rstrip('\n'))
        if not m:
            continue
        rows.append((m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5)))

print('========== 日志头部（前 25 行） ==========')
for h in head:
    print('  ', h)

print()
print('========== WerFault.exe 事件 (pid 3700) ==========')
for r in rows:
    if r[1] == 3700:
        print(f'  {r[0]}  tid={r[3]}  {r[4]}')

print()
print('========== smartscreen.exe 事件 (pid 6592) ==========')
for r in rows:
    if r[1] == 6592:
        print(f'  {r[0]}  tid={r[3]}  {r[4]}')

print()
print('========== 目标进程最后 20 条事件 ==========')
tgt = [r for r in rows if r[2].lower() == 'chat-deepseek.all.exe']
for r in tgt[-20:]:
    print(f'  {r[0]}  tid={r[3]}  {r[4]}')

print()
print('========== 全部事件类别统计（全日志） ==========')
cat = collections.Counter()
for r in rows:
    cat[r[4].split()[0]] += 1
for k, v in cat.most_common():
    print(f'  {v:8d}  {k}')

print()
print('========== 全日志中所有 PROC / MEM / TOKEN / THREAD / INJECT / HOOK 事件 ==========')
for r in rows:
    c = r[4].split()[0]
    if c in ('PROC', 'MEM', 'TOKEN', 'THREAD', 'INJECT', 'HOOK', 'APC'):
        print(f'  {r[0]}  pid={r[1]:5d} [{r[2]}]  {r[4]}')

print()
print('========== 日志尾部（最后 15 行） ==========')
with open(p, 'r', encoding='utf-8', errors='replace') as f:
    alll = f.readlines()
for line in alll[-15:]:
    print('  ', line.rstrip('\n'))
