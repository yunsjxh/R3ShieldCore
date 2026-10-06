import re, collections

import sys, os
p = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'R3ShieldCore', 'Release', 'r3shieldcore-events.log')
pat = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+pid=(\d+)\s+\[([^\]]+)\]\s+tid=(\d+)\s+(.*)$')

rows = []
with open(p, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = pat.match(line.rstrip('\n'))
        if not m:
            continue
        rows.append((m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5)))

TARGET = 'chat-deepseek.all.exe'
tgt = [r for r in rows if r[2].lower() == TARGET]

def parse_rest(rest):
    parts = rest.split(None, 3)
    cat = parts[0] if len(parts) > 0 else ''
    act = parts[1] if len(parts) > 1 else ''
    op = parts[2] if len(parts) > 2 else ''
    kv = parts[3] if len(parts) > 3 else ''
    return cat, act, op, kv

print('========== 1) FILE 路径（去重+计数） ==========')
paths = collections.Counter()
for r in tgt:
    cat, act, op, kv = parse_rest(r[4])
    if cat == 'FILE':
        mm = re.search(r'path=(.*?)\s+\[', kv)
        path = mm.group(1) if mm else kv
        paths[path] += 1
for k, v in paths.most_common():
    print(f'{v:5d}  {k}')

print()
print('========== 2) REG 键（去重+计数） ==========')
keys = collections.Counter()
for r in tgt:
    cat, act, op, kv = parse_rest(r[4])
    if cat == 'REG':
        keys[kv] += 1
for k, v in keys.most_common():
    print(f'{v:5d}  {k}')

print()
print('========== 3) DLL LoadLibrary ==========')
for r in tgt:
    cat, act, op, kv = parse_rest(r[4])
    if cat == 'DLL':
        print(f'  {r[0]}  {op:12s} {kv}')

print()
print('========== 4) 银狐样本启动器.exe (pid 5484) 全部事件 ==========')
for r in rows:
    if r[1] == 5484:
        print(f'  {r[0]}  tid={r[3]}  {r[4]}')

print()
print('========== 5) 17:09:40~17:11:30 全进程非 msedge 事件 ==========')
lo, hi = '2026-10-02 17:09:40', '2026-10-02 17:11:30'
for r in rows:
    if lo <= r[0][:19] <= hi and r[2].lower() != 'msedge.exe':
        print(f'  {r[0]}  pid={r[1]:5d} [{r[2]}] tid={r[3]}  {r[4]}')
