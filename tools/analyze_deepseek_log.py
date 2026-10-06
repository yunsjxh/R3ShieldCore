import re, collections, sys

import sys, os
p = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'R3ShieldCore', 'Release', 'r3shieldcore-events.log')
pat = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+pid=(\d+)\s+\[([^\]]+)\]\s+tid=(\d+)\s+(.*)$')

byproc = collections.Counter()
byproc_pid = {}
rows = []
with open(p, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        m = pat.match(line.rstrip('\n'))
        if not m:
            continue
        ts, pid, proc, tid, rest = m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5)
        byproc[proc] += 1
        byproc_pid.setdefault(proc, set()).add(pid)
        rows.append((ts, pid, proc, tid, rest))

print('total parsed', len(rows))
print('--- by process (top 40) ---')
for k, v in byproc.most_common(40):
    print(f'{v:8d}  pids={sorted(byproc_pid[k])}  {k}')

TARGET = 'chat-deepseek.all.exe'
tgt = [r for r in rows if r[2].lower() == TARGET]
print()
print(f'=== {TARGET}: {len(tgt)} events, pids={sorted(set(r[1] for r in tgt))} ===')
if tgt:
    print('time range:', tgt[0][0], '->', tgt[-1][0])

# parse rest: "CATEGORY ACTION  OpName  k=v ..."
def parse_rest(rest):
    parts = rest.split(None, 3)
    cat = parts[0] if len(parts) > 0 else ''
    act = parts[1] if len(parts) > 1 else ''
    op = parts[2] if len(parts) > 2 else ''
    kv = parts[3] if len(parts) > 3 else ''
    return cat, act, op, kv

# category/action/op breakdown
ca = collections.Counter()
opc = collections.Counter()
for r in tgt:
    cat, act, op, kv = parse_rest(r[4])
    ca[(cat, act)] += 1
    opc[(cat, act, op)] += 1
print()
print('--- (category, action) ---')
for k, v in ca.most_common():
    print(f'{v:8d}  {k[0]:6s} {k[1]}')
print()
print('--- (category, action, op) ---')
for k, v in opc.most_common():
    print(f'{v:8d}  {k[0]:6s} {k[1]:6s} {k[2]}')
