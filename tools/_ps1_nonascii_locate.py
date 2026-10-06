"""One-off: show where non-ASCII bytes live in each .ps1 (comment vs string)."""
import glob
import sys

sys.path.insert(0, 'tools')
from ps1_ansi_swallow_check import decode_like_windows  # noqa: E402


def classify(line):
    stripped = line.strip()
    if stripped.startswith('#'):
        return 'COMMENT'
    if '#' in line:
        return 'CODE+COMMENT'
    return 'CODE/STRING'


for path in sorted(set(glob.glob('tools/*.ps1') + glob.glob('*.ps1'))):
    raw = open(path, 'rb').read()
    if max(raw, default=0) < 128:
        continue
    seen = decode_like_windows(raw)
    print('=== %s' % path)
    shown = 0
    for n, line in enumerate(seen.split('\n'), 1):
        if max((ord(c) for c in line), default=0) < 128:
            continue
        print('    L%-4d [%s] %s' % (n, classify(line), line.strip()[:100]))
        shown += 1
        if shown >= 12:
            print('    ... (more non-ASCII lines omitted)')
            break
    print()
