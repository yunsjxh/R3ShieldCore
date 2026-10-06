"""Add a UTF-8 BOM to .ps1 files that contain non-ASCII text and have no BOM.

WHY: PowerShell 5.1 reads a .ps1 as ANSI unless it starts with a UTF-8 BOM.
Without the BOM, CJK comment text is mis-decoded and the decoder can swallow the
newline after it, silently commenting out the following line (see
ps1_ansi_swallow_check.py for the full story).  A BOM makes PowerShell read the
file as UTF-8, which restores both the text and the line structure.

Refuses to touch a file that is not valid UTF-8 (that would need a real
re-encode, not a BOM).

Usage: python tools/ps1_add_bom.py [--dry-run] [file.ps1 ...]
"""
import glob
import sys

BOM = b'\xef\xbb\xbf'

# ★ 递归扫全仓。原先是 ['tools/*.ps1', '*.ps1'] —— 新增目录里的 .ps1
#   （例如 driver/）会被**完全漏掉**，而检查器同样漏掉 ⇒ 两边一起静默通过。
DEFAULT_GLOBS = ['**/*.ps1']

EXCLUDE_DIRS = ('_t', 'obj', 'verdir', '.git', '.workbuddy-ai', 'node_modules')


def _excluded(path):
    parts = path.replace('\\', '/').split('/')
    return any(d in parts for d in EXCLUDE_DIRS)


def collect_targets(argv):
    explicit = [a for a in argv if not a.startswith('--')]
    if explicit:
        out = []
        for a in explicit:
            out.extend(glob.glob(a) or [a])
        return sorted(p for p in set(out) if not _excluded(p))
    out = []
    for g in DEFAULT_GLOBS:
        out.extend(glob.glob(g, recursive=True))
    return sorted(p for p in set(out) if not _excluded(p))


def main():
    dry = '--dry-run' in sys.argv
    changed = 0
    for path in collect_targets(sys.argv[1:]):
        raw = open(path, 'rb').read()
        if raw.startswith(BOM):
            continue
        if max(raw, default=0) < 128:
            continue
        try:
            raw.decode('utf-8')
        except UnicodeDecodeError as exc:
            print('[SKIP] %s -- not valid UTF-8 (%s); needs a real re-encode' % (path, exc))
            continue
        if dry:
            print('[dry-run] would add BOM: %s' % path)
        else:
            with open(path, 'wb') as fh:
                fh.write(BOM + raw)
            print('[ OK ] added UTF-8 BOM: %s' % path)
        changed += 1
    print('\n%d file(s) %s.' % (changed, 'to change' if dry else 'changed'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
