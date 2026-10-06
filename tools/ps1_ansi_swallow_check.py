"""ps1_ansi_swallow_check.py -- detect the "CJK comment ate the LF" bug in .ps1 files.

WHY THIS EXISTS (v62, real incident)
------------------------------------
PowerShell 5.1 reads a .ps1 file as ANSI (codepage 936 on a Chinese system)
unless the file starts with a UTF-8 BOM.  If the file

  * is saved as UTF-8, and
  * contains CJK text in a `#` comment, and
  * uses bare LF line endings,

then the LAST CJK character's UTF-8 byte sequence ends in a LEAD byte (>=0x81)
followed by 0x0A.  0x0A is not a valid GBK trail byte, so the decoder consumes
BOTH bytes and emits '?'.  The newline is gone -> the next physical line becomes
part of the comment -> **that line's code never runs**.

There is no parse error and no warning.  The only symptom is that a variable
silently keeps its previous value, so later assertions "fail" for no visible
reason.  (v62: $AVAILABLE / $RESUMED / $NOTENABLED were never assigned, which
made a healthy ARK feature look broken across two debugging sessions.)

This is the same failure family as iron rule 40 (a .bat with CJK + LF-only makes
cmd's parser lose sync).  Fix: keep .ps1 sources **pure ASCII** -- then ANSI
decoding is a no-op regardless of the line endings.

★ The decoder here deliberately reproduces .NET/Windows behaviour, NOT Python's:
  Python's `gbk` codec keeps the newline, .NET's eats it.  Verified empirically
  in v62 with [System.Text.Encoding]::GetEncoding(936).GetString().

Usage:
    python tools/ps1_ansi_swallow_check.py [glob ...]
Exit code 1 if any file is affected.
"""
import glob
import sys

# Code appearing AFTER a '#' on the same decoded line == a swallowed line.
CODE_TOKENS = ('$', '[char]', 'function ', 'if (', 'if(', 'Write-Output',
               'foreach', 'switch', 'param', 'return ', 'Set-', 'Get-', 'New-')


def decode_like_windows(raw):
    """Decode bytes the way .NET's codepage-936 decoder does.

    Invalid lead/trail pair -> consume BOTH bytes, emit '?'.
    """
    out = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b < 0x80:
            out.append(chr(b))
            i += 1
            continue
        if i + 1 < n:
            lead, trail = b, raw[i + 1]
            if 0x81 <= lead <= 0xFE and (0x40 <= trail <= 0x7E
                                         or 0x80 <= trail <= 0xFE):
                try:
                    out.append(bytes((lead, trail)).decode('gbk'))
                except UnicodeDecodeError:
                    out.append('?')
                i += 2
                continue
        # Invalid pair: Windows eats the lead byte AND the following byte.
        out.append('?')
        i += 2 if i + 1 < n else 1
    return ''.join(out)


def check(path):
    raw = open(path, 'rb').read()
    has_bom = raw.startswith(b'\xef\xbb\xbf')
    non_ascii = sum(1 for x in raw if x > 127)
    crlf = raw.count(b'\r\n')
    bare_lf = raw.count(b'\n') - crlf

    if non_ascii == 0 or has_bom:
        # Pure ASCII -> ANSI decoding is a no-op.
        # UTF-8 BOM   -> PowerShell 5.1 reads the file as UTF-8, so no mojibake.
        return has_bom, non_ascii, crlf, bare_lf, []

    seen = decode_like_windows(raw)
    hits = []
    for n, line in enumerate(seen.split('\n'), 1):
        hash_at = line.find('#')
        if hash_at < 0:
            continue
        tail = line[hash_at + 1:]
        for tok in CODE_TOKENS:
            if tok in tail:
                hits.append((n, line.strip()[:120]))
                break
    return has_bom, non_ascii, crlf, bare_lf, hits


# ★ 递归扫全仓，而不是只扫 tools/ 和根目录。
#   原来写的是 ['tools/*.ps1', '*.ps1'] —— 于是**新增的目录（例如 driver/）里的
#   .ps1 根本不会被检查**，闸门照样 PASS。这正是"诊断口径必须 ≥ 触发口径"
#   （铁律 99）：检查器的覆盖范围必须跟着代码的存放位置走，否则它只是在
#   检查一个越来越小的子集，而且**看起来永远是绿的**。
DEFAULT_GLOBS = ['**/*.ps1']

# 只排除真正的产物/缓存目录；dist 不排除 —— 那里面是要发给用户的脚本，
# 恰恰最该被检查。
EXCLUDE_DIRS = ('_t', 'obj', 'verdir', '.git', '.workbuddy-ai', 'node_modules')


def _excluded(path):
    parts = path.replace('\\', '/').split('/')
    return any(d in parts for d in EXCLUDE_DIRS)


def main():
    globs = sys.argv[1:] or DEFAULT_GLOBS
    files = []
    for g in globs:
        files.extend(glob.glob(g, recursive=True))
    files = sorted(p for p in set(files) if not _excluded(p))

    affected = 0
    for path in files:
        try:
            has_bom, non_ascii, crlf, bare_lf, hits = check(path)
        except OSError as exc:
            print('[skip] %s (%s)' % (path, exc))
            continue
        if non_ascii == 0 or has_bom:
            continue
        print('=== %s   non-ascii=%d  CRLF=%d  bare-LF=%d  BOM=no'
              % (path, non_ascii, crlf, bare_lf))
        if not hits:
            # Still a hazard: only luck (a comment/blank line) kept the code
            # from being eaten.  Report it rather than stay silent.
            print('    no swallowed lines detected -- but non-ASCII + no BOM is a latent hazard')
        for n, text in hits:
            print('    L%-4d SWALLOWED -> %s' % (n, text))
        if hits:
            affected += 1

    print()
    if affected:
        print('FAIL: %d file(s) have CJK comments eating the following line.' % affected)
        print('      Fix: keep the .ps1 pure ASCII, or save it as UTF-8 WITH BOM.')
        return 1
    print('PASS: every .ps1 is either pure ASCII or UTF-8-with-BOM.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
