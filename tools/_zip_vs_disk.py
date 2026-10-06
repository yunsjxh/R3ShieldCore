import zipfile, hashlib, os

z = zipfile.ZipFile('dist/R3ShieldCore-x64.zip')
names = [n.replace('\\', '/') for n in z.namelist()]
print('zip 条目总数:', len(names))

targets = [
    'R3 ShieldCore.exe',
    '64/r3shieldcore-lib.dll',
    'r3shieldcore.ini',
]

for suffix in targets:
    cands = [n for n in names if n.endswith(suffix)]
    if not cands:
        print('  [zip 里没有]', suffix)
        continue
    zb = z.read(cands[0])
    dp = 'dist/R3ShieldCore-x64/' + suffix
    db = open(dp, 'rb').read() if os.path.exists(dp) else None
    zh = hashlib.sha256(zb).hexdigest()[:32]
    dh = hashlib.sha256(db).hexdigest()[:32] if db is not None else 'MISSING'
    verdict = 'IDENTICAL' if zh == dh else '*** DIFFERENT ***'
    print('%-32s zip=%s  disk=%s  %s' % (suffix, zh, dh, verdict))
