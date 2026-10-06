# -*- coding: utf-8 -*-
"""一次性脚本：把 dist/R3ShieldCore-x64/r3shieldcore.ini 里的长篇注释抽出来，
生成 dist/R3ShieldCore-x64/配置详解.md（逐项参考）。跑完即可删除本文件。"""
import re

SRC = 'dist/R3ShieldCore-x64/r3shieldcore.ini'
DST = 'dist/R3ShieldCore-x64/配置详解.md'

lines = open(SRC, encoding='utf-8').read().splitlines()

DASH = re.compile(r'^#\s*-{10,}\s*$')
SEC = re.compile(r'^#\s*-{2,}\s*(\S.*?)\s*-{2,}\s*$')
KV = re.compile(r'^([a-z_]+)\s*=\s*(.*)$')


def join_par(par):
    """把折行拼回一段：中文直接相接，ASCII 单词之间补空格。"""
    s = ''
    for piece in par:
        if s and s[-1].isascii() and s[-1].isalnum() and piece[:1].isascii() and piece[:1].isalnum():
            s += ' '
        s += piece
    return s


out = []
paras = []      # 已完成段落
cur = []        # 当前段落


def close_par():
    global cur
    if cur:
        paras.append(join_par(cur))
        cur = []


def emit_body():
    """把已积累的段落写成 markdown。"""
    for p in paras:
        out.append(p)
        out.append('')
    if cur:
        out.append(join_par(cur))
        out.append('')
    paras.clear()
    cur.clear()


i, n = 0, len(lines)
started = False
while i < n:
    ln = lines[i]
    s = ln.strip()

    # 三明治标题：# ---- / # 标题 / # ----
    if DASH.match(s) and i + 2 < n and lines[i + 1].strip().startswith('#') \
            and DASH.match(lines[i + 2].strip()):
        close_par()
        title = lines[i + 1].strip().lstrip('#').strip()
        if not started:
            started = True
        emit_body()
        out.append('## ' + title)
        out.append('')
        i += 3
        continue

    # 单行长横线 → 分隔
    if DASH.match(s):
        close_par()
        i += 1
        continue

    # # ---- 章节名 ----
    m = SEC.match(s)
    if m:
        close_par()
        if started:
            emit_body()
        else:
            started = True
            paras.clear()
            cur.clear()
        out.append('## ' + m.group(1))
        out.append('')
        i += 1
        continue

    # 键=值：注释在键**之前**，所以先写标题、再写积累的说明
    m = KV.match(ln)
    if m:
        key, val = m.group(1), m.group(2)
        close_par()
        out.append('### `%s`' % key)
        out.append('')
        out.append('```ini')
        out.append('%s=%s' % (key, val))
        out.append('```')
        out.append('')
        emit_body()
        i += 1
        continue

    if s.startswith('#'):
        t = s.lstrip('#').strip()
        if t:
            cur.append(t)
        else:
            close_par()
        i += 1
        continue

    i += 1

close_par()
emit_body()

text = '\n'.join(out)
text = re.sub(r'\n{3,}', '\n\n', text).rstrip() + '\n'
open(DST, 'w', encoding='utf-8', newline='\n').write(text)
print('wrote', DST, len(text), 'chars')
