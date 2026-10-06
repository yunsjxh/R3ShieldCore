#!/usr/bin/env bash
#
# fix_bat_encoding.sh —— 把 .bat / .cmd 规范化成 cmd.exe **能正确解析**的形态。
#
# 【为什么必须做这一步】
#   cmd.exe 按**字节**读批处理文件。文件含非 ASCII 字符且行尾是 LF-only 时，
#   解析器的行偏移会**失同步** —— 它会把上一行的尾巴和下一行的开头拼成一条
#   命令拿去执行。实测（2026-10-03，CP936 控制台）：
#
#     | 行尾 | 编码        | 结果                                   |
#     |------|-------------|----------------------------------------|
#     | LF   | ASCII       | OK                                     |
#     | CRLF | ASCII       | OK                                     |
#     | LF   | UTF-8 中文  | ★ 崩：'鏂?if' 不是内部或外部命令       |
#     | CRLF | UTF-8 中文  | 能跑，但中文乱码                        |
#     | LF   | GBK 中文    | ★ 崩：'中文' 不是内部或外部命令        |
#     | CRLF | GBK 中文    | ★ 完全正常                              |
#
#   ⇒ **只要含非 ASCII，就必须 CRLF**；中文内容用 **GBK**（本机 CP936 原生）。
#   ⇒ 也不能有 UTF-8 BOM（`\xEF\xBB\xBF@echo off` 会被当成命令名）。
#
# 【第二个坑：GBK 第二字节撞 cmd 元字符】
#   GBK 双字节字符的**第二字节**范围是 0x40-0x7E / 0x80-0xFE，其中
#       0x5C \   0x7C |   0x5E ^   0x60 `   0x7B {   0x7D }   0x7E ~
#   都是 cmd.exe 的元字符。cmd 按字节解析 ⇒ 一个"无辜的中文字"会在
#   命令行里凭空造出一个管道 / 转义 / 变量修饰符。
#   这个**没法自动修**（只能换词），所以本脚本只**报错拦住**（exit 1），
#   由人改文案。常见安全写法：避免在 echo 里用生僻字，改完重跑本脚本。
#
# 【为什么需要工具而不是靠自觉】
#   任何"用文本编辑器/程序化方式"生成 .bat 的地方（包括 AI 的写文件工具）
#   默认都吐 LF。靠自觉一定会再犯 —— 所以：**生成之后立刻规范化 + 闸门拦截**。
#
# 用法:
#   bash fix_bat_encoding.sh                      # 规范化 dist/R3ShieldCore-x64
#   bash fix_bat_encoding.sh fix <目录|文件>...   # 规范化指定目标
#   bash fix_bat_encoding.sh verify <目录|文件>.. # 只检查（不通过则 exit 1）
#
set -u

# ---- 工具链/路径统一由仓库根的 scripts_env.sh 自动探测 ----
#   本脚本可能位于仓库根或子目录（driver/ installer/ tools/），
#   所以向上找到含 scripts_env.sh 的目录（= 仓库根）。
R3SC_ENV=""; _d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ "$_d" != "/" ] && [ -n "$_d" ]; do
    if [ -f "$_d/scripts_env.sh" ]; then R3SC_ENV="$_d/scripts_env.sh"; break; fi
    _d="$(dirname "$_d")"
done
if [ -z "$R3SC_ENV" ]; then echo "scripts_env.sh 未找到（应在仓库根）"; exit 1; fi
# shellcheck source=scripts_env.sh
. "$R3SC_ENV"
PROJECT_ROOT="$R3SC_PROJECT_ROOT"
PY="$PYTHON"   # 由 scripts_env.sh 自动探测（见文件头）
MODE="fix"
case "${1:-}" in
    fix|verify) MODE="$1"; shift ;;
esac

TARGETS=("$@")
if [ "${#TARGETS[@]}" -eq 0 ]; then
    TARGETS=("dist/R3ShieldCore-x64")
fi

cd "$PROJECT_ROOT" || exit 1

"$PY" - "$MODE" "${TARGETS[@]}" <<'PYEOF'
import os
import sys

mode = sys.argv[1]
targets = sys.argv[2:]


def collect(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'build')]
        for f in sorted(files):
            if f.lower().endswith(('.bat', '.cmd')):
                yield os.path.join(root, f)


def decode(data):
    if data.startswith(b'\xef\xbb\xbf'):
        return data[3:].decode('utf-8'), 'utf8-bom'
    try:
        return data.decode('utf-8'), 'utf8'
    except UnicodeDecodeError:
        pass
    try:
        return data.decode('gbk'), 'gbk'
    except UnicodeDecodeError:
        return None, 'unknown'


def normalize(text):
    # 先把所有换行统一成 \n，再整体换成 \r\n（幂等）。
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text.replace('\n', '\r\n')


# GBK 第二字节里会撞上 cmd.exe 元字符的那几个（0x40-0x7E 区间内）
DANGER_TRAIL = {0x5C: '\\', 0x7C: '|', 0x5E: '^', 0x60: '`', 0x7B: '{', 0x7D: '}', 0x7E: '~'}


def danger_chars(raw):
    """找出「GBK 双字节字符的第二字节是 cmd 元字符」的位置。

    返回 [(行号, 字符, 元字符), ...]。这类字符没法自动改，只能换词。
    """
    hits = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if 0x81 <= b <= 0xFE and i + 1 < n:
            b2 = raw[i + 1]
            if 0x40 <= b2 <= 0xFE and b2 != 0x7F:
                if b2 in DANGER_TRAIL:
                    try:
                        ch = raw[i:i + 2].decode('gbk')
                    except Exception:
                        ch = '?'
                    hits.append((raw[:i].count(b'\n') + 1, ch, DANGER_TRAIL[b2]))
                i += 2
                continue
        i += 1
    return hits


problems = []
changed = []

for target in targets:
    for path in collect(target):
        raw = open(path, 'rb').read()
        text, enc = decode(raw)

        if text is None:
            problems.append((path, '无法按 UTF-8/GBK 解码（编码未知）'))
            continue

        has_non_ascii = any(b > 127 for b in raw)
        crlf = raw.count(b'\r\n')
        bare_lf = raw.count(b'\n') - crlf
        bom = raw.startswith(b'\xef\xbb\xbf')

        issues = []
        if bom:
            issues.append('有 UTF-8 BOM')
        if bare_lf:
            issues.append('有 %d 个 LF-only 行尾' % bare_lf)
        if has_non_ascii and enc != 'gbk':
            issues.append('含非 ASCII 但编码是 %s（应为 GBK）' % enc)

        # ★ 这个不能自动修（要改文案），所以无论 fix 还是 verify 都记成 problem
        danger = danger_chars(raw)
        if danger:
            shown = '、'.join('%r 的第二字节是 %s' % (c, m) for _, c, m in danger[:5])
            more = '' if len(danger) <= 5 else '（共 %d 处）' % len(danger)
            problems.append((path, 'GBK 字符撞 cmd 元字符：%s%s —— 请换掉这些字' % (shown, more)))

        if not issues and not danger:
            print('  OK    %s  (CRLF=%d, %s)' % (path.replace('\\', '/'), crlf, enc))
            continue

        if mode == 'verify':
            if issues:
                problems.append((path, '；'.join(issues)))
            continue

        if not issues:
            # 只有"撞元字符"这类不可自动修复的问题
            print('  KEEP  %s  (编码/行尾已正确，但有不可自动修复的问题)' % path.replace('\\', '/'))
            continue

        fixed = normalize(text)
        try:
            out = fixed.encode('gbk')
        except UnicodeEncodeError as exc:
            problems.append((path, '无法转成 GBK: %s' % exc))
            continue

        if out != raw:
            open(path, 'wb').write(out)
            changed.append(path)
        print('  FIXED %s  (%s)' % (path.replace('\\', '/'), '；'.join(issues)))

print()
if mode == 'verify':
    if problems:
        print('!! 有 %d 个 .bat/.cmd 不能被 cmd.exe 正确解析：' % len(problems))
        for path, why in problems:
            print('     %s  ->  %s' % (path.replace('\\', '/'), why))
        print()
        print('   修复: bash fix_bat_encoding.sh fix <目录>')
        sys.exit(1)
    print('所有 .bat/.cmd 都是 CRLF + GBK（cmd.exe 可正确解析）。')
    sys.exit(0)

if problems:
    for path, why in problems:
        print('!! 未修复 %s  ->  %s' % (path.replace('\\', '/'), why))
    sys.exit(1)
print('规范化完成：%d 个文件被改写。' % len(changed))
PYEOF
