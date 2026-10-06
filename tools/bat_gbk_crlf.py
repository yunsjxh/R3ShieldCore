#!/usr/bin/env python3
"""
bat_gbk_crlf.py —— 把 .bat 规范化成 cmd 能安全解析的形式：**CRLF + GBK + 无 BOM**。

为什么必须有这个工具（铁律 40）：

    cmd.exe 读 .bat 是按 **ANSI 代码页（中文系统 = 936）** 逐字节解析的。
    如果文件是 UTF-8 且用 **LF 换行**，一个中文字的**尾字节**很可能落在
    0x0A 之外、而下一字节恰好构成换行判定的错位 —— 于是 cmd 从某一行起
    **解析失同步**，后面的命令被当成上一行的参数。

    症状极其误导：脚本"一闪而过"、什么都不做、或执行了一半就没了。
    没有语法错误、没有提示。

    .ps1 也有同类问题，但解法相反（见 tools/ps1_add_bom.py）：
        .bat  → CRLF + GBK + **无** BOM     （cmd 不认 BOM，会把 BOM 当命令）
        .ps1  → UTF-8 + **有** BOM          （PS 5.1 见 BOM 才按 UTF-8 解码）

用法：
    python tools/bat_gbk_crlf.py driver/install_driver.bat      # 就地转换
    python tools/bat_gbk_crlf.py --check driver/*.bat           # 只检查不改
    python tools/bat_gbk_crlf.py --all                          # 全仓 .bat
退出码：0 = 全部合规 / 已转换；1 = 检查模式下发现不合规，或有字符编不出 GBK
"""

import glob
import os
import sys

BAT_BOM_UTF8 = b"\xef\xbb\xbf"
BAT_BOM_UTF16LE = b"\xff\xfe"
BAT_BOM_UTF16BE = b"\xfe\xff"


def analyze(path):
    """返回 (问题列表, 修复后的字节)。问题为空表示已合规。"""
    with open(path, "rb") as f:
        raw = f.read()

    problems = []

    if raw.startswith(BAT_BOM_UTF8):
        problems.append("带 UTF-8 BOM —— cmd 会把 BOM 当成命令的一部分")
        raw_body = raw[len(BAT_BOM_UTF8):]
    elif raw.startswith(BAT_BOM_UTF16LE) or raw.startswith(BAT_BOM_UTF16BE):
        problems.append("是 UTF-16 —— cmd 只认 ANSI/GBK")
        return problems, None
    else:
        raw_body = raw

    # 解码：优先按 UTF-8 读（本仓源码约定），失败再按 GBK
    try:
        text = raw_body.decode("utf-8")
        encoding_used = "utf-8"
    except UnicodeDecodeError:
        try:
            text = raw_body.decode("gbk")
            encoding_used = "gbk"
        except UnicodeDecodeError as e:
            problems.append("既不是 UTF-8 也不是 GBK，无法解码: %s" % e)
            return problems, None

    # 换行
    crlf = raw_body.count(b"\r\n")
    lf_total = raw_body.count(b"\n")
    bare_lf = lf_total - crlf
    if bare_lf > 0:
        problems.append("有 %d 个裸 LF 换行 —— 必须全部是 CRLF" % bare_lf)
    if crlf == 0 and lf_total == 0:
        problems.append("没有换行符？")

    # GBK 可表示性
    unencodable = []
    for i, ch in enumerate(text):
        if ord(ch) < 128:
            continue
        try:
            ch.encode("gbk")
        except UnicodeEncodeError:
            line = text.count("\n", 0, i) + 1
            unencodable.append((line, ch, ord(ch)))
    if unencodable:
        for line, ch, cp in unencodable[:20]:
            problems.append("第 %d 行的 %r (U+%04X) 编不进 GBK" % (line, ch, cp))

    # 规范化文本
    norm = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    try:
        fixed = norm.encode("gbk")
    except UnicodeEncodeError:
        return problems, None  # 有编不出的字符，不产出

    if encoding_used == "utf-8" and fixed != raw:
        pass  # 正常：从 UTF-8 转成了 GBK

    return problems, fixed


def main():
    args = [a for a in sys.argv[1:]]
    check_only = "--check" in args
    args = [a for a in args if not a.startswith("--")]

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if "--all" in sys.argv:
        targets = sorted(glob.glob(os.path.join(root, "**", "*.bat"), recursive=True))
        targets = [t for t in targets
                   if not any(seg in t for seg in ("_t" + os.sep, "obj" + os.sep,
                                                   "dist" + os.sep, "verdir" + os.sep))]
    elif args:
        targets = []
        for a in args:
            targets.extend(glob.glob(a) or [a])
    else:
        print("用法: python tools/bat_gbk_crlf.py <file.bat>... | --all | --check ...")
        return 2

    if not targets:
        print("没有匹配到 .bat 文件")
        return 1

    bad = 0
    for path in targets:
        if not os.path.isfile(path):
            print("[INFO] 跳过不存在的文件: %s" % path)
            continue
        problems, fixed = analyze(path)
        rel = os.path.relpath(path, root)
        if not problems and fixed is None:
            print("[ OK ] %s（已合规）" % rel)
            continue
        if not problems:
            print("[ OK ] %s（已合规）" % rel)
            continue

        bad += 1
        print("[FAIL] %s" % rel)
        for p in problems:
            print("        - %s" % p)

        if check_only:
            continue
        if fixed is None:
            print("        → 无法自动修复（有编不进 GBK 的字符），请手工替换成 ASCII")
            continue
        with open(path, "wb") as f:
            f.write(fixed)
        print("        → 已重写为 CRLF + GBK + 无 BOM（%d 字节）" % len(fixed))

    print()
    if check_only:
        if bad == 0:
            print("PASS: 所有 .bat 都符合 CRLF + GBK + 无 BOM。")
            return 0
        print("FAIL: %d 个 .bat 不合规。" % bad)
        return 1

    if bad == 0:
        print("PASS: 所有 .bat 都符合 CRLF + GBK + 无 BOM。")
    else:
        print("已处理 %d 个 .bat；若上面还有 [FAIL] 说明有字符编不进 GBK，需手工改。" % bad)
    return 0


if __name__ == "__main__":
    sys.exit(main())
