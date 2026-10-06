#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_text_file.py —— 对**带编码/行尾约束**的文本文件做精确替换，且绝不把文件改坏。

为什么需要它
============
本仓有两类"改坏了不会报错、只会静默失效"的文件：

  · `installer/*.bat`、`driver/*.bat`  —— GBK + CRLF（铁律 40）
  · `*.ps1`                            —— UTF-8 + BOM（铁律 104）
  · 普通源码                            —— UTF-8 无 BOM + LF

用编辑器/通用文本工具直接改它们，会在两个地方静默翻车：

  ① **编码**：按 UTF-8 读一个 GBK 文件 → 中文变乱码 → 再写回就是乱码文件。
     更狠的是"先 open(wb) 再 encode"：`open(...,"wb")` 会**立刻截断**，
     而 `text.encode("gbk")` 是在之后才求值 —— 它一抛异常，文件已经是 **0 字节**。
     本项目实测踩过：installer/install.bat 被清零，仓里没有 git、没有备份
     （铁律 132/133）。
  ② **行尾**：把 CRLF 写成 LF，.bat 会"一闪而过"（铁律 40）。

本工具的做法
============
  · 先读**字节**，再按探测到的编码解码（也可显式指定）；
  · 每条替换都要求**命中次数符合预期**，并且**内容真的变了** ——
    没匹配上就报错退出，绝不"静默什么都没改"；
  · 先写 `<file>.tmp`，`os.replace()` 原子替换 —— 中途抛异常时原文件**完好**；
  · 写回后**再读一遍**复核：编码、行尾、每条新文本都在。

用法
====
    python tools/patch_text_file.py <file> <edits.json> [--enc gbk|utf-8|utf-8-sig] [--eol crlf|lf] [--dry]

edits.json 形如：
    {
      "edits": [
        {"old": "set X=1\r\n", "new": "set X=2\r\n", "count": 1},
        {"old": "abc", "new": "abd"}
      ]
    }

  · `count` 省略时默认 1；写 `"count": "all"` 表示必须至少命中一次、全部替换。
  · `--dry` 只报告会改什么，不落盘。
"""

import json
import os
import sys

ENCODINGS = ("utf-8-sig", "utf-8", "gbk")


def sniff(raw):
    """返回 (编码, 是否有 BOM)。utf-8-sig 优先 —— 否则 BOM 会被当成正文。"""
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig", True
    for enc in ("utf-8", "gbk"):
        try:
            raw.decode(enc)
            return enc, False
        except UnicodeDecodeError:
            continue
    return None, False


def detect_eol(text):
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    if crlf and lf:
        return "mixed"
    if crlf:
        return "crlf"
    return "lf"


def main():
    args = [a for a in sys.argv[1:]]
    dry = "--dry" in args
    args = [a for a in args if a != "--dry"]

    enc_force = None
    eol_force = None
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "--enc":
            enc_force = args[i + 1]
            i += 2
        elif args[i] == "--eol":
            eol_force = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1

    if len(rest) != 2:
        print(__doc__)
        return 2

    path, spec_path = rest

    with open(path, "rb") as f:
        raw = f.read()

    enc, had_bom = sniff(raw)
    if enc_force:
        enc = enc_force
    if enc is None:
        print("[败] 探测不出编码（既不是 UTF-8 也不是 GBK）：%s" % path)
        return 1

    try:
        text = raw.decode(enc)
    except UnicodeDecodeError as e:
        print("[败] 按 %s 解码失败：%s" % (enc, e))
        return 1

    eol = detect_eol(text)
    if eol_force:
        eol = eol_force
    if eol == "mixed":
        print("[败] 行尾是混合的（既有 CRLF 又有 LF）—— 先统一再改，否则替换会漏")
        return 1

    with open(spec_path, "r", encoding="utf-8") as f:
        spec = json.load(f)

    original = text
    report = []

    for idx, edit in enumerate(spec.get("edits", [])):
        old = edit["old"]
        new = edit["new"]
        want = edit.get("count", 1)

        if old == new:
            print("[败] 第 %d 条 old == new，是无操作" % (idx + 1))
            return 1

        found = text.count(old)
        if want == "all":
            if found == 0:
                print("[败] 第 %d 条一处都没匹配上（old 前 60 字：%r）" % (idx + 1, old[:60]))
                return 1
            text = text.replace(old, new)
            report.append("第 %d 条: 替换 %d 处" % (idx + 1, found))
        else:
            if found != want:
                print("[败] 第 %d 条命中 %d 次，期望 %d 次 —— 拒绝" 
                      "「没匹配上就静默跳过」（old 前 60 字：%r）"
                      % (idx + 1, found, want, old[:60]))
                return 1
            text = text.replace(old, new, want)
            report.append("第 %d 条: 替换 %d 处" % (idx + 1, want))

    if text == original:
        print("[败] 全部替换执行完后内容**没有任何变化** —— 这不该发生")
        return 1

    print("文件      : %s" % path)
    print("编码      : %s%s" % (enc, "（带 BOM）" if enc == "utf-8-sig" else ""))
    print("行尾      : %s" % eol)
    for line in report:
        print("  " + line)

    if dry:
        print("（--dry：未落盘）")
        return 0

    # ★ 先编码成字节，再碰目标文件 —— 顺序反了就是 install.bat 被清零那个事故。
    try:
        data = text.encode(enc)
    except UnicodeEncodeError as e:
        print("[败] 改完的内容用 %s 编不出来：%s" % (enc, e))
        print("     （最常见：中文注释里用了 -> 以外的箭头或 emoji，CP936 没有这些字）")
        return 1

    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)

    # ---- 复核：重读一遍，确认编码/行尾/新内容都对 ----
    with open(path, "rb") as f:
        back_raw = f.read()
    back_enc, back_bom = sniff(back_raw)
    back = back_raw.decode(back_enc or "utf-8", "replace")

    problems = []
    if back_raw != data:
        problems.append("重读回来的字节和写下去的不一致")
    if had_bom and not back_bom:
        problems.append("BOM 丢了")
    if detect_eol(back) != eol:
        problems.append("行尾从 %s 变成了 %s" % (eol, detect_eol(back)))
    for edit in spec.get("edits", []):
        if edit["new"] not in back:
            problems.append("新文本没落盘：%r" % edit["new"][:60])
        if edit["old"] in back and edit["old"] not in edit["new"]:
            problems.append("旧文本还在：%r" % edit["old"][:60])

    if problems:
        print("[败] 写回复核没过：")
        for p in problems:
            print("   - " + p)
        return 1

    print("OK  已写回并复核通过（%d 字节）" % len(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
