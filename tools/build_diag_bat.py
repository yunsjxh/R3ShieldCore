#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_diag_bat.py -- 把 tools/diag_autostart_new.txt（UTF-8 源）编译成
                     tools/diag_autostart.bat（cmd 能吃的 GBK+CRLF）。

为什么要有这一步（不是一个 cp）
================================
.bat 必须满足 **GBK 可编码 + CRLF + 无 BOM**（铁律 40/133）。
源文件用 UTF-8 写（好维护、好 diff、IDE 不乱码），产出的 .bat 用 GBK。
直接改 .bat 很容易把某个字符搞成 GBK 编不出来的（比如 `⇒` U+21D2），
那时 `encode("gbk")` 会**抛异常**，或者更糟——被某处静默 errors="replace"
写成一堆 `?`，脚本内容被悄悄改坏。

所以这个编译步骤**先校验再落盘**，并且**落盘前做一次反向读回断言**。

用法
====
    python tools/build_diag_bat.py            # 编译 + 校验
    python tools/build_diag_bat.py --check    # 只校验现有 .bat 与源是否同步
"""

import io
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "tools", "diag_autostart_new.txt")
DST = os.path.join(REPO, "tools", "diag_autostart.bat")


def build_bytes(text):
    """把 UTF-8 文本转成 GBK + CRLF 字节；有编不出的字符就抛。"""
    bad = []
    for i, ch in enumerate(text):
        if ord(ch) < 128:
            continue
        try:
            ch.encode("gbk")
        except UnicodeEncodeError:
            bad.append((text.count("\n", 0, i) + 1, ch, "U+%04X" % ord(ch)))
    if bad:
        msg = ["有 %d 个字符编不进 GBK（先换成 ASCII 或 →）：" % len(bad)]
        for ln, ch, cp in bad[:10]:
            msg.append("    第 %d 行: %r  %s" % (ln, ch, cp))
        raise ValueError("\n".join(msg))
    norm = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    return norm.encode("gbk")


def main():
    check = "--check" in sys.argv

    if not os.path.isfile(SRC):
        print("[FAIL] 源文件不存在: %s" % SRC)
        return 1

    text = io.open(SRC, "rb").read().decode("utf-8")

    try:
        data = build_bytes(text)
    except ValueError as e:
        print("[FAIL] %s" % e)
        return 1

    # 反向读回：确保落盘的字节**逐字**能还原成源文本（防"编进去了但内容变了"）
    back = data.decode("gbk").replace("\r\n", "\n")
    expect = text.replace("\r\n", "\n")
    if back != expect:
        # 找出第一个不同的位置，便于定位
        for i, (a, b) in enumerate(zip(back, expect)):
            if a != b:
                ln = expect.count("\n", 0, i) + 1
                print("[FAIL] 反向读回不一致，第 %d 行：%r != %r" % (ln, a, b))
                break
        else:
            print("[FAIL] 反向读回长度不一致：%d vs %d" % (len(back), len(expect)))
        return 1

    if check:
        if not os.path.isfile(DST):
            print("[FAIL] 产物不存在: %s" % DST)
            return 1
        cur = io.open(DST, "rb").read()
        if cur == data:
            print("[ OK ] %s 与源 %s 同步（%d 字节）"
                  % (os.path.relpath(DST, REPO), os.path.relpath(SRC, REPO), len(data)))
            return 0
        print("[FAIL] %s 与源**不同步** —— 请跑 python tools/build_diag_bat.py 重新编译"
              % os.path.relpath(DST, REPO))
        return 1

    io.open(DST, "wb").write(data)
    print("[ OK ] 已编译 %s -> %s（%d 字节，GBK+CRLF+无 BOM，反向读回一致）"
          % (os.path.relpath(SRC, REPO), os.path.relpath(DST, REPO), len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
