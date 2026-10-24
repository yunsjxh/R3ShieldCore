#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把几张 PNG 纵向拼成一张对比图（纯标准库，不依赖 PIL）。

用法: python make_compare.py 输出.png 输入1.png 输入2.png [...]
     每张先按宽度缩放到统一宽度（面积平均，比最近邻干净），再上下拼接，
     中间留 12px 深灰缝，方便一眼看出"这是两张图"。
"""
import struct
import sys
import zlib

sys.path.insert(0, "tools")
import compare_band as cb   # 复用它的 PNG 解码


def resize(w, h, bpp, s, px, W):
    H = max(1, int(round(h * W / float(w))))
    out = bytearray(W * H * 3)
    for y in range(H):
        y0 = y * h // H
        y1 = max(y0 + 1, (y + 1) * h // H)
        for x in range(W):
            x0 = x * w // W
            x1 = max(x0 + 1, (x + 1) * w // W)
            r = g = b = n = 0
            for yy in range(y0, y1):
                base = yy * s
                for xx in range(x0, x1):
                    o = base + xx * bpp
                    r += px[o]
                    g += px[o + 1]
                    b += px[o + 2]
                    n += 1
            d = (y * W + x) * 3
            out[d] = r // n
            out[d + 1] = g // n
            out[d + 2] = b // n
    return W, H, out


def write_png(path, W, H, rgb):
    raw = bytearray()
    for y in range(H):
        raw.append(0)
        raw += rgb[y * W * 3:(y + 1) * W * 3]

    def chunk(tag, payload):
        body = tag + payload
        return (struct.pack(">I", len(payload)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def main(argv):
    dst = argv[1]
    srcs = argv[2:]
    W = 1024
    parts = []
    for p in srcs:
        w, h, bpp, s, px = cb.decode_png(p)
        parts.append(resize(w, h, bpp, s, px, W))
    gap = 12
    H = sum(p[1] for p in parts) + gap * (len(parts) - 1)
    canvas = bytearray(W * H * 3)
    y = 0
    for i, (_, ph, rgb) in enumerate(parts):
        if i:
            for yy in range(y, y + gap):
                d = yy * W * 3
                for x in range(W):
                    canvas[d + x * 3] = 70
                    canvas[d + x * 3 + 1] = 70
                    canvas[d + x * 3 + 2] = 78
            y += gap
        canvas[y * W * 3:(y + ph) * W * 3] = rgb
        y += ph
    write_png(dst, W, H, canvas)
    print("%s -> %dx%d（%d 张）" % (dst, W, H, len(parts)))


if __name__ == "__main__":
    main(sys.argv)
