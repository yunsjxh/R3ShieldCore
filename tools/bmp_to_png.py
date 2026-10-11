#!/usr/bin/env python3
"""bmp_to_png.py -- 零依赖（只用标准库 zlib）的 BMP -> PNG 转换。

为什么不用 PIL：本仓库**不保证**有 PIL（实测没有），而截图核对是构建/验证链的
一环，不能因为缺一个第三方包就跑不起来。zlib 是标准库，够用。

只处理本仓库探针产出的**那一种** BMP：BITMAPINFOHEADER(40)、32bpp、BI_RGB、
**top-down**（biHeight < 0，即行序从上到下）。别的形态**直接报错**，不猜 ——
猜错的表现是"图能看但上下颠倒/颜色错位"，那比报错难查得多。

用法:
    python tools/bmp_to_png.py <in.bmp> <out.png>
"""
import struct
import sys
import zlib


def read_bmp(path):
    data = open(path, "rb").read()
    if len(data) < 54 or data[:2] != b"BM":
        raise SystemExit("不是 BMP 文件: %s" % path)
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    (hdr_size, width, height, planes, bpp, comp,
     _image_size, _xppm, _yppm, _clr_used, _clr_imp) = struct.unpack_from("<IiiHHIIiiII", data, 14)
    if hdr_size != 40:
        raise SystemExit("只支持 BITMAPINFOHEADER(40)，实际 %d" % hdr_size)
    if bpp != 32 or comp != 0:
        raise SystemExit("只支持 32bpp BI_RGB，实际 bpp=%d comp=%d" % (bpp, comp))
    if height >= 0:
        raise SystemExit("只支持 top-down（biHeight<0），实际 %d" % height)
    height = -height
    need = width * height * 4
    pixels = data[pixel_offset:pixel_offset + need]
    if len(pixels) != need:
        raise SystemExit("像素数据不完整：需要 %d 字节，实际 %d" % (need, len(pixels)))
    return width, height, pixels


def write_png(path, width, height, bgra):
    # BGRA -> RGB（丢掉 alpha，交换 R/B）。用步长切片，别写双重循环 ——
    # 1024x740 就是 75 万像素，纯 Python 逐像素会慢到无法接受。
    blue = bgra[0::4]
    green = bgra[1::4]
    red = bgra[2::4]
    rgb = bytearray(width * height * 3)
    rgb[0::3] = red
    rgb[1::3] = green
    rgb[2::3] = blue

    # PNG 每条扫描行前面要加一个 filter 字节（0 = None）。
    raw = bytearray()
    stride = width * 3
    for y in range(height):
        raw.append(0)
        raw += rgb[y * stride:(y + 1) * stride]

    def chunk(tag, payload):
        body = tag + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")
    open(path, "wb").write(png)


def main(argv):
    if len(argv) != 3:
        raise SystemExit("用法: python tools/bmp_to_png.py <in.bmp> <out.png>")
    width, height, pixels = read_bmp(argv[1])
    write_png(argv[2], width, height, pixels)
    print("  %s -> %s (%dx%d)" % (argv[1], argv[2], width, height))


if __name__ == "__main__":
    main(sys.argv)
