#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compare_band.py —— 比较两张 PNG 的**同一块矩形**是否逐像素一致。

为什么需要它（v82 踩到的真缺陷）：
    cfg「高级」页有三个互斥状态（闸门屏 / 解析屏 / 编辑台），切换时走
    `InvalidateRect(hwnd, nullptr, FALSE)` —— `bErase=FALSE` **不发**
    `WM_ERASEBKGND`。而摘要行 / 说明行是**直接画在底色上**的（底下没有面板），
    于是旧状态的字留在原地、新状态的字叠上去 ⇒ 糊成一团。

    这个缺陷**日志判据抓不到**（日志照样报"闸门=1 编辑框=1"、照样全绿），
    而"直接置状态建窗"的截图也抓不到（那种跑法没有中间那次重绘）。
    ⇒ 唯一能抓住它的是**像素**：让界面真的走一遍切换（`...:cycle`），
      再把它和"直接进编辑台"（`...:editor`）的那一屏**逐像素**比 ——
      两屏末态相同 ⇒ 像素必须一致；不一致就是有残留叠字。

用法:
    python tools/compare_band.py A.png B.png <y0> <y1> [x0] [x1]
退出码: 0 = 一致；1 = 不一致（这一带多出/少了内容）；2 = 尺寸不同

★ 判据用**墨迹像素数**，不是"逐像素是否相同"（实测踩过）：
   两次运行即使末态完全相同，**逐像素**也会有 ~0.4% 的差异 —— 因为
   ClearType 是**亚像素**渲染，窗口在屏幕上的位置（x 相位）一变，
   抗锯齿的相位就跟着变。而**墨迹数**（这一带"有多少深色字"）
   对相位不敏感：实测修复后两屏 `4679 vs 4679`（完全相同），
   坏了的时候 `10750 vs 4679`（多出 130% —— 就是那些残留字）。
   ⇒ 用墨迹计数比"逐像素相同"稳得多，而且判别力更强（0% vs 130%）。

★★ v89：判据从"非白像素"改成"**深色墨迹**像素"。
   原因：玻璃背景现在是**真桌面**（每跑一次都不一样，取决于背后开着什么窗口），
   而旧判据 `r<250 or g<250 or b<250` 会把**整个背景**都算成"有内容" ——
   两张图的背景不同 ⇒ 非白计数差 35% ⇒ 明明界面是对的也报红。
   这不是判据变松，而是变准：这条判据要抓的是"残留的旧字"，
   而字是深色的（墨 24,24,24），背景经过抬阴影后**最低也有 140**
   （见 GlassTheme::shadowLift），中间留了很宽的隔离带。
   阈值取 120：低于它的只可能是界面自己画的墨/深色块。
"""
import struct
import sys
import zlib

# 允许的差异比例（%）。取小值但不为 0：GDI 文字抗锯齿在不同帧之间
# 理论上应当完全确定，留一点余量防"某台机器上差一两个像素"的抖动。
TOLERANCE_PCT = 0.20

# 判"墨迹"的亮度上限。背景抬阴影后最低 ≈140，墨 ≈24 ⇒ 120 是安全的隔离带。
INK_LUMA = 120

# ★ 主判据：这一带**墨迹像素数**的相对差上限（%）。
#
#   实测数据（v89，同一台机器、同一个 exe、连跑两次）：
#     · 正常：892 vs 829 ⇒ 7.1%
#       —— 这 7% **不是**内容差异，是 ClearType 的**亚像素相位**：
#          两次运行时窗口落点差 1px，同一个字的抗锯齿覆盖率就不同。
#          试过"膨胀后计数"（对 1px 平移不敏感）⇒ 仍是 7.0%，
#          说明它不是整块平移，而是每个字形的覆盖率本身变了。
#     · 故障（v89 之前，cfg 窗口被永久排除抓屏 ⇒ 截图里根本没有窗口）：63%
#     · 故障（v82 那个真缺陷：残留旧字叠在新字上）：+130%
#
#   ⇒ 阈值取 25%：离噪声（7%）留 3 倍余量，离故障（63%/130%）差得远。
#     取 10% 会在"某台机器落点更偏"时随机假红 —— 那比漏判更糟：
#     闸门一红，人就会去"修"一个根本不存在的缺陷。
INK_TOLERANCE_PCT = 25.0


def decode_png(path):
    """把 PNG 解成 (w, h, bpp, stride, pixels)。只支持 8 位 RGB/RGBA/灰度。"""
    with open(path, "rb") as f:
        d = f.read()
    if d[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("不是 PNG: " + path)
    i = 8
    idat = b""
    w = h = bd = ct = None
    while i < len(d):
        ln = struct.unpack(">I", d[i:i + 4])[0]
        typ = d[i + 4:i + 8]
        data = d[i + 8:i + 8 + ln]
        if typ == b"IHDR":
            w, h, bd, ct = struct.unpack(">IIBB", data[:10])
        elif typ == b"IDAT":
            idat += data
        i += 12 + ln
    if bd != 8:
        raise ValueError("只支持 8 位色深，实际 %s" % bd)
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[ct]
    bpp = channels
    stride = w * bpp
    raw = zlib.decompress(idat)
    out = bytearray()
    prev = bytearray(stride)
    pos = 0
    for _y in range(h):
        f = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        if f == 1:
            for x in range(bpp, stride):
                line[x] = (line[x] + line[x - bpp]) & 0xFF
        elif f == 2:
            for x in range(stride):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif f == 3:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((a + prev[x]) >> 1)) & 0xFF
        elif f == 4:
            for x in range(stride):
                a = line[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                pa = abs(b - c)
                pb = abs(a - c)
                pc = abs(a + b - 2 * c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pr) & 0xFF
        out += line
        prev = line
    return w, h, bpp, stride, bytes(out)


def band_stats(w, h, bpp, stride, px, x0, y0, x1, y1):
    """返回这块区域里"墨迹"（深色字/深色块）的像素数 —— 判断这一带画了多少字。"""
    x1 = min(x1, w)
    y1 = min(y1, h)
    ink = 0
    total = 0
    for y in range(y0, y1):
        base = y * stride
        for x in range(x0, x1):
            o = base + x * bpp
            r, g, b = px[o], px[o + 1], px[o + 2]
            # 亮度用整数近似（0.299/0.587/0.114 × 256），和着色器/CPU 路径同义。
            if (77 * r + 150 * g + 29 * b) >> 8 < INK_LUMA:
                ink += 1
            total += 1
    return ink, total


def band_diff(w, h, bpp_a, sa, pa, bpp_b, sb, pb, x0, y0, x1, y1):
    x1 = min(x1, w)
    y1 = min(y1, h)
    diff = 0
    total = 0
    for y in range(y0, y1):
        ba = y * sa
        bb = y * sb
        for x in range(x0, x1):
            oa = ba + x * bpp_a
            ob = bb + x * bpp_b
            total += 1
            if (abs(pa[oa] - pb[ob]) > 8
                    or abs(pa[oa + 1] - pb[ob + 1]) > 8
                    or abs(pa[oa + 2] - pb[ob + 2]) > 8):
                diff += 1
    return diff, total


def main(argv):
    if len(argv) < 5:
        print(__doc__)
        return 2
    path_a, path_b = argv[1], argv[2]
    y0, y1 = int(argv[3]), int(argv[4])
    x0 = int(argv[5]) if len(argv) > 5 else 0
    x1 = int(argv[6]) if len(argv) > 6 else 10 ** 9

    wa, ha, bpp_a, sa, pa = decode_png(path_a)
    wb, hb, bpp_b, sb, pb = decode_png(path_b)
    if (wa, ha) != (wb, hb):
        print("SIZE-DIFF %dx%d vs %dx%d —— 两张图尺寸不同，没法比" % (wa, ha, wb, hb))
        return 2

    diff, total = band_diff(wa, ha, bpp_a, sa, pa, bpp_b, sb, pb, x0, y0, x1, y1)
    ratio = diff * 100.0 / total if total else 0.0
    na, _ = band_stats(wa, ha, bpp_a, sa, pa, x0, y0, x1, y1)
    nb, _ = band_stats(wb, hb, bpp_b, sb, pb, x0, y0, x1, y1)
    ink = abs(na - nb) * 100.0 / max(na, nb) if max(na, nb) else 0.0
    print("band y[%d,%d) x[%d,%d)  像素=%d  逐像素差异=%d (%.3f%%)  墨迹: A=%d B=%d"
          % (y0, y1, x0, min(x1, wa), total, diff, ratio, na, nb))
    print("墨迹计数相对差 = %.2f%%（阈值 %.2f%%）" % (ink, INK_TOLERANCE_PCT))
    if ink <= INK_TOLERANCE_PCT:
        print("一致：这一带的墨迹量对得上（没有残留叠字）")
        return 0
    print("不一致：这一带的墨迹量对不上 —— 有残留 / 叠字")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
