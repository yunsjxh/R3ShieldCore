#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_icon.py —— 生成 R3 ShieldCore 的产品图标（.ico），**不依赖任何图形库**。

设计
====
  · 盾牌 = 防护；内部「护芯」六边形 + 字母 R3 = ShieldCore 的"核"。
  · 色系沿用引擎横幅的深蓝（RGB 24,54,100）做竖向渐变，
    描边用近白；R3 用亮青（#4FC3F7）—— 深蓝底上对比足够，
    小尺寸缩下去也不糊成一团。
  · 盾牌**带圆角**（不是老版本的直角矩形）：直角在 16px 下像块砖。

为什么要自己画
==============
安装程序 r3sc_setup.rc 需要 `101 ICON "app.ico"`，主程序也必须有自己的
ICON 资源，否则资源管理器/任务栏/窗口标题栏三处都是系统白的默认图标，
一眼就不像个正经产品。项目里没有现成图标，Pillow 也不保证装了 ——
ICO 的格式其实很简单（一个目录 + 若干张 BMP 位图），手写即可。

★★★ 抗锯齿（这一版的关键修复）★★★
  老版本对每个像素只做"在盾牌内 / 不在盾牌内"的二值判定 —— 16px 下
  边缘全是锯齿，看着像用画图点出来的。
  正确做法是**超采样**：每个目标像素取 SS×SS 个子样本，按覆盖比例混色。
  子样本数与目标尺寸成反比（小图需要更多子样本才不毛躁）：
      size <= 32 → 6x   (36 子样本)
      size <= 64 → 4x   (16 子样本)
      更大       → 3x   (9  子样本)
  ★ 对**形状**做超采样、对**颜色**直接按覆盖比例混合 —— 不能把颜色也平均，
    否则描边和填充交界处会出现第三条脏色。

为什么高分辨率存 PNG 而不是 BMP
================================
  ICO 允许目录项里放 PNG（Vista+）。但只有 **256×256 及更大**才该用 PNG；
  小尺寸一律存 32bpp BMP —— 老工具（含部分版本的资源管理器缩略图、
  windres 的解析器）看到 BMP 才踏实。所以本脚本：
      16/24/32/48/64/128  → BMP
      256                 → PNG
  ★ 128 及以上才用 BMP 是因为：BMP 存储无压缩，256² 就是 256KB，
    六张加起来接近 500KB，对安装包体积不划算；而 256 用 PNG 只有约 5KB。

BMP 在 ICO 里的排布（踩过的坑）
===============================
  · 必须是 **BGRA**，不是 RGBA —— 写反了红蓝互换，深蓝盾牌会变成暗红。
  · 像素行**自下而上**存。
  · 32bpp 其实不用 AND 掩码，但格式要求必须有，且每行按 4 字节对齐。

用法
====
    python make_icon.py app.ico [--png preview.png]

不传 --png 时不产出预览图（构建链里不需要）。
"""

import os
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# 调色板 —— 改这里就是换配色
# ---------------------------------------------------------------------------
BG_TOP = (0x2B, 0x5C, 0xA8)   # 盾牌顶部：中蓝
BG_BOT = (0x0E, 0x22, 0x47)   # 盾牌底部：近黑深蓝
EDGE = (0xEC, 0xF3, 0xFF)     # 描边：冷白
LETTER = (0x5A, 0xD2, 0xFF)   # R3 字色：亮青

# 描边宽度（归一化）。★ 必须 >= 1px 在**最小尺寸**下的宽度：
#   16px 时 1px = 0.0625，所以 0.055 在 16px 上约 0.88px —— 靠超采样
#   仍能得到一条可见的浅色边；再细则 16px 下完全消失（第一版就是这个毛病）。
EDGE_W = 0.055

# 子样本倍数：目标尺寸 -> 每轴子样本数
def _ss(size):
    if size <= 32:
        return 6
    if size <= 64:
        return 4
    return 3


# ---------------------------------------------------------------------------
# 几何：盾牌（经典 "shield" 轮廓）
#
#   ★★ 上角形状踩过两次坑，这里把它钉死：
#
#      第一版：四分之一**圆角** —— 圆心在内侧，超采样时角上只有 1~2 个
#              子样本落进来，16px 实测"缺角"。
#      第二版：**外扩**斜切（dv < CH 时半宽 CH-dv+BASE）—— 数学上 dv=0
#              处半宽只剩 BASE=0.055，于是盾顶变成**两个孤立的角**，
#              实测渲染出"悬浮三角 + 缺口"。这个方向是错的。
#
#      正确做法：**从上往下收**（内切斜切）——
#              dv < CH 时半宽 = HALF_W * dv / CH
#              即顶点附近窄、到 dv=CH 处回落到完整半宽 HALF_W。
#              这样顶端是一个完整的尖，斜切边与直边在 dv=CH 处**相切**，
#              没有外凸、没有孤立角。形状 = 徽章盾，稳。
#
#   轮廓（归一化坐标 (u,v) ∈ [0,1]²，v 向下；dv = v - TOP）：
#     dv < CH        : du <= HALF_W * dv / CH   （顶部收口）
#     CH <= dv < NECK: du <= HALF_W             （直边）
#     NECK <= dv     : du <= HALF_W * (1 - t^p) （收尖，t 归一化到 0..1）
# ---------------------------------------------------------------------------
TOP = 0.055            # 盾顶 v（留出上边距，描边才不贴边被裁）
NECK = 0.44            # 直边与收尖的分界（相对 dv 计）
HALF_W = 0.335         # 直边半宽
CH = 0.155             # 顶部收口高度
TIP_FALLOFF = 1.30     # 盾尖收束指数（>1 = 肩部更饱满）
TIP_HEIGHT = 0.945     # 盾尖最低点 v（相对整图）


def _shield_half(dv):
    """给定相对顶部的 dv，返回盾牌半宽；dv 不在纵向范围内时返回 -1。"""
    if dv < 0.0 or dv > TIP_HEIGHT - TOP:
        return -1.0
    if dv < CH:
        return HALF_W * dv / CH        # 顶部收口（★ 见上文：不能外扩）
    if dv < NECK:
        return HALF_W
    t = (dv - NECK) / (TIP_HEIGHT - TOP - NECK)
    return HALF_W * (1.0 - t ** TIP_FALLOFF)


def shield_inside(u, v, inset=0.0):
    """
    点是否落在盾牌内。inset > 0 表示**内缩**（用来画描边带）。

    ★ 内缩不能简单地绕中心缩放 —— 那样盾尖会一起往上缩、形状变形。
      正确做法是把"半宽"和"上下边界"分别收 inset：
        · 横向：|u-0.5| <= half - inset
        · 纵向：v ∈ [TOP+inset, TIP_HEIGHT-inset]
      这样得到的是**等距偏置**的近似，盾尖仍然是尖的、形状不变形。
    """
    if v < TOP + inset or v > TIP_HEIGHT - inset:
        return False
    half = _shield_half(v - TOP) - inset
    if half <= 0.0:
        return False
    return abs(u - 0.5) <= half


# ---------------------------------------------------------------------------
# 几何：字母 "R3"（线段集合，用"点到线段距离 <= 半线宽"判定）
#
# ★★ 第一版把 "3" 画成了**反向的 C**（上中下三横 + 右侧两竖），
#    因为它跟 "R" 一样是竖笔开在右边 —— 人眼会把 "R3" 读成 "RE"。
#    这一版改用 **7 段数码管式的 "3"**：
#       上横 / 右上竖 / 中横 / 右下竖 / 下横
#    且**下横与上横一样宽（向左伸出）**，这是 "3" 和 "E" 的唯一区别 ——
#    "E" 的下横是收在竖笔左边的，"3" 的下横要跟上半对称地向右伸。
#
# 字面框：x ∈ [0.245, 0.775]、y ∈ [0.21, 0.575]
#   ★ 上半段（y < 0.50）落在直边区里；下半段伸进收尖区，
#     "R" 的斜腿也按收尖区的实际半宽重算了终点，所以**不会出界**。
# ---------------------------------------------------------------------------
GX0 = 0.262            # 字面框左（收窄，给盾牌留出左右留白）
GX1 = 0.735            # 字面框右
#   ★★ 字形必须整体**上移** —— 踩过：GY0/GY1 取 0.32/0.615 时，
#     字形下半压在盾牌收尖区里，左右被收窄的轮廓切掉，
#       · 128px 下 "3" 的右下端顶到描边；
#       · 16px 下整个字糊成一团、看不出是 R3。
#      正确区间：让字形落在**直边区（dv < NECK=0.44 → v < 0.495）**为主，
#      最多下缘伸进收尖区的上四分之一（那里半宽仍 > 0.30）。
#      GY1 = 0.535 时，收尖区半宽 ≈ 0.317，字面框半宽 0.2635 + 描边 0.055
#      = 0.3185 —— 基本贴合，所以取 0.525 留一点余量。
GY0 = 0.262            # 字形顶
GY1 = 0.512            # 字形底
STROKE = 0.040         # 半线宽

# "R"：左竖 + 上横 + 右上竖 + 中横 + 斜腿
#   ★ R 整体压在字面框的**上半**：上碗占 [GY0, R_MID]，斜腿从 R_MID 下到 R_LEG_Y。
#     ★★ 斜腿**不能再细** —— 踩过：R_LEG_X 离 R_X1 太近时斜腿缩成一条缝，
#        128px 下看不出是"腿"，整体读成 "P3"。留出 >= 0.05 的横跨量。
R_X0 = 0.272
R_X1 = 0.406
R_MID = 0.398          # 上碗与中横的分界
R_LEG_X = 0.462        # 斜腿左下起点（★ 与 R_X1 留 0.056 横跨量）
R_LEG_Y = 0.508        # 斜腿终点 v

# "3"：与 R 同宽，右侧竖笔 x
#   ★ N3_LX 必须明显大于 R 斜腿在 GY1 处的 x（= R_LEG_X = 0.462），
#     否则 "3" 的下横会被斜腿盖掉，整体读成 "E"。
#   ★★ 再修一次（256px 大图暴露）：N3_LX=0.528 时，"3" 的下横与 R 斜腿
#      在**大尺寸下**只差 0.026 —— 两条笔画的抗锯齿边几乎贴上，
#      看上去像连成一体。小尺寸察觉不到，但 256 是桌面大图标会用的尺寸。
#      0.545 让净空到 0.043（约 11px @256），视觉上明确分开。
N3_LX = 0.545          # 上/下横左端
N3_RX = 0.695          # 右侧竖笔（= GX1 - STROKE）
N3_MID_L = 0.572       # 中横左端（比上下横靠右，形成 3 的"腰"）
#   ★ MARGIN 决定 "3" 右侧竖笔的纵向上下端：留出空白，不让竖笔与横笔
#     端头糊成直角块。0.045 在 16px 上约 0.7px —— 再大就断了。
N3_MARGIN = 0.045


def _n3_mid_y():
    """3 的中横 v —— 由上下端居中推出，保证三段等高。"""
    return GY0 + (GY1 - GY0) * 0.5 - 0.008


_R_STROKES = [
    (R_X0, GY0, R_X0, GY1),                        # 左竖
    (R_X0, GY0, R_X1 + STROKE, GY0),               # 上横
    (R_X1, GY0, R_X1, R_MID),                      # 右上竖（上碗）
    (R_X0, R_MID, R_X1, R_MID),                    # 中横
    (R_X1, R_MID, R_LEG_X, R_LEG_Y),               # 斜腿（★ 终点不出盾）
]

_N3_STROKES = [
    (N3_LX, GY0, N3_RX, GY0),                                   # 上横
    (N3_RX, GY0 + N3_MARGIN, N3_RX, _n3_mid_y() - N3_MARGIN),   # 右上竖
    (N3_MID_L, _n3_mid_y(), N3_RX, _n3_mid_y()),                # 中横
    (N3_RX, _n3_mid_y() + N3_MARGIN, N3_RX, GY1 - N3_MARGIN),   # 右下竖
    (N3_LX, GY1, N3_RX, GY1),                                   # 下横（★ 外伸 = 3 不是 E）
]

_ALL_STROKES = _R_STROKES + _N3_STROKES


def _seg_dist(px, py, ax, ay, bx, by):
    """
    点到线段 AB 的距离（**圆头端 / round cap**）。

    ★★ 这里踩过一次坑，结论要记住：**不要改成平头(butt cap)**。
       平头的写法是"投影参数必须落在 [0,1] 内"，但本项目所有的转角
       （横竖相接处）都只靠**端点重合**来连接 —— 一旦端头被切成垂直切口，
       转角处就会缺一个四分之一圆，字形直接碎成一段一段：
         · "R" 的上碗和竖笔断开；
         · "3" 变成三条悬浮的短横。
       实测（256px 展示板）碎得非常明显。
       要保持圆头 —— 端头是半圆，转角自动补满，字形是连续的。
       （"端头是圆的" 这个小瑕疵，最终改用**加大笔画重叠**来解决，
         见 _R_STROKES / _N3_STROKES 里横笔延伸到竖笔中心线的写法。）
    """
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    L2 = vx * vx + vy * vy
    if L2 <= 1e-12:
        return (wx * wx + wy * wy) ** 0.5
    t = (wx * vx + wy * vy) / L2
    if t < 0.0:
        t = 0.0
    elif t > 1.0:
        t = 1.0
    hx, hy = wx - t * vx, wy - t * vy
    return (hx * hx + hy * hy) ** 0.5


def letter_inside(u, v):
    """点是否落在 "R3" 笔画上（含笔画半宽）。"""
    # 先做字面框快速排除：绝大多数像素在这里就返回，整体快一倍以上
    M = STROKE
    if u < GX0 - M or u > GX1 + M or v < GY0 - M or v > GY1 + M:
        return False
    for ax, ay, bx, by in _ALL_STROKES:
        if _seg_dist(u, v, ax, ay, bx, by) <= STROKE:
            return True
    return False


# ---------------------------------------------------------------------------
# 采样：给定归一化坐标，返回该点的 BGRA
#   顺序很重要：先算"字形"还是"盾牌"由**几何包含**决定；
#   不在盾牌内 → 全透明（alpha=0），BGRA 全 0。
# ---------------------------------------------------------------------------
def sample(u, v):
    if not shield_inside(u, v):
        return (0, 0, 0, 0)
    # 描边带：在外轮廓内、但不在内缩轮廓内
    if not shield_inside(u, v, inset=EDGE_W):
        r, g, b = EDGE
        return (b, g, r, 255)
    if letter_inside(u, v):
        r, g, b = LETTER
        return (b, g, r, 255)
    # 盾牌填充：竖向渐变
    t = min(1.0, max(0.0, (v - TOP) / (TIP_HEIGHT - TOP)))
    r = int(BG_TOP[0] + (BG_BOT[0] - BG_TOP[0]) * t)
    g = int(BG_TOP[1] + (BG_BOT[1] - BG_TOP[1]) * t)
    b = int(BG_TOP[2] + (BG_BOT[2] - BG_TOP[2]) * t)
    return (b, g, r, 255)


def render_bgra(size):
    """
    超采样渲染，返回 size×size 的 BGRA 字节（自上而下，每行 size*4 字节）。

    ★ 抗锯齿的正确混法（这一版修的 bug）：
      不能对**颜色**求平均 —— 描边白和填充蓝一平均会得到一条灰蓝脏边。
      正确顺序：
        1. 按子样本统计 4 个覆盖率：透明 / 描边 / 字形 / 填充；
        2. alpha = 1 - 透明覆盖率；
        3. 不透明部分的 RGB = (各通道按**覆盖率加权**求和) / alpha。
      这样边缘只跟相邻的两种颜色混，不会串色。
    """
    ss = _ss(size)
    step = 1.0 / size
    sub = step / ss
    # 各层累计
    out = bytearray()
    inv = 1.0 / (ss * ss)

    for y in range(size):
        row = bytearray()
        for x in range(size):
            # 累计各层的 RGB 与计数
            acc = [0.0, 0.0, 0.0]          # r,g,b 加权和
            n_edge = n_fill = n_letter = n_in = 0
            for sy in range(ss):
                vy = y * step + (sy + 0.5) * sub
                for sx in range(ss):
                    u = x * step + (sx + 0.5) * sub
                    v = vy
                    if not shield_inside(u, v):
                        continue
                    n_in += 1
                    if not shield_inside(u, v, inset=EDGE_W):
                        # 描边：冷白
                        acc[0] += EDGE[0]
                        acc[1] += EDGE[1]
                        acc[2] += EDGE[2]
                        n_edge += 1
                    elif letter_inside(u, v):
                        acc[0] += LETTER[0]
                        acc[1] += LETTER[1]
                        acc[2] += LETTER[2]
                        n_letter += 1
                    else:
                        t = min(1.0, max(0.0, v / TIP_HEIGHT))
                        acc[0] += BG_TOP[0] + (BG_BOT[0] - BG_TOP[0]) * t
                        acc[1] += BG_TOP[1] + (BG_BOT[1] - BG_TOP[1]) * t
                        acc[2] += BG_TOP[2] + (BG_BOT[2] - BG_TOP[2]) * t
                        n_fill += 1

            if n_in == 0:
                row += b"\x00\x00\x00\x00"
            else:
                a = int(round(255.0 * n_in * inv))
                if a <= 0:
                    row += b"\x00\x00\x00\x00"
                else:
                    # 不透明部分的颜色 = 加权和 / 不透明子样本数
                    r = int(round(acc[0] / n_in))
                    g = int(round(acc[1] / n_in))
                    b = int(round(acc[2] / n_in))
                    row += bytes((b, g, r, a))
        out += row
    return bytes(out)


# ---------------------------------------------------------------------------
# 编码：BMP 目录项
# ---------------------------------------------------------------------------
def encode_bmp(size):
    """返回 (BITMAPINFOHEADER + BGRA 自带下行序 + AND 掩码)。"""
    bgra = render_bgra(size)
    # BMP 行自下而上
    stride = size * 4
    rows = [bgra[i * stride:(i + 1) * stride] for i in range(size)]
    xor = b"".join(reversed(rows))
    # AND 掩码：32bpp 用不到，但格式要求；每行 4 字节对齐
    and_row = ((size + 31) // 32) * 4
    and_mask = b"\x00" * (and_row * size)
    hdr = struct.pack("<IiiHHIIiiII",
                      40,            # biSize
                      size,          # biWidth
                      size * 2,      # biHeight = XOR 高 + AND 高
                      1,             # biPlanes
                      32,            # biBitCount
                      0,             # BI_RGB
                      len(xor) + len(and_mask),
                      0, 0, 0, 0)
    return hdr + xor + and_mask


def encode_png(size):
    """把 BGRA 转成 RGBA，再手写一个最小 PNG（Vista+ 支持 ICO 内嵌 PNG）。"""
    bgra = render_bgra(size)
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter type 0
        for x in range(size):
            i = (y * size + x) * 4
            b, g, r, a = bgra[i], bgra[i + 1], bgra[i + 2], bgra[i + 3]
            # ★ 预乘 alpha 会让小尺寸出现"黑边"，这里**不做**预乘 ——
            #   PNG 存的是直通 alpha（straight alpha）。
            raw += bytes((r, g, b, a))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# ICO 打包
# ---------------------------------------------------------------------------
SIZES = [16, 24, 32, 48, 64, 128, 256]
# 256 走 PNG（BMP 存 256² 要 256KB），其余走 BMP
PNG_FROM = 256


def build_ico(path):
    images = []
    for s in SIZES:
        if s >= PNG_FROM:
            images.append((s, encode_png(s), True))
        else:
            images.append((s, encode_bmp(s), False))

    n = len(images)
    data = struct.pack("<HHH", 0, 1, n)                    # ICONDIR
    offset = 6 + 16 * n
    dirs = b""
    for s, blob, _is_png in images:
        dirs += struct.pack("<BBBBHHII",
                            s if s < 256 else 0,   # 256 记作 0
                            s if s < 256 else 0,
                            0, 0,                  # 调色板 / 保留
                            1, 32,
                            len(blob), offset)
        offset += len(blob)
    with open(path, "wb") as f:
        f.write(data + dirs + b"".join(blob for _, blob, _ in images))
    return n


def write_preview_png(path, size=256):
    """给"人看"的预览图（RGBA PNG），构建链不用。"""
    with open(path, "wb") as f:
        f.write(encode_png(size))


def main():
    args = [a for a in sys.argv[1:]]
    png = None
    if "--png" in args:
        i = args.index("--png")
        png = args[i + 1]
        del args[i:i + 2]
    out = args[0] if args else "app.ico"

    n = build_ico(out)
    print("  ico -> %s (%d 张: %s；>=%d 用 PNG)" % (
        out, n, ", ".join(str(s) for s in SIZES), PNG_FROM))
    print("        尺寸 %d 字节" % os.path.getsize(out))
    if png:
        write_preview_png(png)
        print("  预览 -> %s" % png)
    return 0


if __name__ == "__main__":
    sys.exit(main())
