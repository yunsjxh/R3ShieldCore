#!/usr/bin/env python3
"""check_cfg_pills.py -- 判「cfg 的自绘按钮真的画出了药丸」+「字段真的看得见且是玻璃」。

为什么需要它（v114 的真缺陷）：
    `UiCtl::Pill` / `SwitchV` 只往 `g_glass.cur[]` **登记**一块玻璃，真正合成
    在 `g_glass.Begin()` 里。而 `Begin()` 第一件事就是 `BeginFrame()` →
    `curCount = 0`。所以**子控件**在 WM_DRAWITEM 里登记的玻璃片活不过一帧，
    永远轮不到 `CommitPanels()` —— 一个都没合成过。

    症状：四个动作按钮内部是**纯色 250**（WM_CTLCOLORBTN 的白刷子），
    圆角、渐变、投影全没有；而「保存」是主按钮（白字）⇒ **白底白字，看不见**。

    这类缺陷"看起来像按钮还在"（框和字都在，只是没有底），
    光看截图很容易放过 —— 所以判据必须是**像素级**的：
      · 主按钮那块必须是**蓝的**（药丸画出来了）
      · 主按钮那块必须有**近白像素**（白字画在蓝底上，而不是白底白字）
      · 次按钮那块必须有**多个颜色**（渐变；纯色 = 只有白刷子）
      · 自绘滚动条附近不能有**纯黑**像素（RoundRect 没换笔 ⇒ 1px 黑描边）

为什么还要判字段（v115→v116 的真缺陷）：
    "下拉框不透明"修过头，变成了"下拉框看不见"：
      · v115 之前：字段填实色 (244,245,247) ⇒ 用户说**不透明**；
      · v115：改成贴**原始玻璃** ⇒ 和面板逐像素相同，**控件消失**
        （实测字段左边缘梯度 2~5，而按钮是 60~120）；
      · v116：贴**提亮过**的玻璃（kFieldVeil）⇒ 有底、有边、仍是玻璃。
    三种状态必须能被机器分开，所以字段判三条：
      · 内部必须**比面板亮一档**（Δ>=12）—— 否掉"消失"
      · 左边缘必须有**梯度**（>=10）      —— 否掉"没有边界"
      · 内部必须有**多个颜色**（>4）       —— 否掉"实色平板"（不透明）

用法:
    python tools/check_cfg_pills.py <shot.bmp>

⚠️ 截图必须**冻住背景**再抓：
    `R3SHIELDCORE_PREVIEW_FREEZEBG=1 tools/gui_preview_probe.exe ... `
    `tools/test_gui_preview.sh` 已经 export 了，**手动跑探针时最容易漏**。
    漏了会怎样（实测，可复现）：探针去抓**实时桌面**当背景，如果桌面上正好
    是一张白窗口（日志 `[glass] 背景抓取 成功 ... 均值=249`），玻璃只能变成
    白卡片 ⇒ 面板 255、画布 235 ⇒ **8 条判据里 7 条红**。
    那是**假红**：同一份 exe 加 FREEZEBG 重抓就是全绿（面板 202 / 画布 242）。
    ⇒ 判据全红时**先看背景均值**，别急着改代码（铁律 274 的第三次验证）。

判据坐标绑定**标准预览几何**（窗口 1024x740、客户区 1024x740 —— 自绘无边框，
所以客户区坐标 == 截图坐标）。布局常量变了这里要跟着改，见 r3shieldcore_cfg.cpp
的 `LayoutAll()`：cx = 客户区宽 - 20，四个按钮从右往左排
（打开所在目录 96 / 立即同步 120 / 保存 76 / 重新加载 96，间距 8，行高 30）。
字段坐标来自实测枚举（`GetWindowRect` 减窗口原点 52）：配置页「运行模式」
combo = 客户区 (506,212,340,28)，外扩 5px 的外壳框线在 x=501。

⚠️ 只对**玻璃模式**成立。经典模式保留系统标题栏，客户区整体下移 32px
   （`R3SHIELDCORE_UI=classic` 时实测按钮行在 y=146，不是 114）——
   拿经典模式的截图喂进来，判据会全红，那是坐标不对，不是界面坏了。
"""
import struct
import sys

# ---- 标准预览几何（1024x740）----------------------------------------------
BTN_Y0, BTN_Y1 = 114, 144          # kRowH=30，ty = cfgToolbar.top = 114
SAVE = (696, BTN_Y0, 772, BTN_Y1)  # 主按钮「保存」
RELOAD = (592, BTN_Y0, 688, BTN_Y1)  # 次按钮「重新加载」
SB_X0, SB_X1 = 190, 215            # 左侧分组列表右侧那条自绘滚动条
SB_Y0, SB_Y1 = 160, 700

# ---- 字段（配置页「运行模式」下拉框）--------------------------------------
FLD_INNER = (660, 218, 800, 232)   # 字段内部、无字区域（取均值色）
FLD_STRIP = (600, 214, 800, 220)   # 字段顶部条带（数颜色，判"是不是实色平板"）
FLD_EDGE_Y = 226                   # 横扫这一行找左边框
FLD_EDGE_X0, FLD_EDGE_X1 = 492, 516  # 外壳框线在 x=501，两侧各留余量
PANEL_REF = (660, 460, 800, 500)   # 同 x 范围、字段下方的空白面板

# ---- 字段的公共横向范围（用于行投影找字段段）------------------------------
#   三个字段左边界实测都在 x=502，右边界 759~849（有一个字段窄一些）；
#   取 505..845 ⇒ 窄字段那一行的填充占比仍有 0.75，阈值 0.6 足够。
FLD_X0, FLD_X1 = 505, 845
FLD_SCAN_Y0, FLD_SCAN_Y1 = 190, 560  # 表单区纵向扫描范围（第 1 字段顶边起）

# ---- 面板 vs 画布（v117 的真缺陷）----------------------------------------
#   画布取样 = 左右两块面板之间那道 14px 的缝（实测 243）；
#   面板取样 = 表单面板内部的空白处（实测 207）。
#   v116 及之前：面板 244 / 画布 227 ⇒ 只差 17，而且方向是"面板更亮"，
#   在亮背景上和画布同色 ⇒ 整页是一张没有分区的平表格（灰度图 y=160~688 全空）。
CANVAS_REF = (222, 420, 234, 600)
PANEL_BODY = (700, 480, 820, 560)


def load_bmp(path):
    data = open(path, "rb").read()
    if len(data) < 54 or data[:2] != b"BM":
        raise SystemExit("不是 BMP: %s" % path)
    off = struct.unpack_from("<I", data, 10)[0]
    hdr, w, h, _p, bpp, comp = struct.unpack_from("<IiiHHI", data, 14)
    if hdr != 40 or bpp != 32 or comp != 0 or h >= 0:
        raise SystemExit("只支持 40 头 / 32bpp / BI_RGB / top-down: %s" % path)
    h = -h
    return w, h, data[off:off + w * h * 4]


class Shot:
    def __init__(self, path):
        self.w, self.h, self.px = load_bmp(path)

    def rgb(self, x, y):
        i = (y * self.w + x) * 4
        return self.px[i + 2], self.px[i + 1], self.px[i]

    def dmax(self, a, b):
        return max(abs(a[0] - b[0]), abs(a[1] - b[1]), abs(a[2] - b[2]))

    def brighter(self, c, ref, thr=6):
        """c 是否**比参考色亮** thr 级以上（单向，不取绝对值）。

        ★★★ 必须单向：字段填充比面板**亮** +13，而 1px 描边比面板**暗** -16。
           用 `dmax`（绝对差）会把描边也当成"字段填充" ⇒ 每一行的左边界提前
           落到描边那一列 ⇒ 直边和圆角顶边量出来一样宽 ⇒ 圆角被判成 1px
           （实测：v120 明明内缩 7px，绝对差版本读 1）。
        """
        return max(c[0] - ref[0], c[1] - ref[1], c[2] - ref[2]) > thr

    def _row_fill(self, y, x0, x1, ref, thr):
        """第 y 行里"字段填充色"的像素个数。"""
        n = 0
        for x in range(x0, x1):
            if self.brighter(self.rgb(x, y), ref, thr):
                n += 1
        return n

    def field_bands(self, y0, y1, ref, thr=6, minh=10, frac=0.6):
        """沿**行**投影找"字段填充色"的连续段 —— 每一段是一个字段。

        ★ 不用硬编码坐标：布局是算出来的（`LayoutFields`），页面/DPI 一变
          坐标就变；上一轮按枚举来的矩形去量，量到的其实是另一个控件。
        ★★★ 也不用**单条竖线**：竖线会撞上字段里的值文字，文字比面板暗 ⇒
          `brighter` 为假 ⇒ 一个字段被切成两段。实测 x=520 上第 2 个字段
          （y=258..287）被文字切出 y=277 的假段，量出"内缩 2px"的假红。
          行投影按"这一行有多少比例是填充色"判，文字只影响几个像素。
        """
        bands = []
        need = int((FLD_X1 - FLD_X0) * frac)
        y = y0
        while y < y1:
            if self._row_fill(y, FLD_X0, FLD_X1, ref, thr) >= need:
                s = y
                while y < y1 and self._row_fill(y, FLD_X0, FLD_X1, ref, thr) >= need:
                    y += 1
                if y - s >= minh:
                    bands.append((s, y))
            else:
                y += 1
        return bands

    def top_inset(self, band, xa, xb, ref, thr=6):
        """字段**上圆角**的高度 = 顶边若干行里，左边界相对直边内缩的最大值。

        直角 ⇒ 0~1；半径 r 的圆弧 ⇒ ≈ r。
        ★ 取"若干行的最大值"而不是只看第一行：`field_bands` 找到的第一行
          未必是外壳的顶边（可能已经跨过圆角），只看一行会漏判。
        ★ 搜索起点必须 > 标签列右边界（240 宽的标签从 258 起 ⇒ 到 498），
          否则会把标签文字当成字段填充（实测负对照量出 -7）。
        """
        y0, y1 = band
        straight = None
        ym = y0 + min(14, (y1 - y0) // 2)
        for x in range(xa, xb):
            if self.brighter(self.rgb(x, ym), ref, thr):
                straight = x
                break
        if straight is None:
            return None
        peak = 0
        for dy in range(0, min(10, y1 - y0)):
            for x in range(xa, xb):
                if self.brighter(self.rgb(x, y0 + dy), ref, thr):
                    peak = max(peak, x - straight)
                    break
        return peak

    def band_uniq(self, r, y0, y1):
        """按钮**顶部一条带**里的颜色数（带内没有字，只有药丸本身）。

        这是"药丸到底画没画出来"最干净的判据：
          纯白刷子（药丸丢失）⇒ 整条带 1 种颜色；
          玻璃药丸          ⇒ 竖直方向有高光/折射渐变，几十种。
        为什么不用整块的颜色数：字是抗锯齿的，几十种颜色光靠字就能凑出来
        （负对照实测：坏的按钮整块也有 49 种颜色 ⇒ 那条判据会假绿）。
        """
        x0, _, x1, _ = r
        colors = set()
        for y in range(y0, y1):
            for x in range(x0 + 10, x1 - 10):
                colors.add(self.rgb(x, y))
        return len(colors)

    def mean(self, r):
        x0, y0, x1, y1 = r
        sr = sg = sb = 0
        n = 0
        for y in range(y0, y1):
            for x in range(x0, x1):
                cr, cg, cb = self.rgb(x, y)
                sr += cr
                sg += cg
                sb += cb
                n += 1
        return sr / n, sg / n, sb / n

    def uniq(self, r):
        x0, y0, x1, y1 = r
        colors = set()
        for y in range(y0, y1):
            for x in range(x0, x1):
                colors.add(self.rgb(x, y))
        return len(colors)

    def max_edge(self, y, x0, x1):
        """横扫第 y 行，返回相邻像素的最大通道差（= 最强的一条竖边）。

        为什么用梯度而不是"和面板比颜色"：
          面板参考色很难取准（字段上方是深色页签条、下方是分隔带），
          取错一次就会把"直角"误判成"有边"。梯度**不需要参考色**。
        """
        best = 0
        prev = self.rgb(x0, y)
        for x in range(x0 + 1, x1):
            cur = self.rgb(x, y)
            d = max(abs(cur[0] - prev[0]), abs(cur[1] - prev[1]), abs(cur[2] - prev[2]))
            if d > best:
                best = d
            prev = cur
        return best

    def max_edge_near(self, y, a, half=12):
        """在第 y 行、x≈a 附近（±half）找相邻像素的最大通道差 —— 一条竖边。

        ★ 为什么不用 `max_edge(y, x0, x1)` 扫一大段：按钮右边紧挨着下一个按钮，
          扫宽了会把**邻按钮的边**算进来（假绿）。
        """
        best = 0
        for x in range(a - half, a + half):
            cur = self.rgb(x, y)
            nxt = self.rgb(x + 1, y)
            d = max(abs(cur[0] - nxt[0]), abs(cur[1] - nxt[1]), abs(cur[2] - nxt[2]))
            if d > best:
                best = d
        return best

    def stats(self, r):
        x0, y0, x1, y1 = r
        colors = set()
        sum_r = sum_g = sum_b = 0
        n = 0
        white = 0
        for y in range(y0, y1):
            for x in range(x0, x1):
                cr, cg, cb = self.rgb(x, y)
                colors.add((cr, cg, cb))
                sum_r += cr
                sum_g += cg
                sum_b += cb
                n += 1
                if cr > 235 and cg > 235 and cb > 235:
                    white += 1
        return {
            "uniq": len(colors),
            "r": sum_r / n,
            "g": sum_g / n,
            "b": sum_b / n,
            "white_ratio": white / n,
        }


def load_geom(bmp_path):
    """读探针落的 `<bmp>.geom`（每行 `class|text|x|y|w|h|vis`，客户坐标）。

    ★★★ 为什么判据不能再用写死坐标（v123 踩过）：
      原来 `SAVE=(696,114,772,144)` 这类常量是按**当时的按钮宽度**量出来的。
      v123 把按钮宽度改成"按文字实测自适应"之后，按钮整体左移/变宽 ⇒
      写死的矩形落在**两个按钮之间的空隙**上 ⇒ 判据报「主按钮不是蓝玻璃」
      的**假红**，看上去像功能坏了。
      判据该盯的是"这个按钮画对了吗"，不是"按钮还在不在老地方"。
      探针顺手把真实几何写出来，判据按**文字**定位 —— 以后再改文案/DPI 都不会假红。

    返回 None 表示没有 .geom（单跑判据时向后兼容，退回旧常量）。
    """
    path = bmp_path + ".geom"
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return None
    out = []
    for ln in lines:
        p = ln.split("|")
        if len(p) != 7:
            continue
        try:
            x, y, w, h, vis = (int(p[2]), int(p[3]), int(p[4]), int(p[5]), int(p[6]))
        except ValueError:
            continue
        out.append((p[0], p[1], x, y, w, h, vis))
    return out or None


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: check_cfg_pills.py <shot.bmp>")
    shot = Shot(sys.argv[1])
    if shot.w < 1000 or shot.h < 700:
        raise SystemExit("截图尺寸不对（期望 >= 1000x700）: %dx%d" % (shot.w, shot.h))

    # ---- 按 .geom 定位按钮（没有就退回旧常量）----------------------------
    geom = load_geom(sys.argv[1])

    def btn_rect(text, fallback):
        if not geom:
            return fallback
        for cls, txt, x, y, w, h, vis in geom:
            if cls == "Button" and txt == text and vis:
                return (x, y, x + w, y + h)
        return fallback

    save_r = btn_rect("保存", SAVE)
    reload_r = btn_rect("重新加载", RELOAD)
    if geom:
        print("  几何来自 .geom：保存=%s 重新加载=%s" % (save_r, reload_r))

    fails = []

    def check(name, ok, detail):
        print("  [%s] %s —— %s" % (" OK " if ok else "FAIL", name, detail))
        if not ok:
            fails.append(name)

    # ① 主按钮必须是蓝玻璃（药丸真的画出来了）
    sv = shot.stats(save_r)
    check("主按钮是蓝玻璃（药丸画出来了）", sv["b"] - sv["r"] > 60,
        "均值 RGB=(%.0f,%.0f,%.0f) 蓝-红=%.0f（要 >60）" % (sv["r"], sv["g"], sv["b"], sv["b"] - sv["r"]))

    # ② 主按钮上必须有近白像素（白字）—— 这条专治「白底白字」
    #    上限 45% 也是判据的一部分：白底白字时整块 96% 都是近白，
    #    只写下限的话它会**假绿**（负对照实测过）。
    check("主按钮上「保存」两个字看得见", 0.02 < sv["white_ratio"] < 0.45,
        "近白像素占 %.1f%%（要 2%%~45%%；白底白字时是 96%%）" % (sv["white_ratio"] * 100))

    # ③ 次按钮必须是渐变（药丸有折射/高光），不是一块纯色
    band = shot.band_uniq(reload_r, reload_r[1] + 3, reload_r[1] + 9)
    check("次按钮是玻璃药丸（不是纯色平板）", band > 6,
        "顶部条带里 %d 种颜色（要 >6；只有白刷子时是 1 种）" % band)

    # ④ 自绘滚动条不能有黑描边
    black = 0
    for y in range(SB_Y0, SB_Y1):
        for x in range(SB_X0, SB_X1):
            cr, cg, cb = shot.rgb(x, y)
            if cr < 20 and cg < 20 and cb < 20:
                black += 1
    check("自绘滚动条没有黑描边", black == 0,
        "纯黑像素 %d 个（要 0；RoundRect 不换笔就会有一圈 1px 黑边）" % black)

    # ------------------------------------------------------------------
    # ⑤⑥⑦ 字段（下拉框）：有底 / 有边 / 不是实色平板
    #
    #   这三条对应三种真实状态，缺一条就会有盲区：
    #     只有⑤：实色平板也能过（正是用户说的"不透明"）
    #     只有⑥：字段消失也能过（v115 的框线还在，只是对比度 8）
    #     只有⑦：实色平板是单色 ⇒ 挂；但"消失"的字段颜色很多 ⇒ 过
    #   三条一起，才把"消失"和"不透明"两头都堵住。
    # ------------------------------------------------------------------
    fr, fg, fb = shot.mean(FLD_INNER)
    pr, pg, pb = shot.mean(PANEL_REF)
    delta = max(abs(fr - pr), abs(fg - pg), abs(fb - pb))
    check("字段内部比面板亮一档（有底，不是消失）", delta >= 12,
        "字段 RGB=(%.0f,%.0f,%.0f) 面板 RGB=(%.0f,%.0f,%.0f) 最大差=%.0f（要 >=12；"
        "贴原始玻璃时差=0，控件就看不见了）" % (fr, fg, fb, pr, pg, pb, delta))

    edge = shot.max_edge(FLD_EDGE_Y, FLD_EDGE_X0, FLD_EDGE_X1)
    check("字段有边界（1px 圆角描边画出来了）", edge >= 10,
        "左边缘最大梯度=%d（要 >=10；v115 只贴玻璃时是 2~5，按钮是 60~120）" % edge)

    fld_uniq = shot.uniq(FLD_STRIP)
    check("字段是玻璃不是实色平板（内部有渐变）", fld_uniq > 4,
        "字段顶部条带 %d 种颜色（要 >4；填实色时是 1~2 种）" % fld_uniq)

    # ⑧ 面板必须和画布**分得开** —— 这条是 v117 补的。
    #    前面七条全过、用户却说"还是原来的样子"，因为面板和画布同色：
    #    整页没有分区，看着就是一张平表格。判据只盯控件、不盯**版面结构**，
    #    就会漏掉这一类"什么都对、但什么都没变"。
    cr, cg, cb = shot.mean(CANVAS_REF)
    br, bg, bb = shot.mean(PANEL_BODY)
    pd = max(abs(br - cr), abs(bg - cg), abs(bb - cb))
    check("面板和画布分得开（页面有分区，不是平表格）", pd >= 25,
        "画布 RGB=(%.0f,%.0f,%.0f) 面板 RGB=(%.0f,%.0f,%.0f) 差=%.0f（要 >=25；"
        "v116 是 17 且同向偏亮，亮背景上和画布同色）" % (cr, cg, cb, br, bg, bb, pd))

    # ⑨ 每个字段的**上圆角**必须真的画出来（顶边有内缩）—— v120 补的。
    #    负对照：v119 的截图（提示文字高 30、压住下一个字段外壳最上面 10px，
    #    把上边框和两个上圆角整块盖掉 ⇒ 顶边内缩只有 1px）。
    #    ★ 这条必须**逐字段**判：只判第一个字段会假绿 —— 第一个字段上面
    #      没有别的字段的提示，它一直是圆的（实测 7px），坏的只有第 2、3 个。
    pr_, pg_, pb_ = shot.mean(PANEL_REF)
    panel = (int(pr_), int(pg_), int(pb_))
    bands = shot.field_bands(FLD_SCAN_Y0, FLD_SCAN_Y1, panel)
    insets = []
    detail = []
    for b in bands:
        v = shot.top_inset(b, 499, 540, panel)
        if v is not None:
            insets.append(v)
            detail.append("y=%d:%d" % (b[0], v))
    worst = min(insets) if insets else 0
    check("每个字段的上圆角都画出来了（顶边有内缩）", len(insets) >= 2 and worst >= 4,
        "字段 %d 个，逐字段内缩 [%s]，最小 %d px（要 >=4；提示文字压住外壳时是 1）"
        % (len(insets), ", ".join(detail), worst))

    # ⑩ 次按钮必须有**看得见的边界** —— v121 补的。
    #    用户原话：「这个 cfg 怎么按钮有问题」。
    #    第 ③ 条（颜色数 > 6）**抓不到这个缺陷**：药丸确实画了、内部也确实有渐变，
    #    只是它的边缘和背景同色 ⇒ 看着像"一行纯文字"。实测：
    #      · 修复前：四个按钮里只有「保存」（Primary 实心蓝）看得见，
    #        左右梯度 47/30；另外三个（Glass）只有 **3~4**；
    #      · 修复后：23~27（与字段描边的 19~20 同量级）。
    #    ★ 取 y = 药丸顶部 +3（**文字还没开始**那一行）：
    #      走行中心会被字的抗锯齿凑出梯度，那是假绿。
    #    ★ v123：x 从 `.geom` 来（按钮宽度改成自适应后，写死的 592/688 会落到
    #      两个按钮之间的空隙上 ⇒ 量到 0 的假红）。
    eL = shot.max_edge_near(reload_r[1] + 3, reload_r[0])
    eR = shot.max_edge_near(reload_r[1] + 3, reload_r[2])
    worst_btn = min(eL, eR)
    check("次按钮有看得见的边界（不是一行纯文字）", worst_btn >= 12,
        "「重新加载」左右边界梯度 %d / %d，最小 %d（要 >=12；"
        "v120 及之前是 3~4 —— 玻璃 rim 是往白掺的，在 236 的亮背景上把边界抹平了）"
        % (eL, eR, worst_btn))

    print("")
    if fails:
        # ★ 假红体检：全窗都接近白 = 抓到的背景本身是白纸，玻璃无从折射。
        #   这不是界面缺陷，是**抓图姿势**错了（没设 FREEZEBG），
        #   必须当场说清楚，否则下次又会去改 DrawPanel。
        if br >= 246 and cr >= 238:
            print("提示：面板 %.0f / 画布 %.0f 都接近白 —— 这张截图的背景抓的是"
                  "桌面上的白色窗口（玻璃只能变白卡片）。" % (br, cr))
            print("      请用 R3SHIELDCORE_PREVIEW_FREEZEBG=1 重抓再判；"
                  "同一条 exe 这样重抓应当全绿。这不是界面缺陷。")
        print("失败 %d 项：%s" % (len(fails), "、".join(fails)))
        return 1
    print("全部通过（10 项）")
    return 0


sys.exit(main())
