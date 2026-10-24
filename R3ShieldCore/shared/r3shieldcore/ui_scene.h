#pragma once
//
// ui_scene.h —— 全窗口 OpenGL 场景渲染器（v86）
// ============================================================================
//
// 这个头是"**窗口整个由 OpenGL 画**"的那一层。参考项目
// `LiquidGlassControls` 的渲染架构（三条关键约定）原样搬过来：
//
//   1. 所有 pass 共用一个 quad / 一批顶点，但用**包围盒**把绘制限制住，
//      不做 N 次全屏着色。
//   2. 玻璃层是一个**有序 vector**，后 push 的盖住先 push 的 —— 天然支持
//      "卡片 → 凹槽 → 填充 → 把手" 这种叠放，不必区分 pass。
//   3. 实心 / 图标 / 文字各自**批量成一次 draw**，顶点里带颜色和 SDF 局部坐标。
//
// 与参考项目的**唯一实质差异**（也是必须的差异）：
//   · 参考项目只烘 ASCII 32..127（`stbtt_BakeFontBitmap`），因为它是英文 demo。
//     本项目的界面是中文的，ASCII 图集根本画不出汉字。
//     ⇒ 文字层改成 **GDI 光栅化字形 + 自建图集**：
//         `GetGlyphOutlineW(GGO_GRAY8_BITMAP)` 拿到抗锯齿灰度位图，
//         按需烘进一张 2048² 的 R8 图集，GL 里当 alpha 贴图采样。
//       好处：汉字/等宽/粗体全都能画，字体跟系统走，不需要打包 ttf，
//             也不需要 stb_truetype。
//   · 参考项目用 GLFW/GLEW/glm 建窗口和取函数入口；本项目沿用
//     `ui_gl.h` 的 WGL 自建上下文（零新增 DLL），这里只借用它的 GL 上下文。
//
// ★★ 坐标约定：**设备像素，y 向下**（与 GDI / 现有布局代码一致）。
//    顶点着色器里翻成 NDC，所以片元着色器不需要再算 y。
//    `ui_gl.h` 的玻璃着色器用 `uRes.y - gl_FragCoord.y` 做同一件事，两者一致。
//
// ★★ 失败必须能回落：`Scene::Ready()` 为 false 时调用方走 `PaintGdi()`
//    ——同一份场景用 GDI 重放（平面观感，但内容一个不少）。RDP / 虚拟显卡
//    只有 GL 1.1 时就是这条路。
//
#include <windows.h>
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <cstdio>

#include "ui_gl.h"

namespace R3ShieldCoreUi {

// ★ 代次标记：发布闸门查"场景渲染器真的编进了 exe"。
//   注意 inline constexpr 的宽串如果没人引用会被链接器丢掉 ⇒ 调用方必须引用一次。
inline constexpr wchar_t kSceneMarker[] = L"R3ShieldCoreScene.v86";

// ---------------------------------------------------------------------------
// 颜色：0x00BBGGRR（与 COLORREF 同序，方便和既有配色常量混用）
// ---------------------------------------------------------------------------
inline unsigned SceneRgb(int r, int g, int b)
{
    const unsigned rr = (unsigned)(r < 0 ? 0 : (r > 255 ? 255 : r));
    const unsigned gg = (unsigned)(g < 0 ? 0 : (g > 255 ? 255 : g));
    const unsigned bb = (unsigned)(b < 0 ? 0 : (b > 255 ? 255 : b));
    return rr | (gg << 8) | (bb << 16);
}
inline unsigned SceneFromColorref(COLORREF c)
{
    return SceneRgb(GetRValue(c), GetGValue(c), GetBValue(c));
}
inline unsigned SceneMix(unsigned a, unsigned b, float t)
{
    const int ar = (int)(a & 0xFF), ag = (int)((a >> 8) & 0xFF), ab = (int)((a >> 16) & 0xFF);
    const int br = (int)(b & 0xFF), bg = (int)((b >> 8) & 0xFF), bb = (int)((b >> 16) & 0xFF);
    return SceneRgb((int)(ar + (br - ar) * t), (int)(ag + (bg - ag) * t), (int)(ab + (bb - ab) * t));
}

// ---------------------------------------------------------------------------
// 字体：**逻辑字号**，设备像素 = 字号 × dpi
// ---------------------------------------------------------------------------
enum SceneFont {
    SF_Label = 0,   // 13 常规  —— 正文/表格
    SF_Title,       // 17 半粗  —— 窗口标题
    SF_Value,       // 22 半粗  —— 大数字
    SF_Mono,        // 12 等宽  —— 表格数值
    SF_Tab,         // 14 半粗  —— 页签/按钮
    SF_Bold,        // 13 粗    —— 行内强调
    SF_Small,       // 11 常规  —— 副标题/脚注
    SF_Count
};

struct SceneFontDef {
    const wchar_t* face;
    int            px;
    int            weight;
};

inline const SceneFontDef& SceneFontTable(int id)
{
    static const SceneFontDef kTable[SF_Count] = {
        { L"Microsoft YaHei UI", 13, 400 },
        { L"Microsoft YaHei UI", 17, 600 },
        { L"Microsoft YaHei UI", 22, 600 },
        { L"Consolas",           12, 400 },
        { L"Microsoft YaHei UI", 14, 600 },
        { L"Microsoft YaHei UI", 13, 700 },
        { L"Microsoft YaHei UI", 11, 400 },
    };
    if (id < 0 || id >= SF_Count) {
        id = SF_Label;
    }
    return kTable[id];
}

// 文字排版标志
enum SceneTextFlag {
    ST_Left     = 0,
    ST_Center   = 1 << 0,
    ST_Right    = 1 << 1,
    ST_Top      = 1 << 2,   // 默认竖直居中
    ST_Ellipsis = 1 << 3,   // 放不下用 … 收尾
    ST_Wrap     = 1 << 4,   // 按宽度折行（行距 = 字体行高）
    ST_NoShadow = 1 << 5,   // 默认**不加**投影；只有大标题才加
    ST_Shadow   = 1 << 6,
};

// ---------------------------------------------------------------------------
// 顶点（与着色器 attribute 一一对应）
// ---------------------------------------------------------------------------
struct SceneSolidV {
    float x, y;        // 顶点位置（设备 px，y 向下）
    float lx, ly;      // 相对元素中心的局部坐标
    float hw, hh;      // 半尺寸
    float r;           // 圆角
    float cr, cg, cb, ca;
};

struct SceneIconV {
    float x, y;
    float lx, ly;      // 图标局部坐标（SDF 定义域 ±10）
    float id;
    float cr, cg, cb, ca;
};

struct SceneTextV {
    float x, y;
    float u, v;
    float cr, cg, cb, ca;
};

// 一次"文字运行"的 GDI 重放记录。
// ★ 为什么 GL 顶点之外还要留一份：顶点里只有字形矩形，没有**字符**，
//   GDI 回落路径没法从矩形反推出原文。所以在这里存一份原文 + 基线位置，
//   回落时用 `TextOutW` 按同一条基线重放，排版结果与 GL 路径一致。
struct SceneGdiRun {
    std::wstring s;
    float        x = 0;
    float        baseline = 0;
    int          font = 0;
    unsigned     col = 0;
};

// 一个"段" = 一次剪裁矩形 + 三批顶点。
// 为什么分段而不是全局一个批次：剪裁在 GL 里只能靠 glScissor（全局状态），
// 而界面上剪裁区极少变化（整页一个）⇒ 每段一次 scissor，段内照常批量。
struct SceneSeg {
    int x0 = 0, y0 = 0, x1 = 0, y1 = 0;   // 空矩形 = 不剪裁
    std::vector<SceneSolidV> solid;
    std::vector<SceneIconV>  icon;
    std::vector<SceneTextV>  text;
    std::vector<SceneGdiRun> gdi;
};

// ---------------------------------------------------------------------------
// 字形图集
// ---------------------------------------------------------------------------
struct SceneGlyph {
    float u0 = 0, v0 = 0, u1 = 0, v1 = 0;
    float w = 0, h = 0;        // 位图尺寸（设备 px）
    float xoff = 0;            // 相对笔位的左偏移
    float yoff = 0;            // 相对基线的上偏移（>0 = 更靠上）
    float adv = 0;             // 前进量
};

struct SceneFontMetric {
    float ascent = 0;
    float descent = 0;
    float height = 0;
    float lineGap = 0;
};

// ---------------------------------------------------------------------------
// Scene
// ---------------------------------------------------------------------------
class Scene : public GlSceneHook {
public:
    static constexpr int kAtlasSize = 2048;

    // ---------------------------------------------------------------- 生命周期
    void Begin(int w, int h, float dpi)
    {
        w_ = w;
        h_ = h;
        dpi_ = (dpi > 0.2f && dpi < 8.0f) ? dpi : 1.0f;
        segs_.clear();
        segs_.push_back(SceneSeg{});
        panelCount_ = 0;
    }

    // 兼容旧调用：不清理面板表（面板在 Scene 里独立收集）
    void Clear()
    {
        segs_.clear();
        segs_.push_back(SceneSeg{});
        panelCount_ = 0;
    }

    int  Width()  const { return w_; }
    int  Height() const { return h_; }
    float Dpi()   const { return dpi_; }

    // 逻辑 px -> 设备 px
    int  Dp(float logical) const
    {
        const int v = (int)(logical * dpi_ + 0.5f);
        return v < 1 ? 1 : v;
    }
    float Dpf(float logical) const { return logical * dpi_; }

    // ---------------------------------------------------------------- 玻璃面板
    // 与参考项目 `addGlass` 同义：登记一块玻璃，后登记的盖住先登记的。
    // kind: 0=面板 1=玻璃片 2=凹槽（无外投影）
    void Panel(int x0, int y0, int x1, int y1, float radius, float tint,
               int kind = 0, unsigned col = 0x00FFFFFF)
    {
        if (panelCount_ >= kMaxPanels || x1 <= x0 || y1 <= y0) {
            return;
        }
        GlGlass::PanelDraw& p = panels_[panelCount_++];
        p.x0 = x0; p.y0 = y0; p.x1 = x1; p.y1 = y1;
        p.radius = radius; p.tint = tint; p.kind = kind;
        p.cr = (BYTE)(col & 0xFF);
        p.cg = (BYTE)((col >> 8) & 0xFF);
        p.cb = (BYTE)((col >> 16) & 0xFF);
    }

    const GlGlass::PanelDraw* Panels() const { return panels_; }
    int  PanelCount() const { return panelCount_; }

    // ---------------------------------------------------------------- 剪裁
    void Clip(int x0, int y0, int x1, int y1)
    {
        if (segs_.empty()) {
            segs_.push_back(SceneSeg{});
        }
        if (!segs_.back().solid.empty() || !segs_.back().icon.empty() ||
            !segs_.back().text.empty()) {
            segs_.push_back(SceneSeg{});
        }
        SceneSeg& s = segs_.back();
        s.x0 = x0; s.y0 = y0; s.x1 = x1; s.y1 = y1;
    }
    void ClipAll() { Clip(0, 0, 0, 0); }

    // ---------------------------------------------------------------- 实心图元
    void Fill(int x0, int y0, int x1, int y1, unsigned col, float a = 1.0f)
    {
        Round(x0, y0, x1, y1, 0.0f, col, a);
    }

    void Round(int x0, int y0, int x1, int y1, float radius, unsigned col, float a = 1.0f)
    {
        if (x1 <= x0 || y1 <= y0 || a <= 0.002f) {
            return;
        }
        const float hw = (x1 - x0) * 0.5f;
        const float hh = (y1 - y0) * 0.5f;
        const float cx = (x0 + x1) * 0.5f;
        const float cy = (y0 + y1) * 0.5f;
        float r = radius;
        if (r > hw) r = hw;
        if (r > hh) r = hh;
        if (r < 0.0f) r = 0.0f;
        PushQuad(seg().solid, cx, cy, hw, hh, r, col, a);
    }

    void Line(int x0, int y0, int x1, int y1, unsigned col, float a = 1.0f,
              float thick = 1.0f)
    {
        const float t = thick * 0.5f;
        if (y0 == y1) {
            Round(x0, (int)(y0 - t), x1, (int)(y0 + t + 0.5f), t, col, a);
        } else if (x0 == x1) {
            Round((int)(x0 - t), y0, (int)(x0 + t + 0.5f), y1, t, col, a);
        } else {
            // 斜线不常用：拆成水平/竖直两段近似，避免引入三角剖分
            Round(x0, y0, x1, y1, 0.0f, col, a);
        }
    }

    // 圆点（进度/状态灯）
    void Dot(float cx, float cy, float r, unsigned col, float a = 1.0f)
    {
        if (r <= 0.2f || a <= 0.002f) {
            return;
        }
        PushQuad(seg().solid, cx, cy, r, r, r, col, a);
    }

    // ---------------------------------------------------------------- 图标
    // size = 图标逻辑直径（SDF 定义域 ±10 映射到这个直径）
    void Icon(int id, float cx, float cy, float size, unsigned col, float a = 1.0f)
    {
        if (size <= 1.0f || a <= 0.002f) {
            return;
        }
        const float half = size * 0.5f;
        const float k = 10.0f / half;      // 逻辑偏移 -> SDF 单位
        SceneSeg& s = seg();
        static const float kCorner[6][2] = {
            { -1, -1 }, { 1, -1 }, { 1, 1 }, { -1, -1 }, { 1, 1 }, { -1, 1 }
        };
        for (int i = 0; i < 6; ++i) {
            SceneIconV v;
            const float lx = kCorner[i][0] * half;
            const float ly = kCorner[i][1] * half;
            v.x = cx + lx;
            v.y = cy + ly;
            v.lx = lx * k;
            v.ly = ly * k;
            v.id = (float)id;
            v.cr = (float)(col & 0xFF) / 255.0f;
            v.cg = (float)((col >> 8) & 0xFF) / 255.0f;
            v.cb = (float)((col >> 16) & 0xFF) / 255.0f;
            v.ca = a;
            s.icon.push_back(v);
        }
    }

    // ---------------------------------------------------------------- 文字
    float Measure(const wchar_t* s, int font)
    {
        if (!s) return 0.0f;
        float total = 0.0f;
        for (const wchar_t* p = s; *p; ++p) {
            total += GlyphFor(font, (unsigned)*p).adv;
        }
        return total;
    }

    int LineHeight(int font)
    {
        const SceneFontMetric& m = Metric(font);
        return (int)(m.height + 0.5f);
    }

    // 单行：以**基线** y 定位（内部排版用）
    void TextBaseline(const wchar_t* s, float x, float baseline, int font,
                      unsigned col, float a = 1.0f, int flags = 0)
    {
        if (!s || !*s || a <= 0.002f) {
            return;
        }
        const float cr = (float)(col & 0xFF) / 255.0f;
        const float cg = (float)((col >> 8) & 0xFF) / 255.0f;
        const float cb = (float)((col >> 16) & 0xFF) / 255.0f;
        EmitRun(seg().text, seg().gdi, s, x, baseline, font, cr, cg, cb, a, true);
        // ★ 投影只给**浅色字**（玻璃上的白字）。
        //   深色字再压一层深色影子，等于把字形往右下发胖一遍 ——
        //   在 1:1 屏上看就是"重影"，而这是 v86 第一次跑出来最显眼的瑕疵。
        const float lum = 0.299f * cr + 0.587f * cg + 0.114f * cb;
        if ((flags & ST_Shadow) && lum > 0.55f) {
            EmitRun(seg().text, seg().gdi, s, x + 0.6f * dpi_, baseline + 0.9f * dpi_,
                    font, 0.03f, 0.04f, 0.06f, a * 0.16f, false);
        }
    }

    // 矩形内排版：**这是主力接口**（对齐 / 竖直居中 / 省略号 / 折行）
    void Text(const wchar_t* s, int x0, int y0, int x1, int y1, int font,
              unsigned col, float a = 1.0f, int flags = ST_Left)
    {
        if (!s || !*s || x1 <= x0 || y1 <= y0 || a <= 0.002f) {
            return;
        }
        // ★ 临时诊断（`R3SHIELDCORE_SCENE_DBG=1`）：揪出"矩形窄到只能放一个字"
        //   的调用点 —— 那种调用在场景里会变成竖着一列单字，很难靠看代码发现。
        {
            static int s_dbg = -1;
            if (s_dbg < 0) {
                s_dbg = GetEnvironmentVariableW(L"R3SHIELDCORE_SCENE_DBG", nullptr, 0) > 0 ? 1 : 0;
            }
            if (s_dbg && x0 < 14 && x1 > x0) {
                // ★ 不用 `%ls`：它依赖 locale，中文会让整行静默截断（踩过）。
                char u8[160] = {};
                WideCharToMultiByte(CP_UTF8, 0, s, -1, u8, sizeof(u8) - 1, nullptr, nullptr);
                printf("[scene] 靠左文本 L=%d R=%d T=%d B=%d 宽=%d 文本=%s\n",
                    x0, x1, y0, y1, x1 - x0, u8);
            }
        }
        const SceneFontMetric& m = Metric(font);
        const float avail = (float)(x1 - x0);

        if (flags & ST_Wrap) {
            float by = (float)y0 + m.ascent;
            const float limit = (float)y1;
            const float lh = m.height;
            std::wstring line;
            float lineW = 0.0f;
            for (const wchar_t* p = s; *p; ++p) {
                const SceneGlyph& g = GlyphFor(font, (unsigned)*p);
                const bool brk = (*p == L'\n');
                if (brk || lineW + g.adv > avail) {
                    if (!line.empty()) {
                        DrawLine(line.c_str(), x0, x1, by, font, col, a, flags);
                        by += lh;
                        if (by + m.descent > limit) {
                            return;
                        }
                        line.clear();
                        lineW = 0.0f;
                    }
                    if (brk) {
                        continue;
                    }
                }
                line.push_back(*p);
                lineW += g.adv;
            }
            if (!line.empty()) {
                DrawLine(line.c_str(), x0, x1, by, font, col, a, flags);
            }
            return;
        }

        // 单行
        float w = Measure(s, font);
        const float base = (flags & ST_Top)
            ? (float)y0 + m.ascent
            : (float)y0 + ((float)(y1 - y0) - m.height) * 0.5f + m.ascent;

        if (w > avail && (flags & ST_Ellipsis)) {
            const float ell = Measure(L"\u2026", font);
            std::wstring cut;
            float acc = 0.0f;
            for (const wchar_t* p = s; *p; ++p) {
                const SceneGlyph& g = GlyphFor(font, (unsigned)*p);
                if (acc + g.adv + ell > avail) {
                    break;
                }
                acc += g.adv;
                cut.push_back(*p);
            }
            cut.append(L"\u2026");
            DrawLine(cut.c_str(), x0, x1, base, font, col, a, flags & ~ST_Wrap);
            return;
        }

        DrawLine(s, x0, x1, base, font, col, a, flags & ~ST_Wrap);
    }

    // 居中（以中心点定位）—— 药丸按钮 / 页签文字
    void TextCenter(const wchar_t* s, int cx, int cy, int font, unsigned col,
                    float a = 1.0f)
    {
        const SceneFontMetric& m = Metric(font);
        const float w = Measure(s, font);
        TextBaseline(s, (float)cx - w * 0.5f,
                     (float)cy + m.height * 0.5f - m.descent, font, col, a, 0);
    }

    void TextRight(const wchar_t* s, int rightX, int cy, int font, unsigned col,
                   float a = 1.0f)
    {
        const SceneFontMetric& m = Metric(font);
        const float w = Measure(s, font);
        TextBaseline(s, (float)rightX - w,
                     (float)cy + m.height * 0.5f - m.descent, font, col, a, 0);
    }

    void TextLeft(const wchar_t* s, int leftX, int cy, int font, unsigned col,
                  float a = 1.0f)
    {
        const SceneFontMetric& m = Metric(font);
        TextBaseline(s, (float)leftX,
                     (float)cy + m.height * 0.5f - m.descent, font, col, a, 0);
    }

    // ---------------------------------------------------------------- GDI 重放
    // GL 不可用时的回落：同一份场景用 GDI 重画（平面观感）。
    // 只画实心 + 文字；图标跳过（GL 才有的 SDF），玻璃由 CPU 合成层负责。
    void PaintGdi(HDC dc, bool withText)
    {
        if (!dc) {
            return;
        }
        const int saved = SaveDC(dc);
        SetBkMode(dc, TRANSPARENT);
        for (size_t si = 0; si < segs_.size(); ++si) {
            const SceneSeg& s = segs_[si];
            if (s.x1 > s.x0 && s.y1 > s.y0) {
                IntersectClipRect(dc, s.x0, s.y0, s.x1, s.y1);
            }
            // 实心：同色合并成一个 brush，按顺序画
            for (size_t i = 0; i < s.solid.size(); i += 6) {
                const SceneSolidV& v = s.solid[i];
                const int l = (int)(v.x - v.hw + 0.5f);
                const int t = (int)(v.y - v.hh + 0.5f);
                const int r = (int)(v.x + v.hw + 0.5f);
                const int b = (int)(v.y + v.hh + 0.5f);
                // 回落路径没有混色能力（GDI 的 FillRect 不支持 alpha），
                // 半透明图元按"往白里掺"近似 —— 回落的底就是浅色玻璃，
                // 这样分隔线/淡色叠层不会整块消失，也不会变成实心黑块。
                unsigned c0 = SceneRgb((int)(v.cr * 255), (int)(v.cg * 255), (int)(v.cb * 255));
                if (v.ca < 0.995f) {
                    if (v.ca < 0.06f) {
                        continue;
                    }
                    c0 = SceneMix(c0, 0x00FFFFFFu, 1.0f - v.ca);
                }
                const COLORREF c = RGB((int)(c0 & 0xFF), (int)((c0 >> 8) & 0xFF),
                                       (int)((c0 >> 16) & 0xFF));
                HBRUSH br = CreateSolidBrush(c);
                if (v.r > 0.6f) {
                    HPEN pen = CreatePen(PS_SOLID, 1, c);
                    HGDIOBJ ob = SelectObject(dc, br);
                    HGDIOBJ op = SelectObject(dc, pen);
                    RoundRect(dc, l, t, r, b, (int)(v.r * 2.0f), (int)(v.r * 2.0f));
                    SelectObject(dc, op);
                    SelectObject(dc, ob);
                    DeleteObject(pen);
                } else {
                    RECT rc = { l, t, r, b };
                    FillRect(dc, &rc, br);
                }
                DeleteObject(br);
            }
            if (withText && !s.gdi.empty()) {
                PaintGdiText(dc, s.gdi);
            }
        }
        RestoreDC(dc, saved);
    }

    // 是否已经烘过字形（诊断用）
    int  GlyphCount() const { return (int)glyphs_.size(); }
    bool AtlasOverflow() const { return atlasFull_; }

    // ---------------------------------------------------------------- GL 绘制
    // 由 `GlGlass::Render` 在"面板画完、回读之前"回调。
    void Draw(GlFuncs& g, int w, int h, float dpi) override
    {
        if (segs_.empty()) {
            return;
        }
        if (!EnsureGl(g, w, h)) {
            return;
        }
        UploadAtlas(g);

        glEnable(GL_BLEND);
        glBlendFunc(GL_ONE, GL_ONE_MINUS_SRC_ALPHA);   // 预乘 alpha
        glDisable(GL_SCISSOR_TEST);

        for (size_t si = 0; si < segs_.size(); ++si) {
            const SceneSeg& s = segs_[si];
            if (s.x1 > s.x0 && s.y1 > s.y0) {
                glEnable(GL_SCISSOR_TEST);
                glScissor(s.x0, h - s.y1, s.x1 - s.x0, s.y1 - s.y0);
            } else {
                glDisable(GL_SCISSOR_TEST);
            }

            if (!s.solid.empty()) {
                g.UseProgram(pSolid_);
                g.Uniform2f(g.GetUniformLocation(pSolid_, "uRes"), (float)w, (float)h);
                g.BindVertexArray(vaoSolid_);
                g.BindBuffer(GL_ARRAY_BUFFER, vboSolid_);
                g.BufferData(GL_ARRAY_BUFFER,
                    (GLsizeiptrR3)(s.solid.size() * sizeof(SceneSolidV)),
                    s.solid.data(), GL_STREAM_DRAW);
                glDrawArrays(GL_TRIANGLES, 0, (GLsizei)s.solid.size());
            }
            if (!s.icon.empty()) {
                g.UseProgram(pIcon_);
                g.Uniform2f(g.GetUniformLocation(pIcon_, "uRes"), (float)w, (float)h);
                g.BindVertexArray(vaoIcon_);
                g.BindBuffer(GL_ARRAY_BUFFER, vboIcon_);
                g.BufferData(GL_ARRAY_BUFFER,
                    (GLsizeiptrR3)(s.icon.size() * sizeof(SceneIconV)),
                    s.icon.data(), GL_STREAM_DRAW);
                glDrawArrays(GL_TRIANGLES, 0, (GLsizei)s.icon.size());
            }
            if (!s.text.empty() && texAtlas_) {
                g.UseProgram(pText_);
                g.Uniform2f(g.GetUniformLocation(pText_, "uRes"), (float)w, (float)h);
                g.ActiveTexture(GL_TEXTURE0);
                glBindTexture(GL_TEXTURE_2D, texAtlas_);
                g.Uniform1i(g.GetUniformLocation(pText_, "uAtlas"), 0);
                g.BindVertexArray(vaoText_);
                g.BindBuffer(GL_ARRAY_BUFFER, vboText_);
                g.BufferData(GL_ARRAY_BUFFER,
                    (GLsizeiptrR3)(s.text.size() * sizeof(SceneTextV)),
                    s.text.data(), GL_STREAM_DRAW);
                glDrawArrays(GL_TRIANGLES, 0, (GLsizei)s.text.size());
            }
        }
        glDisable(GL_SCISSOR_TEST);
        g.BindVertexArray(0);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    }

    ~Scene() { ReleaseGdi(); }

private:
    static constexpr int kMaxPanels = 128;

    int   w_ = 0, h_ = 0;
    float dpi_ = 1.0f;
    std::vector<SceneSeg> segs_;
    GlGlass::PanelDraw panels_[kMaxPanels] = {};
    int      panelCount_ = 0;

    // ---- 字形缓存
    std::map<unsigned long long, SceneGlyph> glyphs_;
    std::map<int, SceneFontMetric>           metrics_;
    std::vector<unsigned char> atlas_;
    int   atlasX_ = 0, atlasY_ = 0, atlasRowH_ = 0;
    bool  atlasDirty_ = false;
    bool  atlasFull_ = false;
    int   dirtyX0_ = 0, dirtyY0_ = 0, dirtyX1_ = 0, dirtyY1_ = 0;

    // ---- GDI 光栅化侧
    HDC   gdiDc_ = nullptr;
    HBITMAP gdiBmp_ = nullptr;
    HGDIOBJ gdiOldBmp_ = nullptr;
    std::map<unsigned long long, HFONT> fonts_;   // key = (px<<8)|weight
    std::map<unsigned long long, HFONT> gdiFonts_;

    // ---- GL 侧
    GlFuncs* g_ = nullptr;
    GLuint pSolid_ = 0, pIcon_ = 0, pText_ = 0;
    GLuint vaoSolid_ = 0, vboSolid_ = 0;
    GLuint vaoIcon_ = 0, vboIcon_ = 0;
    GLuint vaoText_ = 0, vboText_ = 0;
    GLuint texAtlas_ = 0;
    bool   glFailed_ = false;

    SceneSeg& seg()
    {
        if (segs_.empty()) {
            segs_.push_back(SceneSeg{});
        }
        return segs_.back();
    }

    static void PushQuad(std::vector<SceneSolidV>& out, float cx, float cy,
                         float hw, float hh, float r, unsigned col, float a)
    {
        static const float kCorner[6][2] = {
            { -1, -1 }, { 1, -1 }, { 1, 1 }, { -1, -1 }, { 1, 1 }, { -1, 1 }
        };
        const float cr = (float)(col & 0xFF) / 255.0f;
        const float cg = (float)((col >> 8) & 0xFF) / 255.0f;
        const float cb = (float)((col >> 16) & 0xFF) / 255.0f;
        for (int i = 0; i < 6; ++i) {
            SceneSolidV v;
            v.lx = kCorner[i][0] * hw;
            v.ly = kCorner[i][1] * hh;
            v.x = cx + v.lx;
            v.y = cy + v.ly;
            v.hw = hw;
            v.hh = hh;
            v.r = r;
            v.cr = cr; v.cg = cg; v.cb = cb; v.ca = a;
            out.push_back(v);
        }
    }

    void DrawLine(const wchar_t* s, int x0, int x1, float baseline, int font,
                  unsigned col, float a, int flags)
    {
        const float w = Measure(s, font);
        float x = (float)x0;
        if (flags & ST_Center) {
            x = (float)x0 + ((float)(x1 - x0) - w) * 0.5f;
        } else if (flags & ST_Right) {
            x = (float)x1 - w;
        }
        const float cr = (float)(col & 0xFF) / 255.0f;
        const float cg = (float)((col >> 8) & 0xFF) / 255.0f;
        const float cb = (float)((col >> 16) & 0xFF) / 255.0f;
        EmitRun(seg().text, seg().gdi, s, x, baseline, font, cr, cg, cb, a, true);
    }

    void EmitRun(std::vector<SceneTextV>& out, std::vector<SceneGdiRun>& runs,
                 const wchar_t* s, float x, float baseline, int font,
                 float cr, float cg, float cb, float a, bool record)
    {
        if (record) {
            SceneGdiRun r;
            r.s = s;
            r.x = x;
            r.baseline = baseline;
            r.font = font;
            r.col = SceneRgb((int)(cr * 255.0f + 0.5f), (int)(cg * 255.0f + 0.5f),
                             (int)(cb * 255.0f + 0.5f));
            runs.push_back(r);
            {
                static int s_dbg2 = -1;
                if (s_dbg2 < 0) {
                    s_dbg2 = GetEnvironmentVariableW(L"R3SHIELDCORE_SCENE_DBG", nullptr, 0) > 0 ? 1 : 0;
                }
                if (s_dbg2 && x < 14.0f) {
                    char u8[120] = {};
                    WideCharToMultiByte(CP_UTF8, 0, s, -1, u8, sizeof(u8) - 1, nullptr, nullptr);
                    printf("[scene2] x=%.1f base=%.1f font=%d 文本=%s\n",
                        (double)x, (double)baseline, font, u8);
                }
            }
        }
        float pen = x;
        for (const wchar_t* p = s; *p; ++p) {
            const unsigned cp = (unsigned)*p;
            if (cp == L'\n' || cp == L'\r') {
                continue;
            }
            const SceneGlyph& gl = GlyphFor(font, cp);
            if (gl.w > 0.0f && gl.h > 0.0f) {
                // ★ 顶点取整：字形位图本身是整像素的，落在半像素上会被
                //   双线性采样糊一层（尤其配合 `pow(m,0.72)` 会显得字发胖）。
                //   GDI 排版本来就是整像素推进，这里对齐它反而更"像原来的字"。
                // ★★★ `gmptGlyphOrigin.y` 是**从基线往上到黑框顶边**的距离，
                //   所以 `baseline - yoff` 是**顶边**、不是底边（v87 踩过）。
                //   把它当底边会让每个字按**自身高度**上移 —— 高度不同的字
                //   相对位置全错，最明显的是冒号（h=12）掉到数字（h=17）基线以下，
                //   "00:00:01" 看起来像 "00.00.01" 而且点还贴底。
                const float x0 = floorf(pen + gl.xoff + 0.5f);
                const float y0 = floorf(baseline - gl.yoff + 0.5f);
                const float x1 = x0 + floorf(gl.w + 0.5f);
                const float y1 = y0 + floorf(gl.h + 0.5f);
                SceneTextV q[6] = {
                    { x0, y0, gl.u0, gl.v0, cr, cg, cb, a },
                    { x0, y1, gl.u0, gl.v1, cr, cg, cb, a },
                    { x1, y0, gl.u1, gl.v0, cr, cg, cb, a },
                    { x0, y1, gl.u0, gl.v1, cr, cg, cb, a },
                    { x1, y1, gl.u1, gl.v1, cr, cg, cb, a },
                    { x1, y0, gl.u1, gl.v0, cr, cg, cb, a },
                };
                for (int i = 0; i < 6; ++i) {
                    out.push_back(q[i]);
                }
            }
            pen += gl.adv;
        }
    }

    // ---------------------------------------------------------------- GDI 资源
    bool EnsureGdi()
    {
        if (gdiDc_) {
            return true;
        }
        HDC screen = GetDC(nullptr);
        gdiDc_ = CreateCompatibleDC(screen);
        gdiBmp_ = CreateCompatibleBitmap(screen, 4, 4);
        ReleaseDC(nullptr, screen);
        if (!gdiDc_ || !gdiBmp_) {
            return false;
        }
        gdiOldBmp_ = SelectObject(gdiDc_, gdiBmp_);
        SetBkMode(gdiDc_, TRANSPARENT);
        return true;
    }

    void ReleaseGdi()
    {
        for (auto& kv : fonts_) {
            if (kv.second) DeleteObject(kv.second);
        }
        fonts_.clear();
        for (auto& kv : gdiFonts_) {
            if (kv.second) DeleteObject(kv.second);
        }
        gdiFonts_.clear();
        if (gdiDc_) {
            if (gdiOldBmp_) SelectObject(gdiDc_, gdiOldBmp_);
            if (gdiBmp_) DeleteObject(gdiBmp_);
            DeleteDC(gdiDc_);
        }
        gdiDc_ = nullptr;
        gdiBmp_ = nullptr;
        gdiOldBmp_ = nullptr;
    }

    int DevPx(int font)
    {
        const SceneFontDef& d = SceneFontTable(font);
        int px = (int)(d.px * dpi_ + 0.5f);
        if (px < 8) px = 8;
        return px;
    }

    HFONT FontFor(int font)
    {
        const SceneFontDef& d = SceneFontTable(font);
        const int px = DevPx(font);
        const unsigned long long key = ((unsigned long long)px << 8) | (unsigned)d.weight;
        auto it = fonts_.find(key);
        if (it != fonts_.end()) {
            return it->second;
        }
        HFONT f = CreateFontW(-px, 0, 0, 0, d.weight, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
            ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, d.face);
        fonts_[key] = f;
        return f;
    }

    const SceneFontMetric& Metric(int font)
    {
        auto it = metrics_.find(font);
        if (it != metrics_.end()) {
            return it->second;
        }
        SceneFontMetric m;
        if (EnsureGdi()) {
            HGDIOBJ old = SelectObject(gdiDc_, FontFor(font));
            TEXTMETRICW tm = {};
            if (GetTextMetricsW(gdiDc_, &tm)) {
                m.ascent = (float)tm.tmAscent;
                m.descent = (float)tm.tmDescent;
                m.height = (float)(tm.tmHeight);
                m.lineGap = (float)(tm.tmExternalLeading);
            }
            SelectObject(gdiDc_, old);
        }
        if (m.height <= 0.0f) {
            m.ascent = (float)DevPx(font) * 0.8f;
            m.descent = (float)DevPx(font) * 0.2f;
            m.height = (float)DevPx(font) * 1.3f;
        }
        auto ins = metrics_.insert(std::make_pair(font, m));
        return ins.first->second;
    }

    // ---------------------------------------------------------------- 字形烘焙
    const SceneGlyph& GlyphFor(int font, unsigned cp)
    {
        static SceneGlyph kBlank;
        const int px = DevPx(font);
        const unsigned long long key =
            ((unsigned long long)px << 40) | ((unsigned long long)cp << 8) |
            (unsigned long long)(font & 0xFF);
        auto it = glyphs_.find(key);
        if (it != glyphs_.end()) {
            return it->second;
        }
        SceneGlyph gl;
        BakeGlyph(font, cp, gl);
        auto ins = glyphs_.insert(std::make_pair(key, gl));
        return ins.first->second;
    }

    void MarkDirty(int x0, int y0, int x1, int y1)
    {
        if (!atlasDirty_) {
            dirtyX0_ = x0; dirtyY0_ = y0; dirtyX1_ = x1; dirtyY1_ = y1;
            atlasDirty_ = true;
            return;
        }
        if (x0 < dirtyX0_) dirtyX0_ = x0;
        if (y0 < dirtyY0_) dirtyY0_ = y0;
        if (x1 > dirtyX1_) dirtyX1_ = x1;
        if (y1 > dirtyY1_) dirtyY1_ = y1;
    }

    void BakeGlyph(int font, unsigned cp, SceneGlyph& gl)
    {
        if (!EnsureGdi()) {
            return;
        }
        HGDIOBJ old = SelectObject(gdiDc_, FontFor(font));

        MAT2 mat = {};
        mat.eM11.value = 1; mat.eM22.value = 1;
        GLYPHMETRICS gm = {};
        const DWORD need = GetGlyphOutlineW(gdiDc_, cp, GGO_GRAY8_BITMAP,
                                            &gm, 0, nullptr, &mat);
        if (need == GDI_ERROR) {
            SelectObject(gdiDc_, old);
            return;
        }

        // ★★★ 前进量必须用 `gm.gmCellIncX`，**不能**用 `GetCharWidth32W`（踩过）。
        //
        //   两者是**两套度量**：`gmCellIncX` 和 `gmptGlyphOrigin` 是同一次
        //   `GetGlyphOutline` 出来的，配在一起才对得上；`GetCharWidth32W` 给的
        //   是 ABC 的 A 宽度（且不带字形微调），和 `gmptGlyphOrigin` 混用会让
        //   部分字母**互相压住** —— 症状是 "R3Shi**e**ld**C**ore" 里 e/C 叠到
        //   前一个字母上，看上去像"重影"，很容易误判成抗锯齿或投影问题。
        gl.adv = (float)gm.gmCellIncX;
        if (gl.adv <= 0.0f) {
            int advPx = 0;
            if (GetCharWidth32W(gdiDc_, cp, cp, &advPx) == FALSE || advPx <= 0) {
                advPx = DevPx(font) / 2;
            }
            gl.adv = (float)advPx;
        }

        // ★ 空格这类字形：GDI 会回一个 **1x1 的框但 0 字节** 的位图。
        //   只看 gmBlackBoxX/Y 判断不出来（它们都是 1）⇒ 必须也判 `need == 0`，
        //   否则 `buf.data()` 是空指针，下面按行拷贝直接段错误（踩过）。
        //   ★ 注意位置：前进量已经取好了，空格照样要有 adv，否则整行会挤在一起。
        if (need == 0 || gm.gmBlackBoxX == 0 || gm.gmBlackBoxY == 0) {
            SelectObject(gdiDc_, old);
            return;
        }

        std::vector<unsigned char> buf(need);
        if (GetGlyphOutlineW(gdiDc_, cp, GGO_GRAY8_BITMAP, &gm, need,
                             buf.data(), &mat) == GDI_ERROR) {
            SelectObject(gdiDc_, old);
            return;
        }
        SelectObject(gdiDc_, old);

        const int bw = (int)gm.gmBlackBoxX;
        const int bh = (int)gm.gmBlackBoxY;
        const int pitch = (bw + 3) & ~3;

        if (atlas_.empty()) {
            atlas_.assign((size_t)kAtlasSize * kAtlasSize, 0);
        }

        // 架式装箱：一行一行排
        if (atlasX_ + bw + 1 > kAtlasSize) {
            atlasX_ = 0;
            atlasY_ += atlasRowH_ + 1;
            atlasRowH_ = 0;
        }
        if (atlasY_ + bh + 1 > kAtlasSize) {
            atlasFull_ = true;
            return;
        }

        unsigned char* dst = atlas_.data();
        for (int y = 0; y < bh; ++y) {
            const unsigned char* src = buf.data() + (size_t)y * pitch;
            unsigned char* drow = dst + (size_t)(atlasY_ + y) * kAtlasSize + atlasX_;
            for (int x = 0; x < bw; ++x) {
                // GGO_GRAY8 是 0..64 级
                const unsigned v = (unsigned)src[x];
                drow[x] = (unsigned char)(v >= 64 ? 255 : (v * 255 + 32) / 64);
            }
        }

        gl.w = (float)bw;
        gl.h = (float)bh;
        gl.xoff = (float)gm.gmptGlyphOrigin.x;
        gl.yoff = (float)gm.gmptGlyphOrigin.y;
        // ★ 图集 UV 必须取**纹素中心**（±0.5 texel）。
        //   直接用 `x / size` 取的是纹素**边界**，LINEAR 采样会把左右相邻的
        //   字形像素混进来 —— 1:1 屏上就是"每个字右边缘挂一层淡影"，
        //   看起来像重影/发虚，很容易误判成投影或抗锯齿问题（v87 踩过）。
        const float half = 0.5f / (float)kAtlasSize;
        gl.u0 = (float)atlasX_ / kAtlasSize + half;
        gl.v0 = (float)atlasY_ / kAtlasSize + half;
        gl.u1 = (float)(atlasX_ + bw) / kAtlasSize - half;
        gl.v1 = (float)(atlasY_ + bh) / kAtlasSize - half;

        MarkDirty(atlasX_, atlasY_, atlasX_ + bw, atlasY_ + bh);

        atlasX_ += bw + 1;
        if (bh > atlasRowH_) {
            atlasRowH_ = bh;
        }
    }

    // ---------------------------------------------------------------- GDI 文字重放
    void PaintGdiText(HDC dc, const std::vector<SceneGdiRun>& runs)
    {
        HGDIOBJ oldFont = nullptr;
        int curFont = -1;
        for (size_t i = 0; i < runs.size(); ++i) {
            const SceneGdiRun& r = runs[i];
            if (r.s.empty()) {
                continue;
            }
            if (r.font != curFont) {
                HFONT f = FontFor(r.font);
                if (f) {
                    oldFont = SelectObject(dc, f);
                }
                curFont = r.font;
            }
            SetTextColor(dc, RGB((int)(r.col & 0xFF), (int)((r.col >> 8) & 0xFF),
                                 (int)((r.col >> 16) & 0xFF)));
            const SceneFontMetric& m = Metric(r.font);
            TextOutW(dc, (int)(r.x + 0.5f), (int)(r.baseline - m.ascent + 0.5f),
                     r.s.c_str(), (int)r.s.size());
        }
        if (oldFont) {
            SelectObject(dc, oldFont);
        }
    }

    // ---------------------------------------------------------------- GL 初始化
    static const char* SolidVS()
    {
        return R"(#version 330 core
layout(location=0) in vec2 aPos;
layout(location=1) in vec2 aLocal;
layout(location=2) in vec2 aHalf;
layout(location=3) in float aRad;
layout(location=4) in vec4 aCol;
uniform vec2 uRes;
out vec2 vLocal; out vec2 vHalf; out float vRad; out vec4 vCol;
void main(){
  vLocal = aLocal; vHalf = aHalf; vRad = aRad; vCol = aCol;
  vec2 n = aPos / uRes * 2.0 - 1.0;
  gl_Position = vec4(n.x, -n.y, 0.0, 1.0);
}
)";
    }

    static const char* SolidFS()
    {
        return R"(#version 330 core
in vec2 vLocal; in vec2 vHalf; in float vRad; in vec4 vCol;
out vec4 fragColor;
float sdRB(vec2 p, vec2 b, float r){
  vec2 q = abs(p) - b + r;
  return min(max(q.x,q.y),0.0) + length(max(q,0.0)) - r;
}
void main(){
  float d = sdRB(vLocal, vHalf, max(vRad, 0.0));
  float aa = max(fwidth(d) * 0.75, 0.35);
  float a = smoothstep(aa, -aa, d) * vCol.a;
  fragColor = vec4(vCol.rgb * a, a);
}
)";
    }

    static const char* IconVS()
    {
        return R"(#version 330 core
layout(location=0) in vec2 aPos;
layout(location=1) in vec2 aLocal;
layout(location=2) in float aId;
layout(location=3) in vec4 aCol;
uniform vec2 uRes;
out vec2 vLocal; out float vId; out vec4 vCol;
void main(){
  vLocal = aLocal; vId = aId; vCol = aCol;
  vec2 n = aPos / uRes * 2.0 - 1.0;
  gl_Position = vec4(n.x, -n.y, 0.0, 1.0);
}
)";
    }

    // 图标 SDF：定义域约 ±10。id 见 SceneIcon 注释。
    static const char* IconFS()
    {
        return R"(#version 330 core
in vec2 vLocal; in float vId; in vec4 vCol;
out vec4 fragColor;

float sdBox(vec2 p, vec2 b){ vec2 d = abs(p)-b; return min(max(d.x,d.y),0.0)+length(max(d,0.0)); }
float sdRB(vec2 p, vec2 b, float r){ vec2 q = abs(p)-b+r; return min(max(q.x,q.y),0.0)+length(max(q,0.0))-r; }
float sdCir(vec2 p, float r){ return length(p)-r; }
float sdSeg(vec2 p, vec2 a, vec2 b, float r){
  vec2 pa = p-a, ba = b-a;
  float h = clamp(dot(pa,ba)/max(dot(ba,ba),1e-6), 0.0, 1.0);
  return length(pa - ba*h) - r;
}
float hp(vec2 p, vec2 a, vec2 b){
  vec2 e = b-a;
  vec2 n = normalize(vec2(e.y, -e.x));
  return dot(p-a, n);
}
float sdTri(vec2 p, vec2 a, vec2 b, vec2 c){
  return max(max(hp(p,a,b), hp(p,b,c)), hp(p,c,a));
}
// 盾牌轮廓（安全软件的主图标）
float sdShield(vec2 p, float w){
  vec2 q = p - vec2(0.0, 1.0);
  float top = sdBox(q, vec2(7.6, 1.2));
  float body = sdTri(q, vec2(-7.6,-0.6), vec2(7.6,-0.6), vec2(0.0,-9.4));
  float side = sdBox(q, vec2(7.6, 4.0));
  return max(min(min(top, body), side), -(length(p) - 11.0)) * w;
}

float iconSDF(int t, vec2 p){
  if(t == 0){                                   // 0 shield 盾牌
    float s = sdShield(p, 1.0);
    return max(s, -1.0);
  }
  if(t == 1){                                   // 1 log 三横线
    float a = sdSeg(p, vec2(-7.5, 5.0), vec2(7.5, 5.0), 1.5);
    float b = sdSeg(p, vec2(-7.5, 0.0), vec2(5.0, 0.0), 1.5);
    float c = sdSeg(p, vec2(-7.5,-5.0), vec2(7.5,-5.0), 1.5);
    return min(min(a,b),c);
  }
  if(t == 2){                                   // 2 cpu 芯片
    float body = sdRB(p, vec2(6.4,6.4), 1.8);
    float ring = abs(sdRB(p, vec2(4.0,4.0), 1.0)) - 0.9;
    float pins = 1e9;
    for(int i=0;i<3;i++){
      float o = -3.4 + float(i)*3.4;
      pins = min(pins, sdSeg(p, vec2(o, 6.4), vec2(o, 9.4), 0.9));
      pins = min(pins, sdSeg(p, vec2(o,-6.4), vec2(o,-9.4), 0.9));
      pins = min(pins, sdSeg(p, vec2( 6.4, o), vec2( 9.4, o), 0.9));
      pins = min(pins, sdSeg(p, vec2(-6.4, o), vec2(-9.4, o), 0.9));
    }
    return min(min(body, ring), pins);
  }
  if(t == 3){                                   // 3 gear 齿轮
    float ang = atan(p.y, p.x);
    float outer = 6.6 + 1.6 * pow(abs(cos(ang * 4.0)), 1.5);
    return max(length(p) - outer, -(length(p) - 2.8));
  }
  if(t == 4){                                   // 4 layers 层叠
    float l1 = sdSeg(p, vec2(-8.0, 3.6), vec2(0.0, 7.4), 1.5);
    float l2 = sdSeg(p, vec2(0.0, 7.4), vec2(8.0, 3.6), 1.5);
    float l3 = sdSeg(p, vec2(-8.0,-1.0), vec2(0.0, 2.8), 1.5);
    float l4 = sdSeg(p, vec2(0.0, 2.8), vec2(8.0,-1.0), 1.5);
    float l5 = sdSeg(p, vec2(-8.0,-5.6), vec2(0.0,-1.8), 1.5);
    float l6 = sdSeg(p, vec2(0.0,-1.8), vec2(8.0,-5.6), 1.5);
    return min(min(min(l1,l2),min(l3,l4)),min(l5,l6));
  }
  if(t == 5){                                   // 5 bolt 闪电
    float t1 = sdTri(p, vec2(2.4, 9.4), vec2(-6.4,-1.2), vec2(0.4,-1.2));
    float t2 = sdTri(p, vec2(-1.6, 1.2), vec2(-2.6,-9.4), vec2(6.2, 1.2));
    return min(t1, t2);
  }
  if(t == 6){                                   // 6 check 勾
    return min(sdSeg(p, vec2(-5.6,-0.4), vec2(-1.6,-4.6), 1.9),
               sdSeg(p, vec2(-1.6,-4.6), vec2(5.8, 4.4), 1.9));
  }
  if(t == 7){                                   // 7 close 叉
    return min(sdSeg(p, vec2(-5.4,-5.4), vec2(5.4, 5.4), 1.8),
               sdSeg(p, vec2(-5.4, 5.4), vec2(5.4,-5.4), 1.8));
  }
  if(t == 8){                                   // 8 search 放大镜
    return min(abs(sdCir(p - vec2(-1.6, 2.0), 5.6)) - 1.5,
               sdSeg(p, vec2(2.2,-1.6), vec2(7.0,-6.6), 1.5));
  }
  if(t == 9){                                   // 9 info
    float ring = abs(sdCir(p, 7.8)) - 1.5;
    float bar  = sdSeg(p, vec2(0.0,-0.8), vec2(0.0,-5.0), 1.3);
    float dot_ = sdCir(p - vec2(0.0, 4.0), 1.4);
    return min(ring, min(bar, dot_));
  }
  if(t == 10){                                  // 10 alert 三角
    float tri = sdTri(p, vec2(0.0, 8.6), vec2(-8.6,-7.2), vec2(8.6,-7.2));
    float ring = abs(tri) - 1.5;
    float bar = sdSeg(p, vec2(0.0, 2.6), vec2(0.0,-1.6), 1.3);
    float dot_ = sdCir(p - vec2(0.0,-4.4), 1.35);
    return min(ring, min(bar, dot_));
  }
  if(t == 11){                                  // 11 clock 时钟
    float ring = abs(sdCir(p, 7.8)) - 1.5;
    float h1 = sdSeg(p, vec2(0.0,0.0), vec2(0.0, 4.6), 1.3);
    float h2 = sdSeg(p, vec2(0.0,0.0), vec2(3.4,-1.6), 1.3);
    return min(ring, min(h1,h2));
  }
  if(t == 12){                                  // 12 lock 锁
    float body = sdRB(p - vec2(0.0,-3.6), vec2(5.6,4.4), 1.6);
    float arc  = max(abs(sdCir(p - vec2(0.0, 0.6), 3.4)) - 1.4, -(p.y - 0.6));
    return min(body, arc);
  }
  if(t == 13){                                  // 13 copy 双矩形
    float a = sdRB(p - vec2(-1.8,-1.8), vec2(4.6,5.6), 1.4);
    float b = abs(sdRB(p - vec2(2.2, 2.2), vec2(4.6,5.6), 1.4)) - 1.2;
    return min(a, b);
  }
  if(t == 14){                                  // 14 trash 垃圾桶
    float lid = sdSeg(p, vec2(-6.6, 5.2), vec2(6.6, 5.2), 1.4);
    float knob = sdSeg(p, vec2(-2.4, 7.4), vec2(2.4, 7.4), 1.4);
    float body = abs(sdRB(p - vec2(0.0,-2.2), vec2(4.8,5.4), 1.2)) - 1.2;
    return min(min(lid, knob), body);
  }
  if(t == 15){                                  // 15 refresh 循环
    float ring = abs(sdCir(p, 6.6)) - 1.5;
    float cut = max(ring, -max(p.y - 3.0, -(p.x + 2.0)));
    float head = sdTri(p, vec2(5.4, 7.4), vec2(2.4, 3.6), vec2(8.4, 3.2));
    return min(cut, head);
  }
  if(t == 16){                                  // 16 eye 眼睛
    float a = abs(sdCir(p - vec2(0.0, 3.6), 5.6)) - 1.4;
    float b = abs(sdCir(p - vec2(0.0,-3.6), 5.6)) - 1.4;
    float lens = max(a, b);
    return min(lens, sdCir(p, 2.0));
  }
  if(t == 17){                                  // 17 arrow-right
    return min(sdSeg(p, vec2(-7.0,0.0), vec2(6.4,0.0), 1.5),
               min(sdSeg(p, vec2(1.6, 5.0), vec2(6.6, 0.0), 1.5),
                   sdSeg(p, vec2(1.6,-5.0), vec2(6.6, 0.0), 1.5)));
  }
  if(t == 18){                                  // 18 dots 三点
    return min(min(sdCir(p - vec2(-6.2,0.0), 1.9), sdCir(p, 1.9)),
               sdCir(p - vec2(6.2,0.0), 1.9));
  }
  if(t == 19){                                  // 19 folder 文件夹
    float a = sdRB(p - vec2(0.0,-1.4), vec2(7.6,5.2), 1.6);
    float tab = sdRB(p - vec2(-3.4, 4.6), vec2(3.6,1.6), 0.8);
    return min(a, tab);
  }
  if(t == 20){                                  // 20 key 钥匙
    float ring = abs(sdCir(p - vec2(-3.4, 3.2), 4.2)) - 1.6;
    float stem = sdSeg(p, vec2(-0.4,-0.4), vec2(7.0,-7.4), 1.5);
    float t1 = sdSeg(p, vec2(4.2,-4.6), vec2(6.4,-2.4), 1.3);
    return min(min(ring, stem), t1);
  }
  if(t == 21){                                  // 21 camera 相机
    float body = sdRB(p - vec2(0.0,-1.2), vec2(7.6,5.4), 1.8);
    float lens = abs(sdCir(p - vec2(0.0,-1.2), 3.2)) - 1.3;
    float top  = sdRB(p - vec2(-2.6, 5.2), vec2(2.6,1.4), 0.8);
    return min(min(body, lens), top);
  }
  if(t == 22){                                  // 22 clipboard 剪贴板
    float body = sdRB(p - vec2(0.0,-1.0), vec2(5.8,6.8), 1.6);
    float clip = sdRB(p - vec2(0.0, 6.0), vec2(3.0,1.8), 0.8);
    return min(body, clip);
  }
  if(t == 23){                                  // 23 network 网络
    float a = sdSeg(p, vec2(-5.6, 4.6), vec2(5.6, 4.6), 1.2);
    float b = sdSeg(p, vec2(-5.6, 4.6), vec2(0.0,-6.2), 1.2);
    float c = sdSeg(p, vec2(5.6, 4.6), vec2(0.0,-6.2), 1.2);
    float n1 = sdCir(p - vec2(-5.6, 4.6), 2.2);
    float n2 = sdCir(p - vec2(5.6, 4.6), 2.2);
    float n3 = sdCir(p - vec2(0.0,-6.2), 2.2);
    return min(min(min(a,b),c), min(min(n1,n2),n3));
  }
  if(t == 24){                                  // 24 plug 插头/DLL
    float body = sdRB(p - vec2(0.0, 1.4), vec2(4.6,4.6), 1.4);
    float p1 = sdSeg(p, vec2(-2.2, 6.0), vec2(-2.2, 9.0), 1.2);
    float p2 = sdSeg(p, vec2( 2.2, 6.0), vec2( 2.2, 9.0), 1.2);
    float stem = sdSeg(p, vec2(0.0,-3.2), vec2(0.0,-8.4), 1.6);
    return min(min(body, p1), min(p2, stem));
  }
  if(t == 25){                                  // 25 pause 暂停
    return min(sdRB(p - vec2(-3.2,0.0), vec2(1.8,7.0), 1.0),
               sdRB(p - vec2( 3.2,0.0), vec2(1.8,7.0), 1.0));
  }
  if(t == 26){                                  // 26 play 播放
    return sdTri(p, vec2(-4.4, 7.4), vec2(-4.4,-7.4), vec2(7.0, 0.0));
  }
  if(t == 27){                                  // 27 shield-x 拦截
    float s = sdShield(p, 1.0);
    float x = min(sdSeg(p - vec2(0.0,-1.0), vec2(-2.6,-3.6), vec2(2.6, 1.6), 1.2),
                  sdSeg(p - vec2(0.0,-1.0), vec2(-2.6, 1.6), vec2(2.6,-3.6), 1.2));
    return max(s, -x);
  }
  if(t == 28){                                  // 28 shield-check 允许
    float s = sdShield(p, 1.0);
    float k = min(sdSeg(p - vec2(0.0,-1.0), vec2(-3.0,-0.4), vec2(-0.6,-3.0), 1.3),
                  sdSeg(p - vec2(0.0,-1.0), vec2(-0.6,-3.0), vec2(3.2, 2.2), 1.3));
    return max(s, -k);
  }
  if(t == 29){                                  // 29 download 下载
    return min(sdSeg(p - vec2(0.0, 1.6), vec2(0.0, 6.4), vec2(0.0,-3.2), 1.5),
               min(sdSeg(p - vec2(0.0, 1.6), vec2(-4.4,-0.6), vec2(0.0,-3.6), 1.5),
                   sdSeg(p - vec2(0.0, 1.6), vec2( 4.4,-0.6), vec2(0.0,-3.6), 1.5)));
  }
  return sdCir(p, 7.0);
}

void main(){
  float d = iconSDF(int(vId + 0.5), vLocal);
  float aa = max(fwidth(d) * 0.85, 0.45);
  float a = smoothstep(aa, -aa, d) * vCol.a;
  fragColor = vec4(vCol.rgb * a, a);
}
)";
    }

    static const char* TextVS()
    {
        return R"(#version 330 core
layout(location=0) in vec2 aPos;
layout(location=1) in vec2 aUV;
layout(location=2) in vec4 aCol;
uniform vec2 uRes;
out vec2 vUV; out vec4 vCol;
void main(){
  vUV = aUV; vCol = aCol;
  vec2 n = aPos / uRes * 2.0 - 1.0;
  gl_Position = vec4(n.x, -n.y, 0.0, 1.0);
}
)";
    }

    static const char* TextFS()
    {
        return R"(#version 330 core
in vec2 vUV; in vec4 vCol;
out vec4 fragColor;
uniform sampler2D uAtlas;
void main(){
  float m = texture(uAtlas, vUV).r;
  // ★ 灰度抗锯齿的"笔画加粗"：GDI 的 ClearType 在 13px 上看起来比纯灰度 AA
  //   重一档，换成灰度图集之后小字会明显发灰（实测：同色同字号，视觉上浅 30%）。
  //   这里对覆盖率做一次 <1 的幂，把中间调往深里压 —— 边缘仍平滑，
  //   但竖笔的芯变实了。指数越大越粗。
  //
  //   ⚠️ 0.72 是**配合双线性采样**调出来的；v86 把图集改成
  //   `GL_NEAREST` + 整像素对齐之后，同一指数会明显过粗（实测墨量 +24%，
  //   相邻字母会**粘在一起**）⇒ 改回 0.85。**改采样方式必须同时复核这个数**。
  m = pow(m, 0.85);
  float a = m * vCol.a;
  fragColor = vec4(vCol.rgb * a, a);
}
)";
    }

    bool EnsureGl(GlFuncs& g, int w, int h)
    {
        if (pText_ && texAtlas_) {
            return !glFailed_;
        }
        if (glFailed_) {
            return false;
        }
        g_ = &g;
        pSolid_ = MakeProgram(g, SolidVS(), SolidFS());
        pIcon_ = MakeProgram(g, IconVS(), IconFS());
        pText_ = MakeProgram(g, TextVS(), TextFS());
        if (!pSolid_ || !pIcon_ || !pText_) {
            glFailed_ = true;
            OutputDebugStringA("[scene] 着色器编译失败，回落到 GDI 重放\n");
            return false;
        }
        SetupVao(g, vaoSolid_, vboSolid_, sizeof(SceneSolidV), 5,
                 kSolidLayout);
        SetupVao(g, vaoIcon_, vboIcon_, sizeof(SceneIconV), 4,
                 kIconLayout);
        SetupVao(g, vaoText_, vboText_, sizeof(SceneTextV), 3,
                 kTextLayout);

        glGenTextures(1, &texAtlas_);
        glBindTexture(GL_TEXTURE_2D, texAtlas_);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, kAtlasSize, kAtlasSize, 0,
                     GL_RED, GL_UNSIGNED_BYTE, nullptr);
        // ★★ v86：**GL_NEAREST**，不是 GL_LINEAR。
        //
        //   字形图集本身就是**按目标字号栅格化好的**（1 texel = 1 设备像素），
        //   顶点又已经对齐到整像素 ⇒ 这里做双线性只会"抄到隔壁 texel"：
        //   每个字母左右各糊 1px、淡边被 `pow` 放大成实墨，结果相邻字母粘成
        //   一团（实测标题 "R3ShieldCore" 里 3/S/h 三段墨连在一起，墨量 +24%）。
        //   最近邻 + 整像素 = 与 GDI 逐像素一致，这才是我们要的。
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        // 图集整张都算"脏"，第一帧全量上传
        MarkDirty(0, 0, kAtlasSize, kAtlasSize);
        atlasDirty_ = true;
        (void)w; (void)h;
        return true;
    }

    // 顶点布局：[{count, offset}, ...]
    struct AttrDef { int count; int offset; };
    static const AttrDef kSolidLayout[5];
    static const AttrDef kIconLayout[4];
    static const AttrDef kTextLayout[3];

    static void SetupVao(GlFuncs& g, GLuint& vao, GLuint& vbo, int stride,
                         int attrCount, const AttrDef* attrs)
    {
        g.GenVertexArrays(1, &vao);
        g.BindVertexArray(vao);
        g.GenBuffers(1, &vbo);
        g.BindBuffer(GL_ARRAY_BUFFER, vbo);
        for (int i = 0; i < attrCount; ++i) {
            g.EnableVertexAttribArray((GLuint)i);
            g.VertexAttribPointer((GLuint)i, attrs[i].count, GL_FLOAT, GL_FALSE,
                                  stride, (const void*)(size_t)attrs[i].offset);
        }
        g.BindVertexArray(0);
    }

    GLuint MakeProgram(GlFuncs& g, const char* vs, const char* fs)
    {
        GLuint v = g.CreateShader(GL_VERTEX_SHADER);
        if (!v) return 0;
        g.ShaderSource(v, 1, &vs, nullptr);
        g.CompileShader(v);
        GLint ok = 0;
        g.GetShaderiv(v, GL_COMPILE_STATUS, &ok);
        if (!ok) {
            char log[1024] = {};
            g.GetShaderInfoLog(v, sizeof(log), nullptr, log);
            OutputDebugStringA(log);
            printf("[scene] shader log: %s\n", log); fflush(stdout);
            g.DeleteShader(v);
            return 0;
        }
        GLuint f = g.CreateShader(GL_FRAGMENT_SHADER);
        if (!f) { g.DeleteShader(v); return 0; }
        g.ShaderSource(f, 1, &fs, nullptr);
        g.CompileShader(f);
        g.GetShaderiv(f, GL_COMPILE_STATUS, &ok);
        if (!ok) {
            char log[1024] = {};
            g.GetShaderInfoLog(f, sizeof(log), nullptr, log);
            OutputDebugStringA(log);
            printf("[scene] shader log: %s\n", log); fflush(stdout);
            g.DeleteShader(v);
            g.DeleteShader(f);
            return 0;
        }
        GLuint p = g.CreateProgram();
        g.AttachShader(p, v);
        g.AttachShader(p, f);
        g.LinkProgram(p);
        g.DeleteShader(v);
        g.DeleteShader(f);
        GLint lok = 0;
        g.GetProgramiv(p, GL_LINK_STATUS, &lok);
        if (!lok) {
            g.DeleteProgram(p);
            return 0;
        }
        return p;
    }

    void UploadAtlas(GlFuncs& g)
    {
        (void)g;
        if (!texAtlas_) {
            return;
        }
        if (!atlasDirty_ || atlas_.empty()) {
            return;
        }
        glBindTexture(GL_TEXTURE_2D, texAtlas_);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
        const int x0 = dirtyX0_ < 0 ? 0 : dirtyX0_;
        const int y0 = dirtyY0_ < 0 ? 0 : dirtyY0_;
        const int x1 = dirtyX1_ > kAtlasSize ? kAtlasSize : dirtyX1_;
        const int y1 = dirtyY1_ > kAtlasSize ? kAtlasSize : dirtyY1_;
        if (x1 > x0 && y1 > y0) {
            // ★ 必须**逐行**上传：glTexSubImage2D 把传入指针当作"紧密排列"的
            //   行首（行距 = width），而我们的图集行距是 kAtlasSize。
            //   直接传整块会把每行往后错 kAtlasSize 字节 —— 症状是文字斜切成
            //   一片噪点，而 GL 不报任何错。
            for (int y = y0; y < y1; ++y) {
                glTexSubImage2D(GL_TEXTURE_2D, 0, x0, y, x1 - x0, 1,
                                GL_RED, GL_UNSIGNED_BYTE,
                                atlas_.data() + (size_t)y * kAtlasSize + x0);
            }
        }
        glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
        atlasDirty_ = false;
    }
};

// 静态成员定义（header-only：inline 变量）
inline const Scene::AttrDef Scene::kSolidLayout[5] = {
    { 2, 0 }, { 2, 8 }, { 2, 16 }, { 1, 24 }, { 4, 28 }
};
inline const Scene::AttrDef Scene::kIconLayout[4] = {
    { 2, 0 }, { 2, 8 }, { 1, 16 }, { 4, 20 }
};
inline const Scene::AttrDef Scene::kTextLayout[3] = {
    { 2, 0 }, { 2, 8 }, { 4, 16 }
};

} // namespace R3ShieldCoreUi
