#pragma once
//
// ui_controls.h —— 液态玻璃**控件原语**（两个 exe 共用，铁律 127）
//
// 出处：参考项目 `LiquidGlassControls`（原生 C++ / OpenGL 3.3 + GLFW/GLEW/glm）。
//
// ★★★ 只借**视觉模型**，不借渲染栈：
//   · 材质/合成 —— 仍然走 `ui_material.h`（CPU）或 `ui_gl.h`（着色器）。
//     参考项目那套 GLASS_FS 我们 v83/v84 已经搬完了，这里不再碰。
//   · 内容（文字/字形）—— 仍然走 **GDI**。参考项目自带 stb_truetype 和
//     一张 512x512 的 ASCII 图集；我们这边有 ClearType（次像素抗锯齿）
//     和完整的中文字体，自绘反而是退化。
//   · 参考项目靠"弹簧 + 每帧重绘"做手感；本项目 v93 起也用**同一组弹簧参数**
//     （见 ui_anim.h），但**不常驻 60fps**：有交互才起 16ms 定时器，
//     全部弹簧收敛后定时器自己停 ⇒ 动画过程逐帧一致，静止时 CPU 为 0。
//     （v92 及之前是纯事件驱动的 normal/hover/press 三态，手感是"跳"的。）
//
// ★★ 这一层解决的到底是什么问题：
//   v84 的界面之所以"白色卡片一叠"，根本原因不是材质写错了，而是
//   **材质只有一种颜色**（掺白）。参考项目同一套材质能做出
//     蓝玻璃主按钮 / 红玻璃危险按钮 / 灰玻璃凹槽 / 纯白滑块 / 奶白卡片,
//   全靠 `uTintCol` 这个参数（见 ui_material.h 里 PanelRec::cr/cg/cb）。
//   所以这里的每个控件 = "一块带颜色的玻璃 + 一点字形"，没有第二套画法。
//
// ★ 兜底：本头**假定玻璃层是活的**（`Surface::On()`）。玻璃不可用时
//   调用方走各页原有的不透明绘制路径（`g_glass.active` 分支），
//   这里不做第二套实色画法 —— 两套并存必然漂移。
//
#include <windows.h>

#include "ui_material.h"

namespace R3ShieldCoreUi {
namespace UiCtl {

// ★ 代次标记（v85）：发布闸门查"控件库真的编进了 exe"。
inline constexpr wchar_t kMarker[] = L"R3ShieldCoreUiCtl.v85";

// ---------------------------------------------------------------------------
// 语义色（0..1，与参考项目同名同值）
// ---------------------------------------------------------------------------
// 参考项目用的是**线性系数**（glUniform3f 直接吃 0..1），GDI 要 0..255，
// 所以统一在这里定义一次、由 ToColor / C8 转换 —— 不要在两处各写一遍字节值。
struct Tone {
    float r, g, b;
};

inline constexpr Tone Ink    { 0.086f, 0.094f, 0.125f };  // 主文字（近黑，带一点冷）
inline constexpr Tone Dim    { 0.200f, 0.220f, 0.280f };  // 次要文字 / 卡片标题
inline constexpr Tone Faint  { 0.360f, 0.380f, 0.450f };  // 最弱文字 / 未选中项
inline constexpr Tone Blue   { 0.090f, 0.400f, 0.860f };  // 强调 / 主按钮
inline constexpr Tone Red    { 0.840f, 0.220f, 0.220f };  // 危险
inline constexpr Tone Green  { 0.130f, 0.660f, 0.420f };  // 放行 / 健康
inline constexpr Tone Amber  { 0.900f, 0.520f, 0.130f };  // 拟拦截 / 警告
inline constexpr Tone Violet { 0.520f, 0.240f, 0.760f };  // 替换（spoof）
// ★ v85 实测：Sunken 一开始用的是参考项目的 (0.72,0.735,0.79)。在本项目的
//   浅色背景下，这个值再掺 0.5 就跟卡片几乎同色 —— 开关"关"和"开"看起来
//   只差一个蓝色，凹槽也看不出凹。整体压暗一档才立得住。
inline constexpr Tone Sunken   { 0.720f, 0.735f, 0.790f };  // 凹槽 / 未激活轨道
inline constexpr Tone Raised   { 0.855f, 0.870f, 0.920f };  // 轻凸起（次按钮）
// ★ 名字带 Tone 后缀：下面有个同名函数 `Card()`（画卡片）。
//   C++ 里**变量和函数不能同名**，而两个名字都该这么叫 —— 折中在这边加后缀。
// ★ v87：卡片必须**比背景亮**（参考项目实测：卡片 231~234 / 缝 225）。
//   原来 0.900 比背景（约 236）暗，卡片读成"灰板"，缝反而被白光照得比卡片还亮 ——
//   层级整个反了，所以怎么调都"浮不起来"。
inline constexpr Tone CardTone { 0.945f, 0.952f, 0.972f };  // 卡片（奶白，比背景亮一档）
inline constexpr Tone Pure     { 1.000f, 1.000f, 1.000f };  // 纯白（滑块 / 圆头）

inline BYTE C8(float v)
{
    if (v <= 0.0f) {
        return 0;
    }
    if (v >= 1.0f) {
        return 255;
    }
    return static_cast<BYTE>(v * 255.0f + 0.5f);
}

inline COLORREF ToColor(const Tone& t)
{
    return RGB(C8(t.r), C8(t.g), C8(t.b));
}

inline Tone Mix(const Tone& a, const Tone& b, float k)
{
    k = Clampf(k, 0.0f, 1.0f);
    return Tone{ a.r + (b.r - a.r) * k, a.g + (b.g - a.g) * k, a.b + (b.b - a.b) * k };
}

// 已有的 GDI 语义色（COLORREF）→ Tone。
// 让上层可以继续用那 20 多个来源标记色，不必为此重写成 Tone。
inline Tone FromColor(COLORREF c)
{
    return Tone{ static_cast<float>(GetRValue(c)) / 255.0f,
                 static_cast<float>(GetGValue(c)) / 255.0f,
                 static_cast<float>(GetBValue(c)) / 255.0f };
}

// ---------------------------------------------------------------------------
// Surface —— "往哪画"三件套（HDC / 玻璃层 / dpi）打包，调用点短一点
// ---------------------------------------------------------------------------
struct Surface {
    HDC dc = nullptr;
    GlassSurface* g = nullptr;
    float dpi = 1.0f;

    bool On() const { return g != nullptr && g->active; }
};

// 面板种类（与 PanelRec::kind 同义）
enum Kind {
    KCard = 0,   // 大块面板：边缘折射 + 大投影
    KPiece = 1,  // 玻璃片：轻微折射 + 小投影（按钮/页签/圆头）
    KWell = 2,   // 凹槽：更暗、折射极小、**不投外投影**（轨道/进度条底）
};

// 登记一块玻璃。`radius` 是**最终像素值**（要不要乘 dpi 由调用方决定 ——
// 布局坐标本身是像素，圆角在有的地方要跟 dpi、有的地方就是"半高"）。
inline void Piece(Surface& s, int x0, int y0, int x1, int y1,
                  float radius, float tint, const Tone& col, int kind)
{
    if (!s.On() || x1 <= x0 || y1 <= y0) {
        return;
    }
    tint = Clampf(tint, 0.0f, 0.97f);
    s.g->AddPanel(x0, y0, x1, y1, radius, tint, kind, C8(col.r), C8(col.g), C8(col.b));
}

inline void PieceR(Surface& s, const RECT& r, float radius, float tint,
                   const Tone& col, int kind)
{
    Piece(s, r.left, r.top, r.right, r.bottom, radius, tint, col, kind);
}

// ---------------------------------------------------------------------------
// 卡片
// ---------------------------------------------------------------------------
// 参考项目 CARD_R = 40（1280 宽窗口、三列、列宽 ~396）。这边窗口 1024、
// 卡片宽 ~470，按比例给 24 —— 40 在这个尺寸上会把内容挤成一小坨。
// tint 0.34：参考项目 `LiquidGlassControls` 的卡片是 0.12 —— 玻璃底下能看见
// 桌面的颜色和结构。我们原来是 0.58，那已经不是玻璃，是一块奶白板：
// 掺白过半之后，背后的窗口再怎么动，卡片也只是"白里透一点点色"。
// 0.34 是折中：桌面透得出来（配合背景抬阴影，墨字仍然站得住），
// 又不至于像参考项目那样只留 12%（那是深色界面的配方，白字靠暗背景立住）。
inline float CardRadius(const Surface& s) { return 24.0f * s.dpi; }

inline void Card(Surface& s, const RECT& r, float tint = 0.44f)
{
    PieceR(s, r, CardRadius(s), tint, CardTone, KCard);
}

// ---------------------------------------------------------------------------
// 药丸按钮
// ---------------------------------------------------------------------------
// 三种语义，区别**只在 tint 颜色**上 —— 这正是参考项目的做法：
//   · Primary：掺蓝 0.88，白字（"继续 / 切换模式"这种主动作）
//   · Danger ：掺红 0.86，白字（"退出引擎"这种破坏性动作）
//   · Glass  ：掺白 0.60，墨色字（其余中性动作）
enum class Btn {
    Glass,
    Primary,
    Danger,
};

// 通用版：任意色相的胶囊玻璃。
// 需要它是因为头部的「超级置顶」用的是**橙色**强调（表示"已回退到普通置顶"），
// 而固定三档表达不了 —— 语义色的唯一来源应该在上层，这里只负责掺色。
//
// ★ v93：hover / press 从 bool 改成 **float 0..1**（逐帧动画的中间值）。
//   bool 传进来会自动转成 0.0f / 1.0f，所以老调用点一个字都不用改。
//   按下缩 2.8%：参考项目 `drawBtn` 里 `s = 1.0f - c.press.v * 0.028f`。
inline void PillTone(Surface& s, const RECT& rIn, const Tone& col, float tint,
                     float hover = 0.0f, float press = 0.0f)
{
    tint += 0.05f * hover + 0.05f * press;

    RECT r = rIn;
    if (press > 0.0001f) {
        const float k = 1.0f - 0.028f * Clampf(press, 0.0f, 1.0f);
        const float cx = (r.left + r.right) * 0.5f;
        const float cy = (r.top + r.bottom) * 0.5f;
        const float hw = (r.right - r.left) * 0.5f * k;
        const float hh = (r.bottom - r.top) * 0.5f * k;
        r.left = static_cast<LONG>(cx - hw + 0.5f);
        r.top = static_cast<LONG>(cy - hh + 0.5f);
        r.right = static_cast<LONG>(cx + hw + 0.5f);
        r.bottom = static_cast<LONG>(cy + hh + 0.5f);
    }

    const float radius = static_cast<float>(r.bottom - r.top) * 0.5f;
    PieceR(s, r, radius, tint, col, KPiece);
}

inline void Pill(Surface& s, const RECT& r, Btn kind, float hover = 0.0f, float press = 0.0f)
{
    switch (kind) {
    case Btn::Primary: PillTone(s, r, Blue, 0.88f, hover, press); break;
    case Btn::Danger:  PillTone(s, r, Red, 0.86f, hover, press); break;
    default:           PillTone(s, r, Raised, 0.60f, hover, press); break;
    }
}

inline COLORREF PillText(Btn kind)
{
    return (kind == Btn::Glass) ? ToColor(Ink) : RGB(255, 255, 255);
}

// ---------------------------------------------------------------------------
// 开关（Switch）
// ---------------------------------------------------------------------------
// 尺寸按本项目的"配置行"给（行距 27px，开关 40x22 放进去上下各余 2.5px）。
// 参考项目是 48x28（它的行距 54），照抄会把这个界面撑开。
inline constexpr int SwitchW = 40;
inline constexpr int SwitchH = 22;

// `right` = 轨道右边缘；`cy` = 轨道中心 y。
//
// ★ v93：`v` 是**动画中间值**（0..1），不是布尔。
//   参考项目里开关是 `Spring v` 驱动的：轨道颜色 `mix(C_SUNK, C_BLUE, v)`、
//   圆头位置 `lerp(-(hw-hh), (hw-hh), v)` —— 所以按下去的瞬间不是"跳过去"，
//   而是滑过去并略微过冲。这两件事必须一起做，只动位置不动颜色会很假。
inline void SwitchV(Surface& s, int right, int cy, float v, float hover = 0.0f)
{
    v = Clampf(v, 0.0f, 1.0f);

    const int x0 = right - SwitchW;
    const int y0 = cy - SwitchH / 2;
    const int x1 = right;
    const int y1 = cy + SwitchH / 2;
    const float radius = SwitchH * 0.5f;

    // 色相插值：关 = 灰轨道，开 = 蓝轨道。掺色量同时从 0.74 走到 0.86
    // （参考项目是 0.46 → 0.74；我们这边因为浅色背景整体压得更实）。
    const Tone rail = Mix(Sunken, Blue, v);
    const float tint = 0.74f + 0.12f * v + 0.06f * Clampf(hover, 0.0f, 1.0f);
    Piece(s, x0, y0, x1, y1, radius, tint, rail, KPiece);

    // 圆头：直径 18、四周留 3px。行程 = SwitchW - 6 - knob。
    const int knob = SwitchH - 6;
    const int ky = cy - knob / 2;
    const float travel = static_cast<float>(SwitchW - 6 - knob);
    const float kxf = static_cast<float>(x0 + 3) + travel * v;
    // +0.5 四舍五入：截断会让慢速段出现"走一像素停一帧"的顿感。
    const int kx = static_cast<int>(kxf + 0.5f);
    Piece(s, kx, ky, kx + knob, ky + knob, knob * 0.5f, 0.94f, Pure, KPiece);
}

inline void Switch(Surface& s, int right, int cy, bool on, bool hover = false)
{
    SwitchV(s, right, cy, on ? 1.0f : 0.0f, hover ? 1.0f : 0.0f);
}

// ---------------------------------------------------------------------------
// 分段控件（页签栏用它）
// ---------------------------------------------------------------------------
// 参考项目：一个整体凹槽 + 一块白色滑块 + N 段文字。
// 比"每个页签各自一块玻璃"清楚得多 —— 后者在没有选中项时像一排散落的胶囊。
inline void SegmentTrough(Surface& s, const RECT& r)
{
    const float radius = static_cast<float>(r.bottom - r.top) * 0.5f;
    PieceR(s, r, radius, 0.55f, Sunken, KWell);
}

// `thumb` 是滑块矩形（调用方按当前选中段算好，内缩 4px）。
inline void SegmentThumb(Surface& s, const RECT& thumb)
{
    const float radius = static_cast<float>(thumb.bottom - thumb.top) * 0.5f;
    PieceR(s, thumb, radius, 0.93f, Pure, KPiece);
}

inline COLORREF SegmentText(bool active)
{
    return active ? ToColor(Ink) : ToColor(Faint);
}

// ---------------------------------------------------------------------------
// 进度条 / 柱状条
// ---------------------------------------------------------------------------
// 轨道 = 凹槽（不投投影），填充 = 同形状的有色玻璃片。
// ★ 填充也用 KWell：它嵌在槽里，投外投影会让条形看起来"浮在槽上方"。
inline void Bar(Surface& s, int x, int y, int w, int h, float frac, const Tone& fill)
{
    if (w <= 0 || h <= 0) {
        return;
    }
    const float radius = static_cast<float>(h) * 0.5f;
    Piece(s, x, y, x + w, y + h, radius, 0.62f, Sunken, KWell);

    frac = Clampf(frac, 0.0f, 1.0f);
    if (frac <= 0.0f) {
        return;
    }
    int filled = static_cast<int>(static_cast<float>(w) * frac + 0.5f);
    if (filled < 2) {
        filled = 2;      // 非零值至少露一点，表示"有"
    }
    if (filled > w) {
        filled = w;
    }
    Piece(s, x, y, x + filled, y + h, radius, 0.82f, fill, KWell);
}

// ---------------------------------------------------------------------------
// 徽章 / 状态胶囊（头部那些小标签）
// ---------------------------------------------------------------------------
inline void Badge(Surface& s, const RECT& r, const Tone& col, float tint = 0.80f)
{
    const float radius = static_cast<float>(r.bottom - r.top) * 0.5f;
    PieceR(s, r, radius, tint, col, KPiece);
}

// ---------------------------------------------------------------------------
// 图标按钮（圆形玻璃 + 字形）
// ---------------------------------------------------------------------------
// 参考项目用 SDF 现算 14 个图标；我们这边图标很少（就几个），
// 用字体里的字符（✕ ⚙ ⇅）更省事，也不额外占一个 draw call。
inline void IconCircle(Surface& s, int cx, int cy, int radius, bool hover = false)
{
    Piece(s, cx - radius, cy - radius, cx + radius, cy + radius,
          static_cast<float>(radius), hover ? 0.72f : 0.58f, Raised, KPiece);
}

} // namespace UiCtl
} // namespace R3ShieldCoreUi
