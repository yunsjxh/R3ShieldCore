#pragma once
//
// ui_material.h —— 液态玻璃材质 + 背景模糊（绘制侧**唯一实现**，铁律 127）
//
// 谁在用：
//   · 主程序 `R3ShieldCore/R3ShieldCore/r3shieldcore_gui.cpp`
//   · 配置工具 `tools/r3shieldcore_cfg.cpp`
//   两边共用这一份，**不要各写一份** —— 各写一份的后果是材质参数慢慢分叉，
//   而且不报错（同 tray_icon.h / cfg_ipc.h 的理由）。
//
// 视觉模型来自 `LiquidGlassNative`（OpenGL 着色器）的 GLASS_FS，逐条移植到 CPU：
//   ① 背景：窗口后方真实屏幕内容（捕获），玻璃内部用**模糊版**
//   ② 圆角 SDF：面板形状的唯一真源（画/命中/投影共用同一个函数）
//   ③ 折射：越靠近边缘偏折越大（`(1-t)^2.2`，带宽 ~9px）
//   ④ 色散：折射处 R/B 通道分离（只在最外 2~3px 可见）
//   ⑤ 磨砂：轻微去饱和 + 提亮
//   ⑥ 染色：白 tint（常态 0.13 / 按下 0.25）
//   ⑦ rim 高光：内侧 1~3px 亮边（`exp(sd/2.6)`）
//   ⑧ 顶部镜面光带：面板上缘 1px 亮线
//   ⑨ 噪点：极细静态颗粒（消除色带、给材质感）
//   ⑩ 投影：向下偏移的柔和阴影
//
// ★★ 为什么是 CPU 而不是 D2D/OpenGL：
//   本项目是纯 GDI 自绘 + 无第三方运行时依赖的安全工具。引 OpenGL(GLFW/GLEW/glm)
//   或 D3D11 都会给"要能跑在别人机器上"增加风险；而这块只做一次离屏合成、
//   结果缓存起来复用（内容滚动不复算玻璃），CPU 完全够（实测见 docs/）。
//
// ★★ 为什么"背景透明"是**假的**（重要，别被后面的代码误导）：
//   Win32 普通窗口里 GDI 画不出逐像素 alpha；`WS_EX_LAYERED` 又会让原生子控件
//   （cfg 的 EDIT/下拉框）失效。所以我们做的是"**把窗口后方的内容抓下来、
//   模糊后当不透明底画上去**" —— 视觉上是透明的玻璃，实现上是不透明像素。
//   好处：子控件照常工作、没有每帧合成成本、不依赖 DWM 版本。
//   代价：后方内容是**快照**（移动/定时器刷新），不是逐帧实时。
//   真正逐像素透明的唯一路径是 ULW 分层窗口，会牺牲原生控件（见预研 §5.3）。
//
#include <windows.h>
#include <dwmapi.h>
#include <math.h>

#if defined(_MSC_VER)
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#endif

#ifndef R3SC_UI_MATERIAL_H
#define R3SC_UI_MATERIAL_H

namespace R3ShieldCoreUi {

// ★★ 代次标记（v83）：给发布闸门 `check_dist_sync.sh` 查"这套材质代码真编进了 exe"。
//   必须是**宽串** —— `printf` 里的中文是窄 GBK 字节，`strings -el` 查不到（v82 踩过）。
inline constexpr wchar_t kGenerationMarker[] = L"R3ShieldCoreGlass.v83";

// ---------------------------------------------------------------------------
// 材质参数（唯一真源）
// ---------------------------------------------------------------------------
//
// ★ 全部是**逻辑像素 / 0..1 系数**，实际绘制时乘 dpi（调用方传进来）。
//   不要在这里写死物理像素 —— 125%/150% 缩放下会整体偏小（v79 踩过同类）。
struct GlassTheme {
    // 面板圆角（逻辑 px）。与 DWM 窗口圆角分开：面板更圆一点更好看。
    float panelRadius        = 18.0f;
    // 小圆角（按钮/页签/chip）
    float smallRadius        = 10.0f;

    // 白 tint 强度（与着色器 uTint 同义）
    float tintIdle           = 0.140f;
    float tintHover          = 0.200f;
    float tintActive         = 0.260f;

    // 折射
    float bendPx             = 14.0f;   // 边缘最大偏移（全分辨率像素）
    float refractBand        = 9.0f;    // 衰减带宽：贴着边到深处的距离
    float chromatic          = 0.34f;   // R/B 分离系数（× bendP）
    float blurBlend          = 0.42f;   // 轻模糊 / 重模糊 的混合比

    // 磨砂
    // ★ v87：对齐参考项目（0.030 / 1.02）。0.10 的去饱和把背景的色相洗掉了，
    //   玻璃看起来是「灰玻璃」而不是「透出背景颜色的白玻璃」。
    float frostDesat         = 0.030f;  // 去饱和比例
    float frostGain          = 1.02f;   // 提亮

    // rim 高光（内侧亮边）
    // ★ v87：2.6 → 5.5（参考项目同值）。高光带太窄 = 一圈脏描边，见 GL 着色器注释。
    //   强度同步从 0.46 降到 0.34 —— 带子宽了 2 倍，不降就整块发白。
    float rimStrength        = 0.46f;
    float rimFalloff         = 5.5f;    // 越小越窄

    // 顶部镜面光带
    float specTopStrength    = 0.12f;

    // 噪点幅度（0..1，乘到 ±127.5）
    float noiseAmp           = 0.020f;

    // 投影
    // ★ v87：这组参数现在描述的是**白色光晕**，不再是黑色投影（见 ComposeGlassPanel）。
    float shadowOffsetY      = 3.0f;
    float shadowRadius       = 40.0f;
    float shadowAlpha        = 0.40f;

    // 背景"薄纱"：整幅背景压一层白，保证深色文字可读（0 = 完全不加）
    //   ★★ v85 起默认 **0**。理由见 GradeBackdropImage 的注释：
    //   往白里掺是"提亮"，会把背景洗成一张白纸，玻璃就只剩"白卡片"一种可能。
    //   现在改成"压暗 + 冷调 + 暗角"（参考项目 BG_FS 的做法）。
    float veil               = 0.00f;
    // 背景冷色化：往这个色偏一点，让桌面壁纸不至于是花花绿绿的照片
    BYTE  veilTintB          = 253;
    BYTE  veilTintG          = 252;
    BYTE  veilTintR          = 250;

    // ---- v85 背景调色（唯一一组常数，CPU 在 GradeBackdropImage 里用）----
    // 高光压缩拐点：lc = l / (1 + l*k)。白色桌面 (l=1) 会被压到 1/(1+k)。
    //   0.34 ⇒ 纯白 → 0.75（≈190）。不压的话，白底网页面前玻璃全是白的。
    //   ★ 别调回 0.2 以下：实测 0.28 时卡片和背景的明度差只有 ~10 个灰阶，
    //     卡片"浮不起来"，整页看起来像一张灰纸（v85 第一次出图就是这样）。
    // ★ v87：0.34 → 0.10。用户明确要求「别降亮度」：0.34 会把 240 压到 180，
    //   整窗发灰。0.10 只削掉最亮的一点（255→232），保留桌面的原亮度。
    // ★ v88：0.10 → 0.16。0.10 时纯白桌面 (255) 只掉到 232，卡片 tint 0.56
    //   掺白后是 243 —— 两者同色，玻璃的 rim/投影/折射全落在白上，等于没画。
    //   0.16 把 255 压到 220（参考项目是 0.22 ⇒ 209），仍属"几乎不压"，
    //   但已经足够让卡片浮起来。别超过 0.22：再往上整窗就发灰了。
    float dimKnee            = 0.10f;
    // 冷调：整体往 (gradeR/G/B) 掺 gradeMix。参考项目是 0.06。
    float gradeMix           = 0.06f;
    BYTE  gradeR             = 245;
    BYTE  gradeG             = 248;
    BYTE  gradeB             = 252;
    // ★★★ v89：抬阴影。**这是"透视真桌面"之后必须补的一步**。
    //
    //   参考项目是深色界面（白字），所以它只要压高光（`l/(1+l*0.22)`），
    //   桌面越暗字越清楚。我们是**浅色界面**（墨字 24,24,24），情况正好相反：
    //   桌面上任何一块深色（深色壁纸、终端窗口、视频）透进来，墨字就直接消失。
    //
    //   做法：把亮度整体压进 [lift, 1] 这一段 —— 纯黑抬到 0.55（≈140），
    //   白色不动。**等比缩放三个通道**，所以色相不变，只改明度，
    //   桌面还是能认出来（结构/颜色都在，只是不会黑到吃掉文字）。
    //
    //   别调到 0.75 以上：那样整块背景会被压平，玻璃后面变成一张灰纸，
    //   "透视真实窗口"就白做了（用户会立刻看出是假背景）。
    float shadowLift         = 0.00f;
    // ★★★ v89：背景**去饱和**。
    //
    //   为什么必须有：玻璃底下现在是**真桌面**，什么颜色都可能出现
    //   （壁纸、视频、彩色网页）。参考项目敢只留 0.05 去饱和，是因为
    //   它底下是一张浅色网页；而且它是**深色界面**（白字），颜色越艳越好看。
    //   我们是浅色界面、墨字、还有 12px 的小字 —— 一块纯品红透进来，
    //   字就没了。去饱和之后它变成"淡粉的一团"，既认得出是那个窗口，
    //   又不跟界面里的语义色（蓝/红/紫）打架。
    //
    //   别超过 0.7：再往上就退化成灰度图，用户会立刻看出"这不是我桌面"。
    float gradeDesat          = 0.05f;
    // 暗角：中心 bright，边缘 dark（乘数，1.0 = 不变）。
    float vigEdge            = 0.98f;
    float vigCenter          = 1.02f;
};

inline const GlassTheme& DefaultTheme()
{
    static const GlassTheme theme;
    return theme;
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
inline float Clampf(float v, float a, float b) { return v < a ? a : (v > b ? b : v); }

// 整数"哈希噪点"：着色器 hash21 的整数版（快、无浮点三角函数）。
inline float Hash21(int x, int y)
{
    unsigned n = static_cast<unsigned>(x) * 374761393u
               + static_cast<unsigned>(y) * 668265263u;
    n = (n ^ (n >> 13)) * 1274126177u;
    n ^= n >> 16;
    return static_cast<float>(n & 0x00FFFFFFu) / 16777215.0f;
}

// 圆角矩形 SDF（与着色器 sdRoundBox 逐字对应）。
// 内部为负、边界为 0、外部为正。
inline float SdRoundBox(float px, float py, float bx, float by, float r)
{
    const float qx = fabsf(px) - bx + r;
    const float qy = fabsf(py) - by + r;
    const float mx = qx > 0.0f ? qx : 0.0f;
    const float my = qy > 0.0f ? qy : 0.0f;
    float m = qx > qy ? qx : qy;
    if (m > 0.0f) {
        m = 0.0f;
    }
    return m + sqrtf(mx * mx + my * my) - r;
}

// ---------------------------------------------------------------------------
// 32bpp top-down DIB（BGRA 内存序）—— 所有离屏绘制的载体
// ---------------------------------------------------------------------------
//
// ★ 为什么不用 `CreateCompatibleBitmap`：它给的是**设备相关**位图，取不到可靠的
//   像素指针（`GetDIBits` 要来回拷贝且 alpha 未定义）。玻璃合成要逐像素算，
//   必须有 `DIBSection` 的线性缓冲。
struct Dib32 {
    HBITMAP bitmap = nullptr;
    HDC     dc     = nullptr;   // 与 bitmap 绑定的内存 DC（画文字/图元用）
    BYTE*   bits   = nullptr;
    int     w      = 0;
    int     h      = 0;
    int     stride   = 0;       // = w * 4

    bool Create(HDC refDc, int width, int height)
    {
        Release();
        if (width <= 0 || height <= 0) {
            return false;
        }
        HDC screen = refDc ? refDc : GetDC(nullptr);
        if (!screen) {
            return false;
        }
        BITMAPINFO bi = {};
        bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth       = width;
        bi.bmiHeader.biHeight      = -height;   // 负 = top-down，行序与直觉一致
        bi.bmiHeader.biPlanes      = 1;
        bi.bmiHeader.biBitCount    = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        void* raw = nullptr;
        HBITMAP bmp = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &raw, nullptr, 0);
        // ★★ 内存 DC 必须在 `screen` 还有效的时候建 ——
        //   第一版把 `ReleaseDC(nullptr, screen)` 写在了这行**前面**，
        //   于是 `CreateCompatibleDC` 拿到一个已释放的 HDC、返回 NULL
        //   ⇒ 整个玻璃层建不起来、静默退回不透明路径，**没有任何报错**
        //   （只有"界面没变化"这一条线索）。
        HDC mem = (bmp && raw) ? CreateCompatibleDC(screen) : nullptr;
        if (!refDc) {
            ReleaseDC(nullptr, screen);
        }
        if (!bmp || !raw || !mem) {
            if (mem) DeleteDC(mem);
            if (bmp) DeleteObject(bmp);
            return false;
        }
        SelectObject(mem, bmp);
        bitmap = bmp;
        dc     = mem;
        bits   = static_cast<BYTE*>(raw);
        w      = width;
        h      = height;
        stride = width * 4;
        // ★ 初始化成全透明 —— 不初始化的话首帧会带未定义内存的随机色块。
        ZeroMemory(bits, static_cast<size_t>(stride) * static_cast<size_t>(height));
        return true;
    }

    void Release()
    {
        if (dc)     { DeleteDC(dc);          dc = nullptr; }
        if (bitmap) { DeleteObject(bitmap);  bitmap = nullptr; }
        bits = nullptr;
        w = h = stride = 0;
    }

    ~Dib32() { Release(); }
    Dib32() = default;
    Dib32(const Dib32&) = delete;
    Dib32& operator=(const Dib32&) = delete;

    BYTE* At(int x, int y) { return bits + static_cast<size_t>(y) * stride + x * 4; }
};

// ---------------------------------------------------------------------------
// 可分离 box blur（3 趟 ≈ 高斯）
// ---------------------------------------------------------------------------
//
// ★ 为什么 box 而不是真高斯：box 的滑动窗口是 O(n)（每像素一加一减），
//   3 趟就已经肉眼接近高斯；真高斯是 O(n*r)，1024×740 上差一个数量级。
inline void BoxBlurH(const BYTE* src, BYTE* dst, int w, int h, int r)
{
    if (r <= 0) {
        memcpy(dst, src, static_cast<size_t>(w) * h * 4);
        return;
    }
    const int denom = 2 * r + 1;
    for (int y = 0; y < h; ++y) {
        const BYTE* s = src + static_cast<size_t>(y) * w * 4;
        BYTE* d = dst + static_cast<size_t>(y) * w * 4;
        int sb = 0, sg = 0, sr = 0;
        for (int i = -r; i <= r; ++i) {
            int xi = i < 0 ? 0 : (i >= w ? w - 1 : i);
            sb += s[xi * 4 + 0]; sg += s[xi * 4 + 1]; sr += s[xi * 4 + 2];
        }
        for (int x = 0; x < w; ++x) {
            d[x * 4 + 0] = static_cast<BYTE>(sb / denom);
            d[x * 4 + 1] = static_cast<BYTE>(sg / denom);
            d[x * 4 + 2] = static_cast<BYTE>(sr / denom);
            d[x * 4 + 3] = 255;
            int xa = x - r;      if (xa < 0)     xa = 0;
            int xb = x + r + 1;  if (xb > w - 1) xb = w - 1;
            sb += s[xb * 4 + 0] - s[xa * 4 + 0];
            sg += s[xb * 4 + 1] - s[xa * 4 + 1];
            sr += s[xb * 4 + 2] - s[xa * 4 + 2];
        }
    }
}

inline void BoxBlurV(const BYTE* src, BYTE* dst, int w, int h, int r)
{
    if (r <= 0) {
        memcpy(dst, src, static_cast<size_t>(w) * h * 4);
        return;
    }
    const int denom = 2 * r + 1;
    const size_t rowBytes = static_cast<size_t>(w) * 4;
    for (int x = 0; x < w; ++x) {
        int sb = 0, sg = 0, sr = 0;
        for (int i = -r; i <= r; ++i) {
            int yi = i < 0 ? 0 : (i >= h ? h - 1 : i);
            const BYTE* s = src + static_cast<size_t>(yi) * rowBytes + x * 4;
            sb += s[0]; sg += s[1]; sr += s[2];
        }
        for (int y = 0; y < h; ++y) {
            BYTE* d = dst + static_cast<size_t>(y) * rowBytes + x * 4;
            d[0] = static_cast<BYTE>(sb / denom);
            d[1] = static_cast<BYTE>(sg / denom);
            d[2] = static_cast<BYTE>(sr / denom);
            d[3] = 255;
            int ya = y - r;      if (ya < 0)     ya = 0;
            int yb = y + r + 1;  if (yb > h - 1) yb = h - 1;
            const BYTE* sa = src + static_cast<size_t>(ya) * rowBytes + x * 4;
            const BYTE* sbp = src + static_cast<size_t>(yb) * rowBytes + x * 4;
            sb += sbp[0] - sa[0];
            sg += sbp[1] - sa[1];
            sr += sbp[2] - sa[2];
        }
    }
}

// 原地多趟 box blur（需要一个同尺寸临时缓冲，由调用方复用避免反复分配）
inline void BoxBlur(BYTE* px, BYTE* tmp, int w, int h, int radius, int passes)
{
    for (int p = 0; p < passes; ++p) {
        BoxBlurH(px, tmp, w, h, radius);
        BoxBlurV(tmp, px, w, h, radius);
    }
}

// 三通道双线性采样（越界钳制）。
//
// ★ 一次取回三通道：玻璃合成里 99% 的像素三通道用的是**同一个**采样坐标，
//   拆成三次单通道调用等于把同样的 4 个地址读 3 遍（实测慢 2.5 倍）。
inline void BilinearRGB(const BYTE* px, int w, int h, float fx, float fy, float out[3])
{
    if (!px || w <= 0 || h <= 0) {
        out[0] = out[1] = out[2] = 0.0f;
        return;
    }
    fx -= 0.5f;
    fy -= 0.5f;
    int x0 = static_cast<int>(floorf(fx));
    int y0 = static_cast<int>(floorf(fy));
    const float tx = fx - static_cast<float>(x0);
    const float ty = fy - static_cast<float>(y0);
    int x1 = x0 + 1, y1 = y0 + 1;
    if (x0 < 0) x0 = 0; if (x0 > w - 1) x0 = w - 1;
    if (x1 < 0) x1 = 0; if (x1 > w - 1) x1 = w - 1;
    if (y0 < 0) y0 = 0; if (y0 > h - 1) y0 = h - 1;
    if (y1 < 0) y1 = 0; if (y1 > h - 1) y1 = h - 1;
    const BYTE* p00 = px + static_cast<size_t>(y0) * w * 4 + x0 * 4;
    const BYTE* p10 = px + static_cast<size_t>(y0) * w * 4 + x1 * 4;
    const BYTE* p01 = px + static_cast<size_t>(y1) * w * 4 + x0 * 4;
    const BYTE* p11 = px + static_cast<size_t>(y1) * w * 4 + x1 * 4;
    for (int c = 0; c < 3; ++c) {
        const float top = p00[c] + (p10[c] - p00[c]) * tx;
        const float bot = p01[c] + (p11[c] - p01[c]) * tx;
        out[c] = top + (bot - top) * ty;
    }
}

// 单通道双线性采样（越界钳制）。只累加需要的通道 —— 三通道都算会白做 3 倍活。
inline float BilinearCh(const BYTE* px, int w, int h, float fx, float fy, int ch)
{
    if (!px || w <= 0 || h <= 0) {
        return 0.0f;
    }
    fx -= 0.5f;
    fy -= 0.5f;
    int x0 = static_cast<int>(floorf(fx));
    int y0 = static_cast<int>(floorf(fy));
    const float tx = fx - static_cast<float>(x0);
    const float ty = fy - static_cast<float>(y0);
    int x1 = x0 + 1, y1 = y0 + 1;
    if (x0 < 0) x0 = 0; if (x0 > w - 1) x0 = w - 1;
    if (x1 < 0) x1 = 0; if (x1 > w - 1) x1 = w - 1;
    if (y0 < 0) y0 = 0; if (y0 > h - 1) y0 = h - 1;
    if (y1 < 0) y1 = 0; if (y1 > h - 1) y1 = h - 1;
    const BYTE* p00 = px + static_cast<size_t>(y0) * w * 4 + x0 * 4;
    const BYTE* p10 = px + static_cast<size_t>(y0) * w * 4 + x1 * 4;
    const BYTE* p01 = px + static_cast<size_t>(y1) * w * 4 + x0 * 4;
    const BYTE* p11 = px + static_cast<size_t>(y1) * w * 4 + x1 * 4;
    const float top = p00[ch] + (p10[ch] - p00[ch]) * tx;
    const float bot = p01[ch] + (p11[ch] - p01[ch]) * tx;
    return top + (bot - top) * ty;
}

// ---------------------------------------------------------------------------
// 背景：捕获 + 两级模糊
// ---------------------------------------------------------------------------
//
// `full`  = 全分辨率**原图**（面板外部直接用它 —— 这是"玻璃外面清楚、里面模糊"
//           的关键；只把背景整体模糊掉会失去通透感）
// `a`/`b` = 半分辨率的轻/重模糊版，玻璃内部按 blurBlend 混合采样
struct Backdrop {
    Dib32 full;
    Dib32 a;
    Dib32 b;
    int  w = 0;
    int  h = 0;
    // ★ 采样参考尺寸 = **抓到这张快照时**的窗口尺寸。
    //   玻璃层是按"当前窗口尺寸"的坐标去采样的，窗口一缩放两者就不一致；
    //   用 refW/refH 归一化之后，**一张快照可以用在任意尺寸**上（拉伸，糊的看不出来）。
    int  refW = 0;
    int  refH = 0;
    int  source = 0;    // 0=没有 1=屏幕捕获 2=兜底渐变 3=关闭
    bool valid = false;
    // ★ v86：快照代次。GL 后端靠它判断"背景有没有换"——没换就**跳过**
    //   上传 + 模糊链（那一段每帧要 3~5ms），模糊结果留在纹理里跨帧复用。
    //   内容层现在每帧都重画，不能再用"整层重建"来挡这一块开销。
    unsigned long long refreshStamp = 0;

    void Release()
    {
        full.Release();
        a.Release();
        b.Release();
        w = h = 0;
        refW = refH = 0;
        source = 0;
        valid = false;
    }

    // 当前窗口坐标 -> 模糊图坐标的缩放
    float ScaleX() const { return refW > 0 ? (float)a.w / (float)refW : 0.5f; }
    float ScaleY() const { return refH > 0 ? (float)a.h / (float)refH : 0.5f; }

    // ★ Dib32 既不可拷贝也不可移动（里面有 HBITMAP/HDC），所以"换一份背景"
    //   只能手工交换字段。写成成员函数，别在调用点散着写一遍。
    static void SwapDib(Dib32& x, Dib32& y)
    {
        HBITMAP b = x.bitmap; x.bitmap = y.bitmap; y.bitmap = b;
        HDC d = x.dc;         x.dc = y.dc;         y.dc = d;
        BYTE* p = x.bits;     x.bits = y.bits;     y.bits = p;
        int t = x.w; x.w = y.w; y.w = t;
        t = x.h;     x.h = y.h; y.h = t;
        t = x.stride; x.stride = y.stride; y.stride = t;
    }

    void SwapWith(Backdrop& o)
    {
        SwapDib(full, o.full);
        SwapDib(a, o.a);
        SwapDib(b, o.b);
        int t = w; w = o.w; o.w = t;
        t = h; h = o.h; o.h = t;
        t = refW; refW = o.refW; o.refW = t;
        t = refH; refH = o.refH; o.refH = t;
        t = source; source = o.source; o.source = t;
        const bool v = valid; valid = o.valid; o.valid = v;
    }
};

inline const wchar_t* BackdropSourceName(int source)
{
    switch (source) {
    case 1:  return L"屏幕捕获";
    case 2:  return L"内置背景";
    case 3:  return L"已关闭";
    default: return L"无";
    }
}

// 背景源：0=自动（抓到太素就换内置）1=只用屏幕 2=只用内置
//
// ★★★ 默认 **1（真桌面）**，不是自动 —— 这条改过一次，记清楚原因：
//   用户要的是「**背景模糊半透明**」，也就是"透过窗口看得到后面被模糊的东西"。
//   自动替换一旦触发，后面真实的内容就被换成了设计渐变 ⇒ 用户看到的是"一张
//   渐变图"，而不是"我的桌面被模糊了"。第一版默认自动，用户直接回"还是不对"。
//   ⇒ 真桌面是默认；内置背景只在**抓不到**（RDP/受保护内容/纯黑）时兜底，
//     想强制用内置再设 `R3SHIELDCORE_GLASS_BG=builtin`。
inline int BackdropMode()
{
    static int mode = -1;
    if (mode >= 0) {
        return mode;
    }
    mode = 1;   // 默认：真桌面捕获
    wchar_t v[16] = {};
    const DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_BG", v, 16);
    if (n > 0 && n < 16 && v[0]) {
        if (_wcsicmp(v, L"desktop") == 0 || _wcsicmp(v, L"screen") == 0) { mode = 1; }
        else if (_wcsicmp(v, L"builtin") == 0 || _wcsicmp(v, L"designed") == 0) { mode = 2; }
        else if (_wcsicmp(v, L"auto") == 0) { mode = 0; }
    }
    return mode;
}

// 2x2 平均降采样（比 StretchBlt 可控，且不需要 HALFTONE 模式）
inline void Downsample2(const BYTE* src, int sw, int sh, BYTE* dst, int dw, int dh)
{
    for (int y = 0; y < dh; ++y) {
        const int y0 = y * 2;
        const int y1 = (y * 2 + 1 < sh) ? y * 2 + 1 : sh - 1;
        const BYTE* r0 = src + static_cast<size_t>(y0) * sw * 4;
        const BYTE* r1 = src + static_cast<size_t>(y1) * sw * 4;
        BYTE* d = dst + static_cast<size_t>(y) * dw * 4;
        for (int x = 0; x < dw; ++x) {
            const int x0 = x * 2;
            const int x1 = (x * 2 + 1 < sw) ? x * 2 + 1 : sw - 1;
            const BYTE* p00 = r0 + x0 * 4; const BYTE* p10 = r0 + x1 * 4;
            const BYTE* p01 = r1 + x0 * 4; const BYTE* p11 = r1 + x1 * 4;
            d[x * 4 + 0] = static_cast<BYTE>((p00[0] + p10[0] + p01[0] + p11[0]) >> 2);
            d[x * 4 + 1] = static_cast<BYTE>((p00[1] + p10[1] + p01[1] + p11[1]) >> 2);
            d[x * 4 + 2] = static_cast<BYTE>((p00[2] + p10[2] + p01[2] + p11[2]) >> 2);
            d[x * 4 + 3] = 255;
        }
    }
}

// 从屏幕抓一块（`excludeHwnd` 用 WDA_EXCLUDEFROMCAPTURE 把自己剔出去）
//
// ★★ 为什么要剔自己：主程序是 WS_EX_TOPMOST（安全控制台语义），
//   不剔的话抓到的就是**我们自己的上一帧** —— 拖动时越拖越糊（真实踩过的坑）。
// ★ WDA_EXCLUDEFROMCAPTURE = 0x11（Win10 2004+）。失败不致命：退回"带着自己"，
//   视觉上只是拖动时糊一点，不会崩。
// ★★ 必须**抓完立刻恢复** WDA_NONE：不恢复的话本窗口对**所有**截图工具不可见，
//   我们自己的 `gui_preview_probe`（屏幕 DC BitBlt）会截到"背后"而不是界面 ⇒ 全部假绿。
// 等 DWM 完成一次合成。
//
// ★ 为什么要它：`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` 的排除
//   是 DWM 在**下一次合成**时才生效的。原来这里盲 `Sleep(90)` —— 慢 5 倍，
//   而且窗口每 150ms 抓一次的话，90ms 里有 60% 的时间窗口是"隐身"的
//   （用户这时截图会截到一个洞）。
//   `DwmFlush()` 正好等"下一次合成完成"，约一帧（16ms）。
//   ★ 动态取地址而不是直接调：本头被 gui / cfg 两个目标共用，
//     不想为一个调用点给 cfg 也加 dwmapi.lib。
inline void WaitForComposition()
{
    using Fn = HRESULT(WINAPI*)();
    static Fn fn = []() -> Fn {
        HMODULE dll = LoadLibraryW(L"dwmapi.dll");
        return dll ? reinterpret_cast<Fn>(GetProcAddress(dll, "DwmFlush")) : nullptr;
    }();
    if (fn) {
        fn();
    } else {
        Sleep(24);
    }
}

inline bool CaptureRegion(HWND excludeHwnd, int sx, int sy, int w, int h, Dib32& out,
                          bool* wdaOk = nullptr, int* meanOut = nullptr)
{
    if (w <= 0 || h <= 0) {
        return false;
    }
    // ★★★ v125：WDA 判断**提到分配之前** —— 判失败时立刻返回，
    //   不要先白白 `Dib32::Create` 一张 w*h*4 的位图（1024x740 就是 3MB，
    //   而这条路径每 150ms 就会被调一次）。
    bool wasExcluded = false;
    if (excludeHwnd && IsWindow(excludeHwnd)) {
        // ★ v89：生产路径已经**永久**排除了自己（见 EnsureBackdrop），
        //   这里就别再设一遍 —— 反复开关会让 DWM 每 150ms 重合成一次，
        //   录屏/截图会看到窗口一闪一闪地"漏底"。
        DWORD aff = 0;
        wasExcluded = GetWindowDisplayAffinity(excludeHwnd, &aff) && aff == 0x00000011u;
        if (!wasExcluded) {
            // ★★★ v125：**永久排除没生效 ⇒ 干脆不抓**，绝不临时开关。
            //
            //   用户原话：「闪烁没解决，还是会有闪烁，**表现是控件的背景
            //   莫名变黑**」。根因就是这里原来那三行：
            //       excluded = SetWindowDisplayAffinity(hwnd, 0x11);
            //       if (excluded) WaitForComposition();
            //       ... 抓完再 SetWindowDisplayAffinity(hwnd, 0);
            //
            //   而 `EnsureBackdrop` 的节流是 **150ms**（`interval = force ? 0 : 150`），
            //   且**每次重画都会走一遍**。用户一移动鼠标就是 60fps 的 WM_PAINT
            //   ⇒ **每 150ms 开关一次 WDA** ⇒ 每次开关都逼 DWM 重新合成
            //   ⇒ 窗口在合成帧里"漏底"，漏出来的是**黑色**
            //   ⇒ 看起来就是"控件的背景莫名变黑"，而且是"闪几下"（不是常亮）。
            //
            //   为什么是"部分控件"：漏底发生在**父窗口**的绘制区
            //   （背景/面板/药丸都是 layer 上画的）；子控件是独立窗口、
            //   没有 WDA ⇒ 它们反而正常。用户说的"控件"其实是父窗口
            //   画出来的那些药丸和卡片。
            //
            //   为什么 v89 没堵住：v89 只处理了"生产路径永久排除成功"那一半
            //   （`wasExcluded == true` ⇒ 不开关）。而"永久排除没设上/设失败"
            //   那一半（预览模式、`NO_WDA=1`、`SetWindowDisplayAffinity` 被拒）
            //   走的还是老路 —— 每 150ms 闪一次。
            //
            //   ⇒ 宁可用内置渐变，也不要闪。这台机器上永久排除后抓到的本来就是
            //     全黑（`LooksBlack` 会拒绝），一直用内置渐变 ⇒ 对它是**零损失**；
            //     能正常抓的机器走 `wasExcluded == true` 分支，行为完全不变。
            static bool logged = false;
            if (!logged) {
                logged = true;
                printf("[glass] 未永久排除自身 ⇒ **放弃抓背景**（临时开关 WDA 会逼 DWM "
                       "每 150ms 重合成，屏幕闪成黑块）。改用内置渐变。\n");
            }
            if (wdaOk) { *wdaOk = false; }
            return false;
        }
    }
    // 走到这里 = 要么没有 excludeHwnd（显示前抓桌面），要么永久排除已生效。
    if (!out.Create(nullptr, w, h)) {
        return false;
    }
    HDC screen = GetDC(nullptr);
    if (!screen) {
        return false;
    }
    // ★★★ v89 根因：**不能**把 `out.bitmap` 再 SelectObject 进第二个 DC。
    //   一个位图同一时刻只能被一个 DC 选中；`Dib32::Create` 里它已经选在
    //   `out.dc` 上了，这里再建一个 DC 去选同一张位图 ⇒ SelectObject 失败，
    //   新 DC 里还是那块默认的 1x1 单色位图 ⇒ BitBlt **返回 TRUE 但什么也没画**，
    //   目标 DIB 保持 CreateDIBSection 时的全零。
    //   症状就是"抓屏成功、均值=0、全黑"——而 GetPixel 同一个屏幕 DC 是正常的
    //   （DC 没问题，是目标画布没接上）。这个 bug 从第一版就在，
    //   所以玻璃**从来没透过一次真桌面**，一直走内置渐变兜底。
    HDC mem = out.dc;
    const bool ownDc = (mem == nullptr);
    HGDIOBJ old = nullptr;
    if (ownDc) {
        mem = CreateCompatibleDC(screen);
        if (!mem) {
            ReleaseDC(nullptr, screen);
            return false;
        }
        old = SelectObject(mem, out.bitmap);
    }
    const BOOL ok = BitBlt(mem, 0, 0, w, h, screen, sx, sy, SRCCOPY);
    if (ownDc) {
        SelectObject(mem, old);
        DeleteDC(mem);
    }
    ReleaseDC(nullptr, screen);
    // ★★★ v125：这里原来有"恢复 WDA 为 0"的收尾。现在**不存在临时设 WDA
    //   这条路径了**（没永久排除就直接不抓，见上面），所以没有要恢复的东西。
    //   ⇒ 屏幕上的窗口**不再有任何"隐身/漏底"的瞬间**，也就不会闪。
    if (wdaOk) {
        *wdaOk = wasExcluded;
    }
    if (meanOut) {
        long long sum = 0;
        int n = 0;
        if (out.bits) {
            for (int y = 0; y < out.h; y += 9) {
                const BYTE* row = out.bits + static_cast<size_t>(y) * out.stride;
                for (int x = 0; x < out.w; x += 9) {
                    const BYTE* p = row + x * 4;
                    sum += (p[0] + p[1] + p[2]) / 3;
                    ++n;
                }
            }
        }
        *meanOut = n ? static_cast<int>(sum / n) : -1;
    }
    return ok != FALSE;
}

// 抓屏内容有没有变？8x8 稀疏采样做一个指纹。
//
// ★ 为什么需要：改成"每 150ms 抓一次"之后，如果每次都跑
//   `GradeBackdropImage`（70 万像素的浮点运算）+ `BuildBlurLevels`（两级降采样），
//   光背景就吃掉 10ms/次 ≈ 单核 7%。而桌面**绝大多数时间是静止的**。
//   指纹不变 ⇒ 直接沿用上次的模糊结果，开销降到一次 BitBlt。
// ★ 量化到 4 级（>>2）：抓屏本身有 ±1 的抖动，精确比较会一直"变"。
inline unsigned long long SampleSignature(const Dib32& img)
{
    if (!img.bits || img.w <= 0 || img.h <= 0) {
        return 0;
    }
    unsigned long long h = 1469598103934665603ull;
    for (int gy = 0; gy < 8; ++gy) {
        const int y = (img.h - 1) * gy / 7;
        const BYTE* row = img.bits + static_cast<size_t>(y) * img.stride;
        for (int gx = 0; gx < 8; ++gx) {
            const int x = (img.w - 1) * gx / 7;
            const BYTE* p = row + x * 4;
            h ^= static_cast<unsigned long long>(p[0] >> 2)
               | (static_cast<unsigned long long>(p[1] >> 2) << 8)
               | (static_cast<unsigned long long>(p[2] >> 2) << 16);
            h *= 1099511628211ull;
        }
    }
    return h;
}

// 捕获失败的兜底背景：程序化渐变（左上冷白 → 右下淡蓝 + 一道柔光带）
//
// ★ 为什么要有它：RDP/虚拟显卡/受保护内容 上屏幕捕获可能整体是黑的。
//   黑底玻璃 = 界面像坏了。有了兜底至少"看起来是设计好的"。
inline void BuildFallbackFull(Backdrop& bd)
{
    if (!bd.full.Create(nullptr, bd.w, bd.h)) {
        return;
    }
    for (int y = 0; y < bd.h; ++y) {
        const float fy = static_cast<float>(y) / static_cast<float>(bd.h > 1 ? bd.h - 1 : 1);
        BYTE* row = bd.full.bits + static_cast<size_t>(y) * bd.full.stride;
        for (int x = 0; x < bd.w; ++x) {
            const float fx = static_cast<float>(x) / static_cast<float>(bd.w > 1 ? bd.w - 1 : 1);
            // 对角渐变
            const float g = Clampf(fx * 0.42f + fy * 0.58f, 0.0f, 1.0f);
            float r = 247.0f - 22.0f * g;
            float gg = 250.0f - 16.0f * g;
            float b = 255.0f - 6.0f * g;
            // 左上到右下的柔光带（让"玻璃"有东西可折射，纯平渐变折射看不出来）
            const float beam = Clampf(1.0f - fabsf((fx - 0.18f) * 1.1f + (fy - 0.1f) * 0.7f) * 2.4f, 0.0f, 1.0f);
            r += beam * 10.0f; gg += beam * 9.0f; b += beam * 8.0f;
            row[x * 4 + 0] = static_cast<BYTE>(Clampf(b, 0, 255));
            row[x * 4 + 1] = static_cast<BYTE>(Clampf(gg, 0, 255));
            row[x * 4 + 2] = static_cast<BYTE>(Clampf(r, 0, 255));
            row[x * 4 + 3] = 255;
        }
    }
}

// 内置背景：**设计好的柔和网格渐变**（浅色但有色相结构）
//
// ★★ 为什么需要它（这是"看起来丑"的根因，不是技术问题）：
//   玻璃的价值全在"背景里有东西可折射"。用户机器上窗口后面往往是**纯白的
//   文档/浏览器**，抓下来一片白 ⇒ 玻璃=白，面板=白卡片，整体就是"灰白平面"。
//   参考项目之所以好看，是因为它底下压了一张彩色照片。
//   ⇒ 抓到的背景**太素**时自动换成这块设计好的网格渐变：
//     浅色（保证面板外的深色文字可读）+ 有色相（玻璃才有折射/色散可看）。
inline void BuildDesignedFull(Backdrop& bd)
{
    if (!bd.full.Create(nullptr, bd.w, bd.h)) {
        return;
    }
    struct Blob { float x, y, r; float cr, cg, cb; float a; };
    // ★★★ v88：画布必须**有颜色、有明暗**，否则液态玻璃整套材质等于白做。
    //
    //   实测（本机预览环境抓屏恒黑 ⇒ 一定走这条内置路径）：
    //     · 旧配色基色 243/247/253、色团 224~250 —— 平均亮度 ~245，
    //       色相幅度（Colorfulness）只有 6~9，等于一张白纸；
    //     · 卡片 tint 0.56 掺白后也是 ~245 ⇒ **卡片和背景同色**，
    //       rim（往白掺 33%）、投影（白晕）、折射全部落在白上 ⇒ 看不见；
    //     · 观感就是"一叠白卡片"，怎么调着色器参数都没用。
    //
    //   玻璃只能折射它背后的东西。所以这里按参考项目 `BG_FS` 的思路，
    //   直接**造一张有层次的画布**：基色压到 228~240 的冷蓝灰，
    //   再压三团明显的色（蓝 / 紫 / 薄荷）+ 一团主光，四角压暗 10%。
    //   平均亮度 ~232、色相幅度 ~26 —— 卡片（~243）才浮得起来。
    const Blob blobs[] = {
        { -0.02f, -0.08f, 1.05f, 150, 186, 238, 0.62f },  // 左上：蓝（主色）
        { 0.58f, -0.02f, 0.72f, 255, 255, 255, 0.52f },    // 中上：主光（白）
        { 1.04f, 0.22f, 0.86f, 178, 160, 232, 0.55f },     // 右中：紫
        { 0.04f, 1.02f, 0.90f, 150, 200, 236, 0.50f },     // 左下：天蓝
        { 0.96f, 0.98f, 0.72f, 146, 214, 196, 0.42f },     // 右下：薄荷
        { 0.42f, 0.62f, 0.60f, 255, 250, 236, 0.22f },     // 中下：一点暖，避免整屏发青
    };
    for (int y = 0; y < bd.h; ++y) {
        const float fy = (float)y / (float)(bd.h > 1 ? bd.h - 1 : 1);
        BYTE* row = bd.full.bits + (size_t)y * bd.full.stride;
        for (int x = 0; x < bd.w; ++x) {
            const float fx = (float)x / (float)(bd.w > 1 ? bd.w - 1 : 1);
            // 底：冷调蓝灰，从上到下压暗（纵向层次；也让面板能"亮"出来）
            float r = 233.0f - 9.0f * fy;
            float g = 238.0f - 8.0f * fy;
            float b = 248.0f - 6.0f * fy;
            for (const Blob& blob : blobs) {
                const float dx = fx - blob.x;
                const float dy = (fy - blob.y) * 0.86f;   // 略压扁，更像相机里的光
                float d = sqrtf(dx * dx + dy * dy) / blob.r;
                if (d >= 1.0f) {
                    continue;
                }
                const float w = (1.0f - d * d) * (1.0f - d * d) * blob.a;
                r += (blob.cr - r) * w;
                g += (blob.cg - g) * w;
                b += (blob.cb - b) * w;
            }
            // 一道很淡的斜向高光带，打破"平涂感"
            const float beam = Clampf(1.0f - fabsf((fx - 0.30f) * 0.8f + (fy - 0.15f) * 0.6f) * 1.8f, 0.0f, 1.0f);
            r += beam * 7.0f; g += beam * 6.0f; b += beam * 4.0f;
            // 轻 vignette：四角压 10%，让中间"厚"一点（画布有厚度，玻璃才有对比）
            const float vx = (fx - 0.5f) * 2.0f, vy = (fy - 0.5f) * 2.0f;
            const float vig = 1.0f - 0.10f * (vx * vx + vy * vy);
            row[x * 4 + 0] = (BYTE)Clampf(b * vig, 0.0f, 255.0f);
            row[x * 4 + 1] = (BYTE)Clampf(g * vig, 0.0f, 255.0f);
            row[x * 4 + 2] = (BYTE)Clampf(r * vig, 0.0f, 255.0f);
            row[x * 4 + 3] = 255;
        }
    }
}

// 背景"有没有东西可折射"：色相幅度（max-min 通道）的平均值。
// ★ 阈值 10 是实测定的：纯白文档 ≈ 0~2；浅色壁纸 ≥ 25；设计渐变 ≈ 18~30。
inline int Colorfulness(const Dib32& img)
{
    if (!img.bits || img.w <= 0 || img.h <= 0) {
        return 0;
    }
    const int stepY = img.h > 48 ? img.h / 48 : 1;
    const int stepX = img.w > 48 ? img.w / 48 : 1;
    long long sum = 0;
    int n = 0;
    for (int y = 0; y < img.h; y += stepY) {
        const BYTE* row = img.bits + (size_t)y * img.stride;
        for (int x = 0; x < img.w; x += stepX) {
            const BYTE* p = row + x * 4;
            const int mx = (p[0] > p[1] ? (p[0] > p[2] ? p[0] : p[2]) : (p[1] > p[2] ? p[1] : p[2]));
            const int mn = (p[0] < p[1] ? (p[0] < p[2] ? p[0] : p[2]) : (p[1] < p[2] ? p[1] : p[2]));
            sum += (mx - mn);
            ++n;
        }
    }
    return n > 0 ? (int)(sum / n) : 0;
}

// ---------------------------------------------------------------------------
// 背景调色（v85）—— 决定整个界面像不像"液态玻璃"
// ---------------------------------------------------------------------------
//
// ★★★ 为什么必须在**抓屏之后、做模糊之前**改这张图：
//
//   v84 的界面被用户形容成"白卡片一叠"。根因不是玻璃算错了，而是**背景**：
//   窗口后面是一份纯白文档，`veil=0.18` 又把它往白里掺了 18%，
//   于是"背景≈白、玻璃≈白 → 卡片≈白"。换成再好的着色器也还是白，
//   因为玻璃只能折射它背后的东西，背后本来就是白的。
//
//   参考项目 `LiquidGlassControls` 的 BG_FS 做了四件事，这四件是"景深"的来源：
//     ① 高光压缩（白桌面被压到 ~0.78，而不是继续往白里推）
//     ② 几乎不去饱和（0.05）—— 保住壁纸的颜色，玻璃才有颜色可折
//     ③ 极轻地往冷白抬一点（0.06），和玻璃的 tint 同色系
//     ④ 暗角：边缘压暗 6~10%，视线自然聚到中间
//
//   放在这里做的好处：**CPU 合成和 OpenGL 后端吃的是同一张已调色的图**，
//   不存在"两条路颜色不一样"的可能（v84 的 GL base 只做了 veil，
//   一旦 veil 改成调色，两边就会分叉 —— 这是最容易埋下静默不一致的地方）。
//
// ★ 成本：只在抓屏/重建背景时跑一次（启动、移动、缩放、换 DPI），
//   不是每帧。1024x740 上 ~5ms。
inline void GradeBackdropImage(Dib32& img, const GlassTheme& th)
{
    if (!img.bits || img.w <= 0 || img.h <= 0) {
        return;
    }
    const float fx = 1.0f / static_cast<float>(img.w);
    const float fy = 1.0f / static_cast<float>(img.h);

    for (int y = 0; y < img.h; ++y) {
        BYTE* row = img.bits + static_cast<size_t>(y) * img.stride;
        const float dy = (static_cast<float>(y) * fy - 0.5f) * 1.12f;
        for (int x = 0; x < img.w; ++x) {
            BYTE* p = row + x * 4;
            float b = static_cast<float>(p[0]);
            float g = static_cast<float>(p[1]);
            float r = static_cast<float>(p[2]);

            // ① 高光压缩：按亮度等比缩放三个通道（不会跑色）
            const float l = (0.299f * r + 0.587f * g + 0.114f * b) / 255.0f;
            const float lc = l / (1.0f + l * th.dimKnee);
            const float k = (l > 1e-3f) ? (lc / l) : 1.0f;
            r *= k; g *= k; b *= k;

            // ② 去饱和 + 抬阴影（v89）：见 GlassTheme::gradeDesat / shadowLift。
            //   顺序不能反：先抬阴影会把高饱和色顶到 255 削顶（越抬越艳），
            //   先去饱和再抬，才是"柔和的一团色"。
            if (th.gradeDesat > 0.001f) {
                const float dl = 0.299f * r + 0.587f * g + 0.114f * b;
                r += (dl - r) * th.gradeDesat;
                g += (dl - g) * th.gradeDesat;
                b += (dl - b) * th.gradeDesat;
            }
            if (th.shadowLift > 0.001f) {
                const float l2 = (0.299f * r + 0.587f * g + 0.114f * b) / 255.0f;
                const float lifted = l2 + (1.0f - l2) * th.shadowLift;
                const float k2 = (l2 > 1e-3f) ? (lifted / l2) : 1.0f;
                r *= k2; g *= k2; b *= k2;
            }

            // ③ 冷调
            r += (static_cast<float>(th.gradeR) - r) * th.gradeMix;
            g += (static_cast<float>(th.gradeG) - g) * th.gradeMix;
            b += (static_cast<float>(th.gradeB) - b) * th.gradeMix;

            // ④ 暗角：到中心的距离做线性衰减（m 从中心 vigCenter 到边缘 vigEdge）
            const float dx = static_cast<float>(x) * fx - 0.5f;
            const float d = sqrtf(dx * dx + dy * dy);
            // smoothstep(1.08, 0.20, d) 的线性近似：d 小 ⇒ 1，d 大 ⇒ 0
            float vig = (1.08f - d) / (1.08f - 0.20f);
            vig = Clampf(vig, 0.0f, 1.0f);
            vig = vig * vig * (3.0f - 2.0f * vig);
            const float m = th.vigEdge + (th.vigCenter - th.vigEdge) * vig;
            r *= m; g *= m; b *= m;

            p[0] = static_cast<BYTE>(Clampf(b, 0.0f, 255.0f));
            p[1] = static_cast<BYTE>(Clampf(g, 0.0f, 255.0f));
            p[2] = static_cast<BYTE>(Clampf(r, 0.0f, 255.0f));
        }
    }
}

// 从 full 生成 a/b 两级模糊（半分辨率）
inline bool BuildBlurLevels(Backdrop& bd)
{
    const int hw = bd.w / 2 > 0 ? bd.w / 2 : 1;
    const int hh = bd.h / 2 > 0 ? bd.h / 2 : 1;
    if (!bd.a.Create(nullptr, hw, hh) || !bd.b.Create(nullptr, hw, hh)) {
        return false;
    }
    Downsample2(bd.full.bits, bd.w, bd.h, bd.a.bits, hw, hh);

    Dib32 tmpA;
    if (!tmpA.Create(nullptr, hw, hh)) {
        return false;
    }
    // ★ 要"霜面"而不是"轻微柔化"：半分辨率上 r=6、3 趟 ≈ 全分辨率 sigma ~14px。
    //   第一版 r=3（sigma ~7px）看起来只是"有点糊"，不像毛玻璃。
    BoxBlur(bd.a.bits, tmpA.bits, hw, hh, 6, 3);

    memcpy(bd.b.bits, bd.a.bits, static_cast<size_t>(hw) * hh * 4);
    Dib32 tmpB;
    if (!tmpB.Create(nullptr, hw, hh)) {
        return false;
    }
    BoxBlur(bd.b.bits, tmpB.bits, hw, hh, 10, 3);
    bd.refW = bd.w;
    bd.refH = bd.h;
    bd.valid = true;
    return true;
}

// 判定"抓屏真的失败了"：**近乎全黑**。
//
// ★★ 这里改过一次，别改回去：原来用"色差跨度 < 12"当失败判据，结果
//   **一个普通的浅色桌面**（IDE/白文档）也会被判成失败 ⇒ 背景被换成内置渐变
//   ⇒ 用户看到的是"一张渐变图"，而不是"我的桌面被模糊了"，直接回"还是不对"。
//   真正的失败症状是**全黑**（受保护内容 / 某些远程会话 / 驱动拒绝），
//   浅色、纯白都是**合法**的画面 —— 该照实模糊，不该替换。
inline bool LooksBlack(const Dib32& img)
{
    if (!img.bits || img.w <= 0 || img.h <= 0) {
        return true;
    }
    long long sum = 0;
    int n = 0;
    const int stepY = img.h > 48 ? img.h / 48 : 1;
    const int stepX = img.w > 48 ? img.w / 48 : 1;
    for (int y = 0; y < img.h; y += stepY) {
        const BYTE* row = img.bits + (size_t)y * img.stride;
        for (int x = 0; x < img.w; x += stepX) {
            const BYTE* p = row + x * 4;
            sum += (long long)p[0] + p[1] + p[2];
            ++n;
        }
    }
    const int mean = n > 0 ? (int)(sum / (3 * (long long)n)) : 0;
    return mean < 6;
}

// 判定一张抓来的图是否"基本是纯色/全黑"（捕获失败的典型症状）
inline bool LooksBlank(const Dib32& img)
{
    if (!img.bits || img.w <= 0 || img.h <= 0) {
        return true;
    }
    int minB = 255, minG = 255, minR = 255, maxB = 0, maxG = 0, maxR = 0;
    const int stepY = img.h > 64 ? img.h / 64 : 1;
    const int stepX = img.w > 64 ? img.w / 64 : 1;
    for (int y = 0; y < img.h; y += stepY) {
        const BYTE* row = img.bits + static_cast<size_t>(y) * img.stride;
        for (int x = 0; x < img.w; x += stepX) {
            const BYTE* p = row + x * 4;
            if (p[0] < minB) minB = p[0]; if (p[0] > maxB) maxB = p[0];
            if (p[1] < minG) minG = p[1]; if (p[1] > maxG) maxG = p[1];
            if (p[2] < minR) minR = p[2]; if (p[2] > maxR) maxR = p[2];
        }
    }
    const int span = (maxB - minB) + (maxG - minG) + (maxR - minR);
    return span < 12;
}

// 采样背景（玻璃内部用）：a/b 两级按 blurBlend 混合，单通道
inline float SampleBackdropCh(const Backdrop& bd, float x, float y, int ch,
                              const GlassTheme& th)
{
    const float ax = x * bd.ScaleX();
    const float ay = y * bd.ScaleY();
    const float va = BilinearCh(bd.a.bits, bd.a.w, bd.a.h, ax, ay, ch);
    const float vb = BilinearCh(bd.b.bits, bd.b.w, bd.b.h, ax, ay, ch);
    return va + (vb - va) * th.blurBlend;
}

// 采样背景：三通道一次取回（玻璃内部**非色散区**的主力路径）
inline void SampleBackdropRGB(const Backdrop& bd, float x, float y,
                              const GlassTheme& th, float out[3])
{
    const float ax = x * bd.ScaleX();
    const float ay = y * bd.ScaleY();
    float va[3], vb[3];
    BilinearRGB(bd.a.bits, bd.a.w, bd.a.h, ax, ay, va);
    BilinearRGB(bd.b.bits, bd.b.w, bd.b.h, ax, ay, vb);
    const float k = th.blurBlend;
    out[0] = va[0] + (vb[0] - va[0]) * k;
    out[1] = va[1] + (vb[1] - va[1]) * k;
    out[2] = va[2] + (vb[2] - va[2]) * k;
}

// ---------------------------------------------------------------------------
// 合成：背景底 + 单个玻璃面板
// ---------------------------------------------------------------------------

// 把**模糊背景**铺满目标，并压一层半透明白纱。
//
// ★★★ 这里用 `bd.a`（模糊版）而不是 `bd.full`（清晰原图）—— 这是"背景模糊
//   半透明"的关键：整个窗口的底就应该是**糊的**，清晰只保留在别处（本项目
//   不需要清晰，全糊）。第一版拿原图当底，只有面板内部是糊的 ⇒ 用户看到的是
//   "清晰桌面 + 几个玻璃块"，不是"一块毛玻璃窗口"。
inline void PaintBackdropBase(BYTE* dst, int dw, int dh, const Backdrop& bd,
                              const GlassTheme& th, float veil)
{
    if (!bd.valid || !bd.full.bits) {
        // 连兜底都没建起来：填个中性色，至少不是黑屏
        const size_t total = static_cast<size_t>(dw) * dh * 4;
        for (size_t i = 0; i < total; i += 4) {
            dst[i + 0] = 250; dst[i + 1] = 251; dst[i + 2] = 252; dst[i + 3] = 255;
        }
        return;
    }
    const float vb = static_cast<float>(th.veilTintB);
    const float vg = static_cast<float>(th.veilTintG);
    const float vr = static_cast<float>(th.veilTintR);
    // 半透明的"纱"：把模糊背景往白色拉一点，既保证深色文字可读，
    // 又保留背景的颜色和明暗结构（拉太多就变成一张白纸了）。
    for (int y = 0; y < dh; ++y) {
        BYTE* out = dst + static_cast<size_t>(y) * dw * 4;
        const float sy = (static_cast<float>(y) + 0.5f) * bd.ScaleY();
        for (int x = 0; x < dw; ++x) {
            float rgb[3];
            BilinearRGB(bd.a.bits, bd.a.w, bd.a.h,
                        (static_cast<float>(x) + 0.5f) * bd.ScaleX(), sy, rgb);
            float b = rgb[0] + (vb - rgb[0]) * veil;
            float g = rgb[1] + (vg - rgb[1]) * veil;
            float r = rgb[2] + (vr - rgb[2]) * veil;
            out[x * 4 + 0] = static_cast<BYTE>(Clampf(b, 0.0f, 255.0f));
            out[x * 4 + 1] = static_cast<BYTE>(Clampf(g, 0.0f, 255.0f));
            out[x * 4 + 2] = static_cast<BYTE>(Clampf(r, 0.0f, 255.0f));
            out[x * 4 + 3] = 255;
        }
    }
}

// 合成一块玻璃面板（含投影）
//
// `x0,y0,x1,y1` 是面板矩形（右/下为**开区间**，与 RECT 的 right/bottom 一致）。
// `tint` 用 GlassTheme 的 tintIdle / tintHover / tintActive。
// `cr,cg,cb` 是 tint 的**颜色**（v85）：掺白 = 255,255,255（v83/v84 的旧行为），
// 掺蓝/红/灰就能得到彩色玻璃与凹槽。`shadowScale=0` 表示不投外投影（凹槽用）。
inline void ComposeGlassPanel(BYTE* dst, int dw, int dh,
                              const Backdrop& bd,
                              int x0, int y0, int x1, int y1,
                              float radius, float tint, float dpi,
                              const GlassTheme& th,
                              BYTE cr = 255, BYTE cg = 255, BYTE cb = 255,
                              float shadowScale = 1.0f)
{
    if (!dst || x1 <= x0 || y1 <= y0 || dw <= 0 || dh <= 0) {
        return;
    }
    if (!bd.valid) {
        return;
    }
    const float cx = (static_cast<float>(x0) + static_cast<float>(x1)) * 0.5f;
    const float cy = (static_cast<float>(y0) + static_cast<float>(y1)) * 0.5f;
    const float hx = (static_cast<float>(x1) - static_cast<float>(x0)) * 0.5f;
    const float hy = (static_cast<float>(y1) - static_cast<float>(y0)) * 0.5f;
    const float r  = radius > 0.0f ? radius : 0.0f;
    // 圆角不能超过短边一半，否则 SDF 会翻负（画出来是个怪形状）
    const float rMax = (hx < hy ? hx : hy);
    const float rr = r > rMax ? rMax : r;

    const float band    = th.refractBand * dpi;
    const float shadowR = th.shadowRadius * dpi;
    const float margin  = shadowR + 2.0f;
    int ix0 = static_cast<int>(floorf(cx - hx - margin));
    int iy0 = static_cast<int>(floorf(cy - hy - margin));
    int ix1 = static_cast<int>(ceilf(cx + hx + margin));
    int iy1 = static_cast<int>(ceilf(cy + hy + margin));
    if (ix0 < 0) ix0 = 0;
    if (iy0 < 0) iy0 = 0;
    if (ix1 > dw) ix1 = dw;
    if (iy1 > dh) iy1 = dh;

    const float bend   = th.bendPx * dpi;
    const float ca     = th.chromatic;
    const float specY  = static_cast<float>(y0) + 1.5f * dpi;
    const float shOffY = th.shadowOffsetY * dpi;

    // 顶部光带的线性衰减宽度（逻辑 4px）。着色器用 exp(-|dy|*1.4)，
    // 这里换成"3px 内线性降到 0" —— 视觉几乎一致，但每行只算一次。
    auto SpecFalloff = [](float dy, float widthPx) -> float {
        const float a = fabsf(dy);
        if (a >= widthPx) {
            return 0.0f;
        }
        const float k = 1.0f - a / widthPx;
        return k * k;
    };
    const float specWidth = 4.0f;

    for (int y = iy0; y < iy1; ++y) {
        BYTE* row = dst + static_cast<size_t>(y) * dw * 4;
        const float fy = static_cast<float>(y) + 0.5f;
        const float py = fy - cy;
        // 顶部镜面光带只在面板上缘几像素内非零 ⇒ 逐行先算，省掉每像素一次 exp。
        const float specRow = SpecFalloff(fy - specY, specWidth * dpi) * th.specTopStrength;
        for (int x = ix0; x < ix1; ++x) {
            const float fx = static_cast<float>(x) + 0.5f;
            const float px = fx - cx;
            const float sd = SdRoundBox(px, py, hx, hy, rr);
            if (sd > margin) {
                continue;
            }
            BYTE* p = row + x * 4;

            // ---- 投影：只在面板**外**可见（里面被玻璃完全盖住）----
            //   ★ 先做这步再做玻璃，等价于着色器的 inside / shadow 二选一。
            if (shadowScale > 0.0f && sd > -0.55f) {
                const float sdSh = SdRoundBox(px, py - shOffY, hx, hy, rr);
                float sh = 1.0f - sdSh / shadowR;
                sh = Clampf(sh, 0.0f, 1.0f);
                const float shadowA = sh * sh * th.shadowAlpha * shadowScale;
                if (shadowA > 0.0f) {
                    // ★★★ v87：往**白**里掺，不是往黑里压。
                    //   必须和 GL 着色器逐字同义 —— 否则 R3SHIELDCORE_GLASS=off
                    //   的现场回退会得到另一套观感，而且这种分叉**不报错**。
                    const float k = shadowA > 1.0f ? 1.0f : shadowA;
                    p[0] = static_cast<BYTE>(p[0] + (255.0f - p[0]) * k);
                    p[1] = static_cast<BYTE>(p[1] + (255.0f - p[1]) * k);
                    p[2] = static_cast<BYTE>(p[2] + (255.0f - p[2]) * k);
                }
            }

            // 面板外（超出 AA 带）就到此为止
            if (sd >= 0.5f) {
                continue;
            }

            // ---- 折射场：贴着边最强，往里二次衰减 ----
            //   ★ 用 v*v 代替 powf(v, 2.2)：视觉上分辨不出，成本差一个数量级
            //     （powf 是 libm 调用，每像素一次会把整块合成拖到几十毫秒）。
            float t = -sd / band;
            t = Clampf(t, 0.0f, 1.0f);
            const float v = 1.0f - t;
            const float bendP = v * v;

            float ox = 0.0f, oy = 0.0f;
            // ★ 只有**外缘带**才需要法线（要 4 次额外 SDF）；面板深处折射为 0，
            //   连梯度都不用算 —— 这一条把大面板的合成成本砍掉一半。
            if (sd > -(band + 1.0f)) {
                const float e = 0.75f;
                const float gx = SdRoundBox(px + e, py, hx, hy, rr) - SdRoundBox(px - e, py, hx, hy, rr);
                const float gy = SdRoundBox(px, py + e, hx, hy, rr) - SdRoundBox(px, py - e, hx, hy, rr);
                const float gl = sqrtf(gx * gx + gy * gy);
                if (gl > 1e-5f) {
                    ox = (gx / gl) * bendP * bend;
                    oy = (gy / gl) * bendP * bend;
                }
            }

            const float sx = fx + ox;
            const float sy = fy + oy;
            float sR, sG, sB;
            const float caK = ca * bendP;
            if (bendP > 0.02f) {
                // 色散：R/B 沿法线反向微分离（只出现在最外 2~3px）
                sR = SampleBackdropCh(bd, sx + ox * caK, sy + oy * caK, 2, th);
                sG = SampleBackdropCh(bd, sx,            sy,            1, th);
                sB = SampleBackdropCh(bd, sx - ox * caK, sy - oy * caK, 0, th);
            } else {
                float rgb[3];
                SampleBackdropRGB(bd, sx, sy, th, rgb);
                sB = rgb[0]; sG = rgb[1]; sR = rgb[2];
            }

            // ---- 磨砂：轻微去饱和 + 提亮 ----
            const float luma = 0.299f * sR + 0.587f * sG + 0.114f * sB;
            sR = (sR + (luma - sR) * th.frostDesat) * th.frostGain;
            sG = (sG + (luma - sG) * th.frostDesat) * th.frostGain;
            sB = (sB + (luma - sB) * th.frostDesat) * th.frostGain;

            // ---- 染色 ----
            sR += (static_cast<float>(cr) - sR) * tint;
            sG += (static_cast<float>(cg) - sG) * tint;
            sB += (static_cast<float>(cb) - sB) * tint;

            // ---- 内侧 rim 高光（线性衰减近似 exp(sd/2.6)，只在内侧 3~4px 有效）----
            if (sd < 0.5f) {
                const float rimW = th.rimFalloff * dpi;
                float rim = 1.0f + sd / (rimW * 1.6f);
                rim = Clampf(rim, 0.0f, 1.0f);
                rim *= rim * th.rimStrength;
                sR += (255.0f - sR) * rim;
                sG += (255.0f - sG) * rim;
                sB += (255.0f - sB) * rim;
            }

            // ---- 顶部镜面光带 ----
            if (specRow > 0.0f) {
                sR += (255.0f - sR) * specRow;
                sG += (255.0f - sG) * specRow;
                sB += (255.0f - sB) * specRow;
            }

            // ---- 噪点（静态，按屏幕坐标，不抖动）----
            const float n = (Hash21(x, y) - 0.5f) * th.noiseAmp * 255.0f;
            sR += n; sG += n; sB += n;

            // ---- 抗锯齿：sd 从 -0.5 到 +0.5 渐隐 ----
            const float aa = Clampf(0.5f - sd, 0.0f, 1.0f);
            p[0] = static_cast<BYTE>(p[0] + (Clampf(sB, 0.0f, 255.0f) - p[0]) * aa);
            p[1] = static_cast<BYTE>(p[1] + (Clampf(sG, 0.0f, 255.0f) - p[1]) * aa);
            p[2] = static_cast<BYTE>(p[2] + (Clampf(sR, 0.0f, 255.0f) - p[2]) * aa);
        }
    }
}

// ---------------------------------------------------------------------------
// 合成一块"玻璃片"（页签 / 按钮 / 徽章）
// ---------------------------------------------------------------------------
//
// 与面板的区别：**不做边缘折射与色散**。
//   小控件半径小，折射带宽一压上去整块都在"扭曲"，看起来脏、字也糊；
//   而小控件要的只是"一眼看出是玻璃" —— tint + rim + 顶光 + 软投影就够。
//   这一条也是性能考量：一屏十几个按钮，每个都做 6 路采样不划算。
inline void ComposeGlassChip(BYTE* dst, int dw, int dh,
                             const Backdrop& bd,
                             int x0, int y0, int x1, int y1,
                             float radius, float tint, float dpi,
                             const GlassTheme& th,
                             BYTE cr = 255, BYTE cg = 255, BYTE cb = 255,
                             float shadowScale = 1.0f)
{
    if (!dst || x1 <= x0 || y1 <= y0 || dw <= 0 || dh <= 0) {
        return;
    }
    if (!bd.valid) {
        return;
    }
    const float cx = (static_cast<float>(x0) + static_cast<float>(x1)) * 0.5f;
    const float cy = (static_cast<float>(y0) + static_cast<float>(y1)) * 0.5f;
    const float hx = (static_cast<float>(x1) - static_cast<float>(x0)) * 0.5f;
    const float hy = (static_cast<float>(y1) - static_cast<float>(y0)) * 0.5f;
    const float rMax = hx < hy ? hx : hy;
    const float rr = radius > rMax ? rMax : (radius > 0.0f ? radius : 0.0f);

    // 小控件的投影要跟着缩小，否则按钮下面会挂一团大阴影
    const float shadowR = th.shadowRadius * dpi * 0.45f;
    const float shOffY  = th.shadowOffsetY * dpi * 0.6f;
    const float margin  = shadowR + 2.0f;
    int ix0 = static_cast<int>(floorf(cx - hx - margin));
    int iy0 = static_cast<int>(floorf(cy - hy - margin));
    int ix1 = static_cast<int>(ceilf(cx + hx + margin));
    int iy1 = static_cast<int>(ceilf(cy + hy + margin));
    if (ix0 < 0) ix0 = 0;
    if (iy0 < 0) iy0 = 0;
    if (ix1 > dw) ix1 = dw;
    if (iy1 > dh) iy1 = dh;

    const float specY = static_cast<float>(y0) + 1.0f * dpi;
    const float specW = 3.5f * dpi;
    for (int y = iy0; y < iy1; ++y) {
        BYTE* row = dst + static_cast<size_t>(y) * dw * 4;
        const float fy = static_cast<float>(y) + 0.5f;
        const float py = fy - cy;
        const float dy = fabsf(fy - specY);
        const float specRow = dy < specW
            ? (1.0f - dy / specW) * (1.0f - dy / specW) * th.specTopStrength
            : 0.0f;
        for (int x = ix0; x < ix1; ++x) {
            const float fx = static_cast<float>(x) + 0.5f;
            const float px = fx - cx;
            const float sd = SdRoundBox(px, py, hx, hy, rr);
            if (sd > margin) {
                continue;
            }
            BYTE* p = row + x * 4;
            if (shadowScale > 0.0f && sd > -0.55f) {
                const float sdSh = SdRoundBox(px, py - shOffY, hx, hy, rr);
                float sh = 1.0f - sdSh / shadowR;
                sh = Clampf(sh, 0.0f, 1.0f);
                const float shadowA = sh * sh * th.shadowAlpha * shadowScale;
                if (shadowA > 0.0f) {
                    // ★★★ v87：往**白**里掺，不是往黑里压。
                    //   必须和 GL 着色器逐字同义 —— 否则 R3SHIELDCORE_GLASS=off
                    //   的现场回退会得到另一套观感，而且这种分叉**不报错**。
                    const float k = shadowA > 1.0f ? 1.0f : shadowA;
                    p[0] = static_cast<BYTE>(p[0] + (255.0f - p[0]) * k);
                    p[1] = static_cast<BYTE>(p[1] + (255.0f - p[1]) * k);
                    p[2] = static_cast<BYTE>(p[2] + (255.0f - p[2]) * k);
                }
            }
            if (sd >= 0.5f) {
                continue;
            }
            float rgb[3];
            SampleBackdropRGB(bd, fx, fy, th, rgb);
            float sB = rgb[0], sG = rgb[1], sR = rgb[2];

            const float luma = 0.299f * sR + 0.587f * sG + 0.114f * sB;
            sR = (sR + (luma - sR) * th.frostDesat) * th.frostGain;
            sG = (sG + (luma - sG) * th.frostDesat) * th.frostGain;
            sB = (sB + (luma - sB) * th.frostDesat) * th.frostGain;

            sR += (static_cast<float>(cr) - sR) * tint;
            sG += (static_cast<float>(cg) - sG) * tint;
            sB += (static_cast<float>(cb) - sB) * tint;

            const float rimW = th.rimFalloff * dpi;
            float rim = 1.0f + sd / (rimW * 1.6f);
            rim = Clampf(rim, 0.0f, 1.0f);
            rim *= rim * th.rimStrength;
            sR += (255.0f - sR) * rim;
            sG += (255.0f - sG) * rim;
            sB += (255.0f - sB) * rim;

            if (specRow > 0.0f) {
                sR += (255.0f - sR) * specRow;
                sG += (255.0f - sG) * specRow;
                sB += (255.0f - sB) * specRow;
            }

            const float n = (Hash21(x, y) - 0.5f) * th.noiseAmp * 255.0f;
            sR += n; sG += n; sB += n;

            const float aa = Clampf(0.5f - sd, 0.0f, 1.0f);
            p[0] = static_cast<BYTE>(p[0] + (Clampf(sB, 0.0f, 255.0f) - p[0]) * aa);
            p[1] = static_cast<BYTE>(p[1] + (Clampf(sG, 0.0f, 255.0f) - p[1]) * aa);
            p[2] = static_cast<BYTE>(p[2] + (Clampf(sR, 0.0f, 255.0f) - p[2]) * aa);
        }
    }
}

// ---------------------------------------------------------------------------
// 半透明填充 / 描边（内容层用）
// ---------------------------------------------------------------------------
//
// ★ 为什么不在 GDI 上用 AlphaBlend：目标就是那块 DIB 的线性缓冲，
//   直接在内存里混合比"建 1x1 位图 + AlphaBlend 拉伸"快得多，也没有
//   预乘 alpha 的坑（AlphaBlend 的 AC_SRC_ALPHA 要求源是预乘的）。
inline void BlendRect(BYTE* dst, int dw, int dh, int x0, int y0, int x1, int y1,
                      int r, int g, int b, float alpha)
{
    if (!dst || alpha <= 0.0f) {
        return;
    }
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > dw) x1 = dw;
    if (y1 > dh) y1 = dh;
    const float a = alpha > 1.0f ? 1.0f : alpha;
    for (int y = y0; y < y1; ++y) {
        BYTE* row = dst + static_cast<size_t>(y) * dw * 4;
        for (int x = x0; x < x1; ++x) {
            BYTE* p = row + x * 4;
            p[0] = static_cast<BYTE>(p[0] + (b - p[0]) * a);
            p[1] = static_cast<BYTE>(p[1] + (g - p[1]) * a);
            p[2] = static_cast<BYTE>(p[2] + (r - p[2]) * a);
        }
    }
}

// 圆角半透明填充（按钮/chip 的"玻璃片"底色）
inline void BlendRoundRect(BYTE* dst, int dw, int dh, int x0, int y0, int x1, int y1,
                           float radius, int r, int g, int b, float alpha)
{
    if (!dst || alpha <= 0.0f || x1 <= x0 || y1 <= y0) {
        return;
    }
    const float cx = (static_cast<float>(x0) + static_cast<float>(x1)) * 0.5f;
    const float cy = (static_cast<float>(y0) + static_cast<float>(y1)) * 0.5f;
    const float hx = (static_cast<float>(x1) - static_cast<float>(x0)) * 0.5f;
    const float hy = (static_cast<float>(y1) - static_cast<float>(y0)) * 0.5f;
    const float rMax = hx < hy ? hx : hy;
    const float rr = radius > rMax ? rMax : radius;
    int ix0 = x0, iy0 = y0, ix1 = x1, iy1 = y1;
    if (ix0 < 0) ix0 = 0;
    if (iy0 < 0) iy0 = 0;
    if (ix1 > dw) ix1 = dw;
    if (iy1 > dh) iy1 = dh;
    for (int y = iy0; y < iy1; ++y) {
        BYTE* row = dst + static_cast<size_t>(y) * dw * 4;
        const float py = static_cast<float>(y) + 0.5f - cy;
        for (int x = ix0; x < ix1; ++x) {
            const float px = static_cast<float>(x) + 0.5f - cx;
            const float sd = SdRoundBox(px, py, hx, hy, rr);
            if (sd >= 0.5f) {
                continue;
            }
            const float aa = Clampf(0.5f - sd, 0.0f, 1.0f);
            const float a = alpha * aa;
            BYTE* p = row + x * 4;
            p[0] = static_cast<BYTE>(p[0] + (b - p[0]) * a);
            p[1] = static_cast<BYTE>(p[1] + (g - p[1]) * a);
            p[2] = static_cast<BYTE>(p[2] + (r - p[2]) * a);
        }
    }
}

// ---------------------------------------------------------------------------
// 窗口外框圆角（背景透明圆角）
// ---------------------------------------------------------------------------
//
// ★ 优先 DWM 的 `DWMWA_WINDOW_CORNER_PREFERENCE`（Win11 22H2+）：
//   它由合成器做**抗锯齿**圆角，圆角外面是真正的桌面，零代码零成本。
// ★ Win10 没有这个属性 ⇒ 返回 false，调用方退回 `SetWindowRgn` 硬裁剪
//   （有锯齿，但至少是圆的）。判断依据是**API 返回值**，不是版本号 ——
//   版本号在"Win11 但没启用圆角策略"的环境上会骗人。
inline bool ApplyDwmRoundCorners(HWND hwnd)
{
    if (!hwnd) {
        return false;
    }
    // 用数值而不是枚举：项目按 Win10 SDK 编译，枚举可能不存在。
    constexpr DWORD DwmwaWindowCornerPreference = 33;
    constexpr int DwmwcpRound = 2;
    const HRESULT hr = DwmSetWindowAttribute(hwnd, DwmwaWindowCornerPreference,
                                             &DwmwcpRound, sizeof(DwmwcpRound));
    return SUCCEEDED(hr);
}

inline void ApplyRoundRegion(HWND hwnd, int radiusPx, bool enable)
{
    if (!hwnd) {
        return;
    }
    if (!enable) {
        SetWindowRgn(hwnd, nullptr, TRUE);
        return;
    }
    RECT rc = {};
    GetWindowRect(hwnd, &rc);
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w <= 0 || h <= 0) {
        return;
    }
    HRGN rgn = CreateRoundRectRgn(0, 0, w + 1, h + 1, radiusPx * 2, radiusPx * 2);
    if (rgn) {
        // 成功后 rgn 归系统所有，不要 DeleteObject
        SetWindowRgn(hwnd, rgn, TRUE);
    }
}

// 总入口：先试 DWM，失败再退回 region。返回 1=DWM 2=region 0=都没成
inline int ApplyRoundedWindow(HWND hwnd, int radiusPx)
{
    if (ApplyDwmRoundCorners(hwnd)) {
        // DWM 已经接管，别再加 region（两者同时存在会把抗锯齿边切掉）
        ApplyRoundRegion(hwnd, radiusPx, false);
        return 1;
    }
    if (radiusPx > 0) {
        ApplyRoundRegion(hwnd, radiusPx, true);
        return 2;
    }
    return 0;
}

// 前置声明（定义在下面的"开关"小节；GlassSurface::Begin 要用它）
inline bool GlassEnabled();

// ---------------------------------------------------------------------------
// GlassSurface —— 一帧的绘制载体（背景缓存 + 面板层缓存）
// ---------------------------------------------------------------------------
//
// 为什么要"两帧收敛"这套记录/比对（别看着绕就删）：
//   面板矩形是**绘制过程中**才知道的（本项目布局与绘制是同一遍），而玻璃层
//   必须在画内容**之前**就合成好。所以只能：本帧用**上一帧记录的**面板表合成，
//   本帧结束时记下真实表；两张表不一致就要求再刷一帧。
//   ⇒ 状态稳定后每帧只花一次整幅 memcpy；状态一变多刷一帧（用户看不见）。
//
// ★ 不做这个缓存的话：ARK 页 300ms 全屏重绘 + 鼠标移动全窗失效
//   ⇒ 每帧都要重算 ~40 万个像素的折射/色散，CPU 直接顶满。
struct PanelRec {
    int   x0, y0, x1, y1;
    float radius;
    float tint;
    // 0 = 面板（大块，带边缘折射/色散）；1 = 玻璃片（页签/按钮/徽章）
    //   ★ 小控件不做折射：半径小、折射带一压上去就会显得脏，
    //     而小控件要的是"一眼看出是玻璃"（tint + rim + 顶光 + 软投影）。
    //   2 = 凹槽（滑块轨道 / 分段槽 / 进度条底）：更暗更平，不投外投影。
    int   kind;
    // ★★ v85：tint 的**颜色**。
    //
    //   v83/v84 里 tint 只有一个标量，含义隐含为"往白色掺"——于是所有玻璃
    //   都是白的，界面读起来就是一堆白卡片/白按钮。参考项目
    //   `LiquidGlassControls` 的做法是 `col = mix(blur, uTintCol, uTint)`：
    //   **颜色也是参数**，于是同一套材质就能做出
    //     · 蓝玻璃主按钮（掺蓝 0.88 + 白字）
    //     · 红玻璃危险按钮
    //     · 灰玻璃凹槽（掺 0.72,0.735,0.79，读成"凹下去的槽"）
    //     · 纯白滑块（掺白 0.93）
    //   这是"液态玻璃控件库"和"白色卡片"的全部区别所在，所以必须进契约。
    BYTE  cr = 255, cg = 255, cb = 255;
};

inline bool SamePanel(const PanelRec& a, const PanelRec& b)
{
    return a.x0 == b.x0 && a.y0 == b.y0 && a.x1 == b.x1 && a.y1 == b.y1
        && a.radius == b.radius
        && a.kind == b.kind
        && a.cr == b.cr && a.cg == b.cg && a.cb == b.cb
        && fabsf(a.tint - b.tint) < 0.001f;
}

struct GlassSurface {
    static constexpr int kMaxPanels = 96;

    Backdrop backdrop;
    Dib32    layer;      // 背景 + 面板（**不含**内容）
    int      w = 0;
    int      h = 0;
    float    dpi = 1.0f;

    bool      layerDirty    = true;
    bool      backdropDirty = true;
    ULONGLONG backdropAt    = 0;
    bool      active        = false;
    // ★★ GL 合成挂载点：不为空时，玻璃层交给 GPU 画（见 ui_gl.h）。
    //   约定：把 **背景 + 顶栏薄纱 + 所有面板** 画进 `out`（top-down BGRA，w*h*4）。
    //   这样 `ui_material.h` 不需要 #include 任何 GL 头（CPU 后端仍然独立可用）。
    using GlComposeFn = void (*)(void* ctx, const Backdrop& bd,
                                 const PanelRec* panels, int count,
                                 int headerBand, float headerVeil,
                                 int w, int h, float dpi, BYTE* out);
    GlComposeFn glCompose = nullptr;
    void*       glCtx = nullptr;
    // 实际用的后端（0=CPU 1=GL），给日志/判据看
    int         backend = 0;

    // 顶部"另一块玻璃片"的薄纱高度（逻辑 px，0=不要）。
    // 由调用方在 Begin 之前设 —— 各页共用同一段顶栏，但高度由调用方决定。
    int      headerBand = 0;
    float    headerVeil = 0.30f;

    int       failStage     = 0;

    // ★★ v89：背景是"实时透视桌面/其它窗口"还是"只抓一次"。
    //
    //   true （生产）：每 150ms 抓一次，桌面/下面的窗口变了玻璃就跟着变
    //                  —— 这是参考项目的行为，也是用户要的"半透明+模糊"。
    //   false（--gui-preview）：抓成功一次就冻住。
    //                  原因：本项目的验收探针（tools/gui_preview_probe.cpp）
    //                  是靠**屏幕 BitBlt** 截这个窗口的，而抓背景时必须
    //                  短暂 `SetWindowDisplayAffinity(0x11)` 排除自己 ——
    //                  若在预览模式下反复抓，探针有概率正好落在那个窗口里，
    //                  截到一张"窗口是洞"的图，闸门会假红。
    bool      liveCapture   = true;
    // ★★ v90：要不要把"排除自身抓屏"做成**永久**的。
    //
    //   true （生产）：抓第一次时设一次 `WDA_EXCLUDEFROMCAPTURE` 就再也不动，
    //                  之后每帧抓屏都不用开关 ⇒ 不闪、也不和截图抢时间。
    //                  代价：**系统截图/录屏里这个窗口是空的**（只有真人看得见）。
    //   false（预览 + LIVEBG）：每次抓完就恢复，截图/录屏仍能拍到窗口，
    //                  代价是每抓一次让 DWM 重合成两次。
    //                  仅用于"人眼看实时玻璃"，绝不能用在生产路径上。
    bool      permanentWda  = true;
    // 上一次抓到的内容指纹（见 SampleSignature）
    unsigned long long captureSig = 0;

    PanelRec cur[kMaxPanels] = {};
    int      curCount = 0;
    PanelRec used[kMaxPanels] = {};
    int      usedCount = 0;

    void Shutdown()
    {
        backdrop.Release();
        layer.Release();
        w = h = 0;
        curCount = usedCount = 0;
        layerDirty = backdropDirty = true;
        active = false;
    }

    void InvalidateBackdrop() { backdropDirty = true; }
    void InvalidateLayer()    { layerDirty = true; }

    // 行内记录一块面板（DrawPanel 调用）
    void AddPanel(int x0, int y0, int x1, int y1, float radius, float tint, int kind = 0,
                  BYTE cr = 255, BYTE cg = 255, BYTE cb = 255)
    {
        if (curCount >= kMaxPanels) {
            return;
        }
        PanelRec& r = cur[curCount++];
        r.x0 = x0; r.y0 = y0; r.x1 = x1; r.y1 = y1;
        r.radius = radius; r.tint = tint; r.kind = kind;
        r.cr = cr; r.cg = cg; r.cb = cb;
    }

    // 本帧结束：把本帧的面板表存成"已合成的那张"的对照。
    //
    // ★★★ 两套调用顺序，同一个函数有两种用法 —— 分清楚，否则就是"卡片永远不出现"：
    //
    //   · **主程序（v86+）**：BeginFrame → 画内容 → Compose → **SyncPanels()**。
    //     Compose 直接吃 `cur[]`，本帧就对齐，不需要"下一帧"。
    //   · **cfg 工具（GDI 内容画在玻璃层**之上**，没法先画后合成）**：
    //     Begin() → 画内容 → **CommitPanels()**。
    //     Begin() 只能用 `used[]`（上一帧的表）合成 ⇒ 需要两帧收敛，
    //     所以 CommitPanels 必须**在表变了的时候置 layerDirty**，逼下一帧重合成。
    //
    //   ★ 踩过：v86 把 `ComposeLayer` 改成只吃 `cur[]` 之后，cfg 的
    //     `Begin()`（内部 BeginFrame 会清零 curCount）在**画内容之前**就合成，
    //     于是它永远合成到一张空表 —— cfg 整个窗口一张卡片都没有，
    //     而且不报错、日志里还写着"液态玻璃已就绪"。这就是"两帧收敛"被
    //     单方面改掉、调用方没跟上的典型后果。
    bool CommitPanels()
    {
        bool same = (curCount == usedCount);
        if (same) {
            for (int i = 0; i < curCount; ++i) {
                if (!SamePanel(cur[i], used[i])) { same = false; break; }
            }
        }
        if (same) {
            return false;
        }
        for (int i = 0; i < curCount; ++i) {
            used[i] = cur[i];
        }
        usedCount = curCount;
        layerDirty = true;
        return true;
    }

    // 主程序用：本帧的合成已经用了 `cur[]`，把 `used[]` 同步过去即可，
    // **不能**置 layerDirty（否则 CPU 回落路径会每帧重跑一遍 box blur）。
    void SyncPanels()
    {
        for (int i = 0; i < curCount; ++i) {
            used[i] = cur[i];
        }
        usedCount = curCount;
    }

    bool EnsureBackdrop(HWND hwnd, bool force)
    {
        if (!active) {
            return false;
        }

        const int bgMode = BackdropMode();
        const ULONGLONG now = GetTickCount64();

        // ---- 生产路径：把"抓屏时排除自己"一次设死 ----
        //
        // 参考项目就是这么做的（`setupWindowChrome` 里设一次 `0x11`，之后每帧
        // 抓屏都不用管）。我们原来只在抓的那一瞬间开关，代价是：
        //   · 每次开关都会让 DWM 重合成 ⇒ 录屏/截图里窗口会一闪一闪地漏底；
        //   · 探针截图有概率正好落在"隐身"那 10ms 里 ⇒ 闸门随机假红。
        //
        // 预览模式**不能**这么做：探针是靠屏幕 BitBlt 截这个窗口的，
        // 永久排除 ⇒ 截到的永远是桌面，整条闸门失效。
        //
        // 想给这个窗口录屏/截图的话，设 `R3SHIELDCORE_GLASS_NO_WDA=1` 关掉它
        // （那时玻璃会退化成"抓到自己"的镜像反馈，只适合调试）。
        if (liveCapture && permanentWda && hwnd && IsWindow(hwnd)) {
            static int wdaState = -1;   // -1 未设，0 失败，1 成功
            if (wdaState < 0) {
                wchar_t off[8] = {};
                const bool optOut =
                    GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_NO_WDA", off, 8) > 0 && off[0] == L'1';
                wdaState = (!optOut && SetWindowDisplayAffinity(hwnd, 0x00000011u)) ? 1 : 0;
                printf("[glass] 永久排除自身抓屏=%d（录屏/截图看不到本窗口，"
                       "R3SHIELDCORE_GLASS_NO_WDA=1 可关）\n", wdaState);
            }
        }

        // ---- 明确要求"内置背景"（R3SHIELDCORE_GLASS_BG=builtin）----
        if (bgMode == 2) {
            if (!backdrop.valid) {
                Backdrop fresh;
                fresh.w = w;
                fresh.h = h;
                BuildDesignedFull(fresh);
                fresh.source = 2;
                GradeBackdropImage(fresh.full, DefaultTheme());
                BuildBlurLevels(fresh);
                backdrop.SwapWith(fresh);
                fresh.Release();
                backdrop.refreshStamp++;
                backdropAt = now;
                layerDirty = true;
            }
            backdropDirty = false;
            return true;
        }

        // ---- 什么时候才值得重抓 ----
        //
        // ★★★ v89：这里原来是
        //     if (backdrop.valid && !force && !backdropDirty) return true;
        //   —— `backdrop.valid` 一旦为真就**永不再抓**。配合"显示前抓一次"
        //   （那次抓到全黑 ⇒ 内置渐变兜底），结果是：屏幕上那层玻璃透视的
        //   一直是 `BuildDesignedFull` 画的一张程序化渐变，**不是桌面**。
        //
        //   参考项目是每帧抓。我们按 150ms 节流（拖动/缩放期间 force 直接放行）：
        //   · 桌面静止时：BitBlt + 指纹比较，指纹没变就什么都不做（≈0.3ms）；
        //   · 下面的窗口动了：指纹一变就重算调色 + 模糊；
        //   · 拖动窗口：force=true，每帧都抓（跟手）。
        //
        //   `liveCapture == false`（预览模式）时，抓成功一次就把间隔拉到无限大，
        //   之后不再碰屏幕 —— 理由见成员声明处的注释（探针要截这个窗口）。
        //
        //   ★★★ v125：条件从 `source == 1` 放宽成 `backdrop.valid`。
        //   原来只有"抓到过真桌面"才停手；抓失败退到内置渐变（source=2）时
        //   仍然每 150ms 试一次 ⇒ cfg 明明已经声明"不抓了"，还在每 150ms
        //   问一次 `GetWindowDisplayAffinity`。放宽之后：只要有背景（不管是
        //   抓的还是内置的），不抓就是真不抓。
        const ULONGLONG interval = (!liveCapture && backdrop.valid)
            ? ~0ull
            : (force ? 0ull : 150ull);
        if (backdrop.valid && !backdropDirty && (now - backdropAt) < interval) {
            return true;
        }

        // ★★ 用"先造新、成功才换"的写法：抓不到时**留着上一次的快照**，
        //   而不是把它毁掉退回内置背景（那正是这一版要修的病）。
        Backdrop fresh;
        fresh.w = w;
        fresh.h = h;

        bool useCaptured = false;
        bool wdaOk = false;
        int capMean = -1;
        bool bltOk = false;
        if (hwnd && IsWindow(hwnd)) {
            POINT origin = { 0, 0 };
            ClientToScreen(hwnd, &origin);
            bltOk = CaptureRegion(hwnd, origin.x, origin.y, w, h, fresh.full, &wdaOk, &capMean);
            useCaptured = bltOk;
            if (useCaptured && LooksBlack(fresh.full)) {
                useCaptured = false;
            }
            if (useCaptured && bgMode == 0 && Colorfulness(fresh.full) < 10) {
                useCaptured = false;
            }
        }
        // ★ v89 诊断：背景到底是"真桌面"还是"内置渐变"，只看日志就能判断。
        //   只在**状态变化**时打，否则 150ms 一条会刷屏。
        {
            static int lastState = -1;
            const int state = useCaptured ? 1 : 0;
            if (state != lastState) {
                lastState = state;
                printf("[glass] 背景抓取 %s WDA=%d BitBlt=%d 均值=%d 尺寸=%dx%d 来源=%s\n",
                    useCaptured ? "成功" : "失败", wdaOk ? 1 : 0, bltOk ? 1 : 0, capMean,
                    fresh.full.w, fresh.full.h,
                    useCaptured ? "真桌面/其它窗口" : "沿用旧快照或内置");
            }
        }
        if (useCaptured) {
            // ★ 诊断：`R3SHIELDCORE_GLASS_RAW=<路径>` ⇒ 把**抓到的原始背景**落盘
            //   （BGRA、top-down、无文件头）。用来回答"玻璃底下到底是什么"：
            //   拿它和屏幕截图对比，一眼就能看出抓的是桌面、是自己、还是别处。
            {
                static bool rawDone = false;
                if (!rawDone) {
                    wchar_t rawPath[512] = {};
                    if (GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_RAW", rawPath, 512) > 0) {
                        rawDone = true;
                        FILE* f = _wfopen(rawPath, L"wb");
                        if (f) {
                            for (int yy = 0; yy < fresh.full.h; ++yy) {
                                fwrite(fresh.full.bits + static_cast<size_t>(yy) * fresh.full.stride,
                                    1, static_cast<size_t>(fresh.full.w) * 4, f);
                            }
                            fclose(f);
                            printf("[glass] 原始背景已落盘 %dx%d -> %ls\n",
                                fresh.full.w, fresh.full.h, rawPath);
                        }
                    }
                }
            }
            const unsigned long long sig = SampleSignature(fresh.full);
            if (backdrop.valid && backdrop.source == 1 && sig == captureSig) {
                // 背后什么都没变 ⇒ 沿用已经算好的模糊结果，一次 BitBlt 就结束。
                fresh.Release();
                backdropAt = now;
                backdropDirty = false;
                return true;
            }
            captureSig = sig;
            fresh.source = 1;
            // ★ v85：先调色再模糊 —— 顺序反了（先糊再调）视觉上差不多，
            //   但"高光压缩"必须在模糊前做：模糊会把大片白揉成一片中灰，
            //   之后再压就只能压到那团灰上，白底的层次全丢。
            GradeBackdropImage(fresh.full, DefaultTheme());
            BuildBlurLevels(fresh);
        } else if (backdrop.valid) {
            // 抓不到（RDP / 受保护内容 / 刚显示还没合成）⇒ 沿用现有快照。
            fresh.Release();
            backdropAt = now;
            backdropDirty = false;
            return true;
        } else {
            // 一次都没抓到过才用内置背景；抓到之后会被上面的分支永久替换掉。
            BuildDesignedFull(fresh);
            fresh.source = 2;
            GradeBackdropImage(fresh.full, DefaultTheme());
            BuildBlurLevels(fresh);
        }

        backdrop.SwapWith(fresh);
        backdrop.refreshStamp++;   // ★ v86：背景换了，GL 那边要重新上传+模糊
        fresh.Release();
        backdropAt = now;
        backdropDirty = false;
        layerDirty = true;
        return true;
    }

    // 把背景铺底 + 按给定的面板表合成
    //
    // ★★★ 为什么要把表当参数传进来：两套调用顺序需要两张不同的表。
    //   · 主程序：`ComposeLayer(cur, curCount)` —— 本帧的，天然对齐。
    //   · cfg  ：`ComposeLayer(used, usedCount)` —— 上一帧的（两帧收敛）。
    //   写死成 `cur[]` 会让 cfg 合成到空表（详见 CommitPanels 的注释）。
    void ComposeLayer(const PanelRec* panels, int count)
    {
        if (!layer.bits) {
            return;
        }
        if (glCompose) {
            glCompose(glCtx, backdrop, panels, count,
                      headerBand, headerVeil, w, h, dpi, layer.bits);
            backend = 1;
            layerDirty = false;
            return;
        }
        backend = 0;
        PaintBackdropBase(layer.bits, w, h, backdrop, DefaultTheme(), DefaultTheme().veil);
        // 顶栏：压一层更亮的薄纱，读成"另一块玻璃片"（原来是 GradientFill 干的）。
        // ★ 放在**玻璃层里**而不是画内容时叠一次：内容是每帧重画的，
        //   薄纱属于"材质"，只该在重建层的时候算一次。
        if (headerBand > 0) {
            const int band = headerBand < h ? headerBand : h;
            BlendRect(layer.bits, w, h, 0, 0, w, band, 255, 255, 255, headerVeil);
        }
        for (int i = 0; i < count; ++i) {
            // kind 2 = 凹槽：形状同玻璃片，但**不投外投影** —— 槽是"凹下去"的，
            // 底下挂一团投影会让滑块轨道看起来是浮起来的，方向正好相反。
            if (panels[i].kind == 1 || panels[i].kind == 2) {
                ComposeGlassChip(layer.bits, w, h, backdrop,
                    panels[i].x0, panels[i].y0, panels[i].x1, panels[i].y1,
                    panels[i].radius, panels[i].tint, dpi, DefaultTheme(),
                    panels[i].cr, panels[i].cg, panels[i].cb,
                    panels[i].kind == 2 ? 0.0f : 1.0f);
            } else {
                ComposeGlassPanel(layer.bits, w, h, backdrop,
                    panels[i].x0, panels[i].y0, panels[i].x1, panels[i].y1,
                    panels[i].radius, panels[i].tint, dpi, DefaultTheme(),
                    panels[i].cr, panels[i].cg, panels[i].cb, 1.0f);
            }
        }
        layerDirty = false;
    }

    // ------------------------------------------------------------------
    // ★★★ 在**窗口显示之前**抓一次背景（这是拿到"真实桌面"的唯一时机）
    //
    //   为什么必须"显示之前"：
    //     · 窗口显示后，它自己把要抓的区域挡住了；用
    //       `WDA_EXCLUDEFROMCAPTURE` 把它排除，**这台 Win11 上抓到的是全黑**
    //       （实测 均值=0 极差=0），不是"透过它看到后面"；
    //     · 而窗口还没 Show 的时候，屏幕上那块就是真实的桌面
    //       —— 包括别的窗口、壁纸、图标。
    //   代价：这张快照是**启动那一刻**的。之后移动/缩放都沿用它（拉伸采样），
    //   因为糊了之后"位置对不上"几乎看不出来。
    // ------------------------------------------------------------------
    bool CaptureBackdropBeforeShow(HWND hwnd, int width, int height)
    {
        if (!hwnd || width < 32 || height < 32) {
            return false;
        }
        backdrop.Release();
        backdrop.w = width;
        backdrop.h = height;
        POINT origin = { 0, 0 };
        ClientToScreen(hwnd, &origin);
        // 注意：**不传 hwnd** ⇒ 不做 WDA 排除（此刻窗口还没显示，不需要排除）
        if (!CaptureRegion(nullptr, origin.x, origin.y, width, height, backdrop.full)) {
            return false;
        }
        {
            long long sum = 0; int nn = 0;
            if (backdrop.full.bits) {
                for (int y = 0; y < backdrop.full.h; y += 9) {
                    const BYTE* row = backdrop.full.bits + (size_t)y * backdrop.full.stride;
                    for (int x = 0; x < backdrop.full.w; x += 9) {
                        const BYTE* q = row + x * 4;
                        sum += (q[0] + q[1] + q[2]) / 3; ++nn;
                    }
                }
            }
            printf("[glass] 快照诊断 请求=%dx%d 实际=%dx%d 原点=%ld,%ld 均值=%d\n",
                width, height, backdrop.full.w, backdrop.full.h,
                (long)origin.x, (long)origin.y, nn ? (int)(sum / nn) : -1);
        }
        if (LooksBlack(backdrop.full)) {
            return false;
        }
        BuildBlurLevels(backdrop);
        backdrop.source = 1;
        backdrop.refreshStamp++;   // ★ v86：见上
        backdropDirty = false;
        layerDirty = true;
        return true;
    }

    // ★★★ v86：一帧被拆成 **三段**（原来是 `Begin` 一把做完）。
    //
    //   为什么必须拆：v86 之后"画内容"发生在**合成过程中**（GL 后端回调场景
    //   把实心/图标/文字直接画进 layer）。而内容又必须先知道"这一帧有没有玻璃"
    //   （决定登记不登记面板、用不用深色文字）。原来的 `Begin` 是
    //   "判断 + 备背景 + 合成"三合一，一旦挪到画内容之前就没东西可合成，
    //   挪到之后又拿不到 `active`。
    //   ⇒ 拆成：
    //       BeginFrame()  清空本帧面板表            （画之前）
    //       Prepare()     判断可用性 / 建层 / 备背景（画之前，**不合成**）
    //       Compose()     背景 + 面板 [+ 内容]      （画之后）
    //   `Begin()` 保留为"三段连做"的旧语义，给不需要内容的调用方用。
    void BeginFrame() { curCount = 0; }

    bool Prepare(HWND hwnd, int width, int height, float scale, bool wantBackdropRefresh)
    {
        if (!GlassEnabled()) {
            failStage = 1;
            active = false;
            return false;
        }
        if (width < 32 || height < 32) {
            failStage = 1;
            active = false;
            return false;
        }
        failStage = 0;
        if (width != w || height != h || fabsf(scale - dpi) > 0.001f) {
            w = width;
            h = height;
            dpi = scale;
            curCount = usedCount = 0;
            layerDirty = true;
            backdropDirty = true;
            if (!layer.Create(nullptr, w, h)) {
                failStage = 2;
                active = false;
                return false;
            }
        }
        if (!layer.bits) {
            failStage = 3;
            active = false;
            return false;
        }
        active = true;
        EnsureBackdrop(hwnd, wantBackdropRefresh);
        return true;
    }

    // 合成这一帧的 layer。
    //
    // ★ GL 后端：**每帧都合成** —— 内容（文字/图标/表格）就是在这条路上
    //   画进 layer 的，跳过一帧就等于这一帧没内容。
    // ★ CPU 后端：内容由调用方用 GDI 画在 layer **之上**（见 ui_scene.h 的
    //   PaintGdi），所以 layer 只在"背景变了 / 面板表变了"时才重建 ——
    //   重建一次要跑 N 块面板的 box blur，不能每帧做。
    void Compose()
    {
        if (!active || !layer.bits) {
            return;
        }
        if (glCompose) {
            ComposeLayer(cur, curCount);
            return;
        }
        if (layerDirty || !SamePanelSet()) {
            ComposeLayer(cur, curCount);
        }
    }

    bool SamePanelSet() const
    {
        if (curCount != usedCount) {
            return false;
        }
        for (int i = 0; i < curCount; ++i) {
            if (!SamePanel(cur[i], used[i])) {
                return false;
            }
        }
        return true;
    }

    // ★★★ v124：本帧面板表相对"已合成的那张"**变了哪一块**（客户坐标包围盒）。
    //
    // 为什么需要它（用户原话："移动鼠标时部分控件老是闪几下"）：
    //   悬停动画是 16ms 一帧、每帧 tint 都在变 ⇒ `CommitPanels()` 每帧都报"变了"
    //   ⇒ cfg 那边每帧 `InvalidateRect(hwnd, nullptr)` + `InvalidateAllChildren()`
    //   ⇒ **整窗 + 全部子控件每秒重画 60 次**，而真正变的只有一个按钮药丸。
    //   实测（`_t/flicker_probe.py`）抓到的症状：离按钮很远的标签
    //   （`超时兜底` / `决定「记」还是「拦」…`）文字整行消失一帧再自己回来 ——
    //   它们的底是从 layer 贴的（WM_CTLCOLORSTATIC 里 BitBlt），
    //   重画风暴里偶尔就出现"底贴了、字没跟上"的一帧。
    //   ⇒ 只重画真的变了的那块，无关控件**根本不再重画**，闪无从发生。
    //
    // 返回 false = 表没变（调用方照旧什么都不用做）。
    // `pad` 给描边/软投影留余量（药丸的 1px 暗描边画在矩形内，投影在外）。
    bool PanelsDiffRect(RECT* out, int pad = 8) const
    {
        if (!out) {
            return false;
        }
        bool any = false;
        RECT acc = { 0, 0, 0, 0 };
        const int n = (curCount > usedCount) ? curCount : usedCount;
        for (int i = 0; i < n; ++i) {
            const bool both = (i < curCount) && (i < usedCount);
            if (both && SamePanel(cur[i], used[i])) {
                continue;
            }
            RECT r;
            if (both) {
                // 两边都有但不同（tint / 颜色 / 半径变了）⇒ 取并集
                r.left   = (cur[i].x0 < used[i].x0) ? cur[i].x0 : used[i].x0;
                r.top    = (cur[i].y0 < used[i].y0) ? cur[i].y0 : used[i].y0;
                r.right  = (cur[i].x1 > used[i].x1) ? cur[i].x1 : used[i].x1;
                r.bottom = (cur[i].y1 > used[i].y1) ? cur[i].y1 : used[i].y1;
            } else if (i < curCount) {
                // 新出现的面板
                r.left = cur[i].x0; r.top = cur[i].y0;
                r.right = cur[i].x1; r.bottom = cur[i].y1;
            } else {
                // 被删掉的面板
                r.left = used[i].x0; r.top = used[i].y0;
                r.right = used[i].x1; r.bottom = used[i].y1;
            }
            r.left -= pad; r.top -= pad; r.right += pad; r.bottom += pad;
            if (!any) {
                acc = r;
                any = true;
            } else {
                if (r.left   < acc.left)   { acc.left = r.left; }
                if (r.top    < acc.top)    { acc.top = r.top; }
                if (r.right  > acc.right)  { acc.right = r.right; }
                if (r.bottom > acc.bottom) { acc.bottom = r.bottom; }
            }
        }
        if (!any) {
            return false;
        }
        *out = acc;
        return true;
    }

    // 一帧开始：准备好 layer（玻璃层）。调用方把它 BitBlt 到自己的双缓冲位图上，
    // 再在位图上画内容 —— ★ 不要直接把内容画进这个 DIB（见下面的说明）。
    //   `wantBackdropRefresh` 由调用方的定时器/移动事件决定
    //
    // ★★ 这是**给 cfg 工具**的兼容入口（内容用 GDI 画在 layer 之上，
    //    没法"先画后合成"）。它合成的是**上一帧**登记的表，画完内容后
    //    必须调 `CommitPanels()` 把本帧的表交上去，否则永远合成空表。
    //    主程序走 `BeginFrame() → 画 → Compose() → SyncPanels()`。
    bool Begin(HWND hwnd, int width, int height, float scale, bool wantBackdropRefresh)
    {
        BeginFrame();
        if (!Prepare(hwnd, width, height, scale, wantBackdropRefresh)) {
            return false;
        }
        if (glCompose) {
            // GL 后端每帧都得合成（内容由它画进 layer）
            ComposeLayer(used, usedCount);
        } else if (layerDirty || !SamePanelSet()) {
            ComposeLayer(used, usedCount);
        }
        return true;
    }
};


// ---------------------------------------------------------------------------
// 诊断：把"这一帧到底画成什么样"直接落盘（不经屏幕捕获）
// ---------------------------------------------------------------------------
//
// ★ 为什么需要它：屏幕 DC 抓图会被 `WDA_EXCLUDEFROMCAPTURE` 影响、
//   也会被"窗口还没画完"影响 —— 一旦界面看起来不对，你无法区分
//   「画错了」和「没抓到」。把缓冲自己导出来看，这两个可能立刻分开。
//   只在设了环境变量时才写，正常路径零开销。
inline bool SaveHdcToBmp(HDC memDc, int w, int h, const wchar_t* path)
{
    if (!memDc || w <= 0 || h <= 0 || !path) {
        return false;
    }
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    const DWORD imageBytes = static_cast<DWORD>(w) * static_cast<DWORD>(h) * 4u;
    const DWORD headerBytes = 14u + 40u;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    BITMAPFILEHEADER fh = {};
    fh.bfType = 0x4D42;
    fh.bfOffBits = headerBytes;
    fh.bfSize = headerBytes + imageBytes;
    DWORD written = 0;
    WriteFile(file, &fh, sizeof(fh), &written, nullptr);
    WriteFile(file, &bi.bmiHeader, sizeof(BITMAPINFOHEADER), &written, nullptr);

    // 逐行读，避免一次性申请整幅（大窗口时更稳）
    BYTE* row = static_cast<BYTE*>(malloc(static_cast<size_t>(w) * 4));
    if (row) {
        for (int y = 0; y < h; ++y) {
            if (GetDIBits(memDc, static_cast<HBITMAP>(GetCurrentObject(memDc, OBJ_BITMAP)),
                          static_cast<UINT>(y), 1, row, &bi, DIB_RGB_COLORS) == 0) {
                break;
            }
            WriteFile(file, row, static_cast<DWORD>(w) * 4u, &written, nullptr);
        }
        free(row);
    }
    CloseHandle(file);
    return true;
}

// ---------------------------------------------------------------------------
// 开关（A/B 与负对照）
// ---------------------------------------------------------------------------
//
// ★ 必须有这个开关：新材质一旦出问题（比如某台机器捕获恒黑），
//   用户/现场能一键回到能用的界面，而不用等我们发版。
inline bool GlassEnabled()
{
    wchar_t value[16] = {};
    const DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS", value, 16);
    if (n > 0 && n < 16 && value[0] != 0) {
        if (_wcsicmp(value, L"off") == 0 || _wcsicmp(value, L"0") == 0) {
            return false;
        }
    }
    return true;
}

// 背景刷新间隔（毫秒）。移动/缩放期间用短间隔，静止后不刷。
inline UINT BackdropRefreshInterval()
{
    wchar_t value[16] = {};
    const DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_MS", value, 16);
    if (n > 0 && n < 16 && value[0] != 0) {
        const int ms = _wtoi(value);
        if (ms >= 200 && ms <= 10000) {
            return static_cast<UINT>(ms);
        }
    }
    return 1500;
}

} // namespace R3ShieldCoreUi

#endif // R3SC_UI_MATERIAL_H
