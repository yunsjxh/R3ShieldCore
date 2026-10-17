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
    float tintIdle           = 0.300f;
    float tintHover          = 0.360f;
    float tintActive         = 0.420f;

    // 折射
    float bendPx             = 14.0f;   // 边缘最大偏移（全分辨率像素）
    float refractBand        = 9.0f;    // 衰减带宽：贴着边到深处的距离
    float chromatic          = 0.34f;   // R/B 分离系数（× bendP）
    float blurBlend          = 0.42f;   // 轻模糊 / 重模糊 的混合比

    // 磨砂
    float frostDesat         = 0.10f;   // 去饱和比例
    float frostGain          = 1.04f;   // 提亮

    // rim 高光（内侧亮边）
    float rimStrength        = 0.46f;
    float rimFalloff         = 2.6f;    // 越小越窄

    // 顶部镜面光带
    float specTopStrength    = 0.16f;

    // 噪点幅度（0..1，乘到 ±127.5）
    float noiseAmp           = 0.020f;

    // 投影
    float shadowOffsetY      = 5.0f;
    float shadowRadius       = 24.0f;
    float shadowAlpha        = 0.22f;

    // 背景"薄纱"：整幅背景压一层白，保证深色文字可读（0 = 完全不加）
    float veil               = 0.00f;
    // 背景冷色化：往这个色偏一点，让桌面壁纸不至于是花花绿绿的照片
    BYTE  veilTintB          = 252;
    BYTE  veilTintG          = 250;
    BYTE  veilTintR          = 246;
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
    int  source = 0;    // 0=没有 1=屏幕捕获 2=兜底渐变 3=关闭
    bool valid = false;

    void Release()
    {
        full.Release();
        a.Release();
        b.Release();
        w = h = 0;
        source = 0;
        valid = false;
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
//   ★ 自动是默认：既保留"真透视"（后面有内容时），又不会在纯白文档前变成一张白纸。
inline int BackdropMode()
{
    static int mode = -1;
    if (mode >= 0) {
        return mode;
    }
    mode = 0;
    wchar_t v[16] = {};
    const DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_GLASS_BG", v, 16);
    if (n > 0 && n < 16 && v[0]) {
        if (_wcsicmp(v, L"desktop") == 0 || _wcsicmp(v, L"screen") == 0) { mode = 1; }
        else if (_wcsicmp(v, L"builtin") == 0 || _wcsicmp(v, L"designed") == 0) { mode = 2; }
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
inline bool CaptureRegion(HWND excludeHwnd, int sx, int sy, int w, int h, Dib32& out)
{
    if (w <= 0 || h <= 0) {
        return false;
    }
    if (!out.Create(nullptr, w, h)) {
        return false;
    }
    HDC screen = GetDC(nullptr);
    if (!screen) {
        return false;
    }
    bool excluded = false;
    if (excludeHwnd && IsWindow(excludeHwnd)) {
        excluded = SetWindowDisplayAffinity(excludeHwnd, 0x00000011u) != FALSE;
        if (excluded) {
            // 给 DWM 一帧时间把"排除"生效，否则仍然抓到自己的残影。
            Sleep(24);
        }
    }
    HDC mem = CreateCompatibleDC(screen);
    HGDIOBJ old = SelectObject(mem, out.bitmap);
    const BOOL ok = BitBlt(mem, 0, 0, w, h, screen, sx, sy, SRCCOPY);
    SelectObject(mem, old);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    if (excluded) {
        SetWindowDisplayAffinity(excludeHwnd, 0x00000000u);
    }
    return ok != FALSE;
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
    // ★★ 配色取向：**冷调浅蓝画布** + 很淡的色团。
    //   为什么要冷调、要淡：面板是"白色半透明玻璃"，只有画布明显**比它深一点、
    //   冷一点**，面板才会"浮"起来。第一版用了饱和度高的暖色团，结果整屏发闷、
    //   面板和背景糊在一起（用户直接说"丑死了"）—— 配色比技术更决定观感。
    const Blob blobs[] = {
        { 0.08f, 0.02f, 0.72f, 205, 224, 247, 0.62f },   // 天蓝
        { 0.95f, 0.00f, 0.58f, 219, 213, 244, 0.52f },   // 淡紫
        { 0.88f, 1.00f, 0.66f, 201, 234, 226, 0.55f },   // 薄荷
        { 0.00f, 0.92f, 0.58f, 246, 231, 217, 0.34f },   // 一点点暖（避免整体发青）
    };
    for (int y = 0; y < bd.h; ++y) {
        const float fy = (float)y / (float)(bd.h > 1 ? bd.h - 1 : 1);
        BYTE* row = bd.full.bits + (size_t)y * bd.full.stride;
        for (int x = 0; x < bd.w; ++x) {
            const float fx = (float)x / (float)(bd.w > 1 ? bd.w - 1 : 1);
            // 底：冷调浅蓝灰，向下压暗一档（给纵向层次；也让面板能"亮"出来）
            float r = 233.0f - 10.0f * fy;
            float g = 239.0f - 9.0f * fy;
            float b = 249.0f - 6.0f * fy;
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
            r += beam * 9.0f; g += beam * 8.0f; b += beam * 6.0f;
            // 轻 vignette：四角压 5%，让中间"厚"一点（画布有厚度，玻璃才有对比）
            const float vx = (fx - 0.5f) * 2.0f, vy = (fy - 0.5f) * 2.0f;
            const float vig = 1.0f - 0.05f * (vx * vx + vy * vy);
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
    BoxBlur(bd.a.bits, tmpA.bits, hw, hh, 3, 3);

    memcpy(bd.b.bits, bd.a.bits, static_cast<size_t>(hw) * hh * 4);
    Dib32 tmpB;
    if (!tmpB.Create(nullptr, hw, hh)) {
        return false;
    }
    BoxBlur(bd.b.bits, tmpB.bits, hw, hh, 7, 3);
    bd.valid = true;
    return true;
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
    const float ax = x * 0.5f;
    const float ay = y * 0.5f;
    const float va = BilinearCh(bd.a.bits, bd.a.w, bd.a.h, ax, ay, ch);
    const float vb = BilinearCh(bd.b.bits, bd.b.w, bd.b.h, ax, ay, ch);
    return va + (vb - va) * th.blurBlend;
}

// 采样背景：三通道一次取回（玻璃内部**非色散区**的主力路径）
inline void SampleBackdropRGB(const Backdrop& bd, float x, float y,
                              const GlassTheme& th, float out[3])
{
    const float ax = x * 0.5f;
    const float ay = y * 0.5f;
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

// 把 full 原图铺满目标（可选压一层"薄纱"），并做一次轻微冷色化
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
    for (int y = 0; y < dh; ++y) {
        const int sy = (y < bd.full.h) ? y : bd.full.h - 1;
        const BYTE* src = bd.full.bits + static_cast<size_t>(sy) * bd.full.stride;
        BYTE* out = dst + static_cast<size_t>(y) * dw * 4;
        for (int x = 0; x < dw; ++x) {
            const int sx = (x < bd.full.w) ? x : bd.full.w - 1;
            const BYTE* p = src + sx * 4;
            float b = static_cast<float>(p[0]);
            float g = static_cast<float>(p[1]);
            float r = static_cast<float>(p[2]);
            // 薄纱：往 veilTint 偏（也顺带压掉壁纸的高饱和，保证深字可读）
            b += (vb - b) * veil;
            g += (vg - g) * veil;
            r += (vr - r) * veil;
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
inline void ComposeGlassPanel(BYTE* dst, int dw, int dh,
                              const Backdrop& bd,
                              int x0, int y0, int x1, int y1,
                              float radius, float tint, float dpi,
                              const GlassTheme& th)
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
            if (sd > -0.55f) {
                const float sdSh = SdRoundBox(px, py - shOffY, hx, hy, rr);
                float sh = 1.0f - sdSh / shadowR;
                sh = Clampf(sh, 0.0f, 1.0f);
                const float shadowA = sh * sh * th.shadowAlpha;
                if (shadowA > 0.0f) {
                    const float k = 1.0f - shadowA;
                    p[0] = static_cast<BYTE>(p[0] * k);
                    p[1] = static_cast<BYTE>(p[1] * k);
                    p[2] = static_cast<BYTE>(p[2] * k);
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
            sR += (255.0f - sR) * tint;
            sG += (255.0f - sG) * tint;
            sB += (255.0f - sB) * tint;

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
                             const GlassTheme& th)
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
            if (sd > -0.55f) {
                const float sdSh = SdRoundBox(px, py - shOffY, hx, hy, rr);
                float sh = 1.0f - sdSh / shadowR;
                sh = Clampf(sh, 0.0f, 1.0f);
                const float shadowA = sh * sh * th.shadowAlpha;
                if (shadowA > 0.0f) {
                    const float k = 1.0f - shadowA;
                    p[0] = static_cast<BYTE>(p[0] * k);
                    p[1] = static_cast<BYTE>(p[1] * k);
                    p[2] = static_cast<BYTE>(p[2] * k);
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

            sR += (255.0f - sR) * tint;
            sG += (255.0f - sG) * tint;
            sB += (255.0f - sB) * tint;

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
    int   kind;
};

inline bool SamePanel(const PanelRec& a, const PanelRec& b)
{
    return a.x0 == b.x0 && a.y0 == b.y0 && a.x1 == b.x1 && a.y1 == b.y1
        && a.radius == b.radius
        && a.kind == b.kind
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
    void AddPanel(int x0, int y0, int x1, int y1, float radius, float tint, int kind = 0)
    {
        if (curCount >= kMaxPanels) {
            return;
        }
        PanelRec& r = cur[curCount++];
        r.x0 = x0; r.y0 = y0; r.x1 = x1; r.y1 = y1;
        r.radius = radius; r.tint = tint; r.kind = kind;
    }

    // 本帧结束：把真实面板表与"已合成的那张"比对，不一致就要求再刷一帧。
    // 返回 true = 调用方应当 InvalidateRect（否则玻璃层会与内容错位一帧）。
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

    bool EnsureBackdrop(HWND hwnd, bool force)
    {
        if (!active) {
            return false;
        }
        if (backdrop.valid && !force && !backdropDirty) {
            return true;
        }
        backdrop.Release();
        backdrop.w = w;
        backdrop.h = h;

        const int bgMode = BackdropMode();
        bool useCaptured = false;
        if (bgMode != 2 && hwnd && IsWindow(hwnd)) {
            POINT origin = { 0, 0 };
            ClientToScreen(hwnd, &origin);
            useCaptured = CaptureRegion(hwnd, origin.x, origin.y, w, h, backdrop.full);
            if (useCaptured && LooksBlank(backdrop.full)) {
                // 全黑/纯色 = 抓失败了（受保护内容、RDP、显卡驱动）
                useCaptured = false;
            }
            // ★★ 自动模式的关键一步：抓到了，但**太素**（窗口后面是白文档）
            //   ⇒ 玻璃没有可折射的内容，效果等于"白玻璃压白背景"= 一张白纸。
            //   这种情况换成内置的设计背景，视觉上才成立。
            if (useCaptured && bgMode == 0 && Colorfulness(backdrop.full) < 10) {
                useCaptured = false;
            }
        }
        if (useCaptured) {
            backdrop.source = 1;
        } else {
            BuildDesignedFull(backdrop);
            backdrop.source = 2;
        }
        BuildBlurLevels(backdrop);
        backdropAt = GetTickCount64();
        backdropDirty = false;
        layerDirty = true;
        return true;
    }

    // 把背景铺底 + 按 used[] 合成面板
    void ComposeLayer()
    {
        if (!layer.bits) {
            return;
        }
        if (glCompose) {
            glCompose(glCtx, backdrop, used, usedCount,
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
        for (int i = 0; i < usedCount; ++i) {
            if (used[i].kind == 1) {
                ComposeGlassChip(layer.bits, w, h, backdrop,
                    used[i].x0, used[i].y0, used[i].x1, used[i].y1,
                    used[i].radius, used[i].tint, dpi, DefaultTheme());
            } else {
                ComposeGlassPanel(layer.bits, w, h, backdrop,
                    used[i].x0, used[i].y0, used[i].x1, used[i].y1,
                    used[i].radius, used[i].tint, dpi, DefaultTheme());
            }
        }
        layerDirty = false;
    }

    // 一帧开始：准备好 layer（玻璃层）。调用方把它 BitBlt 到自己的双缓冲位图上，
    // 再在位图上画内容 —— ★ 不要直接把内容画进这个 DIB（见下面的说明）。
    //   `wantBackdropRefresh` 由调用方的定时器/移动事件决定
    bool Begin(HWND hwnd, int width, int height, float scale, bool wantBackdropRefresh)
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
        if (layerDirty) {
            ComposeLayer();
        }
        curCount = 0;
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
