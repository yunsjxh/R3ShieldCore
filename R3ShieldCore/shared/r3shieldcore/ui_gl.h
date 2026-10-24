#pragma once
//
// ui_gl.h —— 液态玻璃的 **OpenGL 后端**（真正的着色器实现）
//
// 为什么单独一个后端：
//   `ui_material.h` 里的 CPU 合成是"逐条近似"着色器（powf/expf 都换成了多项式）。
//   这里直接把参考项目 `LiquidGlassNative` 的 `GLASS_FS` 搬到 GPU 上跑，
//   得到的是同一份视觉模型**原样**的结果（真高斯模糊、真 fwidth 抗锯齿、
//   真 2.2 次幂衰减），同时把合成成本从 CPU 挪到 GPU。
//
// ★★★ 零额外依赖（关键决策）：
//   参考项目用 GLFW/GLEW/glm，那三样都要跟着发布 DLL。本项目**不引**它们：
//     · 窗口和 GL 上下文用 **WGL** 自己建（`opengl32.dll` 是 Windows 系统 DLL，
//       不需要随包分发任何东西）；
//     · 函数入口用 `wglGetProcAddress` 自己取（等价于 GLEW 干的事，只取用到的那几十个）。
//   ⇒ 发布包里**一个新增文件都没有**，与"不引第三方运行时"的项目约束一致。
//
// ★★ 失败必须能回落：
//   远程桌面 / 虚拟显卡 / 老驱动只有 GL 1.1（微软软件实现）⇒ 建不出 3.3 core
//   ⇒ `Init()` 返回 false ⇒ 调用方自动退回 CPU 合成（`ui_material.h`）。
//   两条路都产出同一块 32bpp DIB，上层（GDI 画内容）完全不知道差别。
//
#include <windows.h>
#include <GL/gl.h>
#include <string.h>

#if defined(_MSC_VER)
#pragma comment(lib, "opengl32.lib")
#endif

// ---------------------------------------------------------------------------
// GL 1.2+ 的常量与入口声明（Windows SDK 的 GL/gl.h 只到 1.1）
// ---------------------------------------------------------------------------
// ★ 只取**用到**的那些：把 glext.h 整份抄进来等于自己维护一个 GLEW。
typedef char GLchar;

#ifndef GL_TEXTURE0
#define GL_TEXTURE0                    0x84C0
#define GL_TEXTURE1                    0x84C1
#define GL_ARRAY_BUFFER                0x8892
#define GL_STATIC_DRAW                 0x88E4
#define GL_FRAGMENT_SHADER             0x8B30
#define GL_VERTEX_SHADER               0x8B31
#define GL_COMPILE_STATUS              0x8B81
#define GL_LINK_STATUS                 0x8B82
#define GL_FRAMEBUFFER                 0x8D40
#define GL_COLOR_ATTACHMENT0           0x8CE0
#define GL_FRAMEBUFFER_COMPLETE        0x8CD5
#define GL_RGBA8                       0x8058
#define GL_BGRA                        0x80E1
#define GL_CLAMP_TO_EDGE               0x812F
#define GL_SCISSOR_TEST                0x0C11
#define GL_UNPACK_ALIGNMENT            0x0CF5
#define GL_PACK_ALIGNMENT              0x0D05
#define GL_STREAM_DRAW                 0x88E0
#define GL_R8                          0x8229
#define GL_RED                         0x1903
#endif

#define R3SC_GLAPI __stdcall

typedef ptrdiff_t GLsizeiptrR3;
typedef GLuint(R3SC_GLAPI* R3PFNGLCREATESHADER)(GLenum);
typedef void(R3SC_GLAPI* R3PFNGLSHADERSOURCE)(GLuint, GLsizei, const GLchar* const*, const GLint*);
typedef void(R3SC_GLAPI* R3PFNGLCOMPILESHADER)(GLuint);
typedef void(R3SC_GLAPI* R3PFNGLGETSHADERIV)(GLuint, GLenum, GLint*);
typedef void(R3SC_GLAPI* R3PFNGLGETSHADERINFOLOG)(GLuint, GLsizei, GLsizei*, GLchar*);
typedef void(R3SC_GLAPI* R3PFNGLDELETESHADER)(GLuint);
typedef GLuint(R3SC_GLAPI* R3PFNGLCREATEPROGRAM)(void);
typedef void(R3SC_GLAPI* R3PFNGLATTACHSHADER)(GLuint, GLuint);
typedef void(R3SC_GLAPI* R3PFNGLLINKPROGRAM)(GLuint);
typedef void(R3SC_GLAPI* R3PFNGLGETPROGRAMIV)(GLuint, GLenum, GLint*);
typedef void(R3SC_GLAPI* R3PFNGLGETPROGRAMINFOLOG)(GLuint, GLsizei, GLsizei*, GLchar*);
typedef void(R3SC_GLAPI* R3PFNGLDELETEPROGRAM)(GLuint);
typedef void(R3SC_GLAPI* R3PFNGLUSEPROGRAM)(GLuint);
typedef GLint(R3SC_GLAPI* R3PFNGLGETUNIFORMLOCATION)(GLuint, const GLchar*);
typedef void(R3SC_GLAPI* R3PFNGLUNIFORM1I)(GLint, GLint);
typedef void(R3SC_GLAPI* R3PFNGLUNIFORM1F)(GLint, GLfloat);
typedef void(R3SC_GLAPI* R3PFNGLUNIFORM2F)(GLint, GLfloat, GLfloat);
typedef void(R3SC_GLAPI* R3PFNGLUNIFORM3F)(GLint, GLfloat, GLfloat, GLfloat);
typedef void(R3SC_GLAPI* R3PFNGLUNIFORM4F)(GLint, GLfloat, GLfloat, GLfloat, GLfloat);
typedef void(R3SC_GLAPI* R3PFNGLACTIVETEXTURE)(GLenum);
typedef void(R3SC_GLAPI* R3PFNGLGENBUFFERS)(GLsizei, GLuint*);
typedef void(R3SC_GLAPI* R3PFNGLBINDBUFFER)(GLenum, GLuint);
typedef void(R3SC_GLAPI* R3PFNGLBUFFERDATA)(GLenum, GLsizeiptrR3, const void*, GLenum);
typedef void(R3SC_GLAPI* R3PFNGLDELETEBUFFERS)(GLsizei, const GLuint*);
typedef void(R3SC_GLAPI* R3PFNGLVERTEXATTRIBPOINTER)(GLuint, GLint, GLenum, GLboolean, GLsizei, const void*);
typedef void(R3SC_GLAPI* R3PFNGLENABLEVERTEXATTRIBARRAY)(GLuint);
typedef void(R3SC_GLAPI* R3PFNGLGENFRAMEBUFFERS)(GLsizei, GLuint*);
typedef void(R3SC_GLAPI* R3PFNGLBINDFRAMEBUFFER)(GLenum, GLuint);
typedef void(R3SC_GLAPI* R3PFNGLFRAMEBUFFERTEXTURE2D)(GLenum, GLenum, GLenum, GLuint, GLint);
typedef GLenum(R3SC_GLAPI* R3PFNGLCHECKFRAMEBUFFERSTATUS)(GLenum);
typedef void(R3SC_GLAPI* R3PFNGLDELETEFRAMEBUFFERS)(GLsizei, const GLuint*);
typedef void(R3SC_GLAPI* R3PFNGLGENVERTEXARRAYS)(GLsizei, GLuint*);
typedef void(R3SC_GLAPI* R3PFNGLBINDVERTEXARRAY)(GLuint);
typedef void(R3SC_GLAPI* R3PFNGLDELETEVERTEXARRAYS)(GLsizei, const GLuint*);

namespace R3ShieldCoreUi {

// ★★ 代次标记（v84）：发布闸门查"GL 后端真的编进了 exe"。
inline constexpr wchar_t kGlMarker[] = L"R3ShieldCoreGL.v84";

struct GlFuncs {
    R3PFNGLACTIVETEXTURE            ActiveTexture = nullptr;    R3PFNGLCREATESHADER             CreateShader = nullptr;
    R3PFNGLSHADERSOURCE             ShaderSource = nullptr;
    R3PFNGLCOMPILESHADER            CompileShader = nullptr;
    R3PFNGLGETSHADERIV              GetShaderiv = nullptr;
    R3PFNGLGETSHADERINFOLOG         GetShaderInfoLog = nullptr;
    R3PFNGLDELETESHADER             DeleteShader = nullptr;
    R3PFNGLCREATEPROGRAM            CreateProgram = nullptr;
    R3PFNGLATTACHSHADER             AttachShader = nullptr;
    R3PFNGLLINKPROGRAM              LinkProgram = nullptr;
    R3PFNGLGETPROGRAMIV             GetProgramiv = nullptr;
    R3PFNGLGETPROGRAMINFOLOG        GetProgramInfoLog = nullptr;
    R3PFNGLDELETEPROGRAM            DeleteProgram = nullptr;
    R3PFNGLUSEPROGRAM               UseProgram = nullptr;
    R3PFNGLGETUNIFORMLOCATION       GetUniformLocation = nullptr;
    R3PFNGLUNIFORM1I                Uniform1i = nullptr;
    R3PFNGLUNIFORM1F                Uniform1f = nullptr;
    R3PFNGLUNIFORM2F                Uniform2f = nullptr;
    R3PFNGLUNIFORM3F                Uniform3f = nullptr;
    R3PFNGLUNIFORM4F                Uniform4f = nullptr;
    R3PFNGLGENBUFFERS               GenBuffers = nullptr;
    R3PFNGLBINDBUFFER               BindBuffer = nullptr;
    R3PFNGLBUFFERDATA               BufferData = nullptr;
    R3PFNGLDELETEBUFFERS            DeleteBuffers = nullptr;
    R3PFNGLVERTEXATTRIBPOINTER      VertexAttribPointer = nullptr;
    R3PFNGLENABLEVERTEXATTRIBARRAY  EnableVertexAttribArray = nullptr;
    R3PFNGLGENFRAMEBUFFERS          GenFramebuffers = nullptr;
    R3PFNGLBINDFRAMEBUFFER          BindFramebuffer = nullptr;
    R3PFNGLFRAMEBUFFERTEXTURE2D     FramebufferTexture2D = nullptr;
    R3PFNGLCHECKFRAMEBUFFERSTATUS   CheckFramebufferStatus = nullptr;
    R3PFNGLDELETEFRAMEBUFFERS       DeleteFramebuffers = nullptr;
    R3PFNGLGENVERTEXARRAYS          GenVertexArrays = nullptr;
    R3PFNGLBINDVERTEXARRAY          BindVertexArray = nullptr;
    R3PFNGLDELETEVERTEXARRAYS       DeleteVertexArrays = nullptr;
};

typedef HGLRC(WINAPI* R3PFNWGLCREATECONTEXTATTRIBS)(HDC, HGLRC, const int*);

// ---------------------------------------------------------------------------
// 着色器源码
// ---------------------------------------------------------------------------
//
// ★ 坐标约定：**y 向下**（与 GDI 一致）。`gl_FragCoord` 的 y 原点在**下**，
//   所以着色器里统一用 `p.y = uRes.y - gl_FragCoord.y` 翻到"上到下"。
//   ★ 这一步漏了会得到**上下颠倒**的玻璃（折射方向全反），而看起来"像是"
//     画得没问题 —— 只有对照背景才能发现。

inline const char* GlQuadVS()
{
    return R"(#version 330 core
layout(location=0) in vec2 aPos;
out vec2 vUV;
void main(){ vUV = aPos*0.5+0.5; gl_Position = vec4(aPos,0.0,1.0); }
)";
}

// ★ 底图 = **模糊后的背景** + 半透明白纱。
//   这就是"背景模糊半透明"本身：整个窗口的底是糊的，纱给深色文字留可读性。
//
// ★★★ v102：**必须把 V 翻过来**（`1.0 - vUV.y`）。
//
//   抓屏进 GL 的那张图是 **top-down** 的（DIB 负高度，第 0 行是屏幕最上面），
//   而 GL 的纹理 v=0 指的是**数据第 0 行**，同时 clip space 的 y=-1 才是屏幕
//   下方 ⇒ `vUV = aPos*0.5+0.5` 会把"屏幕最上面那行"画到窗口**最下面**。
//
//   为什么玻璃面板没跟着翻：面板着色器用的是
//   `p.y = uRes.y - gl_FragCoord.y`（**y 向下**，和 GDI 一致）再算 uv，
//   正好又翻了一次 ⇒ 面板是对的、只有这层底图是反的。
//   症状就是用户看到的："底面背景上下颠倒，但各个框里又是正的"。
//
//   ★ 以前没被发现，是因为背景被 v89 的去饱和+抬阴影洗成了一片灰白，
//     翻不翻看不出来；v96 把压暗降到 0.10 之后结构回来了，这个 bug 才露出来。
inline const char* GlBaseFS()
{
    return R"(#version 330 core
in vec2 vUV;
out vec4 fragColor;
uniform sampler2D uTex;
uniform float uVeil;
void main(){
  vec3 c = texture(uTex, vec2(vUV.x, 1.0 - vUV.y)).rgb;
  fragColor = vec4(mix(c, vec3(1.0), uVeil), 1.0);
}
)";
}

inline const char* GlDownFS()
{
    return R"(#version 330 core
in vec2 vUV;
out vec4 fragColor;
uniform sampler2D uTex;
uniform vec2 uTexel;
void main(){
  vec2 o = uTexel * 0.5;
  vec3 s = texture(uTex, vUV + vec2(-o.x,-o.y)).rgb
         + texture(uTex, vUV + vec2( o.x,-o.y)).rgb
         + texture(uTex, vUV + vec2(-o.x, o.y)).rgb
         + texture(uTex, vUV + vec2( o.x, o.y)).rgb;
  fragColor = vec4(s * 0.25, 1.0);
}
)";
}

inline const char* GlBlurFS()
{
    return R"(#version 330 core
in vec2 vUV;
out vec4 fragColor;
uniform sampler2D uTex;
uniform vec2 uTexel;
uniform vec2 uDir;
void main(){
  vec3 s = texture(uTex, vUV).rgb * 0.227027;
  s += (texture(uTex, vUV + uDir*uTexel*1.3846).rgb
      + texture(uTex, vUV - uDir*uTexel*1.3846).rgb) * 0.3162162;
  s += (texture(uTex, vUV + uDir*uTexel*3.2308).rgb
      + texture(uTex, vUV - uDir*uTexel*3.2308).rgb) * 0.0702702;
  fragColor = vec4(s, 1.0);
}
)";
}

inline const char* GlBandFS()
{
    return R"(#version 330 core
in vec2 vUV;
out vec4 fragColor;
uniform float uAlpha;
void main(){ fragColor = vec4(1.0, 1.0, 1.0, uAlpha); }
)";
}

// ★★★ 玻璃面板：参考项目 GLASS_FS 的移植（去掉图标/滑块，保留材质本身）
inline const char* GlGlassFS()
{
    return R"(#version 330 core
out vec4 fragColor;

uniform sampler2D uBlurA;
uniform sampler2D uBlurB;
uniform vec2  uRes;
uniform vec2  uCenter;
uniform vec2  uHalf;
uniform float uRadius;
uniform float uTint;
// ★ v85：tint 的**颜色**。v84 之前隐含为白色（mix(blur, 1.0, tint)），
//   于是所有玻璃都是白的；这里把它参数化，才能做出彩色玻璃与凹槽。
uniform vec3  uTintCol;
uniform float uDpi;
uniform float uBend;
uniform float uBand;
uniform float uChroma;
uniform float uBlurBlend;
uniform float uRim;
uniform float uSpec;
uniform float uNoise;
uniform float uShadowR;
uniform float uShadowOff;
uniform float uShadowA;

float sdRoundBox(vec2 p, vec2 b, float r){
  vec2 q = abs(p) - b + r;
  return min(max(q.x,q.y),0.0) + length(max(q,0.0)) - r;
}
float hash21(vec2 q){
  q = fract(q * vec2(127.1, 311.7));
  q += dot(q, q + 34.56);
  return fract(q.x * q.y);
}

void main(){
  vec2 p = vec2(gl_FragCoord.x, uRes.y - gl_FragCoord.y);
  vec2 d = p - uCenter;
  float sd = sdRoundBox(d, uHalf, uRadius);
  float margin = uShadowR + 2.0;
  if (sd > margin) { discard; }

  vec2 uv = p / uRes;

  // ★★★ 外侧光晕（v87）：白玻璃**不投黑影像**，而是把光散到周围。
  //
  //   这一条是参考项目 `LiquidGlassControls` 的做法，本项目一直没搬过来：
  //   原来这里输出的是 vec4(0,0,0,a) 的**黑色**投影，alpha 0.24、半径 24。
  //   一屏十几块面板（顶栏 + 页签 + 6 张卡 + 十几个按钮），每块都往下压一圈黑，
  //   叠加之后整片背景从 236 掉到 203 —— 卡片和背景只差 6 级，于是"浮不起来"。
  //   白色光晕反过来：越靠近玻璃越亮，卡片是"发光浮起来"而不是"压出一个坑"。
  float sdSh = sdRoundBox(d - vec2(0.0, uShadowOff * 0.35), uHalf, uRadius);
  float sh = clamp(1.0 - sdSh / uShadowR, 0.0, 1.0);
  float glow = sh * sh * uShadowA;

  if (sd >= 0.5) {
    fragColor = vec4(vec3(1.0), glow);
    return;
  }

  // 外法线（数值梯度）
  float e = 0.75;
  vec2 g = vec2(
    sdRoundBox(d + vec2(e,0.0), uHalf, uRadius) - sdRoundBox(d - vec2(e,0.0), uHalf, uRadius),
    sdRoundBox(d + vec2(0.0,e), uHalf, uRadius) - sdRoundBox(d - vec2(0.0,e), uHalf, uRadius));
  vec2 n = g / max(length(g), 1e-5);

  // 折射场：贴边最强，往里 2.2 次幂衰减
  float t = clamp(-sd / (uBand * uDpi), 0.0, 1.0);
  float bendP = pow(1.0 - t, 2.2);
  vec2 off = n * bendP * uBend * uDpi / uRes;

  // 色散：R/B 沿法线反向微分离（只在最外 2~3px）
  float caK = uChroma * bendP;
  vec3 bl;
  bl.r = mix(texture(uBlurA, uv + off*(1.0+caK)).r, texture(uBlurB, uv + off*(1.0+caK)).r, uBlurBlend);
  bl.g = mix(texture(uBlurA, uv + off            ).g, texture(uBlurB, uv + off            ).g, uBlurBlend);
  bl.b = mix(texture(uBlurA, uv + off*(1.0-caK)).b, texture(uBlurB, uv + off*(1.0-caK)).b, uBlurBlend);

  // 磨砂：轻微去饱和 + 提亮
  float luma = dot(bl, vec3(0.299, 0.587, 0.114));
  bl = mix(bl, vec3(luma), 0.030) * 1.02;

  vec3 col = mix(bl, uTintCol, uTint);

  // 顶部到底部极淡的压暗：玻璃总比它后面的世界暗一点点。
  // 有这 10% 的差，深色字才站得住；再多就失去通透了。
  float hN = (p.y - (uCenter.y - uHalf.y)) / max(2.0 * uHalf.y, 1e-3);
  col *= mix(0.985, 1.025, clamp(hN, 0.0, 1.0));

  // 内侧 rim 高光
  // ★★ 衰减宽度 2.6 → 5.5（和参考项目一致）。
  //   2.6px 时边缘是一条 1~2px 的白线，紧跟着就掉回面板内部 =>
  //   读起来是"白线 + 内侧灰带"，像一圈脏描边。5.5px 才有"厚度"。
  float rim = clamp(exp(sd / (5.5 * uDpi)), 0.0, 1.0);
  col = mix(col, vec3(1.0), rim * uRim * 0.72);

  // 最外 1px 的"唇线"：一条更窄更亮的高光，给边缘一个明确的终点。
  // 没有它，放宽后的 rim 会让边缘看起来发毛（找不到边在哪）。
  float lip = clamp(exp(sd / (0.9 * uDpi)), 0.0, 1.0);
  col = mix(col, vec3(1.0), lip * uRim * 0.60);

  // 顶部镜面光带
  float topY = uCenter.y - uHalf.y + 1.5 * uDpi;
  col = mix(col, vec3(1.0), exp(-abs(p.y - topY) * 1.4 / uDpi) * uSpec);

  // 磨砂颗粒
  col += (hash21(p) - 0.5) * uNoise;

  float aa = max(fwidth(sd) * 0.75, 0.4);
  float inside = smoothstep(aa, -aa, sd);

  // 面板内 = 玻璃色；面板外 = 白色光晕。两者在 AA 带上线性交接。
  float alpha = inside + (1.0 - inside) * glow;
  vec3 rgb = col * inside + vec3(1.0) * (1.0 - inside) * glow;

  // ★★★ v87：**还原成非预乘 alpha** 再输出。
  //
  //   上面的 rgb 是**预乘**的（已经乘过覆盖率 inside）。而这一层用的混合是
  //   glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA) —— 它会把 rgb 再乘一次
  //   alpha。于是抗锯齿带上（inside 从 0 到 1 的那 1~2px）颜色被乘了两次，
  //   结果就是卡片边缘有一圈**暗线**：看起来像描了一圈脏边，
  //   而卡片内部和背景的亮度其实是对的（这就是边缘很黑但采样又是白的那个怪现象）。
  //
  //   除回去之后：inside=1 ⇒ rgb/a = col（原色）；inside=0 ⇒ rgb/a = 白（光晕）。
  fragColor = vec4(alpha > 0.001 ? rgb / alpha : vec3(0.0), alpha);
}
)";
}

// ---------------------------------------------------------------------------
// GlGlass —— 上下文 + 程序 + 纹理 + FBO
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ★★ v86：内容层挂载点
//
// 参考项目 `LiquidGlassControls` 把"玻璃层 → 实心层 → 图标层 → 文字层"
// 全部画在同一个 FBO 里，最后一次性上屏。本项目原来只把**玻璃**交给 GL，
// 文字/柱状条还是 GDI 画在兼容位图上 —— 于是玻璃再准，界面看起来仍是
// "GDI 界面上贴了几张玻璃卡"。
//
// 这里开一个回调：`GlGlass::Render` 在"面板画完、回读之前"把它调起来，
// 此时 FBO 已绑定、视口已设好、GL 上下文 current ⇒ 实现方（ui_scene.h 的
// `Scene`）可以自由地画实心/图标/文字。
//
// 用回调而不是把顶点类型搬进本头：`ui_gl.h` 保持"只管玻璃"，
// 场景那一层（含字形图集）全在 `ui_scene.h` 里，两个头互不污染。
// ---------------------------------------------------------------------------
struct GlSceneHook {
    virtual ~GlSceneHook() {}
    virtual void Draw(GlFuncs& g, int w, int h, float dpi) = 0;
};

struct GlGlass {
    struct PanelDraw {
        int   x0, y0, x1, y1;
        float radius;
        float tint;
        int   kind;      // 0=面板 1=玻璃片（不做折射） 2=凹槽（无外投影）
        // ★ v85：tint 的颜色（与 PanelRec 一一对应，桥只做搬运）
        unsigned char cr = 255, cg = 255, cb = 255;
    };

    HWND   dummyWnd = nullptr;
    HDC    dummyDc  = nullptr;
    HGLRC  ctx      = nullptr;
    GlFuncs g{};
    bool   ready    = false;
    int    failStage = 0;        // 1=窗口 2=像素格式 3=上下文/入口 4=着色器 5=FBO
    char   info[192] = {};

    GLuint pBase = 0, pDown = 0, pBlur = 0, pBand = 0, pGlass = 0;
    GLuint vao = 0, vbo = 0;

    GLuint texFull = 0;
    GLuint texA[2] = { 0, 0 };
    GLuint texB[2] = { 0, 0 };
    GLuint fboA[2] = { 0, 0 };
    GLuint fboB[2] = { 0, 0 };
    GLuint fboOut = 0, texOut = 0;
    int    w = 0, h = 0, aw = 0, ah = 0, bw = 0, bh = 0;
    bool   blurReady = false;     // ★ v86：模糊链结果是否已就绪（跨帧复用）

    bool Ready() const { return ready; }

    // ---------------------------------------------------------------- 初始化
    bool Init()
    {
        if (ready) {
            return true;
        }
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"R3ShieldCoreGlDummy";
        RegisterClassExW(&wc);
        dummyWnd = CreateWindowExW(0, wc.lpszClassName, L"", WS_OVERLAPPEDWINDOW,
            0, 0, 8, 8, nullptr, nullptr, wc.hInstance, nullptr);
        if (!dummyWnd) {
            failStage = 1;
            return false;
        }
        dummyDc = GetDC(dummyWnd);
        if (!dummyDc) {
            failStage = 1;
            return false;
        }

        PIXELFORMATDESCRIPTOR pfd = {};
        pfd.nSize = sizeof(pfd);
        pfd.nVersion = 1;
        pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
        pfd.iPixelType = PFD_TYPE_RGBA;
        pfd.cColorBits = 32;
        pfd.cAlphaBits = 8;
        pfd.iLayerType = PFD_MAIN_PLANE;
        const int pf = ChoosePixelFormat(dummyDc, &pfd);
        if (!pf || !SetPixelFormat(dummyDc, pf, &pfd)) {
            failStage = 2;
            return false;
        }

        // 先建一个 legacy 上下文，只为拿到 wglCreateContextAttribsARB
        HGLRC legacy = wglCreateContext(dummyDc);
        if (!legacy) {
            failStage = 3;
            return false;
        }
        if (!wglMakeCurrent(dummyDc, legacy)) {
            wglDeleteContext(legacy);
            failStage = 3;
            return false;
        }
        auto createCtx = reinterpret_cast<R3PFNWGLCREATECONTEXTATTRIBS>(
            wglGetProcAddress("wglCreateContextAttribsARB"));
        HGLRC core = nullptr;
        if (createCtx) {
            const int attribs[] = {
                0x2091, 3,           // WGL_CONTEXT_MAJOR_VERSION_ARB
                0x2092, 3,           // WGL_CONTEXT_MINOR_VERSION_ARB
                0x9126, 0x00000001,  // WGL_CONTEXT_PROFILE_MASK_ARB = CORE
                0
            };
            core = createCtx(dummyDc, nullptr, attribs);
        }
        wglMakeCurrent(nullptr, nullptr);
        wglDeleteContext(legacy);
        if (!core) {
            // 只有 GL 1.1（微软软件实现 / 老驱动）⇒ 交给 CPU 后端
            failStage = 3;
            return false;
        }
        if (!wglMakeCurrent(dummyDc, core)) {
            wglDeleteContext(core);
            failStage = 3;
            return false;
        }
        ctx = core;

        if (!LoadFuncs()) {
            failStage = 3;
            return false;
        }

        pBase = MakeProgram(GlQuadVS(), GlBaseFS());
        pDown = MakeProgram(GlQuadVS(), GlDownFS());
        pBlur = MakeProgram(GlQuadVS(), GlBlurFS());
        pBand = MakeProgram(GlQuadVS(), GlBandFS());
        pGlass = MakeProgram(GlQuadVS(), GlGlassFS());
        if (!pBase || !pDown || !pBlur || !pBand || !pGlass) {
            failStage = 4;
            return false;
        }

        g.GenVertexArrays(1, &vao);
        g.BindVertexArray(vao);
        g.GenBuffers(1, &vbo);
        g.BindBuffer(GL_ARRAY_BUFFER, vbo);
        const float quad[] = { -1, -1, 1, -1, -1, 1, 1, 1 };
        g.BufferData(GL_ARRAY_BUFFER, sizeof(quad), quad, GL_STATIC_DRAW);
        g.EnableVertexAttribArray(0);
        g.VertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 2 * (GLsizei)sizeof(float), nullptr);

        glDisable(GL_DEPTH_TEST);
        glDisable(GL_CULL_FACE);

        const char* ver = reinterpret_cast<const char*>(glGetString(GL_VERSION));
        if (ver) {
            strncpy_s(info, sizeof(info), ver, _TRUNCATE);
        }
        ready = true;
        return true;
    }

    void Shutdown()
    {
        if (!ctx) {
            return;
        }
        wglMakeCurrent(dummyDc, ctx);
        ReleaseTargets();
        if (vbo) { g.DeleteBuffers(1, &vbo); vbo = 0; }
        if (vao) { g.DeleteVertexArrays(1, &vao); vao = 0; }
        GLuint* progs[5] = { &pBase, &pDown, &pBlur, &pBand, &pGlass };
        for (int i = 0; i < 5; ++i) {
            if (*progs[i]) {
                g.DeleteProgram(*progs[i]);
                *progs[i] = 0;
            }
        }
        wglMakeCurrent(nullptr, nullptr);
        wglDeleteContext(ctx);
        ctx = nullptr;
        if (dummyDc) { ReleaseDC(dummyWnd, dummyDc); dummyDc = nullptr; }
        if (dummyWnd) { DestroyWindow(dummyWnd); dummyWnd = nullptr; }
        ready = false;
    }

    ~GlGlass() { Shutdown(); }

    // ---------------------------------------------------------------- 渲染
    bool Render(const BYTE* bgBgra, int bgW, int bgH,
                const PanelDraw* panels, int panelCount,
                int headerBand, float headerVeil,
                int outW, int outH, float dpi, float baseVeil,
                BYTE* outBgra, GlSceneHook* scene = nullptr,
                bool refreshBackdrop = true)
    {
        if (!ready || !bgBgra || !outBgra || outW <= 0 || outH <= 0) {
            return false;
        }
        wglMakeCurrent(dummyDc, ctx);
        if (!EnsureTargets(outW, outH)) {
            return false;
        }

        // ★★ v86：背景没变就**跳过**上传 + 模糊链。
        //   原来是"layerDirty 才重建"，所以每帧最多跑一次；现在内容层每帧都要
        //   重画（计数器在动），如果跟着每帧跑一遍抓屏上传 + 5 遍高斯，
        //   光这一块就吃掉 3~5ms。背景只在抓屏刷新时才变 ⇒ 用 `refreshBackdrop`
        //   卡住，模糊结果留在纹理里跨帧复用。
        const bool needBlur = refreshBackdrop || !blurReady;
        if (needBlur) {
        // 上传背景原图（BGRA 直接进 GL_BGRA）
        g.ActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, texFull);
        glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, bgW, bgH, 0,
            GL_BGRA, GL_UNSIGNED_BYTE, bgBgra);
        SetClampLinear();

        glDisable(GL_BLEND);
        // 1/2 降采样
        BindFbo(fboA[0]);
        glViewport(0, 0, aw, ah);
        UseQuad(pDown);
        glBindTexture(GL_TEXTURE_2D, texFull);
        g.Uniform2f(Loc(pDown, "uTexel"), 1.0f / (float)bgW, 1.0f / (float)bgH);
        g.Uniform1i(Loc(pDown, "uTex"), 0);
        DrawQuad();
        // 高斯 H/V ×2
        for (int i = 0; i < 3; ++i) {
            BindFbo(fboA[1]);
            glViewport(0, 0, aw, ah);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texA[0]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 2.0f / (float)aw, 2.0f / (float)ah);
            g.Uniform2f(Loc(pBlur, "uDir"), 1.0f, 0.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
            BindFbo(fboA[0]);
            glViewport(0, 0, aw, ah);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texA[1]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 2.0f / (float)aw, 2.0f / (float)ah);
            g.Uniform2f(Loc(pBlur, "uDir"), 0.0f, 1.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
        }
        // 1/4
        BindFbo(fboB[0]);
        glViewport(0, 0, bw, bh);
        UseQuad(pDown);
        glBindTexture(GL_TEXTURE_2D, texA[0]);
        g.Uniform2f(Loc(pDown, "uTexel"), 1.0f / (float)aw, 1.0f / (float)ah);
        g.Uniform1i(Loc(pDown, "uTex"), 0);
        DrawQuad();
        for (int i = 0; i < 2; ++i) {
            BindFbo(fboB[1]);
            glViewport(0, 0, bw, bh);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texB[0]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 2.0f / (float)bw, 2.0f / (float)bh);
            g.Uniform2f(Loc(pBlur, "uDir"), 1.0f, 0.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
            BindFbo(fboB[0]);
            glViewport(0, 0, bw, bh);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texB[1]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 2.0f / (float)bw, 2.0f / (float)bh);
            g.Uniform2f(Loc(pBlur, "uDir"), 0.0f, 1.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
        }

        // 输出：底图 + 顶栏薄纱 + 面板
        blurReady = true;
        }   // ← needBlur

        BindFbo(fboOut);
        glViewport(0, 0, outW, outH);
        glDisable(GL_SCISSOR_TEST);
        glDisable(GL_BLEND);
        UseQuad(pBase);
        g.ActiveTexture(GL_TEXTURE0);
        // ★★ 绑定 **texA[0]**（模糊版），不是 texFull —— 整个窗口的底必须是糊的。
        glBindTexture(GL_TEXTURE_2D, texA[0]);
        g.Uniform1i(Loc(pBase, "uTex"), 0);
        g.Uniform1f(Loc(pBase, "uVeil"), baseVeil);
        DrawQuad();

        if (headerBand > 0 && headerVeil > 0.0f) {
            glEnable(GL_BLEND);
            glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
            const int band = headerBand < outH ? headerBand : outH;
            glViewport(0, outH - band, outW, band);
            UseQuad(pBand);
            g.Uniform1f(Loc(pBand, "uAlpha"), headerVeil);
            DrawQuad();
            glViewport(0, 0, outW, outH);
        }

        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        glEnable(GL_SCISSOR_TEST);
        UseQuad(pGlass);
        g.ActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, texA[0]);
        g.Uniform1i(Loc(pGlass, "uBlurA"), 0);
        g.ActiveTexture(GL_TEXTURE1);
        glBindTexture(GL_TEXTURE_2D, texB[0]);
        g.Uniform1i(Loc(pGlass, "uBlurB"), 1);
        g.Uniform2f(Loc(pGlass, "uRes"), (float)outW, (float)outH);
        g.Uniform1f(Loc(pGlass, "uDpi"), dpi);
        g.Uniform1f(Loc(pGlass, "uBlurBlend"), 0.42f);

        for (int i = 0; i < panelCount; ++i) {
            SetPanelUniforms(panels[i], dpi);
            DrawOnePanel(panels[i], outW, outH, dpi);
        }

        // ★★ v86：内容层（实心 / 图标 / 文字）画在面板之上、回读之前。
        //   ★★★ 必须**先把 viewport 复原**：`DrawOnePanel` 是逐块设 viewport 的
        //   （把 quad 限制在包围盒里），循环结束后 viewport 还停在**最后一块面板**
        //   上。忘了复原 ⇒ 所有内容都被裁进那一小块，症状是"内容全没了"，
        //   而右下角某处会莫名其妙多出一团字（踩过）。
        //   scissor 同理：面板那一段是逐块设的，留着会裁掉内容。
        glDisable(GL_SCISSOR_TEST);
        glViewport(0, 0, outW, outH);
        if (scene) {
            scene->Draw(g, outW, outH, dpi);
        }
        glViewport(0, 0, outW, outH);

        glDisable(GL_SCISSOR_TEST);
        glDisable(GL_BLEND);

        BindFbo(fboOut);
        glPixelStorei(GL_PACK_ALIGNMENT, 4);
        ReadbackFlip(outW, outH, outBgra);
        BindFbo(0);
        return true;
    }

private:
    void BindFbo(GLuint f) { g.BindFramebuffer(GL_FRAMEBUFFER, f); }
    GLint Loc(GLuint prog, const char* name) { return g.GetUniformLocation(prog, name); }
    void UseQuad(GLuint prog) { g.UseProgram(prog); g.BindVertexArray(vao); }
    void DrawQuad() { glDrawArrays(GL_TRIANGLE_STRIP, 0, 4); }

    void SetClampLinear()
    {
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    }

    bool LoadFuncs()
    {
        bool ok = true;
        struct Entry { const char* name; void** slot; };
        const Entry entries[] = {
            { "glActiveTexture",           reinterpret_cast<void**>(&g.ActiveTexture) },
            { "glCreateShader",            reinterpret_cast<void**>(&g.CreateShader) },
            { "glShaderSource",            reinterpret_cast<void**>(&g.ShaderSource) },
            { "glCompileShader",           reinterpret_cast<void**>(&g.CompileShader) },
            { "glGetShaderiv",             reinterpret_cast<void**>(&g.GetShaderiv) },
            { "glGetShaderInfoLog",        reinterpret_cast<void**>(&g.GetShaderInfoLog) },
            { "glDeleteShader",            reinterpret_cast<void**>(&g.DeleteShader) },
            { "glCreateProgram",           reinterpret_cast<void**>(&g.CreateProgram) },
            { "glAttachShader",            reinterpret_cast<void**>(&g.AttachShader) },
            { "glLinkProgram",             reinterpret_cast<void**>(&g.LinkProgram) },
            { "glGetProgramiv",            reinterpret_cast<void**>(&g.GetProgramiv) },
            { "glGetProgramInfoLog",       reinterpret_cast<void**>(&g.GetProgramInfoLog) },
            { "glDeleteProgram",           reinterpret_cast<void**>(&g.DeleteProgram) },
            { "glUseProgram",              reinterpret_cast<void**>(&g.UseProgram) },
            { "glGetUniformLocation",      reinterpret_cast<void**>(&g.GetUniformLocation) },
            { "glUniform1i",               reinterpret_cast<void**>(&g.Uniform1i) },
            { "glUniform1f",               reinterpret_cast<void**>(&g.Uniform1f) },
            { "glUniform2f",               reinterpret_cast<void**>(&g.Uniform2f) },
            { "glUniform3f",               reinterpret_cast<void**>(&g.Uniform3f) },
            { "glUniform4f",               reinterpret_cast<void**>(&g.Uniform4f) },
            { "glGenBuffers",              reinterpret_cast<void**>(&g.GenBuffers) },
            { "glBindBuffer",              reinterpret_cast<void**>(&g.BindBuffer) },
            { "glBufferData",              reinterpret_cast<void**>(&g.BufferData) },
            { "glDeleteBuffers",           reinterpret_cast<void**>(&g.DeleteBuffers) },
            { "glVertexAttribPointer",     reinterpret_cast<void**>(&g.VertexAttribPointer) },
            { "glEnableVertexAttribArray", reinterpret_cast<void**>(&g.EnableVertexAttribArray) },
            { "glGenFramebuffers",         reinterpret_cast<void**>(&g.GenFramebuffers) },
            { "glBindFramebuffer",         reinterpret_cast<void**>(&g.BindFramebuffer) },
            { "glFramebufferTexture2D",    reinterpret_cast<void**>(&g.FramebufferTexture2D) },
            { "glCheckFramebufferStatus",  reinterpret_cast<void**>(&g.CheckFramebufferStatus) },
            { "glDeleteFramebuffers",      reinterpret_cast<void**>(&g.DeleteFramebuffers) },
            { "glGenVertexArrays",         reinterpret_cast<void**>(&g.GenVertexArrays) },
            { "glBindVertexArray",         reinterpret_cast<void**>(&g.BindVertexArray) },
            { "glDeleteVertexArrays",      reinterpret_cast<void**>(&g.DeleteVertexArrays) },
        };
        for (const Entry& e : entries) {
            *e.slot = reinterpret_cast<void*>(wglGetProcAddress(e.name));
            if (!*e.slot) {
                ok = false;
            }
        }
        return ok;
    }

    GLuint CompileShader(GLenum type, const char* src)
    {
        GLuint s = g.CreateShader(type);
        if (!s) {
            return 0;
        }
        g.ShaderSource(s, 1, &src, nullptr);
        g.CompileShader(s);
        GLint okv = 0;
        g.GetShaderiv(s, GL_COMPILE_STATUS, &okv);
        if (!okv) {
            char log[1024] = {};
            g.GetShaderInfoLog(s, sizeof(log), nullptr, log);
            OutputDebugStringA(log);
            g.DeleteShader(s);
            return 0;
        }
        return s;
    }

    GLuint MakeProgram(const char* vs, const char* fs)
    {
        GLuint v = CompileShader(GL_VERTEX_SHADER, vs);
        GLuint f = CompileShader(GL_FRAGMENT_SHADER, fs);
        if (!v || !f) {
            if (v) g.DeleteShader(v);
            if (f) g.DeleteShader(f);
            return 0;
        }
        GLuint p = g.CreateProgram();
        g.AttachShader(p, v);
        g.AttachShader(p, f);
        g.LinkProgram(p);
        g.DeleteShader(v);
        g.DeleteShader(f);
        GLint okv = 0;
        g.GetProgramiv(p, GL_LINK_STATUS, &okv);
        if (!okv) {
            char log[1024] = {};
            g.GetProgramInfoLog(p, sizeof(log), nullptr, log);
            OutputDebugStringA(log);
            g.DeleteProgram(p);
            return 0;
        }
        return p;
    }

    GLuint MakeTex(int tw, int th)
    {
        GLuint t = 0;
        glGenTextures(1, &t);
        glBindTexture(GL_TEXTURE_2D, t);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, tw, th, 0, GL_BGRA, GL_UNSIGNED_BYTE, nullptr);
        SetClampLinear();
        return t;
    }

    GLuint MakeFbo(GLuint tex)
    {
        GLuint f = 0;
        g.GenFramebuffers(1, &f);
        BindFbo(f);
        g.FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex, 0);
        if (g.CheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
            g.DeleteFramebuffers(1, &f);
            f = 0;
        }
        BindFbo(0);
        return f;
    }

    void ReleaseTargets()
    {
        if (texFull) { glDeleteTextures(1, &texFull); texFull = 0; }
        for (int i = 0; i < 2; ++i) {
            if (texA[i]) { glDeleteTextures(1, &texA[i]); texA[i] = 0; }
            if (texB[i]) { glDeleteTextures(1, &texB[i]); texB[i] = 0; }
            if (fboA[i]) { g.DeleteFramebuffers(1, &fboA[i]); fboA[i] = 0; }
            if (fboB[i]) { g.DeleteFramebuffers(1, &fboB[i]); fboB[i] = 0; }
        }
        if (texOut) { glDeleteTextures(1, &texOut); texOut = 0; }
        if (fboOut) { g.DeleteFramebuffers(1, &fboOut); fboOut = 0; }
        w = h = aw = ah = bw = bh = 0;
        blurReady = false;
    }

    bool EnsureTargets(int outW, int outH)
    {
        if (outW == w && outH == h && fboOut) {
            return true;
        }
        ReleaseTargets();
        w = outW; h = outH;
        aw = outW / 2 > 0 ? outW / 2 : 1; ah = outH / 2 > 0 ? outH / 2 : 1;
        bw = outW / 4 > 0 ? outW / 4 : 1; bh = outH / 4 > 0 ? outH / 4 : 1;

        texFull = MakeTex(outW, outH);
        for (int i = 0; i < 2; ++i) {
            texA[i] = MakeTex(aw, ah);
            fboA[i] = MakeFbo(texA[i]);
            texB[i] = MakeTex(bw, bh);
            fboB[i] = MakeFbo(texB[i]);
        }
        texOut = MakeTex(outW, outH);
        fboOut = MakeFbo(texOut);
        if (!fboOut || !fboA[0] || !fboA[1] || !fboB[0] || !fboB[1]) {
            failStage = 5;
            return false;
        }
        return true;
    }

    void SetPanelUniforms(const PanelDraw& pd, float dpi)
    {
        const float cx = (pd.x0 + pd.x1) * 0.5f;
        const float cy = (pd.y0 + pd.y1) * 0.5f;
        const float hx = (pd.x1 - pd.x0) * 0.5f;
        const float hy = (pd.y1 - pd.y0) * 0.5f;
        const bool chip = (pd.kind == 1);
        const bool well = (pd.kind == 2);
        g.Uniform2f(Loc(pGlass, "uCenter"), cx, cy);
        g.Uniform2f(Loc(pGlass, "uHalf"), hx, hy);
        g.Uniform1f(Loc(pGlass, "uRadius"), pd.radius);
        g.Uniform1f(Loc(pGlass, "uTint"), pd.tint);
        g.Uniform3f(Loc(pGlass, "uTintCol"),
            (float)pd.cr / 255.0f, (float)pd.cg / 255.0f, (float)pd.cb / 255.0f);
        // ★ 小控件也给**轻微**折射：用户明确要"按钮和框体都是液态玻璃"，
        //   完全不做折射的 tint 片看起来只是一块淡色圆角矩形。
        //   但幅度必须小（5px / 带宽 6px）：半径小的时候大折射会把字底糊成一团。
        // ★ v85：凹槽（kind 2）折射再小一档（3px）—— 槽里要放滑块/填充条，
        //   折射一大，槽底的颜色就被搅动，看起来像"槽里有水在动"。
        const float bend = well ? 3.0f : (chip ? 5.0f : 14.0f);
        g.Uniform1f(Loc(pGlass, "uBend"), bend);
        g.Uniform1f(Loc(pGlass, "uBand"), chip || well ? 6.0f : 9.0f);
        g.Uniform1f(Loc(pGlass, "uChroma"), chip || well ? 0.16f : 0.34f);
        g.Uniform1f(Loc(pGlass, "uRim"), well ? 0.34f : 0.46f);
        g.Uniform1f(Loc(pGlass, "uSpec"), well ? 0.05f : (chip ? 0.11f : 0.12f));
        g.Uniform1f(Loc(pGlass, "uNoise"), 0.018f);
        // ★ v87：光晕半径 24 → 40（参考项目同值）。光晕比投影要铺得开，
        //   否则它只是一圈"亮描边"，读不出"玻璃把光散出来"。
        g.Uniform1f(Loc(pGlass, "uShadowR"), (chip || well ? 14.0f : 40.0f) * dpi);
        g.Uniform1f(Loc(pGlass, "uShadowOff"), (chip || well ? 2.0f : 3.0f) * dpi);
        // 凹槽不发光：槽是"凹下去"的，往外散光方向正好反了。
        // ★ v87：0.30 → 0.14。光晕只是"把光散到边缘"，不能亮到把缝照得比卡片还亮 ——
        //   那样层级就反了（缝 > 卡片），整页看起来是一张亮纸而不是几块玻璃。
        g.Uniform1f(Loc(pGlass, "uShadowA"), well ? 0.0f : (chip ? 0.12f : 0.40f));
    }

    void DrawOnePanel(const PanelDraw& pd, int outW, int outH, float dpi)
    {
        // ★ v87：quad 必须包住光晕，否则光晕被裁成一条硬边（= 又变回"描边"）。
        const float marginPx = (pd.kind == 0) ? 46.0f : (pd.kind == 2 ? 6.0f : 18.0f);
        const float margin = marginPx * dpi + 2.0f;
        int x0 = (int)(pd.x0 - margin);
        int y0 = (int)(pd.y0 - margin);
        int x1 = (int)(pd.x1 + margin);
        int y1 = (int)(pd.y1 + margin);
        if (x0 < 0) x0 = 0;
        if (y0 < 0) y0 = 0;
        if (x1 > outW) x1 = outW;
        if (y1 > outH) y1 = outH;
        if (x1 <= x0 || y1 <= y0) {
            return;
        }
        // GL 窗口坐标原点在左下 ⇒ 竖直翻一下
        glViewport(x0, outH - y1, x1 - x0, y1 - y0);
        glScissor(x0, outH - y1, x1 - x0, y1 - y0);
        DrawQuad();
    }

    void ReadbackFlip(int outW, int outH, BYTE* outBgra)
    {
        const size_t rowBytes = (size_t)outW * 4;
        BYTE* tmp = static_cast<BYTE*>(malloc(rowBytes * (size_t)outH));
        if (!tmp) {
            return;
        }
        glReadPixels(0, 0, outW, outH, GL_BGRA, GL_UNSIGNED_BYTE, tmp);
        for (int y = 0; y < outH; ++y) {
            memcpy(outBgra + (size_t)y * rowBytes,
                   tmp + (size_t)(outH - 1 - y) * rowBytes, rowBytes);
        }
        free(tmp);
    }
};

} // namespace R3ShieldCoreUi
