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
    R3PFNGLACTIVETEXTURE            ActiveTexture = nullptr;
    R3PFNGLCREATESHADER             CreateShader = nullptr;
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

inline const char* GlBaseFS()
{
    return R"(#version 330 core
in vec2 vUV;
out vec4 fragColor;
uniform sampler2D uTex;
void main(){ fragColor = vec4(texture(uTex, vUV).rgb, 1.0); }
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

  // 投影：只在面板外可见（面板内被玻璃完全盖住）
  float sdSh = sdRoundBox(d - vec2(0.0, uShadowOff), uHalf, uRadius);
  float sh = clamp(1.0 - sdSh / uShadowR, 0.0, 1.0);
  float shadowA = sh * sh * uShadowA;

  if (sd >= 0.5) {
    fragColor = vec4(0.0, 0.0, 0.0, shadowA);
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
  bl = mix(bl, vec3(luma), 0.10) * 1.04;

  vec3 col = mix(bl, vec3(1.0), uTint);

  // 内侧 rim 高光
  float rim = clamp(exp(sd / (2.6 * uDpi)), 0.0, 1.0);
  col = mix(col, vec3(1.0), rim * uRim);

  // 顶部镜面光带
  float topY = uCenter.y - uHalf.y + 1.5 * uDpi;
  col = mix(col, vec3(1.0), exp(-abs(p.y - topY) * 1.4 / uDpi) * uSpec);

  // 磨砂颗粒
  col += (hash21(p) - 0.5) * uNoise;

  float aa = max(fwidth(sd) * 0.75, 0.4);
  float inside = smoothstep(aa, -aa, sd);

  fragColor = vec4(col * inside, inside);
}
)";
}

// ---------------------------------------------------------------------------
// GlGlass —— 上下文 + 程序 + 纹理 + FBO
// ---------------------------------------------------------------------------
struct GlGlass {
    struct PanelDraw {
        int   x0, y0, x1, y1;
        float radius;
        float tint;
        int   kind;      // 0=面板 1=玻璃片（不做折射）
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
                int outW, int outH, float dpi,
                BYTE* outBgra)
    {
        if (!ready || !bgBgra || !outBgra || outW <= 0 || outH <= 0) {
            return false;
        }
        wglMakeCurrent(dummyDc, ctx);
        if (!EnsureTargets(outW, outH)) {
            return false;
        }

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
        for (int i = 0; i < 2; ++i) {
            BindFbo(fboA[1]);
            glViewport(0, 0, aw, ah);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texA[0]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 1.0f / (float)aw, 1.0f / (float)ah);
            g.Uniform2f(Loc(pBlur, "uDir"), 1.0f, 0.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
            BindFbo(fboA[0]);
            glViewport(0, 0, aw, ah);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texA[1]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 1.0f / (float)aw, 1.0f / (float)ah);
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
            g.Uniform2f(Loc(pBlur, "uTexel"), 1.0f / (float)bw, 1.0f / (float)bh);
            g.Uniform2f(Loc(pBlur, "uDir"), 1.0f, 0.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
            BindFbo(fboB[0]);
            glViewport(0, 0, bw, bh);
            UseQuad(pBlur);
            glBindTexture(GL_TEXTURE_2D, texB[1]);
            g.Uniform2f(Loc(pBlur, "uTexel"), 1.0f / (float)bw, 1.0f / (float)bh);
            g.Uniform2f(Loc(pBlur, "uDir"), 0.0f, 1.0f);
            g.Uniform1i(Loc(pBlur, "uTex"), 0);
            DrawQuad();
        }

        // 输出：底图 + 顶栏薄纱 + 面板
        BindFbo(fboOut);
        glViewport(0, 0, outW, outH);
        glDisable(GL_SCISSOR_TEST);
        glDisable(GL_BLEND);
        UseQuad(pBase);
        g.ActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, texFull);
        g.Uniform1i(Loc(pBase, "uTex"), 0);
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
        g.Uniform2f(Loc(pGlass, "uCenter"), cx, cy);
        g.Uniform2f(Loc(pGlass, "uHalf"), hx, hy);
        g.Uniform1f(Loc(pGlass, "uRadius"), pd.radius);
        g.Uniform1f(Loc(pGlass, "uTint"), pd.tint);
        g.Uniform1f(Loc(pGlass, "uBend"), chip ? 0.0f : 14.0f);
        g.Uniform1f(Loc(pGlass, "uBand"), chip ? 1.0f : 9.0f);
        g.Uniform1f(Loc(pGlass, "uChroma"), chip ? 0.0f : 0.34f);
        g.Uniform1f(Loc(pGlass, "uRim"), 0.46f);
        g.Uniform1f(Loc(pGlass, "uSpec"), chip ? 0.13f : 0.16f);
        g.Uniform1f(Loc(pGlass, "uNoise"), 0.018f);
        g.Uniform1f(Loc(pGlass, "uShadowR"), (chip ? 11.0f : 24.0f) * dpi);
        g.Uniform1f(Loc(pGlass, "uShadowOff"), (chip ? 3.0f : 5.0f) * dpi);
        g.Uniform1f(Loc(pGlass, "uShadowA"), chip ? 0.16f : 0.24f);
    }

    void DrawOnePanel(const PanelDraw& pd, int outW, int outH, float dpi)
    {
        const float margin = ((pd.kind == 1 ? 11.0f : 24.0f) * dpi) + 2.0f;
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
