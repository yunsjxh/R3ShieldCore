#pragma once
//
// ui_anim.h —— 逐帧动画基元（两个 exe 共用，铁律 127）
//
// 出处：参考项目 `LiquidGlassControls` 的 `Spring` / hover 逼近。
//   参考项目那三行是整个"手感"的来源：
//       c.v.step(dt);                          // 值：k=320 d=30
//       c.press.step(dt, 720.0f, 42.0f);       // 按下：k=720 d=42
//       c.hover += (tgt - hover) * min(1, dt*14);   // 悬停：指数逼近
//   参数、dt 上限（0.032s）、过冲量全部照抄 —— 手感是这些数字的结果，
//   改一个就不是"同款"了。
//
// ★★★ 与参考项目唯一的差别：**我们不常驻 60fps 渲染**。
//
//   参考项目是 `glfwSwapInterval(1)` + 无限循环，每帧都重画。
//   本项目是常驻的安全软件，"不动鼠标时不占 CPU"是硬要求（见
//   ui_controls.h 开头那段）。所以这里的模型是：
//     · 有交互（鼠标移动/点击/换页）→ 起一个 16ms 定时器，逐帧推进；
//     · 全部弹簧收敛（`Busy()` 为假）→ 定时器自己停掉，回到 0 帧。
//   ⇒ 动画过程与参考项目逐帧一致，静止时 CPU 占用为 0。
//
// ★ 为什么"收敛"要同时看位移和速度：只看位移会在"刚好穿过目标点"
//   那一帧判成静止（v==tgt 但 vel 还很大），动画会**卡在中间**。
//
#include <windows.h>

#include <cmath>

namespace R3ShieldCoreUi {
namespace Anim {

// 欠阻尼弹簧：略微过冲，就是 iOS 那种"弹一下"的手感。
struct Spring {
    float v = 0.0f;
    float tgt = 0.0f;
    float vel = 0.0f;

    void Init(float x)
    {
        v = tgt = x;
        vel = 0.0f;
    }

    void Step(float dt, float k = 320.0f, float d = 30.0f)
    {
        if (dt <= 0.0f) {
            return;
        }
        // 上限 0.032s：掉帧（比如窗口被拖动、DWM 卡一下）时 dt 可能是 0.2s，
        // 不夹住会一步冲过目标再弹回来，看起来是"抽一下"。
        if (dt > 0.032f) {
            dt = 0.032f;
        }
        const float a = (tgt - v) * k - vel * d;
        vel += a * dt;
        v += vel * dt;
    }

    // 是否还在动。阈值按**像素级**给：0.001 的值差在 40px 的开关上是 0.04px，
    // 肉眼绝对看不出；速度阈值防止"过零点被判静止"。
    bool Busy() const
    {
        return std::fabs(tgt - v) > 0.001f || std::fabs(vel) > 0.02f;
    }

    void Snap()
    {
        v = tgt;
        vel = 0.0f;
    }
};

// 指数逼近（参考项目的 hover：`c.hover += (tgt-hover) * min(1, dt*14)`）。
inline float Approach(float cur, float tgt, float dt, float rate)
{
    if (dt <= 0.0f) {
        return cur;
    }
    float k = dt * rate;
    if (k > 1.0f) {
        k = 1.0f;
    }
    return cur + (tgt - cur) * k;
}

// 一个控件的一组动画状态。
struct Slot {
    Spring v;                 // 值 0..1（开关开合 / 选中 / 进度）
    Spring press;             // 按下程度 0..1
    float  hover = 0.0f;      // 悬停 0..1（指数逼近，不是弹簧）
    float  hoverTgt = 0.0f;
    bool   seeded = false;    // 第一次取用时用当前真值初始化，避免"从 0 弹出来"
};

// 按整数 key 存一组 Slot。
//
// 为什么按 key 而不是"控件对象持有状态"：本项目的界面是**每次 WM_PAINT 重画
// 一遍**的立即模式（没有控件对象），状态只能外置。key 由调用方给
// （见 gui 里的 AnimKey(page,x,y)），必须**跨帧稳定**。
//
// 容量 192：一个页面上同时动的控件远小于这个数（页签 6 + 动作 5 + 开关 ~12）。
// 满了以后新 key 会退化成"不缓存"（每帧从真值开始 ⇒ 不动画），
// 但不会崩、也不会串到别的控件上 —— 静默退化而不是静默画错。
class Bank {
public:
    static constexpr int kMax = 192;

    Slot& Get(int key, float initial)
    {
        for (int i = 0; i < count_; ++i) {
            if (entries_[i].key == key) {
                Slot& s = entries_[i].slot;
                if (!s.seeded) {
                    s.v.Init(initial);
                    s.seeded = true;
                }
                return s;
            }
        }
        if (count_ >= kMax) {
            // 退化槽：不缓存，每次调用都从真值开始 ⇒ 该控件不动画。
            fallback_ = Slot();
            fallback_.v.Init(initial);
            fallback_.seeded = true;
            return fallback_;
        }
        Entry& e = entries_[count_++];
        e.key = key;
        e.slot = Slot();
        e.slot.v.Init(initial);
        e.slot.seeded = true;
        return e.slot;
    }

    // 推进一帧。返回"是否还有东西在动"。
    bool Tick(float dt)
    {
        bool busy = false;
        for (int i = 0; i < count_; ++i) {
            Slot& s = entries_[i].slot;
            s.v.Step(dt);
            s.press.Step(dt, 720.0f, 42.0f);
            s.hover = Approach(s.hover, s.hoverTgt, dt, 14.0f);
            if (s.v.Busy() || s.press.Busy() || std::fabs(s.hoverTgt - s.hover) > 0.004f) {
                busy = true;
            }
        }
        return busy;
    }

    void Clear() { count_ = 0; }

private:
    struct Entry {
        int  key = 0;
        Slot slot;
    };
    Entry entries_[kMax] = {};
    int   count_ = 0;
    Slot  fallback_;
};

} // namespace Anim
} // namespace R3ShieldCoreUi
