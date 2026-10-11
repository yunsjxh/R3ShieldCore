//
// spoof_e2e_target.cpp —— 端到端验证的「被注入目标」进程（v74：三面版）。
//
// 它**自己不做任何 hook**：只负责
//   ① 报告自己起来了（READY），让 runner 知道可以放引擎去注入；
//   ② 等一个注入窗口（默认 3s）；
//   ③ 走**三条真的数据获取路径**，把结果打成一行机器可解析的 `RESULT ...`：
//        · 屏幕  —— BitBlt 屏幕 DC -> 内存 DC -> GetDIBits 读回（ScreenGuard 已挂）
//                   外加 GetPixel 直读（ScreenGuard **没挂**）作为真实画面参照；
//        · 剪贴板 —— SetClipboardData(CF_UNICODETEXT) 后 GetClipboardData 读回
//                   （ClipboardGuard 已挂）；
//        · 注册表 —— RegQueryValueExW 读一个**预先存在**的值
//                   （内部走 NtQueryValueKey，RegistryGuard 已挂）。
//
// 为什么要有它：三个 guard 的替换逻辑都活在 **被注入进程** 里，所以
//   「端到端」必须有一个真的被注入、真的去取数据的进程。它就是这个进程。
//
// ⚠️ 它只**读**屏幕 / 读剪贴板 / **读**注册表；唯一一次写是**往剪贴板放自己的
//    测试文本**（`SetClipboardData` 不被 guard 拦，见下）。注册表的值由
//    runner 在**起引擎之前**用 `reg.exe` 建好 —— 本进程只读，不写。
//    为什么不在本进程里建：`protect_reg=` 命中的路径被算作**高危写**
//    （r3shieldcore_rules.cpp:678），`mode=block` 下会**被拒** ⇒ 建不出来。
//    （那不是 bug，正是"保护 = 写不进"这条设计；所以建值这一步必须在引擎外做。）
//
// ⚠️ 屏幕内容会变（时钟、动画）。所以屏幕判据不是"像素等于某个具体值"，
//    而是"BitBlt 路 vs GetPixel 路 的关系"（见 spoof_e2e.sh 的三格矩阵）。
//    剪贴板 / 注册表判据是"读回来的内容 vs 我们放进去的**已知常量**"，确定性强。
//
// 编译：bash build_spoof_e2e.sh
// 运行：spoof_e2e_target.exe [--wait-ms=3000] [--tag=NAME]
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// 采样区域：取屏幕左上角一块。桌面这里通常是壁纸 / 图标 ⇒ 大概率非黑。
static const int kSampleW = 128;
static const int kSampleH = 96;

// ★★★ `GetPixel` 的采样**预算**（v74 加）。
//
// 为什么非要有：`GetPixel` 在屏幕 DC 上**极慢** —— 实测本机约 **17ms/次**
//   （GDI 要往显示驱动跑一趟）。原来两块采样合计 ~700 次 ⇒ 光这一项就
//   **11.7 秒**（整个目标程序 15s 里占 11.7s）。后果：
//     · `--prepare` / `--collect` 每次都要跑一遍基线 ⇒ 每次多等 15s；
//     · 夹具的判据自测（tools/spoof_e2e_selftest.sh）要跑十几遍 ⇒ 6 分钟。
//   而 `GetPixel` 采样的**目的**只是"证明这条**未被 hook** 的路仍能读到
//   真实画面"（多路径戳穿）—— 几个点就够，不需要几百个。
//
// ⇒ 给它一个**调用次数上限**，采样步长按屏幕尺寸自适应。这样在"GetPixel 很快"
//   的机器上覆盖更密，在"很慢"的机器上自动变稀，总耗时都可控。
//   ⚠️ 上限不能太小：B 格要证的是"屏幕上**存在**非黑点"，采样太稀可能
//      全落在黑区（引擎窗口、暗色壁纸）⇒ 假 FAIL。64 个点是够的。
static const int kGetPixelBudget = 64;

// ---- 剪贴板：我们自己放进去的**已知秘密**（替换生效时应读回空串）----
static const wchar_t* kClipSecret = L"R3SC-E2E-CLIP-SECRET-0123456789";

// ---- 注册表：runner 预先建好的键 / 值 / 内容 ----
//    ★ 这三个常量与 spoof_e2e.sh 里 `reg add` 的那份**必须一致**。
//      它们是跨进程契约（bash 侧建、本进程读）⇒ 改一处必须改两处。
//      运行时用 `reg_match` 判"读到的等不等于 kRegSecret"，所以真的漂了
//      会**判 FAIL**，不会静默（铁律 97：口径必须与实际一致）。
static const wchar_t* kRegSubKey    = L"Software\\R3ShieldCoreE2E";
static const wchar_t* kRegValueName = L"Secret";
static const wchar_t* kRegSecret    = L"R3SC-E2E-REG-SECRET";

static unsigned ParseMsArg(const char* name, unsigned fallback)
{
    // 极简解析：在命令行里找 "--name=NNN"。
    const char* cl = GetCommandLineA();
    const size_t nlen = strlen(name);
    for (const char* p = cl; (p = strstr(p, "--")) != nullptr; ++p) {
        ++p;   // 跳过 "--"
        if (_strnicmp(p, name, nlen) == 0 && p[nlen] == '=') {
            return static_cast<unsigned>(strtoul(p + nlen + 1, nullptr, 10));
        }
    }
    return fallback;
}

static const char* TagArg()
{
    const char* cl = GetCommandLineA();
    const char* key = "--tag=";
    const char* p = strstr(cl, key);
    return p ? (p + strlen(key)) : "";
}

// ==================================================================
// 剪贴板：放一段已知文本，再读回来
// ==================================================================
//
// ⚠️ 为什么自己放：剪贴板是**全局共享**的，别的进程随时可能改它。
//    只有在**同一次运行内**「我放 X → 我读回 Y」，Y 与 X 的比较才是确定的。
//    否则"读到空"到底是"被替换了"还是"本来就没内容"分不清（铁律 110 空真）。
//
// ⚠️ `SetClipboardData` 不被 guard 拦（剪贴板面只拦**读**：Open 记录、取数据高危）。
//    所以本进程能正常把自己的文本放上去 —— 这是**前提**，不是被测试的对象。
static bool OpenClipboardRetry(int attempts)
{
    for (int i = 0; i < attempts; ++i) {
        if (OpenClipboard(nullptr)) {
            return true;
        }
        Sleep(50);
    }
    return false;
}

// 返回 true = 已把 kClipSecret 放进剪贴板。
static bool PutClipboardSecret()
{
    if (!OpenClipboardRetry(20)) {
        return false;
    }

    EmptyClipboard();

    const size_t bytes = (wcslen(kClipSecret) + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hg) {
        CloseClipboard();
        return false;
    }
    memcpy(GlobalLock(hg), kClipSecret, bytes);
    GlobalUnlock(hg);

    // ⚠️ SetClipboardData 成功后**所有权转移给系统**：失败时必须自己释放，
    //    成功时**不能**再释放（否则系统持有野句柄）。探针踩过这个坑。
    if (!SetClipboardData(CF_UNICODETEXT, hg)) {
        GlobalFree(hg);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}

struct ClipOutcome
{
    bool read;          // GetClipboardData 返回非空
    DWORD err;          // 失败时的 GetLastError
    size_t strlen;      // 读回字符串的长度（字符数）
    bool match;         // 读回的字符串 == kClipSecret
};

static ClipOutcome ReadClipboardSecret()
{
    ClipOutcome out = { false, 0, 0, false };

    if (!OpenClipboardRetry(20)) {
        out.err = GetLastError();
        return out;
    }

    SetLastError(0);
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) {
        out.err = GetLastError();
        CloseClipboard();
        return out;
    }

    out.read = true;

    // CF_UNICODETEXT 的块是 HGLOBAL，里面是 NUL 结尾的 UTF-16。
    const wchar_t* text = static_cast<const wchar_t*>(GlobalLock(h));
    if (text) {
        out.strlen = wcslen(text);
        out.match = (wcscmp(text, kClipSecret) == 0);
        GlobalUnlock(h);
    }

    CloseClipboard();
    return out;
}

// ==================================================================
// 注册表：读一个**预先存在**的值（runner 建的）
// ==================================================================
struct RegOutcome
{
    bool read;      // RegQueryValueExW 返回 ERROR_SUCCESS
    DWORD err;      // 失败时的返回码
    size_t strlen;  // 读回字符串长度（字符数）
    bool match;     // 读回的字符串 == kRegSecret
};

static RegOutcome ReadRegistrySecret()
{
    RegOutcome out = { false, 0, 0, false };

    HKEY key = nullptr;
    LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER, kRegSubKey, 0, KEY_READ, &key);
    if (st != ERROR_SUCCESS) {
        out.err = static_cast<DWORD>(st);
        return out;
    }

    wchar_t buffer[256] = {};
    DWORD cbData = sizeof(buffer);
    DWORD type = 0;
    SetLastError(0);
    st = RegQueryValueExW(key, kRegValueName, nullptr, &type,
        reinterpret_cast<LPBYTE>(buffer), &cbData);
    if (st != ERROR_SUCCESS) {
        out.err = static_cast<DWORD>(st);
        RegCloseKey(key);
        return out;
    }

    out.read = true;
    if (type == REG_SZ) {
        // ⚠️ 替换是"清零**数据区**、长度字段一个不改" ⇒ 返回的 cbData 不变，
        //    但首字符变 0 ⇒ wcslen == 0。所以判据用 **strlen**，不是 cbData。
        buffer[(sizeof(buffer) / sizeof(buffer[0])) - 1] = L'\0';
        out.strlen = wcslen(buffer);
        out.match = (wcscmp(buffer, kRegSecret) == 0);
    }

    RegCloseKey(key);
    return out;
}

int main()
{
    const unsigned waitMs = ParseMsArg("wait-ms", 3000);
    const char* tag = TagArg();

    setvbuf(stdout, nullptr, _IONBF, 0);

    printf("TARGET pid=%lu arch=%s tag=%s\n",
        static_cast<unsigned long>(GetCurrentProcessId()),
#ifdef _WIN64
        "x64",
#else
        "x86",
#endif
        tag);
    printf("READY\n");

    // ---- 注入窗口：让引擎的轮询注入有时间落进来 ----
    Sleep(waitMs);

    // ================================================================
    // ① 真实截屏路径：BitBlt(屏幕 DC -> 内存 DC) 然后 GetDIBits 读回
    // ================================================================
    HDC screen = GetDC(nullptr);
    if (!screen) {
        printf("RESULT error=GetDC failed err=%lu\n", GetLastError());
        return 3;
    }

    HDC memDc = CreateCompatibleDC(screen);
    HBITMAP memBmp = CreateCompatibleBitmap(screen, kSampleW, kSampleH);
    if (!memDc || !memBmp) {
        printf("RESULT error=CreateCompatibleDC/Bitmap failed err=%lu\n", GetLastError());
        ReleaseDC(nullptr, screen);
        return 3;
    }
    HGDIOBJ oldBmp = SelectObject(memDc, memBmp);

    // 先把目标位图涂成一个**可识别**的非黑非零值：这样"BitBlt 到底有没有
    // 写进去"和"写进去之后有没有被涂黑"能分开。
    // （若 BitBlt 被 Block，目标应保持这个值；若被 Spoof，应变成全黑。）
    {
        RECT r = { 0, 0, kSampleW, kSampleH };
        HBRUSH br = CreateSolidBrush(RGB(0x12, 0x34, 0x56));
        FillRect(memDc, &r, br);
        DeleteObject(br);
    }

    SetLastError(0);
    const BOOL bitbltOk = BitBlt(memDc, 0, 0, kSampleW, kSampleH, screen, 0, 0, SRCCOPY);
    const DWORD bitbltErr = GetLastError();

    // ---- GetDIBits 读回（32bpp top-down）----
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = kSampleW;
    bi.bmiHeader.biHeight = -kSampleH;   // 负 = top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    DWORD* px = static_cast<DWORD*>(calloc(static_cast<size_t>(kSampleW) * kSampleH, sizeof(DWORD)));
    int lines = 0;
    DWORD first = 0xFFFFFFFF;
    int nonBlack = 0;
    if (px) {
        SetLastError(0);
        lines = GetDIBits(memDc, memBmp, 0, static_cast<UINT>(kSampleH), px, &bi, DIB_RGB_COLORS);
        first = px[0];
        const int total = kSampleW * kSampleH;
        for (int i = 0; i < total; ++i) {
            // DIB 32bpp 像素是 BGRA 内存序；全 0 = 黑。
            if ((px[i] & 0x00FFFFFFu) != 0) {
                ++nonBlack;
            }
        }
    }

    // ================================================================
    // ② GetPixel 直接读屏幕 —— **ScreenGuard 没挂这条路径**
    //    它永远拿到真实画面 ⇒ 用来实证「多路径戳穿」。
    //    ⚠️ 见 kGetPixelBudget 的说明：这条路的调用次数**必须有预算**
    //       （17ms/次 ⇒ 几百次就是十几秒）。
    // ================================================================
    const COLORREF gp0 = GetPixel(screen, 0, 0);
    const COLORREF gpMid = GetPixel(screen, kSampleW / 2, kSampleH / 2);

    // 统计 GetPixel 路径下的非黑像素数（小样本，够判"是不是全黑屏"）。
    // 步长 16 ⇒ 8×6 = 48 次（在 64 的预算内）。
    int gpNonBlack = 0;
    int gpGridTotal = 0;
    for (int y = 0; y < kSampleH; y += 16) {
        for (int x = 0; x < kSampleW; x += 16) {
            ++gpGridTotal;
            const COLORREF c = GetPixel(screen, x, y);
            if (c != CLR_INVALID && (c & 0x00FFFFFFu) != 0) {
                ++gpNonBlack;
            }
        }
    }

    // ★ 再加一份**全屏**采样（粗网格）。
    //
    // 为什么要它：引擎起来之后会开一个 GUI 窗口，可能正好压在左上角那 128x96 上。
    //   那样 `getpixel_nonblack`（只采那一小块）会变成 0，看起来像"GetPixel 也被
    //   替换了"，其实是"那块被引擎窗口盖住了"。全屏采样能把这层区分开。
    //
    // ★ 步长**自适应**：把调用次数压在预算内（见 kGetPixelBudget）。
    //   本机 1920×1080 下 step=64 会有 510 次 ≈ 8.5s；自适应后取 256 ⇒ 40 次。
    int gpFullNonBlack = 0;
    int gpFullTotal = 0;
    {
        const int sw = GetSystemMetrics(SM_CXSCREEN);
        const int sh = GetSystemMetrics(SM_CYSCREEN);
        int step = 64;
        // 每放大一倍，调用数降到约 1/4；循环一定终止（step 会超过屏幕尺寸）。
        while (step < 4096 && ((sw / step) + 1) * ((sh / step) + 1) > kGetPixelBudget) {
            step *= 2;
        }
        for (int y = 0; y < sh; y += step) {
            for (int x = 0; x < sw; x += step) {
                ++gpFullTotal;
                const COLORREF c = GetPixel(screen, x, y);
                if (c != CLR_INVALID && (c & 0x00FFFFFFu) != 0) {
                    ++gpFullNonBlack;
                }
            }
        }
    }

    // ================================================================
    // ③ 剪贴板：放已知文本 -> 读回（ClipboardGuard 已挂 GetClipboardData）
    // ================================================================
    const bool clipPut = PutClipboardSecret();
    ClipOutcome clip = { false, 0, 0, false };
    if (clipPut) {
        clip = ReadClipboardSecret();
    }

    // ================================================================
    // ④ 注册表：读预先存在的值（RegistryGuard 已挂 NtQueryValueKey）
    // ================================================================
    const RegOutcome reg = ReadRegistrySecret();

    // ---- 一行机器可解析的结果 ----
    printf("RESULT bitblt=%d err=%lu lines=%d first=0x%08lX nonblack=%d/%d "
           "getpixel0=0x%08lX getpixelmid=0x%08lX getpixel_nonblack=%d "
           "getpixel_full_nonblack=%d/%d "
           "clip_put=%d clip_read=%d clip_err=%lu clip_strlen=%llu clip_match=%d "
           "reg_read=%d reg_err=%lu reg_strlen=%llu reg_match=%d\n",
        bitbltOk ? 1 : 0,
        static_cast<unsigned long>(bitbltErr),
        lines,
        static_cast<unsigned long>(first),
        nonBlack, kSampleW * kSampleH,
        static_cast<unsigned long>(gp0),
        static_cast<unsigned long>(gpMid),
        gpNonBlack,
        gpFullNonBlack, gpFullTotal,
        clipPut ? 1 : 0,
        clip.read ? 1 : 0,
        static_cast<unsigned long>(clip.err),
        static_cast<unsigned long long>(clip.strlen),
        clip.match ? 1 : 0,
        reg.read ? 1 : 0,
        static_cast<unsigned long>(reg.err),
        static_cast<unsigned long long>(reg.strlen),
        reg.match ? 1 : 0);

    // ---- 收尾 ----
    if (px) {
        free(px);
    }
    SelectObject(memDc, oldBmp);
    DeleteObject(memBmp);
    DeleteDC(memDc);
    ReleaseDC(nullptr, screen);

    return 0;
}
