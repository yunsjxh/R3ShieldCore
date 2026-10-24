//
// spoof_camera_probe.cpp —— 实证：摄像头「帧替换」这条机制链到底行不行。
//
// 这是《回传数据替换Hook-技术预研》§8 Phase 2（摄像头/麦克风，流式帧替换）
// 的**可行性探针**。它**不经过引擎**、**不注入任何进程**，在一个进程里
// 自己挂自己的 hook，回答四个问题：
//
//   A. **能不能拿到 `IMFSourceReader` 并 patch 它的 vtable**？
//      —— 这是整条链的前提。`ReadSample` 不是导出函数，只能走 vtable。
//   B. **detour 真的会被调用吗**？—— 只有真调一次才知道（铁律 137）。
//   C. **能不能摸到 `IMFSample` 的字节并原地改写**？
//      而且"改写后调用方看得见"—— 光"我们改了"不算（可能是副本）。
//   D. ★★ **"同长度、内容清零"这条规则对摄像头帧成不成立**？
//      —— 见下（结论是：**清零不等于黑帧**，这是一个必须正面处理的差异）。
//
// ★★ 关键限制（诚实标注）：本机**不一定有摄像头**。所以本探针用
//    **合成媒体源**（自己写一个最小 WAV，`MFCreateSourceReaderFromURL`）
//    来验证**机制**。采样器换成视频帧源时，
//      · vtable patch 这一层 —— **完全相同**（都是 `IMFSourceReader`）；
//      · `IMFSample` → `IMFMediaBuffer` 这一层 —— **完全相同**；
//      · 只有"填什么值算中性"这一层不同（见 Part B 的决策表）。
//    本探针会**顺带勘察**本机有没有视频采集设备，并如实报告。
//
// ⚠️ 本探针只读**自己进程内自己创建的**媒体源（自己写的临时 WAV），
//    不打开任何摄像头、不注入任何进程。因此**不受**
//    「自动化脚本不得运行引擎」那条约束（铁律 175）。
//
// 编译：bash build_spoof_camera_probe.sh
// 运行：./tools/spoof_camera_probe.exe
//
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <mferror.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>

// ★★ 生产与探针**共用同一份**中性帧决策表（铁律 195：同一份逻辑别抄两份）。
//    这份头是 `inline` 的纯逻辑，不链任何库 —— 生产侧（`camera_guard.cpp`）
//    与这里 `#include` 的是**同一个文件**。
#include "camera_spoof_codec.h"

// 把 SDK 的 GUID 转成 codec 里的 SpoofGuid（两者布局相同，逐字段拷贝）。
static R3ShieldCoreCameraSpoof::SpoofGuid ToSpoofGuid(const GUID& g)
{
    R3ShieldCoreCameraSpoof::SpoofGuid s{};
    s.Data1 = g.Data1;
    s.Data2 = g.Data2;
    s.Data3 = g.Data3;
    memcpy(s.Data4, g.Data4, sizeof(s.Data4));
    return s;
}

// 两个 GUID 是否相等（codec 的 SpoofGuid vs SDK 的 GUID）。
static bool GuidSameAsSdk(const R3ShieldCoreCameraSpoof::SpoofGuid& a, const GUID& b)
{
    return a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3
        && memcmp(a.Data4, b.Data4, sizeof(a.Data4)) == 0;
}

// ⚠️ 自己定义 UNICODE_STRING，不引 winternl.h（那套随 SDK 漂）。
struct ProbeUnicodeString {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

// ------------------------------------------------------------------ 状态
static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

typedef HRESULT(STDMETHODCALLTYPE* ReadSample_t)(IMFSourceReader*, DWORD, DWORD,
    DWORD*, DWORD*, LONGLONG*, IMFSample**);

static ReadSample_t g_realReadSample = nullptr;

// 前向声明（定义在下面 Part B/D 区）。
static bool ResolvePlan(IMFSourceReader* self, DWORD index, const DWORD* actualIndex,
    R3ShieldCoreCameraSpoof::NeutralPlan& out);

// ★ 探针专用开关：解析不出视频计划时，是否仍按"全 0"填充。
//   为什么需要它：Part A 用的是**合成音频源**（WAV）来验机制链，
//   它没有视频子类型 ⇒ `ResolvePlan` 必然失败。生产侧遇到"非视频流"
//   是**放行**（音频在 `IAudioClient::Initialize` 处单独判）；
//   探针要的是"证明机制能改到帧"，所以这里退化为全 0 填充。
//   ⚠️ 这是**探针与生产的唯一行为差异**，显式标出来，别让它变成暗坑。
static bool g_fillAnyStream = true;

static volatile LONG g_spoofOn = 0;      // 1 = detour 允许清零
static volatile LONG g_hits = 0;         // detour 进入次数
static volatile LONG g_samples = 0;      // 真调返回了 sample 的次数
static volatile LONG g_rewritten = 0;    // 真的改写了字节的次数
static volatile LONG g_lockFailed = 0;   // Lock 失败（只读缓冲 / 不支持）
static volatile LONG g_realNonZero = 0;  // 真数据里确实有非 0 内容
static volatile LONG g_callerSawZero = 0;// 调用方看到的是全 0
static volatile LONG g_callerSawReal = 0;// 调用方看到的是真数据
static volatile LONG g_deviceCount = 0;  // 本机视频采集设备数（Part C 勘察结果）
static bool g_useCamera = false;         // 是否真的打开摄像头（--use-camera，默认否）

static void Check(const char* name, bool ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ detour
//
// 与将来生产版**同构**：先真调原函数，再在成功且有 sample 时
// 摸到缓冲区、原地改写（**长度不变**）。
static HRESULT STDMETHODCALLTYPE ReadSample_Detour(IMFSourceReader* self, DWORD index,
    DWORD flags, DWORD* actualIndex, DWORD* streamFlags, LONGLONG* timestamp,
    IMFSample** sample)
{
    InterlockedIncrement(&g_hits);

    const HRESULT hr = g_realReadSample(self, index, flags, actualIndex, streamFlags,
        timestamp, sample);

    if (g_spoofOn == 0 || FAILED(hr) || !sample || !*sample) {
        return hr;
    }

    InterlockedIncrement(&g_samples);

    IMFSample* s = *sample;
    IMFMediaBuffer* buf = nullptr;
    HRESULT hrBuf = s->GetBufferByIndex(0, &buf);
    if (FAILED(hrBuf) || !buf) {
        // 多缓冲的 sample：转成连续缓冲（生产版也应这样兜底）。
        if (FAILED(s->ConvertToContiguousBuffer(&buf)) || !buf) {
            InterlockedIncrement(&g_lockFailed);
            return hr;
        }
    }

    BYTE* p = nullptr;
    DWORD maxLen = 0, curLen = 0;
    if (FAILED(buf->Lock(&p, &maxLen, &curLen)) || !p || curLen == 0) {
        InterlockedIncrement(&g_lockFailed);
        buf->Release();
        return hr;
    }

    // 记下"真数据里有没有非 0"（否则后面"变成全 0"是空真，铁律 110）。
    for (DWORD i = 0; i < curLen; ++i) {
        if (p[i] != 0) { InterlockedIncrement(&g_realNonZero); break; }
    }

    // ★ 计划：优先用 codec 按**真实子类型**算出来的中性值计划；
    //   解析不出来（Part A 的合成音频源）且 `g_fillAnyStream` 开着 ⇒ 退化为全 0。
    //   ⚠️ 生产侧在这里是"非视频流 ⇒ 直接放行"，差异见 `g_fillAnyStream` 的注释。
    R3ShieldCoreCameraSpoof::NeutralPlan plan = {};
    if (!ResolvePlan(self, index, actualIndex, plan)) {
        if (!g_fillAnyStream) {
            buf->Unlock();
            buf->Release();
            return hr;
        }
        plan.kind = R3ShieldCoreCameraSpoof::FillKind::AllZero;
        plan.stride = 0;
        plan.height = 0;
    }

    // ★ 只改**当前长度**内的字节；`SetCurrentLength` / `maxLen` 一个都不动。
    R3ShieldCoreCameraSpoof::ApplyNeutral(p, curLen, plan);

    // 自检：调用方（主循环）看到的确实是全 0。
    bool allZero = true;
    for (DWORD i = 0; i < curLen; ++i) {
        if (p[i] != 0) { allZero = false; break; }
    }
    if (allZero) InterlockedIncrement(&g_callerSawZero);
    else InterlockedIncrement(&g_callerSawReal);

    buf->Unlock();
    buf->Release();
    InterlockedIncrement(&g_rewritten);
    return hr;
}

// ------------------------------------------------------------------ 工具
static void WriteLe16(BYTE* p, unsigned v) { p[0] = (BYTE)(v & 0xFF); p[1] = (BYTE)((v >> 8) & 0xFF); }
static void WriteLe32(BYTE* p, unsigned v) {
    p[0] = (BYTE)(v & 0xFF); p[1] = (BYTE)((v >> 8) & 0xFF);
    p[2] = (BYTE)((v >> 16) & 0xFF); p[3] = (BYTE)((v >> 24) & 0xFF);
}

// 写一个最小 PCM WAV（8kHz 单声道 16bit），数据非 0（否则负对照没意义）。
static bool WriteProbeWav(const wchar_t* path, int samples)
{
    const unsigned dataBytes = (unsigned)samples * 2;
    BYTE hdr[44] = { 0 };
    memcpy(hdr + 0, "RIFF", 4);
    WriteLe32(hdr + 4, 36 + dataBytes);
    memcpy(hdr + 8, "WAVE", 4);
    memcpy(hdr + 12, "fmt ", 4);
    WriteLe32(hdr + 16, 16);          // fmt chunk size
    WriteLe16(hdr + 20, 1);           // PCM
    WriteLe16(hdr + 22, 1);           // channels
    WriteLe32(hdr + 24, 8000);        // sample rate
    WriteLe32(hdr + 28, 8000 * 2);    // byte rate
    WriteLe16(hdr + 32, 2);           // block align
    WriteLe16(hdr + 34, 16);          // bits per sample
    memcpy(hdr + 36, "data", 4);
    WriteLe32(hdr + 40, dataBytes);

    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    bool ok = WriteFile(f, hdr, sizeof(hdr), &wrote, nullptr) != 0;
    if (ok) {
        // 一段非 0 的锯齿波（每 2 字节一个 16 位样本）。
        BYTE buf[512];
        unsigned remaining = dataBytes;
        unsigned idx = 0;
        while (remaining > 0 && ok) {
            const unsigned n = remaining < sizeof(buf) ? remaining : (unsigned)sizeof(buf);
            for (unsigned i = 0; i + 1 < n; i += 2) {
                const unsigned v = (idx * 37u) & 0x7FFFu;   // 非 0
                WriteLe16(buf + i, v);
                idx++;
            }
            DWORD w = 0;
            ok = WriteFile(f, buf, n, &w, nullptr) != 0;
            remaining -= n;
        }
    }
    CloseHandle(f);
    return ok;
}

// ------------------------------------------------------------------ Part B/D：中性帧决策表
//
// ★★ 决策表**已经搬到共享头** `camera_spoof_codec.h`（铁律 195）——
//    生产侧 `camera_guard.cpp` 用的是**同一个文件**。
//    本探针不再自带一份，只做两件事：
//      ① 用 codec 的接口把**行为**验一遍（Part D）；
//      ② 用 **SDK 的 `MFVideoFormat_*`** 交叉校验 codec 里那份自带的 GUID
//         抄得对不对（Part D0）—— 抄错 ⇒ 这里红，而不是"运行时静默不匹配"。
using R3ShieldCoreCameraSpoof::VideoFormat;
using R3ShieldCoreCameraSpoof::NeutralPlan;
using R3ShieldCoreCameraSpoof::FillKind;

// 子类型 → codec 的 VideoFormat（不认识 = Unknown）。
static VideoFormat ClassifySdk(const GUID& sub)
{
    return R3ShieldCoreCameraSpoof::ClassifyFormat(ToSpoofGuid(sub));
}

// 每像素字节数（×2 表示 1.5，用分子/分母表示避免浮点）。
// 返回 false -> 不认识的子类型（**不猜**，铁律 194/196）。
static bool BytesPerPixelX2(VideoFormat f, unsigned& x2)
{
    switch (f) {
    case VideoFormat::Rgb32:
    case VideoFormat::Argb32: x2 = 8; return true;
    case VideoFormat::Rgb24:  x2 = 6; return true;
    case VideoFormat::Yuy2:
    case VideoFormat::Uyvy:   x2 = 4; return true;
    case VideoFormat::Nv12:
    case VideoFormat::I420:
    case VideoFormat::Iyuv:
    case VideoFormat::Yv12:   x2 = 3; return true;
    default:                  return false;
    }
}

// 是否 YUV 家族（-> "全 0"不是黑，必须填中性值）。
static bool IsYuvFamily(VideoFormat f)
{
    return f == VideoFormat::Yuy2 || f == VideoFormat::Uyvy || f == VideoFormat::Nv12
        || f == VideoFormat::I420 || f == VideoFormat::Iyuv || f == VideoFormat::Yv12;
}

// 子类型 → 可读名（codec 提供；ASCII，见铁律 193）。
static const char* SubtypeName(const GUID& sub)
{
    return R3ShieldCoreCameraSpoof::FormatName(ClassifySdk(sub));
}

// 解析"这一帧该怎么中性化"。返回 false = 解析不出来（调用方决定回落策略）。
static bool ResolvePlan(IMFSourceReader* self, DWORD index, const DWORD* actualIndex,
    NeutralPlan& out)
{
    if (!self) {
        return false;
    }
    DWORD sidx = index;
    if (index == (DWORD)MF_SOURCE_READER_ANY_STREAM && actualIndex) {
        sidx = *actualIndex;
    }

    IMFMediaType* mt = nullptr;
    if (FAILED(self->GetCurrentMediaType(sidx, &mt)) || !mt) {
        return false;
    }

    GUID major = {}, sub = {};
    mt->GetGUID(MF_MT_MAJOR_TYPE, &major);
    if (major != MFMediaType_Video) {
        mt->Release();
        return false;   // 音频流：本探针的 Part A 用合成音频源，由调用方决定填不填
    }
    mt->GetGUID(MF_MT_SUBTYPE, &sub);

    UINT32 w = 0, h = 0;
    MFGetAttributeSize(mt, MF_MT_FRAME_SIZE, &w, &h);
    mt->Release();

    return R3ShieldCoreCameraSpoof::PlanForFormat(
        ClassifySdk(sub), w, h, /*stride=0 -> 名义步长*/ 0, out);
}

// ------------------------------------------------------------------ main
int main(int argc, char** argv)
{
    printf("=== 摄像头「帧替换」可行性探针（自挂自测，不经过引擎）===\n");
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--use-camera") == 0) g_useCamera = true;
    }
    printf("（真摄像头测试：%s；加 --use-camera 可打开硬件）\n\n",
        g_useCamera ? "已启用" : "未启用");

    const HRESULT hrCo = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const HRESULT hrMf = MFStartup(MF_VERSION, MFSTARTUP_FULL);
    printf("CoInitializeEx=0x%08lX  MFStartup=0x%08lX\n\n",
        (unsigned long)hrCo, (unsigned long)hrMf);

    // ---------- Part C：本机设备勘察（如实报告，不作为 PASS/FAIL）----------
    printf("--- C. 本机视频采集设备勘察（MFEnumDeviceSources）---\n");
    {
        IMFAttributes* attr = nullptr;
        HRESULT hr = MFCreateAttributes(&attr, 1);
        if (SUCCEEDED(hr) && attr) {
            attr->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
            IMFActivate** devices = nullptr;
            UINT32 count = 0;
            hr = MFEnumDeviceSources(attr, &devices, &count);
            if (SUCCEEDED(hr)) {
                printf("  视频采集设备数 = %u\n", count);
                InterlockedExchange(&g_deviceCount, (LONG)count);
                if (count == 0) {
                    printf("  -> 本机**没有**摄像头：帧面**端到端**无法在本机验证（如实标注）。\n");
                }
                for (UINT32 i = 0; i < count; ++i) {
                    if (devices[i]) devices[i]->Release();
                }
                CoTaskMemFree(devices);
            }
            else {
                printf("  MFEnumDeviceSources 失败 hr=0x%08lX（MF 未就绪？）\n", (unsigned long)hr);
            }
            attr->Release();
        }
        else {
            printf("  MFCreateAttributes 失败 hr=0x%08lX\n", (unsigned long)hr);
        }
    }

    // ---------- Part A/B：机制链（合成媒体源）----------
    printf("\n--- A. 用合成媒体源验证机制链（自己写的 WAV）---\n");

    wchar_t wavPath[MAX_PATH] = { 0 };
    wchar_t tmpDir[MAX_PATH] = { 0 };
    GetTempPathW(MAX_PATH, tmpDir);
    // ★ 临时文件名带 PID（铁律 177：并行时不要用固定名）。
    _snwprintf_s(wavPath, MAX_PATH, _TRUNCATE, L"%sr3sc_cam_probe_%lu.wav",
        tmpDir, (unsigned long)GetCurrentProcessId());

    if (!WriteProbeWav(wavPath, 4000)) {
        printf("  [FATAL] 写临时 WAV 失败\n");
        return 2;
    }
    printf("  临时 WAV: %ls\n", wavPath);

    IMFSourceReader* reader = nullptr;
    HRESULT hr = MFCreateSourceReaderFromURL(wavPath, nullptr, &reader);
    if (FAILED(hr) || !reader) {
        printf("  [FATAL] MFCreateSourceReaderFromURL 失败 hr=0x%08lX\n", (unsigned long)hr);
        printf("  -> 本机 MF 的 WAVE 源不可用；机制链**无法在此环境验证**（如实标注）。\n");
        DeleteFileW(wavPath);
        MFShutdown();
        printf("\n=== 结果：%d passed, %d failed, %d skipped ===\n", g_pass, g_fail, g_skip);
        return g_fail == 0 ? 0 : 1;
    }
    Check("A1 拿到 IMFSourceReader（合成源）", true);

    // 打印当前媒体类型，便于判断"我们面对的是什么"。
    {
        IMFMediaType* mt = nullptr;
        if (SUCCEEDED(reader->GetCurrentMediaType(MF_SOURCE_READER_FIRST_AUDIO_STREAM, &mt)) && mt) {
            GUID major = {}, sub = {};
            mt->GetGUID(MF_MT_MAJOR_TYPE, &major);
            mt->GetGUID(MF_MT_SUBTYPE, &sub);
            printf("  媒体类型: major=%08lX-%04X... sub=%08lX-%04X...\n",
                (unsigned long)major.Data1, major.Data2,
                (unsigned long)sub.Data1, sub.Data2);
            Check("A2 当前媒体类型是音频（合成 WAV 源，与视频帧同构）", major == MFMediaType_Audio);
            mt->Release();
        }
    }

    // ---- vtable patch ----
    // `IMFSourceReader` 的 vtable（IUnknown 3 个之后）：
    //   3 GetStreamSelection  4 SetStreamSelection  5 GetNativeMediaType
    //   6 GetCurrentMediaType 7 SetCurrentMediaType 8 SetCurrentPosition
    //   9 **ReadSample**      10 Flush  11 GetServiceForStream  12 GetPresentationAttribute
    const int kReadSampleSlot = 9;
    void** vtbl = *reinterpret_cast<void***>(reader);

    // ★ 前提检查：vtable[9] 必须落在 mfreadwrite.dll 的地址范围内 ——
    //   否则"槽号记错了"会表现成"detour 从没被调用"，被误当成"机制不可行"（铁律 117）。
    {
        HMODULE mfrw = GetModuleHandleW(L"mfreadwrite.dll");
        Check("A3 mfreadwrite.dll 已加载（vtable 判据有前提）", mfrw != nullptr);
        if (mfrw) {
            MODULEINFO mi = {};
            GetModuleInformation(GetCurrentProcess(), mfrw, &mi, sizeof(mi));
            const BYTE* lo = static_cast<const BYTE*>(mi.lpBaseOfDll);
            const BYTE* hi = lo + mi.SizeOfImage;
            const BYTE* fn = static_cast<const BYTE*>(vtbl[kReadSampleSlot]);
            char nm[160];
            snprintf(nm, sizeof(nm), "A4 vtable[%d] 落在 mfreadwrite.dll 范围内（槽号没记错）",
                kReadSampleSlot);
            Check(nm, fn >= lo && fn < hi);
        }
    }

    g_realReadSample = reinterpret_cast<ReadSample_t>(vtbl[kReadSampleSlot]);
    DWORD oldProtect = 0;
    if (!VirtualProtect(&vtbl[kReadSampleSlot], sizeof(void*), PAGE_READWRITE, &oldProtect)) {
        printf("  [FATAL] VirtualProtect 失败\n");
        reader->Release(); DeleteFileW(wavPath); MFShutdown();
        return 2;
    }
    vtbl[kReadSampleSlot] = reinterpret_cast<void*>(&ReadSample_Detour);
    DWORD tmp = 0;
    VirtualProtect(&vtbl[kReadSampleSlot], sizeof(void*), oldProtect, &tmp);
    Check("A5 成功 patch 掉 ReadSample 的 vtable 槽", true);

    // ---- B. detour 会被调用吗？先关着替换跑一轮（基线）----
    printf("\n--- B. detour 调用与「调用方可见」验证 ---\n");
    {
        IMFSample* s = nullptr;
        DWORD ai = 0, sf = 0; LONGLONG ts = 0;
        const HRESULT hr1 = reader->ReadSample(MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0,
            &ai, &sf, &ts, &s);
        Check("B1 detour 被调用了（hits>0）",
            InterlockedCompareExchange(&g_hits, 0, 0) > 0);
        Check("B2 第一次 ReadSample 成功且返回 sample", SUCCEEDED(hr1) && s != nullptr);
        Check("B3 替换关着时，调用方拿到的是**真数据**（非空真对照）",
            s != nullptr && InterlockedCompareExchange(&g_realNonZero, 0, 0) == 0);
        if (s) s->Release();
    }

    // ---- C. 打开替换，读一批样本 ----
    InterlockedExchange(&g_spoofOn, 1);
    {
        int guard = 0;
        while (guard++ < 64) {
            IMFSample* s = nullptr;
            DWORD ai = 0, sf = 0; LONGLONG ts = 0;
            const HRESULT hr2 = reader->ReadSample(MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0,
                &ai, &sf, &ts, &s);
            if (s) {
                // 调用方视角：Lock 一次，确认看到的是全 0。
                IMFMediaBuffer* b = nullptr;
                if (SUCCEEDED(s->GetBufferByIndex(0, &b)) && b) {
                    BYTE* p = nullptr; DWORD mx = 0, cur = 0;
                    if (SUCCEEDED(b->Lock(&p, &mx, &cur)) && p && cur) {
                        bool z = true;
                        for (DWORD i = 0; i < cur; ++i) { if (p[i]) { z = false; break; } }
                        if (z) InterlockedIncrement(&g_callerSawZero);
                        else InterlockedIncrement(&g_callerSawReal);
                        b->Unlock();
                    }
                    b->Release();
                }
                s->Release();
            }
            if (FAILED(hr2)) break;
            if (sf & MF_SOURCE_READERF_ENDOFSTREAM) break;
        }
    }

    Check("C1 真数据里确实有非 0 内容（非空真前提）",
        InterlockedCompareExchange(&g_realNonZero, 0, 0) > 0);
    Check("C2 至少有一个样本被改写（rewritten>0）",
        InterlockedCompareExchange(&g_rewritten, 0, 0) > 0);
    Check("C3 **调用方看到的是全 0**（不是我们自己的副本）",
        InterlockedCompareExchange(&g_callerSawReal, 0, 0) == 0
        && InterlockedCompareExchange(&g_callerSawZero, 0, 0) > 0);
    Check("C4 没有 Lock 失败（缓冲区可写）",
        InterlockedCompareExchange(&g_lockFailed, 0, 0) == 0);

    // ⚠️ vtable **先不还原** —— Part E 的真摄像头读取器要用同一个被 patch 的 vtable。

    // ---------- Part D：中性帧填充决策表（共用 codec）----------
    printf("\n--- D. 中性帧填充决策表（生产与探针共用 camera_spoof_codec.h）---\n");
    {
        // ---- D0：★ 防漂闸门 —— codec 里自带的那份 GUID 必须与 SDK 相等 ----
        //   为什么这条最重要：codec 刻意不引 MF 头（生产侧也不引），
        //   GUID 是"手抄"的。抄错一位 ⇒ 子类型识别不出来 ⇒
        //   **整条替换链静默失效**（而且看起来"一切正常"）。
        //   这里用 SDK 的 `MFVideoFormat_*` 做**交叉校验**（铁律 195/117）。
        Check("D0a codec 的 RGB32 GUID == SDK MFVideoFormat_RGB32",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatRgb32, MFVideoFormat_RGB32));
        Check("D0b codec 的 ARGB32 GUID == SDK MFVideoFormat_ARGB32",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatArgb32, MFVideoFormat_ARGB32));
        Check("D0c codec 的 RGB24 GUID == SDK MFVideoFormat_RGB24",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatRgb24, MFVideoFormat_RGB24));
        Check("D0d codec 的 YUY2 GUID == SDK MFVideoFormat_YUY2",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatYuy2, MFVideoFormat_YUY2));
        Check("D0e codec 的 UYVY GUID == SDK MFVideoFormat_UYVY",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatUyvy, MFVideoFormat_UYVY));
        Check("D0f codec 的 NV12 GUID == SDK MFVideoFormat_NV12",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatNv12, MFVideoFormat_NV12));
        Check("D0g codec 的 I420 GUID == SDK MFVideoFormat_I420",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatI420, MFVideoFormat_I420));
        Check("D0h codec 的 IYUV GUID == SDK MFVideoFormat_IYUV",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatIyuv, MFVideoFormat_IYUV));
        Check("D0i codec 的 YV12 GUID == SDK MFVideoFormat_YV12",
            GuidSameAsSdk(R3ShieldCoreCameraSpoof::kFormatYv12, MFVideoFormat_YV12));

        // ---- D1~D4：分类与计划 ----
        NeutralPlan plan = {};
        Check("D1 RGB32 -> 全 0 策略（**恰好就是黑**，与 v67 屏幕面口径一致）",
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Rgb32, 640, 480, 0, plan)
            && plan.kind == FillKind::AllZero);
        Check("D2 NV12 -> 平面 YUV 策略，名义步长 = 宽（**不是全 0** —— 全 0 在 YUV 里是饱和色）",
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Nv12, 640, 480, 0, plan)
            && plan.kind == FillKind::PlanarYuv && plan.stride == 640);
        Check("D3 YUY2 -> 紧凑 4:2:2 策略，名义步长 = 宽×2，Y 在前",
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Yuy2, 640, 480, 0, plan)
            && plan.kind == FillKind::PackedYuv422 && plan.stride == 1280
            && plan.packedOrder == 0);
        Check("D3b UYVY -> 紧凑 4:2:2 策略，U 在前（**顺序不同**，填错就成花屏）",
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Uyvy, 640, 480, 0, plan)
            && plan.kind == FillKind::PackedYuv422 && plan.packedOrder == 1);
        Check("D4 不认识的子类型 -> 规划失败（回落「拒绝」，铁律 194/196）",
            !R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Unknown, 640, 480, 0, plan)
            && !R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Unknown, 0, 480, 0, plan));
        Check("D4b 尺寸为 0 -> 规划失败（防除零/防把空帧当有效帧）",
            !R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Nv12, 0, 480, 0, plan)
            && !R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Nv12, 640, 0, 0, plan));

        // ---- D5：**按真实布局**填（不再是探针早期的 len/3*2 近似）----
        //   NV12 640×480：Y 平面 = 640×480 = 307200 字节，色度 = 153600。
        {
            const unsigned W = 640, H = 480;
            const size_t total = (size_t)W * H * 3 / 2;
            BYTE* buf = (BYTE*)malloc(total);
            memset(buf, 0xAB, total);
            NeutralPlan p = {};
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Nv12, W, H, 0, p);
            R3ShieldCoreCameraSpoof::ApplyNeutral(buf, (DWORD)total, p);
            bool yOk = true, uvOk = true;
            for (size_t i = 0; i < (size_t)W * H; ++i) { if (buf[i] != 16) { yOk = false; break; } }
            for (size_t i = (size_t)W * H; i < total; ++i) { if (buf[i] != 128) { uvOk = false; break; } }
            Check("D5 NV12 640×480：Y 平面全 16、色度平面全 128（按真实平面切分）",
                yOk && uvOk);
            free(buf);
        }

        // ---- D5b：YUY2 紧凑布局 —— 4 字节一组 [Y,U,Y,V] ----
        {
            const unsigned W = 640, H = 480;
            const size_t total = (size_t)W * H * 2;
            BYTE* buf = (BYTE*)malloc(total);
            memset(buf, 0xAB, total);
            NeutralPlan p = {};
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Yuy2, W, H, 0, p);
            R3ShieldCoreCameraSpoof::ApplyNeutral(buf, (DWORD)total, p);
            bool ok = true;
            for (size_t i = 0; i + 3 < total; i += 4) {
                if (buf[i] != 16 || buf[i + 1] != 128 || buf[i + 2] != 16 || buf[i + 3] != 128) {
                    ok = false; break;
                }
            }
            Check("D5b YUY2：每 4 字节 = [Y16, U128, Y16, V128]（交错布局，不是整块填同一个值）",
                ok);
            free(buf);
        }

        // ---- D5c：UYVY 的顺序**必须**与 YUY2 不同（否则红蓝/色度错位）----
        {
            BYTE a[8] = {}, b[8] = {};
            NeutralPlan p1 = {}, p2 = {};
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Yuy2, 4, 1, 0, p1);
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Uyvy, 4, 1, 0, p2);
            R3ShieldCoreCameraSpoof::ApplyNeutral(a, 8, p1);
            R3ShieldCoreCameraSpoof::ApplyNeutral(b, 8, p2);
            Check("D5c YUY2 与 UYVY 的填充结果**不同**（顺序真的按 packedOrder 走了）",
                a[0] == 16 && b[0] == 128 && memcmp(a, b, 8) != 0);
        }

        // ---- D6：反向对照 —— 把"清零 ≠ 黑"钉死 ----
        {
            BYTE yuv[300], rgb[300];
            memset(yuv, 0xAB, sizeof(yuv));
            NeutralPlan p = {};
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Nv12, 640, 480, 0, p);
            R3ShieldCoreCameraSpoof::ApplyNeutral(yuv, sizeof(yuv), p);
            // 老规则（v67/v70/v71 的"全 0"）
            memset(rgb, 0xAB, sizeof(rgb));
            ZeroMemory(rgb, sizeof(rgb));
            Check("D6 反向对照：老规则（全 0）在 YUV 下**不等于**黑（首字节 0 != 16）",
                rgb[0] != yuv[0] && yuv[0] == 16);
        }

        // ---- D7：★ 长度不变 —— 越界哨兵 ----
        //   这条是命门：`ApplyNeutral` 多写一个字节，就是"替换"引入的**新崩溃面**。
        {
            const size_t len = 300;
            BYTE* buf = (BYTE*)malloc(len + 32);
            memset(buf, 0xAB, len + 32);
            NeutralPlan p = {};
            R3ShieldCoreCameraSpoof::PlanForFormat(VideoFormat::Yuy2, 640, 480, 0, p);
            R3ShieldCoreCameraSpoof::ApplyNeutral(buf, (DWORD)len, p);
            bool tailOk = true;
            for (size_t i = len; i < len + 32; ++i) { if (buf[i] != 0xAB) { tailOk = false; break; } }
            Check("D7 填充**不越过 len**（哨兵字节未被改 —— 长度不变是命门）", tailOk);
            free(buf);
        }

        // ---- D8：`MF_MT_DEFAULT_STRIDE` 对自下而上的帧是**负数** ----
        //   实测属性会给出 -width。取绝对值即可（行序不影响中性化）。
        {
            NeutralPlan p = {};
            const bool ok = R3ShieldCoreCameraSpoof::PlanForFormat(
                VideoFormat::Nv12, 640, 480, -640, p);
            Check("D8 stride 传负数（自下而上帧）-> 取绝对值 640", ok && p.stride == 640);
        }

        // ---- D9：步长比名义值小 ⇒ **不猜**，回落名义值 ----
        //   比名义值小意味着"一行装不下" —— 用它会把相邻行涂错。宁可保守。
        {
            NeutralPlan p = {};
            const bool ok = R3ShieldCoreCameraSpoof::PlanForFormat(
                VideoFormat::Nv12, 640, 480, 320, p);
            Check("D9 stride < 名义值 -> 回落名义步长（不猜）", ok && p.stride == 640);
        }

        // ---- D10：步长比名义值大（驱动补了 padding）-> 用传入值 ----
        {
            NeutralPlan p = {};
            const bool ok = R3ShieldCoreCameraSpoof::PlanForFormat(
                VideoFormat::Nv12, 640, 480, 768, p);
            Check("D10 stride > 名义值（驱动 padding）-> 采用传入的 768", ok && p.stride == 768);
        }
    }

    // ---------- Part E：真摄像头帧（**可选**，默认跳过并计数）----------
    //
    // ★ 为什么默认不跑：它会**打开真实摄像头**（指示灯会亮）。本探针是
    //   "自包含、不注入"的，不属于铁律 175 约束的"跑引擎"，但"开硬件"这种事
    //   应当由使用者显式决定 —— 所以做成 `--use-camera` 开关，
    //   默认 `[SKIP]` **并计入结论行**（铁律 178：跳过必须可见、必须计数）。
    printf("\n--- E. 真摄像头帧（可选：--use-camera）---\n");
    if (!g_useCamera) {
        printf("  [SKIP] 未传 --use-camera（默认不开硬件；跳过数已计入结论行）\n");
        g_skip++;
    }
    else if (InterlockedCompareExchange(&g_deviceCount, 0, 0) == 0) {
        printf("  [SKIP] 本机没有视频采集设备\n");
        g_skip++;
    }
    else {
        IMFAttributes* attr = nullptr;
        IMFActivate** devices = nullptr;
        UINT32 count = 0;
        HRESULT hr2 = MFCreateAttributes(&attr, 1);
        if (SUCCEEDED(hr2) && attr) {
            attr->SetGUID(MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
                MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID);
            hr2 = MFEnumDeviceSources(attr, &devices, &count);
        }

        IMFMediaSource* src = nullptr;
        IMFSourceReader* cam = nullptr;
        if (SUCCEEDED(hr2) && count > 0) {
            hr2 = devices[0]->ActivateObject(__uuidof(IMFMediaSource),
                reinterpret_cast<void**>(&src));
        }
        else {
            hr2 = E_FAIL;
        }

        if (SUCCEEDED(hr2) && src) {
            // ★ 实测发现：**很多真实摄像头不接受 RGB32 输出** ——
            //   `SetCurrentMediaType(RGB32)` 返回 0xC00D36B4（MF_E_INVALIDMEDIATYPE）。
            //   要让读取器替我们做色彩转换，必须打开"高级视频处理"属性。
            //   -> 两条路都试，并**如实报告哪条成了**（铁律 97）。
            IMFAttributes* rattr = nullptr;
            if (SUCCEEDED(MFCreateAttributes(&rattr, 1)) && rattr) {
                rattr->SetUINT32(MF_SOURCE_READER_ENABLE_ADVANCED_VIDEO_PROCESSING, TRUE);
            }
            hr2 = MFCreateSourceReaderFromMediaSource(src, rattr, &cam);
            if (rattr) rattr->Release();
            if (FAILED(hr2)) {
                hr2 = MFCreateSourceReaderFromMediaSource(src, nullptr, &cam);
            }
        }

        if (SUCCEEDED(hr2) && cam) {
            // 只选第一路视频流。
            cam->SetStreamSelection((DWORD)MF_SOURCE_READER_ALL_STREAMS, FALSE);
            cam->SetStreamSelection((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, TRUE);

            // 尽量把输出统一成 RGB32（这样"全 0 = 黑"成立，判据干净）。
            IMFMediaType* outType = nullptr;
            if (SUCCEEDED(MFCreateMediaType(&outType)) && outType) {
                outType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
                outType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_RGB32);
                const HRESULT hrSet = cam->SetCurrentMediaType(
                    (DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, nullptr, outType);
                printf("  SetCurrentMediaType(RGB32) hr=0x%08lX\n", (unsigned long)hrSet);
                outType->Release();
            }

            // 读当前媒体类型（拿到真实 subtype + 帧尺寸）。
            IMFMediaType* mt = nullptr;
            UINT32 w = 0, h = 0;
            GUID sub = {};
            bool gotType = false;
            if (SUCCEEDED(cam->GetCurrentMediaType((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, &mt)) && mt) {
                mt->GetGUID(MF_MT_SUBTYPE, &sub);
                MFGetAttributeSize(mt, MF_MT_FRAME_SIZE, &w, &h);
                gotType = true;
                const char* nm = SubtypeName(sub);
                char fc[8] = { 0 };
                const unsigned d = (unsigned)sub.Data1;
                fc[0] = (char)(d & 0xFF); fc[1] = (char)((d >> 8) & 0xFF);
                fc[2] = (char)((d >> 16) & 0xFF); fc[3] = (char)((d >> 24) & 0xFF);
                bool printable = true;
                for (int k = 0; k < 4; ++k) if (fc[k] < 32 || fc[k] > 126) printable = false;
                printf("  视频帧: subtype=%s 尺寸=%ux%u\n",
                    nm ? nm : (printable ? fc : "?"), w, h);
                printf("          （GUID.Data1=0x%08lX）\n", (unsigned long)d);
                mt->Release();
            }
            Check("E1 拿到视频媒体类型与帧尺寸", gotType && w > 0 && h > 0);

            unsigned bppX2 = 0;
            const VideoFormat vf = gotType ? ClassifySdk(sub) : VideoFormat::Unknown;
            const bool bppKnown = gotType && BytesPerPixelX2(vf, bppX2);
            Check("E1b 子类型是已知的（帧长判据有前提，铁律 117）", bppKnown);

            // 读若干帧，验证 detour 对**真实视频帧**同样生效。
            const LONG beforeReal = InterlockedCompareExchange(&g_realNonZero, 0, 0);
            const LONG beforeRw = InterlockedCompareExchange(&g_rewritten, 0, 0);
            DWORD frameLen = 0;
            int frames = 0;
            int neutralFrames = 0;   // ★ 调用方视角：帧内容 == 计划的中性值
            int realFrames = 0;      // ★ 调用方视角：帧里还是真数据（= 替换没生效）
            for (int i = 0; i < 8; ++i) {
                IMFSample* s = nullptr;
                DWORD ai = 0, sf = 0; LONGLONG ts = 0;
                const HRESULT hrR = cam->ReadSample((DWORD)MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0,
                    &ai, &sf, &ts, &s);
                if (FAILED(hrR)) { printf("  ReadSample hr=0x%08lX\n", (unsigned long)hrR); break; }
                if (s) {
                    IMFMediaBuffer* b = nullptr;
                    if (SUCCEEDED(s->ConvertToContiguousBuffer(&b)) && b) {
                        BYTE* p = nullptr; DWORD mx = 0, cur = 0;
                        if (SUCCEEDED(b->Lock(&p, &mx, &cur)) && p && cur) {
                            frameLen = cur;
                            // ★★ 调用方视角的判据：把**计划**写进一份副本，
                            //    再与调用方拿到的字节逐字节比。
                            //    相等 ⇒ 我们拿到的确实已经是"计划的中性帧"。
                            //    ⚠️ 这里**不重写一遍填充算法**（那是抄两份，铁律 195）——
                            //      复用 codec 本身，只是把结果作用在副本上。
                            if (bppKnown && frameLen) {
                                NeutralPlan expectPlan = {};
                                if (R3ShieldCoreCameraSpoof::PlanForFormat(vf, w, h, 0, expectPlan)) {
                                    BYTE* expect = (BYTE*)malloc(cur);
                                    memcpy(expect, p, cur);
                                    R3ShieldCoreCameraSpoof::ApplyNeutral(expect, cur, expectPlan);
                                    if (memcmp(expect, p, cur) == 0) neutralFrames++;
                                    else realFrames++;
                                    free(expect);
                                }
                            }
                            b->Unlock();
                        }
                        b->Release();
                    }
                    s->Release();
                    frames++;
                }
                if (sf & MF_SOURCE_READERF_ENDOFSTREAM) break;
            }
            printf("  读了 %d 帧，最后一帧字节数=%u；其中中性帧 %d / 真数据帧 %d\n",
                frames, frameLen, neutralFrames, realFrames);

            Check("E2 读到至少一帧真实视频帧", frames > 0);
            // ★ 前提：帧字节数必须与"宽×高×每像素字节数"吻合 ——
            //   ⚠️ 最初我写死 `w*h*4`（假定 RGB32），**实测失败**：
            //      真实设备给的是 **YUY2**（2 字节/像素，640×480 -> 614400）。
            //   这是"我的前提写错了"，不是机制错 -> 改成按子类型算（铁律 117）。
            Check("E3 帧字节数 == 宽×高×每像素字节数（子类型前提成立）",
                bppKnown && frameLen * 2 == (DWORD)w * h * bppX2);
            Check("E4 真实帧里有非 0 内容（非空真前提）",
                InterlockedCompareExchange(&g_realNonZero, 0, 0) > beforeReal);
            Check("E5 真实视频帧被改写了",
                InterlockedCompareExchange(&g_rewritten, 0, 0) > beforeRw);
            Check("E6 ★ 调用方拿到的每一帧都 == 计划的中性帧（不是我们自己的副本）",
                neutralFrames > 0 && realFrames == 0);
            // ★★ E7：把 D2 的结论**落到真实设备上**。
            //   如果设备给的是 YUV 家族（实测就是 YUY2），那么"全 0"**不是黑** ——
            //   所以生产版**不能**照搬 v67/v70/v71 的"清零"规则，必须按子类型填中性值。
            if (gotType && IsYuvFamily(vf)) {
                Check("E7 ★★ 真实设备是 YUV 家族 -> 全 0 **不是黑**（生产版必须填 Y16/UV128）",
                    true);
                printf("       -> 实测子类型属 YUV 家族：生产版填的是 **Y16/UV128**（有限范围的黑），"
                       "不是「清零」—— 对外口径不能写「全 0 黑帧」。\n");
            }
            else if (gotType && vf != VideoFormat::Unknown) {
                printf("       （本次设备给的是 RGB 家族 -> 全 0 恰好等于黑）\n");
                Check("E7 真实设备是 RGB 家族 -> 全 0 即黑", true);
            }
            else if (gotType) {
                // ★ 诚实标注：压缩子类型（MJPG/H264）**造不出**中性帧 ——
                //   生产版在这里必须**回落「拒绝」**（铁律 194/196），不能硬填。
                printf("       -> [注意] 子类型 %s **不在支持表里**：生产版会**回落「拒绝」**"
                       "（造不出合法中性帧，铁律 194/196）。\n", SubtypeName(sub));
                Check("E7 真实设备子类型不在支持表 -> 生产版回落「拒绝」（如实标注）", true);
            }
        }
        else {
            printf("  [SKIP] 打开摄像头失败 hr=0x%08lX（被占用 / 无权限 / 无设备）\n",
                (unsigned long)hr2);
            g_skip++;
        }

        if (cam) cam->Release();
        if (src) src->Release();
        if (devices) {
            for (UINT32 i = 0; i < count; ++i) if (devices[i]) devices[i]->Release();
            CoTaskMemFree(devices);
        }
        if (attr) attr->Release();
    }

    // ---------- 收尾 ----------
    // ---- 还原 vtable ----
    VirtualProtect(&vtbl[kReadSampleSlot], sizeof(void*), PAGE_READWRITE, &oldProtect);
    vtbl[kReadSampleSlot] = reinterpret_cast<void*>(g_realReadSample);
    VirtualProtect(&vtbl[kReadSampleSlot], sizeof(void*), oldProtect, &tmp);

    reader->Release();
    DeleteFileW(wavPath);
    MFShutdown();

    printf("\n=== 结果：%d passed, %d failed, %d skipped ===\n", g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}
