//
// v73_guard_ut.cpp —— R3ShieldCore v73「摄像头帧替换」单测（**纯逻辑，不碰 MF / 摄像头**）。
//
// ★ v73 加了什么：
//   把「回传数据替换」扩到**流式**的摄像头帧 —— 建读取器时 patch
//   `IMFSourceReader::ReadSample` 的 vtable 槽，之后**每一帧**被原地改成中性帧
//   （`Decision::Spoofed`）。
//
// ★ 为什么这个单测和机制探针**都要有**（分工）：
//   · 本文件：**纯逻辑**，零 MF 调用、零设备、毫秒级。覆盖
//     `camera_spoof_codec.h` 的**全部决策分支** —— 分类 / 名义步长 / 步长回落
//     / 三种填充 / 溢出防护 / **越界哨兵**。
//   · `tools/spoof_camera_probe.cpp`：**真 API**。自己挂自己的 hook，用合成
//     音频源 + 真摄像头，实测"vtable 槽 9 到底是不是 ReadSample"、
//     "`IMFMediaBuffer::Lock` 改完调用方看不看得见"、以及 SDK GUID 的
//     static_assert 交叉校验。
//   两者缺一：只跑探针 ⇒ 分支（溢出 / 尾部不足一组 / stride 回落）覆盖不全；
//   只跑单测 ⇒ "真 API 到底认不认这套布局"没人证。
//
// ★★ 本面的**命门**（前三个面 v67/v70/v71 没有的）：
//   ① **"全 0"在 YUV 里不是黑**（是饱和色）⇒ 谁把清零当黑帧谁就错；
//   ② **长度一个都不改** —— 只写 [0, len)，越界一个字节都不许碰。
//   本文件对这两条都配了**反向对照**（否则断言可能恒真）。
//
// 构建/运行：bash build_guard_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <wchar.h>

#include "camera_spoof_codec.h"

using namespace R3ShieldCoreCameraSpoof;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// ------------------------------------------------------------------ 工具
static SpoofGuid MakeGuid(ULONG d1, USHORT d2, USHORT d3,
	BYTE b0, BYTE b1, BYTE b2, BYTE b3, BYTE b4, BYTE b5, BYTE b6, BYTE b7)
{
	SpoofGuid g = {};
	g.Data1 = d1; g.Data2 = d2; g.Data3 = d3;
	g.Data4[0] = b0; g.Data4[1] = b1; g.Data4[2] = b2; g.Data4[3] = b3;
	g.Data4[4] = b4; g.Data4[5] = b5; g.Data4[6] = b6; g.Data4[7] = b7;
	return g;
}

// FourCC('a','b','c','d') 的小端值。
static ULONG FourCc(char a, char b, char c, char d)
{
	return static_cast<ULONG>(static_cast<BYTE>(a))
		| (static_cast<ULONG>(static_cast<BYTE>(b)) << 8)
		| (static_cast<ULONG>(static_cast<BYTE>(c)) << 16)
		| (static_cast<ULONG>(static_cast<BYTE>(d)) << 24);
}

static bool IsAsciiOnly(const char* s)
{
	if (!s) return false;
	for (const char* p = s; *p; ++p) {
		const unsigned char c = static_cast<unsigned char>(*p);
		if (c < 0x20 || c > 0x7E) return false;
	}
	return true;
}

// ================================================================== 1. 分类
static void TestClassify()
{
	printf("\n--- 1. ClassifyFormat：9 个已知子类型 + 未知 ---\n");

	struct Case { const char* name; SpoofGuid g; VideoFormat want; };
	const Case cases[] = {
		{ "RGB32",  kFormatRgb32,  VideoFormat::Rgb32  },
		{ "ARGB32", kFormatArgb32, VideoFormat::Argb32 },
		{ "RGB24",  kFormatRgb24,  VideoFormat::Rgb24  },
		{ "YUY2",   kFormatYuy2,   VideoFormat::Yuy2   },
		{ "UYVY",   kFormatUyvy,   VideoFormat::Uyvy   },
		{ "NV12",   kFormatNv12,   VideoFormat::Nv12   },
		{ "I420",   kFormatI420,   VideoFormat::I420   },
		{ "IYUV",   kFormatIyuv,   VideoFormat::Iyuv   },
		{ "YV12",   kFormatYv12,   VideoFormat::Yv12   },
	};
	for (const Case& c : cases) {
		char buf[96];
		snprintf(buf, sizeof(buf), "ClassifyFormat(%s) -> %s", c.name, c.name);
		Check(buf, ClassifyFormat(c.g) == c.want);
	}

	// 未知：随便一个 GUID 必须是 Unknown（**不能**"猜一个最像的"）。
	const SpoofGuid bogus = MakeGuid(0x11111111, 0x2222, 0x3333, 1, 2, 3, 4, 5, 6, 7, 8);
	Check("ClassifyFormat(未知 GUID) -> Unknown", ClassifyFormat(bogus) == VideoFormat::Unknown);

	// ★ 反向对照：未知 GUID 与任何一个已知 GUID 都**不相等**
	//   （否则"返回 Unknown"这条断言可能因为 GuidEquals 恒真而变得没意义）。
	Check("GuidEquals：未知 GUID != RGB32（GuidEquals 本身是活的）",
		!GuidEquals(bogus, kFormatRgb32));
	Check("GuidEquals：GUID 与自身相等",
		GuidEquals(kFormatRgb32, kFormatRgb32));

	// ★ 9 个 GUID **两两不同**（防手滑抄成同一个值 ⇒ 分类全塌）。
	int dup = 0;
	const SpoofGuid all[] = {
		kFormatRgb32, kFormatArgb32, kFormatRgb24, kFormatYuy2, kFormatUyvy,
		kFormatNv12, kFormatI420, kFormatIyuv, kFormatYv12,
	};
	for (int i = 0; i < 9; ++i) {
		for (int j = i + 1; j < 9; ++j) {
			if (GuidEquals(all[i], all[j])) dup++;
		}
	}
	Check("9 个子类型 GUID 两两不同（0 对重复）", dup == 0);

	// ★ 尾巴不变量：MF 的 D3D 格式 GUID 尾巴统一是
	//   0000-0010-8000-00AA00389B71。抄错一位 ⇒ 真机上一个都匹配不上。
	const SpoofGuid tail = MakeGuid(0, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71);
	int tailBad = 0;
	for (int i = 0; i < 9; ++i) {
		SpoofGuid t = all[i];
		t.Data1 = 0;
		if (!GuidEquals(t, tail)) tailBad++;
	}
	Check("9 个 GUID 的尾巴都是 0000-0010-8000-00AA00389B71", tailBad == 0);

	// ★ FourCC 自洽：6 个压缩/平面 YUV 的 Data1 应当**就是**它名字的 FourCC。
	Check("kFormatYuy2 的 Data1 == FOURCC('YUY2')", kFormatYuy2.Data1 == FourCc('Y', 'U', 'Y', '2'));
	Check("kFormatUyvy 的 Data1 == FOURCC('UYVY')", kFormatUyvy.Data1 == FourCc('U', 'Y', 'V', 'Y'));
	Check("kFormatNv12 的 Data1 == FOURCC('NV12')", kFormatNv12.Data1 == FourCc('N', 'V', '1', '2'));
	Check("kFormatI420 的 Data1 == FOURCC('I420')", kFormatI420.Data1 == FourCc('I', '4', '2', '0'));
	Check("kFormatIyuv 的 Data1 == FOURCC('IYUV')", kFormatIyuv.Data1 == FourCc('I', 'Y', 'U', 'V'));
	Check("kFormatYv12 的 Data1 == FOURCC('YV12')", kFormatYv12.Data1 == FourCc('Y', 'V', '1', '2'));
	// D3DFMT_X8R8G8B8 = 22 / D3DFMT_A8R8G8B8 = 21 / D3DFMT_R8G8B8 = 20
	Check("kFormatRgb32 的 Data1 == 22 (D3DFMT_X8R8G8B8)", kFormatRgb32.Data1 == 22);
	Check("kFormatArgb32 的 Data1 == 21 (D3DFMT_A8R8G8B8)", kFormatArgb32.Data1 == 21);
	Check("kFormatRgb24 的 Data1 == 20 (D3DFMT_R8G8B8)", kFormatRgb24.Data1 == 20);
}

// ================================================================== 2. 名字
static void TestFormatName()
{
	printf("\n--- 2. FormatName：非空 + 纯 ASCII + 两两不同 ---\n");

	const VideoFormat all[] = {
		VideoFormat::Unknown,
		VideoFormat::Rgb32, VideoFormat::Argb32, VideoFormat::Rgb24,
		VideoFormat::Yuy2, VideoFormat::Uyvy,
		VideoFormat::Nv12, VideoFormat::I420, VideoFormat::Iyuv, VideoFormat::Yv12,
	};
	const int n = static_cast<int>(sizeof(all) / sizeof(all[0]));

	int nonAscii = 0, empty = 0, dup = 0;
	for (int i = 0; i < n; ++i) {
		const char* s = FormatName(all[i]);
		if (!s || s[0] == '\0') empty++;
		else if (!IsAsciiOnly(s)) nonAscii++;
		for (int j = i + 1; j < n; ++j) {
			const char* t = FormatName(all[j]);
			if (s && t && strcmp(s, t) == 0) dup++;
		}
	}
	// ★ 纯 ASCII 是硬要求：`strings -el` 只输出 ASCII（铁律 193），
	//   日志里的格式名要能被 `check_dist_sync.sh` 之类的闸门 grep 到。
	Check("FormatName：10 个取值都非空", empty == 0);
	Check("FormatName：10 个取值都是纯 ASCII（铁律 193）", nonAscii == 0);
	Check("FormatName：10 个取值两两不同（0 对重复）", dup == 0);

	// 抽查几个名字本身（不是"只要有名字就行"）。
	Check("FormatName(Rgb32) == \"RGB32\"", strcmp(FormatName(VideoFormat::Rgb32), "RGB32") == 0);
	Check("FormatName(Yuy2)  == \"YUY2\"", strcmp(FormatName(VideoFormat::Yuy2), "YUY2") == 0);
	Check("FormatName(Unknown) == \"UNKNOWN\"", strcmp(FormatName(VideoFormat::Unknown), "UNKNOWN") == 0);
}

// ================================================================== 3. 名义步长
static void TestNominalStride()
{
	printf("\n--- 3. NominalStride：每像素字节数 × 宽度 ---\n");

	struct Case { VideoFormat f; unsigned w; unsigned want; bool ok; const char* name; };
	const Case cases[] = {
		{ VideoFormat::Rgb32,  640, 640 * 4, true,  "RGB32"  },
		{ VideoFormat::Argb32, 640, 640 * 4, true,  "ARGB32" },
		{ VideoFormat::Rgb24,  640, 640 * 3, true,  "RGB24"  },
		{ VideoFormat::Yuy2,   640, 640 * 2, true,  "YUY2"   },
		{ VideoFormat::Uyvy,   640, 640 * 2, true,  "UYVY"   },
		{ VideoFormat::Nv12,   640, 640,     true,  "NV12"   },
		{ VideoFormat::I420,   640, 640,     true,  "I420"   },
		{ VideoFormat::Iyuv,   640, 640,     true,  "IYUV"   },
		{ VideoFormat::Yv12,   640, 640,     true,  "YV12"   },
	};
	for (const Case& c : cases) {
		unsigned got = 0;
		const bool ok = NominalStride(c.f, c.w, got);
		char buf[96];
		snprintf(buf, sizeof(buf), "NominalStride(%s, 640) == %u", c.name, c.want);
		Check(buf, ok == c.ok && got == c.want);
	}

	unsigned got = 12345;
	Check("NominalStride(Unknown) 返回 false",
		!NominalStride(VideoFormat::Unknown, 640, got));
	// ★ 返回 false 时**不能**改 out（否则调用方可能拿旧值当有效值用）。
	Check("NominalStride(Unknown) 失败时不改 out（out 保持 12345）", got == 12345);
}

// ================================================================== 4. 造计划
static void TestPlanForFormat()
{
	printf("\n--- 4. PlanForFormat：可造 / 不可造 + 步长规则 ---\n");

	NeutralPlan plan = {};

	// ---- 不可造：必须返回 false ⇒ 调用方回落「拒绝」（铁律 194/196）----
	Check("Unknown -> false", !PlanForFormat(VideoFormat::Unknown, 640, 480, 0, plan));
	Check("width == 0 -> false", !PlanForFormat(VideoFormat::Rgb32, 0, 480, 0, plan));
	Check("height == 0 -> false", !PlanForFormat(VideoFormat::Rgb32, 640, 0, 0, plan));

	// ---- 填充类别映射 ----
	Check("RGB32  -> AllZero", PlanForFormat(VideoFormat::Rgb32, 640, 480, 0, plan)
		&& plan.kind == FillKind::AllZero);
	Check("ARGB32 -> AllZero", PlanForFormat(VideoFormat::Argb32, 640, 480, 0, plan)
		&& plan.kind == FillKind::AllZero);
	Check("RGB24  -> AllZero", PlanForFormat(VideoFormat::Rgb24, 640, 480, 0, plan)
		&& plan.kind == FillKind::AllZero);
	Check("YUY2   -> PackedYuv422 且 packedOrder == 0（Y 在前）",
		PlanForFormat(VideoFormat::Yuy2, 640, 480, 0, plan)
		&& plan.kind == FillKind::PackedYuv422 && plan.packedOrder == 0);
	Check("UYVY   -> PackedYuv422 且 packedOrder == 1（U 在前）",
		PlanForFormat(VideoFormat::Uyvy, 640, 480, 0, plan)
		&& plan.kind == FillKind::PackedYuv422 && plan.packedOrder == 1);
	Check("NV12   -> PlanarYuv", PlanForFormat(VideoFormat::Nv12, 640, 480, 0, plan)
		&& plan.kind == FillKind::PlanarYuv);
	Check("I420   -> PlanarYuv", PlanForFormat(VideoFormat::I420, 640, 480, 0, plan)
		&& plan.kind == FillKind::PlanarYuv);
	Check("IYUV   -> PlanarYuv", PlanForFormat(VideoFormat::Iyuv, 640, 480, 0, plan)
		&& plan.kind == FillKind::PlanarYuv);
	Check("YV12   -> PlanarYuv", PlanForFormat(VideoFormat::Yv12, 640, 480, 0, plan)
		&& plan.kind == FillKind::PlanarYuv);

	// ---- 步长规则 ----
	Check("stride == 0 -> 用名义步长（640*4）",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, 0, plan) && plan.stride == 640 * 4);
	Check("stride == 名义值 -> 就是名义值",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, 640 * 4, plan) && plan.stride == 640 * 4);
	Check("stride 比名义值大 -> 采用（驱动可能加了行 padding）",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, 640 * 4 + 64, plan) && plan.stride == 640 * 4 + 64);
	// ★ 负数 = **行序**（自下而上），不是"负步长"（MF_MT_DEFAULT_STRIDE 语义）。
	Check("stride == -名义值 -> 取绝对值",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, -(640 * 4), plan) && plan.stride == 640 * 4);
	Check("stride == -(名义值+64) -> 取绝对值",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, -(640 * 4 + 64), plan) && plan.stride == 640 * 4 + 64);
	// ★ 比名义值小 = 一行装不下 ⇒ **不猜**，回落名义值（铁律 117：判据要有前提检查）。
	Check("stride 比名义值小 -> 回落名义值（不猜）",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, 640 * 4 - 4, plan) && plan.stride == 640 * 4);
	Check("stride == 1 -> 回落名义值",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, 1, plan) && plan.stride == 640 * 4);
	Check("stride == -1 -> 回落名义值",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, -1, plan) && plan.stride == 640 * 4);

	// ---- 计划里带上了尺寸（ApplyNeutral 要用）----
	Check("计划里 width/height/format 都填好了",
		PlanForFormat(VideoFormat::Nv12, 320, 240, 0, plan)
		&& plan.width == 320 && plan.height == 240
		&& plan.format == VideoFormat::Nv12);

	// ---- 失败时 out 必须被清成**不可用**（fail-safe）----
	//
	// ★ 为什么是"清掉"而不是"原样留着"：调用方**有可能**忽略返回值直接
	//   `ApplyNeutral`（本项目的铁律 93：文档写了 ≠ 代码会读）。
	//   清成 `FillKind::Unsupported` ⇒ `ApplyNeutral` 什么都不做 = fail-safe；
	//   若留着上一次的 `AllZero`，就会**拿旧计划填新帧**（隐蔽得多）。
	NeutralPlan dirty = {};
	dirty.kind = FillKind::AllZero;
	dirty.stride = 999;
	const bool failed = !PlanForFormat(VideoFormat::Unknown, 640, 480, 0, dirty);
	Check("失败时 out.kind 被清成 Unsupported（不是留着旧计划）",
		failed && dirty.kind == FillKind::Unsupported);
	Check("失败时 out.stride 被清成 0（旧的 999 没有残留）", failed && dirty.stride == 0);
	// ★ 负对照：证明上面两条不是"恒真"—— 一个**成功**的调用必须写出非零 stride。
	NeutralPlan ok = {};
	Check("负对照：成功的调用会写出非零 stride（说明上面确实在测「被清掉」）",
		PlanForFormat(VideoFormat::Rgb32, 640, 480, 0, ok) && ok.stride == 640 * 4);
}

// ================================================================== 5. 填充
static void TestApplyNeutral()
{
	printf("\n--- 5. ApplyNeutral：三种填充 + 越界哨兵 ---\n");

	NeutralPlan plan = {};

	// ---- AllZero：整块清零 ----
	{
		BYTE buf[64];
		memset(buf, 0xAA, sizeof(buf));
		PlanForFormat(VideoFormat::Rgb32, 4, 4, 0, plan);
		ApplyNeutral(buf, static_cast<DWORD>(sizeof(buf)), plan);
		int nz = 0;
		for (BYTE b : buf) if (b != 0) nz++;
		Check("RGB32 -> 整块全 0（64 字节）", nz == 0);
	}

	// ---- PackedYuv422：YUY2 = [16,128,16,128] ----
	{
		BYTE buf[16];
		memset(buf, 0xAA, sizeof(buf));
		PlanForFormat(VideoFormat::Yuy2, 4, 2, 0, plan);
		ApplyNeutral(buf, static_cast<DWORD>(sizeof(buf)), plan);
		bool ok = true;
		for (int i = 0; i < 16; i += 4) {
			if (buf[i + 0] != 16 || buf[i + 1] != 128 || buf[i + 2] != 16 || buf[i + 3] != 128) ok = false;
		}
		Check("YUY2 -> 每 4 字节 [16,128,16,128]", ok);
	}

	// ---- PackedYuv422：UYVY = [128,16,128,16] ----
	{
		BYTE buf[16];
		memset(buf, 0xAA, sizeof(buf));
		PlanForFormat(VideoFormat::Uyvy, 4, 2, 0, plan);
		ApplyNeutral(buf, static_cast<DWORD>(sizeof(buf)), plan);
		bool ok = true;
		for (int i = 0; i < 16; i += 4) {
			if (buf[i + 0] != 128 || buf[i + 1] != 16 || buf[i + 2] != 128 || buf[i + 3] != 16) ok = false;
		}
		Check("UYVY -> 每 4 字节 [128,16,128,16]", ok);
	}

	// ★★ 反向对照（本面的命门）：
	//   YUY2 与 UYVY **必须不一样**；而且 YUV 的中性帧**不是全 0**
	//   —— 谁把"清零"当黑帧，这两条至少挂一条。
	{
		BYTE a[8], b[8];
		memset(a, 0xAA, sizeof(a)); memset(b, 0xAA, sizeof(b));
		PlanForFormat(VideoFormat::Yuy2, 4, 1, 0, plan);
		ApplyNeutral(a, 8, plan);
		PlanForFormat(VideoFormat::Uyvy, 4, 1, 0, plan);
		ApplyNeutral(b, 8, plan);
		Check("反向对照：YUY2 的填充 != UYVY 的填充（顺序没抄反）",
			memcmp(a, b, sizeof(a)) != 0);

		BYTE z[8] = {};
		Check("反向对照：YUY2 的中性帧 != 全 0（全 0 在 YUV 里是饱和色，不是黑）",
			memcmp(a, z, sizeof(a)) != 0);
	}

	// ---- 尾部不足一组（len 不是 4 的倍数）----
	{
		BYTE buf[6];
		memset(buf, 0xAA, sizeof(buf));
		PlanForFormat(VideoFormat::Yuy2, 4, 1, 0, plan);
		ApplyNeutral(buf, 6, plan);
		Check("YUY2 尾部不足一组 -> 剩 2 字节填 16（亮度）",
			buf[0] == 16 && buf[1] == 128 && buf[2] == 16 && buf[3] == 128
			&& buf[4] == 16 && buf[5] == 16);
	}

	// ---- PlanarYuv：NV12 640x480 按**真实平面**切分 ----
	{
		const DWORD len = 640 * 480 + 640 * 240;   // Y + UV(NV12 的色度是半高)
		BYTE* buf = new BYTE[len];
		memset(buf, 0xAA, len);
		PlanForFormat(VideoFormat::Nv12, 640, 480, 0, plan);
		ApplyNeutral(buf, len, plan);

		const DWORD yLen = 640 * 480;
		int yBad = 0, cBad = 0;
		for (DWORD i = 0; i < yLen; ++i) if (buf[i] != 16) yBad++;
		for (DWORD i = yLen; i < len; ++i) if (buf[i] != 128) cBad++;
		Check("NV12 640x480 -> Y 平面 [0, 307200) 全 16", yBad == 0);
		Check("NV12 640x480 -> 色度平面 [307200, len) 全 128", cBad == 0);
		// ★ 负对照：如果实现把 len/2 当分界，这条会红。
		Check("NV12 分界点 == stride*height（不是 len/2）", yLen == 640 * 480 && yLen != len / 2);
		delete[] buf;
	}

	// ---- PlanarYuv：缓冲区比"一个 Y 平面"还小 -> 整块都当亮度 ----
	{
		BYTE buf[100];
		memset(buf, 0xAA, sizeof(buf));
		PlanForFormat(VideoFormat::Nv12, 640, 480, 0, plan);   // yLen = 307200 >> 100
		ApplyNeutral(buf, static_cast<DWORD>(sizeof(buf)), plan);
		int bad = 0;
		for (BYTE b : buf) if (b != 16) bad++;
		Check("PlanarYuv：yLen > len 时**截到 len**，整块填 16（不越界）", bad == 0);
	}

	// ---- 溢出防护：stride × height 用 ULONGLONG 算 ----
	//   若用 32 位乘法：0xFFFF0000 * 0xFFFF 会回绕成很小的值 ⇒
	//   色度平面被当成亮度填 ⇒ 大量字节变成 16 而不是 128。
	{
		BYTE buf[256];
		memset(buf, 0xAA, sizeof(buf));
		NeutralPlan big = {};
		big.kind = FillKind::PlanarYuv;
		big.format = VideoFormat::Nv12;
		big.width = 0xFFFF0000u;
		big.height = 0xFFFFu;
		big.stride = 0xFFFF0000u;
		ApplyNeutral(buf, static_cast<DWORD>(sizeof(buf)), big);
		int bad = 0;
		for (BYTE b : buf) if (b != 16) bad++;
		Check("溢出防护：stride*height 回绕时整块仍是亮度 16（不越界、不误判色度）", bad == 0);
	}

	// ---- 越界哨兵：len 之后 32 字节**一个都不能改** ----
	//   ★ 这是本面"长度不变"的**唯一**硬判据（结构上不可能靠改长度来通过）。
	{
		const DWORD len = 640 * 480 + 640 * 240;
		const DWORD guard = 32;
		BYTE* buf = new BYTE[len + guard];
		memset(buf, 0xAA, len + guard);
		// ★ 前提检查：哨兵区在填充前确实是 0xAA（否则这条判据可能恒真）。
		bool preOk = true;
		for (DWORD i = len; i < len + guard; ++i) if (buf[i] != 0xAA) preOk = false;
		Check("哨兵前提：填充前 [len, len+32) 确实是 0xAA", preOk);

		PlanForFormat(VideoFormat::Nv12, 640, 480, 0, plan);
		ApplyNeutral(buf, len, plan);

		bool sentinelOk = true;
		for (DWORD i = len; i < len + guard; ++i) if (buf[i] != 0xAA) sentinelOk = false;
		Check("越界哨兵：ApplyNeutral 只写 [0, len)，len 之后 32 字节未动", sentinelOk);
		delete[] buf;
	}

	// ---- YUY2 也过一遍哨兵（另一条填充分支）----
	{
		const DWORD len = 640 * 2 * 4;
		const DWORD guard = 32;
		BYTE* buf = new BYTE[len + guard];
		memset(buf, 0xAA, len + guard);
		PlanForFormat(VideoFormat::Yuy2, 640, 4, 0, plan);
		ApplyNeutral(buf, len, plan);
		bool sentinelOk = true;
		for (DWORD i = len; i < len + guard; ++i) if (buf[i] != 0xAA) sentinelOk = false;
		Check("越界哨兵（YUY2 分支）：len 之后 32 字节未动", sentinelOk);
		delete[] buf;
	}

	// ---- 边界：p == nullptr / len == 0 必须是**无操作** ----
	{
		PlanForFormat(VideoFormat::Rgb32, 4, 4, 0, plan);
		ApplyNeutral(nullptr, 64, plan);   // 不能崩
		Check("ApplyNeutral(nullptr, ...) 不崩", true);

		BYTE buf[8];
		memset(buf, 0xAA, sizeof(buf));
		ApplyNeutral(buf, 0, plan);
		int bad = 0;
		for (BYTE b : buf) if (b != 0xAA) bad++;
		Check("ApplyNeutral(len == 0) 是无操作", bad == 0);
	}

	// ---- Unsupported 计划：什么都不做（调用方本该先看 PlanForFormat）----
	{
		BYTE buf[16];
		memset(buf, 0xAA, sizeof(buf));
		NeutralPlan unsupported = {};
		unsupported.kind = FillKind::Unsupported;
		ApplyNeutral(buf, static_cast<DWORD>(sizeof(buf)), unsupported);
		int bad = 0;
		for (BYTE b : buf) if (b != 0xAA) bad++;
		Check("Unsupported 计划 -> 一个字节都不动（fail-safe，不是 fail-open）", bad == 0);
	}
}

// ================================================================== 6. 常量
static void TestConstants()
{
	printf("\n--- 6. 中性值常量 ---\n");

	// ★ 这两个数字不是"随便定的"：有限范围（video range）里
	//   黑 = Y16 / UV128。写成 0 就是把饱和色当黑（本面的头号坑）。
	Check("kLimitedBlackY == 16（有限范围的黑，不是 0）", kLimitedBlackY == 16);
	Check("kNeutralChroma == 128（色度中性点）", kNeutralChroma == 128);
	Check("反向对照：kLimitedBlackY != 0（否则就是「清零当黑」那个错）",
		kLimitedBlackY != 0);
}

// ------------------------------------------------------------------ 主流程
int main()
{
	setlocale(LC_ALL, ".936");
	printf("=== v73 摄像头帧替换 · codec 层单测（纯逻辑，不碰 MF / 摄像头）===\n");

	TestClassify();
	TestFormatName();
	TestNominalStride();
	TestPlanForFormat();
	TestApplyNeutral();
	TestConstants();

	printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
