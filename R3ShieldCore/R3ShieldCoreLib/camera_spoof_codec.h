#pragma once
//
// camera_spoof_codec.h —— 摄像头/视频帧「替换」的**中性帧决策表与填充**。
//
// 职责单一：给定**子类型**与**帧尺寸**，回答两件事 ——
//   ① 这一帧能不能造出**合法的中性替代物**？（造不出 ⇒ 调用方必须回落「拒绝」）
//   ② 能造的话，往缓冲区的哪些字节填什么值？（**长度一个都不改**）
//
// ★★ 为什么单独成一个**头文件**（而不是塞进 camera_guard.cpp）：
//   这份逻辑要**同时**被三处使用 ——
//     ① 生产：`camera_guard.cpp` 的 `ReadSample` / `OnReadSample` detour；
//     ② 验证：`tools/spoof_camera_probe.cpp`（自包含可行性探针）；
//     ③ 单测：`tools/v73_guard_ut.cpp`（纯逻辑，不需要摄像头 / MF 运行时）。
//   抄两份 ⇒ 必漂（铁律 127）；而且**漂了之后探针照样全绿、生产照样出错**。
//   全部 `inline` ⇒ 探针/单测直接 `#include`，不链 lib、不改构建（铁律 195）。
//
// ⚠️ 这里**不做**任何判定（不读 Policy、不看 mode、不打日志、不碰 COM）——
//   那是 guard 的事。本文件是**纯函数**：进什么、出什么，没有全局状态。
//
// ==================================================================
// ★★★ 本面**特有**的坑：v67/v70/v71 那条"同长度、内容清零"**不能照搬**
// ==================================================================
//
//   前三个面的规则是「同格式、同尺寸、内容清零」。摄像头帧**不行** ——
//   因为"全 0"在 **YUV** 里**不是黑**，而是一个**饱和色**（洋红/绿那种）。
//   安全目标（不泄露真画面）仍然达到（全 0 也是"合法图像"），
//   但如果对外声称"黑帧"，那是**撒谎**（铁律 97 的同类：口径必须与实际一致）。
//
//   ⇒ 所以这里按 `MF_MT_SUBTYPE` 给出**中性值**：
//        · RGB 家族：全 0（**恰好就是黑**，与屏幕面口径一致）；
//        · YUV 家族：**有限范围（video range）的黑** = Y16 / UV128。
//
//   ★ 判据（探针里有反向对照把这条钉死）：
//       "全 0" 与 "黑" 在 YUV 下**不相等** ⇒ 谁把清零当黑帧，谁就错。
//
// ==================================================================
// ★★ 第二条：**不认识的子类型必须回落「拒绝」，不能猜**
// ==================================================================
//
//   压缩子类型（MJPG / H264 / HEVC …）的帧是**码流**，不是像素。
//   往里填 16/128 得到的是**一帧解不出来的垃圾** —— 既不是黑帧，
//   又可能让下游解码器报错/花屏。所以：
//     不认识的子类型 ⇒ `PlanForFormat` 返回 false ⇒ 调用方**回落「拒绝」**
//     （= 没有本开关时的行为），**绝不**"随便填点什么"（铁律 194/196）。
//
// ⚠️ 已知盲区（诚实标注，非本开关引入）：
//   · 异步读取（`MF_SOURCE_READER_ASYNC_CALLBACK`）走回调交付帧 ——
//     由 `camera_guard.cpp` 额外 patch 回调的 `OnReadSample` 覆盖；
//   · 帧**尺寸/步长**取自 `MF_MT_FRAME_SIZE` + `MF_MT_DEFAULT_STRIDE`
//     （拿不到时按**名义步长**算）—— 若驱动用了非标准步长，
//     可能出现"右侧/底部若干字节没被中性化"的**残留**（不是泄露整帧，
//     但也不是像素级干净）。这类残留**只影响观感，不影响"不泄露"**；
//   · DirectShow / WinRT `MediaCapture` / 内核态摄像头驱动路径**未覆盖**。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <string.h>

namespace R3ShieldCoreCameraSpoof
{
	// ------------------------------------------------------------------
	// GUID（与 SDK 的 `MFVideoFormat_*` 一一对应）
	// ------------------------------------------------------------------
	//
	// ★ 为什么在这里自己定义一份，而不是 `#include <mfapi.h>`：
	//   ① 生产侧（`camera_guard.cpp`）**刻意不引 MF 头**（那套会拉进
	//      一大堆类型与潜在的链接依赖，而 guard 只用到几个 GUID）；
	//   ② 单测/探针要能在**没有 MF 运行时**的机器上跑。
	//   ⇒ GUID 值本身是**冻结的 ABI**（Windows SDK 定义，永不改变），
	//     定义在这里是安全的。
	//   ★★ 防漂：`tools/spoof_camera_probe.cpp` 里有 **static_assert**
	//      把这里的每个值与 SDK 的 `MFVideoFormat_*` 逐一钉住 ——
	//      SDK 若哪天改了（不可能）或我们抄错了（很可能），探针**编不过**。
	struct SpoofGuid
	{
		ULONG Data1;
		USHORT Data2;
		USHORT Data3;
		UCHAR Data4[8];
	};

	// FOURCC('x','y','z','w') = x | y<<8 | z<<16 | w<<24（小端字节序）
	// MF 的 D3D 格式 GUID 的尾巴统一是 0000-0010-8000-00AA00389B71。
	inline constexpr SpoofGuid kFormatRgb32 = { 0x00000016, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatArgb32 = { 0x00000015, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatRgb24 = { 0x00000014, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatYuy2 = { 0x32595559, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatUyvy = { 0x59565955, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatNv12 = { 0x3231564E, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatI420 = { 0x30323449, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatIyuv = { 0x56555949, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };
	inline constexpr SpoofGuid kFormatYv12 = { 0x32315659, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 } };

	inline bool GuidEquals(const SpoofGuid& a, const SpoofGuid& b) noexcept
	{
		return a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3
			&& memcmp(a.Data4, b.Data4, sizeof(a.Data4)) == 0;
	}

	// ------------------------------------------------------------------
	// 支持面
	// ------------------------------------------------------------------

	// 能造出**合法中性帧**的视频子类型。不在表里的 = 不支持。
	enum class VideoFormat
	{
		Unknown = 0,
		Rgb32,
		Argb32,
		Rgb24,
		Yuy2,
		Uyvy,
		Nv12,
		I420,
		Iyuv,
		Yv12,
	};

	// 中性值填充策略（决定"往哪些字节填什么"）。
	enum class FillKind
	{
		Unsupported = 0, // 不认识 ⇒ 调用方回落「拒绝」（铁律 194/196）
		AllZero,         // RGB：全 0 **就是**黑
		PackedYuv422,    // YUY2 / UYVY：4 字节一组交错（Y 与 UV 混在一行里）
		PlanarYuv,       // NV12 / I420 / IYUV / YV12：Y 平面 + 色度平面
	};

	// ★ 有限范围（video range）的黑。
	//
	// 为什么不是 0：YUV 的"有限范围"约定把 8bit 的合法区间定在 16..235（Y）
	// 与 16..240（UV）。全 0 落在**合法区间之外**，解码/显示时会被钳到
	// 最暗的**饱和色**（不同色彩矩阵下偏绿或偏洋红）—— 它**不是黑**。
	// 黑 = Y16 / UV128。
	inline constexpr BYTE kLimitedBlackY = 16;
	inline constexpr BYTE kNeutralChroma = 128;

	// 填充计划。**长度不变**是这个结构存在的前提 ——
	// `ApplyNeutral` 只写 [0, len)，一个字节都不多写。
	struct NeutralPlan
	{
		FillKind kind;
		VideoFormat format;
		unsigned width;
		unsigned height;
		unsigned stride;      // 平面/行的名义步长（字节）
		unsigned packedOrder; // 0 = Y 在前（YUY2），1 = U 在前（UYVY）
	};

	// 子类型 GUID ⇒ VideoFormat。不认识返回 Unknown。
	inline VideoFormat ClassifyFormat(const SpoofGuid& sub) noexcept
	{
		if (GuidEquals(sub, kFormatRgb32)) { return VideoFormat::Rgb32; }
		if (GuidEquals(sub, kFormatArgb32)) { return VideoFormat::Argb32; }
		if (GuidEquals(sub, kFormatRgb24)) { return VideoFormat::Rgb24; }
		if (GuidEquals(sub, kFormatYuy2)) { return VideoFormat::Yuy2; }
		if (GuidEquals(sub, kFormatUyvy)) { return VideoFormat::Uyvy; }
		if (GuidEquals(sub, kFormatNv12)) { return VideoFormat::Nv12; }
		if (GuidEquals(sub, kFormatI420)) { return VideoFormat::I420; }
		if (GuidEquals(sub, kFormatIyuv)) { return VideoFormat::Iyuv; }
		if (GuidEquals(sub, kFormatYv12)) { return VideoFormat::Yv12; }
		return VideoFormat::Unknown;
	}

	// 可读名（日志/判据用；**ASCII** —— 见铁律 193：`strings -el` 只认 ASCII）。
	inline const char* FormatName(VideoFormat f) noexcept
	{
		switch (f) {
		case VideoFormat::Rgb32:  return "RGB32";
		case VideoFormat::Argb32: return "ARGB32";
		case VideoFormat::Rgb24:  return "RGB24";
		case VideoFormat::Yuy2:   return "YUY2";
		case VideoFormat::Uyvy:   return "UYVY";
		case VideoFormat::Nv12:   return "NV12";
		case VideoFormat::I420:   return "I420";
		case VideoFormat::Iyuv:   return "IYUV";
		case VideoFormat::Yv12:   return "YV12";
		default:                  return "UNKNOWN";
		}
	}

	// 名义步长（拿不到 `MF_MT_DEFAULT_STRIDE` 时的兜底）。
	//
	// ⚠️ 这里用"每像素字节数 × 宽度"的**名义值**：对绝大多数采集设备成立
	//    （MF 的默认步长就是这么算的）。真机上若驱动声明了非标准步长，
	//    调用方应把 `MF_MT_DEFAULT_STRIDE` 传进来（见 camera_guard.cpp）。
	inline bool NominalStride(VideoFormat f, unsigned width, unsigned& out) noexcept
	{
		switch (f) {
		case VideoFormat::Rgb32:
		case VideoFormat::Argb32: out = width * 4u; return true;
		case VideoFormat::Rgb24:  out = width * 3u; return true;
		case VideoFormat::Yuy2:
		case VideoFormat::Uyvy:   out = width * 2u; return true;
		case VideoFormat::Nv12:
		case VideoFormat::I420:
		case VideoFormat::Iyuv:
		case VideoFormat::Yv12:   out = width; return true;
		default:                  return false;
		}
	}

	// 造计划。**返回 false ⇒ 调用方必须回落「拒绝」**（铁律 194/196）。
	//
	// ★ 失败时 `out` 会被**清成 `FillKind::Unsupported`**（fail-safe）——
	//   万一调用方忽略了返回值直接 `ApplyNeutral`，那也只会"什么都不做"，
	//   而**不会**拿上一次的计划去填这一帧（铁律 93：文档写了 ≠ 代码会读）。
	//
	// stride 传 0 表示"用名义步长"。传进来时取绝对值（MF 的
	// `MF_MT_DEFAULT_STRIDE` 对**自下而上**的帧是**负数** —— 那是"行序"
	// 的表示，不是"步长是负的"；填充时按绝对值算，行序不影响中性化）。
	inline bool PlanForFormat(VideoFormat f, unsigned width, unsigned height,
		int stride, NeutralPlan& out) noexcept
	{
		out = NeutralPlan{};
		if (f == VideoFormat::Unknown || width == 0 || height == 0) {
			return false;
		}

		unsigned nominal = 0;
		if (!NominalStride(f, width, nominal)) {
			return false;
		}

		unsigned use = nominal;
		if (stride != 0) {
			const unsigned absStride = (stride < 0)
				? static_cast<unsigned>(-static_cast<long long>(stride))
				: static_cast<unsigned>(stride);
			// ⚠️ 步长必须**至少**能装下一行像素 —— 比名义值小 ⇒ 那是调用方
			//    传错了（或属性坏了），用它会把相邻行也涂掉/涂不满。
			//    这种情况**不猜**，回落名义值。
			if (absStride >= nominal) {
				use = absStride;
			}
		}

		out.format = f;
		out.width = width;
		out.height = height;
		out.stride = use;
		out.packedOrder = 0;

		switch (f) {
		case VideoFormat::Rgb32:
		case VideoFormat::Argb32:
		case VideoFormat::Rgb24:
			out.kind = FillKind::AllZero;
			return true;

		case VideoFormat::Yuy2:
			out.kind = FillKind::PackedYuv422;
			out.packedOrder = 0;
			return true;
		case VideoFormat::Uyvy:
			out.kind = FillKind::PackedYuv422;
			out.packedOrder = 1;
			return true;

		case VideoFormat::Nv12:
		case VideoFormat::I420:
		case VideoFormat::Iyuv:
		case VideoFormat::Yv12:
			out.kind = FillKind::PlanarYuv;
			return true;

		default:
			return false;
		}
	}

	// ------------------------------------------------------------------
	// 填充（★ 只写 [0, len)，**长度一个都不改**）
	// ------------------------------------------------------------------
	//
	// ★ 为什么"长度不变"是命门（与 v70 剪贴板、v71 注册表同一条规则）：
	//   要"改长度"就得同步改**三处**（`IMFSample` 的总长、
	//   `IMFMediaBuffer::SetCurrentLength`、以及调用方缓存的 `GetMaxLength`），
	//   改错一处 ⇒ 调用方按旧长度读/按新长度算 ⇒ 读到脏数据或越界。
	//   "长度不动、只改内容" ⇒ 长度与数据区天然自洽，结构上不可能出现
	//   "声明长度 ≠ 实际长度"。
	inline void ApplyNeutral(BYTE* p, DWORD len, const NeutralPlan& plan) noexcept
	{
		if (!p || len == 0) {
			return;
		}

		switch (plan.kind) {
		case FillKind::AllZero:
			// RGB：全 0 就是黑。**整块**清零 —— 连行末 padding 一起
			// （padding 不进图像，清掉无害，还省得算步长）。
			ZeroMemory(p, len);
			return;

		case FillKind::PackedYuv422: {
			// 4 字节 = 2 像素：
			//   YUY2：Y0 U Y1 V  ⇒ [16,128,16,128]
			//   UYVY：U  Y0 V Y1 ⇒ [128,16,128,16]
			const BYTE a = (plan.packedOrder == 0) ? kLimitedBlackY : kNeutralChroma;
			const BYTE b = (plan.packedOrder == 0) ? kNeutralChroma : kLimitedBlackY;
			DWORD i = 0;
			for (; i + 4u <= len; i += 4u) {
				p[i + 0] = a;
				p[i + 1] = b;
				p[i + 2] = a;
				p[i + 3] = b;
			}
			// 尾部不足一组（正常帧不会有；有的话只可能是缓冲区被截断）：
			// 填亮度值 —— Y 通道占每像素的一半以上，填 Y 更接近"黑"。
			for (; i < len; ++i) {
				p[i] = kLimitedBlackY;
			}
			return;
		}

		case FillKind::PlanarYuv: {
			// Y 平面在前（stride × height 字节），色度平面在后。
			// ⚠️ 用 ULONGLONG 算乘积防溢出（stride/height 都是 32 位，
			//    极端值下 unsigned 乘法会回绕 ⇒ yLen 变小 ⇒ 色度被当亮度填）。
			ULONGLONG yLen = static_cast<ULONGLONG>(plan.stride) * plan.height;
			if (yLen > len) {
				yLen = len;
			}
			memset(p, kLimitedBlackY, static_cast<size_t>(yLen));
			if (len > yLen) {
				memset(p + yLen, kNeutralChroma, static_cast<size_t>(len - yLen));
			}
			return;
		}

		default:
			// Unsupported：**什么都不做**（调用方本该先看 PlanForFormat 的返回值）。
			return;
		}
	}
}
