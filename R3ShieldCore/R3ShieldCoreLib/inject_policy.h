#pragma once

#include <windows.h>

//
// 进程注入分级（v42）
// ============================================================================
//
// 背景：R3ShieldCore 是**用户态注入**，新进程要"被注入 + hook 装好"才受监控。
// 于是「进程启动 → 注入完成」之间有一段**盲区**，落进去的行为拦不住。
// 样本 `Windows XP Horror` 就在 Delphi `FormCreate`（进程启动后几十~几百 ms）
// 里无条件写 MBR ⇒ 盲区一旦被抢到就输了（v41 把轮询压到 10 ms）。
//
// 引擎有两条注入路：
//   ① 同步路 —— 在**父进程**里 hook `CreateProcessInternalW`，强制
//      `CREATE_SUSPENDED` → 注入 → `ResumeThread`。子进程**跑第一行代码之前**
//      hook 就装好了 ⇒ 盲区 ≈ 0。
//   ② 轮询路 —— `NtGetNextProcess` 定期扫新进程。盲区 = 间隔 + 注入耗时。
//
// ★ 而 ① 的前提是「**父进程已被注入**」。双击启动的父进程是 `explorer.exe`、
//   UAC 提权的父进程是 `svchost.exe`（AppInfo 服务）—— 这两个原来都在
//   "绝不注入"名单里 ⇒ 那条链上**永远拿不到同步路**。
//
// 解法（v42）= **瘦注入**：把这些"会当父进程"的宿主**注进去**，但
//   **只装 `CreateProcessInternalW` 一个 hook**，不装任何 guard。
//   于是：
//     · 它自己**不受监控**（行为上与"没被注入"等价）⇒ 不会因为挂了
//       文件/注册表/网络等一堆 hook 而拖慢或弄坏它（`explorer.exe` 的
//       文件 I/O 极高频，`block_all` 下全量 hook 必炸）；
//     · 但它拉起的子进程能走**同步路** ⇒ 盲区 ≈ 0。
//
// 分级三档（见 `ClassifyImagePath`）：
//   Full —— 完整注入（默认，绝大多数进程）
//   Thin —— 瘦注入：只装 `CreateProcessInternalW`
//   Skip —— 完全不注入
//
// ⚠️ 本文件**故意不依赖 stdafx / 共享内存 / Policy**：它只做
//   「镜像路径 → 档位」的**纯函数**分类，好让 `build_ut.sh` 能把它单独
//   链起来做单元测试（与 `r3shieldcore_rules.cpp` 同一套路）。Policy 上的
//   开关由调用方以 `thinAllowed` 传进来。
//
namespace InjectPolicy
{
	enum class Mode
	{
		Full,   // 完整注入：所有 guard 都装
		Thin,   // 瘦注入：只装 CreateProcessInternalW（同步注入路），不装任何 guard
		Skip,   // 完全不注入
	};

	// 按**完整镜像路径**分类。
	//
	//   imagePath   —— `QueryFullProcessImageNameW` 的结果；空指针/空串 → Full。
	//   thinAllowed —— Policy 里的 `FlagInjectShellThin`。为 false 时
	//                  瘦名单成员退化成 Skip（= v41 及以前的行为，逃生门）。
	//
	// ★ 只有落在 **Windows 目录**下的进程才可能是 Thin/Skip —— 别处的
	//   同名 exe（比如 `D:\tools\explorer.exe`）是攻击者放的山寨货，
	//   必须按 Full 处理（否则就是"用文件名当身份"的经典漏洞）。
	//
	// ★ v53 例外：**内置路径判据**（`IsBuiltinNeverInjectPath`，目前只有
	//   VMware Tools）先于上面那道"Windows 目录"的门判定 —— 它自带
	//   `Program Files` 根约束，不依赖 Windows 目录。
	Mode ClassifyImagePath(PCWSTR imagePath, bool thinAllowed) noexcept;

	// 分类**当前进程自己**（用 `GetModuleFileNameW(NULL, ...)`）。
	// 被注入的 DLL 用它决定"我这个会话是瘦的还是完整的"。
	Mode ClassifyCurrentProcess(bool thinAllowed) noexcept;

	// 基础名是否命中瘦名单（不含 thinAllowed 判定、不含目录判定）。
	// 只给日志/自检用，**不要**拿它做注入决策（缺目录校验）。
	bool IsThinInjectBaseName(PCWSTR baseName) noexcept;

	// 基础名是否命中"绝不注入"名单（同上，仅供日志/自检）。
	bool IsNeverInjectBaseName(PCWSTR baseName) noexcept;

	// ★ v53：内置「绝不注入」的**路径**判据（与上面的**文件名**判据并列）。
	//
	//   目前只有一条：**VMware Tools**
	//   （`<盘符>:\Program Files[\ (x86)]\VMware\VMware Tools\…`）。
	//   理由见 `inject_policy.cpp` 里那段长注释（共享剪贴板是取证通道，
	//   注进去就被引擎自己的剪贴板 hook 掐断）。
	//
	//   与 `IsNeverInjectBaseName` 的区别：那个按**文件名**、只在 Windows
	//   目录下认；这个按**路径**、自带 `Program Files` 根约束 ——
	//   想伪造必须先有"写 Program Files"的管理员权限。
	bool IsBuiltinNeverInjectPath(PCWSTR imagePath) noexcept;

	// ★ v49：用户自定义「绝不注入」路径的**纯匹配器**（ini: `never_inject=`）。
	//
	//   命中 = **前缀匹配 + 路径边界**（不区分大小写）。
	//     · 前缀以分隔符结尾（`D:\App\`、`C:\`）⇒ 边界天然满足；
	//     · 否则要求 imagePath 里紧接着是分隔符或结束
	//       （`D:\App` 命中 `D:\App\x.exe`，**不**命中 `D:\App2\x.exe`）。
	//
	//   为什么必须带"路径边界"：只做前缀匹配时，配置写
	//   `D:\Program Files\MyApp` 会连 `D:\Program Files\MyApp-evil\x.exe`
	//   一起命中 ⇒ 白送一个"改个目录名就免注入"的后门
	//   （与铁律 42「豁免必须不可伪造」同族）。
	//
	//   空指针 / 空串 / **纯分隔符** ⇒ false：配置写坏了**绝不能**整体免注入。
	//
	//   ⚠️ 这里刻意**不做** `\\?\` / `\??\` 前缀剥离 —— 用户写的是他自己看到的
	//      路径，两边形式一致即可；不一致时判不中 ⇒ 退化成"照常注入"（安全方向）。
	bool MatchesNeverInjectPath(PCWSTR imagePath, PCWSTR prefix) noexcept;

	// 档位名（窄字符，给日志用）。
	const char* ModeName(Mode mode) noexcept;
}
