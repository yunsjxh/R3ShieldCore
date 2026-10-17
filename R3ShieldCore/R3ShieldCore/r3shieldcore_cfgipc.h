#pragma once

#include <r3shieldcore/r3shieldcore_shared.h>
// ★ `r3shieldcore_config.h` 住在**本目录**（R3ShieldCore/R3ShieldCore/），
//   不在共享头目录 shared/r3shieldcore/ 下 ⇒ 必须用**引号式**相对包含。
//   写成 `<r3shieldcore/r3shieldcore_config.h>` 会解析到 shared/r3shieldcore/
//   下不存在的路径 ⇒ C1083（`-I shared` 只覆盖共享头那一层）。
#include "r3shieldcore_config.h"

// ★ v81：协议契约（管道名 / 命令字 / 转义规则）也在这里暴露一份。
//   为什么本头要**再包含一次**：调用方（`app.cpp`）除了 `...Server::Start`
//   还要打诊断（`R3ShieldCoreCfgIpc::PipeName()`）—— 那是协议命名空间里的东西。
//   不在这里包含，调用方就得自己记住"先 include 协议头再 include 本头"，
//   漏了就是 `C2653: 不是类或命名空间名称`（本轮实测踩到）。
//   ⇒ 本头对外**自洽**：include 它一个就够（铁律 127 的延伸）。
#include <r3shieldcore/cfg_ipc.h>

#include <filesystem>
#include <string>

class EngineControl;

//
// ★ v81：配置工具（`r3shieldcore-cfg.exe`）⇄ 引擎 的**管道服务端**。
//
//   为什么要有它：
//     配置工具的日志页原来自己去 tail `r3shieldcore-events.log`。
//     v81 起改成**向引擎要数据**（用户要求）—— 因为引擎手里那份事件流是
//     **进程内**的环形缓冲（`R3ShieldCoreStats`），它**不进共享内存**
//     （共享内存里只有 `Policy`），所以只能跨进程问。
//
//   顺带一个好处：`R3ShieldCoreStats` 自带 `CRITICAL_SECTION`，
//     服务线程可以直接调 `GetLogsSince` 增量取，**不需要**再做一个快照通道。
//
//   协议与转义规则全部在共享头 `shared/r3shieldcore/cfg_ipc.h`（铁律 127）。
//
//   ⚠️ **本服务只服务本机、本会话**：
//      · 管道名带会话号（多登录会话下不会连到别人的引擎）；
//      · DACL 只放「调用方用户 SID」+「Administrators」——
//        引擎是 requireAdministrator、配置工具是普通用户，跨完整性级别
//        访问命名管道**必须**显式授 DACL，否则 `CreateFileW` 恒定拿到
//        `ERROR_ACCESS_DENIED(5)`，而症状是"配置工具说引擎没在跑"
//        （不是权限错误，最难查）。
//      · `PIPE_REJECT_REMOTE_CLIENTS`：不接受来自网络的连接。
//
namespace R3ShieldCoreCfgIpcServer
{
	struct Options
	{
		// 引擎**本地**的策略副本（可写）。服务端读它来回答 CONFIG；
		// `SYNC` 热应用 `mode` 时也会写回这里，让后续 CONFIG 报的是新值。
		R3ShieldCore::Policy* Policy = nullptr;

		// 引擎侧开关（启动期定死的那批，见 r3shieldcore_config.h）。
		const R3ShieldCoreConfig::EngineSettings* EngineSettings = nullptr;

		// 引擎**真正读到**的那份 ini（`R3ShieldCoreConfig::ResolveConfigPath`）。
		// 配置工具会拿自己的解析结果和它对，不一致时明说。
		std::filesystem::path IniPath;

		// 解析相对路径用的引擎 exe 目录。
		std::filesystem::path ExeDirectory;
	};

	// 起服务线程。失败（管道建不出来）返回 false 并写日志 ——
	// 引擎**照常继续跑**：这只影响"配置工具能不能向引擎要数据"。
	bool Start(const Options& options) noexcept;

	// 停服务线程并关闭管道。可重复调用。
	void Stop() noexcept;

	// ★ 主循环每轮调用：处理挂起的 `SYNC`（重读 ini + 热应用 mode）。
	//
	//   为什么必须由主循环做、不能由服务线程直接做：
	//     `SetMode` 会碰 DLL 侧共享内存、必要时还会建询问通道
	//     （`R3ShieldCorePrompt::Create`）—— 那是主循环线程的活。
	//     服务线程只负责"把请求挂起来 + 等结论"。
	//
	//   主循环没在跑（正在收尾）时服务线程会超时并回 `ERR`，不会挂死。
	void PollSync(EngineControl& engineControl) noexcept;

	// 诊断用计数（服务线程写、主循环读；只增不改，用 Interlocked）。
	struct Stats
	{
		ULONG Accepted = 0;       // 成功接受的连接数
		ULONG LogRequests = 0;
		ULONG ConfigRequests = 0;
		ULONG SyncRequests = 0;
		ULONG Errors = 0;
		ULONG Malformed = 0;      // 认不出的请求
		bool ClientConnected = false;
	};
	Stats GetStats() noexcept;

	// 最近一次 SYNC 的结论（给主程序自己的启动/诊断日志用）。
	// 返回 false = 还没有过 SYNC。
	bool LastSyncSummary(std::wstring& appliedOut, std::wstring& restartOut) noexcept;
}
