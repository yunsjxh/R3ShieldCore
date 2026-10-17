// log_line.h —— 「事件日志那一行」的**唯一**格式化实现（铁律 127）。
//
//   为什么必须只有一份：
//     `r3shieldcore-events.log` 的每一行由**注入 DLL** 写（DLL 跑在每个被注入
//     进程里，只有它拿得到 `R3ShieldCore::Event`）。
//     而引擎（主程序）也需要同一份文本 —— 它的界面事件列表要显示、v81 起
//     配置工具还要**向引擎要这条文本**（而不是自己去读日志文件）。
//     两边各写一份格式化代码 ⇒ 哪天改个标签、多个空格，**谁都不会报错**，
//     只是"引擎界面里看到的"和"日志文件里看到的"悄悄变成两种东西
//     （这正是本项目吃过最多亏的一类故障）。
//     ⇒ 格式化只有这一个函数，DLL 与引擎都调它。
//
//   本头只依赖 `r3shieldcore_shared.h`（Event 布局 + 三个名字函数）+ CRT，
//   两个 exe 都能直接 #include。
//
//   ⚠️ 进程名**不由本函数解析** —— DLL 有它自己的窄字符名字缓存（跑在
//      被注入进程里），引擎有自己的宽字符统计表。两者解析策略不同、
//      但都是"只取文件名"。所以名字作为**参数**传进来，本函数保持纯函数。
#pragma once
#ifndef R3SHIELDCORE_LOG_LINE_H
#define R3SHIELDCORE_LOG_LINE_H

#include <r3shieldcore/r3shieldcore_shared.h>
#include <r3shieldcore/text_conv.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace R3ShieldCoreLogLine
{
	// 与 DLL 侧 `ToUtf8` **逐字同语义**的转换：
	//   · 按**显式字符数**（不是找 NUL）转，生产者可能刚好填满整段；
	//   · 最多写 `destinationBytes - 1` 字节，并补 NUL（截断而不是溢出）；
	//   · 转换失败（含非法代理对）⇒ 返回 0，**目标缓冲区保持原样**
	//     （调用方预清零 ⇒ 结果为空串 ⇒ 上层渲染成 `(unknown)`）。
	//
	// ⚠️ 这是"写进定长缓冲区"的版本，和 `R3ShieldCoreText::WideToUtf8`
	//    （整串、返回 `std::string`）**不是同一个用途** —— 前者要复刻
	//    DLL 的截断行为（日志行长度的边界就靠它），后者给普通调用方用。
	inline int WideToUtf8(const WCHAR* source, int sourceChars,
		char* destination, int destinationBytes) noexcept
	{
		if (!source || sourceChars <= 0 || !destination || destinationBytes <= 0) {
			return 0;
		}

		const int written = ::WideCharToMultiByte(CP_UTF8, 0, source, sourceChars,
			destination, destinationBytes - 1, nullptr, nullptr);
		if (written <= 0) {
			return 0;
		}

		destination[written] = '\0';
		return written;
	}

	//
	// 把一条事件渲染成**事件日志文件里的那一行**（★ 含结尾 `\r\n`）。
	//
	//   · 含 `\r\n` 是刻意的：DLL 侧 `WriteFile` 要**逐字节**写出本函数的
	//     返回值，包含行尾 —— 这样"搬到共享头"这件事对日志文件的字节
	//     是**零影响**的（可以用现成的日志文件做逐行回归）。
	//   · 引擎侧拿它当界面文本时会自己去掉行尾与 NUL（见 StripForDisplay）。
	//
	//   `processNameUtf8`：调用方已解析好的进程名（UTF-8，只含文件名）。
	//     空指针或空串 ⇒ 渲染成 `?`（与 DLL 原行为一致）。
	//
	//   ⚠️ 行长上限 2048 字节，`snprintf` 截断时的行为**逐字节照搬原实现**
	//      （含"把结尾 NUL 一起写出去"这个老行为）—— 改它等于改日志文件格式。
	inline std::string FormatEventLine(const R3ShieldCore::Event& event,
		const char* processNameUtf8) noexcept
	{
		FILETIME fileTime;
		fileTime.dwLowDateTime = static_cast<DWORD>(event.TimeStamp & 0xFFFFFFFF);
		fileTime.dwHighDateTime = static_cast<DWORD>(event.TimeStamp >> 32);

		FILETIME localFileTime;
		SYSTEMTIME systemTime = {};
		if (::FileTimeToLocalFileTime(&fileTime, &localFileTime)
			&& ::FileTimeToSystemTime(&localFileTime, &systemTime)) {
			// 已转换成功
		}
		else {
			::GetLocalTime(&systemTime);
		}

		char keyPath[1024] = {};
		char valueName[512] = {};
		WideToUtf8(event.KeyPath, static_cast<int>(event.KeyPathLength), keyPath, sizeof(keyPath));
		WideToUtf8(event.ValueName, static_cast<int>(event.ValueNameLength), valueName, sizeof(valueName));

		// 进程旁路事件的第二字段是 CommandLine（不是 ValueName）。
		// DLL 加载事件没有第二字段（KeyPath 已经是完整 DLL 路径）。
		char spawnCmd[1200] = {};
		const bool objectIsSpawn = (static_cast<R3ShieldCore::ObjectType>(event.ObjectType)
			== R3ShieldCore::ObjectType::ProcessSpawn);
		if (objectIsSpawn) {
			WideToUtf8(event.CommandLine, static_cast<int>(wcslen(event.CommandLine)),
				spawnCmd, sizeof(spawnCmd));
		}

		// 不同对象类型的第二个字段含义不同，标签必须区分，否则日志读串：
		//   文件     → ValueName 是改名后的新名字
		//   驱动     → ValueName 是服务名
		//   网络     → 无 ValueName，第二个字段由 TargetPort/NetProtocol 合成
		//   hive 级  → ValueName 是 hive 文件路径
		//   键级     → ValueName 才是值名
		//   进程/线程 → 无第二个字段（pid 跟在路径后面）
		//   摄像头   → 无第二个字段（KeyPath 是设备/接口说明）
		//   输入钩子 → KeyPath 是注入的模块路径，ValueName 是钩子类型
		//   截屏     → KeyPath 是来源（屏幕 DC / 窗口），ValueName 是区域
		//   DLL加载  → KeyPath / DllPath 都是被加载的 DLL 路径，无第二字段
		//   剪贴板   → KeyPath 是"打开/读取"，ValueName 是格式
		//   进程旁路 → KeyPath 是目标映像，CommandLine 是命令行（第二字段）
		const auto objectType = static_cast<R3ShieldCore::ObjectType>(event.ObjectType);
		const bool isFile = (objectType == R3ShieldCore::ObjectType::File);
		const bool isDriver = (objectType == R3ShieldCore::ObjectType::Driver);
		const bool isProc = (objectType == R3ShieldCore::ObjectType::Process);
		const bool isThread = (objectType == R3ShieldCore::ObjectType::Thread);
		const bool isNetwork = (objectType == R3ShieldCore::ObjectType::Network);
		const bool isCamera = (objectType == R3ShieldCore::ObjectType::Camera);
		const bool isInputHook = (objectType == R3ShieldCore::ObjectType::InputHook);
		const bool isScreen = (objectType == R3ShieldCore::ObjectType::Screen);
		const bool isDllLoad = (objectType == R3ShieldCore::ObjectType::DllLoad);
		const bool isClipboard = (objectType == R3ShieldCore::ObjectType::Clipboard);
		const bool isSpawn = (objectType == R3ShieldCore::ObjectType::ProcessSpawn);
		const bool isServiceConfig = (objectType == R3ShieldCore::ObjectType::ServiceConfig);
		const bool isComHijack = (objectType == R3ShieldCore::ObjectType::ComHijack);
		const bool isScheduledTask = (objectType == R3ShieldCore::ObjectType::ScheduledTask);
		const bool isTokenTheft = (objectType == R3ShieldCore::ObjectType::TokenTheft);
		const bool isWmiSubscription = (objectType == R3ShieldCore::ObjectType::WmiSubscription);
		const bool hive = !isFile && !isDriver && !isProc && !isThread && !isNetwork &&
			!isCamera && !isInputHook && !isScreen && !isDllLoad && !isClipboard && !isSpawn &&
			!isServiceConfig && !isComHijack && !isScheduledTask &&
			!isTokenTheft && !isWmiSubscription &&
			(event.TargetKind == static_cast<ULONG>(R3ShieldCore::TargetKind::Hive));

		const char* secondLabel = isDriver ? "  service="
			: (isFile ? "  rename="
			: (isInputHook ? "  hook="
			: (isScreen ? "  area="
			: (isClipboard ? "  format="
			: (isSpawn ? "  cmd="
			: (isServiceConfig ? "  detail="
			: (isComHijack ? "  server="
			: (isScheduledTask ? "  action="
			: (isTokenTheft ? "  detail="
			: (isWmiSubscription ? "  detail="
			: (hive ? "  file=" : "  value=")))))))))));
		const char* firstLabel = isDriver ? "driver="
			: (isFile ? "path="
			: (isNetwork ? "peer="
			: (isCamera ? "device="
			: (isInputHook ? "module="
			: (isScreen ? "source="
			: (isDllLoad ? "dll="
			: (isClipboard ? "what="
			: (isSpawn ? "image="
			: (isServiceConfig ? "object="
			: (isComHijack ? "clsid="
			: (isScheduledTask ? "task="
			: (isTokenTheft ? "target="
			: (isWmiSubscription ? "class="
			: (isProc ? "image=" : (isThread ? "target=" : (hive ? "target=" : "key="))))))))))))))));

		// 进程/线程事件把 pid 跟成 "(pid=N)"，拼进 keyPath 缓冲之后。
		char procSuffix[32] = {};
		if ((isProc || isThread) && event.TargetProcessId != 0) {
			snprintf(procSuffix, sizeof(procSuffix), "  (pid=%u)", event.TargetProcessId);
		}

		// 网络事件：把端口/协议合成第二字段（ValueName 是空的）。
		char netDetail[160] = {};
		if (isNetwork) {
			if (event.Op == static_cast<ULONG>(R3ShieldCore::NetOp::DnsQuery)) {
				strcpy_s(netDetail, "dns");
			}
			else if (event.TargetPort != 0) {
				snprintf(netDetail, sizeof(netDetail), "%u/%s",
					event.TargetPort, R3ShieldCore::NetProtocolName(event.NetProtocol));
			}
			else {
				strcpy_s(netDetail, "n/a");
			}
		}

		// 尾部标记。高危优先显示，和"[by R3ShieldCore]"可以并存。
		char tags[128] = {};
		if (event.Flags & R3ShieldCore::FlagEventHighRisk) {
			strcat_s(tags, "  [HIGH-RISK]");
		}
		if (event.Flags & R3ShieldCore::FlagEventBlocked) {
			strcat_s(tags, "  [by R3ShieldCore]");
		}
		// ★ v26：全拦模式下"可问项因询问通道不可用而降级放行"。
		//
		//   为什么必须在日志里显式标出来：这种放行**不是判定结论**，
		//   而是"该问没问成"的降级。如果日志里看不出来，事后审计会以为
		//   "这条本来就不该拦"，掩盖了"引擎询问通道坏了"这个真问题
		//   （VM 实测 2026-09-30：17 条 `key=Software` 静默被拒，
		//    看日志**完全看不出**是因为通道不可用才走的 fallback）。
		if (event.Flags2 & R3ShieldCore::FlagEvent2AskUnavailable) {
			strcat_s(tags, "  [ASK-UNAVAIL→ALLOW]");
		}

		char line[2048] = {};
		// ⚠️ 格式串的 %s 个数必须和后面传的实参**严格一致**。
		//    多一个 %s 会让 snprintf 去读一个不存在的指针 → 立刻 0xC0000005。
		//    头部 2 个 %s：进程名（紧跟 pid= 方括号内）；
		//    尾部 6 个 %s：firstLabel / keyPath / procSuffix / 第二字段标签 /
		//                  第二字段值 / tags。
		//    合计 8 个 %s，逐个核对下面的实参。
		//
		// 第二字段的取值按对象类型分流：
		//   网络     → 合成的 proto/detail（在 netDetail 里）
		//   进程旁路 → CommandLine（spawnCmd）
		//   其余     → ValueName（没有就整段留空）
		const bool hasSecondField = isNetwork || objectIsSpawn || valueName[0];
		const char* secondTag = isNetwork ? "  proto="
			: (objectIsSpawn ? secondLabel : (valueName[0] ? secondLabel : ""));
		const char* secondValue = isNetwork ? netDetail
			: (objectIsSpawn ? spawnCmd : (valueName[0] ? valueName : ""));

		// 进程名。取不到时退化成 "pid=<N>" 独占（保持原有信息不丢）。
		const char* processName = (processNameUtf8 && processNameUtf8[0]) ? processNameUtf8 : "";

		int length = snprintf(line, sizeof(line),
			"%04u-%02u-%02u %02u:%02u:%02u.%03u  pid=%-6u[%s] tid=%-6u  %-4s %-11s %-4s %-16s  status=0x%08X  %s%s%s%s%s%s\r\n",
			systemTime.wYear, systemTime.wMonth, systemTime.wDay,
			systemTime.wHour, systemTime.wMinute, systemTime.wSecond, systemTime.wMilliseconds,
			event.ProcessId, processName[0] ? processName : "?",
			event.ThreadId,
			R3ShieldCore::ObjectTypeName(event.ObjectType),
			R3ShieldCore::DecisionName(event.Decision),
			(event.Flags & R3ShieldCore::FlagEventHighRisk) ? "HIGH" : "",
			R3ShieldCore::AnyOpName(event.ObjectType, event.Op),
			event.Status,
			firstLabel,
			keyPath[0] ? keyPath : "(unknown)",
			procSuffix,
			hasSecondField ? secondTag : "",
			hasSecondField ? secondValue : "",
			tags);

		if (length <= 0) {
			return std::string();
		}

		if (length > static_cast<int>(sizeof(line))) {
			length = static_cast<int>(sizeof(line));
		}

		// ★ 含结尾 `\r\n`（截断时可能连结尾 NUL 一起带上）—— 逐字节照搬原实现。
		return std::string(line, static_cast<size_t>(length));
	}

	//
	// 把 `FormatEventLine` 的结果收拾成"能显示、能上网线"的形态：
	//   · 去掉结尾 `\r\n` / `\r` / `\n`
	//   · 截到第一个 NUL（`snprintf` 截断时会带一个 NUL 出来）
	//
	// 为什么单独一个函数：引擎界面、管道传输、单元测试三处都要这个动作，
	// 各自写一遍就会漂（其中一处忘了去 NUL ⇒ 显示截断，看起来像"日志丢了"）。
	inline std::string StripForDisplay(const std::string& rawLine) noexcept
	{
		size_t end = rawLine.size();
		const size_t nul = rawLine.find('\0');
		if (nul != std::string::npos && nul < end) {
			end = nul;
		}
		while (end > 0 && (rawLine[end - 1] == '\r' || rawLine[end - 1] == '\n')) {
			--end;
		}
		return rawLine.substr(0, end);
	}

}  // namespace R3ShieldCoreLogLine

#endif  // R3SHIELDCORE_LOG_LINE_H
