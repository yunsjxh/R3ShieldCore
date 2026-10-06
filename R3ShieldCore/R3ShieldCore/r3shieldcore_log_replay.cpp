#include "stdafx.h"
#include "r3shieldcore_log_replay.h"

#include <r3shieldcore/r3shieldcore_shared.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace
{
	using R3ShieldCore::ObjectType;
	using R3ShieldCoreStats::LogEntry;
	using R3ShieldCoreLogReplay::Result;

	//
	// ------------------------------------------------------------------
	// 行格式（必须与 R3ShieldCoreLib/r3shieldcore_log.cpp 的 WriteEventLine
	// 严格对齐 —— 那边改了这个解析器就必须跟着改）
	// ------------------------------------------------------------------
	//
	//   %04u-%02u-%02u %02u:%02u:%02u.%03u  pid=%-6u[%s] tid=%-6u  %-4s %-11s %-4s %-16s  status=0x%08X  %s%s%s%s%s%s\r\n
	//
	// 展开成实际样子（%-6u 会补空格，所以字段宽度**不固定**）：
	//
	//   2026-10-04 21:15:03.412  pid=1234  [chrome.exe] tid=5678    REG  BLOCK       HIGH SetValueKey       status=0xC0000022  key=Software\Foo  value=Bar  [HIGH-RISK]  [by R3ShieldCore]
	//
	// 拆解策略：不按固定列切（%s 里可能含空格，比如命令行、进程名），
	// 而是按**标记子串**逐步定位。顺序固定，所以可以顺序 find。
	//
	//   1) 时间戳   固定宽度 23 字符（"YYYY-MM-DD HH:MM:SS.mmm"）
	//   2) "pid="   到 '[' 之间是 pid，'[' 到 ']' 之间是进程名
	//   3) "tid="   `%-6u` 补齐到 6 —— ⚠️ 数字 >6 位时不补，宽度 = max(6, 位数)
	//   4) 对象类型 4 字符宽（%-4s）—— ⚠️ "TOKEN"/"SVCCFG"/"SPAWN" 会超出
	//   5) decision 11 字符宽（%-11s）—— "WOULD-BLOCK" 正好 11
	//   6) risk     4 字符宽（空或 "HIGH"）
	//   7) op       16 字符宽（%-16s）—— "SetInformationKey" 等 19 字符会超出
	//   8) "status=0x" 后 8 位十六进制
	//   9) 之后是可变长的 "  label=value" 段 + 尾部 [TAG]
	//
	// ⚠️⚠️ 关于 4)~7)：`%-Ns` 的宽度是**下限不是上限**，内容更长时列会**整体右移**。
	//   因此 4)~7) 的列起点**必须逐列推进**（本列起点 + max(N, 实际长度) + 1），
	//   不能写成常量累加。实测踩过的两个坑（都在真实日志上复现过）：
	//     · risk 列为空时 `%-4s` 输出 4 个空格 —— 若"跳空格分词"，空字段会消失
	//       ⇒ op 被当成 risk 读走 ⇒ `status=` 再也找不到（62 行全军覆没）。
	//     · `TOKEN`（5 字符 > 4）让 decision 列右移 1 —— 若用常量 `base+5`
	//       定位 decision ⇒ 读到空 ⇒ 6 行 TOKEN 事件解析失败（step8）。
	//
	struct Cursor
	{
		const char* p;
		const char* end;

		bool Eof() const { return p >= end; }
		size_t Rest() const { return static_cast<size_t>(end - p); }

		void SkipSpaces()
		{
			while (p < end && (*p == ' ' || *p == '\t')) {
				++p;
			}
		}

		// 跳到下一个指定子串，返回是否找到。找得到则 p 指向该子串之后。
		bool Seek(const char* needle)
		{
			size_t n = strlen(needle);
			if (n == 0) {
				return true;
			}
			const char* found = std::search(p, end, needle, needle + n);
			if (found == end) {
				return false;
			}
			p = found + n;
			return true;
		}
	};

	// 从 [p, 界) 里取一段出来，边界由"下一个双空格"决定。
	// 日志里字段之间是**两个空格**分隔（格式串里写死的），
	// 而字段内部（路径、命令行）不会有连续两个空格以外的陷阱 ——
	// 路径里不会有两个连续空格，命令行里可能有，所以这个函数只用于
	// **非第二字段**（即第一个 label=value 段）。
	std::string TakeUntilDoubleSpace(Cursor& c)
	{
		const char* start = c.p;
		while (c.p + 1 < c.end) {
			if (c.p[0] == ' ' && c.p[1] == ' ') {
				std::string result(start, static_cast<size_t>(c.p - start));
				c.p += 2;
				return result;
			}
			++c.p;
		}
		std::string result(start, static_cast<size_t>(c.end - start));
		c.p = c.end;
		return result;
	}

	// 取到行尾（用于第二字段 —— 命令行里可能有双空格，所以取到 tags 之前）。
	// tags 形如 "  [HIGH-RISK]" / "  [by R3ShieldCore]" / "  [ASK-UNAVAIL→ALLOW]"，
	// 全都以 "  [" 开头，所以找第一个 "  [" 就是第二字段的结束。
	std::string TakeSecondField(Cursor& c, bool& sawTags)
	{
		const char* start = c.p;
		const char* tagsAt = nullptr;

		for (const char* q = c.p; q + 2 < c.end; ++q) {
			if (q[0] == ' ' && q[1] == ' ' && q[2] == '[') {
				tagsAt = q;
				break;
			}
		}

		if (tagsAt) {
			sawTags = true;
			std::string result(start, static_cast<size_t>(tagsAt - start));
			c.p = tagsAt;
			return result;
		}

		std::string result(start, static_cast<size_t>(c.end - start));
		c.p = c.end;
		return result;
	}

	// ---- 名称反查 ----------------------------------------------------------
	// 日志里写的是短名（"REG"/"BLOCK"/"HIGH"/"SetValueKey"），
	// 要还原成枚举值。反查表必须覆盖所有会出现在日志里的名字。

	ULONG ObjectTypeFromName(const std::string& name)
	{
		static const struct { const char* name; ObjectType type; } kMap[] = {
			{ "REG",    ObjectType::Registry },
			{ "FILE",   ObjectType::File },
			{ "PROC",   ObjectType::Process },
			{ "THRD",   ObjectType::Thread },
			{ "DRV",    ObjectType::Driver },
			{ "NET",    ObjectType::Network },
			{ "CAM",    ObjectType::Camera },
			{ "HOOK",   ObjectType::InputHook },
			{ "SCRN",   ObjectType::Screen },
			{ "DLL",    ObjectType::DllLoad },
			{ "CLIP",   ObjectType::Clipboard },
			{ "SPAWN",  ObjectType::ProcessSpawn },
			{ "SVCCFG", ObjectType::ServiceConfig },
			{ "COM",    ObjectType::ComHijack },
			{ "TASK",   ObjectType::ScheduledTask },
			{ "TOKEN",  ObjectType::TokenTheft },
			{ "WMI",    ObjectType::WmiSubscription },
			{ "HOST",   ObjectType::HostHijack },
		};

		for (const auto& entry : kMap) {
			if (name == entry.name) {
				return static_cast<ULONG>(entry.type);
			}
		}
		return static_cast<ULONG>(ObjectType::Registry); // "REG" 是 default
	}

	ULONG DecisionFromName(const std::string& name)
	{
		if (name == "BLOCK") {
			return static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		}
		if (name == "WOULD-BLOCK") {
			return static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
		}
		if (name == "ALLOW") {
			return static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
		}
		return static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
	}

	//
	// Op 名 -> 值。
	//
	// ★ 这里**必须**按 objectType 选表：`R3ShieldCore::Op` 和 `FileOp`、
	//   `ProcessOp` 等的数值空间是**互相重叠**的（都从 1 开始），
	//   拿错表会得到"看着像但错一位"的 Op ⇒ 界面显示的"操作"列全乱。
	//
	// 做法：用共享头里的 `AnyOpName(objectType, op)` 正向枚举一遍，
	// 找到名字匹配的那个 op —— 这样**永远和写日志时用的是同一张表**，
	// 以后共享头加了新 op，这里自动跟上，不会漏。
	//
	ULONG OpFromName(ULONG objectType, const std::string& name)
	{
		// 枚举上界取一个够大的值：共享头里 op 的个数都在 64 以内。
		constexpr ULONG kMaxOp = 64;
		for (ULONG op = 0; op < kMaxOp; ++op) {
			const char* candidate = R3ShieldCore::AnyOpName(objectType, op);
			if (candidate && name == candidate) {
				return op;
			}
		}
		return 0;
	}

	// 把 "2026-10-04 21:15:03.412" 转成 FILETIME（LONG64）。
	// 失败返回 0 —— 调用方会把时间显示成 "(未知)"。
	LONG64 ParseTimestamp(const std::string& text)
	{
		if (text.size() < 19) {
			return 0;
		}

		SYSTEMTIME st = {};
		int millis = 0;
		// 手写解析，不用 sscanf_s 的 %d 组合（它对非法输入的行为不直观）。
		auto digits = [&text](size_t offset, size_t count, int& out) -> bool {
			if (offset + count > text.size()) {
				return false;
			}
			int value = 0;
			for (size_t i = 0; i < count; ++i) {
				const char ch = text[offset + i];
				if (ch < '0' || ch > '9') {
					return false;
				}
				value = value * 10 + (ch - '0');
			}
			out = value;
			return true;
		};

		int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
		if (!digits(0, 4, year) || !digits(5, 2, month) || !digits(8, 2, day) ||
			!digits(11, 2, hour) || !digits(14, 2, minute) || !digits(17, 2, second)) {
			return 0;
		}
		if (text.size() >= 23 && text[19] == '.') {
			digits(20, 3, millis);
		}

		st.wYear = static_cast<WORD>(year);
		st.wMonth = static_cast<WORD>(month);
		st.wDay = static_cast<WORD>(day);
		st.wHour = static_cast<WORD>(hour);
		st.wMinute = static_cast<WORD>(minute);
		st.wSecond = static_cast<WORD>(second);
		st.wMilliseconds = static_cast<WORD>(millis);

		// 日志写的是**本地时间**（WriteEventLine 里先 FileTimeToLocalFileTime），
		// 所以还原时必须用 TzSpecificLocalTimeToSystemTime 转回 UTC。
		FILETIME local = {};
		if (!SystemTimeToFileTime(&st, &local)) {
			return 0;
		}
		FILETIME utc = {};
		if (!LocalFileTimeToFileTime(&local, &utc)) {
			return 0;
		}
		ULONGLONG value = (static_cast<ULONGLONG>(utc.dwHighDateTime) << 32) | utc.dwLowDateTime;
		return static_cast<LONG64>(value);
	}

	// UTF-8 -> UTF-16。
	std::wstring Utf8ToWide(const std::string& text)
	{
		if (text.empty()) {
			return std::wstring();
		}
		const int needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
			static_cast<int>(text.size()), nullptr, 0);
		if (needed <= 0) {
			// 不是合法 UTF-8（比如被别的工具改成了 GBK）——
			// 退化成按 ACP 解，总比整行丢掉强。
			const int fallback = MultiByteToWideChar(CP_ACP, 0, text.c_str(),
				static_cast<int>(text.size()), nullptr, 0);
			if (fallback <= 0) {
				return std::wstring();
			}
			std::wstring wide(static_cast<size_t>(fallback), L'\0');
			MultiByteToWideChar(CP_ACP, 0, text.c_str(), static_cast<int>(text.size()),
				wide.data(), fallback);
			return wide;
		}
		std::wstring wide(static_cast<size_t>(needed), L'\0');
		MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
			wide.data(), needed);
		return wide;
	}

	// ★ 诊断：最后一次解析停在哪一步。只在 `ParseLineForTest` 的
	//   `--stage` 模式里读，业务路径完全不看它（所以生产环境零代价）。
	//   用 const char* 而不是 std::string —— 静态字符串，不分配。
	const char* g_lastStage = "start";

	// 解析一行。成功返回 true。
	bool ParseLine(const std::string& line, LogEntry& entry)
	{
		// ⚠️ 日志文件开头有 UTF-8 BOM（`r3shieldcore_log.cpp` 在文件为空时写
		//    `EF BB BF`）。BOM 只出现在**第一行**开头，但那一行通常正是
		//    我们最想看的（文件很短时就是唯一一行）。不去掉的话，
		//    时间戳会从偏移 3 开始，`ParseTimestamp` 直接失败。
		const std::string* text = &line;
		std::string stripped;
		if (line.size() >= 3 &&
			static_cast<unsigned char>(line[0]) == 0xEF &&
			static_cast<unsigned char>(line[1]) == 0xBB &&
			static_cast<unsigned char>(line[2]) == 0xBF) {
			stripped = line.substr(3);
			text = &stripped;
		}

		const std::string& s = *text;

		// ---- 1) 时间戳：固定 23 字符 ----
		if (s.size() < 23) {
			g_lastStage = "step1";
			return false;
		}
		entry.TimeStamp = ParseTimestamp(s.substr(0, 23));
		if (entry.TimeStamp == 0) {
			g_lastStage = "step2";
			return false;
		}

		Cursor c{s.c_str() + 23, s.c_str() + s.size()};
		entry.BlockedByUs = false;
		entry.IsHive = false;
		entry.IsHighRisk = false;
		entry.TargetProcessId = 0;
		entry.Flags = 0;
		entry.Status = 0;

		// ---- 2) pid=NNN[进程名] ----
		if (!c.Seek("pid=")) {
			g_lastStage = "step3";
			return false;
		}
		{
			char* stop = nullptr;
			const long pid = strtol(c.p, &stop, 10);
			if (stop == c.p || pid < 0) {
				g_lastStage = "step4";
				return false;
			}
			entry.ProcessId = static_cast<ULONG>(pid);
			c.p = stop;
		}

		// ⚠️ pid= 和 [ 之间**有两个空格**（格式串里 `pid=%-6u[%s]`，
		//    %-6u 不足 6 位时补空格，真实日志里是 `pid=7296  [TextInput...`）
		//    —— 直接判 *c.p == '[' 会全军覆没（实测：62 行一条都解析不出来）。
		c.SkipSpaces();
		if (c.Eof() || *c.p != '[') {
			g_lastStage = "step5";
			return false;
		}
		++c.p;
		{
			const char* close = static_cast<const char*>(memchr(c.p, ']',
				static_cast<size_t>(c.end - c.p)));
			if (!close) {
				g_lastStage = "step6";
				return false;
			}
			const std::string name(c.p, static_cast<size_t>(close - c.p));
			// "?" 是引擎写不出名字时的占位，别当成真名字显示。
			entry.ProcessName = (name == "?") ? std::wstring() : Utf8ToWide(name);
			c.p = close + 1;
		}

		// ---- 3) tid=NNN ----
		//
		// ⚠️ tid 也是 `%-6u`，所以"tid= 之后的固定偏移"要靠它算出来。
		//    但 tid 数字本身长度不定 —— 所以先记下 tid 字段的**起点**，
		//    字段宽度固定为 6，之后的列边界就是 start + 6。
		//
		if (!c.Seek("tid=")) {
			g_lastStage = "step7";
			return false;
		}
		const char* tidFieldStart = c.p;
		size_t tidDigits = 0;
		{
			char* stop = nullptr;
			strtol(c.p, &stop, 10); // tid 我们不显示，但必须跳过
			tidDigits = static_cast<size_t>(stop - c.p);
			c.p = stop;
		}

		//
		// ---- 4) 对象类型 / 决策 / 风险 / 操作 / status ----
		//
		// 格式（R3ShieldCoreLib/r3shieldcore_log.cpp 的 snprintf 格式串，逐字对齐）：
		//
		//   ... tid=%-6u  %-4s %-11s %-4s %-16s  status=0x%08X  ...
		//                ^^   ^^  ^    ^^   ^    ^^   ^     ^^
		//                这里两个空格，列与列之间一个空格，status 前两个空格
		//
		// ⚠️⚠️ 为什么**必须**按固定宽度切、绝不能"跳空格分词"：
		//
		//   实测（62 行真实日志，一版跳空格分词 ⇒ **一条都解析不出来**）：
		//   `%-4s` 在 risk 为空时输出的是 **4 个空格**（只有高危才是 "HIGH"）。
		//   跳空格的分词会让"空字段"**整个消失** ⇒ op 列被当成 risk 列读走
		//   ⇒ 之后 `status=` 再也找不到。
		//
		//   而"字段间的单空格"和"字段内的补位空格"都是空格，无法用
		//   跳空格区分。唯一的确定方式是**用字段宽度累加出列边界**：
		//
		//     tid 字段起点 + 6（%-6u） + 2（格式串里的两个空格）
		//       = 对象类型列的起点，之后再按 4(+1) / 11(+1) / 4(+1) / 16 累加。
		//
		//   注意 `%-Ns` 的语义是"**至少** N 宽"：内容更长时会超出边界，
		//   数字更长时**补位空格反而变少**。所以列起点不能写成常量
		//   `tidFieldStart + 6 + 2` —— 那假设 tid 恒 ≤ 6 位。实测 tid=13736
		//   （5 位）时 `%-6u` 只补 1 个空格，真实是 `13736   TOKEN`（3 空格），
		//   而常量算式给 8 ⇒ 列起点右偏 1 ⇒ 对象类型列读出来是 "OKEN"
		//   ⇒ 该行解析失败（6 行 TOKEN 事件全挂）。
		//
		//   正确宽度 = max(6, tid 位数) + 2（格式串里 tid 后固定两个空格）。
		//
		//   本例中几种名字都短于 N，所以宽度是准的（Op 名最长 19 = SetInformationKey，
		//   超过 16 —— 那两个 op 会多占 3 列，这里用"取到空格为止"兜住，
		//   下游 `OpFromName` 匹配不上就退回 0，不会错位到别的字段）。
		//
		const size_t tidFieldWidth = (tidDigits > 6) ? tidDigits : 6;
		const char* columnBase = tidFieldStart + tidFieldWidth + 2;   // %-6u 后跟两个空格

		// 取一格：从 from 起，取到空格为止（上限 width 仅防越界，不做补齐）。
		auto takeColumn = [&c](const char* from, size_t width) -> std::string {
			const char* p = from;
			const char* start = p;
			while (p < c.end && *p != ' ' && static_cast<size_t>(p - start) < width) {
				++p;
			}
			return std::string(start, static_cast<size_t>(p - start));
		};

		// ★★ 关键：`%-Ns` 的宽度是**下限**，内容更长时列会**整体右移**。
		//   对象类型名里有 5 字符的（TOKEN/SVCCFG/SPAWN）、6 字符的（WMI 之外的
		//   TASK 是 4），decision 里 "WOULD-BLOCK" 是 11 字符（正好）。
		//   所以列起点**不能**用常量累加（`columnBase + 5`、`+17`、`+22`）——
		//   实测：`TOKEN` 行 obj='TOKE' 但 dec='' op=''，因为 decision 列实际
		//   在 columnBase+6（TOKEN 5 字符 + 1 空格）而不是 columnBase+5。
		//
		//   正确做法：**逐列推进** —— 取到本列的值之后，下一列的起点 =
		//   本列起点 + max(格式宽度, 实际长度) + 1（列间的那个空格）。
		//
		auto advance = [](const char* columnStart, size_t formatWidth,
			const std::string& taken) -> const char* {
			const size_t actual = taken.size();
			const size_t cell = (actual > formatWidth) ? actual : formatWidth;
			return columnStart + cell + 1;   // +1 = 列之间的单个空格
		};

		const std::string objectTypeName = takeColumn(columnBase, 8);
		const char* decisionBase = advance(columnBase, 4, objectTypeName);
		const std::string decisionName = takeColumn(decisionBase, 12);
		const char* riskBase = advance(decisionBase, 11, decisionName);
		const std::string riskName = takeColumn(riskBase, 4);
		const char* opBase = advance(riskBase, 4, riskName);
		const std::string opName = takeColumn(opBase, 19);   // 最长 op 名 19 = SetInformationKey

		// status 之后的部分从 op 列起点之后重新定位（不走列边界，走 Seek）。
		c.p = columnBase;

		if (objectTypeName.empty() || decisionName.empty() || opName.empty()) {
			g_lastStage = "step8";
			return false;
		}

		entry.ObjectType = ObjectTypeFromName(objectTypeName);
		entry.Decision = DecisionFromName(decisionName);
		entry.Op = OpFromName(entry.ObjectType, opName);

		if (riskName == "HIGH") {
			entry.Flags |= R3ShieldCore::FlagEventHighRisk;
			entry.IsHighRisk = true;
		}
		if (decisionName == "BLOCK") {
			entry.Flags |= R3ShieldCore::FlagEventBlocked;
			entry.BlockedByUs = true;
		}

		// ---- 5) status=0x???????? ----
		if (!c.Seek("status=0x")) {
			g_lastStage = "step9";
			return false;
		}
		{
			char* stop = nullptr;
			const unsigned long status = strtoul(c.p, &stop, 16);
			if (stop == c.p) {
				g_lastStage = "step10";
				return false;
			}
			entry.Status = static_cast<ULONG>(status);
			c.p = stop;
		}

		// ---- 6) 第一个 label=value 段 ----
		// 标签有：key= / path= / image= / target= / driver= / peer= / device=
		//         module= / source= / dll= / what= / object= / clsid= / task=
		//         class= / 以及 hive 的 file=
		c.SkipSpaces();
		std::string firstLabel;
		if (c.p < c.end) {
			const char* eq = static_cast<const char*>(memchr(c.p, '=',
				static_cast<size_t>(c.end - c.p)));
			if (eq) {
				firstLabel.assign(c.p, static_cast<size_t>(eq - c.p));
				c.p = eq + 1;
			}
		}

		// value 取到下一个双空格为止。
		const std::string firstValue = TakeUntilDoubleSpace(c);

		// 第一个值统一放进 Target（界面的"目标"列）。
		entry.Target = Utf8ToWide(firstValue);

		// 进程/线程事件：keyPath 后面紧跟 "(pid=N)"，被当成同一段读到，
		// 这里从中把 pid 抠出来，并把那段从 Target 里去掉。
		if (entry.ObjectType == static_cast<ULONG>(ObjectType::Process) ||
			entry.ObjectType == static_cast<ULONG>(ObjectType::Thread)) {
			const std::wstring marker = L"  (pid=";
			const size_t at = entry.Target.rfind(marker);
			if (at != std::wstring::npos) {
				const std::wstring tail = entry.Target.substr(at + marker.size());
				const size_t close = tail.find(L')');
				if (close != std::wstring::npos) {
					entry.TargetProcessId = static_cast<ULONG>(wcstoul(tail.c_str(), nullptr, 10));
					entry.Target = entry.Target.substr(0, at);
				}
			}
		}

		// ---- 7) 第二字段（可选）+ 尾部标签 ----
		// 第二字段可能是 "value=" / "rename=" / "service=" / "hook=" /
		// "area=" / "format=" / "cmd=" / "detail=" / "server=" / "action=" /
		// "proto=" / "file="。
		c.SkipSpaces();
		bool sawTags = false;
		std::string secondValue;
		if (c.p < c.end && *c.p != '[') {
			// 跳过 "label="
			const char* eq = static_cast<const char*>(memchr(c.p, '=',
				static_cast<size_t>(c.end - c.p)));
			if (eq) {
				c.p = eq + 1;
				secondValue = TakeSecondField(c, sawTags);
			}
		}
		else if (c.p < c.end) {
			sawTags = true;
		}

		// 第二字段统一放进 Value（界面的"值"列）。
		// ⚠️ 但 hive 事件的第二字段是**文件路径**，而 hive 在界面上走的是
		//    "目标"列 —— 与实时路径（OnEvent）的填法保持一致才不会两轮不一致。
		if (firstLabel == "file") {
			// hive：file= 那一格其实是 hive 文件路径，已经填进 Target 了，
			// 这里不应该再有第二字段。真出现了就当 Value。
			entry.Value = Utf8ToWide(secondValue);
		}
		else {
			entry.Value = Utf8ToWide(secondValue);
		}

		// hive 判定：与 OnEvent 里同款 —— 非文件对象 + IsHiveOp。
		if (entry.ObjectType != static_cast<ULONG>(ObjectType::File) &&
			entry.ObjectType != static_cast<ULONG>(ObjectType::Driver) &&
			R3ShieldCore::IsHiveOp(entry.Op)) {
			entry.IsHive = true;
		}

		// ---- 8) 尾部标签 ----
		// 已经通过 decision=="BLOCK" 设过 BlockedByUs；这里再兜一次
		// [by R3ShieldCore] 的存在性（防"日志里写了标签但 decision 列不是 BLOCK"
		// 这种不该发生但真发生过的情况）。
		if (!sawTags) {
			if (c.Seek("[by R3ShieldCore]")) {
				entry.Flags |= R3ShieldCore::FlagEventBlocked;
				entry.BlockedByUs = true;
			}
			if (c.Seek("[HIGH-RISK]")) {
				entry.Flags |= R3ShieldCore::FlagEventHighRisk;
				entry.IsHighRisk = true;
			}
		}

		return true;
	}

	// 把整块字节按行切开，只保留**最后** maxLines 行。
	// 为什么要限制：日志文件可能几十 MB（跑了一整天），全切会吃内存。
	std::vector<std::string> SplitTailLines(const std::string& blob, size_t maxLines)
	{
		std::vector<std::string> lines;
		lines.reserve(std::min<size_t>(maxLines + 16, 4096));

		size_t start = 0;
		while (start < blob.size()) {
			size_t nl = blob.find('\n', start);
			if (nl == std::string::npos) {
				nl = blob.size();
			}
			size_t end = nl;
			// 去掉结尾的 \r（文件是 CRLF）。
			if (end > start && blob[end - 1] == '\r') {
				--end;
			}
			if (end > start) {
				lines.emplace_back(blob.substr(start, end - start));
			}
			start = nl + 1;
		}

		// 只留尾巴。多留一些是因为其中可能夹着解析失败的行。
		if (lines.size() > maxLines) {
			lines.erase(lines.begin(), lines.end() - static_cast<ptrdiff_t>(maxLines));
		}
		return lines;
	}
}

namespace R3ShieldCoreLogReplay
{
	bool ParseLineForTest(const std::string& line, R3ShieldCoreStats::LogEntry& entry) noexcept
	{
		entry = R3ShieldCoreStats::LogEntry{};
		g_lastStage = "ok";
		return ParseLine(line, entry);
	}

	const char* LastFailureStage() noexcept
	{
		return g_lastStage;
	}

	Result ReadTail(const std::filesystem::path& logPath, size_t maxEntries) noexcept
	{
		Result result = {};

		if (maxEntries == 0) {
			maxEntries = 200;
		}

		if (logPath.empty()) {
			return result;
		}

		//
		// ★ 必须带 FILE_SHARE_WRITE —— 引擎在跑时这个文件正被**另一个进程**
		//   以追加方式持有。不带 SHARE_WRITE 会拿到 ERROR_SHARING_VIOLATION(32)，
		//   表现是"读到 0 条"，而那**不等于**"没有历史"（铁律 57）。
		//
		HANDLE file = CreateFileW(logPath.c_str(), GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return result;
		}

		LARGE_INTEGER size = {};
		if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0) {
			CloseHandle(file);
			return result;
		}
		result.FileBytes = static_cast<ULONGLONG>(size.QuadPart);

		//
		// 只读尾部一块。
		//
		// 一行最长约 2048 字节（`line[2048]`）。想要 maxEntries 条，
		// 读 maxEntries * 2KB 一定够，再加一点余量兜住最后那条没写完的。
		// 上限 4MB：再大也不读了 —— 那已经远超用户能滚动的范围。
		//
		constexpr ULONGLONG kMaxRead = 4ull * 1024 * 1024;
		ULONGLONG want = static_cast<ULONGLONG>(maxEntries) * 2048ull + 4096ull;
		if (want > kMaxRead) {
			want = kMaxRead;
		}

		ULONGLONG fileSize = static_cast<ULONGLONG>(size.QuadPart);
		ULONGLONG readFrom = (fileSize > want) ? (fileSize - want) : 0;

		LARGE_INTEGER offset = {};
		offset.QuadPart = static_cast<LONGLONG>(readFrom);
		if (!SetFilePointerEx(file, offset, nullptr, FILE_BEGIN)) {
			CloseHandle(file);
			return result;
		}

		const DWORD toRead = static_cast<DWORD>(fileSize - readFrom);
		std::string blob;
		blob.resize(toRead);

		DWORD got = 0;
		const BOOL ok = ReadFile(file, blob.data(), toRead, &got, nullptr);
		CloseHandle(file);

		if (!ok || got == 0) {
			return result;
		}
		blob.resize(got);

		// 从中间截断时，第一行很可能是**半行** —— 丢掉它，
		// 否则会解析出一条时间戳错乱的假事件。
		if (readFrom > 0) {
			const size_t nl = blob.find('\n');
			if (nl != std::string::npos) {
				blob.erase(0, nl + 1);
			}
			else {
				return result;
			}
		}

		// 尾部可能有一条**正在被写**的半行（没有结尾 \n）——
		// 它会在 SplitTailLines 里被当成完整行。判断方法：blob 不以 \n 结尾
		// 且 size(got) == toRead（说明我们读到了文件当前末尾）。
		// 这种情况下把最后一段丢掉，除非它能正常解析。
		std::vector<std::string> lines = SplitTailLines(blob, maxEntries * 2);
		result.LinesRead = lines.size();

		// 从后往前解析，凑够 maxEntries 条就停 —— 这样哪怕前面有大量
		// 解析不了的行，也不影响拿到"最近的 N 条"。
		result.Entries.reserve(std::min<size_t>(maxEntries, lines.size()));
		for (size_t i = lines.size(); i-- > 0 && result.Entries.size() < maxEntries;) {
			LogEntry entry = {};
			if (ParseLine(lines[i], entry)) {
				result.Entries.push_back(std::move(entry));
				++result.LinesParsed;
			}
		}

		// 上面是逆序收集的，翻回来成时间升序。
		std::reverse(result.Entries.begin(), result.Entries.end());
		return result;
	}
}
