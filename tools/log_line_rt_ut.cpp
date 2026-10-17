//
// log_line_rt_ut.cpp —— v81「事件日志行只有一个实现」单测 + 管道协议编解码单测。
//
// ★ 为什么必须单测（而不是"编过了就完事"）
//
//   v81 做了一件**看起来很安全、其实最容易悄悄出错**的事：
//   把「事件日志那一行」的格式化，从注入 DLL（`r3shieldcore_log.cpp`）
//   搬进共享头 `shared/r3shieldcore/log_line.h`，让引擎侧也能生成同一行
//   （配置工具从 v81 起向引擎要日志，而不是自己去读日志文件）。
//
//   搬完之后的**失败模式**是：
//     · 编译通过、引擎能跑、配置工具能连上、日志文件照旧在长；
//     · 只是"界面上显示的那一行"和"文件里的那一行"**长得不一样**了
//       （少个 `tid=`、网络事件少个 `proto=`、标签顺序不同、少一个空格）。
//   两边都不报错，只有人眼并排看才发现 —— 所以必须有机器判据（铁律 24/28）。
//
//   本单测钉住三件事：
//     ① **格式契约**：每一类对象类型格式化出来的行，都能被**独立的**解析器
//        （`r3shieldcore_log_replay.cpp`，它是照着格式串逐列切的）读回来，
//        并且关键字段与原始事件一致。格式化与解析是两份独立实现 ⇒
//        任何一边改了字段顺序 / 标签 / 列宽，这里立刻红。
//     ② **逐字节钉死**：注册表那条（本项目日志里最常见的一类）用**字面量**
//        比对整行尾部 —— 这段字面量是照着 `r3shieldcore_log_replay.cpp`
//        顶部注释里引用的格式串与示例行手写的（独立来源，不是抄格式化代码）。
//     ③ **引擎侧真的用上了**：直接驱动生产的 `R3ShieldCoreStats::OnEvent`，
//        检查它落到环形缓冲里的 `Line` 与 `FormatEventLine` 的输出**一致**
//        （否则"共享头写好了但没人调"是查不出来的）。
//
//   另外覆盖 v81 新增的 `cfg_ipc.h` 编解码：日志行里有 `|` / `\` / CR / LF /
//   中文时，字段切分必须不漂（转义漏一处 ⇒ 字段数漂 ⇒ 下游全错位）。
//
// 构建/运行：bash build_log_line_rt_ut.sh [x64|x86]
//
#include <windows.h>
#include <stdio.h>

#include <string>
#include <vector>

#include <r3shieldcore/r3shieldcore_shared.h>
#include <r3shieldcore/log_line.h>
#include <r3shieldcore/cfg_ipc.h>
#include <r3shieldcore/text_conv.h>

#include "r3shieldcore_stats.h"
#include "r3shieldcore_log_replay.h"

namespace LogLine = R3ShieldCoreLogLine;
namespace Ipc = R3ShieldCoreCfgIpc;
namespace Text = R3ShieldCoreText;

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) { g_pass++; } else { g_fail++; }
}

// ---------------------------------------------------------------- 工具

// 造一条事件。所有"没给"的字段留零 —— 与真实事件里"该字段不适用"一致。
static R3ShieldCore::Event MakeEvent(ULONG objectType, ULONG op, ULONG decision)
{
	R3ShieldCore::Event e = {};
	e.ObjectType = objectType;
	e.Op = op;
	e.Decision = decision;
	e.TargetKind = static_cast<ULONG>(R3ShieldCore::TargetKind::Key);
	// 2026-10-16 12:00:00 UTC 附近的一个固定 FILETIME —— 值本身不重要，
	// 只要稳定（本地时区转换由被测代码做，测试不去猜时区）。
	e.TimeStamp = 134054400000000000LL;
	return e;
}

static void SetKeyPath(R3ShieldCore::Event& e, const WCHAR* path)
{
	wcsncpy_s(e.KeyPath, path, _TRUNCATE);
	e.KeyPathLength = static_cast<ULONG>(wcslen(e.KeyPath));
}

static void SetValueName(R3ShieldCore::Event& e, const WCHAR* value)
{
	wcsncpy_s(e.ValueName, value, _TRUNCATE);
	e.ValueNameLength = static_cast<ULONG>(wcslen(e.ValueName));
}

// 时间戳是"本地时间"，时区随机器变 ⇒ 只比对**前 23 字符之后的尾部**，
// 但先证明前 23 字符确实是 `YYYY-MM-DD HH:MM:SS.mmm` 的形状。
static bool TimestampShapeOk(const std::string& line)
{
	if (line.size() < 23) { return false; }
	const char* p = line.c_str();
	for (int i = 0; i < 23; ++i) {
		const char c = p[i];
		const bool digit = (c >= '0' && c <= '9');
		const bool sep = (i == 4 || i == 7) ? (c == '-')
			: (i == 10 ? (c == ' ') : (i == 13 || i == 16 ? (c == ':') : (i == 19 ? (c == '.') : false)));
		if (!digit && !sep) { return false; }
	}
	return true;
}

// ---------------------------------------------------------------- ① 逐字节钉死

static void TestGoldenRegistryLine()
{
	printf("\n-- ① 注册表事件整行尾部（字面量比对）\n");

	R3ShieldCore::Event e = MakeEvent(
		static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
		static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
		static_cast<ULONG>(R3ShieldCore::Decision::Blocked));
	e.ProcessId = 1234;
	e.ThreadId = 5678;
	e.Status = 0xC0000022;
	e.Flags = R3ShieldCore::FlagEventHighRisk | R3ShieldCore::FlagEventBlocked;
	SetKeyPath(e, L"Software\\Foo");
	SetValueName(e, L"Bar");

	const std::string raw = LogLine::FormatEventLine(e, "chrome.exe");
	const std::string line = LogLine::StripForDisplay(raw);

	Check("整行以 CRLF 结尾（DLL 要逐字节写出去）",
		raw.size() > 2 && raw.substr(raw.size() - 2) == "\r\n");
	Check("去尾之后不含 CR/LF", line.find('\r') == std::string::npos
		&& line.find('\n') == std::string::npos);
	Check("时间戳形状 YYYY-MM-DD HH:MM:SS.mmm", TimestampShapeOk(line));

	// ★ 这段字面量是**手写**的，来源是 r3shieldcore_log_replay.cpp 顶部
	//   注释里引用的格式串与示例行（独立于 log_line.h 的实现）。
	const std::string expectedTail =
		"  pid=1234  [chrome.exe] tid=5678    REG  BLOCK       HIGH SetValueKey       "
		"status=0xC0000022  key=Software\\Foo  value=Bar  [HIGH-RISK]  [by R3ShieldCore]";

	const std::string actualTail = line.size() > 23 ? line.substr(23) : std::string();
	Check("尾部与手写字面量逐字节一致", actualTail == expectedTail);
	if (actualTail != expectedTail) {
		printf("        期望: [%s]\n", expectedTail.c_str());
		printf("        实际: [%s]\n", actualTail.c_str());
	}
}

// ---------------------------------------------------------------- ② 格式契约

// 每一类对象类型：格式化 -> 独立解析器读回来 -> 关键字段一致。
static void TestAllObjectTypesRoundTrip()
{
	printf("\n-- ② 全部对象类型：格式化 -> 解析器读回 -> 字段一致\n");

	struct Case
	{
		const char* name;
		R3ShieldCore::ObjectType type;
		ULONG op;
		const WCHAR* keyPath;
		const WCHAR* valueName;
	};

	// 每个对象类型都取一个**真实存在**的 op（名字函数里查得到），
	// 否则 `AnyOpName` 返回 "Unknown" ⇒ 解析器 `OpFromName` 退化成 0，
	// 这条就变成"恒真"的假判据了。
	const Case cases[] = {
		{ "REG",   R3ShieldCore::ObjectType::Registry,        static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),  L"Software\\Test", L"V" },
		{ "FILE",  R3ShieldCore::ObjectType::File,            static_cast<ULONG>(R3ShieldCore::FileOp::Create),   L"C:\\Temp\\a.txt", nullptr },
		{ "PROC",  R3ShieldCore::ObjectType::Process,         static_cast<ULONG>(R3ShieldCore::ProcessOp::Create), L"C:\\a.exe", nullptr },
		{ "THRD",  R3ShieldCore::ObjectType::Thread,          static_cast<ULONG>(R3ShieldCore::ThreadOp::Create),  L"C:\\b.exe", nullptr },
		{ "DRV",   R3ShieldCore::ObjectType::Driver,          static_cast<ULONG>(R3ShieldCore::DriverOp::Load),    L"C:\\x.sys", L"svc" },
		{ "NET",   R3ShieldCore::ObjectType::Network,         static_cast<ULONG>(R3ShieldCore::NetOp::Connect),    L"1.2.3.4", nullptr },
		{ "CAM",   R3ShieldCore::ObjectType::Camera,          static_cast<ULONG>(R3ShieldCore::CameraOp::OpenDevice), L"dev", nullptr },
		{ "HOOK",  R3ShieldCore::ObjectType::InputHook,       static_cast<ULONG>(R3ShieldCore::HookOp::SetKeyboardHook), L"mod", L"WH_KEYBOARD" },
		{ "SCRN",  R3ShieldCore::ObjectType::Screen,          static_cast<ULONG>(R3ShieldCore::ScreenOp::BitBlt),  L"screen-dc", L"0,0,100,100" },
		{ "DLL",   R3ShieldCore::ObjectType::DllLoad,         static_cast<ULONG>(R3ShieldCore::DllLoadOp::LoadLibrary),   L"C:\\evil.dll", nullptr },
		{ "CLIP",  R3ShieldCore::ObjectType::Clipboard,       static_cast<ULONG>(R3ShieldCore::ClipboardOp::Read), L"read", L"CF_TEXT" },
		{ "SPAWN", R3ShieldCore::ObjectType::ProcessSpawn,    static_cast<ULONG>(R3ShieldCore::SpawnOp::ShellExecute), L"C:\\cmd.exe", nullptr },
		{ "SVCCFG",R3ShieldCore::ObjectType::ServiceConfig,   static_cast<ULONG>(R3ShieldCore::ServiceConfigOp::SetServiceSecurity), L"svc", L"sdset" },
		{ "COM",   R3ShieldCore::ObjectType::ComHijack,       static_cast<ULONG>(R3ShieldCore::ComOp::CreateInstance),   L"{clsid}", L"srv" },
		{ "TASK",  R3ShieldCore::ObjectType::ScheduledTask,   static_cast<ULONG>(R3ShieldCore::ScheduledTaskOp::RegisterTaskDefinition), L"task", L"cmd" },
		{ "TOKEN", R3ShieldCore::ObjectType::TokenTheft,      static_cast<ULONG>(R3ShieldCore::TokenTheftOp::DuplicateTokenEx), L"lsass", L"detail" },
		{ "WMI",   R3ShieldCore::ObjectType::WmiSubscription, static_cast<ULONG>(R3ShieldCore::WmiSubscriptionOp::PutInstance), L"cls", L"detail" },
		{ "HOST",  R3ShieldCore::ObjectType::HostHijack,      static_cast<ULONG>(R3ShieldCore::HostHijackOp::MapSectionRemote), L"t", L"d" },
	};

	for (const Case& c : cases) {
		R3ShieldCore::Event e = MakeEvent(static_cast<ULONG>(c.type), c.op,
			static_cast<ULONG>(R3ShieldCore::Decision::Blocked));
		e.ProcessId = 4242;
		e.ThreadId = 777;
		e.Status = 0xC0000022;
		e.Flags = R3ShieldCore::FlagEventBlocked;
		SetKeyPath(e, c.keyPath);
		if (c.valueName) { SetValueName(e, c.valueName); }

		// 进程 / 线程事件带目标 pid（走 "(pid=N)" 后缀那条分支）
		if (c.type == R3ShieldCore::ObjectType::Process
			|| c.type == R3ShieldCore::ObjectType::Thread) {
			e.TargetProcessId = 909;
		}

		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, "x.exe"));
		const bool shape = TimestampShapeOk(line);

		R3ShieldCoreStats::LogEntry parsed = {};
		const bool ok = R3ShieldCoreLogReplay::ParseLineForTest(line, parsed);

		char name[160] = {};
		snprintf(name, sizeof(name), "%s：格式化出来的行能被解析器读回（stage=%s）",
			c.name, R3ShieldCoreLogReplay::LastFailureStage());
		Check(name, ok && shape);
		if (!ok || !shape) {
			printf("        行: [%s]\n", line.c_str());
			continue;
		}

		char n2[160] = {};
		snprintf(n2, sizeof(n2), "%s：对象类型 / op / decision / status / pid / tid 一致", c.name);
		Check(n2,
			parsed.ObjectType == static_cast<ULONG>(c.type)
			&& parsed.Op == c.op
			&& parsed.Decision == static_cast<ULONG>(R3ShieldCore::Decision::Blocked)
			&& parsed.Status == 0xC0000022
			&& parsed.ProcessId == 4242
			&& parsed.ThreadId == 777);

		char n3[160] = {};
		snprintf(n3, sizeof(n3), "%s：目标 / 进程名 / 被拦标记一致", c.name);
		const bool targetOk = (parsed.Target == c.keyPath);
		const bool targetPidOk = (c.type == R3ShieldCore::ObjectType::Process
			|| c.type == R3ShieldCore::ObjectType::Thread)
			? (parsed.TargetProcessId == 909) : true;
		Check(n3, targetOk && targetPidOk && parsed.ProcessName == L"x.exe"
			&& parsed.BlockedByUs
			&& (parsed.Flags & R3ShieldCore::FlagEventBlocked) != 0);
	}
}

// 三个"特殊标签"分支：高危 / 降级放行 / 网络 proto。
static void TestSpecialTags()
{
	printf("\n-- ②b 特殊尾部标签与网络字段\n");

	{
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
			static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
		e.ProcessId = 1;
		e.Flags2 = R3ShieldCore::FlagEvent2AskUnavailable;
		SetKeyPath(e, L"Software\\X");
		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, "a.exe"));

		R3ShieldCoreStats::LogEntry parsed = {};
		const bool ok = R3ShieldCoreLogReplay::ParseLineForTest(line, parsed);
		Check("降级放行标记：解析成功且 Flags2 位被还原",
			ok && (parsed.Flags2 & R3ShieldCore::FlagEvent2AskUnavailable) != 0);
		Check("降级放行标记：行尾确实带 [ASK-UNAVAIL...",
			line.find("[ASK-UNAVAIL") != std::string::npos);

		// 反向对照：没置位时**不该**出现这个标记（否则上面那条可能恒真）
		R3ShieldCore::Event e2 = e;
		e2.Flags2 = 0;
		const std::string line2 = LogLine::StripForDisplay(LogLine::FormatEventLine(e2, "a.exe"));
		Check("NEG：未置位时行尾没有该标记",
			line2.find("[ASK-UNAVAIL") == std::string::npos);
	}

	{
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::Network),
			static_cast<ULONG>(R3ShieldCore::NetOp::Connect),
			static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
		e.ProcessId = 2;
		e.TargetPort = 443;
		e.NetProtocol = 6;
		SetKeyPath(e, L"example.com");
		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, "b.exe"));
		Check("网络事件：第二字段是合成的 proto=443/TCP",
			line.find("proto=443/TCP") != std::string::npos);

		// DNS 查询：没有端口，走 "dns" 分支
		R3ShieldCore::Event d = e;
		d.Op = static_cast<ULONG>(R3ShieldCore::NetOp::DnsQuery);
		d.TargetPort = 0;
		const std::string lineD = LogLine::StripForDisplay(LogLine::FormatEventLine(d, "b.exe"));
		Check("网络事件（DNS）：第二字段是 proto=dns",
			lineD.find("proto=dns") != std::string::npos);
	}

	{
		// 进程旁路：第二字段是命令行（不是 ValueName）
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::ProcessSpawn),
			static_cast<ULONG>(R3ShieldCore::SpawnOp::ShellExecute),
			static_cast<ULONG>(R3ShieldCore::Decision::Blocked));
		e.ProcessId = 3;
		SetKeyPath(e, L"C:\\Windows\\cmd.exe");
		wcsncpy_s(e.CommandLine, L"/c whoami", _TRUNCATE);
		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, "c.exe"));
		Check("进程旁路：第二字段是 cmd=/c whoami",
			line.find("cmd=/c whoami") != std::string::npos);
	}

	{
		// hive 级操作：第一字段是 target=，第二字段是 file=
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
			static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
		e.TargetKind = static_cast<ULONG>(R3ShieldCore::TargetKind::Hive);
		e.ProcessId = 4;
		SetKeyPath(e, L"C:\\Users\\a\\NTUSER.DAT");
		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, "d.exe"));
		Check("hive 级：第一字段是 target=（不是 key=）",
			line.find("  target=C:\\Users\\a\\NTUSER.DAT") != std::string::npos);

		// 反向对照：同样的 op 但 TargetKind=Key ⇒ 必须是 key=
		R3ShieldCore::Event k = e;
		k.TargetKind = static_cast<ULONG>(R3ShieldCore::TargetKind::Key);
		const std::string lineK = LogLine::StripForDisplay(LogLine::FormatEventLine(k, "d.exe"));
		Check("NEG：TargetKind=Key 时是 key=",
			lineK.find("  key=C:\\Users\\a\\NTUSER.DAT") != std::string::npos);
	}

	{
		// 进程名为空 ⇒ 渲染成 "?"（原行为，别改）
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
			static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
		e.ProcessId = 5;
		SetKeyPath(e, L"Software\\Y");
		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, ""));
		Check("进程名取不到时渲染成 ?", line.find("[?]") != std::string::npos);
	}

	{
		// 空 KeyPath ⇒ 渲染成 (unknown)（原行为，别改）
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
			static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
		e.ProcessId = 6;
		// KeyPath 与 KeyPathLength 都留 0（= 生产者没填）
		const std::string line = LogLine::StripForDisplay(LogLine::FormatEventLine(e, "e.exe"));
		Check("空 KeyPath 渲染成 key=(unknown)",
			line.find("key=(unknown)") != std::string::npos);
	}
}

// ---------------------------------------------------------------- ③ 引擎侧真的用上了

static void TestEngineStatsProducesSameLine()
{
	printf("\n-- ③ 引擎侧 OnEvent 落到环形缓冲的 Line 与共享头一致\n");

	R3ShieldCoreStats::Reset();

	R3ShieldCore::Event e = MakeEvent(
		static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
		static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
		static_cast<ULONG>(R3ShieldCore::Decision::Blocked));
	e.ProcessId = 31337;
	e.ThreadId = 12;
	e.Status = 0xC0000022;
	e.Flags = R3ShieldCore::FlagEventHighRisk | R3ShieldCore::FlagEventBlocked;
	SetKeyPath(e, L"Software\\V81");
	SetValueName(e, L"V");

	R3ShieldCoreStats::OnEvent(e);

	const R3ShieldCoreStats::LogChunk chunk = R3ShieldCoreStats::GetLogsSince(0, 8);
	Check("环形缓冲里拿到 1 条", chunk.Entries.size() == 1);
	if (chunk.Entries.empty()) { return; }

	const R3ShieldCoreStats::LogEntry& row = chunk.Entries.front();
	// 引擎侧此时统计表里没有 31337 这个名字 ⇒ 两侧都退化成 "?"，
	// 正是"同一条事件在两条数据源里显示成同一个字"的判据。
	const std::string expected = LogLine::StripForDisplay(
		LogLine::FormatEventLine(e, Text::WideToUtf8(row.ProcessName).c_str()));

	Check("Line 非空", !row.Line.empty());
	Check("Line 与 FormatEventLine 输出一致", row.Line == expected);
	Check("Line 结尾不带 CR/LF",
		row.Line.find('\r') == std::string::npos && row.Line.find('\n') == std::string::npos);
	Check("ThreadId 已落进 LogEntry", row.ThreadId == 12);
	Check("Flags2 已落进 LogEntry", row.Flags2 == 0);
	Check("Line 里带 tid=12", row.Line.find("tid=12") != std::string::npos);
	Check("Line 里带 [HIGH-RISK] 与 [by R3ShieldCore]",
		row.Line.find("[HIGH-RISK]") != std::string::npos
		&& row.Line.find("[by R3ShieldCore]") != std::string::npos);
}

// ---------------------------------------------------------------- ④ 管道协议编解码

static void TestIpcCodec()
{
	printf("\n-- ④ cfg_ipc.h 编解码（转义 / 字段切分 / 应答解析）\n");

	// 转义：往返必须无损（含分隔符与换行 —— 这是"字段数会漂"的根源）
	{
		const char* tricky[] = {
			"a|b",
			"back\\slash",
			"cr\rlf\nmix",
			"\\|\\p\\\\",
			"中文 路径 C:\\Program Files\\x",
			"|\\\r\n",
		};
		bool all = true;
		for (const char* t : tricky) {
			const std::string esc = Ipc::Escape(t);
			const std::string back = Ipc::Unescape(esc);
			if (back != t) {
				all = false;
				printf("        失败: [%s] -> [%s] -> [%s]\n", t, esc.c_str(), back.c_str());
			}
			// 转义后的串里**不能**再有裸的分隔符 / 换行
			if (esc.find('|') != std::string::npos
				|| esc.find('\r') != std::string::npos
				|| esc.find('\n') != std::string::npos) {
				all = false;
				printf("        转义后仍含分隔符: [%s]\n", esc.c_str());
			}
		}
		Check("6 组刁钻文本：转义往返无损且不含裸分隔符", all);
	}

	// ★★ 关键：一条**含 `|` 的日志行**经载荷行编码后，字段数不能漂
	{
		const std::string logLine =
			"2026-10-16 12:00:00.000  pid=1  [a.exe] tid=2    REG  BLOCK       HIGH "
			"SetValueKey       status=0xC0000022  key=a|b|c  value=d|e  [HIGH-RISK]";
		const std::string payload = Ipc::BuildLogPayloadLine(12345, logLine);
		const std::vector<std::string> fields = Ipc::SplitFields(payload);
		Check("载荷行切成 3 个字段（不是被行内的 | 撑开）", fields.size() == 3);

		ULONG serial = 0;
		std::string back;
		Check("载荷行解析成功", Ipc::ParseLogPayloadLine(payload, serial, back));
		Check("序号一致", serial == 12345);
		Check("日志行逐字节还原", back == logLine);
	}

	// 配置载荷行：值里有 `|` 与中文
	{
		const std::string payload = Ipc::BuildConfigPayloadLine("protect_reg",
			"SOFTWARE\\A|B \xe4\xb8\xad\xe6\x96\x87");
		std::string k, v;
		Check("配置载荷行解析成功", Ipc::ParseConfigPayloadLine(payload, k, v));
		Check("键 / 值一致", k == "protect_reg"
			&& v == "SOFTWARE\\A|B \xe4\xb8\xad\xe6\x96\x87");
		Check("NEG：日志载荷行不会被当成配置行",
			!Ipc::ParseConfigPayloadLine(Ipc::BuildLogPayloadLine(1, "x"), k, v));
	}

	// 整块应答：状态行 + 载荷行
	{
		const std::vector<std::string> status = { "OK", "latest=12", "total=20", "count=2" };
		const std::vector<std::string> payload = {
			Ipc::BuildLogPayloadLine(11, "line|eleven"),
			Ipc::BuildLogPayloadLine(12, "line|twelve"),
		};
		const std::string blob = Ipc::BuildResponse(status, payload);

		Ipc::Response resp;
		Check("应答解析成功", Ipc::ParseResponse(blob, resp));
		Check("不是错误应答", resp.Ok && !resp.IsError);
		Check("latest 取到 12", Ipc::ToULong(Ipc::FindKeyed(resp, "latest")) == 12);
		Check("载荷 2 行", resp.Payload.size() == 2);
		if (resp.Payload.size() == 2) {
			ULONG s = 0;
			std::string l;
			Check("第 2 条载荷行还原",
				Ipc::ParseLogPayloadLine(resp.Payload[1], s, l)
				&& s == 12 && l == "line|twelve");
		}

		// 错误应答
		Ipc::Response err;
		Check("ERR 应答被识别", Ipc::ParseResponse(Ipc::BuildErrorResponse("没有引擎|在跑"),
			err) && err.IsError && !err.Ok);
		Check("错误说明里的 | 能还原",
			Ipc::Unescape(err.Fields.size() > 1 ? err.Fields[1] : "") == "没有引擎|在跑");

		// 反向对照：垃圾输入**不能**被当成成功应答（否则判据恒真）
		Ipc::Response junk;
		Check("NEG：乱码不被当成 OK",
			!Ipc::ParseResponse("hello there\n", junk) || !junk.Ok);
		Check("NEG：空应答解析失败", !Ipc::ParseResponse("", junk));
	}

	// 管道名必须带会话号（多会话下不能撞）
	{
		const std::wstring name = Ipc::PipeName();
		Check("管道名带 \\\\.\\pipe\\ 前缀",
			name.rfind(L"\\\\.\\pipe\\", 0) == 0);
		DWORD session = 0;
		ProcessIdToSessionId(GetCurrentProcessId(), &session);
		Check("管道名以本会话号结尾",
			name.size() > 4
			&& name.compare(name.size() - std::to_wstring(session).size(),
				std::string::npos, std::to_wstring(session)) == 0);
	}
}

// ---------------------------------------------------------------- ⑤ 真实日志语料（可选）

static void TestRealLogCorpus(const char* path)
{
	printf("\n-- ⑤ 真实日志语料（每个键的格式契约）\n");

	if (!path || !path[0]) {
		printf("  [SKIP] 未提供日志文件（用法：log_line_rt_ut.exe <events.log>）\n");
		return;
	}

	FILE* f = nullptr;
	if (fopen_s(&f, path, "rb") != 0 || !f) {
		printf("  [SKIP] 打不开：%s\n", path);
		return;
	}

	std::string blob;
	char buf[65536];
	size_t got = 0;
	while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
		blob.append(buf, got);
	}
	fclose(f);

	size_t total = 0;
	size_t ok = 0;
	size_t firstBadLine = 0;
	std::string firstBadText;
	size_t start = 0;
	while (start < blob.size()) {
		size_t nl = blob.find('\n', start);
		if (nl == std::string::npos) { nl = blob.size(); }
		size_t end = nl;
		if (end > start && blob[end - 1] == '\r') { --end; }
		if (end > start) {
			const std::string line = blob.substr(start, end - start);
			++total;
			R3ShieldCoreStats::LogEntry e = {};
			if (R3ShieldCoreLogReplay::ParseLineForTest(line, e)) {
				++ok;
			}
			else if (firstBadText.empty()) {
				firstBadLine = total;
				firstBadText = line;
			}
		}
		start = nl + 1;
	}

	printf("        共 %zu 行，解析成功 %zu 行\n", total, ok);
	char name[160] = {};
	snprintf(name, sizeof(name), "语料里每一行都能被解析（%zu/%zu）", ok, total);
	Check(name, total > 0 && ok == total);
	if (ok != total) {
		printf("        第一处失败：第 %zu 行 stage=%s\n            %s\n",
			firstBadLine, R3ShieldCoreLogReplay::LastFailureStage(), firstBadText.c_str());
	}
}

// ---------------------------------------------------------------- ⑥ 逐字节回环（最强判据）

// 把解析出来的 LogEntry **还原成一条 Event**，再用共享头格式化一遍，
// 要求得到**和原行逐字节相同**的文本。
//
// ★ 这是"把格式化搬进共享头"这件事**唯一**真正有力的证明：
//   格式化（log_line.h）与解析（r3shieldcore_log_replay.cpp）是两份
//   独立实现 —— 如果搬的过程中少了 `tid=`、少了 `proto=`、标签顺序变了、
//   或者少了一个空格，这里立刻红，而且是**逐字节**地红。
//
//   注意还原是有损的：解析器只保留它关心的字段。所以本测试**只对能还原的
//   部分负责** —— 凡是"解析器压根没留"的信息（本地端点、DesiredAccess 等）
//   都不参与格式化，因此不影响结论。
static bool ReconstructEvent(const R3ShieldCoreStats::LogEntry& e,
	R3ShieldCore::Event& out)
{
	out = R3ShieldCore::Event{};
	out.ObjectType = e.ObjectType;
	out.Op = e.Op;
	out.Decision = e.Decision;
	out.Status = e.Status;
	out.ProcessId = e.ProcessId;
	out.ThreadId = e.ThreadId;
	out.TargetProcessId = e.TargetProcessId;
	out.Flags = e.Flags;
	out.Flags2 = e.Flags2;
	out.TargetKind = e.IsHive ? static_cast<ULONG>(R3ShieldCore::TargetKind::Hive)
		: static_cast<ULONG>(R3ShieldCore::TargetKind::Key);
	out.TimeStamp = e.TimeStamp;

	wcsncpy_s(out.KeyPath, e.Target.c_str(), _TRUNCATE);
	out.KeyPathLength = static_cast<ULONG>(wcslen(out.KeyPath));

	const auto type = static_cast<R3ShieldCore::ObjectType>(e.ObjectType);
	if (type == R3ShieldCore::ObjectType::Network) {
		// 网络事件：解析器把合成的第二字段（"443/TCP" / "dns" / "n/a"）
		// 放进了 Value，这里反过来拆成 TargetPort / NetProtocol。
		const std::wstring& v = e.Value;
		if (v == L"dns") {
			// Op 已经是 DnsQuery，端口无关紧要
			out.TargetPort = 0;
			out.NetProtocol = 0;
		}
		else if (v == L"n/a") {
			out.TargetPort = 0;
		}
		else {
			const size_t slash = v.find(L'/');
			if (slash == std::wstring::npos) {
				return false;   // 认不出来就别装作能还原
			}
			out.TargetPort = static_cast<ULONG>(wcstoul(v.substr(0, slash).c_str(), nullptr, 10));
			const std::wstring proto = v.substr(slash + 1);
			out.NetProtocol = (proto == L"TCP") ? 6u : ((proto == L"UDP") ? 17u : 0u);
		}
		return true;
	}

	if (type == R3ShieldCore::ObjectType::ProcessSpawn) {
		// 进程旁路：第二字段是命令行（ValueName 不参与）
		wcsncpy_s(out.CommandLine, e.Value.c_str(), _TRUNCATE);
		return true;
	}

	// 其余：第二字段就是 ValueName
	wcsncpy_s(out.ValueName, e.Value.c_str(), _TRUNCATE);
	out.ValueNameLength = static_cast<ULONG>(wcslen(out.ValueName));
	return true;
}

static void TestRealLogByteRoundTrip(const char* path)
{
	printf("\n-- ⑥ 逐字节回环：format(parse(行)) == 行（最强判据）\n");

	if (!path || !path[0]) {
		printf("  [SKIP] 未提供日志文件（用法：log_line_rt_ut.exe <events.log>）\n");
		return;
	}

	FILE* f = nullptr;
	if (fopen_s(&f, path, "rb") != 0 || !f) {
		printf("  [SKIP] 打不开：%s\n", path);
		return;
	}
	std::string blob;
	char buf[65536];
	size_t got = 0;
	while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
		blob.append(buf, got);
	}
	fclose(f);

	size_t total = 0;
	size_t parsed = 0;
	size_t identical = 0;
	size_t unrepresentable = 0;
	size_t bomLines = 0;
	std::string firstDiffOriginal;
	std::string firstDiffFormatted;
	size_t start = 0;
	while (start < blob.size()) {
		size_t nl = blob.find('\n', start);
		if (nl == std::string::npos) { nl = blob.size(); }
		size_t end = nl;
		if (end > start && blob[end - 1] == '\r') { --end; }
		if (end > start) {
			std::string line = blob.substr(start, end - start);
			++total;

			// ★ 文件**开头**有一个 UTF-8 BOM（DLL 在 `Open` 时写一次，
			//   不是每行一个）。它是**文件级**的东西，不属于"事件那一行" ——
			//   所以比对前剥掉，并且下面单独钉住"格式化不会自己吐 BOM"
			//   （真吐了的话每一行都会变成乱码，而日志文件照样在长）。
			if (line.size() >= 3
				&& static_cast<unsigned char>(line[0]) == 0xEF
				&& static_cast<unsigned char>(line[1]) == 0xBB
				&& static_cast<unsigned char>(line[2]) == 0xBF) {
				line.erase(0, 3);
				++bomLines;
			}

			R3ShieldCoreStats::LogEntry e = {};
			if (R3ShieldCoreLogReplay::ParseLineForTest(line, e)) {
				++parsed;
				R3ShieldCore::Event ev = {};
				if (ReconstructEvent(e, ev)) {
					const std::string again = LogLine::StripForDisplay(
						LogLine::FormatEventLine(ev, Text::WideToUtf8(e.ProcessName).c_str()));
					if (again == line) {
						++identical;
					}
					else if (firstDiffOriginal.empty()) {
						firstDiffOriginal = line;
						firstDiffFormatted = again;
					}
				}
				else {
					++unrepresentable;
				}
			}
		}
		start = nl + 1;
	}

	printf("        共 %zu 行（其中带文件头 BOM 的 %zu 行）：解析成功 %zu，"
		"逐字节相同 %zu，无法还原 %zu\n",
		total, bomLines, parsed, identical, unrepresentable);
	printf("        （无法还原 = 解析器没留该字段，属于已知有损，不算失败）\n");

	char name[200] = {};
	snprintf(name, sizeof(name), "每一条可还原的行都逐字节相同（%zu 条）", identical);
	Check(name, identical > 0 && firstDiffOriginal.empty());

	// 反向对照：格式化**绝不能**自己吐 BOM（否则每行都带一个 ⇒ 全是乱码）
	{
		R3ShieldCore::Event e = MakeEvent(
			static_cast<ULONG>(R3ShieldCore::ObjectType::Registry),
			static_cast<ULONG>(R3ShieldCore::Op::SetValueKey),
			static_cast<ULONG>(R3ShieldCore::Decision::Allowed));
		e.ProcessId = 7;
		SetKeyPath(e, L"Software\\Bom");
		const std::string line = LogLine::FormatEventLine(e, "z.exe");
		Check("NEG：格式化输出不带 BOM（BOM 是文件级的，只写一次）",
			line.size() < 3
			|| static_cast<unsigned char>(line[0]) != 0xEF
			|| static_cast<unsigned char>(line[1]) != 0xBB
			|| static_cast<unsigned char>(line[2]) != 0xBF);
	}

	if (!firstDiffOriginal.empty()) {
		printf("        第一处不一致：\n          原行: [%s]\n          重排: [%s]\n",
			firstDiffOriginal.c_str(), firstDiffFormatted.c_str());
	}
}

int main(int argc, char** argv)
{
	printf("=== v81 单测：事件日志行唯一实现 + 管道协议编解码 ===\n");

	TestGoldenRegistryLine();
	TestAllObjectTypesRoundTrip();
	TestSpecialTags();
	TestEngineStatsProducesSameLine();
	TestIpcCodec();
	TestRealLogCorpus(argc > 1 ? argv[1] : nullptr);
	TestRealLogByteRoundTrip(argc > 1 ? argv[1] : nullptr);

	printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
