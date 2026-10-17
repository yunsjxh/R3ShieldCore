//
// cfg_ipc_probe.cpp —— v81「配置工具 ⇄ 引擎」管道协议的**端到端夹具**。
//
// ============================================================================
//  为什么需要它（以及为什么它**不跑引擎**）
// ============================================================================
//  本机明令禁止运行引擎（全局注入会 hook 编辑器 ⇒ 崩，铁律 175）。
//  但管道协议恰恰是**跨进程**的东西 —— 如果只在单测里测"编解码函数"
//  （`log_line_rt_ut` 已覆盖），那么"两侧对管道的假设不一致"这类缺陷
//  一条都测不出来。本轮就实测到一个：
//    · 服务端建管道用 `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE`；
//    · 客户端却去 `SetNamedPipeHandleState(..., PIPE_READMODE_MESSAGE)`。
//  两侧各自单测都能过，**只有真连一次**才会暴露。
//
//  ⇒ 本夹具的做法：**自己起一个"假引擎"服务端**（用共享头里的协议，
//     与生产服务端**同一份编解码**），然后用**生产客户端代码**
//     （`R3ShieldCoreCfgIpc::Call`）去连它。
//
//  ★ 它测的是"协议契约两侧是否一致"，不是"引擎业务是否正确"——
//    后者由别的套件管。所以假服务端只回**固定的**数据。
//
//  ★ 反向对照（铁律 54）：`--neg` 让夹具**故意**用消息模式建管道，
//    生产客户端（字节模式假设）应当读不出东西 ⇒ 证明这组判据**有分辨力**
//    （"能过"不是因为判据太松）。
//
//  用法：
//    cfg_ipc_probe.exe            正常跑（应全过）
//    cfg_ipc_probe.exe --neg      反向对照（应报失败）
//
#include <r3shieldcore/cfg_ipc.h>

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

namespace Ipc = R3ShieldCoreCfgIpc;

static int g_pass = 0;
static int g_fail = 0;

static void Check(bool ok, const char* name)
{
	if (ok) {
		++g_pass;
		std::printf("  [PASS] %s\n", name);
	}
	else {
		++g_fail;
		std::printf("  [FAIL] %s\n", name);
	}
}

// ---------------------------------------------------------------------------
//  假服务端：用**共享头里的构造器**造应答（与生产服务端同一份代码）
// ---------------------------------------------------------------------------
namespace
{
	HANDLE g_pipe = INVALID_HANDLE_VALUE;
	HANDLE g_thread = nullptr;
	volatile LONG g_stop = 0;
	bool g_negMode = false;          // --neg：故意用消息模式建管道（反面对照）
	int g_served = 0;

	// 三条固定的假数据：一条日志行、两条配置项。
	std::string FakeLogResponse()
	{
		std::vector<std::string> payload;
		payload.push_back(Ipc::BuildLogPayloadLine(11,
			"2026-10-16 21:30:00.000  pid=4242[probe.exe] tid=1  REG  BLOCK  HIGH  CreateKey  0x00000000  key=Software\\Evil"));
		payload.push_back(Ipc::BuildLogPayloadLine(12,
			"2026-10-16 21:30:01.125  pid=4243[other.exe] tid=2  FILE ALLOW        CreateFile 0x00000000  path=C:\\a|b.txt"));
		return Ipc::BuildResponse({ "OK", "latest=12", "total=12", "count=2" }, payload);
	}

	std::string FakeConfigResponse()
	{
		std::vector<std::string> payload;
		payload.push_back(Ipc::BuildConfigPayloadLine("mode", "block"));
		payload.push_back(Ipc::BuildConfigPayloadLine("weird|key", "v=x\\y"));
		return Ipc::BuildResponse({ "OK", "count=2" }, payload);
	}

	std::string HandleFake(const std::string& request)
	{
		const std::vector<std::string> f = Ipc::SplitFields(request);
		if (f.empty() || f[0].empty()) {
			return Ipc::BuildErrorResponse("空请求");
		}
		const std::string verb = f[0];
		if (verb == Ipc::kVerbHello) {
			return Ipc::BuildResponse({ "OK", "proto=1", "abi=26", "pid=999" });
		}
		if (verb == Ipc::kVerbPing) {
			return Ipc::BuildResponse({ "OK" });
		}
		if (verb == Ipc::kVerbLog) {
			return FakeLogResponse();
		}
		if (verb == Ipc::kVerbConfig) {
			return FakeConfigResponse();
		}
		if (verb == Ipc::kVerbSync) {
			return Ipc::BuildResponse({ "OK", "applied=mode", "restart=hook_file,hook_reads",
				"detail=只有 mode 能热应用" });
		}
		return Ipc::BuildErrorResponse("认不出的命令");
	}

	DWORD WINAPI FakeServer(LPVOID)
	{
		const std::wstring name = Ipc::PipeName();
		while (!g_stop) {
			DWORD openMode = PIPE_ACCESS_DUPLEX;
			DWORD mode = g_negMode
				? (PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS)
				: (PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS);
			(void)openMode;

			HANDLE p = ::CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX, mode,
				4, 256 * 1024, 16 * 1024, 0, nullptr);
			if (p == INVALID_HANDLE_VALUE) {
				::Sleep(200);
				continue;
			}

			const BOOL ok = ::ConnectNamedPipe(p, nullptr)
				? TRUE
				: (::GetLastError() == ERROR_PIPE_CONNECTED);
			if (g_stop) { ::CloseHandle(p); break; }
			if (!ok) { ::CloseHandle(p); continue; }

			++g_served;

			// 读一条请求（到 '\n' 为止）。
			std::string buf;
			for (;;) {
				char c[512] = {};
				DWORD got = 0;
				if (!::ReadFile(p, c, sizeof(c), &got, nullptr) || got == 0) { break; }
				buf.append(c, got);
				if (buf.find('\n') != std::string::npos) { break; }
			}

			std::string line = buf;
			const size_t nl = line.find('\n');
			if (nl != std::string::npos) { line.erase(nl); }
			if (!line.empty() && line.back() == '\r') { line.pop_back(); }

			const std::string response =
				(g_served == 1 && line.rfind(Ipc::kVerbConfig, 0) == 0)
				? std::string()   // 第一个请求不该是 CONFIG；给个空应答当哨兵
				: HandleFake(line);

			DWORD wrote = 0;
			::WriteFile(p, response.data(), static_cast<DWORD>(response.size()), &wrote, nullptr);
			::FlushFileBuffers(p);
			::DisconnectNamedPipe(p);
			::CloseHandle(p);
		}
		return 0;
	}
}  // namespace

int main(int argc, char** argv)
{
	const bool neg = (argc > 1 && std::string(argv[1]) == "--neg");
	g_negMode = neg;

	std::setvbuf(stdout, nullptr, _IONBF, 0);   // 铁律 253：不要 _IOLBF

	std::printf("=== cfg_ipc 端到端夹具（协议契约两侧一致性）===\n");
	std::printf("模式: %s\n", neg ? "反向对照（故意用消息模式建管道）" : "正常（字节模式，与生产一致）");
	std::printf("管道: %ls\n\n", Ipc::PipeName().c_str());

	g_thread = ::CreateThread(nullptr, 0, FakeServer, nullptr, 0, nullptr);
	::Sleep(300);   // 等管道实例建好

	// ---- ① 握手 --------------------------------------------------------
	{
		const auto r = Ipc::Call(Ipc::BuildHelloRequest());
		Check(r.Connected, "① HELLO: 连上了");
		if (neg) {
			// 反向对照：字节模式客户端撞消息模式服务端 ⇒ 不该拿到正确应答。
			Check(!r.Ok, "① HELLO(NEG): **不应**解析成功（证明判据有分辨力）");
		}
		else {
			Check(r.Ok, "① HELLO: 应答 OK");
			Check(Ipc::FindKeyed(r.Reply, "abi") == "26", "① HELLO: abi=26");
		}
	}

	// ---- ② LOG：载荷行解析 + 转义还原 ----------------------------------
	if (!neg) {
		const auto r = Ipc::Call(Ipc::BuildLogRequest(0, 64));
		Check(r.Ok, "② LOG: 应答 OK");
		Check(r.Reply.Payload.size() == 2, "② LOG: 拿到 2 条载荷行");
		Check(Ipc::FindKeyed(r.Reply, "latest") == "12", "② LOG: latest=12");

		ULONG s1 = 0; std::string t1;
		const bool p1 = !r.Reply.Payload.empty()
			&& Ipc::ParseLogPayloadLine(r.Reply.Payload[0], s1, t1);
		Check(p1 && s1 == 11, "② LOG: 第 1 条序号=11");
		Check(p1 && t1.find("key=Software\\Evil") != std::string::npos,
			"② LOG: 第 1 条文本完整（含反斜杠路径）");

		// ★ 第 2 条的文本里**本来就有 `|`**（`C:\a|b.txt`）——
		//   它能原样还原 = 转义/反转义真的生效（不是靠"碰巧没有分隔符"）。
		ULONG s2 = 0; std::string t2;
		const bool p2 = r.Reply.Payload.size() > 1
			&& Ipc::ParseLogPayloadLine(r.Reply.Payload[1], s2, t2);
		Check(p2 && t2.find("path=C:\\a|b.txt") != std::string::npos,
			"② LOG: 第 2 条里**原有的 `|`** 被完整还原（转义生效）");
	}

	// ---- ③ CONFIG：键值里带 `|` 与 `\` ---------------------------------
	if (!neg) {
		const auto r = Ipc::Call(Ipc::BuildConfigRequest());
		Check(r.Ok, "③ CONFIG: 应答 OK");
		Check(r.Reply.Payload.size() == 2, "③ CONFIG: 拿到 2 条配置行");

		std::string k, v;
		const bool c1 = !r.Reply.Payload.empty()
			&& Ipc::ParseConfigPayloadLine(r.Reply.Payload[0], k, v);
		Check(c1 && k == "mode" && v == "block", "③ CONFIG: mode=block");

		std::string k2, v2;
		const bool c2 = r.Reply.Payload.size() > 1
			&& Ipc::ParseConfigPayloadLine(r.Reply.Payload[1], k2, v2);
		Check(c2 && k2 == "weird|key", "③ CONFIG: 键里的 `|` 被还原");
		Check(c2 && v2 == "v=x\\y", "③ CONFIG: 值里的 `\\` 被还原");
	}

	// ---- ④ SYNC：热应用 vs 要重启 --------------------------------------
	if (!neg) {
		const auto r = Ipc::Call(Ipc::BuildSyncRequest());
		Check(r.Ok, "④ SYNC: 应答 OK");
		Check(Ipc::FindKeyed(r.Reply, Ipc::kSyncFieldApplied) == "mode",
			"④ SYNC: applied 字段可读");
		Check(Ipc::FindKeyed(r.Reply, Ipc::kSyncFieldRestart)
			== "hook_file,hook_reads", "④ SYNC: restart 字段可读");
	}

	// ---- ⑤ 引擎不在跑：必须**明确失败**，不能假装成功（铁律 57 家族）---
	{
		// 先停服务端，让管道消失。
		::InterlockedExchange(&g_stop, 1);
		if (g_thread) {
			// 用一次连接把它从 ConnectNamedPipe 上踢下来。
			HANDLE kick = ::CreateFileW(Ipc::PipeName().c_str(), GENERIC_READ | GENERIC_WRITE,
				0, nullptr, OPEN_EXISTING, 0, nullptr);
			if (kick != INVALID_HANDLE_VALUE) { ::CloseHandle(kick); }
			::WaitForSingleObject(g_thread, 3000);
			::CloseHandle(g_thread);
			g_thread = nullptr;
		}
		::Sleep(200);

		const auto r = Ipc::Call(Ipc::BuildPingRequest());
		if (neg) {
			// 反向对照模式下面板已经乱了，这里不再叠加。
			std::printf("  [SKIP] ⑤ 反向对照模式下跳过\n");
		}
		else {
			Check(!r.Connected, "⑤ 引擎不在跑: Connected=false（不会假装连上）");
			Check(!r.Ok, "⑤ 引擎不在跑: Ok=false（**不是**静默成功）");
			Check(!r.Error.empty(), "⑤ 引擎不在跑: 给出可读的失败原因");
			std::printf("       原因: %s\n", r.Error.c_str());
		}
	}

	std::printf("\n=== %d passed, %d failed ===\n", g_pass, g_fail);

	// ★ 判定要看**分辨力**：正常模式必须全过；反向对照模式**必须**有失败，
	//   否则说明这组判据在"协议不一致"时也会报绿（空判据，铁律 110/128）。
	if (neg) {
		if (g_fail == 0) {
			std::printf("[BAD] 反向对照竟然全过 —— 判据没有分辨力\n");
			return 1;
		}
		std::printf("[OK] 反向对照按预期失败（%d failed）—— 判据有分辨力\n", g_fail);
		return 0;
	}
	return (g_fail == 0 && g_pass > 0) ? 0 : 1;
}
