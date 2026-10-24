// engine_client.h —— 界面进程这一侧的「引擎客户端」。
//
//   ────────────────────────────────────────────────────────────────
//   它替掉了原来的 `EngineControl`（同进程 LoadLibrary 那个）
//   ────────────────────────────────────────────────────────────────
//   界面里所有"跟引擎有关"的动作都收敛到这里：
//     · 启动/连接引擎进程（`Start`）
//     · 收事件 → 转给 `R3ShieldCoreStats`（通过 sink 回调，本类不认识 Stats）
//     · 收统计快照 → 界面每帧读 `LatestStats()`
//     · 切模式 / 判高危 / 内部退出 / 停引擎（同步请求-应答）
//
//   ★ 一个刻意的取舍：**同一时刻只允许一个在途请求**（内部用一把锁串行化）。
//     界面侧这类请求本来就少（点按钮、每秒几次高危检查），串行化换来的是
//     "应答按顺序匹配"这件简单事 —— 不用在协议里再塞一个 requestId。
//
//   ★ 另一个取舍：统计**只由引擎主动推**（200ms 一次），界面不发 `ReadStats`。
//     少一条请求路径，就少一处"推的和应答的混在一起分不清"。
#pragma once

#include <r3shieldcore/engine_ipc.h>
#include <r3shieldcore/r3shieldcore_shared.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace R3ShieldCoreEngine
{
	class Client
	{
	public:
		using EventSink = void (*)(const R3ShieldCore::Event&, void*);

		Client() = default;
		~Client();
		Client(const Client&) = delete;
		Client& operator=(const Client&) = delete;

		// 连接引擎；没有就拉起一个。
		//
		//   exeDirectory —— 引擎 exe 所在目录（通常和界面 exe 同目录）
		//   返回 false 时 `LastError()` 里是给人看的中文原因。
		bool Start(const std::filesystem::path& exeDirectory, EventSink sink, void* context);

		// 断开并（可选）要求引擎退出。
		//
		//   ★ `stopEngine = true` 对应界面上的「退出引擎」—— 引擎会收尾
		//     （反注入、销毁共享内存）后退出。`false` 只是断开连接，
		//     引擎继续防护（这是分进程的意义：界面可以随便关）。
		void Stop(bool stopEngine);

		bool Connected() const { return connected_.load(std::memory_order_relaxed); }
		const std::wstring& LastError() const { return lastError_; }
		uint32_t EnginePid() const { return enginePid_.load(std::memory_order_relaxed); }

		// ★ v90：`Stop(true)` 之后**到底停没停**，用一句人话回答。
		//
		//   为什么需要：v89 的 `Stop` 发完 `StopEngine` 就不管了，只打印
		//   "已请求退出"。而用户看到的"退出引擎用不了"恰恰可能是
		//   —— 请求发出去了、引擎没退（或压根没发出去）。
		//   ⇒ 这里给出三种明确结论：已退出 / 请求没发出去 / 发了但还在收尾。
		//   （铁律 97：布尔判定不可诊断，要给出"卡在哪一步"。）
		const std::wstring& StopReport() const { return stopReport_; }

		// 最新一份统计快照（引擎 200ms 推一次）。线程安全。
		R3ShieldCoreEngineIpc::StatsPayload LatestStats() const;

		// —— 请求-应答 ——
		// 全部带超时（默认 3000ms）。超时返回 false 并把原因写进 lastError_。
		//
		//   `engineReplied` 用来区分两类失败（铁律 97）：
		//     false + 返回 false ⇒ 通信失败（没连上/超时），下一步查部署
		//     true  + 返回 false ⇒ 引擎明确说"切不动"（DLL 不支持运行期切换），下一步查版本
		bool SetMode(R3ShieldCore::Mode mode, bool* engineReplied = nullptr);
		// 命中返回 true 并填 reason（UTF-8 → 宽串）；没命中返回 false 且 reason 为空。
		// ★ 必须和 `Available()` 区分：连不上引擎时返回 false 且 lastError_ 非空。
		//
		// ★★ v101：新增 `reachable` —— 把"引擎压根没答"与"引擎答了但没命中"
		//   分开。这两个在返回值上都是 false，而调用方（procwatch 的判据回调）
		//   **必须**分得开：前者要立刻熔断、别再把剩下几百个进程挨个问一遍。
		//   2026-10-24 现场就是 288 个进程 × 一次超时把主循环整场卡死。
		bool CheckHighRiskProcess(const std::wstring& imagePath, const std::wstring& systemRoot,
			std::wstring& reason, bool* reachable = nullptr);
		struct SelfExitResult
		{
			int code = -1;            // ArkActions::Result
			bool dllPresent = false;
			bool dllSameBuild = false;
			uint32_t win32Error = 0;
			uint32_t elapsedMs = 0;
		};
		bool SelfExit(uint32_t pid, SelfExitResult& out);

	private:
		bool ConnectOnly(int timeoutMs);
		bool LaunchEngine(const std::filesystem::path& exeDirectory);
		bool DoHandshake();
		void ReaderLoop();
		bool Request(R3ShieldCoreEngineIpc::Msg type, const void* payload, size_t len,
			std::vector<BYTE>& reply, int timeoutMs);

		HANDLE pipe_ = INVALID_HANDLE_VALUE;
		R3ShieldCoreEngineIpc::Aead aead_;
		R3ShieldCoreEngineIpc::FrameWriter writer_;
		R3ShieldCoreEngineIpc::FrameReader reader_;

		// 写管道要互斥（读线程回 Pong 之类 + 请求线程写请求）
		std::mutex writeMutex_;
		// 请求串行化 + 应答投递
		std::mutex requestMutex_;
		std::mutex replyMutex_;
		std::condition_variable replyCv_;
		std::vector<BYTE> replyBuf_;
		bool replyReady_ = false;

		std::mutex statsMutex_;
		R3ShieldCoreEngineIpc::StatsPayload stats_ = {};

		std::thread readerThread_;
		std::atomic<bool> running_{ false };
		std::atomic<bool> connected_{ false };
		std::atomic<uint32_t> enginePid_{ 0 };
		std::wstring lastError_;
		std::wstring stopReport_;

		EventSink sink_ = nullptr;
		void* sinkContext_ = nullptr;
	};
}
