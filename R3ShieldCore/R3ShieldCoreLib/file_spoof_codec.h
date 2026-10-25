#pragma once

//
// file_spoof_codec.h —— 文件「读替换」的**共享**实现（生产 + 探针同一份）。
//
// ======================================================================
// 为什么要有这个文件（铁律 127：同一份逻辑不许抄两份）
// ======================================================================
// 生产侧在 `file_guard.cpp` 的 `NtReadFile_Hook` 里用，探针
// `tools/spoof_file_probe.cpp` 在**自己挂的** NtReadFile detour 里用。
// 如果探针自己重写一遍"清多少字节 / 怎么记句柄"，那么探针通过
// **不能证明**生产代码是对的 —— 它只证明探针自己那套是对的
// （v73 摄像头就吃过这个亏，见铁律 210 的同族问题）。
// ⇒ 凡是"判据/落值"这类会漂的东西，一律抽到这里，两边 `#include`。
//
// ======================================================================
// 这一层负责什么、不负责什么
// ======================================================================
// 负责：
//   ① `HandleTable` —— 进程级「句柄 → 是否受保护」定长表（无锁、可重入）；
//   ② `BytesToZero` —— 这次读**该清多少字节**（含 STATUS_PENDING / 失败 /
//      EOF 三种"不该动"的情形）；
//   ③ `ZeroBuffer` —— 真去清，并如实返回"到底清成了没有"。
// 不负责：
//   · 判断路径是否受保护（那是 `R3ShieldCoreRules::MatchesUserProtectFile`）；
//   · 上报事件 / 写日志（生产侧自己做，探针没有 logger）。
//
// ======================================================================
// ★★★ 为什么表是「定长数组 + 原子交换」而不是 CRITICAL_SECTION
// ======================================================================
// hook 里拿锁有两个致命问题：
//   ① 持有者被挂起时，**所有线程**的读都停（NtReadFile 是整机最热的路径）；
//   ② 更糟的是**重入**：锁内代码若触发文件 I/O（日志！），会再次进
//      NtReadFile ⇒ **自死锁**，整个进程卡死。
// 定长数组的每个槽独立原子交换，没有"持有者"，也就不可能死锁。
// 代价：并发标记同一个句柄可能留下**两条相同记录** —— 无害
// （查询命中即返回；擦除会把两条都擦掉）。
//
// ★★★ 句柄值复用是这个面最大的正确性风险
// ======================================================================
// Windows 的句柄值是"最小的空闲槽位"，关掉一个立刻会被下一次打开复用。
// 若记录不擦，那么"受保护文件 A 的句柄 0x1A4"在 A 关闭后可能变成
// "无关文件 B"，于是我们会去清 **B 的读缓冲区** —— **静默数据损坏**，
// 比"没替换"严重得多（铁律 97 反面：宁可少做，不可做错）。
// ⇒ 三道防线：
//     ① 每次 open **成功**后先 `Forget` 再 `Mark`（覆盖式更新，主力防线 ——
//        进程里所有可用句柄都是 open 出来的，复用必经这里）；
//     ② `NtClose` 时 `Forget`（补"关掉后立刻被非文件对象复用"这条缝）；
//     ③ 表满时**不记录**（fail-open：放行真内容），由调用方吵一次日志。
//

#include <windows.h>
#include <string.h>
#include <wchar.h>

namespace R3ShieldCoreFileSpoof
{
	//
	// STATUS_PENDING。winternl.h 里叫 STATUS_PENDING，但本项目多个 TU
	// 刻意不 include winternl.h（会和 ntsecapi.h 的 SubAuth.h 撞定义），
	// 所以这里写死数值 —— 该值从 NT 3.1 起没变过，是稳定 ABI。
	//
	constexpr long StatusPending = 0x00000103L;

	//
	// 定长表的容量。
	//
	// ★ 为什么是 64：`protect_file=` 是用户手写的少数几条路径前缀，
	//   一个进程同时打开**受保护**文件的句柄数通常是个位数。
	//   64 已经远超正常用量；而"表满"的后果是 fail-open（放行真内容），
	//   不是崩溃 ⇒ 宁可小一点（查询是 O(n) 线性扫描，n 越小越快）。
	//   ★ 别为了"更保险"把它调大：这是**每次 NtReadFile** 都要扫的表。
	//
	constexpr ULONG MaxHandles = 64;

	//
	// 每个槽存不存路径（v135）。
	//
	// ★★★ 为什么必须存：v135 起文件面支持**按路径**配规则
	//   （`当 文件 的 路径 含 "secret" 时 替换为 全FF`）。
	//   而 `NtReadFile` 的参数里**没有路径**，只有 `HANDLE`
	//   —— 路径在 open 时才知道，所以只能在 open 时存下来。
	//
	// ★ 为什么是 260：与 `MaxProtectPathChars` / `MAX_PATH` 对齐。
	//   路径在入库前已被规范化（`MatchesUserProtectFile` 那一套）。
	//
	constexpr ULONG MaxPathChars = 260;

	//
	// 「槽已被某个线程抢下、正在写入」的哨兵值。
	//
	// ★★ 为什么需要它（并发正确性，不是洁癖）：
	//   `Mark` 要往槽里写路径，写完之后读者才该看到这个句柄。
	//   如果先 CAS 发布句柄、再写路径，读者会看到"句柄已在、路径还是空的"
	//   ⇒ 按空路径求值 ⇒ 命中不了任何规则 ⇒ **回落到默认动作**（至少还是假内容）。
	//   更糟的是两个线程同时 `Mark` 两个不同文件、抢到**同一个空槽**：
	//   A 发布句柄后 B 又把路径写进去 ⇒ A 的句柄配上 B 的路径。
	//   ⇒ 改成"先用哨兵独占槽，把路径写完整，再发布真句柄"。
	//
	//   ★ 哨兵选 `(HANDLE)1`：真实内核句柄都是 4 的倍数且非 0，
	//     1 永远不可能是有效句柄，所以读者永远不会把它当成命中。
	//   ★ 这个窗口内读者"看不见"这个句柄 ⇒ 看起来像 fail-open，
	//     但**实际不可能读到真内容**：句柄要等 open 返回才可被应用使用，
	//     而 `Refresh` 是在 open 的 hook 里、返回之前完成的。
	//
	inline HANDLE SlotClaimSentinel() noexcept
	{
		return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1));
	}

	struct HandleTable
	{
		struct Slot
		{
			HANDLE Handle;          // nullptr = 空槽
			volatile LONG Reported; // 是否已上报过（每次读都报会把日志刷爆）
			WCHAR Path[MaxPathChars];   // 受保护文件的路径（v135：规则求值用）
		};

		Slot Slots[MaxHandles];
		volatile LONG Count;           // 非空槽数量（只用于"表满"判定）
		volatile LONG OverflowLogged;  // 表满日志只吵一次

		//
		// 擦掉某个句柄值上的所有记录。
		//
		// ★ 先擦再记 / 先擦再关，两处都调它。擦一个**没记录过**的句柄是
		//   完全正常的（绝大多数 open 都不在保护范围内），不是错误。
		//
		void Forget(HANDLE handle) noexcept
		{
			if (!handle)
			{
				return;
			}

			for (ULONG i = 0; i < MaxHandles; i++)
			{
				PVOID previous = InterlockedCompareExchangePointer(
					reinterpret_cast<PVOID volatile*>(&Slots[i].Handle), nullptr, handle);

				if (previous == handle)
				{
					Slots[i].Reported = 0;
					InterlockedDecrement(&Count);
				}
			}
		}

		//
		// 记下"这个句柄指向受保护文件"。
		//
		// 返回值：true = 记下了；false = **表满，没记**（调用方应吵一次日志）。
		//
		// ⚠️ 调用方必须**先** `Forget` 过（或直接用 `Replace` 语义）——
		//    本函数**不**替调用方擦旧记录：同一个句柄值上有旧记录却直接
		//    Mark，会出现"一条旧记录 + 一条新记录"，旧的那条指向别的文件。
		//    `Refresh` 把两步合成一个，避免调用方漏掉。
		//
		bool Mark(HANDLE handle, const WCHAR* path = nullptr) noexcept
		{
			if (!handle)
			{
				return false;
			}

			for (ULONG i = 0; i < MaxHandles; i++)
			{
				// ① 先用**哨兵**独占这一槽（见 `SlotClaimSentinel` 的注释）。
				//    抢不到 ⇒ 这一槽被占 / 正被别人写，看下一槽。
				if (InterlockedCompareExchangePointer(
						reinterpret_cast<PVOID volatile*>(&Slots[i].Handle),
						SlotClaimSentinel(), nullptr) != nullptr)
				{
					continue;
				}

				// ② 槽归我：把路径写**完整**。此刻读者看到的是哨兵，
				//    不会匹配任何真实句柄 ⇒ 看不到"半成品"。
				Slots[i].Reported = 0;
				if (path)
				{
					wcsncpy_s(Slots[i].Path, path, _TRUNCATE);
				}
				else
				{
					Slots[i].Path[0] = L'\0';
				}

				// ③ 发布真句柄。
				InterlockedExchangePointer(
					reinterpret_cast<PVOID volatile*>(&Slots[i].Handle), handle);
				InterlockedIncrement(&Count);
				return true;
			}

			return false;
		}

		//
		// 覆盖式更新：先擦同值的旧记录，再按 `shouldProtect` 决定要不要记。
		// ⇒ 这就是防句柄复用的**第一道防线**（见文件头）。
		//
		// ★★★ 为什么参数是 `shouldProtect` 而不是"记/不记"两个函数：
		//   调用点只有一个动作 —— "open 成功了，这个句柄该不该受保护"。
		//   拆成 `Forget()` + `Mark()` 两步让调用方自己拼，**一定会有人
		//   只调 Mark**（忘了先擦）或者**先判后擦**（不受保护就直接返回，
		//   把旧记录留在那儿）—— 后者正是"句柄值复用时误清无关文件"
		//   这条最贵 bug 的入口。
		//   v133 第一版这里叫 `MarkAfterForget`（先擦再**无条件**记），
		//   探针立刻抓出来了：不受保护的复用句柄也被记了进去（D3/D4 失败）。
		//   ⇒ 语义必须由这个函数**自己**表达，不能指望调用方拼对。
		//
		// 返回：true = 记下了（或本来就不该记）；false = **表满，没记**。
		//
		// ★ v135：多了 `path` 参数 —— 规则求值要在读的时候按路径匹配，
		//   而读的时候只有句柄。默认 nullptr 是为了**不影响探针**的既有调用
		//   （探针不测规则，只要"记没记"）。
		bool Refresh(HANDLE handle, bool shouldProtect, const WCHAR* path = nullptr) noexcept
		{
			if (!handle)
			{
				return true;
			}

			Forget(handle);

			if (!shouldProtect)
			{
				return true;
			}

			return Mark(handle, path);
		}

		//
		// 查询；命中时顺手把 Reported 置位，并通过 `firstTime` 告诉调用方
		// "这是不是第一次"（用来把"每个句柄报一次"而不是"每次读报一次"）。
		//
		// ★ v135：`pathOut` 非空时顺手把路径抄出去（规则求值要用）。
		//   为什么要抄而不是返回槽内指针：槽会被回收，把指针交出去等于
		//   让调用方拿着一块随时可能被改写的内存。
		//   只有**真配了文件面规则**时调用方才传 pathOut（`HasFace` 预筛），
		//   所以这次 520 字节的拷贝在常见情况下根本不会发生。
		//
		bool Take(HANDLE handle, bool* firstTime,
			WCHAR* pathOut = nullptr, size_t pathCap = 0) noexcept
		{
			if (firstTime)
			{
				*firstTime = false;
			}
			if (!handle)
			{
				return false;
			}

			for (ULONG i = 0; i < MaxHandles; i++)
			{
				if (Slots[i].Handle == handle)
				{
					if (firstTime)
					{
						*firstTime = (InterlockedExchange(&Slots[i].Reported, 1) == 0);
					}
					if (pathOut && pathCap > 0)
					{
						wcsncpy_s(pathOut, pathCap, Slots[i].Path, _TRUNCATE);
					}
					return true;
				}
			}

			return false;
		}

		bool IsTracked(HANDLE handle) const noexcept
		{
			if (!handle)
			{
				return false;
			}
			for (ULONG i = 0; i < MaxHandles; i++)
			{
				if (Slots[i].Handle == handle)
				{
					return true;
				}
			}
			return false;
		}

		ULONG TrackedCount() const noexcept
		{
			return static_cast<ULONG>(Count);
		}
	};

	//
	// 这次读**该清多少字节**。返回 0 = 一个字节都别动。
	//
	// 三种"不该动"的情形，每一种都有独立的理由：
	//   ① `STATUS_PENDING` —— **异步**读：数据要等 I/O 完成才落进缓冲区，
	//      此刻清零毫无作用，而真数据稍后仍会写进去。见下面 `IsAsyncPending`。
	//   ② 失败（status < 0）—— 缓冲区里**没有内容**，无可泄露。
	//   ③ `information == 0` —— 读到 EOF，同样没有内容。
	// 另外把 `information` 钳到 `length`：正常不会超，但这是**别人的**
	// 内核返回值，一旦超了而照抄，`memset` 就会写越界（在别人进程里）。
	//
	inline ULONG BytesToZero(long status, ULONG length, ULONG_PTR information) noexcept
	{
		if (status == StatusPending)
		{
			return 0;
		}
		if (status < 0)
		{
			return 0;
		}
		if (information == 0)
		{
			return 0;
		}

		return (information > length) ? length : static_cast<ULONG>(information);
	}

	//
	// 是不是"异步已提交"（调用方**不能**把它当成失败来拒绝）。
	//
	// ★★ 为什么要把这一条单独暴露出来：`STATUS_PENDING` 在 NTSTATUS 里
	//   是 `>= 0`（"成功"类），所以"成功就替换"的写法会把它当成成功，
	//   然后**清一块还没被写入的缓冲区** —— 看起来什么都没发生，
	//   真数据随后落进来。而"干脆把调用拒掉"更糟：I/O 已经提交给内核，
	//   调用方拿到失败后可能立刻释放/复用缓冲区，内核随后往里写
	//   ⇒ **目标进程内存损坏**。所以这里唯一安全的动作是
	//   **放行 + 如实记录"本次没替换"**（铁律 97）。
	//
	inline bool IsAsyncPending(long status) noexcept
	{
		return status == StatusPending;
	}

	//
	// 真去清零。返回 false = 缓冲区不可写（调用方传了只读内存），
	// 一个字节都没动 ⇒ 调用方**不得**上报 `Spoofed`（铁律 97）。
	//
	inline bool ZeroBuffer(void* buffer, ULONG bytes) noexcept
	{
		if (!buffer || bytes == 0)
		{
			return false;
		}

		__try
		{
			memset(buffer, 0, bytes);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}

		return true;
	}

	//
	// 按某个字节值填充（`替换为 全FF` / `全41` …）。返回 false = 缓冲区不可写。
	//
	inline bool FillBuffer(void* buffer, ULONG bytes, BYTE value) noexcept
	{
		if (!buffer || bytes == 0)
		{
			return false;
		}

		__try
		{
			memset(buffer, value, bytes);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}

		return true;
	}

	//
	// 假文本转 UTF-8。返回字节数；0 = 空文本 / 转不出来。
	//
	// ★ 为什么用 UTF-8 而不是 UTF-16：被替换的绝大多数是文本文件
	//   （日志 / 配置 / 密钥 / 源码），它们几乎都是 UTF-8（或纯 ASCII）。
	//   按 UTF-16 塞进去，在 UTF-8 视角下就是一堆夹着 0x00 的乱码，
	//   反而更像"文件损坏"而不像"内容被换了"。
	//
	// ★ 为什么要限制长度：这个函数在**被注入进程**的读路径上跑，
	//   不能为了转换而做大块分配（也不该在 hook 里 new/delete）。
	//   超长就截断 —— 截断的后果只是"假内容短一点"，不影响正确性。
	//
	constexpr int MaxFakeTextBytes = 1024;

	inline int TextToUtf8(const WCHAR* text, BYTE* out, int cap) noexcept
	{
		if (!text || !text[0] || !out || cap <= 0)
		{
			return 0;
		}

		const int srcLen = static_cast<int>(wcslen(text));
		int chars = srcLen;
		int need = WideCharToMultiByte(CP_UTF8, 0, text, chars, nullptr, 0, nullptr, nullptr);
		if (need <= 0)
		{
			return 0;
		}

		// 超长 ⇒ 按**字符边界**往前退（截在多字节字符中间会留下非法序列：
		// 不会越界，但没必要主动制造乱码）。
		while (need > cap && chars > 0)
		{
			--chars;
			need = WideCharToMultiByte(CP_UTF8, 0, text, chars, nullptr, 0, nullptr, nullptr);
			if (need <= 0)
			{
				return 0;
			}
		}
		if (chars <= 0 || need <= 0)
		{
			return 0;
		}

		// ★★★ 必须传**显式源长度**（`chars`），不能传 -1：
		//   传 -1 表示"源串以 NUL 结尾"，函数会把结尾 NUL 也算进需求字节数，
		//   于是 `cbMultiByte` 少一格就返回 0（ERROR_INSUFFICIENT_BUFFER）
		//   ⇒ 本函数静默返回 0 ⇒ 调用方回落到"全零" ⇒
		//   用户配了 `替换为 "假内容"`，实际看到的是空文件。
		//   第一次实现就栽在这里（v135 单测抓出来的：内容全是 0x00）。
		const int wrote = WideCharToMultiByte(CP_UTF8, 0, text, chars,
			reinterpret_cast<char*>(out), need, nullptr, nullptr);
		return (wrote > 0) ? wrote : 0;
	}

	//
	// 用假文本**平铺**填充一段读缓冲区。
	//
	// ★★★ 为什么是"平铺"而不是"文本 + 零填充"：
	//   文件是**按偏移分块读**的。调用方可能先读 4KB、再读下一个 4KB，
	//   还可能 `SetFilePointer` 跳到中间读。如果假流是"文本 + 一堆 0"，
	//   那么从第 2 块开始读到的就全是 0 —— 看起来像"文件被截断/损坏"，
	//   而且"第几块开始变 0"取决于假文本长度，用户完全无法预期。
	//   平铺（`假流[i] = 文本[i % 长度]`）的好处是**任意偏移都有内容**，
	//   且长度与原文件**完全一致**（我们只覆盖本次读到的那些字节），
	//   ⇒ 调用方的偏移计算、`ftell`、`fgets` 切行全都不会错位。
	//
	// ★ 偏移拿不到时（`ByteOffset == NULL` 的同步句柄）按 0 算：
	//   这样假流"每块都从头开始"。因为平铺本身就在重复，视觉上差别很小，
	//   而代价是**零**（不需要为每次读多打一次
	//   `NtQueryInformationFile(FilePositionInformation)` ——
	//   那是给整机最热的读路径再加一次系统调用）。
	//   ⚠️ 如实记录这个取舍：同一次读，用 `ReadFile`（offset=NULL）和
	//   用 `ReadFile` 带 OVERLAPPED（offset 非 NULL）拿到的假内容**可能不同**，
	//   但两者都是假的，都不会泄露真实字节。
	//
	inline bool FillWithText(void* buffer, ULONG bytes, long long offset,
		const WCHAR* text) noexcept
	{
		if (!buffer || bytes == 0)
		{
			return false;
		}

		BYTE utf8[MaxFakeTextBytes];
		const int n = TextToUtf8(text, utf8, MaxFakeTextBytes);
		if (n <= 0)
		{
			// 空文本 ⇒ 等价于"替换为空" ⇒ 全零。**不返回 false**：
			// 返回 false 会让调用方以为"没替换成"，从而上报真实内容已泄露
			// （铁律 97：口径必须与实际一致）。
			return FillBuffer(buffer, bytes, 0);
		}

		__try
		{
			BYTE* out = static_cast<BYTE*>(buffer);
			long long k = offset;
			if (k < 0)
			{
				k = 0;
			}
			for (ULONG i = 0; i < bytes; i++)
			{
				out[i] = utf8[k % n];
				++k;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}

		return true;
	}
}
