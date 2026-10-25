//
// spoof_file_probe.cpp —— 「文件读替换」的机制探针（v133）。
//
// ======================================================================
// 它回答什么问题
// ======================================================================
// 在**真 Windows** 上，把 `NtReadFile` 挂上 detour、在真调成功之后
// 把回传缓冲区清零，调用方（`ReadFile`）拿到的到底是：
//   · 全 0 但**长度不变**的数据（替换生效），还是
//   · 真数据（替换没生效）？
// 顺带把三个**容易做错**的点逐个证出来：
//   ① **不能多清**：只清"真读到的字节数"（`IoStatusBlock->Information`），
//      缓冲区尾巴上的东西一个字节都不许动（调用方可能正用着）；
//   ② **不能改文件**：我们只改**回传的副本**，磁盘上的文件必须原样
//      （否则就是"删除数据"，不是"替换"）；
//   ③ **句柄复用**：受保护文件关掉后，同一个句柄值被**无关文件**复用时，
//      必须**不再**替换 —— 否则就是静默数据损坏。
//
// ======================================================================
// ★ 为什么这个探针不需要引擎、也不违反「不得运行引擎」那条铁律
// ======================================================================
// 它**自己挂自己的 hook**（MinHook 装在**本进程**的 ntdll 上），
// 不注入任何别的进程、不读共享内存、不经过引擎 -> 铁律 175 的豁免。
// 它只碰自己在 `%TEMP%` 下建的两个小文件。
//
// ★★ 替换逻辑**不在这里重写** —— `#include "file_spoof_codec.h"`，
//    与生产 `file_guard.cpp` 用**同一份**（铁律 127）。
//    本探针只负责"搭台子"：建文件、挂 hook、发请求、看结果。
//

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "MinHook.h"
#include "file_spoof_codec.h"

namespace
{
	int g_pass = 0;
	int g_fail = 0;

	void Check(const char* name, bool ok)
	{
		printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
		if (ok) {
			g_pass++;
		}
		else {
			g_fail++;
		}
	}

	void Info(const char* fmt, ...)
	{
		va_list ap;
		va_start(ap, fmt);
		vprintf(fmt, ap);
		va_end(ap);
		printf("\n");
	}

	// ------------------------------------------------------------------
	// 本地 NT 原型（不 include winternl.h：会和 ntsecapi.h 的 SubAuth.h 撞）
	// ------------------------------------------------------------------
	struct IO_STATUS_BLOCK_LOCAL
	{
		union
		{
			long Status;
			void* Pointer;
		};
		ULONG_PTR Information;
	};

	typedef long(NTAPI* NtReadFilePtr)(HANDLE, HANDLE, void*, void*, IO_STATUS_BLOCK_LOCAL*,
		void*, ULONG, LARGE_INTEGER*, ULONG*);

	NtReadFilePtr g_originalNtReadFile = nullptr;

	// 与生产**同一份**句柄表实现。
	R3ShieldCoreFileSpoof::HandleTable g_table = {};

	// 探针的统计（用来证明"确实进过替换分支"）。
	volatile LONG g_spoofedReads = 0;
	volatile LONG g_trackedReads = 0;

	long NTAPI NtReadFile_Detour(HANDLE FileHandle, HANDLE Event, void* ApcRoutine,
		void* ApcContext, IO_STATUS_BLOCK_LOCAL* IoStatusBlock, void* Buffer,
		ULONG Length, LARGE_INTEGER* ByteOffset, ULONG* Key)
	{
		bool firstTime = false;
		const bool tracked = g_table.Take(FileHandle, &firstTime);

		const long status = g_originalNtReadFile(FileHandle, Event, ApcRoutine, ApcContext,
			IoStatusBlock, Buffer, Length, ByteOffset, Key);

		if (tracked) {
			InterlockedIncrement(&g_trackedReads);

			const ULONG_PTR information = IoStatusBlock ? IoStatusBlock->Information : 0;
			const ULONG bytes = R3ShieldCoreFileSpoof::BytesToZero(status, Length, information);

			if (bytes > 0 && R3ShieldCoreFileSpoof::ZeroBuffer(Buffer, bytes)) {
				InterlockedIncrement(&g_spoofedReads);
			}
		}

		return status;
	}

	// ------------------------------------------------------------------
	// 文件小工具
	// ------------------------------------------------------------------
	HANDLE CreateTempFile(const WCHAR* path, const char* content)
	{
		HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return INVALID_HANDLE_VALUE;
		}

		DWORD written = 0;
		if (!WriteFile(file, content, static_cast<DWORD>(strlen(content)), &written, nullptr)) {
			CloseHandle(file);
			return INVALID_HANDLE_VALUE;
		}

		// 关掉重开，让后续读走一次干净的 open（句柄值也更可预测）。
		CloseHandle(file);

		return CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	bool ReadAllBytes(HANDLE file, unsigned char* buffer, DWORD capacity, DWORD* readOut)
	{
		SetFilePointer(file, 0, nullptr, FILE_BEGIN);
		DWORD read = 0;
		if (!ReadFile(file, buffer, capacity, &read, nullptr)) {
			return false;
		}
		if (readOut) {
			*readOut = read;
		}
		return true;
	}

	bool AllZero(const unsigned char* data, DWORD count)
	{
		for (DWORD i = 0; i < count; i++) {
			if (data[i] != 0) {
				return false;
			}
		}
		return true;
	}

	bool FileContains(HANDLE file, const char* expected)
	{
		char buffer[512] = {};
		DWORD read = 0;
		if (!ReadAllBytes(file, reinterpret_cast<unsigned char*>(buffer), sizeof(buffer) - 1, &read)) {
			return false;
		}
		buffer[read] = '\0';
		return strcmp(buffer, expected) == 0;
	}
}

int main()
{
	printf("=== 文件读替换探针（spoof_file, v133）===\n");
	printf("说明：自己挂自己的 NtReadFile detour，不注入、不经过引擎\n\n");

	// ------------------------------------------------------------------
	printf("--- A. codec 的纯判定（不碰文件）---\n");
	{
		// 成功 + 读了 100 字节 + 缓冲区 4096 -> 清 100
		Check("A1 成功且 information < length -> 清 information 字节",
			R3ShieldCoreFileSpoof::BytesToZero(0, 4096, 100) == 100);

		// information > length（异常返回值）-> 钳到 length，绝不越界写
		Check("A2 information > length -> 钳到 length（不越界）",
			R3ShieldCoreFileSpoof::BytesToZero(0, 100, 4096) == 100);

		// EOF
		Check("A3 information == 0（EOF）-> 不清",
			R3ShieldCoreFileSpoof::BytesToZero(0, 4096, 0) == 0);

		// 失败
		Check("A4 失败（status < 0）-> 不清",
			R3ShieldCoreFileSpoof::BytesToZero(static_cast<long>(0xC000000FL), 4096, 100) == 0);

		// ★ 异步：STATUS_PENDING 是 ">= 0" 的成功类，最容易误判
		Check("A5 STATUS_PENDING -> 不清（异步，数据还没落进缓冲区）",
			R3ShieldCoreFileSpoof::BytesToZero(R3ShieldCoreFileSpoof::StatusPending, 4096, 100) == 0);
		Check("A6 STATUS_PENDING 被单独识别出来（供调用方如实上报）",
			R3ShieldCoreFileSpoof::IsAsyncPending(R3ShieldCoreFileSpoof::StatusPending)
			&& !R3ShieldCoreFileSpoof::IsAsyncPending(0));

		// 缓冲区不可写：如实返回 false
		Check("A7 缓冲区为空指针 -> 不清并返回 false",
			!R3ShieldCoreFileSpoof::ZeroBuffer(nullptr, 10));
	}

	// ------------------------------------------------------------------
	printf("\n--- B. 句柄表的复用防护（这是本面最大的正确性风险）---\n");
	{
		HANDLE fake = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x1234));
		g_table.Mark(fake);
		Check("B1 标记后能查到", g_table.IsTracked(fake));

		bool first = false;
		Check("B2 第一次 Take 报告 firstTime=true", g_table.Take(fake, &first) && first);
		Check("B3 第二次 Take 报告 firstTime=false（每句柄只报一次）",
			g_table.Take(fake, &first) && !first);

		g_table.Forget(fake);
		Check("B4 Forget 之后查不到", !g_table.IsTracked(fake));

		// 覆盖式更新：先记，再用同一个值 Refresh(protect=true)，仍只有一条
		g_table.Mark(fake);
		const ULONG before = g_table.TrackedCount();
		g_table.Refresh(fake, true);
		Check("B5 Refresh(protect=true) 不产生重复记录（条数不增）",
			g_table.TrackedCount() == before && g_table.IsTracked(fake));
		Check("B5b Refresh(protect=false) 会把记录擦掉（不受保护 ⇒ 不跟踪）",
			(g_table.Refresh(fake, false), !g_table.IsTracked(fake)));

		// 表满：fail-open（返回 false），而不是死循环或覆盖别人的记录
		R3ShieldCoreFileSpoof::HandleTable tinyTable = {};
		ULONG marked = 0;
		for (ULONG i = 0; i < R3ShieldCoreFileSpoof::MaxHandles + 10; i++) {
			if (tinyTable.Mark(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x1000 + i * 4)))) {
				marked++;
			}
		}
		Check("B6 表满时 Mark 返回 false（fail-open，不是覆盖别人的记录）",
			marked == R3ShieldCoreFileSpoof::MaxHandles);

		g_table.Forget(fake);
	}

	// ------------------------------------------------------------------
	printf("\n--- C. 真文件：受保护 vs 不受保护 ---\n");

	WCHAR tempDir[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, tempDir);

	WCHAR secretPath[MAX_PATH] = {};
	WCHAR plainPath[MAX_PATH] = {};
	swprintf_s(secretPath, L"%sr3sc_spoof_secret.txt", tempDir);
	swprintf_s(plainPath, L"%sr3sc_spoof_plain.txt", tempDir);

	const char* kSecret = "REAL-SECRET-PAYLOAD-0123456789";
	const char* kPlain = "PLAIN-CONTENT-abcdefghij";

	HANDLE secretFile = CreateTempFile(secretPath, kSecret);
	HANDLE plainFile = CreateTempFile(plainPath, kPlain);

	if (secretFile == INVALID_HANDLE_VALUE || plainFile == INVALID_HANDLE_VALUE) {
		printf("  [FAIL] 建临时文件失败（err=%lu）\n", GetLastError());
		return 1;
	}

	Check("C0 两个临时文件都建好了", true);

	// 挂 detour
	if (MH_Initialize() != MH_OK) {
		printf("  [FAIL] MinHook 初始化失败\n");
		return 1;
	}
	void* target = reinterpret_cast<void*>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadFile"));
	if (!target) {
		printf("  [FAIL] 找不到 NtReadFile\n");
		return 1;
	}
	if (MH_CreateHook(target, reinterpret_cast<void*>(&NtReadFile_Detour),
			reinterpret_cast<void**>(&g_originalNtReadFile)) != MH_OK
		|| MH_EnableHook(target) != MH_OK) {
		printf("  [FAIL] 挂 NtReadFile 失败\n");
		return 1;
	}
	Check("C1 NtReadFile detour 已挂上", true);

	// 模拟生产侧 open 钩子做的事：把受保护文件那个句柄记进表
	g_table.Refresh(secretFile, true);

	// ---- 受保护文件：应拿到全 0 ----
	{
		unsigned char buffer[512];
		// 先铺满哨兵，用来验证"只清真读到的那些字节"
		memset(buffer, 0xAB, sizeof(buffer));

		DWORD read = 0;
		const bool ok = ReadAllBytes(secretFile, buffer, sizeof(buffer), &read);
		const DWORD expected = static_cast<DWORD>(strlen(kSecret));

		Check("C2 受保护文件的读**成功**返回（不是拒绝）", ok);
		Check("C3 读到的字节数 == 文件长度（长度没变）", read == expected);
		Check("C4 回传内容全是 0（替换生效）", AllZero(buffer, read));
		Check("C5 缓冲区**尾巴**没被动过（只清真读到的字节）",
			buffer[read] == 0xAB && buffer[sizeof(buffer) - 1] == 0xAB);
		Check("C6 detour 确实进过替换分支", g_spoofedReads > 0);
	}

	// ---- 磁盘上的文件必须原样（我们只改副本）----
	{
		// 用**另一个**句柄读（不受表管辖），确认磁盘内容没变
		HANDLE fresh = CreateFileW(secretPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		Check("C7 另开句柄能打开同一个文件", fresh != INVALID_HANDLE_VALUE);
		if (fresh != INVALID_HANDLE_VALUE) {
			Check("C8 磁盘上的文件内容**原样未变**（只替换回传，不改文件）",
				FileContains(fresh, kSecret));
			CloseHandle(fresh);
		}
	}

	// ---- 不受保护文件：必须拿到真内容（负对照）----
	{
		unsigned char buffer[512];
		DWORD read = 0;
		const bool ok = ReadAllBytes(plainFile, buffer, sizeof(buffer), &read);
		buffer[read < sizeof(buffer) ? read : sizeof(buffer) - 1] = '\0';

		Check("C9 不受保护文件的读成功", ok);
		Check("C10 不受保护文件读到的是**真内容**（负对照，证明不是无差别清零）",
			strcmp(reinterpret_cast<char*>(buffer), kPlain) == 0);
	}

	// ---- 同一进程里再读一次受保护文件，内容仍是 0 ----
	{
		unsigned char buffer[512];
		DWORD read = 0;
		ReadAllBytes(secretFile, buffer, sizeof(buffer), &read);
		Check("C11 同一个句柄第二次读仍被替换（不是只生效一次）",
			read > 0 && AllZero(buffer, read));
	}

	// ------------------------------------------------------------------
	printf("\n--- D. 句柄值复用：关掉受保护文件后，同值句柄不能再被替换 ---\n");
	{
		const ULONG_PTR secretValue = reinterpret_cast<ULONG_PTR>(secretFile);
		CloseHandle(secretFile);

		// 关掉后表里必须已经没有它（生产侧由 NtClose 钩子做）
		g_table.Forget(reinterpret_cast<HANDLE>(secretValue));
		Check("D1 关掉并 Forget 之后，该句柄值不再被跟踪",
			!g_table.IsTracked(reinterpret_cast<HANDLE>(secretValue)));

		// 反复打开，直到拿到**同一个句柄值**（Windows 通常立刻复用最小槽位）
		HANDLE reused = INVALID_HANDLE_VALUE;
		for (int i = 0; i < 64; i++) {
			HANDLE h = CreateFileW(plainPath, GENERIC_READ, FILE_SHARE_READ, nullptr,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (h == INVALID_HANDLE_VALUE) {
				break;
			}
			if (reinterpret_cast<ULONG_PTR>(h) == secretValue) {
				reused = h;
				break;
			}
			CloseHandle(h);
		}

		if (reused == INVALID_HANDLE_VALUE) {
			printf("  [skip] D2 系统没有复用同一个句柄值（本次无法构造该场景，不算失败）\n");
		}
		else {
			Check("D2 确实拿到了与受保护文件相同的句柄值（场景构造成功）", true);

			// 关键：此时**如果**不擦，就会误伤这个无关文件。
			// 生产侧在 open 钩子里调 Refresh(handle, shouldProtect)，
			// 这个无关文件 shouldProtect=false ⇒ 既擦掉旧记录、也不新记。
			g_table.Refresh(reused, false);

			Check("D3 open 时先擦再判 -> 同值的无关文件**不被跟踪**",
				!g_table.IsTracked(reused));

			unsigned char buffer[512];
			DWORD read = 0;
			ReadAllBytes(reused, buffer, sizeof(buffer), &read);
			buffer[read < sizeof(buffer) ? read : sizeof(buffer) - 1] = '\0';

			Check("D4 同值句柄读到的是**真内容**（没有被误清 —— 这是本面最贵的 bug）",
				strcmp(reinterpret_cast<char*>(buffer), kPlain) == 0);

			CloseHandle(reused);
		}
	}

	// ------------------------------------------------------------------
	// 收尾
	MH_DisableHook(target);
	MH_Uninitialize();

	DeleteFileW(secretPath);
	DeleteFileW(plainPath);

	printf("\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	printf("结论：\n");
	printf("  受保护文件的读**成功返回**、长度不变、内容全 0、磁盘文件原样；\n");
	printf("  不受保护文件读到真内容；句柄值被复用时不会误清无关读。\n");
	return g_fail == 0 ? 0 : 1;
}
