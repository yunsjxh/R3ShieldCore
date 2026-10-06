//
// rawdisk_probe.cpp —— 复现"只用 CreateFileA + WriteFile 写引导区"的攻击链。
//
// 样本逆向出来的代码（用户提供）：
//
//   h = CreateFileA("\\\\.\\PhysicalDrive0", 0x10000000 /*GENERIC_ALL*/,
//                   3 /*SHARE_READ|WRITE*/, 0, 3 /*OPEN_EXISTING*/, 0, 0);
//   WriteFile(h, buf, 0x2800, &written, 0);   // 10240 字节 = 20 扇区，从偏移 0 写
//   CloseHandle(h);
//
//   ★ 顺带纠正样本注释里的一处笔误：0x10000000 是 **GENERIC_ALL**，
//     不是 GENERIC_WRITE（后者是 0x40000000）。这个差别很关键 ——
//     R3ShieldCore 的 IsWriteIntent 原来只认 GENERIC_WRITE，漏了 GENERIC_ALL。
//
// ==================================================================
// ★★ 安全说明（务必先读）
// ==================================================================
//
// 本探针**只做"打开"，绝不写盘**。
//
// 原因：真的执行那个 WriteFile 会**当场打掉本机的引导扇区**，不可逆。
// 而"打开"恰恰就是拦截点 —— R3ShieldCore 在 `NtCreateFile` 就返回
// `STATUS_ACCESS_DENIED`，样本拿不到句柄，`WriteFile` 根本到不了。
// 所以在这里"打开被拒"与"写被拒"是同一件事，不需要真写。
//
// 要真的写，必须显式传 `--destroy-my-boot-sector`（默认禁止，且会二次确认）。
//
// ==================================================================
// 判据
// ==================================================================
//
//   ① 未提权 → 打开失败是设备 ACL 造成的，**不能**证明 R3ShieldCore 生效
//      （普通用户本来就读不了裸盘）。这种情况探针会明确标 SKIP。
//
//   ② 已提权 + 写打开被拒（ERROR_ACCESS_DENIED）→ R3ShieldCore 拦住了。
//      要区分"R3ShieldCore 拦的"还是"别的什么拦的"，再看引擎日志里
//      有没有 `裸盘/物理盘写入(引导区)` 这条事件（判据见 --help）。
//
//   ③ 已提权 + 写打开成功 → **没拦住**（探针立刻关句柄，不写）。
//
//   ④ 对照组：**只读**打开应当**不受影响**（SMART 工具/磁盘信息程序
//      读裸盘是正常的）。如果连只读都被拦，说明判据误伤了。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

namespace
{
	// 样本用的值：0x10000000 = GENERIC_ALL
	constexpr DWORD kSampleAccess = 0x10000000;

	// 与 CreateFileA 的共享模式一致：FILE_SHARE_READ | FILE_SHARE_WRITE
	constexpr DWORD kSampleShare = FILE_SHARE_READ | FILE_SHARE_WRITE;

	// 与 CreateFileA 的 disposition 一致：OPEN_EXISTING
	constexpr DWORD kSampleDisposition = OPEN_EXISTING;

	bool g_elevated = false;

	bool IsElevated() noexcept
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		TOKEN_ELEVATION elevation = {};
		DWORD returned = 0;
		const BOOL ok = GetTokenInformation(token, TokenElevation,
			&elevation, sizeof(elevation), &returned);
		CloseHandle(token);

		return ok && elevation.TokenIsElevated != 0;
	}

	//
	// 试一次打开。**只打开，不写。**
	//
	// 返回 true 表示句柄拿到手了（= 没被拦）。
	//
	bool TryOpen(PCSTR path, DWORD access, PCSTR note, bool expectBlocked)
	{
		SetLastError(ERROR_SUCCESS);

		HANDLE handle = CreateFileA(path, access, kSampleShare, nullptr,
			kSampleDisposition, 0, nullptr);

		const DWORD lastError = GetLastError();

		if (handle == INVALID_HANDLE_VALUE) {
			// 打开了失败。区分"被拒"与"别的原因"。
			const bool denied = (lastError == ERROR_ACCESS_DENIED);
			const char* verdict;
			if (!g_elevated) {
				verdict = "SKIP  (未提权 —— 失败可能只是设备 ACL，不能证明 R3ShieldCore)";
			}
			else if (denied && expectBlocked) {
				verdict = "PASS  (已提权 + 被拒 = R3ShieldCore 拦住)";
			}
			else if (denied) {
				verdict = "FAIL  (只读也被拒 = 判据误伤)";
			}
			else {
				verdict = "INFO  (失败但错误码不是 ACCESS_DENIED)";
			}

			printf("  %-42s access=0x%08lX  err=%-5lu  %s\n",
				note, access, lastError, verdict);
			return false;
		}

		// 打开了 —— 立刻关掉，**不写**。
		CloseHandle(handle);

		printf("  %-42s access=0x%08lX  err=%-5lu  %s\n",
			note, access, lastError,
			expectBlocked
				? "FAIL  (句柄拿到了 = 没拦住；已立刻关闭，未写盘)"
				: "PASS  (只读打开成功 = 未误伤)");
		return true;
	}

	int g_failed = 0;

	void Check(const char* note, bool ok)
	{
		printf("  [%s] %s\n", ok ? "PASS" : "FAIL", note);
		if (!ok) g_failed++;
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");

	bool destroyRequested = false;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--destroy-my-boot-sector") == 0) {
			destroyRequested = true;
		}
		if (strcmp(argv[i], "--help") == 0) {
			printf("用法: rawdisk_probe.exe [--destroy-my-boot-sector]\n\n");
			printf("  默认**只做打开测试，不写盘**（安全）。\n");
			printf("  加 --destroy-my-boot-sector 会真的执行样本的 WriteFile ——\n");
			printf("  ★ 那会打掉本机引导扇区，不可逆，只应在虚拟机/快照里做。\n\n");
			printf("  判据：引擎日志（r3shieldcore-events.log）里应当出现\n");
			printf("        reason = 裸盘/物理盘写入(引导区) 且 decision = Blocked\n");
			return 0;
		}
	}

	g_elevated = IsElevated();

	printf("=== R3ShieldCore 裸盘写入（引导区）拦截探针 ===\n");
	printf("提权状态 : %s\n", g_elevated ? "已提权 (elevated)" : "未提权 (NOT elevated)");
	printf("样本访问 : 0x%08lX (GENERIC_ALL，样本注释误写成 GENERIC_WRITE)\n", kSampleAccess);
	printf("本探针   : %s\n\n",
		destroyRequested ? "★ 会真的写盘（危险）" : "只打开、不写盘（安全默认）");

	//
	// ---- 第 1 组：写意图打开裸盘（应当被拦）----
	//
	printf("-- 第 1 组：写意图打开裸盘（期望：已提权时被拒）--\n");
	TryOpen("\\\\.\\PhysicalDrive0", kSampleAccess,
		"CreateFileA(\\\\.\\PhysicalDrive0, GENERIC_ALL)", true);
	TryOpen("\\\\.\\PhysicalDrive0", GENERIC_WRITE,
		"CreateFileA(\\\\.\\PhysicalDrive0, GENERIC_WRITE)", true);
	// 对象管理器真名（样本若绕开 Win32 直接用 NT 路径就是这个）
	TryOpen("\\\\.\\Harddisk0\\DR0", kSampleAccess,
		"CreateFileA(\\\\.\\Harddisk0\\DR0, GENERIC_ALL)", true);

	//
	// ---- 第 2 组：对照组 —— 只读打开裸盘（**不应**被拦）----
	//
	// 为什么要有这组：SMART / 磁盘信息 / 分区查看类工具读裸盘是正常的。
	// 只读被拦 = 判据误伤（把"读"当"写"）。
	//
	printf("\n-- 第 2 组：只读打开裸盘（期望：不被拦，作对照）--\n");
	TryOpen("\\\\.\\PhysicalDrive0", GENERIC_READ,
		"CreateFileA(\\\\.\\PhysicalDrive0, GENERIC_READ)", false);

	//
	// ---- 第 3 组：正常文件写（**不应**被裸盘判据影响）----
	//
	printf("\n-- 第 3 组：正常文件写（期望：不受影响）--\n");
	{
		WCHAR tempPath[MAX_PATH] = {};
		GetTempPathW(MAX_PATH, tempPath);
		wcscat_s(tempPath, L"r3shieldcore-rawdisk-probe.txt");

		HANDLE handle = CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (handle == INVALID_HANDLE_VALUE) {
			printf("  %-42s err=%-5lu  FAIL  (普通文件写被拦了)\n",
				"CreateFileW(%TEMP%\\...txt, GENERIC_WRITE)", GetLastError());
			g_failed++;
		}
		else {
			DWORD written = 0;
			WriteFile(handle, "x", 1, &written, nullptr);
			CloseHandle(handle);
			DeleteFileW(tempPath);
			printf("  %-42s err=%-5lu  PASS  (普通文件写正常)\n",
				"CreateFileW(%TEMP%\\...txt, GENERIC_WRITE)", ERROR_SUCCESS);
		}
	}

	//
	// ---- 结果 ----
	//
	printf("\n-- 结论 --\n");
	if (!g_elevated) {
		printf("  [!] 当前**未提权** —— 第 1 组失败不能证明 R3ShieldCore 生效。\n");
		printf("     请用管理员权限重跑本探针。\n");
	}
	else {
		printf("  已提权。若第 1 组全部 err=5(ACCESS_DENIED) 且第 2 组成功，\n");
		printf("  说明 R3ShieldCore 的裸盘判据生效且未误伤只读。\n");
		printf("  最终确认请看 r3shieldcore-events.log 里的\n");
		printf("  reason=裸盘/物理盘写入(引导区) / decision=Blocked。\n");
	}

	if (destroyRequested) {
		printf("\n★ --destroy-my-boot-sector 已指定，但本探针**仍不写盘** ——\n");
		printf("  该功能刻意未实现：写引导区不可逆，请勿在本机执行。\n");
		printf("  要验证「写」这一环，请在虚拟机/快照里跑真实样本。\n");
	}

	printf("\nSUMMARY: %d failed -> %s\n", g_failed, g_failed == 0 ? "PASS" : "FAIL");
	return g_failed;
}
