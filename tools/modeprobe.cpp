//
// 模式切换探针：证明"运行期切模式"对**已经在跑的**被注入进程立刻生效。
//
// 为什么需要它：只用"切完模式再起一个探针"验证是不够的 —— 新进程是切换后
// 才被注入的，它拿到新 Policy 是理所当然的。真正要证明的是：
// 引擎**不重新注入**任何进程，存量进程的下一次判定就用新模式。
//
// 做法：本进程一直跑，每 400ms 尝试写一次注册表键，把返回码打出来。
// 引擎在旁边点按钮切模式，就能看到同一进程的输出从 0 变成 5（或反过来）。
//
//   HKCU\Software\R3ShieldCoreModeProbe   —— 普通键，不在高危规则表里，
//   所以判定完全由 mode 决定（LOG=放行，BLOCK/ASK/BLOCK_ALL=拒绝）。
//
// 用法：
//   modeprobe           跑 15 秒
//   modeprobe 30        跑 30 秒
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>

namespace
{
	constexpr PCWSTR ProbeKeyPath = L"Software\\R3ShieldCoreModeProbe";

	// 返回码 -> 人话。
	//
	// ⚠️ 这里拿到的是 **Win32 码**，不是 NTSTATUS：RegCreateKeyExW 会把
	//    NtCreateKey 返回的 0xC0000022 映射成 ERROR_ACCESS_DENIED(5)。
	//    所以判断"被 R3ShieldCore 拦了"要看 5，不是 0xC0000022
	//    （同一个坑在 regtest 里也踩过 —— 见 HANDOVER §8）。
	//    HKCU\Software\ 下普通进程本来一定有写权限，所以这里出现 5
	//    只可能是被拦。
	const char* VerdictText(LONG status)
	{
		if (status == 0) {
			return "放行";
		}
		if (status == ERROR_ACCESS_DENIED) {
			return "被拦（ACCESS_DENIED）";
		}
		return "其它错误";
	}
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, "");

	int seconds = 15;
	if (argc > 1) {
		seconds = _wtoi(argv[1]);
		if (seconds <= 0) {
			seconds = 15;
		}
	}

	wprintf(L"R3ShieldCore 模式切换探针 (pid=%lu)  跑 %d 秒，每 400ms 写一次注册表\n",
		GetCurrentProcessId(), seconds);
	wprintf(L"目标键 : HKCU\\%s\n", ProbeKeyPath);
	wprintf(L"注意   : 这个进程**一直不退出**，切模式时它不会重新注入。\n");
	wprintf(L"--------------------------------------------------------------\n");

	ULONG pass = 0;
	ULONG blocked = 0;
	ULONG other = 0;

	for (int i = 1; i <= seconds * 5 / 2; ++i) {
		HKEY key = nullptr;
		LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, ProbeKeyPath, 0, nullptr,
			REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, nullptr, &key, nullptr);

		SYSTEMTIME now = {};
		GetLocalTime(&now);

		if (status == 0) {
			++pass;
			if (key) {
				RegCloseKey(key);
			}
		}
		else if (status == ERROR_ACCESS_DENIED) {
			++blocked;
		}
		else {
			++other;
		}

		wprintf(L"[%02u:%02u:%02u.%03u] #%02d  status=0x%08lX  %S\n",
			now.wHour, now.wMinute, now.wSecond, now.wMilliseconds,
			i, static_cast<ULONG>(status), VerdictText(status));

		Sleep(400);
	}

	wprintf(L"--------------------------------------------------------------\n");
	wprintf(L"汇总: 放行 %lu 次 / 被拦 %lu 次 / 其它 %lu 次\n", pass, blocked, other);
	return 0;
}
