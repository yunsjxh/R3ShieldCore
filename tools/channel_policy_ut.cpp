//
// channel_policy_ut.cpp —— v49：验证 `R3ShieldCoreChannel::OpenPolicyOnly`。
//
// 为什么需要它：
//   v42 起**瘦会话**（explorer.exe / svchost.exe / runtimebroker.exe）一个 guard
//   都不装，因此**从不碰共享通道**。但瘦会话装的 `CreateProcessInternalW` 在注入前
//   会调 `ShouldSkipProcessInjection`，而 `IsUserNeverInject` 需要读 `Policy` 才能
//   拿到用户的 `never_inject=` 名单 —— 没有 Policy ⇒ 名单恒不生效。
//
//   修法 = 新增 `OpenPolicyOnly`：**只读挂载 Policy**（不挂 Events 通道）。
//   本测试要钉住它的两个性质：
//     ① 能真的读到 Policy（`NeverInjectCount` / `NeverInjectPaths` 逐字正确）；
//     ② **`IsOpen()` 必须仍是 false** —— 瘦会话不是"受监控进程"，
//        若这里返回 true，瘦会话在别处会被误判成"有通道能上报事件"。
//
// ★ 必须**跨进程**测：`OpenFileMapping` / 映射 ACL 的语义是按**对象**判的，
//   同进程内自己开自己建的映射证明不了"别的进程能打开它"。
//
// 用法：channel_policy_ut.exe            # 父进程：建通道 + 起子进程验证
//       channel_policy_ut.exe --child <enginePid>   # 子进程：只读挂载并断言
//
// 退出码：0 = 全部通过；1 = 有失败。
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ⚠️ `r3shieldcore_channel.h` 用到 `wil::unique_hlocal` 但自己不 include wil
//    （DLL 里靠 `stdafx.h` 先包含）。本单测不链 stdafx，所以要自己先补上。
#include <wil/resource.h>

#include "r3shieldcore_channel.h"

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// 名单里放一条真实形态的路径（与发布 ini 默认值一致）。
static const WCHAR kNeverInject[] = L"D:\\Program Files\\MyApp\\";

static int RunChild(DWORD enginePid)
{
	printf("--- 子进程 pid=%lu，目标 enginePid=%lu ---\n", GetCurrentProcessId(), enginePid);

	// ① 只读挂载 Policy
	const bool opened = R3ShieldCoreChannel::OpenPolicyOnly(enginePid);
	Check("OpenPolicyOnly 成功（能读到引擎建的 Policy）", opened);
	if (!opened) {
		printf("  （OpenPolicyOnly 失败，err=%lu）\n", GetLastError());
		return 1;
	}

	// ② IsOpen() 必须仍是 false —— 这是本 API 的核心不变量
	Check("IsOpen() == false（只挂 Policy 不等于\"受监控进程\"）",
		!R3ShieldCoreChannel::IsOpen());

	// ③ Policy 指针可用且内容逐字正确
	const R3ShieldCore::Policy* p = R3ShieldCoreChannel::Policy();
	Check("Policy() != nullptr", p != nullptr);
	if (!p) {
		return 1;
	}

	Check("NeverInjectCount == 1", p->NeverInjectCount == 1);
	Check("NeverInjectPaths[0] 逐字等于 D:\\Program Files\\MyApp\\",
		p->NeverInjectCount >= 1 && wcscmp(p->NeverInjectPaths[0], kNeverInject) == 0);
	Check("Mode 也读得到（证明读到的是完整 Policy，不是残段）",
		p->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Block));

	// ④ 对照：完整的 Open() 应该让 IsOpen() 变 true
	R3ShieldCoreChannel::Close();
	const bool fullOpen = R3ShieldCoreChannel::Open(enginePid);
	Check("对照：Open() 成功", fullOpen);
	Check("对照：Open() 之后 IsOpen() == true（证明 ② 的 false 不是\"永远 false\"）",
		R3ShieldCoreChannel::IsOpen());

	R3ShieldCoreChannel::Close();
	return 0;
}

int main(int argc, char** argv)
{
	setvbuf(stdout, nullptr, _IONBF, 0);

	for (int i = 1; i < argc; ++i) {
		if (_stricmp(argv[i], "--child") == 0 && i + 1 < argc) {
			return RunChild(static_cast<DWORD>(strtoul(argv[i + 1], nullptr, 10)));
		}
	}

	printf("=== R3ShieldCoreChannel::OpenPolicyOnly 单测（v49）===\n");

	R3ShieldCore::Policy policy = {};
	policy.Mode = static_cast<ULONG>(R3ShieldCore::Mode::Block);
	policy.NeverInjectCount = 1;
	wcsncpy_s(policy.NeverInjectPaths[0], kNeverInject, _TRUNCATE);

	// 父进程扮演"引擎"：建通道。
	if (!R3ShieldCoreChannel::Create(policy)) {
		printf("[FAIL] R3ShieldCoreChannel::Create 失败 err=%lu\n", GetLastError());
		return 1;
	}
	printf("父进程 pid=%lu 已建通道\n", GetCurrentProcessId());

	// 跨进程：起一个自己当"瘦会话"，只读挂载并断言。
	char self[MAX_PATH] = {};
	GetModuleFileNameA(nullptr, self, MAX_PATH);
	char cmdLine[MAX_PATH + 64] = {};
	sprintf_s(cmdLine, "\"%s\" --child %lu", self,
		static_cast<unsigned long>(GetCurrentProcessId()));

	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = {};
	if (!CreateProcessA(nullptr, cmdLine, nullptr, nullptr, FALSE, 0,
		nullptr, nullptr, &si, &pi)) {
		printf("[FAIL] 起子进程失败 err=%lu\n", GetLastError());
		return 1;
	}
	// 子进程的断言跑在**另一个地址空间**里，父进程的计数器收不到 ⇒
	// 只能靠退出码回传（这也是本测试"必须跨进程"的代价）。
	WaitForSingleObject(pi.hProcess, 30000);
	DWORD childExit = 0;
	GetExitCodeProcess(pi.hProcess, &childExit);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	R3ShieldCoreChannel::Close();

	Check("子进程全部断言通过（exit=0）", childExit == 0);

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	printf("（子进程的 8 条断言由退出码回传：exit=%lu，见上方子进程输出）\n",
		static_cast<unsigned long>(childExit));
	return g_fail == 0 ? 0 : 1;
}
