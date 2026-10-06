//
// v14_rules_ut.cpp - R3ShieldCoreRules v14 新增判据的单元测试。
//
// 覆盖两块（v14 补的防护面）：
//   1. 代码注入链  → ProcessOp::WriteMemory / ProtectMemory / AllocateMemory
//   2. 反向输入    → HookOp::SendInputEvents / BlockUserInput / ClipCursorLock
//
// ⚠️ 两块判据各自的「存活关键」：
//
//   代码注入链 —— **本进程一律放行**是唯一不可动的铁律。
//     NtAllocateVirtualMemory / NtWriteVirtualMemory / NtProtectVirtualMemory
//     在每个进程里都被合法高频调用（JIT、堆、GC、加壳）。只要有一条
//     "本进程也算高危"，系统会在几秒内瘫掉 —— 这不是误报，是不可用。
//     本单测把这条钉死（targetPid == selfPid、targetPid == 0 全返正常）。
//
//     跨进程再按「权限位是否齐全」分档：
//       · Write 跨进程即高危（注入链第二步，铁证）
//       · Protect 只有改成**可执行**才是高危（普通改权限很常见）
//       · Allocate 只有 **COMMIT 且可执行** 才是高危（RESERVE / RW 很常见）
//
//   反向输入 —— SendInput 走密度判据（规则层只管"一旦认定即高危"），
//     BlockInput / ClipCursor 走**前台窗口归属**判据：
//     调用方就是前台窗口属主 → 合法（演示工具/游戏/安装器），
//     否则 = 后台干预别人的界面 → 高危（勒索锁屏 / 伪造登录框）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskMemoryOp(ULONG targetPid, ULONG selfPid, ULONG processOp,
		ULONG protect, ULONG allocationType) noexcept;
	const char* MemoryOpRiskReason(ULONG targetPid, ULONG selfPid, ULONG processOp,
		ULONG protect, ULONG allocationType) noexcept;
	bool IsHighRiskInputInjection(ULONG hookOp, bool foregroundOwnedByCaller) noexcept;
	const char* InputInjectionRiskReason(ULONG hookOp, bool foregroundOwnedByCaller) noexcept;
}

// ProcessOp（对齐 r3shieldcore_shared.h）
enum
{
	PROC_Create = 1,
	PROC_Terminate = 2,
	PROC_Open = 3,
	PROC_WriteMemory = 4,
	PROC_ProtectMemory = 5,
	PROC_AllocateMemory = 6,
};

// HookOp —— 反向输入三项（对齐 r3shieldcore_shared.h）
enum
{
	HK_SendInputEvents = 10,
	HK_BlockUserInput = 11,
	HK_ClipCursorLock = 12,
};

static int g_failed = 0;

static void CheckBool(const char* group, const char* note, bool got, bool expect)
{
	const char* mark = (got == expect) ? "OK  " : "FAIL";
	if (got != expect) g_failed++;
	printf("%s  [%s] %-50s expect=%-4s got=%-4s\n", mark, group, note,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm");
}

static void CheckMem(const char* note, ULONG targetPid, ULONG selfPid, ULONG op,
	ULONG protect, ULONG allocType, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskMemoryOp(targetPid, selfPid, op, protect, allocType);
	CheckBool("mem", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::MemoryOpRiskReason(targetPid, selfPid, op, protect, allocType);
		if (reason) printf("        reason=%s\n", reason);
	}
}

static void CheckInput(const char* note, ULONG op, bool fgOwned, bool expect)
{
	const bool got = R3ShieldCoreRules::IsHighRiskInputInjection(op, fgOwned);
	CheckBool("input", note, got, expect);
	if (got) {
		const char* reason = R3ShieldCoreRules::InputInjectionRiskReason(op, fgOwned);
		if (reason) printf("        reason=%s\n", reason);
	}
}

int wmain()
{
	setlocale(LC_ALL, "");

	const ULONG SELF = 1234;   // 当前进程
	const ULONG OTHER = 5678;  // 别的进程

	printf("=== 1. 跨进程内存操作 / 代码注入链（v14 新增）===\n");
	{
		// ---- ★ 存活前提：本进程一律放行（最重要的一组，必须全 norm）----
		CheckMem("本进程 写内存（JIT/堆，必须放行）", SELF, SELF,
			PROC_WriteMemory, PAGE_READWRITE, MEM_COMMIT, false);
		CheckMem("本进程 改页可执行（JIT RWX，必须放行）", SELF, SELF,
			PROC_ProtectMemory, PAGE_EXECUTE_READWRITE, 0, false);
		CheckMem("本进程 申请可执行内存（必须放行）", SELF, SELF,
			PROC_AllocateMemory, PAGE_EXECUTE_READ, MEM_COMMIT, false);
		CheckMem("targetPid=0（取不到目标，放行）", 0, SELF,
			PROC_WriteMemory, PAGE_READWRITE, MEM_COMMIT, false);
		CheckMem("selfPid=0（异常，放行）", OTHER, 0,
			PROC_WriteMemory, PAGE_READWRITE, MEM_COMMIT, false);

		// ---- 跨进程写内存：跨进程即高危（注入链第二步）----
		CheckMem("跨进程 写内存（注入链，RW）", OTHER, SELF,
			PROC_WriteMemory, PAGE_READWRITE, MEM_COMMIT, true);
		CheckMem("跨进程 写内存（只读页也算）", OTHER, SELF,
			PROC_WriteMemory, PAGE_READONLY, 0, true);

		// ---- 跨进程改页权限：只有改成可执行才算 ----
		CheckMem("跨进程 改成 RX（注入链，高危）", OTHER, SELF,
			PROC_ProtectMemory, PAGE_EXECUTE_READ, 0, true);
		CheckMem("跨进程 改成 RWX（注入链，高危）", OTHER, SELF,
			PROC_ProtectMemory, PAGE_EXECUTE_READWRITE, 0, true);
		CheckMem("跨进程 改成 RW（调试器常见，只记录）", OTHER, SELF,
			PROC_ProtectMemory, PAGE_READWRITE, 0, false);
		CheckMem("跨进程 改成只读（只记录）", OTHER, SELF,
			PROC_ProtectMemory, PAGE_READONLY, 0, false);

		// ---- 跨进程申请内存：只有 COMMIT 且可执行才算 ----
		CheckMem("跨进程 COMMIT+RX（注入链起点，高危）", OTHER, SELF,
			PROC_AllocateMemory, PAGE_EXECUTE_READ, MEM_COMMIT, true);
		CheckMem("跨进程 COMMIT+RWX（高危）", OTHER, SELF,
			PROC_AllocateMemory, PAGE_EXECUTE_READWRITE, MEM_COMMIT, true);
		CheckMem("跨进程 仅 RESERVE（不占物理页，只记录）", OTHER, SELF,
			PROC_AllocateMemory, PAGE_EXECUTE_READ, MEM_RESERVE, false);
		CheckMem("跨进程 COMMIT+RW 不可执行（只记录）", OTHER, SELF,
			PROC_AllocateMemory, PAGE_READWRITE, MEM_COMMIT, false);

		// ---- 非内存 Op（Create/Open/Terminate）不属于本判据 ----
		CheckMem("跨进程 Create（不归本判据）", OTHER, SELF,
			PROC_Create, PAGE_READWRITE, MEM_COMMIT, false);
		CheckMem("跨进程 Open（不归本判据）", OTHER, SELF,
			PROC_Open, PAGE_READWRITE, MEM_COMMIT, false);
		CheckMem("op=0（未设置）", OTHER, SELF, 0, PAGE_READWRITE, MEM_COMMIT, false);
		CheckMem("op=99（未知）", OTHER, SELF, 99, PAGE_READWRITE, MEM_COMMIT, false);

		// ---- 带修饰位的保护值（低字节是类型，高位是修饰）仍要正确识别 ----
		CheckMem("跨进程 PROTECT 带 PAGE_GUARD 修饰仍认 RX", OTHER, SELF,
			PROC_ProtectMemory, (PAGE_EXECUTE_READ | PAGE_GUARD), 0, true);
		CheckMem("跨进程 ALLOC 带 MEM_COMMIT|MEM_RESERVE 仍认", OTHER, SELF,
			PROC_AllocateMemory, PAGE_EXECUTE_READ, (MEM_COMMIT | MEM_RESERVE), true);
	}

	printf("\n=== 2. 反向输入 / 锁屏勒索（v14 新增）===\n");
	{
		// ---- SendInput：密度检测器认定后才调此判据 → 一律高危 ----
		CheckInput("SendInput 合成键鼠（认定即高危）", HK_SendInputEvents, true, true);
		CheckInput("SendInput 合成键鼠（非前台也高危）", HK_SendInputEvents, false, true);

		// ---- BlockInput：前台属主自己冻结自己 = 合法 ----
		CheckInput("BlockInput 前台属主自己冻结（合法）", HK_BlockUserInput, true, false);
		CheckInput("BlockInput 后台冻结输入（勒索锁屏，高危）", HK_BlockUserInput, false, true);

		// ---- ClipCursor：前台属主锁自己 = 游戏合法 ----
		CheckInput("ClipCursor 前台属主锁自己（游戏合法）", HK_ClipCursorLock, true, false);
		CheckInput("ClipCursor 后台锁鼠标（伪造登录框，高危）", HK_ClipCursorLock, false, true);

		// ---- 旧的捕获类 Op 不归本判据（防串档）----
		CheckInput("SetMouseHook（捕获面，不归本判据）", 1, false, false);
		CheckInput("PollAsyncKeyState（捕获面，不归本判据）", 7, false, false);
		CheckInput("op=0（未设置）", 0, false, false);
		CheckInput("op=99（未知）", 99, false, false);
	}

	printf("\n=== 3. Op 枚举隔离（v14 语义，防串档）===\n");
	{
		// ProcessOp 与 ThreadOp 的 1 含义不同：ProcessOp=1 是 Create，
		// 不是内存操作 → 内存判据不认。
		CheckMem("ProcessOp=1（Create，非内存操作）", OTHER, SELF,
			1, PAGE_READWRITE, MEM_COMMIT, false);
		// ProcessOp=4 才是 WriteMemory。
		CheckMem("ProcessOp=4（WriteMemory，命中）", OTHER, SELF,
			4, PAGE_READWRITE, MEM_COMMIT, true);

		// HookOp=10/11/12 是反向输入；1~9 是捕获面。
		CheckInput("HookOp=10（SendInput，命中）", 10, false, true);
		CheckInput("HookOp=9（SetWinEventHook，非反向输入）", 9, false, false);
	}

	printf("\n");
	if (g_failed == 0) printf("全部通过  失败 0\n");
	else printf("存在失败  %d\n", g_failed);
	return g_failed;
}
