//
// spawn_rules_ut.cpp - R3ShieldCoreRules 进程创建旁路高危规则单元测试。
//
// 判据（v10）：按 API 分档
//   WithToken / WithLogon → 高危（换 token / 凭据 = 提权与横向移动）
//   WinExec / System      → 高危（shellcode 常用的一层）
//   ShellExecute          → 高危（可能触发关联劫持）
//   AsUser                → 高危（CreateProcessAsUser，换取身份，v11 新增）
//   其它 / 0              → 不算高危
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskSpawn(unsigned long spawnOp) noexcept;
	const char* SpawnRiskReason(unsigned long spawnOp) noexcept;
}

// SpawnOp 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	S_ShellExecute = 1,
	S_WinExec      = 2,
	S_WithToken    = 3,
	S_WithLogon    = 4,
	S_System       = 5,
	S_AsUser       = 6,
};

struct Case
{
	unsigned long op;
	bool expectHigh;
	const char* note;
};

int wmain()
{
	setlocale(LC_ALL, "");

	const Case cases[] = {
		{ S_ShellExecute, true,  "ShellExecute（关联劫持）" },
		{ S_WinExec,      true,  "WinExec（shellcode 常用）" },
		{ S_WithToken,    true,  "WithToken（提权/横向）" },
		{ S_WithLogon,    true,  "WithLogon（凭据滥用）" },
		{ S_System,       true,  "system/_wsystem（拉起 cmd）" },
		{ S_AsUser,       true,  "CreateProcessAsUser（换身份，不走 seclogon）" },
		{ 0,              false, "op=0（未设置，不判高危）" },
		{ 99,             false, "未知 op（兜底不判高危）" },
	};

	int failed = 0;
	for (const Case& c : cases) {
		const char* reason = R3ShieldCoreRules::SpawnRiskReason(c.op);
		bool got = (reason != nullptr);
		const char* mark = (got == c.expectHigh) ? "OK  " : "FAIL";
		if (got != c.expectHigh) failed++;
		printf("%s  op=%-3lu expect=%-5s got=%-5s  %-30s reason=%s\n",
			mark, c.op, c.expectHigh ? "HIGH" : "norm",
			got ? "HIGH" : "norm", c.note, reason ? reason : "(null)");
	}

	printf("\n%s  失败 %d\n", failed == 0 ? "全部通过" : "存在失败", failed);
	return failed;
}
