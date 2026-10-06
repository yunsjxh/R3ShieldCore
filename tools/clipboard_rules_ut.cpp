//
// clipboard_rules_ut.cpp - R3ShieldCoreRules 剪贴板高危规则单元测试。
//
// 核心判据（v10）：
//   - Open（OpenClipboard）→ **不算高危**（只记录）。拦它 = 按 Ctrl+C 就弹窗。
//   - Read（GetClipboardData）→ 高危。
//   - 其它值 → 不算高危。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskClipboard(unsigned long clipboardOp) noexcept;
	const char* ClipboardRiskReason(unsigned long clipboardOp) noexcept;
}

// ClipboardOp 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	C_Open = 1,
	C_Read = 2,
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
		{ C_Open, false, "OpenClipboard（只记录，不判高危）" },
		{ C_Read, true,  "GetClipboardData（读取内容，高危）" },
		{ 0,      false, "op=0（未设置，不判高危）" },
		{ 99,     false, "未知 op（兜底不判高危）" },
	};

	int failed = 0;
	for (const Case& c : cases) {
		const char* reason = R3ShieldCoreRules::ClipboardRiskReason(c.op);
		bool got = (reason != nullptr);
		const char* mark = (got == c.expectHigh) ? "OK  " : "FAIL";
		if (got != c.expectHigh) failed++;
		printf("%s  op=%-3lu expect=%-5s got=%-5s  %-42s reason=%s\n",
			mark, c.op, c.expectHigh ? "HIGH" : "norm",
			got ? "HIGH" : "norm", c.note, reason ? reason : "(null)");
	}

	printf("\n%s  失败 %d\n", failed == 0 ? "全部通过" : "存在失败", failed);
	return failed;
}
