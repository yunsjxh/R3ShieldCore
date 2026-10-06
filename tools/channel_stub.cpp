//
// channel_stub.cpp - 单元测试用的最小 R3ShieldCoreChannel 桩。
//
// r3shieldcore_rules.cpp 只用到 Policy() 一个函数（读自定义保护路径）。
// 这里给一个静态 Policy 实例，全部字段清零，让规则判定走"无自定义规则"分支。
//
#include <r3shieldcore/r3shieldcore_shared.h>
#include <string.h>

namespace R3ShieldCoreChannel
{
	static R3ShieldCore::Policy g_policy = {};

	R3ShieldCore::Policy* Policy() noexcept
	{
		return &g_policy;
	}

	// ★ 单元测试专用：往 Policy 里塞一条自定义注册表保护前缀，
	//   等价于 ini 里写一行 `protect_reg=<prefix>`。
	//   引擎本体**没有**这个函数 —— 它只在 UT 里存在，用来把
	//   "用户配置"这一层纳入测试（否则 protect_reg 永远没人测）。
	void StubSetProtectReg(const wchar_t* prefix) noexcept
	{
		if (!prefix || prefix[0] == L'\0') {
			return;
		}
		if (g_policy.ProtectRegCount >= R3ShieldCore::MaxProtectPaths) {
			return;
		}
		wcsncpy_s(g_policy.ProtectRegPaths[g_policy.ProtectRegCount],
			R3ShieldCore::MaxProtectPathChars, prefix, _TRUNCATE);
		g_policy.ProtectRegCount++;
	}

	void StubClearProtectReg() noexcept
	{
		g_policy.ProtectRegCount = 0;
	}
}
