#include "stdafx.h"

#include <wtsapi32.h>

#include "functions.h"
#include "inject_policy.h"
#include "r3shieldcore_channel.h"
#include "logger.h"

namespace
{
	//
	// ★ v55：解析「当前会话的交互用户」SID。
	//
	// 为什么非有它不可（这是一次**全局零事件**的根因）：
	//   UIAccess 子引擎是用 **winlogon.exe 的 LocalSystem 令牌**拉起来的
	//   （见 r3shieldcore_superdesk.cpp：「它的令牌就是当前登录会话的 LocalSystem」），
	//   所以那个进程的 token 用户 = SYSTEM (S-1-5-18)。
	//
	//   而共享对象（Policy / Events / 询问通道 / 注入互斥体）的 ACL 历来只写
	//   "本进程 token 用户" 这一条 ACE。SYSTEM 引擎建出来的对象就**没有交互
	//   用户的 ACE** ⇒ 普通（中等完整性）进程 OpenFileMapping 被 DACL 直接拒
	//   ⇒ 日志"共享通道不可用，本进程跳过全部 Hook" ⇒ **一条事件都没有**。
	//   只有 SYSTEM 与"管理组已启用"的提权进程还能连上。
	//
	//   所以这里按**会话**取交互用户 SID 并额外放行。相比 IU/AU/Everyone：
	//     · 精确到本会话的登录用户，不放开全局；
	//     · 在受限令牌（浏览器沙箱）里该 SID 同样存在，覆盖更完整；
	//     · 不会像 Everyone(WD) 那样让任意进程都能读写通道。
	//
	// ⚠️ WTSQueryUserToken 需要 SeTcbPrivilege。SYSTEM 引擎天然具备；普通引擎
	//    拿到失败也无所谓 —— 那时进程 token 用户本身就是交互用户，已经覆盖。
	//
	bool TryGetSessionUserSid(std::wstring& sidOut) noexcept
	{
		sidOut.clear();

		DWORD sessionId = 0;
		if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId)) {
			return false;
		}

		HANDLE userToken = nullptr;
		if (!WTSQueryUserToken(sessionId, &userToken)) {
			return false;
		}

		DWORD bytes = 0;
		GetTokenInformation(userToken, TokenUser, nullptr, 0, &bytes);
		if (bytes == 0) {
			CloseHandle(userToken);
			return false;
		}

		wil::unique_hlocal buffer(LocalAlloc(LMEM_FIXED, bytes));
		const bool ok = buffer &&
			GetTokenInformation(userToken, TokenUser, buffer.get(), bytes, &bytes);
		CloseHandle(userToken);
		if (!ok) {
			return false;
		}

		WCHAR* text = nullptr;
		if (!ConvertSidToStringSidW(static_cast<const TOKEN_USER*>(buffer.get())->User.Sid, &text)) {
			return false;
		}

		sidOut.assign(text);
		LocalFree(text);
		return true;
	}

	wil::unique_hlocal BuildSharedSecurityDescriptor(bool allowWrite, bool includeLowLabel) noexcept
	{
		try {
			HANDLE token = nullptr;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
				return wil::unique_hlocal();
			}

			DWORD bytes = 0;
			GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
			if (bytes == 0) {
				CloseHandle(token);
				return wil::unique_hlocal();
			}

			wil::unique_hlocal tokenBuffer(LocalAlloc(LMEM_FIXED, bytes));
			if (!tokenBuffer || !GetTokenInformation(token, TokenUser, tokenBuffer.get(), bytes, &bytes)) {
				CloseHandle(token);
				return wil::unique_hlocal();
			}
			CloseHandle(token);

			WCHAR* sidText = nullptr;
			const auto* tokenUser = static_cast<const TOKEN_USER*>(tokenBuffer.get());
			if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidText)) {
				return wil::unique_hlocal();
			}

			std::wstring processUserSid(sidText);
			LocalFree(sidText);

			// ★ v55：除"本进程 token 用户"外，**必须**再放行「当前会话的交互用户」。
			//
			//   UIAccess 子引擎以 SYSTEM 身份运行（winlogon 令牌），此时进程
			//   token 用户 = S-1-5-18；只写这一条的话，交互用户一条 ACE 都没有，
			//   普通进程会被 DACL 直接拒 ⇒ "共享通道不可用" ⇒ 全局零事件。
			//   详见 TryGetSessionUserSid 的注释。
			std::wstring sessionUserSid;
			const bool haveSessionUser = TryGetSessionUserSid(sessionUserSid);

			// 解析失败但身份是 SYSTEM ⇒ 退化成放行"交互用户组"(IU)，
			// 总比一条都连不上强；IU 远比 Everyone 窄。
			const bool needExtraUserAce =
				(haveSessionUser && sessionUserSid != processUserSid) ||
				(!haveSessionUser && processUserSid == L"S-1-5-18");
			const std::wstring extraUserSid = haveSessionUser ? sessionUserSid : std::wstring(L"IU");

			// Event objects do not map GENERIC_READ to SYNCHRONIZE on all
			// Windows builds.  The injected side must wait on prompt-slot
			// events, so the owner SID needs the complete object access mask.
			// Keep read-only policy mappings read-only; only the channel/prompt
			// owner gets GA.
			const std::wstring access = allowWrite ? L"GA" : L"GR";
			std::wstring sddl =
				L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;" + access + L";;;" + processUserSid + L")";
			if (needExtraUserAce) {
				sddl += L"(A;;" + access + L";;;" + extraUserSid + L")";
			}
			if (includeLowLabel) {
				sddl += L"S:(ML;;NW;;;LW)";
			}

			PSECURITY_DESCRIPTOR descriptor = nullptr;
			if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
				sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
				return wil::unique_hlocal();
			}

			return wil::unique_hlocal(descriptor);
		}
		catch (...) {
			return wil::unique_hlocal();
		}
	}

	bool EnableTokenPrivilege(PCWSTR privilegeName) noexcept
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) {
			return false;
		}

		LUID luid = {};
		TOKEN_PRIVILEGES privileges = {};
		privileges.PrivilegeCount = 1;
		if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
			CloseHandle(token);
			return false;
		}

		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		SetLastError(ERROR_SUCCESS);
		BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
		DWORD error = GetLastError();
		CloseHandle(token);

		return adjusted != FALSE && error == ERROR_SUCCESS;
	}
}

BOOL GetFullAccessSecurityDescriptor(
	_Outptr_ PSECURITY_DESCRIPTOR* SecurityDescriptor,
	_Out_opt_ PULONG SecurityDescriptorSize)
{
	// http://rsdn.org/forum/winapi/7510772.flat
	//
	// For full access maniacs :)
	// Full access for the "Everyone" group and for the "All [Restricted] App Packages" groups.
	// The integrity label is Untrusted (lowest level).
	//
	// D - DACL
	// P - Protected
	// A - Access Allowed
	// GA - GENERIC_ALL
	// WD - 'All' Group (World)
	// S-1-15-2-1 - All Application Packages
	// S-1-15-2-2 - All Restricted Application Packages
	//
	// S - SACL
	// ML - Mandatory Label
	// NW - No Write-Up policy
	// S-1-16-0 - Untrusted Mandatory Level
	auto descriptor = BuildSharedSecurityDescriptor(true, true);
	if (!descriptor) {
		return FALSE;
	}

	if (SecurityDescriptorSize) {
		*SecurityDescriptorSize = GetSecurityDescriptorLength(descriptor.get());
	}
	*SecurityDescriptor = descriptor.release();
	return TRUE;
}

bool IsProcessElevated() noexcept
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return false;
	}

	TOKEN_ELEVATION elevation = {};
	DWORD returned = 0;
	BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
	CloseHandle(token);

	return ok && elevation.TokenIsElevated != 0;
}

//
// ★ v42：名单与分类逻辑搬到了 `inject_policy.{h,cpp}`。
//
// 为什么搬：这张表现在有**三档**（不注入 / 瘦注入 / 完整注入），而且
//   "瘦注入"是**被注入进程自己**也要判的事（它得知道"我这个会话只装
//   CreateProcessInternalW"）。把判定放在一个**不依赖共享内存/Policy**
//   的纯函数模块里，引擎和 DLL 读的是**同一份**代码与同一张表 ⇒ 天然一致；
//   同时 `build_ut.sh` 能把它单独链起来做单元测试（铁律 9：看探针不看 grep）。
//
//
// ★ v49：用户自定义的「绝不注入」名单（ini: `never_inject=`）。
//
// 为什么放在 `ShouldSkipProcessInjection` 里、而不是塞进 `InjectPolicy`：
//   `inject_policy.{h,cpp}` 是**纯函数**模块（不依赖 Policy/共享内存），
//   这样 `build_ut.sh` 能把它单独链起来测（铁律 9）。Policy 相关的遍历
//   留在这一层，纯匹配器 `InjectPolicy::MatchesNeverInjectPath` 仍可单测。
//
// Policy 打不开（例如瘦会话自己没开通道）时返回 false ⇒ **照常注入**：
//   这个方向的误判是"多监控"，不是"漏监控"，是安全方向。
//
bool IsUserNeverInject(PCWSTR imagePath) noexcept
{
	R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
	if (!policy || !imagePath || imagePath[0] == L'\0') {
		return false;
	}

	ULONG count = policy->NeverInjectCount;
	if (count > R3ShieldCore::MaxNeverInjectPaths) {
		count = static_cast<ULONG>(R3ShieldCore::MaxNeverInjectPaths);
	}

	for (ULONG i = 0; i < count; ++i) {
		if (InjectPolicy::MatchesNeverInjectPath(imagePath, policy->NeverInjectPaths[i])) {
			return true;
		}
	}

	return false;
}

bool ShouldSkipProcessInjection(HANDLE process) noexcept
{
	if (!process || process == INVALID_HANDLE_VALUE) {
		return false;
	}

	WCHAR imagePath[MAX_PATH * 2] = {};
	DWORD length = _countof(imagePath);
	if (!QueryFullProcessImageNameW(process, 0, imagePath, &length) || length == 0) {
		return false;
	}

	// ★ v49：先看**用户自定义**名单 —— 用户明确说了"别注入这个"就照办，
	//   优先级高于内置的三档分类。
	if (IsUserNeverInject(imagePath)) {
		LOG(L"用户名单跳过注入 image=%ls", imagePath);
		return true;
	}

	const InjectPolicy::Mode mode = InjectPolicy::ClassifyImagePath(
		imagePath, IsThinInjectAllowed());

	if (mode == InjectPolicy::Mode::Skip) {
		// ★ v53：内置**路径**豁免（目前只有 VMware Tools）走这里 —— 日志里
		//   点名，否则"VMware Tools 被豁免"这件事在真机上**不可见、不可核对**
		//   （与铁律 23「GUI 诊断不能靠 printf」同族：看不见就等于没做）。
		if (InjectPolicy::IsBuiltinNeverInjectPath(imagePath)) {
			LOG(L"跳过内置豁免进程注入(VMware Tools) image=%ls", imagePath);
		}
		else {
			LOG(L"跳过安全进程注入 image=%ls", imagePath);
		}
		return true;
	}

	return false;
}

//
// 瘦注入是否被允许（Policy 位 `FlagInjectShellThin`，ini: `inject_shell_thin`）。
//
// ★ Policy 打不开时（例如**瘦会话自己**根本没开通道）按"**允许**"处理。
//   这一点很关键：瘦会话里的 `CreateProcessInternalW` hook 也会调
//   `ShouldSkipProcessInjection`（new_process_injector.cpp），
//   那时 `R3ShieldCoreChannel::Policy()` 是 nullptr —— 如果这里返回 false，
//   瘦会话就再也拉不起同步路了（自锁）。
//
bool IsThinInjectAllowed() noexcept
{
	R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
	return !policy || (policy->Flags2 & R3ShieldCore::FlagInjectShellThin) != 0;
}

wil::unique_hlocal GetSharedObjectSecurityDescriptor(bool allowWrite) noexcept
{
	bool includeLowLabel = false;
	if (IsProcessElevated()) {
		// Applying the explicit mandatory label requires SeSecurityPrivilege.
		// Global named objects may also require SeCreateGlobalPrivilege.
		// Both privileges are commonly present but disabled in an elevated token.
		const bool canSetMandatoryLabel = EnableTokenPrivilege(SE_SECURITY_NAME);
		EnableTokenPrivilege(SE_CREATE_GLOBAL_NAME);
		includeLowLabel = canSetMandatoryLabel;

		if (auto descriptor = BuildSharedSecurityDescriptor(allowWrite, includeLowLabel)) {
			return descriptor;
		}
	}

	// Non-elevated callers cannot set a mandatory label, but must still use
	// the owner/admin/system ACL instead of granting Everyone write access.
	return BuildSharedSecurityDescriptor(allowWrite, false);
}
