#pragma once
//
// engine_deploy_acl.h —— 「这个部署目录能不能加载引擎 DLL」的唯一判据。
//
// ★★ 为什么单独抽成一个 header：
//
//   这条判据原本是 `engine_control.cpp` 匿名命名空间里的两个函数。它一旦
//   返回 false，引擎会**抛异常退出**（不是降级、不是警告），屏幕上只留
//   一行 `Refusing to load an engine DLL from a user-writable deployment
//   directory`。用户看到的是"双击 → 窗口一闪 → 没有任何防护"，而真正
//   的原因埋在 `r3shieldcore-startup-error.log` 里。
//
//   这个坑踩过两次（铁律 25、2026-10-03）：**dist 目录继承了
//   `Authenticated Users:(M)`，引擎拒绝加载 DLL，于是"引擎在跑"其实是
//   "引擎已经退出了"，所有拦截测试都是假的**。
//
//   所以判据必须能被**独立验证**：`tools/deploy_acl_probe.cpp` 与引擎
//   包含的是**同一个 header**（不是复制一份），跑一次就能回答
//   "引擎会不会加载这个目录里的 DLL"。
//
// 【判据本身】
//   DLL 文件 **和** 它所在的目录，都不能对
//   `Everyone` / `Authenticated Users` / `BUILTIN\Users` 授予写权限。
//
//   为什么是这三个 SID：它们代表"任何低权限进程都能写"。只要能写，
//   低权限进程就能把 DLL 换成自己的，然后让以管理员身份运行的引擎
//   把它注入到**每一个进程** —— 等于把本机的管理员权限送出去。
//
//   ★ 注意：判据**不检查**"当前用户自己的 SID"。用户自己的账户带 M
//     是允许的（这也是 Visual Studio 的 `Release\<arch>\` 布局能直接
//     通过的原因）。这是**有意**的：开发/测试机需要能重新拷贝文件。
//
//   ★ 也**不检查** `BUILTIN\Administrators`：管理员本来就能改任何东西。
//
// 【加固办法】只加固**根目录**，不要加 `/T`：
//     icacls <根目录> /inheritance:r ^
//            /grant:r "*S-1-5-32-544:(OI)(CI)F" ^   (Administrators)
//                     "*S-1-5-18:(OI)(CI)F" ^       (SYSTEM)
//                     "*S-1-5-32-545:(OI)(CI)RX"    (Users：只读+执行)
//   加固根目录后，子对象的继承 ACE 会被系统**自动重算**，无需 `/T`。
//
//   ⚠️ 加 `/T` 会出事：`/inheritance:r` 会把每个**文件**的继承 ACE 也剥掉，
//      而 `(OI)(CI)` 这两个容器标志对文件无效 ⇒ `/grant:r` 在文件上失败
//      ⇒ 文件留下**空 DACL**（谁都读不了）。2026-10-03 实测踩到。
//
// 【为什么不用「目录里放个哨兵文件」之类的取巧办法】
//   判据必须和"攻击者能替换 DLL"这件事**同构**。检查别的对象等于没检查。
//
#include <windows.h>
#include <aclapi.h>

#include <filesystem>

namespace EngineDeploy
{
	//
	// 该对象是否对"任何人"开放了写权限。
	//
	// ⚠️ 拿不到安全描述符时返回 **true**（= 认为不安全）。
	//    失败方向必须是"拒绝加载"，不能是"放行"。
	//
	inline bool HasBroadWriteAccess(const std::filesystem::path& path)
	{
		PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
		PACL dacl = nullptr;
		DWORD status = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &securityDescriptor);
		if (status != ERROR_SUCCESS || !securityDescriptor || !dacl) {
			if (securityDescriptor) {
				LocalFree(securityDescriptor);
			}
			return true;
		}

		BYTE worldBuffer[SECURITY_MAX_SID_SIZE] = {};
		BYTE authenticatedBuffer[SECURITY_MAX_SID_SIZE] = {};
		BYTE usersBuffer[SECURITY_MAX_SID_SIZE] = {};
		DWORD worldSize = sizeof(worldBuffer);
		DWORD authenticatedSize = sizeof(authenticatedBuffer);
		DWORD usersSize = sizeof(usersBuffer);
		if (!CreateWellKnownSid(WinWorldSid, nullptr, worldBuffer, &worldSize) ||
			!CreateWellKnownSid(WinAuthenticatedUserSid, nullptr,
				authenticatedBuffer, &authenticatedSize) ||
			!CreateWellKnownSid(WinBuiltinUsersSid, nullptr, usersBuffer, &usersSize)) {
			LocalFree(securityDescriptor);
			return true;
		}

		constexpr ACCESS_MASK kWriteMask = FILE_WRITE_DATA | FILE_APPEND_DATA |
			FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER |
			GENERIC_WRITE | GENERIC_ALL;
		bool writable = false;
		for (DWORD index = 0; index < dacl->AceCount; index++) {
			LPVOID rawAce = nullptr;
			if (!GetAce(dacl, index, &rawAce)) {
				continue;
			}

			auto* header = static_cast<PACE_HEADER>(rawAce);
			if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) {
				continue;
			}

			auto* allowed = static_cast<PACCESS_ALLOWED_ACE>(rawAce);
			PSID aceSid = &allowed->SidStart;
			if ((EqualSid(aceSid, worldBuffer) || EqualSid(aceSid, authenticatedBuffer) ||
				EqualSid(aceSid, usersBuffer)) &&
				(allowed->Mask & kWriteMask) != 0) {
				writable = true;
				break;
			}
		}

		LocalFree(securityDescriptor);
		return writable;
	}

	//
	// DLL 文件 **和** 它所在目录都必须"不对外开放写权限"。
	//
	// 只查文件不够：能写目录就能把 DLL 删掉换成自己的（DELETE + 建新文件），
	// 那样即使文件本身是只读的也没用。
	//
	inline bool IsProtectedEngineDeployment(const std::filesystem::path& libraryPath)
	{
		if (GetFileAttributesW(libraryPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
			return false;
		}

		const std::filesystem::path directory = libraryPath.parent_path();
		return !HasBroadWriteAccess(libraryPath) && !HasBroadWriteAccess(directory);
	}
}
