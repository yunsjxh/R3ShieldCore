#include "stdafx.h"
#include "registry_guard.h"
#include "r3shieldcore_channel.h"
#include "r3shieldcore_prompt.h"
#include "r3shieldcore_rules.h"
#include "host_hijack_guard.h"
#include "logger.h"

//
// 数字签名校验（ComputeBypass 的第二条件）。
//
// ⚠️ `softpub.h` / `mssip.h` 里带 `#include <wincrypt.h>`，而 stdafx.h 可能已经
//    拉过；用 `_WIN32_WINNT` 保护宏 + 只取需要的常量自己定义，避免头文件打架。
//    `WINTRUST_ACTION_GENERIC_VERIFY_V2` 的 GUID 是固定值，直接写出来。
//
#include <wintrust.h>
#include <mscat.h>      // CATALOG_INFO / CryptCATAdmin* （目录签名）
#include <bcrypt.h>     // BCRYPT_SHA256_ALGORITHM

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

//
// 为什么不直接 include <winternl.h>：
// 项目的 stdafx.h 已经带了 <ntsecapi.h>，而 ntsecapi.h 会牵进 SubAuth.h，
// 两个头文件都会定义 UNICODE_STRING / NTSTATUS。这里自己定义一份布局等价
// 的本地类型，彻底避开重定义风险。布局必须与系统结构一致。
//
namespace
{
	struct RG_UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	};

	struct RG_OBJECT_ATTRIBUTES
	{
		ULONG Length;
		HANDLE RootDirectory;
		RG_UNICODE_STRING* ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	};

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

	// ntdll 注册表 API 原型。用 _Ptr 后缀避开 winternl.h 里已有的 NtRenameKey 声明。
	typedef NTSTATUS(NTAPI* NtCreateKeyPtr)(PHANDLE, ACCESS_MASK, const RG_OBJECT_ATTRIBUTES*, ULONG, RG_UNICODE_STRING*, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtOpenKeyPtr)(PHANDLE, ACCESS_MASK, const RG_OBJECT_ATTRIBUTES*);
	typedef NTSTATUS(NTAPI* NtOpenKeyExPtr)(PHANDLE, ACCESS_MASK, const RG_OBJECT_ATTRIBUTES*, ULONG);
	typedef NTSTATUS(NTAPI* NtSetValueKeyPtr)(HANDLE, const RG_UNICODE_STRING*, ULONG, ULONG, PVOID, ULONG);
	typedef NTSTATUS(NTAPI* NtDeleteKeyPtr)(HANDLE);
	typedef NTSTATUS(NTAPI* NtDeleteValueKeyPtr)(HANDLE, const RG_UNICODE_STRING*);
	typedef NTSTATUS(NTAPI* NtRenameKeyPtr)(HANDLE, const RG_UNICODE_STRING*);
	typedef NTSTATUS(NTAPI* NtQueryKeyPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtQueryValueKeyPtr)(HANDLE, const RG_UNICODE_STRING*, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtEnumerateKeyPtr)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtEnumerateValueKeyPtr)(HANDLE, ULONG, ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtFlushKeyPtr)(HANDLE);
	typedef NTSTATUS(NTAPI* NtSetInformationKeyPtr)(HANDLE, ULONG, PVOID, ULONG);

	// Hive 级操作。这些不操作键句柄，而是直接吃文件路径 ——
	// 也正是原版覆盖不到的地方。
	//
	// NtLoadKey(Ex) 把 hive 文件挂到注册表树上，攻击者可以借此把整个
	// 子树换成自己的（经典的 "HKLM\SYSTEM 挂载恶意 hive"）。
	// NtSaveKey(Ex) 把键导成文件，SAM / SECURITY 导出就靠它。
	// NtRestoreKey 用文件内容覆盖现有键（比 LoadKey 更隐蔽）。
	// NtReplaceKey 原子替换 —— 是 NtRestoreKey 的底层实现。
	typedef NTSTATUS(NTAPI* NtLoadKeyPtr)(const RG_OBJECT_ATTRIBUTES*, const RG_OBJECT_ATTRIBUTES*);
	typedef NTSTATUS(NTAPI* NtLoadKeyExPtr)(const RG_OBJECT_ATTRIBUTES*, const RG_OBJECT_ATTRIBUTES*, ULONG, HANDLE, HANDLE, ULONG, PVOID, PULONG);
	typedef NTSTATUS(NTAPI* NtUnloadKeyPtr)(const RG_OBJECT_ATTRIBUTES*);
	typedef NTSTATUS(NTAPI* NtUnloadKeyExPtr)(const RG_OBJECT_ATTRIBUTES*, HANDLE);
	typedef NTSTATUS(NTAPI* NtSaveKeyPtr)(HANDLE, HANDLE);
	typedef NTSTATUS(NTAPI* NtSaveKeyExPtr)(HANDLE, HANDLE, ULONG);
	typedef NTSTATUS(NTAPI* NtRestoreKeyPtr)(HANDLE, HANDLE, ULONG);
	typedef NTSTATUS(NTAPI* NtReplaceKeyPtr)(const RG_OBJECT_ATTRIBUTES*, HANDLE, const RG_OBJECT_ATTRIBUTES*);

	NtCreateKeyPtr pOriginalNtCreateKey = nullptr;
	NtOpenKeyPtr pOriginalNtOpenKey = nullptr;
	NtOpenKeyExPtr pOriginalNtOpenKeyEx = nullptr;
	NtSetValueKeyPtr pOriginalNtSetValueKey = nullptr;
	NtDeleteKeyPtr pOriginalNtDeleteKey = nullptr;
	NtDeleteValueKeyPtr pOriginalNtDeleteValueKey = nullptr;
	NtRenameKeyPtr pOriginalNtRenameKey = nullptr;
	NtQueryKeyPtr pOriginalNtQueryKey = nullptr;
	NtQueryValueKeyPtr pOriginalNtQueryValueKey = nullptr;
	NtEnumerateKeyPtr pOriginalNtEnumerateKey = nullptr;
	NtEnumerateValueKeyPtr pOriginalNtEnumerateValueKey = nullptr;
	NtFlushKeyPtr pOriginalNtFlushKey = nullptr;
	NtSetInformationKeyPtr pOriginalNtSetInformationKey = nullptr;

	NtLoadKeyPtr pOriginalNtLoadKey = nullptr;
	NtLoadKeyExPtr pOriginalNtLoadKeyEx = nullptr;
	NtUnloadKeyPtr pOriginalNtUnloadKey = nullptr;
	NtUnloadKeyExPtr pOriginalNtUnloadKeyEx = nullptr;
	NtSaveKeyPtr pOriginalNtSaveKey = nullptr;
	NtSaveKeyExPtr pOriginalNtSaveKeyEx = nullptr;
	NtRestoreKeyPtr pOriginalNtRestoreKey = nullptr;
	NtReplaceKeyPtr pOriginalNtReplaceKey = nullptr;

	// ------------------------------------------------------------------
	// 状态。g_bypass 在 Install() 里算一次，之后 hook 路径上只读它。
	// ------------------------------------------------------------------
	bool g_installed = false;
	bool g_bypass = false;
	int g_hookCount = 0;

	//
	// 当前有多少个线程正跑在 hook 里。
	//
	// 收尾时必须等它归零才能 MH_Uninitialize()：那一步会释放 trampoline，
	// 而还在 hook 里的线程返回时会跳进去 —— 实测会让宿主进程 c0000005 崩在
	// "r3shieldcore-lib.dll_unloaded"（曾打崩 WorkBuddyAI.exe）。
	//
	volatile LONG g_activeHooks = 0;

	enum class Action
	{
		Pass,   // 无需关注，直接放行
		Record, // 放行并上报
		Block,  // 拒绝
	};

	Action ExceptionAction(R3ShieldCore::Event& event) noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->Mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}
		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
		event.Flags |= R3ShieldCore::FlagEventBlocked;
		return Action::Block;
	}

	// ------------------------------------------------------------------
	// 工具
	// ------------------------------------------------------------------
	bool StartsWithNoCase(PCWSTR text, PCWSTR prefix) noexcept
	{
		return _wcsnicmp(text, prefix, wcslen(prefix)) == 0;
	}

	LONG64 NowFileTime() noexcept
	{
		FILETIME fileTime;
		GetSystemTimeAsFileTime(&fileTime);
		return static_cast<LONG64>((static_cast<ULONGLONG>(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime);
	}

	// 只关心"要写"的打开；纯读打开在非系统进程里太频繁，默认不记录。
	//
	// 注意：这里绝不能用 KEY_WRITE / STANDARD_RIGHTS_WRITE 参与判断。
	// 它们的 READ_CONTROL(0x00020000) 位和 KEY_READ / STANDARD_RIGHTS_READ 完全重叠，
	// 拿它们做掩码会把所有纯读打开都误判成写意图（实测 12 秒里刷出 240 条噪音）。
	bool IsWriteAccess(ULONG access) noexcept
	{
		constexpr ULONG WriteIntent =
			KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK |
			DELETE | WRITE_DAC | WRITE_OWNER;

		return (access & WriteIntent) != 0;
	}

	// ------------------------------------------------------------------
	// 数字签名校验（ComputeBypass 的第二条件）
	// ------------------------------------------------------------------
	//
	// ⚠️ 为什么需要它：
	//
	//   原来 bypass 只按**目录前缀**判（`%SystemRoot%\` 下全部放行）。
	//   但 `C:\Windows\` 下有很多**用户可写**的子目录：
	//     · `%SystemRoot%\Temp\`      —— 默认 Users 可写，恶意软件常驻
	//     · `%SystemRoot%\Tasks\`     —— 通常可写
	//     · `%SystemRoot%\Prefetch\`  —— 可写
	//     · `%SystemRoot%\tracing\`、`%SystemRoot%\LiveKernelReports\`、`%SystemRoot%\Logs\`
	//   往这些目录里丢一个 EXE 并执行，它镜像路径以 `C:\Windows\` 开头 →
	//   **原判据直接 bypass 整个进程** → 什么都监控不到。这是真实可利用的洞。
	//
	//   目录判据的第二个问题：攻击者也可以把程序伪装成"系统路径"的名字
	//   （复制到 System32 需要管理员，但把同名的放到可写子目录不需要）。
	//
	// ⚠️ 判据（**签名 + 目录双条件**，只要有一条不满足就挂 hook）：
	//
	//     ① 目录在**可写子目录名单**里 → 挂（不看签名）
	//     ② 目录可信，但**没有有效签名**（未签名 / 签名损坏 / 证书被吊销）→ 挂
	//     ③ 目录可信、有有效签名，但**签名者不是 Microsoft** → 挂
	//
	//   ⇒ **只有"微软签名 + 可信目录"两者同时成立才 bypass。**
	//     这正是需求原文：
	//       "System32 下未签名的、或签名者非 Microsoft 的、或来自
	//        %SystemRoot%\Temp／可写子目录的，必须挂 hook。"
	//
	//   `%SystemRoot%\Temp\evil.exe`（可写目录）→ 挂；
	//   `System32\apphelp.dll`（微软签名）→ bypass；
	//   `System32\atiadlxx.dll`（AMD 签名，可信目录）→ **挂**（签名者非微软）。
	//
	// ⚠️ 代价与取舍（**这是有意为之，不是缺陷**）：
	//   收紧到"必须微软签名"会让 System32 下**大量非微软签名的正常组件**
	//   （AMD/NVIDIA/Realtek/Intel 的 DLL）也被挂上 hook —— 相比旧判据
	//   会多出一些监控面。这是需求明确要求的取舍：宁可多监控，
	//   也不放过"可信目录里被替换成非微软签名载荷"的情况。
	//   如果后续要减噪，方向是**只对这些非微软签名的 DLL 所在的宿主进程**
	//   放宽，而不是放松这里的判据。
	//
	// ⚠️ 性能：这个函数只在 Install() 里调用**一次**（每个进程一次），
	//    不在 hook 热路径上，所以可以放心做 WinVerifyTrust（几十毫秒）。
	//    但为了不给进程启动加太多延迟，**先做便宜的目录检查**，
	//    目录已经可疑就直接返回，不跑签名校验。

	// `%SystemRoot%\` 下用户可写子目录的名单 + 微软签名者判断，已经提到
	// 规则层（`R3ShieldCoreRules::IsInWritableWindowsSubdir` /
	// `IsMicrosoftSigner`）—— 它们是纯字符串判断，放规则层才能被
	// v16_rules_ut 覆盖。这里只保留需要系统 API 的部分。
	// 规则层提供的三个纯函数（见 r3shieldcore_rules.h）：
	//   · R3ShieldCoreRules::IsInWritableWindowsSubdir —— 路径是否在可写子目录
	//   · R3ShieldCoreRules::IsMicrosoftSigner        —— 签名者是否微软
	//   · R3ShieldCoreRules::IsWhitelistedSystemImage —— 路径是否在**具体文件白名单**（v20）
	using R3ShieldCoreRules::IsInWritableWindowsSubdir;
	using R3ShieldCoreRules::IsMicrosoftSigner;
	using R3ShieldCoreRules::IsWhitelistedSystemImage;

	// 从证书里取"签发者（发布者）名称"。
	//
	// ⚠️ 用 `CERT_NAME_SIMPLE_DISPLAY_TYPE` 拿简化名（"Microsoft Windows"），
	//    比拿完整 DN（"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond..."）
	//    好比较，也不受字段顺序影响。
	bool TryGetSignerName(const WCHAR* filePath, WCHAR* outName, size_t outChars) noexcept
	{
		if (!filePath || !outName || outChars < 2) {
			return false;
		}

		outName[0] = L'\0';

		// 1) 找文件的嵌入式签名。
		//
		//    ⚠️ 只认"嵌入式"（`CERT_FIND_ANY`），不认目录文件，也不做吊销检查
		//       —— 吊销检查要联网（CRL/OCSP），会拖慢进程启动几秒，得不偿失。
		//       吊销的检测交给 WinVerifyTrust 那条路（它按系统策略走缓存）。
		HCERTSTORE store = nullptr;
		HCRYPTMSG message = nullptr;

		if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
			0, nullptr, nullptr, nullptr, &store, &message, nullptr)) {
			return false;
		}

		bool ok = false;

		// 2) 取签名者信息。
		DWORD signerInfoSize = 0;
		PCMSG_SIGNER_INFO signerInfo = nullptr;

		if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)
			&& signerInfoSize > 0) {
			BYTE* buffer = static_cast<BYTE*>(LocalAlloc(LPTR, signerInfoSize));
			if (buffer && CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer, &signerInfoSize)) {
				signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer);

				// 3) 用签名者的 Issuer + SerialNumber 在证书库里找出签名证书。
				CERT_INFO certInfo = {};
				certInfo.Issuer = signerInfo->Issuer;
				certInfo.SerialNumber = signerInfo->SerialNumber;

				PCCERT_CONTEXT cert = CertFindCertificateInStore(store,
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
					CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

				if (cert) {
					// 4) 取"主题的简化显示名" = 发布者名。
					const DWORD nameChars = CertGetNameString(cert,
						CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, outName,
						static_cast<DWORD>(outChars));

					ok = (nameChars > 1) && (outName[0] != L'\0');
					CertFreeCertificateContext(cert);
				}

				LocalFree(buffer);
			}
		}

		CryptMsgClose(message);
		CertCloseStore(store, 0);
		return ok;
	}

	// 签名者名字是否为微软 —— 判断逻辑在规则层（R3ShieldCoreRules::IsMicrosoftSigner），
	// 这里只是调用点。见 r3shieldcore_rules.cpp 末尾。

	// ------------------------------------------------------------------
	// 目录签名（catalog）校验 —— 嵌入式签名之外的第二条路
	// ------------------------------------------------------------------
	//
	// 为什么要它：`WTD_CHOICE_FILE` 只认**嵌入式**签名。Windows 大量系统程序
	// （尤其 .exe）没有嵌入式签名，签名放在 `System32\CatRoot\` 的 catalog
	// 文件里。对这类文件，WTD_CHOICE_FILE 返回 `TRUST_E_NOSIGNATURE`。
	//
	// 微软官方两段式：
	//   ① 按文件内容算 hash（`CryptCATAdminCalcHashFromFileHandle2`）
	//   ② 从 hash 找 catalog（`CryptCATAdminEnumCatalogFromHash`）
	//   ③ 用 `WTD_CHOICE_CATALOG` 校验该 catalog（认信任链）
	//
	// ⚠️ 两个坑（都实测踩过）：
	//   ① 用 `BCRYPT_SHA256_ALGORITHM` 算 hash 能"找到 catalog"，
	//      但 catalog 内是按 **SHA1** tag 索引的 → 验证时 tag 不匹配失败。
	//      必须用**默认算法**（`CryptCATAdminAcquireContext2` 传 nullptr）。
	//   ② 输出 catalog 文件路径给调用方 —— catalog 签名者的名字要从
	//      **catalog 文件**（它自己是 PKCS7 签名的）里读，不是从目标文件。
	bool IsCatalogTrusted(const WCHAR* filePath, WCHAR* outCatalogFile, size_t outCatalogChars) noexcept
	{
		if (outCatalogFile && outCatalogChars > 0) {
			outCatalogFile[0] = L'\0';
		}

		HANDLE file = CreateFileW(filePath, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) {
			return false;
		}

		CATALOG_INFO catalogInfo = {};
		catalogInfo.cbStruct = sizeof(catalogInfo);

		HANDLE hCatAdmin = nullptr;
		bool trusted = false;

		// 默认算法（SHA1），与 catalog 内容一致。
		if (CryptCATAdminAcquireContext2(&hCatAdmin, nullptr, nullptr, nullptr, 0)) {

			DWORD hashSize = 0;
			if (CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file, &hashSize, nullptr, 0) || hashSize > 0) {
				BYTE* hash = static_cast<BYTE*>(LocalAlloc(LPTR, hashSize));
				if (hash && CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file, &hashSize, hash, 0)) {
					// ② 找 catalog。
					HCATADMIN catAdmin = static_cast<HCATADMIN>(hCatAdmin);
					HCATINFO catInfo = CryptCATAdminEnumCatalogFromHash(
						catAdmin, hash, hashSize, 0, nullptr);

					if (catInfo && CryptCATCatalogInfoFromContext(catInfo, &catalogInfo, 0)) {
						// memberTag 用 hash 的十六进制串（catalog 里成员就是按它索引）。
						WCHAR memberTag[2 * 64 + 1] = {};
						for (DWORD i = 0; i < hashSize && i < 64; i++) {
							swprintf_s(memberTag + i * 2, 3, L"%02X", hash[i]);
						}

						// ③ 校验 catalog。
						WINTRUST_CATALOG_INFO catTrustInfo = {};
						catTrustInfo.cbStruct = sizeof(catTrustInfo);
						catTrustInfo.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
						catTrustInfo.pcwszMemberFilePath = filePath;
						catTrustInfo.pcwszMemberTag = memberTag;
						catTrustInfo.pbCalculatedFileHash = hash;
						catTrustInfo.cbCalculatedFileHash = hashSize;

						WINTRUST_DATA catData = {};
						catData.cbStruct = sizeof(catData);
						catData.dwUIChoice = WTD_UI_NONE;
						catData.fdwRevocationChecks = WTD_REVOKE_NONE;
						catData.dwUnionChoice = WTD_CHOICE_CATALOG;
						catData.pCatalog = &catTrustInfo;
						catData.dwStateAction = WTD_STATEACTION_VERIFY;
						catData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

						GUID actionGuid = { 0x00AAC56B, 0xCD44, 0x11d0,
							{ 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };

						trusted = (WinVerifyTrust(nullptr, &actionGuid, &catData) == ERROR_SUCCESS);

						catData.dwStateAction = WTD_STATEACTION_CLOSE;
						WinVerifyTrust(nullptr, &actionGuid, &catData);

						// 把 catalog 文件路径交给调用方（用来取签名者名）。
						if (outCatalogFile && outCatalogChars > 0) {
							wcsncpy_s(outCatalogFile, outCatalogChars,
								catalogInfo.wszCatalogFile, _TRUNCATE);
						}

						CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
					}

					if (hash) {
						LocalFree(hash);
					}
				}
			}

			CryptCATAdminReleaseContext(hCatAdmin, 0);
		}

		CloseHandle(file);
		return trusted;
	}

	// 对文件做完整签名校验（走系统策略：信任链 + 时间戳 + 吊销）。
	//
	// ⚠️ 为什么还要 WinVerifyTrust（不能只看"有没有签名结构"）：
	//    `TryGetSignerName` 只证明"文件里嵌了签名块"，不证明签名**有效**。
	//    攻击者可以把一个无效/自签的签名块塞进去冒充。
	//    `WinVerifyTrust` 才真正验证信任链。
	//
	// ⚠️ 超时控制：WinVerifyTrust 在证书链要下载时可能变慢。这里**不**做
	//    在线吊销检查（`WTD_REVOKE_NONE` + 关闭 `WTD_REVOCATION_CHECK_CHAIN`），
	//    避免进程启动被网络拖住。本地信任链验证够快（一般 < 20ms）。
	//
	// ⚠️ 出参 outCatalogFile：如果是**目录签名**通过的，回填 catalog 文件路径，
	//    调用方要用它去取签名者名（目标文件本身没有嵌入式签名）。
	bool IsSignatureTrusted(const WCHAR* filePath, WCHAR* outCatalogFile, size_t outCatalogChars) noexcept
	{
		if (outCatalogFile && outCatalogChars > 0) {
			outCatalogFile[0] = L'\0';
		}

		if (!filePath || !filePath[0]) {
			return false;
		}

		WINTRUST_FILE_INFO fileInfo = {};
		fileInfo.cbStruct = sizeof(fileInfo);
		fileInfo.pcwszFilePath = filePath;

		WINTRUST_DATA trustData = {};
		trustData.cbStruct = sizeof(trustData);
		trustData.dwUIChoice = WTD_UI_NONE;
		trustData.fdwRevocationChecks = WTD_REVOKE_NONE;  // 不做联网吊销检查
		trustData.dwUnionChoice = WTD_CHOICE_FILE;
		trustData.pFile = &fileInfo;
		trustData.dwStateAction = WTD_STATEACTION_VERIFY;
		trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

		// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
		GUID actionGuid = { 0x00AAC56B, 0xCD44, 0x11d0,
			{ 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };

		LONG status = WinVerifyTrust(nullptr, &actionGuid, &trustData);

		// ⚠️ 校验完必须关一次（`WTD_STATEACTION_CLOSE`），否则会泄漏状态句柄。
		trustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(nullptr, &actionGuid, &trustData);

		if (status == ERROR_SUCCESS) {
			return true;
		}

		// ⚠️⚠️ 关键回退：**目录签名（catalog）**。
		//
		//   `WTD_CHOICE_FILE` 只认**嵌入式**签名。但 Windows 大量系统程序
		//   （尤其是 .exe，如 System32\notepad.exe、以及很多系统 DLL）
		//   **没有嵌入式签名**，它们的签名放在 `System32\CatRoot\` 的
		//   catalog 文件里 —— 这类文件用 WTD_CHOICE_FILE 会返回
		//   `TRUST_E_NOSIGNATURE (0x800B0100)`。
		//
		//   v16 初版只做嵌入式校验，结果 notepad.exe 这类**微软目录签名**
		//   的系统程序被判"未签名" → 全挂 hook → 日志雪崩。
		//   （实测：sigcheck 对 notepad.exe 报 0x800B0100，而
		//     PowerShell Get-AuthenticodeSignature 报 Valid —— 差值就在这里。）
		//
		//   修法（微软官方两段式）：按文件算 hash → 找 catalog → 校验 catalog。
		if (status == static_cast<LONG>(TRUST_E_NOSIGNATURE)) {
			return IsCatalogTrusted(filePath, outCatalogFile, outCatalogChars);
		}

		return false;
	}

	// 综合判据：镜像是否"可信系统程序"（可以 bypass）。
	//
	// 调用前提：imagePath 已命中**具体文件白名单**（v20）。
	// 这里只回答"不落可写子目录 + 签名这一条件是否也满足"。
	//
	// ⚠️ v20：本函数不再做目录判断（白名单由 `IsWhitelistedSystemImage` 负责），
	//    只做「可写子目录双保险 + 微软签名」两项。
	bool IsTrustedSystemImage(PCWSTR imagePath) noexcept
	{
		// ---- ① 便宜检查优先：可写子目录直接否掉，不跑签名 ----
		//     规则层的匹配本身不区分大小写，不必预先转小写。
		if (IsInWritableWindowsSubdir(imagePath)) {
			return false;
		}

		// ---- ② 签名有效（嵌入式 → 回退 catalog）+ 签名者必须是微软 ----
		WCHAR catalogFile[MAX_PATH * 2] = {};
		if (!IsSignatureTrusted(imagePath, catalogFile, _countof(catalogFile))) {
			return false;
		}

		// ---- ③ 取签名者名 ----
		//
		// ⚠️ 两条路：
		//   · 有嵌入式签名 → 从目标文件里读（TryGetSignerName(imagePath)）
		//   · 目录签名 → 目标文件里没有签名，必须从 **catalog 文件**里读
		//     （catalog 自己就是 PKCS7 签名的，签名者 = 微软）
		WCHAR signerName[256] = {};
		bool gotSigner = TryGetSignerName(imagePath, signerName, _countof(signerName));

		if (!gotSigner && catalogFile[0] != L'\0') {
			gotSigner = TryGetSignerName(catalogFile, signerName, _countof(signerName));
		}

		if (!gotSigner) {
			// 有有效信任链但取不到发布者名（极少见）——保守按"非微软"处理。
			return false;
		}

		return IsMicrosoftSigner(signerName);
	}

	// 判定当前进程是否属于"系统程序"，是则完全不挂 hook。
	bool ComputeBypass(DWORD enginePid) noexcept	{
		DWORD pid = GetCurrentProcessId();

		// 0 = Idle，4 = System
		if (pid == 0 || pid == 4) {
			return true;
		}

		// 引擎自身也会被全局注入，必须放行，否则日志会自噬。
		if (enginePid != 0 && pid == enginePid) {
			return true;
		}

		WCHAR imagePath[MAX_PATH * 2] = {};
		DWORD size = _countof(imagePath);
		if (!QueryFullProcessImageName(GetCurrentProcess(), 0, imagePath, &size) || size == 0) {
			// ⚠️ v20.1 修复（原为 `return true`，是个结构性漏洞）：
			//
			//   原逻辑"拿不到镜像路径就保守放行"，本意是避免误伤。
			//   但 bypass = **一个 hook 都不挂** —— 一旦攻击者能让这次查询失败
			//   （注入时机上刚好退出、或在受限令牌下让
			//    PROCESS_QUERY_LIMITED_INFORMATION 被拒），
			//   它就直接绕过了全部监控，**而且日志里连一条记录都不会有**。
			//
			//   在 block_all / block_all_safe 下这个洞的后果最严重：那两个模式
			//   没有兜底判据（不看豁免、不看高危），bypass 就是完全隐身。
			//
			//   改为 `return false`（不 bypass → 挂全部 hook）：
			//   代价是极少数"查不到自己路径"的进程会多挂一层 hook，
			//   收益是堵住"查不到就隐身"这条路。权衡明显偏向安全性。
			//
			//   ⚠️ 注意：真正的系统核心进程（smss/csrss/…）**不可能**查不到
			//   自己的镜像路径，所以这个改动**不会**误伤系统进程 ——
			//   它们走的是下面的白名单分支返回 true。
			return false;
		}

		// 1) v20：**具体文件路径白名单** + 微软签名，才算系统程序。
		//
		//    ⚠️ v16 → v20 的收紧：
		//
		//      v16：目录在 `%SystemRoot%\` 下 + 微软签名 → bypass。
		//           这挡住了 `C:\Windows\Temp\evil.exe`，但**信任了整个
		//           System32 里任何微软签名的模块** —— 合法的微软签名组件
		//           被滥用（DLL 侧加载落点、被白利用的签名程序）照样 bypass。
		//
		//      v20：改成**白名单制**。只有 `kSystemImageWhitelist` 里**逐个列出
		//           的具体文件**（smss/csrss/wininit/winlogon/services/lsass/
		//           svchost/dwm/explorer 等核心系统进程）才可能 bypass；
		//           **System32 下未列出的文件，哪怕微软签名，也挂 hook**。
		//
		//    三条同时成立才 bypass：
		//      ① `IsWhitelistedSystemImage(imagePath)` —— 精确路径命中白名单
		//      ② `!IsInWritableWindowsSubdir(imagePath)` —— 不在可写子目录（双保险）
		//      ③ `IsSignatureTrusted` + `IsMicrosoftSigner` —— 微软签名
		//
		//    ⚠️ 顺序：先做最便宜的①（纯字符串全等），再做②，最后才跑签名③。
		if (IsWhitelistedSystemImage(imagePath)) {
			if (IsInWritableWindowsSubdir(imagePath)) {
				// 白名单命中但落在可写子目录 —— 理论上不该发生（白名单都是
				// System32 根下），留这条防御内部名单写错。
				LOG(L"R3ShieldCore: 白名单命中但落可写子目录，**不 bypass**（挂 hook）pid=%u path=%s",
					pid, imagePath);
				return false;
			}

			// ②+③ 通过 → bypass
			if (IsTrustedSystemImage(imagePath)) {
				LOG(L"R3ShieldCore: bypass（白名单文件 + 微软签名）pid=%u path=%s", pid, imagePath);
				return true;
			}

			// 白名单命中但签名不可信 → 不 bypass（挂全部 hook）。
			//
			// ⚠️ 可观测点：白名单里的核心系统进程若签名异常（被替换 / 被劫持），
			//    这里会留痕 —— 排查"为什么系统进程被监控了"看这条。
			LOG(L"R3ShieldCore: 白名单文件但签名不可信，**不 bypass**（挂 hook）pid=%u path=%s",
				pid, imagePath);
			return false;
		}

		// 1b) 已不在任何白名单里 → 不 bypass（挂 hook）。
		//
		//     ⚠️ v20 语义变化：以前 `%SystemRoot%\` 下的**所有**微软签名程序
		//        都 bypass，现在只有白名单里的才 bypass。System32 下大量
		//        未列出的系统程序（notepad.exe / 各种 .dll 宿主）会开始挂 hook。
		//        这是**有意的**（最严判据），代价是噪音上升 —— 若要减噪，
		//        正确方向是往 `kSystemImageWhitelist` 里补具体文件，
		//        **不要**退回目录前缀判据。
		//
		//     ⚠️ 只在"系统目录下"时才打日志，避免给普通第三方程序刷屏。
		{
			WCHAR windowsDirectory[MAX_PATH] = {};
			UINT windowsDirectoryLength = GetWindowsDirectory(windowsDirectory, _countof(windowsDirectory));
			if (windowsDirectoryLength > 0 && windowsDirectoryLength < _countof(windowsDirectory) &&
				StartsWithNoCase(imagePath, windowsDirectory)) {
				PCWSTR rest = imagePath + windowsDirectoryLength;
				if (*rest == L'\\' || *rest == L'/') {
					LOG(L"R3ShieldCore: 系统目录但不在白名单，**不 bypass**（挂 hook）pid=%u path=%s",
						pid, imagePath);
				}
			}
		}

		// 2) 商店应用：%ProgramFiles%\WindowsApps 下
		//
		//    ⚠️ WindowsApps 的目录 ACL 本身就只有 TrustedInstaller 可写，
		//    普通用户改不了；而且里面的包签名归各发行者（非微软的很多）。
		//    所以这里**保持只按目录判** —— 加签名条件会把正常的 Store 应用
		//    全挂上 hook（那些包本身是有效签名的，但发布者五花八门）。
		//
		//    如果后续要收紧，方向是"看包的 AppxManifest 里的 Publisher 属性"，
		//    而不是这份进程内的签名 —— 那属于包完整性校验，不在本层。
		WCHAR programFiles[MAX_PATH] = {};
		DWORD programFilesLength = GetEnvironmentVariable(L"ProgramFiles", programFiles, _countof(programFiles));
		if (programFilesLength > 0 && programFilesLength < _countof(programFiles)) {
			WCHAR windowsAppsPrefix[MAX_PATH + 16] = {};
			if (swprintf_s(windowsAppsPrefix, L"%s\\WindowsApps\\", programFiles) > 0 &&
				StartsWithNoCase(imagePath, windowsAppsPrefix)) {
				LOG(L"R3ShieldCore: bypass（WindowsApps 商店应用）pid=%u path=%s", pid, imagePath);
				return true;
			}
		}

		// 2b) ★ v24 修正：系统 UWP 应用 `%SystemRoot%\SystemApps\`
		//
		//    ⚠️ 实测漏洞（用户 VM 日志）：`TextInputHost.exe` 的路径是
		//       C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe
		//
		//       它**既不在** `kSystemImageWhitelist`（白名单只有 35 个核心进程），
		//       **也不在** `%ProgramFiles%\WindowsApps\`（那是商店应用的位置）。
		//       于是被判"不 bypass" → 挂全部 hook → 在 `block_all_safe` 下
		//       它写 `LocalState` 注册表被**直接拒**（日志里连拦 24 次），
		//       用户看到的就是"Windows 无法访问指定设备"。
		//
		//       这不是个例：`C:\Windows\SystemApps\` 下住着一批**系统自带的
		//       UWP 组件**（输入法 TextInputHost、ShellExperienceHost、
		//       StartMenuExperienceHost、SearchHost、Windows.CloudExperienceHost…），
		//       它们都是"系统目录 + 只有 TrustedInstaller 可写 + 微软签名"，
		//       本来就在 `IsTrustedLaunchImage` 的语义范围内，只是这里漏了。
		//
		//    判据（与 `IsTrustedLaunchImage` 保持一致，只按目录判，理由同上面 2）：
		//       · 路径以 `%SystemRoot%\SystemApps\` 开头
		//       · 再叠一次"不在可写子目录"防御（与白名单分支同款双保险）
		//       · SystemApps 的 ACL 只有 TrustedInstaller 可写，普通用户/样本
		//         无法把文件放进去，所以不需要额外签名校验（与 WindowsApps 同论）
		//
		//    ⚠️ 为什么不像白名单那样要求签名：SystemApps 里的包发布者可能是
		//       微软的各种子品牌（Contoso 测试包等），加签名条件容易误伤；
		//       而 ACL 已经把"能不能放文件进去"这件事锁死了 —— 目录本身是边界。
		{
			WCHAR windowsDirectory[MAX_PATH] = {};
			UINT windowsDirectoryLength = GetWindowsDirectory(windowsDirectory, _countof(windowsDirectory));
			if (windowsDirectoryLength > 0 && windowsDirectoryLength < _countof(windowsDirectory)) {
				WCHAR systemAppsPrefix[MAX_PATH + 16] = {};
				if (swprintf_s(systemAppsPrefix, L"%s\\SystemApps\\", windowsDirectory) > 0 &&
					StartsWithNoCase(imagePath, systemAppsPrefix) &&
					!IsInWritableWindowsSubdir(imagePath)) {
					LOG(L"R3ShieldCore: bypass（SystemApps 系统 UWP 应用）pid=%u path=%s", pid, imagePath);
					return true;
				}
			}
		}

		// 3) 策略里的用户自定义排除项
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy) {
			ULONG count = policy->ExcludePathCount;
			if (count > R3ShieldCore::MaxExcludePaths) {
				count = R3ShieldCore::MaxExcludePaths;
			}

			for (ULONG i = 0; i < count; i++) {
				if (policy->ExcludePaths[i][0] != L'\0' && StartsWithNoCase(imagePath, policy->ExcludePaths[i])) {
					return true;
				}
			}
		}

		return false;
	}

	// 用 NtQueryKey(KeyNameInformation) 把句柄还原成完整路径。
	// 走的是 trampoline，不会再进自己的 hook，所以不存在递归。
	ULONG ResolveKeyPath(HANDLE keyHandle, WCHAR* buffer, ULONG capacity) noexcept
	{
		if (!keyHandle || !pOriginalNtQueryKey || capacity == 0) {
			return 0;
		}

		constexpr ULONG KeyNameInformation = 3;

		struct KEY_NAME_INFORMATION_LOCAL
		{
			ULONG NameLength;
			WCHAR Name[1];
		};

		BYTE raw[sizeof(ULONG) + (R3ShieldCore::MaxKeyPathChars + 1) * sizeof(WCHAR)] = {};
		ULONG resultLength = 0;

		NTSTATUS status = pOriginalNtQueryKey(keyHandle, KeyNameInformation, raw, sizeof(raw), &resultLength);
		if (status < 0) {
			return 0;
		}

		auto* information = reinterpret_cast<KEY_NAME_INFORMATION_LOCAL*>(raw);
		ULONG chars = information->NameLength / sizeof(WCHAR);
		// 留一格给结尾 NUL：调用方拿到的 KeyPath 要能当 C 字符串用
		// （日志和前缀比较都依赖这一点）。
		if (chars >= capacity) {
			chars = capacity - 1;
		}

		if (chars > 0) {
			memcpy(buffer, information->Name, chars * sizeof(WCHAR));
		}

		return chars;
	}

	void CopyUnicodeString(const RG_UNICODE_STRING* source, WCHAR* destination, ULONG capacity, ULONG& length) noexcept
	{
		length = 0;
		if (!source || !source->Buffer || source->Length == 0) {
			return;
		}

		ULONG chars = source->Length / sizeof(WCHAR);
		if (chars > capacity) {
			chars = capacity;
		}

		memcpy(destination, source->Buffer, chars * sizeof(WCHAR));
		length = chars;
	}

	//
	// 把文件句柄还原成路径，用于 hive 级操作（NtSaveKey / NtRestoreKey 等
	// 拿的是文件句柄而不是路径字符串）。
	//
	// 用 NtQueryObject(ObjectNameInformation=1)，和 NtQueryKey 同理：
	// NtQueryObject 不挂 hook，只取干净函数指针，不可能递归。
	//
	// 拿到的会是 \Device\HarddiskVolume2\Tools\x.hiv 这种设备路径。
	// 转成 DOS 路径要查盘符映射，代价高且不保证成功 —— 这里就保留设备路径，
	// 对识别"这是本地磁盘文件"和做前缀比较已经够用，日志里也看得懂。
	//
	typedef NTSTATUS(NTAPI* NtQueryObjectPtr)(HANDLE, ULONG, PVOID, ULONG, PULONG);
	NtQueryObjectPtr pOriginalNtQueryObject = nullptr;

	ULONG ResolveObjectPath(HANDLE objectHandle, WCHAR* buffer, ULONG capacity) noexcept
	{
		if (!objectHandle || !pOriginalNtQueryObject || capacity == 0) {
			return 0;
		}

		constexpr ULONG ObjectNameInformation = 1;

		// OBJECT_NAME_INFORMATION 就是 { UNICODE_STRING Name; WCHAR Buffer[]; }
		// 这里按本文件的本地类型展开，避免牵进 winternl.h。
		struct OBJECT_NAME_INFORMATION_LOCAL
		{
			RG_UNICODE_STRING Name;
			WCHAR Buffer[1];
		};

		BYTE raw[sizeof(OBJECT_NAME_INFORMATION_LOCAL) + (R3ShieldCore::MaxKeyPathChars + 1) * sizeof(WCHAR)] = {};
		ULONG resultLength = 0;

		NTSTATUS status = pOriginalNtQueryObject(objectHandle, ObjectNameInformation, raw, sizeof(raw), &resultLength);
		if (status < 0) {
			return 0;
		}

		auto* information = reinterpret_cast<OBJECT_NAME_INFORMATION_LOCAL*>(raw);
		ULONG chars = information->Name.Length / sizeof(WCHAR);
		if (chars >= capacity) {
			chars = capacity - 1;
		}

		if (chars > 0 && information->Name.Buffer) {
			memcpy(buffer, information->Name.Buffer, chars * sizeof(WCHAR));
		}

		return chars;
	}

	// 把设备路径 \Device\HarddiskVolumeN\Foo 转成盘符路径 C:\Foo。
	// 转不了就原样保留（调用方拿到设备路径也比什么都没有强）。
	//
	// 只在日志/弹窗路径上调用，不追求覆盖所有情况：
	// 卷影副本、网络重定向、命名管道都会退回原样。
	bool DevicePathToDosPath(WCHAR* path, ULONG capacity) noexcept
	{
		if (capacity == 0 || _wcsnicmp(path, L"\\Device\\", 8) != 0) {
			return false;
		}

		// \Device\HarddiskVolumeN 之后就是卷内相对路径
		PCWSTR rest = path + 8;
		PCWSTR slash = wcschr(rest, L'\\');
		if (!slash) {
			return false;
		}

		size_t deviceNameChars = static_cast<size_t>(slash - path);

		WCHAR deviceName[R3ShieldCore::MaxImagePathChars] = {};
		if (deviceNameChars >= _countof(deviceName)) {
			return false;
		}

		wcsncpy_s(deviceName, path, deviceNameChars);

		// 枚举 A: 到 Z:，用 QueryDosDevice 找出哪个盘符指向这个设备
		for (WCHAR letter = L'A'; letter <= L'Z'; letter++) {
			WCHAR drive[3] = { letter, L':', L'\0' };
			WCHAR target[R3ShieldCore::MaxImagePathChars] = {};
			if (QueryDosDevice(drive, target, _countof(target)) == 0) {
				continue;
			}

			if (_wcsicmp(target, deviceName) != 0) {
				continue;
			}

			// 拼成 C: + \卷内剩余路径
			WCHAR converted[R3ShieldCore::MaxKeyPathChars] = {};
			if (swprintf_s(converted, L"%s%s", drive, slash) < 0) {
				return false;
			}

			if (wcslen(converted) >= capacity) {
				return false;
			}

			wcscpy_s(path, capacity, converted);
			return true;
		}

		return false;
	}

	// 解析并落进 event：设备路径 → 尽量转 DOS 路径 → 拷贝。
	void CaptureFileHandlePath(HANDLE fileHandle, R3ShieldCore::Event& event) noexcept
	{
		if (!fileHandle || fileHandle == INVALID_HANDLE_VALUE) {
			return;
		}

		WCHAR path[R3ShieldCore::MaxKeyPathChars] = {};
		ULONG chars = ResolveObjectPath(fileHandle, path, _countof(path));
		if (chars == 0) {
			return;
		}

		path[chars] = L'\0';
		DevicePathToDosPath(path, _countof(path));

		// hive 文件路径借用 ValueName 字段（KeyPath 留给"挂到哪里/导出哪个键"）。
		wcsncpy_s(event.ValueName, path, _TRUNCATE);
		event.ValueNameLength = static_cast<ULONG>(wcslen(event.ValueName));
		event.Flags |= R3ShieldCore::FlagEventHiveFile;
	}

	void Publish(R3ShieldCore::Event& event) noexcept
	{
		if (!R3ShieldCoreChannel::IsOpen()) {
			return;
		}

		event.Sequence = 0;
		event.TimeStamp = NowFileTime();
		event.ProcessId = GetCurrentProcessId();
		event.ThreadId = GetCurrentThreadId();

		R3ShieldCoreChannel::Publish(event);
	}

	// 询问模式的兜底结论：用户不答或答不上来时怎么办。
	R3ShieldCore::Verdict PromptFallbackVerdict() noexcept
	{
		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		if (policy && policy->PromptDefaultVerdict <= static_cast<ULONG>(R3ShieldCore::Verdict::DenyAlways)) {
			return static_cast<R3ShieldCore::Verdict>(policy->PromptDefaultVerdict);
		}

		return R3ShieldCore::Verdict::Deny;
	}

	//
	// 这个键是否属于"Windows 自己运行时要写的基础设施"，不该问用户。
	//
	// 为什么需要这个：实测 COM 基础设施（ComBase）会持续对
	// \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows 这类键调用
	// NtCreateKey / NtSetInformationKey —— 25 秒内 158 次。
	// ASK 模式如果照单全问，就是给用户一个弹窗机关枪；更糟的是
	// 用户点"拒绝"后 COM 初始化失败会立刻重试，形成弹窗死循环。
	//
	// 判定用**路径前缀**而不是"键属于哪个 hive"：
	//   - HKLM 下并非全都是系统键（第三方软件也装在那）
	//   - 但 SOFTWARE\Microsoft\Windows、Cryptography、COM3 这些
	//     是 Windows 自身组件在跑，用户没有判断依据
	//
	// 命中则**只记录不问**（仍然是可见的，只是不打扰用户）。
	bool IsSystemInfrastructureKey(PCWSTR keyPath) noexcept
	{
		if (!keyPath || keyPath[0] == L'\0') {
			return false;
		}

		// 去掉可能存在的 \REGISTRY\MACHINE\ 前缀，统一成从 SOFTWARE 开始比。
		PCWSTR path = keyPath;
		if (_wcsnicmp(path, L"\\REGISTRY\\MACHINE\\", 18) == 0) {
			path += 18;
		}
		else if (_wcsnicmp(path, L"\\REGISTRY\\USER\\", 15) == 0) {
			// 用户 hive 里的系统组件路径，比如
			// S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\...
			// 这里不做精细判定，交给下面的通用前缀。
			PCWSTR slash = wcschr(path + 15, L'\\');
			if (slash) {
				path = slash + 1;
			}
		}

		static const PCWSTR prefixes[] = {
			L"SOFTWARE\\Microsoft\\Windows",
			L"Software\\Microsoft\\Windows",
			L"SOFTWARE\\Microsoft\\Cryptography",
			L"Software\\Microsoft\\Cryptography",
			L"SOFTWARE\\Microsoft\\COM3",
			L"Software\\Microsoft\\COM3",
			L"SOFTWARE\\Microsoft\\SystemCertificates",
			L"Software\\Microsoft\\SystemCertificates",
			L"SOFTWARE\\Microsoft\\OLE",
			L"Software\\Microsoft\\OLE",
			L"SOFTWARE\\Policies\\Microsoft\\Cryptography",
			L"Software\\Policies\\Microsoft\\Cryptography",
			L"SOFTWARE\\Microsoft\\AppModel",
			L"Software\\Microsoft\\AppModel",
			L"SYSTEM\\ControlSet",
			L"System\\ControlSet",
			L"SOFTWARE\\Classes",
			L"Software\\Classes",
			L"SOFTWARE\\Microsoft\\MMDevices",
			L"Software\\Microsoft\\MMDevices",
		};

		for (PCWSTR prefix : prefixes) {
			size_t length = wcslen(prefix);
			if (_wcsnicmp(path, prefix, length) != 0) {
				continue;
			}

			// 要求边界落在 '\' 上，避免 SOFTWARE\Microsoft\WindowsApps 之类误命中
			WCHAR next = path[length];
			if (next == L'\0' || next == L'\\') {
				return true;
			}
		}

		return false;
	}

	// 核心判定。绝不抛异常、绝不分配内存。
	//
	// targetKind 用来区分 KeyPath 里放的是键路径还是 hive 文件路径：
	//   TargetKind::Key  → 正常情况，keyHandle 优先、objectName 兜底
	//   TargetKind::Hive → KeyPath 直接取 objectName（键的目标位置），
	//                      hive 文件本身另由调用方通过 CaptureFileHandlePath 填进 ValueName
	Action Evaluate(
		R3ShieldCore::Op op,
		HANDLE keyHandle,
		const RG_UNICODE_STRING* objectName,
		const RG_UNICODE_STRING* valueName,
		ULONG desiredAccess,
		R3ShieldCore::Event& event,
		bool blockable) noexcept
	{
		ZeroMemory(&event, sizeof(event));

		event.Op = static_cast<ULONG>(op);
		event.DesiredAccess = desiredAccess;
		event.TargetKind = static_cast<ULONG>(R3ShieldCore::IsHiveOp(static_cast<ULONG>(op))
			? R3ShieldCore::TargetKind::Hive
			: R3ShieldCore::TargetKind::Key);

		// hive 级操作没有键句柄，ObjectName 描述的是"挂到哪 / 导出哪个子树"。
		if (keyHandle) {
			event.KeyPathLength = ResolveKeyPath(keyHandle, event.KeyPath, static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars));
		}
		else if (objectName) {
			CopyUnicodeString(objectName, event.KeyPath, static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars), event.KeyPathLength);
		}

		// hive 级操作的"值名"槽位要留给文件路径，不能被 valueName 占掉。
		if (valueName && !R3ShieldCore::IsHiveOp(static_cast<ULONG>(op))) {
			CopyUnicodeString(valueName, event.ValueName, static_cast<ULONG>(R3ShieldCore::MaxValueNameChars), event.ValueNameLength);
		}

		// NtOpenKey 默认只关心带写意图的打开。
		if (op == R3ShieldCore::Op::OpenKey) {
			R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
			bool logAllOpens = policy && (policy->Flags & R3ShieldCore::FlagLogAllOpen) != 0;
			if (!logAllOpens && !IsWriteAccess(desiredAccess)) {
				return Action::Pass;
			}
		}

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();
		ULONG mode = policy ? policy->Mode : static_cast<ULONG>(R3ShieldCore::Mode::Log);

		// ---- 完全拦截模式（ini: mode=block_all / block_all_safe）----
		//
		// ★ v66：**不再弹窗**（撤销 v25/v26 的"先问再拦"）。判定顺序：
		//
		//   ① `ShouldAskInsteadOfBlockAll` = false
		//        → **直接拒**。这一档覆盖了高危规则表命中（持久化落点）、
		//          Windows 基础设施键、hive 级操作、COM+ 目录。
		//          **恶意样本的注册表持久化全落在这里。**
		//
		//   ② = true（非高危、非基础设施的普通写入）
		//        → **静默放行**（原来是弹窗）。
		//
		//   ★ 为什么 ② 是"放行"而不是"拒" —— 这是"全拦但不影响程序启动"
		//     这条要求唯一必须让步的地方：
		//       ② 这一档就是"**正常软件写自己的配置**"。v25 的实测事故正是
		//       把它静默拒掉 ⇒ 系统弹「Windows 无法访问指定设备、路径或文件」
		//       （0xC0000022）且没有任何提示 ⇒ 用户报"桌面软件全打不开"。
		//       所以对 ② 一律拒 = 原样复现 v25 事故，与"不影响程序启动"直接冲突。
		//   ★ 与 v26 的降级放行**同向**（不是新发明）：v26 已经认定这一档
		//     "通道不在时放行比静默全拒更符合原意"。v66 只是把
		//     "通道不在才放行"改成"一律放行"，同时把"问"彻底去掉。
		//   ★ 安全边界**没有降低**：样本的持久化落点全在 ①（`= false`）那一档，
		//     照样直接拒，连记录之外的任何机会都没有。
		//
		// 注意：这个分支**抢在后面的基础设施豁免之前**执行，所以
		// `ShouldAskInsteadOfBlockAll` 必须自己再判一遍基础设施键
		// （已经在规则层做了，见 r3shieldcore_rules.cpp）。
		if (R3ShieldCore::IsAnyBlockAllMode(mode)) {
			const bool askable = R3ShieldCoreRules::ShouldAskInsteadOfBlockAll(
				event.KeyPath, event.ValueName, static_cast<ULONG>(op));

			// ② 非高危、非基础设施的普通写入 → 静默放行（不弹窗、不问用户）。
			//
			//    `op == OpenKey` 不算 —— 它本来就只有"读意图"，与写入无关，
			//    让下面那档统一处理（与 v25 起的口径一致）。
			if (askable && op != R3ShieldCore::Op::OpenKey) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return Action::Record;
			}

			// ① 高危持久化落点 / Windows 基础设施键 / hive 级 / COM+ 目录
			//    → 直接拒，连问都不问。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			return Action::Block;
		}

		if (!blockable) {
			// 读操作永远只记录。
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		//
		// 高危判定。优先级高于 Mode —— 写自启动、改服务、动 SAM 这类操作
		// 哪怕用户当前开的是 log 模式，也不该静默通过。
		//
		// 命中后强行走询问路径（下面的 Ask 分支），RiskLevel 标 High。
		//
		bool highRisk = false;
		if (!policy || (policy->Flags & R3ShieldCore::FlagHighRiskGuard) != 0) {
			if (R3ShieldCoreRules::IsHighRiskRegistry(event.KeyPath, event.ValueName,
					static_cast<ULONG>(op))) {
				highRisk = true;
				event.RiskLevel = static_cast<ULONG>(R3ShieldCore::RiskLevel::High);
				event.Flags |= R3ShieldCore::FlagEventHighRisk;
			}
		}

		// BLOCK is the daily-use active-defense mode: benign application
		// configuration writes must continue to work. Only a high-confidence
		// persistence, hijack, credential, or hive operation is blocked below.
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block) && !highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
			return Action::Record;
		}

		// Do not enter the prompt path in BLOCK. Prompt availability depends on
		// integrity/session boundaries and a missing channel must never turn an
		// active-defense decision into an unexplained access-denied result.
		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Block) && highRisk) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
				InterlockedIncrement(&channel->HighRiskBlocked);
			}
			return Action::Block;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log)) {
			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
			return Action::Record;
		}

		if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Ask)) {
			// 开键这一步不问。否则一次写入会被问两遍：先问"要打开这个键"，
			// 再问"要写这个值"。开键只记录，真正的判定留给写操作。
			//
			// 但高危的 OpenKey 例外 —— 比如以写意图打开 SAM，这本身就是
			// 值得让用户看到的事。
			if (op == R3ShieldCore::Op::OpenKey && !highRisk) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return Action::Record;
			}

			// Windows 自身运行时要写的基础设施键，只记录不问。
			// 问用户没有意义（用户没有判断依据），而且这类调用极其频繁，
			// 问了会变成弹窗机关枪；用户点"拒绝"还会诱发重试形成死循环。
			//
			// 高危规则优先于这条豁免 —— 规则表已经排除了高频路径，
			// 能命中说明确实是要害位置。
			if (!highRisk && IsSystemInfrastructureKey(event.KeyPath)) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return Action::Record;
			}

			// ------------------------------------------------------------------
			// ★ v28：LOG 模式下"该问但问不出去" → 降级放行（★ 同 block-all 分支）
			// ------------------------------------------------------------------
			//
			// ★ 为什么必须补这一段（用户实报，2026-09-30）：
			//   `mode=log` + `high_risk=1` 时，高危写**照样进这个分支**（见上面的
			//   `|| highRisk`），然后调 `Ask()`。而 `Ask()` 在询问通道拿不到时
			//   **立刻返回 fallback**（`prompt_default=deny`）→ 下面把 deny 当
			//   "用户拒绝" → `Action::Block` → 调用方拿 `STATUS_ACCESS_DENIED`
			//   → 用户看到「Windows 无法访问指定设备、路径或文件」(0xC0000022)
			//   **且界面上没有任何弹窗**。
			//
			//   触发条件：引擎**以管理员启动** → 跨完整性级别 / UIPI / 会话边界
			//   → 被注入进程 `OpenFileMapping` 打不开引擎的询问通道
			//   → `IsOpen() == false`。用户原话：「用管理员就会炸」。
			//
			//   `mode=log` 的承诺是"只记录、全部放行"（r3shieldcore.ini 第 3 行）。
			//   静默拒直接违背这个承诺 —— 既拦了用户，又没告诉他。
			//
			// ★ v26 只修了 block_all 分支（见上面的 IsAnyBlockAllMode 段），
			//   漏了这条常规分支。本轮补上，语义与 v26 完全一致。
			//
			// ★ 安全边界不降：
			//   · **仅 LOG 模式**降级。BLOCK / ASK 是用户明确表达的"要拦 / 要问"，
			//     通道坏了也不该放行（真正需要拦住高危的是这两档）；
			//   · LOG 本来就不承诺拦高危，降级只是回到"如实记录"。
			//
			// ★ 与 v26 一致：必须打 `FlagEvent2AskUnavailable`
			//   （日志出 `[ASK-UNAVAIL→ALLOW]`），否则这类"静默拒"事后完全看不出。
			const bool promptAvailable = R3ShieldCorePrompt::IsOpen();

			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !promptAvailable) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
				return Action::Record;
			}

			// 同一次 Win32 调用可能先打开再写。如果一个线程已经在为同一个
			// 键等用户答复，后续 Nt 调用直接按兜底走，不再弹第二个窗。
			//
			// Ask 会拿 event 里的进程/线程/时间做展示和去重，这里先补齐。
			event.ProcessId = GetCurrentProcessId();
			event.ThreadId = GetCurrentThreadId();
			event.TimeStamp = NowFileTime();

			// 计数器必须写在 Events 通道头里 —— Policy 是只读映射（FILE_MAP_READ），
			// 往 policy->HighRiskAsked 写会直接 0xC0000005。
			if (highRisk) {
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskAsked);
				}
			}

			R3ShieldCore::Verdict verdict = R3ShieldCorePrompt::Ask(event, PromptFallbackVerdict());

			if (verdict == R3ShieldCore::Verdict::Allow || verdict == R3ShieldCore::Verdict::AllowAlways) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Allowed);
				return Action::Record;
			}

			// ★ v28：通道在"调用中失效"（引擎退出）→ LOG 模式同样降级放行。
			//   与 v26 的第二次补探逐字同构。
			if (mode == static_cast<ULONG>(R3ShieldCore::Mode::Log) && !R3ShieldCorePrompt::IsOpen()) {
				event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
				event.Flags2 |= R3ShieldCore::FlagEvent2AskUnavailable;
				return Action::Record;
			}

			event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::Blocked);
			if (highRisk) {
				if (R3ShieldCore::ChannelHeader* channel = R3ShieldCoreChannel::Channel()) {
					InterlockedIncrement(&channel->HighRiskBlocked);
				}
			}
			return Action::Block;
		}

		event.Decision = static_cast<ULONG>(R3ShieldCore::Decision::WouldBlock);
		return Action::Record;
	}

	// 调用成功后用真实句柄补全路径，失败就保留 ObjectName 里的原始值。
	void RefineKeyPath(HANDLE keyHandle, R3ShieldCore::Event& event) noexcept
	{
		ULONG length = ResolveKeyPath(keyHandle, event.KeyPath, static_cast<ULONG>(R3ShieldCore::MaxKeyPathChars));
		if (length > 0) {
			event.KeyPathLength = length;
		}
	}

	// ==================================================================
	// 写类 hook —— 可拦截
	// ==================================================================
	NTSTATUS NTAPI NtCreateKey_Hook(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
		const RG_OBJECT_ATTRIBUTES* ObjectAttributes, ULONG TitleIndex,
		RG_UNICODE_STRING* Class, ULONG CreateOptions, PULONG Disposition)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::CreateKey, nullptr,
				ObjectAttributes ? ObjectAttributes->ObjectName : nullptr, nullptr,
				DesiredAccess, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtCreateKey(KeyHandle, DesiredAccess, ObjectAttributes,
				TitleIndex, Class, CreateOptions, Disposition);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);

				if (status >= 0 && KeyHandle) {
					__try {
						RefineKeyPath(*KeyHandle, event);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
					}
				}

				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtOpenKey_Hook(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
		const RG_OBJECT_ATTRIBUTES* ObjectAttributes)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::OpenKey, nullptr,
				ObjectAttributes ? ObjectAttributes->ObjectName : nullptr, nullptr,
				DesiredAccess, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);

				if (status >= 0 && KeyHandle) {
					__try {
						RefineKeyPath(*KeyHandle, event);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
					}
				}

				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtOpenKeyEx_Hook(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
		const RG_OBJECT_ATTRIBUTES* ObjectAttributes, ULONG OpenOptions)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::OpenKey, nullptr,
				ObjectAttributes ? ObjectAttributes->ObjectName : nullptr, nullptr,
				DesiredAccess, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);

				if (status >= 0 && KeyHandle) {
					__try {
						RefineKeyPath(*KeyHandle, event);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
					}
				}

				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

		NTSTATUS NTAPI NtSetValueKey_Hook(HANDLE KeyHandle, const RG_UNICODE_STRING* ValueName,
			ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
		{
			InterlockedIncrement(&g_activeHooks);

			R3ShieldCore::Event event;
			Action action = Action::Pass;
			NTSTATUS status = STATUS_UNSUCCESSFUL;

			__try {
				action = Evaluate(R3ShieldCore::Op::SetValueKey, KeyHandle, nullptr, ValueName, 0, event, true);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				 action = ExceptionAction(event);
			}

			if (action == Action::Block) {
				event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
				Publish(event);
				status = STATUS_ACCESS_DENIED;
			}
			else {
				status = pOriginalNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);

				if (action == Action::Record) {
					event.Status = static_cast<ULONG>(status);
					Publish(event);
				}

				// ---- 宿主劫持补充判定（v15）----
				//
				// ⚠️ 注册表规则是按**键前缀**粗筛的（比如 HKLM\Software\Microsoft\
				//    Windows NT\CurrentVersion\Windows 整块），粒度不足以区分
				//    "写了 AppInit_DLLs 值指向用户目录" 这种真劫持。这里把
				//    "键路径 + 值名 + 值内容"三件套交给 HostHijackGuard 精判。
				//
				// 只在写入成功（status >= 0）后做，且必须是 REG_SZ / REG_EXPAND_SZ
				// 这类可含路径的类型 —— 二进制值（REG_BINARY）不构成"劫持路径"。
				if (status >= 0 && (Type == REG_SZ || Type == REG_EXPAND_SZ)) {
					__try {
						WCHAR keyPath[R3ShieldCore::MaxKeyPathChars] = {};
						ResolveKeyPath(KeyHandle, keyPath, R3ShieldCore::MaxKeyPathChars);

						WCHAR valueNameBuf[256] = {};
						if (ValueName && ValueName->Buffer && ValueName->Length > 0) {
							const size_t chars = ValueName->Length / sizeof(WCHAR);
							const size_t copy = chars < (_countof(valueNameBuf) - 1) ? chars : (_countof(valueNameBuf) - 1);
							wmemcpy_s(valueNameBuf, _countof(valueNameBuf), ValueName->Buffer, copy);
						}

						// REG_SZ 的 Data 可能是非 NUL 结尾的，按 DataSize 手动截。
						WCHAR valueBuf[R3ShieldCore::MaxKeyPathChars] = {};
						if (Data && DataSize >= sizeof(WCHAR)) {
							const size_t chars = (DataSize / sizeof(WCHAR));
							const size_t copy = chars < (_countof(valueBuf) - 1) ? chars : (_countof(valueBuf) - 1);
							wmemcpy_s(valueBuf, _countof(valueBuf), static_cast<PCWSTR>(Data), copy);
							valueBuf[copy] = L'\0';
						}

						if (keyPath[0]) {
							HostHijackGuard::EvaluateInjectionKeyWrite(keyPath, valueNameBuf, valueBuf);
						}
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
					}
				}
			}

			InterlockedDecrement(&g_activeHooks);
			return status;
		}

	NTSTATUS NTAPI NtDeleteKey_Hook(HANDLE KeyHandle)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::DeleteKey, KeyHandle, nullptr, nullptr, 0, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtDeleteKey(KeyHandle);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtDeleteValueKey_Hook(HANDLE KeyHandle, const RG_UNICODE_STRING* ValueName)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::DeleteValueKey, KeyHandle, nullptr, ValueName, 0, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtDeleteValueKey(KeyHandle, ValueName);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtRenameKey_Hook(HANDLE KeyHandle, const RG_UNICODE_STRING* NewName)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::RenameKey, KeyHandle, nullptr, NewName, 0, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtRenameKey(KeyHandle, NewName);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// NtSetInformationKey —— 改键的名字或标志位。
	//
	// KeySetInformationClass 的取值（实测 + 公开文档）：
	//   1 = KeyWriteTimeInformation   改"最后写入时间"
	//   2 = KeyWow64FlagsInformation  改 32/64 位重定向标志
	//
	// ⚠ 实测结论：class 1 是**高频**调用，绝不能进 ASK 判定。
	//
	// COM 基础设施（ComBase）、加密服务（Cryptography\OID）、证书自动更新
	// （SystemCertificates\AuthRoot）都会持续用 class 1 打时间戳。
	// 实测 25 秒内 class 1 触发 158 次，全部打在
	// \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows 这类系统键上 ——
	// ASK 模式下每次都会弹窗，等于给用户一个弹窗机关枪，
	// 而且用户点"拒绝"后 COM 初始化失败会重试，形成弹窗死循环。
	//
	// 所以按 class 分流：
	//   class 2（WOW64 重定向绕过）→ 真正的威胁，走完整 ASK 判定
	//   其余 class（含 class 1）   → 只记录，永不询问
	//
	// 这是个取舍：放弃拦截"时间戳伪造"（价值低，且误伤面大），
	// 保住拦截"WOW64 重定向绕过"（价值高，调用极少）。
	constexpr ULONG KeyWow64FlagsInformation = 2;

	NTSTATUS NTAPI NtSetInformationKey_Hook(HANDLE KeyHandle, ULONG KeySetInformationClass,
		PVOID KeySetInformation, ULONG KeySetInformationLength)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// 只有 WOW64 重定向这一类才值得问用户。
		// 其余（尤其是高频的 class 1 时间戳）一律只记录。
		const bool blockable = (KeySetInformationClass == KeyWow64FlagsInformation);

		__try {
			// DesiredAccess 复用来带 class，日志里能看出改的是哪一类信息。
			action = Evaluate(R3ShieldCore::Op::SetInformationKey, KeyHandle, nullptr, nullptr,
				KeySetInformationClass, event, blockable);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtSetInformationKey(KeyHandle, KeySetInformationClass,
				KeySetInformation, KeySetInformationLength);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// NtFlushKey —— 强制把内存里的键刷到磁盘。
	// 本身不改变注册表内容，但"写盘时机"这个动作值得记录，不拦截。
	NTSTATUS NTAPI NtFlushKey_Hook(HANDLE KeyHandle)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;

		__try {
			action = Evaluate(R3ShieldCore::Op::FlushKey, KeyHandle, nullptr, nullptr, 0, event, false);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		NTSTATUS status = pOriginalNtFlushKey(KeyHandle);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// Hive 级 hook —— 可拦截
	//
	// 这一类是整个模块补上的最大缺口。它们不吃键句柄，吃的是
	// OBJECT_ATTRIBUTES：TargetKey 描述"挂到哪里 / 导出哪个子树"，
	// SourceFile 描述"用哪个 hive 文件"。
	//
	// 典型滥用：
	//   NtLoadKey(HKLM\SYSTEM 下的某个位置, evil.hiv)  → 整棵子树被换掉
	//   NtSaveKey(HKLM\SAM, out.hiv)                   → 拖走 SAM 去离线破密码
	//   NtRestoreKey(HKLM\SYSTEM\...\Services, evil.hiv) → 静默覆盖服务配置
	// ==================================================================
	NTSTATUS NTAPI NtLoadKey_Hook(const RG_OBJECT_ATTRIBUTES* TargetKey, const RG_OBJECT_ATTRIBUTES* SourceFile)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::LoadKey, nullptr,
				TargetKey ? TargetKey->ObjectName : nullptr, nullptr, 0, event, true);

			if (SourceFile && SourceFile->ObjectName) {
				CaptureFileHandlePath(nullptr, event);
				CopyUnicodeString(SourceFile->ObjectName, event.ValueName,
					static_cast<ULONG>(R3ShieldCore::MaxValueNameChars), event.ValueNameLength);
				event.Flags |= R3ShieldCore::FlagEventHiveFile;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtLoadKey(TargetKey, SourceFile);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtLoadKeyEx_Hook(const RG_OBJECT_ATTRIBUTES* TargetKey, const RG_OBJECT_ATTRIBUTES* SourceFile,
		ULONG Flags, HANDLE TrustClassKey, HANDLE Event, ULONG DesiredAccess, PVOID Private, PULONG Disposition)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::LoadKeyEx, nullptr,
				TargetKey ? TargetKey->ObjectName : nullptr, nullptr, DesiredAccess, event, true);

			if (SourceFile && SourceFile->ObjectName) {
				CopyUnicodeString(SourceFile->ObjectName, event.ValueName,
					static_cast<ULONG>(R3ShieldCore::MaxValueNameChars), event.ValueNameLength);
				event.Flags |= R3ShieldCore::FlagEventHiveFile;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtLoadKeyEx(TargetKey, SourceFile, Flags, TrustClassKey,
				Event, DesiredAccess, Private, Disposition);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// NtUnloadKey —— 把 hive 从注册表树上摘下来。
	// 可以用来把某个防护组件依赖的子树整个卸掉。
	NTSTATUS NTAPI NtUnloadKey_Hook(const RG_OBJECT_ATTRIBUTES* TargetKey)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::UnloadKey, nullptr,
				TargetKey ? TargetKey->ObjectName : nullptr, nullptr, 0, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtUnloadKey(TargetKey);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtUnloadKeyEx_Hook(const RG_OBJECT_ATTRIBUTES* TargetKey, HANDLE Event)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::UnloadKeyEx, nullptr,
				TargetKey ? TargetKey->ObjectName : nullptr, nullptr, 0, event, true);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtUnloadKeyEx(TargetKey, Event);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// NtSaveKey / NtSaveKeyEx —— 把键导出成 hive 文件。
	// KeyHandle 是被导出的键，FileHandle 是落盘目标。
	NTSTATUS NTAPI NtSaveKey_Hook(HANDLE KeyHandle, HANDLE FileHandle)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::SaveKey, KeyHandle, nullptr, nullptr, 0, event, true);

			if (action != Action::Pass) {
				CaptureFileHandlePath(FileHandle, event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtSaveKey(KeyHandle, FileHandle);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtSaveKeyEx_Hook(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::SaveKeyEx, KeyHandle, nullptr, nullptr, Format, event, true);

			if (action != Action::Pass) {
				CaptureFileHandlePath(FileHandle, event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtSaveKeyEx(KeyHandle, FileHandle, Format);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// NtRestoreKey —— 用 hive 文件的内容覆盖一个现有键。
	// 比 NtLoadKey 更隐蔽：不需要挂载点，直接原地替换。
	NTSTATUS NTAPI NtRestoreKey_Hook(HANDLE KeyHandle, HANDLE FileHandle, ULONG Flags)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::RestoreKey, KeyHandle, nullptr, nullptr, Flags, event, true);

			if (action != Action::Pass) {
				CaptureFileHandlePath(FileHandle, event);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = ExceptionAction(event);
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtRestoreKey(KeyHandle, FileHandle, Flags);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// NtReplaceKey —— 原子替换：把 NewFile 的内容变成 TargetKey 的内容，
	// 原内容落到 BackupFile。是 NtRestoreKey 的底层实现。
	NTSTATUS NTAPI NtReplaceKey_Hook(const RG_OBJECT_ATTRIBUTES* NewFile, HANDLE TargetKey,
		const RG_OBJECT_ATTRIBUTES* BackupFile)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		__try {
			action = Evaluate(R3ShieldCore::Op::ReplaceKey, TargetKey, nullptr, nullptr, 0, event, true);

			if (NewFile && NewFile->ObjectName) {
				CopyUnicodeString(NewFile->ObjectName, event.ValueName,
					static_cast<ULONG>(R3ShieldCore::MaxValueNameChars), event.ValueNameLength);
				event.Flags |= R3ShieldCore::FlagEventHiveFile;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = Action::Pass;
		}

		if (action == Action::Block) {
			event.Status = static_cast<ULONG>(STATUS_ACCESS_DENIED);
			event.Flags |= R3ShieldCore::FlagEventBlocked;
			Publish(event);
			status = STATUS_ACCESS_DENIED;
		}
		else {
			status = pOriginalNtReplaceKey(NewFile, TargetKey, BackupFile);

			if (action == Action::Record) {
				event.Status = static_cast<ULONG>(status);
				Publish(event);
			}
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// 读类 hook —— 只记录，永不拦截。默认关闭，由 hook_reads 打开。
	// ==================================================================
	NTSTATUS NTAPI NtQueryValueKey_Hook(HANDLE KeyHandle, const RG_UNICODE_STRING* ValueName,
		ULONG KeyValueInformationClass, PVOID KeyValueInformation,
		ULONG Length, PULONG ResultLength)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;

		__try {
			action = Evaluate(R3ShieldCore::Op::QueryValueKey, KeyHandle, nullptr, ValueName, 0, event, false);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = Action::Pass;
		}

		NTSTATUS status = pOriginalNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
			KeyValueInformation, Length, ResultLength);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtEnumerateKey_Hook(HANDLE KeyHandle, ULONG Index,
		ULONG KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;

		__try {
			action = Evaluate(R3ShieldCore::Op::EnumerateKey, KeyHandle, nullptr, nullptr, 0, event, false);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = Action::Pass;
		}

		NTSTATUS status = pOriginalNtEnumerateKey(KeyHandle, Index, KeyInformationClass,
			KeyInformation, Length, ResultLength);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	NTSTATUS NTAPI NtEnumerateValueKey_Hook(HANDLE KeyHandle, ULONG Index,
		ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
	{
		InterlockedIncrement(&g_activeHooks);

		R3ShieldCore::Event event;
		Action action = Action::Pass;

		__try {
			action = Evaluate(R3ShieldCore::Op::EnumerateValueKey, KeyHandle, nullptr, nullptr, 0, event, false);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			action = Action::Pass;
		}

		NTSTATUS status = pOriginalNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass,
			KeyValueInformation, Length, ResultLength);

		if (action == Action::Record) {
			event.Status = static_cast<ULONG>(status);
			Publish(event);
		}

		InterlockedDecrement(&g_activeHooks);
		return status;
	}

	// ==================================================================
	// 挂载
	// ==================================================================
	bool QueueHook(LPCSTR functionName, LPVOID detour, LPVOID* original, bool required) noexcept
	{
		HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
		if (!ntdll) {
			return false;
		}

		LPVOID target = reinterpret_cast<LPVOID>(GetProcAddress(ntdll, functionName));
		if (!target) {
			if (required) {
				LOG(L"R3ShieldCore: ntdll 缺少导出 %S", functionName);
			}
			return false;
		}

		MH_STATUS status = MH_CreateHook(target, detour, original);
		if (status != MH_OK) {
			LOG(L"R3ShieldCore: MH_CreateHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		status = MH_QueueEnableHook(target);
		if (status != MH_OK) {
			LOG(L"R3ShieldCore: MH_QueueEnableHook(%S) 失败，状态 %d", functionName, status);
			return false;
		}

		g_hookCount++;
		return true;
	}

	// NtQueryKey / NtQueryObject 不挂 hook，只需要能直接调用的干净指针：
	// 前者供 ResolveKeyPath 还原句柄路径，后者供 hive 操作还原文件路径。
	// 不挂 = 不可能递归。
	void BindQueryHelpers() noexcept
	{
		HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
		if (!ntdll) {
			return;
		}

		pOriginalNtQueryKey = reinterpret_cast<NtQueryKeyPtr>(GetProcAddress(ntdll, "NtQueryKey"));
		pOriginalNtQueryObject = reinterpret_cast<NtQueryObjectPtr>(GetProcAddress(ntdll, "NtQueryObject"));
	}

	void QueueHooks(R3ShieldCore::Policy* policy) noexcept
	{
		BindQueryHelpers();

		// 写类：可拦截
		QueueHook("NtCreateKey", reinterpret_cast<LPVOID>(NtCreateKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtCreateKey), true);
		QueueHook("NtOpenKey", reinterpret_cast<LPVOID>(NtOpenKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtOpenKey), true);
		QueueHook("NtOpenKeyEx", reinterpret_cast<LPVOID>(NtOpenKeyEx_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtOpenKeyEx), false);
		QueueHook("NtSetValueKey", reinterpret_cast<LPVOID>(NtSetValueKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtSetValueKey), true);
		QueueHook("NtDeleteKey", reinterpret_cast<LPVOID>(NtDeleteKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtDeleteKey), true);
		QueueHook("NtDeleteValueKey", reinterpret_cast<LPVOID>(NtDeleteValueKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtDeleteValueKey), true);
		QueueHook("NtRenameKey", reinterpret_cast<LPVOID>(NtRenameKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtRenameKey), false);

		// 键信息 / 刷盘：前者可拦截（时间戳伪造、WOW64 重定向），后者只记录。
		//
		// 注意这两个导出不是所有系统版本都有：
		//   NtSetInformationKey 从 Vista 起才有，NtFlushKey 一直都有。
		// 所以两个都按非必需挂 —— 缺了只少一层覆盖，不能因此让整个模块失败。
		const bool hookSetInfo = !policy || (policy->Flags & R3ShieldCore::FlagHookSetInfo) != 0;
		if (hookSetInfo) {
			QueueHook("NtSetInformationKey", reinterpret_cast<LPVOID>(NtSetInformationKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtSetInformationKey), false);
		}

		QueueHook("NtFlushKey", reinterpret_cast<LPVOID>(NtFlushKey_Hook),
			reinterpret_cast<LPVOID*>(&pOriginalNtFlushKey), false);

		// Hive 级：可拦截，是原版覆盖不到的最大缺口。
		//
		// NtLoadKey / NtSaveKey / NtRestoreKey / NtReplaceKey 是 32 位时代就有的
		// 用户态系统调用；64 位上通过 wow64 层能直接调到。
		// NtLoadKeyEx / NtUnloadKeyEx 是 Vista 之后加的。
		const bool hookHive = !policy || (policy->Flags & R3ShieldCore::FlagHookHive) != 0;
		if (hookHive) {
			QueueHook("NtLoadKey", reinterpret_cast<LPVOID>(NtLoadKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtLoadKey), false);
			QueueHook("NtLoadKeyEx", reinterpret_cast<LPVOID>(NtLoadKeyEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtLoadKeyEx), false);
			QueueHook("NtUnloadKey", reinterpret_cast<LPVOID>(NtUnloadKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtUnloadKey), false);
			QueueHook("NtUnloadKeyEx", reinterpret_cast<LPVOID>(NtUnloadKeyEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtUnloadKeyEx), false);
			QueueHook("NtSaveKey", reinterpret_cast<LPVOID>(NtSaveKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtSaveKey), false);
			QueueHook("NtSaveKeyEx", reinterpret_cast<LPVOID>(NtSaveKeyEx_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtSaveKeyEx), false);
			QueueHook("NtRestoreKey", reinterpret_cast<LPVOID>(NtRestoreKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtRestoreKey), false);
			QueueHook("NtReplaceKey", reinterpret_cast<LPVOID>(NtReplaceKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtReplaceKey), false);
		}

		// 读类：默认关闭，噪音太大
		if (policy && (policy->Flags & R3ShieldCore::FlagHookReads)) {
			QueueHook("NtQueryValueKey", reinterpret_cast<LPVOID>(NtQueryValueKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtQueryValueKey), false);
			QueueHook("NtEnumerateKey", reinterpret_cast<LPVOID>(NtEnumerateKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtEnumerateKey), false);
			QueueHook("NtEnumerateValueKey", reinterpret_cast<LPVOID>(NtEnumerateValueKey_Hook),
				reinterpret_cast<LPVOID*>(&pOriginalNtEnumerateValueKey), false);
		}
	}
}

namespace RegistryGuard
{
	bool IsBypassed() noexcept
	{
		return g_bypass;
	}

	int HookCount() noexcept
	{
		return g_hookCount;
	}

	void WaitForHooksToDrain(DWORD timeoutMs) noexcept
	{
		ULONGLONG deadline = GetTickCount64() + timeoutMs;

		while (InterlockedCompareExchange(&g_activeHooks, 0, 0) != 0) {
			if (GetTickCount64() >= deadline) {
				LOG(L"R3ShieldCore: 等待 hook 排空超时，仍有 %d 个在跑", g_activeHooks);
				return;
			}

			Sleep(10);
		}
	}

	bool Install(HANDLE engineProcess) noexcept
	{
		if (g_installed) {
			return true;
		}

		DWORD enginePid = engineProcess ? GetProcessId(engineProcess) : 0;

		// 排除判定要用策略里的自定义排除路径，所以先开通道。
		if (!R3ShieldCoreChannel::Open(enginePid)) {
			// 通道开不了就没什么可做的：既没策略也没处上报。
			LOG(L"R3ShieldCore: 无法挂载共享通道，本进程跳过");
			return false;
		}

		if (ComputeBypass(enginePid)) {
			// 系统进程 / 引擎自身 / 排除项：不挂监控 hook。
			//
			// ⚠️ 例外：自我保护开着时通道要留着。ProcessGuard 会在这些进程里
			// 装 NtOpenProcess 保护 hook（它是唯一刻意跨过 bypass 的 hook），
			// 命中受保护目标时得能上报事件；而且 ProcessGuard::Install 也要
			// 从 Policy 里读 FlagSelfProtect —— 通道一关 Policy() 就是 nullptr，
			// 判断直接失效（这个坑实测踩过：bypass 进程照样能把引擎杀掉）。
			R3ShieldCore::Policy* bypassPolicy = R3ShieldCoreChannel::Policy();
			const bool keepChannelForSelfProtect =
				bypassPolicy && (bypassPolicy->Flags & R3ShieldCore::FlagSelfProtect) != 0;

			if (!keepChannelForSelfProtect && !R3ShieldCoreChannel::IsOwner()) {
				R3ShieldCoreChannel::Close();
			}

			g_bypass = true;
			g_installed = true;
			return true;
		}

		g_bypass = false;

		R3ShieldCore::Policy* policy = R3ShieldCoreChannel::Policy();

		// 询问通道：**无条件**打开，不再只在 ASK 模式下开。
		//
		// 原来这里是 `if (policy->Mode == Mode::Ask)`，代价是"运行期切到 ASK
		// 却发不出询问" —— 在 LOG/BLOCK 下被注入的进程，Install 时没开过通道，
		// 之后引擎把模式切成 ASK，本进程的 `R3ShieldCorePrompt::Ask` 拿不到
		// `g_requestEvent`，会**立刻**返回兜底结论(deny)。
		// 表现是"界面点了切换到 ASK，操作却直接全被拒"，而且不给用户任何
		// 弹窗 —— 比不拦还糟。
		//
		// ⚠️ 这是"把运行期可变的状态在 Install 时固化"这一类 bug 的又一例，
		//    同一个坑在"UI 线程只在 ASK 模式启动"上踩过（见 main.cpp）。
		//    Install 只发生一次，而 Mode 随时可能变 —— 凡是受 Mode 影响的
		//    准备动作，都不能挂在 Install 的条件里。
		//
		// 代价只是一次性的几个 OpenFileMapping / OpenEvent，可以忽略；
		// 真正贵的是每个进程都多映射一小块共享内存（几十 KB 级）。
		// 兜底：`R3ShieldCorePrompt::Ask` 里还有一次"按需补开"，防的是
		// "本进程比询问通道先存在"这类边角。
		if (!R3ShieldCorePrompt::Open(enginePid)) {
			LOG(L"R3ShieldCore: 询问通道打开失败，本进程跳过全部 Hook");
			R3ShieldCoreChannel::Close();
			return false;
		}

		QueueHooks(policy);

		g_installed = true;

		LOG(L"R3ShieldCore: 已挂载 %d 个注册表 hook (pid=%u)", g_hookCount, GetCurrentProcessId());
		return true;
	}
}

// ==================================================================
// block_all_safe 的支持函数（★ 不属于 RegistryGuard 命名空间）
// ==================================================================
//
// ⚠️ 为什么实现放在这个文件：签名校验（IsSignatureTrusted /
//    TryGetSignerName）和 IsTrustedSystemImage 都在本文件的匿名
//    namespace 里。跨 TU 暴露它们要把一整条 WinVerifyTrust 调用链
//    提到头文件，代价大于收益。同一个 TU 内直接调用最省事。
//
// ⚠️ 调用约束：本函数会跑 WinVerifyTrust（证书链可能要下载，几十毫秒级）。
//    **只允许在进程创建这条低频路径上调用**（process_guard.cpp 的
//    EvaluateProcess 的 block_all_safe 分支），绝不能进 hook 热路径。
namespace R3ShieldCoreRules
{
	namespace
	{
		// 可信启动目录前缀（归一化**之后**的形态，见 NormalizeImagePath）。
		//
		// ⚠️ 用 `\` 收尾，避免 `C:\Program Files2\` 这类前缀撞车。
		// ⚠️ Program Files 两种写法都要列：32 位系统上只有前者，
		//    64 位系统上 32 位程序装在 `Program Files (x86)`。
		constexpr PCWSTR kTrustedLaunchDirs[] = {
			L"%SystemRoot%\\",
			L"%ProgramFiles%\\",
			L"%ProgramFiles(x86)%\\",
		};

		// 把镜像路径归一化成"可信目录前缀可比对"的形态。
		//
		// 归一化规则（与 NormalizeImagePath 保持一致，但不复用它是因为
		// 复用会引入 `%SystemRoot%\` 之外的处理，这里只要反斜杠 + 环境前缀）：
		//   · `/` → `\`
		//   · `X:\Windows\` / `\SystemRoot\` → `%SystemRoot%\`
		//   · `X:\Program Files\` → `%ProgramFiles%\`
		//   · `X:\Program Files (x86)\` → `%ProgramFiles(x86)%\`
		//
		// 之所以不直接用 ExpandEnvironmentStrings：
		//   · 那会走环境块（可能被恶意程序污染）
		//   · 而且要在 hook 路径上避免额外 API 调用
		void NormalizeForTrustedDir(PCWSTR in, WCHAR* out, size_t cch) noexcept
		{
			if (!out || cch == 0) {
				return;
			}
			out[0] = L'\0';
			if (!in || in[0] == L'\0') {
				return;
			}

			// ① `/` → `\`（先整体转，后面都按 `\` 处理）
			size_t n = 0;
			for (; in[n] != L'\0' && n + 1 < cch; ++n) {
				out[n] = (in[n] == L'/') ? L'\\' : in[n];
			}
			out[n] = L'\0';

			// ② `\SystemRoot\` 开头 → `%SystemRoot%\`
			constexpr PCWSTR kSystemRootAlias = L"\\SystemRoot\\";
			constexpr size_t kSystemRootAliasLen = 12;
			if (_wcsnicmp(out, kSystemRootAlias, kSystemRootAliasLen) == 0) {
				WCHAR tmp[MAX_PATH * 2] = {};
				swprintf_s(tmp, L"%%SystemRoot%%\\%s", out + kSystemRootAliasLen);
				wcsncpy_s(out, cch, tmp, _TRUNCATE);
				return;
			}

			// ③ `X:\Windows\` / `X:\Program Files\` / `X:\Program Files (x86)\`
			//    要求：盘符 + `:` + `\`（长度 >= 3），且路径是绝对路径。
			if (!(iswalpha(out[0]) && out[1] == L':' && out[2] == L'\\')) {
				return;
			}

			const WCHAR* tail = out + 3;  // 跳过 `X:\`

			struct Alias
			{
				PCWSTR from;
				size_t fromLen;
				PCWSTR to;
			};
			constexpr Alias kAliases[] = {
				{ L"Windows\\",            8,  L"%SystemRoot%\\" },
				{ L"Program Files (x86)\\", 21, L"%ProgramFiles(x86)%\\" },
				{ L"Program Files\\",      14, L"%ProgramFiles%\\" },
			};

			for (const Alias& a : kAliases) {
				if (_wcsnicmp(tail, a.from, a.fromLen) != 0) {
					continue;
				}
				WCHAR tmp[MAX_PATH * 2] = {};
				swprintf_s(tmp, L"%s%s", a.to, tail + a.fromLen);
				wcsncpy_s(out, cch, tmp, _TRUNCATE);
				return;
			}
		}
	}

	bool IsTrustedLaunchImage(PCWSTR imagePath) noexcept
	{
		// ---- ⓪ 空路径 → 不可信（★ 绝不能放行，见头文件说明）----
		if (!imagePath || imagePath[0] == L'\0') {
			return false;
		}

		WCHAR normalized[MAX_PATH * 2] = {};
		NormalizeForTrustedDir(imagePath, normalized, _countof(normalized));
		if (normalized[0] == L'\0') {
			return false;
		}

		// ---- ① 目录前缀必须命中可信目录 ----
		bool inTrustedDir = false;
		for (PCWSTR prefix : kTrustedLaunchDirs) {
			if (_wcsnicmp(normalized, prefix, wcslen(prefix)) == 0) {
				inTrustedDir = true;
				break;
			}
		}
		if (!inTrustedDir) {
			return false;
		}

		// ---- ② 不在 Windows 的用户可写子目录里 ----
		//
		// ⚠️ 这层是必须的：`C:\Windows\Temp\evil.exe` 满足 ①，
		//    但它是可写目录，任何用户都能丢东西进去。
		//    （Program Files 下的可写目录不在 kWindowsWritableSubdirFragments
		//      的覆盖范围里 —— 那需要管理员权限才能写，风险等级不同。）
		if (IsInWritableWindowsSubdir(normalized)) {
			return false;
		}

		// ---- ③ 微软签名有效 ----
		//
		// 复用 ComputeBypass 那条路用的同一个组合：
		//   IsSignatureTrusted（WinVerifyTrust 信任链）
		//   + 取签名者名（嵌入式优先，回退 catalog）
		//   + IsMicrosoftSigner
		//
		// ⚠️ 注意：这里**不复用 IsTrustedSystemImage()** —— 那个函数的前置
		//    条件是"已命中具体文件白名单"，语义是 bypass 判据。本函数要的是
		//    "目录 + 签名"这个更宽的口径，直接调底层两个函数更清晰。
		WCHAR catalogFile[MAX_PATH * 2] = {};
		if (!IsSignatureTrusted(normalized, catalogFile, _countof(catalogFile))) {
			return false;
		}

		WCHAR signerName[256] = {};
		bool gotSigner = TryGetSignerName(normalized, signerName, _countof(signerName));
		if (!gotSigner && catalogFile[0] != L'\0') {
			gotSigner = TryGetSignerName(catalogFile, signerName, _countof(signerName));
		}
		if (!gotSigner) {
			return false;
		}

		return IsMicrosoftSigner(signerName);
	}

	// ------------------------------------------------------------------
	// ★ v66：取"**真实**的 Windows 目录"（如 `C:\Windows`）。
	// ------------------------------------------------------------------
	//
	// ★ 为什么不能复用 `NormalizeForTrustedDir`（**这是本函数存在的唯一理由**）：
	//
	//   `NormalizeForTrustedDir` 会把**任意盘符**的 `X:\Windows\` 都折成
	//   `%SystemRoot%\` —— 那对 `IsTrustedLaunchImage` 是安全的，因为它
	//   后面还有一道**微软签名**校验兜底。
	//
	//   但 `IsUacConsentImage` **不查签名**（刻意为之：它只在 System32 下
	//   三个固定文件名上比对，跑 WinVerifyTrust 是多余开销）。
	//   于是别名映射就成了一个**真漏洞**：
	//     攻击者在任意可写卷上建 `D:\Windows\System32\consent.exe`
	//     → 归一化后等于 `%SystemRoot%\System32\consent.exe`
	//     → **蹭过白名单** → 在全拦模式下被放行启动。
	//   （全拦模式的全部意义就是"全拦"，这个洞不能留。）
	//
	//   ⇒ 所以这里改成：拿 `GetWindowsDirectoryW` 的**真实**目录来比前缀。
	//     代价是一次 API 调用，但调用点在**进程创建**这条低频路径上
	//     （`EvaluateProcess`），不在 hook 热路径 —— 可以接受。
	//
	// 返回：归一化后的长度（>=1）；失败返回 0（调用方必须**拒答**）。
	//
	// ⚠️ 必须待在自己的匿名 namespace 里（**别**把它放到
	//    `namespace R3ShieldCoreRules` 的普通作用域）：它只服务本文件，
	//    不该进导出表，也不该和 `IsUacConsentImage` 之外的调用者共享。
	namespace
	{
		size_t RealWindowsDirNormalized(WCHAR* out, size_t cch) noexcept
		{
			if (!out || cch < 4) {
				return 0;
			}
			out[0] = L'\0';

			const UINT n = GetWindowsDirectoryW(out, static_cast<UINT>(cch));
			if (n == 0 || n >= cch) {
				out[0] = L'\0';
				return 0;
			}

			// `/` → `\`，并去掉尾部反斜杠（`GetWindowsDirectoryW` 一般不返回，
			// 但别赌它）。
			for (size_t i = 0; i < n; ++i) {
				if (out[i] == L'/') {
					out[i] = L'\\';
				}
			}
			size_t len = n;
			while (len > 0 && out[len - 1] == L'\\') {
				out[--len] = L'\0';
			}
			return len;
		}
	}

// ------------------------------------------------------------------
// ★ v66：全拦模式下的 UAC 提权链最小白名单（见 r3shieldcore_rules.h）。
// ------------------------------------------------------------------
//
// 为什么需要：v66 把 block_all / block_all_safe 对「进程创建 / 远程线程 /
//   跨进程内存」恢复成**直接拒**（撤销 v21 的"先问再拦"）。硬拒之后，
//   若把 UAC 同意框也拒掉，用户就连提权这条路都断了。
//
// ⚠️ 为什么这条缝"可以开"（而不是留洞）：
//   · 放行范围**只有三个镜像**，且必须落在真实 `%SystemRoot%\System32\` 下；
//   · **不放行**"被提权的那个目标程序"（那是任意镜像，路径判据认不出来）；
//   · 提权链本来**结构性不受监控**（`svchost.exe` 瘦会话 + `consent.exe`
//     在 `kNeverInject[]`）⇒ 这条白名单其实是**兜底**，不是主路径。
//     ⇒ 正常机器上它几乎不会被命中；被命中时也只放行这三个系统镜像。
//
// ⚠️ 与 IsTrustedLaunchImage 的关键区别：**不查签名**（见上）。
bool IsUacConsentImage(PCWSTR imagePath) noexcept
{
	if (!imagePath || imagePath[0] == L'\0') {
		return false;
	}

	// ---- ① 分隔符归一化（只做 `/` → `\`，**不做**盘符别名映射）----
	WCHAR path[MAX_PATH * 2] = {};
	size_t n = 0;
	for (; imagePath[n] != L'\0' && n + 1 < _countof(path); ++n) {
		path[n] = (imagePath[n] == L'/') ? L'\\' : imagePath[n];
	}
	path[n] = L'\0';

	// ---- ② 真实 Windows 目录（失败必须**拒答**，不能放行）----
	WCHAR winDir[MAX_PATH] = {};
	const size_t winLen = RealWindowsDirNormalized(winDir, _countof(winDir));
	if (winLen == 0) {
		return false;
	}

	// ---- ③ 剥前缀，得到"相对 Windows 目录"的尾巴 ----
	//
	//   两种合法写法：
	//     · `C:\Windows\System32\consent.exe`   （真实绝对路径）
	//     · `\SystemRoot\System32\consent.exe`  （NT 风格，等价于上面那条）
	//   ⚠️ `_wcsnicmp` 在 path 更短时会因撞到 NUL 而返回非 0，
	//      所以 `path[winLen]` 只在前缀真的相等时才会被读到。
	const WCHAR* rel = nullptr;
	if (_wcsnicmp(path, winDir, winLen) == 0 && path[winLen] == L'\\') {
		rel = path + winLen + 1;
	}
	else if (_wcsnicmp(path, L"\\SystemRoot\\", 12) == 0) {
		rel = path + 12;
	}
	else {
		// 含 `\\?\` / `\??\` / 任意盘符的 `X:\Windows\` —— **一律不放行**。
		// 保守是刻意的：这条白名单是"少拦一个系统进程"的兜底，
		// 不是"多放一个"的便利。见上面对别名映射那段说明。
		return false;
	}

	// ---- ④ 尾巴必须**恰好等于** `System32\<三个名字之一>` ----
	//
	// ⚠️ 用 `_wcsicmp`（全串相等）而不是 `wcsstr`（子串）：
	//    子串匹配会让 `C:\Windows\System32\evil-consent.exe` 之类蹭过去。
	constexpr PCWSTR kUacConsentRels[] = {
		L"System32\\consent.exe",
		L"System32\\CredentialUIBroker.exe",
		L"System32\\LogonUI.exe",
	};

	for (PCWSTR r : kUacConsentRels) {
		if (_wcsicmp(rel, r) == 0) {
			return true;
		}
	}

	return false;
}

}   // namespace R3ShieldCoreRules

// ==================================================================
// ★ 单测专用入口（v28）
// ==================================================================
//
// 为什么需要它：`Evaluate` 在本文件的匿名 namespace 里，外部 TU 拿不到；
// 而 v28 的修复点（"LOG 模式 + 高危不可问 → 降级放行"）**就在 Evaluate 里**。
// 纯规则层单测（`build_ut.sh` 只链 `r3shieldcore_rules.cpp`）**测不到**它。
//
// 用编译宏 `REGUARD_GUARD_UT` 隔离：**只在单测构建里编译**，
// 生产构建（build.sh）不带这个宏 ⇒ 导出表不变（仍是 10 个）。
//
// 语义：用给定键路径跑一遍真实的 `Evaluate`，把结果返回给单测断言。
#ifdef REGUARD_GUARD_UT
namespace RegistryGuardTest
{
	R3ShieldCore::Event EvaluateKey(PCWSTR keyPath, PCWSTR valueName, ULONG op, ULONG mode,
		bool blockable) noexcept
	{
		// ⚠️ 不能先填 event 再调 Evaluate —— `Evaluate` 开头就
		//    `ZeroMemory(&event, ...)`，预填的路径会被抹掉。
		//    必须通过 `objectName` 形参传进去（真实 hook 就是这么调的）。
		RG_UNICODE_STRING key = {};
		if (keyPath) {
			key.Length = static_cast<USHORT>(wcslen(keyPath) * sizeof(WCHAR));
			key.MaximumLength = static_cast<USHORT>(key.Length + sizeof(WCHAR));
			key.Buffer = const_cast<PWSTR>(keyPath);
		}

		RG_UNICODE_STRING val = {};
		if (valueName) {
			val.Length = static_cast<USHORT>(wcslen(valueName) * sizeof(WCHAR));
			val.MaximumLength = static_cast<USHORT>(val.Length + sizeof(WCHAR));
			val.Buffer = const_cast<PWSTR>(valueName);
		}

		R3ShieldCore::Event event = {};

		// keyHandle=0 ⇒ 走 objectName 分支，把 keyPath 拷进 event.KeyPath。
		(void)Evaluate(static_cast<R3ShieldCore::Op>(op), nullptr,
			keyPath ? &key : nullptr, valueName ? &val : nullptr, 0,
			event, blockable);

		return event;
	}
}
#endif // REGUARD_GUARD_UT
