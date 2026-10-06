//
// sigcheck.cpp - 离线验证 v16 bypass 判据（签名 + 目录双条件）。
//
// 为什么需要它：
//    v16 把 ComputeBypass 从"目录前缀"改成"目录 + 微软签名"。光看进程
//    里挂没挂 hook 不直观（DLL 反正都会注入），而且没法拿 System32 下
//    的**微软签名**文件做阴性样本（System32 不可写、也不能改它）。
//    这个工具直接对**任意文件**跑同一套判据，把三档结果打出来：
//      · 目录是否在可写子目录名单里（复用 R3ShieldCoreRules::IsInWritableWindowsSubdir）
//      · 有没有有效签名（WinVerifyTrust）
//      · 签名者是不是微软（复用 R3ShieldCoreRules::IsMicrosoftSigner）
//
// 用法： sigcheck.exe <文件路径> [更多文件...]
//
#include <windows.h>
#include <wintrust.h>
#include <mscat.h>
#include <bcrypt.h>
#include <softpub.h>
#include <stdio.h>
#include <locale.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace R3ShieldCoreRules
{
	bool IsInWritableWindowsSubdir(PCWSTR imagePath) noexcept;
	bool IsMicrosoftSigner(PCWSTR signerName) noexcept;
}

// ---- 与 registry_guard.cpp 同源的两段（保持判据一致）----

static bool TryGetSignerName(const WCHAR* filePath, WCHAR* outName, size_t outChars)
{
	outName[0] = L'\0';

	HCERTSTORE store = nullptr;
	HCRYPTMSG message = nullptr;
	if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
		0, nullptr, nullptr, nullptr, &store, &message, nullptr)) {
		return false;
	}

	bool ok = false;
	DWORD signerInfoSize = 0;
	if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)
		&& signerInfoSize > 0) {
		BYTE* buffer = static_cast<BYTE*>(LocalAlloc(LPTR, signerInfoSize));
		if (buffer && CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer, &signerInfoSize)) {
			auto* signerInfo = reinterpret_cast<PCMSG_SIGNER_INFO>(buffer);
			CERT_INFO certInfo = {};
			certInfo.Issuer = signerInfo->Issuer;
			certInfo.SerialNumber = signerInfo->SerialNumber;

			PCCERT_CONTEXT cert = CertFindCertificateInStore(store,
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
				CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);
			if (cert) {
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

static LONG g_lastTrustStatus = 0;

// 目录签名（catalog）校验 —— 与 registry_guard.cpp 同源。
// 成功时把 catalog 文件路径写到 g_catalogFile（供取签名者名）。
static WCHAR g_catalogFile[MAX_PATH * 2] = {};

static bool IsCatalogTrusted(const WCHAR* filePath)
{
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

	// ⚠️ 用**默认算法**（不指定 BCRYPT_SHA256）：catalog 里的成员 hash
	//    多数是 SHA1。用 SHA256 算出的 hash 虽能"找到 catalog"，
	//    但 catalog 内按 SHA1 tag 索引，验证时会 tag 不匹配。
	//    `CryptCATAdminAcquireContext2(&h, nullptr, nullptr, nullptr, 0)`
	//    走系统默认（SHA1），与 catalog 内容一致。
	if (!CryptCATAdminAcquireContext2(&hCatAdmin, nullptr, nullptr, nullptr, 0)) {
		CloseHandle(file);
		return false;
	}

	{
		DWORD hashSize = 0;
		if (CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file, &hashSize, nullptr, 0) || hashSize > 0) {
			BYTE* hash = static_cast<BYTE*>(LocalAlloc(LPTR, hashSize));
			if (hash && CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, file, &hashSize, hash, 0)) {
				HCATADMIN catAdmin = static_cast<HCATADMIN>(hCatAdmin);
				HCATINFO catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash, hashSize, 0, nullptr);
				if (catInfo && CryptCATCatalogInfoFromContext(catInfo, &catalogInfo, 0)) {
					WCHAR memberTag[2 * 64 + 1] = {};
					for (DWORD i = 0; i < hashSize && i < 64; i++) {
						swprintf_s(memberTag + i * 2, 3, L"%02X", hash[i]);
					}

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

					if (trusted) {
						wcsncpy_s(g_catalogFile, catalogInfo.wszCatalogFile, _TRUNCATE);
					}

					CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
				}
				if (hash) LocalFree(hash);
			}
		}
		CryptCATAdminReleaseContext(hCatAdmin, 0);
	}

	CloseHandle(file);
	return trusted;
}

static bool IsSignatureTrusted(const WCHAR* filePath)
{
	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(fileInfo);
	fileInfo.pcwszFilePath = filePath;

	WINTRUST_DATA trustData = {};
	trustData.cbStruct = sizeof(trustData);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

	GUID actionGuid = { 0x00AAC56B, 0xCD44, 0x11d0,
		{ 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE } };

	LONG status = WinVerifyTrust(nullptr, &actionGuid, &trustData);
	g_lastTrustStatus = status;
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(nullptr, &actionGuid, &trustData);

	if (status == ERROR_SUCCESS) {
		return true;
	}

	if (status == static_cast<LONG>(TRUST_E_NOSIGNATURE)) {
		if (IsCatalogTrusted(filePath)) {
			g_lastTrustStatus = 0;
			return true;
		}
	}

	return false;
}

static void CheckFile(const WCHAR* path)
{
	const bool writableSubdir = R3ShieldCoreRules::IsInWritableWindowsSubdir(path);

	g_catalogFile[0] = L'\0';
	const bool trusted = IsSignatureTrusted(path);

	// 签名者名：嵌入式优先，回退 catalog 文件。
	WCHAR signer[256] = {};
	bool gotSigner = TryGetSignerName(path, signer, _countof(signer));
	if (!gotSigner && g_catalogFile[0]) {
		gotSigner = TryGetSignerName(g_catalogFile, signer, _countof(signer));
	}
	const bool ms = gotSigner && R3ShieldCoreRules::IsMicrosoftSigner(signer);

	// 与 ComputeBypass 一致的结论（仅对 %SystemRoot%\ 下的文件有意义）。
	const bool bypass = !writableSubdir && trusted && ms;

	wprintf(L"%s\n", path);
	wprintf(L"    可写子目录=%s  签名可信=%s  签名者=%s  微软=%s\n",
		writableSubdir ? L"是" : L"否",
		trusted ? L"是" : L"否",
		gotSigner ? signer : L"(取不到)",
		ms ? L"是" : L"否");
	wprintf(L"    => %s\n\n",
		bypass ? L"BYPASS（目录+微软签名，不挂 hook）" : L"挂 hook（不 bypass）");
}

int wmain(int argc, wchar_t** argv)
{
	setlocale(LC_ALL, ".UTF-8");
	SetConsoleOutputCP(CP_UTF8);

	if (argc < 2) {
		wprintf(L"用法: sigcheck.exe <文件路径> [更多文件...]\n");
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		CheckFile(argv[i]);
	}
	return 0;
}
