#include "stdafx.h"
#include "session_private_namespace.h"
#include "functions.h"
#include "logger.h"
#include "r3shieldcore_channel.h"

namespace
{
	constexpr auto boundaryDescriptorName = L"CustomizationBoundary";

	wil::unique_boundary_descriptor BuildBoundaryDescriptor()
	{
		wil::unique_boundary_descriptor boundaryDesc(CreateBoundaryDescriptor(boundaryDescriptorName, 0));
		THROW_LAST_ERROR_IF_NULL(boundaryDesc);

		{
			wil::unique_sid pSID;
			SID_IDENTIFIER_AUTHORITY SIDWorldAuth = SECURITY_WORLD_SID_AUTHORITY;
			THROW_IF_WIN32_BOOL_FALSE(
				AllocateAndInitializeSid(&SIDWorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSID));

			THROW_IF_WIN32_BOOL_FALSE(AddSIDToBoundaryDescriptor(boundaryDesc.addressof(), pSID.get()));
		}

		{
			wil::unique_sid pSID;
			SID_IDENTIFIER_AUTHORITY SIDMandatoryLabelAuth = SECURITY_MANDATORY_LABEL_AUTHORITY;
			THROW_IF_WIN32_BOOL_FALSE(
				AllocateAndInitializeSid(&SIDMandatoryLabelAuth, 1, SECURITY_MANDATORY_MEDIUM_RID, 0, 0, 0, 0, 0, 0, 0, &pSID));

			THROW_IF_WIN32_BOOL_FALSE(AddIntegrityLabelToBoundaryDescriptor(boundaryDesc.addressof(), pSID.get()));
		}

		return boundaryDesc;
	}
}

namespace SessionPrivateNamespace
{
	int MakeName(WCHAR szPrivateNamespaceName[PrivateNamespaceMaxLen + 1], DWORD dwSessionManagerProcessId) noexcept
	{
		if (auto* policy = R3ShieldCoreChannel::Policy();
			policy && policy->EngineProcessId == dwSessionManagerProcessId &&
			policy->PrivateNamespaceName[0] != L'\0') {
			wcsncpy_s(szPrivateNamespaceName, PrivateNamespaceMaxLen + 1,
				policy->PrivateNamespaceName, _TRUNCATE);
			return static_cast<int>(wcslen(szPrivateNamespaceName));
		}

		static_assert(PrivateNamespaceMaxLen + 1 == sizeof("CustomizationSession1234567890-FFFFFFFFFFFFFFFF"));

		ULONGLONG creationTime = 0;
		wil::unique_handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
			dwSessionManagerProcessId));
		if (process) {
			FILETIME creation = {}, exit = {}, kernel = {}, user = {};
			if (GetProcessTimes(process.get(), &creation, &exit, &kernel, &user)) {
				creationTime = (static_cast<ULONGLONG>(creation.dwHighDateTime) << 32) |
					creation.dwLowDateTime;
			}
		}

		return swprintf_s(szPrivateNamespaceName, PrivateNamespaceMaxLen + 1,
			L"CustomizationSession%u-%016llX", dwSessionManagerProcessId, creationTime);
	}

	int MakeProcessInitAPCMutexName(WCHAR* szBuffer, size_t cchBuffer,
		DWORD dwSessionManagerProcessId, DWORD processId) noexcept
	{
		if (!szBuffer || cchBuffer == 0) {
			return -1;
		}
		szBuffer[0] = L'\0';

		WCHAR szNamespaceName[PrivateNamespaceMaxLen + 1] = {};
		const int namespaceLen = MakeName(szNamespaceName, dwSessionManagerProcessId);
		if (namespaceLen <= 0 || static_cast<size_t>(namespaceLen) >= cchBuffer) {
			return -1;
		}

		wcsncpy_s(szBuffer, cchBuffer, szNamespaceName, _TRUNCATE);

		// ★ 连字符，不是反斜杠 —— 理由见头文件里的铁律说明。
		const int suffixLen = swprintf_s(szBuffer + namespaceLen, cchBuffer - namespaceLen,
			L"-ProcessInitAPCMutex-pid=%u", processId);
		if (suffixLen <= 0) {
			szBuffer[0] = L'\0';
			return -1;
		}

		// ★ 防复发自检：成品名里**不允许**出现反斜杠。
		//   一旦出现，这个名字就是"对象路径"，而私有命名空间从未真正创建
		//   ⇒ CreateMutex 必返 ERROR_PATH_NOT_FOUND(3) ⇒ 整条路静默失效。
		//   宁可在这里明确失败（调用方会抛异常、日志里有痕迹），也不要
		//   又一次"看起来成功、其实一直没生效"。
		if (wcschr(szBuffer, L'\\') != nullptr) {
			szBuffer[0] = L'\0';
			return -1;
		}

		return namespaceLen + suffixLen;
	}

	bool Create(DWORD dwSessionManagerProcessId) noexcept
	{
		WCHAR szNamespaceName[PrivateNamespaceMaxLen + 1] = {};
		MakeName(szNamespaceName, dwSessionManagerProcessId);
		if (auto* policy = R3ShieldCoreChannel::Policy();
			policy && policy->EngineProcessId == dwSessionManagerProcessId) {
			wcsncpy_s(policy->PrivateNamespaceName, _countof(policy->PrivateNamespaceName),
				szNamespaceName, _TRUNCATE);
			LOG(L"Using unique session synchronization name %ls", szNamespaceName);
			return true;
		}
		return false;
	}

	bool Open(DWORD dwSessionManagerProcessId) noexcept
	{
		WCHAR szNamespaceName[PrivateNamespaceMaxLen + 1] = {};
		MakeName(szNamespaceName, dwSessionManagerProcessId);
		return szNamespaceName[0] != L'\0';
	}
}
