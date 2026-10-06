//
// 快速探测 NtSetInformationKey 各 class 的可用性。
// 用来确认"哪个 class + 多长的缓冲区"能通过，从而让探针有可用的基线。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtSetInformationKey_t)(HANDLE, ULONG, PVOID, ULONG);

int main()
{
	setlocale(LC_ALL, "");

	HKEY key = nullptr;
	DWORD disposition = 0;
	LSTATUS st = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreSetInfoProbe", 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE | KEY_SET_VALUE, nullptr, &key, &disposition);
	if (st != ERROR_SUCCESS) {
		printf("开键失败: %ld\n", st);
		return 1;
	}

	auto pNtSetInformationKey = reinterpret_cast<NtSetInformationKey_t>(
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationKey"));

	// 逐 class 试，缓冲区给足 64 字节（全零），看谁返回 SUCCESS
	for (ULONG cls = 0; cls <= 4; cls++) {
		BYTE buffer[64] = {};
		NTSTATUS status = pNtSetInformationKey(key, cls, buffer, sizeof(buffer));
		printf("class=%lu len=64  -> 0x%08lX\n", cls, (unsigned long)status);
	}

	printf("---- 只试 class 1，长度从 4 到 32 ----\n");
	for (ULONG len = 4; len <= 32; len += 4) {
		BYTE buffer[64] = {};
		NTSTATUS status = pNtSetInformationKey(key, 1, buffer, len);
		printf("class=1 len=%2lu  -> 0x%08lX\n", len, (unsigned long)status);
	}

	RegCloseKey(key);
	RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\R3ShieldCoreSetInfoProbe");
	return 0;
}
