//
// dskill.cpp — 直 syscall 终止探针。
//
// 两个用途：
//   1) 验证残余绕过：NtOpenProcess 的保护 hook 挂在 ntdll 导出上，
//      从磁盘 ntdll 解析出 syscall 号、自己发 syscall 就绕过去了 ——
//      这是用户态 hook 的固有上限（同 sysinject 的结论）。
//   2) 当引擎的自我保护生效后，普通 taskkill / TerminateProcess 都杀不掉它，
//      这个工具是留给开发者的"逃生门"。
//
// 用法: dskill.exe <pid> [outFile]
//
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG NTSTATUS;

static FILE* g_out = nullptr;

static void Emit(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	if (g_out) {
		va_start(ap, fmt);
		vfprintf(g_out, fmt, ap);
		va_end(ap);
		fflush(g_out);
	}
}

// 从磁盘 ntdll 解析导出函数的 syscall 号（x64 stub: 4C 8B D1 B8 <imm32>）。
static DWORD GetSyscallNumber(const char* funcName)
{
	HANDLE f = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
		FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (f == INVALID_HANDLE_VALUE) {
		return 0;
	}

	const DWORD size = GetFileSize(f, nullptr);
	BYTE* buf = static_cast<BYTE*>(malloc(size));
	DWORD read = 0;
	const BOOL ok = ReadFile(f, buf, size, &read, nullptr);
	CloseHandle(f);
	if (!ok || read != size) {
		free(buf);
		return 0;
	}

	const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
	const IMAGE_NT_HEADERS* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buf + dos->e_lfanew);
	const DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const DWORD expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (expRva == 0) {
		free(buf);
		return 0;
	}

	const IMAGE_EXPORT_DIRECTORY* exp =
		reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buf + expRva);
	const DWORD* names = reinterpret_cast<const DWORD*>(buf + exp->AddressOfNames);
	const WORD* ords = reinterpret_cast<const WORD*>(buf + exp->AddressOfNameOrdinals);
	const DWORD* funcs = reinterpret_cast<const DWORD*>(buf + exp->AddressOfFunctions);

	DWORD ssn = 0;
	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		const char* n = reinterpret_cast<const char*>(buf + names[i]);
		if (strcmp(n, funcName) != 0) {
			continue;
		}
		const DWORD funcRva = funcs[ords[i]];
		if (funcRva < expRva || funcRva >= expRva + expSize) {
			const BYTE* p = buf + funcRva;
			if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8) {
				ssn = *reinterpret_cast<const DWORD*>(p + 4);
			}
		}
		break;
	}

	free(buf);
	return ssn;
}

typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);

// 造 syscall stub：mov r10,rcx; mov eax,ssn; syscall; ret
static NtOpenProcess_t MakeStub(DWORD ssn)
{
	BYTE code[] = {
		0x4C, 0x8B, 0xD1,
		0xB8, 0x00, 0x00, 0x00, 0x00,
		0x0F, 0x05,
		0xC3
	};
	*reinterpret_cast<DWORD*>(code + 4) = ssn;

	BYTE* mem = static_cast<BYTE*>(VirtualAlloc(nullptr, sizeof(code),
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (mem) {
		memcpy(mem, code, sizeof(code));
	}
	return reinterpret_cast<NtOpenProcess_t>(mem);
}

int main(int argc, char** argv)
{
	WCHAR self[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, self, _countof(self));

	const DWORD pid = (argc > 1) ? static_cast<DWORD>(strtoul(argv[1], nullptr, 10)) : 0;
	if (argc > 2 && argv[2][0]) {
		g_out = fopen(argv[2], "w");
	}

	Emit("dskill pid=%u\n", GetCurrentProcessId());
	Emit("镜像路径: %ls\n", self);
	Emit("目标 pid=%u\n", pid);
	if (pid == 0) {
		Emit("缺少目标 pid。\n");
		if (g_out) fclose(g_out);
		return 1;
	}

	const DWORD ssn = GetSyscallNumber("NtOpenProcess");
	Emit("NtOpenProcess syscall 号  %u (0x%X)\n", ssn, ssn);
	if (ssn == 0) {
		Emit("解析 syscall 号失败。\n");
		if (g_out) fclose(g_out);
		return 1;
	}

	NtOpenProcess_t pSysOpen = MakeStub(ssn);
	if (!pSysOpen) {
		Emit("stub 分配失败。\n");
		if (g_out) fclose(g_out);
		return 1;
	}

	// CLIENT_ID：只有 UniqueProcess 有效。
	struct { HANDLE UniqueProcess; HANDLE UniqueThread; } cid = {};
	cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid));

	// OBJECT_ATTRIBUTES 不能为 NULL —— NtOpenProcess 会直接读它（kernel32 也是这么传的）。
	struct { ULONG Length; HANDLE RootDirectory; PVOID ObjectName; ULONG Attributes;
		PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } oa = {};
	oa.Length = sizeof(oa);

	// 1) 直 syscall 打开 —— 绕过 ntdll!NtOpenProcess 上的保护 hook。
	HANDLE h = nullptr;
	const NTSTATUS st = pSysOpen(&h, PROCESS_TERMINATE, &oa, &cid);
	Emit("1) 直syscall NtOpenProcess(PROCESS_TERMINATE)  NTSTATUS=0x%08X %s\n",
		static_cast<unsigned>(st), st >= 0 ? "成功" : "失败");
	if (st < 0 || !h) {
		Emit("   拿不到句柄，退出。\n");
		if (g_out) fclose(g_out);
		return 1;
	}

	// 2) 用普通 API 终止 —— NtTerminateProcess 只记录不拦，所以这一步会成功。
	SetLastError(0);
	const BOOL ok = TerminateProcess(h, 1);
	Emit("2) TerminateProcess  -> %s err=%u\n", ok ? "成功" : "失败", ok ? 0u : GetLastError());
	CloseHandle(h);

	Sleep(400);
	HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (q) {
		DWORD code = 0;
		GetExitCodeProcess(q, &code);
		Emit("3) 目标状态  %s\n", (code == STILL_ACTIVE) ? "仍在运行" : "已退出");
		CloseHandle(q);
	} else {
		Emit("3) 目标状态  已不存在\n");
	}

	Emit("完成。\n");
	if (g_out) fclose(g_out);
	return 0;
}
