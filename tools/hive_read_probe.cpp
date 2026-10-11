//
// R3ShieldCore —— 「hive 文件直读」可行性探针（v75 预研）
//
// 问题：注册表面（registry_guard）挂的是 22 个 Nt*Key* 系统调用。攻击者若绕开
//       注册表 API、直接把 hive 文件（`\System32\config\SYSTEM` 等）当**文件**
//       读出来解析，我们的 hook 全部不经过 ⇒ 这就是盘点文档 §2.4 记的
//       「hive 文件直读 ❌ 未挂」。
//
// 本探针要回答的**唯一**问题：
//       ★ **活 hive（已被系统加载的那个文件）到底能不能被用户态程序打开 / 读 / 映射？**
//
//   为什么这是决定性问题：
//     · 若**打不开**（系统独占锁定）⇒ "直读活 hive"这条路在活系统上根本走不通，
//       该面**不必做**（与"文件内容"同族的淘汰结论）。
//     · 若**能打开、甚至能映射** ⇒ 那是一条真实的绕过路，且**映射之后是无 API
//       可拦的直接内存访问**（盘点文档 §2.6 的结论）⇒ 用户态**拦不住**，
//       只能退而"拦打开"（而"拦打开"又要求我们有正当理由区分 hive 与普通文件）。
//
// ★ 本探针**不挂任何 hook、不注入、不跑引擎** ⇒ 不受铁律 175 约束。
// ★ 它**只读**，不写任何 hive；只在自己 %TEMP% 下建一个**普通文件**做基线负对照。
//
// 用法：
//   hive_read_probe              全部跑一遍
//   hive_read_probe --no-elev    不尝试开 SeBackupPrivilege（模拟普通用户）
//   hive_read_probe --save       额外用 RegSaveKey 导出一个键做"离线 hive"样本
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>

// ------------------------------------------------------------------
// ntdll 原型（自带定义，避开 winternl.h 的版本差异）
// ------------------------------------------------------------------
typedef LONG NTSTATUS;

typedef struct _HRP_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} HRP_UNICODE_STRING;

typedef struct _HRP_OBJECT_ATTRIBUTES {
	ULONG               Length;
	HANDLE              RootDirectory;
	HRP_UNICODE_STRING* ObjectName;
	ULONG               Attributes;
	PVOID               SecurityDescriptor;
	PVOID               SecurityQualityOfService;
} HRP_OBJECT_ATTRIBUTES;

typedef struct _HRP_IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} HRP_IO_STATUS_BLOCK;

typedef NTSTATUS(NTAPI* NtCreateFilePtr)(PHANDLE, ACCESS_MASK, HRP_OBJECT_ATTRIBUTES*,
	HRP_IO_STATUS_BLOCK*, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* NtCreateSectionPtr)(PHANDLE, ACCESS_MASK, HRP_OBJECT_ATTRIBUTES*,
	PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSectionPtr)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
	PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);

static NtCreateFilePtr        pNtCreateFile        = nullptr;
static NtCreateSectionPtr     pNtCreateSection     = nullptr;
static NtMapViewOfSectionPtr  pNtMapViewOfSection  = nullptr;

// NtCreateFile 的 CreateOptions
#define HRP_FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#define HRP_FILE_NON_DIRECTORY_FILE     0x00000040UL
#define HRP_FILE_SYNCHRONOUS_IO_NONALERT 0x00000020UL

#define HRP_SEC_COMMIT 0x08000000UL
#define HRP_VIEW_SHARE 1
#define HRP_VIEW_UNMAP 2

// ------------------------------------------------------------------
// 计数器
// ------------------------------------------------------------------
static int g_pass = 0;
static int g_fail = 0;
static int g_obs  = 0;

static void Ok(const char* what)
{
	++g_pass;
	printf("  [ OK ] %s\n", what);
}

static void Fail(const char* what)
{
	++g_fail;
	printf("  [FAIL] %s\n", what);
}

// 观察记录：不是判据，是**事实**
static void Obs(const char* what)
{
	++g_obs;
	printf("  [obs ] %s\n", what);
}

// ------------------------------------------------------------------
// 工具
// ------------------------------------------------------------------
static void InitNt()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		return;
	}
	pNtCreateFile = reinterpret_cast<NtCreateFilePtr>(
		reinterpret_cast<void*>(GetProcAddress(ntdll, "NtCreateFile")));
	pNtCreateSection = reinterpret_cast<NtCreateSectionPtr>(
		reinterpret_cast<void*>(GetProcAddress(ntdll, "NtCreateSection")));
	pNtMapViewOfSection = reinterpret_cast<NtMapViewOfSectionPtr>(
		reinterpret_cast<void*>(GetProcAddress(ntdll, "NtMapViewOfSection")));
}

// 当前进程是否提权（不依赖 shellapi.h 的 IsUserAnAdmin）
static bool IsElevated()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		return false;
	}
	TOKEN_ELEVATION te = {};
	DWORD sz = sizeof(te);
	const BOOL ok = GetTokenInformation(token, TokenElevation, &te, sizeof(te), &sz);
	CloseHandle(token);
	return ok && te.TokenIsElevated != 0;
}

// 尝试开启 SeBackupPrivilege（备份意图读文件的必要前提）。
// 返回 true = 成功开启（或本来就开着）。
static bool TryEnableBackupPrivilege()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		return false;
	}

	LUID luid = {};
	if (!LookupPrivilegeValueW(nullptr, SE_BACKUP_NAME, &luid)) {
		CloseHandle(token);
		return false;
	}

	TOKEN_PRIVILEGES tp = {};
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	const BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
	const DWORD err = GetLastError();
	CloseHandle(token);

	// AdjustTokenPrivileges 成功但 err=ERROR_NOT_ALL_ASSIGNED ⇒ 没这个特权
	return ok && err == ERROR_SUCCESS;
}

// 普通 CreateFileW 读打开，返回是否成功，并记录 GetLastError。
static bool TryCreateFileW(const wchar_t* path, DWORD share, DWORD flags,
	DWORD* outErr, HANDLE* outHandle)
{
	HANDLE h = CreateFileW(path, GENERIC_READ, share, nullptr, OPEN_EXISTING,
		flags, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		*outErr = GetLastError();
		*outHandle = nullptr;
		return false;
	}
	*outErr = 0;
	*outHandle = h;
	return true;
}

// 读前 4 字节，判断是不是 hive 签名 "regf"。
static bool ReadHiveMagic(HANDLE h, char out[5])
{
	LARGE_INTEGER zero = {};
	SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);

	char buf[4] = {};
	DWORD read = 0;
	if (!ReadFile(h, buf, 4, &read, nullptr) || read != 4) {
		out[0] = 0;
		return false;
	}
	memcpy(out, buf, 4);
	out[4] = 0;
	return true;
}

// ------------------------------------------------------------------
// 检查一：基线（负对照）—— 探针自己的读路径必须是通的
// ------------------------------------------------------------------
static void CheckBaseline()
{
	printf("\n=== 检查一：基线（负对照）—— 自建普通文件必须能读 ===\n");

	wchar_t tmp[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, tmp);
	wchar_t path[MAX_PATH] = {};
	wsprintfW(path, L"%sr3sc_hive_probe_%lu.bin", tmp, GetCurrentProcessId());

	// 写一个带 "regf" 头的 4KB 文件（模拟一个**未加载**的 hive 文件）
	HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		Fail("基线：连普通文件都建不出来 -> 探针环境有问题，后续结论不可信");
		return;
	}

	unsigned char buf[4096] = {};
	memcpy(buf, "regf", 4);           // hive 签名
	DWORD written = 0;
	WriteFile(h, buf, sizeof(buf), &written, nullptr);
	CloseHandle(h);

	if (written != sizeof(buf)) {
		Fail("基线：写入字节数不对");
		DeleteFileW(path);
		return;
	}
	Ok("基线：普通文件已建好（4096 B，头 4 字节 = 'regf'）");

	// 读回来
	HANDLE r = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (r == INVALID_HANDLE_VALUE) {
		Fail("基线：普通文件读打开失败 -> 读路径本身坏了");
		DeleteFileW(path);
		return;
	}
	Ok("基线：普通文件读打开成功");

	char magic[5] = {};
	if (ReadHiveMagic(r, magic) && memcmp(magic, "regf", 4) == 0) {
		Ok("基线：读到 'regf' 签名 -> 探针的「读 hive 签名」判据本身有效");
	}
	else {
		Fail("基线：读不到 'regf' -> 判据无效（后面所有'读不到'都不能归因）");
	}
	CloseHandle(r);

	// ★ 关键推论：一个**未加载**的 hive 文件，就是普通文件，随便读。
	//   所以"hive 直读"的可行性**完全取决于活 hive 能不能被打开**。
	Obs("推论：未加载的 hive 文件 = 普通文件 -> 可读（本检查已证）");
	Obs("-> 决定性问题只剩「活 hive（已被系统加载）能不能被打开」");

	// ★★ 负对照：用**同一个 NtCreateFile** 打开这个普通文件。
	//   这一条是为了让后面"活 hive 打不开"能被归因 —— 如果连普通文件都打不开，
	//   那就是**探针自己的 NtCreateFile 调用写错了**，而不是"系统拒绝"。
	//   （第一版就踩过：CreateDisposition 写成 0 / 路径没加 `\??\` 前缀，
	//     结果活 hive 一律 0xC000000D，看着像"被拒"其实是参数错。）
	if (pNtCreateFile) {
		wchar_t ntPath[600] = {};
		wsprintfW(ntPath, L"\\??\\%s", path);

		HRP_UNICODE_STRING name = {};
		name.Buffer = ntPath;
		name.Length = static_cast<USHORT>(wcslen(ntPath) * sizeof(wchar_t));
		name.MaximumLength = static_cast<USHORT>(name.Length + sizeof(wchar_t));

		HRP_OBJECT_ATTRIBUTES oa = {};
		oa.Length = sizeof(oa);
		oa.ObjectName = &name;
		oa.Attributes = 0x00000040UL;   // OBJ_CASE_INSENSITIVE

		HRP_IO_STATUS_BLOCK iosb = {};
		HANDLE hn = nullptr;
		// ⚠️ 参数顺序：... FileAttributes, **ShareAccess, CreateDisposition, CreateOptions**,
		//    EaBuffer, EaLength。CreateDisposition 与 CreateOptions **不能传反** ——
		//    传反了 CreateDisposition 变成一个非法枚举值 ⇒ 0xC000000D
		//    （STATUS_INVALID_PARAMETER），而且**连普通文件都打不开**，
		//    看上去却像"系统拒绝"。本探针第一版就是这么错的，靠负对照抓到。
		const NTSTATUS st = pNtCreateFile(&hn, GENERIC_READ, &oa, &iosb, nullptr,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			1 /* CreateDisposition = FILE_OPEN */,
			HRP_FILE_OPEN_FOR_BACKUP_INTENT | HRP_FILE_NON_DIRECTORY_FILE /* CreateOptions */,
			nullptr, 0);

		if (st >= 0 && hn) {
			Ok("负对照：同一个 NtCreateFile 能打开普通文件 -> 该调用方式本身有效");
			CloseHandle(hn);
		}
		else {
			Fail("负对照：NtCreateFile 连普通文件都打不开 -> 后面活 hive 的结论**不可信**");
			printf("        NTSTATUS=0x%08lX\n", static_cast<unsigned long>(st));
		}
	}

	DeleteFileW(path);
}

// ------------------------------------------------------------------
// 检查二：活 hive 直开（各种 share / flags 组合）
// ------------------------------------------------------------------
struct HiveTarget {
	const wchar_t* path;
	const char*    label;
	bool           userHive;   // true = 当前用户自己的 NTUSER.DAT
};

static void CheckLiveHives(bool useBackupIntent)
{
	printf("\n=== 检查二：活 hive 直开（%s）===\n",
		useBackupIntent ? "含备份意图" : "普通读");

	wchar_t userHive[MAX_PATH] = {};
	{
		wchar_t profile[MAX_PATH] = {};
		DWORD n = GetEnvironmentVariableW(L"USERPROFILE", profile, MAX_PATH);
		if (n > 0 && n < MAX_PATH) {
			wsprintfW(userHive, L"%s\\NTUSER.DAT", profile);
		}
	}

	const HiveTarget targets[] = {
		{ L"C:\\Windows\\System32\\config\\SYSTEM",   "HKLM\\SYSTEM   (活)", false },
		{ L"C:\\Windows\\System32\\config\\SOFTWARE", "HKLM\\SOFTWARE (活)", false },
		{ L"C:\\Windows\\System32\\config\\SAM",      "HKLM\\SAM      (活)", false },
		{ L"C:\\Windows\\System32\\config\\SECURITY", "HKLM\\SECURITY (活)", false },
		{ userHive,                                   "HKCU NTUSER.DAT(活)", true  },
	};

	for (const HiveTarget& t : targets) {
		if (t.path[0] == 0) {
			continue;
		}

		// 存在性先证一下（否则"打不开"可能只是路径不对）。
		// ★ 必须区分"真的不存在"与"连 stat 都不让"：后者是**权限**问题 ——
		//   非提权下 `C:\Windows\System32\config\*` 就属于这一类
		//   （目录 ACL 不让读元数据）。把两者混为一谈会得出错误的"文件不存在"。
		const DWORD attrs = GetFileAttributesW(t.path);
		if (attrs == INVALID_FILE_ATTRIBUTES) {
			const DWORD se = GetLastError();
			const bool reallyMissing = (se == ERROR_FILE_NOT_FOUND || se == ERROR_PATH_NOT_FOUND);
			printf("  · %s\n", t.label);
			printf("        连 GetFileAttributes 都失败，err=%lu（%s）\n", se,
				reallyMissing ? "文件真的不存在" : "★ 权限不足，不是不存在");
			if (!reallyMissing) {
				Obs("→ 非提权下连元数据都读不到 => 更不可能打开");
			}
			continue;
		}

		// 组合 A：普通共享（读 + 写 + 删共享）—— 最宽松
		DWORD errA = 0;
		HANDLE hA = nullptr;
		const bool okA = TryCreateFileW(t.path, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			0, &errA, &hA);

		// 组合 B：只读共享
		DWORD errB = 0;
		HANDLE hB = nullptr;
		const bool okB = TryCreateFileW(t.path, FILE_SHARE_READ, 0, &errB, &hB);

		printf("  · %s\n", t.label);
		if (okA) {
			Obs("共享全开 -> 打开**成功**");
			char magic[5] = {};
			if (ReadHiveMagic(hA, magic)) {
				printf("        读到签名 '%s'%s\n", magic,
					memcmp(magic, "regf", 4) == 0 ? "（是 hive）" : "（不是 hive？）");
			}
			CloseHandle(hA);
		}
		else {
			printf("        共享全开 -> 失败，Win32 err=%lu\n", errA);
		}

		if (okB) {
			Obs("只读共享 -> 打开**成功**");
			CloseHandle(hB);
		}
		else {
			printf("        只读共享 -> 失败，Win32 err=%lu\n", errB);
		}

		// 组合 C：CreateFileW + FILE_FLAG_BACKUP_SEMANTICS
		//   （这条最贴近"备份软件"的读法，也是最可能绕过共享检查的一条）
		if (useBackupIntent) {
			DWORD errC = 0;
			HANDLE hC = nullptr;
			const bool okC = TryCreateFileW(t.path,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				FILE_FLAG_BACKUP_SEMANTICS, &errC, &hC);
			if (okC) {
				Obs("备份语义(CreateFileW) -> 打开**成功**");
				CloseHandle(hC);
			}
			else {
				printf("        备份语义(CreateFileW) -> 失败，Win32 err=%lu\n", errC);
			}
		}

		// 组合 D：NtCreateFile + FILE_OPEN_FOR_BACKUP_INTENT
		if (useBackupIntent && pNtCreateFile) {
			// ★ `NtCreateFile` 吃的是 **NT 路径**，不是 Win32 路径：
			//   必须加 `\??\` 前缀（Win32 那层前缀是 kernel32!CreateFileW 自己加的）。
			//   传裸 `C:\...` 会得到 0xC000000D（STATUS_INVALID_PARAMETER），
			//   看起来像"备份意图被拒"，其实是参数错 —— 探针自己先踩过。
			wchar_t ntPath[600] = {};
			wsprintfW(ntPath, L"\\??\\%s", t.path);

			HRP_UNICODE_STRING name = {};
			name.Buffer = ntPath;
			name.Length = static_cast<USHORT>(wcslen(ntPath) * sizeof(wchar_t));
			name.MaximumLength = static_cast<USHORT>(name.Length + sizeof(wchar_t));

			HRP_OBJECT_ATTRIBUTES oa = {};
			oa.Length = sizeof(oa);
			oa.ObjectName = &name;
			// ★ 必须带 OBJ_CASE_INSENSITIVE(0x40)：Win32 风格路径（含盘符）走
			//   `NtCreateFile` 时要按大小写不敏感解析，缺了会走到不同的失败分支。
			oa.Attributes = 0x00000040UL;   // OBJ_CASE_INSENSITIVE

			HRP_IO_STATUS_BLOCK iosb = {};
			HANDLE hD = nullptr;
			// ⚠️ 同 CheckBaseline 的负对照：CreateDisposition 必须是 FILE_OPEN(1)，
			//   且**不能**与 CreateOptions 传反（传反 ⇒ 0xC000000D，看着像"被拒"）。
			const NTSTATUS st = pNtCreateFile(&hD, GENERIC_READ, &oa, &iosb, nullptr,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				1 /* CreateDisposition = FILE_OPEN */,
				HRP_FILE_OPEN_FOR_BACKUP_INTENT | HRP_FILE_NON_DIRECTORY_FILE /* CreateOptions */,
				nullptr, 0);

			if (st >= 0 && hD) {
				Obs("备份意图(NtCreateFile) -> 打开**成功**");
				CloseHandle(hD);
			}
			else {
				printf("        备份意图(NtCreateFile) -> 失败，NTSTATUS=0x%08lX\n",
					static_cast<unsigned long>(st));
			}
		}
	}
}

// ------------------------------------------------------------------
// 检查三：内存映射（若打开成功 ⇒ 映射后是无 API 可拦的直接内存访问）
// ------------------------------------------------------------------
static void CheckMapping()
{
	printf("\n=== 检查三：内存映射（打开成功才可能）===\n");

	if (!pNtCreateSection || !pNtMapViewOfSection) {
		Obs("ntdll 缺 NtCreateSection / NtMapViewOfSection -> 跳过");
		return;
	}

	const wchar_t* path = L"C:\\Windows\\System32\\config\\SOFTWARE";

	HANDLE hFile = CreateFileW(path, GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("  打不开 %ls（err=%lu）-> 无法进入映射检查\n",
			path, GetLastError());
		Obs("★ 打开这一步就挡住了 -> 映射路径**不可达**");
		return;
	}
	Obs("文件已打开 -> 继续试映射");

	HANDLE hSection = nullptr;
	NTSTATUS st = pNtCreateSection(&hSection, SECTION_MAP_READ, nullptr, nullptr,
		PAGE_READONLY, HRP_SEC_COMMIT, hFile);
	if (st < 0 || !hSection) {
		printf("  NtCreateSection 失败，NTSTATUS=0x%08lX\n", static_cast<unsigned long>(st));
		CloseHandle(hFile);
		return;
	}
	Obs("NtCreateSection 成功");

	PVOID base = nullptr;
	SIZE_T viewSize = 0;
	st = pNtMapViewOfSection(hSection, GetCurrentProcess(), &base, 0, 0, nullptr,
		&viewSize, HRP_VIEW_SHARE, 0, PAGE_READONLY);
	if (st < 0 || !base) {
		printf("  NtMapViewOfSection 失败，NTSTATUS=0x%08lX\n", static_cast<unsigned long>(st));
		CloseHandle(hSection);
		CloseHandle(hFile);
		return;
	}

	char magic[5] = {};
	memcpy(magic, base, 4);
	magic[4] = 0;
	printf("  映射成功：base=%p size=%llu 头 4 字节='%s'%s\n", base,
		static_cast<unsigned long long>(viewSize), magic,
		memcmp(magic, "regf", 4) == 0 ? "（是 hive）" : "");

	// ★★ 这就是决定性事实：映射之后是**直接内存读**，用户态没有任何 API 经过。
	Obs("★★ 映射后直接内存读到了 hive 内容 -> 该路径**用户态无法拦**（无 API 可挂）");

	UnmapViewOfFile(base);
	CloseHandle(hSection);
	CloseHandle(hFile);
}

// ------------------------------------------------------------------
// 检查四：能否 RegSaveKey 导出（"合法导出"这条路）
// ------------------------------------------------------------------
static void CheckRegSaveKey()
{
	printf("\n=== 检查四：RegSaveKey 导出（合法导出，另说）===\n");

	HKEY hk = nullptr;
	const LSTATUS ls = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0,
		KEY_READ, &hk);
	if (ls != ERROR_SUCCESS) {
		Obs("打不开 HKCU\\Software -> 跳过");
		return;
	}

	wchar_t tmp[MAX_PATH] = {};
	GetTempPathW(MAX_PATH, tmp);
	wchar_t out[MAX_PATH] = {};
	wsprintfW(out, L"%sr3sc_hivesave_%lu.hiv", tmp, GetCurrentProcessId());
	DeleteFileW(out);

	// RegSaveKeyW 需要 SeBackupPrivilege
	const LSTATUS ls2 = RegSaveKeyW(hk, out, nullptr);
	RegCloseKey(hk);

	if (ls2 == ERROR_SUCCESS) {
		Obs("RegSaveKey 成功 -> 导出的 .hiv 就是**普通文件**，随便读（见检查一）");
		Obs("★ 注意：这条走的是**合法导出 API**，不是「直读活 hive」");
		DeleteFileW(out);
	}
	else {
		printf("  RegSaveKey 失败，err=%ld（多半缺 SeBackupPrivilege）\n", ls2);
		Obs("合法导出这条路在当前权限下不可行");
	}
}

// ------------------------------------------------------------------
int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	SetConsoleOutputCP(65001);

	bool useBackupIntent = true;
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--no-elev") == 0) {
			useBackupIntent = false;
		}
	}

	printf("R3ShieldCore —— hive 文件直读可行性探针\n");
	printf("本探针不挂 hook、不注入、不跑引擎；只读，只在自己 %%TEMP%% 下建普通文件。\n");

	InitNt();
	if (!pNtCreateFile) {
		printf("!! ntdll 缺 NtCreateFile -> 探针不完整\n");
	}

	const bool admin = IsElevated();
	printf("当前进程：%s\n", admin ? "管理员" : "普通用户");

	if (useBackupIntent) {
		const bool priv = TryEnableBackupPrivilege();
		printf("SeBackupPrivilege：%s\n", priv ? "已开启" : "不可用（非管理员或未分配）");
	}

	CheckBaseline();
	CheckLiveHives(useBackupIntent);
	CheckMapping();
	CheckRegSaveKey();

	printf("\n=== 结果：通过 %d / 失败 %d / 观察 %d ===\n", g_pass, g_fail, g_obs);
	printf("（本探针的产出主要是 [obs] 事实行，判据只用来证明探针自身可信）\n");

	return g_fail == 0 ? 0 : 1;
}
