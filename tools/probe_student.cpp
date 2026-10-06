//
// probe_student.cpp —— 直接问规则层：
//   「C:\Users\测试\Desktop\student.exe 从桌面/管理员启动，判不判高危？」
//
// 背景：用户报「以管理员启动的 student.exe 显示『Windows 无法访问指定设备、
//       路径或文件』(0xC0000022)，哪怕引擎开着 log 模式」。
//
// 要分清两件事：
//   ① 进程创建路径（EvaluateProcess）：LOG 下高危也只 Record，**不会拦**。
//   ② 注册表 / 文件路径：LOG 下 **高危仍走 Ask**（见 registry_guard.cpp:1160
//      `if (mode == Ask || highRisk)`）—— 若 Ask 问不出去 → fallback=deny → 静默拒。
//
// 本探针把 student.exe 的镜像路径 + 各种父进程喂进进程规则层，
// 看它到底判不判高危；再把启动器常写的键喂进注册表规则层，看是否命中高危。

#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskProcessImage(PCWSTR imagePath, ULONG processOp, ULONG parentPid) noexcept;
	bool IsUserInitiatedLaunch(PCWSTR parentImagePath) noexcept;
	bool IsHighRiskRegistry(PCWSTR keyPath, PCWSTR valueName, ULONG op) noexcept;
	bool IsHighRiskFile(PCWSTR path, ULONG fileOp) noexcept;
}

// ProcessOp::Create = 1（各 Op 独立从 1 起）
static const ULONG kProcessOpCreate = 1;
// R3ShieldCore::Op
enum { OpCreateKey = 1, OpOpenKey = 2, OpSetValueKey = 3, OpDeleteKey = 4 };

struct ProcCase
{
	PCWSTR image;
	const char* note;
};

int main()
{
	setlocale(LC_ALL, ".UTF8");

	printf("=== 一、进程创建判据：student.exe 各形态 ===\n");
	printf("   （注：LOG 模式下进程创建即使高危也只 Record，不拦；\n");
	printf("     这里只回答『判不判高危』，用于排除/确认父子关系规则）\n\n");

	ProcCase cases[] = {
		{ L"C:\\Users\\测试\\Desktop\\student.exe", "用户截图里的真身" },
		{ L"\\??\\C:\\Users\\测试\\Desktop\\student.exe", "NT 路径形态" },
		{ L"C:\\Users\\user\\Desktop\\student.exe", "换用户名" },
		{ L"student.exe", "项目根" },
		{ L"C:\\Users\\user\\Downloads\\student.exe", "下载目录（应对照=高危）" },
		{ L"C:\\Windows\\System32\\student.exe", "System32（应对照=高危）" },
	};

	for (const ProcCase& c : cases)
	{
		const bool high = R3ShieldCoreRules::IsHighRiskProcessImage(c.image, kProcessOpCreate, 0);
		printf("  high=%-3s  ", high ? "YES" : "no");
		wprintf(L"%-50s", c.image);
		printf("  %s\n", c.note);
	}

	printf("\n=== 二、各父进程是否算『人启动』（仅 block_all 下用）===\n\n");
	PCWSTR parents[] = {
		L"C:\\Windows\\explorer.exe",
		L"C:\\Windows\\System32\\svchost.exe",
		L"C:\\Windows\\System32\\cmd.exe",
		L"C:\\Windows\\System32\\powershell.exe",
		nullptr,
	};
	for (PCWSTR p : parents)
	{
		const bool ui = R3ShieldCoreRules::IsUserInitiatedLaunch(p);
		const WCHAR* shown = p ? p : L"(null)";
		wprintf(L"  init=%-3s  %s\n", ui ? L"YES" : L"no", shown);
	}

	printf("\n=== 三、启动器常写的注册表键（LOG 下若高危 → 仍走 Ask）===\n\n");
	struct RegCase { PCWSTR key; PCWSTR val; ULONG op; const char* note; };
	RegCase regs[] = {
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", L"student", OpSetValueKey, "自启动项" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\student.exe", L"", OpCreateKey, "IFEO 劫持点" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"", OpCreateKey, "策略键" },
		{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", L"", OpSetValueKey, "Shell 钩子" },
		{ L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.exe", L"", OpSetValueKey, "exe 关联劫持" },
		{ L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SomeSvc", L"", OpSetValueKey, "服务项" },
		{ L"\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\student\\Settings", L"", OpSetValueKey, "第三方自用配置（应对照=非高危）" },
	};
	for (const RegCase& r : regs)
	{
		const bool high = R3ShieldCoreRules::IsHighRiskRegistry(r.key, r.val, r.op);
		printf("  high=%-3s  ", high ? "YES" : "no");
		wprintf(L"%-58s", r.key);
		printf("  %s\n", r.note);
	}

	printf("\n=== 四、启动/运行常碰的文件路径（hook_file=0 时不生效，仅参考）===\n\n");
	PCWSTR files[] = {
		L"C:\\Windows\\System32\\drivers\\etc\\hosts",
		L"C:\\Windows\\System32\\student.dll",
		L"C:\\Users\\user\\Desktop\\student.exe",
		L"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\a.exe",
	};
	for (PCWSTR f : files)
	{
		const bool high = R3ShieldCoreRules::IsHighRiskFile(f, 1 /*Create*/);
		printf("  high=%-3s  ", high ? "YES" : "no");
		wprintf(L"%s\n", f);
	}

	return 0;
}
