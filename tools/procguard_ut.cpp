//
// procguard_ut.cpp - 进程 / 线程 / 驱动 高危规则单元测试。
//
// 直接链 r3shieldcore_rules.cpp + channel_stub.cpp 的目标文件，纯逻辑验证，
// 不需要引擎、不需要注入。
//
// 覆盖：
//   - IsHighRiskProcessImage    可执行来源敏感位置
//   - ProcessPairRiskReason     可疑父子关系
//   - IsHighRiskThread          远程线程（注入）
//   - IsHighRiskDriverLoad      非系统驱动加载/卸载
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	const char* ProcessRiskReason(const wchar_t* imagePath, unsigned long processOp, unsigned long parentPid) noexcept;
	const char* ProcessPairRiskReason(const wchar_t* parentPath, const wchar_t* childPath) noexcept;
	const char* ThreadRiskReason(unsigned long targetPid, unsigned long selfPid, unsigned long threadOp) noexcept;
	const char* DriverRiskReason(const wchar_t* driverPath, unsigned long driverOp, bool kernelDriverService) noexcept;
}

// Op 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	Proc_Create = 1, Proc_Terminate = 2,
	Thr_Create = 1, Thr_Terminate = 2,
	Drv_Load = 1, Drv_Unload = 2,
};

static int g_failed = 0;
static int g_total = 0;

static void Check(const char* what, bool got, bool expect, const char* reason)
{
	g_total++;
	bool ok = (got == expect);
	if (!ok) g_failed++;
	printf("%s  %-46s expect=%-5s got=%-5s  reason=%s\n",
		ok ? "OK  " : "FAIL", what,
		expect ? "HIGH" : "norm", got ? "HIGH" : "norm",
		reason ? reason : "(null)");
}

int wmain()
{
	setlocale(LC_ALL, "");

	printf("========== 进程来源（IsHighRiskProcessImage） ==========\n");
	{
		struct { const wchar_t* path; bool expect; const char* note; } c[] = {
			{ L"C:\\Windows\\System32\\cmd.exe",                        true,  "System32 下的程序" },
			{ L"C:\\Windows\\SysWOW64\\wscript.exe",                    true,  "SysWOW64 下的程序" },
			{ L"C:\\Windows\\Temp\\dropper.exe",                        true,  "Windows 临时目录" },
			{ L"C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe",        true,  "用户临时目录" },
			{ L"C:\\Users\\bob\\Downloads\\setup.exe",                  true,  "下载目录" },
			{ L"C:\\ProgramData\\payload.exe",                          true,  "ProgramData" },
			{ L"C:\\$Recycle.Bin\\S-1-5-21\\x.exe",                     true,  "回收站" },
			// 对照：正常安装目录
			{ L"C:\\Program Files\\Mozilla Firefox\\firefox.exe",       false, "Program Files（正常）" },
			{ L"C:\\Program Files (x86)\\Tencent\\WeChat\\WeChat.exe",  false, "Program Files x86（正常）" },
			{ L"D:\\Games\\steam.exe",                                  false, "普通盘（正常）" },
			{ L"C:\\Users\\bob\\AppData\\Local\\Programs\\app\\app.exe",false, "Local Programs（正常）" },
		};
		for (auto& x : c) {
			const char* r = R3ShieldCoreRules::ProcessRiskReason(x.path, Proc_Create, 0);
			Check(x.note, r != nullptr, x.expect, r);
		}
		// 终止不判高危
		const char* r = R3ShieldCoreRules::ProcessRiskReason(L"C:\\Windows\\System32\\cmd.exe", Proc_Terminate, 0);
		Check("终止 System32 进程（不应判高危）", r != nullptr, false, r);
	}

	printf("\n========== 可疑父子关系（ProcessPairRiskReason） ==========\n");
	{
		struct { const wchar_t* p; const wchar_t* ch; bool expect; const char* note; } c[] = {
			{ L"C:\\Program Files\\Microsoft Office\\WINWORD.EXE", L"C:\\Windows\\System32\\cmd.exe",        true,  "winword -> cmd" },
			{ L"C:\\Program Files\\Microsoft Office\\EXCEL.EXE",   L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", true, "excel -> powershell" },
			{ L"C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE", L"C:\\Windows\\System32\\wscript.exe",    true,  "outlook -> wscript" },
			{ L"C:\\Program Files\\Google\\Chrome\\chrome.exe",    L"C:\\Windows\\System32\\cmd.exe",        true,  "chrome -> cmd" },
			{ L"C:\\Windows\\System32\\svchost.exe",               L"C:\\Windows\\System32\\cmd.exe",        true,  "svchost -> cmd" },
			{ L"C:\\Windows\\System32\\rundll32.exe",              L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", true, "rundll32 -> powershell" },
			// 对照：正常关系
			{ L"C:\\Windows\\explorer.exe",                        L"C:\\Program Files\\Google\\Chrome\\chrome.exe", false, "explorer -> chrome（正常）" },
			{ L"C:\\Program Files\\Google\\Chrome\\chrome.exe",    L"C:\\Program Files\\Google\\Chrome\\chrome.exe", false, "chrome -> chrome（正常）" },
			{ L"C:\\Windows\\System32\\cmd.exe",                   L"C:\\Windows\\System32\\cmd.exe",        false, "cmd -> cmd（正常）" },
			{ L"C:\\Program Files\\Microsoft Office\\WINWORD.EXE", L"C:\\Program Files\\Microsoft Office\\WINWORD.EXE", false, "winword -> winword（正常）" },
		};
		for (auto& x : c) {
			const char* r = R3ShieldCoreRules::ProcessPairRiskReason(x.p, x.ch);
			Check(x.note, r != nullptr, x.expect, r);
		}
	}

	printf("\n========== 线程（IsHighRiskThread） ==========\n");
	{
		struct { unsigned long target; unsigned long self; unsigned long op; bool expect; const char* note; } c[] = {
			{ 1234, 4321, Thr_Create,  true,  "远程线程注入（pid 不同）" },
			{ 4321, 4321, Thr_Create,  false, "本进程线程（pid 相同）" },
			{ 0,    4321, Thr_Create,  false, "target=0（拿不到）" },
			{ 1234, 4321, Thr_Terminate, false, "终止线程（不判高危）" },
		};
		for (auto& x : c) {
			const char* r = R3ShieldCoreRules::ThreadRiskReason(x.target, x.self, x.op);
			Check(x.note, r != nullptr, x.expect, r);
		}
	}

	printf("\n========== 驱动（IsHighRiskDriverLoad） ==========\n");
	{
		struct { const wchar_t* path; unsigned long op; bool expect; const char* note; } c[] = {
			{ L"C:\\Windows\\System32\\drivers\\tcpip.sys",   Drv_Load,   false, "System32\\drivers（正常）" },
			{ L"C:\\Windows\\SysWOW64\\drivers\\foo.sys",     Drv_Load,   false, "SysWOW64\\drivers（正常）" },
			{ L"C:\\Users\\bob\\Desktop\\rootkit.sys",        Drv_Load,   true,  "桌面上的驱动（高危）" },
			{ L"C:\\Users\\bob\\AppData\\Local\\Temp\\x.sys", Drv_Load,   true,  "临时目录驱动（高危）" },
			{ L"D:\\tools\\byovd.sys",                        Drv_Load,   true,  "非系统目录驱动（高危）" },
			{ L"C:\\Users\\bob\\Desktop\\rootkit.sys",        Drv_Unload, true,  "卸载非系统驱动（高危）" },
			{ L"C:\\Windows\\System32\\drivers\\tcpip.sys",   Drv_Unload, false, "卸载系统驱动（不判高危）" },
		};
		for (auto& x : c) {
			const char* r = R3ShieldCoreRules::DriverRiskReason(x.path, x.op, true);
			Check(x.note, r != nullptr, x.expect, r);
		}
	}

	printf("\n%s  失败 %d / %d\n", g_failed == 0 ? "全部通过" : "存在失败", g_failed, g_total);
	return g_failed;
}
