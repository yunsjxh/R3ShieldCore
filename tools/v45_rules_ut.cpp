//
// v45_rules_ut.cpp - v45 进程来源豁免表 + 「豁免不可伪造」单元测试。
//
// 背景（用户真机实测）：
//   `kProcessPathRules` 里 `\Windows\System32\` 是**片段**规则 ⇒ System32 下
//   每一个程序都判 HIGH；而 `EvaluateProcess`（process_guard.cpp）在 block
//   模式下对 highRisk 的进程创建是**直接拒**（不是只记录）。
//   结果引擎把**自己的部署脚本**打瘫了：
//       PROC BLOCK HIGH CreateProcess image=C:\WINDOWS\system32\tasklist.exe
//   ⇒ start.bat 的存活检查、stop.bat 的管理员判据全部失效。
//
// v45 的修法是加一张 `kCommonTrustedSystemConsoleTools` 豁免表
// （`IsCommonTrustedSystemExecutable`）。本文件钉住三件事，改坏任何一件
// 都在这里红：
//   ① 该放行的（只读 / 诊断 / 文本 / 时间工具）确实放行；
//   ② 不该放行的（LOLBin / 持久化 / 执行类）继续 HIGH；
//   ③ ★ 豁免**不可伪造** —— 改名 + 换目录、改名 + `..` 路径、
//      改名 + 塞进子目录，都不能白嫖这张表。
//
// ⚠️ 测试局限（写清楚免得误读）：`ProcessRiskReason` 返回 nullptr 既可能
//   是"命中豁免"，也可能是"没命中任何规则"。所以「借不到豁免」必须用
//   **本来会命中片段规则**的路径来验（Temp / Downloads / System32 自身），
//   否则 nullptr 说明不了问题。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	const char* ProcessRiskReason(const wchar_t* imagePath, unsigned long processOp, unsigned long parentPid) noexcept;
}

enum { Proc_Create = 1, Proc_Terminate = 2 };

static int g_failed = 0;
static int g_total = 0;

static void Check(const char* note, const wchar_t* path, bool expectHigh)
{
	const char* r = R3ShieldCoreRules::ProcessRiskReason(path, Proc_Create, 0);
	const bool gotHigh = (r != nullptr);
	g_total++;
	const bool ok = (gotHigh == expectHigh);
	if (!ok) {
		g_failed++;
	}
	printf("%s  %-58ls expect=%-4s got=%-4s  %s\n",
		ok ? "OK  " : "FAIL", path,
		expectHigh ? "HIGH" : "norm",
		gotHigh ? "HIGH" : "norm",
		note);
}

int wmain()
{
	setlocale(LC_ALL, "");

	printf("========== ① v45 新增豁免：控制台 / 诊断工具（必须放行） ==========\n");
	{
		struct { const wchar_t* path; const char* note; } c[] = {
			{ L"C:\\Windows\\System32\\tasklist.exe",   "start.bat / stop.bat 的存活与 PID 检查" },
			{ L"C:\\Windows\\System32\\findstr.exe",    "脚本里判 CSV 逗号" },
			{ L"C:\\Windows\\System32\\find.exe",       "" },
			{ L"C:\\Windows\\System32\\timeout.exe",    "脚本里的等待" },
			{ L"C:\\Windows\\System32\\icacls.exe",     "unlock-acl.bat 用的（v57 起默认还原 ACL）" },
			{ L"C:\\Windows\\System32\\whoami.exe",     "v45 起用它判管理员" },
			{ L"C:\\Windows\\System32\\hostname.exe",   "" },
			{ L"C:\\Windows\\System32\\where.exe",      "" },
			{ L"C:\\Windows\\System32\\systeminfo.exe", "" },
			{ L"C:\\Windows\\System32\\sort.exe",       "" },
			{ L"C:\\Windows\\System32\\more.exe",       "" },
			{ L"C:\\Windows\\System32\\fc.exe",         "" },
			{ L"C:\\Windows\\System32\\comp.exe",       "" },
			{ L"C:\\Windows\\System32\\tree.exe",       "" },
			{ L"C:\\Windows\\System32\\attrib.exe",     "" },
			{ L"C:\\Windows\\System32\\choice.exe",     "" },
			{ L"C:\\Windows\\System32\\ping.exe",       "" },
			{ L"C:\\Windows\\System32\\ipconfig.exe",   "" },
			{ L"C:\\Windows\\System32\\netstat.exe",    "" },
			{ L"C:\\Windows\\System32\\nslookup.exe",   "" },
			{ L"C:\\Windows\\System32\\tracert.exe",    "" },
			{ L"C:\\Windows\\System32\\pathping.exe",   "" },
			{ L"C:\\Windows\\System32\\arp.exe",        "" },
			{ L"C:\\Windows\\System32\\getmac.exe",     "" },
		};
		for (auto& x : c) {
			Check(x.note, x.path, false);
		}
	}

	printf("\n========== ② SysWOW64 / 大小写 / 设备路径形态（同一份豁免） ==========\n");
	{
		struct { const wchar_t* path; const char* note; } c[] = {
			{ L"C:\\Windows\\SysWOW64\\tasklist.exe", "SysWOW64 变体" },
			{ L"C:\\Windows\\SysWOW64\\findstr.exe",  "SysWOW64 变体" },
			{ L"C:\\Windows\\SysWOW64\\icacls.exe",   "SysWOW64 变体" },
			{ L"c:\\windows\\system32\\TASKLIST.EXE", "大小写不敏感（规则与豁免都不分大小写）" },
			{ L"\\Device\\HarddiskVolume3\\Windows\\System32\\tasklist.exe", "设备路径形态" },
		};
		for (auto& x : c) {
			Check(x.note, x.path, false);
		}
	}

	printf("\n========== ③ LOLBin / 持久化 / 执行类（必须继续 HIGH） ==========\n");
	{
		struct { const wchar_t* path; const char* note; } c[] = {
			{ L"C:\\Windows\\System32\\cmd.exe",        "执行类 —— 绝不能放行" },
			{ L"C:\\Windows\\System32\\powershell.exe", "★ stop.bat 的自动提权就是被它拦住的" },
			{ L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "★ 真实路径：不是紧跟 System32\\，所以借不到豁免" },
			{ L"C:\\Windows\\System32\\wscript.exe",    "脚本宿主" },
			{ L"C:\\Windows\\System32\\cscript.exe",    "脚本宿主" },
			{ L"C:\\Windows\\System32\\mshta.exe",      "HTA 宿主" },
			{ L"C:\\Windows\\System32\\rundll32.exe",   "LOLBin" },
			{ L"C:\\Windows\\System32\\regsvr32.exe",   "LOLBin" },
			{ L"C:\\Windows\\System32\\msiexec.exe",    "LOLBin" },
			{ L"C:\\Windows\\System32\\certutil.exe",   "下载类" },
			{ L"C:\\Windows\\System32\\bitsadmin.exe",  "下载类" },
			{ L"C:\\Windows\\System32\\curl.exe",       "下载类" },
			{ L"C:\\Windows\\System32\\ftp.exe",        "下载类" },
			{ L"C:\\Windows\\System32\\forfiles.exe",   "执行类" },
			{ L"C:\\Windows\\System32\\schtasks.exe",   "持久化" },
			{ L"C:\\Windows\\System32\\sc.exe",         "持久化 / 服务" },
			{ L"C:\\Windows\\System32\\reg.exe",        "配置变更" },
			{ L"C:\\Windows\\System32\\net.exe",        "★ v45 起 stop.bat 不再依赖它，但它仍必须 HIGH" },
			{ L"C:\\Windows\\System32\\net1.exe",       "net 的别名" },
			{ L"C:\\Windows\\System32\\at.exe",         "持久化" },
			{ L"C:\\Windows\\System32\\taskkill.exe",   "终止动作另有 terminate 判据盯着" },
			{ L"C:\\Windows\\System32\\wmic.exe",       "WMI 可执行方法" },
			{ L"C:\\Windows\\System32\\robocopy.exe",   "横向复制常用" },
		};
		for (auto& x : c) {
			Check(x.note, x.path, true);
		}
	}

	printf("\n========== ④ ★ 豁免不可伪造（这些路径本来就命中片段规则） ==========\n");
	{
		struct { const wchar_t* path; const char* note; } c[] = {
			// 换目录：改名丢到可写 / 已列入高危规则的地方
			{ L"C:\\Windows\\Temp\\tasklist.exe",                     "改名丢进 Windows\\Temp（命中该片段规则）" },
			{ L"C:\\Users\\bob\\AppData\\Local\\Temp\\findstr.exe",    "改名丢进用户 Temp" },
			{ L"D:\\Users\\bob\\Downloads\\icacls.exe",               "改名丢进下载目录" },
			{ L"C:\\ProgramData\\tasklist.exe",                       "改名丢进 ProgramData" },
			// `..` 路径：豁免是**子串**匹配，NormalizeFilePath **不折叠 `..`**
			{ L"C:\\Windows\\System32\\..\\Temp\\tasklist.exe",       "★ 含 \\Windows\\System32\\ 子串，实际在 Temp" },
			{ L"C:\\Windows\\System32\\..\\..\\Temp\\findstr.exe",    "★ 多级 .." },
			{ L"C:\\Windows\\System32\\..\\tasklist.exe",             "★ .. 回到 Windows 根" },
			{ L"C:\\Windows\\SysWOW64\\..\\Temp\\icacls.exe",         "★ SysWOW64 方向的同一绕过" },
			{ L"C:\\Windows\\System32\\..\\Temp\\notepad.exe",        "★ 原有 GUI 豁免表同样不可伪造" },
			// 不是"紧跟目录 + 结尾"
			{ L"C:\\Windows\\System32\\sub\\tasklist.exe",            "★ 塞进 System32 的子目录" },
			{ L"C:\\Windows\\System32\\tasklist.exe.evil",            "★ 文件名不是路径最后一段" },
			{ L"C:\\Windows\\System32\\mytasklist.exe",               "★ 只是包含 tasklist.exe 子串" },
			{ L"C:\\Windows\\System32\\notmyfindstr.exe",             "★ 同理，findstr" },
		};
		for (auto& x : c) {
			Check(x.note, x.path, true);
		}
	}

	printf("\n========== ⑤ 原有行为不受影响（回归） ==========\n");
	{
		struct { const wchar_t* path; bool high; const char* note; } c[] = {
			// 原有 GUI 豁免表
			{ L"C:\\Windows\\System32\\notepad.exe",   false, "原有 GUI 豁免" },
			{ L"C:\\Windows\\System32\\calc.exe",      false, "原有 GUI 豁免" },
			{ L"C:\\Windows\\System32\\mspaint.exe",   false, "原有 GUI 豁免" },
			{ L"C:\\Windows\\System32\\taskmgr.exe",   false, "原有 GUI 豁免" },
			{ L"C:\\Windows\\System32\\explorer.exe",  false, "原有 GUI 豁免" },
			{ L"C:\\Windows\\System32\\eventvwr.exe",  false, "原有 GUI 豁免" },
			// System32 片段规则本身仍然有意义：没进豁免表的照样 HIGH
			{ L"C:\\Windows\\System32\\evil_dropped.exe", true, "System32 里没进豁免表的样本" },
			{ L"C:\\Windows\\SysWOW64\\evil_dropped.exe", true, "SysWOW64 同理" },
			// 其它片段规则
			{ L"C:\\Windows\\Temp\\dropper.exe",       true,  "Windows 临时目录" },
			{ L"C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe", true, "用户临时目录" },
			{ L"C:\\Users\\bob\\Downloads\\setup.exe", true,  "下载目录" },
			{ L"C:\\ProgramData\\payload.exe",         true,  "ProgramData" },
			{ L"C:\\$Recycle.Bin\\S-1-5-21\\x.exe",    true,  "回收站" },
			{ L"C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.exe", true, "启动目录" },
			// 正常位置
			{ L"C:\\Program Files\\Mozilla Firefox\\firefox.exe", false, "Program Files（正常）" },
			{ L"D:\\Games\\steam.exe",                 false, "普通盘（正常）" },
			{ L"C:\\Users\\bob\\AppData\\Local\\Programs\\app\\app.exe", false, "Local Programs（正常）" },
		};
		for (auto& x : c) {
			Check(x.note, x.path, x.high);
		}

		// 终止不判高危（与 procguard_ut 一致）
		const char* r = R3ShieldCoreRules::ProcessRiskReason(
			L"C:\\Windows\\System32\\cmd.exe", Proc_Terminate, 0);
		g_total++;
		if (r != nullptr) {
			g_failed++;
		}
		printf("%s  终止 System32 进程（不应判高危）                       reason=%s\n",
			r == nullptr ? "OK  " : "FAIL", r ? r : "(null)");
	}

	printf("\n%s  失败 %d / %d\n",
		g_failed == 0 ? "全部通过" : "存在失败", g_failed, g_total);
	return g_failed;
}
