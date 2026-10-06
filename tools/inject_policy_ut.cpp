//
// inject_policy_ut.cpp —— `inject_policy.{h,cpp}` 的单元测试（v42）
//
// ==================================================================
// 为什么必须单测这张表
// ==================================================================
//
// 这张表决定**哪些进程会被注入、以什么强度注入**。判错的两种后果：
//
//   · 把该 Skip 的判成 Thin/Full（比如把 `consent.exe` 注进去）
//     ⇒ UAC 框可能根本不出现（v29 那条实测：提权链任一环静默拒 = UAC 不弹）。
//   · 把该 Thin 的判成 Skip（比如 `explorer.exe`）
//     ⇒ 静默退回"只有轮询路"，盲区从 ~0 变回 10~60 ms ——
//       而**表面上什么都看不出来**，正是 v41「还是没拦住」的成因。
//
// 所以每一条都要**钉住**，而不是靠读代码确认。
//
// ★ 还钉两条不变量：
//   ① 两张表**互斥**（同名不能既"绝不注入"又"瘦注入"）；
//   ② 只有 **%SystemRoot% 下**的同名进程才享受 Skip/Thin ——
//      `D:\tools\explorer.exe` 这种山寨货必须走 Full
//      （否则就是"用文件名当身份"的经典漏洞）。
//
// 链法（见 build_ut.sh）：只链 `inject_policy.cpp` + kernel32，
// 因为它**故意不依赖** stdafx / 共享内存 / Policy。
//
#include "inject_policy.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>

namespace
{
	int g_pass = 0;
	int g_fail = 0;

	void Check(bool ok, const char* what, const char* detail = "")
	{
		if (ok) {
			++g_pass;
			printf("PASS %s%s%s\n", what, detail[0] ? " -- " : "", detail);
		}
		else {
			++g_fail;
			printf("FAIL %s%s%s\n", what, detail[0] ? " -- " : "", detail);
		}
	}

	// 拼一个 %SystemRoot% 下的路径。
	void WinPath(WCHAR* out, size_t cch, const WCHAR* relative) noexcept
	{
		WCHAR root[MAX_PATH] = {};
		GetWindowsDirectoryW(root, _countof(root));
		swprintf_s(out, cch, L"%s\\%s", root, relative);
	}

	InjectPolicy::Mode ClassifyWin(const WCHAR* relative, bool thinAllowed) noexcept
	{
		WCHAR path[MAX_PATH * 2] = {};
		WinPath(path, _countof(path), relative);
		return InjectPolicy::ClassifyImagePath(path, thinAllowed);
	}

	const char* Name(InjectPolicy::Mode m) noexcept
	{
		return InjectPolicy::ModeName(m);
	}

	void ExpectWin(const char* relative, bool thinAllowed, InjectPolicy::Mode expected)
	{
		WCHAR wide[260] = {};
		mbstowcs(wide, relative, _countof(wide) - 1);

		const InjectPolicy::Mode got = ClassifyWin(wide, thinAllowed);
		char detail[320] = {};
		sprintf_s(detail, sizeof(detail), "%s\\%s thin=%d -> %s (期望 %s)",
			"<Windows>", relative, thinAllowed ? 1 : 0, Name(got), Name(expected));
		Check(got == expected, relative, detail);
	}

	// 瘦名单的**期望内容**（钉住：改表必须改这里 —— 铁律 15）。
	const char* kExpectedThin[] = {
		"explorer.exe",
		"svchost.exe",
		"runtimebroker.exe",
	};

	// 必须在"绝不注入"里、**绝不能**变成 Thin/Full 的进程。
	const char* kMustStayNeverInject[] = {
		"consent.exe",
		"LogonUI.exe",
		"winlogon.exe",
		"csrss.exe",
		"lsass.exe",
		"services.exe",
		"dwm.exe",
		"TextInputHost.exe",
		"ShellExperienceHost.exe",
		"StartMenuExperienceHost.exe",
		"SearchHost.exe",
		"conhost.exe",
	};
}

int main()
{
	printf("=== inject_policy 单元测试（v42 瘦注入分类表）===\n\n");

	WCHAR windowsRoot[MAX_PATH] = {};
	GetWindowsDirectoryW(windowsRoot, _countof(windowsRoot));
	printf("SystemRoot = %ls\n\n", windowsRoot);

	// ---------------------------------------------------------------
	printf("-- 1. 瘦名单：thin=1 必须是 Thin，thin=0 必须退化成 Skip --\n");
	// ---------------------------------------------------------------
	for (const char* name : kExpectedThin) {
		WCHAR wide[260] = {};
		mbstowcs(wide, name, _countof(wide) - 1);
		ExpectWin(name, true, InjectPolicy::Mode::Thin);
		ExpectWin(name, false, InjectPolicy::Mode::Skip);
		// ★ 名字单独问也要能认出来（日志/自检路径）
		Check(InjectPolicy::IsThinInjectBaseName(wide), "IsThinInjectBaseName 命中", name);
	}

	// ---------------------------------------------------------------
	printf("\n-- 2. 绝不注入：thin 开关不影响（永远 Skip）--\n");
	// ---------------------------------------------------------------
	for (const char* name : kMustStayNeverInject) {
		WCHAR wide[260] = {};
		mbstowcs(wide, name, _countof(wide) - 1);
		ExpectWin(name, true, InjectPolicy::Mode::Skip);
		ExpectWin(name, false, InjectPolicy::Mode::Skip);
		Check(InjectPolicy::IsNeverInjectBaseName(wide), "IsNeverInjectBaseName 命中", name);
	}

	// ---------------------------------------------------------------
	printf("\n-- 3. 两张表必须互斥（同名不能既 Never 又 Thin）--\n");
	// ---------------------------------------------------------------
	for (const char* name : kExpectedThin) {
		WCHAR wide[260] = {};
		mbstowcs(wide, name, _countof(wide) - 1);
		Check(!InjectPolicy::IsNeverInjectBaseName(wide),
			"瘦名单成员不在绝不注入名单里", name);
	}
	for (const char* name : kMustStayNeverInject) {
		WCHAR wide[260] = {};
		mbstowcs(wide, name, _countof(wide) - 1);
		Check(!InjectPolicy::IsThinInjectBaseName(wide),
			"绝不注入成员不在瘦名单里", name);
	}

	// ---------------------------------------------------------------
	printf("\n-- 4. 普通进程 = Full（不能被误判成 Skip/Thin）--\n");
	// ---------------------------------------------------------------
	ExpectWin("notepad.exe", true, InjectPolicy::Mode::Full);
	ExpectWin("System32\\cmd.exe", true, InjectPolicy::Mode::Full);
	ExpectWin("System32\\Taskmgr.exe", true, InjectPolicy::Mode::Full);
	ExpectWin("System32\\WindowsPowerShell\\v1.0\\powershell.exe", true, InjectPolicy::Mode::Full);

	// ---------------------------------------------------------------
	printf("\n-- 5. ★ 目录校验：只有 %%SystemRoot%% 下的同名进程才享受待遇 --\n");
	// ---------------------------------------------------------------
	// 攻击者把自己的样本改名成 explorer.exe —— 必须走 Full（被完整监控）。
	{
		const WCHAR* fakes[] = {
			L"D:\\tools\\explorer.exe",
			L"D:\\malware\\svchost.exe",
			L"C:\\Users\\Public\\explorer.exe",
		};
		for (const WCHAR* fake : fakes) {
			const InjectPolicy::Mode got = InjectPolicy::ClassifyImagePath(fake, true);
			char narrow[260] = {};
			wcstombs(narrow, fake, sizeof(narrow) - 1);
			char detail[320] = {};
			sprintf_s(detail, sizeof(detail), "%s -> %s（期望 Full：用文件名当身份是经典漏洞）",
				narrow, Name(got));
			Check(got == InjectPolicy::Mode::Full, "山寨路径不得享受 Skip/Thin", detail);
		}

		// ★ 前缀相同但**不是子目录**：`C:\Windows2\explorer.exe`
		WCHAR sibling[MAX_PATH * 2] = {};
		swprintf_s(sibling, L"%s2\\explorer.exe", windowsRoot);
		const InjectPolicy::Mode got = InjectPolicy::ClassifyImagePath(sibling, true);
		Check(got == InjectPolicy::Mode::Full,
			"同前缀但非子目录（<root>2\\explorer.exe）必须是 Full",
			Name(got));
	}

	// ---------------------------------------------------------------
	printf("\n-- 6. 大小写 / 分隔符不敏感 --\n");
	// ---------------------------------------------------------------
	{
		WCHAR upper[MAX_PATH * 2] = {};
		swprintf_s(upper, L"%s\\EXPLORER.EXE", windowsRoot);
		// 整串大写（含盘符与目录部分）
		for (WCHAR* p = upper; *p; ++p) {
			*p = (WCHAR)towupper(*p);
		}
		Check(InjectPolicy::ClassifyImagePath(upper, true) == InjectPolicy::Mode::Thin,
			"全大写路径仍认作 Thin", "");

		//
		// ★ 正斜杠只出现在**基础名之前**那一段。
		//
		// 真实路径的分隔符恒为 `\`（`GetWindowsDirectoryW` /
		// `QueryFullProcessImageNameW` 都返回 `\`），所以不能把根目录的
		// 分隔符也换成 `/` —— 那测的是一个**不存在**的输入。
		// 这里只把"最后一个分隔符"改成 `/`，专门测 `BaseNameOf` 的
		// 正斜杠分支（`C:\Windows/explorer.exe`）。
		//
		WCHAR slashed[MAX_PATH * 2] = {};
		swprintf_s(slashed, L"%s/explorer.exe", windowsRoot);
		Check(InjectPolicy::ClassifyImagePath(slashed, true) == InjectPolicy::Mode::Thin,
			"基础名前用正斜杠仍认作 Thin", "");

		WCHAR mixed[MAX_PATH * 2] = {};
		swprintf_s(mixed, L"%s\\SvChOsT.ExE", windowsRoot);
		Check(InjectPolicy::ClassifyImagePath(mixed, true) == InjectPolicy::Mode::Thin,
			"混合大小写 svchost 仍认作 Thin", "");
	}

	// ---------------------------------------------------------------
	printf("\n-- 6b. ★ 长路径 / NT 前缀必须剥掉（否则 explorer 会装全量 hook）--\n");
	// ---------------------------------------------------------------
	{
		WCHAR longPath[MAX_PATH * 4] = {};
		swprintf_s(longPath, L"\\\\?\\%s\\explorer.exe", windowsRoot);
		Check(InjectPolicy::ClassifyImagePath(longPath, true) == InjectPolicy::Mode::Thin,
			"\\\\?\\C:\\Windows\\explorer.exe 剥前缀后认作 Thin", "");

		WCHAR ntPath[MAX_PATH * 4] = {};
		swprintf_s(ntPath, L"\\??\\%s\\explorer.exe", windowsRoot);
		Check(InjectPolicy::ClassifyImagePath(ntPath, true) == InjectPolicy::Mode::Thin,
			"\\??\\C:\\Windows\\explorer.exe 剥前缀后认作 Thin", "");

		WCHAR unc[MAX_PATH * 4] = {};
		swprintf_s(unc, L"\\\\?\\UNC\\server\\share\\explorer.exe");
		Check(InjectPolicy::ClassifyImagePath(unc, true) == InjectPolicy::Mode::Full,
			"\\\\?\\UNC\\... 映射不回 SystemRoot，判 Full（保守）", "");

		// 山寨货套个 \\?\ 前缀也不能变成 Thin
		WCHAR fakeLong[MAX_PATH * 4] = {};
		swprintf_s(fakeLong, L"\\\\?\\D:\\tools\\explorer.exe");
		Check(InjectPolicy::ClassifyImagePath(fakeLong, true) == InjectPolicy::Mode::Full,
			"\\\\?\\D:\\tools\\explorer.exe 剥前缀后仍是 Full", "");
	}

	// ---------------------------------------------------------------
	printf("\n-- 7. 空/无效输入 → Full（保守：不放过监控）--\n");
	// ---------------------------------------------------------------
	Check(InjectPolicy::ClassifyImagePath(nullptr, true) == InjectPolicy::Mode::Full,
		"nullptr -> Full", "");
	Check(InjectPolicy::ClassifyImagePath(L"", true) == InjectPolicy::Mode::Full,
		"空串 -> Full", "");
	Check(InjectPolicy::ClassifyImagePath(L"explorer.exe", true) == InjectPolicy::Mode::Full,
		"裸文件名（无目录）-> Full", "");

	// ---------------------------------------------------------------
	printf("\n-- 8. ClassifyCurrentProcess：本进程是测试 exe，必须是 Full --\n");
	// ---------------------------------------------------------------
	{
		const InjectPolicy::Mode self = InjectPolicy::ClassifyCurrentProcess(true);
		Check(self == InjectPolicy::Mode::Full,
			"本测试进程（inject_policy_ut.exe）分类为 Full", Name(self));
	}

	// ---------------------------------------------------------------
	printf("\n-- 10. MatchesNeverInjectPath：用户名单（v49，ini: never_inject=）--\n");
	// ---------------------------------------------------------------
	//
	// ★ 这个匹配器决定"哪些进程**完全不受监控**"。它比内置名单更危险：
	//   内置名单只认 %SystemRoot% 下的系统进程，而用户名单是任意路径。
	//   所以必须钉死两件事：
	//     ① 目录前缀**不能**溢出到同前缀的别的目录（`MyApp` vs `MyApp-evil`）；
	//     ② 配置写坏（空 / 纯分隔符）时**一个都不免**（安全方向）。
	//
	{
		const WCHAR* kProbe = L"D:\\Program Files\\MyApp\\MyApp.exe";

		Check(InjectPolicy::MatchesNeverInjectPath(kProbe,
			L"D:\\Program Files\\MyApp\\MyApp.exe"),
			"完整 exe 路径精确命中", "");

		Check(InjectPolicy::MatchesNeverInjectPath(kProbe,
			L"D:\\Program Files\\MyApp"),
			"目录前缀（无结尾 \\）命中", "");

		Check(InjectPolicy::MatchesNeverInjectPath(kProbe,
			L"D:\\Program Files\\MyApp\\"),
			"目录前缀（有结尾 \\）命中", "");

		Check(InjectPolicy::MatchesNeverInjectPath(kProbe,
			L"d:\\program files\\myapp"),
			"大小写不敏感", "");

		Check(InjectPolicy::MatchesNeverInjectPath(
			L"D:/Program Files/MyApp/MyApp.exe",
			L"D:\\Program Files\\MyApp"),
			"路径里用 / 也认边界", "");

		Check(InjectPolicy::MatchesNeverInjectPath(
			L"D:\\Program Files\\MyApp\\MyApp.exe",
			L"D:/Program Files/MyApp"),
			"前缀写成 / 也命中（手写 ini 常见）", "");

		// ★ 路径边界 —— 本函数存在的唯一理由
		Check(!InjectPolicy::MatchesNeverInjectPath(
			L"D:\\Program Files\\MyApp-evil\\malware.exe",
			L"D:\\Program Files\\MyApp"),
			"**不**命中同前缀的另一目录 MyApp-evil", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(
			L"D:\\Program Files\\MyApp2\\x.exe",
			L"D:\\Program Files\\MyApp"),
			"**不**命中同前缀的另一目录 MyApp2", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(
			L"D:\\Program Files\\MyAppX.exe",
			L"D:\\Program Files\\MyApp"),
			"**不**命中同前缀的另一文件名", "");

		Check(!InjectPolicy::MatchesNeverInjectPath(
			L"C:\\Windows\\System32\\cmd.exe",
			L"D:\\Program Files\\MyApp"),
			"完全不同的路径不命中", "");

		// 盘根前缀：`C:\` 应当命中 C: 盘下的一切（且不能溢出到 `C:\` 之外）
		Check(InjectPolicy::MatchesNeverInjectPath(L"C:\\Windows\\cmd.exe", L"C:\\"),
			"盘根前缀 C:\\ 命中 C: 盘下的路径", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(L"D:\\x.exe", L"C:\\"),
			"盘根前缀 C:\\ 不命中 D: 盘", "");

		// 配置写坏 ⇒ 一个都不免（安全方向）
		Check(!InjectPolicy::MatchesNeverInjectPath(nullptr, L"D:\\App"),
			"imagePath=nullptr -> false", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(kProbe, nullptr),
			"prefix=nullptr -> false", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(L"", L"D:\\App"),
			"imagePath 空串 -> false", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(kProbe, L""),
			"prefix 空串 -> false", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(kProbe, L"\\"),
			"prefix 只有单个分隔符 -> false（否则匹配一切）", "");
		Check(!InjectPolicy::MatchesNeverInjectPath(kProbe, L"\\\\"),
			"prefix 只有两个分隔符 -> false（否则匹配所有 UNC）", "");
	}

	// ---------------------------------------------------------------
	printf("\n-- 11. ModeName 稳定性（日志里靠它认档位）--\n");
	// ---------------------------------------------------------------
	Check(strcmp(Name(InjectPolicy::Mode::Full), "Full") == 0, "ModeName(Full)", Name(InjectPolicy::Mode::Full));
	Check(strcmp(Name(InjectPolicy::Mode::Thin), "Thin") == 0, "ModeName(Thin)", Name(InjectPolicy::Mode::Thin));
	Check(strcmp(Name(InjectPolicy::Mode::Skip), "Skip") == 0, "ModeName(Skip)", Name(InjectPolicy::Mode::Skip));

	// ---------------------------------------------------------------
	printf("\n-- 12. ★ v53 内置路径豁免：VMware Tools 必须 Skip --\n");
	// ---------------------------------------------------------------
	//
	// 为什么单独钉：这条判据让一个**非 Windows 目录**的进程拿到"完全不注入"，
	// 是 v53 唯一放宽的地方。两件事必须同时成立：
	//   ① 真的命中 —— 否则共享剪贴板（取证通道）会被引擎自己的
	//      clipboard hook 掐死，"日志拿不出来"这个病没治好；
	//   ② 不能溢出 —— 改个名 / 换个目录就能免注入 = 白送后门。
	//
	{
		// ---- ① 必须命中 ----
		Check(InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"),
			"命中 vmtoolsd.exe（标准安装路径）", "");
		Check(InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files\\VMware\\VMware Tools\\vmware-user-svc.exe"),
			"命中 vmware-user-svc.exe（会话代理 = 共享剪贴板本体）", "");
		Check(InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files\\VMware\\VMware Tools\\vmware-tray.exe"),
			"命中 vmware-tray.exe", "");
		Check(InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files (x86)\\VMware\\VMware Tools\\vmtoolsd.exe"),
			"命中 Program Files (x86) 变体", "");
		Check(InjectPolicy::IsBuiltinNeverInjectPath(
			L"D:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"),
			"★ 盘符任意（Windows 装在 D: 也认）", "");
		Check(InjectPolicy::IsBuiltinNeverInjectPath(
			L"c:\\program files\\vmware\\vmware tools\\VMTOOLSD.EXE"),
			"大小写不敏感", "");

		// ⚠️ 刻意**不**测"路径里用 `/`"：`QueryFullProcessImageNameW` /
		//    `GetModuleFileNameW` **只会**返回 `\`，归一化是死代码。
		//    真写成 `/` 时判不中 ⇒ 退化成 Full（安全方向），不会假豁免。

		// ---- ② 不能溢出 ----
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(
			L"D:\\tools\\vmtoolsd.exe"),
			"**不**命中：只改了名、不在 Program Files\\VMware\\VMware Tools 下", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Users\\Public\\VMware\\VMware Tools\\vmtoolsd.exe"),
			"**不**命中：目录结构对但不在 Program Files 根下", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program FilesXYZ\\VMware\\VMware Tools\\vmtoolsd.exe"),
			"**不**命中：Program FilesXYZ（目录边界，防裸前缀）", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files\\VMware\\VMware Tools-evil\\vmtoolsd.exe"),
			"**不**命中：VMware Tools-evil（目录边界）", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files\\OtherVendor\\VMware\\VMware Tools\\x.exe"),
			"**不**命中：VMware Tools 不在 Program Files 根的第一层", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(
			L"C:\\Program Files\\VMware\\VMware Tools"),
			"**不**命中：路径以目录结尾（不是镜像文件）", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(nullptr),
			"nullptr -> false", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(L""),
			"空串 -> false", "");
		Check(!InjectPolicy::IsBuiltinNeverInjectPath(L"\\VMware\\VMware Tools\\vmtoolsd.exe"),
			"无盘符 -> false", "");

		// ---- ③ 与 ClassifyImagePath 的接线（最容易"写了规则但命中不了"）----
		Check(InjectPolicy::ClassifyImagePath(
			L"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe", true)
			== InjectPolicy::Mode::Skip,
			"ClassifyImagePath: VMware Tools -> Skip（先于 Windows 目录那道门）", "");
		Check(InjectPolicy::ClassifyImagePath(
			L"D:\\tools\\vmtoolsd.exe", true) == InjectPolicy::Mode::Full,
			"ClassifyImagePath: 山寨 vmtoolsd.exe -> Full（仍受完整监控）", "");
	}

	printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
