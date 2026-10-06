//
// high_risk_process_ut.cpp —— 钉住 v61「高危进程」三条判据的语义边界。
//
// 为什么需要这个测试：
//
//   v60b 复盘（`Windows XP Horror`）暴露了一条结构性盲区 ——
//   `IsHighRiskProcessImage` 判的是"**这一次创建**该不该拦"，数据来自
//   被注入进程里的 hook ⇒ **只看得见被监控进程发起、且落在引擎观测窗内**
//   的创建。症状键（SwapMouseButtons / HideIcons / Wallpaper）在整份日志里
//   **0 命中**，正是因为破坏发生在观测窗之前。
//
//   v61 补的是另一条路：引擎定期**快照全机进程**，逐个过
//   `HighRiskProcessReasonForRoot` —— 不依赖注入覆盖、也不依赖观测窗。
//
//   本测试钉的就是那份判据的"度"：
//     ① 伪装系统进程名   ② 形近伪装   ③ 已知攻击工具
//   以及**同样重要的**：不该报的绝不能报（负对照）。
//
// ★ 本测试里"必须不报"的用例和"必须报"的用例**数量相当** ——
//   一个只会说"是"的判据没有价值，误报会把这个提示功能整个淹掉。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string>
#include <vector>

namespace R3ShieldCoreRules
{
	const char* HighRiskProcessReasonForRoot(const wchar_t* imagePath, const wchar_t* systemRoot) noexcept;
	const char* HighRiskProcessReason(const wchar_t* imagePath) noexcept;
	bool IsHighRiskProcess(const wchar_t* imagePath) noexcept;
	void NormalizeImageNameForCompare(const wchar_t* fileName, wchar_t* out, size_t cch) noexcept;
	unsigned long SystemCriticalImageCount() noexcept;
	const wchar_t* SystemCriticalImageAt(unsigned long index) noexcept;
	unsigned long MasqueradeExemptCount() noexcept;
	const wchar_t* MasqueradeExemptAt(unsigned long index) noexcept;
	unsigned long AttackToolNameCount() noexcept;
	const wchar_t* AttackToolNameAt(unsigned long index) noexcept;
	unsigned long SystemImageExtraDirCount() noexcept;
	bool SystemImageExtraDirAt(unsigned long index, const wchar_t** name,
		const wchar_t** dir, unsigned long* depth) noexcept;
}

namespace R3ShieldCoreChannel
{
	void StubClearProtectReg() noexcept;
}

// 测试统一用这个假 systemRoot —— 不依赖真机的 Windows 目录，
// 结果才是可复现的（真机路径随机器变，测出来的东西就不一样了）。
static const wchar_t* kRoot = L"C:\\Windows";

static int g_pass = 0;
static int g_fail = 0;

static void Check(const char* name, bool ok)
{
	printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) g_pass++; else g_fail++;
}

// 判据断言。wantHigh 同时决定"该报"和"不该报"两个方向。
static void Expect(const wchar_t* imagePath, bool wantHigh, const char* name)
{
	const char* reason = R3ShieldCoreRules::HighRiskProcessReasonForRoot(imagePath, kRoot);
	const bool got = (reason != nullptr);
	printf("      path=%-62ls\n", imagePath);
	printf("      reason=%s\n", reason ? reason : "(null)");
	Check(name, got == wantHigh);
}

// 系统目录里的路径拼接（覆盖 System32 / SysWOW64 / Sysnative / WinSxS）。
static std::wstring SysPath(const wchar_t* sub, const wchar_t* name)
{
	std::wstring p = kRoot;
	p += L"\\";
	p += sub;
	p += L"\\";
	p += name;
	return p;
}

// 不在系统目录里的路径（用户可写目录 / 伪装目录）。
static std::wstring ElsewherePath(const wchar_t* name)
{
	std::wstring p = L"C:\\Users\\tester\\AppData\\Local\\Temp\\";
	p += name;
	return p;
}

int wmain()
{
	setlocale(LC_ALL, "");
	R3ShieldCoreChannel::StubClearProtectReg();

	// ---------------------------------------------------------------
	// A. ① 系统进程名伪装 —— 名字对但位置不对
	// ---------------------------------------------------------------
	printf("\n=== A. 系统进程名伪装（不在系统目录）必须报 ===\n");
	Expect(ElsewherePath(L"svchost.exe").c_str(), true, "Temp\\svchost.exe 必须报");
	Expect(L"C:\\Users\\Public\\lsass.exe", true, "Public\\lsass.exe 必须报");
	Expect(L"C:\\ProgramData\\services.exe", true, "ProgramData\\services.exe 必须报");
	Expect(L"C:\\Tools\\explorer.exe", true, "普通目录\\explorer.exe 必须报");
	Expect(L"D:\\games\\csrss.exe", true, "非系统盘\\csrss.exe 必须报");

	// ★ 对抗用例：路径里**故意包含** `\Windows\System32\` 片段，
	//   但整体不在系统根下 —— 判据必须锚定在 systemRoot 上，不能被片段骗过。
	Expect(L"C:\\Evil\\Windows\\System32\\svchost.exe", true,
		"含 System32 片段但不在系统根下 → 必须报");

	// ---------------------------------------------------------------
	// B. 真的系统进程 —— 绝不能报（否则每次开机刷屏）
	// ---------------------------------------------------------------
	printf("\n=== B. 真正的系统进程绝不能报 ===\n");
	Expect(SysPath(L"System32", L"svchost.exe").c_str(), false, "System32\\svchost.exe 不能报");
	Expect(SysPath(L"System32", L"lsass.exe").c_str(), false, "System32\\lsass.exe 不能报");
	Expect(SysPath(L"System32", L"services.exe").c_str(), false, "System32\\services.exe 不能报");
	Expect(SysPath(L"SysWOW64", L"svchost.exe").c_str(), false, "SysWOW64\\svchost.exe 不能报");
	Expect(SysPath(L"System32", L"smss.exe").c_str(), false, "System32\\smss.exe 不能报");
	Expect(SysPath(L"System32", L"taskmgr.exe").c_str(), false, "System32\\taskmgr.exe 不能报");
	Expect(L"C:\\Windows\\System32\\drivers\\etc\\svchost.exe", false,
		"System32 子目录里的同名文件也不报（在系统根下）");

	// 系统目录里的**其它**正常程序 —— 判据不看它们（避免 System32 噪音）
	printf("\n=== B2. 系统目录里的普通程序不该报 ===\n");
	Expect(SysPath(L"System32", L"notepad.exe").c_str(), false, "System32\\notepad.exe 不能报");
	Expect(SysPath(L"System32", L"cmd.exe").c_str(), false, "System32\\cmd.exe 不能报");
	Expect(SysPath(L"System32", L"powershell.exe").c_str(), false, "System32\\powershell.exe 不能报");

	// ---------------------------------------------------------------
	// B3. ★★ 真机回归：**这些路径在一台普通 Win10 上真实存在**
	// ---------------------------------------------------------------
	//
	// 这一节的每一条都来自 v61 真机首跑的 `r3shieldcore-console.log`：
	// 引擎在 270 个进程里报出 **5 个候选，全是误报** ——
	//   C:\Windows\explorer.exe                     （住在 Windows **根目录**）
	//   C:\Windows\SystemApps\...\SearchHost.exe     （住在 SystemApps）
	//   C:\Windows\SystemApps\...\StartMenuExperienceHost.exe
	//   C:\Windows\SystemApps\...\TextInputHost.exe
	//   C:\Windows\SystemApps\...\ShellExperienceHost.exe
	//
	// 为什么原来的用例全绿却没发现：**测试里的"正常路径"只写了
	// `System32\...`** —— 覆盖不到真机上真实存在的正常路径。
	// 这一节把真机观察到的路径**原样**钉住（铁律 54：对照必须来自真机）。
	printf("\n=== B3. ★ 真机真实存在的正常路径（v61 首跑 5 个误报的回归）===\n");
	Expect(L"C:\\Windows\\explorer.exe", false,
		"★ 根目录的 explorer.exe 不能报（explorer 本来就不在 System32）");
	Expect(L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe", false,
		"★ SystemApps 里的 SearchHost.exe 不能报");
	Expect(L"C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe", false,
		"★ SystemApps 里的 StartMenuExperienceHost.exe 不能报");
	Expect(L"C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\TextInputHost.exe", false,
		"★ SystemApps 里的 TextInputHost.exe 不能报");
	Expect(L"C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe", false,
		"★ SystemApps 里的 ShellExperienceHost.exe 不能报");
	// 大小写不敏感（真机 systemRoot 实测是 `C:\WINDOWS`）
	Expect(L"C:\\WINDOWS\\explorer.exe", false, "★ 大小写不敏感：C:\\WINDOWS\\explorer.exe 不能报");

	// ★ 反向对照（铁律 54）：修误报**绝不能**顺手把整个根目录 / SystemApps 洗白
	printf("\n=== B4. ★ 反向对照：根目录与 SystemApps 里的**别人**照报 ===\n");
	Expect(L"C:\\Windows\\lsass.exe", true,
		"★ 根目录里的 lsass.exe 必须报（不能因为 explorer 在根目录就把根目录洗白）");
	Expect(L"C:\\Windows\\svchost.exe", true, "★ 根目录里的 svchost.exe 必须报");
	Expect(L"C:\\Windows\\SystemApps\\evil\\svchost.exe", true,
		"★ SystemApps 里的 svchost.exe 必须报（只对 4 个 UWP 宿主名开口子）");
	Expect(L"C:\\Windows\\SystemApps\\evil\\lsass.exe", true, "★ SystemApps 里的 lsass.exe 必须报");
	Expect(L"C:\\Windows\\SystemApps\\evil\\scvhost.exe", true,
		"★ SystemApps 里的形近伪装照样报（额外目录只对 ① 的**精确名字**开放）");
	// explorer.exe 只在**根目录**（深度 0）合法 —— 深一层就不算数
	Expect(L"C:\\Windows\\Temp\\explorer.exe", true,
		"★ C:\\Windows\\Temp\\explorer.exe 必须报（经典落盘目录！深度=1 ≠ 0）");
	Expect(L"C:\\Windows\\SystemApps\\evil\\explorer.exe", true,
		"★ explorer.exe 只认根目录：放进 SystemApps 必须报（深度=2 ≠ 0）");
	// UWP 宿主只在 SystemApps 下**正好一层**（包目录）合法
	Expect(L"C:\\Windows\\SystemApps\\SearchHost.exe", true,
		"★ SystemApps 根下**直接**放 SearchHost.exe 必须报（深度=0 ≠ 1）");
	Expect(L"C:\\Windows\\SystemApps\\evil\\deep\\SearchHost.exe", true,
		"★ SystemApps 下深两层必须报（深度=2 ≠ 1）");
	Expect(L"C:\\Windows\\SearchHost.exe", true, "★ 根目录里的 SearchHost.exe 必须报");

	// ---------------------------------------------------------------
	// C. ② 形近伪装
	// ---------------------------------------------------------------
	printf("\n=== C. 形近伪装必须报 ===\n");
	Expect(ElsewherePath(L"lsass .exe").c_str(), true, "`lsass .exe`（夹空格）必须报");
	Expect(ElsewherePath(L"lsass.exe ").c_str(), true, "`lsass.exe `（尾随空格）必须报");
	Expect(ElsewherePath(L"svch0st.exe").c_str(), true, "`svch0st.exe`（0→o）必须报");
	Expect(ElsewherePath(L"scvhost.exe").c_str(), true, "`scvhost.exe`（相邻交换）必须报");
	Expect(ElsewherePath(L"1sass.exe").c_str(), true, "`1sass.exe`（1→l）必须报");
	Expect(ElsewherePath(L"csrss .exe").c_str(), true, "`csrss .exe` 必须报");
	Expect(ElsewherePath(L"winl0gon.exe").c_str(), true, "`winl0gon.exe` 必须报");
	Expect(ElsewherePath(L"expl0rer.exe").c_str(), true, "`expl0rer.exe` 必须报");

	printf("\n=== C2. 形近伪装的反向对照 ===\n");
	Expect(ElsewherePath(L"ssms.exe").c_str(), false,
		"`ssms.exe`（SQL Server Management Studio）必须豁免");
	Expect(ElsewherePath(L"service.exe").c_str(), false,
		"`service.exe`（第三方服务极常见）不能报 —— 不做任意编辑距离");
	Expect(ElsewherePath(L"myservice.exe").c_str(), false, "普通程序名不能报");
	Expect(ElsewherePath(L"host.exe").c_str(), false, "`host.exe` 不能报");

	// ---------------------------------------------------------------
	// D. ③ 已知攻击工具
	// ---------------------------------------------------------------
	printf("\n=== D. 已知攻击工具必须报 ===\n");
	Expect(ElsewherePath(L"mimikatz.exe").c_str(), true, "mimikatz.exe 必须报");
	Expect(ElsewherePath(L"mimikatz_x64.exe").c_str(), false,
		"`mimikatz_x64.exe` 不在名单里（按**完整去扩展名**比对，不做子串）");
	Expect(L"C:\\Windows\\System32\\mimikatz.exe", true,
		"攻击工具放到 System32 里照样报（与位置无关）");
	Expect(ElsewherePath(L"psexec.exe").c_str(), true, "psexec.exe 必须报");
	Expect(ElsewherePath(L"Rubeus.exe").c_str(), true, "大小写不敏感：Rubeus.exe 必须报");
	Expect(ElsewherePath(L"procdump.exe").c_str(), true, "procdump.exe 必须报");
	Expect(ElsewherePath(L"ncat.exe").c_str(), true, "ncat.exe 必须报");

	printf("\n=== D2. 攻击工具名单的反向对照 ===\n");
	Expect(ElsewherePath(L"notepad.exe").c_str(), false, "notepad.exe 不能报");
	Expect(ElsewherePath(L"chrome.exe").c_str(), false, "chrome.exe 不能报");
	Expect(ElsewherePath(L"putty.exe").c_str(), false, "putty.exe（正常工具）不能报");

	// ---------------------------------------------------------------
	// E. 普通程序 —— 负对照（这个功能会不会把用户机器刷屏）
	// ---------------------------------------------------------------
	printf("\n=== E. 普通程序绝不能报 ===\n");
	Expect(L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", false, "Chrome 不能报");
	Expect(L"C:\\Program Files\\Microsoft VS Code\\Code.exe", false, "VS Code 不能报");
	Expect(L"C:\\Users\\tester\\AppData\\Local\\Temp\\setup.exe", false,
		"临时目录里的安装包不能报（用户可写目录刻意不作为判据）");
	Expect(L"C:\\Users\\tester\\Downloads\\portable.exe", false, "下载目录里的便携程序不能报");
	Expect(L"C:\\ProgramData\\SomeApp\\updater.exe", false, "ProgramData 里的更新器不能报");
	Expect(L"C:\\Windows\\Temp\\installer.exe", false, "Windows\\Temp 里的安装器不能报");

	// ---------------------------------------------------------------
	// F. 边界：systemRoot 判不出来时必须**不报**
	// ---------------------------------------------------------------
	printf("\n=== F. systemRoot 缺失时不猜（宁可漏报也不误报）===\n");
	{
		const char* reason = R3ShieldCoreRules::HighRiskProcessReasonForRoot(
			L"C:\\Anywhere\\svchost.exe", L"");
		Check("systemRoot 为空 → 返回 nullptr（不把真 svchost 报成伪装）", reason == nullptr);

		reason = R3ShieldCoreRules::HighRiskProcessReasonForRoot(L"", kRoot);
		Check("空路径 → 返回 nullptr", reason == nullptr);

		reason = R3ShieldCoreRules::HighRiskProcessReasonForRoot(nullptr, kRoot);
		Check("空指针 → 返回 nullptr", reason == nullptr);
	}

	// ---------------------------------------------------------------
	// G. 归一化函数本身（判据 ② 的地基）
	// ---------------------------------------------------------------
	printf("\n=== G. 归一化函数 ===\n");
	{
		wchar_t buf[128] = {};
		R3ShieldCoreRules::NormalizeImageNameForCompare(L"LSASS .EXE", buf, 128);
		Check("大写+空格被归一化掉", wcscmp(buf, L"lsass.exe") == 0);

		R3ShieldCoreRules::NormalizeImageNameForCompare(L"svch0st.exe", buf, 128);
		Check("0 被折叠成 o", wcscmp(buf, L"svchost.exe") == 0);

		R3ShieldCoreRules::NormalizeImageNameForCompare(L"chrome.exe", buf, 128);
		Check("普通名字保持原样", wcscmp(buf, L"chrome.exe") == 0);
	}

	// ---------------------------------------------------------------
	// H. ★ 穷举：系统组件名的**每一个相邻交换变体**都必须有归宿
	// ---------------------------------------------------------------
	//
	// 这条是本次判据设计里唯一"会随规则表增长而自动加严"的断言：
	// 以后往 `kSystemCriticalImages` 里加名字时，只要新名字的某个交换变体
	// 撞上了某个正常软件名，这里就会 FAIL —— 逼着人显式决定
	// "是检出，还是加进豁免表"，而不是让误报悄悄上线。
	//
	printf("\n=== H. 穷举相邻交换变体（每个都要么检出、要么豁免）===\n");
	{
		std::vector<std::wstring> exempt;
		for (unsigned long i = 0; i < R3ShieldCoreRules::MasqueradeExemptCount(); i++) {
			exempt.emplace_back(R3ShieldCoreRules::MasqueradeExemptAt(i));
		}

		int variants = 0;
		int detected = 0;
		int exempted = 0;
		int missing = 0;

		for (unsigned long i = 0; i < R3ShieldCoreRules::SystemCriticalImageCount(); i++) {
			const std::wstring systemImage = R3ShieldCoreRules::SystemCriticalImageAt(i);

			for (size_t k = 0; k + 1 < systemImage.size(); k++) {
				if (systemImage[k] == systemImage[k + 1]) {
					continue;   // 相同字符交换 = 没变化
				}

				std::wstring variant = systemImage;
				const wchar_t tmp = variant[k];
				variant[k] = variant[k + 1];
				variant[k + 1] = tmp;
				if (variant == systemImage) {
					continue;
				}

				variants++;

				bool isExempt = false;
				for (const std::wstring& e : exempt) {
					if (e == variant) {
						isExempt = true;
						break;
					}
				}

				const std::wstring path = ElsewherePath(variant.c_str());
				const char* reason =
					R3ShieldCoreRules::HighRiskProcessReasonForRoot(path.c_str(), kRoot);

				if (isExempt) {
					if (reason == nullptr) {
						exempted++;
					}
					else {
						missing++;
						printf("      !! 豁免表里的 %ls 仍被判高危：%s\n",
							variant.c_str(), reason);
					}
				}
				else if (reason != nullptr) {
					detected++;
				}
				else {
					missing++;
					printf("      !! 漏检交换变体：%ls（源自 %ls）\n",
						variant.c_str(), systemImage.c_str());
				}
			}
		}

		printf("      变体 %d 个：检出 %d，豁免 %d，漏 %d\n",
			variants, detected, exempted, missing);
		Check("所有交换变体都有归宿（检出或显式豁免）", missing == 0);
		Check("确实产生了变体（穷举没跑空）", variants > 100);
		Check("豁免表条目都在变体集合里（没有僵尸豁免）", exempted == static_cast<int>(exempt.size()));
	}

	// ---------------------------------------------------------------
	// H2. ★ 穷举「额外规范目录」表：每条 (名字, 目录, 深度) 都要成立
	// ---------------------------------------------------------------
	//
	// 与 H 节同一个套路：表本身会随"真机又发现一个正常路径"而增长，
	// 所以断言要能**自动跟着表长**，而不是把路径硬编码一遍。
	// 对每一条：
	//   · `<root><目录>` 后**正好** `深度` 层目录 + 名字 ⇒ 必须**不报**
	//   · 再深一层                                    ⇒ 必须**报**
	//   · 同名放进 Temp（用户可写目录）                ⇒ 必须**报**
	//
	printf("\n=== H2. 穷举额外规范目录表（(名字,目录,深度) 三元组）===\n");
	{
		const unsigned long count = R3ShieldCoreRules::SystemImageExtraDirCount();
		printf("      额外目录条目 %lu 条\n", count);
		Check("额外目录表非空（v61 真机误报的修复确实在表里）", count > 0);

		bool allOk = true;
		for (unsigned long i = 0; i < count; i++) {
			const wchar_t* name = nullptr;
			const wchar_t* dir = nullptr;
			unsigned long depth = 0;
			if (!R3ShieldCoreRules::SystemImageExtraDirAt(i, &name, &dir, &depth)
				|| !name || !dir) {
				printf("      !! 条目 %lu 取不出来\n", i);
				allOk = false;
				continue;
			}

			// 构造"正好 depth 层"的规范路径
			std::wstring canonical = kRoot;
			canonical += dir;
			for (unsigned long d = 0; d < depth; d++) {
				canonical += L"Pkg";
				canonical += std::to_wstring(d);
				canonical += L"\\";
			}
			canonical += name;

			const char* r1 = R3ShieldCoreRules::HighRiskProcessReasonForRoot(
				canonical.c_str(), kRoot);
			if (r1 != nullptr) {
				printf("      !! 规范路径被判高危：%ls（%s）\n", canonical.c_str(), r1);
				allOk = false;
			}

			// 再深一层 ⇒ 必须报
			std::wstring deeper = kRoot;
			deeper += dir;
			for (unsigned long d = 0; d < depth + 1; d++) {
				deeper += L"Pkg";
				deeper += std::to_wstring(d);
				deeper += L"\\";
			}
			deeper += name;
			const char* r2 = R3ShieldCoreRules::HighRiskProcessReasonForRoot(
				deeper.c_str(), kRoot);
			if (r2 == nullptr) {
				printf("      !! 多一层的路径没报：%ls\n", deeper.c_str());
				allOk = false;
			}

			// 同名丢进用户可写目录 ⇒ 必须报（额外目录不是"免死金牌"）
			const std::wstring elsewhere = ElsewherePath(name);
			const char* r3 = R3ShieldCoreRules::HighRiskProcessReasonForRoot(
				elsewhere.c_str(), kRoot);
			if (r3 == nullptr) {
				printf("      !! Temp 里的 %ls 没报\n", name);
				allOk = false;
			}
		}
		Check("每条 (名字,目录,深度)：正好=不报 / 更深=报 / 换目录=报", allOk);
	}

	// ---------------------------------------------------------------
	// I. 判据表自身的卫生
	// ---------------------------------------------------------------
	printf("\n=== I. 判据表卫生 ===\n");
	{
		bool allLower = true;
		for (unsigned long i = 0; i < R3ShieldCoreRules::SystemCriticalImageCount(); i++) {
			const std::wstring s = R3ShieldCoreRules::SystemCriticalImageAt(i);
			if (s.size() < 5 || s.compare(s.size() - 4, 4, L".exe") != 0) {
				allLower = false;
				printf("      !! 系统组件名 %ls 不是 .exe 结尾\n", s.c_str());
			}
		}
		Check("系统组件名都带 .exe 后缀", allLower);

		bool toolsOk = true;
		for (unsigned long i = 0; i < R3ShieldCoreRules::AttackToolNameCount(); i++) {
			const std::wstring t = R3ShieldCoreRules::AttackToolNameAt(i);
			if (t.empty() || t.find(L'.') != std::wstring::npos) {
				toolsOk = false;
				printf("      !! 攻击工具名 %ls 不该带扩展名\n", t.c_str());
			}
		}
		Check("攻击工具名都不带扩展名", toolsOk);

		// 真机自检：本机的 svchost 必须判不出来（用**真实** systemRoot ——
		// 本机 Windows 可能装在 D: 上，写死 C:\Windows 会测出一个假结果）。
		wchar_t realRoot[MAX_PATH] = {};
		GetWindowsDirectoryW(realRoot, MAX_PATH);
		std::wstring realSvchost = realRoot;
		realSvchost += L"\\System32\\svchost.exe";
		printf("      真机 systemRoot=%ls\n", realRoot);
		const char* reason = R3ShieldCoreRules::HighRiskProcessReason(realSvchost.c_str());
		Check("真机 systemRoot 下 System32\\svchost.exe 不报", reason == nullptr);
	}

	printf("\nSUMMARY: %d passed, %d failed -> %s\n",
		g_pass, g_fail, g_fail == 0 ? "PASS" : "FAIL");
	return g_fail == 0 ? 0 : 1;
}
