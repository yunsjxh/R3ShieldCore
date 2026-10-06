//
// uacwhitelist_ut.cpp —— R3ShieldCore v66「全拦模式的 UAC 提权链最小白名单」单测。
//
// 被测对象：`R3ShieldCoreRules::IsUacConsentImage(PCWSTR)`（实现见 registry_guard.cpp）。
//
// ==================================================================
// 为什么这条白名单需要专门一个单测文件
// ==================================================================
//   v66 把全拦模式恢复成"直接拒"（撤销 v21 的"先问再拦"）。硬拒之后必须
//   给 UAC 留一条缝，否则用户连提权框都弹不出来。这条缝就是
//   `IsUacConsentImage` —— 它是**全拦模式下唯一的"放行"判据**。
//
//   ⇒ 一个"只用来放行"的判据，一旦判宽了就是**洞**，而且**不会有人发现**
//     （放行了不报错、日志也正常）。所以它的**反面用例比正面用例更重要**。
//
// ==================================================================
// ★ 本文件的核心判据：盘符别名攻击（这条是真正在防的那个洞）
// ==================================================================
//   `IsTrustedLaunchImage` 走 `NormalizeForTrustedDir`，会把**任意盘符**的
//   `X:\Windows\` 折成 `%SystemRoot%\`。那对它安全 —— 它后面还有
//   **微软签名**校验兜底。
//
//   但 `IsUacConsentImage` **不查签名**（刻意：只在 System32 下三个固定名字
//   上比对，跑 WinVerifyTrust 是多余开销）。若它也沿用别名映射，就有：
//     攻击者在任意可写卷上建 `D:\Windows\System32\consent.exe`
//     → 归一化后 == `%SystemRoot%\System32\consent.exe`
//     → **蹭过白名单** → 全拦模式下被放行启动。
//
//   ⇒ 实现改用 `GetWindowsDirectoryW` 的**真实**目录比前缀。
//     本文件用一对**成对**用例把这个性质钉死：
//       · `<真实Windows目录>\System32\consent.exe`      → **必须 true**
//       · `<非系统盘>\Windows\System32\consent.exe`     → **必须 false**
//     这两个必须同时成立；只测前一个的话，退回别名映射也照样绿
//     —— 那就是铁律 128「闸门负对照走真判据」说的假绿。
//
// ==================================================================
// 为什么这个单测能直接调（不需要单测专用入口）
// ==================================================================
//   `IsUacConsentImage` 定义在 `registry_guard.cpp` 的
//   `namespace R3ShieldCoreRules` **文件作用域**（不在匿名 namespace 里），
//   声明在 `r3shieldcore_rules.h`。所以链接 `registry_guard.obj` 后
//   **直接调用**即可，不需要 `REGUARD_GUARD_UT` 那种包装。
//   构建脚本：`build_guard_ut.sh`（与 v29_guard_ut 同一个脚本）。
//
// ==================================================================
// 机器无关性（**别写死 C:\Windows**）
// ==================================================================
//   Windows 可能装在任意盘/任意目录。所有"真实路径"用例都从
//   `GetWindowsDirectoryW` **现场拼**，不硬编码盘符。
//   本文件还额外打印一次真实 Windows 目录，便于事后核对。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <r3shieldcore/r3shieldcore_shared.h>
#include <r3shieldcore_rules.h>

static int g_pass = 0;
static int g_fail = 0;

// 真实 Windows 目录（无尾反斜杠），如 `C:\Windows`。
static WCHAR g_win[MAX_PATH] = {};

// 一个与系统盘不同的盘符，用于"盘符别名攻击"用例。
static WCHAR g_otherDrive = L'D';

// 拼一条路径：`<win>\System32\consent.exe` 这类。
static void JoinWin(WCHAR* out, size_t cch, PCWSTR tail)
{
	swprintf_s(out, cch, L"%ls\\%ls", g_win, tail);
}

// 通用断言：路径 + 期望值。
static void Check(const char* group, const char* note, PCWSTR path, bool expect)
{
	const bool got = R3ShieldCoreRules::IsUacConsentImage(path);
	const bool ok = (got == expect);
	if (ok) { g_pass++; } else { g_fail++; }

	// 路径可能是 nullptr —— 打印时兜一下，别让 printf 崩掉。
	const WCHAR* shown = path ? path : L"(nullptr)";
	printf("%s [%s] %-40s expect=%-5s got=%-5s  path=%ls\n",
		ok ? "  ok  " : "  FAIL", group, note,
		expect ? "true" : "false", got ? "true" : "false", shown);
}

int main()
{
	setlocale(LC_ALL, ".UTF8");

	// ---- 现场取真实 Windows 目录（机器无关）----
	const UINT winLen = GetWindowsDirectoryW(g_win, _countof(g_win));
	if (winLen == 0 || winLen >= _countof(g_win)) {
		printf("  FAIL [setup] GetWindowsDirectoryW 失败，无法继续\n");
		return 1;
	}
	// 去掉可能的尾部反斜杠（`GetWindowsDirectoryW` 一般不返回，但别赌它）。
	{
		size_t len = wcslen(g_win);
		while (len > 0 && g_win[len - 1] == L'\\') {
			g_win[--len] = L'\0';
		}
	}
	printf("=== UAC 白名单单测（v66）===\n");
	printf("真实 Windows 目录 : %ls\n", g_win);

	// 选一个 != 系统盘的盘符。
	g_otherDrive = (g_win[0] == L'C') ? L'D' : L'C';
	printf("用于别名攻击的盘符: %lc:\n\n", g_otherDrive);

	WCHAR buf[MAX_PATH * 2] = {};

	// ===============================================================
	// 1. ★★★ 正面：三个镜像的**真实**绝对路径 → 必须放行
	// ===============================================================
	printf("=== 1. ★★★ 正面：真实绝对路径 → 放行 ===\n");
	JoinWin(buf, _countof(buf), L"System32\\consent.exe");
	Check("pos", "真实 consent.exe", buf, true);

	JoinWin(buf, _countof(buf), L"System32\\CredentialUIBroker.exe");
	Check("pos", "真实 CredentialUIBroker.exe", buf, true);

	JoinWin(buf, _countof(buf), L"System32\\LogonUI.exe");
	Check("pos", "真实 LogonUI.exe", buf, true);

	// ===============================================================
	// 2. ★★ 大小写 / 分隔符 / NT 风格：都必须照样命中
	//
	//    这几条防"写死大小写或写死反斜杠"的实现（Windows 路径本来就
	//    大小写不敏感，而不同 API 回来的分隔符不保证一致）。
	// ===============================================================
	printf("\n=== 2. ★★ 大小写 / 正斜杠 / \\SystemRoot 风格 → 照样命中 ===\n");
	JoinWin(buf, _countof(buf), L"System32\\CONSENT.EXE");
	Check("case", "全大写 CONSENT.EXE", buf, true);

	JoinWin(buf, _countof(buf), L"system32\\Consent.Exe");
	Check("case", "混合大小写 system32\\Consent.Exe", buf, true);

	// 全大写目录 + 正斜杠（模拟不同来源 API 的形态）。
	{
		WCHAR tmp[MAX_PATH * 2] = {};
		swprintf_s(tmp, _countof(tmp), L"%ls/System32/consent.exe", g_win);
		Check("sep", "正斜杠路径", tmp, true);
	}
	Check("nt", "\\SystemRoot\\System32\\consent.exe",
		L"\\SystemRoot\\System32\\consent.exe", true);
	Check("nt", "\\SystemRoot\\System32\\LogonUI.exe",
		L"\\SystemRoot\\System32\\LogonUI.exe", true);
	Check("nt", "\\SystemRoot\\System32\\CredentialUIBroker.exe",
		L"\\SystemRoot\\System32\\CredentialUIBroker.exe", true);

	// ===============================================================
	// 3. ★★★ 反面核心：**盘符别名攻击** → 必须拒
	//
	//    这一节是"退回 NormalizeForTrustedDir 就会变红"的**回归陷阱**。
	//    §1 的 `<win>\System32\consent.exe` 与这里的
	//    `<别的盘>:\Windows\System32\consent.exe` **必须一真一假**。
	// ===============================================================
	printf("\n=== 3. ★★★ 反面核心：盘符别名攻击（别的盘上的 Windows 目录）→ 必须拒 ===\n");
	{
		WCHAR tmp[MAX_PATH * 2] = {};
		swprintf_s(tmp, _countof(tmp), L"%lc:\\Windows\\System32\\consent.exe", g_otherDrive);
		Check("alias", "非系统盘 X:\\Windows\\System32\\consent.exe", tmp, false);

		swprintf_s(tmp, _countof(tmp), L"%lc:\\Windows\\System32\\LogonUI.exe", g_otherDrive);
		Check("alias", "非系统盘 X:\\Windows\\System32\\LogonUI.exe", tmp, false);

		swprintf_s(tmp, _countof(tmp), L"%lc:\\Windows\\System32\\CredentialUIBroker.exe",
			g_otherDrive);
		Check("alias", "非系统盘 X:\\Windows\\System32\\CredentialUIBroker.exe", tmp, false);

		// 大小写变体 + 正斜杠变体，堵"大小写归一化又顺手带回别名"这条路。
		swprintf_s(tmp, _countof(tmp), L"%lc:/WINDOWS/system32/consent.exe", g_otherDrive);
		Check("alias", "非系统盘 X:/WINDOWS/system32/consent.exe", tmp, false);
	}

	// ===============================================================
	// 4. ★★ 反面：`\\?\` / `\??\` 前缀 → 必须拒
	//
	//    这两种写法能绕过大量"按字符串比前缀"的检查。本实现刻意
	//    **不做**规范化 ⇒ 一律拒（保守方向）。
	// ===============================================================
	printf("\n=== 4. ★★ 反面：\\\\?\\ 与 \\??\\ 前缀 → 必须拒 ===\n");
	{
		WCHAR tmp[MAX_PATH * 2] = {};
		swprintf_s(tmp, _countof(tmp), L"\\\\?\\%ls\\System32\\consent.exe", g_win);
		Check("prefix", "\\\\?\\<win>\\System32\\consent.exe", tmp, false);

		swprintf_s(tmp, _countof(tmp), L"\\??\\%ls\\System32\\consent.exe", g_win);
		Check("prefix", "\\??\\<win>\\System32\\consent.exe", tmp, false);

		// `\\?\GLOBALROOT\...` 也是同类。
		Check("prefix", "\\\\?\\GLOBALROOT\\System32\\consent.exe",
			L"\\\\?\\GLOBALROOT\\System32\\consent.exe", false);
	}

	// ===============================================================
	// 5. ★★ 反面：**同名不同地** —— 文件名对但不在 System32 里 → 必须拒
	//
	//    "文件名等于 consent.exe 就放"是最容易犯的错。
	// ===============================================================
	printf("\n=== 5. ★★ 反面：同名不同地 → 必须拒 ===\n");
	JoinWin(buf, _countof(buf), L"SysWOW64\\consent.exe");
	Check("dir", "<win>\\SysWOW64\\consent.exe（32 位系统目录）", buf, false);

	JoinWin(buf, _countof(buf), L"Temp\\consent.exe");
	Check("dir", "<win>\\Temp\\consent.exe", buf, false);

	JoinWin(buf, _countof(buf), L"consent.exe");
	Check("dir", "<win>\\consent.exe（直接在 Windows 根）", buf, false);

	Check("dir", "C:\\Users\\x\\consent.exe", L"C:\\Users\\x\\consent.exe", false);
	Check("dir", "C:\\Program Files\\consent.exe",
		L"C:\\Program Files\\consent.exe", false);
	Check("dir", "C:\\Windows\\System32 的伪装：C:\\Windows\\System32x\\consent.exe",
		L"C:\\Windows\\System32x\\consent.exe", false);

	// ===============================================================
	// 6. ★★ 反面：**子串/后缀蹭白名单** → 必须拒
	//
	//    这几个是"用 wcsstr 而不是 _wcsicmp"时必踩的坑。
	// ===============================================================
	printf("\n=== 6. ★★ 反面：子串 / 后缀蹭白名单 → 必须拒 ===\n");
	JoinWin(buf, _countof(buf), L"System32\\evil-consent.exe");
	Check("sub", "<win>\\System32\\evil-consent.exe", buf, false);

	JoinWin(buf, _countof(buf), L"System32\\notconsent.exe");
	Check("sub", "<win>\\System32\\notconsent.exe", buf, false);

	JoinWin(buf, _countof(buf), L"System32\\consent.exe.bak");
	Check("sub", "<win>\\System32\\consent.exe.bak", buf, false);

	JoinWin(buf, _countof(buf), L"System32\\consent.exe ");
	Check("sub", "<win>\\System32\\consent.exe（尾随空格）", buf, false);

	JoinWin(buf, _countof(buf), L"System32\\ConsentUIBroker.exe");
	Check("sub", "<win>\\System32\\ConsentUIBroker.exe（伪名）", buf, false);

	// ===============================================================
	// 7. ★★ 反面：相对路径 / 裸文件名 / 未规范化路径 → 必须拒
	// ===============================================================
	printf("\n=== 7. ★★ 反面：相对路径 / 裸名 / 未规范化 → 必须拒 ===\n");
	Check("rel", "裸文件名 consent.exe", L"consent.exe", false);
	Check("rel", "相对路径 System32\\consent.exe", L"System32\\consent.exe", false);
	// `..` 穿越：本实现**不做**路径规范化 ⇒ 必须拒（保守方向）。
	// 若将来加了规范化，这条会变红 —— 那是**提醒**你去重新审视白名单，
	// 不是让你把这条用例删掉。
	JoinWin(buf, _countof(buf), L"System32\\..\\System32\\consent.exe");
	Check("rel", "<win>\\System32\\..\\System32\\consent.exe", buf, false);

	// ===============================================================
	// 8. ★★★ 空输入 → 必须拒（**绝不能放行**）
	//
	//    与 IsTrustedLaunchImage 同一条铁律：拿不到镜像路径时
	//    **不可信**。`NtCreateProcess` / `NtCreateProcessEx` 拿不到路径，
	//    而它们正是进程镂空 / 反射加载的特征手法。
	// ===============================================================
	printf("\n=== 8. ★★★ 空输入 → 必须拒 ===\n");
	Check("null", "nullptr", nullptr, false);
	Check("null", "空串 L\"\"", L"", false);

	// ===============================================================
	// 9. ★★★ 成对性自检（铁律 148 / 128）
	//
	//    上面所有用例"各自"绿，不能证明**这一对**是有效的对照：
	//    如果 `<win>` 恰好就是 `<别的盘>:\Windows`（理论上可能，
	//    若系统盘符不是 C 而我选的盘符正好是系统盘），那 §1 和 §3
	//    测的是同一条字符串，对照就失效了。
	//    所以这里**显式**断言两个对照输入确实不同，且一真一假。
	// ===============================================================
	printf("\n=== 9. ★★★ 成对性自检：§1 与 §3 的输入必须不同、结果必须相反 ===\n");
	{
		WCHAR good[MAX_PATH * 2] = {};
		WCHAR bad[MAX_PATH * 2] = {};
		JoinWin(good, _countof(good), L"System32\\consent.exe");
		swprintf_s(bad, _countof(bad), L"%lc:\\Windows\\System32\\consent.exe", g_otherDrive);

		const bool diffOk = (_wcsicmp(good, bad) != 0);
		const bool goodOk = R3ShieldCoreRules::IsUacConsentImage(good);
		const bool badOk = !R3ShieldCoreRules::IsUacConsentImage(bad);
		const bool ok = diffOk && goodOk && badOk;
		if (ok) { g_pass++; } else { g_fail++; }

		printf("%s [pair] 对照有效: 输入不同=%d(需1) 真路径放行=%d(需1) 别名路径拒=%d(需1)\n",
			ok ? "  ok  " : "  FAIL", diffOk, goodOk, badOk);
		printf("        good=%ls\n        bad =%ls\n", good, bad);
		if (!diffOk) {
			printf("        [!] 两条对照输入相同 -> §1/§3 互相印证不了，本文件失去意义\n");
		}
	}

	printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
