//
// v135_guard_ut.cpp —— 「文件 / 截屏」两个面接进引擎后的行为单测。
//
// ======================================================================
// 这个单测验什么（以及为什么非测不可）
// ======================================================================
// ① **截屏面**：`ScreenMode` 决定"这一次到底怎么替换"。
//    它是 `screen_guard.cpp` 匿名 namespace 里的函数，走
//    `ScreenGuardTest::ScreenModeForTest` 暴露出来（宏隔离，导出表不变）。
//    ★ 关键在 `Pass`：命中"放行"时**不能替换**，而且上报口径要从
//      `Spoofed` 改成 `Allowed` —— 这条只在运行时成立，看代码看不出来。
//
// ② **文件面**：`FillBuffer` / `FillWithText` 决定"填什么"。
//    ★★ 最关键的判据是**分块读的偏移自洽**：
//      文件是按偏移一块一块读的。假文本必须"平铺"，使得
//      `读[0..3] + 读[4..7]` 拼起来 **等于** `一次读[0..7]`。
//      如果不是这样，调用方算出来的偏移/切出来的行就是错的
//      —— 而那种错"看起来像文件内容本来就这样"，极难归因。
//
// ③ **句柄表存路径**：规则要按路径匹配，而 `NtReadFile` 只有 HANDLE。
//    路径在 open 时存进表，读的时候取出来。要验"存进去 == 取出来"，
//    以及"不传输出缓冲区的老调用方式仍然能用"（探针还在用它）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string>
#include <vector>

#include <r3shieldcore/r3shieldcore_shared.h>
#include <r3shieldcore/rules_codec.h>
#include "file_spoof_codec.h"

// guard_stub.cpp 提供的控制器（Policy 由桩持有，与生产路径同源）。
// ★ 没有 guard_stub.h —— 这个项目里各单测都是**就地声明**自己用到的那几个
//   （见 v132_privacy_action_ut.cpp 同款）。加一个头反而会多一份要同步的清单。
namespace GuardStub
{
	void ResetPolicy() noexcept;
	R3ShieldCore::Policy* PolicyPtr() noexcept;
}

namespace RScript = R3ShieldCoreRuleScript;

// screen_guard.cpp 在 -DSCREENGUARD_GUARD_UT 下导出的测试入口
namespace ScreenGuardTest
{
	int ScreenModeForTest(WCHAR* imageOut, int cap) noexcept;
	const WCHAR* ProcessExeNameForTest() noexcept;
}

static int g_pass = 0;
static int g_fail = 0;

static void Check(const wchar_t* what, bool ok)
{
	if (ok) { wprintf(L"  [PASS] %ls\n", what); ++g_pass; }
	else    { wprintf(L"  [FAIL] %ls\n", what); ++g_fail; }
}

int main()
{
	setlocale(LC_ALL, ".936");
	wprintf(L"=== v135 「文件 / 截屏」面接进引擎 · 行为单测（不注入、不跑引擎）===\n\n");

	GuardStub::ResetPolicy();
	RScript::Clear();

	// ================================================================
	// 1. 截屏面：ScreenMode 的四种结果
	// ================================================================
	wprintf(L"--- 1. 截屏面 ScreenMode ---\n");
	{
		WCHAR img[260] = {};
		Check(L"没配规则、ini 也没图 -> 黑帧", ScreenGuardTest::ScreenModeForTest(img, 260) == 0);
		Check(L"  黑帧时图片路径为空", img[0] == L'\0');

		const WCHAR* exe = ScreenGuardTest::ProcessExeNameForTest();
		Check(L"能拿到自己的 exe 名（规则靠它匹配）", exe && exe[0] != L'\0');
		wprintf(L"      当前 exe = %ls\n", exe ? exe : L"(空)");

		// 命中"替换为图"
		{
			std::wstring err;
			int idx = -1;
			std::wstring line = L"当 截屏 的 进程 含 \"";
			line += exe;
			line += L"\" 时 替换为图 \"C:\\fake\\desktop.bmp\"";
			Check(L"装入：命中本进程 -> 替换为图",
				RScript::Add(line.c_str(), err, &idx));

			WCHAR got[260] = {};
			const int mode = ScreenGuardTest::ScreenModeForTest(got, 260);
			Check(L"  结果 = 画图", mode == 1);
			Check(L"  路径原样传出来（不是悬垂指针）",
				wcscmp(got, L"C:\\fake\\desktop.bmp") == 0);
		}

		// ★★ 负对照：换一个**不命中**的进程名 -> 必须回落到黑帧，
		//    而不是"只要有截屏规则就一律画图"。
		RScript::Clear();
		{
			std::wstring err;
			int idx = -1;
			Check(L"装入：只匹配 no_such_process_zzz.exe",
				RScript::Add(L"当 截屏 的 进程 含 \"no_such_process_zzz.exe\" 时 替换为图 \"C:\\x.bmp\"",
					err, &idx));
			WCHAR got[260] = {};
			Check(L"负对照：进程不命中 -> 黑帧",
				ScreenGuardTest::ScreenModeForTest(got, 260) == 0);
		}

		// 命中"全零"（= 黑帧，但走的是规则）
		RScript::Clear();
		{
			std::wstring err;
			int idx = -1;
			std::wstring line = L"当 截屏 的 进程 含 \"";
			line += exe;
			line += L"\" 时 替换为 全零";
			RScript::Add(line.c_str(), err, &idx);
			WCHAR got[260] = {};
			Check(L"命中「替换为 全零」-> 黑帧",
				ScreenGuardTest::ScreenModeForTest(got, 260) == 0);
		}

		// 命中"放行"
		RScript::Clear();
		{
			std::wstring err;
			int idx = -1;
			std::wstring line = L"当 截屏 的 进程 含 \"";
			line += exe;
			line += L"\" 时 放行";
			RScript::Add(line.c_str(), err, &idx);
			WCHAR got[260] = {};
			Check(L"命中「放行」-> Pass（本次不替换）",
				ScreenGuardTest::ScreenModeForTest(got, 260) == 2);
		}

		// first-match wins：放行写在前面，就不能被后面的"替换为图"顶掉
		RScript::Clear();
		{
			std::wstring err;
			int idx = -1;
			std::wstring pass = L"当 截屏 的 进程 含 \"";
			pass += exe; pass += L"\" 时 放行";
			std::wstring imgRule = L"当 截屏 的 进程 含 \"";
			imgRule += exe; imgRule += L"\" 时 替换为图 \"C:\\y.bmp\"";
			RScript::Add(pass.c_str(), err, &idx);
			RScript::Add(imgRule.c_str(), err, &idx);
			WCHAR got[260] = {};
			Check(L"first-match wins：先加的「放行」生效",
				ScreenGuardTest::ScreenModeForTest(got, 260) == 2);
		}

		// ★ 叠加语义：规则一条都没命中时，回落到 ini 的全局图片（v134 行为）
		RScript::Clear();
		{
			R3ShieldCore::Policy* p = GuardStub::PolicyPtr();
			wcsncpy_s(p->SpoofScreenImagePath, L"C:\\ini\\global.bmp", _TRUNCATE);
			WCHAR got[260] = {};
			Check(L"无规则 + ini 有图 -> 画 ini 那张（叠加，不是替代）",
				ScreenGuardTest::ScreenModeForTest(got, 260) == 1
				&& wcscmp(got, L"C:\\ini\\global.bmp") == 0);

			// 有规则命中时**规则优先于 ini**
			std::wstring err;
			int idx = -1;
			std::wstring line = L"当 截屏 的 进程 含 \"";
			line += exe; line += L"\" 时 替换为图 \"C:\\rule\\wins.bmp\"";
			RScript::Add(line.c_str(), err, &idx);
			WCHAR got2[260] = {};
			Check(L"规则命中时规则优先（ini 只是回落）",
				ScreenGuardTest::ScreenModeForTest(got2, 260) == 1
				&& wcscmp(got2, L"C:\\rule\\wins.bmp") == 0);

			// ★★ 面隔离：文件面的规则不能影响截屏面的决定
			RScript::Clear();
			Check(L"装入一条**文件面**规则（不该影响截屏）",
				RScript::Add(L"当 文件 的 路径 含 \"secret\" 时 替换为 全零", err, &idx));
			WCHAR got3[260] = {};
			Check(L"★面隔离：文件规则不影响截屏 -> 仍是 ini 那张",
				ScreenGuardTest::ScreenModeForTest(got3, 260) == 1
				&& wcscmp(got3, L"C:\\ini\\global.bmp") == 0);

			p->SpoofScreenImagePath[0] = L'\0';
			GuardStub::ResetPolicy();
		}
	}

	// ================================================================
	// 2. 文件面：FillBuffer（全零 / 全FF）
	// ================================================================
	wprintf(L"\n--- 2. 文件面 FillBuffer ---\n");
	{
		BYTE buf[16];
		memset(buf, 0xAB, sizeof(buf));
		Check(L"全FF 填 8 字节", R3ShieldCoreFileSpoof::FillBuffer(buf, 8, 0xFF));
		bool all = true;
		for (int i = 0; i < 8; ++i) if (buf[i] != 0xFF) all = false;
		Check(L"  前 8 字节都是 0xFF", all);
		Check(L"  第 9 字节没被动（只填指定的字节数）", buf[8] == 0xAB);

		memset(buf, 0xAB, sizeof(buf));
		Check(L"全零 填 4 字节", R3ShieldCoreFileSpoof::FillBuffer(buf, 4, 0x00));
		Check(L"  4 字节都是 0", buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0);
		Check(L"  第 5 字节没被动", buf[4] == 0xAB);

		Check(L"bytes=0 -> false", !R3ShieldCoreFileSpoof::FillBuffer(buf, 0, 0xFF));
		Check(L"缓冲区为空 -> false", !R3ShieldCoreFileSpoof::FillBuffer(nullptr, 8, 0xFF));
	}

	// ================================================================
	// 3. ★★ 文件面：FillWithText 的**偏移自洽**（本单测最重要的一条）
	// ================================================================
	wprintf(L"\n--- 3. 文件面 FillWithText（分块读不能错位）---\n");
	{
		// 3.1 平铺：文本 "AB" 铺 6 字节 => ABABAB
		{
			BYTE buf[6] = {};
			Check(L"文本 \"AB\" 平铺 6 字节", R3ShieldCoreFileSpoof::FillWithText(buf, 6, 0, L"AB"));
			Check(L"  内容 = ABABAB",
				buf[0] == 'A' && buf[1] == 'B' && buf[2] == 'A'
				&& buf[3] == 'B' && buf[4] == 'A' && buf[5] == 'B');
		}

		// 3.2 带偏移：从第 1 字节开始 => BABA
		{
			BYTE buf[4] = {};
			R3ShieldCoreFileSpoof::FillWithText(buf, 4, 1, L"AB");
			Check(L"偏移 1 读 4 字节 = BABA",
				buf[0] == 'B' && buf[1] == 'A' && buf[2] == 'B' && buf[3] == 'A');
		}

		// 3.3 ★★★ 分块读拼接 == 一次读
		//
		//     这是"文件按偏移分块读"的核心正确性：调用方可能 4KB 一块地读，
		//     也可能一次读完。两种读法拿到的**字节流必须一模一样**，
		//     否则调用方算出来的偏移、切出来的行、解析出来的结构全是错的。
		{
			const WCHAR* text = L"假内容FAKE";
			BYTE whole[64] = {};
			R3ShieldCoreFileSpoof::FillWithText(whole, 64, 0, text);

			BYTE joined[64] = {};
			const ULONG chunk = 7;      // 故意不整除
			ULONG pos = 0;
			bool ok = true;
			while (pos < 64)
			{
				const ULONG n = (pos + chunk <= 64) ? chunk : (64 - pos);
				if (!R3ShieldCoreFileSpoof::FillWithText(joined + pos, n, (long long)pos, text))
				{
					ok = false;
					break;
				}
				pos += n;
			}
			Check(L"★分块读（7 字节一块）能拼回来", ok);
			Check(L"★拼接结果 == 一次读完（偏移完全自洽）",
				ok && memcmp(whole, joined, sizeof(whole)) == 0);
			// ★★ 光比"两边一样"不够：两边**都变成全零**时也会通过（空真判据）。
			//    必须再钉"确实有内容、而且内容就是假文本的平铺"。
			bool hasNonZero = false;
			for (int i = 0; i < 64; ++i) if (whole[i] != 0) hasNonZero = true;
			Check(L"★拼接结果不是全零（否则上一条是空真判据）", hasNonZero);
			Check(L"★首字节就是假文本首字节（UTF-8 的 '假' = 0xE5）",
				whole[0] == 0xE5 && whole[1] == 0x81 && whole[2] == 0x87);
		}

		// 3.4 空文本 => 全零（**不是** false —— false 会让调用方以为没替换成）
		{
			BYTE buf[8];
			memset(buf, 0xAB, sizeof(buf));
			const bool ret = R3ShieldCoreFileSpoof::FillWithText(buf, 8, 0, L"");
			bool allZero = true;
			for (int i = 0; i < 8; ++i) if (buf[i] != 0) allZero = false;
			Check(L"空文本返回 true（等价于替换为空）", ret);
			Check(L"  空文本填成全零", allZero);
		}

		// 3.5 中文按 UTF-8 落地（不是 UTF-16）
		{
			BYTE buf[16] = {};
			R3ShieldCoreFileSpoof::FillWithText(buf, 16, 0, L"假");
			// U+5047 的 UTF-8 是 E5 81 87（3 字节）
			Check(L"中文「假」按 UTF-8 = E5 81 87",
				buf[0] == 0xE5 && buf[1] == 0x81 && buf[2] == 0x87);
			Check(L"  第 4 字节回到平铺起点（3 字节一循环）", buf[3] == 0xE5);
		}

		// 3.6 边界
		{
			BYTE buf[4] = {};
			Check(L"bytes=0 -> false", !R3ShieldCoreFileSpoof::FillWithText(buf, 0, 0, L"A"));
			Check(L"缓冲区为空 -> false", !R3ShieldCoreFileSpoof::FillWithText(nullptr, 4, 0, L"A"));
		}
	}

	// ================================================================
	// 4. 句柄表：路径存得住、取得出（规则求值靠它）
	// ================================================================
	wprintf(L"\n--- 4. 句柄表存路径 ---\n");
	{
		R3ShieldCoreFileSpoof::HandleTable table = {};

		Check(L"Refresh(true, 路径) 成功", table.Refresh((HANDLE)0x1234, true, L"C:\\data\\secret.txt"));
		Check(L"  句柄被跟踪", table.IsTracked((HANDLE)0x1234));

		WCHAR got[260] = {};
		bool first = false;
		Check(L"Take 命中", table.Take((HANDLE)0x1234, &first, got, 260));
		Check(L"  第一次 Take 报告 firstTime=true", first);
		Check(L"  ★路径原样取回来", wcscmp(got, L"C:\\data\\secret.txt") == 0);

		table.Take((HANDLE)0x1234, &first);
		Check(L"  第二次 Take 报告 firstTime=false", !first);

		// 兼容老调用（探针只用两个参数）
		Check(L"不传输出缓冲区也能用（探针的老调用方式）",
			table.Take((HANDLE)0x1234, &first));

		// 不受保护 => 不记，且**旧路径不能残留**
		Check(L"Refresh(false) 成功", table.Refresh((HANDLE)0x1234, false, L"C:\\data\\secret.txt"));
		Check(L"  不再被跟踪", !table.IsTracked((HANDLE)0x1234));

		// 另一个句柄，验证"换文件后路径跟着换"
		table.Refresh((HANDLE)0x5678, true, L"C:\\a\\one.txt");
		table.Refresh((HANDLE)0x5678, true, L"C:\\b\\two.txt");
		WCHAR got2[260] = {};
		table.Take((HANDLE)0x5678, &first, got2, 260);
		Check(L"同一个句柄重新 Refresh 后路径更新为新文件",
			wcscmp(got2, L"C:\\b\\two.txt") == 0);

		// 超长路径：截断，不越界
		{
			std::wstring huge(400, L'x');
			Check(L"超长路径不会写越界", table.Refresh((HANDLE)0x9999, true, huge.c_str()));
			WCHAR got3[260] = {};
			table.Take((HANDLE)0x9999, &first, got3, 260);
			Check(L"  截断到 259 个字符", wcslen(got3) == 259);
		}

		// ★ 哨兵不能泄漏成"被跟踪的句柄"
		Check(L"哨兵 (HANDLE)1 不被当成真实句柄", !table.IsTracked((HANDLE)1));
		Check(L"跟踪计数正确（3 个：0x1234 已撤，剩 0x5678/0x9999）",
			table.TrackedCount() == 2);
	}

	RScript::Clear();
	GuardStub::ResetPolicy();

	wprintf(L"\n=== 结果：%d passed, %d failed ===\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
