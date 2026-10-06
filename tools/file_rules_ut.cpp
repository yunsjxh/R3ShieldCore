//
// file_rules_ut.cpp - R3ShieldCoreRules::IsHighRiskFile 单元测试。
//
// 直接链 r3shieldcore_rules.cpp 的目标文件，验证文件高危规则判定。
// 重点覆盖"改时间戳（SetBasicInfo）"的差异化行为：
//   - hosts 的 SetBasicInfo  → 不高危（系统/浏览器高频正常行为）
//   - hosts 的 Write/Delete  → 仍然高危
//   - 其他敏感路径的 SetBasicInfo → 仍然高危
//
// v39 追加：裸盘 / 物理盘（写 MBR / 引导区 = bootkit）。
//   真实绕过：样本只用 CreateFileA("\\.\PhysicalDrive0", GENERIC_ALL)
//   + WriteFile 就改掉了引导区。这一组用例盯两件事：
//     ① 各种裸盘写法都要判高危（含 op=Open —— 它不在高危 op 表里）；
//     ② **正常卷路径绝不能误伤**（\Device\HarddiskVolumeN 长得像裸盘）。
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>

namespace R3ShieldCoreRules
{
	bool IsHighRiskFile(const wchar_t* path, unsigned long fileOp) noexcept;
	const char* FileRiskReason(const wchar_t* path, unsigned long fileOp) noexcept;
	bool IsRawDiskDevicePath(const wchar_t* path) noexcept;
}

// FileOp 枚举值（对齐 r3shieldcore_shared.h）
enum
{
	F_Create = 1,
	F_Open = 2,
	F_Write = 3,
	F_Delete = 4,
	F_Rename = 5,
	F_SetBasicInfo = 6,
	F_SetSecurity = 7,
	F_SetEa = 8,
	F_Truncate = 9,
};

struct Case
{
	const wchar_t* path;
	unsigned long op;
	bool expectHigh;
	const char* note;
};

int wmain()
{
	setlocale(LC_ALL, "");

	const Case cases[] = {
		// ---- hosts：写内容仍高危 ----
		{ L"C:\\Windows\\System32\\drivers\\etc\\hosts", F_Write,       true,  "hosts 写内容（高危）" },
		{ L"C:\\Windows\\System32\\drivers\\etc\\hosts", F_Delete,      true,  "hosts 删除（高危）" },
		{ L"C:\\Windows\\System32\\drivers\\etc\\hosts", F_Create,      true,  "hosts 创建/覆盖（高危）" },
		// ---- hosts：改时间戳不高危（本轮修复）----
		{ L"C:\\Windows\\System32\\drivers\\etc\\hosts", F_SetBasicInfo, false, "hosts 改时间戳（应不高危）" },
		// ---- System32 其他文件：改时间戳仍高危 ----
		{ L"C:\\Windows\\System32\\kernel32.dll",       F_SetBasicInfo, true,  "System32 DLL 改时间戳（高危）" },
		{ L"C:\\Windows\\System32\\drivers\\etc\\hosts", F_SetSecurity, true,  "hosts 改 ACL（高危）" },
		// ---- 启动目录 ----
		{ L"C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.exe",
		  F_Create, true, "启动目录建文件（高危）" },
		{ L"C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.exe",
		  F_SetBasicInfo, true, "启动目录改时间戳（高危）" },
		// ---- 计划任务 / 引导 ----
		{ L"C:\\Windows\\System32\\Tasks\\Evil",        F_Create,      true,  "计划任务（高危）" },
		{ L"C:\\EFI\\Microsoft\\Boot\\bootmgfw.efi",   F_Write,       true,  "EFI 引导（高危）" },
		// ---- Open 永不高危 ----
		{ L"C:\\Windows\\System32\\drivers\\etc\\hosts", F_Open,        false, "hosts 纯打开（不高危）" },
		// ---- 普通路径（对照）----
		{ L"D:\\MyData\\a.txt",                          F_Write,       false, "普通数据文件写（不高危）" },
		{ L"D:\\MyData\\a.txt",                          F_SetBasicInfo,false, "普通数据文件改时间戳（不高危）" },

		// ---- v39：裸盘 / 物理盘（写引导区 = bootkit）----
		// 归一化前的形态（Win32 \\.\PhysicalDrive0 → \??\PhysicalDrive0）
		{ L"\\??\\PhysicalDrive0",                       F_Create,      true,  "\\??\\PhysicalDrive0 建/覆盖（高危）" },
		// 归一化后的形态（NormalizeDosPrefix 剥掉 \??\ 之后）
		{ L"PhysicalDrive0",                             F_Create,      true,  "PhysicalDrive0 建/覆盖（高危）" },
		{ L"PhysicalDrive0",                             F_Open,        true,  "PhysicalDrive0 op=Open 也高危（v39 提前判）" },
		{ L"PhysicalDrive3",                             F_Write,       true,  "PhysicalDrive3（高危）" },
		// 对象管理器解析后的真名
		{ L"\\Device\\Harddisk0\\DR0",                   F_Write,       true,  "\\Device\\Harddisk0\\DR0（高危）" },
		{ L"\\Device\\Harddisk2\\Partition0",            F_Write,       true,  "整盘分区设备 Partition0（高危）" },
		// ---- 反例：正常卷路径**绝不能**误伤 ----
		{ L"\\Device\\HarddiskVolume3\\Users\\u\\a.txt",  F_Write,       false, "正常卷路径不误判（不高危）" },
		{ L"\\Device\\HarddiskVolumeShadowCopy1\\a.txt",  F_Write,       false, "卷影副本不误判（不高危）" },
		{ L"C:\\Users\\u\\a.txt",                        F_Write,       false, "普通盘符路径（不高危）" },
	};

	int failed = 0;
	for (const Case& c : cases) {
		const char* reason = R3ShieldCoreRules::FileRiskReason(c.path, c.op);
		bool got = (reason != nullptr);
		const char* mark = (got == c.expectHigh) ? "OK  " : "FAIL";
		if (got != c.expectHigh) failed++;
		printf("%s  op=%-2lu expect=%-5s got=%-5s  %-36s  reason=%s\n",
			mark, c.op, c.expectHigh ? "HIGH" : "norm",
			got ? "HIGH" : "norm", c.note, reason ? reason : "(null)");
	}

	//
	// v39：`IsRawDiskDevicePath` 直接单测（判据本身，与 op 无关）。
	//
	// ⚠️ 这一组里**最关键的**是两条反例：`\Device\HarddiskVolumeN` 与裸盘
	//    `\Device\HarddiskN\DRN` 前缀几乎一样，只差 `Harddisk` 后面是
	//    `V` 还是数字。判错了就会把**所有文件操作**都当裸盘拦 ⇒ 整机报废。
	//
	printf("\n-- IsRawDiskDevicePath 直接判定 --\n");

	struct RawCase
	{
		const wchar_t* path;
		bool expect;
		const char* note;
	};

	const RawCase rawCases[] = {
		{ L"PhysicalDrive0",                true,  "归一化后（\\??\\ 已剥掉）" },
		{ L"physicaldrive12",               true,  "大小写不敏感" },
		{ L"\\??\\PhysicalDrive0",          true,  "\\??\\ 前缀" },
		{ L"\\DosDevices\\PhysicalDrive1",  true,  "\\DosDevices\\ 前缀" },
		{ L"\\Device\\Harddisk0\\DR0",      true,  "物理盘真名" },
		{ L"\\Device\\Harddisk10\\DR25",    true,  "多位数盘号/分区号" },
		{ L"\\Device\\Harddisk0\\Partition0", true, "整盘分区设备" },
		{ L"\\Device\\Harddisk0\\Partition2", true, "分区设备" },
		{ L"\\Device\\HarddiskVolume3\\Windows", false, "★ 正常卷（绝不能误伤）" },
		{ L"\\Device\\HarddiskVolumeShadowCopy1\\x", false, "★ 卷影副本" },
		{ L"\\Device\\Harddisk\\DR0",       false, "缺盘号" },
		{ L"PhysicalDriveX",                false, "后缀非数字" },
		{ L"PhysicalDrive",                 false, "无盘号" },
		{ L"\\Device\\Afd",                 false, "套接字设备" },
		{ L"C:\\Windows\\System32\\x.dll",  false, "盘符路径" },
		{ L"",                              false, "空串" },
	};

	for (const RawCase& r : rawCases) {
		const bool got = R3ShieldCoreRules::IsRawDiskDevicePath(r.path);
		const char* mark = (got == r.expect) ? "OK  " : "FAIL";
		if (got != r.expect) failed++;
		printf("%s  expect=%-5s got=%-5s  %-28s  %ls\n",
			mark, r.expect ? "raw" : "norm", got ? "raw" : "norm", r.note, r.path);
	}

	const int total = static_cast<int>(sizeof(cases) / sizeof(cases[0])) +
		static_cast<int>(sizeof(rawCases) / sizeof(rawCases[0]));

	printf("\n%s  失败 %d / %d\n", failed == 0 ? "全部通过" : "存在失败", failed, total);
	return failed;
}
