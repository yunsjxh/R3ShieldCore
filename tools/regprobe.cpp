//
// R3ShieldCore 测试程序。
//
// 放在 C:\Windows 之外运行，才会被 R3ShieldCore 判定为「非系统程序」而纳入监控。
// 它按层级依次做注册表读写，每一步都回读验证，最后给出汇总。
//
// 关键：只返回码不够。ERROR_ACCESS_DENIED(5) 既可能是 R3ShieldCore 拦的，
// 也可能是本来就没权限。所以这里区分两件事：
//   1. 返回码
//   2. 操作后注册表里的实际状态（回读 / 重新查询键是否存在）
// 只有"返回 0 但实际没写进去"或者"本来该成功却返回 5"才是 R3ShieldCore 的痕迹。
//
// 用法: regprobe.exe           完整跑一遍（自动清理）
//       regprobe.exe keep      跑完不清理，方便用 regedit 肉眼看
//
#include <windows.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>

namespace
{
	constexpr PCWSTR UserKeyPath = L"Software\\R3ShieldCoreProbe";
	constexpr PCWSTR MachineKeyPath = L"SOFTWARE\\R3ShieldCoreProbe";
	constexpr PCWSTR ServiceKeyPath = L"SYSTEM\\CurrentControlSet\\Services\\R3ShieldCoreProbe";
	constexpr PCWSTR ValueName = L"Probe";
	constexpr WCHAR ValueData[] = L"hello";

	int g_index = 0;
	int g_denied = 0;
	int g_ok = 0;
	int g_other = 0;
	bool g_elevated = false;

	void Narrow(PCWSTR wide, char* buffer, int bufferBytes)
	{
		buffer[0] = '\0';
		if (wide) {
			WideCharToMultiByte(CP_ACP, 0, wide, -1, buffer, bufferBytes - 1, nullptr, nullptr);
			buffer[bufferBytes - 1] = '\0';
		}
	}

	bool IsProcessElevated()
	{
		HANDLE token = nullptr;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
			return false;
		}

		TOKEN_ELEVATION elevation = {};
		DWORD returned = 0;
		BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned);
		CloseHandle(token);

		return ok && elevation.TokenIsElevated != 0;
	}

	void Step(const char* operation, PCWSTR target, LSTATUS status, bool requiresAdmin)
	{
		g_index++;

		char narrowTarget[200];
		Narrow(target, narrowTarget, sizeof(narrowTarget));

		const char* note = "";
		if (status == ERROR_ACCESS_DENIED) {
			// 关键区分：没提权时 HKLM 本来就会 ACCESS_DENIED，
			// 把它算成"被 R3ShieldCore 拦了"会给出完全错误的结论。
			if (requiresAdmin && !g_elevated) {
				note = "  没提权，本来就会失败（不是 R3ShieldCore 拦的）";
				g_other++;
			}
			else {
				note = "  <== 被拦截 (ERROR_ACCESS_DENIED)";
				g_denied++;
			}
		}
		else if (status == ERROR_SUCCESS) {
			note = "  成功";
			g_ok++;
		}
		else {
			note = "";
			g_other++;
		}

		printf("[%2d] %-18s %-52s -> %-3ld%s\n", g_index, operation, narrowTarget, status, note);
	}

	// 回读验证：写入到底有没有真的落进注册表
	bool ValueExists(HKEY root, PCWSTR keyPath, PCWSTR valueName)
	{
		HKEY key = nullptr;
		if (RegOpenKeyExW(root, keyPath, 0, KEY_READ, &key) != ERROR_SUCCESS) {
			return false;
		}

		DWORD type = 0;
		WCHAR data[64] = {};
		DWORD bytes = sizeof(data);
		LSTATUS status = RegQueryValueExW(key, valueName, nullptr, &type,
			reinterpret_cast<BYTE*>(data), &bytes);
		RegCloseKey(key);

		return status == ERROR_SUCCESS;
	}

	void Note(const char* text)
	{
		printf("     %s\n", text);
	}

	void NoteValue(const char* label, bool exists)
	{
		printf("     %s: %s\n", label, exists ? "存在（写入确实生效了）" : "不存在（写入没有生效）");
	}

	void Cleanup(HKEY root, PCWSTR keyPath, PCWSTR valueName)
	{
		HKEY key = nullptr;
		if (RegOpenKeyExW(root, keyPath, 0, KEY_SET_VALUE | KEY_READ, &key) == ERROR_SUCCESS) {
			RegDeleteValueW(key, valueName);
			RegCloseKey(key);
		}
		RegDeleteKeyW(root, keyPath);
	}
}

int main(int argc, char** argv)
{
	setlocale(LC_ALL, "");
	setvbuf(stdout, nullptr, _IONBF, 0);

	bool keep = (argc > 1 && _stricmp(argv[1], "keep") == 0);

	g_elevated = IsProcessElevated();

	WCHAR imagePath[MAX_PATH] = {};
	DWORD size = _countof(imagePath);
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, imagePath, &size);

	char narrowImage[MAX_PATH * 2];
	Narrow(imagePath, narrowImage, sizeof(narrowImage));

	printf("================================================================\n");
	printf(" R3ShieldCore 测试程序\n");
	printf("================================================================\n");
	printf("PID        : %lu\n", GetCurrentProcessId());
	printf("镜像路径   : %s\n", narrowImage);
	printf("提权状态   : %s\n", g_elevated ? "是（HKLM 写入才有意义）" : "否（HKLM 写入本来就会失败，结果不可区分）");
	printf("\n");
	printf("提示：这个 exe 不在 C:\\Windows 下，所以会被 R3ShieldCore 当作\n");
	printf("      「非系统程序」纳入监控。把它复制到 C:\\Windows\\ 下再跑，\n");
	printf("      结果应该完全不同（系统程序不受监控）。\n");
	printf("================================================================\n\n");

	// ---- 第一层：HKCU，普通用户权限就能写 ----
	printf("--- 第一层: HKCU（用户级，普通权限即可）---\n");

	HKEY userKey = nullptr;
	DWORD disposition = 0;
	LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, UserKeyPath, 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &userKey, &disposition);
	Step("RegCreateKeyEx", L"HKCU\\Software\\R3ShieldCoreProbe", status, false);

	if (status == ERROR_SUCCESS) {
		status = RegSetValueExW(userKey, ValueName, 0, REG_SZ,
			reinterpret_cast<const BYTE*>(ValueData), sizeof(ValueData));
		Step("RegSetValueEx", L"HKCU\\...\\R3ShieldCoreProbe  value=Probe", status, false);

		NoteValue("  回读", ValueExists(HKEY_CURRENT_USER, UserKeyPath, ValueName));

		status = RegDeleteValueW(userKey, ValueName);
		Step("RegDeleteValue", L"HKCU\\...\\R3ShieldCoreProbe  value=Probe", status, false);

		RegCloseKey(userKey);
	}
	else {
		Note("  建键就被拒了，本层后续步骤跳过");
	}

	// ---- 第二层：HKLM\SOFTWARE，需要管理员 ----
	printf("\n--- 第二层: HKLM\\SOFTWARE（机器级，需要管理员）---\n");

	HKEY machineKey = nullptr;
	status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, MachineKeyPath, 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &machineKey, &disposition);
	Step("RegCreateKeyEx", L"HKLM\\SOFTWARE\\R3ShieldCoreProbe", status, true);

	if (status == ERROR_SUCCESS) {
		status = RegSetValueExW(machineKey, ValueName, 0, REG_SZ,
			reinterpret_cast<const BYTE*>(ValueData), sizeof(ValueData));
		Step("RegSetValueEx", L"HKLM\\...\\R3ShieldCoreProbe  value=Probe", status, true);

		NoteValue("  回读", ValueExists(HKEY_LOCAL_MACHINE, MachineKeyPath, ValueName));

		RegCloseKey(machineKey);
	}
	else {
		Note("  建键就被拒了");
	}

	// ---- 第三层：HKLM\SYSTEM\...\Services，最敏感的一层 ----
	printf("\n--- 第三层: HKLM\\SYSTEM\\...\\Services（服务项，最敏感）---\n");

	HKEY serviceKey = nullptr;
	status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, ServiceKeyPath, 0, nullptr,
		REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &serviceKey, &disposition);
	Step("RegCreateKeyEx", L"HKLM\\SYSTEM\\...\\Services\\R3ShieldCoreProbe", status, true);

	if (status == ERROR_SUCCESS) {
		status = RegSetValueExW(serviceKey, L"ImagePath", 0, REG_SZ,
			reinterpret_cast<const BYTE*>(ValueData), sizeof(ValueData));
		Step("RegSetValueEx", L"HKLM\\...\\Services\\R3ShieldCoreProbe  ImagePath", status, true);
		RegCloseKey(serviceKey);
	}

	// ---- 汇总 ----
	printf("\n================================================================\n");
	printf(" 汇总\n");
	printf("================================================================\n");
	printf("总共 %d 步：成功 %d，被拒 %d，其他 %d\n", g_index, g_ok, g_denied, g_other);
	printf("\n");

	if (g_denied > 0) {
		printf("有 %d 步被拒。\n", g_denied);
		printf("HKCU 那几层本来就该成功 —— 被拒就说明 R3ShieldCore 的拦截生效了。\n");
	}
	else {
		printf("没有任何一步被拒。可能的原因：\n");
		printf("  - R3ShieldCore 根本没在跑\n");
		printf("  - 当前是 LOG 模式（只记录不拦）\n");
		printf("  - ASK 模式，但弹窗被点了「允许」\n");
		printf("  - 这个 exe 被 r3shieldcore.ini 的白名单排除了\n");
	}

	if (!g_elevated) {
		printf("\n注意：本次没有提权，HKLM 那两层本来就写不进去，\n");
		printf("      所以它们的失败不能作为 R3ShieldCore 生效的证据。\n");
		printf("      想验证机器级的拦截，请用管理员身份运行本程序。\n");
	}

	printf("\n对照 R3ShieldCore 的事件日志（Release\\r3shieldcore-events.log），\n");
	printf("应该能看到上面每一步对应的记录。\n");

	// ---- 清理 ----
	if (keep) {
		printf("\n(--keep) 保留测试用的注册表项，可以用 regedit 查看：\n");
		printf("  HKCU\\Software\\R3ShieldCoreProbe\n");
		printf("  HKLM\\SOFTWARE\\R3ShieldCoreProbe\n");
		printf("  HKLM\\SYSTEM\\CurrentControlSet\\Services\\R3ShieldCoreProbe\n");
	}
	else {
		Cleanup(HKEY_CURRENT_USER, UserKeyPath, ValueName);
		Cleanup(HKEY_LOCAL_MACHINE, MachineKeyPath, ValueName);
		Cleanup(HKEY_LOCAL_MACHINE, ServiceKeyPath, L"ImagePath");
		printf("\n测试用的注册表项已清理。\n");
	}

	return 0;
}
