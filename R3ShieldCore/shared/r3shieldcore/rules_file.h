#pragma once
//
// rules_file.h —— 「规则脚本文件」放在哪：**唯一一份**路径解析（铁律 195）。
//
// ★ 为什么必须共享，不能各写一份
//   规则文件有**两个**使用者，而且必须指向**同一个文件**：
//     · `R3ShieldCore/r3shieldcore_gui.cpp`      —— 主程序「高级」页签（**写**）
//     · `R3ShieldCoreLib/registry_guard.cpp` 等  —— 引擎（被注入进程，**读**）
//   抄两份必然漂（铁律 127）：漂了之后界面里存得好好的规则，
//   引擎读的是另一个路径 ⇒ **界面显示"已保存"，引擎一条都不生效**，
//   而且两边都不会报错。这是本文件存在的全部理由。
//
// ★ 位置与 `r3shieldcore.ini` **同目录**（`R3ShieldCoreConfig::ResolveConfigPath`
//   用的是同一套口径）—— 用户改配置时两样东西在一起，不会找不到。
//
//   解析顺序：
//     ① `%ProgramData%\R3 Shield Core\` 这个**目录存在** ⇒ 用它
//     ② 否则 ⇒ 调用方**自己所在模块**的目录
//
// ★ 为什么判"目录存在"而不是"文件存在"（与 ini 那条**故意不同**）
//   ini 是随包发出去的，**必然存在** ⇒ 判"文件在不在"能区分"装过"与"没装"。
//   规则文件**可能还不存在**（用户第一次存规则）⇒ 若判文件存在，
//   首次保存就会被判去 exe 目录，之后 ProgramData 目录一建好，
//   路径又**跳到 ProgramData** —— 用户存的规则"自己搬家了"（最难查的一类）。
//   判目录则**一旦安装完成就稳定**（安装程序会建那个目录，见 installer/）。
//
// ★ 模块目录取法：`GetModuleHandleExW(FROM_ADDRESS)` 拿"本函数所在模块"。
//   本函数是 header-only 的 `static` ⇒ 每个 TU 一份 ⇒ 在 GUI 里它是 exe、
//   在 guard 里它是 `r3shieldcore-lib.dll`，而这两者**安装后同目录**。
//   所以 ProgramData 不可用时，两侧仍然落在同一个地方（绿色包场景）。
//
#ifndef _WINDOWS_
#include <windows.h>
#endif
#include <string.h>

namespace R3ShieldCoreRulesFile
{
	// 文件名（不含目录）。改这里即改两侧 —— 没有第二处。
	constexpr const WCHAR* kFileName = L"r3shieldcore-rules.txt";

	// `%ProgramData%\R3 Shield Core\`（不带尾反斜杠）。取不到环境变量返回 false。
	inline bool ProgramDataDir(WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch < 2) return false;
		WCHAR buf[MAX_PATH] = {};
		const DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, _countof(buf));
		if (n == 0 || n >= _countof(buf)) return false;

		// 拼上 "\R3 Shield Core"
		const WCHAR* suffix = L"\\R3 Shield Core";
		const size_t len = wcslen(buf);
		if (len + wcslen(suffix) + 1 > cch) return false;
		memcpy(out, buf, len * sizeof(WCHAR));
		memcpy(out + len, suffix, (wcslen(suffix) + 1) * sizeof(WCHAR));
		return true;
	}

	// 模块（exe / dll）所在目录。selfModule == nullptr ⇒ 用**调用方**所在模块。
	inline bool ModuleDir(HMODULE selfModule, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch < 2) return false;

		HMODULE mod = selfModule;
		if (!mod) {
			// ★ 传"本文件里一个函数的地址" ⇒ 拿到的是**调用方**模块。
			//   `&ModuleDir` 在 inline 之后可能落在调用方 TU 里 —— 这正是我们要的。
			mod = nullptr;
			GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
					| GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCWSTR>(&ModuleDir), &mod);
			if (!mod) return false;
		}

		WCHAR buf[MAX_PATH] = {};
		const DWORD n = GetModuleFileNameW(mod, buf, _countof(buf));
		if (n == 0 || n >= _countof(buf)) return false;

		// 砍掉文件名部分。
		WCHAR* slash = wcsrchr(buf, L'\\');
		if (!slash) return false;
		*slash = L'\0';
		if (wcslen(buf) + 1 > cch) return false;
		wcscpy_s(out, cch, buf);
		return true;
	}

	// 解析规则文件的完整路径。**成功即返回 true**（不要求文件已存在 ——
	// 调用方可能是要**新建**它）。
	//
	// selfModule：显式指定模块；传 nullptr 表示"调用方所在模块"（推荐）。
	inline bool ResolveRulesPath(HMODULE selfModule, WCHAR* out, size_t cch) noexcept
	{
		if (!out || cch < 2) return false;

		WCHAR pd[MAX_PATH] = {};
		if (ProgramDataDir(pd, _countof(pd))) {
			const DWORD attr = GetFileAttributesW(pd);
			// 目录存在 ⇒ 用它（安装版走这条）。
			if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
				const size_t need = wcslen(pd) + 1 + wcslen(kFileName) + 1;
				if (need <= cch) {
					swprintf_s(out, cch, L"%s\\%s", pd, kFileName);
					return true;
				}
			}
		}

		// 回退：调用方模块目录（绿色包 / ProgramData 目录还没建）。
		WCHAR dir[MAX_PATH] = {};
		if (!ModuleDir(selfModule, dir, _countof(dir))) return false;
		const size_t need = wcslen(dir) + 1 + wcslen(kFileName) + 1;
		if (need > cch) return false;
		swprintf_s(out, cch, L"%s\\%s", dir, kFileName);
		return true;
	}

	// 为写文件做准备：确保**父目录**存在（ProgramData 下那个目录若被删过，
	// 保存会失败 —— 建回来，而不是静默失败）。已存在 ⇒ 直接 true。
	inline bool EnsureParentDirectory(const WCHAR* path) noexcept
	{
		if (!path || !*path) return false;
		WCHAR dir[MAX_PATH] = {};
		if (wcslen(path) + 1 > _countof(dir)) return false;
		wcscpy_s(dir, path);

		WCHAR* slash = wcsrchr(dir, L'\\');
		if (!slash || slash == dir) return false;
		*slash = L'\0';

		const DWORD attr = GetFileAttributesW(dir);
		if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
			return true;
		}
		return CreateDirectoryW(dir, nullptr) != FALSE;
	}
}
