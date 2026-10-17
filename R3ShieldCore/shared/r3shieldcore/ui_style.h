#pragma once
//
// ui_style.h —— 界面风格的**唯一契约**（两个 exe 共用，铁律 127）
//
// 为什么单独一个头：
//   主程序和配置工具都要读"用户选的是哪套界面"，各写一份的后果是
//   两边各解析一遍文件、各写一遍默认值 —— 然后某一版开始不一致，
//   而且**不报错**（一边变成玻璃、一边还是经典，看起来像"没生效"）。
//
// 两套风格：
//   · Glass   = 液态玻璃（OpenGL 着色器；GL 不可用时自动退到 CPU 合成）
//   · Classic = v82 那套完全不透明的平面界面
//
// 取值优先级：
//   ① 环境变量 `R3SHIELDCORE_UI=glass|classic`（自动化 / 现场排错）
//   ② `%ProgramData%\R3 Shield Core\r3shieldcore-ui.ini` 的 `[ui] style`
//   ③ 默认 Glass
//
#include <windows.h>
#include <string>

namespace R3ShieldCoreUi {

// ★ 代次标记（v84）：闸门查"这套风格契约真编进了 exe"
inline constexpr wchar_t kStyleMarker[] = L"R3ShieldCoreUiStyle.v84";

enum class Style {
    Glass = 0,
    Classic = 1,
};

inline const wchar_t* StyleName(Style style)
{
    return style == Style::Glass ? L"液态玻璃" : L"经典";
}

inline std::wstring SettingsPath()
{
    wchar_t base[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"ProgramData", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return std::wstring();
    }
    std::wstring dir = base;
    dir += L"\\R3 Shield Core";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\r3shieldcore-ui.ini";
}

inline Style LoadStyle()
{
    // ① 环境变量优先
    wchar_t env[24] = {};
    const DWORD n = GetEnvironmentVariableW(L"R3SHIELDCORE_UI", env, 24);
    if (n > 0 && n < 24 && env[0]) {
        if (_wcsicmp(env, L"classic") == 0) {
            return Style::Classic;
        }
        if (_wcsicmp(env, L"glass") == 0) {
            return Style::Glass;
        }
    }
    // ② 用户上次选的
    const std::wstring path = SettingsPath();
    if (!path.empty()) {
        wchar_t buf[24] = {};
        GetPrivateProfileStringW(L"ui", L"style", L"glass", buf, 24, path.c_str());
        if (_wcsicmp(buf, L"classic") == 0) {
            return Style::Classic;
        }
    }
    return Style::Glass;
}

inline void SaveStyle(Style style)
{
    const std::wstring path = SettingsPath();
    if (path.empty()) {
        return;
    }
    WritePrivateProfileStringW(L"ui", L"style",
        style == Style::Glass ? L"glass" : L"classic", path.c_str());
}

// 托盘菜单里那一项的文案：写**目标**而不是当前状态（"界面：经典" = 点我切到经典）
inline std::wstring ToggleLabel(Style current)
{
    std::wstring s = L"界面：";
    s += (current == Style::Glass) ? L"经典" : L"液态玻璃";
    return s;
}

} // namespace R3ShieldCoreUi
