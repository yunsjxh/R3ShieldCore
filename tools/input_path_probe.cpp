// 最小探针：实测 RegisterRawInputDevices / SetWindowsHookEx 在本机当前状态下
// 是否被拒 —— 用来判断「输入框打不进字」是不是注入层的 block_all 干的。
//
// ★ 第一版写错了：`lpfn=nullptr` 时系统直接返回 ERROR_INVALID_PARAMETER(87) /
//   ERROR_GLOBAL_ONLY_HOOK(1427)，看起来像"被拒绝"，其实**根本没走到引擎的 hook**。
//   这是典型的假阳性 —— 所以必须给真回调，让调用真正进入 SetWindowsHookEx 内部。
//
// 只读、不改系统状态、不注入、不弹窗。
#include <cstdio>
#include <windows.h>

static LRESULT CALLBACK DummyKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

int main()
{
    printf("=== input path probe ===\n\n");

    // 1) RegisterRawInputDevices —— 现代输入框 / 浏览器 / Electron 走这条。
    //    ★ usUsagePage=0x01 usUsage=0x06 = Generic Desktop / Keyboard。
    //    RIDEV_INPUTSINK 要求 hwndTarget 非空，否则 87。
    //    ⇒ 建一个**消息窗口**作 target，让参数真正合法。
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"R3ScInputProbeWnd";
    RegisterClassExW(&wc);
    HWND hw = CreateWindowExW(0, wc.lpszClassName, L"probe", 0, 0, 0, 0, 0,
        HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
    printf("[setup] message hwnd=%p\n", (void*)hw);

    RAWINPUTDEVICE rid = {};
    rid.usUsagePage = 0x01;
    rid.usUsage = 0x06;
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = hw;

    SetLastError(0);
    const BOOL raw = RegisterRawInputDevices(&rid, 1, sizeof(rid));
    const DWORD rawErr = GetLastError();
    printf("[RegisterRawInputDevices] ret=%d err=%lu %s\n",
        raw ? 1 : 0, (unsigned long)rawErr, raw ? "(OK)" : "(REJECTED)");

    // 2) SetWindowsHookEx(WH_KEYBOARD_LL) —— 全局低级键盘钩子（真回调）
    SetLastError(0);
    HHOOK hk = SetWindowsHookExW(WH_KEYBOARD_LL, DummyKeyboardProc,
        GetModuleHandleW(nullptr), 0);
    const DWORD hookErr = GetLastError();
    printf("[SetWindowsHookEx WH_KEYBOARD_LL] hhook=%p err=%lu %s\n",
        (void*)hk, (unsigned long)hookErr, hk ? "(OK)" : "(REJECTED)");
    if (hk) { UnhookWindowsHookEx(hk); }

    // 3) SetWindowsHookEx(WH_KEYBOARD) 线程内 —— 输入法 / TSF 常用（真回调）
    SetLastError(0);
    HHOOK hk2 = SetWindowsHookExW(WH_KEYBOARD, DummyKeyboardProc,
        GetModuleHandleW(nullptr), GetCurrentThreadId());
    const DWORD hook2Err = GetLastError();
    printf("[SetWindowsHookEx WH_KEYBOARD tid] hhook=%p err=%lu %s\n",
        (void*)hk2, (unsigned long)hook2Err, hk2 ? "(OK)" : "(REJECTED)");
    if (hk2) { UnhookWindowsHookEx(hk2); }

    // 4) 写临时文件 —— block_all 下写类操作也会被拒，作为对照
    WCHAR tmp[MAX_PATH] = {};
    GetTempPathW(_countof(tmp), tmp);
    wcscat_s(tmp, L"r3sc_input_probe.tmp");
    SetLastError(0);
    HANDLE f = CreateFileW(tmp, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    const DWORD fileErr = GetLastError();
    printf("[CreateFileW write] handle=%p err=%lu %s\n",
        (void*)f, (unsigned long)fileErr,
        (f != INVALID_HANDLE_VALUE) ? "(OK)" : "(REJECTED)");
    if (f != INVALID_HANDLE_VALUE) { CloseHandle(f); DeleteFileW(tmp); }

    if (hw) { DestroyWindow(hw); }
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    printf("\n=== verdict ===\n");
    printf("all three input paths REJECTED + write REJECTED => block_all is eating input\n");
    return 0;
}
