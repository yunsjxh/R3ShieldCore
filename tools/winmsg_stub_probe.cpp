// winmsg_stub_probe.cpp
//
// 目的：实证 user32.dll 的窗口管理导出到底是不是“薄壳跳 win32u.dll”。
//
// 这决定 R3ShieldCore 要挂窗口操作时“该挂谁”：
//   · 若 user32!Xxx 只是 `jmp win32u!NtUserXxx`，那么挂 user32 导出
//     能拦住“按 Win32 API 调用”的应用（绝大多数），但拦不住直接
//     从 win32u 导入 / 直 syscall 的调用方。
//   · 若 user32!Xxx 是真实实现，挂它就够了。
//
// 只读不写：解析目标模块的首字节，识别 E9(rel32 jmp) / FF 25(间接 jmp)
// / 其它。不依赖任何文档，只看本机实际二进制。

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

struct StubInfo
{
    const char* user32Name;    // user32 里的名字
    const char* win32uName;    // win32u 里的对应名字（可能没有）
    void*       user32Addr;
    void*       win32uAddr;
    uint8_t     bytes[16];
    int         kind;          // 0=未知 1=E9 jmp rel32 2=FF25 间接 3=其它
    void*       jmpTarget;     // E9 时解析出的绝对目标
    bool        targetIsWin32u;// jmpTarget 是否落在 win32u 的 NtUser 里
};

static void DecodeStub(StubInfo& s, HMODULE hWin32u)
{
    memcpy(s.bytes, s.user32Addr, sizeof(s.bytes));

    uint8_t* addr = static_cast<uint8_t*>(s.user32Addr);
    int rex = 0;

    // 跳过常见 REX.W 前缀（48）。
    if (s.bytes[0] == 0x48) rex = 1;

    // FF 25 (+REX) = jmp qword ptr [rip+disp32] —— 通常直接跳 win32u 实现。
    if (s.bytes[rex] == 0xFF && s.bytes[rex + 1] == 0x25)
    {
        int32_t disp = 0;
        memcpy(&disp, s.bytes + rex + 2, sizeof(disp));
        uint8_t* slot = addr + rex + 6 + disp;
        void* target = nullptr;
        memcpy(&target, slot, sizeof(target));
        s.jmpTarget = target;
        s.kind = 2;
    }
    else
    {
        // 扫描前 8 字节里的 E9（jmp rel32）——有些壳是
        // `xor r9d,r9d; jmp ...` 之类，前面有少量真实指令。
        for (int i = 0; i <= 6; i++)
        {
            if (s.bytes[i] == 0xE9)
            {
                int32_t rel = 0;
                memcpy(&rel, s.bytes + i + 1, sizeof(rel));
                s.jmpTarget = addr + i + 5 + rel;
                s.kind = 1;
                break;
            }
        }
        if (s.kind == 0) s.kind = 3;
    }

    if (s.jmpTarget && hWin32u)
    {
        uint8_t* p = static_cast<uint8_t*>(s.jmpTarget);
        uint8_t* base = reinterpret_cast<uint8_t*>(hWin32u);
        s.targetIsWin32u = (p >= base && p < base + 0x1000000);
    }
}

int main()
{
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    HMODULE hWin32u = LoadLibraryW(L"win32u.dll");
    if (!hUser32 || !hWin32u)
    {
        printf("LoadLibrary failed: user32=%p win32u=%p err=%lu\n",
            (void*)hUser32, (void*)hWin32u, GetLastError());
        return 1;
    }

    printf("user32 base = %p\n", (void*)hUser32);
    printf("win32u base = %p\n\n", (void*)hWin32u);

    const char* pairs[][2] = {
        { "SetWindowPos",           "NtUserSetWindowPos" },
        { "ShowWindow",             "NtUserShowWindow" },
        { "CreateWindowExW",        "NtUserCreateWindowEx" },
        { "DestroyWindow",          "NtUserDestroyWindow" },
        { "MoveWindow",             "NtUserMoveWindow" },
        { "SetForegroundWindow",    "NtUserSetForegroundWindow" },
        { "SetWindowLongPtrW",      "NtUserSetWindowLongPtr" },
        { "SendMessageW",           "NtUserMessageCall" },
        { "PostMessageW",           "NtUserMessageCall" },
        { "SetWindowTextW",         "NtUserSetWindowText" },
        { "EnableWindow",           "NtUserEnableWindow" },
        { "SetWindowsHookExW",      nullptr },
    };

    printf("%-20s %-18s %-10s %-18s %s\n",
        "user32", "bytes", "kind", "jmpTarget", "inWin32u?");
    printf("---------------------------------------------------------------------------------\n");

    int stubs = 0, direct = 0, indirect = 0, other = 0, toWin32u = 0;

    for (auto& p : pairs)
    {
        StubInfo s = {};
        s.user32Name = p[0];
        s.win32uName = p[1];
        s.user32Addr = (void*)GetProcAddress(hUser32, p[0]);
        s.win32uAddr = p[1] ? (void*)GetProcAddress(hWin32u, p[1]) : nullptr;

        if (!s.user32Addr)
        {
            printf("%-20s <not exported>\n", p[0]);
            continue;
        }

        DecodeStub(s, hWin32u);

        char bytesStr[64] = {};
        for (int i = 0; i < 6; i++)
            sprintf_s(bytesStr + i * 3, sizeof(bytesStr) - i * 3, "%02X ", s.bytes[i]);

        const char* kindStr = s.kind == 1 ? "E9 jmp" : s.kind == 2 ? "FF25" : "other";
        if (s.kind == 1) stubs++;
        else if (s.kind == 2) indirect++;
        else other++;
        if (s.targetIsWin32u) toWin32u++;

        printf("%-20s %-18s %-10s %-18p %s\n",
            p[0], bytesStr, kindStr, s.jmpTarget,
            s.targetIsWin32u ? "YES" : (s.jmpTarget ? "no" : "-"));

        if (s.jmpTarget && s.win32uAddr)
        {
            printf("    -> win32u!%s = %p  %s\n", s.win32uName, s.win32uAddr,
                s.jmpTarget == s.win32uAddr ? "[EXACT MATCH]" : "");
        }
        (void)direct;
    }

    printf("\nSUMMARY: E9stub=%d FF25=%d other=%d, jmpIntoWin32u=%d\n",
        stubs, indirect, other, toWin32u);
    return 0;
}
