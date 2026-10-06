// modof.cpp — 给定若干绝对地址，打印它们各自属于哪个已加载模块。
// 用法：modof.exe 0x7fff... 0x7fff...
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "psapi.lib")

int main(int argc, char** argv)
{
    DWORD needed = 0;
    HMODULE mods[512] = {};
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        printf("EnumProcessModules failed err=%lu\n", GetLastError());
        return 1;
    }
    const DWORD count = needed / sizeof(HMODULE);

    for (int i = 1; i < argc; i++) {
        ULONGLONG addr = _strtoui64(argv[i], nullptr, 16);
        const char* owner = "<not in any module>";
        ULONGLONG base = 0, end = 0;
        char name[MAX_PATH] = {};
        for (DWORD m = 0; m < count; m++) {
            MODULEINFO mi = {};
            if (!GetModuleInformation(GetCurrentProcess(), mods[m], &mi, sizeof(mi))) continue;
            ULONGLONG b = (ULONGLONG)mi.lpBaseOfDll;
            ULONGLONG e = b + mi.SizeOfImage;
            if (addr >= b && addr < e) {
                owner = "yes";
                base = b; end = e;
                GetModuleBaseNameA(GetCurrentProcess(), mods[m], name, MAX_PATH);
                break;
            }
        }
        if (owner[0] == 'y') {
            printf("%s  ->  %s  [base=%08llX end=%08llX off=%llX]\n",
                argv[i], name, base, end, addr - base);
        } else {
            printf("%s  ->  %s\n", argv[i], owner);
        }
    }
    return 0;
}
