// apiprobe.cpp —— 探测"待挂的 API 变体"在当前系统上是否真的存在。
//
// 为什么要有这个探针：
//   API 变体扩展（截屏/输入/摄像头/进程旁路）依赖一批新符号。
//   这些符号有的在 Win10 才出现（GetDIBits 一直在，但 SetWinEventHook 的
//   out-of-context 变体、CreateProcessAsUserW 的导出模块各不相同），
//   有的在系统 DLL 里是**转发导出**（真实现在别处）。
//   靠文档猜会在实机上翻车 —— 挂不上去时 MinHook 只返回一个 MH_ERROR，
//   还得回头查是哪一步错。这里先把"模块是否存在 + 导出是否存在 +
//   解析到的真实地址落在哪个模块"一次性打出来。
//
// 输出每一行：
//   <模块>!<函数>  found=<0/1>  addr=<真实地址>  owner=<拥有该地址的模块>
//
// 用法：
//   apiprobe.exe

#include <windows.h>
#include <stdio.h>

namespace
{
    struct Target
    {
        const char* module;
        const char* function;
    };

    // 待扩展的 API 变体。分组与 guard 对应。
    const Target kTargets[] =
    {
        // ---- 截屏：GDI 的第三条路（GetDC(NULL) + GetDIBits）----
        { "user32.dll", "GetDC" },
        { "gdi32.dll",  "GetDIBits" },
        { "gdi32.dll",  "CreateCompatibleBitmap" },

        // ---- 截屏 / 桌面复制：DXGI（COM 虚函数，无导出可挂 —— 只探测模块）----
        { "dxgi.dll",   "CreateDXGIFactory1" },

        // ---- 输入：轮询式键盘记录 + 事件钩子 ----
        { "user32.dll", "GetAsyncKeyState" },
        { "user32.dll", "GetKeyState" },
        { "user32.dll", "GetKeyboardState" },
        { "user32.dll", "SetWinEventHook" },

        // ---- 进程旁路：CreateProcessAsUser 系 ----
        { "advapi32.dll", "CreateProcessAsUserW" },
        { "advapi32.dll", "CreateProcessWithTokenW" }, // 已挂，做对照
        { "kernel32.dll", "CreateProcessW" },

        // ---- 服务权限：改 DACL / 安全对象 ----
        { "advapi32.dll", "SetServiceObjectSecurity" },
        { "ntdll.dll",    "NtSetSecurityObject" },
        // v12 补强：SetServiceObjectSecurity 的底层旁路。直调这两条可绕过它。
        { "advapi32.dll", "SetSecurityInfo" },          // handle 版（SetServiceObjectSecurity 底层）
        { "advapi32.dll", "SetNamedSecurityInfoW" },    // 名字版（sc sdset 实际走这条）
        { "advapi32.dll", "SetEntriesInAclW" },         // 构造 ACE 的必经之路
        // v12：COM 激活三路（combase 起，ole32 退）
        { "combase.dll",  "CoCreateInstance" },
        { "combase.dll",  "CoCreateInstanceEx" },
        { "combase.dll",  "CoGetClassObject" },
        // v12：计划任务（纯 COM 接口，无导出可挂 —— 只探 CLSID 可创性由 taskprobe 负责）
        { "taskschd.dll", "DllGetClassObject" },

        // ---- v13：音频采集 / 环回 ----
        // 老式波形录音是 winmm 的导出，好挂。
        { "winmm.dll",   "waveInOpen" },
        { "winmm.dll",   "waveInPrepareHeader" },   // 做对照：真要取数据才会调
        { "winmm.dll",   "mciSendCommandW" },
        // WASAPI 是纯 COM（IAudioClient::Initialize 无导出）—— 只能 vtable patch。
        // 这里探两个模块是否存在，确认 vtable patch 有靶子。
        // ⚠️ 实测结论（本机 Win11）：
        //     audioses.dll 里**没有** AUDIOSESSIONCTRL_CreateObject 这样的导出
        //     （试过，found=NO）—— WASAPI 的入口在 mmdevapi（驱动侧）与
        //     combase 的激活路径上，所以只能 vtable patch，别指望找导出挂。
        { "mmdevapi.dll", "ActivateAudioInterfaceAsync" },   // WASAPI 激活入口（实测存在）
        // 设备枚举（MMDeviceEnumerator 也是 COM，探测模块）
        { "mmdevapi.dll", "DllGetClassObject" },

        // ---- v13：令牌窃取 ----
        { "advapi32.dll", "OpenProcessToken" },
        { "advapi32.dll", "OpenThreadToken" },
        { "advapi32.dll", "DuplicateTokenEx" },
        { "advapi32.dll", "ImpersonateLoggedOnUser" },
        { "advapi32.dll", "SetThreadToken" },
        { "advapi32.dll", "AdjustTokenPrivileges" },
        { "advapi32.dll", "CreateProcessAsUserW" },  // 已挂（spawn），做对照
        // 内核态旁路（只记录不挂，探测存在性）
        { "ntdll.dll",    "NtOpenProcessToken" },
        { "ntdll.dll",    "NtDuplicateToken" },

        // ---- v13：WMI 事件订阅 ----
        // WMI 是纯 COM（IWbemLocator::ConnectServer 无导出）—— 只能 vtable patch。
        { "wbemprox.dll", "DllGetClassObject" },
        { "fastprox.dll", "DllGetClassObject" },
        { "ole32.dll",    "CoCreateInstance" },      // 对照：看是不是转发到 combase
    };

    // 查这个地址真正属于哪个已加载模块。转发导出（如 kernel32!X → api-ms-*）
    // 会在这里现形。
    const char* OwningModule(void* address, char* buffer, size_t cch)
    {
        HMODULE owner = nullptr;
        if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(address), &owner)) {
            return "(无法确定)";
        }

        char path[MAX_PATH] = {};
        GetModuleFileNameA(owner, path, MAX_PATH);
        const char* slash = strrchr(path, '\\');
        const char* name = slash ? slash + 1 : path;
        strncpy_s(buffer, cch, name, _TRUNCATE);
        return buffer;
    }
}

int main(int argc, char** argv)
{
    // 默认就会主动 LoadLibrary。原因：这是一个控制台探针，user32/gdi32/dxgi
    // 这些模块在纯控制台进程里本来就没加载 —— 不加载的话满屏"模块未加载"，
    // 探测不出任何有用信息。而真实场景里（被注入的 GUI 进程）这些模块都是在的，
    // 所以这里主动加载反而更接近真实注入环境。
    //
    //   apiprobe.exe          主动加载每个模块再探测
    //   apiprobe.exe --noload 只看已加载模块（观察"进程启动时谁在场"）
    const bool loadModules = !(argc > 1 && strcmp(argv[1], "--noload") == 0);

    printf("R3ShieldCore API 变体探测  (pid=%u)%s\n", GetCurrentProcessId(),
        loadModules ? "" : "  [只看已加载]");
    printf("%-14s %-28s %-6s %-18s %s\n", "模块", "函数", "found", "解析地址", "实际拥有者");
    printf("--------------------------------------------------------------------------------\n");

    int found = 0;
    int missing = 0;

    for (const Target& target : kTargets) {
        HMODULE module = GetModuleHandleA(target.module);

        if (!module && loadModules) {
            module = LoadLibraryA(target.module);
        }

        if (!module) {
            printf("%-14s %-28s %-6s %-18s %s\n", target.module, target.function,
                "-", "-", "(模块未加载/加载失败)");
            ++missing;
            continue;
        }

        void* address = reinterpret_cast<void*>(GetProcAddress(module, target.function));
        if (!address) {
            printf("%-14s %-28s %-6s %-18s %s\n", target.module, target.function,
                "NO", "-", "(导出不存在)");
            ++missing;
            continue;
        }

        char owner[64] = {};
        const char* ownerName = OwningModule(address, owner, sizeof(owner));
        printf("%-14s %-28s %-6s %-18p %s\n", target.module, target.function,
            "yes", address, ownerName);
        ++found;
    }

    printf("--------------------------------------------------------------------------------\n");
    printf("合计: found=%d  missing/未加载=%d\n", found, missing);
    printf("done\n");
    return 0;
}
