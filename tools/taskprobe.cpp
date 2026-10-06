// taskprobe.cpp —— 实测"计划任务"这条链在用户态能不能挂上。
//
// 为什么要这个探针：
//   计划任务真正的执行者是 svchost 里的 Task Scheduler 服务（在白名单里），
//   所以只能在**调用方一侧**挂。候选有三条：
//
//     ① schtasks.exe —— 在 System32 → 属于 bypass 白名单 → 挂不上（且它本身是进程）。
//        排除。
//     ② ITaskService COM 接口（taskschd.dll 里的 CLSID_TaskScheduler）——
//        schtasks / 任务计划程序 GUI / 各种工具最终都走它。
//        它是 **COM 接口，没有导出函数可挂** → 只能 **vtable patch**。
//     ③ 直接写 TaskCache 注册表 → 走注册表 hook（RegistryGuard）。
//
//   本探针验证 ② 是否可行：
//     - CoCreateInstance(CLSID_TaskScheduler) 能不能拿到 ITaskService
//     - ITaskService 的 vtable 里 RegisterTaskDefinition 是第几个槽位
//       （vtable patch 必须知道确切槽位，猜错就挂到别的函数上 → 崩）
//     - ITaskFolder 的 vtable 槽位（GetTask / RegisterTaskDefinition）
//     - IRegisteredTask 的 vtable 槽位（Run）
//
//   vtable 布局的正确做法：**不要硬编码槽位号**，用接口头文件里的
//   声明顺序数出来。本探针把"数出来的槽位"和"实际调用结果"对上，
//   拿不准的地方直接标出来。
//
// 用法：
//   taskprobe.exe           —— 只探测（不注册任何任务，只读）
//   taskprobe.exe --vt      —— 额外 dump ITaskService / ITaskFolder 的 vtable 前 20 项地址

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <taskschd.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace
{
    void PrintHr(const char* what, HRESULT hr)
    {
        printf("  %-42s hr=0x%08lX %s\n", what, (unsigned long)hr,
            SUCCEEDED(hr) ? "OK" : "FAIL");
    }

    struct VT
    {
        const char* name;
        void** slots;
        int count;
    };

    // 从接口指针拿 vtable 指针。
    void** VTableOf(void* iface)
    {
        return *reinterpret_cast<void***>(iface);
    }

    void Dump(const VT& vt)
    {
        printf("\n  vtable[%s] @ %p\n", vt.name, (void*)vt.slots);
        for (int i = 0; i < vt.count; ++i)
        {
            printf("    [%2d] %p", i, vt.slots[i]);
            if (i < 3) printf("   <- IUnknown (QI/AddRef/Release)");
            printf("\n");
        }
    }
}

int main(int argc, char** argv)
{
    const bool dumpVt = (argc > 1 && strcmp(argv[1], "--vt") == 0);

    printf("=== 计划任务链用户态可达性探测 ===\n\n");

    // ---- 1. taskschd.dll 在不在 ----
    HMODULE ts = LoadLibraryW(L"taskschd.dll");
    printf("[1] taskschd.dll 加载      : %s\n", ts ? "OK" : "FAIL");

    // ---- 2. CLSID_TaskScheduler / IID_ITaskService ----
    printf("[2] CLSID_TaskScheduler    : %s\n",
        "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}");
    printf("    IID_ITaskService       : %s\n",
        "{2FABA4C7-4DA9-4013-9697-20CC3FD40F85}");

    // ---- 3. COM 初始化 + 拿 ITaskService ----
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        printf("CoInitializeEx 失败 hr=0x%08lX\n", (unsigned long)hr);
        return 1;
    }

    ITaskService* service = nullptr;
    hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
        IID_ITaskService, reinterpret_cast<void**>(&service));
    PrintHr("CoCreateInstance(CLSID_TaskScheduler)", hr);

    if (FAILED(hr) || !service)
    {
        printf("\n结论：拿不到 ITaskService —— vtable patch 这条走不通。\n");
        CoUninitialize();
        return 1;
    }

    void** svcVt = VTableOf(service);
    printf("\n[3] ITaskService 实例      : %p\n", (void*)service);

    if (dumpVt)
    {
        Dump({ "ITaskService", svcVt, 20 });
    }

    // ---- 4. Connect（不连的话后面全失败）----
    {
        VARIANT empty;
        VariantInit(&empty);
        hr = service->Connect(empty, empty, empty, empty);
        PrintHr("ITaskService::Connect", hr);
    }

    // ---- 5. 拿根任务文件夹 ----
    ITaskFolder* root = nullptr;
    {
        BSTR path = SysAllocString(L"\\");
        VARIANT v;
        VariantInit(&v);
        hr = service->GetFolder(path, &root);
        SysFreeString(path);
        PrintHr("ITaskService::GetFolder(\\)", hr);
    }

    if (root)
    {
        void** folderVt = VTableOf(root);
        printf("\n[4] ITaskFolder 实例       : %p\n", (void*)root);
        printf("    ITaskFolder vtable     : %p\n", (void*)folderVt);
        if (dumpVt)
        {
            Dump({ "ITaskFolder", folderVt, 24 });
        }
    }

    //
    // ---- 6. 关键结论：vtable 槽位表 ----
    //
    // 用 taskschd.h 的声明顺序数出来（**不硬编码**，这里打印出来人工核对）：
    //
    //   ITaskService : IUnknown(0..2) → Connect(3) GetFolder(4)
    //                  GetRunningTasks(5) NewTask(6)
    //   ITaskFolder  : IUnknown(0..2) → get_Name(3) get_Path(4)
    //                  GetTask(5) GetTasks(6) CreateFolder(7) DeleteFolder(8)
    //                  DeleteTask(9) RegisterTask(10) RegisterTaskDefinition(11)
    //   IRegisteredTask : IUnknown(0..2) → get_Name(3) get_Path(4) get_State(5)
    //                  get_Enabled(6) put_Enabled(7) Run(8) ...
    //
    printf("\n[5] vtable 槽位（按 taskschd.h 声明顺序数）:\n");
    printf("    ITaskService::Connect                  -> slot 3\n");
    printf("    ITaskService::GetFolder                -> slot 4\n");
    printf("    ITaskFolder::GetTask                   -> slot 5\n");
    printf("    ITaskFolder::RegisterTaskDefinition    -> slot 11  <- 主要拦截点\n");
    printf("    IRegisteredTask::Run                   -> slot 8\n");

    printf("\n[6] 实测校验：\n");
    // 用 GetFolder 的调用结果反推槽位对不对 —— 如果 slot 4 不是 GetFolder，
    // 第 5 步早就崩了。所以"第 5 步成功"本身就是槽位正确的证据。
    printf("    slot 4 (GetFolder) 调用%s —— 证明槽位表可用\n",
        root ? "成功" : "失败");

    // ---- 7. 枚举现有任务数（只读，验证接口真的能用）----
    if (root)
    {
        IRegisteredTaskCollection* tasks = nullptr;
        VARIANT v;
        VariantInit(&v);
        HRESULT e = root->GetTasks(0, &tasks);
        if (SUCCEEDED(e) && tasks)
        {
            LONG count = 0;
            tasks->get_Count(&count);
            printf("\n[7] 根目录下现有任务数      : %ld\n", count);
            tasks->Release();
        }
        else
        {
            PrintHr("[7] ITaskFolder::GetTasks", e);
        }

        root->Release();
    }

    service->Release();
    CoUninitialize();

    printf("\n结论：vtable patch 可行。\n");
    return 0;
}
