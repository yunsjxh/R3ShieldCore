/* ============================================================================
 * r3shieldcore_kernel.c —— R3ShieldCore 内核组件 v1
 *
 * ★ 本版本**只做「开机自启」**，不含任何防护功能。
 *   （不做 ObRegisterCallbacks / 不做进程回调 / 不做注册表回调 / 不做 minifilter。
 *     那些是后续按需逐层加的，本次明确不做。）
 *
 * 它存在的唯一目的：证明「R3ShieldCore 能有一个 R0 组件，随系统自动加载」这条链是通的
 * —— 能编、能签、能被内核接受、能在开机时自动起来。
 *
 * ---------------------------------------------------------------------------
 * 启动类型：SERVICE_BOOT_START（**已由用户明确指定**，2026-10-05 改）
 * ---------------------------------------------------------------------------
 * 早先本驱动用的是 SERVICE_AUTO_START，理由是"风险小、收益已经够了"。
 * 用户明确要求改成 **BOOT_START（最早）**，并接受随之而来的性质：
 *
 * ① 收益：BOOT_START 由**引导加载器**在 AUTO_START 之前加载，是
 *    用户态代码开始跑之前能拿到的**最早**一档（ELAM 之下）。
 * ② 代价（必须记住，别再踩）：BOOT_START 的驱动**安全模式也会加载**。
 *    · DriverEntry 里**任何**可能失败/挂起的操作都可能变成"进不去系统"；
 *    · 所以这里的铁律是：**不碰系统其它部分**（不挂回调、不改别人的注册表、
 *      不等待任何外部对象），且建设备失败也**返回 STATUS_SUCCESS**。
 * ③ 安全模式下的行为：本驱动**不启动任何进程**（内核组件没有这个能力，
 *    也刻意不加）。"安全模式下 R3 ShieldCore 不激活"这条由用户态服务
 *    （service/r3shieldcore_svc.c 的 IsSafeMode 闸门）保证。
 * ④ 上限：真正比 BOOT_START 更早的是 ELAM（Early Launch Anti-Malware），
 *    需要 SERVICE_BOOT_START + ELAM 标志 + **微软 MVI 颁发的 ELAM 证书**。
 *    自签名拿不到，个人开发者拿不到。详见 driver/README.md。
 *
 * ★ 本文件**不含**安全模式判断：驱动只是"被加载"，加不加它行为完全一样
 *   （不建设备也不会让安全模式出问题），多一个内核分支就多一个开机风险点。
 *   需要这个信息的是用户态那一侧，判据也在那一侧（SM_CLEANBOOT）。
 *
 * ---------------------------------------------------------------------------
 * 安全设计（每一条都是"驱动写错了会怎样"换来的）
 * ---------------------------------------------------------------------------
 * ① DriverEntry 里**最先**记录加载时刻，在任何可能失败的操作之前 —— 这样即使后面
 *    建设备失败，"我什么时候被加载的"这个证据也已经拿到了。
 * ② 建设备失败**不返回错误**（仍返回 STATUS_SUCCESS）：本驱动存在的意义就是"被加载"，
 *    因为设备名冲突这种小事让整个加载失败，是把手段当成了目的。失败原因会 DbgPrint
 *    出来，并记进状态结构供用户态查询（铁律 97：不能只有布尔结论，要有原因）。
 * ③ 实现 DriverUnload，使 `sc stop` 可用 —— 否则驱动只能"禁用 + 重启"才能卸掉。
 * ④ 绝不碰系统其它部分：不挂任何回调、不改任何注册表项（只写自己服务键下的一个值）。
 *
 * ---------------------------------------------------------------------------
 * 构建
 * ---------------------------------------------------------------------------
 *   bash driver/build_driver.sh
 * 产物：driver/build/r3shieldcore_kernel.sys
 * ==========================================================================*/

#include <ntddk.h>

/* ---------------------------------------------------------------------------
 * 常量
 * -------------------------------------------------------------------------*/

/* 设备与符号链接名。符号链接带 \DosDevices\ 前缀，用户态才能用 \\.\ 打开。 */
#define RG_DEVICE_NAME   L"\\Device\\R3ShieldCoreKernel"
#define RG_SYMLINK_NAME  L"\\DosDevices\\R3ShieldCoreKernel"

/* 用户态用 DeviceIoControl 发这个码查询状态。 */
#define RG_IOCTL_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 状态结构的魔数与版本：用户态据此确认"对面真的是 R3ShieldCore 驱动、且是同代次"。
   ★ 没有这两个字段的话，"读到一堆 0" 和 "驱动根本没在" 分不开（铁律 97）。 */
#define RG_STATUS_MAGIC    0x52474B31UL   /* 'R','G','K','1' */
#define RG_STATUS_VERSION  1UL

/* ---------------------------------------------------------------------------
 * 状态
 * -------------------------------------------------------------------------*/

/* ★ 为什么不用浮点：内核 DbgPrint 不支持 %f，而且内核里浮点要自己保存
   FPU 状态。所有时间一律用整数毫秒。 */
#define RG_100NS_PER_MS 10000ULL

typedef struct _RG_STATUS
{
    ULONG     Magic;                    /* 必须是 RG_STATUS_MAGIC */
    ULONG     Version;                  /* 必须是 RG_STATUS_VERSION */
    ULONG     DeviceOk;                 /* 1 = 控制设备建好了，0 = 失败（看 LastError） */
    ULONG     RegStampOk;               /* 1 = 注册表加载戳写成功 */
    ULONG     LastError;                /* 最近一次失败的 NTSTATUS（0 = 无） */
    ULONG     OsBuildNumber;            /* 宿主系统 build 号，便于对号入座 */
    ULONGLONG LoadSinceBootMs;          /* ★ 核心证据：自开机到本驱动被加载的毫秒数 */
    ULONGLONG LoadSystemTime100ns;      /* 加载时的系统时间（1601 起 100ns），墙钟用 */
} RG_STATUS;

static RG_STATUS      g_Status;
static PDEVICE_OBJECT g_DeviceObject  = NULL;
static BOOLEAN        g_SymLinkCreated = FALSE;

/* ---------------------------------------------------------------------------
 * 注册表加载戳
 *
 * 为什么值得写这一笔：DbgPrint 只有挂调试器/开 DebugView 才看得到；控制设备要用户态
 * 主动去查。**注册表这一笔是"不需要任何工具就能看到"的落盘证据**，而且它写在驱动
 * 自己的服务键下（DriverEntry 的 RegistryPath 就是那个键），卸载时随服务键一起删掉。
 *
 * 失败**绝不**影响加载：这只是一条诊断，不是功能。
 * -------------------------------------------------------------------------*/
static VOID
RgWriteLoadStamp(
    _In_ PUNICODE_STRING RegistryPath,
    _In_ ULONGLONG       LoadSinceBootMs
    )
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING    valueName;
    HANDLE            hKey   = NULL;
    NTSTATUS          status;
    ULONGLONG         data   = LoadSinceBootMs;

    /* OBJ_KERNEL_HANDLE：句柄落在内核句柄表里，不会被用户态误用。
       DriverEntry 跑在 system 进程上下文，但显式声明是正确写法。 */
    InitializeObjectAttributes(&oa, RegistryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[R3ShieldCoreKernel] ZwOpenKey 失败 status=0x%08X（仅诊断失效，不影响加载）\n",
            status);
        g_Status.LastError = (ULONG)status;
        return;
    }

    RtlInitUnicodeString(&valueName, L"LoadSinceBootMs");

    status = ZwSetValueKey(hKey, &valueName, 0, REG_QWORD, &data, sizeof(data));
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[R3ShieldCoreKernel] ZwSetValueKey 失败 status=0x%08X\n", status);
        g_Status.LastError = (ULONG)status;
    }
    else
    {
        g_Status.RegStampOk = 1;
    }

    ZwClose(hKey);
}

/* ---------------------------------------------------------------------------
 * IRP 分发
 * -------------------------------------------------------------------------*/

static NTSTATUS
RgDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
RgDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
    )
{
    PIO_STACK_LOCATION sp     = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS           status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG              info   = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (sp->Parameters.DeviceIoControl.IoControlCode == RG_IOCTL_QUERY)
    {
        /* METHOD_BUFFERED：输入输出都走 SystemBuffer，长度在
           Parameters.DeviceIoControl.OutputBufferLength。 */
        if (sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(RG_STATUS))
        {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &g_Status, sizeof(RG_STATUS));
            info   = sizeof(RG_STATUS);
            status = STATUS_SUCCESS;
        }
        else
        {
            /* ★ 缓冲区太小要**明确报出来**，不能静默返回成功 + 0 字节
               —— 那样调用方只会看到"结构体全是 0"（铁律 97）。 */
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---------------------------------------------------------------------------
 * 卸载
 *
 * 有它 `sc stop` 才有效；没有它只能"禁用 + 重启"。
 * -------------------------------------------------------------------------*/
static VOID
RgDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_SymLinkCreated)
    {
        UNICODE_STRING symName;
        RtlInitUnicodeString(&symName, RG_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symName);
        g_SymLinkCreated = FALSE;
    }

    if (g_DeviceObject != NULL)
    {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[R3ShieldCoreKernel] 已卸载（卸载时刻 = 自开机 %I64u ms）\n",
        KeQueryInterruptTime() / RG_100NS_PER_MS);
}

/* ---------------------------------------------------------------------------
 * 入口
 * -------------------------------------------------------------------------*/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS       status;
    UNICODE_STRING devName;
    UNICODE_STRING symName;

    RtlZeroMemory(&g_Status, sizeof(g_Status));
    g_Status.Magic   = RG_STATUS_MAGIC;
    g_Status.Version = RG_STATUS_VERSION;

    /* ---- ① 最先记录"我是什么时候被加载的"（在任何可能失败的操作之前）----
     *
     * ★ KeQueryInterruptTime() = 自**开机**以来的 100ns 计数。这是本驱动最关键的
     *   一个数字，因为它**自己就能区分两种情形**：
     *     开机自启生效 → 这个值很小（几十秒内）
     *     手动 sc start  → 这个值 ≈ 当前系统已运行时长（可能是几小时）
     *   不需要调试器、不需要比对任何外部时间戳。
     */
    g_Status.LoadSinceBootMs     = KeQueryInterruptTime() / RG_100NS_PER_MS;
    {
        LARGE_INTEGER sysTime;
        KeQuerySystemTime(&sysTime);
        g_Status.LoadSystemTime100ns = (ULONGLONG)sysTime.QuadPart;
    }
    {
        RTL_OSVERSIONINFOW osvi;
        RtlZeroMemory(&osvi, sizeof(osvi));
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        if (NT_SUCCESS(RtlGetVersion(&osvi)))
        {
            g_Status.OsBuildNumber = osvi.dwBuildNumber;
        }
    }

    DbgPrint("[R3ShieldCoreKernel] DriverEntry 进入：自开机 %I64u ms，系统 build %u\n",
        g_Status.LoadSinceBootMs, g_Status.OsBuildNumber);

    /* ---- ② 注册表加载戳（纯诊断，失败不影响加载）---- */
    RgWriteLoadStamp(RegistryPath, g_Status.LoadSinceBootMs);

    /* ---- ③ 控制设备（用户态据此取证）----
     *
     * ★ 失败也**继续返回成功**：本驱动的目的是"被加载"，不是"必须有设备"。
     *   原因记进 LastError，用户态查询时看得到。 */
    RtlInitUnicodeString(&devName, RG_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
        0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[R3ShieldCoreKernel] IoCreateDevice 失败 status=0x%08X"
                 "（驱动仍保持已加载）\n", status);
        g_Status.LastError = (ULONG)status;
        g_DeviceObject     = NULL;
    }
    else
    {
        RtlInitUnicodeString(&symName, RG_SYMLINK_NAME);
        status = IoCreateSymbolicLink(&symName, &devName);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[R3ShieldCoreKernel] IoCreateSymbolicLink 失败 status=0x%08X\n", status);
            g_Status.LastError = (ULONG)status;
        }
        else
        {
            g_SymLinkCreated = TRUE;
        }
        g_Status.DeviceOk = 1;
    }

    /* ---- ④ 分发与卸载 ---- */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = RgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = RgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = RgDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RgDispatchDeviceControl;
    DriverObject->DriverUnload                         = RgDriverUnload;

    DbgPrint("[R3ShieldCoreKernel] DriverEntry 完成：设备=%s 注册表戳=%s\n",
        g_Status.DeviceOk  ? "OK" : "失败",
        g_Status.RegStampOk ? "OK" : "失败");

    return STATUS_SUCCESS;
}
