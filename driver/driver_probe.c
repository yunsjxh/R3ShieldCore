/*
 * driver_probe.c —— 证明「驱动开机自启**真的生效**」的取证工具（用户态）。
 *
 * 为什么需要它：`sc query` 说服务是 RUNNING、`StartMode=Auto/Boot`，**并不能**证明
 * 「它是开机时自动起来的」—— 你完全可能刚才手动 `sc start` 过，状态一模一样。
 * 本探针用驱动**自报**的一个数字把这两种情形分开：
 *
 *     LoadSinceBootMs = 驱动被加载时，系统已经开机了多少毫秒
 *
 *   · 开机自启生效 → 这个数很小（BOOT_START 下往往就是 0 或几十毫秒）
 *   · 手动 sc start → 这个数 ≈ 当前系统已运行时长（可能是几小时）
 *
 * ★ v2（2026-10-05，驱动改成 SERVICE_BOOT_START 后）：`LoadSinceBootMs == 0`
 *   从"可疑/缺失"变成**正常且最好**的结果 —— BOOT_START 的 DriverEntry 跑在
 *   中断计时器刚开始走的时候，读到 0 完全合理。所以判据里必须把
 *   「值不存在」和「值就是 0」分开（这就是 haveStamp 存在的理由，铁律 97）。
 *
 * 这个数字由驱动在 DriverEntry 的**第一件事**里用 KeQueryInterruptTime() 取，
 * 不依赖任何外部时间戳，也不需要挂调试器。
 *
 * 三条独立证据（互相交叉验证，铁律 59）：
 *   ① 控制设备 IOCTL   —— 驱动活着并自报
 *   ② 注册表加载戳     —— 驱动落盘的、不需要任何工具就能看的证据
 *   ③ 服务配置 Start   —— 0=Boot / 1=System / 2=Auto / 3=Demand / 4=Disabled
 *
 * ★ 前提门控（铁律 108）：若系统开机还不到 10 分钟，"自启"和"刚手动起"本来就
 *   分不开（两个数都很小），此时本探针**拒绝给结论**，而不是给一个假 PASS。
 *
 * 用法：
 *   driver_probe.exe
 * 退出码：0 = 自启已证实 / 1 = 未证实或有问题
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>   /* ★ 必须：CTL_CODE / FILE_DEVICE_UNKNOWN / METHOD_BUFFERED
                           / FILE_ANY_ACCESS 都在这里。WIN32_LEAN_AND_MEAN 下
                           windows.h 不会带它进来。 */
#include <stdio.h>
#include <locale.h>

/* ---- 必须与 r3shieldcore_kernel.c 逐字节一致 ---- */

#define RG_DEVICE_WIN32_PATH  L"\\\\.\\R3ShieldCoreKernel"
#define RG_SERVICE_REG_PATH   L"SYSTEM\\CurrentControlSet\\Services\\R3ShieldCoreKernel"

#define RG_IOCTL_QUERY \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define RG_STATUS_MAGIC    0x52474B31UL   /* 'R','G','K','1' */
#define RG_STATUS_VERSION  1UL

typedef struct _RG_STATUS
{
    ULONG     Magic;
    ULONG     Version;
    ULONG     DeviceOk;
    ULONG     RegStampOk;
    ULONG     LastError;
    ULONG     OsBuildNumber;
    ULONGLONG LoadSinceBootMs;
    ULONGLONG LoadSystemTime100ns;
} RG_STATUS;

/* ★ 布局必须两侧一致，否则读到的是错位的垃圾 —— 而且**不会报错**。
   这里用编译期断言把它钉死（driver 侧同款断言在 README 里有说明）。 */
typedef char rg_status_size_must_be_40[(sizeof(RG_STATUS) == 40) ? 1 : -1];

/* ------------------------------------------------------------------ */

static int g_fail = 0;

static void Ok(const char* m)   { printf("[ OK ] %s\n", m); }
static void Bad(const char* m)  { g_fail++; printf("[FAIL] %s\n", m); }
static void Info(const char* m) { printf("[INFO] %s\n", m); }

/* 把"自开机毫秒数"翻成人话 */
static void FormatSinceBoot(ULONGLONG ms, char* out, size_t outLen)
{
    const ULONGLONG totalSec = ms / 1000ULL;
    const ULONGLONG h = totalSec / 3600ULL;
    const ULONGLONG m = (totalSec % 3600ULL) / 60ULL;
    const ULONGLONG s = totalSec % 60ULL;
    if (h > 0) {
        _snprintf_s(out, outLen, _TRUNCATE, "%llu 小时 %llu 分 %llu 秒",
            (unsigned long long)h, (unsigned long long)m, (unsigned long long)s);
    } else if (m > 0) {
        _snprintf_s(out, outLen, _TRUNCATE, "%llu 分 %llu 秒",
            (unsigned long long)m, (unsigned long long)s);
    } else {
        _snprintf_s(out, outLen, _TRUNCATE, "%llu 秒", (unsigned long long)s);
    }
}

/* FILETIME(1601) → 本地时间字符串 */
static void FormatFileTime(ULONGLONG time100ns, char* out, size_t outLen)
{
    FILETIME ft;
    SYSTEMTIME st;
    ft.dwLowDateTime  = (DWORD)(time100ns & 0xFFFFFFFFULL);
    ft.dwHighDateTime = (DWORD)(time100ns >> 32);
    if (!FileTimeToSystemTime(&ft, &st)) {
        _snprintf_s(out, outLen, _TRUNCATE, "(转换失败)");
        return;
    }
    if (!SystemTimeToTzSpecificLocalTime(NULL, &st, &st)) {
        /* 拿不到时区就按 UTC 显示，并标注出来 */
        _snprintf_s(out, outLen, _TRUNCATE,
            "%04u-%02u-%02u %02u:%02u:%02u UTC",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return;
    }
    _snprintf_s(out, outLen, _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

/* ---- 证据 ②：注册表加载戳 ----
 *
 * ★ `haveStampOut` 是必须的：`LoadSinceBootMs == 0` 在 BOOT_START 下是**正常**的
 *   （DriverEntry 跑在中断计时器刚开始走的时候），所以"值为 0"和"值不存在"
 *   绝不能合并成同一个结论（铁律 97：布尔结论不可诊断）。 */
static ULONGLONG ReadRegStamp(DWORD* startTypeOut, int* haveStartType,
                              int* haveStampOut)
{
    HKEY  hKey = NULL;
    DWORD startType = 0xFFFFFFFF;
    ULONGLONG stamp = 0;
    DWORD cb;
    LONG  rc;

    *haveStartType = 0;
    *haveStampOut  = 0;

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, RG_SERVICE_REG_PATH, 0,
        KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        printf("[INFO] 读服务注册表键失败 rc=%ld（驱动多半还没安装）\n", rc);
        return 0;
    }

    cb = sizeof(startType);
    if (RegQueryValueExW(hKey, L"Start", NULL, NULL, (LPBYTE)&startType, &cb)
            == ERROR_SUCCESS) {
        *startTypeOut  = startType;
        *haveStartType = 1;
    }

    {
        ULONGLONG v = 0;
        cb = sizeof(v);
        if (RegQueryValueExW(hKey, L"LoadSinceBootMs", NULL, NULL,
                (LPBYTE)&v, &cb) == ERROR_SUCCESS) {
            stamp = v;
            *haveStampOut = 1;
        }
    }

    RegCloseKey(hKey);
    return stamp;
}

static const char* StartTypeName(DWORD t)
{
    switch (t) {
    case 0: return "0 = Boot   （★ 本驱动用这一档：引导加载器加载，最早；安全模式也加载）";
    case 1: return "1 = System （内核初始化早期）";
    case 2: return "2 = Auto   （内核初始化阶段，早于所有用户态服务；比 Boot 晚）";
    case 3: return "3 = Demand （手动 / 按需）";
    case 4: return "4 = Disabled";
    default: return "(未知)";
    }
}

/* ------------------------------------------------------------------ */

int main(void)
{
    HANDLE    h = INVALID_HANDLE_VALUE;
    RG_STATUS st;
    DWORD     bytesReturned = 0;
    BOOL      deviceOk = FALSE;
    ULONGLONG uptimeMs;
    ULONGLONG regStamp;
    DWORD     startType = 0xFFFFFFFF;
    int       haveStartType = 0;
    int       haveRegStamp = 0;
    int       haveLoadValue = 0;
    ULONGLONG loadMs = 0;
    char      buf[128];

    setlocale(LC_ALL, "");

    printf("=== R3ShieldCore 内核组件：开机自启取证 ===\n\n");

    /* ---------- 证据 ①：控制设备 ---------- */
    printf("--- 证据 1/3：控制设备 IOCTL ---\n");
    h = CreateFileW(RG_DEVICE_WIN32_PATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        printf("[INFO] 打不开 %ls，GetLastError=%lu\n", RG_DEVICE_WIN32_PATH, err);
        switch (err) {
        case ERROR_FILE_NOT_FOUND:      /* 2 */
        case ERROR_PATH_NOT_FOUND:      /* 3 */
            Info("→ 设备不存在：驱动没加载，或加载了但 IoCreateDevice 失败");
            Info("  先看：sc query R3ShieldCoreKernel / 看驱动自己的 DbgPrint");
            break;
        case ERROR_ACCESS_DENIED:       /* 5 */
            Info("→ 拒绝访问：本探针没有管理员权限，或设备 DACL 只放行 SYSTEM/管理员");
            Info("  用管理员身份重跑一次即可区分这两种原因");
            break;
        default:
            Info("→ 见上面 GetLastError 值");
            break;
        }
        Bad("设备打不开 —— 证据 1 缺失");
    } else {
        ZeroMemory(&st, sizeof(st));
        if (!DeviceIoControl(h, RG_IOCTL_QUERY, NULL, 0, &st, sizeof(st),
                &bytesReturned, NULL)) {
            printf("[INFO] DeviceIoControl 失败 GetLastError=%lu\n", GetLastError());
            Bad("IOCTL 查询失败 —— 证据 1 缺失");
        } else if (bytesReturned != sizeof(st)) {
            printf("[INFO] 返回长度=%lu，期望=%lu\n",
                (unsigned long)bytesReturned, (unsigned long)sizeof(st));
            Bad("返回长度不对 —— 结构体布局两侧不一致");
        } else if (st.Magic != RG_STATUS_MAGIC) {
            printf("[INFO] 魔数=0x%08X，期望 0x%08X\n", st.Magic, RG_STATUS_MAGIC);
            Bad("魔数不对 —— 对面不是 R3ShieldCore 驱动（设备名撞车？）");
        } else {
            deviceOk = TRUE;
            printf("[ OK ] 设备可打开，驱动自报如下：\n");
            printf("       magic=0x%08X version=%u os_build=%u\n",
                st.Magic, st.Version, st.OsBuildNumber);
            printf("       device_ok=%u reg_stamp_ok=%u last_error=0x%08X\n",
                st.DeviceOk, st.RegStampOk, st.LastError);
            if (st.LastError != 0) {
                printf("[INFO] last_error 非 0：驱动内部有一步失败了（见驱动 DbgPrint）\n");
            }
            loadMs = st.LoadSinceBootMs;
            haveLoadValue = 1;
            FormatSinceBoot(loadMs, buf, sizeof(buf));
            printf("       LoadSinceBootMs=%llu  →  开机后 %s 被加载\n",
                (unsigned long long)loadMs, buf);
            FormatFileTime(st.LoadSystemTime100ns, buf, sizeof(buf));
            printf("       加载墙钟时间 = %s\n", buf);
        }
        CloseHandle(h);
    }

    /* ---------- 证据 ②：注册表加载戳 ---------- */
    printf("\n--- 证据 2/3：注册表加载戳（驱动落盘，不需要任何工具就能看）---\n");
    regStamp = ReadRegStamp(&startType, &haveStartType, &haveRegStamp);
    if (!haveRegStamp) {
        Info("HKLM\\SYSTEM\\CurrentControlSet\\Services\\R3ShieldCoreKernel\\LoadSinceBootMs "
             "**不存在** —— 驱动从没成功跑过 DriverEntry？");
    } else {
        FormatSinceBoot(regStamp, buf, sizeof(buf));
        printf("[ OK ] LoadSinceBootMs=%llu  →  开机后 %s 被加载\n",
            (unsigned long long)regStamp, buf);
        if (regStamp == 0) {
            /* ★ 0 不是"没拿到"，是"加载得极早"。BOOT_START 下这是预期值。 */
            printf("[INFO] 值为 0：BOOT_START 的 DriverEntry 跑在中断计时器刚开始走的时候，"
                   "0 是**正常且最早**的结果（不是缺失）\n");
        }
        if (haveLoadValue && regStamp != loadMs) {
            printf("[INFO] [注意] 与设备自报的 %llu 不一致（差 %lld ms）——两次启动？\n",
                (unsigned long long)loadMs,
                (long long)((long long)loadMs - (long long)regStamp));
        } else if (haveLoadValue) {
            printf("[ OK ] 与设备自报值一致（交叉校验通过，铁律 59）\n");
        }
        if (!haveLoadValue) {
            loadMs = regStamp;
            haveLoadValue = 1;
        }
    }

    /* ---------- 证据 ③：服务启动类型 ---------- */
    printf("\n--- 证据 3/3：服务启动类型 ---\n");
    if (haveStartType) {
        printf("[INFO] Start = %s\n", StartTypeName(startType));
        if (startType == 0) {
            Ok("启动类型是 Boot(0) —— 引导加载器加载，**最早的一档**（用户指定的目标）");
        } else if (startType == 2) {
            Bad("启动类型是 Auto(2)，不是要求的 Boot(0) —— Auto 也算开机自启，"
                "但它比 Boot 晚，不满足「最早启动」");
        } else {
            Bad("启动类型既不是 Boot(0) 也不是 Auto(2) —— 它不会开机自启");
        }
    } else {
        Bad("读不到 Start 值 —— 服务键不存在？");
    }

    /* ---------- 结论（带前提门控）---------- */
    printf("\n=== 结论 ===\n");
    uptimeMs = GetTickCount64();
    FormatSinceBoot(uptimeMs, buf, sizeof(buf));
    printf("[INFO] 系统当前已运行：%llu ms（%s）\n",
        (unsigned long long)uptimeMs, buf);

    if (!haveLoadValue) {
        Bad("拿不到任何加载时刻证据 —— 无法判定（驱动没装 / 没加载）");
        printf("\n结果：未证实\n");
        return 1;
    }

    printf("[INFO] 驱动加载于开机后 %llu ms；系统已运行 %llu ms\n",
        (unsigned long long)loadMs, (unsigned long long)uptimeMs);

    /* ★ 前提门控：开机不到 10 分钟时，'自启' 与 '刚手动起' 本来就分不开
       —— 两个数都很小。此时拒绝给结论，而不是给假 PASS（铁律 108）。 */
    if (uptimeMs < 10ULL * 60ULL * 1000ULL) {
        Bad("前提不足：系统开机还不到 10 分钟，「自启」和「刚手动 sc start」"
            "在数值上无法区分");
        Info("→ 请开机满 10 分钟后再跑本探针（或重启后等一会儿再跑）");
        printf("\n结果：前提不足，未证实\n");
        return 1;
    }

    /* 自启生效：加载时刻应远早于"现在"。这里用 2 分钟作为绝对上限，
       并要求加载时刻 < 运行时长的一半 —— 后者才是真正能证伪的那条。 */
    if (loadMs <= 120000ULL) {
        Ok("驱动在开机 2 分钟内被加载 —— 开机自启生效");
        printf("\n结果：开机自启已证实（开机后 %llu ms 加载，系统已运行 %llu ms）\n",
            (unsigned long long)loadMs, (unsigned long long)uptimeMs);
        return 0;
    }

    if (loadMs * 2ULL >= uptimeMs) {
        Bad("加载时刻接近系统运行时长 —— 这是「刚被手动启动」，不是开机自启");
        Info("→ 手动 sc stop 再重启系统，然后**什么都不要做**直接跑本探针");
        printf("\n结果：未证实（像是手动启动的）\n");
        return 1;
    }

    Bad("加载时刻既不够早（>2 分钟）也不够晚（<运行时长的一半）—— 无法归类");
    Info("→ 可能是：驱动加载失败后被 SCM 重试；或系统长时间未重启而驱动中途被起过");
    printf("\n结果：未证实（无法归类）\n");
    return 1;
}
