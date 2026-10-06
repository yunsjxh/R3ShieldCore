// rawdisk_lock_probe.cpp —— 裸盘"独占句柄"硬锁可行性探针
// ============================================================================
//
// 【要回答的问题】
//   v39 的裸盘保护是**注入后 hook `NtCreateFile`/`NtWriteFile`** 实现的，
//   天然带一个"进程启动 -> 注入完成"的**盲区**（v41 把轮询压到 10ms）。
//   对一个"启动后几十毫秒就写 MBR"的样本（如 Windows XP Horror 的
//   `FormCreate -> sub_47A300`），盲区一旦被抢到就输了。
//
//   有没有**不依赖注入、与竞态无关**的用户态手段？
//
//   候选：引擎以管理员身份**独占打开** `\\.\PhysicalDrive0`（dwShareMode = 0），
//   并一直持有该句柄。之后任何进程再用
//     CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ|WRITE, ...)
//   都会因**共享冲突**（ERROR_SHARING_VIOLATION = 32）失败。
//
//   这依赖一个**行为事实**：磁盘类驱动（disk.sys）是否调用
//   `IoCheckShareAccess` 来执行共享模式检查。**文档没写，必须实测**
//   （参见 win-api-behavior-probe 技能：不要相信文档，要探测）。
//
// 【安全性】
//   本探针**只做打开/关闭，绝对不写盘**（真写 = 当场毁引导区）。
//   "写意图打开"用的是 GENERIC_READ|GENERIC_WRITE 的**打开**，一个字节都不写。
//   另外会顺带检查：持有独占句柄期间，**卷上的普通文件读写是否仍然正常**
//   （这是该方案能否上线的关键副作用判据）。
//
// 【需要管理员】非管理员连基线打开都会 err=5，探针会明确 SKIP 而不是 FAIL。
//
// 用法:
//   tools\rawdisk_lock_probe.exe            # 全部
//   tools\rawdisk_lock_probe.exe --quick    # 只跑 0 号盘
//   tools\rawdisk_lock_probe.exe --no-pause # 不暂停（脚本/自动化用）
//
// ★ 默认**暂停**再退出。原因：双击运行时（尤其"未提权"这条提前返回的
//   路径）窗口会一闪而过，用户什么都看不到 —— 这本身就是一次误诊来源。
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

// 双击运行时窗口一闪而过 = 结论永远读不到。默认暂停，`--no-pause` 关闭。
static bool g_noPause = false;

static void PauseBeforeExit()
{
    if (g_noPause) { return; }
    printf("\n按回车键退出...");
    (void)getchar();
}

static void Report(const char* ok, const char* what, const char* detail)
{
    if (strcmp(ok, "PASS") == 0) { g_pass++; printf("  [PASS] %s%s%s\n", what, detail[0] ? " -- " : "", detail); }
    else if (strcmp(ok, "SKIP") == 0) { g_skip++; printf("  [SKIP] %s%s%s\n", what, detail[0] ? " -- " : "", detail); }
    else { g_fail++; printf("  [FAIL] %s%s%s\n", what, detail[0] ? " -- " : "", detail); }
}

// 尝试以给定访问权限 + 共享模式打开裸盘。**只打开，不写。**
static HANDLE TryOpenRawDisk(int diskIndex, DWORD access, DWORD share, DWORD* lastErr)
{
    char path[64];
    sprintf_s(path, sizeof(path), "\\\\.\\PhysicalDrive%d", diskIndex);

    HANDLE h = CreateFileA(path, access, share, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        if (lastErr) { *lastErr = GetLastError(); }
        return INVALID_HANDLE_VALUE;
    }
    if (lastErr) { *lastErr = 0; }
    return h;
}

static bool IsElevated()
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) { return false; }
    TOKEN_ELEVATION elevation = { 0 };
    DWORD size = sizeof(elevation);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// 检查"持有独占句柄期间，卷上普通文件读写是否正常"。
// 在 %TEMP% 下建一个探针文件 -> 写 -> 读回 -> 删除。全是普通文件操作。
static void CheckVolumeStillUsable(const char* phase)
{
    char tempPath[MAX_PATH] = { 0 };
    if (GetTempPathA(MAX_PATH, tempPath) == 0) {
        Report("SKIP", "卷可用性检查", "拿不到 %TEMP%");
        return;
    }

    char filePath[MAX_PATH];
    sprintf_s(filePath, sizeof(filePath), "%srg_rawdisk_lock_probe.tmp", tempPath);

    HANDLE h = CreateFileA(filePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "建临时文件失败 err=%lu", GetLastError());
        Report("FAIL", phase, buf);
        return;
    }

    const char payload[] = "R3ShieldCore raw-disk lock probe: volume write path OK";
    DWORD written = 0;
    BOOL wrote = WriteFile(h, payload, (DWORD)strlen(payload), &written, NULL);
    if (!wrote || written != strlen(payload)) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "写临时文件失败 err=%lu", GetLastError());
        Report("FAIL", phase, buf);
        CloseHandle(h);
        return;
    }

    CloseHandle(h);

    // 读回
    HANDLE hr = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hr == INVALID_HANDLE_VALUE) {
        char buf[128];
        sprintf_s(buf, sizeof(buf), "回读临时文件失败 err=%lu", GetLastError());
        Report("FAIL", phase, buf);
        DeleteFileA(filePath);
        return;
    }
    char readback[128] = { 0 };
    DWORD got = 0;
    ReadFile(hr, readback, sizeof(readback) - 1, &got, NULL);
    CloseHandle(hr);
    DeleteFileA(filePath);

    if (strcmp(readback, payload) != 0) {
        Report("FAIL", phase, "回读内容不一致");
        return;
    }
    Report("PASS", phase, "卷上普通文件 建/写/读/删 全部正常");
}

// 一个盘的一整套实验
static void ProbeOneDisk(int diskIndex, bool quick)
{
    printf("\n---- PhysicalDrive%d ----\n", diskIndex);

    DWORD err = 0;

    // 步骤 1：基线 —— 病毒用的那种打开方式（写意图 + 共享读写）
    //   样本代码：CreateFileA("\\\\.\\PhysicalDrive0", 0x10000000 /*GENERIC_WRITE*/,
    //                          3 /*SHARE_READ|WRITE*/, 0, 3, 0, 0)
    //   这里用 GENERIC_READ|GENERIC_WRITE 而不是 0x10000000，是为了确认
    //   "写意图"这条路径本身能通（0x10000000 是 GENERIC_ALL，见铁律 34）。
    HANDLE hBaseline = TryOpenRawDisk(diskIndex, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &err);
    if (hBaseline == INVALID_HANDLE_VALUE) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "基线打开(写意图,share=3)失败 err=%lu", err);
        if (err == 5) {
            Report("SKIP", "基线：写意图打开裸盘", "err=5 = 不是管理员，整组实验跳过");
            printf("         -> 请以管理员身份重跑本探针\n");
            return;
        }
        Report("FAIL", "基线：写意图打开裸盘", buf);
        printf("         -> 基线都不通，无法判断独占锁是否有效\n");
        return;
    }
    Report("PASS", "基线：写意图打开裸盘", "成功（说明当前无人独占）");
    CloseHandle(hBaseline);

    // 步骤 2：持有独占句柄（share=0）
    //   两种访问权限都试：只读、读写。只读能成功最好（副作用最小）。
    DWORD lockAccess = quick ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    const char* lockAccessName = quick ? "只读" : "读写";
    HANDLE hLock = TryOpenRawDisk(diskIndex, lockAccess, 0 /* 独占 */, &err);
    if (hLock == INVALID_HANDLE_VALUE) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "%s + share=0 打开失败 err=%lu", lockAccessName, err);
        Report("FAIL", "持锁：独占打开裸盘", buf);
        printf("         -> 拿不到独占句柄 = 方案不可行（可能已被系统/其他程序占用）\n");
        return;
    }
    Report("PASS", "持锁：独占打开裸盘", "成功持有 share=0 句柄");

    // 步骤 3：★ 关键判据 —— 持锁期间，病毒那种打开方式必须失败
    HANDLE hAttack = TryOpenRawDisk(diskIndex, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &err);
    if (hAttack == INVALID_HANDLE_VALUE) {
        char buf[200];
        sprintf_s(buf, sizeof(buf),
            "被拒绝 err=%lu (%s)", err,
            err == 32 ? "ERROR_SHARING_VIOLATION 共享冲突，正是预期" : "非共享冲突，原因需查");
        if (err == 32) {
            Report("PASS", "持锁期间：写意图打开被挡", buf);
        }
        else {
            Report("FAIL", "持锁期间：写意图打开被挡", buf);
        }
    }
    else {
        Report("FAIL", "持锁期间：写意图打开被挡",
            "竟然还打开了 = disk.sys 不检查共享模式，独占句柄方案无效");
        CloseHandle(hAttack);
    }

    // 步骤 4：★ 副作用判据 —— 持锁期间卷上普通文件必须还能用
    CheckVolumeStillUsable("持锁期间：卷上文件读写");

    // 步骤 5：持锁期间 `\\.\C:` 是否还能开（有些工具要开卷）
    {
        char volPath[8] = "\\\\.\\C:";
        HANDLE hv = CreateFileA(volPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hv == INVALID_HANDLE_VALUE) {
            char buf[160];
            sprintf_s(buf, sizeof(buf), "打开 \\\\.\\C: 失败 err=%lu（可能影响磁盘工具，记录即可）", GetLastError());
            Report("SKIP", "持锁期间：打开卷句柄", buf);
        }
        else {
            Report("PASS", "持锁期间：打开卷句柄", "\\\\.\\C: 仍可打开");
            CloseHandle(hv);
        }
    }

    // 步骤 6：释放后必须恢复
    CloseHandle(hLock);
    HANDLE hAfter = TryOpenRawDisk(diskIndex, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &err);
    if (hAfter == INVALID_HANDLE_VALUE) {
        char buf[160];
        sprintf_s(buf, sizeof(buf), "释放后仍打不开 err=%lu", err);
        Report("FAIL", "释放锁：写意图打开恢复", buf);
    }
    else {
        Report("PASS", "释放锁：写意图打开恢复", "锁是可逆的");
        CloseHandle(hAfter);
    }
}

int main(int argc, char** argv)
{
    SetConsoleOutputCP(936);
    bool quick = false;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--quick") == 0) { quick = true; }
        if (strcmp(argv[i], "--no-pause") == 0) { g_noPause = true; }
        if (strcmp(argv[i], "--help") == 0) {
            printf("rawdisk_lock_probe.exe [--quick] [--no-pause]\n");
            printf("  验证\"引擎独占持有 \\\\.\\PhysicalDriveN\"能否硬挡写意图打开。\n");
            printf("  --quick    只试只读独占 + 0 号盘。\n");
            printf("  --no-pause 跑完直接退出（脚本用）。\n");
            printf("  ★ 本探针只打开，不写盘。需管理员。\n");
            PauseBeforeExit();
            return 0;
        }
    }

    printf("============================================================\n");
    printf(" R3ShieldCore 裸盘独占锁探针（只打开，不写盘）\n");
    printf("============================================================\n");
    printf(" 管理员: %s\n", IsElevated() ? "是" : "否");

    if (!IsElevated()) {
        printf("\n[SKIP] 非管理员无法打开裸盘做写意图测试。\n");
        printf("       请右键 -> 以管理员身份运行。\n");
        printf("\n汇总: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);
        printf("（未取得结论）\n");
        PauseBeforeExit();
        return 2;
    }

    ProbeOneDisk(0, quick);
    if (!quick) {
        ProbeOneDisk(1, quick);   // 多盘机器上顺带确认第二块
    }

    printf("\n============================================================\n");
    printf(" 汇总: PASS=%d FAIL=%d SKIP=%d\n", g_pass, g_fail, g_skip);

    if (g_fail == 0 && g_pass > 0) {
        printf(" 结论: 独占句柄**可行** —— 持锁期间写意图打开被 err=32 挡下，\n");
        printf("       且卷上普通文件读写不受影响。可作为\"与竞态无关\"的硬保护。\n");
        printf("       注: 磁盘管理/碎片整理/chkdsk 之类需要独占盘的工具会被挡。\n");
        PauseBeforeExit();
        return 0;
    }
    printf(" 结论: 见上面 FAIL 项 —— 独占句柄方案不成立或需调整。\n");
    PauseBeforeExit();
    return 1;
}
