//
// spoof_e2e_target.cpp —— 端到端验证的「被注入目标」进程（v133：四面版）。
//
// 它**自己不做任何 hook**：只负责
//   ① 报告自己起来了（READY），让 runner 知道可以放引擎去注入；
//   ② 等一个注入窗口（默认 3s）；
//   ③ 走**四条真的数据获取路径**，把结果打成一行机器可解析的 `RESULT ...`：
//        · 屏幕  —— BitBlt 屏幕 DC -> 内存 DC -> GetDIBits 读回（ScreenGuard 已挂）
//                   外加 GetPixel 直读（ScreenGuard **没挂**）作为真实画面参照；
//        · 剪贴板 —— SetClipboardData(CF_UNICODETEXT) 后 GetClipboardData 读回
//                   （ClipboardGuard 已挂）；
//        · 注册表 —— RegQueryValueExW 读一个**预先存在**的值
//                   （内部走 NtQueryValueKey，RegistryGuard 已挂）；
//        · 文件  —— CreateFileW(GENERIC_READ) + ReadFile 读一个**预先存在**的文件
//                   （内部走 NtCreateFile + NtReadFile，FileGuard v133 已挂）。
//
// ★ v133 为什么文件面必须也来真的、不能只靠自挂探针：
//   `tools/spoof_file_probe.exe` 是**自己 hook 自己**（机制行不行）；
//   而这里的"句柄 → 是否受保护"那张表是**跨调用**的：
//     open 时记、read 时查、close 时擦，三步分布在三个 hook 里。
//   只有让**真引擎**注入**真进程**、走"一次 open + 一次 read"的真实时序，
//   才能证明这三步在生产链路里真的串起来了（探针里是同一次调用内手搓的顺序）。
//   而且这里能顺带验到"**替换不依赖 hook_file**"（ini 里显式 hook_file=0）——
//   那条设计约束在探针里根本表达不出来。
//
// 为什么要有它：三个 guard 的替换逻辑都活在 **被注入进程** 里，所以
//   「端到端」必须有一个真的被注入、真的去取数据的进程。它就是这个进程。
//
// ⚠️ 它只**读**屏幕 / 读剪贴板 / **读**注册表 / **读**文件；唯一一次写是
//    **往剪贴板放自己的测试文本**（`SetClipboardData` 不被 guard 拦，见下）。
//    注册表的值与那个测试文件都由 runner 在**起引擎之前**备好 —— 本进程只读。
//    为什么不在本进程里建：
//      · 注册表：`protect_reg=` 命中的路径被算作**高危写**
//        （r3shieldcore_rules.cpp:678），`mode=block` 下会**被拒** ⇒ 建不出来。
//      · 文件：`protect_file=` 命中的路径同样算高危**写**（同上那处），
//        `mode=block` 下 `CreateFileW(GENERIC_WRITE)` 会被拒 ⇒ 也建不出来。
//    （那不是 bug，正是"保护 = 写不进"这条设计；所以备料必须在引擎外做。）
//    ★ 顺带说明：正因为**写**被拒而**读**不被拒，本进程用 GENERIC_READ 打开
//      受保护文件是能成功的 —— A/B 格才有"同一份路径、spoof 开/关两种结果"
//      这个可比性（否则 B 格连门都进不去，会退化成"都没读到"，看不出区别）。
//
// ⚠️ 屏幕内容会变（时钟、动画）。所以屏幕判据不是"像素等于某个具体值"，
//    而是"BitBlt 路 vs GetPixel 路 的关系"（见 spoof_e2e.sh 的三格矩阵）。
//    剪贴板 / 注册表判据是"读回来的内容 vs 我们放进去的**已知常量**"，确定性强。
//
// 编译：bash build_spoof_e2e.sh
// 运行：spoof_e2e_target.exe [--wait-ms=3000] [--tag=NAME] [--file=PATH]
//       ★ --file=PATH 是文件面要读的那个文件（**绝对 Windows 路径**）；
//         runner 每次调用都会带它，手工跑漏了就 file_open=0（会判 FAIL，不会假绿）。
//
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// 采样区域：取屏幕左上角一块。桌面这里通常是壁纸 / 图标 ⇒ 大概率非黑。
static const int kSampleW = 128;
static const int kSampleH = 96;

// ★★★ `GetPixel` 的采样**预算**（v74 加）。
//
// 为什么非要有：`GetPixel` 在屏幕 DC 上**极慢** —— 实测本机约 **17ms/次**
//   （GDI 要往显示驱动跑一趟）。原来两块采样合计 ~700 次 ⇒ 光这一项就
//   **11.7 秒**（整个目标程序 15s 里占 11.7s）。后果：
//     · `--prepare` / `--collect` 每次都要跑一遍基线 ⇒ 每次多等 15s；
//     · 夹具的判据自测（tools/spoof_e2e_selftest.sh）要跑十几遍 ⇒ 6 分钟。
//   而 `GetPixel` 采样的**目的**只是"证明这条**未被 hook** 的路仍能读到
//   真实画面"（多路径戳穿）—— 几个点就够，不需要几百个。
//
// ⇒ 给它一个**调用次数上限**，采样步长按屏幕尺寸自适应。这样在"GetPixel 很快"
//   的机器上覆盖更密，在"很慢"的机器上自动变稀，总耗时都可控。
//   ⚠️ 上限不能太小：B 格要证的是"屏幕上**存在**非黑点"，采样太稀可能
//      全落在黑区（引擎窗口、暗色壁纸）⇒ 假 FAIL。64 个点是够的。
static const int kGetPixelBudget = 64;

// ---- 剪贴板：我们自己放进去的**已知秘密**（替换生效时应读回空串）----
static const wchar_t* kClipSecret = L"R3SC-E2E-CLIP-SECRET-0123456789";

// ---- 注册表：runner 预先建好的键 / 值 / 内容 ----
//    ★ 这三个常量与 spoof_e2e.sh 里 `reg add` 的那份**必须一致**。
//      它们是跨进程契约（bash 侧建、本进程读）⇒ 改一处必须改两处。
//      运行时用 `reg_match` 判"读到的等不等于 kRegSecret"，所以真的漂了
//      会**判 FAIL**，不会静默（铁律 97：口径必须与实际一致）。
static const wchar_t* kRegSubKey    = L"Software\\R3ShieldCoreE2E";
static const wchar_t* kRegValueName = L"Secret";
static const wchar_t* kRegSecret    = L"R3SC-E2E-REG-SECRET";

// ---- 文件：runner 预先写好的文件内容（替换生效时应读回**全 0**）----
//    ★★★ 判据是**字节**语义，不是宽字符语义：
//      v133 的替换做的是 `memset(缓冲区, 0, 实际读到的字节数)` —— 它把**字节**
//      清掉，长度不变。所以文件面必须按字节判断，不能把内容当 `wchar_t` 读回来
//      （第一版就是这么写的：ASCII 31 字节按 UTF-16 解成 15 个宽字符，
//       `wcslen` 得到 16、`match=0` —— 那会让人以为"替换把内容改坏了"）。
//    ★ 判据要**两个字段一起看**，别只看 `file_strlen=0`：
//        · 替换生效：ReadFile **成功**、`file_bytes` 仍有值（长度不变）、`file_strlen`=0
//        · 没读到  ：ReadFile 失败 / `file_bytes`=0
//      只查 strlen=0 的话，"根本没读到"也满足 ⇒ 空真（铁律 110）。
//      ⇒ runner 的 B/C 格断言里必须同时要求 `file_bytes > 0`。
//    ★ 与 spoof_e2e.sh 里的 `FILE_SECRET` **必须逐字符一致**：bash 侧写、本进程读，
//      是跨进程契约。真漂了会**判 FAIL**（file_match=0），不会静默（铁律 97）。
static const char* kFileSecret = "R3SC-E2E-FILE-SECRET-0123456789";

// 命令行参数解析：找 `--name=VALUE`。
//
// ★★★ v133 修：这里原来写的是
//       for (p = cl; (p = strstr(p, "--")) != nullptr; ++p) { ++p; ... }
//   `strstr` 返回的是**第一个** '-' 的位置，循环体和 for 的自增**各跳一个**，
//   合起来才是"跳过 -- "——但比较发生在**只跳过一次**的时候 ⇒ 比的是
//   `-name` vs `name` ⇒ **永远不匹配**。
//   实测（v133）：`--wait-ms=0` / `--wait-ms=2500` 一直被**静默忽略**，
//   目标每次都按默认 3000ms 等 —— 因为 2500 与 3000 只差 0.5s，而引擎窗口有
//   20s，**功能上看不出来**，于是这个 bug 活了 60 多代次。
//   ⇒ 判据：解析器自己不报错，只会"取值落到默认"，所以在 runner 侧**看不出来**；
//     这类"静默回落"必须靠"传一个极端值看有没有效果"来验（v133 是传 --file
//     时立刻暴露的：路径为空 ⇒ file_oerr=87）。
//
// ⚠️ 现在写法是 `p += 2` 且**不再**用 for 的第三个表达式 —— 一处跳完，
//    别再把"跳两次"的活拆到两个地方（就是那么裂的）。
static unsigned ParseMsArg(const char* name, unsigned fallback)
{
    const char* cl = GetCommandLineA();
    const size_t nlen = strlen(name);
    const char* p = cl;
    while (p && (p = strstr(p, "--")) != nullptr) {
        p += 2;   // 跳过 "--"
        if (_strnicmp(p, name, nlen) == 0 && p[nlen] == '=') {
            return static_cast<unsigned>(strtoul(p + nlen + 1, nullptr, 10));
        }
    }
    return fallback;
}

// 取 `--tag=NAME` 的 NAME。
//
// ★ 为什么要截到第一个空格：原来的实现直接返回 `--tag=` 之后的**全部内容**，
//   命令行形如 `--tag=A --file=B` 时 tag 就变成 `A --file=B` ——
//   打进 TARGET 行里既难看又会让"看日志诊断"的人以为 tag 里真的有路径
//   （铁律 97：输出必须如实）。v133 加 `--file=` 时这个毛病立刻显形。
static const char* TagArg(char* out, size_t capacity, const char* fallback)
{
    if (!out || capacity == 0) {
        return fallback;
    }
    out[0] = '\0';
    if (fallback) {
        strncpy_s(out, capacity, fallback, _TRUNCATE);
    }

    const char* cl = GetCommandLineA();
    const char* key = "--tag=";
    const char* p = cl ? strstr(cl, key) : nullptr;
    if (!p) {
        return out;
    }
    p += strlen(key);

    size_t i = 0;
    while (p[i] != '\0' && p[i] != ' ' && i + 1 < capacity) {
        out[i] = p[i];
        ++i;
    }
    out[i] = '\0';
    return out;
}

// 取一个**字符串**形式的命令行参数（形如 `--file=C:\...\x.txt`）。
//
// ★ 为什么文件路径**必须由 runner 传进来**、不能让本进程自己拼：
//   本进程运行在**父 shell** 里，ProgramData 并**没有**被重定向（那是引擎子进程
//   才有的事），所以本进程看不到工作区。工作区路径只有 runner 知道。
//   传绝对路径还有个好处：ini 里 `protect_file=` 用的就是同一条串，
//   "目标读的文件" 与 "配置声明的受保护前缀" 天然是同一个来源（铁律 127）。
//
// ★★★ 为什么走**宽**命令行（`GetCommandLineW`）而不是 `GetCommandLineA`：
//   `GetCommandLineA` 会把命令行走一遍系统 ANSI 代码页（中文机 = CP936）。
//   本机 `%TEMP%` 是 ASCII（`C:\Users\44338\AppData\Local\Temp`）所以看不出问题，
//   但**用户名带汉字**的机器上目录名就是中文 ⇒ `GetCommandLineA` 拿到的
//   已经是问号串 ⇒ 打开失败 ⇒ B/C 格报"file_bytes=0"，而真实原因
//   "路径被代码页吃了"跟"替换没生效"差十万八千里（铁律 185 同族）。
//   ⇒ 入口就用宽版本，内部不再有窄宽转换这一步。
static void WideStrArg(const wchar_t* name, wchar_t* out, size_t capacity,
    const wchar_t* fallback)
{
    if (!out || capacity == 0) {
        return;
    }
    out[0] = L'\0';
    if (fallback) {
        wcsncpy_s(out, capacity, fallback, _TRUNCATE);
    }

    const wchar_t* cl = GetCommandLineW();
    if (!cl) {
        return;
    }
    const size_t nlen = wcslen(name);
    const wchar_t* p = cl;
    // ⚠️ `p += 2` 一次跳完 "--"（原因见 ParseMsArg 上面那段 v133 修复说明）。
    while ((p = wcsstr(p, L"--")) != nullptr) {
        p += 2;
        if (_wcsnicmp(p, name, nlen) == 0 && p[nlen] == L'=') {
            wcsncpy_s(out, capacity, p + nlen + 1, _TRUNCATE);
            return;
        }
    }
}

// ==================================================================
// 剪贴板：放一段已知文本，再读回来
// ==================================================================
//
// ⚠️ 为什么自己放：剪贴板是**全局共享**的，别的进程随时可能改它。
//    只有在**同一次运行内**「我放 X → 我读回 Y」，Y 与 X 的比较才是确定的。
//    否则"读到空"到底是"被替换了"还是"本来就没内容"分不清（铁律 110 空真）。
//
// ⚠️ `SetClipboardData` 不被 guard 拦（剪贴板面只拦**读**：Open 记录、取数据高危）。
//    所以本进程能正常把自己的文本放上去 —— 这是**前提**，不是被测试的对象。
static bool OpenClipboardRetry(int attempts)
{
    for (int i = 0; i < attempts; ++i) {
        if (OpenClipboard(nullptr)) {
            return true;
        }
        Sleep(50);
    }
    return false;
}

// 返回 true = 已把 kClipSecret 放进剪贴板。
static bool PutClipboardSecret()
{
    if (!OpenClipboardRetry(20)) {
        return false;
    }

    EmptyClipboard();

    const size_t bytes = (wcslen(kClipSecret) + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!hg) {
        CloseClipboard();
        return false;
    }
    memcpy(GlobalLock(hg), kClipSecret, bytes);
    GlobalUnlock(hg);

    // ⚠️ SetClipboardData 成功后**所有权转移给系统**：失败时必须自己释放，
    //    成功时**不能**再释放（否则系统持有野句柄）。探针踩过这个坑。
    if (!SetClipboardData(CF_UNICODETEXT, hg)) {
        GlobalFree(hg);
        CloseClipboard();
        return false;
    }

    CloseClipboard();
    return true;
}

struct ClipOutcome
{
    bool read;          // GetClipboardData 返回非空
    DWORD err;          // 失败时的 GetLastError
    size_t strlen;      // 读回字符串的长度（字符数）
    bool match;         // 读回的字符串 == kClipSecret
};

static ClipOutcome ReadClipboardSecret()
{
    ClipOutcome out = { false, 0, 0, false };

    if (!OpenClipboardRetry(20)) {
        out.err = GetLastError();
        return out;
    }

    SetLastError(0);
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (!h) {
        out.err = GetLastError();
        CloseClipboard();
        return out;
    }

    out.read = true;

    // CF_UNICODETEXT 的块是 HGLOBAL，里面是 NUL 结尾的 UTF-16。
    const wchar_t* text = static_cast<const wchar_t*>(GlobalLock(h));
    if (text) {
        out.strlen = wcslen(text);
        out.match = (wcscmp(text, kClipSecret) == 0);
        GlobalUnlock(h);
    }

    CloseClipboard();
    return out;
}

// ==================================================================
// 注册表：读一个**预先存在**的值（runner 建的）
// ==================================================================
struct RegOutcome
{
    bool read;      // RegQueryValueExW 返回 ERROR_SUCCESS
    DWORD err;      // 失败时的返回码
    size_t strlen;  // 读回字符串长度（字符数）
    bool match;     // 读回的字符串 == kRegSecret
};

static RegOutcome ReadRegistrySecret()
{
    RegOutcome out = { false, 0, 0, false };

    HKEY key = nullptr;
    LSTATUS st = RegOpenKeyExW(HKEY_CURRENT_USER, kRegSubKey, 0, KEY_READ, &key);
    if (st != ERROR_SUCCESS) {
        out.err = static_cast<DWORD>(st);
        return out;
    }

    wchar_t buffer[256] = {};
    DWORD cbData = sizeof(buffer);
    DWORD type = 0;
    SetLastError(0);
    st = RegQueryValueExW(key, kRegValueName, nullptr, &type,
        reinterpret_cast<LPBYTE>(buffer), &cbData);
    if (st != ERROR_SUCCESS) {
        out.err = static_cast<DWORD>(st);
        RegCloseKey(key);
        return out;
    }

    out.read = true;
    if (type == REG_SZ) {
        // ⚠️ 替换是"清零**数据区**、长度字段一个不改" ⇒ 返回的 cbData 不变，
        //    但首字符变 0 ⇒ wcslen == 0。所以判据用 **strlen**，不是 cbData。
        buffer[(sizeof(buffer) / sizeof(buffer[0])) - 1] = L'\0';
        out.strlen = wcslen(buffer);
        out.match = (wcscmp(buffer, kRegSecret) == 0);
    }

    RegCloseKey(key);
    return out;
}

// ==================================================================
// 文件：读一个**预先存在**的文件（runner 写的）
// ==================================================================
//
// ★ 为什么要专门判 `bytes`（读到的字节数）：
//   v133 的替换是"**调用成功、长度不变、内容全 0**"。所以三个量必须分开看：
//     bytes  > 0   ⇒ 这次读**真的发生了**（不是打开失败 / EOF）
//     strlen == 0  ⇒ 内容被清空
//     match  == 0  ⇒ 读到的不是原始秘密
//   任何一个缺失，"替换生效"和"压根没读到"就会混在一起（铁律 110）。
//
// ★ 走 `CreateFileW` + `ReadFile` 而不是 `fopen`/`ifstream`：
//   这两条是**确定**落到 `NtCreateFile` / `NtReadFile` 上的最短路径
//   （CRT 的 `fopen` 还会先搞一通缓冲与查找，多绕几层，判据就不好归因）。
//
// ★ 按**字节**读（`char` 缓冲，不做宽窄转换）：替换就是清字节，
//   用宽字符解析等于自己引入一层编码假设（见 `kFileSecret` 那段说明）。
struct FileOutcome
{
    bool   openOk;   // CreateFileW 成功
    DWORD  openErr;  // 打开失败的 GetLastError
    bool   read;     // ReadFile 成功
    DWORD  err;      // 读失败的 GetLastError
    DWORD  bytes;    // 读到的字节数
    size_t strlen;   // 读到内容里第一个 0 字节之前的长度（字节）
    bool   match;    // 读到的内容 == kFileSecret
};

static FileOutcome ReadFileSecret(const wchar_t* path)
{
    FileOutcome out = { false, 0, false, 0, 0, 0, false };
    if (!path || !path[0]) {
        out.openErr = ERROR_INVALID_PARAMETER;
        return out;
    }

    // ⚠️ **只读**打开：受保护路径的**写**在 block 下会被拒（那是设计），
    //    但**读**不在高危 op 表里 ⇒ 打开必然成功。A/B 两格的可比性靠这一点。
    //    FILE_SHARE_READ|WRITE：runner 那边可能正拿着它（--collect 复查时）。
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        out.openErr = GetLastError();
        return out;
    }
    out.openOk = true;

    char buffer[256] = {};
    DWORD read = 0;
    SetLastError(0);
    if (!ReadFile(h, buffer, sizeof(buffer) - 1, &read, nullptr)) {
        out.err = GetLastError();
        CloseHandle(h);
        return out;
    }

    out.read = true;
    out.bytes = read;

    // ⚠️ 被替换时 buffer **全是 0** ⇒ strlen 得到 0，
    //    而 `read`（字节数）仍是真实的 31 —— 这正是判据要的"长度不变"。
    size_t n = 0;
    while (n < read && buffer[n] != '\0') {
        ++n;
    }
    out.strlen = n;

    const size_t secretLen = strlen(kFileSecret);
    out.match = (n == secretLen && memcmp(buffer, kFileSecret, n) == 0);

    CloseHandle(h);
    return out;
}

int main()
{
    const unsigned waitMs = ParseMsArg("wait-ms", 3000);
    char tagBuf[64] = {};
    const char* tag = TagArg(tagBuf, _countof(tagBuf), "");

    // ★ 文件面的**目标路径**由 runner 传（理由见 WideStrArg 的长注释）。
    //   不传 ⇒ filePath 为空 ⇒ 文件面直接判"打不开"，RUNNER 侧会因此 FAIL，
    //   **不会**静默当成"读到真值"（那是要防的那种假绿）。
    wchar_t filePath[MAX_PATH] = {};
    WideStrArg(L"file", filePath, _countof(filePath), L"");

    setvbuf(stdout, nullptr, _IONBF, 0);

    printf("TARGET pid=%lu arch=%s tag=%s\n",
        static_cast<unsigned long>(GetCurrentProcessId()),
#ifdef _WIN64
        "x64",
#else
        "x86",
#endif
        tag);
    printf("READY\n");

    // ---- 注入窗口：让引擎的轮询注入有时间落进来 ----
    Sleep(waitMs);

    // ================================================================
    // ① 真实截屏路径：BitBlt(屏幕 DC -> 内存 DC) 然后 GetDIBits 读回
    // ================================================================
    HDC screen = GetDC(nullptr);
    if (!screen) {
        printf("RESULT error=GetDC failed err=%lu\n", GetLastError());
        return 3;
    }

    HDC memDc = CreateCompatibleDC(screen);
    HBITMAP memBmp = CreateCompatibleBitmap(screen, kSampleW, kSampleH);
    if (!memDc || !memBmp) {
        printf("RESULT error=CreateCompatibleDC/Bitmap failed err=%lu\n", GetLastError());
        ReleaseDC(nullptr, screen);
        return 3;
    }
    HGDIOBJ oldBmp = SelectObject(memDc, memBmp);

    // 先把目标位图涂成一个**可识别**的非黑非零值：这样"BitBlt 到底有没有
    // 写进去"和"写进去之后有没有被涂黑"能分开。
    // （若 BitBlt 被 Block，目标应保持这个值；若被 Spoof，应变成全黑。）
    {
        RECT r = { 0, 0, kSampleW, kSampleH };
        HBRUSH br = CreateSolidBrush(RGB(0x12, 0x34, 0x56));
        FillRect(memDc, &r, br);
        DeleteObject(br);
    }

    SetLastError(0);
    const BOOL bitbltOk = BitBlt(memDc, 0, 0, kSampleW, kSampleH, screen, 0, 0, SRCCOPY);
    const DWORD bitbltErr = GetLastError();

    // ---- GetDIBits 读回（32bpp top-down）----
    BITMAPINFO bi = {};
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = kSampleW;
    bi.bmiHeader.biHeight = -kSampleH;   // 负 = top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;

    DWORD* px = static_cast<DWORD*>(calloc(static_cast<size_t>(kSampleW) * kSampleH, sizeof(DWORD)));
    int lines = 0;
    DWORD first = 0xFFFFFFFF;
    int nonBlack = 0;
    if (px) {
        SetLastError(0);
        lines = GetDIBits(memDc, memBmp, 0, static_cast<UINT>(kSampleH), px, &bi, DIB_RGB_COLORS);
        first = px[0];
        const int total = kSampleW * kSampleH;
        for (int i = 0; i < total; ++i) {
            // DIB 32bpp 像素是 BGRA 内存序；全 0 = 黑。
            if ((px[i] & 0x00FFFFFFu) != 0) {
                ++nonBlack;
            }
        }
    }

    // ================================================================
    // ② GetPixel 直接读屏幕 —— **ScreenGuard 没挂这条路径**
    //    它永远拿到真实画面 ⇒ 用来实证「多路径戳穿」。
    //    ⚠️ 见 kGetPixelBudget 的说明：这条路的调用次数**必须有预算**
    //       （17ms/次 ⇒ 几百次就是十几秒）。
    // ================================================================
    const COLORREF gp0 = GetPixel(screen, 0, 0);
    const COLORREF gpMid = GetPixel(screen, kSampleW / 2, kSampleH / 2);

    // 统计 GetPixel 路径下的非黑像素数（小样本，够判"是不是全黑屏"）。
    // 步长 16 ⇒ 8×6 = 48 次（在 64 的预算内）。
    int gpNonBlack = 0;
    int gpGridTotal = 0;
    for (int y = 0; y < kSampleH; y += 16) {
        for (int x = 0; x < kSampleW; x += 16) {
            ++gpGridTotal;
            const COLORREF c = GetPixel(screen, x, y);
            if (c != CLR_INVALID && (c & 0x00FFFFFFu) != 0) {
                ++gpNonBlack;
            }
        }
    }

    // ★ 再加一份**全屏**采样（粗网格）。
    //
    // 为什么要它：引擎起来之后会开一个 GUI 窗口，可能正好压在左上角那 128x96 上。
    //   那样 `getpixel_nonblack`（只采那一小块）会变成 0，看起来像"GetPixel 也被
    //   替换了"，其实是"那块被引擎窗口盖住了"。全屏采样能把这层区分开。
    //
    // ★ 步长**自适应**：把调用次数压在预算内（见 kGetPixelBudget）。
    //   本机 1920×1080 下 step=64 会有 510 次 ≈ 8.5s；自适应后取 256 ⇒ 40 次。
    int gpFullNonBlack = 0;
    int gpFullTotal = 0;
    {
        const int sw = GetSystemMetrics(SM_CXSCREEN);
        const int sh = GetSystemMetrics(SM_CYSCREEN);
        int step = 64;
        // 每放大一倍，调用数降到约 1/4；循环一定终止（step 会超过屏幕尺寸）。
        while (step < 4096 && ((sw / step) + 1) * ((sh / step) + 1) > kGetPixelBudget) {
            step *= 2;
        }
        for (int y = 0; y < sh; y += step) {
            for (int x = 0; x < sw; x += step) {
                ++gpFullTotal;
                const COLORREF c = GetPixel(screen, x, y);
                if (c != CLR_INVALID && (c & 0x00FFFFFFu) != 0) {
                    ++gpFullNonBlack;
                }
            }
        }
    }

    // ================================================================
    // ③ 剪贴板：放已知文本 -> 读回（ClipboardGuard 已挂 GetClipboardData）
    // ================================================================
    const bool clipPut = PutClipboardSecret();
    ClipOutcome clip = { false, 0, 0, false };
    if (clipPut) {
        clip = ReadClipboardSecret();
    }

    // ================================================================
    // ④ 注册表：读预先存在的值（RegistryGuard 已挂 NtQueryValueKey）
    // ================================================================
    const RegOutcome reg = ReadRegistrySecret();

    // ================================================================
    // ⑤ 文件：读预先存在的文件（FileGuard v133 已挂 NtCreateFile + NtReadFile）
    //    ★ 放在**最后**：文件面是四面里唯一"open 与 read 分离"的，
    //      前面那些路径若因为别的原因出错，不应该连带把它的时序搅乱。
    // ================================================================
    const FileOutcome file = ReadFileSecret(filePath);

    // ---- 一行机器可解析的结果 ----
    printf("RESULT bitblt=%d err=%lu lines=%d first=0x%08lX nonblack=%d/%d "
           "getpixel0=0x%08lX getpixelmid=0x%08lX getpixel_nonblack=%d "
           "getpixel_full_nonblack=%d/%d "
           "clip_put=%d clip_read=%d clip_err=%lu clip_strlen=%llu clip_match=%d "
           "reg_read=%d reg_err=%lu reg_strlen=%llu reg_match=%d "
           "file_open=%d file_oerr=%lu file_read=%d file_rerr=%lu "
           "file_bytes=%lu file_strlen=%llu file_match=%d\n",
        bitbltOk ? 1 : 0,
        static_cast<unsigned long>(bitbltErr),
        lines,
        static_cast<unsigned long>(first),
        nonBlack, kSampleW * kSampleH,
        static_cast<unsigned long>(gp0),
        static_cast<unsigned long>(gpMid),
        gpNonBlack,
        gpFullNonBlack, gpFullTotal,
        clipPut ? 1 : 0,
        clip.read ? 1 : 0,
        static_cast<unsigned long>(clip.err),
        static_cast<unsigned long long>(clip.strlen),
        clip.match ? 1 : 0,
        reg.read ? 1 : 0,
        static_cast<unsigned long>(reg.err),
        static_cast<unsigned long long>(reg.strlen),
        reg.match ? 1 : 0,
        file.openOk ? 1 : 0,
        static_cast<unsigned long>(file.openErr),
        file.read ? 1 : 0,
        static_cast<unsigned long>(file.err),
        static_cast<unsigned long>(file.bytes),
        static_cast<unsigned long long>(file.strlen),
        file.match ? 1 : 0);

    // ---- 收尾 ----
    if (px) {
        free(px);
    }
    SelectObject(memDc, oldBmp);
    DeleteObject(memBmp);
    DeleteDC(memDc);
    ReleaseDC(nullptr, screen);

    return 0;
}
