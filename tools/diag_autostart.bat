@echo off
setlocal enabledelayedexpansion
chcp 936 >nul 2>&1
title R3 ShieldCore 开机自启诊断（只读）

rem ======================================================================
rem  ★★ "窗口一闪就过" 的兜底（双击场景必须做）★★
rem ----------------------------------------------------------------------
rem  双击 .bat 时，cmd 会为它开一个窗口；**脚本一结束窗口就关**，
rem  用户一个字都看不到。更糟的是：如果脚本在**很前面**就异常退出
rem  （比如 :cnt 标签被删、语法错、被安全软件拦），连末尾那个 pause
rem  都到不了 —— 用户只看到一闪。
rem
rem  解决办法：所有出口统一走 `call :__maybe_pause`（见文件末尾），
rem  这样无论中途从哪儿 exit /b，都会先停住。
rem
rem  ★ 自动化会不会被挂死？**不会** —— 实测（本机 2026-10-06）：
rem    `pause` 在**没有真控制台输入**时（stdin 是管道/DEVNULL/
rem    被 `> out.txt` 重定向）会**立刻返回** rc=0，不会阻塞。
rem    它只在一个"真人坐在真控制台前"时才会等键 —— 而那正是双击场景。
rem    （所以不需要去探测 %cmdcmdline% 有没有重定向，那样反而更脆。）
rem
rem  ★ 但仍然提供 --no-pause / -n：给那些"不想要那一行提示"的自动化用。
rem ======================================================================

rem ★ 解析参数：  --no-pause / -n  => 跑完不停
set "NOPAUSE="
if /i "%~1"=="--no-pause" set "NOPAUSE=1" & set "ARG_DIR="
if /i "%~1"=="-n"         set "NOPAUSE=1" & set "ARG_DIR="
if /i "%~2"=="--no-pause" set "NOPAUSE=1"
if /i "%~2"=="-n"         set "NOPAUSE=1"

rem ======================================================================
rem  diag_autostart.bat —— 「开机自启没生效」的只读排查器（纯 cmd 版）
rem ----------------------------------------------------------------------
rem  和 tools/diag_autostart.py 是同一套判据，给没装 Python 的机器用。
rem
rem  用法：
rem      diag_autostart.bat                     安装目录从注册表/默认路径推导
rem      diag_autostart.bat "D:\R3 ShieldCore"  手工指定安装目录
rem
rem  设计原则：
rem    1) 只读：不装、不删、不改、不启动任何东西。
rem    2) 按三层链顺序查，最后只报「第一个断掉的环节」（按优先级，不按发现顺序）。
rem    3) 只用系统自带工具。默认 mode=log 下 reg/net 这类只会被记录，
rem       不会拦也不会弹窗；tasklist.exe 本身还在 System32 豁免表里
rem       （r3shieldcore_rules.cpp 的 kCommonTrustedSystemConsoleTools）。
rem    4) 服务日志是 UTF-8（带 BOM），GBK 的 findstr **匹配不了里面的中文**。
rem       所以本脚本只 findstr **ASCII 锚点**（[PRIV] / [TOKEN] / [LAUNCH] /
rem       err= / upgrade= / fallback=），再把这些行原样打出来让 Windows 自己
rem       去渲染 UTF-8 —— 这样"哪条特权没开、令牌提没提权、拉起报什么错"
rem       全都看得见，不用你去翻整份日志。
rem       （服务端配合：r3shieldcore_svc.c 里这些锚点**故意放在行首**。）
rem    5) chcp 65001 之下的 findstr 对含中文的 UTF-8 行**匹配会不准**，
rem       所以所有计数都在 936 码页下先做完（纯 ASCII 模式，可靠）。
rem
rem  ★★ 本脚本最重要的一条工程约束（血泪；归因已用原生探针修正）★★
rem --------------------------------------------------------------------
rem   症状：本脚本在真机上"什么都读不出来" —— 每个 for /f 都报
rem         `'...' 不是内部或外部命令` 或 `系统找不到指定的路径`，
rem         所有计数恒 0，最后**错误地**下结论"开机自启根本没注册"。
rem
rem   ★ 归因修正（重要）：一开始我以为是 `2^>nul` 的 `^` 被剥掉。
rem     后来写了原生探针 tools/forfprobe.cpp（不拿 cmd 测 cmd），六组对照：
rem         A  tasklist ... 2^>nul                    -> 正常
rem         B  "C:\...\tasklist.exe" ... 2^>nul       -> **失效**
rem         C  "C:\...\tasklist.exe" ...              -> **失效**（没重定向也失效！）
rem         D  C:\...\tasklist.exe ... 2^>nul         -> 正常
rem         E  "C:\...\reg.exe" query ... ^| findstr  -> **失效**
rem         F  C:\...\reg.exe query ... ^| findstr    -> 正常
rem     B/C 的对照是铁证：**真判据是「子命令第一个非空白字符是不是双引号」**，
rem     与有没有 `2^>nul` **无关**；去掉重定向并不能救它。
rem     （`2^>nul` 在 for /f 里其实完全正常 —— A/D 都成功。）
rem
rem   所以本脚本的硬约束是：**for /f 子命令的第一个字符必须是命令本身**，
rem   绝不能是 `"`。本脚本所有子命令都满足（都从 reg/type/find/findstr/
rem   tasklist 这些裸命令名或 `"%VAR%"` 里的字母开头）。
rem
rem   附带实践（无害，照旧保留）：子命令里**不写任何重定向**，需要静默时在
rem   **调用点**写 `call :x 2>nul`。理由：
rem     · 本脚本有些子命令是 `"%SystemRoot%\...\tasklist.exe" ...` 这种，
rem       路径带引号，一旦写错位置更容易踩上面那条坑；
rem     · 统一在调用点静音，子命令里一眼能看出"跑的是什么"。
rem   `for /f` **不会**吞掉子命令的 stderr —— 不静默的话，`reg query`
rem   查不存在的键会把「错误: 系统找不到指定的注册表项」打在屏幕上污染输出。
rem   所以凡是"允许失败"的查询一律走 `call :x 2>nul`。
rem
rem   ★ 更强的替代品：如果这台机器上连本脚本都跑不出东西，改用
rem     tools\diag_autostart.exe（原生 C++ 版，**一次都不 shell out**，
rem     不可能出现"计数恒 0 / (查不出)"）。源码 tools/diag_autostart.cpp。
rem
rem  三层链：
rem      驱动 r3shieldcore_kernel.sys   BOOT_START   只加载，不拉进程
rem      服务 R3ShieldCoreGuard         AUTO_START   把引擎拉进交互会话
rem      引擎 R3 ShieldCore.exe        用户会话      真正干活
rem  任何一层断了，用户看到的现象都是同一句「没有开机自启」。
rem ======================================================================

set "SVC_NAME=R3ShieldCoreGuard"
set "SVC_EXE=r3shieldcore_svc.exe"
set "DRV_SVC=R3ShieldCoreKernel"
set "DRV_SYS=r3shieldcore_kernel.sys"
set "ENGINE_EXE=R3 ShieldCore.exe"
set "SVC_LOG=r3shieldcore-svc.log"
set "SVCKEY=HKLM\SYSTEM\CurrentControlSet\Services\%SVC_NAME%"
set "DRVKEY=HKLM\SYSTEM\CurrentControlSet\Services\%DRV_SVC%"
set "UNKEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\R3ShieldCore"
set "DEFAULT_DIR=C:\Program Files\R3 ShieldCore"

set "ARG_DIR=%~1"
set "FIRST="
set "DEST="
set "DEST_SRC="
set "DIR_OK=0"
set "F_ENG=0"
set "F_SVC=0"
set "F_DRV=0"
set "F_LOG=0"
set "SVCKEY_OK=0"
set "LAST_CODE="
set "LAST_ERR="
set "LAST_SESS="
set "LOG_PRIV=0"
set "LOG_PRIVFAIL=0"
set "LOG_TOKEN=0"
set "LOG_NOELEV=0"
set "LOG_NOELEVYES=0"
set "LOG_UPFAIL=0"
set "LOG_FBOK=0"
set "LOG_ASFAIL=0"
set "LOG_LFAIL=0"
set "LOG_LOK=0"
set "LOG_LASTN=0"
set "LOG_READ=0"
set "LOG_LINES="
set "LOG_ITER="
set "LF_BAD=0"
set "LOGSZ="
set "CNT_BAD=0"
set "SVC_START="
set "SVC_IMG="
set "SVC_TARGET_OK=0"
set "DRVKEY_OK=0"
set "DRV_START="
set "DRV_IMG="
set "DRV_STAMP="
set "ENG_N=0"
set "ENG_PIDS="
set "ENG_READ=0"
set "NOREB="
set "SYS_MAN=(查不出)"
set "SYS_PROD=(查不出)"
set "SAFE="
set "SAFE_READ=0"
set "BOOT_D="
set "BOOT_TXT=(查不出)"
set "FORF_OK=0"
set "FORF_WHY="

echo ======================================================================
echo  R3 ShieldCore 开机自启诊断（只读：不装不删不改不启动）
echo ======================================================================

rem ---------------- -1. 自检：本脚本在这台机器上能不能读到东西 ----------------
rem  ★ 这一步是整个脚本的**前提**。没有它，一旦 for /f 坏掉（见文件头注释），
rem    脚本会照常打印一堆"查不出"和 0，最后给出一个**完全错误的结论** ——
rem    这正是"假阴性比漏报更贵"的形态（铁律 137：自测全绿 != 功能存在）。
rem  做法：拿一个**必定存在**的目标（本脚本自己所在目录下的自身文件）做一次
rem    for /f 计数。数不到 1 说明这台机器上 for /f 读不到东西，立刻停手。
call :selftest_forf
if "!FORF_OK!"=="0" (
    echo.
    echo   [ 致命 ] 本脚本在这台机器上**读不出任何东西**，下面的结论全部不可信。
    echo            原因：!FORF_WHY!
    echo.
    echo            这通常不是自启的问题，是**脚本自身**在这台机器上跑不了
    echo            （cmd 版本/代码页/组策略/被安全软件拦了 for /f 子命令）。
    echo.
    echo            请改用原生版的诊断器（不用 Python、不 shell out）：
    echo                tools\diag_autostart.exe
    echo            报错信息请连这一整段一起贴出来。
    echo ======================================================================
    call :__maybe_pause
    exit /b 90
)
echo   [ OK ] 自检：本脚本在本机能正常读取系统信息（for /f 可用）。

rem ---------------- 0. 环境 ----------------
echo.
echo === 0. 环境 ===
set "SYS_MAN=(查不出)"
call :q_bios SystemManufacturer SYS_MAN 2>nul
set "SYS_PROD=(查不出)"
call :q_bios SystemProductName SYS_PROD 2>nul
echo   [信息] 机型          : !SYS_MAN! / !SYS_PROD!
echo   [信息] 说明          : 机型里出现 VMware/VirtualBox/QEMU/Hyper-V 等字样即为虚拟机

rem 本次开机时间：net statistics workstation 最快（约 0.5s），且不依赖 wmic
rem （Win11 起 wmic 已被移除）。日期格式随语言，用含 "/" 的 token 定位。
set "T2="
set "T3="
call :q_boottime 2>nul
if defined T2 (
    set "BY=" & set "BM=" & set "BD="
    for /f "tokens=1,2,3 delims=/" %%x in ("!T2!") do (
        set "BY=%%x"
        set "BM=%%y"
        set "BD=%%z"
    )
    if !BM! LSS 10 set "BM=0!BM!"
    if !BD! LSS 10 set "BD=0!BD!"
    set "BOOT_D=!BY!!BM!!BD!"
    set "BOOT_TXT=!T2! !T3!"
)
echo   [信息] 本次开机于    : !BOOT_TXT!

rem 安全模式（注册表口径；正常启动时这个键一般不存在）
call :q_safeboot 2>nul
if defined SAFE (
    echo   [注意] 安全模式      : 是（OptionValue=!SAFE!）
    echo           ★ 安全模式下按设计**不启动**引擎（驱动仍会加载）。这不是故障。
) else if "!SAFE_READ!"=="0" (
    echo   [注意] 安全模式      : **读不出**（注册表键不可读）—— 这一项不参与结论
) else (
    echo   [信息] 安全模式      : 否（正常启动）
)

rem ---------------- 1. 安装目录与文件 ----------------
echo.
echo === 1. 安装目录与文件 ===
if defined ARG_DIR (
    set "DEST=!ARG_DIR!"
    set "DEST_SRC=命令行参数"
) else (
    set "DEST="
    call :q_uninst_installloc 2>nul
    if defined DEST (
        set "DEST_SRC=注册表 InstallLocation"
    ) else (
        set "DEST=%DEFAULT_DIR%"
        set "DEST_SRC=默认路径（卸载项里没有 InstallLocation）"
    )
)
echo   [信息] 安装目录      : !DEST!   （来源：!DEST_SRC!）

set "INST_RAW="
if exist "!DEST!\" (
    set "DIR_OK=1"
    echo   [ OK ] 目录存在
    for %%A in ("!DEST!") do set "INST_RAW=%%~tA"
    echo   [信息] 目录时间戳    : !INST_RAW!
) else (
    echo   [ 断 ] 目录**不存在**
)

if "!DIR_OK!"=="1" (
    call :chkfile "引擎" "!DEST!\%ENGINE_EXE%" 1 F_ENG
    call :chkfile "服务" "!DEST!\%SVC_EXE%" 1 F_SVC
    call :chkfile "驱动" "!DEST!\driver\%DRV_SYS%" 1 F_DRV
    call :chkfile "日志" "!DEST!\%SVC_LOG%" 0 F_LOG
)

rem 关键文件不齐 → 把目录真实内容列出来（否则只能靠猜）
set "ALLF=!F_ENG!!F_SVC!!F_DRV!"
if "!DIR_OK!"=="1" if not "!ALLF!"=="111" (
    echo.
    echo   ---- 目录实际内容（dir /a "!DEST!"）----
    dir /a "!DEST!"
    if exist "!DEST!\driver\" (
        echo.
        echo   ---- driver 子目录 ----
        dir /a "!DEST!\driver\"
    )
    echo.
    echo   ★ 已知失败模式：本引擎是"用户态 AV + 注入器"，**Windows Defender
    echo      很可能直接把主程序当恶意软件隔离掉**（installer 侧踩过同族的坑）。
    echo      去看「Windows 安全中心 - 病毒和威胁防护 - 保护历史记录」有没有它。
)

rem ★ VM 专项：安装之后到底重启过没有（按日期粗判；精确到分秒请自己看时间戳）
if "!DIR_OK!"=="1" if defined BOOT_D if defined INST_RAW (
    set "IDATE=!INST_RAW:~0,10!"
    set "IDATE=!IDATE:/=!"
    set "IDATE=!IDATE:-=!"
    if !BOOT_D! LSS !IDATE! (
        echo.
        echo   [ 断 ] ★ 安装之后**还没有真正重启过**
        echo           目录时间 !INST_RAW! ，而系统是 !BOOT_TXT! 启动的。
        echo           开机自启**只能靠「重启后」证明**。
        echo           ★★ VM 专项：虚拟机上的重启必须是**真正的关机再开机**。
        echo              「挂起 / 保存状态后恢复」**不算重启** —— 内核状态原样恢复，
        echo              服务的 AUTO_START 不会再触发、驱动的 BOOT_START 也不会重跑；
        echo              「快照回滚」更糟 —— 它把服务注册和文件一起回滚掉。
        set "NOREB=1"
    )
)

rem ---------------- 2. 驱动层 ----------------
echo.
echo === 2. 驱动层（BOOT_START，只负责被加载）===
reg query "%DRVKEY%" >nul 2>&1
if errorlevel 1 (
    echo   [注意] 服务键 %DRV_SVC% **不存在**（驱动没注册）
    echo          -^> 只是「没有内核组件」。三层是独立的，**不影响用户态引擎的自启**。
) else (
    set "DRVKEY_OK=1"
    echo   [ OK ] 服务键存在
    set "DRV_START="
    call :q_reg "%DRVKEY%" Start DRV_START 2>nul
    echo   [信息] Start          : !DRV_START!   （期望 0x0 = Boot）
    set "DRV_IMG="
    call :q_reg "%DRVKEY%" ImagePath DRV_IMG 2>nul
    echo   [信息] ImagePath      : !DRV_IMG!
    if exist "%SystemRoot%\System32\drivers\%DRV_SYS%" (
        echo   [ OK ] 驱动文件       : 存在  %SystemRoot%\System32\drivers\%DRV_SYS%
    ) else (
        echo   [ 断 ] 驱动文件       : **不存在**  %SystemRoot%\System32\drivers\%DRV_SYS%
    )
    set "DRV_STAMP="
    call :q_reg "%DRVKEY%" LoadSinceBootMs DRV_STAMP 2>nul
    if defined DRV_STAMP (
        echo   [信息] LoadSinceBootMs: !DRV_STAMP!
        echo           ^(0 对 BOOT_START 是**正常且最好**的结果；很小 -^> 确实是开机时加载的；
        echo            较大 -^> 更像手动 sc start 起来的，不是开机自启^)
    ) else (
        echo   [注意] LoadSinceBootMs: 没有这个值（驱动可能还没被加载过）
    )
)

rem ---------------- 3. 服务层（关键） ----------------
echo.
echo === 3. 服务层（AUTO_START，负责把引擎拉进交互会话）===
reg query "%SVCKEY%" >nul 2>&1
if errorlevel 1 (
    echo   [ 断 ] 服务键 %SVC_NAME% **不存在** —— 开机自启根本没注册
    echo          可能原因：装的时候「开机自动启动引擎」那格没勾 / 注册那步失败 /
    echo                    服务被 sc delete 了 / **VM 上回滚了快照**。
) else (
    set "SVCKEY_OK=1"
    echo   [ OK ] 服务键存在
    set "SVC_START="
    call :q_reg "%SVCKEY%" Start SVC_START 2>nul
    echo   [信息] Start          : !SVC_START!   （期望 0x2 = Auto）
    set "SVC_IMG="
    call :q_reg "%SVCKEY%" ImagePath SVC_IMG 2>nul
    echo   [信息] ImagePath      : !SVC_IMG!
    if defined SVC_IMG (
        if exist "!SVC_IMG!" (
            set "SVC_TARGET_OK=1"
            echo   [ OK ] 指向的服务 exe : 存在
        ) else (
            echo   [ 断 ] 指向的服务 exe : **不存在** —— !SVC_IMG!
        )
    ) else (
        echo   [ 断 ] 指向的服务 exe : **读不出 ImagePath**（服务键里没有这个值？）
    )
)

rem 日志**不挂在服务键分支下** —— 日志存在本身就说明服务跑过，
rem 哪怕服务键后来被删了（快照回滚），日志也是唯一的第一诊断口径。
echo.
if "!F_LOG!"=="0" (
    echo   [ 断 ] 服务日志**不存在**：!DEST!\%SVC_LOG%
    echo          -^> 服务**从来没被启动过**（服务一起来第一件事就是写日志）。
) else (
    rem ---- 全部用 ASCII 锚点统计。在 936 码页下做，纯 ASCII 模式最可靠。----
    rem ★ 判据说明（这些锚点在 r3shieldcore_svc.c 里是**行首**写的）：
    rem     [PRIV] ... FAIL          某个特权没打开 -^> WTSQueryUserToken / CreateProcess 必失败
    rem     [TOKEN] elevated=no      拿到的令牌没提权
    rem     [TOKEN] upgrade=FAIL     关联令牌升级失败（只能退保底路）
    rem     [TOKEN] fallback=OK      退了保底路
    rem     [LAUNCH] asuser=FAIL     第一步 CreateProcessAsUser 失败
    rem     [LAUNCH] FAIL err=N      最终失败，N = 真正的 err
    rem     [LAUNCH] OK             成功
    rem
    rem  ★★ 每个计数都走 `call :cnt <短键> <变量> 2>nul`：
    rem     子过程里的 findstr **不带任何重定向**，stderr 在**调用点**咽掉。
    rem     这是本文件头说的那条工程约束，别再改回去。
    call :cnt prv          LOG_PRIV      2>nul
    rem ★ 特权失败行："[PRIV] SeXxx<对齐空格>FAIL   （说明）"。
    rem   锚点收窄过程（都实测过，日志形状：失败行 `FAIL   （`，成功行 `OK   （`）：
    rem     "FAIL "  (1 空格) -^> 7  ? 把 `[LAUNCH] FAIL err=` 和
    rem                              "失败 err=1314 ... FAIL。" 也数进来了
    rem     "FAIL  " (2 空格) -^> 4  ? 与特权 FAIL 行数逐行一致
    rem     "FAIL   "(3 空格) -^> 4  ? 同上，更保险
    rem   取 2 空格版本（与上面实测一致）。
    call :cnt prvfail      LOG_PRIVFAIL  2>nul
    call :cnt tok          LOG_TOKEN     2>nul
    call :cnt noelev       LOG_NOELEV    2>nul
    rem ★ `elevated=yes` = 令牌**已升级**成功（v1.2 之后正常情况下会出现）。
    rem   它和 noelev 一起用：只看 noelev 会在正常机器上报假根因（实测）。
    call :cnt elevyes      LOG_NOELEVYES 2>nul
    call :cnt upfail       LOG_UPFAIL    2>nul
    call :cnt fbok         LOG_FBOK      2>nul
    rem ★ 不能用 "] OK" / "] FAIL" —— "] OK" 是 "[PRIV] SeXxx  OK" 的子串，
    rem   实测误报 18 条。用紧贴锚点的 "LAUNCH] OK" / "LAUNCH] FAIL"。
    call :cnt lok          LOG_LOK       2>nul
    call :cnt lfail        LOG_LFAIL     2>nul
    call :cnt asfail       LOG_ASFAIL    2>nul
    call :cnt last         LOG_LASTN     2>nul

    rem ★ 读到了吗？[TOKEN] 行是服务**每次启动必写、且与被查内容无关**的记录，
    rem   用它当"这份日志确实被读到了"的前提（铁律 108：PASS 要带前提）。
    rem   注意：老版本服务的日志可能本来就没有 [TOKEN]，所以这里只在
    rem   "所有计数全 0 且 [LAST] 也 0" 时才判定为"读不出"。
    set "LOG_READ=1"
    rem  ★★ 必须用 `set /a` —— `set "X=!A!+!B!"` 只是拼出一个**字符串** "0+0+0"，
    rem    而 `if "0+0+0" EQU 0` 是**字符串比较**，恒为假 -> 整个"读不出"判定
    rem    永远不触发（实测：负对照红不了，等于这条保护不存在）。
    set /a CNT_ALLZERO=LOG_PRIV+LOG_TOKEN+LOG_LOK+LOG_LFAIL+LOG_LASTN
    if !CNT_ALLZERO! EQU 0 (
        rem 再确认一次：文件真的非空吗？
        for %%F in ("!DEST!\%SVC_LOG%") do set "LOGSZ=%%~zF"
        if !LOGSZ! GTR 0 (
            set "LOG_READ=0"
        ) else (
            set "LOG_READ=2"
        )
    )

    rem ★★★ 根因：服务端每次拉起尝试都会写**唯一一行** [LAST] <字母> err=N。
    rem     字母就是根因分类（服务端 r3shieldcore_svc.c 的 SetOutcome 注释）：
    rem       E = 令牌没提权（err=740，引擎清单要管理员）
    rem       P = 缺特权（err=1314，令牌里"有"特权不等于"能用"）
    rem       S = 拿不到可用令牌 / 令牌升级也失败
    rem       C = CreateProcess 失败（别的原因，看 err=）
    rem       X = 进程建出来了但**秒退**（引擎自己挂了，去看引擎日志）
    rem       O = 成功
    rem     一行定根因，不用本脚本自己拼判据（拼错就是"报了个假原因"）。
    rem ★ 解析 [LAST] 行时**绝不能按字段序号取** —— 日志每行开头是
    rem   "YYYY-MM-DD HH:MM:SS.mmm  "，"HH:MM:SS.mmm" 自己就被拆成多段，
    rem   字段序号完全对不上（实测把时间戳当成过 CODE，也把日期当成过 CODE）。
    rem   改用**最笨但确定**的办法：把整行按空格切成词，逐词比对前缀。
    set "LAST_CODE="
    set "LAST_ERR="
    set "LAST_SESS="
    call :q_last 2>nul

    echo   [信息] 服务日志锚点统计（下面「关键行」是逐字原文）：
    echo          · 拉起成功    [LAUNCH] OK    : !LOG_LOK!
    echo          · 拉起失败    [LAUNCH] FAIL  : !LOG_LFAIL!
    echo          · 令牌事实行  [TOKEN]        : !LOG_TOKEN!
    echo          · 令牌没提权  elevated=no    : !LOG_NOELEV!
    echo          · 令牌已提权  elevated=yes   : !LOG_NOELEVYES!
    echo          · 关联令牌升级失败             : !LOG_UPFAIL!
    echo          · 退到保底令牌                 : !LOG_FBOK!
    echo          · 特权没打开  [PRIV] FAIL    : !LOG_PRIVFAIL!
    echo          · 特权总行数  [PRIV]          : !LOG_PRIV!
    echo          · 拉起尝试行  [LAST]          : !LOG_LASTN!
    rem  ★★ 换行符自检（实测踩过的一个"静默少数"）：
    rem    `for /f` 只把 **CRLF** 当行分隔；日志里若有**裸 LF**，
    rem    连续几行会被**合并成一次迭代** -> findstr 明明命中 5 行，计数器只记 1~3。
    rem    服务的 Log() 写的是 CRLF（`L"...\r\n"`），所以正常不会发生；
    rem    但如果日志被某个工具重写过（转存/上传/编辑器"转成 LF"），就会。
    rem    判据：`for /f` 迭代数 必须 >= 物理行数（相等才对；少了就是合并了）。
    call :q_loglines 2>nul
    set "LF_BAD=0"
    if defined LOG_ITER if defined LOG_LINES (
        if !LOG_ITER! LSS !LOG_LINES! set "LF_BAD=1"
    )
    if "!LF_BAD!"=="1" (
        echo          · **换行符警告**：文件有 !LOG_LINES! 个换行，但 for /f 只迭代了
        echo            !LOG_ITER! 次 —— 日志里有**裸 LF**，多行被并成一次，
        echo            所以下面的计数**偏小、不可信**。根因判定已停用。
        echo            修法：把日志转成 CRLF（服务自己写的是 CRLF，别用编辑器转存）。
        rem ★ 把"读不出"这条保护**复用**到换行符异常上 —— 两者后果一样：
        rem   计数不可信 => 任何基于计数的根因都不许下。用同一个 LOG_READ 变量，
        rem   下游所有 `if "!LOG_READ!"=="1"` 的闸门自动生效（不用改多处）。
        set "LOG_READ=3"
    )
    rem ★ 自检：这些计数**必须**自洽，否则说明 :cnt 又坏了（宁可不报，不报错数）。
    rem   自洽条件（容易反推）：LOK + LFAIL == LASTN（每次拉起尝试恰好写一行 [LAST]）。
    call :cnt_selfcheck
    if !CNT_BAD! GTR 0 (
        echo          · **计数自检不过**：OK+FAIL = !LOG_LOK!+!LOG_LFAIL! 与 [LAST] 行数 !LOG_LASTN! 不等。
        echo            计数仅供参考，**根因以下面 [LAST] 那行为准**。
    ) else (
        echo          · 计数自检：OK（OK + FAIL = [LAST] 行数 = !LOG_LASTN!）
    )
    if "!LOG_READ!"=="0" (
        echo          · **日志读不出内容**：文件有 !LOGSZ! 字节，但一个 ASCII 锚点都没数到。
        echo            说明**这份日志不是本引擎的服务日志**，或权限不足读不到内容。
        echo            下面的根因判定**已停用**（不拿"没读到"当"没发生"）。
    )
    if defined LAST_CODE (
        rem  ★ 带上字段名 —— 光打 `O  0  1` 没人看得懂，也看不出解析有没有错位。
        echo          · 最后一次拉起结论 [LAST]      : 代码=!LAST_CODE!  err=!LAST_ERR!  session=!LAST_SESS!
    ) else if "!LOG_READ!"=="2" (
        echo          · 最后一次拉起结论 [LAST]      : 日志是**空文件**（0 字节）
    ) else if "!LOG_READ!"=="0" (
        echo          · 最后一次拉起结论 [LAST]      : **读不出**（见上）
    ) else if "!LOG_READ!"=="3" (
        echo          · 最后一次拉起结论 [LAST]      : **计数不可信**（换行符异常，见上）
    ) else (
        echo          · 最后一次拉起结论 [LAST]      : **没有这一行** ——
        echo            说明写这份日志的服务版本太老（v1.1 之前没有 [LAST]），
        echo            或者服务起来后**从没走到"拉起引擎"这一步**。
    )
    echo.

    rem ★★ 根因判定：先用服务端自己写的 [LAST] 一行定根因（最准），
    rem    再用锚点计数当兜底。**前提是日志真被读到了** —— 读不到就一条都不许下
    rem    （铁律 100：没看见 / 没规则 / 判据错，三种要分开）。
    if "!LOG_READ!"=="1" (
        if "!LAST_CODE!"=="E" call :first "**令牌没提权**（[LAST] E err=740）：服务用 UAC 过滤令牌去建 requireAdministrator 的引擎，内核直接拒。修法 = 取关联令牌升级（v1.2 已做），升级不了就退 SYSTEM 令牌"
        if "!LAST_CODE!"=="P" call :first "**缺特权**（[LAST] P err=1314）：令牌里\"有\"特权不等于\"能用\"（默认全关）。看上面 [PRIV] 哪几行是 FAIL —— 服务需要 SeTcb/SeAssignPrimaryToken/SeIncreaseQuota/SeImpersonate/SeDebug 全部打开"
        if "!LAST_CODE!"=="S" call :first "**拿不到可用令牌**（[LAST] S）：WTSQueryUserToken 失败、关联令牌升级也失败、连保底令牌都造不出来 —— 看 [TOKEN] 那几行"
        if "!LAST_CODE!"=="C" call :first "**CreateProcess 失败**（[LAST] C）：不是提权问题，看同一行的 err= 和上面的路径/文件检查"
        if "!LAST_CODE!"=="X" call :first "**引擎建出来了但秒退了**（[LAST] X）：服务这边没问题，去开引擎自己的 r3shieldcore-console.log 看它为什么退出"
        if !LOG_LFAIL! GTR 0 call :first "**服务拉起引擎失败了**（日志里有 [LAUNCH] FAIL）—— 下面「关键行」里的 err= 是真原因"
        if !LOG_UPFAIL! GTR 0 if !LOG_FBOK! EQU 0 call :first "关联令牌升级失败（upgrade=FAIL）且没退保底路 —— 见日志「关键行」"
        if !LOG_PRIVFAIL! GTR 0 if !LOG_LFAIL! EQU 0 if !LOG_LOK! EQU 0 call :first "服务的特权没打开（[PRIV] 有 FAIL）—— 令牌里**有**特权 != **能用**（默认全关），不打开则 WTSQueryUserToken / CreateProcess 必失败"
        rem  ★★ 这一条的判据必须是「**最后**拿到的令牌也还是没提权」。
        rem     `elevated=no` 是**中间态**、是正常的：服务拿到的本来就是一个
        rem     UAC 过滤令牌，升级成提权令牌之后才去 CreateProcess。
        rem     实测踩过：只看 `LOG_NOELEV>0` 就在一台**完全正常**的机器上报
        rem     "这条必失败" —— 因为日志里确实留着 old 的那行 elevated=no。
        rem     正确判据 = 有 elevated=no，且**没有** `elevated=yes`（升级成功），
        rem                 且没有 LAUNCH] OK（最后成功了）。
        if !LOG_NOELEV! GTR 0 if !LOG_NOELEVYES! EQU 0 if !LOG_LOK! EQU 0 call :first "服务**最后**仍是拿未提权的令牌去拉 requireAdministrator 引擎（引擎清单要求管理员）—— 这条必失败"
    )

    echo   ---- 关键行（只显示带 ASCII 锚点的行）----
    chcp 65001 >nul 2>&1
    findstr /c:"[PRIV]" "!DEST!\%SVC_LOG%" 2>nul
    findstr /c:"[TOKEN]" "!DEST!\%SVC_LOG%" 2>nul
    findstr /c:"[LAUNCH]" "!DEST!\%SVC_LOG%" 2>nul
    echo   ---- 关键行结束 ----
    chcp 936 >nul 2>&1
    echo.
    echo   ---- 服务日志全文（UTF-8；太长可 Ctrl+C 跳过）----
    chcp 65001 >nul 2>&1
    type "!DEST!\%SVC_LOG%" 2>nul
    chcp 936 >nul 2>&1
    echo   ---- 日志结束 ----
)

rem ---------------- 4. 引擎层 ----------------
echo.
echo === 4. 引擎层（真正干活的）===
set "ENG_N=0"
set "ENG_PIDS="
call :q_engine 2>nul
if "!ENG_READ!"=="0" (
    echo   [注意] 引擎进程      : **读不出**（tasklist 不可用）—— 这一项不参与结论
) else if !ENG_N! GTR 0 (
    echo   [ OK ] 引擎在跑：pid =!ENG_PIDS!
) else (
    echo   [注意] 引擎**没在跑**
)

rem ---------------- 5. 结论 ----------------
if "!DIR_OK!"=="0" call :first "安装目录不存在 —— 没装成功 / 已被卸载 / VM 上回滚了快照"
if "!DIR_OK!"=="1" (
    if "!F_ENG!"=="0" call :first "安装目录里缺 %ENGINE_EXE% —— 文件没装全（看上面的 dir /a 和 Defender 提示）"
    if "!F_SVC!"=="0" call :first "安装目录里缺 %SVC_EXE% —— 文件没装全"
    if "!F_DRV!"=="0" call :first "安装目录里缺 driver\%DRV_SYS% —— 文件没装全"
)
if "!SVCKEY_OK!"=="0" call :first "开机启动服务没注册 —— 重装一次并勾上「开机自动启动引擎」"
if "!SVCKEY_OK!"=="1" (
    if not "!SVC_START!"=="0x2" call :first "服务启动类型不是 AUTO_START（现在是 !SVC_START!）—— 开机不会自启"
    if "!SVC_TARGET_OK!"=="0" call :first "服务指向的 exe 不存在或读不出（binPath 写错 / 文件被删）"
)
if defined NOREB call :first "安装后还没真正重启过（或用了挂起/快照）—— 先真重启一次再看"
if "!F_LOG!"=="0" call :first "服务从未被拉起过（日志不存在）—— 服务注册了但没跑起来"
if "!ENG_READ!"=="1" if "!ENG_N!"=="0" (
    if "!LOG_READ!"=="1" (
        if !LOG_LFAIL! GTR 0 (
            call :first "服务**试图**拉起引擎但失败了（[LAUNCH] FAIL）—— 真原因看第 3 节「关键行」里的 err="
        ) else if !LOG_LOK! GTR 0 (
            call :first "服务日志写着**拉起成功**但引擎不在跑 —— 引擎拉起来后自己退了（看引擎自己的 console.log）"
        ) else if !LOG_PRIVFAIL! GTR 0 (
            call :first "服务的特权没打开（[PRIV] 有 FAIL）—— 令牌里**有**特权 != **能用**"
        ) else (
            call :first "引擎没在跑，且日志里没有拉起记录 —— 看第 3 节「关键行」"
        )
    ) else (
        call :first "引擎没在跑，但**服务日志读不出内容** —— 先解决"读不出"这件事，再谈自启（不拿没读到当没发生）"
    )
)
if !ENG_N! GTR 1 call :first "同时有多份引擎在跑（引擎没有单实例互斥体，会互相打架）"

echo.
echo ======================================================================
if defined FIRST (
    echo  第一个断掉的环节：
    echo    -^> !FIRST!
    echo.
    echo  修完再跑一次本诊断，看下一个断点在哪。
) else if "!ENG_READ!"=="0" (
    echo  **本诊断读不完整**（引擎进程数读不出）—— 不能断言"三层全通"。
) else (
    echo  三层链**全通**：服务已注册且指向正确、引擎正在跑。
)
echo ======================================================================
echo.
echo  排查顺序永远是这条链：驱动（被加载）-^> 服务（被 SCM 拉起）-^> 引擎（被服务拉起）
echo  三层任何一层断了，用户看到的现象都是同一句「没有开机自启」。
echo.
call :__maybe_pause
exit /b 0

rem ----------------------------------------------------------------------
rem  ★ 统一的"停住窗口"出口（"一闪就过"的解决）
rem  · 双击 / 交互式跑        -> 停住（pause 真的会等键）
rem  · 管道 / 重定向 / 无 tty -> pause **立即返回**，不会挂死（实测）
rem  · --no-pause / -n       -> 连那行提示都不打，直接走
rem  所以这里不需要任何"探测"，`pause` 本身在两种场景下都安全。
rem ----------------------------------------------------------------------
:__maybe_pause
if defined NOPAUSE exit /b 0
echo.
echo  按「回车」或「任意键」关闭本窗口 ...（不想停：加参数 --no-pause）
pause
exit /b 0

rem ----------------------------------------------------------------------
rem  子过程
rem ----------------------------------------------------------------------
rem  ★★ 本文件所有"会失败的系统查询"都做成子过程，调用点写 `call :x 2>nul`。
rem     原因见文件头：`for /f ... ('cmd 2^>nul')` 在 for /f 里会坏掉，
rem     而 `call :x 2>nul` 是唯一能把子过程 stderr 一起咽掉的干净写法。
rem  ★ 全部子过程必须以 `exit /b 0` 结尾 —— 否则会 fall through 到下一个
rem     子过程（铁律 123 形态）。
rem ----------------------------------------------------------------------

:selftest_forf
rem  ★ 前提自检：拿"本脚本自己"当目标做一次 for /f 计数。
rem    数不到 1 就说明这台机器上 for /f 读不到东西 —— 后面的全是噪音。
set "FORF_OK=0"
set "FORF_WHY="
set "SELF=%~f0"
set "SELFTEST_N=0"
for /f "delims=" %%L in ('findstr /c:"@echo off" "!SELF!"') do set /a SELFTEST_N+=1
if !SELFTEST_N! GTR 0 (
    set "FORF_OK=1"
    exit /b 0
)
rem 再试一次：只数行数（不依赖 findstr，看 for /f 本身活不活）
set "SELFTEST_N=0"
for /f "delims=" %%L in ('type "!SELF!"') do set /a SELFTEST_N+=1
if !SELFTEST_N! GTR 0 (
    set "FORF_WHY=for /f 能跑，但 findstr 数不到东西（findstr 被拦或路径含特殊字符）"
    exit /b 0
)
set "FORF_WHY=连 for /f ... ('type ...') 都拿不到输出（cmd 的 for /f 子命令整条不工作）"
exit /b 0

:q_bios
rem  %1=值名  %2=结果变量名（默认 (查不出)，读到才覆盖）
set "Q_TMP="
for /f "tokens=2,*" %%a in ('reg query "HKLM\HARDWARE\DESCRIPTION\System\BIOS" /v %~1 ^| findstr /i /c:"%~1"') do set "Q_TMP=%%~b"
if defined Q_TMP set "%~2=!Q_TMP!"
exit /b 0

:q_boottime
rem  结果写进 T2 / T3（调用者的变量）
set "T2="
set "T3="
for /f "tokens=2,3" %%a in ('net statistics workstation ^| findstr /r /c:"[0-9][0-9]*/[0-9][0-9]*/[0-9][0-9]*"') do (
    set "T2=%%a"
    set "T3=%%b"
)
if defined T2 if "!T2!"=="!T2:/=!" set "T2="
exit /b 0

:q_safeboot
set "SAFE="
set "SAFE_READ=0"
for /f "tokens=2,*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" /v OptionValue ^| findstr /i /c:"OptionValue"') do (
    set "SAFE=%%~b"
    set "SAFE_READ=1"
)
rem  证明"键确实不存在"而不是"reg 坏了"：拿一个一定存在的键做对照。
if not defined SAFE (
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v SystemRoot >nul 2>&1
    if not errorlevel 1 set "SAFE_READ=1"
)
exit /b 0

:q_uninst_installloc
set "DEST="
for /f "tokens=2,*" %%a in ('reg query "%UNKEY%" /v InstallLocation ^| findstr /i /c:"InstallLocation"') do set "DEST=%%~b"
exit /b 0

:q_reg
rem  %1=键  %2=值名  %3=结果变量名
set "Q_TMP="
for /f "tokens=2,*" %%a in ('reg query "%~1" /v %~2 ^| findstr /i /c:"%~2"') do set "Q_TMP=%%~b"
if defined Q_TMP set "%~3=!Q_TMP!"
exit /b 0

:q_loglines
rem  返回两个数，用来判断换行符是否正常：
rem    LOG_LINES  = 文件物理行数（`find /c /v ""` 数的是 **LF** 的个数）
rem    LOG_ITER   = `for /f` 实际迭代了几次（用 `type` 喂进去）
rem  ★★ 为什么要两个数（实测踩过）：
rem    `for /f` 只把 **CRLF** 当行分隔，裸 LF 会被**并进上一行**。
rem    所以日志里如果有裸 LF（被转存工具/编辑器"转成 LF"过），
rem    `for /f` 看到的行数会 **少于** 物理行数 —— 于是所有锚点计数**偏小**，
rem    而且是**静默**偏小（外面看只是个比较小的数字，不像错误）。
rem    判据：LOG_ITER < LOG_LINES  =>  换行符不是全 CRLF，计数不可信。
rem  ★ 中文版 `find /c /v ""` 的输出形如：
rem      ---------- D:\...\R3SHIELDCORE-SVC.LOG: 12
rem    所以取**最后一个** token。措辞变了（非数字）就作废，宁可不用。
set "LOG_LINES="
for /f "tokens=*" %%L in ('find /c /v "" "!DEST!\%SVC_LOG%"') do (
    for %%W in (%%L) do set "LOG_LINES=%%W"
)
set "LL_CHK=!LOG_LINES!"
for /f "delims=0123456789" %%X in ("!LOG_LINES!") do set "LL_CHK="
if not defined LL_CHK set "LOG_LINES="

set "LOG_ITER="
set "LI_N=0"
for /f "delims=" %%L in ('type "!DEST!\%SVC_LOG%"') do set /a LI_N+=1
if !LI_N! GTR 0 set "LOG_ITER=!LI_N!"
exit /b 0

:q_last
rem  把每一行 [LAST] 日志拆成词，按**特征前缀**取值（多个 [LAST] 行时取最后一个）。
rem
rem  ★★ 两个实测出来的坑，都别踩 ★★
rem   坑 1：不能按字段序号取（tokens=2,3,4）。日志开头是
rem         "YYYY-MM-DD HH:MM:SS.mmm"，"23:14:28.589" 自己就是一个词，
rem         序号对不上 —— 实测把日期当成过 CODE，把时间当成过 CODE。
rem   坑 2：`for %%W in (...)` 的切分符**包含 `=`**（不只是空格）！
rem         所以 "err=1314" 会被切成两个词 "err" 和 "1314"。
rem         知道这一点之后就好办了：先记住刚看到 "err"，下一个词就是值。
set "LAST_CODE="
set "LAST_ERR="
set "LAST_SESS="
for /f "delims=" %%L in ('findstr /c:"[LAST] " "!DEST!\%SVC_LOG%"') do (
    set "LWORDS=%%L"
    call :parse_last
)
exit /b 0

:parse_last
rem  ★ 每行都从干净状态开始 —— 否则上一行的 LAST_CODE 会把这一行的覆盖掉。
set "LAST_CODE="
set "LAST_ERR="
set "LAST_SESS="
set "SAW_ANCHOR="
set "WANT="
for %%W in (!LWORDS!) do (
    if defined WANT (
        rem  ★ 必须**按 WANT 分派**，不能无条件写 LAST_ERR ——
        rem    实测踩过：写成 `if not defined LAST_ERR set LAST_ERR=%%W`
        rem    时，"session=1" 的 "1" 会被塞进 LAST_ERR（因为 LAST_ERR 还没值）。
        rem    症状：[LAST] O err=0 session=1 被解析成 `O <空> 1`。
        if /i "!WANT!"=="err"     set "LAST_ERR=%%W"
        if /i "!WANT!"=="session" set "LAST_SESS=%%W"
        set "WANT="
    ) else (
        if defined SAW_ANCHOR if not defined LAST_CODE set "LAST_CODE=%%W"
        if "%%W"=="[LAST]" set "SAW_ANCHOR=1"
        if /i "%%W"=="err"     set "WANT=err"
        if /i "%%W"=="session" set "WANT=session"
    )
)
exit /b 0

:q_engine
rem  按映像名找引擎进程。**必须 /nh /fo csv**：
rem  tasklist 默认表格输出会把映像名截断到 25 字符，带空格的名字会被截
rem  （铁律 41）。csv 模式不截断，并用 delims=, 取第 2 列 = pid。
rem  ★ 用 ENG_READ 区分"真没在跑"和"tasklist 读不出"（铁律 100）。
set "ENG_N=0"
set "ENG_PIDS="
set "ENG_READ=0"
for /f "tokens=2 delims=," %%P in ('tasklist /nh /fo csv /fi "imagename eq %ENGINE_EXE%" ^| findstr /i /c:"%ENGINE_EXE%"') do (
    set /a ENG_N+=1
    set "ENG_PIDS=!ENG_PIDS! %%~P"
)
rem  对照：tasklist 本身活不活？拿一个一定在跑的进程（cmd.exe 自己）试。
set "CTRL_N=0"
for /f "tokens=2 delims=," %%P in ('tasklist /nh /fo csv /fi "imagename eq cmd.exe" ^| findstr /i /c:"cmd.exe"') do set /a CTRL_N+=1
if !CTRL_N! GTR 0 set "ENG_READ=1"
exit /b 0

:chkfile
rem  %1=标签 %2=完整路径 %3=是否关键(1/0) %4=结果变量名（存在=1，不存在=0）
if exist "%~2" (
    echo   [ OK ] %~1 %~2
    set "%~4=1"
) else (
    if "%~3"=="1" (
        echo   [ 断 ] %~1 %~2   **不存在**
    ) else (
        echo   [注意] %~1 %~2   **不存在**
    )
    set "%~4=0"
)
exit /b 0

:first
rem  只在还没设置时写入 —— 于是「第一个」= 优先级最高的那个断点
if not defined FIRST set "FIRST=%~1"
exit /b 0

:cnt_selfcheck
rem  计数自洽性检查。CNT_BAD=0 表示 OK。
rem  ★ 存在的意义：:cnt 曾经静默返回 0（findstr 被拆词 / 管道失败），
rem    而"计数 0"和"真没发生"在输出上完全一样 —— 这类 bug 只有靠**交叉约束**
rem    才能暴露（这里用 "OK+FAIL 必须等于 [LAST] 行数" 这条恒等式）。
set "CNT_BAD=0"
set /a CNT_SUM=!LOG_LOK!+!LOG_LFAIL!
if not !CNT_SUM! EQU !LOG_LASTN! set "CNT_BAD=1"
rem  ★ 前提检查：只有真读到 [LAST] 行时这条恒等式才成立；
rem    [LAST] 行数为 0 且 OK+FAIL 也为 0 属于"日志里根本没有拉起段"，不算矛盾。
if !LOG_LASTN! EQU 0 if !CNT_SUM! EQU 0 set "CNT_BAD=0"
exit /b 0

:cnt
rem  %1=锚点短键（纯字母数字，**绝不含空格/点/等号/方括号**）  %2=结果变量名
rem  ★ 坑 1：不能写 `findstr ... | find /c /v ""` —— findstr 在 936 码页下遇到
rem    含中文的 UTF-8 行会直接失败（FINDSTR: 无法打开 ...），管道里就没了输入，
rem    于是计数**恒为 0** —— 正是"闸门恒绿"的那种假成功。
rem  ★ 坑 2（实测踩过）：锚点**绝不能经 %1 传进来**。
rem    `call :cnt "[PRIV]"  VAR` 在 :cnt 里 %1='"[PRIV]"' 还会带引号原样；
rem    而 `call :cnt "LAUNCH] OK" VAR` 这种带空格/方括号的锚点，cmd 会**再拆一次词**，
rem    结果 findstr 收到半个模式 -^> 报 "FINDSTR: 无法打开 OK" -^> 计数恒 0；
rem    更糟的是被拆剩下的片段（如 "OK"）会**误命中**其它行 -^> 计数虚高。
rem    实测症状：LAUNCH] OK 计数 2（真值 0）、LAUNCH] FAIL 计数 2（真值 1）。
rem    所以这里改掉：调用方只传**纯字母数字短键**，锚点字面量在本函数里 if/else 选。
rem  ★ 坑 3（真的踩过）：删/插标签时**别把 `:cnt` 这行本身吃掉**。
rem    实测症状：`系统找不到指定的批处理标签 - cnt`，所有计数恒 0，
rem    而"找不到标签"这句话是自解释的 —— 看到它就来看这里。
rem  ★ 坑 4（**本次的根因**）：子命令里**不能写任何重定向**。
rem    `for /f ... ('findstr /c:"!CNT_P!" "log" 2^>nul')` 里的 `2^>nul`
rem    会被 cmd 剥掉 ^ 之后当成 findstr 的**字面参数** -^>
rem    `FINDSTR: 无法打开 2>nul` -^> 计数恒 0（在一个不存在的文件上匹配）。
rem    现在改成：子命令里零重定向，stderr 由**调用点的 `call :cnt x V 2>nul`** 咽掉。
set "CNT_P="
if /i "%~1"=="prv"      set "CNT_P=[PRIV]"
if /i "%~1"=="prvfail"  set "CNT_P=FAIL  "
if /i "%~1"=="tok"      set "CNT_P=[TOKEN]"
if /i "%~1"=="noelev"   set "CNT_P=elevated=no"
if /i "%~1"=="elevyes"  set "CNT_P=elevated=yes"
if /i "%~1"=="upfail"   set "CNT_P=upgrade=FAIL"
if /i "%~1"=="fbok"     set "CNT_P=fallback=OK"
if /i "%~1"=="lok"      set "CNT_P=LAUNCH] OK"
if /i "%~1"=="lfail"    set "CNT_P=LAUNCH] FAIL"
if /i "%~1"=="asfail"   set "CNT_P=asuser=FAIL"
if /i "%~1"=="last"     set "CNT_P=[LAST]"
rem  ★ 未知短键必须**响亮地**失败，不能静默返回 0（假绿）。
if not defined CNT_P (
    echo   [内部错误] :cnt 收到未知锚点短键 "%~1" —— 计数不可信，请修脚本
    exit /b 9
)
rem  ★ 重点：把模式**先存进变量再 `!CNT_P!` 展开**，而不是直接写 `%~1`。
rem   变量展开发生在解析之后，所以 `findstr /c:"!CNT_P!"` 里的空格/方括号
rem    不会再被 cmd 当分隔符拆词 —— 这是"带空格锚点"唯一可靠的传法。
set "CNT_N=0"
set "CNT_ONE="
for /f "delims=" %%L in ('findstr /c:"!CNT_P!" "!DEST!\%SVC_LOG%"') do (
    set /a CNT_N+=1
    set "CNT_ONE=1"
)
rem  ★ 必须区分"命中 0 行"和"findstr 失败"：两者在外面看起来都是 0。
rem   只有真拿到过行（CNT_ONE 定义过）才写回计数。
rem   没拿到 -> 保持调用者预设的 0（并由 LOG_READ 那套前提检查兜住）。
if defined CNT_ONE set "%~2=!CNT_N!"
exit /b 0