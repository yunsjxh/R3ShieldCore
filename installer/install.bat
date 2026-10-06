@echo off
REM ============================================================
REM  R3 ShieldCore -- 安装程序（主脚本）
REM
REM  用法：
REM      R3ShieldCore-Setup.exe          （双击，正常安装）
REM      install.bat                     （在解压目录里直接跑）
REM      install.bat /nodriver           （只装用户态引擎，不装内核驱动）
REM      install.bat /dest=D:\R3SC       （自定义安装目录）
REM      install.bat /quiet              （静默，不 pause）
REM
REM  ★★★【签名策略：按用户要求"别管签名有没有用"】★★★
REM  本脚本**不做任何签名有效性预检**，也**不因签名失败而中止**。
REM     · 不调 signtool verify
REM     · 不检查驱动的 Authenticode 证书链
REM     · sc start 失败时只**报告**原因（含"签名不被信任"的提示），
REM       然后**继续**把用户态引擎装完 —— 因为用户态引擎不依赖驱动。
REM  ★ 为什么这样也合理：本机 testsigning 是关闭的、测试证书不在
REM    LocalMachine 的 Root/TrustedPublisher 里，所以自签驱动**本来就**
REM    加载不了。把它做成硬门槛只会让整个安装包装不上，而装不上的
REM    损失远大于"驱动没起来"。
REM  ★ 想真让驱动起来：见 driver/README.md（加信任 + 开 testsigning）。
REM
REM  ★★★【本文件必须 CRLF 行尾 + GBK 编码】★★★
REM  cmd.exe 按**字节**读批处理：文件里有非 ASCII 字符而行尾是 LF-only 时，
REM  解析器的行偏移会失同步，把上一行尾巴和下一行开头拼成一条命令。
REM  现象 = 窗口一闪而过。改完请跑：  python tools/bat_gbk_crlf.py install.bat
REM
REM  ★★★【产品名里有空格】★★★
REM  "R3 ShieldCore.exe" / "%ProgramFiles%\R3 ShieldCore" 里都有空格，
REM  每一处引用都必须加引号，否则会被 cmd 拆参（静默失效）。
REM  闸门：  python tools/check_spaced_name_quoted.py
REM ============================================================
setlocal enabledelayedexpansion
set "SELF=%~f0"
set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"

set "OPT_NODRIVER=0"
set "OPT_QUIET=0"
set "OPT_DRYRUN=0"
set "DEST=%ProgramFiles%\R3 ShieldCore"
set "ELEVATED=0"
set "STAGE=%TEMP%\R3ShieldCore-Setup-%RANDOM%%RANDOM%"

REM ★ 驱动服务名 / 驱动落点必须**在变量区就定义好**：
REM   dryrun 块在 [4/7] 之前就要 echo 它们；留到 [4/7] 再 set 的话，
REM   那两处 echo 出来的就是**空字符串**（括号块按解析时展开）——静默、难查。
set "DRV_SVC=R3ShieldCoreKernel"
REM   ★ 驱动**文件名**和服务名是两个不同的东西：
REM     服务名 R3ShieldCoreKernel（无下划线）/ 文件名 r3shieldcore_kernel.sys（有下划线）。
REM     写混了 → 驱动那步静默跳过，而日志只说"没找到"。
REM   ★ 再加一个**纯文件名**变量：sc create 的 binPath 要的是
REM     "System32\drivers\<文件名>"。早先这里错写成 %DRV_SVC%.sys（把服务名
REM     当文件名）-> 指向一个不存在的 .sys -> 驱动静默不加载（铁律 125）。
set "DRV_NAME=r3shieldcore_kernel.sys"
set "DRV_FILE=%SystemRoot%\System32\drivers\%DRV_NAME%"

for %%A in (%*) do (
    if /i "%%~A"=="/elevated"       set "ELEVATED=1"
    if /i "%%~A"=="/nodriver"       set "OPT_NODRIVER=1"
    if /i "%%~A"=="/quiet"          set "OPT_QUIET=1"
    if /i "%%~A"=="/nopause"        set "OPT_QUIET=1"
    if /i "%%~A"=="/dryrun"         set "OPT_DRYRUN=1"
)
for %%A in (%*) do (
    set "ARG=%%~A"
    if /i "!ARG:~0,6!"=="/dest=" set "DEST=!ARG:~6!"
)

REM ★ /dryrun 不修改系统，所以**不需要管理员权限** —— 提前跳过提权检查。
REM   否则每次验证安装包都要弹一次 UAC，验证成本高到没人愿意跑。
if "%OPT_DRYRUN%"=="1" goto :SKIP_ELEV

echo ============================================================
echo  R3 ShieldCore 安装程序
echo ============================================================
echo  安装目录 : %DEST%
echo  内核驱动 : 若 /nodriver 未指定则安装
echo  签名检查 : **不做**（按配置）
echo.

REM ------------------------------------------------------------
REM [1/7] 管理员权限
REM   ★ 判据 = whoami 的**完整性级别**（S-1-16-12288 = High）。
REM     不用 `net session` —— 它自己要 spawn net.exe。
REM   ★ whoami 走全路径：PATH 里可能有同名程序顶掉它。
REM ------------------------------------------------------------
set "IS_ADMIN=0"
"%SystemRoot%\System32\whoami.exe" /groups 2>nul | "%SystemRoot%\System32\findstr.exe" /c:"S-1-16-12288" /c:"S-1-16-16384" >nul
if not errorlevel 1 set "IS_ADMIN=1"

if "%IS_ADMIN%"=="0" (
    if "%ELEVATED%"=="1" (
        echo [错误] 需要管理员权限。请右键 -^> 以管理员身份运行。
        goto :FAIL
    )
    echo [1/7] 正在请求管理员权限...
    REM ★★★ 这里的 -Wait 不能省 ★★★
    REM   拉起这个进程的是 iexpress 的自解压器（wextract）。wextract 会在
    REM   "它拉起的那个 cmd 退出"之后**删掉整个解压目录** —— 而提权实例
    REM   正要读里面的 payload.zip。不等它 = 随机"解压失败"或"装到一半"。
    REM   （踩过：一次真实安装里驱动那步整段没执行，事后无法复现 —— 就是这个竞态。）
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath $env:SELF -ArgumentList '/elevated','/nodriver=%OPT_NODRIVER%','/quiet=%OPT_QUIET%','/dest=%DEST%' -Verb RunAs -Wait" >nul 2>&1
    if errorlevel 1 (
        echo [错误] 提权被取消或失败。
        echo        请改用：右键本文件 -^> 以管理员身份运行
        goto :FAIL
    )
    echo        已在新窗口继续，本窗口关闭。
    exit /b 0
)
echo [1/7] 管理员权限 OK

:SKIP_ELEV

REM ------------------------------------------------------------
REM [2/7] 解压 payload
REM   iexpress 的自解压包**不支持子目录**，而引擎要求
REM     <部署根>\64\r3shieldcore-lib.dll
REM     <部署根>\32\r3shieldcore-lib.dll
REM   这两个固定子目录。所以 payload 打成 zip 带进来，这里用
REM   Windows 自带的 tar.exe（bsdtar，Win10 1803+）解出来。
REM   ★ 这一步必须在**引擎启动之前** —— 引擎跑起来之后
REM     System32 下的程序会被它自己的进程规则拦掉。
REM ------------------------------------------------------------
echo [2/7] 解压安装文件...
if not exist "%HERE%\payload.zip" (
    echo [错误] 找不到 %HERE%\payload.zip
    echo        如果你是把 zip 解压后直接跑 install.bat，
    echo        请确认 install.bat 和 payload.zip 在同一目录。
    goto :FAIL
)
if exist "%STAGE%" rd /s /q "%STAGE%" >nul 2>&1
mkdir "%STAGE%" >nul 2>&1
"%SystemRoot%\System32\tar.exe" -xf "%HERE%\payload.zip" -C "%STAGE%" >nul 2>&1
if errorlevel 1 (
    echo [错误] 解压失败（tar.exe 返回 %errorlevel%）。
    goto :FAIL
)
if not exist "%STAGE%\R3 ShieldCore.exe" (
    echo [错误] 解压后没找到 "R3 ShieldCore.exe" —— payload 结构不对。
    goto :FAIL
)
echo        OK

REM ------------------------------------------------------------
REM [2.5/7] /dryrun —— 干跑一遍：只做到"解压成功"就停。
REM   ★ 为什么要有这个开关：安装包必须**可测试**。
REM     没有 dryrun 时，唯一能验证"payload 对不对、脚本解析对不对"的办法
REM     就是真的往系统里装一遍 —— 那既慢又危险，结果是**没人测**。
REM   ★ 它验证的东西恰好是最容易坏的那部分：
REM     自解压有没有正常落地、payload.zip 结构对不对、
REM     cmd 的批处理解析有没有因为中文/CRLF 出问题。
REM   ★ 它**不碰**系统：不复制文件、不建服务、不写注册表、不建快捷方式。
REM ------------------------------------------------------------
if "%OPT_DRYRUN%"=="1" goto :DRYRUN_BLOCK
goto :DRYRUN_DONE

REM ------------------------------------------------------------
REM  [DRYRUN] 干跑块
REM   ★ 这里用 goto/label 而不是 if(...) 括号块，原因很硬：
REM     括号块里的 %VAR% 是**解析整块时**一次性展开的，所以块内 set 的变量
REM     在块内用 %VAR% 根本取不到（经典陷阱）。label 块按行执行，没这问题。
REM   ★ 必须把证据落到 %TEMP% 下的报告文件：
REM     iexpress 起的控制台窗口在自动化里**抓不到输出**，
REM     不落盘就永远没法证明"这条链真的跑过"。
REM   ★ 报告要**逐项列出**关键前提（引擎 / 两个 DLL / 驱动 / ini），
REM     而不是只写一句 DRYRUN-OK —— 否则"解压出来是空的"也会报 OK。
REM ------------------------------------------------------------
:DRYRUN_BLOCK
echo.
echo ============================================================
echo  [DRYRUN] 干跑模式 —— 到此为止，不修改系统
echo ============================================================
echo  已确认：payload 解压成功，主程序在里面。
echo.
echo  接下来**会**做这些（现在都没做）：
echo    3^) 复制到 "%DEST%"（含 64\ 与 32\ 两个子目录）
echo    4^) 装内核驱动 %DRV_SVC%
echo         copy "%STAGE%\driver\r3shieldcore_kernel.sys" -^> %SystemRoot%\System32\drivers\
echo         sc create %DRV_SVC% ... start= auto  然后 sc start
echo         ★ 不做签名预检、不因签名失败中止
echo    5^) 建开始菜单 / 桌面快捷方式
echo    6^) 写卸载项 HKLM\...\Uninstall\R3ShieldCore
echo    7^) 清理临时目录
echo.

set "RPT=%TEMP%\R3ShieldCore-dryrun-report.txt"
> "%RPT%" (
    echo DRYRUN-OK
    echo STAGE=%STAGE%
    echo HERE=%HERE%
    echo DEST=%DEST%
    echo DRV_SVC=%DRV_SVC%
    echo ENGINE=%STAGE%\R3 ShieldCore.exe
    echo LIB64=%STAGE%\64\r3shieldcore-lib.dll
    echo LIB32=%STAGE%\32\r3shieldcore-lib.dll
    echo DRIVER=%STAGE%\driver\r3shieldcore_kernel.sys
    echo INI=%STAGE%\r3shieldcore.ini
    echo --- payload 文件清单 ---
    dir /b /s "%STAGE%"
)
REM ★ 存在性断言写成 `echo X>>"%RPT%"`（>> 前不留空格）：
REM   `echo X >>"%RPT%"` 里的那个空格会被当成正文写进文件。
echo --- 关键文件存在性（下面应出现 5 行 OK_*）--->>"%RPT%"
if exist "%STAGE%\R3 ShieldCore.exe"               echo OK_ENGINE>>"%RPT%"
if exist "%STAGE%\64\r3shieldcore-lib.dll"        echo OK_LIB64>>"%RPT%"
if exist "%STAGE%\32\r3shieldcore-lib.dll"        echo OK_LIB32>>"%RPT%"
if exist "%STAGE%\driver\r3shieldcore_kernel.sys" echo OK_DRIVER>>"%RPT%"
if exist "%STAGE%\r3shieldcore.ini"                echo OK_INI>>"%RPT%"

echo.
echo  报告已写到 "%RPT%"
echo  ------------------------------------------------------------
type "%RPT%"
echo  ------------------------------------------------------------
echo.
rd /s /q "%STAGE%" >nul 2>&1
if "%OPT_QUIET%"=="1" exit /b 0
pause
exit /b 0

:DRYRUN_DONE

REM ------------------------------------------------------------
REM [3/7] 建目录 + 复制用户态引擎
REM ------------------------------------------------------------
echo [3/7] 安装用户态引擎到 "%DEST%"...
mkdir "%DEST%" >nul 2>&1
mkdir "%DEST%\64" >nul 2>&1
mkdir "%DEST%\32" >nul 2>&1

copy /y "%STAGE%\R3 ShieldCore.exe"            "%DEST%\"            >nul
copy /y "%STAGE%\64\r3shieldcore-lib.dll"      "%DEST%\64\"         >nul
copy /y "%STAGE%\32\r3shieldcore-lib.dll"      "%DEST%\32\"         >nul

for %%F in (r3shieldcore.ini r3shieldcore-block.ini r3shieldcore-blockall.ini r3shieldcore-blockallsafe.ini r3shieldcore-safe-first.ini) do (
    if exist "%STAGE%\%%F" copy /y "%STAGE%\%%F" "%DEST%\" >nul
)
for %%F in (start.bat stop.bat unlock-acl.bat verify-v26.bat netcheck-diag.bat) do (
    if exist "%STAGE%\%%F" copy /y "%STAGE%\%%F" "%DEST%\" >nul
)
for %%F in (dskill.exe) do (
    if exist "%STAGE%\%%F" copy /y "%STAGE%\%%F" "%DEST%\" >nul
)
for %%F in (配置详解.md 模式选择说明.md 部署指南.md 预设说明.txt) do (
    if exist "%STAGE%\%%F" copy /y "%STAGE%\%%F" "%DEST%\" >nul
)
REM ★ uninstall.bat **不在 payload.zip 里** —— 它和 install.bat 一样是 iexpress 的
REM   顶层文件（由 SED 的 [SourceFiles] 单独列出）。所以必须从 %HERE% 取。
REM   踩过：原来写的是 %STAGE%\uninstall.bat ? copy **静默失败**（源文件不存在），
REM   结果注册表的 UninstallString 指向一个不存在的文件 ——
REM   用户在"程序和功能"里点卸载没反应，而且**全程没有任何报错**。
if exist "%HERE%\uninstall.bat" (
    copy /y "%HERE%\uninstall.bat" "%DEST%\" >nul 2>&1
    if not exist "%DEST%\uninstall.bat" echo [警告] uninstall.bat 复制失败 —— 控制面板卸载项会失效。
) else (
    echo [警告] 找不到 "%HERE%\uninstall.bat" —— 控制面板卸载项会失效。
)

REM 部署指南里引用的 dskill 逃生门必须在（stop.bat 依赖它）
if not exist "%DEST%\dskill.exe" (
    echo [警告] 没找到 dskill.exe —— stop.bat 的逃生门不可用。
)
echo        OK

REM ------------------------------------------------------------
REM [3.5/7] 配置目录 %ProgramData%\R3 Shield Core
REM   ★ v66：Program Files 下的安装目录**刻意不给用户写权限**（给了就等于
REM     让用户态恶意程序能替换 exe/dll/驱动）。代价是普通用户改不了安装
REM     目录里的 r3shieldcore.ini（存不进去）。所以把**配置文件**单独放
REM     到 ProgramData 下，并**只对该目录**授 Users:(OI)(CI)M。
REM   ★ 用 SID *S-1-5-32-545 而不是名字 "Users"（系统语言变了名字就变）。
REM   ★ 已存在则不覆盖 —— 升级安装不能丢用户改过的配置。
REM   ★ 本段失败**不中止安装**：引擎会自动回退到安装目录里的 ini
REM     （见 r3shieldcore_config.cpp 的 ResolveConfigPath）。
REM ------------------------------------------------------------
set "CFGDIR=%ProgramData%\R3 Shield Core"
if not exist "%CFGDIR%" mkdir "%CFGDIR%" >nul 2>&1
if not exist "%CFGDIR%" goto R3SC_CFG_SKIP
"%SystemRoot%\System32\icacls.exe" "%CFGDIR%" /grant *S-1-5-32-545:(OI)(CI)M /T /C /Q >nul 2>&1
if exist "%CFGDIR%\r3shieldcore.ini" goto R3SC_CFG_KEEP
if exist "%STAGE%\r3shieldcore.ini" copy /y "%STAGE%\r3shieldcore.ini" "%CFGDIR%\" >nul 2>&1
if exist "%CFGDIR%\r3shieldcore.ini" echo        配置 -> "%CFGDIR%\r3shieldcore.ini"
goto R3SC_CFG_SKIP
:R3SC_CFG_KEEP
echo        配置已存在，保留用户改动
:R3SC_CFG_SKIP

REM ------------------------------------------------------------
REM [4/7] 内核驱动（可选）
REM   ★ 不做签名预检、不因签名失败中止（见文件头"签名策略"）。
REM   ★ 启动类型 = **boot**（SERVICE_BOOT_START）。2026-10-05 由 auto 改成 boot
REM     （用户明确要求"最早启动"）。代价：安全模式下**也会加载**，且
REM     DriverEntry 早期出问题可能进不去系统 —— 所以驱动本身刻意不碰系统
REM     其它部分、建设备失败也返回成功。
REM     ★ 安全模式下**不会拉起引擎**：那由服务（r3shieldcore_svc.exe）的
REM       IsSafeMode 闸门保证，**不在驱动里做**。
REM   ★ 先 copy 到 System32\drivers\ 再 sc create。
REM     注意 sc create 的 binPath= 后面**必须**跟一个空格再跟引号，
REM     这是 sc 的参数解析怪癖（"binPath= xxx" 而不是 "binPath=xxx"）。
REM ------------------------------------------------------------
set "DRV_OK=0"

if "%OPT_NODRIVER%"=="1" (
    echo [4/7] 内核驱动：已按 /nodriver 跳过
    goto :SKIP_DRIVER
)

echo [4/7] 安装内核驱动 %DRV_SVC%...
if not exist "%STAGE%\driver\r3shieldcore_kernel.sys" (
    echo [警告] payload 里没有 driver\r3shieldcore_kernel.sys —— 跳过驱动。
    goto :SKIP_DRIVER
)

copy /y "%STAGE%\driver\r3shieldcore_kernel.sys" "%DRV_FILE%" >nul
if errorlevel 1 (
    echo [警告] 复制驱动文件失败 —— 跳过驱动安装。
    goto :SKIP_DRIVER
)

REM 已存在就先删掉旧服务，避免 sc create 报 1073（服务已存在）
"%SystemRoot%\System32\sc.exe" query "%DRV_SVC%" >nul 2>&1
if not errorlevel 1 (
    "%SystemRoot%\System32\sc.exe" stop "%DRV_SVC%" >nul 2>&1
    "%SystemRoot%\System32\sc.exe" delete "%DRV_SVC%" >nul 2>&1
)

"%SystemRoot%\System32\sc.exe" create "%DRV_SVC%" binPath= "System32\drivers\%DRV_NAME%" type= kernel start= boot DisplayName= "R3 ShieldCore Kernel Component" >nul 2>&1
if errorlevel 1 (
    echo [警告] sc create 失败 —— 驱动服务没建起来。
    goto :SKIP_DRIVER
)

"%SystemRoot%\System32\sc.exe" start "%DRV_SVC%" >nul 2>&1
if errorlevel 1 (
    echo.
    echo [注意] 驱动服务已注册（start=boot），但**本次没能启动**。
    echo        最常见原因 = 自签证书不被信任 / testsigning 未开启。
    echo        这不影响用户态引擎 —— 安装继续。
    echo        让它真能加载：见安装包里的 driver\README.md
    echo        （核心两步：把签名证书加进 LocalMachine 的 Root + TrustedPublisher；
    echo          再 bcdedit /set testsigning on 并重启。★ 改启动配置前先备好
    echo          BitLocker 恢复密钥。）
    echo.
    set "DRV_OK=1"
    goto :SKIP_DRIVER
)
set "DRV_OK=2"
echo        OK（服务已启动）

:SKIP_DRIVER

REM ------------------------------------------------------------
REM [5/7] 开始菜单 / 桌面快捷方式
REM ------------------------------------------------------------
echo [5/7] 创建快捷方式...
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command ^
  "$ws=New-Object -ComObject WScript.Shell;" ^
  "$lnk=$ws.CreateShortcut([Environment]::GetFolderPath('CommonPrograms')+'\R3 ShieldCore.lnk');" ^
  "$lnk.TargetPath='%DEST%\R3 ShieldCore.exe'; $lnk.WorkingDirectory='%DEST%'; $lnk.Description='R3 ShieldCore 引擎'; $lnk.Save();" ^
  "$lnk2=$ws.CreateShortcut([Environment]::GetFolderPath('CommonDesktopDirectory')+'\R3 ShieldCore.lnk');" ^
  "$lnk2.TargetPath='%DEST%\R3 ShieldCore.exe'; $lnk2.WorkingDirectory='%DEST%'; $lnk2.Save()" >nul 2>&1
if errorlevel 1 (
    echo [警告] 快捷方式创建失败（不影响使用）。
) else (
    echo        OK
)

REM ------------------------------------------------------------
REM [5/7-附] 开机自启（**服务**）
REM   ★ 2026-10-05：由"计划任务"改成"Windows 服务"。
REM     计划任务 /sc onlogon 只在**登录后**才触发 —— 开机到登录这段窗口
REM     没有防护，而且任务计划程序里用户随手能禁用/删除。
REM     服务由 SCM 管：开机即起、以 LocalSystem 跑、不依赖任何用户登录。
REM   ★ 为什么不是 Run 键：引擎清单是 requireAdministrator，写 Run 键
REM     会让每次登录都弹一个 UAC 框（用户不点它就不启动）。
REM   ★ 服务名 R3ShieldCoreGuard 必须和 uninstall.bat / r3sc_setup.c /
REM     selftest_setup.py 一致 —— 装一个名、卸另一个名会让服务永远删不掉。
REM     有闸门（tools/check_payload_manifest.py）比对这四处。
REM   ★ binPath 里的路径**含空格**，所以整条要再套一层引号：\"...\"。
REM     少一层 -> SCM 把它拆成"可执行文件 + 参数"，服务照样 RUNNING
REM     但开机什么都不启动（假成功）。
REM ------------------------------------------------------------
REM   ★ 旧版本用过的计划任务先清掉（装新不装旧；留着会变成两条自启链）。
"%SystemRoot%\System32\schtasks.exe" /delete /tn "R3ShieldCore" /f >nul 2>&1

"%SystemRoot%\System32\sc.exe" stop "R3ShieldCoreGuard" >nul 2>&1
"%SystemRoot%\System32\sc.exe" delete "R3ShieldCoreGuard" >nul 2>&1
"%SystemRoot%\System32\sc.exe" create "R3ShieldCoreGuard" binPath= "\"%DEST%\r3shieldcore_svc.exe\"" start= auto DisplayName= "R3 ShieldCore 开机启动服务" >nul 2>&1
if errorlevel 1 (
    echo [警告] 开机启动服务注册失败（本次仍可用，但重启后不会自动启动）。
    goto :SKIP_AUTOSTART
)
"%SystemRoot%\System32\sc.exe" start "R3ShieldCoreGuard" >nul 2>&1
REM   ★ 回读确认：「服务存在」不等于「服务指对了程序」。
REM     路径含空格，少一层引号就会被拆成两截 -> 服务 RUNNING 但开机不启动。
"%SystemRoot%\System32\sc.exe" qc "R3ShieldCoreGuard" | "%SystemRoot%\System32\findstr.exe" /c:"r3shieldcore_svc.exe" >nul 2>&1
if errorlevel 1 (
    echo [警告] 开机启动服务的 binPath 里没有 r3shieldcore_svc.exe。
) else (
    echo        OK（含开机启动服务）
)

:SKIP_AUTOSTART

REM ------------------------------------------------------------
REM [6/7] 卸载信息（控制面板 - 程序和功能）
REM ------------------------------------------------------------
echo [6/7] 写入卸载信息...
set "UNKEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\R3ShieldCore"
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v DisplayName     /t REG_SZ /d "R3 ShieldCore" /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v DisplayVersion  /t REG_SZ /d "v65" /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v Publisher       /t REG_SZ /d "R3 ShieldCore" /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v InstallLocation /t REG_SZ /d "%DEST%" /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v UninstallString /t REG_SZ /d "\"%DEST%\uninstall.bat\"" /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v NoModify /t REG_DWORD /d 1 /f >nul 2>&1
"%SystemRoot%\System32\reg.exe" add "%UNKEY%" /v NoRepair /t REG_DWORD /d 1 /f >nul 2>&1
echo        OK

REM ------------------------------------------------------------
REM [7/7] 汇总
REM ------------------------------------------------------------
echo [7/7] 清理临时文件...
rd /s /q "%STAGE%" >nul 2>&1
echo        OK

echo.
echo ============================================================
echo  安装完成
echo ============================================================
echo  安装目录 : %DEST%
echo  主程序   : "%DEST%\R3 ShieldCore.exe"
echo.
if "%DRV_OK%"=="2" echo  内核驱动 : 已安装并启动
if "%DRV_OK%"=="1" echo  内核驱动 : 已注册但**未启动**（多半是签名不被信任，见上面的提示）
if "%OPT_NODRIVER%"=="1" echo  内核驱动 : 未安装（/nodriver）
echo.
echo  下一步：
echo    1) 双击桌面 "R3 ShieldCore" 图标启动引擎（会弹 UAC）
echo    2) 或运行 "%DEST%\start.bat"
echo.
echo  卸载：控制面板 - 程序和功能 - "R3 ShieldCore"，
echo        或运行 "%DEST%\uninstall.bat"
echo.
echo  日志（安装后）：
echo    "%DEST%\r3shieldcore-events.log"    拦截事件
echo    "%DEST%\r3shieldcore-console.log"   引擎自述
echo ============================================================

if "%OPT_QUIET%"=="1" exit /b 0
pause
exit /b 0

:FAIL
if "%OPT_QUIET%"=="1" exit /b 1
echo.
pause
exit /b 1
