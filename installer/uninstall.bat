@echo off
REM ============================================================
REM  R3 ShieldCore -- 卸载程序
REM
REM  用法：
REM      uninstall.bat              （双击，会自己弹 UAC）
REM      uninstall.bat /quiet       （静默）
REM      uninstall.bat /dest=D:\R3SC
REM
REM  ★★★【顺序一：必须先停引擎，再动 System32 下的程序】★★★
REM  引擎跑着的时候，它自己的进程规则把 `\Windows\System32\` 当**片段**规则
REM  => System32 下**每一个**程序都判 HIGH；block 模式下对 highRisk 的进程
REM  创建是**直接拒**。实测（tools/procpath_probe.exe）被拒的有：
REM      sc.exe / reg.exe / powershell.exe / net.exe / cmd.exe / schtasks.exe …
REM  放行的有：tasklist / findstr / find / timeout / whoami / hostname …
REM
REM  所以：
REM    · 停引擎只能用**部署目录里**的 dskill.exe（直 syscall，绕开被 hook 的
REM      NtOpenProcess），**不能**用 taskkill（它在 System32，会被拒）；
REM    · 取 PID 只能用 tasklist（在放行名单里）；
REM    · sc / reg / powershell 一律**等引擎停掉之后**再调。
REM
REM  ★★★【顺序二：删安装目录必须是最后一步】★★★
REM  cmd.exe 是**按需从磁盘读**批处理文件的，不是一次性读进内存。
REM  而安装目录里就躺着 uninstall.bat 自己 —— 目录一被删，脚本剩下的行就
REM  全读不到，**一声不吭地终止**。
REM  踩过（v65c）：老版把"删目录"放在 [4/6]、"快捷方式+注册表"放在 [5/6]，
REM  结果卸载后快捷方式和注册表项**全都还在**，而日志里没有任何错误。
REM  修法：把删目录挪到最后，并用 start 起一个**独立**的 cmd 去删它。
REM
REM  ★★★【本文件必须 CRLF 行尾 + GBK 编码】★★★ 否则窗口一闪而过。
REM      改完请跑：  python tools/bat_gbk_crlf.py uninstall.bat
REM
REM  ★★★【产品名里有空格】★★★ 每一处引用都要加引号。
REM      闸门：  python tools/check_spaced_name_quoted.py
REM ============================================================
setlocal enabledelayedexpansion
set "HERE=%~dp0"
if "%HERE:~-1%"=="\" set "HERE=%HERE:~0,-1%"

set "OPT_QUIET=0"
set "ELEVATED=0"
set "DEST=%ProgramFiles%\R3 ShieldCore"

for %%A in (%*) do (
    if /i "%%~A"=="/elevated"  set "ELEVATED=1"
    if /i "%%~A"=="/quiet"     set "OPT_QUIET=1"
    if /i "%%~A"=="/nopause"   set "OPT_QUIET=1"
)
for %%A in (%*) do (
    set "ARG=%%~A"
    if /i "!ARG:~0,6!"=="/dest=" set "DEST=!ARG:~6!"
)

REM 如果本脚本是从安装目录里跑的，就以**自己所在目录**为准（更可靠）
if exist "%HERE%\R3 ShieldCore.exe" set "DEST=%HERE%"

REM ★ 驱动**文件名**是 r3shieldcore_kernel.sys（有下划线、全小写），
REM   而**服务名**是 R3ShieldCoreKernel（无下划线）—— 两者别混。
REM   踩过：写成 R3ShieldCoreKernel.sys 时 NTFS 大小写不敏感还能凑合，
REM   但和 C 版安装程序（用小写名）不一致，容易在对大小写敏感的目录上翻车。
set "DRV_SVC=R3ShieldCoreKernel"
set "DRV_FILE=%SystemRoot%\System32\drivers\r3shieldcore_kernel.sys"
set "UNKEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\R3ShieldCore"

echo ============================================================
echo  R3 ShieldCore 卸载程序
echo ============================================================
echo  安装目录 : %DEST%
echo.

REM ------------------------------------------------------------
REM [1/6] 管理员权限
REM ------------------------------------------------------------
set "IS_ADMIN=0"
"%SystemRoot%\System32\whoami.exe" /groups 2>nul | "%SystemRoot%\System32\findstr.exe" /c:"S-1-16-12288" /c:"S-1-16-16384" >nul
if not errorlevel 1 set "IS_ADMIN=1"

if "%IS_ADMIN%"=="0" (
    if "%ELEVATED%"=="1" (
        echo [错误] 需要管理员权限。请右键 -^> 以管理员身份运行。
        goto :FAIL
    )
    echo [1/6] 正在请求管理员权限...
    REM ★ 同 install.bat：-Wait 不能省，否则 wextract 会在本进程退出后
    REM   立刻删掉解压目录，提权实例还没读完就没了。
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '/elevated','/quiet=%OPT_QUIET%','/dest=%DEST%' -Verb RunAs -Wait" >nul 2>&1
    if errorlevel 1 (
        echo [错误] 提权被取消或失败。请右键 -^> 以管理员身份运行。
        goto :FAIL
    )
    echo        已在新窗口继续，本窗口关闭。
    exit /b 0
)
echo [1/6] 管理员权限 OK

REM ------------------------------------------------------------
REM [2/6] 先停引擎（★ 必须用部署目录里的 dskill，不能用 taskkill）
REM   tasklist 是 CSV + /fi 精确匹配；不用默认表格输出 ——
REM   它会把映像名截断到 25 字符，长名会静默漏掉。
REM ------------------------------------------------------------
echo [2/6] 停止引擎...
set "ENGINE_PID="
for /f "tokens=2 delims=," %%p in ('%SystemRoot%\System32\tasklist.exe /nh /fo csv /fi "imagename eq R3 ShieldCore.exe" 2^>nul') do set "ENGINE_PID=%%~p"

REM 保险：只接受纯数字，避免把 tasklist 的提示文字当成 PID
if defined ENGINE_PID (
    echo %ENGINE_PID%| "%SystemRoot%\System32\findstr.exe" /r /c:"^[0-9][0-9]*$" >nul
    if errorlevel 1 set "ENGINE_PID="
)

if not defined ENGINE_PID (
    echo        引擎没在运行。
    goto :ENGINE_DONE
)
echo        引擎 PID = %ENGINE_PID%
if not exist "%DEST%\dskill.exe" (
    echo        [警告] 没找到 "%DEST%\dskill.exe" —— 没法自动停引擎。
    echo               请手动关掉引擎的控制台窗口，然后重跑本脚本。
    goto :FAIL
)
"%DEST%\dskill.exe" %ENGINE_PID% >nul 2>&1
"%SystemRoot%\System32\timeout.exe" /t 2 /nobreak >nul 2>&1
set "STILL="
for /f "tokens=2 delims=," %%p in ('%SystemRoot%\System32\tasklist.exe /nh /fo csv /fi "imagename eq R3 ShieldCore.exe" 2^>nul') do set "STILL=%%~p"
if defined STILL (
    echo        [警告] 引擎仍在运行（dskill 没杀掉）。
    echo               请手动关掉引擎的控制台窗口，然后重跑本脚本。
    goto :FAIL
)
echo        OK

:ENGINE_DONE

REM ------------------------------------------------------------
REM [3/6] 卸内核驱动
REM ------------------------------------------------------------
echo [3/6] 卸载内核驱动 %DRV_SVC%...
"%SystemRoot%\System32\sc.exe" query "%DRV_SVC%" >nul 2>&1
if errorlevel 1 (
    echo        驱动服务本来就不在。
    goto :DRIVER_DONE
)
"%SystemRoot%\System32\sc.exe" stop "%DRV_SVC%" >nul 2>&1
"%SystemRoot%\System32\timeout.exe" /t 2 /nobreak >nul 2>&1
"%SystemRoot%\System32\sc.exe" delete "%DRV_SVC%" >nul 2>&1
if errorlevel 1 (
    echo        [警告] sc delete 失败 —— 驱动服务可能还在（重启后再试一次）。
) else (
    echo        服务已删除。
)

:DRIVER_DONE
if exist "%DRV_FILE%" (
    del /f /q "%DRV_FILE%" >nul 2>&1
    if exist "%DRV_FILE%" (
        echo        [警告] 驱动文件删不掉（可能被占用）：%DRV_FILE%
        echo               重启后再删一次。
    ) else (
        echo        驱动文件已删除。
    )
)

REM ------------------------------------------------------------
REM [4/6] 删快捷方式 + 卸载注册项 + 删开机启动服务 + 清遗留计划任务
REM   ★★★ 这几件事必须在**删安装目录之前**做完（见文件头"顺序二"）。
REM   老版把它们放在删目录之后 ? 整段没执行，且没有任何报错。
REM   ★ 开机自启 = **服务** R3ShieldCoreGuard（2026-10-05 由计划任务改成服务）：
REM     服务由 SCM 管、开机即起、不依赖任何用户登录；而计划任务 /sc onlogon
REM     只在**登录后**才触发，开机到登录这段窗口没有防护。
REM     Run 键从来没用过 —— 引擎清单是 requireAdministrator，
REM     写 Run 键会让每次登录都弹 UAC 框。
REM ------------------------------------------------------------
echo [4/6] 清理快捷方式、注册表与开机自启...
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command ^
  "Remove-Item ([Environment]::GetFolderPath('CommonPrograms')+'\R3 ShieldCore.lnk') -Force -ErrorAction SilentlyContinue;" ^
  "Remove-Item ([Environment]::GetFolderPath('CommonDesktopDirectory')+'\R3 ShieldCore.lnk') -Force -ErrorAction SilentlyContinue" >nul 2>&1
"%SystemRoot%\System32\reg.exe" delete "%UNKEY%" /f >nul 2>&1

REM   ★ 开机启动**服务**：先停再删。
REM     服务进程活着时它的 exe 被占用 -> 安装目录删不掉；而且 sc delete 对
REM     "还在跑"的服务只是标记删除，文件仍然被占着。
REM   ★ 回读确认：sc delete 对**不存在**的服务也可能返回成功，
REM     所以删完必须再 query 一次才敢说"删掉了"。
REM     （用 label 块不用括号块：括号块是整块解析的，块内取不到块内 set 的变量）
"%SystemRoot%\System32\sc.exe" stop "R3ShieldCoreGuard" >nul 2>&1
"%SystemRoot%\System32\timeout.exe" /t 2 /nobreak >nul 2>&1
"%SystemRoot%\System32\sc.exe" delete "R3ShieldCoreGuard" >nul 2>&1
"%SystemRoot%\System32\sc.exe" query "R3ShieldCoreGuard" >nul 2>&1
if errorlevel 1 goto R3SC_SVC_GONE
echo        [警告] 开机启动服务没删掉：R3ShieldCoreGuard
goto R3SC_SVC_DONE
:R3SC_SVC_GONE
echo        OK（含开机启动服务）
:R3SC_SVC_DONE

REM   ★ 旧版本用过的**计划任务**也要顺手清掉 —— 否则老版本升上来的机器上
REM     会同时留着"任务 + 服务"两条自启链（可能拉出两份引擎）。
"%SystemRoot%\System32\schtasks.exe" /delete /tn "R3ShieldCore" /f >nul 2>&1
"%SystemRoot%\System32\schtasks.exe" /query /tn "R3ShieldCore" >nul 2>&1
if errorlevel 1 goto R3SC_AUTO_GONE
echo        [警告] 遗留的旧版计划任务没删掉：R3ShieldCore
goto R3SC_AUTO_DONE
:R3SC_AUTO_GONE
echo        OK（含遗留计划任务）
:R3SC_AUTO_DONE

REM   ★ v66：配置文件目录（%ProgramData%\R3 Shield Core）也要清掉 ——
REM     安装时把 r3shieldcore.ini 放在那里，并**只对它**授了
REM     Users:(OI)(CI)M（这样普通用户能改配置，但改不了 Program Files
REM     下的程序本体）。卸载不删就会留一份"孤儿配置"。
REM     ★ 先 icacls /reset 把显式 ACE 还原成继承再删：带显式 ACE 的文件
REM       会让 rd 报"拒绝访问"，而那句提示和"被占用/被设只读"一模一样，
REM       光看提示分不出根因（铁律 161）。
set "CFGDIR=%ProgramData%\R3 Shield Core"
if not exist "%CFGDIR%" goto R3SC_CFG_DONE
"%SystemRoot%\System32\icacls.exe" "%CFGDIR%" /reset /T /C /Q >nul 2>&1
rd /s /q "%CFGDIR%" >nul 2>&1
if not exist "%CFGDIR%" goto R3SC_CFG_GONE
echo        [警告] 配置目录没删掉：%CFGDIR%
goto R3SC_CFG_DONE
:R3SC_CFG_GONE
echo        OK（含配置目录）
:R3SC_CFG_DONE

REM ------------------------------------------------------------
REM [5/6] 汇总
REM ------------------------------------------------------------
echo [5/6] 完成。
echo.
echo ============================================================
echo  卸载完成
echo ============================================================
echo  已删除：内核驱动服务与文件 / 开机启动服务 / 快捷方式 / 卸载注册项 / 配置目录
echo  安装目录：将在本窗口关闭后自动删除
echo            %DEST%
echo ============================================================

REM ------------------------------------------------------------
REM [6/6] 安排删除安装目录（★ 必须是最后一步）
REM   ★ 目录里躺着 uninstall.bat 自己，而 cmd 按需读批处理 —— 直接 rd 会让
REM     后面的行全部失效。所以用 start 起一个**独立**的 cmd 去删，本脚本
REM     不依赖它的结果，可以正常走完 pause。
REM   ★ 延迟 2 秒：让用户看清上面的汇总，也避开本进程退出时的文件锁。
REM   ★ 先做安全检查：只删"确实是本产品安装目录"的路径，避免 /dest= 指错
REM     时误删无关目录。
REM   ★ 目录名含空格，cmd /c "..." 里用 "" 表示字面引号。
REM ------------------------------------------------------------
set "LOOKS_OK=0"
if exist "%DEST%\R3 ShieldCore.exe" set "LOOKS_OK=1"
if exist "%DEST%\r3shieldcore.ini"  set "LOOKS_OK=1"
if exist "%DEST%\64\r3shieldcore-lib.dll" set "LOOKS_OK=1"
if "%LOOKS_OK%"=="0" (
    echo [6/6] [跳过] "%DEST%" 看起来**不是**本产品的安装目录，为安全起见不删。
    goto :SKIP_RMDIR
)
echo [6/6] 已安排删除安装目录...
start "" /min cmd /c "timeout /t 2 /nobreak >nul & rd /s /q ""%DEST%"""

:SKIP_RMDIR

if "%OPT_QUIET%"=="1" exit /b 0
pause
exit /b 0

:FAIL
if "%OPT_QUIET%"=="1" exit /b 1
echo.
pause
exit /b 1
