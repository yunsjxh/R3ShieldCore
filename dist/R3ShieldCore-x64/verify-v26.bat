@echo off
setlocal
chcp 936 >nul 2>&1

rem =====================================================================
rem  verify-v26.bat  —— R3ShieldCore 部署自检（双击即可，会自动请求管理员）
rem
rem   ① 引擎是不是 v26
rem   ② 进程创建监控挂没挂
rem   ③ 该问的键是被"问"了还是被"静默拒"了
rem
rem  用法：
rem    · 双击运行（放在引擎 EXE 同目录）
rem    · 或把 r3shieldcore-events.log 拖到本文件上
rem  结果同时写入 verify-v26.txt（同目录），方便发回来。
rem =====================================================================

set "SCRIPTDIR=%~dp0"
set "LOGFILE=%~1"
if "%LOGFILE%"=="" set "LOGFILE=%SCRIPTDIR%r3shieldcore-events.log"
set "OUT=%SCRIPTDIR%verify-v26.txt"

cls
echo ============================================================
echo   R3ShieldCore 部署自检
echo ============================================================
echo.
echo  日志文件：%LOGFILE%
echo.

if not exist "%LOGFILE%" (
    echo [X] 找不到日志文件。
    echo     请把本脚本放到引擎 EXE 所在目录，
    echo     或把 r3shieldcore-events.log 拖到本脚本图标上。
    echo.
    goto :done
)

rem ---- 去 BOM 副本 ------------------------------------------------
rem  引擎日志是 UTF-8 with BOM（r3shieldcore_log.cpp 写 "\xEF\xBB\xBF"）。
rem  cmd 的 type 在 GBK 控制台下会把 BOM 显示成乱码（"锘?"），
rem  为便于阅读，生成一个去掉前 3 字节的副本供后续使用。
set "LOGCLEAN=%TEMP%\_rg_clean.log"
set "LOGSRC=%LOGFILE%"
powershell -NoProfile -Command "try{$b=[IO.File]::ReadAllBytes('%LOGSRC%'); if($b.Length -gt 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF){$b=$b[3..($b.Length-1)]}; [IO.File]::WriteAllBytes('%TEMP%\_rg_clean.log',$b); exit 0}catch{exit 1}" >nul 2>&1
if exist "%TEMP%\_rg_clean.log" (
    set "LOGFILE=%TEMP%\_rg_clean.log"
)
echo.

call :run > "%OUT%" 2>&1
type "%OUT%"
echo.
echo ------------------------------------------------------------
echo  完整结果已写入：%OUT%
echo ------------------------------------------------------------

:done
echo.
echo 按任意键关闭窗口...
pause >nul
endlocal
exit /b


rem =====================================================================
rem  下面是真正干活的子过程，输出全部被重定向到文件
rem =====================================================================
:run

for %%F in ("%LOGFILE%") do (
    echo [i] 文件大小：%%~zF 字节
    echo [i] 最后修改：%%~tF
)
echo.

rem ---------- 1. 引擎进程 ----------
echo ---------- 1. 引擎进程在不在 ----------
tasklist /FI "IMAGENAME eq R3 ShieldCore.exe" > "%TEMP%\_rg_tl.txt" 2>&1
findstr /I /C:"r3shieldcore" "%TEMP%\_rg_tl.txt" >nul 2>&1
if errorlevel 1 (
    echo [X] 没发现 R3 ShieldCore.exe - 引擎可能没在跑
) else (
    echo [OK] 引擎在跑：
    findstr /I /C:"r3shieldcore" "%TEMP%\_rg_tl.txt"
)
if exist "%TEMP%\_rg_tl.txt" del "%TEMP%\_rg_tl.txt" >nul 2>&1
echo.

rem ---------- 2. v26 标记 ----------
echo ---------- 2. 引擎是不是 v26 ----------
findstr /C:"ASK-UNAVAIL" "%LOGFILE%" > "%TEMP%\_rg_v26.txt" 2>nul
for %%F in ("%TEMP%\_rg_v26.txt") do set "SZ26=%%~zF"
if "%SZ26%"=="0" (
    echo [!!] 日志里没有 "ASK-UNAVAIL" 标记。
    echo      可能原因：^(a^) 还没触发过降级路径；^(b^) 跑的是旧引擎。
    echo      判断办法见第 4、5 节。
) else (
    echo [OK] 出现 "ASK-UNAVAIL" 标记 = 引擎是 v26，
    echo      且询问通道确实不可用（该问的已降级放行）。
)
if exist "%TEMP%\_rg_v26.txt" del "%TEMP%\_rg_v26.txt" >nul 2>&1
echo.

rem ---------- 3. 进程创建监控 ----------
echo ---------- 3. 进程创建监控挂没挂 ----------
findstr /C:"PROC " "%LOGFILE%" > "%TEMP%\_rg_proc.txt" 2>nul
findstr /C:"Create" "%TEMP%\_rg_proc.txt" > "%TEMP%\_rg_procc.txt" 2>nul
for %%F in ("%TEMP%\_rg_proc.txt") do set "SZP=%%~zF"
for %%F in ("%TEMP%\_rg_procc.txt") do set "SZC=%%~zF"
if "%SZP%"=="0" (
    echo     PROC 事件：0 条
) else (
    echo     PROC 事件：有（%SZP% 字节的匹配内容）
)
if "%SZC%"=="0" (
    echo [!!] Create 计数为 0 - 进程创建监控可能没挂。
    echo      如果你刚操作过电脑（开过程序）却没有任何 Create，这就是异常。
) else (
    echo [OK] 有 Create 事件，进程创建监控在工作：
    type "%TEMP%\_rg_procc.txt"
)
if exist "%TEMP%\_rg_proc.txt" del "%TEMP%\_rg_proc.txt" >nul 2>&1
if exist "%TEMP%\_rg_procc.txt" del "%TEMP%\_rg_procc.txt" >nul 2>&1
echo.

rem ---------- 4. 计数器 ----------
echo ---------- 4. 注册表拦截统计 ----------
findstr /C:"REG  BLOCK" "%LOGFILE%" > "%TEMP%\_rg_rb.txt" 2>nul
findstr /C:"ASK-UNAVAIL" "%LOGFILE%" > "%TEMP%\_rg_au.txt" 2>nul
for %%F in ("%TEMP%\_rg_rb.txt") do echo     REG BLOCK 匹配字节数         ：%%~zF
for %%F in ("%TEMP%\_rg_au.txt") do echo     ASK-UNAVAIL 匹配字节数       ：%%~zF
if exist "%TEMP%\_rg_rb.txt" del "%TEMP%\_rg_rb.txt" >nul 2>&1
if exist "%TEMP%\_rg_au.txt" del "%TEMP%\_rg_au.txt" >nul 2>&1
echo.

rem ---------- 5. 可疑的裸段键 ----------
echo ---------- 5. 被拒的键里，哪些"看起来不该拒" ----------
rem  判据（要精确，否则会把高危键误列进来）：
rem    key=Software          （裸段，末尾是空格）
rem    key=System            （裸段，末尾是空格）
rem    key=\REGISTRY\MACHINE\SOFTWARE\CLASSES  （全前缀裸 CLASSES，末尾是空格）
rem  注意：不要用 2^>^&1 捕获 findstr 的 stderr — 管道上游无输出时，
rem      下游 findstr 的报错会被写进结果文件，type 出来就是"系统找不到指定的文件"。
rem      统一把错误丢到 nul。
findstr /C:"REG  BLOCK" "%LOGFILE%" 2>nul | findstr /I /C:"key=Software " /C:"key=System " /C:"SOFTWARE\CLASSES " 2>nul > "%TEMP%\_rg_sus.txt"
rem  再排除高危键（它们本来就该拒，不是"误拒"）
findstr /I /V /C:"Classes\CLSID" /C:"Classes\AppID" /C:"Classes\ActivatableClasses" /C:"Classes\Extensions" /C:"CurrentVersion\Run" /C:"Image File Execution" "%TEMP%\_rg_sus.txt" 2>nul > "%TEMP%\_rg_sus2.txt"
if not exist "%TEMP%\_rg_sus2.txt" copy /y nul "%TEMP%\_rg_sus2.txt" >nul 2>&1
for %%F in ("%TEMP%\_rg_sus2.txt") do set "SZSU=%%~zF"
if not defined SZSU set "SZSU=0"
if "%SZSU%"=="0" (
    echo [OK] 没有发现"裸 Software / 裸 System / 裸 CLASSES"被拒的记录。
    echo      注意：这只说明**还没触发过应当弹窗的写入**，
    echo            不等于"引擎是 v26"（这点看第 2 节）。
) else (
    echo [!!] 以下这些按规则层应当弹窗，却被静默拒了 ——
    echo      若引擎是 v26 且弹窗通道正常，这些应当被"问"。
    echo      全被拒 ^<且无 ASK-UNAVAIL^> = 旧引擎特征（或 v26 未生效）：
    echo.
    type "%TEMP%\_rg_sus2.txt"
)
if exist "%TEMP%\_rg_sus.txt" del "%TEMP%\_rg_sus.txt" >nul 2>&1
if exist "%TEMP%\_rg_sus2.txt" del "%TEMP%\_rg_sus2.txt" >nul 2>&1
echo.

rem ---------- 6. 高危键对照 ----------
echo ---------- 6. 对照：这些被拒是对的 ----------
findstr /C:"REG  BLOCK" "%LOGFILE%" | findstr /I /C:"CurrentControlSet\Services" /C:"CurrentControlSet\Control" /C:"Winlogon" /C:"Image File Execution" /C:"SOFTWARE\Classes\CLSID" /C:"CurrentVersion\Run" > "%TEMP%\_rg_hi.txt" 2>nul
for %%F in ("%TEMP%\_rg_hi.txt") do set "SZHI=%%~zF"
if "%SZHI%"=="0" (
    echo     无
) else (
    echo     命中"系统服务/驱动""Control""Winlogon""IFEO""CLSID""Run"等 - 拒是对的：
    echo.
    type "%TEMP%\_rg_hi.txt"
)
if exist "%TEMP%\_rg_hi.txt" del "%TEMP%\_rg_hi.txt" >nul 2>&1
echo.

echo ============================================================
echo  结论速读
echo ============================================================
echo   1) 第 2 节出现 "ASK-UNAVAIL"  = 引擎是 v26
echo   2) 第 3 节 Create 计数         = 进程创建监控是否工作
echo   3) 第 5 节有内容              = 旧引擎特征（该问的却拒了）
echo.
echo   把上面全部内容（或 verify-v26.txt）发回来即可。
exit /b
