@echo off
REM ============================================================
REM  netcheck32 打不开 —— 一键取证脚本（VM 里右键以管理员身份运行）
REM
REM  产出：同目录下的 netcheck-diag.txt
REM  把那个文件发回来即可。
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set OUT=netcheck-diag.txt
set "ENGINE=R3 ShieldCore.exe"
set LOG=r3shieldcore-events.log

echo ============================================ > "%OUT%"
echo  R3ShieldCore netcheck32 诊断报告 >> "%OUT%"
echo  时间: %DATE% %TIME% >> "%OUT%"
echo ============================================ >> "%OUT%"
echo. >> "%OUT%"

echo [1] 引擎是否在运行 >> "%OUT%"
tasklist /fi "imagename eq %ENGINE%" 2>&1 | find /i "%ENGINE%" >> "%OUT%"
if errorlevel 1 echo   ^>^> 引擎【没在运行】！这就是所有操作都不被拦的原因。 >> "%OUT%"
echo. >> "%OUT%"

echo [2] r3shieldcore.ini 关键配置 >> "%OUT%"
if exist r3shieldcore.ini (
    findstr /b /i "mode= hook_process= hook_thread= hook_file= hook_dll_load= hook_net= hook_memory_op= high_risk=" r3shieldcore.ini >> "%OUT%"
) else (
    echo   ^>^> 找不到 r3shieldcore.ini >> "%OUT%"
)
echo. >> "%OUT%"

echo [3] 当前 ini 的实际 mode（第一处非注释 mode=） >> "%OUT%"
findstr /b /i "mode=" r3shieldcore.ini >> "%OUT%"
echo. >> "%OUT%"

echo [4] 日志文件时间戳（看最后一次写入是什么时候） >> "%OUT%"
if exist %LOG% (
    dir /od %LOG% | find /i "%LOG%" >> "%OUT%"
) else (
    echo   ^>^> 找不到 %LOG% >> "%OUT%"
)
echo. >> "%OUT%"

echo [5] netcheck32 相关日志行 >> "%OUT%"
if exist %LOG% (
    findstr /i "netcheck32" %LOG% >> "%OUT%"
    echo   --- 以上为空则表示日志里没有它的记录 --- >> "%OUT%"
) else (
    echo   ^>^> 无日志 >> "%OUT%"
)
echo. >> "%OUT%"

echo [6] 日志里各类事件的数量（PROC 为 0 = 进程创建没被监控） >> "%OUT%"
if exist %LOG% (
    for %%K in (PROC REG FILE NET DLL COM TOKEN) do (
        findstr /c:" %%K " %LOG% > "%TEMP%\_cnt.tmp" 2>nul
        find /c /v "" "%TEMP%\_cnt.tmp" >> "%OUT%"
    )
    echo   --- 上面 7 个数字依次是 PROC REG FILE NET DLL COM TOKEN 的行数 --- >> "%OUT%"
    echo   --- 日志总行数 --- >> "%OUT%"
    find /c /v "" %LOG% >> "%OUT%"
    del "%TEMP%\_cnt.tmp" 2>nul
) else (
    echo   ^>^> 无日志 >> "%OUT%"
)
echo. >> "%OUT%"

echo [7] 日志最后 25 行（看停止在哪一刻） >> "%OUT%"
if exist %LOG% (
    powershell -NoProfile -Command "Get-Content '%LOG%' -Tail 25" >> "%OUT%" 2>&1
) else (
    echo   ^>^> 无日志 >> "%OUT%"
)
echo. >> "%OUT%"

echo [8] 目标文件信息 >> "%OUT%"
if exist "C:\Users\测试\Desktop\netcheck32.exe" (
    dir "C:\Users\测试\Desktop\netcheck32.exe" >> "%OUT%"
    echo   --- 备用数据流（Zone.Identifier = 被"阻止"标记） --- >> "%OUT%"
    dir /r "C:\Users\测试\Desktop\netcheck32.exe" >> "%OUT%"
    echo   --- ACL --- >> "%OUT%"
    icacls "C:\Users\测试\Desktop\netcheck32.exe" >> "%OUT%" 2>&1
) else (
    echo   ^>^> 该路径下找不到 netcheck32.exe（路径不对？用户目录不是"测试"？） >> "%OUT%"
    echo   --- 列出桌面 exe --- >> "%OUT%"
    dir /b "C:\Users\测试\Desktop\*.exe" >> "%OUT%" 2>&1
)
echo. >> "%OUT%"

echo [9] 引擎的崩溃记录（应用事件日志，最近 30 条错误） >> "%OUT%"
wevtutil qe Application /q:"*[System[(Level=1 or Level=2)]]" /c:30 /rd:true /f:text 2>&1 | findstr /i "r3shieldcore R3ShieldCore" >> "%OUT%"
echo   --- 以上为空表示没有引擎崩溃记录 --- >> "%OUT%"
echo. >> "%OUT%"

echo [10] hookcheck（如果同目录有这个工具就用它验 hook 是否装上） >> "%OUT%"
if exist hookcheck.exe (
    echo   注意：hookcheck 必须以【双击】方式运行才能反映真实注入状态 >> "%OUT%"
    echo   （从本脚本里调用的话，父进程是 cmd，观察不到 block_all 下的真实行为） >> "%OUT%"
)

echo ============================================ >> "%OUT%"
echo  完成。请把 %OUT% 发回。 >> "%OUT%"
echo ============================================ >> "%OUT%"

echo.
echo 诊断完成，已写入 %OUT%
echo 请把该文件发回给我。
echo.
pause
