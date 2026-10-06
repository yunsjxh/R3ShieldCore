@echo off
setlocal EnableExtensions

set SVC=R3ShieldCoreKernel
set SRC=%~dp0build\r3shieldcore_kernel.sys
rem ★ 驱动**文件名**（有下划线、全小写）≠ **服务名**（%SVC%，无下划线）。
rem   混用会让 sc create 指向一个不存在的 .sys —— 驱动静默不加载（铁律 125）。
set DRV_FILE=r3shieldcore_kernel.sys
set DST=%SystemRoot%\System32\drivers\%DRV_FILE%

rem ============================================================
rem  安装 R3ShieldCore 内核组件为**开机自启**（SERVICE_BOOT_START，最早）
rem
rem  ★ 2026-10-05 由 AUTO_START 改成 BOOT_START（用户明确要求「最早启动」）。
rem    BOOT_START 由**引导加载器**加载，比 AUTO_START 更早，代价是：
rem    **安全模式也会加载**，且 DriverEntry 早期出问题可能导致进不去系统。
rem    本驱动刻意不碰系统其它部分（不挂回调、不改别人的注册表、
rem    建设备失败也返回 STATUS_SUCCESS），就是为了扛住这个代价。
rem  ★ 安全模式下**不会拉起用户态引擎** —— 那由服务
rem    （service/r3shieldcore_svc.c 的 IsSafeMode 闸门）保证，**不在驱动里做**。
rem
rem  卸载：uninstall_driver.bat
rem  若出问题进不去系统：进 WinRE 删掉
rem    %SystemRoot%\System32\drivers\r3shieldcore_kernel.sys
rem  并删掉注册表键
rem    HKLM\SYSTEM\CurrentControlSet\Services\R3ShieldCoreKernel
rem ============================================================

rem ---- 提权 ----
net session >nul 2>&1
if errorlevel 1 (
    echo 需要管理员权限，正在尝试提权...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo === 安装 %SVC% 为开机自启的内核驱动 ===
echo.

if not exist "%SRC%" (
    echo [错误] 找不到驱动文件: %SRC%
    echo        先执行: bash driver/build_driver.sh
    goto :end
)

rem ---- 签名预检 ----
rem 没签名的驱动在 x64 上根本加载不了，而报出来的错只有
rem "拒绝访问(5)" 或 0xC0000428，看不出是签名问题。先查一遍。
set SIGNTOOL=
for /f "delims=" %%i in ('dir /b /s /o-n "D:\Windows Kits\10\bin\*\x64\signtool.exe" 2^>nul') do (
    if not defined SIGNTOOL set SIGNTOOL=%%i
)
if defined SIGNTOOL (
    echo [1/5] 校验签名...
    "%SIGNTOOL%" verify /kp "%SRC%" >nul 2>&1
    if errorlevel 1 (
        echo       [警告] 签名校验未通过。
        echo              若还没开测试签名 ^(bcdedit /set testsigning on^)，
        echo              驱动加载会失败。详见 driver\README.md
    ) else (
        echo       [ OK ] 签名有效
    )
) else (
    echo [1/5] 找不到 signtool.exe，跳过签名预检
)

echo [2/5] 复制驱动到驱动目录...
copy /y "%SRC%" "%DST%" >nul
if errorlevel 1 (
    echo       [错误] 复制失败
    goto :end
)
echo        -^> %DST%

echo [3/5] 注册服务（type= kernel, start= boot）...
rem 先删掉可能存在的旧服务，避免 sc create 报 1073
sc query %SVC% >nul 2>&1
if not errorlevel 1 (
    sc stop %SVC% >nul 2>&1
    sc delete %SVC% >nul 2>&1
)
sc create %SVC% binPath= "System32\drivers\%DRV_FILE%" type= kernel start= boot DisplayName= "R3ShieldCore Kernel Component"
if errorlevel 1 (
    echo       [错误] sc create 失败
    goto :end
)

rem 可选：想让它比别的 BOOT_START 驱动更早加载，可以设 Group/Tag。
rem 但 Group 填错会导致服务**根本不被加载**，所以默认注释掉。
rem sc config %SVC% group= "File System" tag= yes

echo [4/5] 启动服务（本次立即生效，无需重启）...
sc start %SVC%
if errorlevel 1 (
    echo.
    echo       [警告] sc start 失败。最常见的两个原因：
    echo         1) 没开测试签名 / 驱动没签名  ^(错误 577 / 0xC0000428^)
    echo         2) 已开 Secure Boot ^(自签名驱动一定加载不了^)
    echo       看系统事件日志: eventvwr -^> Windows 日志 -^> 系统
    echo.
    goto :end
)

echo [5/5] 查询状态...
sc query %SVC%

echo.
echo 安装完成。
echo.
echo ★ 现在还不能宣布"开机自启生效" —— 因为可能是你刚 sc start 起来的。
echo   正确验证方式：重启系统，什么都不要做，等满 10 分钟后运行：
echo       powershell -ExecutionPolicy Bypass -File driver\verify_autostart.ps1
echo.

:end
pause
endlocal
