@echo off
setlocal EnableExtensions

set SVC=R3ShieldCoreKernel
set DST=%SystemRoot%\System32\drivers\%SVC%.sys

rem ============================================================
rem  卸载 R3ShieldCore 内核组件
rem  这一步是可逆的：停服务 - 删服务 - 删文件。
rem  建议先执行本脚本，再考虑删源码目录。
rem ============================================================

net session >nul 2>&1
if errorlevel 1 (
    echo 需要管理员权限，正在尝试提权...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo === 卸载 %SVC% ===
echo.

echo [1/3] 停止服务...
sc stop %SVC%
rem 停不下来是正常的（可能正被引用），继续删即可 —— 删掉注册后
rem 下次开机就不会再加载了。
timeout /t 2 /nobreak >nul

echo [2/3] 删除服务注册...
sc delete %SVC%
if errorlevel 1 (
    echo       [警告] sc delete 失败。若提示服务不存在，说明已经删过了。
)

echo [3/3] 删除驱动文件...
if exist "%DST%" (
    del /f /q "%DST%"
    if errorlevel 1 (
        echo       [警告] 删除失败 —— 文件可能仍被内核引用。
        echo              重启后再跑一次本脚本即可。
    ) else (
        echo       已删除 %DST%
    )
) else (
    echo       文件不存在，跳过
)

echo.
echo 卸载完成。
echo.
echo 如果还想关掉测试签名（恢复到干净状态）：
echo     bcdedit /set testsigning off
echo 然后重启。^（注意：本机若启用了 BitLocker，改启动配置会要恢复密钥^）
echo.

pause
endlocal
