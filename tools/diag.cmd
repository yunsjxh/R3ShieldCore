@echo off
rem ======================================================================
rem  diag.cmd -- "双击就用" 的入口（不用记参数、不用开 cmd）
rem ----------------------------------------------------------------------
rem  为什么还要一个入口脚本：
rem    · diag_autostart.exe 是控制台程序，双击时窗口会随进程关掉；
rem      虽然 exe 内部已经做了"双击就停住"，但万一它因为别的原因
rem      （缺 DLL、被杀软拦、路径不对）秒退，用户还是只看到一闪。
rem    · 本脚本的作用就是**兜住这一切**：无论 exe 在不在、跑成什么样，
rem      最后都停住，并把"该看什么"指出来。
rem
rem  用法：双击本文件即可。也可以：
rem      diag.cmd                 -> 自动诊断
rem      diag.cmd D:\某路径        -> 指定安装目录
rem ======================================================================
setlocal
chcp 936 >nul 2>&1
title R3 ShieldCore 开机自启诊断
cd /d "%~dp0"

echo ======================================================================
echo  R3 ShieldCore 开机自启诊断（双击入口）
echo ======================================================================
echo.

set "EXE=%~dp0diag_autostart.exe"
set "BAT=%~dp0diag_autostart.bat"
set "ARG=%~1"

if exist "%EXE%" goto :use_exe
if exist "%BAT%" goto :use_bat

echo  [错误] 同目录下既没有 diag_autostart.exe 也没有 diag_autostart.bat。
echo         请确认本文件和它们是**一起**拷过来的（同一个目录）。
echo.
echo  当前目录：%~dp0
echo  目录内容：
dir /b "%~dp0"
goto :done

:use_exe
echo  [信息] 使用原生诊断器：diag_autostart.exe
echo         （不 shell out、不依赖 Python）
echo.
if defined ARG (
    "%EXE%" "%ARG%"
) else (
    "%EXE%"
)
goto :done

:use_bat
echo  [信息] 没找到 exe，改用脚本版：diag_autostart.bat
echo.
if defined ARG (
    call "%BAT%" "%ARG%"
) else (
    call "%BAT%"
)
goto :done

:done
echo.
echo ======================================================================
echo  诊断结束。
echo ----------------------------------------------------------------------
echo  这里可以做的下一步：
echo    · 结论里有 [ 断 ] 的行 = 真正断掉的那一层，按它说的去看。
echo    · 三个断点依次排：驱动被加载 -^> 服务被 SCM 拉起 -^> 引擎被服务拉起。
echo    · 想看日志细节，去安装目录下的 r3shieldcore-svc.log。
echo    · 如果在 VM 上，**必须真正关机再开机**才算重启（挂起/快照不算）。
echo ======================================================================
echo.
echo  按「回车」或「任意键」关闭本窗口 ...
pause >nul
exit /b 0
