@echo off
rem ============================================================================
rem  界面预览启动器（--gui-preview）
rem
rem  用法:
rem     preview.bat                  概览页（玻璃实时跟随背后的窗口）
rem     preview.bat config           直接进配置页
rem     preview.bat log              直接进事件日志
rem     preview.bat process          直接进进程页
rem     preview.bat ark              直接进 ARK 页
rem     preview.bat advanced         直接进高级页
rem
rem     preview.bat overview freeze  背景冻住（截图用：拖窗口时玻璃不跟着变）
rem     preview.bat color            背后先放一个彩色渐变窗口，看玻璃透视效果
rem
rem  说明:
rem    · 预览模式不初始化注入引擎、不 hook 任何进程，可以安全反复开关。
rem    · 关掉窗口即退出。本 exe 是免提权构建（asInvoker），不弹 UAC。
rem    · 默认实时抓背景：拖动窗口 / 背后换窗口时，玻璃里跟着变。
rem    · 加 freeze 才冻住。跑验收闸门时脚本自己会设这个开关。
rem ============================================================================
setlocal

set "HERE=%~dp0"
set "EXE=%HERE%..\R3ShieldCore\BuildCheck\R3 ShieldCore.exe"

if not exist "%EXE%" (
    echo [错误] 找不到主程序:
    echo        %EXE%
    echo        先构建: R3SHIELDCORE_NO_UAC=1 bash build.sh BuildCheck x64
    pause
    exit /b 1
)

set "TAB=%~1"
set "MODE=%~2"
if "%TAB%"=="" set "TAB=overview"

if /i "%TAB%"=="color" (
    if exist "%HERE%_color_bg.exe" (
        start "" "%HERE%_color_bg.exe" 20
        ping -n 3 127.0.0.1 >nul
    ) else (
        echo [提示] 没有 _color_bg.exe，用普通桌面做背景。
    )
    set "TAB=overview"
)

set "R3SHIELDCORE_START_TAB=%TAB%"
set "R3SHIELDCORE_PREVIEW_FREEZEBG="
if /i "%MODE%"=="freeze" set "R3SHIELDCORE_PREVIEW_FREEZEBG=1"

start "" "%EXE%" --gui-preview

endlocal
