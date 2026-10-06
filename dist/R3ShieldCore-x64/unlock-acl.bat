@echo off
REM ============================================================
REM  R3ShieldCore 部署目录权限还原（需管理员权限）
REM
REM  【为什么会有这个脚本】
REM  v56 及更早的版本有一道硬门槛：部署目录必须加固成
REM  「Users 只读」，引擎才肯加载 DLL。加固的副作用是
REM  **连 r3shieldcore.ini 也一起被锁**，用户改完保存不了。
REM
REM  那道门禁**已在 v57 删除** —— 现在引擎从任何目录都能启动，
REM  配置文件也不再需要管理员才能改。
REM
REM  【本脚本干什么】
REM  把 ACL 还原成「从父目录继承」，抹掉历史加固留下的显式 ACE。
REM  跑完之后 r3shieldcore.ini / 几个预设 ini 都能直接双击编辑保存。
REM
REM  【什么时候需要跑】
REM  只有**从旧版本升级上来**、且目录被加固过的才需要。
REM  新部署（直接复制文件夹）继承的 ACL 本来就是对的，不用跑。
REM
REM  【它不改什么】
REM  不碰任何文件内容，只改 ACL。引擎能不能启动与它无关。
REM
REM  用法：
REM    unlock-acl.bat         单独运行，打印前后 ACL 并暂停
REM    unlock-acl.bat -q      静默
REM
REM  ★★★ 本文件必须保持 CRLF 行尾 + GBK 编码，否则 cmd.exe 的
REM      批处理解析器会失同步，现象 = 窗口**一闪而过**。
REM      （不要加 chcp 65001：内容已是 GBK，切 UTF-8 反而乱码，
REM        而且 chcp 会干扰后面的 pause。）
REM      改完请跑：  bash fix_bat_encoding.sh fix
REM ============================================================
setlocal
cd /d "%~dp0"

set "QUIET=0"
if /i "%~1"=="-q" set "QUIET=1"
if /i "%~2"=="-q" set "QUIET=1"

REM ---- 管理员权限（自动提权；/elevated 防递归）----
REM ★ 不用 `net session` —— 它要 spawn net.exe，而 net.exe 在
REM   System32 高危规则里，引擎跑起来之后会被直接拒。
REM   改用 whoami 的**完整性级别**（S-1-16-12288 = High），只读、无副作用。
REM   ★ 走全路径：PATH 里可能有同名程序顶掉 whoami。
set "IS_ADMIN=0"
"%SystemRoot%\System32\whoami.exe" /groups 2>nul | findstr /c:"S-1-16-12288" /c:"S-1-16-16384" >nul
if not errorlevel 1 set "IS_ADMIN=1"

if "%IS_ADMIN%"=="0" (
    if /i not "%~1"=="/elevated" if /i not "%~2"=="/elevated" (
        echo [信息] 需要管理员权限，正在请求提权...
        REM ★ 不能用 set 变量再展开 —— 整个 if(...) 块是一次性解析的，
        REM   块内的 %VAR% 取的是**解析时**的值（此时还没 set）。
        if "%QUIET%"=="1" (
            "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath (Resolve-Path '.\unlock-acl.bat').Path -ArgumentList '-q /elevated' -Verb RunAs" >nul 2>&1
        ) else (
            "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath (Resolve-Path '.\unlock-acl.bat').Path -ArgumentList '/elevated' -Verb RunAs" >nul 2>&1
        )
        if errorlevel 1 (
            echo.
            echo [错误] 提权被取消或失败。
            echo        请改用：右键本文件 -^> 以管理员身份运行
            echo.
            if "%QUIET%"=="0" pause
            exit /b 1
        )
        echo        已在新窗口继续，本窗口关闭。
        exit /b 0
    )
    echo [错误] 需要管理员权限。请右键本文件 -^> 以管理员身份运行。
    if "%QUIET%"=="0" pause
    exit /b 1
)

if "%QUIET%"=="0" (
    echo === 还原前 ===
    icacls "%CD%"
    echo.
)

REM ★ /reset 把每个对象还原成「从父目录继承」—— 这会抹掉加固留下的
REM   显式 ACE。加 /T 连子对象一起还原。
REM   /C = 遇到改不动的对象继续（例如属主是 Administrators 的日志文件，
REM   非提权进程改不了它的 DACL；那些对象本来也不影响使用）。
icacls "%CD%" /reset /T /C >nul 2>&1
if errorlevel 1 (
    echo [警告] 部分对象还原失败（通常无害，日志文件属主可能是 Administrators）。
)

if "%QUIET%"=="0" (
    echo.
    echo === 还原后 ===
    icacls "%CD%"
    echo.
    echo [OK] 已还原为继承 ACL。
    echo.
    echo      现在 r3shieldcore.ini 可以直接双击编辑保存了。
    echo      引擎 v57 起不再要求目录不可写，所以这一步不影响启动。
    echo.
    echo      说明：本目录对普通用户可写是**预期的**，不是错误。
    pause
)
exit /b 0
