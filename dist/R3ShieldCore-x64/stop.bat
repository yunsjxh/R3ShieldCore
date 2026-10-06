@echo off
REM ============================================================
REM  R3ShieldCore 引擎 -- 停止（逃生门）
REM
REM  用法：双击即可（脚本会自己弹 UAC 提权），
REM        也可以右键 -> 以管理员身份运行。
REM
REM  ★★★【坑 1】本文件必须保持 CRLF 行尾 + GBK 编码，否则 cmd.exe
REM      的批处理解析器会失同步，现象 = 窗口**一闪而过**。
REM      改完请跑：  bash fix_bat_encoding.sh fix
REM
REM  ★★★【坑 2】tasklist 默认表格输出把「映像名称」列截断到 25 个
REM      字符，而 R3 ShieldCore.exe 有 26 个字符（显示成
REM      R3 ShieldCore.ex）—— 所以本文件一律用
REM        tasklist /nh /fo csv /fi "imagename eq ..."
REM      取全名（CSV 不截断，/fi 本身是精确匹配）。
REM
REM  ★★★【坑 3】没匹配到时 tasklist 仍然往 stdout 打一行
REM      「信息: 没有运行的任务匹配指定标准。」且 exit code = 0。
REM      用 `tokens=2 delims=,` 取第 2 列：这行提示**没有逗号**，
REM      取不到第 2 个 token -> 循环体不执行 -> PID 保持为空 = 没找到。
REM
REM  ★★★★【坑 4 · v45】**本文件是"引擎正在运行"时执行的**，所以
REM      它绝不能 spawn System32 下的程序 —— 那些会被引擎自己拦掉
REM      （`\Windows\System32\` 是片段规则 => System32 下每个程序都判
REM      HIGH；block 模式对 highRisk 的进程创建**直接拒**）。
REM      实测（tools/procpath_probe.exe）HIGH 的有：net.exe / cmd.exe /
REM        powershell.exe / reg.exe / sc.exe / schtasks.exe …
REM      放行的有：tasklist / findstr / find / timeout / icacls /
REM        whoami / hostname / where / ping / ipconfig / netstat …
REM      因此：
REM        · 管理员判据用 whoami 的完整性级别，**不用 `net session`**；
REM        · 提权用的 powershell.exe 也会被拦 => 引擎跑着的时候
REM          **本脚本无法自己提权**，必须右键"以管理员身份运行"。
REM          这一点在 :NO_ELEV 里向用户讲清楚（含原因）。
REM ============================================================
setlocal
cd /d "%~dp0"

REM ---- [1/4] 取 PID（★ CSV 第 2 列，见文件头坑 3）----
echo 查找引擎进程...
set "PID="
for /f "tokens=2 delims=," %%p in ('tasklist /nh /fo csv /fi "imagename eq R3 ShieldCore.exe" 2^>nul') do set "PID=%%~p"

REM 保险：只接受纯数字，避免把任何提示文字当成 PID
if defined PID (
    echo %PID%| findstr /r /c:"^[0-9][0-9]*$" >nul
    if errorlevel 1 set "PID="
)

if not defined PID (
    echo [提示] 没有找到正在运行的引擎。
    pause & exit /b 0
)
echo 引擎 PID = %PID%

REM ---- [2/4] 管理员权限（★ 不用 net session，理由见文件头坑 4）----
REM   whoami 走全路径：PATH 里可能有同名程序顶掉它，而且全路径
REM   也在 kCommonTrustedSystemConsoleTools 的豁免里。
set "IS_ADMIN=0"
"%SystemRoot%\System32\whoami.exe" /groups 2>nul | findstr /c:"S-1-16-12288" /c:"S-1-16-16384" >nul
if not errorlevel 1 set "IS_ADMIN=1"

if "%IS_ADMIN%"=="0" (
    if /i "%~1"=="/elevated" (
        echo [错误] 需要管理员权限。请右键本文件 -^> 以管理员身份运行。
        pause & exit /b 1
    )
    echo [信息] 需要管理员权限才能停掉引擎，正在请求提权...
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath (Resolve-Path '.\stop.bat').Path -ArgumentList '/elevated' -Verb RunAs" >nul 2>&1
    if not errorlevel 1 (
        echo        已在新窗口继续，本窗口关闭。
        exit /b 0
    )
    call :NO_ELEV
    exit /b 1
)

REM ---- [3/4] 用逃生门 dskill 停掉 ----
REM   dskill.exe 在部署目录里（不是 System32），所以它自己能起来；
REM   它用的是**直 syscall**，绕开 ntdll 上被 hook 的 NtOpenProcess。
echo 用逃生门 dskill 停止...
"dskill.exe" %PID%
set "DSKILL_RC=%errorlevel%"
timeout /t 2 /nobreak >nul

REM ---- [4/4] 复查（同样用 CSV + 逗号判定，见文件头坑 2/3）----
tasklist /nh /fo csv /fi "imagename eq R3 ShieldCore.exe" 2>nul | findstr /c:"," >nul
if errorlevel 1 (
    echo [OK] 引擎已停止。
    pause & exit /b 0
)

echo.
echo [警告] 引擎仍在运行（dskill 返回码 %DSKILL_RC%）。
echo        请手动关掉引擎的控制台窗口，或者右键本文件
echo        -^> 以管理员身份运行 之后再试一次。
echo.
pause
exit /b 1

REM ============================================================
REM  提权失败时的说明（上面 `call :NO_ELEV` 进来）
REM
REM  ★ 这里必须把**真正的原因**讲出来。原来只写"提权被取消或失败"，
REM    会让人以为是 UAC 的问题；实际原因是引擎在跑，而 powershell.exe
REM    被引擎自己的进程规则拦掉了。
REM  ★ 用 `call :label` 而不是在 if(...) 块里 `goto` —— 块内 goto 虽然
REM    能用，但它是 cmd 的经典坑（配合 else 时行为诡异）；子程序调用
REM    语义明确，而且可以单独测。
REM ============================================================
:NO_ELEV
echo.
echo [错误] 无法自动提权，请手动提权。
echo.
echo   原因：引擎正在运行，而提权要调用 powershell.exe —— 它是
echo         System32 下的高危程序，会被引擎自己的进程规则
echo         （PROC BLOCK HIGH CreateProcess）拦掉。
echo         也就是说：**引擎跑着的时候，脚本没法自己提权。**
echo.
echo   请改用（任选其一）：
echo     1) 右键本文件 -^> 以管理员身份运行
echo     2) 直接关掉引擎的控制台窗口
echo.
pause
exit /b 1
