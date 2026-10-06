@echo off
REM ============================================================
REM  R3ShieldCore 引擎 -- 启动（部署脚本，需管理员权限）
REM
REM  用法：双击即可（脚本会自己弹 UAC 提权），
REM        也可以右键 -> 以管理员身份运行。
REM
REM  ★★★【坑 1】本文件必须保持 CRLF 行尾 + GBK 编码。
REM      cmd.exe 按**字节**读批处理文件：只要文件里有非 ASCII 字符
REM      而行尾是 LF-only，解析器的行偏移就会**失同步** —— 它会把
REM      上一行的尾巴和下一行的开头拼成一条命令拿去执行。
REM      现象 = 窗口**一闪而过**（还可能蹦出
REM      'xxx' 不是内部或外部命令）。
REM      改完请跑：  bash fix_bat_encoding.sh fix
REM
REM  ★★★【坑 2】tasklist 默认的**表格**输出会把「映像名称」列
REM      截断到 25 个字符，而本程序的名字有 26 个字符：
REM        R3 ShieldCore.exe  ->  R3 ShieldCore.ex
REM      所以 `tasklist | find "R3 ShieldCore.exe"` **永远
REM      匹配不上**。本文件一律改用
REM        tasklist /nh /fo csv /fi "imagename eq ..."
REM      这个格式**不截断**，而且 /fi 本身就是精确匹配。
REM
REM  ★★★【坑 3】没匹配到时 tasklist **仍然往 stdout 打一行**
REM      「信息: 没有运行的任务匹配指定标准。」而且 **exit code 是 0**！
REM      所以既不能用 errorlevel 判断，也不能用 for /f 收行（会收到
REM      这行提示）。用 findstr 找 CSV 行特有的 ASCII 逗号来判定。
REM
REM  ★★★★【坑 4 · v45】引擎跑起来之后，**脚本不能再 spawn 任何
REM      System32 下的程序**。原因：
REM        r3shieldcore_rules.cpp 的 kProcessPathRules 里
REM        `\Windows\System32\` 是**片段**规则 => System32 下**每一个**
REM        程序都判 HIGH；而 process_guard.cpp 在 block 模式下对
REM        highRisk 的进程创建是**直接拒**（不是只记录）。
REM      实测（tools/procpath_probe.exe）：net.exe / cmd.exe /
REM        powershell.exe / reg.exe / sc.exe / schtasks.exe 全是 HIGH。
REM      由此两条硬结论：
REM        · **不能用 `net session` 判管理员** —— 它自己要 spawn net.exe，
REM          会被引擎拦掉。改用 whoami 的完整性级别（见下面 IS_ADMIN）。
REM        · **不能用 powershell 提权** —— 同样被拦。也就是：引擎跑着
REM          的时候脚本**没法自己提权**，只能右键"以管理员身份运行"。
REM      已经放行的（kCommonTrustedSystemConsoleTools）：tasklist /
REM        findstr / find / timeout / icacls / whoami / hostname / where /
REM        ping / ipconfig / netstat / attrib …
REM      这就是为什么本文件把「引擎是否已在运行」放在**提权之前**：
REM      引擎在跑就立刻退出，绝不 spawn net.exe / powershell.exe。
REM ============================================================
setlocal
cd /d "%~dp0"

REM ------------------------------------------------------------
REM [0/5] 先看引擎是不是已经在跑
REM   ★ 必须放在提权之前 —— 理由见上面坑 4。
REM ------------------------------------------------------------
tasklist /nh /fo csv /fi "imagename eq R3 ShieldCore.exe" 2>nul | findstr /c:"," >nul
if not errorlevel 1 (
    echo [提示] 引擎已在运行。如需重启，请先运行 stop.bat。
    pause & exit /b 0
)

REM ------------------------------------------------------------
REM [1/5] 管理员权限（自动提权，省得每次右键）
REM   ★ 判据 = whoami 的**完整性级别**（S-1-16-12288 = High Mandatory
REM     Level），不用 `net session`（理由见坑 4）。
REM   ★ whoami / findstr 都走**全路径**：PATH 里可能有同名程序顶掉它们
REM     （实测：某些环境里 `whoami` 会解析到别的同名程序），
REM     而且全路径也落在 kCommonTrustedSystemConsoleTools 的豁免里。
REM   ★ /elevated 是防递归的标记参数。
REM ------------------------------------------------------------
set "IS_ADMIN=0"
"%SystemRoot%\System32\whoami.exe" /groups 2>nul | findstr /c:"S-1-16-12288" /c:"S-1-16-16384" >nul
if not errorlevel 1 set "IS_ADMIN=1"

if "%IS_ADMIN%"=="0" (
    if /i not "%~1"=="/elevated" (
        echo [信息] 需要管理员权限，正在请求提权...
        "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath (Resolve-Path '.\start.bat').Path -ArgumentList '/elevated' -Verb RunAs" >nul 2>&1
        if errorlevel 1 (
            echo.
            echo [错误] 提权被取消或失败。
            echo        请改用：右键本文件 -^> 以管理员身份运行
            echo.
            pause
            exit /b 1
        )
        echo        已在新窗口继续，本窗口关闭。
        exit /b 0
    )
    echo [错误] 需要管理员权限。请右键本文件 -^> 以管理员身份运行。
    pause
    exit /b 1
)

echo ============================================
echo  R3ShieldCore 引擎 -- 启动（模式见 r3shieldcore.ini）
echo ============================================
echo.

REM ------------------------------------------------------------
REM [2/5] 必要文件检查
REM ------------------------------------------------------------
if not exist "R3 ShieldCore.exe" (
    echo [错误] 未找到 R3 ShieldCore.exe
    pause & exit /b 1
)
if not exist "64\r3shieldcore-lib.dll" (
    echo [错误] 未找到 64\r3shieldcore-lib.dll
    pause & exit /b 1
)

REM ------------------------------------------------------------
REM [3/5] 检查配置可写性 —— v57 起**不再加固目录 ACL**
REM   v56 及更早有一道硬门槛：部署目录必须加固成 Users 只读，
REM   引擎才肯加载 DLL。副作用是 r3shieldcore.ini 也被一起锁，
REM   用户改完保存不了。
REM   那道门禁已在 v57 删除 —— 引擎从可写目录也能正常启动，
REM   所以这里**不再改任何 ACL**，只在旧加固目录上提示怎么修。
REM ------------------------------------------------------------
echo [3/5] 检查配置可写性（v57 起不再加固目录 ACL）...
copy /y nul "%~dp0._wtest.tmp" >nul 2>&1
if not exist "%~dp0._wtest.tmp" goto :rg_acl_warn
del "%~dp0._wtest.tmp" >nul 2>&1
echo       完成：目录可写，r3shieldcore.ini 可以直接编辑保存。
goto :rg_acl_ok
:rg_acl_warn
echo.
echo [警告] 本目录**不可写** —— r3shieldcore.ini 改完会保存不了。
echo        这通常是旧版本加固留下的 ACL。修复：
echo            右键 unlock-acl.bat  -^>  以管理员身份运行
echo        （引擎本身不受影响，v57 起从可写目录也能启动。）
echo.
:rg_acl_ok

REM ------------------------------------------------------------
REM [4/5] 信息：部署目录是否对外开放写权限
REM   ★ v57 起这只是**信息**，不再作为启动条件 ——
REM     「对外可写」是预期状态，不是错误。
REM ------------------------------------------------------------
echo [4/5] 部署目录 ACL：不再作为启动条件（v57 起目录可写也能启动）

REM ------------------------------------------------------------
REM [5/5] 启动引擎 + 确认存活
REM   ★ 存活检查用 tasklist CSV + findstr 逗号（坑 2 + 坑 3）；
REM     timeout 也在放行名单里，所以这一步不会被引擎自己拦。
REM ------------------------------------------------------------
echo [5/5] 启动引擎...
start "" "R3 ShieldCore.exe"

echo       等待 3 秒确认存活...
timeout /t 3 /nobreak >nul
tasklist /nh /fo csv /fi "imagename eq R3 ShieldCore.exe" 2>nul | findstr /c:"," >nul
if errorlevel 1 (
    echo.
    echo [错误] 引擎未成功启动 —— 它启动后立刻退出了。
    echo        常见原因：64\ 下没有 DLL、清单没过、或被别的安全软件拦了。
    echo        下面这份日志通常能直接指出原因：
    echo.
    if exist "r3shieldcore-startup-error.log" (
        echo        r3shieldcore-startup-error.log 内容：
        echo        ------------------------------------------
        type "r3shieldcore-startup-error.log"
        echo        ------------------------------------------
    ) else (
        echo        没有找到 r3shieldcore-startup-error.log —— 它可能压根没启动
    )
    echo.
    pause & exit /b 1
)

echo.
echo [OK] 引擎已启动（控制台窗口应该已经出现）。
echo.
echo      日志：
echo        r3shieldcore-events.log    拦截事件
echo        r3shieldcore-console.log     引擎自述
echo                               ★ 关键证据：注入新进程 N 个
echo.
echo      停止：运行 stop.bat，或关掉引擎控制台窗口。
echo.
echo      下一步（验证拦截真的生效）：
echo        运行 tools\inject_race_probe.exe 做注入盲区实测。
echo.
pause
