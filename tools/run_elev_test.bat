@echo off
REM ============================================================
REM  R3ShieldCore -- elevated-interception test (one shot)
REM
REM  Answers ONE question: does the engine still intercept a
REM  program that runs ELEVATED (admin token)?
REM
REM  Run by RIGHT-CLICK -> "Run as administrator".
REM
REM  What it does:
REM    0) cleans old elevprobe-*.out
REM    1) stops any running engine (dskill escape hatch)
REM    2) starts the engine and waits for it to come up
REM    3) runs elevprobe-admin.exe (elevated)   <- the measurement
REM    4) optional: you double-click elevprobe-user.exe (normal rights)
REM    5) stops the engine
REM    6) bundles probes + engine logs into elev-test-result.txt
REM
REM  * WHY IT DOES NOT RUN elevprobe-user.exe ITSELF:
REM    "asInvoker" means "run at the SAME level as the parent". A child
REM    spawned from this (elevated) script inherits the elevated token,
REM    so elevprobe-user.exe would ALSO run elevated and the A/B
REM    comparison would be meaningless. The non-elevated variant must
REM    be started from a normal (medium integrity) context -> you
REM    double-click it. Step 4 below waits for you.
REM
REM  WHY THIS FILE IS PURE ASCII:
REM    A .bat with non-ASCII bytes AND LF-only line endings desyncs the
REM    cmd.exe batch parser (window flashes and dies). Keep it ASCII,
REM    or run:  bash fix_bat_encoding.sh fix
REM ============================================================
setlocal
cd /d "%~dp0"

set "DIST=%~dp0..\dist\R3ShieldCore-x64"
set "RESULT=%~dp0elev-test-result.txt"
set "ENGINE=R3 ShieldCore.exe"

REM ---- admin check (full path: PATH may shadow whoami) ----
"%SystemRoot%\System32\whoami.exe" /groups 2>nul | findstr /c:"S-1-16-12288" /c:"S-1-16-16384" >nul
if errorlevel 1 (
    echo [ERROR] Administrator rights required.
    echo         Right-click this file -^> "Run as administrator".
    pause
    exit /b 1
)

echo ============================================
echo  R3ShieldCore elevated-interception test
echo ============================================
echo.

if not exist "%DIST%\%ENGINE%" (
    echo [ERROR] engine not found: %DIST%\%ENGINE%
    pause & exit /b 1
)
if not exist "%~dp0elevprobe-admin.exe" (
    echo [ERROR] elevprobe-admin.exe not found next to this script.
    pause & exit /b 1
)

REM ---- 0. clean old probe outputs ----
echo [0] cleaning old elevprobe-*.out ...
del /q "%~dp0elevprobe-*.out" 2>nul

REM ---- 1. stop a running engine (CSV + dskill, see stop.bat) ----
echo [1] stopping any running engine ...
for /f "tokens=2 delims=," %%p in ('tasklist /nh /fo csv /fi "imagename eq %ENGINE%" 2^>nul') do "%DIST%\dskill.exe" %%~p
timeout /t 2 /nobreak >nul

REM ---- 2. start the engine ----
echo [2] starting engine ...
start "" "%DIST%\%ENGINE%"
timeout /t 4 /nobreak >nul
tasklist /nh /fo csv /fi "imagename eq %ENGINE%" 2>nul | findstr /c:"," >nul
if errorlevel 1 (
    echo     [ERROR] engine did not stay up.
    echo             see %DIST%\r3shieldcore-startup-error.log
    pause & exit /b 1
)
echo     engine is running (mode = see r3shieldcore.ini).

REM ---- 3. elevated probe: THE measurement ----
echo.
echo [3] running elevprobe-admin.exe ^(ELEVATED^) ...
"%~dp0elevprobe-admin.exe" --no-pause
timeout /t 2 /nobreak >nul

REM ---- 4. optional non-elevated probe ----
echo.
echo ============================================================
echo  [4] OPTIONAL A/B: the engine is STILL RUNNING.
echo      Double-click   %~dp0elevprobe-user.exe
echo      (normal rights -- do NOT "run as administrator"),
echo      wait for it to finish, then press any key here.
echo      Press a key now if you want to skip this.
echo ============================================================
pause >nul

REM ---- 5. stop the engine ----
echo.
echo [5] stopping engine ...
for /f "tokens=2 delims=," %%p in ('tasklist /nh /fo csv /fi "imagename eq %ENGINE%" 2^>nul') do "%DIST%\dskill.exe" %%~p
timeout /t 2 /nobreak >nul

REM ---- 6. bundle the evidence ----
echo.
echo [6] collecting evidence ...
>"%RESULT%" echo ==== R3ShieldCore elevated-interception test ====
>>"%RESULT%" echo date: %DATE% %TIME%
>>"%RESULT%" echo.
>>"%RESULT%" echo ---- probe outputs (elevprobe-*.out) ----
type "%~dp0elevprobe-*.out" >>"%RESULT%" 2>nul
>>"%RESULT%" echo.
>>"%RESULT%" echo ---- r3shieldcore-events.log ----
type "%DIST%\r3shieldcore-events.log" >>"%RESULT%" 2>nul
>>"%RESULT%" echo.
>>"%RESULT%" echo ---- r3shieldcore-console.log ----
type "%DIST%\r3shieldcore-console.log" >>"%RESULT%" 2>nul

echo.
echo ============================================
echo  DONE. Send this file back:
echo    %RESULT%
echo ============================================
pause
