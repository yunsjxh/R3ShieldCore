@echo off
rem R3ShieldCore input/focus diagnostic launcher (pure ASCII, CRLF)
rem Double-click = it will ask which app is broken, so the focus/cursor
rem checks land on THAT app instead of on this console window.
setlocal
set "PS=powershell.exe"
set "PSCAND=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%PSCAND%" set "PS=%PSCAND%"

set "TARGET="
if "%~1"=="" if not defined NOPAUSE (
    echo.
    echo ============================================================
    echo  Which app is broken?
    echo   - type its process name, e.g.  notepad   or   chrome
    echo   - or type its PID, e.g.  1234
    echo   - or just press Enter to skip
    echo  Skipping means the focus/cursor checks may measure THIS
    echo   console window instead of the app that actually fails.
    echo ============================================================
    set /p TARGET=" Target app: "
)

set "TARGS="
if defined TARGET set "TARGS=-TargetApp %TARGET%"

"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0diag-input-focus.ps1" %TARGS% %*
set RC=%ERRORLEVEL%
echo.
echo exit code = %RC%
if not defined NOPAUSE pause
endlocal
