@echo off
setlocal
cd /d "%~dp0..\R3ShieldCore\Release"
if not exist "R3 ShieldCore.exe" ( echo [X] R3 ShieldCore.exe not found in %CD% & pause & exit /b 1 )

net session >nul 2>nul
if errorlevel 1 (
  echo [i] not elevated - relaunching with UAC ...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo === R3ShieldCore UIAccess handoff self-test ===
echo [i] This runs LaunchUiAccessInstance -- the SAME function the
echo     "super topmost" button calls. No engine is started.
echo.
if exist superdesk-panel.log del superdesk-panel.log
rem Clear r3shieldcore-console.log too, so the [diag]/handoff lines below belong ONLY
rem to THIS run -- otherwise old err=1460 history masquerades as a live failure.
if exist r3shieldcore-console.log del r3shieldcore-console.log
if exist engine-console-*.log del engine-console-*.log
rem NOTE: "start /wait" is REQUIRED. This exe is GUI-subsystem, so cmd does
rem       NOT wait for it when called directly -- the type/findstr below would
rem       then read a stale or empty file and report the wrong result.
start "" /wait "R3 ShieldCore.exe" --uiaccess-selftest
echo.
echo === superdesk-panel.log ===
if exist superdesk-panel.log ( type superdesk-panel.log ) else ( echo [X] log not written )
echo.
echo === r3shieldcore-console.log : redirect status ===
if exist r3shieldcore-console.log findstr /C:"[diag] redirect" r3shieldcore-console.log
echo.
echo === r3shieldcore-console.log : UIAccess handoff lines ===
if exist r3shieldcore-console.log findstr /C:"UIAccess handoff" r3shieldcore-console.log
echo.
echo [i] PASS requires: ok=1, child alive after 3s=1, rc=0
pause
