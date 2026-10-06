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
echo === R3ShieldCore superdesk A-recipe self-test ===
if exist superdesk-panel.log del superdesk-panel.log
"R3 ShieldCore.exe" --superdesk-selftest
echo.
echo === superdesk-panel.log ===
if exist superdesk-panel.log ( type superdesk-panel.log ) else ( echo [X] log not written )
echo.
echo [i] PASS requires: desktop=Winlogon  system=1  uiaccess=1  and rc=0
pause
