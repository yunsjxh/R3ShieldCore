$ErrorActionPreference = 'Continue'
# Elevated probe run, ASCII-only. Use cmd.exe (RunAs) with shell redirection.
$root = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $root '_t\channel_acl_probe.exe'
$out = Join-Path $root '_t\probe_elev.txt'

$env:P_ROOT = $root
$env:P_EXE = $exe
$env:P_OUT = $out

# cmd /s /c "cd /d "%P_ROOT%" & "%P_EXE%" c > "%P_OUT%" 2>&1"
$cmdLine = 'cd /d "%P_ROOT%" & "%P_EXE%" c > "%P_OUT%" 2>&1'
Start-Process -FilePath 'cmd.exe' -ArgumentList '/s','/c',$cmdLine -Verb RunAs -Wait -WindowStyle Hidden

Write-Output "=== probe (elevated) ==="
if (Test-Path $out) { Get-Content $out -Encoding Default } else { Write-Output "(no output file)" }
