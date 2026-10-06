# v56_persist.ps1 -- prove stats carry across restarts.
# ASCII-only source.
#
# Round 1: run engine ~40s (so the 30s fallback-save fires), then dskill it.
# Round 2: run engine again, confirm it LOADS the value written in round 1.

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
$dir = Join-Path $root 'dist\R3ShieldCore-x64-v56'
$exe = Join-Path $dir 'R3 ShieldCore.exe'
$console = Join-Path $dir 'r3shieldcore-console.log'
$stats = Join-Path $dir 'r3shieldcore-stats.json'
$dskill = Join-Path $root 'tools\dskill.exe'

$LOADED = [char]0x5DF2 + [char]0x8F7D          # 'loaded'
$REPLAY = [char]0x56DE + [char]0x653E          # 'replay'
$NOTHING = [char]0x65E0 + [char]0x53EF         # 'nothing to load'

function Log($m) { Write-Output $m }

function Launch-And-Wait($seconds) {
    $proc = Start-Process -FilePath $exe -WorkingDirectory $dir -Verb RunAs -PassThru -WindowStyle Minimized
    $pid2 = 0
    $deadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
        $p = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
        if ($p) { $pid2 = $p[0].Id; break }
    }
    if ($pid2 -eq 0) { return 0 }
    Log ("  engine pid = " + $pid2 + ", holding " + $seconds + "s ...")
    Start-Sleep -Seconds $seconds
    & $dskill $pid2 (Join-Path $dir '_dskill1.txt') | Out-Null
    Start-Sleep -Seconds 2
    $still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
    if ($still) { & $dskill $still[0].Id | Out-Null; Start-Sleep -Seconds 2 }
    return $pid2
}

# ---------- Round 1 ----------
Log "=== ROUND 1: run 40s so the 30s fallback-save fires ==="
$c0 = 0
if (Test-Path $console) { $c0 = (Get-Item $console).Length }
$null = Launch-And-Wait 40
Log ("  console grew from " + $c0 + " to " + (Get-Item $console).Length + " bytes")

Log ""
Log "---- round-1 tail ----"
Get-Content $console -Encoding UTF8 | Select-Object -Last 6

Log ""
Log "---- stats.json after round 1 ----"
if (Test-Path $stats) {
    Log ("  EXISTS, " + (Get-Item $stats).Length + " bytes")
    Get-Content $stats -Raw -Encoding UTF8 | Write-Output
} else {
    Log "  (NO stats.json -- fallback save did not fire)"
}

Log ""
Log "=== ROUND 2: relaunch, expect it to LOAD round-1 value ==="
$null = Launch-And-Wait 12
Log ""
Log "---- round-2 load line ----"

# r3shieldcore-console.log mixes GBK (printf) and UTF-8 (ConsoleLog) -- decode as
# GBK, not UTF8, or the CJK needles never match (they silently become 0 hits).
$bytes = [System.IO.File]::ReadAllBytes($console)
$txt = [System.Text.Encoding]::GetEncoding(936).GetString($bytes)
$lines = $txt -split "`r?`n"
$hit2 = $lines | Where-Object { $_.IndexOf($LOADED) -ge 0 }
if ($hit2) { $hit2 | ForEach-Object { Log ("[LOAD] " + $_) } }
else { Log "[FAIL] no 'loaded' line in round 2" }
$hit3 = $lines | Where-Object { $_.IndexOf($REPLAY) -ge 0 }
if ($hit3) { $hit3 | ForEach-Object { Log ("[REPLAY] " + $_) } }
else { Log "[FAIL] no 'replay' line in round 2" }
