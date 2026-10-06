# v55_smoke.ps1 -- end-to-end smoke (kept in ONE process; bash forks fail while engine runs)
# ASCII-only source: PowerShell 5.1 reads .ps1 as ANSI, so CJK breaks parsing.

$ErrorActionPreference = 'Continue'
# Avoid CJK literals entirely: PSScriptRoot is .../tools, so root = its parent.
$root = Split-Path $PSScriptRoot -Parent
$dir = Join-Path $root '_t\v55_smoke'
$exe = Join-Path $dir 'R3 ShieldCore.exe'
$console = Join-Path $dir 'r3shieldcore-console.log'
$stats = Join-Path $dir 'r3shieldcore-stats.json'
$dskill = Join-Path $root 'tools\dskill.exe'

function Log($m) { Write-Output $m }

Log "=== [1/4] launch engine (RunAs, silent-elevate) ==="
$baseLen = 0
if (Test-Path $console) { $baseLen = (Get-Item $console).Length }
Log ("console base bytes: " + $baseLen)

$proc = Start-Process -FilePath $exe -WorkingDirectory $dir -Verb RunAs -PassThru -WindowStyle Minimized
Log ("spawned, pid(from PS) = " + $proc.Id)

$enginePid = 0
$spawnDeadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $spawnDeadline) {
    Start-Sleep -Milliseconds 300
    $p = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
    if ($p) { $enginePid = $p[0].Id; break }
}
if ($enginePid -eq 0) {
    Log "[FAIL] engine process not seen in 20s"
    if (Test-Path $console) { Get-Content $console -Tail 40 }
    exit 1
}
Log ("engine pid = " + $enginePid)

Log ""
Log "=== [2/4] wait for replay (up to 25s) ==="
$replayLine = $null
$watchDeadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $watchDeadline) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $console) {
        $txt = Get-Content $console -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($txt -and ($txt.IndexOf([char]0x56DE + [char]0x653E) -ge 0)) {   # 'replay' in CJK
            $lines = $txt -split "`r?`n"
            $hit = $lines | Where-Object { $_.IndexOf([char]0x56DE + [char]0x653E) -ge 0 } | Select-Object -First 1
            $replayLine = $hit
            break
        }
    }
}
if ($replayLine) { Log ("[OK] " + $replayLine) } else { Log "[FAIL] no replay line in 25s" }

Log ""
Log "=== [3/4] stop engine (dskill) ==="
& $dskill $enginePid (Join-Path $dir '_dskill_out.txt') | Out-Null
Start-Sleep -Seconds 2
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) {
    Log ("[WARN] still alive pid=" + $still[0].Id + " -- second shot")
    & $dskill $still[0].Id | Out-Null
    Start-Sleep -Seconds 2
    $still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
}
if ($still) { Log "[FAIL] engine still running" } else { Log "[OK] engine stopped" }

Log ""
Log "=== [4/4] check persisted artifacts ==="
if (Test-Path $stats) {
    Log ("[OK] r3shieldcore-stats.json created, " + (Get-Item $stats).Length + " bytes")
    Log "---- stats content ----"
    Get-Content $stats -Raw -Encoding UTF8 | Write-Output
} else {
    Log "[FAIL] r3shieldcore-stats.json NOT created"
}

Log ""
Log "---- r3shieldcore-console.log tail 70 lines ----"
if (Test-Path $console) { Get-Content $console -Tail 70 -Encoding UTF8 } else { Log "(no console)" }
