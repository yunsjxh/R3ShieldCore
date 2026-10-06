# v56_smoke.ps1 -- verify the packaged v56 tree end-to-end.
# ASCII-only source: PowerShell 5.1 reads .ps1 as ANSI, CJK breaks parsing.

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
$dir = Join-Path $root 'dist\R3ShieldCore-x64-v56'
$exe = Join-Path $dir 'R3 ShieldCore.exe'
$console = Join-Path $dir 'r3shieldcore-console.log'
$stats = Join-Path $dir 'r3shieldcore-stats.json'
$dskill = Join-Path $root 'tools\dskill.exe'

function Log($m) { Write-Output $m }

# CJK code points we look for (avoid literals in source):
$REPLAY = [char]0x56DE + [char]0x653E     # replay
$LOADED = [char]0x5DF2 + [char]0x8F7D     # loaded

Log "=== v56 packaged smoke ==="
Log ("dir = " + $dir)
if (-not (Test-Path $exe)) { Log "[FAIL] exe missing"; exit 1 }

# Force a known baseline in stats.json so we can prove the load path.
$statsBase = '{"totalEvents": 424242, "injectedProcesses": 999, "blockedEvents": 0, "highRiskEvents": 0, "wouldBlockEvents": 0, "topProcesses": []}'
Set-Content -Path $stats -Value $statsBase -Encoding ASCII -NoNewline
Log ("stats.json seeded: " + $statsBase)

Log ""
Log "=== [1/3] launch engine (RunAs) ==="
$proc = Start-Process -FilePath $exe -WorkingDirectory $dir -Verb RunAs -PassThru -WindowStyle Minimized
Log ("spawned, pid(from PS) = " + $proc.Id)

$enginePid = 0
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $p = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
    if ($p) { $enginePid = $p[0].Id; break }
}
if ($enginePid -eq 0) {
    Log "[FAIL] engine process not seen in 25s"
    if (Test-Path $console) { Get-Content $console -Tail 40 -Encoding UTF8 }
    exit 1
}
Log ("engine pid = " + $enginePid)

Log ""
Log "=== [2/3] wait for startup banner (up to 25s) ==="
$loadedLine = $null
$replayLine = $null
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $console) {
        $txt = Get-Content $console -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($txt) {
            $lines = $txt -split "`r?`n"
            if (-not $loadedLine) {
                $loadedLine = $lines | Where-Object { $_.IndexOf($LOADED) -ge 0 } | Select-Object -First 1
            }
            if (-not $replayLine) {
                $replayLine = $lines | Where-Object { $_.IndexOf($REPLAY) -ge 0 } | Select-Object -First 1
            }
            if ($loadedLine -and $replayLine) { break }
        }
    }
}
if ($loadedLine) { Log ("[OK] " + $loadedLine) } else { Log "[FAIL] no 'loaded stats' line" }
if ($replayLine) { Log ("[OK] " + $replayLine) } else { Log "[WARN] no replay line" }

Log ""
Log "=== [3/3] stop engine + inspect ==="
& $dskill $enginePid (Join-Path $dir '_dskill_out.txt') | Out-Null
Start-Sleep -Seconds 2
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) {
    & $dskill $still[0].Id | Out-Null
    Start-Sleep -Seconds 2
    $still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
}
if ($still) { Log "[FAIL] engine still running" } else { Log "[OK] engine stopped" }

Log ""
Log "---- stats.json after run ----"
if (Test-Path $stats) { Get-Content $stats -Raw -Encoding UTF8 | Write-Output } else { Log "(no stats.json)" }

Log ""
Log "---- console: key lines ----"
if (Test-Path $console) {
    Get-Content $console -Encoding UTF8 | Where-Object {
        ($_.IndexOf($LOADED) -ge 0) -or ($_.IndexOf($REPLAY) -ge 0)
    } | Select-Object -First 8
}
