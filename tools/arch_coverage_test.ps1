# arch_coverage_test.ps1 -- A/B test: does the engine inject 32-bit processes?
#
# Why: the package used to ship the x86 DLL as `64\R3ShieldCoreLib-x86.dll`,
# while dll_inject.cpp:409 asks for `<deploy>\32\r3shieldcore-lib.dll`
# (GetEnginePath() returns a FOLDER named "32" or "64"). So 32-bit injection
# failed silently -- zero events for every 32-bit process, with no warning.
#
# This script proves the fix end to end:
#   - launch the engine (elevated)
#   - launch a 32-bit probe AND a 64-bit probe (same source, same dir)
#   - the 64-bit one is the CONTROL: if it has no events either, the engine is
#     not injecting at all and the test proves nothing.
#
# ASCII-only source (PS 5.1 reads .ps1 as ANSI).
#
# Usage: & 'D:\...\arch_coverage_test.ps1' [deployDir]

$ErrorActionPreference = 'Continue'

$root = Split-Path $PSScriptRoot -Parent
if ($args.Count -ge 1 -and $args[0]) { $dir = $args[0] } else { $dir = Join-Path $root 'dist\R3ShieldCore-x64-v57' }

$exe        = Join-Path $dir 'R3 ShieldCore.exe'
$console    = Join-Path $dir 'r3shieldcore-console.log'
$events     = Join-Path $dir 'r3shieldcore-events.log'
$startupErr = Join-Path $dir 'r3shieldcore-startup-error.log'
$dskill     = Join-Path $root 'tools\dskill.exe'

$probe32 = Join-Path $root '_t\x86probe\rg32probe.exe'
$probe64 = Join-Path $root '_t\x86probe\rg64probe.exe'
$report  = Join-Path $root '_t\x86probe\rgprobe-report.txt'

function Log($m) { Write-Output $m }

# r3shieldcore-console.log / r3shieldcore-events.log mix GBK (printf) and UTF-8 -> decode as GBK
function Read-LogFile($path) {
    if (-not (Test-Path $path)) { return '' }
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::GetEncoding(936))
        $t = $sr.ReadToEnd(); $sr.Close(); $fs.Close()
        return $t
    } catch { return '' }
}

Log "=== arch coverage A/B test ==="
Log ("deploy dir = " + $dir)

# ---- 0. preconditions --------------------------------------------------------
foreach ($p in @($exe, $dskill, $probe32, $probe64)) {
    if (-not (Test-Path $p)) { Log ("[FAIL] missing: " + $p); exit 1 }
}
$dll32 = Join-Path $dir '32\r3shieldcore-lib.dll'
$dll64 = Join-Path $dir '64\r3shieldcore-lib.dll'
if (-not (Test-Path $dll64)) { Log "[FAIL] 64\r3shieldcore-lib.dll is MISSING"; exit 1 }
if (Test-Path $dll32) {
    Log "[ OK ] both arch DLLs present (32\ and 64\)"
} else {
    # Do NOT abort: the behavioural consequence (0 events for 32-bit) is the
    # evidence we want to see. Aborting here would hide it.
    Log "[WARN] 32\r3shieldcore-lib.dll is MISSING -> expect ZERO 32-bit events"
}

$stale = Join-Path $dir '64\R3ShieldCoreLib-x86.dll'
if (Test-Path $stale) { Log "[WARN] stale 64\R3ShieldCoreLib-x86.dll still present (unused, confusing)" }

$running = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($running) { Log "[FAIL] an engine is already running; stop it first"; exit 1 }

# ---- 1. clean logs -----------------------------------------------------------
foreach ($f in @($startupErr, $console, $events, $report)) {
    if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
}

# ---- 2. launch engine (RunAs) ------------------------------------------------
Log ""
Log "=== launch engine (RunAs) ==="
$proc = Start-Process -FilePath $exe -WorkingDirectory $dir -Verb RunAs -PassThru -WindowStyle Minimized
$enginePid = 0
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $p = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
    if ($p) { $enginePid = $p[0].Id; break }
}
if ($enginePid -eq 0) { Log "[FAIL] engine never appeared"; exit 1 }
Log ("engine pid = " + $enginePid)

# let the engine settle (global hooks + first poll cycles)
Start-Sleep -Seconds 4

# ---- 3. launch both probes from THIS (medium-integrity) context ---------------
Log ""
Log "=== launch probes (32-bit and 64-bit) ==="
$p32 = Start-Process -FilePath $probe32 -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 400
$p64 = Start-Process -FilePath $probe64 -PassThru -WindowStyle Hidden
Log ("rg32probe pid = " + $p32.Id)
Log ("rg64probe pid = " + $p64.Id)

Start-Sleep -Seconds 8

# ---- 4. stop engine ----------------------------------------------------------
Log ""
Log "=== stop engine ==="
& $dskill $enginePid (Join-Path $dir '_dskill_out.txt') | Out-Null
Start-Sleep -Seconds 2
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) { & $dskill $still[0].Id | Out-Null; Start-Sleep -Seconds 2 }
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) { Log "[WARN] engine still alive" } else { Log "[OK] engine stopped" }

# ---- 5. assertions -----------------------------------------------------------
Log ""
Log "=== assertion A: probe self-report (rule-independent) ==="
# The probe reads ntdll!NtSetValueKey's prologue IN ITS OWN PROCESS and writes
# the result next to itself. E9 / FF 25 => MinHook installed a detour => the
# engine injected this process. This does NOT depend on any rule table.
$lines = @()
if (Test-Path $report) {
    $lines = @(Get-Content -Path $report -Encoding UTF8 | Where-Object { $_ -match 'arch=' })
}
Log ("report lines: " + $lines.Count)
foreach ($l in $lines) { Log ("  " + $l.Trim()) }

$r32 = $lines | Where-Object { $_ -match 'arch=x86' } | Select-Object -First 1
$r64 = $lines | Where-Object { $_ -match 'arch=x64' } | Select-Object -First 1

$fail = 0
if ($r64) {
    if ($r64 -match 'hooked=1') { Log "[PASS] x64 probe: injected (control ok)" }
    else { Log "[FAIL] x64 probe NOT injected -> engine is not injecting at all; test inconclusive"; $fail = 1 }
} else { Log "[FAIL] x64 probe produced no report line -> it never ran"; $fail = 1 }

if ($r32) {
    if ($r32 -match 'hooked=1') { Log "[PASS] x86 probe: injected (the fix works)" }
    else { Log "[FAIL] x86 probe NOT injected -> 32-bit injection still broken"; $fail = 1 }
} else { Log "[FAIL] x86 probe produced no report line -> it never ran"; $fail = 1 }

Log ""
Log "=== assertion B: events attributed to each probe (secondary) ==="
$txt = Read-LogFile $events
$n32 = ([regex]::Matches($txt, '\[rg32probe\.exe\]')).Count
$n64 = ([regex]::Matches($txt, '\[rg64probe\.exe\]')).Count
Log ("events FROM rg32probe.exe (process-name field) : " + $n32)
Log ("events FROM rg64probe.exe (process-name field) : " + $n64)
Log "NOTE: matching the [name] FIELD, not a substring -- a SPAWN BLOCK line also"
Log "      carries the path in image=, and counting that would be a false pass."

Log ""
Log "=== sample event lines ==="
($txt -split "`n") | Where-Object { $_ -match '\[rg32probe\.exe\]|\[rg64probe\.exe\]' } | Select-Object -First 6 | ForEach-Object { Log ("  " + $_.Trim()) }

Log ""
if ($fail -eq 0) { Log "RESULT: PASS -- both architectures covered" } else { Log "RESULT: FAIL" }
exit $fail
