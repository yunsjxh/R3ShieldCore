# v61_procwatch_probe.ps1 -- PROVE the high-risk-process watch can still FIRE.
#
# Why this exists (iron rule 54: a fix with no reverse control proves nothing):
#   v61 first ran on a real desktop and reported 5 candidates in 270 processes --
#   ALL of them false positives (explorer.exe in the Windows ROOT, four UWP hosts
#   in SystemApps). The fix narrowed the "canonical directory" check.
#   After the fix the same desktop reports **0** candidates -- which is the
#   desired result, but "0" is ALSO what you would see if the criterion had been
#   accidentally disabled entirely. This probe supplies the missing control:
#   plant a process that MUST be reported, and assert it is.
#
# Method:
#   1. copy a real system binary into a user-writable dir under a protected
#      system-component NAME  ->  that is exactly the "masquerade" signature
#   2. start it BEFORE the engine  ->  proves the "no observation window needed"
#      claim too (the engine sees processes that were already running)
#   3. run the proven engine start/stop path (tools/v57_smoke.ps1)
#   4. assert the console contains a [procwatch] high-risk line naming our path
#   5. kill + delete the planted file (always, even on failure)
#
# ASCII-only source (PS 5.1 reads .ps1 as ANSI). CJK needles are built from
# code points.

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
if ($args.Count -ge 1 -and $args[0]) {
    $dir = $args[0]
} else {
    $dir = Join-Path $root 'dist\R3ShieldCore-x64'
}

$console = Join-Path $dir 'r3shieldcore-console.log'

# Needles (code points -- no literal CJK in this file).
$HR      = [char]0x9AD8 + [char]0x5371 + [char]0x8FDB + [char]0x7A0B            # 'high-risk process'
$PW      = '[procwatch]'
$MASK    = [char]0x4F2A + [char]0x88C5 + [char]0x7CFB + [char]0x7EDF + [char]0x8FDB + [char]0x7A0B + [char]0x540D  # 'masquerading as system process name'

function Log($m) { Write-Output $m }

# r3shieldcore-console.log mixes GBK (printf) and UTF-8 (ConsoleLog) -> decode as GBK.
function Read-LogFile($path) {
    if (-not (Test-Path $path)) { return '' }
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::GetEncoding(936))
        $t = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        return $t
    } catch { return '' }
}

# ---- 1. plant the masquerading process --------------------------------------
$plantDir  = [System.IO.Path]::GetTempPath()
$plantExe  = Join-Path $plantDir 'svchost.exe'
$plantPid  = 0
$ok = $false

try {
    # ★ Payload choice matters. On Windows 11 `System32\notepad.exe` is a STUB
    #   that hands off to the packaged Store app and EXITS immediately -- the
    #   planted process was gone before the engine started, so the probe failed
    #   with "not reported" and looked exactly like a product bug (it was a
    #   TEST bug). cmd.exe driven with a long ping keeps the image alive for the
    #   whole engine run.
    $source = Join-Path $env:SystemRoot 'System32\cmd.exe'
    if (-not (Test-Path $source)) { Log "[FAIL] no $source to copy"; exit 1 }

    # Copy via .NET (not Copy-Item) so a policy-wrapped shell cannot interfere.
    [System.IO.File]::Copy($source, $plantExe, $true)
    Log ("[OK] planted " + $plantExe + " (" + (Get-Item $plantExe).Length + " B)")

    $p = Start-Process -FilePath $plantExe -ArgumentList '/c','ping','-n','40','127.0.0.1' `
        -PassThru -WindowStyle Minimized
    $plantPid = $p.Id
    Start-Sleep -Milliseconds 1500

    # ★ Premise check (iron rule 59/94): if the payload is already gone, the
    #   product cannot be blamed. Say so explicitly instead of reporting FAIL.
    $alive = Get-Process -Id $plantPid -ErrorAction SilentlyContinue
    if (-not $alive) {
        Log ("[FAIL] planted payload exited immediately (pid " + $plantPid + ") -- TEST bug, not a product bug")
        Log "       (on Win11 do not use notepad.exe: it is a stub that exits)"
        exit 1
    }
    Log ("[OK] planted process running, pid = " + $plantPid)

    # ---- 2. run the proven engine start/stop path ---------------------------
    Log ""
    Log "=== invoking tools/v57_smoke.ps1 (starts + stops the engine) ==="
    & (Join-Path $PSScriptRoot 'v57_smoke.ps1') $dir 2>&1 | Out-Null

    # ---- 3. assert ----------------------------------------------------------
    Log ""
    Log "=== assertion: procwatch REPORTED the planted masquerader ==="
    $txt = Read-LogFile $console

    if ($txt.IndexOf($PW) -lt 0) {
        Log "[FAIL] no [procwatch] line at all -- module never ran"
    }
    elseif ($txt.IndexOf($plantExe) -ge 0 -and $txt.IndexOf($HR) -ge 0) {
        Log ("[PASS] procwatch reported the planted process: " + $plantExe)
        $ok = $true
        # echo the matching line(s) for the record
        foreach ($line in ($txt -split "`n")) {
            if ($line.IndexOf($plantExe) -ge 0) { Log ("       " + $line.Trim()) }
        }
    }
    else {
        Log ("[FAIL] planted process " + $plantExe + " was NOT reported -- criterion 1 is dead?")
    }

    Log ""
    Log "=== info: masquerade reason text present ==="
    if ($txt.IndexOf($MASK) -ge 0) { Log "[INFO] reason text 'masquerading as system process name' present" }
    else { Log "[INFO] that exact reason text not seen (may be another reason)" }
}
finally {
    # ---- 4. cleanup (always) ------------------------------------------------
    Log ""
    Log "=== cleanup ==="
    if ($plantPid -ne 0) {
        try { Stop-Process -Id $plantPid -Force -ErrorAction SilentlyContinue; Log ("[OK] killed pid " + $plantPid) } catch { }
    }
    # also catch a surviving copy by image path
    foreach ($q in (Get-Process -Name 'svchost' -ErrorAction SilentlyContinue)) {
        try {
            if ($q.Path -eq $plantExe) { Stop-Process -Id $q.Id -Force -ErrorAction SilentlyContinue }
        } catch { }
    }
    Start-Sleep -Milliseconds 400
    try { [System.IO.File]::Delete($plantExe); Log ("[OK] deleted " + $plantExe) } catch { Log ("[WARN] could not delete " + $plantExe) }
}

Log ""
if ($ok) { Log "RESULT: PASS -- the high-risk-process watch still fires" ; exit 0 }
else { Log "RESULT: FAIL -- no detection of a planted masquerader" ; exit 1 }
