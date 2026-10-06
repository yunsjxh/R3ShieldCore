# v62_ark_probe.ps1 -- end-to-end proof of the ARK page.
#
# ---------------------------------------------------------------------------
# THIS FILE MUST STAY PURE ASCII.  DO NOT put CJK anywhere in it.
#
# Why (v62, real incident, cost two debugging sessions):
#   PowerShell 5.1 reads a .ps1 as ANSI (codepage 936 here) unless the file
#   starts with a UTF-8 BOM.  This file is UTF-8 with bare LF endings, so a CJK
#   comment's LAST character ends in a lead byte (>=0x81) followed by 0x0A; the
#   936 decoder eats BOTH bytes, the newline vanishes, and the NEXT physical
#   line becomes part of the comment -- that line's code never runs.  No parse
#   error, no warning.  Variables silently keep their old value.
#   Symptom: three needle variables ($NOTENABLED / $AVAILABLE / $RESUMED) were
#   never assigned, so a perfectly healthy ARK feature "failed" its own probe.
#   Same family as iron rule 40 (.bat with CJK + LF-only loses cmd's sync).
#   The CJK needles below are built from code points precisely for this reason
#   -- keep it that way, and keep the prose ASCII.
#   Check: python tools/ps1_ansi_swallow_check.py
# ---------------------------------------------------------------------------
#
# WHAT THIS PROVES (each assertion exists because a plausible failure would
# otherwise look like success):
#
#   1. ARK actually STARTED and SCANNED the whole machine  -> '[ark] enabled'
#      + '[ark] heartbeat'.  Without these, "page is empty" and "feature never
#      ran" look identical (iron rule 97).
#   2. The DLL export was picked up -> the enable line says "self-exit=usable".
#      If the engine's LoadLibrary'd DLL were stale, this degrades silently.
#   3. The ARK page really RENDERED -> '[ark] page painted', printed from inside
#      DrawArkPage.  * The engine is launched VISIBLE on purpose: a MINIMIZED
#      window never receives WM_PAINT, so a minimized launch can never prove
#      rendering at all (see the note on the launch line).
#   4. The request really was issued by the GUI thread -> '[ark-selftest]'.
#      This is driven by WM_TIMER, not by WM_PAINT, so it does not depend on
#      the window being visible.
#   5. The action really EXECUTED through the production chain
#      (GUI thread -> R3ShieldCoreArk::RequestAction -> queue -> main-loop Tick ->
#       DrainActions -> ArkActions::Perform) -> '[ark] action ... result=OK'.
#   6. The target was really FROZEN (not just "the call returned 0")
#      -> the victim's tick file stops growing.
#      * Positive control first: the same measurement must show GROWTH while
#        the victim is running (iron rule 103).
#      * PREMISE-GATED: if no action line was logged, the freeze check is
#        meaningless and is reported as a failure with that reason -- it must
#        NOT be allowed to "pass" (iron rule 54: a PASS without a control is
#        no test at all).
#   7. The engine exits GRACEFULLY (not TerminateProcess'd) -> '[ark] stopped'.
#   8. On that graceful exit it AUTO-RESUMES what it suspended
#      -> '[ark] resumed-before-stop: ok=N' + the tick file grows again.
#      Without this, closing the engine would leave processes frozen forever
#      with no UI left to un-freeze them.
#      * Graceful exit is forced by R3SHIELDCORE_EXIT_AFTER_MS, which goes through
#        the SAME break as the exit button.  Killing the engine with dskill
#        (TerminateProcess) cannot run any cleanup code at all, so "auto-resume"
#        would be untestable -- and assertion 8 would falsely pass because the
#        victim was never suspended in the first place.
#
# Usage: powershell -ExecutionPolicy Bypass -File tools\v62_ark_probe.ps1

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
if ($args.Count -ge 1 -and $args[0]) { $dir = $args[0] } else { $dir = Join-Path $root '_t\ark-probe' }

$exe     = Join-Path $dir 'R3 ShieldCore.exe'
$console = Join-Path $dir 'r3shieldcore-console.log'
$events  = Join-Path $dir 'r3shieldcore-events.log'
$startup = Join-Path $dir 'r3shieldcore-startup-error.log'
$dskill  = Join-Path $root 'tools\dskill.exe'

# How long the engine should live before it takes the graceful-exit path.
$exitAfterMs = 12000

$pass = 0; $fail = 0
function Ok($m)   { $script:pass++; Write-Output ("[PASS] " + $m) }
function Bad($m)  { $script:fail++; Write-Output ("[FAIL] " + $m) }
function Info($m) { Write-Output ("[INFO] " + $m) }

# ---- CJK needles, built from code points (see the header note) --------------
$ENABLED   = [char]0x5DF2 + [char]0x542F + [char]0x7528                     # yi-qi-yong
$NOTENABLED= [char]0x672A + [char]0x542F + [char]0x7528                     # wei-qi-yong
$HEARTBEAT = [char]0x5FC3 + [char]0x8DF3                                    # xin-tiao
$SELFEXIT  = [char]0x5185 + [char]0x90E8 + [char]0x9000 + [char]0x51FA       # nei-bu-tui-chu
$AVAILABLE = [char]0x53EF + [char]0x7528                                    # ke-yong
$PAINTED   = [char]0x9875 + [char]0x9762 + [char]0x5DF2 + [char]0x7ED8       # ye-mian-yi-hui
$RESULT    = [char]0x7ED3 + [char]0x679C                                    # jie-guo
$ACTION    = [char]0x52A8 + [char]0x4F5C                                    # dong-zuo
$STOPPED   = [char]0x5DF2 + [char]0x505C + [char]0x6B62                     # yi-ting-zhi
$RESUMED   = [char]0x6062 + [char]0x590D + [char]0x6302 + [char]0x8D77       # hui-fu-gua-qi

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

# Print the tail of the console log.  A probe that reports "no heartbeat"
# without showing what it actually read is undiagnosable (iron rule 97).
function DumpTail($path, $lines) {
    $t = Read-LogFile $path
    if (-not $t) { Write-Output "  (log unreadable or empty: $path)"; return }
    $all = $t -split "`n"
    $from = [Math]::Max(0, $all.Count - $lines)
    Write-Output ("  ---- tail of " + (Split-Path $path -Leaf) + " (" +
        $t.Length + " chars, " + $all.Count + " lines) ----")
    for ($i = $from; $i -lt $all.Count; $i++) {
        Write-Output ("  | " + $all[$i].TrimEnd("`r"))
    }
}

function TickSize($p) {
    if (-not (Test-Path $p)) { return -1 }
    try {
        $fs = [System.IO.File]::Open($p, [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        $n = $fs.Length; $fs.Close(); return $n
    } catch { return -1 }
}

Write-Output "=== v62 ARK end-to-end probe ==="
Write-Output ("dir = " + $dir)

if (-not (Test-Path $exe)) { Bad "probe exe missing -- run: bash build_ark_probe.sh"; exit 1 }

# ---- 0. fresh state ---------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
$work  = Join-Path $env:TEMP ('ark_probe_' + $stamp)
[System.IO.Directory]::CreateDirectory($work) | Out-Null
$tick = Join-Path $work 'tick.txt'
$bat  = Join-Path $work 'victim.bat'
# * CRLF + ASCII: an LF-only .bat makes cmd's parser lose sync (iron rule 40).
[System.IO.File]::WriteAllText($bat,
    "@echo off`r`ncd /d `"$work`"`r`n:loop`r`necho tick>>tick.txt`r`ngoto loop`r`n",
    [System.Text.Encoding]::ASCII)

foreach ($f in @($console, $events, $startup)) {
    if ([System.IO.File]::Exists($f)) { try { [System.IO.File]::Delete($f) } catch { } }
}

# ---- 1. victim ---------------------------------------------------------------
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$victim = Start-Process -FilePath $cmd -ArgumentList '/c', ('"' + $bat + '"') `
    -PassThru -WindowStyle Hidden
$victimPid = $victim.Id
Write-Output ("victim pid = " + $victimPid)

# PAYLOAD PREMISE (iron rule 103): if the victim never writes, every later
# "size unchanged" assertion would pass for the wrong reason.
$deadline = (Get-Date).AddSeconds(6)
while ((Get-Date) -lt $deadline -and (TickSize $tick) -le 0) { Start-Sleep -Milliseconds 100 }
$s0 = TickSize $tick
if ($s0 -le 0) {
    Bad "victim never wrote to tick.txt -- TEST BUG, not a product bug"
    try { $victim | Stop-Process -Force } catch { }
    exit 1
}
Ok ("payload premise: victim is writing (tick.txt = " + $s0 + " bytes)")

# POSITIVE CONTROL for the measurement itself: while NOT suspended it must grow.
Start-Sleep -Milliseconds 800
$s1 = TickSize $tick
if ($s1 -gt $s0) { Ok ("positive control: tick.txt grows while running (" + $s0 + " -> " + $s1 + ")") }
else { Bad ("positive control FAILED: tick.txt did not grow (" + $s0 + " -> " + $s1 + ") -- measurement is broken") }

# ---- 1b. v63: pin a NON-DEFAULT ark_refresh_ms into the deployed ini ---------
# Why a non-default value: the shipped default is 1000, and the GUI's hard-coded
# fallback is ALSO 1000 -- so asserting "refresh=1000" would pass even if the
# config key were never read at all.  That is a vacuous assertion (iron rule 54).
# A value only the ini can produce makes it a real end-to-end proof that the
# key is parsed and reaches the GUI.
#
# Byte-safe on purpose: the ini is UTF-8 WITHOUT BOM and carries CJK comments,
# so rewriting it through the ANSI (936) path would corrupt it (iron rule 40
# family).  Latin-1 (28591) is a 1:1 byte round-trip, and we only ever touch
# ASCII-only lines, so the CJK bytes pass through untouched.
$refreshMs = 1500
$iniPath = Join-Path $dir 'r3shieldcore.ini'
if (-not (Test-Path $iniPath)) { Bad "r3shieldcore.ini missing in probe dir: $iniPath"; exit 1 }
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
$iniText = [System.IO.File]::ReadAllText($iniPath, $latin1)
$iniLines = $iniText -split "`r`n" | Where-Object {
    ($_ -notmatch '^ark_refresh_ms=') -and ($_ -notmatch '^# probe override \(v63\)$')
}
$iniText = ($iniLines -join "`r`n") + "`r`n# probe override (v63)`r`nark_refresh_ms=$refreshMs`r`n"
[System.IO.File]::WriteAllText($iniPath, $iniText, $latin1)
Ok ("pinned ark_refresh_ms=$refreshMs in the deployed ini (non-default, so the check is not vacuous)")

# ---- 2. launch the engine on the ARK tab, with a pending action request -------
# action 0 = Suspend (R3ShieldCoreArk::ActionSuspend)
$env:R3SHIELDCORE_START_TAB     = 'ark'
$env:R3SHIELDCORE_ARK_ACTION    = ($victimPid.ToString() + ':0')
$env:R3SHIELDCORE_EXIT_AFTER_MS = $exitAfterMs.ToString()

Write-Output ""
Write-Output "=== launch engine (no UAC build, so env vars get through) ==="
# * VISIBLE, not -WindowStyle Minimized.
#   A minimized window NEVER receives WM_PAINT, so DrawArkPage would never run
#   and '[ark] page painted' could never appear.  (The action chain itself no
#   longer depends on painting -- the self-test is timer-driven -- but the
#   "page really renders" claim can only be proven with a visible window.)
$engine = Start-Process -FilePath $exe -WorkingDirectory $dir -PassThru
$enginePid = 0
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 300
    $p = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
    if ($p) { $enginePid = $p[0].Id; break }
}
if ($enginePid -eq 0) { Bad "engine never appeared"; try { $victim | Stop-Process -Force } catch { }; exit 1 }
Ok ("engine pid = " + $enginePid)

# ---- 3. let it scan + run the action -----------------------------------------
Start-Sleep -Seconds 6
$alive = Get-Process -Id $enginePid -ErrorAction SilentlyContinue
if ($alive) { Ok "engine still alive after startup" } else { Bad "engine died during startup" }

# ---- 4. was the victim actually FROZEN? --------------------------------------
$f0 = TickSize $tick
Start-Sleep -Milliseconds 1500
$f1 = TickSize $tick
$frozen = ($f1 -eq $f0)

# ---- 5. wait for the engine's own graceful exit -------------------------------
Write-Output ""
Write-Output ("=== wait for graceful exit (R3SHIELDCORE_EXIT_AFTER_MS=" + $exitAfterMs + ") ===")
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    if (-not (Get-Process -Id $enginePid -ErrorAction SilentlyContinue)) { break }
}
$exitedByItself = -not (Get-Process -Id $enginePid -ErrorAction SilentlyContinue)
if ($exitedByItself) { Ok "engine exited on its own (graceful path)" }
else {
    Bad "engine did not exit within the grace window -- forcing with dskill"
    & $dskill $enginePid (Join-Path $dir '_dskill_out.txt') | Out-Null
    Start-Sleep -Seconds 3
}
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) { & $dskill $still[0].Id | Out-Null; Start-Sleep -Seconds 3 }
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) { Bad "engine still alive -- console may be unreadable" } else { Ok "engine stopped" }

# ---- 6. auto-resume on exit --------------------------------------------------
$r0 = TickSize $tick
Start-Sleep -Milliseconds 1500
$r1 = TickSize $tick

# ---- 7. console assertions ---------------------------------------------------
Write-Output ""
Write-Output "=== assertion: ARK module started and scanned ==="
$txt = Read-LogFile $console
Info ("console log: " + $txt.Length + " chars")
if ($txt.Length -eq 0) { Bad "console log is EMPTY -- cannot judge anything below" }

if ($txt.IndexOf('[ark]') -ge 0) { Ok "console has [ark] lines" } else { Bad "no [ark] line -- ARK never started" }

if ($txt.IndexOf($ENABLED) -ge 0) { Ok "ARK reported enabled (first line, printed immediately)" }
else { Bad "no ARK 'enabled' line" }

if ($txt.IndexOf($NOTENABLED) -ge 0) { Bad "ARK reported a NOT-ENABLED reason -- read that line" }
else { Ok "ARK did not report a not-enabled reason" }

if ($txt.IndexOf($HEARTBEAT) -ge 0) { Ok "ARK heartbeat present (it is really scanning)" }
else { Bad "no ARK heartbeat -- the module is not scanning" }

if ($txt.IndexOf($SELFEXIT) -ge 0 -and $txt.IndexOf($AVAILABLE) -ge 0) {
    Ok "engine picked up the DLL export (self-exit = usable)"
} else {
    Bad "enable line does not say self-exit=usable -- stale DLL loaded?"
}

Write-Output ""
Write-Output "=== assertion: the ARK page actually RENDERED ==="
if ($txt.IndexOf($PAINTED) -ge 0) { Ok "ARK page painted ([ark] page-painted line present)" }
else { Bad "no [ark] page-painted line -- DrawArkPage never ran" }

# ---- v63: grouping + refresh interval really in effect -----------------------
# The painted line carries the row count, the three group counts and the
# effective refresh interval.  Parsed with FIELD-ANCHORED regexes, never with
# substring matching (iron rule 94).  CJK needles are written as \uXXXX escapes
# so this file stays pure ASCII (iron rule 104).
#
# PREMISE-GATED (iron rule 108).  The FIRST paint happens ~300ms after the
# window is created, while the FIRST scan is still running (a full-machine
# enumeration takes >1s here), so that early paint legitimately renders an
# EMPTY snapshot.  Judging grouping on it would "pass" as 0+0+0 == 0 -- an
# assertion a completely broken GroupRankOf() would satisfy just as well.
# So: take the paint that saw the MOST rows, and refuse to believe anything
# unless that paint is non-empty AND came after a completed scan.
$paintM = [regex]::Matches($txt,
    '\[ark\][^\r\n]*\u884C\u6570=(\d+)[^\r\n]*\u5DF2\u626B\u63CF=(\d+)' +
    '[^\r\n]*\u5206\u7EC4=(\d+)/(\d+)/(\d+)[^\r\n]*\u5237\u65B0=(\d+)ms')

$bestM = $null
$bestRows = -1
foreach ($m in $paintM) {
    if ([int]$m.Groups[1].Value -gt $bestRows) {
        $bestRows = [int]$m.Groups[1].Value
        $bestM = $m
    }
}

if ($null -eq $bestM) {
    Bad "no '[ark] page painted' line carried the v63 fields -- v63 logging did not run"
} elseif ($bestRows -eq 0) {
    Bad ("premise missing: every paint saw an EMPTY snapshot (max rows=0, scans=" +
        [int]$bestM.Groups[2].Value +
        ") -- grouping was never exercised, so it must not pass (iron rule 108)")
} else {
    $rows = [int]$bestM.Groups[1].Value
    $scans = [int]$bestM.Groups[2].Value
    $g0 = [int]$bestM.Groups[3].Value
    $g1 = [int]$bestM.Groups[4].Value
    $g2 = [int]$bestM.Groups[5].Value
    Ok ("painted line with the most rows: " + $rows + " rows, scans=" + $scans +
        ", groups " + $g0 + "/" + $g1 + "/" + $g2)

    if ($scans -lt 1) {
        Bad "that paint reports scans=0 -- its row count did not come from a completed scan"
    } else {
        Ok ("that paint followed a completed scan (scans=" + $scans + ")")
    }

    if (($g0 + $g1 + $g2) -eq $rows) {
        Ok "group counts add up to the row count (every row was classified)"
    } else {
        Bad ("group counts sum to " + ($g0 + $g1 + $g2) + " but there are " +
            $rows + " rows -- some rows were never classified")
    }

    # Independent cross-check (iron rule 59): the heartbeat's system count comes
    # from the SAME row.IsSystem flag GroupRankOf() reads, computed in the same
    # ScanOnce() pass, so for that scan the two numbers must agree EXACTLY.
    # ' [ \t]' after the number keeps scan=1 from matching scan=10.
    $hb = [regex]::Match($txt,
        '\u626B\u63CF=' + $scans + '[ \t][^\r\n]*\u7CFB\u7EDF\u8FDB\u7A0B=(\d+)')
    if ($hb.Success) {
        $hbSys = [int]$hb.Groups[1].Value
        if ($hbSys -eq $g2) {
            Ok ("system group " + $g2 + " == heartbeat system count " + $hbSys +
                " for scan #" + $scans + " (cross-checked against the scan stats)")
        } else {
            Bad ("system group " + $g2 + " != heartbeat system count " + $hbSys +
                " for scan #" + $scans + " -- grouping disagrees with the scan stats")
        }
    } else {
        Bad ("no heartbeat line for scan #" + $scans + " -- cannot cross-check the system group")
    }

    if ($g2 -gt 0) {
        Ok ("system group is non-empty (" + $g2 + ") -- rows were really classified, not defaulted")
    } else {
        Bad "system group is EMPTY although live system processes exist -- GroupRankOf looks broken"
    }

    $refSeen = [int]$bestM.Groups[6].Value
    if ($refSeen -eq $refreshMs) {
        Ok ("effective refresh interval = " + $refSeen + "ms, matching the ini override")
    } else {
        Bad ("refresh interval = " + $refSeen + "ms but the ini said " + $refreshMs +
            " -- ark_refresh_ms was not read")
    }
}

if ($txt.IndexOf('[ark-selftest]') -ge 0) { Ok "action request issued by the GUI thread ([ark-selftest])" }
else { Bad "no [ark-selftest] line -- self-test never fired, or env vars did not get through" }

Write-Output ""
Write-Output "=== assertion: the action executed through the production chain ==="
$actionOk = $false
foreach ($line in ($txt -split "`n")) {
    if ($line.IndexOf('[ark]') -ge 0 -and $line.IndexOf($ACTION) -ge 0 `
        -and $line.IndexOf($RESULT) -ge 0 -and $line.IndexOf('OK') -ge 0) {
        $actionOk = $true
        Info ("action line: " + $line.Trim())
    }
}
if ($actionOk) { Ok "a [ark] action line reports result=OK" }
else { Bad "no successful [ark] action line" }

# ---- 8. the freeze verdict, PREMISE-GATED ------------------------------------
Write-Output ""
Write-Output "=== assertion: the target was really FROZEN ==="
if (-not $actionOk) {
    # Iron rule 54/103: without a confirmed successful suspend, "tick.txt did
    # not grow" proves nothing -- it could just mean the measurement broke.
    Bad ("cannot judge freeze: no result=OK action line, so the premise is missing (" +
        $f0 + " -> " + $f1 + ")")
}
elseif ($frozen) {
    Ok ("victim FROZEN: tick.txt stopped growing (" + $f0 + " -> " + $f1 + ")")
}
else {
    Bad ("victim NOT frozen although the action reported OK: tick.txt still grew (" +
        $f0 + " -> " + $f1 + ") -- suspend is a no-op")
}

# ---- 9. graceful shutdown + auto-resume --------------------------------------
Write-Output ""
Write-Output "=== assertion: graceful shutdown auto-resumed the victim ==="
if ($exitedByItself -and $txt.IndexOf($STOPPED) -ge 0) { Ok "engine took the graceful shutdown path ([ark] stopped)" }
elseif ($exitedByItself) { Bad "engine exited on its own but printed no [ark] stopped line" }
else { Bad "engine had to be killed -- the auto-resume path could not run at all" }

if ($txt.IndexOf($RESUMED) -ge 0) { Ok "engine logged its auto-resume pass ([ark] resumed-before-stop)" }
else { Bad "no [ark] resumed-before-stop line -- nothing was resumed on exit" }

if (-not $actionOk) {
    Bad ("cannot judge auto-resume: the victim was never suspended, so 'it grew again' " +
        "would be a FALSE PASS (" + $r0 + " -> " + $r1 + ")")
}
elseif ($r1 -gt $r0) { Ok ("engine exit AUTO-RESUMED the victim (" + $r0 + " -> " + $r1 + ")") }
else { Bad ("victim still frozen after engine exit (" + $r0 + " -> " + $r1 + ") -- it would stay frozen forever") }

# ---- diagnostics on failure --------------------------------------------------
if ($fail -gt 0) {
    Write-Output ""
    Write-Output "=== DIAGNOSTICS (read this before touching the code) ==="
    DumpTail $console 25
}

# ---- cleanup -----------------------------------------------------------------
try { $victim | Stop-Process -Force } catch { }
try { [System.IO.Directory]::Delete($work, $true) } catch { }

Write-Output ""
Write-Output ("SUMMARY: " + $pass + " passed, " + $fail + " failed")
if ($fail -eq 0) { Write-Output "RESULT: PASS"; exit 0 }
Write-Output "RESULT: FAIL"; exit 1
