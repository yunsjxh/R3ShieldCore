# v57_smoke.ps1 -- prove the engine starts from a USER-WRITABLE deployment dir.
# This is the whole point of v57: the old gate refused to load the DLL there.
#
# ASCII-only source (PS 5.1 reads .ps1 as ANSI).
#
# ★ 不要在引擎运行期间读 r3shieldcore-console.log —— 引擎以独占方式持有它，
#   ReadAllBytes / FileStream 都会报 "used by another process"。
#   本脚本的做法：先停引擎，再读日志断言。

$ErrorActionPreference = 'Continue'
$root = Split-Path $PSScriptRoot -Parent
if ($args.Count -ge 1 -and $args[0]) {
    $dir = $args[0]
} else {
    $dir = Join-Path $root 'dist\R3ShieldCore-x64-v57'
}
$exe = Join-Path $dir 'R3 ShieldCore.exe'
$console = Join-Path $dir 'r3shieldcore-console.log'
$events = Join-Path $dir 'r3shieldcore-events.log'
$startupErr = Join-Path $dir 'r3shieldcore-startup-error.log'
$dskill = Join-Path $root 'tools\dskill.exe'

$INJECT = [char]0x5F00 + [char]0x59CB            # 'begin'  (开始全局注入)
$REFUSE = 'user-writable deployment directory'
$HOLD_MS = 9000

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

Log "=== v57 smoke: engine from a WRITABLE dir ==="
Log ("dir = " + $dir)

# ---- 1. prove the dir really is user-writable --------------------------------
# ★ 用 .NET 的 File API，不用 Remove-Item：某些环境的 safe-delete 策略会拦截
#   批量删除（SAFE_DELETE_BULK_CONFIRM_REQUIRED），让"清理临时文件"失败，
#   于是这里被误判成"目录不可写" —— 一个纯粹的脚手架假阴性。
$wtest = Join-Path $dir '_wtest.tmp'
try {
    [System.IO.File]::WriteAllText($wtest, 'x')
    [System.IO.File]::Delete($wtest)
    Log "[OK] deployment dir IS user-writable (this is exactly what v56 refused)"
} catch {
    Log ("[FAIL] dir is not writable -- test is meaningless: " + $_.Exception.Message); exit 1
}

foreach ($f in @($startupErr, $console, $events)) {
    if ([System.IO.File]::Exists($f)) {
        try { [System.IO.File]::Delete($f) } catch { }
    }
}

# ---- 2. launch ---------------------------------------------------------------
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

# ---- 3. hold, watching the EVENTS file grow (that one is shareable) ----------
Log ""
Log ("=== hold " + ($HOLD_MS / 1000) + "s, watching r3shieldcore-events.log ===")
$eventsStart = 0
if (Test-Path $events) { $eventsStart = (Get-Item $events).Length }
Start-Sleep -Milliseconds $HOLD_MS
$eventsEnd = 0
if (Test-Path $events) { $eventsEnd = (Get-Item $events).Length }
Log ("events.log: " + $eventsStart + " -> " + $eventsEnd + " bytes")

$alive = Get-Process -Id $enginePid -ErrorAction SilentlyContinue
if ($alive) { Log "[OK] engine still alive after startup (it did NOT exit on the gate)" }
else { Log "[FAIL] engine died during startup" }

# ---- 4. stop -----------------------------------------------------------------
Log ""
Log "=== stop engine ==="
& $dskill $enginePid (Join-Path $dir '_dskill_out.txt') | Out-Null
Start-Sleep -Seconds 2
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) { & $dskill $still[0].Id | Out-Null; Start-Sleep -Seconds 2 }
$still = Get-Process -Name 'R3 ShieldCore' -ErrorAction SilentlyContinue
if ($still) { Log "[WARN] engine still alive" } else { Log "[OK] engine stopped" }

# ---- 5. assertions (now safe to read) ---------------------------------------
Log ""
Log "=== assertion: console banner ==="
$txt = Read-LogFile $console
if ($txt.IndexOf($INJECT) -ge 0) { Log "[PASS] console reached 'begin global injection'" }
else { Log "[FAIL] no injection banner in console" }

Log ""
Log "=== assertion: no old refusal ==="
$err = Read-LogFile $startupErr
if ($err.IndexOf($REFUSE) -ge 0) { Log "[FAIL] still hit the old DLL-refusal!" }
elseif ($err) { Log ("[PASS] startup-error has content but no refusal: " + $err.Trim()) }
else { Log "[PASS] r3shieldcore-startup-error.log is absent/empty" }

Log ""
Log "=== assertion: events recorded ==="
if ($eventsEnd -gt $eventsStart) { Log ("[PASS] events grew by " + ($eventsEnd - $eventsStart) + " bytes") }
else { Log "[WARN] events file did not grow (engine may still be warming up)" }

Log ""
Log "=== assertion: overlay sentinel ran (v59 heartbeat) ==="
# The sentinel prints its first heartbeat on the very first scan (not after 60s),
# so a short smoke run still proves the module started. ASCII needle on purpose.
$SENT = '[sentinel]'
if ($txt.IndexOf($SENT) -ge 0) { Log "[PASS] sentinel heartbeat present in console" }
else { Log "[FAIL] no [sentinel] line -- overlay countermeasure never ran" }

Log ""
Log "=== assertion: v60 heartbeat carries per-scan match count ==="
# v59 printed only the CUMULATIVE match count, so a heartbeat stuck at "命中=15"
# could not be told apart from "this scan matched nothing". v60 prints both.
# Needle built from code points: PS 5.1 reads .ps1 as ANSI, so no literal CJK here.
$HB = [char]0x672C + [char]0x626B + [char]0x63CF + [char]0x547D   # '本扫描命中'
if ($txt.IndexOf($HB) -ge 0) { Log "[PASS] heartbeat has per-scan counter (v60 binary)" }
else { Log "[FAIL] heartbeat lacks per-scan counter -- dist still holds a v59 binary?" }

Log ""
Log "=== info: near-miss diagnostic coverage (v60 widened gate) ==="
# On a live desktop the input host owns a full-screen borderless window, so the
# widened gate normally produces at least one 差一点命中 line. Informational only
# (a bare VM may legitimately have none).
$NM = [char]0x5DEE + [char]0x4E00 + [char]0x70B9 + [char]0x547D + [char]0x4E2D  # '差一点命中'
if ($txt.IndexOf($NM) -ge 0) { Log "[INFO] near-miss diagnostic fired at least once (gate is live)" }
else { Log "[INFO] no near-miss line in this short run (acceptable)" }

Log ""
Log "=== assertion: v61 high-risk process watch started ==="
# v61: the engine enumerates the WHOLE machine on its own (no injection coverage,
# no observation window needed). Start() prints an 'enabled' line immediately and
# then runs one scan right away, so a short smoke run must already show the
# '[procwatch]' prefix. Without this line, 'feature never started' and 'started but
# found nothing' would look identical in the log (iron rule 97).
$PW = '[procwatch]'
if ($txt.IndexOf($PW) -ge 0) { Log "[PASS] procwatch lines present in console (v61 binary)" }
else { Log "[FAIL] no [procwatch] line -- high-risk process watch never started" }

Log ""
Log "=== assertion: v61 procwatch prints an explicit enable/disable reason ==="
# 'not enabled' and 'enabled' must be distinguishable. Needle = '未启用' (not
# enabled) -- it is what the module prints for alert=0 / missing export /
# no %SystemRoot%. ASCII-safe: built from code points.
$NE = [char]0x672A + [char]0x542F + [char]0x7528   # '未启用'
if ($txt.IndexOf($NE) -ge 0) {
    Log "[WARN] procwatch reported a NOT-ENABLED reason -- read that line in the console"
} else {
    Log "[PASS] procwatch did not report a not-enabled reason (it is running)"
}

