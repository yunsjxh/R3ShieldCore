<#
    verify_autostart.ps1 —— 证明「驱动开机自启**真的生效**」

    ===========================================================================
    这个脚本存在的理由：`sc query` 说 RUNNING 证明不了「开机自启」
    ===========================================================================

    下面两种情况在 `sc query` 眼里**完全一样**：
        · 驱动是开机时自动起来的
        · 你五分钟前手动 `sc start` 过
    两者都是 State=RUNNING、StartMode=Auto 或 Boot。

    真正能区分它们的是驱动**自报**的一个数字：LoadSinceBootMs
    （驱动被加载时，系统已经开机了多少毫秒）。
        开机自启 → 很小（BOOT_START 下往往就是 0）
        手动启动 → ≈ 当前系统已运行时长

    ★ 前提门控（铁律 108）：系统开机不到 10 分钟时，"自启"和"刚手动起"
      数值上都小，本来就分不开 —— 此时本脚本**拒绝给结论**，而不是给假 PASS。

    ===========================================================================
    用法（重启后什么都不要做，直接跑这个）
    ===========================================================================
      powershell -ExecutionPolicy Bypass -File driver\verify_autostart.ps1
#>

[CmdletBinding()]
param(
    [string]$ServiceName = 'R3ShieldCoreKernel',
    # ★ 驱动**文件名**（全小写、有下划线）≠ **服务名**（无下划线）—— 铁律 125。
    #   早先这里用 "$ServiceName.sys" 拼路径，拼出来的是 R3ShieldCoreKernel.sys，
    #   而磁盘上真正的文件叫 r3shieldcore_kernel.sys ⇒ 恒报"驱动文件不在"（假 FAIL）。
    [string]$DriverFile  = 'r3shieldcore_kernel.sys'
)

$ErrorActionPreference = 'Continue'

$pass = 0
$fail = 0
function Ok($m)   { $script:pass++; Write-Output ("[ OK ] " + $m) }
function Bad($m)  { $script:fail++; Write-Output ("[FAIL] " + $m) }
function Info($m) { Write-Output ("[INFO] " + $m) }

Write-Output '=== R3ShieldCore 内核组件：开机自启验证 ==='
Write-Output ''

$probe = Join-Path $PSScriptRoot 'build\driver_probe.exe'
$sysInDriverStore = Join-Path $env:SystemRoot "System32\drivers\$DriverFile"

# ---------------------------------------------------------------------------
# 1) 文件到位了吗
# ---------------------------------------------------------------------------
Write-Output '--- 1/4：文件与注册表 ---'
if (Test-Path $sysInDriverStore) {
    $fi = Get-Item $sysInDriverStore
    Ok ("驱动文件在位: $sysInDriverStore（" + $fi.Length + " 字节，" + $fi.LastWriteTime + "）")
} else {
    Bad "驱动文件不在 $sysInDriverStore —— 先跑 install_driver.bat"
}

$svcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
if (Test-Path $svcKey) {
    $p = Get-ItemProperty $svcKey
    $startMap = @{ 0 = 'Boot'; 1 = 'System'; 2 = 'Auto'; 3 = 'Demand'; 4 = 'Disabled' }
    $startName = if ($null -ne $p.Start) { $startMap[[int]$p.Start] } else { '(无)' }
    Info ("ImagePath = " + $p.ImagePath)
    Info ("Start     = " + $p.Start + " (" + $startName + ")")
    if ($p.Start -eq 0) {
        Ok 'Start=0(Boot) —— 引导加载器加载，**最早的一档**（用户指定的目标）'
    } elseif ($p.Start -eq 2) {
        Bad ("Start=" + $p.Start + "(Auto) —— 也算开机自启，但比 Boot(0) 晚，不满足「最早启动」")
    } else {
        Bad ("Start=" + $p.Start + " 既不是 Boot(0) 也不是 Auto(2) —— 它不会开机自启")
    }

    if ($null -ne $p.LoadSinceBootMs) {
        Info ("注册表加载戳 LoadSinceBootMs = " + $p.LoadSinceBootMs + " ms")
    } else {
        Bad '注册表里没有 LoadSinceBootMs —— 驱动从没成功跑过 DriverEntry'
    }
} else {
    Bad "服务注册表键不存在: $svcKey"
}

# ---------------------------------------------------------------------------
# 2) 服务状态（WMI，与下面的驱动自报值互为交叉校验 —— 铁律 59）
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- 2/4：服务状态（WMI 独立来源）---'
$drv = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if ($drv) {
    Info ("StartMode=" + $drv.StartMode + "  State=" + $drv.State + "  Started=" + $drv.Started)
    if ($drv.Started) { Ok '服务处于已启动状态' } else { Bad '服务未启动' }
    if ($drv.StartMode -eq 'Boot') { Ok 'StartMode=Boot' }
    else { Bad ("StartMode=" + $drv.StartMode + " —— 期望 Boot") }
} else {
    Bad "WMI 里查不到 $ServiceName —— 服务没装"
}

# ---------------------------------------------------------------------------
# 3) 驱动自报（核心证据）
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- 3/4：驱动自报（设备 IOCTL）---'
$probeOk = $false
if (Test-Path $probe) {
    $out = & $probe 2>&1
    $out | ForEach-Object { Write-Output ("  | " + $_) }
    $probeOk = ($LASTEXITCODE -eq 0)
    if ($probeOk) { Ok 'driver_probe.exe 判定：自启已证实' }
    else { Bad 'driver_probe.exe 判定：未证实（原因见上面 4 行内的 [FAIL]）' }
} else {
    Bad "找不到探针 $probe —— 先跑 bash driver/build_driver.sh"
}

# ---------------------------------------------------------------------------
# 4) 结论（带前提门控）
# ---------------------------------------------------------------------------
Write-Output ''
Write-Output '--- 4/4：结论 ---'

# ★ 不要用 [Environment]::TickCount —— 在 PS 5.1（.NET Framework）里它是 **Int32**，
#   开机超过 ~24.9 天就溢出成负数，判定会反过来。
#   （.NET Core 的 TickCount64 在 Framework 上没有；C 探针用的是 GetTickCount64，是对的。）
#   用 LastBootUpTime 算，既准确又和探针的口径一致。
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os -and $os.LastBootUpTime) {
    $uptimeMs = [int64]((Get-Date) - $os.LastBootUpTime).TotalMilliseconds
    Info ("上次启动时间 = " + $os.LastBootUpTime)
} else {
    # 退路：拿不到 LastBootUpTime 时用 TickCount，但把溢出风险说出来
    $uptimeMs = [int64][Environment]::TickCount
    Info '拿不到 LastBootUpTime，退化为 TickCount（开机超 24.9 天会溢出，结论不可信）'
}
if ($uptimeMs -lt 0) {
    Bad '算出来的运行时长是负数 —— 计时口径溢出，本次结论作废'
    $uptimeMs = 0
}
$uptimeMin = [math]::Round($uptimeMs / 60000.0, 1)
Info ("系统已运行 " + $uptimeMin + " 分钟")

if ($uptimeMs -lt 10 * 60 * 1000) {
    Bad '前提不足：系统开机不到 10 分钟 —— 「自启」与「刚手动起」数值上无法区分'
    Info '→ 请重启后等满 10 分钟再跑本脚本（期间不要 sc start / sc stop）'
} elseif ($probeOk) {
    Ok '前提满足（开机 > 10 分钟）且驱动自报加载于开机后很早 —— 开机自启成立'
} else {
    Info '前提满足，但驱动自报不足以证明自启 —— 见上面的 [FAIL]'
}

Write-Output ''
Write-Output ("SUMMARY: " + $pass + " passed, " + $fail + " failed")
if ($fail -eq 0) {
    Write-Output 'RESULT: PASS —— 开机自启已证实'
    exit 0
} else {
    Write-Output 'RESULT: FAIL'
    exit 1
}
