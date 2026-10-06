<#
    sign_driver.ps1 —— 给 r3shieldcore_kernel.sys 签名（★ 参考实现，按你自己的证书调整）

    ===========================================================================
    先读这段：内核驱动的签名不是"可选步骤"，它是**能不能加载的前提**
    ===========================================================================

    x64 的 Windows 从 Vista 起就要求内核驱动必须有签名。到 Win10 1607+，
    在**开启 Secure Boot** 的机器上，驱动必须由 **Microsoft 签名**
    （EV 证书 + 微软 attestation 签名服务，或 WHQL）。

    所以只有三条路：

      A) 本机测试签名（本脚本默认走这条）
         - 必须 `bcdedit /set testsigning on` 并**重启**
         - 必须**关闭 Secure Boot**（开着的话 testsigning 不生效）
         - 桌面右下角会出现"测试模式"水印
         - 只适合开发机 / 虚拟机，**绝不能**用于分发

      B) EV 证书 + 微软 attestation 签名
         - 正式的开发期分发路径。需要购买 EV 代码签名证书，
           再通过 Microsoft Partner Center 提交做 attestation 签名。
         - 本脚本的 -EvCert 分支留了位置。

      C) WHQL / MVI
         - 走微软硬件认证，或加入 Microsoft Virus Initiative。
         - ★ 只有这条路的 ELAM 证书能让你做"开机最早加载"的驱动。
           详见 README.md 的"关于 ELAM"。

    ===========================================================================
    ★ 前提状态（在开发机上实测；换机器请自行核对）
    ===========================================================================
      Secure Boot ............ 已关闭（UEFISecureBootEnabled=0）→ 测试签名可行
      testsigning ............ 未开启（需 bcdedit + 重启）
      BitLocker .............. ★ 已启用（启动项里有 FVEBOOT）★
                               → 改启动配置会触发恢复密钥提示。
                                 请先在别处确认拿得到 48 位恢复密钥，再重启。

    ===========================================================================
    用法
    ===========================================================================
      # 1) 先建证书（只需一次）
      powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1 -MakeCert

      # 2) 开测试签名（需管理员；★ 先确认 BitLocker 恢复密钥）
      powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1 -EnableTestSigning

      # 3) 重启

      # 4) 签名
      powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1

      # 5) 校验签名
      powershell -ExecutionPolicy Bypass -File driver\sign_driver.ps1 -Verify
#>

[CmdletBinding()]
param(
    [switch]$MakeCert,
    [switch]$EnableTestSigning,
    [switch]$Verify,
    [string]$SysPath,
    [string]$CertSubject = 'CN=R3ShieldCore Test Kernel Signing',
    [string]$EvCertName  = ''      # 有 EV 证书时填证书的 Subject 或 Thumbprint
)

$ErrorActionPreference = 'Stop'

$root    = Split-Path $PSScriptRoot -Parent
if (-not $SysPath) { $SysPath = Join-Path $PSScriptRoot 'build\r3shieldcore_kernel.sys' }

function Find-SignTool {
    # ★ 不写死盘符：先读环境变量，再依次扫常见根。
    $roots = @()
    if ($env:SIGNTOOL_DIR) { $roots += $env:SIGNTOOL_DIR }
    foreach ($d in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($d) { $roots += (Join-Path $d 'Windows Kits\10\bin') }
    }
    $roots += 'C:\Windows Kits\10\bin', 'D:\Windows Kits\10\bin'
    $candidates = @()
    foreach ($r in $roots) {
        if (Test-Path $r) {
            $candidates += Get-ChildItem $r -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' }
        }
    }
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw "找不到 signtool.exe（已扫：$($roots -join ' | ')）。可用 `$env:SIGNTOOL_DIR 指定。"
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw '本操作需要管理员权限。请用管理员身份打开 PowerShell 后重跑。'
    }
}

# ---------------------------------------------------------------- -MakeCert
if ($MakeCert) {
    Write-Output '=== 创建自签名内核代码签名证书 ==='
    Assert-Admin

    $existing = Get-ChildItem Cert:\LocalMachine\My |
        Where-Object { $_.Subject -eq $CertSubject }
    if ($existing) {
        Write-Output ("已存在同名证书，直接复用: " + $existing[0].Thumbprint)
        $cert = $existing[0]
    } else {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -CertStoreLocation 'Cert:\LocalMachine\My' `
            -KeyUsage DigitalSignature `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(5)
        Write-Output ("已创建: " + $cert.Thumbprint)
    }

    # ★ 必须把证书导进"受信任的根"和"受信任的发布者"。
    #   只放 My 是不够的：内核在加载驱动时会验证证书链，链的根不受信任
    #   就判定签名无效 —— 而报错信息只会说"签名无效"，不会告诉你"缺根证书"。
    foreach ($storeName in @('Root', 'TrustedPublisher')) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'LocalMachine')
        $store.Open('ReadWrite')
        try {
            $store.Add($cert)
            Write-Output ("已加入 LocalMachine\$storeName")
        } finally {
            $store.Close()
        }
    }

    Write-Output ''
    Write-Output '下一步：-EnableTestSigning（然后重启）'
    exit 0
}

# ------------------------------------------------------- -EnableTestSigning
if ($EnableTestSigning) {
    Write-Output '=== 开启测试签名模式 ==='
    Assert-Admin

    Write-Output '⚠ 注意：本机 BitLocker 已启用。'
    Write-Output '  修改启动配置后重启，系统可能要求输入 48 位 BitLocker 恢复密钥。'
    Write-Output '  请先确认你拿得到它（aka.ms/myrecoverykey 或你自己的备份）。'
    Write-Output ''

    $ans = Read-Host '确认已备好 BitLocker 恢复密钥？输入 yes 继续'
    if ($ans -ne 'yes') { Write-Output '已取消。'; exit 1 }

    # Secure Boot 必须先关 —— 开着的话 testsigning 根本不生效，
    # 而症状只是"驱动加载失败 status=0xC0000428"，看不出跟 Secure Boot 有关。
    try {
        $sb = Confirm-SecureBootUEFI
        Write-Output ("Secure Boot = " + $sb)
        if ($sb) {
            Write-Output '⚠ Secure Boot 处于开启状态 —— 必须先到 BIOS/UEFI 里关掉它，'
            Write-Output '  否则 testsigning 不生效，驱动加载会失败（0xC0000428）。'
            exit 1
        }
    } catch {
        Write-Output '无法查询 Secure Boot（多为 Legacy BIOS 或权限不足）—— 继续。'
    }

    bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) { throw 'bcdedit 失败' }
    Write-Output ''
    Write-Output '已设置 testsigning on。★ 需要重启才生效。'
    Write-Output '重启后桌面右下角会出现"测试模式"水印 —— 那是正常的。'
    Write-Output '撤销：bcdedit /set testsigning off 然后重启。'
    exit 0
}

# ------------------------------------------------------------------- -Verify
if ($Verify) {
    Write-Output '=== 校验驱动签名 ==='
    $signtool = Find-SignTool
    # /kp = 按内核模式驱动策略校验（比默认的 /pa 更严格、更贴近加载时的判定）
    & $signtool verify /v /kp $SysPath
    if ($LASTEXITCODE -ne 0) {
        Write-Output ''
        Write-Output '签名校验未通过。常见原因：'
        Write-Output '  1) 证书不在 LocalMachine\Root（缺根证书 → 链不受信任）'
        Write-Output '  2) 没用 -fd sha256'
        Write-Output '  3) 证书已过期'
        exit 1
    }
    Write-Output ''
    Write-Output '签名校验通过。'
    exit 0
}

# -------------------------------------------------------------------- 签名
Write-Output '=== 给驱动签名 ==='
if (-not (Test-Path $SysPath)) {
    throw "找不到 $SysPath —— 先跑 bash driver/build_driver.sh"
}
Assert-Admin

$signtool = Find-SignTool
Write-Output ("signtool : " + $signtool)
Write-Output ("目标     : " + $SysPath)
Write-Output ''

# ★ 时间戳服务器：内核在**加载时**会校验签名，如果证书已过期但签名带可信
#   时间戳，仍然有效。不带时间戳的话，证书一过期驱动就加载不了。
$timestamp = 'http://timestamp.digicert.com'

if ($EvCertName) {
    Write-Output ("使用 EV 证书: " + $EvCertName)
    Write-Output '（EV 证书签出来的驱动**在开了 Secure Boot 的机器上也加载不了** ——'
    Write-Output ' 还需要走微软 attestation 签名。见本脚本顶部说明 B。）'
    & $signtool sign /v /n $EvCertName /fd sha256 /tr $timestamp /td sha256 $SysPath
} else {
    Write-Output ("使用自签名证书: " + $CertSubject)
    & $signtool sign /v /s My /n $CertSubject /fd sha256 /tr $timestamp /td sha256 $SysPath
}
if ($LASTEXITCODE -ne 0) { throw 'signtool sign 失败' }

Write-Output ''
Write-Output '签名完成。接着校验一遍：'
& $signtool verify /v /kp $SysPath
Write-Output ''
Write-Output '下一步：driver\install_driver.bat（需管理员）'
