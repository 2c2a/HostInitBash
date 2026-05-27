param(
    [Parameter(Position=0)]
    [string]$Secret,
    [switch]$DebugMode
)

if ($args -contains '--debug') { $DebugMode = $true }

if ($args -contains '--help' -or $args -contains '-h') {
    Write-Host 'Usage: .\h_side_init.ps1 {secret} [--debug]'
    Write-Host '  secret   C 端获取的加密配置字符串'
    Write-Host '  --debug  输出详细调试信息'
    exit 0
}

if (-not $Secret) {
    Write-Host '错误: 必须提供 secret 参数' -ForegroundColor Red
    Write-Host 'Usage: .\h_side_init.ps1 {secret} [--debug]'
    exit 1
}

$ErrorActionPreference = 'Continue'
$TotalSteps = 7

function Show-Progress($step, $msg) {
    if (-not $DebugMode) {
        $pct = [math]::Floor(($step / $TotalSteps) * 100)
        Write-Progress -Activity '2c2a H-Side 初始化' -Status $msg -PercentComplete $pct
    }
}

function Step-Start($step, $msg) {
    Show-Progress $step $msg
    if ($DebugMode) {
        Write-Host "`n[Step $step/$TotalSteps] $msg" -ForegroundColor Cyan
    } else {
        Write-Host "[$step/$TotalSteps] $msg" -ForegroundColor White -NoNewline
    }
}

function Step-Ok($msg) {
    if ($DebugMode) {
        Write-Host "  [OK] $msg" -ForegroundColor Green
    } else {
        Write-Host ' OK' -ForegroundColor Green
    }
}

function Step-Fail($msg) {
    if ($DebugMode) {
        Write-Host "  [FAIL] $msg" -ForegroundColor Red
    } else {
        Write-Host ' FAIL' -ForegroundColor Red
        Write-Host "  $msg" -ForegroundColor Red
    }
}

function Step-Warn($msg) {
    if ($DebugMode) {
        Write-Host "  [WARN] $msg" -ForegroundColor Yellow
    }
}

function Dbg($msg) {
    if ($DebugMode) {
        Write-Host "  $msg" -ForegroundColor DarkGray
    }
}

$modeLabel = if ($DebugMode) { ' (调试模式)' } else { '' }
Write-Host ('=' * 50)
Write-Host "2c2a H-Side 初始化$modeLabel"
Write-Host ('=' * 50)

# --- Step 1: Parse Secret ---
Step-Start 1 '解析配置...'
try {
    $decodedBytes = [System.Convert]::FromBase64String($Secret)
    $decodedStr = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
    $config = $decodedStr | ConvertFrom-Json
    $cSideUrl = $config.c_side_url
    $token = $config.token
    $hostId = $config.host_id
    $expiresAt = $config.expires_at
    Step-Ok '配置解析成功'
    Dbg "c_side_url=$cSideUrl"
    Dbg "token=$($token.Substring(0,8))..."
    Dbg "host_id=$hostId"
    Dbg "expires_at=$expiresAt"
} catch {
    Step-Fail "配置解析失败: $_"
    exit 1
}

$hostname = $env:COMPUTERNAME
Dbg "hostname=$hostname"

# --- Step 2: Exchange Token ---
Step-Start 2 '交换令牌...'
$sessionToken = ''
$maxRetries = 3
for ($attempt = 0; $attempt -lt $maxRetries; $attempt++) {
    try {
        $headers = @{ 'Authorization' = "Bearer $token" }
        Dbg "POST $cSideUrl/bootstrap/api/get_session_token/"
        $resp = Invoke-RestMethod -Uri "$cSideUrl/bootstrap/api/get_session_token/" -Method POST -Headers $headers -ContentType 'application/json' -Body '{}' -UseBasicParsing -TimeoutSec 15
        if ($resp.success) {
            $sessionToken = $resp.session_token
            $expiresIn = $resp.expires_in
            Step-Ok "令牌交换成功 (有效期 ${expiresIn}s)"
            Dbg "session_token=$($sessionToken.Substring(0,8))..."
            break
        } else {
            Step-Warn "令牌交换失败: $($resp.error)"
            Dbg "错误响应: $($resp | ConvertTo-Json -Compress)"
        }
    } catch {
        Step-Warn "网络错误 (尝试 $($attempt+1)/$maxRetries): $($_.Exception.Message)"
    }
    if ($attempt -lt $maxRetries - 1) {
        $waitSec = ($attempt + 1) * 3
        Dbg "${waitSec}s 后重试..."
        Start-Sleep -Seconds $waitSec
    }
}
if (-not $sessionToken) {
    Step-Fail '令牌交换失败'
    exit 1
}

# --- Step 3: Create Self-Signed Certificate ---
Step-Start 3 '创建证书...'
$cert = $null
try {
    $existingCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=2c2a-h-side' -and $_.NotAfter -gt (Get-Date) }
    if ($existingCert) {
        Step-Warn '发现已有证书，正在移除...'
        Remove-Item -Path $existingCert.PSPath -Force -ErrorAction SilentlyContinue
    }

    $cert = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject 'CN=2c2a-h-side' -KeyExportPolicy Exportable -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddYears(5) -HashAlgorithm SHA256 -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1','2.5.29.19={text}ca=0')
    Step-Ok '证书创建成功'
    Dbg "thumbprint=$($cert.Thumbprint)"
    Dbg "subject=$($cert.Subject)"
    Dbg "notAfter=$($cert.NotAfter)"
} catch {
    Step-Fail "证书创建失败: $_"
    exit 1
}

try {
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    $rootStore.Open('ReadWrite')
    $rootStore.Add($cert)
    $rootStore.Close()

    $tpStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople', 'LocalMachine')
    $tpStore.Open('ReadWrite')
    $tpStore.Add($cert)
    $tpStore.Close()
    Step-Ok '证书已添加到 Root 和 TrustedPeople 存储'
} catch {
    Step-Warn "无法添加证书到存储: $_"
}

# --- Step 4: Create Service Account ---
Step-Start 4 '创建服务账户...'
$svcUser = '2c2a-service'
$svcPwd = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

try {
    $existingUser = Get-LocalUser -Name $svcUser -ErrorAction SilentlyContinue
    if ($existingUser) {
        Step-Warn "用户 $svcUser 已存在，正在移除..."
        Remove-LocalUser -Name $svcUser -ErrorAction SilentlyContinue
    }

    $secPwd = ConvertTo-SecureString $svcPwd -AsPlainText -Force
    New-LocalUser -Name $svcUser -Password $secPwd -Description '2c2a service account' -ErrorAction Stop
    Add-LocalGroupMember -Group 'Administrators' -Member $svcUser -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group 'Remote Management Users' -Member $svcUser -ErrorAction SilentlyContinue
    Step-Ok "服务账户已创建: $svcUser"
    Dbg "username=$svcUser"
    Dbg "password=$($svcPwd.Substring(0,4))****"
} catch {
    Step-Warn "服务账户创建问题: $_"
}

$fullUsername = "$hostname\$svcUser"
Dbg "fullUsername=$fullUsername"

# --- Step 5: Configure WinRM HTTPS ---
Step-Start 5 '配置 WinRM HTTPS...'
try {
    winrm quickconfig -quiet 2>$null | Out-Null

    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM -ErrorAction SilentlyContinue

    winrm delete 'winrm/config/Listener?Address=*+Transport=HTTPS' 2>$null | Out-Null

    $thumbprint = $cert.Thumbprint
    Dbg "创建 HTTPS 监听器, thumbprint=$thumbprint"
    winrm create "winrm/config/Listener?Address=*+Transport=HTTPS" "@{Hostname=`"2c2a-h-side`";CertificateThumbprint=`"$thumbprint`"}" 2>$null | Out-Null
    Step-Ok 'WinRM HTTPS 监听器已创建'

    winrm set 'winrm/config/Service/Auth' '@{ClientCertificate="true";Basic="true"}' 2>$null | Out-Null
    winrm set 'winrm/config/Service' '@{AllowUnencrypted="false"}' 2>$null | Out-Null

    netsh advfirewall firewall delete rule name='WinRM HTTPS' 2>$null | Out-Null
    netsh advfirewall firewall add rule name='WinRM HTTPS' dir=in action=allow protocol=TCP localport=5986 2>$null | Out-Null
    Step-Ok '防火墙规则已添加 (端口 5986)'

    Dbg "创建证书映射: user=$fullUsername"
    winrm create "winrm/config/Service/Auth/CertMapping?Issuer=$thumbprint+Subject=2c2a-h-side+URI=*" "@{UserName=`"$fullUsername`";Password=`"$svcPwd`"}" 2>$null | Out-Null
    Step-Ok '证书映射已创建'

    Restart-Service -Name WinRM -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Step-Ok 'WinRM 服务已重启'
} catch {
    Step-Warn "WinRM 配置问题: $_"
}

$portCheck = Test-NetConnection -ComputerName 127.0.0.1 -Port 5986 -WarningAction SilentlyContinue
if ($portCheck.TcpTestSucceeded) {
    Step-Ok 'WinRM HTTPS 端口 5986 已开放'
} else {
    Step-Warn 'WinRM HTTPS 端口 5986 未开放'
}

# --- Step 6: Export PFX and Upload ---
Step-Start 6 '上传证书到服务器...'
$configDir = "$env:ProgramData\2c2a"
New-Item -ItemType Directory -Path $configDir -Force | Out-Null

$pfxPath = Join-Path $configDir 'cert.pfx'
$pfxPassword = '2c2acert'

try {
    $secPfxPwd = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secPfxPwd -Force | Out-Null
    Dbg "PFX 已导出到 $pfxPath"
} catch {
    Step-Fail "PFX 导出失败: $_"
    exit 1
}

try {
    $pfxBytes = [System.IO.File]::ReadAllBytes($pfxPath)
    $pfxB64 = [System.Convert]::ToBase64String($pfxBytes)

    $payload = @{
        token = $token
        pfx_b64 = $pfxB64
        pfx_password = $pfxPassword
        service_user = $svcUser
        service_password = $svcPwd
    } | ConvertTo-Json -Compress

    Dbg "PFX b64 长度: $($pfxB64.Length)"
    Dbg "Payload 大小: $($payload.Length) bytes"
    Dbg "POST $cSideUrl/bootstrap/api/upload_host_cert/"

    $resp = Invoke-RestMethod -Uri "$cSideUrl/bootstrap/api/upload_host_cert/" -Method POST -ContentType 'application/json' -Body $payload -UseBasicParsing -TimeoutSec 30
    if ($resp.success) {
        Step-Ok '证书已上传到服务器'
        Remove-Item -Path $pfxPath -Force -ErrorAction SilentlyContinue
    } else {
        Step-Fail "证书上传失败: $($resp.error)"
    }
} catch {
    Step-Fail "证书上传错误: $_"
}

# --- Step 7: Save Config ---
Step-Start 7 '保存配置...'
$localConfig = @{
    session_token = $sessionToken
    host_id = $hostId
    c_side_url = $cSideUrl
    hostname = $hostname
    ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -notlike '127.*' } | Select-Object -First 1).IPAddress
} | ConvertTo-Json -Depth 3

$configPath = Join-Path $configDir 'h_side_config.json'
$localConfig | Out-File -FilePath $configPath -Encoding UTF8
Step-Ok "配置已保存到 $configPath"

$credPath = Join-Path $configDir 'winrm_credentials.txt'
"$svcUser`n$svcPwd" | Out-File -FilePath $credPath -Encoding UTF8 -NoNewline

$thumbPath = Join-Path $configDir 'winrm_cert_thumb.txt'
$cert.Thumbprint | Out-File -FilePath $thumbPath -Encoding UTF8 -NoNewline

# --- Complete ---
if (-not $DebugMode) {
    Write-Progress -Activity '2c2a H-Side 初始化' -Status '完成' -PercentComplete 100 -Completed
}

Write-Host ''
Write-Host ('=' * 50)
Write-Host 'OK H-Side 初始化完成!' -ForegroundColor Green
Write-Host "  会话令牌: $($sessionToken.Substring(0,8))..."
Write-Host '  WinRM HTTPS: 端口 5986'
Write-Host "  服务账户: $svcUser"
Write-Host ('=' * 50)
