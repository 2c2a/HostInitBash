param(
    [Parameter(Mandatory=$true)]
    [string]$Secret,
    [switch]$VerboseLog
)

$ErrorActionPreference = 'Continue'

function Write-Status($msg) { Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host "[ERR] $msg" -ForegroundColor Red }
function Write-Dbg($msg) { if ($VerboseLog) { Write-Host "[DBG] $msg" -ForegroundColor DarkGray } }

Write-Host ('=' * 50)
Write-Host '2c2a H-Side Init (PowerShell Debug Version)'
Write-Host ('=' * 50)

# --- Step 1: Parse Secret ---
Write-Status 'Step 1: Parsing secret...'
try {
    $decodedBytes = [System.Convert]::FromBase64String($Secret)
    $decodedStr = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
    $config = $decodedStr | ConvertFrom-Json
    $cSideUrl = $config.c_side_url
    $token = $config.token
    $hostId = $config.host_id
    $expiresAt = $config.expires_at
    Write-Ok "c_side_url=$cSideUrl"
    Write-Ok "token=$($token.Substring(0,8))..."
    Write-Ok "host_id=$hostId"
} catch {
    Write-Err "Failed to parse secret: $_"
    exit 1
}

$hostname = $env:COMPUTERNAME
Write-Ok "hostname=$hostname"

# --- Step 2: Exchange Token ---
Write-Status 'Step 2: Exchanging token for session token...'
$sessionToken = ''
$maxRetries = 3
for ($attempt = 0; $attempt -lt $maxRetries; $attempt++) {
    try {
        $headers = @{ 'Authorization' = "Bearer $token" }
        $resp = Invoke-RestMethod -Uri "$cSideUrl/bootstrap/api/get_session_token/" -Method POST -Headers $headers -ContentType 'application/json' -Body '{}' -UseBasicParsing -TimeoutSec 15
        if ($resp.success) {
            $sessionToken = $resp.session_token
            $expiresIn = $resp.expires_in
            Write-Ok "Session token obtained, expires_in=${expiresIn}s"
            break
        } else {
            Write-Warn "Token exchange failed: $($resp.error)"
        }
    } catch {
        Write-Warn "Network error (attempt $($attempt+1)/$maxRetries): $($_.Exception.Message)"
    }
    if ($attempt -lt $maxRetries - 1) {
        Start-Sleep -Seconds (($attempt + 1) * 3)
    }
}
if (-not $sessionToken) {
    Write-Err 'Token exchange failed after all retries'
    exit 1
}

# --- Step 3: Create Self-Signed Certificate ---
Write-Status 'Step 3: Creating self-signed certificate for WinRM...'
$cert = $null
try {
    $existingCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=2c2a-h-side' -and $_.NotAfter -gt (Get-Date) }
    if ($existingCert) {
        Write-Warn "Found existing cert, removing..."
        Remove-Item -Path $existingCert.PSPath -Force -ErrorAction SilentlyContinue
    }

    $cert = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject 'CN=2c2a-h-side' -KeyExportPolicy Exportable -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddYears(5) -HashAlgorithm SHA256 -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1','2.5.29.19={text}ca=0')
    Write-Ok "Certificate created: thumbprint=$($cert.Thumbprint)"
} catch {
    Write-Err "Certificate creation failed: $_"
    exit 1
}

# Export cert to Root and TrustedPeople stores
try {
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    $rootStore.Open('ReadWrite')
    $rootStore.Add($cert)
    $rootStore.Close()

    $tpStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPeople', 'LocalMachine')
    $tpStore.Open('ReadWrite')
    $tpStore.Add($cert)
    $tpStore.Close()
    Write-Ok 'Certificate added to Root and TrustedPeople stores'
} catch {
    Write-Warn "Could not add cert to stores: $_"
}

# --- Step 4: Create Service Account ---
Write-Status 'Step 4: Creating service account...'
$svcUser = '2c2a-service'
$svcPwd = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

try {
    $existingUser = Get-LocalUser -Name $svcUser -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Warn "User $svcUser already exists, removing..."
        Remove-LocalUser -Name $svcUser -ErrorAction SilentlyContinue
    }

    $secPwd = ConvertTo-SecureString $svcPwd -AsPlainText -Force
    New-LocalUser -Name $svcUser -Password $secPwd -Description '2c2a service account' -ErrorAction Stop
    Add-LocalGroupMember -Group 'Administrators' -Member $svcUser -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group 'Remote Management Users' -Member $svcUser -ErrorAction SilentlyContinue
    Write-Ok "Service account created: $svcUser"
} catch {
    Write-Warn "Service account creation issue: $_"
}

$fullUsername = "$hostname\$svcUser"

# --- Step 5: Configure WinRM HTTPS ---
Write-Status 'Step 5: Configuring WinRM HTTPS...'
try {
    winrm quickconfig -quiet 2>$null | Out-Null

    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM -ErrorAction SilentlyContinue

    winrm delete 'winrm/config/Listener?Address=*+Transport=HTTPS' 2>$null | Out-Null

    $thumbprint = $cert.Thumbprint
    winrm create "winrm/config/Listener?Address=*+Transport=HTTPS" "@{Hostname=`"2c2a-h-side`";CertificateThumbprint=`"$thumbprint`"}" 2>$null | Out-Null
    Write-Ok 'WinRM HTTPS listener created'

    winrm set 'winrm/config/Service/Auth' '@{ClientCertificate="true";Basic="true"}' 2>$null | Out-Null
    winrm set 'winrm/config/Service' '@{AllowUnencrypted="false"}' 2>$null | Out-Null

    netsh advfirewall firewall delete rule name='WinRM HTTPS' 2>$null | Out-Null
    netsh advfirewall firewall add rule name='WinRM HTTPS' dir=in action=allow protocol=TCP localport=5986 2>$null | Out-Null
    Write-Ok 'Firewall rule added for port 5986'

    winrm create "winrm/config/Service/Auth/CertMapping?Issuer=$thumbprint+Subject=2c2a-h-side+URI=*" "@{UserName=`"$fullUsername`";Password=`"$svcPwd`"}" 2>$null | Out-Null
    Write-Ok 'Cert mapping created'

    Restart-Service -Name WinRM -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Write-Ok 'WinRM service restarted'
} catch {
    Write-Warn "WinRM configuration issue: $_"
}

# Verify port 5986
$portCheck = Test-NetConnection -ComputerName 127.0.0.1 -Port 5986 -WarningAction SilentlyContinue
if ($portCheck.TcpTestSucceeded) {
    Write-Ok 'WinRM HTTPS port 5986 is open'
} else {
    Write-Warn 'WinRM HTTPS port 5986 is NOT open'
}

# --- Step 6: Export PFX and Upload to Server ---
Write-Status 'Step 6: Uploading certificate to server...'
$configDir = "$env:ProgramData\2c2a"
New-Item -ItemType Directory -Path $configDir -Force | Out-Null

$pfxPath = Join-Path $configDir 'cert.pfx'
$pfxPassword = '2c2acert'

try {
    $secPfxPwd = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $secPfxPwd -Force | Out-Null
    Write-Ok "PFX exported to $pfxPath"
} catch {
    Write-Err "PFX export failed: $_"
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

    Write-Dbg "PFX b64 length: $($pfxB64.Length)"
    Write-Dbg "Payload size: $($payload.Length) bytes"

    $resp = Invoke-RestMethod -Uri "$cSideUrl/bootstrap/api/upload_host_cert/" -Method POST -ContentType 'application/json' -Body $payload -UseBasicParsing -TimeoutSec 30
    if ($resp.success) {
        Write-Ok 'Certificate uploaded to server!'
        Remove-Item -Path $pfxPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Err "Certificate upload failed: $($resp.error)"
    }
} catch {
    Write-Err "Certificate upload error: $_"
}

# --- Step 7: Save Config ---
Write-Status 'Step 7: Saving local config...'
$localConfig = @{
    session_token = $sessionToken
    host_id = $hostId
    c_side_url = $cSideUrl
    hostname = $hostname
    ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' -and $_.IPAddress -notlike '127.*' } | Select-Object -First 1).IPAddress
} | ConvertTo-Json -Depth 3

$configPath = Join-Path $configDir 'h_side_config.json'
$localConfig | Out-File -FilePath $configPath -Encoding UTF8
Write-Ok "Config saved to $configPath"

# Save credentials
$credPath = Join-Path $configDir 'winrm_credentials.txt'
"$svcUser`n$svcPwd" | Out-File -FilePath $credPath -Encoding UTF8 -NoNewline

$thumbPath = Join-Path $configDir 'winrm_cert_thumb.txt'
$cert.Thumbprint | Out-File -FilePath $thumbPath -Encoding UTF8 -NoNewline

Write-Host ('=' * 50)
Write-Ok 'H-Side initialization complete!'
Write-Host "  Session token: $($sessionToken.Substring(0,8))..."
Write-Host "  WinRM HTTPS: port 5986"
Write-Host "  Service account: $svcUser"
Write-Host ('=' * 50)
