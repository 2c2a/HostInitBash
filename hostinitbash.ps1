param(
    [Parameter(Mandatory=$true)]
    [string]$Secret
)

$ErrorActionPreference = 'Stop'

$exeUrl = 'https://2c2a.cc.cd/hostinitbash.exe'
$exePath = Join-Path $env:TEMP 'h_side_init.exe'

Write-Host '==================================================' -ForegroundColor Cyan
Write-Host '  2c2a H 端自动配置' -ForegroundColor Cyan
Write-Host '==================================================' -ForegroundColor Cyan

Write-Host '[1/2] 下载初始化程序...' -ForegroundColor Yellow

try {
    Invoke-WebRequest -Uri $exeUrl -OutFile $exePath -UseBasicParsing
} catch {
    Write-Host "  下载失败: $_" -ForegroundColor Red
    Write-Host '  请使用备用命令手动下载' -ForegroundColor Yellow
    exit 1
}

$fileSize = (Get-Item $exePath).Length
if ($fileSize -lt 1024) {
    Write-Host '  下载文件异常(过小)，可能下载不完整' -ForegroundColor Red
    Remove-Item $exePath -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "  下载完成 ($fileSize 字节)" -ForegroundColor Green

Write-Host '[2/2] 运行初始化...' -ForegroundColor Yellow

try {
    & $exePath $Secret
} catch {
    Write-Host "  运行失败: $_" -ForegroundColor Red
    exit 1
} finally {
    Remove-Item $exePath -Force -ErrorAction SilentlyContinue
}
