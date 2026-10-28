# Смоук-проверка HTTP-слоя сервиса обогащения.
# Поднимает сервис на свободном порту, вызывает все эндпоинты, печатает результат и останавливает его.
#Requires -Version 5.1
[CmdletBinding()]
param(
    [int]$Port = 8099,
    [string]$Config = 'config/config.local.json',
    [string]$Python = ''
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:PYTHONIOENCODING = 'utf-8'

if (-not $Python) {
    $candidate = Join-Path (Get-Location) '.venv\Scripts\python.exe'
    $Python = if (Test-Path $candidate) { $candidate } else { 'python' }
}

$base = "http://127.0.0.1:$Port"
$log = Join-Path (Get-Location) 'var\logs\http_smoke.log'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null

Write-Host "-> запускаю сервис: $Python -m siem_enricher serve --port $Port" -ForegroundColor Cyan
$process = Start-Process -FilePath $Python `
    -ArgumentList @('-m', 'siem_enricher', 'serve', '--config', $Config, '--port', "$Port") `
    -PassThru -RedirectStandardOutput $log -RedirectStandardError "$log.err" -NoNewWindow

function Invoke-Api {
    param([string]$Name, [string]$Method, [string]$Path, $Body)
    try {
        if ($Body) {
            $json = $Body | ConvertTo-Json -Depth 8 -Compress
            $response = Invoke-RestMethod -Uri "$base$Path" -Method $Method -Body $json `
                -ContentType 'application/json; charset=utf-8' -TimeoutSec 60
        } else {
            $response = Invoke-RestMethod -Uri "$base$Path" -Method $Method -TimeoutSec 60
        }
        $preview = ($response | ConvertTo-Json -Depth 4 -Compress)
        if ($preview.Length -gt 150) { $preview = $preview.Substring(0, 150) + '…' }
        Write-Host ("[ OK ] {0,-26} {1} {2} -> {3}" -f $Name, $Method, $Path, $preview) -ForegroundColor Green
        return $response
    } catch {
        Write-Host ("[НЕТ ] {0,-26} {1} {2} -> {3}" -f $Name, $Method, $Path, $_.Exception.Message) -ForegroundColor Red
        return $null
    }
}

try {
    $ready = $false
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        Start-Sleep -Milliseconds 500
        try {
            $null = Invoke-RestMethod -Uri "$base/healthz" -TimeoutSec 3
            $ready = $true
            break
        } catch { }
    }
    if (-not $ready) {
        Write-Host '!! сервис не поднялся, лог:' -ForegroundColor Red
        Get-Content $log -Tail 20 -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Host "сервис поднят за $([math]::Round($attempt * 0.5, 1)) с" -ForegroundColor Cyan

    Invoke-Api 'healthz'      'GET'  '/healthz' | Out-Null
    Invoke-Api 'readyz'       'GET'  '/readyz'  | Out-Null
    Invoke-Api 'version'      'GET'  '/v1/version' | Out-Null
    Invoke-Api 'policies'     'GET'  '/v1/policies' | Out-Null

    $event = @{
        '@timestamp' = '2025-03-03T09:41:00Z'
        'id'         = '1700000000.000900'
        'agent'      = @{ name = 'pc-hr-01'; ip = '10.0.0.11' }
        'rule'       = @{ id = '92500'; level = 12; description = 'Загрузка архива во внешний файлообменник' }
        'data'       = @{
            action = 'upload'
            win    = @{
                system    = @{ computer = 'pc-hr-01' }
                eventdata = @{
                    targetFilename = 'C:\Users\ivanov\Documents\hr_2025.zip'
                    image          = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
                    user           = 'DOMAIN\ivanov'
                    destinationIp  = '185.220.101.5'
                    destinationUrl = 'https://dropbox.com/s/hr_2025.zip'
                }
            }
        }
    }
    $enriched = Invoke-Api 'enrich' 'POST' '/v1/enrich?source=http' $event
    if ($enriched) {
        Write-Host ("   класс={0} уверенность={1} риск={2} ({3}) правила={4}" -f `
            $enriched.data_sensitivity, $enriched.sensitivity_confidence, $enriched.risk_score, `
            $enriched.risk_severity, ($enriched.policy_rule_ids -join ',')) -ForegroundColor DarkCyan
    }

    Invoke-Api 'classify' 'POST' '/v1/classify' @{ paths = @('C:\keys\id_rsa', 'C:\Public\readme.md') } | Out-Null
    Invoke-Api 'chain'    'POST' '/v1/provenance/chain' @{ path = 'C:\Users\ivanov\Documents\hr_2025.zip' } | Out-Null
    Invoke-Api 'audit'    'GET'  '/v1/audit?limit=3' | Out-Null

    try {
        $metrics = Invoke-WebRequest -Uri "$base/metrics" -TimeoutSec 30 -UseBasicParsing
        $lines = ($metrics.Content -split "`n" | Where-Object { $_ -match '^siem_enricher_' }).Count
        Write-Host ("[ OK ] {0,-26} GET /metrics -> строк метрик: {1}" -f 'metrics', $lines) -ForegroundColor Green
    } catch {
        Write-Host ("[НЕТ ] metrics -> {0}" -f $_.Exception.Message) -ForegroundColor Red
    }
} finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        Write-Host '-> сервис остановлен' -ForegroundColor Cyan
    }
}
