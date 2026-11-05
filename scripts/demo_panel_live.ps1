# Живой режим: сервис обогащает события по API, панель обновляется на лету
param(
    [int]$Port = 8085,
    [int]$Events = 80,
    [switch]$NoBrowser,
    [string]$PythonExe = 'C:\Users\idv1102\PycharmProjects\PythonProject11\.venv\Scripts\python.exe'
)

$ErrorActionPreference = 'Continue'
chcp 65001 | Out-Null
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host ''
Write-Host '  ЖИВОЙ РЕЖИМ: сервис + панель' -ForegroundColor Cyan
Write-Host '  ----------------------------' -ForegroundColor DarkCyan

foreach ($file in @('var\state\provenance.db', 'var\state\checkpoint.json')) {
    if (Test-Path $file) { Remove-Item $file -Force }
}

$env:PYTHONPATH = Join-Path $Root 'src'
$env:PYTHONIOENCODING = 'utf-8'
$env:TOKENIZERS_PARALLELISM = 'false'
$env:TRANSFORMERS_VERBOSITY = 'error'

Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

Write-Host '  поднимаю сервис...'
$service = Start-Process -FilePath $PythonExe -ArgumentList @(
    '-m', 'siem_enricher', '--log-level', 'ERROR', 'serve',
    '--config', 'config/config.local.json', '--port', "$Port"
) -WorkingDirectory $Root -WindowStyle Hidden -PassThru

for ($i = 1; $i -le 40; $i++) {
    Start-Sleep -Milliseconds 700
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 2 | Out-Null; break } catch { }
}

Write-Host "  отправляю $Events событий в /v1/enrich..."
$sent = 0
Get-Content 'var\experiment\dataset.jsonl' -Encoding UTF8 | Select-Object -First $Events | ForEach-Object {
    try {
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/v1/enrich" `
            -ContentType 'application/json' -Body ([System.Text.Encoding]::UTF8.GetBytes($_)) -TimeoutSec 20 | Out-Null
        $sent++
        if ($sent % 20 -eq 0) { Write-Host "    обработано: $sent" }
    } catch { }
}

$stats = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/ui/events?limit=1" -TimeoutSec 8
Write-Host ("  в панели: {0} событий, критичных {1}, блокировок {2}" -f `
    $stats.stats.total, $stats.stats.critical, $stats.stats.blocked) -ForegroundColor Green

$url = "http://127.0.0.1:$Port/ui"
Write-Host ''
Write-Host "  Открываю панель: $url" -ForegroundColor Cyan
Write-Host '  Клик по строке — обоснование, кнопка «показать цепочку» — шаги происхождения.' -ForegroundColor Cyan
Write-Host "  Сервис: pid $($service.Id). Остановить: Stop-Process -Id $($service.Id)" -ForegroundColor DarkGray

if (-not $NoBrowser) { Start-Process $url }
