# Панель в потоке: сервис читает Kafka, панель обновляется на глазах
param(
    [int]$Port = 8086,
    [int]$Events = 40,
    [switch]$NoBrowser,
    [string]$PythonExe = 'C:\Users\idv1102\PycharmProjects\PythonProject11\.venv\Scripts\python.exe'
)

$ErrorActionPreference = 'Continue'
chcp 65001 | Out-Null
$Root = Split-Path -Parent $PSScriptRoot
$LinuxRoot = '/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher'
Set-Location $Root

Write-Host ''
Write-Host '  ПАНЕЛЬ В ПОТОКЕ' -ForegroundColor Cyan
Write-Host '  ---------------' -ForegroundColor DarkCyan

Write-Host '  поднимаю Redpanda...'
wsl -e bash -lc "docker start siem-redpanda >/dev/null 2>&1" | Out-Null
for ($i = 0; $i -le 15; $i++) {
    Start-Sleep -Seconds 2
    if (wsl -e bash -lc "docker exec siem-redpanda rpk cluster health 2>/dev/null") { break }
}

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

Write-Host '  запускаю сервис с чтением потока...'
$service = Start-Process -FilePath $PythonExe -ArgumentList @(
    '-m', 'siem_enricher', '--log-level', 'ERROR', 'serve',
    '--config', 'config\config.kafka.json', '--run-pipeline', '--port', "$Port"
) -WorkingDirectory $Root -WindowStyle Hidden -PassThru

for ($i = 1; $i -le 40; $i++) {
    Start-Sleep -Milliseconds 800
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 2 | Out-Null; break } catch { }
}

Write-Host "  отправляю $Events событий в Kafka..."
wsl -e bash -lc "cd $LinuxRoot; docker exec siem-redpanda rpk topic delete siem-events >/dev/null 2>&1; docker exec siem-redpanda rpk topic create siem-events -p 1 -r 1 >/dev/null 2>&1; head -$Events var/experiment/dataset.jsonl | docker exec -i siem-redpanda rpk topic produce siem-events -f '%v\n' 2>&1 | tail -1"

for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 2
    try {
        $stats = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/ui/events?limit=1" -TimeoutSec 5
        if ($stats.stats.total -ge $Events) { break }
    } catch { }
}

$url = "http://127.0.0.1:$Port/ui"
Write-Host ("  в панели: {0} событий, критичных {1}, блокировок {2}" -f `
    $stats.stats.total, $stats.stats.critical, $stats.stats.blocked) -ForegroundColor Green
Write-Host "  Открываю: $url" -ForegroundColor Cyan
Write-Host '  События пришли из Kafka, панель обновилась сама, без вызовов API.' -ForegroundColor Cyan
if (-not $NoBrowser) { Start-Process $url }
