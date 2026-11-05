# Панель аналитика: прогон событий, запуск панели и открытие браузера
param(
    [int]$Port = 8099,
    [int]$Limit = 136,
    [switch]$NoBrowser,
    [string]$PythonExe = 'C:\Users\idv1102\PycharmProjects\PythonProject11\.venv\Scripts\python.exe'
)

$ErrorActionPreference = 'Continue'
chcp 65001 | Out-Null
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host ''
Write-Host '  ПАНЕЛЬ АНАЛИТИКА' -ForegroundColor Cyan
Write-Host '  -----------------' -ForegroundColor DarkCyan

# 1. чистое состояние истории, чтобы числа совпадали с ВКР
foreach ($file in @('var\state\provenance.db', 'var\state\checkpoint.json')) {
    if (Test-Path $file) { Remove-Item $file -Force; Write-Host "  сброшено: $file" }
}

# 2. прогон событий через сервис
if (Test-Path $PythonExe) {
    Write-Host "  обогащаю $Limit событий..."
    $env:PYTHONPATH = Join-Path $Root 'src'
    $env:PYTHONIOENCODING = 'utf-8'
    $env:TOKENIZERS_PARALLELISM = 'false'
    $env:TRANSFORMERS_VERBOSITY = 'error'
    $env:HF_HUB_DISABLE_PROGRESS_BARS = '1'
    & $PythonExe -m siem_enricher --log-level ERROR replay `
        --input (Join-Path $Root 'var\experiment\dataset.jsonl') `
        --limit $Limit --output (Join-Path $Root 'var\screens\replay_out.jsonl') 2>&1 | Select-Object -Last 12
} else {
    Write-Host '  python не найден, беру ранее сохранённые события' -ForegroundColor Yellow
}

# 3. освободить порт и запустить панель
Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1

$panel = Start-Process -FilePath $PythonExe -ArgumentList 'tools\panel.py', '--port', "$Port" `
    -WorkingDirectory $Root -WindowStyle Hidden -PassThru

for ($i = 1; $i -le 20; $i++) {
    Start-Sleep -Milliseconds 700
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 3 | Out-Null; break } catch { }
}

$url = "http://127.0.0.1:$Port/"
try {
    $stats = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/events?limit=1" -TimeoutSec 8
    Write-Host ("  в панели событий: {0}, критичных: {1}, блокировок: {2}" -f `
        $stats.stats.total, $stats.stats.critical, $stats.stats.blocked) -ForegroundColor Green
} catch {
    Write-Host '  панель не ответила' -ForegroundColor Red
}

Write-Host ''
Write-Host "  Открываю: $url" -ForegroundColor Cyan
Write-Host '  Фильтры сверху, клик по строке — обоснование решения справа.' -ForegroundColor Cyan
Write-Host "  Остановить: Get-Process -Id $($panel.Id) | Stop-Process" -ForegroundColor DarkGray

if (-not $NoBrowser) { Start-Process $url }
