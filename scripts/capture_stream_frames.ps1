# Съёмка кадров панели по мере поступления событий из Kafka
param(
    [int]$Port = 8086,
    [int]$Batches = 6,
    [int]$PerBatch = 8,
    [string]$PythonExe = 'C:\Users\idv1102\PycharmProjects\PythonProject11\.venv\Scripts\python.exe'
)

$ErrorActionPreference = 'Continue'
chcp 65001 | Out-Null
$Root = Split-Path -Parent $PSScriptRoot
$LinuxRoot = '/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher'
$Browser = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$OutDir = Join-Path $Root 'var\gifs'
Set-Location $Root

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Remove-Item "$OutDir\*.png" -Force -ErrorAction SilentlyContinue

function Capture([string]$Path) {
    Remove-Item $Path -ErrorAction SilentlyContinue
    & $Browser --headless=new --disable-gpu --hide-scrollbars --window-size=1600,1050 `
        --virtual-time-budget=6000 --screenshot=$Path "http://127.0.0.1:$Port/ui" 2>&1 | Out-Null
}

# чистое состояние и запуск сервиса в режиме потока
Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
foreach ($file in @('var\state\provenance.db', 'var\state\checkpoint.json')) {
    if (Test-Path $file) { Remove-Item $file -Force }
}
Start-Sleep -Seconds 1

$env:PYTHONPATH = Join-Path $Root 'src'
$env:PYTHONIOENCODING = 'utf-8'
$env:TOKENIZERS_PARALLELISM = 'false'
$env:TRANSFORMERS_VERBOSITY = 'error'

$service = Start-Process -FilePath $PythonExe -ArgumentList @(
    '-m', 'siem_enricher', '--log-level', 'ERROR', 'serve',
    '--config', 'config\config.kafka.json', '--run-pipeline', '--port', "$Port"
) -WorkingDirectory $Root -WindowStyle Hidden -PassThru

for ($i = 1; $i -le 40; $i++) {
    Start-Sleep -Milliseconds 800
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/healthz" -TimeoutSec 2 | Out-Null; break } catch { }
}

wsl -e bash -lc "cd $LinuxRoot; docker exec siem-redpanda rpk topic delete siem-events >/dev/null 2>&1; docker exec siem-redpanda rpk topic create siem-events -p 1 -r 1 >/dev/null 2>&1" | Out-Null

Write-Host '  кадр 0: пустая панель'
Capture (Join-Path $OutDir 'frame_00.png')

for ($batch = 1; $batch -le $Batches; $batch++) {
    $from = ($batch - 1) * $PerBatch + 1
    $to = $batch * $PerBatch
    wsl -e bash -lc "cd $LinuxRoot; sed -n '${from},${to}p' var/experiment/dataset.jsonl | docker exec -i siem-redpanda rpk topic produce siem-events -f '%v\n' >/dev/null 2>&1" | Out-Null
    Start-Sleep -Seconds 4
    $name = 'frame_{0:D2}.png' -f $batch
    Capture (Join-Path $OutDir $name)
    Write-Host ("  кадр {0}: отправлено событий {1}" -f $batch, $to) -ForegroundColor Cyan
}

Write-Host "  кадров снято: $((Get-ChildItem $OutDir -Filter 'frame_*.png').Count)"
