# Живой поток Kafka: Redpanda -> сервис -> топик результатов
param(
    [int]$Events = 136,
    [switch]$NoPause,
    [string]$PythonExe = 'C:\Users\idv1102\PycharmProjects\PythonProject11\.venv\Scripts\python.exe'
)

$ErrorActionPreference = 'Continue'
chcp 65001 | Out-Null
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Topic = 'siem-events'
$OutTopic = 'siem-enriched'
$LinuxRoot = '/mnt/c/Users/idv1102/Documents/deepseek-harness/default-workspace/siem-enricher'

Write-Host ''
Write-Host '  ЖИВОЙ ПОТОК KAFKA' -ForegroundColor Cyan
Write-Host '  -----------------' -ForegroundColor DarkCyan

# 1. брокер
Write-Host '  поднимаю Redpanda...'
wsl -e bash -lc "docker start siem-redpanda >/dev/null 2>&1 || docker run -d --name siem-redpanda -p 9092:9092 -p 9644:9644 redpandadata/redpanda:v24.2.7 redpanda start --overprovisioned --smp 1 --memory 1G --reserve-memory 0M --node-id 0 --check=false --kafka-addr PLAINTEXT://0.0.0.0:9092 --advertise-kafka-addr PLAINTEXT://localhost:9092" | Out-Null
for ($i = 0; $i -le 20; $i++) {
    Start-Sleep -Seconds 2
    $health = wsl -e bash -lc "docker exec siem-redpanda rpk cluster health 2>/dev/null"
    if ($health) { break }
}
Write-Host '  брокер готов' -ForegroundColor Green

# 2. чистые топики и заливка событий
wsl -e bash -lc "cd $LinuxRoot; docker exec siem-redpanda rpk topic delete $Topic >/dev/null 2>&1; docker exec siem-redpanda rpk topic delete $OutTopic >/dev/null 2>&1; docker exec siem-redpanda rpk topic create $Topic -p 1 -r 1 >/dev/null 2>&1; docker exec siem-redpanda rpk topic create $OutTopic -p 1 -r 1 >/dev/null 2>&1" | Out-Null

Write-Host "  заливаю $Events событий в топик $Topic..."
wsl -e bash -lc "cd $LinuxRoot; head -$Events var/experiment/dataset.jsonl | docker exec -i siem-redpanda rpk topic produce $Topic -f '%v\n' 2>&1 | tail -1"

Write-Host ''
Write-Host '  запускаю сервис: источник kafka, приёмники kafka + файл' -ForegroundColor Cyan
foreach ($file in @('var\state\provenance.db', 'var\state\checkpoint.json')) {
    if (Test-Path $file) { Remove-Item $file -Force }
}

$env:PYTHONPATH = Join-Path $Root 'src'
$env:PYTHONIOENCODING = 'utf-8'
$env:TOKENIZERS_PARALLELISM = 'false'
$env:TRANSFORMERS_VERBOSITY = 'error'
$env:HF_HUB_DISABLE_PROGRESS_BARS = '1'

& $PythonExe -m siem_enricher --log-level WARNING run --config config\config.kafka.json --max-events $Events 2>&1 |
    Select-Object -Last 12

Write-Host ''
Write-Host '  проверяю топик результатов:' -ForegroundColor Cyan
wsl -e bash -lc "docker exec siem-redpanda rpk topic consume $OutTopic --num 1 --offset beginning 2>/dev/null | head -c 600; echo"

if (-not $NoPause) { Read-Host '  Enter — закрыть' | Out-Null }
