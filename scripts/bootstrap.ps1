# PowerShell-обвязка проекта: подготовка окружения и типовые сценарии.
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Python = 'python',
    [switch]$WithMl,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

Write-Host "== Подготовка окружения siem-enricher ==" -ForegroundColor Cyan
Write-Host "Каталог проекта: $projectRoot"

if (-not (Test-Path '.venv')) {
    Write-Host '-> создаю виртуальное окружение .venv'
    & $Python -m venv .venv
} else {
    Write-Host '-> .venv уже существует'
}

$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) { throw "Не найден интерпретатор venv: $venvPython" }

if (-not $SkipInstall) {
    Write-Host '-> обновляю pip'
    & $venvPython -m pip install --upgrade pip | Out-Null

    if ($WithMl) {
        Write-Host '-> устанавливаю зависимости с ML (scikit-learn, joblib, pandas)'
        & $venvPython -m pip install -e '.[all,dev]'
    } else {
        Write-Host '-> устанавливаю ядро и сервисные зависимости (без ML)'
        & $venvPython -m pip install -e '.[config,service,http,dev]'
    }
}

Write-Host '-> проверяю ядро (сквозной сценарий без внешних сервисов)'
& $venvPython tools\smoke_pipeline.py

Write-Host '-> прогоняю тесты'
& $venvPython -m pytest -q

Write-Host ''
Write-Host 'Готово. Полезные команды:' -ForegroundColor Green
Write-Host '  .\.venv\Scripts\Activate.ps1'
Write-Host '  python -m siem_enricher replay --config config/config.example.json --input tests/fixtures/events/sample_events.jsonl --output var/enriched_events.jsonl'
Write-Host '  python -m siem_enricher serve  --config config/config.example.json --port 8080'
