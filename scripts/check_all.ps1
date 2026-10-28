# Проверка качества проекта: конфигурации, сквозной сценарий, тесты, линтер, типы.
# Шаги, для которых не установлены инструменты, помечаются как пропущенные.
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Config = 'config/config.local.json',
    [switch]$IncludeDocker,
    [switch]$SkipLint
)

$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:PYTHONIOENCODING = 'utf-8'

$failed = @()
$skipped = @()

function Test-Module {
    param([string]$Name)
    $null = python -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('$Name') else 1)" 2>$null
    return $LASTEXITCODE -eq 0
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "== $Name ==" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) {
        Write-Host "!! шаг провален: $Name" -ForegroundColor Red
        $script:failed += $Name
    }
}

Invoke-Step 'Проверка конфигурации и правил' {
    python -m siem_enricher validate-config --config $Config --quiet
}

Invoke-Step 'Сквозной сценарий (с ML, если доступен)' {
    python tools/smoke_pipeline.py --config $Config --quiet
}

Invoke-Step 'Сквозной сценарий (только правила)' {
    python tools/smoke_pipeline.py --config $Config --force-heuristic --quiet
}

Invoke-Step 'Тесты (стандартный unittest)' {
    python -m unittest discover -s tests -t .
}

if (-not $SkipLint) {
    if (Test-Module 'ruff') {
        Invoke-Step 'Линтер ruff' { python -m ruff check src tests tools ml }
    } else {
        Write-Host '-- ruff не установлен, шаг пропущен (pip install -e ".[dev]")' -ForegroundColor Yellow
        $skipped += 'Линтер ruff'
    }
    if (Test-Module 'mypy') {
        Invoke-Step 'Проверка типов mypy' { python -m mypy }
    } else {
        Write-Host '-- mypy не установлен, шаг пропущен (pip install -e ".[dev]")' -ForegroundColor Yellow
        $skipped += 'Проверка типов mypy'
    }
    if (Test-Module 'pytest') {
        Invoke-Step 'Тесты через pytest' { python -m pytest -q }
    }
}

if ($IncludeDocker) {
    Invoke-Step 'Сборка образа' { docker build -t siem-enricher:0.1.0 . }
}

Write-Host ''
if ($skipped.Count -gt 0) {
    Write-Host ("Пропущено шагов: " + ($skipped -join ', ')) -ForegroundColor Yellow
}
if ($failed.Count -eq 0) {
    Write-Host 'ВСЕ ОБЯЗАТЕЛЬНЫЕ ПРОВЕРКИ ПРОЙДЕНЫ' -ForegroundColor Green
    exit 0
}
Write-Host ("Провалены шаги: " + ($failed -join ', ')) -ForegroundColor Red
exit 1
