# Быстрый локальный прогон: генерация событий -> обогащение -> сводка.
#Requires -Version 5.1
[CmdletBinding()]
param(
    [int]$Count = 120,
    [string]$Config = 'config/config.local.json',
    [string]$InputFile = 'var/generated.jsonl',
    [string]$OutputFile = 'var/enriched_events.jsonl',
    [switch]$Serve
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)

# Ядро работает без установки пакета: добавляем src в путь поиска модулей
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:PYTHONIOENCODING = 'utf-8'

Write-Host "-> генерирую $Count синтетических событий в $InputFile" -ForegroundColor Cyan
python tools\generate_sample_events.py --scenario mixed --count $Count --out $InputFile

Write-Host "-> обогащаю события (конфиг $Config)" -ForegroundColor Cyan
python -m siem_enricher replay --config $Config --input $InputFile --output $OutputFile --quiet

Write-Host '-> сводка по первым трём обогащённым событиям' -ForegroundColor Cyan
Get-Content $OutputFile -TotalCount 3 | ForEach-Object {
    $e = $_ | ConvertFrom-Json
    [pscustomobject]@{
        event_id         = $e.event_id
        action           = $e.action
        sensitivity      = $e.data_sensitivity
        confidence       = $e.sensitivity_confidence
        risk_score       = $e.risk_score
        risk_severity    = $e.risk_severity
        provenance_depth = $e.provenance_depth
        policies         = ($e.policy_actions | ForEach-Object { $_.rule_id }) -join ','
    }
} | Format-Table -AutoSize

Write-Host '-> журнал аудита: var\logs\policy_audit.jsonl' -ForegroundColor Cyan

if ($Serve) {
    Write-Host '-> поднимаю HTTP-сервис на http://127.0.0.1:8080' -ForegroundColor Cyan
    python -m siem_enricher serve --config $Config --port 8080
}
