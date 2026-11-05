# Демонстрация записи событий в Quickwit: пошагово, с паузами для скриншотов
param(
    [switch]$NoPause, [switch]$NoBrowser,
    [string]$PythonExe = 'C:\Users\idv1102\PycharmProjects\PythonProject11\.venv\Scripts\python.exe',
    [int]$Limit = 136
)

$ErrorActionPreference = 'Continue'
chcp 65001 | Out-Null
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Base = 'http://localhost:7280'
$Index = 'siem-enriched'

function Pause-Step([string]$Text) {
    if ($NoPause) { return }
    Write-Host ''
    Write-Host "  $Text" -ForegroundColor Yellow
    Read-Host '  Нажми Enter, чтобы продолжить (сейчас удобно сделать скриншот)'
    Write-Host ''
}

function Step([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function Invoke-QwJson {
    param([string]$Uri, [string]$Method = 'Post', [object]$Body)
    $params = @{ Uri = $Uri; Method = $Method; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($Body) { $params['ContentType'] = 'application/json'; $params['Body'] = $Body }
    $response = Invoke-WebRequest @params
    $text = [System.Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray())
    return $text | ConvertFrom-Json
}
# --- шаг 0: поднять движок -------------------------------------------------
Step 'ШАГ 0. Подготовка Quickwit'

Write-Host '  проверяю WSL и контейнер...'
wsl -e bash -lc "docker start siem-quickwit 2>/dev/null || docker run -d --name siem-quickwit -p 7280:7280 quickwit/quickwit:0.8.1 run" | Out-Null

$ready = $false
for ($i = 1; $i -le 20; $i++) {
    Start-Sleep -Seconds 3
    try {
        $version = Invoke-RestMethod -Uri "$Base/api/v1/version" -TimeoutSec 5
        $ready = $true
        break
    } catch { }
}

if (-not $ready) {
    Write-Host '  Quickwit не поднялся. Проверь, что Docker работает в WSL.' -ForegroundColor Red
    exit 1
}
Write-Host "  Quickwit готов: $($version.build.version)" -ForegroundColor Green
Pause-Step 'Движок запущен.'

# --- шаг 1: сервис формирует обогащённые события ---------------------------
Step 'ШАГ 1. Сервис обогащает события SIEM'

$eventsFile = Join-Path $Root 'var\screens\replay_out.jsonl'
if (-not (Test-Path $eventsFile)) { New-Item -ItemType Directory -Force -Path (Split-Path $eventsFile) | Out-Null }

if (Test-Path $PythonExe) {
    $stateFile = Join-Path $Root 'var\state\provenance.db'
    $checkpoint = Join-Path $Root 'var\state\checkpoint.json'
    foreach ($file in @($stateFile, $checkpoint)) {
        if (Test-Path $file) { Remove-Item $file -Force }
        Write-Host '  история происхождения сброшена (иначе цепочки копятся от прогона к прогону)'
    }
    Write-Host "  запуск: python -m siem_enricher replay --limit $Limit"
    $env:PYTHONPATH = Join-Path $Root 'src'
    $env:PYTHONIOENCODING = 'utf-8'
    $env:TOKENIZERS_PARALLELISM = 'false'
    $env:TRANSFORMERS_VERBOSITY = 'error'
    $env:HF_HUB_DISABLE_PROGRESS_BARS = '1'
    & $PythonExe -m siem_enricher --log-level ERROR replay `
        --input (Join-Path $Root 'var\experiment\dataset.jsonl') `
        --limit $Limit --output $eventsFile 2>&1 | Select-Object -Last 20
} else {
    Write-Host '  python не найден, использую ранее сохранённый файл событий' -ForegroundColor Yellow
}

$records = Get-Content $eventsFile -Encoding UTF8 | Where-Object { $_.Trim() }
Write-Host ''
Write-Host "  обогащённых событий в файле: $($records.Count)" -ForegroundColor Green
Pause-Step 'Вот как сервис записывает обогащённые события в файл (var\screens\replay_out.jsonl).'

# --- шаг 2: создание индекса -----------------------------------------------
Step 'ШАГ 2. Создание индекса в Quickwit'

$mapping = @{
    version    = '0.8'
    index_id   = $Index
    doc_mapping = @{
        field_mappings = @(
            @{ name = 'timestamp'; type = 'datetime'; input_formats = @('rfc3339'); output_format = 'rfc3339'; fast = $true }
            @{ name = 'event_id'; type = 'text'; tokenizer = 'raw'; fast = $true }
            @{ name = 'action'; type = 'text'; tokenizer = 'raw'; fast = $true }
            @{ name = 'user'; type = 'text'; tokenizer = 'raw' }
            @{ name = 'host'; type = 'text'; tokenizer = 'raw' }
            @{ name = 'file_name'; type = 'text'; tokenizer = 'default' }
            @{ name = 'file_path'; type = 'text'; tokenizer = 'raw' }
            @{ name = 'directory'; type = 'text'; tokenizer = 'default'; fast = $true }
            @{ name = 'rule_level'; type = 'u64'; fast = $true }
            @{ name = 'data_sensitivity'; type = 'text'; tokenizer = 'raw'; fast = $true }
            @{ name = 'confidence'; type = 'f64' }
            @{ name = 'method'; type = 'text'; tokenizer = 'raw' }
            @{ name = 'provenance_depth'; type = 'u64' }
            @{ name = 'external_count'; type = 'u64' }
            @{ name = 'risk_score'; type = 'f64'; fast = $true }
            @{ name = 'risk_severity'; type = 'text'; tokenizer = 'raw'; fast = $true }
            @{ name = 'decision'; type = 'text'; tokenizer = 'raw'; fast = $true }
            @{ name = 'rules'; type = 'text'; tokenizer = 'raw' }
        )
        timestamp_field = 'timestamp'
        mode = 'strict'
    }
    search_settings = @{ default_search_fields = @('file_name', 'directory', 'action', 'decision') }
}

try { Invoke-RestMethod -Uri "$Base/api/v1/indexes/$Index" -Method Delete -TimeoutSec 10 | Out-Null } catch { }

$created = Invoke-RestMethod -Uri "$Base/api/v1/indexes" -Method Post `
    -ContentType 'application/json' -Body ($mapping | ConvertTo-Json -Depth 8) -TimeoutSec 30

Write-Host "  HTTP 200   индекс: $($created.index_uid)" -ForegroundColor Green
Write-Host "  полей в схеме: $(($created.index_config.doc_mapping.field_mappings).Count)"
Write-Host '  поля: timestamp, event_id, action, user, host, file_name, file_path,'
Write-Host '        directory, rule_level, data_sensitivity, confidence, method,'
Write-Host '        provenance_depth, external_count, risk_score, risk_severity, decision, rules'
Pause-Step 'Индекс создан — видно схему документа.'

# --- шаг 3: запись событий --------------------------------------------------
Step 'ШАГ 3. Запись обогащённых событий в индекс'

$lines = foreach ($record in $records) {
    $event = $record | ConvertFrom-Json
    [pscustomobject]@{
        timestamp       = $event.'@timestamp'
        event_id        = $event.event_id
        action          = $event.action
        user            = $event.user.name
        host            = $event.host.name
        file_name       = $event.file.name
        file_path       = $event.file.path
        directory       = $event.file.directory
        rule_level      = $event.rule.level
        data_sensitivity = $event.data_sensitivity
        confidence      = $event.sensitivity_confidence
        method          = $event.sensitivity_method
        provenance_depth = $event.provenance_depth
        external_count  = $event.external_destinations_count
        risk_score      = $event.risk_score
        risk_severity   = $event.risk_severity
        decision        = $event.policy_decision
        rules           = ($event.policy_rule_ids -join ', ')
    } | ConvertTo-Json -Compress
}
$ndjson = ($lines -join "`n")

$ingested = Invoke-RestMethod -Uri "$Base/api/v1/$Index/ingest?commit=force" -Method Post `
    -ContentType 'application/x-ndjson' -Body ([System.Text.Encoding]::UTF8.GetBytes($ndjson)) -TimeoutSec 120

$countResponse = Invoke-QwJson -Uri "$Base/api/v1/$Index/search" -Body '{"query":"*","max_hits":0}'
$total = $countResponse.num_hits

Write-Host "  HTTP 200   $($ingested | ConvertTo-Json -Compress)" -ForegroundColor Green
Write-Host "  в индексе документов: $total" -ForegroundColor Green
Pause-Step "События записаны: $total документов."

# --- шаг 4: поиск -----------------------------------------------------------
Step 'ШАГ 4. Поиск событий с решением о блокировке'

$query = '{"query":"decision:block","max_hits":3,"sort_by":"risk_score"}'
$found = Invoke-QwJson -Uri "$Base/api/v1/$Index/search" -Body $query

Write-Host ("  найдено: {0}   за {1:N1} мс" -f $found.num_hits, ($found.elapsed_time_micros / 1000)) -ForegroundColor Green
Write-Host ''
foreach ($hit in $found.hits) {
    Write-Host ("  {0}  {1,-8} {2}" -f $hit.event_id, $hit.action, $hit.file_name)
    Write-Host ("      класс {0}   риск {1:N2} {2}   решение {3}   {4}" -f `
        $hit.data_sensitivity, $hit.risk_score, $hit.risk_severity, $hit.decision, $hit.rules) -ForegroundColor DarkGray
}
Pause-Step 'Поиск по индексу работает.'

# --- шаг 5: агрегаты --------------------------------------------------------
Step 'ШАГ 5. Сводка по записанным событиям'

$aggregation = @'
{"query":"*","max_hits":0,"aggs":{"by_decision":{"terms":{"field":"decision","size":5}},"by_class":{"terms":{"field":"data_sensitivity","size":6}},"by_risk":{"terms":{"field":"risk_severity","size":5}}}}
'@
$aggregated = Invoke-QwJson -Uri "$Base/api/v1/$Index/search" -Body $aggregation

$labels = @{ by_decision = 'по решению'; by_class = 'по классу'; by_risk = 'по уровню риска' }
foreach ($name in $aggregated.aggregations.PSObject.Properties.Name) {
    $pairs = ($aggregated.aggregations.$name.buckets | ForEach-Object { "$($_.key)=$($_.doc_count)" }) -join '  '
    Write-Host ("  {0,-16}:  {1}" -f $labels[$name], $pairs) -ForegroundColor Green
}
Pause-Step 'Готово: видно, как события записаны и как по ним ищется.'

Write-Host ''
$uiUrl = "$Base/ui/search?indexId=$Index"
Write-Host ''
Write-Host "  Интерфейс Quickwit: $uiUrl" -ForegroundColor Cyan
Write-Host '  Там таблица событий, поиск и панель агрегаций — можно скринить.' -ForegroundColor Cyan
if (-not $NoBrowser) { Start-Process $uiUrl }

Write-Host '  Демонстрация завершена. Индекс остаётся в Quickwit (контейнер siem-quickwit).' -ForegroundColor Cyan
if (-not $NoPause) { Read-Host '  Нажми Enter, чтобы закрыть окно' | Out-Null }
