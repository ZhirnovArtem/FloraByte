# Архитектура AI Security Workflow (FloraByte)

## Общая схема

```
React Flow (Frontend)  ── Drag & Drop · Node Settings · Live WS · Report & History
        │  HTTP + WebSocket (/api, /ws)
        ▼
┌────────────────────────────────────────────────────────────────────┐
│                        FastAPI (app/api)                           │
│  workflows · runs · node-types · uploads · credentials · templates │
│  ws (live + DB replay) · ci (/api/ci/run, /runs/{id}, /webhook)    │
└────────────────────────────────┬───────────────────────────────────┘
                                 │
                   ┌─────────────▼──────────────┐
                   │   Workflow Engine          │
                   │   (app/engine)             │
                   │   graph · executor · events│
                   │   scheduler (APScheduler)  │
                   └─────────────┬──────────────┘
                                 │  type → registry
                   ┌─────────────▼──────────────┐
                   │   Node Registry            │
                   │   (app/nodes)              │
                   │   @register_node           │
                   └───┬────┬────┬────┬────┬────┘
                       │    │    │    │    │
                  source  trigger logic scanners  ai  notify  findings
```

## Принципы

1. **Расширяемость**  
   Движок знает только `BaseNode` и реестр.  
   Новая нода = один файл + декоратор `@register_node`.  
   Никаких правок в executor / API.

2. **Контракты зафиксированы** (`CONTRACTS.md`)  
   - `Finding` — формат организаторов (`{"findings": [...]}`)  
   - `scan(root, params) → list[Finding]` — единый интерфейс сканеров  
   - Типизированные порты (`Workspace | Findings | Report | Any`)  
   - События WebSocket с replay из БД после рестарта

3. **Безопасность и изоляция**  
   - Credentials → Fernet (`APP_SECRET_KEY` или постоянный ключ `~/.florabyte/secret.key`)  
   - Секреты маскируются (`redact_text`) до логов / LLM / API / WS / уведомлений  
   - `source.git_clone` ограничен allowlist (`https://github.com/TBagirov/training`)  
   - `source.upload_zip` защищён от zip-slip, symlinks, zip-bomb (потоковый подсчёт байт, max ratio, timeout)  
   - `notify.webhook` защищён от SSRF и DNS rebinding (резолвинг + проверка private/loopback/link-local IP, pinning IP + `sni_hostname`, запрет редиректов, лимит ответа 64 KB)  
   - Уведомления поддерживают `dry_run` и до 3 ретраев с экспоненциальной задержкой на `429`/`5xx`/сетевых ошибках

4. **Отказоустойчивое выполнение**  
   - Топологический порядок выполнения DAG  
   - `asyncio` + `to_thread` для сканеров и блокирующего I/O  
   - Изоляция сбоев: падение одной ветки (`failed` + dependent `skipped`) не останавливает остальные сканеры и итоговый экспорт (`status="partial"`)  
   - Постоянный workspace `/tmp/runs/{run_id}` очищается по завершении

## Потоки данных

```
trigger (manual / cron) → source (upload_zip / git_clone)
       → scanners (secrets / sca / sast)
       → findings.merge (dedup)
       → findings.export (report.json + report.md)
       → ai.explain (AI_CODE_CHECKER + validator + fallback)
       → logic.if_else (по severity / count)
       → notify.telegram / notify.webhook
```

## AI-нода и анти-галлюцинационный валидатор

1. В LLM уходят только `Finding` с замаскированным `evidence`.  
2. Ответ приводится к строгой Pydantic-схеме.  
3. `validator.py` проверяет:
   - схему ответа
   - существование `finding_ref`
   - совпадение `path`/`line` с реальной находкой
   - CVE/GHSA строго из переданных `advisoryId` + `aliases` (с поддержкой `VULN_DB_PATH`)
   - отсутствие строк, похожих на незамаскированные секреты
4. При провале — retry, затем детерминированный обогащённый fallback (без LLM).  
5. В output всегда присутствует `validation: {passed, retried, mode, dropped_items, ...}`.

## Хранилище (SQLite / SQLModel)

| Таблица | Назначение |
|--------|------------|
| `workflows` | id, name, graph_json, is_template, schedule_cron |
| `runs` | id, workflow_id, status (`running` / `success` / `partial` / `failed`), summary_json, ai_report_json |
| `node_runs` | per-node status, timing, error, output_preview |
| `credentials` | encrypted_value (Fernet) |
