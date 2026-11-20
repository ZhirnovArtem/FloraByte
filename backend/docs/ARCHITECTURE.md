# Архитектура AI Security Workflow (Backend)

## Общая схема

```
React Flow (Frontend)
        │  HTTP + WebSocket
        ▼
┌───────────────────────────────────────────────────────────┐
│                     FastAPI (app/api)                     │
│  workflows · runs · node-types · uploads · credentials    │
│  templates · ws · ci                                      │
└───────────────────────────┬───────────────────────────────┘
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
   - `Finding` — формат организаторов  
   - `scan(root, params) → list[Finding]` — интерфейс для сканеров  
   - Порты (`Workspace | Findings | Report | Any`)  
   - События WebSocket

3. **Безопасность**  
   - Credentials → Fernet (`APP_SECRET_KEY`)  
   - Секреты маскируются до логов / LLM / API / WS  
   - `git_clone` только из allowlist  
   - Zip-slip защита, лимиты размера/файлов  
   - LLM получает только замаскированный `evidence`

4. **Выполнение**  
   - Топологический порядок  
   - `asyncio` + `to_thread` для блокирующих сканеров  
   - Таймаут на ноду (по умолчанию 120 с)  
   - Падение одной ноды → `failed` + dependent `skipped`, независимые ветки продолжают  
   - Workspace: `/tmp/runs/{run_id}` (чистится после)

## Потоки данных

```
trigger → source (workspace: Path)
       → scanners (findings: list[Finding])
       → findings.merge (dedup)
       → findings.export (report.json + report.md)
       → ai.explain (validated explanation + summary)
       → logic.if_else (по severity / count)
       → notify.telegram / webhook
```

## AI-нода (обязательный валидатор)

1. В LLM уходят только Finding с замаскированным evidence.  
2. Ответ — строгий JSON по Pydantic-схеме.  
3. `validator.py` проверяет:
   - схему
   - существование `finding_ref`
   - совпадение path/line с реальной находкой
   - CVE/GHSA только из переданных advisoryId + aliases
   - отсутствие похожих на секреты строк
4. При провале — один retry, затем детерминированный fallback (без LLM).  
5. В output всегда есть `validation: {passed, retried, dropped_items, ...}`.

## Хранилище

| Таблица | Назначение |
|--------|------------|
| `workflows` | id, name, graph_json, is_template, … |
| `runs` | id, workflow_id, status, summary_json, ai_report_json |
| `node_runs` | per-node status + output_preview |
| `credentials` | encrypted_value (Fernet) |

## Добавление новой ноды (пример)

```python
# app/nodes/notify/slack.py
from app.nodes.base import BaseNode, Port
from app.nodes.registry import register_node

@register_node
class SlackNotifyNode(BaseNode):
    type = "notify.slack"
    label = "Slack"
    group = "notify"
    inputs = [Port(name="in", kind="Any")]
    outputs = []
    Params = ...  # Pydantic model

    async def run(self, ctx, inputs, params):
        ...
```

После импорта (или `import app.nodes.notify.slack`) нода появляется в `GET /api/node-types` без изменений движка.
