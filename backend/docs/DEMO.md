# Демонстрационный сценарий (Phase F)

Цель: за < 5–7 минут показать полный цикл на живом API (без фронта).

## Подготовка

```bash
cd backend
source .venv/bin/activate
# Для демо можно включить стабы (реальные сканеры ещё от людей 3/4)
export USE_STUB_SCANNERS=1
uvicorn app.main:app --reload --port 8000
```

В другом терминале:

```bash
export BASE=http://127.0.0.1:8000
```

## 1. Палитра нод

```bash
curl -s $BASE/api/node-types | python -m json.tool | head -40
```

Должно быть 15 нод.

## 2. Создать workflow (Manual → Upload → Secrets → Merge → Export)

```bash
curl -s -X POST $BASE/api/workflows \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Demo Secrets Scan",
    "graph_json": {
      "nodes": [
        {"id": "t1", "type": "trigger.manual", "params": {}, "position": {"x": 0, "y": 0}},
        {"id": "s1", "type": "source.upload_zip", "params": {}, "position": {"x": 200, "y": 0}},
        {"id": "sc1", "type": "scanner.secrets", "params": {}, "position": {"x": 400, "y": 0}},
        {"id": "m1", "type": "findings.merge", "params": {}, "position": {"x": 600, "y": 0}},
        {"id": "e1", "type": "findings.export", "params": {}, "position": {"x": 800, "y": 0}}
      ],
      "edges": [
        {"id": "e1", "source": "t1", "target": "s1"},
        {"id": "e2", "source": "s1", "target": "sc1"},
        {"id": "e3", "source": "sc1", "target": "m1"},
        {"id": "e4", "source": "m1", "target": "e1"}
      ]
    }
  }' | python -m json.tool
```

Запомните `id` созданного workflow.

## 3. Загрузить zip (или использовать git_clone)

Если есть zip учебного проекта:

```bash
curl -s -X POST $BASE/api/uploads -F "file=@/path/to/training-project.zip" | python -m json.tool
```

Получите `upload_id` и подставьте его в params ноды `source.upload_zip` (через PUT workflow) **или** используйте шаблон.

Альтернатива — `source.git_clone` с URL из allowlist:

```json
{"type": "source.git_clone", "params": {"url": "https://github.com/TBagirov/training", "subdir": "training-project"}}
```

## 4. Запуск

```bash
WF_ID=<id из шага 2>
curl -s -X POST "$BASE/api/workflows/$WF_ID/run" | python -m json.tool
```

Получите `run_id`.

## 5. Статус и отчёты

```bash
RUN_ID=<run_id>
curl -s $BASE/api/runs/$RUN_ID | python -m json.tool

# Отчёты в формате организаторов
curl -s $BASE/api/runs/$RUN_ID/report.json | python -m json.tool
curl -s $BASE/api/runs/$RUN_ID/report.md
```

## 6. WebSocket (опционально)

```bash
# в браузере или websocat / wscat
# ws://127.0.0.1:8000/ws/runs/$RUN_ID
```

События: `run_started` → `node_started` / `node_finished` / `node_skipped` → `run_finished`.

## 7. AI-объяснение (если LLM-ключ задан)

Добавьте ноду `ai.explain` после merge/export и перезапустите.  
Валидатор отбросит выдуманные CVE и несуществующие finding_ref.  
При ошибке LLM сработает fallback-отчёт.

## 8. Telegram / Webhook

Создайте credential:

```bash
curl -s -X POST $BASE/api/credentials \
  -H "Content-Type: application/json" \
  -d '{"name": "tg-bot", "kind": "telegram", "value": "BOT_TOKEN"}'
```

В params ноды `notify.telegram` укажите `credential_id` и `chat_id`.

## 9. Готовые шаблоны

```bash
curl -s $BASE/api/templates | python -m json.tool
curl -s -X POST $BASE/api/templates/full-security-scan/copy | python -m json.tool
```

## 10. CI-режим

```bash
curl -s -X POST "$BASE/api/workflows/$WF_ID/run?wait=true" | python -m json.tool
```

Возвращает результат после завершения (удобно для pipeline).

---

## Что показать жюри

1. Конструктор (фронт) + живой запуск.
2. Реальные/стабовые находки → `report.json` в формате организаторов.
3. AI-объяснение + результат валидации.
4. Уведомление в Telegram.
5. Архитектуру: «новая нода = один файл».
6. `tools/evaluate.py` (когда реальные сканеры готовы — 15/15 + 0 false positive).

---

**Важно для финальной сборки:** `USE_STUB_SCANNERS=0`.
