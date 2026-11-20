# FloraByte — AI Security Workflow

Визуальная платформа автоматизации проверок безопасности (кейс Cyber Garden 2026 / Центр-инвест).

## Структура

```
backend/     # FastAPI + workflow engine (Python 3.11+)
```

## Backend (Phase A)

Каркас, контракты `Finding` / `BaseNode`, реестр нод, SQLite-схема, маскирование секретов, Fernet, `GET /api/node-types`.

```bash
cd backend
pip install -r requirements.txt
pytest -q
uvicorn app.main:app --reload --port 8000
```

Подробности: [`backend/README.md`](backend/README.md) и [`backend/CONTRACTS.md`](backend/CONTRACTS.md).

## Важно

- Секреты (Telegram, LLM) — только через env / credentials API, не в репозитории.
- Сканеры Secrets / SCA / SAST реализуются отдельно; в backend — адаптеры и стабы под флагом `USE_STUB_SCANNERS=1`.
