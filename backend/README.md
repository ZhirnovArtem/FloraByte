# AI Security Workflow — Backend

FastAPI + собственный лёгкий workflow-engine.  
Стек: Python 3.11+, FastAPI, Pydantic v2, SQLModel + SQLite, APScheduler, httpx, cryptography (Fernet), pytest.

**Текущая версия: Phase F (freeze)**

---

## Быстрый старт

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # при необходимости заполните ключи
pytest -q
uvicorn app.main:app --reload --port 8000
```

- Health: `GET /health`
- Палитра нод: `GET /api/node-types`
- Swagger: http://127.0.0.1:8000/docs

---

## Конфигурация (`.env`)

Скопируйте `.env.example` → `.env`. Основные переменные:

| Переменная | Назначение | По умолчанию |
|------------|------------|--------------|
| `APP_SECRET_KEY` | Ключ Fernet (если пусто — генерируется) | — |
| `USE_STUB_SCANNERS` | Стабы сканеров (только dev) | `0` |
| `LLM_BASE_URL` | OpenAI-совместимый endpoint | Gemini OpenAI endpoint |
| `LLM_MODEL` | Модель | `gemini-2.0-flash` |
| `LLM_API_KEY` | Ключ LLM | — |
| `TELEGRAM_BOT_TOKEN` | Токен бота (или через credentials) | — |
| `TELEGRAM_CHAT_ID` | Chat ID | — |
| `GIT_CLONE_ALLOWLIST` | Разрешённые URL для `git_clone` | `https://github.com/TBagirov/training` |
| `DATABASE_URL` | SQLite | `sqlite:///./ai_security_workflow.db` |

Переключение на локальную Ollama:

```env
LLM_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama3.2
LLM_API_KEY=ollama
```

---

## API (кратко)

```
GET/POST        /api/workflows
GET/PUT/DELETE  /api/workflows/{id}
POST            /api/workflows/{id}/run          → {run_id}
                ?wait=true                       # для CI
GET             /api/runs
GET             /api/runs/{id}
GET             /api/runs/{id}/report.json
GET             /api/runs/{id}/report.md
WS              /ws/runs/{id}
GET             /api/node-types
POST            /api/uploads                     # zip → upload_id
GET/POST/DELETE /api/credentials
GET             /api/templates
POST            /api/templates/{id}/copy
GET             /health
```

Полные контракты — в `CONTRACTS.md`.

---

## Ноды (15)

| type | group | Назначение |
|------|-------|------------|
| `source.upload_zip` | source | Распаковка zip + определение корня Gradle |
| `source.git_clone` | source | `git clone --depth 1` (только allowlist) |
| `trigger.manual` | trigger | Запуск по кнопке |
| `trigger.schedule` | trigger | Cron / interval (APScheduler) |
| `logic.if_else` | logic | Ветвление true/false |
| `logic.compare` | logic | Сравнение значений |
| `logic.regex` | logic | Regex-матч (с защитой от ReDoS) |
| `scanner.secrets` | scanner | Адаптер Secrets |
| `scanner.sca` | scanner | Адаптер SCA |
| `scanner.sast` | scanner | Адаптер SAST |
| `findings.merge` | findings | Слияние + дедуп |
| `findings.export` | findings | `report.json` + `report.md` |
| `ai.explain` | ai | LLM-объяснение + валидатор + fallback |
| `notify.telegram` | notify | Telegram |
| `notify.webhook` | notify | HTTP webhook |

**Новая нода** = один файл в `app/nodes/<group>/` + `@register_node`. Движок и API не трогаем.

---

## Сканеры

Реальные алгоритмы пишут люди 3 и 4. В backend — только адаптеры:

```python
# интерфейс
def scan(root: Path, params: dict) -> list[Finding]: ...
```

При `USE_STUB_SCANNERS=1` возвращаются минимальные синтетические находки (не эталон!).  
В демо и финальной сборке флаг **должен быть 0**.

Оценка по эталону:

```bash
python -m tools.evaluate --report report.json --truth /path/to/ground-truth/training-findings.json
```

Мутации против переобучения: `python -m tools.mutate_project`.

---

## Тесты

```bash
pytest -q
```

Покрыто: контракты Finding, топосортировка/циклы, ветвление и skipped, таймауты, маскирование/шифрование, zip-slip, определение корня, AI-валидатор (невалидный JSON, чужой ref, выдуманный CVE), шаблоны, webhook и т.д.

---

## Демо и архитектура

- Пошаговый сценарий демонстрации: [`docs/DEMO.md`](docs/DEMO.md)
- Архитектурная схема: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Phase history

| Phase | Содержание |
|-------|------------|
| A | Каркас, Finding, BaseNode, реестр, БД, node-types |
| B | CRUD workflows, uploads, source.*, executor, WS, merge/export |
| C | Адаптеры сканеров, evaluate, telegram |
| D | logic.*, schedule, credentials+Fernet, ai.explain+validator |
| E | webhook, templates, CI `?wait=true`, мутации |
| **F** | Freeze: README, архитектура, демо-скрипт, полировка |

---

**Не добавлять:** авторизацию пользователей, Docker, Celery/Redis, внешние БД, готовые workflow-платформы (n8n и т.п.).
