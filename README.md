# FloraByte — AI Security Workflow

Визуальная платформа автоматизации проверок безопасности  
**Кейс Cyber Garden 2026 / Банк «Центр-инвест»**

Платформа объединяет визуальный редактор сценариев (React + React Flow), движок выполнения workflow на FastAPI, собственные сканеры (Secrets / SCA / SAST), AI-объяснение через `AI_CODE_CHECKER` с обязательным валидатором фактов, CI/CD-шлюз и уведомления в Telegram / Webhook.

---

## Структура репозитория

```
FloraByte/
├── pyproject.toml            # Единая установка backend + scanners + security_scanners
├── .env.example              # Корневой шаблон переменных окружения
├── README.md                 # Этот файл
├── AUDIT_REPORT.md           # Карта архитектуры и результаты аудита
├── scripts/
│   └── demo_e2e.sh           # Воспроизводимый E2E-демо-скрипт (с dry_run)
├── backend/                  # FastAPI API, workflow engine, ноды, адаптеры, tools
│   ├── app/
│   │   ├── api/              # workflows, runs, uploads, credentials, templates, ws, ci
│   │   ├── core/             # config, db, crypto (Fernet), redact, rate_limit
│   │   ├── engine/           # graph, executor, events (WS + DB replay), scheduler
│   │   └── nodes/            # trigger, source, scanners, findings, ai, logic, notify
│   ├── templates/            # Готовые workflow-шаблоны
│   ├── tools/                # evaluate.py, mutate_project.py
│   ├── tests/
│   ├── CONTRACTS.md
│   └── docs/
│       ├── ARCHITECTURE.md
│       └── DEMO.md
├── scanners/                 # Собственный SAST-сканер (Kotlin / Spring Boot)
├── security_scanners/        # Собственные Secrets и SCA сканеры
├── AI_AND_INTEGRATION/       # AI_CODE_CHECKER (Gemini + scrubber + контракты)
├── frontend/                 # React + React Flow редактор с Vite proxy
└── tests/                    # Юнит-тесты сканеров
```

---

## Быстрый старт (Linux / macOS и Windows)

### Требования

- Python **3.11+** (проверено на 3.13)
- Node.js **20+** (см. `.nvmrc`) и npm

### 1. Установка Python-пакетов (из корня репозитория)

**Linux / macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
```

**Windows (PowerShell):**

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[test]"
```

### 2. Настройка окружения (опционально)

```bash
cp backend/.env.example backend/.env        # Windows: copy backend\.env.example backend\.env
```

Основные переменные в `backend/.env`:
- `USE_STUB_SCANNERS=0` (по умолчанию выключено — работают реальные сканеры)
- `VULN_DB_PATH` — путь к справочнику уязвимостей (`vulnerability-database/vulnerabilities.json`)
- `LLM_PROVIDER=gemini` и `GEMINI_API_KEY` (или `LLM_API_KEY` / credential) — реальный AI; `LLM_PROVIDER=openai_compatible` + `LLM_BASE_URL` для Ollama/vLLM; без доступной модели работает детерминированный fallback
- `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` (или через `/api/credentials`) — для ноды `notify.telegram` (поддерживает `dry_run: true` для безопасного демо)

### 3. Запуск тестов и линта

```bash
pytest -q
cd frontend && npm ci && npm run lint && npm run build && cd ..
```

### 4. Запуск Backend и Frontend

**Терминал 1 (Backend):**
```bash
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Проверка:
- Health: http://127.0.0.1:8000/health
- Палитра нод: http://127.0.0.1:8000/api/node-types
- CI/CD Run API: `POST /api/ci/run`, `GET /api/ci/runs/{id}`, `GET /api/ci/runs/{id}/result`
- Swagger UI: http://127.0.0.1:8000/docs

**Терминал 2 (Frontend):**
```bash
cd frontend
npm run dev
```

Откройте http://localhost:5173. Vite автоматически проксирует `/api`, `/ws` и `/health` на `http://127.0.0.1:8000` (можно переопределить через `VITE_BACKEND_URL`).

---

## Быстрое воспроизводимое E2E-демо и оценка качества

```bash
chmod +x scripts/demo_e2e.sh
./scripts/demo_e2e.sh /path/to/training-project /path/to/training/ground-truth/training-findings.json
```

Или вручную для любого отчёта:

```bash
cd backend
python -m tools.evaluate --report /path/to/report.json --truth /path/to/training/ground-truth/training-findings.json
```

---

## Документация

- [Карта архитектуры и аудит](AUDIT_REPORT.md)
- [Контракты платформы и адаптеров](backend/CONTRACTS.md)
- [Инструкция запуска для демо](backend/docs/DEMO.md)
- [Архитектура backend](backend/docs/ARCHITECTURE.md)
