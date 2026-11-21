# FloraByte — AI Security Workflow

Визуальная платформа автоматизации проверок безопасности  
**Кейс Cyber Garden 2026 / Банк «Центр-инвест»**

Платформа объединяет визуальный редактор сценариев (React + React Flow), движок выполнения workflow на FastAPI, собственные сканеры (Secrets / SCA / SAST), AI-объяснение через `AI_CODE_CHECKER` с валидатором и уведомления в Telegram / Webhook.

---

## Структура репозитория

```
FloraByte/
├── pyproject.toml            # Единая установка backend + scanners + security_scanners
├── README.md                 # Этот файл
├── backend/                  # FastAPI API, workflow engine, ноды, адаптеры, tools
│   ├── app/
│   ├── templates/            # Готовые workflow-шаблоны
│   ├── tools/                # evaluate.py, mutate_project.py
│   ├── tests/
│   ├── CONTRACTS.md
│   └── docs/DEMO.md
├── scanners/                 # Собственный SAST-сканер (Kotlin/Spring Boot)
├── security_scanners/        # Собственные Secrets и SCA сканеры
├── AI_AND_INTEGRATION/       # AI_CODE_CHECKER (Gemini + scrubber + контракты)
├── frontend/                 # React + React Flow редактор с Vite proxy
└── tests/                    # Юнит-тесты сканеров
```

---

## Быстрый старт (Linux / macOS и Windows)

### Требования

- Python 3.11+
- Node.js 22.12+ и npm (или совместимая с Vite 8 версия)

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

*(В Windows Command Prompt: `.venv\Scripts\activate.bat`)*

### 2. Настройка окружения (опционально)

```bash
cp backend/.env.example backend/.env        # Windows: copy backend\.env.example backend\.env
```

Основные переменные в `backend/.env`:
- `USE_STUB_SCANNERS=0` (по умолчанию выключено — работают реальные сканеры)
- `VULN_DB_PATH` — путь к справочнику уязвимостей организаторов (`vulnerability-database/vulnerabilities.json`)
- `LLM_PROVIDER=gemini` и `GEMINI_API_KEY` (или `LLM_API_KEY` / credential) — реальный AI; `LLM_PROVIDER=openai_compatible` + `LLM_BASE_URL` для Ollama/vLLM; без доступной модели работает fallback
- `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` (или через `/api/credentials`) — для ноды `notify.telegram`

### 3. Запуск тестов

Из корня репозитория запускаются все тесты (`tests/` + `backend/tests/`):

```bash
pytest -q
```

### 4. Запуск Backend

**Linux / macOS:**

```bash
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

**Windows (PowerShell):**

```powershell
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Проверка:
- Health: http://127.0.0.1:8000/health
- Палитра нод: http://127.0.0.1:8000/api/node-types
- Swagger UI: http://127.0.0.1:8000/docs

### 5. Запуск Frontend

В отдельном терминале:

```bash
cd frontend
npm ci
npm run dev
```

Откройте http://localhost:5173. Vite автоматически проксирует `/api`, `/ws` и `/health` на `http://127.0.0.1:8000` (можно переопределить через `VITE_BACKEND_URL`).

---

## Оценка по эталону организаторов

```bash
cd backend
python -m tools.evaluate --report /path/to/report.json --truth /path/to/training/ground-truth/training-findings.json
```

---

## Документация

- [Исправления и проверка этой версии](FIXES_AND_VERIFICATION.md)
- [Контракты платформы и адаптеров](backend/CONTRACTS.md)
- [Инструкция запуска для демо](backend/docs/DEMO.md)
- [Архитектура backend](backend/docs/ARCHITECTURE.md)
