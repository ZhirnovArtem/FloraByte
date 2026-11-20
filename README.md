# FloraByte — AI Security Workflow

Визуальная платформа автоматизации проверок безопасности  
**Кейс Cyber Garden 2026 / Банк «Центр-инвест»**

Платформа позволяет собирать drag-and-drop сценарии (workflow) из блоков (нод): загрузка кода → собственные сканеры (Secrets / SCA / SAST) → слияние находок → AI-объяснение → уведомление в Telegram/Webhook.

---

## Быстрый старт (< 10 минут)

```bash
# 1. Клонировать
git clone https://github.com/ZhirnovArtem/FloraByte.git
cd FloraByte/backend

# 2. Виртуальное окружение + зависимости
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Конфиг (опционально)
cp .env.example .env
# Отредактируйте .env при необходимости (LLM, Telegram и т.д.)

# 4. Тесты
pytest -q

# 5. Запуск API
uvicorn app.main:app --reload --port 8000
```

Откройте:

- Health: http://127.0.0.1:8000/health
- Node types (палитра для фронта): http://127.0.0.1:8000/api/node-types
- Docs (Swagger): http://127.0.0.1:8000/docs

---

## Структура репозитория

```
FloraByte/
├── README.md                 # этот файл
├── backend/
│   ├── app/                  # FastAPI + engine + nodes
│   ├── templates/            # готовые workflow-шаблоны
│   ├── tools/                # evaluate.py, mutate_project.py
│   ├── tests/
│   ├── docs/                 # ARCHITECTURE.md, DEMO.md
│   ├── CONTRACTS.md          # зафиксированные контракты
│   ├── requirements.txt
│   └── .env.example
└── (frontend — отдельно, React + React Flow)
```

---

## Что реализовано (чек-лист)

- [x] Zip / git-clone + автоопределение корня Gradle-проекта
- [x] Workflow собирается, сохраняется, запускается по кнопке и по cron
- [x] if/else, compare, regex — ветвление
- [x] Адаптеры `scanner.secrets` / `sca` / `sast` (реальные реализации — команда 3/4)
- [x] `findings.merge` + `findings.export` → `report.json` + `report.md` (формат организаторов)
- [x] AI-нода `ai.explain` с валидатором (схема, finding_ref, CVE, fallback)
- [x] WebSocket статусы в реальном времени + история запусков
- [x] Уведомления: Telegram + Webhook
- [x] Credentials шифруются Fernet, маскируются в API/логах
- [x] Новая нода = один файл (`@register_node`)
- [x] Переключение LLM (облако / Ollama / vLLM) — только конфиг
- [x] Шаблоны workflow + copy
- [x] CI-запуск `?wait=true`
- [x] `tools/evaluate.py` + `mutate_project.py`

---

## Важные ограничения кейса

1. **Запрещены** готовые сканеры (Semgrep, Gitleaks, Trivy, detekt security-rules и т.п.).
2. **LLM не ищет** уязвимости — только объясняет и агрегирует находки собственных анализаторов.
3. Сканировать можно только учебный репозиторий организаторов (`https://github.com/TBagirov/training`) и собственные безопасные проекты.
4. Секреты никогда не уходят в LLM, логи, WebSocket и API в открытом виде.
5. Стабы сканеров (`USE_STUB_SCANNERS=1`) — **только для разработки**. В демо и финальной сборке флаг выключен.

---

## Документация

| Документ | Описание |
|----------|----------|
| [backend/README.md](backend/README.md) | Подробный запуск, API, ноды |
| [backend/CONTRACTS.md](backend/CONTRACTS.md) | Finding, BaseNode, события, credentials |
| [backend/docs/ARCHITECTURE.md](backend/docs/ARCHITECTURE.md) | Архитектура и схема |
| [backend/docs/DEMO.md](backend/docs/DEMO.md) | Скрипт демонстрации |

---

## Команда

Backend + engine + contracts — реализованы по брифу.  
Сканеры Secrets / SCA / SAST — адаптеры готовы, алгоритмы реализуют люди 3 и 4.  
Frontend (React Flow) — отдельный репозиторий / человек.

---

**Phase F (freeze)** — 2026-11-20
