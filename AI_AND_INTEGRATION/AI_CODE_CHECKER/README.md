# AI_CODE_CHECKER — AI-модуль CyberGarden

Независимый компонент: принимает findings от сканеров, возвращает
валидированный AI-отчёт. Backend, scanners, frontend и уведомления —
вне этого репозитория.

## Требования

- Python 3.10+
- `GEMINI_API_KEY` (для реального прогона; для тестов не нужен)

## Установка

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt