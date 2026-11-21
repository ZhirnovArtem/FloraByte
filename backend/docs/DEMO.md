# Демонстрационная инструкция (Full Integration)

Цель: за < 5 минут показать полный цикл **Frontend + Backend + реальные сканеры + AI + Telegram/Webhook (safe dry_run или live) + CI/CD + evaluate**.

## 1. Подготовка перед демо

1. Установите зависимости (из корня `FloraByte/`):
   ```bash
   pip install -e ".[test]"
   cd frontend && npm ci && cd ..
   ```
2. Проверьте `backend/.env` (при необходимости):
   - `USE_STUB_SCANNERS=0`
   - `VULN_DB_PATH=/path/to/training/vulnerability-database/vulnerabilities.json`
   - `GEMINI_API_KEY=...` (без ключа `ai.explain` автоматически выдаст валидированный fallback-отчёт)
   - `TELEGRAM_BOT_TOKEN=...`, `TELEGRAM_CHAT_ID=...` (либо добавляются в UI через Credentials; для безопасного показа без отправки используйте `dry_run: true`)
3. Запустите автотесты перед демо:
   ```bash
   pytest -q
   ```

## 2. Быстрый headless-прогон (одним скриптом)

```bash
chmod +x scripts/demo_e2e.sh
./scripts/demo_e2e.sh /path/to/training-project /path/to/training/ground-truth/training-findings.json
```

## 3. Запуск сервисов для интерактивного демо в UI

**Терминал 1 (Backend):**
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Терминал 2 (Frontend):**
```bash
cd frontend
npm run dev
```

Откройте браузер: `http://localhost:5173`.

## 4. Сценарий демонстрации в UI

1. **Палитра нод:** бейдж в левой панели показывает `API` — все ноды загружены из `GET /api/node-types` (поддерживаются клик и drag-and-drop на холст).
2. **Загрузка шаблона:** выберите **Full Security Scan** — на холсте появятся ноды `Manual → Upload ZIP → Secrets + SCA + SAST → Merge → Export + AI Explain → If/Else → Telegram`.
3. **Загрузка проекта:** нажмите **Загрузить ZIP** и выберите `training-project.zip`. Все ноды `source.upload_zip` автоматически получат `upload_id`.
4. **Запуск и WebSocket:** нажмите **▶ Run**. На узлах в реальном времени отображаются статусы (`pending → running → success/skipped`), время выполнения и счётчики находок.
5. **Отчёт и история запусков:**
   - **Находки** — фильтры по категориям и severity, клик по строке открывает детали и рекомендации (секреты замаскированы);
   - **AI-отчёт** — резюме, статус валидации (`mode=llm` или `fallback`, `dropped_cve`) и план исправления;
   - **История запусков** — переключение между прошлыми прогонами с сохранением после перезапуска backend;
   - **Markdown** и скачивание **↓ report.json / ↓ report.md**.

## 5. Проверка качества по эталону (`tools.evaluate`) и CI/CD Gate

```bash
cd backend
python -m tools.evaluate --report report.json --truth /path/to/training/ground-truth/training-findings.json
```

CI/CD API для автоматических проверок в пайплайнах:
```bash
curl -X POST http://127.0.0.1:8000/api/ci/run \
  -H "Content-Type: application/json" \
  -d '{"git_url":"https://github.com/TBagirov/training","fail_on_severity":"HIGH"}'
```
