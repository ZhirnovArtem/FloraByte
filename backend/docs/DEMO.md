# Демонстрационная инструкция (Full Integration)

Цель: за < 5 минут показать полный цикл **Frontend + Backend + реальные сканеры + AI + Telegram + evaluate**.

## 1. Подготовка перед демо

1. Установите зависимости (из корня `FloraByte/`):
   ```bash
   pip install -e ".[test]"
   cd frontend && npm install && cd ..
   ```
2. Проверьте `backend/.env` (при необходимости):
   - `USE_STUB_SCANNERS=0`
   - `VULN_DB_PATH=/path/to/training/vulnerability-database/vulnerabilities.json`
   - `GEMINI_API_KEY=...` (без ключа `ai.explain` автоматически выдаст fallback-отчёт)
   - `TELEGRAM_BOT_TOKEN=...`, `TELEGRAM_CHAT_ID=...` (либо добавляются в UI через Credentials)
3. Запустите тесты перед демо:
   ```bash
   pytest -q
   ```

## 2. Запуск сервисов

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

## 3. Сценарий демонстрации в UI

1. **Палитра нод:** убедитесь, что бейдж в левой панели показывает `API` — список из 15 нод загружен из `GET /api/node-types`.
2. **Загрузка шаблона:** в левой панели нажмите **Full Security Scan** — на холст загрузятся ноды `Manual → Upload ZIP → Secrets + SCA + SAST → Merge → Export → AI Explain → If/Else → Telegram`.
3. **Загрузка проекта:** нажмите **Загрузить ZIP** в верхней панели и выберите архив `training-project.zip`. Все блоки `source.upload_zip` автоматически получат `upload_id`.
   *(Если нужно указать путь к `vulnerabilities.json`, кликните по блоку `SCA Scanner` и задайте `vuln_db_path` в правой панели, затем нажмите «Применить параметры».)*
4. **Запуск и WebSocket:** нажмите **▶ Run**. На блоках в реальном времени будут обновляться статусы (`pending → running → success/skipped`), время выполнения и количество находок.
5. **Просмотр отчёта:** в нижней панели откройте:
   - **Находки** — таблица с фильтрами по категориям (`SECRET`, `SCA`, `SAST`), секреты замаскированы;
   - **AI-отчёт** — резюме, статус валидации (`mode=llm` или `fallback`, `dropped_cve`) и шаги исправления;
   - **Markdown** и ссылки **↓ report.json / ↓ report.md**.

## 4. Проверка качества по эталону (`tools.evaluate`)

Скачайте `report.json` из панели отчёта (или через `GET /api/runs/<run_id>/report.json`) и запустите:

```bash
cd backend
python -m tools.evaluate --report report.json --truth /path/to/training/ground-truth/training-findings.json
```
