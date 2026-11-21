# FloraByte — исправления интеграции (21.11.2026)

Это исправленная версия проекта из архива `FloraByte-integration (1).zip`. Для проверки нужно установить зависимости, указанные в `pyproject.toml` и `frontend/package-lock.json`.

## Что исправлено

1. **Full Security Scan**: несовместимое ребро `Export Report → AI Explain` удалено. Из `Merge Findings` идут две параллельные ветви в Export и AI. Результат AI поступает в `If/Else`, а две Telegram-ноды обрабатывают и ненулевое, и нулевое число находок. Ранее загруженный старый шаблон обновляется при повторном обращении к библиотеке.
2. **Frontend**: запрет некорректных соединений (`Workspace → Findings`, занятые порты, петли и циклы); сообщения об ошибках; исправлено имя поля `value_preview` для masked credentials; кнопка ввода необязательного ключа API; отчёты скачиваются с нужными заголовками. Из резервной копии localStorage исключаются значения параметров с секретами.
3. **SCA**: поддержка версий через `val`/`var`, `gradle.properties`, aliases из `gradle/libs.versions.toml`, `gradle.lockfile`; параметр `lockfile_priority` теперь действительно влияет на анализ. Улучшено сравнение обычных версий и pre-release. Реализация — собственная, без сканирующих движков.
4. **AI**: настраиваемый `LLM_PROVIDER=gemini|openai_compatible` и OpenAI-compatible endpoint для Ollama/vLLM; проверка явных файлов/строк; удаление неразрешённых advisory ID и признаков секретов. Продолжает работать валидация ответа и fallback, но fallback не считается успешным вызовом LLM.
5. **Notifications**: Telegram получает краткие AI-рекомендации, не принимает plaintext `bot_token` в параметрах; Webhook запрещает private/loopback адреса по умолчанию и HTTP-редиректы. Для локальной разработки URL можно разрешить явно через `WEBHOOK_HOST_ALLOWLIST`.
6. **Security**: проверка UUID `upload_id`, запрет Zip-slip, выходов из `subdir` ZIP/Git, отказ в сохранении plaintext-секретов внутри workflow JSON; опциональный API + WS токен `WORKFLOW_ACCESS_TOKEN` (кнопка «Ключ API» во frontend), CI-токен отдельно.
7. **Schedules**: изменения и удаление workflow сразу обновляют APScheduler; шаблоны не запускаются по расписанию; при остановке приложения scheduler завершается.
8. **CI**: защищённый `POST /api/ci/workflows/{id}/run?upload_id=...&fail_on=CRITICAL`. Ответ: `200` при успехе, `409` при блокирующих находках, `500` если выполнение завершилось ошибкой. Пример GitHub Actions — `examples/github-actions-training.yml` (использовать **только** на разрешённом учебном репозитории).

## Команды запуска

Из **корня** проекта в PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m pytest -q
```

Затем открыть **два терминала**:

```powershell
# терминал 1 — из корня проекта
cd backend
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

```powershell
# терминал 2 — из корня проекта
cd frontend
npm ci
npm run dev
npm run build
```

Сначала загрузите учебный Kotlin ZIP, затем откройте шаблон `Full Security Scan`. Для его успешного выполнения дополнительно настройте `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` и AI-ключ или credentials. Для запуска с локальной моделью используйте в `backend/.env`:

```env
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=llama3.2
LLM_API_KEY=ollama
```

Для Gemini: `LLM_PROVIDER=gemini`, затем `GEMINI_API_KEY` или `LLM_API_KEY`.

Для внешнего доступа выставьте `WORKFLOW_ACCESS_TOKEN` и `CI_TOKEN` (последний только для CI), настройте HTTPS + reverse proxy и ограничьте CORS. Ключ интерфейса вводится через «Ключ API» и хранится только в `sessionStorage`; это **общий ключ демо**, а не полноценная система аутентификации пользователей. Не открывайте сервис в публичный интернет без дополнительного контроля доступа и ограничений загрузки данных.

## Что удалось проверить здесь

- `python -m pytest -q tests` — **33/33 пройдено**, включая новые тесты SCA и версий.
- `python -m pytest -q AI_AND_INTEGRATION/AI_CODE_CHECKER/tests` (из директории `AI_CODE_CHECKER`) — **66/66 пройдено**.
- Оба bundled workflow прошли статическую проверку графа по определениям портов 15 нод.
- Все 11 TypeScript/TSX-файлов frontend успешно разобраны синтаксическим парсером TypeScript.
- Все Python-модули успешно прошли `compileall`.

## Что здесь не удалось проверить

- Полный backend-suite (`backend/tests`), живой FastAPI API/WebSocket, реальные AI/Telegram/Webhook запросы и end-to-end запуск: в среде недоступны Python-пакеты `sqlmodel`/`apscheduler` и внешние сервисы.
- `npm run build` / `npm run lint`: не удалось установить npm-пакеты (`npm ci --offline` сообщил `ENOTCACHED`).
- Точность сканеров на обучающем/скрытом репозитории организаторов: исходники, JSON справочник и эталонные находки не приложены к этому архиву.

Это **исправленный исходный проект, а не гарантированно проверенный в развёрнутой среде релиз**. После установки зависимостей обязательно выполните полные тесты и сквозную демонстрацию перед защитой.
