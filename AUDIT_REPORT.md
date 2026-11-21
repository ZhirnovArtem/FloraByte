# AUDIT_REPORT — FloraByte (Cyber Garden 2026)

**Ветка:** `fix/florabyte-integration` (базовый коммит аудита: `5983292`)  
**Дата аудита:** 2026-11-21  
**Цель:** зафиксировать архитектуру репозитория, выявленные проблемы (P0 / P1 / P2), план исправлений по фазам 1–12 и подтверждающие проверки.

---

## 1. Карта архитектуры репозитория

```
FloraByte/
├── pyproject.toml                   # Единая установка (scanners*, security_scanners*, backend) и pytest
├── README.md / FIXES_AND_VERIFICATION.md
├── scanners/sast/                   # Собственный SAST-анализатор (Kotlin/Spring Boot, правила SAST-*)
├── security_scanners/
│   ├── core/                        # Модели ScanInput/SourceFile/Finding сканеров
│   ├── secrets/                     # Собственный Secrets-сканер
│   └── sca/                         # Собственный SCA-сканер (Gradle parser + version range + vulnerabilities.json)
├── AI_AND_INTEGRATION/
│   └── AI_CODE_CHECKER/             # Модуль AI-анализа (Gemini REST + scrubber + SecurityFinding v1.0)
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI entrypoint, CORS, lifespan (APScheduler), token middleware
│   │   ├── config.py                # Pydantic Settings (.env)
│   │   ├── api/                     # node_types, workflows, runs, uploads, ws, credentials, templates, ci
│   │   ├── core/                    # models.py (Finding, Workflow, Run, NodeRun, Credential), db, crypto, masking, logging
│   │   ├── engine/                  # graph.py (validate/toposort), executor.py, events.py, scheduler.py
│   │   └── nodes/                   # @register_node ноды: triggers, source, scanners, findings, logic, ai, notify
│   ├── templates/                   # full-security-scan.json, quick-secrets.json
│   ├── tools/                       # evaluate.py, mutate_project.py
│   └── tests/                       # Backend-тесты
├── tests/                           # Тесты сканеров (Secrets, SCA, SAST)
├── examples/                        # Пример GitHub Actions (github-actions-training.yml)
└── frontend/                        # React 19 + @xyflow/react + Vite 8 + Tailwind 4 редактор
```

### Покрытие подсистем на момент аудита (коммит `5983292`)

| Подсистема | Текущее состояние | Основные файлы |
|---|---|---|
| Реестр нод и движок | 15 нод через `@register_node`, DAG-валидация, топосортировка, `if_else`, таймауты, частичные ошибки (`partial`) | `backend/app/nodes/registry.py`, `backend/app/engine/graph.py`, `executor.py` |
| API & БД | SQLite + SQLModel (`Workflow`, `Run`, `NodeRun`, `Credential`); CRUD workflow, runs, uploads, credentials, templates, CI | `backend/app/core/models.py`, `backend/app/api/*.py` |
| Сканеры (Secrets/SCA/SAST) | Реальные модули подключены адаптерами (`USE_STUB_SCANNERS=0`); в `5983292` восстановлен `security_scanners/secrets/` | `security_scanners/`, `scanners/sast/`, `backend/app/nodes/scanners/` |
| AI Explain | Адаптер над `AI_CODE_CHECKER` (`gemini`) + `openai_compatible` (Ollama/vLLM) + валидатор + fallback | `backend/app/nodes/ai/explain.py`, `validator.py`, `llm_client.py` |
| Уведомления | Telegram Bot API + HTTP Webhook с проверкой URL/IP и `follow_redirects=False` | `backend/app/nodes/notify/telegram.py`, `webhook.py` |
| WebSocket | `/ws/runs/{run_id}` с очередью событий в памяти (`EventBus`) и replay текущей истории | `backend/app/api/ws.py`, `backend/app/engine/events.py` |
| Безопасность и Crypto | Fernet-шифрование credentials, маскирование секретов, ZIP-slip проверка, `GIT_CLONE_ALLOWLIST`, опциональные `WORKFLOW_ACCESS_TOKEN` / `CI_TOKEN` | `backend/app/core/crypto.py`, `masking.py`, `source/upload_zip.py`, `source/git_clone.py` |
| Frontend | React Flow редактор, настройки нод, загрузка ZIP, запуск, WS + polling fallback, отчёты (`findings`, `ai`, `markdown`, `log`) | `frontend/src/components/*.tsx`, `frontend/src/api/client.ts` |

---

## 2. Выявленные проблемы и план исправлений

### P0 — Критичные проблемы

1. **Ошибки `eslint` во frontend (`npm run lint` падает с exit code 1)**
   - **Файлы:** `frontend/src/components/NodeSettings.tsx` (строки 32, 40, 47, 49 — `react-hooks/set-state-in-effect`, `react-hooks/exhaustive-deps`), `frontend/src/components/WorkflowEditor.tsx` (строка 316 — warning `react-hooks/exhaustive-deps`).
   - **Способ исправления (Фаза 7):** убрать синхронные `setState` внутри `useEffect` (использовать `key={selectedNode?.id}` или производное состояние/сброс при изменении пропсов без каскадных эффектов) и выровнять зависимости эффектов.
   - **Подтверждающий тест:** `cd frontend && npm run lint && npm run build`.

2. **Отсутствие неanchored правила `.gitignore` для `secrets/` блокирует отслеживание новых файлов в `security_scanners/secrets/`**
   - **Файлы:** `.gitignore` (строка 43: `secrets/`), `backend/.gitignore` (строка 27: `secrets/`).
   - **Способ исправления (Фаза 1):** заменить `secrets/` на `/secrets/` (добавив также `*.key` и `*.db*`), чтобы папка `security_scanners/secrets/` не попадала под ignore.
   - **Подтверждающий тест:** `git check-ignore -v security_scanners/secrets/new_file.py` возвращает пустой результат (не игнорируется), а `.env`, `*.db`, `*.key` игнорируются.

3. **Неконсистентные зависимости и конфигурация окружения для чистой установки**
   - **Файлы:** корень репозитория (нет `.env.example`, `.python-version`, `.nvmrc`), `backend/.env.example` (не отражены `GEMINI_API_KEY`, `GEMINI_MODEL`, `VULN_DB_PATH`, `CORS_ALLOW_ORIGINS`, `NODE_TIMEOUT_SEC`, `APP_SECRET_KEY_FILE`), `backend/requirements.txt` (отсутствует `python-dotenv>=1.0.0`, указанный в `pyproject.toml`), `frontend/package.json` (не зафиксирован `engines.node`).
   - **Способ исправления (Фаза 1):** добавить корневой `.env.example`, синхронизировать `backend/.env.example`, зафиксировать `.python-version` (`3.13`) и `.nvmrc` (`20.20.2`), добавить `python-dotenv>=1.0.0` в `backend/requirements.txt`, добавить `engines.node` в `frontend/package.json`.
   - **Подтверждающий тест:** чистая проверка `pip install -e ".[test]"` / `pip install -r backend/requirements.txt`, `pytest -q`, `cd frontend && npm ci && npm run build`.

4. **Качество анализаторов на эталонном учебном наборе организаторов не подтверждено на текущей ветке**
   - **Файлы:** `security_scanners/secrets/`, `security_scanners/sca/`, `scanners/sast/`, `backend/tools/evaluate.py`, `backend/tools/mutate_project.py`.
   - **Причина:** каталог `/tmp/training` (`https://github.com/TBagirov/training`) отсутствует в текущем окружении (хранится вне git); по прежним прогонам baseline-версия находила не 15/15 эталонных уязвимостей и допускала ложные срабатывания на контрольных примерах.
   - **Способ исправления (Фазы 3–4):** клонировать учебный репозиторий в `/tmp/training`, прогнать `python -m tools.evaluate`, доработать правила Secrets/SCA/SAST (без хардкода под конкретные классы/строки) и проверить устойчивость через `tools/mutate_project.py`.
   - **Подтверждающий тест:** `python -m tools.evaluate` (exit code `0`, 15/15 matched, 0 control hits) + `pytest -q`.

---

### P1 — Важные проблемы (безопасность, надёжность, UX, CI/CD)

5. **Эфемерный путь ключа Fernet по умолчанию (`/tmp/ai_security_workflow_secret.key`)**
   - **Файлы:** `backend/app/core/crypto.py`, `backend/app/config.py`.
   - **Риск:** при очистке `/tmp` или перезапуске контейнера без заданного `APP_SECRET_KEY` ранее зашифрованные credentials становятся нечитаемыми.
   - **Способ исправления (Фаза 6):** перенести fallback-файл ключа по умолчанию в постоянный локальный каталог вне `/tmp` (или требовать/генерировать в `data/.secret.key`, игнорируемом `.gitignore`), сохраняя поддержку `APP_SECRET_KEY` и `APP_SECRET_KEY_FILE`.
   - **Подтверждающий тест:** тест на сохранение расшифровки credentials после сброса кэша и перезагрузки модуля (`backend/tests/test_masking_crypto.py`).

6. **Потенциальное окно DNS rebinding и отсутствие лимита размера ответа в Webhook**
   - **Файлы:** `backend/app/nodes/notify/webhook.py`.
   - **Риск:** `_validate_destination` проверяет DNS отдельно от `httpx.AsyncClient.post()`, а ответ сервера не ограничен по объёму; кроме того, отсутствует retry на временные 5xx/сетевые ошибки (Фаза 8).
   - **Способ исправления (Фазы 6 и 8):** проверять резолвинг непосредственно перед запросом / пинить валидированный IP или транспорт-проверку, ограничить чтение ответа, добавить ограниченный retry с backoff.
   - **Подтверждающий тест:** `backend/tests/test_templates_webhook.py` + новые тесты на SSRF/redirect/timeout/retry.

7. **Отсутствие явной проверки compression ratio (zip bomb) и таймаута распаковки в `upload_zip`**
   - **Файлы:** `backend/app/nodes/source/upload_zip.py`, `backend/app/api/uploads.py`.
   - **Способ исправления (Фаза 6):** добавить проверку коэффициента сжатия / фактического количества распакованных байт при потоковой распаковке вместо `zf.extractall()`, ограничить время распаковки и гарантировать очистку временных директорий.
   - **Подтверждающий тест:** `backend/tests/test_zip_and_root.py` (добавить тест zip-bomb / symlink / traversal).

8. **Потеря истории WebSocket-событий после рестарта backend**
   - **Файлы:** `backend/app/engine/events.py`, `backend/app/api/ws.py`.
   - **Способ исправления (Фаза 2):** при подключении к `/ws/runs/{run_id}`, если в памяти `event_bus` нет истории, восстанавливать события из БД (`Run` + `NodeRun`), чтобы клиент получал состояние уже завершившегося или прерванного запуска.
   - **Подтверждающий тест:** интеграционный тест `backend/tests/test_e2e_phase_b.py` / новый WS-тест с очисткой `event_bus._history`.

9. **Валидация CVE/GHSA против реального справочника в AI Explain и проверка OpenAI-compatible режима**
   - **Файлы:** `backend/app/nodes/ai/validator.py`, `backend/app/nodes/ai/explain.py`, `backend/app/nodes/ai/llm_client.py`.
   - **Способ исправления (Фаза 5):** дополнительно сверять упомянутые CVE/GHSA не только с входными находками, но и с загруженным справочником уязвимостей (`VULN_DB_PATH`), а также добавить тесты переключения `gemini` ↔ `openai_compatible` (Ollama/vLLM) и проверки всех обязательных полей объяснения.
   - **Подтверждающий тест:** `backend/tests/test_ai_validator.py`, `backend/tests/test_ai_explain_node.py`.

10. **CI/CD и GitHub Actions**
    - **Файлы:** `backend/app/api/ci.py`, отсутствие `.github/workflows/*.yml`.
    - **Способ исправления (Фаза 9):** доработать CI API (запуск, статус/результат, политика `CRITICAL`/`HIGH`, webhook при необходимости) и добавить `.github/workflows/` для backend tests, frontend build + lint, проверки безопасности репозитория и оценки анализаторов.
    - **Подтверждающий тест:** CI API тесты в `backend/tests/`.

11. **Согласованность API-аутентификации на открытом стенде**
    - **Файлы:** `backend/app/main.py`, `frontend/src/api/client.ts`.
    - **Замечание:** `WORKFLOW_ACCESS_TOKEN` опционален для локальной разработки; при выставлении в публичном демо UI должен иметь способ ввода/передачи токена без ручной правки `sessionStorage` (Фаза 6–7).

---

### P2 — Улучшения UX, документации и дополнительные функции (Фаза 12)

12. **Отсутствие корневого `ARCHITECTURE.md` и обновление единой документации (Фаза 11)**
    - **Файлы:** `README.md`, `backend/docs/ARCHITECTURE.md`, `backend/docs/DEMO.md`.
    - **План:** проверить полноту и актуальность после завершения Фаз 2–10.

13. **Дополнительные возможности (Фаза 12 — строго после обязательных критериев Фаз 0–11):**
    - Библиотека готовых шаблонов (`GET/POST/PUT/DELETE /api/templates`, `/publish`, `/clone`, санитизация секретов при публикации, экран «Библиотека шаблонов»);
    - Расширенная CI/CD интеграция;
    - AI Workflow Generator («Создать с помощью AI»);
    - Сравнение запусков, Dashboard по критичности, дедупликация между запусками, экспорт PDF.

---

## 3. Проверка секретов в репозитории (Фаза 0/1)

- Проведён автоматический поиск по всем коммитам истории (`git rev-list --all`) на паттерны реальных ключей (`AIza...`, `ghp_...`, `sk-...`, Telegram bot tokens).
- **Результат:** реальных секретов в текущих файлах и истории Git не обнаружено (единственные совпадения — синтетические тестовые строки в `backend/tests/test_masking_crypto.py`).
- Никакие ключи не передаются в код, шаблоны, логи или отчёты.

---

## 4. Базовые метрики на старте (коммит `5983292`)

- `pytest -q` (из корня): **88 passed**
- `cd frontend && npm ci && npm run build`: **успешно** (`dist/` собран за 304 ms)
- `cd frontend && npm run lint`: **ошибка (exit code 1)** — 2 ошибки в `NodeSettings.tsx`, 3 warning (`NodeSettings.tsx`, `WorkflowEditor.tsx`)
- `tools.evaluate`: **не запускалось** (в текущем sandbox отсутствует `/tmp/training`; требуется клонирование учебного репозитория в Фазе 4).
