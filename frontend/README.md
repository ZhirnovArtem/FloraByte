# FloraByte — Frontend (React + React Flow)

Визуальный конструктор security-сценариев (workflow) для платформы **AI Security Workflow**.

## Возможности

- **Каталог нод из Backend (`GET /api/node-types`):** палитра в левой панели строится динамически, при недоступности сервера используется локальный fallback-каталог.
- **Готовые шаблоны (`GET /api/templates`, `POST /api/templates/{id}/copy`):** быстрая загрузка преднастроенных графов (например, `Full Security Scan`).
- **Редактор графа (React Flow):** добавление/удаление нод, соединение типизированных портов (`Workspace`, `Findings`, `Report`, ветки `true`/`false`), предзапусковая проверка графа.
- **Динамические настройки нод:** форма параметров генерируется по `params_schema`, поддерживает загрузку `.zip` (`POST /api/uploads`) и управление Fernet-секретами (`GET/POST /api/credentials`).
- **Сохранение и загрузка (`GET/POST/PUT /api/workflows`):** сохранение на сервере с автоматическим резервным копированием в `localStorage`.
- **Выполнение и мониторинг в реальном времени (`POST /api/workflows/{id}/run`, `WS /ws/runs/{run_id}`):** отображение статусов нод (`pending → running → success | failed | skipped`), восстановление отслеживания через `GET /api/runs/{id}` при обрыве WebSocket или перезагрузке страницы.
- **Панель находок и отчётов:** таблица находок с фильтрами, вкладка AI-отчёта с явным индикатором режима (`LLM (Gemini)` / `Fallback (без LLM)` / `Нет находок`), Markdown-предпросмотр и скачивание `report.json` / `report.md`.

## Структура `src/`

- `src/api/client.ts` — HTTP и WebSocket клиент к FastAPI backend
- `src/types/workflow.ts` — TypeScript-типы графа, нод, запусков, находок и AI-отчёта
- `src/config/nodeCatalog.ts` — запасной локальный каталог нод (при офлайн-режиме)
- `src/components/WorkflowEditor.tsx` — основной редактор, тулбар, загрузка ZIP, запуск и отслеживание статусов
- `src/components/NodeSidebar.tsx` — левая панель блоков и шаблонов
- `src/components/NodeSettings.tsx` — правая панель параметров выбранной ноды
- `src/components/SecurityNode.tsx` — кастомная нода React Flow с портами и бейджами статуса
- `src/components/ReportPanel.tsx` — нижняя панель находок, AI-анализа, Markdown и WS-лога

## Локальный запуск и сборка

```bash
cd frontend
npm install
npm run dev       # http://localhost:5173 (проксирует /api, /ws, /health на http://127.0.0.1:8000)
npm run build     # проверка TypeScript (tsc -b) и production-сборка Vite
npm run lint      # ESLint
```

Переменная окружения `VITE_BACKEND_URL` позволяет переопределить адрес backend для Vite proxy (по умолчанию `http://127.0.0.1:8000`).
