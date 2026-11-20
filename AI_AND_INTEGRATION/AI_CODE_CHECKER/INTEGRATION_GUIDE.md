# INTEGRATION_GUIDE — AI analysis component

Версия контракта: **1.0.0** (`contracts.CONTRACT_VERSION`).
Документ для разработчика, собирающего CyberGarden. Описывает только
этот компонент; backend, scanners и frontend — вне его границ.

## 1. Что делает компонент

Принимает нормализованные findings от сканеров, получает от Gemini
объяснение/риск/рекомендацию, возвращает валидированный отчёт.
Не сканирует, не хранит, не отправляет уведомления, не имеет HTTP API.

## 2. Публичный API

```python
from services.ai_service import analyze_findings, AIServiceError

report: dict = await analyze_findings(findings: list[dict])