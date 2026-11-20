# CyberGarden SAST v0.1 — стартовый исполняемый артефакт

Собственный regex-first SAST для учебных Kotlin/Spring Boot проектов. Не использует Semgrep, Gitleaks, Trivy, detekt-security, чужие rule packs или LLM как детектор.

## Запуск

```bash
python -m venv .venv
. .venv/bin/activate                 # Windows: .venv\\Scripts\\activate
pip install -e '.[test]'
python -m scanners.sast --path /path/to/training-project --format json
pytest -q
```

## API

```python
from scanners.sast import run
result = run("/path/to/training-project")
findings = [f.model_dump(mode="json") for f in result.findings]
summary = result.summary()
```

## Нода

`SastKotlinNode.type = "scanner.sast_kotlin"`; вход `project_path`; выход `outputs.findings`, `outputs.summary`; ошибки перехватываются на границе ноды.

## Реестр

10 собственных правил: SEC-001/002/003/005, INJ-001/002, CRY-001, CFG-001/002, LOG-001. Каталог является начальной реализацией; правила требуют сверки с эталоном организаторов.

## Ограничения v0.1

- Regex-first, без полноценного Kotlin AST и межпроцедурного taint analysis. Уровни L2/L3 из ТЗ пока не реализованы.
- Тесты дают две положительные и две отрицательные проверки на каждое правило, но это начальные smoke-fixtures, а не доказательство recall/precision на учебном проекте.
- Секреты в evidence обрезаются по длине, но универсальное обнаружение и маскирование секретов должно быть предоставлено/согласовано с владельцем Secrets (Человек 3). Не считать это закрытием FR-FND-04.
- Таймаут должен обеспечиваться исполнителем workflow; поле timeout_seconds зарезервировано в схеме параметров, но отдельный процессный timeout в этой версии не реализован.
- YAML разбирается regex-правилами только для двух заданных ключей; общая YAML-семантика и наследование профилей не реализованы.
