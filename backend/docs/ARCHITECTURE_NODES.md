# Архитектура модульных узлов FloraByte

## Контракт узла (`BaseNode`)

Каждый узел (нода) в FloraByte — это независимый Python-класс, наследующий `app.nodes.base.BaseNode` и декорированный `@register_node`.

### Обязательные поля класса
- `type: ClassVar[str]` — уникальный идентификатор узла (например, `notify.slack`, `scanner.secrets`).
- `label: ClassVar[str]` — человекочитаемое название в конструкторе.
- `group: ClassVar[str]` — категория (`trigger` | `source` | `scanner` | `logic` | `findings` | `ai` | `notify`).
- `inputs: ClassVar[list[Port]]` — типизированные входные порты (`Workspace`, `Findings`, `Report`, `Boolean`, `Any`).
- `outputs: ClassVar[list[Port]]` — типизированные выходные порты.
- `Params: ClassVar[type[BaseModel]]` — Pydantic-схема параметров; автоматически публикуется через `GET /api/node-types` (JSON Schema) для генерации формы настроек в UI.
- `continue_downstream_on_error: ClassVar[bool] = False` — если `True`, ошибка в отчёте узла помечает узел как `failed`, но позволяет нижестоящим узлам получить переданные данные (используется в `ai.explain`).

### Метод выполнения
```python
async def run(self, ctx: NodeContext, inputs: dict[str, Any], params: BaseModel) -> dict[str, Any]:
    ...
```
- `ctx` содержит `run_id`, `node_id`, `workspace`, `settings`, `owner_id`.
- Возвращаемое значение — словарь `{output_port_name: value}`.
- Любое необработанное исключение переводится ядром (`Executor`) в статус `failed`, изолируя ветку графа без падения остальных веток.

## Автообнаружение нод

Функция `discover_nodes()` в `backend/app/nodes/__init__.py` автоматически обходит пакет `app.nodes.*` через `pkgutil.walk_packages`. Чтобы добавить новый тип блока, достаточно создать один новый файл (например, `backend/app/nodes/notify/mattermost.py`) с `@register_node` — изменения в `Executor`, `main.py` или роутерах API не требуются.
