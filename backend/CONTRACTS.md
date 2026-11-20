# CONTRACTS — Phase A (do not change without team confirmation)

## 1. Finding (organisers' submission format)

```python
class Finding(BaseModel):
    category: Literal["SECRET", "SAST", "SCA"]
    path: str                    # relative to Gradle project root, '/' separators
    class_: str | None           # alias "class" — required for SECRET/SAST
    line: int | None             # required for SECRET/SAST, >= 1
    endLine: int | None          # optional, line <= endLine <= line+14
    group / artifact / version / advisoryId  # required for SCA
    severity / description / remediation     # optional
    # internal (not exported): id, rule_id, evidence (masked), confidence
```

`to_submission()` emits only organisers' keys with exact casing. Empty optional fields are omitted.

Validators enforce path safety (no absolute, no `..`, no `:`) and typed lines.

## 2. Scanner interface (for people 3 & 4)

```python
def scan(root: Path, params: dict) -> list[Finding]:
    ...
```

- `root` = Gradle project root.
- Secrets must be masked (`core.masking.mask_secret`) before returning.
- SCA receives `vuln_db_path` and `lockfile_priority` in `params`.
- Real implementations live outside this contract; adapters call them.

Stubs under `USE_STUB_SCANNERS=1` only. Default is off.

## 3. Node contract

```python
class BaseNode(ABC):
    type: ClassVar[str]          # e.g. "scanner.secrets"
    label: ClassVar[str]
    group: ClassVar[str]         # source|trigger|logic|scanner|ai|notify|findings
    inputs / outputs: ClassVar[list[Port]]
    Params: ClassVar[type[BaseModel]]
    async def run(self, ctx: NodeContext, inputs: dict, params: BaseModel) -> dict[str, Any]
```

Registration: `@register_node` on the class. New node = one file, zero engine/API edits.

`GET /api/node-types` returns `type, label, group, inputs, outputs, params_schema` for the palette.

## 4. Workflow JSON (React Flow compatible)

```json
{
  "nodes": [{"id":"n1","type":"scanner.secrets","params":{},"position":{"x":0,"y":0}}],
  "edges": [{"id":"e1","source":"n3","sourceHandle":"true","target":"n4","targetHandle":"in"}]
}
```

## 5. Execution events (WebSocket + node_runs)

Events: `run_started`, `node_started`, `node_finished`, `node_failed`, `node_skipped`, `run_finished`.

Statuses: `pending → running → success | failed | skipped`.

## 6. Credentials

Values encrypted with Fernet (`APP_SECRET_KEY` or generated file outside repo).  
API never returns plaintext — only `"****"` + last 2–4 chars.  
Node params store only `credential_id`.

## 7. Allowed git URLs

Configured via `GIT_CLONE_ALLOWLIST` (default contains `https://github.com/TBagirov/training`).

---

**Phase A status:** contracts frozen, registry live, tests green.
