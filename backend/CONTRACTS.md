# CONTRACTS — Integration Baseline

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

## 2. Scanner interface and adapters

```python
def scan(root: Path, params: dict) -> list[Finding]:
    ...
```

- `root` = Gradle project root.
- Secrets are masked (`app.core.masking.mask_secret`, `mask_evidence`, `redact_text`) before leaving the node.
- SCA receives `vuln_db_path` and `lockfile_priority` in `params`. Supports both the organisers' OSV/JSON format (`{"vulnerabilities": [...]}`) and the built-in `security_scanners/sca/vulnerabilities.json`.
- Real implementations wired in `backend/app/nodes/scanners/`:
  - `secrets.py` → `security_scanners.secrets.scanner.SecretsScanner` (mapped to `password`, `api-key`, `configuration-token`, `private-key`)
  - `sca.py` → `security_scanners.sca.scanner.ScaScanner`
  - `sast.py` → `scanners.sast.engine.run` (mapped to `sql-injection`, `route-authorization`, `credentialed-cors`, `tls-verification`, `object-authorization`, etc.)
- Stubs under `USE_STUB_SCANNERS=1` only. Default is `0`.

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

`GET /api/node-types` returns `type, label, group, inputs, outputs, params_schema` for the frontend palette and dynamic settings forms.

## 4. AI node (`ai.explain`)

- Calls `analyze_findings` from `AI_AND_INTEGRATION/AI_CODE_CHECKER/services/ai_service.py` (Gemini API, `GEMINI_API_KEY` / `LLM_API_KEY` / `credential_id`), converting platform `Finding` objects into canonical `SecurityFinding v1.0` dicts (with masked `evidence`).
- Validates output through `app.nodes.ai.validator.validate_llm_response` (JSON schema, `finding_ref`, stripping hallucinated CVE/GHSA IDs, secret-leak check).
- Retries once on validation failure; falls back deterministically to `fallback_report()` if key is absent or provider fails.
- Persists result into `runs.ai_report_json` (returned as `ai_report` in `GET /api/runs/{id}`).

## 5. Workflow JSON (React Flow compatible)

```json
{
  "nodes": [{"id":"n1","type":"scanner.secrets","params":{},"position":{"x":0,"y":0}}],
  "edges": [{"id":"e1","source":"n3","sourceHandle":"true","target":"n4","targetHandle":"in"}]
}
```

## 6. Execution events (WebSocket `/ws/runs/{run_id}` + `node_runs`)

Events: `run_started`, `node_started`, `node_finished`, `node_failed`, `node_skipped`, `run_finished`.

Statuses: `pending → running → success | failed | skipped`.

## 7. Credentials

Values encrypted with Fernet (`APP_SECRET_KEY` or generated file outside repo).  
API never returns plaintext — only `"****"` + last 2–4 chars.  
Node params store only `credential_id`.

## 8. Allowed git URLs

Configured via `GIT_CLONE_ALLOWLIST` (default contains `https://github.com/TBagirov/training`).
