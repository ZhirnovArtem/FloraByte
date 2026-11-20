# AI Security Workflow — Backend

Visual security-check workflow platform (Cyber Garden 2026 / Центр-инвест).

## Phase A (current)

- Finding model compatible with organisers' submission format
- BaseNode + registry (`@register_node`)
- All required node types registered (stubs)
- SQLite schema, config, masking, Fernet crypto
- `GET /api/node-types`, `/health`
- Unit tests for contracts

## Quick start

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q
uvicorn app.main:app --reload --port 8000
# open http://127.0.0.1:8000/api/node-types
```

## Structure

See `CONTRACTS.md` and the brief. New node = one file under `app/nodes/<group>/`.

## Secrets

Never put tokens in source. Use `.env` (gitignored) or the credentials API (Phase D).
Telegram bot token and Gemini key belong in credentials / env only.
