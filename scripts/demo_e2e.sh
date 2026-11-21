#!/usr/bin/env bash
set -euo pipefail

# Safe reproducible FloraByte demo script (uses dry_run notifications, no external secrets required).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="${1:-/tmp/training/training-project}"
TRUTH_FILE="${2:-/tmp/training/ground-truth/training-findings.json}"
VULN_DB="${VULN_DB_PATH:-/tmp/training/vulnerability-database/vulnerabilities.json}"
PORT="${DEMO_PORT:-8010}"
TMP_ZIP="/tmp/florabyte_demo_project.zip"
TMP_REPORT="/tmp/florabyte_demo_report.json"

if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "Demo project not found at $PROJECT_DIR"
  echo "Usage: $0 /path/to/training-project [/path/to/training-findings.json]"
  exit 1
fi

echo "[1/5] Packing $PROJECT_DIR -> $TMP_ZIP"
python3 - <<PY
import zipfile
from pathlib import Path
src = Path("$PROJECT_DIR")
with zipfile.ZipFile("$TMP_ZIP", "w") as zf:
    for p in src.rglob("*"):
        if p.is_file():
            zf.write(p, f"{src.name}/{p.relative_to(src)}")
PY

echo "[2/5] Starting FloraByte backend on 127.0.0.1:$PORT"
export USE_STUB_SCANNERS=0
if [[ -f "$VULN_DB" ]]; then
  export VULN_DB_PATH="$VULN_DB"
fi
cd "$ROOT_DIR/backend"
uvicorn app.main:app --host 127.0.0.1 --port "$PORT" >/tmp/florabyte_demo_uvicorn.log 2>&1 &
UVICORN_PID=$!
trap 'kill $UVICORN_PID >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

echo "[3/5] Running full 9-node pipeline via API (Secrets + SCA + SAST -> Merge -> Export + AI Explain -> Telegram dry_run)"
python3 - <<PY
import json, httpx
from pathlib import Path

base = "http://127.0.0.1:$PORT"
with open("$TMP_ZIP", "rb") as f:
    up = httpx.post(f"{base}/api/uploads", files={"file": ("demo.zip", f, "application/zip")}, timeout=15.0)
up.raise_for_status()
upload_id = up.json()["upload_id"]

graph = {
    "nodes": [
        {"id": "t1", "type": "trigger.manual", "params": {}},
        {"id": "s1", "type": "source.upload_zip", "params": {"upload_id": upload_id}},
        {"id": "sc1", "type": "scanner.secrets", "params": {}},
        {"id": "sc2", "type": "scanner.sca", "params": {}},
        {"id": "sc3", "type": "scanner.sast", "params": {}},
        {"id": "m1", "type": "findings.merge", "params": {}},
        {"id": "e1", "type": "findings.export", "params": {}},
        {"id": "ai1", "type": "ai.explain", "params": {}},
        {"id": "tg1", "type": "notify.telegram", "params": {"dry_run": True}},
    ],
    "edges": [
        {"id": "e1", "source": "t1", "target": "s1"},
        {"id": "e2", "source": "s1", "target": "sc1"},
        {"id": "e3", "source": "s1", "target": "sc2"},
        {"id": "e4", "source": "s1", "target": "sc3"},
        {"id": "e5", "source": "sc1", "target": "m1", "targetHandle": "a"},
        {"id": "e6", "source": "sc2", "target": "m1", "targetHandle": "b"},
        {"id": "e7", "source": "sc3", "target": "m1", "targetHandle": "c"},
        {"id": "e8", "source": "m1", "target": "e1"},
        {"id": "e9", "source": "m1", "target": "ai1"},
        {"id": "e10", "source": "ai1", "target": "tg1"},
    ],
}
wf = httpx.post(f"{base}/api/workflows", json={"name": "demo-full-scan", "graph_json": graph}, timeout=15.0)
wf.raise_for_status()
run = httpx.post(f"{base}/api/workflows/{wf.json()['id']}/run?wait=true", timeout=60.0)
run.raise_for_status()
run_id = run.json()["run_id"]
detail = httpx.get(f"{base}/api/runs/{run_id}", timeout=15.0).json()
rep = httpx.get(f"{base}/api/runs/{run_id}/report.json", timeout=15.0).json()
Path("$TMP_REPORT").write_text(json.dumps(rep, ensure_ascii=False, indent=2))
print(f"Run ID: {run_id} | status={detail['status']} | findings={len(rep['findings'])}")
PY

if [[ -f "$TRUTH_FILE" ]]; then
  echo "[4/5] Evaluating $TMP_REPORT against $TRUTH_FILE"
  PYTHONPATH="$ROOT_DIR/backend" python3 -m tools.evaluate --report "$TMP_REPORT" --truth "$TRUTH_FILE"
else
  echo "[4/5] Ground-truth file not found at $TRUTH_FILE, skipping evaluate."
fi

echo "[5/5] Demo finished cleanly! Report saved to $TMP_REPORT"
