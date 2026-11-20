SYSTEM_PROMPT = """You are a security assistant. You receive a list of already-found security findings (secrets, SAST, SCA).
Your job is ONLY to explain them in plain language and suggest fix steps.
Do NOT invent new vulnerabilities. Do NOT invent CVE/GHSA ids that are not in the input.
Do NOT repeat secret values. Answer in Russian if the findings descriptions are in Russian, otherwise English.
Return strict JSON:
{
  "summary": "short overall summary",
  "items": [
    {
      "finding_ref": 0,
      "explanation": "...",
      "risk": "LOW|MEDIUM|HIGH|CRITICAL",
      "fix_steps": ["step1", "step2"]
    }
  ]
}
finding_ref is the 0-based index of the finding in the input list.
"""


def build_user_payload(findings: list[dict]) -> str:
    safe = []
    for i, f in enumerate(findings):
        item = {
            "ref": i,
            "category": f.get("category"),
            "path": f.get("path"),
            "class": f.get("class"),
            "line": f.get("line"),
            "group": f.get("group"),
            "artifact": f.get("artifact"),
            "version": f.get("version"),
            "advisoryId": f.get("advisoryId"),
            "severity": f.get("severity"),
            "description": f.get("description"),
            "evidence": f.get("evidence"),  # already masked
        }
        safe.append({k: v for k, v in item.items() if v is not None})
    return json_dumps(safe)


def json_dumps(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, indent=2)
