from dataclasses import replace
from pathlib import Path
from .context import FileContext, build_context
from .rules.registry import RULES
from .model import Finding, Severity, Confidence

SKIP_DIRS={".git",".gradle","build","out","target","venv",".venv"}
ALLOWED={".kt",".kts",".properties",".yml",".yaml"}

class SastResult:
    def __init__(self, findings: list[Finding], files_scanned: int, errors: list[str]):
        self.findings=findings; self.files_scanned=files_scanned; self.errors=errors
    def summary(self):
        counts={s.value:0 for s in Severity}
        for f in self.findings: counts[f.severity.value]+=1
        return {"total":len(self.findings),"by_severity":counts,"files_scanned":self.files_scanned,"errors":len(self.errors)}
    def model_dump(self):
        return {"findings":[f.model_dump(mode="json") for f in self.findings],"summary":self.summary(),"errors":self.errors}

def run(project_path: str|Path, config: dict|None=None) -> SastResult:
    root=Path(project_path).resolve()
    if not root.exists() or not root.is_dir(): raise ValueError(f"project_path is not a directory: {root}")
    config=config or {}; enabled=set(config.get("enabled_rules", [r.id for r in RULES]))
    exclude_tests=config.get("exclude_tests", True)
    findings=[]; errors=[]; scanned=0
    contexts: list[FileContext] = []
    for file in sorted(root.rglob("*")):
        if not file.is_file() or file.suffix.lower() not in ALLOWED: continue
        rel=file.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts): continue
        if exclude_tests and "test" in rel.parts: continue
        if file.suffix.lower() in {".yml",".yaml",".properties"} and not (file.name.startswith("application") or file.suffix.lower()==".properties"):
            continue
        try:
            raw=file.read_text(encoding="utf-8-sig")
        except (UnicodeDecodeError,OSError) as exc:
            errors.append(f"{rel.as_posix()}: {type(exc).__name__}"); continue
        scanned+=1
        contexts.append(build_context(root,file,raw))

    all_ctx = tuple(contexts)
    for ctx in contexts:
        enriched = replace(ctx, project_contexts=all_ctx)
        for rule in RULES:
            if rule.id in enabled:
                findings.extend(rule.run(enriched))
    # Stable intra-scanner deduplication.
    unique={f.fingerprint:f for f in findings}
    ordered=sorted(unique.values(),key=lambda f:(list(Severity).index(f.severity),list(Confidence).index(f.confidence),f.file,f.line,f.rule_id))
    return SastResult(ordered,scanned,errors)
