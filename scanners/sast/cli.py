import argparse, json
from pathlib import Path
from .engine import run

def main():
    p=argparse.ArgumentParser(description="CyberGarden Kotlin/Spring Boot SAST")
    p.add_argument("--path",required=True); p.add_argument("--format",choices=["json","text"],default="json")
    a=p.parse_args(); result=run(a.path)
    if a.format=="json": print(json.dumps(result.model_dump(),ensure_ascii=False,indent=2))
    else:
        print(f"Scanned {result.files_scanned} files; findings={len(result.findings)}")
        for f in result.findings: print(f"{f.severity.value} {f.rule_id} {f.file}:{f.line} {f.title}")
if __name__=="__main__": main()
