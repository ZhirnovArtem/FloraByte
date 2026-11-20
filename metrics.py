"""Compare SAST JSON output with an organizer ground-truth JSON.
Expected truth shape: {"findings": [{"class": rule_id, "path": relative_path, "line": int}, ...]}.
The comparison is rule+path+line exact; mutation runs may supply adjusted line numbers.
"""
import argparse, json
from pathlib import Path
from scanners.sast.engine import run

def key(x): return (x.get("class") or x.get("rule_id"), x.get("path") or x.get("file"), x.get("line"))

def main():
    p=argparse.ArgumentParser(); p.add_argument("--project",required=True); p.add_argument("--ground-truth",required=True); p.add_argument("--out",default="metrics.json"); a=p.parse_args()
    actual=run(a.project)
    truth=json.loads(Path(a.ground_truth).read_text(encoding="utf-8"))["findings"]
    predicted=[{"class":f.rule_id,"path":f.file,"line":f.line} for f in actual.findings]
    tset={key(x) for x in truth}; pset={key(x) for x in predicted}
    tp=len(tset & pset); fn=len(tset-pset); fp=len(pset-tset)
    recall=tp/(tp+fn) if tp+fn else 1.0
    precision=tp/(tp+fp) if tp+fp else 1.0
    report={"true_positive":tp,"false_positive":fp,"false_negative":fn,"recall":round(recall,4),"precision":round(precision,4),"files_scanned":actual.files_scanned,"scanner_errors":actual.errors,"acceptance_recall_ge_0_90":recall>=0.90,"acceptance_false_positives_le_2_per_10_findings":fp <= max(0.2*max(tp+fn,1),2)}
    Path(a.out).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2))
if __name__=="__main__": main()
