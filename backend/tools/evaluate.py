"""Evaluate a submission report.json against organisers' ground-truth.

Matching rules (from brief / ground-truth README):
- category + path
- SECRET/SAST: class + line in [line, endLine] (consider alternateLocations)
- SCA: group/artifact/version/advisoryId
- Controls: any hit is a false positive

Usage:
  python -m tools.evaluate --report out.json --truth /path/to/ground-truth/training-findings.json
Exit code 0 only if all 15 findings matched and 0 control hits.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict | list:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _path_norm(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./")


def _line_in_range(line: int | None, start: int | None, end: int | None) -> bool:
    if line is None or start is None:
        return False
    end = end if end is not None else start
    return start <= line <= end


def locations_of(truth: dict) -> list[tuple[str, int | None, int | None]]:
    locs = [(_path_norm(truth.get("path", "")), truth.get("line"), truth.get("endLine"))]
    for alt in truth.get("alternateLocations") or []:
        locs.append((_path_norm(alt.get("path", "")), alt.get("line"), alt.get("endLine")))
    return locs


def match_secret_sast(pred: dict, truth: dict) -> bool:
    if pred.get("category") != truth.get("category"):
        return False
    if (pred.get("class") or "") != (truth.get("class") or ""):
        return False
    pline = pred.get("line")
    ppath = _path_norm(pred.get("path", ""))
    for tpath, tline, tend in locations_of(truth):
        if ppath == tpath and _line_in_range(pline, tline, tend):
            return True
        # also accept if pred spans and overlaps
        pend = pred.get("endLine") or pline
        if ppath == tpath and pline is not None and tline is not None:
            if not (pend < tline or pline > (tend or tline)):
                return True
    return False


def match_sca(pred: dict, truth: dict) -> bool:
    if pred.get("category") != "SCA" or truth.get("category") != "SCA":
        return False
    if _path_norm(pred.get("path", "")) != _path_norm(truth.get("path", "")):
        # path soft: still require coords
        pass
    if (pred.get("group") or "") != (truth.get("group") or ""):
        return False
    if (pred.get("artifact") or "") != (truth.get("artifact") or ""):
        return False
    if (pred.get("version") or "") != (truth.get("version") or ""):
        return False
    advisory = pred.get("advisoryId") or ""
    truth_ids = set(truth.get("advisoryIds") or [])
    if truth.get("advisoryId"):
        truth_ids.add(truth["advisoryId"])
    return advisory in truth_ids or advisory == truth.get("advisoryId")


def match_one(pred: dict, truth: dict) -> bool:
    cat = truth.get("category")
    if cat in ("SECRET", "SAST"):
        return match_secret_sast(pred, truth)
    if cat == "SCA":
        return match_sca(pred, truth)
    return False


def evaluate(report: dict, truth: dict) -> dict[str, Any]:
    preds = report.get("findings") or []
    findings = truth.get("findings") or []
    controls = truth.get("controls") or []

    matched_truth: list[str] = []
    missed: list[dict] = []
    used_pred: set[int] = set()

    for t in findings:
        found = False
        for i, p in enumerate(preds):
            if i in used_pred:
                continue
            if match_one(p, t):
                matched_truth.append(t.get("id") or t.get("class") or str(t.get("path")))
                used_pred.add(i)
                found = True
                break
        if not found:
            missed.append({
                "id": t.get("id"),
                "category": t.get("category"),
                "class": t.get("class"),
                "path": t.get("path"),
                "line": t.get("line"),
                "group": t.get("group"),
                "artifact": t.get("artifact"),
                "version": t.get("version"),
                "advisoryIds": t.get("advisoryIds"),
            })

    control_hits: list[dict] = []
    for c in controls:
        for p in preds:
            # control hit if same category/path/class/line roughly
            if match_one(p, {**c, "category": c.get("category"), "advisoryIds": c.get("advisoryIds") or []}):
                control_hits.append({
                    "control_id": c.get("id"),
                    "reason": c.get("reason"),
                    "pred": p,
                })
                break
            # softer control check for SECRET placeholders etc.
            if (
                p.get("category") == c.get("category")
                and _path_norm(p.get("path", "")) == _path_norm(c.get("path", ""))
                and (c.get("line") is None or p.get("line") == c.get("line") or _line_in_range(p.get("line"), c.get("line"), c.get("endLine")))
            ):
                # class match if present
                if c.get("class") and p.get("class") and p.get("class") != c.get("class"):
                    continue
                control_hits.append({
                    "control_id": c.get("id"),
                    "reason": c.get("reason"),
                    "pred": p,
                })
                break

    tp = len(matched_truth)
    fn = len(missed)
    fp_controls = len(control_hits)
    # precision/recall relative to ground-truth findings (controls counted separately)
    recall = tp / len(findings) if findings else 1.0
    precision = tp / (tp + fp_controls) if (tp + fp_controls) else (1.0 if tp == 0 and not preds else 0.0)

    return {
        "total_truth": len(findings),
        "total_preds": len(preds),
        "matched": tp,
        "missed": missed,
        "matched_ids": matched_truth,
        "control_hits": control_hits,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "passed": fn == 0 and fp_controls == 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate report against ground-truth")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--json", action="store_true", help="Print full JSON result")
    args = parser.parse_args(argv)

    report = load_json(args.report)
    truth = load_json(args.truth)
    if isinstance(report, list):
        report = {"findings": report}

    result = evaluate(report, truth)

    print(f"Matched: {result['matched']}/{result['total_truth']}")
    print(f"Missed:  {len(result['missed'])}")
    for m in result["missed"]:
        print(f"  - MISS {m.get('category')} {m.get('class') or m.get('artifact')} @ {m.get('path')}:{m.get('line')}")
    print(f"Control hits (false positives): {len(result['control_hits'])}")
    for h in result["control_hits"]:
        print(f"  - FP control {h.get('control_id')}: {h.get('reason')}")
    print(f"Precision: {result['precision']}  Recall: {result['recall']}")
    print("PASS" if result["passed"] else "FAIL")

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
