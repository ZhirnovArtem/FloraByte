from __future__ import annotations
import re

def _tokenize(version: str) -> list[int | str]:
    tokens: list[int | str] = []
    for part in re.split(r"[.\-_+]", version.strip().lower()):
        for sub in re.findall(r"\d+|[a-z]+", part):
            tokens.append(int(sub) if sub.isdigit() else sub)
    return tokens

def compare_versions(a: str, b: str) -> int:
    ta, tb = _tokenize(a), _tokenize(b)
    for x, y in zip(ta, tb):
        if x == y: continue
        if isinstance(x, int) and isinstance(y, int): return -1 if x < y else 1
        if isinstance(x, int) and isinstance(y, str): return 1
        if isinstance(x, str) and isinstance(y, int): return -1
        if isinstance(x, str) and isinstance(y, str): return -1 if x < y else 1
    if len(ta) == len(tb): return 0
    return -1 if len(ta) < len(tb) else 1

class VersionRange:
    @staticmethod
    def compare(a: str, b: str) -> int:
        return compare_versions(a, b)

    @staticmethod
    def in_range(version: str, range_expr: str) -> bool:
        normalized = range_expr.replace(",", " ").strip()
        if not normalized: return False
        parts = [p for p in re.split(r"\s+", normalized) if p]
        for part in parts:
            if part.startswith(">=") and compare_versions(version, part[2:]) < 0: return False
            elif part.startswith("<=") and compare_versions(version, part[2:]) > 0: return False
            elif part.startswith(">") and compare_versions(version, part[1:]) <= 0: return False
            elif part.startswith("<") and compare_versions(version, part[1:]) >= 0: return False
            elif part.startswith("=") and compare_versions(version, part[1:]) != 0: return False
            elif not part.startswith((">", "<", "=")) and compare_versions(version, part) != 0: return False
        return True