"""Conservative in-house Gradle/Maven version comparison and interval matching.

It handles common numeric versions and pre-release qualifiers; it does not
pretend to fully implement Maven's ComparableVersion semantics.
"""
from __future__ import annotations

import re

_QUALIFIER_RANK = {"snapshot": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "milestone": -2,
                   "m": -2, "rc": -1, "cr": -1, "final": 0, "ga": 0, "release": 0}


def _parse(version: str) -> tuple[list[int], tuple[int, int]]:
    version = version.strip().lower().removeprefix("v").split("+", 1)[0]
    m = re.match(r"^([\d.]+)(?:[-_.]?([a-z]+)[.\-]?(\d*))?$", version)
    if m:
        numbers = [int(n) for n in m.group(1).split(".") if n]
        while len(numbers) > 1 and numbers[-1] == 0:
            numbers.pop()
        tag = m.group(2) or ""
        rank = _QUALIFIER_RANK.get(tag, -1 if tag else 0)
        return numbers, (rank, int(m.group(3) or 0))
    # Fallback to numeric segments rather than treating a malformed version as current.
    segments = [int(n) for n in re.findall(r"\d+", version)]
    while len(segments) > 1 and segments[-1] == 0:
        segments.pop()
    return segments, (-1, 0) if re.search(r"[a-z]", version) else (0, 0)


def compare_versions(a: str, b: str) -> int:
    aa, aq = _parse(a)
    bb, bq = _parse(b)
    for i in range(max(len(aa), len(bb))):
        ai = aa[i] if i < len(aa) else 0
        bi = bb[i] if i < len(bb) else 0
        if ai != bi:
            return -1 if ai < bi else 1
    if aq == bq:
        return 0
    return -1 if aq < bq else 1


class VersionRange:
    @staticmethod
    def compare(a: str, b: str) -> int:
        return compare_versions(a, b)

    @staticmethod
    def in_range(version: str, range_expr: str) -> bool:
        normalized = range_expr.replace(",", " ").strip()
        if not normalized:
            return False
        parts = [p for p in re.split(r"\s+", normalized) if p]
        for part in parts:
            if part.startswith(">=") and compare_versions(version, part[2:]) < 0:
                return False
            if part.startswith("<=") and compare_versions(version, part[2:]) > 0:
                return False
            if part.startswith(">") and compare_versions(version, part[1:]) <= 0:
                return False
            if part.startswith("<") and compare_versions(version, part[1:]) >= 0:
                return False
            if part.startswith("=") and compare_versions(version, part[1:]) != 0:
                return False
            if not part.startswith((">", "<", "=")) and compare_versions(version, part) != 0:
                return False
        return True
