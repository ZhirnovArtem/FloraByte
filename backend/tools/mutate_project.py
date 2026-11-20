"""Create mutated copies of training-project to detect overfitted scanners.

Usage:
  python -m tools.mutate_project --src /path/to/training-project --out /tmp/mutations --count 3
"""

from __future__ import annotations

import argparse
import random
import re
import shutil
import string
from pathlib import Path


def _rand_suffix(n: int = 4) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def mutate_identifiers(root: Path, rng: random.Random) -> list[str]:
    notes: list[str] = []
    kt_files = list(root.rglob("*.kt"))
    if not kt_files:
        return notes
    sample = kt_files[0].read_text(encoding="utf-8", errors="ignore")
    names = re.findall(r"\b([a-z][a-zA-Z0-9]{3,})\b", sample)
    stop = {"return", "class", "fun", "val", "var", "when", "else", "true", "false", "null", "this", "super", "import", "package"}
    names = [n for n in names if n not in stop]
    if not names:
        return notes
    old = rng.choice(names)
    new = old + _rand_suffix(3)
    for f in kt_files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        if old in text:
            f.write_text(text.replace(old, new), encoding="utf-8")
            notes.append(f"rename {old} -> {new} in {f.relative_to(root)}")
    return notes


def mutate_string_literals(root: Path, rng: random.Random) -> list[str]:
    notes: list[str] = []
    for f in root.rglob("*.kt"):
        text = f.read_text(encoding="utf-8", errors="ignore")

        def repl(m: re.Match) -> str:
            inner = m.group(1)
            if len(inner) < 6 or rng.random() > 0.4:
                return m.group(0)
            flipped = inner[:-2] + _rand_suffix(2)
            notes.append(f"literal in {f.name}")
            return f'"{flipped}"'

        new_text = re.sub(r'"([^"\\]{6,})"', repl, text)
        if new_text != text:
            f.write_text(new_text, encoding="utf-8")
    return notes


def mutate_gradle_layout(root: Path, style: str) -> list[str]:
    notes: list[str] = []
    gradle = root / "build.gradle.kts"
    if not gradle.exists():
        return notes
    text = gradle.read_text(encoding="utf-8")
    pattern = re.compile(r'"([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([0-9][0-9A-Za-z.+-]*)"')
    matches = list(pattern.finditer(text))
    if not matches:
        return notes
    m = matches[0]
    g, a, v = m.group(1), m.group(2), m.group(3)
    key = re.sub(r"[^a-zA-Z0-9]", "", a) + "Version"
    old = f'"{g}:{a}:{v}"'

    if style == "val":
        text = f'val {key} = "{v}"\n' + text
        text = text.replace(old, '"%s:%s:${%s}"' % (g, a, key), 1)
        gradle.write_text(text, encoding="utf-8")
        notes.append(f"gradle style=val for {g}:{a}")
    elif style == "properties":
        props = root / "gradle.properties"
        existing = props.read_text(encoding="utf-8") if props.exists() else ""
        props.write_text(existing + f"\n{key}={v}\n", encoding="utf-8")
        text = text.replace(old, '"%s:%s:${%s}"' % (g, a, key), 1)
        gradle.write_text(text, encoding="utf-8")
        notes.append(f"gradle style=properties for {g}:{a}")
    elif style == "multiline":
        text = text.replace(old, '"""\n    %s:%s:%s\n"""' % (g, a, v), 1)
        gradle.write_text(text, encoding="utf-8")
        notes.append(f"gradle style=multiline for {g}:{a}")
    return notes


def mutate_once(src: Path, dst: Path, seed: int) -> list[str]:
    rng = random.Random(seed)
    copy_tree(src, dst)
    notes: list[str] = [f"seed={seed}"]
    notes += mutate_identifiers(dst, rng)
    notes += mutate_string_literals(dst, rng)
    style = rng.choice(["val", "properties", "multiline", "none"])
    if style != "none":
        notes += mutate_gradle_layout(dst, style)
    return notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    for i in range(args.count):
        dest = args.out / f"mut_{i}"
        notes = mutate_once(args.src, dest, seed=args.seed + i)
        (dest / "MUTATION_NOTES.txt").write_text("\n".join(notes), encoding="utf-8")
        print(f"Wrote {dest}: {notes[:3]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
