from dataclasses import dataclass
from pathlib import Path
import re

@dataclass(frozen=True)
class FileContext:
    path: Path
    rel_path: str
    text: str
    code: str
    lines: tuple[str, ...]
    profile: str | None = None


def strip_comments_preserve_offsets(text: str) -> str:
    """Remove Kotlin // and /* */ comments while preserving newlines/offsets.
    String literals are intentionally retained; rule patterns must avoid treating arbitrary
    string-only examples as executable constructs where relevant.
    """
    out = list(text)
    i, n = 0, len(text)
    in_string = False
    triple = False
    escaped = False
    while i < n:
        if not in_string and text.startswith('//', i):
            j = text.find('\n', i)
            if j < 0: j = n
            for k in range(i, j): out[k] = ' '
            i = j
            continue
        if not in_string and text.startswith('/*', i):
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n': out[k] = ' '
            i = j
            continue
        if text.startswith('"""', i) and not in_string:
            in_string, triple = True, True
            i += 3
            continue
        if text[i] == '"' and not triple:
            if not escaped: in_string = not in_string
            escaped = False
            i += 1
            continue
        if triple and text.startswith('"""', i):
            in_string, triple = False, False
            i += 3
            continue
        if in_string and not triple:
            if text[i] == '\\' and not escaped: escaped = True
            else: escaped = False
        i += 1
    return ''.join(out)


def build_context(root: Path, file: Path, text: str) -> FileContext:
    rel = file.relative_to(root).as_posix()
    profile = None
    m = re.search(r'application-([\w-]+)\.(?:yml|yaml|properties)$', file.name)
    if m: profile = m.group(1).lower()
    return FileContext(file, rel, text, strip_comments_preserve_offsets(text), tuple(text.splitlines()), profile)
