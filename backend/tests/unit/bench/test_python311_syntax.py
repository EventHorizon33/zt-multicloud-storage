"""The project supports Python 3.11 (README), but the development machine runs 3.12, where a quote of the
same kind inside the braces of an f-string is legal (PEP 701). On 3.11 that is a SyntaxError that would
stop a module from loading. This test finds such f-strings in the repository's own Python files."""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SKIP = {".venv", "node_modules", ".emulators", "__pycache__", ".git", "data", "dist", "results"}
START = re.compile(r"(?<![A-Za-z0-9_])(?:[fF][rR]?|[rR][fF])([\"'])")


def needs_python_312(line: str) -> bool:
    """True if a single-line f-string has its own quote character, or a backslash, inside a replacement field."""
    i = 0
    while i < len(line):
        m = START.match(line, i)
        if not m:
            i += 1
            continue
        q = m.group(1)
        if line.startswith(q * 3, m.end() - 1):                           # triple-quoted: not checked
            i = m.end() + 2
            continue
        j, depth = m.end(), 0
        while j < len(line):
            c = line[j]
            if depth == 0:
                if c == "\\":
                    j += 2
                    continue
                if c == q:
                    break
                if c == "{":
                    if line.startswith("{{", j):
                        j += 2
                        continue
                    depth = 1
            else:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                elif c == q or c == "\\":
                    return True
            j += 1
        i = j + 1
    return False


def test_the_scanner_flags_the_bad_pattern_and_accepts_the_good_one():
    assert needs_python_312('print(f"at least {math.ceil(t["ingress"] / GIB)} GiB")')
    assert not needs_python_312("print(f\"at least {math.ceil(t['ingress'] / GIB)} GiB\")")
    assert not needs_python_312('x = f"literal {{braces}} and {a}"')
    assert not needs_python_312('x = f"{a:>10} {b!r}"')


def python_files():
    for top in ("backend/app", "backend/tests", "scripts", "analysis"):
        base = REPO / top
        if not base.exists():
            continue
        for p in base.rglob("*.py"):
            if p.name == Path(__file__).name:                             # this file quotes the bad pattern as test data
                continue
            if not SKIP.intersection(p.relative_to(REPO).parts):
                yield p


def test_no_python_312_only_fstring_anywhere_in_the_repository():
    offenders = []
    checked = 0
    for path in python_files():
        checked += 1
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if needs_python_312(line):
                offenders.append(f"{path.relative_to(REPO)}:{n}: {line.strip()[:90]}")
    assert checked > 100, f"scan looks wrong: only {checked} files"
    assert not offenders, "f-strings that need Python 3.12:\n" + "\n".join(offenders[:10])
