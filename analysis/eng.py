#!/usr/bin/env python3
"""Engineering metrics (experiment i): lines of code, tests per category and module, coverage, security-findings history.

  backend/.venv/bin/python analysis/eng.py               # loc, tests, findings (fast)
  backend/.venv/bin/python analysis/eng.py --coverage    # also run the whole suite under pytest-cov (needs the emulators)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import DATA, REPO  # noqa: E402

PY = REPO / "backend" / ".venv" / "bin" / "python"


def count_lines(p: Path) -> tuple[int, int, int]:
    total = blank = comment = 0
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        total += 1
        s = line.strip()
        if not s:
            blank += 1
        elif s.startswith(("#", "//", "/*", "*")):
            comment += 1
    return total, blank, comment


def loc() -> pd.DataFrame:
    rows = []
    skip = {"__pycache__", "node_modules", ".venv", ".emulators", "dist", "results", "data", "figures"}

    def add(area: str, base: Path, patterns, module_depth: int = 1):
        for pat in patterns:
            for p in sorted(base.rglob(pat)):
                rel = p.relative_to(base)
                if skip.intersection(rel.parts):
                    continue
                t, b, c = count_lines(p)
                module = rel.parts[0] if len(rel.parts) > module_depth else "(top level)"
                rows.append(dict(area=area, module=module, file=str(rel).replace("\\", "/"), total=t, blank=b, comment=c, code=t - b - c))

    add("backend/app", REPO / "backend" / "app", ["*.py"])
    add("backend/tests", REPO / "backend" / "tests", ["*.py"])
    add("frontend/src", REPO / "frontend" / "src", ["*.ts", "*.tsx", "*.css"])
    add("scripts", REPO / "scripts", ["*.py", "*.sh"])
    add("analysis", REPO / "analysis", ["*.py", "*.sh"])
    return pd.DataFrame(rows)


def tests_table() -> pd.DataFrame:
    out = subprocess.run([str(PY), "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"], cwd=REPO / "backend",
                         capture_output=True, text=True).stdout
    counts: dict = {}
    for line in out.splitlines():
        if line.startswith("tests/") and "::" in line:
            parts = line.split("::")[0].split("/")
            cat = parts[1]
            module = parts[2] if len(parts) > 3 else Path(parts[-1]).stem
            counts[(cat, module)] = counts.get((cat, module), 0) + 1
    assert counts, "no tests collected"
    return pd.DataFrame([dict(category=c, module=m, tests=n) for (c, m), n in sorted(counts.items())])


def findings() -> pd.DataFrame:
    text = (REPO / "docs" / "SECURITY_TESTING.md").read_text(encoding="utf-8")
    rows = []
    for m in re.finditer(r"^\| (F\d) \| (.+?) \| (high|medium-high|medium|low-medium|low) \| \*\*fixed\*\*", text, re.M):
        rows.append(dict(id=m[1], source="own testing (Phase 8)", severity=m[3], status="fixed", title=m[2][:70]))
    sec4a = text.split("## 4a. Independent security review", 1)[1].split("## 5.", 1)[0]
    for m in re.finditer(r"^\| ([HMLI]\d) \| (high|medium|low|informational|info) \| (.+?) \|", sec4a, re.M):
        rows.append(dict(id=m[1], source="independent review", severity="info" if m[2] == "informational" else m[2], status="fixed", title=m[3][:70]))
    assert rows, "no findings parsed"
    return pd.DataFrame(rows)


def coverage() -> None:
    out = DATA / "coverage.json"
    cp = subprocess.run([str(PY), "-m", "pytest", "--cov=app", f"--cov-report=json:{out}", "-q", "-rs", "-p", "no:cacheprovider"],
                        cwd=REPO / "backend", capture_output=True, text=True)
    (DATA / "coverage_run.txt").write_text(cp.stdout[-4000:] + cp.stderr[-1000:], encoding="utf-8")
    tail = [l for l in cp.stdout.splitlines() if re.search(r"\d+ passed", l)]
    print("[eng] coverage run:", tail[-1] if tail else "NO RESULT LINE", flush=True)
    cov = json.loads(out.read_text())
    rows = []
    for path, d in cov["files"].items():
        parts = Path(path).parts
        rel = parts[parts.index("app") + 1:] if "app" in parts else parts
        module = rel[0] if len(rel) > 1 else "(top level)"
        s = d["summary"]
        rows.append(dict(module=module, file="/".join(rel), statements=s["num_statements"], covered=s["covered_lines"], missing=s["missing_lines"]))
    pd.DataFrame(rows).to_csv(DATA / "coverage_files.csv", index=False)
    print(f"[eng] total coverage {cov['totals']['percent_covered']:.2f}% of {cov['totals']['num_statements']} statements", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--coverage", action="store_true")
    a = ap.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    loc().to_csv(DATA / "i_loc.csv", index=False)
    tests_table().to_csv(DATA / "i_tests.csv", index=False)
    f = findings()
    f.to_csv(DATA / "i_findings.csv", index=False)
    print(f"[eng] loc, tests and findings written ({len(f)} findings)", flush=True)
    if a.coverage:
        coverage()


if __name__ == "__main__":
    main()
