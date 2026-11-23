#!/usr/bin/env python3
"""Turn the evidence JSON written by the security test suite
(``ZT_SECURITY_EVIDENCE=<file> pytest tests/security``) into a readable
table: scenario -> attempt -> mechanism -> observed result -> observed audit
event -> pytest outcome.

    report.py evidence.json              plain-text table (terminal)
    report.py evidence.json --markdown   GitHub-flavoured markdown table

Every cell comes from what the tests OBSERVED at run time (status codes,
error codes, audit records), not from static descriptions."""
from __future__ import annotations

import json
import shutil
import sys
import textwrap

ORDER = ["S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12", "S13", "S14",
         "S15", "S16", "S17", "E01", "E02", "E03", "E04", "E05", "E06", "E07"]
LABEL = {"passed": "PASS", "failed": "FAIL", "xfailed": "XFAIL (known finding)", "xpassed": "XPASS",
         "skipped": "SKIP", "error": "ERROR"}


def load(path: str) -> list[dict]:
    rows = json.loads(open(path, encoding="utf-8").read())
    for r in rows:
        if not r.get("scenario"):
            # xfail finding tests do not record evidence: describe them from the test name
            name = r["test"].split("::")[-1]
            r["scenario"] = name.split("_")[1].upper() if name.startswith("test_") else "?"
            r["attempt"] = name.replace("test_", "", 1).replace("_", " ")
            reason = r.get("xfail_reason", "")
            r["mechanism"] = ("KNOWN FINDING - " + reason[:220] + ("..." if len(reason) > 220 else "")) \
                if reason else "(see pytest -rx output)"
            r.setdefault("result", [])
            r.setdefault("audit", [])
    key = {s: i for i, s in enumerate(ORDER)}
    rows.sort(key=lambda r: (key.get(r["scenario"], 99), r["test"]))
    return rows


def cells(r: dict) -> list[str]:
    return [r["scenario"], r["attempt"], r["mechanism"], "; ".join(r.get("result") or []) or "-",
            "; ".join(r.get("audit") or []) or "-", LABEL.get(r["outcome"], r["outcome"])]


HEAD = ["#", "Attempt", "Mechanism", "Observed result", "Audit record", "Outcome"]


def text_table(rows: list[dict]) -> str:
    width = max(120, shutil.get_terminal_size((160, 40)).columns)
    widths = [4, 0, 0, 0, 0, 10]
    rest = width - sum(widths) - 3 * len(widths)
    widths[1], widths[2], widths[3], widths[4] = (int(rest * f) for f in (0.24, 0.24, 0.27, 0.25))
    sep = "+".join("-" * (w + 2) for w in widths)
    out = [sep, " | ".join(h.ljust(w) for h, w in zip(HEAD, widths)), sep]
    for r in rows:
        wrapped = [textwrap.wrap(c, w) or [""] for c, w in zip(cells(r), widths)]
        for i in range(max(len(x) for x in wrapped)):
            out.append(" | ".join((x[i] if i < len(x) else "").ljust(w) for x, w in zip(wrapped, widths)))
        out.append(sep)
    return "\n".join(out)


def md_table(rows: list[dict]) -> str:
    esc = lambda s: s.replace("|", "\\|").replace("\n", " ")  # noqa: E731
    out = ["| " + " | ".join(HEAD + ["Test"]) + " |", "|" + "---|" * (len(HEAD) + 1)]
    for r in rows:
        test = r["test"].split("tests/security/", 1)[-1]
        out.append("| " + " | ".join(esc(c) for c in cells(r)) + f" | `{esc(test)}` |")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    rows = load(argv[0])
    if "--markdown" in argv:
        print(md_table(rows))
        return 0
    print(text_table(rows))
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    print("Totals: " + ", ".join(f"{LABEL.get(k, k)}={v}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
