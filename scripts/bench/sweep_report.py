#!/usr/bin/env python3
"""Summarise a chunk-size sweep produced by bench.py.

Expects <dir>/<providers>-c<chunk MiB>/{small,gib}/run.json (providers = memory|emulators).
Prints, per provider mode and direction, a table of median MiB/s (rows: file size,
columns: chunk size) with the best chunk size per file size, then the same for
median wall time in ms and for the server's peak RSS.

  .venv/bin/python ../scripts/bench/sweep_report.py ../scripts/bench/results/sweep-20261124
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def load(d: Path) -> dict:
    """{(providers, chunk_mib): {size_mib: entry}}"""
    out: dict = {}
    for p in sorted(d.glob("*-c*/*/run.json")):
        m = re.match(r"(memory|emulators)-c(\d+(?:\.\d+)?)$", p.parent.parent.name)
        if not m:
            continue
        run = json.loads(p.read_text())
        for e in run["sizes"]:
            if "error" in e:
                out.setdefault((m[1], float(m[2])), {})[e["size_mib"]] = {"error": e["error"]}
            else:
                out.setdefault((m[1], float(m[2])), {})[e["size_mib"]] = e
    return out


def table(data: dict, mode: str, getter, fmt: str, best: str | None, title: str) -> str:
    chunks = sorted({c for (m, c) in data if m == mode})
    sizes = sorted({s for (m, c), v in data.items() if m == mode for s in v})
    if not chunks:
        return ""
    lines = [f"\n### {title}\n", "| File size \\ chunk | " + " | ".join(f"{c:g} MiB" for c in chunks) + " | best |",
             "|---:|" + "---:|" * (len(chunks) + 1)]
    for s in sizes:
        vals = []
        for c in chunks:
            e = data.get((mode, c), {}).get(s)
            if e is None:
                vals.append(None)
            elif "error" in e:
                vals.append("ERR")
            else:
                vals.append(getter(e))
        nums = [v for v in vals if isinstance(v, (int, float))]
        if nums and best:
            b = max(nums) if best == "max" else min(nums)
            bc = next(c for c, v in zip(chunks, vals) if v == b)
        cells = []
        for v in vals:
            if v is None:
                cells.append("-")
            elif isinstance(v, str):
                cells.append(v)
            else:
                txt = fmt.format(v)
                cells.append(f"**{txt}**" if best and nums and v == b else txt)
        lines.append(f"| {s:g} MiB | " + " | ".join(cells) + f" | {f'{bc:g} MiB' if best and nums else ''} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    d = Path(sys.argv[1])
    data = load(d)
    if not data:
        sys.exit(f"no run.json files under {d}")
    env = next(iter(json.loads(p.read_text())["env"] for p in d.glob("*-c*/*/run.json")), None)
    print("# Chunk-size sweep\n")
    if env:
        print(f"- Machine: {env['cpu']}, {env['logical_cpus']} logical CPUs, {env['mem_total_mib']} MiB RAM; "
              f"Python {env['python']}; commit {env['git_commit']}; {env['platform']}")
    print("- Transport: real uvicorn on loopback, fresh server per repeat after an untimed warm-up; 3 repeats "
          "(2 at 1 GiB); cells are medians; best per row in bold.")
    for mode in ("memory", "emulators"):
        if not any(m == mode for m, _ in data):
            continue
        print(f"\n## {mode} providers")
        print(table(data, mode, lambda e: e["upload_mib_s"]["median"], "{:.1f}", "max", "Upload throughput, MiB/s (higher is better)"))
        print(table(data, mode, lambda e: e["download_mib_s"]["median"], "{:.1f}", "max", "Download throughput, MiB/s (higher is better)"))
        print(table(data, mode, lambda e: e["upload_s"]["median"] * 1000, "{:.0f}", "min", "Upload wall time, ms (lower is better)"))
        print(table(data, mode, lambda e: e["download_s"]["median"] * 1000, "{:.0f}", "min", "Download wall time, ms (lower is better)"))
        print(table(data, mode, lambda e: e["server_peak_rss_mib"] or 0, "{:.0f}", None, "Server peak RSS, MiB"))
        print(table(data, mode, lambda e: e["upload_s"]["max"] / e["upload_s"]["min"], "{:.2f}", None,
                    "Upload run-to-run spread (max/min; near 1.00 is stable)"))


if __name__ == "__main__":
    main()
