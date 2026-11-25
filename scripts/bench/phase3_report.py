#!/usr/bin/env python3
"""Summarise the interleaved before/after run (1 MiB vs 16 MiB chunks).

Expects <dir>/r<round>-<providers>-c<chunk>/run.json (one repeat per size per round, the
two chunk sizes alternating order from round to round) and optionally <dir>/crypto/crypto.json.

Speed-ups are PAIRED: for each round, time(1 MiB) / time(16 MiB) from the same round, so a
machine that is slow or fast for a while affects both arms alike. Cells show
median [min-max] over rounds.

  .venv/bin/python ../scripts/bench/phase3_report.py ../scripts/bench/results/phase3-20261125
"""
from __future__ import annotations

import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def rng(xs, scale=1.0, fmt="{:.0f}"):
    xs = sorted(xs)
    return f"{fmt.format(statistics.median(xs) * scale)} [{fmt.format(xs[0] * scale)}-{fmt.format(xs[-1] * scale)}]"


def main() -> None:
    d = Path(sys.argv[1])
    # data[(prov, size)][chunk][round] = (up_s, down_s, rss, verified)
    data = defaultdict(lambda: defaultdict(dict))
    env = None
    for p in sorted(d.glob("r*-*-c*/run.json")):
        m = re.match(r"r(\d+)-(memory|emulators)-c(\d+)$", p.parent.name)
        if not m:
            continue
        r, prov, c = int(m[1]), m[2], int(m[3])
        run = json.loads(p.read_text())
        env = env or run["env"]
        for e in run["sizes"]:
            if "error" in e:
                print(f"WARNING: round {r} {prov} c{c} {e['size_mib']:g} MiB: {e['error']}", file=sys.stderr)
                continue
            rep = e["repeats"][0]
            data[(prov, e["size_mib"])][c][r] = (rep["upload_s"], rep["download_s"], rep["server_peak_rss_mib"], rep["verified"])
    if not data:
        sys.exit(f"no results under {d}")

    rounds = sorted({r for v in data.values() for c in v.values() for r in c})
    print("# Before / after: 1 MiB (framework default) vs 16 MiB (deployment setting) chunks\n")
    if env:
        print(f"- Machine: {env['cpu']}, {env['logical_cpus']} logical CPUs, {env['mem_total_mib']} MiB RAM; Python "
              f"{env['python']}; commit {env['git_commit']}{' (backend/app modified)' if env['git_dirty'] else ''}; {env['platform']}")
    print(f"- Method: real uvicorn server on loopback, fresh server per measurement after an untimed 1 MiB warm-up; "
          f"{len(rounds)} rounds, each round measures both chunk sizes back to back, alternating which goes first. "
          f"Cells are median [min-max] over rounds; speed-up = same-round time(1 MiB) / time(16 MiB).")
    bad = [(k, c, r) for k, v in data.items() for c, rr in v.items() for r, t in rr.items() if not t[3]]
    print(f"- Integrity: every measured transfer was verified byte-for-byte against the source"
          f"{'' if not bad else '; FAILURES: ' + str(bad)}.\n")

    for prov in ("memory", "emulators"):
        sizes = sorted(s for (p, s) in data if p == prov)
        if not sizes:
            continue
        print(f"## {prov} providers\n")
        print("| File | Upload, 1 MiB chunks (ms) | Upload, 16 MiB chunks (ms) | Upload speed-up | "
              "Download, 1 MiB (ms) | Download, 16 MiB (ms) | Download speed-up |")
        print("|---:|---:|---:|---:|---:|---:|---:|")
        for s in sizes:
            v = data[(prov, s)]
            common = sorted(set(v.get(1, {})) & set(v.get(16, {})))
            if not common:
                continue
            up1 = [v[1][r][0] for r in common]; up16 = [v[16][r][0] for r in common]
            dn1 = [v[1][r][1] for r in common]; dn16 = [v[16][r][1] for r in common]
            sp_up = [a / b for a, b in zip(up1, up16)]
            sp_dn = [a / b for a, b in zip(dn1, dn16)]
            print(f"| {s:g} MiB | {rng(up1, 1000)} | {rng(up16, 1000)} | **{rng(sp_up, 1, '{:.2f}')}x** | "
                  f"{rng(dn1, 1000)} | {rng(dn16, 1000)} | **{rng(sp_dn, 1, '{:.2f}')}x** |")
        print("\nServer peak RSS (MiB, max over rounds) and throughput at 16 MiB chunks:\n")
        print("| File | RSS 1 MiB | RSS 16 MiB | Upload MiB/s, 16 MiB | Download MiB/s, 16 MiB |")
        print("|---:|---:|---:|---:|---:|")
        for s in sizes:
            v = data[(prov, s)]
            r1 = max((t[2] or 0) for t in v.get(1, {}).values()) if v.get(1) else 0
            r16 = max((t[2] or 0) for t in v.get(16, {}).values()) if v.get(16) else 0
            u = [s / t[0] for t in v.get(16, {}).values()]
            dn = [s / t[1] for t in v.get(16, {}).values()]
            print(f"| {s:g} MiB | {r1:.0f} | {r16:.0f} | {rng(u, 1, '{:.1f}') if u else '-'} | {rng(dn, 1, '{:.1f}') if dn else '-'} |")
        # drift control: the same 1 MiB configuration, 100 MiB upload, by round
        ref = data.get((prov, 100.0), {}).get(1, {})
        if ref:
            print(f"\nDrift check, 100 MiB upload at 1 MiB chunks by round (ms): "
                  + ", ".join(f"r{r}={ref[r][0]*1000:.0f}" for r in sorted(ref)) + "\n")

    cj = d / "crypto" / "crypto.json"
    if cj.exists():
        cr = json.loads(cj.read_text())
        print("## Where the cipher sits in the total (same session)\n")
        print("Cipher-only throughput (single thread, 1 MiB chunks, no I/O) next to measured end-to-end time at 16 MiB chunks, in-memory providers.\n")
        print("| File | Encrypt MiB/s | Decrypt MiB/s | Encrypt share of upload | Decrypt share of download |")
        print("|---:|---:|---:|---:|---:|")
        for e in cr["sizes"]:
            s = e["size_mib"]
            v = data.get(("memory", s), {}).get(16, {})
            if not v:
                continue
            up = statistics.median(t[0] for t in v.values()); dn = statistics.median(t[1] for t in v.values())
            enc = e["encrypt_mib_s"]["median"]; dec = e["decrypt_mib_s"]["median"]
            print(f"| {s:g} MiB | {enc:.0f} | {dec:.0f} | {100 * (s / enc) / up:.0f}% | {100 * (s / dec) / dn:.0f}% |")
        print()


if __name__ == "__main__":
    main()
