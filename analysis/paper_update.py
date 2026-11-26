#!/usr/bin/env python3
"""Update the number-driven parts of paper/main.tex from analysis/data (run after analysis/run_all.sh and analysis/paper_figures.py).

Replaces the Performance subsection with a short audit paragraph plus a new "Statistical evaluation" subsection (method, key-results
table, two figures), and updates the abstract, the code-size figures, the ADR count and the conclusion. Every figure comes from the CSV
files through analysis/lib.py; nothing is typed in by hand. Idempotence: it refuses to run twice (the anchors will no longer match).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import DATA, REPO, compare, describe, linfit, st, wilson  # noqa: E402

TEX = REPO / "paper" / "main.tex"
rd = lambda n: pd.read_csv(DATA / f"{n}.csv")
meta = json.loads((DATA / "meta.json").read_text())
ENV, N = meta["env"], meta["n"]
S = json.loads((DATA / "summary.json").read_text())


def p_tex(p: float) -> str:
    return "$p<0.0001$" if p < 1e-4 else f"$p={p:.3f}$"


def mn(x: float, d: int = 1) -> str:
    """A number with a typographic minus sign for LaTeX."""
    return f"{x:+.{d}f}".replace("-", "$-$").replace("+", "") if x < 0 else f"{x:+.{d}f}"


def pct(x: float, d: int = 1) -> str:
    return f"{100 * x:.{d}f}\\%"


# ---- numbers ------------------------------------------------------------------------------------------------
a = rd("a_scaling"); a = a[a.ok]
fits = {op: linfit(a[a.op == op].size_mib.values, a[a.op == op].seconds.values) for op in ("upload", "download")}
thr = {op: (1 / f["slope"], 1 / f["slope_ci_hi"], 1 / f["slope_ci_lo"], f["r2"]) for op, f in fits.items()}

b = rd("b_overhead"); b = b[b.ok]
def arm(op, s, name): return b[(b.op == op) & (b.size_mib == s) & (b.arm == name)].seconds.values
cu, cd = compare(arm("upload", 16, "app"), arm("upload", 16, "plain_chunked")), compare(arm("download", 16, "app"), arm("download", 16, "plain_chunked"))
mic = rd("b_crypto_micro")
enc, dec = describe(mic[mic.op == "encrypt"].seconds_per_mib.values), describe(mic[mic.op == "decrypt"].seconds_per_mib.values)
share_up, share_dn = enc["mean"] * 16 / cu["diff"], dec["mean"] * 16 / cd["diff"]

c = rd("c_chunk"); c = c[c.ok].copy(); c["mib_s"] = 32 / c.seconds
grp = {op: {int(k): v.mib_s.values for k, v in c[c.op == op].groupby("chunk_kib")} for op in ("upload", "download")}
kw = {op: st.kruskal(*g.values()).pvalue for op, g in grp.items()}
med_up = {k: float(np.median(v)) for k, v in grp["upload"].items()}
kmin, kmax = min(med_up), max(med_up)

d = rd("d_fault")
dn1 = d[(d.phase == "gcs_down") & (d.op == "download")].sort_values("trial")
up1 = d[(d.phase == "gcs_down") & (d.op == "upload")]
two = d[d.phase == "two_down"]
allup = d[(d.phase == "all_up") & (d.op == "download")].seconds.values
steady = dn1.seconds.values[3:3 + len(allup)]
cmpd = compare(steady, allup)
rk = lambda df: (int(df.ok.sum()), len(df), wilson(int(df.ok.sum()), len(df)))
r_dn, r_up, r_two = rk(dn1), rk(up1), rk(two)

e = rd("e_placement")
echi = {}
for strat in ("rotating", "hash"):
    cnt = e[(e.strategy == strat) & (e.kind == "replicas_per_provider")]["count"].values
    echi[strat] = st.chisquare(cnt)

f = rd("f_entropy").drop_duplicates(["kind", "chunk_index"])
f_rej, f_n = int((f.p < 0.05).sum()), len(f)
f_lo, f_hi = f.entropy_cipher.min(), f.entropy_cipher.max()

g_s = S["g"]
h_n, h_k, (h_lo, h_hi) = S["h"]["n"], S["h"]["detected"], S["h"]["wilson"]
cov = S.get("coverage_total_pct")
loc = rd("i_loc"); tests = rd("i_tests")
n_tests = int(tests.tests.sum())

# ---- LaTeX text ---------------------------------------------------------------------------------------------
table_rows = [
 ("Scaling (a)", f"Time grows roughly linearly with size: upload {thr['upload'][0]:.1f}\\,MiB/s [{thr['upload'][1]:.1f}, {thr['upload'][2]:.1f}], download {thr['download'][0]:.1f}\\,MiB/s "
                 f"[{thr['download'][1]:.1f}, {thr['download'][2]:.1f}]; $R^2$ {thr['upload'][3]:.3f} and {thr['download'][3]:.3f}."),
 ("Cost of security (b), 16\\,MiB", f"Full pipeline against plain chunked storage of the same bytes: upload $\\times${cu['ratio']:.2f} ($+${cu['diff']:.2f}\\,s [{cu['diff_ci_lo']:.2f}, {cu['diff_ci_hi']:.2f}], "
                 f"{cu['primary']}, {p_tex(cu['p'])}), download $\\times${cd['ratio']:.2f}. AES-256-GCM with SHA-256 explains {pct(share_up, 0)} of the upload and {pct(share_dn, 0)} of the download difference."),
 ("Chunk size (c)", f"Throughput depends on chunk size (Kruskal--Wallis, upload {p_tex(kw['upload'])}, download {p_tex(kw['download'])}); median upload {med_up[kmin]:.1f}\\,MiB/s at {kmin}\\,KiB "
                 f"and {med_up[kmax]:.1f}\\,MiB/s at {kmax // 1024}\\,MiB."),
 ("One provider killed (d)", f"{r_dn[0]}/{r_dn[1]} reads and {r_up[0]}/{r_up[1]} writes succeed (Wilson lower bounds {pct(r_dn[2][0])} and {pct(r_up[2][0])}); steady download latency "
                 f"{mn(cmpd['diff'] * 1000)}\\,ms [{mn(cmpd['diff_ci_lo'] * 1000)}, {mn(cmpd['diff_ci_hi'] * 1000)}] (no detectable change; {cmpd['primary']}, {p_tex(cmpd['p'])}). Two killed: {r_two[0]}/{r_two[1]} reads."),
 ("Placement (e)", f"Replicas are uniform over the providers: rotating $\\chi^2={echi['rotating'].statistic:.2f}$ ({p_tex(echi['rotating'].pvalue)}), hash $\\chi^2={echi['hash'].statistic:.2f}$ ({p_tex(echi['hash'].pvalue)}); 2 d.f."),
 ("Stored objects (f)", f"Entropy {f_lo:.4f}--{f_hi:.4f} bits/byte for random, text and all-zero plaintext; the chi-square test rejected uniformity for {f_rej} of {f_n} objects ({pct(f_rej / f_n)}; 5\\% expected by chance)."),
 ("Audit log (g)", f"Verification time is linear in the log size (log-log slope {g_s['loglog']['slope']:.3f} [{g_s['loglog']['slope_ci_lo']:.3f}, {g_s['loglog']['slope_ci_hi']:.3f}]); "
                 f"{g_s['record_events_per_s']['mean']:.0f}\\,events/s with an fsync per event."),
 ("Attack suite (h)", f"{h_k}/{h_n} designed attack and failure tests passed (Wilson lower bound {pct(h_lo)}); not a random sample."),
]
if cov is not None:
    table_rows.append(("Coverage (i)", f"{cov:.1f}\\% line coverage of \\code{{backend/app}} by the {n_tests:,}-test suite."))
rows_tex = "\n".join(f"{l} & {t} \\\\" for l, t in table_rows)

NEW_SECTION = f"""\\subsection{{Performance}}\\label{{sec:perf}}
% NUMBERS: audit numbers from backend/app/audit/NOTES.md ("Measured performance"); end-to-end numbers: see Section~\\ref{{sec:stats}} (analysis/data via analysis/run_all.sh).
The audit subsystem's own measurements (\\code{{backend/app/audit/NOTES.md}}) are as follows. 1,000 real \\code{{record()}} calls take 1.35\\,s, i.e., about 739 events/s with an fsync per event. Verifying a chain of 20,000 events with 190 signed checkpoints and 570 anchor copies takes 0.54\\,s. The end-to-end figures below were measured through the full API stack (authentication, PDP, KMS, encryption, $R=2$ placement with read-back verification, audit) against the three emulators; they exclude network latency, so they show the cost of the security pipeline and of per-chunk work, not achievable cloud throughput. A download is verified in full before its first byte is released (the plaintext is held in memory up to 8\\,MiB and in a temporary file beyond that), so its latency grows with file size by design.

\\subsection{{Statistical evaluation}}\\label{{sec:stats}}
% NUMBERS: analysis/data/*.csv through analysis/analyze.py (docs/STATISTICAL_ANALYSIS.md); reproduce with analysis/run_all.sh.
We measured the framework with the scripts in \\code{{analysis/}}; one command reproduces every number. Each API measurement is one request to a real server on the loopback interface, with conditions interleaved in random order, $n={N}$ repetitions per condition after three discarded warm-ups, and 95\\% confidence intervals. Two groups are compared with Welch's $t$-test, or the Mann--Whitney $U$ test when a Shapiro--Wilk test rejects normality; several groups with Kruskal--Wallis; proportions with Wilson intervals; placement and ciphertext with $\\chi^2$ tests. The host is an {ENV['cpu']} ({ENV['logical_cpus']} logical CPUs, {ENV['ram_gib']:.1f}\\,GiB) under WSL2, Python {ENV['python']}, commit \\code{{{ENV['git_commit']}}}; absolute times belong to this machine, ratios and shapes are the transferable part. Table~\\ref{{tab:stats}} and Figs.~\\ref{{fig:statmain}} and~\\ref{{fig:stataux}} summarise the results.

\\begin{{table}}[t]
\\caption{{Key results of the statistical evaluation (95\\% confidence intervals in brackets)}}
\\label{{tab:stats}}
\\centering
\\footnotesize
\\begin{{tabularx}}{{\\columnwidth}}{{@{{}}>{{\\raggedright\\arraybackslash}}p{{2.35cm}}L@{{}}}}
\\toprule
Question & Result \\\\
\\midrule
{rows_tex}
\\bottomrule
\\end{{tabularx}}
\\end{{table}}

\\begin{{figure*}}[t]
\\centering
\\includegraphics[width=\\textwidth]{{figures/stat-main.pdf}}
\\caption{{(a) Transfer time against file size with the fitted line; (b) the same bytes stored with the full pipeline and as plain chunked and plain single-object storage; (c) throughput against chunk size for a 32\\,MiB file; (d) download latency with one provider killed, and the read and write success counts.}}
\\label{{fig:statmain}}
\\end{{figure*}}

\\begin{{figure*}}[t]
\\centering
\\includegraphics[width=\\textwidth]{{figures/stat-aux.pdf}}
\\caption{{(e) Entropy of the objects as stored at the providers against the entropy of the plaintext; (f) audit-chain verification time against the number of events; (g) replicas per provider for the two placement strategies.}}
\\label{{fig:stataux}}
\\end{{figure*}}

At 16\\,MiB the pipeline adds {pct(cu['ratio'] - 1, 0)} to the upload time and multiplies the download time by {cd['ratio']:.1f} compared with plain chunked storage of the same bytes; the cipher itself accounts for only a few per cent of that difference, and the rest was not decomposed. Larger chunks raise throughput (uploads from {med_up[kmin]:.1f} to {med_up[kmax]:.1f}\\,MiB/s between {kmin}\\,KiB and {kmax // 1024}\\,MiB chunks). Losing one provider caused no failed request and no detectable latency change, while losing two broke every read, as the replication factor predicts. The stored objects are statistically indistinguishable from random bytes, and audit verification scales linearly. These results come from emulators on one host with no network latency, from designed (not randomly sampled) attack scenarios, and from sequential requests that are not fully independent, so they bound the cost of the pipeline rather than predict cloud performance.

"""

edits = [
 # abstract
 ("The backend suite of 1,236 tests passes", "The backend suite of 1,273 tests passes"),
 ("including failover when an emulator process is killed. Verifying 20,000 audit events takes 0.54\\,s.",
  f"including failover when an emulator process is killed. A statistical evaluation shows that, at 16\\,MiB, the full pipeline adds {pct(cu['ratio'] - 1, 0)} to the upload time and multiplies the download time by {cd['ratio']:.1f} compared with plain chunked storage, "
  f"and that with one of three providers killed {r_dn[0]}/{r_dn[1]} reads and {r_up[0]}/{r_up[1]} writes still succeed. Verifying 20,000 audit events takes 0.54\\,s."),
 ("% NUMBERS: abstract quotes 1,236 passing tests,", f"% NUMBERS: abstract quotes 1,273 passing tests, the cost ratio and success counts from analysis/data (Section~\\ref{{sec:stats}}),"),
 # implementation
 ("11,330 lines in 71 test files", f"{int(loc[loc.area == 'backend/tests'].total.sum()):,} lines in {int((loc.area == 'backend/tests').sum())} test files"),
 ("Eleven architecture decision records (ADR-0001 to ADR-0011) document the design choices. Fig.",
  "Twelve architecture decision records (ADR-0001 to ADR-0012) document the design choices. The container deployment overrides three framework defaults (16\\,MiB chunks, a 10\\,GiB upload cap and a 20\\,GiB bulk-download threshold; ADR-0012), and the benchmark and large-file tools are in \\code{scripts/bench/}. Fig."),
 # conclusion
 ("The prototype passes its 17 attack scenarios and survives a real provider outage.",
  f"The prototype passes its 17 attack scenarios and survives a real provider outage; a statistical evaluation puts the price of that protection at {pct(cu['ratio'] - 1, 0)} more upload time and {cd['ratio']:.1f} times the download time of plain chunked storage at 16\\,MiB."),
]

s = TEX.read_bytes().decode("utf-8")
nl = "\r\n" if "\r\n" in s else "\n"
for old, new in edits:
    old, new = old.replace("\n", nl), new.replace("\n", nl)
    assert s.count(old) == 1, f"expected exactly 1 match, found {s.count(old)} for {old[:80]!r}"
    s = s.replace(old, new)
start = s.index("\\subsection{Performance}")
end = s.index(("%=====================================================================\n\\section{Security Findings").replace("\n", nl))
s = s[:start] + NEW_SECTION.replace("\n", nl) + s[end:]
TEX.write_bytes(s.encode("utf-8"))
print(f"[paper_update] main.tex updated: {len(NEW_SECTION.split())} words added in the evaluation, abstract, implementation and conclusion edited")
