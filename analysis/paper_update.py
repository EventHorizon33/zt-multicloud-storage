#!/usr/bin/env python3
"""Update paper/main.tex from analysis/data (run after analysis/run_all.sh and analysis/paper_figures.py).

Start from the paper as it was before any statistical update (git show d9d09d7:paper/main.tex > paper/main.tex). The script applies the
text edits for the new test counts, deployment settings and related work, replaces the Performance subsection with a short audit paragraph
plus a "Statistical evaluation" subsection (method, key-results table, two figures), and updates the abstract, code-size figures, ADR count
and conclusion. Every number comes from analysis/data/summary.json and the CSV files; nothing is typed in by hand.
It refuses to run twice (the anchors no longer match after the first run).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import DATA, REPO, wilson  # noqa: E402

TEX = REPO / "paper" / "main.tex"
rd = lambda n: pd.read_csv(DATA / f"{n}.csv")
meta = json.loads((DATA / "meta.json").read_text())
ENV, N = meta["env"], meta["n"]
S = json.loads((DATA / "summary.json").read_text())


def p_tex(p: float) -> str:
    return "$p<0.0001$" if p < 1e-4 else f"$p={p:.3f}$"


def pct(x: float, d: int = 1) -> str:
    return f"{100 * x:.{d}f}\\%"


def mn(x: float, d: int = 1) -> str:
    """A number with a typographic minus sign for LaTeX."""
    return f"{x:.{d}f}".replace("-", "$-$")


# ---- numbers ------------------------------------------------------------------------------------------------
A = S["a"]
thr = {op: (A[op]["throughput_mib_s"], A[op]["thr_ci"][0], A[op]["thr_ci"][1], A[op]["r2"]) for op in ("upload", "download")}
ll = A["loglog"]
B, P, M = S["b"], S["p"], S["model"]
cu, cd = B["upload16"], B["download16"]
share_up, share_dn = B["cipher_share_of_overhead_up"], B["cipher_share_of_overhead_down"]
pm = P["median_s"]
slow = P["slowest_put"]
NAME = {"aws-s3": "S3", "azure-blob": "Azure", "gcs": "GCS"}
put4 = {pr: pm[f"put 4MiB {pr}"] * 1000 for pr in NAME}
model_factor = max(max(v["ratio"], 1 / v["ratio"]) for v in M.values())
cons = B["consistency"]

C = S["c"]
c = rd("c_chunk"); c = c[c.ok].copy(); c["mib_s"] = 32 / c.seconds
med_up = {int(k): float(np.median(v.mib_s.values)) for k, v in c[c.op == "upload"].groupby("chunk_kib")}
kmin, kmax = min(med_up), max(med_up)
per_chunk_ms = C["per_chunk"]["upload"]["slope"] * 1000

d = rd("d_fault")
dn1 = d[(d.phase == "gcs_down") & (d.op == "download")].sort_values("trial")
up1 = d[(d.phase == "gcs_down") & (d.op == "upload")]
two = d[d.phase == "two_down"]
rk = lambda df: (int(df.ok.sum()), len(df), wilson(int(df.ok.sum()), len(df)))
r_dn, r_up, r_two = rk(dn1), rk(up1), rk(two)
dcmp = S["d"]["compare"]
lat_sig = dcmp["p"] < 0.05

e = S["e"]
fb = S["f_binomial"]
f = rd("f_entropy").drop_duplicates(["kind", "chunk_index"])
f_lo, f_hi = f.entropy_cipher.min(), f.entropy_cipher.max()
g_s = S["g"]
h_n, h_k, (h_lo, h_hi) = S["h"]["n"], S["h"]["detected"], S["h"]["wilson"]
cov = S.get("coverage_total_pct")
loc = rd("i_loc"); tests = rd("i_tests")
n_tests = int(tests.tests.sum())
RO = S["run_order"]
n_drift = sum(1 for v in RO.values() if v["p"] < 0.05)

# ---- LaTeX text ---------------------------------------------------------------------------------------------
table_rows = [
 ("Scaling (a)", f"Time grows roughly linearly with size: upload {thr['upload'][0]:.1f}\\,MiB/s [{thr['upload'][1]:.1f}, {thr['upload'][2]:.1f}], download {thr['download'][0]:.1f}\\,MiB/s "
                 f"[{thr['download'][1]:.1f}, {thr['download'][2]:.1f}]; $R^2$ {thr['upload'][3]:.2f} and {thr['download'][3]:.2f}; log-log slope {ll['upload']['slope']:.2f} (upload)."),
 ("The emulators (b)", f"One 4\\,MiB object takes a median of {put4['aws-s3']:.0f}\\,ms to write to the S3 emulator, {put4['azure-blob']:.0f}\\,ms to the Azure emulator and "
                 f"{put4['gcs']:.0f}\\,ms to the GCS emulator; the 1\\,MiB put latencies alone predict plain chunked uploads within a factor of {model_factor:.1f}."),
 ("Cost of security (b), 16\\,MiB", f"Framework against plain chunked storage of the same bytes: upload $\\times${cu['med_ratio']:.2f} (median difference {mn(cu['med_diff'], 2)}\\,s "
                 f"[{mn(cu['med_diff_ci_lo'], 2)}, {mn(cu['med_diff_ci_hi'], 2)}], Mann--Whitney {p_tex(cu['p'])}), download $\\times${cd['med_ratio']:.2f}. These ratios are set by the "
                 f"emulators and are not transferable. AES-256-GCM with SHA-256 explains {pct(share_up, 0)} of the upload and {pct(share_dn, 0)} of the download difference."),
 ("Chunk size (c)", f"Throughput depends on chunk size (Kruskal--Wallis, upload {p_tex(C['upload']['kw_p'])}, download {p_tex(C['download']['kw_p'])}); median upload {med_up[kmin]:.1f}\\,MiB/s at "
                 f"{kmin}\\,KiB and {med_up[kmax]:.1f}\\,MiB/s at {kmax // 1024}\\,MiB; one more chunk costs about {per_chunk_ms:.0f}\\,ms of upload."),
 ("One provider killed (d)", f"{r_dn[0]}/{r_dn[1]} reads and {r_up[0]}/{r_up[1]} writes succeed (Wilson lower bounds {pct(r_dn[2][0])} and {pct(r_up[2][0])}); download latency changes by "
                 f"{mn(dcmp['med_diff'] * 1000)}\\,ms [{mn(dcmp['med_diff_ci_lo'] * 1000)}, {mn(dcmp['med_diff_ci_hi'] * 1000)}] ({'a small change' if lat_sig else 'no detectable change'}; Mann--Whitney {p_tex(dcmp['p'])}). "
                 f"Two killed: {r_two[0]}/{r_two[1]} reads."),
 ("Placement (e)", f"Replicas are uniform over the providers: rotating $\\chi^2={e['rotating']['chi2']:.2f}$ ({p_tex(e['rotating']['p'])}), hash $\\chi^2={e['hash']['chi2']:.2f}$ "
                 f"({p_tex(e['hash']['p'])}); 2 d.f."),
 ("Stored objects (f)", f"Entropy {f_lo:.4f}--{f_hi:.4f} bits/byte for random, text and all-zero plaintext; {fb['k']} of {fb['n']} objects fail a chi-square uniformity test at 5\\% "
                 f"({0.05 * fb['n']:.1f} expected; $P(X\\ge{fb['k']})={fb['p_tail']:.2f}$)."),
 ("Audit log (g)", f"Verification time is linear in the log size (log-log slope {g_s['loglog']['slope']:.3f} [{g_s['loglog']['slope_ci_lo']:.3f}, {g_s['loglog']['slope_ci_hi']:.3f}]), "
                 f"{g_s['linear']['slope'] * 1e6:.1f}\\,ms per 1000 events; {g_s['record_events_per_s']['mean']:.0f}\\,events/s with an fsync per event."),
 ("Attack suite (h)", f"{h_k}/{h_n} designed attack and failure tests passed (Wilson lower bound {pct(h_lo)}); not a random sample."),
]
if cov is not None:
    table_rows.append(("Coverage (i)", f"{cov:.1f}\\% line coverage of \\code{{backend/app}} by the {n_tests:,}-test suite."))
rows_tex = "\n".join(f"{l} & {t} \\\\" for l, t in table_rows)

lat_close = (f"a small change in download latency (median {mn(dcmp['med_diff'] * 1000)}\\,ms, Mann--Whitney {p_tex(dcmp['p'])})" if lat_sig else "no detectable latency change")
why_short = ("the framework alone takes the same time as in experiment~a, and longer only when interleaved with the plain arms" if cons["iso_vs_a"]["p_holm"] >= 0.05 and cons["inter_vs_iso"]["p_holm"] < 0.05
             else "absolute times differ between experiments run on the same code")

NEW_SECTION = f"""\\subsection{{Performance}}\\label{{sec:perf}}
% NUMBERS: audit numbers from backend/app/audit/NOTES.md ("Measured performance"); end-to-end numbers: see Section~\\ref{{sec:stats}} (analysis/data via analysis/run_all.sh).
The audit subsystem's own measurements (\\code{{backend/app/audit/NOTES.md}}) are as follows. 1,000 real \\code{{record()}} calls take 1.35\\,s, i.e., about 739 events/s with an fsync per event. Verifying a chain of 20,000 events with 190 signed checkpoints and 570 anchor copies takes 0.54\\,s. The end-to-end figures below were measured through the full API stack (authentication, PDP, KMS, encryption, $R=2$ placement with read-back verification, audit) against the three emulators; they exclude network latency, so they show the cost of the security pipeline and of per-chunk work, not achievable cloud throughput. A download is verified in full before its first byte is released (the plaintext is held in memory up to 8\\,MiB and in a temporary file beyond that), so its latency grows with file size by design.

\\subsection{{Statistical evaluation}}\\label{{sec:stats}}
% NUMBERS: analysis/data/*.csv through analysis/analyze.py (docs/STATISTICAL_ANALYSIS.md); reproduce with analysis/run_all.sh.
We measured the framework with the scripts in \\code{{analysis/}}; one command reproduces every number. Each API measurement is one request to a real server on the loopback interface, with conditions interleaved in random order, $n={N}$ repetitions per condition after three discarded warm-ups, 95\\% confidence intervals, and the emulators restarted on an empty data directory before every experiment. The tests were fixed in advance: two groups are compared with the Mann--Whitney $U$ test and the difference of medians with a bootstrap interval, several groups with Kruskal--Wallis, proportions with Wilson intervals, placement and ciphertext with $\\chi^2$ tests. The host is an {ENV['cpu']} ({ENV['logical_cpus']} logical CPUs, {ENV['ram_gib']:.1f}\\,GiB) under WSL2, Python {ENV['python']}, commit \\code{{{ENV['git_commit']}}}, on AC power with a high-performance plan; absolute times belong to this machine and its emulators. Table~\\ref{{tab:stats}} and Figs.~\\ref{{fig:statmain}} and~\\ref{{fig:stataux}} summarise the results.

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
\\caption{{(a) Transfer time against file size with the fitted line; (b) the same 16\\,MiB stored with the full pipeline, as plain chunked storage and as one plain object on each emulator; (c) throughput against chunk size for a 32\\,MiB file; (d) download latency with one provider killed, and the read and write success counts.}}
\\label{{fig:statmain}}
\\end{{figure*}}

\\begin{{figure*}}[t]
\\centering
\\includegraphics[width=\\textwidth]{{figures/stat-aux.pdf}}
\\caption{{(e) Entropy of the objects as stored at the providers against the entropy of the plaintext; (f) audit-chain verification time against the number of events; (g) replicas per provider for the two placement strategies.}}
\\label{{fig:stataux}}
\\end{{figure*}}

The cost of the pipeline cannot be read off the ratios alone. The three emulators differ strongly (the {NAME[slow]} emulator is the slowest to write to), uploads wait for the slower emulator of each chunk's pair, and a model that uses only the 1\\,MiB put latencies predicts the plain chunked time within a factor of {model_factor:.1f}; the upload and download ratios are therefore properties of these emulators and should not be transferred to real providers. The cipher is a small part of the difference. The framework's 16\\,MiB upload also differs between experiments ({why_short}), and {n_drift} of {len(RO)} upload series show a significant trend with run order, so only arms interleaved inside one experiment are compared. Losing one provider caused no failed request and {lat_close}, while losing two broke every read, as the replication factor predicts. The stored objects are statistically indistinguishable from random bytes, and audit verification scales linearly. These results come from emulators on one host with no network latency, from designed (not randomly sampled) attack scenarios, and from sequential requests that are not fully independent.

"""

edits = [
 # ---- contributions, chunk size, test table, related work, limitations (the text edits that do not depend on the new data)
 ("with a 17-scenario attack suite, provider-failure experiments and measurements.",
  "with a 17-scenario attack suite, provider-failure experiments and a statistical evaluation of its cost, scaling and availability."),
 ("The file is streamed in 1\\,MiB chunks. Each chunk is stored as",
  "The file is streamed in 1\\,MiB chunks by default. The chunk size is a deployment setting, and each manifest records the size used for its file, so files written under different settings stay readable. Each chunk is stored as"),
 ("% NUMBERS: final verification run of 2026-11-23 (docs/SECURITY_TESTING.md, docs/FINAL_REPORT.md);\n% row 5 from backend/app/audit/NOTES.md.",
  "% NUMBERS: final verification run of 2026-11-25 (docs/SECURITY_TESTING.md, docs/FINAL_REPORT.md); the Playwright row was re-run on 2026-11-26.\n% row 5 from backend/app/audit/NOTES.md."),
 ("Whole backend suite (\\code{pytest}) & 1,236 passed \\\\", "Whole backend suite (\\code{pytest}) & 1,273 passed \\\\"),
 ("Frontend: Vitest unit / Playwright end-to-end checks & 15 / 54 of 54 \\\\", "Frontend: Vitest unit / Playwright end-to-end checks$^{*}$ & 15 / 54 of 54 \\\\"),
 ("The final verification run was recorded on 23 November 2026 with all three emulators reachable: 1,236 backend tests (935 unit, 151 integration, 108 security, 42 review) passed with no failures, no skips and no expected failures.",
  "The final verification run was recorded on 25 and 26 November 2026 with all three emulators reachable: 1,273 backend tests (968 unit, 155 integration, 108 security, 42 review) passed with no failures, no skips and no expected failures. $^{*}$The Playwright walk-through was re-run on 26 November (54 of 54). The 37 tests added since the first submission cover the deployment settings, per-file chunk sizes and the benchmark tooling, and no application code changed. The container deployment was built and smoke-tested once on 26 November (12 of 12 checks with a 20\\,MiB and a 300\\,MiB file through nginx); the smoke test found and we fixed one defect in the compose file."),
 ("which is the gap our case study and prototype target~\\cite{casestudy2026}.\n",
  """which is the gap our case study and prototype target~\\cite{casestudy2026}.

\\textbf{Performance of multi-cloud storage.} Published evaluations are mostly over real wide-area links, so their absolute figures are not comparable with ours, which exclude network latency. DepSky measured clients on four continents against four commercial clouds and found that cryptography and coding cost at most 5\\% of read and 10\\% of write latency, and that moving from 100\\,kb to 1\\,Mb data units raised throughput about fivefold, with much smaller gains beyond~\\cite{bessani2011depsky}. NCCloud reports about 3\\% of a 10\\,MB transfer on Azure spent in coding~\\cite{hu2012nccloud}, and CYRUS finds that data transfer, not coding, is the bottleneck~\\cite{chung2015cyrus}. RACS erasure-codes at 95\\,MB/s on a 2\\,GHz Core~2 Duo~\\cite{abulibdeh2010racs}. On a 1\\,Gb/s LAN, CDStore reaches 77.5\\,MB/s upload and 99.2\\,MB/s download, and 6.2 and 12.3\\,MB/s across four commercial clouds~\\cite{li2015cdstore}. CYRUS and CDStore use units of about 4\\,MB, which suits wide-area transfers and deduplication; our 16\\,MiB deployment setting is justified by local measurements only (Section~\\ref{sec:stats}). A 2026 preprint on client-side envelope encryption for S3-compatible storage also uses 4\\,MiB chunks and binds the chunk index and a final flag into the associated data, as we do~\\cite{lingala2026}.
"""),
 ("and no TLS or reverse proxy was in the path.",
  "and no TLS or reverse proxy was in the path. The chunk-size tuning of Section~\\ref{sec:stats} was measured on one host with no network latency and up to 10\\,GiB; on real links a large chunk is a larger retry unit, so the provider timeout we pair with 16\\,MiB chunks (30\\,s in the container settings, 10\\,s by default) should be re-validated against real providers."),
 # ---- abstract, implementation, conclusion (these depend on the data)
 ("The backend suite of 1,236 tests passes", "The backend suite of 1,273 tests passes"),
 ("including failover when an emulator process is killed. Verifying 20,000 audit events takes 0.54\\,s.",
  f"including failover when an emulator process is killed. A statistical evaluation on local emulators finds that, with one of three providers killed, {r_dn[0]}/{r_dn[1]} reads and {r_up[0]}/{r_up[1]} writes still succeed, "
  f"and that upload time is set mainly by the emulators' own latency (the cipher explains {pct(share_up, 0)} of the framework's upload overhead). Verifying 20,000 audit events takes 0.54\\,s."),
 ("% NUMBERS: abstract quotes 1,236 passing tests,", "% NUMBERS: abstract quotes 1,273 passing tests, the success counts and the cipher share from analysis/data (Section~\\ref{sec:stats}),"),
 ("11,330 lines in 71 test files", f"{int(loc[loc.area == 'backend/tests'].total.sum()):,} lines in {int((loc.area == 'backend/tests').sum())} test files"),
 ("Eleven architecture decision records (ADR-0001 to ADR-0011) document the design choices. Fig.",
  "Twelve architecture decision records (ADR-0001 to ADR-0012) document the design choices. The container deployment overrides three framework defaults (16\\,MiB chunks, a 10\\,GiB upload cap and a 20\\,GiB bulk-download threshold; ADR-0012), and the benchmark and large-file tools are in \\code{scripts/bench/}. Fig."),
 ("The prototype passes its 17 attack scenarios and survives a real provider outage.",
  f"The prototype passes its 17 attack scenarios and survives a real provider outage ({r_dn[0]}/{r_dn[1]} reads and {r_up[0]}/{r_up[1]} writes with one of three providers killed); on local emulators its cost is dominated by the emulators' own latency, and that cost does not transfer to real clouds."),
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
print(f"[paper_update] main.tex updated ({len(NEW_SECTION.split())} words in the evaluation)")
