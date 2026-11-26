#!/usr/bin/env python3
"""Compact vector figures for the article, built from analysis/data/*.csv (run after analysis/run_all.sh).

Writes analysis/figures/stat-main.{pdf,png} and stat-aux.{pdf,png}; copy the PDFs to paper/figures/ for LaTeX.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import COLORS, DATA, SEED, describe, linfit, savefig, style, wilson  # noqa: E402

plt = style()
plt.rcParams.update({"font.size": 6.5, "axes.titlesize": 7, "axes.labelsize": 6.5, "legend.fontsize": 5.8, "xtick.labelsize": 6, "ytick.labelsize": 6,
                     "axes.linewidth": 0.6, "lines.linewidth": 0.9, "figure.constrained_layout.use": True})
rd = lambda n: pd.read_csv(DATA / f"{n}.csv")

# ----------------------------------------------------------------- main: a, b, c, d
a, b, c, d = rd("a_scaling"), rd("b_overhead"), rd("c_chunk"), rd("d_fault")
a, b, c = a[a.ok], b[b.ok], c[c.ok].copy()
fig, ax = plt.subplots(1, 4, figsize=(7.16, 2.1))

for op in ("upload", "download"):
    s = a[a.op == op]
    fit = linfit(s.size_mib.values, s.seconds.values)
    ax[0].scatter(s.size_mib, s.seconds, s=3, alpha=0.35, color=COLORS[op])
    xs = np.linspace(0, 66, 20)
    ax[0].plot(xs, fit["intercept"] + fit["slope"] * xs, color=COLORS[op], label=f"{op}: {1 / fit['slope']:.0f} MiB/s, R²={fit['r2']:.3f}")
ax[0].set_xlabel("File size (MiB)"); ax[0].set_ylabel("Seconds"); ax[0].set_title("(a) Time against size"); ax[0].legend(loc="upper left", fontsize=5.2, framealpha=0.9); ax[0].set_ylim(0, 22)

sizes, w = 16, 0.26
for k, arm in enumerate(("app", "plain_chunked", "plain_single")):
    for j, op in enumerate(("upload", "download")):
        dd = describe(b[(b.op == op) & (b.size_mib == sizes) & (b.arm == arm)].seconds.values)
        ax[1].bar(j + (k - 1) * w, dd["mean"], w, yerr=dd["mean"] - dd["ci_lo"], capsize=1.5, color=COLORS[arm], label=arm.replace("_", " ") if j == 0 else None)
ax[1].set_xticks([0, 1]); ax[1].set_xticklabels(["upload", "download"]); ax[1].set_ylabel("Seconds, 16 MiB (mean, 95% CI)")
ax[1].set_title("(b) Cost of security"); ax[1].legend(loc="center right", fontsize=5.2); ax[1].set_ylim(0, 4.6)

c["mib_s"] = 32 / c.seconds
for op in ("upload", "download"):
    ks = sorted(c.chunk_kib.unique())
    med, lo, hi = [], [], []
    for kk in ks:
        dd = describe(c[(c.op == op) & (c.chunk_kib == kk)].mib_s.values)
        med.append(dd["median"]); lo.append(dd["median"] - dd["med_ci_lo"]); hi.append(dd["med_ci_hi"] - dd["median"])
    ax[2].errorbar(range(len(ks)), med, yerr=[lo, hi], marker="o", ms=2.5, capsize=1.5, color=COLORS[op], label=op)
ax[2].set_xticks(range(len(ks))); ax[2].set_xticklabels([f"{kk // 1024 if kk >= 1024 else kk / 1024:g}" for kk in ks]); ax[2].set_xlabel("Chunk size (MiB)")
ax[2].set_ylabel("MiB/s (median, 95% CI)"); ax[2].set_title("(c) Chunk size"); ax[2].legend()

up_all = d[(d.phase == "all_up") & (d.op == "download")].seconds.values
gd = d[(d.phase == "gcs_down") & (d.op == "download")].sort_values("trial")
steady = gd.seconds.values[3:3 + len(up_all)]
bp = ax[3].boxplot([up_all, steady], tick_labels=["all up", "1 down"], patch_artist=True, widths=0.5, flierprops=dict(markersize=2))
for patch in bp["boxes"]:
    patch.set(facecolor=COLORS["download"], alpha=0.5)
k_dn, n_dn = int(gd.ok.sum()), len(gd)
k_up = int(d[(d.phase == "gcs_down") & (d.op == "upload")].ok.sum()); n_up = len(d[(d.phase == "gcs_down") & (d.op == "upload")])
two = d[d.phase == "two_down"]
ax[3].set_ylabel("Download seconds (16 MiB)"); ax[3].set_title("(d) One provider killed"); ax[3].set_ylim(0.1, 1.15)
ax[3].text(0.5, 0.97, f"1 down: {k_dn}/{n_dn} reads,\n{k_up}/{n_up} writes ok\n2 down: {int(two.ok.sum())}/{len(two)} reads", transform=ax[3].transAxes, ha="center", va="top", fontsize=5.4)
savefig(fig, "stat-main"); plt.close(fig)

# ----------------------------------------------------------------- aux: e, f, g
e, f, gv = rd("e_placement"), rd("f_entropy").drop_duplicates(["kind", "chunk_index"]), rd("g_audit_verify")
fig, ax = plt.subplots(1, 3, figsize=(7.16, 1.9))
kinds = ["random", "english_text", "zeros"]
ax[0].boxplot([f[f.kind == k].entropy_cipher for k in kinds], tick_labels=["random", "text", "zeros"], patch_artist=True, widths=0.5, flierprops=dict(markersize=2),
              boxprops=dict(facecolor=COLORS["cipher"], alpha=0.5))
ax[0].scatter(range(1, 4), [f[f.kind == k].entropy_plain.mean() for k in kinds], marker="D", s=10, color=COLORS["plain"], zorder=3, label="plaintext")
ax[0].set_ylabel("Entropy (bits per byte)"); ax[0].set_title("(e) Stored objects look random"); ax[0].legend(loc="center right")

lin = linfit(gv.events.values, gv.seconds.values)
ax[1].scatter(gv.events / 1000, gv.seconds, s=4, alpha=0.6, color=COLORS["app"])
xs = np.array(sorted(gv.events.unique()))
ax[1].plot(xs / 1000, lin["intercept"] + lin["slope"] * xs, color="black", label=f"linear, R²={lin['r2']:.4f}")
ax[1].set_xlabel("Events in the audit log (thousands)"); ax[1].set_ylabel("verify_chain seconds"); ax[1].set_title("(f) Verification scales linearly"); ax[1].legend(loc="upper left")

tot = None
for k, strat in enumerate(("rotating", "hash")):
    sub = e[(e.strategy == strat) & (e.kind == "replicas_per_provider")].set_index("label")["count"]
    ax[2].bar(np.arange(3) + (k - 0.5) * 0.36, [sub[p] for p in ("aws-s3", "azure-blob", "gcs")], 0.36, label=strat)
    tot = sub.sum()
ax[2].axhline(tot / 3, color="black", ls="--", lw=0.7, label="uniform")
ax[2].set_xticks(range(3)); ax[2].set_xticklabels(["S3", "Azure", "GCS"]); ax[2].set_ylabel("Replicas"); ax[2].set_title("(g) Placement balance"); ax[2].legend(loc="lower right")
savefig(fig, "stat-aux"); plt.close(fig)
print("[paper_figures] wrote analysis/figures/stat-main.pdf and stat-aux.pdf")
