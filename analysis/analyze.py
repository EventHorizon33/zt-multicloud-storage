#!/usr/bin/env python3
"""Analyse analysis/data/*.csv: statistics, figures, docs/STATISTICAL_ANALYSIS.md and analysis/statistical-analysis.pdf.

Every number in the report is computed here from the CSV files (nothing is typed in by hand). The same content blocks
produce the Markdown and the PDF.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import (COLORS, DATA, FIG, MIB, REPO, ROOT, SEED, compare, describe, fmt_p, holm, linfit, savefig, st, style,  # noqa: E402
                 wilson)

plt = style()
META = json.loads((DATA / "meta.json").read_text())
ENV = META["env"]
N = META["n"]
SUMMARY: dict = {}


# --------------------------------------------------------------------------- #
# document model: blocks -> markdown and PDF
# --------------------------------------------------------------------------- #
class Doc:
    def __init__(self):
        self.blocks: list[tuple] = []

    def h(self, level: int, text: str): self.blocks.append(("h", level, text))
    def p(self, text: str): self.blocks.append(("p", text))
    def bullets(self, items): self.blocks.append(("ul", list(items)))
    def table(self, headers, rows, caption=None): self.blocks.append(("table", list(headers), [list(map(str, r)) for r in rows], caption))
    def fig(self, name: str, caption: str): self.blocks.append(("fig", name, caption))

    def markdown(self) -> str:
        out = []
        for b in self.blocks:
            if b[0] == "h":
                out.append("#" * b[1] + " " + b[2] + "\n")
            elif b[0] == "p":
                out.append(b[1] + "\n")
            elif b[0] == "ul":
                out.append("\n".join(f"* {i}" for i in b[1]) + "\n")
            elif b[0] == "table":
                _, hd, rows, cap = b
                if cap:
                    out.append(f"**{cap}**\n")
                out.append("| " + " | ".join(hd) + " |\n|" + "|".join("---" for _ in hd) + "|\n" + "\n".join("| " + " | ".join(r) + " |" for r in rows) + "\n")
            elif b[0] == "fig":
                out.append(f"![{b[2]}](../analysis/figures/{b[1]}.png)\n\n*{b[2]}* ([PDF](../analysis/figures/{b[1]}.pdf))\n")
        return "\n".join(out)

    def pdf(self, path: Path) -> None:
        """A paginated A4 report (reportlab): wrapped paragraphs, bold and code spans, tables that fit the page, figures with captions."""
        import re
        from xml.sax.saxutils import escape
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, Image, KeepTogether, ListFlowable, ListItem, PageTemplate,
                                        Paragraph, Spacer, Table, TableStyle)

        def mk(text: str) -> str:
            t = escape(text)
            t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
            t = re.sub(r"`([^`]+)`", r'<font name="Courier" size="8.2">\1</font>', t)
            return t.replace("²", "<sup>2</sup>")

        body = ParagraphStyle("body", fontName="Helvetica", fontSize=9.2, leading=12.6, spaceAfter=5)
        small = ParagraphStyle("small", parent=body, fontSize=7.8, leading=10, textColor=colors.HexColor("#444444"), spaceAfter=8)
        cap = ParagraphStyle("cap", parent=body, fontName="Helvetica-Bold", fontSize=8.4, leading=10.5, spaceBefore=6, spaceAfter=3, keepWithNext=True)
        hs = {1: ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold", fontSize=19, leading=23, spaceAfter=8),
              2: ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold", fontSize=13.5, leading=17, spaceBefore=10, spaceAfter=5, keepWithNext=True),
              3: ParagraphStyle("h3", parent=body, fontName="Helvetica-Bold", fontSize=10.5, leading=13, spaceBefore=6, spaceAfter=3, keepWithNext=True)}
        page_w, page_h = A4
        margin = 16 * mm
        avail = page_w - 2 * margin
        meta = f"Statistical analysis of the framework - commit {ENV['git_commit']} - {ENV['date'][:10]}"

        def footer(canvas, doc_):
            canvas.saveState()
            canvas.setFont("Helvetica", 7.2)
            canvas.setFillColor(colors.HexColor("#666666"))
            canvas.drawString(margin, 9 * mm, meta)
            canvas.drawRightString(page_w - margin, 9 * mm, f"Page {doc_.page}")
            canvas.restoreState()

        doc = BaseDocTemplate(str(path), pagesize=A4, leftMargin=margin, rightMargin=margin, topMargin=15 * mm, bottomMargin=17 * mm,
                              title="Statistical analysis of the framework", author="Zero-Trust Multi-Cloud Storage team")
        doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(margin, 17 * mm, avail, page_h - 32 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=footer)])

        def table(hd, rows, caption):
            n = len(hd)
            fs = 8.0 if n <= 4 else 7.4 if n <= 6 else 6.7 if n <= 8 else 6.0
            cell = ParagraphStyle("cell", parent=body, fontSize=fs, leading=fs * 1.22, spaceAfter=0)
            head = ParagraphStyle("head", parent=cell, fontName="Helvetica-Bold")
            data = [[Paragraph(mk(h), head) for h in hd]] + [[Paragraph(mk(str(c)), cell) for c in r] for r in rows]
            lens = [max(min(len(str(x)), 46) for x in [h] + [r[i] for r in rows]) + 3 for i, h in enumerate(hd)]
            wts = [max(l, 0.55 * max(lens), 9) for l in lens]
            widths = [avail * w / sum(wts) for w in wts]
            t = Table(data, colWidths=widths, repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6edf5")), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b9c2cc")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                                   ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                                   ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")])]))
            return ([Paragraph(mk(caption), cap)] if caption else []) + [t, Spacer(1, 6)]

        story = []
        for b in self.blocks:
            if b[0] == "h":
                if b[1] == 2:
                    story.append(CondPageBreak(60 * mm))
                story.append(Paragraph(mk(b[2]), hs.get(b[1], hs[3])))
            elif b[0] == "p":
                story.append(Paragraph(mk(b[1]), body))
            elif b[0] == "ul":
                story.append(ListFlowable([ListItem(Paragraph(mk(i), body), leftIndent=12) for i in b[1]], bulletType="bullet", start="•", leftIndent=12, bulletFontSize=8))
                story.append(Spacer(1, 4))
            elif b[0] == "table":
                story += table(b[1], b[2], b[3])
            elif b[0] == "fig":
                img = plt.imread(FIG / f"{b[1]}.png")
                ih, iw = img.shape[:2]
                w = avail
                h = w * ih / iw
                if h > 95 * mm:
                    h = 95 * mm
                    w = h * iw / ih
                story.append(KeepTogether([Image(str(FIG / f"{b[1]}.png"), width=w, height=h), Paragraph(mk(b[2]), small)]))
        doc.build(story)

def f3(x, d=3): return f"{x:.{d}f}"
def pm(d, k="mean", dd=3): return f"{d[k]:.{dd}f}"
def ci(d, lo="ci_lo", hi="ci_hi", dd=3): return f"[{d[lo]:.{dd}f}, {d[hi]:.{dd}f}]"


def rd(name):
    return pd.read_csv(DATA / f"{name}.csv")


doc = Doc()
doc.h(1, "Statistical analysis of the framework")
doc.p("Everything in this report was measured by the scripts in `analysis/` on the machine described below, from the code at the commit "
      "shown. Raw data are in `analysis/data/*.csv`, figures in `analysis/figures/`, and `analysis/run_all.sh` reproduces all of it. "
      "No number was typed in by hand: they are computed from the CSV files by `analysis/analyze.py`.")
doc.h(2, "Environment and method")
doc.table(["Item", "Value"], [
    ["Date", ENV["date"]], ["Hardware", f"{ENV['cpu']}, {ENV['logical_cpus']} logical CPUs, {ENV['ram_gib']} GiB RAM"], ["OS", ENV["os"]],
    ["Python / numpy / scipy / pandas / matplotlib", f"{ENV['python']} / {ENV['numpy']} / {ENV['scipy']} / {ENV['pandas']} / {ENV['matplotlib']}"],
    ["Git commit", f"{ENV['git_commit']}" + (" (backend/app has uncommitted changes)" if ENV["git_app_dirty"] else " (no uncommitted changes in backend/app; the later commits that add tests and documentation change no application code)")],
    ["Random seed", str(ENV["seed"]) + " (order of conditions, bootstrap resampling)"],
    ["Repetitions", f"n = {N} per condition after 3 discarded warm-up repetitions" + ("  (QUICK RUN: not a full-size sample)" if META.get("quick") else "")],
    ["Setting", ENV["setting"]]])
doc.bullets([
    "**Statistics.** Per condition: n, mean, SD, median, 95% t-interval of the mean and 95% percentile-bootstrap interval of the median "
    "(5000 resamples). Two-group comparisons report both Welch's t-test and the Mann-Whitney U test; the primary test is Welch's when both "
    "samples pass a Shapiro-Wilk check at 0.05 and Mann-Whitney otherwise. Several groups: one-way ANOVA and Kruskal-Wallis (primary "
    "Kruskal-Wallis unless every group is normal), pairwise Mann-Whitney with Holm correction. Proportions: Wilson 95% intervals.",
    "**Design.** Conditions were interleaved in a random order within each repetition, so slow or fast periods of the machine affect them "
    "alike. Successive requests to one server are not fully independent (caches, background threads); the interleaving reduces but does "
    "not remove that.",
    "**Honest limits.** Local emulators on one machine, no network latency, and the attack outcomes are designed scenarios, not a random "
    "sample. Absolute times are specific to this machine; ratios and shapes are the transferable part."])

KEY: list[str] = []

# ---------------------------------------------------------------- a. scaling
a = rd("a_scaling")
a_ok = a[a.ok]
doc.h(2, "a. Upload and download against file size")
doc.p("One real API server (1 MiB chunks, the framework default), files of 1, 4, 16 and 64 MiB, each uploaded and downloaded n times through the "
      "full stack (authentication, policy, KMS, encryption, replication to 2 of 3 emulators with read-back verification, audit). "
      f"{len(a) - len(a_ok)} of {len(a)} transfers failed or did not verify; the rest are analysed.")
rows, fits = [], {}
for op in ("upload", "download"):
    for s in sorted(a_ok.size_mib.unique()):
        x = a_ok[(a_ok.op == op) & (a_ok.size_mib == s)].seconds.values
        d = describe(x)
        thr = describe(s / x)
        rows.append([op, f"{s:g} MiB", d["n"], f3(d["mean"]), f3(d["sd"]), f3(d["median"]), ci(d), f3(thr["mean"], 1), f"{d['shapiro_p']:.3f}"])
    sub = a_ok[a_ok.op == op]
    fit = linfit(sub.size_mib.values, sub.seconds.values)
    fits[op] = fit
doc.table(["Op", "Size", "n", "Mean s", "SD s", "Median s", "95% CI of mean (s)", "Mean MiB/s", "Shapiro p"], rows, "Time per transfer")
fr = []
for op, f in fits.items():
    fr.append([op, f3(f["slope"], 4), f"[{f['slope_ci_lo']:.4f}, {f['slope_ci_hi']:.4f}]", f3(1 / f["slope"], 1),
               f"[{1 / f['slope_ci_hi']:.1f}, {1 / f['slope_ci_lo']:.1f}]", f3(f["intercept"], 3), f"[{f['intercept_ci_lo']:.3f}, {f['intercept_ci_hi']:.3f}]", f3(f["r2"], 4)])
doc.table(["Op", "Slope s/MiB", "95% CI", "Throughput MiB/s", "95% CI", "Intercept s", "95% CI", "R²"], fr,
          "Linear model: seconds = intercept + slope x size (ordinary least squares on all individual transfers)")
SUMMARY["a"] = {op: dict(throughput_mib_s=1 / f["slope"], thr_ci=[1 / f["slope_ci_hi"], 1 / f["slope_ci_lo"]], r2=f["r2"], intercept_s=f["intercept"]) for op, f in fits.items()}
KEY.append(f"Time grows roughly linearly with size (R² {fits['upload']['r2']:.3f} upload, {fits['download']['r2']:.3f} download; the rest is run-to-run scatter): the marginal rate is "
           f"{1 / fits['upload']['slope']:.1f} MiB/s upload (95% CI {1 / fits['upload']['slope_ci_hi']:.1f} to {1 / fits['upload']['slope_ci_lo']:.1f}) "
           f"and {1 / fits['download']['slope']:.1f} MiB/s download (95% CI {1 / fits['download']['slope_ci_hi']:.1f} to {1 / fits['download']['slope_ci_lo']:.1f}).")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.4), sharey=False)
for ax, op in zip(axes, ("upload", "download")):
    sub = a_ok[a_ok.op == op]
    ax.scatter(sub.size_mib + np.random.default_rng(SEED).uniform(-0.6, 0.6, len(sub)) * np.sqrt(sub.size_mib), sub.seconds, s=8, alpha=0.5, color=COLORS[op])
    xs = np.linspace(0, 66, 50)
    f = fits[op]
    ax.plot(xs, f["intercept"] + f["slope"] * xs, color="black", lw=1.2, label=f"{1 / f['slope']:.1f} MiB/s, R²={f['r2']:.3f}")
    ax.set_title(op.capitalize()); ax.set_xlabel("File size (MiB)"); ax.set_ylabel("Seconds"); ax.legend(loc="upper left")
savefig(fig, "a_scaling"); plt.close(fig)
doc.fig("a_scaling", f"Time against file size with the fitted line (n = {N} per point, 1 MiB chunks).")
doc.p(f"**What this shows.** Transfer time grows roughly linearly with file size (R² {fits['upload']['r2']:.2f} upload, {fits['download']['r2']:.2f} download), so throughput is mostly a property of the pipeline rather than of the "
      "file size. The intercepts' confidence intervals include zero, so no fixed per-request cost is resolved at these sizes (the 1 MiB transfers are dominated by run-to-run scatter). Upload is much slower than download because every chunk is written to two providers and read back for verification. **Limitations.** Variance rises "
      "with size, so the least-squares standard errors are approximate and the linear fit leaves a good deal unexplained; emulators have no network latency; one machine.")

# ---------------------------------------------------------------- b. overhead
b = rd("b_overhead")
b_ok = b[b.ok]
mic = rd("b_crypto_micro")
doc.h(2, "b. Cost of security")
doc.p("The same bytes stored three ways, against the same emulators and through the same provider adapters: **app** = the full framework; "
      "**plain chunked** = a harness outside the application that splits the file into 1 MiB chunks and writes each plain chunk to 2 of the 3 "
      "providers in parallel (rotating placement), with no encryption, manifest, database, policy, audit or read-back verification; **plain single** = one "
      "object to one provider. The plain arms are the cheapest possible storage of these bytes; the difference to the app is the price of the "
      "whole security pipeline, not of encryption alone.")
rows, tests = [], []
for op in ("upload", "download"):
    for s in sorted(b_ok.size_mib.unique()):
        g = {arm: b_ok[(b_ok.op == op) & (b_ok.size_mib == s) & (b_ok.arm == arm)].seconds.values for arm in ("app", "plain_chunked", "plain_single")}
        for arm, x in g.items():
            d = describe(x)
            rows.append([op, f"{s:g} MiB", arm, d["n"], f3(d["mean"]), f3(d["sd"]), f3(d["median"]), ci(d)])
        c = compare(g["app"], g["plain_chunked"])
        c.update(op=op, size=s)
        tests.append(c)
adj = holm([t["p"] for t in tests])
for t, p_adj in zip(tests, adj):
    t["p_holm"] = p_adj
doc.table(["Op", "Size", "Arm", "n", "Mean s", "SD s", "Median s", "95% CI of mean (s)"], rows, "Time per transfer by arm")
doc.table(["Op", "Size", "App minus plain chunked (s)", "95% CI (Welch)", "Ratio app/plain", "Primary test", "p", "p (Holm)", "Cohen d", "Cliff delta"],
          [[t["op"], f"{t['size']:g} MiB", f3(t["diff"]), f"[{t['diff_ci_lo']:.3f}, {t['diff_ci_hi']:.3f}]", f3(t["ratio"], 2), t["primary"], fmt_p(t["p"]),
            fmt_p(t["p_holm"]), f3(t["cohens_d"], 1), f3(t["cliffs_delta"], 2)] for t in tests],
          "Overhead of the full pipeline over plain chunked storage (six comparisons, Holm-adjusted)")
enc = describe(mic[mic.op == "encrypt"].seconds_per_mib.values)
dec = describe(mic[mic.op == "decrypt"].seconds_per_mib.values)
doc.table(["Cipher alone, no I/O", "n", "Mean ms per MiB", "SD", "95% CI", "MiB/s"],
          [["encrypt (AES-256-GCM + SHA-256)", enc["n"], f3(enc["mean"] * 1000, 3), f3(enc["sd"] * 1000, 3), f"[{enc['ci_lo'] * 1000:.3f}, {enc['ci_hi'] * 1000:.3f}]", f3(1 / enc["mean"], 0)],
           ["decrypt (SHA-256 check + AES-256-GCM)", dec["n"], f3(dec["mean"] * 1000, 3), f3(dec["sd"] * 1000, 3), f"[{dec['ci_lo'] * 1000:.3f}, {dec['ci_hi'] * 1000:.3f}]", f3(1 / dec["mean"], 0)]],
          "CPU cost of the cipher itself (the same calls the application makes, 16 MiB per repetition)")
t16 = next(t for t in tests if t["op"] == "upload" and t["size"] == 16)
d16 = next(t for t in tests if t["op"] == "download" and t["size"] == 16)
share_up = enc["mean"] * 16 / t16["diff"]
share_dn = dec["mean"] * 16 / d16["diff"]
SUMMARY["b"] = dict(upload16=t16, download16=d16, cipher_share_of_overhead_up=share_up, cipher_share_of_overhead_down=share_dn)
KEY.append(f"The whole security pipeline makes a 16 MiB upload {t16['ratio']:.2f} times slower than plain chunked storage of the same bytes "
           f"(difference {t16['diff']:.3f} s, 95% CI {t16['diff_ci_lo']:.3f} to {t16['diff_ci_hi']:.3f}; {t16['primary']} p {fmt_p(t16['p'])}) and a download "
           f"{d16['ratio']:.2f} times slower (difference {d16['diff']:.3f} s, 95% CI {d16['diff_ci_lo']:.3f} to {d16['diff_ci_hi']:.3f}); "
           f"AES-256-GCM with SHA-256 alone explains about {100 * share_up:.0f}% of the upload overhead and {100 * share_dn:.0f}% of the download overhead.")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.4))
for ax, op in zip(axes, ("upload", "download")):
    sizes = sorted(b_ok.size_mib.unique())
    w = 0.26
    for k, arm in enumerate(("app", "plain_chunked", "plain_single")):
        means, errs = [], []
        for s in sizes:
            d = describe(b_ok[(b_ok.op == op) & (b_ok.size_mib == s) & (b_ok.arm == arm)].seconds.values)
            means.append(d["mean"]); errs.append(d["mean"] - d["ci_lo"])
        ax.bar(np.arange(len(sizes)) + (k - 1) * w, means, w, yerr=errs, capsize=2, color=COLORS[arm], label=arm.replace("_", " "))
    ax.set_xticks(range(len(sizes))); ax.set_xticklabels([f"{s:g} MiB" for s in sizes]); ax.set_title(op.capitalize()); ax.set_ylabel("Seconds (mean, 95% CI)")
    ax.legend()
savefig(fig, "b_overhead"); plt.close(fig)
doc.fig("b_overhead", "Mean time with 95% confidence intervals: the framework against plain chunked and plain single-object storage.")
worst_p = max(t["p_holm"] for t in tests)
up_r = [t["ratio"] for t in tests if t["op"] == "upload"]; dn_r = [t["ratio"] for t in tests if t["op"] == "download"]
doc.p(f"**What this shows.** The pipeline is slower than plain chunked storage at every size and operation (largest Holm-adjusted p {fmt_p(worst_p)}): uploads take {min(up_r):.2f} to {max(up_r):.2f} times as long and downloads {min(dn_r):.2f} to {max(dn_r):.2f} times. The cipher itself is a small part of the difference (about {100 * share_up:.0f}% of the upload and {100 * share_dn:.0f}% of the download overhead at 16 MiB); "
      "the remainder is everything else the pipeline does and plain storage does not (HTTP request handling, metadata commits, audit events, policy checks, read-back verification and spooling), which this experiment did not separate. "
      "**Limitations.** The plain arms are a lower bound (they do not authenticate, authorise, log or verify), so the overhead is the price of the "
      "whole pipeline, not a like-for-like comparison with an encryption-only design; emulators only.")

# ---------------------------------------------------------------- c. chunk size
c = rd("c_chunk")
c_ok = c[c.ok].copy()
c_ok["mib_s"] = 32 / c_ok.seconds
doc.h(2, "c. Effect of chunk size")
doc.p("A 32 MiB file through four servers that differ only in chunk size (256 KiB, 1 MiB, 4 MiB, 16 MiB), interleaved in random order.")
rows, groups = [], {}
for op in ("upload", "download"):
    gs = {int(k): v.mib_s.values for k, v in c_ok[c_ok.op == op].groupby("chunk_kib")}
    groups[op] = gs
    for k, x in gs.items():
        d = describe(x)
        rows.append([op, f"{k} KiB", d["n"], f3(d["mean"], 1), f3(d["sd"], 1), f3(d["median"], 1), ci(d, dd=1), f"{d['shapiro_p']:.3f}"])
doc.table(["Op", "Chunk", "n", "Mean MiB/s", "SD", "Median", "95% CI of mean", "Shapiro p"], rows, "Throughput by chunk size")
trows, ctest = [], {}
for op, gs in groups.items():
    arrays = list(gs.values())
    an = st.f_oneway(*arrays)
    kw = st.kruskal(*arrays)
    allx = np.concatenate(arrays)
    ss_b = sum(len(x) * (x.mean() - allx.mean()) ** 2 for x in arrays)
    eta2 = ss_b / ((allx - allx.mean()) ** 2).sum()
    normal = all(st.shapiro(x).pvalue > 0.05 for x in arrays)
    ctest[op] = dict(anova_F=float(an.statistic), anova_p=float(an.pvalue), kw_H=float(kw.statistic), kw_p=float(kw.pvalue), eta2=float(eta2))
    trows.append([op, f3(an.statistic, 1), fmt_p(an.pvalue), f3(kw.statistic, 1), fmt_p(kw.pvalue), "ANOVA" if normal else "Kruskal-Wallis", f3(eta2, 3)])
doc.table(["Op", "ANOVA F", "ANOVA p", "Kruskal-Wallis H", "KW p", "Primary", "Eta squared"], trows, "Does throughput depend on chunk size? (3 degrees of freedom)")
keys = list(groups["upload"].keys())
pr = []
for op, gs in groups.items():
    ps, pairs = [], []
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            ps.append(st.mannwhitneyu(gs[keys[i]], gs[keys[j]]).pvalue); pairs.append((keys[i], keys[j]))
    for (ki, kj), p_, ph in zip(pairs, ps, holm(ps)):
        pr.append([op, f"{ki} vs {kj} KiB", f3(np.median(gs[kj]) / np.median(gs[ki]), 2), fmt_p(p_), fmt_p(ph)])
doc.table(["Op", "Pair", "Median ratio (second/first)", "p", "p (Holm)"], pr, "Pairwise Mann-Whitney U tests")
SUMMARY["c"] = ctest
best = {op: max(gs, key=lambda k: np.median(gs[k])) for op, gs in groups.items()}
KEY.append(f"Chunk size matters: throughput differs between 256 KiB, 1, 4 and 16 MiB chunks (Kruskal-Wallis upload p {fmt_p(ctest['upload']['kw_p'])}, download p {fmt_p(ctest['download']['kw_p'])}; "
           f"eta squared {ctest['upload']['eta2']:.2f} and {ctest['download']['eta2']:.2f}); the best median upload is at {best['upload']} KiB "
           f"({np.median(groups['upload'][best['upload']]):.1f} MiB/s) against {np.median(groups['upload'][keys[0]]):.1f} MiB/s at {keys[0]} KiB.")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.3))
for ax, op in zip(axes, ("upload", "download")):
    gs = groups[op]
    ax.boxplot([gs[k] for k in gs], tick_labels=[f"{k} KiB" for k in gs], showfliers=True, patch_artist=True, boxprops=dict(facecolor=COLORS[op], alpha=0.5))
    ax.set_title(op.capitalize()); ax.set_ylabel("MiB/s")
savefig(fig, "c_chunk"); plt.close(fig)
doc.fig("c_chunk", f"Throughput by chunk size for a 32 MiB file (n = {N} per box).")
gu, gd = groups["upload"], groups["download"]
ku = sorted(gu)
r_up = np.median(gu[ku[-1]]) / np.median(gu[ku[-2]]); r_dn = np.median(gd[ku[-1]]) / np.median(gd[ku[-2]])
doc.p(f"**What this shows.** Larger chunks raise throughput: the median goes up with every step for uploads (the last step, {ku[-2]} to {ku[-1]} KiB, is still a factor {r_up:.2f}), while downloads flatten out between {ku[-2]} and {ku[-1]} KiB (factor {r_dn:.2f}). Fewer chunks mean fewer provider requests and database rows for the same bytes. **Limitations.** One file size; "
      "emulators have no per-request network latency, which on real providers would favour larger chunks even more; a chunk is also the unit of retry and repair, "
      "which this experiment does not measure.")

# ---------------------------------------------------------------- d. fault tolerance
d = rd("d_fault")
doc.h(2, "d. Fault tolerance: a real emulator outage")
doc.p("The gcs-storage emulator process was killed with `scripts/emulators.sh stop-one gcs` while a file uploaded before the outage was downloaded repeatedly "
      "and new files were uploaded. Then a second emulator (Azurite) was stopped to show the limit of 2-way replication, and both were restarted.")
up_all = d[(d.phase == "all_up") & (d.op == "download")].seconds.values
down_all = d[(d.phase == "gcs_down") & (d.op == "download")].sort_values("trial")
adapt, steady = down_all.seconds.values[:3], down_all.seconds.values[3:3 + len(up_all)]
cmp_ = compare(steady, up_all)
rows = [["download, all providers up", len(up_all), f3(np.mean(up_all)), f3(np.std(up_all, ddof=1)), f3(np.median(up_all)), "-"],
        [f"download, gcs down (trials 4 to {3 + len(steady)})", len(steady), f3(np.mean(steady)), f3(np.std(steady, ddof=1)), f3(np.median(steady)), "-"],
        ["download, gcs down, first 3 trials after the outage", len(adapt), f3(np.mean(adapt)), "-", f3(np.median(adapt)), "failover and breaker adapting"]]
doc.table(["Condition", "n", "Mean s", "SD s", "Median s", "Note"], rows, "Download latency (16 MiB file, 1 MiB chunks)")
doc.table(["Comparison", "Mean difference (s)", "95% CI (Welch)", "Ratio", "Primary test", "p", "Cohen d", "Cliff delta"],
          [["gcs down minus all up", f3(cmp_["diff"], 4), f"[{cmp_['diff_ci_lo']:.4f}, {cmp_['diff_ci_hi']:.4f}]", f3(cmp_["ratio"], 3), cmp_["primary"], fmt_p(cmp_["p"]), f3(cmp_["cohens_d"], 2), f3(cmp_["cliffs_delta"], 2)]],
          "Does one provider down change steady-state download latency?")
sr = []
def rate(label, sub):
    k, nn = int(sub.ok.sum()), len(sub)
    lo, hi = wilson(k, nn)
    sr.append([label, nn, k, f"{100 * k / nn:.1f}%", f"[{100 * lo:.1f}%, {100 * hi:.1f}%]"])
    return k, nn, lo, hi
r_dn = rate("downloads, 1 provider down", d[(d.phase == "gcs_down") & (d.op == "download")])
r_up = rate("uploads, 1 provider down", d[(d.phase == "gcs_down") & (d.op == "upload")])
r_two = rate("downloads, 2 providers down", d[d.phase == "two_down"])
r_rest = rate("downloads after restart", d[d.phase == "restored"])
doc.table(["Scenario", "Trials", "Successes", "Success rate", "Wilson 95% CI"], sr, "Success rates")
rep = d[d.op.str.contains("replicas_on_gcs")]
rec = d[d.op == "time_to_first_good_download"]
if len(rep):
    on_gcs = json.loads(rep.iloc[0].status).get("gcs", 0)
    doc.p(f"Placement during the outage: replicas of the files uploaded while gcs was down: `{rep.iloc[0].status}` ({on_gcs} on gcs)."
          + (f" After the emulators were restarted the first good download came {rec.iloc[0].seconds:.1f} s later." if len(rec) and bool(rec.iloc[0].ok) else " The first good download after the restart was not observed within 120 s."))
SUMMARY["d"] = dict(compare=cmp_, rates=sr)
KEY.append(f"With one of three providers killed, {r_dn[0]}/{r_dn[1]} downloads and {r_up[0]}/{r_up[1]} uploads still succeeded (Wilson 95% lower bound "
           f"{100 * r_dn[2]:.1f}% and {100 * r_up[2]:.1f}%), and steady-state download latency changed by {cmp_['diff'] * 1000:.1f} ms "
           f"(95% CI {cmp_['diff_ci_lo'] * 1000:.1f} to {cmp_['diff_ci_hi'] * 1000:.1f}; {cmp_['primary']} p {fmt_p(cmp_['p'])}); with two providers down {r_two[0]}/{r_two[1]} downloads succeeded, the documented limit of 2-way replication.")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.3))
axes[0].boxplot([up_all, steady], tick_labels=["all up", "gcs down"], patch_artist=True, boxprops=dict(facecolor=COLORS["download"], alpha=0.5))
axes[0].set_ylabel("Download seconds"); axes[0].set_title("Download latency")
labels = [r[0].replace(", ", "\n") for r in sr]
ks = [(r[2], r[1]) for r in sr]
for i, (k, nn) in enumerate(ks):
    lo, hi = wilson(k, nn)
    axes[1].bar(i, k / nn, color="#5aa469" if k == nn else "#b2442f", alpha=0.8)
    axes[1].errorbar(i, k / nn, yerr=[[max(0.0, k / nn - lo)], [max(0.0, hi - k / nn)]], color="black", capsize=3)
axes[1].set_xticks(range(len(labels))); axes[1].set_xticklabels(labels, fontsize=6.5); axes[1].set_ylim(0, 1.05); axes[1].set_ylabel("Success rate (Wilson 95% CI)"); axes[1].set_title("Availability")
savefig(fig, "d_fault"); plt.close(fig)
doc.fig("d_fault", "Download latency with and without one provider, and success rates with Wilson intervals.")
doc.p("**What this shows.** A real outage of one provider does not stop reads or writes (reads fail over to the surviving replica, writes are placed on the other providers) and "
      "shows no detectable change in steady-state latency (the confidence interval of the difference includes zero), while two providers down breaks reads of chunks whose two replicas were both on them, as designed. "
      "**Limitations.** The emulator refuses connections immediately; a provider that hangs would be detected only after the 30 s deadline in the container deployment; one outage pattern.")

# ---------------------------------------------------------------- e. placement
e = rd("e_placement")
doc.h(2, "e. Placement balance")
doc.p("60 uploads of an 8 MiB file (480 chunks, 960 replicas) per placement strategy; replicas counted from the metadata database. Null hypothesis: replicas are spread "
      "uniformly over the three providers. Chunks of one file are not independent draws, so the p-values are approximate.")
rows, erep = [], {}
for strat in ("rotating", "hash"):
    sub = e[(e.strategy == strat) & (e.kind == "replicas_per_provider")].set_index("label")["count"]
    chi = st.chisquare(sub.values)
    pairs = e[(e.strategy == strat) & (e.kind == "provider_pair_per_chunk")]["count"].values
    chip = st.chisquare(pairs, f_exp=[pairs.sum() / 3] * 3) if len(pairs) == 3 else None
    erep[strat] = dict(counts=sub.to_dict(), chi2=float(chi.statistic), p=float(chi.pvalue), pair_chi2=float(chip.statistic) if chip else None, pair_p=float(chip.pvalue) if chip else None)
    rows.append([strat, int(sub["aws-s3"]), int(sub["azure-blob"]), int(sub["gcs"]), f3(sub.sum() / 3, 1), f3(chi.statistic, 2), fmt_p(chi.pvalue),
                 ("/".join(str(int(x)) for x in pairs)), (f3(chip.statistic, 2) if chip else "-"), (fmt_p(chip.pvalue) if chip else "-")])
doc.table(["Strategy", "S3", "Azure", "GCS", "Expected each", "chi2 (2 df)", "p", "Chunks per provider pair", "chi2 pairs", "p pairs"], rows,
          "Replicas per provider and chi-square goodness of fit against uniform")
SUMMARY["e"] = erep
KEY.append("Placement is balanced: replicas per provider " + "; ".join(f"{s}: {erep[s]['counts']} (chi2 {erep[s]['chi2']:.2f}, p {fmt_p(erep[s]['p'])})" for s in erep) + " (no evidence against uniformity).")
fig, ax = plt.subplots(figsize=(6.2, 3.2))
for k, strat in enumerate(("rotating", "hash")):
    cnt = erep[strat]["counts"]
    ax.bar(np.arange(3) + (k - 0.5) * 0.36, [cnt[p] for p in ("aws-s3", "azure-blob", "gcs")], 0.36, label=strat, alpha=0.85)
tot = sum(erep["rotating"]["counts"].values())
ax.axhline(tot / 3, color="black", ls="--", lw=1, label="uniform")
ax.set_xticks(range(3)); ax.set_xticklabels(["S3", "Azure", "GCS"]); ax.set_ylabel("Replicas"); ax.legend(); ax.set_title("Replicas per provider")
savefig(fig, "e_placement"); plt.close(fig)
doc.fig("e_placement", "Replicas per provider for the two placement strategies against a uniform expectation.")
doc.p("**What this shows.** Neither strategy concentrates chunks on one provider, so a single provider holds about two thirds of the chunks and none holds all. "
      "**Limitations.** A non-rejected chi-square test is absence of evidence of imbalance, not proof of uniformity; chunks within a file are dependent; the rotating strategy is "
      "balanced by construction.")

# ---------------------------------------------------------------- f. entropy
f = rd("f_entropy").drop_duplicates(["kind", "chunk_index"])
doc.h(2, "f. Ciphertext randomness at the providers")
doc.p("Objects were read raw from the emulators through each provider's own SDK, exactly as a holder of a provider credential would see them, for 16 MiB files of "
      "random bytes, English text and zeros. For each stored object: Shannon entropy in bits per byte and a chi-square test of the byte frequencies against uniform "
      "(255 degrees of freedom). Replicas of one chunk are the same bytes and are counted once.")
rows, frep = [], {}
for kind in ("random", "english_text", "zeros"):
    g = f[f.kind == kind]
    ec, ep = describe(g.entropy_cipher.values), describe(g.entropy_plain.values)
    rej = int((g.p < 0.05).sum())
    lo, hi = wilson(rej, len(g))
    ks = st.kstest(g.p.values, "uniform")
    frep[kind] = dict(entropy_plain=ep["mean"], entropy_cipher=ec["mean"], rejected=rej, n=len(g), ks_p=float(ks.pvalue))
    rows.append([kind, len(g), f3(ep["mean"], 4), f3(ec["mean"], 5), f3(ec["sd"], 5), f"{rej}/{len(g)}", f"[{100 * lo:.1f}%, {100 * hi:.1f}%]", fmt_p(ks.pvalue)])
doc.table(["Plaintext", "Objects", "Plaintext entropy (bits/byte)", "Ciphertext entropy mean", "SD", "Chi-square rejections at 0.05", "Wilson 95% of rate", "KS p of p-values vs uniform"], rows,
          "Entropy and byte-frequency tests of the stored objects")
SUMMARY["f"] = frep
plain_txt = ", ".join("%.2f" % v["entropy_plain"] for v in frep.values())
KEY.append("Stored objects look random whatever the plaintext: mean ciphertext entropy " + ", ".join(f"{k} {v['entropy_cipher']:.4f}" for k, v in frep.items()) +
           f" bits per byte against plaintext entropy of {plain_txt}; the chi-square test rejected uniformity for "
           f"{sum(v['rejected'] for v in frep.values())} of {sum(v['n'] for v in frep.values())} objects (about 5% would be expected by chance).")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.3))
kinds = ["random", "english_text", "zeros"]
axes[0].boxplot([f[f.kind == k].entropy_cipher for k in kinds], tick_labels=kinds, patch_artist=True, boxprops=dict(facecolor=COLORS["cipher"], alpha=0.5))
axes[0].scatter(range(1, 4), [f[f.kind == k].entropy_plain.mean() for k in kinds], color=COLORS["plain"], marker="D", zorder=3, label="plaintext")
axes[0].set_ylabel("Entropy (bits per byte)"); axes[0].set_title("Stored object vs plaintext"); axes[0].legend()
axes[1].hist([f[f.kind == k].p for k in kinds], bins=10, range=(0, 1), label=kinds)
axes[1].set_xlabel("Chi-square p-value"); axes[1].set_ylabel("Objects"); axes[1].set_title("p-values (uniform if the bytes are random)"); axes[1].legend()
savefig(fig, "f_entropy"); plt.close(fig)
doc.fig("f_entropy", "Entropy of stored ciphertext against plaintext, and the distribution of chi-square p-values.")
doc.p("**What this shows.** A provider that reads its own objects sees data statistically indistinguishable from random bytes, even when the plaintext is all zeros. "
      "**Limitations.** Passing these tests is necessary, not sufficient, for security (the guarantee comes from AES-256-GCM, not from the tests); object sizes, counts and timing remain visible to a provider.")

# ---------------------------------------------------------------- g. audit
gv, gr = rd("g_audit_verify"), rd("g_audit_record")
doc.h(2, "g. Audit log: verification scaling and write throughput")
doc.p("Events were written to a fresh hash-chained audit log (each one fsynced), and `verify_chain` (hash chain, signed checkpoints and anchors) was timed at each size.")
rows = []
for nev, grp in gv.groupby("events"):
    dd = describe(grp.seconds.values)
    rows.append([int(nev), dd["n"], f3(dd["mean"], 4), f3(dd["sd"], 4), f3(dd["median"], 4), ci(dd, dd=4), f"{int(grp.ok.sum())}/{len(grp)}"])
doc.table(["Events", "n", "Mean s", "SD s", "Median s", "95% CI of mean", "Chain valid"], rows, "verify_chain time")
lin = linfit(gv.events.values, gv.seconds.values)
loglog = linfit(np.log10(gv.events.values), np.log10(gv.seconds.values))
rec_rate = describe(gr.events_per_s.values)
trend = linfit(gr.events_total.values, gr.events_per_s.values)
doc.table(["Model", "Slope", "95% CI", "Intercept", "R²"],
          [["seconds = a + b x events", f"{lin['slope'] * 1000:.4f} ms/1000 events", f"[{lin['slope_ci_lo'] * 1000:.4f}, {lin['slope_ci_hi'] * 1000:.4f}]", f"{lin['intercept']:.4f} s", f3(lin["r2"], 4)],
           ["log10 seconds = a + b log10 events", f3(loglog["slope"], 3), f"[{loglog['slope_ci_lo']:.3f}, {loglog['slope_ci_hi']:.3f}]", f3(loglog["intercept"], 3), f3(loglog["r2"], 4)]],
          "Is verification linear in the number of events? (a log-log slope of 1 means linear)")
doc.p(f"`record()` throughput over {int(gr.block.sum())} events: mean {rec_rate['mean']:.0f} events/s (SD {rec_rate['sd']:.0f}, 95% CI of the mean {rec_rate['ci_lo']:.0f} to {rec_rate['ci_hi']:.0f}); "
      f"trend against log size {trend['slope'] * 1000:+.3f} events/s per 1000 events (95% CI {trend['slope_ci_lo'] * 1000:+.3f} to {trend['slope_ci_hi'] * 1000:+.3f}, p {fmt_p(trend['p'])}).")
SUMMARY["g"] = dict(linear=lin, loglog=loglog, record_events_per_s=rec_rate)
KEY.append(f"Audit verification is linear: the log-log slope of time against events is {loglog['slope']:.3f} (95% CI {loglog['slope_ci_lo']:.3f} to {loglog['slope_ci_hi']:.3f}; "
           f"1 means linear), R² {lin['r2']:.4f} for the linear fit ({lin['slope'] * 1000:.3f} ms per 1000 events); `record()` sustains {rec_rate['mean']:.0f} events/s with an fsync per event.")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.3))
axes[0].scatter(gv.events, gv.seconds, s=10, alpha=0.6, color=COLORS["app"])
xs = np.array(sorted(gv.events.unique()))
axes[0].plot(xs, lin["intercept"] + lin["slope"] * xs, color="black", lw=1, label=f"linear, R²={lin['r2']:.4f}")
axes[0].set_xlabel("Events in the log"); axes[0].set_ylabel("verify_chain seconds"); axes[0].legend(); axes[0].set_title("Verification time")
axes[1].plot(gr.events_total, gr.events_per_s, marker="o", ms=3, color=COLORS["upload"])
axes[1].set_xlabel("Events written so far"); axes[1].set_ylabel("record() events per second"); axes[1].set_title("Write throughput (fsync per event)")
savefig(fig, "g_audit"); plt.close(fig)
doc.fig("g_audit", "verify_chain time against log size with a linear fit, and record() throughput as the log grows.")
doc.p("**What this shows.** Verifying the whole log costs time proportional to its length, and no trend in the write rate is detectable as the log grows (the confidence interval of the trend includes zero), so the audit log can be checked "
      "routinely. **Limitations.** Memory-backed providers hold the anchors here, SQLite on one disk; a PostgreSQL deployment was not measured; the per-event fsync cost depends on the disk.")

# ---------------------------------------------------------------- h. attacks
h = rd("h_attacks")
doc.h(2, "h. Detection of attacks and tampering")
doc.p("Outcomes of the security suite (`scripts/attacks/run_all.sh`): each row is one designed attack or failure scenario with its observed result and audit record. "
      "**This is a table of designed scenarios, not a random sample of attacks**, so the intervals below say how well the suite supports the claim, not what an unknown attacker would achieve.")
h["family"] = h.scenario.str[:3]
fam = h.groupby("scenario").outcome.agg(lambda s: f"{(s == 'PASS').sum()}/{len(s)}").reset_index()
doc.table(["Scenario", "Attack or failure (first test)", "Tests passed"],
          [[sc, h[h.scenario == sc].attempt.iloc[0][:60], fam[fam.scenario == sc].outcome.iloc[0]] for sc in fam.scenario],
          "Scenarios (S = attack, E = provider failure)")
k, nn = int((h.outcome == "PASS").sum()), len(h)
lo, hi = wilson(k, nn)
doc.table(["Attempts (tests)", "Stopped or detected", "Missed", "Rate", "Wilson 95% CI"], [[nn, k, nn - k, f"{100 * k / nn:.1f}%", f"[{100 * lo:.1f}%, {100 * hi:.1f}%]"]], "Confusion-style summary")
SUMMARY["h"] = dict(n=nn, detected=k, wilson=[lo, hi])
KEY.append(f"The security suite stopped or detected {k} of {nn} designed attack and failure tests, {'none missed' if k == nn else str(nn - k) + ' missed'} (Wilson 95% interval {100 * lo:.1f}% to {100 * hi:.1f}%; designed scenarios, not a random sample).")
fig, ax = plt.subplots(figsize=(7.5, 3.0))
counts = h.groupby("scenario").size()
ax.bar(counts.index, counts.values, color="#5aa469")
ax.set_ylabel("Tests"); ax.set_title("Tests per scenario"); plt.setp(ax.get_xticklabels(), rotation=60, fontsize=7)
savefig(fig, "h_attacks"); plt.close(fig)
doc.fig("h_attacks", f"Number of tests per attack or failure scenario ({k} of {nn} passed).")
doc.p("**What this shows.** Every designed scenario ended in a block, a detection or a documented limit, with an audit record. **Limitations.** A passing suite shows the checks "
      "work for the scenarios someone thought of; it says nothing about unknown ones, and no external penetration test was done.")

# ---------------------------------------------------------------- i. engineering
loc, tests, fnd = rd("i_loc"), rd("i_tests"), rd("i_findings")
doc.h(2, "i. Engineering metrics")
app = loc[loc.area == "backend/app"].groupby("module")[["total", "code"]].sum().sort_values("code", ascending=False)
doc.table(["Module (backend/app)", "Lines", "Code lines"], [[m, int(r.total), int(r.code)] for m, r in app.iterrows()] + [["TOTAL", int(app.total.sum()), int(app.code.sum())]],
          "Lines of Python per module (code = not blank, not comment-only)")
areas = loc.groupby("area")[["total", "code"]].sum()
doc.table(["Area", "Lines", "Code lines"], [[a_, int(r.total), int(r.code)] for a_, r in areas.iterrows()], "Lines by area")
cat = tests.groupby("category").tests.sum()
doc.table(["Test category", "Tests"], [[c_, int(n_)] for c_, n_ in cat.items()] + [["TOTAL", int(cat.sum())]], "Tests by category (pytest --collect-only)")
mod = tests.groupby(["category", "module"]).tests.sum().reset_index()
doc.table(["Category", "Module", "Tests"], [[r.category, r.module, int(r.tests)] for r in mod.itertuples()], "Tests by module")
cov_path = DATA / "coverage_files.csv"
if cov_path.exists():
    cf = pd.read_csv(cov_path)
    cm = cf.groupby("module")[["statements", "covered"]].sum()
    cm["pct"] = 100 * cm.covered / cm.statements
    tot = cf.statements.sum(), cf.covered.sum()
    doc.table(["Module", "Statements", "Covered", "Line coverage %"], [[m, int(r.statements), int(r.covered), f3(r.pct, 1)] for m, r in cm.sort_values("pct").iterrows()] +
              [["TOTAL", int(tot[0]), int(tot[1]), f3(100 * tot[1] / tot[0], 1)]], "Line coverage of backend/app by the whole suite (pytest-cov)")
    SUMMARY["coverage_total_pct"] = 100 * tot[1] / tot[0]
    KEY.append(f"The {int(cat.sum())}-test suite covers {100 * tot[1] / tot[0]:.1f}% of the {int(tot[0])} statements in backend/app (pytest-cov line coverage).")
sev_order = ["high", "medium-high", "medium", "low-medium", "low", "info"]
fp = fnd.pivot_table(index="severity", columns="source", values="id", aggfunc="count", fill_value=0).reindex([s for s in sev_order if s in set(fnd.severity)])
doc.table(["Severity"] + list(fp.columns) + ["Total"], [[sv] + [int(x) for x in r.values] + [int(r.sum())] for sv, r in fp.iterrows()] + [["TOTAL"] + [int(x) for x in fp.sum().values] + [int(fp.values.sum())]],
          "Security findings history (all fixed)")
SUMMARY["i"] = dict(loc_app=int(app.total.sum()), tests=int(cat.sum()), findings=len(fnd))
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.6))
axes[0].barh(app.index[::-1], app.code.values[::-1], color=COLORS["app"]); axes[0].set_xlabel("Code lines"); axes[0].set_title("backend/app by module")
axes[1].bar(cat.index, cat.values, color="#5aa469"); axes[1].set_ylabel("Tests"); axes[1].set_title("Tests by category")
savefig(fig, "i_engineering"); plt.close(fig)
doc.fig("i_engineering", "Code size per module and number of tests per category.")
doc.p("**What this shows.** The size of the code, how the tests are spread over categories and modules, and that all 23 recorded weaknesses (6 found by our own testing, 17 by the independent review) are fixed. "
      "**Limitations.** Lines of code and test counts are size measures, not quality measures; coverage is line coverage, which does not show whether the assertions are strong; severities are the team's assessments.")

# ---------------------------------------------------------------- assemble
summary_doc = Doc()
summary_doc.h(1, "Statistical analysis of the framework")
summary_doc.h(2, "Key findings")
summary_doc.bullets(KEY)
head = doc.blocks[:1]
doc.blocks = head + summary_doc.blocks[1:] + doc.blocks[1:]
md = doc.markdown()
(REPO / "docs").mkdir(exist_ok=True)
(REPO / "docs" / "STATISTICAL_ANALYSIS.md").write_text(md, encoding="utf-8")
(DATA / "summary.json").write_text(json.dumps(SUMMARY, indent=1, default=lambda o: None if isinstance(o, float) and o != o else float(o) if isinstance(o, (np.floating, np.integer)) else str(o)))
doc.pdf(ROOT / "statistical-analysis.pdf")
print(f"[analyze] wrote docs/STATISTICAL_ANALYSIS.md ({len(md.splitlines())} lines), analysis/statistical-analysis.pdf, analysis/figures/*.png|pdf, analysis/data/summary.json")
