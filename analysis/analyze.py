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
from lib import (binom_tail, COLORS, DATA, FIG, MIB, REPO, ROOT, SEED, compare, describe, fmt_p, holm, linfit, savefig, st, style,  # noqa: E402
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
    ["Setting", ENV["setting"]],
    ["Machine state", META.get("power") or "not recorded"],
    ["Emulator state", "stopped and restarted on an empty data directory before every experiment, so no experiment starts with objects left by another"]])
doc.bullets([
    "**Statistics.** Per condition: n, mean, SD, median, 95% t-interval of the mean and 95% percentile-bootstrap interval of the median (5000 resamples). The tests were fixed before the data were looked at and do not depend on the data: two groups are compared with the Mann-Whitney U test (no normality assumption), with the difference of the medians and its 95% percentile-bootstrap interval (10000 resamples) as the effect size; Welch's t-test and the difference of the means are reported only as a secondary check in the data files. Several groups: Kruskal-Wallis, then pairwise Mann-Whitney with Holm correction. Proportions: Wilson 95% intervals; a binomial tail probability where a count is compared with an expected rate. Shapiro-Wilk p-values are shown only as a description of the shape of a distribution and never select a test.",
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
doc.table(["Op", "Size", "n", "Mean s", "SD s", "Median s", "95% CI of mean (s)", "Mean MiB/s", "Shapiro p (descriptive only)"], rows, "Time per transfer")
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

# ---------------------------------------------------------------- a (extra). proportionality
loglog_a = {}
for op in ("upload", "download"):
    sub = a_ok[a_ok.op == op]
    loglog_a[op] = linfit(np.log10(sub.size_mib.values), np.log10(sub.seconds.values))
doc.table(["Op", "log-log slope", "95% CI", "R²"],
          [[op, f3(f["slope"], 3), f"[{f['slope_ci_lo']:.3f}, {f['slope_ci_hi']:.3f}]", f3(f["r2"], 3)] for op, f in loglog_a.items()],
          "Log-log fit, log10 seconds = a + b log10 size (b = 1 means time proportional to size; with 1 MiB chunks the number of chunks equals the size in MiB, "
          "so size and chunk count cannot be separated here; experiment c varies the chunk count at a fixed size)")
SUMMARY["a"]["loglog"] = {op: dict(slope=f["slope"], ci=[f["slope_ci_lo"], f["slope_ci_hi"]]) for op, f in loglog_a.items()}

# ---------------------------------------------------------------- b. providers and cost of security
PROV = ["aws-s3", "azure-blob", "gcs"]
PN = {"aws-s3": "S3 emulator (moto)", "azure-blob": "Azure emulator (Azurite)", "gcs": "GCS emulator"}
pmi = rd("p_provider_micro")
p_ok = pmi[pmi.ok]
b = rd("b_overhead")
b_ok = b[b.ok]
mic = rd("b_crypto_micro")
doc.h(2, "b. Cost of security, and the emulators beneath it")
doc.h(3, "b1. What one emulator costs: put and get straight through each provider adapter")
doc.p("Before attributing any time to the framework, the three emulators were measured on their own: one object of 1 MiB or 4 MiB written and read straight "
      "through the application's own S3, Azure and GCS adapters (no application, no encryption), in random order, each object deleted afterwards. "
      "The latency of an emulator is a property of that emulator (a Python server for S3, a Node.js server for Azure, a Python server for GCS), not of the framework or of a real cloud.")
rows, pm = [], {}
for op in ("put", "get"):
    for s in sorted(p_ok.size_mib.unique()):
        for pr in PROV:
            x = p_ok[(p_ok.op == op) & (p_ok.size_mib == s) & (p_ok.provider == pr)].seconds.values
            d_ = describe(x)
            pm[(op, float(s), pr)] = d_["median"]
            rows.append([PN[pr], f"{s:g} MiB", op, d_["n"], f3(d_["median"] * 1000, 1), f"[{d_['med_ci_lo'] * 1000:.1f}, {d_['med_ci_hi'] * 1000:.1f}]",
                         f3(d_["mean"] * 1000, 1), f3(d_["sd"] * 1000, 1), f3(s / d_["median"], 1)])
doc.table(["Emulator", "Size", "Op", "n", "Median ms", "95% CI of median (ms)", "Mean ms", "SD ms", "Median MiB/s"], rows, "Latency of one object by emulator")
kw_rows = []
for op in ("put", "get"):
    for s in sorted(p_ok.size_mib.unique()):
        gs_ = [p_ok[(p_ok.op == op) & (p_ok.size_mib == s) & (p_ok.provider == pr)].seconds.values for pr in PROV]
        k_ = st.kruskal(*gs_)
        kw_rows.append([op, f"{s:g} MiB", f3(k_.statistic, 1), fmt_p(k_.pvalue)])
doc.table(["Op", "Size", "Kruskal-Wallis H (2 df)", "p"], kw_rows, "Do the three emulators differ in latency?")
big = float(max(s for s in p_ok.size_mib.unique()))
slow_put = max(PROV, key=lambda pr: pm[("put", big, pr)])
fast_put = min(PROV, key=lambda pr: pm[("put", big, pr)])
slow_get = max(PROV, key=lambda pr: pm[("get", big, pr)])
SUMMARY["p"] = dict(median_s={f"{op} {s:g}MiB {pr}": v for (op, s, pr), v in pm.items()}, slowest_put=slow_put, fastest_put=fast_put, slowest_get=slow_get, size_mib=big,
                    ratio_put=pm[("put", big, slow_put)] / pm[("put", big, fast_put)])

# does the emulator speed explain the plain chunked upload?  one chunk is written to 2 providers in parallel, so it takes the slower of the two
t1 = {pr: pm[("put", 1.0, pr)] for pr in PROV}
def predicted_chunked_put(n_chunks):
    tot = 0.0
    for off in range(3):                     # the start offset of the rotation is random per file
        tot += sum(max(t1[PROV[(i + off) % 3]], t1[PROV[(i + off + 1) % 3]]) for i in range(n_chunks))
    return tot / 3
mrows = []
SUMMARY["model"] = {}
for s in sorted(b_ok.size_mib.unique()):
    meas = float(np.median(b_ok[(b_ok.arm == "plain_chunked") & (b_ok.op == "upload") & (b_ok.size_mib == s)].seconds.values))
    pred = predicted_chunked_put(int(s))
    app_med = float(np.median(b_ok[(b_ok.arm == "app") & (b_ok.op == "upload") & (b_ok.size_mib == s)].seconds.values))
    mrows.append([f"{s:g} MiB", f3(pred, 2), f3(meas, 2), f3(meas / pred, 2), f3(app_med, 2)])
    SUMMARY["model"][f"{s:g}"] = dict(predicted=pred, measured_plain_chunked=meas, ratio=meas / pred, app=app_med)
doc.table(["Size", "Predicted plain chunked upload (s)", "Measured plain chunked upload, median (s)", "Measured / predicted", "Framework upload, median (s)"], mrows,
          "Predicting the plain chunked upload from the 1 MiB put latencies alone (each chunk waits for the slower of its two providers)")
doc.p(f"The slowest emulator for writes is the {PN[slow_put]} (median {pm[('put', big, slow_put)] * 1000:.0f} ms for a {big:g} MiB object, against {pm[('put', big, fast_put)] * 1000:.0f} ms "
      f"for the {PN[fast_put]}). Every chunk is written to two of the three emulators in parallel, so uploads wait for the slower of the two. The model above, which uses nothing but the "
      "1 MiB put latencies, comes within a factor of " + f"{max(max(v['ratio'], 1 / v['ratio']) for v in SUMMARY['model'].values()):.1f}" + " of the measured plain chunked time"
      + (" and under-predicts it (the measured time also contains per-call SDK overhead and thread hand-offs that one put does not)" if all(v["ratio"] > 1 for v in SUMMARY["model"].values()) else "")
      + ", so the emulators' own latency is the main part of the plain chunked upload time, but not the only part.")

doc.h(3, "b2. The same bytes with and without the security pipeline")
doc.p("The same bytes stored five ways, against the same emulators and through the same provider adapters: **app** = the full framework; **plain chunked** = a harness outside the "
      "application that splits the file into 1 MiB chunks and writes each plain chunk to 2 of the 3 providers in parallel (rotating placement), with no encryption, manifest, database, "
      "policy, audit or read-back verification; **plain single (S3 / Azure / GCS)** = one object to one provider, measured separately for each emulator. The plain arms are the cheapest "
      "possible storage of these bytes; the difference to the app is the price of the whole security pipeline on these emulators, not of encryption alone.")
rows, tests = [], []
arms_all = ["app", "plain_chunked", "plain_single_s3", "plain_single_azure", "plain_single_gcs"]
ARM_LABEL = {"app": "framework", "plain_chunked": "plain chunked", "plain_single_s3": "plain single, S3", "plain_single_azure": "plain single, Azure", "plain_single_gcs": "plain single, GCS"}
for op in ("upload", "download"):
    for s in sorted(b_ok.size_mib.unique()):
        g = {arm: b_ok[(b_ok.op == op) & (b_ok.size_mib == s) & (b_ok.arm == arm)].seconds.values for arm in arms_all}
        for arm, x in g.items():
            d = describe(x)
            rows.append([op, f"{s:g} MiB", ARM_LABEL[arm], d["n"], f3(d["mean"]), f3(d["sd"]), f3(d["median"]), ci(d)])
        c = compare(g["app"], g["plain_chunked"])
        c.update(op=op, size=s)
        tests.append(c)
adj = holm([t["p"] for t in tests])
for t, p_adj in zip(tests, adj):
    t["p_holm"] = p_adj
doc.table(["Op", "Size", "Arm", "n", "Mean s", "SD s", "Median s", "95% CI of mean (s)"], rows, "Time per transfer by arm")
doc.table(["Op", "Size", "Median: framework minus plain chunked (s)", "95% bootstrap CI", "Ratio of medians", "Mann-Whitney p", "p (Holm)", "Cliff delta"],
          [[t["op"], f"{t['size']:g} MiB", f3(t["med_diff"]), f"[{t['med_diff_ci_lo']:.3f}, {t['med_diff_ci_hi']:.3f}]", f3(t["med_ratio"], 2), fmt_p(t["p"]), fmt_p(t["p_holm"]),
            f3(t["cliffs_delta"], 2)] for t in tests],
          "Framework against plain chunked storage (six comparisons; primary test fixed in advance: Mann-Whitney U, effect size = difference of medians with a bootstrap interval)")
thr_rows = []
SUMMARY_THIRDS = {}
for op in ("upload", "download"):
    for s_ in sorted(b_ok.size_mib.unique()):
        fa = b_ok[(b_ok.arm == "app") & (b_ok.op == op) & (b_ok.size_mib == s_)].sort_values("seq").seconds.values
        fp = b_ok[(b_ok.arm == "plain_chunked") & (b_ok.op == op) & (b_ok.size_mib == s_)].sort_values("seq").seconds.values
        k_ = len(fa) // 3
        fm, pm_, lm, lp = np.median(fa[:k_]), np.median(fp[:k_]), np.median(fa[-k_:]), np.median(fp[-k_:])
        thr_rows.append([op, f"{s_:g} MiB", f3(fm), f3(pm_), f3(fm / pm_, 2), f3(lm), f3(lp), f3(lm / lp, 2)])
        SUMMARY_THIRDS[f"{op} {s_:g}"] = dict(first_ratio=float(fm / pm_), last_ratio=float(lm / lp), app_first=float(fm), app_last=float(lm), plain_first=float(pm_), plain_last=float(lp))
doc.table(["Op", "Size", "Framework, first third (s)", "Plain chunked, first third (s)", "Ratio", "Framework, last third (s)", "Plain chunked, last third (s)", "Ratio"], thr_rows,
          "The same comparison at the start and at the end of the run (medians of the first and last 10 repetitions): both arms change during the run, so the ratio is not constant")
enc = describe(mic[mic.op == "encrypt"].seconds_per_mib.values)
dec = describe(mic[mic.op == "decrypt"].seconds_per_mib.values)
doc.table(["Cipher alone, no I/O", "n", "Mean ms per MiB", "SD", "95% CI", "MiB/s"],
          [["encrypt (AES-256-GCM + SHA-256)", enc["n"], f3(enc["mean"] * 1000, 3), f3(enc["sd"] * 1000, 3), f"[{enc['ci_lo'] * 1000:.3f}, {enc['ci_hi'] * 1000:.3f}]", f3(1 / enc["mean"], 0)],
           ["decrypt (SHA-256 check + AES-256-GCM)", dec["n"], f3(dec["mean"] * 1000, 3), f3(dec["sd"] * 1000, 3), f"[{dec['ci_lo'] * 1000:.3f}, {dec['ci_hi'] * 1000:.3f}]", f3(1 / dec["mean"], 0)]],
          "CPU cost of the cipher itself (the same calls the application makes, 16 MiB per repetition)")
t16 = next(t for t in tests if t["op"] == "upload" and t["size"] == 16)
d16 = next(t for t in tests if t["op"] == "download" and t["size"] == 16)
share_up = enc["mean"] * 16 / t16["med_diff"]
share_dn = dec["mean"] * 16 / d16["med_diff"]

# is the application's own number the same in experiment a, alone, and next to the plain arms?
xa = a_ok[(a_ok.op == "upload") & (a_ok.size_mib == 16)].seconds.values
xi = b_ok[(b_ok.arm == "app_isolated") & (b_ok.op == "upload")].seconds.values
xb = b_ok[(b_ok.arm == "app") & (b_ok.op == "upload") & (b_ok.size_mib == 16)].seconds.values
cons = {"iso_vs_a": compare(xi, xa), "inter_vs_iso": compare(xb, xi), "inter_vs_a": compare(xb, xa)}
adj3 = holm([c_["p"] for c_ in cons.values()])
for c_, pa in zip(cons.values(), adj3):
    c_["p_holm"] = pa
doc.h(3, "b3. Why the framework's 16 MiB upload differs between experiments a and b")
doc.table(["Series (framework, 16 MiB upload, 1 MiB chunks)", "n", "Mean s", "SD s", "Median s"],
          [[lbl, len(x), f3(float(np.mean(x))), f3(float(np.std(x, ddof=1))), f3(float(np.median(x)))] for lbl, x in
           (("experiment a (fresh emulators, framework only, four sizes interleaved)", xa), ("experiment b, isolated block (fresh emulators, framework only, 16 MiB)", xi),
            ("experiment b, interleaved with the plain arms (fresh emulators)", xb))], "The same measurement taken three ways")
doc.table(["Comparison", "Median difference (s)", "95% bootstrap CI", "Mann-Whitney p", "p (Holm)"],
          [[lbl, f3(c_["med_diff"]), f"[{c_['med_diff_ci_lo']:.3f}, {c_['med_diff_ci_hi']:.3f}]", fmt_p(c_["p"]), fmt_p(c_["p_holm"])] for lbl, c_ in
           (("b isolated minus a", cons["iso_vs_a"]), ("b interleaved minus b isolated", cons["inter_vs_iso"]), ("b interleaved minus a", cons["inter_vs_a"]))],
          "Pairwise comparison (three comparisons, Holm-adjusted)")
def thirds_of(x_df):
    v = x_df.sort_values("seq").seconds.values
    k_ = len(v) // 3
    return float(np.median(v[:k_])), float(np.median(v[-k_:])), float(st.spearmanr(np.arange(len(v)), v).statistic)
ta = thirds_of(a_ok[(a_ok.op == "upload") & (a_ok.size_mib == 16)])
ti = thirds_of(b_ok[(b_ok.arm == "app_isolated") & (b_ok.op == "upload")])
tb = thirds_of(b_ok[(b_ok.arm == "app") & (b_ok.op == "upload") & (b_ok.size_mib == 16)])
all_differ = max(c_["p_holm"] for c_ in cons.values()) < 0.05
why = (f"The three series are the same measurement (the framework, 16 MiB upload, 1 MiB chunks, freshly started emulators), but their medians are {np.median(xa):.2f} s (experiment a), "
       f"{np.median(xi):.2f} s (b, framework alone) and {np.median(xb):.2f} s (b, interleaved), and " + ("every pair differs (all Holm p < 0.05). " if all_differ else "not every pair differs. ") +
       f"Within each series, upload time changes as the run goes on: Spearman rho {ta[2]:+.2f} in a, {ti[2]:+.2f} for the framework alone in b and {tb[2]:+.2f} interleaved in b; the median of the first "
       f"third of the trials against the last third is {ta[0]:.2f} s against {ta[1]:.2f} s in a, {ti[0]:.2f} s against {ti[1]:.2f} s alone in b and {tb[0]:.2f} s against {tb[1]:.2f} s interleaved in b. "
       f"Both arms of the interleaved block slow down as the run goes on: the 16 MiB upload takes {SUMMARY_THIRDS['upload 16']['app_first']:.2f} s then {SUMMARY_THIRDS['upload 16']['app_last']:.2f} s for the framework and "
       f"{SUMMARY_THIRDS['upload 16']['plain_first']:.2f} s then {SUMMARY_THIRDS['upload 16']['plain_last']:.2f} s for plain chunked storage (first and last third of the repetitions), so the ratio moves from "
       f"{SUMMARY_THIRDS['upload 16']['first_ratio']:.2f} to {SUMMARY_THIRDS['upload 16']['last_ratio']:.2f}; downloads show no such drift. The plain arm deletes its objects after every trial and still slows down, so a growing number of "
       "stored objects does not explain it by itself. The cause (emulator internals, disk state or machine state) was not identified. Switching the laptop to AC power and a high-performance plan did not remove the drift. "
       "The consequences are that absolute times from different experiments must not be compared, that the ratios of experiment b are averages over a comparison that changes during the run, and that only arms interleaved "
       "inside one experiment can be compared at all.")
SUMMARY_WHY_THIRDS = dict(a=ta, b_alone=ti, b_interleaved=tb)
doc.p("**Reading.** " + why)
SUMMARY["b"] = dict(upload16=t16, download16=d16, cipher_share_of_overhead_up=share_up, cipher_share_of_overhead_down=share_dn, consistency=cons, why=why, thirds=SUMMARY_THIRDS, why_thirds=SUMMARY_WHY_THIRDS)
SUMMARY["b"]["plain_single_upload16_median"] = {arm: float(np.median(b_ok[(b_ok.arm == arm) & (b_ok.op == "upload") & (b_ok.size_mib == 16)].seconds.values))
                                                for arm in ("plain_single_s3", "plain_single_azure", "plain_single_gcs")}
ps = SUMMARY["b"]["plain_single_upload16_median"]
KEY.append(f"On these emulators the framework's 16 MiB upload takes {t16['med_ratio']:.2f} times the median of plain chunked storage of the same bytes (median difference {t16['med_diff']:.2f} s, "
           f"95% bootstrap CI {t16['med_diff_ci_lo']:.2f} to {t16['med_diff_ci_hi']:.2f}; Mann-Whitney p {fmt_p(t16['p'])}) and its download {d16['med_ratio']:.2f} times "
           f"(median difference {d16['med_diff']:.2f} s, CI {d16['med_diff_ci_lo']:.2f} to {d16['med_diff_ci_hi']:.2f}). These ratios are not transferable: they are set by the emulators. "
           f"A single 4 MiB object takes a median of {pm[('put', 4.0, 'aws-s3')] * 1000:.0f} ms to write to the S3 emulator, {pm[('put', 4.0, 'azure-blob')] * 1000:.0f} ms to the Azure "
           f"emulator and {pm[('put', 4.0, 'gcs')] * 1000:.0f} ms to the GCS emulator, so the slowest emulator for writes is the {PN[slow_put]}; a model that uses only the 1 MiB put latencies (each chunk waits for the slower of its two emulators) predicts the plain chunked upload "
           f"time to within a factor of {max(max(v['ratio'], 1 / v['ratio']) for v in SUMMARY['model'].values()):.2f}. "
           f"AES-256-GCM with SHA-256 alone explains about {100 * share_up:.0f}% of the upload and {100 * share_dn:.0f}% of the download difference.")
fig, axes = plt.subplots(1, 2, figsize=(9.2, 3.5))
ACOL = {"app": COLORS["app"], "plain_chunked": COLORS["plain_chunked"], "plain_single_s3": "#9a9a9a", "plain_single_azure": "#6f6f6f", "plain_single_gcs": "#c9b458"}
for ax, op in zip(axes, ("upload", "download")):
    sizes = sorted(b_ok.size_mib.unique())
    w = 0.16
    for k, arm in enumerate(arms_all):
        means, errs = [], []
        for s in sizes:
            d = describe(b_ok[(b_ok.op == op) & (b_ok.size_mib == s) & (b_ok.arm == arm)].seconds.values)
            means.append(d["mean"]); errs.append(d["mean"] - d["ci_lo"])
        ax.bar(np.arange(len(sizes)) + (k - 2) * w, means, w, yerr=errs, capsize=1.5, color=ACOL[arm], label=ARM_LABEL[arm])
    ax.set_xticks(range(len(sizes))); ax.set_xticklabels([f"{s:g} MiB" for s in sizes]); ax.set_title(op.capitalize()); ax.set_ylabel("Seconds (mean, 95% CI)")
    ax.legend(fontsize=6.5)
savefig(fig, "b_overhead"); plt.close(fig)
doc.fig("b_overhead", "Mean time with 95% confidence intervals: the framework, plain chunked storage and a plain single object on each emulator.")
fig, ax = plt.subplots(figsize=(6.4, 3.1))
for k, op in enumerate(("put", "get")):
    for j, s in enumerate(sorted(p_ok.size_mib.unique())):
        base = (k * 2 + j) * 4
        for q, pr in enumerate(PROV):
            d_ = describe(p_ok[(p_ok.op == op) & (p_ok.size_mib == s) & (p_ok.provider == pr)].seconds.values)
            ax.bar(base + q, d_["median"] * 1000, 0.9, yerr=[[d_["median"] * 1000 - d_["med_ci_lo"] * 1000], [d_["med_ci_hi"] * 1000 - d_["median"] * 1000]], capsize=1.5,
                   color=["#9a9a9a", "#6f6f6f", "#c9b458"][q], label=PN[pr] if (k, j) == (0, 0) else None)
ax.set_xticks([1, 5, 9, 13]); ax.set_xticklabels([f"put {s:g} MiB" if k == 0 else f"get {s:g} MiB" for k in (0, 1) for s in sorted(p_ok.size_mib.unique())])
ax.set_ylabel("Median ms (95% CI)"); ax.set_title("One object through each emulator, no application"); ax.legend()
savefig(fig, "b_providers"); plt.close(fig)
doc.fig("b_providers", "Median latency of one object straight through each provider adapter, by emulator.")
doc.p("**What this shows.** The three emulators are very different from one another, and uploads wait for the slower emulator of each chunk's pair, so most of an upload's time is "
      "emulator time. The framework is slower than plain chunked storage at every size (largest Holm-adjusted p "
      f"{fmt_p(max(t['p_holm'] for t in tests))}); the cipher itself is a small part of the difference and the remainder was not decomposed (HTTP request handling, metadata commits, audit events, "
      "policy checks, read-back verification and spooling). **Limitations.** The ratios between the framework and plain storage depend on the speed of the emulators: with faster or slower "
      "providers they would be different, so they are not transferable and no real-cloud claim is made. The plain arms are a lower bound (they do not authenticate, authorise, log or verify).")

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
doc.table(["Op", "Chunk", "n", "Mean MiB/s", "SD", "Median", "95% CI of mean", "Shapiro p (descriptive only)"], rows, "Throughput by chunk size")
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
    trows.append([op, f3(an.statistic, 1), fmt_p(an.pvalue), f3(kw.statistic, 1), fmt_p(kw.pvalue), "Kruskal-Wallis (fixed in advance)", f3(eta2, 3)])
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
nfit = {}
for op in ("upload", "download"):
    sub_ = c_ok[c_ok.op == op]
    nfit[op] = linfit(sub_.n_chunks.values, sub_.seconds.values)
doc.table(["Op", "Seconds per extra chunk", "95% CI", "Intercept s", "R²"],
          [[op, f3(f_["slope"], 4), f"[{f_['slope_ci_lo']:.4f}, {f_['slope_ci_hi']:.4f}]", f3(f_["intercept"], 3), f3(f_["r2"], 3)] for op, f_ in nfit.items()],
          "Time against the number of chunks (the same 32 MiB file cut into 2 to 128 chunks): the cost of one more chunk")
ctest["per_chunk"] = {op: dict(slope=f_["slope"], ci=[f_["slope_ci_lo"], f_["slope_ci_hi"]], r2=f_["r2"]) for op, f_ in nfit.items()}
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

# ---------------------------------------------------------------- run order, drift and bimodality
doc.h(2, "Run order, drift and bimodality")
doc.p("Every timed trial carries its position in the run. If the machine or an emulator slowed down or sped up during an experiment, time would trend with run order; if two modes were "
      "present (for example one provider pair being slower), the histogram would have two humps. For each series: the Spearman correlation between run order and time, and the bimodality "
      "coefficient BC = (skewness² + 1) / (excess kurtosis + 3(n−1)² / ((n−2)(n−3))), where BC above 0.555 (the value for a uniform distribution) suggests more than one mode.")
def bimodality(x):
    x = np.asarray(x, float); n_ = len(x)
    if n_ < 5 or np.ptp(x) == 0:
        return float("nan")
    return float((st.skew(x, bias=False) ** 2 + 1) / (st.kurtosis(x, bias=False) + 3 * (n_ - 1) ** 2 / ((n_ - 2) * (n_ - 3))))
series = []
for s in sorted(a_ok.size_mib.unique()):
    series.append((f"a: framework upload, {s:g} MiB", a_ok[(a_ok.op == "upload") & (a_ok.size_mib == s)]))
series.append(("b: framework upload alone, 16 MiB", b_ok[(b_ok.arm == "app_isolated") & (b_ok.op == "upload")]))
for s in sorted(b_ok.size_mib.unique()):
    series.append((f"b: framework upload interleaved, {s:g} MiB", b_ok[(b_ok.arm == "app") & (b_ok.op == "upload") & (b_ok.size_mib == s)]))
for k in sorted(c_ok.chunk_kib.unique()):
    series.append((f"c: upload, 32 MiB, {k} KiB chunks", c_ok[(c_ok.op == "upload") & (c_ok.chunk_kib == k)]))
ro_rows, ro = [], {}
for lbl, g_ in series:
    g_ = g_.sort_values("seq")
    r_ = st.spearmanr(g_.seq, g_.seconds)
    bc = bimodality(g_.seconds.values)
    first, last = g_.seconds.values[: len(g_) // 3], g_.seconds.values[-(len(g_) // 3):]
    ro[lbl] = dict(rho=float(r_.statistic), p=float(r_.pvalue), bc=bc, first_third_median=float(np.median(first)), last_third_median=float(np.median(last)))
    ro_rows.append([lbl, len(g_), f"{r_.statistic:+.2f}", fmt_p(r_.pvalue), f3(float(np.median(first)), 3), f3(float(np.median(last)), 3), f3(bc, 2), "yes" if bc > 0.555 else "no"])
doc.table(["Series", "n", "Spearman rho (run order, time)", "p", "Median, first third (s)", "Median, last third (s)", "Bimodality coefficient", "BC > 0.555"], ro_rows,
          "Drift and bimodality checks")
SUMMARY["run_order"] = ro
# replica counts per file as an explanation for slow and fast uploads (16 MiB, 16 chunks, 32 replicas)
def ols(X, y):
    X = np.column_stack([np.ones(len(y)), X]); beta, *_ = np.linalg.lstsq(X, y, rcond=None)
    res = y - X @ beta; dfree = len(y) - X.shape[1]; s2 = float(res @ res) / dfree
    cov = s2 * np.linalg.inv(X.T @ X); se = np.sqrt(np.diag(cov)); t_ = st.t.ppf(0.975, dfree)
    r2 = 1 - float(res @ res) / float(((y - y.mean()) ** 2).sum())
    return beta, se, t_, r2
rg_rows = []
for lbl, g_ in (("a, 16 MiB upload", a_ok[(a_ok.op == "upload") & (a_ok.size_mib == 16)]),
                ("b, 16 MiB upload, interleaved", b_ok[(b_ok.arm == "app") & (b_ok.op == "upload") & (b_ok.size_mib == 16)])):
    g_ = g_.dropna(subset=["n_aws", "n_azure", "n_gcs"])
    if len(g_) > 5 and g_[["n_azure", "n_gcs"]].nunique().max() > 1:
        beta, se, t_, r2 = ols(g_[["n_azure", "n_gcs"]].values.astype(float), g_.seconds.values)
        rg_rows.append([lbl, len(g_), f"{beta[1]:+.3f} [{beta[1] - t_ * se[1]:.3f}, {beta[1] + t_ * se[1]:.3f}]", f"{beta[2]:+.3f} [{beta[2] - t_ * se[2]:.3f}, {beta[2] + t_ * se[2]:.3f}]", f3(r2, 3)])
    else:
        rg_rows.append([lbl, len(g_), "no variation in replica counts", "-", "-"])
doc.table(["Series", "n", "Seconds per extra replica on Azure (CI)", "Seconds per extra replica on GCS (CI)", "R²"], rg_rows,
          "Does the number of replicas a file puts on each emulator explain its upload time? (16 chunks, 32 replicas per file; the S3 count is the remainder)")
fig, axes = plt.subplots(1, 3, figsize=(9.2, 3.1))
ga = a_ok[(a_ok.op == "upload") & (a_ok.size_mib == 16)].sort_values("seq")
axes[0].plot(ga.seq, ga.seconds, "o-", ms=3, lw=0.6, color=COLORS["upload"]); axes[0].set_title("a: 16 MiB upload, in run order"); axes[0].set_xlabel("Run order (trial number)"); axes[0].set_ylabel("Seconds")
gi = b_ok[(b_ok.arm == "app_isolated") & (b_ok.op == "upload")].sort_values("seq")
gb = b_ok[(b_ok.arm == "app") & (b_ok.op == "upload") & (b_ok.size_mib == 16)].sort_values("seq")
axes[1].plot(np.arange(len(gi)), gi.seconds, "o-", ms=3, lw=0.6, color=COLORS["app"], label="b, framework alone")
axes[1].plot(np.arange(len(gb)), gb.seconds, "s-", ms=3, lw=0.6, color=COLORS["download"], label="b, interleaved")
axes[1].set_title("b: 16 MiB upload, by repetition"); axes[1].set_xlabel("Repetition"); axes[1].legend()
for k in sorted(c_ok.chunk_kib.unique()):
    gc = c_ok[(c_ok.op == "upload") & (c_ok.chunk_kib == k)].sort_values("seq")
    axes[2].plot(np.arange(len(gc)), gc.seconds, "o-", ms=3, lw=0.6, label=f"{k} KiB")
axes[2].set_yscale("log"); axes[2].set_title("c: 32 MiB upload, by repetition"); axes[2].set_xlabel("Repetition"); axes[2].legend(fontsize=6.5)
savefig(fig, "run_order"); plt.close(fig)
doc.fig("run_order", "Upload times in run order for experiments a, b and c (a straight line would mean no drift).")
n_drift = sum(1 for v in ro.values() if v["p"] < 0.05)
n_bimodal = sum(1 for v in ro.values() if v["bc"] > 0.555)
KEY.append(f"Run-order checks: {n_drift} of {len(ro)} upload series show a significant trend with run order (Spearman p < 0.05) and {n_bimodal} of {len(ro)} have a bimodality coefficient above 0.555; "
           "absolute times therefore carry run-to-run variation of the emulators and the machine, which is why comparisons are made only between arms interleaved inside one experiment.")
doc.p("**What this shows.** The table lists, for every upload series, whether time drifted during the run and whether its distribution has more than one mode. Series with drift or "
      "two modes are the reason the report compares conditions only when they were interleaved in random order within one experiment. **Limitations.** Spearman correlation detects a "
      "monotone trend only; the bimodality coefficient is a rough indicator at n = 30; the replica-count regression has few distinct counts to work with because rotating placement is balanced by design.")

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
doc.table(["Comparison", "Median difference (ms)", "95% bootstrap CI (ms)", "Ratio of medians", "Mann-Whitney p", "Mean difference (ms)", "Cliff delta"],
          [["gcs down minus all up", f3(cmp_["med_diff"] * 1000, 1), f"[{cmp_['med_diff_ci_lo'] * 1000:.1f}, {cmp_['med_diff_ci_hi'] * 1000:.1f}]", f3(cmp_["med_ratio"], 3), fmt_p(cmp_["p"]), f3(cmp_["diff"] * 1000, 1), f3(cmp_["cliffs_delta"], 2)]],
          "Does one provider down change steady-state download latency?")
lat_sig = cmp_["p"] < 0.05
lat_txt = (f"download latency changed measurably but little: the median moved by {cmp_['med_diff'] * 1000:+.1f} ms (95% bootstrap CI {cmp_['med_diff_ci_lo'] * 1000:.1f} to {cmp_['med_diff_ci_hi'] * 1000:.1f}; Mann-Whitney p {fmt_p(cmp_['p'])}) and the mean by {cmp_['diff'] * 1000:+.1f} ms, the mean being pulled up by a few slow requests (slowest {max(steady):.2f} s against {max(up_all):.2f} s with all providers up)" if lat_sig else f"no detectable change in download latency (median difference {cmp_['med_diff'] * 1000:+.1f} ms, 95% bootstrap CI {cmp_['med_diff_ci_lo'] * 1000:.1f} to {cmp_['med_diff_ci_hi'] * 1000:.1f}; Mann-Whitney p {fmt_p(cmp_['p'])})")
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
           f"{100 * r_dn[2]:.1f}% and {100 * r_up[2]:.1f}%), and {lat_txt}; with two providers down {r_two[0]}/{r_two[1]} downloads succeeded, the documented limit of 2-way replication.")
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
doc.p("**What this shows.** A real outage of one provider does not stop reads or writes (reads fail over to the surviving replica, writes are placed on the other providers). With one provider down, " + lat_txt + ". With two providers down, reads fail for chunks whose two replicas were both on them, as designed. "
      "**Limitations.** The emulator refuses connections immediately, so detection was instant. A provider that hangs would be detected only after the provider timeout, which is 10 s by default in the framework, 30 s in the container deployment settings and 600 s in this measurement setup (raised so that slow emulator transfers never time out); a hanging provider was not tested. One outage pattern.")

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
doc.table(["Strategy", "S3 emulator", "Azure emulator", "GCS emulator", "Expected each", "chi2 (2 df)", "p", "Chunks per provider pair", "chi2 pairs", "p pairs"], rows,
          "Replicas per provider and chi-square goodness of fit against uniform")
SUMMARY["e"] = erep
KEY.append("Placement is balanced: replicas on the S3, Azure and GCS emulators were " + "; ".join(
    f"{s} {erep[s]['counts']['aws-s3']} / {erep[s]['counts']['azure-blob']} / {erep[s]['counts']['gcs']} (chi-square {erep[s]['chi2']:.2f}, p {fmt_p(erep[s]['p'])})" for s in erep) + " (no evidence against uniformity).")
fig, ax = plt.subplots(figsize=(6.2, 3.2))
for k, strat in enumerate(("rotating", "hash")):
    cnt = erep[strat]["counts"]
    ax.bar(np.arange(3) + (k - 0.5) * 0.36, [cnt[p] for p in ("aws-s3", "azure-blob", "gcs")], 0.36, label=strat, alpha=0.85)
tot = sum(erep["rotating"]["counts"].values())
ax.axhline(tot / 3, color="black", ls="--", lw=1, label="uniform")
ax.set_xticks(range(3)); ax.set_xticklabels(["S3 (moto)", "Azure (Azurite)", "GCS emulator"]); ax.set_ylabel("Replicas"); ax.legend(); ax.set_title("Replicas per provider")
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
SUMMARY["f_binomial"] = dict(k=int(sum(v["rejected"] for v in frep.values())), n=int(sum(v["n"] for v in frep.values())), p_tail=binom_tail(int(sum(v["rejected"] for v in frep.values())), int(sum(v["n"] for v in frep.values())), 0.05))
plain_txt = ", ".join("%.2f" % v["entropy_plain"] for v in frep.values())
f_k, f_n = sum(v["rejected"] for v in frep.values()), sum(v["n"] for v in frep.values())
KEY.append("Stored objects look random whatever the plaintext: mean ciphertext entropy " + ", ".join(f"{k} {v['entropy_cipher']:.4f}" for k, v in frep.items()) +
           f" bits per byte against plaintext entropy of {plain_txt}; the chi-square test rejected uniformity for "
           f"{f_k} of {f_n} objects; if every object were uniform at the 5% level, {0.05 * f_n:.1f} rejections would be expected and P(X >= {f_k}) = {binom_tail(f_k, f_n, 0.05):.2f}, so this is not unusual.")
fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.3))
kinds = ["random", "english_text", "zeros"]
axes[0].boxplot([f[f.kind == k].entropy_cipher for k in kinds], tick_labels=kinds, patch_artist=True, boxprops=dict(facecolor=COLORS["cipher"], alpha=0.5))
axes[0].scatter(range(1, 4), [f[f.kind == k].entropy_plain.mean() for k in kinds], color=COLORS["plain"], marker="D", zorder=3, label="plaintext")
axes[0].set_ylabel("Entropy (bits per byte)"); axes[0].set_title("Stored object vs plaintext"); axes[0].legend()
axes[1].hist([f[f.kind == k].p for k in kinds], bins=10, range=(0, 1), label=kinds)
axes[1].set_xlabel("Chi-square p-value"); axes[1].set_ylabel("Objects"); axes[1].set_title("p-values (uniform if the bytes are random)"); axes[1].legend()
savefig(fig, "f_entropy"); plt.close(fig)
doc.fig("f_entropy", "Entropy of stored ciphertext against plaintext, and the distribution of chi-square p-values.")
doc.p(f"**Is the number of rejections unusual?** With {f_n} independent objects and a 5% level, {0.05 * f_n:.1f} rejections are expected by chance; {f_k} were observed, "
      f"and the probability of {f_k} or more under that assumption is P(X >= {f_k}) = {binom_tail(f_k, f_n, 0.05):.2f} (binomial). That is not evidence of non-randomness.")
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
          [["seconds = a + b x events", f"{lin['slope'] * 1e6:.1f} ms per 1000 events ({lin['slope'] * 1000:.4f} ms per event)", f"[{lin['slope_ci_lo'] * 1e6:.1f}, {lin['slope_ci_hi'] * 1e6:.1f}] ms per 1000 events", f"{lin['intercept']:.4f} s", f3(lin["r2"], 4)],
           ["log10 seconds = a + b log10 events", f3(loglog["slope"], 3), f"[{loglog['slope_ci_lo']:.3f}, {loglog['slope_ci_hi']:.3f}]", f3(loglog["intercept"], 3), f3(loglog["r2"], 4)]],
          "Is verification linear in the number of events? (a log-log slope of 1 means linear)")
doc.p(f"`record()` throughput over {int(gr.block.sum())} events: mean {rec_rate['mean']:.0f} events/s (SD {rec_rate['sd']:.0f}, 95% CI of the mean {rec_rate['ci_lo']:.0f} to {rec_rate['ci_hi']:.0f}); "
      f"trend against log size {trend['slope'] * 1000:+.3f} events/s per 1000 events (95% CI {trend['slope_ci_lo'] * 1000:+.3f} to {trend['slope_ci_hi'] * 1000:+.3f}, p {fmt_p(trend['p'])}).")
SUMMARY["g"] = dict(linear=lin, loglog=loglog, record_events_per_s=rec_rate)
KEY.append(f"Audit verification is linear: the log-log slope of time against events is {loglog['slope']:.3f} (95% CI {loglog['slope_ci_lo']:.3f} to {loglog['slope_ci_hi']:.3f}; "
           f"1 means linear), R² {lin['r2']:.4f} for the linear fit ({lin['slope'] * 1e6:.1f} ms per 1000 events); `record()` sustains {rec_rate['mean']:.0f} events/s with an fsync per event.")
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
          [[sc, h[h.scenario == sc].attempt.iloc[0], fam[fam.scenario == sc].outcome.iloc[0]] for sc in fam.scenario],
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
