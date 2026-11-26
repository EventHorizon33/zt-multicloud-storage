"""Shared helpers for the statistical analysis: environment record, descriptive statistics, tests, plotting.

Every number in docs/STATISTICAL_ANALYSIS.md is computed from the CSV files in analysis/data/ by these helpers.
All randomness (shuffling the order of conditions, bootstrap resampling) uses SEED.
"""
from __future__ import annotations

import os
import platform
import subprocess
from datetime import datetime
from pathlib import Path

import numpy as np
from scipy import stats as st

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
DATA, FIG = ROOT / "data", ROOT / "figures"
SEED = 20261125
MIB = 1024 * 1024


def env_info() -> dict:
    def sh(*cmd):
        try:
            return subprocess.check_output(cmd, text=True, cwd=REPO, stderr=subprocess.DEVNULL).strip()
        except Exception:
            return None

    cpu = None
    try:
        for line in open("/proc/cpuinfo", encoding="utf-8"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    ram = None
    try:
        ram = round(int(open("/proc/meminfo", encoding="utf-8").read().split()[1]) / 2**20, 1)
    except OSError:
        pass
    import matplotlib
    import pandas
    import scipy
    return dict(
        date=datetime.now().astimezone().isoformat(timespec="seconds"), cpu=cpu, logical_cpus=os.cpu_count(), ram_gib=ram,
        os=platform.platform(), python=platform.python_version(), numpy=np.__version__, scipy=scipy.__version__,
        pandas=pandas.__version__, matplotlib=matplotlib.__version__,
        git_commit=sh("git", "rev-parse", "--short", "HEAD"), git_app_dirty=bool(sh("git", "status", "--porcelain", "--", "backend/app")),
        seed=SEED,
        setting="three local emulators (moto S3, Azurite, gcp-storage-emulator) and the real boto3, azure-storage-blob and "
                "google-cloud-storage SDKs on one machine under WSL2; no network latency")


# --------------------------------------------------------------------------- #
# descriptive statistics and tests
# --------------------------------------------------------------------------- #
def describe(x, boot: int = 5000, seed: int = SEED) -> dict:
    x = np.asarray(x, dtype=float)
    n = len(x)
    if n == 0:
        return dict(n=0)
    sd = float(x.std(ddof=1)) if n > 1 else 0.0
    se = sd / np.sqrt(n) if n > 1 else 0.0
    tcrit = float(st.t.ppf(0.975, n - 1)) if n > 1 else 0.0
    med = float(np.median(x))
    if n > 1:
        idx = np.random.default_rng(seed).integers(0, n, size=(boot, n))
        mlo, mhi = np.percentile(np.median(x[idx], axis=1), [2.5, 97.5])
    else:
        mlo = mhi = med
    q1, q3 = np.percentile(x, [25, 75])
    shapiro = float(st.shapiro(x).pvalue) if 3 <= n <= 5000 and np.ptp(x) > 0 else float("nan")
    return dict(n=n, mean=float(x.mean()), sd=sd, median=med, q1=float(q1), q3=float(q3), min=float(x.min()), max=float(x.max()),
                ci_lo=float(x.mean() - tcrit * se), ci_hi=float(x.mean() + tcrit * se), med_ci_lo=float(mlo), med_ci_hi=float(mhi),
                shapiro_p=shapiro)


def compare(a, b, boot: int = 10000, seed: int = SEED) -> dict:
    """Two independent samples. ONE test is fixed in advance and is the primary one, whatever the data look like: the Mann-Whitney U
    test (no normality assumption), with the difference of the MEDIANS and its 95% percentile-bootstrap interval as the effect size.
    Welch's t-test and the difference of the means are reported only as a secondary check."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    u = st.mannwhitneyu(a, b, alternative="two-sided")
    w = st.ttest_ind(a, b, equal_var=False)
    ci = w.confidence_interval(0.95)
    rng = np.random.default_rng(seed)
    ia = rng.integers(0, len(a), size=(boot, len(a)))
    ib = rng.integers(0, len(b), size=(boot, len(b)))
    dm = np.median(a[ia], axis=1) - np.median(b[ib], axis=1)
    mlo, mhi = np.percentile(dm, [2.5, 97.5])
    pooled = np.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2) if len(a) > 1 and len(b) > 1 else float("nan")
    ma, mb = float(np.median(a)), float(np.median(b))
    return dict(n_a=len(a), n_b=len(b), median_a=ma, median_b=mb, med_diff=ma - mb, med_diff_ci_lo=float(mlo), med_diff_ci_hi=float(mhi),
                med_ratio=ma / mb, mean_a=float(a.mean()), mean_b=float(b.mean()), diff=float(a.mean() - b.mean()),
                diff_ci_lo=float(ci.low), diff_ci_hi=float(ci.high), ratio=float(a.mean() / b.mean()),
                welch_t=float(w.statistic), welch_df=float(w.df), welch_p=float(w.pvalue),
                mwu_U=float(u.statistic), mwu_p=float(u.pvalue), primary="Mann-Whitney U", p=float(u.pvalue),
                cohens_d=float((a.mean() - b.mean()) / pooled), cliffs_delta=float(2 * u.statistic / (len(a) * len(b)) - 1))


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (float(max(0.0, centre - half)), float(min(1.0, centre + half)))


def holm(pvals) -> list[float]:
    p = np.asarray(pvals, float)
    order = np.argsort(p)
    adj = np.empty_like(p)
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, (len(p) - rank) * p[i])
        adj[i] = min(1.0, running)
    return adj.tolist()


def linfit(x, y) -> dict:
    x, y = np.asarray(x, float), np.asarray(y, float)
    r = st.linregress(x, y)
    n = len(x)
    t = float(st.t.ppf(0.975, n - 2))
    return dict(n=n, slope=float(r.slope), slope_se=float(r.stderr), slope_ci_lo=float(r.slope - t * r.stderr),
                slope_ci_hi=float(r.slope + t * r.stderr), intercept=float(r.intercept), intercept_se=float(r.intercept_stderr),
                intercept_ci_lo=float(r.intercept - t * r.intercept_stderr), intercept_ci_hi=float(r.intercept + t * r.intercept_stderr),
                r2=float(r.rvalue ** 2), p=float(r.pvalue))


def entropy_bits(b: bytes) -> float:
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(float)
    p = c[c > 0] / c.sum()
    return float(-(p * np.log2(p)).sum())


def binom_tail(k: int, n: int, p0: float) -> float:
    """P(X >= k) for X ~ Binomial(n, p0): how surprising k rejections out of n tests are when each rejects with probability p0."""
    return float(st.binom.sf(k - 1, n, p0)) if k > 0 else 1.0


def fmt_p(p: float) -> str:
    if p != p:
        return "n/a"
    return "< 0.0001" if p < 1e-4 else f"{p:.4f}"


# --------------------------------------------------------------------------- #
# plotting
# --------------------------------------------------------------------------- #
def style():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"figure.dpi": 120, "savefig.dpi": 200, "axes.grid": True, "grid.alpha": 0.3, "axes.spines.top": False,
                         "axes.spines.right": False, "font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
                         "legend.fontsize": 8, "figure.constrained_layout.use": True})
    return plt


COLORS = {"upload": "#1f6fb2", "download": "#d9822b", "app": "#1f6fb2", "plain_chunked": "#5aa469", "plain_single": "#9a9a9a",
          "cipher": "#b2442f", "plain": "#7f7f7f"}


def savefig(fig, name: str) -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / f"{name}.png")
    fig.savefig(FIG / f"{name}.pdf")
