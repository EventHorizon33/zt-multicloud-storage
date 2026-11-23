"""Tiny thread-safe metrics registry for the storage layer (no external
dependency). Labels are provider instance names and operation names only;
never object keys, sizes per object, or anything user-derived."""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

COUNTERS = ("attempts", "successes", "failures", "retries", "bytes")
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class StorageMetrics:
    """Counters per (provider, op): attempts, successes, failures, retries,
    bytes; plus a latency histogram per (provider, op)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: dict.fromkeys(COUNTERS, 0))
        self._hist: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0] * (len(LATENCY_BUCKETS) + 1))
        self._hist_sum: dict[tuple[str, str], float] = defaultdict(float)

    def inc(self, provider: str, op: str, counter: str, n: int = 1) -> None:
        if counter not in COUNTERS:
            raise ValueError(f"unknown counter {counter!r}")
        with self._lock:
            self._counters[(provider, op)][counter] += n

    def observe(self, provider: str, op: str, seconds: float) -> None:
        idx = len(LATENCY_BUCKETS)
        for i, bound in enumerate(LATENCY_BUCKETS):
            if seconds <= bound:
                idx = i
                break
        with self._lock:
            self._hist[(provider, op)][idx] += 1
            self._hist_sum[(provider, op)] += seconds

    def get(self, provider: str, op: str, counter: str) -> int:
        with self._lock:
            return self._counters.get((provider, op), {}).get(counter, 0)

    def total(self, counter: str, provider: str | None = None) -> int:
        with self._lock:
            return sum(c[counter] for (p, _), c in self._counters.items() if provider in (None, p))

    def snapshot(self) -> dict[str, Any]:
        """``{"counters": {provider: {op: {counter: n}}}, "latency": {provider:
        {op: {"count", "sum_seconds", "buckets": {le: cumulative}}}}}``"""
        with self._lock:
            counters: dict[str, dict[str, dict[str, int]]] = {}
            for (p, op), c in sorted(self._counters.items()):
                counters.setdefault(p, {})[op] = dict(c)
            latency: dict[str, dict[str, Any]] = {}
            for (p, op), h in sorted(self._hist.items()):
                cumulative, buckets = 0, {}
                for bound, n in zip([*map(str, LATENCY_BUCKETS), "+Inf"], h):
                    cumulative += n
                    buckets[bound] = cumulative
                latency.setdefault(p, {})[op] = {"count": cumulative,
                                                 "sum_seconds": round(self._hist_sum[(p, op)], 6),
                                                 "buckets": buckets}
        return {"counters": counters, "latency": latency}

    def render_prometheus(self) -> str:
        """Prometheus text exposition format (version 0.0.4)."""
        snap = self.snapshot()
        lines: list[str] = []
        for counter in COUNTERS:
            metric = f"zt_storage_{counter}_total"
            lines.append(f"# HELP {metric} Storage provider operation {counter}.")
            lines.append(f"# TYPE {metric} counter")
            for p, ops in snap["counters"].items():
                for op, c in ops.items():
                    lines.append(f'{metric}{{provider="{_esc(p)}",op="{_esc(op)}"}} {c[counter]}')
        metric = "zt_storage_latency_seconds"
        lines.append(f"# HELP {metric} Storage provider call latency.")
        lines.append(f"# TYPE {metric} histogram")
        for p, ops in snap["latency"].items():
            for op, h in ops.items():
                labels = f'provider="{_esc(p)}",op="{_esc(op)}"'
                for le, n in h["buckets"].items():
                    lines.append(f'{metric}_bucket{{{labels},le="{le}"}} {n}')
                lines.append(f"{metric}_sum{{{labels}}} {h['sum_seconds']}")
                lines.append(f"{metric}_count{{{labels}}} {h['count']}")
        return "\n".join(lines) + "\n"


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
