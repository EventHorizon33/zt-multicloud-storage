from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any

import pytest

from app.storage import (
    FaultInjectingProvider,
    HealthMonitor,
    RetryPolicy,
    RotatingPlacement,
    StorageMetrics,
    StorageOrchestrator,
)
from app.storage.memory import MemoryProvider


class FakeAudit:
    """Implements the AuditSink contract; keeps events in memory."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.fail = False

    def record(self, **kwargs: Any) -> None:
        if self.fail:
            raise RuntimeError("audit store unavailable")
        with self._lock:
            self.events.append(kwargs)

    def of(self, event_type: str) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["event_type"] == event_type]


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@dataclass
class Cluster:
    orch: StorageOrchestrator
    faults: dict[str, FaultInjectingProvider]
    mem: dict[str, MemoryProvider]
    audit: FakeAudit
    health: HealthMonitor
    clock: FakeClock
    metrics: StorageMetrics
    sleeps: list[float] = field(default_factory=list)

    def holders(self, key: str) -> list[str]:
        return sorted(n for n, m in self.mem.items() if m.exists(key))


NAMES = ["p-a", "p-b", "p-c"]


@pytest.fixture
def make_cluster():
    created: list[StorageOrchestrator] = []

    def factory(*, n: int = 3, r: int = 2, min_write: int = 2, verify_writes: bool = True,
                timeout: float | None = 5.0, max_attempts: int = 3, failure_threshold: int = 3,
                cooldown: float = 30.0, placement=None) -> Cluster:
        names = NAMES[:n] if n <= 3 else [f"p-{i}" for i in range(n)]
        mem = {name: MemoryProvider(name) for name in names}
        faults = {name: FaultInjectingProvider(m) for name, m in mem.items()}
        audit, clock, metrics, sleeps = FakeAudit(), FakeClock(), StorageMetrics(), []
        health = HealthMonitor(faults, interval=60, clock=clock, failure_threshold=failure_threshold,
                               cooldown_seconds=cooldown, audit=audit)
        orch = StorageOrchestrator(
            faults, placement or RotatingPlacement(),
            RetryPolicy(max_attempts=max_attempts, base_delay=0.01, max_delay=0.05), health,
            replication_factor=r, min_write_replicas=min_write, audit=audit, timeout_seconds=timeout,
            metrics=metrics, verify_writes=verify_writes, sleep=sleeps.append)
        created.append(orch)
        return Cluster(orch, faults, mem, audit, health, clock, metrics, sleeps)

    yield factory
    for o in created:
        o.close()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verifier(data: bytes):
    expected = sha(data)
    return lambda got: hashlib.sha256(got).hexdigest() == expected
