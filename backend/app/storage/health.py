"""Provider health tracking with a simple circuit breaker.

Passive health: the orchestrator reports the outcome of every real provider
operation (``record_success`` / ``record_failure``). Active health:
``check_all()`` calls each provider's cheap ``health()`` probe, optionally on
a background daemon thread.

Circuit breaker per provider:
  closed     normal; ``allow_request`` is True
  open       after ``failure_threshold`` consecutive failures; requests are
             refused (the orchestrator skips the provider) for
             ``cooldown_seconds``
  half-open  after the cool-down ONE trial request is allowed; success closes
             the breaker, failure re-opens it for another cool-down. A
             successful active probe also closes it.

Audit: ``storage.provider.health`` is emitted only on TRANSITIONS recorded by
``record_success`` / ``record_failure`` / probes (healthy flag flips, breaker
opens or closes), never per probe. The silent open -> half-open step taken by
``allow_request`` is not audited; its outcome (close or re-open) is. Error strings stored or
emitted are sanitised.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping

from app.contracts import AuditSink, Outcome, Severity, StorageProvider

from ._common import sanitize_text, utcnow

log = logging.getLogger(__name__)

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half-open"


@dataclass
class _State:
    healthy: bool | None = None          # None = never observed
    latency_ms: float | None = None
    consecutive_failures: int = 0
    last_error: str | None = None
    last_checked: datetime | None = None
    last_source: str | None = None       # "probe" | "operation"
    breaker: str = CLOSED
    opened_at: float | None = None
    trial_started_at: float | None = None
    total_failures: int = 0
    total_successes: int = 0


class HealthMonitor:
    """Thread-safe per-provider health state. ``clock`` is a monotonic clock
    (injectable for tests); ``wall_clock`` stamps ``last_checked``."""

    def __init__(
        self,
        providers: Mapping[str, StorageProvider],
        interval: float = 15.0,
        clock: Callable[[], float] = time.monotonic,
        *,
        failure_threshold: int = 3,
        cooldown_seconds: float = 30.0,
        audit: AuditSink | None = None,
        wall_clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if interval <= 0:
            raise ValueError("interval must be > 0")
        self._providers = dict(providers)
        self.interval = interval
        self._clock = clock
        self._wall = wall_clock
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self._audit = audit
        self._lock = threading.RLock()
        self._states = {name: _State() for name in self._providers}
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # -- passive ------------------------------------------------------------ #
    def record_success(self, provider: str, latency_ms: float | None = None, *,
                       source: str = "operation") -> None:
        with self._lock:
            st = self._state(provider)
            before = (st.healthy, st.breaker)
            st.healthy = True
            st.consecutive_failures = 0
            st.total_successes += 1
            if latency_ms is not None:
                st.latency_ms = round(float(latency_ms), 3)
            st.last_checked = self._wall()
            st.last_source = source
            st.breaker, st.opened_at, st.trial_started_at = CLOSED, None, None
            after = (st.healthy, st.breaker)
            snap = self._row(provider, st) if before != after else None
        if snap is not None:
            self._emit(provider, snap, before)

    def record_failure(self, provider: str, error: object, *, latency_ms: float | None = None,
                       source: str = "operation") -> None:
        with self._lock:
            st = self._state(provider)
            before = (st.healthy, st.breaker)
            st.healthy = False
            st.consecutive_failures += 1
            st.total_failures += 1
            st.last_error = sanitize_text(error)
            if latency_ms is not None:
                st.latency_ms = round(float(latency_ms), 3)
            st.last_checked = self._wall()
            st.last_source = source
            if st.breaker == HALF_OPEN or st.consecutive_failures >= self.failure_threshold:
                st.breaker, st.opened_at, st.trial_started_at = OPEN, self._clock(), None
            after = (st.healthy, st.breaker)
            snap = self._row(provider, st) if before != after else None
        if snap is not None:
            self._emit(provider, snap, before)

    # -- breaker ------------------------------------------------------------ #
    def allow_request(self, provider: str) -> bool:
        """True if the orchestrator may send a request now. May move an open
        breaker whose cool-down elapsed to half-open and admit one trial."""
        with self._lock:
            st = self._state(provider)
            now = self._clock()
            if st.breaker == CLOSED:
                return True
            if st.breaker == OPEN:
                if st.opened_at is not None and now - st.opened_at >= self.cooldown_seconds:
                    st.breaker, st.trial_started_at = HALF_OPEN, now
                    return True
                return False
            # half-open: one trial at a time; a trial that never reported back
            # is abandoned after another cool-down
            if st.trial_started_at is None or now - st.trial_started_at >= self.cooldown_seconds:
                st.trial_started_at = now
                return True
            return False

    def breaker_state(self, provider: str) -> str:
        with self._lock:
            return self._state(provider).breaker

    def is_open(self, provider: str) -> bool:
        """Open and still cooling down (no mutation)."""
        with self._lock:
            st = self._state(provider)
            return st.breaker == OPEN and st.opened_at is not None and \
                self._clock() - st.opened_at < self.cooldown_seconds

    def is_healthy(self, provider: str) -> bool:
        """Last observation was a success, or nothing observed yet."""
        with self._lock:
            return self._state(provider).healthy is not False

    def rank(self, provider: str) -> int:
        """0 = healthy & closed, 1 = unknown/unhealthy but not refused,
        2 = breaker open (cooling down). Used to order candidates."""
        with self._lock:
            st = self._state(provider)
            if st.breaker == OPEN and st.opened_at is not None and \
                    self._clock() - st.opened_at < self.cooldown_seconds:
                return 2
            return 0 if st.healthy is not False and st.breaker == CLOSED else 1

    # -- active ------------------------------------------------------------- #
    def check_one(self, name: str) -> dict[str, Any]:
        provider = self._providers[name]
        try:
            status = provider.health()
            healthy, latency, error = status.healthy, status.latency_ms, status.error
        except Exception as exc:  # contract says health() never raises; be defensive anyway
            healthy, latency, error = False, None, f"health probe raised {type(exc).__name__}"
        if healthy:
            self.record_success(name, latency, source="probe")
        else:
            self.record_failure(name, error or "unhealthy", latency_ms=latency, source="probe")
        with self._lock:
            return self._row(name, self._states[name])

    def check_all(self) -> list[dict[str, Any]]:
        """Active probe of every provider (sequential; each probe is bounded
        by the adapter's SDK timeouts). Returns the new snapshot."""
        for name in self._providers:
            self.check_one(name)
        return self.snapshot()

    def start(self) -> None:
        """Start the background prober (daemon thread). Idempotent."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="zt-storage-health", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.check_all()
            except Exception:  # pragma: no cover - never let the prober die
                log.exception("storage health check failed")
            self._stop.wait(self.interval)

    # -- reporting ---------------------------------------------------------- #
    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [self._row(name, st) for name, st in self._states.items()]

    def _row(self, name: str, st: _State) -> dict[str, Any]:
        provider = self._providers.get(name)
        fault = getattr(provider, "status", None)
        fault_status = fault() if callable(fault) else None
        return {
            "provider": name,
            "kind": getattr(provider, "kind", None),
            "healthy": st.healthy,
            "state": st.breaker,
            "latency_ms": st.latency_ms,
            "consecutive_failures": st.consecutive_failures,
            "last_error": st.last_error,
            "last_checked": st.last_checked.isoformat() if st.last_checked else None,
            "last_source": st.last_source,
            "total_successes": st.total_successes,
            "total_failures": st.total_failures,
            "injected": bool(fault_status and fault_status.get("injected")),
            "fault_mode": fault_status.get("mode") if fault_status else None,
        }

    def _state(self, provider: str) -> _State:
        try:
            return self._states[provider]
        except KeyError:
            raise KeyError(f"unknown storage provider {provider!r}") from None

    def _emit(self, provider: str, row: dict[str, Any], before: tuple[bool | None, str]) -> None:
        """Audit a transition. A health monitor must keep running even if the
        audit sink fails, so failures here are logged (sanitised) and swallowed;
        data-path audit events in the orchestrator, by contrast, propagate."""
        if self._audit is None:
            return
        up = bool(row["healthy"]) and row["state"] == CLOSED
        try:
            self._audit.record(
                event_type="storage.provider.health",
                action="storage:health",
                outcome=Outcome.SUCCESS if up else Outcome.ERROR,
                resource_type="storage",
                resource_id=provider,
                reason=None if up else row["last_error"],
                severity=Severity.INFO if up else Severity.WARNING,
                details={
                    "provider": provider,
                    "healthy": bool(row["healthy"]),
                    "state": row["state"],
                    "previous_state": before[1],
                    "consecutive_failures": row["consecutive_failures"],
                    "injected": row["injected"],
                },
            )
        except Exception as exc:
            log.error("audit of storage health transition failed: %s", type(exc).__name__)
