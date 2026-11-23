"""Storage orchestrator: placement, replication, retry, failover, write
verification, read verification, repair and audit anchors across providers.

It sees only opaque object keys (chunk ids) and ciphertext bytes. It holds no
keys, knows no users or filenames, and never puts object contents into audit
events, exceptions or metrics.

Security / reliability properties:
  * replicas of one chunk always land on DISTINCT providers;
  * a write counts only after it is verified on the provider (size via stat,
    and by default a read-back SHA-256 comparison) so a provider that
    acknowledges writes it did not keep is detected at upload time;
  * an upload that cannot reach ``min_write_replicas`` leaves no stored
    replicas behind (best-effort cleanup) and raises ``ChunkStoreError``;
  * reads accept a replica only if the caller's ``verify`` callback (SHA-256
    against the MAC-protected manifest) accepts it; bad replicas are skipped
    and audited;
  * every provider call is bounded: SDK timeouts, a per-call deadline, and a
    bounded retry policy.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence, TypeVar

from app.contracts import (
    AuditSink,
    ObjectNotFound,
    Outcome,
    ProviderAuthError,
    ProviderTimeout,
    ProviderUnavailable,
    Severity,
    StorageError,
    StorageProvider,
)

from ._common import ANCHOR_PREFIX, InvalidObjectKey, error_summary, require_bytes, validate_key, \
    validate_prefix
from .faults import FaultInjectingProvider
from .health import HealthMonitor
from .metrics import StorageMetrics
from .placement import PlacementStrategy
from .retry import DeadlineRunner, RetryPolicy, call_with_retry

log = logging.getLogger(__name__)
T = TypeVar("T")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Errors and result types
# --------------------------------------------------------------------------- #
class WriteVerificationError(StorageError):
    """A provider acknowledged a write that it does not actually hold (missing,
    wrong size, or wrong content on read-back)."""
    retryable = False


class CircuitOpenError(ProviderUnavailable):
    """The provider's circuit breaker is open; no request was sent."""
    retryable = False


class FaultInjectionDisabled(StorageError):
    retryable = False


@dataclass(frozen=True)
class ProviderFailure:
    provider: str
    error_type: str            # exception class name, e.g. "ProviderUnavailable"
    message: str               # sanitised
    retryable: bool
    attempts: int = 1
    injected: bool = False     # True when the failure came from fault injection


@dataclass(frozen=True)
class StoreResult:
    """``degraded`` is True when fewer than ``replication_factor`` replicas
    were stored (but at least ``min_write_replicas``). ``failed_over`` is True
    when a fallback provider replaced a preferred target. ``failed`` lists
    every provider that was tried and did not end up holding a verified
    replica."""
    chunk_id: str
    stored_on: list[str]
    failed: list[ProviderFailure]
    degraded: bool
    failed_over: bool = False
    attempts: int = 0


class ChunkStoreError(StorageError):
    """Fewer than ``min_write_replicas`` verified replicas could be written.
    Whatever was written for the chunk has been deleted (best effort)."""
    retryable = False

    def __init__(self, message: str, *, chunk_id: str, failures: Sequence[ProviderFailure],
                 cleanup_failed: Sequence[str] = ()):
        super().__init__(message)
        self.chunk_id = chunk_id
        self.failures = list(failures)
        self.cleanup_failed = list(cleanup_failed)


@dataclass(frozen=True)
class ReplicaAttempt:
    provider: str
    outcome: str               # ok | missing | corrupt | unavailable | timeout | error
    retries: int = 0
    error: str | None = None   # sanitised
    injected: bool = False


@dataclass(frozen=True)
class FetchResult:
    data: bytes = field(repr=False)
    provider: str
    attempts: list[ReplicaAttempt]


class ChunkUnavailableError(StorageError):
    """No replica produced data that passed verification. ``attempts`` tells
    the caller whether the cause was integrity (corrupt) or availability."""
    retryable = False

    def __init__(self, message: str, *, chunk_id: str, attempts: Sequence[ReplicaAttempt]):
        super().__init__(message)
        self.chunk_id = chunk_id
        self.attempts = list(attempts)

    @property
    def outcomes(self) -> list[str]:
        return [a.outcome for a in self.attempts]

    @property
    def all_corrupt(self) -> bool:
        return bool(self.attempts) and all(a.outcome == "corrupt" for a in self.attempts)

    @property
    def any_corrupt(self) -> bool:
        return any(a.outcome == "corrupt" for a in self.attempts)

    @property
    def all_missing(self) -> bool:
        return bool(self.attempts) and all(a.outcome == "missing" for a in self.attempts)


@dataclass(frozen=True)
class DeleteResult:
    deleted: list[str]
    failed: list[ProviderFailure]


@dataclass(frozen=True)
class AnchorWriteResult:
    key: str
    stored_on: list[str]
    failed: list[ProviderFailure]


@dataclass(frozen=True)
class AnchorRead:
    provider: str
    outcome: str               # ok | missing | unavailable | timeout | error
    data: bytes | None = field(default=None, repr=False)
    error: str | None = None


@dataclass(frozen=True)
class AnchorListing:
    keys: dict[str, list[str]]     # provider -> anchor keys (full "anchors/..." keys), sorted
    errors: dict[str, str]         # provider -> sanitised error, for providers that could not list


def _failure(provider: str, exc: BaseException, attempts: int = 1) -> ProviderFailure:
    return ProviderFailure(provider=provider, error_type=type(exc).__name__,
                           message=error_summary(exc), retryable=bool(getattr(exc, "retryable", False)),
                           attempts=attempts, injected=bool(getattr(exc, "injected", False)))


def _outcome_of(exc: BaseException) -> str:
    if isinstance(exc, ObjectNotFound):
        return "missing"
    if isinstance(exc, ProviderTimeout):
        return "timeout"
    if isinstance(exc, ProviderUnavailable):
        return "unavailable"
    return "error"


def _counts_against_health(exc: BaseException) -> bool:
    """Object-level outcomes (missing object, bad key) say nothing about the
    provider's availability; everything else does."""
    return not isinstance(exc, (ObjectNotFound, InvalidObjectKey, CircuitOpenError))


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
class StorageOrchestrator:
    """Thread-safe: all mutable state lives in ``StorageMetrics`` and
    ``HealthMonitor`` (both locked); everything else is immutable after
    construction, so concurrent request threads may call any method."""

    def __init__(
        self,
        providers: Mapping[str, StorageProvider],
        placement: PlacementStrategy,
        retry_policy: RetryPolicy,
        health: HealthMonitor | None = None,
        replication_factor: int = 2,
        min_write_replicas: int = 2,
        audit: AuditSink | None = None,
        timeout_seconds: float | None = 10.0,
        metrics: StorageMetrics | None = None,
        *,
        verify_writes: bool = True,
        sleep: Callable[[float], None] = time.sleep,
        max_parallel: int = 16,
        deadline_workers: int = 64,
    ) -> None:
        if not providers:
            raise ValueError("at least one storage provider is required")
        for name, p in providers.items():
            if getattr(p, "name", name) != name:
                raise ValueError("provider mapping key must equal provider.name")
        if not 1 <= min_write_replicas <= replication_factor:
            raise ValueError("require 1 <= min_write_replicas <= replication_factor")
        if replication_factor > len(providers):
            raise ValueError(f"replication_factor {replication_factor} exceeds the number of providers "
                             f"({len(providers)})")
        self._providers = dict(providers)
        self._names = list(self._providers)
        self.placement = placement
        self.retry_policy = retry_policy
        self.health = health
        self.replication_factor = replication_factor
        self.min_write_replicas = min_write_replicas
        self._audit = audit
        self.timeout_seconds = timeout_seconds
        self.metrics = metrics or StorageMetrics()
        self.verify_writes = verify_writes
        self._sleep = sleep
        self._runner = DeadlineRunner(max_workers=deadline_workers)
        self._io_pool = ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix="zt-storage-fanout")
        self._closed = threading.Event()

    # -- properties / admin -------------------------------------------------- #
    @property
    def provider_names(self) -> list[str]:
        return list(self._names)

    def provider(self, name: str) -> StorageProvider:
        return self._providers[name]

    def health_snapshot(self) -> list[dict[str, Any]]:
        """Dashboard view. Uses the HealthMonitor if present, else probes now."""
        if self.health is not None:
            return self.health.snapshot()
        rows = []
        for name, p in self._providers.items():
            st = p.health()
            fault = p.status() if isinstance(p, FaultInjectingProvider) else None
            rows.append({"provider": name, "kind": p.kind, "healthy": st.healthy, "state": None,
                         "latency_ms": st.latency_ms, "consecutive_failures": None,
                         "last_error": st.error, "last_checked": st.checked_at.isoformat(),
                         "injected": bool(fault and fault["injected"]),
                         "fault_mode": fault["mode"] if fault else None})
        return rows

    def set_fault(self, provider: str, mode: str, **params: Any) -> dict[str, Any]:
        """Demo/test only. Raises FaultInjectionDisabled unless the provider
        was wrapped in FaultInjectingProvider (``enable_fault_injection``)."""
        p = self._providers.get(provider)
        if p is None:
            raise KeyError(f"unknown storage provider {provider!r}")
        if not isinstance(p, FaultInjectingProvider):
            raise FaultInjectionDisabled("fault injection is not enabled for this deployment",
                                         provider=provider)
        return p.set_mode(mode, **params)

    def fault_status(self) -> list[dict[str, Any]]:
        return [p.status() for p in self._providers.values() if isinstance(p, FaultInjectingProvider)]

    def close(self) -> None:
        """Release worker threads. Does not stop an injected HealthMonitor."""
        self._closed.set()
        self._io_pool.shutdown(wait=False, cancel_futures=True)
        self._runner.shutdown()

    # -- low-level call wrapper --------------------------------------------- #
    def _call(self, name: str, op: str, fn: Callable[[], T], *, respect_breaker: bool = True,
              retry: bool = True, nbytes: Callable[[Any], int] | None = None) -> tuple[T, int]:
        """One logical provider operation: breaker check, deadline-bounded
        attempts, retry with backoff, metrics and passive health. Returns
        (result, retries). On failure the raised StorageError carries
        ``zt_retries``."""
        if respect_breaker and self.health is not None and not self.health.allow_request(name):
            exc = CircuitOpenError(f"{op} skipped: circuit breaker open", provider=name)
            exc.zt_retries = 0  # type: ignore[attr-defined]
            raise exc
        retries = 0
        metrics = self.metrics

        def on_retry(_n: int, _exc: BaseException, _delay: float) -> None:
            nonlocal retries
            retries += 1
            metrics.inc(name, op, "retries")

        def attempt() -> T:
            metrics.inc(name, op, "attempts")
            t0 = time.perf_counter()
            try:
                result = self._runner.call(fn, self.timeout_seconds, provider=name, op=op)
            except StorageError as exc:
                metrics.observe(name, op, time.perf_counter() - t0)
                metrics.inc(name, op, "failures")
                if exc.provider is None:
                    exc.provider = name
                raise
            except Exception as exc:
                metrics.observe(name, op, time.perf_counter() - t0)
                metrics.inc(name, op, "failures")
                raise StorageError(f"{op} failed: unexpected {type(exc).__name__}", provider=name) from None
            metrics.observe(name, op, time.perf_counter() - t0)
            metrics.inc(name, op, "successes")
            if nbytes is not None:
                metrics.inc(name, op, "bytes", nbytes(result))
            return result

        policy = self.retry_policy if retry else RetryPolicy(max_attempts=1, base_delay=0, max_delay=0)
        started = time.perf_counter()
        try:
            result = call_with_retry(attempt, policy, sleep=self._sleep, on_retry=on_retry)
        except StorageError as exc:
            exc.zt_retries = retries  # type: ignore[attr-defined]
            if self.health is not None:
                latency = (time.perf_counter() - started) * 1000.0
                if _counts_against_health(exc):
                    self.health.record_failure(name, error_summary(exc), latency_ms=latency)
                elif isinstance(exc, ObjectNotFound):
                    self.health.record_success(name, latency)
            raise
        if self.health is not None:
            self.health.record_success(name, (time.perf_counter() - started) * 1000.0)
        return result, retries

    def _rank(self, name: str) -> int:
        return self.health.rank(name) if self.health is not None else 0

    def _audit_event(self, **kwargs: Any) -> None:
        if self._audit is not None:
            self._audit.record(**kwargs)

    @staticmethod
    def _chunk_key(chunk_id: str) -> str:
        validate_key(chunk_id)
        if chunk_id.startswith(ANCHOR_PREFIX):
            raise InvalidObjectKey(f"chunk ids must not use the reserved '{ANCHOR_PREFIX}' prefix")
        return chunk_id

    @staticmethod
    def _check_sha(sha256_hex: str) -> str:
        sha = (sha256_hex or "").lower()
        if not _SHA256_RE.match(sha):
            raise ValueError("sha256_hex must be 64 hex characters")
        return sha

    # -- write path ---------------------------------------------------------- #
    def _write_one(self, name: str, key: str, data: bytes, sha: str) -> tuple[ProviderFailure | None, int, bool]:
        """Put + verify on one provider. Returns (failure or None, attempts,
        maybe_written). ``maybe_written`` means an object may exist there even
        though the write did not count (timeout mid-write, failed verify)."""
        provider = self._providers[name]
        attempts = 0
        try:
            _, r = self._call(name, "put", lambda: provider.put(key, data), nbytes=lambda _r: len(data))
            attempts += 1 + r
        except StorageError as exc:
            attempts += 1 + getattr(exc, "zt_retries", 0)
            if isinstance(exc, CircuitOpenError):
                attempts -= 1  # nothing was sent
            # A timed-out put may still have landed (or may land later: the
            # deadline cannot stop an in-flight SDK call); refused/unavailable
            # puts did not.
            return _failure(name, exc, max(attempts, 1)), attempts, isinstance(exc, ProviderTimeout)
        try:
            try:
                info, r = self._call(name, "stat", lambda: provider.stat(key))
                attempts += 1 + r
            except ObjectNotFound:
                attempts += 1
                raise WriteVerificationError("write verification failed: object missing after acknowledged "
                                             "write", provider=name) from None
            if info.size != len(data):
                raise WriteVerificationError("write verification failed: stored size differs", provider=name)
            if self.verify_writes:
                try:
                    back, r = self._call(name, "get", lambda: provider.get(key), nbytes=len)
                    attempts += 1 + r
                except ObjectNotFound:
                    attempts += 1
                    raise WriteVerificationError("write verification failed: object missing on read-back",
                                                 provider=name) from None
                if not hmac.compare_digest(hashlib.sha256(back).hexdigest(), sha):
                    raise WriteVerificationError("write verification failed: read-back hash mismatch",
                                                 provider=name)
        except WriteVerificationError as exc:
            if self.health is not None:
                self.health.record_failure(name, error_summary(exc))
            return _failure(name, exc, attempts), attempts, True
        except StorageError as exc:
            # put was acknowledged but verification could not complete
            attempts += 1 + getattr(exc, "zt_retries", 0)
            return _failure(name, exc, attempts), attempts, True
        return None, attempts, True

    def _fanout(self, fn: Callable[[str], T], names: Sequence[str]) -> list[T]:
        if len(names) <= 1 or self._closed.is_set():
            return [fn(n) for n in names]
        # Each task runs in its own copy of the caller's context, so the ambient
        # audit request context (app.audit.context, F5) reaches audit events
        # recorded from the fan-out threads (one copy per task: a Context
        # cannot be entered by two threads at once).
        futures = [self._io_pool.submit(contextvars.copy_context().run, fn, n) for n in names]
        return [f.result() for f in futures]

    def _cleanup(self, key: str, names: Iterable[str]) -> list[str]:
        """Best-effort single-attempt delete; returns providers where it failed."""
        failed = []
        for name in names:
            provider = self._providers[name]
            try:
                self._call(name, "delete", lambda p=provider: p.delete(key), retry=False)
            except StorageError:
                failed.append(name)
        return failed

    def store_chunk(self, file_id: str, chunk_id: str, chunk_index: int, data: bytes,
                    sha256_hex: str) -> StoreResult:
        """Write ``data`` under key ``chunk_id`` to ``replication_factor``
        distinct providers, failing over to fallback candidates. Raises
        ChunkStoreError (after best-effort cleanup) if fewer than
        ``min_write_replicas`` verified replicas exist. ``sha256_hex`` must be
        the SHA-256 of ``data``; it is checked before anything is sent."""
        key = self._chunk_key(chunk_id)
        blob = require_bytes(data)
        sha = self._check_sha(sha256_hex)
        if not hmac.compare_digest(hashlib.sha256(blob).hexdigest(), sha):
            raise StorageError("refusing to store chunk: sha256_hex does not match data")
        R = self.replication_factor
        order = self.placement.targets(file_id, chunk_id, chunk_index, self._names, R)
        preferred, fallbacks = order[:R], sorted(order[R:], key=self._rank)
        queue = preferred + fallbacks

        stored: list[str] = []
        failures: list[ProviderFailure] = []
        maybe_dirty: list[str] = []
        total_attempts = 0
        pending, idx = queue[:R], R
        while pending:
            results = self._fanout(lambda n: self._write_one(n, key, blob, sha), pending)
            for name, (failure, attempts, maybe_written) in zip(pending, results):
                total_attempts += attempts
                if failure is None:
                    stored.append(name)
                else:
                    failures.append(failure)
                    if maybe_written:
                        maybe_dirty.append(name)
            need = R - len(stored)
            pending = queue[idx: idx + need] if need > 0 else []
            idx += len(pending)

        failed_names = [f.provider for f in failures]
        failed_over = any(n in stored for n in fallbacks)
        if len(stored) < self.min_write_replicas:
            cleanup_failed = self._cleanup(key, stored + maybe_dirty)
            self._audit_event(
                event_type="chunk.distribute", action="storage:write", outcome=Outcome.ERROR,
                resource_type="chunk", resource_id=chunk_id, severity=Severity.WARNING,
                reason=f"only {len(stored)} of {self.min_write_replicas} required replicas stored",
                details={"chunk_index": chunk_index, "providers": [], "attempts": total_attempts,
                         "failed_providers": failed_names})
            raise ChunkStoreError(
                f"chunk could not be stored: {len(stored)} of {self.min_write_replicas} required replicas "
                f"succeeded", chunk_id=chunk_id, failures=failures, cleanup_failed=cleanup_failed)

        if maybe_dirty:  # stray partial copies on providers that did not count
            self._cleanup(key, maybe_dirty)
        result = StoreResult(chunk_id=chunk_id, stored_on=stored, failed=failures,
                             degraded=len(stored) < R, failed_over=failed_over, attempts=total_attempts)
        try:
            self._audit_event(
                event_type="chunk.distribute", action="storage:write", outcome=Outcome.SUCCESS,
                resource_type="chunk", resource_id=chunk_id,
                severity=Severity.WARNING if (failures or result.degraded) else Severity.INFO,
                details={"chunk_index": chunk_index, "providers": stored, "attempts": total_attempts,
                         "failed_providers": failed_names})
        except Exception:
            # an operation that cannot be audited must not proceed
            self._cleanup(key, stored)
            raise
        return result

    # -- read path ------------------------------------------------------------ #
    def fetch_chunk(self, chunk_id: str, replicas: Sequence[str],
                    verify: Callable[[bytes], bool]) -> FetchResult:
        """Return the first replica whose bytes pass ``verify``. Replicas are
        tried healthy-first; providers whose breaker is open are tried last
        (reads prefer a slow answer to no answer). Raises ChunkUnavailableError
        with per-replica attempts when none verifies."""
        key = self._chunk_key(chunk_id)
        seen: list[str] = []
        for r in replicas:
            if r not in seen:
                seen.append(r)
        order = sorted(seen, key=lambda n: self._rank(n) if n in self._providers else 3)
        attempts: list[ReplicaAttempt] = []
        result: FetchResult | None = None
        for name in order:
            provider = self._providers.get(name)
            if provider is None:
                attempts.append(ReplicaAttempt(name, "error", 0, "unknown provider"))
                continue
            try:
                data, retries = self._call(name, "get", lambda p=provider: p.get(key), respect_breaker=False,
                                           nbytes=len)
            except StorageError as exc:
                attempts.append(ReplicaAttempt(name, _outcome_of(exc), getattr(exc, "zt_retries", 0),
                                               error_summary(exc), bool(getattr(exc, "injected", False))))
                continue
            try:
                ok = bool(verify(data))
            except Exception as exc:
                attempts.append(ReplicaAttempt(name, "error", retries,
                                               f"verify callback raised {type(exc).__name__}"))
                continue
            if not ok:
                attempts.append(ReplicaAttempt(name, "corrupt", retries, "replica failed verification"))
                continue
            attempts.append(ReplicaAttempt(name, "ok", retries))
            result = FetchResult(data=data, provider=name, attempts=attempts)
            break

        for a in attempts:
            if a.outcome == "corrupt":
                self._audit_event(event_type="storage.replica.corrupt", action="storage:read",
                                  outcome=Outcome.FAILURE, resource_type="chunk", resource_id=chunk_id,
                                  severity=Severity.CRITICAL, reason="replica failed integrity verification",
                                  details={"provider": a.provider})
            elif a.outcome == "missing":
                self._audit_event(event_type="storage.replica.missing", action="storage:read",
                                  outcome=Outcome.FAILURE, resource_type="chunk", resource_id=chunk_id,
                                  severity=Severity.WARNING, reason="replica not found at provider",
                                  details={"provider": a.provider})
        failed = [a.provider for a in attempts if a.outcome != "ok"]
        outcomes = [f"{a.provider}:{a.outcome}" for a in attempts]
        if result is None:
            all_corrupt = bool(attempts) and all(a.outcome == "corrupt" for a in attempts)
            self._audit_event(event_type="chunk.retrieve", action="storage:read",
                              outcome=Outcome.FAILURE if all_corrupt else Outcome.ERROR,
                              resource_type="chunk", resource_id=chunk_id,
                              severity=Severity.CRITICAL if any(a.outcome == "corrupt" for a in attempts)
                              else Severity.WARNING,
                              reason="no replica passed verification" if attempts else "no replicas listed",
                              details={"providers": [], "attempts": len(attempts), "failed_providers": failed,
                                       "outcomes": outcomes})
            raise ChunkUnavailableError(
                f"no valid replica available ({', '.join(outcomes) or 'no replicas'})",
                chunk_id=chunk_id, attempts=attempts)
        self._audit_event(event_type="chunk.retrieve", action="storage:read", outcome=Outcome.SUCCESS,
                          resource_type="chunk", resource_id=chunk_id,
                          severity=Severity.WARNING if failed else Severity.INFO,
                          details={"providers": [result.provider], "attempts": len(attempts),
                                   "failed_providers": failed, "outcomes": outcomes})
        return result

    # -- delete ---------------------------------------------------------------- #
    def delete_chunk(self, chunk_id: str, replicas: Sequence[str]) -> DeleteResult:
        """Delete every listed replica (with retry). Missing objects count as
        deleted. Never raises for provider errors; they are reported in
        ``failed``."""
        key = self._chunk_key(chunk_id)
        names = [n for i, n in enumerate(replicas) if n not in replicas[:i]]

        def one(name: str) -> ProviderFailure | None:
            provider = self._providers.get(name)
            if provider is None:
                return ProviderFailure(name, "UnknownProvider", "unknown provider", False, 0)
            try:
                self._call(name, "delete", lambda: provider.delete(key))
            except ObjectNotFound:
                return None
            except StorageError as exc:
                return _failure(name, exc, 1 + getattr(exc, "zt_retries", 0))
            return None

        results = self._fanout(one, names)
        deleted = [n for n, f in zip(names, results) if f is None]
        return DeleteResult(deleted=deleted, failed=[f for f in results if f is not None])

    # -- scrub / repair ------------------------------------------------------- #
    def verify_replica(self, provider: str, chunk_id: str, sha256_hex: str) -> str:
        """'ok' | 'missing' | 'corrupt' | 'unavailable'. Never raises for
        provider errors (timeouts and other errors count as 'unavailable')."""
        key = self._chunk_key(chunk_id)
        sha = self._check_sha(sha256_hex)
        p = self._providers.get(provider)
        if p is None:
            raise KeyError(f"unknown storage provider {provider!r}")
        try:
            data, _ = self._call(provider, "get", lambda: p.get(key), respect_breaker=False, nbytes=len)
        except ObjectNotFound:
            return "missing"
        except StorageError:
            return "unavailable"
        return "ok" if hmac.compare_digest(hashlib.sha256(data).hexdigest(), sha) else "corrupt"

    def repair_chunk(self, chunk_id: str, chunk_index: int, file_id: str, good_data: bytes, sha256_hex: str,
                     current_replicas: Sequence[str], bad_replicas: Sequence[str]) -> list[str]:
        """Re-replicate ``good_data`` until ``replication_factor`` healthy
        replicas exist. Bad/missing providers are rewritten first, then other
        providers in placement order. Returns the new replica list (good
        existing replicas first). May return fewer than R entries if not
        enough providers accept the write; the caller decides what that means.
        ``good_data`` is verified against ``sha256_hex`` before it is spread."""
        key = self._chunk_key(chunk_id)
        blob = require_bytes(good_data)
        sha = self._check_sha(sha256_hex)
        if not hmac.compare_digest(hashlib.sha256(blob).hexdigest(), sha):
            raise StorageError("refusing to repair: good_data does not match sha256_hex")
        bad = [n for n in bad_replicas if n in self._providers]
        keep: list[str] = []
        for n in current_replicas:
            if n in self._providers and n not in bad and n not in keep:
                keep.append(n)
        R = self.replication_factor
        order = self.placement.targets(file_id, chunk_id, chunk_index, self._names, R)
        others = sorted([n for n in order if n not in keep and n not in bad], key=self._rank)
        queue = [n for i, n in enumerate(bad) if n not in bad[:i]] + others
        written: list[str] = []
        failures: list[ProviderFailure] = []
        attempts_total = 0
        for name in queue:
            if len(keep) + len(written) >= R:
                break
            failure, attempts, _ = self._write_one(name, key, blob, sha)
            attempts_total += attempts
            if failure is None:
                written.append(name)
            else:
                failures.append(failure)
        leftover_bad = [n for n in bad if n not in written]
        if leftover_bad:
            self._cleanup(key, leftover_bad)  # drop corrupt copies we could not replace
        new_set = keep + written
        ok = len(new_set) >= R
        self._audit_event(event_type="chunk.repair", action="storage:repair",
                          outcome=Outcome.SUCCESS if ok else Outcome.ERROR,
                          resource_type="chunk", resource_id=chunk_id,
                          severity=Severity.INFO if ok else Severity.WARNING,
                          reason=None if ok else f"only {len(new_set)} of {R} replicas after repair",
                          details={"chunk_index": chunk_index, "providers": new_set, "attempts": attempts_total,
                                   "failed_providers": [f.provider for f in failures]})
        return new_set

    # -- audit anchors ------------------------------------------------------- #
    @staticmethod
    def _anchor_key(key: str) -> str:
        full = key if key.startswith(ANCHOR_PREFIX) else ANCHOR_PREFIX + key
        validate_key(full)
        if full == ANCHOR_PREFIX:
            raise InvalidObjectKey("anchor key must not be empty")
        return full

    def put_anchor(self, key: str, data: bytes) -> AnchorWriteResult:
        """Write a small object (e.g. a signed audit checkpoint) to ALL
        providers, best effort, verified by size. Not audited here (the audit
        subsystem calls this while checkpointing; auditing from inside would
        recurse)."""
        full = self._anchor_key(key)
        blob = require_bytes(data)

        def one(name: str) -> ProviderFailure | None:
            p = self._providers[name]
            try:
                self._call(name, "put", lambda: p.put(full, blob), nbytes=lambda _r: len(blob))
                info, _ = self._call(name, "stat", lambda: p.stat(full))
                if info.size != len(blob):
                    raise WriteVerificationError("anchor verification failed: size differs", provider=name)
            except ObjectNotFound:
                return _failure(name, WriteVerificationError("anchor missing after acknowledged write",
                                                             provider=name))
            except StorageError as exc:
                return _failure(name, exc, 1 + getattr(exc, "zt_retries", 0))
            return None

        results = self._fanout(one, self._names)
        return AnchorWriteResult(key=full, stored_on=[n for n, f in zip(self._names, results) if f is None],
                                 failed=[f for f in results if f is not None])

    def get_anchor(self, key: str) -> dict[str, AnchorRead]:
        """Read the anchor from every provider; per-provider result."""
        full = self._anchor_key(key)

        def one(name: str) -> AnchorRead:
            p = self._providers[name]
            try:
                data, _ = self._call(name, "get", lambda: p.get(full), respect_breaker=False, nbytes=len)
            except StorageError as exc:
                return AnchorRead(name, _outcome_of(exc), None, error_summary(exc))
            return AnchorRead(name, "ok", data)

        return dict(zip(self._names, self._fanout(one, self._names)))

    def list_anchors(self, prefix: str = "") -> AnchorListing:
        """List anchor keys (full ``anchors/...`` keys) on every provider."""
        full_prefix = ANCHOR_PREFIX + validate_prefix(prefix) if not prefix.startswith(ANCHOR_PREFIX) \
            else validate_prefix(prefix)

        def one(name: str) -> list[str] | StorageError:
            p = self._providers[name]
            try:
                keys, _ = self._call(name, "list", lambda: sorted(p.list_keys(full_prefix)),
                                     respect_breaker=False)
                return keys
            except StorageError as exc:
                return exc

        results = self._fanout(one, self._names)
        keys = {n: r for n, r in zip(self._names, results) if isinstance(r, list)}
        errors = {n: error_summary(r) for n, r in zip(self._names, results) if isinstance(r, StorageError)}
        return AnchorListing(keys=keys, errors=errors)
