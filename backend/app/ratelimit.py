"""In-memory token-bucket rate limiter.

Security property: bounds how fast one client key (IP, user id, ...) can drive
an operation such as login guessing or upload flooding.

Limitations (see docs/THREAT_MODEL.md): state is PER PROCESS. Several
backend workers/instances each keep their own buckets, so the effective limit
is multiplied by the number of processes, and a restart resets all buckets.
A distributed limiter (e.g. Redis) is not implemented.

Memory is bounded: buckets that have refilled completely carry no state worth
keeping and are swept; if more than ``max_buckets`` are still live the least
recently used are evicted (which can only make the limiter more lenient for
those keys, never stricter).
"""
from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Hashable

from app.errors import RateLimited


IPV6_RATE_LIMIT_PREFIX = 64


def client_network_key(ip: str | None) -> str:
    """Rate-limit key for a client address (finding L4).

    IPv4 addresses are keyed individually (/32). IPv6 addresses are keyed by
    their /64: one end site normally receives at least a /64, so keying the
    full address would give a single client 2**64 independent buckets.
    IPv4-mapped IPv6 is treated as IPv4. The key is the network *address*
    (a valid IP string, e.g. ``2001:db8:1:2::``), so it can also be used as an
    audit ``source_ip`` (the audit filter generalises it further). Missing or
    unparseable input maps to ``"unknown"`` (one shared bucket)."""
    if not ip:
        return "unknown"
    text = str(ip).strip()
    if text.startswith("[") and "]" in text:
        text = text[1:text.index("]")]
    text = text.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return "unknown"
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.IPv6Network((addr, IPV6_RATE_LIMIT_PREFIX), strict=False).network_address)
    return str(addr)


@dataclass
class _Bucket:
    tokens: float
    capacity: float
    rate: float          # tokens per second
    updated: float


class RateLimiter:
    """Thread-safe token buckets keyed by ``(scope, key)``.

    ``check(scope, key, limit_per_minute)``: bucket capacity is
    ``limit_per_minute`` (burst) and it refills at ``limit_per_minute / 60``
    tokens per second. Each call spends one token or raises
    ``RateLimited`` with ``retry_after_seconds`` set (integer, >= 1).
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic, max_buckets: int = 100_000,
                 sweep_every: int = 1024) -> None:
        if max_buckets < 1:
            raise ValueError("max_buckets must be >= 1")
        self._clock = clock
        self._max = max_buckets
        self._sweep_every = max(1, sweep_every)
        self._buckets: OrderedDict[tuple[str, Hashable], _Bucket] = OrderedDict()
        self._lock = threading.Lock()
        self._calls = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._buckets)

    @staticmethod
    def _refill(bucket: _Bucket, now: float) -> None:
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(bucket.capacity, bucket.tokens + elapsed * bucket.rate)
        bucket.updated = now

    def _sweep(self, now: float) -> None:
        """Drop buckets that are full again (indistinguishable from new)."""
        idle = [k for k, b in self._buckets.items()
                if b.tokens + max(0.0, now - b.updated) * b.rate >= b.capacity]
        for k in idle:
            del self._buckets[k]

    def check(self, scope: str, key: Hashable, limit_per_minute: int) -> None:
        """Spend one token for ``(scope, key)`` or raise ``RateLimited``.
        The exception message never contains the key (it may be an IP or user)."""
        if not isinstance(limit_per_minute, int) or isinstance(limit_per_minute, bool) or limit_per_minute < 1:
            raise ValueError("limit_per_minute must be a positive integer")
        now = float(self._clock())
        capacity = float(limit_per_minute)
        rate = capacity / 60.0
        bk = (scope, key)
        with self._lock:
            self._calls += 1
            bucket = self._buckets.get(bk)
            if bucket is None:
                if self._calls % self._sweep_every == 0 or len(self._buckets) >= self._max:
                    self._sweep(now)
                while len(self._buckets) >= self._max:
                    self._buckets.popitem(last=False)          # least recently used
                bucket = _Bucket(tokens=capacity, capacity=capacity, rate=rate, updated=now)
                self._buckets[bk] = bucket
            else:
                self._refill(bucket, now)
                if bucket.capacity != capacity:                # limit reconfigured
                    bucket.capacity, bucket.rate = capacity, rate
                    bucket.tokens = min(bucket.tokens, capacity)
                self._buckets.move_to_end(bk)
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return
            retry_after = max(1, math.ceil((1.0 - bucket.tokens) / bucket.rate))
        exc = RateLimited("rate limit exceeded", reasons=("rate-limited",))
        exc.retry_after_seconds = retry_after
        raise exc

    def exhausted(self, scope: str, key: Hashable, limit_per_minute: int) -> int:
        """Peek without spending: 0 if ``(scope, key)`` has at least one token
        (or no bucket yet), otherwise the Retry-After in seconds. Used to
        refuse a request cheaply before doing expensive work whose FAILURE is
        what spends the tokens (``spend``)."""
        now = float(self._clock())
        with self._lock:
            bucket = self._buckets.get((scope, key))
            if bucket is None:
                return 0
            tokens = min(bucket.capacity, bucket.tokens + max(0.0, now - bucket.updated) * bucket.rate)
            if tokens >= 1.0:
                return 0
            return max(1, math.ceil((1.0 - tokens) / bucket.rate))

    def spend(self, scope: str, key: Hashable, limit_per_minute: int) -> bool:
        """Spend one token if available. Returns False (instead of raising)
        when the bucket is empty."""
        try:
            self.check(scope, key, limit_per_minute)
        except RateLimited:
            return False
        return True

    def reset(self, scope: str | None = None) -> None:
        """Clear all buckets, or only those of one scope."""
        with self._lock:
            if scope is None:
                self._buckets.clear()
            else:
                for k in [k for k in self._buckets if k[0] == scope]:
                    del self._buckets[k]


# --------------------------------------------------------------------------- #
# Auditing of rejections (finding F6)
# --------------------------------------------------------------------------- #
@dataclass
class _RejectWindow:
    started: datetime
    suppressed: int = 0
    user_keyed: bool = False
    key: Hashable = None


class RateLimitAuditor:
    """Puts HTTP 429s into the tamper-evident audit log without letting a
    flood flood the log.

    * The FIRST rejection per ``(scope, key)`` per window is recorded as
      ``security.rate-limited`` (outcome denied, WARNING, ``details={"scope",
      "count": 1, "window_seconds", "kind": "first"}``), with the request's
      id, client network and (for user-keyed scopes) actor.
    * Further rejections in the same window are only counted. When a later
      rejection or the periodic ``flush`` finds the window over, one summary
      event (``kind: "summary"``, ``count`` = rejections not recorded
      individually) is written, outside any request context so it is not
      attributed to an unrelated request.
    * State is bounded (``max_keys``; the oldest windows are summarised and
      dropped first). Like the limiter itself it is per process.

    The limiter key (an IP or a user id) is never put in ``details``: an IP
    goes in ``source_ip`` (generalised by the audit filter) and a user id in
    ``actor_id`` (pseudonymised)."""

    EVENT = "security.rate-limited"

    def __init__(self, *, audit: object, clock: Callable[[], datetime], window_seconds: int = 60,
                 max_keys: int = 10_000) -> None:
        self._audit = audit
        self._clock = clock
        self._window = max(1, int(window_seconds))
        self._max = max(1, int(max_keys))
        self._lock = threading.Lock()
        self._windows: OrderedDict[tuple[str, Hashable], _RejectWindow] = OrderedDict()

    def _expired(self, w: _RejectWindow, now: datetime) -> bool:
        return (now - w.started).total_seconds() >= self._window

    def _emit(self, scope: str, w: _RejectWindow, *, kind: str, count: int, request_id: str | None = None,
              source_ip: str | None = None) -> None:
        from app.contracts import Outcome, Severity     # local: keep the limiter import-light
        actor = str(w.key) if w.user_keyed else None
        ip = None if w.user_keyed else (str(w.key) if w.key is not None else None)
        self._audit.record(
            event_type=self.EVENT, action="security:rate-limit", outcome=Outcome.DENIED,
            actor_id=actor, reason="rate-limited", severity=Severity.WARNING,
            details={"scope": scope, "count": int(count), "window_seconds": self._window, "kind": kind},
            request_id=request_id, source_ip=source_ip if source_ip is not None else ip)

    def _summarise(self, items: list[tuple[str, _RejectWindow]]) -> None:
        from app.audit.context import suspended
        with suspended():
            for scope, w in items:
                if w.suppressed > 0:
                    try:
                        self._emit(scope, w, kind="summary", count=w.suppressed)
                    except Exception:   # pragma: no cover - auditing must not break the 429 path
                        pass

    def _track(self, scope: str, key: Hashable, user_keyed: bool) -> tuple[bool, _RejectWindow]:
        """Open or extend the window of ``(scope, key)``. Returns ``(first,
        window)``; windows that are over (or evicted) are summarised."""
        now = self._clock()
        bk = (scope, key)
        first = False
        done: list[tuple[str, _RejectWindow]] = []
        with self._lock:
            w = self._windows.get(bk)
            if w is not None and self._expired(w, now):
                done.append((scope, self._windows.pop(bk)))
                w = None
            if w is None:
                while len(self._windows) >= self._max:
                    (s, _k), old = self._windows.popitem(last=False)
                    done.append((s, old))
                w = _RejectWindow(started=now, user_keyed=user_keyed, key=key)
                self._windows[bk] = w
                first = True
            else:
                w.suppressed += 1
                self._windows.move_to_end(bk)
        self._summarise(done)
        return first, w

    def rejected(self, scope: str, key: Hashable, *, user_keyed: bool = False, request_id: str | None = None,
                 source_ip: str | None = None) -> None:
        """Called for every 429. Never raises."""
        first, w = self._track(scope, key, user_keyed)
        if first:
            try:
                self._emit(scope, w, kind="first", count=1, request_id=request_id, source_ip=source_ip)
            except Exception:   # pragma: no cover - fail open for the audit, the 429 still happens
                pass

    def flush(self, *, force: bool = False) -> int:
        """Summarise and drop windows that are over (all of them with
        ``force``). Returns the number of summary events written."""
        now = self._clock()
        with self._lock:
            keys = [k for k, w in self._windows.items() if force or self._expired(w, now)]
            done = [(k[0], self._windows.pop(k)) for k in keys]
        self._summarise(done)
        return sum(1 for _, w in done if w.suppressed > 0)


class TokenFailureAuditor(RateLimitAuditor):
    """Aggregates ``auth.token`` failure events (finding M2) the same way
    ``RateLimitAuditor`` aggregates 429s: per client network (IPv4 /32, IPv6
    /64, ``client_network_key``) the FIRST invalid bearer token in a window is
    recorded individually by the auth service (``admit`` returns True); later
    ones are only counted and written as one ``auth.token`` summary event
    (outcome failure, WARNING, reason ``token-failures-aggregated``,
    ``details={"count", "window_seconds", "kind": "summary", "scope": "token"}``)
    when the window is over. Together with the invalid-token rate limit this
    bounds what an anonymous client can append to the audit chain."""

    EVENT = "auth.token"
    SCOPE = "token"

    def admit(self, source_ip: str | None) -> bool:
        """True if this failure should be recorded individually. Never raises."""
        try:
            first, _ = self._track(self.SCOPE, client_network_key(source_ip), False)
        except Exception:   # pragma: no cover - fail open: record it
            return True
        return first

    def _emit(self, scope: str, w: _RejectWindow, *, kind: str, count: int, request_id: str | None = None,
              source_ip: str | None = None) -> None:
        from app.contracts import Outcome, Severity
        ip = str(w.key) if w.key is not None and w.key != "unknown" else None
        self._audit.record(
            event_type=self.EVENT, action="auth:token", outcome=Outcome.FAILURE,
            reason="token-failures-aggregated", severity=Severity.WARNING,
            details={"scope": scope, "count": int(count), "window_seconds": self._window, "kind": kind},
            request_id=request_id, source_ip=source_ip if source_ip is not None else ip)
