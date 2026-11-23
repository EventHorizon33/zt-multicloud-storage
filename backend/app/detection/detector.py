"""Download-volume and authentication-failure anomaly detection.

Security properties:
  * Bulk export through legitimate download calls (the UNC5537 pattern,
    case study §5.3/§7.3) is detected per user over a sliding window of
    ``DownloadRecord`` rows. When the next download would exceed the count or
    byte threshold of the current policy, a ``DownloadBlock`` is written for
    ``block_seconds`` and a CRITICAL ``security.anomaly.bulk-download`` event
    is audited. The block only takes effect through the PDP
    (``RequestContext.download_blocked`` -> ``download-rate-exceeded``).
  * Credential stuffing (many different accounts failing from one source
    network) raises a CRITICAL ``security.anomaly.auth-failures`` event.
    Account names are kept only as HMACs under a per-process random key and
    never leave memory; source addresses are generalised to a network.

Limitations: the auth-failure window is per process (like the rate limiter);
download thresholds are checked before the download and recorded after it,
so N concurrent downloads by one user can overshoot the count by up to N-1.
The audit detail keys ``block_seconds`` and ``distinct_accounts`` are not in
the audit module's global allow-list; the container registers them for
``security.anomaly.*`` (``app/container.py``).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.orm import Session as DbSession

from app.contracts import AuditSink, Outcome, Severity
from app.models import DownloadBlock, DownloadRecord

Clock = Callable[[], datetime]

BULK_DOWNLOAD_EVENT = "security.anomaly.bulk-download"
AUTH_ANOMALY_EVENT = "security.anomaly.auth-failures"


class DownloadThresholds(Protocol):
    """Duck-typed view of ``PolicyConfig`` (keeps this package free of an
    import of app.policy)."""
    max_downloads_in_window: int
    max_download_bytes_in_window: int
    window_seconds: int
    block_seconds: int


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class DownloadSignals:
    """What goes into ``RequestContext`` for a ``file:read`` decision."""
    count: int                       # downloads in the window (before this one)
    bytes: int                       # plaintext bytes downloaded in the window
    blocked: bool
    blocked_until: datetime | None = None
    newly_blocked: bool = False      # this evaluation created the block


class DownloadDetector:
    """Sliding-window bulk-download detector backed by the metadata DB."""

    def __init__(self, *, audit: AuditSink, clock: Clock) -> None:
        self._audit = audit
        self._clock = clock

    def _now(self) -> datetime:
        return _utc(self._clock())  # type: ignore[return-value]

    # ------------------------------------------------------------------ #
    def _window_stats(self, db: DbSession, user_id: str, since: datetime) -> tuple[int, int]:
        count, total = db.execute(
            select(func.count(DownloadRecord.id), func.coalesce(func.sum(DownloadRecord.size_bytes), 0))
            .where(DownloadRecord.user_id == user_id, DownloadRecord.at >= since)
        ).one()
        return int(count or 0), int(total or 0)

    def _block_row(self, db: DbSession, user_id: str) -> DownloadBlock | None:
        return db.execute(select(DownloadBlock).where(DownloadBlock.user_id == user_id)
                          .execution_options(populate_existing=True)).scalar_one_or_none()

    def signals(self, db: DbSession, user_id: str, thresholds: DownloadThresholds,
                now: datetime | None = None) -> DownloadSignals:
        """Current window statistics and block state (read-only)."""
        now = _utc(now) or self._now()
        since = now - timedelta(seconds=int(thresholds.window_seconds))
        count, total = self._window_stats(db, user_id, since)
        block = self._block_row(db, user_id)
        until = _utc(block.blocked_until) if block is not None else None
        blocked = until is not None and until > now
        return DownloadSignals(count=count, bytes=total, blocked=blocked,
                               blocked_until=until if blocked else None)

    def evaluate(self, db: DbSession, user_id: str, *, size_bytes: int, thresholds: DownloadThresholds,
                 actor_role: str | None = None, resource_id: str | None = None,
                 request_id: str | None = None, source_ip: str | None = None) -> DownloadSignals:
        """Called BEFORE a download is authorised. Prunes old records; if the
        user is already blocked, or this download (``size_bytes``) would push
        the window over a threshold, writes/extends a ``DownloadBlock`` and
        audits a CRITICAL anomaly. Commits its own changes."""
        now = self._now()
        window = int(thresholds.window_seconds)
        since = now - timedelta(seconds=window)
        db.execute(delete(DownloadRecord).where(DownloadRecord.at < since))
        sig = self.signals(db, user_id, thresholds, now)
        if sig.blocked:
            db.commit()
            return sig
        over_count = sig.count + 1 > int(thresholds.max_downloads_in_window)
        over_bytes = sig.bytes + max(0, int(size_bytes)) > int(thresholds.max_download_bytes_in_window)
        if not (over_count or over_bytes):
            db.commit()
            return sig
        block_seconds = int(thresholds.block_seconds)
        until = now + timedelta(seconds=block_seconds) if block_seconds > 0 else None
        try:
            if until is not None:
                row = self._block_row(db, user_id)
                if row is None:
                    db.add(DownloadBlock(user_id=user_id, blocked_until=until, reason="bulk-download"))
                else:
                    row.blocked_until = until
                    row.reason = "bulk-download"
                try:
                    db.flush()
                except SAIntegrityError:
                    # A concurrent request of the same user inserted the block
                    # first (primary key = user_id). That request audits the
                    # anomaly; this one is simply blocked.
                    db.rollback()
                    return self.signals(db, user_id, thresholds, now)
            self._audit.record(
                event_type=BULK_DOWNLOAD_EVENT, action="file:read", outcome=Outcome.DENIED
                if until is not None else Outcome.FAILURE,
                actor_id=user_id, actor_role=actor_role, resource_type="file", resource_id=resource_id,
                reason="download-count-threshold" if over_count else "download-bytes-threshold",
                severity=Severity.CRITICAL,
                details={"count": sig.count + 1, "bytes": sig.bytes + max(0, int(size_bytes)),
                         "window_seconds": window,
                         "threshold": int(thresholds.max_downloads_in_window) if over_count
                         else int(thresholds.max_download_bytes_in_window),
                         "block_seconds": block_seconds},
                request_id=request_id, source_ip=source_ip)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return DownloadSignals(count=sig.count, bytes=sig.bytes, blocked=until is not None,
                               blocked_until=until, newly_blocked=until is not None)

    def record(self, db: DbSession, user_id: str, file_id: str, size_bytes: int) -> None:
        """Count a completed (verified, released) download. Commits."""
        db.add(DownloadRecord(user_id=user_id, file_id=file_id, size_bytes=max(0, int(size_bytes)),
                              at=self._now()))
        db.commit()

    def prune(self, db: DbSession, window_seconds: int) -> int:
        """Housekeeping: drop records older than the window and expired
        blocks. Returns the number of download records removed. Commits."""
        now = self._now()
        removed = db.execute(delete(DownloadRecord).where(
            DownloadRecord.at < now - timedelta(seconds=int(window_seconds)))).rowcount
        db.execute(delete(DownloadBlock).where(DownloadBlock.blocked_until <= now))
        db.commit()
        return int(removed or 0)

    def active_blocks(self, db: DbSession, user_id: str | None = None) -> list[DownloadBlock]:
        now = self._now()
        stmt = select(DownloadBlock).where(DownloadBlock.blocked_until > now)
        if user_id is not None:
            stmt = stmt.where(DownloadBlock.user_id == user_id)
        return list(db.execute(stmt.order_by(DownloadBlock.blocked_until.desc())).scalars())

    def lift_block(self, db: DbSession, user_id: str) -> bool:
        """Remove a block (admin action; the caller audits it). Commits."""
        result = db.execute(delete(DownloadBlock).where(DownloadBlock.user_id == user_id))
        db.commit()
        return bool(result.rowcount)


class AuthFailureDetector:
    """Flags one source network failing logins for many DIFFERENT accounts
    within ``window_seconds`` (credential stuffing / password spraying).

    In-memory, bounded (``max_networks`` LRU). One alert per network per
    window. Account names are reduced to an HMAC under a random key created
    at start-up, so even process memory holds no usernames from this
    module."""

    def __init__(self, *, audit: AuditSink, clock: Clock, window_seconds: int = 300,
                 distinct_accounts_threshold: int = 5, prefix_v4: int = 24, prefix_v6: int = 48,
                 max_networks: int = 10_000, max_events_per_network: int = 4096) -> None:
        if distinct_accounts_threshold < 2:
            raise ValueError("distinct_accounts_threshold must be >= 2")
        self._audit = audit
        self._clock = clock
        self.window_seconds = int(window_seconds)
        self.threshold = int(distinct_accounts_threshold)
        self._p4, self._p6 = int(prefix_v4), int(prefix_v6)
        self._max = int(max_networks)
        self._max_events = max(self.threshold, int(max_events_per_network))
        self._key = os.urandom(32)
        self._lock = threading.Lock()
        # network -> (deque[(ts, account_hmac)], last_alert_ts | None)
        self._nets: OrderedDict[str, tuple[deque, list]] = OrderedDict()

    def _network(self, source_ip: str | None) -> str | None:
        if not source_ip:
            return None
        try:
            ip = ipaddress.ip_address(source_ip.strip())
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        prefix = self._p4 if ip.version == 4 else self._p6
        return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))

    def record_failure(self, source_ip: str | None, username: Any, *,
                       request_id: str | None = None) -> bool:
        """Note one failed login. Returns True if this failure raised an alert."""
        net = self._network(source_ip)
        if net is None:
            return False
        name = username.lower() if isinstance(username, str) else repr(type(username))
        account = hmac.new(self._key, name.encode("utf-8", "replace"), hashlib.sha256).digest()
        now = _utc(self._clock())
        cutoff = now - timedelta(seconds=self.window_seconds)
        with self._lock:
            entry = self._nets.get(net)
            if entry is None:
                entry = (deque(maxlen=self._max_events), [None])
                self._nets[net] = entry
            self._nets.move_to_end(net)
            while len(self._nets) > self._max:
                self._nets.popitem(last=False)
            events, last_alert = entry
            events.append((now, account))
            while events and events[0][0] < cutoff:
                events.popleft()
            distinct = len({a for _, a in events})
            # (a bounded deque keeps memory flat under a flood; it can only
            # under-count distinct accounts, never invent them)
            fire = distinct >= self.threshold and (last_alert[0] is None or last_alert[0] < cutoff)
            if fire:
                last_alert[0] = now
            failures = len(events)
        if fire:
            self._audit.record(
                event_type=AUTH_ANOMALY_EVENT, action="auth:login", outcome=Outcome.FAILURE,
                resource_type="network", reason="many-accounts-failing-from-one-network",
                severity=Severity.CRITICAL,
                details={"count": failures, "distinct_accounts": distinct,
                         "window_seconds": self.window_seconds, "threshold": self.threshold},
                request_id=request_id, source_ip=source_ip)
        return fire
