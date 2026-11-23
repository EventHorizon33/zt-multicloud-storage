"""Retention: delete old audit events without destroying verifiability.

Security property: events are only ever deleted as a whole prefix of the
chain that ends at a signed (and anchored) checkpoint of kind
``"retention"``. Verification then requires the first retained record's
``prev_hash`` to equal that checkpoint's signed ``head_hash``, so a
legitimate pruning is distinguishable from an attacker deleting records:
removing even one more early record (or any record outside retention) is
reported as ``genesis-invalid``.

Retention refuses to run if the prefix it would delete does not verify, so
it can never be used to launder evidence of tampering.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import and_, delete, func, select
from sqlalchemy.exc import SQLAlchemyError

from app.audit.chain import format_ts
from app.audit.errors import AuditError, AuditIntegrityError
from app.audit.models import CHECKPOINTS, EVENTS, begin_write
from app.audit.records import AuditContext, Checkpoint, RetentionResult
from app.contracts import Outcome, Severity

if TYPE_CHECKING:  # pragma: no cover
    from app.audit.service import AuditService


def _count(conn) -> int:
    return int(conn.execute(select(func.count()).select_from(EVENTS)).scalar_one())


def apply_retention(service: "AuditService", now: datetime | None = None, *,
                    audit_context: AuditContext | None = None) -> RetentionResult:
    """Prune events older than ``now - settings.audit_retention_days``.

    The cut point S is the last seq such that *every* event with seq <= S is
    older than the cutoff (an event with a newer timestamp stops the cut, so
    nothing younger than the retention period is ever deleted). Steps:

    1. verify the chain from the first retained record up to S (refuse with
       ``AuditIntegrityError`` if it does not verify);
    2. in ONE write transaction: sign and insert a ``retention`` checkpoint
       at S (head_hash = hash of record S), delete events seq <= S and
       non-retention checkpoints with seq <= S;
    3. anchor the retention checkpoint on every provider.

    ``audit_retention_days <= 0`` disables retention (nothing is deleted)."""
    settings = service.settings
    days = int(settings.audit_retention_days)
    try:
        result = _apply(service, days, now)
    except Exception as exc:
        if audit_context is not None:
            service._record_housekeeping(
                audit_context, "audit.retention", "audit:retention",
                Outcome.FAILURE if isinstance(exc, AuditIntegrityError) else Outcome.ERROR,
                {"error_class": type(exc).__name__, "window_seconds": max(days, 0) * 86400},
                Severity.CRITICAL if isinstance(exc, AuditIntegrityError) else Severity.WARNING)
        if isinstance(exc, SQLAlchemyError):
            raise AuditError("retention could not be applied") from None
        raise
    if audit_context is not None:
        service._record_housekeeping(
            audit_context, "audit.retention", "audit:retention", Outcome.SUCCESS,
            {"deleted": result.deleted, "kept": result.kept,
             "first_seq": result.new_first_seq, "seq": result.checkpoint_seq,
             "mode": "disabled" if days <= 0 else "applied",
             "window_seconds": max(days, 0) * 86400})
    return result


def _apply(service: "AuditService", days: int, now: datetime | None) -> RetentionResult:
    engine = service.engine
    if days <= 0:
        with engine.connect() as conn:
            kept = _count(conn)
            first = conn.execute(select(func.min(EVENTS.c.seq))).scalar()
        return RetentionResult(deleted=0, kept=kept, new_first_seq=first, checkpoint_seq=None)

    now = now or service._clock()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    cutoff = format_ts(now - timedelta(days=days))

    with service._lock:
        with engine.connect() as conn:
            first = conn.execute(select(func.min(EVENTS.c.seq))).scalar()
            head = conn.execute(select(func.max(EVENTS.c.seq))).scalar()
            if first is None:
                return RetentionResult(0, 0, None, None)
            first_young = conn.execute(select(func.min(EVENTS.c.seq))
                                       .where(EVENTS.c.ts >= cutoff)).scalar()
        cut = int(head) if first_young is None else int(first_young) - 1
        if cut < int(first):
            with engine.connect() as conn:
                return RetentionResult(0, _count(conn), int(first), None)

        # 1. never delete a prefix that does not verify (evidence preservation)
        report = service.verify_chain(to_seq=cut, check_anchors=True)
        failing = [f for f in report.findings
                   if f.type not in ("anchor-missing", "anchor-unavailable", "truncated")]
        if failing or report.last_seq != cut:
            raise AuditIntegrityError("audit chain does not verify; retention refused")

        # 2. checkpoint + delete atomically
        with engine.connect() as conn:
            try:
                begin_write(conn)
                row = conn.execute(select(EVENTS.c.hash).where(EVENTS.c.seq == cut)).first()
                if row is None:
                    raise AuditIntegrityError("retention cut point vanished")
                cp: Checkpoint = service._store_checkpoint(cut, row[0], "retention", conn)
                deleted = conn.execute(EVENTS.delete().where(EVENTS.c.seq <= cut)).rowcount
                conn.execute(delete(CHECKPOINTS).where(and_(CHECKPOINTS.c.seq <= cut,
                                                            CHECKPOINTS.c.kind != "retention")))
                kept = _count(conn)
                new_first = conn.execute(select(func.min(EVENTS.c.seq))).scalar()
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
    # 3. anchor outside the lock (network I/O); failures are recorded, not raised
    service._anchor(cp)
    return RetentionResult(deleted=int(deleted), kept=kept,
                           new_first_seq=int(new_first) if new_first is not None else None,
                           checkpoint_seq=cut)
