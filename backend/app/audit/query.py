"""Read-side of the audit log: search, statistics, export.

Security property: every query is built with SQLAlchemy Core bound
parameters (no string interpolation of caller input), result sizes are
bounded, and the returned events carry ``seq``, ``hash`` and ``prev_hash`` so
a UI can show integrity information next to each record. Nothing here can
modify the log.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Iterable, Iterator, Mapping

from sqlalchemy import Engine, and_, func, or_, select

from app.audit.chain import EVENT_FIELDS, canonical_json, coerce_ts
from app.audit.models import EVENTS
from app.contracts import Outcome, Severity

MAX_LIMIT = 1000
DEFAULT_LIMIT = 100
SEVERITY_ORDER: tuple[str, ...] = (Severity.INFO.value, Severity.WARNING.value,
                                   Severity.CRITICAL.value)
_EXPORT_BATCH = 1000


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def severities_at_least(minimum: Severity | str) -> list[str]:
    value = _enum_value(minimum)
    if value not in SEVERITY_ORDER:
        raise ValueError("unknown severity")
    return list(SEVERITY_ORDER[SEVERITY_ORDER.index(value):])


MAX_ACTORS = 64


def _actor_condition(column, actor: "str | Iterable[str]"):
    """``actor`` is one pseudonym or a collection of pseudonyms (all key
    versions of one user, finding M3/L7) -> ``=`` or ``IN (...)``."""
    if isinstance(actor, str):
        return column == actor
    values = sorted({str(a) for a in actor})
    if not values or len(values) > MAX_ACTORS:
        raise ValueError("actor set must hold 1..64 pseudonyms")
    return column.in_(values)


def event_to_dict(row: Mapping[str, Any]) -> dict[str, Any]:
    """Stored row -> API dict (``details`` parsed back into an object)."""
    out = {f: row[f] for f in EVENT_FIELDS}
    try:
        out["details"] = json.loads(row["details"]) if row["details"] else {}
    except (TypeError, ValueError):
        out["details"] = {"_unparseable": True}
    return out


class AuditQuery:
    """Search and reporting over the audit events table."""

    def __init__(self, engine: Engine):
        self._engine = engine

    # ------------------------------------------------------------------ #
    def search(
        self,
        *,
        actor: "str | Iterable[str] | None" = None,
        event_type: str | None = None,
        action: str | None = None,
        resource_id: str | None = None,
        resource_type: str | None = None,
        outcome: Outcome | str | None = None,
        severity: Severity | str | None = None,
        min_severity: Severity | str | None = None,
        ts_from: datetime | str | None = None,
        ts_to: datetime | str | None = None,
        request_id: str | None = None,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
        order: str = "desc",
    ) -> tuple[list[dict[str, Any]], int]:
        """Filtered, paginated search. Returns ``(events, total_matching)``.

        ``actor`` is a pseudonym (see ``AuditService.pseudonym_for``) or a
        collection of pseudonyms (``AuditService.pseudonyms_for``: SQL ``IN``).
        ``event_type`` is exact, or a prefix when it ends in ``*`` or ``.``
        (``"auth.*"``, ``"auth."``). ``ts_from`` is inclusive, ``ts_to``
        exclusive. ``limit`` must be 1..1000 and ``offset`` >= 0, otherwise
        ValueError (the API layer maps that to 422)."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be >= 0")
        if order not in ("asc", "desc"):
            raise ValueError("order must be 'asc' or 'desc'")

        c = EVENTS.c
        conds = []
        if actor is not None:
            conds.append(_actor_condition(c.actor, actor))
        if event_type is not None:
            if event_type.endswith("*"):
                conds.append(c.event_type.startswith(event_type[:-1], autoescape=True))
            elif event_type.endswith("."):
                conds.append(c.event_type.startswith(event_type, autoescape=True))
            else:
                conds.append(c.event_type == event_type)
        if action is not None:
            conds.append(c.action == action)
        if resource_id is not None:
            conds.append(c.resource_id == resource_id)
        if resource_type is not None:
            conds.append(c.resource_type == resource_type)
        if outcome is not None:
            conds.append(c.outcome == _enum_value(outcome))
        if severity is not None:
            conds.append(c.severity == _enum_value(severity))
        if min_severity is not None:
            conds.append(c.severity.in_(severities_at_least(min_severity)))
        if ts_from is not None:
            conds.append(c.ts >= coerce_ts(ts_from))
        if ts_to is not None:
            conds.append(c.ts < coerce_ts(ts_to))
        if request_id is not None:
            conds.append(c.request_id == request_id)

        where = and_(*conds) if conds else None
        count_stmt = select(func.count()).select_from(EVENTS)
        stmt = select(EVENTS)
        if where is not None:
            count_stmt = count_stmt.where(where)
            stmt = stmt.where(where)
        stmt = stmt.order_by(c.seq.asc() if order == "asc" else c.seq.desc())
        stmt = stmt.limit(limit).offset(offset)
        with self._engine.connect() as conn:
            total = conn.execute(count_stmt).scalar_one()
            rows = conn.execute(stmt).mappings().all()
        return [event_to_dict(r) for r in rows], int(total)

    def get_event(self, seq: int) -> dict[str, Any] | None:
        """One event by sequence number, or None."""
        with self._engine.connect() as conn:
            row = conn.execute(select(EVENTS).where(EVENTS.c.seq == int(seq))).mappings().first()
        return event_to_dict(row) if row is not None else None

    # ------------------------------------------------------------------ #
    def stats(self, since: datetime | str | None = None) -> dict[str, Any]:
        """Dashboard counters since ``since`` (inclusive; None = everything
        retained): total, by outcome, by severity, by event-type prefix (the
        part before the first dot) and by full event type."""
        c = EVENTS.c
        where = c.ts >= coerce_ts(since) if since is not None else None

        def grouped(col):
            stmt = select(col, func.count()).group_by(col)
            return stmt.where(where) if where is not None else stmt

        with self._engine.connect() as conn:
            by_outcome = {k: int(v) for k, v in conn.execute(grouped(c.outcome)).all()}
            by_severity = {k: int(v) for k, v in conn.execute(grouped(c.severity)).all()}
            by_type = {k: int(v) for k, v in conn.execute(grouped(c.event_type)).all()}
            head = conn.execute(select(func.min(c.seq), func.max(c.seq))).one()
        by_prefix: dict[str, int] = {}
        for etype, n in by_type.items():
            prefix = etype.split(".", 1)[0]
            by_prefix[prefix] = by_prefix.get(prefix, 0) + n
        for o in Outcome:
            by_outcome.setdefault(o.value, 0)
        for s in Severity:
            by_severity.setdefault(s.value, 0)
        return {
            "since": coerce_ts(since) if since is not None else None,
            "total": sum(by_type.values()),
            "by_outcome": by_outcome,
            "by_severity": by_severity,
            "by_event_prefix": dict(sorted(by_prefix.items())),
            "by_event_type": dict(sorted(by_type.items())),
            "first_seq": head[0],
            "last_seq": head[1],
        }

    def recent_security_events(self, limit: int = 50, *, severity: str | None = None,
                               actors: "Iterable[str] | None" = None) -> list[dict[str, Any]]:
        """Newest events with severity >= warning or outcome denied/failure
        (the security centre feed). With ``severity`` only events of exactly
        that severity (the security centre's separate critical list, so a
        flood of warnings cannot push critical alerts out; finding M2). With
        ``actors`` only those pseudonyms' events."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
        c = EVENTS.c
        if severity is not None:
            sev = _enum_value(severity)
            if sev not in SEVERITY_ORDER:
                raise ValueError("unknown severity")
            cond = c.severity == sev
        else:
            cond = or_(c.severity.in_(severities_at_least(Severity.WARNING)),
                       c.outcome.in_([Outcome.DENIED.value, Outcome.FAILURE.value]))
        if actors is not None:
            cond = and_(cond, _actor_condition(c.actor, actors))
        stmt = select(EVENTS).where(cond).order_by(c.seq.desc()).limit(limit)
        with self._engine.connect() as conn:
            rows = conn.execute(stmt).mappings().all()
        return [event_to_dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    def export_ndjson(self, from_seq: int | None = None, to_seq: int | None = None, *,
                      actors: "Iterable[str] | None" = None) -> Iterator[str]:
        """Stream events ``from_seq..to_seq`` (inclusive, ascending) as NDJSON.

        Each line is the canonical JSON of the stored record exactly as
        hashed, plus ``hash`` (``details`` stays a JSON *string*), so an
        investigator can re-verify the chain offline:
        ``hash == sha256(bytes.fromhex(prev_hash) + canonical(line - hash))``.
        Rows are read in batches; the table is never loaded whole. With
        ``actors`` (the own-scope export, finding L7) the actor filter is part
        of the SQL query (indexed column), so only matching rows are read."""
        c = EVENTS.c
        actor_cond = _actor_condition(c.actor, actors) if actors is not None else None
        last = (int(from_seq) - 1) if from_seq is not None else None
        while True:
            stmt = select(EVENTS).order_by(c.seq.asc()).limit(_EXPORT_BATCH)
            if last is not None:
                stmt = stmt.where(c.seq > last)
            if to_seq is not None:
                stmt = stmt.where(c.seq <= int(to_seq))
            if actor_cond is not None:
                stmt = stmt.where(actor_cond)
            with self._engine.connect() as conn:
                rows = conn.execute(stmt).mappings().all()
            if not rows:
                return
            for row in rows:
                yield canonical_json({f: row[f] for f in EVENT_FIELDS}) + "\n"
            last = rows[-1]["seq"]
