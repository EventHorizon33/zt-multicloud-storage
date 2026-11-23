"""/api/audit: search, event by seq, verify, checkpoints, retention, export.

Scoping (integration item 5): callers whose role passes ``audit:read-all``
(auditor, admin) see every event; everyone else is enforced on
``audit:read-own`` and the API forces ``actor`` to the caller's own
pseudonym, whatever filter the client sent. "Own" means every pseudonym the
caller has had (one per retained pseudonym-key version, finding M3), matched
in SQL (``actor IN (...)``), also for the export (finding L7, which is also
rate limited). Integer parameters are bounded (``seq`` 1..2**63-1, I2)."""
from __future__ import annotations

from datetime import datetime
from typing import Iterator

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import StreamingResponse

from app.api.deps import Caller, get_caller, rate_limit
from app.api.schemas import VerifyIn
from app.audit import AuditContext
from app.contracts import Action, Resource
from app.errors import NotFound, ValidationFailed

router = APIRouter(prefix="/api/audit", tags=["audit"])

AUDIT = Resource(type="audit")
#: Largest value of a signed 64-bit INTEGER (SQLite / PostgreSQL bigint).
MAX_SEQ = 2**63 - 1


def audit_scope(caller: Caller) -> set[str] | None:
    """Enforce read access; return None for all events, or the set of
    pseudonyms (all key versions of the caller) the query is restricted to."""
    if caller.check(Action.AUDIT_READ_ALL, AUDIT):
        caller.enforce(Action.AUDIT_READ_ALL, AUDIT)
        return None
    caller.enforce(Action.AUDIT_READ_OWN, AUDIT)
    return caller.container.audit.pseudonyms_for(caller.user.id)


def _ctx(caller: Caller) -> AuditContext:
    return AuditContext(actor_id=caller.user.id, actor_role=caller.subject.role.value,
                        request_id=caller.context.request_id, source_ip=caller.context.source_ip)


@router.get("/events")
def search(caller: Caller = Depends(get_caller),
           actor: str | None = Query(default=None, max_length=64),
           event_type: str | None = Query(default=None, max_length=64),
           action: str | None = Query(default=None, max_length=64),
           resource_id: str | None = Query(default=None, max_length=64),
           resource_type: str | None = Query(default=None, max_length=32),
           outcome: str | None = Query(default=None, pattern="^(success|failure|denied|error)$"),
           severity: str | None = Query(default=None, pattern="^(info|warning|critical)$"),
           min_severity: str | None = Query(default=None, pattern="^(info|warning|critical)$"),
           ts_from: datetime | None = Query(default=None, alias="from"),
           ts_to: datetime | None = Query(default=None, alias="to"),
           request_id: str | None = Query(default=None, max_length=64),
           limit: int = Query(default=50, ge=1, le=1000), offset: int = Query(default=0, ge=0, le=MAX_SEQ),
           order: str = Query(default="desc", pattern="^(asc|desc)$")) -> dict:
    own = audit_scope(caller)
    try:
        events, total = caller.container.audit.search(
            actor=own if own is not None else actor, event_type=event_type, action=action,
            resource_id=resource_id, resource_type=resource_type, outcome=outcome, severity=severity,
            min_severity=min_severity, ts_from=ts_from, ts_to=ts_to, request_id=request_id,
            limit=limit, offset=offset, order=order)
    except ValueError:
        raise ValidationFailed("invalid search", reasons=("invalid-search",)) from None
    return {"events": events, "total": total, "limit": limit, "offset": offset,
            "scope": "own" if own is not None else "all"}


@router.get("/events/{seq}")
def get_event(seq: int = Path(ge=1, le=MAX_SEQ), caller: Caller = Depends(get_caller)) -> dict:
    own = audit_scope(caller)
    ev = caller.container.audit.get_event(seq)
    if ev is None or (own is not None and ev.get("actor") not in own):
        raise NotFound("event not found")
    return ev


@router.get("/stats")
def stats(caller: Caller = Depends(get_caller), since: datetime | None = Query(default=None)) -> dict:
    caller.enforce(Action.AUDIT_READ_ALL, AUDIT)
    return caller.container.audit.stats(since)


@router.post("/verify")
def verify(body: VerifyIn | None = None, caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.AUDIT_VERIFY, AUDIT)
    body = body or VerifyIn()
    report = caller.container.audit.verify_chain(from_seq=body.from_seq, to_seq=body.to_seq,
                                                 check_anchors=body.check_anchors, audit_context=_ctx(caller))
    return report.to_dict()


@router.post("/checkpoints", status_code=201)
def checkpoint(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.AUDIT_CHECKPOINT, AUDIT)
    return caller.container.audit.create_checkpoint("manual", audit_context=_ctx(caller)).to_dict()


@router.get("/checkpoints")
def checkpoints(caller: Caller = Depends(get_caller), limit: int = Query(default=100, ge=1, le=1000)) -> dict:
    caller.enforce(Action.AUDIT_VERIFY, AUDIT)
    return {"checkpoints": [cp.to_dict() for cp in caller.container.audit.list_checkpoints(limit)]}


@router.post("/retention")
def retention(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.AUDIT_RETENTION, AUDIT)
    return caller.container.audit.apply_retention(audit_context=_ctx(caller)).to_dict()


@router.get("/export")
def export(request: Request, caller: Caller = Depends(get_caller),
           from_seq: int | None = Query(default=None, ge=1, le=MAX_SEQ),
           to_seq: int | None = Query(default=None, ge=1, le=MAX_SEQ)) -> StreamingResponse:
    own = audit_scope(caller)
    c = caller.container
    rate_limit(request, "audit-export", caller.user.id,
               int(getattr(c.settings, "rate_limit_audit_export_per_minute", 6)))
    lines = c.audit.export_ndjson(from_seq, to_seq, actors=own)

    def body() -> Iterator[bytes]:
        for line in lines:
            yield line.encode("ascii")

    return StreamingResponse(body(), media_type="application/x-ndjson",
                             headers={"Content-Disposition": 'attachment; filename="audit-export.ndjson"'})
