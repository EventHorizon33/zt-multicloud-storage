"""/api/security: security event feed, policy description and settings,
anomaly (download) blocks."""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, Query, Response

from app.api.deps import Caller, get_caller
from app.api.schemas import PolicyUpdateIn
from app.contracts import Action, Outcome, Resource, Role, Severity
from app.errors import NotFound
from app.models import User
from app.policy import describe_policies

router = APIRouter(prefix="/api/security", tags=["security"])

SEC = Resource(type="system")
POLICY = Resource(type="policy")


def security_events(caller: Caller, limit: int, severity: str | None = None) -> tuple[list[dict], str]:
    """Newest security events (all for auditor/admin, the caller's own --
    every pseudonym version -- otherwise). With ``severity`` only events of
    exactly that severity."""
    audit = caller.container.audit
    if caller.subject.role in (Role.ADMIN, Role.AUDITOR):
        return audit.recent_security_events(limit, severity=severity), "all"
    mine = audit.pseudonyms_for(caller.user.id)
    if severity is not None:
        return audit.recent_security_events(limit, severity=severity, actors=mine), "own"
    events, _ = audit.search(actor=mine, min_severity="warning", limit=limit)
    return events, "own"


@router.get("/events")
def events(caller: Caller = Depends(get_caller), limit: int = Query(default=50, ge=1, le=500),
           critical_limit: int = Query(default=50, ge=1, le=500)) -> dict:
    """``events``: newest warning-or-worse / denied / failed events.
    ``critical``: the newest CRITICAL events, selected separately (finding
    M2), so a flood of lower-severity events cannot push a critical alert out
    of the security centre."""
    caller.enforce(Action.SECURITY_READ, SEC)
    evs, scope = security_events(caller, limit)
    critical, _ = security_events(caller, critical_limit, severity=Severity.CRITICAL.value)
    return {"events": evs, "critical": critical, "scope": scope}


@router.get("/policies")
def policies(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.POLICY_READ, POLICY)
    cfg, version, ignored = caller.container.policy_store.load_report(caller.db)
    return {"rules": describe_policies(), "config": cfg.to_dict(), "version": version,
            "ignored_keys": list(ignored)}


@router.get("/policy-settings")
def policy_settings(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.POLICY_READ, POLICY)
    store = caller.container.policy_store
    cfg, version, ignored = store.load_report(caller.db)
    return {"config": cfg.to_dict(), "defaults": store.defaults.to_dict(), "version": version,
            "ignored_keys": list(ignored)}


@router.put("/policy-settings")
def update_policy(body: PolicyUpdateIn, caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.POLICY_WRITE, POLICY)
    store = caller.container.policy_store
    store.update(caller.db, body.changes, actor_id=caller.user.id, actor_role=caller.subject.role.value,
                 request_id=caller.context.request_id, source_ip=caller.context.source_ip)
    cfg, version, ignored = store.load_report(caller.db)
    return {"config": cfg.to_dict(), "defaults": store.defaults.to_dict(), "version": version,
            "ignored_keys": list(ignored)}


def _iso(dt):
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return dt.isoformat().replace("+00:00", "Z")


@router.get("/anomaly-blocks")
def anomaly_blocks(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.SECURITY_READ, SEC)
    c = caller.container
    role = caller.subject.role
    blocks = c.download_detector.active_blocks(caller.db, None if role in (Role.ADMIN, Role.AUDITOR)
                                               else caller.user.id)
    out = []
    for b in blocks:
        item = {"blocked_until": _iso(b.blocked_until), "reason": b.reason,
                "actor": c.audit.pseudonym_for(b.user_id)}
        if role is Role.ADMIN or b.user_id == caller.user.id:
            u = caller.db.get(User, b.user_id)
            item.update({"user_id": b.user_id, "username": u.username if u else None})
        out.append(item)
    return {"blocks": out, "scope": "all" if role in (Role.ADMIN, Role.AUDITOR) else "own"}


@router.delete("/anomaly-blocks/{user_id}", status_code=204)
def lift_block(user_id: str, caller: Caller = Depends(get_caller)) -> Response:
    caller.enforce(Action.USER_MANAGE, Resource(type="user", id=user_id[:32]))
    c = caller.container
    if not c.download_detector.lift_block(caller.db, user_id[:32]):
        raise NotFound("no block for this user")
    c.audit.record(event_type="security.block.lift", action=Action.USER_MANAGE.value, outcome=Outcome.SUCCESS,
                   actor_id=caller.user.id, actor_role=caller.subject.role.value, resource_type="user",
                   resource_id=user_id[:32], severity=Severity.WARNING,
                   details={"target_user": c.audit.pseudonym_for(user_id[:32])},
                   request_id=caller.context.request_id, source_ip=caller.context.source_ip)
    return Response(status_code=204)
