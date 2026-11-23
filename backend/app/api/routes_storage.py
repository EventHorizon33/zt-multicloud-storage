"""/api/storage: provider health, distribution totals, storage metrics and
(only when ``enable_fault_injection``) the demo fault-injection endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.deps import Caller, get_caller
from app.api.schemas import FaultIn
from app.contracts import Action, Resource, Role
from app.errors import NotFound, ValidationFailed

router = APIRouter(prefix="/api/storage", tags=["storage"])


def global_scope(caller: Caller) -> bool:
    return caller.subject.role in (Role.ADMIN, Role.AUDITOR)


def provider_rows(caller: Caller) -> list[dict]:
    rows = caller.container.orchestrator.health_snapshot()
    keep = ("provider", "kind", "healthy", "state", "latency_ms", "consecutive_failures", "last_checked",
            "last_error", "total_successes", "total_failures", "injected", "fault_mode")
    return [{k: r.get(k) for k in keep} for r in rows]


@router.get("/providers")
def providers(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.STORAGE_READ, Resource(type="storage"))
    o = caller.container.orchestrator
    return {"providers": provider_rows(caller), "replication_factor": o.replication_factor,
            "min_write_replicas": o.min_write_replicas,
            "fault_injection_enabled": bool(caller.container.settings.enable_fault_injection)}


@router.get("/distribution")
def distribution(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.STORAGE_READ, Resource(type="storage"))
    scope_all = global_scope(caller)
    stats = caller.container.files.stats(caller.db, None if scope_all else caller.user.id)
    return {"scope": "all" if scope_all else "own", **stats}


@router.get("/metrics")
def metrics(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.STORAGE_READ, Resource(type="storage"))
    return caller.container.orchestrator.metrics.snapshot()


#: Registered only when ``settings.enable_fault_injection`` is true.
fault_router = APIRouter(prefix="/api/storage/faults", tags=["storage"])


@fault_router.get("")
def fault_status(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.STORAGE_ADMIN, Resource(type="storage"))
    return {"faults": caller.container.orchestrator.fault_status()}


def _apply_fault(provider: str, body: FaultIn, caller: Caller) -> dict:
    caller.enforce(Action.STORAGE_ADMIN, Resource(type="storage", id=provider[:32]))
    o = caller.container.orchestrator
    if provider not in o.provider_names:
        raise NotFound("unknown provider")
    params = {k: v for k, v in (("delay", body.delay), ("n", body.n)) if v is not None}
    try:
        status = o.set_fault(provider, body.mode, **params)
    except (ValueError, TypeError):
        raise ValidationFailed("invalid fault parameters", reasons=("invalid-fault",)) from None
    caller.container.audit.record(
        event_type="storage.fault.set", action=Action.STORAGE_ADMIN.value, outcome="success",
        actor_id=caller.user.id, actor_role=caller.subject.role.value, resource_type="storage",
        resource_id=provider, severity="warning",
        details={"provider": provider, "mode": body.mode, "injected": body.mode != "none"},
        request_id=caller.context.request_id, source_ip=caller.context.source_ip)
    return status


@fault_router.put("/{provider}")
def set_fault(provider: str, body: FaultIn, caller: Caller = Depends(get_caller)) -> dict:
    return _apply_fault(provider, body, caller)


@fault_router.delete("/{provider}")
def clear_fault(provider: str, caller: Caller = Depends(get_caller)) -> dict:
    return _apply_fault(provider, FaultIn(mode="none"), caller)
