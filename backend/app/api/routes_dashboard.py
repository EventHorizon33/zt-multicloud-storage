"""/api/dashboard, /metrics, /api/health.

Every dashboard number is computed from live data: file/chunk/byte totals
and per-provider distribution from the metadata DB (committed files only),
operation outcomes from the audit DB, provider availability from the health
monitor. Users see their own scope; auditors/admins the global scope."""
from __future__ import annotations

import hmac
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

from app.api.deps import Caller, get_caller, get_container, get_db
from app.api.routes_security import security_events
from app.api.routes_storage import global_scope, provider_rows
from app.contracts import Action, Outcome, Resource, Role
from app.errors import AccessDenied

router = APIRouter(tags=["dashboard"])


def operations(caller: Caller, scope_all: bool) -> dict:
    audit = caller.container.audit
    if scope_all:
        st = audit.stats()
        return {"by_outcome": st["by_outcome"], "total": st["total"], "by_event_prefix": st["by_event_prefix"]}
    me = audit.pseudonyms_for(caller.user.id)
    by_outcome = {}
    for o in Outcome:
        _, n = audit.search(actor=me, outcome=o.value, limit=1)
        by_outcome[o.value] = n
    return {"by_outcome": by_outcome, "total": sum(by_outcome.values()), "by_event_prefix": None}


@router.get("/api/dashboard")
def dashboard(caller: Caller = Depends(get_caller)) -> dict:
    caller.enforce(Action.DASHBOARD_READ, Resource(type="system"))
    scope_all = global_scope(caller)
    c = caller.container
    stats = c.files.stats(caller.db, None if scope_all else caller.user.id)
    events, _ = security_events(caller, 10)
    providers = provider_rows(caller)
    return {
        "scope": "all" if scope_all else "own",
        "generated_at": c.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": {"count": stats["files"], "bytes": stats["bytes"], "chunks": stats["chunks"],
                  "by_status": stats["files_by_status"]},
        "distribution": stats["distribution"],
        "operations": operations(caller, scope_all),
        "recent_security_events": events,
        "providers": providers,
        "providers_available": sum(1 for p in providers if p.get("healthy")),
        "providers_total": len(providers),
    }


@router.get("/api/health")
def health(request: Request) -> dict:
    c = get_container(request)
    db_ok = True
    try:
        with c.db() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "database": db_ok}


def _metric_lines(c) -> list[str]:
    lines = []
    with c.db() as db:
        st = c.files.stats(db)
    lines += ["# HELP zt_files_committed Committed files.", "# TYPE zt_files_committed gauge",
              f"zt_files_committed {st['files']}",
              "# HELP zt_bytes_committed Plaintext bytes in committed files.", "# TYPE zt_bytes_committed gauge",
              f"zt_bytes_committed {st['bytes']}",
              "# HELP zt_files_by_status Files per state-machine status.", "# TYPE zt_files_by_status gauge"]
    lines += [f'zt_files_by_status{{status="{k}"}} {v}' for k, v in sorted(st["files_by_status"].items())]
    lines += ["# HELP zt_replicas_stored Stored chunk replicas per provider.", "# TYPE zt_replicas_stored gauge"]
    lines += [f'zt_replicas_stored{{provider="{p}"}} {d["replicas"]}' for p, d in sorted(st["distribution"].items())]
    lines += ["# HELP zt_provider_healthy 1 if the provider is healthy.", "# TYPE zt_provider_healthy gauge"]
    lines += [f'zt_provider_healthy{{provider="{r["provider"]}"}} {1 if r.get("healthy") else 0}'
              for r in c.orchestrator.health_snapshot()]
    a = c.audit.stats()
    lines += ["# HELP zt_audit_events Audit events retained, by outcome.", "# TYPE zt_audit_events gauge"]
    lines += [f'zt_audit_events{{outcome="{k}"}} {v}' for k, v in sorted(a["by_outcome"].items())]
    return lines


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request, db=Depends(get_db)) -> PlainTextResponse:
    """Prometheus text format. Finding L5: no peer address is trusted (behind
    a same-host proxy every client is 127.0.0.1). The caller must present
    either the scrape token from ``ZT_METRICS_TOKEN`` as a bearer token
    (constant-time comparison) or the access token of an administrator
    (``storage:read`` through the PEP)."""
    c = get_container(request)
    expected = getattr(c.settings, "metrics_token", None)
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    scrape_ok = bool(expected) and scheme.lower() == "bearer" and hmac.compare_digest(
        presented.strip().encode("utf-8"), str(expected).encode("utf-8"))
    if not scrape_ok:
        from app.api.deps import get_caller as _gc
        caller = _gc(request, db)
        if caller.subject.role is not Role.ADMIN:
            raise AccessDenied("admin only", reasons=("admin-required",))
        caller.enforce(Action.STORAGE_READ, Resource(type="storage"))
    body = c.orchestrator.metrics.render_prometheus().rstrip("\n").split("\n")
    body += _metric_lines(c)
    body += ["# HELP zt_http_responses_total HTTP responses by status.", "# TYPE zt_http_responses_total counter"]
    body += [f'zt_http_responses_total{{status="{k}"}} {v}'
             for k, v in sorted(request.app.state.counters.snapshot().items())]
    return PlainTextResponse("\n".join(line for line in body if line) + "\n",
                             media_type="text/plain; version=0.0.4")
