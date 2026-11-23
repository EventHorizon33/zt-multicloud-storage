"""Finding F5: the ambient request context fills request id, network and actor
of events whose emitter did not pass them (storage-layer events)."""
from __future__ import annotations

import contextvars
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.audit.context import begin_request, bind_actor, end_request, suspended
from app.ratelimit import RateLimitAuditor


def _record(svc, **kw):
    return svc.record(event_type="storage.replica.corrupt", action="storage:read", outcome="failure",
                      severity="critical", **kw)


def test_context_fills_missing_fields_and_explicit_values_win(service):
    token = begin_request("req-ctx-000001", "198.51.100.7")
    try:
        bind_actor("user-1", "user")
        _record(service)
        _record(service, actor_id="user-2", request_id="req-explicit-1", source_ip="203.0.113.5")
    finally:
        end_request(token)
    _record(service)                                    # outside any request
    first, explicit, outside = service.search(order="asc")[0]
    assert first["request_id"] == "req-ctx-000001" and first["source_net"] == "198.51.100.0/24"
    assert first["actor"] == service.pseudonym_for("user-1") and first["actor_role"] == "user"
    assert explicit["actor"] == service.pseudonym_for("user-2") and explicit["actor_role"] is None
    assert (explicit["request_id"], explicit["source_net"]) == ("req-explicit-1", "203.0.113.0/24")
    assert outside["request_id"] is None and outside["actor"] is None


def test_actor_bound_in_one_worker_thread_is_seen_in_another(service):
    """FastAPI runs get_caller and the endpoint in different worker threads,
    each with a copy of the request context: the holder is shared."""
    token = begin_request("req-ctx-000002", "198.51.100.7")
    try:
        t = threading.Thread(target=contextvars.copy_context().run, args=(bind_actor, "user-9", "auditor"))
        t.start()
        t.join()
        with ThreadPoolExecutor(2) as pool:
            pool.submit(contextvars.copy_context().run, _record, service).result()
    finally:
        end_request(token)
    (e,), _ = service.search()
    assert e["actor"] == service.pseudonym_for("user-9") and e["request_id"] == "req-ctx-000002"


def test_suspended_and_rate_limit_summary_are_not_attributed(service):
    clock_now = [datetime(2026, 11, 13, tzinfo=timezone.utc)]
    rl = RateLimitAuditor(audit=service, clock=lambda: clock_now[0], window_seconds=60)
    rl.rejected("login", "203.0.113.9", source_ip="203.0.113.9", request_id="req-flood-0001")
    rl.rejected("login", "203.0.113.9")
    token = begin_request("req-unrelated-1", "192.0.2.1")
    try:
        bind_actor("user-x", "user")
        from datetime import timedelta
        clock_now[0] += timedelta(seconds=61)
        rl.flush()
        with suspended():
            _record(service)
    finally:
        end_request(token)
    events, _ = service.search(order="asc")
    summary = [e for e in events if e["details"].get("kind") == "summary"][0]
    assert summary["request_id"] is None and summary["actor"] is None
    assert summary["source_net"] == "203.0.113.0/24" and summary["details"]["count"] == 1
    assert events[-1]["request_id"] is None and events[-1]["actor"] is None
