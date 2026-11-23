"""Ambient request context for audit records (finding F5).

The API middleware opens a context for every HTTP request (request id and
client IP); ``get_caller`` binds the authenticated actor to it. While the
request runs, ``AuditService.record`` fills ``request_id``, ``source_ip`` and
the actor from it for every event whose emitter did not pass them, so events
recorded deep in the storage layer (``storage.replica.corrupt``,
``chunk.retrieve``, ...) can be joined to the request and user that caused
them without changing any subsystem signature.

Mechanics: a ``ContextVar`` holds a small MUTABLE holder. FastAPI runs sync
dependencies and sync endpoints in worker threads, each with a *copy* of the
request's context; the copies all reference the same holder object, so the
actor bound inside ``get_caller`` (one worker thread) is visible to the
endpoint (another worker thread). Code that hands work to its own thread
pools must propagate the context explicitly with ``contextvars.copy_context()``
(``StorageOrchestrator`` and ``DeadlineRunner`` do).

Explicit values always win: the context only fills fields that are ``None``.
Background threads (health monitor, maintenance) run outside any request
context and are unaffected. ``suspended()`` turns the filling off for events
that are deliberately not attributed to the current request (e.g. the
rate-limit summary of an earlier window).
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator

from app.audit.records import AuditContext


@dataclass
class _RequestAuditState:
    request_id: str | None = None
    source_ip: str | None = None
    actor_id: str | None = None
    actor_role: str | None = None
    client_request_id: str | None = None     # client-supplied X-Request-ID (validated; L8)


_CURRENT: ContextVar[_RequestAuditState | None] = ContextVar("zt_audit_request_context", default=None)


def begin_request(request_id: str | None, source_ip: str | None, client_request_id: str | None = None) -> Token:
    """Open the context for one request; pass the token to ``end_request``.
    ``request_id`` is always server-generated; ``client_request_id`` is the
    validated value the client sent in ``X-Request-ID`` (finding L8), kept
    apart so a client cannot make its events share another request's id."""
    return _CURRENT.set(_RequestAuditState(request_id=request_id, source_ip=source_ip,
                                           client_request_id=client_request_id))


def end_request(token: Token) -> None:
    _CURRENT.reset(token)


def bind_actor(actor_id: str | None, actor_role: str | None) -> None:
    """Record the authenticated caller of the current request (no-op outside a request)."""
    state = _CURRENT.get()
    if state is not None:
        state.actor_id = actor_id
        state.actor_role = actor_role


def current_audit_context() -> AuditContext | None:
    state = _CURRENT.get()
    if state is None:
        return None
    return AuditContext(actor_id=state.actor_id, actor_role=state.actor_role,
                        request_id=state.request_id, source_ip=state.source_ip)


def current_client_request_id() -> str | None:
    state = _CURRENT.get()
    return state.client_request_id if state is not None else None


@contextmanager
def suspended() -> Iterator[None]:
    """Record events inside this block without the ambient request context."""
    token = _CURRENT.set(None)
    try:
        yield
    finally:
        _CURRENT.reset(token)
