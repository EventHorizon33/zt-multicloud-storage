"""Request-scoped dependencies: DB session, authentication, request context,
rate limiting, PEP helper.

Every sensitive route depends on ``get_caller``, which calls
``AuthService.authenticate_request`` (verifies the token AND re-reads the
session and user from the DB on every call, ADR-0008) and builds the
``RequestContext`` (request id, client IP, one clock)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from fastapi import Depends, Request
from sqlalchemy.orm import Session as DbSession

from app.audit.context import bind_actor
from app.auth import AuthenticatedPrincipal
from app.container import Container
from app.contracts import Action, Decision, RequestContext, Resource, Subject
from app.errors import AuthenticationError, RateLimited
from app.models import Session, User
from app.ratelimit import client_network_key

#: Rate-limit scope for requests whose bearer token fails (M2).
INVALID_TOKEN_SCOPE = "invalid-token"


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_db(request: Request) -> Iterator[DbSession]:
    db = get_container(request).db()
    try:
        yield db
    finally:
        db.close()


def request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or "unknown"


def source_ip(request: Request) -> str | None:
    return getattr(request.state, "client_ip", None)


def make_context(request: Request) -> RequestContext:
    c = get_container(request)
    return RequestContext(request_id=request_id(request), source_ip=source_ip(request), now=c.clock())


@dataclass
class Caller:
    container: Container
    db: DbSession
    principal: AuthenticatedPrincipal
    context: RequestContext

    @property
    def subject(self) -> Subject:
        return self.principal.subject

    @property
    def user(self) -> User:
        return self.principal.user

    @property
    def session(self) -> Session:
        return self.principal.session

    def enforce(self, action: Action, resource: Resource | None = None) -> Decision:
        return self.container.pep.enforce(self.db, self.subject, action,
                                          resource or Resource(type="system"), self.context)

    def check(self, action: Action, resource: Resource | None = None) -> bool:
        return self.container.pep.check(self.db, self.subject, action,
                                        resource or Resource(type="system"), self.context).allow


def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip() or len(token) > 4096:
        raise AuthenticationError("authentication required", reasons=("token-missing",))
    return token.strip()


def _invalid_token_gate(request: Request, c: Container) -> tuple[str, int]:
    """Finding M2: a client network (IPv4 address, IPv6 /64) that has sent
    too many INVALID bearer tokens is answered 429 before any token
    verification work is done (no signature check, no DB read, no audit
    append). Only failures spend from the bucket, so valid tokens are not
    counted; while a network is over the limit every bearer request from it
    is refused until the bucket refills (Retry-After)."""
    key = client_network_key(source_ip(request))
    limit = int(getattr(c.settings, "rate_limit_invalid_token_per_minute", 20))
    retry = c.rate_limiter.exhausted(INVALID_TOKEN_SCOPE, key, limit)
    if retry:
        auditor = getattr(c, "rate_limit_auditor", None)
        if auditor is not None:
            auditor.rejected(INVALID_TOKEN_SCOPE, key, user_keyed=False, request_id=request_id(request),
                             source_ip=source_ip(request))
        exc = RateLimited("too many invalid tokens", reasons=("rate-limited",))
        exc.retry_after_seconds = retry
        raise exc
    return key, limit


def get_caller(request: Request, db: DbSession = Depends(get_db)) -> Caller:
    c = get_container(request)
    token = bearer_token(request)
    key, limit = _invalid_token_gate(request, c)
    try:
        principal = c.auth.authenticate_request(db, token, source_ip(request), request_id=request_id(request))
    except AuthenticationError as exc:
        if "token-expired" not in (exc.reasons or ()):   # routine expiry is not counted
            c.rate_limiter.spend(INVALID_TOKEN_SCOPE, key, limit)
        raise
    bind_actor(principal.user.id, principal.user.role)       # F5: actor for every later audit event
    return Caller(container=c, db=db, principal=principal, context=make_context(request))


#: Rate-limit scopes keyed by user id (the others are keyed by client IP).
USER_KEYED_SCOPES = frozenset({"mfa", "upload", "download", "verify", "audit-export"})


def rate_limit(request: Request, scope: str, key: object, per_minute: int) -> None:
    """Spend one token or raise ``RateLimited`` (429). Rejections are audited
    (F6) through ``RateLimitAuditor``: the first per (scope, key) per window
    as ``security.rate-limited``, later ones aggregated into a summary."""
    c = get_container(request)
    try:
        c.rate_limiter.check(scope, key, int(per_minute))
    except RateLimited:
        auditor = getattr(c, "rate_limit_auditor", None)
        if auditor is not None:
            auditor.rejected(scope, key, user_keyed=scope in USER_KEYED_SCOPES,
                             request_id=request_id(request), source_ip=source_ip(request))
        raise
