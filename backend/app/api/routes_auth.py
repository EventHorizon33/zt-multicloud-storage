"""/api/auth: registration, login, refresh (HttpOnly cookie), logout, me,
sessions, MFA, password change.

These are authentication endpoints, not PDP-gated actions: they only
require a valid (possibly restricted) session, so a user forced to enrol MFA
by ``require_mfa_for_login`` can still reach enrol/activate (integration
item 3). What they enforce themselves (in ``AuthService``):
  * the network allow list on login, refresh, password change and every MFA
    endpoint (F2);
  * MFA enrolment gating: trust-on-first-use window, bootstrap admin, or an
    admin-issued enrolment code; replacing a factor needs its current code;
    activation never makes the current session MFA-verified (F1, ADR-0010);
  * registration answers the same 202 whether or not the name exists (F3);
  * the allow list also on ``/me`` and session list/revoke (L1);
  * restricted (password-only / factor-less) sessions may only call me,
    logout, MFA enrol/activate (gated) -- session list/revoke and password
    change answer 403 ``mfa-required`` (M5);
  * password change needs a FRESH second factor (403 ``mfa-required`` /
    ``mfa-stale`` + ``step-up-mfa``) and never revokes a session verified more
    recently than the caller's (H1).
Rate limits: register, login, refresh (per client network: IPv4 address,
IPv6 /64, L4), MFA and password change (per user); rejections are audited
(F6, ``deps.rate_limit``)."""
from __future__ import annotations

from datetime import timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session as DbSession

from app.api.deps import Caller, get_caller, get_container, get_db, rate_limit, request_id, source_ip
from app.api.schemas import (CodeIn, LoginIn, MeOut, MfaEnrollIn, MfaEnrollOut, PasswordChangeIn, RegisterIn,
                             RegisterOut, SessionOut, TokenOut, UserOut)
from app.errors import AccessDenied, AuthenticationError, Conflict, NotFound
from app.ratelimit import client_network_key

router = APIRouter(prefix="/api/auth", tags=["auth"])

REFRESH_COOKIE = "zt_refresh"
COOKIE_PATH = "/api/auth"


def _utc(dt):
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def user_out(u) -> UserOut:
    return UserOut(id=u.id, username=u.username, role=u.role, clearance=u.clearance,
                   is_active=bool(u.is_active), mfa_enabled=bool(u.mfa_enabled), created_at=_utc(u.created_at))


def session_out(s, current_id: str | None) -> SessionOut:
    return SessionOut(id=s.id, created_at=_utc(s.created_at), last_seen_at=_utc(s.last_seen_at),
                      expires_at=_utc(s.expires_at), mfa_verified=s.mfa_verified_at is not None,
                      current=s.id == current_id)


def _set_refresh_cookie(request: Request, response: Response, token: str) -> None:
    s = get_container(request).settings
    response.set_cookie(REFRESH_COOKIE, token, max_age=int(s.refresh_token_ttl_seconds), path=COOKIE_PATH,
                        httponly=True, samesite="strict", secure=bool(s.cookie_secure))


def _clear_refresh_cookie(request: Request, response: Response) -> None:
    s = get_container(request).settings
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH, httponly=True, samesite="strict",
                           secure=bool(s.cookie_secure))


def _token_out(result) -> TokenOut:
    return TokenOut(access_token=result.access_token, expires_in=int(result.expires_in),
                    session_id=result.session.id, mfa_verified=bool(result.mfa_verified),
                    user=user_out(result.user))


def _ip_key(request: Request) -> str:
    """IPv4 address or IPv6 /64 (finding L4)."""
    return client_network_key(source_ip(request))


@router.post("/register", status_code=202, response_model=RegisterOut)
def register(body: RegisterIn, request: Request, db: DbSession = Depends(get_db)) -> RegisterOut:
    """Uniform answer (F3): 202 ``{"status": "accepted"}`` both when the
    account was created and when the name already exists (no duplicate is
    created; the service audits ``auth.register`` failure ``username-taken``
    and spends the same Argon2 work). Invalid input is still 422 (it does not
    depend on whether the name exists); 403 ``registration-disabled`` when
    ``allow_self_registration`` is false."""
    c = get_container(request)
    rate_limit(request, "register", _ip_key(request), c.settings.rate_limit_register_per_minute)
    try:
        c.auth.register(db, body.username, body.password, source_ip=source_ip(request),
                        request_id=request_id(request))
    except Conflict as exc:
        if "username-taken" not in (exc.reasons or ()):
            raise
    return RegisterOut()


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, response: Response, db: DbSession = Depends(get_db)) -> TokenOut:
    c = get_container(request)
    rate_limit(request, "login", _ip_key(request), c.settings.rate_limit_login_per_minute)
    try:
        result = c.auth.login(db, body.username, body.password, body.totp_code, source_ip(request),
                              request_id=request_id(request))
    except AuthenticationError as exc:
        if "mfa-required" not in (exc.reasons or ()):
            # credential-stuffing signal: many accounts failing from one network
            c.auth_failure_detector.record_failure(source_ip(request), body.username,
                                                   request_id=request_id(request))
        raise
    _set_refresh_cookie(request, response, result.refresh_token)
    return _token_out(result)


@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, response: Response, db: DbSession = Depends(get_db)) -> TokenOut:
    c = get_container(request)
    rate_limit(request, "refresh", _ip_key(request), c.settings.rate_limit_login_per_minute)
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise AuthenticationError("no refresh token", reasons=("refresh-missing",))
    try:
        result = c.auth.refresh(db, token, source_ip(request), request_id=request_id(request))
    except AuthenticationError:
        _clear_refresh_cookie(request, response)
        raise
    _set_refresh_cookie(request, response, result.refresh_token)
    return _token_out(result)


@router.post("/logout", status_code=204)
def logout(request: Request, caller: Caller = Depends(get_caller)) -> Response:
    caller.container.auth.logout(caller.db, caller.session.id, source_ip=caller.context.source_ip,
                                 request_id=caller.context.request_id)
    resp = Response(status_code=204)
    _clear_refresh_cookie(request, resp)
    return resp


def _network(caller: Caller, event: str) -> None:
    """L1: the allow list applies to every account endpoint, not only to the
    PDP-gated routes."""
    caller.container.auth.require_network(caller.user, event, session_id=caller.session.id,
                                          source_ip=caller.context.source_ip,
                                          request_id=caller.context.request_id)


def _not_restricted(caller: Caller, event: str) -> None:
    """M5: a restricted session (no factor, or not MFA-verified while
    ``require_mfa_for_login`` applies) may not manage sessions."""
    cfg = caller.container.policy_store.load(caller.db)
    caller.container.auth.require_mfa_session(caller.user, caller.session, event,
                                              require_mfa_for_login=bool(cfg.require_mfa_for_login),
                                              source_ip=caller.context.source_ip,
                                              request_id=caller.context.request_id)


def _me(caller: Caller) -> MeOut:
    c = caller.container
    cfg = c.policy_store.load(caller.db)
    s = caller.subject
    fresh = bool(s.mfa_verified and s.mfa_age_seconds is not None
                 and s.mfa_age_seconds <= cfg.mfa_step_up_max_age_seconds)
    return MeOut(user=user_out(caller.user), session=session_out(caller.session, caller.session.id),
                 audit_pseudonym=c.audit.pseudonym_for(caller.user.id),
                 restricted=bool(cfg.require_mfa_for_login and not s.mfa_verified), mfa_fresh=fresh)


@router.get("/me", response_model=MeOut)
def me(caller: Caller = Depends(get_caller)) -> MeOut:
    _network(caller, "auth.me")
    return _me(caller)


@router.get("/sessions", response_model=list[SessionOut])
def sessions(caller: Caller = Depends(get_caller)) -> list[SessionOut]:
    _network(caller, "auth.session_list")
    _not_restricted(caller, "auth.session_list")
    rows = caller.container.auth.list_sessions(caller.db, caller.user)
    return [session_out(s, caller.session.id) for s in rows]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke_session(session_id: str, caller: Caller = Depends(get_caller)) -> Response:
    _network(caller, "auth.session_revoke")
    _not_restricted(caller, "auth.session_revoke")
    ok = caller.container.auth.revoke_session(
        caller.db, session_id[:64], "user-revoked", owner_id=caller.user.id, actor_id=caller.user.id,
        source_ip=caller.context.source_ip, request_id=caller.context.request_id)
    if not ok:
        raise NotFound("session not found")
    return Response(status_code=204)


def _mfa_rate(request: Request, caller: Caller) -> None:
    rate_limit(request, "mfa", caller.user.id, caller.container.settings.rate_limit_login_per_minute)


def _second_factor_errors(exc: AuthenticationError) -> Exception:
    """A wrong code is a 403 (the session stays valid), not a 401."""
    reasons = tuple(exc.reasons or ())
    if "mfa-invalid" in reasons:
        return AccessDenied("invalid code", reasons=("mfa-invalid",))
    if "mfa-not-enrolled" in reasons:
        return Conflict("mfa not enrolled", reasons=("mfa-not-enrolled",))
    return exc


@router.post("/mfa/enroll", response_model=MfaEnrollOut)
def mfa_enroll(request: Request, body: MfaEnrollIn | None = None,
               caller: Caller = Depends(get_caller)) -> MfaEnrollOut:
    _mfa_rate(request, caller)
    body = body or MfaEnrollIn()
    try:
        e = caller.container.auth.enroll_mfa(caller.db, caller.user, enrollment_code=body.enrollment_code,
                                             current_code=body.current_code, session=caller.session,
                                             source_ip=caller.context.source_ip,
                                             request_id=caller.context.request_id)
    except AuthenticationError as exc:
        raise _second_factor_errors(exc) from None
    return MfaEnrollOut(secret=e.secret, otpauth_uri=e.otpauth_uri)


@router.post("/mfa/activate", response_model=MeOut)
def mfa_activate(body: CodeIn, request: Request, caller: Caller = Depends(get_caller)) -> MeOut:
    _mfa_rate(request, caller)
    try:
        caller.container.auth.activate_mfa(caller.db, caller.user, body.code, session=caller.session,
                                           source_ip=caller.context.source_ip,
                                           request_id=caller.context.request_id)
    except AuthenticationError as exc:
        raise _second_factor_errors(exc) from None
    return _refreshed_me(request, caller)


@router.post("/mfa/verify", response_model=MeOut)
def mfa_verify(body: CodeIn, request: Request, caller: Caller = Depends(get_caller)) -> MeOut:
    _mfa_rate(request, caller)
    try:
        caller.container.auth.verify_mfa_step_up(caller.db, caller.session, body.code,
                                                 source_ip=caller.context.source_ip,
                                                 request_id=caller.context.request_id)
    except AuthenticationError as exc:
        raise _second_factor_errors(exc) from None
    return _refreshed_me(request, caller)


@router.post("/mfa/disable", response_model=MeOut)
def mfa_disable(body: CodeIn, request: Request, caller: Caller = Depends(get_caller)) -> MeOut:
    _mfa_rate(request, caller)
    try:
        caller.container.auth.disable_mfa(caller.db, caller.user, body.code, session=caller.session,
                                          source_ip=caller.context.source_ip,
                                          request_id=caller.context.request_id)
    except AuthenticationError as exc:
        raise _second_factor_errors(exc) from None
    return _refreshed_me(request, caller)


def _refreshed_me(request: Request, caller: Caller) -> MeOut:
    c = caller.container
    caller.db.expire_all()
    p = c.auth.authenticate_request(caller.db, request.headers["authorization"].split(" ", 1)[1].strip(),
                                    caller.context.source_ip, request_id=caller.context.request_id)
    caller.principal = p
    return _me(caller)


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, caller: Caller = Depends(get_caller)) -> dict:
    _mfa_rate(request, caller)
    cfg = caller.container.policy_store.load(caller.db)
    try:
        n = caller.container.auth.change_password(
            caller.db, caller.user, body.current_password, body.new_password,
            keep_session_id=caller.session.id, session=caller.session,
            mfa_max_age_seconds=int(cfg.mfa_step_up_max_age_seconds),
            require_mfa_for_login=bool(cfg.require_mfa_for_login),
            source_ip=caller.context.source_ip, request_id=caller.context.request_id)
    except AuthenticationError:
        # wrong current password / locked: the session itself is still valid
        raise AccessDenied("password change refused", reasons=("current-password-invalid",)) from None
    return {"sessions_revoked": int(n)}
