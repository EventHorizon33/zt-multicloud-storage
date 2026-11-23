"""Authentication service: registration, login, MFA, sessions, token refresh.

This is the direct answer to the credential-replay path of the UNC5537
campaign: a password alone yields at most a short-lived, server-revocable
session without second-factor status, and nothing in a token is trusted for
authorisation.

Security properties:
  * Login failures are indistinguishable to the client for unknown username,
    wrong password, locked account and disabled account (same exception class,
    same message, no reason codes, equal Argon2 work).
  * Consecutive failures lock the account for a fixed window; while locked even
    the correct password is refused.
  * ``authenticate_request`` re-reads the session and user rows from the
    database on every call, so revocation, disablement, role and allow-list
    changes apply to the very next request.
  * Refresh tokens are single-use (atomic compare-and-set); reuse revokes the
    session and raises a critical audit event.
  * Every outcome is audited. Audit calls never contain usernames, passwords,
    tokens, TOTP codes or seeds.

Transactions: methods commit their own changes on the passed ``Session``.
Failure state (failed-login counters, lockouts, revocations) is committed
BEFORE the exception is raised so that a caller rolling back on error cannot
undo it. For successful operations the audit event is written before commit:
if the event cannot be recorded the operation is rolled back.
"""
from __future__ import annotations

import hmac
import re
import secrets
import threading
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.orm import Session as DbSession

from app.auth.mfa import MfaEnrollment, TotpService
from app.auth.passwords import PasswordHasher, validate_password
from app.auth.tokens import AccessClaims, TokenService
from app.config import Settings
from app.contracts import (AuditSink, Classification, KeyManagementService, KeyPurpose, Outcome, Role,
                           Severity, Subject)
from app.errors import AccessDenied, AuthenticationError, Conflict, ValidationFailed
from app.models import MfaEnrollmentCode, MfaFactorState, RefreshToken, Session, User
from app.policy.pdp import ip_allowed

Clock = Callable[[], datetime]

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
_MAX_REFRESH_TOKEN_LENGTH = 256
_GENERIC_LOGIN_ERROR = "invalid credentials"
_USER_LOCK_STRIPES = 256        # per-user in-process login serialisation (L3), bounded memory
# Admin-issued MFA enrolment codes: 16 characters from a 32-symbol alphabet
# without look-alikes (80 bits), shown as XXXX-XXXX-XXXX-XXXX.
_ENROLL_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_ENROLL_CODE_LEN = 16
#: Bases on which an MFA enrolment may proceed (ADR-0010).
MFA_BASIS_TOFU = "tofu"              # never had MFA, within the self-enrolment window
MFA_BASIS_BOOTSTRAP = "bootstrap"    # the configured bootstrap admin, never had MFA
MFA_BASIS_ADMIN_CODE = "admin-code"  # single-use code issued by an administrator
MFA_BASIS_ROTATION = "rotation"      # replacing an existing factor, proven with its current code


@dataclass(frozen=True)
class LoginResult:
    """Returned by ``login`` and ``refresh``. ``refresh_token`` is the only
    copy of the opaque token; it is stored server-side only as an HMAC."""
    access_token: str
    expires_in: int
    refresh_token: str
    session: Session
    user: User
    mfa_verified: bool


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Result of ``authenticate_request``: database-fresh identity state."""
    user: User
    session: Session
    subject: Subject
    claims: AccessClaims


def _as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; everything is stored in UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class AuthService:
    def __init__(
        self,
        *,
        settings: Settings,
        kms: KeyManagementService,
        audit: AuditSink,
        clock: Clock,
        password_hasher: PasswordHasher | None = None,
        last_seen_granularity_seconds: float = 0.0,
    ) -> None:
        """``last_seen_granularity_seconds``: skip the ``last_seen_at`` write if
        the stored value is newer than this (0 = write on every request). Keep
        it far below ``session_idle_ttl_seconds``."""
        self._settings = settings
        self._kms = kms
        self._audit = audit
        self._clock = clock
        self._hasher = password_hasher or PasswordHasher()
        self._tokens = TokenService(kms, settings, clock)
        self._totp = TotpService(kms, issuer=settings.token_issuer)
        self._touch_granularity = max(0.0, float(last_seen_granularity_seconds))
        self._login_locks = tuple(threading.Lock() for _ in range(_USER_LOCK_STRIPES))
        #: Optional ``(source_ip) -> bool``: should this invalid-token failure be
        #: recorded individually? Set by the container to a
        #: ``TokenFailureAuditor.admit`` (M2); None = record every failure.
        self.token_failure_gate: Callable[[str | None], bool] | None = None

    @property
    def tokens(self) -> TokenService:
        return self._tokens

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #
    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return an aware datetime")
        return now.astimezone(timezone.utc)

    def _record(
        self,
        event: str,
        outcome: Outcome,
        *,
        user: User | None = None,
        actor_id: str | None = None,
        reason: str | None = None,
        severity: Severity = Severity.INFO,
        session_id: str | None = None,
        details: Mapping[str, Any] | None = None,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        """Single choke point for audit calls from this module. Only ids,
        reason codes and counters go in; never credentials or usernames."""
        merged: dict[str, Any] = dict(details or {})
        if reason is not None:
            merged.setdefault("reason", reason)
        self._audit.record(
            event_type=event,
            action=event.replace(".", ":", 1),
            outcome=outcome,
            actor_id=actor_id if actor_id is not None else (user.id if user is not None else None),
            actor_role=user.role if user is not None else None,
            resource_type="session" if session_id else ("user" if user is not None else None),
            resource_id=session_id if session_id else (user.id if user is not None else None),
            reason=reason,
            severity=severity,
            details=merged or None,
            request_id=request_id,
            source_ip=source_ip,
        )

    @staticmethod
    def _find_user(db: DbSession, username: object) -> User | None:
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            return None
        return db.execute(
            select(User).where(func.lower(User.username) == username.lower())
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()

    @staticmethod
    def _fresh_user(db: DbSession, user_id: str) -> User | None:
        return db.execute(
            select(User).where(User.id == user_id).execution_options(populate_existing=True)
        ).scalar_one_or_none()

    @staticmethod
    def _fresh_session(db: DbSession, session_id: str) -> Session | None:
        return db.execute(
            select(Session).where(Session.id == session_id).execution_options(populate_existing=True)
        ).scalar_one_or_none()

    def _is_locked(self, user: User, now: datetime) -> bool:
        locked_until = _as_utc(user.locked_until)
        return locked_until is not None and now < locked_until

    def _clear_expired_lock(self, user: User, now: datetime) -> None:
        if user.locked_until is not None and not self._is_locked(user, now):
            user.locked_until = None
            user.failed_login_count = 0

    def _count_failure(self, db: DbSession, user: User, now: datetime) -> bool:
        """Atomically increment the failure counter (no lost updates under
        concurrency). Returns True if this failure triggered a lockout."""
        db.flush()
        db.execute(update(User).where(User.id == user.id)
                   .values(failed_login_count=User.failed_login_count + 1))
        db.refresh(user)
        if user.failed_login_count >= int(self._settings.max_failed_logins) and not self._is_locked(user, now):
            user.locked_until = now + timedelta(seconds=int(self._settings.lockout_seconds))
            return True
        return False

    def _login_lock(self, user_id: str) -> threading.Lock:
        return self._login_locks[zlib.crc32(user_id.encode("utf-8")) % _USER_LOCK_STRIPES]

    def _reserve_attempt(self, db: DbSession, user: User, now: datetime) -> bool:
        """Finding L3: atomically reserve one password attempt BEFORE the
        (slow) verification. The conditional UPDATE increments
        ``failed_login_count`` only while it is below ``max_failed_logins`` and
        the account is not locked, so at most ``max_failed_logins`` attempts
        can be in flight or failed, however many requests arrive in parallel
        (across processes too: the database decides). A successful login
        resets the counter; a failed one keeps the reservation as its failure."""
        max_failed = int(self._settings.max_failed_logins)
        # End the read transaction first: on SQLite (WAL) upgrading a read
        # snapshot to a write after another attempt committed fails at once
        # with SQLITE_BUSY instead of waiting; a fresh write transaction waits.
        db.commit()
        result = db.execute(
            update(User)
            .where(User.id == user.id, User.failed_login_count < max_failed,
                   or_(User.locked_until.is_(None), User.locked_until <= now))
            .values(failed_login_count=User.failed_login_count + 1)
            .execution_options(synchronize_session=False))
        db.commit()                       # visible to every other attempt at once
        db.refresh(user)
        return result.rowcount == 1

    def _release_attempt(self, db: DbSession, user: User) -> None:
        """Give a reservation back (correct password, but no TOTP code was
        supplied yet: a prompt, not a failure)."""
        db.execute(update(User).where(User.id == user.id, User.failed_login_count > 0)
                   .values(failed_login_count=User.failed_login_count - 1)
                   .execution_options(synchronize_session=False))
        db.commit()
        db.refresh(user)

    def _lock_if_exhausted(self, db: DbSession, user: User, now: datetime) -> bool:
        """After a failed reserved attempt: lock the account when the counter
        reached the limit. Returns True if this call locked it."""
        db.refresh(user)
        if user.failed_login_count >= int(self._settings.max_failed_logins) and not self._is_locked(user, now):
            user.locked_until = now + timedelta(seconds=int(self._settings.lockout_seconds))
            return True
        return False

    def _audit_lockout(self, user: User, *, source_ip: str | None, request_id: str | None) -> None:
        self._record("auth.lockout", Outcome.FAILURE, user=user, reason="too-many-failures",
                     severity=Severity.WARNING,
                     details={"failed_count": int(user.failed_login_count),
                              "lockout_seconds": int(self._settings.lockout_seconds)},
                     source_ip=source_ip, request_id=request_id)

    @staticmethod
    def _revoke(session: Session, reason: str, now: datetime) -> bool:
        if session.revoked_at is not None:
            return False
        session.revoked_at = now
        session.revoke_reason = reason[:64]
        return True

    def _session_problem(self, session: Session, now: datetime) -> str | None:
        """Reason code if the session may no longer be used, else None."""
        if session.revoked_at is not None:
            return "session-revoked"
        if now >= _as_utc(session.expires_at):
            return "session-expired"
        idle = (now - _as_utc(session.last_seen_at)).total_seconds()
        if idle > int(self._settings.session_idle_ttl_seconds):
            return "session-idle-expired"
        return None

    def _ip_binding_ok(self, session: Session, source_ip: str | None) -> bool:
        if not self._settings.bind_session_to_ip:
            return True
        current = self._tokens.hash_ip(source_ip)
        if current is None or not session.ip_hash:
            return False   # fail closed: binding demanded but not provable
        return hmac.compare_digest(current, session.ip_hash)

    def _validate_session(self, db: DbSession, session: Session, user: User | None, now: datetime,
                          source_ip: str | None) -> str | None:
        """Shared liveness checks for request authentication and refresh.
        Idle/absolute expiry is made permanent by revoking the row."""
        problem = self._session_problem(session, now)
        if problem in ("session-expired", "session-idle-expired"):
            self._revoke(session, "expired" if problem == "session-expired" else "idle-timeout", now)
            db.commit()
        if problem is not None:
            return problem
        if user is None or not user.is_active:
            return "user-disabled"
        if not self._ip_binding_ok(session, source_ip):
            return "ip-mismatch"
        return None

    @staticmethod
    def network_allowed(user: User, source_ip: str | None) -> bool:
        """The user's network allow list (``users.allowed_cidrs``), applied with
        the same semantics as the PDP guard ``network-not-allowed``: an empty
        list allows everything; otherwise a missing/unparseable IP fails."""
        cidrs = user.allowed_cidrs if isinstance(user.allowed_cidrs, (list, tuple)) else ()
        if not cidrs:
            return True
        return ip_allowed(tuple(str(c) for c in cidrs), source_ip)

    def _require_network(self, user: User, event: str, *, session_id: str | None = None,
                         source_ip: str | None = None, request_id: str | None = None) -> None:
        """Account-management endpoints (password change, MFA enrol/activate/
        verify/disable) are not PDP-gated, so they apply the allow list here
        (F2). Refused with 403 ``network-not-allowed`` and audited."""
        if self.network_allowed(user, source_ip):
            return
        self._record(event, Outcome.DENIED, user=user, reason="network-not-allowed", severity=Severity.WARNING,
                     session_id=session_id, source_ip=source_ip, request_id=request_id)
        raise AccessDenied("network not allowed", reasons=("network-not-allowed",))

    def require_network(self, user: User, event: str, *, session_id: str | None = None,
                        source_ip: str | None = None, request_id: str | None = None) -> None:
        """Public form of the allow-list check for API routes that are not
        PDP-gated (``/api/auth/me``, session list/revoke; finding L1)."""
        self._require_network(user, event, session_id=session_id, source_ip=source_ip, request_id=request_id)

    def require_mfa_session(self, user: User, session: Session, event: str, *, require_mfa_for_login: bool,
                            fresh_within_seconds: int | None = None, source_ip: str | None = None,
                            request_id: str | None = None) -> None:
        """Gate for account-management actions (findings M5 and H1).

        * A *restricted* session -- the user holds no factor, or the session is
          not MFA-verified while ``require_mfa_for_login`` applies -- is refused
          with 403 ``mfa-required`` (obligation ``enroll-mfa`` without a factor,
          ``step-up-mfa`` with one).
        * With ``fresh_within_seconds`` (password change) the session must have
          verified the factor within that many seconds, whatever
          ``require_mfa_for_login`` says: 403 ``mfa-required`` / ``mfa-stale``
          with the ``step-up-mfa`` obligation, which the UI's step-up dialog
          handles. An account without a factor cannot satisfy it at all.
        Refusals are audited (``outcome=denied``, WARNING)."""
        now = self._now()
        has_factor = bool(user.mfa_enabled)
        verified_at = _as_utc(session.mfa_verified_at) if has_factor else None
        reason: str | None = None
        if not has_factor:
            reason = "mfa-required"
        elif fresh_within_seconds is not None:
            if verified_at is None:
                reason = "mfa-required"
            elif not 0 <= (now - verified_at).total_seconds() <= int(fresh_within_seconds):
                reason = "mfa-stale"
        elif verified_at is None and require_mfa_for_login:
            reason = "mfa-required"
        if reason is None:
            return
        obligations = ("step-up-mfa",) if has_factor else ("enroll-mfa",)
        self._record(event, Outcome.DENIED, user=user, reason=reason, severity=Severity.WARNING,
                     session_id=session.id, details={"obligations": list(obligations)},
                     source_ip=source_ip, request_id=request_id)
        exc = AccessDenied("this action needs a session verified with your second factor", reasons=(reason,))
        exc.obligations = obligations
        raise exc

    def build_subject(self, user: User, session: Session, now: datetime | None = None) -> Subject:
        """Policy subject from database state (never from token claims).
        Raises ``AuthenticationError`` if the stored role/clearance is not a
        known value (fail closed rather than guess a privilege level)."""
        now = now or self._now()
        try:
            role = Role(user.role)
            clearance = Classification(user.clearance)
        except ValueError:
            raise AuthenticationError("invalid session", reasons=("user-state-invalid",)) from None
        verified_at = _as_utc(session.mfa_verified_at)
        mfa_verified = bool(user.mfa_enabled) and verified_at is not None
        cidrs = user.allowed_cidrs if isinstance(user.allowed_cidrs, (list, tuple)) else ()
        return Subject(
            user_id=user.id,
            role=role,
            clearance=clearance,
            session_id=session.id,
            mfa_enrolled=bool(user.mfa_enabled),
            mfa_verified=mfa_verified,
            mfa_age_seconds=max(0.0, (now - verified_at).total_seconds()) if mfa_verified else None,
            session_age_seconds=max(0.0, (now - _as_utc(session.created_at)).total_seconds()),
            allowed_cidrs=tuple(str(c) for c in cidrs),
            is_active=bool(user.is_active),
        )

    def _issue(self, db: DbSession, user: User, session: Session, now: datetime) -> LoginResult:
        """New refresh token (bounded by the session's absolute expiry) plus a
        new access token for an existing session row."""
        refresh_token, token_hash = self._tokens.new_refresh_token()
        expires = min(now + timedelta(seconds=int(self._settings.refresh_token_ttl_seconds)),
                      _as_utc(session.expires_at))
        db.add(RefreshToken(session_id=session.id, token_hash=token_hash, issued_at=now, expires_at=expires))
        access_token, claims = self._tokens.issue_access_token(user_id=user.id, session_id=session.id)
        return LoginResult(
            access_token=access_token,
            expires_in=claims.exp - claims.iat,
            refresh_token=refresh_token,
            session=session,
            user=user,
            mfa_verified=bool(user.mfa_enabled) and session.mfa_verified_at is not None,
        )

    def _accept_totp(self, db: DbSession, user: User, code: object, now: datetime) -> str | None:
        """Verify a TOTP code and consume its time step. Returns None on
        success or a reason code. The counter update is a compare-and-set so
        two concurrent requests cannot both spend the same code."""
        check = self._totp.verify(user_id=user.id, encrypted_seed=user.mfa_secret_enc, code=code,
                                  now=now, last_counter=user.mfa_last_counter)
        if not check.ok:
            return check.reason or "mfa-invalid"
        db.flush()
        result = db.execute(
            update(User)
            .where(User.id == user.id,
                   or_(User.mfa_last_counter.is_(None), User.mfa_last_counter < check.counter))
            .values(mfa_last_counter=check.counter)
        )
        db.refresh(user)
        if result.rowcount != 1:
            return "mfa-replay"
        return None

    # ------------------------------------------------------------------ #
    # registration
    # ------------------------------------------------------------------ #
    def _create_user(self, db: DbSession, username: str, password: str, role: Role, event: str,
                     source_ip: str | None, request_id: str | None) -> User:
        def reject(exc: Exception, reason: str) -> Exception:
            self._record(event, Outcome.FAILURE, reason=reason, source_ip=source_ip, request_id=request_id)
            return exc

        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise reject(ValidationFailed("invalid username", reasons=("invalid-username",)),
                         "invalid-username")
        # Canonical form: usernames are stored lowercase so "Alice" and "alice"
        # are one account; the functional unique index on lower(username)
        # (app/models.py) makes a concurrent duplicate fail at flush.
        username = username.lower()
        try:
            validate_password(password, username=username, min_length=int(self._settings.password_min_length))
        except ValidationFailed as exc:
            raise reject(exc, "weak-password") from None
        if self._find_user(db, username) is not None:
            # Same Argon2 work as the success path, so response timing does not
            # reveal that the account exists (F3; the API answers a uniform 202).
            self._hasher.hash(password)
            raise reject(Conflict("username unavailable", reasons=("username-taken",)), "username-taken")
        now = self._now()
        user = User(username=username, password_hash=self._hasher.hash(password), role=role.value,
                    password_changed_at=now, created_at=now)
        db.add(user)
        try:
            db.flush()
        except SAIntegrityError:
            db.rollback()
            raise reject(Conflict("username unavailable", reasons=("username-taken",)),
                         "username-taken") from None
        try:
            self._record(event, Outcome.SUCCESS, user=user, source_ip=source_ip, request_id=request_id)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return user

    def register(self, db: DbSession, username: str, password: str, *, source_ip: str | None = None,
                 request_id: str | None = None) -> User:
        """Create an account. The role is ALWAYS ``user``: there is no
        parameter through which a caller could self-assign a higher role.

        Raises ``AccessDenied(registration-disabled)`` when
        ``allow_self_registration`` is false, and ``Conflict(username-taken)``
        for an existing name: the API maps that to the same 202 as a success
        (F3), and the work done (validation + one Argon2 hash) is the same."""
        if not bool(getattr(self._settings, "allow_self_registration", True)):
            self._record("auth.register", Outcome.DENIED, reason="registration-disabled",
                         severity=Severity.WARNING, source_ip=source_ip, request_id=request_id)
            raise AccessDenied("self-registration is disabled", reasons=("registration-disabled",))
        return self._create_user(db, username, password, Role.USER, "auth.register", source_ip, request_id)

    def ensure_bootstrap_admin(self, db: DbSession, username: str, password: str) -> User:
        """Create the first admin if no account with that username exists.
        An existing account is returned untouched (its password and role are
        never reset from configuration)."""
        existing = self._find_user(db, username)
        if existing is not None:
            if existing.role != Role.ADMIN.value:
                # Refuse to start: someone registered the configured bootstrap
                # name as an ordinary account (e.g. before the first start), and
                # the bootstrap-admin MFA exception (ADR-0010) is keyed on that
                # name. Fix the configuration or the account; never promote it.
                raise Conflict("the bootstrap admin username exists as a non-admin account",
                               reasons=("bootstrap-username-not-admin",))
            return existing
        return self._create_user(db, username, password, Role.ADMIN, "auth.bootstrap_admin", None, None)

    # ------------------------------------------------------------------ #
    # login / refresh / logout
    # ------------------------------------------------------------------ #
    def login(self, db: DbSession, username: str, password: str, totp_code: str | None = None,
              source_ip: str | None = None, *, request_id: str | None = None) -> LoginResult:
        """Password (+ TOTP when enrolled) login.

        Raises ``AuthenticationError``. For unknown user, wrong password,
        locked or disabled account the error is identical and carries no
        reasons. Only after a CORRECT password may it carry ``mfa-required``
        (no code supplied) or ``mfa-invalid`` so the client can prompt.
        """
        now = self._now()
        ctx = {"source_ip": source_ip, "request_id": request_id}

        def fail(reason: str, user: User | None, *, client_reasons: tuple[str, ...] = (),
                 locked_now: bool = False) -> AuthenticationError:
            db.commit()   # persist counters/lockout before anything can roll them back
            self._record("auth.login", Outcome.FAILURE, user=user, reason=reason,
                         severity=Severity.WARNING, **ctx)
            if locked_now and user is not None:
                self._audit_lockout(user, **ctx)
            return AuthenticationError(_GENERIC_LOGIN_ERROR, reasons=client_reasons)

        user = self._find_user(db, username)
        if user is None:
            self._hasher.verify_dummy(password)
            raise fail("bad-credentials", None)
        if not self.network_allowed(user, source_ip):
            # F2: the allow list is checked before the password, so a caller
            # outside it cannot even test a password; the client sees the same
            # generic 401 as a wrong password, and it does NOT count towards
            # lockout (an outsider must not be able to lock the owner out).
            self._hasher.verify_dummy(password)
            raise fail("network-not-allowed", user)

        with self._login_lock(user.id):     # L3 belt: one attempt per user at a time in this process
            return self._login_attempt(db, user, password, totp_code, now, ctx, fail)

    def _login_attempt(self, db: DbSession, user: User, password: str, totp_code: str | None, now: datetime,
                       ctx: dict[str, Any], fail: Callable[..., AuthenticationError]) -> LoginResult:
        self._clear_expired_lock(user, now)
        if self._is_locked(user, now):
            self._hasher.verify_dummy(password)     # same work, result ignored
            raise fail("account-locked", user)
        if not user.is_active:
            self._hasher.verify_dummy(password)
            raise fail("user-disabled", user)
        if not self._reserve_attempt(db, user, now):
            # L3: max_failed_logins attempts are already failed or in flight
            self._hasher.verify_dummy(password)
            raise fail("account-locked", user)

        if not self._hasher.verify(user.password_hash, password):
            locked_now = self._lock_if_exhausted(db, user, now)
            raise fail("bad-credentials", user, locked_now=locked_now)

        mfa_passed = False
        if user.mfa_enabled:
            if totp_code is None or totp_code == "":
                self._release_attempt(db, user)
                raise fail("mfa-required", user, client_reasons=("mfa-required",))
            problem = self._accept_totp(db, user, totp_code, now)
            if problem is not None:
                locked_now = self._lock_if_exhausted(db, user, now)
                db.commit()
                self._record("auth.mfa_verify", Outcome.FAILURE, user=user, reason=problem,
                             severity=Severity.WARNING, **ctx)
                raise fail(problem, user, client_reasons=("mfa-invalid",), locked_now=locked_now)
            mfa_passed = True

        try:
            user.failed_login_count = 0
            user.locked_until = None
            if self._hasher.needs_rehash(user.password_hash):
                user.password_hash = self._hasher.hash(password)
            session = Session(
                user_id=user.id, created_at=now, last_seen_at=now,
                expires_at=now + timedelta(seconds=int(self._settings.session_absolute_ttl_seconds)),
                mfa_verified_at=now if mfa_passed else None,
                ip_hash=self._tokens.hash_ip(ctx["source_ip"]),
            )
            db.add(session)
            db.flush()
            result = self._issue(db, user, session, now)
            db.flush()
            if mfa_passed:
                self._record("auth.mfa_verify", Outcome.SUCCESS, user=user, session_id=session.id, **ctx)
            self._record("auth.login", Outcome.SUCCESS, user=user, session_id=session.id,
                         details={"mfa": mfa_passed}, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return result

    def refresh(self, db: DbSession, refresh_token: str, source_ip: str | None = None, *,
                request_id: str | None = None) -> LoginResult:
        """Exchange a refresh token for a new access + refresh token pair.

        Single use: the presented token is consumed with an atomic
        compare-and-set. If it was ALREADY used, either the legitimate client
        or a thief is replaying it; we cannot tell which, so the whole session
        is revoked (reason ``refresh-reuse``) and a critical event is audited.
        """
        now = self._now()
        ctx = {"source_ip": source_ip, "request_id": request_id}

        def fail(reason: str, user: User | None = None, session_id: str | None = None) -> AuthenticationError:
            db.commit()
            self._record("auth.refresh", Outcome.FAILURE, user=user, reason=reason,
                         severity=Severity.WARNING, session_id=session_id, **ctx)
            return AuthenticationError("invalid refresh token", reasons=(reason,))

        def reuse(session: Session, user: User | None) -> AuthenticationError:
            self._revoke(session, "refresh-reuse", now)
            db.commit()
            self._record("auth.refresh_reuse", Outcome.FAILURE, user=user,
                         actor_id=session.user_id, reason="refresh-reuse",
                         severity=Severity.CRITICAL, session_id=session.id, **ctx)
            return AuthenticationError("invalid refresh token", reasons=("refresh-reuse",))

        if (not isinstance(refresh_token, str) or not refresh_token
                or len(refresh_token) > _MAX_REFRESH_TOKEN_LENGTH):
            raise fail("refresh-invalid")
        token_hash = self._tokens.hash_refresh_token(refresh_token)
        row = db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
            .execution_options(populate_existing=True)
        ).scalar_one_or_none()
        if row is None:
            raise fail("refresh-invalid")
        session = self._fresh_session(db, row.session_id)
        if session is None:
            raise fail("refresh-invalid")
        user = self._fresh_user(db, session.user_id)

        if user is not None and not self.network_allowed(user, source_ip):
            # F2 + L2: a refresh token (e.g. stolen together with the browser
            # profile) is not usable from outside the allow list, and this is
            # checked FIRST: an outsider presenting an already-used token must
            # not be able to trigger the reuse revocation of the victim's live
            # session. Nothing is consumed or revoked; the attempt is audited
            # (WARNING) with a note when the token had already been used.
            db.commit()
            self._record("auth.refresh", Outcome.FAILURE, user=user, reason="network-not-allowed",
                         severity=Severity.WARNING, session_id=session.id,
                         details={"reuse_suspected": row.used_at is not None}, **ctx)
            raise AuthenticationError("invalid refresh token", reasons=("network-not-allowed",))
        if row.used_at is not None:
            raise reuse(session, user)
        if now >= _as_utc(row.expires_at):
            raise fail("refresh-expired", user, session.id)
        problem = self._validate_session(db, session, user, now, source_ip)
        if problem is not None:
            raise fail(problem, user, session.id)

        consumed = db.execute(
            update(RefreshToken)
            .where(RefreshToken.id == row.id, RefreshToken.used_at.is_(None))
            .values(used_at=now)
        )
        if consumed.rowcount != 1:      # lost a race against a concurrent use of the same token
            db.rollback()
            session = self._fresh_session(db, row.session_id)
            raise reuse(session, user)
        try:
            session.last_seen_at = now
            result = self._issue(db, user, session, now)
            db.flush()
            self._record("auth.refresh", Outcome.SUCCESS, user=user, session_id=session.id, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return result

    def logout(self, db: DbSession, session_id: str, *, source_ip: str | None = None,
               request_id: str | None = None) -> bool:
        """Revoke the session server-side: its access tokens stop working on
        the next request and its refresh tokens can no longer be exchanged."""
        session = self._fresh_session(db, session_id) if isinstance(session_id, str) else None
        if session is None:
            return False
        changed = self._revoke(session, "logout", self._now())
        try:
            self._record("auth.logout", Outcome.SUCCESS, actor_id=session.user_id, session_id=session.id,
                         source_ip=source_ip, request_id=request_id)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return changed

    # ------------------------------------------------------------------ #
    # per-request authentication
    # ------------------------------------------------------------------ #
    def authenticate_request(self, db: DbSession, access_token: str, source_ip: str | None = None, *,
                             request_id: str | None = None) -> AuthenticatedPrincipal:
        """Zero-trust request authentication (ADR-0008).

        1. Verify the token (pinned EdDSA, signature via KMS, exp/iat/iss/aud/typ).
        2. Load the session AND the user from the database, every time:
           session exists and belongs to ``sub``, is not revoked, not past its
           absolute expiry, not idle-expired; user exists and is active;
           optional IP binding.
        3. Update ``last_seen_at`` and build the policy ``Subject`` from the
           database rows (role, clearance, allow list, MFA state).

        Raises ``AuthenticationError`` with a reason code (``token-*``,
        ``session-not-found``, ``session-revoked``, ``session-expired``,
        ``session-idle-expired``, ``user-disabled``, ``ip-mismatch``).
        """
        ctx = {"source_ip": source_ip, "request_id": request_id}
        try:
            claims = self._tokens.verify_access_token(access_token)
        except AuthenticationError as exc:
            reason = exc.reasons[0] if exc.reasons else "token-malformed"
            # ordinary expiry is not a security event; other failures are
            # aggregated per client network when a gate is installed (M2)
            gate = self.token_failure_gate
            if reason != "token-expired" and (gate is None or gate(source_ip)):
                self._record("auth.token", Outcome.FAILURE, reason=reason, severity=Severity.WARNING,
                             details={"kind": "first"} if gate is not None else None, **ctx)
            raise
        now = self._now()

        def fail(reason: str, user: User | None, session_id: str | None) -> AuthenticationError:
            self._record("auth.session", Outcome.FAILURE, user=user, reason=reason,
                         severity=Severity.WARNING, session_id=session_id, **ctx)
            return AuthenticationError("invalid session", reasons=(reason,))

        session = self._fresh_session(db, claims.sid)
        if session is None or not hmac.compare_digest(session.user_id, claims.sub):
            raise fail("session-not-found", None, None)
        user = self._fresh_user(db, session.user_id)
        problem = self._validate_session(db, session, user, now, source_ip)
        if problem is not None:
            raise fail(problem, user, session.id)
        try:
            subject = self.build_subject(user, session, now)
        except AuthenticationError:
            raise fail("user-state-invalid", user, session.id) from None
        if (now - _as_utc(session.last_seen_at)).total_seconds() >= self._touch_granularity:
            session.last_seen_at = now
            db.commit()
        return AuthenticatedPrincipal(user=user, session=session, subject=subject, claims=claims)

    # ------------------------------------------------------------------ #
    # MFA
    # ------------------------------------------------------------------ #
    # ---- enrolment gating (ADR-0010) ---------------------------------- #
    @staticmethod
    def _mfa_state(db: DbSession, user: User, *, create: bool = False) -> MfaFactorState | None:
        state = db.execute(select(MfaFactorState).where(MfaFactorState.user_id == user.id)
                           .execution_options(populate_existing=True)).scalar_one_or_none()
        if state is None and create:
            state = MfaFactorState(user_id=user.id, ever_enabled=bool(user.mfa_enabled))
            db.add(state)
        return state

    @staticmethod
    def _ever_had_mfa(user: User, state: MfaFactorState | None) -> bool:
        return bool(user.mfa_enabled) or bool(state is not None and state.ever_enabled)

    def _is_bootstrap_admin(self, user: User) -> bool:
        name = self._settings.bootstrap_admin_username
        return (bool(name) and user.role == Role.ADMIN.value
                and hmac.compare_digest(user.username.lower(), str(name).lower()))

    @staticmethod
    def _other_admin_with_mfa(db: DbSession, user: User) -> bool:
        """Is there another active administrator who holds a factor (and so
        could issue this account an enrolment code)?"""
        return db.execute(
            select(func.count()).select_from(User)
            .where(User.id != user.id, User.role == Role.ADMIN.value, User.is_active.is_(True),
                   User.mfa_enabled.is_(True))
        ).scalar_one() > 0

    def _self_enroll_basis(self, db: DbSession, user: User, state: MfaFactorState | None,
                           now: datetime) -> str | None:
        """On what basis may this account enrol its FIRST factor without an
        admin-issued code? ``None`` means it may not.

        Root truth (F1): a password-only session cannot be told apart from a
        thief holding the password, so it must not be able to establish the
        factor that later proves identity -- except in the trust-on-first-use
        window right after registration (the password is new, so the chance
        that it was already stolen is lowest) and for the bootstrap admin at
        first login (the deployment's root of trust).

        The bootstrap exception is not time-boxed (the first login may come
        long after the deployment created the account), but it closes as soon
        as any OTHER active administrator holds a factor: from then on someone
        exists who can issue the bootstrap account an enrolment code."""
        if self._ever_had_mfa(user, state):
            return None
        if self._is_bootstrap_admin(user) and not self._other_admin_with_mfa(db, user):
            return MFA_BASIS_BOOTSTRAP
        created = _as_utc(user.created_at)
        window = int(getattr(self._settings, "mfa_self_enroll_window_seconds", 0))
        if created is not None and window > 0 and 0 <= (now - created).total_seconds() <= window:
            return MFA_BASIS_TOFU
        return None

    @staticmethod
    def _normalise_enrollment_code(code: object) -> str | None:
        if not isinstance(code, str) or len(code) > 64:
            return None
        norm = code.replace("-", "").replace(" ", "").upper()
        if len(norm) != _ENROLL_CODE_LEN or any(ch not in _ENROLL_CODE_ALPHABET for ch in norm):
            return None
        return norm

    def _enrollment_code_hmac(self, user_id: str, normalised: str) -> str:
        """Bound to the user id and domain-separated from refresh tokens and
        IP hashes; only this HMAC is stored."""
        return self._kms.mac(b"mfa-enrollment-code:" + user_id.encode("ascii") + b":"
                                     + normalised.encode("ascii"), purpose=KeyPurpose.LOOKUP_HMAC).hex()

    def _consume_enrollment_code(self, db: DbSession, user: User, code: object, now: datetime) -> bool:
        """Single use: atomic compare-and-set on ``used_at``. False for an
        unknown, foreign, expired, revoked or already used code."""
        norm = self._normalise_enrollment_code(code)
        if norm is None:
            return False
        digest = self._enrollment_code_hmac(user.id, norm)
        row = db.execute(select(MfaEnrollmentCode).where(MfaEnrollmentCode.code_hmac == digest)
                         .execution_options(populate_existing=True)).scalar_one_or_none()
        if (row is None or not hmac.compare_digest(row.user_id, user.id) or row.used_at is not None
                or row.revoked_at is not None or now >= _as_utc(row.expires_at)):
            return False
        result = db.execute(update(MfaEnrollmentCode)
                            .where(MfaEnrollmentCode.id == row.id, MfaEnrollmentCode.used_at.is_(None),
                                   MfaEnrollmentCode.revoked_at.is_(None))
                            .values(used_at=now))
        return result.rowcount == 1

    def issue_mfa_enrollment_code(self, db: DbSession, user: User, *, issued_by: str) -> tuple[str, datetime]:
        """Create a single-use, time-limited enrolment code for ``user`` and
        revoke any earlier unused one. Returns ``(code, expires_at)``; the
        code is returned once and only its HMAC is stored. Does NOT commit or
        audit: the caller (AdminService, after its PEP + fresh-MFA checks)
        records the event and commits."""
        now = self._now()
        db.execute(update(MfaEnrollmentCode)
                   .where(MfaEnrollmentCode.user_id == user.id, MfaEnrollmentCode.used_at.is_(None),
                          MfaEnrollmentCode.revoked_at.is_(None))
                   .values(revoked_at=now))
        raw = "".join(secrets.choice(_ENROLL_CODE_ALPHABET) for _ in range(_ENROLL_CODE_LEN))
        ttl = int(getattr(self._settings, "mfa_enrollment_code_ttl_seconds", 24 * 3600))
        expires = now + timedelta(seconds=max(60, ttl))
        db.add(MfaEnrollmentCode(user_id=user.id, code_hmac=self._enrollment_code_hmac(user.id, raw),
                                 issued_by=issued_by, created_at=now, expires_at=expires))
        db.flush()
        return "-".join(raw[i:i + 4] for i in range(0, _ENROLL_CODE_LEN, 4)), expires

    def reset_mfa(self, db: DbSession, user: User) -> bool:
        """Admin recovery path: remove the user's factor (and any pending
        enrolment), clear MFA status on every session. Returns whether a factor
        was enabled. The account keeps ``ever_enabled``, so the user needs an
        admin-issued enrolment code to enrol again. Does NOT commit, audit or
        revoke sessions: AdminService does those."""
        state = self._mfa_state(db, user, create=True)
        had = bool(user.mfa_enabled)
        state.ever_enabled = bool(state.ever_enabled) or had
        state.pending_basis = state.pending_created_at = state.pending_secret_enc = None
        user.mfa_enabled = False
        user.mfa_secret_enc = None
        user.mfa_last_counter = None
        for s in self._live_sessions(db, user.id):
            s.mfa_verified_at = None
        db.flush()
        return had

    def enroll_mfa(self, db: DbSession, user: User, *, enrollment_code: str | None = None,
                   current_code: str | None = None, session: Session | None = None,
                   source_ip: str | None = None, request_id: str | None = None) -> MfaEnrollment:
        """Start TOTP enrolment. The seed is returned once and stored only
        KMS-encrypted; nothing is enabled until ``activate_mfa`` proves the
        authenticator works.

        Gating (ADR-0010, finding F1):
          * no factor yet: allowed on a self-enrolment basis (trust-on-first-use
            window after registration, or the bootstrap admin), otherwise only
            with a valid admin-issued ``enrollment_code`` (consumed here);
            otherwise ``AccessDenied(mfa-enrollment-requires-approval)``.
          * a factor exists: replacing it needs ``current_code`` from that
            factor (failures count towards lockout); without it
            ``Conflict(mfa-already-enabled)``. The current factor keeps working
            until the replacement is activated.
          * the network allow list applies (``AccessDenied(network-not-allowed)``).
        """
        now = self._now()
        sid = session.id if session is not None else None
        ctx = {"source_ip": source_ip, "request_id": request_id}
        self._require_network(user, "auth.mfa_enroll", session_id=sid, **ctx)
        state = self._mfa_state(db, user)

        if user.mfa_enabled:
            if current_code is None or current_code == "":
                self._record("auth.mfa_enroll", Outcome.FAILURE, user=user, reason="mfa-already-enabled",
                             session_id=sid, **ctx)
                raise Conflict("mfa already enabled; replacing it needs a code from the current factor",
                               reasons=("mfa-already-enabled",))
            self._second_factor(db, user, current_code, "auth.mfa_enroll", session, ctx)
            enrollment, encrypted = self._totp.new_enrollment(user_id=user.id, account_name=user.username)
            try:
                state = state or self._mfa_state(db, user, create=True)
                state.ever_enabled = True
                state.pending_basis = MFA_BASIS_ROTATION
                state.pending_created_at = now
                state.pending_secret_enc = encrypted
                db.flush()
                self._record("auth.mfa_enroll", Outcome.SUCCESS, user=user, reason="replace-factor",
                             severity=Severity.WARNING, session_id=sid,
                             details={"method": MFA_BASIS_ROTATION}, **ctx)
                db.commit()
            except Exception:
                db.rollback()
                raise
            return enrollment

        basis = self._self_enroll_basis(db, user, state, now)
        if basis is None:
            if enrollment_code is None or enrollment_code == "":
                self._record("auth.mfa_enroll", Outcome.DENIED, user=user,
                             reason="mfa-enrollment-requires-approval", severity=Severity.WARNING,
                             session_id=sid, **ctx)
                raise AccessDenied("mfa enrolment requires an administrator-issued enrolment code",
                                   reasons=("mfa-enrollment-requires-approval",))
            if not self._consume_enrollment_code(db, user, enrollment_code, now):
                db.rollback()
                self._record("auth.mfa_enroll", Outcome.DENIED, user=user, reason="enrollment-code-invalid",
                             severity=Severity.WARNING, session_id=sid, **ctx)
                raise AccessDenied("invalid or expired enrolment code",
                                   reasons=("mfa-enrollment-code-invalid",))
            basis = MFA_BASIS_ADMIN_CODE
        enrollment, encrypted = self._totp.new_enrollment(user_id=user.id, account_name=user.username)
        try:
            state = state or self._mfa_state(db, user, create=True)
            state.pending_basis = basis
            state.pending_created_at = now
            state.pending_secret_enc = None
            user.mfa_secret_enc = encrypted
            user.mfa_last_counter = None
            db.flush()
            self._record("auth.mfa_enroll", Outcome.SUCCESS, user=user, session_id=sid,
                         severity=Severity.INFO if basis != MFA_BASIS_ADMIN_CODE else Severity.WARNING,
                         details={"method": basis}, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return enrollment

    def _pending_fresh(self, state: MfaFactorState | None, now: datetime) -> bool:
        if state is None or not state.pending_basis or state.pending_created_at is None:
            return False
        ttl = int(getattr(self._settings, "mfa_pending_enrollment_ttl_seconds", 15 * 60))
        return (now - _as_utc(state.pending_created_at)).total_seconds() <= ttl

    def activate_mfa(self, db: DbSession, user: User, code: str, *, session: Session | None = None,
                     source_ip: str | None = None, request_id: str | None = None) -> None:
        """Enable (or replace) the factor after a valid code for the pending
        seed. The time step is consumed (cannot be replayed at login).

        Deliberately (F1): the current session is NOT marked MFA-verified and
        no other session is revoked. Whoever started the enrolment proved only
        the password; MFA-verified status comes only from a later login or
        step-up with the new factor. Audited at WARNING, reason ``new-factor``.
        The pending enrolment must be younger than
        ``mfa_pending_enrollment_ttl_seconds``."""
        now = self._now()
        ctx = {"source_ip": source_ip, "request_id": request_id}
        sid = session.id if session is not None else None
        self._require_network(user, "auth.mfa_activate", session_id=sid, **ctx)
        state = self._mfa_state(db, user)

        def refuse(exc: Exception, reason: str, severity: Severity = Severity.INFO) -> Exception:
            db.commit()
            self._record("auth.mfa_activate", Outcome.FAILURE, user=user, reason=reason, severity=severity,
                         session_id=sid, **ctx)
            return exc

        replacing = bool(user.mfa_enabled)
        if replacing:
            if (state is None or state.pending_basis != MFA_BASIS_ROTATION or not state.pending_secret_enc):
                raise refuse(Conflict("mfa activation not possible", reasons=("mfa-already-enabled",)),
                             "mfa-already-enabled")
            pending_seed = state.pending_secret_enc
        else:
            if not user.mfa_secret_enc:
                raise refuse(Conflict("mfa activation not possible", reasons=("mfa-not-enrolled",)),
                             "mfa-not-enrolled")
            pending_seed = user.mfa_secret_enc
            if state is None or not state.pending_basis:
                # pending seed from before ADR-0010 bookkeeping: re-check the gate now
                if self._self_enroll_basis(db, user, state, now) is None:
                    raise refuse(AccessDenied("mfa enrolment requires an administrator-issued enrolment code",
                                              reasons=("mfa-enrollment-requires-approval",)),
                                 "mfa-enrollment-requires-approval", Severity.WARNING)
        if state is not None and state.pending_basis and not self._pending_fresh(state, now):
            state.pending_basis = state.pending_created_at = state.pending_secret_enc = None
            if not replacing:
                user.mfa_secret_enc = None
                user.mfa_last_counter = None
            raise refuse(Conflict("enrolment expired; start again", reasons=("mfa-enrollment-expired",)),
                         "mfa-enrollment-expired")

        if replacing:
            check = self._totp.verify(user_id=user.id, encrypted_seed=pending_seed, code=code, now=now,
                                      last_counter=None)
            problem = None if check.ok else (check.reason or "mfa-invalid")
        else:
            problem = self._accept_totp(db, user, code, now)
        if problem is not None:
            raise refuse(AuthenticationError("invalid code", reasons=("mfa-invalid",)), problem,
                         Severity.WARNING)
        try:
            basis = (state.pending_basis if state is not None and state.pending_basis else MFA_BASIS_TOFU)
            if replacing:
                user.mfa_secret_enc = pending_seed
                user.mfa_last_counter = max(int(user.mfa_last_counter or 0), int(check.counter))
                # Sessions verified with the OLD factor lose MFA-verified status:
                # whoever held that factor must prove the new one (review item).
                for other in self._live_sessions(db, user.id):
                    if sid is None or other.id != sid:
                        other.mfa_verified_at = None
            user.mfa_enabled = True
            state = state or self._mfa_state(db, user, create=True)
            state.ever_enabled = True
            state.pending_basis = state.pending_created_at = state.pending_secret_enc = None
            db.flush()
            self._record("auth.mfa_activate", Outcome.SUCCESS, user=user, reason="new-factor",
                         severity=Severity.WARNING, session_id=sid, details={"method": basis}, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise

    def _second_factor(self, db: DbSession, user: User, code: str, event: str, session: Session | None,
                       ctx: dict[str, Any]) -> datetime:
        """Verify a code for an already-enrolled user with brute-force
        throttling: failures share the login failure counter, and reaching the
        limit locks the account and revokes the session that was guessing."""
        now = self._now()
        sid = session.id if session is not None else None

        def fail(reason: str, client_reason: str, locked_now: bool = False) -> AuthenticationError:
            db.commit()
            self._record(event, Outcome.FAILURE, user=user, reason=reason, severity=Severity.WARNING,
                         session_id=sid, **ctx)
            if locked_now:
                self._audit_lockout(user, **ctx)
            return AuthenticationError("second factor failed", reasons=(client_reason,))

        if not user.is_active:
            raise fail("user-disabled", "user-disabled")
        if session is not None and (session.user_id != user.id or session.revoked_at is not None):
            raise fail("session-revoked", "session-revoked")
        if not user.mfa_enabled or not user.mfa_secret_enc:
            raise fail("mfa-not-enrolled", "mfa-not-enrolled")
        self._clear_expired_lock(user, now)
        if self._is_locked(user, now):
            raise fail("account-locked", "mfa-invalid")
        problem = self._accept_totp(db, user, code, now)
        if problem is not None:
            locked_now = self._count_failure(db, user, now)
            if locked_now and session is not None:
                self._revoke(session, "mfa-failures", now)
            raise fail(problem, "mfa-invalid", locked_now)
        user.failed_login_count = 0
        return now

    def verify_mfa_step_up(self, db: DbSession, session: Session, code: str, *,
                           source_ip: str | None = None, request_id: str | None = None) -> Session:
        """Step-up: prove possession of the second factor again and stamp
        ``Session.mfa_verified_at`` so the PDP sees fresh MFA."""
        ctx = {"source_ip": source_ip, "request_id": request_id}
        user = self._fresh_user(db, session.user_id)
        if user is None:
            raise AuthenticationError("second factor failed", reasons=("user-disabled",))
        self._require_network(user, "auth.mfa_verify", session_id=session.id, **ctx)
        now = self._second_factor(db, user, code, "auth.mfa_verify", session, ctx)
        try:
            session.mfa_verified_at = now
            db.flush()
            self._record("auth.mfa_verify", Outcome.SUCCESS, user=user, session_id=session.id, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return session

    def disable_mfa(self, db: DbSession, user: User, code: str, *, session: Session | None = None,
                    source_ip: str | None = None, request_id: str | None = None) -> None:
        """Remove the second factor. Requires a currently valid TOTP code, so
        a stolen password/session alone cannot downgrade the account. The
        encrypted seed is deleted and no session keeps MFA-verified status."""
        ctx = {"source_ip": source_ip, "request_id": request_id}
        self._require_network(user, "auth.mfa_disable",
                              session_id=session.id if session is not None else None, **ctx)
        self._second_factor(db, user, code, "auth.mfa_disable", session, ctx)
        try:
            state = self._mfa_state(db, user, create=True)
            state.ever_enabled = True        # re-enrolling later needs an admin-issued code
            state.pending_basis = state.pending_created_at = state.pending_secret_enc = None
            user.mfa_enabled = False
            user.mfa_secret_enc = None
            user.mfa_last_counter = None
            for s in self._live_sessions(db, user.id):
                s.mfa_verified_at = None
            if session is not None:
                session.mfa_verified_at = None
            db.flush()
            self._record("auth.mfa_disable", Outcome.SUCCESS, user=user,
                         session_id=session.id if session is not None else None,
                         severity=Severity.WARNING, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise

    # ------------------------------------------------------------------ #
    # password change
    # ------------------------------------------------------------------ #
    def change_password(self, db: DbSession, user: User, current_password: str, new_password: str, *,
                        keep_session_id: str | None = None, session: Session | None = None,
                        mfa_max_age_seconds: int | None = None, require_mfa_for_login: bool = True,
                        source_ip: str | None = None, request_id: str | None = None) -> int:
        """Change the password after re-verifying the current one.

        Finding H1: with ``session`` given (the API always passes the caller's
        session) the change needs a session that verified the second factor
        within ``mfa_max_age_seconds`` (403 ``mfa-required``/``mfa-stale`` +
        ``step-up-mfa``); an account without a factor is refused (403
        ``mfa-required`` + ``enroll-mfa``, finding M5). Then other sessions are
        revoked so a thief holding a password-only session is cut off -- but a
        session that is MFA-verified MORE RECENTLY than the caller's, or any
        MFA-verified session when the caller's own session is not
        MFA-verified, is never revoked: a password change must not let the
        weaker credential evict the stronger one. Returns the number of
        sessions revoked. Wrong current passwords count towards lockout."""
        now = self._now()
        ctx = {"source_ip": source_ip, "request_id": request_id}
        keep_session_id = keep_session_id or (session.id if session is not None else None)
        self._require_network(user, "auth.password_change", session_id=keep_session_id, **ctx)
        gate = session if session is not None else (
            self._fresh_session(db, keep_session_id) if keep_session_id else None)
        if gate is None or gate.user_id != user.id:
            # fail closed: without the caller's session there is no proof of a
            # second factor, so the change is refused like a restricted session
            self._record("auth.password_change", Outcome.DENIED, user=user, reason="mfa-required",
                         severity=Severity.WARNING, **ctx)
            exc = AccessDenied("password change needs an MFA-verified session", reasons=("mfa-required",))
            exc.obligations = ("step-up-mfa",) if user.mfa_enabled else ("enroll-mfa",)
            raise exc
        self.require_mfa_session(user, gate, "auth.password_change",
                                 require_mfa_for_login=require_mfa_for_login,
                                 fresh_within_seconds=int(mfa_max_age_seconds if mfa_max_age_seconds is not None
                                                          else self._settings.mfa_step_up_max_age_seconds),
                                 **ctx)

        def fail(reason: str, locked_now: bool = False) -> None:
            db.commit()
            self._record("auth.password_change", Outcome.FAILURE, user=user, reason=reason,
                         severity=Severity.WARNING, session_id=keep_session_id, **ctx)
            if locked_now:
                self._audit_lockout(user, **ctx)

        self._clear_expired_lock(user, now)
        if self._is_locked(user, now) or not user.is_active:
            self._hasher.verify_dummy(current_password)
            fail("account-locked" if user.is_active else "user-disabled")
            raise AuthenticationError(_GENERIC_LOGIN_ERROR)
        if not self._hasher.verify(user.password_hash, current_password):
            fail("bad-credentials", self._count_failure(db, user, now))
            raise AuthenticationError(_GENERIC_LOGIN_ERROR)
        try:
            validate_password(new_password, username=user.username,
                              min_length=int(self._settings.password_min_length))
        except ValidationFailed:
            fail("weak-password")
            raise
        if self._hasher.verify(user.password_hash, new_password):
            fail("password-unchanged")
            raise ValidationFailed("password does not meet policy", reasons=("password-unchanged",))
        caller = self._fresh_session(db, keep_session_id) if keep_session_id else None
        caller_verified = _as_utc(caller.mfa_verified_at) if caller is not None else None
        try:
            user.password_hash = self._hasher.hash(new_password)
            user.password_changed_at = now
            user.failed_login_count = 0
            revoked = kept = 0
            for s in self._live_sessions(db, user.id):
                if s.id == keep_session_id:
                    continue
                other_verified = _as_utc(s.mfa_verified_at)
                if other_verified is not None and (caller_verified is None or other_verified > caller_verified):
                    kept += 1             # stronger (or more recent) proof than the caller's: never evicted
                    continue
                if self._revoke(s, "password-change", now):
                    revoked += 1
            db.flush()
            self._record("auth.password_change", Outcome.SUCCESS, user=user, session_id=keep_session_id,
                         details={"sessions_revoked": revoked, "sessions_kept": kept}, **ctx)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return revoked

    # ------------------------------------------------------------------ #
    # session management
    # ------------------------------------------------------------------ #
    @staticmethod
    def _live_sessions(db: DbSession, user_id: str) -> list[Session]:
        return list(db.execute(
            select(Session).where(Session.user_id == user_id, Session.revoked_at.is_(None))
            .execution_options(populate_existing=True)
        ).scalars())

    def list_sessions(self, db: DbSession, user: User) -> list[Session]:
        """The user's currently usable sessions (not revoked, not past
        absolute or idle expiry), newest first."""
        now = self._now()
        live = [s for s in self._live_sessions(db, user.id) if self._session_problem(s, now) is None]
        return sorted(live, key=lambda s: _as_utc(s.created_at), reverse=True)

    def revoke_session(self, db: DbSession, session_id: str, reason: str, *, owner_id: str | None = None,
                       actor_id: str | None = None, source_ip: str | None = None,
                       request_id: str | None = None) -> bool:
        """Revoke one session. With ``owner_id`` the session must belong to
        that user, otherwise it is treated as not found (no cross-user
        revocation by guessing ids). Returns False if nothing was revoked."""
        session = self._fresh_session(db, session_id) if isinstance(session_id, str) else None
        if session is None or (owner_id is not None and session.user_id != owner_id):
            return False
        if not self._revoke(session, reason, self._now()):
            return False
        try:
            db.flush()
            self._record("auth.session_revoke", Outcome.SUCCESS, actor_id=actor_id or session.user_id,
                         reason=reason, session_id=session.id, source_ip=source_ip, request_id=request_id)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return True

    def revoke_all_sessions(self, db: DbSession, user_id: str, reason: str, *,
                            except_session_id: str | None = None, actor_id: str | None = None,
                            source_ip: str | None = None, request_id: str | None = None) -> int:
        """Revoke every live session of a user (optionally sparing one).
        Returns the number revoked."""
        now = self._now()
        try:
            count = 0
            for s in self._live_sessions(db, user_id):
                if s.id != except_session_id and self._revoke(s, reason, now):
                    count += 1
            db.flush()
            self._audit.record(
                event_type="auth.session_revoke", action="auth:session_revoke_all", outcome=Outcome.SUCCESS,
                actor_id=actor_id or user_id, resource_type="user", resource_id=user_id, reason=reason,
                severity=Severity.INFO, details={"reason": reason, "sessions_revoked": count},
                request_id=request_id, source_ip=source_ip)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return count
