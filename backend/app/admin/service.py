"""Administrative operations: user role / clearance / activation / network
allow list / session revocation, KMS rotation with DEK re-wrap, audited
pseudonym re-identification.

Security properties:
  * Every operation passes the PEP first (``user:manage`` / ``kms:rotate``
    need fresh MFA by default) and is audited with the target as a
    pseudonym, never a username.
  * An administrator cannot change their own role, clearance or activation
    (no self-escalation/self-lockout through the API), and the last active
    admin cannot be demoted or disabled.
  * Changes apply on the target's next request: subjects are re-read from
    the DB on every request (ADR-0008); disabling also revokes all sessions.
  * The user directory never carries audit pseudonyms (finding M1): the only
    way to map a pseudonym to an account is the audited ``reidentify``.
  * The audit-pseudonym key cannot be rotated through the API (finding M3,
    ADR-0007 amendment): that is an offline, two-person operation.
"""
from __future__ import annotations

import hmac
import ipaddress
from datetime import timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from app.contracts import (Action, Classification, KeyPurpose, Outcome, RequestContext, Resource, Role,
                           Severity, Subject)
from app.errors import AccessDenied, Conflict, NotFound, ValidationFailed
from app.models import Session, User


def _iso(dt):
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return dt.isoformat().replace("+00:00", "Z")


class AdminService:
    def __init__(self, *, pep: Any, audit: Any, auth: Any, kms: Any, files: Any, clock: Any,
                 policy_store: Any = None) -> None:
        self._pep, self._audit, self._auth, self._kms, self._files = pep, audit, auth, kms, files
        self._clock = clock
        self._policy_store = policy_store

    # ------------------------------------------------------------------ #
    def _record(self, event: str, action: Action, outcome: Outcome, subject: Subject, ctx: RequestContext, *,
                target_id: str | None = None, reason: str | None = None,
                severity: Severity = Severity.WARNING, details: dict | None = None) -> None:
        d = dict(details or {})
        if target_id:
            d["target_user"] = self._audit.pseudonym_for(target_id)
        self._audit.record(event_type=event, action=action.value, outcome=outcome, actor_id=subject.user_id,
                           actor_role=subject.role.value, resource_type="user", resource_id=target_id,
                           reason=reason, severity=severity, details=d or None,
                           request_id=ctx.request_id, source_ip=ctx.source_ip)

    def _target(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str,
                action: Action = Action.USER_MANAGE) -> User:
        self._pep.enforce(db, subject, action, Resource(type="user", id=user_id[:32]), ctx)
        user = db.execute(select(User).where(User.id == user_id)
                          .execution_options(populate_existing=True)).scalar_one_or_none()
        if user is None:
            raise NotFound("user not found")
        return user

    @staticmethod
    def _not_self(subject: Subject, user: User) -> None:
        if hmac.compare_digest(subject.user_id, user.id):
            raise Conflict("administrators cannot change their own account here", reasons=("cannot-modify-self",))

    @staticmethod
    def _active_admins(db: DbSession) -> int:
        return int(db.execute(select(func.count()).select_from(User)
                              .where(User.role == Role.ADMIN.value, User.is_active.is_(True))).scalar_one())

    def user_view(self, db: DbSession, u: User) -> dict[str, Any]:
        now = self._clock()
        live = db.execute(select(func.count()).select_from(Session).where(
            Session.user_id == u.id, Session.revoked_at.is_(None), Session.expires_at > now)).scalar_one()
        return {"id": u.id, "username": u.username, "role": u.role, "clearance": u.clearance,
                "is_active": bool(u.is_active), "mfa_enabled": bool(u.mfa_enabled),
                "allowed_cidrs": list(u.allowed_cidrs or []), "created_at": _iso(u.created_at),
                "locked_until": _iso(u.locked_until), "active_sessions": int(live)}

    # ------------------------------------------------------------------ #
    def list_users(self, db: DbSession, subject: Subject, ctx: RequestContext) -> list[dict[str, Any]]:
        self._pep.enforce(db, subject, Action.USER_LIST, Resource(type="user"), ctx)
        users = db.execute(select(User).order_by(User.created_at)).scalars().all()
        return [self.user_view(db, u) for u in users]

    def set_role(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str, role: str) -> dict:
        user = self._target(db, subject, ctx, user_id)
        self._not_self(subject, user)
        new = Role(role).value
        old = user.role
        if old == Role.ADMIN.value and new != old and user.is_active and self._active_admins(db) <= 1:
            raise Conflict("cannot demote the last administrator", reasons=("last-admin",))
        if new != old:
            user.role = new
            db.flush()
            self._record("admin.user.role", Action.USER_MANAGE, Outcome.SUCCESS, subject, ctx, target_id=user.id,
                         details={"old_role": old, "new_role": new})
            db.commit()
        return self.user_view(db, user)

    def set_clearance(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str,
                      clearance: str) -> dict:
        user = self._target(db, subject, ctx, user_id)
        self._not_self(subject, user)
        new = Classification(clearance).value
        old = user.clearance
        if new != old:
            user.clearance = new
            db.flush()
            self._record("admin.user.clearance", Action.USER_MANAGE, Outcome.SUCCESS, subject, ctx,
                         target_id=user.id, details={"old_clearance": old, "new_clearance": new})
            db.commit()
        return self.user_view(db, user)

    def set_active(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str,
                   active: bool) -> dict:
        user = self._target(db, subject, ctx, user_id)
        self._not_self(subject, user)
        if not active and user.role == Role.ADMIN.value and user.is_active and self._active_admins(db) <= 1:
            raise Conflict("cannot disable the last administrator", reasons=("last-admin",))
        if bool(user.is_active) != active:
            user.is_active = active
            db.flush()
            self._record("admin.user.enable" if active else "admin.user.disable", Action.USER_MANAGE,
                         Outcome.SUCCESS, subject, ctx, target_id=user.id, details={"active": active})
            db.commit()
            if not active:
                self._auth.revoke_all_sessions(db, user.id, "user-disabled", actor_id=subject.user_id,
                                               source_ip=ctx.source_ip, request_id=ctx.request_id)
        return self.user_view(db, user)

    def set_cidrs(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str,
                  cidrs: list[str]) -> dict:
        user = self._target(db, subject, ctx, user_id)
        normalised: list[str] = []
        for c in cidrs:
            try:
                net = ipaddress.ip_network(str(c).strip(), strict=False)
            except ValueError:
                raise ValidationFailed("invalid CIDR", reasons=("invalid-cidr",)) from None
            if str(net) not in normalised:
                normalised.append(str(net))
        user.allowed_cidrs = normalised
        db.flush()
        self._record("admin.user.allow_list", Action.USER_MANAGE, Outcome.SUCCESS, subject, ctx,
                     target_id=user.id, details={"cidr_count": len(normalised)})
        db.commit()
        return self.user_view(db, user)

    def revoke_sessions(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str) -> int:
        user = self._target(db, subject, ctx, user_id)
        return int(self._auth.revoke_all_sessions(
            db, user.id, "admin-revoked",
            except_session_id=subject.session_id if user.id == subject.user_id else None,
            actor_id=subject.user_id, source_ip=ctx.source_ip, request_id=ctx.request_id))

    # ------------------------------------------------------------------ #
    # MFA recovery / enrolment approval (ADR-0010)
    # ------------------------------------------------------------------ #
    def _require_fresh_mfa(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str) -> None:
        """Independent of the runtime policy: even if an administrator removed
        ``user:manage`` from ``mfa_required_actions``, issuing an enrolment code
        or resetting a factor needs fresh MFA (these are the privileged paths
        that hand out the ability to establish a second factor)."""
        cfg = self._policy_store.load(db) if self._policy_store is not None else None
        max_age = int(cfg.mfa_step_up_max_age_seconds) if cfg is not None else 600
        age = subject.mfa_age_seconds
        if subject.mfa_verified and age is not None and 0 <= age <= max_age:
            return
        reason = "mfa-stale" if subject.mfa_verified else "mfa-required"
        self._audit.record(event_type="authz.decision", action=Action.USER_MANAGE.value, outcome=Outcome.DENIED,
                           actor_id=subject.user_id, actor_role=subject.role.value, resource_type="user",
                           resource_id=user_id[:32], reason=reason, severity=Severity.WARNING,
                           details={"reasons": [reason], "policies": ["admin.mfa-recovery-needs-fresh-mfa"],
                                    "obligations": ["step-up-mfa"]},
                           request_id=ctx.request_id, source_ip=ctx.source_ip)
        exc = AccessDenied("fresh MFA required", reasons=(reason,))
        exc.obligations = ("step-up-mfa",)
        raise exc

    def issue_mfa_enrollment_code(self, db: DbSession, subject: Subject, ctx: RequestContext,
                                  user_id: str) -> dict[str, Any]:
        """Single-use, time-limited code that lets ``user_id`` enrol a factor
        outside the trust-on-first-use window. Requires ``user:manage`` and
        fresh admin MFA; not for the administrator's own account."""
        user = self._target(db, subject, ctx, user_id)
        self._require_fresh_mfa(db, subject, ctx, user.id)
        self._not_self(subject, user)
        if user.mfa_enabled:
            # a code could not be used (replacing a factor needs a code from the
            # current one); for a lost device reset the factor first
            raise Conflict("the user already has an MFA factor; reset it first",
                           reasons=("mfa-already-enabled",))
        code, expires = self._auth.issue_mfa_enrollment_code(db, user, issued_by=subject.user_id)
        ttl = int((expires - self._clock()).total_seconds())
        self._record("admin.user.mfa_enrollment_code", Action.USER_MANAGE, Outcome.SUCCESS, subject, ctx,
                     target_id=user.id, details={"window_seconds": ttl})
        db.commit()
        return {"user_id": user.id, "enrollment_code": code, "expires_at": _iso(expires),
                "single_use": True}

    def reset_mfa(self, db: DbSession, subject: Subject, ctx: RequestContext, user_id: str) -> dict[str, Any]:
        """Recovery path for a lost or hijacked factor: remove the user's
        factor and revoke all their sessions. The user then needs an
        admin-issued enrolment code to enrol again."""
        user = self._target(db, subject, ctx, user_id)
        self._require_fresh_mfa(db, subject, ctx, user.id)
        self._not_self(subject, user)
        had = self._auth.reset_mfa(db, user)
        self._record("admin.user.mfa_reset", Action.USER_MANAGE, Outcome.SUCCESS, subject, ctx,
                     target_id=user.id, details={"mfa": had})
        db.commit()
        revoked = self._auth.revoke_all_sessions(db, user.id, "mfa-reset", actor_id=subject.user_id,
                                                 source_ip=ctx.source_ip, request_id=ctx.request_id)
        return {**self.user_view(db, user), "sessions_revoked": int(revoked)}

    # ------------------------------------------------------------------ #
    def list_keys(self, db: DbSession, subject: Subject, ctx: RequestContext) -> list[dict[str, Any]]:
        self._pep.enforce(db, subject, Action.KMS_READ, Resource(type="kms"), ctx)
        return [{"purpose": k.purpose, "key_id": k.key_id, "version": k.version, "algorithm": k.algorithm,
                 "created_at": _iso(k.created_at), "state": k.state} for k in self._kms.list_keys()]

    def rotate_key(self, db: DbSession, subject: Subject, ctx: RequestContext, purpose: str) -> dict[str, Any]:
        p = KeyPurpose(purpose)
        self._pep.enforce(db, subject, Action.KMS_ROTATE, Resource(type="kms", id=p.value), ctx)
        if p is KeyPurpose.AUDIT_PSEUDONYM:
            # M3: rotating the pseudonym key through the API would let one
            # administrator act and then cut the link between their earlier
            # actions and their account in every product view. It is an
            # offline, two-person operation (ADR-0007 amendment); history stays
            # attributable because lookups match every retained key version.
            self._audit.record(
                event_type="admin.kms.rotate", action=Action.KMS_ROTATE.value, outcome=Outcome.DENIED,
                actor_id=subject.user_id, actor_role=subject.role.value, resource_type="kms",
                resource_id=p.value, reason="pseudonym-key-rotation-disabled", severity=Severity.WARNING,
                details={"key_purpose": p.value}, request_id=ctx.request_id, source_ip=ctx.source_ip)
            raise AccessDenied("the audit-pseudonym key cannot be rotated through the API",
                               reasons=("pseudonym-key-rotation-disabled",))
        info = self._kms.rotate(p)
        rewrapped = failures = 0
        if p is KeyPurpose.FILE_DEK_WRAP:
            rewrapped, failures = self._files.rewrap_all(db, self._kms)
        self._audit.record(
            event_type="admin.kms.rotate", action=Action.KMS_ROTATE.value,
            outcome=Outcome.SUCCESS if not failures else Outcome.FAILURE, actor_id=subject.user_id,
            actor_role=subject.role.value, resource_type="kms", resource_id=p.value,
            severity=Severity.WARNING if not failures else Severity.CRITICAL,
            details={"key_purpose": p.value, "new_version": info.version, "files_rewrapped": rewrapped,
                     "rewrap_failures": failures},
            request_id=ctx.request_id, source_ip=ctx.source_ip)
        return {"purpose": info.purpose, "key_id": info.key_id, "version": info.version,
                "files_rewrapped": rewrapped, "rewrap_failures": failures}

    def reidentify(self, db: DbSession, subject: Subject, ctx: RequestContext, pseudonym: str) -> dict:
        """Map an audit pseudonym to a user by recomputing candidates' pseudonyms
        (there is no reverse table). Always audited (ADR-0007). Every retained
        version of the pseudonym key is tried, so a pseudonym written before a
        (offline) key rotation still resolves (finding M3)."""
        self._pep.enforce(db, subject, Action.USER_MANAGE, Resource(type="user"), ctx)
        found = None
        for u in db.execute(select(User)).scalars():
            if any(hmac.compare_digest(candidate, pseudonym) for candidate in self._audit.pseudonyms_for(u.id)):
                found = u
                break
        self._audit.record(event_type="audit.reidentify", action=Action.USER_MANAGE.value,
                           outcome=Outcome.SUCCESS if found else Outcome.FAILURE, actor_id=subject.user_id,
                           actor_role=subject.role.value, resource_type="user",
                           resource_id=found.id if found else None, severity=Severity.WARNING,
                           details={"target_user": pseudonym},
                           request_id=ctx.request_id, source_ip=ctx.source_ip)
        if found is None:
            raise NotFound("no user has this pseudonym")
        return {"pseudonym": pseudonym, "user": {"id": found.id, "username": found.username,
                                                 "role": found.role}}
