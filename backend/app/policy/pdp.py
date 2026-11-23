"""Policy Decision Point (ADR-0008).

``PolicyDecisionPoint.evaluate`` is a pure function of (subject, action,
resource, context, PolicyConfig): no database, no I/O, no clock reads.

Evaluation:
  1. Guard rules (stage ``guard``) can only DENY: inactive user, network allow
     list, session age, restricted (MFA-less) session, download block.
  2. Constraint rules (stage ``constraint``) can only DENY: ownership /
     separation of duties, classification vs clearance, MFA freshness, file
     availability.
  3. Allow rules (stage ``allow``) grant by role, ownership and sharing.
  The decision is ALLOW only if at least one allow rule matched and no deny
  rule matched. Otherwise DENY with every deny reason; ``default-deny`` is
  added when no allow rule matched and nothing more specific explains it.

Rules are plain data (``PolicyRule``) so the UI can list them through
``describe_policies()``.
"""
from __future__ import annotations

import hmac
import ipaddress
from dataclasses import dataclass
from typing import Callable

from app.contracts import (Action, Classification, Decision, RequestContext, Resource, Role,
                           Subject)
from app.policy.config import PolicyConfig

Condition = Callable[[Subject, Action, Resource, RequestContext, PolicyConfig], bool]

ALL_ROLES: frozenset[Role] = frozenset(Role)

#: Actions that address one specific file and therefore need an owner/share check.
FILE_INSTANCE_ACTIONS: frozenset[Action] = frozenset({
    Action.FILE_READ_METADATA, Action.FILE_READ, Action.FILE_DELETE, Action.FILE_SHARE,
    Action.FILE_VERIFY, Action.FILE_REPAIR,
})
OWNER_FILE_ACTIONS = FILE_INSTANCE_ACTIONS
GRANTEE_FILE_ACTIONS: frozenset[Action] = frozenset({Action.FILE_READ_METADATA, Action.FILE_READ})
#: Admin may run these on ANY file: no plaintext leaves the backend.
ADMIN_ANY_FILE_ACTIONS: frozenset[Action] = frozenset({
    Action.FILE_VERIFY, Action.FILE_REPAIR, Action.FILE_READ_METADATA,
})
CLEARANCE_CHECKED_ACTIONS: frozenset[Action] = frozenset({
    Action.FILE_READ, Action.FILE_READ_METADATA, Action.FILE_CREATE,
})
#: What a restricted session (require_mfa_for_login, no MFA) may still do:
#: open the security centre (where MFA enrolment lives) and read the policy.
RESTRICTED_SESSION_ACTIONS: frozenset[Action] = frozenset({Action.SECURITY_READ, Action.POLICY_READ})

USER_BASE_ACTIONS: frozenset[Action] = frozenset({
    Action.FILE_CREATE, Action.FILE_LIST, Action.AUDIT_READ_OWN, Action.DASHBOARD_READ,
    Action.STORAGE_READ, Action.POLICY_READ, Action.SECURITY_READ,
})
#: Auditors work with pseudonyms only: no ``user:list`` (finding M1), the user
#: directory would let them map pseudonyms back to accounts outside the
#: audited re-identification path.
AUDITOR_ACTIONS: frozenset[Action] = frozenset({
    Action.AUDIT_READ_ALL, Action.AUDIT_VERIFY, Action.SECURITY_READ, Action.KMS_READ,
})
ADMIN_ACTIONS: frozenset[Action] = frozenset({
    Action.USER_LIST, Action.USER_MANAGE, Action.POLICY_READ, Action.POLICY_WRITE, Action.KMS_READ,
    Action.KMS_ROTATE, Action.STORAGE_READ, Action.STORAGE_ADMIN, Action.AUDIT_READ_ALL,
    Action.AUDIT_VERIFY, Action.AUDIT_CHECKPOINT, Action.AUDIT_RETENTION, Action.DASHBOARD_READ,
    Action.SECURITY_READ,
})

OBLIGATION_STEP_UP = "step-up-mfa"
OBLIGATION_ENROLL = "enroll-mfa"
_MFA_REASONS = frozenset({"mfa-required", "mfa-stale"})


@dataclass(frozen=True)
class PolicyRule:
    id: str
    description: str
    effect: str                        # "allow" | "deny"
    stage: str                         # "guard" | "constraint" | "allow"
    actions: frozenset[Action] | None  # None = every action
    roles: frozenset[Role]
    condition: Condition
    reason: str | None = None          # deny reason code
    condition_text: str = ""

    def applies(self, subject: Subject, action: Action) -> bool:
        return (self.actions is None or action in self.actions) and subject.role in self.roles

    def describe(self) -> dict:
        return {
            "id": self.id,
            "description": self.description,
            "effect": self.effect,
            "stage": self.stage,
            "actions": "*" if self.actions is None else sorted(a.value for a in self.actions),
            "roles": sorted(r.value for r in self.roles),
            "condition": self.condition_text,
            "reason": self.reason,
        }


# --------------------------------------------------------------------------- #
# condition helpers (pure)
# --------------------------------------------------------------------------- #
def _always(*_: object) -> bool:
    return True


def _is_file(r: Resource) -> bool:
    return r.type == "file"


def _is_owner(s: Subject, r: Resource) -> bool:
    return (_is_file(r) and isinstance(r.owner_id, str) and bool(r.owner_id)
            and hmac.compare_digest(r.owner_id, s.user_id))


def _ip_allowed(cidrs: tuple[str, ...], source_ip: str | None) -> bool:
    """True if ``source_ip`` lies in any of ``cidrs``. Malformed CIDR entries
    are skipped (they can never match); a missing or unparseable IP fails."""
    if not source_ip:
        return False
    try:
        ip = ipaddress.ip_address(source_ip.strip())
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(str(cidr).strip(), strict=False)
        except ValueError:
            continue
        if net.version == ip.version and ip in net:
            return True
    return False


#: Public name: the auth service applies the same allow-list check at login,
#: refresh and on account-management endpoints (F2), outside the PDP.
ip_allowed = _ip_allowed


def _network_denied(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    return bool(s.allowed_cidrs) and not _ip_allowed(s.allowed_cidrs, c.source_ip)


def _restricted_session(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    return p.require_mfa_for_login and not s.mfa_verified and a not in RESTRICTED_SESSION_ACTIONS


def _not_owner_or_grantee(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    if not _is_file(r) or _is_owner(s, r):
        return False
    if a in GRANTEE_FILE_ACTIONS and r.shared_with_subject:
        return False
    if s.role is Role.ADMIN and a in ADMIN_ANY_FILE_ACTIONS:
        return False
    return not (s.role is Role.ADMIN)   # admin gets its own, more specific reason


def _admin_content(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    if not _is_file(r) or _is_owner(s, r) or a in ADMIN_ANY_FILE_ACTIONS:
        return False
    if a in GRANTEE_FILE_ACTIONS and r.shared_with_subject:
        return False   # an admin who was explicitly shared a file reads it as a grantee
    return True


def _classification_missing(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    return _is_file(r) and r.classification is None


def _insufficient_clearance(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    return _is_file(r) and r.classification is not None and r.classification.rank > s.clearance.rank


def _needs_mfa(a: Action, r: Resource, p: PolicyConfig) -> bool:
    if a in p.mfa_required_actions:
        return True
    return (a is Action.FILE_READ and r.classification is not None
            and r.classification.rank >= p.mfa_required_classification.rank)


def _mfa_missing(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    return _needs_mfa(a, r, p) and not s.mfa_verified


def _mfa_stale(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    if not _needs_mfa(a, r, p) or not s.mfa_verified:
        return False
    age = s.mfa_age_seconds
    return age is None or age < 0 or age > p.mfa_step_up_max_age_seconds


def _file_unavailable(s: Subject, a: Action, r: Resource, c: RequestContext, p: PolicyConfig) -> bool:
    return _is_file(r) and r.status != "committed"


# --------------------------------------------------------------------------- #
# rule set
# --------------------------------------------------------------------------- #
GUARD_RULES: tuple[PolicyRule, ...] = (
    PolicyRule("guard.user-inactive", "Disabled accounts can do nothing.", "deny", "guard", None, ALL_ROLES,
               lambda s, a, r, c, p: not s.is_active, "user-inactive", "subject.is_active is false"),
    PolicyRule("guard.network-allow-list",
               "If the user has a network allow list, the request must come from inside it "
               "(IPv4 and IPv6; a missing source IP is refused).", "deny", "guard", None, ALL_ROLES,
               _network_denied, "network-not-allowed",
               "subject.allowed_cidrs non-empty and context.source_ip not in any CIDR"),
    PolicyRule("guard.session-age", "Sessions older than the maximum session age are refused.",
               "deny", "guard", None, ALL_ROLES,
               lambda s, a, r, c, p: s.session_age_seconds > p.max_session_age_seconds,
               "session-too-old", "subject.session_age_seconds > max_session_age_seconds"),
    PolicyRule("guard.require-mfa-for-login",
               "When MFA is mandatory for login, a session without a verified second factor may only "
               "open the security centre to enrol MFA and read the policy.", "deny", "guard", None,
               ALL_ROLES, _restricted_session, "mfa-enrollment-required",
               "require_mfa_for_login and not subject.mfa_verified and action not in "
               + str(sorted(x.value for x in RESTRICTED_SESSION_ACTIONS))),
    PolicyRule("guard.download-block",
               "Users flagged by bulk-download detection cannot download until the block expires.",
               "deny", "guard", frozenset({Action.FILE_READ}), ALL_ROLES,
               lambda s, a, r, c, p: bool(c.download_blocked), "download-rate-exceeded",
               "context.download_blocked"),
)

CONSTRAINT_RULES: tuple[PolicyRule, ...] = (
    PolicyRule("constraint.file-ownership",
               "File operations require ownership; a grantee may only read metadata and content.",
               "deny", "constraint", FILE_INSTANCE_ACTIONS, frozenset({Role.USER, Role.AUDITOR}),
               _not_owner_or_grantee, "not-owner", "resource.owner_id != subject.user_id and not shared"),
    PolicyRule("constraint.admin-no-content-access",
               "Separation of duties: administrators cannot read, delete or share files they do not own; "
               "they may only verify, repair and read metadata (no plaintext leaves).",
               "deny", "constraint", FILE_INSTANCE_ACTIONS, frozenset({Role.ADMIN}),
               _admin_content, "admin-no-content-access",
               "role admin, not owner, action not in {file:verify, file:repair, file:read-metadata}"),
    PolicyRule("constraint.classification-required",
               "Classification-checked file actions must state the file's classification (fail closed).",
               "deny", "constraint", CLEARANCE_CHECKED_ACTIONS, ALL_ROLES,
               _classification_missing, "classification-missing", "resource.classification is None"),
    PolicyRule("constraint.clearance",
               "Reading or creating a file above the user's clearance is refused.",
               "deny", "constraint", CLEARANCE_CHECKED_ACTIONS, ALL_ROLES,
               _insufficient_clearance, "insufficient-clearance",
               "resource.classification.rank > subject.clearance.rank"),
    PolicyRule("constraint.mfa-required",
               "Sensitive actions (configurable) and downloads at or above the MFA classification need a "
               "session that passed a second factor.", "deny", "constraint", None, ALL_ROLES,
               _mfa_missing, "mfa-required",
               "action in mfa_required_actions or (file:read and classification >= "
               "mfa_required_classification), and not subject.mfa_verified"),
    PolicyRule("constraint.mfa-fresh",
               "The second factor must have been verified within the step-up window.",
               "deny", "constraint", None, ALL_ROLES, _mfa_stale, "mfa-stale",
               "as above, and mfa_age_seconds > mfa_step_up_max_age_seconds"),
    PolicyRule("constraint.file-committed", "Only fully committed files can be downloaded.",
               "deny", "constraint", frozenset({Action.FILE_READ}), ALL_ROLES,
               _file_unavailable, "file-not-available", "resource.status != 'committed'"),
)

ALLOW_RULES: tuple[PolicyRule, ...] = (
    PolicyRule("allow.user-base",
               "Every role may upload, list its own files, and read its own audit events, dashboard, "
               "storage health, policy and security information.",
               "allow", "allow", USER_BASE_ACTIONS, ALL_ROLES,
               lambda s, a, r, c, p: (a not in (Action.FILE_CREATE, Action.FILE_LIST)) or _is_file(r),
               condition_text="file actions on a 'file' resource"),
    PolicyRule("allow.file-owner", "Owners have full control of their own files.", "allow", "allow",
               OWNER_FILE_ACTIONS, ALL_ROLES, lambda s, a, r, c, p: _is_owner(s, r),
               condition_text="resource.owner_id == subject.user_id"),
    PolicyRule("allow.file-grantee", "A user a file was shared with may read its metadata and content.",
               "allow", "allow", GRANTEE_FILE_ACTIONS, ALL_ROLES,
               lambda s, a, r, c, p: _is_file(r) and r.shared_with_subject,
               condition_text="resource.shared_with_subject"),
    PolicyRule("allow.auditor", "Auditors read and verify the whole audit trail and security posture.",
               "allow", "allow", AUDITOR_ACTIONS, frozenset({Role.AUDITOR}), _always),
    PolicyRule("allow.admin", "Administrators manage users, policy, keys, storage and audit operations.",
               "allow", "allow", ADMIN_ACTIONS, frozenset({Role.ADMIN}), _always),
    PolicyRule("allow.admin-file-integrity",
               "Administrators may verify and repair any file and read its metadata (no plaintext).",
               "allow", "allow", ADMIN_ANY_FILE_ACTIONS, frozenset({Role.ADMIN}),
               lambda s, a, r, c, p: _is_file(r), condition_text="resource.type == 'file'"),
)

ALL_RULES: tuple[PolicyRule, ...] = GUARD_RULES + CONSTRAINT_RULES + ALLOW_RULES


def describe_policies() -> list[dict]:
    """Human-readable list of every rule (for the security-policy UI)."""
    return [rule.describe() for rule in ALL_RULES]


class PolicyDecisionPoint:
    """Default-deny decision function. Stateless apart from the config
    snapshot; safe to share between threads."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self._config = config or PolicyConfig()

    @property
    def config(self) -> PolicyConfig:
        return self._config

    def with_config(self, config: PolicyConfig) -> "PolicyDecisionPoint":
        return PolicyDecisionPoint(config)

    @staticmethod
    def describe_policies() -> list[dict]:
        return describe_policies()

    def evaluate(self, subject: Subject, action: Action, resource: Resource, context: RequestContext,
                 config: PolicyConfig | None = None) -> Decision:
        """Decide. ``config`` overrides the instance snapshot for this call.
        Malformed inputs (unknown action/role/clearance) are denied."""
        cfg = config or self._config
        try:
            action = Action(action)
            subject_ok = isinstance(subject, Subject) and isinstance(subject.role, Role) \
                and isinstance(subject.clearance, Classification) and bool(subject.user_id)
        except (ValueError, TypeError):
            subject_ok = False
        if not subject_ok or not isinstance(resource, Resource) or not isinstance(context, RequestContext):
            return Decision(False, ("invalid-request",), ())

        reasons: list[str] = []
        matched: list[str] = []
        for rule in GUARD_RULES + CONSTRAINT_RULES:
            if rule.applies(subject, action) and rule.condition(subject, action, resource, context, cfg):
                matched.append(rule.id)
                if rule.reason and rule.reason not in reasons:
                    reasons.append(rule.reason)
        allowed_by: list[str] = [
            rule.id for rule in ALLOW_RULES
            if rule.applies(subject, action) and rule.condition(subject, action, resource, context, cfg)
        ]
        matched.extend(allowed_by)

        if allowed_by and not reasons:
            return Decision(True, (), tuple(matched))
        if not allowed_by and not reasons:
            reasons.append("default-deny")

        obligations: list[str] = []
        if "mfa-enrollment-required" in reasons:
            obligations.append(OBLIGATION_ENROLL if not subject.mfa_enrolled else OBLIGATION_STEP_UP)
        elif allowed_by and set(reasons) <= _MFA_REASONS:
            obligations.append(OBLIGATION_STEP_UP)
            if not subject.mfa_enrolled:
                obligations.append(OBLIGATION_ENROLL)
        return Decision(False, tuple(reasons), tuple(matched), tuple(obligations))
