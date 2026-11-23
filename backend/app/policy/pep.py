"""Policy Enforcement Point: PDP + audit + raise.

Security properties:
  * Every decision made through ``enforce`` is audited (``authz.decision``)
    BEFORE the result is acted on. If the audit write fails the exception
    propagates, so the operation does not proceed (fail closed).
  * The policy snapshot is loaded from the ``PolicyStore`` per call, so a
    policy change applies to the next request.
"""
from __future__ import annotations

from sqlalchemy.orm import Session as DbSession

from app.contracts import (Action, AuditSink, Decision, Outcome, RequestContext, Resource, Severity,
                           Subject)
from app.errors import AccessDenied
from app.policy.config import PolicyStore
from app.policy.pdp import PolicyDecisionPoint


class PolicyEnforcementPoint:
    def __init__(self, pdp: PolicyDecisionPoint, audit: AuditSink, policy_store: PolicyStore) -> None:
        self._pdp = pdp
        self._audit = audit
        self._store = policy_store

    def _decide(self, db: DbSession, subject: Subject, action: Action, resource: Resource,
                context: RequestContext) -> Decision:
        return self._pdp.evaluate(subject, action, resource, context, self._store.load(db))

    def _record(self, subject: Subject, action: Action, resource: Resource, context: RequestContext,
                decision: Decision) -> None:
        details: dict = {"reasons": list(decision.reasons), "policies": list(decision.matched_policies)}
        if decision.obligations:
            details["obligations"] = list(decision.obligations)
        self._audit.record(
            event_type="authz.decision",
            action=getattr(action, "value", str(action)),
            outcome=Outcome.SUCCESS if decision.allow else Outcome.DENIED,
            actor_id=getattr(subject, "user_id", None),
            actor_role=getattr(getattr(subject, "role", None), "value", None),
            resource_type=getattr(resource, "type", None),
            resource_id=getattr(resource, "id", None),
            reason=decision.reasons[0] if decision.reasons else None,
            severity=Severity.INFO if decision.allow else Severity.WARNING,
            details=details,
            request_id=getattr(context, "request_id", None),
            source_ip=getattr(context, "source_ip", None),
        )

    def enforce(self, db: DbSession, subject: Subject, action: Action, resource: Resource,
                context: RequestContext) -> Decision:
        """Decide, audit, and raise ``AccessDenied(reasons=...)`` on deny (the
        exception also carries ``.decision`` and ``.obligations``).
        Returns the (allowing) Decision so callers can inspect matched policies."""
        decision = self._decide(db, subject, action, resource, context)
        self._record(subject, action, resource, context, decision)
        if not decision.allow:
            exc = AccessDenied("access denied", reasons=decision.reasons)
            exc.decision = decision          # obligations (e.g. "step-up-mfa") for the API layer
            exc.obligations = decision.obligations
            raise exc
        return decision

    def check(self, db: DbSession, subject: Subject, action: Action, resource: Resource,
              context: RequestContext, *, audit: bool = False) -> Decision:
        """Decide without raising (e.g. to filter a list). Audited only when
        ``audit=True``."""
        decision = self._decide(db, subject, action, resource, context)
        if audit:
            self._record(subject, action, resource, context, decision)
        return decision
