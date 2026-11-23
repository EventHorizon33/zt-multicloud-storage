"""Runtime policy parameters (``PolicyConfig``) and their persistence
(``PolicyStore``, table ``policy_settings``).

Security properties:
  * Every value is validated (type and range) before it is stored; unknown
    keys are rejected. A safety floor keeps ``policy:write`` itself behind
    fresh MFA so policy cannot be loosened by a password-only session.
  * Every successful change bumps the policy version and is audited as
    ``policy.change`` with the old and new values of the changed keys only.
  * Stored rows that no longer validate (e.g. edited directly in the DB) are
    ignored and the built-in default is used for that key; this is reported
    via ``PolicyStore.load_report``.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.config import Settings
from app.contracts import Action, AuditSink, Classification, Outcome, Severity
from app.errors import ValidationFailed
from app.models import PolicySetting

Clock = Callable[[], datetime]

DEFAULT_MFA_REQUIRED_ACTIONS: frozenset[Action] = frozenset({
    Action.FILE_DELETE, Action.FILE_SHARE, Action.USER_MANAGE, Action.POLICY_WRITE,
    Action.KMS_ROTATE, Action.AUDIT_RETENTION, Action.STORAGE_ADMIN,
})
#: Actions that can never be removed from ``mfa_required_actions``.
MFA_FLOOR_ACTIONS: frozenset[Action] = frozenset({Action.POLICY_WRITE})


@dataclass(frozen=True)
class PolicyConfig:
    """Immutable snapshot of adjustable policy parameters. Defaults mirror
    ``Settings`` defaults; use ``PolicyConfig.from_settings`` in the app."""
    mfa_required_actions: frozenset[Action] = field(default_factory=lambda: DEFAULT_MFA_REQUIRED_ACTIONS)
    mfa_required_classification: Classification = Classification.CONFIDENTIAL
    mfa_step_up_max_age_seconds: int = 600
    max_session_age_seconds: int = 12 * 3600
    require_mfa_for_login: bool = True        # ADR-0010: password-only sessions are restricted
    max_downloads_in_window: int = 20
    max_download_bytes_in_window: int = 512 * 1024 * 1024
    window_seconds: int = 300
    block_seconds: int = 600

    @classmethod
    def from_settings(cls, settings: Settings) -> "PolicyConfig":
        return cls(
            mfa_step_up_max_age_seconds=int(settings.mfa_step_up_max_age_seconds),
            max_session_age_seconds=int(settings.session_absolute_ttl_seconds),
            require_mfa_for_login=bool(settings.require_mfa_for_login),
            max_downloads_in_window=int(settings.detect_max_downloads_in_window),
            max_download_bytes_in_window=int(settings.detect_max_download_bytes_in_window),
            window_seconds=int(settings.detect_window_seconds),
            block_seconds=int(settings.detect_block_seconds),
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation (for the API / policy UI / audit)."""
        out = asdict(self)
        out["mfa_required_actions"] = sorted(a.value for a in self.mfa_required_actions)
        out["mfa_required_classification"] = self.mfa_required_classification.value
        return out


POLICY_KEYS: tuple[str, ...] = tuple(f.name for f in fields(PolicyConfig))

# (min, max) inclusive for integer parameters
_INT_RANGES: dict[str, tuple[int, int]] = {
    "mfa_step_up_max_age_seconds": (30, 24 * 3600),
    "max_session_age_seconds": (300, 30 * 24 * 3600),
    "max_downloads_in_window": (1, 1_000_000),
    "max_download_bytes_in_window": (1, 1 << 50),
    "window_seconds": (10, 7 * 24 * 3600),
    "block_seconds": (0, 30 * 24 * 3600),
}


def _validate_value(key: str, value: Any) -> Any:
    """Return the typed value for ``key`` or raise ValueError(reason code)."""
    if key == "mfa_required_actions":
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise ValueError("invalid-type")
        try:
            actions = frozenset(Action(v) for v in value)
        except ValueError:
            raise ValueError("unknown-action") from None
        if not MFA_FLOOR_ACTIONS <= actions:
            raise ValueError("below-safety-floor")
        return actions
    if key == "mfa_required_classification":
        try:
            return Classification(value)
        except ValueError:
            raise ValueError("unknown-classification") from None
    if key == "require_mfa_for_login":
        if not isinstance(value, bool):
            raise ValueError("invalid-type")
        return value
    if key in _INT_RANGES:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError("invalid-type")
        lo, hi = _INT_RANGES[key]
        if not lo <= value <= hi:
            raise ValueError("out-of-range")
        return value
    raise ValueError("unknown-key")


def _jsonable(value: Any) -> Any:
    if isinstance(value, frozenset):
        return sorted(v.value if hasattr(v, "value") else v for v in value)
    if isinstance(value, Classification):
        return value.value
    return value


def validate_changes(changes: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a partial update. Raises ``ValidationFailed`` whose reasons
    are ``"<key>:<code>"`` (codes: unknown-key, invalid-type, out-of-range,
    unknown-action, unknown-classification, below-safety-floor)."""
    if not isinstance(changes, Mapping) or not changes:
        raise ValidationFailed("no policy changes", reasons=("empty-change",))
    typed: dict[str, Any] = {}
    errors: list[str] = []
    for key, value in changes.items():
        if key not in POLICY_KEYS:
            errors.append(f"{str(key)[:64]}:unknown-key")
            continue
        try:
            typed[key] = _validate_value(key, value)
        except ValueError as exc:
            errors.append(f"{key}:{exc.args[0]}")
    if errors:
        raise ValidationFailed("invalid policy settings", reasons=tuple(errors))
    return typed


class PolicyStore:
    """Loads/saves ``PolicyConfig`` in ``policy_settings`` (one row per key,
    ``value = {"v": <json>}``). The policy version is the highest row version."""

    def __init__(self, *, settings: Settings, audit: AuditSink, clock: Clock) -> None:
        self._defaults = PolicyConfig.from_settings(settings)
        self._audit = audit
        self._clock = clock

    @property
    def defaults(self) -> PolicyConfig:
        return self._defaults

    @staticmethod
    def _rows(db: DbSession) -> dict[str, PolicySetting]:
        rows = db.execute(select(PolicySetting).execution_options(populate_existing=True)).scalars()
        return {r.key: r for r in rows}

    def load_report(self, db: DbSession) -> tuple[PolicyConfig, int, tuple[str, ...]]:
        """(config, version, keys whose stored value was invalid and ignored)."""
        rows = self._rows(db)
        overrides: dict[str, Any] = {}
        ignored: list[str] = []
        for key, row in rows.items():
            if key not in POLICY_KEYS:
                ignored.append(key)
                continue
            raw = row.value.get("v") if isinstance(row.value, dict) else None
            try:
                overrides[key] = _validate_value(key, raw)
            except ValueError:
                ignored.append(key)
        version = max((r.version for r in rows.values()), default=0)
        return replace(self._defaults, **overrides), version, tuple(sorted(ignored))

    def load(self, db: DbSession) -> PolicyConfig:
        """Current effective policy (defaults overlaid with stored values)."""
        return self.load_report(db)[0]

    def version(self, db: DbSession) -> int:
        return self.load_report(db)[1]

    def update(self, db: DbSession, changes: Mapping[str, Any], *, actor_id: str | None,
               actor_role: str | None = None, request_id: str | None = None,
               source_ip: str | None = None) -> PolicyConfig:
        """Validate and apply a partial update, bump the version, audit
        ``policy.change`` (warning) with old/new values of changed keys, commit.
        Authorisation (``policy:write`` + fresh MFA) is the caller's PEP job.
        A no-op update (all values equal) changes nothing and is not audited."""
        try:
            typed = validate_changes(changes)
        except ValidationFailed as exc:
            self._audit.record(event_type="policy.change", action=Action.POLICY_WRITE.value,
                               outcome=Outcome.FAILURE, actor_id=actor_id, actor_role=actor_role,
                               resource_type="policy", reason="validation-failed",
                               severity=Severity.WARNING, details={"reasons": list(exc.reasons)},
                               request_id=request_id, source_ip=source_ip)
            raise
        current, version, _ = self.load_report(db)
        diff = {k: {"old": _jsonable(getattr(current, k)), "new": _jsonable(v)}
                for k, v in typed.items() if getattr(current, k) != v}
        if not diff:
            return current
        new_version = version + 1
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return an aware datetime")
        rows = self._rows(db)
        try:
            for key in diff:
                value = {"v": _jsonable(typed[key])}
                row = rows.get(key)
                if row is None:
                    db.add(PolicySetting(key=key, value=value, version=new_version,
                                         updated_at=now.astimezone(timezone.utc), updated_by=actor_id))
                else:
                    row.value = value
                    row.version = new_version
                    row.updated_at = now.astimezone(timezone.utc)
                    row.updated_by = actor_id
            db.flush()
            self._audit.record(event_type="policy.change", action=Action.POLICY_WRITE.value,
                               outcome=Outcome.SUCCESS, actor_id=actor_id, actor_role=actor_role,
                               resource_type="policy", resource_id=str(new_version),
                               severity=Severity.WARNING,
                               details={"changes": diff, "version": new_version},
                               request_id=request_id, source_ip=source_ip)
            db.commit()
        except Exception:
            db.rollback()
            raise
        return replace(current, **typed)
