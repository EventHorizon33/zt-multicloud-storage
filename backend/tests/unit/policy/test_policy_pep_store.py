import json

import pytest

from app.contracts import Action, Classification, Outcome, Resource, Role, Severity
from app.errors import AccessDenied, ValidationFailed
from app.models import PolicySetting
from app.policy.config import PolicyConfig, PolicyStore
from app.policy.pdp import PolicyDecisionPoint
from app.policy.pep import PolicyEnforcementPoint
from tests.unit.policy.conftest import OTHER, ctx, file_res, subject


@pytest.fixture
def store(settings, audit, clock):
    return PolicyStore(settings=settings, audit=audit, clock=clock)


@pytest.fixture
def pep(store, audit):
    return PolicyEnforcementPoint(PolicyDecisionPoint(), audit, store)


def test_pep_audits_allow(pep, db, audit):
    d = pep.enforce(db, subject(), Action.FILE_READ, file_res(), ctx())
    assert d.allow
    (e,) = audit.of("authz.decision")
    assert e["outcome"] == Outcome.SUCCESS and e["severity"] == Severity.INFO
    assert e["resource_type"] == "file" and e["resource_id"] == "file-1" and e["action"] == "file:read"
    assert e["details"]["reasons"] == [] and "allow.file-owner" in e["details"]["policies"]
    assert e["actor_id"] == "user-me" and e["request_id"] == "req-1"


def test_pep_audits_and_raises_deny(pep, db, audit):
    with pytest.raises(AccessDenied) as ei:
        pep.enforce(db, subject(Role.ADMIN), Action.FILE_READ, file_res(OTHER), ctx())
    assert ei.value.reasons == ("admin-no-content-access",)
    (e,) = audit.of("authz.decision")
    assert e["outcome"] == Outcome.DENIED and e["severity"] == Severity.WARNING
    assert e["details"]["reasons"] == ["admin-no-content-access"]


def test_pep_deny_carries_obligations(pep, db):
    with pytest.raises(AccessDenied) as ei:
        pep.enforce(db, subject(mfa_verified=False, mfa_age_seconds=None), Action.FILE_DELETE, file_res(), ctx())
    assert ei.value.reasons == ("mfa-required",) and ei.value.obligations == ("step-up-mfa",)


def test_pep_fails_closed_if_audit_fails(pep, db, audit):
    audit.fail = True
    with pytest.raises(RuntimeError):
        pep.enforce(db, subject(), Action.FILE_READ, file_res(), ctx())


def test_check_audits_only_on_request(pep, db, audit):
    assert not pep.check(db, subject(), Action.USER_MANAGE, Resource(type="user"), ctx()).allow
    assert audit.events == []
    pep.check(db, subject(), Action.USER_MANAGE, Resource(type="user"), ctx(), audit=True)
    assert len(audit.of("authz.decision")) == 1


def test_pep_uses_current_stored_policy(pep, store, db):
    s = subject(mfa_verified=False, mfa_age_seconds=None)
    pep.enforce(db, s, Action.FILE_LIST, file_res(), ctx())
    store.update(db, {"require_mfa_for_login": True}, actor_id="admin")
    with pytest.raises(AccessDenied) as ei:
        pep.enforce(db, s, Action.FILE_LIST, file_res(), ctx())
    assert "mfa-enrollment-required" in ei.value.reasons


def test_store_defaults_from_settings(store, db, settings):
    cfg = store.load(db)
    assert cfg == PolicyConfig.from_settings(settings) and store.version(db) == 0
    assert cfg.mfa_step_up_max_age_seconds == settings.mfa_step_up_max_age_seconds
    assert cfg.window_seconds == settings.detect_window_seconds
    assert json.dumps(cfg.to_dict())


def test_store_round_trip_version_and_audit(store, db, audit, settings, clock):
    cfg = store.update(db, {"mfa_step_up_max_age_seconds": 300, "require_mfa_for_login": True,
                            "mfa_required_classification": "restricted",
                            "mfa_required_actions": ["policy:write", "file:share"]}, actor_id="admin-1")
    assert store.version(db) == 1
    fresh = PolicyStore(settings=settings, audit=audit, clock=clock).load(db)
    assert fresh == cfg
    assert fresh.mfa_required_actions == frozenset({Action.POLICY_WRITE, Action.FILE_SHARE})
    assert fresh.mfa_required_classification is Classification.RESTRICTED
    (e,) = audit.of("policy.change")
    ch = e["details"]["changes"]
    assert ch["mfa_step_up_max_age_seconds"] == {"old": 600, "new": 300}
    assert ch["require_mfa_for_login"] == {"old": False, "new": True}
    assert set(ch) == {"mfa_step_up_max_age_seconds", "require_mfa_for_login",
                       "mfa_required_classification", "mfa_required_actions"}
    assert e["actor_id"] == "admin-1" and e["severity"] == Severity.WARNING
    # second update bumps the version and only reports changed keys
    store.update(db, {"mfa_step_up_max_age_seconds": 300, "block_seconds": 60}, actor_id="admin-1")
    assert store.version(db) == 2
    assert set(audit.of("policy.change")[-1]["details"]["changes"]) == {"block_seconds"}
    # no-op update: no version bump, no audit
    store.update(db, {"block_seconds": 60}, actor_id="admin-1")
    assert store.version(db) == 2 and len(audit.of("policy.change")) == 2


@pytest.mark.parametrize("changes,code", [
    ({"nope": 1}, "nope:unknown-key"),
    ({"mfa_step_up_max_age_seconds": 5}, "mfa_step_up_max_age_seconds:out-of-range"),
    ({"mfa_step_up_max_age_seconds": "600"}, "mfa_step_up_max_age_seconds:invalid-type"),
    ({"max_downloads_in_window": True}, "max_downloads_in_window:invalid-type"),
    ({"require_mfa_for_login": "yes"}, "require_mfa_for_login:invalid-type"),
    ({"mfa_required_classification": "top-secret"}, "mfa_required_classification:unknown-classification"),
    ({"mfa_required_actions": ["file:fly", "policy:write"]}, "mfa_required_actions:unknown-action"),
    ({"mfa_required_actions": []}, "mfa_required_actions:below-safety-floor"),
    ({"mfa_required_actions": "policy:write"}, "mfa_required_actions:invalid-type"),
])
def test_store_validation(store, db, audit, changes, code):
    with pytest.raises(ValidationFailed) as ei:
        store.update(db, changes, actor_id="admin")
    assert code in ei.value.reasons
    assert store.version(db) == 0
    assert audit.of("policy.change")[-1]["outcome"] == Outcome.FAILURE


def test_tampered_row_ignored(store, db):
    db.add(PolicySetting(key="mfa_step_up_max_age_seconds", value={"v": 10 ** 9}, version=1))
    db.add(PolicySetting(key="unknown", value={"v": 1}, version=1))
    db.commit()
    cfg, version, ignored = store.load_report(db)
    assert cfg.mfa_step_up_max_age_seconds == 600 and ignored == ("mfa_step_up_max_age_seconds", "unknown")
