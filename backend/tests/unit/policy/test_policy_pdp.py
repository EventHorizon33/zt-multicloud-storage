"""PDP tests. The expected matrix below is written independently from the
rule implementation, straight from the permission model in NOTES.md."""
from dataclasses import replace

import pytest

from app.contracts import Action as A
from app.contracts import Classification as C
from app.contracts import Resource, Role
from app.policy.config import PolicyConfig
from app.policy.pdp import PolicyDecisionPoint, describe_policies
from tests.unit.policy.conftest import ME, OTHER, ctx, file_res, subject

# Most rules below are tested in isolation, without the restricted-session
# guard. Since ADR-0010 ``require_mfa_for_login`` defaults to TRUE (asserted in
# test_require_mfa_for_login_is_the_default), so the module PDP switches it off
# explicitly; the guard itself is tested with the default config.
NO_LOGIN_MFA = PolicyConfig(require_mfa_for_login=False)
pdp = PolicyDecisionPoint(NO_LOGIN_MFA)

FILE_INSTANCE = {A.FILE_READ_METADATA, A.FILE_READ, A.FILE_DELETE, A.FILE_SHARE, A.FILE_VERIFY, A.FILE_REPAIR}
USER_GLOBAL = {A.AUDIT_READ_OWN, A.DASHBOARD_READ, A.STORAGE_READ, A.POLICY_READ, A.SECURITY_READ}
ROLE_GLOBAL = {
    Role.USER: USER_GLOBAL,
    # M1 (external review): auditors work with pseudonyms only, no user:list (user directory)
    Role.AUDITOR: USER_GLOBAL | {A.AUDIT_READ_ALL, A.AUDIT_VERIFY, A.KMS_READ},
    Role.ADMIN: {A.USER_LIST, A.USER_MANAGE, A.POLICY_READ, A.POLICY_WRITE, A.KMS_READ, A.KMS_ROTATE,
                 A.STORAGE_READ, A.STORAGE_ADMIN, A.AUDIT_READ_ALL, A.AUDIT_VERIFY, A.AUDIT_CHECKPOINT,
                 A.AUDIT_RETENTION, A.DASHBOARD_READ, A.SECURITY_READ, A.AUDIT_READ_OWN},
}
RELATIONS = ("owner", "grantee", "other", "system")


def resource_for(rel: str) -> Resource:
    if rel == "owner":
        return file_res(ME)
    if rel == "grantee":
        return file_res(OTHER, shared_with_subject=True)
    if rel == "other":
        return file_res(OTHER)
    return Resource(type="system")


def expected(role: Role, action: A, rel: str) -> tuple[bool, str | None]:
    if action in (A.FILE_CREATE, A.FILE_LIST):
        return (True, None) if rel != "system" else (False, "default-deny")
    if action in FILE_INSTANCE:
        if rel == "system":
            return False, "default-deny"
        if rel == "owner":
            return True, None
        if role is Role.ADMIN and action in {A.FILE_VERIFY, A.FILE_REPAIR, A.FILE_READ_METADATA}:
            return True, None
        if rel == "grantee" and action in {A.FILE_READ_METADATA, A.FILE_READ}:
            return True, None
        return False, "admin-no-content-access" if role is Role.ADMIN else "not-owner"
    return (True, None) if action in ROLE_GLOBAL[role] else (False, "default-deny")


MATRIX = [(r, a, rel) for r in Role for a in A for rel in RELATIONS]


@pytest.mark.parametrize("role,action,rel", MATRIX, ids=[f"{r.value}-{a.value}-{rel}" for r, a, rel in MATRIX])
def test_permission_matrix(role, action, rel):
    d = pdp.evaluate(subject(role), action, resource_for(rel), ctx())
    allow, reason = expected(role, action, rel)
    assert d.allow is allow, d
    if allow:
        assert d.reasons == () and d.matched_policies
    else:
        assert reason in d.reasons, d


def test_matrix_is_exhaustive():
    assert len(MATRIX) == len(Role) * len(A) * len(RELATIONS)


# --- separation of duties: headline property --------------------------------
@pytest.mark.parametrize("action", [A.FILE_READ, A.FILE_DELETE, A.FILE_SHARE])
def test_admin_has_no_content_access_to_other_users_files(action):
    d = pdp.evaluate(subject(Role.ADMIN), action, file_res(OTHER, classification=C.PUBLIC), ctx())
    assert not d.allow and d.reasons == ("admin-no-content-access",)
    assert "constraint.admin-no-content-access" in d.matched_policies
    assert d.obligations == ()        # fresh MFA would not help


@pytest.mark.parametrize("action", [A.FILE_VERIFY, A.FILE_REPAIR, A.FILE_READ_METADATA])
def test_admin_integrity_operations_on_any_file(action):
    assert pdp.evaluate(subject(Role.ADMIN), action, file_res(OTHER), ctx()).allow


def test_admin_reads_own_file():
    assert pdp.evaluate(subject(Role.ADMIN), A.FILE_READ, file_res(ME), ctx()).allow


def test_empty_owner_never_matches():
    assert not pdp.evaluate(subject(user_id="x"), A.FILE_READ, file_res(""), ctx()).allow


# --- guards -----------------------------------------------------------------
def test_inactive_user_denied_everything():
    for a in A:
        d = pdp.evaluate(subject(Role.ADMIN, is_active=False), a, file_res(ME), ctx())
        assert not d.allow and "user-inactive" in d.reasons


@pytest.mark.parametrize("cidrs,ip,allowed", [
    (("10.0.0.0/8",), "10.1.2.3", True),
    (("10.0.0.0/8",), "11.1.2.3", False),
    (("10.0.0.0/8",), None, False),
    (("10.0.0.0/8",), "", False),
    (("10.0.0.0/8",), "not-an-ip", False),
    (("10.0.0.0/8",), "::ffff:10.1.2.3", True),       # IPv4-mapped IPv6
    (("2001:db8::/32",), "2001:db8:1::5", True),
    (("2001:db8::/32",), "2001:db9::5", False),
    (("2001:db8::/32",), "10.1.2.3", False),          # family mismatch
    (("garbage", "192.168.0.0/16"), "192.168.4.4", True),
    (("garbage",), "192.168.4.4", False),
    ((), None, True),                                  # no allow list configured
])
def test_network_allow_list(cidrs, ip, allowed):
    d = pdp.evaluate(subject(allowed_cidrs=cidrs), A.DASHBOARD_READ, Resource(type="system"), ctx(source_ip=ip))
    assert d.allow is allowed
    if not allowed:
        assert d.reasons == ("network-not-allowed",)


def test_session_too_old():
    cfg = PolicyConfig(max_session_age_seconds=3600, require_mfa_for_login=False)
    d = pdp.evaluate(subject(session_age_seconds=3601), A.DASHBOARD_READ, Resource(type="system"), ctx(), cfg)
    assert not d.allow and d.reasons == ("session-too-old",)


def test_download_block_only_affects_file_read():
    d = pdp.evaluate(subject(), A.FILE_READ, file_res(), ctx(download_blocked=True))
    assert not d.allow and d.reasons == ("download-rate-exceeded",)
    assert pdp.evaluate(subject(), A.FILE_READ_METADATA, file_res(), ctx(download_blocked=True)).allow


def test_require_mfa_for_login_is_the_default():
    from app.config import Settings
    assert PolicyConfig().require_mfa_for_login is True
    assert Settings(_env_file=None).require_mfa_for_login is True
    assert PolicyConfig.from_settings(Settings(_env_file=None)).require_mfa_for_login is True
    restricted = subject(mfa_enrolled=False, mfa_verified=False, mfa_age_seconds=None)
    d = PolicyDecisionPoint().evaluate(restricted, A.FILE_LIST, file_res(), ctx())
    assert not d.allow and d.reasons == ("mfa-enrollment-required",)


def test_require_mfa_for_login_restricts_session():
    cfg = PolicyConfig(require_mfa_for_login=True)
    s = subject(mfa_enrolled=False, mfa_verified=False, mfa_age_seconds=None)
    d = pdp.evaluate(s, A.FILE_LIST, file_res(), ctx(), cfg)
    assert not d.allow and "mfa-enrollment-required" in d.reasons and "enroll-mfa" in d.obligations
    assert pdp.evaluate(s, A.SECURITY_READ, Resource(type="system"), ctx(), cfg).allow
    assert pdp.evaluate(s, A.POLICY_READ, Resource(type="system"), ctx(), cfg).allow
    assert pdp.evaluate(subject(), A.FILE_LIST, file_res(), ctx(), cfg).allow
    assert pdp.evaluate(s, A.FILE_LIST, file_res(), ctx()).allow   # switch off -> allowed


# --- constraints ------------------------------------------------------------
@pytest.mark.parametrize("action", [A.FILE_READ, A.FILE_READ_METADATA, A.FILE_CREATE])
def test_insufficient_clearance(action):
    s = subject(clearance=C.INTERNAL)
    d = pdp.evaluate(s, action, file_res(classification=C.CONFIDENTIAL), ctx())
    assert not d.allow and "insufficient-clearance" in d.reasons
    assert pdp.evaluate(s, action, file_res(classification=C.INTERNAL), ctx()).allow


def test_clearance_not_checked_for_delete_or_verify():
    s = subject(clearance=C.PUBLIC)
    assert pdp.evaluate(s, A.FILE_VERIFY, file_res(classification=C.RESTRICTED), ctx()).allow


def test_missing_classification_fails_closed():
    d = pdp.evaluate(subject(), A.FILE_READ, file_res(classification=None), ctx())
    assert not d.allow and "classification-missing" in d.reasons


@pytest.mark.parametrize("action", sorted(PolicyConfig().mfa_required_actions, key=lambda a: a.value))
def test_mfa_required_and_stale_for_sensitive_actions(action):
    role = Role.USER if action.value.startswith("file:") else Role.ADMIN
    res = file_res(ME) if action.value.startswith("file:") else Resource(type="system")
    no_mfa = subject(role, mfa_verified=False, mfa_age_seconds=None)
    d = pdp.evaluate(no_mfa, action, res, ctx())
    assert not d.allow and d.reasons == ("mfa-required",) and d.obligations == ("step-up-mfa",)
    stale = subject(role, mfa_age_seconds=601.0)
    d = pdp.evaluate(stale, action, res, ctx())
    assert not d.allow and d.reasons == ("mfa-stale",) and d.obligations == ("step-up-mfa",)
    assert pdp.evaluate(subject(role, mfa_age_seconds=600.0), action, res, ctx()).allow


def test_mfa_for_download_by_classification():
    no_mfa = subject(mfa_verified=False, mfa_age_seconds=None, mfa_enrolled=False)
    assert pdp.evaluate(no_mfa, A.FILE_READ, file_res(classification=C.INTERNAL), ctx()).allow
    d = pdp.evaluate(no_mfa, A.FILE_READ, file_res(classification=C.CONFIDENTIAL), ctx())
    assert d.reasons == ("mfa-required",) and d.obligations == ("step-up-mfa", "enroll-mfa")
    # metadata of a confidential file does not need MFA
    assert pdp.evaluate(no_mfa, A.FILE_READ_METADATA, file_res(classification=C.CONFIDENTIAL), ctx()).allow
    cfg = PolicyConfig(mfa_required_classification=C.PUBLIC, require_mfa_for_login=False)
    assert not pdp.evaluate(no_mfa, A.FILE_READ, file_res(classification=C.PUBLIC), ctx(), cfg).allow


def test_no_step_up_obligation_when_other_reasons():
    s = subject(mfa_verified=False, mfa_age_seconds=None)
    d = pdp.evaluate(s, A.FILE_DELETE, file_res(OTHER), ctx())
    assert set(d.reasons) == {"not-owner", "mfa-required"} and d.obligations == ()


def test_file_not_available():
    for status in ("pending", "uploading", "failed", "deleting", "deleted", None):
        d = pdp.evaluate(subject(), A.FILE_READ, file_res(status=status), ctx())
        assert not d.allow and d.reasons == ("file-not-available",)


def test_all_deny_reasons_returned():
    s = subject(clearance=C.PUBLIC, mfa_verified=False, mfa_age_seconds=None, allowed_cidrs=("10.0.0.0/8",))
    d = pdp.evaluate(s, A.FILE_READ, file_res(OTHER, classification=C.RESTRICTED, status="pending"),
                     ctx(download_blocked=True))
    assert set(d.reasons) == {"network-not-allowed", "download-rate-exceeded", "not-owner",
                              "insufficient-clearance", "mfa-required", "file-not-available"}
    assert "guard.network-allow-list" in d.matched_policies


def test_unlisted_combination_default_deny():
    d = pdp.evaluate(subject(Role.USER), A.USER_MANAGE, Resource(type="user", id="u2"), ctx())
    assert not d.allow and d.reasons == ("default-deny",) and d.matched_policies == ()


def test_malformed_input_denied():
    assert pdp.evaluate(subject(), "file:explode", file_res(), ctx()).reasons == ("invalid-request",)
    bad = replace(subject(), role="root")
    assert not pdp.evaluate(bad, A.DASHBOARD_READ, Resource(type="system"), ctx()).allow


def test_describe_policies():
    rules = describe_policies()
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    assert {"guard.network-allow-list", "constraint.admin-no-content-access", "allow.admin"} <= set(ids)
    for r in rules:
        assert r["effect"] in ("allow", "deny") and r["description"]
        assert r["effect"] == "allow" or r["reason"]
