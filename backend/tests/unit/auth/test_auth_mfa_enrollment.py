"""MFA enrolment gating (ADR-0010, finding F1) and network allow list on the
auth service itself (finding F2)."""
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.auth.mfa import code_at
from app.auth.service import AuthService
from app.config import Settings
from app.contracts import Outcome, Role, Severity
from app.errors import AccessDenied, AuthenticationError, Conflict
from app.models import MfaEnrollmentCode, User
from tests.unit.auth.conftest import FAST_HASHER, PASSWORD

IP = "203.0.113.7"
DAY = 24 * 3600


def make_user(svc, db, name="alice"):
    return svc.register(db, name, PASSWORD, source_ip=IP)


def denied(fn) -> tuple[str, ...]:
    with pytest.raises(AccessDenied) as ei:
        fn()
    return ei.value.reasons


def test_self_enrolment_inside_the_window(svc, db, clock):
    u = make_user(svc, db)
    clock.advance(DAY - 1)
    enrol = svc.enroll_mfa(db, u)
    svc.activate_mfa(db, u, code_at(enrol.secret, clock()))
    assert u.mfa_enabled


def test_self_enrolment_outside_the_window_needs_approval(svc, db, clock, audit):
    u = make_user(svc, db)
    clock.advance(DAY + 1)
    assert denied(lambda: svc.enroll_mfa(db, u)) == ("mfa-enrollment-requires-approval",)
    e = audit.of("auth.mfa_enroll")[-1]
    assert (e["outcome"], e["reason"], e["severity"]) == (Outcome.DENIED, "mfa-enrollment-requires-approval",
                                                          Severity.WARNING)
    assert db.get(User, u.id).mfa_secret_enc is None


def test_window_is_configurable(tmp_path, kms, audit, clock, db):
    settings = Settings(env="test", data_dir=tmp_path, _env_file=None, mfa_self_enroll_window_seconds=60)
    svc = AuthService(settings=settings, kms=kms, audit=audit, clock=clock, password_hasher=FAST_HASHER)
    u = make_user(svc, db)
    clock.advance(61)
    assert denied(lambda: svc.enroll_mfa(db, u)) == ("mfa-enrollment-requires-approval",)


def test_admin_code_works_once_and_is_stored_only_as_hmac(svc, db, clock):
    u = make_user(svc, db)
    clock.advance(2 * DAY)
    code, expires = svc.issue_mfa_enrollment_code(db, u, issued_by="admin-1")
    db.commit()
    assert expires == clock() + timedelta(seconds=DAY)
    row = db.execute(select(MfaEnrollmentCode)).scalar_one()
    assert code.replace("-", "") not in row.code_hmac and len(row.code_hmac) == 64
    enrol = svc.enroll_mfa(db, u, enrollment_code=code.lower())   # case/format-insensitive
    assert db.get(MfaEnrollmentCode, row.id).used_at is not None
    # single use: a second enrolment with the same code is refused
    assert denied(lambda: svc.enroll_mfa(db, u, enrollment_code=code)) == ("mfa-enrollment-code-invalid",)
    svc.activate_mfa(db, u, code_at(enrol.secret, clock()))
    assert u.mfa_enabled


def test_admin_code_expires_and_is_bound_to_its_user(svc, db, clock):
    alice, bob = make_user(svc, db), make_user(svc, db, "bob")
    clock.advance(2 * DAY)
    code, _ = svc.issue_mfa_enrollment_code(db, alice, issued_by="admin-1")
    db.commit()
    assert denied(lambda: svc.enroll_mfa(db, bob, enrollment_code=code)) == ("mfa-enrollment-code-invalid",)
    clock.advance(DAY + 1)
    assert denied(lambda: svc.enroll_mfa(db, alice, enrollment_code=code)) == ("mfa-enrollment-code-invalid",)
    for garbage in ("not-a-code", "AAAA-AAAA-AAAA-AAA1", "x" * 20):
        assert denied(lambda: svc.enroll_mfa(db, alice, enrollment_code=garbage)) \
            == ("mfa-enrollment-code-invalid",)


def test_new_code_revokes_the_previous_one(svc, db, clock):
    u = make_user(svc, db)
    clock.advance(2 * DAY)
    first, _ = svc.issue_mfa_enrollment_code(db, u, issued_by="admin-1")
    second, _ = svc.issue_mfa_enrollment_code(db, u, issued_by="admin-1")
    db.commit()
    assert denied(lambda: svc.enroll_mfa(db, u, enrollment_code=first)) == ("mfa-enrollment-code-invalid",)
    svc.enroll_mfa(db, u, enrollment_code=second)


def test_window_does_not_reopen_after_disable_or_reset(svc, db, clock):
    u = make_user(svc, db)
    enrol = svc.enroll_mfa(db, u)
    svc.activate_mfa(db, u, code_at(enrol.secret, clock()))
    clock.advance(30)
    svc.disable_mfa(db, u, code_at(enrol.secret, clock()))
    # still inside 24 h of registration, but the account HAD a factor
    assert denied(lambda: svc.enroll_mfa(db, u)) == ("mfa-enrollment-requires-approval",)


def test_reenrolment_needs_a_code_from_the_current_factor(svc, db, clock, audit):
    u = make_user(svc, db)
    enrol = svc.enroll_mfa(db, u)
    svc.activate_mfa(db, u, code_at(enrol.secret, clock()))
    clock.advance(30)
    with pytest.raises(Conflict) as ei:
        svc.enroll_mfa(db, u)
    assert ei.value.reasons == ("mfa-already-enabled",)
    with pytest.raises(AuthenticationError):
        svc.enroll_mfa(db, u, current_code="000000" if code_at(enrol.secret, clock()) != "000000" else "111111")
    assert db.get(User, u.id).failed_login_count == 1                     # counts towards lockout
    new = svc.enroll_mfa(db, u, current_code=code_at(enrol.secret, clock()))
    # until the new factor is proven, the old one still logs in
    clock.advance(30)
    assert svc.login(db, "alice", PASSWORD, code_at(enrol.secret, clock())).mfa_verified
    svc.activate_mfa(db, u, code_at(new.secret, clock()))
    clock.advance(30)
    with pytest.raises(AuthenticationError):
        svc.login(db, "alice", PASSWORD, code_at(enrol.secret, clock()))
    assert svc.login(db, "alice", PASSWORD, code_at(new.secret, clock())).mfa_verified
    assert audit.of("auth.mfa_activate")[-1]["details"]["method"] == "rotation"


def test_pending_enrolment_expires(svc, db, clock, settings):
    u = make_user(svc, db)
    enrol = svc.enroll_mfa(db, u)
    clock.advance(settings.mfa_pending_enrollment_ttl_seconds + 1)
    with pytest.raises(Conflict) as ei:
        svc.activate_mfa(db, u, code_at(enrol.secret, clock()))
    assert ei.value.reasons == ("mfa-enrollment-expired",)
    assert not db.get(User, u.id).mfa_enabled and db.get(User, u.id).mfa_secret_enc is None


def test_bootstrap_admin_may_enrol_outside_the_window(tmp_path, kms, audit, clock, db):
    settings = Settings(env="test", data_dir=tmp_path, _env_file=None, bootstrap_admin_username="root")
    svc = AuthService(settings=settings, kms=kms, audit=audit, clock=clock, password_hasher=FAST_HASHER)
    admin = svc.ensure_bootstrap_admin(db, "root", PASSWORD + "-admin")
    clock.advance(30 * DAY)
    enrol = svc.enroll_mfa(db, admin)
    svc.activate_mfa(db, admin, code_at(enrol.secret, clock()))
    assert admin.mfa_enabled and audit.of("auth.mfa_activate")[-1]["details"]["method"] == "bootstrap"
    # an ordinary admin (not the bootstrap account) gets no such exception
    other = make_user(svc, db, "second-admin")
    other.role = Role.ADMIN.value
    db.commit()
    clock.advance(DAY + 1)
    assert denied(lambda: svc.enroll_mfa(db, other)) == ("mfa-enrollment-requires-approval",)


def test_bootstrap_exception_closes_once_another_admin_holds_a_factor(tmp_path, kms, audit, clock, db):
    """The bootstrap exception exists because nobody could issue the first
    admin a code. Once another active admin has MFA, that is no longer true."""
    settings = Settings(env="test", data_dir=tmp_path, _env_file=None, bootstrap_admin_username="root")
    svc = AuthService(settings=settings, kms=kms, audit=audit, clock=clock, password_hasher=FAST_HASHER)
    admin = svc.ensure_bootstrap_admin(db, "root", PASSWORD + "-admin")
    other = make_user(svc, db, "second-admin")
    enrol = svc.enroll_mfa(db, other)                       # TOFU window
    svc.activate_mfa(db, other, code_at(enrol.secret, clock()))
    other.role = Role.ADMIN.value
    db.commit()
    clock.advance(30 * DAY)
    assert denied(lambda: svc.enroll_mfa(db, admin)) == ("mfa-enrollment-requires-approval",)
    other.is_active = False                                 # no usable admin with a factor -> open again
    db.commit()
    assert svc.enroll_mfa(db, admin).secret


def test_reset_mfa_clears_the_factor_and_keeps_the_window_closed(svc, db, clock):
    u = make_user(svc, db)
    enrol = svc.enroll_mfa(db, u)
    svc.activate_mfa(db, u, code_at(enrol.secret, clock()))
    assert svc.reset_mfa(db, u) is True
    db.commit()
    assert not u.mfa_enabled and u.mfa_secret_enc is None
    assert denied(lambda: svc.enroll_mfa(db, u)) == ("mfa-enrollment-requires-approval",)


# ---------------------------------------------------------------- F2
def _restrict(db, user, cidrs):
    user.allowed_cidrs = cidrs
    db.commit()


def test_login_outside_allow_list_is_generic_401_and_not_counted(svc, db, audit, settings):
    u = make_user(svc, db)
    _restrict(db, u, ["10.20.0.0/16"])
    for _ in range(settings.max_failed_logins + 2):
        with pytest.raises(AuthenticationError) as ei:
            svc.login(db, "alice", PASSWORD, source_ip=IP)
        assert ei.value.reasons == ()
    assert db.get(User, u.id).failed_login_count == 0 and db.get(User, u.id).locked_until is None
    assert audit.of("auth.login")[-1]["reason"] == "network-not-allowed"
    assert svc.login(db, "alice", PASSWORD, source_ip="10.20.1.1").access_token     # owner not locked out


def test_refresh_outside_allow_list_is_refused_without_consuming(svc, db):
    u = make_user(svc, db)
    _restrict(db, u, ["10.20.0.0/16"])
    r = svc.login(db, "alice", PASSWORD, source_ip="10.20.1.1")
    with pytest.raises(AuthenticationError):
        svc.refresh(db, r.refresh_token, source_ip=IP)
    assert svc.refresh(db, r.refresh_token, source_ip="10.20.1.1").access_token


def test_account_management_outside_allow_list_is_403(svc, db, audit):
    u = make_user(svc, db)
    _restrict(db, u, ["10.20.0.0/16"])
    assert denied(lambda: svc.change_password(db, u, PASSWORD, "Another-Long-Passw0rd!", source_ip=IP)) \
        == ("network-not-allowed",)
    assert denied(lambda: svc.enroll_mfa(db, u, source_ip=IP)) == ("network-not-allowed",)
    assert denied(lambda: svc.activate_mfa(db, u, "123456", source_ip=IP)) == ("network-not-allowed",)
    assert audit.of("auth.password_change")[-1]["reason"] == "network-not-allowed"
