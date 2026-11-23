import json

import pytest
from sqlalchemy import select

from app.auth.mfa import code_at
from app.auth.service import AuthService
from app.contracts import Classification, Outcome, Role, Severity
from app.errors import AuthenticationError, Conflict, ValidationFailed
from app.models import RefreshToken, Session, User
from tests.unit.auth.conftest import FAST_HASHER, PASSWORD

IP = "203.0.113.7"


def reasons(fn):
    with pytest.raises(AuthenticationError) as ei:
        fn()
    return ei.value.reasons


def make_user(svc, db, name="alice", pw=PASSWORD):
    return svc.register(db, name, pw, source_ip=IP)


def enable_mfa(svc, db, clock, user):
    enrol = svc.enroll_mfa(db, user)
    svc.activate_mfa(db, user, code_at(enrol.secret, clock()))
    clock.advance(30)  # move past the step consumed by activation
    return enrol.secret


# ---------------------------------------------------------------- register
def test_register_always_user_role_and_validates(svc, db, audit):
    u = make_user(svc, db)
    assert u.role == "user" and u.password_hash.startswith("$argon2id$")
    with pytest.raises(Conflict):
        make_user(svc, db, name="ALICE")
    for bad in ("ab", "a" * 65, "bad name", "x/../y", "émile"):
        with pytest.raises(ValidationFailed):
            svc.register(db, bad, PASSWORD)
    with pytest.raises(ValidationFailed) as ei:
        svc.register(db, "bob", "bob-password-1")
    assert "password-contains-username" in ei.value.reasons
    assert [e["outcome"] for e in audit.of("auth.register")][0] == Outcome.SUCCESS


def test_bootstrap_admin_is_idempotent(svc, db):
    a = svc.ensure_bootstrap_admin(db, "root-admin", PASSWORD)
    assert a.role == "admin"
    again = svc.ensure_bootstrap_admin(db, "root-admin", "different-password-99")
    assert again.id == a.id and FAST_HASHER.verify(again.password_hash, PASSWORD)


# ---------------------------------------------------------------- login
def test_login_success_and_authenticate(svc, db, audit):
    u = make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD, None, IP)
    assert r.user.id == u.id and r.expires_in == 300 and not r.mfa_verified
    p = svc.authenticate_request(db, r.access_token, IP)
    assert p.user.id == u.id and p.session.id == r.session.id
    assert p.subject.role is Role.USER and p.subject.clearance is Classification.CONFIDENTIAL
    assert p.subject.mfa_verified is False and p.subject.session_id == r.session.id
    ok = [e for e in audit.of("auth.login") if e["outcome"] == Outcome.SUCCESS]
    assert ok and ok[0]["actor_id"] == u.id


def test_unknown_user_and_wrong_password_identical(svc, db, audit):
    make_user(svc, db)
    with pytest.raises(AuthenticationError) as e1:
        svc.login(db, "nobody", PASSWORD, None, IP)
    with pytest.raises(AuthenticationError) as e2:
        svc.login(db, "alice", "wrong-password-xyz", None, IP)
    assert type(e1.value) is type(e2.value)
    assert str(e1.value) == str(e2.value) and e1.value.reasons == e2.value.reasons == ()
    unknown = [e for e in audit.of("auth.login") if e["outcome"] == Outcome.FAILURE][0]
    assert unknown["actor_id"] is None and unknown["details"] == {"reason": "bad-credentials"}


def test_lockout_and_recovery(svc, db, clock, audit, settings):
    make_user(svc, db)
    for _ in range(settings.max_failed_logins):
        reasons(lambda: svc.login(db, "alice", "wrong-password-xyz", None, IP))
    lock = audit.of("auth.lockout")
    assert len(lock) == 1 and lock[0]["severity"] == Severity.WARNING
    # correct password refused while locked, with the same generic error
    assert reasons(lambda: svc.login(db, "alice", PASSWORD, None, IP)) == ()
    clock.advance(settings.lockout_seconds - 1)
    reasons(lambda: svc.login(db, "alice", PASSWORD, None, IP))
    clock.advance(2)
    assert svc.login(db, "alice", PASSWORD, None, IP).access_token
    u = db.execute(select(User)).scalar_one()
    assert u.failed_login_count == 0 and u.locked_until is None


def test_failure_counter_resets_on_success(svc, db, settings):
    make_user(svc, db)
    for _ in range(settings.max_failed_logins - 1):
        reasons(lambda: svc.login(db, "alice", "wrong-password-xyz"))
    svc.login(db, "alice", PASSWORD)
    for _ in range(settings.max_failed_logins - 1):
        reasons(lambda: svc.login(db, "alice", "wrong-password-xyz"))
    assert svc.login(db, "alice", PASSWORD).access_token


def test_disabled_user_cannot_login(svc, db):
    u = make_user(svc, db)
    u.is_active = False
    db.commit()
    assert reasons(lambda: svc.login(db, "alice", PASSWORD)) == ()


# ---------------------------------------------------------------- MFA
def test_login_requires_totp_when_enabled(svc, db, clock, audit):
    u = make_user(svc, db)
    seed = enable_mfa(svc, db, clock, u)
    assert u.mfa_secret_enc and seed.encode() not in u.mfa_secret_enc
    assert reasons(lambda: svc.login(db, "alice", PASSWORD, None, IP)) == ("mfa-required",)
    assert reasons(lambda: svc.login(db, "alice", PASSWORD, "000000", IP)) == ("mfa-invalid",)
    r = svc.login(db, "alice", PASSWORD, code_at(seed, clock()), IP)
    assert r.mfa_verified
    p = svc.authenticate_request(db, r.access_token, IP)
    assert p.subject.mfa_verified and p.subject.mfa_age_seconds == 0
    clock.advance(100)
    assert svc.authenticate_request(db, r.access_token, IP).subject.mfa_age_seconds == 100


def test_wrong_password_does_not_reveal_mfa_state(svc, db, clock):
    u = make_user(svc, db)
    enable_mfa(svc, db, clock, u)
    assert reasons(lambda: svc.login(db, "alice", "wrong-password-xyz", None)) == ()


def test_totp_replay_rejected(svc, db, clock):
    u = make_user(svc, db)
    seed = enable_mfa(svc, db, clock, u)
    code = code_at(seed, clock())
    svc.login(db, "alice", PASSWORD, code, IP)
    assert reasons(lambda: svc.login(db, "alice", PASSWORD, code, IP)) == ("mfa-invalid",)
    assert db.get(User, u.id).mfa_last_counter is not None


def test_activation_requires_valid_code_and_activation_code_cannot_be_replayed(svc, db, clock):
    u = make_user(svc, db)
    enrol = svc.enroll_mfa(db, u)
    with pytest.raises(AuthenticationError):
        svc.activate_mfa(db, u, "123456" if code_at(enrol.secret, clock()) != "123456" else "654321")
    assert not u.mfa_enabled
    code = code_at(enrol.secret, clock())
    svc.activate_mfa(db, u, code)
    assert u.mfa_enabled
    assert reasons(lambda: svc.login(db, "alice", PASSWORD, code)) == ("mfa-invalid",)
    with pytest.raises(Conflict):
        svc.enroll_mfa(db, u)   # cannot swap the factor without disabling it first


def test_activate_mfa_does_not_grant_mfa_or_revoke_other_sessions(svc, db, clock, audit):
    """ADR-0010 / F1: whoever activates a factor proved only the password, so
    activation neither stamps the current session nor kicks out the others."""
    u = make_user(svc, db)
    a = svc.login(db, "alice", PASSWORD)
    b = svc.login(db, "alice", PASSWORD)
    enrol = svc.enroll_mfa(db, u)
    svc.activate_mfa(db, u, code_at(enrol.secret, clock()), session=a.session)
    assert u.mfa_enabled
    assert not svc.authenticate_request(db, a.access_token).subject.mfa_verified
    assert not svc.authenticate_request(db, b.access_token).subject.mfa_verified   # still alive
    e = audit.of("auth.mfa_activate")[-1]
    assert (e["outcome"], e["reason"], e["severity"]) == (Outcome.SUCCESS, "new-factor", Severity.WARNING)
    clock.advance(30)
    svc.verify_mfa_step_up(db, a.session, code_at(enrol.secret, clock()))   # proof with the factor
    assert svc.authenticate_request(db, a.access_token).subject.mfa_verified


def test_step_up_sets_mfa_verified_at(svc, db, clock, audit):
    u = make_user(svc, db)
    seed = enable_mfa(svc, db, clock, u)
    r = svc.login(db, "alice", PASSWORD, code_at(seed, clock()))
    clock.advance(1200)
    r = svc.refresh(db, r.refresh_token)
    assert svc.authenticate_request(db, r.access_token).subject.mfa_age_seconds == 1200
    reasons(lambda: svc.verify_mfa_step_up(db, r.session, "000000"))
    svc.verify_mfa_step_up(db, r.session, code_at(seed, clock()))
    assert svc.authenticate_request(db, r.access_token).subject.mfa_age_seconds == 0
    outcomes = [e["outcome"] for e in audit.of("auth.mfa_verify")]
    assert Outcome.SUCCESS in outcomes and Outcome.FAILURE in outcomes


def test_step_up_bruteforce_locks_and_revokes(svc, db, clock, settings):
    u = make_user(svc, db)
    seed = enable_mfa(svc, db, clock, u)
    r = svc.login(db, "alice", PASSWORD, code_at(seed, clock()))
    good = code_at(seed, clock(), step_offset=1)
    bad = "000000" if good != "000000" else "111111"
    for _ in range(settings.max_failed_logins):
        reasons(lambda: svc.verify_mfa_step_up(db, r.session, bad))
    assert reasons(lambda: svc.authenticate_request(db, r.access_token)) == ("session-revoked",)


def test_disable_mfa_requires_code(svc, db, clock):
    u = make_user(svc, db)
    seed = enable_mfa(svc, db, clock, u)
    reasons(lambda: svc.disable_mfa(db, u, "abcdef"))
    assert u.mfa_enabled
    svc.disable_mfa(db, u, code_at(seed, clock()))
    assert not u.mfa_enabled and u.mfa_secret_enc is None
    assert svc.login(db, "alice", PASSWORD).access_token


# ---------------------------------------------------------------- sessions
def test_token_for_revoked_session(svc, db, audit):
    make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    assert svc.logout(db, r.session.id)
    assert reasons(lambda: svc.authenticate_request(db, r.access_token)) == ("session-revoked",)
    assert reasons(lambda: svc.refresh(db, r.refresh_token)) == ("session-revoked",)
    assert audit.of("auth.logout")


def test_expired_access_token(svc, db, clock):
    make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    clock.advance(300)
    assert reasons(lambda: svc.authenticate_request(db, r.access_token)) == ("token-expired",)


def test_idle_expired_session(svc, db, clock, settings):
    make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    for _ in range(3):                       # activity keeps it alive
        clock.advance(250)
        svc.authenticate_request(db, svc.tokens.issue_access_token(user_id=r.user.id, session_id=r.session.id)[0])
    clock.advance(settings.session_idle_ttl_seconds + 1)
    tok = svc.tokens.issue_access_token(user_id=r.user.id, session_id=r.session.id)[0]
    assert reasons(lambda: svc.authenticate_request(db, tok)) == ("session-idle-expired",)
    assert db.get(Session, r.session.id).revoke_reason == "idle-timeout"
    assert reasons(lambda: svc.refresh(db, r.refresh_token)) in (("session-revoked",), ("refresh-expired",))


def test_absolute_session_expiry(svc, db, clock, settings):
    make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    rt = r.refresh_token
    elapsed = 0
    while elapsed < settings.session_absolute_ttl_seconds:
        clock.advance(1500); elapsed += 1500
        try:
            rt = svc.refresh(db, rt).refresh_token
        except AuthenticationError as exc:
            assert exc.reasons[0] in ("session-expired", "refresh-expired", "session-revoked")
            break
    else:
        pytest.fail("session outlived its absolute lifetime")


def test_disabled_user_mid_session(svc, db):
    u = make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    svc.authenticate_request(db, r.access_token)
    # an admin disables the account in another DB session
    other = type(db)(bind=db.get_bind())
    other.get(User, u.id).is_active = False
    other.commit(); other.close()
    assert reasons(lambda: svc.authenticate_request(db, r.access_token)) == ("user-disabled",)


def test_role_change_takes_effect_without_relogin(svc, db):
    u = make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    assert svc.authenticate_request(db, r.access_token).subject.role is Role.USER
    other = type(db)(bind=db.get_bind())
    row = other.get(User, u.id)
    row.role, row.clearance, row.allowed_cidrs = "auditor", "restricted", ["10.0.0.0/8"]
    other.commit(); other.close()
    s = svc.authenticate_request(db, r.access_token).subject
    assert s.role is Role.AUDITOR and s.clearance is Classification.RESTRICTED
    assert s.allowed_cidrs == ("10.0.0.0/8",)


def test_invalid_role_in_db_fails_closed(svc, db):
    u = make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    u.role = "superuser"; db.commit()
    assert reasons(lambda: svc.authenticate_request(db, r.access_token)) == ("user-state-invalid",)


def test_token_for_other_users_session_rejected(svc, db):
    make_user(svc, db); make_user(svc, db, name="bob")
    a = svc.login(db, "alice", PASSWORD)
    b = svc.login(db, "bob", PASSWORD)
    forged = svc.tokens.issue_access_token(user_id=b.user.id, session_id=a.session.id)[0]
    assert reasons(lambda: svc.authenticate_request(db, forged)) == ("session-not-found",)


def test_ip_binding(settings, kms, audit, clock, db):
    settings.bind_session_to_ip = True
    svc = AuthService(settings=settings, kms=kms, audit=audit, clock=clock, password_hasher=FAST_HASHER)
    make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD, None, IP)
    assert db.get(Session, r.session.id).ip_hash and IP not in db.get(Session, r.session.id).ip_hash
    svc.authenticate_request(db, r.access_token, IP)
    svc.authenticate_request(db, r.access_token, "::ffff:" + IP)
    assert reasons(lambda: svc.authenticate_request(db, r.access_token, "198.51.100.1")) == ("ip-mismatch",)
    assert reasons(lambda: svc.authenticate_request(db, r.access_token, None)) == ("ip-mismatch",)


# ---------------------------------------------------------------- refresh
def test_refresh_rotation_and_reuse_detection(svc, db, audit):
    make_user(svc, db)
    r1 = svc.login(db, "alice", PASSWORD)
    stored = db.execute(select(RefreshToken)).scalars().all()
    assert all(r1.refresh_token not in t.token_hash for t in stored)
    r2 = svc.refresh(db, r1.refresh_token)
    assert r2.refresh_token != r1.refresh_token and r2.session.id == r1.session.id
    svc.authenticate_request(db, r2.access_token)
    # attacker replays the old token -> whole session revoked
    assert reasons(lambda: svc.refresh(db, r1.refresh_token)) == ("refresh-reuse",)
    assert db.get(Session, r1.session.id).revoke_reason == "refresh-reuse"
    assert reasons(lambda: svc.authenticate_request(db, r2.access_token)) == ("session-revoked",)
    assert reasons(lambda: svc.refresh(db, r2.refresh_token)) == ("session-revoked",)
    ev = audit.of("auth.refresh_reuse")
    assert len(ev) == 1 and ev[0]["severity"] == Severity.CRITICAL and ev[0]["actor_id"] == r1.user.id


def test_refresh_unknown_and_expired(svc, db, clock, settings):
    make_user(svc, db)
    r = svc.login(db, "alice", PASSWORD)
    assert reasons(lambda: svc.refresh(db, "not-a-real-token")) == ("refresh-invalid",)
    assert reasons(lambda: svc.refresh(db, "")) == ("refresh-invalid",)
    clock.advance(settings.refresh_token_ttl_seconds)
    assert reasons(lambda: svc.refresh(db, r.refresh_token)) == ("refresh-expired",)


# ---------------------------------------------------------------- password change & session mgmt
def test_change_password_revokes_other_sessions(svc, db, clock, audit):
    u = make_user(svc, db)
    other = svc.login(db, "alice", PASSWORD)                 # password-only session
    secret = enable_mfa(svc, db, clock, u)
    keep = svc.login(db, "alice", PASSWORD, code_at(secret, clock()))   # MFA-verified now
    new_pw = "violet-gravity-mango-77"
    with pytest.raises(AuthenticationError):
        svc.change_password(db, u, "wrong-password-xyz", new_pw, keep_session_id=keep.session.id)
    with pytest.raises(ValidationFailed):
        svc.change_password(db, u, PASSWORD, "short", keep_session_id=keep.session.id)
    assert svc.change_password(db, u, PASSWORD, new_pw, keep_session_id=keep.session.id) == 1
    svc.authenticate_request(db, keep.access_token)
    assert reasons(lambda: svc.authenticate_request(db, other.access_token)) == ("session-revoked",)
    clock.advance(30)
    reasons(lambda: svc.login(db, "alice", PASSWORD, code_at(secret, clock())))
    clock.advance(30)
    assert svc.login(db, "alice", new_pw, code_at(secret, clock())).access_token
    assert any(e["outcome"] == Outcome.SUCCESS for e in audit.of("auth.password_change"))


def test_change_password_needs_fresh_mfa_and_fails_closed_without_a_session(svc, db, clock, audit, settings):
    """H1/M5 at the service level: no session -> refused; no factor -> refused
    (enroll-mfa); stale factor -> mfa-stale (step-up-mfa)."""
    from app.errors import AccessDenied
    u = make_user(svc, db)
    plain = svc.login(db, "alice", PASSWORD)
    with pytest.raises(AccessDenied) as e:
        svc.change_password(db, u, PASSWORD, "violet-gravity-mango-77")
    assert e.value.reasons == ("mfa-required",)
    with pytest.raises(AccessDenied) as e:
        svc.change_password(db, u, PASSWORD, "violet-gravity-mango-77", keep_session_id=plain.session.id)
    assert e.value.reasons == ("mfa-required",) and e.value.obligations == ("enroll-mfa",)
    secret = enable_mfa(svc, db, clock, u)
    s = svc.login(db, "alice", PASSWORD, code_at(secret, clock()))
    clock.advance(settings.mfa_step_up_max_age_seconds + 1)
    with pytest.raises(AccessDenied) as e:
        svc.change_password(db, u, PASSWORD, "violet-gravity-mango-77", keep_session_id=s.session.id)
    assert e.value.reasons == ("mfa-stale",) and e.value.obligations == ("step-up-mfa",)
    assert [ev["outcome"] for ev in audit.of("auth.password_change")] == [Outcome.DENIED] * 3


def test_list_and_revoke_sessions(svc, db, clock, audit):
    u = make_user(svc, db); make_user(svc, db, name="bob")
    a = svc.login(db, "alice", PASSWORD)
    clock.advance(1)
    b = svc.login(db, "alice", PASSWORD)
    bob = svc.login(db, "bob", PASSWORD)
    assert [s.id for s in svc.list_sessions(db, u)] == [b.session.id, a.session.id]
    assert not svc.revoke_session(db, bob.session.id, "user-request", owner_id=u.id)
    assert svc.revoke_session(db, a.session.id, "user-request", owner_id=u.id)
    assert [s.id for s in svc.list_sessions(db, u)] == [b.session.id]
    assert svc.revoke_all_sessions(db, u.id, "admin-action", actor_id="admin1") == 1
    assert svc.list_sessions(db, u) == []
    svc.authenticate_request(db, bob.access_token)
    assert len(audit.of("auth.session_revoke")) == 2


def test_audit_failure_blocks_login(svc, db, audit):
    make_user(svc, db)
    audit.fail = True
    with pytest.raises(RuntimeError):
        svc.login(db, "alice", PASSWORD)
    audit.fail = False
    assert db.execute(select(Session)).scalars().all() == []


# ---------------------------------------------------------------- secrets never reach the audit sink
def test_no_secrets_in_audit_events(svc, db, clock, audit):
    u = make_user(svc, db)
    wrong = "Wrong-Secret-Guess-991"
    reasons(lambda: svc.login(db, "alice", wrong))
    reasons(lambda: svc.login(db, "ghost-user", wrong))
    enrol = svc.enroll_mfa(db, u)
    codes = [code_at(enrol.secret, clock())]
    svc.activate_mfa(db, u, codes[0])
    clock.advance(30)
    codes.append(code_at(enrol.secret, clock()))
    r = svc.login(db, "alice", PASSWORD, codes[-1], IP)
    r2 = svc.refresh(db, r.refresh_token, IP)
    reasons(lambda: svc.refresh(db, r.refresh_token, IP))
    clock.advance(30)
    codes.append(code_at(enrol.secret, clock()))
    r3 = svc.login(db, "alice", PASSWORD, codes[-1])
    clock.advance(30)
    codes.append(code_at(enrol.secret, clock()))
    svc.verify_mfa_step_up(db, r3.session, codes[-1])
    svc.authenticate_request(db, r3.access_token)
    reasons(lambda: svc.authenticate_request(db, r3.access_token + "x"))
    new_pw = "violet-gravity-mango-77"
    svc.change_password(db, u, PASSWORD, new_pw, keep_session_id=r3.session.id)
    svc.logout(db, r3.session.id)

    secrets_used = [PASSWORD, wrong, new_pw, enrol.secret, enrol.otpauth_uri, r.access_token,
                    r.refresh_token, r2.access_token, r2.refresh_token, r3.access_token,
                    r3.refresh_token, *codes, "ghost-user", "alice"]
    blob = json.dumps(audit.events, default=str)
    assert len(audit.events) > 10
    for s in secrets_used:
        assert s not in blob, f"secret leaked into audit: {s[:4]}..."
        assert s.casefold() not in blob.casefold()
