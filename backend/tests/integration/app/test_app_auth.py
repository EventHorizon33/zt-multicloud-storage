"""Integrated auth flows through the HTTP API."""
from __future__ import annotations

import threading

from sqlalchemy import func, select

from app.models import User

from .conftest import ADMIN_PASSWORD, PASSWORD


def test_register_login_me_refresh_logout(env):
    u = env.register("alice")
    assert u["username"] == "alice" and u["role"] == "user" and u["clearance"] == "confidential"
    r = env.client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"access_token", "token_type", "expires_in", "session_id", "mfa_verified", "user"}
    cookie = r.headers["set-cookie"]
    assert "zt_refresh=" in cookie and "HttpOnly" in cookie and "Path=/api/auth" in cookie
    assert "samesite=strict" in cookie.lower()
    token = body["access_token"]
    me = env.client.get("/api/auth/me", headers=env.h(token)).json()
    assert me["user"]["username"] == "alice" and me["restricted"] is False
    assert me["audit_pseudonym"].startswith("u_") and me["session"]["current"] is True

    r = env.client.post("/api/auth/refresh")
    assert r.status_code == 200, r.text
    token2 = r.json()["access_token"]
    assert env.client.get("/api/auth/me", headers=env.h(token2)).status_code == 200

    assert env.client.post("/api/auth/logout", headers=env.h(token2)).status_code == 204
    # both access tokens belong to the revoked session
    assert env.client.get("/api/auth/me", headers=env.h(token)).status_code == 401
    assert env.client.post("/api/auth/refresh").status_code == 401


def test_secure_cookie_flag_follows_settings(make_env):
    env = make_env(cookie_secure=True)
    env.register("bob")
    r = env.client.post("/api/auth/login", json={"username": "bob", "password": PASSWORD})
    assert "Secure" in r.headers["set-cookie"]


def test_login_errors_are_generic(env):
    env.register("alice")
    bad = env.client.post("/api/auth/login", json={"username": "alice", "password": "wrong-password-123"})
    unknown = env.client.post("/api/auth/login", json={"username": "nobody", "password": "wrong-password-123"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json()["reasons"] == unknown.json()["reasons"] == []
    assert bad.json()["error"] == "unauthenticated"


def test_usernames_are_case_insensitive_and_unique_under_race(env):
    results = []

    def reg(name):
        r = env.client.post("/api/auth/register", json={"username": name, "password": PASSWORD})
        results.append(r.status_code)

    threads = [threading.Thread(target=reg, args=(n,)) for n in ("Alice", "alice", "ALICE", "aLiCe")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # F3: the client always gets the same 202, whichever request won the race,
    # so the response cannot be used to learn that the name exists ...
    assert results == [202, 202, 202, 202]
    # ... but exactly one account was created; the other three are audited
    # internally as username-taken (the outcome is not lost, only not disclosed).
    regs = env.audit_events(event_type="auth.register")
    assert sorted((e["outcome"], e["reason"]) for e in regs) == \
        [("failure", "username-taken")] * 3 + [("success", None)]
    with env.db() as db:
        assert db.execute(select(func.count()).select_from(User)
                          .where(func.lower(User.username) == "alice")).scalar_one() == 1
        assert db.execute(select(User.username).where(func.lower(User.username) == "alice")).scalar_one() == "alice"
    assert env.client.post("/api/auth/login", json={"username": "ALICE", "password": PASSWORD}).status_code == 200


def test_expired_token_is_401(env):
    token = env.user("alice")
    assert env.client.get("/api/auth/me", headers=env.h(token)).status_code == 200
    env.clock.advance(301)
    r = env.client.get("/api/files", headers=env.h(token))
    assert r.status_code == 401 and r.json()["reasons"] == []
    assert r.headers["www-authenticate"] == "Bearer"


def test_revoked_session_is_401(env):
    token = env.user("alice")
    secret = env.enable_mfa(token)          # session management needs an MFA-verified session (M5)
    env.clock.advance(31)
    other = env.login("alice", totp=env.totp(secret))
    sid = env.client.get("/api/auth/me", headers=env.h(other)).json()["session"]["id"]
    assert env.client.delete(f"/api/auth/sessions/{sid}", headers=env.h(token)).status_code == 204
    assert env.client.get("/api/files", headers=env.h(other)).status_code == 401
    assert env.client.get("/api/files", headers=env.h(token)).status_code == 200


def test_disabled_user_is_401_immediately(env):
    token = env.user("alice")
    uid = env.client.get("/api/auth/me", headers=env.h(token)).json()["user"]["id"]
    admin, _ = env.admin()
    r = env.client.post(f"/api/admin/users/{uid}/disable", headers=env.h(admin))
    assert r.status_code == 200 and r.json()["is_active"] is False
    assert env.client.get("/api/files", headers=env.h(token)).status_code == 401
    assert env.client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD}).status_code == 401


def test_admin_management_requires_fresh_mfa(env):
    env.register("alice")
    admin = env.login("root", ADMIN_PASSWORD)
    users = env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]
    uid = next(u["id"] for u in users if u["username"] == "alice")
    r = env.client.put(f"/api/admin/users/{uid}/role", headers=env.h(admin), json={"role": "auditor"})
    assert r.status_code == 403 and "mfa-required" in r.json()["reasons"]
    assert "step-up-mfa" in r.json()["obligations"]
    env.enable_mfa(admin)
    r = env.client.put(f"/api/admin/users/{uid}/role", headers=env.h(admin), json={"role": "auditor"})
    assert r.status_code == 200 and r.json()["role"] == "auditor"
    root_id = next(u["id"] for u in users if u["username"] == "root")
    r = env.client.put(f"/api/admin/users/{root_id}/role", headers=env.h(admin), json={"role": "user"})
    assert r.status_code == 409 and r.json()["reasons"] == ["cannot-modify-self"]


def test_rate_limit_login_429(make_env):
    env = make_env(rate_limit_login_per_minute=3)
    env.register("alice")
    codes = [env.client.post("/api/auth/login", json={"username": "alice", "password": "nope-nope-nope"}).status_code
             for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3] == 429
    r = env.client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert r.json()["error"] == "rate-limited"


def test_restricted_session_can_enrol_mfa(env):
    admin, secret = env.admin()
    r = env.client.put("/api/security/policy-settings", headers=env.h(admin),
                       json={"changes": {"require_mfa_for_login": True}})
    assert r.status_code == 200 and r.json()["config"]["require_mfa_for_login"] is True
    token = env.user("alice")
    me = env.client.get("/api/auth/me", headers=env.h(token)).json()
    assert me["restricted"] is True
    r = env.client.get("/api/files", headers=env.h(token))
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-enrollment-required"]
    assert r.json()["obligations"] == ["enroll-mfa"]
    assert env.client.get("/api/security/policies", headers=env.h(token)).status_code == 200
    # enrol + activate are reachable from the restricted session
    env.enable_mfa(token)
    me = env.client.get("/api/auth/me", headers=env.h(token)).json()
    assert me["restricted"] is False and me["user"]["mfa_enabled"] is True
    assert env.client.get("/api/files", headers=env.h(token)).status_code == 200


def test_mfa_wrong_code_is_403_not_401(env):
    token = env.user("alice")
    env.enable_mfa(token)
    r = env.client.post("/api/auth/mfa/verify", headers=env.h(token), json={"code": "000000"})
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-invalid"]
    assert env.client.get("/api/auth/me", headers=env.h(token)).status_code == 200


def test_security_headers_and_request_id(env):
    r = env.client.get("/api/health", headers={"X-Request-ID": "client-req-0001"})
    assert r.status_code == 200
    h = r.headers
    # L8: the request id is always server-generated; the client's value is echoed separately
    assert len(h["x-request-id"]) == 32 and h["x-request-id"] != "client-req-0001"
    assert h["x-client-request-id"] == "client-req-0001"
    assert "default-src 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store"
    bad = env.client.get("/api/health", headers={"X-Request-ID": "bad id\nwith spaces"})
    assert len(bad.headers["x-request-id"]) == 32 and "x-client-request-id" not in bad.headers
    err = env.client.get("/api/files")
    assert err.status_code == 401 and err.json()["request_id"] == err.headers["x-request-id"]
    assert set(err.json()) == {"error", "reasons", "request_id"}


def test_cors_allows_only_configured_origin(env):
    ok = env.client.options("/api/files", headers={"Origin": "https://ui.example",
                                                    "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://ui.example"
    bad = env.client.options("/api/files", headers={"Origin": "https://evil.example",
                                                     "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers


def test_json_body_size_limit(env):
    r = env.client.post("/api/auth/register", content=b"{" + b" " * (70 * 1024) + b"}",
                        headers={"Content-Type": "application/json"})
    assert r.status_code == 413 and r.json()["error"] == "request-too-large"


def test_validation_errors_are_structured(env):
    r = env.client.post("/api/auth/register", json={"username": "a b", "password": PASSWORD, "role": "admin"})
    assert r.status_code == 422
    assert r.json()["error"] == "validation-failed" and r.json()["reasons"]


def test_password_change_revokes_other_sessions(env):
    t1 = env.user("alice")
    t2 = env.login("alice")                  # password-only session
    env.enable_mfa(t1)                       # H1: password change needs a fresh second factor
    r = env.client.post("/api/auth/password", headers=env.h(t1),
                        json={"current_password": PASSWORD, "new_password": "Another-Long-Passw0rd"})
    assert r.status_code == 200 and r.json() == {"sessions_revoked": 1}
    assert env.client.get("/api/auth/me", headers=env.h(t2)).status_code == 401
    assert env.client.get("/api/auth/me", headers=env.h(t1)).status_code == 200
    r = env.client.post("/api/auth/password", headers=env.h(t1),
                        json={"current_password": "wrong-wrong-wrong", "new_password": "Yet-Another-Passw0rd"})
    assert r.status_code == 403 and r.json()["reasons"] == ["current-password-invalid"]


def test_username_uniqueness_is_enforced_by_the_database(env):
    """Functional unique index on lower(username): even a writer that bypasses
    the service's lower-casing cannot create a case-variant duplicate."""
    import pytest
    from sqlalchemy.exc import IntegrityError

    env.register("carol")
    with env.db() as db:
        db.add(User(username="CAROL", password_hash="x"))
        with pytest.raises(IntegrityError):
            db.commit()


def test_log_redaction():
    from app.api.logging_setup import redact
    jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlc2lnbmF0dXJl"
    out = redact(f"Authorization: Bearer abcdefghijklmnop token={jwt} password=hunter2hunter2 zt_refresh=abc123")
    assert jwt not in out and "hunter2" not in out and "abcdefghijklmnop" not in out and "abc123" not in out


# --------------------------------------------------------------------------- #
# ADR-0010 over HTTP: require_mfa_for_login default, admin enrolment codes, reset
# --------------------------------------------------------------------------- #
def _uid(env, admin, username):
    users = env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]
    return next(u["id"] for u in users if u["username"] == username)


def test_default_policy_requires_mfa_and_activation_needs_a_new_login(make_env):
    from app.config import Settings
    assert Settings(_env_file=None).require_mfa_for_login is True          # production default
    env = make_env(require_mfa_for_login=True)
    token = env.user("alice")
    assert env.client.get("/api/auth/me", headers=env.h(token)).json()["restricted"] is True
    assert env.client.get("/api/files", headers=env.h(token)).json()["reasons"] == ["mfa-enrollment-required"]
    secret = env.enable_mfa(token, step_up=False)                          # TOFU window: allowed
    me = env.client.get("/api/auth/me", headers=env.h(token)).json()
    # activation did not upgrade this (password-only) session
    assert me["user"]["mfa_enabled"] is True and me["restricted"] is True and me["mfa_fresh"] is False
    assert env.client.get("/api/files", headers=env.h(token)).status_code == 403
    env.clock.advance(31)
    fresh = env.login("alice", totp=env.totp(secret))                       # new login with the factor
    assert env.client.get("/api/auth/me", headers=env.h(fresh)).json()["restricted"] is False
    assert env.client.get("/api/files", headers=env.h(fresh)).status_code == 200
    assert env.client.get("/api/files", headers=env.h(token)).status_code == 403   # old session still restricted
    act = env.audit_events(event_type="auth.mfa_activate")[-1]
    assert (act["outcome"], act["severity"], act["reason"]) == ("success", "warning", "new-factor")


def test_admin_enrolment_code_flow(make_env):
    env = make_env(mfa_step_up_max_age_seconds=60)
    admin, admin_secret = env.admin()
    token = env.user("alice")
    bob = env.user("bob")
    env.clock.advance(env.settings.mfa_self_enroll_window_seconds + 1)
    token = env.login("alice")
    r = env.client.post("/api/auth/mfa/enroll", headers=env.h(token))
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-enrollment-requires-approval"]
    admin = env.login("root", ADMIN_PASSWORD, totp=env.totp(admin_secret))
    uid = _uid(env, admin, "alice")
    # a normal user cannot issue codes
    bob = env.login("bob")
    assert env.client.post(f"/api/admin/users/{uid}/mfa-enrollment-code", headers=env.h(bob)).status_code == 403
    # stale admin MFA -> refused with the step-up obligation
    env.clock.advance(61)                          # admin MFA older than mfa_step_up_max_age_seconds
    r = env.client.post(f"/api/admin/users/{uid}/mfa-enrollment-code", headers=env.h(admin))
    assert r.status_code == 403 and "step-up-mfa" in r.json()["obligations"]
    env.step_up(admin, admin_secret)
    r = env.client.post(f"/api/admin/users/{uid}/mfa-enrollment-code", headers=env.h(admin))
    assert r.status_code == 200, r.text
    body = r.json()
    code = body["enrollment_code"]
    assert body["single_use"] is True and len(code) == 19 and code.count("-") == 3
    issued = env.audit_events(event_type="admin.user.mfa_enrollment_code")[-1]
    assert (issued["outcome"], issued["severity"]) == ("success", "warning")
    assert code not in str(issued) and code.replace("-", "") not in str(issued)
    # not for the admin's own account
    own = env.client.post(f"/api/admin/users/{_uid(env, admin, 'root')}/mfa-enrollment-code", headers=env.h(admin))
    assert own.status_code == 409
    # the code lets alice enrol once; a wrong code is refused
    bad = env.client.post("/api/auth/mfa/enroll", headers=env.h(token),
                          json={"enrollment_code": "AAAA-BBBB-CCCC-DDDD"})
    assert bad.status_code == 403 and bad.json()["reasons"] == ["mfa-enrollment-code-invalid"]
    r = env.client.post("/api/auth/mfa/enroll", headers=env.h(token), json={"enrollment_code": code})
    assert r.status_code == 200
    secret = r.json()["secret"]
    again = env.client.post("/api/auth/mfa/enroll", headers=env.h(token), json={"enrollment_code": code})
    assert again.status_code == 403 and again.json()["reasons"] == ["mfa-enrollment-code-invalid"]
    r = env.client.post("/api/auth/mfa/activate", headers=env.h(token), json={"code": env.totp(secret)})
    assert r.status_code == 200 and r.json()["user"]["mfa_enabled"] is True and r.json()["mfa_fresh"] is False
    assert env.audit_events(event_type="auth.mfa_activate")[-1]["details"]["method"] == "admin-code"


def test_admin_mfa_reset_revokes_sessions(env):
    admin, admin_secret = env.admin()
    token = env.user("alice")
    env.enable_mfa(token)
    uid = _uid(env, admin, "alice")
    r = env.client.post(f"/api/admin/users/{uid}/mfa-reset", headers=env.h(admin))
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False and r.json()["sessions_revoked"] == 1
    assert env.client.get("/api/files", headers=env.h(token)).status_code == 401
    e = env.audit_events(event_type="admin.user.mfa_reset")[-1]
    assert (e["outcome"], e["severity"], e["details"]["mfa"]) == ("success", "warning", True)
    # the account had a factor: self-enrolment is closed even inside the window
    token = env.login("alice")
    r = env.client.post("/api/auth/mfa/enroll", headers=env.h(token))
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-enrollment-requires-approval"]
    # a code for an account that HAS a factor is refused (it could not be used: reset first)
    bob = env.user("bob")
    env.enable_mfa(bob, step_up=False)
    r = env.client.post(f"/api/admin/users/{_uid(env, admin, 'bob')}/mfa-enrollment-code", headers=env.h(admin))
    assert r.status_code == 409 and r.json()["reasons"] == ["mfa-already-enabled"]
    # a user cannot reset someone else's (or their own) factor through the admin API
    assert env.client.post(f"/api/admin/users/{uid}/mfa-reset", headers=env.h(token)).status_code == 403
