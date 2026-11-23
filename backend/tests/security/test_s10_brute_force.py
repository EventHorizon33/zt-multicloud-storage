"""Scenario 10: repeated failed authentication — password guessing against one
account (lockout), credential stuffing across many accounts from one network
(anomaly detection), and request flooding (rate limiting)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from .conftest import PASSWORD

pytestmark = pytest.mark.security


def _login(env, username, password, client=None, totp=None):
    body = {"username": username, "password": password}
    if totp:
        body["totp_code"] = totp
    return env.req("POST", "/api/auth/login", json=body, client=client)


def test_s10_lockout_after_n_failures_refuses_correct_password(env, evidence):
    ev = evidence("S10", "Guess alice's password 5 times, then use the CORRECT password",
                  "Account lockout after max_failed_logins (5) for lockout_seconds (900)")
    env.register("alice")
    n = env.settings.max_failed_logins
    for i in range(n):
        r = _login(env, "alice", f"Wrong-Guess-{i:04d}-xx")
        assert r.status_code == 401 and r.json()["reasons"] == []
    lock = env.one(r, "auth.lockout")
    assert (lock["outcome"], lock["severity"], lock["reason"]) == ("failure", "warning", "too-many-failures")
    assert lock["details"]["failed_count"] == n and lock["details"]["lockout_seconds"] == env.settings.lockout_seconds
    r = _login(env, "alice", PASSWORD)
    assert r.status_code == 401 and r.json() == {**r.json(), "error": "unauthenticated", "reasons": []}
    assert "access_token" not in r.text
    locked = env.one(r, "auth.login")
    assert (locked["outcome"], locked["reason"]) == ("failure", "account-locked")
    # indistinguishable from an unknown user / wrong password
    unknown = _login(env, "nobody-here", PASSWORD)
    assert (unknown.status_code, unknown.json()["reasons"]) == (r.status_code, r.json()["reasons"])
    # lockout is time-boxed
    env.clock.advance(env.settings.lockout_seconds + 1)
    assert _login(env, "alice", PASSWORD).status_code == 200
    ev.response(r, "correct password while locked")
    ev.audit(lock)
    ev.audit(locked)


def test_s10_wrong_totp_codes_count_towards_lockout(env, evidence):
    ev = evidence("S10", "Attacker with the password brute-forces the 6-digit TOTP",
                  "TOTP failures share the lockout counter")
    token = env.user("alice")
    secret = env.enable_mfa(token)
    good = env.totp(secret)
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(env.settings.max_failed_logins):
        r = _login(env, "alice", PASSWORD, totp=wrong)
        assert r.status_code == 401 and r.json()["reasons"] == ["mfa-invalid"]
    lock = env.one(r, "auth.lockout")
    env.clock.advance(31)
    r = _login(env, "alice", PASSWORD, totp=env.totp(secret))     # right password + right code, still locked
    assert r.status_code == 401 and r.json()["reasons"] == []
    assert env.one(r, "auth.login")["reason"] == "account-locked"
    ev.response(r, "correct password+TOTP while locked")
    ev.audit(lock)


def test_s10_credential_stuffing_across_accounts_raises_anomaly(env, evidence):
    ev = evidence("S10", "Try one leaked password against 6 different usernames from one /24",
                  "AuthFailureDetector: >=5 distinct accounts failing from one network in the window")
    for u in ("carol", "dave", "erin", "frank", "grace", "heidi"):
        env.register(u)
    stuffing = TestClient(env.app, base_url="https://testserver", client=("203.0.113.50", 4444))
    results = []
    for i, u in enumerate(("carol", "dave", "erin", "frank", "grace", "heidi")):
        cl = stuffing if i % 2 == 0 else TestClient(env.app, base_url="https://testserver",
                                                    client=("203.0.113.77", 5555))   # same /24
        results.append(_login(env, u, "Leaked-Password-2024!", client=cl))
    assert {r.status_code for r in results} == {401}
    alerts = env.audit_events(event_type="security.anomaly.auth-failures")
    assert len(alerts) == 1
    a = alerts[0]
    assert (a["outcome"], a["severity"], a["source_net"]) == ("failure", "critical", "203.0.113.0/24")
    assert a["details"]["distinct_accounts"] >= 5
    # no account got locked by the spray (one failure each), so the stuffing would otherwise go unnoticed
    assert env.audit_events(event_type="auth.lockout") == []
    sec = env.client.get("/api/security/events", headers=env.h(env.admin()[0])).json()["events"]
    assert any(e["event_type"] == "security.anomaly.auth-failures" for e in sec)
    ev.result("6 x 401; one critical anomaly for 203.0.113.0/24; visible in /api/security/events")
    ev.audit(a)


def test_s10_login_flood_is_rate_limited(make_env, evidence):
    ev = evidence("S10", "Flood /api/auth/login from one IP (20 requests)",
                  "Per-IP token bucket (rate_limit_login_per_minute=10) -> 429 + Retry-After")
    env = make_env(rate_limit_login_per_minute=10)
    env.register("alice")
    codes = []
    for i in range(20):
        r = _login(env, "alice", f"Wrong-Guess-{i:04d}-xx")
        codes.append(r.status_code)
    assert codes[:10] == [401] * 10 and set(codes[10:]) == {429}
    assert r.json()["error"] == "rate-limited" and int(r.headers["retry-after"]) >= 1
    # The limiter runs before the password check: the flood did not consume more guesses than the bucket.
    failures = env.audit_events(event_type="auth.login", outcome="failure")
    assert len(failures) == 10
    ev.response(r, "11th..20th request")
    ev.audit(env.audit_events(event_type="auth.lockout")[-1])


def test_s10_rate_limit_rejections_are_audited(make_env, evidence):
    ev = evidence("S10", "Flood /api/auth/login above the limit (2/min) and look for the 429s in the audit log",
                  "RateLimitAuditor (F6): first 429 per (scope, key) per window -> security.rate-limited "
                  "WARNING with request id + source; later ones aggregated into one summary")
    env = make_env(rate_limit_login_per_minute=2)
    env.register("alice")
    rs = [_login(env, "alice", f"Wrong-Guess-{i:04d}-xx") for i in range(6)]
    assert [r.status_code for r in rs] == [401, 401, 429, 429, 429, 429]
    # the FIRST rejection of the window is recorded, joined to its request
    first = env.one(rs[2], "security.rate-limited")
    assert (first["outcome"], first["severity"], first["reason"]) == ("denied", "warning", "rate-limited")
    assert first["details"]["scope"] == "login" and first["details"]["kind"] == "first"
    assert first["details"]["count"] == 1 and first["source_net"] == "198.51.100.0/24"
    # the rest of the flood is only counted: the audit log itself cannot be flooded
    assert all(env.events_for(r) == [] for r in rs[3:])
    assert len(env.audit_events(event_type="security.rate-limited")) == 1
    # when the window rolls, one summary carries the number of suppressed rejections
    env.clock.advance(61)
    assert env.container.rate_limit_auditor.flush() == 1
    summary = env.audit_events(event_type="security.rate-limited")[-1]
    assert summary["details"]["kind"] == "summary" and summary["details"]["count"] == 3
    assert summary["request_id"] is None                 # not attributed to an unrelated request
    assert summary["source_net"] == "198.51.100.0/24"
    ev.response(rs[2], "3rd request (first 429)")
    ev.result("4th-6th: 429, no individual record; after the window: one summary count=3")
    ev.audit(first)
    ev.audit(summary)


def test_s10_registration_does_not_reveal_existing_usernames(env, evidence):
    ev = evidence("S10", "Probe registration with a known and an unknown username (enumeration, F3)",
                  "Uniform 202 {status: accepted} for both; no duplicate created; username-taken audited internally")
    env.register("alice")
    taken = env.req("POST", "/api/auth/register", json={"username": "alice", "password": "Another-Passw0rd-77"})
    fresh = env.req("POST", "/api/auth/register", json={"username": "zed-unused", "password": "Another-Passw0rd-77"})
    assert (taken.status_code, taken.json()) == (fresh.status_code, fresh.json()) == (202, {"status": "accepted"})
    e = env.one(taken, "auth.register")
    assert (e["outcome"], e["reason"]) == ("failure", "username-taken")
    assert env.one(fresh, "auth.register")["outcome"] == "success"
    # alice's original password still works; the probe did not create or change anything
    assert _login(env, "alice", PASSWORD).status_code == 200
    assert _login(env, "alice", "Another-Passw0rd-77").status_code == 401
    ev.response(taken, "existing name")
    ev.response(fresh, "new name")
    ev.audit(e)


def test_s10_self_registration_can_be_disabled(make_env, evidence):
    ev = evidence("S10", "Register while the deployment disables self-registration",
                  "Setting allow_self_registration=false -> 403 registration-disabled, audited")
    env = make_env(allow_self_registration=False)
    r = env.req("POST", "/api/auth/register", json={"username": "newbie", "password": "Another-Passw0rd-77"})
    assert r.status_code == 403 and r.json()["reasons"] == ["registration-disabled"]
    e = env.one(r, "auth.register")
    assert (e["outcome"], e["reason"]) == ("denied", "registration-disabled")
    ev.response(r)
    ev.audit(e)
