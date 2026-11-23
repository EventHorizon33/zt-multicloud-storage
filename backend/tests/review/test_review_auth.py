"""AuthN / session findings of the external review: regression tests.

Each test started life as a PoC that asserted the VULNERABLE behaviour. After
the fixes they assert the FIXED behaviour (``test_fixed_*``); the docstring
names the finding and the original attack."""
from __future__ import annotations

import contextlib
import threading
import time

import pytest
from fastapi.testclient import TestClient

from tests.review.conftest import PASSWORD, set_cidrs

NEW_PASSWORD = "Another-Sturdy-Phrase-77"


def _refresh(env, cookie: str, ip: str = "198.51.100.7"):
    c = TestClient(env.app, base_url="https://testserver", client=(ip, 5555))
    return c.post("/api/auth/refresh", headers={"Cookie": f"zt_refresh={cookie}"})


def _me(env, token: str):
    return env.client.get("/api/auth/me", headers=env.h(token))


# --------------------------------------------------------------------------- #
# H1 -- password change needed no fresh MFA and evicted the MFA-verified owner
# --------------------------------------------------------------------------- #
def test_fixed_password_change_needs_fresh_mfa_and_cannot_evict_the_mfa_owner(make_env):
    """H1. A stolen session (refresh cookie, MFA now stale) + the password is
    no longer enough to change the password: 403 ``mfa-stale`` with the
    ``step-up-mfa`` obligation, exactly like file:delete. The owner keeps
    every session and can still sign in with the old password."""
    env = make_env(require_mfa_for_login=True)
    env.register("alice")
    first = env.login("alice")
    thief_cookie = env.client.cookies.get("zt_refresh")      # stolen with the browser profile
    secret = env.enable_mfa(first)                            # TOFU enrolment + step-up on this session
    env.clock.advance(31)
    owner = env.login("alice", totp=env.totp(secret))          # owner's MFA session
    owner_cookie = env.client.cookies.get("zt_refresh")
    f = env.upload_ok(owner, b"x" * 100)

    env.clock.advance(11 * 60)                                 # step-up window (10 min) expired
    r = _refresh(env, thief_cookie)
    assert r.status_code == 200, r.text
    stolen = r.json()["access_token"]
    r = env.client.delete(f"/api/files/{f['id']}", headers=env.h(stolen))
    assert r.status_code == 403 and "mfa-stale" in r.json()["reasons"]

    r = env.client.post("/api/auth/password", headers=env.h(stolen),
                        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 403, r.text
    assert r.json()["reasons"] == ["mfa-stale"] and r.json()["obligations"] == ["step-up-mfa"]
    ev = env.audit_events(event_type="auth.password_change")[-1]
    assert (ev["outcome"], ev["reason"], ev["severity"]) == ("denied", "mfa-stale", "warning")
    assert _refresh(env, owner_cookie).status_code == 200                    # owner not kicked out
    env.clock.advance(31)
    r = env.client.post("/api/auth/login", json={"username": "alice", "password": PASSWORD,
                                                  "totp_code": env.totp(secret)})
    assert r.status_code == 200                                               # password unchanged


def test_fixed_password_change_never_revokes_a_more_recently_verified_session(make_env):
    """H1. With fresh MFA the change succeeds and revokes sessions with weaker
    or older proof (password-only, MFA-verified earlier), but never one that
    verified the factor more recently than the caller."""
    env = make_env()
    env.register("alice")
    password_only = env.login("alice")
    a = env.login("alice")
    secret = env.enable_mfa(a)                                 # a: MFA-verified at t0 (step-up)
    env.clock.advance(31)
    b = env.login("alice", totp=env.totp(secret))               # b: verified at t0 + 31 s
    env.clock.advance(31)
    env.step_up(a, secret)                                       # a: re-verified at t0 + 93 s
    env.clock.advance(31)
    c = env.login("alice", totp=env.totp(secret))               # c: verified at t0 + 124 s (newest)
    r = env.client.post("/api/auth/password", headers=env.h(a),
                        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    assert r.json() == {"sessions_revoked": 2}
    assert _me(env, password_only).status_code == 401           # weaker proof: revoked
    assert _me(env, b).status_code == 401                        # verified before the caller: revoked
    assert _me(env, c).status_code == 200                        # verified after the caller: kept
    assert _me(env, a).status_code == 200
    ev = env.audit_events(event_type="auth.password_change")[-1]
    assert ev["details"]["sessions_revoked"] == 2 and ev["details"]["sessions_kept"] == 1


def test_fixed_password_change_refused_for_an_account_without_a_factor(make_env):
    """H1/M5: an account that holds no factor cannot change its password
    through the API (403 ``mfa-required`` + ``enroll-mfa``)."""
    env = make_env()
    t = env.user("nofactor")
    r = env.client.post("/api/auth/password", headers=env.h(t),
                        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 403
    assert r.json()["reasons"] == ["mfa-required"] and r.json()["obligations"] == ["enroll-mfa"]


# --------------------------------------------------------------------------- #
# M5 -- restricted (password-only) session could manage sessions + password
# --------------------------------------------------------------------------- #
def test_fixed_restricted_password_only_session_is_limited_to_mfa_enrolment(make_env):
    """M5. THREAT_MODEL: 'a password-only session can only enrol MFA'. Now
    true: it can read /me, log out, reach MFA enrolment (with its own
    gating) and read the policy, but session list/revoke and password change
    answer 403 ``mfa-required``."""
    env = make_env(require_mfa_for_login=True)
    env.register("bob")
    owner = env.login("bob")
    env.clock.advance(25 * 3600)                     # TOFU window over, never enrolled
    env.client.get("/api/auth/me", headers=env.h(owner))
    owner = env.login("bob")                          # owner's current session
    thief = env.login("bob")                          # thief with the stolen password
    owner_sid = _me(env, owner).json()["session"]["id"]
    h = env.h(thief)
    assert env.client.get("/api/files", headers=h).status_code == 403          # PDP-gated: restricted

    r = env.client.get("/api/auth/sessions", headers=h)
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"]
    assert r.json()["obligations"] == ["enroll-mfa"]
    r = env.client.delete(f"/api/auth/sessions/{owner_sid}", headers=h)
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"]
    assert _me(env, owner).status_code == 200                                   # owner untouched
    r = env.client.post("/api/auth/password", headers=h,
                        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"]
    # what a restricted session may still do
    assert _me(env, thief).status_code == 200 and _me(env, thief).json()["restricted"] is True
    assert env.client.get("/api/security/policies", headers=h).status_code == 200
    r = env.client.post("/api/auth/mfa/enroll", headers=h)                       # gated (ADR-0010)
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-enrollment-requires-approval"]
    assert env.client.post("/api/auth/logout", headers=h).status_code == 204
    r = env.client.post("/api/auth/login", json={"username": "bob", "password": PASSWORD})
    assert r.status_code == 200                       # the owner is NOT locked out of the account
    denied = [e for e in env.audit_events(outcome="denied") if e["event_type"].startswith("auth.")]
    assert {e["event_type"] for e in denied} >= {"auth.session_list", "auth.session_revoke",
                                                  "auth.password_change"}


def test_fixed_session_management_needs_an_mfa_verified_session(make_env):
    """M5 with a factor: an MFA-verified session lists and revokes sessions."""
    env = make_env(require_mfa_for_login=True)
    env.register("carl")
    t = env.login("carl")
    secret = env.enable_mfa(t)                        # step-up: this session is now MFA-verified
    env.clock.advance(31)
    other = env.login("carl", totp=env.totp(secret))
    sessions = env.client.get("/api/auth/sessions", headers=env.h(t))
    assert sessions.status_code == 200
    victim = [s["id"] for s in sessions.json() if not s["current"]]
    assert victim
    for sid in victim:
        assert env.client.delete(f"/api/auth/sessions/{sid}", headers=env.h(t)).status_code == 204
    assert _me(env, other).status_code == 401


# --------------------------------------------------------------------------- #
# H2 -- X-Forwarded-For: only the first header line was read
# --------------------------------------------------------------------------- #
def _xff(*lines: str) -> list[tuple[str, str]]:
    return [("X-Forwarded-For", v) for v in lines]


def test_fixed_xff_joins_all_header_lines_and_takes_the_trusted_hop(make_env):
    """H2. All X-Forwarded-For lines are joined in order (RFC 9110 5.3), and
    the entry ``trusted_proxy_hops`` (default 1) from the right is the
    client. The client-supplied first line no longer wins."""
    env = make_env(trust_forwarded_for=True)
    u = env.register("carol")
    set_cidrs(env, u["id"], ["10.0.0.0/8"])
    body = {"username": "carol", "password": PASSWORD}
    r = env.client.post("/api/auth/login", json=body, headers={"X-Forwarded-For": "10.9.9.9, 203.0.113.50"})
    assert r.status_code == 401
    r = env.client.post("/api/auth/login", json=body, headers=_xff("10.9.9.9", "203.0.113.50"))
    assert r.status_code == 401                                         # was 200 (bypass)
    ev = env.audit_events(event_type="auth.login")[-1]
    assert ev["reason"] == "network-not-allowed" and ev["source_net"] == "203.0.113.0/24"
    # a genuine inside client behind the proxy
    r = env.client.post("/api/auth/login", json=body, headers=_xff("203.0.113.50, 10.1.2.3"))
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    r = env.client.get("/api/files", headers=[("Authorization", f"Bearer {tok}"),
                                              *_xff("10.9.9.9", "203.0.113.50")])
    assert r.status_code == 403 and r.json()["reasons"] == ["network-not-allowed"]
    r = env.client.get("/api/files", headers=[("Authorization", f"Bearer {tok}"), *_xff("10.1.2.3:51234")])
    assert r.status_code == 200                                         # ip:port -> port stripped


@pytest.mark.parametrize("value", ["10.1.2.3, garbage", "unknown", "10.1.2.3:99999", "10.1.2.3,,10.1.2.4",
                                   "[2001:db8::1", "fe80::1%eth0", "10.1.2.3:", "[10.1.2.3]:80",
                                   "2001:db8::1:80:x"])
def test_fixed_malformed_xff_is_rejected_not_ignored(make_env, value):
    """H2. Any unparseable entry -> 400 ``bad-forwarded-for`` (no fallback to
    the TCP peer or another entry)."""
    env = make_env(trust_forwarded_for=True)
    r = env.client.get("/api/health", headers={"X-Forwarded-For": value})
    assert r.status_code == 400 and r.json()["error"] == "bad-forwarded-for"


@pytest.mark.parametrize("value,expected", [("[2001:db8::1]:443", "2001:db8::/48"),
                                            ("2001:db8::1", "2001:db8::/48"),
                                            ("203.0.113.9:8080", "203.0.113.0/24")])
def test_fixed_xff_port_forms_are_parsed(make_env, value, expected):
    env = make_env(trust_forwarded_for=True)
    env.client.post("/api/auth/login", json={"username": "nobody-here", "password": "Some-Password-123"},
                    headers={"X-Forwarded-For": value})
    assert env.audit_events(event_type="auth.login")[-1]["source_net"] == expected


def test_fixed_xff_hops_and_trusted_proxy_cidrs(make_env):
    """H2/ADR-0011. ``trusted_proxy_hops=2``: two appending proxies, the
    client is the second entry from the right; a shorter chain is refused.
    ``trusted_proxy_cidrs``: the header is honoured only from those peers."""
    env = make_env(trust_forwarded_for=True, trusted_proxy_hops=2)
    u = env.register("dave")
    set_cidrs(env, u["id"], ["10.0.0.0/8"])
    body = {"username": "dave", "password": PASSWORD}
    assert env.client.post("/api/auth/login", json=body,
                           headers=_xff("10.9.9.9", "203.0.113.50", "192.0.2.10")).status_code == 401
    assert env.client.post("/api/auth/login", json=body,
                           headers=_xff("203.0.113.50", "10.1.2.3", "192.0.2.10")).status_code == 200
    r = env.client.post("/api/auth/login", json=body, headers=_xff("10.1.2.3"))
    assert r.status_code == 400 and r.json()["error"] == "bad-forwarded-for"

    env2 = make_env(trust_forwarded_for=True, trusted_proxy_cidrs=["192.0.2.0/24"])
    u2 = env2.register("erik")
    set_cidrs(env2, u2["id"], ["10.0.0.0/8"])
    body = {"username": "erik", "password": PASSWORD}
    # peer 198.51.100.7 (the harness client) is not a trusted proxy: header ignored, peer used
    assert env2.client.post("/api/auth/login", json=body, headers=_xff("10.1.2.3")).status_code == 401
    proxy = TestClient(env2.app, base_url="https://testserver", client=("192.0.2.5", 443))
    assert proxy.post("/api/auth/login", json=body, headers=_xff("10.1.2.3")).status_code == 200


def test_fixed_xff_resolved_ip_keys_the_rate_limit(make_env):
    """H2: rate-limit keys use the resolved client IP, not the proxy."""
    env = make_env(trust_forwarded_for=True, rate_limit_login_per_minute=2)
    body = {"username": "nobody-here", "password": "Some-Password-123"}
    codes = [env.client.post("/api/auth/login", json=body, headers=_xff("203.0.113.7")).status_code
             for _ in range(3)]
    assert codes == [401, 401, 429]
    assert env.client.post("/api/auth/login", json=body, headers=_xff("203.0.113.8")).status_code == 401


# --------------------------------------------------------------------------- #
# L2 -- used refresh token from outside the allow list revoked the victim
# --------------------------------------------------------------------------- #
def test_fixed_used_refresh_token_from_outside_allow_list_revokes_nothing(make_env):
    """L2. The network check runs before the reuse check: an outsider holding
    an old (rotated) refresh cookie gets the generic 401, the victim's live
    session survives, nothing is consumed, and the attempt is audited at
    WARNING with reason network-not-allowed and a reuse-suspected note."""
    env = make_env()
    u = env.register("dora")
    set_cidrs(env, u["id"], ["198.51.100.0/24"])      # the harness client IP is inside
    env.login("dora")
    old = env.client.cookies.get("zt_refresh")
    r = env.client.post("/api/auth/refresh")
    assert r.status_code == 200
    live = r.json()["access_token"]

    outsider = TestClient(env.app, base_url="https://testserver", client=("203.0.113.9", 4444))
    r = outsider.post("/api/auth/refresh", headers={"Cookie": f"zt_refresh={old}"})
    assert r.status_code == 401 and r.json()["reasons"] == []
    assert _me(env, live).status_code == 200                                 # victim NOT revoked
    assert env.audit_events(event_type="auth.refresh_reuse") == []
    ev = env.audit_events(event_type="auth.refresh")[-1]
    assert (ev["outcome"], ev["severity"], ev["reason"]) == ("failure", "warning", "network-not-allowed")
    assert ev["details"]["reuse_suspected"] is True and ev["source_net"] == "203.0.113.0/24"
    # from inside the allow list the same used token is still a detected reuse
    assert _refresh(env, old).status_code == 401
    assert env.audit_events(event_type="auth.refresh_reuse")


# --------------------------------------------------------------------------- #
# L3 -- parallel logins exceeded the lockout threshold
# --------------------------------------------------------------------------- #
def _parallel_logins(env, guesses, *, delay: float = 0.3):
    auth = env.container.auth
    real = auth._hasher
    verifies: list[str] = []
    lock = threading.Lock()

    class SlowHasher:
        def verify(self, h, p):
            with lock:
                verifies.append(p)
            time.sleep(delay)
            return real.verify(h, p)

        def __getattr__(self, name):
            return getattr(real, name)

    auth._hasher = SlowHasher()
    results: dict[str, str] = {}
    barrier = threading.Barrier(len(guesses))

    def attempt(pw: str) -> None:
        with env.db() as db:
            barrier.wait()
            try:
                auth.login(db, "erin", pw, source_ip="198.51.100.7")
                results[pw] = "ok"
            except Exception as exc:          # noqa: BLE001
                results[pw] = type(exc).__name__

    threads = [threading.Thread(target=attempt, args=(g,)) for g in guesses]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        auth._hasher = real
    return verifies, results


@pytest.mark.parametrize("in_process_lock", [True, False], ids=["with-user-lock", "db-reservation-only"])
def test_fixed_parallel_login_attempts_cannot_exceed_lockout(make_env, monkeypatch, in_process_lock):
    """L3. 15 parallel wrong guesses against max_failed_logins=5: at most 5
    password checks run (each attempt atomically reserves a slot with a
    conditional UPDATE before the slow verify); the account ends up locked
    and the correct password is then refused. The second case disables the
    per-user in-process lock to show the database reservation alone holds."""
    env = make_env(max_failed_logins=5)
    env.register("erin")
    if not in_process_lock:
        monkeypatch.setattr(env.container.auth, "_login_locks",
                            tuple(contextlib.nullcontext() for _ in range(256)))
    guesses = [f"wrong-guess-{i:02d}-xxxx" for i in range(15)]
    verifies, results = _parallel_logins(env, guesses)
    assert 1 <= len(verifies) <= 5                    # never more than the limit
    assert set(results.values()) == {"AuthenticationError"}
    r = env.client.post("/api/auth/login", json={"username": "erin", "password": PASSWORD})
    assert r.status_code == 401                       # locked: the correct password is refused
    assert env.audit_events(event_type="auth.lockout")


def test_fixed_correct_guess_in_a_parallel_batch_only_counts_within_the_limit(make_env):
    """L3. The PoC batch (14 wrong + the correct password in parallel): the
    correct password can only succeed if it was evaluated before the limit
    was reached; at most 5 wrong guesses are ever verified before it."""
    env = make_env(max_failed_logins=5)
    env.register("erin")
    guesses = [f"wrong-guess-{i:02d}-xxxx" for i in range(14)] + [PASSWORD]
    verifies, results = _parallel_logins(env, guesses)
    if PASSWORD in verifies:
        assert verifies.index(PASSWORD) <= 4          # fewer than 5 failures before it
        assert results[PASSWORD] == "ok"
    else:
        assert results[PASSWORD] == "AuthenticationError"
        assert len(verifies) <= 5
    wrong_before_success = len(verifies) if PASSWORD not in verifies else verifies.index(PASSWORD)
    assert wrong_before_success <= 5
    # a success resets the counter (consecutive failures), so at most 4 wrong
    # guesses before it and 5 after it are ever evaluated -- never all 14
    assert len([v for v in verifies if v != PASSWORD]) <= 9


# --------------------------------------------------------------------------- #
# L4 -- rate limits keyed on the full IPv6 address
# --------------------------------------------------------------------------- #
def test_fixed_login_rate_limit_is_per_ipv6_slash_64(make_env):
    """L4. IPv6 clients are keyed by their /64: rotating the interface
    identifier inside one /64 no longer escapes the per-IP login limit;
    another /64 has its own bucket; IPv4 stays per address."""
    env = make_env(rate_limit_login_per_minute=3)
    body = {"username": "nobody-here", "password": "Some-Password-123"}
    codes = []
    for i in range(1, 6):
        c = TestClient(env.app, base_url="https://testserver", client=(f"2001:db8:1:2::{i:x}", 1))
        codes.append(c.post("/api/auth/login", json=body).status_code)
    assert codes == [401, 401, 401, 429, 429]
    other = TestClient(env.app, base_url="https://testserver", client=("2001:db8:1:3::1", 1))
    assert other.post("/api/auth/login", json=body).status_code == 401
    v4 = TestClient(env.app, base_url="https://testserver", client=("203.0.113.1", 1))
    assert v4.post("/api/auth/login", json=body).status_code == 401
    rl = env.audit_events(event_type="security.rate-limited")
    assert rl and rl[0]["source_net"] == "2001:db8:1::/48"


# --------------------------------------------------------------------------- #
# L1 -- session endpoints ignored the network allow list
# --------------------------------------------------------------------------- #
def test_fixed_session_endpoints_apply_the_network_allow_list(make_env):
    """L1. /me, GET /api/auth/sessions and DELETE /api/auth/sessions/{id}
    now refuse a token replayed from outside the allow list (403
    network-not-allowed, audited); the owner's sessions survive."""
    env = make_env()
    u = env.register("gina")
    set_cidrs(env, u["id"], ["198.51.100.0/24"])
    owner = env.login("gina")
    stolen = env.login("gina")
    owner_sid = _me(env, owner).json()["session"]["id"]
    outside = TestClient(env.app, base_url="https://testserver", client=("203.0.113.9", 4444))
    h = env.h(stolen)
    assert outside.get("/api/files", headers=h).status_code == 403
    for r in (outside.get("/api/auth/me", headers=h), outside.get("/api/auth/sessions", headers=h),
              outside.delete(f"/api/auth/sessions/{owner_sid}", headers=h),
              outside.post("/api/auth/password", headers=h, json={"current_password": "x", "new_password": "y"})):
        assert r.status_code == 403 and r.json()["reasons"] == ["network-not-allowed"]
    assert _me(env, owner).status_code == 200
    types = {e["event_type"] for e in env.audit_events(outcome="denied")
             if e["reason"] == "network-not-allowed"}
    assert {"auth.me", "auth.session_list", "auth.session_revoke"} <= types


# --------------------------------------------------------------------------- #
# Unconfirmed items closed cheaply
# --------------------------------------------------------------------------- #
def test_fixed_replacing_the_factor_clears_mfa_status_of_other_sessions(make_env):
    """Replacing a factor: sessions verified with the OLD factor lose their
    MFA-verified status (fresh-MFA actions need the new factor)."""
    env = make_env()
    env.register("hank")
    a = env.login("hank")
    old_secret = env.enable_mfa(a)
    env.clock.advance(31)
    b = env.login("hank", totp=env.totp(old_secret))
    assert _me(env, b).json()["session"]["mfa_verified"] is True
    env.clock.advance(31)
    r = env.client.post("/api/auth/mfa/enroll", headers=env.h(a), json={"current_code": env.totp(old_secret)})
    assert r.status_code == 200, r.text
    new_secret = r.json()["secret"]
    env.clock.advance(31)
    r = env.client.post("/api/auth/mfa/activate", headers=env.h(a), json={"code": env.totp(new_secret)})
    assert r.status_code == 200, r.text
    assert _me(env, b).json()["session"]["mfa_verified"] is False
    f = env.upload_ok(b, b"data")
    r = env.client.delete(f"/api/files/{f['id']}", headers=env.h(b))
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"]


def test_fixed_bootstrap_admin_name_held_by_a_non_admin_refuses_to_start(tmp_path):
    """ensure_bootstrap_admin: if the configured bootstrap username exists as
    a non-admin account the server refuses to start with a clear error."""
    from tests.integration.app.conftest import build_env
    env, client = build_env(tmp_path / "a")
    with client:
        env.register("rootless")
    env2, client2 = build_env(tmp_path / "a", bootstrap_admin_username="rootless")
    with pytest.raises(RuntimeError, match="bootstrap-username-not-admin"):
        with client2:
            pass
