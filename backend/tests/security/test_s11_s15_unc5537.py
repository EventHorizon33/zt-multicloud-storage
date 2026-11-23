"""Scenarios 11-15: the UNC5537 kill chain replayed against this system.

Case study: infostealer-harvested passwords, no MFA, credentials valid for
years, no network allow lists, and legitimate export functions used for bulk
data theft. Each test plays one stage of that chain."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from .conftest import MARKER, PASSWORD, payload

pytestmark = pytest.mark.security


def _login(env, username, password=PASSWORD, totp=None, client=None):
    body = {"username": username, "password": password}
    if totp:
        body["totp_code"] = totp
    return env.req("POST", "/api/auth/login", json=body, client=client)


# --------------------------------------------------------------------------- #
# 11. stolen password
# --------------------------------------------------------------------------- #
def test_s11_stolen_password_but_mfa_enrolled_cannot_log_in(env, evidence):
    ev = evidence("S11", "Infostealer password for an MFA-enrolled user, no TOTP",
                  "Login requires TOTP once MFA is enrolled; no session is created")
    victim = env.user("victim")
    secret = env.enable_mfa(victim)
    meta = env.upload_ok(victim, payload())
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.0.2.66", 1234))
    r = _login(env, "victim", client=attacker)
    assert r.status_code == 401 and r.json()["reasons"] == ["mfa-required"]
    assert "access_token" not in r.text and "zt_refresh" not in r.headers.get("set-cookie", "")
    e = env.one(r, "auth.login")
    assert (e["outcome"], e["reason"], e["source_net"]) == ("failure", "mfa-required", "192.0.2.0/24")
    r2 = _login(env, "victim", totp="123456", client=attacker)
    assert r2.status_code == 401 and r2.json()["reasons"] == ["mfa-invalid"]
    assert env.one(r2, "auth.mfa_verify")["outcome"] == "failure"
    sessions = env.client.get("/api/auth/sessions", headers=env.h(victim)).json()
    assert len(sessions) == 1                                   # only the victim's own session exists
    assert env.download(victim, meta["id"]).status_code == 200
    ev.response(r)
    ev.audit(e)
    del secret


def test_s11_stolen_password_without_mfa_cannot_take_sensitive_actions(env, evidence):
    ev = evidence("S11", "Infostealer password for a user WITHOUT MFA: log in, download confidential, delete, share",
                  "Step-up MFA required for confidential+ reads, delete, share (mfa-required + obligations)")
    victim = env.user("victim")
    env.register("accomplice")
    conf = env.upload_ok(victim, payload(), filename="board-minutes.docx", classification="confidential")
    internal = env.upload_ok(victim, payload(), classification="internal")
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.0.2.66", 1234))
    r = _login(env, "victim", client=attacker)
    assert r.status_code == 200 and r.json()["mfa_verified"] is False   # residual risk: password-only login works
    tok = r.json()["access_token"]
    login_ev = env.one(r, "auth.login")
    assert login_ev["details"]["mfa"] is False
    # confidential download
    r = env.req("GET", f"/api/files/{conf['id']}/download", tok, client=attacker)
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"]
    assert set(r.json()["obligations"]) == {"step-up-mfa", "enroll-mfa"}
    assert MARKER not in r.content
    deny = env.one(r, "authz.decision")
    assert (deny["outcome"], deny["details"]["reasons"]) == ("denied", ["mfa-required"])
    # delete + share
    for method, path, body in (("DELETE", f"/api/files/{internal['id']}", None),
                               ("POST", f"/api/files/{internal['id']}/shares", {"username": "accomplice"})):
        rr = env.req(method, path, tok, json=body, client=attacker)
        assert rr.status_code == 403 and "mfa-required" in rr.json()["reasons"], rr.text
    # documented residual risk: internal files ARE readable with the password alone
    assert env.req("GET", f"/api/files/{internal['id']}/download", tok, client=attacker).status_code == 200
    ev.response(r, "confidential download")
    ev.audit(deny)


def _hijack_mfa(env, attacker_client) -> tuple[str, str]:
    """Attacker logs in with the stolen password and enrols THEIR OWN authenticator."""
    r = _login(env, "victim", client=attacker_client)
    assert r.status_code == 200
    tok = r.json()["access_token"]
    enr = env.req("POST", "/api/auth/mfa/enroll", tok, client=attacker_client)
    assert enr.status_code == 200
    secret = enr.json()["secret"]
    act = env.req("POST", "/api/auth/mfa/activate", tok, client=attacker_client, json={"code": env.totp(secret)})
    assert act.status_code == 200
    return tok, secret


def test_s11_mfa_enrolment_from_stolen_password_session_does_not_grant_step_up(env, evidence):
    ev = evidence("S11", "Stolen password (account inside the TOFU window): enrol + activate own TOTP, then "
                         "download a confidential file",
                  "Activation does not stamp the session MFA-verified (ADR-0010, F1) -> PDP mfa-required")
    victim = env.user("victim")
    conf = env.upload_ok(victim, payload(), classification="confidential")
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.0.2.66", 1234))
    tok, _ = _hijack_mfa(env, attacker)
    r = env.req("GET", f"/api/files/{conf['id']}/download", tok, client=attacker)
    assert r.status_code == 403, "attacker downloaded a confidential file after self-enrolling MFA"
    assert r.json()["reasons"] == ["mfa-required"] and MARKER not in r.content
    assert env.req("GET", "/api/files", victim).status_code == 200   # no session of the victim revoked
    ev.response(r, "confidential download after activation")
    ev.audit(env.one(r, "authz.decision"))


def test_s11_mfa_enrolment_hijack_with_require_mfa_for_login(env, evidence):
    ev = evidence("S11", "Same hijack with require_mfa_for_login=true (restricted session reaches enrol/activate)",
                  "Activation leaves the session restricted (mfa-enrollment-required) -> confidential download 403")
    victim = env.user("victim")
    conf = env.upload_ok(victim, payload(), classification="confidential")
    admin, _ = env.admin()
    assert env.client.put("/api/security/policy-settings", headers=env.h(admin),
                          json={"changes": {"require_mfa_for_login": True}}).status_code == 200
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.0.2.66", 1234))
    tok, _ = _hijack_mfa(env, attacker)
    r = env.req("GET", f"/api/files/{conf['id']}/download", tok, client=attacker)
    assert r.status_code == 403, "restricted (password-only) session self-enrolled MFA and downloaded"
    assert MARKER not in r.content
    assert env.req("GET", "/api/auth/me", tok, client=attacker).json()["restricted"] is True
    ev.response(r, "confidential download after activation")
    ev.audit(env.one(r, "authz.decision"))


def test_s11_mfa_enrolment_hijack_is_blocked_and_audited(env, evidence):
    """F1 (fixed, ADR-0010). Two cases of an infostealer password for a user
    who never enrolled MFA:

    A. Account older than the trust-on-first-use window (24 h): the attacker's
       password-only session cannot enrol a factor at all (403
       mfa-enrollment-requires-approval, audited WARNING); nothing changes
       for the victim.
    B. Account still inside the window: enrolment is allowed (TOFU), but
       activation does NOT make the attacker's session MFA-verified and does
       NOT revoke the victim's sessions; the confidential download is still
       denied. Activation is audited at WARNING with the attacker's network.
       The admin MFA reset is the recovery path."""
    ev = evidence("S11", "Attacker with a stolen password self-enrols THEIR OWN TOTP factor on a non-MFA account",
                  "ADR-0010: enrolment gated by TOFU window / admin enrolment code; activation never "
                  "stamps the session MFA-verified nor revokes other sessions")
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.0.2.66", 1234))

    # ---- A: outside the self-enrolment window -> refused outright
    old = env.user("oldtimer")
    conf_a = env.upload_ok(old, payload(), classification="confidential")
    env.clock.advance(env.settings.mfa_self_enroll_window_seconds + 60)
    old = env.login("oldtimer")                       # victim's current session (the old one idled out)
    r = _login(env, "oldtimer", client=attacker)
    assert r.status_code == 200 and r.json()["mfa_verified"] is False
    atok = r.json()["access_token"]
    enr = env.req("POST", "/api/auth/mfa/enroll", atok, client=attacker)
    assert enr.status_code == 403 and enr.json()["reasons"] == ["mfa-enrollment-requires-approval"]
    assert "secret" not in enr.json() and "otpauth" not in enr.text
    deny = env.one(enr, "auth.mfa_enroll")
    assert (deny["outcome"], deny["severity"], deny["reason"]) == \
        ("denied", "warning", "mfa-enrollment-requires-approval")
    assert deny["source_net"] == "192.0.2.0/24"
    act = env.req("POST", "/api/auth/mfa/activate", atok, client=attacker, json={"code": "123456"})
    assert act.status_code == 409 and act.json()["reasons"] == ["mfa-not-enrolled"]
    dl = env.req("GET", f"/api/files/{conf_a['id']}/download", atok, client=attacker)
    assert dl.status_code == 403 and dl.json()["reasons"] == ["mfa-required"] and MARKER not in dl.content
    assert env.req("GET", "/api/files", old).status_code == 200    # victim untouched
    assert _login(env, "oldtimer").status_code == 200              # and not locked out

    # ---- B: inside the window -> TOFU enrolment works but grants nothing
    victim = env.user("victim")
    conf = env.upload_ok(victim, payload(), classification="confidential")
    tok, secret = _hijack_mfa(env, attacker)
    me = env.req("GET", "/api/auth/me", tok, client=attacker).json()
    assert me["session"]["mfa_verified"] is False and me["mfa_fresh"] is False
    r = env.req("GET", f"/api/files/{conf['id']}/download", tok, client=attacker)
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"] and MARKER not in r.content
    assert env.req("GET", "/api/files", victim).status_code == 200  # victim's session NOT revoked
    a = env.audit_events(event_type="auth.mfa_activate")[-1]
    assert (a["outcome"], a["severity"], a["reason"]) == ("success", "warning", "new-factor")
    assert a["source_net"] == "192.0.2.0/24" and a["details"]["method"] == "tofu"
    # Recovery: an admin (fresh MFA) resets the factor -> every session of the
    # account, including the attacker's, is revoked and the attacker's TOTP is gone.
    admin, _ = env.admin()
    uid = next(u["id"] for u in env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]
               if u["username"] == "victim")
    rr = env.req("POST", f"/api/admin/users/{uid}/mfa-reset", admin)
    assert rr.status_code == 200 and rr.json()["mfa_enabled"] is False and rr.json()["sessions_revoked"] >= 2
    reset = env.one(rr, "admin.user.mfa_reset")
    assert (reset["outcome"], reset["severity"]) == ("success", "warning")
    assert env.req("GET", "/api/files", tok, client=attacker).status_code == 401
    # the factor is gone: the victim's next login is password-only again (not locked
    # out by the attacker's TOTP); re-enrolling now needs an admin enrolment code
    relog = _login(env, "victim")
    assert relog.status_code == 200 and relog.json()["mfa_verified"] is False
    again = env.req("POST", "/api/auth/mfa/enroll", relog.json()["access_token"])
    assert again.status_code == 403 and again.json()["reasons"] == ["mfa-enrollment-requires-approval"]
    ev.response(enr, "A (account > 24 h old): enrol")
    ev.response(r, "B (inside TOFU window): confidential download after activation")
    ev.result("victim sessions not revoked; admin mfa-reset revokes the attacker's session")
    ev.audit(deny)
    ev.audit(a)
    ev.audit(reset)


def test_s11_stated_limit_tofu_window(env, evidence):
    """Stated limit of ADR-0010 (THREAT_MODEL residual): a password stolen
    INSIDE the trust-on-first-use window, before the owner enrols, lets the
    thief enrol their own factor and then prove it with a step-up. The
    controls make this visible (WARNING events with the thief's network) and
    recoverable (admin MFA reset), not impossible."""
    ev = evidence("S11", "(STATED LIMIT) password stolen inside the 24 h TOFU window, before the owner enrols: "
                         "thief enrols own TOTP, then steps up with it",
                  "Not prevented (ADR-0010 residual): detective (WARNING auth.mfa_enroll/activate with the "
                  "thief's network) + recoverable (admin MFA reset)")
    victim = env.user("victim")
    conf = env.upload_ok(victim, payload(), classification="confidential")
    attacker = TestClient(env.app, base_url="https://testserver", client=("192.0.2.66", 1234))
    tok, secret = _hijack_mfa(env, attacker)
    env.clock.advance(31)
    v = env.req("POST", "/api/auth/mfa/verify", tok, client=attacker, json={"code": env.totp(secret)})
    assert v.status_code == 200 and v.json()["mfa_fresh"] is True
    assert env.req("GET", f"/api/files/{conf['id']}/download", tok, client=attacker).status_code == 200
    kinds = [(e["event_type"], e["severity"], e["source_net"])
             for e in env.audit_events(event_type="auth.mfa_activate")]
    assert ("auth.mfa_activate", "warning", "192.0.2.0/24") in kinds
    ev.response(v, "step-up with the thief's own factor")
    ev.result("confidential download then 200 (documented residual risk)")
    ev.audit(env.audit_events(event_type="auth.mfa_activate")[-1])


# --------------------------------------------------------------------------- #
# 12. network allow list
# --------------------------------------------------------------------------- #
def _restrict(env, username: str, cidrs: list[str]) -> None:
    admin, _ = env.admin()
    uid = next(u["id"] for u in env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]
               if u["username"] == username)
    r = env.client.put(f"/api/admin/users/{uid}/allowed-cidrs", headers=env.h(admin), json={"cidrs": cidrs})
    assert r.status_code == 200 and r.json()["allowed_cidrs"] == cidrs


def test_s12_valid_credentials_from_outside_the_allow_list_cannot_use_the_api(env, evidence):
    ev = evidence("S12", "Session opened inside alice's allow list (10.20.0.0/16), token replayed from outside",
                  "PDP guard network-not-allowed on every PDP-gated request (ADR-0008)")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload())
    _restrict(env, "alice", ["10.20.0.0/16"])
    outside = env.client                                         # TEST_IP 198.51.100.7
    inside = TestClient(env.app, base_url="https://testserver", client=("10.20.3.4", 1))
    r = _login(env, "alice", client=inside)
    assert r.status_code == 200
    tok = r.json()["access_token"]
    for method, path in (("GET", "/api/files"), ("GET", f"/api/files/{meta['id']}/download"),
                         ("GET", f"/api/files/{meta['id']}"), ("GET", "/api/audit/events"),
                         ("GET", "/api/dashboard")):
        r = env.req(method, path, tok, client=outside)
        assert r.status_code == 403 and "network-not-allowed" in r.json()["reasons"], (path, r.text)
        e = env.one(r, "authz.decision")
        assert e["outcome"] == "denied" and "network-not-allowed" in e["details"]["reasons"]
        assert e["source_net"] == "198.51.100.0/24"
    assert MARKER not in r.content
    ok = env.req("GET", f"/api/files/{meta['id']}/download", tok, client=inside)
    assert ok.status_code == 200                                 # same token, allowed network
    ev.response(r, "every file/audit/dashboard route")
    ev.audit(e)


def test_s12_login_from_outside_the_allow_list_is_refused(env, evidence):
    ev = evidence("S12", "Valid password for alice from outside her allow list (login + refresh)",
                  "AuthService.login/refresh check users.allowed_cidrs (F2): generic 401, audited "
                  "network-not-allowed, no lockout increment")
    env.user("alice")
    _restrict(env, "alice", ["10.20.0.0/16"])
    for _ in range(env.settings.max_failed_logins + 1):            # more than the lockout threshold
        r = _login(env, "alice")                                   # from 198.51.100.7 (outside)
        assert r.status_code == 401 and r.json()["reasons"] == []  # same as a wrong password
        assert "access_token" not in r.text and "zt_refresh" not in r.headers.get("set-cookie", "")
    e = env.one(r, "auth.login")
    assert (e["outcome"], e["severity"], e["reason"]) == ("failure", "warning", "network-not-allowed")
    assert e["source_net"] == "198.51.100.0/24"
    assert env.audit_events(event_type="auth.lockout") == []      # cannot be used to lock the owner out
    inside = TestClient(env.app, base_url="https://testserver", client=("10.20.3.4", 1))
    assert _login(env, "alice", client=inside).status_code == 200
    # a refresh cookie taken from the inside client does not work from outside ...
    thief = TestClient(env.app, base_url="https://testserver", client=("192.0.2.99", 1),
                       cookies={"zt_refresh": inside.cookies.get("zt_refresh")})
    rr = env.req("POST", "/api/auth/refresh", client=thief)
    assert rr.status_code == 401 and rr.json()["reasons"] == []
    re_ = env.one(rr, "auth.refresh")
    assert (re_["outcome"], re_["reason"]) == ("failure", "network-not-allowed")
    # ... and is not consumed by the refused attempt: the owner can still use it
    assert env.req("POST", "/api/auth/refresh", client=inside).status_code == 200
    ev.response(r, "login from outside")
    ev.response(rr, "refresh from outside")
    ev.audit(e)
    ev.audit(re_)


def test_s12_account_takeover_actions_from_outside_the_allow_list_are_refused(env, evidence):
    ev = evidence("S12", "Token of a session opened inside the allow list used from outside for "
                         "password change and MFA enrol/activate/verify/disable",
                  "AuthService._require_network (F2): 403 network-not-allowed, audited per endpoint")
    env.user("alice")
    _restrict(env, "alice", ["10.20.0.0/16"])
    inside = TestClient(env.app, base_url="https://testserver", client=("10.20.3.4", 1))
    tok = _login(env, "alice", client=inside).json()["access_token"]
    attempts = (("/api/auth/password", {"current_password": PASSWORD, "new_password": "Attacker-Chosen-Pass-99"},
                 "auth.password_change"),
                ("/api/auth/mfa/enroll", None, "auth.mfa_enroll"),
                ("/api/auth/mfa/activate", {"code": "123456"}, "auth.mfa_activate"),
                ("/api/auth/mfa/verify", {"code": "123456"}, "auth.mfa_verify"),
                ("/api/auth/mfa/disable", {"code": "123456"}, "auth.mfa_disable"))
    for path, body, event in attempts:
        r = env.req("POST", path, tok, json=body)                  # from 198.51.100.7 (outside)
        assert r.status_code == 403 and r.json()["reasons"] == ["network-not-allowed"], (path, r.text)
        e = env.one(r, event)
        assert (e["outcome"], e["severity"], e["reason"]) == ("denied", "warning", "network-not-allowed")
        assert e["source_net"] == "198.51.100.0/24"
    # nothing changed: the old password still works from inside, no factor enrolled
    r2 = _login(env, "alice", client=inside)
    assert r2.status_code == 200 and r2.json()["user"]["mfa_enabled"] is False
    ev.response(r, "password change / MFA enrol / activate / verify / disable")
    ev.audit(env.one(env.req("POST", "/api/auth/password", tok, json=attempts[0][1]), "auth.password_change"))


# --------------------------------------------------------------------------- #
# 13. bulk export
# --------------------------------------------------------------------------- #
def test_s13_bulk_export_by_a_valid_session_is_blocked_and_alerted(make_env, evidence):
    ev = evidence("S13", "Valid session downloads every file in a loop (bulk export)",
                  "DownloadDetector count threshold -> DownloadBlock -> PDP download-rate-exceeded")
    env = make_env(detect_max_downloads_in_window=5)
    alice = env.user("alice")
    metas = [env.upload_ok(alice, payload(1)) for _ in range(8)]
    codes = [env.req("GET", f"/api/files/{m['id']}/download", alice).status_code for m in metas]
    assert codes == [200] * 5 + [403] * 3
    r = env.req("GET", f"/api/files/{metas[0]['id']}/download", alice)
    assert r.status_code == 403 and r.json()["reasons"] == ["download-rate-exceeded"]
    deny = env.one(r, "authz.decision")
    assert deny["details"]["reasons"] == ["download-rate-exceeded"]
    alert = env.audit_events(event_type="security.anomaly.bulk-download")
    assert len(alert) == 1
    a = alert[0]
    assert (a["outcome"], a["severity"], a["reason"]) == ("denied", "critical", "download-count-threshold")
    assert a["details"]["count"] == 6 and a["details"]["threshold"] == 5
    # a fresh login does not escape the block (it is per user, not per session)
    fresh = env.login("alice")
    assert env.req("GET", f"/api/files/{metas[1]['id']}/download", fresh).status_code == 403
    admin, _ = env.admin()
    blocks = env.client.get("/api/security/anomaly-blocks", headers=env.h(admin)).json()["blocks"]
    assert [b["username"] for b in blocks] == ["alice"]
    ev.response(r, "6th+ download")
    ev.audit(a)


def test_s13_bulk_export_by_volume_is_blocked(make_env, evidence):
    ev = evidence("S13", "Few but large downloads (byte volume)", "DownloadDetector byte threshold")
    env = make_env(detect_max_download_bytes_in_window=40_000)
    alice = env.user("alice")
    big = env.upload_ok(alice, payload(4))                       # ~16 KiB each
    codes = [env.req("GET", f"/api/files/{big['id']}/download", alice).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and codes[-1] == 403
    a = env.audit_events(event_type="security.anomaly.bulk-download")[0]
    assert (a["severity"], a["reason"]) == ("critical", "download-bytes-threshold")
    ev.result(f"downloads: {codes}")
    ev.audit(a)


# --------------------------------------------------------------------------- #
# 14. stolen refresh token
# --------------------------------------------------------------------------- #
def _thief(env, cookie: str) -> TestClient:
    return TestClient(env.app, base_url="https://testserver", client=("192.0.2.99", 1),
                      cookies={"zt_refresh": cookie})


def test_s14_stolen_refresh_token_replayed_after_rotation_revokes_session(env, evidence):
    ev = evidence("S14", "Thief replays a refresh token the legitimate client already rotated",
                  "Single-use refresh tokens; reuse -> whole session revoked + critical audit")
    env.register("alice")
    r = _login(env, "alice")
    legit_access = r.json()["access_token"]
    stolen = env.client.cookies.get("zt_refresh")
    assert stolen
    r = env.req("POST", "/api/auth/refresh")                     # legitimate rotation
    assert r.status_code == 200
    legit_access = r.json()["access_token"]
    r = env.req("POST", "/api/auth/refresh", client=_thief(env, stolen))
    assert r.status_code == 401 and r.json()["reasons"] == []
    e = env.one(r, "auth.refresh_reuse")
    assert (e["outcome"], e["severity"], e["reason"]) == ("failure", "critical", "refresh-reuse")
    # the whole session is dead for everybody, immediately
    r2 = env.req("GET", "/api/files", legit_access)
    assert r2.status_code == 401
    assert env.one(r2, "auth.session")["reason"] == "session-revoked"
    assert env.req("POST", "/api/auth/refresh").status_code == 401   # the rotated token too
    ev.response(r)
    ev.audit(e)


def test_s14_thief_refreshes_first_then_legit_client_kills_the_session(env, evidence):
    ev = evidence("S14", "Thief uses the stolen refresh token FIRST, gets fresh tokens",
                  "Legitimate client's next refresh is a reuse -> session (incl. thief's tokens) revoked")
    env.register("alice")
    _login(env, "alice")
    stolen = env.client.cookies.get("zt_refresh")
    thief = _thief(env, stolen)
    r = env.req("POST", "/api/auth/refresh", client=thief)
    assert r.status_code == 200
    thief_access = r.json()["access_token"]
    assert env.req("GET", "/api/files", thief_access, client=thief).status_code == 200
    r = env.req("POST", "/api/auth/refresh")                     # legit client, same (now used) token
    assert r.status_code == 401
    e = env.one(r, "auth.refresh_reuse")
    assert e["severity"] == "critical"
    assert env.req("GET", "/api/files", thief_access, client=thief).status_code == 401
    ev.result("thief's access token -> 401 after the legit client's refresh")
    ev.audit(e)


# --------------------------------------------------------------------------- #
# 15. revocation is immediate
# --------------------------------------------------------------------------- #
def test_s15_revoked_session_fails_on_the_next_request(env, evidence):
    ev = evidence("S15", "Keep using an access token after its session was revoked (user revokes / logs out)",
                  "Session row re-read on every request (ADR-0008)")
    a = env.user("alice")
    secret = env.enable_mfa(a)               # managing sessions needs an MFA-verified session (M5)
    env.clock.advance(31)
    b = env.login("alice", totp=env.totp(secret))
    sid_b = env.me(b)["session"]["id"]
    assert env.req("GET", "/api/files", b).status_code == 200
    assert env.client.delete(f"/api/auth/sessions/{sid_b}", headers=env.h(a)).status_code == 204
    r = env.req("GET", "/api/files", b)
    assert r.status_code == 401
    e = env.one(r, "auth.session")
    assert (e["outcome"], e["reason"]) == ("failure", "session-revoked")
    assert env.client.post("/api/auth/logout", headers=env.h(a)).status_code == 204
    assert env.req("GET", "/api/files", a).status_code == 401
    ev.response(r)
    ev.audit(e)


def test_s15_disabled_account_and_demotion_take_effect_immediately(env, evidence):
    ev = evidence("S15", "Admin disables alice / demotes an auditor while their tokens are still unexpired",
                  "User row (is_active, role) re-read on every request; disable revokes sessions")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload())
    auditor = env.auditor("audrey")
    admin, _ = env.admin()
    users = {u["username"]: u["id"] for u in env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]}
    assert env.req("POST", "/api/audit/verify", auditor, json={}).status_code == 200
    assert env.client.post(f"/api/admin/users/{users['alice']}/disable", headers=env.h(admin)).status_code == 200
    assert env.client.put(f"/api/admin/users/{users['audrey']}/role", headers=env.h(admin),
                          json={"role": "user"}).status_code == 200
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 401
    e = env.one(r, "auth.session")
    assert e["reason"] in ("session-revoked", "user-disabled")
    r2 = _login(env, "alice")
    assert r2.status_code == 401 and r2.json()["reasons"] == []
    assert env.one(r2, "auth.login")["reason"] == "user-disabled"
    r3 = env.req("POST", "/api/audit/verify", auditor, json={})
    assert r3.status_code == 403
    assert env.one(r3, "authz.decision")["actor_role"] == "user"
    ev.response(r, "disabled user's token")
    ev.audit(e)
