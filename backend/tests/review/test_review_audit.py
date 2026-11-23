"""Audit / privacy findings of the external review: regression tests
(formerly PoCs asserting the vulnerable behaviour)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.contracts import KeyPurpose
from tests.review.conftest import set_role


# --------------------------------------------------------------------------- #
# M1 -- the user directory was a reverse pseudonym table for auditors
# --------------------------------------------------------------------------- #
def test_fixed_auditor_cannot_reidentify_pseudonyms_through_the_user_list(make_env):
    """M1. ADR-0007: 'Mapping a pseudonym back to a user requires an
    explicit, audited admin lookup.' Now true: the auditor role no longer
    holds ``user:list`` (403), the user view carries no ``audit_pseudonym``
    even for admins, and the only mapping path (pseudonym-lookup) is
    admin-only and writes ``audit.reidentify``."""
    env = make_env()
    alice = env.user("alice")
    env.upload_ok(alice, b"hello")
    aud = env.register("auditor1")
    set_role(env, aud["id"], "auditor")
    atok = env.login("auditor1")

    r = env.client.post("/api/admin/pseudonym-lookup", headers=env.h(atok), json={"pseudonym": "u_" + "0" * 32})
    assert r.status_code == 403
    ev = env.client.get("/api/audit/events", headers=env.h(atok),
                        params={"event_type": "file.upload"}).json()["events"][0]
    r = env.client.get("/api/admin/users", headers=env.h(atok))
    assert r.status_code == 403 and r.json()["reasons"] == ["default-deny"]
    # auditors still work with pseudonyms: the full trail, verify, keys
    assert ev["actor"].startswith("u_")
    assert env.client.post("/api/audit/verify", headers=env.h(atok)).status_code == 200
    assert env.client.get("/api/admin/kms/keys", headers=env.h(atok)).status_code == 200

    admin, _ = env.admin()
    users = env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]
    assert users and all("audit_pseudonym" not in u for u in users)
    assert all(ev["actor"] not in str(u) for u in users)
    assert env.audit_events(event_type="audit.reidentify") == []
    r = env.client.post("/api/admin/pseudonym-lookup", headers=env.h(admin), json={"pseudonym": ev["actor"]})
    assert r.status_code == 200 and r.json()["user"]["username"] == "alice"
    lookups = env.audit_events(event_type="audit.reidentify")
    assert len(lookups) == 1 and lookups[0]["details"]["target_user"] == ev["actor"]


# --------------------------------------------------------------------------- #
# M2 -- unauthenticated audit flood via invalid bearer tokens
# --------------------------------------------------------------------------- #
def test_fixed_invalid_token_flood_is_rate_limited_aggregated_and_cannot_hide_critical_events(make_env,
                                                                                             monkeypatch):
    """M2. Garbage bearer tokens are limited per client network (20/min by
    default) and the limit is checked BEFORE any token verification; the
    auth.token failures are aggregated (one record per network per window
    + a summary), and /api/security/events returns CRITICAL events in a
    separate list that a flood cannot push out."""
    env = make_env()
    admin, _ = env.admin()
    env.register("victim")
    env.login("victim")
    old = env.client.cookies.get("zt_refresh")
    env.client.post("/api/auth/refresh")
    env.client.post("/api/auth/refresh", headers={"Cookie": f"zt_refresh={old}"})   # critical reuse alert

    verify_calls = {"n": 0}
    real_verify = env.container.auth.tokens.verify_access_token

    def counting(token):
        verify_calls["n"] += 1
        return real_verify(token)

    monkeypatch.setattr(env.container.auth.tokens, "verify_access_token", counting)
    attacker = TestClient(env.app, base_url="https://testserver", client=("203.0.113.66", 1))
    before = env.container.audit.stats()["total"]
    codes = [attacker.get("/api/files", headers={"Authorization": "Bearer a.b.c"}).status_code
             for _ in range(120)]
    limit = env.settings.rate_limit_invalid_token_per_minute
    assert codes[:limit] == [401] * limit and set(codes[limit:]) == {429}
    assert verify_calls["n"] == limit                       # 429s did no token verification work
    r = attacker.get("/api/files", headers={"Authorization": "Bearer a.b.c"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    grown = env.container.audit.stats()["total"] - before
    assert grown <= 3                                        # first auth.token + first 429 record
    first = env.audit_events(event_type="auth.token")
    assert len(first) == 1 and first[0]["reason"] == "token-malformed"
    assert first[0]["source_net"] == "203.0.113.0/24"
    # the window closes: one summary with the suppressed count
    env.clock.advance(61)
    assert env.container.token_failure_auditor.flush() == 1
    summary = env.audit_events(event_type="auth.token")[-1]
    assert summary["reason"] == "token-failures-aggregated"
    assert summary["details"]["kind"] == "summary" and summary["details"]["count"] == limit - 1

    # another network is unaffected; a valid token from a fresh network works
    other = TestClient(env.app, base_url="https://testserver", client=("198.51.100.99", 1))
    assert other.get("/api/files", headers=env.h(admin)).status_code == 200

    body = env.client.get("/api/security/events", headers=env.h(admin)).json()
    assert any(e["event_type"] == "auth.refresh_reuse" for e in body["critical"])
    assert all(e["severity"] == "critical" for e in body["critical"])


def test_fixed_invalid_token_limit_keys_ipv6_by_slash_64(make_env):
    """M2 + L4: the invalid-token bucket of an IPv6 client is its /64."""
    env = make_env(rate_limit_invalid_token_per_minute=3)
    codes = []
    for i in range(1, 6):
        c = TestClient(env.app, base_url="https://testserver", client=(f"2001:db8:9:9::{i:x}", 1))
        codes.append(c.get("/api/files", headers={"Authorization": "Bearer a.b.c"}).status_code)
    assert codes == [401, 401, 401, 429, 429]


def test_fixed_security_feed_keeps_critical_events_under_a_warning_flood(make_env):
    """M2. Even when the general feed is filled with newer warnings, the
    ``critical`` list still contains the critical alert."""
    env = make_env(rate_limit_invalid_token_per_minute=1000)
    admin, _ = env.admin()
    env.register("victim")
    env.login("victim")
    old = env.client.cookies.get("zt_refresh")
    env.client.post("/api/auth/refresh")
    env.client.post("/api/auth/refresh", headers={"Cookie": f"zt_refresh={old}"})
    for i in range(60):                                       # 60 distinct networks: 60 records
        c = TestClient(env.app, base_url="https://testserver", client=(f"203.0.{i}.1", 1))
        c.get("/api/files", headers={"Authorization": "Bearer a.b.c"})
    body = env.client.get("/api/security/events", headers=env.h(admin), params={"limit": 50}).json()
    assert not any(e["event_type"] == "auth.refresh_reuse" for e in body["events"])
    assert any(e["event_type"] == "auth.refresh_reuse" for e in body["critical"])


# --------------------------------------------------------------------------- #
# L8 -- client-chosen X-Request-ID merged two users in forensics
# --------------------------------------------------------------------------- #
def test_fixed_request_id_is_server_generated_and_client_id_kept_apart(make_env):
    """L8. The audit request id is always generated by the server. A client
    value is validated, echoed in X-Client-Request-ID and stored as
    ``details.client_request_id``; reusing a victim's id no longer mixes two
    actors under one request id."""
    env = make_env()
    a = env.user("alice")
    b = env.user("bob")
    rid = "deadbeefcafe0001"
    ra = env.client.get("/api/files/" + "ab" * 16, headers={**env.h(a), "X-Request-ID": rid})
    rb = env.client.get("/api/files/" + "ab" * 16, headers={**env.h(b), "X-Request-ID": rid})
    assert ra.headers["x-client-request-id"] == rid == rb.headers["x-client-request-id"]
    assert ra.headers["x-request-id"] != rb.headers["x-request-id"] != rid
    assert env.audit_events(request_id=rid) == []
    for r in (ra, rb):
        evs = env.audit_events(request_id=r.headers["x-request-id"])
        assert evs and len({e["actor"] for e in evs}) == 1
        assert all(e["details"].get("client_request_id") == rid for e in evs)
    r = env.client.get("/api/health", headers={"X-Request-ID": "x" * 65})
    assert "x-client-request-id" not in r.headers


# --------------------------------------------------------------------------- #
# L7 -- own-scope audit export scanned the whole log
# --------------------------------------------------------------------------- #
def test_fixed_own_scope_audit_export_filters_in_sql_and_is_rate_limited(make_env, monkeypatch):
    """L7. GET /api/audit/export for a normal user reads only the caller's
    rows (actor IN (...) in the SQL query, every pseudonym-key version) and
    is rate limited (``rate_limit_audit_export_per_minute``, default 6)."""
    env = make_env(rate_limit_register_per_minute=100, rate_limit_login_per_minute=100)
    for i in range(5):
        env.user(f"noise{i}")
    tok = env.user("quiet")
    seen = {"n": 0, "actors": None}
    orig = env.container.audit.export_ndjson

    def counting(*a, **k):
        seen["actors"] = k.get("actors")
        for line in orig(*a, **k):
            seen["n"] += 1
            yield line

    monkeypatch.setattr(env.container.audit, "export_ndjson", counting)
    r = env.client.get("/api/audit/export", headers=env.h(tok))
    assert r.status_code == 200
    own = [line for line in r.text.splitlines() if line]
    total = env.container.audit.stats()["total"]
    assert own and seen["n"] == len(own) and len(own) < total / 3       # only own rows were read
    assert seen["actors"] == env.container.audit.pseudonyms_for(
        env.audit_events(event_type="auth.register")[-1]["resource_id"])
    codes = [env.client.get("/api/audit/export", headers=env.h(tok)).status_code for _ in range(6)]
    assert codes[-1] == 429 and codes.count(200) == env.settings.rate_limit_audit_export_per_minute - 1


# --------------------------------------------------------------------------- #
# M3 -- admin rotation of the pseudonym key made past actions unattributable
# --------------------------------------------------------------------------- #
def test_fixed_pseudonym_key_rotation_is_refused_and_history_survives_offline_rotation(make_env):
    """M3. The API refuses to rotate the audit-pseudonym key (403
    ``pseudonym-key-rotation-disabled``, audited). If an operator rotates it
    out of band (ADR-0007 amendment: offline, two-person), lookups and
    'own events' match every retained key version, so nothing is orphaned."""
    env = make_env()
    admin, _ = env.admin()
    victim = env.register("victim")
    vtok = env.login("victim")
    env.upload_ok(vtok, b"victim data")
    before = env.client.get("/api/audit/events", headers=env.h(vtok)).json()["total"]
    r = env.client.put(f"/api/admin/users/{victim['id']}/clearance", headers=env.h(admin),
                       json={"clearance": "public"})
    assert r.status_code == 200
    old_actor = env.audit_events(event_type="admin.user.clearance")[-1]["actor"]

    r = env.client.post("/api/admin/kms/rotate", headers=env.h(admin), json={"purpose": "audit-pseudonym"})
    assert r.status_code == 403 and r.json()["reasons"] == ["pseudonym-key-rotation-disabled"]
    rot = env.audit_events(event_type="admin.kms.rotate")[-1]
    assert (rot["outcome"], rot["reason"]) == ("denied", "pseudonym-key-rotation-disabled")
    assert rot["actor"] == old_actor
    assert [k["version"] for k in env.client.get("/api/admin/kms/keys", headers=env.h(admin)).json()["keys"]
            if k["purpose"] == "audit-pseudonym"] == [1]

    # out-of-band rotation (what an operator with keystore access could do)
    env.container.kms.rotate(KeyPurpose.AUDIT_PSEUDONYM)
    assert env.container.audit.pseudonym_for(victim["id"]) != env.audit_events(
        event_type="file.upload")[-1]["actor"]
    r = env.client.post("/api/admin/pseudonym-lookup", headers=env.h(admin), json={"pseudonym": old_actor})
    assert r.status_code == 200 and r.json()["user"]["username"] == "root"          # still attributable
    env.upload_ok(vtok, b"after rotation", classification="public")   # clearance is now public
    after = env.client.get("/api/audit/events", headers=env.h(vtok)).json()
    assert after["total"] >= before + 2                                             # history kept
    uploads = [e for e in after["events"] if e["event_type"] == "file.upload"]
    assert len({e["actor"] for e in uploads}) == 2                                  # both key versions
    seq = uploads[-1]["seq"]
    assert env.client.get(f"/api/audit/events/{seq}", headers=env.h(vtok)).status_code == 200
