"""Scenario 3 (horizontal: another user's files) and scenario 4 (vertical:
administrative operations by non-admins; separation of duties for admins).

Mechanism: ``FileService._authorize`` (load row -> PEP -> 404 masking for
non-parties), the PDP permission matrix (``app/policy``), and the admin role
having no ``file:read`` on others' files (``admin-no-content-access``)."""
from __future__ import annotations

import secrets

import pytest

from .conftest import MARKER, payload

pytestmark = pytest.mark.security


def _strip(r) -> tuple:
    body = r.json()
    body.pop("request_id", None)
    hdrs = {k: v for k, v in r.headers.items() if k.lower() not in ("x-request-id", "x-client-request-id", "date",
                                                                          "content-length")}
    return r.status_code, body, tuple(sorted(hdrs.items()))


OPS = [
    ("download", "GET", "/api/files/{id}/download", None),
    ("metadata", "GET", "/api/files/{id}", None),
    ("delete", "DELETE", "/api/files/{id}", None),
    ("share-to-self", "POST", "/api/files/{id}/shares", {"username": "bob"}),
    ("list-shares", "GET", "/api/files/{id}/shares", None),
    ("distribution", "GET", "/api/files/{id}/distribution", None),
    ("verify", "POST", "/api/files/{id}/verify", None),
    ("repair", "POST", "/api/files/{id}/repair", None),
]


@pytest.mark.parametrize("op,method,path,body", OPS, ids=[o[0] for o in OPS])
def test_s03_other_users_file_is_indistinguishable_from_nonexistent(env, evidence, op, method, path, body):
    ev = evidence("S03", f"bob calls {op} on alice's file id",
                  "PEP ownership/share check; non-party denies masked as 404")
    alice = env.user("alice")
    bob = env.user("bob")
    bob_secret = env.enable_mfa(bob)
    env.step_up(bob, bob_secret)                     # even with fresh MFA: not his file
    meta = env.upload_ok(alice, payload(), filename="alice-payroll.xlsx", classification="confidential")
    real = env.req(method, path.format(id=meta["id"]), bob, json=body)
    fake = env.req(method, path.format(id=secrets.token_hex(16)), bob, json=body)
    assert real.status_code == 404 and real.json()["error"] == "not-found" and real.json()["reasons"] == []
    assert _strip(real) == _strip(fake)              # byte-identical apart from the request id
    assert MARKER not in real.content and b"alice-payroll" not in real.content
    e = env.one(real, "authz.decision")
    assert (e["outcome"], e["severity"], e["resource_id"]) == ("denied", "warning", meta["id"])
    assert "not-owner" in e["details"]["reasons"]
    f = env.one(fake, "authz.decision")
    assert (f["outcome"], f["reason"]) == ("denied", "not-found")
    # the attempt changed nothing
    assert env.download(alice, meta["id"]).status_code == 403          # alice: confidential => step-up needed
    with env.db() as db:
        from app.models import File, FileShare
        assert db.get(File, meta["id"]).status == "committed"
        assert db.query(FileShare).count() == 0
    ev.response(real)
    ev.audit(e)


def test_s03_id_guessing_reveals_nothing_and_every_guess_is_audited(env, evidence):
    ev = evidence("S03", "bob enumerates 40 random file ids + alice's real id",
                  "Unknown and foreign ids both 404; each guess is an authz.decision deny")
    alice = env.user("alice")
    bob = env.user("bob")
    meta = env.upload_ok(alice, payload())
    guesses = [secrets.token_hex(16) for _ in range(40)] + [meta["id"]]
    results = {env.req("GET", f"/api/files/{g}", bob).status_code for g in guesses}
    assert results == {404}
    listed = env.client.get("/api/files", headers=env.h(bob)).json()
    assert listed["total"] == 0                                         # no list-all across owners
    admin_list = env.client.get("/api/admin/files", headers=env.h(bob)).json()
    assert admin_list["scope"] == "own" and admin_list["total"] == 0
    bob_pseudo = env.me(bob)["audit_pseudonym"]
    denies = env.audit_events(actor=bob_pseudo, event_type="authz.decision", outcome="denied")
    assert len(denies) >= 41
    ev.result("41/41 guesses -> 404; GET /api/files total=0; /api/admin/files scope=own total=0")
    ev.audit(denies[-1])


def test_s03_grantee_access_is_scoped_and_revocable(env, evidence):
    """Sharing is explicit; revoking it takes effect on the next request."""
    ev = evidence("S03", "bob keeps using alice's file after alice revokes the share",
                  "Share row re-read on every request")
    alice = env.user("alice")
    bob = env.user("bob")
    secret = env.enable_mfa(alice)
    meta = env.upload_ok(alice, payload())
    assert env.client.post(f"/api/files/{meta['id']}/shares", headers=env.h(alice),
                           json={"username": "bob"}).status_code == 201
    assert env.download(bob, meta["id"]).status_code == 200
    # grantee cannot re-share or delete
    r = env.req("DELETE", f"/api/files/{meta['id']}", bob)
    assert r.status_code == 403 and "not-owner" in r.json()["reasons"]
    assert env.client.delete(f"/api/files/{meta['id']}/shares/bob", headers=env.h(alice)).status_code == 204
    r = env.req("GET", f"/api/files/{meta['id']}/download", bob)
    assert r.status_code == 404
    e = env.one(r, "authz.decision")
    assert e["outcome"] == "denied" and "not-owner" in e["details"]["reasons"]
    ev.response(r, "after unshare")
    ev.audit(e)
    del secret


# --------------------------------------------------------------------------- #
# scenario 4
# --------------------------------------------------------------------------- #
def _admin_ops(env, target_id: str) -> list[tuple[str, str, str, dict | None]]:
    return [
        ("role-change", "PUT", f"/api/admin/users/{target_id}/role", {"role": "admin"}),
        ("disable-user", "POST", f"/api/admin/users/{target_id}/disable", None),
        ("set-cidrs", "PUT", f"/api/admin/users/{target_id}/allowed-cidrs", {"cidrs": ["0.0.0.0/0"]}),
        ("kms-rotate", "POST", "/api/admin/kms/rotate", {"purpose": "file-dek-wrap"}),
        ("policy-write", "PUT", "/api/security/policy-settings", {"changes": {"max_downloads_in_window": 100000}}),
        ("fault-injection", "PUT", "/api/storage/faults/memory-a", {"mode": "unavailable"}),
        ("audit-retention", "POST", "/api/audit/retention", None),
        ("audit-checkpoint", "POST", "/api/audit/checkpoints", None),
        ("pseudonym-lookup", "POST", "/api/admin/pseudonym-lookup", {"pseudonym": "u_" + "0" * 32}),
    ]


@pytest.mark.parametrize("role", ["user", "auditor"])
def test_s04_admin_operations_forbidden_for_user_and_auditor(env, evidence, role):
    ev = evidence("S04", f"A {role} (with FRESH MFA) calls every admin-only operation",
                  "PDP RBAC: user:manage/kms:rotate/policy:write/storage:admin/audit:retention are admin-only")
    victim = env.register("victim")
    token = env.auditor("mallory") if role == "auditor" else env.user("mallory")
    secret = env.enable_mfa(token)
    env.step_up(token, secret)
    assert env.me(token)["mfa_fresh"] is True
    policy_before = env.client.get("/api/security/policy-settings", headers=env.h(token)).json()["version"]
    for name, method, path, body in _admin_ops(env, victim["id"]):
        r = env.req(method, path, token, json=body)
        assert r.status_code == 403, (name, r.status_code, r.text)
        assert r.json()["error"] == "access-denied" and "default-deny" in r.json()["reasons"], (name, r.json())
        assert "obligations" not in r.json()                     # no step-up would help
        e = env.one(r, "authz.decision")
        assert e["outcome"] == "denied" and e["actor_role"] == role and "default-deny" in e["details"]["reasons"]
    ev.response(r, "each of 9 admin ops")
    ev.audit(e)
    # nothing changed
    admin, _ = env.admin()
    users = {u["username"]: u for u in env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]}
    assert users["victim"]["role"] == "user" and users["victim"]["is_active"] and users["victim"]["allowed_cidrs"] == []
    assert users["mallory"]["role"] == role
    keys = env.client.get("/api/admin/kms/keys", headers=env.h(admin)).json()["keys"]
    assert all(k["version"] == 1 for k in keys if k["purpose"] == "file-dek-wrap")
    assert env.client.get("/api/security/policy-settings", headers=env.h(admin)).json()["version"] == policy_before
    assert env.client.get("/api/storage/faults", headers=env.h(admin)).json()["faults"][0]["mode"] == "none"


def test_s04_user_cannot_read_all_audit_or_verify(env, evidence):
    ev = evidence("S04", "A normal user reads everyone's audit events / runs chain verification",
                  "audit:read-all and audit:verify are auditor/admin only; read-own is forced to own pseudonym")
    alice = env.user("alice")
    bob = env.user("bob")
    env.upload_ok(bob, payload())
    bob_p = env.me(bob)["audit_pseudonym"]
    r = env.req("GET", f"/api/audit/events?actor={bob_p}&limit=1000", alice)
    assert r.status_code == 200 and r.json()["scope"] == "own"
    assert {e["actor"] for e in r.json()["events"]} == {env.me(alice)["audit_pseudonym"]}
    for method, path in (("POST", "/api/audit/verify"), ("GET", "/api/audit/stats"),
                         ("GET", "/api/admin/users"), ("GET", "/api/admin/kms/keys")):
        r = env.req(method, path, alice)
        assert r.status_code == 403, path
        e = env.one(r, "authz.decision")
        assert e["outcome"] == "denied"
    ev.response(r, "verify/stats/users/keys")
    ev.audit(e)


def test_s04_admin_cannot_read_user_file_content(env, evidence):
    ev = evidence("S04", "Admin (fresh MFA) downloads / deletes / shares a user's file",
                  "Separation of duties: admin-no-content-access constraint in the PDP")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload(), filename="alice-diary.txt")
    admin, _ = env.admin()
    assert env.me(admin)["mfa_fresh"] is True
    r = env.req("GET", f"/api/files/{meta['id']}/download", admin)
    assert r.status_code == 403 and r.json()["reasons"] == ["admin-no-content-access"]
    assert MARKER not in r.content
    e = env.one(r, "authz.decision")
    assert (e["outcome"], e["actor_role"]) == ("denied", "admin") and e["details"]["reasons"] == ["admin-no-content-access"]
    ev.response(r, "download")
    ev.audit(e)
    for method, path, body in (("DELETE", f"/api/files/{meta['id']}", None),
                               ("POST", f"/api/files/{meta['id']}/shares", {"username": "root"})):
        r = env.req(method, path, admin, json=body)
        assert r.status_code == 403 and "admin-no-content-access" in r.json()["reasons"], r.text
    # admin may see metadata, but not the (encrypted) filename
    md = env.req("GET", f"/api/files/{meta['id']}", admin).json()
    assert md["filename"] is None and md["mime_type"] is None
    lst = env.client.get("/api/admin/files", headers=env.h(admin)).json()
    assert lst["scope"] == "all" and all(f["filename"] is None for f in lst["files"])
    assert b"alice-diary" not in env.client.get("/api/admin/files", headers=env.h(admin)).content
    # admin may verify (ciphertext only) - no plaintext leaves
    v = env.req("POST", f"/api/files/{meta['id']}/verify", admin)
    assert v.status_code == 200 and MARKER not in v.content
    # admin cannot promote/modify itself (no self-escalation path)
    me = env.me(admin)["user"]["id"]
    r = env.req("PUT", f"/api/admin/users/{me}/clearance", admin, json={"clearance": "restricted"})
    assert r.status_code == 409 and r.json()["reasons"] == ["cannot-modify-self"]
    # the file is still alice's and intact
    assert env.download(alice, meta["id"]).status_code == 200
