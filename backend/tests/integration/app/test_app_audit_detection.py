"""Audit integration, privacy, detection, dashboard, metrics, admin KMS."""
from __future__ import annotations

import io
import logging
import os
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.logging_setup import JsonFormatter
from app.models import Chunk, ChunkReplica, File, FileStatus

from .conftest import ADMIN_PASSWORD, PASSWORD, chunk_keys

CHUNK = 4096


def _all_events(env) -> list[dict]:
    out, offset = [], 0
    while True:
        evs, total = env.container.audit.search(limit=1000, offset=offset, order="asc")
        out += evs
        offset += len(evs)
        if offset >= total or not evs:
            return out


def _full_flow(env) -> dict:
    """Exercise every subsystem; return the secrets used along the way."""
    secrets_seen: dict[str, list] = {"tokens": [], "refresh": [], "totp": []}
    # --- auth: register, failed logins (lockout), credential stuffing, MFA, refresh reuse, password change
    env.register("zelda_unique")
    for _ in range(5):
        env.client.post("/api/auth/login", json={"username": "zelda_unique", "password": "Wrong-Password-99"})
    env.clock.advance(15 * 60 + 1)                                   # lockout over
    for i in range(5):                                               # 5 distinct accounts from one /24
        env.client.post("/api/auth/login", json={"username": f"ghost{i}", "password": "Wrong-Password-99"})
    r = env.client.post("/api/auth/login", json={"username": "zelda_unique", "password": PASSWORD})
    token = r.json()["access_token"]
    first_refresh = env.client.cookies.get("zt_refresh")
    secrets_seen["refresh"].append(first_refresh)
    secret = env.enable_mfa(token)
    secrets_seen["totp"].append(secret)
    r = env.client.post("/api/auth/refresh")                          # rotates
    secrets_seen["refresh"].append(env.client.cookies.get("zt_refresh"))
    token = r.json()["access_token"]
    env.client.cookies.set("zt_refresh", first_refresh, domain="testserver.local", path="/api/auth")
    reuse = TestClient(env.app, base_url="https://testserver", client=("198.51.100.7", 1),
                       cookies={"zt_refresh": first_refresh})
    assert reuse.post("/api/auth/refresh").status_code == 401         # reuse -> session revoked
    env.client.cookies.clear()
    env.clock.advance(31)
    token2 = env.login("zelda_unique", totp=env.totp(secret))
    env.clock.advance(31)
    token = env.login("zelda_unique", totp=env.totp(secret))
    secrets_seen["tokens"].append(token)
    # H1: the older MFA-verified session (token2) is revoked, a newer one would be kept
    r = env.client.post("/api/auth/password", headers=env.h(token),
                        json={"current_password": PASSWORD, "new_password": "Zelda-New-Passw0rd-77"})
    assert r.status_code == 200 and r.json()["sessions_revoked"] >= 1
    del token2
    # --- files + storage: upload with a provider down (failover + health events), download with a corrupt
    #     replica, verify, repair, share, delete
    env.fault("memory-a", "unavailable")
    meta = env.upload_ok(token, b"FILE-CONTENT-MARKER " * 600, filename="tax-return-zelda.pdf")
    env.fault("memory-a", "none")
    env.container.health.check_all()
    env.fault("memory-b", "corrupt-reads")
    assert env.download(token, meta["id"]).status_code == 200
    env.fault("memory-b", "none")
    with env.db() as db:
        rep = db.execute(select(ChunkReplica).join(Chunk).where(Chunk.file_id == meta["id"])).scalars().first()
        env.providers[rep.provider].inner.put(rep.chunk_id, b"bit rot")
    env.client.post(f"/api/files/{meta['id']}/verify", headers=env.h(token))
    env.client.post(f"/api/files/{meta['id']}/repair", headers=env.h(token))
    env.register("yorick_unique")
    env.step_up(token, secret)
    assert env.client.post(f"/api/files/{meta['id']}/shares", headers=env.h(token),
                           json={"username": "yorick_unique"}).status_code == 201
    other = env.upload_ok(token, b"second", filename="other-secret-name.txt")
    assert env.client.delete(f"/api/files/{other['id']}", headers=env.h(token)).status_code == 200
    # --- detection: bulk download
    for _ in range(4):
        env.download(token, meta["id"])
    # --- admin: policy change, role change, kms rotate, fault API, checkpoint, verify, retention, re-identify
    admin, asecret = env.admin()
    secrets_seen["totp"].append(asecret)
    secrets_seen["tokens"] += [token, admin]
    assert env.client.put("/api/security/policy-settings", headers=env.h(admin),
                          json={"changes": {"block_seconds": 300, "mfa_required_actions": [
                              "policy:write", "file:delete", "file:share", "user:manage", "kms:rotate",
                              "audit:retention", "storage:admin"]}}).status_code == 200
    users = env.client.get("/api/admin/users", headers=env.h(admin)).json()["users"]
    yid = next(u["id"] for u in users if u["username"] == "yorick_unique")
    assert env.client.put(f"/api/admin/users/{yid}/role", headers=env.h(admin), json={"role": "auditor"}).status_code == 200
    assert env.client.post("/api/admin/kms/rotate", headers=env.h(admin),
                           json={"purpose": "file-dek-wrap"}).status_code == 200
    assert env.client.put("/api/storage/faults/memory-c", headers=env.h(admin),
                          json={"mode": "slow", "delay": 0}).status_code == 200
    assert env.client.delete("/api/storage/faults/memory-c", headers=env.h(admin)).status_code == 200
    pseudo = env.client.get("/api/auth/me", headers=env.h(token)).json()["audit_pseudonym"]
    assert env.client.post("/api/admin/pseudonym-lookup", headers=env.h(admin),
                           json={"pseudonym": pseudo}).json()["user"]["username"] == "zelda_unique"
    assert env.client.post("/api/audit/checkpoints", headers=env.h(admin)).status_code == 201
    assert env.client.post("/api/audit/retention", headers=env.h(admin)).status_code == 200
    v = env.client.post("/api/audit/verify", headers=env.h(admin))
    assert v.status_code == 200
    secrets_seen["file_id"] = meta["id"]
    return secrets_seen


def test_no_audit_detail_dropped_across_subsystems_and_chain_verifies(make_env):
    env = make_env(rate_limit_login_per_minute=1000, detect_max_downloads_in_window=3)
    _full_flow(env)
    events = _all_events(env)
    types = {e["event_type"] for e in events}
    expected = {"auth.register", "auth.login", "auth.lockout", "auth.mfa_enroll", "auth.mfa_activate",
                "auth.refresh", "auth.refresh_reuse", "auth.password_change", "auth.mfa_verify",
                "authz.decision", "policy.change", "chunk.distribute", "chunk.retrieve", "chunk.repair",
                "storage.replica.corrupt", "storage.provider.health", "storage.fault.set",
                "file.upload", "chunk.create", "file.download", "file.verify", "file.repair", "file.share",
                "file.delete", "security.anomaly.bulk-download", "security.anomaly.auth-failures",
                "admin.user.role", "admin.kms.rotate", "audit.reidentify", "audit.checkpoint",
                "audit.retention", "auth.bootstrap_admin"}
    assert expected <= types, expected - types
    dropped = [(e["event_type"], e["details"]) for e in events if "_dropped" in (e["details"] or {})]
    assert dropped == []
    # the keys that the subsystem reports said must survive did survive
    by = {t: [e for e in events if e["event_type"] == t] for t in types}
    assert {"failed_count", "lockout_seconds"} <= set(by["auth.lockout"][0]["details"])
    assert "sessions_revoked" in by["auth.password_change"][-1]["details"]
    pc = by["policy.change"][0]["details"]
    assert pc["version"] == 1 and pc["changes"]["block_seconds"] == "600 -> 300"
    assert {"healthy", "state", "previous_state", "consecutive_failures", "injected"} <= \
        set(by["storage.provider.health"][0]["details"])
    assert "outcomes" in by["chunk.retrieve"][0]["details"]
    assert {"block_seconds", "count", "threshold"} <= set(by["security.anomaly.bulk-download"][0]["details"])
    assert "distinct_accounts" in by["security.anomaly.auth-failures"][0]["details"]
    assert {"files_rewrapped", "rewrap_failures"} <= set(by["admin.kms.rotate"][0]["details"])
    # whole chain (incl. signed checkpoints and their provider anchors) verifies
    report = env.container.audit.verify_chain()
    assert report.ok, report.to_dict()
    assert report.checkpoints_checked >= 1 and report.anchors_checked >= 3


def test_no_secret_in_audit_db_or_app_log(make_env):
    env = make_env(rate_limit_login_per_minute=1000, detect_max_downloads_in_window=3)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    loggers = [logging.getLogger(n) for n in ("zt", "app")]
    for lg in loggers:
        lg.addHandler(handler)
    try:
        seen = _full_flow(env)
    finally:
        for lg in loggers:
            lg.removeHandler(handler)
    needles = [PASSWORD, ADMIN_PASSWORD, "Zelda-New-Passw0rd-77", "Wrong-Password-99", "zelda_unique",
               "yorick_unique", "tax-return-zelda", "other-secret-name", "FILE-CONTENT-MARKER"]
    needles += [t for t in seen["tokens"] if t] + [t for t in seen["refresh"] if t] + seen["totp"]
    needles += [t.split(".")[2][:20] for t in seen["tokens"]]           # token signature fragments
    export = "".join(env.container.audit.export_ndjson())
    with env.container.audit.engine.connect() as conn:
        cps = repr(conn.exec_driver_sql("SELECT * FROM audit_checkpoints").fetchall())
    db_path = Path(env.settings.audit_database_url.split("///", 1)[1])
    raw = b"".join(p.read_bytes() for p in db_path.parent.glob(db_path.name + "*"))
    logs = buf.getvalue()
    assert '"request"' in logs or "request" in logs
    for n in needles:
        assert n not in export, n
        assert n not in cps, n
        assert n.encode() not in raw, n
        assert n not in logs, n


def test_audit_scope_own_vs_all(env):
    alice = env.user("alice")
    bob = env.user("bob")
    env.upload_ok(bob, b"bob's")
    bob_pseudo = env.client.get("/api/auth/me", headers=env.h(bob)).json()["audit_pseudonym"]
    me = env.client.get("/api/auth/me", headers=env.h(alice)).json()["audit_pseudonym"]
    r = env.client.get(f"/api/audit/events?actor={bob_pseudo}&limit=1000", headers=env.h(alice)).json()
    assert r["scope"] == "own" and r["events"] and {e["actor"] for e in r["events"]} == {me}
    bob_seq = env.client.get("/api/audit/events?limit=1", headers=env.h(bob)).json()["events"][0]["seq"]
    assert env.client.get(f"/api/audit/events/{bob_seq}", headers=env.h(alice)).status_code == 404
    export = env.client.get("/api/audit/export", headers=env.h(alice))
    assert export.status_code == 200 and bob_pseudo not in export.text and me in export.text
    assert env.client.post("/api/audit/verify", headers=env.h(alice)).status_code == 403
    admin, _ = env.admin()
    r = env.client.get(f"/api/audit/events?actor={bob_pseudo}", headers=env.h(admin)).json()
    assert r["scope"] == "all" and {e["actor"] for e in r["events"]} == {bob_pseudo}


def test_checkpoints_are_anchored_on_every_provider(env):
    admin, _ = env.admin()
    cp = env.client.post("/api/audit/checkpoints", headers=env.h(admin)).json()
    assert cp["anchors"] == {"memory-a": True, "memory-b": True, "memory-c": True}
    for p in env.providers.values():
        keys = list(p.inner.list_keys("anchors/audit/"))
        assert f"anchors/audit/{env.container.audit.log_id}/checkpoint-{cp['seq']:012d}.json" in keys
    listed = env.client.get("/api/audit/checkpoints", headers=env.h(admin)).json()["checkpoints"]
    assert listed[0]["seq"] == cp["seq"]
    rep = env.client.post("/api/audit/verify", headers=env.h(admin), json={}).json()
    assert rep["ok"] is True and rep["anchors_checked"] >= 3


def test_bulk_download_detection_blocks_then_audits(make_env):
    env = make_env(detect_max_downloads_in_window=3)
    token = env.user("alice")
    meta = env.upload_ok(token, b"x" * 1000)
    for _ in range(3):
        assert env.download(token, meta["id"]).status_code == 200
    r = env.download(token, meta["id"])
    assert r.status_code == 403 and r.json()["reasons"] == ["download-rate-exceeded"]
    ev = env.audit_events(event_type="security.anomaly.bulk-download")
    assert len(ev) == 1 and ev[0]["severity"] == "critical" and ev[0]["details"]["count"] == 4
    assert env.download(token, meta["id"]).status_code == 403            # still blocked, not re-audited
    assert len(env.audit_events(event_type="security.anomaly.bulk-download")) == 1
    blocks = env.client.get("/api/security/anomaly-blocks", headers=env.h(token)).json()
    assert blocks["scope"] == "own" and len(blocks["blocks"]) == 1
    sec = env.client.get("/api/security/events", headers=env.h(token)).json()["events"]
    assert any(e["event_type"] == "security.anomaly.bulk-download" for e in sec)
    env.clock.advance(601)                                                # block expired
    token = env.login("alice")
    assert env.download(token, meta["id"]).status_code == 200


def test_admin_can_lift_block(make_env):
    env = make_env(detect_max_downloads_in_window=1)
    token = env.user("alice")
    uid = env.client.get("/api/auth/me", headers=env.h(token)).json()["user"]["id"]
    meta = env.upload_ok(token, b"x")
    env.download(token, meta["id"])
    assert env.download(token, meta["id"]).status_code == 403
    admin, _ = env.admin()
    blocks = env.client.get("/api/security/anomaly-blocks", headers=env.h(admin)).json()["blocks"]
    assert blocks[0]["user_id"] == uid and blocks[0]["username"] == "alice"
    assert env.client.delete(f"/api/security/anomaly-blocks/{uid}", headers=env.h(admin)).status_code == 204
    assert env.audit_events(event_type="security.block.lift")


def test_credential_stuffing_alert(env):
    for i in range(6):
        env.client.post("/api/auth/login", json={"username": f"victim{i}", "password": "Wrong-Password-99"})
    ev = env.audit_events(event_type="security.anomaly.auth-failures")
    assert len(ev) == 1 and ev[0]["severity"] == "critical"
    assert ev[0]["source_net"] == "198.51.100.0/24" and ev[0]["details"]["distinct_accounts"] == 5


def test_dashboard_numbers_equal_real_counts(env):
    token = env.user("alice")
    secret = env.enable_mfa(token)
    sizes = [100, 5000, 9000, 0]
    metas = [env.upload_ok(token, os.urandom(s)) for s in sizes]
    env.step_up(token, secret)
    assert env.client.delete(f"/api/files/{metas[0]['id']}", headers=env.h(token)).status_code == 200
    env.fault("memory-a", "unavailable")
    env.fault("memory-b", "unavailable")
    assert env.upload(token, os.urandom(10)).status_code == 502
    env.fault("memory-a", "none")
    env.fault("memory-b", "none")
    bob = env.user("bob")
    env.upload_ok(bob, os.urandom(4096 * 2))

    dash = env.client.get("/api/dashboard", headers=env.h(token)).json()
    assert dash["scope"] == "own"
    with env.db() as db:
        uid = db.get(File, metas[1]["id"]).owner_id
        q = select(func.count(), func.sum(File.size_bytes), func.sum(File.chunk_count)).where(
            File.owner_id == uid, File.status == FileStatus.COMMITTED)
        n, size, chunks = db.execute(q).one()
        per = dict(db.execute(select(ChunkReplica.provider, func.count()).join(Chunk).join(File).where(
            File.owner_id == uid, File.status == FileStatus.COMMITTED, ChunkReplica.status == "stored")
            .group_by(ChunkReplica.provider)).all())
        failed = db.execute(select(func.count()).select_from(File).where(
            File.owner_id == uid, File.status == FileStatus.FAILED)).scalar_one()
    assert (dash["files"]["count"], dash["files"]["bytes"], dash["files"]["chunks"]) == (3, 14000, size and chunks)
    assert n == 3 and size == 14000
    assert dash["files"]["by_status"]["deleted"] == 1 and dash["files"]["by_status"]["failed"] == failed == 1
    assert {p: d["replicas"] for p, d in dash["distribution"].items() if d["replicas"]} == per
    assert sum(per.values()) == 2 * chunks
    me = env.client.get("/api/auth/me", headers=env.h(token)).json()["audit_pseudonym"]
    for outcome in ("success", "failure", "denied", "error"):
        _, total = env.container.audit.search(actor=me, outcome=outcome, limit=1)
        assert dash["operations"]["by_outcome"][outcome] == total
    assert dash["providers_total"] == 3 and dash["providers_available"] == 3
    # admin sees the global scope, equal to the whole DB
    admin, _ = env.admin()
    g = env.client.get("/api/dashboard", headers=env.h(admin)).json()
    with env.db() as db:
        n_all = db.execute(select(func.count()).select_from(File).where(File.status == FileStatus.COMMITTED)).scalar_one()
    assert g["scope"] == "all" and g["files"]["count"] == n_all == 4
    st = env.container.audit.stats()
    assert g["operations"]["by_outcome"]["success"] <= st["by_outcome"]["success"]
    dist = env.client.get("/api/storage/distribution", headers=env.h(admin)).json()
    assert dist["files"] == 4


def test_metrics_endpoint_access(make_env):
    scrape = "s" * 40
    env = make_env(metrics_token=scrape)
    token = env.user("alice")
    assert env.client.get("/metrics").status_code == 401
    assert env.client.get("/metrics", headers=env.h(token)).status_code == 403
    admin, _ = env.admin()
    r = env.client.get("/metrics", headers=env.h(admin))
    assert r.status_code == 200 and "zt_files_committed 0" in r.text and "zt_provider_healthy" in r.text
    local = TestClient(env.app, base_url="https://testserver", client=("127.0.0.1", 1))
    assert local.get("/metrics").status_code == 401                     # L5: loopback is not trusted
    r = local.get("/metrics", headers={"Authorization": f"Bearer {scrape}"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert local.get("/metrics", headers={"Authorization": "Bearer " + "t" * 40}).status_code == 401


def test_kms_rotation_rewraps_existing_files(env):
    token = env.user("alice")
    data = os.urandom(3 * CHUNK)
    metas = [env.upload_ok(token, data) for _ in range(3)]
    admin, _ = env.admin()
    keys = env.client.get("/api/admin/kms/keys", headers=env.h(admin)).json()["keys"]
    assert all("material" not in k for k in keys)
    r = env.client.post("/api/admin/kms/rotate", headers=env.h(admin), json={"purpose": "file-dek-wrap"}).json()
    assert r["version"] == 2 and r["files_rewrapped"] == 3 and r["rewrap_failures"] == 0
    with env.db() as db:
        assert {db.get(File, m["id"]).kek_version for m in metas} == {2}
    for m in metas:
        assert env.download(token, m["id"]).content == data
    assert env.upload_ok(token, b"new")["status"] == "committed"


def test_health_and_storage_views(env):
    token = env.user("alice")
    assert env.client.get("/api/health").json() == {"status": "ok", "database": True}
    p = env.client.get("/api/storage/providers", headers=env.h(token)).json()
    assert [x["provider"] for x in p["providers"]] == ["memory-a", "memory-b", "memory-c"]
    assert p["replication_factor"] == 2 and p["fault_injection_enabled"] is True
    env.upload_ok(token, b"x" * 100)
    m = env.client.get("/api/storage/metrics", headers=env.h(token)).json()
    assert "counters" in m and m["counters"]
    assert env.client.get("/api/storage/faults", headers=env.h(token)).status_code == 403


def test_fault_routes_absent_when_disabled(make_env):
    env = make_env(enable_fault_injection=False)
    admin, _ = env.admin()
    assert env.client.get("/api/storage/faults", headers=env.h(admin)).status_code == 404


def test_audit_db_is_separate_from_metadata_db(env):
    meta = Path(env.settings.database_url.split("///", 1)[1])
    aud = Path(env.settings.audit_database_url.split("///", 1)[1])
    assert meta != aud
    with sqlite3.connect(meta) as c:
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "audit_events" not in tables and "files" in tables
    assert not chunk_keys(env.providers["memory-a"])
