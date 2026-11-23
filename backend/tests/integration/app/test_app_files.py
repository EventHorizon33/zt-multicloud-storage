"""Upload / download / delete / share through the integrated API."""
from __future__ import annotations

import hashlib
import os
import threading

import pytest
from sqlalchemy import select

from app.models import Chunk, ChunkReplica, File, FileStatus

from .conftest import chunk_keys

CHUNK = 4096


@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 17])
def test_round_trip_sizes(env, size):
    token = env.user("alice")
    data = os.urandom(size)
    meta = env.upload_ok(token, data, filename="data.bin")
    assert meta["status"] == "committed" and meta["size_bytes"] == size
    assert meta["chunk_count"] == max(1, -(-size // CHUNK))
    r = env.download(token, meta["id"])
    assert r.status_code == 200
    assert r.content == data
    assert r.headers["x-content-sha256"] == hashlib.sha256(data).hexdigest()
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-length"] == str(size)


def test_round_trip_5mib_random_binary(make_env):
    env = make_env(chunk_size_bytes=64 * 1024)
    token = env.user("alice")
    data = os.urandom(5 * 1024 * 1024)
    meta = env.upload_ok(token, data, filename="big.bin")
    assert meta["chunk_count"] == 80
    r = env.download(token, meta["id"])
    assert r.status_code == 200 and hashlib.sha256(r.content).digest() == hashlib.sha256(data).digest()


def test_duplicate_uploads_are_distinct_files(env):
    token = env.user("alice")
    data = b"same content " * 1000
    a = env.upload_ok(token, data, filename="x.txt")
    b = env.upload_ok(token, data, filename="x.txt")
    assert a["id"] != b["id"]
    with env.db() as db:
        ca = set(db.execute(select(Chunk.id).where(Chunk.file_id == a["id"])).scalars())
        cb = set(db.execute(select(Chunk.id).where(Chunk.file_id == b["id"])).scalars())
        sa = set(db.execute(select(Chunk.ciphertext_sha256).where(Chunk.file_id == a["id"])).scalars())
        sb = set(db.execute(select(Chunk.ciphertext_sha256).where(Chunk.file_id == b["id"])).scalars())
    assert not (ca & cb) and not (sa & sb)          # fresh DEK, ids and nonces per file
    assert env.download(token, a["id"]).content == env.download(token, b["id"]).content == data
    assert len(env.client.get("/api/files", headers=env.h(token)).json()["files"]) == 2


def test_concurrent_uploads(env):
    token = env.user("alice")
    payloads = [os.urandom(3 * CHUNK + i) for i in range(8)]
    results: dict[int, dict] = {}
    errors = []

    def go(i):
        try:
            results[i] = env.upload_ok(token, payloads[i], filename=f"f{i}.bin")
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(repr(exc))

    threads = [threading.Thread(target=go, args=(i,)) for i in range(len(payloads))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len({r["id"] for r in results.values()}) == len(payloads)
    for i, meta in results.items():
        assert env.download(token, meta["id"]).content == payloads[i]


def test_classification_default_choice_and_clearance(env):
    token = env.user("alice")
    assert env.upload_ok(token, b"x")["classification"] == "internal"
    assert env.upload_ok(token, b"x", classification="public")["classification"] == "public"
    r = env.client.post("/api/files?classification=confidential", headers=env.h(token),
                        files={"file": ("q.txt", b"q", "text/plain")})
    assert r.status_code == 201 and r.json()["classification"] == "confidential"
    r = env.upload(token, b"x", classification="top-secret")
    assert r.status_code == 422 and r.json()["reasons"] == ["invalid-classification"]
    r = env.upload(token, b"x", classification="restricted")       # above clearance "confidential"
    assert r.status_code == 403 and r.json()["reasons"] == ["insufficient-clearance"]
    # confidential downloads need MFA
    conf = env.upload_ok(token, b"secret stuff", classification="confidential")
    r = env.download(token, conf["id"])
    assert r.status_code == 403 and "mfa-required" in r.json()["reasons"]


def test_upload_validation(env):
    token = env.user("alice")
    r = env.client.post("/api/files", headers=env.h(token), json={"x": 1})
    assert r.status_code == 422 and r.json()["reasons"] == ["multipart-required"]
    r = env.client.post("/api/files", headers=env.h(token), data={"classification": "internal"},
                        files={"other": ("a", b"a")})
    assert r.status_code == 422 and r.json()["reasons"] == ["file-missing"]
    r = env.upload(token, b"x", filename="../../")
    assert r.status_code == 422 and r.json()["reasons"] == ["invalid-filename"]
    meta = env.upload_ok(token, b"x", filename="../../etc/passwd", mime="text/html; charset=utf-8")
    assert meta["filename"] == "passwd" and meta["mime_type"] == "text/html"


def test_upload_too_large_is_413_and_cleaned_up(make_env):
    env = make_env(max_upload_bytes=10 * CHUNK)
    token = env.user("alice")
    r = env.upload(token, os.urandom(10 * CHUNK + 1))
    assert r.status_code == 413
    with env.db() as db:
        row = db.execute(select(File)).scalar_one()
        assert row.status == FileStatus.FAILED and row.failure_reason == "upload-too-large"
        assert row.wrapped_dek is None
    assert all(chunk_keys(p) == [] for p in env.providers.values())


def test_hostile_filename_content_disposition(env):
    token = env.user("alice")
    name = 'evil"; filename=x.html\r\nSet-Cookie: a=b;‮gnp.exe'
    meta = env.upload_ok(token, b"hi", filename=name)
    r = env.download(token, meta["id"])
    cd = r.headers["content-disposition"]
    assert "\r" not in cd and "\n" not in cd and "set-cookie" not in {k.lower() for k in r.headers}
    assert cd.startswith('attachment; filename="') and cd.count('"') == 2
    assert "filename*=UTF-8''" in cd


def test_other_user_gets_404_and_deny_is_audited(env):
    owner = env.user("alice")
    meta = env.upload_ok(owner, b"private")
    mallory = env.user("mallory")
    for path in ("", "/download", "/distribution"):
        r = env.client.get(f"/api/files/{meta['id']}{path}", headers=env.h(mallory))
        assert r.status_code == 404 and r.json()["error"] == "not-found"
    assert env.client.delete(f"/api/files/{meta['id']}", headers=env.h(mallory)).status_code == 404
    unknown = env.client.get("/api/files/" + "0" * 32 + "/download", headers=env.h(mallory))
    assert unknown.status_code == 404 and unknown.json()["reasons"] == []
    denies = env.audit_events(event_type="authz.decision", outcome="denied", resource_id=meta["id"])
    assert any(e["reason"] == "not-owner" and e["action"] == "file:read" for e in denies)
    unk = env.audit_events(event_type="authz.decision", outcome="denied", resource_id="0" * 32)
    assert unk and unk[0]["reason"] == "not-found"
    assert env.client.get("/api/files", headers=env.h(mallory)).json()["files"] == []


def test_admin_cannot_download_others_file(env):
    owner = env.user("alice")
    meta = env.upload_ok(owner, b"payroll")
    admin, _ = env.admin()
    r = env.download(admin, meta["id"])
    assert r.status_code == 403 and r.json()["reasons"] == ["admin-no-content-access"]
    assert b"payroll" not in r.content
    m = env.client.get(f"/api/files/{meta['id']}", headers=env.h(admin))
    assert m.status_code == 200 and m.json()["filename"] is None      # metadata, never names
    listing = env.client.get("/api/admin/files", headers=env.h(admin)).json()
    assert listing["total"] == 1 and listing["files"][0]["filename"] is None
    assert env.client.delete(f"/api/files/{meta['id']}", headers=env.h(admin)).status_code == 403
    v = env.client.post(f"/api/files/{meta['id']}/verify", headers=env.h(admin))
    assert v.status_code == 200 and v.json()["healthy"] is True


def test_delete_requires_fresh_mfa_and_crypto_shreds(env):
    token = env.user("alice")
    data = b"MARKER-" * 2000
    meta = env.upload_ok(token, data)
    r = env.client.delete(f"/api/files/{meta['id']}", headers=env.h(token))
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-required"]
    assert r.json()["obligations"] == ["step-up-mfa", "enroll-mfa"]
    secret = env.enable_mfa(token)
    env.clock.advance(601)                       # MFA now stale; refresh keeps the session
    token = env.client.post("/api/auth/refresh").json()["access_token"]
    r = env.client.delete(f"/api/files/{meta['id']}", headers=env.h(token))
    assert r.status_code == 403 and r.json()["reasons"] == ["mfa-stale"]
    env.step_up(token, secret)
    with env.db() as db:
        chunk_ids = list(db.execute(select(Chunk.id).where(Chunk.file_id == meta["id"])).scalars())
        assert db.get(File, meta["id"]).wrapped_dek
    r = env.client.delete(f"/api/files/{meta['id']}", headers=env.h(token))
    assert r.status_code == 200 and r.json() == {"file_id": meta["id"], "status": "deleted", "leftover_replicas": 0}
    with env.db() as db:
        row = db.get(File, meta["id"])
        assert row.status == FileStatus.DELETED and row.deleted_at is not None
        assert row.wrapped_dek is None and row.enc_metadata is None and row.manifest_json is None
        assert {r.status for r in db.execute(select(ChunkReplica)).scalars()} == {"deleted"}
    for p in env.providers.values():
        assert not set(chunk_keys(p)) & set(chunk_ids)
    assert env.download(token, meta["id"]).status_code == 404
    assert env.client.get(f"/api/files/{meta['id']}", headers=env.h(token)).status_code == 404


def test_delete_with_provider_down_still_shreds_and_records_leftovers(env):
    token = env.user("alice")
    secret = env.enable_mfa(token)
    meta = env.upload_ok(token, os.urandom(3 * CHUNK))
    env.fault("memory-b", "unavailable")
    r = env.client.delete(f"/api/files/{meta['id']}", headers=env.h(token))
    assert r.status_code == 200 and r.json()["leftover_replicas"] > 0
    with env.db() as db:
        assert db.get(File, meta["id"]).wrapped_dek is None
        left = db.execute(select(ChunkReplica).where(ChunkReplica.status == "failed")).scalars().all()
        assert left and {x.provider for x in left} == {"memory-b"}
    env.fault("memory-b", "none")
    out = env.container.run_maintenance()
    assert out["leftovers_removed"] == r.json()["leftover_replicas"]
    assert chunk_keys(env.providers["memory-b"]) == []
    del secret


def test_ciphertext_on_providers_has_no_plaintext(env):
    token = env.user("alice")
    marker = b"PLAINTEXT-MARKER-0123456789"
    filename = "quarterly-secret-report.xlsx"
    env.upload_ok(token, marker * 500, filename=filename)
    env.upload_ok(token, marker, filename=filename)
    seen = 0
    for p in env.providers.values():
        inner = p.inner
        for key in inner.list_keys(""):
            blob = inner.get(key)
            seen += 1
            assert marker not in blob and marker[:12] not in blob
            assert filename.encode() not in blob and b"alice" not in blob
    assert seen >= 4


def test_share_flow(env):
    owner = env.user("alice")
    secret = env.enable_mfa(owner)
    bob = env.user("bob")
    meta = env.upload_ok(owner, b"shared data", filename="s.txt")
    r = env.client.post(f"/api/files/{meta['id']}/shares", headers=env.h(owner), json={"username": "BOB"})
    assert r.status_code == 201 and r.json()["username"] == "bob"
    for bad in ("nobody", "alice"):
        r = env.client.post(f"/api/files/{meta['id']}/shares", headers=env.h(owner), json={"username": bad})
        assert r.status_code == 422 and r.json()["reasons"] == ["share-target-invalid"]
    assert env.download(bob, meta["id"]).content == b"shared data"
    listed = env.client.get("/api/files", headers=env.h(bob)).json()["files"]
    assert [f["shared_with_me"] for f in listed] == [True] and listed[0]["filename"] == "s.txt"
    assert env.client.delete(f"/api/files/{meta['id']}", headers=env.h(bob)).status_code == 403
    assert env.client.get(f"/api/files/{meta['id']}/shares", headers=env.h(owner)).json()["shares"][0]["username"] == "bob"
    assert env.client.delete(f"/api/files/{meta['id']}/shares/bob", headers=env.h(owner)).status_code == 204
    assert env.download(bob, meta["id"]).status_code == 404
    ev = env.audit_events(event_type="file.share", outcome="success")
    assert ev and ev[0]["details"]["target_user"].startswith("u_")
    del secret


def test_distribution_view(env):
    token = env.user("alice")
    meta = env.upload_ok(token, os.urandom(5 * CHUNK))
    d = env.client.get(f"/api/files/{meta['id']}/distribution", headers=env.h(token)).json()
    assert d["chunk_count"] == 5 and d["replication_factor"] == 2 and len(d["chunks"]) == 5
    assert all(len(c["replicas"]) == 2 and {r["status"] for r in c["replicas"]} == {"stored"} for c in d["chunks"])
    assert sum(d["providers"].values()) == 10
    for c in d["chunks"]:
        for rep in c["replicas"]:
            assert c["chunk_id"] in chunk_keys(env.providers[rep["provider"]])


def test_large_download_spools_to_unlinked_tempfile(env):
    token = env.user("alice")
    env.container.files.spool_threshold_bytes = 1024          # force rollover to disk
    data = os.urandom(20 * CHUNK)
    meta = env.upload_ok(token, data)
    spool_dir = env.settings.data_dir / "tmp"
    r = env.download(token, meta["id"])
    assert r.status_code == 200 and r.content == data
    assert list(spool_dir.iterdir()) == []                     # temp file was never linked / is gone
    # a failed download releases nothing and leaves nothing behind
    for name in ("memory-a", "memory-b", "memory-c"):
        env.fault(name, "corrupt-reads")
    r = env.download(token, meta["id"])
    assert r.status_code == 409 and data[:64] not in r.content
    assert list(spool_dir.iterdir()) == []
