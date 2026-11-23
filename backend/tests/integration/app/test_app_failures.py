"""Failure handling: provider outages, corruption, tampering, crash recovery."""
from __future__ import annotations

import json
import os
from datetime import timedelta

from sqlalchemy import select, update

from app.contracts import ProviderUnavailable
from app.models import Chunk, ChunkReplica, File, FileStatus, User
from app.storage import FaultInjectingProvider
from app.storage.memory import MemoryProvider

from .conftest import PROVIDERS, chunk_keys

CHUNK = 4096


def _chunks(env, file_id):
    with env.db() as db:
        return [(c.id, c.index, sorted(r.provider for r in c.replicas))
                for c in db.execute(select(Chunk).where(Chunk.file_id == file_id).order_by(Chunk.index)).scalars()]


def _assert_failed_and_clean(env, token, file_id=None):
    with env.db() as db:
        rows = db.execute(select(File)).scalars().all()
        assert len(rows) == 1
        row = rows[0]
        assert row.status == FileStatus.FAILED and row.failure_reason == "storage-unavailable"
        assert row.wrapped_dek is None and row.manifest_json is None and row.enc_metadata is None
    for p in env.providers.values():
        assert chunk_keys(p) == [], f"objects left on {p.name}"
    listed = env.client.get("/api/files", headers=env.h(token)).json()["files"]
    assert [f["status"] for f in listed] == ["failed"] and listed[0]["filename"] is None
    r = env.download(token, row.id)
    assert r.status_code == 403 and r.json()["reasons"] == ["file-not-available"]
    ev = env.audit_events(event_type="file.upload")
    assert ev[-1]["outcome"] == "error" and ev[-1]["reason"] == "storage-unavailable"
    return row


def test_upload_fails_cleanly_when_two_providers_down(env):
    token = env.user("alice")
    env.fault("memory-a", "unavailable")
    env.fault("memory-b", "unavailable")
    r = env.upload(token, os.urandom(5 * CHUNK))
    assert r.status_code == 502 and r.json()["error"] == "upload-failed"
    _assert_failed_and_clean(env, token)
    dash = env.client.get("/api/dashboard", headers=env.h(token)).json()
    assert dash["files"]["count"] == 0 and dash["files"]["by_status"]["failed"] == 1


class _DiesAfter(MemoryProvider):
    """Accepts ``after`` puts, then behaves like an outage."""

    def __init__(self, name: str, after: int) -> None:
        super().__init__(name)
        self.after, self.puts = after, 0

    def put(self, key, data, metadata=None):
        if not key.startswith("anchors/"):
            self.puts += 1
            if self.puts > self.after:
                raise ProviderUnavailable("down", provider=self.name)
        return super().put(key, data, metadata)


def test_mid_upload_failure_removes_already_stored_chunks(make_env):
    providers = {
        "memory-a": FaultInjectingProvider(_DiesAfter("memory-a", 3), sleep=lambda s: None),
        "memory-b": FaultInjectingProvider(_DiesAfter("memory-b", 3), sleep=lambda s: None),
        "memory-c": FaultInjectingProvider(MemoryProvider("memory-c"), sleep=lambda s: None),
    }
    env = make_env(providers=providers)
    token = env.user("alice")
    r = env.upload(token, os.urandom(12 * CHUNK))
    assert r.status_code == 502
    with env.db() as db:
        stored = db.execute(select(ChunkReplica)).scalars().all()
        assert stored and all(x.status == "deleted" for x in stored)   # some chunks had been stored
    _assert_failed_and_clean(env, token)


def test_read_served_from_replica_when_provider_down(env):
    token = env.user("alice")
    data = os.urandom(6 * CHUNK)
    meta = env.upload_ok(token, data)
    for name in PROVIDERS:
        env.fault(name, "unavailable")
        r = env.download(token, meta["id"])
        assert r.status_code == 200 and r.content == data, name
        env.fault(name, "none")
    env.fault("memory-a", "timeout")
    assert env.download(token, meta["id"]).content == data


def test_corrupted_replica_served_from_other_and_critical_audit(env):
    token = env.user("alice")
    data = os.urandom(6 * CHUNK)
    meta = env.upload_ok(token, data)
    env.fault("memory-a", "corrupt-reads")
    r = env.download(token, meta["id"])
    assert r.status_code == 200 and r.content == data
    crit = env.audit_events(event_type="storage.replica.corrupt")
    assert crit and all(e["severity"] == "critical" for e in crit)
    assert {e["details"]["provider"] for e in crit} == {"memory-a"}
    with env.db() as db:
        statuses = {(x.provider, x.status) for x in db.execute(select(ChunkReplica)).scalars()}
    assert ("memory-a", "corrupt") in statuses


def test_all_replicas_corrupt_is_409_without_content(env):
    token = env.user("alice")
    marker = b"TOP-SECRET-PLAINTEXT"
    meta = env.upload_ok(token, marker * 100)
    for name in PROVIDERS:
        env.fault(name, "corrupt-reads")
    r = env.download(token, meta["id"])
    assert r.status_code == 409 and r.headers["content-type"].startswith("application/json")
    assert r.json()["error"] == "integrity-failure" and r.json()["reasons"] == ["all-replicas-corrupt"]
    assert marker not in r.content
    ev = env.audit_events(event_type="file.integrity")
    assert ev and ev[-1]["severity"] == "critical"
    assert env.audit_events(event_type="file.download")[-1]["outcome"] == "failure"


def test_partially_corrupt_last_chunk_never_partially_delivered(env):
    """Chunks 0..n-2 are fine; the last chunk has no valid replica. The client
    must get an error, not the first n-1 chunks (verify-then-release)."""
    token = env.user("alice")
    meta = env.upload_ok(token, os.urandom(4 * CHUNK))
    last_id, _, reps = _chunks(env, meta["id"])[-1]
    for p in reps:
        env.providers[p].inner.put(last_id, os.urandom(CHUNK + 28))
    r = env.download(token, meta["id"])
    assert r.status_code == 409 and len(r.content) < 300


def test_missing_chunk_everywhere_is_503(env):
    token = env.user("alice")
    meta = env.upload_ok(token, os.urandom(3 * CHUNK))
    cid, _, reps = _chunks(env, meta["id"])[1]
    for p in reps:
        env.providers[p].inner.delete(cid)
    r = env.download(token, meta["id"])
    assert r.status_code == 503 and r.json()["error"] == "data-unavailable"
    assert env.audit_events(event_type="storage.replica.missing")


def _tamper(env, file_id, **values):
    with env.db() as db:
        db.execute(update(File).where(File.id == file_id).values(**values))
        db.commit()


def test_tampered_manifest_is_409(env):
    token = env.user("alice")
    meta = env.upload_ok(token, os.urandom(3 * CHUNK))
    with env.db() as db:
        mj = db.get(File, meta["id"]).manifest_json
    _tamper(env, meta["id"], manifest_json=mj.replace('"size_bytes":', '"size_bytes":1', 1))
    r = env.download(token, meta["id"])
    assert r.status_code == 409 and r.json()["error"] == "manifest-integrity-failure"
    assert r.json()["reasons"] == ["manifest-mac-invalid"]
    assert env.audit_events(event_type="file.integrity")[-1]["severity"] == "critical"
    # verify / repair refuse as well
    assert env.client.post(f"/api/files/{meta['id']}/verify", headers=env.h(token)).status_code == 409


def test_swapped_manifest_entries_is_409(env):
    token = env.user("alice")
    meta = env.upload_ok(token, os.urandom(3 * CHUNK))
    with env.db() as db:
        m = json.loads(db.get(File, meta["id"]).manifest_json)
    m["chunks"][0], m["chunks"][1] = m["chunks"][1], m["chunks"][0]
    m["chunks"][0]["i"], m["chunks"][1]["i"] = 0, 1
    _tamper(env, meta["id"], manifest_json=json.dumps(m, sort_keys=True, separators=(",", ":")))
    r = env.download(token, meta["id"])
    assert r.status_code == 409


def test_manifest_and_key_swapped_between_files_is_409(env):
    token = env.user("alice")
    a = env.upload_ok(token, b"a" * 5000)
    b = env.upload_ok(token, b"b" * 5000)
    with env.db() as db:
        rb = db.get(File, b["id"])
        mj, mac, dek = rb.manifest_json, rb.manifest_mac, rb.wrapped_dek
    _tamper(env, a["id"], manifest_json=mj, manifest_mac=mac)
    assert env.download(token, a["id"]).status_code == 409
    _tamper(env, a["id"], wrapped_dek=dek)
    r = env.download(token, a["id"])
    assert r.status_code == 409 and r.json()["reasons"] == ["key-unwrap-failed"]


def test_owner_changed_in_db_fails(env):
    alice = env.user("alice")
    bob = env.user("bob")
    meta = env.upload_ok(alice, b"alice's data" * 100)
    with env.db() as db:
        bob_id = db.execute(select(User.id).where(User.username == "bob")).scalar_one()
    _tamper(env, meta["id"], owner_id=bob_id)
    r = env.download(bob, meta["id"])
    assert r.status_code == 409 and r.json()["reasons"] == ["key-unwrap-failed"]
    assert b"alice's data" not in r.content
    assert env.download(alice, meta["id"]).status_code == 404


def test_enc_metadata_hash_checked_before_decrypt(env):
    token = env.user("alice")
    meta = env.upload_ok(token, b"x" * 100, filename="name.txt")
    with env.db() as db:
        blob = bytearray(db.get(File, meta["id"]).enc_metadata)
    blob[-1] ^= 1
    _tamper(env, meta["id"], enc_metadata=bytes(blob))
    r = env.download(token, meta["id"])
    assert r.status_code == 409 and r.json()["reasons"] == ["metadata-hash-mismatch"]
    listed = env.client.get("/api/files", headers=env.h(token)).json()["files"][0]
    assert listed["metadata_error"] == "integrity-failure" and listed["filename"] is None


def test_classification_downgrade_in_db_is_detected(env):
    token = env.user("alice")
    secret = env.enable_mfa(token)
    meta = env.upload_ok(token, b"conf" * 10, classification="confidential")
    _tamper(env, meta["id"], classification="public")       # try to dodge the MFA rule
    r = env.download(token, meta["id"])
    assert r.status_code == 409 and r.json()["reasons"] == ["manifest-classification-mismatch"]
    del secret


def test_verify_and_repair(env):
    token = env.user("alice")
    data = os.urandom(4 * CHUNK)
    meta = env.upload_ok(token, data)
    chunks = _chunks(env, meta["id"])
    c0, _, reps0 = chunks[0]
    c2, _, reps2 = chunks[2]
    env.providers[reps0[0]].inner.put(c0, b"garbage" * 10)        # corrupt one replica
    env.providers[reps2[1]].inner.delete(c2)                      # lose another
    v = env.client.post(f"/api/files/{meta['id']}/verify", headers=env.h(token)).json()
    assert v["healthy"] is False and v["recoverable"] is True
    assert v["summary"]["corrupt"] == 1 and v["summary"]["missing"] == 1 and v["summary"]["ok"] == 6
    d = env.client.get(f"/api/files/{meta['id']}/distribution", headers=env.h(token)).json()
    st = {(c["index"], r["provider"]): r["status"] for c in d["chunks"] for r in c["replicas"]}
    assert st[(0, reps0[0])] == "corrupt" and st[(2, reps2[1])] == "missing"

    rep = env.client.post(f"/api/files/{meta['id']}/repair", headers=env.h(token)).json()
    assert rep["ok"] is True and sorted(rep["repaired_chunks"]) == [0, 2]
    v = env.client.post(f"/api/files/{meta['id']}/verify", headers=env.h(token)).json()
    assert v["healthy"] is True and v["summary"]["ok"] == 8
    assert env.download(token, meta["id"]).content == data      # re-sealed manifest verifies
    assert env.audit_events(event_type="chunk.repair") and env.audit_events(event_type="file.repair")


def test_unrepairable_chunk_reported(env):
    token = env.user("alice")
    meta = env.upload_ok(token, os.urandom(2 * CHUNK))
    cid, _, reps = _chunks(env, meta["id"])[1]
    for p in reps:
        env.providers[p].inner.delete(cid)
    rep = env.client.post(f"/api/files/{meta['id']}/repair", headers=env.h(token)).json()
    assert rep == {"file_id": meta["id"], "ok": False, "repaired_chunks": [], "unrepairable_chunks": [1]}


def test_crash_recovery_of_stale_uploads(env):
    token = env.user("alice")
    me = env.client.get("/api/auth/me", headers=env.h(token)).json()["user"]
    now = env.clock()
    with env.db() as db:
        f = File(id="ab" * 16, owner_id=me["id"], status=FileStatus.UPLOADING, classification="internal",
                 chunk_size=CHUNK, created_at=now - timedelta(minutes=30))
        db.add(f)
        db.add(Chunk(id="cd" * 16, file_id=f.id, index=0, ciphertext_size=10, ciphertext_sha256="0" * 64))
        db.commit()
    for name in ("memory-a", "memory-c"):        # objects written before the "crash"
        env.providers[name].inner.put("cd" * 16, b"ciphertext")
    listed = env.client.get("/api/files", headers=env.h(token)).json()["files"]
    assert listed[0]["status"] == "uploading"
    r = env.download(token, "ab" * 16)
    assert r.status_code == 403 and r.json()["reasons"] == ["file-not-available"]
    out = env.container.run_maintenance()
    assert out["uploads_recovered"] == 1
    with env.db() as db:
        row = db.get(File, "ab" * 16)
        assert row.status == FileStatus.FAILED and row.failure_reason == "interrupted"
    assert all(chunk_keys(p) == [] for p in env.providers.values())
    # a fresh (non-stale) upload in progress is left alone
    with env.db() as db:
        db.add(File(id="ef" * 16, owner_id=me["id"], status=FileStatus.UPLOADING, classification="internal",
                    chunk_size=CHUNK, created_at=now))
        db.commit()
    assert env.container.run_maintenance()["uploads_recovered"] == 0
