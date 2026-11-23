"""Scenarios 5-7: tampering with ciphertext at a provider and with the
manifest in the metadata DB.

Mechanisms: per-replica SHA-256 against the MAC'd manifest (orchestrator
failover without keys), AES-GCM tag + AAD(file_id, index, final) in the
engine, manifest HMAC under a DEK-derived key, DEK unwrap bound to
(file_id, owner_id), whole-file SHA-256, verify-then-release (ADR-0005)."""
from __future__ import annotations

import json

import pytest
from sqlalchemy import update

from app.models import Chunk, ChunkReplica, File

from .conftest import MARKER, inner_of, payload

pytestmark = pytest.mark.security


def _blob(env, provider: str, chunk_id: str) -> bytes:
    return inner_of(env.providers[provider]).get(chunk_id)


def _put(env, provider: str, chunk_id: str, data: bytes) -> None:
    inner_of(env.providers[provider]).put(chunk_id, data)        # attacker writes at the provider


def _flip(blob: bytes, pos: int = 40) -> bytes:
    b = bytearray(blob)
    b[pos] ^= 0x01
    return bytes(b)


def _assert_no_content(r, data: bytes):
    assert r.headers["content-type"].startswith("application/json")
    assert MARKER not in r.content and data[100:140] not in r.content


# --------------------------------------------------------------------------- #
# scenario 5
# --------------------------------------------------------------------------- #
def test_s05_bit_flip_in_one_replica_is_served_from_the_other(env, evidence):
    ev = evidence("S05", "Flip one bit of one chunk replica at one provider",
                  "Per-replica SHA-256 vs MAC'd manifest -> failover to the other replica")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    cid, idx, (p0, p1) = env.chunk_rows(meta["id"])[1]
    _put(env, p0, cid, _flip(_blob(env, p0, cid)))
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 200 and r.content == data
    corrupt = env.audit_events(event_type="storage.replica.corrupt", resource_id=cid)
    assert len(corrupt) == 1 and corrupt[0]["severity"] == "critical" and corrupt[0]["outcome"] == "failure"
    assert corrupt[0]["details"]["provider"] == p0 and corrupt[0]["resource_id"] == cid
    dl = env.one(r, "file.download")
    assert (dl["outcome"], dl["severity"], dl["details"]["corrupt"]) == ("success", "warning", 1)
    dist = env.client.get(f"/api/files/{meta['id']}/distribution", headers=env.h(alice)).json()
    st = {rep["provider"]: rep["status"] for rep in dist["chunks"][idx]["replicas"]}
    assert st == {p0: "corrupt", p1: "stored"}
    ev.result(f"200, plaintext identical; replica on {p0} marked corrupt")
    ev.audit(corrupt[0])


def test_s05_bit_flip_in_both_replicas_is_409_without_any_bytes(env, evidence):
    ev = evidence("S05", "Flip one bit in BOTH replicas of one chunk",
                  "No intact replica -> all-replicas-corrupt; verify-then-release")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    cid, _, reps = env.chunk_rows(meta["id"])[2]
    for p in reps:
        _put(env, p, cid, _flip(_blob(env, p, cid)))
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 409
    assert r.json()["error"] == "integrity-failure" and r.json()["reasons"] == ["all-replicas-corrupt"]
    _assert_no_content(r, data)
    integ = env.one(r, "file.integrity")
    assert (integ["outcome"], integ["severity"], integ["reason"]) == ("failure", "critical", "all-replicas-corrupt")
    dl = env.one(r, "file.download")
    assert (dl["outcome"], dl["severity"]) == ("failure", "critical")
    assert len(env.audit_events(event_type="storage.replica.corrupt", resource_id=cid)) == 2
    ev.response(r)
    ev.audit(integ)


# --------------------------------------------------------------------------- #
# scenario 6
# --------------------------------------------------------------------------- #
def _manifest(env, file_id) -> dict:
    with env.db() as db:
        return json.loads(db.get(File, file_id).manifest_json)


def _set_row(env, file_id, **values):
    with env.db() as db:
        db.execute(update(File).where(File.id == file_id).values(**values))
        db.commit()


def _canon(m: dict) -> str:
    return json.dumps(m, sort_keys=True, separators=(",", ":"))


def _reorder(m):
    m["chunks"][0], m["chunks"][1] = m["chunks"][1], m["chunks"][0]
    m["chunks"][0]["i"], m["chunks"][1]["i"] = 0, 1


def _relocate(m):
    m["chunks"][0]["replicas"] = ["memory-c", "memory-a"] if m["chunks"][0]["replicas"] != ["memory-a", "memory-c"] \
        else ["memory-b", "memory-c"]


def _resize(m):
    m["size_bytes"] = m["size_bytes"] - 10


def _drop_last(m):
    m["chunks"] = m["chunks"][:-1]


MANIFEST_EDITS = [("reorder-chunks", _reorder), ("change-replica-location", _relocate),
                  ("change-size", _resize), ("drop-last-chunk", _drop_last)]


@pytest.mark.parametrize("name,edit", MANIFEST_EDITS, ids=[m[0] for m in MANIFEST_EDITS])
def test_s06_modified_manifest_is_rejected_before_any_chunk_is_fetched(env, evidence, name, edit):
    ev = evidence("S06", f"Edit the manifest in the metadata DB: {name}",
                  "Manifest HMAC (DEK-derived key) verified before any fetch")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    m = _manifest(env, meta["id"])
    assert "chunks" in m and "replicas" in m["chunks"][0], m.keys()
    edit(m)
    _set_row(env, meta["id"], manifest_json=_canon(m))
    gets_before = env.container.orchestrator.metrics.total("attempts")
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 409 and r.json()["error"] == "manifest-integrity-failure"
    assert r.json()["reasons"] == ["manifest-mac-invalid"]
    assert env.container.orchestrator.metrics.total("attempts") == gets_before     # nothing fetched
    _assert_no_content(r, data)
    integ = env.one(r, "file.integrity")
    assert (integ["outcome"], integ["severity"], integ["reason"]) == ("failure", "critical", "manifest-mac-invalid")
    # verify/repair refuse as well (the attacker cannot get the system to "repair" towards the forged manifest)
    assert env.req("POST", f"/api/files/{meta['id']}/repair", alice).status_code == 409
    ev.response(r)
    ev.audit(integ)


def test_s06_changed_owner_in_db_gives_attacker_nothing(env, evidence):
    ev = evidence("S06", "Set files.owner_id to the attacker's user id in the metadata DB",
                  "DEK unwrap context binds (file_id, owner_id) -> key-unwrap-failed")
    alice = env.user("alice")
    mallory = env.user("mallory")
    data = payload()
    meta = env.upload_ok(alice, data)
    _set_row(env, meta["id"], owner_id=env.user_id(mallory))
    r = env.req("GET", f"/api/files/{meta['id']}/download", mallory)
    assert r.status_code == 409 and r.json()["reasons"] == ["key-unwrap-failed"]
    _assert_no_content(r, data)
    integ = env.one(r, "file.integrity")
    assert (integ["severity"], integ["reason"]) == ("critical", "key-unwrap-failed")
    md = env.req("GET", f"/api/files/{meta['id']}", mallory).json()
    assert md["filename"] is None and md["metadata_error"] == "integrity-failure"
    ev.response(r)
    ev.audit(integ)


def test_s06_projection_tables_are_not_trusted(env, evidence):
    """Editing the chunks/chunk_replicas projection (not the manifest) cannot redirect a read."""
    ev = evidence("S06", "Edit the chunks/chunk_replicas projection rows (sha256, replica status)",
                  "Reconstruction uses only the MAC'd manifest (ADR-0003)")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    with env.db() as db:
        db.execute(update(Chunk).where(Chunk.file_id == meta["id"]).values(ciphertext_sha256="0" * 64))
        db.execute(update(ChunkReplica).values(status="deleted"))
        db.commit()
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 200 and r.content == data
    e = env.one(r, "file.download")
    assert e["outcome"] == "success"
    ev.result("200, correct plaintext (projection ignored)")
    ev.audit(e)


# --------------------------------------------------------------------------- #
# scenario 7
# --------------------------------------------------------------------------- #
def test_s07_swapping_two_chunk_objects_at_the_providers(env, evidence):
    ev = evidence("S07", "Swap the contents of chunk 0 and chunk 1 objects at every provider",
                  "Per-chunk SHA-256 in the manifest (and AAD index binding)")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    rows = env.chunk_rows(meta["id"])
    (c0, _, r0), (c1, _, r1) = rows[0], rows[1]
    b0, b1 = _blob(env, r0[0], c0), _blob(env, r1[0], c1)
    for p in r0:
        _put(env, p, c0, b1)
    for p in r1:
        _put(env, p, c1, b0)
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 409 and r.json()["reasons"] == ["all-replicas-corrupt"]
    _assert_no_content(r, data)
    integ = env.one(r, "file.integrity")
    assert integ["severity"] == "critical"
    ev.response(r)
    ev.audit(integ)


def test_s07_substituting_a_chunk_from_another_file_of_the_same_user(env, evidence):
    ev = evidence("S07", "Replace file A chunk 0 with file B chunk 0 (same owner, same index)",
                  "SHA-256 per chunk; AAD binds file_id; different DEK per file")
    alice = env.user("alice")
    a_data, b_data = payload(), payload()
    a = env.upload_ok(alice, a_data)
    b = env.upload_ok(alice, b_data)
    ca, _, ra = env.chunk_rows(a["id"])[0]
    cb, _, rb = env.chunk_rows(b["id"])[0]
    stolen = _blob(env, rb[0], cb)
    for p in ra:
        _put(env, p, ca, stolen)
    r = env.req("GET", f"/api/files/{a['id']}/download", alice)
    assert r.status_code == 409 and r.json()["reasons"] == ["all-replicas-corrupt"]
    _assert_no_content(r, a_data)
    assert b_data[:200] not in r.content
    integ = env.one(r, "file.integrity")
    assert integ["severity"] == "critical"
    assert env.download(alice, b["id"]).content == b_data          # B untouched
    ev.response(r)
    ev.audit(integ)


def test_s07_aad_binding_stops_reordering_even_with_a_forged_manifest(env, evidence):
    """Defence in depth: assume the attacker could ALSO forge the manifest MAC
    (we re-seal it with the file's real keys, which no attacker has) after
    swapping two chunks, so every SHA-256 matches. The AEAD AAD still binds each
    chunk to its index, so decryption fails and nothing is released."""
    ev = evidence("S07", "Swap chunks 0/1 AND re-seal a consistent manifest (simulated MAC-key compromise)",
                  "AES-GCM AAD = (version, file_id, index, final) -> tag failure")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    c = env.container
    with env.db() as db:
        row = db.get(File, meta["id"])
        keys = c.crypto.load_file_keys(row.id, row.owner_id, row.wrapped_dek)
        m = c.crypto.open_manifest(keys, row.manifest_json, row.manifest_mac,
                                   expected_file_id=row.id, expected_owner_id=row.owner_id)
        m = json.loads(json.dumps(m))
        e0, e1 = m["chunks"][0], m["chunks"][1]
        for k in [k for k in e0 if k != "i"]:
            e0[k], e1[k] = e1[k], e0[k]
        mj, mac = c.crypto.seal_manifest(keys, m)
        keys.destroy()
        row.manifest_json, row.manifest_mac = mj, mac
        db.commit()
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 409, r.text
    assert r.json()["error"] in ("chunk-integrity-failure", "integrity-failure", "file-integrity-failure")
    _assert_no_content(r, data)
    integ = env.one(r, "file.integrity")
    assert integ["severity"] == "critical"
    ev.response(r)
    ev.audit(integ)


def test_s07_truncating_the_last_chunk(env, evidence):
    ev = evidence("S07", "Truncate the last chunk object (drop its tail bytes) at both providers",
                  "SHA-256 per chunk + final-flag AAD; no partial delivery")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    cid, _, reps = env.chunk_rows(meta["id"])[-1]
    for p in reps:
        _put(env, p, cid, _blob(env, p, cid)[:-100])
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 409 and r.json()["reasons"] == ["all-replicas-corrupt"]
    _assert_no_content(r, data)
    assert data[:4096] not in r.content                     # the intact first chunks were NOT released
    integ = env.one(r, "file.integrity")
    ev.response(r)
    ev.audit(integ)


def test_s07_deleting_the_last_chunk_everywhere(env, evidence):
    ev = evidence("S07", "Delete the last chunk object at every provider holding it",
                  "Manifest fixes the chunk count; missing chunk -> 503, never a short file")
    alice = env.user("alice")
    data = payload()
    meta = env.upload_ok(alice, data)
    cid, _, reps = env.chunk_rows(meta["id"])[-1]
    for p in reps:
        inner_of(env.providers[p]).delete(cid)
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 503 and r.json() == {**r.json(), "error": "data-unavailable",
                                                 "reasons": ["data-unavailable"]}
    _assert_no_content(r, data)
    dl = env.one(r, "file.download")
    assert (dl["outcome"], dl["reason"]) == ("error", "data-unavailable")
    missing = env.audit_events(event_type="storage.replica.missing", resource_id=cid)
    assert len(missing) == 2 and {e["details"]["provider"] for e in missing} == set(reps)
    ev.response(r)
    ev.audit(dl)


def test_s05_storage_integrity_events_carry_the_request_context(env, evidence):
    ev = evidence("S05", "Corrupt one replica, download, and join the storage alert to the request and user",
                  "Ambient AuditContext contextvar (F5) set per request, propagated into the orchestrator "
                  "thread pool with contextvars.copy_context()")
    alice = env.user("alice")
    meta = env.upload_ok(alice, payload())
    cid, _, (p0, _p1) = env.chunk_rows(meta["id"])[0]
    _put(env, p0, cid, _flip(_blob(env, p0, cid)))
    r = env.req("GET", f"/api/files/{meta['id']}/download", alice)
    assert r.status_code == 200
    e = env.one(r, "storage.replica.corrupt")          # joinable by request id
    assert e["actor"] == env.me(alice)["audit_pseudonym"]
    assert e["severity"] == "critical" and e["source_net"] == "198.51.100.0/24"
    assert e["request_id"] == r.request_id
    retrieve = env.one(r, "chunk.retrieve")           # the data-path events of the same request too
    assert retrieve["actor"] == e["actor"]
    ev.result("storage.replica.corrupt and chunk.retrieve carry request_id, actor pseudonym and source /24")
    ev.audit(e)
