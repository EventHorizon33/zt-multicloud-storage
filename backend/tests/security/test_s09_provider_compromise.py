"""Scenario 9: an attacker holds a full-access credential for ONE storage
provider (the multi-cloud analogue of the UNC5537 stolen credential). The test
uses that provider object directly, bypassing the application.

Claims checked: the provider holds only opaque-named ciphertext (no plaintext,
filenames, user ids or key material); deleting or overwriting everything there
does not prevent correct retrieval (R=2 of 3) and integrity monitoring reports
it; the stated limit (two providers wiped -> some chunks unavailable -> 503,
never wrong bytes)."""
from __future__ import annotations

import math
import os
import re
from collections import Counter

import pytest
from app.cryptoengine import dek_context
from app.cryptoengine.keys import FileKeys
from app.kms.local import load_root_key
from app.models import File

from .conftest import MARKER, inner_of, payload

pytestmark = pytest.mark.security

OPAQUE = re.compile(r"^[0-9a-f]{32,64}$")


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    return -sum(n / len(b) * math.log2(n / len(b)) for n in c.values())


def _setup(env, n_files: int = 4):
    alice = env.user("alice-sec")
    bob = env.user("bob-sec")
    files = []
    for i, (tok, owner) in enumerate([(alice, "alice-sec"), (bob, "bob-sec")] * (n_files // 2)):
        data = payload(3.5)
        meta = env.upload_ok(tok, data, filename=f"{owner}-secret-report-{i}.pdf", classification="internal")
        files.append((tok, meta, data, f"{owner}-secret-report-{i}.pdf"))
    return alice, bob, files


def _file_keys(env, file_id):
    with env.db() as db:
        row = db.get(File, file_id)
        dek = env.container.kms.unwrap_data_key(row.wrapped_dek, context=dek_context(row.id, row.owner_id))
        keys = FileKeys.derive(dek, row.id)
        return dek, keys, row.wrapped_dek


def test_s09_one_provider_holds_only_opaque_ciphertext_and_no_keys(env, evidence):
    ev = evidence("S09", "Read EVERYTHING at one provider with its credential (keys, bytes, metadata)",
                  "Chunks are AES-256-GCM ciphertext under opaque random ids; no keys or metadata on providers")
    alice, bob, files = _setup(env)
    stolen = inner_of(env.providers["memory-a"])          # the attacker's view of provider A
    keys = list(stolen.list_keys(""))
    chunk_keys = [k for k in keys if not k.startswith("anchors/")]
    assert chunk_keys, "provider A holds no chunks?"
    user_ids = {env.user_id(alice), env.user_id(bob)}
    file_ids = {m["id"] for _, m, _, _ in files}
    secrets_ = []
    for _, meta, _, _ in files:
        dek, fk, wrapped = _file_keys(env, meta["id"])
        secrets_ += [dek, wrapped, fk._k_enc, fk._k_mac, fk._k_meta]
    secrets_.append(load_root_key(env.settings))
    secrets_.append(env.settings.kms_keystore_path.read_bytes()[:64])
    names = [n.encode() for *_, n in files] + [b"alice-sec", b"bob-sec", b"secret-report"]
    total = 0
    for k in keys:
        blob = stolen.get(k)
        info = stolen.stat(k)
        assert dict(info.metadata or {}) == {}                       # no object metadata at all
        assert not any(u in k for u in user_ids | file_ids)          # names say nothing
        if not k.startswith("anchors/"):
            assert OPAQUE.match(k), k
            assert _entropy(blob) > 7.5 or len(blob) < 512, (k, _entropy(blob))
            total += 1
        assert MARKER not in blob
        for n in names:
            assert n not in blob
        for u in user_ids | file_ids:
            assert u.encode() not in blob
        for s in secrets_:
            assert s not in blob                                     # no key material anywhere
    # A provider does not get every chunk: with R=2 of 3 it holds about 2/3 of them.
    all_chunks = sum(len(env.chunk_rows(m["id"])) for _, m, _, _ in files)
    assert total < all_chunks
    # Same plaintext uploaded twice -> unrelated ciphertext (no dedup / equality leak)
    same = payload(1)
    m1 = env.upload_ok(alice, same)
    m2 = env.upload_ok(alice, same)
    c1, c2 = env.chunk_rows(m1["id"])[0], env.chunk_rows(m2["id"])[0]
    b1 = inner_of(env.providers[c1[2][0]]).get(c1[0])
    b2 = inner_of(env.providers[c2[2][0]]).get(c2[0])
    assert b1 != b2 and b1[12:44] != b2[12:44]
    ev.result(f"{total} chunk objects of {all_chunks}: opaque ids, entropy>7.5 bit/byte, no metadata, "
              f"no marker/filename/user id/DEK/KEK/root key")
    ev.audit(None)


@pytest.mark.parametrize("attack", ["delete-everything", "overwrite-everything"])
def test_s09_destroying_one_provider_does_not_prevent_retrieval(env, evidence, attack):
    ev = evidence("S09", f"With provider A's credential: {attack} (chunks AND audit anchors)",
                  "R=2 replication + per-replica SHA-256 failover; verify/scrub + audit anchors report it")
    alice, bob, files = _setup(env)
    auditor = env.auditor()
    admin, _ = env.admin()
    assert env.client.post("/api/audit/checkpoints", headers=env.h(admin)).status_code == 201   # anchored
    stolen = inner_of(env.providers["memory-a"])
    assert any(k.startswith("anchors/") for k in stolen.list_keys(""))
    for k in list(stolen.list_keys("")):
        if attack == "delete-everything":
            stolen.delete(k)
        else:
            stolen.put(k, os.urandom(len(stolen.get(k))))
    for tok, meta, data, _ in files:
        r = env.req("GET", f"/api/files/{meta['id']}/download", tok)
        assert r.status_code == 200 and r.content == data           # correct plaintext from the other replicas
    ev_type = "storage.replica.missing" if attack == "delete-everything" else "storage.replica.corrupt"
    bad = env.audit_events(event_type=ev_type)
    assert bad and {e["details"]["provider"] for e in bad} == {"memory-a"}
    assert {e["severity"] for e in bad} == ({"warning"} if attack == "delete-everything" else {"critical"})
    # integrity monitoring: per-file scrub
    tok, meta, data, _ = files[0]
    v = env.req("POST", f"/api/files/{meta['id']}/verify", tok).json()
    kind = "missing" if attack == "delete-everything" else "corrupt"
    assert v["healthy"] is False and v["recoverable"] is True and v["summary"][kind] >= 1
    fv = env.audit_events(event_type="file.verify", resource_id=meta["id"])[-1]
    assert fv["outcome"] == "failure"
    # audit-anchor monitoring: the provider's checkpoint copies are gone / forged
    rep = env.req("POST", "/api/audit/verify", auditor, json={}).json()
    if attack == "overwrite-everything":
        assert rep["ok"] is False and "anchor-mismatch" in {f["type"] for f in rep["findings"]}
    else:
        assert "anchor-missing" in {f["type"] for f in rep["findings"]}  # informational
    # repair restores replication on the provider
    rp = env.req("POST", f"/api/files/{meta['id']}/repair", tok).json()
    assert rp["ok"] is True and rp["repaired_chunks"]
    v2 = env.req("POST", f"/api/files/{meta['id']}/verify", tok).json()
    assert v2["healthy"] is True
    ev.result(f"all {len(files)} files download byte-identical; verify healthy=false ({kind}); "
              f"repair ok; audit verify findings={sorted({f['type'] for f in rep['findings']})}")
    ev.audit(bad[0])
    ev.audit(fv)


def test_s09_stated_limit_two_providers_wiped(env, evidence):
    ev = evidence("S09", "(stated limit) Wipe TWO providers",
                  "No reconstruction beyond R: chunk with no replica -> 503 data-unavailable, never wrong bytes")
    alice, bob, files = _setup(env, n_files=6)
    for name in ("memory-a", "memory-b"):
        p = inner_of(env.providers[name])
        for k in list(p.list_keys("")):
            p.delete(k)
    unavailable = ok = 0
    for tok, meta, data, _ in files:
        lost = any(set(reps) <= {"memory-a", "memory-b"} for _, _, reps in env.chunk_rows(meta["id"]))
        r = env.req("GET", f"/api/files/{meta['id']}/download", tok)
        if lost:
            assert r.status_code == 503 and r.json()["error"] == "data-unavailable"
            assert MARKER not in r.content
            e = env.one(r, "file.download")
            assert (e["outcome"], e["reason"]) == ("error", "data-unavailable")
            unavailable += 1
        else:
            assert r.status_code == 200 and r.content == data
            ok += 1
    assert unavailable >= 1                         # 6 files x 4 chunks: some chunk sits on {a, b}
    rp = env.req("POST", f"/api/files/{files[0][1]['id']}/verify", files[0][0]).json()
    assert rp["healthy"] is False
    ev.result(f"{unavailable} file(s) 503 data-unavailable, {ok} file(s) 200 correct; no corrupted output")
    ev.audit(e)
