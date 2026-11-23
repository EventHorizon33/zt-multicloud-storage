"""Crypto engine tests. Self-contained: a LocalKMS in tmp_path, no providers."""
from __future__ import annotations

import hashlib
import io
import json
import os
import random
import re
from typing import Any

import pytest

from app.errors import ChunkIntegrityError, IntegrityError, KmsError, ManifestIntegrityError, ValidationFailed
from app.kms import LocalKMS
from app.cryptoengine import (
    CHUNK_OVERHEAD,
    MAX_CHUNKS_PER_FILE,
    CryptoEngine,
    FileKeys,
    MetadataIntegrityError,
    PlaintextAccumulator,
    WholeFileIntegrityError,
    canonical_json,
    chunk_aad,
    iter_plain_chunks,
    update_manifest_replicas,
)
from app.cryptoengine import chunks as chunks_mod

OWNER = "user-1"
CS = 1024
PROVIDERS = ["aws-s3", "azure-blob", "gcs"]


@pytest.fixture
def kms(tmp_path):
    return LocalKMS(tmp_path / "ks.json", os.urandom(32))


@pytest.fixture
def engine(kms):
    return CryptoEngine(kms, CS)


class ShortReader:
    """Returns at most ``step`` (random up to step) bytes per read()."""

    def __init__(self, data: bytes, step: int = 7, seed: int = 0):
        self._buf = io.BytesIO(data)
        self._step = step
        self._rng = random.Random(seed)

    def read(self, n: int = -1) -> bytes:
        k = self._rng.randint(1, self._step)
        return self._buf.read(min(n, k) if n >= 0 else k)


def upload(engine: CryptoEngine, data: bytes, file_id: str = "file-1", *, stream=None,
           classification: str = "internal"):
    """Mini integrator: returns (keys, dk, store, manifest_json, mac, enc_meta)."""
    keys, dk = engine.new_file_keys(file_id, OWNER)
    acc = PlaintextAccumulator()
    store: dict[str, bytes] = {}
    entries = []
    for i, ch in enumerate(engine.encrypt_stream(keys, file_id, stream or io.BytesIO(data), accumulator=acc)):
        assert ch.index == i
        store[ch.chunk_id] = ch.blob
        entries.append(ch.manifest_entry(PROVIDERS[i % 3:i % 3 + 1] + PROVIDERS[(i + 1) % 3:(i + 1) % 3 + 1]))
    assert acc.size_bytes == len(data) and acc.plaintext_sha256 == hashlib.sha256(data).hexdigest()
    enc_meta = engine.encrypt_metadata(keys, file_id, {"filename": "secret-report.pdf",
                                                       "mime_type": "application/pdf",
                                                       "plaintext_sha256": acc.plaintext_sha256})
    manifest = engine.build_manifest(
        file_id=file_id, owner_id=OWNER, classification=classification, size_bytes=acc.size_bytes,
        plaintext_sha256=acc.plaintext_sha256, enc_metadata_sha256=hashlib.sha256(enc_meta).hexdigest(),
        kek_id=dk.key_id, kek_version=dk.key_version, chunks=entries)
    mj, mac = engine.seal_manifest(keys, manifest)
    return keys, dk, store, mj, mac, enc_meta


def download(engine, kms_wrapped, file_id, mj, mac, store, owner=OWNER):
    keys = engine.load_file_keys(file_id, owner, kms_wrapped)
    m = engine.open_manifest(keys, mj, mac, expected_file_id=file_id, expected_owner_id=owner)
    sink = io.BytesIO()
    res = engine.assemble(keys, m, lambda e: store[e["id"]], sink)
    return sink.getvalue(), res, m


# --------------------------------------------------------------------------- #
# round trips
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("size", [0, 1, CS - 1, CS, CS + 1, 2 * CS, 3 * CS + 17, 10 * CS])
def test_round_trip_sizes(engine, size):
    data = os.urandom(size)
    keys, dk, store, mj, mac, _ = upload(engine, data)
    out, res, m = download(engine, dk.wrapped, "file-1", mj, mac, store)
    assert out == data and res.size_bytes == size
    expected_chunks = max(1, -(-size // CS))
    assert res.chunk_count == m["chunk_count"] == len(store) == expected_chunks
    assert [c["i"] for c in m["chunks"]] == list(range(expected_chunks))
    sizes = [c["size"] - CHUNK_OVERHEAD for c in m["chunks"]]
    assert all(s == CS for s in sizes[:-1]) and sum(sizes) == size


@pytest.mark.parametrize("chunk_size", [1, 3, 64, 1000, 4096, 65536])
def test_non_default_chunk_sizes(kms, chunk_size):
    eng = CryptoEngine(kms, chunk_size)
    for size in (0, 1, chunk_size, chunk_size + 1, 5 * chunk_size + 3):
        if size > 300_000:
            continue
        data = os.urandom(size)
        _, dk, store, mj, mac, _ = upload(eng, data, file_id=f"f-{chunk_size}-{size}")
        out, _, _ = download(eng, dk.wrapped, f"f-{chunk_size}-{size}", mj, mac, store)
        assert out == data


def test_randomised_round_trips(kms):
    rng = random.Random(1234)
    for trial in range(30):
        cs = rng.choice([1, 2, 5, 16, 100, 1024, 4000])
        data = os.urandom(rng.randint(0, 20_000 if cs >= 16 else 200))
        eng = CryptoEngine(kms, cs)
        stream = ShortReader(data, step=rng.randint(1, 50), seed=trial) if trial % 2 else None
        _, dk, store, mj, mac, _ = upload(eng, data, file_id=f"r{trial}", stream=stream)
        out, _, _ = download(eng, dk.wrapped, f"r{trial}", mj, mac, store)
        assert out == data


def test_large_file_20mib(kms):
    eng = CryptoEngine(kms, 1024 * 1024)
    data = os.urandom(20 * 1024 * 1024 + 123)
    _, dk, store, mj, mac, _ = upload(eng, data, file_id="big")
    out, res, m = download(eng, dk.wrapped, "big", mj, mac, store)
    assert out == data and m["chunk_count"] == 21


def test_short_reads(engine):
    data = os.urandom(5 * CS + 9)
    _, dk, store, mj, mac, _ = upload(engine, data, stream=ShortReader(data, step=3))
    assert download(engine, dk.wrapped, "file-1", mj, mac, store)[0] == data


# --------------------------------------------------------------------------- #
# chunking
# --------------------------------------------------------------------------- #
def test_iter_plain_chunks_basics():
    assert list(iter_plain_chunks(io.BytesIO(b""), 4)) == [(0, b"", True)]
    assert list(iter_plain_chunks(io.BytesIO(b"abcd"), 4)) == [(0, b"abcd", True)]
    assert list(iter_plain_chunks(io.BytesIO(b"abcde"), 4)) == [(0, b"abcd", False), (1, b"e", True)]
    assert list(iter_plain_chunks(ShortReader(b"abcdefgh", 1), 4)) == [(0, b"abcd", False), (1, b"efgh", True)]


def test_iter_plain_chunks_lookahead_is_lazy():
    reads = []

    class R:
        def __init__(self):
            self.b = io.BytesIO(b"x" * 40)

        def read(self, n):
            reads.append(n)
            return self.b.read(n)
    it = iter_plain_chunks(R(), 10)
    next(it)
    assert sum(reads) <= 20 + 10  # current + one lookahead (+ possible short-read retries)


@pytest.mark.parametrize("bad", [0, -1, 64 * 1024 * 1024 + 1, 1.5, True, "10"])
def test_chunk_size_bounds(kms, bad):
    with pytest.raises(ValueError):
        CryptoEngine(kms, bad)
    with pytest.raises(ValueError):
        list(iter_plain_chunks(io.BytesIO(b"abc"), bad))


def test_max_chunks_per_file(monkeypatch):
    monkeypatch.setattr(chunks_mod, "MAX_CHUNKS_PER_FILE", 3)
    assert len(list(chunks_mod.iter_plain_chunks(io.BytesIO(b"abc"), 1))) == 3
    with pytest.raises(ValidationFailed):
        list(chunks_mod.iter_plain_chunks(io.BytesIO(b"abcd"), 1))
    assert MAX_CHUNKS_PER_FILE == 2 ** 20


def test_encrypt_stream_max_bytes(engine):
    keys, _ = engine.new_file_keys("f", OWNER)
    with pytest.raises(ValidationFailed):
        list(engine.encrypt_stream(keys, "f", io.BytesIO(b"x" * (CS + 1)), max_bytes=CS))
    assert len(list(engine.encrypt_stream(keys, "f", io.BytesIO(b"x" * CS), max_bytes=CS))) == 1


def test_stream_returning_too_much_rejected():
    class Bad:
        def read(self, n):
            return b"x" * (n + 1)
    with pytest.raises(ValueError):
        list(iter_plain_chunks(Bad(), 4))


# --------------------------------------------------------------------------- #
# ciphertext properties
# --------------------------------------------------------------------------- #
def test_blob_format_and_no_plaintext(engine):
    marker = b"TOP-SECRET-MARKER-0123456789"
    data = (marker * 200)[:3 * CS + 5]
    keys, dk, store, mj, mac, enc_meta = upload(engine, data)
    for blob in store.values():
        assert marker[:12] not in blob and blob[12:] != data[:len(blob) - 28]
    assert b"secret-report" not in enc_meta and b"application/pdf" not in enc_meta
    for text in (mj, ):
        assert "secret-report" not in text and "TOP-SECRET" not in text
    for cid in store:
        assert re.fullmatch(r"[0-9a-f]{32}", cid)
        assert OWNER not in cid and "file-1" not in cid


def test_same_plaintext_twice_differs(engine):
    data = b"A" * (2 * CS)
    _, _, s1, *_ = upload(engine, data, "a")
    _, _, s2, *_ = upload(engine, data, "a")
    assert not set(s1) & set(s2)
    assert not set(s1.values()) & set(s2.values())
    keys, _ = engine.new_file_keys("x", OWNER)
    c1 = engine.encrypt_chunk(keys, "x", 0, b"same", True)
    c2 = engine.encrypt_chunk(keys, "x", 0, b"same", True)
    assert c1.blob != c2.blob and c1.chunk_id != c2.chunk_id and c1.blob[:12] != c2.blob[:12]
    assert c1.sha256_hex == hashlib.sha256(c1.blob).hexdigest() and c1.size == len(c1.blob) == 4 + 28
    assert "blob" not in repr(c1) or c1.blob.hex() not in repr(c1)


def test_chunk_aad_unambiguous():
    seen = set()
    for fid in ("a", "ab", "a\x00", "1"):
        for idx in (0, 1, 256):
            for fin in (False, True):
                seen.add(chunk_aad(fid, idx, fin))
    assert len(seen) == 4 * 3 * 2


# --------------------------------------------------------------------------- #
# chunk tamper / substitution / reordering / truncation
# --------------------------------------------------------------------------- #
def _one_chunk(engine, n=3):
    keys, _ = engine.new_file_keys("f", OWNER)
    data = os.urandom(n * CS)
    chs = list(engine.encrypt_stream(keys, "f", io.BytesIO(data)))
    return keys, chs, data


@pytest.mark.parametrize("region", ["nonce", "body", "tag"])
def test_bit_flip_detected(engine, region):
    keys, chs, _ = _one_chunk(engine)
    ch = chs[1]
    pos = {"nonce": 3, "body": 12 + CS // 2, "tag": len(ch.blob) - 2}[region]
    t = bytearray(ch.blob)
    t[pos] ^= 0x10
    # (a) hash from manifest catches it
    with pytest.raises(ChunkIntegrityError, match="chunk 1"):
        engine.decrypt_chunk(keys, "f", 1, bytes(t), False, ch.sha256_hex)
    # (b) even if the attacker also fixes the manifest hash, AEAD catches it
    with pytest.raises(ChunkIntegrityError, match="authentication"):
        engine.decrypt_chunk(keys, "f", 1, bytes(t), False, hashlib.sha256(bytes(t)).hexdigest())


def test_every_byte_flip_detected_by_aead(engine):
    keys, _ = engine.new_file_keys("f", OWNER)
    ch = engine.encrypt_chunk(keys, "f", 0, b"hello world", True)
    for pos in range(len(ch.blob)):
        t = bytearray(ch.blob)
        t[pos] ^= 1
        with pytest.raises(ChunkIntegrityError):
            engine.decrypt_chunk(keys, "f", 0, bytes(t), True, hashlib.sha256(bytes(t)).hexdigest())


def test_error_messages_contain_no_secrets(engine):
    keys, chs, data = _one_chunk(engine)
    with pytest.raises(ChunkIntegrityError) as exc:
        engine.decrypt_chunk(keys, "f", 0, chs[1].blob, False, chs[1].sha256_hex)
    msg = str(exc.value)
    assert keys.k_enc.hex() not in msg and data[:16].hex() not in msg and "chunk 0" in msg


def test_swapped_chunks_detected(engine):
    keys, chs, _ = _one_chunk(engine)
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(keys, "f", 0, chs[1].blob, False, chs[1].sha256_hex)
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(keys, "f", 1, chs[0].blob, False, chs[0].sha256_hex)


def test_swapped_chunks_in_store_detected_by_assembler(engine):
    data = os.urandom(3 * CS)
    _, dk, store, mj, mac, _ = upload(engine, data)
    ids = list(store)
    store[ids[0]], store[ids[1]] = store[ids[1]], store[ids[0]]
    with pytest.raises(ChunkIntegrityError):
        download(engine, dk.wrapped, "file-1", mj, mac, store)


def test_chunk_from_other_file_detected(engine):
    k1, _ = engine.new_file_keys("f1", OWNER)
    k2, _ = engine.new_file_keys("f2", OWNER)
    c2 = engine.encrypt_chunk(k2, "f2", 0, b"x" * 10, True)
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(k1, "f1", 0, c2.blob, True, c2.sha256_hex)
    # same DEK reused under another file id still fails (AAD + derivation bind file id)
    dek = os.urandom(32)
    ka, kb = FileKeys.derive(dek, "fa"), FileKeys.derive(dek, "fb")
    ca = engine.encrypt_chunk(ka, "fa", 0, b"data", True)
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(kb, "fb", 0, ca.blob, True, ca.sha256_hex)
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(ka, "fb", 0, ca.blob, True, ca.sha256_hex)


def test_truncation_detected(engine):
    keys, chs, _ = _one_chunk(engine)
    # drop last chunk and claim the previous one is final
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(keys, "f", 1, chs[1].blob, True, chs[1].sha256_hex)


def test_extra_chunk_appended_detected(engine):
    keys, chs, _ = _one_chunk(engine)
    # the old final chunk is no longer final once something is appended after it
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(keys, "f", 2, chs[2].blob, False, chs[2].sha256_hex)
    extra = engine.encrypt_chunk(keys, "f", 3, b"extra", True)
    with pytest.raises(ChunkIntegrityError):  # chunk 2 decrypted as non-final fails first
        engine.decrypt_chunk(keys, "f", 2, chs[2].blob, False, chs[2].sha256_hex)
    assert engine.decrypt_chunk(keys, "f", 3, extra.blob, True, extra.sha256_hex) == b"extra"


def test_short_or_wrong_type_blob(engine):
    keys, _ = engine.new_file_keys("f", OWNER)
    for blob in (b"", b"x" * 27):
        with pytest.raises(ChunkIntegrityError):
            engine.decrypt_chunk(keys, "f", 0, blob, True, hashlib.sha256(blob).hexdigest())
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(keys, "f", 0, "str", True, "00" * 32)
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(keys, "f", -1, b"x" * 40, True, "00" * 32)


# --------------------------------------------------------------------------- #
# manifest
# --------------------------------------------------------------------------- #
def _sealed(engine, size=3 * CS + 5):
    data = os.urandom(size)
    keys, dk, store, mj, mac, enc_meta = upload(engine, data)
    return keys, dk, store, mj, mac, data


def test_manifest_fields(engine):
    keys, dk, store, mj, mac, data = _sealed(engine)
    m = json.loads(mj)
    assert set(m) == {"v", "file_id", "owner_id", "classification", "size_bytes", "chunk_size",
                      "chunk_count", "plaintext_sha256", "enc_metadata_sha256", "created_at",
                      "kek", "chunks"}
    assert m["kek"] == {"id": dk.key_id, "version": dk.key_version}
    assert m["created_at"].endswith("Z")
    assert all(c["replicas"] == sorted(c["replicas"]) for c in m["chunks"])
    assert mj == canonical_json(m) and " " not in mj and re.fullmatch(r"[0-9a-f]{64}", mac)


def test_canonical_json_rules():
    assert canonical_json({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"\\u00e9"],"b":1}'
    for bad in ({"x": 1.0}, {"x": float("nan")}, {"x": float("inf")}, {1: "a"}, {"x": b"b"}, {"x": {1, 2}}):
        with pytest.raises(ValueError):
            canonical_json(bad)


def _resealed_tamper(engine, keys, mj, fn):
    m = json.loads(mj)
    fn(m)
    return json.dumps(m, sort_keys=True, separators=(",", ":"))


@pytest.mark.parametrize("name,mutate", [
    ("reorder", lambda m: m["chunks"].reverse()),
    ("replica", lambda m: m["chunks"][0].update(replicas=["evil-provider"])),
    ("size", lambda m: m.update(size_bytes=m["size_bytes"] - 1)),
    ("owner", lambda m: m.update(owner_id="attacker")),
    ("chunk-hash", lambda m: m["chunks"][1].update(sha256="0" * 64)),
    ("chunk-id", lambda m: m["chunks"][1].update(id="f" * 32)),
    ("classification", lambda m: m.update(classification="public")),
    ("drop-last", lambda m: (m["chunks"].pop(), m.update(chunk_count=m["chunk_count"] - 1))),
    ("kek", lambda m: m["kek"].update(version=9)),
])
def test_manifest_modification_detected(engine, name, mutate):
    keys, dk, store, mj, mac, _ = _sealed(engine)
    bad = _resealed_tamper(engine, keys, mj, mutate)
    assert bad != mj
    with pytest.raises(ManifestIntegrityError):
        engine.open_manifest(keys, bad, mac, expected_file_id="file-1", expected_owner_id=OWNER)


@pytest.mark.parametrize("variant", [
    lambda s: s + " ", lambda s: " " + s, lambda s: s.replace(",", ", ", 1),
    lambda s: s.replace(":", ": ", 1), lambda s: s + "\n",
    lambda s: json.dumps(json.loads(s), sort_keys=True, separators=(",", ":"), indent=0),
])
def test_manifest_whitespace_change_detected(engine, variant):
    keys, _, _, mj, mac, _ = _sealed(engine)
    with pytest.raises(ManifestIntegrityError):
        engine.open_manifest(keys, variant(mj), mac, expected_file_id="file-1", expected_owner_id=OWNER)


def test_manifest_mac_tamper(engine):
    keys, _, _, mj, mac, _ = _sealed(engine)
    assert engine.open_manifest(keys, mj, mac.upper(), expected_file_id="file-1", expected_owner_id=OWNER)
    for bad in ("0" * 64, mac[:-1] + ("0" if mac[-1] != "0" else "1"), "", mac[:32], None):
        with pytest.raises(ManifestIntegrityError):
            engine.open_manifest(keys, mj, bad, expected_file_id="file-1", expected_owner_id=OWNER)


def test_valid_mac_wrong_expectations(engine):
    keys, _, _, mj, mac, _ = _sealed(engine)
    with pytest.raises(ManifestIntegrityError, match="owner"):
        engine.open_manifest(keys, mj, mac, expected_file_id="file-1", expected_owner_id="user-2")
    with pytest.raises(ManifestIntegrityError):
        engine.open_manifest(keys, mj, mac, expected_file_id="file-2", expected_owner_id=OWNER)


def test_wrong_dek_cannot_open(engine):
    k1, _, store, mj, mac, _ = _sealed(engine)
    other_keys, _ = engine.new_file_keys("file-1", OWNER)  # same id, different DEK
    with pytest.raises(ManifestIntegrityError):
        engine.open_manifest(other_keys, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    m = engine.open_manifest(k1, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    c = m["chunks"][0]
    with pytest.raises(ChunkIntegrityError):
        engine.decrypt_chunk(other_keys, "file-1", 0, store[c["id"]], False, c["sha256"])


def test_wrapped_dek_moved_to_other_row_fails(engine):
    _, dk, store, mj, mac, _ = _sealed(engine)
    with pytest.raises(KmsError):
        engine.load_file_keys("file-2", OWNER, dk.wrapped)
    with pytest.raises(KmsError):
        engine.load_file_keys("file-1", "user-2", dk.wrapped)


def _base_manifest(engine, keys, n=3, last=5):
    entries = []
    for i in range(n):
        size = (CS if i < n - 1 else last) + CHUNK_OVERHEAD
        entries.append({"i": i, "id": os.urandom(16).hex(), "size": size, "sha256": "a" * 64,
                        "replicas": ["aws-s3", "gcs"]})
    return engine.build_manifest(file_id=keys.file_id, owner_id=OWNER, classification="internal",
                                 size_bytes=(n - 1) * CS + last, plaintext_sha256="b" * 64,
                                 enc_metadata_sha256="c" * 64, kek_id="k", kek_version=1,
                                 chunks=entries)


@pytest.mark.parametrize("name,mutate", [
    ("version", lambda m: m.update(v=2)),
    ("version-bool", lambda m: m.update(v=True)),
    ("count", lambda m: m.update(chunk_count=4)),
    ("indices-gap", lambda m: m["chunks"][2].update(i=3)),
    ("indices-order", lambda m: (m["chunks"][0].update(i=1), m["chunks"][1].update(i=0))),
    ("dup-id", lambda m: m["chunks"][1].update(id=m["chunks"][0]["id"])),
    ("neg-size", lambda m: m["chunks"][2].update(size=-1)),
    ("str-size", lambda m: m["chunks"][2].update(size="33")),
    ("short-middle", lambda m: m["chunks"][1].update(size=CS + CHUNK_OVERHEAD - 1)),
    ("long-last", lambda m: m["chunks"][2].update(size=CS + CHUNK_OVERHEAD + 1)),
    ("empty-last-nonempty-file", lambda m: (m["chunks"][2].update(size=CHUNK_OVERHEAD),
                                            m.update(size_bytes=2 * CS))),
    ("size-sum", lambda m: m.update(size_bytes=m["size_bytes"] + 1)),
    ("size-vs-count", lambda m: m.update(size_bytes=CS)),
    ("no-replicas", lambda m: m["chunks"][0].update(replicas=[])),
    ("dup-replicas", lambda m: m["chunks"][0].update(replicas=["gcs", "gcs"])),
    ("unsorted-replicas", lambda m: m["chunks"][0].update(replicas=["gcs", "aws-s3"])),
    ("extra-field", lambda m: m.update(extra=1)),
    ("missing-field", lambda m: m.pop("plaintext_sha256")),
    ("chunk-extra-field", lambda m: m["chunks"][0].update(x=1)),
    ("bad-hash", lambda m: m.update(plaintext_sha256="XYZ")),
    ("bad-chunk-id", lambda m: m["chunks"][0].update(id="../../etc/passwd")),
    ("chunk-size-zero", lambda m: m.update(chunk_size=0)),
    ("kek-bad", lambda m: m.update(kek={"id": "k"})),
    ("no-chunks", lambda m: (m.update(chunks=[], chunk_count=0, size_bytes=0))),
])
def test_structural_validation(engine, name, mutate):
    """Seal a structurally invalid manifest with a *valid* MAC (simulating a
    bug or key holder misuse): open_manifest must still reject it."""
    import hmac as _h
    from app.cryptoengine.manifest import _MAC_DOMAIN
    keys, _ = engine.new_file_keys("file-1", OWNER)
    m = _base_manifest(engine, keys)
    mutate(m)
    text = json.dumps(m, sort_keys=True, separators=(",", ":"))
    mac = _h.new(keys.k_mac, _MAC_DOMAIN + text.encode(), hashlib.sha256).hexdigest()
    with pytest.raises(ManifestIntegrityError):
        engine.open_manifest(keys, text, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    with pytest.raises(ManifestIntegrityError):
        engine.seal_manifest(keys, m)


def test_float_or_duplicate_key_manifest_rejected(engine):
    import hmac as _h
    from app.cryptoengine.manifest import _MAC_DOMAIN
    keys, _ = engine.new_file_keys("file-1", OWNER)
    good = canonical_json(_base_manifest(engine, keys))
    for text in (good.replace('"v":1', '"v":1.0'), good.replace('{"chunk_count"', '{"v":1,"chunk_count"', 1),
                 good.replace('"v":1', '"v":NaN')):
        mac = _h.new(keys.k_mac, _MAC_DOMAIN + text.encode(), hashlib.sha256).hexdigest()
        with pytest.raises(ManifestIntegrityError):
            engine.open_manifest(keys, text, mac, expected_file_id="file-1", expected_owner_id=OWNER)


def test_empty_file_manifest_valid(engine):
    _, dk, store, mj, mac, _ = upload(engine, b"")
    m = json.loads(mj)
    assert m["chunk_count"] == 1 and m["chunks"][0]["size"] == CHUNK_OVERHEAD and m["size_bytes"] == 0


def test_update_replicas_and_reseal(engine):
    keys, dk, store, mj, mac, data = _sealed(engine)
    m = engine.open_manifest(keys, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    m2 = update_manifest_replicas(m, 1, ["gcs", "aws-s3"])
    assert m["chunks"][1]["replicas"] != m2["chunks"][1]["replicas"]  # original untouched
    assert m2["chunks"][1]["replicas"] == ["aws-s3", "gcs"]
    mj2, mac2 = engine.seal_manifest(keys, m2)
    assert mac2 != mac
    out, _, _ = download(engine, dk.wrapped, "file-1", mj2, mac2, store)
    assert out == data
    with pytest.raises(ManifestIntegrityError):  # old MAC on new JSON
        engine.open_manifest(keys, mj2, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    for bad in ([], ["a", "a"], [""]):
        with pytest.raises(ValueError):
            update_manifest_replicas(m, 0, bad)
    with pytest.raises(ValueError):
        update_manifest_replicas(m, 9, ["gcs"])


def test_seal_requires_matching_keys(engine):
    k1, _ = engine.new_file_keys("file-1", OWNER)
    k2, _ = engine.new_file_keys("file-2", OWNER)
    with pytest.raises(ValueError):
        engine.seal_manifest(k2, _base_manifest(engine, k1))


# --------------------------------------------------------------------------- #
# assembler
# --------------------------------------------------------------------------- #
def test_assembler_whole_file_hash_mismatch(engine):
    data = os.urandom(2 * CS + 3)
    keys, dk, store, mj, mac, _ = upload(engine, data)
    m = json.loads(mj)
    m["plaintext_sha256"] = hashlib.sha256(b"something else").hexdigest()
    mj2, mac2 = engine.seal_manifest(keys, m)
    m2 = engine.open_manifest(keys, mj2, mac2, expected_file_id="file-1", expected_owner_id=OWNER)
    sink = io.BytesIO()
    with pytest.raises(WholeFileIntegrityError) as exc:
        engine.assemble(keys, m2, lambda e: store[e["id"]], sink)
    assert isinstance(exc.value, IntegrityError) and exc.value.reasons == ("file-hash-mismatch",)


def test_assembler_size_mismatch(engine):
    data = os.urandom(CS + 3)
    keys, dk, store, mj, mac, _ = upload(engine, data)
    m = engine.open_manifest(keys, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    m = dict(m, size_bytes=m["size_bytes"] + 1)  # bypasses validation on purpose
    with pytest.raises(WholeFileIntegrityError):
        engine.assemble(keys, m, lambda e: store[e["id"]], io.BytesIO())


def test_assembler_stops_on_bad_chunk_and_returns_nothing(engine):
    data = os.urandom(3 * CS)
    keys, dk, store, mj, mac, _ = upload(engine, data)
    m = engine.open_manifest(keys, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    bad_id = m["chunks"][1]["id"]
    store[bad_id] = store[bad_id][:-1] + bytes([store[bad_id][-1] ^ 1])
    fetched = []

    def fetch(e):
        fetched.append(e["i"])
        return store[e["id"]]
    sink = io.BytesIO()
    with pytest.raises(ChunkIntegrityError, match="chunk 1"):
        engine.assemble(keys, m, fetch, sink)
    assert fetched == [0, 1]
    assert len(sink.getvalue()) == CS  # partial content exists; the caller discards it


def test_assembler_fetch_errors_propagate(engine):
    keys, dk, store, mj, mac, _ = upload(engine, b"abc")
    m = engine.open_manifest(keys, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)

    def fetch(e):
        raise RuntimeError("provider down")
    with pytest.raises(RuntimeError):
        engine.assemble(keys, m, fetch, io.BytesIO())


def test_assembler_keys_for_other_file(engine):
    keys, dk, store, mj, mac, _ = upload(engine, b"abc")
    m = engine.open_manifest(keys, mj, mac, expected_file_id="file-1", expected_owner_id=OWNER)
    k2, _ = engine.new_file_keys("file-2", OWNER)
    with pytest.raises(ChunkIntegrityError):
        engine.assemble(k2, m, lambda e: store[e["id"]], io.BytesIO())


# --------------------------------------------------------------------------- #
# metadata
# --------------------------------------------------------------------------- #
def test_metadata_round_trip_and_tamper(engine):
    keys, _ = engine.new_file_keys("f", OWNER)
    meta = {"filename": "../../etc/passwd ü.txt", "mime_type": "text/plain", "plaintext_sha256": "a" * 64}
    blob = engine.encrypt_metadata(keys, "f", meta)
    assert engine.decrypt_metadata(keys, "f", blob) == meta
    assert blob != engine.encrypt_metadata(keys, "f", meta)
    for pos in (0, 12, len(blob) - 1):
        t = bytearray(blob)
        t[pos] ^= 1
        with pytest.raises(MetadataIntegrityError):
            engine.decrypt_metadata(keys, "f", bytes(t))
    with pytest.raises(MetadataIntegrityError):
        engine.decrypt_metadata(keys, "f", blob[:20])
    dek = os.urandom(32)
    ka, kb = FileKeys.derive(dek, "fa"), FileKeys.derive(dek, "fb")
    with pytest.raises(MetadataIntegrityError):
        engine.decrypt_metadata(kb, "fb", engine.encrypt_metadata(ka, "fa", meta))
    other, _ = engine.new_file_keys("f", OWNER)
    with pytest.raises(MetadataIntegrityError):
        engine.decrypt_metadata(other, "f", blob)
    assert issubclass(MetadataIntegrityError, IntegrityError)


def test_metadata_shape_enforced(engine):
    keys, _ = engine.new_file_keys("f", OWNER)
    for bad in ({"filename": "a"}, {"filename": "a", "mime_type": "b", "plaintext_sha256": "c", "x": "d"},
                {"filename": 1, "mime_type": "b", "plaintext_sha256": "c"}):
        with pytest.raises(ValueError):
            engine.encrypt_metadata(keys, "f", bad)


# --------------------------------------------------------------------------- #
# FileKeys
# --------------------------------------------------------------------------- #
def test_key_separation_and_determinism():
    dek = os.urandom(32)
    a = FileKeys.derive(dek, "f1")
    b = FileKeys.derive(dek, "f1")
    c = FileKeys.derive(dek, "f2")
    assert len({a.k_enc, a.k_mac, a.k_meta}) == 3 and dek not in (a.k_enc, a.k_mac, a.k_meta)
    assert (a.k_enc, a.k_mac, a.k_meta) == (b.k_enc, b.k_mac, b.k_meta)
    assert not {a.k_enc, a.k_mac, a.k_meta} & {c.k_enc, c.k_mac, c.k_meta}
    d = FileKeys.derive(os.urandom(32), "f1")
    assert a.k_enc != d.k_enc


def test_file_keys_repr_destroy_pickle():
    import copy
    import pickle
    k = FileKeys.derive(os.urandom(32), "f1")
    secrets_ = [k.k_enc, k.k_mac, k.k_meta]
    for r in (repr(k), str(k), f"{k}"):
        for s in secrets_:
            assert s.hex() not in r and repr(s) not in r
    with pytest.raises(TypeError):
        pickle.dumps(k)
    with pytest.raises(TypeError):
        copy.copy(k)
    with k:
        pass
    assert k.destroyed and "destroyed" in repr(k)
    with pytest.raises(ValueError):
        _ = k.k_enc
    with pytest.raises(ValueError):
        FileKeys.derive(os.urandom(16), "f1")
    with pytest.raises(ValueError):
        FileKeys.derive(os.urandom(32), "")


def test_new_and_load_file_keys_match(engine, kms):
    keys, dk = engine.new_file_keys("f", OWNER)
    assert kms.wrapped_key_version(dk.wrapped) == (dk.key_id, dk.key_version)
    loaded = engine.load_file_keys("f", OWNER, dk.wrapped)
    assert (loaded.k_enc, loaded.k_mac, loaded.k_meta) == (keys.k_enc, keys.k_mac, keys.k_meta)
    assert repr(engine) == f"CryptoEngine(chunk_size={CS})"


def test_kek_rotation_does_not_affect_file(engine, kms):
    from app.contracts import KeyPurpose
    data = os.urandom(2 * CS)
    _, dk, store, mj, mac, _ = upload(engine, data)
    kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    rw = kms.rewrap_data_key(dk.wrapped, context={"file_id": "file-1", "owner_id": OWNER})
    assert download(engine, rw.wrapped, "file-1", mj, mac, store)[0] == data
    assert download(engine, dk.wrapped, "file-1", mj, mac, store)[0] == data


def test_engine_with_fake_kms():
    """The engine depends only on the contract: works with a trivial in-test fake."""
    from app.contracts import DataKey

    class FakeKMS:
        def __init__(self):
            self.store = {}

        def generate_data_key(self, *, context):
            k = os.urandom(32)
            w = os.urandom(8)
            self.store[w] = (k, dict(context))
            return DataKey(plaintext=k, wrapped=w, key_id="fake", key_version=1)

        def unwrap_data_key(self, wrapped, *, context):
            k, ctx = self.store[wrapped]
            if ctx != dict(context):
                raise KmsError("ctx")
            return k
    eng = CryptoEngine(FakeKMS(), 16)
    data = os.urandom(100)
    _, dk, store, mj, mac, _ = upload(eng, data)
    assert download(eng, dk.wrapped, "file-1", mj, mac, store)[0] == data
