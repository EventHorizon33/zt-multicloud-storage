"""LocalKMS unit tests. No network, no cloud."""
from __future__ import annotations

import base64
import json
import logging
import os
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.contracts import KeyManagementService, KeyPurpose
from app.errors import KmsError
from app.kms import LocalKMS, build_kms, load_root_key
from app.kms.local import BLOB_MAGIC, parse_blob

CTX = {"file_id": "f-1", "owner_id": "u-1"}


@pytest.fixture
def root_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / "kms" / "keystore.json"


@pytest.fixture
def kms(path: Path, root_key: bytes) -> LocalKMS:
    return LocalKMS(path, root_key)


def _all_material(k: LocalKMS) -> dict:
    """Test-only: reach into the in-memory table to get raw key material."""
    return {(p, kv.version): kv.material for p, vs in k._keys.items() for kv in vs}


# --------------------------------------------------------------------------- #
# basics / contract
# --------------------------------------------------------------------------- #
def test_implements_every_abstract_method(kms):
    assert isinstance(kms, KeyManagementService)
    assert not getattr(LocalKMS, "__abstractmethods__", set())


def test_root_key_must_be_32_bytes(path):
    for bad in (b"", os.urandom(16), os.urandom(33), "x" * 32):
        with pytest.raises(KmsError):
            LocalKMS(path, bad)


def test_generate_data_key_shape_and_randomness(kms):
    a = kms.generate_data_key(context=CTX)
    b = kms.generate_data_key(context=CTX)
    assert len(a.plaintext) == 32 and a.plaintext != b.plaintext
    assert a.wrapped != b.wrapped
    assert a.key_id == "local/file-dek-wrap" and a.key_version == 1
    assert a.wrapped.startswith(BLOB_MAGIC)
    assert a.plaintext not in a.wrapped


def test_wrap_unwrap_round_trip(kms):
    for _ in range(25):
        dk = kms.generate_data_key(context=CTX)
        assert kms.unwrap_data_key(dk.wrapped, context=CTX) == dk.plaintext


def test_context_order_irrelevant(kms):
    dk = kms.generate_data_key(context={"a": "1", "b": "2"})
    assert kms.unwrap_data_key(dk.wrapped, context={"b": "2", "a": "1"}) == dk.plaintext


@pytest.mark.parametrize("ctx", [
    {"file_id": "f-2", "owner_id": "u-1"},
    {"file_id": "f-1", "owner_id": "u-2"},
    {"file_id": "f-1"},
    {},
    {"file_id": "f-1", "owner_id": "u-1", "extra": "x"},
    {"file_id": "f-1", "owner_id": "u-1 "},
    {"file_idowner_id": "f-1u-1"},
])
def test_wrong_context_fails(kms, ctx):
    dk = kms.generate_data_key(context=CTX)
    with pytest.raises(KmsError):
        kms.unwrap_data_key(dk.wrapped, context=ctx)


def test_context_encoding_not_ambiguous(kms):
    dk = kms.generate_data_key(context={"a": "bc"})
    with pytest.raises(KmsError):
        kms.unwrap_data_key(dk.wrapped, context={"ab": "c"})


def test_invalid_context_rejected(kms):
    for bad in ({"a": 1}, {1: "a"}, {"": "x"}, "file_id=1"):
        with pytest.raises(KmsError):
            kms.generate_data_key(context=bad)


def test_bit_flip_anywhere_fails(kms):
    dk = kms.generate_data_key(context=CTX)
    w = dk.wrapped
    for pos in range(len(w)):
        for bit in (0x01, 0x80):
            t = bytearray(w)
            t[pos] ^= bit
            with pytest.raises(KmsError):
                kms.unwrap_data_key(bytes(t), context=CTX)


def test_truncation_and_extension_fail(kms):
    w = kms.generate_data_key(context=CTX).wrapped
    for cut in range(len(w)):
        with pytest.raises(KmsError):
            kms.unwrap_data_key(w[:cut], context=CTX)
    with pytest.raises(KmsError):
        kms.unwrap_data_key(w + b"\x00", context=CTX)


def test_secret_blob_not_accepted_as_data_key(kms):
    blob = kms.encrypt(os.urandom(32), context=CTX)
    with pytest.raises(KmsError):
        kms.unwrap_data_key(blob, context=CTX)
    dk = kms.generate_data_key(context=CTX)
    with pytest.raises(KmsError):
        kms.decrypt(dk.wrapped, context=CTX)


def test_unknown_version_fails(kms):
    w = kms.generate_data_key(context=CTX).wrapped
    p = parse_blob(w)
    hdr = p.header[:-4] + (99).to_bytes(4, "big")
    with pytest.raises(KmsError, match="unknown key version"):
        kms.unwrap_data_key(hdr + p.nonce + p.ciphertext, context=CTX)


def test_wrapped_key_version_parses_header_only(kms):
    dk = kms.generate_data_key(context=CTX)
    assert kms.wrapped_key_version(dk.wrapped) == ("local/file-dek-wrap", 1)
    with pytest.raises(KmsError):
        kms.wrapped_key_version(b"garbage")


# --------------------------------------------------------------------------- #
# rotation
# --------------------------------------------------------------------------- #
def test_rotation_old_unwraps_new_wraps_rewrap(kms):
    old = kms.generate_data_key(context=CTX)
    info = kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    assert info.version == 2 and info.state == "active"
    assert kms.unwrap_data_key(old.wrapped, context=CTX) == old.plaintext
    new = kms.generate_data_key(context=CTX)
    assert new.key_version == 2 and kms.wrapped_key_version(new.wrapped)[1] == 2

    rw = kms.rewrap_data_key(old.wrapped, context=CTX)
    assert rw.plaintext == b""
    assert rw.key_version == 2 and kms.wrapped_key_version(rw.wrapped) == ("local/file-dek-wrap", 2)
    assert kms.unwrap_data_key(rw.wrapped, context=CTX) == old.plaintext
    with pytest.raises(KmsError):
        kms.rewrap_data_key(old.wrapped, context={"file_id": "other", "owner_id": "u-1"})

    states = {(k.purpose, k.version): k.state for k in kms.list_keys()}
    assert states[("file-dek-wrap", 1)] == "decrypt-only"
    assert states[("file-dek-wrap", 2)] == "active"


def test_rotation_is_per_purpose(kms):
    kms.ensure_keys()
    kms.rotate(KeyPurpose.LOOKUP_HMAC)
    versions = {(k.purpose, k.version) for k in kms.list_keys()}
    assert ("lookup-hmac", 2) in versions
    assert ("file-dek-wrap", 2) not in versions


def test_list_keys_metadata_only(kms):
    infos = kms.ensure_keys()
    assert {k.purpose for k in infos} == {p.value for p in KeyPurpose}
    material = set(_all_material(kms).values())
    for k in infos:
        assert isinstance(k.created_at, datetime) and k.created_at.tzinfo is not None
        for v in vars(k).values() if hasattr(k, "__dict__") else (k.purpose, k.key_id, k.algorithm, k.state):
            assert v not in material
    algs = {k.purpose: k.algorithm for k in infos}
    assert algs["file-dek-wrap"] == algs["secret-encryption"] == "AES-256-GCM"
    assert algs["token-signing"] == algs["audit-signing"] == "Ed25519"
    assert algs["audit-pseudonym"] == algs["lookup-hmac"] == "HMAC-SHA256"


def test_key_separation_all_purposes_distinct(kms):
    kms.ensure_keys()
    material = list(_all_material(kms).values())
    assert len(material) == len(KeyPurpose) and len(set(material)) == len(material)


# --------------------------------------------------------------------------- #
# persistence / keystore file
# --------------------------------------------------------------------------- #
def test_persistence_across_instances(path, root_key, kms):
    dk = kms.generate_data_key(context=CTX)
    sig = kms.sign(b"m", purpose=KeyPurpose.TOKEN_SIGNING)
    mac = kms.mac(b"m", purpose=KeyPurpose.LOOKUP_HMAC)
    kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    other = LocalKMS(path, root_key)
    assert other.unwrap_data_key(dk.wrapped, context=CTX) == dk.plaintext
    assert other.verify(b"m", sig.signature, purpose=KeyPurpose.TOKEN_SIGNING,
                        key_id=sig.key_id, version=sig.version)
    assert other.mac(b"m", purpose=KeyPurpose.LOOKUP_HMAC) == mac
    assert other.generate_data_key(context=CTX).key_version == 2


def test_second_instance_sees_rotation_by_first(path, root_key, kms):
    kms.ensure_keys()
    other = LocalKMS(path, root_key)
    kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    # mtime granularity can hide a same-size rewrite; force a stat difference
    os.utime(path, ns=(1, 1))
    assert other.generate_data_key(context=CTX).key_version == 2


def test_wrong_root_key_fails(path, kms):
    kms.ensure_keys()
    with pytest.raises(KmsError):
        LocalKMS(path, os.urandom(32))


def test_keystore_perms_and_no_plaintext_material(path, kms):
    kms.ensure_keys()
    kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    dk = kms.generate_data_key(context=CTX)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    raw = path.read_bytes()
    for material in _all_material(kms).values():
        for enc in (material, material.hex().encode(), base64.b64encode(material),
                    base64.urlsafe_b64encode(material).rstrip(b"=")):
            assert enc not in raw
    assert dk.plaintext not in raw and base64.b64encode(dk.plaintext) not in raw
    assert not [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]


def _edit(path: Path, fn) -> None:
    doc = json.loads(path.read_text())
    fn(doc)
    path.write_text(json.dumps(doc))


def test_swapped_entries_detected(path, root_key, kms):
    kms.ensure_keys()

    def swap(doc):
        a, b = doc["keys"]["file-dek-wrap"]["versions"][0], doc["keys"]["secret-encryption"]["versions"][0]
        a["nonce"], b["nonce"] = b["nonce"], a["nonce"]
        a["ct"], b["ct"] = b["ct"], a["ct"]
    _edit(path, swap)
    with pytest.raises(KmsError):
        LocalKMS(path, root_key)


def test_swapped_entries_detected_even_with_valid_file_mac(path, root_key, kms):
    """Entry AAD alone must catch a swap: recompute the file MAC with the
    (test-only) MAC key so only the per-entry binding stands in the way."""
    import hashlib
    import hmac as _h
    kms.ensure_keys()
    doc = json.loads(path.read_text())
    a, b = doc["keys"]["audit-pseudonym"]["versions"][0], doc["keys"]["lookup-hmac"]["versions"][0]
    a["nonce"], b["nonce"], a["ct"], b["ct"] = b["nonce"], a["nonce"], b["ct"], a["ct"]
    body = {k: doc[k] for k in ("format", "v", "keys")}
    doc["mac"] = _h.new(kms._mac_key, json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
                        hashlib.sha256).hexdigest()
    path.write_text(json.dumps(doc))
    with pytest.raises(KmsError, match="entry authentication"):
        LocalKMS(path, root_key)


@pytest.mark.parametrize("mutate", [
    lambda d: d["keys"].pop("lookup-hmac"),
    lambda d: d["keys"]["file-dek-wrap"]["versions"].pop(),
    lambda d: d["keys"]["file-dek-wrap"]["versions"][0].update(created_at="2000-01-01T00:00:00+00:00"),
    lambda d: d.update(v=2),
    lambda d: d.update(mac="0" * 64),
])
def test_keystore_tamper_detected(path, root_key, kms, mutate):
    kms.ensure_keys()
    kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    _edit(path, mutate)
    with pytest.raises(KmsError):
        LocalKMS(path, root_key)


def test_corrupt_keystore_detected(path, root_key, kms):
    kms.ensure_keys()
    path.write_bytes(b"{not json")
    with pytest.raises(KmsError):
        LocalKMS(path, root_key)


def test_deleted_keystore_is_not_silently_recreated(path, kms):
    kms.ensure_keys()
    path.unlink()
    with pytest.raises(KmsError):
        kms.generate_data_key(context=CTX)


def test_repr_does_not_leak(kms):
    kms.ensure_keys()
    r = repr(kms) + repr(kms._keys)
    for m in _all_material(kms).values():
        assert m.hex() not in r and repr(m) not in r


def test_thread_safety_concurrent_first_use(path, root_key):
    k = LocalKMS(path, root_key)
    errors, results = [], []

    def work():
        try:
            for _ in range(10):
                dk = k.generate_data_key(context=CTX)
                results.append(k.unwrap_data_key(dk.wrapped, context=CTX) == dk.plaintext)
        except Exception as e:  # pragma: no cover
            errors.append(e)
    ts = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors and all(results) and len(results) == 80
    assert [i.version for i in k.list_keys() if i.purpose == "file-dek-wrap"] == [1]


# --------------------------------------------------------------------------- #
# sign / verify / mac / secrets
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("purpose", [KeyPurpose.TOKEN_SIGNING, KeyPurpose.AUDIT_SIGNING])
def test_sign_verify(kms, purpose):
    s = kms.sign(b"hello", purpose=purpose)
    assert len(s.signature) == 64 and s.version == 1
    assert kms.verify(b"hello", s.signature, purpose=purpose, key_id=s.key_id, version=1)
    assert not kms.verify(b"hellO", s.signature, purpose=purpose, key_id=s.key_id, version=1)
    bad = bytearray(s.signature)
    bad[0] ^= 1
    assert not kms.verify(b"hello", bytes(bad), purpose=purpose, key_id=s.key_id, version=1)
    assert not kms.verify(b"hello", b"short", purpose=purpose, key_id=s.key_id, version=1)
    assert not kms.verify(b"hello", s.signature, purpose=purpose, key_id="other", version=1)
    assert not kms.verify(b"hello", s.signature, purpose=purpose, key_id=s.key_id, version=7)


def test_signing_purposes_separated(kms):
    s = kms.sign(b"m", purpose=KeyPurpose.TOKEN_SIGNING)
    assert not kms.verify(b"m", s.signature, purpose=KeyPurpose.AUDIT_SIGNING,
                          key_id="local/audit-signing", version=1)


def test_sign_after_rotation_old_still_verifies(kms):
    old = kms.sign(b"m", purpose=KeyPurpose.AUDIT_SIGNING)
    old_pem = kms.public_key_pem(purpose=KeyPurpose.AUDIT_SIGNING)
    kms.rotate(KeyPurpose.AUDIT_SIGNING)
    new = kms.sign(b"m", purpose=KeyPurpose.AUDIT_SIGNING)
    assert new.version == 2 and new.signature != old.signature
    assert kms.verify(b"m", old.signature, purpose=KeyPurpose.AUDIT_SIGNING, key_id=old.key_id, version=1)
    assert kms.verify(b"m", new.signature, purpose=KeyPurpose.AUDIT_SIGNING, key_id=new.key_id, version=2)
    assert not kms.verify(b"m", old.signature, purpose=KeyPurpose.AUDIT_SIGNING, key_id=old.key_id, version=2)
    assert kms.public_key_pem(purpose=KeyPurpose.AUDIT_SIGNING, version=1) == old_pem
    assert kms.public_key_pem(purpose=KeyPurpose.AUDIT_SIGNING) != old_pem


def test_public_key_pem_verifies_externally(kms):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    s = kms.sign(b"tok", purpose=KeyPurpose.TOKEN_SIGNING)
    pem = kms.public_key_pem(purpose=KeyPurpose.TOKEN_SIGNING, version=1)
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    load_pem_public_key(pem).verify(s.signature, b"tok")
    with pytest.raises(KmsError):
        kms.public_key_pem(purpose=KeyPurpose.TOKEN_SIGNING, version=5)


def test_wrong_algorithm_for_purpose_rejected(kms):
    with pytest.raises(KmsError):
        kms.sign(b"m", purpose=KeyPurpose.LOOKUP_HMAC)
    with pytest.raises(KmsError):
        kms.mac(b"m", purpose=KeyPurpose.TOKEN_SIGNING)
    with pytest.raises(KmsError):
        kms.mac(b"m", purpose=KeyPurpose.FILE_DEK_WRAP)
    with pytest.raises(KmsError):
        kms.public_key_pem(purpose=KeyPurpose.SECRET_ENCRYPTION)


def test_mac_stability_and_separation(kms):
    a1 = kms.mac(b"user-1", purpose=KeyPurpose.AUDIT_PSEUDONYM)
    assert len(a1) == 32 and a1 == kms.mac(b"user-1", purpose=KeyPurpose.AUDIT_PSEUDONYM)
    assert a1 != kms.mac(b"user-2", purpose=KeyPurpose.AUDIT_PSEUDONYM)
    assert a1 != kms.mac(b"user-1", purpose=KeyPurpose.LOOKUP_HMAC)
    kms.rotate(KeyPurpose.AUDIT_PSEUDONYM)
    assert kms.mac(b"user-1", purpose=KeyPurpose.AUDIT_PSEUDONYM) != a1  # unlinkability lever


def test_secret_encrypt_decrypt_context_bound(kms):
    seed = b"JBSWY3DPEHPK3PXP"
    ctx = {"user_id": "u-1", "field": "totp_seed"}
    ct = kms.encrypt(seed, context=ctx)
    assert seed not in ct and ct != kms.encrypt(seed, context=ctx)
    assert kms.decrypt(ct, context=ctx) == seed
    assert kms.decrypt(kms.encrypt(b"", context=ctx), context=ctx) == b""
    with pytest.raises(KmsError):
        kms.decrypt(ct, context={"user_id": "u-2", "field": "totp_seed"})
    t = bytearray(ct)
    t[-1] ^= 1
    with pytest.raises(KmsError):
        kms.decrypt(bytes(t), context=ctx)
    kms.rotate(KeyPurpose.SECRET_ENCRYPTION)
    assert kms.decrypt(ct, context=ctx) == seed
    assert kms.wrapped_key_version.__name__  # sanity
    with pytest.raises(KmsError):
        kms.encrypt(b"x" * (64 * 1024 + 1), context=ctx)


def test_no_key_material_in_logs(path, root_key, caplog):
    caplog.set_level(logging.DEBUG)
    k = LocalKMS(path, root_key)
    k.ensure_keys()
    k.rotate(KeyPurpose.FILE_DEK_WRAP)
    dk = k.generate_data_key(context=CTX)
    text = caplog.text
    for m in list(_all_material(k).values()) + [dk.plaintext, root_key]:
        assert m.hex() not in text and base64.b64encode(m).decode() not in text


# --------------------------------------------------------------------------- #
# load_root_key / build_kms
# --------------------------------------------------------------------------- #
def _settings(tmp_path, **kw):
    base = dict(env="test", data_dir=tmp_path, kms_root_key=None, kms_root_key_file=None,
                kms_backend="local", kms_keystore_path=tmp_path / "kms" / "keystore.json",
                aws_kms_key_id=None, aws_kms_endpoint_url=None, s3_region="us-east-1")
    base.update(kw)
    return SimpleNamespace(**base)


def test_load_root_key_inline_and_file(tmp_path):
    key = os.urandom(32)
    assert load_root_key(_settings(tmp_path, kms_root_key=base64.b64encode(key).decode(),
                                   env="production")) == key
    f = tmp_path / "root.key"
    f.write_text(base64.b64encode(key).decode() + "\n")
    assert load_root_key(_settings(tmp_path, kms_root_key_file=f, env="production")) == key


@pytest.mark.parametrize("value", ["not base64!!", base64.b64encode(b"short").decode()])
def test_load_root_key_rejects_bad_values(tmp_path, value):
    with pytest.raises(KmsError) as exc:
        load_root_key(_settings(tmp_path, kms_root_key=value))
    assert value not in str(exc.value)


def test_production_without_root_key_raises(tmp_path):
    with pytest.raises(KmsError):
        load_root_key(_settings(tmp_path, env="production"))
    with pytest.raises(KmsError):
        build_kms(_settings(tmp_path, env="production"))
    assert not (tmp_path / "kms" / "dev-root.key").exists()


@pytest.mark.parametrize("env", ["test", "development"])
def test_dev_root_key_generated_once(tmp_path, caplog, env):
    caplog.set_level(logging.WARNING)
    s = _settings(tmp_path, env=env)
    k1 = load_root_key(s)
    f = tmp_path / "kms" / "dev-root.key"
    assert f.exists() and stat.S_IMODE(os.stat(f).st_mode) == 0o600
    assert load_root_key(s) == k1 and len(k1) == 32
    assert "DEVELOPMENT-ONLY" in caplog.text
    assert base64.b64encode(k1).decode() not in caplog.text


def test_build_kms_local_and_errors(tmp_path):
    k = build_kms(_settings(tmp_path))
    assert isinstance(k, LocalKMS)
    dk = k.generate_data_key(context=CTX)
    assert build_kms(_settings(tmp_path)).unwrap_data_key(dk.wrapped, context=CTX) == dk.plaintext
    with pytest.raises(KmsError):
        build_kms(_settings(tmp_path, kms_backend="vault"))
    with pytest.raises(KmsError):
        build_kms(_settings(tmp_path, kms_backend="aws"))


def test_build_kms_with_real_settings_object(tmp_path, monkeypatch):
    from app.config import Settings
    monkeypatch.chdir(tmp_path)
    s = Settings(env="test", data_dir=tmp_path / "d")
    k = build_kms(s)
    assert isinstance(k, LocalKMS)
    k.ensure_keys()
    assert Path(s.kms_keystore_path).exists()
