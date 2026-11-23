"""AwsKMS against moto's in-process mock of the AWS KMS API.

These tests drive the real boto3 client, but every request is answered by
moto inside this process. They are NOT tests against real AWS KMS.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import boto3
import pytest
from moto import mock_aws

from app.contracts import KeyManagementService, KeyPurpose
from app.errors import KmsError
from app.kms import LocalKMS, build_kms
from app.kms.aws import AWS_BLOB_MAGIC, AwsKMS, parse_aws_blob

CTX = {"file_id": "f-1", "owner_id": "u-1"}
REGION = "us-east-1"


@pytest.fixture(autouse=True)
def _fake_aws_env(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_SESSION_TOKEN": "testing", "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def aws():
    with mock_aws():
        client = boto3.client("kms", region_name=REGION)
        yield client


@pytest.fixture
def local(tmp_path):
    return LocalKMS(tmp_path / "ks.json", os.urandom(32))


@pytest.fixture
def key_id(aws):
    return aws.create_key(Description="zt-test")["KeyMetadata"]["KeyId"]


@pytest.fixture
def kms(aws, key_id, local):
    return AwsKMS(key_id, local, client=aws)


def test_is_a_kms(kms):
    assert isinstance(kms, KeyManagementService)
    assert not getattr(AwsKMS, "__abstractmethods__", set())


def test_data_key_round_trip(kms):
    dk = kms.generate_data_key(context=CTX)
    assert len(dk.plaintext) == 32 and dk.key_version == 1
    assert dk.key_id.startswith("arn:aws:kms:") and dk.wrapped.startswith(AWS_BLOB_MAGIC)
    assert kms.unwrap_data_key(dk.wrapped, context=CTX) == dk.plaintext
    assert kms.unwrap_data_key(dk.wrapped, context=dict(reversed(list(CTX.items())))) == dk.plaintext
    assert kms.wrapped_key_version(dk.wrapped) == (dk.key_id, 1)
    assert kms.generate_data_key(context=CTX).plaintext != dk.plaintext


@pytest.mark.parametrize("ctx", [
    {"file_id": "f-2", "owner_id": "u-1"},
    {"file_id": "f-1", "owner_id": "u-2"},
    {"file_id": "f-1"},
    {},
])
def test_wrong_encryption_context_fails(kms, ctx):
    dk = kms.generate_data_key(context=CTX)
    with pytest.raises(KmsError):
        kms.unwrap_data_key(dk.wrapped, context=ctx)


def test_reserved_context_keys_rejected(kms):
    with pytest.raises(KmsError):
        kms.generate_data_key(context={"zt_kms_use": "secret"})


def test_tampered_ciphertext_fails(kms):
    dk = kms.generate_data_key(context=CTX)
    p = parse_aws_blob(dk.wrapped)
    hdr_len = len(dk.wrapped) - len(p.ciphertext)
    for pos in (hdr_len, hdr_len + 10, len(dk.wrapped) - 1):
        t = bytearray(dk.wrapped)
        t[pos] ^= 1
        with pytest.raises(KmsError):
            kms.unwrap_data_key(bytes(t), context=CTX)
    with pytest.raises(KmsError):
        kms.unwrap_data_key(b"ZTK1garbage", context=CTX)


def test_version_label_in_header_is_bound(kms):
    """Changing the header's version label changes the encryption context."""
    dk = kms.generate_data_key(context=CTX)
    p = parse_aws_blob(dk.wrapped)
    hdr = dk.wrapped[:len(dk.wrapped) - len(p.ciphertext)]
    forged = hdr[:-4] + (2).to_bytes(4, "big") + p.ciphertext
    with pytest.raises(KmsError):
        kms.unwrap_data_key(forged, context=CTX)


def test_blob_from_other_key_rejected(aws, local, kms):
    other_id = aws.create_key()["KeyMetadata"]["KeyId"]
    other = AwsKMS(other_id, local, client=aws)
    dk = other.generate_data_key(context=CTX)
    with pytest.raises(KmsError, match="different AWS KMS key"):
        kms.unwrap_data_key(dk.wrapped, context=CTX)


def test_rotate_and_rewrap(kms):
    old = kms.generate_data_key(context=CTX)
    info = kms.rotate(KeyPurpose.FILE_DEK_WRAP)
    assert info.version == 2 and info.state == "active"
    assert kms.unwrap_data_key(old.wrapped, context=CTX) == old.plaintext
    new = kms.generate_data_key(context=CTX)
    assert new.key_version == 2
    rw = kms.rewrap_data_key(old.wrapped, context=CTX)
    assert rw.plaintext == b"" and rw.key_version == 2
    assert kms.wrapped_key_version(rw.wrapped)[1] == 2
    assert kms.unwrap_data_key(rw.wrapped, context=CTX) == old.plaintext
    with pytest.raises(KmsError):
        kms.rewrap_data_key(old.wrapped, context={"file_id": "x", "owner_id": "u-1"})


def test_secret_encrypt_decrypt(kms):
    ctx = {"user_id": "u-1", "field": "totp"}
    ct = kms.encrypt(b"seed-bytes", context=ctx)
    assert kms.decrypt(ct, context=ctx) == b"seed-bytes"
    with pytest.raises(KmsError):
        kms.decrypt(ct, context={"user_id": "u-2", "field": "totp"})
    dk = kms.generate_data_key(context=ctx)
    with pytest.raises(KmsError):
        kms.decrypt(dk.wrapped, context=ctx)
    with pytest.raises(KmsError):
        kms.encrypt(b"x" * 4097, context=ctx)


def test_rotate_secret_purpose_refused(kms):
    with pytest.raises(KmsError, match="FILE_DEK_WRAP"):
        kms.rotate(KeyPurpose.SECRET_ENCRYPTION)


def test_signing_and_mac_delegated(kms, local):
    s = kms.sign(b"m", purpose=KeyPurpose.TOKEN_SIGNING)
    assert local.verify(b"m", s.signature, purpose=KeyPurpose.TOKEN_SIGNING, key_id=s.key_id, version=1)
    assert kms.verify(b"m", s.signature, purpose=KeyPurpose.TOKEN_SIGNING, key_id=s.key_id, version=1)
    assert kms.mac(b"x", purpose=KeyPurpose.LOOKUP_HMAC) == local.mac(b"x", purpose=KeyPurpose.LOOKUP_HMAC)
    assert kms.public_key_pem(purpose=KeyPurpose.TOKEN_SIGNING) == local.public_key_pem(purpose=KeyPurpose.TOKEN_SIGNING)
    assert kms.rotate(KeyPurpose.TOKEN_SIGNING).version == 2


def test_list_keys(kms):
    kms.sign(b"m", purpose=KeyPurpose.AUDIT_SIGNING)
    purposes = {k.purpose for k in kms.list_keys()}
    assert {"file-dek-wrap", "secret-encryption", "audit-signing"} <= purposes


def test_unknown_key_gives_kms_error(aws, local):
    k = AwsKMS("00000000-0000-0000-0000-000000000000", local, client=aws)
    with pytest.raises(KmsError) as exc:
        k.generate_data_key(context=CTX)
    assert "NotFoundException" in str(exc.value)


def test_repr_does_not_leak(kms):
    assert "testing" not in repr(kms)


def test_build_kms_aws(aws, key_id, tmp_path):
    s = SimpleNamespace(env="test", data_dir=tmp_path, kms_root_key=None, kms_root_key_file=None,
                        kms_backend="aws", kms_keystore_path=tmp_path / "kms" / "ks.json",
                        aws_kms_key_id=key_id, aws_kms_endpoint_url=None, s3_region=REGION)
    k = build_kms(s)
    assert isinstance(k, AwsKMS)
    dk = k.generate_data_key(context=CTX)
    assert k.unwrap_data_key(dk.wrapped, context=CTX) == dk.plaintext
