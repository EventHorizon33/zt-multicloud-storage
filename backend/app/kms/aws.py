"""AWS KMS adapter.

Scope (stated plainly, see NOTES.md):
  * data-key envelope operations (generate / unwrap / rewrap) and small-secret
    encrypt / decrypt go to AWS KMS through boto3, using one symmetric
    customer-managed key;
  * signing (TOKEN_SIGNING, AUDIT_SIGNING) and MAC (AUDIT_PSEUDONYM,
    LOOKUP_HMAC) are delegated to an injected ``KeyManagementService``
    (normally :class:`app.kms.local.LocalKMS`).

This module has only been exercised against moto's in-process mock, never
against real AWS.
"""
from __future__ import annotations

import logging
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from app.contracts import DataKey, KeyInfo, KeyManagementService, KeyPurpose, Signature
from app.errors import KmsError

from ._encoding import validate_context

logger = logging.getLogger(__name__)

AWS_BLOB_MAGIC = b"ZTA1"       # "ZTA" + format version 1
KIND_DATA_KEY = 0x01
KIND_SECRET = 0x02
_KIND_USE = {KIND_DATA_KEY: "data-key", KIND_SECRET: "secret"}

# Entries this adapter adds to the AWS encryption context. Callers may not use
# these names. They bind the blob's use and version label cryptographically.
CTX_USE = "zt_kms_use"
CTX_VERSION = "zt_kms_version"
_RESERVED = (CTX_USE, CTX_VERSION)

DATA_KEY_BYTES = 32
AWS_ENCRYPT_MAX_BYTES = 4096   # AWS KMS Encrypt limit for symmetric keys

_AWS_PURPOSES = (KeyPurpose.FILE_DEK_WRAP, KeyPurpose.SECRET_ENCRYPTION)
_LOCAL_PURPOSES = (KeyPurpose.TOKEN_SIGNING, KeyPurpose.AUDIT_SIGNING,
                   KeyPurpose.AUDIT_PSEUDONYM, KeyPurpose.LOOKUP_HMAC)


@dataclass(frozen=True)
class ParsedAwsBlob:
    kind: int
    key_id: str        # key ARN the blob was produced with
    version: int       # version label (1 + rotations listed at wrap time)
    ciphertext: bytes  # opaque AWS KMS CiphertextBlob


def parse_aws_blob(blob: bytes) -> ParsedAwsBlob:
    """Parse the header this adapter puts in front of an AWS CiphertextBlob.
    Raises :class:`KmsError` if the blob is not in that format."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise KmsError("wrapped blob must be bytes")
    blob = bytes(blob)
    if len(blob) < 7 or blob[:4] != AWS_BLOB_MAGIC:
        raise KmsError("unrecognised wrapped-blob format")
    kind = blob[4]
    if kind not in _KIND_USE:
        raise KmsError("unrecognised wrapped-blob kind")
    (id_len,) = struct.unpack(">H", blob[5:7])
    end = 7 + id_len + 4
    if id_len == 0 or len(blob) <= end:
        raise KmsError("wrapped blob is truncated")
    try:
        key_id = blob[7:7 + id_len].decode("ascii")
    except UnicodeDecodeError:
        raise KmsError("malformed wrapped-blob header") from None
    (version,) = struct.unpack(">I", blob[7 + id_len:end])
    if version < 1:
        raise KmsError("malformed wrapped-blob header")
    return ParsedAwsBlob(kind=kind, key_id=key_id, version=version, ciphertext=blob[end:])


def _build_blob(kind: int, key_id: str, version: int, ciphertext: bytes) -> bytes:
    kid = key_id.encode("ascii")
    return (AWS_BLOB_MAGIC + bytes([kind]) + struct.pack(">H", len(kid)) + kid
            + struct.pack(">I", version) + bytes(ciphertext))


class AwsKMS(KeyManagementService):
    """KeyManagementService backed by AWS KMS for envelope encryption.

    Security properties:
      * the key-encryption key never leaves AWS KMS; this process only sees
        data keys it asked for;
      * the caller's ``context`` is passed as the AWS ``EncryptionContext``
        (plus two reserved entries binding the blob's use and version label),
        so unwrap with a different context fails inside AWS KMS;
      * decrypt always names the expected key (``KeyId``), so a ciphertext
        produced under some other key the role can use is rejected.

    Note that AWS records encryption contexts in CloudTrail in clear text;
    only non-secret identifiers belong in ``context``.
    """

    def __init__(self, key_id: str, local: KeyManagementService, *, client: Any = None,
                 endpoint_url: str | None = None, region_name: str | None = None,
                 version_cache_ttl: float = 60.0,
                 monotonic: Callable[[], float] = time.monotonic):
        if not key_id:
            raise KmsError("AWS KMS key id is required")
        if not isinstance(local, KeyManagementService):
            raise KmsError("AwsKMS needs a KeyManagementService for signing and MAC purposes")
        if client is None:
            try:
                import boto3
                client = boto3.client("kms", endpoint_url=endpoint_url, region_name=region_name)
            except Exception as exc:  # NoRegionError, missing boto3, ...
                raise KmsError(f"could not create AWS KMS client ({type(exc).__name__})") from None
        self._client = client
        self._configured_key_id = key_id
        self._local = local
        self._ttl = version_cache_ttl
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._arn: str | None = None
        self._created_at: datetime | None = None
        self._version: int | None = None
        self._version_at = 0.0

    def __repr__(self) -> str:
        return f"AwsKMS(key_id={self._configured_key_id!r})"

    # ------------------------------------------------------------------ #
    # data keys
    # ------------------------------------------------------------------ #
    def generate_data_key(self, *, context: Mapping[str, str]) -> DataKey:
        """``kms:GenerateDataKey`` (AES_256) bound to ``context``."""
        arn, version = self._key_arn(), self._current_version()
        resp = self._call("GenerateDataKey", self._client.generate_data_key,
                          KeyId=arn, KeySpec="AES_256",
                          EncryptionContext=self._aws_context(context, KIND_DATA_KEY, version))
        plaintext = bytes(resp["Plaintext"])
        if len(plaintext) != DATA_KEY_BYTES:
            raise KmsError("AWS KMS returned a data key of unexpected length")
        return DataKey(plaintext=plaintext,
                       wrapped=_build_blob(KIND_DATA_KEY, arn, version, resp["CiphertextBlob"]),
                       key_id=arn, key_version=version)

    def unwrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> bytes:
        """``kms:Decrypt`` with the same context; raises KmsError on any failure."""
        plaintext = self._decrypt(KIND_DATA_KEY, wrapped, context)
        if len(plaintext) != DATA_KEY_BYTES:
            raise KmsError("unwrap failed")
        return plaintext

    def rewrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> DataKey:
        """``kms:ReEncrypt`` under the key's current material. The data key
        never reaches this process; ``DataKey.plaintext`` is ``b""``."""
        parsed = self._parse_own(wrapped, KIND_DATA_KEY)
        arn, version = self._key_arn(), self._current_version()
        resp = self._call(
            "ReEncrypt", self._client.re_encrypt,
            CiphertextBlob=parsed.ciphertext,
            SourceKeyId=arn,
            SourceEncryptionContext=self._aws_context(context, KIND_DATA_KEY, parsed.version),
            DestinationKeyId=arn,
            DestinationEncryptionContext=self._aws_context(context, KIND_DATA_KEY, version))
        return DataKey(plaintext=b"",
                       wrapped=_build_blob(KIND_DATA_KEY, arn, version, resp["CiphertextBlob"]),
                       key_id=arn, key_version=version)

    def wrapped_key_version(self, wrapped: bytes) -> tuple[str, int]:
        """(key ARN, version label) from the header only; no AWS call."""
        parsed = parse_aws_blob(wrapped)
        if parsed.kind != KIND_DATA_KEY:
            raise KmsError("not a wrapped data key")
        return parsed.key_id, parsed.version

    # ------------------------------------------------------------------ #
    # small secrets
    # ------------------------------------------------------------------ #
    def encrypt(self, plaintext: bytes, *, context: Mapping[str, str]) -> bytes:
        """``kms:Encrypt`` of a small secret (<= 4096 bytes) bound to ``context``."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise KmsError("plaintext must be bytes")
        if len(plaintext) > AWS_ENCRYPT_MAX_BYTES:
            raise KmsError("secret too large for AWS KMS Encrypt (max 4096 bytes)")
        arn, version = self._key_arn(), self._current_version()
        resp = self._call("Encrypt", self._client.encrypt, KeyId=arn, Plaintext=bytes(plaintext),
                          EncryptionContext=self._aws_context(context, KIND_SECRET, version))
        return _build_blob(KIND_SECRET, arn, version, resp["CiphertextBlob"])

    def decrypt(self, ciphertext: bytes, *, context: Mapping[str, str]) -> bytes:
        return self._decrypt(KIND_SECRET, ciphertext, context)

    # ------------------------------------------------------------------ #
    # signing / MAC: delegated
    # ------------------------------------------------------------------ #
    def sign(self, message: bytes, *, purpose: KeyPurpose) -> Signature:
        return self._local.sign(message, purpose=purpose)

    def verify(self, message: bytes, signature: bytes, *, purpose: KeyPurpose,
               key_id: str, version: int) -> bool:
        return self._local.verify(message, signature, purpose=purpose, key_id=key_id, version=version)

    def public_key_pem(self, *, purpose: KeyPurpose, version: int | None = None) -> bytes:
        return self._local.public_key_pem(purpose=purpose, version=version)

    def mac(self, message: bytes, *, purpose: KeyPurpose) -> bytes:
        return self._local.mac(message, purpose=purpose)

    def mac_all_versions(self, message: bytes, *, purpose: KeyPurpose) -> list[bytes]:
        return self._local.mac_all_versions(message, purpose=purpose)

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def rotate(self, purpose: KeyPurpose) -> KeyInfo:
        """FILE_DEK_WRAP: ``kms:RotateKeyOnDemand`` on the customer-managed key.
        Signing/MAC purposes: delegated. SECRET_ENCRYPTION: refused, because it
        shares the AWS key with FILE_DEK_WRAP (rotate that purpose instead)."""
        try:
            purpose = KeyPurpose(purpose)
        except ValueError:
            raise KmsError("unknown key purpose") from None
        if purpose in _LOCAL_PURPOSES:
            return self._local.rotate(purpose)
        if purpose is KeyPurpose.SECRET_ENCRYPTION:
            raise KmsError("SECRET_ENCRYPTION shares the AWS KMS key with FILE_DEK_WRAP; "
                           "rotate FILE_DEK_WRAP to rotate both")
        arn = self._key_arn()
        before = self._current_version(force=True)
        rotate_now = getattr(self._client, "rotate_key_on_demand", None)
        if rotate_now is None:
            # Old SDK without RotateKeyOnDemand: the best available is AWS's
            # automatic rotation, which does not create a version now.
            self._call("EnableKeyRotation", self._client.enable_key_rotation, KeyId=arn)
            raise KmsError("on-demand rotation is not available in this boto3 version; automatic "
                           "rotation was enabled on the key instead and no new version exists yet")
        self._call("RotateKeyOnDemand", rotate_now, KeyId=arn)
        listed = self._current_version(force=True)
        with self._lock:
            # Real AWS may list an on-demand rotation only after it completes.
            self._version = max(listed, before + 1)
            self._version_at = self._monotonic()
            version = self._version
        logger.info("aws kms key rotated purpose=%s version=%d", purpose.value, version)
        return self._aws_info(purpose, version)

    def list_keys(self) -> list[KeyInfo]:
        """The AWS key (reported once per purpose that uses it, current version
        label only) plus the delegate's signing/MAC key versions."""
        version = self._current_version()
        out = [self._aws_info(p, version) for p in _AWS_PURPOSES]
        local_names = {p.value for p in _LOCAL_PURPOSES}
        out.extend(k for k in self._local.list_keys() if k.purpose in local_names)
        return out

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #
    def _aws_info(self, purpose: KeyPurpose, version: int) -> KeyInfo:
        arn = self._key_arn()
        return KeyInfo(purpose=purpose.value, key_id=arn, version=version,
                       algorithm="AWS-KMS/SYMMETRIC_DEFAULT",
                       created_at=self._created_at or datetime.now(timezone.utc), state="active")

    def _aws_context(self, context: Mapping[str, str], kind: int, version: int) -> dict[str, str]:
        ctx = validate_context(context)
        for name in _RESERVED:
            if name in ctx:
                raise KmsError(f"context key {name!r} is reserved")
        ctx[CTX_USE] = _KIND_USE[kind]
        ctx[CTX_VERSION] = str(version)
        return ctx

    def _parse_own(self, blob: bytes, kind: int) -> ParsedAwsBlob:
        parsed = parse_aws_blob(blob)
        if parsed.kind != kind:
            raise KmsError("blob was not produced for this purpose")
        if parsed.key_id != self._key_arn():
            raise KmsError("blob was produced with a different AWS KMS key")
        return parsed

    def _decrypt(self, kind: int, blob: bytes, context: Mapping[str, str]) -> bytes:
        parsed = self._parse_own(blob, kind)
        resp = self._call("Decrypt", self._client.decrypt,
                          CiphertextBlob=parsed.ciphertext, KeyId=parsed.key_id,
                          EncryptionContext=self._aws_context(context, kind, parsed.version))
        return bytes(resp["Plaintext"])

    def _key_arn(self) -> str:
        with self._lock:
            if self._arn is not None:
                return self._arn
        meta = self._call("DescribeKey", self._client.describe_key,
                          KeyId=self._configured_key_id)["KeyMetadata"]
        with self._lock:
            self._arn = meta["Arn"]
            created = meta.get("CreationDate")
            if isinstance(created, datetime):
                self._created_at = created.astimezone(timezone.utc)
            return self._arn

    def _current_version(self, *, force: bool = False) -> int:
        """Version label = 1 + number of rotations AWS lists for the key.
        Cached for ``version_cache_ttl`` seconds."""
        now = self._monotonic()
        with self._lock:
            if not force and self._version is not None and now - self._version_at < self._ttl:
                return self._version
        arn = self._key_arn()
        count, marker = 0, None
        while True:
            kwargs: dict[str, Any] = {"KeyId": arn}
            if marker:
                kwargs["Marker"] = marker
            resp = self._call("ListKeyRotations", self._client.list_key_rotations, **kwargs)
            count += len(resp.get("Rotations", []))
            marker = resp.get("NextMarker")
            if not resp.get("Truncated") or not marker:
                break
        with self._lock:
            self._version = count + 1
            self._version_at = now
            return self._version

    @staticmethod
    def _call(operation: str, fn: Callable[..., Any], **kwargs: Any) -> Any:
        """Invoke a boto3 KMS operation, translating every SDK failure into
        KmsError. Only the AWS error *code* is put in the message (no request
        parameters, no ciphertext, no context values)."""
        try:
            return fn(**kwargs)
        except KmsError:
            raise
        except Exception as exc:
            code = None
            response = getattr(exc, "response", None)
            if isinstance(response, dict):
                code = response.get("Error", {}).get("Code")
            detail = code or type(exc).__name__
            raise KmsError(f"AWS KMS {operation} failed: {detail}") from None
