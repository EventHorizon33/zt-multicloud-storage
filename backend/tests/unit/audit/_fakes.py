"""In-test fakes implementing the contracts the audit subsystem depends on.

FakeKMS uses real Ed25519 and HMAC-SHA256 from ``cryptography``/``hmac`` with
versioned keys, so signature verification, rotation and tampering behave
like the real KMS. FakeAnchorStore emulates several storage providers.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.contracts import DataKey, KeyInfo, KeyManagementService, KeyPurpose, Signature


class FakeKMS(KeyManagementService):
    def __init__(self) -> None:
        self._sign_keys: dict[KeyPurpose, list[Ed25519PrivateKey]] = {}
        self._mac_keys: dict[KeyPurpose, list[bytes]] = {}
        self.sign_calls = 0
        self.fail_sign = False

    # --- helpers ---
    def _signers(self, purpose: KeyPurpose) -> list[Ed25519PrivateKey]:
        return self._sign_keys.setdefault(purpose, [Ed25519PrivateKey.generate()])

    def _macs(self, purpose: KeyPurpose) -> list[bytes]:
        return self._mac_keys.setdefault(purpose, [os.urandom(32)])

    @staticmethod
    def _key_id(purpose: KeyPurpose) -> str:
        return f"fake-{purpose.value}"

    # --- used by audit ---
    def sign(self, message: bytes, *, purpose: KeyPurpose) -> Signature:
        if self.fail_sign:
            raise RuntimeError("kms unavailable")
        self.sign_calls += 1
        keys = self._signers(purpose)
        return Signature(key_id=self._key_id(purpose), version=len(keys),
                         signature=keys[-1].sign(message))

    def verify(self, message: bytes, signature: bytes, *, purpose: KeyPurpose,
               key_id: str, version: int) -> bool:
        keys = self._signers(purpose)
        if key_id != self._key_id(purpose) or not 1 <= version <= len(keys):
            return False
        try:
            keys[version - 1].public_key().verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def mac(self, message: bytes, *, purpose: KeyPurpose) -> bytes:
        return hmac.new(self._macs(purpose)[-1], message, hashlib.sha256).digest()

    def rotate(self, purpose: KeyPurpose) -> KeyInfo:
        if purpose in (KeyPurpose.AUDIT_PSEUDONYM, KeyPurpose.LOOKUP_HMAC):
            self._macs(purpose).append(os.urandom(32))
            n = len(self._macs(purpose))
        else:
            self._signers(purpose).append(Ed25519PrivateKey.generate())
            n = len(self._signers(purpose))
        return KeyInfo(purpose=purpose.value, key_id=self._key_id(purpose), version=n,
                       algorithm="fake", created_at=datetime.now(timezone.utc), state="active")

    def public_key_pem(self, *, purpose: KeyPurpose, version: int | None = None) -> bytes:
        keys = self._signers(purpose)
        key = keys[(version or len(keys)) - 1]
        return key.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)

    def list_keys(self) -> list[KeyInfo]:
        return []

    # --- not used by audit ---
    def generate_data_key(self, *, context: Mapping[str, str]) -> DataKey:
        raise NotImplementedError("not used by the audit subsystem")

    def unwrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> bytes:
        raise NotImplementedError("not used by the audit subsystem")

    def rewrap_data_key(self, wrapped: bytes, *, context: Mapping[str, str]) -> DataKey:
        raise NotImplementedError("not used by the audit subsystem")

    def wrapped_key_version(self, wrapped: bytes) -> tuple[str, int]:
        raise NotImplementedError("not used by the audit subsystem")

    def encrypt(self, plaintext: bytes, *, context: Mapping[str, str]) -> bytes:
        raise NotImplementedError("not used by the audit subsystem")

    def decrypt(self, ciphertext: bytes, *, context: Mapping[str, str]) -> bytes:
        raise NotImplementedError("not used by the audit subsystem")


class FakeAnchorStore:
    """Dict-backed multi-provider anchor store."""

    def __init__(self, providers=("aws-s3", "azure-blob", "gcs")) -> None:
        self.objects: dict[str, dict[str, bytes]] = {p: {} for p in providers}
        self.down: set[str] = set()       # providers that refuse writes / reads
        self.raise_on_put = False

    def put_anchor(self, key: str, data: bytes) -> dict[str, bool]:
        if self.raise_on_put:
            raise ConnectionError("all providers down")
        result = {}
        for p, store in self.objects.items():
            if p in self.down:
                result[p] = False
            else:
                store[key] = bytes(data)
                result[p] = True
        return result

    def get_anchor(self, key: str) -> dict[str, bytes | None]:
        return {p: (None if p in self.down else store.get(key))
                for p, store in self.objects.items()}

    def list_anchors(self, prefix: str) -> dict[str, list[str]]:
        return {p: sorted(k for k in store if k.startswith(prefix))
                for p, store in self.objects.items() if p not in self.down}


class ManualClock:
    """Injectable clock: advances 1 ms per call unless told otherwise."""

    def __init__(self, start: datetime | None = None, step: timedelta = timedelta(milliseconds=1)):
        self.now = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.step = step

    def __call__(self) -> datetime:
        current = self.now
        self.now = self.now + self.step
        return current

    def advance(self, delta: timedelta) -> None:
        self.now = self.now + delta


def fill(svc, n: int, **kw) -> list:
    out = []
    for i in range(n):
        out.append(svc.record(event_type=kw.get("event_type", "file.download"),
                              action=kw.get("action", "file:read"),
                              outcome=kw.get("outcome", "success"),
                              actor_id=kw.get("actor_id", f"user-{i % 3}"),
                              resource_type="file", resource_id=f"f{i:04d}",
                              details={"size_bytes": i, "chunk_count": 1}))
    return out
