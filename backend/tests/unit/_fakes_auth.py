"""In-test fakes for the auth/policy unit tests: a real in-memory KMS (Ed25519
signing, AES-GCM secret encryption bound to context, HMAC) and a recording
AuditSink. Not used by production code."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.contracts import DataKey, KeyInfo, KeyManagementService, KeyPurpose, Signature


def _aad(context: Mapping[str, str]) -> bytes:
    return json.dumps(dict(context), sort_keys=True, separators=(",", ":")).encode()


class FakeKms(KeyManagementService):
    def __init__(self) -> None:
        self._sign: dict[KeyPurpose, dict[int, Ed25519PrivateKey]] = {
            KeyPurpose.TOKEN_SIGNING: {1: Ed25519PrivateKey.generate()},
            KeyPurpose.AUDIT_SIGNING: {1: Ed25519PrivateKey.generate()},
        }
        self._sym: dict[KeyPurpose, dict[int, bytes]] = {
            p: {1: os.urandom(32)} for p in (KeyPurpose.FILE_DEK_WRAP, KeyPurpose.SECRET_ENCRYPTION,
                                             KeyPurpose.AUDIT_PSEUDONYM, KeyPurpose.LOOKUP_HMAC)
        }
        self.created = datetime(2026, 1, 1, tzinfo=timezone.utc)

    @staticmethod
    def key_id(purpose: KeyPurpose) -> str:
        return f"fake-{purpose.value}"

    def _active(self, purpose: KeyPurpose) -> int:
        store = self._sign if purpose in self._sign else self._sym
        return max(store[purpose])

    # --- data keys ---
    def generate_data_key(self, *, context):
        dek = os.urandom(32)
        return DataKey(plaintext=dek, wrapped=self._seal(KeyPurpose.FILE_DEK_WRAP, dek, context),
                       key_id=self.key_id(KeyPurpose.FILE_DEK_WRAP), key_version=self._active(KeyPurpose.FILE_DEK_WRAP))

    def unwrap_data_key(self, wrapped, *, context):
        return self._open(KeyPurpose.FILE_DEK_WRAP, wrapped, context)

    def rewrap_data_key(self, wrapped, *, context):
        pt = self.unwrap_data_key(wrapped, context=context)
        return DataKey(b"", self._seal(KeyPurpose.FILE_DEK_WRAP, pt, context),
                       self.key_id(KeyPurpose.FILE_DEK_WRAP), self._active(KeyPurpose.FILE_DEK_WRAP))

    def wrapped_key_version(self, wrapped):
        return self.key_id(KeyPurpose.FILE_DEK_WRAP), int.from_bytes(wrapped[:4], "big")

    def _seal(self, purpose, plaintext, context) -> bytes:
        v = self._active(purpose)
        nonce = os.urandom(12)
        return v.to_bytes(4, "big") + nonce + AESGCM(self._sym[purpose][v]).encrypt(nonce, plaintext, _aad(context))

    def _open(self, purpose, blob, context) -> bytes:
        v = int.from_bytes(blob[:4], "big")
        return AESGCM(self._sym[purpose][v]).decrypt(blob[4:16], blob[16:], _aad(context))

    def encrypt(self, plaintext, *, context):
        return self._seal(KeyPurpose.SECRET_ENCRYPTION, plaintext, context)

    def decrypt(self, ciphertext, *, context):
        return self._open(KeyPurpose.SECRET_ENCRYPTION, ciphertext, context)

    # --- signing ---
    def sign(self, message, *, purpose):
        v = self._active(purpose)
        return Signature(self.key_id(purpose), v, self._sign[purpose][v].sign(message))

    def verify(self, message, signature, *, purpose, key_id, version):
        if key_id != self.key_id(purpose) or version not in self._sign.get(purpose, {}):
            return False
        try:
            self._sign[purpose][version].public_key().verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def public_key_pem(self, *, purpose, version=None):
        v = version or self._active(purpose)
        return self._sign[purpose][v].public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def mac(self, message, *, purpose):
        return hmac.new(self._sym[purpose][self._active(purpose)], message, hashlib.sha256).digest()

    def rotate(self, purpose):
        if purpose in self._sign:
            v = self._active(purpose) + 1
            self._sign[purpose][v] = Ed25519PrivateKey.generate()
        else:
            v = self._active(purpose) + 1
            self._sym[purpose][v] = os.urandom(32)
        return self._info(purpose, v)

    def _info(self, purpose, v) -> KeyInfo:
        state = "active" if v == self._active(purpose) else "decrypt-only"
        algo = "Ed25519" if purpose in self._sign else "AES-256-GCM/HMAC"
        return KeyInfo(purpose.value, self.key_id(purpose), v, algo, self.created, state)

    def list_keys(self):
        out = []
        for store in (self._sign, self._sym):
            for p, versions in store.items():
                out.extend(self._info(p, v) for v in versions)
        return out


class RecordingAudit:
    """AuditSink fake: collects every record() kwargs dict."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.fail = False

    def record(self, **kwargs: Any) -> None:
        if self.fail:
            raise RuntimeError("audit store unavailable")
        self.events.append(kwargs)

    def of(self, event_type: str) -> list[dict[str, Any]]:
        return [e for e in self.events if e["event_type"] == event_type]


class FakeClock:
    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now = self.now + timedelta(seconds=seconds)
