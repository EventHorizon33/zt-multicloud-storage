"""TOTP second factor (RFC 6238: HMAC-SHA1, 6 digits, 30 s step, +/-1 step).

Security properties:
  * The TOTP seed is persisted only as ``kms.encrypt(seed, context={"user_id":
    ..., "purpose": "totp"})``. The context is AEAD-bound, so a ciphertext
    copied onto another user's row fails to decrypt.
  * Verification reports the matched time-step counter so the caller can
    enforce single use (replay guard) with an atomic compare-and-set.
  * Codes are compared with ``hmac.compare_digest``; every step in the window
    is evaluated (no early exit).
  * Neither seeds nor codes are logged or placed in exceptions.
"""
from __future__ import annotations

import base64
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

import pyotp

from app.contracts import KeyManagementService

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_WINDOW_STEPS = 1
_SEED_BYTES = 20  # 160 bits, the RFC 4226 recommended secret length


@dataclass(frozen=True)
class MfaEnrollment:
    """Returned ONCE at enrolment so the user can configure an authenticator.
    Must be shown to the user and never stored or logged by the caller."""
    secret: str        # base32 seed
    otpauth_uri: str   # otpauth://totp/... for QR rendering


@dataclass(frozen=True)
class TotpCheck:
    ok: bool
    counter: int | None      # matched RFC 6238 time-step counter when ok
    reason: str | None       # "mfa-invalid" | "mfa-replay" when not ok


def generate_seed() -> str:
    """New random base32 TOTP seed from the OS CSPRNG."""
    return base64.b32encode(secrets.token_bytes(_SEED_BYTES)).decode("ascii")


def time_step(now: datetime) -> int:
    """RFC 6238 counter T = floor(unix_time / 30)."""
    return int(now.timestamp()) // TOTP_STEP_SECONDS


def code_at(seed: str, now: datetime, *, step_offset: int = 0) -> str:
    """The code an authenticator shows at ``now`` (+ offset steps)."""
    return _totp(seed).generate_otp(time_step(now) + step_offset)


def _totp(seed: str) -> pyotp.TOTP:
    return pyotp.TOTP(seed, digits=TOTP_DIGITS, interval=TOTP_STEP_SECONDS)


def _normalise_code(code: object) -> str | None:
    if not isinstance(code, str):
        return None
    stripped = code.replace(" ", "").strip()
    if len(stripped) != TOTP_DIGITS or not stripped.isascii() or not stripped.isdigit():
        return None
    return stripped


def check_code(seed: str, code: object, *, now: datetime, last_counter: int | None) -> TotpCheck:
    """Verify ``code`` against the seed within +/-1 step of ``now``.

    Replay guard: a counter less than or equal to ``last_counter`` (the newest
    counter already accepted for this user) is rejected with ``mfa-replay``,
    so an observed code cannot be used twice, not even within its 30 s step.
    """
    candidate = _normalise_code(code)
    if candidate is None:
        return TotpCheck(False, None, "mfa-invalid")
    totp = _totp(seed)
    current = time_step(now)
    matched: list[int] = []
    for offset in range(-TOTP_WINDOW_STEPS, TOTP_WINDOW_STEPS + 1):
        counter = current + offset
        if counter < 0:
            continue
        expected = totp.generate_otp(counter)
        if hmac.compare_digest(expected.encode("ascii"), candidate.encode("ascii")):
            matched.append(counter)
    if not matched:
        return TotpCheck(False, None, "mfa-invalid")
    fresh = [c for c in matched if last_counter is None or c > last_counter]
    if not fresh:
        return TotpCheck(False, None, "mfa-replay")
    return TotpCheck(True, max(fresh), None)


class TotpService:
    """TOTP enrolment/verification with the seed held only KMS-encrypted."""

    def __init__(self, kms: KeyManagementService, *, issuer: str) -> None:
        self._kms = kms
        self._issuer = issuer

    @staticmethod
    def _context(user_id: str) -> Mapping[str, str]:
        return {"user_id": user_id, "purpose": "totp"}

    def new_enrollment(self, *, user_id: str, account_name: str) -> tuple[MfaEnrollment, bytes]:
        """Create a seed. Returns the one-time enrolment material for the user
        and the KMS-encrypted blob to store in ``User.mfa_secret_enc``."""
        seed = generate_seed()
        encrypted = self._kms.encrypt(seed.encode("ascii"), context=self._context(user_id))
        uri = _totp(seed).provisioning_uri(name=account_name, issuer_name=self._issuer)
        return MfaEnrollment(secret=seed, otpauth_uri=uri), encrypted

    def verify(self, *, user_id: str, encrypted_seed: bytes | None, code: object,
               now: datetime, last_counter: int | None) -> TotpCheck:
        """Decrypt the seed inside this call only and check the code. Any
        decryption failure (wrong context, tampered blob) is a failed check."""
        if not encrypted_seed or _normalise_code(code) is None:
            return TotpCheck(False, None, "mfa-invalid")
        try:
            seed = self._kms.decrypt(bytes(encrypted_seed), context=self._context(user_id)).decode("ascii")
        except Exception:
            return TotpCheck(False, None, "mfa-invalid")
        return check_code(seed, code, now=now, last_counter=last_counter)
