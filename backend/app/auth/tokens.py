"""Access tokens (EdDSA JWT signed inside the KMS) and opaque refresh tokens.

Security properties:
  * The signing key never leaves the ``KeyManagementService``: the compact JWS
    is assembled here and only ``kms.sign`` / ``kms.verify`` touch key material.
  * The algorithm is pinned. A token whose header ``alg`` is anything other
    than ``EdDSA`` (``none``, ``HS256``, ...) is rejected BEFORE any signature
    work, so algorithm-confusion attacks have nothing to negotiate with. The
    header may contain only ``alg``, ``typ``, ``kid`` (no ``jwk``/``jku``/``crit``).
  * ``kid`` carries ``<key_id>:<version>`` so tokens signed before a key
    rotation still verify against the version that signed them.
  * Tokens carry identity only (sub, sid, jti, iat, exp, iss, aud, typ): no
    roles or permissions. Authorisation data is re-read from the DB per request.
  * ``exp`` is enforced strictly (no leeway); ``iat`` may be at most
    ``CLOCK_SKEW_LEEWAY_SECONDS`` in the future.
  * Refresh tokens are 256-bit random values stored only as an HMAC.
  * Error reasons are machine codes; token contents never appear in exceptions.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from app.config import Settings
from app.contracts import KeyManagementService, KeyPurpose
from app.errors import AuthenticationError, KmsError

Clock = Callable[[], datetime]

ALGORITHM = "EdDSA"
TOKEN_TYPE = "access"
CLOCK_SKEW_LEEWAY_SECONDS = 5
MAX_TOKEN_LENGTH = 2048
_ED25519_SIGNATURE_LEN = 64
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_KID_RE = re.compile(r"^(?P<key_id>.{1,128}):(?P<version>[0-9]{1,9})$", re.DOTALL)
_HEADER_KEYS = frozenset({"alg", "typ", "kid"})
_CLAIM_KEYS = frozenset({"sub", "sid", "jti", "iat", "exp", "iss", "aud", "typ"})
_REFRESH_TOKEN_BYTES = 32  # 256 bits


@dataclass(frozen=True)
class AccessClaims:
    sub: str   # user id
    sid: str   # session id
    jti: str   # unique token id
    iat: int
    exp: int
    iss: str
    aud: str
    typ: str


def _invalid(reason: str) -> AuthenticationError:
    return AuthenticationError("invalid token", reasons=(reason,))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    if not segment or not _B64URL_RE.match(segment) or len(segment) % 4 == 1:
        raise ValueError("bad base64url")
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("bad base64url") from exc


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _json_object(raw: bytes) -> dict[str, Any]:
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


def _canonical_json(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 128


def normalise_ip(source_ip: str | None) -> str | None:
    """Canonical text form of an IP (IPv4-mapped IPv6 collapsed to IPv4), or
    None if absent/unparseable."""
    if not source_ip or not isinstance(source_ip, str):
        return None
    try:
        addr = ipaddress.ip_address(source_ip.strip())
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


class TokenService:
    """Mints and validates access tokens; creates and hashes refresh tokens."""

    def __init__(self, kms: KeyManagementService, settings: Settings, clock: Clock) -> None:
        self._kms = kms
        self._settings = settings
        self._clock = clock

    # ------------------------------------------------------------------ #
    # access tokens
    # ------------------------------------------------------------------ #
    def _now_ts(self) -> float:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return an aware datetime")
        return now.astimezone(timezone.utc).timestamp()

    def _active_signing_key(self) -> tuple[str, int]:
        active = [
            k for k in self._kms.list_keys()
            if str(getattr(k.purpose, "value", k.purpose)) == KeyPurpose.TOKEN_SIGNING.value
            and k.state == "active"
        ]
        if not active:
            raise KmsError("no active token-signing key")
        newest = max(active, key=lambda k: k.version)
        return newest.key_id, newest.version

    def issue_access_token(self, *, user_id: str, session_id: str) -> tuple[str, AccessClaims]:
        """Mint a short-lived EdDSA JWT for ``session_id``. The token proves
        only "this bearer was issued this session"; it grants nothing by itself."""
        iat = int(self._now_ts())
        claims = AccessClaims(
            sub=user_id,
            sid=session_id,
            jti=secrets.token_urlsafe(16),
            iat=iat,
            exp=iat + int(self._settings.access_token_ttl_seconds),
            iss=self._settings.token_issuer,
            aud=self._settings.token_audience,
            typ=TOKEN_TYPE,
        )
        payload = _b64url_encode(_canonical_json(claims.__dict__))
        # The header (with kid) is part of the signed input, so the key version
        # must be known before signing. If a rotation races between list_keys()
        # and sign(), the returned Signature names a different version: retry.
        for _ in range(3):
            key_id, version = self._active_signing_key()
            header = _b64url_encode(_canonical_json(
                {"alg": ALGORITHM, "typ": "JWT", "kid": f"{key_id}:{version}"}))
            signing_input = f"{header}.{payload}".encode("ascii")
            sig = self._kms.sign(signing_input, purpose=KeyPurpose.TOKEN_SIGNING)
            if sig.key_id == key_id and sig.version == version:
                return f"{header}.{payload}.{_b64url_encode(sig.signature)}", claims
        raise KmsError("token-signing key changed repeatedly while signing")

    def verify_access_token(self, token: str) -> AccessClaims:
        """Validate structure, pinned algorithm, signature (via the KMS), and
        every claim. Raises ``AuthenticationError`` with one reason code:
        token-malformed | token-alg-not-allowed | token-bad-signature |
        token-expired | token-not-yet-valid | token-wrong-issuer |
        token-wrong-audience | token-wrong-type | token-bad-claims.

        A valid result still authorises nothing: the caller must load the
        session and user from the database (``AuthService.authenticate_request``).
        """
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH or not token.isascii():
            raise _invalid("token-malformed")
        parts = token.split(".")
        if len(parts) != 3:
            raise _invalid("token-malformed")
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = _json_object(_b64url_decode(header_b64))
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise _invalid("token-malformed") from None

        # --- algorithm pinning: decided before any cryptography happens ---
        if header.get("alg") != ALGORITHM:
            raise _invalid("token-alg-not-allowed")
        if set(header) - _HEADER_KEYS or header.get("typ") != "JWT":
            raise _invalid("token-malformed")
        kid = header.get("kid")
        match = _KID_RE.match(kid) if isinstance(kid, str) else None
        if match is None:
            raise _invalid("token-malformed")
        key_id, version = match.group("key_id"), int(match.group("version"))

        try:
            signature = _b64url_decode(sig_b64)
        except ValueError:
            raise _invalid("token-bad-signature") from None
        if len(signature) != _ED25519_SIGNATURE_LEN:
            raise _invalid("token-bad-signature")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        try:
            ok = self._kms.verify(signing_input, signature, purpose=KeyPurpose.TOKEN_SIGNING,
                                  key_id=key_id, version=version)
        except Exception:
            # Unknown key id / version or a KMS fault: fail closed.
            ok = False
        if ok is not True:
            raise _invalid("token-bad-signature")

        # --- claims (only reached for an authentic token) ---
        try:
            claims = _json_object(_b64url_decode(payload_b64))
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise _invalid("token-bad-claims") from None
        if set(claims) != _CLAIM_KEYS:
            raise _invalid("token-bad-claims")
        if not all(_nonempty_str(claims[k]) for k in ("sub", "sid", "jti")):
            raise _invalid("token-bad-claims")
        if not (_is_int(claims["iat"]) and _is_int(claims["exp"])):
            raise _invalid("token-bad-claims")
        if claims["typ"] != TOKEN_TYPE:
            raise _invalid("token-wrong-type")
        if claims["iss"] != self._settings.token_issuer:
            raise _invalid("token-wrong-issuer")
        if claims["aud"] != self._settings.token_audience:   # must be this exact string, not a list
            raise _invalid("token-wrong-audience")
        iat, exp = claims["iat"], claims["exp"]
        now = self._now_ts()
        if exp <= iat or exp - iat > int(self._settings.access_token_ttl_seconds):
            raise _invalid("token-bad-claims")   # lifetime longer than this server ever issues
        if now >= exp:
            raise _invalid("token-expired")
        if iat > now + CLOCK_SKEW_LEEWAY_SECONDS:
            raise _invalid("token-not-yet-valid")
        return AccessClaims(sub=claims["sub"], sid=claims["sid"], jti=claims["jti"], iat=iat, exp=exp,
                            iss=claims["iss"], aud=claims["aud"], typ=claims["typ"])

    # ------------------------------------------------------------------ #
    # refresh tokens / lookups
    # ------------------------------------------------------------------ #
    def new_refresh_token(self) -> tuple[str, str]:
        """Return ``(token, token_hash)``. Only the hash may be persisted."""
        token = secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)
        return token, self.hash_refresh_token(token)

    def hash_refresh_token(self, token: str) -> str:
        """Hex HMAC-SHA256 of the token under the KMS lookup key. A database
        dump therefore yields nothing that can be presented as a refresh token."""
        return self._kms.mac(token.encode("utf-8"), purpose=KeyPurpose.LOOKUP_HMAC).hex()

    def hash_ip(self, source_ip: str | None) -> str | None:
        """Keyed hash of the client IP for optional session binding (the raw IP
        is not stored). Domain-separated from refresh-token hashes."""
        ip = normalise_ip(source_ip)
        if ip is None:
            return None
        return self._kms.mac(b"session-ip:" + ip.encode("ascii"), purpose=KeyPurpose.LOOKUP_HMAC).hex()
