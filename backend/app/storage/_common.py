"""Helpers shared by every storage adapter: object-key validation, message
sanitisation and error construction.

Security properties provided here:
  * ``validate_key`` rules out path traversal and header/log injection through
    object keys before a key ever reaches a vendor SDK.
  * ``sanitize_text`` removes credential-shaped material (connection strings,
    account keys, signed-URL query strings, access key ids, long opaque
    tokens) from any text that may end up in an exception, a health record or
    an audit event.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Mapping

from app.contracts import StorageError

MAX_KEY_LENGTH = 256
ANCHOR_PREFIX = "anchors/"


class InvalidObjectKey(StorageError, ValueError):
    """The object key (or prefix / metadata) is not acceptable. Never retryable.
    Also a ``ValueError`` so generic input-validation handlers catch it."""
    retryable = False


class StorageConfigError(StorageError):
    """A provider cannot be constructed from the given settings (unknown
    provider name, missing bucket, missing connection string...). The message
    names the missing *setting*, never its value."""
    retryable = False


def _has_control_chars(value: str) -> bool:
    return any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in value)


def validate_key(key: str) -> str:
    """Return ``key`` unchanged if it is a safe object key, else raise
    ``InvalidObjectKey``.

    Rejected: non-strings, empty keys, keys longer than 256 characters, a
    leading ``/``, any ``..`` sequence, backslashes, and ASCII/C1 control
    characters (including NUL, CR, LF). The error message never echoes the key.
    """
    if not isinstance(key, str):
        raise InvalidObjectKey("object key must be a string")
    if key == "":
        raise InvalidObjectKey("object key must not be empty")
    if len(key) > MAX_KEY_LENGTH:
        raise InvalidObjectKey(f"object key longer than {MAX_KEY_LENGTH} characters")
    if key.startswith("/"):
        raise InvalidObjectKey("object key must not start with '/'")
    if ".." in key:
        raise InvalidObjectKey("object key must not contain '..'")
    if "\\" in key:
        raise InvalidObjectKey("object key must not contain a backslash")
    if _has_control_chars(key):
        raise InvalidObjectKey("object key must not contain control characters")
    return key


def validate_prefix(prefix: str) -> str:
    """Same rules as ``validate_key`` except that the empty prefix is allowed
    (it means "everything")."""
    if not isinstance(prefix, str):
        raise InvalidObjectKey("prefix must be a string")
    if prefix == "":
        return prefix
    try:
        return validate_key(prefix)
    except InvalidObjectKey as exc:
        raise InvalidObjectKey(str(exc).replace("object key", "prefix")) from None


_META_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def validate_metadata(metadata: Mapping[str, str] | None) -> dict[str, str]:
    """Normalise object metadata to a plain ``dict[str, str]``.

    Keys must be identifier-like (the common subset S3, Azure and GCS all
    accept); values must be short printable ASCII. Providers are untrusted, so
    callers must never put user-identifying data here; this function only
    guarantees the metadata cannot be used for header injection."""
    if not metadata:
        return {}
    out: dict[str, str] = {}
    for k, v in metadata.items():
        if not isinstance(k, str) or not _META_KEY_RE.match(k):
            raise InvalidObjectKey("metadata keys must match [A-Za-z_][A-Za-z0-9_]{0,63}")
        if not isinstance(v, str) or len(v) > 1024 or not v.isascii() or _has_control_chars(v):
            raise InvalidObjectKey("metadata values must be printable ASCII strings up to 1024 chars")
        out[k] = v
    return out


def require_bytes(data: object) -> bytes:
    """Providers accept only ``bytes``-like ciphertext; anything else is a
    programming error upstream and is refused before any network call."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise StorageError("object data must be bytes")


_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # whole Azure-style connection strings
    (re.compile(r"DefaultEndpointsProtocol=[^\s\"']+", re.I), "<connection-string>"),
    # key=value secrets (connection-string parts, signed-URL parameters)
    (re.compile(
        r"(?i)\b(AccountKey|SharedAccessSignature|SharedAccessKey|sig|signature|"
        r"X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|X-Goog-Signature|"
        r"X-Goog-Credential|AWSAccessKeyId|aws_secret_access_key|aws_access_key_id|"
        r"access_token|token|password|passwd|secret|key)\s*[=:]\s*[^;&\s\"',)]+"),
     r"\1=<redacted>"),
    # Authorization-style headers
    (re.compile(r"(?i)\b(Bearer|SharedKey|AWS4-HMAC-SHA256)\s+[^\s\"']+"), r"\1 <redacted>"),
    # userinfo in URLs
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@"), r"\1<redacted>@"),
    # URL query strings (signed URLs)
    (re.compile(r"(?i)\b(https?://[^\s?\"']+)\?[^\s\"']+"), r"\1?<redacted>"),
    # AWS access key ids
    (re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{12,}\b"), "<redacted-key-id>"),
    # long opaque base64/hex tokens
    (re.compile(r"[A-Za-z0-9+/_=-]{40,}"), "<redacted>"),
)


def sanitize_text(text: object, max_len: int = 200) -> str:
    """Return a single-line, length-bounded version of ``text`` with
    credential-shaped substrings replaced. Applied to every error string that
    is stored in health state or passed to the audit sink (defence in depth:
    adapter exceptions are already built from fixed templates)."""
    s = str(text)
    for pattern, repl in _REDACTIONS:
        s = pattern.sub(repl, s)
    s = "".join(" " if _has_control_chars(c) else c for c in s)
    s = " ".join(s.split())
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s


_CODE_RE = re.compile(r"[^A-Za-z0-9._-]")


def safe_code(code: object) -> str:
    """Reduce a service error code / exception class name to a short token
    that cannot carry secrets."""
    return _CODE_RE.sub("", str(code))[:64] or "unknown"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def error_summary(exc: BaseException) -> str:
    """Sanitised one-line description of an exception for health/audit use."""
    if isinstance(exc, StorageError):
        return sanitize_text(f"{type(exc).__name__}: {exc}")
    # Unknown exception types: the class name only. Their message could contain
    # anything (endpoints with embedded credentials, signed URLs).
    return f"{safe_code(type(exc).__name__)}"
