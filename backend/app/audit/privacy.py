"""Privacy filter for audit events (ADR-0007).

Security property: nothing reaches the audit database unless it passed
through this module. ``details`` is reduced to an allow-list of field names
with simple values; independently, a deny scan removes keys whose *name*
suggests a secret and redacts values that *look* like a secret (JWT, bearer
header, PEM block, long key-like blob, email address). Source addresses are
generalised to a network. The filter never raises on hostile input: it drops
or redacts instead, and counts what it dropped without naming it.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from enum import Enum
from typing import Any, Iterable, Mapping

from app.audit.chain import canonical_json

REDACTED = "[REDACTED]"
DROPPED_FIELD = "_dropped"
MAX_STRING_LENGTH = 256          # characters kept from any string value
MAX_REASON_LENGTH = 512
MAX_COLLECTION_ITEMS = 50        # items kept from a list / nested dict
MAX_DETAIL_KEYS = 64
MAX_DETAILS_BYTES = 8192         # size cap of the canonical details JSON

# --------------------------------------------------------------------------- #
# Allow-list (exported for the integrator: these are the only top-level
# ``details`` keys that are stored)
# --------------------------------------------------------------------------- #
GLOBAL_ALLOWED_DETAIL_KEYS: frozenset[str] = frozenset({
    # decisions
    "reason", "reasons", "policies", "obligations",
    # chunks / files / storage
    "chunk_index", "chunk_count", "chunk_size", "size_bytes", "bytes",
    "providers", "provider", "failed_providers", "replicas", "attempts", "retries",
    "classification", "file_status", "verified", "corrupt", "missing", "repaired",
    # identity / session (ids are opaque; user ids must be pseudonymised by the caller)
    "role", "old_role", "new_role", "session_id", "mfa", "method", "target_user",
    # the client's own X-Request-ID (validated [A-Za-z0-9._-]{1,64}); the
    # request_id column is always server-generated (finding L8)
    "client_request_id",
    # configuration changes
    "changed_keys", "old", "new",
    # keys (metadata only, never material)
    "key_purpose", "key_version", "old_version", "new_version",
    # detection / rate limiting
    "count", "window_seconds", "threshold",
    # operations
    "latency_ms", "duration_ms", "error_class", "state", "previous_state",
    "http_status", "ok", "mode", "kind",
    # audit housekeeping
    "seq", "first_seq", "last_seq", "deleted", "kept",
})

# Optional extra keys per event type. A key ending in ".*" (or ".") applies to
# every event type with that prefix. Extras still pass the deny scan.
EVENT_ALLOWED_DETAIL_KEYS: dict[str, frozenset[str]] = {
    "audit.verify": frozenset({"events_checked", "checkpoints_checked",
                               "anchors_checked", "finding_types"}),
    "audit.checkpoint": frozenset({"event_count"}),
}

# --------------------------------------------------------------------------- #
# Deny scan
# --------------------------------------------------------------------------- #
# Substrings of a normalised key name (lowercase, non-alphanumerics -> "_")
# that mark the field as sensitive regardless of the allow-list.
DENY_KEY_PATTERNS: tuple[str, ...] = (
    "password", "passwd", "passphrase", "pwd", "secret", "token", "authorization",
    "cookie", "credential", "bearer", "jwt",
    "dek", "kek", "private_key", "privatekey", "api_key", "apikey", "access_key",
    "accesskey", "key_material", "keymaterial",
    "totp", "otp", "seed",
    "filename", "file_name", "username", "user_name", "email", "e_mail",
    "content", "plaintext",
)

_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
_NORMALISE_RE = re.compile(r"[^a-z0-9]+")

_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"
    r"|(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}(?![A-Za-z0-9_\-])"
)
_BEARER_RE = re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9_\-.~+/=]{6,}")
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|passphrase|secret|token|api[_\-]?key|authorization|cookie)\s*[=:]\s*\S+"
)
_BLOB_RE = re.compile(r"[A-Za-z0-9+/_=\-]{40,}")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BLOB_MIN_ENTROPY = 3.0          # bits per character


def _shannon_entropy(text: str) -> float:
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_key_like_blob(token: str) -> bool:
    """A run of >= 40 base64/hex characters is treated as key material when it
    is pure hex, or mixes at least two of {upper, lower, digit} with high
    entropy. Long lowercase slugs ("provider-unavailable-after-...") are not."""
    if _HEX_RE.match(token):
        return True
    classes = (any(c.isupper() for c in token) + any(c.islower() for c in token)
               + any(c.isdigit() for c in token))
    return classes >= 2 and _shannon_entropy(token) >= _BLOB_MIN_ENTROPY


def is_sensitive_key(name: str) -> bool:
    """True if a field NAME matches a deny pattern (password, token, dek, ...)."""
    norm = _NORMALISE_RE.sub("_", name.lower()).strip("_")
    squeezed = norm.replace("_", "")
    return any(p in norm or p.replace("_", "") in squeezed for p in DENY_KEY_PATTERNS)


def looks_sensitive(value: str, *, check_blobs: bool = True) -> bool:
    """True if a string VALUE looks like a credential or personal identifier:
    JWT, bearer/basic header, PEM block, ``password=...`` style assignment,
    email address, or (``check_blobs``) a long key-like base64/hex blob."""
    if (_JWT_RE.search(value) or _BEARER_RE.search(value) or _PEM_RE.search(value)
            or _EMAIL_RE.search(value) or _ASSIGNMENT_RE.search(value)):
        return True
    if check_blobs:
        return any(_is_key_like_blob(m.group(0)) for m in _BLOB_RE.finditer(value))
    return False


def scrub_text(value: Any, *, max_length: int = MAX_STRING_LENGTH,
               check_blobs: bool = True) -> str | None:
    """Value scan for a free-text field (``reason`` and the label columns).

    Returns None for None, ``"[REDACTED]"`` if the text looks sensitive, else
    the text truncated to ``max_length``. The scan runs on the full text
    before truncation so a secret cannot hide behind the cut."""
    if value is None:
        return None
    if isinstance(value, Enum):
        value = value.value
    text = value if isinstance(value, str) else str(value)
    if looks_sensitive(text, check_blobs=check_blobs):
        return REDACTED
    return text[:max_length]


def allowed_keys_for(event_type: str | None,
                     extra: Mapping[str, Iterable[str]] | None = None) -> frozenset[str]:
    """The allow-list that applies to ``event_type``: global set plus any
    per-event-type set (exact match or ``"prefix.*"``)."""
    allowed = set(GLOBAL_ALLOWED_DETAIL_KEYS)
    if event_type:
        for table in (EVENT_ALLOWED_DETAIL_KEYS, extra or {}):
            for pattern, keys in table.items():
                if pattern == event_type:
                    allowed.update(keys)
                elif pattern.endswith(".*") and event_type.startswith(pattern[:-1]):
                    allowed.update(keys)
                elif pattern.endswith(".") and event_type.startswith(pattern):
                    allowed.update(keys)
    return frozenset(allowed)


_DROP = object()


def _scalar(value: Any) -> Any:
    """Return a storable scalar or ``_DROP``."""
    if isinstance(value, Enum):
        value = value.value
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) < 2 ** 63 else _DROP
    if isinstance(value, float):
        return value if math.isfinite(value) else _DROP
    if isinstance(value, str):
        return scrub_text(value)
    return _DROP                      # bytes, datetimes, objects: never stored


def _key_ok(key: Any) -> bool:
    return (isinstance(key, str) and bool(_KEY_NAME_RE.match(key))
            and not is_sensitive_key(key) and not looks_sensitive(key))


def _value(value: Any) -> tuple[Any, int]:
    """Filter one allow-listed value. Returns (storable value or _DROP, number
    of nested entries dropped)."""
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=repr) if isinstance(value, (set, frozenset)) else list(value)
        out, dropped = [], 0
        for item in items:
            if len(out) >= MAX_COLLECTION_ITEMS:
                dropped += 1
                continue
            s = _scalar(item)
            if s is _DROP:
                dropped += 1
            else:
                out.append(s)
        return out, dropped
    if isinstance(value, Mapping):
        out_d: dict[str, Any] = {}
        dropped = 0
        for k, v in value.items():
            if len(out_d) >= MAX_COLLECTION_ITEMS or not _key_ok(k):
                dropped += 1
                continue
            s = _scalar(v)
            if s is _DROP:
                dropped += 1
            else:
                out_d[k] = s
        return out_d, dropped
    return _scalar(value), 0


def filter_details(details: Mapping[str, Any] | None, event_type: str | None = None, *,
                   extra_allowed: Mapping[str, Iterable[str]] | None = None) -> dict[str, Any]:
    """Reduce ``details`` to what may be stored.

    * a top-level key is kept only if it is on the allow-list for the event
      type AND its name does not match a deny pattern;
    * values are str/int/float/bool/None, or one level of list/dict of those;
    * strings are scanned (-> ``"[REDACTED]"``) and truncated;
    * everything else is dropped; the number of dropped entries is stored in
      ``_dropped`` (only when > 0). Names of dropped keys are never stored.

    Never raises for any input."""
    if not details:
        return {}
    if not isinstance(details, Mapping):
        return {DROPPED_FIELD: 1}
    allowed = allowed_keys_for(event_type, extra_allowed)
    out: dict[str, Any] = {}
    dropped = 0
    for key, value in details.items():
        if (not isinstance(key, str) or key not in allowed or is_sensitive_key(key)
                or len(out) >= MAX_DETAIL_KEYS):
            dropped += 1
            continue
        try:
            filtered, nested = _value(value)
        except Exception:             # hostile __iter__/__repr__ etc.: drop, never raise
            dropped += 1
            continue
        dropped += nested
        if filtered is _DROP:
            dropped += 1
        else:
            out[key] = filtered
    if dropped:
        out[DROPPED_FIELD] = dropped
    if len(canonical_json(out)) > MAX_DETAILS_BYTES:
        return {DROPPED_FIELD: dropped + len([k for k in out if k != DROPPED_FIELD])}
    return out


def generalise_ip(source_ip: str | None, v4_prefix: int = 24, v6_prefix: int = 48) -> str | None:
    """Generalise an address to its network, e.g. ``203.0.113.77`` ->
    ``203.0.113.0/24``. The full address is never returned. Anything that is
    not a single valid IP address (including ``host:port``) yields None.
    IPv4-mapped IPv6 addresses are treated as IPv4."""
    if not source_ip or not isinstance(source_ip, str):
        return None
    text = source_ip.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.split("%", 1)[0]      # drop an IPv6 zone id
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if isinstance(addr, ipaddress.IPv4Address):
        prefix = min(max(int(v4_prefix), 0), 32)
    else:
        prefix = min(max(int(v6_prefix), 0), 128)
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
