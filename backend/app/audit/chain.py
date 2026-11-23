"""Hash-chain primitives: canonical encoding, record hash, timestamps.

Security property: ``compute_hash`` binds every stored field of a record
(including its sequence number and the previous record's hash) into one
SHA-256 value, so changing, moving or removing a record changes a hash that a
later record, a signed checkpoint or an external anchor still remembers.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

GENESIS_HASH = "0" * 64

# Order of columns in ``audit_events``. Every field except ``hash`` is hashed.
EVENT_FIELDS: tuple[str, ...] = (
    "seq", "id", "ts", "event_type", "action", "outcome", "severity", "actor",
    "actor_role", "resource_type", "resource_id", "reason", "details",
    "request_id", "source_net", "prev_hash", "hash",
)
HASHED_FIELDS: tuple[str, ...] = tuple(f for f in EVENT_FIELDS if f != "hash")

CHECKPOINT_VERSION = 1
CHECKPOINT_PAYLOAD_FIELDS: tuple[str, ...] = (
    "v", "seq", "head_hash", "ts", "event_count", "first_seq", "kind",
)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only. The same
    logical value always yields the same bytes, which is what gets hashed
    and signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def canonical_record(record: Mapping[str, Any]) -> bytes:
    """Canonical bytes of an event: all stored fields except ``hash``."""
    return canonical_json({f: record[f] for f in HASHED_FIELDS}).encode("ascii")


def compute_hash(record: Mapping[str, Any]) -> str:
    """``SHA-256(prev_hash_bytes || canonical_record_bytes)`` as lowercase hex.

    Raises ValueError if ``prev_hash`` is not 32 bytes of hex (a tampered row);
    verification treats that as a modified record."""
    prev = record["prev_hash"]
    if not isinstance(prev, str) or len(prev) != 64:
        raise ValueError("prev_hash is not a SHA-256 hex digest")
    prev_bytes = bytes.fromhex(prev)
    return hashlib.sha256(prev_bytes + canonical_record(record)).hexdigest()


def format_ts(dt: datetime) -> str:
    """Fixed-width ISO-8601 UTC with microseconds, e.g.
    ``2026-01-02T03:04:05.000006Z``. Fixed width means string order equals
    time order, and the stored text is exactly the hashed text. A naive
    datetime is taken to be UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def coerce_ts(value: datetime | str) -> str:
    """Normalise a datetime or ISO string to the stored timestamp format."""
    if isinstance(value, datetime):
        return format_ts(value)
    text = str(value).strip()
    try:
        return format_ts(parse_ts(text))
    except ValueError:
        pass
    return format_ts(datetime.fromisoformat(text.replace("Z", "+00:00")))
