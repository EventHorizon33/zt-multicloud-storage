"""Manifest build / canonical encoding / seal / open / validate (ADR-0003)."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from app.errors import ManifestIntegrityError

from .chunks import CHUNK_OVERHEAD, MAX_CHUNK_SIZE, MAX_CHUNKS_PER_FILE, MIN_CHUNK_SIZE
from .keys import FileKeys

MANIFEST_VERSION = 1
SUPPORTED_VERSIONS = frozenset({MANIFEST_VERSION})
MAX_MANIFEST_JSON_BYTES = 512 * 1024 * 1024
_MAC_DOMAIN = b"zt-mcs/manifest-mac/v1\x00"

_TOP_FIELDS = frozenset({
    "v", "file_id", "owner_id", "classification", "size_bytes", "chunk_size", "chunk_count",
    "plaintext_sha256", "enc_metadata_sha256", "created_at", "kek", "chunks",
})
_CHUNK_FIELDS = frozenset({"i", "id", "size", "sha256", "replicas"})
_KEK_FIELDS = frozenset({"id", "version"})
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CHUNK_ID = re.compile(r"[0-9a-f]{32}")


def _fail(msg: str, reason: str = "manifest-invalid") -> ManifestIntegrityError:
    return ManifestIntegrityError(f"manifest rejected: {msg}", reasons=(reason,))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


# --------------------------------------------------------------------------- #
# canonical JSON
# --------------------------------------------------------------------------- #
def _check_json_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, str)):
        return
    if _is_int(value):
        return
    if isinstance(value, float):
        raise ValueError("floats are not allowed in canonical JSON")
    if isinstance(value, Mapping):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _check_json_value(v)
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _check_json_value(v)
        return
    raise ValueError(f"type {type(value).__name__} is not allowed in canonical JSON")


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, separators (",", ":"), ASCII only.
    Floats (incl. NaN/Infinity) and non-JSON types raise ``ValueError``, so a
    value has exactly one encoding."""
    _check_json_value(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} not allowed")


def _reject_float(text: str) -> Any:
    raise ValueError("floats are not allowed in a manifest")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def build_manifest(*, file_id: str, owner_id: str, classification: str, size_bytes: int,
                   chunk_size: int, plaintext_sha256: str, enc_metadata_sha256: str,
                   kek_id: str, kek_version: int, chunks: Sequence[Mapping[str, Any]],
                   created_at: datetime | None = None) -> dict[str, Any]:
    """Assemble a manifest dict and validate it (raises ``ManifestIntegrityError``
    if inconsistent). ``chunks`` is a sequence of entries
    ``{"i", "id", "size", "sha256", "replicas"}`` in index order, e.g. from
    ``EncryptedChunk.manifest_entry(replicas)``. Replica lists are sorted.
    ``classification`` may be a ``Classification`` enum or its string value."""
    ts = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest = {
        "v": MANIFEST_VERSION,
        "file_id": file_id,
        "owner_id": owner_id,
        "classification": getattr(classification, "value", classification),
        "size_bytes": size_bytes,
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "plaintext_sha256": plaintext_sha256,
        "enc_metadata_sha256": enc_metadata_sha256,
        "created_at": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "kek": {"id": kek_id, "version": kek_version},
        "chunks": [
            {"i": c["i"], "id": c["id"], "size": c["size"], "sha256": c["sha256"],
             "replicas": sorted(c["replicas"])}
            for c in chunks
        ],
    }
    validate_manifest(manifest, expected_file_id=file_id, expected_owner_id=owner_id)
    return manifest


# --------------------------------------------------------------------------- #
# validation
# --------------------------------------------------------------------------- #
def validate_manifest(m: Any, *, expected_file_id: str, expected_owner_id: str) -> None:
    """Strict structural validation; raises ``ManifestIntegrityError``.

    Checks: exact field set and types; supported version; file/owner match the
    expected values (constant-time); ``chunk_count == len(chunks)`` and within
    ``MAX_CHUNKS_PER_FILE``; indices exactly 0..n-1 in order; unique 128-bit
    hex chunk ids; each blob size equals plaintext size + 28 with every chunk
    but the last carrying exactly ``chunk_size`` plaintext bytes, the last
    1..chunk_size (0 only for an empty file); ``size_bytes`` equals the sum;
    each chunk has >= 1 unique, sorted replica name.
    """
    if not isinstance(m, dict):
        raise _fail("not an object")
    if set(m) != _TOP_FIELDS:
        raise _fail("unexpected or missing fields")
    if not _is_int(m["v"]) or m["v"] not in SUPPORTED_VERSIONS:
        raise _fail("unsupported version", "manifest-unsupported-version")

    for name in ("file_id", "owner_id", "classification", "created_at"):
        if not isinstance(m[name], str) or not m[name]:
            raise _fail(f"{name} must be a non-empty string")
    if not hmac.compare_digest(m["file_id"].encode(), str(expected_file_id).encode()):
        raise _fail("file id does not match", "manifest-wrong-file")
    if not hmac.compare_digest(m["owner_id"].encode(), str(expected_owner_id).encode()):
        raise _fail("owner does not match", "manifest-wrong-owner")
    try:
        datetime.fromisoformat(m["created_at"].replace("Z", "+00:00"))
    except ValueError:
        raise _fail("created_at is not an ISO timestamp") from None
    for name in ("plaintext_sha256", "enc_metadata_sha256"):
        if not isinstance(m[name], str) or not _HEX64.fullmatch(m[name]):
            raise _fail(f"{name} must be 64 lowercase hex chars")

    kek = m["kek"]
    if (not isinstance(kek, dict) or set(kek) != _KEK_FIELDS or not isinstance(kek["id"], str)
            or not kek["id"] or not _is_int(kek["version"]) or kek["version"] < 1):
        raise _fail("kek must be {id: str, version: int >= 1}")

    chunk_size, count, size_bytes, chunks = m["chunk_size"], m["chunk_count"], m["size_bytes"], m["chunks"]
    if not _is_int(chunk_size) or not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise _fail("chunk_size out of range")
    if not _is_int(size_bytes) or size_bytes < 0:
        raise _fail("size_bytes must be a non-negative int")
    if not isinstance(chunks, list):
        raise _fail("chunks must be a list")
    if not _is_int(count) or count != len(chunks):
        raise _fail("chunk_count does not match the chunk list", "manifest-chunk-count")
    if not 1 <= count <= MAX_CHUNKS_PER_FILE:
        raise _fail("chunk count out of range", "manifest-chunk-count")
    expected_count = max(1, -(-size_bytes // chunk_size))
    if count != expected_count:
        raise _fail("chunk_count inconsistent with size_bytes and chunk_size", "manifest-chunk-count")

    seen: set[str] = set()
    total_plain = 0
    for pos, c in enumerate(chunks):
        if not isinstance(c, dict) or set(c) != _CHUNK_FIELDS:
            raise _fail(f"chunk entry {pos} malformed")
        if not _is_int(c["i"]) or c["i"] != pos:
            raise _fail("chunk indices are not 0..n-1 in order", "manifest-chunk-order")
        if not isinstance(c["id"], str) or not _CHUNK_ID.fullmatch(c["id"]):
            raise _fail(f"chunk {pos} id malformed")
        if c["id"] in seen:
            raise _fail("duplicate chunk id", "manifest-duplicate-chunk")
        seen.add(c["id"])
        if not isinstance(c["sha256"], str) or not _HEX64.fullmatch(c["sha256"]):
            raise _fail(f"chunk {pos} sha256 malformed")
        size = c["size"]
        if not _is_int(size) or size < 0:
            raise _fail(f"chunk {pos} size must be a non-negative int")
        plain = size - CHUNK_OVERHEAD
        last = pos == count - 1
        if last:
            ok = (plain == 0 and size_bytes == 0) or 1 <= plain <= chunk_size
        else:
            ok = plain == chunk_size
        if not ok:
            raise _fail(f"chunk {pos} size inconsistent with chunk_size", "manifest-chunk-size")
        total_plain += plain
        reps = c["replicas"]
        if (not isinstance(reps, list) or not reps
                or not all(isinstance(r, str) and r for r in reps)
                or len(set(reps)) != len(reps) or reps != sorted(reps)):
            raise _fail(f"chunk {pos} needs >= 1 unique, sorted replica name", "manifest-replicas")
    if total_plain != size_bytes:
        raise _fail("size_bytes does not equal the sum of chunk sizes", "manifest-size")


# --------------------------------------------------------------------------- #
# seal / open
# --------------------------------------------------------------------------- #
def _mac(keys: FileKeys, manifest_json: str) -> str:
    return hmac.new(keys.k_mac, _MAC_DOMAIN + manifest_json.encode("ascii"), hashlib.sha256).hexdigest()


def seal_manifest(keys: FileKeys, manifest: Mapping[str, Any]) -> tuple[str, str]:
    """Validate, canonicalise and MAC a manifest. Returns ``(manifest_json,
    mac_hex)``; store both verbatim. HMAC-SHA256 under ``keys.k_mac``."""
    if manifest.get("file_id") != keys.file_id:
        raise ValueError("manifest belongs to a different file than these keys")
    validate_manifest(dict(manifest), expected_file_id=keys.file_id,
                      expected_owner_id=manifest.get("owner_id"))
    text = canonical_json(manifest)
    return text, _mac(keys, text)


def open_manifest(keys: FileKeys, manifest_json: str, mac_hex: str, *,
                  expected_file_id: str, expected_owner_id: str) -> dict[str, Any]:
    """Verify the MAC over the exact stored string (constant time), then parse
    and validate strictly. Raises ``ManifestIntegrityError`` on any problem;
    the returned dict is safe to drive reconstruction."""
    if not isinstance(manifest_json, str) or not isinstance(mac_hex, str):
        raise _fail("manifest or MAC missing", "manifest-mac-invalid")
    if len(manifest_json) > MAX_MANIFEST_JSON_BYTES:
        raise _fail("manifest too large")
    try:
        manifest_json.encode("ascii")
    except UnicodeEncodeError:
        raise _fail("MAC verification failed", "manifest-mac-invalid") from None
    if keys.file_id != expected_file_id:
        raise _fail("keys do not belong to the expected file", "manifest-wrong-file")
    expected = _mac(keys, manifest_json)
    if not hmac.compare_digest(expected.encode("ascii"), mac_hex.lower().encode("utf-8", "replace")):
        raise _fail("MAC verification failed", "manifest-mac-invalid")
    try:
        doc = json.loads(manifest_json, object_pairs_hook=_no_duplicate_keys,
                         parse_float=_reject_float, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise _fail("not valid canonical JSON") from None
    validate_manifest(doc, expected_file_id=expected_file_id, expected_owner_id=expected_owner_id)
    if canonical_json(doc) != manifest_json:
        raise _fail("not in canonical form")
    return doc


def update_manifest_replicas(manifest: Mapping[str, Any], chunk_index: int,
                             replicas: Sequence[str]) -> dict[str, Any]:
    """Return a deep copy of ``manifest`` with chunk ``chunk_index``'s replica
    list replaced (sorted). The caller must re-seal with ``seal_manifest``."""
    out = copy.deepcopy(dict(manifest))
    chunks = out.get("chunks")
    if not _is_int(chunk_index) or not isinstance(chunks, list) or not 0 <= chunk_index < len(chunks):
        raise ValueError("chunk_index out of range")
    reps = sorted(replicas)
    if not reps or not all(isinstance(r, str) and r for r in reps) or len(set(reps)) != len(reps):
        raise ValueError("replicas must be >= 1 unique non-empty names")
    chunks[chunk_index]["replicas"] = reps
    return out
