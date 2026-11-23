"""Chunking, per-chunk AEAD (ADR-0002) and metadata encryption."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidTag

from app.errors import ChunkIntegrityError, IntegrityError, ValidationFailed

from .keys import FileKeys, encode_file_id

FORMAT_VERSION = 1
NONCE_BYTES = 12
TAG_BYTES = 16
CHUNK_OVERHEAD = NONCE_BYTES + TAG_BYTES          # blob size - plaintext size
MIN_CHUNK_SIZE = 1
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MAX_CHUNKS_PER_FILE = 2 ** 20
MAX_METADATA_BYTES = 16 * 1024
METADATA_FIELDS = ("filename", "mime_type", "plaintext_sha256")

_CHUNK_AAD_MAGIC = b"ZTC"
_META_AAD_MAGIC = b"ZTM"


class MetadataIntegrityError(IntegrityError):
    """The encrypted filename/MIME blob failed authentication or is malformed."""
    code = "metadata-integrity-failure"


class BinaryReadable(Protocol):
    def read(self, n: int = -1, /) -> bytes: ...


def validate_chunk_size(chunk_size: int) -> int:
    """Return ``chunk_size`` if it is an int within [MIN_CHUNK_SIZE, MAX_CHUNK_SIZE]."""
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise ValueError("chunk_size must be an int")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes")
    return chunk_size


def _check_index(index: int) -> int:
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < MAX_CHUNKS_PER_FILE:
        raise ValueError(f"chunk index must be an int in [0, {MAX_CHUNKS_PER_FILE})")
    return index


def chunk_aad(file_id: str, index: int, is_final: bool) -> bytes:
    """Associated data of one chunk.

    Layout (fixed-width / length-prefixed, so no two different
    (version, file_id, index, final) tuples encode to the same bytes)::

        "ZTC" | u8 format_version | u16 len(file_id) | file_id utf-8 | u64 index | u8 final
    """
    fid = encode_file_id(file_id)
    return (_CHUNK_AAD_MAGIC + struct.pack(">BH", FORMAT_VERSION, len(fid)) + fid
            + struct.pack(">QB", index, 1 if is_final else 0))


def metadata_aad(file_id: str) -> bytes:
    """``"ZTM" | u8 format_version | u16 len(file_id) | file_id utf-8``"""
    fid = encode_file_id(file_id)
    return _META_AAD_MAGIC + struct.pack(">BH", FORMAT_VERSION, len(fid)) + fid


@dataclass(frozen=True)
class EncryptedChunk:
    """One encrypted chunk ready for storage. ``blob`` is ciphertext only."""
    chunk_id: str        # opaque random object name (32 hex chars)
    index: int
    blob: bytes = field(repr=False)   # nonce(12) || AES-256-GCM ciphertext || tag(16)
    sha256_hex: str      # SHA-256 of ``blob``
    size: int            # len(blob)

    def manifest_entry(self, replicas: Sequence[str]) -> dict[str, Any]:
        """Manifest ``chunks[]`` entry for this chunk stored at ``replicas``
        (provider instance names). Holds no ciphertext, so callers can drop
        ``blob`` after storing it."""
        return {"i": self.index, "id": self.chunk_id, "size": self.size,
                "sha256": self.sha256_hex, "replicas": sorted(replicas)}


@dataclass
class PlaintextAccumulator:
    """Running totals over the plaintext seen by :func:`encrypt_stream`.
    Read ``plaintext_sha256`` / ``size_bytes`` / ``chunk_count`` after the loop."""
    size_bytes: int = 0
    chunk_count: int = 0
    _hash: Any = field(default_factory=hashlib.sha256, repr=False)

    def update(self, plaintext: bytes) -> None:
        self._hash.update(plaintext)
        self.size_bytes += len(plaintext)
        self.chunk_count += 1

    @property
    def plaintext_sha256(self) -> str:
        return self._hash.hexdigest()


def _read_exactly(stream: BinaryReadable, n: int) -> bytes:
    """Read ``n`` bytes unless EOF comes first; tolerates short reads."""
    parts: list[bytes] = []
    remaining = n
    while remaining > 0:
        data = stream.read(remaining)
        if data is None:
            raise ValueError("stream is non-blocking and returned no data; a blocking stream is required")
        if not data:
            break
        if len(data) > remaining:
            raise ValueError("stream returned more bytes than requested")
        parts.append(bytes(data))
        remaining -= len(data)
    return parts[0] if len(parts) == 1 else b"".join(parts)


def iter_plain_chunks(stream: BinaryReadable, chunk_size: int) -> Iterator[tuple[int, bytes, bool]]:
    """Split ``stream`` into ``(index, plaintext, is_final)``.

    Every chunk is exactly ``chunk_size`` bytes except possibly the last. An
    empty stream yields a single final empty chunk; a non-empty stream never
    yields an empty chunk. Uses one chunk of lookahead (at most two chunks in
    memory). Raises ``ValidationFailed`` if the stream would need more than
    ``MAX_CHUNKS_PER_FILE`` chunks.
    """
    validate_chunk_size(chunk_size)
    current = _read_exactly(stream, chunk_size)
    index = 0
    while True:
        nxt = _read_exactly(stream, chunk_size) if len(current) == chunk_size else b""
        if not nxt:
            yield index, current, True
            return
        yield index, current, False
        index += 1
        if index >= MAX_CHUNKS_PER_FILE:
            raise ValidationFailed(
                f"file needs more than {MAX_CHUNKS_PER_FILE} chunks at this chunk size",
                reasons=("too-many-chunks",))
        current = nxt


def encrypt_chunk(keys: FileKeys, file_id: str, index: int, plaintext: bytes,
                  is_final: bool) -> EncryptedChunk:
    """AES-256-GCM encrypt one chunk under ``keys.k_enc`` with a fresh random
    96-bit nonce and AAD = (format version, file id, index, final flag).

    Security property: the result only decrypts at the same position of the
    same file with the same final flag. ``chunk_id`` is 128 random bits and
    reveals nothing about the file, owner or content.
    """
    if keys.file_id != file_id:
        raise ValueError("keys belong to a different file")
    _check_index(index)
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise ValueError("plaintext must be bytes")
    if len(plaintext) > MAX_CHUNK_SIZE:
        raise ValueError("chunk plaintext exceeds MAX_CHUNK_SIZE")
    nonce = os.urandom(NONCE_BYTES)
    blob = nonce + keys.chunk_aead.encrypt(nonce, bytes(plaintext), chunk_aad(file_id, index, bool(is_final)))
    return EncryptedChunk(chunk_id=secrets.token_hex(16), index=index, blob=blob,
                          sha256_hex=hashlib.sha256(blob).hexdigest(), size=len(blob))


def decrypt_chunk(keys: FileKeys, file_id: str, index: int, blob: bytes, is_final: bool,
                  expected_sha256: str) -> bytes:
    """Verify and decrypt one chunk.

    Order: (1) SHA-256 of the blob against ``expected_sha256`` (the value from
    the MAC-verified manifest) in constant time, (2) AES-GCM tag with the AAD
    for this exact (file, index, final). Any failure raises
    ``ChunkIntegrityError`` naming only the index; plaintext is returned only
    if both checks pass.
    """
    def fail(what: str, reason: str) -> ChunkIntegrityError:
        return ChunkIntegrityError(f"chunk {index!r}: {what}", reasons=(reason,))

    try:
        _check_index(index)
        aad = chunk_aad(file_id, index, bool(is_final))
    except ValueError:
        raise fail("invalid chunk position", "chunk-invalid-position") from None
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise fail("stored object is not bytes", "chunk-malformed")
    blob = bytes(blob)
    if not isinstance(expected_sha256, str):
        raise fail("no expected hash supplied", "chunk-hash-mismatch")
    actual = hashlib.sha256(blob).hexdigest()
    if not hmac.compare_digest(actual.encode("ascii"), expected_sha256.lower().encode("utf-8", "replace")):
        raise fail("stored object hash does not match the manifest", "chunk-hash-mismatch")
    if len(blob) < CHUNK_OVERHEAD:
        raise fail("stored object is too short", "chunk-malformed")
    if keys.file_id != file_id:
        raise fail("authentication failed", "chunk-auth-failed")
    try:
        return keys.chunk_aead.decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
    except InvalidTag:
        raise fail("authentication failed", "chunk-auth-failed") from None


def encrypt_stream(keys: FileKeys, file_id: str, stream: BinaryReadable, chunk_size: int, *,
                   accumulator: PlaintextAccumulator | None = None,
                   max_bytes: int | None = None) -> Iterator[EncryptedChunk]:
    """Lazily chunk and encrypt ``stream``; yields chunks in index order.

    ``accumulator`` (if given) receives every plaintext chunk before it is
    encrypted. If ``max_bytes`` is set and the plaintext exceeds it,
    ``ValidationFailed`` is raised before the offending chunk is encrypted
    (chunks yielded earlier must then be discarded by the caller).
    """
    total = 0
    for index, plaintext, is_final in iter_plain_chunks(stream, chunk_size):
        total += len(plaintext)
        if max_bytes is not None and total > max_bytes:
            raise ValidationFailed("upload exceeds the maximum allowed size",
                                   reasons=("upload-too-large",))
        if accumulator is not None:
            accumulator.update(plaintext)
        yield encrypt_chunk(keys, file_id, index, plaintext, is_final)


# --------------------------------------------------------------------------- #
# metadata (filename / MIME type / plaintext hash)
# --------------------------------------------------------------------------- #
def encrypt_metadata(keys: FileKeys, file_id: str, metadata: Mapping[str, str]) -> bytes:
    """Encrypt ``{"filename", "mime_type", "plaintext_sha256"}`` under
    ``keys.k_meta`` (AES-256-GCM, random nonce, AAD binds the file id).
    Returns ``nonce(12) || ciphertext || tag``. The blob cannot be moved to
    another file's row."""
    if keys.file_id != file_id:
        raise ValueError("keys belong to a different file")
    if not isinstance(metadata, Mapping) or set(metadata) != set(METADATA_FIELDS):
        raise ValueError(f"metadata must have exactly the fields {METADATA_FIELDS}")
    if not all(isinstance(metadata[k], str) for k in METADATA_FIELDS):
        raise ValueError("metadata values must be strings")
    plaintext = json.dumps({k: metadata[k] for k in METADATA_FIELDS}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(plaintext) > MAX_METADATA_BYTES:
        raise ValueError("metadata is too large")
    nonce = os.urandom(NONCE_BYTES)
    return nonce + keys.metadata_aead.encrypt(nonce, plaintext, metadata_aad(file_id))


def decrypt_metadata(keys: FileKeys, file_id: str, blob: bytes) -> dict[str, str]:
    """Authenticate and decrypt a metadata blob; raises
    ``MetadataIntegrityError`` if it was modified, truncated, produced for a
    different file, or does not have the expected shape."""
    def fail() -> MetadataIntegrityError:
        return MetadataIntegrityError("file metadata failed authentication",
                                      reasons=("metadata-auth-failed",))

    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise fail()
    blob = bytes(blob)
    if len(blob) < CHUNK_OVERHEAD or keys.file_id != file_id:
        raise fail()
    try:
        plaintext = keys.metadata_aead.decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], metadata_aad(file_id))
        doc = json.loads(plaintext.decode("ascii"))
    except (InvalidTag, ValueError):
        raise fail() from None
    if (not isinstance(doc, dict) or set(doc) != set(METADATA_FIELDS)
            or not all(isinstance(v, str) for v in doc.values())):
        raise fail()
    return doc
