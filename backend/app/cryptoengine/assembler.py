"""Verify-then-release reconstruction (ADR-0005)."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from app.errors import ChunkIntegrityError, IntegrityError

from .chunks import decrypt_chunk
from .keys import FileKeys


class WholeFileIntegrityError(IntegrityError):
    """All chunks authenticated individually, but total size or whole-file
    SHA-256 does not match the manifest."""
    code = "file-integrity-failure"


class BinaryWritable(Protocol):
    def write(self, data: bytes, /) -> Any: ...


@dataclass(frozen=True)
class AssemblyResult:
    """Returned ONLY when every chunk and the whole file verified. If
    :func:`assemble_file` raises instead, whatever reached the sink must be
    discarded and never delivered."""
    size_bytes: int
    plaintext_sha256: str
    chunk_count: int


def assemble_file(keys: FileKeys, manifest: Mapping[str, Any],
                  fetch: Callable[[Mapping[str, Any]], bytes], sink: BinaryWritable) -> AssemblyResult:
    """Fetch, verify, decrypt and write every chunk of ``manifest`` in order.

    ``manifest`` must come from ``open_manifest`` (MAC + structure verified).
    ``fetch(entry)`` returns the stored blob for a manifest chunk entry (the
    integrator's replica failover lives there; it may itself check
    ``entry["sha256"]``). Chunk ``i`` is final iff ``i == chunk_count - 1``.

    Raises ``ChunkIntegrityError`` / ``WholeFileIntegrityError`` (both
    ``IntegrityError``) or whatever ``fetch``/``sink`` raise. Success is
    signalled only by the returned :class:`AssemblyResult`; on any exception
    the sink content is unverified and must be discarded.
    """
    file_id = manifest["file_id"]
    if keys.file_id != file_id:
        raise ChunkIntegrityError("chunk 0: keys belong to a different file",
                                  reasons=("chunk-auth-failed",))
    chunks = manifest["chunks"]
    count = manifest["chunk_count"]
    if count != len(chunks):
        raise WholeFileIntegrityError("manifest chunk count inconsistent",
                                      reasons=("file-chunk-count",))
    digest = hashlib.sha256()
    total = 0
    for pos, entry in enumerate(chunks):
        index = entry["i"]
        if index != pos:
            raise ChunkIntegrityError(f"chunk {pos!r}: out of order", reasons=("chunk-order",))
        blob = fetch(entry)
        plaintext = decrypt_chunk(keys, file_id, index, blob, index == count - 1, entry["sha256"])
        digest.update(plaintext)
        total += len(plaintext)
        sink.write(plaintext)
    if total != manifest["size_bytes"]:
        raise WholeFileIntegrityError("reconstructed size does not match the manifest",
                                      reasons=("file-size-mismatch",))
    actual = digest.hexdigest()
    if not hmac.compare_digest(actual.encode("ascii"), str(manifest["plaintext_sha256"]).encode("utf-8", "replace")):
        raise WholeFileIntegrityError("reconstructed file hash does not match the manifest",
                                      reasons=("file-hash-mismatch",))
    return AssemblyResult(size_bytes=total, plaintext_sha256=actual, chunk_count=count)
