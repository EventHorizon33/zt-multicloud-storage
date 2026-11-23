"""``CryptoEngine``: the facade the file service uses."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Iterator, Mapping, Sequence

from app.contracts import DataKey, KeyManagementService
from app.errors import KmsError

from . import chunks as _c
from . import manifest as _m
from .assembler import AssemblyResult, BinaryWritable, assemble_file
from .chunks import BinaryReadable, EncryptedChunk, PlaintextAccumulator
from .keys import FileKeys


def dek_context(file_id: str, owner_id: str) -> dict[str, str]:
    """KMS context binding a wrapped DEK to its file row and owner (ADR-0001)."""
    if not isinstance(file_id, str) or not file_id or not isinstance(owner_id, str) or not owner_id:
        raise ValueError("file_id and owner_id must be non-empty strings")
    return {"file_id": file_id, "owner_id": owner_id}


class CryptoEngine:
    """Chunk encryption, manifest sealing and verified reassembly.

    Holds no per-file state; safe to share across threads. Talks only to the
    injected ``KeyManagementService`` (never to storage or the DB).
    """

    def __init__(self, kms: KeyManagementService, chunk_size: int):
        self._kms = kms
        self.chunk_size = _c.validate_chunk_size(chunk_size)

    def __repr__(self) -> str:
        return f"CryptoEngine(chunk_size={self.chunk_size})"

    # -- keys ----------------------------------------------------------------
    def new_file_keys(self, file_id: str, owner_id: str) -> tuple[FileKeys, DataKey]:
        """New random DEK from the KMS, wrapped with context {file_id, owner_id}.
        Persist ``DataKey.wrapped`` (+ ``key_id``/``key_version``) only; the
        plaintext DEK is not kept by ``FileKeys``."""
        dk = self._kms.generate_data_key(context=dek_context(file_id, owner_id))
        return FileKeys.derive(dk.plaintext, file_id), dk

    def load_file_keys(self, file_id: str, owner_id: str, wrapped_dek: bytes) -> FileKeys:
        """Unwrap with the same context; ``KmsError`` if the wrapped key was
        moved to another file/owner or modified."""
        dek = self._kms.unwrap_data_key(wrapped_dek, context=dek_context(file_id, owner_id))
        if len(dek) != 32:
            raise KmsError("unwrap returned a key of unexpected length")
        return FileKeys.derive(dek, file_id)

    # -- chunks --------------------------------------------------------------
    def iter_plain_chunks(self, stream: BinaryReadable, chunk_size: int | None = None
                          ) -> Iterator[tuple[int, bytes, bool]]:
        return _c.iter_plain_chunks(stream, chunk_size or self.chunk_size)

    def encrypt_chunk(self, keys: FileKeys, file_id: str, index: int, plaintext: bytes,
                      is_final: bool) -> EncryptedChunk:
        return _c.encrypt_chunk(keys, file_id, index, plaintext, is_final)

    def decrypt_chunk(self, keys: FileKeys, file_id: str, index: int, blob: bytes,
                      is_final: bool, expected_sha256: str) -> bytes:
        return _c.decrypt_chunk(keys, file_id, index, blob, is_final, expected_sha256)

    def encrypt_stream(self, keys: FileKeys, file_id: str, stream: BinaryReadable, *,
                       accumulator: PlaintextAccumulator | None = None,
                       max_bytes: int | None = None) -> Iterator[EncryptedChunk]:
        return _c.encrypt_stream(keys, file_id, stream, self.chunk_size,
                                 accumulator=accumulator, max_bytes=max_bytes)

    # -- metadata ------------------------------------------------------------
    def encrypt_metadata(self, keys: FileKeys, file_id: str, metadata: Mapping[str, str]) -> bytes:
        return _c.encrypt_metadata(keys, file_id, metadata)

    def decrypt_metadata(self, keys: FileKeys, file_id: str, blob: bytes) -> dict[str, str]:
        return _c.decrypt_metadata(keys, file_id, blob)

    # -- manifest ------------------------------------------------------------
    def build_manifest(self, *, file_id: str, owner_id: str, classification: str,
                       size_bytes: int, plaintext_sha256: str, enc_metadata_sha256: str,
                       kek_id: str, kek_version: int, chunks: Sequence[Mapping[str, Any]],
                       created_at: datetime | None = None) -> dict[str, Any]:
        return _m.build_manifest(file_id=file_id, owner_id=owner_id, classification=classification,
                                 size_bytes=size_bytes, chunk_size=self.chunk_size,
                                 plaintext_sha256=plaintext_sha256,
                                 enc_metadata_sha256=enc_metadata_sha256, kek_id=kek_id,
                                 kek_version=kek_version, chunks=chunks, created_at=created_at)

    def seal_manifest(self, keys: FileKeys, manifest: Mapping[str, Any]) -> tuple[str, str]:
        return _m.seal_manifest(keys, manifest)

    def open_manifest(self, keys: FileKeys, manifest_json: str, mac_hex: str, *,
                      expected_file_id: str, expected_owner_id: str) -> dict[str, Any]:
        return _m.open_manifest(keys, manifest_json, mac_hex, expected_file_id=expected_file_id,
                                expected_owner_id=expected_owner_id)

    @staticmethod
    def update_manifest_replicas(manifest: Mapping[str, Any], chunk_index: int,
                                 replicas: Sequence[str]) -> dict[str, Any]:
        return _m.update_manifest_replicas(manifest, chunk_index, replicas)

    # -- reconstruction ------------------------------------------------------
    def assemble(self, keys: FileKeys, manifest: Mapping[str, Any],
                 fetch: Callable[[Mapping[str, Any]], bytes], sink: BinaryWritable) -> AssemblyResult:
        return assemble_file(keys, manifest, fetch, sink)
