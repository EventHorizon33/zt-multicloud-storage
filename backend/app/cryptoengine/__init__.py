"""Chunking + cryptographic engine (ADR-0001/0002/0003/0005). See NOTES.md."""
from .assembler import AssemblyResult, WholeFileIntegrityError, assemble_file
from .chunks import (
    CHUNK_OVERHEAD,
    FORMAT_VERSION,
    MAX_CHUNK_SIZE,
    MAX_CHUNKS_PER_FILE,
    MIN_CHUNK_SIZE,
    EncryptedChunk,
    MetadataIntegrityError,
    PlaintextAccumulator,
    chunk_aad,
    decrypt_chunk,
    decrypt_metadata,
    encrypt_chunk,
    encrypt_metadata,
    encrypt_stream,
    iter_plain_chunks,
)
from .engine import CryptoEngine, dek_context
from .keys import FileKeys
from .manifest import (
    MANIFEST_VERSION,
    build_manifest,
    canonical_json,
    open_manifest,
    seal_manifest,
    update_manifest_replicas,
    validate_manifest,
)

__all__ = [
    "AssemblyResult", "WholeFileIntegrityError", "assemble_file",
    "CHUNK_OVERHEAD", "FORMAT_VERSION", "MAX_CHUNK_SIZE", "MAX_CHUNKS_PER_FILE", "MIN_CHUNK_SIZE",
    "EncryptedChunk", "MetadataIntegrityError", "PlaintextAccumulator", "chunk_aad",
    "decrypt_chunk", "decrypt_metadata", "encrypt_chunk", "encrypt_metadata", "encrypt_stream",
    "iter_plain_chunks", "CryptoEngine", "dek_context", "FileKeys", "MANIFEST_VERSION",
    "build_manifest", "canonical_json", "open_manifest", "seal_manifest",
    "update_manifest_replicas", "validate_manifest",
]
