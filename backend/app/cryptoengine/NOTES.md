# app/cryptoengine — NOTES

Phase 3. Implements ADR-0001 (per-file DEK + HKDF), ADR-0002 (chunk AEAD), ADR-0003
(MAC'd manifest) and ADR-0005 (verify-then-release reassembly). Imports only
`app.contracts`, `app.errors` and its own package. No storage, DB, or FastAPI.
Primitives come only from `cryptography` (AESGCM, HKDF, HMAC via stdlib `hmac`+`hashlib`).

## Public API (exact signatures)

```python
from app.cryptoengine import (CryptoEngine, FileKeys, EncryptedChunk, PlaintextAccumulator,
    AssemblyResult, WholeFileIntegrityError, MetadataIntegrityError, canonical_json,
    dek_context, MAX_CHUNKS_PER_FILE, CHUNK_OVERHEAD)

CryptoEngine(kms: KeyManagementService, chunk_size: int)        # 1 <= chunk_size <= 64 MiB
  .chunk_size: int
  .new_file_keys(file_id: str, owner_id: str) -> tuple[FileKeys, DataKey]
  .load_file_keys(file_id: str, owner_id: str, wrapped_dek: bytes) -> FileKeys     # KmsError on mismatch
  .iter_plain_chunks(stream, chunk_size: int | None = None) -> Iterator[tuple[int, bytes, bool]]
  .encrypt_chunk(keys, file_id, index: int, plaintext: bytes, is_final: bool) -> EncryptedChunk
  .decrypt_chunk(keys, file_id, index: int, blob: bytes, is_final: bool, expected_sha256: str) -> bytes
  .encrypt_stream(keys, file_id, stream, *, accumulator: PlaintextAccumulator | None = None,
                  max_bytes: int | None = None) -> Iterator[EncryptedChunk]
  .encrypt_metadata(keys, file_id, {"filename","mime_type","plaintext_sha256"}) -> bytes
  .decrypt_metadata(keys, file_id, blob: bytes) -> dict[str, str]   # MetadataIntegrityError
  .build_manifest(*, file_id, owner_id, classification, size_bytes, plaintext_sha256,
                  enc_metadata_sha256, kek_id, kek_version, chunks, created_at=None) -> dict
  .seal_manifest(keys, manifest: Mapping) -> tuple[str, str]       # (manifest_json, mac_hex)
  .open_manifest(keys, manifest_json: str, mac_hex: str, *, expected_file_id: str,
                 expected_owner_id: str) -> dict                   # ManifestIntegrityError
  .update_manifest_replicas(manifest, chunk_index: int, replicas: Sequence[str]) -> dict  # static; re-seal after
  .assemble(keys, manifest, fetch: Callable[[Mapping], bytes], sink) -> AssemblyResult

EncryptedChunk(chunk_id: str, index: int, blob: bytes, sha256_hex: str, size: int)
  .manifest_entry(replicas: Sequence[str]) -> {"i","id","size","sha256","replicas"(sorted)}
PlaintextAccumulator: .size_bytes, .chunk_count, .plaintext_sha256 (hex)
AssemblyResult(size_bytes: int, plaintext_sha256: str, chunk_count: int)
FileKeys.derive(dek: bytes, file_id: str) -> FileKeys;  .file_id  .k_enc  .k_mac  .k_meta
  .destroy()  .destroyed   (also a context manager: `with keys: ...` destroys on exit)
dek_context(file_id, owner_id) -> {"file_id": ..., "owner_id": ...}
```
Module-level functions with the same names (`encrypt_chunk`, `decrypt_chunk`,
`iter_plain_chunks(stream, chunk_size)`, `encrypt_stream(keys, file_id, stream, chunk_size, ...)`,
`build_manifest(..., chunk_size=...)`, `seal_manifest`, `open_manifest`,
`validate_manifest`, `update_manifest_replicas`, `assemble_file`) are also exported.

### Integrator recipe

Upload:
```python
keys, dk = engine.new_file_keys(file_id, owner_id)        # store dk.wrapped, dk.key_id, dk.key_version
acc = PlaintextAccumulator(); entries = []
for ch in engine.encrypt_stream(keys, file_id, upload_stream, accumulator=acc,
                                max_bytes=settings.max_upload_bytes):
    replicas = orchestrator.store(ch.chunk_id, ch.blob, ch.sha256_hex)   # provider names
    entries.append(ch.manifest_entry(replicas))
enc_meta = engine.encrypt_metadata(keys, file_id, {"filename": n, "mime_type": m,
                                                   "plaintext_sha256": acc.plaintext_sha256})
manifest = engine.build_manifest(file_id=..., owner_id=..., classification=...,
    size_bytes=acc.size_bytes, plaintext_sha256=acc.plaintext_sha256,
    enc_metadata_sha256=sha256(enc_meta).hexdigest(), kek_id=dk.key_id,
    kek_version=dk.key_version, chunks=entries)
manifest_json, manifest_mac = engine.seal_manifest(keys, manifest)       # store both verbatim
keys.destroy()
```
Download (only after the PDP allowed `file:read`):
```python
keys = engine.load_file_keys(file_id, owner_id, wrapped_dek)
m = engine.open_manifest(keys, manifest_json, manifest_mac,
                         expected_file_id=file_id, expected_owner_id=owner_id)
result = engine.assemble(keys, m, fetch=lambda entry: orchestrator.fetch(entry), sink=spool)
# release `spool` to the client ONLY if `result` was returned; on any exception discard it.
```
`fetch(entry)` gets the manifest chunk entry (`id`, `sha256`, `replicas`, `size`, `i`). It
may check `entry["sha256"]` itself to fail over between replicas without keys.
`decrypt_chunk` re-checks the hash anyway.

## Formats

**Key derivation** (ADR-0001): `k = HKDF-SHA256(ikm=DEK, salt=None, length=32,
info = lp("zt-mcs/file-keys/v1") | lp(label) | lp(file_id utf-8))`. Labels are
`chunk-encryption` → k_enc, `manifest-mac` → k_mac, `metadata-encryption` → k_meta.
`lp` = u32 big-endian length prefix. Deterministic for (DEK, file_id). The DEK itself is
not retained by `FileKeys`.

**Chunk blob** (ADR-0002): `nonce(12, os.urandom) || AES-256-GCM(k_enc, plaintext, AAD) (ct || tag16)`.
Blob size = plaintext size + 28 (`CHUNK_OVERHEAD`).
AAD = `"ZTC" | u8 format_version(=1) | u16 len(file_id) | file_id utf-8 | u64 index | u8 final`.
`chunk_id = secrets.token_hex(16)` (random, unrelated to file, user, or content).
`sha256_hex = SHA-256(blob)`. Decrypt order: constant-time SHA-256 compare against the
manifest value, then GCM. Any failure → `ChunkIntegrityError("chunk <i>: ...", reasons=(...))`,
never with key or plaintext bytes in it.

**Chunking**: every chunk is exactly `chunk_size` bytes except the last. A non-empty file
never has an empty chunk. An empty file is one final empty chunk (index 0). One-chunk
lookahead decides `is_final`. Short reads are handled; a `read()` returning `None`
(non-blocking) or more than requested raises `ValueError`. More than `MAX_CHUNKS_PER_FILE`
(2^20) chunks raises `ValidationFailed(reasons=("too-many-chunks",))`. `max_bytes`
exceeded raises `ValidationFailed(reasons=("upload-too-large",))`.

**Metadata blob**: `nonce(12) || AES-256-GCM(k_meta, canonical JSON {filename, mime_type,
plaintext_sha256}, AAD = "ZTM" | u8 1 | u16 len(file_id) | file_id)`. Max 16 KiB plaintext.

**Manifest** (ADR-0003), canonical JSON (sorted keys, separators `(",", ":")`, ASCII,
floats/NaN rejected):
```json
{"chunk_count":N,"chunk_size":1048576,
 "chunks":[{"i":0,"id":"<32 hex>","replicas":["aws-s3","gcs"],"sha256":"<64 hex>","size":1048604}],
 "classification":"internal","created_at":"2026-11-12T08:00:00.000000Z",
 "enc_metadata_sha256":"<64 hex>","file_id":"...","kek":{"id":"...","version":1},
 "owner_id":"...","plaintext_sha256":"<64 hex>","size_bytes":123,"v":1}
```
`mac_hex = HMAC-SHA256(k_mac, "zt-mcs/manifest-mac/v1\0" || manifest_json)`, hex.
`open_manifest` checks, in this order:
1. MAC in constant time over the **exact stored string**. Any byte change, including
   whitespace, fails.
2. Parsing rejects floats, NaN and duplicate keys.
3. Strict validation:
   * exact field sets, and `v` is supported;
   * file_id and owner_id equal the expected values;
   * `chunk_count == len(chunks)` and is in 1..2^20, and equals `max(1, ceil(size_bytes/chunk_size))`;
   * indices are exactly 0..n-1 in order, and chunk ids are unique 32-hex;
   * sizes are non-negative ints; every non-last chunk carries exactly `chunk_size`
     plaintext bytes; the last carries 1..chunk_size (0 only for the empty file);
     the sum equals `size_bytes`;
   * each chunk has ≥1 unique, sorted replica;
   * hex hashes and kek fields are well formed.
4. Re-canonicalisation must reproduce the string.

Every failure raises `ManifestIntegrityError` with a reason code
(`manifest-mac-invalid`, `manifest-wrong-owner`, `manifest-chunk-order`, …).

**Assembler**: chunk i is final iff `i == chunk_count-1`. It writes plaintext to the sink
chunk by chunk while hashing. After the last chunk it checks the total size and the
whole-file SHA-256 (`WholeFileIntegrityError`, an `IntegrityError`). Success is signalled
only by the returned `AssemblyResult`. On any exception the sink may hold partial,
unverified plaintext, which the caller must discard (the API layer must spool and release
only on success, per ADR-0005).

## Implemented

Everything listed above, including the max-chunk bound, chunk-size bounds, and
`FileKeys` repr/pickle protection.

## Not implemented / limitations

* **Memory wiping**: `FileKeys.destroy()` drops references only. CPython `bytes` are
  immutable and may be copied, so there is no guarantee that key bytes are erased from memory.
* `chunk_size` is recorded per manifest. The engine validates a manifest against its own
  recorded `chunk_size`, not the engine's current setting, so changing the setting
  does not break old files.
* `enc_metadata_sha256` is recorded in the manifest. Comparing it with the stored
  metadata blob is the integrator's job (one `hmac.compare_digest` of `sha256(blob)`).
* No whole-file rollback protection beyond immutability (files are never updated in place).
* Random 96-bit nonces: safe far beyond the 2^20 chunk bound per file key.

## Tests

```
cd backend && .venv/bin/python -m pytest tests/unit/cryptoengine -q
```
Last run: **103 passed** (`tests/unit/cryptoengine/test_crypto_engine.py`, includes a
20 MiB / 1 MiB-chunk round trip and randomised short-read streams).

Combined Phase 3 run (last run):
```
cd backend && .venv/bin/python -m pytest tests/unit/kms tests/unit/cryptoengine -q
176 passed
```

## Chunk size is per file, not per engine (2026-11-25)

`CryptoEngine.chunk_size` only decides how new files are split. The manifest stores `chunk_size` and `validate_manifest` checks each
file against its own value (1 byte to 64 MiB); the AEAD associated data is (version, file id, index, final flag) and does not include
the chunk size. Changing the setting therefore never invalidates existing files.
