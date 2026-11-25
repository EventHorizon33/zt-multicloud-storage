# app/files — file workflow service (Phase 6)

Also documented here: `app/container.py` (composition root), `app/detection` (finished from the
previous engineer's draft) and `app/admin` (user/KMS administration).

## Public API

```python
from app.files.service import FileService, DownloadHandle, sanitize_filename, sanitize_mime, parse_classification

FileService(*, settings, crypto: CryptoEngine, orchestrator: StorageOrchestrator, pep: PolicyEnforcementPoint,
            audit: AuditService, detector: DownloadDetector, policy_store: PolicyStore, clock,
            stale_upload_minutes: float = 10.0, spool_threshold_bytes: int = 8 MiB)
  .upload(db, subject, stream, *, filename, mime_type, classification, context) -> dict   # File view
  .list_files(db, subject, context) -> list[dict]
  .admin_list_files(db, subject, context, *, limit=200, offset=0) -> (list[dict], total)
  .get_metadata(db, subject, file_id, context) -> dict
  .distribution(db, subject, file_id, context) -> dict
  .download(db, subject, file_id, context) -> DownloadHandle(file_id, filename, mime_type, size_bytes,
                                                             plaintext_sha256, stream)  # caller closes stream
  .delete(db, subject, file_id, context) -> {"file_id", "status": "deleted", "leftover_replicas"}
  .share(db, subject, file_id, username, context) -> dict ; .unshare(...) ; .list_shares(...)
  .verify(db, subject, file_id, context) -> report ; .repair(db, subject, file_id, context) -> report
  .stats(db, owner_id=None) -> dict          # dashboard / distribution totals (committed files)
  .rewrap_all(db, kms) -> (rewrapped, failed)  # after FILE_DEK_WRAP rotation
  .recover(db) -> {"uploads_recovered", "deletes_finished", "leftovers_removed"}
```
Every method that takes a `file_id` runs `_authorize`: load row → PEP → unknown/deleted ids and denied ids of
non-parties (not owner, not grantee, not admin) raise `NotFound`; unknown ids are audited here as
`authz.decision` denied `not-found`, other denies by the PEP. Owners/grantees/admins get the real 403
(with reasons/obligations, e.g. `mfa-required` + `step-up-mfa`).

## State machine (models.FileStatus)

```
PENDING --commit--> UPLOADING --(all chunks stored, ONE txn: manifest+wrapped DEK+metadata)--> COMMITTED
   |                     |--any failure--> FAILED (objects deleted, key material NULL, reason code)
   |                     |--crash, older than stale_upload_minutes--> recover(): FAILED("interrupted")
COMMITTED --delete (CAS)--> DELETING --provider deletes, shred--> DELETED
FAILED    --delete--------> DELETING --> DELETED
DELETING (crash, stale) --recover()--> DELETED
```
* **Intent log.** Each chunk's `Chunk` row is committed *before* `store_chunk`, and its replica rows after,
  so the projection always names every object that might exist. Deviation from the brief ("write
  chunks/replicas projection in the commit transaction"): writing them progressively is what lets crash
  recovery find the objects. They never make a file look complete: totals count only `committed` files,
  and the PDP refuses `file:read` unless `status == committed`.
* **Failure cleanup**: delete every stored replica (+ the orchestrator's own cleanup for the failing
  chunk; its `cleanup_failed` providers are recorded); replicas that could not be deleted get status
  `failed` (= leftover) and are retried by `recover()`. The row keeps no wrapped DEK / manifest / metadata.
  Audit: `file.upload` outcome `error` (storage) or `failure` (validation) with a reason code.
* **Reason codes** (`failure_reason`): `storage-unavailable`, `upload-too-large`, `client-aborted`,
  `interrupted`, `invalid-*`, `<AppError.code>`, `internal-error`. Never exception text.
* **Delete targets** = projection replicas ∪ replica lists of the stored manifest (parsed without the MAC,
  only to widen deletion; restricted to chunk ids the projection knows). The wrapped DEK, metadata blob
  and manifest are set to NULL in the same transaction as `DELETED` (crypto-shred), even if provider
  deletes failed; shares are revoked.

## Download (ADR-0005)

1. Detection (`DownloadDetector.evaluate`, only for owner/grantee) → `RequestContext.download_blocked`.
2. PEP `file:read`.
3. `load_file_keys` (KmsError → `IntegrityError("key-unwrap-failed")`: moved key / changed owner).
4. `open_manifest` (MAC + structure + file/owner binding); manifest classification must equal the row's
   (`manifest-classification-mismatch`: a DB downgrade to dodge the MFA rule is caught).
5. `sha256(enc_metadata)` vs manifest `enc_metadata_sha256` (`metadata-hash-mismatch`) **before** decrypting.
6. `assemble` into a `SpooledTemporaryFile` (memory up to `spool_threshold_bytes`, then an unlinked file in
   `<data_dir>/tmp`); `fetch` = `orchestrator.fetch_chunk(..., verify=sha256 == manifest)`.
7. Released only if `AssemblyResult` was returned; on any exception the spool is closed. Chunk with no
   valid replica: any corrupt → 409 `all-replicas-corrupt`, otherwise 503 `data-unavailable`. Integrity
   failures audit `file.integrity` (CRITICAL). Bad replicas are marked `corrupt`/`missing` in the projection.
8. `DownloadRecord` written, `file.download` audited.

## Verify / repair
`verify` opens the MAC'd manifest (DEK unwrapped only to authenticate it), then `verify_replica` on every
listed replica; no plaintext is produced. `repair` fetches a verified replica, `repair_chunk`s it to
corrupt/missing providers (then others), updates the manifest replica lists and **re-seals** the manifest.

## Container (`app/container.py`)
`Container.build(settings, *, clock=None, providers=None, password_hasher=None, kms=None, background=True,
stale_upload_minutes=10.0)`; `.start()` (bootstrap admin, maintenance once, initial health probe, background
health monitor + maintenance thread every 60 s), `.stop()`, `.run_maintenance()`.
* One clock for auth, policy, audit, detection, files.
* Audit is built first and is every subsystem's sink. Its anchor store is `OrchestratorAnchorStore`
  (adapts `put_anchor/get_anchor/list_anchors` result types to `app.audit.AnchorStore`; a provider that is
  unreachable is omitted, all unreachable → raises → audit records `anchor-unavailable`).
* `EXTRA_AUDIT_DETAILS` extends the audit allow-list per event family (auth.*, policy.*, chunk.*,
  storage.*, security.*, file.*, admin.*).
* `_PolicyAuditAdapter` (PolicyStore only) flattens `policy.change` `changes: {key: {old,new}}` to
  `{key: "<old json> -> <new json>"}`: the audit filter keeps one nesting level only, so the original
  shape lost every value (`_dropped`). Integration-layer fix; neither subsystem was changed.

## Detection (`app/detection/detector.py`)
Reviewed draft; kept the design (sliding window over `DownloadRecord`, `DownloadBlock` row, PDP decides).
Changes: concurrent first-block insert (PK race) no longer 500s; `prune()` housekeeping; per-network deque
bounded (`max_events_per_network`) so a flood cannot grow memory. `AuthFailureDetector` is fed by the login
route (failures other than `mfa-required`); threshold 5 distinct accounts per /24 (/48) per
`detect_window_seconds`, one alert per window.

## Admin (`app/admin/service.py`)
`AdminService(pep, audit, auth, kms, files, clock)`: `list_users`, `set_role`, `set_clearance`, `set_active`
(disable revokes sessions), `set_cidrs`, `revoke_sessions`, `list_keys`, `rotate_key` (FILE_DEK_WRAP →
`rewrap_all`), `reidentify` (audited `audit.reidentify`). No self-modification, last admin protected.

## Not implemented / limitations
* Files are immutable; no versions, no rename, no resumable/multipart-to-provider uploads.
* Per-file `list_files` decrypts names: one KMS unwrap + manifest MAC per committed file per listing
  (fine for LocalKMS; would be a network call per file with AWS KMS).
* A KMS *outage* during download is reported as `key-unwrap-failed` (409) because the contract does not
  distinguish "wrong context" from "unavailable".
* After KEK rotation the manifest's recorded `kek` stays the upload-time value (informational; the row's
  `kek_id/kek_version` are updated). Manifests are not re-sealed on rotation.
* The download detector counts before and records after the download: N concurrent downloads can overshoot
  the count threshold by up to N-1. Detection state for auth failures is per process.
* Crash recovery treats PENDING/UPLOADING rows older than `stale_upload_minutes` (default 10) as dead;
  with several backend instances a slow upload on another instance could be reaped (single instance assumed).
* Orphans: an object written by a provider call that timed out client-side but completed later is not in
  the intent log replica rows; for crashed uploads `recover()` deletes every recorded chunk id from *all*
  providers, but for a failed (not crashed) upload only the orchestrator's cleanup covers it.

## Tests
`cd backend && .venv/bin/python -m pytest tests/integration/app -q -rs` (emulators running) →
**70 passed** (69 TestClient tests on memory providers + 1 emulator test through S3/Azure/GCS adapters).
Whole suite at the end of Phase 6: see `app/api/NOTES.md`.

## Chunk size and large files (2026-11-25)

`chunk_size_bytes` is a setting (framework default 1 MiB; the container deployment uses 16 MiB). Each file's row and manifest store
the chunk size it was written with and validation uses that value, so files written under another setting stay readable
(`backend/tests/integration/app/test_large_files_and_chunk_sizes.py`). The download spool is `<data_dir>/tmp` (see step 6 above), so
the data volume needs room for the largest file per concurrent download. A single download larger than
`detect_max_download_bytes_in_window` is refused by the detector (see `docs/adr/README.md`, ADR-0012).
