# Final implementation report

**Project:** Zero-Trust Multi-Cloud Chunked Storage Framework with Privacy-Aware Audit Logging
**Course:** Cloud SRE and Security, IIIT Dharwad
**Team:** Vaibhav Sharma (23BDS066), Shivansh Shukla (23BDS054), Kishlay Singh (23BCS066), Dhanraj Matke (23BCS042)
**Verification dates:** 2026-11-23 for the original submission. Section 6 and the new section 9 were produced on 2026-11-25 (no application code changed in between; 37 tests were added for the deployment settings and tooling).

This report states what was built, how complete each part is, and what evidence supports each claim. Each
claim names a test, a command or a document. Where something is partial, simulated or untested, the report
says so.

## 1. What was built, per phase

The phases follow the roadmap in `docs/ARCHITECTURE.md` §7.

| Phase | Built | Evidence |
|---|---|---|
| 1. Design | Architecture with the case-study → requirement mapping (R1–R10), threat model, ADR-0001…0011, module contracts | `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, `docs/adr/README.md`, `docs/CONTRACTS.md` |
| 2. Identity and policy | Argon2id passwords, TOTP MFA with gated enrolment (ADR-0010), EdDSA access tokens, rotating single-use refresh tokens, sessions, lockout; pure PDP and PEP with reason codes and obligations | `tests/unit/auth` (79 tests), `tests/unit/policy` (339 tests, incl. the full role × action × relationship matrix) |
| 3. Keys and crypto | Local KMS (versioned keystore under a root key; AWS KMS backend), envelope encryption, HKDF key separation, chunk AEAD with AAD binding, MAC'd canonical manifest, verify-then-release assembler | `tests/unit/kms` (73), `tests/unit/cryptoengine` (103) |
| 4. Multi-cloud storage | S3, Azure Blob and GCS adapters on the real SDKs, in-memory provider, rotating/hash placement, retry with backoff and deadline, failover, health monitor and circuit breaker, fault injection, metrics | `tests/unit/storage` (145), `tests/integration/storage` (78: one contract suite run against all three emulators) |
| 5. Audit | Privacy filter, HMAC pseudonyms, hash chain, Ed25519 checkpoints, anchors on the providers (per-log namespace), verification, retention, search and export | `tests/unit/audit` (187) |
| 6. Integration and API | File workflow state machine (upload/download/delete/verify/repair/share), REST API, middleware, detection, admin, dashboard, `/metrics` | `tests/integration/app` (73), `docs/API.md` |
| 7. Frontend | React 19 + Vite + TypeScript console (8 screens), API client with single-flight refresh and step-up | `npm run build`, `npx vitest run` (15), `frontend/e2e/live.mjs` (54 checks), `docs/screenshots/` |
| 8. Security testing | 17 attack scenarios (S01–S17) and 7 provider-failure scenarios (E01–E07); findings F1–F6 fixed; independent review (17 items) fixed | `tests/security` (108), `tests/review` (42), `scripts/attacks/run_all.sh`, `scripts/demo.sh`, `docs/SECURITY_TESTING.md` |
| 9. Documentation and delivery | README, QUICKSTART, this report, container files (smoke-tested once), repository hygiene | this repository |

## 2. Implementation status

| Component | Status | Notes |
|---|---|---|
| Authentication (passwords, TOTP, tokens, sessions, lockout, rate limits) | **Fully implemented** | Single-process rate limits and lockout serialisation |
| Authorisation (PDP/PEP, RBAC + ownership + classification ABAC, allow lists, step-up) | **Fully implemented** | |
| Chunking + AES-256-GCM + manifest MAC + envelope encryption | **Fully implemented** | |
| Local KMS (keystore under a root key, rotation, signing, MAC) | **Fully implemented** | Root key supplied by env var or file; no HSM |
| AWS KMS backend | **Partial** | Implemented; tested only against moto's KMS (`tests/unit/kms/test_kms_aws_moto.py`), never against AWS |
| S3 / Azure Blob / GCS adapters | **Real SDK integrations, tested against emulators only** | boto3 ↔ moto, azure-storage-blob ↔ Azurite, google-cloud-storage ↔ gcp-storage-emulator. No real cloud account was used |
| Orchestrator (placement, replication R=2 of 3, retry, failover, health, circuit breaker, repair) | **Fully implemented** | Replication, not erasure coding (ADR-0004) |
| Provider outages | **Real (emulator process killed)** in E01/E07 and demo step 13; **simulated** (fault injection over the real adapter) in E04/E05 and the UI's SIMULATED FAULT controls | Fault injection is refused in production |
| Audit (privacy filter, chain, checkpoints, anchors, verification, retention, search, export) | **Fully implemented** | Tail after the last checkpoint can be truncated undetected (ADR-0006 limit) |
| Anomaly detection (bulk download, credential stuffing, refresh reuse) | **Fully implemented** (threshold rules) | No ML; per process |
| Web console | **Fully implemented** | API-client unit tests + live e2e; no component tests |
| Database | SQLite **tested**; PostgreSQL **supported by URL, untested** | Postgres advisory-lock path not exercised |
| Containers (`deploy/`) | **Built and smoke-tested once** (2026-11-26) | `deploy/smoke_test.py`: 12/12 checks with a 20 MiB and with a 300 MiB file through nginx; one defect found and fixed (Azurite volume ownership) |
| TLS, multi-instance, real IAM provisioning | **Not implemented** (out of scope, stated) | `docs/THREAT_MODEL.md` |

## 3. Acceptance criteria

| Criterion | Met? | Evidence |
|---|---|---|
| **Authentication** | Yes | `tests/unit/auth/*`; `test_s01_s02_authentication.py` (alg confusion, forged/expired/foreign tokens); `test_s10_brute_force.py` (lockout, TOTP brute force, stuffing, rate limits); `test_s11_s15_unc5537.py::test_s11_stolen_password_but_mfa_enrolled_cannot_log_in`; `tests/review/test_review_auth.py` |
| **Authorisation** | Yes | `tests/unit/policy/test_policy_pdp.py` (matrix); `test_s03_s04_authorization.py` (horizontal access, ID guessing, admin-only operations, admin cannot read content); `test_s12_*` (allow list) |
| **Chunking** | Yes | `tests/unit/cryptoengine/test_crypto_engine.py::test_round_trip_sizes`, `::test_non_default_chunk_sizes`, `::test_max_chunks_per_file`; `tests/integration/app/test_app_files.py::test_round_trip_sizes` |
| **Encryption** | Yes | `test_crypto_engine.py::test_blob_format_and_no_plaintext`, `::test_same_plaintext_twice_differs`, `::test_every_byte_flip_detected_by_aead`, `::test_wrong_dek_cannot_open`; `test_app_files.py::test_ciphertext_on_providers_has_no_plaintext`; demo step 8 (raw objects at each provider: entropy ≈ 8 bit/byte, no plaintext) |
| **Multi-cloud** | Yes (on emulators) | `tests/integration/storage/test_emulator_contract.py` (contract suite against moto, Azurite, GCS emulator); `test_app_emulators.py::test_full_flow_through_three_real_adapters`; `tests/unit/storage/test_orchestrator.py::test_multi_chunk_file_spread_over_all_providers` |
| **Metadata** | Yes | Filename/MIME encrypted, manifest MAC'd: `test_app_failures.py::test_enc_metadata_hash_checked_before_decrypt`, `::test_classification_downgrade_in_db_is_detected`, `test_s05_s07_data_integrity.py::test_s06_*` |
| **Retrieval** | Yes | `test_app_files.py::test_round_trip_sizes`, `::test_large_download_spools_to_unlinked_tempfile`; `test_app_failures.py::test_read_served_from_replica_when_provider_down`; demo step 9 (SHA-256 match) |
| **Integrity** | Yes | `test_s05_*`, `test_s06_*`, `test_s07_*` (bit flips, manifest edits, reorder, substitute, truncate); `test_app_failures.py::test_partially_corrupt_last_chunk_never_partially_delivered`; `test_e03_corrupted_object_detected_and_replica_used` |
| **Audit** | Yes | `tests/unit/audit/*`; `test_app_audit_detection.py::test_no_audit_detail_dropped_across_subsystems_and_chain_verifies`, `::test_checkpoints_are_anchored_on_every_provider`, `::test_audit_db_is_separate_from_metadata_db` |
| **Privacy** | Yes | `tests/unit/audit/test_audit_privacy.py`; `test_s17_audit_privacy.py::test_s17_no_secret_in_any_audit_database` (`109 audit DBs, 2810 events, 634 long secrets + 68 TOTP codes + 6 full IPs: 0 hits` in the 2026-11-23 scenario table); `test_app_audit_detection.py::test_no_secret_in_audit_db_or_app_log`; review M1/M3/L8 tests |
| **Tamper evidence** | Yes, with the stated tail limit | `test_s08_audit_tampering.py` (modify, recompute hash, delete, reorder, truncate, forge checkpoint, wipe checkpoint rows, shared bucket); `tests/unit/audit/test_audit_tamper.py`; `test_s08_stated_limit_tail_after_last_checkpoint` documents the limit |
| **Availability** | Yes for one provider down; two providers down → 503 by design | `test_e01_provider_failures.py` E01–E07; `test_s09_provider_compromise.py`; `test_s09_stated_limit_two_providers_wiped`; demo steps 13–14 |
| **Security testing** | Yes | `scripts/attacks/run_all.sh` → `Totals: PASS=108`; findings F1–F6 and review H1–I2 fixed with regression tests (§5) |
| **Frontend** | Yes | `npm run build` exit 0; `npx vitest run` 15 passed; `frontend/e2e/live.mjs` 54/54; 30 screenshots |
| **Documentation** | Yes | README, QUICKSTART, ARCHITECTURE, THREAT_MODEL, ADRs, API, SECURITY_TESTING, this report, per-module `NOTES.md`, `frontend/README.md`, `deploy/README.md` |

## 4. Required test cases

All names are pytest node ids under `backend/tests/`. The integration tests use a 4096-byte chunk size, so
the sizes are small but cover every boundary.

| Case | Test(s) |
|---|---|
| Empty file | `integration/app/test_app_files.py::test_round_trip_sizes[0]`; `unit/cryptoengine/test_crypto_engine.py::test_empty_file_manifest_valid`; storage contract `test_empty_object` |
| Small file | `integration/app/test_app_files.py::test_round_trip_sizes[1]`, `[4095]` (below one chunk) |
| Large file | `unit/cryptoengine/test_crypto_engine.py::test_large_file_20mib`; `integration/app/test_app_files.py::test_large_download_spools_to_unlinked_tempfile`; demo step 5 (3.5 MiB, 4 × 1 MiB chunks) |
| Multi-chunk file | `integration/app/test_app_files.py::test_round_trip_sizes[4096]`, `[4097]`, `[12288]`, `[12305]`; `unit/storage/test_orchestrator.py::test_multi_chunk_file_spread_over_all_providers` |
| Binary file | `integration/app/test_app_files.py::test_round_trip_5mib_random_binary`; storage contract `test_put_get_roundtrip_binary` |
| Duplicate upload | `integration/app/test_app_files.py::test_duplicate_uploads_are_distinct_files` |
| Concurrent uploads | `integration/app/test_app_files.py::test_concurrent_uploads`; `unit/audit` `test_concurrent_appends_never_fork_the_chain`; storage contract `test_concurrent_store_and_fetch` |
| Partial failure | `integration/app/test_app_failures.py::test_upload_fails_cleanly_when_two_providers_down`, `::test_mid_upload_failure_removes_already_stored_chunks`, `::test_read_served_from_replica_when_provider_down`, `::test_crash_recovery_of_stale_uploads`; `security/test_e01_provider_failures.py::test_e01_*`, `test_e04_*`, `test_e05_*` |
| Missing chunk | `integration/app/test_app_failures.py::test_missing_chunk_everywhere_is_503`; `security/test_e01_provider_failures.py::test_e02_object_missing_at_one_provider_served_from_replica`, `::test_e06_chunk_permanently_unavailable_is_503` |
| Corrupted chunk | `integration/app/test_app_failures.py::test_corrupted_replica_served_from_other_and_critical_audit`, `::test_all_replicas_corrupt_is_409_without_content`; `security/test_e01_provider_failures.py::test_e03_corrupted_object_detected_and_replica_used`; `security/test_s05_s07_data_integrity.py::test_s05_*` |
| Invalid manifest | `integration/app/test_app_failures.py::test_tampered_manifest_is_409`, `::test_swapped_manifest_entries_is_409`, `::test_manifest_and_key_swapped_between_files_is_409`; `unit/cryptoengine/test_crypto_engine.py::test_manifest_modification_detected`, `::test_structural_validation`, `::test_float_or_duplicate_key_manifest_rejected`; `security/…::test_s06_modified_manifest_is_rejected_before_any_chunk_is_fetched` |
| Expired token | `integration/app/test_app_auth.py::test_expired_token_is_401`; `security/test_s01_s02_authentication.py::test_s02_expired_token_is_refused`, `::test_s02_expired_session_is_refused_and_audited`, `::test_s02_refresh_after_absolute_session_expiry_is_refused` |
| Revoked access | `integration/app/test_app_auth.py::test_revoked_session_is_401`; `security/test_s03_s04_authorization.py::test_s03_grantee_access_is_scoped_and_revocable` (unshare); `security/test_s11_s15_unc5537.py::test_s15_revoked_session_fails_on_the_next_request`, `::test_s15_disabled_account_and_demotion_take_effect_immediately` |

No required case was missing, so no new test was written in this pass.

## 5. Security findings history

| Source | # | Severity | Finding | Status | Regression test |
|---|---|---|---|---|---|
| Phase 8 | F1 | high | MFA enrolment hijack from a password-only session | fixed (ADR-0010) | `test_s11_mfa_enrolment_hijack_is_blocked_and_audited` and 3 more |
| Phase 8 | F2 | medium-high | Allow list not enforced at login/refresh/account endpoints | fixed | `test_s12_login_from_outside_the_allow_list_is_refused`, `test_s12_account_takeover_actions_from_outside_the_allow_list_are_refused` |
| Phase 8 | F3 | low | Username enumeration via registration | fixed | `test_s10_registration_does_not_reveal_existing_usernames` |
| Phase 8 | F4 | medium | Audit anchors not namespaced per deployment | fixed (ADR-0006 amendment) | `test_s08_anchors_of_two_deployments_sharing_a_bucket_do_not_collide` |
| Phase 8 | F5 | low-medium | Storage audit events without request context | fixed | `test_s05_storage_integrity_events_carry_the_request_context` |
| Phase 8 | F6 | low | Rate-limit rejections not audited | fixed | `test_s10_rate_limit_rejections_are_audited` |
| Review | H1 | high | Password change without fresh MFA evicted the MFA-verified owner | fixed | `test_fixed_password_change_*` (3) |
| Review | H2 | high | `X-Forwarded-For`: client-chosen IP via a first header line | fixed (ADR-0011) | `test_fixed_xff_*` (5 functions, 15 cases) |
| Review | M1 | medium | Auditors could re-identify pseudonyms via the user list | fixed (ADR-0007 amendment) | `test_fixed_auditor_cannot_reidentify_pseudonyms_through_the_user_list` |
| Review | M2 | medium | Unauthenticated audit flood with invalid tokens | fixed | `test_fixed_invalid_token_flood_*`, `test_fixed_security_feed_keeps_critical_events_under_a_warning_flood` |
| Review | M3 | medium | Pseudonym-key rotation by one admin erased attribution | fixed (ADR-0007 amendment) | `test_fixed_pseudonym_key_rotation_is_refused_and_history_survives_offline_rotation` |
| Review | M4 | medium | Insecure default `ZT_ENV=development` | fixed | `test_fixed_default_env_is_production_*`, `test_fixed_production_hides_docs_and_sends_hsts` |
| Review | M5 | medium | Restricted session could manage sessions and change the password | fixed (ADR-0010 amendment) | `test_fixed_restricted_password_only_session_is_limited_to_mfa_enrolment` |
| Review | L1–L8 | low | Session endpoints without allow list; refresh-reuse revocation from outside; parallel logins beyond lockout; IPv6 rate-limit keys; `/metrics` loopback trust; unthrottled verify/repair; whole-log own export; client-chosen request id | all fixed | see `docs/SECURITY_TESTING.md` §4a |
| Review | I1, I2 | info | Malformed multipart and out-of-range integers gave 500s | fixed | `test_fixed_malformed_multipart_*`, `test_fixed_out_of_range_integers_are_422` |
| Review | X1, X2 | low | Factor replacement left other sessions MFA-verified; bootstrap name held by a non-admin | fixed | `test_fixed_replacing_the_factor_*`, `test_fixed_bootstrap_admin_name_*` |

Three documentation claims were false before the review and are true now: the pseudonym-mapping claim in
ADR-0007 (M1), "a password-only session can only enrol MFA" (M5), and "the app refuses to start without its
secrets" (M4). Full detail: `docs/SECURITY_TESTING.md` §4 and §4a.

## 6. Test results (verbatim, 2026-11-25)

```
$ cd backend && .venv/bin/python -m pytest -q -rs          # emulators running
1273 passed, 1 warning in 205.80s (0:03:25)

$ scripts/attacks/run_all.sh --markdown
108 passed, 1 warning in 80.71s (0:01:20)
Totals: PASS=108

$ scripts/demo.sh
    46/46 checks passed

$ cd frontend && npm run build
✓ built in 495ms                                           (exit 0; tsc -b reported no errors)

$ npx vitest run
 Test Files  1 passed (1)
      Tests  15 passed (15)

$ node e2e/live.mjs                                         (live backend + Vite, headless Chromium; 54/54 on 2026-11-26)
54/54 checks passed
```

0 failed, 0 skipped, 0 xfailed. The one warning is a third-party `StarletteDeprecationWarning`. By `--collect-only`: 968 unit,
155 integration, 108 security, 42 independent-review tests.

## 7. Residual risks

- **TOFU window:** a password stolen within 24 h of registration, before the owner enrols, lets the thief
  enrol their own factor (detected and recoverable, not prevented; `test_s11_stated_limit_tofu_window`).
  Until the bootstrap admin enrols, its password alone can establish the admin factor.
- **Audit tail:** records after the last signed checkpoint can be truncated undetected (window =
  `audit_checkpoint_every` events).
- **DB write access:** roles, shares and password hashes are not row-MAC'd. Changes are detectable only
  afterwards through the separate audit log.
- **Two providers lost:** chunks whose two replicas were both on them are unavailable (503, never wrong
  bytes).
- **Bearer tokens:** a stolen access token works for up to 5 min from an allowed network (no DPoP/mTLS).
- **Shared rate limits:** the invalid-token limit is per client network, so users behind one NAT or /64
  share it.
- **Proxy configuration:** a wrong `ZT_TRUSTED_PROXY_HOPS` trusts a client entry (too low) or refuses
  requests (too high).
- **Backend host compromise** exposes plaintext and keys (application-side encryption).

## 8. Known limitations

- Emulators only: no AWS, Azure or GCP run. The AWS KMS backend was tested only against moto.
- Single backend instance: rate limits, lockout, circuit breaker and detection are per process. Only SQLite
  is tested.
- Containers in `deploy/` were smoke-tested once (2026-11-26); they are not covered by the browser suite, real clouds, TLS or files above 300 MiB through nginx.
- No TLS in the application, no erasure coding, no client-side (end-to-end) encryption.
- Downloads are buffered and verified before the first byte (ADR-0005), so time to first byte grows with
  file size, and the browser buffers the whole file to hash it.
- No dependency CVE scan, no fuzzing beyond hand-picked payloads, no timing side-channel measurement, no
  frontend component tests.
- Polling instead of server push in the UI.

## 9. Post-submission additions (2026-11-25)

Nothing in `backend/app` changed. What was added:

- **Deployment settings** (`deploy/docker-compose.yml`, `deploy/nginx.conf`, `deploy/README.md`): 16 MiB chunks, a 30 s provider
  deadline, a 10 GiB upload cap, a 20 GiB bulk-download threshold per window, an nginx body limit of 10250m and a read timeout of
  1800 s. Framework defaults are unchanged. Consistency tests: `backend/tests/unit/deploy/test_deployment_config.py`.
- **Per-file chunk sizes:** files written under one chunk size stay readable and verifiable after the setting changes, because each
  manifest records its own (`backend/tests/integration/app/test_large_files_and_chunk_sizes.py`).
- **Measurements** (`scripts/bench/`, results in `scripts/bench/results/`): per-size breakdown of upload, encryption, decryption and
  download (phase 1); large-file experiments up to 10 GiB (phase 2, `docs/SECURITY_TESTING.md` section 3a); 1 MiB against 16 MiB chunks
  in same-session paired rounds (phase 3). Local emulators only.
- **Residual risk added by the deployment:** the 20 GiB detector threshold weakens the bulk-export control about 40-fold against a
  stolen account (the count limit of 20 downloads per 5 minutes is unchanged). Without it no file above 512 MiB can be downloaded.
- **Not verified:** files above 300 MiB through the Docker stack and nginx, real cloud providers (the real-cloud tool was only rehearsed on
  emulators), and a multi-GiB upload from a browser.
